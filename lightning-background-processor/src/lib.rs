//! Utilities that take care of tasks that (1) need to happen periodically to keep Rust-Lightning
//! running properly, and (2) either can or should be run in the background. See docs for
//! [`BackgroundProcessor`] for more details on the nitty-gritty.

// Prefix these with `rustdoc::` when we update our MSRV to be >= 1.52 to remove warnings.
#![deny(broken_intra_doc_links)]
#![deny(private_intra_doc_links)]

#![deny(missing_docs)]
#![cfg_attr(not(feature = "futures"), deny(unsafe_code))]

#![cfg_attr(docsrs, feature(doc_auto_cfg))]

#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]

#[cfg(any(test, feature = "std"))]
extern crate core;

#[cfg(not(feature = "std"))]
extern crate alloc;

#[macro_use] extern crate lightning;
extern crate lightning_rapid_gossip_sync;

use lightning::chain;
use lightning::chain::chaininterface::{BroadcasterInterface, FeeEstimator};
use lightning::chain::chainmonitor::{ChainMonitor, Persist};
use lightning::sign::{EntropySource, NodeSigner, SignerProvider};
use lightning::events::{Event, PathFailure};
#[cfg(feature = "std")]
use lightning::events::{EventHandler, EventsProvider};
use lightning::ln::channelmanager::ChannelManager;
use lightning::ln::peer_handler::APeerManager;
use lightning::routing::gossip::{NetworkGraph, P2PGossipSync};
use lightning::routing::utxo::UtxoLookup;
use lightning::routing::router::Router;
use lightning::routing::scoring::{ScoreUpdate, WriteableScore};
use lightning::util::logger::Logger;
use lightning::util::persist::Persister;
#[cfg(feature = "std")]
use lightning::util::wakers::Sleeper;
use lightning_rapid_gossip_sync::RapidGossipSync;

use core::ops::Deref;
use core::time::Duration;

#[cfg(feature = "std")]
use std::sync::Arc;
#[cfg(feature = "std")]
use core::sync::atomic::{AtomicBool, Ordering};
#[cfg(feature = "std")]
use std::thread::{self, JoinHandle};
#[cfg(feature = "std")]
use std::time::Instant;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

/// `BackgroundProcessor` takes care of tasks that (1) need to happen periodically to keep
/// Rust-Lightning running properly, and (2) either can or should be run in the background. Its
/// responsibilities are:
/// * Processing [`Event`]s with a user-provided [`EventHandler`].
/// * Monitoring whether the [`ChannelManager`] needs to be re-persisted to disk, and if so,
///   writing it to disk/backups by invoking the callback given to it at startup.
///   [`ChannelManager`] persistence should be done in the background.
/// * Calling [`ChannelManager::timer_tick_occurred`], [`ChainMonitor::rebroadcast_pending_claims`]
///   and [`PeerManager::timer_tick_occurred`] at the appropriate intervals.
/// * Calling [`NetworkGraph::remove_stale_channels_and_tracking`] (if a [`GossipSync`] with a
///   [`NetworkGraph`] is provided to [`BackgroundProcessor::start`]).
///
/// It will also call [`PeerManager::process_events`] periodically though this shouldn't be relied
/// upon as doing so may result in high latency.
///
/// # Note
///
/// If [`ChannelManager`] persistence fails and the persisted manager becomes out-of-date, then
/// there is a risk of channels force-closing on startup when the manager realizes it's outdated.
/// However, as long as [`ChannelMonitor`] backups are sound, no funds besides those used for
/// unilateral chain closure fees are at risk.
///
/// [`ChannelMonitor`]: lightning::chain::channelmonitor::ChannelMonitor
/// [`Event`]: lightning::events::Event
/// [`PeerManager::timer_tick_occurred`]: lightning::ln::peer_handler::PeerManager::timer_tick_occurred
/// [`PeerManager::process_events`]: lightning::ln::peer_handler::PeerManager::process_events
#[cfg(feature = "std")]
#[must_use = "BackgroundProcessor will immediately stop on drop. It should be stored until shutdown."]
pub struct BackgroundProcessor {
	stop_thread: Arc<AtomicBool>,
	thread_handle: Option<JoinHandle<Result<(), std::io::Error>>>,
}

#[cfg(not(test))]
const FRESHNESS_TIMER: u64 = 60;
#[cfg(test)]
const FRESHNESS_TIMER: u64 = 1;

#[cfg(all(not(test), not(debug_assertions)))]
const PING_TIMER: u64 = 10;
/// Signature operations take a lot longer without compiler optimisations.
/// Increasing the ping timer allows for this but slower devices will be disconnected if the
/// timeout is reached.
#[cfg(all(not(test), debug_assertions))]
const PING_TIMER: u64 = 30;
#[cfg(test)]
const PING_TIMER: u64 = 1;

/// Prune the network graph of stale entries hourly.
const NETWORK_PRUNE_TIMER: u64 = 60 * 60;

#[cfg(not(test))]
const SCORER_PERSIST_TIMER: u64 = 60 * 60;
#[cfg(test)]
const SCORER_PERSIST_TIMER: u64 = 1;

#[cfg(not(test))]
const FIRST_NETWORK_PRUNE_TIMER: u64 = 60;
#[cfg(test)]
const FIRST_NETWORK_PRUNE_TIMER: u64 = 1;

#[cfg(not(test))]
const REBROADCAST_TIMER: u64 = 30;
#[cfg(test)]
const REBROADCAST_TIMER: u64 = 1;

#[cfg(feature = "futures")]
/// core::cmp::min is not currently const, so we define a trivial (and equivalent) replacement
const fn min_u64(a: u64, b: u64) -> u64 { if a < b { a } else { b } }
#[cfg(feature = "futures")]
const FASTEST_TIMER: u64 = min_u64(min_u64(FRESHNESS_TIMER, PING_TIMER),
	min_u64(SCORER_PERSIST_TIMER, min_u64(FIRST_NETWORK_PRUNE_TIMER, REBROADCAST_TIMER)));

/// Either [`P2PGossipSync`] or [`RapidGossipSync`].
pub enum GossipSync<
	P: Deref<Target = P2PGossipSync<G, U, L>>,
	R: Deref<Target = RapidGossipSync<G, L>>,
	G: Deref<Target = NetworkGraph<L>>,
	U: Deref,
	L: Deref,
>
where U::Target: UtxoLookup, L::Target: Logger {
	/// Gossip sync via the lightning peer-to-peer network as defined by BOLT 7.
	P2P(P),
	/// Rapid gossip sync from a trusted server.
	Rapid(R),
	/// No gossip sync.
	None,
}

impl<
	P: Deref<Target = P2PGossipSync<G, U, L>>,
	R: Deref<Target = RapidGossipSync<G, L>>,
	G: Deref<Target = NetworkGraph<L>>,
	U: Deref,
	L: Deref,
> GossipSync<P, R, G, U, L>
where U::Target: UtxoLookup, L::Target: Logger {
	fn network_graph(&self) -> Option<&G> {
		match self {
			GossipSync::P2P(gossip_sync) => Some(gossip_sync.network_graph()),
			GossipSync::Rapid(gossip_sync) => Some(gossip_sync.network_graph()),
			GossipSync::None => None,
		}
	}

	fn prunable_network_graph(&self) -> Option<&G> {
		match self {
			GossipSync::P2P(gossip_sync) => Some(gossip_sync.network_graph()),
			GossipSync::Rapid(gossip_sync) => {
				if gossip_sync.is_initial_sync_complete() {
					Some(gossip_sync.network_graph())
				} else {
					None
				}
			},
			GossipSync::None => None,
		}
	}
}

/// This is not exported to bindings users as the bindings concretize everything and have constructors for us
impl<P: Deref<Target = P2PGossipSync<G, U, L>>, G: Deref<Target = NetworkGraph<L>>, U: Deref, L: Deref>
	GossipSync<P, &RapidGossipSync<G, L>, G, U, L>
where
	U::Target: UtxoLookup,
	L::Target: Logger,
{
	/// Initializes a new [`GossipSync::P2P`] variant.
	pub fn p2p(gossip_sync: P) -> Self {
		GossipSync::P2P(gossip_sync)
	}
}

/// This is not exported to bindings users as the bindings concretize everything and have constructors for us
impl<'a, R: Deref<Target = RapidGossipSync<G, L>>, G: Deref<Target = NetworkGraph<L>>, L: Deref>
	GossipSync<
		&P2PGossipSync<G, &'a (dyn UtxoLookup + Send + Sync), L>,
		R,
		G,
		&'a (dyn UtxoLookup + Send + Sync),
		L,
	>
where
	L::Target: Logger,
{
	/// Initializes a new [`GossipSync::Rapid`] variant.
	pub fn rapid(gossip_sync: R) -> Self {
		GossipSync::Rapid(gossip_sync)
	}
}

/// This is not exported to bindings users as the bindings concretize everything and have constructors for us
impl<'a, L: Deref>
	GossipSync<
		&P2PGossipSync<&'a NetworkGraph<L>, &'a (dyn UtxoLookup + Send + Sync), L>,
		&RapidGossipSync<&'a NetworkGraph<L>, L>,
		&'a NetworkGraph<L>,
		&'a (dyn UtxoLookup + Send + Sync),
		L,
	>
where
	L::Target: Logger,
{
	/// Initializes a new [`GossipSync::None`] variant.
	pub fn none() -> Self {
		GossipSync::None
	}
}

fn handle_network_graph_update<L: Deref>(
	network_graph: &NetworkGraph<L>, event: &Event
) where L::Target: Logger {
	if let Event::PaymentPathFailed {
		failure: PathFailure::OnPath { network_update: Some(ref upd) }, .. } = event
	{
		network_graph.handle_network_update(upd);
	}
}

/// Updates scorer based on event and returns whether an update occurred so we can decide whether
/// to persist.
fn update_scorer<'a, S: 'static + Deref<Target = SC> + Send + Sync, SC: 'a + WriteableScore<'a>>(
	scorer: &'a S, event: &Event
) -> bool {
	match event {
		Event::PaymentPathFailed { ref path, short_channel_id: Some(scid), .. } => {
			let mut score = scorer.write_lock();
			score.payment_path_failed(path, *scid);
		},
		Event::PaymentPathFailed { ref path, payment_failed_permanently: true, .. } => {
			// Reached if the destination explicitly failed it back. We treat this as a successful probe
			// because the payment made it all the way to the destination with sufficient liquidity.
			let mut score = scorer.write_lock();
			score.probe_successful(path);
		},
		Event::PaymentPathSuccessful { path, .. } => {
			let mut score = scorer.write_lock();
			score.payment_path_successful(path);
		},
		Event::ProbeSuccessful { path, .. } => {
			let mut score = scorer.write_lock();
			score.probe_successful(path);
		},
		Event::ProbeFailed { path, short_channel_id: Some(scid), .. } => {
			let mut score = scorer.write_lock();
			score.probe_failed(path, *scid);
		},
		_ => return false,
	}
	true
}

macro_rules! define_run_body {
	($persister: ident, $chain_monitor: ident, $process_chain_monitor_events: expr,
	 $channel_manager: ident, $process_channel_manager_events: expr,
	 $gossip_sync: ident, $peer_manager: ident, $logger: ident, $scorer: ident,
	 $loop_exit_check: expr, $await: expr, $get_timer: expr, $timer_elapsed: expr,
	 $check_slow_await: expr)
	=> { {
		log_trace!($logger, "Calling ChannelManager's timer_tick_occurred on startup");
		$channel_manager.timer_tick_occurred();
		log_trace!($logger, "Rebroadcasting monitor's pending claims on startup");
		$chain_monitor.rebroadcast_pending_claims();

		let mut last_freshness_call = $get_timer(FRESHNESS_TIMER);
		let mut last_ping_call = $get_timer(PING_TIMER);
		let mut last_prune_call = $get_timer(FIRST_NETWORK_PRUNE_TIMER);
		let mut last_scorer_persist_call = $get_timer(SCORER_PERSIST_TIMER);
		let mut last_rebroadcast_call = $get_timer(REBROADCAST_TIMER);
		let mut have_pruned = false;

		loop {
			$process_channel_manager_events;
			$process_chain_monitor_events;

			// Note that the PeerManager::process_events may block on ChannelManager's locks,
			// hence it comes last here. When the ChannelManager finishes whatever it's doing,
			// we want to ensure we get into `persist_manager` as quickly as we can, especially
			// without running the normal event processing above and handing events to users.
			//
			// Specifically, on an *extremely* slow machine, we may see ChannelManager start
			// processing a message effectively at any point during this loop. In order to
			// minimize the time between such processing completing and persisting the updated
			// ChannelManager, we want to minimize methods blocking on a ChannelManager
			// generally, and as a fallback place such blocking only immediately before
			// persistence.
			$peer_manager.as_ref().process_events();

			// Exit the loop if the background processor was requested to stop.
			if $loop_exit_check {
				log_trace!($logger, "Terminating background processor.");
				break;
			}

			// We wait up to 100ms, but track how long it takes to detect being put to sleep,
			// see `await_start`'s use below.
			let mut await_start = None;
			if $check_slow_await { await_start = Some($get_timer(1)); }
			let updates_available = $await;
			let await_slow = if $check_slow_await { $timer_elapsed(&mut await_start.unwrap(), 1) } else { false };

			// Exit the loop if the background processor was requested to stop.
			if $loop_exit_check {
				log_trace!($logger, "Terminating background processor.");
				break;
			}

			if updates_available {
				log_trace!($logger, "Persisting ChannelManager...");
				$persister.persist_manager(&*$channel_manager)?;
				log_trace!($logger, "Done persisting ChannelManager.");
			}
			if $timer_elapsed(&mut last_freshness_call, FRESHNESS_TIMER) {
				log_trace!($logger, "Calling ChannelManager's timer_tick_occurred");
				$channel_manager.timer_tick_occurred();
				last_freshness_call = $get_timer(FRESHNESS_TIMER);
			}
			if await_slow {
				// On various platforms, we may be starved of CPU cycles for several reasons.
				// E.g. on iOS, if we've been in the background, we will be entirely paused.
				// Similarly, if we're on a desktop platform and the device has been asleep, we
				// may not get any cycles.
				// We detect this by checking if our max-100ms-sleep, above, ran longer than a
				// full second, at which point we assume sockets may have been killed (they
				// appear to be at least on some platforms, even if it has only been a second).
				// Note that we have to take care to not get here just because user event
				// processing was slow at the top of the loop. For example, the sample client
				// may call Bitcoin Core RPCs during event handling, which very often takes
				// more than a handful of seconds to complete, and shouldn't disconnect all our
				// peers.
				log_trace!($logger, "100ms sleep took more than a second, disconnecting peers.");
				$peer_manager.as_ref().disconnect_all_peers();
				last_ping_call = $get_timer(PING_TIMER);
			} else if $timer_elapsed(&mut last_ping_call, PING_TIMER) {
				log_trace!($logger, "Calling PeerManager's timer_tick_occurred");
				$peer_manager.as_ref().timer_tick_occurred();
				last_ping_call = $get_timer(PING_TIMER);
			}

			// Note that we want to run a graph prune once not long after startup before
			// falling back to our usual hourly prunes. This avoids short-lived clients never
			// pruning their network graph. We run once 60 seconds after startup before
			// continuing our normal cadence. For RGS, since 60 seconds is likely too long,
			// we prune after an initial sync completes.
			let prune_timer = if have_pruned { NETWORK_PRUNE_TIMER } else { FIRST_NETWORK_PRUNE_TIMER };
			let prune_timer_elapsed = $timer_elapsed(&mut last_prune_call, prune_timer);
			let should_prune = match $gossip_sync {
				GossipSync::Rapid(_) => !have_pruned || prune_timer_elapsed,
				_ => prune_timer_elapsed,
			};
			if should_prune {
				// The network graph must not be pruned while rapid sync completion is pending
				if let Some(network_graph) = $gossip_sync.prunable_network_graph() {
					#[cfg(feature = "std")] {
						log_trace!($logger, "Pruning and persisting network graph.");
						network_graph.remove_stale_channels_and_tracking();
					}
					#[cfg(not(feature = "std"))] {
						log_warn!($logger, "Not pruning network graph, consider enabling `std` or doing so manually with remove_stale_channels_and_tracking_with_time.");
						log_trace!($logger, "Persisting network graph.");
					}

					if let Err(e) = $persister.persist_graph(network_graph) {
						log_error!($logger, "Error: Failed to persist network graph, check your disk and permissions {}", e)
					}

					have_pruned = true;
				}
				let prune_timer = if have_pruned { NETWORK_PRUNE_TIMER } else { FIRST_NETWORK_PRUNE_TIMER };
				last_prune_call = $get_timer(prune_timer);
			}

			if $timer_elapsed(&mut last_scorer_persist_call, SCORER_PERSIST_TIMER) {
				if let Some(ref scorer) = $scorer {
					log_trace!($logger, "Persisting scorer");
					if let Err(e) = $persister.persist_scorer(&scorer) {
						log_error!($logger, "Error: Failed to persist scorer, check your disk and permissions {}", e)
					}
				}
				last_scorer_persist_call = $get_timer(SCORER_PERSIST_TIMER);
			}

			if $timer_elapsed(&mut last_rebroadcast_call, REBROADCAST_TIMER) {
				log_trace!($logger, "Rebroadcasting monitor's pending claims");
				$chain_monitor.rebroadcast_pending_claims();
				last_rebroadcast_call = $get_timer(REBROADCAST_TIMER);
			}
		}

		// After we exit, ensure we persist the ChannelManager one final time - this avoids
		// some races where users quit while channel updates were in-flight, with
		// ChannelMonitor update(s) persisted without a corresponding ChannelManager update.
		$persister.persist_manager(&*$channel_manager)?;

		// Persist Scorer on exit
		if let Some(ref scorer) = $scorer {
			$persister.persist_scorer(&scorer)?;
		}

		// Persist NetworkGraph on exit
		if let Some(network_graph) = $gossip_sync.network_graph() {
			$persister.persist_graph(network_graph)?;
		}

		Ok(())
	} }
}

#[cfg(feature = "futures")]
pub(crate) mod futures_util {
	use core::future::Future;
	use core::task::{Poll, Waker, RawWaker, RawWakerVTable};
	use core::pin::Pin;
	use core::marker::Unpin;
	pub(crate) struct Selector<
		A: Future<Output=()> + Unpin, B: Future<Output=()> + Unpin, C: Future<Output=bool> + Unpin
	> {
		pub a: A,
		pub b: B,
		pub c: C,
	}
	pub(crate) enum SelectorOutput {
		A, B, C(bool),
	}

	impl<
		A: Future<Output=()> + Unpin, B: Future<Output=()> + Unpin, C: Future<Output=bool> + Unpin
	> Future for Selector<A, B, C> {
		type Output = SelectorOutput;
		fn poll(mut self: Pin<&mut Self>, ctx: &mut core::task::Context<'_>) -> Poll<SelectorOutput> {
			match Pin::new(&mut self.a).poll(ctx) {
				Poll::Ready(()) => { return Poll::Ready(SelectorOutput::A); },
				Poll::Pending => {},
			}
			match Pin::new(&mut self.b).poll(ctx) {
				Poll::Ready(()) => { return Poll::Ready(SelectorOutput::B); },
				Poll::Pending => {},
			}
			match Pin::new(&mut self.c).poll(ctx) {
				Poll::Ready(res) => { return Poll::Ready(SelectorOutput::C(res)); },
				Poll::Pending => {},
			}
			Poll::Pending
		}
	}

	// If we want to poll a future without an async context to figure out if it has completed or
	// not without awaiting, we need a Waker, which needs a vtable...we fill it with dummy values
	// but sadly there's a good bit of boilerplate here.
	fn dummy_waker_clone(_: *const ()) -> RawWaker { RawWaker::new(core::ptr::null(), &DUMMY_WAKER_VTABLE) }
	fn dummy_waker_action(_: *const ()) { }

	const DUMMY_WAKER_VTABLE: RawWakerVTable = RawWakerVTable::new(
		dummy_waker_clone, dummy_waker_action, dummy_waker_action, dummy_waker_action);
	pub(crate) fn dummy_waker() -> Waker { unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &DUMMY_WAKER_VTABLE)) } }
}
#[cfg(feature = "futures")]
use futures_util::{Selector, SelectorOutput, dummy_waker};
#[cfg(feature = "futures")]
use core::task;

/// Processes background events in a future.
///
/// `sleeper` should return a future which completes in the given amount of time and returns a
/// boolean indicating whether the background processing should exit. Once `sleeper` returns a
/// future which outputs `true`, the loop will exit and this function's future will complete.
/// The `sleeper` future is free to return early after it has triggered the exit condition.
///
/// See [`BackgroundProcessor::start`] for information on which actions this handles.
///
/// Requires the `futures` feature. Note that while this method is available without the `std`
/// feature, doing so will skip calling [`NetworkGraph::remove_stale_channels_and_tracking`],
/// you should call [`NetworkGraph::remove_stale_channels_and_tracking_with_time`] regularly
/// manually instead.
///
/// The `mobile_interruptable_platform` flag should be set if we're currently running on a
/// mobile device, where we may need to check for interruption of the application regularly. If you
/// are unsure, you should set the flag, as the performance impact of it is minimal unless there
/// are hundreds or thousands of simultaneous process calls running.
///
/// For example, in order to process background events in a [Tokio](https://tokio.rs/) task, you
/// could setup `process_events_async` like this:
/// ```
/// # use lightning::io;
/// # use std::sync::{Arc, Mutex};
/// # use std::sync::atomic::{AtomicBool, Ordering};
/// # use lightning_background_processor::{process_events_async, GossipSync};
/// # struct MyStore {}
/// # impl lightning::util::persist::KVStore for MyStore {
/// #     fn read(&self, namespace: &str, sub_namespace: &str, key: &str) -> io::Result<Vec<u8>> { Ok(Vec::new()) }
/// #     fn write(&self, namespace: &str, sub_namespace: &str, key: &str, buf: &[u8]) -> io::Result<()> { Ok(()) }
/// #     fn remove(&self, namespace: &str, sub_namespace: &str, key: &str, lazy: bool) -> io::Result<()> { Ok(()) }
/// #     fn list(&self, namespace: &str, sub_namespace: &str) -> io::Result<Vec<String>> { Ok(Vec::new()) }
/// # }
/// # struct MyEventHandler {}
/// # impl MyEventHandler {
/// #     async fn handle_event(&self, _: lightning::events::Event) {}
/// # }
/// # #[derive(Eq, PartialEq, Clone, Hash)]
/// # struct MySocketDescriptor {}
/// # impl lightning::ln::peer_handler::SocketDescriptor for MySocketDescriptor {
/// #     fn send_data(&mut self, _data: &[u8], _resume_read: bool) -> usize { 0 }
/// #     fn disconnect_socket(&mut self) {}
/// # }
/// # type MyBroadcaster = dyn lightning::chain::chaininterface::BroadcasterInterface + Send + Sync;
/// # type MyFeeEstimator = dyn lightning::chain::chaininterface::FeeEstimator + Send + Sync;
/// # type MyNodeSigner = dyn lightning::sign::NodeSigner + Send + Sync;
/// # type MyUtxoLookup = dyn lightning::routing::utxo::UtxoLookup + Send + Sync;
/// # type MyFilter = dyn lightning::chain::Filter + Send + Sync;
/// # type MyLogger = dyn lightning::util::logger::Logger + Send + Sync;
/// # type MyChainMonitor = lightning::chain::chainmonitor::ChainMonitor<lightning::sign::InMemorySigner, Arc<MyFilter>, Arc<MyBroadcaster>, Arc<MyFeeEstimator>, Arc<MyLogger>, Arc<MyStore>>;
/// # type MyPeerManager = lightning::ln::peer_handler::SimpleArcPeerManager<MySocketDescriptor, MyChainMonitor, MyBroadcaster, MyFeeEstimator, MyUtxoLookup, MyLogger>;
/// # type MyNetworkGraph = lightning::routing::gossip::NetworkGraph<Arc<MyLogger>>;
/// # type MyGossipSync = lightning::routing::gossip::P2PGossipSync<Arc<MyNetworkGraph>, Arc<MyUtxoLookup>, Arc<MyLogger>>;
/// # type MyChannelManager = lightning::ln::channelmanager::SimpleArcChannelManager<MyChainMonitor, MyBroadcaster, MyFeeEstimator, MyLogger>;
/// # type MyScorer = Mutex<lightning::routing::scoring::ProbabilisticScorer<Arc<MyNetworkGraph>, Arc<MyLogger>>>;
///
/// # async fn setup_background_processing(my_persister: Arc<MyStore>, my_event_handler: Arc<MyEventHandler>, my_chain_monitor: Arc<MyChainMonitor>, my_channel_manager: Arc<MyChannelManager>, my_gossip_sync: Arc<MyGossipSync>, my_logger: Arc<MyLogger>, my_scorer: Arc<MyScorer>, my_peer_manager: Arc<MyPeerManager>) {
///	let background_persister = Arc::clone(&my_persister);
///	let background_event_handler = Arc::clone(&my_event_handler);
///	let background_chain_mon = Arc::clone(&my_chain_monitor);
///	let background_chan_man = Arc::clone(&my_channel_manager);
///	let background_gossip_sync = GossipSync::p2p(Arc::clone(&my_gossip_sync));
///	let background_peer_man = Arc::clone(&my_peer_manager);
///	let background_logger = Arc::clone(&my_logger);
///	let background_scorer = Arc::clone(&my_scorer);
///
///	// Setup the sleeper.
///	let (stop_sender, stop_receiver) = tokio::sync::watch::channel(());
///
///	let sleeper = move |d| {
///		let mut receiver = stop_receiver.clone();
///		Box::pin(async move {
///			tokio::select!{
///				_ = tokio::time::sleep(d) => false,
///				_ = receiver.changed() => true,
///			}
///		})
///	};
///
///	let mobile_interruptable_platform = false;
///
///	let handle = tokio::spawn(async move {
///		process_events_async(
///			background_persister,
///			|e| background_event_handler.handle_event(e),
///			background_chain_mon,
///			background_chan_man,
///			background_gossip_sync,
///			background_peer_man,
///			background_logger,
///			Some(background_scorer),
///			sleeper,
///			mobile_interruptable_platform,
///			)
///			.await
///			.expect("Failed to process events");
///	});
///
///	// Stop the background processing.
///	stop_sender.send(()).unwrap();
///	handle.await.unwrap();
///	# }
///```
#[cfg(feature = "futures")]
pub async fn process_events_async<
	'a,
	UL: 'static + Deref + Send + Sync,
	CF: 'static + Deref + Send + Sync,
	CW: 'static + Deref + Send + Sync,
	T: 'static + Deref + Send + Sync,
	ES: 'static + Deref + Send + Sync,
	NS: 'static + Deref + Send + Sync,
	SP: 'static + Deref + Send + Sync,
	F: 'static + Deref + Send + Sync,
	R: 'static + Deref + Send + Sync,
	G: 'static + Deref<Target = NetworkGraph<L>> + Send + Sync,
	L: 'static + Deref + Send + Sync,
	P: 'static + Deref + Send + Sync,
	EventHandlerFuture: core::future::Future<Output = ()>,
	EventHandler: Fn(Event) -> EventHandlerFuture,
	PS: 'static + Deref + Send,
	M: 'static + Deref<Target = ChainMonitor<<SP::Target as SignerProvider>::Signer, CF, T, F, L, P>> + Send + Sync,
	CM: 'static + Deref<Target = ChannelManager<CW, T, ES, NS, SP, F, R, L>> + Send + Sync,
	PGS: 'static + Deref<Target = P2PGossipSync<G, UL, L>> + Send + Sync,
	RGS: 'static + Deref<Target = RapidGossipSync<G, L>> + Send,
	APM: APeerManager + Send + Sync,
	PM: 'static + Deref<Target = APM> + Send + Sync,
	S: 'static + Deref<Target = SC> + Send + Sync,
	SC: for<'b> WriteableScore<'b>,
	SleepFuture: core::future::Future<Output = bool> + core::marker::Unpin,
	Sleeper: Fn(Duration) -> SleepFuture
>(
	persister: PS, event_handler: EventHandler, chain_monitor: M, channel_manager: CM,
	gossip_sync: GossipSync<PGS, RGS, G, UL, L>, peer_manager: PM, logger: L, scorer: Option<S>,
	sleeper: Sleeper, mobile_interruptable_platform: bool,
) -> Result<(), lightning::io::Error>
where
	UL::Target: 'static + UtxoLookup,
	CF::Target: 'static + chain::Filter,
	CW::Target: 'static + chain::Watch<<SP::Target as SignerProvider>::Signer>,
	T::Target: 'static + BroadcasterInterface,
	ES::Target: 'static + EntropySource,
	NS::Target: 'static + NodeSigner,
	SP::Target: 'static + SignerProvider,
	F::Target: 'static + FeeEstimator,
	R::Target: 'static + Router,
	L::Target: 'static + Logger,
	P::Target: 'static + Persist<<SP::Target as SignerProvider>::Signer>,
	PS::Target: 'static + Persister<'a, CW, T, ES, NS, SP, F, R, L, SC>,
{
	let mut should_break = false;
	let async_event_handler = |event| {
		let network_graph = gossip_sync.network_graph();
		let event_handler = &event_handler;
		let scorer = &scorer;
		let logger = &logger;
		let persister = &persister;
		async move {
			if let Some(network_graph) = network_graph {
				handle_network_graph_update(network_graph, &event)
			}
			if let Some(ref scorer) = scorer {
				if update_scorer(scorer, &event) {
					log_trace!(logger, "Persisting scorer after update");
					if let Err(e) = persister.persist_scorer(&scorer) {
						log_error!(logger, "Error: Failed to persist scorer, check your disk and permissions {}", e)
					}
				}
			}
			event_handler(event).await;
		}
	};
	define_run_body!(persister,
		chain_monitor, chain_monitor.process_pending_events_async(async_event_handler).await,
		channel_manager, channel_manager.process_pending_events_async(async_event_handler).await,
		gossip_sync, peer_manager, logger, scorer, should_break, {
			let fut = Selector {
				a: channel_manager.get_persistable_update_future(),
				b: chain_monitor.get_update_future(),
				c: sleeper(if mobile_interruptable_platform { Duration::from_millis(100) } else { Duration::from_secs(FASTEST_TIMER) }),
			};
			match fut.await {
				SelectorOutput::A => true,
				SelectorOutput::B => false,
				SelectorOutput::C(exit) => {
					should_break = exit;
					false
				}
			}
		}, |t| sleeper(Duration::from_secs(t)),
		|fut: &mut SleepFuture, _| {
			let mut waker = dummy_waker();
			let mut ctx = task::Context::from_waker(&mut waker);
			match core::pin::Pin::new(fut).poll(&mut ctx) {
				task::Poll::Ready(exit) => { should_break = exit; true },
				task::Poll::Pending => false,
			}
		}, mobile_interruptable_platform)
}

#[cfg(feature = "std")]
impl BackgroundProcessor {
	/// Start a background thread that takes care of responsibilities enumerated in the [top-level
	/// documentation].
	///
	/// The thread runs indefinitely unless the object is dropped, [`stop`] is called, or
	/// [`Persister::persist_manager`] returns an error. In case of an error, the error is retrieved by calling
	/// either [`join`] or [`stop`].
	///
	/// # Data Persistence
	///
	/// [`Persister::persist_manager`] is responsible for writing out the [`ChannelManager`] to disk, and/or
	/// uploading to one or more backup services. See [`ChannelManager::write`] for writing out a
	/// [`ChannelManager`]. See the `lightning-persister` crate for LDK's
	/// provided implementation.
	///
	/// [`Persister::persist_graph`] is responsible for writing out the [`NetworkGraph`] to disk, if
	/// [`GossipSync`] is supplied. See [`NetworkGraph::write`] for writing out a [`NetworkGraph`].
	/// See the `lightning-persister` crate for LDK's provided implementation.
	///
	/// Typically, users should either implement [`Persister::persist_manager`] to never return an
	/// error or call [`join`] and handle any error that may arise. For the latter case,
	/// `BackgroundProcessor` must be restarted by calling `start` again after handling the error.
	///
	/// # Event Handling
	///
	/// `event_handler` is responsible for handling events that users should be notified of (e.g.,
	/// payment failed). [`BackgroundProcessor`] may decorate the given [`EventHandler`] with common
	/// functionality implemented by other handlers.
	/// * [`P2PGossipSync`] if given will update the [`NetworkGraph`] based on payment failures.
	///
	/// # Rapid Gossip Sync
	///
	/// If rapid gossip sync is meant to run at startup, pass [`RapidGossipSync`] via `gossip_sync`
	/// to indicate that the [`BackgroundProcessor`] should not prune the [`NetworkGraph`] instance
	/// until the [`RapidGossipSync`] instance completes its first sync.
	///
	/// [top-level documentation]: BackgroundProcessor
	/// [`join`]: Self::join
	/// [`stop`]: Self::stop
	/// [`ChannelManager`]: lightning::ln::channelmanager::ChannelManager
	/// [`ChannelManager::write`]: lightning::ln::channelmanager::ChannelManager#impl-Writeable
	/// [`Persister::persist_manager`]: lightning::util::persist::Persister::persist_manager
	/// [`Persister::persist_graph`]: lightning::util::persist::Persister::persist_graph
	/// [`NetworkGraph`]: lightning::routing::gossip::NetworkGraph
	/// [`NetworkGraph::write`]: lightning::routing::gossip::NetworkGraph#impl-Writeable
	pub fn start<
		'a,
		UL: 'static + Deref + Send + Sync,
		CF: 'static + Deref + Send + Sync,
		CW: 'static + Deref + Send + Sync,
		T: 'static + Deref + Send + Sync,
		ES: 'static + Deref + Send + Sync,
		NS: 'static + Deref + Send + Sync,
		SP: 'static + Deref + Send + Sync,
		F: 'static + Deref + Send + Sync,
		R: 'static + Deref + Send + Sync,
		G: 'static + Deref<Target = NetworkGraph<L>> + Send + Sync,
		L: 'static + Deref + Send + Sync,
		P: 'static + Deref + Send + Sync,
		EH: 'static + EventHandler + Send,
		PS: 'static + Deref + Send,
		M: 'static + Deref<Target = ChainMonitor<<SP::Target as SignerProvider>::Signer, CF, T, F, L, P>> + Send + Sync,
		CM: 'static + Deref<Target = ChannelManager<CW, T, ES, NS, SP, F, R, L>> + Send + Sync,
		PGS: 'static + Deref<Target = P2PGossipSync<G, UL, L>> + Send + Sync,
		RGS: 'static + Deref<Target = RapidGossipSync<G, L>> + Send,
		APM: APeerManager + Send + Sync,
		PM: 'static + Deref<Target = APM> + Send + Sync,
		S: 'static + Deref<Target = SC> + Send + Sync,
		SC: for <'b> WriteableScore<'b>,
	>(
		persister: PS, event_handler: EH, chain_monitor: M, channel_manager: CM,
		gossip_sync: GossipSync<PGS, RGS, G, UL, L>, peer_manager: PM, logger: L, scorer: Option<S>,
	) -> Self
	where
		UL::Target: 'static + UtxoLookup,
		CF::Target: 'static + chain::Filter,
		CW::Target: 'static + chain::Watch<<SP::Target as SignerProvider>::Signer>,
		T::Target: 'static + BroadcasterInterface,
		ES::Target: 'static + EntropySource,
		NS::Target: 'static + NodeSigner,
		SP::Target: 'static + SignerProvider,
		F::Target: 'static + FeeEstimator,
		R::Target: 'static + Router,
		L::Target: 'static + Logger,
		P::Target: 'static + Persist<<SP::Target as SignerProvider>::Signer>,
		PS::Target: 'static + Persister<'a, CW, T, ES, NS, SP, F, R, L, SC>,
	{
		let stop_thread = Arc::new(AtomicBool::new(false));
		let stop_thread_clone = stop_thread.clone();
		let handle = thread::spawn(move || -> Result<(), std::io::Error> {
			let event_handler = |event| {
				let network_graph = gossip_sync.network_graph();
				if let Some(network_graph) = network_graph {
					handle_network_graph_update(network_graph, &event)
				}
				if let Some(ref scorer) = scorer {
					if update_scorer(scorer, &event) {
						log_trace!(logger, "Persisting scorer after update");
						if let Err(e) = persister.persist_scorer(&scorer) {
							log_error!(logger, "Error: Failed to persist scorer, check your disk and permissions {}", e)
						}
					}
				}
				event_handler.handle_event(event);
			};
			define_run_body!(persister, chain_monitor, chain_monitor.process_pending_events(&event_handler),
				channel_manager, channel_manager.process_pending_events(&event_handler),
				gossip_sync, peer_manager, logger, scorer, stop_thread.load(Ordering::Acquire),
				Sleeper::from_two_futures(
					channel_manager.get_persistable_update_future(),
					chain_monitor.get_update_future()
				).wait_timeout(Duration::from_millis(100)),
				|_| Instant::now(), |time: &Instant, dur| time.elapsed().as_secs() > dur, false)
		});
		Self { stop_thread: stop_thread_clone, thread_handle: Some(handle) }
	}

	/// Join `BackgroundProcessor`'s thread, returning any error that occurred while persisting
	/// [`ChannelManager`].
	///
	/// # Panics
	///
	/// This function panics if the background thread has panicked such as while persisting or
	/// handling events.
	///
	/// [`ChannelManager`]: lightning::ln::channelmanager::ChannelManager
	pub fn join(mut self) -> Result<(), std::io::Error> {
		assert!(self.thread_handle.is_some());
		self.join_thread()
	}

	/// Stop `BackgroundProcessor`'s thread, returning any error that occurred while persisting
	/// [`ChannelManager`].
	///
	/// # Panics
	///
	/// This function panics if the background thread has panicked such as while persisting or
	/// handling events.
	///
	/// [`ChannelManager`]: lightning::ln::channelmanager::ChannelManager
	pub fn stop(mut self) -> Result<(), std::io::Error> {
		assert!(self.thread_handle.is_some());
		self.stop_and_join_thread()
	}

	fn stop_and_join_thread(&mut self) -> Result<(), std::io::Error> {
		self.stop_thread.store(true, Ordering::Release);
		self.join_thread()
	}

	fn join_thread(&mut self) -> Result<(), std::io::Error> {
		match self.thread_handle.take() {
			Some(handle) => handle.join().unwrap(),
			None => Ok(()),
		}
	}
}

#[cfg(feature = "std")]
impl Drop for BackgroundProcessor {
	fn drop(&mut self) {
		self.stop_and_join_thread().unwrap();
	}
}

#[cfg(all(feature = "std", test))]
mod tests {
	use bitcoin::blockdata::constants::{genesis_block, ChainHash};
	use bitcoin::blockdata::locktime::PackedLockTime;
	use bitcoin::blockdata::transaction::{Transaction, TxOut};
	use bitcoin::network::constants::Network;
	use bitcoin::secp256k1::{SecretKey, PublicKey, Secp256k1};
	use lightning::chain::{BestBlock, Confirm, chainmonitor};
	use lightning::chain::channelmonitor::ANTI_REORG_DELAY;
	use lightning::sign::{InMemorySigner, KeysManager};
	use lightning::chain::transaction::OutPoint;
	use lightning::events::{Event, PathFailure, MessageSendEventsProvider, MessageSendEvent};
	use lightning::{get_event_msg, get_event};
	use lightning::ln::PaymentHash;
	use lightning::ln::channelmanager;
	use lightning::ln::channelmanager::{BREAKDOWN_TIMEOUT, ChainParameters, MIN_CLTV_EXPIRY_DELTA, PaymentId};
	use lightning::ln::features::{ChannelFeatures, NodeFeatures};
	use lightning::ln::functional_test_utils::*;
	use lightning::ln::msgs::{ChannelMessageHandler, Init};
	use lightning::ln::peer_handler::{PeerManager, MessageHandler, SocketDescriptor, IgnoringMessageHandler};
	use lightning::routing::gossip::{NetworkGraph, NodeId, P2PGossipSync};
	use lightning::routing::router::{DefaultRouter, Path, RouteHop};
	use lightning::routing::scoring::{ChannelUsage, ScoreUpdate, ScoreLookUp};
	use lightning::util::config::UserConfig;
	use lightning::util::ser::Writeable;
	use lightning::util::test_utils;
	use lightning::util::persist::{KVStore, CHANNEL_MANAGER_PERSISTENCE_NAMESPACE, CHANNEL_MANAGER_PERSISTENCE_SUB_NAMESPACE, CHANNEL_MANAGER_PERSISTENCE_KEY, NETWORK_GRAPH_PERSISTENCE_NAMESPACE, NETWORK_GRAPH_PERSISTENCE_SUB_NAMESPACE, NETWORK_GRAPH_PERSISTENCE_KEY, SCORER_PERSISTENCE_NAMESPACE, SCORER_PERSISTENCE_SUB_NAMESPACE, SCORER_PERSISTENCE_KEY};
	use lightning_persister::fs_store::FilesystemStore;
	use std::collections::VecDeque;
	use std::{fs, env};
	use std::path::PathBuf;
	use std::sync::{Arc, Mutex};
	use std::sync::mpsc::SyncSender;
	use std::time::Duration;
	use lightning_rapid_gossip_sync::RapidGossipSync;
	use super::{BackgroundProcessor, GossipSync, FRESHNESS_TIMER};

	const EVENT_DEADLINE: u64 = 5 * FRESHNESS_TIMER;

	#[derive(Clone, Hash, PartialEq, Eq)]
	struct TestDescriptor{}
	impl SocketDescriptor for TestDescriptor {
		fn send_data(&mut self, _data: &[u8], _resume_read: bool) -> usize {
			0
		}

		fn disconnect_socket(&mut self) {}
	}

	type ChannelManager =
		channelmanager::ChannelManager<
			Arc<ChainMonitor>,
			Arc<test_utils::TestBroadcaster>,
			Arc<KeysManager>,
			Arc<KeysManager>,
			Arc<KeysManager>,
			Arc<test_utils::TestFeeEstimator>,
			Arc<DefaultRouter<
				Arc<NetworkGraph<Arc<test_utils::TestLogger>>>,
				Arc<test_utils::TestLogger>,
				Arc<Mutex<TestScorer>>,
				(),
				TestScorer>
			>,
			Arc<test_utils::TestLogger>>;

	type ChainMonitor = chainmonitor::ChainMonitor<InMemorySigner, Arc<test_utils::TestChainSource>, Arc<test_utils::TestBroadcaster>, Arc<test_utils::TestFeeEstimator>, Arc<test_utils::TestLogger>, Arc<FilesystemStore>>;

	type PGS = Arc<P2PGossipSync<Arc<NetworkGraph<Arc<test_utils::TestLogger>>>, Arc<test_utils::TestChainSource>, Arc<test_utils::TestLogger>>>;
	type RGS = Arc<RapidGossipSync<Arc<NetworkGraph<Arc<test_utils::TestLogger>>>, Arc<test_utils::TestLogger>>>;

	struct Node {
		node: Arc<ChannelManager>,
		p2p_gossip_sync: PGS,
		rapid_gossip_sync: RGS,
		peer_manager: Arc<PeerManager<TestDescriptor, Arc<test_utils::TestChannelMessageHandler>, Arc<test_utils::TestRoutingMessageHandler>, IgnoringMessageHandler, Arc<test_utils::TestLogger>, IgnoringMessageHandler, Arc<KeysManager>>>,
		chain_monitor: Arc<ChainMonitor>,
		kv_store: Arc<FilesystemStore>,
		tx_broadcaster: Arc<test_utils::TestBroadcaster>,
		network_graph: Arc<NetworkGraph<Arc<test_utils::TestLogger>>>,
		logger: Arc<test_utils::TestLogger>,
		best_block: BestBlock,
		scorer: Arc<Mutex<TestScorer>>,
	}

	impl Node {
		fn p2p_gossip_sync(&self) -> GossipSync<PGS, RGS, Arc<NetworkGraph<Arc<test_utils::TestLogger>>>, Arc<test_utils::TestChainSource>, Arc<test_utils::TestLogger>> {
			GossipSync::P2P(self.p2p_gossip_sync.clone())
		}

		fn rapid_gossip_sync(&self) -> GossipSync<PGS, RGS, Arc<NetworkGraph<Arc<test_utils::TestLogger>>>, Arc<test_utils::TestChainSource>, Arc<test_utils::TestLogger>> {
			GossipSync::Rapid(self.rapid_gossip_sync.clone())
		}

		fn no_gossip_sync(&self) -> GossipSync<PGS, RGS, Arc<NetworkGraph<Arc<test_utils::TestLogger>>>, Arc<test_utils::TestChainSource>, Arc<test_utils::TestLogger>> {
			GossipSync::None
		}
	}

	impl Drop for Node {
		fn drop(&mut self) {
			let data_dir = self.kv_store.get_data_dir();
			match fs::remove_dir_all(data_dir.clone()) {
				Err(e) => println!("Failed to remove test store directory {}: {}", data_dir.display(), e),
				_ => {}
			}
		}
	}

	struct Persister {
		graph_error: Option<(std::io::ErrorKind, &'static str)>,
		graph_persistence_notifier: Option<SyncSender<()>>,
		manager_error: Option<(std::io::ErrorKind, &'static str)>,
		scorer_error: Option<(std::io::ErrorKind, &'static str)>,
		kv_store: FilesystemStore,
	}

	impl Persister {
		fn new(data_dir: PathBuf) -> Self {
			let kv_store = FilesystemStore::new(data_dir);
			Self { graph_error: None, graph_persistence_notifier: None, manager_error: None, scorer_error: None, kv_store }
		}

		fn with_graph_error(self, error: std::io::ErrorKind, message: &'static str) -> Self {
			Self { graph_error: Some((error, message)), ..self }
		}

		fn with_graph_persistence_notifier(self, sender: SyncSender<()>) -> Self {
			Self { graph_persistence_notifier: Some(sender), ..self }
		}

		fn with_manager_error(self, error: std::io::ErrorKind, message: &'static str) -> Self {
			Self { manager_error: Some((error, message)), ..self }
		}

		fn with_scorer_error(self, error: std::io::ErrorKind, message: &'static str) -> Self {
			Self { scorer_error: Some((error, message)), ..self }
		}
	}

	impl KVStore for Persister {
		fn read(&self, namespace: &str, sub_namespace: &str, key: &str) -> lightning::io::Result<Vec<u8>> {
			self.kv_store.read(namespace, sub_namespace, key)
		}

		fn write(&self, namespace: &str, sub_namespace: &str, key: &str, buf: &[u8]) -> lightning::io::Result<()> {
			if namespace == CHANNEL_MANAGER_PERSISTENCE_NAMESPACE &&
				sub_namespace == CHANNEL_MANAGER_PERSISTENCE_SUB_NAMESPACE &&
				key == CHANNEL_MANAGER_PERSISTENCE_KEY
			{
				if let Some((error, message)) = self.manager_error {
					return Err(std::io::Error::new(error, message))
				}
			}

			if namespace == NETWORK_GRAPH_PERSISTENCE_NAMESPACE &&
				sub_namespace == NETWORK_GRAPH_PERSISTENCE_SUB_NAMESPACE &&
				key == NETWORK_GRAPH_PERSISTENCE_KEY
			{
				if let Some(sender) = &self.graph_persistence_notifier {
					match sender.send(()) {
						Ok(()) => {},
						Err(std::sync::mpsc::SendError(())) => println!("Persister failed to notify as receiver went away."),
					}
				};

				if let Some((error, message)) = self.graph_error {
					return Err(std::io::Error::new(error, message))
				}
			}

			if namespace == SCORER_PERSISTENCE_NAMESPACE &&
				sub_namespace == SCORER_PERSISTENCE_SUB_NAMESPACE &&
				key == SCORER_PERSISTENCE_KEY
			{
				if let Some((error, message)) = self.scorer_error {
					return Err(std::io::Error::new(error, message))
				}
			}

			self.kv_store.write(namespace, sub_namespace, key, buf)
		}

		fn remove(&self, namespace: &str, sub_namespace: &str, key: &str, lazy: bool) -> lightning::io::Result<()> {
			self.kv_store.remove(namespace, sub_namespace, key, lazy)
		}

		fn list(&self, namespace: &str, sub_namespace: &str) -> lightning::io::Result<Vec<String>> {
			self.kv_store.list(namespace, sub_namespace)
		}
	}

	struct TestScorer {
		event_expectations: Option<VecDeque<TestResult>>,
	}

	#[derive(Debug)]
	enum TestResult {
		PaymentFailure { path: Path, short_channel_id: u64 },
		PaymentSuccess { path: Path },
		ProbeFailure { path: Path },
		ProbeSuccess { path: Path },
	}

	impl TestScorer {
		fn new() -> Self {
			Self { event_expectations: None }
		}

		fn expect(&mut self, expectation: TestResult) {
			self.event_expectations.get_or_insert_with(VecDeque::new).push_back(expectation);
		}
	}

	impl lightning::util::ser::Writeable for TestScorer {
		fn write<W: lightning::util::ser::Writer>(&self, _: &mut W) -> Result<(), lightning::io::Error> { Ok(()) }
	}

	impl ScoreLookUp for TestScorer {
		type ScoreParams = ();
		fn channel_penalty_msat(
			&self, _short_channel_id: u64, _source: &NodeId, _target: &NodeId, _usage: ChannelUsage, _score_params: &Self::ScoreParams
		) -> u64 { unimplemented!(); }
	}

	impl ScoreUpdate for TestScorer {
		fn payment_path_failed(&mut self, actual_path: &Path, actual_short_channel_id: u64) {
			if let Some(expectations) = &mut self.event_expectations {
				match expectations.pop_front().unwrap() {
					TestResult::PaymentFailure { path, short_channel_id } => {
						assert_eq!(actual_path, &path);
						assert_eq!(actual_short_channel_id, short_channel_id);
					},
					TestResult::PaymentSuccess { path } => {
						panic!("Unexpected successful payment path: {:?}", path)
					},
					TestResult::ProbeFailure { path } => {
						panic!("Unexpected probe failure: {:?}", path)
					},
					TestResult::ProbeSuccess { path } => {
						panic!("Unexpected probe success: {:?}", path)
					}
				}
			}
		}

		fn payment_path_successful(&mut self, actual_path: &Path) {
			if let Some(expectations) = &mut self.event_expectations {
				match expectations.pop_front().unwrap() {
					TestResult::PaymentFailure { path, .. } => {
						panic!("Unexpected payment path failure: {:?}", path)
					},
					TestResult::PaymentSuccess { path } => {
						assert_eq!(actual_path, &path);
					},
					TestResult::ProbeFailure { path } => {
						panic!("Unexpected probe failure: {:?}", path)
					},
					TestResult::ProbeSuccess { path } => {
						panic!("Unexpected probe success: {:?}", path)
					}
				}
			}
		}

		fn probe_failed(&mut self, actual_path: &Path, _: u64) {
			if let Some(expectations) = &mut self.event_expectations {
				match expectations.pop_front().unwrap() {
					TestResult::PaymentFailure { path, .. } => {
						panic!("Unexpected payment path failure: {:?}", path)
					},
					TestResult::PaymentSuccess { path } => {
						panic!("Unexpected payment path success: {:?}", path)
					},
					TestResult::ProbeFailure { path } => {
						assert_eq!(actual_path, &path);
					},
					TestResult::ProbeSuccess { path } => {
						panic!("Unexpected probe success: {:?}", path)
					}
				}
			}
		}
		fn probe_successful(&mut self, actual_path: &Path) {
			if let Some(expectations) = &mut self.event_expectations {
				match expectations.pop_front().unwrap() {
					TestResult::PaymentFailure { path, .. } => {
						panic!("Unexpected payment path failure: {:?}", path)
					},
					TestResult::PaymentSuccess { path } => {
						panic!("Unexpected payment path success: {:?}", path)
					},
					TestResult::ProbeFailure { path } => {
						panic!("Unexpected probe failure: {:?}", path)
					},
					TestResult::ProbeSuccess { path } => {
						assert_eq!(actual_path, &path);
					}
				}
			}
		}
	}

	impl Drop for TestScorer {
		fn drop(&mut self) {
			if std::thread::panicking() {
				return;
			}

			if let Some(event_expectations) = &self.event_expectations {
				if !event_expectations.is_empty() {
					panic!("Unsatisfied event expectations: {:?}", event_expectations);
				}
			}
		}
	}

	fn get_full_filepath(filepath: String, filename: String) -> String {
		let mut path = PathBuf::from(filepath);
		path.push(filename);
		path.to_str().unwrap().to_string()
	}

	fn create_nodes(num_nodes: usize, persist_dir: &str) -> (String, Vec<Node>) {
		let persist_temp_path = env::temp_dir().join(persist_dir);
		let persist_dir = persist_temp_path.to_string_lossy().to_string();
		let network = Network::Bitcoin;
		let mut nodes = Vec::new();
		for i in 0..num_nodes {
			let tx_broadcaster = Arc::new(test_utils::TestBroadcaster::new(network));
			let fee_estimator = Arc::new(test_utils::TestFeeEstimator { sat_per_kw: Mutex::new(253) });
			let logger = Arc::new(test_utils::TestLogger::with_id(format!("node {}", i)));
			let genesis_block = genesis_block(network);
			let network_graph = Arc::new(NetworkGraph::new(network, logger.clone()));
			let scorer = Arc::new(Mutex::new(TestScorer::new()));
			let seed = [i as u8; 32];
			let router = Arc::new(DefaultRouter::new(network_graph.clone(), logger.clone(), seed, scorer.clone(), ()));
			let chain_source = Arc::new(test_utils::TestChainSource::new(Network::Bitcoin));
			let kv_store = Arc::new(FilesystemStore::new(format!("{}_persister_{}", &persist_dir, i).into()));
			let now = Duration::from_secs(genesis_block.header.time as u64);
			let keys_manager = Arc::new(KeysManager::new(&seed, now.as_secs(), now.subsec_nanos()));
			let chain_monitor = Arc::new(chainmonitor::ChainMonitor::new(Some(chain_source.clone()), tx_broadcaster.clone(), logger.clone(), fee_estimator.clone(), kv_store.clone()));
			let best_block = BestBlock::from_network(network);
			let params = ChainParameters { network, best_block };
			let manager = Arc::new(ChannelManager::new(fee_estimator.clone(), chain_monitor.clone(), tx_broadcaster.clone(), router.clone(), logger.clone(), keys_manager.clone(), keys_manager.clone(), keys_manager.clone(), UserConfig::default(), params, genesis_block.header.time));
			let p2p_gossip_sync = Arc::new(P2PGossipSync::new(network_graph.clone(), Some(chain_source.clone()), logger.clone()));
			let rapid_gossip_sync = Arc::new(RapidGossipSync::new(network_graph.clone(), logger.clone()));
			let msg_handler = MessageHandler {
				chan_handler: Arc::new(test_utils::TestChannelMessageHandler::new(ChainHash::using_genesis_block(Network::Testnet))),
				route_handler: Arc::new(test_utils::TestRoutingMessageHandler::new()),
				onion_message_handler: IgnoringMessageHandler{}, custom_message_handler: IgnoringMessageHandler{}
			};
			let peer_manager = Arc::new(PeerManager::new(msg_handler, 0, &seed, logger.clone(), keys_manager.clone()));
			let node = Node { node: manager, p2p_gossip_sync, rapid_gossip_sync, peer_manager, chain_monitor, kv_store, tx_broadcaster, network_graph, logger, best_block, scorer };
			nodes.push(node);
		}

		for i in 0..num_nodes {
			for j in (i+1)..num_nodes {
				nodes[i].node.peer_connected(&nodes[j].node.get_our_node_id(), &Init {
					features: nodes[j].node.init_features(), networks: None, remote_network_address: None
				}, true).unwrap();
				nodes[j].node.peer_connected(&nodes[i].node.get_our_node_id(), &Init {
					features: nodes[i].node.init_features(), networks: None, remote_network_address: None
				}, false).unwrap();
			}
		}

		(persist_dir, nodes)
	}

	macro_rules! open_channel {
		($node_a: expr, $node_b: expr, $channel_value: expr) => {{
			begin_open_channel!($node_a, $node_b, $channel_value);
			let events = $node_a.node.get_and_clear_pending_events();
			assert_eq!(events.len(), 1);
			let (temporary_channel_id, tx) = handle_funding_generation_ready!(events[0], $channel_value);
			$node_a.node.funding_transaction_generated(&temporary_channel_id, &$node_b.node.get_our_node_id(), tx.clone()).unwrap();
			$node_b.node.handle_funding_created(&$node_a.node.get_our_node_id(), &get_event_msg!($node_a, MessageSendEvent::SendFundingCreated, $node_b.node.get_our_node_id()));
			get_event!($node_b, Event::ChannelPending);
			$node_a.node.handle_funding_signed(&$node_b.node.get_our_node_id(), &get_event_msg!($node_b, MessageSendEvent::SendFundingSigned, $node_a.node.get_our_node_id()));
			get_event!($node_a, Event::ChannelPending);
			tx
		}}
	}

	macro_rules! begin_open_channel {
		($node_a: expr, $node_b: expr, $channel_value: expr) => {{
			$node_a.node.create_channel($node_b.node.get_our_node_id(), $channel_value, 100, 42, None).unwrap();
			$node_b.node.handle_open_channel(&$node_a.node.get_our_node_id(), &get_event_msg!($node_a, MessageSendEvent::SendOpenChannel, $node_b.node.get_our_node_id()));
			$node_a.node.handle_accept_channel(&$node_b.node.get_our_node_id(), &get_event_msg!($node_b, MessageSendEvent::SendAcceptChannel, $node_a.node.get_our_node_id()));
		}}
	}

	macro_rules! handle_funding_generation_ready {
		($event: expr, $channel_value: expr) => {{
			match $event {
				Event::FundingGenerationReady { temporary_channel_id, channel_value_satoshis, ref output_script, user_channel_id, .. } => {
					assert_eq!(channel_value_satoshis, $channel_value);
					assert_eq!(user_channel_id, 42);

					let tx = Transaction { version: 1 as i32, lock_time: PackedLockTime(0), input: Vec::new(), output: vec![TxOut {
						value: channel_value_satoshis, script_pubkey: output_script.clone(),
					}]};
					(temporary_channel_id, tx)
				},
				_ => panic!("Unexpected event"),
			}
		}}
	}

	fn confirm_transaction_depth(node: &mut Node, tx: &Transaction, depth: u32) {
		for i in 1..=depth {
			let prev_blockhash = node.best_block.block_hash();
			let height = node.best_block.height() + 1;
			let header = create_dummy_header(prev_blockhash, height);
			let txdata = vec![(0, tx)];
			node.best_block = BestBlock::new(header.block_hash(), height);
			match i {
				1 => {
					node.node.transactions_confirmed(&header, &txdata, height);
					node.chain_monitor.transactions_confirmed(&header, &txdata, height);
				},
				x if x == depth => {
					node.node.best_block_updated(&header, height);
					node.chain_monitor.best_block_updated(&header, height);
				},
				_ => {},
			}
		}
	}
	fn confirm_transaction(node: &mut Node, tx: &Transaction) {
		confirm_transaction_depth(node, tx, ANTI_REORG_DELAY);
	}

	#[test]
	fn test_background_processor() {
		// Test that when a new channel is created, the ChannelManager needs to be re-persisted with
		// updates. Also test that when new updates are available, the manager signals that it needs
		// re-persistence and is successfully re-persisted.
		let (persist_dir, nodes) = create_nodes(2, "test_background_processor");

		// Go through the channel creation process so that each node has something to persist. Since
		// open_channel consumes events, it must complete before starting BackgroundProcessor to
		// avoid a race with processing events.
		let tx = open_channel!(nodes[0], nodes[1], 100000);

		// Initiate the background processors to watch each node.
		let data_dir = nodes[0].kv_store.get_data_dir();
		let persister = Arc::new(Persister::new(data_dir));
		let event_handler = |_: _| {};
		let bg_processor = BackgroundProcessor::start(persister, event_handler, nodes[0].chain_monitor.clone(), nodes[0].node.clone(), nodes[0].p2p_gossip_sync(), nodes[0].peer_manager.clone(), nodes[0].logger.clone(), Some(nodes[0].scorer.clone()));

		macro_rules! check_persisted_data {
			($node: expr, $filepath: expr) => {
				let mut expected_bytes = Vec::new();
				loop {
					expected_bytes.clear();
					match $node.write(&mut expected_bytes) {
						Ok(()) => {
							match std::fs::read($filepath) {
								Ok(bytes) => {
									if bytes == expected_bytes {
										break
									} else {
										continue
									}
								},
								Err(_) => continue
							}
						},
						Err(e) => panic!("Unexpected error: {}", e)
					}
				}
			}
		}

		// Check that the initial channel manager data is persisted as expected.
		let filepath = get_full_filepath(format!("{}_persister_0", &persist_dir), "manager".to_string());
		check_persisted_data!(nodes[0].node, filepath.clone());

		loop {
			if !nodes[0].node.get_persistence_condvar_value() { break }
		}

		// Force-close the channel.
		nodes[0].node.force_close_broadcasting_latest_txn(&OutPoint { txid: tx.txid(), index: 0 }.to_channel_id(), &nodes[1].node.get_our_node_id()).unwrap();

		// Check that the force-close updates are persisted.
		check_persisted_data!(nodes[0].node, filepath.clone());
		loop {
			if !nodes[0].node.get_persistence_condvar_value() { break }
		}

		// Check network graph is persisted
		let filepath = get_full_filepath(format!("{}_persister_0", &persist_dir), "network_graph".to_string());
		check_persisted_data!(nodes[0].network_graph, filepath.clone());

		// Check scorer is persisted
		let filepath = get_full_filepath(format!("{}_persister_0", &persist_dir), "scorer".to_string());
		check_persisted_data!(nodes[0].scorer, filepath.clone());

		if !std::thread::panicking() {
			bg_processor.stop().unwrap();
		}
	}

	#[test]
	fn test_timer_tick_called() {
		// Test that `ChannelManager::timer_tick_occurred` is called every `FRESHNESS_TIMER`,
		// `ChainMonitor::rebroadcast_pending_claims` is called every `REBROADCAST_TIMER`, and
		// `PeerManager::timer_tick_occurred` every `PING_TIMER`.
		let (_, nodes) = create_nodes(1, "test_timer_tick_called");
		let data_dir = nodes[0].kv_store.get_data_dir();
		let persister = Arc::new(Persister::new(data_dir));
		let event_handler = |_: _| {};
		let bg_processor = BackgroundProcessor::start(persister, event_handler, nodes[0].chain_monitor.clone(), nodes[0].node.clone(), nodes[0].no_gossip_sync(), nodes[0].peer_manager.clone(), nodes[0].logger.clone(), Some(nodes[0].scorer.clone()));
		loop {
			let log_entries = nodes[0].logger.lines.lock().unwrap();
			let desired_log_1 = "Calling ChannelManager's timer_tick_occurred".to_string();
			let desired_log_2 = "Calling PeerManager's timer_tick_occurred".to_string();
			let desired_log_3 = "Rebroadcasting monitor's pending claims".to_string();
			if log_entries.get(&("lightning_background_processor".to_string(), desired_log_1)).is_some() &&
				log_entries.get(&("lightning_background_processor".to_string(), desired_log_2)).is_some() &&
				log_entries.get(&("lightning_background_processor".to_string(), desired_log_3)).is_some() {
				break
			}
		}

		if !std::thread::panicking() {
			bg_processor.stop().unwrap();
		}
	}

	#[test]
	fn test_channel_manager_persist_error() {
		// Test that if we encounter an error during manager persistence, the thread panics.
		let (_, nodes) = create_nodes(2, "test_persist_error");
		open_channel!(nodes[0], nodes[1], 100000);

		let data_dir = nodes[0].kv_store.get_data_dir();
		let persister = Arc::new(Persister::new(data_dir).with_manager_error(std::io::ErrorKind::Other, "test"));
		let event_handler = |_: _| {};
		let bg_processor = BackgroundProcessor::start(persister, event_handler, nodes[0].chain_monitor.clone(), nodes[0].node.clone(), nodes[0].no_gossip_sync(), nodes[0].peer_manager.clone(), nodes[0].logger.clone(), Some(nodes[0].scorer.clone()));
		match bg_processor.join() {
			Ok(_) => panic!("Expected error persisting manager"),
			Err(e) => {
				assert_eq!(e.kind(), std::io::ErrorKind::Other);
				assert_eq!(e.get_ref().unwrap().to_string(), "test");
			},
		}
	}

	#[tokio::test]
	#[cfg(feature = "futures")]
	async fn test_channel_manager_persist_error_async() {
		// Test that if we encounter an error during manager persistence, the thread panics.
		let (_, nodes) = create_nodes(2, "test_persist_error_sync");
		open_channel!(nodes[0], nodes[1], 100000);

		let data_dir = nodes[0].kv_store.get_data_dir();
		let persister = Arc::new(Persister::new(data_dir).with_manager_error(std::io::ErrorKind::Other, "test"));

		let bp_future = super::process_events_async(
			persister, |_: _| {async {}}, nodes[0].chain_monitor.clone(), nodes[0].node.clone(),
			nodes[0].rapid_gossip_sync(), nodes[0].peer_manager.clone(), nodes[0].logger.clone(),
			Some(nodes[0].scorer.clone()), move |dur: Duration| {
				Box::pin(async move {
					tokio::time::sleep(dur).await;
					false // Never exit
				})
			}, false,
		);
		match bp_future.await {
			Ok(_) => panic!("Expected error persisting manager"),
			Err(e) => {
				assert_eq!(e.kind(), std::io::ErrorKind::Other);
				assert_eq!(e.get_ref().unwrap().to_string(), "test");
			},
		}
	}

	#[test]
	fn test_network_graph_persist_error() {
		// Test that if we encounter an error during network graph persistence, an error gets returned.
		let (_, nodes) = create_nodes(2, "test_persist_network_graph_error");
		let data_dir = nodes[0].kv_store.get_data_dir();
		let persister = Arc::new(Persister::new(data_dir).with_graph_error(std::io::ErrorKind::Other, "test"));
		let event_handler = |_: _| {};
		let bg_processor = BackgroundProcessor::start(persister, event_handler, nodes[0].chain_monitor.clone(), nodes[0].node.clone(), nodes[0].p2p_gossip_sync(), nodes[0].peer_manager.clone(), nodes[0].logger.clone(), Some(nodes[0].scorer.clone()));

		match bg_processor.stop() {
			Ok(_) => panic!("Expected error persisting network graph"),
			Err(e) => {
				assert_eq!(e.kind(), std::io::ErrorKind::Other);
				assert_eq!(e.get_ref().unwrap().to_string(), "test");
			},
		}
	}

	#[test]
	fn test_scorer_persist_error() {
		// Test that if we encounter an error during scorer persistence, an error gets returned.
		let (_, nodes) = create_nodes(2, "test_persist_scorer_error");
		let data_dir = nodes[0].kv_store.get_data_dir();
		let persister = Arc::new(Persister::new(data_dir).with_scorer_error(std::io::ErrorKind::Other, "test"));
		let event_handler = |_: _| {};
		let bg_processor = BackgroundProcessor::start(persister, event_handler, nodes[0].chain_monitor.clone(), nodes[0].node.clone(), nodes[0].no_gossip_sync(), nodes[0].peer_manager.clone(),  nodes[0].logger.clone(), Some(nodes[0].scorer.clone()));

		match bg_processor.stop() {
			Ok(_) => panic!("Expected error persisting scorer"),
			Err(e) => {
				assert_eq!(e.kind(), std::io::ErrorKind::Other);
				assert_eq!(e.get_ref().unwrap().to_string(), "test");
			},
		}
	}

	#[test]
	fn test_background_event_handling() {
		let (_, mut nodes) = create_nodes(2, "test_background_event_handling");
		let channel_value = 100000;
		let data_dir = nodes[0].kv_store.get_data_dir();
		let persister = Arc::new(Persister::new(data_dir.clone()));

		// Set up a background event handler for FundingGenerationReady events.
		let (funding_generation_send, funding_generation_recv) = std::sync::mpsc::sync_channel(1);
		let (channel_pending_send, channel_pending_recv) = std::sync::mpsc::sync_channel(1);
		let event_handler = move |event: Event| match event {
			Event::FundingGenerationReady { .. } => funding_generation_send.send(handle_funding_generation_ready!(event, channel_value)).unwrap(),
			Event::ChannelPending { .. } => channel_pending_send.send(()).unwrap(),
			Event::ChannelReady { .. } => {},
			_ => panic!("Unexpected event: {:?}", event),
		};

		let bg_processor = BackgroundProcessor::start(persister, event_handler, nodes[0].chain_monitor.clone(), nodes[0].node.clone(), nodes[0].no_gossip_sync(), nodes[0].peer_manager.clone(), nodes[0].logger.clone(), Some(nodes[0].scorer.clone()));

		// Open a channel and check that the FundingGenerationReady event was handled.
		begin_open_channel!(nodes[0], nodes[1], channel_value);
		let (temporary_channel_id, funding_tx) = funding_generation_recv
			.recv_timeout(Duration::from_secs(EVENT_DEADLINE))
			.expect("FundingGenerationReady not handled within deadline");
		nodes[0].node.funding_transaction_generated(&temporary_channel_id, &nodes[1].node.get_our_node_id(), funding_tx.clone()).unwrap();
		nodes[1].node.handle_funding_created(&nodes[0].node.get_our_node_id(), &get_event_msg!(nodes[0], MessageSendEvent::SendFundingCreated, nodes[1].node.get_our_node_id()));
		get_event!(nodes[1], Event::ChannelPending);
		nodes[0].node.handle_funding_signed(&nodes[1].node.get_our_node_id(), &get_event_msg!(nodes[1], MessageSendEvent::SendFundingSigned, nodes[0].node.get_our_node_id()));
		let _ = channel_pending_recv.recv_timeout(Duration::from_secs(EVENT_DEADLINE))
			.expect("ChannelPending not handled within deadline");

		// Confirm the funding transaction.
		confirm_transaction(&mut nodes[0], &funding_tx);
		let as_funding = get_event_msg!(nodes[0], MessageSendEvent::SendChannelReady, nodes[1].node.get_our_node_id());
		confirm_transaction(&mut nodes[1], &funding_tx);
		let bs_funding = get_event_msg!(nodes[1], MessageSendEvent::SendChannelReady, nodes[0].node.get_our_node_id());
		nodes[0].node.handle_channel_ready(&nodes[1].node.get_our_node_id(), &bs_funding);
		let _as_channel_update = get_event_msg!(nodes[0], MessageSendEvent::SendChannelUpdate, nodes[1].node.get_our_node_id());
		nodes[1].node.handle_channel_ready(&nodes[0].node.get_our_node_id(), &as_funding);
		let _bs_channel_update = get_event_msg!(nodes[1], MessageSendEvent::SendChannelUpdate, nodes[0].node.get_our_node_id());

		if !std::thread::panicking() {
			bg_processor.stop().unwrap();
		}

		// Set up a background event handler for SpendableOutputs events.
		let (sender, receiver) = std::sync::mpsc::sync_channel(1);
		let event_handler = move |event: Event| match event {
			Event::SpendableOutputs { .. } => sender.send(event).unwrap(),
			Event::ChannelReady { .. } => {},
			Event::ChannelClosed { .. } => {},
			_ => panic!("Unexpected event: {:?}", event),
		};
		let persister = Arc::new(Persister::new(data_dir));
		let bg_processor = BackgroundProcessor::start(persister, event_handler, nodes[0].chain_monitor.clone(), nodes[0].node.clone(), nodes[0].no_gossip_sync(), nodes[0].peer_manager.clone(), nodes[0].logger.clone(), Some(nodes[0].scorer.clone()));

		// Force close the channel and check that the SpendableOutputs event was handled.
		nodes[0].node.force_close_broadcasting_latest_txn(&nodes[0].node.list_channels()[0].channel_id, &nodes[1].node.get_our_node_id()).unwrap();
		let commitment_tx = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().pop().unwrap();
		confirm_transaction_depth(&mut nodes[0], &commitment_tx, BREAKDOWN_TIMEOUT as u32);

		let event = receiver
			.recv_timeout(Duration::from_secs(EVENT_DEADLINE))
			.expect("Events not handled within deadline");
		match event {
			Event::SpendableOutputs { .. } => {},
			_ => panic!("Unexpected event: {:?}", event),
		}

		if !std::thread::panicking() {
			bg_processor.stop().unwrap();
		}
	}

	#[test]
	fn test_scorer_persistence() {
		let (_, nodes) = create_nodes(2, "test_scorer_persistence");
		let data_dir = nodes[0].kv_store.get_data_dir();
		let persister = Arc::new(Persister::new(data_dir));
		let event_handler = |_: _| {};
		let bg_processor = BackgroundProcessor::start(persister, event_handler, nodes[0].chain_monitor.clone(), nodes[0].node.clone(), nodes[0].no_gossip_sync(), nodes[0].peer_manager.clone(), nodes[0].logger.clone(), Some(nodes[0].scorer.clone()));

		loop {
			let log_entries = nodes[0].logger.lines.lock().unwrap();
			let expected_log = "Persisting scorer".to_string();
			if log_entries.get(&("lightning_background_processor".to_string(), expected_log)).is_some() {
				break
			}
		}

		if !std::thread::panicking() {
			bg_processor.stop().unwrap();
		}
	}

	macro_rules! do_test_not_pruning_network_graph_until_graph_sync_completion {
		($nodes: expr, $receive: expr, $sleep: expr) => {
			let features = ChannelFeatures::empty();
			$nodes[0].network_graph.add_channel_from_partial_announcement(
				42, 53, features, $nodes[0].node.get_our_node_id(), $nodes[1].node.get_our_node_id()
			).expect("Failed to update channel from partial announcement");
			let original_graph_description = $nodes[0].network_graph.to_string();
			assert!(original_graph_description.contains("42: features: 0000, node_one:"));
			assert_eq!($nodes[0].network_graph.read_only().channels().len(), 1);

			loop {
				$sleep;
				let log_entries = $nodes[0].logger.lines.lock().unwrap();
				let loop_counter = "Calling ChannelManager's timer_tick_occurred".to_string();
				if *log_entries.get(&("lightning_background_processor".to_string(), loop_counter))
					.unwrap_or(&0) > 1
				{
					// Wait until the loop has gone around at least twice.
					break
				}
			}

			let initialization_input = vec![
				76, 68, 75, 1, 111, 226, 140, 10, 182, 241, 179, 114, 193, 166, 162, 70, 174, 99, 247,
				79, 147, 30, 131, 101, 225, 90, 8, 156, 104, 214, 25, 0, 0, 0, 0, 0, 97, 227, 98, 218,
				0, 0, 0, 4, 2, 22, 7, 207, 206, 25, 164, 197, 231, 230, 231, 56, 102, 61, 250, 251,
				187, 172, 38, 46, 79, 247, 108, 44, 155, 48, 219, 238, 252, 53, 192, 6, 67, 2, 36, 125,
				157, 176, 223, 175, 234, 116, 94, 248, 201, 225, 97, 235, 50, 47, 115, 172, 63, 136,
				88, 216, 115, 11, 111, 217, 114, 84, 116, 124, 231, 107, 2, 158, 1, 242, 121, 152, 106,
				204, 131, 186, 35, 93, 70, 216, 10, 237, 224, 183, 89, 95, 65, 3, 83, 185, 58, 138,
				181, 64, 187, 103, 127, 68, 50, 2, 201, 19, 17, 138, 136, 149, 185, 226, 156, 137, 175,
				110, 32, 237, 0, 217, 90, 31, 100, 228, 149, 46, 219, 175, 168, 77, 4, 143, 38, 128,
				76, 97, 0, 0, 0, 2, 0, 0, 255, 8, 153, 192, 0, 2, 27, 0, 0, 0, 1, 0, 0, 255, 2, 68,
				226, 0, 6, 11, 0, 1, 2, 3, 0, 0, 0, 2, 0, 40, 0, 0, 0, 0, 0, 0, 3, 232, 0, 0, 3, 232,
				0, 0, 0, 1, 0, 0, 0, 0, 58, 85, 116, 216, 255, 8, 153, 192, 0, 2, 27, 0, 0, 25, 0, 0,
				0, 1, 0, 0, 0, 125, 255, 2, 68, 226, 0, 6, 11, 0, 1, 5, 0, 0, 0, 0, 29, 129, 25, 192,
			];
			$nodes[0].rapid_gossip_sync.update_network_graph_no_std(&initialization_input[..], Some(1642291930)).unwrap();

			// this should have added two channels and pruned the previous one.
			assert_eq!($nodes[0].network_graph.read_only().channels().len(), 2);

			$receive.expect("Network graph not pruned within deadline");

			// all channels should now be pruned
			assert_eq!($nodes[0].network_graph.read_only().channels().len(), 0);
		}
	}

	#[test]
	fn test_not_pruning_network_graph_until_graph_sync_completion() {
		let (sender, receiver) = std::sync::mpsc::sync_channel(1);

		let (_, nodes) = create_nodes(2, "test_not_pruning_network_graph_until_graph_sync_completion");
		let data_dir = nodes[0].kv_store.get_data_dir();
		let persister = Arc::new(Persister::new(data_dir).with_graph_persistence_notifier(sender));

		let event_handler = |_: _| {};
		let background_processor = BackgroundProcessor::start(persister, event_handler, nodes[0].chain_monitor.clone(), nodes[0].node.clone(), nodes[0].rapid_gossip_sync(), nodes[0].peer_manager.clone(), nodes[0].logger.clone(), Some(nodes[0].scorer.clone()));

		do_test_not_pruning_network_graph_until_graph_sync_completion!(nodes,
			receiver.recv_timeout(Duration::from_secs(super::FIRST_NETWORK_PRUNE_TIMER * 5)),
			std::thread::sleep(Duration::from_millis(1)));

		background_processor.stop().unwrap();
	}

	#[tokio::test]
	#[cfg(feature = "futures")]
	async fn test_not_pruning_network_graph_until_graph_sync_completion_async() {
		let (sender, receiver) = std::sync::mpsc::sync_channel(1);

		let (_, nodes) = create_nodes(2, "test_not_pruning_network_graph_until_graph_sync_completion_async");
		let data_dir = nodes[0].kv_store.get_data_dir();
		let persister = Arc::new(Persister::new(data_dir).with_graph_persistence_notifier(sender));

		let (exit_sender, exit_receiver) = tokio::sync::watch::channel(());
		let bp_future = super::process_events_async(
			persister, |_: _| {async {}}, nodes[0].chain_monitor.clone(), nodes[0].node.clone(),
			nodes[0].rapid_gossip_sync(), nodes[0].peer_manager.clone(), nodes[0].logger.clone(),
			Some(nodes[0].scorer.clone()), move |dur: Duration| {
				let mut exit_receiver = exit_receiver.clone();
				Box::pin(async move {
					tokio::select! {
						_ = tokio::time::sleep(dur) => false,
						_ = exit_receiver.changed() => true,
					}
				})
			}, false,
		);

		let t1 = tokio::spawn(bp_future);
		let t2 = tokio::spawn(async move {
			do_test_not_pruning_network_graph_until_graph_sync_completion!(nodes, {
				let mut i = 0;
				loop {
					tokio::time::sleep(Duration::from_secs(super::FIRST_NETWORK_PRUNE_TIMER)).await;
					if let Ok(()) = receiver.try_recv() { break Ok::<(), ()>(()); }
					assert!(i < 5);
					i += 1;
				}
			}, tokio::time::sleep(Duration::from_millis(1)).await);
			exit_sender.send(()).unwrap();
		});
		let (r1, r2) = tokio::join!(t1, t2);
		r1.unwrap().unwrap();
		r2.unwrap()
	}

	macro_rules! do_test_payment_path_scoring {
		($nodes: expr, $receive: expr) => {
			// Ensure that we update the scorer when relevant events are processed. In this case, we ensure
			// that we update the scorer upon a payment path succeeding (note that the channel must be
			// public or else we won't score it).
			// A background event handler for FundingGenerationReady events must be hooked up to a
			// running background processor.
			let scored_scid = 4242;
			let secp_ctx = Secp256k1::new();
			let node_1_privkey = SecretKey::from_slice(&[42; 32]).unwrap();
			let node_1_id = PublicKey::from_secret_key(&secp_ctx, &node_1_privkey);

			let path = Path { hops: vec![RouteHop {
				pubkey: node_1_id,
				node_features: NodeFeatures::empty(),
				short_channel_id: scored_scid,
				channel_features: ChannelFeatures::empty(),
				fee_msat: 0,
				cltv_expiry_delta: MIN_CLTV_EXPIRY_DELTA as u32,
			}], blinded_tail: None };

			$nodes[0].scorer.lock().unwrap().expect(TestResult::PaymentFailure { path: path.clone(), short_channel_id: scored_scid });
			$nodes[0].node.push_pending_event(Event::PaymentPathFailed {
				payment_id: None,
				payment_hash: PaymentHash([42; 32]),
				payment_failed_permanently: false,
				failure: PathFailure::OnPath { network_update: None },
				path: path.clone(),
				short_channel_id: Some(scored_scid),
			});
			let event = $receive.expect("PaymentPathFailed not handled within deadline");
			match event {
				Event::PaymentPathFailed { .. } => {},
				_ => panic!("Unexpected event"),
			}

			// Ensure we'll score payments that were explicitly failed back by the destination as
			// ProbeSuccess.
			$nodes[0].scorer.lock().unwrap().expect(TestResult::ProbeSuccess { path: path.clone() });
			$nodes[0].node.push_pending_event(Event::PaymentPathFailed {
				payment_id: None,
				payment_hash: PaymentHash([42; 32]),
				payment_failed_permanently: true,
				failure: PathFailure::OnPath { network_update: None },
				path: path.clone(),
				short_channel_id: None,
			});
			let event = $receive.expect("PaymentPathFailed not handled within deadline");
			match event {
				Event::PaymentPathFailed { .. } => {},
				_ => panic!("Unexpected event"),
			}

			$nodes[0].scorer.lock().unwrap().expect(TestResult::PaymentSuccess { path: path.clone() });
			$nodes[0].node.push_pending_event(Event::PaymentPathSuccessful {
				payment_id: PaymentId([42; 32]),
				payment_hash: None,
				path: path.clone(),
			});
			let event = $receive.expect("PaymentPathSuccessful not handled within deadline");
			match event {
				Event::PaymentPathSuccessful { .. } => {},
				_ => panic!("Unexpected event"),
			}

			$nodes[0].scorer.lock().unwrap().expect(TestResult::ProbeSuccess { path: path.clone() });
			$nodes[0].node.push_pending_event(Event::ProbeSuccessful {
				payment_id: PaymentId([42; 32]),
				payment_hash: PaymentHash([42; 32]),
				path: path.clone(),
			});
			let event = $receive.expect("ProbeSuccessful not handled within deadline");
			match event {
				Event::ProbeSuccessful  { .. } => {},
				_ => panic!("Unexpected event"),
			}

			$nodes[0].scorer.lock().unwrap().expect(TestResult::ProbeFailure { path: path.clone() });
			$nodes[0].node.push_pending_event(Event::ProbeFailed {
				payment_id: PaymentId([42; 32]),
				payment_hash: PaymentHash([42; 32]),
				path,
				short_channel_id: Some(scored_scid),
			});
			let event = $receive.expect("ProbeFailure not handled within deadline");
			match event {
				Event::ProbeFailed { .. } => {},
				_ => panic!("Unexpected event"),
			}
		}
	}

	#[test]
	fn test_payment_path_scoring() {
		let (sender, receiver) = std::sync::mpsc::sync_channel(1);
		let event_handler = move |event: Event| match event {
			Event::PaymentPathFailed { .. } => sender.send(event).unwrap(),
			Event::PaymentPathSuccessful { .. } => sender.send(event).unwrap(),
			Event::ProbeSuccessful { .. } => sender.send(event).unwrap(),
			Event::ProbeFailed { .. } => sender.send(event).unwrap(),
			_ => panic!("Unexpected event: {:?}", event),
		};

		let (_, nodes) = create_nodes(1, "test_payment_path_scoring");
		let data_dir = nodes[0].kv_store.get_data_dir();
		let persister = Arc::new(Persister::new(data_dir));
		let bg_processor = BackgroundProcessor::start(persister, event_handler, nodes[0].chain_monitor.clone(), nodes[0].node.clone(), nodes[0].no_gossip_sync(), nodes[0].peer_manager.clone(), nodes[0].logger.clone(), Some(nodes[0].scorer.clone()));

		do_test_payment_path_scoring!(nodes, receiver.recv_timeout(Duration::from_secs(EVENT_DEADLINE)));

		if !std::thread::panicking() {
			bg_processor.stop().unwrap();
		}

		let log_entries = nodes[0].logger.lines.lock().unwrap();
		let expected_log = "Persisting scorer after update".to_string();
		assert_eq!(*log_entries.get(&("lightning_background_processor".to_string(), expected_log)).unwrap(), 5);
	}

	#[tokio::test]
	#[cfg(feature = "futures")]
	async fn test_payment_path_scoring_async() {
		let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
		let event_handler = move |event: Event| {
			let sender_ref = sender.clone();
			async move {
				match event {
					Event::PaymentPathFailed { .. } => { sender_ref.send(event).await.unwrap() },
					Event::PaymentPathSuccessful { .. } => { sender_ref.send(event).await.unwrap() },
					Event::ProbeSuccessful { .. } => { sender_ref.send(event).await.unwrap() },
					Event::ProbeFailed { .. } => { sender_ref.send(event).await.unwrap() },
					_ => panic!("Unexpected event: {:?}", event),
				}
			}
		};

		let (_, nodes) = create_nodes(1, "test_payment_path_scoring_async");
		let data_dir = nodes[0].kv_store.get_data_dir();
		let persister = Arc::new(Persister::new(data_dir));

		let (exit_sender, exit_receiver) = tokio::sync::watch::channel(());

		let bp_future = super::process_events_async(
			persister, event_handler, nodes[0].chain_monitor.clone(), nodes[0].node.clone(),
			nodes[0].no_gossip_sync(), nodes[0].peer_manager.clone(), nodes[0].logger.clone(),
			Some(nodes[0].scorer.clone()), move |dur: Duration| {
				let mut exit_receiver = exit_receiver.clone();
				Box::pin(async move {
					tokio::select! {
						_ = tokio::time::sleep(dur) => false,
						_ = exit_receiver.changed() => true,
					}
				})
			}, false,
		);
		let t1 = tokio::spawn(bp_future);
		let t2 = tokio::spawn(async move {
			do_test_payment_path_scoring!(nodes, receiver.recv().await);
			exit_sender.send(()).unwrap();

			let log_entries = nodes[0].logger.lines.lock().unwrap();
			let expected_log = "Persisting scorer after update".to_string();
			assert_eq!(*log_entries.get(&("lightning_background_processor".to_string(), expected_log)).unwrap(), 5);
		});

		let (r1, r2) = tokio::join!(t1, t2);
		r1.unwrap().unwrap();
		r2.unwrap()
	}
}
