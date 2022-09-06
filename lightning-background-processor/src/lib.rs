//! Utilities that take care of tasks that (1) need to happen periodically to keep Rust-Lightning
//! running properly, and (2) either can or should be run in the background. See docs for
//! [`BackgroundProcessor`] for more details on the nitty-gritty.

// Prefix these with `rustdoc::` when we update our MSRV to be >= 1.52 to remove warnings.
#![deny(broken_intra_doc_links)]
#![deny(private_intra_doc_links)]

#![deny(missing_docs)]
#![deny(unsafe_code)]

#![cfg_attr(docsrs, feature(doc_auto_cfg))]

#[macro_use] extern crate lightning;
extern crate lightning_rapid_gossip_sync;

use lightning::chain;
use lightning::chain::chaininterface::{BroadcasterInterface, FeeEstimator};
use lightning::chain::chainmonitor::{ChainMonitor, Persist};
use lightning::chain::keysinterface::{Sign, KeysInterface};
use lightning::ln::channelmanager::ChannelManager;
use lightning::ln::msgs::{ChannelMessageHandler, OnionMessageHandler, RoutingMessageHandler};
use lightning::ln::peer_handler::{CustomMessageHandler, PeerManager, SocketDescriptor};
use lightning::routing::gossip::{NetworkGraph, P2PGossipSync};
use lightning::routing::scoring::WriteableScore;
use lightning::util::events::{Event, EventHandler, EventsProvider};
use lightning::util::logger::Logger;
use lightning::util::persist::Persister;
use lightning_rapid_gossip_sync::RapidGossipSync;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use std::ops::Deref;

#[cfg(feature = "futures")]
use futures::{select, future::FutureExt};

/// `BackgroundProcessor` takes care of tasks that (1) need to happen periodically to keep
/// Rust-Lightning running properly, and (2) either can or should be run in the background. Its
/// responsibilities are:
/// * Processing [`Event`]s with a user-provided [`EventHandler`].
/// * Monitoring whether the [`ChannelManager`] needs to be re-persisted to disk, and if so,
///   writing it to disk/backups by invoking the callback given to it at startup.
///   [`ChannelManager`] persistence should be done in the background.
/// * Calling [`ChannelManager::timer_tick_occurred`] and [`PeerManager::timer_tick_occurred`]
///   at the appropriate intervals.
/// * Calling [`NetworkGraph::remove_stale_channels`] (if a [`GossipSync`] with a [`NetworkGraph`]
///   is provided to [`BackgroundProcessor::start`]).
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
/// [`Event`]: lightning::util::events::Event
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
const SCORER_PERSIST_TIMER: u64 = 30;
#[cfg(test)]
const SCORER_PERSIST_TIMER: u64 = 1;

#[cfg(not(test))]
const FIRST_NETWORK_PRUNE_TIMER: u64 = 60;
#[cfg(test)]
const FIRST_NETWORK_PRUNE_TIMER: u64 = 1;

/// Either [`P2PGossipSync`] or [`RapidGossipSync`].
pub enum GossipSync<
	P: Deref<Target = P2PGossipSync<G, A, L>>,
	R: Deref<Target = RapidGossipSync<G, L>>,
	G: Deref<Target = NetworkGraph<L>>,
	A: Deref,
	L: Deref,
>
where A::Target: chain::Access, L::Target: Logger {
	/// Gossip sync via the lightning peer-to-peer network as defined by BOLT 7.
	P2P(P),
	/// Rapid gossip sync from a trusted server.
	Rapid(R),
	/// No gossip sync.
	None,
}

impl<
	P: Deref<Target = P2PGossipSync<G, A, L>>,
	R: Deref<Target = RapidGossipSync<G, L>>,
	G: Deref<Target = NetworkGraph<L>>,
	A: Deref,
	L: Deref,
> GossipSync<P, R, G, A, L>
where A::Target: chain::Access, L::Target: Logger {
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

/// (C-not exported) as the bindings concretize everything and have constructors for us
impl<P: Deref<Target = P2PGossipSync<G, A, L>>, G: Deref<Target = NetworkGraph<L>>, A: Deref, L: Deref>
	GossipSync<P, &RapidGossipSync<G, L>, G, A, L>
where
	A::Target: chain::Access,
	L::Target: Logger,
{
	/// Initializes a new [`GossipSync::P2P`] variant.
	pub fn p2p(gossip_sync: P) -> Self {
		GossipSync::P2P(gossip_sync)
	}
}

/// (C-not exported) as the bindings concretize everything and have constructors for us
impl<'a, R: Deref<Target = RapidGossipSync<G, L>>, G: Deref<Target = NetworkGraph<L>>, L: Deref>
	GossipSync<
		&P2PGossipSync<G, &'a (dyn chain::Access + Send + Sync), L>,
		R,
		G,
		&'a (dyn chain::Access + Send + Sync),
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

/// (C-not exported) as the bindings concretize everything and have constructors for us
impl<'a, L: Deref>
	GossipSync<
		&P2PGossipSync<&'a NetworkGraph<L>, &'a (dyn chain::Access + Send + Sync), L>,
		&RapidGossipSync<&'a NetworkGraph<L>, L>,
		&'a NetworkGraph<L>,
		&'a (dyn chain::Access + Send + Sync),
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

/// Decorates an [`EventHandler`] with common functionality provided by standard [`EventHandler`]s.
struct DecoratingEventHandler<
	'a,
	E: EventHandler,
	PGS: Deref<Target = P2PGossipSync<G, A, L>>,
	RGS: Deref<Target = RapidGossipSync<G, L>>,
	G: Deref<Target = NetworkGraph<L>>,
	A: Deref,
	L: Deref,
>
where A::Target: chain::Access, L::Target: Logger {
	event_handler: E,
	gossip_sync: &'a GossipSync<PGS, RGS, G, A, L>,
}

impl<
	'a,
	E: EventHandler,
	PGS: Deref<Target = P2PGossipSync<G, A, L>>,
	RGS: Deref<Target = RapidGossipSync<G, L>>,
	G: Deref<Target = NetworkGraph<L>>,
	A: Deref,
	L: Deref,
> EventHandler for DecoratingEventHandler<'a, E, PGS, RGS, G, A, L>
where A::Target: chain::Access, L::Target: Logger {
	fn handle_event(&self, event: &Event) {
		if let Some(network_graph) = self.gossip_sync.network_graph() {
			network_graph.handle_event(event);
		}
		self.event_handler.handle_event(event);
	}
}

macro_rules! define_run_body {
	($persister: ident, $event_handler: ident, $chain_monitor: ident, $channel_manager: ident,
	 $gossip_sync: ident, $peer_manager: ident, $logger: ident, $scorer: ident,
	 $loop_exit_check: expr, $await: expr)
	=> { {
		let event_handler = DecoratingEventHandler {
			event_handler: $event_handler,
			gossip_sync: &$gossip_sync,
		};

		log_trace!($logger, "Calling ChannelManager's timer_tick_occurred on startup");
		$channel_manager.timer_tick_occurred();

		let mut last_freshness_call = Instant::now();
		let mut last_ping_call = Instant::now();
		let mut last_prune_call = Instant::now();
		let mut last_scorer_persist_call = Instant::now();
		let mut have_pruned = false;

		loop {
			$channel_manager.process_pending_events(&event_handler);
			$chain_monitor.process_pending_events(&event_handler);

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
			$peer_manager.process_events();

			// We wait up to 100ms, but track how long it takes to detect being put to sleep,
			// see `await_start`'s use below.
			let await_start = Instant::now();
			let updates_available = $await;
			let await_time = await_start.elapsed();

			if updates_available {
				log_trace!($logger, "Persisting ChannelManager...");
				$persister.persist_manager(&*$channel_manager)?;
				log_trace!($logger, "Done persisting ChannelManager.");
			}
			// Exit the loop if the background processor was requested to stop.
			if $loop_exit_check {
				log_trace!($logger, "Terminating background processor.");
				break;
			}
			if last_freshness_call.elapsed().as_secs() > FRESHNESS_TIMER {
				log_trace!($logger, "Calling ChannelManager's timer_tick_occurred");
				$channel_manager.timer_tick_occurred();
				last_freshness_call = Instant::now();
			}
			if await_time > Duration::from_secs(1) {
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
				$peer_manager.disconnect_all_peers();
				last_ping_call = Instant::now();
			} else if last_ping_call.elapsed().as_secs() > PING_TIMER {
				log_trace!($logger, "Calling PeerManager's timer_tick_occurred");
				$peer_manager.timer_tick_occurred();
				last_ping_call = Instant::now();
			}

			// Note that we want to run a graph prune once not long after startup before
			// falling back to our usual hourly prunes. This avoids short-lived clients never
			// pruning their network graph. We run once 60 seconds after startup before
			// continuing our normal cadence.
			if last_prune_call.elapsed().as_secs() > if have_pruned { NETWORK_PRUNE_TIMER } else { FIRST_NETWORK_PRUNE_TIMER } {
				// The network graph must not be pruned while rapid sync completion is pending
				log_trace!($logger, "Assessing prunability of network graph");
				if let Some(network_graph) = $gossip_sync.prunable_network_graph() {
					network_graph.remove_stale_channels();

					if let Err(e) = $persister.persist_graph(network_graph) {
						log_error!($logger, "Error: Failed to persist network graph, check your disk and permissions {}", e)
					}

					last_prune_call = Instant::now();
					have_pruned = true;
				} else {
					log_trace!($logger, "Not pruning network graph, either due to pending rapid gossip sync or absence of a prunable graph.");
				}
			}

			if last_scorer_persist_call.elapsed().as_secs() > SCORER_PERSIST_TIMER {
				if let Some(ref scorer) = $scorer {
					log_trace!($logger, "Persisting scorer");
					if let Err(e) = $persister.persist_scorer(&scorer) {
						log_error!($logger, "Error: Failed to persist scorer, check your disk and permissions {}", e)
					}
				}
				last_scorer_persist_call = Instant::now();
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

/// Processes background events in a future.
///
/// `sleeper` should return a future which completes in the given amount of time and returns a
/// boolean indicating whether the background processing should continue. Once `sleeper` returns a
/// future which outputs false, the loop will exit and this function's future will complete.
///
/// See [`BackgroundProcessor::start`] for information on which actions this handles.
#[cfg(feature = "futures")]
pub async fn process_events_async<
	'a,
	Signer: 'static + Sign,
	CA: 'static + Deref + Send + Sync,
	CF: 'static + Deref + Send + Sync,
	CW: 'static + Deref + Send + Sync,
	T: 'static + Deref + Send + Sync,
	K: 'static + Deref + Send + Sync,
	F: 'static + Deref + Send + Sync,
	G: 'static + Deref<Target = NetworkGraph<L>> + Send + Sync,
	L: 'static + Deref + Send + Sync,
	P: 'static + Deref + Send + Sync,
	Descriptor: 'static + SocketDescriptor + Send + Sync,
	CMH: 'static + Deref + Send + Sync,
	RMH: 'static + Deref + Send + Sync,
	EH: 'static + EventHandler + Send,
	PS: 'static + Deref + Send,
	M: 'static + Deref<Target = ChainMonitor<Signer, CF, T, F, L, P>> + Send + Sync,
	CM: 'static + Deref<Target = ChannelManager<Signer, CW, T, K, F, L>> + Send + Sync,
	PGS: 'static + Deref<Target = P2PGossipSync<G, CA, L>> + Send + Sync,
	RGS: 'static + Deref<Target = RapidGossipSync<G, L>> + Send,
	UMH: 'static + Deref + Send + Sync,
	PM: 'static + Deref<Target = PeerManager<Descriptor, CMH, RMH, L, UMH>> + Send + Sync,
	S: 'static + Deref<Target = SC> + Send + Sync,
	SC: WriteableScore<'a>,
	SleepFuture: core::future::Future<Output = bool>,
	Sleeper: Fn(Duration) -> SleepFuture
>(
	persister: PS, event_handler: EH, chain_monitor: M, channel_manager: CM,
	gossip_sync: GossipSync<PGS, RGS, G, CA, L>, peer_manager: PM, logger: L, scorer: Option<S>,
	sleeper: Sleeper,
) -> Result<(), std::io::Error>
where
	CA::Target: 'static + chain::Access,
	CF::Target: 'static + chain::Filter,
	CW::Target: 'static + chain::Watch<Signer>,
	T::Target: 'static + BroadcasterInterface,
	K::Target: 'static + KeysInterface<Signer = Signer>,
	F::Target: 'static + FeeEstimator,
	L::Target: 'static + Logger,
	P::Target: 'static + Persist<Signer>,
	CMH::Target: 'static + ChannelMessageHandler,
	RMH::Target: 'static + RoutingMessageHandler,
	UMH::Target: 'static + CustomMessageHandler,
	PS::Target: 'static + Persister<'a, Signer, CW, T, K, F, L, SC>,
{
	let mut should_continue = true;
	define_run_body!(persister, event_handler, chain_monitor, channel_manager,
		gossip_sync, peer_manager, logger, scorer, should_continue, {
			select! {
				_ = channel_manager.get_persistable_update_future().fuse() => true,
				cont = sleeper(Duration::from_millis(100)).fuse() => {
					should_continue = cont;
					false
				}
			}
		})
}

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
		Signer: 'static + Sign,
		CA: 'static + Deref + Send + Sync,
		CF: 'static + Deref + Send + Sync,
		CW: 'static + Deref + Send + Sync,
		T: 'static + Deref + Send + Sync,
		K: 'static + Deref + Send + Sync,
		F: 'static + Deref + Send + Sync,
		G: 'static + Deref<Target = NetworkGraph<L>> + Send + Sync,
		L: 'static + Deref + Send + Sync,
		P: 'static + Deref + Send + Sync,
		Descriptor: 'static + SocketDescriptor + Send + Sync,
		CMH: 'static + Deref + Send + Sync,
		OMH: 'static + Deref + Send + Sync,
		RMH: 'static + Deref + Send + Sync,
		EH: 'static + EventHandler + Send,
		PS: 'static + Deref + Send,
		M: 'static + Deref<Target = ChainMonitor<Signer, CF, T, F, L, P>> + Send + Sync,
		CM: 'static + Deref<Target = ChannelManager<Signer, CW, T, K, F, L>> + Send + Sync,
		PGS: 'static + Deref<Target = P2PGossipSync<G, CA, L>> + Send + Sync,
		RGS: 'static + Deref<Target = RapidGossipSync<G, L>> + Send,
		UMH: 'static + Deref + Send + Sync,
		PM: 'static + Deref<Target = PeerManager<Descriptor, CMH, RMH, OMH, L, UMH>> + Send + Sync,
		S: 'static + Deref<Target = SC> + Send + Sync,
		SC: WriteableScore<'a>,
	>(
		persister: PS, event_handler: EH, chain_monitor: M, channel_manager: CM,
		gossip_sync: GossipSync<PGS, RGS, G, CA, L>, peer_manager: PM, logger: L, scorer: Option<S>,
	) -> Self
	where
		CA::Target: 'static + chain::Access,
		CF::Target: 'static + chain::Filter,
		CW::Target: 'static + chain::Watch<Signer>,
		T::Target: 'static + BroadcasterInterface,
		K::Target: 'static + KeysInterface<Signer = Signer>,
		F::Target: 'static + FeeEstimator,
		L::Target: 'static + Logger,
		P::Target: 'static + Persist<Signer>,
		CMH::Target: 'static + ChannelMessageHandler,
		OMH::Target: 'static + OnionMessageHandler,
		RMH::Target: 'static + RoutingMessageHandler,
		UMH::Target: 'static + CustomMessageHandler,
		PS::Target: 'static + Persister<'a, Signer, CW, T, K, F, L, SC>,
	{
		let stop_thread = Arc::new(AtomicBool::new(false));
		let stop_thread_clone = stop_thread.clone();
		let handle = thread::spawn(move || -> Result<(), std::io::Error> {
			define_run_body!(persister, event_handler, chain_monitor, channel_manager,
				gossip_sync, peer_manager, logger, scorer, stop_thread.load(Ordering::Acquire),
				channel_manager.await_persistable_update_timeout(Duration::from_millis(100)))
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

impl Drop for BackgroundProcessor {
	fn drop(&mut self) {
		self.stop_and_join_thread().unwrap();
	}
}

#[cfg(test)]
mod tests {
	use bitcoin::blockdata::block::BlockHeader;
	use bitcoin::blockdata::constants::genesis_block;
	use bitcoin::blockdata::locktime::PackedLockTime;
	use bitcoin::blockdata::transaction::{Transaction, TxOut};
	use bitcoin::network::constants::Network;
	use lightning::chain::{BestBlock, Confirm, chainmonitor};
	use lightning::chain::channelmonitor::ANTI_REORG_DELAY;
	use lightning::chain::keysinterface::{InMemorySigner, Recipient, KeysInterface, KeysManager};
	use lightning::chain::transaction::OutPoint;
	use lightning::get_event_msg;
	use lightning::ln::channelmanager::{BREAKDOWN_TIMEOUT, ChainParameters, ChannelManager, SimpleArcChannelManager};
	use lightning::ln::features::{ChannelFeatures, InitFeatures};
	use lightning::ln::msgs::{ChannelMessageHandler, Init};
	use lightning::ln::peer_handler::{PeerManager, MessageHandler, SocketDescriptor, IgnoringMessageHandler};
	use lightning::routing::gossip::{NetworkGraph, P2PGossipSync};
	use lightning::util::config::UserConfig;
	use lightning::util::events::{Event, MessageSendEventsProvider, MessageSendEvent};
	use lightning::util::ser::Writeable;
	use lightning::util::test_utils;
	use lightning::util::persist::KVStorePersister;
	use lightning_invoice::payment::{InvoicePayer, Retry};
	use lightning_invoice::utils::DefaultRouter;
	use lightning_persister::FilesystemPersister;
	use std::fs;
	use std::path::PathBuf;
	use std::sync::{Arc, Mutex};
	use std::sync::mpsc::SyncSender;
	use std::time::Duration;
	use bitcoin::hashes::Hash;
	use bitcoin::TxMerkleNode;
	use lightning::routing::scoring::{FixedPenaltyScorer};
	use lightning_rapid_gossip_sync::RapidGossipSync;
	use super::{BackgroundProcessor, GossipSync, FRESHNESS_TIMER};

	const EVENT_DEADLINE: u64 = 5 * FRESHNESS_TIMER;

	#[derive(Clone, Eq, Hash, PartialEq)]
	struct TestDescriptor{}
	impl SocketDescriptor for TestDescriptor {
		fn send_data(&mut self, _data: &[u8], _resume_read: bool) -> usize {
			0
		}

		fn disconnect_socket(&mut self) {}
	}

	type ChainMonitor = chainmonitor::ChainMonitor<InMemorySigner, Arc<test_utils::TestChainSource>, Arc<test_utils::TestBroadcaster>, Arc<test_utils::TestFeeEstimator>, Arc<test_utils::TestLogger>, Arc<FilesystemPersister>>;

	type PGS = Arc<P2PGossipSync<Arc<NetworkGraph<Arc<test_utils::TestLogger>>>, Arc<test_utils::TestChainSource>, Arc<test_utils::TestLogger>>>;
	type RGS = Arc<RapidGossipSync<Arc<NetworkGraph<Arc<test_utils::TestLogger>>>, Arc<test_utils::TestLogger>>>;

	struct Node {
		node: Arc<SimpleArcChannelManager<ChainMonitor, test_utils::TestBroadcaster, test_utils::TestFeeEstimator, test_utils::TestLogger>>,
		p2p_gossip_sync: PGS,
		rapid_gossip_sync: RGS,
		peer_manager: Arc<PeerManager<TestDescriptor, Arc<test_utils::TestChannelMessageHandler>, Arc<test_utils::TestRoutingMessageHandler>, IgnoringMessageHandler, Arc<test_utils::TestLogger>, IgnoringMessageHandler>>,
		chain_monitor: Arc<ChainMonitor>,
		persister: Arc<FilesystemPersister>,
		tx_broadcaster: Arc<test_utils::TestBroadcaster>,
		network_graph: Arc<NetworkGraph<Arc<test_utils::TestLogger>>>,
		logger: Arc<test_utils::TestLogger>,
		best_block: BestBlock,
		scorer: Arc<Mutex<FixedPenaltyScorer>>,
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
			let data_dir = self.persister.get_data_dir();
			match fs::remove_dir_all(data_dir.clone()) {
				Err(e) => println!("Failed to remove test persister directory {}: {}", data_dir, e),
				_ => {}
			}
		}
	}

	struct Persister {
		graph_error: Option<(std::io::ErrorKind, &'static str)>,
		graph_persistence_notifier: Option<SyncSender<()>>,
		manager_error: Option<(std::io::ErrorKind, &'static str)>,
		scorer_error: Option<(std::io::ErrorKind, &'static str)>,
		filesystem_persister: FilesystemPersister,
	}

	impl Persister {
		fn new(data_dir: String) -> Self {
			let filesystem_persister = FilesystemPersister::new(data_dir.clone());
			Self { graph_error: None, graph_persistence_notifier: None, manager_error: None, scorer_error: None, filesystem_persister }
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

	impl KVStorePersister for Persister {
		fn persist<W: Writeable>(&self, key: &str, object: &W) -> std::io::Result<()> {
			if key == "manager" {
				if let Some((error, message)) = self.manager_error {
					return Err(std::io::Error::new(error, message))
				}
			}

			if key == "network_graph" {
				if let Some(sender) = &self.graph_persistence_notifier {
					sender.send(()).unwrap();
				};

				if let Some((error, message)) = self.graph_error {
					return Err(std::io::Error::new(error, message))
				}
			}

			if key == "scorer" {
				if let Some((error, message)) = self.scorer_error {
					return Err(std::io::Error::new(error, message))
				}
			}

			self.filesystem_persister.persist(key, object)
		}
	}

	fn get_full_filepath(filepath: String, filename: String) -> String {
		let mut path = PathBuf::from(filepath);
		path.push(filename);
		path.to_str().unwrap().to_string()
	}

	fn create_nodes(num_nodes: usize, persist_dir: String) -> Vec<Node> {
		let mut nodes = Vec::new();
		for i in 0..num_nodes {
			let tx_broadcaster = Arc::new(test_utils::TestBroadcaster{txn_broadcasted: Mutex::new(Vec::new()), blocks: Arc::new(Mutex::new(Vec::new()))});
			let fee_estimator = Arc::new(test_utils::TestFeeEstimator { sat_per_kw: Mutex::new(253) });
			let chain_source = Arc::new(test_utils::TestChainSource::new(Network::Testnet));
			let logger = Arc::new(test_utils::TestLogger::with_id(format!("node {}", i)));
			let persister = Arc::new(FilesystemPersister::new(format!("{}_persister_{}", persist_dir, i)));
			let seed = [i as u8; 32];
			let network = Network::Testnet;
			let genesis_block = genesis_block(network);
			let now = Duration::from_secs(genesis_block.header.time as u64);
			let keys_manager = Arc::new(KeysManager::new(&seed, now.as_secs(), now.subsec_nanos()));
			let chain_monitor = Arc::new(chainmonitor::ChainMonitor::new(Some(chain_source.clone()), tx_broadcaster.clone(), logger.clone(), fee_estimator.clone(), persister.clone()));
			let best_block = BestBlock::from_genesis(network);
			let params = ChainParameters { network, best_block };
			let manager = Arc::new(ChannelManager::new(fee_estimator.clone(), chain_monitor.clone(), tx_broadcaster.clone(), logger.clone(), keys_manager.clone(), UserConfig::default(), params));
			let network_graph = Arc::new(NetworkGraph::new(genesis_block.header.block_hash(), logger.clone()));
			let p2p_gossip_sync = Arc::new(P2PGossipSync::new(network_graph.clone(), Some(chain_source.clone()), logger.clone()));
			let rapid_gossip_sync = Arc::new(RapidGossipSync::new(network_graph.clone()));
			let msg_handler = MessageHandler { chan_handler: Arc::new(test_utils::TestChannelMessageHandler::new()), route_handler: Arc::new(test_utils::TestRoutingMessageHandler::new()), onion_message_handler: IgnoringMessageHandler{}};
			let peer_manager = Arc::new(PeerManager::new(msg_handler, keys_manager.get_node_secret(Recipient::Node).unwrap(), 0, &seed, logger.clone(), IgnoringMessageHandler{}));
			let scorer = Arc::new(Mutex::new(test_utils::TestScorer::with_penalty(0)));
			let node = Node { node: manager, p2p_gossip_sync, rapid_gossip_sync, peer_manager, chain_monitor, persister, tx_broadcaster, network_graph, logger, best_block, scorer };
			nodes.push(node);
		}

		for i in 0..num_nodes {
			for j in (i+1)..num_nodes {
				nodes[i].node.peer_connected(&nodes[j].node.get_our_node_id(), &Init { features: InitFeatures::known(), remote_network_address: None });
				nodes[j].node.peer_connected(&nodes[i].node.get_our_node_id(), &Init { features: InitFeatures::known(), remote_network_address: None });
			}
		}

		nodes
	}

	macro_rules! open_channel {
		($node_a: expr, $node_b: expr, $channel_value: expr) => {{
			begin_open_channel!($node_a, $node_b, $channel_value);
			let events = $node_a.node.get_and_clear_pending_events();
			assert_eq!(events.len(), 1);
			let (temporary_channel_id, tx) = handle_funding_generation_ready!(&events[0], $channel_value);
			end_open_channel!($node_a, $node_b, temporary_channel_id, tx);
			tx
		}}
	}

	macro_rules! begin_open_channel {
		($node_a: expr, $node_b: expr, $channel_value: expr) => {{
			$node_a.node.create_channel($node_b.node.get_our_node_id(), $channel_value, 100, 42, None).unwrap();
			$node_b.node.handle_open_channel(&$node_a.node.get_our_node_id(), InitFeatures::known(), &get_event_msg!($node_a, MessageSendEvent::SendOpenChannel, $node_b.node.get_our_node_id()));
			$node_a.node.handle_accept_channel(&$node_b.node.get_our_node_id(), InitFeatures::known(), &get_event_msg!($node_b, MessageSendEvent::SendAcceptChannel, $node_a.node.get_our_node_id()));
		}}
	}

	macro_rules! handle_funding_generation_ready {
		($event: expr, $channel_value: expr) => {{
			match $event {
				&Event::FundingGenerationReady { temporary_channel_id, channel_value_satoshis, ref output_script, user_channel_id, .. } => {
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

	macro_rules! end_open_channel {
		($node_a: expr, $node_b: expr, $temporary_channel_id: expr, $tx: expr) => {{
			$node_a.node.funding_transaction_generated(&$temporary_channel_id, &$node_b.node.get_our_node_id(), $tx.clone()).unwrap();
			$node_b.node.handle_funding_created(&$node_a.node.get_our_node_id(), &get_event_msg!($node_a, MessageSendEvent::SendFundingCreated, $node_b.node.get_our_node_id()));
			$node_a.node.handle_funding_signed(&$node_b.node.get_our_node_id(), &get_event_msg!($node_b, MessageSendEvent::SendFundingSigned, $node_a.node.get_our_node_id()));
		}}
	}

	fn confirm_transaction_depth(node: &mut Node, tx: &Transaction, depth: u32) {
		for i in 1..=depth {
			let prev_blockhash = node.best_block.block_hash();
			let height = node.best_block.height() + 1;
			let header = BlockHeader { version: 0x20000000, prev_blockhash, merkle_root: TxMerkleNode::all_zeros(), time: height, bits: 42, nonce: 42 };
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
		let nodes = create_nodes(2, "test_background_processor".to_string());

		// Go through the channel creation process so that each node has something to persist. Since
		// open_channel consumes events, it must complete before starting BackgroundProcessor to
		// avoid a race with processing events.
		let tx = open_channel!(nodes[0], nodes[1], 100000);

		// Initiate the background processors to watch each node.
		let data_dir = nodes[0].persister.get_data_dir();
		let persister = Arc::new(Persister::new(data_dir));
		let event_handler = |_: &_| {};
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
		let filepath = get_full_filepath("test_background_processor_persister_0".to_string(), "manager".to_string());
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
		let filepath = get_full_filepath("test_background_processor_persister_0".to_string(), "network_graph".to_string());
		check_persisted_data!(nodes[0].network_graph, filepath.clone());

		// Check scorer is persisted
		let filepath = get_full_filepath("test_background_processor_persister_0".to_string(), "scorer".to_string());
		check_persisted_data!(nodes[0].scorer, filepath.clone());

		assert!(bg_processor.stop().is_ok());
	}

	#[test]
	fn test_timer_tick_called() {
		// Test that ChannelManager's and PeerManager's `timer_tick_occurred` is called every
		// `FRESHNESS_TIMER`.
		let nodes = create_nodes(1, "test_timer_tick_called".to_string());
		let data_dir = nodes[0].persister.get_data_dir();
		let persister = Arc::new(Persister::new(data_dir));
		let event_handler = |_: &_| {};
		let bg_processor = BackgroundProcessor::start(persister, event_handler, nodes[0].chain_monitor.clone(), nodes[0].node.clone(), nodes[0].no_gossip_sync(), nodes[0].peer_manager.clone(), nodes[0].logger.clone(), Some(nodes[0].scorer.clone()));
		loop {
			let log_entries = nodes[0].logger.lines.lock().unwrap();
			let desired_log = "Calling ChannelManager's timer_tick_occurred".to_string();
			let second_desired_log = "Calling PeerManager's timer_tick_occurred".to_string();
			if log_entries.get(&("lightning_background_processor".to_string(), desired_log)).is_some() &&
					log_entries.get(&("lightning_background_processor".to_string(), second_desired_log)).is_some() {
				break
			}
		}

		assert!(bg_processor.stop().is_ok());
	}

	#[test]
	fn test_channel_manager_persist_error() {
		// Test that if we encounter an error during manager persistence, the thread panics.
		let nodes = create_nodes(2, "test_persist_error".to_string());
		open_channel!(nodes[0], nodes[1], 100000);

		let data_dir = nodes[0].persister.get_data_dir();
		let persister = Arc::new(Persister::new(data_dir).with_manager_error(std::io::ErrorKind::Other, "test"));
		let event_handler = |_: &_| {};
		let bg_processor = BackgroundProcessor::start(persister, event_handler, nodes[0].chain_monitor.clone(), nodes[0].node.clone(), nodes[0].no_gossip_sync(), nodes[0].peer_manager.clone(), nodes[0].logger.clone(), Some(nodes[0].scorer.clone()));
		match bg_processor.join() {
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
		let nodes = create_nodes(2, "test_persist_network_graph_error".to_string());
		let data_dir = nodes[0].persister.get_data_dir();
		let persister = Arc::new(Persister::new(data_dir).with_graph_error(std::io::ErrorKind::Other, "test"));
		let event_handler = |_: &_| {};
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
		let nodes = create_nodes(2, "test_persist_scorer_error".to_string());
		let data_dir = nodes[0].persister.get_data_dir();
		let persister = Arc::new(Persister::new(data_dir).with_scorer_error(std::io::ErrorKind::Other, "test"));
		let event_handler = |_: &_| {};
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
		let mut nodes = create_nodes(2, "test_background_event_handling".to_string());
		let channel_value = 100000;
		let data_dir = nodes[0].persister.get_data_dir();
		let persister = Arc::new(Persister::new(data_dir.clone()));

		// Set up a background event handler for FundingGenerationReady events.
		let (sender, receiver) = std::sync::mpsc::sync_channel(1);
		let event_handler = move |event: &Event| {
			sender.send(handle_funding_generation_ready!(event, channel_value)).unwrap();
		};
		let bg_processor = BackgroundProcessor::start(persister, event_handler, nodes[0].chain_monitor.clone(), nodes[0].node.clone(), nodes[0].no_gossip_sync(), nodes[0].peer_manager.clone(), nodes[0].logger.clone(), Some(nodes[0].scorer.clone()));

		// Open a channel and check that the FundingGenerationReady event was handled.
		begin_open_channel!(nodes[0], nodes[1], channel_value);
		let (temporary_channel_id, funding_tx) = receiver
			.recv_timeout(Duration::from_secs(EVENT_DEADLINE))
			.expect("FundingGenerationReady not handled within deadline");
		end_open_channel!(nodes[0], nodes[1], temporary_channel_id, funding_tx);

		// Confirm the funding transaction.
		confirm_transaction(&mut nodes[0], &funding_tx);
		let as_funding = get_event_msg!(nodes[0], MessageSendEvent::SendChannelReady, nodes[1].node.get_our_node_id());
		confirm_transaction(&mut nodes[1], &funding_tx);
		let bs_funding = get_event_msg!(nodes[1], MessageSendEvent::SendChannelReady, nodes[0].node.get_our_node_id());
		nodes[0].node.handle_channel_ready(&nodes[1].node.get_our_node_id(), &bs_funding);
		let _as_channel_update = get_event_msg!(nodes[0], MessageSendEvent::SendChannelUpdate, nodes[1].node.get_our_node_id());
		nodes[1].node.handle_channel_ready(&nodes[0].node.get_our_node_id(), &as_funding);
		let _bs_channel_update = get_event_msg!(nodes[1], MessageSendEvent::SendChannelUpdate, nodes[0].node.get_our_node_id());

		assert!(bg_processor.stop().is_ok());

		// Set up a background event handler for SpendableOutputs events.
		let (sender, receiver) = std::sync::mpsc::sync_channel(1);
		let event_handler = move |event: &Event| sender.send(event.clone()).unwrap();
		let persister = Arc::new(Persister::new(data_dir));
		let bg_processor = BackgroundProcessor::start(persister, event_handler, nodes[0].chain_monitor.clone(), nodes[0].node.clone(), nodes[0].no_gossip_sync(), nodes[0].peer_manager.clone(), nodes[0].logger.clone(), Some(nodes[0].scorer.clone()));

		// Force close the channel and check that the SpendableOutputs event was handled.
		nodes[0].node.force_close_broadcasting_latest_txn(&nodes[0].node.list_channels()[0].channel_id, &nodes[1].node.get_our_node_id()).unwrap();
		let commitment_tx = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().pop().unwrap();
		confirm_transaction_depth(&mut nodes[0], &commitment_tx, BREAKDOWN_TIMEOUT as u32);
		let event = receiver
			.recv_timeout(Duration::from_secs(EVENT_DEADLINE))
			.expect("SpendableOutputs not handled within deadline");
		match event {
			Event::SpendableOutputs { .. } => {},
			Event::ChannelClosed { .. } => {},
			_ => panic!("Unexpected event: {:?}", event),
		}

		assert!(bg_processor.stop().is_ok());
	}

	#[test]
	fn test_scorer_persistence() {
		let nodes = create_nodes(2, "test_scorer_persistence".to_string());
		let data_dir = nodes[0].persister.get_data_dir();
		let persister = Arc::new(Persister::new(data_dir));
		let event_handler = |_: &_| {};
		let bg_processor = BackgroundProcessor::start(persister, event_handler, nodes[0].chain_monitor.clone(), nodes[0].node.clone(), nodes[0].no_gossip_sync(), nodes[0].peer_manager.clone(), nodes[0].logger.clone(), Some(nodes[0].scorer.clone()));

		loop {
			let log_entries = nodes[0].logger.lines.lock().unwrap();
			let expected_log = "Persisting scorer".to_string();
			if log_entries.get(&("lightning_background_processor".to_string(), expected_log)).is_some() {
				break
			}
		}

		assert!(bg_processor.stop().is_ok());
	}

	#[test]
	fn test_not_pruning_network_graph_until_graph_sync_completion() {
		let nodes = create_nodes(2, "test_not_pruning_network_graph_until_graph_sync_completion".to_string());
		let data_dir = nodes[0].persister.get_data_dir();
		let (sender, receiver) = std::sync::mpsc::sync_channel(1);
		let persister = Arc::new(Persister::new(data_dir.clone()).with_graph_persistence_notifier(sender));
		let network_graph = nodes[0].network_graph.clone();
		let features = ChannelFeatures::empty();
		network_graph.add_channel_from_partial_announcement(42, 53, features, nodes[0].node.get_our_node_id(), nodes[1].node.get_our_node_id())
			.expect("Failed to update channel from partial announcement");
		let original_graph_description = network_graph.to_string();
		assert!(original_graph_description.contains("42: features: 0000, node_one:"));
		assert_eq!(network_graph.read_only().channels().len(), 1);

		let event_handler = |_: &_| {};
		let background_processor = BackgroundProcessor::start(persister, event_handler, nodes[0].chain_monitor.clone(), nodes[0].node.clone(), nodes[0].rapid_gossip_sync(), nodes[0].peer_manager.clone(), nodes[0].logger.clone(), Some(nodes[0].scorer.clone()));

		loop {
			let log_entries = nodes[0].logger.lines.lock().unwrap();
			let expected_log_a = "Assessing prunability of network graph".to_string();
			let expected_log_b = "Not pruning network graph, either due to pending rapid gossip sync or absence of a prunable graph.".to_string();
			if log_entries.get(&("lightning_background_processor".to_string(), expected_log_a)).is_some() &&
				log_entries.get(&("lightning_background_processor".to_string(), expected_log_b)).is_some() {
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
		nodes[0].rapid_gossip_sync.update_network_graph(&initialization_input[..]).unwrap();

		// this should have added two channels
		assert_eq!(network_graph.read_only().channels().len(), 3);

		let _ = receiver
			.recv_timeout(Duration::from_secs(super::FIRST_NETWORK_PRUNE_TIMER * 5))
			.expect("Network graph not pruned within deadline");

		background_processor.stop().unwrap();

		// all channels should now be pruned
		assert_eq!(network_graph.read_only().channels().len(), 0);
	}

	#[test]
	fn test_invoice_payer() {
		let keys_manager = test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();
		let nodes = create_nodes(2, "test_invoice_payer".to_string());

		// Initiate the background processors to watch each node.
		let data_dir = nodes[0].persister.get_data_dir();
		let persister = Arc::new(Persister::new(data_dir));
		let router = DefaultRouter::new(Arc::clone(&nodes[0].network_graph), Arc::clone(&nodes[0].logger), random_seed_bytes);
		let invoice_payer = Arc::new(InvoicePayer::new(Arc::clone(&nodes[0].node), router, Arc::clone(&nodes[0].scorer), Arc::clone(&nodes[0].logger), |_: &_| {}, Retry::Attempts(2)));
		let event_handler = Arc::clone(&invoice_payer);
		let bg_processor = BackgroundProcessor::start(persister, event_handler, nodes[0].chain_monitor.clone(), nodes[0].node.clone(), nodes[0].no_gossip_sync(), nodes[0].peer_manager.clone(), nodes[0].logger.clone(), Some(nodes[0].scorer.clone()));
		assert!(bg_processor.stop().is_ok());
	}
}
