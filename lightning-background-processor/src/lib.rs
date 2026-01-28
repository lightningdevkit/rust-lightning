// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Utilities that take care of tasks that (1) need to happen periodically to keep Rust-Lightning
//! running properly, and (2) either can or should be run in the background.
#![cfg_attr(feature = "std", doc = "See docs for [`BackgroundProcessor`] for more details.")]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(rustdoc::private_intra_doc_links)]
#![deny(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]

#[cfg(any(test, feature = "std"))]
extern crate core;

#[cfg(not(feature = "std"))]
extern crate alloc;

#[macro_use]
extern crate lightning;
extern crate lightning_rapid_gossip_sync;

mod fwd_batch;

use fwd_batch::BatchDelay;

use lightning::chain;
use lightning::chain::chaininterface::{BroadcasterInterface, FeeEstimator};
use lightning::chain::chainmonitor::{ChainMonitor, Persist};
#[cfg(feature = "std")]
use lightning::events::EventHandler;
#[cfg(feature = "std")]
use lightning::events::EventsProvider;
use lightning::events::ReplayEvent;
use lightning::events::{Event, PathFailure};
use lightning::util::ser::Writeable;

#[cfg(not(c_bindings))]
use lightning::io::Error;
use lightning::ln::channelmanager::AChannelManager;
use lightning::ln::msgs::OnionMessageHandler;
use lightning::ln::peer_handler::APeerManager;
use lightning::onion_message::messenger::AOnionMessenger;
use lightning::routing::gossip::{NetworkGraph, P2PGossipSync};
use lightning::routing::scoring::{ScoreUpdate, WriteableScore};
use lightning::routing::utxo::UtxoLookup;
use lightning::sign::{
	ChangeDestinationSource, ChangeDestinationSourceSync, EntropySource, OutputSpender,
};
#[cfg(not(c_bindings))]
use lightning::util::async_poll::MaybeSend;
use lightning::util::logger::Logger;
use lightning::util::persist::{
	KVStore, KVStoreSync, KVStoreSyncWrapper, CHANNEL_MANAGER_PERSISTENCE_KEY,
	CHANNEL_MANAGER_PERSISTENCE_PRIMARY_NAMESPACE, CHANNEL_MANAGER_PERSISTENCE_SECONDARY_NAMESPACE,
	NETWORK_GRAPH_PERSISTENCE_KEY, NETWORK_GRAPH_PERSISTENCE_PRIMARY_NAMESPACE,
	NETWORK_GRAPH_PERSISTENCE_SECONDARY_NAMESPACE, SCORER_PERSISTENCE_KEY,
	SCORER_PERSISTENCE_PRIMARY_NAMESPACE, SCORER_PERSISTENCE_SECONDARY_NAMESPACE,
};
use lightning::util::sweep::{OutputSweeper, OutputSweeperSync};
use lightning::util::wakers::Future;
#[cfg(feature = "std")]
use lightning::util::wakers::Sleeper;
use lightning_rapid_gossip_sync::RapidGossipSync;

use lightning_liquidity::ALiquidityManager;
#[cfg(feature = "std")]
use lightning_liquidity::ALiquidityManagerSync;

use core::ops::Deref;
use core::time::Duration;

#[cfg(feature = "std")]
use core::sync::atomic::{AtomicBool, Ordering};
#[cfg(feature = "std")]
use std::sync::Arc;
#[cfg(feature = "std")]
use std::thread::{self, JoinHandle};
#[cfg(feature = "std")]
use std::time::Instant;

#[cfg(not(feature = "std"))]
use alloc::boxed::Box;
#[cfg(all(not(c_bindings), not(feature = "std")))]
use alloc::string::String;
#[cfg(all(not(c_bindings), not(feature = "std")))]
use alloc::sync::Arc;
#[cfg(all(not(c_bindings), not(feature = "std")))]
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
/// [`ChannelManager`]: lightning::ln::channelmanager::ChannelManager
/// [`ChannelManager::timer_tick_occurred`]: lightning::ln::channelmanager::ChannelManager::timer_tick_occurred
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
const FRESHNESS_TIMER: Duration = Duration::from_secs(60);
#[cfg(test)]
const FRESHNESS_TIMER: Duration = Duration::from_secs(1);

#[cfg(all(not(test), not(debug_assertions)))]
const PING_TIMER: Duration = Duration::from_secs(10);
/// Signature operations take a lot longer without compiler optimisations.
/// Increasing the ping timer allows for this but slower devices will be disconnected if the
/// timeout is reached.
#[cfg(all(not(test), debug_assertions))]
const PING_TIMER: Duration = Duration::from_secs(30);
#[cfg(test)]
const PING_TIMER: Duration = Duration::from_secs(1);

#[cfg(not(test))]
const ONION_MESSAGE_HANDLER_TIMER: Duration = Duration::from_secs(10);
#[cfg(test)]
const ONION_MESSAGE_HANDLER_TIMER: Duration = Duration::from_secs(1);

/// Prune the network graph of stale entries hourly.
const NETWORK_PRUNE_TIMER: Duration = Duration::from_secs(60 * 60);

#[cfg(not(test))]
const SCORER_PERSIST_TIMER: Duration = Duration::from_secs(60 * 5);
#[cfg(test)]
const SCORER_PERSIST_TIMER: Duration = Duration::from_secs(1);

#[cfg(not(test))]
const FIRST_NETWORK_PRUNE_TIMER: Duration = Duration::from_secs(60);
#[cfg(test)]
const FIRST_NETWORK_PRUNE_TIMER: Duration = Duration::from_secs(1);

#[cfg(not(test))]
const REBROADCAST_TIMER: Duration = Duration::from_secs(30);
#[cfg(test)]
const REBROADCAST_TIMER: Duration = Duration::from_secs(1);

#[cfg(not(test))]
const SWEEPER_TIMER: Duration = Duration::from_secs(30);
#[cfg(test)]
const SWEEPER_TIMER: Duration = Duration::from_secs(1);

#[cfg(not(test))]
const FIRST_ARCHIVE_STALE_MONITORS_TIMER: Duration = Duration::from_secs(15);
#[cfg(test)]
const FIRST_ARCHIVE_STALE_MONITORS_TIMER: Duration = Duration::ZERO;

#[cfg(not(test))]
const ARCHIVE_STALE_MONITORS_TIMER: Duration = Duration::from_secs(60 * 10);
#[cfg(test)]
const ARCHIVE_STALE_MONITORS_TIMER: Duration = Duration::from_secs(1);

/// core::cmp::min is not currently const, so we define a trivial (and equivalent) replacement
const fn min_duration(a: Duration, b: Duration) -> Duration {
	if a.as_nanos() < b.as_nanos() {
		a
	} else {
		b
	}
}
const FASTEST_TIMER: Duration = min_duration(
	min_duration(FRESHNESS_TIMER, PING_TIMER),
	min_duration(SCORER_PERSIST_TIMER, min_duration(FIRST_NETWORK_PRUNE_TIMER, REBROADCAST_TIMER)),
);

/// Either [`P2PGossipSync`] or [`RapidGossipSync`].
pub enum GossipSync<
	P: Deref<Target = P2PGossipSync<G, U, L>>,
	R: Deref<Target = RapidGossipSync<G, L>>,
	G: Deref<Target = NetworkGraph<L>>,
	U: Deref,
	L: Deref,
> where
	U::Target: UtxoLookup,
	L::Target: Logger,
{
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
where
	U::Target: UtxoLookup,
	L::Target: Logger,
{
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

	fn validation_completion_future(&self) -> Option<Future> {
		match self {
			GossipSync::P2P(gossip_sync) => Some(gossip_sync.validation_completion_future()),
			GossipSync::Rapid(_) => None,
			GossipSync::None => None,
		}
	}
}

/// This is not exported to bindings users as the bindings concretize everything and have constructors for us
impl<
		P: Deref<Target = P2PGossipSync<G, U, L>>,
		G: Deref<Target = NetworkGraph<L>>,
		U: Deref,
		L: Deref,
	> GossipSync<P, &RapidGossipSync<G, L>, G, U, L>
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
impl<
		'a,
		R: Deref<Target = RapidGossipSync<G, L>>,
		G: Deref<Target = NetworkGraph<L>>,
		L: Deref,
	>
	GossipSync<
		&P2PGossipSync<G, &'a (dyn UtxoLookup + Send + Sync), L>,
		R,
		G,
		&'a (dyn UtxoLookup + Send + Sync),
		L,
	> where
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
	> where
	L::Target: Logger,
{
	/// Initializes a new [`GossipSync::None`] variant.
	pub fn none() -> Self {
		GossipSync::None
	}
}

fn handle_network_graph_update<L: Deref>(network_graph: &NetworkGraph<L>, event: &Event)
where
	L::Target: Logger,
{
	if let Event::PaymentPathFailed {
		failure: PathFailure::OnPath { network_update: Some(ref upd) },
		..
	} = event
	{
		network_graph.handle_network_update(upd);
	}
}

/// Updates scorer based on event and returns whether an update occurred so we can decide whether
/// to persist.
fn update_scorer<'a, S: Deref<Target = SC>, SC: 'a + WriteableScore<'a>>(
	scorer: &'a S, event: &Event, duration_since_epoch: Duration,
) -> bool {
	match event {
		Event::PaymentPathFailed { ref path, short_channel_id: Some(scid), .. } => {
			let mut score = scorer.write_lock();
			score.payment_path_failed(path, *scid, duration_since_epoch);
		},
		Event::PaymentPathFailed { ref path, payment_failed_permanently: true, .. } => {
			// Reached if the destination explicitly failed it back. We treat this as a successful probe
			// because the payment made it all the way to the destination with sufficient liquidity.
			let mut score = scorer.write_lock();
			score.probe_successful(path, duration_since_epoch);
		},
		Event::PaymentPathSuccessful { path, .. } => {
			let mut score = scorer.write_lock();
			score.payment_path_successful(path, duration_since_epoch);
		},
		Event::ProbeSuccessful { path, .. } => {
			let mut score = scorer.write_lock();
			score.probe_successful(path, duration_since_epoch);
		},
		Event::ProbeFailed { path, short_channel_id: Some(scid), .. } => {
			let mut score = scorer.write_lock();
			score.probe_failed(path, *scid, duration_since_epoch);
		},
		_ => return false,
	}
	true
}

#[cfg(all(not(c_bindings), feature = "std"))]
type ScorerWrapper<T> = std::sync::RwLock<T>;

#[cfg(all(not(c_bindings), not(feature = "std")))]
type ScorerWrapper<T> = core::cell::RefCell<T>;

#[cfg(not(c_bindings))]
type DynRouter = lightning::routing::router::DefaultRouter<
	&'static NetworkGraph<&'static (dyn Logger + Send + Sync)>,
	&'static (dyn Logger + Send + Sync),
	&'static (dyn EntropySource + Send + Sync),
	&'static ScorerWrapper<
		lightning::routing::scoring::ProbabilisticScorer<
			&'static NetworkGraph<&'static (dyn Logger + Send + Sync)>,
			&'static (dyn Logger + Send + Sync),
		>,
	>,
	lightning::routing::scoring::ProbabilisticScoringFeeParameters,
	lightning::routing::scoring::ProbabilisticScorer<
		&'static NetworkGraph<&'static (dyn Logger + Send + Sync)>,
		&'static (dyn Logger + Send + Sync),
	>,
>;

#[cfg(not(c_bindings))]
type DynMessageRouter = lightning::onion_message::messenger::DefaultMessageRouter<
	&'static NetworkGraph<&'static (dyn Logger + Send + Sync)>,
	&'static (dyn Logger + Send + Sync),
	&'static (dyn EntropySource + Send + Sync),
>;

#[cfg(all(not(c_bindings), not(taproot)))]
type DynSignerProvider = dyn lightning::sign::SignerProvider<EcdsaSigner = lightning::sign::InMemorySigner>
	+ Send
	+ Sync;

#[cfg(all(not(c_bindings), taproot))]
type DynSignerProvider = (dyn lightning::sign::SignerProvider<
	EcdsaSigner = lightning::sign::InMemorySigner,
	TaprootSigner = lightning::sign::InMemorySigner,
> + Send
     + Sync);

#[cfg(not(c_bindings))]
type DynChannelManager = lightning::ln::channelmanager::ChannelManager<
	&'static (dyn chain::Watch<lightning::sign::InMemorySigner> + Send + Sync),
	&'static (dyn BroadcasterInterface + Send + Sync),
	&'static (dyn EntropySource + Send + Sync),
	&'static (dyn lightning::sign::NodeSigner + Send + Sync),
	&'static DynSignerProvider,
	&'static (dyn FeeEstimator + Send + Sync),
	&'static DynRouter,
	&'static DynMessageRouter,
	&'static (dyn Logger + Send + Sync),
>;

/// When initializing a background processor without an onion messenger, this can be used to avoid
/// specifying a concrete `OnionMessenger` type.
#[cfg(not(c_bindings))]
pub const NO_ONION_MESSENGER: Option<
	Arc<
		dyn AOnionMessenger<
				EntropySource = dyn EntropySource + Send + Sync,
				ES = &(dyn EntropySource + Send + Sync),
				NodeSigner = dyn lightning::sign::NodeSigner + Send + Sync,
				NS = &(dyn lightning::sign::NodeSigner + Send + Sync),
				Logger = dyn Logger + Send + Sync,
				L = &'static (dyn Logger + Send + Sync),
				NodeIdLookUp = DynChannelManager,
				NL = &'static DynChannelManager,
				MessageRouter = DynMessageRouter,
				MR = &'static DynMessageRouter,
				OffersMessageHandler = lightning::ln::peer_handler::IgnoringMessageHandler,
				OMH = &'static lightning::ln::peer_handler::IgnoringMessageHandler,
				AsyncPaymentsMessageHandler = lightning::ln::peer_handler::IgnoringMessageHandler,
				APH = &'static lightning::ln::peer_handler::IgnoringMessageHandler,
				DNSResolverMessageHandler = lightning::ln::peer_handler::IgnoringMessageHandler,
				DRH = &'static lightning::ln::peer_handler::IgnoringMessageHandler,
				CustomOnionMessageHandler = lightning::ln::peer_handler::IgnoringMessageHandler,
				CMH = &'static lightning::ln::peer_handler::IgnoringMessageHandler,
			> + Send
			+ Sync,
	>,
> = None;

#[cfg(not(c_bindings))]
/// A panicking implementation of [`KVStore`] that is used in [`NO_LIQUIDITY_MANAGER`].
pub struct DummyKVStore;

#[cfg(not(c_bindings))]
impl KVStore for DummyKVStore {
	fn read(
		&self, _: &str, _: &str, _: &str,
	) -> impl core::future::Future<Output = Result<Vec<u8>, Error>> + MaybeSend + 'static {
		async { unimplemented!() }
	}

	fn write(
		&self, _: &str, _: &str, _: &str, _: Vec<u8>,
	) -> impl core::future::Future<Output = Result<(), Error>> + MaybeSend + 'static {
		async { unimplemented!() }
	}

	fn remove(
		&self, _: &str, _: &str, _: &str, _: bool,
	) -> impl core::future::Future<Output = Result<(), Error>> + MaybeSend + 'static {
		async { unimplemented!() }
	}

	fn list(
		&self, _: &str, _: &str,
	) -> impl core::future::Future<Output = Result<Vec<String>, Error>> + MaybeSend + 'static {
		async { unimplemented!() }
	}
}

/// When initializing a background processor without a liquidity manager, this can be used to avoid
/// specifying a concrete `LiquidityManager` type.
#[cfg(not(c_bindings))]
pub const NO_LIQUIDITY_MANAGER: Option<
	Arc<
		dyn ALiquidityManager<
				EntropySource = dyn EntropySource + Send + Sync,
				ES = &(dyn EntropySource + Send + Sync),
				NodeSigner = dyn lightning::sign::NodeSigner + Send + Sync,
				NS = &(dyn lightning::sign::NodeSigner + Send + Sync),
				AChannelManager = DynChannelManager,
				CM = &DynChannelManager,
				Filter = dyn chain::Filter + Send + Sync,
				C = &(dyn chain::Filter + Send + Sync),
				KVStore = DummyKVStore,
				K = &DummyKVStore,
				TimeProvider = dyn lightning_liquidity::utils::time::TimeProvider + Send + Sync,
				TP = &(dyn lightning_liquidity::utils::time::TimeProvider + Send + Sync),
				BroadcasterInterface = dyn lightning::chain::chaininterface::BroadcasterInterface
				                           + Send
				                           + Sync,
				T = &(dyn BroadcasterInterface + Send + Sync),
			> + Send
			+ Sync,
	>,
> = None;

/// When initializing a background processor without a liquidity manager, this can be used to avoid
/// specifying a concrete `LiquidityManagerSync` type.
#[cfg(all(not(c_bindings), feature = "std"))]
pub const NO_LIQUIDITY_MANAGER_SYNC: Option<
	Arc<
		dyn ALiquidityManagerSync<
				EntropySource = dyn EntropySource + Send + Sync,
				ES = &(dyn EntropySource + Send + Sync),
				NodeSigner = dyn lightning::sign::NodeSigner + Send + Sync,
				NS = &(dyn lightning::sign::NodeSigner + Send + Sync),
				AChannelManager = DynChannelManager,
				CM = &DynChannelManager,
				Filter = dyn chain::Filter + Send + Sync,
				C = &(dyn chain::Filter + Send + Sync),
				KVStoreSync = dyn lightning::util::persist::KVStoreSync + Send + Sync,
				KS = &(dyn lightning::util::persist::KVStoreSync + Send + Sync),
				TimeProvider = dyn lightning_liquidity::utils::time::TimeProvider + Send + Sync,
				TP = &(dyn lightning_liquidity::utils::time::TimeProvider + Send + Sync),
				BroadcasterInterface = dyn lightning::chain::chaininterface::BroadcasterInterface
				                           + Send
				                           + Sync,
				T = &(dyn BroadcasterInterface + Send + Sync),
			> + Send
			+ Sync,
	>,
> = None;

pub(crate) mod futures_util {
	use core::future::Future;
	use core::marker::Unpin;
	use core::pin::Pin;
	use core::task::{Poll, RawWaker, RawWakerVTable, Waker};
	pub(crate) struct Selector<
		A: Future<Output = bool> + Unpin,
		B: Future<Output = ()> + Unpin,
		C: Future<Output = ()> + Unpin,
		D: Future<Output = ()> + Unpin,
		E: Future<Output = ()> + Unpin,
		F: Future<Output = ()> + Unpin,
	> {
		pub a: A,
		pub b: B,
		pub c: C,
		pub d: D,
		pub e: E,
		pub f: F,
	}

	pub(crate) enum SelectorOutput {
		A(bool),
		B,
		C,
		D,
		E,
		F,
	}

	impl<
			A: Future<Output = bool> + Unpin,
			B: Future<Output = ()> + Unpin,
			C: Future<Output = ()> + Unpin,
			D: Future<Output = ()> + Unpin,
			E: Future<Output = ()> + Unpin,
			F: Future<Output = ()> + Unpin,
		> Future for Selector<A, B, C, D, E, F>
	{
		type Output = SelectorOutput;
		fn poll(
			mut self: Pin<&mut Self>, ctx: &mut core::task::Context<'_>,
		) -> Poll<SelectorOutput> {
			// Bias the selector so it first polls the sleeper future, allowing to exit immediately
			// if the flag is set.
			match Pin::new(&mut self.a).poll(ctx) {
				Poll::Ready(res) => {
					return Poll::Ready(SelectorOutput::A(res));
				},
				Poll::Pending => {},
			}
			match Pin::new(&mut self.b).poll(ctx) {
				Poll::Ready(()) => {
					return Poll::Ready(SelectorOutput::B);
				},
				Poll::Pending => {},
			}
			match Pin::new(&mut self.c).poll(ctx) {
				Poll::Ready(()) => {
					return Poll::Ready(SelectorOutput::C);
				},
				Poll::Pending => {},
			}
			match Pin::new(&mut self.d).poll(ctx) {
				Poll::Ready(()) => {
					return Poll::Ready(SelectorOutput::D);
				},
				Poll::Pending => {},
			}
			match Pin::new(&mut self.e).poll(ctx) {
				Poll::Ready(()) => {
					return Poll::Ready(SelectorOutput::E);
				},
				Poll::Pending => {},
			}
			match Pin::new(&mut self.f).poll(ctx) {
				Poll::Ready(()) => {
					return Poll::Ready(SelectorOutput::F);
				},
				Poll::Pending => {},
			}
			Poll::Pending
		}
	}

	/// A selector that takes a future wrapped in an option that will be polled if it is `Some` and
	/// will always be pending otherwise.
	pub(crate) struct OptionalSelector<F: Future<Output = ()> + Unpin> {
		pub optional_future: Option<F>,
	}

	impl<F: Future<Output = ()> + Unpin> Future for OptionalSelector<F> {
		type Output = ();
		fn poll(mut self: Pin<&mut Self>, ctx: &mut core::task::Context<'_>) -> Poll<Self::Output> {
			match self.optional_future.as_mut() {
				Some(f) => match Pin::new(f).poll(ctx) {
					Poll::Ready(()) => {
						self.optional_future.take();
						Poll::Ready(())
					},
					Poll::Pending => Poll::Pending,
				},
				None => Poll::Pending,
			}
		}
	}

	impl<F: Future<Output = ()> + Unpin> From<Option<F>> for OptionalSelector<F> {
		fn from(optional_future: Option<F>) -> Self {
			Self { optional_future }
		}
	}

	// If we want to poll a future without an async context to figure out if it has completed or
	// not without awaiting, we need a Waker, which needs a vtable...we fill it with dummy values
	// but sadly there's a good bit of boilerplate here.
	fn dummy_waker_clone(_: *const ()) -> RawWaker {
		RawWaker::new(core::ptr::null(), &DUMMY_WAKER_VTABLE)
	}
	fn dummy_waker_action(_: *const ()) {}

	const DUMMY_WAKER_VTABLE: RawWakerVTable = RawWakerVTable::new(
		dummy_waker_clone,
		dummy_waker_action,
		dummy_waker_action,
		dummy_waker_action,
	);
	pub(crate) fn dummy_waker() -> Waker {
		unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &DUMMY_WAKER_VTABLE)) }
	}

	enum JoinerResult<ERR, F: Future<Output = Result<(), ERR>> + Unpin> {
		Pending(Option<F>),
		Ready(Result<(), ERR>),
	}

	pub(crate) struct Joiner<
		ERR,
		A: Future<Output = Result<(), ERR>> + Unpin,
		B: Future<Output = Result<(), ERR>> + Unpin,
		C: Future<Output = Result<(), ERR>> + Unpin,
		D: Future<Output = Result<(), ERR>> + Unpin,
		E: Future<Output = Result<(), ERR>> + Unpin,
	> {
		a: JoinerResult<ERR, A>,
		b: JoinerResult<ERR, B>,
		c: JoinerResult<ERR, C>,
		d: JoinerResult<ERR, D>,
		e: JoinerResult<ERR, E>,
	}

	impl<
			ERR,
			A: Future<Output = Result<(), ERR>> + Unpin,
			B: Future<Output = Result<(), ERR>> + Unpin,
			C: Future<Output = Result<(), ERR>> + Unpin,
			D: Future<Output = Result<(), ERR>> + Unpin,
			E: Future<Output = Result<(), ERR>> + Unpin,
		> Joiner<ERR, A, B, C, D, E>
	{
		pub(crate) fn new() -> Self {
			Self {
				a: JoinerResult::Pending(None),
				b: JoinerResult::Pending(None),
				c: JoinerResult::Pending(None),
				d: JoinerResult::Pending(None),
				e: JoinerResult::Pending(None),
			}
		}

		pub(crate) fn set_a(&mut self, fut: A) {
			self.a = JoinerResult::Pending(Some(fut));
		}
		pub(crate) fn set_a_res(&mut self, res: Result<(), ERR>) {
			self.a = JoinerResult::Ready(res);
		}
		pub(crate) fn set_b(&mut self, fut: B) {
			self.b = JoinerResult::Pending(Some(fut));
		}
		pub(crate) fn set_c(&mut self, fut: C) {
			self.c = JoinerResult::Pending(Some(fut));
		}
		pub(crate) fn set_d(&mut self, fut: D) {
			self.d = JoinerResult::Pending(Some(fut));
		}
		pub(crate) fn set_e(&mut self, fut: E) {
			self.e = JoinerResult::Pending(Some(fut));
		}
	}

	impl<
			ERR,
			A: Future<Output = Result<(), ERR>> + Unpin,
			B: Future<Output = Result<(), ERR>> + Unpin,
			C: Future<Output = Result<(), ERR>> + Unpin,
			D: Future<Output = Result<(), ERR>> + Unpin,
			E: Future<Output = Result<(), ERR>> + Unpin,
		> Future for Joiner<ERR, A, B, C, D, E>
	where
		Joiner<ERR, A, B, C, D, E>: Unpin,
	{
		type Output = [Result<(), ERR>; 5];
		fn poll(mut self: Pin<&mut Self>, ctx: &mut core::task::Context<'_>) -> Poll<Self::Output> {
			let mut all_complete = true;
			macro_rules! handle {
				($val: ident) => {
					match &mut (self.$val) {
						JoinerResult::Pending(None) => {
							self.$val = JoinerResult::Ready(Ok(()));
						},
						JoinerResult::<ERR, _>::Pending(Some(ref mut val)) => {
							match Pin::new(val).poll(ctx) {
								Poll::Ready(res) => {
									self.$val = JoinerResult::Ready(res);
								},
								Poll::Pending => {
									all_complete = false;
								},
							}
						},
						JoinerResult::Ready(_) => {},
					}
				};
			}
			handle!(a);
			handle!(b);
			handle!(c);
			handle!(d);
			handle!(e);

			if all_complete {
				let mut res = [Ok(()), Ok(()), Ok(()), Ok(()), Ok(())];
				if let JoinerResult::Ready(ref mut val) = &mut self.a {
					core::mem::swap(&mut res[0], val);
				}
				if let JoinerResult::Ready(ref mut val) = &mut self.b {
					core::mem::swap(&mut res[1], val);
				}
				if let JoinerResult::Ready(ref mut val) = &mut self.c {
					core::mem::swap(&mut res[2], val);
				}
				if let JoinerResult::Ready(ref mut val) = &mut self.d {
					core::mem::swap(&mut res[3], val);
				}
				if let JoinerResult::Ready(ref mut val) = &mut self.e {
					core::mem::swap(&mut res[4], val);
				}
				Poll::Ready(res)
			} else {
				Poll::Pending
			}
		}
	}
}
use core::task;
use futures_util::{dummy_waker, Joiner, OptionalSelector, Selector, SelectorOutput};

/// Processes background events in a future.
///
/// `sleeper` should return a future which completes in the given amount of time and returns a
/// boolean indicating whether the background processing should exit. Once `sleeper` returns a
/// future which outputs `true`, the loop will exit and this function's future will complete.
/// The `sleeper` future is free to return early after it has triggered the exit condition.
///
#[cfg_attr(
	feature = "std",
	doc = " See [`BackgroundProcessor::start`] for information on which actions this handles.\n"
)]
/// The `mobile_interruptable_platform` flag should be set if we're currently running on a
/// mobile device, where we may need to check for interruption of the application regularly. If you
/// are unsure, you should set the flag, as the performance impact of it is minimal unless there
/// are hundreds or thousands of simultaneous process calls running.
///
/// The `fetch_time` parameter should return the current wall clock time, if one is available. If
/// no time is available, some features may be disabled, however the node will still operate fine.
///
/// For example, in order to process background events in a [Tokio](https://tokio.rs/) task, you
/// could setup `process_events_async` like this:
/// ```
/// # use lightning::io;
/// # use lightning::events::ReplayEvent;
/// # use std::sync::{Arc, RwLock};
/// # use std::sync::atomic::{AtomicBool, Ordering};
/// # use std::time::SystemTime;
/// # use lightning_background_processor::{process_events_async, GossipSync};
/// # use core::future::Future;
/// # use core::pin::Pin;
/// # use lightning_liquidity::utils::time::TimeProvider;
/// # struct Logger {}
/// # impl lightning::util::logger::Logger for Logger {
/// #     fn log(&self, _record: lightning::util::logger::Record) {}
/// # }
/// # struct StoreSync {}
/// # impl lightning::util::persist::KVStoreSync for StoreSync {
/// #     fn read(&self, primary_namespace: &str, secondary_namespace: &str, key: &str) -> io::Result<Vec<u8>> { Ok(Vec::new()) }
/// #     fn write(&self, primary_namespace: &str, secondary_namespace: &str, key: &str, buf: Vec<u8>) -> io::Result<()> { Ok(()) }
/// #     fn remove(&self, primary_namespace: &str, secondary_namespace: &str, key: &str, lazy: bool) -> io::Result<()> { Ok(()) }
/// #     fn list(&self, primary_namespace: &str, secondary_namespace: &str) -> io::Result<Vec<String>> { Ok(Vec::new()) }
/// # }
/// # struct Store {}
/// # impl lightning::util::persist::KVStore for Store {
/// #     fn read(&self, primary_namespace: &str, secondary_namespace: &str, key: &str) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, io::Error>> + 'static + Send>> { todo!() }
/// #     fn write(&self, primary_namespace: &str, secondary_namespace: &str, key: &str, buf: Vec<u8>) -> Pin<Box<dyn Future<Output = Result<(), io::Error>> + 'static + Send>> { todo!() }
/// #     fn remove(&self, primary_namespace: &str, secondary_namespace: &str, key: &str, lazy: bool) -> Pin<Box<dyn Future<Output = Result<(), io::Error>> + 'static + Send>> { todo!() }
/// #     fn list(&self, primary_namespace: &str, secondary_namespace: &str) -> Pin<Box<dyn Future<Output = Result<Vec<String>, io::Error>> + 'static + Send>> { todo!() }
/// # }
/// # use core::time::Duration;
/// # struct DefaultTimeProvider;
/// #
/// # impl TimeProvider for DefaultTimeProvider {
/// #    fn duration_since_epoch(&self) -> Duration {
/// #        use std::time::{SystemTime, UNIX_EPOCH};
/// #        SystemTime::now().duration_since(UNIX_EPOCH).expect("system time before Unix epoch")
/// #    }
/// # }
/// # struct EventHandler {}
/// # impl EventHandler {
/// #     async fn handle_event(&self, _: lightning::events::Event) -> Result<(), ReplayEvent> { Ok(()) }
/// # }
/// # #[derive(Eq, PartialEq, Clone, Hash)]
/// # struct SocketDescriptor {}
/// # impl lightning::ln::peer_handler::SocketDescriptor for SocketDescriptor {
/// #     fn send_data(&mut self, _data: &[u8], _continue_read: bool) -> usize { 0 }
/// #     fn disconnect_socket(&mut self) {}
/// # }
/// # type ChainMonitor<B, F, FE> = lightning::chain::chainmonitor::ChainMonitor<lightning::sign::InMemorySigner, Arc<F>, Arc<B>, Arc<FE>, Arc<Logger>, Arc<StoreSync>, Arc<lightning::sign::KeysManager>>;
/// # type NetworkGraph = lightning::routing::gossip::NetworkGraph<Arc<Logger>>;
/// # type P2PGossipSync<UL> = lightning::routing::gossip::P2PGossipSync<Arc<NetworkGraph>, Arc<UL>, Arc<Logger>>;
/// # type ChannelManager<B, F, FE> = lightning::ln::channelmanager::SimpleArcChannelManager<ChainMonitor<B, F, FE>, B, FE, Logger>;
/// # type OnionMessenger<B, F, FE> = lightning::onion_message::messenger::OnionMessenger<Arc<lightning::sign::KeysManager>, Arc<lightning::sign::KeysManager>, Arc<Logger>, Arc<ChannelManager<B, F, FE>>, Arc<lightning::onion_message::messenger::DefaultMessageRouter<Arc<NetworkGraph>, Arc<Logger>, Arc<lightning::sign::KeysManager>>>, Arc<ChannelManager<B, F, FE>>, lightning::ln::peer_handler::IgnoringMessageHandler, lightning::ln::peer_handler::IgnoringMessageHandler, lightning::ln::peer_handler::IgnoringMessageHandler>;
/// # type LiquidityManager<B, F, FE> = lightning_liquidity::LiquidityManager<Arc<lightning::sign::KeysManager>, Arc<lightning::sign::KeysManager>, Arc<ChannelManager<B, F, FE>>, Arc<F>, Arc<Store>, Arc<DefaultTimeProvider>, Arc<B>>;
/// # type Scorer = RwLock<lightning::routing::scoring::ProbabilisticScorer<Arc<NetworkGraph>, Arc<Logger>>>;
/// # type PeerManager<B, F, FE, UL> = lightning::ln::peer_handler::SimpleArcPeerManager<SocketDescriptor, ChainMonitor<B, F, FE>, B, FE, Arc<UL>, Logger, F, StoreSync>;
/// # type OutputSweeper<B, D, FE, F, O> = lightning::util::sweep::OutputSweeper<Arc<B>, Arc<D>, Arc<FE>, Arc<F>, Arc<Store>, Arc<Logger>, Arc<O>>;
///
/// # struct Node<
/// #     B: lightning::chain::chaininterface::BroadcasterInterface + Send + Sync + 'static,
/// #     F: lightning::chain::Filter + Send + Sync + 'static,
/// #     FE: lightning::chain::chaininterface::FeeEstimator + Send + Sync + 'static,
/// #     UL: lightning::routing::utxo::UtxoLookup + Send + Sync + 'static,
/// #     D: lightning::sign::ChangeDestinationSource + Send + Sync + 'static,
/// #     O: lightning::sign::OutputSpender + Send + Sync + 'static,
/// # > {
/// #     peer_manager: Arc<PeerManager<B, F, FE, UL>>,
/// #     event_handler: Arc<EventHandler>,
/// #     channel_manager: Arc<ChannelManager<B, F, FE>>,
/// #     onion_messenger: Arc<OnionMessenger<B, F, FE>>,
/// #     liquidity_manager: Arc<LiquidityManager<B, F, FE>>,
/// #     chain_monitor: Arc<ChainMonitor<B, F, FE>>,
/// #     gossip_sync: Arc<P2PGossipSync<UL>>,
/// #     persister: Arc<Store>,
/// #     logger: Arc<Logger>,
/// #     scorer: Arc<Scorer>,
/// #     sweeper: Arc<OutputSweeper<B, D, FE, F, O>>,
/// # }
/// #
/// # async fn setup_background_processing<
/// #     B: lightning::chain::chaininterface::BroadcasterInterface + Send + Sync + 'static,
/// #     F: lightning::chain::Filter + Send + Sync + 'static,
/// #     FE: lightning::chain::chaininterface::FeeEstimator + Send + Sync + 'static,
/// #     UL: lightning::routing::utxo::UtxoLookup + Send + Sync + 'static,
/// #     D: lightning::sign::ChangeDestinationSource + Send + Sync + 'static,
/// #     O: lightning::sign::OutputSpender + Send + Sync + 'static,
/// # >(node: Node<B, F, FE, UL, D, O>) {
///	let background_persister = Arc::clone(&node.persister);
///	let background_event_handler = Arc::clone(&node.event_handler);
///	let background_chain_mon = Arc::clone(&node.chain_monitor);
///	let background_chan_man = Arc::clone(&node.channel_manager);
///	let background_gossip_sync = GossipSync::p2p(Arc::clone(&node.gossip_sync));
///	let background_peer_man = Arc::clone(&node.peer_manager);
///	let background_onion_messenger = Arc::clone(&node.onion_messenger);
///	let background_liquidity_manager = Arc::clone(&node.liquidity_manager);
///	let background_logger = Arc::clone(&node.logger);
///	let background_scorer = Arc::clone(&node.scorer);
///	let background_sweeper = Arc::clone(&node.sweeper);
///	// Setup the sleeper.
#[cfg_attr(
	feature = "std",
	doc = "	let (stop_sender, stop_receiver) = tokio::sync::watch::channel(());"
)]
#[cfg_attr(feature = "std", doc = "")]
///	let sleeper = move |d| {
#[cfg_attr(feature = "std", doc = "		let mut receiver = stop_receiver.clone();")]
///		Box::pin(async move {
///			tokio::select!{
///				_ = tokio::time::sleep(d) => false,
#[cfg_attr(feature = "std", doc = "				_ = receiver.changed() => true,")]
///			}
///		})
///	};
///
///	let mobile_interruptable_platform = false;
///
#[cfg_attr(feature = "std", doc = "	let handle = tokio::spawn(async move {")]
#[cfg_attr(
	not(feature = "std"),
	doc = "	let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();"
)]
#[cfg_attr(not(feature = "std"), doc = "	rt.block_on(async move {")]
///		process_events_async(
///			background_persister,
///			|e| background_event_handler.handle_event(e),
///			background_chain_mon,
///			background_chan_man,
///			Some(background_onion_messenger),
///			background_gossip_sync,
///			background_peer_man,
///			Some(background_liquidity_manager),
///			Some(background_sweeper),
///			background_logger,
///			Some(background_scorer),
///			sleeper,
///			mobile_interruptable_platform,
///			|| Some(SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap())
///		)
///		.await
///		.expect("Failed to process events");
///	});
///
///	// Stop the background processing.
#[cfg_attr(feature = "std", doc = "	stop_sender.send(()).unwrap();")]
#[cfg_attr(feature = "std", doc = "	handle.await.unwrap()")]
///	# }
///```
pub async fn process_events_async<
	'a,
	UL: Deref,
	CF: Deref,
	T: Deref,
	F: Deref,
	G: Deref<Target = NetworkGraph<L>>,
	L: Deref,
	P: Deref,
	EventHandlerFuture: core::future::Future<Output = Result<(), ReplayEvent>>,
	EventHandler: Fn(Event) -> EventHandlerFuture,
	ES: Deref,
	M: Deref<Target = ChainMonitor<<CM::Target as AChannelManager>::Signer, CF, T, F, L, P, ES>>,
	CM: Deref,
	OM: Deref,
	PGS: Deref<Target = P2PGossipSync<G, UL, L>>,
	RGS: Deref<Target = RapidGossipSync<G, L>>,
	PM: Deref,
	LM: Deref,
	D: Deref,
	O: Deref,
	K: Deref,
	OS: Deref<Target = OutputSweeper<T, D, F, CF, K, L, O>>,
	S: Deref<Target = SC>,
	SC: for<'b> WriteableScore<'b>,
	SleepFuture: core::future::Future<Output = bool> + core::marker::Unpin,
	Sleeper: Fn(Duration) -> SleepFuture,
	FetchTime: Fn() -> Option<Duration>,
>(
	kv_store: K, event_handler: EventHandler, chain_monitor: M, channel_manager: CM,
	onion_messenger: Option<OM>, gossip_sync: GossipSync<PGS, RGS, G, UL, L>, peer_manager: PM,
	liquidity_manager: Option<LM>, sweeper: Option<OS>, logger: L, scorer: Option<S>,
	sleeper: Sleeper, mobile_interruptable_platform: bool, fetch_time: FetchTime,
) -> Result<(), lightning::io::Error>
where
	UL::Target: UtxoLookup,
	CF::Target: chain::Filter,
	T::Target: BroadcasterInterface,
	F::Target: FeeEstimator,
	L::Target: Logger,
	P::Target: Persist<<CM::Target as AChannelManager>::Signer>,
	ES::Target: EntropySource,
	CM::Target: AChannelManager,
	OM::Target: AOnionMessenger,
	PM::Target: APeerManager,
	LM::Target: ALiquidityManager,
	O::Target: OutputSpender,
	D::Target: ChangeDestinationSource,
	K::Target: KVStore,
{
	let async_event_handler = |event| {
		let network_graph = gossip_sync.network_graph();
		let event_handler = &event_handler;
		let scorer = &scorer;
		let logger = &logger;
		let kv_store = &kv_store;
		let fetch_time = &fetch_time;
		// We should be able to drop the Box once our MSRV is 1.68
		Box::pin(async move {
			if let Some(network_graph) = network_graph {
				handle_network_graph_update(network_graph, &event)
			}
			if let Some(ref scorer) = scorer {
				if let Some(duration_since_epoch) = fetch_time() {
					if update_scorer(scorer, &event, duration_since_epoch) {
						log_trace!(logger, "Persisting scorer after update");
						if let Err(e) = kv_store
							.write(
								SCORER_PERSISTENCE_PRIMARY_NAMESPACE,
								SCORER_PERSISTENCE_SECONDARY_NAMESPACE,
								SCORER_PERSISTENCE_KEY,
								scorer.encode(),
							)
							.await
						{
							log_error!(logger, "Error: Failed to persist scorer, check your disk and permissions {}", e);
							// We opt not to abort early on persistence failure here as persisting
							// the scorer is non-critical and we still hope that it will have
							// resolved itself when it is potentially critical in event handling
							// below.
						}
					}
				}
			}
			event_handler(event).await
		})
	};
	let mut batch_delay = BatchDelay::new();

	log_trace!(logger, "Calling ChannelManager's timer_tick_occurred on startup");
	channel_manager.get_cm().timer_tick_occurred();
	log_trace!(logger, "Rebroadcasting monitor's pending claims on startup");
	chain_monitor.rebroadcast_pending_claims();

	let mut last_freshness_call = sleeper(FRESHNESS_TIMER);
	let mut last_onion_message_handler_call = sleeper(ONION_MESSAGE_HANDLER_TIMER);
	let mut last_ping_call = sleeper(PING_TIMER);
	let mut last_prune_call = sleeper(FIRST_NETWORK_PRUNE_TIMER);
	let mut last_scorer_persist_call = sleeper(SCORER_PERSIST_TIMER);
	let mut last_rebroadcast_call = sleeper(REBROADCAST_TIMER);
	let mut last_sweeper_call = sleeper(SWEEPER_TIMER);
	let mut last_archive_call = sleeper(FIRST_ARCHIVE_STALE_MONITORS_TIMER);
	let mut have_pruned = false;
	let mut have_decayed_scorer = false;
	let mut have_archived = false;

	let mut last_forwards_processing_call = sleeper(batch_delay.get());

	loop {
		channel_manager.get_cm().process_pending_events_async(async_event_handler).await;
		chain_monitor.process_pending_events_async(async_event_handler).await;
		if let Some(om) = &onion_messenger {
			om.get_om().process_pending_events_async(async_event_handler).await
		}

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
		peer_manager.as_ref().process_events();
		match check_and_reset_sleeper(&mut last_forwards_processing_call, || {
			sleeper(batch_delay.next())
		}) {
			Some(false) => {
				channel_manager.get_cm().process_pending_htlc_forwards();
			},
			Some(true) => break,
			None => {},
		}

		// We wait up to 100ms, but track how long it takes to detect being put to sleep,
		// see `await_start`'s use below.
		let mut await_start = None;
		if mobile_interruptable_platform {
			await_start = Some(sleeper(Duration::from_secs(1)));
		}
		let om_fut: OptionalSelector<_> =
			onion_messenger.as_ref().map(|om| om.get_om().get_update_future()).into();
		let lm_fut: OptionalSelector<_> = liquidity_manager
			.as_ref()
			.map(|lm| lm.get_lm().get_pending_msgs_or_needs_persist_future())
			.into();
		let gv_fut: OptionalSelector<_> = gossip_sync.validation_completion_future().into();
		let needs_processing = channel_manager.get_cm().needs_pending_htlc_processing();
		let sleep_delay = match (needs_processing, mobile_interruptable_platform) {
			(true, true) => batch_delay.get().min(Duration::from_millis(100)),
			(true, false) => batch_delay.get().min(FASTEST_TIMER),
			(false, true) => Duration::from_millis(100),
			(false, false) => FASTEST_TIMER,
		};
		let fut = Selector {
			a: sleeper(sleep_delay),
			b: channel_manager.get_cm().get_event_or_persistence_needed_future(),
			c: chain_monitor.get_update_future(),
			d: om_fut,
			e: lm_fut,
			f: gv_fut,
		};
		match fut.await {
			SelectorOutput::B
			| SelectorOutput::C
			| SelectorOutput::D
			| SelectorOutput::E
			| SelectorOutput::F => {},
			SelectorOutput::A(exit) => {
				if exit {
					break;
				}
			},
		}

		let await_slow = if mobile_interruptable_platform {
			// Specify a zero new sleeper timeout because we won't use the new sleeper. It is re-initialized in the next
			// loop iteration.
			match check_and_reset_sleeper(&mut await_start.unwrap(), || sleeper(Duration::ZERO)) {
				Some(true) => break,
				Some(false) => true,
				None => false,
			}
		} else {
			false
		};
		match check_and_reset_sleeper(&mut last_freshness_call, || sleeper(FRESHNESS_TIMER)) {
			Some(false) => {
				log_trace!(logger, "Calling ChannelManager's timer_tick_occurred");
				channel_manager.get_cm().timer_tick_occurred();
			},
			Some(true) => break,
			None => {},
		}

		let mut futures = Joiner::new();

		if channel_manager.get_cm().get_and_clear_needs_persistence() {
			log_trace!(logger, "Persisting ChannelManager...");

			let fut = async {
				kv_store
					.write(
						CHANNEL_MANAGER_PERSISTENCE_PRIMARY_NAMESPACE,
						CHANNEL_MANAGER_PERSISTENCE_SECONDARY_NAMESPACE,
						CHANNEL_MANAGER_PERSISTENCE_KEY,
						channel_manager.get_cm().encode(),
					)
					.await
			};
			// TODO: Once our MSRV is 1.68 we should be able to drop the Box
			let mut fut = Box::pin(fut);

			// Because persisting the ChannelManager is important to avoid accidental
			// force-closures, go ahead and poll the future once before we do slightly more
			// CPU-intensive tasks in the form of NetworkGraph pruning or scorer time-stepping
			// below. This will get it moving but won't block us for too long if the underlying
			// future is actually async.
			use core::future::Future;
			let mut waker = dummy_waker();
			let mut ctx = task::Context::from_waker(&mut waker);
			match core::pin::Pin::new(&mut fut).poll(&mut ctx) {
				task::Poll::Ready(res) => futures.set_a_res(res),
				task::Poll::Pending => futures.set_a(fut),
			}

			log_trace!(logger, "Done persisting ChannelManager.");
		}

		// Note that we want to archive stale ChannelMonitors and run a network graph prune once
		// not long after startup before falling back to their usual infrequent runs. This avoids
		// short-lived clients never archiving stale ChannelMonitors or pruning their network
		// graph. For network graph pruning, in the case of RGS sync, we run a prune immediately
		// after initial sync completes, otherwise we do so on a timer which should be long enough
		// to give us a chance to get most of the network graph from our peers.
		let archive_timer = if have_archived {
			ARCHIVE_STALE_MONITORS_TIMER
		} else {
			FIRST_ARCHIVE_STALE_MONITORS_TIMER
		};
		let archive_timer_elapsed = {
			match check_and_reset_sleeper(&mut last_archive_call, || sleeper(archive_timer)) {
				Some(false) => true,
				Some(true) => break,
				None => false,
			}
		};
		if archive_timer_elapsed {
			log_trace!(logger, "Archiving stale ChannelMonitors.");
			chain_monitor.archive_fully_resolved_channel_monitors();
			have_archived = true;
			log_trace!(logger, "Archived stale ChannelMonitors.");
		}

		let prune_timer = if gossip_sync.prunable_network_graph().is_some() {
			NETWORK_PRUNE_TIMER
		} else {
			FIRST_NETWORK_PRUNE_TIMER
		};
		let prune_timer_elapsed = {
			match check_and_reset_sleeper(&mut last_prune_call, || sleeper(prune_timer)) {
				Some(false) => true,
				Some(true) => break,
				None => false,
			}
		};

		let should_prune = match gossip_sync {
			GossipSync::Rapid(_) => !have_pruned || prune_timer_elapsed,
			_ => prune_timer_elapsed,
		};
		if should_prune {
			// The network graph must not be pruned while rapid sync completion is pending
			if let Some(network_graph) = gossip_sync.prunable_network_graph() {
				if let Some(duration_since_epoch) = fetch_time() {
					log_trace!(logger, "Pruning and persisting network graph.");
					network_graph.remove_stale_channels_and_tracking_with_time(
						duration_since_epoch.as_secs(),
					);
				} else {
					log_warn!(logger, "Not pruning network graph, consider implementing the fetch_time argument or calling remove_stale_channels_and_tracking_with_time manually.");
					log_trace!(logger, "Persisting network graph.");
				}
				let fut = async {
					if let Err(e) = kv_store
						.write(
							NETWORK_GRAPH_PERSISTENCE_PRIMARY_NAMESPACE,
							NETWORK_GRAPH_PERSISTENCE_SECONDARY_NAMESPACE,
							NETWORK_GRAPH_PERSISTENCE_KEY,
							network_graph.encode(),
						)
						.await
					{
						log_error!(logger, "Error: Failed to persist network graph, check your disk and permissions {}",e);
					}

					Ok(())
				};

				// TODO: Once our MSRV is 1.68 we should be able to drop the Box
				futures.set_b(Box::pin(fut));

				have_pruned = true;
			}
		}
		if !have_decayed_scorer {
			if let Some(ref scorer) = scorer {
				if let Some(duration_since_epoch) = fetch_time() {
					log_trace!(logger, "Calling time_passed on scorer at startup");
					scorer.write_lock().time_passed(duration_since_epoch);
				}
			}
			have_decayed_scorer = true;
		}
		match check_and_reset_sleeper(&mut last_scorer_persist_call, || {
			sleeper(SCORER_PERSIST_TIMER)
		}) {
			Some(false) => {
				if let Some(ref scorer) = scorer {
					if let Some(duration_since_epoch) = fetch_time() {
						log_trace!(logger, "Calling time_passed and persisting scorer");
						scorer.write_lock().time_passed(duration_since_epoch);
					} else {
						log_trace!(logger, "Persisting scorer");
					}
					let fut = async {
						if let Err(e) = kv_store
							.write(
								SCORER_PERSISTENCE_PRIMARY_NAMESPACE,
								SCORER_PERSISTENCE_SECONDARY_NAMESPACE,
								SCORER_PERSISTENCE_KEY,
								scorer.encode(),
							)
							.await
						{
							log_error!(
							logger,
							"Error: Failed to persist scorer, check your disk and permissions {}",
							e
						);
						}

						Ok(())
					};

					// TODO: Once our MSRV is 1.68 we should be able to drop the Box
					futures.set_c(Box::pin(fut));
				}
			},
			Some(true) => break,
			None => {},
		}
		match check_and_reset_sleeper(&mut last_sweeper_call, || sleeper(SWEEPER_TIMER)) {
			Some(false) => {
				log_trace!(logger, "Regenerating sweeper spends if necessary");
				if let Some(ref sweeper) = sweeper {
					let fut = async {
						let _ = sweeper.regenerate_and_broadcast_spend_if_necessary().await;

						Ok(())
					};

					// TODO: Once our MSRV is 1.68 we should be able to drop the Box
					futures.set_d(Box::pin(fut));
				}
			},
			Some(true) => break,
			None => {},
		}

		if let Some(liquidity_manager) = liquidity_manager.as_ref() {
			let fut = async {
				liquidity_manager
					.get_lm()
					.persist()
					.await
					.map(|did_persist| {
						if did_persist {
							log_trace!(logger, "Persisted LiquidityManager.");
						}
					})
					.map_err(|e| {
						log_error!(logger, "Persisting LiquidityManager failed: {}", e);
						e
					})
			};
			futures.set_e(Box::pin(fut));
		}

		// Run persistence tasks in parallel and exit if any of them returns an error.
		for res in futures.await {
			res?;
		}

		match check_and_reset_sleeper(&mut last_onion_message_handler_call, || {
			sleeper(ONION_MESSAGE_HANDLER_TIMER)
		}) {
			Some(false) => {
				if let Some(om) = &onion_messenger {
					log_trace!(logger, "Calling OnionMessageHandler's timer_tick_occurred");
					om.get_om().timer_tick_occurred();
				}
			},
			Some(true) => break,
			None => {},
		}

		// Peer manager timer tick. If we were interrupted on a mobile platform, we disconnect all peers.
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
			log_trace!(logger, "100ms sleep took more than a second, disconnecting peers.");
			peer_manager.as_ref().disconnect_all_peers();
			last_ping_call = sleeper(PING_TIMER);
		} else {
			match check_and_reset_sleeper(&mut last_ping_call, || sleeper(PING_TIMER)) {
				Some(false) => {
					log_trace!(logger, "Calling PeerManager's timer_tick_occurred");
					peer_manager.as_ref().timer_tick_occurred();
				},
				Some(true) => break,
				_ => {},
			}
		}

		// Rebroadcast pending claims.
		match check_and_reset_sleeper(&mut last_rebroadcast_call, || sleeper(REBROADCAST_TIMER)) {
			Some(false) => {
				log_trace!(logger, "Rebroadcasting monitor's pending claims");
				chain_monitor.rebroadcast_pending_claims();
			},
			Some(true) => break,
			None => {},
		}
	}
	log_trace!(logger, "Terminating background processor.");

	// After we exit, ensure we persist the ChannelManager one final time - this avoids
	// some races where users quit while channel updates were in-flight, with
	// ChannelMonitor update(s) persisted without a corresponding ChannelManager update.
	kv_store
		.write(
			CHANNEL_MANAGER_PERSISTENCE_PRIMARY_NAMESPACE,
			CHANNEL_MANAGER_PERSISTENCE_SECONDARY_NAMESPACE,
			CHANNEL_MANAGER_PERSISTENCE_KEY,
			channel_manager.get_cm().encode(),
		)
		.await?;
	if let Some(ref scorer) = scorer {
		kv_store
			.write(
				SCORER_PERSISTENCE_PRIMARY_NAMESPACE,
				SCORER_PERSISTENCE_SECONDARY_NAMESPACE,
				SCORER_PERSISTENCE_KEY,
				scorer.encode(),
			)
			.await?;
	}
	if let Some(network_graph) = gossip_sync.network_graph() {
		kv_store
			.write(
				NETWORK_GRAPH_PERSISTENCE_PRIMARY_NAMESPACE,
				NETWORK_GRAPH_PERSISTENCE_SECONDARY_NAMESPACE,
				NETWORK_GRAPH_PERSISTENCE_KEY,
				network_graph.encode(),
			)
			.await?;
	}
	Ok(())
}

fn check_and_reset_sleeper<
	SleepFuture: core::future::Future<Output = bool> + core::marker::Unpin,
>(
	fut: &mut SleepFuture, mut new_sleeper: impl FnMut() -> SleepFuture,
) -> Option<bool> {
	let mut waker = dummy_waker();
	let mut ctx = task::Context::from_waker(&mut waker);
	match core::pin::Pin::new(&mut *fut).poll(&mut ctx) {
		task::Poll::Ready(exit) => {
			*fut = new_sleeper();
			Some(exit)
		},
		task::Poll::Pending => None,
	}
}

/// Async events processor that is based on [`process_events_async`] but allows for [`KVStoreSync`] to be used for
/// synchronous background persistence.
pub async fn process_events_async_with_kv_store_sync<
	UL: Deref,
	CF: Deref,
	T: Deref,
	F: Deref,
	G: Deref<Target = NetworkGraph<L>>,
	L: Deref,
	P: Deref,
	EventHandlerFuture: core::future::Future<Output = Result<(), ReplayEvent>>,
	EventHandler: Fn(Event) -> EventHandlerFuture,
	ES: Deref,
	M: Deref<Target = ChainMonitor<<CM::Target as AChannelManager>::Signer, CF, T, F, L, P, ES>>,
	CM: Deref,
	OM: Deref,
	PGS: Deref<Target = P2PGossipSync<G, UL, L>>,
	RGS: Deref<Target = RapidGossipSync<G, L>>,
	PM: Deref,
	LM: Deref,
	D: Deref,
	O: Deref,
	K: Deref,
	OS: Deref<Target = OutputSweeperSync<T, D, F, CF, K, L, O>>,
	S: Deref<Target = SC>,
	SC: for<'b> WriteableScore<'b>,
	SleepFuture: core::future::Future<Output = bool> + core::marker::Unpin,
	Sleeper: Fn(Duration) -> SleepFuture,
	FetchTime: Fn() -> Option<Duration>,
>(
	kv_store: K, event_handler: EventHandler, chain_monitor: M, channel_manager: CM,
	onion_messenger: Option<OM>, gossip_sync: GossipSync<PGS, RGS, G, UL, L>, peer_manager: PM,
	liquidity_manager: Option<LM>, sweeper: Option<OS>, logger: L, scorer: Option<S>,
	sleeper: Sleeper, mobile_interruptable_platform: bool, fetch_time: FetchTime,
) -> Result<(), lightning::io::Error>
where
	UL::Target: UtxoLookup,
	CF::Target: chain::Filter,
	T::Target: BroadcasterInterface,
	F::Target: FeeEstimator,
	L::Target: Logger,
	P::Target: Persist<<CM::Target as AChannelManager>::Signer>,
	ES::Target: EntropySource,
	CM::Target: AChannelManager,
	OM::Target: AOnionMessenger,
	PM::Target: APeerManager,
	LM::Target: ALiquidityManager,
	O::Target: OutputSpender,
	D::Target: ChangeDestinationSourceSync,
	K::Target: KVStoreSync,
{
	let kv_store = KVStoreSyncWrapper(kv_store);
	process_events_async(
		kv_store,
		event_handler,
		chain_monitor,
		channel_manager,
		onion_messenger,
		gossip_sync,
		peer_manager,
		liquidity_manager,
		sweeper.as_ref().map(|os| os.sweeper_async()),
		logger,
		scorer,
		sleeper,
		mobile_interruptable_platform,
		fetch_time,
	)
	.await
}

#[cfg(feature = "std")]
impl BackgroundProcessor {
	/// Start a background thread that takes care of responsibilities enumerated in the [top-level
	/// documentation].
	///
	/// The thread runs indefinitely unless the object is dropped, [`stop`] is called, or
	/// [`KVStoreSync`] returns an error. In case of an error, the error is retrieved by calling
	/// either [`join`] or [`stop`].
	///
	/// # Data Persistence
	///
	/// [`KVStoreSync`] is responsible for writing out the [`ChannelManager`] to disk, and/or
	/// uploading to one or more backup services. See [`ChannelManager::write`] for writing out a
	/// [`ChannelManager`]. See the `lightning-persister` crate for LDK's
	/// provided implementation.
	///
	/// [`KVStoreSync`] is also responsible for writing out the [`NetworkGraph`] to disk, if
	/// [`GossipSync`] is supplied. See [`NetworkGraph::write`] for writing out a [`NetworkGraph`].
	/// See the `lightning-persister` crate for LDK's provided implementation.
	///
	/// Typically, users should either implement [`KVStoreSync`] to never return an
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
	/// [`NetworkGraph`]: lightning::routing::gossip::NetworkGraph
	/// [`NetworkGraph::write`]: lightning::routing::gossip::NetworkGraph#impl-Writeable
	pub fn start<
		'a,
		UL: 'static + Deref,
		CF: 'static + Deref,
		T: 'static + Deref,
		F: 'static + Deref + Send,
		G: 'static + Deref<Target = NetworkGraph<L>>,
		L: 'static + Deref + Send,
		P: 'static + Deref,
		EH: 'static + EventHandler + Send,
		ES: 'static + Deref + Send,
		M: 'static
			+ Deref<
				Target = ChainMonitor<<CM::Target as AChannelManager>::Signer, CF, T, F, L, P, ES>,
			>
			+ Send
			+ Sync,
		CM: 'static + Deref + Send,
		OM: 'static + Deref + Send,
		PGS: 'static + Deref<Target = P2PGossipSync<G, UL, L>> + Send,
		RGS: 'static + Deref<Target = RapidGossipSync<G, L>> + Send,
		PM: 'static + Deref + Send,
		LM: 'static + Deref + Send,
		S: 'static + Deref<Target = SC> + Send + Sync,
		SC: for<'b> WriteableScore<'b>,
		D: 'static + Deref,
		O: 'static + Deref,
		K: 'static + Deref + Send,
		OS: 'static + Deref<Target = OutputSweeperSync<T, D, F, CF, K, L, O>> + Send,
	>(
		kv_store: K, event_handler: EH, chain_monitor: M, channel_manager: CM,
		onion_messenger: Option<OM>, gossip_sync: GossipSync<PGS, RGS, G, UL, L>, peer_manager: PM,
		liquidity_manager: Option<LM>, sweeper: Option<OS>, logger: L, scorer: Option<S>,
	) -> Self
	where
		UL::Target: 'static + UtxoLookup,
		CF::Target: 'static + chain::Filter,
		T::Target: 'static + BroadcasterInterface,
		F::Target: 'static + FeeEstimator,
		L::Target: 'static + Logger,
		P::Target: 'static + Persist<<CM::Target as AChannelManager>::Signer>,
		ES::Target: 'static + EntropySource,
		CM::Target: AChannelManager,
		OM::Target: AOnionMessenger,
		PM::Target: APeerManager,
		LM::Target: ALiquidityManagerSync,
		D::Target: ChangeDestinationSourceSync,
		O::Target: 'static + OutputSpender,
		K::Target: 'static + KVStoreSync,
	{
		let stop_thread = Arc::new(AtomicBool::new(false));
		let stop_thread_clone = Arc::clone(&stop_thread);
		let handle = thread::spawn(move || -> Result<(), std::io::Error> {
			let event_handler = |event| {
				let network_graph = gossip_sync.network_graph();
				if let Some(network_graph) = network_graph {
					handle_network_graph_update(network_graph, &event)
				}
				if let Some(ref scorer) = scorer {
					use std::time::SystemTime;
					let duration_since_epoch = SystemTime::now()
						.duration_since(SystemTime::UNIX_EPOCH)
						.expect("Time should be sometime after 1970");
					if update_scorer(scorer, &event, duration_since_epoch) {
						log_trace!(logger, "Persisting scorer after update");
						if let Err(e) = kv_store.write(
							SCORER_PERSISTENCE_PRIMARY_NAMESPACE,
							SCORER_PERSISTENCE_SECONDARY_NAMESPACE,
							SCORER_PERSISTENCE_KEY,
							scorer.encode(),
						) {
							log_error!(logger, "Error: Failed to persist scorer, check your disk and permissions {}", e)
						}
					}
				}
				event_handler.handle_event(event)
			};
			let mut batch_delay = BatchDelay::new();

			log_trace!(logger, "Calling ChannelManager's timer_tick_occurred on startup");
			channel_manager.get_cm().timer_tick_occurred();
			log_trace!(logger, "Rebroadcasting monitor's pending claims on startup");
			chain_monitor.rebroadcast_pending_claims();

			let mut last_freshness_call = Instant::now();
			let mut last_onion_message_handler_call = Instant::now();
			let mut last_ping_call = Instant::now();
			let mut last_prune_call = Instant::now();
			let mut last_scorer_persist_call = Instant::now();
			let mut last_rebroadcast_call = Instant::now();
			let mut last_sweeper_call = Instant::now();
			let mut last_archive_call = Instant::now();
			let mut have_pruned = false;
			let mut have_decayed_scorer = false;
			let mut have_archived = false;

			let mut cur_batch_delay = batch_delay.get();
			let mut last_forwards_processing_call = Instant::now();

			loop {
				channel_manager.get_cm().process_pending_events(&event_handler);
				chain_monitor.process_pending_events(&event_handler);
				if let Some(om) = &onion_messenger {
					om.get_om().process_pending_events(&event_handler)
				};

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
				peer_manager.as_ref().process_events();
				if last_forwards_processing_call.elapsed() > cur_batch_delay {
					channel_manager.get_cm().process_pending_htlc_forwards();
					cur_batch_delay = batch_delay.next();
					last_forwards_processing_call = Instant::now();
				}
				if stop_thread.load(Ordering::Acquire) {
					log_trace!(logger, "Terminating background processor.");
					break;
				}
				let om_fut = onion_messenger.as_ref().map(|om| om.get_om().get_update_future());
				let lm_fut = liquidity_manager
					.as_ref()
					.map(|lm| lm.get_lm().get_pending_msgs_or_needs_persist_future());
				let gv_fut = gossip_sync.validation_completion_future();
				let always_futures = [
					channel_manager.get_cm().get_event_or_persistence_needed_future(),
					chain_monitor.get_update_future(),
				];
				let futures = always_futures.into_iter().chain(om_fut).chain(lm_fut).chain(gv_fut);
				let sleeper = Sleeper::from_futures(futures);

				let batch_delay = if channel_manager.get_cm().needs_pending_htlc_processing() {
					batch_delay.get()
				} else {
					Duration::MAX
				};
				let fastest_timeout = batch_delay.min(Duration::from_millis(100));
				sleeper.wait_timeout(fastest_timeout);
				if stop_thread.load(Ordering::Acquire) {
					log_trace!(logger, "Terminating background processor.");
					break;
				}
				if last_freshness_call.elapsed() > FRESHNESS_TIMER {
					log_trace!(logger, "Calling ChannelManager's timer_tick_occurred");
					channel_manager.get_cm().timer_tick_occurred();
					last_freshness_call = Instant::now();
				}
				if channel_manager.get_cm().get_and_clear_needs_persistence() {
					log_trace!(logger, "Persisting ChannelManager...");
					(kv_store.write(
						CHANNEL_MANAGER_PERSISTENCE_PRIMARY_NAMESPACE,
						CHANNEL_MANAGER_PERSISTENCE_SECONDARY_NAMESPACE,
						CHANNEL_MANAGER_PERSISTENCE_KEY,
						channel_manager.get_cm().encode(),
					))?;
					log_trace!(logger, "Done persisting ChannelManager.");
				}

				if let Some(liquidity_manager) = liquidity_manager.as_ref() {
					log_trace!(logger, "Persisting LiquidityManager...");
					let _ = liquidity_manager.get_lm().persist().map_err(|e| {
						log_error!(logger, "Persisting LiquidityManager failed: {}", e);
					});
				}

				// Note that we want to archive stale ChannelMonitors and run a network graph prune once
				// not long after startup before falling back to their usual infrequent runs. This avoids
				// short-lived clients never archiving stale ChannelMonitors or pruning their network
				// graph. For network graph pruning, in the case of RGS sync, we run a prune immediately
				// after initial sync completes, otherwise we do so on a timer which should be long enough
				// to give us a chance to get most of the network graph from our peers.
				let archive_timer = if have_archived {
					ARCHIVE_STALE_MONITORS_TIMER
				} else {
					FIRST_ARCHIVE_STALE_MONITORS_TIMER
				};
				let archive_timer_elapsed = last_archive_call.elapsed() > archive_timer;
				if archive_timer_elapsed {
					log_trace!(logger, "Archiving stale ChannelMonitors.");
					chain_monitor.archive_fully_resolved_channel_monitors();
					have_archived = true;
					last_archive_call = Instant::now();
					log_trace!(logger, "Archived stale ChannelMonitors.");
				}

				let prune_timer =
					if have_pruned { NETWORK_PRUNE_TIMER } else { FIRST_NETWORK_PRUNE_TIMER };
				let prune_timer_elapsed = last_prune_call.elapsed() > prune_timer;
				let should_prune = match gossip_sync {
					GossipSync::Rapid(_) => !have_pruned || prune_timer_elapsed,
					_ => prune_timer_elapsed,
				};
				if should_prune {
					// The network graph must not be pruned while rapid sync completion is pending
					if let Some(network_graph) = gossip_sync.prunable_network_graph() {
						let duration_since_epoch = std::time::SystemTime::now()
							.duration_since(std::time::SystemTime::UNIX_EPOCH)
							.expect("Time should be sometime after 1970");

						log_trace!(logger, "Pruning and persisting network graph.");
						network_graph.remove_stale_channels_and_tracking_with_time(
							duration_since_epoch.as_secs(),
						);
						if let Err(e) = kv_store.write(
							NETWORK_GRAPH_PERSISTENCE_PRIMARY_NAMESPACE,
							NETWORK_GRAPH_PERSISTENCE_SECONDARY_NAMESPACE,
							NETWORK_GRAPH_PERSISTENCE_KEY,
							network_graph.encode(),
						) {
							log_error!(logger, "Error: Failed to persist network graph, check your disk and permissions {}", e);
						}
						have_pruned = true;
					}
					last_prune_call = Instant::now();
				}
				if !have_decayed_scorer {
					if let Some(ref scorer) = scorer {
						let duration_since_epoch = std::time::SystemTime::now()
							.duration_since(std::time::SystemTime::UNIX_EPOCH)
							.expect("Time should be sometime after 1970");
						log_trace!(logger, "Calling time_passed on scorer at startup");
						scorer.write_lock().time_passed(duration_since_epoch);
					}
					have_decayed_scorer = true;
				}
				if last_scorer_persist_call.elapsed() > SCORER_PERSIST_TIMER {
					if let Some(ref scorer) = scorer {
						let duration_since_epoch = std::time::SystemTime::now()
							.duration_since(std::time::SystemTime::UNIX_EPOCH)
							.expect("Time should be sometime after 1970");
						log_trace!(logger, "Calling time_passed and persisting scorer");
						scorer.write_lock().time_passed(duration_since_epoch);
						if let Err(e) = kv_store.write(
							SCORER_PERSISTENCE_PRIMARY_NAMESPACE,
							SCORER_PERSISTENCE_SECONDARY_NAMESPACE,
							SCORER_PERSISTENCE_KEY,
							scorer.encode(),
						) {
							log_error!(logger, "Error: Failed to persist scorer, check your disk and permissions {}", e);
						}
					}
					last_scorer_persist_call = Instant::now();
				}
				if last_sweeper_call.elapsed() > SWEEPER_TIMER {
					log_trace!(logger, "Regenerating sweeper spends if necessary");
					if let Some(ref sweeper) = sweeper {
						let _ = sweeper.regenerate_and_broadcast_spend_if_necessary();
					}
					last_sweeper_call = Instant::now();
				}
				if last_onion_message_handler_call.elapsed() > ONION_MESSAGE_HANDLER_TIMER {
					if let Some(om) = &onion_messenger {
						log_trace!(logger, "Calling OnionMessageHandler's timer_tick_occurred");
						om.get_om().timer_tick_occurred();
					}
					last_onion_message_handler_call = Instant::now();
				}
				if last_ping_call.elapsed() > PING_TIMER {
					log_trace!(logger, "Calling PeerManager's timer_tick_occurred");
					peer_manager.as_ref().timer_tick_occurred();
					last_ping_call = Instant::now();
				}
				if last_rebroadcast_call.elapsed() > REBROADCAST_TIMER {
					log_trace!(logger, "Rebroadcasting monitor's pending claims");
					chain_monitor.rebroadcast_pending_claims();
					last_rebroadcast_call = Instant::now();
				}
			}

			// After we exit, ensure we persist the ChannelManager one final time - this avoids
			// some races where users quit while channel updates were in-flight, with
			// ChannelMonitor update(s) persisted without a corresponding ChannelManager update.
			kv_store.write(
				CHANNEL_MANAGER_PERSISTENCE_PRIMARY_NAMESPACE,
				CHANNEL_MANAGER_PERSISTENCE_SECONDARY_NAMESPACE,
				CHANNEL_MANAGER_PERSISTENCE_KEY,
				channel_manager.get_cm().encode(),
			)?;
			if let Some(ref scorer) = scorer {
				kv_store.write(
					SCORER_PERSISTENCE_PRIMARY_NAMESPACE,
					SCORER_PERSISTENCE_SECONDARY_NAMESPACE,
					SCORER_PERSISTENCE_KEY,
					scorer.encode(),
				)?;
			}
			if let Some(network_graph) = gossip_sync.network_graph() {
				kv_store.write(
					NETWORK_GRAPH_PERSISTENCE_PRIMARY_NAMESPACE,
					NETWORK_GRAPH_PERSISTENCE_SECONDARY_NAMESPACE,
					NETWORK_GRAPH_PERSISTENCE_KEY,
					network_graph.encode(),
				)?;
			}
			Ok(())
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
	use super::{BackgroundProcessor, GossipSync, FRESHNESS_TIMER};
	use bitcoin::constants::{genesis_block, ChainHash};
	use bitcoin::hashes::Hash;
	use bitcoin::locktime::absolute::LockTime;
	use bitcoin::network::Network;
	use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
	use bitcoin::transaction::Version;
	use bitcoin::transaction::{Transaction, TxOut};
	use bitcoin::{Amount, ScriptBuf, Txid};
	use core::sync::atomic::{AtomicBool, Ordering};
	use lightning::chain::channelmonitor::ANTI_REORG_DELAY;
	use lightning::chain::transaction::OutPoint;
	use lightning::chain::{chainmonitor, BestBlock, Confirm, Filter};
	use lightning::events::{Event, PathFailure, ReplayEvent};
	use lightning::ln::channelmanager;
	use lightning::ln::channelmanager::{
		ChainParameters, PaymentId, BREAKDOWN_TIMEOUT, MIN_CLTV_EXPIRY_DELTA,
	};
	use lightning::ln::functional_test_utils::*;
	use lightning::ln::msgs::{BaseMessageHandler, ChannelMessageHandler, Init, MessageSendEvent};
	use lightning::ln::peer_handler::{
		IgnoringMessageHandler, MessageHandler, PeerManager, SocketDescriptor,
	};
	use lightning::ln::types::ChannelId;
	use lightning::onion_message::messenger::{DefaultMessageRouter, OnionMessenger};
	use lightning::routing::gossip::{NetworkGraph, P2PGossipSync};
	use lightning::routing::router::{CandidateRouteHop, DefaultRouter, Path, RouteHop};
	use lightning::routing::scoring::{ChannelUsage, LockableScore, ScoreLookUp, ScoreUpdate};
	use lightning::sign::{ChangeDestinationSourceSync, InMemorySigner, KeysManager, NodeSigner};
	use lightning::types::features::{ChannelFeatures, NodeFeatures};
	use lightning::types::payment::PaymentHash;
	use lightning::util::config::UserConfig;
	use lightning::util::persist::{
		KVStoreSync, KVStoreSyncWrapper, CHANNEL_MANAGER_PERSISTENCE_KEY,
		CHANNEL_MANAGER_PERSISTENCE_PRIMARY_NAMESPACE,
		CHANNEL_MANAGER_PERSISTENCE_SECONDARY_NAMESPACE, NETWORK_GRAPH_PERSISTENCE_KEY,
		NETWORK_GRAPH_PERSISTENCE_PRIMARY_NAMESPACE, NETWORK_GRAPH_PERSISTENCE_SECONDARY_NAMESPACE,
		SCORER_PERSISTENCE_KEY, SCORER_PERSISTENCE_PRIMARY_NAMESPACE,
		SCORER_PERSISTENCE_SECONDARY_NAMESPACE,
	};
	use lightning::util::ser::Writeable;
	use lightning::util::sweep::{
		OutputSpendStatus, OutputSweeper, OutputSweeperSync, PRUNE_DELAY_BLOCKS,
	};
	use lightning::util::test_utils;
	use lightning::{get_event, get_event_msg};
	use lightning_liquidity::utils::time::DefaultTimeProvider;
	use lightning_liquidity::{ALiquidityManagerSync, LiquidityManager, LiquidityManagerSync};
	use lightning_persister::fs_store::FilesystemStore;
	use lightning_rapid_gossip_sync::RapidGossipSync;
	use std::collections::VecDeque;
	use std::path::PathBuf;
	use std::sync::mpsc::SyncSender;
	use std::sync::Arc;
	use std::time::Duration;
	use std::{env, fs};

	const EVENT_DEADLINE: Duration =
		Duration::from_millis(5 * (FRESHNESS_TIMER.as_millis() as u64));

	#[derive(Clone, Hash, PartialEq, Eq)]
	struct TestDescriptor {}
	impl SocketDescriptor for TestDescriptor {
		fn send_data(&mut self, _data: &[u8], _continue_read: bool) -> usize {
			0
		}

		fn disconnect_socket(&mut self) {}
	}

	#[cfg(c_bindings)]
	type LockingWrapper<T> = lightning::routing::scoring::MultiThreadedLockableScore<T>;
	#[cfg(not(c_bindings))]
	type LockingWrapper<T> = std::sync::Mutex<T>;

	type ChannelManager = channelmanager::ChannelManager<
		Arc<ChainMonitor>,
		Arc<test_utils::TestBroadcaster>,
		Arc<KeysManager>,
		Arc<KeysManager>,
		Arc<KeysManager>,
		Arc<test_utils::TestFeeEstimator>,
		Arc<
			DefaultRouter<
				Arc<NetworkGraph<Arc<test_utils::TestLogger>>>,
				Arc<test_utils::TestLogger>,
				Arc<KeysManager>,
				Arc<LockingWrapper<TestScorer>>,
				(),
				TestScorer,
			>,
		>,
		Arc<
			DefaultMessageRouter<
				Arc<NetworkGraph<Arc<test_utils::TestLogger>>>,
				Arc<test_utils::TestLogger>,
				Arc<KeysManager>,
			>,
		>,
		Arc<test_utils::TestLogger>,
	>;

	type ChainMonitor = chainmonitor::ChainMonitor<
		InMemorySigner,
		Arc<test_utils::TestChainSource>,
		Arc<test_utils::TestBroadcaster>,
		Arc<test_utils::TestFeeEstimator>,
		Arc<test_utils::TestLogger>,
		Arc<Persister>,
		Arc<KeysManager>,
	>;

	type PGS = Arc<
		P2PGossipSync<
			Arc<NetworkGraph<Arc<test_utils::TestLogger>>>,
			Arc<test_utils::TestChainSource>,
			Arc<test_utils::TestLogger>,
		>,
	>;
	type RGS = Arc<
		RapidGossipSync<
			Arc<NetworkGraph<Arc<test_utils::TestLogger>>>,
			Arc<test_utils::TestLogger>,
		>,
	>;

	type OM = OnionMessenger<
		Arc<KeysManager>,
		Arc<KeysManager>,
		Arc<test_utils::TestLogger>,
		Arc<ChannelManager>,
		Arc<
			DefaultMessageRouter<
				Arc<NetworkGraph<Arc<test_utils::TestLogger>>>,
				Arc<test_utils::TestLogger>,
				Arc<KeysManager>,
			>,
		>,
		IgnoringMessageHandler,
		Arc<ChannelManager>,
		IgnoringMessageHandler,
		IgnoringMessageHandler,
	>;

	type LM = LiquidityManagerSync<
		Arc<KeysManager>,
		Arc<KeysManager>,
		Arc<ChannelManager>,
		Arc<dyn Filter + Sync + Send>,
		Arc<Persister>,
		DefaultTimeProvider,
		Arc<test_utils::TestBroadcaster>,
	>;

	struct Node {
		node: Arc<ChannelManager>,
		messenger: Arc<OM>,
		p2p_gossip_sync: PGS,
		rapid_gossip_sync: RGS,
		peer_manager: Arc<
			PeerManager<
				TestDescriptor,
				Arc<test_utils::TestChannelMessageHandler>,
				Arc<test_utils::TestRoutingMessageHandler>,
				Arc<OM>,
				Arc<test_utils::TestLogger>,
				IgnoringMessageHandler,
				Arc<KeysManager>,
				IgnoringMessageHandler,
			>,
		>,
		liquidity_manager: Arc<LM>,
		chain_monitor: Arc<ChainMonitor>,
		kv_store: Arc<Persister>,
		tx_broadcaster: Arc<test_utils::TestBroadcaster>,
		network_graph: Arc<NetworkGraph<Arc<test_utils::TestLogger>>>,
		logger: Arc<test_utils::TestLogger>,
		best_block: BestBlock,
		scorer: Arc<LockingWrapper<TestScorer>>,
		sweeper: Arc<
			OutputSweeperSync<
				Arc<test_utils::TestBroadcaster>,
				Arc<TestWallet>,
				Arc<test_utils::TestFeeEstimator>,
				Arc<test_utils::TestChainSource>,
				Arc<Persister>,
				Arc<test_utils::TestLogger>,
				Arc<KeysManager>,
			>,
		>,
	}

	impl Node {
		fn p2p_gossip_sync(
			&self,
		) -> GossipSync<
			PGS,
			RGS,
			Arc<NetworkGraph<Arc<test_utils::TestLogger>>>,
			Arc<test_utils::TestChainSource>,
			Arc<test_utils::TestLogger>,
		> {
			GossipSync::P2P(Arc::clone(&self.p2p_gossip_sync))
		}

		fn rapid_gossip_sync(
			&self,
		) -> GossipSync<
			PGS,
			RGS,
			Arc<NetworkGraph<Arc<test_utils::TestLogger>>>,
			Arc<test_utils::TestChainSource>,
			Arc<test_utils::TestLogger>,
		> {
			GossipSync::Rapid(Arc::clone(&self.rapid_gossip_sync))
		}

		fn no_gossip_sync(
			&self,
		) -> GossipSync<
			PGS,
			RGS,
			Arc<NetworkGraph<Arc<test_utils::TestLogger>>>,
			Arc<test_utils::TestChainSource>,
			Arc<test_utils::TestLogger>,
		> {
			GossipSync::None
		}
	}

	impl Drop for Node {
		fn drop(&mut self) {
			let data_dir = self.kv_store.get_data_dir();
			match fs::remove_dir_all(data_dir.clone()) {
				Err(e) => {
					println!("Failed to remove test store directory {}: {}", data_dir.display(), e)
				},
				_ => {},
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
			Self {
				graph_error: None,
				graph_persistence_notifier: None,
				manager_error: None,
				scorer_error: None,
				kv_store,
			}
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

		pub fn get_data_dir(&self) -> PathBuf {
			self.kv_store.get_data_dir()
		}
	}

	impl KVStoreSync for Persister {
		fn read(
			&self, primary_namespace: &str, secondary_namespace: &str, key: &str,
		) -> lightning::io::Result<Vec<u8>> {
			self.kv_store.read(primary_namespace, secondary_namespace, key)
		}

		fn write(
			&self, primary_namespace: &str, secondary_namespace: &str, key: &str, buf: Vec<u8>,
		) -> lightning::io::Result<()> {
			if primary_namespace == CHANNEL_MANAGER_PERSISTENCE_PRIMARY_NAMESPACE
				&& secondary_namespace == CHANNEL_MANAGER_PERSISTENCE_SECONDARY_NAMESPACE
				&& key == CHANNEL_MANAGER_PERSISTENCE_KEY
			{
				if let Some((error, message)) = self.manager_error {
					return Err(std::io::Error::new(error, message).into());
				}
			}

			if primary_namespace == NETWORK_GRAPH_PERSISTENCE_PRIMARY_NAMESPACE
				&& secondary_namespace == NETWORK_GRAPH_PERSISTENCE_SECONDARY_NAMESPACE
				&& key == NETWORK_GRAPH_PERSISTENCE_KEY
			{
				if let Some(sender) = &self.graph_persistence_notifier {
					match sender.send(()) {
						Ok(()) => {},
						Err(std::sync::mpsc::SendError(())) => {
							println!("Persister failed to notify as receiver went away.")
						},
					}
				};

				if let Some((error, message)) = self.graph_error {
					return Err(std::io::Error::new(error, message).into());
				}
			}

			if primary_namespace == SCORER_PERSISTENCE_PRIMARY_NAMESPACE
				&& secondary_namespace == SCORER_PERSISTENCE_SECONDARY_NAMESPACE
				&& key == SCORER_PERSISTENCE_KEY
			{
				if let Some((error, message)) = self.scorer_error {
					return Err(std::io::Error::new(error, message).into());
				}
			}

			self.kv_store.write(primary_namespace, secondary_namespace, key, buf)
		}

		fn remove(
			&self, primary_namespace: &str, secondary_namespace: &str, key: &str, lazy: bool,
		) -> lightning::io::Result<()> {
			self.kv_store.remove(primary_namespace, secondary_namespace, key, lazy)
		}

		fn list(
			&self, primary_namespace: &str, secondary_namespace: &str,
		) -> lightning::io::Result<Vec<String>> {
			self.kv_store.list(primary_namespace, secondary_namespace)
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
		fn write<W: lightning::util::ser::Writer>(
			&self, _: &mut W,
		) -> Result<(), lightning::io::Error> {
			Ok(())
		}
	}

	impl ScoreLookUp for TestScorer {
		type ScoreParams = ();
		fn channel_penalty_msat(
			&self, _candidate: &CandidateRouteHop, _usage: ChannelUsage,
			_score_params: &Self::ScoreParams,
		) -> u64 {
			unimplemented!();
		}
	}

	impl ScoreUpdate for TestScorer {
		fn payment_path_failed(
			&mut self, actual_path: &Path, actual_short_channel_id: u64, _: Duration,
		) {
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
					},
				}
			}
		}

		fn payment_path_successful(&mut self, actual_path: &Path, _: Duration) {
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
					},
				}
			}
		}

		fn probe_failed(&mut self, actual_path: &Path, _: u64, _: Duration) {
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
					},
				}
			}
		}
		fn probe_successful(&mut self, actual_path: &Path, _: Duration) {
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
					},
				}
			}
		}
		fn time_passed(&mut self, _: Duration) {}
	}

	#[cfg(c_bindings)]
	impl lightning::routing::scoring::Score for TestScorer {}

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

	struct TestWallet {}

	impl ChangeDestinationSourceSync for TestWallet {
		fn get_change_destination_script(&self) -> Result<ScriptBuf, ()> {
			Ok(ScriptBuf::new())
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
			let fee_estimator = Arc::new(test_utils::TestFeeEstimator::new(253));
			let logger = Arc::new(test_utils::TestLogger::with_id(format!("node {}", i)));
			let genesis_block = genesis_block(network);
			let network_graph = Arc::new(NetworkGraph::new(network, Arc::clone(&logger)));
			let scorer = Arc::new(LockingWrapper::new(TestScorer::new()));
			let now = Duration::from_secs(genesis_block.header.time as u64);
			let seed = [i as u8; 32];
			let keys_manager =
				Arc::new(KeysManager::new(&seed, now.as_secs(), now.subsec_nanos(), true));
			let router = Arc::new(DefaultRouter::new(
				Arc::clone(&network_graph),
				Arc::clone(&logger),
				Arc::clone(&keys_manager),
				Arc::clone(&scorer),
				Default::default(),
			));
			let msg_router = Arc::new(DefaultMessageRouter::new(
				Arc::clone(&network_graph),
				Arc::clone(&keys_manager),
			));
			let chain_source = Arc::new(test_utils::TestChainSource::new(Network::Bitcoin));
			let kv_store =
				Arc::new(Persister::new(format!("{}_persister_{}", &persist_dir, i).into()));
			let now = Duration::from_secs(genesis_block.header.time as u64);
			let keys_manager =
				Arc::new(KeysManager::new(&seed, now.as_secs(), now.subsec_nanos(), true));
			let chain_monitor = Arc::new(chainmonitor::ChainMonitor::new(
				Some(Arc::clone(&chain_source)),
				Arc::clone(&tx_broadcaster),
				Arc::clone(&logger),
				Arc::clone(&fee_estimator),
				Arc::clone(&kv_store),
				Arc::clone(&keys_manager),
				keys_manager.get_peer_storage_key(),
			));
			let best_block = BestBlock::from_network(network);
			let params = ChainParameters { network, best_block };
			let mut config = UserConfig::default();
			config.channel_handshake_config.negotiate_anchors_zero_fee_htlc_tx = false;
			let manager = Arc::new(ChannelManager::new(
				Arc::clone(&fee_estimator),
				Arc::clone(&chain_monitor),
				Arc::clone(&tx_broadcaster),
				Arc::clone(&router),
				Arc::clone(&msg_router),
				Arc::clone(&logger),
				Arc::clone(&keys_manager),
				Arc::clone(&keys_manager),
				Arc::clone(&keys_manager),
				config,
				params,
				genesis_block.header.time,
			));
			let messenger = Arc::new(OnionMessenger::new(
				Arc::clone(&keys_manager),
				Arc::clone(&keys_manager),
				Arc::clone(&logger),
				Arc::clone(&manager),
				Arc::clone(&msg_router),
				IgnoringMessageHandler {},
				Arc::clone(&manager),
				IgnoringMessageHandler {},
				IgnoringMessageHandler {},
			));
			let wallet = Arc::new(TestWallet {});
			let sweeper = Arc::new(OutputSweeperSync::new(
				best_block,
				Arc::clone(&tx_broadcaster),
				Arc::clone(&fee_estimator),
				None::<Arc<test_utils::TestChainSource>>,
				Arc::clone(&keys_manager),
				wallet,
				Arc::clone(&kv_store),
				Arc::clone(&logger),
			));
			let p2p_gossip_sync = Arc::new(P2PGossipSync::new(
				Arc::clone(&network_graph),
				Some(Arc::clone(&chain_source)),
				Arc::clone(&logger),
			));
			let rapid_gossip_sync =
				Arc::new(RapidGossipSync::new(Arc::clone(&network_graph), Arc::clone(&logger)));
			let msg_handler = MessageHandler {
				chan_handler: Arc::new(test_utils::TestChannelMessageHandler::new(
					ChainHash::using_genesis_block(Network::Testnet),
				)),
				route_handler: Arc::new(test_utils::TestRoutingMessageHandler::new()),
				onion_message_handler: Arc::clone(&messenger),
				custom_message_handler: IgnoringMessageHandler {},
				send_only_message_handler: IgnoringMessageHandler {},
			};
			let peer_manager = Arc::new(PeerManager::new(
				msg_handler,
				0,
				&seed,
				Arc::clone(&logger),
				Arc::clone(&keys_manager),
			));
			let liquidity_manager = Arc::new(
				LiquidityManagerSync::new(
					Arc::clone(&keys_manager),
					Arc::clone(&keys_manager),
					Arc::clone(&manager),
					None,
					None,
					Arc::clone(&kv_store),
					Arc::clone(&tx_broadcaster),
					None,
					None,
				)
				.unwrap(),
			);
			let node = Node {
				node: manager,
				p2p_gossip_sync,
				rapid_gossip_sync,
				peer_manager,
				liquidity_manager,
				chain_monitor,
				kv_store,
				tx_broadcaster,
				network_graph,
				logger,
				best_block,
				scorer,
				sweeper,
				messenger,
			};
			nodes.push(node);
		}

		for i in 0..num_nodes {
			for j in (i + 1)..num_nodes {
				let init_i = Init {
					features: nodes[j].node.init_features(),
					networks: None,
					remote_network_address: None,
				};
				nodes[i]
					.node
					.peer_connected(nodes[j].node.get_our_node_id(), &init_i, true)
					.unwrap();
				let init_j = Init {
					features: nodes[i].node.init_features(),
					networks: None,
					remote_network_address: None,
				};
				nodes[j]
					.node
					.peer_connected(nodes[i].node.get_our_node_id(), &init_j, false)
					.unwrap();
			}
		}

		(persist_dir, nodes)
	}

	macro_rules! open_channel {
		($node_a: expr, $node_b: expr, $channel_value: expr) => {{
			begin_open_channel!($node_a, $node_b, $channel_value);
			let events = $node_a.node.get_and_clear_pending_events();
			assert_eq!(events.len(), 1);
			let (temporary_channel_id, tx) =
				handle_funding_generation_ready!(events[0], $channel_value);
			$node_a
				.node
				.funding_transaction_generated(
					temporary_channel_id,
					$node_b.node.get_our_node_id(),
					tx.clone(),
				)
				.unwrap();
			let msg_a = get_event_msg!(
				$node_a,
				MessageSendEvent::SendFundingCreated,
				$node_b.node.get_our_node_id()
			);
			$node_b.node.handle_funding_created($node_a.node.get_our_node_id(), &msg_a);
			get_event!($node_b, Event::ChannelPending);
			let msg_b = get_event_msg!(
				$node_b,
				MessageSendEvent::SendFundingSigned,
				$node_a.node.get_our_node_id()
			);
			$node_a.node.handle_funding_signed($node_b.node.get_our_node_id(), &msg_b);
			get_event!($node_a, Event::ChannelPending);
			tx
		}};
	}

	macro_rules! begin_open_channel {
		($node_a: expr, $node_b: expr, $channel_value: expr) => {{
			$node_a
				.node
				.create_channel($node_b.node.get_our_node_id(), $channel_value, 100, 42, None, None)
				.unwrap();
			let msg_a = get_event_msg!(
				$node_a,
				MessageSendEvent::SendOpenChannel,
				$node_b.node.get_our_node_id()
			);
			$node_b.node.handle_open_channel($node_a.node.get_our_node_id(), &msg_a);
			let events = $node_b.node.get_and_clear_pending_events();
			assert_eq!(events.len(), 1);
			match &events[0] {
				Event::OpenChannelRequest {
					temporary_channel_id, counterparty_node_id, ..
				} => {
					$node_b
						.node
						.accept_inbound_channel(
							temporary_channel_id,
							counterparty_node_id,
							42,
							None,
						)
						.unwrap();
				},
				_ => panic!("Unexpected event"),
			};

			let msg_b = get_event_msg!(
				$node_b,
				MessageSendEvent::SendAcceptChannel,
				$node_a.node.get_our_node_id()
			);
			$node_a.node.handle_accept_channel($node_b.node.get_our_node_id(), &msg_b);
		}};
	}

	macro_rules! handle_funding_generation_ready {
		($event: expr, $channel_value: expr) => {{
			match $event {
				Event::FundingGenerationReady {
					temporary_channel_id,
					channel_value_satoshis,
					ref output_script,
					user_channel_id,
					..
				} => {
					assert_eq!(channel_value_satoshis, $channel_value);
					assert_eq!(user_channel_id, 42);

					let tx = Transaction {
						version: Version::ONE,
						lock_time: LockTime::ZERO,
						input: Vec::new(),
						output: vec![TxOut {
							value: Amount::from_sat(channel_value_satoshis),
							script_pubkey: output_script.clone(),
						}],
					};
					(temporary_channel_id, tx)
				},
				_ => panic!("Unexpected event"),
			}
		}};
	}

	fn confirm_transaction_depth(node: &mut Node, tx: &Transaction, depth: u32) {
		for i in 1..=depth {
			let prev_blockhash = node.best_block.block_hash;
			let height = node.best_block.height + 1;
			let header = create_dummy_header(prev_blockhash, height);
			let txdata = vec![(0, tx)];
			node.best_block = BestBlock::new(header.block_hash(), height);
			match i {
				1 => {
					node.node.transactions_confirmed(&header, &txdata, height);
					node.chain_monitor.transactions_confirmed(&header, &txdata, height);
					node.sweeper.transactions_confirmed(&header, &txdata, height);
				},
				x if x == depth => {
					// We need the TestBroadcaster to know about the new height so that it doesn't think
					// we're violating the time lock requirements of transactions broadcasted at that
					// point.
					let block = (genesis_block(Network::Bitcoin), height);
					node.tx_broadcaster.blocks.lock().unwrap().push(block);
					node.node.best_block_updated(&header, height);
					node.chain_monitor.best_block_updated(&header, height);
					node.sweeper.best_block_updated(&header, height);
				},
				_ => {},
			}
		}
	}

	fn advance_chain(node: &mut Node, num_blocks: u32) {
		for i in 1..=num_blocks {
			let prev_blockhash = node.best_block.block_hash;
			let height = node.best_block.height + 1;
			let header = create_dummy_header(prev_blockhash, height);
			node.best_block = BestBlock::new(header.block_hash(), height);
			if i == num_blocks {
				// We need the TestBroadcaster to know about the new height so that it doesn't think
				// we're violating the time lock requirements of transactions broadcasted at that
				// point.
				let block = (genesis_block(Network::Bitcoin), height);
				node.tx_broadcaster.blocks.lock().unwrap().push(block);
				node.node.best_block_updated(&header, height);
				node.chain_monitor.best_block_updated(&header, height);
				node.sweeper.best_block_updated(&header, height);
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
		let event_handler = |_: _| Ok(());
		let bg_processor = BackgroundProcessor::start(
			persister,
			event_handler,
			Arc::clone(&nodes[0].chain_monitor),
			Arc::clone(&nodes[0].node),
			Some(Arc::clone(&nodes[0].messenger)),
			nodes[0].p2p_gossip_sync(),
			Arc::clone(&nodes[0].peer_manager),
			Some(Arc::clone(&nodes[0].liquidity_manager)),
			Some(Arc::clone(&nodes[0].sweeper)),
			Arc::clone(&nodes[0].logger),
			Some(Arc::clone(&nodes[0].scorer)),
		);

		macro_rules! check_persisted_data {
			($node: expr, $filepath: expr) => {
				let mut expected_bytes = Vec::new();
				loop {
					expected_bytes.clear();
					match $node.write(&mut expected_bytes) {
						Ok(()) => match std::fs::read($filepath) {
							Ok(bytes) => {
								if bytes == expected_bytes {
									break;
								} else {
									continue;
								}
							},
							Err(_) => continue,
						},
						Err(e) => panic!("Unexpected error: {}", e),
					}
				}
			};
		}

		// Check that the initial channel manager data is persisted as expected.
		let filepath =
			get_full_filepath(format!("{}_persister_0", &persist_dir), "manager".to_string());
		check_persisted_data!(nodes[0].node, filepath.clone());

		loop {
			if !nodes[0].node.get_event_or_persist_condvar_value() {
				break;
			}
		}

		// Force-close the channel.
		let error_message = "Channel force-closed";
		nodes[0]
			.node
			.force_close_broadcasting_latest_txn(
				&ChannelId::v1_from_funding_outpoint(OutPoint {
					txid: tx.compute_txid(),
					index: 0,
				}),
				&nodes[1].node.get_our_node_id(),
				error_message.to_string(),
			)
			.unwrap();

		// Check that the force-close updates are persisted.
		check_persisted_data!(nodes[0].node, filepath.clone());
		loop {
			if !nodes[0].node.get_event_or_persist_condvar_value() {
				break;
			}
		}

		// Check network graph is persisted
		let filepath =
			get_full_filepath(format!("{}_persister_0", &persist_dir), "network_graph".to_string());
		check_persisted_data!(nodes[0].network_graph, filepath.clone());

		// Check scorer is persisted
		let filepath =
			get_full_filepath(format!("{}_persister_0", &persist_dir), "scorer".to_string());
		check_persisted_data!(nodes[0].scorer, filepath.clone());

		if !std::thread::panicking() {
			bg_processor.stop().unwrap();
		}
	}

	#[test]
	fn test_timer_tick_called() {
		// Test that:
		// - `ChannelManager::timer_tick_occurred` is called every `FRESHNESS_TIMER`,
		// - `ChainMonitor::rebroadcast_pending_claims` is called every `REBROADCAST_TIMER`,
		// - `PeerManager::timer_tick_occurred` is called every `PING_TIMER`, and
		// - `OnionMessageHandler::timer_tick_occurred` is called every `ONION_MESSAGE_HANDLER_TIMER`.
		let (_, nodes) = create_nodes(1, "test_timer_tick_called");
		let data_dir = nodes[0].kv_store.get_data_dir();
		let persister = Arc::new(Persister::new(data_dir));
		let event_handler = |_: _| Ok(());
		let bg_processor = BackgroundProcessor::start(
			persister,
			event_handler,
			Arc::clone(&nodes[0].chain_monitor),
			Arc::clone(&nodes[0].node),
			Some(Arc::clone(&nodes[0].messenger)),
			nodes[0].no_gossip_sync(),
			Arc::clone(&nodes[0].peer_manager),
			Some(Arc::clone(&nodes[0].liquidity_manager)),
			Some(Arc::clone(&nodes[0].sweeper)),
			Arc::clone(&nodes[0].logger),
			Some(Arc::clone(&nodes[0].scorer)),
		);
		loop {
			let log_entries = nodes[0].logger.lines.lock().unwrap();
			let desired_log_1 = "Calling ChannelManager's timer_tick_occurred".to_string();
			let desired_log_2 = "Calling PeerManager's timer_tick_occurred".to_string();
			let desired_log_3 = "Rebroadcasting monitor's pending claims".to_string();
			let desired_log_4 = "Calling OnionMessageHandler's timer_tick_occurred".to_string();
			if log_entries.get(&("lightning_background_processor", desired_log_1)).is_some()
				&& log_entries.get(&("lightning_background_processor", desired_log_2)).is_some()
				&& log_entries.get(&("lightning_background_processor", desired_log_3)).is_some()
				&& log_entries.get(&("lightning_background_processor", desired_log_4)).is_some()
			{
				break;
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
		let persister = Arc::new(
			Persister::new(data_dir).with_manager_error(std::io::ErrorKind::Other, "test"),
		);
		let event_handler = |_: _| Ok(());
		let bg_processor = BackgroundProcessor::start(
			persister,
			event_handler,
			Arc::clone(&nodes[0].chain_monitor),
			Arc::clone(&nodes[0].node),
			Some(Arc::clone(&nodes[0].messenger)),
			nodes[0].no_gossip_sync(),
			Arc::clone(&nodes[0].peer_manager),
			Some(Arc::clone(&nodes[0].liquidity_manager)),
			Some(Arc::clone(&nodes[0].sweeper)),
			Arc::clone(&nodes[0].logger),
			Some(Arc::clone(&nodes[0].scorer)),
		);
		match bg_processor.join() {
			Ok(_) => panic!("Expected error persisting manager"),
			Err(e) => {
				assert_eq!(e.kind(), std::io::ErrorKind::Other);
				assert_eq!(e.get_ref().unwrap().to_string(), "test");
			},
		}
	}

	#[tokio::test]
	async fn test_channel_manager_persist_error_async() {
		// Test that if we encounter an error during manager persistence, the thread panics.
		let (_, nodes) = create_nodes(2, "test_persist_error_sync");
		open_channel!(nodes[0], nodes[1], 100000);

		let data_dir = nodes[0].kv_store.get_data_dir();
		let kv_store_sync = Arc::new(
			Persister::new(data_dir).with_manager_error(std::io::ErrorKind::Other, "test"),
		);
		let kv_store = KVStoreSyncWrapper(kv_store_sync);

		// Yes, you can unsafe { turn off the borrow checker }
		let lm_async: &'static LiquidityManager<_, _, _, _, _, _, _> = unsafe {
			&*(nodes[0].liquidity_manager.get_lm_async()
				as *const LiquidityManager<_, _, _, _, _, _, _>)
				as &'static LiquidityManager<_, _, _, _, _, _, _>
		};
		let sweeper_async: &'static OutputSweeper<_, _, _, _, _, _, _> = unsafe {
			&*(nodes[0].sweeper.sweeper_async() as *const OutputSweeper<_, _, _, _, _, _, _>)
				as &'static OutputSweeper<_, _, _, _, _, _, _>
		};

		let bp_future = super::process_events_async(
			kv_store,
			|_: _| async { Ok(()) },
			Arc::clone(&nodes[0].chain_monitor),
			Arc::clone(&nodes[0].node),
			Some(Arc::clone(&nodes[0].messenger)),
			nodes[0].rapid_gossip_sync(),
			Arc::clone(&nodes[0].peer_manager),
			Some(lm_async),
			Some(sweeper_async),
			Arc::clone(&nodes[0].logger),
			Some(Arc::clone(&nodes[0].scorer)),
			move |dur: Duration| {
				Box::pin(async move {
					tokio::time::sleep(dur).await;
					false // Never exit
				})
			},
			false,
			|| Some(Duration::ZERO),
		);
		match bp_future.await {
			Ok(_) => panic!("Expected error persisting manager"),
			Err(e) => {
				assert_eq!(e.kind(), lightning::io::ErrorKind::Other);
				assert_eq!(e.get_ref().unwrap().to_string(), "test");
			},
		}
	}

	#[test]
	fn test_network_graph_persist_error() {
		// Test that if we encounter an error during network graph persistence, an error gets returned.
		let (_, nodes) = create_nodes(2, "test_persist_network_graph_error");
		let data_dir = nodes[0].kv_store.get_data_dir();
		let persister =
			Arc::new(Persister::new(data_dir).with_graph_error(std::io::ErrorKind::Other, "test"));
		let event_handler = |_: _| Ok(());
		let bg_processor = BackgroundProcessor::start(
			persister,
			event_handler,
			Arc::clone(&nodes[0].chain_monitor),
			Arc::clone(&nodes[0].node),
			Some(Arc::clone(&nodes[0].messenger)),
			nodes[0].p2p_gossip_sync(),
			Arc::clone(&nodes[0].peer_manager),
			Some(Arc::clone(&nodes[0].liquidity_manager)),
			Some(Arc::clone(&nodes[0].sweeper)),
			Arc::clone(&nodes[0].logger),
			Some(Arc::clone(&nodes[0].scorer)),
		);

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
		let persister =
			Arc::new(Persister::new(data_dir).with_scorer_error(std::io::ErrorKind::Other, "test"));
		let event_handler = |_: _| Ok(());
		let bg_processor = BackgroundProcessor::start(
			persister,
			event_handler,
			Arc::clone(&nodes[0].chain_monitor),
			Arc::clone(&nodes[0].node),
			Some(Arc::clone(&nodes[0].messenger)),
			nodes[0].no_gossip_sync(),
			Arc::clone(&nodes[0].peer_manager),
			Some(Arc::clone(&nodes[0].liquidity_manager)),
			Some(Arc::clone(&nodes[0].sweeper)),
			Arc::clone(&nodes[0].logger),
			Some(Arc::clone(&nodes[0].scorer)),
		);

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
		let node_0_id = nodes[0].node.get_our_node_id();
		let node_1_id = nodes[1].node.get_our_node_id();

		let channel_value = 100000;
		let data_dir = nodes[0].kv_store.get_data_dir();
		let persister = Arc::new(Persister::new(data_dir.clone()));

		// Set up a background event handler for FundingGenerationReady events.
		let (funding_generation_send, funding_generation_recv) = std::sync::mpsc::sync_channel(1);
		let (channel_pending_send, channel_pending_recv) = std::sync::mpsc::sync_channel(1);
		let event_handler = move |event: Event| {
			match event {
				Event::FundingGenerationReady { .. } => funding_generation_send
					.send(handle_funding_generation_ready!(event, channel_value))
					.unwrap(),
				Event::ChannelPending { .. } => channel_pending_send.send(()).unwrap(),
				Event::ChannelReady { .. } => {},
				_ => panic!("Unexpected event: {:?}", event),
			}
			Ok(())
		};

		let bg_processor = BackgroundProcessor::start(
			persister,
			event_handler,
			Arc::clone(&nodes[0].chain_monitor),
			Arc::clone(&nodes[0].node),
			Some(Arc::clone(&nodes[0].messenger)),
			nodes[0].no_gossip_sync(),
			Arc::clone(&nodes[0].peer_manager),
			Some(Arc::clone(&nodes[0].liquidity_manager)),
			Some(Arc::clone(&nodes[0].sweeper)),
			Arc::clone(&nodes[0].logger),
			Some(Arc::clone(&nodes[0].scorer)),
		);

		// Open a channel and check that the FundingGenerationReady event was handled.
		begin_open_channel!(nodes[0], nodes[1], channel_value);
		let (temporary_channel_id, funding_tx) = funding_generation_recv
			.recv_timeout(EVENT_DEADLINE)
			.expect("FundingGenerationReady not handled within deadline");
		nodes[0]
			.node
			.funding_transaction_generated(temporary_channel_id, node_1_id, funding_tx.clone())
			.unwrap();
		let msg_0 = get_event_msg!(nodes[0], MessageSendEvent::SendFundingCreated, node_1_id);
		nodes[1].node.handle_funding_created(node_0_id, &msg_0);
		get_event!(nodes[1], Event::ChannelPending);
		let msg_1 = get_event_msg!(nodes[1], MessageSendEvent::SendFundingSigned, node_0_id);
		nodes[0].node.handle_funding_signed(node_1_id, &msg_1);
		channel_pending_recv
			.recv_timeout(EVENT_DEADLINE)
			.expect("ChannelPending not handled within deadline");

		// Confirm the funding transaction.
		confirm_transaction(&mut nodes[0], &funding_tx);
		let as_funding = get_event_msg!(nodes[0], MessageSendEvent::SendChannelReady, node_1_id);
		confirm_transaction(&mut nodes[1], &funding_tx);
		let bs_funding = get_event_msg!(nodes[1], MessageSendEvent::SendChannelReady, node_0_id);
		nodes[0].node.handle_channel_ready(node_1_id, &bs_funding);
		let _as_channel_update =
			get_event_msg!(nodes[0], MessageSendEvent::SendChannelUpdate, node_1_id);
		nodes[1].node.handle_channel_ready(node_0_id, &as_funding);
		let _bs_channel_update =
			get_event_msg!(nodes[1], MessageSendEvent::SendChannelUpdate, node_0_id);
		let broadcast_funding =
			nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().pop().unwrap();
		assert_eq!(broadcast_funding.compute_txid(), funding_tx.compute_txid());
		assert!(nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().is_empty());

		if !std::thread::panicking() {
			bg_processor.stop().unwrap();
		}

		// Set up a background event handler for SpendableOutputs events.
		let (sender, receiver) = std::sync::mpsc::sync_channel(1);
		let event_handler = move |event: Event| {
			match event {
				Event::SpendableOutputs { .. } => sender.send(event).unwrap(),
				Event::ChannelReady { .. } => {},
				Event::ChannelClosed { .. } => {},
				_ => panic!("Unexpected event: {:?}", event),
			}
			Ok(())
		};
		let persister = Arc::new(Persister::new(data_dir));
		let bg_processor = BackgroundProcessor::start(
			persister,
			event_handler,
			Arc::clone(&nodes[0].chain_monitor),
			Arc::clone(&nodes[0].node),
			Some(Arc::clone(&nodes[0].messenger)),
			nodes[0].no_gossip_sync(),
			Arc::clone(&nodes[0].peer_manager),
			Some(Arc::clone(&nodes[0].liquidity_manager)),
			Some(Arc::clone(&nodes[0].sweeper)),
			Arc::clone(&nodes[0].logger),
			Some(Arc::clone(&nodes[0].scorer)),
		);

		// Force close the channel and check that the SpendableOutputs event was handled.
		let error_message = "Channel force-closed";
		nodes[0]
			.node
			.force_close_broadcasting_latest_txn(
				&nodes[0].node.list_channels()[0].channel_id,
				&node_1_id,
				error_message.to_string(),
			)
			.unwrap();
		let commitment_tx = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().pop().unwrap();
		confirm_transaction_depth(&mut nodes[0], &commitment_tx, BREAKDOWN_TIMEOUT as u32);

		let event =
			receiver.recv_timeout(EVENT_DEADLINE).expect("Events not handled within deadline");
		match event {
			Event::SpendableOutputs { outputs, channel_id } => {
				nodes[0]
					.sweeper
					.track_spendable_outputs(outputs, channel_id, false, Some(153))
					.unwrap();
			},
			_ => panic!("Unexpected event: {:?}", event),
		}

		// Check we don't generate an initial sweeping tx until we reach the required height.
		assert_eq!(nodes[0].sweeper.tracked_spendable_outputs().len(), 1);
		let tracked_output = nodes[0].sweeper.tracked_spendable_outputs().first().unwrap().clone();
		if let Some(sweep_tx_0) = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().pop() {
			assert!(!tracked_output.is_spent_in(&sweep_tx_0));
			match tracked_output.status {
				OutputSpendStatus::PendingInitialBroadcast { delayed_until_height } => {
					assert_eq!(delayed_until_height, Some(153));
				},
				_ => panic!("Unexpected status"),
			}
		}

		advance_chain(&mut nodes[0], 3);

		let tx_broadcaster = Arc::clone(&nodes[0].tx_broadcaster);
		let wait_for_sweep_tx = || -> Transaction {
			loop {
				let sweep_tx = tx_broadcaster.txn_broadcasted.lock().unwrap().pop();
				if let Some(sweep_tx) = sweep_tx {
					return sweep_tx;
				}

				std::thread::sleep(Duration::from_millis(10));
			}
		};

		// Check we generate an initial sweeping tx.
		assert_eq!(nodes[0].sweeper.tracked_spendable_outputs().len(), 1);
		let sweep_tx_0 = wait_for_sweep_tx();
		let tracked_output = nodes[0].sweeper.tracked_spendable_outputs().first().unwrap().clone();
		match tracked_output.status {
			OutputSpendStatus::PendingFirstConfirmation { latest_spending_tx, .. } => {
				assert_eq!(sweep_tx_0.compute_txid(), latest_spending_tx.compute_txid());
			},
			_ => panic!("Unexpected status"),
		}

		// Check we regenerate and rebroadcast the sweeping tx each block.
		advance_chain(&mut nodes[0], 1);
		assert_eq!(nodes[0].sweeper.tracked_spendable_outputs().len(), 1);
		let sweep_tx_1 = wait_for_sweep_tx();
		let tracked_output = nodes[0].sweeper.tracked_spendable_outputs().first().unwrap().clone();
		match tracked_output.status {
			OutputSpendStatus::PendingFirstConfirmation { latest_spending_tx, .. } => {
				assert_eq!(sweep_tx_1.compute_txid(), latest_spending_tx.compute_txid());
			},
			_ => panic!("Unexpected status"),
		}
		assert_ne!(sweep_tx_0, sweep_tx_1);

		advance_chain(&mut nodes[0], 1);
		assert_eq!(nodes[0].sweeper.tracked_spendable_outputs().len(), 1);
		let sweep_tx_2 = wait_for_sweep_tx();
		let tracked_output = nodes[0].sweeper.tracked_spendable_outputs().first().unwrap().clone();
		match tracked_output.status {
			OutputSpendStatus::PendingFirstConfirmation { latest_spending_tx, .. } => {
				assert_eq!(sweep_tx_2.compute_txid(), latest_spending_tx.compute_txid());
			},
			_ => panic!("Unexpected status"),
		}
		assert_ne!(sweep_tx_0, sweep_tx_2);
		assert_ne!(sweep_tx_1, sweep_tx_2);

		// Check we still track the spendable outputs up to ANTI_REORG_DELAY confirmations.
		confirm_transaction_depth(&mut nodes[0], &sweep_tx_2, 5);
		assert_eq!(nodes[0].sweeper.tracked_spendable_outputs().len(), 1);
		let tracked_output = nodes[0].sweeper.tracked_spendable_outputs().first().unwrap().clone();
		match tracked_output.status {
			OutputSpendStatus::PendingThresholdConfirmations { latest_spending_tx, .. } => {
				assert_eq!(sweep_tx_2.compute_txid(), latest_spending_tx.compute_txid());
			},
			_ => panic!("Unexpected status"),
		}

		// Check we still see the transaction as confirmed if we unconfirm any untracked
		// transaction. (We previously had a bug that would mark tracked transactions as
		// unconfirmed if any transaction at an unknown block height would be unconfirmed.)
		let unconf_txid = Txid::from_slice(&[0; 32]).unwrap();
		nodes[0].sweeper.transaction_unconfirmed(&unconf_txid);

		assert_eq!(nodes[0].sweeper.tracked_spendable_outputs().len(), 1);
		let tracked_output = nodes[0].sweeper.tracked_spendable_outputs().first().unwrap().clone();
		match tracked_output.status {
			OutputSpendStatus::PendingThresholdConfirmations { latest_spending_tx, .. } => {
				assert_eq!(sweep_tx_2.compute_txid(), latest_spending_tx.compute_txid());
			},
			_ => panic!("Unexpected status"),
		}

		// Check we stop tracking the spendable outputs when one of the txs reaches
		// PRUNE_DELAY_BLOCKS confirmations.
		confirm_transaction_depth(&mut nodes[0], &sweep_tx_0, PRUNE_DELAY_BLOCKS);
		assert_eq!(nodes[0].sweeper.tracked_spendable_outputs().len(), 0);

		if !std::thread::panicking() {
			bg_processor.stop().unwrap();
		}
	}

	#[test]
	fn test_event_handling_failures_are_replayed() {
		let (_, nodes) = create_nodes(2, "test_event_handling_failures_are_replayed");
		let channel_value = 100000;
		let data_dir = nodes[0].kv_store.get_data_dir();
		let persister = Arc::new(Persister::new(data_dir.clone()));

		let (first_event_send, first_event_recv) = std::sync::mpsc::sync_channel(1);
		let (second_event_send, second_event_recv) = std::sync::mpsc::sync_channel(1);
		let should_fail_event_handling = Arc::new(AtomicBool::new(true));
		let event_handler = move |event: Event| {
			if let Ok(true) = should_fail_event_handling.compare_exchange(
				true,
				false,
				Ordering::Acquire,
				Ordering::Relaxed,
			) {
				first_event_send.send(event).unwrap();
				return Err(ReplayEvent());
			}

			second_event_send.send(event).unwrap();
			Ok(())
		};

		let bg_processor = BackgroundProcessor::start(
			persister,
			event_handler,
			Arc::clone(&nodes[0].chain_monitor),
			Arc::clone(&nodes[0].node),
			Some(Arc::clone(&nodes[0].messenger)),
			nodes[0].no_gossip_sync(),
			Arc::clone(&nodes[0].peer_manager),
			Some(Arc::clone(&nodes[0].liquidity_manager)),
			Some(Arc::clone(&nodes[0].sweeper)),
			Arc::clone(&nodes[0].logger),
			Some(Arc::clone(&nodes[0].scorer)),
		);

		begin_open_channel!(nodes[0], nodes[1], channel_value);
		assert_eq!(
			first_event_recv.recv_timeout(EVENT_DEADLINE).unwrap(),
			second_event_recv.recv_timeout(EVENT_DEADLINE).unwrap()
		);

		if !std::thread::panicking() {
			bg_processor.stop().unwrap();
		}
	}

	#[test]
	fn test_scorer_persistence() {
		let (_, nodes) = create_nodes(2, "test_scorer_persistence");
		let data_dir = nodes[0].kv_store.get_data_dir();
		let persister = Arc::new(Persister::new(data_dir));
		let event_handler = |_: _| Ok(());
		let bg_processor = BackgroundProcessor::start(
			persister,
			event_handler,
			Arc::clone(&nodes[0].chain_monitor),
			Arc::clone(&nodes[0].node),
			Some(Arc::clone(&nodes[0].messenger)),
			nodes[0].no_gossip_sync(),
			Arc::clone(&nodes[0].peer_manager),
			Some(Arc::clone(&nodes[0].liquidity_manager)),
			Some(Arc::clone(&nodes[0].sweeper)),
			Arc::clone(&nodes[0].logger),
			Some(Arc::clone(&nodes[0].scorer)),
		);

		loop {
			let log_entries = nodes[0].logger.lines.lock().unwrap();
			let expected_log = "Calling time_passed and persisting scorer".to_string();
			if log_entries.get(&("lightning_background_processor", expected_log)).is_some() {
				break;
			}
		}

		if !std::thread::panicking() {
			bg_processor.stop().unwrap();
		}
	}

	macro_rules! do_test_not_pruning_network_graph_until_graph_sync_completion {
		($nodes: expr, $receive: expr, $sleep: expr) => {
			let features = ChannelFeatures::empty();
			$nodes[0]
				.network_graph
				.add_channel_from_partial_announcement(
					42,
					None,
					53,
					features,
					$nodes[0].node.get_our_node_id().into(),
					$nodes[1].node.get_our_node_id().into(),
				)
				.expect("Failed to update channel from partial announcement");
			let original_graph_description = $nodes[0].network_graph.to_string();
			assert!(original_graph_description.contains("42: features: 0000, node_one:"));
			assert_eq!($nodes[0].network_graph.read_only().channels().len(), 1);

			loop {
				$sleep;
				let log_entries = $nodes[0].logger.lines.lock().unwrap();
				let loop_counter = "Calling ChannelManager's timer_tick_occurred".to_string();
				if *log_entries.get(&("lightning_background_processor", loop_counter)).unwrap_or(&0)
					> 1
				{
					// Wait until the loop has gone around at least twice.
					break;
				}
			}

			let initialization_input = vec![
				76, 68, 75, 1, 111, 226, 140, 10, 182, 241, 179, 114, 193, 166, 162, 70, 174, 99,
				247, 79, 147, 30, 131, 101, 225, 90, 8, 156, 104, 214, 25, 0, 0, 0, 0, 0, 97, 227,
				98, 218, 0, 0, 0, 4, 2, 22, 7, 207, 206, 25, 164, 197, 231, 230, 231, 56, 102, 61,
				250, 251, 187, 172, 38, 46, 79, 247, 108, 44, 155, 48, 219, 238, 252, 53, 192, 6,
				67, 2, 36, 125, 157, 176, 223, 175, 234, 116, 94, 248, 201, 225, 97, 235, 50, 47,
				115, 172, 63, 136, 88, 216, 115, 11, 111, 217, 114, 84, 116, 124, 231, 107, 2, 158,
				1, 242, 121, 152, 106, 204, 131, 186, 35, 93, 70, 216, 10, 237, 224, 183, 89, 95,
				65, 3, 83, 185, 58, 138, 181, 64, 187, 103, 127, 68, 50, 2, 201, 19, 17, 138, 136,
				149, 185, 226, 156, 137, 175, 110, 32, 237, 0, 217, 90, 31, 100, 228, 149, 46, 219,
				175, 168, 77, 4, 143, 38, 128, 76, 97, 0, 0, 0, 2, 0, 0, 255, 8, 153, 192, 0, 2,
				27, 0, 0, 0, 1, 0, 0, 255, 2, 68, 226, 0, 6, 11, 0, 1, 2, 3, 0, 0, 0, 2, 0, 40, 0,
				0, 0, 0, 0, 0, 3, 232, 0, 0, 3, 232, 0, 0, 0, 1, 0, 0, 0, 0, 58, 85, 116, 216, 255,
				8, 153, 192, 0, 2, 27, 0, 0, 25, 0, 0, 0, 1, 0, 0, 0, 125, 255, 2, 68, 226, 0, 6,
				11, 0, 1, 5, 0, 0, 0, 0, 29, 129, 25, 192,
			];
			$nodes[0]
				.rapid_gossip_sync
				.update_network_graph_no_std(&initialization_input[..], Some(1642291930))
				.unwrap();

			// this should have added two channels and pruned the previous one.
			assert_eq!($nodes[0].network_graph.read_only().channels().len(), 2);

			$receive.expect("Network graph not pruned within deadline");

			// all channels should now be pruned
			assert_eq!($nodes[0].network_graph.read_only().channels().len(), 0);
		};
	}

	#[test]
	fn test_not_pruning_network_graph_until_graph_sync_completion() {
		let (sender, receiver) = std::sync::mpsc::sync_channel(1);

		let (_, nodes) =
			create_nodes(2, "test_not_pruning_network_graph_until_graph_sync_completion");
		let data_dir = nodes[0].kv_store.get_data_dir();
		let persister = Arc::new(Persister::new(data_dir).with_graph_persistence_notifier(sender));

		let event_handler = |_: _| Ok(());
		let background_processor = BackgroundProcessor::start(
			persister,
			event_handler,
			Arc::clone(&nodes[0].chain_monitor),
			Arc::clone(&nodes[0].node),
			Some(Arc::clone(&nodes[0].messenger)),
			nodes[0].rapid_gossip_sync(),
			Arc::clone(&nodes[0].peer_manager),
			Some(Arc::clone(&nodes[0].liquidity_manager)),
			Some(Arc::clone(&nodes[0].sweeper)),
			Arc::clone(&nodes[0].logger),
			Some(Arc::clone(&nodes[0].scorer)),
		);

		do_test_not_pruning_network_graph_until_graph_sync_completion!(
			nodes,
			receiver.recv_timeout(super::FIRST_NETWORK_PRUNE_TIMER * 5),
			std::thread::sleep(Duration::from_millis(1))
		);

		background_processor.stop().unwrap();
	}

	#[tokio::test]
	async fn test_not_pruning_network_graph_until_graph_sync_completion_async() {
		let (sender, receiver) = std::sync::mpsc::sync_channel(1);

		let (_, nodes) =
			create_nodes(2, "test_not_pruning_network_graph_until_graph_sync_completion_async");
		let data_dir = nodes[0].kv_store.get_data_dir();
		let kv_store_sync =
			Arc::new(Persister::new(data_dir).with_graph_persistence_notifier(sender));
		let kv_store = KVStoreSyncWrapper(kv_store_sync);

		// Yes, you can unsafe { turn off the borrow checker }
		let lm_async: &'static LiquidityManager<_, _, _, _, _, _, _> = unsafe {
			&*(nodes[0].liquidity_manager.get_lm_async()
				as *const LiquidityManager<_, _, _, _, _, _, _>)
				as &'static LiquidityManager<_, _, _, _, _, _, _>
		};
		let sweeper_async: &'static OutputSweeper<_, _, _, _, _, _, _> = unsafe {
			&*(nodes[0].sweeper.sweeper_async() as *const OutputSweeper<_, _, _, _, _, _, _>)
				as &'static OutputSweeper<_, _, _, _, _, _, _>
		};

		let (exit_sender, exit_receiver) = tokio::sync::watch::channel(());
		let bp_future = super::process_events_async(
			kv_store,
			|_: _| async { Ok(()) },
			Arc::clone(&nodes[0].chain_monitor),
			Arc::clone(&nodes[0].node),
			Some(Arc::clone(&nodes[0].messenger)),
			nodes[0].rapid_gossip_sync(),
			Arc::clone(&nodes[0].peer_manager),
			Some(lm_async),
			Some(sweeper_async),
			Arc::clone(&nodes[0].logger),
			Some(Arc::clone(&nodes[0].scorer)),
			move |dur: Duration| {
				let mut exit_receiver = exit_receiver.clone();
				Box::pin(async move {
					tokio::select! {
						_ = tokio::time::sleep(dur) => false,
						_ = exit_receiver.changed() => true,
					}
				})
			},
			false,
			|| Some(Duration::from_secs(1696300000)),
		);

		let t1 = tokio::spawn(bp_future);
		let t2 = tokio::spawn(async move {
			do_test_not_pruning_network_graph_until_graph_sync_completion!(
				nodes,
				{
					let mut i = 0;
					loop {
						tokio::time::sleep(super::FIRST_NETWORK_PRUNE_TIMER).await;
						if let Ok(()) = receiver.try_recv() {
							break Ok::<(), ()>(());
						}
						assert!(i < 5);
						i += 1;
					}
				},
				tokio::time::sleep(Duration::from_millis(1)).await
			);
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
				maybe_announced_channel: true,
			}], blinded_tail: None };

			$nodes[0].scorer.write_lock().expect(TestResult::PaymentFailure { path: path.clone(), short_channel_id: scored_scid });
			$nodes[0].node.push_pending_event(Event::PaymentPathFailed {
				payment_id: None,
				payment_hash: PaymentHash([42; 32]),
				payment_failed_permanently: false,
				failure: PathFailure::OnPath { network_update: None },
				path: path.clone(),
				short_channel_id: Some(scored_scid),
				error_code: None,
				error_data: None,
				hold_times: Vec::new(),
			});
			let event = $receive.expect("PaymentPathFailed not handled within deadline");
			match event {
				Event::PaymentPathFailed { .. } => {},
				_ => panic!("Unexpected event"),
			}

			// Ensure we'll score payments that were explicitly failed back by the destination as
			// ProbeSuccess.
			$nodes[0].scorer.write_lock().expect(TestResult::ProbeSuccess { path: path.clone() });
			$nodes[0].node.push_pending_event(Event::PaymentPathFailed {
				payment_id: None,
				payment_hash: PaymentHash([42; 32]),
				payment_failed_permanently: true,
				failure: PathFailure::OnPath { network_update: None },
				path: path.clone(),
				short_channel_id: None,
				error_code: None,
				error_data: None,
				hold_times: Vec::new(),
			});
			let event = $receive.expect("PaymentPathFailed not handled within deadline");
			match event {
				Event::PaymentPathFailed { .. } => {},
				_ => panic!("Unexpected event"),
			}

			$nodes[0].scorer.write_lock().expect(TestResult::PaymentSuccess { path: path.clone() });
			$nodes[0].node.push_pending_event(Event::PaymentPathSuccessful {
				payment_id: PaymentId([42; 32]),
				payment_hash: None,
				path: path.clone(),
				hold_times: Vec::new(),
			});
			let event = $receive.expect("PaymentPathSuccessful not handled within deadline");
			match event {
				Event::PaymentPathSuccessful { .. } => {},
				_ => panic!("Unexpected event"),
			}

			$nodes[0].scorer.write_lock().expect(TestResult::ProbeSuccess { path: path.clone() });
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

			$nodes[0].scorer.write_lock().expect(TestResult::ProbeFailure { path: path.clone() });
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
		let event_handler = move |event: Event| {
			match event {
				Event::PaymentPathFailed { .. } => sender.send(event).unwrap(),
				Event::PaymentPathSuccessful { .. } => sender.send(event).unwrap(),
				Event::ProbeSuccessful { .. } => sender.send(event).unwrap(),
				Event::ProbeFailed { .. } => sender.send(event).unwrap(),
				_ => panic!("Unexpected event: {:?}", event),
			}
			Ok(())
		};

		let (_, nodes) = create_nodes(1, "test_payment_path_scoring");
		let data_dir = nodes[0].kv_store.get_data_dir();
		let persister = Arc::new(Persister::new(data_dir));
		let bg_processor = BackgroundProcessor::start(
			persister,
			event_handler,
			Arc::clone(&nodes[0].chain_monitor),
			Arc::clone(&nodes[0].node),
			Some(Arc::clone(&nodes[0].messenger)),
			nodes[0].no_gossip_sync(),
			Arc::clone(&nodes[0].peer_manager),
			Some(Arc::clone(&nodes[0].liquidity_manager)),
			Some(Arc::clone(&nodes[0].sweeper)),
			Arc::clone(&nodes[0].logger),
			Some(Arc::clone(&nodes[0].scorer)),
		);

		do_test_payment_path_scoring!(nodes, receiver.recv_timeout(EVENT_DEADLINE));

		if !std::thread::panicking() {
			bg_processor.stop().unwrap();
		}

		let log_entries = nodes[0].logger.lines.lock().unwrap();
		let expected_log = "Persisting scorer after update".to_string();
		assert_eq!(*log_entries.get(&("lightning_background_processor", expected_log)).unwrap(), 5);
	}

	#[tokio::test]
	async fn test_payment_path_scoring_async() {
		let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
		let event_handler = move |event: Event| {
			let sender_ref = sender.clone();
			async move {
				match event {
					Event::PaymentPathFailed { .. } => sender_ref.send(event).await.unwrap(),
					Event::PaymentPathSuccessful { .. } => sender_ref.send(event).await.unwrap(),
					Event::ProbeSuccessful { .. } => sender_ref.send(event).await.unwrap(),
					Event::ProbeFailed { .. } => sender_ref.send(event).await.unwrap(),
					_ => panic!("Unexpected event: {:?}", event),
				}
				Ok(())
			}
		};

		let (_, nodes) = create_nodes(1, "test_payment_path_scoring_async");
		let data_dir = nodes[0].kv_store.get_data_dir();
		let kv_store_sync = Arc::new(Persister::new(data_dir));
		let kv_store = KVStoreSyncWrapper(kv_store_sync);

		let (exit_sender, exit_receiver) = tokio::sync::watch::channel(());

		// Yes, you can unsafe { turn off the borrow checker }
		let lm_async: &'static LiquidityManager<_, _, _, _, _, _, _> = unsafe {
			&*(nodes[0].liquidity_manager.get_lm_async()
				as *const LiquidityManager<_, _, _, _, _, _, _>)
				as &'static LiquidityManager<_, _, _, _, _, _, _>
		};
		let sweeper_async: &'static OutputSweeper<_, _, _, _, _, _, _> = unsafe {
			&*(nodes[0].sweeper.sweeper_async() as *const OutputSweeper<_, _, _, _, _, _, _>)
				as &'static OutputSweeper<_, _, _, _, _, _, _>
		};

		let bp_future = super::process_events_async(
			kv_store,
			event_handler,
			Arc::clone(&nodes[0].chain_monitor),
			Arc::clone(&nodes[0].node),
			Some(Arc::clone(&nodes[0].messenger)),
			nodes[0].no_gossip_sync(),
			Arc::clone(&nodes[0].peer_manager),
			Some(lm_async),
			Some(sweeper_async),
			Arc::clone(&nodes[0].logger),
			Some(Arc::clone(&nodes[0].scorer)),
			move |dur: Duration| {
				let mut exit_receiver = exit_receiver.clone();
				Box::pin(async move {
					tokio::select! {
						_ = tokio::time::sleep(dur) => false,
						_ = exit_receiver.changed() => true,
					}
				})
			},
			false,
			|| Some(Duration::ZERO),
		);
		let t1 = tokio::spawn(bp_future);
		let t2 = tokio::spawn(async move {
			do_test_payment_path_scoring!(nodes, receiver.recv().await);
			exit_sender.send(()).unwrap();

			let log_entries = nodes[0].logger.lines.lock().unwrap();
			let expected_log = "Persisting scorer after update".to_string();
			assert_eq!(
				*log_entries.get(&("lightning_background_processor", expected_log)).unwrap(),
				5
			);
		});

		let (r1, r2) = tokio::join!(t1, t2);
		r1.unwrap().unwrap();
		r2.unwrap()
	}

	#[tokio::test]
	#[cfg(not(c_bindings))]
	async fn test_no_consts() {
		// Compile-test the NO_* constants can be used.
		let (_, nodes) = create_nodes(1, "test_no_consts");
		let bg_processor = BackgroundProcessor::start(
			Arc::clone(&nodes[0].kv_store),
			move |_: Event| Ok(()),
			Arc::clone(&nodes[0].chain_monitor),
			Arc::clone(&nodes[0].node),
			crate::NO_ONION_MESSENGER,
			nodes[0].no_gossip_sync(),
			Arc::clone(&nodes[0].peer_manager),
			crate::NO_LIQUIDITY_MANAGER_SYNC,
			Some(Arc::clone(&nodes[0].sweeper)),
			Arc::clone(&nodes[0].logger),
			Some(Arc::clone(&nodes[0].scorer)),
		);

		if !std::thread::panicking() {
			bg_processor.stop().unwrap();
		}

		let kv_store = KVStoreSyncWrapper(Arc::clone(&nodes[0].kv_store));
		let (exit_sender, exit_receiver) = tokio::sync::watch::channel(());
		let sweeper_async: &'static OutputSweeper<_, _, _, _, _, _, _> = unsafe {
			&*(nodes[0].sweeper.sweeper_async() as *const OutputSweeper<_, _, _, _, _, _, _>)
				as &'static OutputSweeper<_, _, _, _, _, _, _>
		};
		let bp_future = super::process_events_async(
			kv_store,
			move |_: Event| async move { Ok(()) },
			Arc::clone(&nodes[0].chain_monitor),
			Arc::clone(&nodes[0].node),
			crate::NO_ONION_MESSENGER,
			nodes[0].no_gossip_sync(),
			Arc::clone(&nodes[0].peer_manager),
			crate::NO_LIQUIDITY_MANAGER,
			Some(sweeper_async),
			Arc::clone(&nodes[0].logger),
			Some(Arc::clone(&nodes[0].scorer)),
			move |dur: Duration| {
				let mut exit_receiver = exit_receiver.clone();
				Box::pin(async move {
					tokio::select! {
						_ = tokio::time::sleep(dur) => false,
						_ = exit_receiver.changed() => true,
					}
				})
			},
			false,
			|| Some(Duration::ZERO),
		);
		let t1 = tokio::spawn(bp_future);
		exit_sender.send(()).unwrap();
		t1.await.unwrap().unwrap();
	}

	#[test]
	fn test_monitor_archive() {
		let (persist_dir, nodes) = create_nodes(2, "test_monitor_archive");
		// Open a channel, but don't confirm it so that it prunes immediately on FC.
		open_channel!(nodes[0], nodes[1], 100000);

		let data_dir = nodes[1].kv_store.get_data_dir();
		let persister = Arc::new(Persister::new(data_dir));
		let event_handler = |_: _| Ok(());
		let bp = BackgroundProcessor::start(
			persister,
			event_handler,
			Arc::clone(&nodes[1].chain_monitor),
			Arc::clone(&nodes[1].node),
			Some(Arc::clone(&nodes[1].messenger)),
			nodes[1].p2p_gossip_sync(),
			Arc::clone(&nodes[1].peer_manager),
			Some(Arc::clone(&nodes[1].liquidity_manager)),
			Some(Arc::clone(&nodes[1].sweeper)),
			Arc::clone(&nodes[1].logger),
			Some(Arc::clone(&nodes[1].scorer)),
		);

		let dir = format!("{}_persister_1/monitors", &persist_dir);
		let mut mons = std::fs::read_dir(&dir).unwrap();
		let mut mon = mons.next().unwrap().unwrap();
		if mon.path().to_str().unwrap().ends_with(".tmp") {
			mon = mons.next().unwrap().unwrap();
			assert_eq!(mon.path().extension(), None);
		}
		assert!(mons.next().is_none());

		// Because the channel wasn't funded, we'll archive the ChannelMonitor immedaitely after
		// its force-closed (at least on node B, which didn't put their money into it).
		nodes[1].node.force_close_all_channels_broadcasting_latest_txn("".to_owned());
		loop {
			let mut mons = std::fs::read_dir(&dir).unwrap();
			if let Some(new_mon) = mons.next() {
				let mut new_mon = new_mon.unwrap();
				if new_mon.path().to_str().unwrap().ends_with(".tmp") {
					new_mon = mons.next().unwrap().unwrap();
					assert_eq!(new_mon.path().extension(), None);
				}
				assert_eq!(new_mon.path(), mon.path());
				assert!(mons.next().is_none());
			} else {
				break;
			}
		}

		bp.stop().unwrap();
	}

	#[tokio::test]
	#[cfg(not(c_bindings))]
	async fn test_monitor_archive_async() {
		let (persist_dir, nodes) = create_nodes(2, "test_monitor_archive_async");
		// Open a channel, but don't confirm it so that it prunes immediately on FC.
		open_channel!(nodes[0], nodes[1], 100000);

		let kv_store = KVStoreSyncWrapper(Arc::clone(&nodes[0].kv_store));
		let sweeper_async: &'static OutputSweeper<_, _, _, _, _, _, _> = unsafe {
			&*(nodes[0].sweeper.sweeper_async() as *const OutputSweeper<_, _, _, _, _, _, _>)
				as &'static OutputSweeper<_, _, _, _, _, _, _>
		};
		let (exit_sender, exit_receiver) = tokio::sync::watch::channel(());
		let bp_future = tokio::spawn(super::process_events_async(
			kv_store,
			move |_: Event| async move { Ok(()) },
			Arc::clone(&nodes[1].chain_monitor),
			Arc::clone(&nodes[1].node),
			crate::NO_ONION_MESSENGER,
			nodes[1].no_gossip_sync(),
			Arc::clone(&nodes[1].peer_manager),
			crate::NO_LIQUIDITY_MANAGER,
			Some(sweeper_async),
			Arc::clone(&nodes[1].logger),
			Some(Arc::clone(&nodes[1].scorer)),
			move |dur: Duration| {
				let mut exit_receiver = exit_receiver.clone();
				Box::pin(async move {
					tokio::select! {
						_ = tokio::time::sleep(dur) => false,
						_ = exit_receiver.changed() => true,
					}
				})
			},
			false,
			|| Some(Duration::ZERO),
		));

		let dir = format!("{}_persister_1/monitors", &persist_dir);
		let mut mons = std::fs::read_dir(&dir).unwrap();
		let mut mon = mons.next().unwrap().unwrap();
		if mon.path().to_str().unwrap().ends_with(".tmp") {
			mon = mons.next().unwrap().unwrap();
			assert_eq!(mon.path().extension(), None);
		}
		assert!(mons.next().is_none());

		// Because the channel wasn't funded, we'll archive the ChannelMonitor immedaitely after
		// its force-closed (at least on node B, which didn't put their money into it).
		nodes[1].node.force_close_all_channels_broadcasting_latest_txn("".to_owned());
		loop {
			let mut mons = std::fs::read_dir(&dir).unwrap();
			if let Some(new_mon) = mons.next() {
				let mut new_mon = new_mon.unwrap();
				if new_mon.path().to_str().unwrap().ends_with(".tmp") {
					new_mon = mons.next().unwrap().unwrap();
					assert_eq!(new_mon.path().extension(), None);
				}
				assert_eq!(new_mon.path(), mon.path());
				assert!(mons.next().is_none());
			} else {
				break;
			}
			tokio::task::yield_now().await;
		}

		exit_sender.send(()).unwrap();
		bp_future.await.unwrap().unwrap();
	}
}
