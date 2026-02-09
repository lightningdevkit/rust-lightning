// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

use crate::blinded_path::message::MessageContext;
use crate::blinded_path::message::{BlindedMessagePath, MessageForwardNode};
use crate::blinded_path::payment::{BlindedPaymentPath, ReceiveTlvs};
use crate::chain;
use crate::chain::chaininterface;
#[cfg(any(test, feature = "_externalize_tests"))]
use crate::chain::chaininterface::FEERATE_FLOOR_SATS_PER_KW;
use crate::chain::chaininterface::{ConfirmationTarget, TransactionType};
use crate::chain::chainmonitor::{ChainMonitor, Persist};
use crate::chain::channelmonitor::{
	ChannelMonitor, ChannelMonitorUpdate, ChannelMonitorUpdateStep, MonitorEvent,
};
use crate::chain::transaction::OutPoint;
use crate::chain::WatchedOutput;
#[cfg(any(test, feature = "_externalize_tests"))]
use crate::ln::chan_utils::CommitmentTransaction;
use crate::ln::channel_state::ChannelDetails;
use crate::ln::channelmanager;
use crate::ln::inbound_payment::ExpandedKey;
use crate::ln::msgs::{BaseMessageHandler, MessageSendEvent};
use crate::ln::script::ShutdownScript;
use crate::ln::types::ChannelId;
use crate::ln::{msgs, wire};
use crate::offers::invoice::UnsignedBolt12Invoice;
use crate::onion_message::messenger::{
	DefaultMessageRouter, Destination, MessageRouter, NodeIdMessageRouter, OnionMessagePath,
};
use crate::routing::gossip::{EffectiveCapacity, NetworkGraph, NodeId, RoutingFees};
use crate::routing::router::{
	CandidateRouteHop, FirstHopCandidate, PrivateHopCandidate, PublicHopCandidate,
};
use crate::routing::router::{
	DefaultRouter, InFlightHtlcs, Path, Route, RouteHintHop, RouteParameters, Router,
	ScorerAccountingForInFlightHtlcs,
};
use crate::routing::scoring::{ChannelUsage, ScoreLookUp, ScoreUpdate};
use crate::routing::utxo::{UtxoLookup, UtxoLookupError, UtxoResult};
use crate::sign::{self, ReceiveAuthKey};
use crate::sign::{ChannelSigner, PeerStorageKey};
use crate::sync::RwLock;
use crate::types::features::{ChannelFeatures, InitFeatures, NodeFeatures};
use crate::util::async_poll::MaybeSend;
use crate::util::config::UserConfig;
use crate::util::dyn_signer::{
	DynKeysInterface, DynKeysInterfaceTrait, DynPhantomKeysInterface, DynSigner,
};
use crate::util::logger::{Logger, Record};
#[cfg(feature = "std")]
use crate::util::mut_global::MutGlobal;
use crate::util::persist::{KVStore, KVStoreSync, MonitorName};
use crate::util::ser::{Readable, ReadableArgs, Writeable, Writer};
use crate::util::test_channel_signer::{EnforcementState, TestChannelSigner};
use crate::util::wakers::Notifier;
use crate::util::wallet_utils::{ConfirmedUtxo, Utxo, WalletSourceSync};

use bitcoin::amount::Amount;
use bitcoin::block::Block;
use bitcoin::constants::genesis_block;
use bitcoin::constants::ChainHash;
use bitcoin::hash_types::{BlockHash, Txid};
use bitcoin::hashes::{hex::FromHex, Hash};
use bitcoin::network::Network;
use bitcoin::script::{Builder, Script, ScriptBuf};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::transaction::{Transaction, TxOut};
use bitcoin::{opcodes, Witness};

use bitcoin::secp256k1::ecdh::SharedSecret;
use bitcoin::secp256k1::ecdsa::{RecoverableSignature, Signature};
use bitcoin::secp256k1::schnorr;
use bitcoin::secp256k1::{self, PublicKey, Scalar, Secp256k1, SecretKey};

use lightning_invoice::RawBolt11Invoice;
use lightning_types::payment::{PaymentHash, PaymentPreimage};

use crate::io;
use crate::prelude::*;
use crate::sign::{EntropySource, NodeSigner, RandomBytes, Recipient, SignerProvider};
use crate::sync::{Arc, Mutex};
use alloc::boxed::Box;
use core::future::Future;
use core::mem;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use core::task::{Context, Poll, Waker};
use core::time::Duration;

use bitcoin::psbt::Psbt;
use bitcoin::Sequence;

use super::test_channel_signer::SignerOp;

pub fn pubkey(byte: u8) -> PublicKey {
	let secp_ctx = Secp256k1::new();
	PublicKey::from_secret_key(&secp_ctx, &privkey(byte))
}

pub fn privkey(byte: u8) -> SecretKey {
	SecretKey::from_slice(&[byte; 32]).unwrap()
}

pub fn secret_from_hex(hex: &str) -> SecretKey {
	SecretKey::from_slice(&<Vec<u8>>::from_hex(hex).unwrap()).unwrap()
}

pub fn bytes_from_hex(hex: &str) -> Vec<u8> {
	<Vec<u8>>::from_hex(hex).unwrap()
}

pub fn pubkey_from_hex(hex: &str) -> PublicKey {
	PublicKey::from_slice(&<Vec<u8>>::from_hex(hex).unwrap()).unwrap()
}

pub fn preimage_from_hex(hex: &str) -> PaymentPreimage {
	PaymentPreimage(<Vec<u8>>::from_hex(hex).unwrap().try_into().unwrap())
}

pub fn public_from_secret_hex(
	secp_ctx: &Secp256k1<bitcoin::secp256k1::All>, hex: &str,
) -> PublicKey {
	let secret = SecretKey::from_slice(&<Vec<u8>>::from_hex(hex).unwrap()[..]).unwrap();
	PublicKey::from_secret_key(&secp_ctx, &secret)
}

pub fn payment_hash_from_hex(hex: &str) -> PaymentHash {
	PaymentHash(<Vec<u8>>::from_hex(hex).unwrap().try_into().unwrap())
}

pub struct TestVecWriter(pub Vec<u8>);
impl Writer for TestVecWriter {
	fn write_all(&mut self, buf: &[u8]) -> Result<(), io::Error> {
		self.0.extend_from_slice(buf);
		Ok(())
	}
}

pub struct TestFeeEstimator {
	pub sat_per_kw: Mutex<u32>,
	pub target_override: Mutex<HashMap<ConfirmationTarget, u32>>,
}
impl TestFeeEstimator {
	pub fn new(sat_per_kw: u32) -> Self {
		let sat_per_kw = Mutex::new(sat_per_kw);
		let target_override = Mutex::new(new_hash_map());
		Self { sat_per_kw, target_override }
	}
}
impl chaininterface::FeeEstimator for TestFeeEstimator {
	fn get_est_sat_per_1000_weight(&self, conf_target: ConfirmationTarget) -> u32 {
		*self
			.target_override
			.lock()
			.unwrap()
			.get(&conf_target)
			.unwrap_or(&*self.sat_per_kw.lock().unwrap())
	}
}

pub struct TestRouter<'a> {
	pub router: DefaultRouter<
		Arc<NetworkGraph<&'a TestLogger>>,
		&'a TestLogger,
		Arc<RandomBytes>,
		&'a RwLock<TestScorer>,
		(),
		TestScorer,
	>,
	pub network_graph: Arc<NetworkGraph<&'a TestLogger>>,
	pub next_routes: Mutex<VecDeque<(RouteParameters, Option<Result<Route, &'static str>>)>>,
	pub next_blinded_payment_paths: Mutex<Vec<BlindedPaymentPath>>,
	pub scorer: &'a RwLock<TestScorer>,
}

impl<'a> TestRouter<'a> {
	pub fn new(
		network_graph: Arc<NetworkGraph<&'a TestLogger>>, logger: &'a TestLogger,
		scorer: &'a RwLock<TestScorer>,
	) -> Self {
		let entropy_source = Arc::new(RandomBytes::new([42; 32]));
		let next_routes = Mutex::new(VecDeque::new());
		let next_blinded_payment_paths = Mutex::new(Vec::new());
		Self {
			router: DefaultRouter::new(
				Arc::clone(&network_graph),
				logger,
				entropy_source,
				scorer,
				Default::default(),
			),
			network_graph,
			next_routes,
			next_blinded_payment_paths,
			scorer,
		}
	}

	pub fn expect_find_route(&self, query: RouteParameters, result: Result<Route, &'static str>) {
		let mut expected_routes = self.next_routes.lock().unwrap();
		expected_routes.push_back((query, Some(result)));
	}

	pub fn expect_find_route_query(&self, query: RouteParameters) {
		let mut expected_routes = self.next_routes.lock().unwrap();
		expected_routes.push_back((query, None));
	}

	pub fn expect_blinded_payment_paths(&self, mut paths: Vec<BlindedPaymentPath>) {
		let mut expected_paths = self.next_blinded_payment_paths.lock().unwrap();
		core::mem::swap(&mut *expected_paths, &mut paths);
	}
}

impl<'a> Router for TestRouter<'a> {
	fn find_route(
		&self, payer: &PublicKey, params: &RouteParameters, first_hops: Option<&[&ChannelDetails]>,
		inflight_htlcs: InFlightHtlcs,
	) -> Result<Route, &'static str> {
		let route_res;
		let next_route_opt = self.next_routes.lock().unwrap().pop_front();
		if let Some((find_route_query, find_route_res)) = next_route_opt {
			assert_eq!(find_route_query, *params);
			if let Some(res) = find_route_res {
				if let Ok(ref route) = res {
					assert_eq!(route.route_params, Some(find_route_query));
					let scorer = self.scorer.read().unwrap();
					let scorer = ScorerAccountingForInFlightHtlcs::new(scorer, &inflight_htlcs);
					for path in &route.paths {
						let mut aggregate_msat = 0u64;
						let mut prev_hop_node = payer;
						for (idx, hop) in path.hops.iter().rev().enumerate() {
							aggregate_msat += hop.fee_msat;
							let usage = ChannelUsage {
								amount_msat: aggregate_msat,
								inflight_htlc_msat: 0,
								effective_capacity: EffectiveCapacity::Unknown,
							};

							if idx == path.hops.len() - 1 {
								if let Some(first_hops) = first_hops {
									if let Some(idx) = first_hops.iter().position(|h| {
										h.get_outbound_payment_scid() == Some(hop.short_channel_id)
									}) {
										let node_id = NodeId::from_pubkey(payer);
										let candidate =
											CandidateRouteHop::FirstHop(FirstHopCandidate {
												details: first_hops[idx],
												payer_node_id: &node_id,
												payer_node_counter: u32::max_value(),
												target_node_counter: u32::max_value(),
											});
										scorer.channel_penalty_msat(
											&candidate,
											usage,
											&Default::default(),
										);
										continue;
									}
								}
							}
							let network_graph = self.network_graph.read_only();
							if let Some(channel) = network_graph.channel(hop.short_channel_id) {
								let (directed, _) = channel
									.as_directed_to(&NodeId::from_pubkey(&hop.pubkey))
									.unwrap();
								let candidate = CandidateRouteHop::PublicHop(PublicHopCandidate {
									info: directed,
									short_channel_id: hop.short_channel_id,
								});
								scorer.channel_penalty_msat(&candidate, usage, &Default::default());
							} else {
								let target_node_id = NodeId::from_pubkey(&hop.pubkey);
								let route_hint = RouteHintHop {
									src_node_id: *prev_hop_node,
									short_channel_id: hop.short_channel_id,
									fees: RoutingFees { base_msat: 0, proportional_millionths: 0 },
									cltv_expiry_delta: 0,
									htlc_minimum_msat: None,
									htlc_maximum_msat: None,
								};
								let candidate =
									CandidateRouteHop::PrivateHop(PrivateHopCandidate {
										hint: &route_hint,
										target_node_id: &target_node_id,
										source_node_counter: u32::max_value(),
										target_node_counter: u32::max_value(),
									});
								scorer.channel_penalty_msat(&candidate, usage, &Default::default());
							}
							prev_hop_node = &hop.pubkey;
						}
					}
				}
				route_res = res;
			} else {
				route_res = self.router.find_route(payer, params, first_hops, inflight_htlcs);
			}
		} else {
			route_res = self.router.find_route(payer, params, first_hops, inflight_htlcs);
		};

		if let Ok(route) = &route_res {
			// Previously, `Route`s failed to round-trip through serialization due to a write/read
			// mismatch. Thus, here we test all test-generated routes round-trip:
			let ser = route.encode();
			assert_eq!(Route::read(&mut &ser[..]).unwrap(), *route);
		}
		route_res
	}

	fn create_blinded_payment_paths<T: secp256k1::Signing + secp256k1::Verification>(
		&self, recipient: PublicKey, local_node_receive_key: ReceiveAuthKey,
		first_hops: Vec<ChannelDetails>, tlvs: ReceiveTlvs, amount_msats: Option<u64>,
		secp_ctx: &Secp256k1<T>,
	) -> Result<Vec<BlindedPaymentPath>, ()> {
		let mut expected_paths = self.next_blinded_payment_paths.lock().unwrap();
		if expected_paths.is_empty() {
			self.router.create_blinded_payment_paths(
				recipient,
				local_node_receive_key,
				first_hops,
				tlvs,
				amount_msats,
				secp_ctx,
			)
		} else {
			Ok(core::mem::take(&mut *expected_paths))
		}
	}
}

impl<'a> Drop for TestRouter<'a> {
	fn drop(&mut self) {
		if std::thread::panicking() {
			return;
		}
		assert!(self.next_routes.lock().unwrap().is_empty());
	}
}

pub enum TestMessageRouterInternal<'a> {
	Default(
		DefaultMessageRouter<
			Arc<NetworkGraph<&'a TestLogger>>,
			&'a TestLogger,
			&'a TestKeysInterface,
		>,
	),
	NodeId(
		NodeIdMessageRouter<
			Arc<NetworkGraph<&'a TestLogger>>,
			&'a TestLogger,
			&'a TestKeysInterface,
		>,
	),
}

pub struct TestMessageRouter<'a> {
	pub inner: TestMessageRouterInternal<'a>,
	pub peers_override: Mutex<Vec<PublicKey>>,
}

impl<'a> TestMessageRouter<'a> {
	pub fn new_default(
		network_graph: Arc<NetworkGraph<&'a TestLogger>>, entropy_source: &'a TestKeysInterface,
	) -> Self {
		Self {
			inner: TestMessageRouterInternal::Default(DefaultMessageRouter::new(
				network_graph,
				entropy_source,
			)),
			peers_override: Mutex::new(Vec::new()),
		}
	}

	pub fn new_node_id_router(
		network_graph: Arc<NetworkGraph<&'a TestLogger>>, entropy_source: &'a TestKeysInterface,
	) -> Self {
		Self {
			inner: TestMessageRouterInternal::NodeId(NodeIdMessageRouter::new(
				network_graph,
				entropy_source,
			)),
			peers_override: Mutex::new(Vec::new()),
		}
	}
}

impl<'a> MessageRouter for TestMessageRouter<'a> {
	fn find_path(
		&self, sender: PublicKey, peers: Vec<PublicKey>, destination: Destination,
	) -> Result<OnionMessagePath, ()> {
		let mut peers = peers;
		{
			let peers_override = self.peers_override.lock().unwrap();
			if !peers_override.is_empty() {
				peers = peers_override.clone();
			}
		}
		match &self.inner {
			TestMessageRouterInternal::Default(inner) => {
				inner.find_path(sender, peers, destination)
			},
			TestMessageRouterInternal::NodeId(inner) => inner.find_path(sender, peers, destination),
		}
	}

	fn create_blinded_paths<T: secp256k1::Signing + secp256k1::Verification>(
		&self, recipient: PublicKey, local_node_receive_key: ReceiveAuthKey,
		context: MessageContext, peers: Vec<MessageForwardNode>, secp_ctx: &Secp256k1<T>,
	) -> Result<Vec<BlindedMessagePath>, ()> {
		let mut peers = peers;
		{
			let peers_override = self.peers_override.lock().unwrap();
			if !peers_override.is_empty() {
				let peer_override_nodes: Vec<_> = peers_override
					.iter()
					.map(|pk| MessageForwardNode { node_id: *pk, short_channel_id: None })
					.collect();
				peers = peer_override_nodes;
			}
		}
		match &self.inner {
			TestMessageRouterInternal::Default(inner) => inner.create_blinded_paths(
				recipient,
				local_node_receive_key,
				context,
				peers,
				secp_ctx,
			),
			TestMessageRouterInternal::NodeId(inner) => inner.create_blinded_paths(
				recipient,
				local_node_receive_key,
				context,
				peers,
				secp_ctx,
			),
		}
	}
}

pub struct OnlyReadsKeysInterface {}

impl EntropySource for OnlyReadsKeysInterface {
	fn get_secure_random_bytes(&self) -> [u8; 32] {
		[0; 32]
	}
}

impl SignerProvider for OnlyReadsKeysInterface {
	type EcdsaSigner = TestChannelSigner;
	#[cfg(taproot)]
	type TaprootSigner = TestChannelSigner;

	fn generate_channel_keys_id(&self, _inbound: bool, _user_channel_id: u128) -> [u8; 32] {
		unreachable!();
	}

	fn derive_channel_signer(&self, _channel_keys_id: [u8; 32]) -> Self::EcdsaSigner {
		unreachable!();
	}

	fn get_destination_script(&self, _channel_keys_id: [u8; 32]) -> Result<ScriptBuf, ()> {
		Err(())
	}
	fn get_shutdown_scriptpubkey(&self) -> Result<ShutdownScript, ()> {
		Err(())
	}
}

#[cfg(feature = "std")]
pub trait SyncBroadcaster: chaininterface::BroadcasterInterface + Sync {}
#[cfg(feature = "std")]
pub trait SyncPersist: Persist<TestChannelSigner> + Sync {}
#[cfg(feature = "std")]
impl<T: chaininterface::BroadcasterInterface + Sync> SyncBroadcaster for T {}
#[cfg(feature = "std")]
impl<T: Persist<TestChannelSigner> + Sync> SyncPersist for T {}

#[cfg(not(feature = "std"))]
pub trait SyncBroadcaster: chaininterface::BroadcasterInterface {}
#[cfg(not(feature = "std"))]
pub trait SyncPersist: Persist<TestChannelSigner> {}
#[cfg(not(feature = "std"))]
impl<T: chaininterface::BroadcasterInterface> SyncBroadcaster for T {}
#[cfg(not(feature = "std"))]
impl<T: Persist<TestChannelSigner>> SyncPersist for T {}

pub struct TestChainMonitor<'a> {
	pub added_monitors: Mutex<Vec<(ChannelId, ChannelMonitor<TestChannelSigner>)>>,
	pub monitor_updates: Mutex<HashMap<ChannelId, Vec<ChannelMonitorUpdate>>>,
	pub latest_monitor_update_id: Mutex<HashMap<ChannelId, (u64, u64)>>,
	pub chain_monitor: ChainMonitor<
		TestChannelSigner,
		&'a TestChainSource,
		&'a dyn SyncBroadcaster,
		&'a TestFeeEstimator,
		&'a TestLogger,
		&'a dyn SyncPersist,
		&'a TestKeysInterface,
	>,
	pub keys_manager: &'a TestKeysInterface,
	/// If this is set to Some(), the next update_channel call (not watch_channel) must be a
	/// ChannelForceClosed event for the given channel_id with should_broadcast set to the given
	/// boolean.
	pub expect_channel_force_closed: Mutex<Option<(ChannelId, bool)>>,
	/// If this is set to Some(), the next round trip serialization check will not hold after an
	/// update_channel call (not watch_channel) for the given channel_id.
	pub expect_monitor_round_trip_fail: Mutex<Option<ChannelId>>,
	#[cfg(feature = "std")]
	pub write_blocker: Mutex<Option<std::sync::mpsc::Receiver<()>>>,
}
impl<'a> TestChainMonitor<'a> {
	pub fn new(
		chain_source: Option<&'a TestChainSource>, broadcaster: &'a dyn SyncBroadcaster,
		logger: &'a TestLogger, fee_estimator: &'a TestFeeEstimator,
		persister: &'a dyn SyncPersist, keys_manager: &'a TestKeysInterface,
	) -> Self {
		Self {
			added_monitors: Mutex::new(Vec::new()),
			monitor_updates: Mutex::new(new_hash_map()),
			latest_monitor_update_id: Mutex::new(new_hash_map()),
			chain_monitor: ChainMonitor::new(
				chain_source,
				broadcaster,
				logger,
				fee_estimator,
				persister,
				keys_manager,
				keys_manager.get_peer_storage_key(),
				false,
			),
			keys_manager,
			expect_channel_force_closed: Mutex::new(None),
			expect_monitor_round_trip_fail: Mutex::new(None),
			#[cfg(feature = "std")]
			write_blocker: Mutex::new(None),
		}
	}

	pub fn complete_sole_pending_chan_update(&self, channel_id: &ChannelId) {
		let (_, latest_update) =
			self.latest_monitor_update_id.lock().unwrap().get(channel_id).unwrap().clone();
		self.chain_monitor.channel_monitor_updated(*channel_id, latest_update).unwrap();
	}

	pub fn load_existing_monitor(
		&self, channel_id: ChannelId, monitor: ChannelMonitor<TestChannelSigner>,
	) -> Result<chain::ChannelMonitorUpdateStatus, ()> {
		#[cfg(feature = "std")]
		if let Some(blocker) = &*self.write_blocker.lock().unwrap() {
			blocker.recv().unwrap();
		}

		// Test that a monitor survives a round-trip, and use the round-tripped monitor in the
		// underlying `ChainMonitor`.
		let mut w = TestVecWriter(Vec::new());
		monitor.write(&mut w).unwrap();
		let new_monitor = <(BlockHash, ChannelMonitor<TestChannelSigner>)>::read(
			&mut io::Cursor::new(&w.0),
			(self.keys_manager, self.keys_manager),
		)
		.unwrap()
		.1;
		// Note that a ChannelMonitor might not round-trip exactly here as we have tests that were
		// serialized prior to LDK 0.1 and re-serializing them will flip the "written after LDK
		// 0.1" flag. Thus, unlike the code in `watch_channel` below, we do not assert that the
		// monitor is the same after a serialization round-trip.
		self.latest_monitor_update_id
			.lock()
			.unwrap()
			.insert(channel_id, (monitor.get_latest_update_id(), monitor.get_latest_update_id()));
		self.added_monitors.lock().unwrap().push((channel_id, monitor));
		self.chain_monitor.load_existing_monitor(channel_id, new_monitor)
	}

	pub fn get_latest_mon_update_id(&self, channel_id: ChannelId) -> (u64, u64) {
		let monitor_id_state = self.latest_monitor_update_id.lock().unwrap();
		monitor_id_state.get(&channel_id).unwrap().clone()
	}
}
impl<'a> chain::Watch<TestChannelSigner> for TestChainMonitor<'a> {
	fn watch_channel(
		&self, channel_id: ChannelId, monitor: ChannelMonitor<TestChannelSigner>,
	) -> Result<chain::ChannelMonitorUpdateStatus, ()> {
		#[cfg(feature = "std")]
		if let Some(blocker) = &*self.write_blocker.lock().unwrap() {
			blocker.recv().unwrap();
		}

		// At every point where we get a monitor update, we should be able to send a useful monitor
		// to a watchtower and disk. At a minimum, this means we should be able to round-trip the
		// monitor to a serialized copy and get he same one back.
		let mut w = TestVecWriter(Vec::new());
		monitor.write(&mut w).unwrap();
		let new_monitor = <(BlockHash, ChannelMonitor<TestChannelSigner>)>::read(
			&mut io::Cursor::new(&w.0),
			(self.keys_manager, self.keys_manager),
		)
		.unwrap()
		.1;
		assert!(new_monitor == monitor);
		self.latest_monitor_update_id
			.lock()
			.unwrap()
			.insert(channel_id, (monitor.get_latest_update_id(), monitor.get_latest_update_id()));
		self.added_monitors.lock().unwrap().push((channel_id, monitor));
		self.chain_monitor.watch_channel(channel_id, new_monitor)
	}

	fn update_channel(
		&self, channel_id: ChannelId, update: &ChannelMonitorUpdate,
	) -> chain::ChannelMonitorUpdateStatus {
		#[cfg(feature = "std")]
		if let Some(blocker) = &*self.write_blocker.lock().unwrap() {
			blocker.recv().unwrap();
		}

		// Every monitor update should survive roundtrip
		let mut w = TestVecWriter(Vec::new());
		update.write(&mut w).unwrap();
		assert_eq!(ChannelMonitorUpdate::read(&mut &w.0[..]).unwrap(), *update);

		self.monitor_updates
			.lock()
			.unwrap()
			.entry(channel_id)
			.or_insert(Vec::new())
			.push(update.clone());

		if let Some(exp) = self.expect_channel_force_closed.lock().unwrap().take() {
			assert_eq!(channel_id, exp.0);
			assert_eq!(update.updates.len(), 1);
			let update = &update.updates[0];
			if let ChannelMonitorUpdateStep::ChannelForceClosed { should_broadcast } = update {
				assert_eq!(*should_broadcast, exp.1);
			} else {
				panic!();
			}
		}

		self.latest_monitor_update_id
			.lock()
			.unwrap()
			.insert(channel_id, (update.update_id, update.update_id));
		let update_res = self.chain_monitor.update_channel(channel_id, update);
		// At every point where we get a monitor update, we should be able to send a useful monitor
		// to a watchtower and disk...
		let monitor = self.chain_monitor.get_monitor(channel_id).unwrap();
		w.0.clear();
		monitor.write(&mut w).unwrap();
		let new_monitor = <(BlockHash, ChannelMonitor<TestChannelSigner>)>::read(
			&mut io::Cursor::new(&w.0),
			(self.keys_manager, self.keys_manager),
		)
		.unwrap()
		.1;
		if let Some(chan_id) = self.expect_monitor_round_trip_fail.lock().unwrap().take() {
			assert_eq!(chan_id, channel_id);
			assert!(new_monitor != *monitor);
		} else {
			assert!(new_monitor == *monitor);
		}
		self.added_monitors.lock().unwrap().push((channel_id, new_monitor));
		update_res
	}

	fn release_pending_monitor_events(
		&self,
	) -> Vec<(OutPoint, ChannelId, Vec<MonitorEvent>, PublicKey)> {
		return self.chain_monitor.release_pending_monitor_events();
	}
}

#[cfg(any(test, feature = "_externalize_tests"))]
struct JusticeTxData {
	justice_tx: Transaction,
	value: Amount,
	commitment_number: u64,
}

#[cfg(any(test, feature = "_externalize_tests"))]
pub(crate) struct WatchtowerPersister {
	persister: TestPersister,
	/// Upon a new commitment_signed, we'll get a
	/// ChannelMonitorUpdateStep::LatestCounterpartyCommitmentTxInfo. We'll store the justice tx
	/// amount, and commitment number so we can build the justice tx after our counterparty
	/// revokes it.
	unsigned_justice_tx_data: Mutex<HashMap<ChannelId, VecDeque<JusticeTxData>>>,
	/// After receiving a revoke_and_ack for a commitment number, we'll form and store the justice
	/// tx which would be used to provide a watchtower with the data it needs.
	watchtower_state: Mutex<HashMap<ChannelId, HashMap<Txid, Transaction>>>,
	destination_script: ScriptBuf,
}

#[cfg(any(test, feature = "_externalize_tests"))]
impl WatchtowerPersister {
	pub(crate) fn new(destination_script: ScriptBuf) -> Self {
		let unsigned_justice_tx_data = Mutex::new(new_hash_map());
		let watchtower_state = Mutex::new(new_hash_map());
		WatchtowerPersister {
			persister: TestPersister::new(),
			unsigned_justice_tx_data,
			watchtower_state,
			destination_script,
		}
	}

	pub(crate) fn justice_tx(
		&self, channel_id: ChannelId, commitment_txid: &Txid,
	) -> Option<Transaction> {
		self.watchtower_state
			.lock()
			.unwrap()
			.get(&channel_id)
			.unwrap()
			.get(commitment_txid)
			.cloned()
	}

	fn form_justice_data_from_commitment(
		&self, counterparty_commitment_tx: &CommitmentTransaction,
	) -> Option<JusticeTxData> {
		let trusted_tx = counterparty_commitment_tx.trust();
		let output_idx = trusted_tx.revokeable_output_index()?;
		let built_tx = trusted_tx.built_transaction();
		let value = built_tx.transaction.output[output_idx as usize].value;
		let justice_tx = trusted_tx
			.build_to_local_justice_tx(
				FEERATE_FLOOR_SATS_PER_KW as u64,
				self.destination_script.clone(),
			)
			.ok()?;
		let commitment_number = counterparty_commitment_tx.commitment_number();
		Some(JusticeTxData { justice_tx, value, commitment_number })
	}
}

#[cfg(any(test, feature = "_externalize_tests"))]
impl<Signer: sign::ecdsa::EcdsaChannelSigner> Persist<Signer> for WatchtowerPersister {
	fn persist_new_channel(
		&self, monitor_name: MonitorName, data: &ChannelMonitor<Signer>,
	) -> chain::ChannelMonitorUpdateStatus {
		let res = self.persister.persist_new_channel(monitor_name, data);

		assert!(self
			.unsigned_justice_tx_data
			.lock()
			.unwrap()
			.insert(data.channel_id(), VecDeque::new())
			.is_none());
		assert!(self
			.watchtower_state
			.lock()
			.unwrap()
			.insert(data.channel_id(), new_hash_map())
			.is_none());

		let initial_counterparty_commitment_tx =
			data.initial_counterparty_commitment_tx().expect("First and only call expects Some");
		if let Some(justice_data) =
			self.form_justice_data_from_commitment(&initial_counterparty_commitment_tx)
		{
			self.unsigned_justice_tx_data
				.lock()
				.unwrap()
				.get_mut(&data.channel_id())
				.unwrap()
				.push_back(justice_data);
		}
		res
	}

	fn update_persisted_channel(
		&self, monitor_name: MonitorName, update: Option<&ChannelMonitorUpdate>,
		data: &ChannelMonitor<Signer>,
	) -> chain::ChannelMonitorUpdateStatus {
		let res = self.persister.update_persisted_channel(monitor_name, update, data);

		if let Some(update) = update {
			let commitment_txs = data.counterparty_commitment_txs_from_update(update);
			let justice_datas = commitment_txs
				.into_iter()
				.filter_map(|commitment_tx| self.form_justice_data_from_commitment(&commitment_tx));
			let mut channels_justice_txs = self.unsigned_justice_tx_data.lock().unwrap();
			let channel_state = channels_justice_txs.get_mut(&data.channel_id()).unwrap();
			channel_state.extend(justice_datas);

			while let Some(JusticeTxData { justice_tx, value, commitment_number }) =
				channel_state.front()
			{
				let input_idx = 0;
				let commitment_txid = justice_tx.input[input_idx].previous_output.txid;
				match data.sign_to_local_justice_tx(
					justice_tx.clone(),
					input_idx,
					value.to_sat(),
					*commitment_number,
				) {
					Ok(signed_justice_tx) => {
						let dup = self
							.watchtower_state
							.lock()
							.unwrap()
							.get_mut(&data.channel_id())
							.unwrap()
							.insert(commitment_txid, signed_justice_tx);
						assert!(dup.is_none());
						channel_state.pop_front();
					},
					Err(_) => break,
				}
			}
		}
		res
	}

	fn archive_persisted_channel(&self, monitor_name: MonitorName) {
		<TestPersister as Persist<TestChannelSigner>>::archive_persisted_channel(
			&self.persister,
			monitor_name,
		);
	}
}

pub struct TestPersister {
	/// The queue of update statuses we'll return. If none are queued, ::Completed will always be
	/// returned.
	pub update_rets: Mutex<VecDeque<chain::ChannelMonitorUpdateStatus>>,
	/// When we get an update_persisted_channel call *with* a ChannelMonitorUpdate, we insert the
	/// [`ChannelMonitor::get_latest_update_id`] here.
	pub offchain_monitor_updates: Mutex<HashMap<MonitorName, HashSet<u64>>>,
	/// When we get an update_persisted_channel call with no ChannelMonitorUpdate, we insert the
	/// monitor's funding outpoint here.
	pub chain_sync_monitor_persistences: Mutex<VecDeque<MonitorName>>,
}
impl TestPersister {
	pub fn new() -> Self {
		let update_rets = Mutex::new(VecDeque::new());
		let offchain_monitor_updates = Mutex::new(new_hash_map());
		let chain_sync_monitor_persistences = Mutex::new(VecDeque::new());
		Self { update_rets, offchain_monitor_updates, chain_sync_monitor_persistences }
	}

	/// Queue an update status to return.
	pub fn set_update_ret(&self, next_ret: chain::ChannelMonitorUpdateStatus) {
		self.update_rets.lock().unwrap().push_back(next_ret);
	}
}
impl<Signer: sign::ecdsa::EcdsaChannelSigner> Persist<Signer> for TestPersister {
	fn persist_new_channel(
		&self, _monitor_name: MonitorName, _data: &ChannelMonitor<Signer>,
	) -> chain::ChannelMonitorUpdateStatus {
		if let Some(update_ret) = self.update_rets.lock().unwrap().pop_front() {
			return update_ret;
		}
		chain::ChannelMonitorUpdateStatus::Completed
	}

	fn update_persisted_channel(
		&self, monitor_name: MonitorName, update: Option<&ChannelMonitorUpdate>,
		_data: &ChannelMonitor<Signer>,
	) -> chain::ChannelMonitorUpdateStatus {
		let mut ret = chain::ChannelMonitorUpdateStatus::Completed;
		if let Some(update_ret) = self.update_rets.lock().unwrap().pop_front() {
			ret = update_ret;
		}

		if let Some(update) = update {
			self.offchain_monitor_updates
				.lock()
				.unwrap()
				.entry(monitor_name)
				.or_insert(new_hash_set())
				.insert(update.update_id);
		} else {
			self.chain_sync_monitor_persistences.lock().unwrap().push_back(monitor_name);
		}
		ret
	}

	fn archive_persisted_channel(&self, monitor_name: MonitorName) {
		// remove the channel from the offchain_monitor_updates and chain_sync_monitor_persistences.
		self.offchain_monitor_updates.lock().unwrap().remove(&monitor_name);
		self.chain_sync_monitor_persistences.lock().unwrap().retain(|x| x != &monitor_name);
	}
}

// A simple multi-producer-single-consumer one-shot channel
type OneShotChannelState = Arc<Mutex<(Option<Result<(), io::Error>>, Option<Waker>)>>;
struct OneShotChannel(OneShotChannelState);
impl Future for OneShotChannel {
	type Output = Result<(), io::Error>;
	fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
		let mut state = self.0.lock().unwrap();
		// If the future is complete, take() the result and return it,
		state.0.take().map(|res| Poll::Ready(res)).unwrap_or_else(|| {
			// otherwise, store the waker so that the future will be poll()ed again when the result
			// is ready.
			state.1 = Some(cx.waker().clone());
			Poll::Pending
		})
	}
}

/// An in-memory KVStore for testing.
///
/// Sync writes always complete immediately while async writes always block until manually
/// completed with [`Self::complete_async_writes_through`] or [`Self::complete_all_async_writes`].
///
/// Removes always complete immediately.
pub struct TestStore {
	pending_async_writes: Mutex<HashMap<String, Vec<(usize, OneShotChannelState, Vec<u8>)>>>,
	persisted_bytes: Mutex<HashMap<String, HashMap<String, Vec<u8>>>>,
	read_only: bool,
}

impl TestStore {
	pub fn new(read_only: bool) -> Self {
		let pending_async_writes = Mutex::new(new_hash_map());
		let persisted_bytes = Mutex::new(new_hash_map());
		Self { pending_async_writes, persisted_bytes, read_only }
	}

	pub fn list_pending_async_writes(
		&self, primary_namespace: &str, secondary_namespace: &str, key: &str,
	) -> Vec<usize> {
		let key = format!("{primary_namespace}/{secondary_namespace}/{key}");
		let writes_lock = self.pending_async_writes.lock().unwrap();
		writes_lock
			.get(&key)
			.map(|v| v.iter().map(|(id, _, _)| *id).collect())
			.unwrap_or(Vec::new())
	}

	/// Completes all pending async writes for the given namespace and key, up to and through the
	/// given `write_id` (which can be fetched from [`Self::list_pending_async_writes`]).
	pub fn complete_async_writes_through(
		&self, primary_namespace: &str, secondary_namespace: &str, key: &str, write_id: usize,
	) {
		let prefix = format!("{primary_namespace}/{secondary_namespace}");
		let key = format!("{primary_namespace}/{secondary_namespace}/{key}");

		let mut persisted_lock = self.persisted_bytes.lock().unwrap();
		let mut writes_lock = self.pending_async_writes.lock().unwrap();

		let pending_writes = writes_lock.get_mut(&key).expect("No pending writes for given key");
		pending_writes.retain(|(id, res, data)| {
			if *id <= write_id {
				let namespace = persisted_lock.entry(prefix.clone()).or_insert(new_hash_map());
				*namespace.entry(key.to_string()).or_default() = data.clone();
				let mut future_state = res.lock().unwrap();
				future_state.0 = Some(Ok(()));
				if let Some(waker) = future_state.1.take() {
					waker.wake();
				}
				false
			} else {
				true
			}
		});
	}

	/// Completes all pending async writes on all namespaces and keys.
	pub fn complete_all_async_writes(&self) {
		let pending_writes: Vec<String> =
			self.pending_async_writes.lock().unwrap().keys().cloned().collect();
		for key in pending_writes {
			let mut levels = key.split("/");
			let primary = levels.next().unwrap();
			let secondary = levels.next().unwrap();
			let key = levels.next().unwrap();
			assert!(levels.next().is_none());
			self.complete_async_writes_through(primary, secondary, key, usize::MAX);
		}
	}

	fn read_internal(
		&self, primary_namespace: &str, secondary_namespace: &str, key: &str,
	) -> io::Result<Vec<u8>> {
		let persisted_lock = self.persisted_bytes.lock().unwrap();
		let prefixed = format!("{primary_namespace}/{secondary_namespace}");

		if let Some(outer_ref) = persisted_lock.get(&prefixed) {
			if let Some(inner_ref) = outer_ref.get(key) {
				let bytes = inner_ref.clone();
				Ok(bytes)
			} else {
				Err(io::Error::new(io::ErrorKind::NotFound, "Key not found"))
			}
		} else {
			Err(io::Error::new(io::ErrorKind::NotFound, "Namespace not found"))
		}
	}

	fn remove_internal(
		&self, primary_namespace: &str, secondary_namespace: &str, key: &str, _lazy: bool,
	) -> io::Result<()> {
		if self.read_only {
			return Err(io::Error::new(
				io::ErrorKind::PermissionDenied,
				"Cannot modify read-only store",
			));
		}

		let mut persisted_lock = self.persisted_bytes.lock().unwrap();
		let mut async_writes_lock = self.pending_async_writes.lock().unwrap();

		let prefixed = format!("{primary_namespace}/{secondary_namespace}");
		if let Some(outer_ref) = persisted_lock.get_mut(&prefixed) {
			outer_ref.remove(&key.to_string());
		}

		if let Some(pending_writes) = async_writes_lock.remove(&format!("{prefixed}/{key}")) {
			for (_, future, _) in pending_writes {
				let mut future_lock = future.lock().unwrap();
				future_lock.0 = Some(Ok(()));
				if let Some(waker) = future_lock.1.take() {
					waker.wake();
				}
			}
		}

		Ok(())
	}

	fn list_internal(
		&self, primary_namespace: &str, secondary_namespace: &str,
	) -> io::Result<Vec<String>> {
		let mut persisted_lock = self.persisted_bytes.lock().unwrap();

		let prefixed = format!("{primary_namespace}/{secondary_namespace}");
		match persisted_lock.entry(prefixed) {
			hash_map::Entry::Occupied(e) => Ok(e.get().keys().cloned().collect()),
			hash_map::Entry::Vacant(_) => Ok(Vec::new()),
		}
	}
}

impl KVStore for TestStore {
	fn read(
		&self, primary_namespace: &str, secondary_namespace: &str, key: &str,
	) -> impl Future<Output = Result<Vec<u8>, io::Error>> + 'static + MaybeSend {
		let res = self.read_internal(&primary_namespace, &secondary_namespace, &key);
		async move { res }
	}
	fn write(
		&self, primary_namespace: &str, secondary_namespace: &str, key: &str, buf: Vec<u8>,
	) -> impl Future<Output = Result<(), io::Error>> + 'static + MaybeSend {
		let path = format!("{primary_namespace}/{secondary_namespace}/{key}");
		let future = Arc::new(Mutex::new((None, None)));

		let mut async_writes_lock = self.pending_async_writes.lock().unwrap();
		let pending_writes = async_writes_lock.entry(path).or_insert(Vec::new());
		let new_id = pending_writes.last().map(|(id, _, _)| id + 1).unwrap_or(0);
		pending_writes.push((new_id, Arc::clone(&future), buf));

		OneShotChannel(future)
	}
	fn remove(
		&self, primary_namespace: &str, secondary_namespace: &str, key: &str, lazy: bool,
	) -> impl Future<Output = Result<(), io::Error>> + 'static + MaybeSend {
		let res = self.remove_internal(&primary_namespace, &secondary_namespace, &key, lazy);
		async move { res }
	}
	fn list(
		&self, primary_namespace: &str, secondary_namespace: &str,
	) -> impl Future<Output = Result<Vec<String>, io::Error>> + 'static + MaybeSend {
		let res = self.list_internal(primary_namespace, secondary_namespace);
		async move { res }
	}
}

impl KVStoreSync for TestStore {
	fn read(
		&self, primary_namespace: &str, secondary_namespace: &str, key: &str,
	) -> io::Result<Vec<u8>> {
		self.read_internal(primary_namespace, secondary_namespace, key)
	}

	fn write(
		&self, primary_namespace: &str, secondary_namespace: &str, key: &str, buf: Vec<u8>,
	) -> io::Result<()> {
		if self.read_only {
			return Err(io::Error::new(
				io::ErrorKind::PermissionDenied,
				"Cannot modify read-only store",
			));
		}
		let mut persisted_lock = self.persisted_bytes.lock().unwrap();
		let mut async_writes_lock = self.pending_async_writes.lock().unwrap();

		let prefixed = format!("{primary_namespace}/{secondary_namespace}");
		let async_writes_pending = async_writes_lock.remove(&format!("{prefixed}/{key}"));
		let outer_e = persisted_lock.entry(prefixed).or_insert(new_hash_map());
		outer_e.insert(key.to_string(), buf);

		if let Some(pending_writes) = async_writes_pending {
			for (_, future, _) in pending_writes {
				let mut future_lock = future.lock().unwrap();
				future_lock.0 = Some(Ok(()));
				if let Some(waker) = future_lock.1.take() {
					waker.wake();
				}
			}
		}
		Ok(())
	}

	fn remove(
		&self, primary_namespace: &str, secondary_namespace: &str, key: &str, lazy: bool,
	) -> io::Result<()> {
		self.remove_internal(primary_namespace, secondary_namespace, key, lazy)
	}

	fn list(&self, primary_namespace: &str, secondary_namespace: &str) -> io::Result<Vec<String>> {
		self.list_internal(primary_namespace, secondary_namespace)
	}
}

unsafe impl Sync for TestStore {}
unsafe impl Send for TestStore {}

pub struct TestBroadcaster {
	pub txn_broadcasted: Mutex<Vec<Transaction>>,
	pub txn_types: Mutex<Vec<TransactionType>>,
	pub blocks: Arc<Mutex<Vec<(Block, u32)>>>,
}

impl TestBroadcaster {
	pub fn new(network: Network) -> Self {
		let txn_broadcasted = Mutex::new(Vec::new());
		let txn_types = Mutex::new(Vec::new());
		let blocks = Arc::new(Mutex::new(vec![(genesis_block(network), 0)]));
		Self { txn_broadcasted, txn_types, blocks }
	}

	pub fn with_blocks(blocks: Arc<Mutex<Vec<(Block, u32)>>>) -> Self {
		let txn_broadcasted = Mutex::new(Vec::new());
		let txn_types = Mutex::new(Vec::new());
		Self { txn_broadcasted, txn_types, blocks }
	}

	pub fn txn_broadcast(&self) -> Vec<Transaction> {
		self.txn_types.lock().unwrap().clear();
		self.txn_broadcasted.lock().unwrap().split_off(0)
	}

	pub fn unique_txn_broadcast(&self) -> Vec<Transaction> {
		let mut txn = self.txn_broadcasted.lock().unwrap().split_off(0);
		self.txn_types.lock().unwrap().clear();
		let mut seen = new_hash_set();
		txn.retain(|tx| seen.insert(tx.compute_txid()));
		txn
	}

	/// Returns all broadcast transactions with their types, clearing both internal lists.
	pub fn txn_broadcast_with_types(&self) -> Vec<(Transaction, TransactionType)> {
		let txn = self.txn_broadcasted.lock().unwrap().split_off(0);
		let types = self.txn_types.lock().unwrap().split_off(0);
		assert_eq!(txn.len(), types.len(), "Transaction and type vectors out of sync");
		txn.into_iter().zip(types.into_iter()).collect()
	}

	/// Clears both the transaction and type vectors.
	pub fn clear(&self) {
		self.txn_broadcasted.lock().unwrap().clear();
		self.txn_types.lock().unwrap().clear();
	}
}

impl chaininterface::BroadcasterInterface for TestBroadcaster {
	fn broadcast_transactions(&self, txs: &[(&Transaction, TransactionType)]) {
		// Assert that any batch of transactions of length greater than 1 is sorted
		// topologically, and is a `child-with-parents` package as defined in
		// <https://github.com/bitcoin/bitcoin/blob/master/doc/policy/packages.md>.
		//
		// Implementations MUST NOT rely on this, and must re-sort the transactions
		// themselves.
		//
		// Right now LDK only ever broadcasts packages of length 2.
		assert!(txs.len() <= 2);
		if txs.len() == 2 {
			let parent_txid = txs[0].0.compute_txid();
			assert!(txs[1]
				.0
				.input
				.iter()
				.map(|input| input.previous_output.txid)
				.any(|txid| txid == parent_txid));
			let child_txid = txs[1].0.compute_txid();
			assert!(txs[0]
				.0
				.input
				.iter()
				.map(|input| input.previous_output.txid)
				.all(|txid| txid != child_txid));
		}

		for (tx, _broadcast_type) in txs {
			let lock_time = tx.lock_time.to_consensus_u32();
			assert!(lock_time < 1_500_000_000);
			if tx.lock_time.is_block_height()
				&& lock_time > self.blocks.lock().unwrap().last().unwrap().1
			{
				for inp in tx.input.iter() {
					if inp.sequence != Sequence::MAX {
						panic!(
							"We should never broadcast a transaction before its locktime ({})!",
							tx.lock_time
						);
					}
				}
			}
		}
		let owned_txs: Vec<Transaction> = txs.iter().map(|(tx, _)| (*tx).clone()).collect();
		let owned_types: Vec<TransactionType> =
			txs.iter().map(|(_, tx_type)| tx_type.clone()).collect();
		self.txn_broadcasted.lock().unwrap().extend(owned_txs);
		self.txn_types.lock().unwrap().extend(owned_types);
	}
}

pub struct ConnectionTracker {
	pub had_peers: AtomicBool,
	pub connected_peers: Mutex<Vec<PublicKey>>,
	pub fail_connections: AtomicBool,
}

impl ConnectionTracker {
	pub fn new() -> Self {
		Self {
			had_peers: AtomicBool::new(false),
			connected_peers: Mutex::new(Vec::new()),
			fail_connections: AtomicBool::new(false),
		}
	}

	pub fn peer_connected(&self, their_node_id: PublicKey) -> Result<(), ()> {
		self.had_peers.store(true, Ordering::Release);
		let mut connected_peers = self.connected_peers.lock().unwrap();
		assert!(!connected_peers.contains(&their_node_id));
		if self.fail_connections.load(Ordering::Acquire) {
			Err(())
		} else {
			connected_peers.push(their_node_id);
			Ok(())
		}
	}

	pub fn peer_disconnected(&self, their_node_id: PublicKey) {
		assert!(self.had_peers.load(Ordering::Acquire));
		let mut connected_peers = self.connected_peers.lock().unwrap();
		assert!(connected_peers.contains(&their_node_id));
		connected_peers.retain(|id| *id != their_node_id);
	}
}

pub struct TestChannelMessageHandler {
	pub pending_events: Mutex<Vec<MessageSendEvent>>,
	expected_recv_msgs: Mutex<Option<Vec<wire::Message<()>>>>,
	pub conn_tracker: ConnectionTracker,
	chain_hash: ChainHash,
}

impl TestChannelMessageHandler {
	thread_local! {
		pub static MESSAGE_FETCH_COUNTER: AtomicUsize = const { AtomicUsize::new(0) };
	}
}

impl TestChannelMessageHandler {
	pub fn new(chain_hash: ChainHash) -> Self {
		TestChannelMessageHandler {
			pending_events: Mutex::new(Vec::new()),
			expected_recv_msgs: Mutex::new(None),
			conn_tracker: ConnectionTracker::new(),
			chain_hash,
		}
	}

	#[cfg(test)]
	pub(crate) fn expect_receive_msg(&self, ev: wire::Message<()>) {
		let mut expected_msgs = self.expected_recv_msgs.lock().unwrap();
		if expected_msgs.is_none() {
			*expected_msgs = Some(Vec::new());
		}
		expected_msgs.as_mut().unwrap().push(ev);
	}

	fn received_msg(&self, _ev: wire::Message<()>) {
		let mut msgs = self.expected_recv_msgs.lock().unwrap();
		if msgs.is_none() {
			return;
		}
		assert!(
			!msgs.as_ref().unwrap().is_empty(),
			"Received message when we weren't expecting one"
		);
		#[cfg(any(test, feature = "_test_utils"))]
		assert_eq!(msgs.as_ref().unwrap()[0], _ev);
		msgs.as_mut().unwrap().remove(0);
	}
}

impl Drop for TestChannelMessageHandler {
	fn drop(&mut self) {
		let l = self.expected_recv_msgs.lock().unwrap();
		if !std::thread::panicking() {
			assert!(l.is_none() || l.as_ref().unwrap().is_empty());
		}
	}
}

impl msgs::ChannelMessageHandler for TestChannelMessageHandler {
	fn handle_open_channel(&self, _their_node_id: PublicKey, msg: &msgs::OpenChannel) {
		self.received_msg(wire::Message::OpenChannel(msg.clone()));
	}
	fn handle_accept_channel(&self, _their_node_id: PublicKey, msg: &msgs::AcceptChannel) {
		self.received_msg(wire::Message::AcceptChannel(msg.clone()));
	}
	fn handle_funding_created(&self, _their_node_id: PublicKey, msg: &msgs::FundingCreated) {
		self.received_msg(wire::Message::FundingCreated(msg.clone()));
	}
	fn handle_funding_signed(&self, _their_node_id: PublicKey, msg: &msgs::FundingSigned) {
		self.received_msg(wire::Message::FundingSigned(msg.clone()));
	}
	fn handle_channel_ready(&self, _their_node_id: PublicKey, msg: &msgs::ChannelReady) {
		self.received_msg(wire::Message::ChannelReady(msg.clone()));
	}
	fn handle_shutdown(&self, _their_node_id: PublicKey, msg: &msgs::Shutdown) {
		self.received_msg(wire::Message::Shutdown(msg.clone()));
	}
	fn handle_closing_signed(&self, _their_node_id: PublicKey, msg: &msgs::ClosingSigned) {
		self.received_msg(wire::Message::ClosingSigned(msg.clone()));
	}
	#[cfg(simple_close)]
	fn handle_closing_complete(&self, _their_node_id: PublicKey, msg: msgs::ClosingComplete) {
		self.received_msg(wire::Message::ClosingComplete(msg));
	}
	#[cfg(simple_close)]
	fn handle_closing_sig(&self, _their_node_id: PublicKey, msg: msgs::ClosingSig) {
		self.received_msg(wire::Message::ClosingSig(msg));
	}
	fn handle_stfu(&self, _their_node_id: PublicKey, msg: &msgs::Stfu) {
		self.received_msg(wire::Message::Stfu(msg.clone()));
	}
	fn handle_splice_init(&self, _their_node_id: PublicKey, msg: &msgs::SpliceInit) {
		self.received_msg(wire::Message::SpliceInit(msg.clone()));
	}
	fn handle_splice_ack(&self, _their_node_id: PublicKey, msg: &msgs::SpliceAck) {
		self.received_msg(wire::Message::SpliceAck(msg.clone()));
	}
	fn handle_splice_locked(&self, _their_node_id: PublicKey, msg: &msgs::SpliceLocked) {
		self.received_msg(wire::Message::SpliceLocked(msg.clone()));
	}
	fn handle_update_add_htlc(&self, _their_node_id: PublicKey, msg: &msgs::UpdateAddHTLC) {
		self.received_msg(wire::Message::UpdateAddHTLC(msg.clone()));
	}
	fn handle_update_fulfill_htlc(&self, _their_node_id: PublicKey, msg: msgs::UpdateFulfillHTLC) {
		self.received_msg(wire::Message::UpdateFulfillHTLC(msg));
	}
	fn handle_update_fail_htlc(&self, _their_node_id: PublicKey, msg: &msgs::UpdateFailHTLC) {
		self.received_msg(wire::Message::UpdateFailHTLC(msg.clone()));
	}
	fn handle_update_fail_malformed_htlc(
		&self, _their_node_id: PublicKey, msg: &msgs::UpdateFailMalformedHTLC,
	) {
		self.received_msg(wire::Message::UpdateFailMalformedHTLC(msg.clone()));
	}
	fn handle_commitment_signed(&self, _their_node_id: PublicKey, msg: &msgs::CommitmentSigned) {
		self.received_msg(wire::Message::CommitmentSigned(msg.clone()));
	}
	fn handle_commitment_signed_batch(
		&self, _their_node_id: PublicKey, _channel_id: ChannelId,
		_batch: Vec<msgs::CommitmentSigned>,
	) {
		unreachable!()
	}
	fn handle_revoke_and_ack(&self, _their_node_id: PublicKey, msg: &msgs::RevokeAndACK) {
		self.received_msg(wire::Message::RevokeAndACK(msg.clone()));
	}
	fn handle_update_fee(&self, _their_node_id: PublicKey, msg: &msgs::UpdateFee) {
		self.received_msg(wire::Message::UpdateFee(msg.clone()));
	}
	fn handle_channel_update(&self, _their_node_id: PublicKey, _msg: &msgs::ChannelUpdate) {
		// Don't call `received_msg` here as `TestRoutingMessageHandler` generates these sometimes
	}
	fn handle_announcement_signatures(
		&self, _their_node_id: PublicKey, msg: &msgs::AnnouncementSignatures,
	) {
		self.received_msg(wire::Message::AnnouncementSignatures(msg.clone()));
	}
	fn handle_channel_reestablish(
		&self, _their_node_id: PublicKey, msg: &msgs::ChannelReestablish,
	) {
		self.received_msg(wire::Message::ChannelReestablish(msg.clone()));
	}
	fn handle_error(&self, _their_node_id: PublicKey, msg: &msgs::ErrorMessage) {
		self.received_msg(wire::Message::Error(msg.clone()));
	}

	fn get_chain_hashes(&self) -> Option<Vec<ChainHash>> {
		Some(vec![self.chain_hash])
	}

	fn handle_open_channel_v2(&self, _their_node_id: PublicKey, msg: &msgs::OpenChannelV2) {
		self.received_msg(wire::Message::OpenChannelV2(msg.clone()));
	}

	fn handle_accept_channel_v2(&self, _their_node_id: PublicKey, msg: &msgs::AcceptChannelV2) {
		self.received_msg(wire::Message::AcceptChannelV2(msg.clone()));
	}

	fn handle_tx_add_input(&self, _their_node_id: PublicKey, msg: &msgs::TxAddInput) {
		self.received_msg(wire::Message::TxAddInput(msg.clone()));
	}

	fn handle_tx_add_output(&self, _their_node_id: PublicKey, msg: &msgs::TxAddOutput) {
		self.received_msg(wire::Message::TxAddOutput(msg.clone()));
	}

	fn handle_tx_remove_input(&self, _their_node_id: PublicKey, msg: &msgs::TxRemoveInput) {
		self.received_msg(wire::Message::TxRemoveInput(msg.clone()));
	}

	fn handle_tx_remove_output(&self, _their_node_id: PublicKey, msg: &msgs::TxRemoveOutput) {
		self.received_msg(wire::Message::TxRemoveOutput(msg.clone()));
	}

	fn handle_tx_complete(&self, _their_node_id: PublicKey, msg: &msgs::TxComplete) {
		self.received_msg(wire::Message::TxComplete(msg.clone()));
	}

	fn handle_tx_signatures(&self, _their_node_id: PublicKey, msg: &msgs::TxSignatures) {
		self.received_msg(wire::Message::TxSignatures(msg.clone()));
	}

	fn handle_tx_init_rbf(&self, _their_node_id: PublicKey, msg: &msgs::TxInitRbf) {
		self.received_msg(wire::Message::TxInitRbf(msg.clone()));
	}

	fn handle_tx_ack_rbf(&self, _their_node_id: PublicKey, msg: &msgs::TxAckRbf) {
		self.received_msg(wire::Message::TxAckRbf(msg.clone()));
	}

	fn handle_tx_abort(&self, _their_node_id: PublicKey, msg: &msgs::TxAbort) {
		self.received_msg(wire::Message::TxAbort(msg.clone()));
	}

	fn handle_peer_storage(&self, _their_node_id: PublicKey, msg: msgs::PeerStorage) {
		self.received_msg(wire::Message::PeerStorage(msg));
	}

	fn handle_peer_storage_retrieval(
		&self, _their_node_id: PublicKey, msg: msgs::PeerStorageRetrieval,
	) {
		self.received_msg(wire::Message::PeerStorageRetrieval(msg));
	}

	fn message_received(&self) {}
}

impl msgs::BaseMessageHandler for TestChannelMessageHandler {
	fn peer_disconnected(&self, their_node_id: PublicKey) {
		self.conn_tracker.peer_disconnected(their_node_id)
	}
	fn peer_connected(
		&self, their_node_id: PublicKey, _msg: &msgs::Init, _inbound: bool,
	) -> Result<(), ()> {
		// Don't bother with `received_msg` for Init as its auto-generated and we don't want to
		// bother re-generating the expected Init message in all tests.
		self.conn_tracker.peer_connected(their_node_id)
	}
	fn provided_node_features(&self) -> NodeFeatures {
		channelmanager::provided_node_features(&UserConfig::default())
	}
	fn provided_init_features(&self, _their_init_features: PublicKey) -> InitFeatures {
		channelmanager::provided_init_features(&UserConfig::default())
	}
	fn get_and_clear_pending_msg_events(&self) -> Vec<MessageSendEvent> {
		Self::MESSAGE_FETCH_COUNTER.with(|val| val.fetch_add(1, Ordering::AcqRel));
		let mut pending_events = self.pending_events.lock().unwrap();
		let mut ret = Vec::new();
		mem::swap(&mut ret, &mut *pending_events);
		ret
	}
}

fn get_dummy_channel_announcement(short_chan_id: u64) -> msgs::ChannelAnnouncement {
	use bitcoin::secp256k1::ffi::Signature as FFISignature;
	let secp_ctx = Secp256k1::new();
	let network = Network::Testnet;
	let node_1_privkey = SecretKey::from_slice(&[42; 32]).unwrap();
	let node_2_privkey = SecretKey::from_slice(&[41; 32]).unwrap();
	let node_1_btckey = SecretKey::from_slice(&[40; 32]).unwrap();
	let node_2_btckey = SecretKey::from_slice(&[39; 32]).unwrap();
	let unsigned_ann = msgs::UnsignedChannelAnnouncement {
		features: ChannelFeatures::empty(),
		chain_hash: ChainHash::using_genesis_block(network),
		short_channel_id: short_chan_id,
		node_id_1: NodeId::from_pubkey(&PublicKey::from_secret_key(&secp_ctx, &node_1_privkey)),
		node_id_2: NodeId::from_pubkey(&PublicKey::from_secret_key(&secp_ctx, &node_2_privkey)),
		bitcoin_key_1: NodeId::from_pubkey(&PublicKey::from_secret_key(&secp_ctx, &node_1_btckey)),
		bitcoin_key_2: NodeId::from_pubkey(&PublicKey::from_secret_key(&secp_ctx, &node_2_btckey)),
		excess_data: Vec::new(),
	};

	unsafe {
		msgs::ChannelAnnouncement {
			node_signature_1: Signature::from(FFISignature::new()),
			node_signature_2: Signature::from(FFISignature::new()),
			bitcoin_signature_1: Signature::from(FFISignature::new()),
			bitcoin_signature_2: Signature::from(FFISignature::new()),
			contents: unsigned_ann,
		}
	}
}

pub fn get_dummy_channel_update(short_chan_id: u64) -> msgs::ChannelUpdate {
	use bitcoin::secp256k1::ffi::Signature as FFISignature;
	let network = Network::Testnet;
	msgs::ChannelUpdate {
		signature: Signature::from(unsafe { FFISignature::new() }),
		contents: msgs::UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(network),
			short_channel_id: short_chan_id,
			timestamp: 0,
			message_flags: 1, // Only must_be_one
			channel_flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: msgs::MAX_VALUE_MSAT,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: vec![],
		},
	}
}

pub struct TestRoutingMessageHandler {
	pub chan_upds_recvd: AtomicUsize,
	pub chan_anns_recvd: AtomicUsize,
	pub pending_events: Mutex<Vec<MessageSendEvent>>,
	pub request_full_sync: AtomicBool,
	pub announcement_available_for_sync: AtomicBool,
	pub conn_tracker: ConnectionTracker,
}

impl TestRoutingMessageHandler {
	pub fn new() -> Self {
		let pending_events = Mutex::new(vec![]);
		TestRoutingMessageHandler {
			chan_upds_recvd: AtomicUsize::new(0),
			chan_anns_recvd: AtomicUsize::new(0),
			pending_events,
			request_full_sync: AtomicBool::new(false),
			announcement_available_for_sync: AtomicBool::new(false),
			conn_tracker: ConnectionTracker::new(),
		}
	}
}
impl msgs::RoutingMessageHandler for TestRoutingMessageHandler {
	fn handle_node_announcement(
		&self, _their_node_id: Option<PublicKey>, _msg: &msgs::NodeAnnouncement,
	) -> Result<bool, msgs::LightningError> {
		Ok(true)
	}
	fn handle_channel_announcement(
		&self, _their_node_id: Option<PublicKey>, _msg: &msgs::ChannelAnnouncement,
	) -> Result<bool, msgs::LightningError> {
		self.chan_anns_recvd.fetch_add(1, Ordering::AcqRel);
		Ok(true)
	}
	fn handle_channel_update(
		&self, _their_node_id: Option<PublicKey>, _msg: &msgs::ChannelUpdate,
	) -> Result<Option<(NodeId, NodeId)>, msgs::LightningError> {
		self.chan_upds_recvd.fetch_add(1, Ordering::AcqRel);
		Ok(Some((NodeId::from_slice(&[2; 33]).unwrap(), NodeId::from_slice(&[3; 33]).unwrap())))
	}
	fn get_next_channel_announcement(
		&self, starting_point: u64,
	) -> Option<(msgs::ChannelAnnouncement, Option<msgs::ChannelUpdate>, Option<msgs::ChannelUpdate>)>
	{
		if self.announcement_available_for_sync.load(Ordering::Acquire) {
			let chan_upd_1 = get_dummy_channel_update(starting_point);
			let chan_upd_2 = get_dummy_channel_update(starting_point);
			let chan_ann = get_dummy_channel_announcement(starting_point);

			Some((chan_ann, Some(chan_upd_1), Some(chan_upd_2)))
		} else {
			None
		}
	}

	fn get_next_node_announcement(
		&self, _starting_point: Option<&NodeId>,
	) -> Option<msgs::NodeAnnouncement> {
		None
	}

	fn handle_reply_channel_range(
		&self, _their_node_id: PublicKey, _msg: msgs::ReplyChannelRange,
	) -> Result<(), msgs::LightningError> {
		Ok(())
	}

	fn handle_reply_short_channel_ids_end(
		&self, _their_node_id: PublicKey, _msg: msgs::ReplyShortChannelIdsEnd,
	) -> Result<(), msgs::LightningError> {
		Ok(())
	}

	fn handle_query_channel_range(
		&self, _their_node_id: PublicKey, _msg: msgs::QueryChannelRange,
	) -> Result<(), msgs::LightningError> {
		Ok(())
	}

	fn handle_query_short_channel_ids(
		&self, _their_node_id: PublicKey, _msg: msgs::QueryShortChannelIds,
	) -> Result<(), msgs::LightningError> {
		Ok(())
	}

	fn processing_queue_high(&self) -> bool {
		false
	}
}

impl BaseMessageHandler for TestRoutingMessageHandler {
	fn peer_connected(
		&self, their_node_id: PublicKey, init_msg: &msgs::Init, _inbound: bool,
	) -> Result<(), ()> {
		if !init_msg.features.supports_gossip_queries() {
			return Ok(());
		}

		#[allow(unused_mut, unused_assignments)]
		let mut gossip_start_time = 0;
		#[cfg(feature = "std")]
		{
			use std::time::{SystemTime, UNIX_EPOCH};
			gossip_start_time = SystemTime::now()
				.duration_since(UNIX_EPOCH)
				.expect("Time must be > 1970")
				.as_secs();
			if self.request_full_sync.load(Ordering::Acquire) {
				gossip_start_time -= 60 * 60 * 24 * 7 * 2; // 2 weeks ago
			} else {
				gossip_start_time -= 60 * 60; // an hour ago
			}
		}

		let mut pending_events = self.pending_events.lock().unwrap();
		pending_events.push(MessageSendEvent::SendGossipTimestampFilter {
			node_id: their_node_id.clone(),
			msg: msgs::GossipTimestampFilter {
				chain_hash: ChainHash::using_genesis_block(Network::Testnet),
				first_timestamp: gossip_start_time as u32,
				timestamp_range: u32::max_value(),
			},
		});

		self.conn_tracker.peer_connected(their_node_id)
	}

	fn peer_disconnected(&self, their_node_id: PublicKey) {
		self.conn_tracker.peer_disconnected(their_node_id);
	}

	fn provided_node_features(&self) -> NodeFeatures {
		let mut features = NodeFeatures::empty();
		features.set_gossip_queries_optional();
		features
	}

	fn provided_init_features(&self, _their_init_features: PublicKey) -> InitFeatures {
		let mut features = InitFeatures::empty();
		features.set_gossip_queries_optional();
		features
	}

	fn get_and_clear_pending_msg_events(&self) -> Vec<MessageSendEvent> {
		let mut ret = Vec::new();
		let mut pending_events = self.pending_events.lock().unwrap();
		core::mem::swap(&mut ret, &mut pending_events);
		ret
	}
}

pub struct TestLogger {
	pub(crate) id: String,
	pub lines: Mutex<HashMap<(&'static str, String), usize>>,
	pub context: Mutex<HashMap<(&'static str, Option<PublicKey>, Option<ChannelId>), usize>>,
}

impl TestLogger {
	pub fn new() -> TestLogger {
		Self::with_id("".to_owned())
	}
	pub fn with_id(id: String) -> TestLogger {
		let lines = Mutex::new(new_hash_map());
		let context = Mutex::new(new_hash_map());
		TestLogger { id, lines, context }
	}
	pub fn assert_log(&self, module: &str, line: String, count: usize) {
		let log_entries = self.lines.lock().unwrap();
		assert_eq!(log_entries.get(&(module, line)), Some(&count));
	}

	/// Search for the number of occurrence of the logged lines which
	/// 1. belongs to the specified module and
	/// 2. contains `line` in it.
	/// And asserts if the number of occurrences is the same with the given `count`
	pub fn assert_log_contains(&self, module: &str, line: &str, count: usize) {
		let log_entries = self.lines.lock().unwrap();
		let l: usize = log_entries
			.iter()
			.filter(|&(&(ref m, ref l), _c)| *m == module && l.contains(line))
			.map(|(_, c)| c)
			.sum();
		assert_eq!(l, count)
	}

	/// Search for the number of occurrences of logged lines which
	/// 1. belong to the specified module and
	/// 2. match the given regex pattern.
	/// Assert that the number of occurrences equals the given `count`
	#[cfg(any(test, feature = "_test_utils"))]
	pub fn assert_log_regex(&self, module: &str, pattern: regex::Regex, count: usize) {
		let log_entries = self.lines.lock().unwrap();
		let l: usize = log_entries
			.iter()
			.filter(|&(&(ref m, ref l), _c)| *m == module && pattern.is_match(&l))
			.map(|(_, c)| c)
			.sum();
		assert_eq!(l, count)
	}

	pub fn assert_log_context_contains(
		&self, module: &str, peer_id: Option<PublicKey>, channel_id: Option<ChannelId>,
		count: usize,
	) {
		let context_entries = self.context.lock().unwrap();
		let l = context_entries.get(&(module, peer_id, channel_id)).unwrap();
		assert_eq!(*l, count)
	}
}

impl Logger for TestLogger {
	fn log(&self, record: Record) {
		let s = format!("{:<6} {}", self.id, record);
		#[cfg(ldk_bench)]
		{
			// When benchmarking, we don't actually want to print logs, but we do want to format
			// them. To make sure LLVM doesn't skip the above entirely we push it through a
			// volitile read. This may not be super fast, but it shouldn't be worse than anything a
			// user actually does with a log
			let s_bytes = s.as_bytes();
			for i in 0..s.len() {
				let _ = unsafe { core::ptr::read_volatile(&s_bytes[i]) };
			}
		}
		#[cfg(not(ldk_bench))]
		{
			*self
				.lines
				.lock()
				.unwrap()
				.entry((record.module_path, format!("{}", record.args)))
				.or_insert(0) += 1;
			*self
				.context
				.lock()
				.unwrap()
				.entry((record.module_path, record.peer_id, record.channel_id))
				.or_insert(0) += 1;
			println!("{}", s);
		}
	}
}

pub struct TestNodeSigner {
	node_secret: SecretKey,
}

impl TestNodeSigner {
	pub fn new(node_secret: SecretKey) -> Self {
		Self { node_secret }
	}
}

impl NodeSigner for TestNodeSigner {
	fn get_expanded_key(&self) -> ExpandedKey {
		ExpandedKey::new([42; 32])
	}

	fn get_peer_storage_key(&self) -> PeerStorageKey {
		unreachable!()
	}

	fn get_receive_auth_key(&self) -> ReceiveAuthKey {
		ReceiveAuthKey(self.node_secret.secret_bytes())
	}

	fn get_node_id(&self, recipient: Recipient) -> Result<PublicKey, ()> {
		let node_secret = match recipient {
			Recipient::Node => Ok(&self.node_secret),
			Recipient::PhantomNode => Err(()),
		}?;
		Ok(PublicKey::from_secret_key(&Secp256k1::signing_only(), node_secret))
	}

	fn ecdh(
		&self, recipient: Recipient, other_key: &PublicKey,
		tweak: Option<&bitcoin::secp256k1::Scalar>,
	) -> Result<SharedSecret, ()> {
		let mut node_secret = match recipient {
			Recipient::Node => Ok(self.node_secret.clone()),
			Recipient::PhantomNode => Err(()),
		}?;
		if let Some(tweak) = tweak {
			node_secret = node_secret.mul_tweak(tweak).map_err(|_| ())?;
		}
		Ok(SharedSecret::new(other_key, &node_secret))
	}

	fn sign_invoice(&self, _: &RawBolt11Invoice, _: Recipient) -> Result<RecoverableSignature, ()> {
		unreachable!()
	}

	fn sign_bolt12_invoice(
		&self, _invoice: &UnsignedBolt12Invoice,
	) -> Result<schnorr::Signature, ()> {
		unreachable!()
	}

	fn sign_gossip_message(&self, _msg: msgs::UnsignedGossipMessage) -> Result<Signature, ()> {
		unreachable!()
	}

	fn sign_message(&self, msg: &[u8]) -> Result<String, ()> {
		Ok(crate::util::message_signing::sign(msg, &self.node_secret))
	}
}

pub struct TestKeysInterface {
	pub backing: DynKeysInterface,
	pub override_random_bytes: Mutex<Option<[u8; 32]>>,
	pub disable_revocation_policy_check: bool,
	pub disable_all_state_policy_checks: bool,
	enforcement_states: Mutex<HashMap<[u8; 32], Arc<Mutex<EnforcementState>>>>,
	expectations: Mutex<Option<VecDeque<OnGetShutdownScriptpubkey>>>,
	pub unavailable_signers_ops: Mutex<HashMap<[u8; 32], HashSet<SignerOp>>>,
	pub next_signer_disabled_ops: Mutex<HashSet<SignerOp>>,
	pub override_next_keys_id: Mutex<Option<[u8; 32]>>,
}

impl std::fmt::Debug for TestKeysInterface {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("TestKeysInterface").finish()
	}
}

impl EntropySource for TestKeysInterface {
	fn get_secure_random_bytes(&self) -> [u8; 32] {
		let override_random_bytes = self.override_random_bytes.lock().unwrap();
		if let Some(bytes) = &*override_random_bytes {
			return *bytes;
		}
		self.backing.get_secure_random_bytes()
	}
}

impl NodeSigner for TestKeysInterface {
	fn get_node_id(&self, recipient: Recipient) -> Result<PublicKey, ()> {
		self.backing.get_node_id(recipient)
	}

	fn ecdh(
		&self, recipient: Recipient, other_key: &PublicKey, tweak: Option<&Scalar>,
	) -> Result<SharedSecret, ()> {
		self.backing.ecdh(recipient, other_key, tweak)
	}

	fn get_expanded_key(&self) -> ExpandedKey {
		self.backing.get_expanded_key()
	}

	fn sign_invoice(
		&self, invoice: &RawBolt11Invoice, recipient: Recipient,
	) -> Result<RecoverableSignature, ()> {
		self.backing.sign_invoice(invoice, recipient)
	}

	fn get_peer_storage_key(&self) -> PeerStorageKey {
		self.backing.get_peer_storage_key()
	}

	fn get_receive_auth_key(&self) -> ReceiveAuthKey {
		self.backing.get_receive_auth_key()
	}

	fn sign_bolt12_invoice(
		&self, invoice: &UnsignedBolt12Invoice,
	) -> Result<schnorr::Signature, ()> {
		self.backing.sign_bolt12_invoice(invoice)
	}

	fn sign_gossip_message(&self, msg: msgs::UnsignedGossipMessage) -> Result<Signature, ()> {
		self.backing.sign_gossip_message(msg)
	}

	fn sign_message(&self, msg: &[u8]) -> Result<String, ()> {
		self.backing.sign_message(msg)
	}
}

impl SignerProvider for TestKeysInterface {
	type EcdsaSigner = TestChannelSigner;
	#[cfg(taproot)]
	type TaprootSigner = TestChannelSigner;

	fn generate_channel_keys_id(&self, inbound: bool, user_channel_id: u128) -> [u8; 32] {
		let mut override_keys = self.override_next_keys_id.lock().unwrap();

		if let Some(keys_id) = *override_keys {
			// Reset after use
			*override_keys = None;
			return keys_id;
		}
		self.backing.generate_channel_keys_id(inbound, user_channel_id)
	}

	fn derive_channel_signer(&self, channel_keys_id: [u8; 32]) -> TestChannelSigner {
		let keys = self.backing.derive_channel_signer(channel_keys_id);
		let state = self.make_enforcement_state_cell(keys.channel_keys_id());
		let rev_checks = self.disable_revocation_policy_check;
		let state_checks = self.disable_all_state_policy_checks;
		let signer = TestChannelSigner::new_with_revoked(keys, state, rev_checks, state_checks);
		#[cfg(test)]
		if let Some(ops) = self.unavailable_signers_ops.lock().unwrap().get(&channel_keys_id) {
			for &op in ops {
				signer.disable_op(op);
			}
		}
		#[cfg(test)]
		for op in self.next_signer_disabled_ops.lock().unwrap().drain() {
			signer.disable_op(op);
		}
		signer
	}

	fn get_destination_script(&self, channel_keys_id: [u8; 32]) -> Result<ScriptBuf, ()> {
		self.backing.get_destination_script(channel_keys_id)
	}

	fn get_shutdown_scriptpubkey(&self) -> Result<ShutdownScript, ()> {
		match &mut *self.expectations.lock().unwrap() {
			None => self.backing.get_shutdown_scriptpubkey(),
			Some(expectations) => match expectations.pop_front() {
				None => panic!("Unexpected get_shutdown_scriptpubkey"),
				Some(expectation) => Ok(expectation.returns),
			},
		}
	}
}

#[cfg(feature = "std")]
pub static SIGNER_FACTORY: MutGlobal<Arc<dyn TestSignerFactory>> =
	MutGlobal::new(|| Arc::new(DefaultSignerFactory()));

pub trait TestSignerFactory: Send + Sync {
	/// Make a dynamic signer
	fn make_signer(
		&self, seed: &[u8; 32], now: Duration, v2_remote_key_derivation: bool,
		phantom_seed: Option<&[u8; 32]>,
	) -> Box<dyn DynKeysInterfaceTrait<EcdsaSigner = DynSigner>>;
}

#[derive(Clone)]
struct DefaultSignerFactory();

impl TestSignerFactory for DefaultSignerFactory {
	fn make_signer(
		&self, seed: &[u8; 32], now: Duration, v2_remote_key_derivation: bool,
		phantom_seed: Option<&[u8; 32]>,
	) -> Box<dyn DynKeysInterfaceTrait<EcdsaSigner = DynSigner>> {
		let phantom = sign::PhantomKeysManager::new(
			seed,
			now.as_secs(),
			now.subsec_nanos(),
			if let Some(provided_seed) = phantom_seed { provided_seed } else { seed },
			v2_remote_key_derivation,
		);
		let dphantom = DynPhantomKeysInterface::new(phantom);
		let backing = Box::new(dphantom) as Box<dyn DynKeysInterfaceTrait<EcdsaSigner = DynSigner>>;
		backing
	}
}

impl TestKeysInterface {
	fn build(backing: Box<dyn DynKeysInterfaceTrait<EcdsaSigner = DynSigner>>) -> Self {
		Self {
			backing: DynKeysInterface::new(backing),
			override_random_bytes: Mutex::new(None),
			disable_revocation_policy_check: false,
			disable_all_state_policy_checks: false,
			enforcement_states: Mutex::new(new_hash_map()),
			expectations: Mutex::new(None),
			unavailable_signers_ops: Mutex::new(new_hash_map()),
			next_signer_disabled_ops: Mutex::new(new_hash_set()),
			override_next_keys_id: Mutex::new(None),
		}
	}

	pub fn new(seed: &[u8; 32], network: Network) -> Self {
		#[cfg(feature = "std")]
		let factory = SIGNER_FACTORY.get();

		#[cfg(not(feature = "std"))]
		let factory = DefaultSignerFactory();

		let now = Duration::from_secs(genesis_block(network).header.time as u64);
		let backing = factory.make_signer(seed, now, true, None);
		Self::build(backing)
	}

	pub fn with_v1_remote_key_derivation(seed: &[u8; 32], network: Network) -> Self {
		#[cfg(feature = "std")]
		let factory = SIGNER_FACTORY.get();

		#[cfg(not(feature = "std"))]
		let factory = DefaultSignerFactory();

		let now = Duration::from_secs(genesis_block(network).header.time as u64);
		let backing = factory.make_signer(seed, now, false, None);
		Self::build(backing)
	}

	pub fn with_settings(
		seed: &[u8; 32], network: Network, v1_derivation: bool, phantom_seed: Option<&[u8; 32]>,
	) -> Self {
		#[cfg(feature = "std")]
		let factory = SIGNER_FACTORY.get();

		#[cfg(not(feature = "std"))]
		let factory = DefaultSignerFactory();

		let now = Duration::from_secs(genesis_block(network).header.time as u64);
		let backing = factory.make_signer(seed, now, !v1_derivation, phantom_seed);
		Self::build(backing)
	}

	/// Sets an expectation that [`sign::SignerProvider::get_shutdown_scriptpubkey`] is
	/// called.
	pub fn expect(&self, expectation: OnGetShutdownScriptpubkey) -> &Self {
		self.expectations
			.lock()
			.unwrap()
			.get_or_insert_with(|| VecDeque::new())
			.push_back(expectation);
		self
	}

	pub fn derive_channel_keys(&self, id: &[u8; 32]) -> TestChannelSigner {
		self.derive_channel_signer(*id)
	}

	fn make_enforcement_state_cell(&self, keys_id: [u8; 32]) -> Arc<Mutex<EnforcementState>> {
		let mut states = self.enforcement_states.lock().unwrap();
		if !states.contains_key(&keys_id) {
			let state = EnforcementState::new();
			states.insert(keys_id, Arc::new(Mutex::new(state)));
		}
		let cell = states.get(&keys_id).unwrap();
		Arc::clone(cell)
	}

	pub fn set_next_keys_id(&self, keys_id: [u8; 32]) -> &Self {
		*self.override_next_keys_id.lock().unwrap() = Some(keys_id);
		self
	}
}

impl Drop for TestKeysInterface {
	fn drop(&mut self) {
		if std::thread::panicking() {
			return;
		}

		if let Some(expectations) = &*self.expectations.lock().unwrap() {
			if !expectations.is_empty() {
				panic!("Unsatisfied expectations: {:?}", expectations);
			}
		}
	}
}

/// An expectation that [`sign::SignerProvider::get_shutdown_scriptpubkey`] was called and
/// returns a [`ShutdownScript`].
pub struct OnGetShutdownScriptpubkey {
	/// A shutdown script used to close a channel.
	pub returns: ShutdownScript,
}

impl core::fmt::Debug for OnGetShutdownScriptpubkey {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		f.debug_struct("OnGetShutdownScriptpubkey").finish()
	}
}

pub struct TestChainSource {
	pub chain_hash: ChainHash,
	pub utxo_ret: Mutex<UtxoResult>,
	pub get_utxo_call_count: AtomicUsize,
	pub watched_txn: Mutex<HashSet<(Txid, ScriptBuf)>>,
	pub watched_outputs: Mutex<HashSet<(OutPoint, ScriptBuf)>>,
}

impl TestChainSource {
	pub fn new(network: Network) -> Self {
		let script_pubkey = Builder::new().push_opcode(opcodes::OP_TRUE).into_script();
		let utxo_ret =
			Mutex::new(UtxoResult::Sync(Ok(TxOut { value: Amount::MAX, script_pubkey })));
		Self {
			chain_hash: ChainHash::using_genesis_block(network),
			utxo_ret,
			get_utxo_call_count: AtomicUsize::new(0),
			watched_txn: Mutex::new(new_hash_set()),
			watched_outputs: Mutex::new(new_hash_set()),
		}
	}
	pub fn remove_watched_txn_and_outputs(&self, outpoint: OutPoint, script_pubkey: ScriptBuf) {
		self.watched_outputs.lock().unwrap().remove(&(outpoint, script_pubkey.clone()));
		self.watched_txn.lock().unwrap().remove(&(outpoint.txid, script_pubkey));
	}
}

impl UtxoLookup for TestChainSource {
	fn get_utxo(&self, chain_hash: &ChainHash, _scid: u64, _notifier: Arc<Notifier>) -> UtxoResult {
		self.get_utxo_call_count.fetch_add(1, Ordering::Relaxed);
		if self.chain_hash != *chain_hash {
			return UtxoResult::Sync(Err(UtxoLookupError::UnknownChain));
		}

		self.utxo_ret.lock().unwrap().clone()
	}
}

impl chain::Filter for TestChainSource {
	fn register_tx(&self, txid: &Txid, script_pubkey: &Script) {
		self.watched_txn.lock().unwrap().insert((*txid, script_pubkey.into()));
	}

	fn register_output(&self, output: WatchedOutput) {
		self.watched_outputs.lock().unwrap().insert((output.outpoint, output.script_pubkey));
	}
}

impl Drop for TestChainSource {
	fn drop(&mut self) {
		if std::thread::panicking() {
			return;
		}
	}
}

pub struct TestScorer {
	/// Stores a tuple of (scid, ChannelUsage)
	scorer_expectations: Mutex<Option<VecDeque<(u64, ChannelUsage)>>>,
}

impl TestScorer {
	pub fn new() -> Self {
		Self { scorer_expectations: Mutex::new(None) }
	}

	pub fn expect_usage(&self, scid: u64, expectation: ChannelUsage) {
		let mut expectations = self.scorer_expectations.lock().unwrap();
		expectations.get_or_insert_with(|| VecDeque::new()).push_back((scid, expectation));
	}
}

#[cfg(c_bindings)]
impl crate::util::ser::Writeable for TestScorer {
	fn write<W: crate::util::ser::Writer>(&self, _: &mut W) -> Result<(), crate::io::Error> {
		unreachable!();
	}
}

impl ScoreLookUp for TestScorer {
	type ScoreParams = ();
	fn channel_penalty_msat(
		&self, candidate: &CandidateRouteHop, usage: ChannelUsage,
		_score_params: &Self::ScoreParams,
	) -> u64 {
		let short_channel_id = match candidate.globally_unique_short_channel_id() {
			Some(scid) => scid,
			None => return 0,
		};
		if let Some(scorer_expectations) = self.scorer_expectations.lock().unwrap().as_mut() {
			match scorer_expectations.pop_front() {
				Some((scid, expectation)) => {
					assert_eq!(expectation, usage);
					assert_eq!(scid, short_channel_id);
				},
				None => {},
			}
		}
		0
	}
}

impl ScoreUpdate for TestScorer {
	fn payment_path_failed(
		&mut self, _actual_path: &Path, _actual_short_channel_id: u64,
		_duration_since_epoch: Duration,
	) {
	}

	fn payment_path_successful(&mut self, _actual_path: &Path, _duration_since_epoch: Duration) {}

	fn probe_failed(&mut self, _actual_path: &Path, _: u64, _duration_since_epoch: Duration) {}

	fn probe_successful(&mut self, _actual_path: &Path, _duration_since_epoch: Duration) {}

	fn time_passed(&mut self, _duration_since_epoch: Duration) {}
}

#[cfg(c_bindings)]
impl crate::routing::scoring::Score for TestScorer {}

impl Drop for TestScorer {
	fn drop(&mut self) {
		if std::thread::panicking() {
			return;
		}

		if let Some(scorer_expectations) = self.scorer_expectations.lock().unwrap().as_ref() {
			if !scorer_expectations.is_empty() {
				panic!("Unsatisfied scorer expectations: {:?}", scorer_expectations)
			}
		}
	}
}

pub struct TestWalletSource {
	secret_key: SecretKey,
	utxos: Mutex<Vec<ConfirmedUtxo>>,
	secp: Secp256k1<bitcoin::secp256k1::All>,
}

impl TestWalletSource {
	pub fn new(secret_key: SecretKey) -> Self {
		Self { secret_key, utxos: Mutex::new(Vec::new()), secp: Secp256k1::new() }
	}

	pub fn add_utxo(&self, prevtx: Transaction, vout: u32) {
		let utxo = ConfirmedUtxo::new_p2wpkh(prevtx, vout).unwrap();
		self.utxos.lock().unwrap().push(utxo);
	}

	pub fn remove_utxo(&self, outpoint: bitcoin::OutPoint) {
		self.utxos.lock().unwrap().retain(|utxo| utxo.outpoint() != outpoint);
	}

	pub fn clear_utxos(&self) {
		self.utxos.lock().unwrap().clear();
	}

	pub fn sign_tx(
		&self, mut tx: Transaction,
	) -> Result<Transaction, bitcoin::sighash::P2wpkhError> {
		let utxos = self.utxos.lock().unwrap();
		for i in 0..tx.input.len() {
			if let Some(utxo) =
				utxos.iter().find(|utxo| utxo.outpoint() == tx.input[i].previous_output)
			{
				let sighash = SighashCache::new(&tx).p2wpkh_signature_hash(
					i,
					&utxo.output().script_pubkey,
					utxo.output().value,
					EcdsaSighashType::All,
				)?;
				#[cfg(not(feature = "grind_signatures"))]
				let signature = self.secp.sign_ecdsa(
					&secp256k1::Message::from_digest(sighash.to_byte_array()),
					&self.secret_key,
				);
				#[cfg(feature = "grind_signatures")]
				let signature = self.secp.sign_ecdsa_low_r(
					&secp256k1::Message::from_digest(sighash.to_byte_array()),
					&self.secret_key,
				);
				let bitcoin_sig =
					bitcoin::ecdsa::Signature { signature, sighash_type: EcdsaSighashType::All };
				tx.input[i].witness =
					Witness::p2wpkh(&bitcoin_sig, &self.secret_key.public_key(&self.secp));
			}
		}
		Ok(tx)
	}
}

impl WalletSourceSync for TestWalletSource {
	fn list_confirmed_utxos(&self) -> Result<Vec<Utxo>, ()> {
		let utxos = self.utxos.lock().unwrap();
		Ok(utxos.iter().map(|ConfirmedUtxo { utxo, .. }| utxo.clone()).collect())
	}

	fn get_prevtx(&self, outpoint: bitcoin::OutPoint) -> Result<Transaction, ()> {
		let utxos = self.utxos.lock().unwrap();
		utxos
			.iter()
			.find(|confirmed_utxo| confirmed_utxo.utxo.outpoint == outpoint)
			.map(|ConfirmedUtxo { prevtx, .. }| prevtx.clone())
			.ok_or(())
	}

	fn get_change_script(&self) -> Result<ScriptBuf, ()> {
		let public_key = bitcoin::PublicKey::new(self.secret_key.public_key(&self.secp));
		Ok(ScriptBuf::new_p2wpkh(&public_key.wpubkey_hash().unwrap()))
	}

	fn sign_psbt(&self, psbt: Psbt) -> Result<Transaction, ()> {
		let tx = psbt.extract_tx_unchecked_fee_rate();
		self.sign_tx(tx).map_err(|_| ())
	}
}
