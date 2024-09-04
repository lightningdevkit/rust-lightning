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
use crate::chain::WatchedOutput;
use crate::chain::chaininterface;
use crate::chain::chaininterface::ConfirmationTarget;
#[cfg(test)]
use crate::chain::chaininterface::FEERATE_FLOOR_SATS_PER_KW;
use crate::chain::chainmonitor;
use crate::chain::channelmonitor;
use crate::chain::channelmonitor::MonitorEvent;
use crate::chain::transaction::OutPoint;
use crate::routing::router::{CandidateRouteHop, FirstHopCandidate, PublicHopCandidate, PrivateHopCandidate};
use crate::sign;
use crate::events;
use crate::events::bump_transaction::{WalletSource, Utxo};
use crate::ln::types::ChannelId;
use crate::ln::channel_state::ChannelDetails;
use crate::ln::channelmanager;
#[cfg(test)]
use crate::ln::chan_utils::CommitmentTransaction;
use crate::ln::features::{ChannelFeatures, InitFeatures, NodeFeatures};
use crate::ln::{msgs, wire};
use crate::ln::msgs::LightningError;
use crate::ln::script::ShutdownScript;
use crate::offers::invoice::UnsignedBolt12Invoice;
use crate::offers::invoice_request::UnsignedInvoiceRequest;
use crate::onion_message::messenger::{DefaultMessageRouter, Destination, MessageRouter, OnionMessagePath};
use crate::routing::gossip::{EffectiveCapacity, NetworkGraph, NodeId, RoutingFees};
use crate::routing::utxo::{UtxoLookup, UtxoLookupError, UtxoResult};
use crate::routing::router::{DefaultRouter, InFlightHtlcs, Path, Route, RouteParameters, RouteHintHop, Router, ScorerAccountingForInFlightHtlcs};
use crate::routing::scoring::{ChannelUsage, ScoreUpdate, ScoreLookUp};
use crate::sync::RwLock;
use crate::util::config::UserConfig;
use crate::util::test_channel_signer::{TestChannelSigner, EnforcementState};
use crate::util::logger::{Logger, Record};
use crate::util::ser::{Readable, ReadableArgs, Writer, Writeable};
use crate::util::persist::KVStore;

use bitcoin::amount::Amount;
use bitcoin::constants::ChainHash;
use bitcoin::constants::genesis_block;
use bitcoin::transaction::{Transaction, TxOut};
use bitcoin::script::{Builder, Script, ScriptBuf};
use bitcoin::opcodes;
use bitcoin::block::Block;
use bitcoin::network::Network;
use bitcoin::hash_types::{BlockHash, Txid};
use bitcoin::hashes::Hash;
use bitcoin::sighash::{SighashCache, EcdsaSighashType};

use bitcoin::secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey, self};
use bitcoin::secp256k1::ecdh::SharedSecret;
use bitcoin::secp256k1::ecdsa::{RecoverableSignature, Signature};
use bitcoin::secp256k1::schnorr;

use lightning_invoice::RawBolt11Invoice;

use crate::io;
use crate::prelude::*;
use core::cell::RefCell;
use core::time::Duration;
use crate::sync::{Mutex, Arc};
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use core::mem;
use crate::sign::{InMemorySigner, RandomBytes, Recipient, EntropySource, NodeSigner, SignerProvider};

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
		Self {
			sat_per_kw: Mutex::new(sat_per_kw),
			target_override: Mutex::new(new_hash_map()),
		}
	}
}
impl chaininterface::FeeEstimator for TestFeeEstimator {
	fn get_est_sat_per_1000_weight(&self, conf_target: ConfirmationTarget) -> u32 {
		*self.target_override.lock().unwrap().get(&conf_target).unwrap_or(&*self.sat_per_kw.lock().unwrap())
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
	pub next_routes: Mutex<VecDeque<(RouteParameters, Option<Result<Route, LightningError>>)>>,
	pub next_blinded_payment_paths: Mutex<Vec<BlindedPaymentPath>>,
	pub scorer: &'a RwLock<TestScorer>,
}

impl<'a> TestRouter<'a> {
	pub fn new(
		network_graph: Arc<NetworkGraph<&'a TestLogger>>, logger: &'a TestLogger,
		scorer: &'a RwLock<TestScorer>,
	) -> Self {
		let entropy_source = Arc::new(RandomBytes::new([42; 32]));
		Self {
			router: DefaultRouter::new(network_graph.clone(), logger, entropy_source, scorer, Default::default()),
			network_graph,
			next_routes: Mutex::new(VecDeque::new()),
			next_blinded_payment_paths: Mutex::new(Vec::new()),
			scorer,
		}
	}

	pub fn expect_find_route(&self, query: RouteParameters, result: Result<Route, LightningError>) {
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
		inflight_htlcs: InFlightHtlcs
	) -> Result<Route, msgs::LightningError> {
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
									if let Some(idx) = first_hops.iter().position(|h| h.get_outbound_payment_scid() == Some(hop.short_channel_id)) {
										let node_id = NodeId::from_pubkey(payer);
										let candidate = CandidateRouteHop::FirstHop(FirstHopCandidate {
											details: first_hops[idx],
											payer_node_id: &node_id,
											payer_node_counter: u32::max_value(),
											target_node_counter: u32::max_value(),
										});
										scorer.channel_penalty_msat(&candidate, usage, &Default::default());
										continue;
									}
								}
							}
							let network_graph = self.network_graph.read_only();
							if let Some(channel) = network_graph.channel(hop.short_channel_id) {
								let (directed, _) = channel.as_directed_to(&NodeId::from_pubkey(&hop.pubkey)).unwrap();
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
								let candidate = CandidateRouteHop::PrivateHop(PrivateHopCandidate {
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

	fn create_blinded_payment_paths<
		T: secp256k1::Signing + secp256k1::Verification
	>(
		&self, recipient: PublicKey, first_hops: Vec<ChannelDetails>, tlvs: ReceiveTlvs,
		amount_msats: u64, secp_ctx: &Secp256k1<T>,
	) -> Result<Vec<BlindedPaymentPath>, ()> {
		let mut expected_paths = self.next_blinded_payment_paths.lock().unwrap();
		if expected_paths.is_empty() {
			self.router.create_blinded_payment_paths(
				recipient, first_hops, tlvs, amount_msats, secp_ctx
			)
		} else {
			Ok(core::mem::take(&mut *expected_paths))
		}
	}
}

impl<'a> MessageRouter for TestRouter<'a> {
	fn find_path(
		&self, sender: PublicKey, peers: Vec<PublicKey>, destination: Destination
	) -> Result<OnionMessagePath, ()> {
		self.router.find_path(sender, peers, destination)
	}

	fn create_blinded_paths<
		T: secp256k1::Signing + secp256k1::Verification
	>(
		&self, recipient: PublicKey, context: MessageContext,
		peers: Vec<PublicKey>, secp_ctx: &Secp256k1<T>,
	) -> Result<Vec<BlindedMessagePath>, ()> {
		self.router.create_blinded_paths(recipient, context, peers, secp_ctx)
	}

	fn create_compact_blinded_paths<
		T: secp256k1::Signing + secp256k1::Verification
	>(
		&self, recipient: PublicKey, context: MessageContext,
		peers: Vec<MessageForwardNode>, secp_ctx: &Secp256k1<T>,
	) -> Result<Vec<BlindedMessagePath>, ()> {
		self.router.create_compact_blinded_paths(recipient, context, peers, secp_ctx)
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

pub struct TestMessageRouter<'a> {
	inner: DefaultMessageRouter<Arc<NetworkGraph<&'a TestLogger>>, &'a TestLogger, &'a TestKeysInterface>,
}

impl<'a> TestMessageRouter<'a> {
	pub fn new(network_graph: Arc<NetworkGraph<&'a TestLogger>>, entropy_source: &'a TestKeysInterface) -> Self {
		Self { inner: DefaultMessageRouter::new(network_graph, entropy_source) }
	}
}

impl<'a> MessageRouter for TestMessageRouter<'a> {
	fn find_path(
		&self, sender: PublicKey, peers: Vec<PublicKey>, destination: Destination
	) -> Result<OnionMessagePath, ()> {
		self.inner.find_path(sender, peers, destination)
	}

	fn create_blinded_paths<T: secp256k1::Signing + secp256k1::Verification>(
		&self, recipient: PublicKey, context: MessageContext,
		peers: Vec<PublicKey>, secp_ctx: &Secp256k1<T>,
	) -> Result<Vec<BlindedMessagePath>, ()> {
		self.inner.create_blinded_paths(recipient, context, peers, secp_ctx)
	}

	fn create_compact_blinded_paths<T: secp256k1::Signing + secp256k1::Verification>(
		&self, recipient: PublicKey, context: MessageContext,
		peers: Vec<MessageForwardNode>, secp_ctx: &Secp256k1<T>,
	) -> Result<Vec<BlindedMessagePath>, ()> {
		self.inner.create_compact_blinded_paths(recipient, context, peers, secp_ctx)
	}
}

pub struct OnlyReadsKeysInterface {}

impl EntropySource for OnlyReadsKeysInterface {
	fn get_secure_random_bytes(&self) -> [u8; 32] { [0; 32] }}

impl SignerProvider for OnlyReadsKeysInterface {
	type EcdsaSigner = TestChannelSigner;
	#[cfg(taproot)]
	type TaprootSigner = TestChannelSigner;

	fn generate_channel_keys_id(&self, _inbound: bool, _channel_value_satoshis: u64, _user_channel_id: u128) -> [u8; 32] { unreachable!(); }

	fn derive_channel_signer(&self, _channel_value_satoshis: u64, _channel_keys_id: [u8; 32]) -> Self::EcdsaSigner { unreachable!(); }

	fn read_chan_signer(&self, mut reader: &[u8]) -> Result<Self::EcdsaSigner, msgs::DecodeError> {
		let inner: InMemorySigner = ReadableArgs::read(&mut reader, self)?;
		let state = Arc::new(Mutex::new(EnforcementState::new()));

		Ok(TestChannelSigner::new_with_revoked(
			inner,
			state,
			false
		))
	}

	fn get_destination_script(&self, _channel_keys_id: [u8; 32]) -> Result<ScriptBuf, ()> { Err(()) }
	fn get_shutdown_scriptpubkey(&self) -> Result<ShutdownScript, ()> { Err(()) }
}

pub struct TestChainMonitor<'a> {
	pub added_monitors: Mutex<Vec<(OutPoint, channelmonitor::ChannelMonitor<TestChannelSigner>)>>,
	pub monitor_updates: Mutex<HashMap<ChannelId, Vec<channelmonitor::ChannelMonitorUpdate>>>,
	pub latest_monitor_update_id: Mutex<HashMap<ChannelId, (OutPoint, u64, u64)>>,
	pub chain_monitor: chainmonitor::ChainMonitor<TestChannelSigner, &'a TestChainSource, &'a dyn chaininterface::BroadcasterInterface, &'a TestFeeEstimator, &'a TestLogger, &'a dyn chainmonitor::Persist<TestChannelSigner>>,
	pub keys_manager: &'a TestKeysInterface,
	/// If this is set to Some(), the next update_channel call (not watch_channel) must be a
	/// ChannelForceClosed event for the given channel_id with should_broadcast set to the given
	/// boolean.
	pub expect_channel_force_closed: Mutex<Option<(ChannelId, bool)>>,
	/// If this is set to Some(), the next round trip serialization check will not hold after an
	/// update_channel call (not watch_channel) for the given channel_id.
	pub expect_monitor_round_trip_fail: Mutex<Option<ChannelId>>,
}
impl<'a> TestChainMonitor<'a> {
	pub fn new(chain_source: Option<&'a TestChainSource>, broadcaster: &'a dyn chaininterface::BroadcasterInterface, logger: &'a TestLogger, fee_estimator: &'a TestFeeEstimator, persister: &'a dyn chainmonitor::Persist<TestChannelSigner>, keys_manager: &'a TestKeysInterface) -> Self {
		Self {
			added_monitors: Mutex::new(Vec::new()),
			monitor_updates: Mutex::new(new_hash_map()),
			latest_monitor_update_id: Mutex::new(new_hash_map()),
			chain_monitor: chainmonitor::ChainMonitor::new(chain_source, broadcaster, logger, fee_estimator, persister),
			keys_manager,
			expect_channel_force_closed: Mutex::new(None),
			expect_monitor_round_trip_fail: Mutex::new(None),
		}
	}

	pub fn complete_sole_pending_chan_update(&self, channel_id: &ChannelId) {
		let (outpoint, _, latest_update) = self.latest_monitor_update_id.lock().unwrap().get(channel_id).unwrap().clone();
		self.chain_monitor.channel_monitor_updated(outpoint, latest_update).unwrap();
	}
}
impl<'a> chain::Watch<TestChannelSigner> for TestChainMonitor<'a> {
	fn watch_channel(&self, funding_txo: OutPoint, monitor: channelmonitor::ChannelMonitor<TestChannelSigner>) -> Result<chain::ChannelMonitorUpdateStatus, ()> {
		// At every point where we get a monitor update, we should be able to send a useful monitor
		// to a watchtower and disk...
		let mut w = TestVecWriter(Vec::new());
		monitor.write(&mut w).unwrap();
		let new_monitor = <(BlockHash, channelmonitor::ChannelMonitor<TestChannelSigner>)>::read(
			&mut io::Cursor::new(&w.0), (self.keys_manager, self.keys_manager)).unwrap().1;
		assert!(new_monitor == monitor);
		self.latest_monitor_update_id.lock().unwrap().insert(monitor.channel_id(),
			(funding_txo, monitor.get_latest_update_id(), monitor.get_latest_update_id()));
		self.added_monitors.lock().unwrap().push((funding_txo, monitor));
		self.chain_monitor.watch_channel(funding_txo, new_monitor)
	}

	fn update_channel(&self, funding_txo: OutPoint, update: &channelmonitor::ChannelMonitorUpdate) -> chain::ChannelMonitorUpdateStatus {
		// Every monitor update should survive roundtrip
		let mut w = TestVecWriter(Vec::new());
		update.write(&mut w).unwrap();
		assert!(channelmonitor::ChannelMonitorUpdate::read(
				&mut io::Cursor::new(&w.0)).unwrap() == *update);
		let channel_id = update.channel_id.unwrap_or(ChannelId::v1_from_funding_outpoint(funding_txo));

		self.monitor_updates.lock().unwrap().entry(channel_id).or_insert(Vec::new()).push(update.clone());

		if let Some(exp) = self.expect_channel_force_closed.lock().unwrap().take() {
			assert_eq!(channel_id, exp.0);
			assert_eq!(update.updates.len(), 1);
			if let channelmonitor::ChannelMonitorUpdateStep::ChannelForceClosed { should_broadcast } = update.updates[0] {
				assert_eq!(should_broadcast, exp.1);
			} else { panic!(); }
		}

		self.latest_monitor_update_id.lock().unwrap().insert(channel_id,
			(funding_txo, update.update_id, update.update_id));
		let update_res = self.chain_monitor.update_channel(funding_txo, update);
		// At every point where we get a monitor update, we should be able to send a useful monitor
		// to a watchtower and disk...
		let monitor = self.chain_monitor.get_monitor(funding_txo).unwrap();
		w.0.clear();
		monitor.write(&mut w).unwrap();
		let new_monitor = <(BlockHash, channelmonitor::ChannelMonitor<TestChannelSigner>)>::read(
			&mut io::Cursor::new(&w.0), (self.keys_manager, self.keys_manager)).unwrap().1;
		if let Some(chan_id) = self.expect_monitor_round_trip_fail.lock().unwrap().take() {
			assert_eq!(chan_id, channel_id);
			assert!(new_monitor != *monitor);
		} else {
			assert!(new_monitor == *monitor);
		}
		self.added_monitors.lock().unwrap().push((funding_txo, new_monitor));
		update_res
	}

	fn release_pending_monitor_events(&self) -> Vec<(OutPoint, ChannelId, Vec<MonitorEvent>, Option<PublicKey>)> {
		return self.chain_monitor.release_pending_monitor_events();
	}
}

#[cfg(test)]
struct JusticeTxData {
	justice_tx: Transaction,
	value: Amount,
	commitment_number: u64,
}

#[cfg(test)]
pub(crate) struct WatchtowerPersister {
	persister: TestPersister,
	/// Upon a new commitment_signed, we'll get a
	/// ChannelMonitorUpdateStep::LatestCounterpartyCommitmentTxInfo. We'll store the justice tx
	/// amount, and commitment number so we can build the justice tx after our counterparty
	/// revokes it.
	unsigned_justice_tx_data: Mutex<HashMap<OutPoint, VecDeque<JusticeTxData>>>,
	/// After receiving a revoke_and_ack for a commitment number, we'll form and store the justice
	/// tx which would be used to provide a watchtower with the data it needs.
	watchtower_state: Mutex<HashMap<OutPoint, HashMap<Txid, Transaction>>>,
	destination_script: ScriptBuf,
}

#[cfg(test)]
impl WatchtowerPersister {
	#[cfg(test)]
	pub(crate) fn new(destination_script: ScriptBuf) -> Self {
		WatchtowerPersister {
			persister: TestPersister::new(),
			unsigned_justice_tx_data: Mutex::new(new_hash_map()),
			watchtower_state: Mutex::new(new_hash_map()),
			destination_script,
		}
	}

	#[cfg(test)]
	pub(crate) fn justice_tx(&self, funding_txo: OutPoint, commitment_txid: &Txid)
	-> Option<Transaction> {
		self.watchtower_state.lock().unwrap().get(&funding_txo).unwrap().get(commitment_txid).cloned()
	}

	fn form_justice_data_from_commitment(&self, counterparty_commitment_tx: &CommitmentTransaction)
	-> Option<JusticeTxData> {
		let trusted_tx = counterparty_commitment_tx.trust();
		let output_idx = trusted_tx.revokeable_output_index()?;
		let built_tx = trusted_tx.built_transaction();
		let value = built_tx.transaction.output[output_idx as usize].value;
		let justice_tx = trusted_tx.build_to_local_justice_tx(
			FEERATE_FLOOR_SATS_PER_KW as u64, self.destination_script.clone()).ok()?;
		let commitment_number = counterparty_commitment_tx.commitment_number();
		Some(JusticeTxData { justice_tx, value, commitment_number })
	}
}

#[cfg(test)]
impl<Signer: sign::ecdsa::EcdsaChannelSigner> chainmonitor::Persist<Signer> for WatchtowerPersister {
	fn persist_new_channel(&self, funding_txo: OutPoint,
		data: &channelmonitor::ChannelMonitor<Signer>
	) -> chain::ChannelMonitorUpdateStatus {
		let res = self.persister.persist_new_channel(funding_txo, data);

		assert!(self.unsigned_justice_tx_data.lock().unwrap()
			.insert(funding_txo, VecDeque::new()).is_none());
		assert!(self.watchtower_state.lock().unwrap()
			.insert(funding_txo, new_hash_map()).is_none());

		let initial_counterparty_commitment_tx = data.initial_counterparty_commitment_tx()
			.expect("First and only call expects Some");
		if let Some(justice_data)
			= self.form_justice_data_from_commitment(&initial_counterparty_commitment_tx) {
			self.unsigned_justice_tx_data.lock().unwrap()
				.get_mut(&funding_txo).unwrap()
				.push_back(justice_data);
		}
		res
	}

	fn update_persisted_channel(
		&self, funding_txo: OutPoint, update: Option<&channelmonitor::ChannelMonitorUpdate>,
		data: &channelmonitor::ChannelMonitor<Signer>
	) -> chain::ChannelMonitorUpdateStatus {
		let res = self.persister.update_persisted_channel(funding_txo, update, data);

		if let Some(update) = update {
			let commitment_txs = data.counterparty_commitment_txs_from_update(update);
			let justice_datas = commitment_txs.into_iter()
				.filter_map(|commitment_tx| self.form_justice_data_from_commitment(&commitment_tx));
			let mut channels_justice_txs = self.unsigned_justice_tx_data.lock().unwrap();
			let channel_state = channels_justice_txs.get_mut(&funding_txo).unwrap();
			channel_state.extend(justice_datas);

			while let Some(JusticeTxData { justice_tx, value, commitment_number }) = channel_state.front() {
				let input_idx = 0;
				let commitment_txid = justice_tx.input[input_idx].previous_output.txid;
				match data.sign_to_local_justice_tx(justice_tx.clone(), input_idx, value.to_sat(), *commitment_number) {
					Ok(signed_justice_tx) => {
						let dup = self.watchtower_state.lock().unwrap()
							.get_mut(&funding_txo).unwrap()
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

	fn archive_persisted_channel(&self, funding_txo: OutPoint) {
		<TestPersister as chainmonitor::Persist<TestChannelSigner>>::archive_persisted_channel(&self.persister, funding_txo);
	}
}

pub struct TestPersister {
	/// The queue of update statuses we'll return. If none are queued, ::Completed will always be
	/// returned.
	pub update_rets: Mutex<VecDeque<chain::ChannelMonitorUpdateStatus>>,
	/// When we get an update_persisted_channel call *with* a ChannelMonitorUpdate, we insert the
	/// [`ChannelMonitor::get_latest_update_id`] here.
	///
	/// [`ChannelMonitor`]: channelmonitor::ChannelMonitor
	pub offchain_monitor_updates: Mutex<HashMap<OutPoint, HashSet<u64>>>,
	/// When we get an update_persisted_channel call with no ChannelMonitorUpdate, we insert the
	/// monitor's funding outpoint here.
	pub chain_sync_monitor_persistences: Mutex<VecDeque<OutPoint>>
}
impl TestPersister {
	pub fn new() -> Self {
		Self {
			update_rets: Mutex::new(VecDeque::new()),
			offchain_monitor_updates: Mutex::new(new_hash_map()),
			chain_sync_monitor_persistences: Mutex::new(VecDeque::new())
		}
	}

	/// Queue an update status to return.
	pub fn set_update_ret(&self, next_ret: chain::ChannelMonitorUpdateStatus) {
		self.update_rets.lock().unwrap().push_back(next_ret);
	}
}
impl<Signer: sign::ecdsa::EcdsaChannelSigner> chainmonitor::Persist<Signer> for TestPersister {
	fn persist_new_channel(&self, _funding_txo: OutPoint, _data: &channelmonitor::ChannelMonitor<Signer>) -> chain::ChannelMonitorUpdateStatus {
		if let Some(update_ret) = self.update_rets.lock().unwrap().pop_front() {
			return update_ret
		}
		chain::ChannelMonitorUpdateStatus::Completed
	}

	fn update_persisted_channel(&self, funding_txo: OutPoint, update: Option<&channelmonitor::ChannelMonitorUpdate>, _data: &channelmonitor::ChannelMonitor<Signer>) -> chain::ChannelMonitorUpdateStatus {
		let mut ret = chain::ChannelMonitorUpdateStatus::Completed;
		if let Some(update_ret) = self.update_rets.lock().unwrap().pop_front() {
			ret = update_ret;
		}

		if let Some(update) = update {
			self.offchain_monitor_updates.lock().unwrap().entry(funding_txo).or_insert(new_hash_set()).insert(update.update_id);
		} else {
			self.chain_sync_monitor_persistences.lock().unwrap().push_back(funding_txo);
		}
		ret
	}

	fn archive_persisted_channel(&self, funding_txo: OutPoint) {
		// remove the channel from the offchain_monitor_updates and chain_sync_monitor_persistences.
		self.offchain_monitor_updates.lock().unwrap().remove(&funding_txo);
		self.chain_sync_monitor_persistences.lock().unwrap().retain(|x| x != &funding_txo);
	}
}

pub struct TestStore {
	persisted_bytes: Mutex<HashMap<String, HashMap<String, Vec<u8>>>>,
	read_only: bool,
}

impl TestStore {
	pub fn new(read_only: bool) -> Self {
		let persisted_bytes = Mutex::new(new_hash_map());
		Self { persisted_bytes, read_only }
	}
}

impl KVStore for TestStore {
	fn read(&self, primary_namespace: &str, secondary_namespace: &str, key: &str) -> io::Result<Vec<u8>> {
		let persisted_lock = self.persisted_bytes.lock().unwrap();
		let prefixed = if secondary_namespace.is_empty() {
			primary_namespace.to_string()
		} else {
			format!("{}/{}", primary_namespace, secondary_namespace)
		};

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

	fn write(&self, primary_namespace: &str, secondary_namespace: &str, key: &str, buf: &[u8]) -> io::Result<()> {
		if self.read_only {
			return Err(io::Error::new(
				io::ErrorKind::PermissionDenied,
				"Cannot modify read-only store",
			));
		}
		let mut persisted_lock = self.persisted_bytes.lock().unwrap();

		let prefixed = if secondary_namespace.is_empty() {
			primary_namespace.to_string()
		} else {
			format!("{}/{}", primary_namespace, secondary_namespace)
		};
		let outer_e = persisted_lock.entry(prefixed).or_insert(new_hash_map());
		let mut bytes = Vec::new();
		bytes.write_all(buf)?;
		outer_e.insert(key.to_string(), bytes);
		Ok(())
	}

	fn remove(&self, primary_namespace: &str, secondary_namespace: &str, key: &str, _lazy: bool) -> io::Result<()> {
		if self.read_only {
			return Err(io::Error::new(
				io::ErrorKind::PermissionDenied,
				"Cannot modify read-only store",
			));
		}

		let mut persisted_lock = self.persisted_bytes.lock().unwrap();

		let prefixed = if secondary_namespace.is_empty() {
			primary_namespace.to_string()
		} else {
			format!("{}/{}", primary_namespace, secondary_namespace)
		};
		if let Some(outer_ref) = persisted_lock.get_mut(&prefixed) {
				outer_ref.remove(&key.to_string());
		}

		Ok(())
	}

	fn list(&self, primary_namespace: &str, secondary_namespace: &str) -> io::Result<Vec<String>> {
		let mut persisted_lock = self.persisted_bytes.lock().unwrap();

		let prefixed = if secondary_namespace.is_empty() {
			primary_namespace.to_string()
		} else {
			format!("{}/{}", primary_namespace, secondary_namespace)
		};
		match persisted_lock.entry(prefixed) {
			hash_map::Entry::Occupied(e) => Ok(e.get().keys().cloned().collect()),
			hash_map::Entry::Vacant(_) => Ok(Vec::new()),
		}
	}
}

unsafe impl Sync for TestStore {}
unsafe impl Send for TestStore {}

pub struct TestBroadcaster {
	pub txn_broadcasted: Mutex<Vec<Transaction>>,
	pub blocks: Arc<Mutex<Vec<(Block, u32)>>>,
}

impl TestBroadcaster {
	pub fn new(network: Network) -> Self {
		Self {
			txn_broadcasted: Mutex::new(Vec::new()),
			blocks: Arc::new(Mutex::new(vec![(genesis_block(network), 0)])),
		}
	}

	pub fn with_blocks(blocks: Arc<Mutex<Vec<(Block, u32)>>>) -> Self {
		Self { txn_broadcasted: Mutex::new(Vec::new()), blocks }
	}

	pub fn txn_broadcast(&self) -> Vec<Transaction> {
		self.txn_broadcasted.lock().unwrap().split_off(0)
	}

	pub fn unique_txn_broadcast(&self) -> Vec<Transaction> {
		let mut txn = self.txn_broadcasted.lock().unwrap().split_off(0);
		let mut seen = new_hash_set();
		txn.retain(|tx| seen.insert(tx.compute_txid()));
		txn
	}
}

impl chaininterface::BroadcasterInterface for TestBroadcaster {
	fn broadcast_transactions(&self, txs: &[&Transaction]) {
		for tx in txs {
			let lock_time = tx.lock_time.to_consensus_u32();
			assert!(lock_time < 1_500_000_000);
			if tx.lock_time.is_block_height() && lock_time > self.blocks.lock().unwrap().last().unwrap().1 {
				for inp in tx.input.iter() {
					if inp.sequence != Sequence::MAX {
						panic!("We should never broadcast a transaction before its locktime ({})!", tx.lock_time);
					}
				}
			}
		}
		let owned_txs: Vec<Transaction> = txs.iter().map(|tx| (*tx).clone()).collect();
		self.txn_broadcasted.lock().unwrap().extend(owned_txs);
	}
}

pub struct TestChannelMessageHandler {
	pub pending_events: Mutex<Vec<events::MessageSendEvent>>,
	expected_recv_msgs: Mutex<Option<Vec<wire::Message<()>>>>,
	connected_peers: Mutex<HashSet<PublicKey>>,
	chain_hash: ChainHash,
}

impl TestChannelMessageHandler {
	thread_local! {
		pub static MESSAGE_FETCH_COUNTER: AtomicUsize = AtomicUsize::new(0);
	}
}

impl TestChannelMessageHandler {
	pub fn new(chain_hash: ChainHash) -> Self {
		TestChannelMessageHandler {
			pending_events: Mutex::new(Vec::new()),
			expected_recv_msgs: Mutex::new(None),
			connected_peers: Mutex::new(new_hash_set()),
			chain_hash,
		}
	}

	#[cfg(test)]
	pub(crate) fn expect_receive_msg(&self, ev: wire::Message<()>) {
		let mut expected_msgs = self.expected_recv_msgs.lock().unwrap();
		if expected_msgs.is_none() { *expected_msgs = Some(Vec::new()); }
		expected_msgs.as_mut().unwrap().push(ev);
	}

	fn received_msg(&self, _ev: wire::Message<()>) {
		let mut msgs = self.expected_recv_msgs.lock().unwrap();
		if msgs.is_none() { return; }
		assert!(!msgs.as_ref().unwrap().is_empty(), "Received message when we weren't expecting one");
		#[cfg(test)]
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
	fn handle_open_channel(&self, _their_node_id: &PublicKey, msg: &msgs::OpenChannel) {
		self.received_msg(wire::Message::OpenChannel(msg.clone()));
	}
	fn handle_accept_channel(&self, _their_node_id: &PublicKey, msg: &msgs::AcceptChannel) {
		self.received_msg(wire::Message::AcceptChannel(msg.clone()));
	}
	fn handle_funding_created(&self, _their_node_id: &PublicKey, msg: &msgs::FundingCreated) {
		self.received_msg(wire::Message::FundingCreated(msg.clone()));
	}
	fn handle_funding_signed(&self, _their_node_id: &PublicKey, msg: &msgs::FundingSigned) {
		self.received_msg(wire::Message::FundingSigned(msg.clone()));
	}
	fn handle_channel_ready(&self, _their_node_id: &PublicKey, msg: &msgs::ChannelReady) {
		self.received_msg(wire::Message::ChannelReady(msg.clone()));
	}
	fn handle_shutdown(&self, _their_node_id: &PublicKey, msg: &msgs::Shutdown) {
		self.received_msg(wire::Message::Shutdown(msg.clone()));
	}
	fn handle_closing_signed(&self, _their_node_id: &PublicKey, msg: &msgs::ClosingSigned) {
		self.received_msg(wire::Message::ClosingSigned(msg.clone()));
	}
	fn handle_stfu(&self, _their_node_id: &PublicKey, msg: &msgs::Stfu) {
		self.received_msg(wire::Message::Stfu(msg.clone()));
	}
	#[cfg(splicing)]
	fn handle_splice_init(&self, _their_node_id: &PublicKey, msg: &msgs::SpliceInit) {
		self.received_msg(wire::Message::SpliceInit(msg.clone()));
	}
	#[cfg(splicing)]
	fn handle_splice_ack(&self, _their_node_id: &PublicKey, msg: &msgs::SpliceAck) {
		self.received_msg(wire::Message::SpliceAck(msg.clone()));
	}
	#[cfg(splicing)]
	fn handle_splice_locked(&self, _their_node_id: &PublicKey, msg: &msgs::SpliceLocked) {
		self.received_msg(wire::Message::SpliceLocked(msg.clone()));
	}
	fn handle_update_add_htlc(&self, _their_node_id: &PublicKey, msg: &msgs::UpdateAddHTLC) {
		self.received_msg(wire::Message::UpdateAddHTLC(msg.clone()));
	}
	fn handle_update_fulfill_htlc(&self, _their_node_id: &PublicKey, msg: &msgs::UpdateFulfillHTLC) {
		self.received_msg(wire::Message::UpdateFulfillHTLC(msg.clone()));
	}
	fn handle_update_fail_htlc(&self, _their_node_id: &PublicKey, msg: &msgs::UpdateFailHTLC) {
		self.received_msg(wire::Message::UpdateFailHTLC(msg.clone()));
	}
	fn handle_update_fail_malformed_htlc(&self, _their_node_id: &PublicKey, msg: &msgs::UpdateFailMalformedHTLC) {
		self.received_msg(wire::Message::UpdateFailMalformedHTLC(msg.clone()));
	}
	fn handle_commitment_signed(&self, _their_node_id: &PublicKey, msg: &msgs::CommitmentSigned) {
		self.received_msg(wire::Message::CommitmentSigned(msg.clone()));
	}
	fn handle_revoke_and_ack(&self, _their_node_id: &PublicKey, msg: &msgs::RevokeAndACK) {
		self.received_msg(wire::Message::RevokeAndACK(msg.clone()));
	}
	fn handle_update_fee(&self, _their_node_id: &PublicKey, msg: &msgs::UpdateFee) {
		self.received_msg(wire::Message::UpdateFee(msg.clone()));
	}
	fn handle_channel_update(&self, _their_node_id: &PublicKey, _msg: &msgs::ChannelUpdate) {
		// Don't call `received_msg` here as `TestRoutingMessageHandler` generates these sometimes
	}
	fn handle_announcement_signatures(&self, _their_node_id: &PublicKey, msg: &msgs::AnnouncementSignatures) {
		self.received_msg(wire::Message::AnnouncementSignatures(msg.clone()));
	}
	fn handle_channel_reestablish(&self, _their_node_id: &PublicKey, msg: &msgs::ChannelReestablish) {
		self.received_msg(wire::Message::ChannelReestablish(msg.clone()));
	}
	fn peer_disconnected(&self, their_node_id: &PublicKey) {
		assert!(self.connected_peers.lock().unwrap().remove(their_node_id));
	}
	fn peer_connected(&self, their_node_id: &PublicKey, _msg: &msgs::Init, _inbound: bool) -> Result<(), ()> {
		assert!(self.connected_peers.lock().unwrap().insert(their_node_id.clone()));
		// Don't bother with `received_msg` for Init as its auto-generated and we don't want to
		// bother re-generating the expected Init message in all tests.
		Ok(())
	}
	fn handle_error(&self, _their_node_id: &PublicKey, msg: &msgs::ErrorMessage) {
		self.received_msg(wire::Message::Error(msg.clone()));
	}
	fn provided_node_features(&self) -> NodeFeatures {
		channelmanager::provided_node_features(&UserConfig::default())
	}
	fn provided_init_features(&self, _their_init_features: &PublicKey) -> InitFeatures {
		channelmanager::provided_init_features(&UserConfig::default())
	}

	fn get_chain_hashes(&self) -> Option<Vec<ChainHash>> {
		Some(vec![self.chain_hash])
	}

	fn handle_open_channel_v2(&self, _their_node_id: &PublicKey, msg: &msgs::OpenChannelV2) {
		self.received_msg(wire::Message::OpenChannelV2(msg.clone()));
	}

	fn handle_accept_channel_v2(&self, _their_node_id: &PublicKey, msg: &msgs::AcceptChannelV2) {
		self.received_msg(wire::Message::AcceptChannelV2(msg.clone()));
	}

	fn handle_tx_add_input(&self, _their_node_id: &PublicKey, msg: &msgs::TxAddInput) {
		self.received_msg(wire::Message::TxAddInput(msg.clone()));
	}

	fn handle_tx_add_output(&self, _their_node_id: &PublicKey, msg: &msgs::TxAddOutput) {
		self.received_msg(wire::Message::TxAddOutput(msg.clone()));
	}

	fn handle_tx_remove_input(&self, _their_node_id: &PublicKey, msg: &msgs::TxRemoveInput) {
		self.received_msg(wire::Message::TxRemoveInput(msg.clone()));
	}

	fn handle_tx_remove_output(&self, _their_node_id: &PublicKey, msg: &msgs::TxRemoveOutput) {
		self.received_msg(wire::Message::TxRemoveOutput(msg.clone()));
	}

	fn handle_tx_complete(&self, _their_node_id: &PublicKey, msg: &msgs::TxComplete) {
		self.received_msg(wire::Message::TxComplete(msg.clone()));
	}

	fn handle_tx_signatures(&self, _their_node_id: &PublicKey, msg: &msgs::TxSignatures) {
		self.received_msg(wire::Message::TxSignatures(msg.clone()));
	}

	fn handle_tx_init_rbf(&self, _their_node_id: &PublicKey, msg: &msgs::TxInitRbf) {
		self.received_msg(wire::Message::TxInitRbf(msg.clone()));
	}

	fn handle_tx_ack_rbf(&self, _their_node_id: &PublicKey, msg: &msgs::TxAckRbf) {
		self.received_msg(wire::Message::TxAckRbf(msg.clone()));
	}

	fn handle_tx_abort(&self, _their_node_id: &PublicKey, msg: &msgs::TxAbort) {
		self.received_msg(wire::Message::TxAbort(msg.clone()));
	}
}

impl events::MessageSendEventsProvider for TestChannelMessageHandler {
	fn get_and_clear_pending_msg_events(&self) -> Vec<events::MessageSendEvent> {
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

fn get_dummy_channel_update(short_chan_id: u64) -> msgs::ChannelUpdate {
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
		}
	}
}

pub struct TestRoutingMessageHandler {
	pub chan_upds_recvd: AtomicUsize,
	pub chan_anns_recvd: AtomicUsize,
	pub pending_events: Mutex<Vec<events::MessageSendEvent>>,
	pub request_full_sync: AtomicBool,
}

impl TestRoutingMessageHandler {
	pub fn new() -> Self {
		TestRoutingMessageHandler {
			chan_upds_recvd: AtomicUsize::new(0),
			chan_anns_recvd: AtomicUsize::new(0),
			pending_events: Mutex::new(vec![]),
			request_full_sync: AtomicBool::new(false),
		}
	}
}
impl msgs::RoutingMessageHandler for TestRoutingMessageHandler {
	fn handle_node_announcement(&self, _their_node_id: Option<&PublicKey>, _msg: &msgs::NodeAnnouncement) -> Result<bool, msgs::LightningError> {
		Err(msgs::LightningError { err: "".to_owned(), action: msgs::ErrorAction::IgnoreError })
	}
	fn handle_channel_announcement(&self, _their_node_id: Option<&PublicKey>, _msg: &msgs::ChannelAnnouncement) -> Result<bool, msgs::LightningError> {
		self.chan_anns_recvd.fetch_add(1, Ordering::AcqRel);
		Err(msgs::LightningError { err: "".to_owned(), action: msgs::ErrorAction::IgnoreError })
	}
	fn handle_channel_update(&self, _their_node_id: Option<&PublicKey>, _msg: &msgs::ChannelUpdate) -> Result<bool, msgs::LightningError> {
		self.chan_upds_recvd.fetch_add(1, Ordering::AcqRel);
		Err(msgs::LightningError { err: "".to_owned(), action: msgs::ErrorAction::IgnoreError })
	}
	fn get_next_channel_announcement(&self, starting_point: u64) -> Option<(msgs::ChannelAnnouncement, Option<msgs::ChannelUpdate>, Option<msgs::ChannelUpdate>)> {
		let chan_upd_1 = get_dummy_channel_update(starting_point);
		let chan_upd_2 = get_dummy_channel_update(starting_point);
		let chan_ann = get_dummy_channel_announcement(starting_point);

		Some((chan_ann, Some(chan_upd_1), Some(chan_upd_2)))
	}

	fn get_next_node_announcement(&self, _starting_point: Option<&NodeId>) -> Option<msgs::NodeAnnouncement> {
		None
	}

	fn peer_connected(&self, their_node_id: &PublicKey, init_msg: &msgs::Init, _inbound: bool) -> Result<(), ()> {
		if !init_msg.features.supports_gossip_queries() {
			return Ok(());
		}

		#[allow(unused_mut, unused_assignments)]
		let mut gossip_start_time = 0;
		#[cfg(not(feature = "no-std"))]
		{
			use std::time::{SystemTime, UNIX_EPOCH};
			gossip_start_time = SystemTime::now().duration_since(UNIX_EPOCH).expect("Time must be > 1970").as_secs();
			if self.request_full_sync.load(Ordering::Acquire) {
				gossip_start_time -= 60 * 60 * 24 * 7 * 2; // 2 weeks ago
			} else {
				gossip_start_time -= 60 * 60; // an hour ago
			}
		}

		let mut pending_events = self.pending_events.lock().unwrap();
		pending_events.push(events::MessageSendEvent::SendGossipTimestampFilter {
			node_id: their_node_id.clone(),
			msg: msgs::GossipTimestampFilter {
				chain_hash: ChainHash::using_genesis_block(Network::Testnet),
				first_timestamp: gossip_start_time as u32,
				timestamp_range: u32::max_value(),
			},
		});
		Ok(())
	}

	fn handle_reply_channel_range(&self, _their_node_id: &PublicKey, _msg: msgs::ReplyChannelRange) -> Result<(), msgs::LightningError> {
		Ok(())
	}

	fn handle_reply_short_channel_ids_end(&self, _their_node_id: &PublicKey, _msg: msgs::ReplyShortChannelIdsEnd) -> Result<(), msgs::LightningError> {
		Ok(())
	}

	fn handle_query_channel_range(&self, _their_node_id: &PublicKey, _msg: msgs::QueryChannelRange) -> Result<(), msgs::LightningError> {
		Ok(())
	}

	fn handle_query_short_channel_ids(&self, _their_node_id: &PublicKey, _msg: msgs::QueryShortChannelIds) -> Result<(), msgs::LightningError> {
		Ok(())
	}

	fn provided_node_features(&self) -> NodeFeatures {
		let mut features = NodeFeatures::empty();
		features.set_gossip_queries_optional();
		features
	}

	fn provided_init_features(&self, _their_init_features: &PublicKey) -> InitFeatures {
		let mut features = InitFeatures::empty();
		features.set_gossip_queries_optional();
		features
	}

	fn processing_queue_high(&self) -> bool { false }
}

impl events::MessageSendEventsProvider for TestRoutingMessageHandler {
	fn get_and_clear_pending_msg_events(&self) -> Vec<events::MessageSendEvent> {
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
		TestLogger {
			id,
			lines: Mutex::new(new_hash_map()),
			context: Mutex::new(new_hash_map()),
		}
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
		let l: usize = log_entries.iter().filter(|&(&(ref m, ref l), _c)| {
			*m == module && l.contains(line)
		}).map(|(_, c) | { c }).sum();
		assert_eq!(l, count)
	}

	/// Search for the number of occurrences of logged lines which
	/// 1. belong to the specified module and
	/// 2. match the given regex pattern.
	/// Assert that the number of occurrences equals the given `count`
	#[cfg(any(test, feature = "_test_utils"))]
	pub fn assert_log_regex(&self, module: &str, pattern: regex::Regex, count: usize) {
		let log_entries = self.lines.lock().unwrap();
		let l: usize = log_entries.iter().filter(|&(&(ref m, ref l), _c)| {
			*m == module && pattern.is_match(&l)
		}).map(|(_, c) | { c }).sum();
		assert_eq!(l, count)
	}

	pub fn assert_log_context_contains(
		&self, module: &str, peer_id: Option<PublicKey>, channel_id: Option<ChannelId>, count: usize
	) {
		let context_entries = self.context.lock().unwrap();
		let l = context_entries.get(&(module, peer_id, channel_id)).unwrap();
		assert_eq!(*l, count)
	}
}

impl Logger for TestLogger {
	fn log(&self, record: Record) {
		let s = format!("{:<55} {}",
			format_args!("{} {} [{}:{}]", self.id, record.level.to_string(), record.module_path, record.line),
			record.args
		);
		#[cfg(ldk_bench)] {
			// When benchmarking, we don't actually want to print logs, but we do want to format
			// them. To make sure LLVM doesn't skip the above entirely we push it through a
			// volitile read. This may not be super fast, but it shouldn't be worse than anything a
			// user actually does with a log
			let s_bytes = s.as_bytes();
			for i in 0..s.len() {
				let _ = unsafe { core::ptr::read_volatile(&s_bytes[i]) };
			}
		}
		#[cfg(not(ldk_bench))] {
			*self.lines.lock().unwrap().entry((record.module_path, format!("{}", record.args))).or_insert(0) += 1;
			*self.context.lock().unwrap().entry((record.module_path, record.peer_id, record.channel_id)).or_insert(0) += 1;
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
	fn get_inbound_payment_key_material(&self) -> crate::sign::KeyMaterial {
		unreachable!()
	}

	fn get_node_id(&self, recipient: Recipient) -> Result<PublicKey, ()> {
		let node_secret = match recipient {
			Recipient::Node => Ok(&self.node_secret),
			Recipient::PhantomNode => Err(())
		}?;
		Ok(PublicKey::from_secret_key(&Secp256k1::signing_only(), node_secret))
	}

	fn ecdh(&self, recipient: Recipient, other_key: &PublicKey, tweak: Option<&bitcoin::secp256k1::Scalar>) -> Result<SharedSecret, ()> {
		let mut node_secret = match recipient {
			Recipient::Node => Ok(self.node_secret.clone()),
			Recipient::PhantomNode => Err(())
		}?;
		if let Some(tweak) = tweak {
			node_secret = node_secret.mul_tweak(tweak).map_err(|_| ())?;
		}
		Ok(SharedSecret::new(other_key, &node_secret))
	}

	fn sign_invoice(&self, _: &RawBolt11Invoice, _: Recipient) -> Result<RecoverableSignature, ()> {
		unreachable!()
	}

	fn sign_bolt12_invoice_request(
		&self, _invoice_request: &UnsignedInvoiceRequest
	) -> Result<schnorr::Signature, ()> {
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
}

pub struct TestKeysInterface {
	pub backing: sign::PhantomKeysManager,
	pub override_random_bytes: Mutex<Option<[u8; 32]>>,
	pub disable_revocation_policy_check: bool,
	enforcement_states: Mutex<HashMap<[u8;32], Arc<Mutex<EnforcementState>>>>,
	expectations: Mutex<Option<VecDeque<OnGetShutdownScriptpubkey>>>,
	pub unavailable_signers_ops: Mutex<HashMap<[u8; 32], HashSet<SignerOp>>>,
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

	fn ecdh(&self, recipient: Recipient, other_key: &PublicKey, tweak: Option<&Scalar>) -> Result<SharedSecret, ()> {
		self.backing.ecdh(recipient, other_key, tweak)
	}

	fn get_inbound_payment_key_material(&self) -> sign::KeyMaterial {
		self.backing.get_inbound_payment_key_material()
	}

	fn sign_invoice(&self, invoice: &RawBolt11Invoice, recipient: Recipient) -> Result<RecoverableSignature, ()> {
		self.backing.sign_invoice(invoice, recipient)
	}

	fn sign_bolt12_invoice_request(
		&self, invoice_request: &UnsignedInvoiceRequest
	) -> Result<schnorr::Signature, ()> {
		self.backing.sign_bolt12_invoice_request(invoice_request)
	}

	fn sign_bolt12_invoice(
		&self, invoice: &UnsignedBolt12Invoice,
	) -> Result<schnorr::Signature, ()> {
		self.backing.sign_bolt12_invoice(invoice)
	}

	fn sign_gossip_message(&self, msg: msgs::UnsignedGossipMessage) -> Result<Signature, ()> {
		self.backing.sign_gossip_message(msg)
	}
}

impl SignerProvider for TestKeysInterface {
	type EcdsaSigner = TestChannelSigner;
	#[cfg(taproot)]
	type TaprootSigner = TestChannelSigner;

	fn generate_channel_keys_id(&self, inbound: bool, channel_value_satoshis: u64, user_channel_id: u128) -> [u8; 32] {
		self.backing.generate_channel_keys_id(inbound, channel_value_satoshis, user_channel_id)
	}

	fn derive_channel_signer(&self, channel_value_satoshis: u64, channel_keys_id: [u8; 32]) -> TestChannelSigner {
		let keys = self.backing.derive_channel_signer(channel_value_satoshis, channel_keys_id);
		let state = self.make_enforcement_state_cell(keys.commitment_seed);
		let signer = TestChannelSigner::new_with_revoked(keys, state, self.disable_revocation_policy_check);
		#[cfg(test)]
		if let Some(ops) = self.unavailable_signers_ops.lock().unwrap().get(&channel_keys_id) {
			for &op in ops {
				signer.disable_op(op);
			}
		}
		signer
	}

	fn read_chan_signer(&self, buffer: &[u8]) -> Result<Self::EcdsaSigner, msgs::DecodeError> {
		let mut reader = io::Cursor::new(buffer);

		let inner: InMemorySigner = ReadableArgs::read(&mut reader, self)?;
		let state = self.make_enforcement_state_cell(inner.commitment_seed);

		Ok(TestChannelSigner::new_with_revoked(
			inner,
			state,
			self.disable_revocation_policy_check
		))
	}

	fn get_destination_script(&self, channel_keys_id: [u8; 32]) -> Result<ScriptBuf, ()> { self.backing.get_destination_script(channel_keys_id) }

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

impl TestKeysInterface {
	pub fn new(seed: &[u8; 32], network: Network) -> Self {
		let now = Duration::from_secs(genesis_block(network).header.time as u64);
		Self {
			backing: sign::PhantomKeysManager::new(seed, now.as_secs(), now.subsec_nanos(), seed),
			override_random_bytes: Mutex::new(None),
			disable_revocation_policy_check: false,
			enforcement_states: Mutex::new(new_hash_map()),
			expectations: Mutex::new(None),
			unavailable_signers_ops: Mutex::new(new_hash_map()),
		}
	}

	/// Sets an expectation that [`sign::SignerProvider::get_shutdown_scriptpubkey`] is
	/// called.
	pub fn expect(&self, expectation: OnGetShutdownScriptpubkey) -> &Self {
		self.expectations.lock().unwrap()
			.get_or_insert_with(|| VecDeque::new())
			.push_back(expectation);
		self
	}

	pub fn derive_channel_keys(&self, channel_value_satoshis: u64, id: &[u8; 32]) -> TestChannelSigner {
		self.derive_channel_signer(channel_value_satoshis, *id)
	}

	fn make_enforcement_state_cell(&self, commitment_seed: [u8; 32]) -> Arc<Mutex<EnforcementState>> {
		let mut states = self.enforcement_states.lock().unwrap();
		if !states.contains_key(&commitment_seed) {
			let state = EnforcementState::new();
			states.insert(commitment_seed, Arc::new(Mutex::new(state)));
		}
		let cell = states.get(&commitment_seed).unwrap();
		Arc::clone(cell)
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
		Self {
			chain_hash: ChainHash::using_genesis_block(network),
			utxo_ret: Mutex::new(UtxoResult::Sync(Ok(TxOut { value: Amount::MAX, script_pubkey }))),
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
	fn get_utxo(&self, chain_hash: &ChainHash, _short_channel_id: u64) -> UtxoResult {
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
	scorer_expectations: RefCell<Option<VecDeque<(u64, ChannelUsage)>>>,
}

impl TestScorer {
	pub fn new() -> Self {
		Self {
			scorer_expectations: RefCell::new(None),
		}
	}

	pub fn expect_usage(&self, scid: u64, expectation: ChannelUsage) {
		self.scorer_expectations.borrow_mut().get_or_insert_with(|| VecDeque::new()).push_back((scid, expectation));
	}
}

#[cfg(c_bindings)]
impl crate::util::ser::Writeable for TestScorer {
	fn write<W: crate::util::ser::Writer>(&self, _: &mut W) -> Result<(), crate::io::Error> { unreachable!(); }
}

impl ScoreLookUp for TestScorer {
	type ScoreParams = ();
	fn channel_penalty_msat(
		&self, candidate: &CandidateRouteHop, usage: ChannelUsage, _score_params: &Self::ScoreParams
	) -> u64 {
		let short_channel_id = match candidate.globally_unique_short_channel_id() {
			Some(scid) => scid,
			None => return 0,
		};
		if let Some(scorer_expectations) = self.scorer_expectations.borrow_mut().as_mut() {
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
	fn payment_path_failed(&mut self, _actual_path: &Path, _actual_short_channel_id: u64, _duration_since_epoch: Duration) {}

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

		if let Some(scorer_expectations) = self.scorer_expectations.borrow().as_ref() {
			if !scorer_expectations.is_empty() {
				panic!("Unsatisfied scorer expectations: {:?}", scorer_expectations)
			}
		}
	}
}

pub struct TestWalletSource {
	secret_key: SecretKey,
	utxos: RefCell<Vec<Utxo>>,
	secp: Secp256k1<bitcoin::secp256k1::All>,
}

impl TestWalletSource {
	pub fn new(secret_key: SecretKey) -> Self {
		Self {
			secret_key,
			utxos: RefCell::new(Vec::new()),
			secp: Secp256k1::new(),
		}
	}

	pub fn add_utxo(&self, outpoint: bitcoin::OutPoint, value: Amount) -> TxOut {
		let public_key = bitcoin::PublicKey::new(self.secret_key.public_key(&self.secp));
		let utxo = Utxo::new_p2pkh(outpoint, value, &public_key.pubkey_hash());
		self.utxos.borrow_mut().push(utxo.clone());
		utxo.output
	}

	pub fn add_custom_utxo(&self, utxo: Utxo) -> TxOut {
		let output = utxo.output.clone();
		self.utxos.borrow_mut().push(utxo);
		output
	}

	pub fn remove_utxo(&self, outpoint: bitcoin::OutPoint) {
		self.utxos.borrow_mut().retain(|utxo| utxo.outpoint != outpoint);
	}
}

impl WalletSource for TestWalletSource {
	fn list_confirmed_utxos(&self) -> Result<Vec<Utxo>, ()> {
		Ok(self.utxos.borrow().clone())
	}

	fn get_change_script(&self) -> Result<ScriptBuf, ()> {
		let public_key = bitcoin::PublicKey::new(self.secret_key.public_key(&self.secp));
		Ok(ScriptBuf::new_p2pkh(&public_key.pubkey_hash()))
	}

	fn sign_psbt(&self, psbt: Psbt) -> Result<Transaction, ()> {
		let mut tx = psbt.extract_tx_unchecked_fee_rate();
		let utxos = self.utxos.borrow();
		for i in 0..tx.input.len() {
			if let Some(utxo) = utxos.iter().find(|utxo| utxo.outpoint == tx.input[i].previous_output) {
				let sighash = SighashCache::new(&tx)
					.legacy_signature_hash(i, &utxo.output.script_pubkey, EcdsaSighashType::All as u32)
					.map_err(|_| ())?;
				let signature = self.secp.sign_ecdsa(&secp256k1::Message::from_digest(sighash.to_byte_array()), &self.secret_key);
				let bitcoin_sig = bitcoin::ecdsa::Signature { signature, sighash_type: EcdsaSighashType::All };
				tx.input[i].script_sig = Builder::new()
					.push_slice(&bitcoin_sig.serialize())
					.push_slice(&self.secret_key.public_key(&self.secp).serialize())
					.into_script();
			}
		}
		Ok(tx)
	}
}
