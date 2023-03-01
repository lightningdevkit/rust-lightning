// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Test that monitor update failures don't get our channel state out of sync.
//! One of the biggest concern with the monitor update failure handling code is that messages
//! resent after monitor updating is restored are delivered out-of-order, resulting in
//! commitment_signed messages having "invalid signatures".
//! To test this we stand up a network of three nodes and read bytes from the fuzz input to denote
//! actions such as sending payments, handling events, or changing monitor update return values on
//! a per-node basis. This should allow it to find any cases where the ordering of actions results
//! in us getting out of sync with ourselves, and, assuming at least one of our recieve- or
//! send-side handling is correct, other peers. We consider it a failure if any action results in a
//! channel being force-closed.

use bitcoin::TxMerkleNode;
use bitcoin::blockdata::block::BlockHeader;
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::blockdata::transaction::{Transaction, TxOut};
use bitcoin::blockdata::script::{Builder, Script};
use bitcoin::blockdata::opcodes;
use bitcoin::blockdata::locktime::PackedLockTime;
use bitcoin::network::constants::Network;

use bitcoin::hashes::Hash as TraitImport;
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::sha256d::Hash as Sha256dHash;
use bitcoin::hash_types::{BlockHash, WPubkeyHash};

use lightning::chain;
use lightning::chain::{BestBlock, ChannelMonitorUpdateStatus, chainmonitor, channelmonitor, Confirm, Watch};
use lightning::chain::channelmonitor::{ChannelMonitor, MonitorEvent};
use lightning::chain::transaction::OutPoint;
use lightning::chain::chaininterface::{BroadcasterInterface, ConfirmationTarget, FeeEstimator};
use lightning::chain::keysinterface::{KeyMaterial, InMemorySigner, Recipient, EntropySource, NodeSigner, SignerProvider};
use lightning::ln::{PaymentHash, PaymentPreimage, PaymentSecret};
use lightning::ln::channelmanager::{ChainParameters, ChannelDetails, ChannelManager, PaymentSendFailure, ChannelManagerReadArgs, PaymentId};
use lightning::ln::channel::FEE_SPIKE_BUFFER_FEE_INCREASE_MULTIPLE;
use lightning::ln::msgs::{self, CommitmentUpdate, ChannelMessageHandler, DecodeError, UpdateAddHTLC, Init};
use lightning::ln::script::ShutdownScript;
use lightning::util::enforcing_trait_impls::{EnforcingSigner, EnforcementState};
use lightning::util::errors::APIError;
use lightning::util::events;
use lightning::util::logger::Logger;
use lightning::util::config::UserConfig;
use lightning::util::events::MessageSendEventsProvider;
use lightning::util::ser::{Readable, ReadableArgs, Writeable, Writer};
use lightning::routing::router::{InFlightHtlcs, Route, RouteHop, RouteParameters, Router};

use crate::utils::test_logger::{self, Output};
use crate::utils::test_persister::TestPersister;

use bitcoin::secp256k1::{Message, PublicKey, SecretKey, Scalar, Secp256k1};
use bitcoin::secp256k1::ecdh::SharedSecret;
use bitcoin::secp256k1::ecdsa::{RecoverableSignature, Signature};

use std::mem;
use std::cmp::{self, Ordering};
use hashbrown::{HashSet, hash_map, HashMap};
use std::sync::{Arc,Mutex};
use std::sync::atomic;
use std::io::Cursor;
use bitcoin::bech32::u5;

const MAX_FEE: u32 = 10_000;
struct FuzzEstimator {
	ret_val: atomic::AtomicU32,
}
impl FeeEstimator for FuzzEstimator {
	fn get_est_sat_per_1000_weight(&self, conf_target: ConfirmationTarget) -> u32 {
		// We force-close channels if our counterparty sends us a feerate which is a small multiple
		// of our HighPriority fee estimate or smaller than our Background fee estimate. Thus, we
		// always return a HighPriority feerate here which is >= the maximum Normal feerate and a
		// Background feerate which is <= the minimum Normal feerate.
		match conf_target {
			ConfirmationTarget::HighPriority => MAX_FEE,
			ConfirmationTarget::Background => 253,
			ConfirmationTarget::Normal => cmp::min(self.ret_val.load(atomic::Ordering::Acquire), MAX_FEE),
		}
	}
}

struct FuzzRouter {}

impl Router for FuzzRouter {
	fn find_route(
		&self, _payer: &PublicKey, _params: &RouteParameters, _first_hops: Option<&[&ChannelDetails]>,
		_inflight_htlcs: &InFlightHtlcs
	) -> Result<Route, msgs::LightningError> {
		Err(msgs::LightningError {
			err: String::from("Not implemented"),
			action: msgs::ErrorAction::IgnoreError
		})
	}
}

pub struct TestBroadcaster {}
impl BroadcasterInterface for TestBroadcaster {
	fn broadcast_transaction(&self, _tx: &Transaction) { }
}

pub struct VecWriter(pub Vec<u8>);
impl Writer for VecWriter {
	fn write_all(&mut self, buf: &[u8]) -> Result<(), ::std::io::Error> {
		self.0.extend_from_slice(buf);
		Ok(())
	}
}

struct TestChainMonitor {
	pub logger: Arc<dyn Logger>,
	pub keys: Arc<KeyProvider>,
	pub persister: Arc<TestPersister>,
	pub chain_monitor: Arc<chainmonitor::ChainMonitor<EnforcingSigner, Arc<dyn chain::Filter>, Arc<TestBroadcaster>, Arc<FuzzEstimator>, Arc<dyn Logger>, Arc<TestPersister>>>,
	// If we reload a node with an old copy of ChannelMonitors, the ChannelManager deserialization
	// logic will automatically force-close our channels for us (as we don't have an up-to-date
	// monitor implying we are not able to punish misbehaving counterparties). Because this test
	// "fails" if we ever force-close a channel, we avoid doing so, always saving the latest
	// fully-serialized monitor state here, as well as the corresponding update_id.
	pub latest_monitors: Mutex<HashMap<OutPoint, (u64, Vec<u8>)>>,
	pub should_update_manager: atomic::AtomicBool,
}
impl TestChainMonitor {
	pub fn new(broadcaster: Arc<TestBroadcaster>, logger: Arc<dyn Logger>, feeest: Arc<FuzzEstimator>, persister: Arc<TestPersister>, keys: Arc<KeyProvider>) -> Self {
		Self {
			chain_monitor: Arc::new(chainmonitor::ChainMonitor::new(None, broadcaster, logger.clone(), feeest, Arc::clone(&persister))),
			logger,
			keys,
			persister,
			latest_monitors: Mutex::new(HashMap::new()),
			should_update_manager: atomic::AtomicBool::new(false),
		}
	}
}
impl chain::Watch<EnforcingSigner> for TestChainMonitor {
	fn watch_channel(&self, funding_txo: OutPoint, monitor: channelmonitor::ChannelMonitor<EnforcingSigner>) -> chain::ChannelMonitorUpdateStatus {
		let mut ser = VecWriter(Vec::new());
		monitor.write(&mut ser).unwrap();
		if let Some(_) = self.latest_monitors.lock().unwrap().insert(funding_txo, (monitor.get_latest_update_id(), ser.0)) {
			panic!("Already had monitor pre-watch_channel");
		}
		self.should_update_manager.store(true, atomic::Ordering::Relaxed);
		self.chain_monitor.watch_channel(funding_txo, monitor)
	}

	fn update_channel(&self, funding_txo: OutPoint, update: &channelmonitor::ChannelMonitorUpdate) -> chain::ChannelMonitorUpdateStatus {
		let mut map_lock = self.latest_monitors.lock().unwrap();
		let mut map_entry = match map_lock.entry(funding_txo) {
			hash_map::Entry::Occupied(entry) => entry,
			hash_map::Entry::Vacant(_) => panic!("Didn't have monitor on update call"),
		};
		let deserialized_monitor = <(BlockHash, channelmonitor::ChannelMonitor<EnforcingSigner>)>::
			read(&mut Cursor::new(&map_entry.get().1), (&*self.keys, &*self.keys)).unwrap().1;
		deserialized_monitor.update_monitor(update, &&TestBroadcaster{}, &FuzzEstimator { ret_val: atomic::AtomicU32::new(253) }, &self.logger).unwrap();
		let mut ser = VecWriter(Vec::new());
		deserialized_monitor.write(&mut ser).unwrap();
		map_entry.insert((update.update_id, ser.0));
		self.should_update_manager.store(true, atomic::Ordering::Relaxed);
		self.chain_monitor.update_channel(funding_txo, update)
	}

	fn release_pending_monitor_events(&self) -> Vec<(OutPoint, Vec<MonitorEvent>, Option<PublicKey>)> {
		return self.chain_monitor.release_pending_monitor_events();
	}
}

struct KeyProvider {
	node_secret: SecretKey,
	rand_bytes_id: atomic::AtomicU32,
	enforcement_states: Mutex<HashMap<[u8;32], Arc<Mutex<EnforcementState>>>>,
}

impl EntropySource for KeyProvider {
	fn get_secure_random_bytes(&self) -> [u8; 32] {
		let id = self.rand_bytes_id.fetch_add(1, atomic::Ordering::Relaxed);
		let mut res = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 11, self.node_secret[31]];
		res[30-4..30].copy_from_slice(&id.to_le_bytes());
		res
	}
}

impl NodeSigner for KeyProvider {
	fn get_node_id(&self, recipient: Recipient) -> Result<PublicKey, ()> {
		let node_secret = match recipient {
			Recipient::Node => Ok(&self.node_secret),
			Recipient::PhantomNode => Err(())
		}?;
		Ok(PublicKey::from_secret_key(&Secp256k1::signing_only(), node_secret))
	}

	fn ecdh(&self, recipient: Recipient, other_key: &PublicKey, tweak: Option<&Scalar>) -> Result<SharedSecret, ()> {
		let mut node_secret = match recipient {
			Recipient::Node => Ok(self.node_secret.clone()),
			Recipient::PhantomNode => Err(())
		}?;
		if let Some(tweak) = tweak {
			node_secret = node_secret.mul_tweak(tweak).map_err(|_| ())?;
		}
		Ok(SharedSecret::new(other_key, &node_secret))
	}

	fn get_inbound_payment_key_material(&self) -> KeyMaterial {
		KeyMaterial([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, self.node_secret[31]])
	}

	fn sign_invoice(&self, _hrp_bytes: &[u8], _invoice_data: &[u5], _recipient: Recipient) -> Result<RecoverableSignature, ()> {
		unreachable!()
	}

	fn sign_gossip_message(&self, msg: lightning::ln::msgs::UnsignedGossipMessage) -> Result<Signature, ()> {
		let msg_hash = Message::from_slice(&Sha256dHash::hash(&msg.encode()[..])[..]).map_err(|_| ())?;
		let secp_ctx = Secp256k1::signing_only();
		Ok(secp_ctx.sign_ecdsa(&msg_hash, &self.node_secret))
	}
}

impl SignerProvider for KeyProvider {
	type Signer = EnforcingSigner;

	fn generate_channel_keys_id(&self, _inbound: bool, _channel_value_satoshis: u64, _user_channel_id: u128) -> [u8; 32] {
		let id = self.rand_bytes_id.fetch_add(1, atomic::Ordering::Relaxed) as u8;
		[id; 32]
	}

	fn derive_channel_signer(&self, channel_value_satoshis: u64, channel_keys_id: [u8; 32]) -> Self::Signer {
		let secp_ctx = Secp256k1::signing_only();
		let id = channel_keys_id[0];
		let keys = InMemorySigner::new(
			&secp_ctx,
			SecretKey::from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, self.node_secret[31]]).unwrap(),
			SecretKey::from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, self.node_secret[31]]).unwrap(),
			SecretKey::from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6, self.node_secret[31]]).unwrap(),
			SecretKey::from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, self.node_secret[31]]).unwrap(),
			SecretKey::from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, self.node_secret[31]]).unwrap(),
			[id, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9, self.node_secret[31]],
			channel_value_satoshis,
			channel_keys_id,
		);
		let revoked_commitment = self.make_enforcement_state_cell(keys.commitment_seed);
		EnforcingSigner::new_with_revoked(keys, revoked_commitment, false)
	}

	fn read_chan_signer(&self, buffer: &[u8]) -> Result<Self::Signer, DecodeError> {
		let mut reader = std::io::Cursor::new(buffer);

		let inner: InMemorySigner = Readable::read(&mut reader)?;
		let state = self.make_enforcement_state_cell(inner.commitment_seed);

		Ok(EnforcingSigner {
			inner,
			state,
			disable_revocation_policy_check: false,
		})
	}

	fn get_destination_script(&self) -> Script {
		let secp_ctx = Secp256k1::signing_only();
		let channel_monitor_claim_key = SecretKey::from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, self.node_secret[31]]).unwrap();
		let our_channel_monitor_claim_key_hash = WPubkeyHash::hash(&PublicKey::from_secret_key(&secp_ctx, &channel_monitor_claim_key).serialize());
		Builder::new().push_opcode(opcodes::all::OP_PUSHBYTES_0).push_slice(&our_channel_monitor_claim_key_hash[..]).into_script()
	}

	fn get_shutdown_scriptpubkey(&self) -> ShutdownScript {
		let secp_ctx = Secp256k1::signing_only();
		let secret_key = SecretKey::from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, self.node_secret[31]]).unwrap();
		let pubkey_hash = WPubkeyHash::hash(&PublicKey::from_secret_key(&secp_ctx, &secret_key).serialize());
		ShutdownScript::new_p2wpkh(&pubkey_hash)
	}
}

impl KeyProvider {
	fn make_enforcement_state_cell(&self, commitment_seed: [u8; 32]) -> Arc<Mutex<EnforcementState>> {
		let mut revoked_commitments = self.enforcement_states.lock().unwrap();
		if !revoked_commitments.contains_key(&commitment_seed) {
			revoked_commitments.insert(commitment_seed, Arc::new(Mutex::new(EnforcementState::new())));
		}
		let cell = revoked_commitments.get(&commitment_seed).unwrap();
		Arc::clone(cell)
	}
}

#[inline]
fn check_api_err(api_err: APIError) {
	match api_err {
		APIError::APIMisuseError { .. } => panic!("We can't misuse the API"),
		APIError::FeeRateTooHigh { .. } => panic!("We can't send too much fee?"),
		APIError::InvalidRoute { .. } => panic!("Our routes should work"),
		APIError::ChannelUnavailable { err } => {
			// Test the error against a list of errors we can hit, and reject
			// all others. If you hit this panic, the list of acceptable errors
			// is probably just stale and you should add new messages here.
			match err.as_str() {
				"Peer for first hop currently disconnected" => {},
				_ if err.starts_with("Cannot push more than their max accepted HTLCs ") => {},
				_ if err.starts_with("Cannot send value that would put us over the max HTLC value in flight our peer will accept ") => {},
				_ if err.starts_with("Cannot send value that would put our balance under counterparty-announced channel reserve value") => {},
				_ if err.starts_with("Cannot send value that would put counterparty balance under holder-announced channel reserve value") => {},
				_ if err.starts_with("Cannot send value that would overdraw remaining funds.") => {},
				_ if err.starts_with("Cannot send value that would not leave enough to pay for fees.") => {},
				_ if err.starts_with("Cannot send value that would put our exposure to dust HTLCs at") => {},
				_ => panic!("{}", err),
			}
		},
		APIError::MonitorUpdateInProgress => {
			// We can (obviously) temp-fail a monitor update
		},
		APIError::IncompatibleShutdownScript { .. } => panic!("Cannot send an incompatible shutdown script"),
	}
}
#[inline]
fn check_payment_err(send_err: PaymentSendFailure) {
	match send_err {
		PaymentSendFailure::ParameterError(api_err) => check_api_err(api_err),
		PaymentSendFailure::PathParameterError(per_path_results) => {
			for res in per_path_results { if let Err(api_err) = res { check_api_err(api_err); } }
		},
		PaymentSendFailure::AllFailedResendSafe(per_path_results) => {
			for api_err in per_path_results { check_api_err(api_err); }
		},
		PaymentSendFailure::PartialFailure { results, .. } => {
			for res in results { if let Err(api_err) = res { check_api_err(api_err); } }
		},
		PaymentSendFailure::DuplicatePayment => panic!(),
	}
}

type ChanMan<'a> = ChannelManager<Arc<TestChainMonitor>, Arc<TestBroadcaster>, Arc<KeyProvider>, Arc<KeyProvider>, Arc<KeyProvider>, Arc<FuzzEstimator>, &'a FuzzRouter, Arc<dyn Logger>>;

#[inline]
fn get_payment_secret_hash(dest: &ChanMan, payment_id: &mut u8) -> Option<(PaymentSecret, PaymentHash)> {
	let mut payment_hash;
	for _ in 0..256 {
		payment_hash = PaymentHash(Sha256::hash(&[*payment_id; 1]).into_inner());
		if let Ok(payment_secret) = dest.create_inbound_payment_for_hash(payment_hash, None, 3600, None) {
			return Some((payment_secret, payment_hash));
		}
		*payment_id = payment_id.wrapping_add(1);
	}
	None
}

#[inline]
fn send_payment(source: &ChanMan, dest: &ChanMan, dest_chan_id: u64, amt: u64, payment_id: &mut u8, payment_idx: &mut u64) -> bool {
	let (payment_secret, payment_hash) =
		if let Some((secret, hash)) = get_payment_secret_hash(dest, payment_id) { (secret, hash) } else { return true; };
	let mut payment_id = [0; 32];
	payment_id[0..8].copy_from_slice(&payment_idx.to_ne_bytes());
	*payment_idx += 1;
	if let Err(err) = source.send_payment(&Route {
		paths: vec![vec![RouteHop {
			pubkey: dest.get_our_node_id(),
			node_features: dest.node_features(),
			short_channel_id: dest_chan_id,
			channel_features: dest.channel_features(),
			fee_msat: amt,
			cltv_expiry_delta: 200,
		}]],
		payment_params: None,
	}, payment_hash, &Some(payment_secret), PaymentId(payment_id)) {
		check_payment_err(err);
		false
	} else { true }
}
#[inline]
fn send_hop_payment(source: &ChanMan, middle: &ChanMan, middle_chan_id: u64, dest: &ChanMan, dest_chan_id: u64, amt: u64, payment_id: &mut u8, payment_idx: &mut u64) -> bool {
	let (payment_secret, payment_hash) =
		if let Some((secret, hash)) = get_payment_secret_hash(dest, payment_id) { (secret, hash) } else { return true; };
	let mut payment_id = [0; 32];
	payment_id[0..8].copy_from_slice(&payment_idx.to_ne_bytes());
	*payment_idx += 1;
	if let Err(err) = source.send_payment(&Route {
		paths: vec![vec![RouteHop {
			pubkey: middle.get_our_node_id(),
			node_features: middle.node_features(),
			short_channel_id: middle_chan_id,
			channel_features: middle.channel_features(),
			fee_msat: 50000,
			cltv_expiry_delta: 100,
		},RouteHop {
			pubkey: dest.get_our_node_id(),
			node_features: dest.node_features(),
			short_channel_id: dest_chan_id,
			channel_features: dest.channel_features(),
			fee_msat: amt,
			cltv_expiry_delta: 200,
		}]],
		payment_params: None,
	}, payment_hash, &Some(payment_secret), PaymentId(payment_id)) {
		check_payment_err(err);
		false
	} else { true }
}

#[inline]
pub fn do_test<Out: Output>(data: &[u8], underlying_out: Out) {
	let out = SearchingOutput::new(underlying_out);
	let broadcast = Arc::new(TestBroadcaster{});
	let router = FuzzRouter {};

	macro_rules! make_node {
		($node_id: expr, $fee_estimator: expr) => { {
			let logger: Arc<dyn Logger> = Arc::new(test_logger::TestLogger::new($node_id.to_string(), out.clone()));
			let node_secret = SecretKey::from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, $node_id]).unwrap();
			let keys_manager = Arc::new(KeyProvider { node_secret, rand_bytes_id: atomic::AtomicU32::new(0), enforcement_states: Mutex::new(HashMap::new()) });
			let monitor = Arc::new(TestChainMonitor::new(broadcast.clone(), logger.clone(), $fee_estimator.clone(),
				Arc::new(TestPersister {
					update_ret: Mutex::new(ChannelMonitorUpdateStatus::Completed)
				}), Arc::clone(&keys_manager)));

			let mut config = UserConfig::default();
			config.channel_config.forwarding_fee_proportional_millionths = 0;
			config.channel_handshake_config.announced_channel = true;
			let network = Network::Bitcoin;
			let params = ChainParameters {
				network,
				best_block: BestBlock::from_network(network),
			};
			(ChannelManager::new($fee_estimator.clone(), monitor.clone(), broadcast.clone(), &router, Arc::clone(&logger), keys_manager.clone(), keys_manager.clone(), keys_manager.clone(), config, params),
			monitor, keys_manager)
		} }
	}

	macro_rules! reload_node {
		($ser: expr, $node_id: expr, $old_monitors: expr, $keys_manager: expr, $fee_estimator: expr) => { {
		    let keys_manager = Arc::clone(& $keys_manager);
			let logger: Arc<dyn Logger> = Arc::new(test_logger::TestLogger::new($node_id.to_string(), out.clone()));
			let chain_monitor = Arc::new(TestChainMonitor::new(broadcast.clone(), logger.clone(), $fee_estimator.clone(),
				Arc::new(TestPersister {
					update_ret: Mutex::new(ChannelMonitorUpdateStatus::Completed)
				}), Arc::clone(& $keys_manager)));

			let mut config = UserConfig::default();
			config.channel_config.forwarding_fee_proportional_millionths = 0;
			config.channel_handshake_config.announced_channel = true;

			let mut monitors = HashMap::new();
			let mut old_monitors = $old_monitors.latest_monitors.lock().unwrap();
			for (outpoint, (update_id, monitor_ser)) in old_monitors.drain() {
				monitors.insert(outpoint, <(BlockHash, ChannelMonitor<EnforcingSigner>)>::read(&mut Cursor::new(&monitor_ser), (&*$keys_manager, &*$keys_manager)).expect("Failed to read monitor").1);
				chain_monitor.latest_monitors.lock().unwrap().insert(outpoint, (update_id, monitor_ser));
			}
			let mut monitor_refs = HashMap::new();
			for (outpoint, monitor) in monitors.iter_mut() {
				monitor_refs.insert(*outpoint, monitor);
			}

			let read_args = ChannelManagerReadArgs {
				entropy_source: keys_manager.clone(),
				node_signer: keys_manager.clone(),
				signer_provider: keys_manager.clone(),
				fee_estimator: $fee_estimator.clone(),
				chain_monitor: chain_monitor.clone(),
				tx_broadcaster: broadcast.clone(),
				router: &router,
				logger,
				default_config: config,
				channel_monitors: monitor_refs,
			};

			let res = (<(BlockHash, ChanMan)>::read(&mut Cursor::new(&$ser.0), read_args).expect("Failed to read manager").1, chain_monitor.clone());
			for (funding_txo, mon) in monitors.drain() {
				assert_eq!(chain_monitor.chain_monitor.watch_channel(funding_txo, mon),
					ChannelMonitorUpdateStatus::Completed);
			}
			res
		} }
	}

	let mut channel_txn = Vec::new();
	macro_rules! make_channel {
		($source: expr, $dest: expr, $chan_id: expr) => { {
			$source.peer_connected(&$dest.get_our_node_id(), &Init { features: $dest.init_features(), remote_network_address: None }, true).unwrap();
			$dest.peer_connected(&$source.get_our_node_id(), &Init { features: $source.init_features(), remote_network_address: None }, false).unwrap();

			$source.create_channel($dest.get_our_node_id(), 100_000, 42, 0, None).unwrap();
			let open_channel = {
				let events = $source.get_and_clear_pending_msg_events();
				assert_eq!(events.len(), 1);
				if let events::MessageSendEvent::SendOpenChannel { ref msg, .. } = events[0] {
					msg.clone()
				} else { panic!("Wrong event type"); }
			};

			$dest.handle_open_channel(&$source.get_our_node_id(), &open_channel);
			let accept_channel = {
				let events = $dest.get_and_clear_pending_msg_events();
				assert_eq!(events.len(), 1);
				if let events::MessageSendEvent::SendAcceptChannel { ref msg, .. } = events[0] {
					msg.clone()
				} else { panic!("Wrong event type"); }
			};

			$source.handle_accept_channel(&$dest.get_our_node_id(), &accept_channel);
			let funding_output;
			{
				let events = $source.get_and_clear_pending_events();
				assert_eq!(events.len(), 1);
				if let events::Event::FundingGenerationReady { ref temporary_channel_id, ref channel_value_satoshis, ref output_script, .. } = events[0] {
					let tx = Transaction { version: $chan_id, lock_time: PackedLockTime::ZERO, input: Vec::new(), output: vec![TxOut {
						value: *channel_value_satoshis, script_pubkey: output_script.clone(),
					}]};
					funding_output = OutPoint { txid: tx.txid(), index: 0 };
					$source.funding_transaction_generated(&temporary_channel_id, &$dest.get_our_node_id(), tx.clone()).unwrap();
					channel_txn.push(tx);
				} else { panic!("Wrong event type"); }
			}

			let funding_created = {
				let events = $source.get_and_clear_pending_msg_events();
				assert_eq!(events.len(), 1);
				if let events::MessageSendEvent::SendFundingCreated { ref msg, .. } = events[0] {
					msg.clone()
				} else { panic!("Wrong event type"); }
			};
			$dest.handle_funding_created(&$source.get_our_node_id(), &funding_created);

			let funding_signed = {
				let events = $dest.get_and_clear_pending_msg_events();
				assert_eq!(events.len(), 1);
				if let events::MessageSendEvent::SendFundingSigned { ref msg, .. } = events[0] {
					msg.clone()
				} else { panic!("Wrong event type"); }
			};
			$source.handle_funding_signed(&$dest.get_our_node_id(), &funding_signed);

			funding_output
		} }
	}

	macro_rules! confirm_txn {
		($node: expr) => { {
			let chain_hash = genesis_block(Network::Bitcoin).block_hash();
			let mut header = BlockHeader { version: 0x20000000, prev_blockhash: chain_hash, merkle_root: TxMerkleNode::all_zeros(), time: 42, bits: 42, nonce: 42 };
			let txdata: Vec<_> = channel_txn.iter().enumerate().map(|(i, tx)| (i + 1, tx)).collect();
			$node.transactions_confirmed(&header, &txdata, 1);
			for _ in 2..100 {
				header = BlockHeader { version: 0x20000000, prev_blockhash: header.block_hash(), merkle_root: TxMerkleNode::all_zeros(), time: 42, bits: 42, nonce: 42 };
			}
			$node.best_block_updated(&header, 99);
		} }
	}

	macro_rules! lock_fundings {
		($nodes: expr) => { {
			let mut node_events = Vec::new();
			for node in $nodes.iter() {
				node_events.push(node.get_and_clear_pending_msg_events());
			}
			for (idx, node_event) in node_events.iter().enumerate() {
				for event in node_event {
					if let events::MessageSendEvent::SendChannelReady { ref node_id, ref msg } = event {
						for node in $nodes.iter() {
							if node.get_our_node_id() == *node_id {
								node.handle_channel_ready(&$nodes[idx].get_our_node_id(), msg);
							}
						}
					} else { panic!("Wrong event type"); }
				}
			}

			for node in $nodes.iter() {
				let events = node.get_and_clear_pending_msg_events();
				for event in events {
					if let events::MessageSendEvent::SendAnnouncementSignatures { .. } = event {
					} else { panic!("Wrong event type"); }
				}
			}
		} }
	}

	let fee_est_a = Arc::new(FuzzEstimator { ret_val: atomic::AtomicU32::new(253) });
	let mut last_htlc_clear_fee_a =  253;
	let fee_est_b = Arc::new(FuzzEstimator { ret_val: atomic::AtomicU32::new(253) });
	let mut last_htlc_clear_fee_b =  253;
	let fee_est_c = Arc::new(FuzzEstimator { ret_val: atomic::AtomicU32::new(253) });
	let mut last_htlc_clear_fee_c =  253;

	// 3 nodes is enough to hit all the possible cases, notably unknown-source-unknown-dest
	// forwarding.
	let (node_a, mut monitor_a, keys_manager_a) = make_node!(0, fee_est_a);
	let (node_b, mut monitor_b, keys_manager_b) = make_node!(1, fee_est_b);
	let (node_c, mut monitor_c, keys_manager_c) = make_node!(2, fee_est_c);

	let mut nodes = [node_a, node_b, node_c];

	let chan_1_funding = make_channel!(nodes[0], nodes[1], 0);
	let chan_2_funding = make_channel!(nodes[1], nodes[2], 1);

	for node in nodes.iter() {
		confirm_txn!(node);
	}

	lock_fundings!(nodes);

	let chan_a = nodes[0].list_usable_channels()[0].short_channel_id.unwrap();
	let chan_b = nodes[2].list_usable_channels()[0].short_channel_id.unwrap();

	let mut payment_id: u8 = 0;
	let mut payment_idx: u64 = 0;

	let mut chan_a_disconnected = false;
	let mut chan_b_disconnected = false;
	let mut ab_events = Vec::new();
	let mut ba_events = Vec::new();
	let mut bc_events = Vec::new();
	let mut cb_events = Vec::new();

	let mut node_a_ser = VecWriter(Vec::new());
	nodes[0].write(&mut node_a_ser).unwrap();
	let mut node_b_ser = VecWriter(Vec::new());
	nodes[1].write(&mut node_b_ser).unwrap();
	let mut node_c_ser = VecWriter(Vec::new());
	nodes[2].write(&mut node_c_ser).unwrap();

	macro_rules! test_return {
		() => { {
			assert_eq!(nodes[0].list_channels().len(), 1);
			assert_eq!(nodes[1].list_channels().len(), 2);
			assert_eq!(nodes[2].list_channels().len(), 1);
			return;
		} }
	}

	let mut read_pos = 0;
	macro_rules! get_slice {
		($len: expr) => {
			{
				let slice_len = $len as usize;
				if data.len() < read_pos + slice_len {
					test_return!();
				}
				read_pos += slice_len;
				&data[read_pos - slice_len..read_pos]
			}
		}
	}

	loop {
		// Push any events from Node B onto ba_events and bc_events
		macro_rules! push_excess_b_events {
			($excess_events: expr, $expect_drop_node: expr) => { {
				let a_id = nodes[0].get_our_node_id();
				let expect_drop_node: Option<usize> = $expect_drop_node;
				let expect_drop_id = if let Some(id) = expect_drop_node { Some(nodes[id].get_our_node_id()) } else { None };
				for event in $excess_events {
					let push_a = match event {
						events::MessageSendEvent::UpdateHTLCs { ref node_id, .. } => {
							if Some(*node_id) == expect_drop_id { panic!("peer_disconnected should drop msgs bound for the disconnected peer"); }
							*node_id == a_id
						},
						events::MessageSendEvent::SendRevokeAndACK { ref node_id, .. } => {
							if Some(*node_id) == expect_drop_id { panic!("peer_disconnected should drop msgs bound for the disconnected peer"); }
							*node_id == a_id
						},
						events::MessageSendEvent::SendChannelReestablish { ref node_id, .. } => {
							if Some(*node_id) == expect_drop_id { panic!("peer_disconnected should drop msgs bound for the disconnected peer"); }
							*node_id == a_id
						},
						events::MessageSendEvent::SendChannelReady { .. } => continue,
						events::MessageSendEvent::SendAnnouncementSignatures { .. } => continue,
						events::MessageSendEvent::SendChannelUpdate { ref node_id, ref msg } => {
							assert_eq!(msg.contents.flags & 2, 0); // The disable bit must never be set!
							if Some(*node_id) == expect_drop_id { panic!("peer_disconnected should drop msgs bound for the disconnected peer"); }
							*node_id == a_id
						},
						_ => panic!("Unhandled message event {:?}", event),
					};
					if push_a { ba_events.push(event); } else { bc_events.push(event); }
				}
			} }
		}

		// While delivering messages, we select across three possible message selection processes
		// to ensure we get as much coverage as possible. See the individual enum variants for more
		// details.
		#[derive(PartialEq)]
		enum ProcessMessages {
			/// Deliver all available messages, including fetching any new messages from
			/// `get_and_clear_pending_msg_events()` (which may have side effects).
			AllMessages,
			/// Call `get_and_clear_pending_msg_events()` first, and then deliver up to one
			/// message (which may already be queued).
			OneMessage,
			/// Deliver up to one already-queued message. This avoids any potential side-effects
			/// of `get_and_clear_pending_msg_events()` (eg freeing the HTLC holding cell), which
			/// provides potentially more coverage.
			OnePendingMessage,
		}

		macro_rules! process_msg_events {
			($node: expr, $corrupt_forward: expr, $limit_events: expr) => { {
				let mut events = if $node == 1 {
					let mut new_events = Vec::new();
					mem::swap(&mut new_events, &mut ba_events);
					new_events.extend_from_slice(&bc_events[..]);
					bc_events.clear();
					new_events
				} else if $node == 0 {
					let mut new_events = Vec::new();
					mem::swap(&mut new_events, &mut ab_events);
					new_events
				} else {
					let mut new_events = Vec::new();
					mem::swap(&mut new_events, &mut cb_events);
					new_events
				};
				let mut new_events = Vec::new();
				if $limit_events != ProcessMessages::OnePendingMessage {
					new_events = nodes[$node].get_and_clear_pending_msg_events();
				}
				let mut had_events = false;
				let mut events_iter = events.drain(..).chain(new_events.drain(..));
				let mut extra_ev = None;
				for event in &mut events_iter {
					had_events = true;
					match event {
						events::MessageSendEvent::UpdateHTLCs { node_id, updates: CommitmentUpdate { update_add_htlcs, update_fail_htlcs, update_fulfill_htlcs, update_fail_malformed_htlcs, update_fee, commitment_signed } } => {
							for (idx, dest) in nodes.iter().enumerate() {
								if dest.get_our_node_id() == node_id {
									for update_add in update_add_htlcs.iter() {
										out.locked_write(format!("Delivering update_add_htlc to node {}.\n", idx).as_bytes());
										if !$corrupt_forward {
											dest.handle_update_add_htlc(&nodes[$node].get_our_node_id(), update_add);
										} else {
											// Corrupt the update_add_htlc message so that its HMAC
											// check will fail and we generate a
											// update_fail_malformed_htlc instead of an
											// update_fail_htlc as we do when we reject a payment.
											let mut msg_ser = update_add.encode();
											msg_ser[1000] ^= 0xff;
											let new_msg = UpdateAddHTLC::read(&mut Cursor::new(&msg_ser)).unwrap();
											dest.handle_update_add_htlc(&nodes[$node].get_our_node_id(), &new_msg);
										}
									}
									for update_fulfill in update_fulfill_htlcs.iter() {
										out.locked_write(format!("Delivering update_fulfill_htlc to node {}.\n", idx).as_bytes());
										dest.handle_update_fulfill_htlc(&nodes[$node].get_our_node_id(), update_fulfill);
									}
									for update_fail in update_fail_htlcs.iter() {
										out.locked_write(format!("Delivering update_fail_htlc to node {}.\n", idx).as_bytes());
										dest.handle_update_fail_htlc(&nodes[$node].get_our_node_id(), update_fail);
									}
									for update_fail_malformed in update_fail_malformed_htlcs.iter() {
										out.locked_write(format!("Delivering update_fail_malformed_htlc to node {}.\n", idx).as_bytes());
										dest.handle_update_fail_malformed_htlc(&nodes[$node].get_our_node_id(), update_fail_malformed);
									}
									if let Some(msg) = update_fee {
										out.locked_write(format!("Delivering update_fee to node {}.\n", idx).as_bytes());
										dest.handle_update_fee(&nodes[$node].get_our_node_id(), &msg);
									}
									let processed_change = !update_add_htlcs.is_empty() || !update_fulfill_htlcs.is_empty() ||
										!update_fail_htlcs.is_empty() || !update_fail_malformed_htlcs.is_empty();
									if $limit_events != ProcessMessages::AllMessages && processed_change {
										// If we only want to process some messages, don't deliver the CS until later.
										extra_ev = Some(events::MessageSendEvent::UpdateHTLCs { node_id, updates: CommitmentUpdate {
											update_add_htlcs: Vec::new(),
											update_fail_htlcs: Vec::new(),
											update_fulfill_htlcs: Vec::new(),
											update_fail_malformed_htlcs: Vec::new(),
											update_fee: None,
											commitment_signed
										} });
										break;
									}
									out.locked_write(format!("Delivering commitment_signed to node {}.\n", idx).as_bytes());
									dest.handle_commitment_signed(&nodes[$node].get_our_node_id(), &commitment_signed);
									break;
								}
							}
						},
						events::MessageSendEvent::SendRevokeAndACK { ref node_id, ref msg } => {
							for (idx, dest) in nodes.iter().enumerate() {
								if dest.get_our_node_id() == *node_id {
									out.locked_write(format!("Delivering revoke_and_ack to node {}.\n", idx).as_bytes());
									dest.handle_revoke_and_ack(&nodes[$node].get_our_node_id(), msg);
								}
							}
						},
						events::MessageSendEvent::SendChannelReestablish { ref node_id, ref msg } => {
							for (idx, dest) in nodes.iter().enumerate() {
								if dest.get_our_node_id() == *node_id {
									out.locked_write(format!("Delivering channel_reestablish to node {}.\n", idx).as_bytes());
									dest.handle_channel_reestablish(&nodes[$node].get_our_node_id(), msg);
								}
							}
						},
						events::MessageSendEvent::SendChannelReady { .. } => {
							// Can be generated as a reestablish response
						},
						events::MessageSendEvent::SendAnnouncementSignatures { .. } => {
							// Can be generated as a reestablish response
						},
						events::MessageSendEvent::SendChannelUpdate { ref msg, .. } => {
							// When we reconnect we will resend a channel_update to make sure our
							// counterparty has the latest parameters for receiving payments
							// through us. We do, however, check that the message does not include
							// the "disabled" bit, as we should never ever have a channel which is
							// disabled when we send such an update (or it may indicate channel
							// force-close which we should detect as an error).
							assert_eq!(msg.contents.flags & 2, 0);
						},
						_ => if out.may_fail.load(atomic::Ordering::Acquire) {
							return;
						} else {
							panic!("Unhandled message event {:?}", event)
						},
					}
					if $limit_events != ProcessMessages::AllMessages {
						break;
					}
				}
				if $node == 1 {
					push_excess_b_events!(extra_ev.into_iter().chain(events_iter), None);
				} else if $node == 0 {
					if let Some(ev) = extra_ev { ab_events.push(ev); }
					for event in events_iter { ab_events.push(event); }
				} else {
					if let Some(ev) = extra_ev { cb_events.push(ev); }
					for event in events_iter { cb_events.push(event); }
				}
				had_events
			} }
		}

		macro_rules! drain_msg_events_on_disconnect {
			($counterparty_id: expr) => { {
				if $counterparty_id == 0 {
					for event in nodes[0].get_and_clear_pending_msg_events() {
						match event {
							events::MessageSendEvent::UpdateHTLCs { .. } => {},
							events::MessageSendEvent::SendRevokeAndACK { .. } => {},
							events::MessageSendEvent::SendChannelReestablish { .. } => {},
							events::MessageSendEvent::SendChannelReady { .. } => {},
							events::MessageSendEvent::SendAnnouncementSignatures { .. } => {},
							events::MessageSendEvent::SendChannelUpdate { ref msg, .. } => {
								assert_eq!(msg.contents.flags & 2, 0); // The disable bit must never be set!
							},
							_ => if out.may_fail.load(atomic::Ordering::Acquire) {
								return;
							} else {
								panic!("Unhandled message event")
							},
						}
					}
					push_excess_b_events!(nodes[1].get_and_clear_pending_msg_events().drain(..), Some(0));
					ab_events.clear();
					ba_events.clear();
				} else {
					for event in nodes[2].get_and_clear_pending_msg_events() {
						match event {
							events::MessageSendEvent::UpdateHTLCs { .. } => {},
							events::MessageSendEvent::SendRevokeAndACK { .. } => {},
							events::MessageSendEvent::SendChannelReestablish { .. } => {},
							events::MessageSendEvent::SendChannelReady { .. } => {},
							events::MessageSendEvent::SendAnnouncementSignatures { .. } => {},
							events::MessageSendEvent::SendChannelUpdate { ref msg, .. } => {
								assert_eq!(msg.contents.flags & 2, 0); // The disable bit must never be set!
							},
							_ => if out.may_fail.load(atomic::Ordering::Acquire) {
								return;
							} else {
								panic!("Unhandled message event")
							},
						}
					}
					push_excess_b_events!(nodes[1].get_and_clear_pending_msg_events().drain(..), Some(2));
					bc_events.clear();
					cb_events.clear();
				}
			} }
		}

		macro_rules! process_events {
			($node: expr, $fail: expr) => { {
				// In case we get 256 payments we may have a hash collision, resulting in the
				// second claim/fail call not finding the duplicate-hash HTLC, so we have to
				// deduplicate the calls here.
				let mut claim_set = HashSet::new();
				let mut events = nodes[$node].get_and_clear_pending_events();
				// Sort events so that PendingHTLCsForwardable get processed last. This avoids a
				// case where we first process a PendingHTLCsForwardable, then claim/fail on a
				// PaymentClaimable, claiming/failing two HTLCs, but leaving a just-generated
				// PaymentClaimable event for the second HTLC in our pending_events (and breaking
				// our claim_set deduplication).
				events.sort_by(|a, b| {
					if let events::Event::PaymentClaimable { .. } = a {
						if let events::Event::PendingHTLCsForwardable { .. } = b {
							Ordering::Less
						} else { Ordering::Equal }
					} else if let events::Event::PendingHTLCsForwardable { .. } = a {
						if let events::Event::PaymentClaimable { .. } = b {
							Ordering::Greater
						} else { Ordering::Equal }
					} else { Ordering::Equal }
				});
				let had_events = !events.is_empty();
				for event in events.drain(..) {
					match event {
						events::Event::PaymentClaimable { payment_hash, .. } => {
							if claim_set.insert(payment_hash.0) {
								if $fail {
									nodes[$node].fail_htlc_backwards(&payment_hash);
								} else {
									nodes[$node].claim_funds(PaymentPreimage(payment_hash.0));
								}
							}
						},
						events::Event::PaymentSent { .. } => {},
						events::Event::PaymentClaimed { .. } => {},
						events::Event::PaymentPathSuccessful { .. } => {},
						events::Event::PaymentPathFailed { .. } => {},
						events::Event::PaymentFailed { .. } => {},
						events::Event::ProbeSuccessful { .. } | events::Event::ProbeFailed { .. } => {
							// Even though we don't explicitly send probes, because probes are
							// detected based on hashing the payment hash+preimage, its rather
							// trivial for the fuzzer to build payments that accidentally end up
							// looking like probes.
						},
						events::Event::PaymentForwarded { .. } if $node == 1 => {},
						events::Event::ChannelReady { .. } => {},
						events::Event::PendingHTLCsForwardable { .. } => {
							nodes[$node].process_pending_htlc_forwards();
						},
						events::Event::HTLCHandlingFailed { .. } => {},
						_ => if out.may_fail.load(atomic::Ordering::Acquire) {
							return;
						} else {
							panic!("Unhandled event")
						},
					}
				}
				had_events
			} }
		}

		let v = get_slice!(1)[0];
		out.locked_write(format!("READ A BYTE! HANDLING INPUT {:x}...........\n", v).as_bytes());
		match v {
			// In general, we keep related message groups close together in binary form, allowing
			// bit-twiddling mutations to have similar effects. This is probably overkill, but no
			// harm in doing so.

			0x00 => *monitor_a.persister.update_ret.lock().unwrap() = ChannelMonitorUpdateStatus::InProgress,
			0x01 => *monitor_b.persister.update_ret.lock().unwrap() = ChannelMonitorUpdateStatus::InProgress,
			0x02 => *monitor_c.persister.update_ret.lock().unwrap() = ChannelMonitorUpdateStatus::InProgress,
			0x04 => *monitor_a.persister.update_ret.lock().unwrap() = ChannelMonitorUpdateStatus::Completed,
			0x05 => *monitor_b.persister.update_ret.lock().unwrap() = ChannelMonitorUpdateStatus::Completed,
			0x06 => *monitor_c.persister.update_ret.lock().unwrap() = ChannelMonitorUpdateStatus::Completed,

			0x08 => {
				if let Some((id, _)) = monitor_a.latest_monitors.lock().unwrap().get(&chan_1_funding) {
					monitor_a.chain_monitor.force_channel_monitor_updated(chan_1_funding, *id);
					nodes[0].process_monitor_events();
				}
			},
			0x09 => {
				if let Some((id, _)) = monitor_b.latest_monitors.lock().unwrap().get(&chan_1_funding) {
					monitor_b.chain_monitor.force_channel_monitor_updated(chan_1_funding, *id);
					nodes[1].process_monitor_events();
				}
			},
			0x0a => {
				if let Some((id, _)) = monitor_b.latest_monitors.lock().unwrap().get(&chan_2_funding) {
					monitor_b.chain_monitor.force_channel_monitor_updated(chan_2_funding, *id);
					nodes[1].process_monitor_events();
				}
			},
			0x0b => {
				if let Some((id, _)) = monitor_c.latest_monitors.lock().unwrap().get(&chan_2_funding) {
					monitor_c.chain_monitor.force_channel_monitor_updated(chan_2_funding, *id);
					nodes[2].process_monitor_events();
				}
			},

			0x0c => {
				if !chan_a_disconnected {
					nodes[0].peer_disconnected(&nodes[1].get_our_node_id());
					nodes[1].peer_disconnected(&nodes[0].get_our_node_id());
					chan_a_disconnected = true;
					drain_msg_events_on_disconnect!(0);
				}
			},
			0x0d => {
				if !chan_b_disconnected {
					nodes[1].peer_disconnected(&nodes[2].get_our_node_id());
					nodes[2].peer_disconnected(&nodes[1].get_our_node_id());
					chan_b_disconnected = true;
					drain_msg_events_on_disconnect!(2);
				}
			},
			0x0e => {
				if chan_a_disconnected {
					nodes[0].peer_connected(&nodes[1].get_our_node_id(), &Init { features: nodes[1].init_features(), remote_network_address: None }, true).unwrap();
					nodes[1].peer_connected(&nodes[0].get_our_node_id(), &Init { features: nodes[0].init_features(), remote_network_address: None }, false).unwrap();
					chan_a_disconnected = false;
				}
			},
			0x0f => {
				if chan_b_disconnected {
					nodes[1].peer_connected(&nodes[2].get_our_node_id(), &Init { features: nodes[2].init_features(), remote_network_address: None }, true).unwrap();
					nodes[2].peer_connected(&nodes[1].get_our_node_id(), &Init { features: nodes[1].init_features(), remote_network_address: None }, false).unwrap();
					chan_b_disconnected = false;
				}
			},

			0x10 => { process_msg_events!(0, true, ProcessMessages::AllMessages); },
			0x11 => { process_msg_events!(0, false, ProcessMessages::AllMessages); },
			0x12 => { process_msg_events!(0, true, ProcessMessages::OneMessage); },
			0x13 => { process_msg_events!(0, false, ProcessMessages::OneMessage); },
			0x14 => { process_msg_events!(0, true, ProcessMessages::OnePendingMessage); },
			0x15 => { process_msg_events!(0, false, ProcessMessages::OnePendingMessage); },

			0x16 => { process_events!(0, true); },
			0x17 => { process_events!(0, false); },

			0x18 => { process_msg_events!(1, true, ProcessMessages::AllMessages); },
			0x19 => { process_msg_events!(1, false, ProcessMessages::AllMessages); },
			0x1a => { process_msg_events!(1, true, ProcessMessages::OneMessage); },
			0x1b => { process_msg_events!(1, false, ProcessMessages::OneMessage); },
			0x1c => { process_msg_events!(1, true, ProcessMessages::OnePendingMessage); },
			0x1d => { process_msg_events!(1, false, ProcessMessages::OnePendingMessage); },

			0x1e => { process_events!(1, true); },
			0x1f => { process_events!(1, false); },

			0x20 => { process_msg_events!(2, true, ProcessMessages::AllMessages); },
			0x21 => { process_msg_events!(2, false, ProcessMessages::AllMessages); },
			0x22 => { process_msg_events!(2, true, ProcessMessages::OneMessage); },
			0x23 => { process_msg_events!(2, false, ProcessMessages::OneMessage); },
			0x24 => { process_msg_events!(2, true, ProcessMessages::OnePendingMessage); },
			0x25 => { process_msg_events!(2, false, ProcessMessages::OnePendingMessage); },

			0x26 => { process_events!(2, true); },
			0x27 => { process_events!(2, false); },

			0x2c => {
				if !chan_a_disconnected {
					nodes[1].peer_disconnected(&nodes[0].get_our_node_id());
					chan_a_disconnected = true;
					drain_msg_events_on_disconnect!(0);
				}
				if monitor_a.should_update_manager.load(atomic::Ordering::Relaxed) {
					node_a_ser.0.clear();
					nodes[0].write(&mut node_a_ser).unwrap();
				}
				let (new_node_a, new_monitor_a) = reload_node!(node_a_ser, 0, monitor_a, keys_manager_a, fee_est_a);
				nodes[0] = new_node_a;
				monitor_a = new_monitor_a;
			},
			0x2d => {
				if !chan_a_disconnected {
					nodes[0].peer_disconnected(&nodes[1].get_our_node_id());
					chan_a_disconnected = true;
					nodes[0].get_and_clear_pending_msg_events();
					ab_events.clear();
					ba_events.clear();
				}
				if !chan_b_disconnected {
					nodes[2].peer_disconnected(&nodes[1].get_our_node_id());
					chan_b_disconnected = true;
					nodes[2].get_and_clear_pending_msg_events();
					bc_events.clear();
					cb_events.clear();
				}
				let (new_node_b, new_monitor_b) = reload_node!(node_b_ser, 1, monitor_b, keys_manager_b, fee_est_b);
				nodes[1] = new_node_b;
				monitor_b = new_monitor_b;
			},
			0x2e => {
				if !chan_b_disconnected {
					nodes[1].peer_disconnected(&nodes[2].get_our_node_id());
					chan_b_disconnected = true;
					drain_msg_events_on_disconnect!(2);
				}
				if monitor_c.should_update_manager.load(atomic::Ordering::Relaxed) {
					node_c_ser.0.clear();
					nodes[2].write(&mut node_c_ser).unwrap();
				}
				let (new_node_c, new_monitor_c) = reload_node!(node_c_ser, 2, monitor_c, keys_manager_c, fee_est_c);
				nodes[2] = new_node_c;
				monitor_c = new_monitor_c;
			},

			// 1/10th the channel size:
			0x30 => { send_payment(&nodes[0], &nodes[1], chan_a, 10_000_000, &mut payment_id, &mut payment_idx); },
			0x31 => { send_payment(&nodes[1], &nodes[0], chan_a, 10_000_000, &mut payment_id, &mut payment_idx); },
			0x32 => { send_payment(&nodes[1], &nodes[2], chan_b, 10_000_000, &mut payment_id, &mut payment_idx); },
			0x33 => { send_payment(&nodes[2], &nodes[1], chan_b, 10_000_000, &mut payment_id, &mut payment_idx); },
			0x34 => { send_hop_payment(&nodes[0], &nodes[1], chan_a, &nodes[2], chan_b, 10_000_000, &mut payment_id, &mut payment_idx); },
			0x35 => { send_hop_payment(&nodes[2], &nodes[1], chan_b, &nodes[0], chan_a, 10_000_000, &mut payment_id, &mut payment_idx); },

			0x38 => { send_payment(&nodes[0], &nodes[1], chan_a, 1_000_000, &mut payment_id, &mut payment_idx); },
			0x39 => { send_payment(&nodes[1], &nodes[0], chan_a, 1_000_000, &mut payment_id, &mut payment_idx); },
			0x3a => { send_payment(&nodes[1], &nodes[2], chan_b, 1_000_000, &mut payment_id, &mut payment_idx); },
			0x3b => { send_payment(&nodes[2], &nodes[1], chan_b, 1_000_000, &mut payment_id, &mut payment_idx); },
			0x3c => { send_hop_payment(&nodes[0], &nodes[1], chan_a, &nodes[2], chan_b, 1_000_000, &mut payment_id, &mut payment_idx); },
			0x3d => { send_hop_payment(&nodes[2], &nodes[1], chan_b, &nodes[0], chan_a, 1_000_000, &mut payment_id, &mut payment_idx); },

			0x40 => { send_payment(&nodes[0], &nodes[1], chan_a, 100_000, &mut payment_id, &mut payment_idx); },
			0x41 => { send_payment(&nodes[1], &nodes[0], chan_a, 100_000, &mut payment_id, &mut payment_idx); },
			0x42 => { send_payment(&nodes[1], &nodes[2], chan_b, 100_000, &mut payment_id, &mut payment_idx); },
			0x43 => { send_payment(&nodes[2], &nodes[1], chan_b, 100_000, &mut payment_id, &mut payment_idx); },
			0x44 => { send_hop_payment(&nodes[0], &nodes[1], chan_a, &nodes[2], chan_b, 100_000, &mut payment_id, &mut payment_idx); },
			0x45 => { send_hop_payment(&nodes[2], &nodes[1], chan_b, &nodes[0], chan_a, 100_000, &mut payment_id, &mut payment_idx); },

			0x48 => { send_payment(&nodes[0], &nodes[1], chan_a, 10_000, &mut payment_id, &mut payment_idx); },
			0x49 => { send_payment(&nodes[1], &nodes[0], chan_a, 10_000, &mut payment_id, &mut payment_idx); },
			0x4a => { send_payment(&nodes[1], &nodes[2], chan_b, 10_000, &mut payment_id, &mut payment_idx); },
			0x4b => { send_payment(&nodes[2], &nodes[1], chan_b, 10_000, &mut payment_id, &mut payment_idx); },
			0x4c => { send_hop_payment(&nodes[0], &nodes[1], chan_a, &nodes[2], chan_b, 10_000, &mut payment_id, &mut payment_idx); },
			0x4d => { send_hop_payment(&nodes[2], &nodes[1], chan_b, &nodes[0], chan_a, 10_000, &mut payment_id, &mut payment_idx); },

			0x50 => { send_payment(&nodes[0], &nodes[1], chan_a, 1_000, &mut payment_id, &mut payment_idx); },
			0x51 => { send_payment(&nodes[1], &nodes[0], chan_a, 1_000, &mut payment_id, &mut payment_idx); },
			0x52 => { send_payment(&nodes[1], &nodes[2], chan_b, 1_000, &mut payment_id, &mut payment_idx); },
			0x53 => { send_payment(&nodes[2], &nodes[1], chan_b, 1_000, &mut payment_id, &mut payment_idx); },
			0x54 => { send_hop_payment(&nodes[0], &nodes[1], chan_a, &nodes[2], chan_b, 1_000, &mut payment_id, &mut payment_idx); },
			0x55 => { send_hop_payment(&nodes[2], &nodes[1], chan_b, &nodes[0], chan_a, 1_000, &mut payment_id, &mut payment_idx); },

			0x58 => { send_payment(&nodes[0], &nodes[1], chan_a, 100, &mut payment_id, &mut payment_idx); },
			0x59 => { send_payment(&nodes[1], &nodes[0], chan_a, 100, &mut payment_id, &mut payment_idx); },
			0x5a => { send_payment(&nodes[1], &nodes[2], chan_b, 100, &mut payment_id, &mut payment_idx); },
			0x5b => { send_payment(&nodes[2], &nodes[1], chan_b, 100, &mut payment_id, &mut payment_idx); },
			0x5c => { send_hop_payment(&nodes[0], &nodes[1], chan_a, &nodes[2], chan_b, 100, &mut payment_id, &mut payment_idx); },
			0x5d => { send_hop_payment(&nodes[2], &nodes[1], chan_b, &nodes[0], chan_a, 100, &mut payment_id, &mut payment_idx); },

			0x60 => { send_payment(&nodes[0], &nodes[1], chan_a, 10, &mut payment_id, &mut payment_idx); },
			0x61 => { send_payment(&nodes[1], &nodes[0], chan_a, 10, &mut payment_id, &mut payment_idx); },
			0x62 => { send_payment(&nodes[1], &nodes[2], chan_b, 10, &mut payment_id, &mut payment_idx); },
			0x63 => { send_payment(&nodes[2], &nodes[1], chan_b, 10, &mut payment_id, &mut payment_idx); },
			0x64 => { send_hop_payment(&nodes[0], &nodes[1], chan_a, &nodes[2], chan_b, 10, &mut payment_id, &mut payment_idx); },
			0x65 => { send_hop_payment(&nodes[2], &nodes[1], chan_b, &nodes[0], chan_a, 10, &mut payment_id, &mut payment_idx); },

			0x68 => { send_payment(&nodes[0], &nodes[1], chan_a, 1, &mut payment_id, &mut payment_idx); },
			0x69 => { send_payment(&nodes[1], &nodes[0], chan_a, 1, &mut payment_id, &mut payment_idx); },
			0x6a => { send_payment(&nodes[1], &nodes[2], chan_b, 1, &mut payment_id, &mut payment_idx); },
			0x6b => { send_payment(&nodes[2], &nodes[1], chan_b, 1, &mut payment_id, &mut payment_idx); },
			0x6c => { send_hop_payment(&nodes[0], &nodes[1], chan_a, &nodes[2], chan_b, 1, &mut payment_id, &mut payment_idx); },
			0x6d => { send_hop_payment(&nodes[2], &nodes[1], chan_b, &nodes[0], chan_a, 1, &mut payment_id, &mut payment_idx); },

			0x80 => {
				let max_feerate = last_htlc_clear_fee_a * FEE_SPIKE_BUFFER_FEE_INCREASE_MULTIPLE as u32;
				if fee_est_a.ret_val.fetch_add(250, atomic::Ordering::AcqRel) + 250 > max_feerate {
					fee_est_a.ret_val.store(max_feerate, atomic::Ordering::Release);
				}
				nodes[0].maybe_update_chan_fees();
			},
			0x81 => { fee_est_a.ret_val.store(253, atomic::Ordering::Release); nodes[0].maybe_update_chan_fees(); },

			0x84 => {
				let max_feerate = last_htlc_clear_fee_b * FEE_SPIKE_BUFFER_FEE_INCREASE_MULTIPLE as u32;
				if fee_est_b.ret_val.fetch_add(250, atomic::Ordering::AcqRel) + 250 > max_feerate {
					fee_est_b.ret_val.store(max_feerate, atomic::Ordering::Release);
				}
				nodes[1].maybe_update_chan_fees();
			},
			0x85 => { fee_est_b.ret_val.store(253, atomic::Ordering::Release); nodes[1].maybe_update_chan_fees(); },

			0x88 => {
				let max_feerate = last_htlc_clear_fee_c * FEE_SPIKE_BUFFER_FEE_INCREASE_MULTIPLE as u32;
				if fee_est_c.ret_val.fetch_add(250, atomic::Ordering::AcqRel) + 250 > max_feerate {
					fee_est_c.ret_val.store(max_feerate, atomic::Ordering::Release);
				}
				nodes[2].maybe_update_chan_fees();
			},
			0x89 => { fee_est_c.ret_val.store(253, atomic::Ordering::Release); nodes[2].maybe_update_chan_fees(); },

			0xff => {
				// Test that no channel is in a stuck state where neither party can send funds even
				// after we resolve all pending events.
				// First make sure there are no pending monitor updates, resetting the error state
				// and calling force_channel_monitor_updated for each monitor.
				*monitor_a.persister.update_ret.lock().unwrap() = ChannelMonitorUpdateStatus::Completed;
				*monitor_b.persister.update_ret.lock().unwrap() = ChannelMonitorUpdateStatus::Completed;
				*monitor_c.persister.update_ret.lock().unwrap() = ChannelMonitorUpdateStatus::Completed;

				if let Some((id, _)) = monitor_a.latest_monitors.lock().unwrap().get(&chan_1_funding) {
					monitor_a.chain_monitor.force_channel_monitor_updated(chan_1_funding, *id);
					nodes[0].process_monitor_events();
				}
				if let Some((id, _)) = monitor_b.latest_monitors.lock().unwrap().get(&chan_1_funding) {
					monitor_b.chain_monitor.force_channel_monitor_updated(chan_1_funding, *id);
					nodes[1].process_monitor_events();
				}
				if let Some((id, _)) = monitor_b.latest_monitors.lock().unwrap().get(&chan_2_funding) {
					monitor_b.chain_monitor.force_channel_monitor_updated(chan_2_funding, *id);
					nodes[1].process_monitor_events();
				}
				if let Some((id, _)) = monitor_c.latest_monitors.lock().unwrap().get(&chan_2_funding) {
					monitor_c.chain_monitor.force_channel_monitor_updated(chan_2_funding, *id);
					nodes[2].process_monitor_events();
				}

				// Next, make sure peers are all connected to each other
				if chan_a_disconnected {
					nodes[0].peer_connected(&nodes[1].get_our_node_id(), &Init { features: nodes[1].init_features(), remote_network_address: None }, true).unwrap();
					nodes[1].peer_connected(&nodes[0].get_our_node_id(), &Init { features: nodes[0].init_features(), remote_network_address: None }, false).unwrap();
					chan_a_disconnected = false;
				}
				if chan_b_disconnected {
					nodes[1].peer_connected(&nodes[2].get_our_node_id(), &Init { features: nodes[2].init_features(), remote_network_address: None }, true).unwrap();
					nodes[2].peer_connected(&nodes[1].get_our_node_id(), &Init { features: nodes[1].init_features(), remote_network_address: None }, false).unwrap();
					chan_b_disconnected = false;
				}

				for i in 0..std::usize::MAX {
					if i == 100 { panic!("It may take may iterations to settle the state, but it should not take forever"); }
					// Then, make sure any current forwards make their way to their destination
					if process_msg_events!(0, false, ProcessMessages::AllMessages) { continue; }
					if process_msg_events!(1, false, ProcessMessages::AllMessages) { continue; }
					if process_msg_events!(2, false, ProcessMessages::AllMessages) { continue; }
					// ...making sure any pending PendingHTLCsForwardable events are handled and
					// payments claimed.
					if process_events!(0, false) { continue; }
					if process_events!(1, false) { continue; }
					if process_events!(2, false) { continue; }
					break;
				}

				// Finally, make sure that at least one end of each channel can make a substantial payment
				assert!(
					send_payment(&nodes[0], &nodes[1], chan_a, 10_000_000, &mut payment_id, &mut payment_idx) ||
					send_payment(&nodes[1], &nodes[0], chan_a, 10_000_000, &mut payment_id, &mut payment_idx));
				assert!(
					send_payment(&nodes[1], &nodes[2], chan_b, 10_000_000, &mut payment_id, &mut payment_idx) ||
					send_payment(&nodes[2], &nodes[1], chan_b, 10_000_000, &mut payment_id, &mut payment_idx));

				last_htlc_clear_fee_a = fee_est_a.ret_val.load(atomic::Ordering::Acquire);
				last_htlc_clear_fee_b = fee_est_b.ret_val.load(atomic::Ordering::Acquire);
				last_htlc_clear_fee_c = fee_est_c.ret_val.load(atomic::Ordering::Acquire);
			},
			_ => test_return!(),
		}

		node_a_ser.0.clear();
		nodes[0].write(&mut node_a_ser).unwrap();
		monitor_a.should_update_manager.store(false, atomic::Ordering::Relaxed);
		node_b_ser.0.clear();
		nodes[1].write(&mut node_b_ser).unwrap();
		monitor_b.should_update_manager.store(false, atomic::Ordering::Relaxed);
		node_c_ser.0.clear();
		nodes[2].write(&mut node_c_ser).unwrap();
		monitor_c.should_update_manager.store(false, atomic::Ordering::Relaxed);
	}
}

/// We actually have different behavior based on if a certain log string has been seen, so we have
/// to do a bit more tracking.
#[derive(Clone)]
struct SearchingOutput<O: Output> {
	output: O,
	may_fail: Arc<atomic::AtomicBool>,
}
impl<O: Output> Output for SearchingOutput<O> {
	fn locked_write(&self, data: &[u8]) {
		// We hit a design limitation of LN state machine (see CONCURRENT_INBOUND_HTLC_FEE_BUFFER)
		if std::str::from_utf8(data).unwrap().contains("Outbound update_fee HTLC buffer overflow - counterparty should force-close this channel") {
			self.may_fail.store(true, atomic::Ordering::Release);
		}
		self.output.locked_write(data)
	}
}
impl<O: Output> SearchingOutput<O> {
	pub fn new(output: O) -> Self {
		Self { output, may_fail: Arc::new(atomic::AtomicBool::new(false)) }
	}
}

pub fn chanmon_consistency_test<Out: Output>(data: &[u8], out: Out) {
	do_test(data, out);
}

#[no_mangle]
pub extern "C" fn chanmon_consistency_run(data: *const u8, datalen: usize) {
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) }, test_logger::DevNull{});
}
