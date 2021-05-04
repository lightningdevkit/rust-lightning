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

use bitcoin::blockdata::block::BlockHeader;
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::blockdata::transaction::{Transaction, TxOut};
use bitcoin::blockdata::script::{Builder, Script};
use bitcoin::blockdata::opcodes;
use bitcoin::network::constants::Network;

use bitcoin::hashes::Hash as TraitImport;
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hash_types::{BlockHash, WPubkeyHash};

use lightning::chain;
use lightning::chain::Confirm;
use lightning::chain::chainmonitor;
use lightning::chain::channelmonitor;
use lightning::chain::channelmonitor::{ChannelMonitor, ChannelMonitorUpdateErr, MonitorEvent};
use lightning::chain::transaction::OutPoint;
use lightning::chain::chaininterface::{BroadcasterInterface, ConfirmationTarget, FeeEstimator};
use lightning::chain::keysinterface::{KeysInterface, InMemorySigner};
use lightning::ln::{PaymentHash, PaymentPreimage, PaymentSecret};
use lightning::ln::channelmanager::{BestBlock, ChainParameters, ChannelManager, PaymentSendFailure, ChannelManagerReadArgs};
use lightning::ln::features::{ChannelFeatures, InitFeatures, NodeFeatures};
use lightning::ln::msgs::{CommitmentUpdate, ChannelMessageHandler, DecodeError, ErrorAction, UpdateAddHTLC, Init};
use lightning::util::enforcing_trait_impls::{EnforcingSigner, INITIAL_REVOKED_COMMITMENT_NUMBER};
use lightning::util::errors::APIError;
use lightning::util::events;
use lightning::util::logger::Logger;
use lightning::util::config::UserConfig;
use lightning::util::events::{EventsProvider, MessageSendEventsProvider};
use lightning::util::ser::{Readable, ReadableArgs, Writeable, Writer};
use lightning::util::test_utils::OnlyReadsKeysInterface;
use lightning::routing::router::{Route, RouteHop};


use utils::test_logger;
use utils::test_persister::TestPersister;

use bitcoin::secp256k1::key::{PublicKey,SecretKey};
use bitcoin::secp256k1::recovery::RecoverableSignature;
use bitcoin::secp256k1::Secp256k1;

use std::mem;
use std::cmp::Ordering;
use std::collections::{HashSet, hash_map, HashMap};
use std::sync::{Arc,Mutex};
use std::sync::atomic;
use std::io::Cursor;

struct FuzzEstimator {}
impl FeeEstimator for FuzzEstimator {
	fn get_est_sat_per_1000_weight(&self, _: ConfirmationTarget) -> u32 {
		253
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
	fn size_hint(&mut self, size: usize) {
		self.0.reserve_exact(size);
	}
}

struct TestChainMonitor {
	pub logger: Arc<dyn Logger>,
	pub chain_monitor: Arc<chainmonitor::ChainMonitor<EnforcingSigner, Arc<dyn chain::Filter>, Arc<TestBroadcaster>, Arc<FuzzEstimator>, Arc<dyn Logger>, Arc<TestPersister>>>,
	pub update_ret: Mutex<Result<(), channelmonitor::ChannelMonitorUpdateErr>>,
	// If we reload a node with an old copy of ChannelMonitors, the ChannelManager deserialization
	// logic will automatically force-close our channels for us (as we don't have an up-to-date
	// monitor implying we are not able to punish misbehaving counterparties). Because this test
	// "fails" if we ever force-close a channel, we avoid doing so, always saving the latest
	// fully-serialized monitor state here, as well as the corresponding update_id.
	pub latest_monitors: Mutex<HashMap<OutPoint, (u64, Vec<u8>)>>,
	pub should_update_manager: atomic::AtomicBool,
}
impl TestChainMonitor {
	pub fn new(broadcaster: Arc<TestBroadcaster>, logger: Arc<dyn Logger>, feeest: Arc<FuzzEstimator>, persister: Arc<TestPersister>) -> Self {
		Self {
			chain_monitor: Arc::new(chainmonitor::ChainMonitor::new(None, broadcaster, logger.clone(), feeest, persister)),
			logger,
			update_ret: Mutex::new(Ok(())),
			latest_monitors: Mutex::new(HashMap::new()),
			should_update_manager: atomic::AtomicBool::new(false),
		}
	}
}
impl chain::Watch<EnforcingSigner> for TestChainMonitor {
	fn watch_channel(&self, funding_txo: OutPoint, monitor: channelmonitor::ChannelMonitor<EnforcingSigner>) -> Result<(), channelmonitor::ChannelMonitorUpdateErr> {
		let mut ser = VecWriter(Vec::new());
		monitor.write(&mut ser).unwrap();
		if let Some(_) = self.latest_monitors.lock().unwrap().insert(funding_txo, (monitor.get_latest_update_id(), ser.0)) {
			panic!("Already had monitor pre-watch_channel");
		}
		self.should_update_manager.store(true, atomic::Ordering::Relaxed);
		assert!(self.chain_monitor.watch_channel(funding_txo, monitor).is_ok());
		self.update_ret.lock().unwrap().clone()
	}

	fn update_channel(&self, funding_txo: OutPoint, update: channelmonitor::ChannelMonitorUpdate) -> Result<(), channelmonitor::ChannelMonitorUpdateErr> {
		let mut map_lock = self.latest_monitors.lock().unwrap();
		let mut map_entry = match map_lock.entry(funding_txo) {
			hash_map::Entry::Occupied(entry) => entry,
			hash_map::Entry::Vacant(_) => panic!("Didn't have monitor on update call"),
		};
		let deserialized_monitor = <(BlockHash, channelmonitor::ChannelMonitor<EnforcingSigner>)>::
			read(&mut Cursor::new(&map_entry.get().1), &OnlyReadsKeysInterface {}).unwrap().1;
		deserialized_monitor.update_monitor(&update, &&TestBroadcaster{}, &&FuzzEstimator{}, &self.logger).unwrap();
		let mut ser = VecWriter(Vec::new());
		deserialized_monitor.write(&mut ser).unwrap();
		map_entry.insert((update.update_id, ser.0));
		self.should_update_manager.store(true, atomic::Ordering::Relaxed);
		self.update_ret.lock().unwrap().clone()
	}

	fn release_pending_monitor_events(&self) -> Vec<MonitorEvent> {
		return self.chain_monitor.release_pending_monitor_events();
	}
}

struct KeyProvider {
	node_id: u8,
	rand_bytes_id: atomic::AtomicU8,
	revoked_commitments: Mutex<HashMap<[u8;32], Arc<Mutex<u64>>>>,
}
impl KeysInterface for KeyProvider {
	type Signer = EnforcingSigner;

	fn get_node_secret(&self) -> SecretKey {
		SecretKey::from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, self.node_id]).unwrap()
	}

	fn get_destination_script(&self) -> Script {
		let secp_ctx = Secp256k1::signing_only();
		let channel_monitor_claim_key = SecretKey::from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, self.node_id]).unwrap();
		let our_channel_monitor_claim_key_hash = WPubkeyHash::hash(&PublicKey::from_secret_key(&secp_ctx, &channel_monitor_claim_key).serialize());
		Builder::new().push_opcode(opcodes::all::OP_PUSHBYTES_0).push_slice(&our_channel_monitor_claim_key_hash[..]).into_script()
	}

	fn get_shutdown_pubkey(&self) -> PublicKey {
		let secp_ctx = Secp256k1::signing_only();
		PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, self.node_id]).unwrap())
	}

	fn get_channel_signer(&self, _inbound: bool, channel_value_satoshis: u64) -> EnforcingSigner {
		let secp_ctx = Secp256k1::signing_only();
		let id = self.rand_bytes_id.fetch_add(1, atomic::Ordering::Relaxed);
		let keys = InMemorySigner::new(
			&secp_ctx,
			SecretKey::from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, self.node_id]).unwrap(),
			SecretKey::from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, self.node_id]).unwrap(),
			SecretKey::from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6, self.node_id]).unwrap(),
			SecretKey::from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, self.node_id]).unwrap(),
			SecretKey::from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, self.node_id]).unwrap(),
			[id, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9, self.node_id],
			channel_value_satoshis,
			[0; 32],
		);
		let revoked_commitment = self.make_revoked_commitment_cell(keys.commitment_seed);
		EnforcingSigner::new_with_revoked(keys, revoked_commitment, false)
	}

	fn get_secure_random_bytes(&self) -> [u8; 32] {
		let id = self.rand_bytes_id.fetch_add(1, atomic::Ordering::Relaxed);
		[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, id, 11, self.node_id]
	}

	fn read_chan_signer(&self, buffer: &[u8]) -> Result<Self::Signer, DecodeError> {
		let mut reader = std::io::Cursor::new(buffer);

		let inner: InMemorySigner = Readable::read(&mut reader)?;
		let revoked_commitment = self.make_revoked_commitment_cell(inner.commitment_seed);

		let last_commitment_number = Readable::read(&mut reader)?;

		Ok(EnforcingSigner {
			inner,
			last_commitment_number: Arc::new(Mutex::new(last_commitment_number)),
			revoked_commitment,
			disable_revocation_policy_check: false,
		})
	}

	fn sign_invoice(&self, _invoice_preimage: Vec<u8>) -> Result<RecoverableSignature, ()> {
		unreachable!()
	}
}

impl KeyProvider {
	fn make_revoked_commitment_cell(&self, commitment_seed: [u8; 32]) -> Arc<Mutex<u64>> {
		let mut revoked_commitments = self.revoked_commitments.lock().unwrap();
		if !revoked_commitments.contains_key(&commitment_seed) {
			revoked_commitments.insert(commitment_seed, Arc::new(Mutex::new(INITIAL_REVOKED_COMMITMENT_NUMBER)));
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
		APIError::RouteError { .. } => panic!("Our routes should work"),
		APIError::ChannelUnavailable { err } => {
			// Test the error against a list of errors we can hit, and reject
			// all others. If you hit this panic, the list of acceptable errors
			// is probably just stale and you should add new messages here.
			match err.as_str() {
				"Peer for first hop currently disconnected/pending monitor update!" => {},
				_ if err.starts_with("Cannot push more than their max accepted HTLCs ") => {},
				_ if err.starts_with("Cannot send value that would put us over the max HTLC value in flight our peer will accept ") => {},
				_ if err.starts_with("Cannot send value that would put our balance under counterparty-announced channel reserve value") => {},
				_ if err.starts_with("Cannot send value that would overdraw remaining funds.") => {},
				_ if err.starts_with("Cannot send value that would not leave enough to pay for fees.") => {},
				_ => panic!("{}", err),
			}
		},
		APIError::MonitorUpdateFailed => {
			// We can (obviously) temp-fail a monitor update
		},
	}
}
#[inline]
fn check_payment_err(send_err: PaymentSendFailure) {
	match send_err {
		PaymentSendFailure::ParameterError(api_err) => check_api_err(api_err),
		PaymentSendFailure::PathParameterError(per_path_results) => {
			for res in per_path_results { if let Err(api_err) = res { check_api_err(api_err); } }
		},
		PaymentSendFailure::AllFailedRetrySafe(per_path_results) => {
			for api_err in per_path_results { check_api_err(api_err); }
		},
		PaymentSendFailure::PartialFailure(per_path_results) => {
			for res in per_path_results { if let Err(api_err) = res { check_api_err(api_err); } }
		},
	}
}

type ChanMan = ChannelManager<EnforcingSigner, Arc<TestChainMonitor>, Arc<TestBroadcaster>, Arc<KeyProvider>, Arc<FuzzEstimator>, Arc<dyn Logger>>;

#[inline]
fn get_payment_secret_hash(dest: &ChanMan, payment_id: &mut u8) -> Option<(PaymentSecret, PaymentHash)> {
	let mut payment_hash;
	for _ in 0..256 {
		payment_hash = PaymentHash(Sha256::hash(&[*payment_id; 1]).into_inner());
		if let Ok(payment_secret) = dest.create_inbound_payment_for_hash(payment_hash, None, 7200, 0) {
			return Some((payment_secret, payment_hash));
		}
		*payment_id = payment_id.wrapping_add(1);
	}
	None
}

#[inline]
fn send_payment(source: &ChanMan, dest: &ChanMan, dest_chan_id: u64, amt: u64, payment_id: &mut u8) -> bool {
	let (payment_secret, payment_hash) =
		if let Some((secret, hash)) = get_payment_secret_hash(dest, payment_id) { (secret, hash) } else { return true; };
	if let Err(err) = source.send_payment(&Route {
		paths: vec![vec![RouteHop {
			pubkey: dest.get_our_node_id(),
			node_features: NodeFeatures::known(),
			short_channel_id: dest_chan_id,
			channel_features: ChannelFeatures::known(),
			fee_msat: amt,
			cltv_expiry_delta: 200,
		}]],
	}, payment_hash, &Some(payment_secret)) {
		check_payment_err(err);
		false
	} else { true }
}
#[inline]
fn send_hop_payment(source: &ChanMan, middle: &ChanMan, middle_chan_id: u64, dest: &ChanMan, dest_chan_id: u64, amt: u64, payment_id: &mut u8) -> bool {
	let (payment_secret, payment_hash) =
		if let Some((secret, hash)) = get_payment_secret_hash(dest, payment_id) { (secret, hash) } else { return true; };
	if let Err(err) = source.send_payment(&Route {
		paths: vec![vec![RouteHop {
			pubkey: middle.get_our_node_id(),
			node_features: NodeFeatures::known(),
			short_channel_id: middle_chan_id,
			channel_features: ChannelFeatures::known(),
			fee_msat: 50000,
			cltv_expiry_delta: 100,
		},RouteHop {
			pubkey: dest.get_our_node_id(),
			node_features: NodeFeatures::known(),
			short_channel_id: dest_chan_id,
			channel_features: ChannelFeatures::known(),
			fee_msat: amt,
			cltv_expiry_delta: 200,
		}]],
	}, payment_hash, &Some(payment_secret)) {
		check_payment_err(err);
		false
	} else { true }
}

#[inline]
pub fn do_test<Out: test_logger::Output>(data: &[u8], out: Out) {
	let fee_est = Arc::new(FuzzEstimator{});
	let broadcast = Arc::new(TestBroadcaster{});

	macro_rules! make_node {
		($node_id: expr) => { {
			let logger: Arc<dyn Logger> = Arc::new(test_logger::TestLogger::new($node_id.to_string(), out.clone()));
			let monitor = Arc::new(TestChainMonitor::new(broadcast.clone(), logger.clone(), fee_est.clone(), Arc::new(TestPersister{})));

			let keys_manager = Arc::new(KeyProvider { node_id: $node_id, rand_bytes_id: atomic::AtomicU8::new(0), revoked_commitments: Mutex::new(HashMap::new()) });
			let mut config = UserConfig::default();
			config.channel_options.fee_proportional_millionths = 0;
			config.channel_options.announced_channel = true;
			let network = Network::Bitcoin;
			let params = ChainParameters {
				network,
				best_block: BestBlock::from_genesis(network),
			};
			(ChannelManager::new(fee_est.clone(), monitor.clone(), broadcast.clone(), Arc::clone(&logger), keys_manager.clone(), config, params),
			monitor, keys_manager)
		} }
	}

	macro_rules! reload_node {
		($ser: expr, $node_id: expr, $old_monitors: expr, $keys_manager: expr) => { {
		    let keys_manager = Arc::clone(& $keys_manager);
			let logger: Arc<dyn Logger> = Arc::new(test_logger::TestLogger::new($node_id.to_string(), out.clone()));
			let chain_monitor = Arc::new(TestChainMonitor::new(broadcast.clone(), logger.clone(), fee_est.clone(), Arc::new(TestPersister{})));

			let mut config = UserConfig::default();
			config.channel_options.fee_proportional_millionths = 0;
			config.channel_options.announced_channel = true;

			let mut monitors = HashMap::new();
			let mut old_monitors = $old_monitors.latest_monitors.lock().unwrap();
			for (outpoint, (update_id, monitor_ser)) in old_monitors.drain() {
				monitors.insert(outpoint, <(BlockHash, ChannelMonitor<EnforcingSigner>)>::read(&mut Cursor::new(&monitor_ser), &OnlyReadsKeysInterface {}).expect("Failed to read monitor").1);
				chain_monitor.latest_monitors.lock().unwrap().insert(outpoint, (update_id, monitor_ser));
			}
			let mut monitor_refs = HashMap::new();
			for (outpoint, monitor) in monitors.iter_mut() {
				monitor_refs.insert(*outpoint, monitor);
			}

			let read_args = ChannelManagerReadArgs {
				keys_manager,
				fee_estimator: fee_est.clone(),
				chain_monitor: chain_monitor.clone(),
				tx_broadcaster: broadcast.clone(),
				logger,
				default_config: config,
				channel_monitors: monitor_refs,
			};

			(<(BlockHash, ChanMan)>::read(&mut Cursor::new(&$ser.0), read_args).expect("Failed to read manager").1, chain_monitor)
		} }
	}

	let mut channel_txn = Vec::new();
	macro_rules! make_channel {
		($source: expr, $dest: expr, $chan_id: expr) => { {
			$source.create_channel($dest.get_our_node_id(), 100_000, 42, 0, None).unwrap();
			let open_channel = {
				let events = $source.get_and_clear_pending_msg_events();
				assert_eq!(events.len(), 1);
				if let events::MessageSendEvent::SendOpenChannel { ref msg, .. } = events[0] {
					msg.clone()
				} else { panic!("Wrong event type"); }
			};

			$dest.handle_open_channel(&$source.get_our_node_id(), InitFeatures::known(), &open_channel);
			let accept_channel = {
				let events = $dest.get_and_clear_pending_msg_events();
				assert_eq!(events.len(), 1);
				if let events::MessageSendEvent::SendAcceptChannel { ref msg, .. } = events[0] {
					msg.clone()
				} else { panic!("Wrong event type"); }
			};

			$source.handle_accept_channel(&$dest.get_our_node_id(), InitFeatures::known(), &accept_channel);
			let funding_output;
			{
				let events = $source.get_and_clear_pending_events();
				assert_eq!(events.len(), 1);
				if let events::Event::FundingGenerationReady { ref temporary_channel_id, ref channel_value_satoshis, ref output_script, .. } = events[0] {
					let tx = Transaction { version: $chan_id, lock_time: 0, input: Vec::new(), output: vec![TxOut {
						value: *channel_value_satoshis, script_pubkey: output_script.clone(),
					}]};
					funding_output = OutPoint { txid: tx.txid(), index: 0 };
					$source.funding_transaction_generated(&temporary_channel_id, tx.clone()).unwrap();
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
			let mut header = BlockHeader { version: 0x20000000, prev_blockhash: chain_hash, merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
			let txdata: Vec<_> = channel_txn.iter().enumerate().map(|(i, tx)| (i + 1, tx)).collect();
			$node.transactions_confirmed(&header, &txdata, 1);
			for _ in 2..100 {
				header = BlockHeader { version: 0x20000000, prev_blockhash: header.block_hash(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
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
					if let events::MessageSendEvent::SendFundingLocked { ref node_id, ref msg } = event {
						for node in $nodes.iter() {
							if node.get_our_node_id() == *node_id {
								node.handle_funding_locked(&$nodes[idx].get_our_node_id(), msg);
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

	// 3 nodes is enough to hit all the possible cases, notably unknown-source-unknown-dest
	// forwarding.
	let (node_a, mut monitor_a, keys_manager_a) = make_node!(0);
	let (node_b, mut monitor_b, keys_manager_b) = make_node!(1);
	let (node_c, mut monitor_c, keys_manager_c) = make_node!(2);

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

	let mut chan_a_disconnected = false;
	let mut chan_b_disconnected = false;
	let mut ba_events = Vec::new();
	let mut bc_events = Vec::new();

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
		macro_rules! process_msg_events {
			($node: expr, $corrupt_forward: expr) => { {
				let events = if $node == 1 {
					let mut new_events = Vec::new();
					mem::swap(&mut new_events, &mut ba_events);
					new_events.extend_from_slice(&bc_events[..]);
					bc_events.clear();
					new_events
				} else { Vec::new() };
				let mut had_events = false;
				for event in events.iter().chain(nodes[$node].get_and_clear_pending_msg_events().iter()) {
					had_events = true;
					match event {
						events::MessageSendEvent::UpdateHTLCs { ref node_id, updates: CommitmentUpdate { ref update_add_htlcs, ref update_fail_htlcs, ref update_fulfill_htlcs, ref update_fail_malformed_htlcs, ref update_fee, ref commitment_signed } } => {
							for dest in nodes.iter() {
								if dest.get_our_node_id() == *node_id {
									assert!(update_fee.is_none());
									for update_add in update_add_htlcs {
										if !$corrupt_forward {
											dest.handle_update_add_htlc(&nodes[$node].get_our_node_id(), &update_add);
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
									for update_fulfill in update_fulfill_htlcs {
										dest.handle_update_fulfill_htlc(&nodes[$node].get_our_node_id(), &update_fulfill);
									}
									for update_fail in update_fail_htlcs {
										dest.handle_update_fail_htlc(&nodes[$node].get_our_node_id(), &update_fail);
									}
									for update_fail_malformed in update_fail_malformed_htlcs {
										dest.handle_update_fail_malformed_htlc(&nodes[$node].get_our_node_id(), &update_fail_malformed);
									}
									dest.handle_commitment_signed(&nodes[$node].get_our_node_id(), &commitment_signed);
								}
							}
						},
						events::MessageSendEvent::SendRevokeAndACK { ref node_id, ref msg } => {
							for dest in nodes.iter() {
								if dest.get_our_node_id() == *node_id {
									dest.handle_revoke_and_ack(&nodes[$node].get_our_node_id(), msg);
								}
							}
						},
						events::MessageSendEvent::SendChannelReestablish { ref node_id, ref msg } => {
							for dest in nodes.iter() {
								if dest.get_our_node_id() == *node_id {
									dest.handle_channel_reestablish(&nodes[$node].get_our_node_id(), msg);
								}
							}
						},
						events::MessageSendEvent::SendFundingLocked { .. } => {
							// Can be generated as a reestablish response
						},
						events::MessageSendEvent::PaymentFailureNetworkUpdate { .. } => {
							// Can be generated due to a payment forward being rejected due to a
							// channel having previously failed a monitor update
						},
						_ => panic!("Unhandled message event"),
					}
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
							events::MessageSendEvent::SendFundingLocked { .. } => {},
							events::MessageSendEvent::PaymentFailureNetworkUpdate { .. } => {},
							events::MessageSendEvent::HandleError { action: ErrorAction::IgnoreError, .. } => {},
							_ => panic!("Unhandled message event"),
						}
					}
					ba_events.clear();
				} else {
					for event in nodes[2].get_and_clear_pending_msg_events() {
						match event {
							events::MessageSendEvent::UpdateHTLCs { .. } => {},
							events::MessageSendEvent::SendRevokeAndACK { .. } => {},
							events::MessageSendEvent::SendChannelReestablish { .. } => {},
							events::MessageSendEvent::SendFundingLocked { .. } => {},
							events::MessageSendEvent::PaymentFailureNetworkUpdate { .. } => {},
							events::MessageSendEvent::HandleError { action: ErrorAction::IgnoreError, .. } => {},
							_ => panic!("Unhandled message event"),
						}
					}
					bc_events.clear();
				}
				let mut events = nodes[1].get_and_clear_pending_msg_events();
				let drop_node_id = if $counterparty_id == 0 { nodes[0].get_our_node_id() } else { nodes[2].get_our_node_id() };
				let msg_sink = if $counterparty_id == 0 { &mut bc_events } else { &mut ba_events };
				for event in events.drain(..) {
					let push = match event {
						events::MessageSendEvent::UpdateHTLCs { ref node_id, .. } => {
							if *node_id != drop_node_id { true } else { false }
						},
						events::MessageSendEvent::SendRevokeAndACK { ref node_id, .. } => {
							if *node_id != drop_node_id { true } else { false }
						},
						events::MessageSendEvent::SendChannelReestablish { ref node_id, .. } => {
							if *node_id != drop_node_id { true } else { false }
						},
						events::MessageSendEvent::SendFundingLocked { .. } => false,
						events::MessageSendEvent::PaymentFailureNetworkUpdate { .. } => false,
						events::MessageSendEvent::HandleError { action: ErrorAction::IgnoreError, .. } => false,
						_ => panic!("Unhandled message event"),
					};
					if push { msg_sink.push(event); }
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
				// PaymentReceived, claiming/failing two HTLCs, but leaving a just-generated
				// PaymentReceived event for the second HTLC in our pending_events (and breaking
				// our claim_set deduplication).
				events.sort_by(|a, b| {
					if let events::Event::PaymentReceived { .. } = a {
						if let events::Event::PendingHTLCsForwardable { .. } = b {
							Ordering::Less
						} else { Ordering::Equal }
					} else if let events::Event::PendingHTLCsForwardable { .. } = a {
						if let events::Event::PaymentReceived { .. } = b {
							Ordering::Greater
						} else { Ordering::Equal }
					} else { Ordering::Equal }
				});
				let had_events = !events.is_empty();
				for event in events.drain(..) {
					match event {
						events::Event::PaymentReceived { payment_hash, .. } => {
							if claim_set.insert(payment_hash.0) {
								if $fail {
									assert!(nodes[$node].fail_htlc_backwards(&payment_hash));
								} else {
									assert!(nodes[$node].claim_funds(PaymentPreimage(payment_hash.0)));
								}
							}
						},
						events::Event::PaymentSent { .. } => {},
						events::Event::PaymentFailed { .. } => {},
						events::Event::PendingHTLCsForwardable { .. } => {
							nodes[$node].process_pending_htlc_forwards();
						},
						_ => panic!("Unhandled event"),
					}
				}
				had_events
			} }
		}

		match get_slice!(1)[0] {
			// In general, we keep related message groups close together in binary form, allowing
			// bit-twiddling mutations to have similar effects. This is probably overkill, but no
			// harm in doing so.

			0x00 => *monitor_a.update_ret.lock().unwrap() = Err(ChannelMonitorUpdateErr::TemporaryFailure),
			0x01 => *monitor_b.update_ret.lock().unwrap() = Err(ChannelMonitorUpdateErr::TemporaryFailure),
			0x02 => *monitor_c.update_ret.lock().unwrap() = Err(ChannelMonitorUpdateErr::TemporaryFailure),
			0x04 => *monitor_a.update_ret.lock().unwrap() = Ok(()),
			0x05 => *monitor_b.update_ret.lock().unwrap() = Ok(()),
			0x06 => *monitor_c.update_ret.lock().unwrap() = Ok(()),

			0x08 => {
				if let Some((id, _)) = monitor_a.latest_monitors.lock().unwrap().get(&chan_1_funding) {
					nodes[0].channel_monitor_updated(&chan_1_funding, *id);
				}
			},
			0x09 => {
				if let Some((id, _)) = monitor_b.latest_monitors.lock().unwrap().get(&chan_1_funding) {
					nodes[1].channel_monitor_updated(&chan_1_funding, *id);
				}
			},
			0x0a => {
				if let Some((id, _)) = monitor_b.latest_monitors.lock().unwrap().get(&chan_2_funding) {
					nodes[1].channel_monitor_updated(&chan_2_funding, *id);
				}
			},
			0x0b => {
				if let Some((id, _)) = monitor_c.latest_monitors.lock().unwrap().get(&chan_2_funding) {
					nodes[2].channel_monitor_updated(&chan_2_funding, *id);
				}
			},

			0x0c => {
				if !chan_a_disconnected {
					nodes[0].peer_disconnected(&nodes[1].get_our_node_id(), false);
					nodes[1].peer_disconnected(&nodes[0].get_our_node_id(), false);
					chan_a_disconnected = true;
					drain_msg_events_on_disconnect!(0);
				}
			},
			0x0d => {
				if !chan_b_disconnected {
					nodes[1].peer_disconnected(&nodes[2].get_our_node_id(), false);
					nodes[2].peer_disconnected(&nodes[1].get_our_node_id(), false);
					chan_b_disconnected = true;
					drain_msg_events_on_disconnect!(2);
				}
			},
			0x0e => {
				if chan_a_disconnected {
					nodes[0].peer_connected(&nodes[1].get_our_node_id(), &Init { features: InitFeatures::known() });
					nodes[1].peer_connected(&nodes[0].get_our_node_id(), &Init { features: InitFeatures::known() });
					chan_a_disconnected = false;
				}
			},
			0x0f => {
				if chan_b_disconnected {
					nodes[1].peer_connected(&nodes[2].get_our_node_id(), &Init { features: InitFeatures::known() });
					nodes[2].peer_connected(&nodes[1].get_our_node_id(), &Init { features: InitFeatures::known() });
					chan_b_disconnected = false;
				}
			},

			0x10 => { process_msg_events!(0, true); },
			0x11 => { process_msg_events!(0, false); },
			0x12 => { process_events!(0, true); },
			0x13 => { process_events!(0, false); },
			0x14 => { process_msg_events!(1, true); },
			0x15 => { process_msg_events!(1, false); },
			0x16 => { process_events!(1, true); },
			0x17 => { process_events!(1, false); },
			0x18 => { process_msg_events!(2, true); },
			0x19 => { process_msg_events!(2, false); },
			0x1a => { process_events!(2, true); },
			0x1b => { process_events!(2, false); },

			0x1c => {
				if !chan_a_disconnected {
					nodes[1].peer_disconnected(&nodes[0].get_our_node_id(), false);
					chan_a_disconnected = true;
					drain_msg_events_on_disconnect!(0);
				}
				let (new_node_a, new_monitor_a) = reload_node!(node_a_ser, 0, monitor_a, keys_manager_a);
				nodes[0] = new_node_a;
				monitor_a = new_monitor_a;
			},
			0x1d => {
				if !chan_a_disconnected {
					nodes[0].peer_disconnected(&nodes[1].get_our_node_id(), false);
					chan_a_disconnected = true;
					nodes[0].get_and_clear_pending_msg_events();
					ba_events.clear();
				}
				if !chan_b_disconnected {
					nodes[2].peer_disconnected(&nodes[1].get_our_node_id(), false);
					chan_b_disconnected = true;
					nodes[2].get_and_clear_pending_msg_events();
					bc_events.clear();
				}
				let (new_node_b, new_monitor_b) = reload_node!(node_b_ser, 1, monitor_b, keys_manager_b);
				nodes[1] = new_node_b;
				monitor_b = new_monitor_b;
			},
			0x1e => {
				if !chan_b_disconnected {
					nodes[1].peer_disconnected(&nodes[2].get_our_node_id(), false);
					chan_b_disconnected = true;
					drain_msg_events_on_disconnect!(2);
				}
				let (new_node_c, new_monitor_c) = reload_node!(node_c_ser, 2, monitor_c, keys_manager_c);
				nodes[2] = new_node_c;
				monitor_c = new_monitor_c;
			},

			// 1/10th the channel size:
			0x20 => { send_payment(&nodes[0], &nodes[1], chan_a, 10_000_000, &mut payment_id); },
			0x21 => { send_payment(&nodes[1], &nodes[0], chan_a, 10_000_000, &mut payment_id); },
			0x22 => { send_payment(&nodes[1], &nodes[2], chan_b, 10_000_000, &mut payment_id); },
			0x23 => { send_payment(&nodes[2], &nodes[1], chan_b, 10_000_000, &mut payment_id); },
			0x24 => { send_hop_payment(&nodes[0], &nodes[1], chan_a, &nodes[2], chan_b, 10_000_000, &mut payment_id); },
			0x25 => { send_hop_payment(&nodes[2], &nodes[1], chan_b, &nodes[0], chan_a, 10_000_000, &mut payment_id); },

			0x28 => { send_payment(&nodes[0], &nodes[1], chan_a, 1_000_000, &mut payment_id); },
			0x29 => { send_payment(&nodes[1], &nodes[0], chan_a, 1_000_000, &mut payment_id); },
			0x2a => { send_payment(&nodes[1], &nodes[2], chan_b, 1_000_000, &mut payment_id); },
			0x2b => { send_payment(&nodes[2], &nodes[1], chan_b, 1_000_000, &mut payment_id); },
			0x2c => { send_hop_payment(&nodes[0], &nodes[1], chan_a, &nodes[2], chan_b, 1_000_000, &mut payment_id); },
			0x2d => { send_hop_payment(&nodes[2], &nodes[1], chan_b, &nodes[0], chan_a, 1_000_000, &mut payment_id); },

			0x30 => { send_payment(&nodes[0], &nodes[1], chan_a, 100_000, &mut payment_id); },
			0x31 => { send_payment(&nodes[1], &nodes[0], chan_a, 100_000, &mut payment_id); },
			0x32 => { send_payment(&nodes[1], &nodes[2], chan_b, 100_000, &mut payment_id); },
			0x33 => { send_payment(&nodes[2], &nodes[1], chan_b, 100_000, &mut payment_id); },
			0x34 => { send_hop_payment(&nodes[0], &nodes[1], chan_a, &nodes[2], chan_b, 100_000, &mut payment_id); },
			0x35 => { send_hop_payment(&nodes[2], &nodes[1], chan_b, &nodes[0], chan_a, 100_000, &mut payment_id); },

			0x38 => { send_payment(&nodes[0], &nodes[1], chan_a, 10_000, &mut payment_id); },
			0x39 => { send_payment(&nodes[1], &nodes[0], chan_a, 10_000, &mut payment_id); },
			0x3a => { send_payment(&nodes[1], &nodes[2], chan_b, 10_000, &mut payment_id); },
			0x3b => { send_payment(&nodes[2], &nodes[1], chan_b, 10_000, &mut payment_id); },
			0x3c => { send_hop_payment(&nodes[0], &nodes[1], chan_a, &nodes[2], chan_b, 10_000, &mut payment_id); },
			0x3d => { send_hop_payment(&nodes[2], &nodes[1], chan_b, &nodes[0], chan_a, 10_000, &mut payment_id); },

			0x40 => { send_payment(&nodes[0], &nodes[1], chan_a, 1_000, &mut payment_id); },
			0x41 => { send_payment(&nodes[1], &nodes[0], chan_a, 1_000, &mut payment_id); },
			0x42 => { send_payment(&nodes[1], &nodes[2], chan_b, 1_000, &mut payment_id); },
			0x43 => { send_payment(&nodes[2], &nodes[1], chan_b, 1_000, &mut payment_id); },
			0x44 => { send_hop_payment(&nodes[0], &nodes[1], chan_a, &nodes[2], chan_b, 1_000, &mut payment_id); },
			0x45 => { send_hop_payment(&nodes[2], &nodes[1], chan_b, &nodes[0], chan_a, 1_000, &mut payment_id); },

			0x48 => { send_payment(&nodes[0], &nodes[1], chan_a, 100, &mut payment_id); },
			0x49 => { send_payment(&nodes[1], &nodes[0], chan_a, 100, &mut payment_id); },
			0x4a => { send_payment(&nodes[1], &nodes[2], chan_b, 100, &mut payment_id); },
			0x4b => { send_payment(&nodes[2], &nodes[1], chan_b, 100, &mut payment_id); },
			0x4c => { send_hop_payment(&nodes[0], &nodes[1], chan_a, &nodes[2], chan_b, 100, &mut payment_id); },
			0x4d => { send_hop_payment(&nodes[2], &nodes[1], chan_b, &nodes[0], chan_a, 100, &mut payment_id); },

			0x50 => { send_payment(&nodes[0], &nodes[1], chan_a, 10, &mut payment_id); },
			0x51 => { send_payment(&nodes[1], &nodes[0], chan_a, 10, &mut payment_id); },
			0x52 => { send_payment(&nodes[1], &nodes[2], chan_b, 10, &mut payment_id); },
			0x53 => { send_payment(&nodes[2], &nodes[1], chan_b, 10, &mut payment_id); },
			0x54 => { send_hop_payment(&nodes[0], &nodes[1], chan_a, &nodes[2], chan_b, 10, &mut payment_id); },
			0x55 => { send_hop_payment(&nodes[2], &nodes[1], chan_b, &nodes[0], chan_a, 10, &mut payment_id); },

			0x58 => { send_payment(&nodes[0], &nodes[1], chan_a, 1, &mut payment_id); },
			0x59 => { send_payment(&nodes[1], &nodes[0], chan_a, 1, &mut payment_id); },
			0x5a => { send_payment(&nodes[1], &nodes[2], chan_b, 1, &mut payment_id); },
			0x5b => { send_payment(&nodes[2], &nodes[1], chan_b, 1, &mut payment_id); },
			0x5c => { send_hop_payment(&nodes[0], &nodes[1], chan_a, &nodes[2], chan_b, 1, &mut payment_id); },
			0x5d => { send_hop_payment(&nodes[2], &nodes[1], chan_b, &nodes[0], chan_a, 1, &mut payment_id); },

			0xff => {
				// Test that no channel is in a stuck state where neither party can send funds even
				// after we resolve all pending events.
				// First make sure there are no pending monitor updates, resetting the error state
				// and calling channel_monitor_updated for each monitor.
				*monitor_a.update_ret.lock().unwrap() = Ok(());
				*monitor_b.update_ret.lock().unwrap() = Ok(());
				*monitor_c.update_ret.lock().unwrap() = Ok(());

				if let Some((id, _)) = monitor_a.latest_monitors.lock().unwrap().get(&chan_1_funding) {
					nodes[0].channel_monitor_updated(&chan_1_funding, *id);
				}
				if let Some((id, _)) = monitor_b.latest_monitors.lock().unwrap().get(&chan_1_funding) {
					nodes[1].channel_monitor_updated(&chan_1_funding, *id);
				}
				if let Some((id, _)) = monitor_b.latest_monitors.lock().unwrap().get(&chan_2_funding) {
					nodes[1].channel_monitor_updated(&chan_2_funding, *id);
				}
				if let Some((id, _)) = monitor_c.latest_monitors.lock().unwrap().get(&chan_2_funding) {
					nodes[2].channel_monitor_updated(&chan_2_funding, *id);
				}

				// Next, make sure peers are all connected to each other
				if chan_a_disconnected {
					nodes[0].peer_connected(&nodes[1].get_our_node_id(), &Init { features: InitFeatures::known() });
					nodes[1].peer_connected(&nodes[0].get_our_node_id(), &Init { features: InitFeatures::known() });
					chan_a_disconnected = false;
				}
				if chan_b_disconnected {
					nodes[1].peer_connected(&nodes[2].get_our_node_id(), &Init { features: InitFeatures::known() });
					nodes[2].peer_connected(&nodes[1].get_our_node_id(), &Init { features: InitFeatures::known() });
					chan_b_disconnected = false;
				}

				for i in 0..std::usize::MAX {
					if i == 100 { panic!("It may take may iterations to settle the state, but it should not take forever"); }
					// Then, make sure any current forwards make their way to their destination
					if process_msg_events!(0, false) { continue; }
					if process_msg_events!(1, false) { continue; }
					if process_msg_events!(2, false) { continue; }
					// ...making sure any pending PendingHTLCsForwardable events are handled and
					// payments claimed.
					if process_events!(0, false) { continue; }
					if process_events!(1, false) { continue; }
					if process_events!(2, false) { continue; }
					break;
				}

				// Finally, make sure that at least one end of each channel can make a substantial payment.
				assert!(
					send_payment(&nodes[0], &nodes[1], chan_a, 10_000_000, &mut payment_id) ||
					send_payment(&nodes[1], &nodes[0], chan_a, 10_000_000, &mut payment_id));
				assert!(
					send_payment(&nodes[1], &nodes[2], chan_b, 10_000_000, &mut payment_id) ||
					send_payment(&nodes[2], &nodes[1], chan_b, 10_000_000, &mut payment_id));
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

pub fn chanmon_consistency_test<Out: test_logger::Output>(data: &[u8], out: Out) {
	do_test(data, out);
}

#[no_mangle]
pub extern "C" fn chanmon_consistency_run(data: *const u8, datalen: usize) {
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) }, test_logger::DevNull{});
}
