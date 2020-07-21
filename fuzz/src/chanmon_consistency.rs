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
use bitcoin::blockdata::transaction::{Transaction, TxOut};
use bitcoin::blockdata::script::{Builder, Script};
use bitcoin::blockdata::opcodes;
use bitcoin::network::constants::Network;

use bitcoin::hashes::Hash as TraitImport;
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hash_types::{BlockHash, WPubkeyHash};

use lightning::chain;
use lightning::chain::transaction::OutPoint;
use lightning::chain::chaininterface::{BroadcasterInterface, ChainListener, ConfirmationTarget, FeeEstimator};
use lightning::chain::keysinterface::{KeysInterface, InMemoryChannelKeys};
use lightning::ln::channelmonitor;
use lightning::ln::channelmonitor::{ChannelMonitor, ChannelMonitorUpdateErr, MonitorEvent};
use lightning::ln::channelmanager::{ChannelManager, PaymentHash, PaymentPreimage, PaymentSecret, ChannelManagerReadArgs};
use lightning::ln::features::{ChannelFeatures, InitFeatures, NodeFeatures};
use lightning::ln::msgs::{CommitmentUpdate, ChannelMessageHandler, ErrorAction, UpdateAddHTLC, Init};
use lightning::util::enforcing_trait_impls::EnforcingChannelKeys;
use lightning::util::events;
use lightning::util::logger::Logger;
use lightning::util::config::UserConfig;
use lightning::util::events::{EventsProvider, MessageSendEventsProvider};
use lightning::util::ser::{Readable, ReadableArgs, Writeable, Writer};
use lightning::routing::router::{Route, RouteHop};


use utils::test_logger;

use bitcoin::secp256k1::key::{PublicKey,SecretKey};
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

struct TestChannelMonitor {
	pub logger: Arc<dyn Logger>,
	pub simple_monitor: Arc<channelmonitor::SimpleManyChannelMonitor<OutPoint, EnforcingChannelKeys, Arc<TestBroadcaster>, Arc<FuzzEstimator>, Arc<dyn Logger>>>,
	pub update_ret: Mutex<Result<(), channelmonitor::ChannelMonitorUpdateErr>>,
	// If we reload a node with an old copy of ChannelMonitors, the ChannelManager deserialization
	// logic will automatically force-close our channels for us (as we don't have an up-to-date
	// monitor implying we are not able to punish misbehaving counterparties). Because this test
	// "fails" if we ever force-close a channel, we avoid doing so, always saving the latest
	// fully-serialized monitor state here, as well as the corresponding update_id.
	pub latest_monitors: Mutex<HashMap<OutPoint, (u64, Vec<u8>)>>,
	pub should_update_manager: atomic::AtomicBool,
}
impl TestChannelMonitor {
	pub fn new(broadcaster: Arc<TestBroadcaster>, logger: Arc<dyn Logger>, feeest: Arc<FuzzEstimator>) -> Self {
		Self {
			simple_monitor: Arc::new(channelmonitor::SimpleManyChannelMonitor::new(broadcaster, logger.clone(), feeest)),
			logger,
			update_ret: Mutex::new(Ok(())),
			latest_monitors: Mutex::new(HashMap::new()),
			should_update_manager: atomic::AtomicBool::new(false),
		}
	}
}
impl chain::Watch for TestChannelMonitor {
	type Keys = EnforcingChannelKeys;

	fn watch_channel(&self, funding_txo: OutPoint, monitor: channelmonitor::ChannelMonitor<EnforcingChannelKeys>) -> Result<(), channelmonitor::ChannelMonitorUpdateErr> {
		let mut ser = VecWriter(Vec::new());
		monitor.write_for_disk(&mut ser).unwrap();
		if let Some(_) = self.latest_monitors.lock().unwrap().insert(funding_txo, (monitor.get_latest_update_id(), ser.0)) {
			panic!("Already had monitor pre-watch_channel");
		}
		self.should_update_manager.store(true, atomic::Ordering::Relaxed);
		assert!(self.simple_monitor.watch_channel(funding_txo, monitor).is_ok());
		self.update_ret.lock().unwrap().clone()
	}

	fn update_channel(&self, funding_txo: OutPoint, update: channelmonitor::ChannelMonitorUpdate) -> Result<(), channelmonitor::ChannelMonitorUpdateErr> {
		let mut map_lock = self.latest_monitors.lock().unwrap();
		let mut map_entry = match map_lock.entry(funding_txo) {
			hash_map::Entry::Occupied(entry) => entry,
			hash_map::Entry::Vacant(_) => panic!("Didn't have monitor on update call"),
		};
		let mut deserialized_monitor = <(BlockHash, channelmonitor::ChannelMonitor<EnforcingChannelKeys>)>::
			read(&mut Cursor::new(&map_entry.get().1)).unwrap().1;
		deserialized_monitor.update_monitor(update.clone(), &&TestBroadcaster {}, &self.logger).unwrap();
		let mut ser = VecWriter(Vec::new());
		deserialized_monitor.write_for_disk(&mut ser).unwrap();
		map_entry.insert((update.update_id, ser.0));
		self.should_update_manager.store(true, atomic::Ordering::Relaxed);
		self.update_ret.lock().unwrap().clone()
	}

	fn release_pending_monitor_events(&self) -> Vec<MonitorEvent> {
		return self.simple_monitor.release_pending_monitor_events();
	}
}

struct KeyProvider {
	node_id: u8,
	rand_bytes_id: atomic::AtomicU8,
}
impl KeysInterface for KeyProvider {
	type ChanKeySigner = EnforcingChannelKeys;

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

	fn get_channel_keys(&self, _inbound: bool, channel_value_satoshis: u64) -> EnforcingChannelKeys {
		let secp_ctx = Secp256k1::signing_only();
		EnforcingChannelKeys::new(InMemoryChannelKeys::new(
			&secp_ctx,
			SecretKey::from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, self.node_id]).unwrap(),
			SecretKey::from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, self.node_id]).unwrap(),
			SecretKey::from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6, self.node_id]).unwrap(),
			SecretKey::from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, self.node_id]).unwrap(),
			SecretKey::from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, self.node_id]).unwrap(),
			[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9, self.node_id],
			channel_value_satoshis,
			(0, 0),
		))
	}

	fn get_secure_random_bytes(&self) -> [u8; 32] {
		let id = self.rand_bytes_id.fetch_add(1, atomic::Ordering::Relaxed);
		[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, id, 11, self.node_id]
	}
}

#[inline]
pub fn do_test<Out: test_logger::Output>(data: &[u8], out: Out) {
	let fee_est = Arc::new(FuzzEstimator{});
	let broadcast = Arc::new(TestBroadcaster{});

	macro_rules! make_node {
		($node_id: expr) => { {
			let logger: Arc<dyn Logger> = Arc::new(test_logger::TestLogger::new($node_id.to_string(), out.clone()));
			let monitor = Arc::new(TestChannelMonitor::new(broadcast.clone(), logger.clone(), fee_est.clone()));

			let keys_manager = Arc::new(KeyProvider { node_id: $node_id, rand_bytes_id: atomic::AtomicU8::new(0) });
			let mut config = UserConfig::default();
			config.channel_options.fee_proportional_millionths = 0;
			config.channel_options.announced_channel = true;
			config.peer_channel_config_limits.min_dust_limit_satoshis = 0;
			(Arc::new(ChannelManager::new(Network::Bitcoin, fee_est.clone(), monitor.clone(), broadcast.clone(), Arc::clone(&logger), keys_manager.clone(), config, 0)),
			monitor)
		} }
	}

	macro_rules! reload_node {
		($ser: expr, $node_id: expr, $old_monitors: expr) => { {
			let logger: Arc<dyn Logger> = Arc::new(test_logger::TestLogger::new($node_id.to_string(), out.clone()));
			let chain_monitor = Arc::new(TestChannelMonitor::new(broadcast.clone(), logger.clone(), fee_est.clone()));

			let keys_manager = Arc::new(KeyProvider { node_id: $node_id, rand_bytes_id: atomic::AtomicU8::new(0) });
			let mut config = UserConfig::default();
			config.channel_options.fee_proportional_millionths = 0;
			config.channel_options.announced_channel = true;
			config.peer_channel_config_limits.min_dust_limit_satoshis = 0;

			let mut monitors = HashMap::new();
			let mut old_monitors = $old_monitors.latest_monitors.lock().unwrap();
			for (outpoint, (update_id, monitor_ser)) in old_monitors.drain() {
				monitors.insert(outpoint, <(BlockHash, ChannelMonitor<EnforcingChannelKeys>)>::read(&mut Cursor::new(&monitor_ser)).expect("Failed to read monitor").1);
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

			(<(BlockHash, ChannelManager<EnforcingChannelKeys, Arc<TestChannelMonitor>, Arc<TestBroadcaster>, Arc<KeyProvider>, Arc<FuzzEstimator>, Arc<dyn Logger>>)>::read(&mut Cursor::new(&$ser.0), read_args).expect("Failed to read manager").1, chain_monitor)
		} }
	}

	let mut channel_txn = Vec::new();
	macro_rules! make_channel {
		($source: expr, $dest: expr, $chan_id: expr) => { {
			$source.create_channel($dest.get_our_node_id(), 10000000, 42, 0, None).unwrap();
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
					$source.funding_transaction_generated(&temporary_channel_id, funding_output);
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

			{
				let events = $source.get_and_clear_pending_events();
				assert_eq!(events.len(), 1);
				if let events::Event::FundingBroadcastSafe { .. } = events[0] {
				} else { panic!("Wrong event type"); }
			}
			funding_output
		} }
	}

	macro_rules! confirm_txn {
		($node: expr) => { {
			let mut header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
			let txdata: Vec<_> = channel_txn.iter().enumerate().map(|(i, tx)| (i + 1, tx)).collect();
			$node.block_connected(&header, &txdata, 1);
			for i in 2..100 {
				header = BlockHeader { version: 0x20000000, prev_blockhash: header.block_hash(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
				$node.block_connected(&header, &[], i);
			}
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
	let (mut node_a, mut monitor_a) = make_node!(0);
	let (mut node_b, mut monitor_b) = make_node!(1);
	let (mut node_c, mut monitor_c) = make_node!(2);

	let mut nodes = [node_a, node_b, node_c];

	let chan_1_funding = make_channel!(nodes[0], nodes[1], 0);
	let chan_2_funding = make_channel!(nodes[1], nodes[2], 1);

	for node in nodes.iter() {
		confirm_txn!(node);
	}

	lock_fundings!(nodes);

	let chan_a = nodes[0].list_usable_channels()[0].short_channel_id.unwrap();
	let chan_b = nodes[2].list_usable_channels()[0].short_channel_id.unwrap();

	let mut payment_id = 0;

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
		macro_rules! send_payment {
			($source: expr, $dest: expr, $amt: expr) => { {
				let payment_hash = Sha256::hash(&[payment_id; 1]);
				payment_id = payment_id.wrapping_add(1);
				if let Err(_) = $source.send_payment(&Route {
					paths: vec![vec![RouteHop {
						pubkey: $dest.0.get_our_node_id(),
						node_features: NodeFeatures::empty(),
						short_channel_id: $dest.1,
						channel_features: ChannelFeatures::empty(),
						fee_msat: $amt,
						cltv_expiry_delta: 200,
					}]],
				}, PaymentHash(payment_hash.into_inner()), &None) {
					// Probably ran out of funds
					test_return!();
				}
			} };
			($source: expr, $middle: expr, $dest: expr, $amt: expr) => { {
				let payment_hash = Sha256::hash(&[payment_id; 1]);
				payment_id = payment_id.wrapping_add(1);
				if let Err(_) = $source.send_payment(&Route {
					paths: vec![vec![RouteHop {
						pubkey: $middle.0.get_our_node_id(),
						node_features: NodeFeatures::empty(),
						short_channel_id: $middle.1,
						channel_features: ChannelFeatures::empty(),
						fee_msat: 50000,
						cltv_expiry_delta: 100,
					},RouteHop {
						pubkey: $dest.0.get_our_node_id(),
						node_features: NodeFeatures::empty(),
						short_channel_id: $dest.1,
						channel_features: ChannelFeatures::empty(),
						fee_msat: $amt,
						cltv_expiry_delta: 200,
					}]],
				}, PaymentHash(payment_hash.into_inner()), &None) {
					// Probably ran out of funds
					test_return!();
				}
			} }
		}
		macro_rules! send_payment_with_secret {
			($source: expr, $middle: expr, $dest: expr) => { {
				let payment_hash = Sha256::hash(&[payment_id; 1]);
				payment_id = payment_id.wrapping_add(1);
				let payment_secret = Sha256::hash(&[payment_id; 1]);
				payment_id = payment_id.wrapping_add(1);
				if let Err(_) = $source.send_payment(&Route {
					paths: vec![vec![RouteHop {
						pubkey: $middle.0.get_our_node_id(),
						node_features: NodeFeatures::empty(),
						short_channel_id: $middle.1,
						channel_features: ChannelFeatures::empty(),
						fee_msat: 50000,
						cltv_expiry_delta: 100,
					},RouteHop {
						pubkey: $dest.0.get_our_node_id(),
						node_features: NodeFeatures::empty(),
						short_channel_id: $dest.1,
						channel_features: ChannelFeatures::empty(),
						fee_msat: 5000000,
						cltv_expiry_delta: 200,
					}],vec![RouteHop {
						pubkey: $middle.0.get_our_node_id(),
						node_features: NodeFeatures::empty(),
						short_channel_id: $middle.1,
						channel_features: ChannelFeatures::empty(),
						fee_msat: 50000,
						cltv_expiry_delta: 100,
					},RouteHop {
						pubkey: $dest.0.get_our_node_id(),
						node_features: NodeFeatures::empty(),
						short_channel_id: $dest.1,
						channel_features: ChannelFeatures::empty(),
						fee_msat: 5000000,
						cltv_expiry_delta: 200,
					}]],
				}, PaymentHash(payment_hash.into_inner()), &Some(PaymentSecret(payment_secret.into_inner()))) {
					// Probably ran out of funds
					test_return!();
				}
			} }
		}

		macro_rules! process_msg_events {
			($node: expr, $corrupt_forward: expr) => { {
				let events = if $node == 1 {
					let mut new_events = Vec::new();
					mem::swap(&mut new_events, &mut ba_events);
					new_events.extend_from_slice(&bc_events[..]);
					bc_events.clear();
					new_events
				} else { Vec::new() };
				for event in events.iter().chain(nodes[$node].get_and_clear_pending_msg_events().iter()) {
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
						events::MessageSendEvent::HandleError { action: ErrorAction::IgnoreError, .. } => {
							// Can be generated at any processing step to send back an error, disconnect
							// peer or just ignore
						},
						_ => panic!("Unhandled message event"),
					}
				}
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
				for event in events.drain(..) {
					match event {
						events::Event::PaymentReceived { payment_hash, payment_secret, amt } => {
							if claim_set.insert(payment_hash.0) {
								if $fail {
									assert!(nodes[$node].fail_htlc_backwards(&payment_hash, &payment_secret));
								} else {
									assert!(nodes[$node].claim_funds(PaymentPreimage(payment_hash.0), &payment_secret, amt));
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
			} }
		}

		match get_slice!(1)[0] {
			0x00 => *monitor_a.update_ret.lock().unwrap() = Err(ChannelMonitorUpdateErr::TemporaryFailure),
			0x01 => *monitor_b.update_ret.lock().unwrap() = Err(ChannelMonitorUpdateErr::TemporaryFailure),
			0x02 => *monitor_c.update_ret.lock().unwrap() = Err(ChannelMonitorUpdateErr::TemporaryFailure),
			0x03 => *monitor_a.update_ret.lock().unwrap() = Ok(()),
			0x04 => *monitor_b.update_ret.lock().unwrap() = Ok(()),
			0x05 => *monitor_c.update_ret.lock().unwrap() = Ok(()),
			0x06 => {
				if let Some((id, _)) = monitor_a.latest_monitors.lock().unwrap().get(&chan_1_funding) {
					nodes[0].channel_monitor_updated(&chan_1_funding, *id);
				}
			},
			0x07 => {
				if let Some((id, _)) = monitor_b.latest_monitors.lock().unwrap().get(&chan_1_funding) {
					nodes[1].channel_monitor_updated(&chan_1_funding, *id);
				}
			},
			0x24 => {
				if let Some((id, _)) = monitor_b.latest_monitors.lock().unwrap().get(&chan_2_funding) {
					nodes[1].channel_monitor_updated(&chan_2_funding, *id);
				}
			},
			0x08 => {
				if let Some((id, _)) = monitor_c.latest_monitors.lock().unwrap().get(&chan_2_funding) {
					nodes[2].channel_monitor_updated(&chan_2_funding, *id);
				}
			},
			0x09 => send_payment!(nodes[0], (&nodes[1], chan_a), 5_000_000),
			0x0a => send_payment!(nodes[1], (&nodes[0], chan_a), 5_000_000),
			0x0b => send_payment!(nodes[1], (&nodes[2], chan_b), 5_000_000),
			0x0c => send_payment!(nodes[2], (&nodes[1], chan_b), 5_000_000),
			0x0d => send_payment!(nodes[0], (&nodes[1], chan_a), (&nodes[2], chan_b), 5_000_000),
			0x0e => send_payment!(nodes[2], (&nodes[1], chan_b), (&nodes[0], chan_a), 5_000_000),
			0x0f => {
				if !chan_a_disconnected {
					nodes[0].peer_disconnected(&nodes[1].get_our_node_id(), false);
					nodes[1].peer_disconnected(&nodes[0].get_our_node_id(), false);
					chan_a_disconnected = true;
					drain_msg_events_on_disconnect!(0);
				}
			},
			0x10 => {
				if !chan_b_disconnected {
					nodes[1].peer_disconnected(&nodes[2].get_our_node_id(), false);
					nodes[2].peer_disconnected(&nodes[1].get_our_node_id(), false);
					chan_b_disconnected = true;
					drain_msg_events_on_disconnect!(2);
				}
			},
			0x11 => {
				if chan_a_disconnected {
					nodes[0].peer_connected(&nodes[1].get_our_node_id(), &Init { features: InitFeatures::empty() });
					nodes[1].peer_connected(&nodes[0].get_our_node_id(), &Init { features: InitFeatures::empty() });
					chan_a_disconnected = false;
				}
			},
			0x12 => {
				if chan_b_disconnected {
					nodes[1].peer_connected(&nodes[2].get_our_node_id(), &Init { features: InitFeatures::empty() });
					nodes[2].peer_connected(&nodes[1].get_our_node_id(), &Init { features: InitFeatures::empty() });
					chan_b_disconnected = false;
				}
			},
			0x13 => process_msg_events!(0, true),
			0x14 => process_msg_events!(0, false),
			0x15 => process_events!(0, true),
			0x16 => process_events!(0, false),
			0x17 => process_msg_events!(1, true),
			0x18 => process_msg_events!(1, false),
			0x19 => process_events!(1, true),
			0x1a => process_events!(1, false),
			0x1b => process_msg_events!(2, true),
			0x1c => process_msg_events!(2, false),
			0x1d => process_events!(2, true),
			0x1e => process_events!(2, false),
			0x1f => {
				if !chan_a_disconnected {
					nodes[1].peer_disconnected(&nodes[0].get_our_node_id(), false);
					chan_a_disconnected = true;
					drain_msg_events_on_disconnect!(0);
				}
				let (new_node_a, new_monitor_a) = reload_node!(node_a_ser, 0, monitor_a);
				node_a = Arc::new(new_node_a);
				nodes[0] = node_a.clone();
				monitor_a = new_monitor_a;
			},
			0x20 => {
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
				let (new_node_b, new_monitor_b) = reload_node!(node_b_ser, 1, monitor_b);
				node_b = Arc::new(new_node_b);
				nodes[1] = node_b.clone();
				monitor_b = new_monitor_b;
			},
			0x21 => {
				if !chan_b_disconnected {
					nodes[1].peer_disconnected(&nodes[2].get_our_node_id(), false);
					chan_b_disconnected = true;
					drain_msg_events_on_disconnect!(2);
				}
				let (new_node_c, new_monitor_c) = reload_node!(node_c_ser, 2, monitor_c);
				node_c = Arc::new(new_node_c);
				nodes[2] = node_c.clone();
				monitor_c = new_monitor_c;
			},
			0x22 => send_payment_with_secret!(nodes[0], (&nodes[1], chan_a), (&nodes[2], chan_b)),
			0x23 => send_payment_with_secret!(nodes[2], (&nodes[1], chan_b), (&nodes[0], chan_a)),
			0x25 => send_payment!(nodes[0], (&nodes[1], chan_a), 10),
			0x26 => send_payment!(nodes[1], (&nodes[0], chan_a), 10),
			0x27 => send_payment!(nodes[1], (&nodes[2], chan_b), 10),
			0x28 => send_payment!(nodes[2], (&nodes[1], chan_b), 10),
			0x29 => send_payment!(nodes[0], (&nodes[1], chan_a), (&nodes[2], chan_b), 10),
			0x2a => send_payment!(nodes[2], (&nodes[1], chan_b), (&nodes[0], chan_a), 10),
			0x2b => send_payment!(nodes[0], (&nodes[1], chan_a), 1_000),
			0x2c => send_payment!(nodes[1], (&nodes[0], chan_a), 1_000),
			0x2d => send_payment!(nodes[1], (&nodes[2], chan_b), 1_000),
			0x2e => send_payment!(nodes[2], (&nodes[1], chan_b), 1_000),
			0x2f => send_payment!(nodes[0], (&nodes[1], chan_a), (&nodes[2], chan_b), 1_000),
			0x30 => send_payment!(nodes[2], (&nodes[1], chan_b), (&nodes[0], chan_a), 1_000),
			0x31 => send_payment!(nodes[0], (&nodes[1], chan_a), 100_000),
			0x32 => send_payment!(nodes[1], (&nodes[0], chan_a), 100_000),
			0x33 => send_payment!(nodes[1], (&nodes[2], chan_b), 100_000),
			0x34 => send_payment!(nodes[2], (&nodes[1], chan_b), 100_000),
			0x35 => send_payment!(nodes[0], (&nodes[1], chan_a), (&nodes[2], chan_b), 100_000),
			0x36 => send_payment!(nodes[2], (&nodes[1], chan_b), (&nodes[0], chan_a), 100_000),
			// 0x24 defined above
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
