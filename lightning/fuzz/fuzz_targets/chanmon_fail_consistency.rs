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

//Uncomment this for libfuzzer builds:
//#![no_main]

extern crate bitcoin;
extern crate bitcoin_hashes;
extern crate lightning;
extern crate secp256k1;

use bitcoin::BitcoinHash;
use bitcoin::blockdata::block::BlockHeader;
use bitcoin::blockdata::transaction::{Transaction, TxOut};
use bitcoin::blockdata::script::{Builder, Script};
use bitcoin::blockdata::opcodes;
use bitcoin::network::constants::Network;

use bitcoin_hashes::Hash as TraitImport;
use bitcoin_hashes::hash160::Hash as Hash160;
use bitcoin_hashes::sha256::Hash as Sha256;
use bitcoin_hashes::sha256d::Hash as Sha256d;

use lightning::chain::chaininterface;
use lightning::chain::transaction::OutPoint;
use lightning::chain::chaininterface::{BroadcasterInterface,ConfirmationTarget,ChainListener,FeeEstimator,ChainWatchInterfaceUtil};
use lightning::chain::keysinterface::{ChannelKeys, KeysInterface};
use lightning::ln::channelmonitor;
use lightning::ln::channelmonitor::{ChannelMonitor, ChannelMonitorUpdateErr, HTLCUpdate};
use lightning::ln::channelmanager::{ChannelManager, PaymentHash, PaymentPreimage, ChannelManagerReadArgs};
use lightning::ln::router::{Route, RouteHop};
use lightning::ln::msgs::{CommitmentUpdate, ChannelMessageHandler, ErrorAction, LightningError, UpdateAddHTLC, LocalFeatures};
use lightning::util::events;
use lightning::util::logger::Logger;
use lightning::util::config::UserConfig;
use lightning::util::events::{EventsProvider, MessageSendEventsProvider};
use lightning::util::ser::{Readable, ReadableArgs, Writeable, Writer};

mod utils;
use utils::test_logger;

use secp256k1::key::{PublicKey,SecretKey};
use secp256k1::Secp256k1;

use std::mem;
use std::cmp::Ordering;
use std::collections::{HashSet, hash_map, HashMap};
use std::sync::{Arc,Mutex};
use std::sync::atomic;
use std::io::Cursor;

struct FuzzEstimator {}
impl FeeEstimator for FuzzEstimator {
	fn get_est_sat_per_1000_weight(&self, _: ConfirmationTarget) -> u64 {
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

static mut IN_RESTORE: bool = false;
pub struct TestChannelMonitor {
	pub simple_monitor: Arc<channelmonitor::SimpleManyChannelMonitor<OutPoint>>,
	pub update_ret: Mutex<Result<(), channelmonitor::ChannelMonitorUpdateErr>>,
	pub latest_good_update: Mutex<HashMap<OutPoint, Vec<u8>>>,
	pub latest_update_good: Mutex<HashMap<OutPoint, bool>>,
	pub latest_updates_good_at_last_ser: Mutex<HashMap<OutPoint, bool>>,
	pub should_update_manager: atomic::AtomicBool,
}
impl TestChannelMonitor {
	pub fn new(chain_monitor: Arc<chaininterface::ChainWatchInterface>, broadcaster: Arc<chaininterface::BroadcasterInterface>, logger: Arc<Logger>, feeest: Arc<chaininterface::FeeEstimator>) -> Self {
		Self {
			simple_monitor: channelmonitor::SimpleManyChannelMonitor::new(chain_monitor, broadcaster, logger, feeest),
			update_ret: Mutex::new(Ok(())),
			latest_good_update: Mutex::new(HashMap::new()),
			latest_update_good: Mutex::new(HashMap::new()),
			latest_updates_good_at_last_ser: Mutex::new(HashMap::new()),
			should_update_manager: atomic::AtomicBool::new(false),
		}
	}
}
impl channelmonitor::ManyChannelMonitor for TestChannelMonitor {
	fn add_update_monitor(&self, funding_txo: OutPoint, monitor: channelmonitor::ChannelMonitor) -> Result<(), channelmonitor::ChannelMonitorUpdateErr> {
		let ret = self.update_ret.lock().unwrap().clone();
		if let Ok(()) = ret {
			let mut ser = VecWriter(Vec::new());
			monitor.write_for_disk(&mut ser).unwrap();
			self.latest_good_update.lock().unwrap().insert(funding_txo, ser.0);
			match self.latest_update_good.lock().unwrap().entry(funding_txo) {
				hash_map::Entry::Vacant(mut e) => { e.insert(true); },
				hash_map::Entry::Occupied(mut e) => {
					if !e.get() && unsafe { IN_RESTORE } {
						// Technically we can't consider an update to be "good" unless we're doing
						// it in response to a test_restore_channel_monitor as the channel may
						// still be waiting on such a call, so only set us to good if we're in the
						// middle of a restore call.
						e.insert(true);
					}
				},
			}
			self.should_update_manager.store(true, atomic::Ordering::Relaxed);
		} else {
			self.latest_update_good.lock().unwrap().insert(funding_txo, false);
		}
		assert!(self.simple_monitor.add_update_monitor(funding_txo, monitor).is_ok());
		ret
	}

	fn fetch_pending_htlc_updated(&self) -> Vec<HTLCUpdate> {
		return self.simple_monitor.fetch_pending_htlc_updated();
	}
}

struct KeyProvider {
	node_id: u8,
	session_id: atomic::AtomicU8,
	channel_id: atomic::AtomicU8,
}
impl KeysInterface for KeyProvider {
	fn get_node_secret(&self) -> SecretKey {
		SecretKey::from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, self.node_id]).unwrap()
	}

	fn get_destination_script(&self) -> Script {
		let secp_ctx = Secp256k1::signing_only();
		let channel_monitor_claim_key = SecretKey::from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, self.node_id]).unwrap();
		let our_channel_monitor_claim_key_hash = Hash160::hash(&PublicKey::from_secret_key(&secp_ctx, &channel_monitor_claim_key).serialize());
		Builder::new().push_opcode(opcodes::all::OP_PUSHBYTES_0).push_slice(&our_channel_monitor_claim_key_hash[..]).into_script()
	}

	fn get_shutdown_pubkey(&self) -> PublicKey {
		let secp_ctx = Secp256k1::signing_only();
		PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, self.node_id]).unwrap())
	}

	fn get_channel_keys(&self, _inbound: bool) -> ChannelKeys {
		ChannelKeys {
			funding_key:               SecretKey::from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, self.node_id]).unwrap(),
			revocation_base_key:       SecretKey::from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, self.node_id]).unwrap(),
			payment_base_key:          SecretKey::from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6, self.node_id]).unwrap(),
			delayed_payment_base_key:  SecretKey::from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, self.node_id]).unwrap(),
			htlc_base_key:             SecretKey::from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, self.node_id]).unwrap(),
			commitment_seed: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9, self.node_id],
		}
	}

	fn get_session_key(&self) -> SecretKey {
		let id = self.session_id.fetch_add(1, atomic::Ordering::Relaxed);
		SecretKey::from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, id, 10, self.node_id]).unwrap()
	}

	fn get_channel_id(&self) -> [u8; 32] {
		let id = self.channel_id.fetch_add(1, atomic::Ordering::Relaxed);
		[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, id, 11, self.node_id]
	}
}

#[inline]
pub fn do_test(data: &[u8]) {
	let fee_est = Arc::new(FuzzEstimator{});
	let broadcast = Arc::new(TestBroadcaster{});

	macro_rules! make_node {
		($node_id: expr) => { {
			let logger: Arc<Logger> = Arc::new(test_logger::TestLogger::new($node_id.to_string()));
			let watch = Arc::new(ChainWatchInterfaceUtil::new(Network::Bitcoin, Arc::clone(&logger)));
			let monitor = Arc::new(TestChannelMonitor::new(watch.clone(), broadcast.clone(), logger.clone(), fee_est.clone()));

			let keys_manager = Arc::new(KeyProvider { node_id: $node_id, session_id: atomic::AtomicU8::new(0), channel_id: atomic::AtomicU8::new(0) });
			let mut config = UserConfig::new();
			config.channel_options.fee_proportional_millionths = 0;
			config.channel_options.announced_channel = true;
			config.peer_channel_config_limits.min_dust_limit_satoshis = 0;
			(ChannelManager::new(Network::Bitcoin, fee_est.clone(), monitor.clone(), watch.clone(), broadcast.clone(), Arc::clone(&logger), keys_manager.clone(), config, 0).unwrap(),
			monitor)
		} }
	}

	macro_rules! reload_node {
		($ser: expr, $node_id: expr, $old_monitors: expr) => { {
			let logger: Arc<Logger> = Arc::new(test_logger::TestLogger::new($node_id.to_string()));
			let watch = Arc::new(ChainWatchInterfaceUtil::new(Network::Bitcoin, Arc::clone(&logger)));
			let monitor = Arc::new(TestChannelMonitor::new(watch.clone(), broadcast.clone(), logger.clone(), fee_est.clone()));

			let keys_manager = Arc::new(KeyProvider { node_id: $node_id, session_id: atomic::AtomicU8::new(0), channel_id: atomic::AtomicU8::new(0) });
			let mut config = UserConfig::new();
			config.channel_options.fee_proportional_millionths = 0;
			config.channel_options.announced_channel = true;
			config.peer_channel_config_limits.min_dust_limit_satoshis = 0;

			let mut monitors = HashMap::new();
			let mut old_monitors = $old_monitors.latest_good_update.lock().unwrap();
			for (outpoint, monitor_ser) in old_monitors.drain() {
				monitors.insert(outpoint, <(Sha256d, ChannelMonitor)>::read(&mut Cursor::new(&monitor_ser), Arc::clone(&logger)).expect("Failed to read monitor").1);
				monitor.latest_good_update.lock().unwrap().insert(outpoint, monitor_ser);
			}
			let mut monitor_refs = HashMap::new();
			for (outpoint, monitor) in monitors.iter() {
				monitor_refs.insert(*outpoint, monitor);
			}

			let read_args = ChannelManagerReadArgs {
				keys_manager,
				fee_estimator: fee_est.clone(),
				monitor: monitor.clone(),
				chain_monitor: watch,
				tx_broadcaster: broadcast.clone(),
				logger,
				default_config: config,
				channel_monitors: &monitor_refs,
			};

			let res = (<(Sha256d, ChannelManager)>::read(&mut Cursor::new(&$ser.0), read_args).expect("Failed to read manager").1, monitor);
			for (_, was_good) in $old_monitors.latest_updates_good_at_last_ser.lock().unwrap().iter() {
				if !was_good {
					// If the last time we updated a monitor we didn't successfully update (and we
					// have sense updated our serialized copy of the ChannelManager) we may
					// force-close the channel on our counterparty cause we know we're missing
					// something. Thus, we just return here since we can't continue to test.
					return;
				}
			}
			res
		} }
	}


	let mut channel_txn = Vec::new();
	macro_rules! make_channel {
		($source: expr, $dest: expr, $chan_id: expr) => { {
			$source.create_channel($dest.get_our_node_id(), 10000000, 42, 0).unwrap();
			let open_channel = {
				let events = $source.get_and_clear_pending_msg_events();
				assert_eq!(events.len(), 1);
				if let events::MessageSendEvent::SendOpenChannel { ref msg, .. } = events[0] {
					msg.clone()
				} else { panic!("Wrong event type"); }
			};

			$dest.handle_open_channel(&$source.get_our_node_id(), LocalFeatures::new(), &open_channel).unwrap();
			let accept_channel = {
				let events = $dest.get_and_clear_pending_msg_events();
				assert_eq!(events.len(), 1);
				if let events::MessageSendEvent::SendAcceptChannel { ref msg, .. } = events[0] {
					msg.clone()
				} else { panic!("Wrong event type"); }
			};

			$source.handle_accept_channel(&$dest.get_our_node_id(), LocalFeatures::new(), &accept_channel).unwrap();
			{
				let events = $source.get_and_clear_pending_events();
				assert_eq!(events.len(), 1);
				if let events::Event::FundingGenerationReady { ref temporary_channel_id, ref channel_value_satoshis, ref output_script, .. } = events[0] {
					let tx = Transaction { version: $chan_id, lock_time: 0, input: Vec::new(), output: vec![TxOut {
						value: *channel_value_satoshis, script_pubkey: output_script.clone(),
					}]};
					let funding_output = OutPoint::new(tx.txid(), 0);
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
			$dest.handle_funding_created(&$source.get_our_node_id(), &funding_created).unwrap();

			let funding_signed = {
				let events = $dest.get_and_clear_pending_msg_events();
				assert_eq!(events.len(), 1);
				if let events::MessageSendEvent::SendFundingSigned { ref msg, .. } = events[0] {
					msg.clone()
				} else { panic!("Wrong event type"); }
			};
			$source.handle_funding_signed(&$dest.get_our_node_id(), &funding_signed).unwrap();

			{
				let events = $source.get_and_clear_pending_events();
				assert_eq!(events.len(), 1);
				if let events::Event::FundingBroadcastSafe { .. } = events[0] {
				} else { panic!("Wrong event type"); }
			}
		} }
	}

	macro_rules! confirm_txn {
		($node: expr) => { {
			let mut header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
			let mut txn = Vec::with_capacity(channel_txn.len());
			let mut posn = Vec::with_capacity(channel_txn.len());
			for i in 0..channel_txn.len() {
				txn.push(&channel_txn[i]);
				posn.push(i as u32 + 1);
			}
			$node.block_connected(&header, 1, &txn, &posn);
			for i in 2..100 {
				header = BlockHeader { version: 0x20000000, prev_blockhash: header.bitcoin_hash(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
				$node.block_connected(&header, i, &Vec::new(), &[0; 0]);
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
								node.handle_funding_locked(&$nodes[idx].get_our_node_id(), msg).unwrap();
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

	make_channel!(nodes[0], nodes[1], 0);
	make_channel!(nodes[1], nodes[2], 1);

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

	macro_rules! test_err {
		($res: expr) => {
			match $res {
				Ok(()) => {},
				Err(LightningError { action: ErrorAction::IgnoreError, .. }) => { },
				_ => { $res.unwrap() },
			}
		}
	}

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
			($source: expr, $dest: expr) => { {
				let payment_hash = Sha256::hash(&[payment_id; 1]);
				payment_id = payment_id.wrapping_add(1);
				if let Err(_) = $source.send_payment(Route {
					hops: vec![RouteHop {
						pubkey: $dest.0.get_our_node_id(),
						short_channel_id: $dest.1,
						fee_msat: 5000000,
						cltv_expiry_delta: 200,
					}],
				}, PaymentHash(payment_hash.into_inner())) {
					// Probably ran out of funds
					test_return!();
				}
			} };
			($source: expr, $middle: expr, $dest: expr) => { {
				let payment_hash = Sha256::hash(&[payment_id; 1]);
				payment_id = payment_id.wrapping_add(1);
				if let Err(_) = $source.send_payment(Route {
					hops: vec![RouteHop {
						pubkey: $middle.0.get_our_node_id(),
						short_channel_id: $middle.1,
						fee_msat: 50000,
						cltv_expiry_delta: 100,
					},RouteHop {
						pubkey: $dest.0.get_our_node_id(),
						short_channel_id: $dest.1,
						fee_msat: 5000000,
						cltv_expiry_delta: 200,
					}],
				}, PaymentHash(payment_hash.into_inner())) {
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
											test_err!(dest.handle_update_add_htlc(&nodes[$node].get_our_node_id(), &update_add));
										} else {
											// Corrupt the update_add_htlc message so that its HMAC
											// check will fail and we generate a
											// update_fail_malformed_htlc instead of an
											// update_fail_htlc as we do when we reject a payment.
											let mut msg_ser = update_add.encode();
											msg_ser[1000] ^= 0xff;
											let new_msg = UpdateAddHTLC::read(&mut Cursor::new(&msg_ser)).unwrap();
											test_err!(dest.handle_update_add_htlc(&nodes[$node].get_our_node_id(), &new_msg));
										}
									}
									for update_fulfill in update_fulfill_htlcs {
										test_err!(dest.handle_update_fulfill_htlc(&nodes[$node].get_our_node_id(), &update_fulfill));
									}
									for update_fail in update_fail_htlcs {
										test_err!(dest.handle_update_fail_htlc(&nodes[$node].get_our_node_id(), &update_fail));
									}
									for update_fail_malformed in update_fail_malformed_htlcs {
										test_err!(dest.handle_update_fail_malformed_htlc(&nodes[$node].get_our_node_id(), &update_fail_malformed));
									}
									test_err!(dest.handle_commitment_signed(&nodes[$node].get_our_node_id(), &commitment_signed));
								}
							}
						},
						events::MessageSendEvent::SendRevokeAndACK { ref node_id, ref msg } => {
							for dest in nodes.iter() {
								if dest.get_our_node_id() == *node_id {
									test_err!(dest.handle_revoke_and_ack(&nodes[$node].get_our_node_id(), msg));
								}
							}
						},
						events::MessageSendEvent::SendChannelReestablish { ref node_id, ref msg } => {
							for dest in nodes.iter() {
								if dest.get_our_node_id() == *node_id {
									test_err!(dest.handle_channel_reestablish(&nodes[$node].get_our_node_id(), msg));
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
			} }
		}

		match get_slice!(1)[0] {
			0x00 => *monitor_a.update_ret.lock().unwrap() = Err(ChannelMonitorUpdateErr::TemporaryFailure),
			0x01 => *monitor_b.update_ret.lock().unwrap() = Err(ChannelMonitorUpdateErr::TemporaryFailure),
			0x02 => *monitor_c.update_ret.lock().unwrap() = Err(ChannelMonitorUpdateErr::TemporaryFailure),
			0x03 => *monitor_a.update_ret.lock().unwrap() = Ok(()),
			0x04 => *monitor_b.update_ret.lock().unwrap() = Ok(()),
			0x05 => *monitor_c.update_ret.lock().unwrap() = Ok(()),
			0x06 => { unsafe { IN_RESTORE = true }; nodes[0].test_restore_channel_monitor(); unsafe { IN_RESTORE = false }; },
			0x07 => { unsafe { IN_RESTORE = true }; nodes[1].test_restore_channel_monitor(); unsafe { IN_RESTORE = false }; },
			0x08 => { unsafe { IN_RESTORE = true }; nodes[2].test_restore_channel_monitor(); unsafe { IN_RESTORE = false }; },
			0x09 => send_payment!(nodes[0], (&nodes[1], chan_a)),
			0x0a => send_payment!(nodes[1], (&nodes[0], chan_a)),
			0x0b => send_payment!(nodes[1], (&nodes[2], chan_b)),
			0x0c => send_payment!(nodes[2], (&nodes[1], chan_b)),
			0x0d => send_payment!(nodes[0], (&nodes[1], chan_a), (&nodes[2], chan_b)),
			0x0e => send_payment!(nodes[2], (&nodes[1], chan_b), (&nodes[0], chan_a)),
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
					nodes[0].peer_connected(&nodes[1].get_our_node_id());
					nodes[1].peer_connected(&nodes[0].get_our_node_id());
					chan_a_disconnected = false;
				}
			},
			0x12 => {
				if chan_b_disconnected {
					nodes[1].peer_connected(&nodes[2].get_our_node_id());
					nodes[2].peer_connected(&nodes[1].get_our_node_id());
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
			_ => test_return!(),
		}

		if monitor_a.should_update_manager.load(atomic::Ordering::Relaxed) {
			node_a_ser.0.clear();
			nodes[0].write(&mut node_a_ser).unwrap();
			monitor_a.should_update_manager.store(false, atomic::Ordering::Relaxed);
			*monitor_a.latest_updates_good_at_last_ser.lock().unwrap() = monitor_a.latest_update_good.lock().unwrap().clone();
		}
		if monitor_b.should_update_manager.load(atomic::Ordering::Relaxed) {
			node_b_ser.0.clear();
			nodes[1].write(&mut node_b_ser).unwrap();
			monitor_b.should_update_manager.store(false, atomic::Ordering::Relaxed);
			*monitor_b.latest_updates_good_at_last_ser.lock().unwrap() = monitor_b.latest_update_good.lock().unwrap().clone();
		}
		if monitor_c.should_update_manager.load(atomic::Ordering::Relaxed) {
			node_c_ser.0.clear();
			nodes[2].write(&mut node_c_ser).unwrap();
			monitor_c.should_update_manager.store(false, atomic::Ordering::Relaxed);
			*monitor_c.latest_updates_good_at_last_ser.lock().unwrap() = monitor_c.latest_update_good.lock().unwrap().clone();
		}
	}
}

#[cfg(feature = "afl")]
#[macro_use] extern crate afl;
#[cfg(feature = "afl")]
fn main() {
	fuzz!(|data| {
		do_test(data);
	});
}

#[cfg(feature = "honggfuzz")]
#[macro_use] extern crate honggfuzz;
#[cfg(feature = "honggfuzz")]
fn main() {
	loop {
		fuzz!(|data| {
			do_test(data);
		});
	}
}

#[cfg(feature = "libfuzzer_fuzz")]
#[macro_use] extern crate libfuzzer_sys;
#[cfg(feature = "libfuzzer_fuzz")]
fuzz_target!(|data: &[u8]| {
	do_test(data);
});

extern crate hex;
#[cfg(test)]
mod tests {
	#[test]
	fn duplicate_crash() {
		super::do_test(&::hex::decode("00").unwrap());
	}
}
