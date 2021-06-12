//! Utilities that take care of tasks that (1) need to happen periodically to keep Rust-Lightning
//! running properly, and (2) either can or should be run in the background. See docs for
//! [`BackgroundProcessor`] for more details on the nitty-gritty.

#![deny(broken_intra_doc_links)]
#![deny(missing_docs)]
#![deny(unsafe_code)]

#[macro_use] extern crate lightning;

use lightning::chain;
use lightning::chain::chaininterface::{BroadcasterInterface, FeeEstimator};
use lightning::chain::chainmonitor::ChainMonitor;
use lightning::chain::channelmonitor;
use lightning::chain::keysinterface::{Sign, KeysInterface};
use lightning::ln::channelmanager::ChannelManager;
use lightning::ln::msgs::{ChannelMessageHandler, RoutingMessageHandler};
use lightning::ln::peer_handler::{PeerManager, SocketDescriptor};
use lightning::util::events::{EventHandler, EventsProvider};
use lightning::util::logger::Logger;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use std::ops::Deref;

/// BackgroundProcessor takes care of tasks that (1) need to happen periodically to keep
/// Rust-Lightning running properly, and (2) either can or should be run in the background. Its
/// responsibilities are:
/// * Monitoring whether the ChannelManager needs to be re-persisted to disk, and if so,
///   writing it to disk/backups by invoking the callback given to it at startup.
///   ChannelManager persistence should be done in the background.
/// * Calling `ChannelManager::timer_tick_occurred()` and
///   `PeerManager::timer_tick_occurred()` every minute (can be done in the
///   background).
///
/// Note that if ChannelManager persistence fails and the persisted manager becomes out-of-date,
/// then there is a risk of channels force-closing on startup when the manager realizes it's
/// outdated. However, as long as `ChannelMonitor` backups are sound, no funds besides those used
/// for unilateral chain closure fees are at risk.
pub struct BackgroundProcessor {
	stop_thread: Arc<AtomicBool>,
	/// May be used to retrieve and handle the error if `BackgroundProcessor`'s thread
	/// exits due to an error while persisting.
	pub thread_handle: JoinHandle<Result<(), std::io::Error>>,
}

#[cfg(not(test))]
const FRESHNESS_TIMER: u64 = 60;
#[cfg(test)]
const FRESHNESS_TIMER: u64 = 1;

/// Trait which handles persisting a [`ChannelManager`] to disk.
///
/// [`ChannelManager`]: lightning::ln::channelmanager::ChannelManager
pub trait ChannelManagerPersister<Signer: Sign, M: Deref, T: Deref, K: Deref, F: Deref, L: Deref>
where
	M::Target: 'static + chain::Watch<Signer>,
	T::Target: 'static + BroadcasterInterface,
	K::Target: 'static + KeysInterface<Signer = Signer>,
	F::Target: 'static + FeeEstimator,
	L::Target: 'static + Logger,
{
	/// Persist the given [`ChannelManager`] to disk, returning an error if persistence failed
	/// (which will cause the [`BackgroundProcessor`] which called this method to exit.
	///
	/// [`ChannelManager`]: lightning::ln::channelmanager::ChannelManager
	fn persist_manager(&self, channel_manager: &ChannelManager<Signer, M, T, K, F, L>) -> Result<(), std::io::Error>;
}

impl<Fun, Signer: Sign, M: Deref, T: Deref, K: Deref, F: Deref, L: Deref>
ChannelManagerPersister<Signer, M, T, K, F, L> for Fun where
	M::Target: 'static + chain::Watch<Signer>,
	T::Target: 'static + BroadcasterInterface,
	K::Target: 'static + KeysInterface<Signer = Signer>,
	F::Target: 'static + FeeEstimator,
	L::Target: 'static + Logger,
	Fun: Fn(&ChannelManager<Signer, M, T, K, F, L>) -> Result<(), std::io::Error>,
{
	fn persist_manager(&self, channel_manager: &ChannelManager<Signer, M, T, K, F, L>) -> Result<(), std::io::Error> {
		self(channel_manager)
	}
}

impl BackgroundProcessor {
	/// Start a background thread that takes care of responsibilities enumerated in the top-level
	/// documentation.
	///
	/// If `persist_manager` returns an error, then this thread will return said error (and
	/// `start()` will need to be called again to restart the `BackgroundProcessor`). Users should
	/// wait on [`thread_handle`]'s `join()` method to be able to tell if and when an error is
	/// returned, or implement `persist_manager` such that an error is never returned to the
	/// `BackgroundProcessor`
	///
	/// `persist_manager` is responsible for writing out the [`ChannelManager`] to disk, and/or
	/// uploading to one or more backup services. See [`ChannelManager::write`] for writing out a
	/// [`ChannelManager`]. See [`FilesystemPersister::persist_manager`] for Rust-Lightning's
	/// provided implementation.
	///
	/// [`thread_handle`]: BackgroundProcessor::thread_handle
	/// [`ChannelManager`]: lightning::ln::channelmanager::ChannelManager
	/// [`ChannelManager::write`]: lightning::ln::channelmanager::ChannelManager#impl-Writeable
	/// [`FilesystemPersister::persist_manager`]: lightning_persister::FilesystemPersister::persist_manager
	pub fn start<
		Signer: 'static + Sign,
		CF: 'static + Deref + Send + Sync,
		CW: 'static + Deref + Send + Sync,
		T: 'static + Deref + Send + Sync,
		K: 'static + Deref + Send + Sync,
		F: 'static + Deref + Send + Sync,
		L: 'static + Deref + Send + Sync,
		P: 'static + Deref + Send + Sync,
		Descriptor: 'static + SocketDescriptor + Send + Sync,
		CMH: 'static + Deref + Send + Sync,
		RMH: 'static + Deref + Send + Sync,
		EH: 'static + EventHandler + Send + Sync,
		CMP: 'static + Send + ChannelManagerPersister<Signer, CW, T, K, F, L>,
		M: 'static + Deref<Target = ChainMonitor<Signer, CF, T, F, L, P>> + Send + Sync,
		CM: 'static + Deref<Target = ChannelManager<Signer, CW, T, K, F, L>> + Send + Sync,
		PM: 'static + Deref<Target = PeerManager<Descriptor, CMH, RMH, L>> + Send + Sync,
	>
	(persister: CMP, event_handler: EH, chain_monitor: M, channel_manager: CM, peer_manager: PM, logger: L) -> Self
	where
		CF::Target: 'static + chain::Filter,
		CW::Target: 'static + chain::Watch<Signer>,
		T::Target: 'static + BroadcasterInterface,
		K::Target: 'static + KeysInterface<Signer = Signer>,
		F::Target: 'static + FeeEstimator,
		L::Target: 'static + Logger,
		P::Target: 'static + channelmonitor::Persist<Signer>,
		CMH::Target: 'static + ChannelMessageHandler,
		RMH::Target: 'static + RoutingMessageHandler,
	{
		let stop_thread = Arc::new(AtomicBool::new(false));
		let stop_thread_clone = stop_thread.clone();
		let handle = thread::spawn(move || -> Result<(), std::io::Error> {
			let mut current_time = Instant::now();
			loop {
				peer_manager.process_events();
				channel_manager.process_pending_events(&event_handler);
				chain_monitor.process_pending_events(&event_handler);
				let updates_available =
					channel_manager.await_persistable_update_timeout(Duration::from_millis(100));
				if updates_available {
					persister.persist_manager(&*channel_manager)?;
				}
				// Exit the loop if the background processor was requested to stop.
				if stop_thread.load(Ordering::Acquire) == true {
					log_trace!(logger, "Terminating background processor.");
					return Ok(());
				}
				if current_time.elapsed().as_secs() > FRESHNESS_TIMER {
					log_trace!(logger, "Calling ChannelManager's and PeerManager's timer_tick_occurred");
					channel_manager.timer_tick_occurred();
					peer_manager.timer_tick_occurred();
					current_time = Instant::now();
				}
			}
		});
		Self { stop_thread: stop_thread_clone, thread_handle: handle }
	}

	/// Stop `BackgroundProcessor`'s thread.
	pub fn stop(self) -> Result<(), std::io::Error> {
		self.stop_thread.store(true, Ordering::Release);
		self.thread_handle.join().unwrap()
	}
}

#[cfg(test)]
mod tests {
	use bitcoin::blockdata::block::BlockHeader;
	use bitcoin::blockdata::constants::genesis_block;
	use bitcoin::blockdata::transaction::{Transaction, TxOut};
	use bitcoin::network::constants::Network;
	use lightning::chain::Confirm;
	use lightning::chain::chainmonitor;
	use lightning::chain::channelmonitor::ANTI_REORG_DELAY;
	use lightning::chain::keysinterface::{InMemorySigner, KeysInterface, KeysManager};
	use lightning::chain::transaction::OutPoint;
	use lightning::get_event_msg;
	use lightning::ln::channelmanager::{BREAKDOWN_TIMEOUT, BestBlock, ChainParameters, ChannelManager, SimpleArcChannelManager};
	use lightning::ln::features::InitFeatures;
	use lightning::ln::msgs::ChannelMessageHandler;
	use lightning::ln::peer_handler::{PeerManager, MessageHandler, SocketDescriptor};
	use lightning::util::config::UserConfig;
	use lightning::util::events::{Event, MessageSendEventsProvider, MessageSendEvent};
	use lightning::util::ser::Writeable;
	use lightning::util::test_utils;
	use lightning_persister::FilesystemPersister;
	use std::fs;
	use std::path::PathBuf;
	use std::sync::{Arc, Mutex};
	use std::time::Duration;
	use super::{BackgroundProcessor, FRESHNESS_TIMER};

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

	struct Node {
		node: Arc<SimpleArcChannelManager<ChainMonitor, test_utils::TestBroadcaster, test_utils::TestFeeEstimator, test_utils::TestLogger>>,
		peer_manager: Arc<PeerManager<TestDescriptor, Arc<test_utils::TestChannelMessageHandler>, Arc<test_utils::TestRoutingMessageHandler>, Arc<test_utils::TestLogger>>>,
		chain_monitor: Arc<ChainMonitor>,
		persister: Arc<FilesystemPersister>,
		tx_broadcaster: Arc<test_utils::TestBroadcaster>,
		logger: Arc<test_utils::TestLogger>,
		best_block: BestBlock,
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

	fn get_full_filepath(filepath: String, filename: String) -> String {
		let mut path = PathBuf::from(filepath);
		path.push(filename);
		path.to_str().unwrap().to_string()
	}

	fn create_nodes(num_nodes: usize, persist_dir: String) -> Vec<Node> {
		let mut nodes = Vec::new();
		for i in 0..num_nodes {
			let tx_broadcaster = Arc::new(test_utils::TestBroadcaster{txn_broadcasted: Mutex::new(Vec::new()), blocks: Arc::new(Mutex::new(Vec::new()))});
			let fee_estimator = Arc::new(test_utils::TestFeeEstimator { sat_per_kw: 253 });
			let chain_source = Arc::new(test_utils::TestChainSource::new(Network::Testnet));
			let logger = Arc::new(test_utils::TestLogger::with_id(format!("node {}", i)));
			let persister = Arc::new(FilesystemPersister::new(format!("{}_persister_{}", persist_dir, i)));
			let seed = [i as u8; 32];
			let network = Network::Testnet;
			let now = Duration::from_secs(genesis_block(network).header.time as u64);
			let keys_manager = Arc::new(KeysManager::new(&seed, now.as_secs(), now.subsec_nanos()));
			let chain_monitor = Arc::new(chainmonitor::ChainMonitor::new(Some(chain_source.clone()), tx_broadcaster.clone(), logger.clone(), fee_estimator.clone(), persister.clone()));
			let best_block = BestBlock::from_genesis(network);
			let params = ChainParameters { network, best_block };
			let manager = Arc::new(ChannelManager::new(fee_estimator.clone(), chain_monitor.clone(), tx_broadcaster.clone(), logger.clone(), keys_manager.clone(), UserConfig::default(), params));
			let msg_handler = MessageHandler { chan_handler: Arc::new(test_utils::TestChannelMessageHandler::new()), route_handler: Arc::new(test_utils::TestRoutingMessageHandler::new() )};
			let peer_manager = Arc::new(PeerManager::new(msg_handler, keys_manager.get_node_secret(), &seed, logger.clone()));
			let node = Node { node: manager, peer_manager, chain_monitor, persister, tx_broadcaster, logger, best_block };
			nodes.push(node);
		}
		nodes
	}

	macro_rules! open_channel {
		($node_a: expr, $node_b: expr, $channel_value: expr) => {{
			begin_open_channel!($node_a, $node_b, $channel_value);
			let events = $node_a.node.get_and_clear_pending_events();
			assert_eq!(events.len(), 1);
			let (temporary_channel_id, tx) = handle_funding_generation_ready!(events[0], $channel_value);
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
				Event::FundingGenerationReady { ref temporary_channel_id, ref channel_value_satoshis, ref output_script, user_channel_id } => {
					assert_eq!(*channel_value_satoshis, $channel_value);
					assert_eq!(user_channel_id, 42);

					let tx = Transaction { version: 1 as i32, lock_time: 0, input: Vec::new(), output: vec![TxOut {
						value: *channel_value_satoshis, script_pubkey: output_script.clone(),
					}]};
					(*temporary_channel_id, tx)
				},
				_ => panic!("Unexpected event"),
			}
		}}
	}

	macro_rules! end_open_channel {
		($node_a: expr, $node_b: expr, $temporary_channel_id: expr, $tx: expr) => {{
			$node_a.node.funding_transaction_generated(&$temporary_channel_id, $tx.clone()).unwrap();
			$node_b.node.handle_funding_created(&$node_a.node.get_our_node_id(), &get_event_msg!($node_a, MessageSendEvent::SendFundingCreated, $node_b.node.get_our_node_id()));
			$node_a.node.handle_funding_signed(&$node_b.node.get_our_node_id(), &get_event_msg!($node_b, MessageSendEvent::SendFundingSigned, $node_a.node.get_our_node_id()));
		}}
	}

	fn confirm_transaction_depth(node: &mut Node, tx: &Transaction, depth: u32) {
		for i in 1..=depth {
			let prev_blockhash = node.best_block.block_hash();
			let height = node.best_block.height() + 1;
			let header = BlockHeader { version: 0x20000000, prev_blockhash, merkle_root: Default::default(), time: height, bits: 42, nonce: 42 };
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
		let persister = move |node: &ChannelManager<InMemorySigner, Arc<ChainMonitor>, Arc<test_utils::TestBroadcaster>, Arc<KeysManager>, Arc<test_utils::TestFeeEstimator>, Arc<test_utils::TestLogger>>| FilesystemPersister::persist_manager(data_dir.clone(), node);
		let event_handler = |_| {};
		let bg_processor = BackgroundProcessor::start(persister, event_handler, nodes[0].chain_monitor.clone(), nodes[0].node.clone(), nodes[0].peer_manager.clone(), nodes[0].logger.clone());

		macro_rules! check_persisted_data {
			($node: expr, $filepath: expr, $expected_bytes: expr) => {
				match $node.write(&mut $expected_bytes) {
					Ok(()) => {
						loop {
							match std::fs::read($filepath) {
								Ok(bytes) => {
									if bytes == $expected_bytes {
										break
									} else {
										continue
									}
								},
								Err(_) => continue
							}
						}
					},
					Err(e) => panic!("Unexpected error: {}", e)
				}
			}
		}

		// Check that the initial channel manager data is persisted as expected.
		let filepath = get_full_filepath("test_background_processor_persister_0".to_string(), "manager".to_string());
		let mut expected_bytes = Vec::new();
		check_persisted_data!(nodes[0].node, filepath.clone(), expected_bytes);
		loop {
			if !nodes[0].node.get_persistence_condvar_value() { break }
		}

		// Force-close the channel.
		nodes[0].node.force_close_channel(&OutPoint { txid: tx.txid(), index: 0 }.to_channel_id()).unwrap();

		// Check that the force-close updates are persisted.
		let mut expected_bytes = Vec::new();
		check_persisted_data!(nodes[0].node, filepath.clone(), expected_bytes);
		loop {
			if !nodes[0].node.get_persistence_condvar_value() { break }
		}

		assert!(bg_processor.stop().is_ok());
	}

	#[test]
	fn test_timer_tick_called() {
		// Test that ChannelManager's and PeerManager's `timer_tick_occurred` is called every
		// `FRESHNESS_TIMER`.
		let nodes = create_nodes(1, "test_timer_tick_called".to_string());
		let data_dir = nodes[0].persister.get_data_dir();
		let persister = move |node: &ChannelManager<InMemorySigner, Arc<ChainMonitor>, Arc<test_utils::TestBroadcaster>, Arc<KeysManager>, Arc<test_utils::TestFeeEstimator>, Arc<test_utils::TestLogger>>| FilesystemPersister::persist_manager(data_dir.clone(), node);
		let event_handler = |_| {};
		let bg_processor = BackgroundProcessor::start(persister, event_handler, nodes[0].chain_monitor.clone(), nodes[0].node.clone(), nodes[0].peer_manager.clone(), nodes[0].logger.clone());
		loop {
			let log_entries = nodes[0].logger.lines.lock().unwrap();
			let desired_log = "Calling ChannelManager's and PeerManager's timer_tick_occurred".to_string();
			if log_entries.get(&("lightning_background_processor".to_string(), desired_log)).is_some() {
				break
			}
		}

		assert!(bg_processor.stop().is_ok());
	}

	#[test]
	fn test_persist_error() {
		// Test that if we encounter an error during manager persistence, the thread panics.
		let nodes = create_nodes(2, "test_persist_error".to_string());
		open_channel!(nodes[0], nodes[1], 100000);

		let persister = |_: &_| Err(std::io::Error::new(std::io::ErrorKind::Other, "test"));
		let event_handler = |_| {};
		let bg_processor = BackgroundProcessor::start(persister, event_handler, nodes[0].chain_monitor.clone(), nodes[0].node.clone(), nodes[0].peer_manager.clone(), nodes[0].logger.clone());
		let _ = bg_processor.thread_handle.join().unwrap().expect_err("Errored persisting manager: test");
	}

	#[test]
	fn test_background_event_handling() {
		let mut nodes = create_nodes(2, "test_background_event_handling".to_string());
		let channel_value = 100000;
		let data_dir = nodes[0].persister.get_data_dir();
		let persister = move |node: &_| FilesystemPersister::persist_manager(data_dir.clone(), node);

		// Set up a background event handler for FundingGenerationReady events.
		let (sender, receiver) = std::sync::mpsc::sync_channel(1);
		let event_handler = move |event| {
			sender.send(handle_funding_generation_ready!(event, channel_value)).unwrap();
		};
		let bg_processor = BackgroundProcessor::start(persister.clone(), event_handler, nodes[0].chain_monitor.clone(), nodes[0].node.clone(), nodes[0].peer_manager.clone(), nodes[0].logger.clone());

		// Open a channel and check that the FundingGenerationReady event was handled.
		begin_open_channel!(nodes[0], nodes[1], channel_value);
		let (temporary_channel_id, funding_tx) = receiver
			.recv_timeout(Duration::from_secs(EVENT_DEADLINE))
			.expect("FundingGenerationReady not handled within deadline");
		end_open_channel!(nodes[0], nodes[1], temporary_channel_id, funding_tx);

		// Confirm the funding transaction.
		confirm_transaction(&mut nodes[0], &funding_tx);
		let as_funding = get_event_msg!(nodes[0], MessageSendEvent::SendFundingLocked, nodes[1].node.get_our_node_id());
		confirm_transaction(&mut nodes[1], &funding_tx);
		let bs_funding = get_event_msg!(nodes[1], MessageSendEvent::SendFundingLocked, nodes[0].node.get_our_node_id());
		nodes[0].node.handle_funding_locked(&nodes[1].node.get_our_node_id(), &bs_funding);
		let _as_channel_update = get_event_msg!(nodes[0], MessageSendEvent::SendChannelUpdate, nodes[1].node.get_our_node_id());
		nodes[1].node.handle_funding_locked(&nodes[0].node.get_our_node_id(), &as_funding);
		let _bs_channel_update = get_event_msg!(nodes[1], MessageSendEvent::SendChannelUpdate, nodes[0].node.get_our_node_id());

		assert!(bg_processor.stop().is_ok());

		// Set up a background event handler for SpendableOutputs events.
		let (sender, receiver) = std::sync::mpsc::sync_channel(1);
		let event_handler = move |event| sender.send(event).unwrap();
		let bg_processor = BackgroundProcessor::start(persister, event_handler, nodes[0].chain_monitor.clone(), nodes[0].node.clone(), nodes[0].peer_manager.clone(), nodes[0].logger.clone());

		// Force close the channel and check that the SpendableOutputs event was handled.
		nodes[0].node.force_close_channel(&nodes[0].node.list_channels()[0].channel_id).unwrap();
		let commitment_tx = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().pop().unwrap();
		confirm_transaction_depth(&mut nodes[0], &commitment_tx, BREAKDOWN_TIMEOUT as u32);
		let event = receiver
			.recv_timeout(Duration::from_secs(EVENT_DEADLINE))
			.expect("SpendableOutputs not handled within deadline");
		match event {
			Event::SpendableOutputs { .. } => {},
			_ => panic!("Unexpected event: {:?}", event),
		}

		assert!(bg_processor.stop().is_ok());
	}
}
