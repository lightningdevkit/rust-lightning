#[macro_use] extern crate lightning;

use lightning::chain;
use lightning::chain::chaininterface::{BroadcasterInterface, FeeEstimator};
use lightning::chain::keysinterface::{Sign, KeysInterface};
use lightning::ln::channelmanager::ChannelManager;
use lightning::util::logger::Logger;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// BackgroundProcessor takes care of tasks that (1) need to happen periodically to keep
/// Rust-Lightning running properly, and (2) either can or should be run in the background. Its
/// responsibilities are:
/// * Monitoring whether the ChannelManager needs to be re-persisted to disk, and if so,
///   writing it to disk/backups by invoking the callback given to it at startup.
///   ChannelManager persistence should be done in the background.
/// * Calling `ChannelManager::timer_chan_freshness_every_min()` every minute (can be done in the
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
const CHAN_FRESHNESS_TIMER: u64 = 60;
#[cfg(test)]
const CHAN_FRESHNESS_TIMER: u64 = 1;

impl BackgroundProcessor {
	/// Start a background thread that takes care of responsibilities enumerated in the top-level
	/// documentation.
	///
	/// If `persist_manager` returns an error, then this thread will return said error (and `start()`
	/// will need to be called again to restart the `BackgroundProcessor`). Users should wait on
	/// [`thread_handle`]'s `join()` method to be able to tell if and when an error is returned, or
	/// implement `persist_manager` such that an error is never returned to the `BackgroundProcessor`
	///
	/// `persist_manager` is responsible for writing out the `ChannelManager` to disk, and/or uploading
	/// to one or more backup services. See [`ChannelManager::write`] for writing out a `ChannelManager`.
	/// See [`FilesystemPersister::persist_manager`] for Rust-Lightning's provided implementation.
	///
	/// [`thread_handle`]: struct.BackgroundProcessor.html#structfield.thread_handle
	/// [`ChannelManager::write`]: ../lightning/ln/channelmanager/struct.ChannelManager.html#method.write
	/// [`FilesystemPersister::persist_manager`]: ../lightning_persister/struct.FilesystemPersister.html#impl
	pub fn start<PM, Signer, M, T, K, F, L>(persist_manager: PM, manager: Arc<ChannelManager<Signer, Arc<M>, Arc<T>, Arc<K>, Arc<F>, Arc<L>>>, logger: Arc<L>) -> Self
	where Signer: 'static + Sign,
	      M: 'static + chain::Watch<Signer>,
	      T: 'static + BroadcasterInterface,
	      K: 'static + KeysInterface<Signer=Signer>,
	      F: 'static + FeeEstimator,
	      L: 'static + Logger,
	      PM: 'static + Send + Fn(&ChannelManager<Signer, Arc<M>, Arc<T>, Arc<K>, Arc<F>, Arc<L>>) -> Result<(), std::io::Error>,
	{
		let stop_thread = Arc::new(AtomicBool::new(false));
		let stop_thread_clone = stop_thread.clone();
		let handle = thread::spawn(move || -> Result<(), std::io::Error> {
			let mut current_time = Instant::now();
			loop {
				let updates_available = manager.wait_timeout(Duration::from_millis(100));
				if updates_available {
					persist_manager(&*manager)?;
				}
				// Exit the loop if the background processor was requested to stop.
				if stop_thread.load(Ordering::Acquire) == true {
					log_trace!(logger, "Terminating background processor.");
					return Ok(())
				}
				if current_time.elapsed().as_secs() > CHAN_FRESHNESS_TIMER {
					log_trace!(logger, "Calling manager's timer_chan_freshness_every_min");
					manager.timer_chan_freshness_every_min();
					current_time = Instant::now();
				}
			}
		});
		Self {
			stop_thread: stop_thread_clone,
			thread_handle: handle,
		}
	}

	/// Stop `BackgroundProcessor`'s thread.
	pub fn stop(self) -> Result<(), std::io::Error> {
		self.stop_thread.store(true, Ordering::Release);
		self.thread_handle.join().unwrap()
	}
}

#[cfg(test)]
mod tests {
	use bitcoin::blockdata::constants::genesis_block;
	use bitcoin::blockdata::transaction::{Transaction, TxOut};
	use bitcoin::network::constants::Network;
	use lightning::chain;
	use lightning::chain::chaininterface::{BroadcasterInterface, FeeEstimator};
	use lightning::chain::chainmonitor;
	use lightning::chain::keysinterface::{Sign, InMemorySigner, KeysInterface, KeysManager};
	use lightning::chain::transaction::OutPoint;
	use lightning::get_event_msg;
	use lightning::ln::channelmanager::{ChainParameters, ChannelManager, SimpleArcChannelManager};
	use lightning::ln::features::InitFeatures;
	use lightning::ln::msgs::ChannelMessageHandler;
	use lightning::util::config::UserConfig;
	use lightning::util::events::{Event, EventsProvider, MessageSendEventsProvider, MessageSendEvent};
	use lightning::util::logger::Logger;
	use lightning::util::ser::Writeable;
	use lightning::util::test_utils;
	use lightning_persister::FilesystemPersister;
	use std::fs;
	use std::path::PathBuf;
	use std::sync::{Arc, Mutex};
	use std::time::Duration;
	use super::BackgroundProcessor;

	type ChainMonitor = chainmonitor::ChainMonitor<InMemorySigner, Arc<test_utils::TestChainSource>, Arc<test_utils::TestBroadcaster>, Arc<test_utils::TestFeeEstimator>, Arc<test_utils::TestLogger>, Arc<FilesystemPersister>>;

	struct Node {
		node: Arc<SimpleArcChannelManager<ChainMonitor, test_utils::TestBroadcaster, test_utils::TestFeeEstimator, test_utils::TestLogger>>,
		persister: Arc<FilesystemPersister>,
		logger: Arc<test_utils::TestLogger>,
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
			let tx_broadcaster = Arc::new(test_utils::TestBroadcaster{txn_broadcasted: Mutex::new(Vec::new())});
			let fee_estimator = Arc::new(test_utils::TestFeeEstimator { sat_per_kw: 253 });
			let chain_source = Arc::new(test_utils::TestChainSource::new(Network::Testnet));
			let logger = Arc::new(test_utils::TestLogger::with_id(format!("node {}", i)));
			let persister = Arc::new(FilesystemPersister::new(format!("{}_persister_{}", persist_dir, i)));
			let seed = [i as u8; 32];
			let network = Network::Testnet;
			let genesis_block = genesis_block(network);
			let now = Duration::from_secs(genesis_block.header.time as u64);
			let keys_manager = Arc::new(KeysManager::new(&seed, now.as_secs(), now.subsec_nanos()));
			let chain_monitor = Arc::new(chainmonitor::ChainMonitor::new(Some(chain_source.clone()), tx_broadcaster.clone(), logger.clone(), fee_estimator.clone(), persister.clone()));
			let params = ChainParameters {
				network,
				latest_hash: genesis_block.block_hash(),
				latest_height: 0,
			};
			let manager = Arc::new(ChannelManager::new(fee_estimator.clone(), chain_monitor.clone(), tx_broadcaster, logger.clone(), keys_manager.clone(), UserConfig::default(), params));
			let node = Node { node: manager, persister, logger };
			nodes.push(node);
		}
		nodes
	}

	macro_rules! open_channel {
		($node_a: expr, $node_b: expr, $channel_value: expr) => {{
			$node_a.node.create_channel($node_b.node.get_our_node_id(), $channel_value, 100, 42, None).unwrap();
			$node_b.node.handle_open_channel(&$node_a.node.get_our_node_id(), InitFeatures::known(), &get_event_msg!($node_a, MessageSendEvent::SendOpenChannel, $node_b.node.get_our_node_id()));
			$node_a.node.handle_accept_channel(&$node_b.node.get_our_node_id(), InitFeatures::known(), &get_event_msg!($node_b, MessageSendEvent::SendAcceptChannel, $node_a.node.get_our_node_id()));
			let events = $node_a.node.get_and_clear_pending_events();
			assert_eq!(events.len(), 1);
			let (temporary_channel_id, tx, funding_output) = match events[0] {
				Event::FundingGenerationReady { ref temporary_channel_id, ref channel_value_satoshis, ref output_script, user_channel_id } => {
					assert_eq!(*channel_value_satoshis, $channel_value);
					assert_eq!(user_channel_id, 42);

					let tx = Transaction { version: 1 as i32, lock_time: 0, input: Vec::new(), output: vec![TxOut {
						value: *channel_value_satoshis, script_pubkey: output_script.clone(),
					}]};
					let funding_outpoint = OutPoint { txid: tx.txid(), index: 0 };
					(*temporary_channel_id, tx, funding_outpoint)
				},
				_ => panic!("Unexpected event"),
			};

			$node_a.node.funding_transaction_generated(&temporary_channel_id, funding_output);
			$node_b.node.handle_funding_created(&$node_a.node.get_our_node_id(), &get_event_msg!($node_a, MessageSendEvent::SendFundingCreated, $node_b.node.get_our_node_id()));
			$node_a.node.handle_funding_signed(&$node_b.node.get_our_node_id(), &get_event_msg!($node_b, MessageSendEvent::SendFundingSigned, $node_a.node.get_our_node_id()));
			tx
		}}
	}

	#[test]
	fn test_background_processor() {
		// Test that when a new channel is created, the ChannelManager needs to be re-persisted with
		// updates. Also test that when new updates are available, the manager signals that it needs
		// re-persistence and is successfully re-persisted.
		let nodes = create_nodes(2, "test_background_processor".to_string());

		// Initiate the background processors to watch each node.
		let data_dir = nodes[0].persister.get_data_dir();
		let callback = move |node: &ChannelManager<InMemorySigner, Arc<ChainMonitor>, Arc<test_utils::TestBroadcaster>, Arc<KeysManager>, Arc<test_utils::TestFeeEstimator>, Arc<test_utils::TestLogger>>| FilesystemPersister::persist_manager(data_dir.clone(), node);
		let bg_processor = BackgroundProcessor::start(callback, nodes[0].node.clone(), nodes[0].logger.clone());

		// Go through the channel creation process until each node should have something persisted.
		let tx = open_channel!(nodes[0], nodes[1], 100000);

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
	fn test_chan_freshness_called() {
		// Test that ChannelManager's `timer_chan_freshness_every_min` is called every
		// `CHAN_FRESHNESS_TIMER`.
		let nodes = create_nodes(1, "test_chan_freshness_called".to_string());
		let data_dir = nodes[0].persister.get_data_dir();
		let callback = move |node: &ChannelManager<InMemorySigner, Arc<ChainMonitor>, Arc<test_utils::TestBroadcaster>, Arc<KeysManager>, Arc<test_utils::TestFeeEstimator>, Arc<test_utils::TestLogger>>| FilesystemPersister::persist_manager(data_dir.clone(), node);
		let bg_processor = BackgroundProcessor::start(callback, nodes[0].node.clone(), nodes[0].logger.clone());
		loop {
			let log_entries = nodes[0].logger.lines.lock().unwrap();
			let desired_log = "Calling manager's timer_chan_freshness_every_min".to_string();
			if log_entries.get(&("background_processor".to_string(), desired_log)).is_some() {
				break
			}
		}

		assert!(bg_processor.stop().is_ok());
	}

	#[test]
	fn test_persist_error() {
		// Test that if we encounter an error during manager persistence, the thread panics.
		fn persist_manager<Signer, M, T, K, F, L>(_data: &ChannelManager<Signer, Arc<M>, Arc<T>, Arc<K>, Arc<F>, Arc<L>>) -> Result<(), std::io::Error>
		where Signer: 'static + Sign,
		      M: 'static + chain::Watch<Signer>,
		      T: 'static + BroadcasterInterface,
		      K: 'static + KeysInterface<Signer=Signer>,
		      F: 'static + FeeEstimator,
		      L: 'static + Logger,
		{
			Err(std::io::Error::new(std::io::ErrorKind::Other, "test"))
		}

		let nodes = create_nodes(2, "test_persist_error".to_string());
		let bg_processor = BackgroundProcessor::start(persist_manager, nodes[0].node.clone(), nodes[0].logger.clone());
		open_channel!(nodes[0], nodes[1], 100000);

		let _ = bg_processor.thread_handle.join().unwrap().expect_err("Errored persisting manager: test");
	}
}
