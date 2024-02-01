#![cfg(all(not(target_os = "windows"), any(feature = "esplora-blocking", feature = "esplora-async", feature = "electrum")))]

#[cfg(any(feature = "esplora-blocking", feature = "esplora-async"))]
use lightning_transaction_sync::EsploraSyncClient;
#[cfg(feature = "electrum")]
use lightning_transaction_sync::ElectrumSyncClient;
use lightning::chain::{Confirm, Filter, WatchedOutput};
use lightning::chain::transaction::{OutPoint, TransactionData};
use lightning::util::test_utils::TestLogger;

use electrsd::{bitcoind, bitcoind::BitcoinD, ElectrsD};
use bitcoin::{Amount, Txid, BlockHash};
use bitcoin::blockdata::block::Header;
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::network::constants::Network;
use electrsd::bitcoind::bitcoincore_rpc::bitcoincore_rpc_json::AddressType;
use bitcoind::bitcoincore_rpc::RpcApi;
use bdk_macros::maybe_await;

use std::env;
use std::sync::Mutex;
use std::time::Duration;
use std::collections::{HashMap, HashSet};

pub fn setup_bitcoind_and_electrsd() -> (BitcoinD, ElectrsD) {
	let bitcoind_exe =
		env::var("BITCOIND_EXE").ok().or_else(|| bitcoind::downloaded_exe_path().ok()).expect(
			"you need to provide an env var BITCOIND_EXE or specify a bitcoind version feature",
		);
	let mut bitcoind_conf = bitcoind::Conf::default();
	bitcoind_conf.network = "regtest";
	let bitcoind = BitcoinD::with_conf(bitcoind_exe, &bitcoind_conf).unwrap();

	let electrs_exe = env::var("ELECTRS_EXE")
		.ok()
		.or_else(electrsd::downloaded_exe_path)
		.expect("you need to provide env var ELECTRS_EXE or specify an electrsd version feature");
	let mut electrsd_conf = electrsd::Conf::default();
	electrsd_conf.http_enabled = true;
	electrsd_conf.network = "regtest";
	let electrsd = ElectrsD::with_conf(electrs_exe, &bitcoind, &electrsd_conf).unwrap();
	(bitcoind, electrsd)
}

pub fn generate_blocks_and_wait(bitcoind: &BitcoinD, electrsd: &ElectrsD, num: usize) {
	let cur_height = bitcoind.client.get_block_count().expect("failed to get current block height");
	let address = bitcoind
		.client
		.get_new_address(Some("test"), Some(AddressType::Legacy))
		.expect("failed to get new address")
		.assume_checked();
	// TODO: expect this Result once the WouldBlock issue is resolved upstream.
	let _block_hashes_res = bitcoind.client.generate_to_address(num as u64, &address);
	wait_for_block(electrsd, cur_height as usize + num);
}

pub fn wait_for_block(electrsd: &ElectrsD, min_height: usize) {
	use electrsd::electrum_client::ElectrumApi;
	let mut header = match electrsd.client.block_headers_subscribe_raw() {
		Ok(header) => header,
		Err(_) => {
			// While subscribing should succeed the first time around, we ran into some cases where
			// it didn't. Since we can't proceed without subscribing, we try again after a delay
			// and panic if it still fails.
			std::thread::sleep(Duration::from_secs(1));
			electrsd.client.block_headers_subscribe_raw().expect("failed to subscribe to block headers")
		}
	};
	loop {
		if header.height >= min_height {
			break;
		}
		header = exponential_backoff_poll(|| {
			electrsd.trigger().expect("failed to trigger electrsd");
			electrsd.client.ping().expect("failed to ping electrsd");
			electrsd.client.block_headers_pop_raw().expect("failed to pop block header")
		});
	}
}

fn exponential_backoff_poll<T, F>(mut poll: F) -> T
where
	F: FnMut() -> Option<T>,
{
	let mut delay = Duration::from_millis(64);
	let mut tries = 0;
	loop {
		match poll() {
			Some(data) => break data,
			None if delay.as_millis() < 512 => {
				delay = delay.mul_f32(2.0);
				tries += 1;
			}
			None if tries == 10 => panic!("Exceeded our maximum wait time."),
			None => tries += 1,
		}

		std::thread::sleep(delay);
	}
}

#[derive(Debug)]
enum TestConfirmableEvent {
	Confirmed(Txid, BlockHash, u32),
	Unconfirmed(Txid),
	BestBlockUpdated(BlockHash, u32),
}

struct TestConfirmable {
	pub confirmed_txs: Mutex<HashMap<Txid, (BlockHash, u32)>>,
	pub unconfirmed_txs: Mutex<HashSet<Txid>>,
	pub best_block: Mutex<(BlockHash, u32)>,
	pub events: Mutex<Vec<TestConfirmableEvent>>,
}

impl TestConfirmable {
	pub fn new() -> Self {
		let genesis_hash = genesis_block(Network::Regtest).block_hash();
		Self {
			confirmed_txs: Mutex::new(HashMap::new()),
			unconfirmed_txs: Mutex::new(HashSet::new()),
			best_block: Mutex::new((genesis_hash, 0)),
			events: Mutex::new(Vec::new()),
		}
	}
}

impl Confirm for TestConfirmable {
	fn transactions_confirmed(&self, header: &Header, txdata: &TransactionData<'_>, height: u32) {
		for (_, tx) in txdata {
			let txid = tx.txid();
			let block_hash = header.block_hash();
			self.confirmed_txs.lock().unwrap().insert(txid, (block_hash, height));
			self.unconfirmed_txs.lock().unwrap().remove(&txid);
			self.events.lock().unwrap().push(TestConfirmableEvent::Confirmed(txid, block_hash, height));
		}
	}

	fn transaction_unconfirmed(&self, txid: &Txid) {
		self.unconfirmed_txs.lock().unwrap().insert(*txid);
		self.confirmed_txs.lock().unwrap().remove(txid);
		self.events.lock().unwrap().push(TestConfirmableEvent::Unconfirmed(*txid));
	}

	fn best_block_updated(&self, header: &Header, height: u32) {
		let block_hash = header.block_hash();
		*self.best_block.lock().unwrap() = (block_hash, height);
		self.events.lock().unwrap().push(TestConfirmableEvent::BestBlockUpdated(block_hash, height));
	}

	fn get_relevant_txids(&self) -> Vec<(Txid, u32, Option<BlockHash>)> {
		self.confirmed_txs.lock().unwrap().iter().map(|(&txid, (hash, height))| (txid, *height, Some(*hash))).collect::<Vec<_>>()
	}
}

macro_rules! test_syncing {
	($tx_sync: expr, $confirmable: expr, $bitcoind: expr, $electrsd: expr) => {{
		// Check we pick up on new best blocks
		assert_eq!($confirmable.best_block.lock().unwrap().1, 0);

		maybe_await!($tx_sync.sync(vec![&$confirmable])).unwrap();
		assert_eq!($confirmable.best_block.lock().unwrap().1, 102);

		let events = std::mem::take(&mut *$confirmable.events.lock().unwrap());
		assert_eq!(events.len(), 1);

		// Check registered confirmed transactions are marked confirmed
		let new_address = $bitcoind.client.get_new_address(Some("test"),
		Some(AddressType::Legacy)).unwrap().assume_checked();
		let txid = $bitcoind.client.send_to_address(&new_address, Amount::from_sat(5000), None, None,
		None, None, None, None).unwrap();
		let second_txid = $bitcoind.client.send_to_address(&new_address, Amount::from_sat(5000), None,
		None, None, None, None, None).unwrap();
		$tx_sync.register_tx(&txid, &new_address.payload.script_pubkey());

		maybe_await!($tx_sync.sync(vec![&$confirmable])).unwrap();

		let events = std::mem::take(&mut *$confirmable.events.lock().unwrap());
		assert_eq!(events.len(), 0);
		assert!($confirmable.confirmed_txs.lock().unwrap().is_empty());
		assert!($confirmable.unconfirmed_txs.lock().unwrap().is_empty());

		generate_blocks_and_wait(&$bitcoind, &$electrsd, 1);
		maybe_await!($tx_sync.sync(vec![&$confirmable])).unwrap();

		let events = std::mem::take(&mut *$confirmable.events.lock().unwrap());
		assert_eq!(events.len(), 2);
		assert!($confirmable.confirmed_txs.lock().unwrap().contains_key(&txid));
		assert!($confirmable.unconfirmed_txs.lock().unwrap().is_empty());

		// Now take an arbitrary output of the second transaction and check we'll confirm its spend.
		let tx_res = $bitcoind.client.get_transaction(&second_txid, None).unwrap();
		let block_hash = tx_res.info.blockhash.unwrap();
		let tx = tx_res.transaction().unwrap();
		let prev_outpoint = tx.input.first().unwrap().previous_output;
		let prev_tx = $bitcoind.client.get_transaction(&prev_outpoint.txid, None).unwrap().transaction()
			.unwrap();
		let prev_script_pubkey = prev_tx.output[prev_outpoint.vout as usize].script_pubkey.clone();
		let output = WatchedOutput {
			block_hash: Some(block_hash),
			outpoint: OutPoint { txid: prev_outpoint.txid, index: prev_outpoint.vout as u16 },
			script_pubkey: prev_script_pubkey
		};

		$tx_sync.register_output(output);
		maybe_await!($tx_sync.sync(vec![&$confirmable])).unwrap();

		let events = std::mem::take(&mut *$confirmable.events.lock().unwrap());
		assert_eq!(events.len(), 1);
		assert!($confirmable.confirmed_txs.lock().unwrap().contains_key(&second_txid));
		assert_eq!($confirmable.confirmed_txs.lock().unwrap().len(), 2);
		assert!($confirmable.unconfirmed_txs.lock().unwrap().is_empty());

		// Check previously confirmed transactions are marked unconfirmed when they are reorged.
		let best_block_hash = $bitcoind.client.get_best_block_hash().unwrap();
		$bitcoind.client.invalidate_block(&best_block_hash).unwrap();

		// We're getting back to the previous height with a new tip, but best block shouldn't change.
		generate_blocks_and_wait(&$bitcoind, &$electrsd, 1);
		assert_ne!($bitcoind.client.get_best_block_hash().unwrap(), best_block_hash);
		maybe_await!($tx_sync.sync(vec![&$confirmable])).unwrap();
		let events = std::mem::take(&mut *$confirmable.events.lock().unwrap());
		assert_eq!(events.len(), 0);

		// Now we're surpassing previous height, getting new tip.
		generate_blocks_and_wait(&$bitcoind, &$electrsd, 1);
		assert_ne!($bitcoind.client.get_best_block_hash().unwrap(), best_block_hash);
		maybe_await!($tx_sync.sync(vec![&$confirmable])).unwrap();

		// Transactions still confirmed but under new tip.
		assert!($confirmable.confirmed_txs.lock().unwrap().contains_key(&txid));
		assert!($confirmable.confirmed_txs.lock().unwrap().contains_key(&second_txid));
		assert!($confirmable.unconfirmed_txs.lock().unwrap().is_empty());

		// Check we got unconfirmed, then reconfirmed in the meantime.
		let mut seen_txids = HashSet::new();
		let events = std::mem::take(&mut *$confirmable.events.lock().unwrap());
		assert_eq!(events.len(), 5);

		match events[0] {
			TestConfirmableEvent::Unconfirmed(t) => {
				assert!(t == txid || t == second_txid);
				assert!(seen_txids.insert(t));
			},
			_ => panic!("Unexpected event"),
		}

		match events[1] {
			TestConfirmableEvent::Unconfirmed(t) => {
				assert!(t == txid || t == second_txid);
				assert!(seen_txids.insert(t));
			},
			_ => panic!("Unexpected event"),
		}

		match events[2] {
			TestConfirmableEvent::BestBlockUpdated(..) => {},
			_ => panic!("Unexpected event"),
		}

		match events[3] {
			TestConfirmableEvent::Confirmed(t, _, _) => {
				assert!(t == txid || t == second_txid);
				assert!(seen_txids.remove(&t));
			},
			_ => panic!("Unexpected event"),
		}

		match events[4] {
			TestConfirmableEvent::Confirmed(t, _, _) => {
				assert!(t == txid || t == second_txid);
				assert!(seen_txids.remove(&t));
			},
			_ => panic!("Unexpected event"),
		}

		assert_eq!(seen_txids.len(), 0);
	}};
}

#[test]
#[cfg(feature = "esplora-blocking")]
fn test_esplora_syncs() {
	let (bitcoind, electrsd) = setup_bitcoind_and_electrsd();
	generate_blocks_and_wait(&bitcoind, &electrsd, 101);
	let mut logger = TestLogger::new();
	let esplora_url = format!("http://{}", electrsd.esplora_url.as_ref().unwrap());
	let tx_sync = EsploraSyncClient::new(esplora_url, &mut logger);
	let confirmable = TestConfirmable::new();

	test_syncing!(tx_sync, confirmable, bitcoind, electrsd);
}

#[tokio::test]
#[cfg(feature = "esplora-async")]
async fn test_esplora_syncs() {
	let (bitcoind, electrsd) = setup_bitcoind_and_electrsd();
	generate_blocks_and_wait(&bitcoind, &electrsd, 101);
	let mut logger = TestLogger::new();
	let esplora_url = format!("http://{}", electrsd.esplora_url.as_ref().unwrap());
	let tx_sync = EsploraSyncClient::new(esplora_url, &mut logger);
	let confirmable = TestConfirmable::new();

	test_syncing!(tx_sync, confirmable, bitcoind, electrsd);
}

#[test]
#[cfg(feature = "electrum")]
fn test_electrum_syncs() {
	let (bitcoind, electrsd) = setup_bitcoind_and_electrsd();
	generate_blocks_and_wait(&bitcoind, &electrsd, 101);
	let mut logger = TestLogger::new();
	let electrum_url = format!("tcp://{}", electrsd.electrum_url);
	let tx_sync = ElectrumSyncClient::new(electrum_url, &mut logger).unwrap();
	let confirmable = TestConfirmable::new();
	test_syncing!(tx_sync, confirmable, bitcoind, electrsd);
}
