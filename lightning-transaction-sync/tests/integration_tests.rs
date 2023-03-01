#![cfg(any(feature = "esplora-blocking", feature = "esplora-async"))]
use lightning_transaction_sync::EsploraSyncClient;
use lightning::chain::{Confirm, Filter};
use lightning::chain::transaction::TransactionData;
use lightning::util::logger::{Logger, Record};

use electrsd::{bitcoind, bitcoind::BitcoinD, ElectrsD};
use bitcoin::{Amount, Txid, BlockHash, BlockHeader};
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::network::constants::Network;
use electrsd::bitcoind::bitcoincore_rpc::bitcoincore_rpc_json::AddressType;
use bitcoind::bitcoincore_rpc::RpcApi;
use electrum_client::ElectrumApi;

use once_cell::sync::OnceCell;

use std::env;
use std::sync::Mutex;
use std::time::Duration;
use std::collections::{HashMap, HashSet};

static BITCOIND: OnceCell<BitcoinD> = OnceCell::new();
static ELECTRSD: OnceCell<ElectrsD> = OnceCell::new();
static PREMINE: OnceCell<()> = OnceCell::new();
static MINER_LOCK: OnceCell<Mutex<()>> = OnceCell::new();

fn get_bitcoind() -> &'static BitcoinD {
	BITCOIND.get_or_init(|| {
		let bitcoind_exe =
			env::var("BITCOIND_EXE").ok().or_else(|| bitcoind::downloaded_exe_path().ok()).expect(
				"you need to provide an env var BITCOIND_EXE or specify a bitcoind version feature",
				);
		let mut conf = bitcoind::Conf::default();
		conf.network = "regtest";
		let bitcoind = BitcoinD::with_conf(bitcoind_exe, &conf).unwrap();
		std::thread::sleep(Duration::from_secs(1));
		bitcoind
	})
}

fn get_electrsd() -> &'static ElectrsD {
	ELECTRSD.get_or_init(|| {
		let bitcoind = get_bitcoind();
		let electrs_exe =
			env::var("ELECTRS_EXE").ok().or_else(electrsd::downloaded_exe_path).expect(
				"you need to provide env var ELECTRS_EXE or specify an electrsd version feature",
			);
		let mut conf = electrsd::Conf::default();
		conf.http_enabled = true;
		conf.network = "regtest";
		let electrsd = ElectrsD::with_conf(electrs_exe, &bitcoind, &conf).unwrap();
		std::thread::sleep(Duration::from_secs(1));
		electrsd
	})
}

fn generate_blocks_and_wait(num: usize) {
	let miner_lock = MINER_LOCK.get_or_init(|| Mutex::new(()));
	let _miner = miner_lock.lock().unwrap();
	let cur_height = get_bitcoind().client.get_block_count().expect("failed to get current block height");
	let address = get_bitcoind().client.get_new_address(Some("test"), Some(AddressType::Legacy)).expect("failed to get new address");
	// TODO: expect this Result once the WouldBlock issue is resolved upstream.
	let _block_hashes_res = get_bitcoind().client.generate_to_address(num as u64, &address);
	wait_for_block(cur_height as usize + num);
}

fn wait_for_block(min_height: usize) {
	let mut header = match get_electrsd().client.block_headers_subscribe() {
		Ok(header) => header,
		Err(_) => {
			// While subscribing should succeed the first time around, we ran into some cases where
			// it didn't. Since we can't proceed without subscribing, we try again after a delay
			// and panic if it still fails.
			std::thread::sleep(Duration::from_secs(1));
			get_electrsd().client.block_headers_subscribe().expect("failed to subscribe to block headers")
		}
	};

	loop {
		if header.height >= min_height {
			break;
		}
		header = exponential_backoff_poll(|| {
			get_electrsd().trigger().expect("failed to trigger electrsd");
			get_electrsd().client.ping().expect("failed to ping electrsd");
			get_electrsd().client.block_headers_pop().expect("failed to pop block header")
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

fn premine() {
	PREMINE.get_or_init(|| {
		generate_blocks_and_wait(101);
	});
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
	fn transactions_confirmed(&self, header: &BlockHeader, txdata: &TransactionData<'_>, height: u32) {
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

	fn best_block_updated(&self, header: &BlockHeader, height: u32) {
		let block_hash = header.block_hash();
		*self.best_block.lock().unwrap() = (block_hash, height);
		self.events.lock().unwrap().push(TestConfirmableEvent::BestBlockUpdated(block_hash, height));
	}

	fn get_relevant_txids(&self) -> Vec<(Txid, Option<BlockHash>)> {
		self.confirmed_txs.lock().unwrap().iter().map(|(&txid, (hash, _))| (txid, Some(*hash))).collect::<Vec<_>>()
	}
}

pub struct TestLogger {}

impl Logger for TestLogger {
	fn log(&self, record: &Record) {
		println!("{} -- {}",
				record.level,
				record.args);
	}
}

#[test]
#[cfg(feature = "esplora-blocking")]
fn test_esplora_syncs() {
	premine();
	let mut logger = TestLogger {};
	let esplora_url = format!("http://{}", get_electrsd().esplora_url.as_ref().unwrap());
	let tx_sync = EsploraSyncClient::new(esplora_url, &mut logger);
	let confirmable = TestConfirmable::new();

	// Check we pick up on new best blocks
	let expected_height = 0u32;
	assert_eq!(confirmable.best_block.lock().unwrap().1, expected_height);

	tx_sync.sync(vec![&confirmable]).unwrap();

	let expected_height = get_bitcoind().client.get_block_count().unwrap() as u32;
	assert_eq!(confirmable.best_block.lock().unwrap().1, expected_height);

	let events = std::mem::take(&mut *confirmable.events.lock().unwrap());
	assert_eq!(events.len(), 1);

	// Check registered confirmed transactions are marked confirmed
	let new_address = get_bitcoind().client.get_new_address(Some("test"), Some(AddressType::Legacy)).unwrap();
	let txid = get_bitcoind().client.send_to_address(&new_address, Amount::from_sat(5000), None, None, None, None, None, None).unwrap();
	tx_sync.register_tx(&txid, &new_address.script_pubkey());

	tx_sync.sync(vec![&confirmable]).unwrap();

	let events = std::mem::take(&mut *confirmable.events.lock().unwrap());
	assert_eq!(events.len(), 0);
	assert!(confirmable.confirmed_txs.lock().unwrap().is_empty());
	assert!(confirmable.unconfirmed_txs.lock().unwrap().is_empty());

	generate_blocks_and_wait(1);
	tx_sync.sync(vec![&confirmable]).unwrap();

	let events = std::mem::take(&mut *confirmable.events.lock().unwrap());
	assert_eq!(events.len(), 2);
	assert!(confirmable.confirmed_txs.lock().unwrap().contains_key(&txid));
	assert!(confirmable.unconfirmed_txs.lock().unwrap().is_empty());

	// Check previously confirmed transactions are marked unconfirmed when they are reorged.
	let best_block_hash = get_bitcoind().client.get_best_block_hash().unwrap();
	get_bitcoind().client.invalidate_block(&best_block_hash).unwrap();

	// We're getting back to the previous height with a new tip, but best block shouldn't change.
	generate_blocks_and_wait(1);
	assert_ne!(get_bitcoind().client.get_best_block_hash().unwrap(), best_block_hash);
	tx_sync.sync(vec![&confirmable]).unwrap();
	let events = std::mem::take(&mut *confirmable.events.lock().unwrap());
	assert_eq!(events.len(), 0);

	// Now we're surpassing previous height, getting new tip.
	generate_blocks_and_wait(1);
	assert_ne!(get_bitcoind().client.get_best_block_hash().unwrap(), best_block_hash);
	tx_sync.sync(vec![&confirmable]).unwrap();

	// Transaction still confirmed but under new tip.
	assert!(confirmable.confirmed_txs.lock().unwrap().contains_key(&txid));
	assert!(confirmable.unconfirmed_txs.lock().unwrap().is_empty());

	// Check we got unconfirmed, then reconfirmed in the meantime.
	let events = std::mem::take(&mut *confirmable.events.lock().unwrap());
	assert_eq!(events.len(), 3);

	match events[0] {
		TestConfirmableEvent::Unconfirmed(t) => {
			assert_eq!(t, txid);
		},
		_ => panic!("Unexpected event"),
	}

	match events[1] {
		TestConfirmableEvent::BestBlockUpdated(..) => {},
		_ => panic!("Unexpected event"),
	}

	match events[2] {
		TestConfirmableEvent::Confirmed(t, _, _) => {
			assert_eq!(t, txid);
		},
		_ => panic!("Unexpected event"),
	}
}

#[tokio::test]
#[cfg(feature = "esplora-async")]
async fn test_esplora_syncs() {
	premine();
	let mut logger = TestLogger {};
	let esplora_url = format!("http://{}", get_electrsd().esplora_url.as_ref().unwrap());
	let tx_sync = EsploraSyncClient::new(esplora_url, &mut logger);
	let confirmable = TestConfirmable::new();

	// Check we pick up on new best blocks
	let expected_height = 0u32;
	assert_eq!(confirmable.best_block.lock().unwrap().1, expected_height);

	tx_sync.sync(vec![&confirmable]).await.unwrap();

	let expected_height = get_bitcoind().client.get_block_count().unwrap() as u32;
	assert_eq!(confirmable.best_block.lock().unwrap().1, expected_height);

	let events = std::mem::take(&mut *confirmable.events.lock().unwrap());
	assert_eq!(events.len(), 1);

	// Check registered confirmed transactions are marked confirmed
	let new_address = get_bitcoind().client.get_new_address(Some("test"), Some(AddressType::Legacy)).unwrap();
	let txid = get_bitcoind().client.send_to_address(&new_address, Amount::from_sat(5000), None, None, None, None, None, None).unwrap();
	tx_sync.register_tx(&txid, &new_address.script_pubkey());

	tx_sync.sync(vec![&confirmable]).await.unwrap();

	let events = std::mem::take(&mut *confirmable.events.lock().unwrap());
	assert_eq!(events.len(), 0);
	assert!(confirmable.confirmed_txs.lock().unwrap().is_empty());
	assert!(confirmable.unconfirmed_txs.lock().unwrap().is_empty());

	generate_blocks_and_wait(1);
	tx_sync.sync(vec![&confirmable]).await.unwrap();

	let events = std::mem::take(&mut *confirmable.events.lock().unwrap());
	assert_eq!(events.len(), 2);
	assert!(confirmable.confirmed_txs.lock().unwrap().contains_key(&txid));
	assert!(confirmable.unconfirmed_txs.lock().unwrap().is_empty());

	// Check previously confirmed transactions are marked unconfirmed when they are reorged.
	let best_block_hash = get_bitcoind().client.get_best_block_hash().unwrap();
	get_bitcoind().client.invalidate_block(&best_block_hash).unwrap();

	// We're getting back to the previous height with a new tip, but best block shouldn't change.
	generate_blocks_and_wait(1);
	assert_ne!(get_bitcoind().client.get_best_block_hash().unwrap(), best_block_hash);
	tx_sync.sync(vec![&confirmable]).await.unwrap();
	let events = std::mem::take(&mut *confirmable.events.lock().unwrap());
	assert_eq!(events.len(), 0);

	// Now we're surpassing previous height, getting new tip.
	generate_blocks_and_wait(1);
	assert_ne!(get_bitcoind().client.get_best_block_hash().unwrap(), best_block_hash);
	tx_sync.sync(vec![&confirmable]).await.unwrap();

	// Transaction still confirmed but under new tip.
	assert!(confirmable.confirmed_txs.lock().unwrap().contains_key(&txid));
	assert!(confirmable.unconfirmed_txs.lock().unwrap().is_empty());

	// Check we got unconfirmed, then reconfirmed in the meantime.
	let events = std::mem::take(&mut *confirmable.events.lock().unwrap());
	assert_eq!(events.len(), 3);

	match events[0] {
		TestConfirmableEvent::Unconfirmed(t) => {
			assert_eq!(t, txid);
		},
		_ => panic!("Unexpected event"),
	}

	match events[1] {
		TestConfirmableEvent::BestBlockUpdated(..) => {},
		_ => panic!("Unexpected event"),
	}

	match events[2] {
		TestConfirmableEvent::Confirmed(t, _, _) => {
			assert_eq!(t, txid);
		},
		_ => panic!("Unexpected event"),
	}
}
