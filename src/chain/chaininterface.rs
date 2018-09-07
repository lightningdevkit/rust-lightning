use bitcoin::blockdata::block::{Block, BlockHeader};
use bitcoin::blockdata::transaction::Transaction;
use bitcoin::blockdata::script::Script;
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::util::hash::Sha256dHash;
use bitcoin::network::constants::Network;
use bitcoin::network::serialize::BitcoinHash;
use util::logger::Logger;
use std::sync::{Mutex,Weak,MutexGuard,Arc};
use std::sync::atomic::{AtomicUsize, Ordering};

/// Used to give chain error details upstream
pub enum ChainError {
	/// Client doesn't support UTXO lookup (but the chain hash matches our genesis block hash)
	NotSupported,
	/// Chain isn't the one watched
	NotWatched,
	/// Tx doesn't exist or is unconfirmed
	UnknownTx,
}

/// An interface to request notification of certain scripts as they appear the
/// chain.
/// Note that all of the functions implemented here *must* be reentrant-safe (obviously - they're
/// called from inside the library in response to ChainListener events, P2P events, or timer
/// events).
pub trait ChainWatchInterface: Sync + Send {
	/// Provides a txid/random-scriptPubKey-in-the-tx which much be watched for.
	fn install_watch_tx(&self, txid: &Sha256dHash, script_pub_key: &Script);

	/// Provides an outpoint which must be watched for, providing any transactions which spend the
	/// given outpoint.
	fn install_watch_outpoint(&self, outpoint: (Sha256dHash, u32), out_script: &Script);

	/// Indicates that a listener needs to see all transactions.
	fn watch_all_txn(&self);

	fn register_listener(&self, listener: Weak<ChainListener>);
	//TODO: unregister

	/// Gets the script and value in satoshis for a given unspent transaction output given a
	/// short_channel_id (aka unspent_tx_output_identier). For BTC/tBTC channels the top three
	/// bytes are the block height, the next 3 the transaction index within the block, and the
	/// final two the output within the transaction.
	fn get_chain_utxo(&self, genesis_hash: Sha256dHash, unspent_tx_output_identifier: u64) -> Result<(Script, u64), ChainError>;
}

/// An interface to send a transaction to the Bitcoin network.
pub trait BroadcasterInterface: Sync + Send {
	/// Sends a transaction out to (hopefully) be mined.
	fn broadcast_transaction(&self, tx: &Transaction);
}

/// A trait indicating a desire to listen for events from the chain
pub trait ChainListener: Sync + Send {
	/// Notifies a listener that a block was connected.
	/// Note that if a new transaction/outpoint is watched during a block_connected call, the block
	/// *must* be re-scanned with the new transaction/outpoints and block_connected should be
	/// called again with the same header and (at least) the new transactions.
	/// This also means those counting confirmations using block_connected callbacks should watch
	/// for duplicate headers and not count them towards confirmations!
	fn block_connected(&self, header: &BlockHeader, height: u32, txn_matched: &[&Transaction], indexes_of_txn_matched: &[u32]);
	/// Notifies a listener that a block was disconnected.
	/// Unlike block_connected, this *must* never be called twice for the same disconnect event.
	fn block_disconnected(&self, header: &BlockHeader);
}

pub enum ConfirmationTarget {
	Background,
	Normal,
	HighPriority,
}

/// A trait which should be implemented to provide feerate information on a number of time
/// horizons.
/// Note that all of the functions implemented here *must* be reentrant-safe (obviously - they're
/// called from inside the library in response to ChainListener events, P2P events, or timer
/// events).
pub trait FeeEstimator: Sync + Send {
	/// Gets estimated satoshis of fee required per 1000 Weight-Units. This translates to:
	///  * satoshis-per-byte * 250
	///  * ceil(satoshis-per-kbyte / 4)
	/// Must be no smaller than 253 (ie 1 satoshi-per-byte rounded up to ensure later round-downs
	/// don't put us below 1 satoshi-per-byte).
	fn get_est_sat_per_1000_weight(&self, confirmation_target: ConfirmationTarget) -> u64;
}

/// Utility to capture some common parts of ChainWatchInterface implementors.
/// Keeping a local copy of this in a ChainWatchInterface implementor is likely useful.
pub struct ChainWatchInterfaceUtil {
	network: Network,
	watched: Mutex<(Vec<Script>, Vec<(Sha256dHash, u32)>, bool)>, //TODO: Something clever to optimize this
	listeners: Mutex<Vec<Weak<ChainListener>>>,
	reentered: AtomicUsize,
	logger: Arc<Logger>,
}

/// Register listener
impl ChainWatchInterface for ChainWatchInterfaceUtil {
	fn install_watch_tx(&self, _txid: &Sha256dHash, script_pub_key: &Script) {
		let mut watched = self.watched.lock().unwrap();
		watched.0.push(script_pub_key.clone());
		self.reentered.fetch_add(1, Ordering::Relaxed);
	}

	fn install_watch_outpoint(&self, outpoint: (Sha256dHash, u32), _out_script: &Script) {
		let mut watched = self.watched.lock().unwrap();
		watched.1.push(outpoint);
		self.reentered.fetch_add(1, Ordering::Relaxed);
	}

	fn watch_all_txn(&self) {
		let mut watched = self.watched.lock().unwrap();
		watched.2 = true;
		self.reentered.fetch_add(1, Ordering::Relaxed);
	}

	fn register_listener(&self, listener: Weak<ChainListener>) {
		let mut vec = self.listeners.lock().unwrap();
		vec.push(listener);
	}

	fn get_chain_utxo(&self, genesis_hash: Sha256dHash, _unspent_tx_output_identifier: u64) -> Result<(Script, u64), ChainError> {
		if genesis_hash != genesis_block(self.network).header.bitcoin_hash() {
			return Err(ChainError::NotWatched);
		}
		Err(ChainError::NotSupported)
	}
}

impl ChainWatchInterfaceUtil {
	pub fn new(network: Network, logger: Arc<Logger>) -> ChainWatchInterfaceUtil {
		ChainWatchInterfaceUtil {
			network: network,
			watched: Mutex::new((Vec::new(), Vec::new(), false)),
			listeners: Mutex::new(Vec::new()),
			reentered: AtomicUsize::new(1),
			logger: logger,
		}
	}

	/// Notify listeners that a block was connected given a full, unfiltered block.
	/// Handles re-scanning the block and calling block_connected again if listeners register new
	/// watch data during the callbacks for you (see ChainListener::block_connected for more info).
	pub fn block_connected_with_filtering(&self, block: &Block, height: u32) {
		let mut reentered = true;
		while reentered {
			let mut matched = Vec::new();
			let mut matched_index = Vec::new();
			{
				let watched = self.watched.lock().unwrap();
				for (index, transaction) in block.txdata.iter().enumerate() {
					if self.does_match_tx_unguarded(transaction, &watched) {
						matched.push(transaction);
						matched_index.push(index as u32);
					}
				}
			}
			reentered = self.block_connected_checked(&block.header, height, matched.as_slice(), matched_index.as_slice());
		}
	}

	/// Notify listeners that a block was disconnected.
	pub fn block_disconnected(&self, header: &BlockHeader) {
		let listeners = self.listeners.lock().unwrap().clone();
		for listener in listeners.iter() {
			match listener.upgrade() {
				Some(arc) => arc.block_disconnected(header),
				None => ()
			}
		}
	}

	/// Notify listeners that a block was connected, given pre-filtered list of transactions in the
	/// block which matched the filter (probably using does_match_tx).
	/// Returns true if notified listeners registered additional watch data (implying that the
	/// block must be re-scanned and this function called again prior to further block_connected
	/// calls, see ChainListener::block_connected for more info).
	pub fn block_connected_checked(&self, header: &BlockHeader, height: u32, txn_matched: &[&Transaction], indexes_of_txn_matched: &[u32]) -> bool {
		let last_seen = self.reentered.load(Ordering::Relaxed);

		let listeners = self.listeners.lock().unwrap().clone();
		for listener in listeners.iter() {
			match listener.upgrade() {
				Some(arc) => arc.block_connected(header, height, txn_matched, indexes_of_txn_matched),
				None => ()
			}
		}
		return last_seen != self.reentered.load(Ordering::Relaxed);
	}

	/// Checks if a given transaction matches the current filter.
	pub fn does_match_tx(&self, tx: &Transaction) -> bool {
		let watched = self.watched.lock().unwrap();
		self.does_match_tx_unguarded (tx, &watched)
	}

	fn does_match_tx_unguarded(&self, tx: &Transaction, watched: &MutexGuard<(Vec<Script>, Vec<(Sha256dHash, u32)>, bool)>) -> bool {
		if watched.2 {
			return true;
		}
		for out in tx.output.iter() {
			for script in watched.0.iter() {
				if script[..] == out.script_pubkey[..] {
					return true;
				}
			}
		}
		for input in tx.input.iter() {
			for outpoint in watched.1.iter() {
				let &(outpoint_hash, outpoint_index) = outpoint;
				if outpoint_hash == input.previous_output.txid && outpoint_index == input.previous_output.vout {
					return true;
				}
			}
		}
		false
	}
}
