use lightning::chain::WatchedOutput;
use bitcoin::{Txid, BlockHash, Transaction, BlockHeader, OutPoint};

use std::collections::{HashSet, HashMap};


// Represents the current state.
pub(crate) struct SyncState {
	// Transactions that were previously processed, but must not be forgotten
	// yet since they still need to be monitored for confirmation on-chain.
	pub watched_transactions: HashSet<Txid>,
	// Outputs that were previously processed, but must not be forgotten yet as
	// as we still need to monitor any spends on-chain.
	pub watched_outputs: HashMap<OutPoint, WatchedOutput>,
	// The tip hash observed during our last sync.
	pub last_sync_hash: Option<BlockHash>,
	// Indicates whether we need to resync, e.g., after encountering an error.
	pub pending_sync: bool,
}

impl SyncState {
	pub fn new() -> Self {
		Self {
			watched_transactions: HashSet::new(),
			watched_outputs: HashMap::new(),
			last_sync_hash: None,
			pending_sync: false,
		}
	}
}


// A queue that is to be filled by `Filter` and drained during the next syncing round.
pub(crate) struct FilterQueue {
	// Transactions that were registered via the `Filter` interface and have to be processed.
	pub transactions: HashSet<Txid>,
	// Outputs that were registered via the `Filter` interface and have to be processed.
	pub outputs: HashMap<OutPoint, WatchedOutput>,
}

impl FilterQueue {
	pub fn new() -> Self {
		Self {
			transactions: HashSet::new(),
			outputs: HashMap::new(),
		}
	}

	// Processes the transaction and output queues and adds them to the given [`SyncState`].
	//
	// Returns `true` if new items had been registered.
	pub fn process_queues(&mut self, sync_state: &mut SyncState) -> bool {
		let mut pending_registrations = false;

		if !self.transactions.is_empty() {
			pending_registrations = true;

			sync_state.watched_transactions.extend(self.transactions.drain());
		}

		if !self.outputs.is_empty() {
			pending_registrations = true;

			sync_state.watched_outputs.extend(self.outputs.drain());
		}
		pending_registrations
	}
}

pub(crate) struct ConfirmedTx {
	pub tx: Transaction,
	pub block_header: BlockHeader,
	pub block_height: u32,
	pub pos: usize,
}
