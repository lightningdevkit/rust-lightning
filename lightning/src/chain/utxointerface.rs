//! Trait which allow others parts of rust-lightning to manage CPFP candidates
//! utxos for increasing feerate of time-sensitive transactions.


use bitcoin::blockdata::transaction::OutPoint as BitcoinOutPoint;
use bitcoin::blockdata::transaction::Transaction;

use ln::onchain_utils::BumpingOutput;

/// A trait which sould be implemented to provide fresh CPFP utxo for onchain
/// transactions.
///
/// Implementation MUST provision and bookmarked utxo correctly to ensure LN
/// channel security in case of adversarial counterparty or unfavorable mempool
/// congestion.
//TODO: document better
pub trait UtxoPool: Sync + Send {
	/// Allocate a utxo to cover fee required to confirm a pending onchain transaction.
	fn allocate_utxo(&self, required_fee: u64) -> Option<(BitcoinOutPoint, BumpingOutput)>;
	/// Free a utxo. Call in case of reorg or counterparty claiming the output first.
	fn free_utxo(&self, free_utxo: BitcoinOutPoint);
	/// Provide a witness for the bumping utxo
	fn provide_utxo_witness(&self, cpfp_transaction: &Transaction, utxo_index: u32) -> Result<Vec<Vec<u8>>, ()>;
}
