// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Types describing on-chain transactions.

use bitcoin::hash_types::Txid;
use bitcoin::blockdata::transaction::OutPoint as BitcoinOutPoint;
use bitcoin::blockdata::transaction::Transaction;

/// Transaction data where each item consists of a transaction reference paired with the index of
/// the transaction within a block.
///
/// Useful for passing enumerated transactions from a block, possibly filtered, in order to retain
/// the transaction index.
///
/// ```
/// extern crate bitcoin;
/// extern crate lightning;
///
/// use bitcoin::blockdata::block::Block;
/// use bitcoin::blockdata::constants::genesis_block;
/// use bitcoin::network::constants::Network;
/// use lightning::chain::transaction::TransactionData;
///
/// let block = genesis_block(Network::Bitcoin);
/// let txdata: Vec<_> = block.txdata.iter().enumerate().collect();
/// check_block(&block, &txdata);
///
/// fn check_block(block: &Block, txdata: &TransactionData) {
/// 	assert_eq!(block.txdata.len(), 1);
/// 	assert_eq!(txdata.len(), 1);
///
/// 	let (index, tx) = txdata[0];
/// 	assert_eq!(index, 0);
/// 	assert_eq!(tx, &block.txdata[0]);
/// }
/// ```
pub type TransactionData<'a> = [(usize, &'a Transaction)];

/// A reference to a transaction output.
///
/// Differs from bitcoin::blockdata::transaction::OutPoint as the index is a u16 instead of u32
/// due to LN's restrictions on index values. Should reduce (possibly) unsafe conversions this way.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct OutPoint {
	/// The referenced transaction's txid.
	pub txid: Txid,
	/// The index of the referenced output in its transaction's vout.
	pub index: u16,
}

impl OutPoint {
	/// Convert an `OutPoint` to a lightning channel id.
	pub fn to_channel_id(&self) -> [u8; 32] {
		let mut res = [0; 32];
		res[..].copy_from_slice(&self.txid[..]);
		res[30] ^= ((self.index >> 8) & 0xff) as u8;
		res[31] ^= ((self.index >> 0) & 0xff) as u8;
		res
	}

	/// Converts this OutPoint into the OutPoint field as used by rust-bitcoin
	/// (C-not exported) as the same type is used universally in the C bindings for all outpoints
	pub fn into_bitcoin_outpoint(self) -> BitcoinOutPoint {
		BitcoinOutPoint {
			txid: self.txid,
			vout: self.index as u32,
		}
	}
}

impl_writeable!(OutPoint, { txid, index });

#[cfg(test)]
mod tests {
	use crate::chain::transaction::OutPoint;

	use bitcoin::blockdata::transaction::Transaction;
	use bitcoin::consensus::encode;

	use hex;

	#[test]
	fn test_channel_id_calculation() {
		let tx: Transaction = encode::deserialize(&hex::decode("020000000001010e0adef48412e4361325ac1c6e36411299ab09d4f083b9d8ddb55fbc06e1b0c00000000000feffffff0220a1070000000000220020f81d95e040bd0a493e38bae27bff52fe2bb58b93b293eb579c01c31b05c5af1dc072cfee54a3000016001434b1d6211af5551905dc2642d05f5b04d25a8fe80247304402207f570e3f0de50546aad25a872e3df059d277e776dda4269fa0d2cc8c2ee6ec9a022054e7fae5ca94d47534c86705857c24ceea3ad51c69dd6051c5850304880fc43a012103cb11a1bacc223d98d91f1946c6752e358a5eb1a1c983b3e6fb15378f453b76bd00000000").unwrap()[..]).unwrap();
		assert_eq!(&OutPoint {
			txid: tx.txid(),
			index: 0
		}.to_channel_id(), &hex::decode("3e88dd7165faf7be58b3c5bb2c9c452aebef682807ea57080f62e6f6e113c25e").unwrap()[..]);
		assert_eq!(&OutPoint {
			txid: tx.txid(),
			index: 1
		}.to_channel_id(), &hex::decode("3e88dd7165faf7be58b3c5bb2c9c452aebef682807ea57080f62e6f6e113c25f").unwrap()[..]);
	}
}
