//! Contains simple structs describing parts of transactions on the chain.

use bitcoin_hashes::sha256d::Hash as Sha256dHash;
use bitcoin::blockdata::transaction::OutPoint as BitcoinOutPoint;

/// A reference to a transaction output.
///
/// Differs from bitcoin::blockdata::transaction::OutPoint as the index is a u16 instead of u32
/// due to LN's restrictions on index values. Should reduce (possibly) unsafe conversions this way.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct OutPoint {
	/// The referenced transaction's txid.
	pub txid: Sha256dHash,
	/// The index of the referenced output in its transaction's vout.
	pub index: u16,
}

impl OutPoint {
	/// Creates a new `OutPoint` from the txid and the index.
	pub fn new(txid: Sha256dHash, index: u16) -> OutPoint {
		OutPoint { txid, index }
	}

	/// Convert an `OutPoint` to a lightning channel id.
	pub fn to_channel_id(&self) -> [u8; 32] {
		let mut res = [0; 32];
		res[..].copy_from_slice(&self.txid[..]);
		res[30] ^= ((self.index >> 8) & 0xff) as u8;
		res[31] ^= ((self.index >> 0) & 0xff) as u8;
		res
	}

	/// Converts this OutPoint into the OutPoint field as used by rust-bitcoin
	pub fn into_bitcoin_outpoint(self) -> BitcoinOutPoint {
		BitcoinOutPoint {
			txid: self.txid,
			vout: self.index as u32,
		}
	}
}

#[cfg(test)]
mod tests {
	use chain::transaction::OutPoint;

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
