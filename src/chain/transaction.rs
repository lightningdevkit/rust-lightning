use bitcoin::util::hash::Sha256dHash;
use bitcoin::util::uint::Uint256;

/// A reference to a transaction output.
/// Differs from bitcoin::blockdata::transaction::TxOutRef as the index is a u16 instead of usize
/// due to LN's restrictions on index values. Should reduce (possibly) unsafe conversions this way.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct OutPoint {
	/// The referenced transaction's txid.
	pub txid: Sha256dHash,
	/// The index of the referenced output in its transaction's vout.
	pub index: u16,
}

impl OutPoint {
	/// Creates a new `OutPoint` from the txid an the index.
	pub fn new(txid: Sha256dHash, index: u16) -> OutPoint {
		OutPoint { txid, index }
	}

	/// Convert an `OutPoint` to a lightning channel id.
	pub fn to_channel_id(&self) -> Uint256 {
		let mut index = [0; 32];
		index[30] = ((self.index >> 8) & 0xff) as u8;
		index[31] = ((self.index >> 0) & 0xff) as u8;
		self.txid.into_le() ^ Sha256dHash::from(&index[..]).into_le()
	}
}
