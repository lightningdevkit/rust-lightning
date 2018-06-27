use bitcoin::util::hash::Sha256dHash;
use bitcoin::util::uint::Uint256;

/// A reference to a transaction output.
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
        // TODO: or le?
        self.txid.into_be() ^ Uint256::from_u64(self.index as u64).unwrap()
    }
}
