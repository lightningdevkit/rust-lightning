// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Various wrapper types (most around 32-byte arrays) for use in lightning.

use crate::chain::transaction::OutPoint;
use crate::io;
use crate::ln::msgs::DecodeError;
use crate::sign::EntropySource;
use crate::util::ser::{Readable, Writeable, Writer};
use super::channel_keys::RevocationBasepoint;

#[allow(unused_imports)]
use crate::prelude::*;

use bitcoin::hashes::{
	Hash as _,
	HashEngine as _,
	sha256::Hash as Sha256,
};
use core::fmt;
use core::ops::Deref;

/// A unique 32-byte identifier for a channel.
/// Depending on how the ID is generated, several varieties are distinguished
/// (but all are stored as 32 bytes):
///   _v1_ and _temporary_.
/// A _v1_ channel ID is generated based on funding tx outpoint (txid & index).
/// A _temporary_ ID is generated randomly.
/// (Later revocation-point-based _v2_ is a possibility.)
/// The variety (context) is not stored, it is relevant only at creation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ChannelId(pub [u8; 32]);

impl ChannelId {
	/// Create _v1_ channel ID based on a funding TX ID and output index
	pub fn v1_from_funding_txid(txid: &[u8; 32], output_index: u16) -> Self {
		let mut res = [0; 32];
		res[..].copy_from_slice(&txid[..]);
		res[30] ^= ((output_index >> 8) & 0xff) as u8;
		res[31] ^= ((output_index >> 0) & 0xff) as u8;
		Self(res)
	}

	/// Create _v1_ channel ID from a funding tx outpoint
	pub fn v1_from_funding_outpoint(outpoint: OutPoint) -> Self {
		Self::v1_from_funding_txid(outpoint.txid.as_byte_array(), outpoint.index)
	}

	/// Create a _temporary_ channel ID randomly, based on an entropy source.
	pub fn temporary_from_entropy_source<ES: Deref>(entropy_source: &ES) -> Self
	where ES::Target: EntropySource {
		Self(entropy_source.get_secure_random_bytes())
	}

	/// Generic constructor; create a new channel ID from the provided data.
	/// Use a more specific `*_from_*` constructor when possible.
	pub fn from_bytes(data: [u8; 32]) -> Self {
		Self(data)
	}

	/// Create a channel ID consisting of all-zeros data (e.g. when uninitialized or a placeholder).
	pub fn new_zero() -> Self {
		Self([0; 32])
	}

	/// Check whether ID is consisting of all zeros (uninitialized)
	pub fn is_zero(&self) -> bool {
		self.0[..] == [0; 32]
	}

	/// Create _v2_ channel ID by concatenating the holder revocation basepoint with the counterparty
	/// revocation basepoint and hashing the result. The basepoints will be concatenated in increasing
	/// sorted order.
	pub fn v2_from_revocation_basepoints(
		ours: &RevocationBasepoint,
		theirs: &RevocationBasepoint,
	) -> Self {
		let ours = ours.0.serialize();
		let theirs = theirs.0.serialize();
		let (lesser, greater) = if ours < theirs {
			(ours, theirs)
		} else {
			(theirs, ours)
		};
		let mut engine = Sha256::engine();
		engine.input(&lesser[..]);
		engine.input(&greater[..]);
		Self(Sha256::from_engine(engine).to_byte_array())
	}

	/// Create temporary _v2_ channel ID by concatenating a zeroed out basepoint with the holder
	/// revocation basepoint and hashing the result.
	pub fn temporary_v2_from_revocation_basepoint(our_revocation_basepoint: &RevocationBasepoint) -> Self {
		Self(Sha256::hash(&[[0u8; 33], our_revocation_basepoint.0.serialize()].concat()).to_byte_array())
	}
}

impl Writeable for ChannelId {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		self.0.write(w)
	}
}

impl Readable for ChannelId {
	fn read<R: io::Read>(r: &mut R) -> Result<Self, DecodeError> {
		let buf: [u8; 32] = Readable::read(r)?;
		Ok(ChannelId(buf))
	}
}

impl fmt::Display for ChannelId {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		crate::util::logger::DebugBytes(&self.0).fmt(f)
	}
}


/// The payment hash is the hash of the [`PaymentPreimage`] which is the value used to lock funds
/// in HTLCs while they transit the lightning network.
///
/// This is not exported to bindings users as we just use [u8; 32] directly
#[derive(Hash, Copy, Clone, PartialEq, Eq, Debug, Ord, PartialOrd)]
pub struct PaymentHash(pub [u8; 32]);

impl core::fmt::Display for PaymentHash {
	fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
		crate::util::logger::DebugBytes(&self.0).fmt(f)
	}
}

/// The payment preimage is the "secret key" which is used to claim the funds of an HTLC on-chain
/// or in a lightning channel.
///
/// This is not exported to bindings users as we just use [u8; 32] directly
#[derive(Hash, Copy, Clone, PartialEq, Eq, Debug, Ord, PartialOrd)]
pub struct PaymentPreimage(pub [u8; 32]);

impl core::fmt::Display for PaymentPreimage {
	fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
		crate::util::logger::DebugBytes(&self.0).fmt(f)
	}
}

/// Converts a `PaymentPreimage` into a `PaymentHash` by hashing the preimage with SHA256.
impl From<PaymentPreimage> for PaymentHash {
	fn from(value: PaymentPreimage) -> Self {
		PaymentHash(Sha256::hash(&value.0).to_byte_array())
	}
}

/// The payment secret is used to authenticate the sender of an HTLC to the recipient and tie
/// multi-part HTLCs together into a single payment.
///
/// This is not exported to bindings users as we just use [u8; 32] directly
#[derive(Hash, Copy, Clone, PartialEq, Eq, Debug, Ord, PartialOrd)]
pub struct PaymentSecret(pub [u8; 32]);

use crate::util::bech32::{Base32Len, Bech32Error, FromBase32, ToBase32, WriteBase32, u5};

impl FromBase32 for PaymentSecret {
	type Err = Bech32Error;

	fn from_base32(field_data: &[u5]) -> Result<PaymentSecret, Bech32Error> {
		if field_data.len() != 52 {
			return Err(Bech32Error::InvalidLength)
		} else {
			let data_bytes = Vec::<u8>::from_base32(field_data)?;
			let mut payment_secret = [0; 32];
			payment_secret.copy_from_slice(&data_bytes);
			Ok(PaymentSecret(payment_secret))
		}
	}
}

impl ToBase32 for PaymentSecret {
	fn write_base32<W: WriteBase32>(&self, writer: &mut W) -> Result<(), <W as WriteBase32>::Err> {
		(&self.0[..]).write_base32(writer)
	}
}

impl Base32Len for PaymentSecret {
	fn base32_len(&self) -> usize {
		52
	}
}

#[cfg(test)]
mod tests {
	use bitcoin::hashes::{
		Hash as _,
		HashEngine as _,
		hex::FromHex as _,
		sha256::Hash as Sha256,
	};
	use bitcoin::secp256k1::PublicKey;
	use hex::DisplayHex;

	use super::ChannelId;
	use crate::ln::channel_keys::RevocationBasepoint;
	use crate::util::ser::{Readable, Writeable};
	use crate::util::test_utils;
	use crate::prelude::*;
	use crate::io;

	#[test]
	fn test_channel_id_v1_from_funding_txid() {
		let channel_id = ChannelId::v1_from_funding_txid(&[2; 32], 1);
		assert_eq!(channel_id.0.as_hex().to_string(), "0202020202020202020202020202020202020202020202020202020202020203");
	}

	#[test]
	fn test_channel_id_new_from_data() {
		let data: [u8; 32] = [2; 32];
		let channel_id = ChannelId::from_bytes(data.clone());
		assert_eq!(channel_id.0, data);
	}

	#[test]
	fn test_channel_id_equals() {
		let channel_id11 = ChannelId::v1_from_funding_txid(&[2; 32], 2);
		let channel_id12 = ChannelId::v1_from_funding_txid(&[2; 32], 2);
		let channel_id21 = ChannelId::v1_from_funding_txid(&[2; 32], 42);
		assert_eq!(channel_id11, channel_id12);
		assert_ne!(channel_id11, channel_id21);
	}

	#[test]
	fn test_channel_id_write_read() {
		let data: [u8; 32] = [2; 32];
		let channel_id = ChannelId::from_bytes(data.clone());

		let mut w = test_utils::TestVecWriter(Vec::new());
		channel_id.write(&mut w).unwrap();

		let channel_id_2 = ChannelId::read(&mut io::Cursor::new(&w.0)).unwrap();
		assert_eq!(channel_id_2, channel_id);
		assert_eq!(channel_id_2.0, data);
	}

	#[test]
	fn test_channel_id_display() {
		let channel_id = ChannelId::v1_from_funding_txid(&[2; 32], 1);
		assert_eq!(format!("{}", &channel_id), "0202020202020202020202020202020202020202020202020202020202020203");
	}

	#[test]
	fn test_channel_id_v2_from_basepoints() {
		// Ours greater than theirs
		let ours = RevocationBasepoint(PublicKey::from_slice(&<Vec<u8>>::from_hex("0324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c").unwrap()[..]).unwrap());
		let theirs = RevocationBasepoint(PublicKey::from_slice(&<Vec<u8>>::from_hex("02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619").unwrap()[..]).unwrap());

		let mut engine = Sha256::engine();
		engine.input(&theirs.0.serialize());
		engine.input(&ours.0.serialize());
		let expected_id = ChannelId(Sha256::from_engine(engine).to_byte_array());

		assert_eq!(ChannelId::v2_from_revocation_basepoints(&ours, &theirs), expected_id);

		// Theirs greater than ours
		let ours = RevocationBasepoint(PublicKey::from_slice(&<Vec<u8>>::from_hex("027f31ebc5462c1fdce1b737ecff52d37d75dea43ce11c74d25aa297165faa2007").unwrap()[..]).unwrap());
		let theirs = RevocationBasepoint(PublicKey::from_slice(&<Vec<u8>>::from_hex("02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619").unwrap()[..]).unwrap());

		let mut engine = Sha256::engine();
		engine.input(&ours.0.serialize());
		engine.input(&theirs.0.serialize());
		let expected_id = ChannelId(Sha256::from_engine(engine).to_byte_array());

		assert_eq!(ChannelId::v2_from_revocation_basepoints(&ours, &theirs), expected_id);
	}
}
