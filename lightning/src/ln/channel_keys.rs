// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Keys used to generate commitment transactions.
//! See: <https://github.com/lightning/bolts/blob/master/03-transactions.md#keys>

use crate::io;
use crate::ln::msgs::DecodeError;
use crate::util::ser::Readable;
use crate::util::ser::Writeable;
use crate::util::ser::Writer;
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::Hash;
use bitcoin::hashes::HashEngine;
use bitcoin::secp256k1;
use bitcoin::secp256k1::PublicKey;
use bitcoin::secp256k1::Scalar;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::secp256k1::SecretKey;

macro_rules! doc_comment {
	($x:expr, $($tt:tt)*) => {
		#[doc = $x]
		$($tt)*
	};
}
macro_rules! basepoint_impl {
	($BasepointT:ty $(, $KeyName: expr)?) => {
		impl $BasepointT {
			/// Get inner Public Key
			pub fn to_public_key(&self) -> PublicKey {
				self.0
			}

			$(doc_comment!(
				concat!(
				"Derives the \"tweak\" used in calculate [`", $KeyName, "::from_basepoint`].\n",
				"\n",
				"[`", $KeyName, "::from_basepoint`] calculates a private key as:\n",
				"`privkey = basepoint_secret + SHA256(per_commitment_point || basepoint)`\n",
				"\n",
				"This calculates the hash part in the tweak derivation process, which is used to\n",
				"ensure that each key is unique and cannot be guessed by an external party."
				),
				pub fn derive_add_tweak(&self, per_commitment_point: &PublicKey) -> Sha256 {
					let mut sha = Sha256::engine();
					sha.input(&per_commitment_point.serialize());
					sha.input(&self.to_public_key().serialize());
					Sha256::from_engine(sha)
				});
			)?
		}

		impl From<PublicKey> for $BasepointT {
			fn from(value: PublicKey) -> Self {
				Self(value)
			}
		}
	};
}
macro_rules! key_impl {
	($BasepointT:ty, $KeyName:expr) => {
		doc_comment! {
			concat!("Derive a public ", $KeyName, " using one node's `per_commitment_point` and its countersignatory's `basepoint`"),
			pub fn from_basepoint<T: secp256k1::Signing>(
				secp_ctx: &Secp256k1<T>,
				countersignatory_basepoint: &$BasepointT,
				per_commitment_point: &PublicKey,
			) -> Self {
				Self(derive_public_key(secp_ctx, per_commitment_point, &countersignatory_basepoint.0))
			}
		}

		doc_comment! {
			concat!("Build a ", $KeyName, " directly from an already-derived private key"),
			pub fn from_secret_key<T: secp256k1::Signing>(secp_ctx: &Secp256k1<T>, sk: &SecretKey) -> Self {
				Self(PublicKey::from_secret_key(&secp_ctx, &sk))
			}
		}

		/// Get inner Public Key
		pub fn to_public_key(&self) -> PublicKey {
			self.0
		}
	}
}
macro_rules! key_read_write {
	($SelfT:ty) => {
		impl Writeable for $SelfT {
			fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
				self.0.serialize().write(w)
			}
		}

		impl Readable for $SelfT {
			fn read<R: io::Read>(r: &mut R) -> Result<Self, DecodeError> {
				let key: PublicKey = Readable::read(r)?;
				Ok(Self(key))
			}
		}
	};
}

/// Base key used in conjunction with a `per_commitment_point` to generate a [`DelayedPaymentKey`].
///
/// The delayed payment key is used to pay the commitment state broadcaster their
/// non-HTLC-encumbered funds after a delay to give their counterparty a chance to punish if the
/// state broadcasted was previously revoked.
#[derive(PartialEq, Eq, Clone, Copy, Debug, Hash)]
pub struct DelayedPaymentBasepoint(pub PublicKey);
basepoint_impl!(DelayedPaymentBasepoint, "DelayedPaymentKey");
key_read_write!(DelayedPaymentBasepoint);

/// A derived key built from a [`DelayedPaymentBasepoint`] and `per_commitment_point`.
///
/// The delayed payment key is used to pay the commitment state broadcaster their
/// non-HTLC-encumbered funds after a delay. This delay gives their counterparty a chance to
/// punish and claim all the channel funds if the state broadcasted was previously revoked.
///
/// [See the BOLT specs]
/// (https://github.com/lightning/bolts/blob/master/03-transactions.md#localpubkey-local_htlcpubkey-remote_htlcpubkey-local_delayedpubkey-and-remote_delayedpubkey-derivation)
/// for more information on key derivation details.
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub struct DelayedPaymentKey(pub PublicKey);

impl DelayedPaymentKey {
	key_impl!(DelayedPaymentBasepoint, "delayedpubkey");
}
key_read_write!(DelayedPaymentKey);

/// Base key used in conjunction with a `per_commitment_point` to generate an [`HtlcKey`].
///
/// HTLC keys are used to ensure only the recipient of an HTLC can claim it on-chain with the HTLC
/// preimage and that only the sender of an HTLC can claim it on-chain after it has timed out.
/// Thus, both channel counterparties' HTLC keys will appears in each HTLC output's script.
#[derive(PartialEq, Eq, Clone, Copy, Debug, Hash)]
pub struct HtlcBasepoint(pub PublicKey);
basepoint_impl!(HtlcBasepoint, "HtlcKey");
key_read_write!(HtlcBasepoint);

/// A derived key built from a [`HtlcBasepoint`] and `per_commitment_point`.
///
/// HTLC keys are used to ensure only the recipient of an HTLC can claim it on-chain with the HTLC
/// preimage and that only the sender of an HTLC can claim it on-chain after it has timed out.
/// Thus, both channel counterparties' HTLC keys will appears in each HTLC output's script.
///
/// [See the BOLT specs]
/// (https://github.com/lightning/bolts/blob/master/03-transactions.md#localpubkey-local_htlcpubkey-remote_htlcpubkey-local_delayedpubkey-and-remote_delayedpubkey-derivation)
/// for more information on key derivation details.
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub struct HtlcKey(pub PublicKey);

impl HtlcKey {
	key_impl!(HtlcBasepoint, "htlcpubkey");
}
key_read_write!(HtlcKey);

/// Derives a per-commitment-transaction public key (eg an htlc key or a delayed_payment key)
/// from the base point and the per_commitment_key. This is the public equivalent of
/// derive_private_key - using only public keys to derive a public key instead of private keys.
fn derive_public_key<T: secp256k1::Signing>(
	secp_ctx: &Secp256k1<T>, per_commitment_point: &PublicKey, base_point: &PublicKey,
) -> PublicKey {
	let mut sha = Sha256::engine();
	sha.input(&per_commitment_point.serialize());
	sha.input(&base_point.serialize());
	let res = Sha256::from_engine(sha);

	add_public_key_tweak(secp_ctx, base_point, &res)
}

/// Adds a tweak to a public key to derive a new public key.
///
/// May panic if `tweak` is not the output of a SHA-256 hash.
pub fn add_public_key_tweak<T: secp256k1::Signing>(
	secp_ctx: &Secp256k1<T>, base_point: &PublicKey, tweak: &Sha256,
) -> PublicKey {
	let hashkey = PublicKey::from_secret_key(
		&secp_ctx,
		&SecretKey::from_slice(tweak.as_byte_array())
			.expect("Hashes should always be valid keys unless SHA-256 is broken"),
	);
	base_point.combine(&hashkey)
		.expect("Addition only fails if the tweak is the inverse of the key. This is not possible when the tweak contains the hash of the key.")
}

/// Master key used in conjunction with per_commitment_point to generate [htlcpubkey](https://github.com/lightning/bolts/blob/master/03-transactions.md#key-derivation) for the latest state of a channel.
/// A watcher can be given a [RevocationBasepoint] to generate per commitment [RevocationKey] to create justice transactions.
#[derive(PartialEq, Eq, Clone, Copy, Debug, Hash)]
pub struct RevocationBasepoint(pub PublicKey);
basepoint_impl!(RevocationBasepoint);
key_read_write!(RevocationBasepoint);

/// The revocation key is used to allow a channel party to revoke their state - giving their
/// counterparty the required material to claim all of their funds if they broadcast that state.
///
/// Each commitment transaction has a revocation key based on the basepoint and
/// per_commitment_point which is used in both commitment and HTLC transactions.
///
/// See [the BOLT spec for derivation details]
/// (https://github.com/lightning/bolts/blob/master/03-transactions.md#revocationpubkey-derivation)
#[derive(PartialEq, Eq, Clone, Copy, Debug, Hash)]
pub struct RevocationKey(pub PublicKey);

impl RevocationKey {
	/// Derives a per-commitment-transaction revocation public key from one party's per-commitment
	/// point and the other party's [`RevocationBasepoint`]. This is the public equivalent of
	/// [`chan_utils::derive_private_revocation_key`] - using only public keys to derive a public
	/// key instead of private keys.
	///
	/// Note that this is infallible iff we trust that at least one of the two input keys are randomly
	/// generated (ie our own).
	///
	/// [`chan_utils::derive_private_revocation_key`]: crate::ln::chan_utils::derive_private_revocation_key
	pub fn from_basepoint<T: secp256k1::Verification>(
		secp_ctx: &Secp256k1<T>, countersignatory_basepoint: &RevocationBasepoint,
		per_commitment_point: &PublicKey,
	) -> Self {
		let rev_append_commit_hash_key = {
			let mut sha = Sha256::engine();
			sha.input(&countersignatory_basepoint.to_public_key().serialize());
			sha.input(&per_commitment_point.serialize());

			Sha256::from_engine(sha).to_byte_array()
		};
		let commit_append_rev_hash_key = {
			let mut sha = Sha256::engine();
			sha.input(&per_commitment_point.serialize());
			sha.input(&countersignatory_basepoint.to_public_key().serialize());

			Sha256::from_engine(sha).to_byte_array()
		};

		let countersignatory_contrib = countersignatory_basepoint.to_public_key().mul_tweak(&secp_ctx, &Scalar::from_be_bytes(rev_append_commit_hash_key).unwrap())
			.expect("Multiplying a valid public key by a hash is expected to never fail per secp256k1 docs");
		let broadcaster_contrib = (&per_commitment_point).mul_tweak(&secp_ctx, &Scalar::from_be_bytes(commit_append_rev_hash_key).unwrap())
			.expect("Multiplying a valid public key by a hash is expected to never fail per secp256k1 docs");
		let pk = countersignatory_contrib.combine(&broadcaster_contrib)
			.expect("Addition only fails if the tweak is the inverse of the key. This is not possible when the tweak commits to the key.");
		Self(pk)
	}

	/// Get inner Public Key
	pub fn to_public_key(&self) -> PublicKey {
		self.0
	}
}
key_read_write!(RevocationKey);

#[cfg(test)]
mod test {
	use super::derive_public_key;
	use bitcoin::hashes::hex::FromHex;
	use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};

	#[test]
	fn test_key_derivation() {
		// Test vectors from BOLT 3 Appendix E:
		let secp_ctx = Secp256k1::new();

		let base_secret = SecretKey::from_slice(
			&<Vec<u8>>::from_hex(
				"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
			)
			.unwrap()[..],
		)
		.unwrap();
		let per_commitment_secret = SecretKey::from_slice(
			&<Vec<u8>>::from_hex(
				"1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100",
			)
			.unwrap()[..],
		)
		.unwrap();

		let base_point = PublicKey::from_secret_key(&secp_ctx, &base_secret);
		assert_eq!(
			base_point.serialize()[..],
			<Vec<u8>>::from_hex(
				"036d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a95b216691468e2"
			)
			.unwrap()[..]
		);

		let per_commitment_point = PublicKey::from_secret_key(&secp_ctx, &per_commitment_secret);
		assert_eq!(
			per_commitment_point.serialize()[..],
			<Vec<u8>>::from_hex(
				"025f7117a78150fe2ef97db7cfc83bd57b2e2c0d0dd25eaf467a4a1c2a45ce1486"
			)
			.unwrap()[..]
		);

		assert_eq!(
			derive_public_key(&secp_ctx, &per_commitment_point, &base_point).serialize()[..],
			<Vec<u8>>::from_hex(
				"0235f2dbfaa89b57ec7b055afe29849ef7ddfeb1cefdb9ebdc43f5494984db29e5"
			)
			.unwrap()[..]
		);
	}
}
