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

use bitcoin::hashes::Hash;
use bitcoin::hashes::HashEngine;
use bitcoin::secp256k1::Scalar;
use bitcoin::secp256k1::SecretKey;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::secp256k1;
use crate::ln::msgs::DecodeError;
use crate::util::ser::Readable;
use crate::io;
use crate::util::ser::Writer;
use crate::util::ser::Writeable;
use bitcoin::secp256k1::PublicKey;
use bitcoin::hashes::sha256::Hash as Sha256;

macro_rules! doc_comment {
    ($x:expr, $($tt:tt)*) => {
        #[doc = $x]
        $($tt)*
    };
}
macro_rules! basepoint_impl {
    ($BasepointT:ty) => {
        impl $BasepointT {
            /// Get inner Public Key
            pub fn to_public_key(&self) -> PublicKey {
                self.0
            }
        }
        
        impl From<PublicKey> for $BasepointT {
            fn from(value: PublicKey) -> Self {
                Self(value)
            }
        }
        
    }
}
macro_rules! key_impl {
    ($BasepointT:ty, $KeyName:expr) => {
        doc_comment! {
            concat!("Generate ", $KeyName, " using per_commitment_point"),
            pub fn from_basepoint<T: secp256k1::Signing>(
                secp_ctx: &Secp256k1<T>,
                basepoint: &$BasepointT,
                per_commitment_point: &PublicKey,
            ) -> Self {
                Self(derive_public_key(secp_ctx, per_commitment_point, &basepoint.0))
            }
        }
        
        doc_comment! {
            concat!("Generate ", $KeyName, " from privkey"),
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
    }
}



/// Master key used in conjunction with per_commitment_point to generate [`local_delayedpubkey`](https://github.com/lightning/bolts/blob/master/03-transactions.md#key-derivation) for the latest state of a channel.
/// A watcher can be given a [DelayedPaymentBasepoint] to generate per commitment [DelayedPaymentKey] to create justice transactions.
#[derive(PartialEq, Eq, Clone, Copy, Debug, Hash)]
pub struct DelayedPaymentBasepoint(pub PublicKey);
basepoint_impl!(DelayedPaymentBasepoint);
key_read_write!(DelayedPaymentBasepoint);

/// [delayedpubkey](https://github.com/lightning/bolts/blob/master/03-transactions.md#localpubkey-local_htlcpubkey-remote_htlcpubkey-local_delayedpubkey-and-remote_delayedpubkey-derivation)
/// To allow a counterparty to contest a channel state published by a node, Lightning protocol sets delays for some of the outputs, before can be spend.
/// For example a commitment transaction has to_local output encumbered by a delay, negotiated at the channel establishment flow.
/// To spend from such output a node has to generate a script using, among others, a local delayed payment key.
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub struct DelayedPaymentKey(pub PublicKey);

impl DelayedPaymentKey {
    key_impl!(DelayedPaymentBasepoint, "delayedpubkey");
}
key_read_write!(DelayedPaymentKey);

/// Master key used in conjunction with per_commitment_point to generate a [localpubkey](https://github.com/lightning/bolts/blob/master/03-transactions.md#key-derivation) for the latest state of a channel.
/// Also used to generate a commitment number in a commitment transaction or as a Payment Key for a remote node (not us) in an anchor output if `option_static_remotekey` is enabled.
/// Shared by both nodes in a channel establishment message flow.
#[derive(PartialEq, Eq, Clone, Copy, Debug, Hash)]
pub struct PaymentBasepoint(pub PublicKey);
basepoint_impl!(PaymentBasepoint);
key_read_write!(PaymentBasepoint);


/// [localpubkey](https://github.com/lightning/bolts/blob/master/03-transactions.md#localpubkey-local_htlcpubkey-remote_htlcpubkey-local_delayedpubkey-and-remote_delayedpubkey-derivation) is a child key of a payment basepoint,
/// that enables a secure hash-lock for off-chain payments without risk of funds getting stuck or stolen. A payment key is normally shared with a counterparty so that it can generate 
/// a commitment transaction's to_remote ouput, which our node can claim in case the counterparty force closes the channel.
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub struct PaymentKey(pub PublicKey);

impl PaymentKey {
    key_impl!(PaymentBasepoint, "localpubkey");
}
key_read_write!(PaymentKey);

/// Master key used in conjunction with per_commitment_point to generate [htlcpubkey](https://github.com/lightning/bolts/blob/master/03-transactions.md#key-derivation) for the latest state of a channel.
#[derive(PartialEq, Eq, Clone, Copy, Debug, Hash)]
pub struct HtlcBasepoint(pub PublicKey);
basepoint_impl!(HtlcBasepoint);
key_read_write!(HtlcBasepoint);


/// [htlcpubkey](https://github.com/lightning/bolts/blob/master/03-transactions.md#localpubkey-local_htlcpubkey-remote_htlcpubkey-local_delayedpubkey-and-remote_delayedpubkey-derivation) is a child key of an htlc basepoint,
/// that enables secure routing of payments in onion scheme without a risk of them getting stuck or diverted. It is used to claim the funds in successful or timed out htlc outputs.
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub struct HtlcKey(pub PublicKey);

impl HtlcKey {
    key_impl!(HtlcBasepoint, "htlcpubkey");
}
key_read_write!(HtlcKey);

/// Derives a per-commitment-transaction public key (eg an htlc key or a delayed_payment key)
/// from the base point and the per_commitment_key. This is the public equivalent of
/// derive_private_key - using only public keys to derive a public key instead of private keys.
fn derive_public_key<T: secp256k1::Signing>(secp_ctx: &Secp256k1<T>, per_commitment_point: &PublicKey, base_point: &PublicKey) -> PublicKey {
	let mut sha = Sha256::engine();
	sha.input(&per_commitment_point.serialize());
	sha.input(&base_point.serialize());
	let res = Sha256::from_engine(sha).to_byte_array();
    

	let hashkey = PublicKey::from_secret_key(&secp_ctx,
		&SecretKey::from_slice(&res).expect("Hashes should always be valid keys unless SHA-256 is broken"));
	base_point.combine(&hashkey)
		.expect("Addition only fails if the tweak is the inverse of the key. This is not possible when the tweak contains the hash of the key.")
}

/// Master key used in conjunction with per_commitment_point to generate [htlcpubkey](https://github.com/lightning/bolts/blob/master/03-transactions.md#key-derivation) for the latest state of a channel.
/// A watcher can be given a [RevocationBasepoint] to generate per commitment [RevocationKey] to create justice transactions.
#[derive(PartialEq, Eq, Clone, Copy, Debug, Hash)]
pub struct RevocationBasepoint(pub PublicKey);
basepoint_impl!(RevocationBasepoint);
key_read_write!(RevocationBasepoint);


/// [htlcpubkey](https://github.com/lightning/bolts/blob/master/03-transactions.md#localpubkey-local_htlcpubkey-remote_htlcpubkey-local_delayedpubkey-and-remote_delayedpubkey-derivation) is a child key of a revocation basepoint,
/// that enables a node to create a justice transaction punishing a counterparty for an attempt to steal funds. Used to in generation of commitment and htlc outputs.
#[derive(PartialEq, Eq, Clone, Copy, Debug, Hash)]
pub struct RevocationKey(pub PublicKey);

impl RevocationKey {
    /// Derives a per-commitment-transaction revocation public key from its constituent parts. This is
    /// the public equivalend of derive_private_revocation_key - using only public keys to derive a
    /// public key instead of private keys.
    ///
    /// Only the cheating participant owns a valid witness to propagate a revoked
    /// commitment transaction, thus per_commitment_point always come from cheater
    /// and revocation_base_point always come from punisher, which is the broadcaster
    /// of the transaction spending with this key knowledge.
    ///
    /// Note that this is infallible iff we trust that at least one of the two input keys are randomly
    /// generated (ie our own).
    pub fn from_basepoint<T: secp256k1::Verification>(
        secp_ctx: &Secp256k1<T>,
        basepoint: &RevocationBasepoint,
        per_commitment_point: &PublicKey,
    ) -> Self {
        let rev_append_commit_hash_key = {
            let mut sha = Sha256::engine();
            sha.input(&basepoint.to_public_key().serialize());
            sha.input(&per_commitment_point.serialize());
    
            Sha256::from_engine(sha).to_byte_array()
        };
        let commit_append_rev_hash_key = {
            let mut sha = Sha256::engine();
            sha.input(&per_commitment_point.serialize());
            sha.input(&basepoint.to_public_key().serialize());
    
            Sha256::from_engine(sha).to_byte_array()
        };
    
        let countersignatory_contrib = basepoint.to_public_key().mul_tweak(&secp_ctx, &Scalar::from_be_bytes(rev_append_commit_hash_key).unwrap())
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
    use bitcoin::secp256k1::{Secp256k1, SecretKey, PublicKey};
    use bitcoin::hashes::hex::FromHex;
    use super::derive_public_key;

    #[test]
	fn test_key_derivation() {
		// Test vectors from BOLT 3 Appendix E:
		let secp_ctx = Secp256k1::new();

		let base_secret = SecretKey::from_slice(&<Vec<u8>>::from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap()[..]).unwrap();
		let per_commitment_secret = SecretKey::from_slice(&<Vec<u8>>::from_hex("1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100").unwrap()[..]).unwrap();

		let base_point = PublicKey::from_secret_key(&secp_ctx, &base_secret);
		assert_eq!(base_point.serialize()[..], <Vec<u8>>::from_hex("036d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a95b216691468e2").unwrap()[..]);

		let per_commitment_point = PublicKey::from_secret_key(&secp_ctx, &per_commitment_secret);
		assert_eq!(per_commitment_point.serialize()[..], <Vec<u8>>::from_hex("025f7117a78150fe2ef97db7cfc83bd57b2e2c0d0dd25eaf467a4a1c2a45ce1486").unwrap()[..]);

		assert_eq!(derive_public_key(&secp_ctx, &per_commitment_point, &base_point).serialize()[..],
				<Vec<u8>>::from_hex("0235f2dbfaa89b57ec7b055afe29849ef7ddfeb1cefdb9ebdc43f5494984db29e5").unwrap()[..]);
	}
}
