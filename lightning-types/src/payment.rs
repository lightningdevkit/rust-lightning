// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Types which describe payments in lightning.

use core::borrow::Borrow;

use bitcoin::hashes::{sha256::Hash as Sha256, Hash as _};

// TODO: Once we switch to rust-bitcoin 0.32, import this as bitcoin::hex
use hex_conservative::display::impl_fmt_traits;

/// The payment hash is the hash of the [`PaymentPreimage`] which is the value used to lock funds
/// in HTLCs while they transit the lightning network.
///
/// This is not exported to bindings users as we just use [u8; 32] directly
#[derive(Hash, Copy, Clone, PartialEq, Eq, Ord, PartialOrd)]
pub struct PaymentHash(pub [u8; 32]);

impl Borrow<[u8]> for PaymentHash {
	fn borrow(&self) -> &[u8] {
		&self.0[..]
	}
}

impl_fmt_traits! {
	impl fmt_traits for PaymentHash {
		const LENGTH: usize = 32;
	}
}

/// The payment preimage is the "secret key" which is used to claim the funds of an HTLC on-chain
/// or in a lightning channel.
///
/// This is not exported to bindings users as we just use [u8; 32] directly
#[derive(Hash, Copy, Clone, PartialEq, Eq, Ord, PartialOrd)]
pub struct PaymentPreimage(pub [u8; 32]);

impl Borrow<[u8]> for PaymentPreimage {
	fn borrow(&self) -> &[u8] {
		&self.0[..]
	}
}

impl_fmt_traits! {
	impl fmt_traits for PaymentPreimage {
		const LENGTH: usize = 32;
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
#[derive(Hash, Copy, Clone, PartialEq, Eq, Ord, PartialOrd)]
pub struct PaymentSecret(pub [u8; 32]);

impl Borrow<[u8]> for PaymentSecret {
	fn borrow(&self) -> &[u8] {
		&self.0[..]
	}
}

impl_fmt_traits! {
	impl fmt_traits for PaymentSecret {
		const LENGTH: usize = 32;
	}
}
