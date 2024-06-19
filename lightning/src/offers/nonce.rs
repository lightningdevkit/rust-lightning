// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! A number used only once.

use crate::sign::EntropySource;
use core::ops::Deref;

#[allow(unused_imports)]
use crate::prelude::*;

/// A 128-bit number used only once.
///
/// Needed when constructing [`Offer::metadata`] and deriving [`Offer::signing_pubkey`] from
/// [`ExpandedKey`]. Must not be reused for any other derivation without first hashing.
///
/// [`Offer::metadata`]: crate::offers::offer::Offer::metadata
/// [`Offer::signing_pubkey`]: crate::offers::offer::Offer::signing_pubkey
/// [`ExpandedKey`]: crate::ln::inbound_payment::ExpandedKey
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Nonce(pub(crate) [u8; Self::LENGTH]);

impl Nonce {
	/// Number of bytes in the nonce.
	pub const LENGTH: usize = 16;

	/// Creates a `Nonce` from the given [`EntropySource`].
	pub fn from_entropy_source<ES: Deref>(entropy_source: ES) -> Self
	where
		ES::Target: EntropySource,
	{
		let mut bytes = [0u8; Self::LENGTH];
		let rand_bytes = entropy_source.get_secure_random_bytes();
		bytes.copy_from_slice(&rand_bytes[..Self::LENGTH]);

		Nonce(bytes)
	}

	/// Returns a slice of the underlying bytes of size [`Nonce::LENGTH`].
	pub fn as_slice(&self) -> &[u8] {
		&self.0
	}
}

impl TryFrom<&[u8]> for Nonce {
	type Error = ();

	fn try_from(bytes: &[u8]) -> Result<Self, ()> {
		if bytes.len() != Self::LENGTH {
			return Err(());
		}

		let mut copied_bytes = [0u8; Self::LENGTH];
		copied_bytes.copy_from_slice(bytes);

		Ok(Self(copied_bytes))
	}
}
