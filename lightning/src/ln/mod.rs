// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Implementations of various parts of the Lightning protocol are in this module.

#[cfg(any(test, feature = "_test_utils"))]
#[macro_use]
pub mod functional_test_utils;

pub mod onion_payment;
pub mod channelmanager;
pub mod channel_keys;
pub mod inbound_payment;
pub mod msgs;
pub mod peer_handler;
pub mod chan_utils;
pub mod features;
pub mod script;
mod channel_id;

#[cfg(fuzzing)]
pub mod peer_channel_encryptor;
#[cfg(not(fuzzing))]
pub(crate) mod peer_channel_encryptor;

#[cfg(fuzzing)]
pub mod channel;
#[cfg(not(fuzzing))]
pub(crate) mod channel;

// Re-export ChannelId
pub use channel_id::ChannelId;

pub(crate) mod onion_utils;
mod outbound_payment;
pub mod wire;

pub use onion_utils::create_payment_onion;
// Older rustc (which we support) refuses to let us call the get_payment_preimage_hash!() macro
// without the node parameter being mut. This is incorrect, and thus newer rustcs will complain
// about an unnecessary mut. Thus, we silence the unused_mut warning in two test modules below.

#[cfg(test)]
#[allow(unused_mut)]
mod blinded_payment_tests;
#[cfg(test)]
#[allow(unused_mut)]
mod functional_tests;
#[cfg(test)]
#[allow(unused_mut)]
mod payment_tests;
#[cfg(test)]
#[allow(unused_mut)]
mod priv_short_conf_tests;
#[cfg(test)]
#[allow(unused_mut)]
mod chanmon_update_fail_tests;
#[cfg(test)]
#[allow(unused_mut)]
mod reorg_tests;
#[cfg(test)]
#[allow(unused_mut)]
mod reload_tests;
#[cfg(test)]
#[allow(unused_mut)]
mod onion_route_tests;
#[cfg(test)]
#[allow(unused_mut)]
mod monitor_tests;
#[cfg(test)]
#[allow(unused_mut)]
mod shutdown_tests;
#[cfg(all(test, async_signing))]
#[allow(unused_mut)]
mod async_signer_tests;
#[cfg(test)]
#[allow(unused_mut)]
mod offers_tests;

pub use self::peer_channel_encryptor::LN_MAX_MSG_LEN;

use bitcoin::hashes::{sha256::Hash as Sha256, Hash};

/// payment_hash type, use to cross-lock hop
///
/// This is not exported to bindings users as we just use [u8; 32] directly
#[derive(Hash, Copy, Clone, PartialEq, Eq, Debug, Ord, PartialOrd)]
pub struct PaymentHash(pub [u8; 32]);

impl core::fmt::Display for PaymentHash {
	fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
		crate::util::logger::DebugBytes(&self.0).fmt(f)
	}
}

/// payment_preimage type, use to route payment between hop
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

/// payment_secret type, use to authenticate sender to the receiver and tie MPP HTLCs together
///
/// This is not exported to bindings users as we just use [u8; 32] directly
#[derive(Hash, Copy, Clone, PartialEq, Eq, Debug, Ord, PartialOrd)]
pub struct PaymentSecret(pub [u8; 32]);

use crate::prelude::*;
use bitcoin::bech32;
use bitcoin::bech32::{Base32Len, FromBase32, ToBase32, WriteBase32, u5};

impl FromBase32 for PaymentSecret {
	type Err = bech32::Error;

	fn from_base32(field_data: &[u5]) -> Result<PaymentSecret, bech32::Error> {
		if field_data.len() != 52 {
			return Err(bech32::Error::InvalidLength)
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
