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

pub mod chan_utils;
pub mod channel_keys;
pub mod channel_state;
pub mod channelmanager;
mod features;
pub mod funding;
pub mod inbound_payment;
pub mod msgs;
pub mod onion_payment;
pub mod our_peer_storage;
pub mod peer_handler;
pub mod script;
pub mod types;

// TODO: These modules were moved from lightning-invoice and need to be better integrated into this
// crate now:
pub mod invoice_utils;

#[cfg(fuzzing)]
pub mod peer_channel_encryptor;
#[cfg(not(fuzzing))]
pub(crate) mod peer_channel_encryptor;

#[cfg(fuzzing)]
pub mod channel;
#[cfg(not(fuzzing))]
pub(crate) mod channel;

pub mod onion_utils;
mod outbound_payment;
pub mod wire;

#[allow(dead_code)] // TODO(dual_funding): Remove once contribution to V2 channels is enabled.
pub(crate) mod interactivetxs;

// Older rustc (which we support) refuses to let us call the get_payment_preimage_hash!() macro
// without the node parameter being mut. This is incorrect, and thus newer rustcs will complain
// about an unnecessary mut. Thus, we silence the unused_mut warning in two test modules below.

#[cfg(test)]
mod accountable_tests;
#[cfg(test)]
#[allow(unused_mut)]
mod async_payments_tests;
#[cfg(test)]
#[allow(unused_mut)]
mod async_signer_tests;
#[cfg(test)]
#[allow(unused_mut)]
mod blinded_payment_tests;
#[cfg(test)]
#[allow(unused_mut)]
pub mod bolt11_payment_tests;
#[cfg(test)]
#[allow(unused_mut)]
mod chanmon_update_fail_tests;
#[cfg(test)]
#[allow(unused_mut)]
mod channel_open_tests;
#[cfg(test)]
#[allow(unused_mut)]
mod channel_type_tests;
#[cfg(test)]
#[allow(unused_mut)]
mod dual_funding_tests;
#[cfg(any(test, feature = "_externalize_tests"))]
#[allow(unused_mut)]
pub mod functional_tests;
#[cfg(any(test, feature = "_externalize_tests"))]
#[allow(unused_mut)]
pub mod htlc_reserve_unit_tests;
#[cfg(test)]
#[allow(unused_mut)]
mod max_payment_path_len_tests;
#[cfg(test)]
#[allow(unused_mut)]
mod monitor_tests;
#[cfg(test)]
#[allow(unused_mut)]
mod offers_tests;
#[cfg(test)]
#[allow(unused_mut)]
mod onion_route_tests;
#[cfg(test)]
#[allow(unused_mut)]
mod payment_tests;
#[cfg(test)]
#[allow(unused_mut)]
mod priv_short_conf_tests;
#[cfg(test)]
mod quiescence_tests;
#[cfg(test)]
#[allow(unused_mut)]
mod reload_tests;
#[cfg(test)]
#[allow(unused_mut)]
mod reorg_tests;
#[cfg(test)]
#[allow(unused_mut)]
mod shutdown_tests;
#[cfg(any(feature = "_test_utils", test))]
pub mod splicing_tests;
#[cfg(any(test, feature = "_externalize_tests"))]
#[allow(unused_mut)]
pub mod update_fee_tests;
#[cfg(test)]
mod zero_fee_commitment_tests;

pub use self::peer_channel_encryptor::LN_MAX_MSG_LEN;
