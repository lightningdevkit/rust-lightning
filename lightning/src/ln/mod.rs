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
pub mod types;

pub use types::{ChannelId, PaymentHash, PaymentPreimage, PaymentSecret};

#[cfg(fuzzing)]
pub mod peer_channel_encryptor;
#[cfg(not(fuzzing))]
pub(crate) mod peer_channel_encryptor;

#[cfg(fuzzing)]
pub mod channel;
#[cfg(not(fuzzing))]
pub(crate) mod channel;

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
mod max_payment_path_len_tests;
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
#[allow(dead_code)] // TODO(dual_funding): Exchange for dual_funding cfg
pub(crate) mod interactivetxs;

pub use self::peer_channel_encryptor::LN_MAX_MSG_LEN;
