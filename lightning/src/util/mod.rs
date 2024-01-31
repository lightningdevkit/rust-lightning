// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Some utility modules live here. See individual sub-modules for more info.

#[macro_use]
pub(crate) mod fuzz_wrappers;

#[macro_use]
pub mod ser_macros;

#[cfg(fuzzing)]
pub mod base32;
#[cfg(not(fuzzing))]
pub(crate) mod base32;
pub mod errors;
pub mod invoice;
pub mod message_signing;
pub mod persist;
pub mod scid_utils;
pub mod ser;
pub mod string;
pub mod wakers;

pub(crate) mod atomic_counter;
pub(crate) mod byte_utils;
pub(crate) mod time;
pub(crate) mod transaction_utils;

pub mod indexed_map;

/// Logging macro utilities.
#[macro_use]
pub(crate) mod macro_logger;

// These have to come after macro_logger to build
pub mod config;
pub mod logger;

#[cfg(any(test, feature = "_test_utils"))]
pub mod test_utils;

/// impls of traits that add exra enforcement on the way they're called. Useful for detecting state
/// machine errors and used in fuzz targets and tests.
#[cfg(any(test, feature = "_test_utils"))]
pub mod test_channel_signer;
