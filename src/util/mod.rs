//! Some utility modules live here. See individual sub-modules for more info.

pub mod events;
pub mod errors;
pub mod ser;

pub(crate) mod byte_utils;
pub(crate) mod chacha20;
#[cfg(not(feature = "fuzztarget"))]
pub(crate) mod poly1305;
pub(crate) mod chacha20poly1305rfc;
pub(crate) mod transaction_utils;

#[macro_use]
pub(crate) mod ser_macros;
#[macro_use]
pub(crate) mod macro_logger;

// These have to come after macro_logger to build
pub mod logger;
pub mod config;

#[cfg(test)]
pub(crate) mod test_utils;

#[macro_use]
pub(crate) mod fuzz_wrappers;
