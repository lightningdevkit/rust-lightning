//! Some utility modules live here. See individual sub-modules for more info.

pub mod events;
pub mod errors;
pub mod ser;

pub(crate) mod byte_utils;
pub(crate) mod chacha20poly1305rfc;
pub(crate) mod internal_traits;
pub(crate) mod rng;
pub(crate) mod transaction_utils;

#[macro_use]
pub(crate) mod ser_macros;
#[macro_use]
pub(crate) mod macro_logger;

// These have to come after macro_logger to build
pub mod logger;
pub mod config;

#[cfg(feature = "fuzztarget")]
pub mod sha2;
#[cfg(not(feature = "fuzztarget"))]
pub(crate) mod sha2;

#[cfg(feature = "fuzztarget")]
pub use self::rng::{reset_rng_state, fill_bytes};

#[cfg(test)]
pub(crate) mod test_utils;
