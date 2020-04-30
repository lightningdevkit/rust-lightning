//! Some utility modules live here. See individual sub-modules for more info.

#[macro_use]
pub(crate) mod fuzz_wrappers;

pub mod errors;
pub mod events;
pub mod ser;

pub(crate) mod byte_utils;
pub(crate) mod chacha20;
pub(crate) mod chacha20poly1305rfc;
#[cfg(not(feature = "fuzztarget"))]
pub(crate) mod poly1305;
pub(crate) mod transaction_utils;

#[macro_use]
pub(crate) mod ser_macros;
#[macro_use]
pub(crate) mod macro_logger;

// These have to come after macro_logger to build
pub mod config;
pub mod logger;

#[cfg(test)]
pub(crate) mod test_utils;

/// impls of traits that add exra enforcement on the way they're called. Useful for detecting state
/// machine errors and used in fuzz targets and tests.
#[cfg(any(test, feature = "fuzztarget"))]
pub mod enforcing_trait_impls;
