#[cfg(not(fuzzing))]
use bitcoin::hashes::cmp::fixed_time_eq;

pub(crate) mod chacha20;
pub(crate) mod chacha20poly1305rfc;
#[cfg(not(fuzzing))]
pub(crate) mod poly1305;
pub(crate) mod streams;
pub(crate) mod utils;
