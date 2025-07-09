#[cfg(not(fuzzing))]
pub(crate) use bitcoin::hashes::cmp::fixed_time_eq;

#[cfg(fuzzing)]
fn fixed_time_eq(a: &[u8], b: &[u8]) -> bool {
	assert_eq!(a.len(), b.len());
	a == b
}

pub(crate) mod chacha20;
pub(crate) mod chacha20poly1305rfc;
pub(crate) mod poly1305;
pub(crate) mod streams;
pub(crate) mod utils;
