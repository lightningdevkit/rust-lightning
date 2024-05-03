// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! [`getrandom`] provides access to OS randomness, but will fail to compile on platforms that do
//! not support fetching OS randomness. This is exactly what you want when you're doing
//! cryptographic operations, but when you're just opportunistically randomizing, we're fine with
//! compiling and simply disabling randomization.
//!
//! This crate does that, returning only possibly-random data.
//!
//! Note that this crate only enables getrandom on a subset of platforms it supports. As getrandom
//! evolves this crate is unlikely to carefully track all getrandom-supported platforms, however
//! will use random data on popular platforms.

#![no_std]

#[cfg(feature = "getrandom")]
extern crate getrandom;

/// Possibly fills `dest` with random data. May fill it with zeros.
#[inline]
pub fn getpossiblyrandom(dest: &mut [u8]) {
	#[cfg(feature = "getrandom")]
	if getrandom::getrandom(dest).is_err() {
		dest.fill(0);
	}
	#[cfg(not(feature = "getrandom"))]
	dest.fill(0);
}
