// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Math utilities for no-std builds. Uses a pure Rust implementation of libm for no-std.

#[cfg(feature = "std")]
#[inline]
pub(crate) fn powf64(n: f64, exp: f64) -> f64 {
	n.powf(exp)
}
#[cfg(not(feature = "std"))]
pub(crate) fn powf64(n: f64, exp: f64) -> f64 {
	libm::pow(n, exp)
}

#[cfg(feature = "std")]
#[inline]
pub(crate) fn expf64(n: f64) -> f64 {
	n.exp()
}
#[cfg(not(feature = "std"))]
pub(crate) fn expf64(n: f64) -> f64 {
	libm::exp(n)
}

#[cfg(feature = "std")]
#[inline]
pub(crate) fn roundf64(n: f64) -> f64 {
	n.round()
}
#[cfg(not(feature = "std"))]
pub(crate) fn roundf64(n: f64) -> f64 {
	libm::round(n)
}
