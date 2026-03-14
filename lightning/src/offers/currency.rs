// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Data structures and encoding for currency conversion support.

use crate::offers::offer::CurrencyCode;

#[allow(unused_imports)]
use crate::prelude::*;
use core::ops::Deref;

/// A trait for converting fiat currencies into millisatoshis (msats).
///
/// Implementations must return the conversion rate in **msats per minor unit**
/// of the currency. For example:
///
/// USD (exponent 2) → per **cent** (0.01 USD), not per dollar.
///
/// This convention ensures amounts remain precise and purely integer-based when parsing and
/// validating BOLT12 invoice requests.
pub trait CurrencyConversion {
	/// Returns the conversion rate in **msats per minor unit** for the given
	/// ISO-4217 currency code.
	fn msats_per_minor_unit(&self, iso4217_code: CurrencyCode) -> Result<u64, ()>;

	/// Returns the acceptable tolerance, expressed as a percentage, used when
	/// deriving conversion ranges.
	///
	/// This represents a user-level policy (e.g., allowance for exchange-rate
	/// drift or cached data) and does not directly affect fiat-to-msat conversion
	/// outside of range computation.
	fn tolerance_percent(&self) -> u8;
}

impl<T: CurrencyConversion + ?Sized, CC: Deref<Target = T>> CurrencyConversion for CC {
	fn msats_per_minor_unit(&self, iso4217_code: CurrencyCode) -> Result<u64, ()> {
		self.deref().msats_per_minor_unit(iso4217_code)
	}

	fn tolerance_percent(&self) -> u8 {
		self.deref().tolerance_percent()
	}
}

/// A [`CurrencyConversion`] implementation that does not support
/// any fiat currency conversions.
pub struct DefaultCurrencyConversion;

impl CurrencyConversion for DefaultCurrencyConversion {
	fn msats_per_minor_unit(&self, _iso4217_code: CurrencyCode) -> Result<u64, ()> {
		Err(())
	}

	fn tolerance_percent(&self) -> u8 {
		0
	}
}
