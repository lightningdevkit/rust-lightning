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

use core::num::NonZeroU64;
use core::ops::Deref;

/// A trait for retrieving fiat-to-bitcoin conversion ranges.
///
/// The returned range defines the minimum and maximum accepted exchange
/// rates for converting fiat minor units into millisatoshis.
///
/// Exchange rates are represented as:
///
/// `msats / minor_units`
pub trait CurrencyConversion {
	/// Returns the accepted conversion range for the given currency.
	fn conversion_range(&self, currency: CurrencyCode) -> Result<ExchangeRange, ()>;
}

impl<T: CurrencyConversion + ?Sized, CC: Deref<Target = T>> CurrencyConversion for CC {
	fn conversion_range(&self, currency: CurrencyCode) -> Result<ExchangeRange, ()> {
		self.deref().conversion_range(currency)
	}
}

/// A range of accepted exchange rates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExchangeRange {
	/// The minimum accepted exchange rate.
	pub minimum: ExchangeRate,

	/// The maximum accepted exchange rate.
	pub maximum: ExchangeRate,
}

/// An exchange rate represented as `msats / minor_units`.
///
/// For example:
///
/// `ExchangeRate { msats: 123, minor_units: 1_000_000 }`
///
/// represents `123 millisatoshis per 1,000,000 minor currency units`.
///
/// Minor units are the smallest unit of an ISO 4217 currency.
///
/// For example:
/// - USD (exponent 2) uses cents (0.01 USD)
/// - JPY (exponent 0) uses yen
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExchangeRate {
	/// The millisatoshi numerator of the exchange-rate ratio.
	pub msats: u64,

	/// The fiat minor-unit denominator of the exchange-rate ratio.
	pub minor_units: NonZeroU64,
}

impl ExchangeRate {
	/// Creates a new exchange rate represented as `msats / minor_units`.
	///
	/// Returns an error if `minor_units` is zero.
	pub fn new(msats: u64, minor_units: u64) -> Result<Self, ()> {
		Ok(Self { msats, minor_units: NonZeroU64::new(minor_units).ok_or(())? })
	}

	/// Converts the given fiat minor-unit amount to millisatoshis using this
	/// exchange rate.
	///
	/// The conversion is calculated as:
	///
	/// `fiat_minor_units * self.msats / self.minor_units`
	///
	/// Returns an error if the calculation overflows.
	pub(crate) fn convert_to_msats(&self, fiat_minor_units: u64) -> Result<u64, ()> {
		u128::from(fiat_minor_units)
			.checked_mul(u128::from(self.msats))
			.and_then(|amount| amount.checked_div(u128::from(self.minor_units.get())))
			.and_then(|amount| amount.try_into().ok())
			.ok_or(())
	}
}

/// A [`CurrencyConversion`] implementation that does not support
/// any fiat currency conversions.
#[derive(Clone, Copy, Debug)]
pub struct NullCurrencyConversion;

impl CurrencyConversion for NullCurrencyConversion {
	fn conversion_range(&self, _currency: CurrencyCode) -> Result<ExchangeRange, ()> {
		Err(())
	}
}
