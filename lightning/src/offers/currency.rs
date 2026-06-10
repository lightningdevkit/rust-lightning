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

use core::cmp::Ordering;
use core::num::NonZeroU64;
use core::ops::Deref;

/// An exchange rate represented as `msats / minor_units`.
///
/// Most exchange rates should be constructed with [`ExchangeRate::new`], which
/// represents a whole number of millisatoshis per one minor currency unit.
/// [`ExchangeRate::from_parts`] is available for rates that require fractional
/// precision.
///
/// ## Minor Units
///
/// Minor units are the smallest unit of an ISO 4217 currency.
///
/// For example:
/// - USD (exponent 2) uses cents (0.01 USD)
/// - JPY (exponent 0) uses yen
///
/// ## Fractional Precision
///
/// For example,
///
/// ExchangeRate::from_parts(123, NonZeroU64::new(1_000_000).unwrap())
///
/// represents `123 millisatoshis per 1,000,000 minor currency units`.
#[derive(Clone, Copy, Debug)]
pub struct ExchangeRate {
	msats: u64,
	minor_units: NonZeroU64,
}

impl ExchangeRate {
	/// Creates a new exchange rate in millisatoshis per one minor currency unit.
	pub fn new(msats_per_minor_unit: u64) -> Self {
		Self { msats: msats_per_minor_unit, minor_units: NonZeroU64::MIN }
	}

	/// Creates a new exchange rate represented as `msats / minor_units`.
	///
	/// This should only be used when the exchange rate cannot be represented as a
	/// whole number of millisatoshis per one minor currency unit.
	pub fn from_parts(msats: u64, minor_units: NonZeroU64) -> Self {
		Self { msats, minor_units }
	}

	/// The millisatoshi numerator of the exchange-rate ratio.
	pub fn msats(&self) -> u64 {
		self.msats
	}

	/// The fiat minor-unit denominator of the exchange-rate ratio.
	pub fn minor_units(&self) -> NonZeroU64 {
		self.minor_units
	}
}

impl PartialEq for ExchangeRate {
	fn eq(&self, other: &Self) -> bool {
		self.cmp(other) == Ordering::Equal
	}
}

impl Eq for ExchangeRate {}

impl PartialOrd for ExchangeRate {
	fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
		Some(self.cmp(other))
	}
}

impl Ord for ExchangeRate {
	fn cmp(&self, other: &Self) -> Ordering {
		let lhs = u128::from(self.msats) * u128::from(other.minor_units.get());
		let rhs = u128::from(other.msats) * u128::from(self.minor_units.get());

		lhs.cmp(&rhs)
	}
}

/// A tolerance applied to an [`ExchangeRate`] when determining acceptable
/// conversion rates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tolerance {
	/// A tolerance expressed in basis points relative to the exchange rate.
	///
	/// One basis point is equal to 0.01%.
	///
	/// For example, `BasisPoints(100)` represents a tolerance of ±1%.
	BasisPoints(u16),

	/// A tolerance expressed as an absolute exchange-rate deviation.
	///
	/// For example, `AbsoluteMsats(10)` permits a deviation of up to
	/// 10 millisatoshis per minor currency unit.
	AbsoluteMsats(u64),
}

/// An exchange rate together with acceptable lower and upper tolerances.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExchangeRateBound {
	/// The reference exchange rate.
	rate: ExchangeRate,

	/// The maximum tolerated deviation below the reference exchange rate.
	lower_tolerance: Tolerance,

	/// The maximum tolerated deviation above the reference exchange rate.
	upper_tolerance: Tolerance,
}

impl ExchangeRateBound {
	/// Constructs a new exchange rate bound from a reference rate and its
	/// tolerated lower and upper deviations.
	///
	/// The tolerances may be asymmetric. For example, a caller may accept an
	/// exchange rate up to 1% below the reference rate while only accepting an
	/// exchange rate up to 0.1% above it.
	///
	/// The tolerances can be expressed either in basis points relative to the
	/// exchange rate or as absolute exchange-rate deviations.
	///
	/// Lower tolerances must keep the minimum accepted exchange rate non-negative.
	/// Upper tolerances greater than or equal to 100% are permitted, provided the
	/// resulting maximum exchange rate can be represented without overflow.
	///
	/// Returns `Err(())` if:
	/// - the lower basis-points tolerance is greater than or equal to 100%,
	/// - the lower absolute tolerance would make the minimum exchange rate
	///   negative, or
	/// - computing either tolerance bound would overflow.
	pub fn new(
		rate: ExchangeRate, lower_tolerance: Tolerance, upper_tolerance: Tolerance,
	) -> Result<Self, ()> {
		match lower_tolerance {
			Tolerance::BasisPoints(bps) if bps >= 10_000 => return Err(()),
			Tolerance::BasisPoints(_) => {},
			Tolerance::AbsoluteMsats(msats_per_minor_unit) => {
				let lower_tolerance_msats = u128::from(msats_per_minor_unit)
					.checked_mul(u128::from(rate.minor_units.get()))
					.ok_or(())?;

				if lower_tolerance_msats > u128::from(rate.msats) {
					return Err(());
				}
			},
		}

		// Ensure the maximum exchange rate can be represented.
		//
		// ExchangeRate stores the rate as `msats / minor_units`, with `msats` as the
		// numerator. Validate that applying the upper tolerance does not overflow the
		// resulting numerator.
		match upper_tolerance {
			Tolerance::BasisPoints(bps) => {
				let upper_tolerance_msats = u128::from(rate.msats)
					.checked_mul(u128::from(bps))
					.and_then(|v| v.checked_div(10_000))
					.ok_or(())?;

				u128::from(rate.msats)
					.checked_add(upper_tolerance_msats)
					.and_then(|v| u64::try_from(v).ok())
					.ok_or(())?;
			},
			Tolerance::AbsoluteMsats(msats_per_minor_unit) => {
				let upper_tolerance_msats = u128::from(msats_per_minor_unit)
					.checked_mul(u128::from(rate.minor_units.get()))
					.ok_or(())?;

				u128::from(rate.msats)
					.checked_add(upper_tolerance_msats)
					.and_then(|v| u64::try_from(v).ok())
					.ok_or(())?;
			},
		}

		Ok(Self { rate, lower_tolerance, upper_tolerance })
	}

	/// Converts this bound into the corresponding accepted exchange-rate range.
	pub(crate) fn to_range(self) -> ExchangeRange {
		let lower_tolerance_msats: u64 = match self.lower_tolerance {
			Tolerance::BasisPoints(bps) => u128::from(self.rate.msats)
				.checked_mul(u128::from(bps))
				.and_then(|v| v.checked_div(10_000))
				.and_then(|v| v.try_into().ok())
				.expect("lower basis-points tolerance is checked during construction"),
			Tolerance::AbsoluteMsats(msats_per_minor_unit) => u128::from(msats_per_minor_unit)
				.checked_mul(u128::from(self.rate.minor_units.get()))
				.and_then(|v| v.try_into().ok())
				.expect("lower absolute tolerance is checked during construction"),
		};

		let upper_tolerance_msats: u64 = match self.upper_tolerance {
			Tolerance::BasisPoints(bps) => u128::from(self.rate.msats)
				.checked_mul(u128::from(bps))
				.and_then(|v| v.checked_div(10_000))
				.and_then(|v| v.try_into().ok())
				.expect("upper basis-points tolerance is checked during construction"),
			Tolerance::AbsoluteMsats(msats_per_minor_unit) => u128::from(msats_per_minor_unit)
				.checked_mul(u128::from(self.rate.minor_units.get()))
				.and_then(|v| v.try_into().ok())
				.expect("upper absolute tolerance is checked during construction"),
		};

		let minimum_rate = ExchangeRate {
			msats: self
				.rate
				.msats
				.checked_sub(lower_tolerance_msats)
				.expect("lower tolerance is checked during construction"),
			minor_units: self.rate.minor_units,
		};

		let maximum_rate = ExchangeRate {
			msats: self
				.rate
				.msats
				.checked_add(upper_tolerance_msats)
				.expect("upper tolerance is checked during construction"),
			minor_units: self.rate.minor_units,
		};

		ExchangeRange { minimum: minimum_rate, maximum: maximum_rate }
	}
}

/// A range of accepted exchange rates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ExchangeRange {
	/// The minimum accepted exchange rate.
	pub(crate) minimum: ExchangeRate,

	/// The maximum accepted exchange rate.
	pub(crate) maximum: ExchangeRate,
}

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
	fn conversion_range(&self, currency: CurrencyCode) -> Result<ExchangeRateBound, ()>;
}

impl<T: CurrencyConversion + ?Sized, CC: Deref<Target = T>> CurrencyConversion for CC {
	fn conversion_range(&self, currency: CurrencyCode) -> Result<ExchangeRateBound, ()> {
		self.deref().conversion_range(currency)
	}
}

/// A [`CurrencyConversion`] implementation that does not support
/// any fiat currency conversions.
#[derive(Clone, Copy, Debug)]
pub struct NullCurrencyConversion;

impl CurrencyConversion for NullCurrencyConversion {
	fn conversion_range(&self, _currency: CurrencyCode) -> Result<ExchangeRateBound, ()> {
		Err(())
	}
}
