// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! A type for representing lightning-specific amounts in millisatoshis.

use core::fmt;
use core::iter::Sum;
use core::ops::{Add, AddAssign, Sub, SubAssign};

/// An amount of money denominated in millisatoshis (msat), the smallest unit used in the Lightning
/// Network.
///
/// While the Bitcoin base layer uses satoshis as its smallest unit, Lightning Network payments
/// can be denominated in millisatoshis (1/1000 of a satoshi), allowing for finer-grained payment
/// amounts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct LightningAmount {
	msat: u64,
}

impl LightningAmount {
	/// The zero amount.
	pub const ZERO: LightningAmount = LightningAmount { msat: 0 };

	/// Constructs a new [`LightningAmount`] from the given number of millisatoshis.
	pub const fn from_msat(msat: u64) -> Self {
		Self { msat }
	}

	/// Constructs a new [`LightningAmount`] from the given number of satoshis.
	///
	/// Saturates to [`u64::MAX`] on overflow.
	pub const fn from_sat(sat: u64) -> Self {
		Self { msat: sat.saturating_mul(1000) }
	}

	/// Returns the amount in millisatoshis.
	pub const fn to_msat(&self) -> u64 {
		self.msat
	}

	/// Returns the amount in satoshis, rounded to the nearest satoshi.
	///
	/// Ties (i.e., exactly 500 sub-satoshi millisatoshis) round up.
	pub const fn to_sat_rounded(&self) -> u64 {
		(self.msat + 500) / 1000
	}

	/// Returns the amount in satoshis, rounded up (ceiling).
	pub const fn to_sat_ceil(&self) -> u64 {
		(self.msat + 999) / 1000
	}

	/// Returns the amount in satoshis, rounded down (floor).
	pub const fn to_sat_floor(&self) -> u64 {
		self.msat / 1000
	}
}

impl From<bitcoin::Amount> for LightningAmount {
	fn from(amount: bitcoin::Amount) -> Self {
		Self::from_sat(amount.to_sat())
	}
}

impl fmt::Display for LightningAmount {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{} msat", self.msat)
	}
}

impl Add for LightningAmount {
	type Output = Self;

	fn add(self, rhs: Self) -> Self::Output {
		Self { msat: self.msat + rhs.msat }
	}
}

impl Sub for LightningAmount {
	type Output = Self;

	fn sub(self, rhs: Self) -> Self::Output {
		Self { msat: self.msat - rhs.msat }
	}
}

impl AddAssign for LightningAmount {
	fn add_assign(&mut self, rhs: Self) {
		self.msat += rhs.msat;
	}
}

impl SubAssign for LightningAmount {
	fn sub_assign(&mut self, rhs: Self) {
		self.msat -= rhs.msat;
	}
}

impl Sum for LightningAmount {
	fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
		iter.fold(Self::ZERO, Add::add)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn from_msat_basic() {
		assert_eq!(LightningAmount::from_msat(0).to_msat(), 0);
		assert_eq!(LightningAmount::from_msat(1).to_msat(), 1);
		assert_eq!(LightningAmount::from_msat(1_000).to_msat(), 1_000);
		assert_eq!(LightningAmount::from_msat(u64::MAX).to_msat(), u64::MAX);
	}

	#[test]
	fn from_sat_basic() {
		assert_eq!(LightningAmount::from_sat(0).to_msat(), 0);
		assert_eq!(LightningAmount::from_sat(1).to_msat(), 1_000);
		assert_eq!(LightningAmount::from_sat(100).to_msat(), 100_000);
	}

	#[test]
	fn from_sat_overflow_saturates() {
		let large = u64::MAX / 1000 + 1;
		let amount = LightningAmount::from_sat(large);
		assert_eq!(amount.to_msat(), u64::MAX);

		let amount = LightningAmount::from_sat(u64::MAX);
		assert_eq!(amount.to_msat(), u64::MAX);
	}

	#[test]
	fn to_sat_rounded() {
		assert_eq!(LightningAmount::from_msat(0).to_sat_rounded(), 0);
		assert_eq!(LightningAmount::from_msat(1).to_sat_rounded(), 0);
		assert_eq!(LightningAmount::from_msat(499).to_sat_rounded(), 0);
		assert_eq!(LightningAmount::from_msat(500).to_sat_rounded(), 1);
		assert_eq!(LightningAmount::from_msat(501).to_sat_rounded(), 1);
		assert_eq!(LightningAmount::from_msat(999).to_sat_rounded(), 1);
		assert_eq!(LightningAmount::from_msat(1000).to_sat_rounded(), 1);
		assert_eq!(LightningAmount::from_msat(1499).to_sat_rounded(), 1);
		assert_eq!(LightningAmount::from_msat(1500).to_sat_rounded(), 2);
	}

	#[test]
	fn to_sat_ceil() {
		assert_eq!(LightningAmount::from_msat(0).to_sat_ceil(), 0);
		assert_eq!(LightningAmount::from_msat(1).to_sat_ceil(), 1);
		assert_eq!(LightningAmount::from_msat(999).to_sat_ceil(), 1);
		assert_eq!(LightningAmount::from_msat(1000).to_sat_ceil(), 1);
		assert_eq!(LightningAmount::from_msat(1001).to_sat_ceil(), 2);
	}

	#[test]
	fn to_sat_floor() {
		assert_eq!(LightningAmount::from_msat(0).to_sat_floor(), 0);
		assert_eq!(LightningAmount::from_msat(999).to_sat_floor(), 0);
		assert_eq!(LightningAmount::from_msat(1000).to_sat_floor(), 1);
		assert_eq!(LightningAmount::from_msat(1001).to_sat_floor(), 1);
		assert_eq!(LightningAmount::from_msat(1999).to_sat_floor(), 1);
	}

	#[test]
	fn from_bitcoin_amount() {
		let btc_amount = bitcoin::Amount::from_sat(42);
		let ln_amount = LightningAmount::from(btc_amount);
		assert_eq!(ln_amount.to_msat(), 42_000);
	}

	#[test]
	fn zero_value() {
		assert_eq!(LightningAmount::ZERO.to_msat(), 0);
		assert_eq!(LightningAmount::ZERO, LightningAmount::from_msat(0));
		assert_eq!(LightningAmount::ZERO, LightningAmount::default());
	}

	#[test]
	fn display_formatting() {
		assert_eq!(format!("{}", LightningAmount::from_msat(0)), "0 msat");
		assert_eq!(format!("{}", LightningAmount::from_msat(1000)), "1000 msat");
		assert_eq!(format!("{}", LightningAmount::from_msat(42)), "42 msat");
	}

	#[test]
	fn arithmetic_add() {
		let a = LightningAmount::from_msat(100);
		let b = LightningAmount::from_msat(200);
		assert_eq!((a + b).to_msat(), 300);
	}

	#[test]
	fn arithmetic_sub() {
		let a = LightningAmount::from_msat(300);
		let b = LightningAmount::from_msat(100);
		assert_eq!((a - b).to_msat(), 200);
	}

	#[test]
	fn arithmetic_add_assign() {
		let mut a = LightningAmount::from_msat(100);
		a += LightningAmount::from_msat(50);
		assert_eq!(a.to_msat(), 150);
	}

	#[test]
	fn arithmetic_sub_assign() {
		let mut a = LightningAmount::from_msat(100);
		a -= LightningAmount::from_msat(30);
		assert_eq!(a.to_msat(), 70);
	}

	#[test]
	fn sum_iterator() {
		let amounts = vec![
			LightningAmount::from_msat(100),
			LightningAmount::from_msat(200),
			LightningAmount::from_msat(300),
		];
		let total: LightningAmount = amounts.into_iter().sum();
		assert_eq!(total.to_msat(), 600);
	}

	#[test]
	fn sum_empty_iterator() {
		let amounts: Vec<LightningAmount> = vec![];
		let total: LightningAmount = amounts.into_iter().sum();
		assert_eq!(total, LightningAmount::ZERO);
	}

	#[test]
	fn ordering() {
		let a = LightningAmount::from_msat(100);
		let b = LightningAmount::from_msat(200);
		let c = LightningAmount::from_msat(100);
		assert!(a < b);
		assert!(b > a);
		assert_eq!(a, c);
		assert!(a <= c);
		assert!(a >= c);
	}

	#[test]
	#[should_panic]
	fn sub_underflow_panics() {
		let a = LightningAmount::from_msat(100);
		let b = LightningAmount::from_msat(200);
		let _ = a - b;
	}

	#[test]
	#[should_panic]
	fn add_overflow_panics() {
		let a = LightningAmount::from_msat(u64::MAX);
		let b = LightningAmount::from_msat(1);
		let _ = a + b;
	}
}
