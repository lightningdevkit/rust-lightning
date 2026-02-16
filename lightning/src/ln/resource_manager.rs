// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

#![allow(dead_code)]

use core::time::Duration;

/// A weighted average that decays over a specified window.
///
/// It enables tracking of historical behavior without storing individual data points.
/// Instead of maintaining a complete history of events (such as HTLC forwards for tracking
/// reputation), the decaying average continuously adjusts a single accumulated value based on the
/// elapsed time in the window.
struct DecayingAverage {
	value: i64,
	last_updated_unix_secs: u64,
	window: Duration,
	/// A constant rate of decay basen on the rolling [`Self::window`] chosen.
	decay_rate: f64,
}

impl DecayingAverage {
	fn new(start_timestamp_unix_secs: u64, window: Duration) -> Self {
		DecayingAverage {
			value: 0,
			last_updated_unix_secs: start_timestamp_unix_secs,
			window,
			// This rate is calculated as `0.5^(2/window_seconds)`, which produces a half-life at the
			// midpoint of the window. For example, with a 24-week window (the default for
			// reputation tracking), a value will decay to half of its value after 12 weeks
			// have elapsed.
			decay_rate: 0.5_f64.powf(2.0 / window.as_secs_f64()),
		}
	}

	fn value_at_timestamp(&mut self, timestamp_unix_secs: u64) -> Result<i64, ()> {
		if timestamp_unix_secs < self.last_updated_unix_secs {
			return Err(());
		}

		let elapsed_secs = (timestamp_unix_secs - self.last_updated_unix_secs) as f64;
		self.value = (self.value as f64 * self.decay_rate.powf(elapsed_secs)).round() as i64;
		self.last_updated_unix_secs = timestamp_unix_secs;
		Ok(self.value)
	}

	fn add_value(&mut self, value: i64, timestamp_unix_secs: u64) -> Result<i64, ()> {
		self.value_at_timestamp(timestamp_unix_secs)?;
		self.value = self.value.saturating_add(value);
		self.last_updated_unix_secs = timestamp_unix_secs;
		Ok(self.value)
	}
}

struct RevenueAverage {
	start_timestamp_unix_secs: u64,
	window_count: u8,
	window_duration: Duration,
	aggregated_revenue_decaying: DecayingAverage,
}

impl RevenueAverage {
	fn new(window: Duration, window_count: u8, start_timestamp_unix_secs: u64) -> Self {
		RevenueAverage {
			start_timestamp_unix_secs,
			window_count,
			window_duration: window,
			aggregated_revenue_decaying: DecayingAverage::new(
				start_timestamp_unix_secs,
				window * window_count.into(),
			),
		}
	}

	fn add_value(&mut self, value: i64, timestamp: u64) -> Result<i64, ()> {
		self.aggregated_revenue_decaying.add_value(value, timestamp)
	}

	fn windows_tracked(&self, timestamp_unix_secs: u64) -> f64 {
		let elapsed_secs = (timestamp_unix_secs - self.start_timestamp_unix_secs) as f64;
		elapsed_secs / self.window_duration.as_secs_f64()
	}

	fn value_at_timestamp(&mut self, timestamp_unix_secs: u64) -> Result<i64, ()> {
		if timestamp_unix_secs < self.start_timestamp_unix_secs {
			return Err(());
		}

		let windows_tracked = self.windows_tracked(timestamp_unix_secs);
		let window_divisor = f64::min(
			if windows_tracked < 1.0 { 1.0 } else { windows_tracked },
			self.window_count as f64,
		);

		Ok((self.aggregated_revenue_decaying.value_at_timestamp(timestamp_unix_secs)? as f64
			/ window_divisor)
			.round() as i64)
	}
}

#[cfg(test)]
mod tests {
	use std::time::{Duration, SystemTime, UNIX_EPOCH};

	use crate::ln::resource_manager::{DecayingAverage, RevenueAverage};

	const WINDOW: Duration = Duration::from_secs(2016 * 10 * 60);

	#[test]
	fn test_decaying_average_values() {
		// Test average decay at different timestamps. The values we are asserting have been
		// independently calculated.
		let current_timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
		let mut avg = DecayingAverage::new(current_timestamp, WINDOW);

		assert_eq!(avg.add_value(1000, current_timestamp).unwrap(), 1000);
		assert_eq!(avg.value_at_timestamp(current_timestamp).unwrap(), 1000);

		let ts_1 = current_timestamp + WINDOW.as_secs() / 4;
		assert_eq!(avg.value_at_timestamp(ts_1).unwrap(), 707);

		let ts_2 = current_timestamp + WINDOW.as_secs() / 2;
		assert_eq!(avg.value_at_timestamp(ts_2).unwrap(), 500);

		assert_eq!(avg.add_value(500, ts_2).unwrap(), 1000);

		let ts_3 = ts_2 + WINDOW.as_secs();
		assert_eq!(avg.value_at_timestamp(ts_3).unwrap(), 250);

		// Test decaying on negative value
		let mut avg = DecayingAverage::new(current_timestamp, WINDOW);

		assert_eq!(avg.add_value(-1000, current_timestamp).unwrap(), -1000);
		assert_eq!(avg.value_at_timestamp(current_timestamp).unwrap(), -1000);

		let ts_1 = current_timestamp + WINDOW.as_secs() / 4;
		assert_eq!(avg.value_at_timestamp(ts_1).unwrap(), -707);

		let ts_2 = current_timestamp + WINDOW.as_secs() / 2;
		assert_eq!(avg.value_at_timestamp(ts_2).unwrap(), -500);
		assert_eq!(avg.add_value(-500, ts_2).unwrap(), -1000);

		let ts_3 = ts_2 + WINDOW.as_secs();
		assert_eq!(avg.value_at_timestamp(ts_3).unwrap(), -250);
	}

	#[test]
	fn test_decaying_average_error() {
		let timestamp = 1000;
		let mut decaying_average = DecayingAverage::new(timestamp, WINDOW);
		assert!(decaying_average.value_at_timestamp(timestamp - 100).is_err());
		assert!(decaying_average.add_value(500, timestamp - 100).is_err());
	}

	#[test]
	fn test_decaying_average_bounds() {
		for (start, bound) in [(1000, i64::MAX), (-1000, i64::MIN)] {
			let timestamp = 1000;
			let mut avg = DecayingAverage::new(timestamp, WINDOW);
			assert_eq!(avg.add_value(start, timestamp).unwrap(), start);
			assert_eq!(avg.add_value(bound, timestamp).unwrap(), bound);
		}
	}

	#[test]
	fn test_value_decays_to_zero_eventually() {
		let timestamp = 1000;
		let mut avg = DecayingAverage::new(timestamp, Duration::from_secs(100));
		assert_eq!(avg.add_value(100_000_000, timestamp).unwrap(), 100_000_000);

		// After many window periods, value should decay to 0
		let result = avg.value_at_timestamp(timestamp * 1000);
		assert_eq!(result, Ok(0));
	}

	#[test]
	fn test_revenue_average() {
		let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
		let window_count = 12;

		let mut revenue_average = RevenueAverage::new(WINDOW, window_count, timestamp);
		assert_eq!(revenue_average.value_at_timestamp(timestamp).unwrap(), 0);
		assert!(revenue_average.value_at_timestamp(timestamp - 100).is_err());

		let value = 10_000;
		revenue_average.add_value(value, timestamp).unwrap();
		assert_eq!(revenue_average.value_at_timestamp(timestamp).unwrap(), value);

		let revenue_window = revenue_average.window_duration.as_secs();
		let end_first_window = timestamp.checked_add(revenue_window).unwrap();
		let decayed_value = revenue_average
			.aggregated_revenue_decaying
			.value_at_timestamp(end_first_window)
			.unwrap();

		assert_eq!(revenue_average.value_at_timestamp(end_first_window).unwrap(), decayed_value);

		// Move halfway through the second window. Now the decayed revenue average should be
		// divided over how many windows we've been tracking revenue.
		let half_second_window = end_first_window.checked_add(revenue_window / 2).unwrap();
		let decayed_value = revenue_average
			.aggregated_revenue_decaying
			.value_at_timestamp(half_second_window)
			.unwrap();

		assert_eq!(
			revenue_average.value_at_timestamp(half_second_window).unwrap(),
			(decayed_value as f64 / 1.5).round() as i64,
		);

		let final_window =
			timestamp.checked_add(revenue_window * revenue_average.window_count as u64).unwrap();
		let decayed_value =
			revenue_average.aggregated_revenue_decaying.value_at_timestamp(final_window).unwrap();

		assert_eq!(
			revenue_average.value_at_timestamp(final_window).unwrap(),
			(decayed_value as f64 / revenue_average.window_count as f64).round() as i64,
		);

		// If we've been tracking the revenue for more than revenue_window * window_count periods,
		// then the average will be divided by the window count.
		let beyond_final_window = timestamp
			.checked_add(revenue_window * revenue_average.window_count as u64 * 5)
			.unwrap();
		let decayed_value = revenue_average
			.aggregated_revenue_decaying
			.value_at_timestamp(beyond_final_window)
			.unwrap();

		assert_eq!(
			revenue_average.value_at_timestamp(beyond_final_window).unwrap(),
			(decayed_value as f64 / revenue_average.window_count as f64).round() as i64,
		);
	}
}
