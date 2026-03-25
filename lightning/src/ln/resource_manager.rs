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
	half_life: f64,
}

impl DecayingAverage {
	fn new(start_timestamp_unix_secs: u64, window: Duration) -> Self {
		DecayingAverage {
			value: 0,
			last_updated_unix_secs: start_timestamp_unix_secs,
			window,
			half_life: window.as_secs_f64() * 2_f64.ln(),
		}
	}

	fn value_at_timestamp(&mut self, timestamp_unix_secs: u64) -> Result<i64, ()> {
		if timestamp_unix_secs < self.last_updated_unix_secs {
			return Err(());
		}

		let elapsed_secs = (timestamp_unix_secs - self.last_updated_unix_secs) as f64;
		let decay_rate = 0.5_f64.powf(elapsed_secs / self.half_life);
		self.value = (self.value as f64 * decay_rate).round() as i64;
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

/// Approximates an [`Self::avg_weeks`]-week average by tracking a decaying average over a larger
/// [`Self::window_weeks`] window to smooth out volatility.
struct AggregatedWindowAverage {
	start_timestamp_unix_secs: u64,
	avg_weeks: u8,
	window_weeks: u8,
	aggregated_revenue_decaying: DecayingAverage,
}

impl AggregatedWindowAverage {
	fn new(avg_weeks: u8, window_multiplier: u8, start_timestamp_unix_secs: u64) -> Self {
		let window_weeks = avg_weeks * window_multiplier;
		let window_duration = Duration::from_secs(60 * 60 * 24 * 7 * window_weeks as u64);
		AggregatedWindowAverage {
			start_timestamp_unix_secs,
			avg_weeks,
			window_weeks,
			aggregated_revenue_decaying: DecayingAverage::new(
				start_timestamp_unix_secs,
				window_duration,
			),
		}
	}

	fn add_value(&mut self, value: i64, timestamp: u64) -> Result<i64, ()> {
		self.aggregated_revenue_decaying.add_value(value, timestamp)
	}

	fn value_at_timestamp(&mut self, timestamp_unix_secs: u64) -> Result<i64, ()> {
		if timestamp_unix_secs < self.start_timestamp_unix_secs {
			return Err(());
		}

		let num_windows = (self.window_weeks / self.avg_weeks) as f64;
		let elapsed = (timestamp_unix_secs - self.start_timestamp_unix_secs) as f64;
		// Early on when elapsed < 5*window, the decaying average underestimates the true sum.
		// The warmup_factor (1 - e^(-elapsed/window)) corrects for this.
		let warmup_factor =
			1.0 - (-elapsed / (self.window_weeks as u64 * 60 * 60 * 24 * 7) as f64).exp();
		let divisor = f64::max(num_windows * warmup_factor, 1.0);

		Ok((self.aggregated_revenue_decaying.value_at_timestamp(timestamp_unix_secs)? as f64
			/ divisor)
			.round() as i64)
	}
}

#[cfg(test)]
mod tests {
	use std::time::Duration;

	use crate::{
		crypto::chacha20::ChaCha20,
		ln::resource_manager::{AggregatedWindowAverage, DecayingAverage},
	};

	const WINDOW: Duration = Duration::from_secs(2016 * 10 * 60);

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
	fn test_decaying_average_values() {
		// Test average decay at different timestamps. The values we are asserting have been
		// independently calculated.
		let mut current_timestamp = 0;
		let mut avg = DecayingAverage::new(current_timestamp, WINDOW);

		assert_eq!(avg.add_value(1000, current_timestamp).unwrap(), 1000);

		let one_week = 60 * 60 * 24 * 7;

		current_timestamp += one_week; // 1 week
		assert_eq!(avg.value_at_timestamp(current_timestamp).unwrap(), 607);
		assert_eq!(avg.add_value(500, current_timestamp).unwrap(), 1107);

		current_timestamp += one_week / 2; // 1.5 weeks
		assert_eq!(avg.value_at_timestamp(current_timestamp).unwrap(), 862);

		current_timestamp += one_week / 2; // 2 weeks
		assert_eq!(avg.value_at_timestamp(current_timestamp).unwrap(), 671);
		assert_eq!(avg.add_value(200, current_timestamp).unwrap(), 871);

		current_timestamp += one_week * 2; // 4 weeks
		assert_eq!(avg.value_at_timestamp(current_timestamp).unwrap(), 320);

		current_timestamp += one_week * 6; // 10 weeks
		assert_eq!(avg.value_at_timestamp(current_timestamp).unwrap(), 16);
		assert_eq!(avg.add_value(1000, current_timestamp).unwrap(), 1016);

		current_timestamp += avg.half_life as u64;
		assert_eq!(avg.value_at_timestamp(current_timestamp).unwrap(), 1016 / 2);
	}

	#[test]
	fn test_aggregated_window_average() {
		let avg_weeks: u8 = 2;
		let window_weeks: u8 = 12;
		let num_windows = (window_weeks / avg_weeks) as usize;
		let week_secs: u64 = 60 * 60 * 24 * 7;
		let sum_window_secs = avg_weeks as u64 * week_secs;

		let num_points: usize = 50_000;
		let duration_weeks: u64 = 120;
		let skip_weeks: u64 = 10;
		let duration_secs = duration_weeks * week_secs;
		let start_timestamp: u64 = 0;

		let mut prng = ChaCha20::new(&[42u8; 32], &[0u8; 12]);
		let mut timestamps = Vec::with_capacity(num_points);
		let mut values = Vec::with_capacity(num_points);
		for _ in 0..num_points {
			let mut buf = [0u8; 8];
			prng.process_in_place(&mut buf);
			let ts_offset = u64::from_le_bytes(buf) % duration_secs;
			timestamps.push(start_timestamp + ts_offset);

			let mut buf = [0u8; 4];
			prng.process_in_place(&mut buf);
			let val = (u32::from_le_bytes(buf) % 49_001 + 1_000) as i64;
			values.push(val);
		}

		let mut indices: Vec<usize> = (0..num_points).collect();
		indices.sort_by_key(|&i| timestamps[i]);
		let sorted_ts: Vec<u64> = indices.iter().map(|&i| timestamps[i]).collect();
		let sorted_vals: Vec<i64> = indices.iter().map(|&i| values[i]).collect();

		let mut avg = AggregatedWindowAverage::new(avg_weeks, window_weeks, start_timestamp);
		let mut data_idx = 0;

		for w in 1..=duration_weeks {
			let sample_time = start_timestamp + w * week_secs;

			// Add all data points up to this sample time.
			while data_idx < num_points && sorted_ts[data_idx] <= sample_time {
				avg.add_value(sorted_vals[data_idx], sorted_ts[data_idx]).unwrap();
				data_idx += 1;
			}

			let approx_avg = avg.value_at_timestamp(sample_time).unwrap();

			let mut window_sums = Vec::with_capacity(num_windows);
			for i in 0..num_windows {
				let window_end = sample_time - i as u64 * sum_window_secs;
				if window_end < sum_window_secs + start_timestamp {
					break;
				}
				let window_start = window_end - sum_window_secs;
				let window_sum: i64 = sorted_ts
					.iter()
					.zip(sorted_vals.iter())
					.filter(|(&t, _)| t > window_start && t <= window_end)
					.map(|(_, &v)| v)
					.sum();
				window_sums.push(window_sum);
			}

			let actual_avg = if window_sums.is_empty() {
				0
			} else {
				(window_sums.iter().sum::<i64>() as f64 / window_sums.len() as f64).round() as i64
			};

			let error_pct = if actual_avg != 0 {
				(approx_avg - actual_avg) as f64 / actual_avg as f64 * 100.0
			} else {
				0.0
			};

			if w >= skip_weeks {
				assert!(
					error_pct.abs() < 3.0,
					"week {w}: error {error_pct:.2}% exceeds 3% \
					 (approx={approx_avg}, actual={actual_avg})"
				);
			}
		}
	}
}
