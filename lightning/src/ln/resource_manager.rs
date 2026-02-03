use std::time::Duration;

struct DecayingAverage {
	value: i64,
	last_updated: u64,
	decay_rate: f64,
}

impl DecayingAverage {
	fn new(start_timestamp: u64, window: Duration) -> Self {
		DecayingAverage {
			value: 0,
			last_updated: start_timestamp,
			decay_rate: 0.5_f64.powf(2.0 / window.as_secs_f64()),
		}
	}

	fn value_at_timestamp(&mut self, timestamp: u64) -> Result<i64, ()> {
		if timestamp < self.last_updated {
			return Err(());
		}

		let elapsed_secs = (timestamp - self.last_updated) as f64;
		self.value = (self.value as f64 * self.decay_rate.powf(elapsed_secs)).round() as i64;
		self.last_updated = timestamp;
		Ok(self.value)
	}

	fn add_value(&mut self, value: i64, timestamp: u64) -> Result<i64, ()> {
		self.value_at_timestamp(timestamp)?;
		self.value = self.value.saturating_add(value);
		self.last_updated = timestamp;
		Ok(self.value)
	}
}

#[cfg(test)]
mod tests {
	use std::time::{Duration, SystemTime, UNIX_EPOCH};

	use crate::ln::resource_manager::DecayingAverage;

	const WINDOW: Duration = Duration::from_secs(2016 * 10 * 60);

	#[test]
	fn test_decaying_average_values() {
		let current_timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
		let mut avg = DecayingAverage::new(current_timestamp, WINDOW);

		// Add initial value
		assert_eq!(avg.add_value(1000, current_timestamp).unwrap(), 1000);
		assert_eq!(avg.value_at_timestamp(current_timestamp).unwrap(), 1000);

		// Check decay after quarter window
		let ts_1 = current_timestamp + WINDOW.as_secs() / 4;
		assert_eq!(avg.value_at_timestamp(ts_1).unwrap(), 707);

		// Check decay after half window
		let ts_2 = current_timestamp + WINDOW.as_secs() / 2;
		assert_eq!(avg.value_at_timestamp(ts_2).unwrap(), 500);

		// Add value after decay
		assert_eq!(avg.add_value(500, ts_2).unwrap(), 1000);

		// Check decay after full window
		let ts_3 = ts_2 + WINDOW.as_secs();
		assert_eq!(avg.value_at_timestamp(ts_3).unwrap(), 250);
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
		let timestamp = 1000;
		let mut avg = DecayingAverage::new(timestamp, WINDOW);

		assert_eq!(avg.add_value(1000, timestamp).unwrap(), 1000);
		assert_eq!(avg.add_value(i64::MAX, timestamp).unwrap(), i64::MAX);

		avg.value = 0;
		assert_eq!(avg.add_value(-100, timestamp).unwrap(), -100);
		assert_eq!(avg.add_value(i64::MIN, timestamp).unwrap(), i64::MIN);
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
}
