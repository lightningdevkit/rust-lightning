// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

#![allow(dead_code)]

use bitcoin::hashes::{sha256, Hash, HashEngine};
use chacha20_poly1305::{chacha20::ChaCha20, Key, Nonce};
use core::{f64, time::Duration};

use crate::{
	ln::types::ChannelId,
	prelude::Vec,
	util::math::{expf64, powf64, roundf64},
};

/// The minimum number of slots required for the general bucket to function.
const MIN_GENERAL_BUCKET_SLOTS: u16 = 5;

/// The general bucket of a channel, available to all forwarding traffic.
///
/// Each incoming/outgoing channel pair is confined to [`Self::per_channel_slots`]
/// deterministically-assigned slots, so no pair can consume the whole bucket. Assignments overlap
/// but an attacker cannot learn which slots will be given and choose to collide with a victim
/// slots.
struct GeneralBucket {
	/// The id of the channel this bucket belongs to.
	channel_id: ChannelId,
	/// The salt used to deterministically assign slots to each forwarding channel pair.
	salt: [u8; 32],

	total_slots: u16,

	/// The number of slots in the general bucket that each forwarding channel pair gets.
	per_channel_slots: u8,
	/// The liquidity amount of each slot in the general bucket that each forwarding channel pair
	/// gets.
	per_slot_msat: u64,

	/// Tracks the occupancy of each HTLC slot in the bucket.
	slots_occupied: Vec<bool>,
}

impl GeneralBucket {
	fn new(
		channel_id: ChannelId, node_salt: &[u8; 32], slots_allocated: u16, liquidity_allocated: u64,
	) -> Result<Self, ()> {
		if slots_allocated < MIN_GENERAL_BUCKET_SLOTS {
			return Err(());
		}

		const GENERAL_BUCKET_SLOTS_PCT: u8 = 5;

		let per_channel_slots = u8::max(
			MIN_GENERAL_BUCKET_SLOTS as u8,
			u8::try_from((slots_allocated * GENERAL_BUCKET_SLOTS_PCT as u16).div_ceil(100))
				.unwrap(),
		);

		let per_slot_msat = liquidity_allocated / slots_allocated as u64;
		// This is a sanity check but based on the minimum channel size accepted by LDK and the
		// max_accepted_htlcs limit of 483 we do not expect to hit this.
		if per_slot_msat == 0 {
			return Err(());
		}
		Ok(GeneralBucket {
			channel_id,
			salt: derive_channel_salt(node_salt, channel_id),
			total_slots: slots_allocated,
			per_channel_slots,
			per_slot_msat,
			slots_occupied: vec![false; slots_allocated as usize],
		})
	}

	/// Marks the given slot indices as occupied (or frees them) in the bucket-wide occupancy
	/// tracking.
	fn set_slots_occupied(&mut self, slots: &[u16], occupied: bool) {
		for &idx in slots {
			debug_assert_eq!(self.slots_occupied[idx as usize], !occupied);
			self.slots_occupied[idx as usize] = occupied;
		}
	}

	/// Returns the available slots that could be used by the outgoing channel for the specified
	/// htlc amount, or None if not enough of its assigned slots are currently free.
	fn available_slots(
		&self, outgoing_channel_id: ChannelId, htlc_amount_msat: u64,
	) -> Option<Vec<u16>> {
		let slots_needed = u64::max(1, htlc_amount_msat.div_ceil(self.per_slot_msat));

		let mut channel_slots = assign_slots_for_channel(
			self.channel_id,
			outgoing_channel_id,
			self.salt,
			self.per_channel_slots,
			self.total_slots,
		);
		channel_slots.retain(|idx| !self.slots_occupied[*idx as usize]);
		channel_slots.truncate(slots_needed as usize);

		if (channel_slots.len() as u64) < slots_needed {
			None
		} else {
			Some(channel_slots)
		}
	}

	/// Marks the given slots as occupied. The slots must have been obtained from
	/// [`Self::available_slots`] and confirmed to be free.
	fn add_htlc(&mut self, slots: &[u16]) {
		self.set_slots_occupied(slots, true);
	}

	/// Frees the given slots, which must be exactly the slots the HTLC being removed previously
	/// occupied.
	fn remove_htlc(&mut self, slots: &[u16]) {
		self.set_slots_occupied(slots, false);
	}
}

fn assign_slots_for_channel(
	incoming_channel_id: ChannelId, outgoing_channel_id: ChannelId, salt: [u8; 32],
	per_channel_slots: u8, total_slots: u16,
) -> Vec<u16> {
	let mut channel_slots = Vec::with_capacity(per_channel_slots.into());

	let mut engine = sha256::Hash::engine();
	engine.input(&incoming_channel_id.0);
	engine.input(&outgoing_channel_id.0);
	let mut nonce = [0u8; 12];
	nonce.copy_from_slice(&sha256::Hash::from_engine(engine).to_byte_array()[..12]);
	let mut prng = ChaCha20::new(Key::new(salt), Nonce::new(nonce), 0);
	let mut buf = [0u8; 4];

	let max_attempts = per_channel_slots as u32 * 10;
	for _ in 0..max_attempts {
		prng.apply_keystream(&mut buf);
		let slot_idx: u16 = (u32::from_le_bytes(buf) % total_slots as u32) as u16;
		if !channel_slots.contains(&slot_idx) {
			channel_slots.push(slot_idx);
			if channel_slots.len() == per_channel_slots as usize {
				return channel_slots;
			}
		}
	}

	debug_assert!(false, "Should require > 2^128 work to get here");
	(0..per_channel_slots as u16).collect::<Vec<_>>()
}

fn derive_channel_salt(node_salt: &[u8; 32], incoming_channel_id: ChannelId) -> [u8; 32] {
	let mut engine = sha256::Hash::engine();
	engine.input(node_salt);
	engine.input(&incoming_channel_id.0);
	sha256::Hash::from_engine(engine).to_byte_array()
}

/// A weighted average that decays over a specified window. It is a decaying average with a
/// half-life of `window * ln(2)`.
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
			half_life: window.as_secs_f64() * f64::consts::LN_2,
		}
	}

	fn value_at_timestamp(&self, timestamp_unix_secs: u64) -> i64 {
		let timestamp = u64::max(timestamp_unix_secs, self.last_updated_unix_secs);
		let elapsed_secs = (timestamp - self.last_updated_unix_secs) as f64;
		let decay_rate = powf64(0.5, elapsed_secs / self.half_life);
		roundf64(self.value as f64 * decay_rate) as i64
	}

	fn add_value(&mut self, value: i64, timestamp_unix_secs: u64) -> i64 {
		let timestamp = u64::max(timestamp_unix_secs, self.last_updated_unix_secs);
		self.value = self.value_at_timestamp(timestamp).saturating_add(value);
		self.last_updated_unix_secs = timestamp;
		self.value
	}
}

/// Estimates how much value accumulates per [`Self::average_duration`], averaged across the last
/// `window_multiplier` periods of that length (so [`Self::tracked_duration`] =
/// [`Self::average_duration`] * `window_multiplier`). It is implemented with a single
/// [`DecayingAverage`] whose window spans the whole [`Self::tracked_duration`].
///
/// This is intended for tracking revenue, where we want a figure for the revenue earned over a
/// period such as two weeks, but do not want a single period to determine it. It is instead
/// tracked over a longer period to protect against shocks.
struct SmoothedDecayingAverage {
	start_timestamp_unix_secs: u64,
	average_duration: Duration,
	tracked_duration: Duration,
	aggregated_decaying_average: DecayingAverage,
}

impl SmoothedDecayingAverage {
	fn new(
		average_duration: Duration, window_multiplier: u8, start_timestamp_unix_secs: u64,
	) -> Self {
		let tracked_duration = average_duration * window_multiplier as u32;
		SmoothedDecayingAverage {
			start_timestamp_unix_secs,
			average_duration,
			tracked_duration,
			aggregated_decaying_average: DecayingAverage::new(
				start_timestamp_unix_secs,
				tracked_duration,
			),
		}
	}

	fn add_value(&mut self, value: i64, timestamp: u64) -> i64 {
		self.aggregated_decaying_average.add_value(value, timestamp)
	}

	fn value_at_timestamp(&self, timestamp_unix_secs: u64) -> i64 {
		let timestamp = u64::max(timestamp_unix_secs, self.start_timestamp_unix_secs);

		let num_windows = self.tracked_duration.as_secs_f64() / self.average_duration.as_secs_f64();
		let elapsed = (timestamp - self.start_timestamp_unix_secs) as f64;

		// Early on when elapsed < 5*tracked_duration, the decaying average underestimates the true sum.
		// The warmup_factor (1 - e^(-elapsed/tracked_duration)) corrects for this.
		let warmup_factor = 1.0 - expf64(-elapsed / self.tracked_duration.as_secs_f64());

		// Clamping at one means that until roughly one `average_duration` has elapsed (exactly:
		// until `num_windows * warmup_factor` reaches 1, which happens ~9% past `average_duration`)
		// we report the value accumulated so far rather than scaling it up to what a full
		// `average_duration` at that rate would be. If a new channel shows high revenue at
		// the beginning, we do not know yet whether this will be the real traffic or if this
		// is a one-off burst. If this will be the common pattern, then as history accumulates
		// it will be reflected in the average.
		let divisor = f64::max(num_windows * warmup_factor, 1.0);

		// The decaying average accumulates values over `tracked_duration`. This is divided
		// by `num_windows` to get an average over our target `average_duration` window.
		roundf64(self.aggregated_decaying_average.value_at_timestamp(timestamp) as f64 / divisor)
			as i64
	}
}

#[cfg(all(test, feature = "std"))]
mod tests {
	use std::time::Duration;

	use chacha20_poly1305::{chacha20::ChaCha20, Key, Nonce};

	use crate::{
		ln::resource_manager::{
			assign_slots_for_channel, DecayingAverage, GeneralBucket, SmoothedDecayingAverage,
		},
		ln::types::ChannelId,
		sign::EntropySource,
		util::test_utils::TestKeysInterface,
	};
	use bitcoin::Network;

	const WINDOW: Duration = Duration::from_secs(2016 * 10 * 60);

	#[test]
	fn test_general_bucket_channel_slots_count() {
		struct TestCase {
			general_slots: u16,
			general_liquidity: u64,
			expected_slots: u8,
			expected_liquidity: u64,
		}

		// Test that it correctly assigns the number of slots based on total slots in general
		// bucket
		let cases = vec![
			TestCase {
				general_slots: 20,
				general_liquidity: 100_000_000,
				expected_slots: 5,
				expected_liquidity: 5_000_000,
			},
			TestCase {
				general_slots: 50,
				general_liquidity: 100_000_000,
				expected_slots: 5,
				expected_liquidity: 2000000,
			},
			TestCase {
				general_slots: 100,
				general_liquidity: 100_000_000,
				expected_slots: 5,
				expected_liquidity: 1000000,
			},
			TestCase {
				general_slots: 114,
				general_liquidity: 300_000_000,
				expected_slots: 6,
				expected_liquidity: 2631578,
			},
			TestCase {
				general_slots: 193,
				general_liquidity: 100_000_000,
				expected_slots: 10,
				expected_liquidity: 518134,
			},
		];

		let channel_id = ChannelId([21; 32]);
		let entropy_source = TestKeysInterface::new(&[0; 32], Network::Testnet);
		let node_salt = entropy_source.get_secure_random_bytes();
		for case in cases {
			let general_bucket = GeneralBucket::new(
				ChannelId::new_zero(),
				&node_salt,
				case.general_slots,
				case.general_liquidity,
			)
			.unwrap();

			assert_eq!(general_bucket.per_channel_slots, case.expected_slots);
			assert_eq!(general_bucket.per_slot_msat, case.expected_liquidity);
			assert_eq!(general_bucket.slots_occupied.len(), case.general_slots as usize);
			assert!(general_bucket.slots_occupied.iter().all(|occupied| !occupied));

			let salt = entropy_source.get_secure_random_bytes();
			let slots = assign_slots_for_channel(
				general_bucket.channel_id,
				channel_id,
				salt,
				general_bucket.per_channel_slots,
				general_bucket.total_slots,
			);
			assert_eq!(slots.len(), case.expected_slots as usize);
		}
	}

	#[test]
	fn test_general_bucket_errors() {
		let node_salt = [0u8; 32];
		let channel_id = ChannelId::new_zero();
		// slots_allocated is below the minimum.
		assert!(GeneralBucket::new(channel_id, &node_salt, 4, 10_000).is_err());
		assert!(GeneralBucket::new(channel_id, &node_salt, 0, 10_000).is_err());

		// per_slot_msat rounds to zero.
		assert!(GeneralBucket::new(channel_id, &node_salt, 100, 0).is_err());
		assert!(GeneralBucket::new(channel_id, &node_salt, 100, 19).is_err());
	}

	fn general_add(
		general_bucket: &mut GeneralBucket, channel_id: ChannelId, htlc_amount_msat: u64,
	) -> Result<Vec<u16>, ()> {
		let slots = general_bucket.available_slots(channel_id, htlc_amount_msat).ok_or(())?;
		general_bucket.add_htlc(&slots);
		Ok(slots)
	}

	#[test]
	fn test_general_bucket_add_htlc_over_max_liquidity() {
		let entropy_source = TestKeysInterface::new(&[0; 32], Network::Testnet);
		let node_salt = entropy_source.get_secure_random_bytes();
		let mut general_bucket =
			GeneralBucket::new(ChannelId::new_zero(), &node_salt, 100, 10_000).unwrap();
		debug_assert_eq!(general_bucket.per_channel_slots, 5);
		debug_assert_eq!(general_bucket.per_slot_msat, 100);

		let channel_id = ChannelId([21; 32]);
		let htlc_amount_over_max = 600;
		// General bucket will assign 5 slots of 100 per channel. Max 5 * 100 = 500
		// An HTLC over the amount cannot find enough free slots.
		assert!(general_add(&mut general_bucket, channel_id, htlc_amount_over_max).is_err());

		// No slots should be occupied since the HTLC was not added.
		assert!(general_bucket.slots_occupied.iter().all(|occupied| !occupied));
	}

	#[test]
	fn test_general_bucket_add_htlc() {
		let entropy_source = TestKeysInterface::new(&[0; 32], Network::Testnet);
		let node_salt = entropy_source.get_secure_random_bytes();
		// General bucket will assign 5 slots of 100 per channel. Max 5 * 100 = 500
		let mut general_bucket =
			GeneralBucket::new(ChannelId::new_zero(), &node_salt, 100, 10_000).unwrap();
		debug_assert_eq!(general_bucket.per_channel_slots, 5);
		debug_assert_eq!(general_bucket.per_slot_msat, 100);

		let channel_id = ChannelId([21; 32]);
		// HTLC of 100 should take one slot
		let slots = general_add(&mut general_bucket, channel_id, 100).unwrap();
		assert_eq!(slots.len(), 1);
		assert!(general_bucket.slots_occupied[slots[0] as usize]);

		// HTLC of 250 should take 3 general slots
		let slots = general_add(&mut general_bucket, channel_id, 250).unwrap();
		assert_eq!(slots.len(), 3);
		for slot in slots.iter() {
			assert!(general_bucket.slots_occupied[*slot as usize]);
		}

		// 4 slots have been taken. Trying to add HTLC that will take 2 or more slots should fail
		// now.
		assert!(general_add(&mut general_bucket, channel_id, 200).is_err());
		// Exactly one of the channel's assigned slots remains free.
		let free = general_bucket.available_slots(channel_id, 100);
		assert_eq!(free.unwrap().len(), 1);
	}

	#[test]
	fn test_general_bucket_remove_htlc() {
		let entropy_source = TestKeysInterface::new(&[0; 32], Network::Testnet);
		let node_salt = entropy_source.get_secure_random_bytes();
		let mut general_bucket =
			GeneralBucket::new(ChannelId::new_zero(), &node_salt, 100, 10_000).unwrap();

		let channel_id = ChannelId([21; 32]);
		let htlc_amount = 100;
		let slots = general_add(&mut general_bucket, channel_id, htlc_amount).unwrap();
		assert_eq!(slots.len(), 1);
		let slot_occupied = slots[0];
		assert!(general_bucket.slots_occupied[slot_occupied as usize]);

		general_bucket.remove_htlc(&slots);
		assert!(!general_bucket.slots_occupied[slot_occupied as usize]);
	}

	#[test]
	fn test_decaying_average_bounds() {
		for (start, bound) in [(1000, i64::MAX), (-1000, i64::MIN)] {
			let timestamp = 1000;
			let mut avg = DecayingAverage::new(timestamp, WINDOW);
			assert_eq!(avg.add_value(start, timestamp), start);
			assert_eq!(avg.add_value(bound, timestamp), bound);
		}
	}

	#[test]
	fn test_value_decays_to_zero_eventually() {
		let timestamp = 1000;
		let mut avg = DecayingAverage::new(timestamp, Duration::from_secs(100));
		assert_eq!(avg.add_value(100_000_000, timestamp), 100_000_000);

		// After many window periods, value should decay to 0
		assert_eq!(avg.value_at_timestamp(timestamp * 1000), 0);
	}

	#[test]
	fn test_decaying_average_values() {
		// Test average decay at different timestamps. The values we are asserting have been
		// independently calculated.
		let mut current_timestamp = 0;
		let mut avg = DecayingAverage::new(current_timestamp, WINDOW);

		assert_eq!(avg.add_value(1000, current_timestamp), 1000);

		let one_week = 60 * 60 * 24 * 7;

		current_timestamp += one_week; // 1 week
		assert_eq!(avg.value_at_timestamp(current_timestamp), 607);
		assert_eq!(avg.add_value(500, current_timestamp), 1107);

		current_timestamp += one_week / 2; // 1.5 weeks
		assert_eq!(avg.value_at_timestamp(current_timestamp), 862);

		current_timestamp += one_week / 2; // 2 weeks
		assert_eq!(avg.value_at_timestamp(current_timestamp), 671);
		assert_eq!(avg.add_value(200, current_timestamp), 871);

		current_timestamp += one_week * 2; // 4 weeks
		assert_eq!(avg.value_at_timestamp(current_timestamp), 320);

		current_timestamp += one_week * 6; // 10 weeks
		assert_eq!(avg.value_at_timestamp(current_timestamp), 16);
		assert_eq!(avg.add_value(1000, current_timestamp), 1016);

		current_timestamp += avg.half_life as u64;
		assert_eq!(avg.value_at_timestamp(current_timestamp), 1016 / 2);
	}

	#[test]
	fn test_aggregated_window_average() {
		let week_secs: u64 = 60 * 60 * 24 * 7;
		let num_windows = 6;
		let average_duration = Duration::from_secs(2 * week_secs);

		// Number of random data points to generate.
		let num_points: usize = 50_000;
		let duration_weeks: u64 = 120;
		let skip_weeks: u64 = 10;
		let start_timestamp: u64 = 0;

		let mut prng = ChaCha20::new(Key::new([42u8; 32]), Nonce::new([0u8; 12]), 0);
		let mut data = Vec::with_capacity(num_points);
		for _ in 0..num_points {
			let mut buf = [0u8; 8];
			prng.apply_keystream(&mut buf);
			let ts = start_timestamp + u64::from_le_bytes(buf) % (duration_weeks * week_secs);

			let mut buf = [0u8; 4];
			prng.apply_keystream(&mut buf);
			let val = (u32::from_le_bytes(buf) % 49_001 + 1_000) as i64;
			data.push((ts, val));
		}

		data.sort_by_key(|&(ts, _)| ts);

		let mut avg =
			SmoothedDecayingAverage::new(average_duration, num_windows as u8, start_timestamp);
		let mut data_idx = 0;

		for w in 1..=duration_weeks {
			let sample_time = start_timestamp + w * week_secs;

			// Add all data points up to this sample time.
			while data_idx < num_points && data[data_idx].0 <= sample_time {
				avg.add_value(data[data_idx].1, data[data_idx].0);
				data_idx += 1;
			}

			let approx_avg = avg.value_at_timestamp(sample_time);

			let mut window_sums = Vec::with_capacity(num_windows);
			for i in 0..num_windows {
				let window_end = sample_time - i as u64 * average_duration.as_secs();
				if window_end < average_duration.as_secs() + start_timestamp {
					break;
				}
				let window_start = window_end - average_duration.as_secs();
				let window_sum: i64 = data
					.iter()
					.filter(|&&(t, _)| t > window_start && t <= window_end)
					.map(|&(_, v)| v)
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

			let accepted_error = if w < skip_weeks { 10.0 } else { 3.0 };
			assert!(
				error_pct.abs() < accepted_error,
				"week {w}: error {error_pct:.2}% exceeds {accepted_error:.2} \
				 (approx={approx_avg}, actual={actual_avg})"
			);
		}
	}
}
