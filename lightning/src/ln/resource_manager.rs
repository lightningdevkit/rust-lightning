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
use core::time::Duration;

use crate::{
	crypto::chacha20::ChaCha20,
	prelude::{hash_map::Entry, new_hash_map, HashMap, Vec},
};

/// The minimum number of slots required for the general bucket to function.
const MIN_GENERAL_BUCKET_SLOTS: u16 = 5;

struct GeneralBucket {
	/// Our SCID
	scid: u64,

	total_slots: u16,
	total_liquidity: u64,

	/// The number of slots in the general bucket that each forwarding channel pair gets.
	per_channel_slots: u8,
	/// The liquidity amount of each slot in the general bucket that each forwarding channel pair
	/// gets.
	per_slot_msat: u64,

	/// A bitset tracking the occupancy of HTLC slots in the bucket, where bit `i` indicates
	/// whether the slot is currently used by any channel. Slot indices never exceed 483, so a
	/// [u64; 8] is always sufficient.
	slots_occupied: [u64; 8],

	/// SCID -> slots assigned
	/// Maps short channel IDs to the slots that the channel is allowed to use. The low 15 bits of
	/// each entry hold the slot index (always < 483, so they fit), and bit 15
	/// ([`SLOT_USED_BIT`]) flags whether this channel is currently using that slot.
	channels_slots: HashMap<u64, Vec<u16>>,
}

/// Bit 15 of a [`GeneralBucket::channels_slots`] entry flags whether the channel currently
/// occupies that slot. Slot indices never exceed 483, so the low 15 bits always hold the index.
const SLOT_USED_BIT: u16 = 15;
const SLOT_INDEX_MASK: u16 = 0x7FFF;

/// Returns the slot index encoded in a [`GeneralBucket::channels_slots`] entry.
fn slot_index(entry: u16) -> u16 {
	entry & SLOT_INDEX_MASK
}

/// Returns whether a [`GeneralBucket::channels_slots`] entry is flagged as currently used by its
/// channel.
fn slot_used(entry: u16) -> bool {
	entry & (1 << SLOT_USED_BIT) != 0
}

impl GeneralBucket {
	fn new(scid: u64, slots_allocated: u16, liquidity_allocated: u64) -> Result<Self, ()> {
		if slots_allocated < MIN_GENERAL_BUCKET_SLOTS {
			return Err(());
		}

		let per_channel_slots = u8::max(
			MIN_GENERAL_BUCKET_SLOTS as u8,
			u8::try_from((slots_allocated * MIN_GENERAL_BUCKET_SLOTS).div_ceil(100)).unwrap(),
		);

		let per_slot_msat = liquidity_allocated * per_channel_slots as u64 / slots_allocated as u64;
		// This is a sanity check but based on the minimum channel size accepted by LDK and the
		// max_accepted_htlcs limit of 483 we do not expect to hit this.
		if per_slot_msat == 0 {
			return Err(());
		}
		Ok(GeneralBucket {
			scid,
			total_slots: slots_allocated,
			total_liquidity: liquidity_allocated,
			per_channel_slots,
			per_slot_msat,
			slots_occupied: [0; 8],
			channels_slots: new_hash_map(),
		})
	}

	/// Returns whether slot `idx` is currently occupied by any channel in the bucket.
	fn is_slot_occupied(&self, idx: u16) -> bool {
		self.slots_occupied[(idx / 64) as usize] & (1u64 << (idx % 64)) != 0
	}

	/// Marks the given slot indices as occupied (or frees them) in the bucket-wide bitset.
	fn set_slots_occupied(&mut self, slots: &[u16], occupied: bool) {
		for idx in slots {
			let word = (idx / 64) as usize;
			let mask = 1u64 << (idx % 64);
			if occupied {
				debug_assert!(self.slots_occupied[word] & mask == 0);
				self.slots_occupied[word] |= mask;
			} else {
				debug_assert!(self.slots_occupied[word] & mask != 0);
				self.slots_occupied[word] &= !mask;
			}
		}
	}

	fn slots_used_by_channel(&self, outgoing_scid: u64) -> Vec<u16> {
		self.channels_slots
			.get(&outgoing_scid)
			.map(|slots| slots.iter().filter(|e| slot_used(**e)).map(|e| slot_index(*e)).collect())
			.unwrap_or_default()
	}

	fn set_channel_slots_used(
		&mut self, outgoing_scid: u64, slots: &[u16], used: bool,
	) -> Result<(), ()> {
		let channel_slots = self.channels_slots.get_mut(&outgoing_scid).ok_or(())?;
		for entry in channel_slots.iter_mut() {
			if slots.contains(&slot_index(*entry)) {
				if used {
					debug_assert!(!slot_used(*entry));
					*entry |= 1 << SLOT_USED_BIT;
				} else {
					debug_assert!(slot_used(*entry));
					*entry &= !(1 << SLOT_USED_BIT);
				}
			}
		}
		Ok(())
	}

	/// Returns the available slots that could be used by the outgoing scid for the specified
	/// htlc amount.
	fn slots_for_amount(
		&mut self, outgoing_scid: u64, htlc_amount_msat: u64, node_salt: &[u8; 32],
	) -> Result<Option<Vec<u16>>, ()> {
		let slots_needed = u64::max(1, htlc_amount_msat.div_ceil(self.per_slot_msat));

		let channel_slots = match self.channels_slots.entry(outgoing_scid) {
			Entry::Occupied(e) => e.get().clone(),
			Entry::Vacant(entry) => {
				let salt = derive_channel_salt(node_salt, outgoing_scid);
				let slots = assign_slots_for_channel(
					self.scid,
					outgoing_scid,
					salt,
					self.per_channel_slots,
					self.total_slots,
				)?;
				entry.insert(slots.clone());
				slots
			},
		};

		let slots_to_use: Vec<u16> = channel_slots
			.iter()
			.map(|entry| slot_index(*entry))
			.filter(|idx| !self.is_slot_occupied(*idx))
			.take(slots_needed as usize)
			.collect();

		if (slots_to_use.len() as u64) < slots_needed {
			Ok(None)
		} else {
			Ok(Some(slots_to_use))
		}
	}

	fn can_add_htlc(
		&mut self, outgoing_scid: u64, htlc_amount_msat: u64, node_salt: &[u8; 32],
	) -> Result<bool, ()> {
		Ok(self.slots_for_amount(outgoing_scid, htlc_amount_msat, node_salt)?.is_some())
	}

	fn add_htlc(
		&mut self, outgoing_scid: u64, htlc_amount_msat: u64, node_salt: &[u8; 32],
	) -> Result<Vec<u16>, ()> {
		match self.slots_for_amount(outgoing_scid, htlc_amount_msat, node_salt)? {
			Some(slots) => {
				self.set_slots_occupied(&slots, true);
				self.set_channel_slots_used(outgoing_scid, &slots, true)?;
				Ok(slots)
			},
			None => Err(()),
		}
	}

	fn remove_htlc(&mut self, outgoing_scid: u64, htlc_amount_msat: u64) -> Result<(), ()> {
		let slots_needed = u64::max(1, htlc_amount_msat.div_ceil(self.per_slot_msat));

		let mut to_release = self.slots_used_by_channel(outgoing_scid);
		if slots_needed > to_release.len() as u64 {
			return Err(());
		}

		// Release only the first `slots_needed` slots
		to_release.truncate(slots_needed as usize);

		self.set_slots_occupied(&to_release, false);
		self.set_channel_slots_used(outgoing_scid, &to_release, false)?;

		Ok(())
	}

	fn remove_channel_slots(&mut self, outgoing_scid: u64) {
		let used = self.slots_used_by_channel(outgoing_scid);
		self.set_slots_occupied(&used, false);
		self.channels_slots.remove(&outgoing_scid);
	}
}

fn assign_slots_for_channel(
	incoming_scid: u64, outgoing_scid: u64, salt: [u8; 32], per_channel_slots: u8, total_slots: u16,
) -> Result<Vec<u16>, ()> {
	debug_assert_ne!(incoming_scid, outgoing_scid);

	let mut channel_slots = Vec::with_capacity(per_channel_slots.into());
	let mut slots_assigned_counter = 0;

	let mut nonce = [0u8; 12];
	nonce[..4].copy_from_slice(&incoming_scid.to_be_bytes()[..4]);
	nonce[4..].copy_from_slice(&outgoing_scid.to_be_bytes());
	let mut prng = ChaCha20::new(&salt, &nonce);
	let mut buf = [0u8; 4];

	let max_attempts = per_channel_slots * 10;
	for _ in 0..max_attempts {
		if slots_assigned_counter == per_channel_slots {
			break;
		}

		prng.process_in_place(&mut buf);
		let slot_idx: u16 = (u32::from_le_bytes(buf) % total_slots as u32) as u16;
		if !channel_slots.contains(&slot_idx) {
			channel_slots.push(slot_idx);
			slots_assigned_counter += 1;
		}
	}

	if slots_assigned_counter < per_channel_slots {
		return Err(());
	}

	Ok(channel_slots)
}

fn derive_channel_salt(node_salt: &[u8; 32], outgoing_scid: u64) -> [u8; 32] {
	let mut engine = sha256::Hash::engine();
	engine.input(node_salt);
	engine.input(&outgoing_scid.to_be_bytes());
	sha256::Hash::from_engine(engine).to_byte_array()
}

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

	fn value_at_timestamp(&mut self, timestamp_unix_secs: u64) -> i64 {
		let timestamp = u64::max(timestamp_unix_secs, self.last_updated_unix_secs);
		let elapsed_secs = (timestamp - self.last_updated_unix_secs) as f64;
		let decay_rate = 0.5_f64.powf(elapsed_secs / self.half_life);
		self.value = (self.value as f64 * decay_rate).round() as i64;
		self.last_updated_unix_secs = timestamp;
		self.value
	}

	fn add_value(&mut self, value: i64, timestamp_unix_secs: u64) -> i64 {
		self.value_at_timestamp(timestamp_unix_secs);
		self.value = self.value.saturating_add(value);
		self.value
	}
}

/// Tracks an average value over [`Self::average_duration`], smoothing out short-term volatility.
/// This tells us what our average value was over [`Self::average_duration`] of time, measured
/// across the last N periods of [`Self::average_duration`] length (where
/// [`Self::tracked_duration`] = [`Self::average_duration`] * N).
///
///  Implemented by aggregating several such windows into a single longer decaying average whose
///  window equals the total duration being tracked.
struct AggregatedWindowAverage {
	start_timestamp_unix_secs: u64,
	average_duration: Duration,
	tracked_duration: Duration,
	aggregated_decaying_average: DecayingAverage,
}

impl AggregatedWindowAverage {
	fn new(
		average_duration: Duration, window_multiplier: u8, start_timestamp_unix_secs: u64,
	) -> Self {
		let tracked_duration = average_duration * window_multiplier as u32;
		AggregatedWindowAverage {
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

	fn value_at_timestamp(&mut self, timestamp_unix_secs: u64) -> i64 {
		let timestamp = u64::max(timestamp_unix_secs, self.start_timestamp_unix_secs);

		let num_windows = self.tracked_duration.as_secs_f64() / self.average_duration.as_secs_f64();
		let elapsed = (timestamp - self.start_timestamp_unix_secs) as f64;
		// Early on when elapsed < 5*window, the decaying average underestimates the true sum.
		// The warmup_factor (1 - e^(-elapsed/window)) corrects for this.
		let warmup_factor = 1.0 - (-elapsed / self.tracked_duration.as_secs_f64()).exp();
		let divisor = f64::max(num_windows * warmup_factor, 1.0);

		// The decaying average accumulates values over `tracked_duration`. This is divided
		// by `num_windows` to get an average over our target `average_duration` window.
		(self.aggregated_decaying_average.value_at_timestamp(timestamp) as f64 / divisor).round()
			as i64
	}
}

#[cfg(test)]
mod tests {
	use std::time::Duration;

	use crate::{
		crypto::chacha20::ChaCha20,
		ln::resource_manager::{
			assign_slots_for_channel, slot_index, slot_used, AggregatedWindowAverage,
			DecayingAverage, GeneralBucket,
		},
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
				expected_liquidity: 25_000_000,
			},
			TestCase {
				general_slots: 50,
				general_liquidity: 100_000_000,
				expected_slots: 5,
				expected_liquidity: 10_000_000,
			},
			TestCase {
				general_slots: 100,
				general_liquidity: 100_000_000,
				expected_slots: 5,
				expected_liquidity: 5_000_000,
			},
			TestCase {
				general_slots: 114,
				general_liquidity: 300_000_000,
				expected_slots: 6,
				expected_liquidity: 15789473,
			},
			TestCase {
				general_slots: 193,
				general_liquidity: 100_000_000,
				expected_slots: 10,
				expected_liquidity: 5_181_347,
			},
		];

		let scid = 21;
		let entropy_source = TestKeysInterface::new(&[0; 32], Network::Testnet);
		for case in cases {
			let general_bucket =
				GeneralBucket::new(0, case.general_slots, case.general_liquidity).unwrap();

			assert_eq!(general_bucket.per_channel_slots, case.expected_slots);
			assert_eq!(general_bucket.per_slot_msat, case.expected_liquidity);
			assert_eq!(general_bucket.slots_occupied, [0u64; 8]);

			let salt = entropy_source.get_secure_random_bytes();
			let slots = assign_slots_for_channel(
				general_bucket.scid,
				scid,
				salt,
				general_bucket.per_channel_slots,
				general_bucket.total_slots,
			)
			.unwrap();
			assert_eq!(slots.len(), case.expected_slots as usize);
		}
	}

	#[test]
	fn test_general_bucket_errors() {
		// slots_allocated is below the minimum.
		assert!(GeneralBucket::new(0, 4, 10_000).is_err());
		assert!(GeneralBucket::new(0, 0, 10_000).is_err());

		// per_slot_msat rounds to zero.
		assert!(GeneralBucket::new(0, 100, 0).is_err());
		assert!(GeneralBucket::new(0, 100, 19).is_err());
	}

	#[test]
	fn test_general_bucket_add_htlc_over_max_liquidity() {
		let entropy_source = TestKeysInterface::new(&[0; 32], Network::Testnet);
		let node_salt = entropy_source.get_secure_random_bytes();
		let mut general_bucket = GeneralBucket::new(0, 100, 10_000).unwrap();
		debug_assert_eq!(general_bucket.per_channel_slots, 5);
		debug_assert_eq!(general_bucket.per_slot_msat, 500);

		let scid = 21;
		let htlc_amount_over_max = 3000;
		// General bucket will assign 5 slots of 500 per channel. Max 5 * 500 = 2500
		// Adding an HTLC over the amount should return error.
		let add_htlc_res = general_bucket.add_htlc(scid, htlc_amount_over_max, &node_salt);
		assert!(add_htlc_res.is_err());

		// All slots for the channel should be unoccupied since adding the HTLC failed.
		let slots = general_bucket.channels_slots.get(&scid).unwrap();
		assert!(slots
			.iter()
			.all(|entry| !slot_used(*entry) && !general_bucket.is_slot_occupied(*entry)));
	}

	/// Asserts that `slot` is occupied by `scid`: the global occupancy bit is set and `scid`'s
	/// `channels_slots` entry for that slot is flagged as used.
	fn assert_slot_occupied_by(general_bucket: &GeneralBucket, scid: u64, slot: u16) {
		assert!(general_bucket.is_slot_occupied(slot));
		let channel_slots = general_bucket.channels_slots.get(&scid).unwrap();
		assert!(channel_slots.iter().any(|entry| slot_index(*entry) == slot && slot_used(*entry)));
	}

	#[test]
	fn test_general_bucket_add_htlc() {
		let entropy_source = TestKeysInterface::new(&[0; 32], Network::Testnet);
		let node_salt = entropy_source.get_secure_random_bytes();
		// General bucket will assign 5 slots of 500 per channel. Max 5 * 500 = 2500
		let mut general_bucket = GeneralBucket::new(0, 100, 10_000).unwrap();
		debug_assert_eq!(general_bucket.per_channel_slots, 5);
		debug_assert_eq!(general_bucket.per_slot_msat, 500);

		let scid = 21;
		// HTLC of 500 should take one slot
		let add_htlc_res = general_bucket.add_htlc(scid, 500, &node_salt);
		assert!(add_htlc_res.is_ok());
		let slots_occupied = add_htlc_res.unwrap();
		assert_eq!(slots_occupied.len(), 1);

		let slot_occupied = slots_occupied[0];
		assert_slot_occupied_by(&general_bucket, scid, slot_occupied);

		// HTLC of 1200 should take 3 general slots
		let add_htlc_res = general_bucket.add_htlc(scid, 1200, &node_salt);
		assert!(add_htlc_res.is_ok());
		let slots_occupied = add_htlc_res.unwrap();
		assert_eq!(slots_occupied.len(), 3);

		for slot_occupied in slots_occupied.iter() {
			assert_slot_occupied_by(&general_bucket, scid, *slot_occupied);
		}

		// 4 slots have been taken. Trying to add HTLC that will take 2 or more slots should fail
		// now.
		assert!(general_bucket.add_htlc(scid, 501, &node_salt).is_err());
		let channel_slots = general_bucket.channels_slots.get(&scid).unwrap();
		let unoccupied_slots_for_channel: Vec<&u16> = channel_slots
			.iter()
			.filter(|entry| !general_bucket.is_slot_occupied(slot_index(**entry)))
			.collect();
		assert_eq!(unoccupied_slots_for_channel.len(), 1);
	}

	#[test]
	fn test_general_bucket_remove_htlc() {
		let entropy_source = TestKeysInterface::new(&[0; 32], Network::Testnet);
		let node_salt = entropy_source.get_secure_random_bytes();
		let mut general_bucket = GeneralBucket::new(0, 100, 10_000).unwrap();

		let scid = 21;
		let htlc_amount = 400;
		let slots_occupied = general_bucket.add_htlc(scid, htlc_amount, &node_salt).unwrap();
		assert_eq!(slots_occupied.len(), 1);
		let slot_occupied = slots_occupied[0];
		assert_slot_occupied_by(&general_bucket, scid, slot_occupied);

		// Trying to remove HTLC over number of slots previously used should result in a error
		assert!(general_bucket.remove_htlc(scid, htlc_amount + 400).is_err());
		assert!(general_bucket.remove_htlc(scid, htlc_amount).is_ok());

		assert!(!general_bucket.is_slot_occupied(slot_occupied));
		let channel_slots = general_bucket.channels_slots.get(&scid).unwrap();
		assert!(channel_slots.iter().all(|entry| !slot_used(*entry)));
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

		let mut prng = ChaCha20::new(&[42u8; 32], &[0u8; 12]);
		let mut data = Vec::with_capacity(num_points);
		for _ in 0..num_points {
			let mut buf = [0u8; 8];
			prng.process_in_place(&mut buf);
			let ts = start_timestamp + u64::from_le_bytes(buf) % (duration_weeks * week_secs);

			let mut buf = [0u8; 4];
			prng.process_in_place(&mut buf);
			let val = (u32::from_le_bytes(buf) % 49_001 + 1_000) as i64;
			data.push((ts, val));
		}

		data.sort_by_key(|&(ts, _)| ts);

		let mut avg =
			AggregatedWindowAverage::new(average_duration, num_windows as u8, start_timestamp);
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
