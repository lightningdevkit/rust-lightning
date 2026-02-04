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

use crate::{
	crypto::chacha20::ChaCha20,
	ln::channel::TOTAL_BITCOIN_SUPPLY_SATOSHIS,
	prelude::{hash_map::Entry, new_hash_map, HashMap},
	sign::EntropySource,
};

#[derive(Clone, PartialEq, Eq, Debug)]
enum BucketAssigned {
	General,
	Congestion,
	Protected,
}

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

	/// Tracks the occupancy of HTLC slots in the bucket where the index represents the slot
	/// number and the optional value indicates which channel is currently using the slot.
	slots_occupied: Vec<Option<u64>>,

	/// SCID -> (slots assigned, salt)
	/// Maps short channel IDs to the slots that the channel is allowed to use and the salt. The
	/// salt is stored to deterministically generate the slots for each channel on restarts.
	channels_slots: HashMap<u64, (Vec<u16>, [u8; 32])>,
}

impl GeneralBucket {
	fn new(scid: u64, slots_allocated: u16, liquidity_allocated: u64) -> Self {
		let general_slot_allocation =
			u8::max(5, u8::try_from((slots_allocated * 5).div_ceil(100)).unwrap());

		let general_liquidity_allocation =
			liquidity_allocated * general_slot_allocation as u64 / slots_allocated as u64;
		GeneralBucket {
			scid,
			total_slots: slots_allocated,
			total_liquidity: liquidity_allocated,
			per_channel_slots: general_slot_allocation,
			per_slot_msat: general_liquidity_allocation,
			slots_occupied: vec![None; slots_allocated as usize],
			channels_slots: new_hash_map(),
		}
	}

	/// Returns the available slots that could be used by the outgoing scid for the specified
	/// htlc amount.
	fn slots_for_amount<ES: EntropySource>(
		&mut self, outgoing_scid: u64, htlc_amount_msat: u64, entropy_source: &ES,
	) -> Result<Option<Vec<u16>>, ()> {
		let slots_needed = u64::max(1, htlc_amount_msat.div_ceil(self.per_slot_msat));

		let assigned;
		let channel_slots: &[u16] = match self.channels_slots.get(&outgoing_scid) {
			Some(slots) => slots.0.as_ref(),
			None => {
				assigned = self.assign_slots_for_channel(outgoing_scid, None, entropy_source)?;
				&assigned
			},
		};

		let slots_to_use: Vec<u16> = channel_slots
			.iter()
			.filter(|idx| match self.slots_occupied.get(**idx as usize) {
				Some(is_occupied) => is_occupied.is_none(),
				None => {
					debug_assert!(false, "assigned slot {} is not present in slots_occupied", idx);
					false
				},
			})
			.take(slots_needed as usize)
			.copied()
			.collect();

		if (slots_to_use.len() as u64) < slots_needed {
			Ok(None)
		} else {
			Ok(Some(slots_to_use))
		}
	}

	fn can_add_htlc<ES: EntropySource>(
		&mut self, outgoing_scid: u64, htlc_amount_msat: u64, entropy_source: &ES,
	) -> Result<bool, ()> {
		Ok(self.slots_for_amount(outgoing_scid, htlc_amount_msat, entropy_source)?.is_some())
	}

	fn add_htlc<ES: EntropySource>(
		&mut self, outgoing_scid: u64, htlc_amount_msat: u64, entropy_source: &ES,
	) -> Result<Vec<u16>, ()> {
		match self.slots_for_amount(outgoing_scid, htlc_amount_msat, entropy_source)? {
			Some(slots) => {
				for slot_idx in &slots {
					debug_assert!(self.slots_occupied[*slot_idx as usize].is_none());
					self.slots_occupied[*slot_idx as usize] = Some(outgoing_scid);
				}
				Ok(slots)
			},
			None => Err(()),
		}
	}

	fn remove_htlc(&mut self, outgoing_scid: u64, htlc_amount_msat: u64) -> Result<(), ()> {
		let channel_slots = match self.channels_slots.get(&outgoing_scid) {
			Some((slots, _)) => slots,
			None => return Err(()),
		};

		let slots_needed = u64::max(1, htlc_amount_msat.div_ceil(self.per_slot_msat));

		let mut slots_used_by_channel: Vec<u16> = channel_slots
			.iter()
			.filter(|slot_idx| self.slots_occupied[**slot_idx as usize] == Some(outgoing_scid))
			.copied()
			.collect();

		if slots_needed > slots_used_by_channel.len() as u64 {
			return Err(());
		}
		let slots_released: Vec<u16> =
			slots_used_by_channel.drain(0..slots_needed as usize).collect();

		for slot_idx in slots_released {
			debug_assert!(self.slots_occupied[slot_idx as usize] == Some(outgoing_scid));
			self.slots_occupied[slot_idx as usize] = None;
		}
		Ok(())
	}

	fn assign_slots_for_channel<ES: EntropySource>(
		&mut self, outgoing_scid: u64, salt: Option<[u8; 32]>, entropy_source: &ES,
	) -> Result<Vec<u16>, ()> {
		debug_assert_ne!(self.scid, outgoing_scid);

		match self.channels_slots.entry(outgoing_scid) {
			Entry::Occupied(e) => Ok(e.get().0.clone()),
			Entry::Vacant(entry) => {
				let mut channel_slots = Vec::with_capacity(self.per_channel_slots.into());
				let mut slots_assigned_counter = 0;
				let salt = salt.unwrap_or(entropy_source.get_secure_random_bytes());

				let mut nonce = [0u8; 12];
				nonce[..4].copy_from_slice(&self.scid.to_be_bytes()[..4]);
				nonce[4..].copy_from_slice(&outgoing_scid.to_be_bytes());
				let mut prng = ChaCha20::new(&salt, &nonce);
				let mut buf = [0u8; 4];

				let max_attempts = self.per_channel_slots * 2;
				for _ in 0..max_attempts {
					if slots_assigned_counter == self.per_channel_slots {
						break;
					}

					prng.process_in_place(&mut buf);
					let slot_idx: u16 = (u32::from_le_bytes(buf) % self.total_slots as u32) as u16;
					if !channel_slots.contains(&slot_idx) {
						channel_slots.push(slot_idx);
						slots_assigned_counter += 1;
					}
				}

				if slots_assigned_counter < self.per_channel_slots {
					return Err(());
				}

				entry.insert((channel_slots.clone(), salt));
				Ok(channel_slots)
			},
		}
	}

	fn remove_channel_slots(&mut self, outgoing_scid: u64) {
		if let Some((slots, _)) = self.channels_slots.remove(&outgoing_scid) {
			for slot_idx in slots {
				if self.slots_occupied[slot_idx as usize] == Some(outgoing_scid) {
					self.slots_occupied[slot_idx as usize] = None;
				}
			}
		}
	}
}

struct BucketResources {
	slots_allocated: u16,
	slots_used: u16,
	liquidity_allocated: u64,
	liquidity_used: u64,
}

impl BucketResources {
	fn new(slots_allocated: u16, liquidity_allocated: u64) -> Self {
		BucketResources { slots_allocated, slots_used: 0, liquidity_allocated, liquidity_used: 0 }
	}

	fn resources_available(&self, htlc_amount_msat: u64) -> bool {
		return (self.liquidity_used + htlc_amount_msat <= self.liquidity_allocated)
			&& (self.slots_used < self.slots_allocated);
	}

	fn add_htlc(&mut self, htlc_amount_msat: u64) -> Result<(), ()> {
		if !self.resources_available(htlc_amount_msat) {
			return Err(());
		}

		self.slots_used += 1;
		self.liquidity_used += htlc_amount_msat;
		Ok(())
	}

	fn remove_htlc(&mut self, htlc_amount_msat: u64) -> Result<(), ()> {
		if self.slots_used == 0 || self.liquidity_used < htlc_amount_msat {
			return Err(());
		}
		self.slots_used -= 1;
		self.liquidity_used -= htlc_amount_msat;
		Ok(())
	}
}

#[derive(Debug, Clone)]
struct PendingHTLC {
	incoming_amount_msat: u64,
	fee: u64,
	outgoing_channel: u64,
	outgoing_accountable: bool,
	added_at_unix_seconds: u64,
	in_flight_risk: u64,
	bucket: BucketAssigned,
}

#[derive(Debug, PartialEq, Eq, Hash)]
struct HtlcRef {
	incoming_channel_id: u64,
	htlc_id: u64,
}

struct Channel {
	/// The reputation this channel has accrued as an outgoing link.
	outgoing_reputation: DecayingAverage,

	/// The revenue this channel has earned us as an incoming link.
	incoming_revenue: AggregatedWindowAverage,

	/// HTLC Ref incoming channel -> pending HTLC outgoing.
	/// It tracks all the pending HTLCs where this channel is the outgoing link.
	pending_htlcs: HashMap<HtlcRef, PendingHTLC>,

	general_bucket: GeneralBucket,
	congestion_bucket: BucketResources,
	/// SCID -> unix seconds timestamp
	/// Tracks which channels have misused the congestion bucket and the unix timestamp.
	last_congestion_misuse: HashMap<u64, u64>,
	protected_bucket: BucketResources,
}

impl Channel {
	fn new(
		scid: u64, max_htlc_value_in_flight_msat: u64, max_accepted_htlcs: u16,
		general_bucket_pct: u8, congestion_bucket_pct: u8, reputation_window: Duration,
		revenue_window_weeks: u8, revenue_week_avg: u8, timestamp_unix_secs: u64,
	) -> Result<Self, ()> {
		if max_accepted_htlcs > 483
			|| (max_htlc_value_in_flight_msat / 1000) >= TOTAL_BITCOIN_SUPPLY_SATOSHIS
		{
			return Err(());
		}

		if general_bucket_pct + congestion_bucket_pct >= 100 {
			return Err(());
		}

		let general_bucket_slots_allocated = max_accepted_htlcs * general_bucket_pct as u16 / 100;
		let general_bucket_liquidity_allocated =
			max_htlc_value_in_flight_msat * general_bucket_pct as u64 / 100;

		let congestion_bucket_slots_allocated =
			max_accepted_htlcs * congestion_bucket_pct as u16 / 100;
		let congestion_bucket_liquidity_allocated =
			max_htlc_value_in_flight_msat * congestion_bucket_pct as u64 / 100;

		let protected_bucket_slots_allocated =
			max_accepted_htlcs - general_bucket_slots_allocated - congestion_bucket_slots_allocated;
		let protected_bucket_liquidity_allocated = max_htlc_value_in_flight_msat
			- general_bucket_liquidity_allocated
			- congestion_bucket_liquidity_allocated;

		Ok(Channel {
			outgoing_reputation: DecayingAverage::new(timestamp_unix_secs, reputation_window),
			incoming_revenue: AggregatedWindowAverage::new(
				revenue_week_avg,
				revenue_window_weeks,
				timestamp_unix_secs,
			),
			pending_htlcs: new_hash_map(),
			general_bucket: GeneralBucket::new(
				scid,
				general_bucket_slots_allocated,
				general_bucket_liquidity_allocated,
			),
			congestion_bucket: BucketResources::new(
				congestion_bucket_slots_allocated,
				congestion_bucket_liquidity_allocated,
			),
			last_congestion_misuse: new_hash_map(),
			protected_bucket: BucketResources::new(
				protected_bucket_slots_allocated,
				protected_bucket_liquidity_allocated,
			),
		})
	}

	fn general_available<ES: EntropySource>(
		&mut self, incoming_amount_msat: u64, outgoing_channel_id: u64, entropy_source: &ES,
	) -> Result<bool, ()> {
		Ok(self.general_bucket.can_add_htlc(
			outgoing_channel_id,
			incoming_amount_msat,
			entropy_source,
		)?)
	}

	fn congestion_eligible(
		&mut self, pending_htlcs_in_congestion: bool, incoming_amount_msat: u64,
		outgoing_channel_id: u64, at_timestamp: u64,
	) -> Result<bool, ()> {
		Ok(!pending_htlcs_in_congestion
			&& self.can_add_htlc_congestion(
				outgoing_channel_id,
				incoming_amount_msat,
				at_timestamp,
			)?)
	}

	fn misused_congestion(&mut self, channel_id: u64, misuse_timestamp: u64) {
		self.last_congestion_misuse.insert(channel_id, misuse_timestamp);
	}

	// Returns whether the outgoing channel has misused the congestion bucket in the last two
	// weeks.
	fn has_misused_congestion(
		&mut self, outgoing_scid: u64, at_timestamp: u64,
	) -> Result<bool, ()> {
		match self.last_congestion_misuse.entry(outgoing_scid) {
			Entry::Vacant(_) => Ok(false),
			Entry::Occupied(last_misuse) => {
				// If the last misuse of the congestion bucket was over more than the
				// revenue window, remote the entry.
				if at_timestamp < *last_misuse.get() {
					return Err(());
				}
				const TWO_WEEKS: u64 = 2016 * 10 * 60;
				let since_last_misuse = at_timestamp - last_misuse.get();
				if since_last_misuse < TWO_WEEKS {
					return Ok(true);
				} else {
					last_misuse.remove();
					return Ok(false);
				}
			},
		}
	}

	fn can_add_htlc_congestion(
		&mut self, channel_id: u64, htlc_amount_msat: u64, at_timestamp: u64,
	) -> Result<bool, ()> {
		let congestion_resources_available =
			self.congestion_bucket.resources_available(htlc_amount_msat);
		let misused_congestion = self.has_misused_congestion(channel_id, at_timestamp)?;

		let below_liquidity_limit = htlc_amount_msat
			<= self.congestion_bucket.liquidity_allocated
				/ self.congestion_bucket.slots_allocated as u64;

		Ok(congestion_resources_available && !misused_congestion && below_liquidity_limit)
	}

	fn sufficient_reputation(
		&mut self, in_flight_htlc_risk: u64, outgoing_reputation: i64,
		outgoing_in_flight_risk: u64, at_timestamp: u64,
	) -> Result<bool, ()> {
		let incoming_revenue_threshold = self.incoming_revenue.value_at_timestamp(at_timestamp)?;

		Ok(outgoing_reputation
			.saturating_sub(i64::try_from(outgoing_in_flight_risk).unwrap_or(i64::MAX))
			.saturating_sub(i64::try_from(in_flight_htlc_risk).unwrap_or(i64::MAX))
			>= incoming_revenue_threshold)
	}
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
	window_duration: Duration,
	aggregated_revenue_decaying: DecayingAverage,
}

impl AggregatedWindowAverage {
	fn new(avg_weeks: u8, window_weeks: u8, start_timestamp_unix_secs: u64) -> Self {
		let window_duration = Duration::from_secs(60 * 60 * 24 * 7 * window_weeks as u64);
		AggregatedWindowAverage {
			start_timestamp_unix_secs,
			avg_weeks,
			window_weeks,
			window_duration,
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
		let warmup_factor = 1.0 - (-elapsed / self.window_duration.as_secs_f64()).exp();
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
		ln::{
			channel::TOTAL_BITCOIN_SUPPLY_SATOSHIS,
			resource_manager::{
				AggregatedWindowAverage, BucketResources, Channel, DecayingAverage, GeneralBucket,
			},
		},
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
			let mut general_bucket =
				GeneralBucket::new(0, case.general_slots, case.general_liquidity);

			assert_eq!(general_bucket.per_channel_slots, case.expected_slots);
			assert_eq!(general_bucket.per_slot_msat, case.expected_liquidity);
			assert!(general_bucket.slots_occupied.iter().all(|slot| slot.is_none()));

			general_bucket.assign_slots_for_channel(scid, None, &entropy_source).unwrap();
			let slots = general_bucket.channels_slots.get(&scid).unwrap();
			assert_eq!(slots.0.len(), case.expected_slots as usize);
		}
	}

	#[test]
	fn test_general_bucket_slots_from_salt() {
		// Test deterministic slot generation from salt
		let entropy_source = TestKeysInterface::new(&[0; 32], Network::Testnet);
		let mut general_bucket = GeneralBucket::new(0, 100, 100_000_000);

		let scid = 21;
		general_bucket.assign_slots_for_channel(scid, None, &entropy_source).unwrap();
		let (slots, salt) = general_bucket.channels_slots.get(&scid).unwrap().clone();

		general_bucket.remove_channel_slots(scid);
		assert!(general_bucket.channels_slots.get(&scid).is_none());
		general_bucket.assign_slots_for_channel(scid, Some(salt), &entropy_source).unwrap();
		let slots_from_salt: Vec<u16> = general_bucket.channels_slots.get(&scid).unwrap().0.clone();

		// Test that slots initially assigned are equal to slots assigned from salt.
		assert_eq!(slots, slots_from_salt);
	}

	#[test]
	fn test_general_bucket_add_htlc_over_max_liquidity() {
		let entropy_source = TestKeysInterface::new(&[0; 32], Network::Testnet);
		let mut general_bucket = GeneralBucket::new(0, 100, 10_000);

		let scid = 21;
		let htlc_amount_over_max = 3000;
		// General bucket will assign 5 slots of 500 per channel. Max 5 * 500 = 2500
		// Adding an HTLC over the amount should return error.
		let add_htlc_res = general_bucket.add_htlc(scid, htlc_amount_over_max, &entropy_source);
		assert!(add_htlc_res.is_err());

		// All slots for the channel should be unoccupied since adding the HTLC failed.
		let slots = &general_bucket.channels_slots.get(&scid).unwrap().0;
		assert!(slots
			.iter()
			.all(|slot_idx| general_bucket.slots_occupied[*slot_idx as usize].is_none()));
	}

	#[test]
	fn test_general_bucket_add_htlc() {
		let entropy_source = TestKeysInterface::new(&[0; 32], Network::Testnet);
		// General bucket will assign 5 slots of 500 per channel. Max 5 * 500 = 2500
		let mut general_bucket = GeneralBucket::new(0, 100, 10_000);

		let scid = 21;
		// HTLC of 500 should take one slot
		let add_htlc_res = general_bucket.add_htlc(scid, 500, &entropy_source);
		assert!(add_htlc_res.is_ok());
		let slots_occupied = add_htlc_res.unwrap();
		assert_eq!(slots_occupied.len(), 1);

		let slot_occupied = slots_occupied[0];
		assert_eq!(general_bucket.slots_occupied[slot_occupied as usize], Some(scid));

		// HTLC of 1200 should take 3 general slots
		let add_htlc_res = general_bucket.add_htlc(scid, 1200, &entropy_source);
		assert!(add_htlc_res.is_ok());
		let slots_occupied = add_htlc_res.unwrap();
		assert_eq!(slots_occupied.len(), 3);

		for slot_occupied in slots_occupied.iter() {
			assert_eq!(general_bucket.slots_occupied[*slot_occupied as usize], Some(scid));
		}

		// 4 slots have been taken. Trying to add HTLC that will take 2 or more slots should fail
		// now.
		assert!(general_bucket.add_htlc(scid, 501, &entropy_source).is_err());
		let channel_slots = &general_bucket.channels_slots.get(&scid).unwrap().0;
		let unoccupied_slots_for_channel: Vec<&u16> = channel_slots
			.iter()
			.filter(|slot_idx| general_bucket.slots_occupied[**slot_idx as usize].is_none())
			.collect();
		assert_eq!(unoccupied_slots_for_channel.len(), 1);
	}

	#[test]
	fn test_general_bucket_remove_htlc() {
		let entropy_source = TestKeysInterface::new(&[0; 32], Network::Testnet);
		let mut general_bucket = GeneralBucket::new(0, 100, 10_000);

		let scid = 21;
		let htlc_amount = 400;
		let slots_occupied = general_bucket.add_htlc(scid, htlc_amount, &entropy_source).unwrap();
		assert_eq!(slots_occupied.len(), 1);
		let slot_occupied = slots_occupied[0];
		assert_eq!(general_bucket.slots_occupied[slot_occupied as usize], Some(scid));

		// Trying to remove HTLC over number of slots previously used should result in a error
		assert!(general_bucket.remove_htlc(scid, htlc_amount + 400).is_err());
		assert!(general_bucket.remove_htlc(scid, htlc_amount).is_ok());

		assert!(general_bucket.slots_occupied[slot_occupied as usize].is_none());
	}

	fn test_bucket_resources() -> BucketResources {
		BucketResources {
			slots_allocated: 10,
			slots_used: 0,
			liquidity_allocated: 100_000,
			liquidity_used: 0,
		}
	}

	#[test]
	fn test_bucket_resources_add_htlc() {
		let mut bucket_resources = test_bucket_resources();
		let available_liquidity = bucket_resources.liquidity_allocated;
		assert!(bucket_resources.add_htlc(available_liquidity + 1000).is_err());

		assert!(bucket_resources.add_htlc(21_000).is_ok());
		assert!(bucket_resources.add_htlc(42_000).is_ok());
		assert_eq!(bucket_resources.slots_used, 2);
		assert_eq!(bucket_resources.liquidity_used, 63_000);
	}

	#[test]
	fn test_bucket_resources_add_htlc_over_resources_available() {
		// Test trying to go over slot limit
		let mut bucket_resources = test_bucket_resources();
		let slots_available = bucket_resources.slots_allocated;
		for _ in 0..slots_available {
			assert!(bucket_resources.add_htlc(10).is_ok());
		}
		assert_eq!(bucket_resources.slots_used, slots_available);
		assert!(bucket_resources.add_htlc(10).is_err());

		// Test trying to go over liquidity limit
		let mut bucket = test_bucket_resources();
		assert!(bucket.add_htlc(bucket.liquidity_allocated - 1000).is_ok());
		assert!(bucket.add_htlc(2000).is_err());
	}

	#[test]
	fn test_bucket_resources_remove_htlc() {
		let mut bucket_resources = test_bucket_resources();

		// If no resources have been used, removing HTLC should fail
		assert!(bucket_resources.remove_htlc(100).is_err());

		bucket_resources.add_htlc(1000).unwrap();
		// Test failure if it tries to remove amount over what is currently in use.
		assert!(bucket_resources.remove_htlc(1001).is_err());

		assert!(bucket_resources.remove_htlc(1000).is_ok());
		assert_eq!(bucket_resources.slots_used, 0);
		assert_eq!(bucket_resources.liquidity_used, 0);
	}

	#[test]
	fn test_invalid_channel_configs() {
		// (max_inflight, max_accepted_htlcs, general_pct, congestion_pct, protected_pct)
		let cases: Vec<(u64, u16, u8, u8)> = vec![
			// Invalid max_accepted_htlcs (> 483)
			(100_000, 500, 40, 20),
			// Invalid max_htlc_value_in_flight_msat (>= total bitcoin supply)
			(TOTAL_BITCOIN_SUPPLY_SATOSHIS * 1000 + 1, 483, 40, 20),
			// Invalid bucket percentages
			(100_000, 483, 70, 50),
		];

		for (max_inflight, max_htlcs, general_pct, congestion_pct) in cases {
			assert!(Channel::new(
				0,
				max_inflight,
				max_htlcs,
				general_pct,
				congestion_pct,
				WINDOW,
				12,
				2,
				0,
			)
			.is_err());
		}
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
