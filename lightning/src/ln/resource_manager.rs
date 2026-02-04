// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

#![allow(dead_code)]

use bitcoin::hashes::{sha256::Hash as Sha256Hash, Hash};
use core::{fmt::Display, time::Duration};
use hashbrown::hash_map::Entry;

use crate::{
	ln::channel::TOTAL_BITCOIN_SUPPLY_SATOSHIS,
	prelude::{new_hash_map, HashMap},
	sign::EntropySource,
};

/// A trait for managing channel resources and making HTLC forwarding decisions.
pub trait ResourceManager {
	/// Registers a new channel with the resource manager for tracking.
	///
	/// This should be called when a channel becomes ready for forwarding
	fn add_channel(
		&self, channel_id: u64, max_htlc_value_in_flight_msat: u64, max_accepted_htlcs: u16,
	) -> Result<(), ()>;

	/// Removes a channel from the resource manager.
	///
	/// This should be called when a channel is closing.
	fn remove_channel(&self, channel_id: u64) -> Result<(), ()>;

	/// Evaluates whether an HTLC should be forwarded and updates resource tracking.
	///
	/// This is called when deciding whether to accept and forward an incoming HTLC. The
	/// implementation determines if sufficient resources are available on the incoming
	/// channel and whether the outgoing channel is suitable for forwarding.
	///
	/// Returns a [`ForwardingOutcome`] indicating the forwarding decision:
	/// - `ForwardingOutcome::Forward(accountable)`: The HTLC should be forwarded. The boolean
	///   flag indicates the accountable signal to use for the outgoing HTLC.
	/// - `ForwardingOutcome::Fail`: The HTLC should be failed back to the sender.
	fn add_htlc<ES: EntropySource>(
		&self, incoming_channel_id: u64, incoming_amount_msat: u64, incoming_cltv_expiry: u32,
		outgoing_channel_id: u64, outgoing_amount_msat: u64, incoming_accountable: bool,
		htlc_id: u64, height_added: u32, added_at: u64, entropy_source: &ES,
	) -> Result<ForwardingOutcome, ()>;

	/// Records the resolution of a forwarded HTLC.
	///
	/// This must be called when an HTLC previously accepted via [`add_htlc`] is resolved,
	/// either successfully settled or failed. This allows the implementation to release
	/// resources and update any internal tracking state.
	///
	/// [`add_htlc`]: ResourceManager::add_htlc
	fn resolve_htlc(
		&self, incoming_channel_id: u64, htlc_id: u64, outgoing_channel_id: u64, settled: bool,
		resolved_at: u64,
	) -> Result<(), ()>;
}

/// The outcome of an HTLC forwarding decision.
#[derive(PartialEq, Eq, Debug)]
pub enum ForwardingOutcome {
	/// Forward the HTLC with the specified accountable signal.
	Forward(bool),
	/// Fail to forward the HTLC.
	Fail,
}

impl Display for ForwardingOutcome {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		match self {
			ForwardingOutcome::Forward(signal) => {
				write!(f, "Forward as {}", if *signal { "accountable " } else { "unaccountable" })
			},
			ForwardingOutcome::Fail => {
				write!(f, "Fail")
			},
		}
	}
}

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

	/// Tracks the occupancy of HTLC slots in the bucket.
	slots_occupied: Vec<bool>,

	/// SCID -> (slots assigned, salt)
	/// Maps short channel IDs to an array of tuples with the slots that the channel is allowed
	/// to use and the current usage state for each slot. It also stores the salt used to
	/// generate the slots for the channel. This is used to deterministically generate the
	/// slots for each channel on restarts.
	channels_slots: HashMap<u64, (Vec<(u16, bool)>, [u8; 32])>,
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
			slots_occupied: vec![false; slots_allocated as usize],
			channels_slots: new_hash_map(),
		}
	}

	/// Returns the available slots that could be used by the outgoing scid for the specified
	/// htlc amount.
	fn slots_for_amount(
		&mut self, outgoing_scid: u64, htlc_amount_msat: u64, salt: Option<[u8; 32]>,
	) -> Result<Option<Vec<u16>>, ()> {
		let slots_needed = u64::max(1, htlc_amount_msat.div_ceil(self.per_slot_msat));

		if self.channels_slots.get(&outgoing_scid).is_none() {
			// If slots have not been assigned yet, a salt must be provided
			let salt = salt.ok_or(())?;
			self.assign_slots_for_channel(outgoing_scid, salt)?;
		}

		// We just assigned slots if they weren't previously so unwrap here should be safe.
		let channel_slots: &[(u16, bool)] =
			self.channels_slots.get(&outgoing_scid).unwrap().0.as_ref();

		let available_slots: Vec<u16> = channel_slots
			.iter()
			.filter(|&slot| !self.slots_occupied[slot.0 as usize])
			.map(|slot| slot.0)
			.collect();

		if (available_slots.len() as u64) < slots_needed {
			Ok(None)
		} else {
			Ok(Some(available_slots.into_iter().take(slots_needed as usize).collect()))
		}
	}

	fn can_add_htlc(
		&mut self, outgoing_scid: u64, htlc_amount_msat: u64, salt: Option<[u8; 32]>,
	) -> Result<bool, ()> {
		Ok(self.slots_for_amount(outgoing_scid, htlc_amount_msat, salt)?.is_some())
	}

	fn add_htlc(
		&mut self, outgoing_scid: u64, htlc_amount_msat: u64, salt: Option<[u8; 32]>,
	) -> Result<Vec<u16>, ()> {
		match self.slots_for_amount(outgoing_scid, htlc_amount_msat, salt)? {
			Some(slots) => match self.channels_slots.entry(outgoing_scid) {
				Entry::Vacant(_) => {
					debug_assert!(false, "Channel should have already been added");
					Err(())
				},
				Entry::Occupied(mut entry) => {
					let channel_slots = entry.get_mut();
					for slot_idx in &slots {
						let slot =
							channel_slots.0.iter_mut().find(|s| s.0 == *slot_idx).ok_or(())?;
						debug_assert!(!slot.1);
						debug_assert!(!self.slots_occupied[*slot_idx as usize]);
						slot.1 = true;
						self.slots_occupied[*slot_idx as usize] = true;
					}
					Ok(slots)
				},
			},
			None => Err(()),
		}
	}

	fn remove_htlc(&mut self, outgoing_scid: u64, htlc_amount_msat: u64) -> Result<(), ()> {
		match self.channels_slots.entry(outgoing_scid) {
			Entry::Vacant(_) => Err(()),
			Entry::Occupied(mut entry) => {
				let slots_needed = u64::max(1, htlc_amount_msat.div_ceil(self.per_slot_msat));

				let channel_slots = entry.get_mut();
				let mut slots_used_by_channel: Vec<u16> = channel_slots
					.0
					.iter()
					.filter_map(|slot| if slot.1 { Some(slot.0) } else { None })
					.collect();

				if slots_needed > slots_used_by_channel.len() as u64 {
					return Err(());
				}
				let slots_released: Vec<u16> =
					slots_used_by_channel.drain(0..slots_needed as usize).collect();

				for slot_idx in slots_released {
					let slot = channel_slots.0.iter_mut().find(|s| s.0 == slot_idx).ok_or(())?;
					debug_assert!(slot.1);
					debug_assert!(self.slots_occupied[slot_idx as usize]);
					slot.1 = false;
					self.slots_occupied[slot_idx as usize] = false;
				}
				Ok(())
			},
		}
	}

	fn assign_slots_for_channel(&mut self, outgoing_scid: u64, salt: [u8; 32]) -> Result<(), ()> {
		debug_assert_ne!(self.scid, outgoing_scid);

		match self.channels_slots.entry(outgoing_scid) {
			// TODO: could return the slots already assigned instead of erroring.
			Entry::Occupied(_) => Err(()),
			Entry::Vacant(entry) => {
				let mut channel_slots = Vec::with_capacity(self.per_channel_slots.into());
				let mut slots_assigned_counter = 0;

				// To generate the slots for the channel we hash the salt and the channel
				// ids along with an index. We fill the buffer with the salt and ids here
				// since those don't change and just change the last item on each iteration
				let mut buf = [0u8; 49];
				buf[0..32].copy_from_slice(&salt);
				buf[32..40].copy_from_slice(&self.scid.to_be_bytes());
				buf[40..48].copy_from_slice(&outgoing_scid.to_be_bytes());

				let max_attempts = self.per_channel_slots * 2;
				for i in 0..max_attempts {
					if slots_assigned_counter == self.per_channel_slots {
						break;
					}

					buf[48] = i;
					let hash = &Sha256Hash::hash(&buf);
					let mut bytes: [u8; 8] = [0u8; 8];
					bytes.copy_from_slice(&hash[0..8]);

					let slot_idx: u16 =
						(u64::from_be_bytes(bytes) % self.total_slots as u64) as u16;
					let slot = (slot_idx, false);

					if !channel_slots.contains(&slot) {
						channel_slots.push(slot);
						slots_assigned_counter += 1;
					}
				}

				if slots_assigned_counter < self.per_channel_slots {
					return Err(());
				}

				entry.insert((channel_slots, salt));
				Ok(())
			},
		}
	}

	fn remove_channel_slots(&mut self, outgoing_scid: u64) {
		self.channels_slots.remove(&outgoing_scid);
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
		general_bucket_pct: u8, congestion_bucket_pct: u8, protected_bucket_pct: u8,
		window: Duration, window_count: u8, timestamp_unix_secs: u64,
	) -> Result<Self, ()> {
		if max_accepted_htlcs > 483
			|| (max_htlc_value_in_flight_msat / 1000) >= TOTAL_BITCOIN_SUPPLY_SATOSHIS
		{
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
			max_accepted_htlcs * protected_bucket_pct as u16 / 100;
		let protected_bucket_liquidity_allocated =
			max_htlc_value_in_flight_msat * protected_bucket_pct as u64 / 100;

		Ok(Channel {
			outgoing_reputation: DecayingAverage::new(
				timestamp_unix_secs,
				window * window_count.into(),
			),
			incoming_revenue: AggregatedWindowAverage::new(
				window,
				window_count,
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

	fn general_available(
		&mut self, incoming_amount_msat: u64, outgoing_channel_id: u64, salt: Option<[u8; 32]>,
	) -> Result<bool, ()> {
		Ok(self.general_bucket.can_add_htlc(outgoing_channel_id, incoming_amount_msat, salt)?)
	}

	fn congestion_eligible(
		&mut self, pending_htlcs_in_congestion: bool, incoming_amount_msat: u64,
		outgoing_channel_id: u64, revenue_window: Duration, at_timestamp: u64,
	) -> Result<bool, ()> {
		Ok(!pending_htlcs_in_congestion
			&& self.can_add_htlc_congestion(
				outgoing_channel_id,
				incoming_amount_msat,
				revenue_window,
				at_timestamp,
			)?)
	}

	fn misused_congestion(&mut self, channel_id: u64, misuse_timestamp: u64) {
		self.last_congestion_misuse.insert(channel_id, misuse_timestamp);
	}

	// Returns whether the outgoing channel has misused the congestion bucket during our last
	// revenue window.
	fn has_misused_congestion(
		&mut self, outgoing_scid: u64, at_timestamp: u64, revenue_window: Duration,
	) -> Result<bool, ()> {
		match self.last_congestion_misuse.entry(outgoing_scid) {
			Entry::Vacant(_) => Ok(false),
			Entry::Occupied(last_misuse) => {
				// If the last misuse of the congestion bucket was over more than the
				// revenue window, remote the entry.
				if at_timestamp <= *last_misuse.get() {
					return Err(());
				}
				let since_last_misuse = Duration::from_secs(at_timestamp - last_misuse.get());
				if since_last_misuse < revenue_window {
					return Ok(true);
				} else {
					last_misuse.remove();
					return Ok(false);
				}
			},
		}
	}

	fn can_add_htlc_congestion(
		&mut self, channel_id: u64, htlc_amount_msat: u64, revenue_window: Duration,
		at_timestamp: u64,
	) -> Result<bool, ()> {
		let congestion_resources_available =
			self.congestion_bucket.resources_available(htlc_amount_msat);
		let misused_congestion =
			self.has_misused_congestion(channel_id, at_timestamp, revenue_window)?;

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

/// Tracks an average value over multiple rolling windows to smooth out volatility.
///
/// It tracks the average value using a single window duration but extends observation over
/// [`Self::window_count`]s to protect against short-term shocks.
///
/// For example: if we're interested in tracking revenue over 2 weeks with a window count of 12,
/// we will track the revenue for 12 periods of 2 weeks.
///
/// During the initial period after initialization, the average is computed over the elapsed
/// time rather than the full window count, preventing artificially low values from a brief
/// history. Once sufficient time has passed, the average stabilizes across the full configured
/// number of windows.
struct AggregatedWindowAverage {
	start_timestamp_unix_secs: u64,
	window_count: u8,
	window_duration: Duration,
	aggregated_revenue_decaying: DecayingAverage,
}

impl AggregatedWindowAverage {
	fn new(window: Duration, window_count: u8, start_timestamp_unix_secs: u64) -> Self {
		AggregatedWindowAverage {
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
		// To calculate the average, we need to get the real number of windows we have been
		// tracking in the case that it is less than the window count. Meaning, if we have
		// tracked the average for only 2 windows but are averaging over 12 windows, we use 2
		// to avoid averaging for 10 windows of 0.
		let window_divisor = f64::min(
			if windows_tracked < 1.0 { 1.0 } else { windows_tracked },
			self.window_count as f64,
		);

		// We are not concerned with the rounding precision loss for this value because it is
		// negligible when dealing with a long rolling average.
		Ok((self.aggregated_revenue_decaying.value_at_timestamp(timestamp_unix_secs)? as f64
			/ window_divisor)
			.round() as i64)
	}
}

#[cfg(test)]
mod tests {
	use std::time::{Duration, SystemTime, UNIX_EPOCH};

	use bitcoin::Network;

	use crate::{
		ln::resource_manager::{
			AggregatedWindowAverage, BucketResources, DecayingAverage, GeneralBucket,
		},
		sign::EntropySource,
		util::test_utils::TestKeysInterface,
	};

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
			assert!(!general_bucket.slots_occupied.iter().any(|slot| *slot));

			general_bucket
				.assign_slots_for_channel(scid, entropy_source.get_secure_random_bytes())
				.unwrap();
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
		general_bucket
			.assign_slots_for_channel(scid, entropy_source.get_secure_random_bytes())
			.unwrap();
		let slots = general_bucket.channels_slots.get(&scid).unwrap();
		let slots_idx: Vec<u16> = slots.0.iter().map(|slot| slot.0).collect();
		let salt = general_bucket.channels_slots.get(&scid).unwrap().1;

		general_bucket.remove_channel_slots(scid);
		assert!(general_bucket.channels_slots.get(&scid).is_none());
		general_bucket.assign_slots_for_channel(scid, salt).unwrap();
		let slots_from_salt: Vec<u16> =
			general_bucket.channels_slots.get(&scid).unwrap().0.iter().map(|slot| slot.0).collect();

		// Test that slots initially assigned are equal to slots assigned from salt.
		assert_eq!(slots_idx, slots_from_salt);
	}

	#[test]
	fn test_general_bucket_add_htlc_over_max_liquidity() {
		let entropy_source = TestKeysInterface::new(&[0; 32], Network::Testnet);
		let mut general_bucket = GeneralBucket::new(0, 100, 10_000);

		let scid = 21;
		let htlc_amount_over_max = 3000;
		let salt = entropy_source.get_secure_random_bytes();
		// General bucket will assign 5 slots of 500 per channel. Max 5 * 500 = 2500
		// Adding an HTLC over the amount should return error.
		let add_htlc_res = general_bucket.add_htlc(scid, htlc_amount_over_max, Some(salt));
		assert!(add_htlc_res.is_err());

		// All slots for the channel should be unoccupied (false) since adding the HTLC failed.
		let slots = general_bucket.channels_slots.get(&scid).unwrap().0.clone();
		assert_eq!(slots.iter().any(|slot| slot.1), false);
	}

	#[test]
	fn test_general_bucket_add_htlc() {
		let entropy_source = TestKeysInterface::new(&[0; 32], Network::Testnet);
		// General bucket will assign 5 slots of 500 per channel. Max 5 * 500 = 2500
		let mut general_bucket = GeneralBucket::new(0, 100, 10_000);

		let scid = 21;
		let salt = entropy_source.get_secure_random_bytes();
		// HTLC of 500 should take one slot
		let add_htlc_res = general_bucket.add_htlc(scid, 500, Some(salt));
		assert!(add_htlc_res.is_ok());
		let slots_occupied = add_htlc_res.unwrap();
		assert_eq!(slots_occupied.len(), 1);

		let slot_occupied = slots_occupied[0];
		assert_eq!(general_bucket.slots_occupied[slot_occupied as usize], true);

		let channel_slots = general_bucket.channels_slots.get(&scid).unwrap();
		let channel_slot_state =
			channel_slots.0.iter().find(|slot| slot.0 == slot_occupied).unwrap();
		assert_eq!(channel_slot_state.1, true);

		// HTLC of 1200 should take 3 general slots
		let add_htlc_res = general_bucket.add_htlc(scid, 1200, None);
		assert!(add_htlc_res.is_ok());
		let slots_occupied = add_htlc_res.unwrap();
		assert_eq!(slots_occupied.len(), 3);

		let channel_slots = general_bucket.channels_slots.get(&scid).unwrap();
		for slot_occupied in slots_occupied.iter() {
			assert_eq!(
				channel_slots.0.iter().find(|slot| slot.0 == *slot_occupied).unwrap().1,
				true
			);
			assert_eq!(general_bucket.slots_occupied[*slot_occupied as usize], true);
		}

		// 4 slots have been taken. Trying to add HTLC that will take 2 or more slots should fail
		// now.
		assert!(general_bucket.add_htlc(scid, 501, None).is_err());
		let channel_slots = general_bucket.channels_slots.get(&scid).unwrap();
		let unoccupied_slots_for_channel: Vec<&(u16, bool)> =
			channel_slots.0.iter().filter(|slot| !slot.1).collect();
		assert_eq!(unoccupied_slots_for_channel.len(), 1);
	}

	#[test]
	fn test_general_bucket_remove_htlc() {
		let entropy_source = TestKeysInterface::new(&[0; 32], Network::Testnet);
		let mut general_bucket = GeneralBucket::new(0, 100, 10_000);

		let scid = 21;
		let htlc_amount = 400;
		let salt = entropy_source.get_secure_random_bytes();
		let slots_occupied = general_bucket.add_htlc(scid, htlc_amount, Some(salt)).unwrap();
		assert_eq!(slots_occupied.len(), 1);
		let slot_occupied = slots_occupied[0];
		assert_eq!(general_bucket.slots_occupied[slot_occupied as usize], true);

		// Trying to remove HTLC over number of slots previously used should result in a error
		assert!(general_bucket.remove_htlc(scid, htlc_amount + 400).is_err());
		assert!(general_bucket.remove_htlc(scid, htlc_amount).is_ok());

		let channel_slots = general_bucket.channels_slots.get(&scid).unwrap();
		assert_eq!(channel_slots.0.iter().find(|slot| slot.0 == slot_occupied).unwrap().1, false);
		assert_eq!(general_bucket.slots_occupied[slot_occupied as usize], false);
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
		struct TestCase {
			setup: fn(&mut BucketResources),
			htlc_amount: u64,
		}

		// Use all available slots
		let case_1 = TestCase {
			setup: |bucket: &mut BucketResources| {
				let slots_available = bucket.slots_allocated;
				for _ in 0..slots_available {
					assert!(bucket.add_htlc(10).is_ok());
				}
				assert_eq!(bucket.slots_used, slots_available);
			},
			htlc_amount: 10,
		};
		// Use liquidity and then try to go over limit
		let case_2 = TestCase {
			setup: |bucket: &mut BucketResources| {
				assert!(bucket.add_htlc(bucket.liquidity_allocated - 1000).is_ok());
			},
			htlc_amount: 2000,
		};

		let cases = vec![case_1, case_2];
		for case in cases {
			let mut bucket_resources = test_bucket_resources();
			(case.setup)(&mut bucket_resources);
			assert!(bucket_resources.add_htlc(case.htlc_amount).is_err());
		}
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

		let mut revenue_average = AggregatedWindowAverage::new(WINDOW, window_count, timestamp);
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
