// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

#![allow(dead_code)]

use core::{fmt::Display, time::Duration};

use crate::{
	crypto::chacha20::ChaCha20,
	ln::channel::TOTAL_BITCOIN_SUPPLY_SATOSHIS,
	prelude::{hash_map::Entry, new_hash_map, HashMap, Vec},
	sign::EntropySource,
	sync::Mutex,
};

/// The minimum number of slots required for the general bucket to function.
const MIN_GENERAL_BUCKET_SLOTS: u16 = 5;

/// The minimum number of accepted HTLCs required for a channel to be added to the resource
/// manager. With the default bucket allocations of 40%/20%/40% (general/congestion/protected),
/// the general bucket (40%) needs at least 5 usable HTLC slots to function effectively. To
/// ensure the general bucket gets 5 slots at its 40% share, we need at least 12 total HTLC
/// slots.
const MIN_ACCEPTED_HTLCS: u16 = 12;

/// The minimum `max_htlc_value_in_flight_msat` required for a channel to be added to the resource
/// manager. This corresponds to the default `min_funding_satoshis` of 1000 in
/// [`crate::util::config::ChannelHandshakeLimits`], which is the smallest channel size LDK will
/// accept.
const MIN_MAX_IN_FLIGHT_MSAT: u64 = 1_000_000;

/// Resolution time in seconds that is considered "good". HTLCs resolved within this period are
/// considered normal and are rewarded in the reputation score.
const ACCEPTABLE_RESOLUTION_PERIOD_SECS: u8 = 90;

/// The maximum time (in seconds) that a HTLC can be held. Corresponds to the largest cltv delta
/// allowed in the protocol which is 2016 blocks. Assuming 10 minute blocks, this is roughly 2
/// weeks.
const REVENUE_WINDOW: u64 = 2016 * 10 * 60;

/// Configuration parameters for the resource manager.
///
/// This configuration controls how the resource manager allocates channel resources (HTLC slots
/// and liquidity) across three buckets (general, congestion, and protected).
pub struct ResourceManagerConfig {
	/// The percentage of channel resources allocated to the general bucket.
	/// The general bucket is available to all traffic with basic denial-of-service protections.
	///
	/// Default: 40%
	pub general_allocation_pct: u8,

	/// The percentage of channel resources allocated to the congestion bucket.
	/// The congestion bucket is used when the general bucket is saturated. It allows an outgoing
	/// channel that does not have reputation to have a chance of getting the HTLC forwarded.
	///
	/// Default: 20%
	pub congestion_allocation_pct: u8,

	/// The amount of time a HTLC is allowed to resolve in that classifies as "good" behavior.
	/// HTLCs resolved within this period are rewarded in the reputation score. HTLCs resolved
	/// slower than this will incur an opportunity cost penalty.
	///
	/// Default: 90 seconds
	pub resolution_period: Duration,

	/// The rolling window over which we track the revenue on the incoming channel.
	///
	/// This corresponds to the largest cltv delta from the current block height that a node will
	/// allow a HTLC to set before failing it with `expiry_too_far`. Assuming 10 minute blocks,
	/// the default 2016 blocks is roughly 2 weeks.
	///
	/// Default: 2016 blocks * 10 minutes = ~2 weeks
	pub revenue_window: Duration,

	/// A multiplier applied to [`revenue_window`] to determine the rolling window over which an
	/// outgoing channel's forwarding history is considered when calculating reputation. The
	/// outgoing channel reputation is tracked over a period of `revenue_window * reputation_multiplier`.
	///
	/// Default: 12 (meaning reputation is tracked over 12 * 2 weeks = 24 weeks)
	///
	/// [`revenue_window`]: Self::revenue_window
	pub reputation_multiplier: u8,
}

impl Default for ResourceManagerConfig {
	fn default() -> ResourceManagerConfig {
		Self {
			general_allocation_pct: 40,
			congestion_allocation_pct: 20,
			resolution_period: Duration::from_secs(ACCEPTABLE_RESOLUTION_PERIOD_SECS.into()),
			revenue_window: Duration::from_secs(REVENUE_WINDOW),
			reputation_multiplier: 12,
		}
	}
}

impl ResourceManagerConfig {
	fn validate(&self) -> Result<(), ()> {
		if self.general_allocation_pct as u16 + self.congestion_allocation_pct as u16 >= 100 {
			return Err(());
		}
		if self.resolution_period == Duration::ZERO {
			return Err(());
		}
		if self.revenue_window == Duration::ZERO {
			return Err(());
		}
		if self.reputation_multiplier == 0 {
			return Err(());
		}
		Ok(())
	}
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
				write!(f, "Forward as {}", if *signal { "accountable" } else { "unaccountable" })
			},
			ForwardingOutcome::Fail => {
				write!(f, "Fail")
			},
		}
	}
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
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
			slots_occupied: vec![None; slots_allocated as usize],
			channels_slots: new_hash_map(),
		})
	}

	/// Returns the available slots that could be used by the outgoing scid for the specified
	/// htlc amount.
	fn slots_for_amount<ES: EntropySource>(
		&mut self, outgoing_scid: u64, htlc_amount_msat: u64, entropy_source: &ES,
	) -> Result<Option<Vec<u16>>, ()> {
		let slots_needed = u64::max(1, htlc_amount_msat.div_ceil(self.per_slot_msat));

		let channel_entry = match self.channels_slots.entry(outgoing_scid) {
			Entry::Occupied(e) => e.into_mut(),
			Entry::Vacant(entry) => {
				let salt = entropy_source.get_secure_random_bytes();
				let slots = assign_slots_for_channel(
					self.scid,
					outgoing_scid,
					salt,
					self.per_channel_slots,
					self.total_slots,
				)?;
				entry.insert((slots, salt))
			},
		};

		let slots_to_use: Vec<u16> = channel_entry
			.0
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
		let channel_slots = &self.channels_slots.get(&outgoing_scid).ok_or(())?.0;
		let slots_needed = u64::max(1, htlc_amount_msat.div_ceil(self.per_slot_msat));
		let slots_used_by_channel = channel_slots
			.iter()
			.filter(|slot_idx| self.slots_occupied[**slot_idx as usize] == Some(outgoing_scid))
			.count();

		if slots_needed > slots_used_by_channel as u64 {
			return Err(());
		}

		let mut released = 0;
		for slot_idx in channel_slots {
			if released == slots_needed {
				break;
			}
			if self.slots_occupied[*slot_idx as usize] == Some(outgoing_scid) {
				self.slots_occupied[*slot_idx as usize] = None;
				released += 1;
			}
		}

		Ok(())
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
		debug_assert!(
			self.slots_used <= self.slots_allocated,
			"slots_used {} exceeded slots_allocated {}",
			self.slots_used,
			self.slots_allocated
		);
		debug_assert!(
			self.liquidity_used <= self.liquidity_allocated,
			"liquidity_used {} exceeded liquidity_allocated {}",
			self.liquidity_used,
			self.liquidity_allocated
		);
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

struct BucketAllocations {
	general_slots: u16,
	general_liquidity: u64,
	congestion_slots: u16,
	congestion_liquidity: u64,
	protected_slots: u16,
	protected_liquidity: u64,
}

fn bucket_allocations(
	max_accepted_htlcs: u16, max_htlc_value_in_flight_msat: u64, general_pct: u8,
	congestion_pct: u8,
) -> BucketAllocations {
	let general_slots = (max_accepted_htlcs as f64 * general_pct as f64 / 100.0).round() as u16;
	let general_liquidity =
		(max_htlc_value_in_flight_msat as f64 * general_pct as f64 / 100.0).round() as u64;

	let congestion_slots =
		(max_accepted_htlcs as f64 * congestion_pct as f64 / 100.0).round() as u16;
	let congestion_liquidity =
		(max_htlc_value_in_flight_msat as f64 * congestion_pct as f64 / 100.0).round() as u64;

	let protected_slots = max_accepted_htlcs - general_slots - congestion_slots;
	let protected_liquidity =
		max_htlc_value_in_flight_msat - general_liquidity - congestion_liquidity;

	BucketAllocations {
		general_slots,
		general_liquidity,
		congestion_slots,
		congestion_liquidity,
		protected_slots,
		protected_liquidity,
	}
}

#[derive(Debug, Clone)]
struct PendingHTLC {
	incoming_amount_msat: u64,
	fee: u64,
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

	/// Whether this channel has been closed. We keep channels around until all its
	/// [`Self::pending_htlcs`] have been resolved. This ensures that HTLC resolutions that
	/// arrive after a force-close can still update reputation and revenue correctly.
	closed: bool,
}

impl Channel {
	fn new(
		scid: u64, bucket_allocations: BucketAllocations, reputation_window: Duration,
		revenue_week_avg_duration: Duration, timestamp_unix_secs: u64,
	) -> Result<Self, ()> {
		const REVENUE_WEEK_MULTIPLIER: u8 = 6;

		Ok(Channel {
			outgoing_reputation: DecayingAverage::new(timestamp_unix_secs, reputation_window),
			incoming_revenue: AggregatedWindowAverage::new(
				revenue_week_avg_duration,
				REVENUE_WEEK_MULTIPLIER,
				timestamp_unix_secs,
			),
			pending_htlcs: new_hash_map(),
			general_bucket: GeneralBucket::new(
				scid,
				bucket_allocations.general_slots,
				bucket_allocations.general_liquidity,
			)?,
			congestion_bucket: BucketResources::new(
				bucket_allocations.congestion_slots,
				bucket_allocations.congestion_liquidity,
			),
			last_congestion_misuse: new_hash_map(),
			protected_bucket: BucketResources::new(
				bucket_allocations.protected_slots,
				bucket_allocations.protected_liquidity,
			),
			closed: false,
		})
	}

	fn general_available<ES: EntropySource>(
		&mut self, incoming_amount_msat: u64, outgoing_channel_id: u64, entropy_source: &ES,
	) -> Result<bool, ()> {
		self.general_bucket.can_add_htlc(outgoing_channel_id, incoming_amount_msat, entropy_source)
	}

	fn congestion_eligible(
		&mut self, pending_htlcs_in_congestion: bool, incoming_amount_msat: u64,
		outgoing_channel_id: u64, at_timestamp: u64,
	) -> bool {
		!pending_htlcs_in_congestion
			&& self.can_add_htlc_congestion(outgoing_channel_id, incoming_amount_msat, at_timestamp)
	}

	fn misused_congestion(&mut self, channel_id: u64, misuse_timestamp: u64) {
		self.last_congestion_misuse.insert(channel_id, misuse_timestamp);
	}

	// Returns whether the outgoing channel has misused the congestion bucket in the last two
	// weeks.
	fn has_misused_congestion(&mut self, outgoing_scid: u64, at_timestamp: u64) -> bool {
		match self.last_congestion_misuse.entry(outgoing_scid) {
			Entry::Vacant(_) => false,
			Entry::Occupied(last_misuse) => {
				let timestamp = u64::max(at_timestamp, *last_misuse.get());
				// If the last misuse of the congestion bucket was over more than two
				// weeks ago, remove the entry.
				const TWO_WEEKS: u64 = 2016 * 10 * 60;
				let since_last_misuse = timestamp - last_misuse.get();
				if since_last_misuse < TWO_WEEKS {
					true
				} else {
					last_misuse.remove();
					false
				}
			},
		}
	}

	fn can_add_htlc_congestion(
		&mut self, channel_id: u64, htlc_amount_msat: u64, at_timestamp: u64,
	) -> bool {
		let congestion_resources_available =
			self.congestion_bucket.resources_available(htlc_amount_msat);
		let misused_congestion = self.has_misused_congestion(channel_id, at_timestamp);

		let below_liquidity_limit = htlc_amount_msat
			<= self.congestion_bucket.liquidity_allocated
				/ self.congestion_bucket.slots_allocated as u64;

		congestion_resources_available && !misused_congestion && below_liquidity_limit
	}

	fn pending_htlcs_in_congestion(&self) -> bool {
		self.pending_htlcs
			.values()
			.any(|pending_htlc| pending_htlc.bucket == BucketAssigned::Congestion)
	}

	fn sufficient_reputation(
		&mut self, in_flight_htlc_risk: u64, outgoing_reputation: i64,
		outgoing_in_flight_risk: u64, at_timestamp: u64,
	) -> bool {
		let incoming_revenue_threshold = self.incoming_revenue.value_at_timestamp(at_timestamp);

		outgoing_reputation
			.saturating_sub(i64::try_from(outgoing_in_flight_risk).unwrap_or(i64::MAX))
			.saturating_sub(i64::try_from(in_flight_htlc_risk).unwrap_or(i64::MAX))
			>= incoming_revenue_threshold
	}

	fn outgoing_in_flight_risk(&self) -> u64 {
		// We only account the in-flight risk for HTLCs that are accountable
		self.pending_htlcs
			.iter()
			.map(|htlc| if htlc.1.outgoing_accountable { htlc.1.in_flight_risk } else { 0 })
			.sum()
	}
}

fn has_incoming_htlc_references(channels: &HashMap<u64, Channel>, channel_id: u64) -> bool {
	channels.iter().any(|channel| {
		channel
			.1
			.pending_htlcs
			.iter()
			.any(|pending_htlc| pending_htlc.0.incoming_channel_id == channel_id)
	})
}

/// An implementation for managing channel resources and informing HTLC forwarding decisions. It
/// implements the core of the mitigation as proposed in <https://github.com/lightning/bolts/pull/1280>.
pub struct DefaultResourceManager {
	config: ResourceManagerConfig,
	channels: Mutex<HashMap<u64, Channel>>,
}

impl DefaultResourceManager {
	pub fn new(config: ResourceManagerConfig) -> Result<Self, ()> {
		config.validate()?;
		Ok(DefaultResourceManager { config, channels: Mutex::new(new_hash_map()) })
	}

	// To calculate the risk of pending HTLCs, we assume they will resolve in the worst
	// possible case. Here we assume block times of 10 minutes.
	fn htlc_in_flight_risk(&self, fee: u64, incoming_cltv_expiry: u32, height_added: u32) -> u64 {
		let maximum_hold_time = (incoming_cltv_expiry.saturating_sub(height_added)) * 10 * 60;
		self.opportunity_cost(Duration::from_secs(maximum_hold_time as u64), fee)
	}

	fn opportunity_cost(&self, resolution_time: Duration, fee_msat: u64) -> u64 {
		// Computed using f64 as a linear function of how far resolution_time exceeds the
		// acceptable resolution_period, scaled by the fee. This is done instead of stepwise at
		// each resolution_period multiple because a stepwise function could possibly allow an
		// attacker to hold HTLCs just under the acceptable resolution_period without incurring
		// any cost but causing the next hop slower's resolution to get fully penalized by the
		// fee.
		let resolution_period = self.config.resolution_period.as_secs_f64();
		let opportunity_cost = 0_f64
			.max((resolution_time.as_secs_f64() - resolution_period) / resolution_period)
			* fee_msat as f64;

		opportunity_cost.round() as u64
	}

	fn effective_fees(
		&self, fee_msat: u64, resolution_time: Duration, accountable: bool, settled: bool,
	) -> i64 {
		let fee = i64::try_from(fee_msat).unwrap_or(i64::MAX);
		if accountable {
			let opportunity_cost =
				i64::try_from(self.opportunity_cost(resolution_time, fee_msat)).unwrap_or(i64::MAX);
			if settled {
				fee - opportunity_cost
			} else {
				-opportunity_cost
			}
		} else {
			if settled && resolution_time <= self.config.resolution_period {
				fee
			} else {
				0
			}
		}
	}

	/// Registers a new channel with the resource manager for tracking.
	///
	/// This should be called when a channel becomes ready for forwarding
	pub fn add_channel(
		&self, channel_id: u64, max_htlc_value_in_flight_msat: u64, max_accepted_htlcs: u16,
		timestamp_unix_secs: u64,
	) -> Result<(), ()> {
		if max_accepted_htlcs > 483
			|| max_htlc_value_in_flight_msat >= TOTAL_BITCOIN_SUPPLY_SATOSHIS * 1000
		{
			return Err(());
		}

		if max_accepted_htlcs < MIN_ACCEPTED_HTLCS
			|| max_htlc_value_in_flight_msat < MIN_MAX_IN_FLIGHT_MSAT
		{
			return Err(());
		}

		let allocations = bucket_allocations(
			max_accepted_htlcs,
			max_htlc_value_in_flight_msat,
			self.config.general_allocation_pct,
			self.config.congestion_allocation_pct,
		);

		let reputation_window =
			self.config.revenue_window * self.config.reputation_multiplier as u32;

		let mut channels_lock = self.channels.lock().unwrap();
		match channels_lock.entry(channel_id) {
			Entry::Vacant(entry) => {
				let channel = Channel::new(
					channel_id,
					allocations,
					reputation_window,
					self.config.revenue_window,
					timestamp_unix_secs,
				)?;
				entry.insert(channel);
				Ok(())
			},
			Entry::Occupied(_) => Err(()),
		}
	}

	/// Removes a channel from the resource manager.
	///
	/// This must be called when a channel is closing.
	pub fn remove_channel(&self, channel_id: u64) -> Result<(), ()> {
		let mut channels_lock = self.channels.lock().unwrap();

		let incoming_htlcs_pending = has_incoming_htlc_references(&channels_lock, channel_id);

		// If the channel has pending HTLCs, it is soft-deleted and will be fully removed once
		// all its pending HTLCs have been resolved.
		let channel = channels_lock.get_mut(&channel_id).ok_or(())?;
		if channel.pending_htlcs.is_empty() && !incoming_htlcs_pending {
			// If the channel had no pending HTLCs, we can remove it.
			channels_lock.remove(&channel_id);
			for (_, channel) in channels_lock.iter_mut() {
				channel.general_bucket.remove_channel_slots(channel_id);
			}
		} else {
			channel.closed = true;
		}
		Ok(())
	}

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
	pub fn add_htlc<ES: EntropySource>(
		&self, incoming_channel_id: u64, incoming_amount_msat: u64, incoming_cltv_expiry: u32,
		outgoing_channel_id: u64, outgoing_amount_msat: u64, incoming_accountable: bool,
		htlc_id: u64, height_added: u32, added_at: u64, entropy_source: &ES,
	) -> Result<ForwardingOutcome, ()> {
		if (outgoing_amount_msat > incoming_amount_msat) || (height_added >= incoming_cltv_expiry) {
			return Err(());
		}

		let mut channels_lock = self.channels.lock().unwrap();

		let htlc_ref = HtlcRef { incoming_channel_id, htlc_id };
		let outgoing_channel =
			channels_lock.get_mut(&outgoing_channel_id).filter(|c| !c.closed).ok_or(())?;

		if outgoing_channel.pending_htlcs.get(&htlc_ref).is_some() {
			return Err(());
		}

		let outgoing_reputation = outgoing_channel.outgoing_reputation.value_at_timestamp(added_at);

		let outgoing_in_flight_risk: u64 = outgoing_channel.outgoing_in_flight_risk();
		let fee = incoming_amount_msat - outgoing_amount_msat;
		let in_flight_htlc_risk = self.htlc_in_flight_risk(fee, incoming_cltv_expiry, height_added);
		let pending_htlcs_in_congestion = outgoing_channel.pending_htlcs_in_congestion();

		let incoming_channel =
			channels_lock.get_mut(&incoming_channel_id).filter(|c| !c.closed).ok_or(())?;

		let (accountable, bucket_assigned) = if !incoming_accountable {
			if incoming_channel.general_available(
				incoming_amount_msat,
				outgoing_channel_id,
				entropy_source,
			)? {
				(false, BucketAssigned::General)
			} else if incoming_channel.sufficient_reputation(
				in_flight_htlc_risk,
				outgoing_reputation,
				outgoing_in_flight_risk,
				added_at,
			) && incoming_channel
				.protected_bucket
				.resources_available(incoming_amount_msat)
			{
				(true, BucketAssigned::Protected)
			} else if incoming_channel.congestion_eligible(
				pending_htlcs_in_congestion,
				incoming_amount_msat,
				outgoing_channel_id,
				added_at,
			) {
				(true, BucketAssigned::Congestion)
			} else {
				return Ok(ForwardingOutcome::Fail);
			}
		} else {
			// If the incoming HTLC is accountable, we only forward it if the outgoing
			// channel has sufficient reputation, otherwise we fail it.
			if incoming_channel.sufficient_reputation(
				in_flight_htlc_risk,
				outgoing_reputation,
				outgoing_in_flight_risk,
				added_at,
			) {
				if incoming_channel.protected_bucket.resources_available(incoming_amount_msat) {
					(true, BucketAssigned::Protected)
				} else if incoming_channel.general_available(
					incoming_amount_msat,
					outgoing_channel_id,
					entropy_source,
				)? {
					(true, BucketAssigned::General)
				} else {
					return Ok(ForwardingOutcome::Fail);
				}
			} else {
				return Ok(ForwardingOutcome::Fail);
			}
		};

		match bucket_assigned {
			BucketAssigned::General => {
				incoming_channel.general_bucket.add_htlc(
					outgoing_channel_id,
					incoming_amount_msat,
					entropy_source,
				)?;
			},
			BucketAssigned::Congestion => {
				incoming_channel.congestion_bucket.add_htlc(incoming_amount_msat)?;
			},
			BucketAssigned::Protected => {
				incoming_channel.protected_bucket.add_htlc(incoming_amount_msat)?;
			},
		}

		let outgoing_channel = channels_lock.get_mut(&outgoing_channel_id).ok_or(())?;
		let pending_htlc = PendingHTLC {
			incoming_amount_msat,
			fee,
			outgoing_accountable: accountable,
			added_at_unix_seconds: added_at,
			in_flight_risk: in_flight_htlc_risk,
			bucket: bucket_assigned,
		};
		outgoing_channel.pending_htlcs.insert(htlc_ref, pending_htlc);

		Ok(ForwardingOutcome::Forward(accountable))
	}

	/// Records the resolution of a forwarded HTLC.
	///
	/// This must be called for HTLCs where [`add_htlc`] returned [`ForwardingOutcome::Forward`].
	/// It reports if the HTLC was successfully settled or failed. This allows the implementation
	/// to release resources and update any internal tracking state.
	///
	/// [`add_htlc`]: DefaultResourceManager::add_htlc
	pub fn resolve_htlc(
		&self, incoming_channel_id: u64, htlc_id: u64, outgoing_channel_id: u64, settled: bool,
		resolved_at: u64,
	) -> Result<(), ()> {
		let mut channels_lock = self.channels.lock().unwrap();
		let outgoing_channel = channels_lock.get_mut(&outgoing_channel_id).ok_or(())?;

		let htlc_ref = HtlcRef { incoming_channel_id, htlc_id };
		let pending_htlc = outgoing_channel.pending_htlcs.remove(&htlc_ref).ok_or(())?;

		let outgoing_closed = outgoing_channel.closed && outgoing_channel.pending_htlcs.is_empty();
		if resolved_at >= pending_htlc.added_at_unix_seconds {
			let resolution_time =
				Duration::from_secs(resolved_at - pending_htlc.added_at_unix_seconds);
			let effective_fee = self.effective_fees(
				pending_htlc.fee,
				resolution_time,
				pending_htlc.outgoing_accountable,
				settled,
			);
			// Note that the decaying averages for reputation and revenue clamp `resolved_at` to
			// `last_updated_unix_secs` if it falls behind. This could happen because
			// `last_updated_unix_secs` is frequently mutated. We accept the clamping rather
			// than erroring, as rejecting out-of-order timestamps would leave resources stuck.
			outgoing_channel.outgoing_reputation.add_value(effective_fee, resolved_at);
		}

		let incoming_channel = channels_lock.get_mut(&incoming_channel_id).ok_or(())?;
		let incoming_closed = incoming_channel.closed && incoming_channel.pending_htlcs.is_empty();
		match pending_htlc.bucket {
			BucketAssigned::General => incoming_channel
				.general_bucket
				.remove_htlc(outgoing_channel_id, pending_htlc.incoming_amount_msat)?,
			BucketAssigned::Congestion => {
				// Mark that congestion bucket was misused if it took more than the valid
				// resolution period. Here we are bit lenient if resolve_at < added_at.
				// This means there is a bug as resolution can't be before added time but
				// no reason to mark congestion as misused in this case.
				let resolution_time = Duration::from_secs(
					resolved_at.saturating_sub(pending_htlc.added_at_unix_seconds),
				);
				if resolution_time > self.config.resolution_period {
					incoming_channel.misused_congestion(outgoing_channel_id, resolved_at);
				}

				incoming_channel.congestion_bucket.remove_htlc(pending_htlc.incoming_amount_msat)?
			},
			BucketAssigned::Protected => {
				incoming_channel.protected_bucket.remove_htlc(pending_htlc.incoming_amount_msat)?
			},
		}

		if settled && resolved_at >= pending_htlc.added_at_unix_seconds {
			let fee: i64 = i64::try_from(pending_htlc.fee).unwrap_or(i64::MAX);
			incoming_channel.incoming_revenue.add_value(fee, resolved_at);
		}

		let mut remove_channel = |closed: bool, channel_id: u64| {
			// If the channel had been marked as closed and it does not have any other pending
			// HTLCs, it can be fully removed now.
			if closed {
				if !has_incoming_htlc_references(&channels_lock, channel_id) {
					channels_lock.remove(&channel_id);
					for (_, channel) in channels_lock.iter_mut() {
						channel.general_bucket.remove_channel_slots(channel_id);
					}
				}
			}
		};
		remove_channel(incoming_closed, incoming_channel_id);
		remove_channel(outgoing_closed, outgoing_channel_id);

		// This is a bug as resolution time can't be before added time. This prevents us from
		// properly updating the reputation and revenue as those need accurate timestamps but
		// we error here rather than earlier to optimistically release bucket resources.
		if resolved_at < pending_htlc.added_at_unix_seconds {
			return Err(());
		}

		Ok(())
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
	use std::time::{Duration, SystemTime, UNIX_EPOCH};

	use crate::{
		crypto::chacha20::ChaCha20,
		ln::{
			channel::TOTAL_BITCOIN_SUPPLY_SATOSHIS,
			resource_manager::{
				assign_slots_for_channel, bucket_allocations, AggregatedWindowAverage,
				BucketAssigned, BucketResources, Channel, DecayingAverage, DefaultResourceManager,
				ForwardingOutcome, GeneralBucket, HtlcRef, ResourceManagerConfig,
			},
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
			assert!(general_bucket.slots_occupied.iter().all(|slot| slot.is_none()));

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
		let mut general_bucket = GeneralBucket::new(0, 100, 10_000).unwrap();
		debug_assert_eq!(general_bucket.per_channel_slots, 5);
		debug_assert_eq!(general_bucket.per_slot_msat, 500);

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
		let mut general_bucket = GeneralBucket::new(0, 100, 10_000).unwrap();
		debug_assert_eq!(general_bucket.per_channel_slots, 5);
		debug_assert_eq!(general_bucket.per_slot_msat, 500);

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
		let mut general_bucket = GeneralBucket::new(0, 100, 10_000).unwrap();

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

	fn test_channel(config: &ResourceManagerConfig) -> Channel {
		let allocations = bucket_allocations(
			100,
			100_000_000,
			config.general_allocation_pct,
			config.congestion_allocation_pct,
		);
		Channel::new(
			0,
			allocations,
			config.revenue_window * config.reputation_multiplier as u32,
			WINDOW,
			SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
		)
		.unwrap()
	}

	#[test]
	fn test_invalid_resource_manager_config() {
		let configs = vec![
			// Invalid bucket percentages (sum >= 100)
			ResourceManagerConfig {
				general_allocation_pct: 70,
				congestion_allocation_pct: 50,
				..Default::default()
			},
			// Zero resolution_period
			ResourceManagerConfig { resolution_period: Duration::ZERO, ..Default::default() },
			// Zero revenue_window
			ResourceManagerConfig { revenue_window: Duration::ZERO, ..Default::default() },
			// Zero reputation_multiplier
			ResourceManagerConfig { reputation_multiplier: 0, ..Default::default() },
		];

		for config in configs {
			assert!(DefaultResourceManager::new(config).is_err());
		}
	}

	#[test]
	fn test_invalid_add_channel() {
		let rm = DefaultResourceManager::new(ResourceManagerConfig::default()).unwrap();

		// (max_inflight, max_accepted_htlcs)
		let cases: Vec<(u64, u16)> = vec![
			// Invalid max_accepted_htlcs (> 483)
			(100_000, 500),
			// Invalid max_htlc_value_in_flight_msat (>= total bitcoin supply)
			(TOTAL_BITCOIN_SUPPLY_SATOSHIS * 1000, 483),
			// Invalid max_accepted_htlcs (< 12)
			(100_000_000, 11),
			// Invalid max_htlc_value_in_flight_msat (< 1000 sats)
			(999_999, 100),
		];

		for (max_inflight, max_htlcs) in cases {
			assert!(rm.add_channel(0, max_inflight, max_htlcs, 0).is_err());
		}
	}

	#[test]
	fn test_misuse_congestion_bucket() {
		let config = ResourceManagerConfig::default();
		let mut channel = test_channel(&config);
		let misusing_channel = 1;

		let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
		assert_eq!(channel.has_misused_congestion(misusing_channel, now), false);

		channel.misused_congestion(misusing_channel, now);
		assert_eq!(channel.has_misused_congestion(misusing_channel, now + 5), true);

		// Congestion misuse is taken into account if the bucket has been misused in the last 2
		// weeks. Test that after 2 weeks since last misuse, it returns that the bucket has not
		// been misused.
		let two_weeks = config.revenue_window.as_secs();
		assert_eq!(channel.has_misused_congestion(misusing_channel, now + two_weeks), false);
	}

	#[test]
	fn test_opportunity_cost() {
		let config = ResourceManagerConfig::default();
		let resource_manager = DefaultResourceManager::new(config).unwrap();

		// Less than resolution_period has zero cost.
		assert_eq!(resource_manager.opportunity_cost(Duration::from_secs(10), 100), 0);

		// Above resolution period it is gradually incremented.
		assert_eq!(resource_manager.opportunity_cost(Duration::from_secs(91), 100), 1);
		assert_eq!(resource_manager.opportunity_cost(Duration::from_secs(135), 100), 50);
		assert_eq!(resource_manager.opportunity_cost(Duration::from_secs(180), 100), 100);

		// Multiple periods above resolution_period charges multiples of fee.
		assert_eq!(resource_manager.opportunity_cost(Duration::from_secs(900), 100), 900);
	}

	#[test]
	fn test_effective_fees() {
		let config = ResourceManagerConfig::default();
		let fast_resolve = config.resolution_period / 2;
		let slow_resolve = config.resolution_period * 3;

		let resource_manager = DefaultResourceManager::new(config).unwrap();

		let accountable = true;
		let settled = true;
		let cases = vec![
			(1000, fast_resolve, accountable, settled, 1000),
			(1000, slow_resolve, accountable, settled, -1000),
			(1000, fast_resolve, accountable, !settled, 0),
			(1000, slow_resolve, accountable, !settled, -2000),
			// Unaccountable HTLCs do not affect negatively
			(1000, fast_resolve, !accountable, settled, 1000),
			(1000, slow_resolve, !accountable, settled, 0),
			(1000, fast_resolve, !accountable, !settled, 0),
			(1000, slow_resolve, !accountable, !settled, 0),
		];

		for (fee_msat, hold_time, accountable, settled, expected) in cases {
			let result = resource_manager.effective_fees(fee_msat, hold_time, accountable, settled);
			assert_eq!(result, expected, "Case failed: fee_msat={fee_msat:?}, hold_time={hold_time:?}, accountable={accountable:?}, settled={settled:?}");
		}
	}

	const INCOMING_SCID: u64 = 100;
	const OUTGOING_SCID: u64 = 200;
	const INCOMING_SCID_2: u64 = 101;
	const OUTGOING_SCID_2: u64 = 201;
	const HTLC_AMOUNT: u64 = 10_000_000;
	const FEE_AMOUNT: u64 = 1_000;
	const CURRENT_HEIGHT: u32 = 1000;
	const CLTV_EXPIRY: u32 = 1144;

	fn create_test_resource_manager_with_channel_pairs(n_pairs: u8) -> DefaultResourceManager {
		let config = ResourceManagerConfig::default();
		let rm = DefaultResourceManager::new(config).unwrap();
		let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
		for i in 0..n_pairs {
			rm.add_channel(INCOMING_SCID + i as u64, 5_000_000_000, 114, now).unwrap();
			rm.add_channel(OUTGOING_SCID + i as u64, 5_000_000_000, 114, now).unwrap();
		}
		rm
	}

	fn create_test_resource_manager_with_channels() -> DefaultResourceManager {
		create_test_resource_manager_with_channel_pairs(1)
	}

	fn add_test_htlc<ES: EntropySource>(
		rm: &DefaultResourceManager, accountable: bool, htlc_id: u64, added_at: Option<u64>,
		entropy_source: &ES,
	) -> Result<ForwardingOutcome, ()> {
		rm.add_htlc(
			INCOMING_SCID,
			HTLC_AMOUNT + FEE_AMOUNT,
			CLTV_EXPIRY,
			OUTGOING_SCID,
			HTLC_AMOUNT,
			accountable,
			htlc_id,
			CURRENT_HEIGHT,
			added_at.unwrap_or(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()),
			entropy_source,
		)
	}

	fn add_reputation(rm: &DefaultResourceManager, outgoing_scid: u64, target_reputation: i64) {
		let mut channels = rm.channels.lock().unwrap();
		let outgoing_channel = channels.get_mut(&outgoing_scid).unwrap();
		let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
		outgoing_channel.outgoing_reputation.add_value(target_reputation, now);
	}

	fn fill_general_bucket(rm: &DefaultResourceManager, incoming_scid: u64) {
		let mut channels = rm.channels.lock().unwrap();
		let incoming_channel = channels.get_mut(&incoming_scid).unwrap();
		for slot in incoming_channel.general_bucket.slots_occupied.iter_mut() {
			*slot = Some(0);
		}
	}

	fn fill_congestion_bucket(rm: &DefaultResourceManager, incoming_scid: u64) {
		let mut channels = rm.channels.lock().unwrap();
		let incoming_channel = channels.get_mut(&incoming_scid).unwrap();
		let slots_allocated = incoming_channel.congestion_bucket.slots_allocated;
		let liquidity_allocated = incoming_channel.congestion_bucket.liquidity_allocated;
		incoming_channel.congestion_bucket.slots_used = slots_allocated;
		incoming_channel.congestion_bucket.liquidity_used = liquidity_allocated;
	}

	fn fill_protected_bucket(rm: &DefaultResourceManager, incoming_scid: u64) {
		let mut channels = rm.channels.lock().unwrap();
		let incoming_channel = channels.get_mut(&incoming_scid).unwrap();
		let slots_allocated = incoming_channel.protected_bucket.slots_allocated;
		let liquidity_allocated = incoming_channel.protected_bucket.liquidity_allocated;
		incoming_channel.protected_bucket.slots_used = slots_allocated;
		incoming_channel.protected_bucket.liquidity_used = liquidity_allocated;
	}

	fn mark_congestion_misused(
		rm: &DefaultResourceManager, incoming_scid: u64, outgoing_scid: u64,
	) {
		let mut channels = rm.channels.lock().unwrap();
		let incoming_channel = channels.get_mut(&incoming_scid).unwrap();
		let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
		incoming_channel.misused_congestion(outgoing_scid, now);
	}

	fn get_htlc_bucket(
		rm: &DefaultResourceManager, incoming_channel_id: u64, htlc_id: u64,
		outgoing_channel_id: u64,
	) -> Option<BucketAssigned> {
		let channels = rm.channels.lock().unwrap();
		let htlc_ref = HtlcRef { incoming_channel_id, htlc_id };
		let htlc = channels.get(&outgoing_channel_id).unwrap().pending_htlcs.get(&htlc_ref);
		htlc.map(|htlc| htlc.bucket)
	}

	fn count_pending_htlcs(rm: &DefaultResourceManager, outgoing_scid: u64) -> usize {
		let channels = rm.channels.lock().unwrap();
		channels.get(&outgoing_scid).unwrap().pending_htlcs.len()
	}

	fn assert_general_bucket_slots_used(
		rm: &DefaultResourceManager, incoming_scid: u64, outgoing_scid: u64, expected_count: usize,
	) {
		let channels = rm.channels.lock().unwrap();
		let channel = channels.get(&incoming_scid).unwrap();
		let slots = &channel.general_bucket.channels_slots.get(&outgoing_scid).unwrap().0;
		let used_count = slots
			.iter()
			.filter(|slot_idx| {
				channel.general_bucket.slots_occupied[**slot_idx as usize] == Some(outgoing_scid)
			})
			.count();
		assert_eq!(used_count, expected_count);
	}

	fn test_congestion_eligible(rm: &DefaultResourceManager, incoming_htlc_amount: u64) -> bool {
		let mut channels_lock = rm.channels.lock().unwrap();
		let outgoing_channel = channels_lock.get_mut(&OUTGOING_SCID).unwrap();
		let pending_htlcs_in_congestion = outgoing_channel.pending_htlcs_in_congestion();

		let incoming_channel = channels_lock.get_mut(&INCOMING_SCID).unwrap();
		incoming_channel.congestion_eligible(
			pending_htlcs_in_congestion,
			incoming_htlc_amount,
			OUTGOING_SCID,
			SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
		)
	}

	#[test]
	fn test_not_congestion_eligible() {
		// Test not congestion eligible for:
		// - Outgoing channel already has HTLC in congestion bucket.
		// - Congestion bucket is full
		// - Congestion bucket was misused
		let cases = vec![
			|rm: &DefaultResourceManager| {
				fill_general_bucket(&rm, INCOMING_SCID);
				let htlc_id = 1;
				let entropy_source = TestKeysInterface::new(&[0; 32], Network::Testnet);
				add_test_htlc(&rm, false, htlc_id, None, &entropy_source).unwrap();
				assert_eq!(
					get_htlc_bucket(&rm, INCOMING_SCID, htlc_id, OUTGOING_SCID).unwrap(),
					BucketAssigned::Congestion
				);
			},
			|rm: &DefaultResourceManager| {
				fill_congestion_bucket(rm, INCOMING_SCID);
			},
			|rm: &DefaultResourceManager| {
				mark_congestion_misused(rm, INCOMING_SCID, OUTGOING_SCID);
			},
		];

		for case_setup in cases {
			let rm = create_test_resource_manager_with_channels();
			case_setup(&rm);
			assert_eq!(test_congestion_eligible(&rm, HTLC_AMOUNT + FEE_AMOUNT), false);
		}
	}

	#[test]
	fn test_congestion_eligible_htlc_over_slot_limit() {
		let rm = create_test_resource_manager_with_channels();
		assert!(test_congestion_eligible(&rm, HTLC_AMOUNT + FEE_AMOUNT));

		// Get the congestion bucket's per-slot limit
		let channels = rm.channels.lock().unwrap();
		let incoming_channel = channels.get(&INCOMING_SCID).unwrap();
		let slot_limit = incoming_channel.congestion_bucket.liquidity_allocated
			/ incoming_channel.congestion_bucket.slots_allocated as u64;
		drop(channels);

		// Try to add HTLC that exceeds the slot limit
		let htlc_amount_over_limit = slot_limit + 1000;
		assert!(!test_congestion_eligible(&rm, htlc_amount_over_limit));
	}

	fn test_sufficient_reputation(rm: &DefaultResourceManager) -> bool {
		let mut channels_lock = rm.channels.lock().unwrap();
		let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

		let outgoing_channel = channels_lock.get_mut(&OUTGOING_SCID).unwrap();
		let outgoing_reputation = outgoing_channel.outgoing_reputation.value_at_timestamp(now);
		let outgoing_in_flight_risk: u64 = outgoing_channel.outgoing_in_flight_risk();
		let fee = FEE_AMOUNT;
		let in_flight_htlc_risk = rm.htlc_in_flight_risk(fee, CLTV_EXPIRY, CURRENT_HEIGHT);

		let incoming_channel = channels_lock.get_mut(&INCOMING_SCID).unwrap();
		incoming_channel.sufficient_reputation(
			in_flight_htlc_risk,
			outgoing_reputation,
			outgoing_in_flight_risk,
			now,
		)
	}

	#[test]
	fn test_insufficient_reputation_outgoing_in_flight_risk() {
		let rm = create_test_resource_manager_with_channels();
		let entropy_source = TestKeysInterface::new(&[0; 32], Network::Testnet);
		let reputation = 50_000_000;
		add_reputation(&rm, OUTGOING_SCID, reputation);

		// Successfully add unaccountable HTLC that should not count in the outgoing
		// accumulated outgoing in-flight risk.
		assert!(add_test_htlc(&rm, false, 0, None, &entropy_source).is_ok());

		let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
		let high_cltv_expiry = CURRENT_HEIGHT + 2000;

		// Add accountable HTLC that will add 49_329_633 to the in-flight risk. This is based
		// on the 3700 and CLTV delta added.
		assert!(rm
			.add_htlc(
				INCOMING_SCID,
				HTLC_AMOUNT + 3700,
				high_cltv_expiry,
				OUTGOING_SCID,
				HTLC_AMOUNT,
				true,
				1,
				CURRENT_HEIGHT,
				current_time,
				&entropy_source,
			)
			.is_ok());

		// Since we have added an accountable HTLC with in-fligh risk that is close to the
		// reputation we added, the next accountable HTLC we try to add should fail.
		assert_eq!(test_sufficient_reputation(&rm), false);
	}

	#[test]
	fn test_insufficient_reputation_higher_incoming_revenue_threshold() {
		let rm = create_test_resource_manager_with_channels();
		add_reputation(&rm, OUTGOING_SCID, 10_000);

		let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
		let mut channels = rm.channels.lock().unwrap();
		let incoming_channel = channels.get_mut(&INCOMING_SCID).unwrap();
		// Add revenue to incoming channel so that it goes above outgoing's reputation
		incoming_channel.incoming_revenue.add_value(50_000, current_time);
		drop(channels);

		assert_eq!(test_sufficient_reputation(&rm), false);
	}

	#[test]
	fn test_sufficient_reputation_exactly_at_threshold() {
		let rm = create_test_resource_manager_with_channels();

		let in_flight_risk = rm.htlc_in_flight_risk(FEE_AMOUNT, CLTV_EXPIRY, CURRENT_HEIGHT);
		let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
		let mut channels = rm.channels.lock().unwrap();

		// Set incoming revenue threshold
		let threshold = 10_000_000;
		let incoming_channel = channels.get_mut(&INCOMING_SCID).unwrap();
		incoming_channel.incoming_revenue.add_value(threshold, current_time);

		// Set outgoing reputation to match threshold plus in-flight risk
		let reputation_needed = threshold + i64::try_from(in_flight_risk).unwrap();
		let outgoing_channel = channels.get_mut(&OUTGOING_SCID).unwrap();
		outgoing_channel.outgoing_reputation.add_value(reputation_needed, current_time);
		drop(channels);

		assert_eq!(test_sufficient_reputation(&rm), true);
	}

	#[test]
	fn test_add_htlc_unaccountable_forwarding_decisions() {
		struct TestCase {
			description: &'static str,
			setup: fn(&DefaultResourceManager),
			expected_outcome: ForwardingOutcome,
			expected_bucket: Option<BucketAssigned>,
		}

		let cases = vec![
			TestCase {
				description: "general bucket available",
				setup: |_rm| {},
				expected_outcome: ForwardingOutcome::Forward(false),
				expected_bucket: Some(BucketAssigned::General),
			},
			TestCase {
				description: "general full, sufficient reputation goes to protected",
				setup: |rm| {
					add_reputation(rm, OUTGOING_SCID, HTLC_AMOUNT as i64);
					fill_general_bucket(rm, INCOMING_SCID);
				},
				expected_outcome: ForwardingOutcome::Forward(true),
				expected_bucket: Some(BucketAssigned::Protected),
			},
			TestCase {
				description: "general full, insufficient reputation goes to congestion",
				setup: |rm| fill_general_bucket(rm, INCOMING_SCID),
				expected_outcome: ForwardingOutcome::Forward(true),
				expected_bucket: Some(BucketAssigned::Congestion),
			},
			TestCase {
				description: "congestion misused recently fails",
				setup: |rm| {
					fill_general_bucket(rm, INCOMING_SCID);
					mark_congestion_misused(rm, INCOMING_SCID, OUTGOING_SCID);
				},
				expected_outcome: ForwardingOutcome::Fail,
				expected_bucket: None,
			},
		];

		let entropy_source = TestKeysInterface::new(&[0; 32], Network::Testnet);
		let htlc_id = 1;
		for case in cases {
			let rm = create_test_resource_manager_with_channels();
			(case.setup)(&rm);

			let result = add_test_htlc(&rm, false, htlc_id, None, &entropy_source);
			assert!(result.is_ok(), "case '{}': add_htlc returned Err", case.description);
			assert_eq!(
				result.unwrap(),
				case.expected_outcome,
				"case '{}': unexpected forwarding outcome",
				case.description
			);
			assert_eq!(
				get_htlc_bucket(&rm, INCOMING_SCID, htlc_id, OUTGOING_SCID),
				case.expected_bucket,
				"case '{}': unexpected bucket assignment",
				case.description
			);
		}
	}

	#[test]
	fn test_add_htlc_unaccountable_congestion_already_has_htlc() {
		let rm = create_test_resource_manager_with_channels();
		let entropy_source = TestKeysInterface::new(&[0; 32], Network::Testnet);
		fill_general_bucket(&rm, INCOMING_SCID);

		// With general bucket full, adding HTLC here should go to congestion bucket.
		let mut htlc_id = 1;
		let result_1 = add_test_htlc(&rm, false, htlc_id, None, &entropy_source);
		assert!(result_1.is_ok());
		assert_eq!(result_1.unwrap(), ForwardingOutcome::Forward(true));
		assert_eq!(
			get_htlc_bucket(&rm, INCOMING_SCID, htlc_id, OUTGOING_SCID).unwrap(),
			BucketAssigned::Congestion
		);

		// Adding a second HTLC should fail because outgoing channel is already using a slot in
		// the congestion bucket and it does not have sufficient reputation to get into the
		// protected bucket.
		htlc_id = 2;
		let result_2 = add_test_htlc(&rm, false, htlc_id, None, &entropy_source);
		assert_eq!(result_2.unwrap(), ForwardingOutcome::Fail);
		assert!(get_htlc_bucket(&rm, INCOMING_SCID, htlc_id, OUTGOING_SCID).is_none());
	}

	#[test]
	fn test_add_htlc_accountable_forwarding_decisions() {
		struct TestCase {
			description: &'static str,
			setup: fn(&DefaultResourceManager),
			expected_outcome: ForwardingOutcome,
			expected_bucket: Option<BucketAssigned>,
		}

		let cases = vec![
			TestCase {
				description: "sufficient reputation goes to protected",
				setup: |rm| add_reputation(rm, OUTGOING_SCID, HTLC_AMOUNT as i64),
				expected_outcome: ForwardingOutcome::Forward(true),
				expected_bucket: Some(BucketAssigned::Protected),
			},
			TestCase {
				description: "insufficient reputation fails",
				setup: |_rm| {},
				expected_outcome: ForwardingOutcome::Fail,
				expected_bucket: None,
			},
			TestCase {
				description: "sufficient reputation, protected full, falls back to general",
				setup: |rm| {
					add_reputation(rm, OUTGOING_SCID, HTLC_AMOUNT as i64);
					fill_protected_bucket(rm, INCOMING_SCID);
				},
				expected_outcome: ForwardingOutcome::Forward(true),
				expected_bucket: Some(BucketAssigned::General),
			},
			TestCase {
				description: "sufficient reputation, protected and general full, fails",
				setup: |rm| {
					add_reputation(rm, OUTGOING_SCID, HTLC_AMOUNT as i64);
					fill_general_bucket(rm, INCOMING_SCID);
					fill_protected_bucket(rm, INCOMING_SCID);
				},
				expected_outcome: ForwardingOutcome::Fail,
				expected_bucket: None,
			},
		];

		let entropy_source = TestKeysInterface::new(&[0; 32], Network::Testnet);
		let htlc_id = 1;

		for case in cases {
			let rm = create_test_resource_manager_with_channels();
			(case.setup)(&rm);

			let result = add_test_htlc(&rm, true, htlc_id, None, &entropy_source);
			assert!(result.is_ok(), "case '{}': add_htlc returned Err", case.description);
			assert_eq!(
				result.unwrap(),
				case.expected_outcome,
				"case '{}': unexpected forwarding outcome",
				case.description
			);
			assert_eq!(
				get_htlc_bucket(&rm, INCOMING_SCID, htlc_id, OUTGOING_SCID),
				case.expected_bucket,
				"case '{}': unexpected bucket assignment",
				case.description
			);
		}
	}

	#[test]
	fn test_add_htlc_stores_correct_pending_htlc_data() {
		let rm = create_test_resource_manager_with_channels();
		let entropy_source = TestKeysInterface::new(&[0; 32], Network::Testnet);

		let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
		let htlc_id = 42;
		let result = rm.add_htlc(
			INCOMING_SCID,
			HTLC_AMOUNT + FEE_AMOUNT,
			CLTV_EXPIRY,
			OUTGOING_SCID,
			HTLC_AMOUNT,
			false,
			htlc_id,
			CURRENT_HEIGHT,
			current_time,
			&entropy_source,
		);
		assert!(result.is_ok());

		let channels = rm.channels.lock().unwrap();
		let htlc_ref = HtlcRef { incoming_channel_id: INCOMING_SCID, htlc_id };
		let pending_htlc = channels.get(&OUTGOING_SCID).unwrap().pending_htlcs.get(&htlc_ref);
		assert!(pending_htlc.is_some());
		// HTLC should only get added to pending list for outgoing channel
		assert!(channels.get(&INCOMING_SCID).unwrap().pending_htlcs.get(&htlc_ref).is_none());

		let pending_htlc = pending_htlc.unwrap();
		assert_eq!(pending_htlc.incoming_amount_msat, HTLC_AMOUNT + FEE_AMOUNT);
		assert_eq!(pending_htlc.fee, FEE_AMOUNT);
		assert_eq!(pending_htlc.added_at_unix_seconds, current_time);

		let expected_in_flight_risk =
			rm.htlc_in_flight_risk(FEE_AMOUNT, CLTV_EXPIRY, CURRENT_HEIGHT);
		assert_eq!(pending_htlc.in_flight_risk, expected_in_flight_risk);
	}

	#[test]
	fn test_resolve_htlc_unaccountable_outcomes() {
		struct TestCase {
			hold_time: Duration,
			settled: bool,
			expected_reputation: i64,
			expected_revenue: i64,
		}

		let config = ResourceManagerConfig::default();
		let fast_resolve = config.resolution_period / 2;
		let slow_resolve = config.resolution_period * 3;

		let cases = vec![
			TestCase {
				hold_time: fast_resolve,
				settled: true,
				expected_reputation: FEE_AMOUNT as i64, // effective_fee = fee
				expected_revenue: FEE_AMOUNT as i64,
			},
			TestCase {
				hold_time: slow_resolve,
				settled: true,
				expected_reputation: 0,              // effective_fee = 0 (slow unaccountable)
				expected_revenue: FEE_AMOUNT as i64, // revenue increases regardless of speed
			},
			TestCase {
				hold_time: fast_resolve,
				settled: false,
				expected_reputation: 0,
				expected_revenue: 0,
			},
			TestCase {
				hold_time: slow_resolve,
				settled: false,
				expected_reputation: 0,
				expected_revenue: 0,
			},
		];

		let entropy_source = TestKeysInterface::new(&[0; 32], Network::Testnet);

		for case in &cases {
			let rm = create_test_resource_manager_with_channels();
			let htlc_id = 1;

			assert_eq!(
				add_test_htlc(&rm, false, htlc_id, None, &entropy_source).unwrap(),
				ForwardingOutcome::Forward(false),
			);

			let resolved_at = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
				+ case.hold_time.as_secs();
			rm.resolve_htlc(INCOMING_SCID, htlc_id, OUTGOING_SCID, case.settled, resolved_at)
				.unwrap();

			let channels = rm.channels.lock().unwrap();
			assert_eq!(
				channels.get(&OUTGOING_SCID).unwrap().outgoing_reputation.value,
				case.expected_reputation,
			);
			assert_eq!(
				channels
					.get(&INCOMING_SCID)
					.unwrap()
					.incoming_revenue
					.aggregated_decaying_average
					.value,
				case.expected_revenue,
			);
		}
	}

	#[test]
	fn test_resolve_htlc_congestion_outcomes() {
		let entropy_source = TestKeysInterface::new(&[0; 32], Network::Testnet);
		let config = ResourceManagerConfig::default();
		let fast_resolve = config.resolution_period / 2;
		let slow_resolve = config.resolution_period * 3;

		let rm = create_test_resource_manager_with_channels();
		fill_general_bucket(&rm, INCOMING_SCID);
		let mut htlc_id = 1;
		assert_eq!(
			add_test_htlc(&rm, false, htlc_id, None, &entropy_source).unwrap(),
			ForwardingOutcome::Forward(true),
		);
		assert_eq!(
			get_htlc_bucket(&rm, INCOMING_SCID, htlc_id, OUTGOING_SCID).unwrap(),
			BucketAssigned::Congestion,
		);

		let resolved_at = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
			+ fast_resolve.as_secs();
		rm.resolve_htlc(INCOMING_SCID, htlc_id, OUTGOING_SCID, false, resolved_at).unwrap();

		let mut channels = rm.channels.lock().unwrap();
		let incoming = channels.get_mut(&INCOMING_SCID).unwrap();

		// The HTLC in congestion bucket resolved fast so it does not count as having misused the
		// congestion bucket.
		assert!(!incoming.has_misused_congestion(OUTGOING_SCID, resolved_at));
		assert_eq!(incoming.congestion_bucket.slots_used, 0);

		drop(channels);

		// Since it does not count as congestion misused, this HTLC can be added to congestion
		htlc_id += 1;
		let added_at = resolved_at;
		assert_eq!(
			add_test_htlc(&rm, false, htlc_id, Some(added_at), &entropy_source).unwrap(),
			ForwardingOutcome::Forward(true),
		);
		assert_eq!(
			get_htlc_bucket(&rm, INCOMING_SCID, htlc_id, OUTGOING_SCID).unwrap(),
			BucketAssigned::Congestion,
		);

		// Slow resolution
		let resolved_at = added_at + slow_resolve.as_secs();
		rm.resolve_htlc(INCOMING_SCID, htlc_id, OUTGOING_SCID, false, resolved_at).unwrap();

		let mut channels = rm.channels.lock().unwrap();
		let incoming = channels.get_mut(&INCOMING_SCID).unwrap();

		// The HTLC in congestion bucket resolved slowly so it does count as having misused the
		// congestion bucket.
		assert!(incoming.has_misused_congestion(OUTGOING_SCID, resolved_at));

		drop(channels);

		// Congestion was misused so trying to add an HTLC should fail because the channel does
		// not have reputation to get into protected.
		htlc_id += 1;
		let added_at = resolved_at;
		assert_eq!(
			add_test_htlc(&rm, false, htlc_id, Some(added_at), &entropy_source).unwrap(),
			ForwardingOutcome::Fail,
		);

		let mut channels = rm.channels.lock().unwrap();
		let incoming = channels.get_mut(&INCOMING_SCID).unwrap();

		// After two weeks, the misused entry should be removed and congestion bucket should be
		// available again for use.
		let after_two_weeks = added_at + config.revenue_window.as_secs();
		assert!(!incoming.has_misused_congestion(OUTGOING_SCID, after_two_weeks));
		assert!(incoming.last_congestion_misuse.get(&OUTGOING_SCID).is_none());

		drop(channels);

		htlc_id += 1;
		assert_eq!(
			add_test_htlc(&rm, false, htlc_id, Some(after_two_weeks), &entropy_source).unwrap(),
			ForwardingOutcome::Forward(true),
		);
	}

	#[test]
	fn test_resolve_htlc_accountable_outcomes() {
		let rm = create_test_resource_manager_with_channels();
		let entropy_source = TestKeysInterface::new(&[0; 32], Network::Testnet);
		let fast_resolve = rm.config.resolution_period / 2;
		let accountable = true;

		add_reputation(&rm, OUTGOING_SCID, HTLC_AMOUNT as i64);

		let mut htlc_id = 1;
		let added_at = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
		assert_eq!(
			add_test_htlc(&rm, accountable, htlc_id, Some(added_at), &entropy_source).unwrap(),
			ForwardingOutcome::Forward(true),
		);
		assert_eq!(
			get_htlc_bucket(&rm, INCOMING_SCID, htlc_id, OUTGOING_SCID).unwrap(),
			BucketAssigned::Protected,
		);

		let get_reputation = |at_timestamp: u64| -> i64 {
			let mut channels = rm.channels.lock().unwrap();
			channels
				.get_mut(&OUTGOING_SCID)
				.unwrap()
				.outgoing_reputation
				.value_at_timestamp(at_timestamp)
		};

		// Check fast settled resolution adds to reputation
		let resolved_at = added_at + fast_resolve.as_secs();
		let current_rep = get_reputation(resolved_at);

		rm.resolve_htlc(INCOMING_SCID, htlc_id, OUTGOING_SCID, true, resolved_at).unwrap();

		let reputation_after_fast_resolve = get_reputation(resolved_at);
		assert_eq!(reputation_after_fast_resolve, (current_rep + FEE_AMOUNT as i64));

		let mut channels = rm.channels.lock().unwrap();
		let revenue = channels
			.get_mut(&INCOMING_SCID)
			.unwrap()
			.incoming_revenue
			.value_at_timestamp(resolved_at);
		assert_eq!(revenue, FEE_AMOUNT as i64,);
		drop(channels);

		// Fast failing accountable HTLC does not affect reputation
		htlc_id += 1;
		let added_at = resolved_at;
		assert_eq!(
			add_test_htlc(&rm, accountable, htlc_id, Some(added_at), &entropy_source).unwrap(),
			ForwardingOutcome::Forward(true),
		);
		assert_eq!(
			get_htlc_bucket(&rm, INCOMING_SCID, htlc_id, OUTGOING_SCID).unwrap(),
			BucketAssigned::Protected,
		);

		let resolved_at = added_at + fast_resolve.as_secs();
		let reputation_before_resolve = get_reputation(resolved_at);

		rm.resolve_htlc(INCOMING_SCID, htlc_id, OUTGOING_SCID, false, resolved_at).unwrap();

		assert_eq!(get_reputation(resolved_at), reputation_before_resolve);

		// Slow resolution should decrease reputation by effective fee
		let slow_resolve = rm.config.resolution_period * 10;
		let added_at = resolved_at;
		assert_eq!(
			add_test_htlc(&rm, accountable, htlc_id, Some(added_at), &entropy_source).unwrap(),
			ForwardingOutcome::Forward(true),
		);
		assert_eq!(
			get_htlc_bucket(&rm, INCOMING_SCID, htlc_id, OUTGOING_SCID).unwrap(),
			BucketAssigned::Protected,
		);

		let resolved_at = added_at + slow_resolve.as_secs();
		let reputation_before_slow_resolve = get_reputation(resolved_at);
		let effective_fee_slow_resolve = rm.effective_fees(FEE_AMOUNT, slow_resolve, true, true);
		rm.resolve_htlc(INCOMING_SCID, htlc_id, OUTGOING_SCID, true, resolved_at).unwrap();
		let reputation_after_slow_resolve = get_reputation(resolved_at);

		assert_eq!(
			reputation_after_slow_resolve,
			reputation_before_slow_resolve + effective_fee_slow_resolve
		);
	}

	#[test]
	fn test_multi_channel_general_bucket_saturation_flow() {
		let rm = create_test_resource_manager_with_channel_pairs(2);
		let entropy_source = TestKeysInterface::new(&[0; 32], Network::Testnet);

		// Fill general bucket (it should have been assigned 5 slots)
		let mut htlc_ids = Vec::new();
		for i in 1..=5 {
			let result = add_test_htlc(&rm, false, i, None, &entropy_source);
			assert!(result.is_ok());
			assert_eq!(result.unwrap(), ForwardingOutcome::Forward(false));
			assert_eq!(
				get_htlc_bucket(&rm, INCOMING_SCID, i, OUTGOING_SCID).unwrap(),
				BucketAssigned::General
			);
			htlc_ids.push(i);
		}
		assert_general_bucket_slots_used(&rm, INCOMING_SCID, OUTGOING_SCID, 5);

		// With the 5 slots in the general bucket used, the 6th HTLC goes to congestion
		let result = add_test_htlc(&rm, false, 6, None, &entropy_source);
		assert!(result.is_ok());
		assert_eq!(result.unwrap(), ForwardingOutcome::Forward(true));
		assert_eq!(
			get_htlc_bucket(&rm, INCOMING_SCID, 6, OUTGOING_SCID).unwrap(),
			BucketAssigned::Congestion
		);

		// 7th HTLC fails because it is already using a congestion slot and channel does not
		// have sufficient reputation to get into protected bucket.
		let result = add_test_htlc(&rm, false, 7, None, &entropy_source);
		assert_eq!(result.unwrap(), ForwardingOutcome::Fail);
		assert!(get_htlc_bucket(&rm, INCOMING_SCID, 7, OUTGOING_SCID).is_none());

		// Resolve 3 HTLCs that were assigned to the general bucket. It should end up with 2 in
		// general and one in congestion.
		let resolved_at = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
		rm.resolve_htlc(INCOMING_SCID, htlc_ids[0], OUTGOING_SCID, true, resolved_at).unwrap();
		rm.resolve_htlc(INCOMING_SCID, htlc_ids[2], OUTGOING_SCID, true, resolved_at).unwrap();
		rm.resolve_htlc(INCOMING_SCID, htlc_ids[4], OUTGOING_SCID, true, resolved_at).unwrap();
		assert_general_bucket_slots_used(&rm, INCOMING_SCID, OUTGOING_SCID, 2);
		assert_eq!(count_pending_htlcs(&rm, OUTGOING_SCID), 3);

		// Adding more HTLCs should now use the freed general slots.
		for i in 8..=10 {
			let result = add_test_htlc(&rm, false, i, None, &entropy_source);
			assert!(result.is_ok());
			assert_eq!(result.unwrap(), ForwardingOutcome::Forward(false));
			assert_eq!(
				get_htlc_bucket(&rm, INCOMING_SCID, i, OUTGOING_SCID).unwrap(),
				BucketAssigned::General
			);
		}
		assert_general_bucket_slots_used(&rm, INCOMING_SCID, OUTGOING_SCID, 5);

		// Adding HTLCs to a different outgoing channel should use its own slots. Some
		// slots may conflict with OUTGOING_SCID's assigned slots, so we check how many
		// are actually available.
		let conflicting_slots = {
			let mut channels = rm.channels.lock().unwrap();
			let incoming = channels.get_mut(&INCOMING_SCID).unwrap();
			let salt = entropy_source.get_secure_random_bytes();
			let slots = assign_slots_for_channel(
				incoming.general_bucket.scid,
				OUTGOING_SCID_2,
				salt,
				incoming.general_bucket.per_channel_slots,
				incoming.general_bucket.total_slots,
			)
			.unwrap();

			let slots_1 = &incoming.general_bucket.channels_slots.get(&OUTGOING_SCID).unwrap().0;
			let ret = slots.iter().filter(|s| slots_1.contains(s)).count();

			incoming.general_bucket.channels_slots.insert(OUTGOING_SCID_2, (slots, salt));
			ret
		};

		let available_slots = 5 - conflicting_slots;
		for i in 11..11 + available_slots as u64 {
			let result = rm.add_htlc(
				INCOMING_SCID,
				HTLC_AMOUNT + FEE_AMOUNT,
				CLTV_EXPIRY,
				OUTGOING_SCID_2,
				HTLC_AMOUNT,
				false,
				i,
				CURRENT_HEIGHT,
				SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
				&entropy_source,
			);
			assert!(result.is_ok());
			assert_eq!(
				get_htlc_bucket(&rm, INCOMING_SCID, i, OUTGOING_SCID_2).unwrap(),
				BucketAssigned::General
			);
		}
		assert_general_bucket_slots_used(&rm, INCOMING_SCID, OUTGOING_SCID_2, available_slots);

		// Different incoming uses its own bucket
		for i in 12 + available_slots as u64..=20 {
			let result = rm.add_htlc(
				INCOMING_SCID_2,
				HTLC_AMOUNT + FEE_AMOUNT,
				CLTV_EXPIRY,
				OUTGOING_SCID,
				HTLC_AMOUNT,
				false,
				i,
				CURRENT_HEIGHT,
				SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
				&entropy_source,
			);
			assert!(result.is_ok());
			assert_eq!(
				get_htlc_bucket(&rm, INCOMING_SCID_2, i, OUTGOING_SCID).unwrap(),
				BucketAssigned::General
			);
		}

		// Verify original channel pair still has 5 slots used
		assert_general_bucket_slots_used(&rm, INCOMING_SCID, OUTGOING_SCID, 5);
	}

	#[test]
	fn test_multi_channel_bucket_fallback_with_earned_reputation() {
		let entropy_source = TestKeysInterface::new(&[2; 32], Network::Testnet);
		let rm = create_test_resource_manager_with_channel_pairs(2);
		let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

		let add_htlc_between =
			|incoming_scid: u64, outgoing_scid: u64, accountable: bool, htlc_id: u64| {
				rm.add_htlc(
					incoming_scid,
					HTLC_AMOUNT + FEE_AMOUNT,
					CLTV_EXPIRY,
					outgoing_scid,
					HTLC_AMOUNT,
					accountable,
					htlc_id,
					CURRENT_HEIGHT,
					now,
					&entropy_source,
				)
			};

		// Build a revenue threshold of 5000 on INCOMING_SCID.
		for i in 1..=5_u64 {
			assert_eq!(
				add_htlc_between(INCOMING_SCID, OUTGOING_SCID_2, false, i).unwrap(),
				ForwardingOutcome::Forward(false),
			);
			rm.resolve_htlc(INCOMING_SCID, i, OUTGOING_SCID_2, true, now).unwrap();
		}

		// Use all generate slots available in INCOMING_SCID for both outgoing channels.
		for i in 6..=10_u64 {
			assert_eq!(
				add_htlc_between(INCOMING_SCID, OUTGOING_SCID, false, i).unwrap(),
				ForwardingOutcome::Forward(false),
			);
		}
		for i in 11..=15_u64 {
			assert_eq!(
				add_htlc_between(INCOMING_SCID, OUTGOING_SCID_2, false, i).unwrap(),
				ForwardingOutcome::Forward(false),
			);
		}
		let mut htlc_id = 16_u64;

		// Acquire a congestion slot for both outgoing channels. Reputation has not been earned
		// yet, so unaccountable HTLCs fall to congestion.
		let congestion_htlc_outgoing = htlc_id;
		assert_eq!(
			add_htlc_between(INCOMING_SCID, OUTGOING_SCID, false, congestion_htlc_outgoing)
				.unwrap(),
			ForwardingOutcome::Forward(true),
		);
		assert_eq!(
			get_htlc_bucket(&rm, INCOMING_SCID, congestion_htlc_outgoing, OUTGOING_SCID).unwrap(),
			BucketAssigned::Congestion,
		);
		htlc_id += 1;

		let congestion_htlc_outgoing_2 = htlc_id;
		assert_eq!(
			add_htlc_between(INCOMING_SCID, OUTGOING_SCID_2, false, congestion_htlc_outgoing_2)
				.unwrap(),
			ForwardingOutcome::Forward(true),
		);
		assert_eq!(
			get_htlc_bucket(&rm, INCOMING_SCID, congestion_htlc_outgoing_2, OUTGOING_SCID_2)
				.unwrap(),
			BucketAssigned::Congestion,
		);
		htlc_id += 1;

		// Build reputation for OUTGOING_SCID channel but not for OUTGOING_SCID_2.
		let rep_fee = 200_000_u64;
		let rep_htlc_amount = 1_000_000_u64;
		for i in htlc_id..htlc_id + 10 {
			assert_eq!(
				rm.add_htlc(
					INCOMING_SCID_2,
					rep_htlc_amount + rep_fee,
					CLTV_EXPIRY,
					OUTGOING_SCID,
					rep_htlc_amount,
					false,
					i,
					CURRENT_HEIGHT,
					now,
					&entropy_source,
				)
				.unwrap(),
				ForwardingOutcome::Forward(false),
			);
			rm.resolve_htlc(INCOMING_SCID_2, i, OUTGOING_SCID, true, now).unwrap();
		}
		htlc_id += 10;

		// Accountable HTLC forwarding decisions diverge based on earned reputation.
		//
		// - OUTGOING_SCID has reputation so accountable HTLC will get access to protected
		// bucket.
		// - OUTGOING_SCID_2 does not have reputation so it should fail.
		assert_eq!(
			add_htlc_between(INCOMING_SCID, OUTGOING_SCID, true, htlc_id).unwrap(),
			ForwardingOutcome::Forward(true),
		);
		assert_eq!(
			get_htlc_bucket(&rm, INCOMING_SCID, htlc_id, OUTGOING_SCID).unwrap(),
			BucketAssigned::Protected,
		);
		htlc_id += 1;

		assert_eq!(
			add_htlc_between(INCOMING_SCID, OUTGOING_SCID_2, true, htlc_id).unwrap(),
			ForwardingOutcome::Fail,
		);
		assert!(get_htlc_bucket(&rm, INCOMING_SCID, htlc_id, OUTGOING_SCID_2).is_none());
	}

	#[test]
	fn test_remove_channel_no_pending_htlcs() {
		let rm = create_test_resource_manager_with_channels();
		let channels = rm.channels.lock().unwrap();
		assert!(channels.get(&OUTGOING_SCID).is_some());
		drop(channels);

		rm.remove_channel(OUTGOING_SCID).unwrap();

		let channels = rm.channels.lock().unwrap();
		assert!(channels.get(&OUTGOING_SCID).is_none());
	}

	#[test]
	fn test_resolve_htlc_after_channel_close() {
		let entropy_source = TestKeysInterface::new(&[0; 32], Network::Testnet);
		let rm = create_test_resource_manager_with_channel_pairs(2);

		let added_at = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

		// HTLC 1: INCOMING_SCID (100) -> OUTGOING_SCID (200)
		assert_eq!(
			add_test_htlc(&rm, false, 1, Some(added_at), &entropy_source).unwrap(),
			ForwardingOutcome::Forward(false),
		);

		// HTLC 2: INCOMING_SCID_2 (101) -> OUTGOING_SCID_2 (201)
		assert_eq!(
			rm.add_htlc(
				INCOMING_SCID_2,
				HTLC_AMOUNT + FEE_AMOUNT,
				CLTV_EXPIRY,
				OUTGOING_SCID_2,
				HTLC_AMOUNT,
				false,
				1,
				CURRENT_HEIGHT,
				added_at,
				&entropy_source,
			)
			.unwrap(),
			ForwardingOutcome::Forward(false),
		);

		// Close the outgoing channel for HTLC 1. It has a pending HTLC so it is soft-deleted.
		rm.remove_channel(OUTGOING_SCID).unwrap();
		{
			let channels = rm.channels.lock().unwrap();
			let outgoing = channels.get(&OUTGOING_SCID).unwrap();
			assert!(outgoing.closed);
			assert_eq!(outgoing.pending_htlcs.len(), 1);
		}

		// Close the incoming channel for HTLC 2. It is referenced as incoming by an HTLC on
		// OUTGOING_SCID_2, so it is soft-deleted.
		rm.remove_channel(INCOMING_SCID_2).unwrap();
		{
			let channels = rm.channels.lock().unwrap();
			let incoming = channels.get(&INCOMING_SCID_2).unwrap();
			assert!(incoming.closed);
		}

		// New HTLCs should be rejected on closed channels.
		assert!(add_test_htlc(&rm, false, 2, None, &entropy_source).is_err());
		assert!(rm
			.add_htlc(
				INCOMING_SCID_2,
				HTLC_AMOUNT + FEE_AMOUNT,
				CLTV_EXPIRY,
				OUTGOING_SCID_2,
				HTLC_AMOUNT,
				false,
				2,
				CURRENT_HEIGHT,
				added_at,
				&entropy_source,
			)
			.is_err());

		let resolved_at = added_at + 10;

		// Resolve HTLC 1. Outgoing channel (200) is closed and now has no pending HTLCs,
		// so it is fully removed. Incoming channel (100) gets revenue updated.
		rm.resolve_htlc(INCOMING_SCID, 1, OUTGOING_SCID, true, resolved_at).unwrap();
		{
			let channels = rm.channels.lock().unwrap();
			assert!(channels.get(&OUTGOING_SCID).is_none());
			let incoming = channels.get(&INCOMING_SCID).unwrap();
			assert_eq!(
				incoming.incoming_revenue.aggregated_decaying_average.value,
				FEE_AMOUNT as i64,
			);
		}

		// Resolve HTLC 2. Incoming channel (101) is closed and has no pending HTLCs or
		// incoming references remaining, so it is fully removed. Outgoing channel (201)
		// gets reputation updated.
		rm.resolve_htlc(INCOMING_SCID_2, 1, OUTGOING_SCID_2, true, resolved_at).unwrap();
		{
			let channels = rm.channels.lock().unwrap();
			assert!(channels.get(&INCOMING_SCID_2).is_none());
			let outgoing = channels.get(&OUTGOING_SCID_2).unwrap();
			assert_eq!(outgoing.outgoing_reputation.value, FEE_AMOUNT as i64);
		}
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
