// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

#![allow(dead_code)]

use bitcoin::{
	hashes::{sha256::Hash as Sha256Hash, Hash},
	io::Read,
};
use core::{fmt::Display, time::Duration};
use hashbrown::hash_map::Entry;

use crate::{
	io,
	ln::channel::TOTAL_BITCOIN_SUPPLY_SATOSHIS,
	ln::msgs::DecodeError,
	prelude::{new_hash_map, HashMap},
	sign::EntropySource,
	sync::Mutex,
	util::ser::{Readable, Writeable, Writer},
};

/// A trait for managing channel resources and making HTLC forwarding decisions.
pub trait ResourceManager {
	/// Registers a new channel with the resource manager for tracking.
	///
	/// This should be called when a channel becomes ready for forwarding
	fn add_channel(
		&self, channel_id: u64, max_htlc_value_in_flight_msat: u64, max_accepted_htlcs: u16,
		timestamp_unix_secs: u64,
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
	/// This must be called for HTLCs where [`add_htlc`] returned [`ForwardingOutcome::Forward`].
	/// It reports if the HTLC was successfully settled or failed. This allows the implementation
	/// to release resources and update any internal tracking state.
	///
	/// [`add_htlc`]: ResourceManager::add_htlc
	fn resolve_htlc(
		&self, incoming_channel_id: u64, htlc_id: u64, outgoing_channel_id: u64, settled: bool,
		resolved_at: u64,
	) -> Result<(), ()>;
}

/// Resolution time in seconds that is considered "good". HTLCs resolved within this period are
/// considered normal and are rewarded in the reputation score. HTLCs resolved slower than this
/// will incur an opportunity cost to penalize slow resolving payments.
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

	/// The percentage of channel resources allocated to the protected bucket.
	/// The protected bucket is reserved for outgoing channels that have built sufficient reputation.
	///
	/// Default: 40%
	pub protected_allocation_pct: u8,

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
			protected_allocation_pct: 40,
			resolution_period: Duration::from_secs(ACCEPTABLE_RESOLUTION_PERIOD_SECS.into()),
			revenue_window: Duration::from_secs(REVENUE_WINDOW),
			reputation_multiplier: 12,
		}
	}
}

impl_writeable_tlv_based!(ResourceManagerConfig, {
	(1, general_allocation_pct, required),
	(3, congestion_allocation_pct, required),
	(5, protected_allocation_pct, required),
	(7, resolution_period, required),
	(9, revenue_window, required),
	(11, reputation_multiplier, required),
});

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

#[derive(Clone, PartialEq, Eq, Debug)]
enum BucketAssigned {
	General,
	Congestion,
	Protected,
}

impl_writeable_tlv_based_enum!(BucketAssigned,
	(1, General) => {},
	(3, Congestion) => {},
	(5, Protected) => {},
);

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

impl Writeable for GeneralBucket {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		let channel_info: HashMap<u64, [u8; 32]> =
			self.channels_slots.iter().map(|(scid, (_slots, salt))| (*scid, *salt)).collect();

		write_tlv_fields!(writer, {
			(1, self.scid, required),
			(3, self.total_slots, required),
			(5, self.total_liquidity, required),
			(7, channel_info, required),
		});
		Ok(())
	}
}

impl Readable for GeneralBucket {
	fn read<R: Read>(reader: &mut R) -> Result<Self, DecodeError> {
		_init_and_read_len_prefixed_tlv_fields!(reader, {
			(1, our_scid, required),
			(3, general_total_slots, required),
			(5, general_total_liquidity, required),
			(7, channel_info, required),
		});

		let mut general_bucket = GeneralBucket::new(
			our_scid.0.unwrap(),
			general_total_slots.0.unwrap(),
			general_total_liquidity.0.unwrap(),
		);

		let channel_info: HashMap<u64, [u8; 32]> = channel_info.0.unwrap();
		for (outgoing_scid, salt) in channel_info {
			general_bucket
				.assign_slots_for_channel(outgoing_scid, salt)
				.map_err(|_| DecodeError::InvalidValue)?;
		}

		Ok(general_bucket)
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

impl Writeable for BucketResources {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		write_tlv_fields!(writer, {
			(1, self.slots_allocated, required),
			(3, self.liquidity_allocated, required),
		});
		Ok(())
	}
}

impl Readable for BucketResources {
	fn read<R: Read>(reader: &mut R) -> Result<Self, DecodeError> {
		_init_and_read_len_prefixed_tlv_fields!(reader, {
			(1, slots_allocated, required),
			(3, liquidity_allocated, required),
		});
		Ok(BucketResources {
			slots_allocated: slots_allocated.0.unwrap(),
			slots_used: 0,
			liquidity_allocated: liquidity_allocated.0.unwrap(),
			liquidity_used: 0,
		})
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

impl_writeable_tlv_based!(PendingHTLC, {
	(1, incoming_amount_msat, required),
	(3, fee, required),
	(5, outgoing_channel, required),
	(7, outgoing_accountable, required),
	(9, added_at_unix_seconds, required),
	(11, in_flight_risk, required),
	(13, bucket, required),
});

#[derive(Debug, PartialEq, Eq, Hash)]
struct HtlcRef {
	incoming_channel_id: u64,
	htlc_id: u64,
}

impl_writeable_tlv_based!(HtlcRef, {
	(1, incoming_channel_id, required),
	(3, htlc_id, required),
});

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

	fn general_available<ES: EntropySource>(
		&mut self, incoming_amount_msat: u64, outgoing_channel_id: u64, entropy_source: &ES,
	) -> Result<bool, ()> {
		// Check if we need to assign slots for this outgoing channel
		let needs_slot_assignment =
			!self.general_bucket.channels_slots.contains_key(&outgoing_channel_id);

		let salt = if needs_slot_assignment {
			Some(entropy_source.get_secure_random_bytes())
		} else {
			None
		};

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
				if at_timestamp < *last_misuse.get() {
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

	fn outgoing_in_flight_risk(&self) -> u64 {
		// We only account the in-flight risk for HTLCs that are accountable
		self.pending_htlcs
			.iter()
			.map(|htlc| if htlc.1.outgoing_accountable { htlc.1.in_flight_risk } else { 0 })
			.sum()
	}
}

impl Writeable for Channel {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		write_tlv_fields!(writer, {
			(1, self.outgoing_reputation, required),
			(3, self.incoming_revenue, required),
			(5, self.pending_htlcs, required),
			(7, self.general_bucket, required),
			(9, self.congestion_bucket, required),
			(11, self.last_congestion_misuse, required),
			(13, self.protected_bucket, required),
		});

		Ok(())
	}
}

impl Readable for Channel {
	fn read<R: Read>(reader: &mut R) -> Result<Channel, DecodeError> {
		_init_and_read_len_prefixed_tlv_fields!(reader, {
			(1, outgoing_reputation, required),
			(3, incoming_revenue, required),
			(5, pending_htlcs, required),
			(7, general_bucket, required),
			(9, congestion_bucket, required),
			(11, last_congestion_misuse, required),
			(13, protected_bucket, required),
		});

		Ok(Channel {
			outgoing_reputation: outgoing_reputation.0.unwrap(),
			incoming_revenue: incoming_revenue.0.unwrap(),
			pending_htlcs: pending_htlcs.0.unwrap(),
			general_bucket: general_bucket.0.unwrap(),
			congestion_bucket: congestion_bucket.0.unwrap(),
			last_congestion_misuse: last_congestion_misuse.0.unwrap(),
			protected_bucket: protected_bucket.0.unwrap(),
		})
	}
}

/// An implementation of [`ResourceManager`] for managing channel resources and informing HTLC
/// forwarding decisions. It implements the core of the mitigation as proposed in
/// https://github.com/lightning/bolts/pull/1280.
pub struct DefaultResourceManager {
	config: ResourceManagerConfig,
	channels: Mutex<HashMap<u64, Channel>>,
}

impl DefaultResourceManager {
	pub fn new(config: ResourceManagerConfig) -> Self {
		DefaultResourceManager { config, channels: Mutex::new(new_hash_map()) }
	}

	// To calculate the risk of pending HTLCs, we assume they will resolve in the worst
	// possible case. Here we assume block times of 10 minutes.
	fn htlc_in_flight_risk(&self, fee: u64, incoming_cltv_expiry: u32, height_added: u32) -> u64 {
		let maximum_hold_time = (incoming_cltv_expiry.saturating_sub(height_added)) * 10 * 60;
		self.opportunity_cost(Duration::from_secs(maximum_hold_time as u64), fee)
	}

	fn opportunity_cost(&self, resolution_time: Duration, fee_msat: u64) -> u64 {
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
}

impl ResourceManager for DefaultResourceManager {
	fn add_channel(
		&self, channel_id: u64, max_htlc_value_in_flight_msat: u64, max_accepted_htlcs: u16,
		timestamp_unix_secs: u64,
	) -> Result<(), ()> {
		let mut channels_lock = self.channels.lock().unwrap();
		match channels_lock.entry(channel_id) {
			Entry::Vacant(entry) => {
				let channel = Channel::new(
					channel_id,
					max_htlc_value_in_flight_msat,
					max_accepted_htlcs,
					self.config.general_allocation_pct,
					self.config.congestion_allocation_pct,
					self.config.protected_allocation_pct,
					self.config.revenue_window,
					self.config.reputation_multiplier,
					timestamp_unix_secs,
				)?;
				entry.insert(channel);
				Ok(())
			},
			Entry::Occupied(_) => {
				debug_assert!(false, "We should not try to add channel that already exists.");
				Ok(())
			},
		}
	}

	fn remove_channel(&self, channel_id: u64) -> Result<(), ()> {
		let mut channels_lock = self.channels.lock().unwrap();
		let res = channels_lock.remove(&channel_id);
		debug_assert!(res.is_some(), "We should not try to remove channel that does not exist.");

		// Remove slots assigned to channel being removed across all other channels.
		for (_, channel) in channels_lock.iter_mut() {
			channel.general_bucket.remove_channel_slots(channel_id);
		}
		Ok(())
	}

	fn add_htlc<ES: EntropySource>(
		&self, incoming_channel_id: u64, incoming_amount_msat: u64, incoming_cltv_expiry: u32,
		outgoing_channel_id: u64, outgoing_amount_msat: u64, incoming_accountable: bool,
		htlc_id: u64, height_added: u32, added_at: u64, entropy_source: &ES,
	) -> Result<ForwardingOutcome, ()> {
		if (outgoing_amount_msat > incoming_amount_msat) || (height_added >= incoming_cltv_expiry) {
			return Err(());
		}

		let mut channels_lock = self.channels.lock().unwrap();

		let outgoing_channel = channels_lock.get_mut(&outgoing_channel_id).ok_or(())?;
		let outgoing_reputation =
			outgoing_channel.outgoing_reputation.value_at_timestamp(added_at)?;

		let outgoing_in_flight_risk: u64 = outgoing_channel.outgoing_in_flight_risk();
		let fee = incoming_amount_msat - outgoing_amount_msat;
		let in_flight_htlc_risk = self.htlc_in_flight_risk(fee, incoming_cltv_expiry, height_added);

		let pending_htlcs_in_congestion = outgoing_channel
			.pending_htlcs
			.iter()
			.find(|(htlc_ref, pending_htlc)| {
				htlc_ref.incoming_channel_id == incoming_channel_id
					&& pending_htlc.bucket == BucketAssigned::Congestion
			})
			.is_some();

		let incoming_channel = channels_lock.get_mut(&incoming_channel_id).ok_or(())?;

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
			)? && incoming_channel
				.protected_bucket
				.resources_available(incoming_amount_msat)
			{
				(true, BucketAssigned::Protected)
			} else if incoming_channel.congestion_eligible(
				pending_htlcs_in_congestion,
				incoming_amount_msat,
				outgoing_channel_id,
				self.config.revenue_window,
				added_at,
			)? {
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
			)? {
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
					None,
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
		let htlc_ref = HtlcRef { incoming_channel_id, htlc_id };
		let pending_htlc = PendingHTLC {
			incoming_amount_msat,
			fee,
			outgoing_channel: outgoing_channel_id,
			outgoing_accountable: accountable,
			added_at_unix_seconds: added_at,
			in_flight_risk: in_flight_htlc_risk,
			bucket: bucket_assigned,
		};
		outgoing_channel.pending_htlcs.insert(htlc_ref, pending_htlc);

		Ok(ForwardingOutcome::Forward(accountable))
	}

	fn resolve_htlc(
		&self, incoming_channel_id: u64, htlc_id: u64, outgoing_channel_id: u64, settled: bool,
		resolved_at: u64,
	) -> Result<(), ()> {
		let mut channels_lock = self.channels.lock().unwrap();
		let outgoing_channel = channels_lock.get_mut(&outgoing_channel_id).ok_or(())?;

		let htlc_ref = HtlcRef { incoming_channel_id, htlc_id };
		let pending_htlc = outgoing_channel.pending_htlcs.remove(&htlc_ref).ok_or(())?;

		if resolved_at < pending_htlc.added_at_unix_seconds {
			return Err(());
		}
		let resolution_time = Duration::from_secs(resolved_at - pending_htlc.added_at_unix_seconds);
		let effective_fee = self.effective_fees(
			pending_htlc.fee,
			resolution_time,
			pending_htlc.outgoing_accountable,
			settled,
		);
		outgoing_channel.outgoing_reputation.add_value(effective_fee, resolved_at)?;

		let incoming_channel = channels_lock.get_mut(&incoming_channel_id).ok_or(())?;
		match pending_htlc.bucket {
			BucketAssigned::General => incoming_channel
				.general_bucket
				.remove_htlc(pending_htlc.outgoing_channel, pending_htlc.incoming_amount_msat)?,
			BucketAssigned::Congestion => {
				// Mark that congestion bucket was misused if it took more than the valid
				// resolution period
				if resolution_time > self.config.resolution_period {
					incoming_channel.misused_congestion(pending_htlc.outgoing_channel, resolved_at);
				}

				incoming_channel.congestion_bucket.remove_htlc(pending_htlc.incoming_amount_msat)?
			},
			BucketAssigned::Protected => {
				incoming_channel.protected_bucket.remove_htlc(pending_htlc.incoming_amount_msat)?
			},
		}

		if settled {
			let fee: i64 = i64::try_from(pending_htlc.fee).unwrap_or(i64::MAX);
			incoming_channel.incoming_revenue.add_value(fee, resolved_at)?;
		}

		Ok(())
	}
}

impl Writeable for DefaultResourceManager {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		let channels = self.channels.lock().unwrap();
		write_tlv_fields!(writer, {
			(1, self.config, required),
			(3, channels, required),
		});
		Ok(())
	}
}

impl Readable for DefaultResourceManager {
	fn read<R: Read>(reader: &mut R) -> Result<DefaultResourceManager, DecodeError> {
		_init_and_read_len_prefixed_tlv_fields!(reader, {
			(1, config, required),
			(3, channels, required),
		});

		let mut channels: HashMap<u64, Channel> = channels.0.unwrap();
		let mut pending_htlcs: HashMap<u64, Vec<PendingHTLC>> = new_hash_map();

		for (_, channel) in channels.iter() {
			for (htlc_ref, htlc) in channel.pending_htlcs.iter() {
				pending_htlcs
					.entry(htlc_ref.incoming_channel_id)
					.or_insert_with(|| Vec::new())
					.push(htlc.clone());
			}
		}

		// Replay pending HTLCs to restore bucket usage.
		for (incoming_channel, htlcs) in pending_htlcs.iter() {
			let incoming_channel =
				channels.get_mut(incoming_channel).ok_or(DecodeError::InvalidValue)?;

			for htlc in htlcs {
				match htlc.bucket {
					BucketAssigned::General => {
						incoming_channel
							.general_bucket
							.add_htlc(htlc.outgoing_channel, htlc.incoming_amount_msat, None)
							.map_err(|_| DecodeError::InvalidValue)?;
					},
					BucketAssigned::Congestion => {
						incoming_channel
							.congestion_bucket
							.add_htlc(htlc.incoming_amount_msat)
							.map_err(|_| DecodeError::InvalidValue)?;
					},
					BucketAssigned::Protected => {
						incoming_channel
							.protected_bucket
							.add_htlc(htlc.incoming_amount_msat)
							.map_err(|_| DecodeError::InvalidValue)?;
					},
				}
			}
		}

		Ok(DefaultResourceManager { config: config.0.unwrap(), channels: Mutex::new(channels) })
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

impl Writeable for DecayingAverage {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		write_tlv_fields!(writer, {
			(1, self.value, required),
			(3, self.last_updated_unix_secs, required),
			(5, self.window, required),
		});
		Ok(())
	}
}

impl Readable for DecayingAverage {
	fn read<R: Read>(reader: &mut R) -> Result<Self, DecodeError> {
		_init_and_read_len_prefixed_tlv_fields!(reader, {
			(1, value, required),
			(3, last_updated_unix_secs, required),
			(5, window, required),
		});
		let window = window.0.unwrap();
		Ok(DecayingAverage {
			value: value.0.unwrap(),
			last_updated_unix_secs: last_updated_unix_secs.0.unwrap(),
			window,
			decay_rate: 0.5_f64.powf(2.0 / window.as_secs_f64()),
		})
	}
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

impl_writeable_tlv_based!(AggregatedWindowAverage, {
	(1, start_timestamp_unix_secs, required),
	(3, window_count, required),
	(5, window_duration, required),
	(7, aggregated_revenue_decaying, required),
});

#[cfg(test)]
mod tests {
	use std::time::{Duration, SystemTime, UNIX_EPOCH};

	use bitcoin::Network;

	use crate::{
		ln::resource_manager::{
			AggregatedWindowAverage, BucketAssigned, BucketResources, Channel, DecayingAverage,
			DefaultResourceManager, ForwardingOutcome, GeneralBucket, HtlcRef, ResourceManager,
			ResourceManagerConfig,
		},
		sign::EntropySource,
		util::{
			ser::{Readable, Writeable},
			test_utils::TestKeysInterface,
		},
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

	fn test_channel(config: &ResourceManagerConfig) -> Channel {
		Channel::new(
			0,
			100_000,
			100,
			config.general_allocation_pct,
			config.congestion_allocation_pct,
			config.protected_allocation_pct,
			config.revenue_window,
			config.reputation_multiplier,
			SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
		)
		.unwrap()
	}

	#[test]
	fn test_misuse_congestion_bucket() {
		let config = ResourceManagerConfig::default();
		let mut channel = test_channel(&config);
		let misusing_channel = 1;

		let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
		assert_eq!(
			channel.has_misused_congestion(misusing_channel, now, config.revenue_window).unwrap(),
			false
		);

		channel.misused_congestion(misusing_channel, now);
		assert_eq!(
			channel
				.has_misused_congestion(misusing_channel, now + 5, config.revenue_window)
				.unwrap(),
			true,
		);

		// Congestion misuse is taken into account if the bucket has been misused in the last 2
		// weeks. Test that after 2 weeks since last misuse, it returns that the bucket has not
		// been misused.
		let two_weeks = config.revenue_window.as_secs();
		assert_eq!(
			channel
				.has_misused_congestion(misusing_channel, now + two_weeks, config.revenue_window)
				.unwrap(),
			false
		);
	}

	#[test]
	fn test_opportunity_cost() {
		let config = ResourceManagerConfig::default();
		let resource_manager = DefaultResourceManager::new(config);

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

		let resource_manager = DefaultResourceManager::new(config);

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
	const HTLC_AMOUNT: u64 = 10_000_000;
	const FEE_AMOUNT: u64 = 1_000;
	const CURRENT_HEIGHT: u32 = 1000;
	const CLTV_EXPIRY: u32 = 1144;

	// TODO: When expanding tests, could change this to take number of channels to add
	fn create_test_resource_manager_with_channels() -> DefaultResourceManager {
		let config = ResourceManagerConfig::default();
		let resource_manager = DefaultResourceManager::new(config);
		let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
		resource_manager.add_channel(INCOMING_SCID, 5_000_000_000, 114, now).unwrap();
		resource_manager.add_channel(OUTGOING_SCID, 5_000_000_000, 114, now).unwrap();
		resource_manager
	}

	fn add_test_htlc<ES: EntropySource>(
		rm: &DefaultResourceManager, accountable: bool, htlc_id: u64, entropy_source: &ES,
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
			SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
			entropy_source,
		)
	}

	fn add_reputation(rm: &DefaultResourceManager, outgoing_scid: u64, target_reputation: i64) {
		let mut channels = rm.channels.lock().unwrap();
		let outgoing_channel = channels.get_mut(&outgoing_scid).unwrap();
		let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
		outgoing_channel.outgoing_reputation.add_value(target_reputation, now).unwrap();
	}

	fn fill_general_bucket(rm: &DefaultResourceManager, incoming_scid: u64) {
		let mut channels = rm.channels.lock().unwrap();
		let incoming_channel = channels.get_mut(&incoming_scid).unwrap();
		for slot in incoming_channel.general_bucket.slots_occupied.iter_mut() {
			*slot = true;
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
		htlc.map(|htlc| htlc.bucket.clone())
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
		let slots = channel.general_bucket.channels_slots.get(&outgoing_scid).unwrap();
		let used_count = slots.0.iter().filter(|slot| slot.1).count();
		assert_eq!(used_count, expected_count);
	}

	fn test_congestion_eligible(rm: &DefaultResourceManager, incoming_htlc_amount: u64) -> bool {
		let mut channels_lock = rm.channels.lock().unwrap();
		let outgoing_channel = channels_lock.get_mut(&OUTGOING_SCID).unwrap();
		let pending_htlcs_in_congestion = outgoing_channel
			.pending_htlcs
			.iter()
			.find(|(htlc_ref, pending_htlc)| {
				htlc_ref.incoming_channel_id == INCOMING_SCID
					&& pending_htlc.bucket == BucketAssigned::Congestion
			})
			.is_some();

		let incoming_channel = channels_lock.get_mut(&INCOMING_SCID).unwrap();
		incoming_channel
			.congestion_eligible(
				pending_htlcs_in_congestion,
				incoming_htlc_amount,
				OUTGOING_SCID,
				rm.config.revenue_window,
				SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
			)
			.unwrap()
	}

	#[test]
	fn test_congestion_eligible_success() {
		let rm = create_test_resource_manager_with_channels();
		assert!(test_congestion_eligible(&rm, HTLC_AMOUNT + FEE_AMOUNT));
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
				add_test_htlc(&rm, false, htlc_id, &entropy_source).unwrap();
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

		// Get the congestion bucket's per-slot limit
		let channels = rm.channels.lock().unwrap();
		let incoming_channel = channels.get(&INCOMING_SCID).unwrap();
		let slot_limit = incoming_channel.congestion_bucket.liquidity_allocated
			/ incoming_channel.congestion_bucket.slots_allocated as u64;
		drop(channels);

		// Try to add HTLC that exceeds the slot limit
		let htlc_amount_over_limit = slot_limit + 1000;
		assert_eq!(test_congestion_eligible(&rm, htlc_amount_over_limit), false);
	}

	fn test_sufficient_reputation(rm: &DefaultResourceManager) -> bool {
		let mut channels_lock = rm.channels.lock().unwrap();
		let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

		let outgoing_channel = channels_lock.get_mut(&OUTGOING_SCID).unwrap();
		let outgoing_reputation =
			outgoing_channel.outgoing_reputation.value_at_timestamp(now).unwrap();
		let outgoing_in_flight_risk: u64 = outgoing_channel.outgoing_in_flight_risk();
		let fee = FEE_AMOUNT;
		let in_flight_htlc_risk = rm.htlc_in_flight_risk(fee, CLTV_EXPIRY, CURRENT_HEIGHT);

		let incoming_channel = channels_lock.get_mut(&INCOMING_SCID).unwrap();
		incoming_channel
			.sufficient_reputation(
				in_flight_htlc_risk,
				outgoing_reputation,
				outgoing_in_flight_risk,
				now,
			)
			.unwrap()
	}

	#[test]
	fn test_insufficient_reputation_outgoing_in_flight_risk() {
		let rm = create_test_resource_manager_with_channels();
		let entropy_source = TestKeysInterface::new(&[0; 32], Network::Testnet);
		let reputation = 50_000_000;
		add_reputation(&rm, OUTGOING_SCID, reputation);

		// Successfully add unaccountable HTLC that should not count in the outgoing
		// accumulated outgoing in-flight risk.
		assert!(add_test_htlc(&rm, false, 0, &entropy_source).is_ok());

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
		incoming_channel.incoming_revenue.add_value(50_000, current_time).unwrap();
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
		incoming_channel.incoming_revenue.add_value(threshold, current_time).unwrap();

		// Set outgoing reputation to match threshold plus in-flight risk
		let reputation_needed = threshold + i64::try_from(in_flight_risk).unwrap();
		let outgoing_channel = channels.get_mut(&OUTGOING_SCID).unwrap();
		outgoing_channel.outgoing_reputation.add_value(reputation_needed, current_time).unwrap();
		drop(channels);

		assert_eq!(test_sufficient_reputation(&rm), true);
	}

	#[test]
	fn test_add_htlc_unaccountable_general_available() {
		let rm = create_test_resource_manager_with_channels();
		let entropy_source = TestKeysInterface::new(&[0; 32], Network::Testnet);

		let htlc_id = 1;
		let result = add_test_htlc(&rm, false, htlc_id, &entropy_source);
		assert!(result.is_ok());
		// Verify HTLC is forwarded as unaccountable and assigned to general bucket
		assert_eq!(result.unwrap(), ForwardingOutcome::Forward(false));
		assert_eq!(
			get_htlc_bucket(&rm, INCOMING_SCID, htlc_id, OUTGOING_SCID).unwrap(),
			BucketAssigned::General
		);

		let resolved_at = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
		let resolve_result =
			rm.resolve_htlc(INCOMING_SCID, htlc_id, OUTGOING_SCID, true, resolved_at);
		assert!(resolve_result.is_ok());
		assert!(get_htlc_bucket(&rm, INCOMING_SCID, htlc_id, OUTGOING_SCID).is_none());
	}

	#[test]
	fn test_add_htlc_unaccountable_protected_sufficient_reputation() {
		// Test that if general bucket is full, HTLC gets forwarded as accountable and goes
		// into protected bucket if outgoing channel has sufficient reputation.
		let rm = create_test_resource_manager_with_channels();
		let entropy_source = TestKeysInterface::new(&[0; 32], Network::Testnet);

		add_reputation(&rm, OUTGOING_SCID, HTLC_AMOUNT as i64);
		fill_general_bucket(&rm, INCOMING_SCID);

		let htlc_id = 1;
		let result = add_test_htlc(&rm, false, htlc_id, &entropy_source);
		assert!(result.is_ok());
		assert_eq!(result.unwrap(), ForwardingOutcome::Forward(true));
		assert_eq!(
			get_htlc_bucket(&rm, INCOMING_SCID, htlc_id, OUTGOING_SCID).unwrap(),
			BucketAssigned::Protected
		);
	}

	#[test]
	fn test_add_htlc_unaccountable_general_full_uses_congestion() {
		// Test that unaccountable HTLC goes into congestion bucket and forwarded as
		// accountable if general bucket is full and channel has insufficient reputation.
		let rm = create_test_resource_manager_with_channels();
		let entropy_source = TestKeysInterface::new(&[0; 32], Network::Testnet);
		fill_general_bucket(&rm, INCOMING_SCID);

		let htlc_id = 1;
		let result = add_test_htlc(&rm, false, htlc_id, &entropy_source);
		assert!(result.is_ok());
		// HTLC in congestion bucket should be forwarded as accountable
		assert_eq!(result.unwrap(), ForwardingOutcome::Forward(true));
		assert_eq!(
			get_htlc_bucket(&rm, INCOMING_SCID, htlc_id, OUTGOING_SCID).unwrap(),
			BucketAssigned::Congestion
		);
	}

	#[test]
	fn test_add_htlc_unaccountable_congestion_already_has_htlc() {
		let rm = create_test_resource_manager_with_channels();
		let entropy_source = TestKeysInterface::new(&[0; 32], Network::Testnet);
		fill_general_bucket(&rm, INCOMING_SCID);

		// With general bucket full, adding HTLC here should go to congestion bucket.
		let mut htlc_id = 1;
		let result_1 = add_test_htlc(&rm, false, htlc_id, &entropy_source);
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
		let result_2 = add_test_htlc(&rm, false, htlc_id, &entropy_source);
		assert_eq!(result_2.unwrap(), ForwardingOutcome::Fail);
		assert!(get_htlc_bucket(&rm, INCOMING_SCID, htlc_id, OUTGOING_SCID).is_none());
	}

	#[test]
	fn test_add_htlc_unaccountable_congestion_misused_recently() {
		// Test that adding HTLC fails if congestion has been misused recently
		let rm = create_test_resource_manager_with_channels();
		let entropy_source = TestKeysInterface::new(&[0; 32], Network::Testnet);
		fill_general_bucket(&rm, INCOMING_SCID);
		mark_congestion_misused(&rm, INCOMING_SCID, OUTGOING_SCID);

		// TODO: similar to this test, add one where it is marked as misused if HTLC took
		// longer that resolution period. Rather than marking it manually as done here.

		let htlc_id = 1;
		let result = add_test_htlc(&rm, false, htlc_id, &entropy_source);
		assert_eq!(result.unwrap(), ForwardingOutcome::Fail);
		assert!(get_htlc_bucket(&rm, INCOMING_SCID, htlc_id, OUTGOING_SCID).is_none());
	}

	#[test]
	fn test_add_htlc_unaccountable_insufficient_reputation_fails() {
		// Test that if outgoing channel does not have sufficient reputation and general and congestion
		// buckets are full, the HTLC forward fails.
		let rm = create_test_resource_manager_with_channels();
		let entropy_source = TestKeysInterface::new(&[0; 32], Network::Testnet);
		fill_general_bucket(&rm, INCOMING_SCID);
		mark_congestion_misused(&rm, INCOMING_SCID, OUTGOING_SCID);

		let htlc_id = 1;
		let result = add_test_htlc(&rm, false, htlc_id, &entropy_source);
		assert_eq!(result.unwrap(), ForwardingOutcome::Fail);
	}

	#[test]
	fn test_add_htlc_accountable_protected_sufficient_reputation() {
		// Test that accountable HTLC to channel with sufficient gets forwarded as
		// accountable and goes into protected bucket.
		let rm = create_test_resource_manager_with_channels();
		let entropy_source = TestKeysInterface::new(&[0; 32], Network::Testnet);
		add_reputation(&rm, OUTGOING_SCID, HTLC_AMOUNT as i64);

		let htlc_id = 1;
		let result = add_test_htlc(&rm, true, htlc_id, &entropy_source);
		assert!(result.is_ok());
		assert_eq!(result.unwrap(), ForwardingOutcome::Forward(true));
		assert_eq!(
			get_htlc_bucket(&rm, INCOMING_SCID, htlc_id, OUTGOING_SCID).unwrap(),
			BucketAssigned::Protected
		);
	}

	#[test]
	fn test_add_htlc_accountable_insufficient_reputation_fails() {
		// Test accountable HTLC to channel with insufficient reputation fails.
		let rm = create_test_resource_manager_with_channels();
		let entropy_source = TestKeysInterface::new(&[0; 32], Network::Testnet);
		let htlc_id = 1;
		let result = add_test_htlc(&rm, true, htlc_id, &entropy_source);
		assert!(result.is_ok());
		assert_eq!(result.unwrap(), ForwardingOutcome::Fail);
		assert!(get_htlc_bucket(&rm, INCOMING_SCID, htlc_id, OUTGOING_SCID).is_none());
	}

	#[test]
	fn test_add_htlc_accountable_protected_full_fallback_general() {
		// Test accountable HTLC to channel with sufficient reputation but protected is full
		// falls back to general bucket if available.
		let rm = create_test_resource_manager_with_channels();
		let entropy_source = TestKeysInterface::new(&[0; 32], Network::Testnet);
		add_reputation(&rm, OUTGOING_SCID, HTLC_AMOUNT as i64);

		fill_protected_bucket(&rm, INCOMING_SCID);
		let htlc_id = 1;
		let result = add_test_htlc(&rm, true, htlc_id, &entropy_source);
		assert!(result.is_ok());
		assert_eq!(result.unwrap(), ForwardingOutcome::Forward(true));
		assert_eq!(
			get_htlc_bucket(&rm, INCOMING_SCID, htlc_id, OUTGOING_SCID).unwrap(),
			BucketAssigned::General
		);
	}

	#[test]
	fn test_add_htlc_accountable_protected_and_general_full_fails() {
		let rm = create_test_resource_manager_with_channels();
		let entropy_source = TestKeysInterface::new(&[0; 32], Network::Testnet);
		add_reputation(&rm, OUTGOING_SCID, HTLC_AMOUNT as i64);
		fill_general_bucket(&rm, INCOMING_SCID);
		fill_protected_bucket(&rm, INCOMING_SCID);

		let htlc_id = 1;
		let result = add_test_htlc(&rm, true, htlc_id, &entropy_source);
		assert!(result.is_ok());
		assert_eq!(result.unwrap(), ForwardingOutcome::Fail);
		assert!(get_htlc_bucket(&rm, INCOMING_SCID, htlc_id, OUTGOING_SCID).is_none());
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
		assert_eq!(pending_htlc.outgoing_channel, OUTGOING_SCID);
		assert_eq!(pending_htlc.added_at_unix_seconds, current_time);

		let expected_in_flight_risk =
			rm.htlc_in_flight_risk(FEE_AMOUNT, CLTV_EXPIRY, CURRENT_HEIGHT);
		assert_eq!(pending_htlc.in_flight_risk, expected_in_flight_risk);
	}

	#[test]
	fn test_multi_channel_general_bucket_saturation_flow() {
		let rm = create_test_resource_manager_with_channels();
		let entropy_source = TestKeysInterface::new(&[0; 32], Network::Testnet);
		let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
		let incoming_101 = 101;
		let outgoing_201 = 201;
		rm.add_channel(incoming_101, 1_000_000_000, 114, now).unwrap();
		rm.add_channel(outgoing_201, 1_000_000_000, 114, now).unwrap();

		// Fill general bucket (it should have been assigned 5 slots)
		let mut htlc_ids = Vec::new();
		for i in 1..=5 {
			let result = add_test_htlc(&rm, false, i, &entropy_source);
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
		let result = add_test_htlc(&rm, false, 6, &entropy_source);
		assert!(result.is_ok());
		assert_eq!(result.unwrap(), ForwardingOutcome::Forward(true));
		assert_eq!(
			get_htlc_bucket(&rm, INCOMING_SCID, 6, OUTGOING_SCID).unwrap(),
			BucketAssigned::Congestion
		);

		// 7th HTLC fails because it is already using a congestion slot and channel does not
		// have sufficient reputation to get into protected bucket.
		let result = add_test_htlc(&rm, false, 7, &entropy_source);
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
			let result = add_test_htlc(&rm, false, i, &entropy_source);
			assert!(result.is_ok());
			assert_eq!(result.unwrap(), ForwardingOutcome::Forward(false));
			assert_eq!(
				get_htlc_bucket(&rm, INCOMING_SCID, i, OUTGOING_SCID).unwrap(),
				BucketAssigned::General
			);
		}
		assert_general_bucket_slots_used(&rm, INCOMING_SCID, OUTGOING_SCID, 5);

		// Adding HTLCs to a different outgoing channel should get 5 other slots. NOTE: this
		// could potentially fail if the 2 outgoing channels get assigned the same slot. Could
		// check before that they do have different general slots.
		for i in 11..=15 {
			let result = rm.add_htlc(
				INCOMING_SCID,
				HTLC_AMOUNT + FEE_AMOUNT,
				CLTV_EXPIRY,
				outgoing_201,
				HTLC_AMOUNT,
				false,
				i,
				CURRENT_HEIGHT,
				SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
				&entropy_source,
			);
			assert!(result.is_ok());
			assert_eq!(
				get_htlc_bucket(&rm, INCOMING_SCID, i, outgoing_201).unwrap(),
				BucketAssigned::General
			);
		}
		assert_general_bucket_slots_used(&rm, INCOMING_SCID, outgoing_201, 5);

		// Different incoming uses its own bucket
		for i in 16..=20 {
			let result = rm.add_htlc(
				incoming_101,
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
				get_htlc_bucket(&rm, incoming_101, i, OUTGOING_SCID).unwrap(),
				BucketAssigned::General
			);
		}

		// Verify original channel pair still has 5 slots used
		assert_general_bucket_slots_used(&rm, INCOMING_SCID, OUTGOING_SCID, 5);
	}

	#[test]
	fn test_simple_manager_serialize_deserialize() {
		let rm = create_test_resource_manager_with_channels();
		let entropy_source = TestKeysInterface::new(&[0; 32], Network::Testnet);

		// Add 7 HTLCs (5 in general, 1 in congestion and 1 in protected)
		for i in 1..=5 {
			add_test_htlc(&rm, false, i, &entropy_source).unwrap();
		}
		let congestion_htlc_amount = 25_000;
		let fee = 1000;
		rm.add_htlc(
			INCOMING_SCID,
			congestion_htlc_amount + fee,
			CLTV_EXPIRY,
			OUTGOING_SCID,
			congestion_htlc_amount,
			false,
			6,
			CURRENT_HEIGHT,
			SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
			&entropy_source,
		)
		.unwrap();

		let reputation = 50_000_000;
		add_reputation(&rm, OUTGOING_SCID, reputation);
		add_test_htlc(&rm, true, 7, &entropy_source).unwrap();

		let serialized_rm = rm.encode();

		let channels = rm.channels.lock().unwrap();
		let expected_incoming_channel = channels.get(&INCOMING_SCID).unwrap();
		let revenue = expected_incoming_channel.incoming_revenue.aggregated_revenue_decaying.value;

		let deserialized_rm = DefaultResourceManager::read(&mut serialized_rm.as_slice()).unwrap();
		let deserialized_channels = deserialized_rm.channels.lock().unwrap();
		assert_eq!(2, deserialized_channels.len());

		let incoming_channel = deserialized_channels.get(&INCOMING_SCID).unwrap();
		let outgoing_channel = deserialized_channels.get(&OUTGOING_SCID).unwrap();
		assert_eq!(7, outgoing_channel.pending_htlcs.len());
		assert_eq!(0, incoming_channel.pending_htlcs.len());

		// Check the 7 pending HTLCs that were on the outgoing channel
		let assert_htlc = |htlc_ref: HtlcRef,
		                   amount: u64,
		                   fee: u64,
		                   accountable: bool,
		                   bucket: BucketAssigned| {
			assert!(outgoing_channel.pending_htlcs.get(&htlc_ref).is_some());
			let htlc = outgoing_channel.pending_htlcs.get(&htlc_ref).unwrap();
			assert_eq!(htlc.outgoing_channel, OUTGOING_SCID);
			assert_eq!(htlc.incoming_amount_msat, amount + fee);
			assert_eq!(htlc.fee, fee);
			assert_eq!(htlc.outgoing_accountable, accountable);
			assert_eq!(htlc.bucket, bucket);
		};

		// Check 5 HTLCs in general bucket
		for i in 1..=5 {
			let htlc_ref = HtlcRef { incoming_channel_id: INCOMING_SCID, htlc_id: i };
			assert_htlc(htlc_ref, HTLC_AMOUNT, FEE_AMOUNT, false, BucketAssigned::General);
		}
		let htlc_ref = HtlcRef { incoming_channel_id: INCOMING_SCID, htlc_id: 6 };
		assert_htlc(htlc_ref, congestion_htlc_amount, fee, true, BucketAssigned::Congestion);

		let htlc_ref = HtlcRef { incoming_channel_id: INCOMING_SCID, htlc_id: 7 };
		assert_htlc(htlc_ref, HTLC_AMOUNT, FEE_AMOUNT, true, BucketAssigned::Protected);

		// Check outgoing reputation
		assert_eq!(outgoing_channel.outgoing_reputation.value, reputation);

		drop(deserialized_channels);
		assert_general_bucket_slots_used(&deserialized_rm, INCOMING_SCID, OUTGOING_SCID, 5);

		// Check incoming revenue
		let deserialized_channels = deserialized_rm.channels.lock().unwrap();
		let incoming_channel = deserialized_channels.get(&INCOMING_SCID).unwrap();
		assert_eq!(incoming_channel.incoming_revenue.aggregated_revenue_decaying.value, revenue);

		let congestion_bucket = &incoming_channel.congestion_bucket;
		assert_eq!(congestion_bucket.slots_used, 1);
		assert_eq!(congestion_bucket.liquidity_used, congestion_htlc_amount + fee);
		assert_eq!(
			congestion_bucket.slots_allocated,
			expected_incoming_channel.congestion_bucket.slots_allocated
		);
		assert_eq!(
			congestion_bucket.liquidity_used,
			expected_incoming_channel.congestion_bucket.liquidity_used
		);
		let protected_bucket = &incoming_channel.protected_bucket;
		assert_eq!(protected_bucket.slots_used, 1);
		assert_eq!(protected_bucket.liquidity_used, HTLC_AMOUNT + FEE_AMOUNT);
		assert_eq!(
			protected_bucket.slots_allocated,
			expected_incoming_channel.protected_bucket.slots_allocated
		);
		assert_eq!(
			protected_bucket.liquidity_used,
			expected_incoming_channel.protected_bucket.liquidity_used
		);
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
