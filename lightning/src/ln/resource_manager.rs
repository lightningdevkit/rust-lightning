// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Channel jamming mitigation via reputation and resource bucketing.
//!
//! Implements the mitigation proposed in
//! <https://github.com/lightning/bolts/pull/1280>, which combines two ideas:
//!
//! **Local reputation.** Every channel is scored by the revenue it has historically earned us, and
//! by whether HTLCs *forwarded out over it* resolved promptly. A peer that forwards HTLCs which
//! resolve quickly builds reputation; one that holds HTLCs to their CLTV expiry loses it. Scores
//! are kept as decaying averages ([`DecayingAverage`]) so no per-HTLC history is stored.
//!
//! **Resource bucketing.** Each channel's `max_accepted_htlcs` slots and
//! `max_htlc_value_in_flight_msat` are split into three buckets:
//!
//! - *General* ([`GeneralBucket`]): Open to all traffic. Each incoming/outgoing channel pair is
//!   assigned a subset of the slots, so no single peer pair can occupy the whole bucket.
//! - *Congestion* ([`BucketResources`]): A small allowance that lets a peer with no reputation yet
//!   get a single HTLC through when the general bucket is saturated, so new peers can bootstrap.
//! - *Protected* ([`BucketResources`]): Reserved for HTLCs from peers that have built sufficient
//! reputation.

#![allow(dead_code)]

use bitcoin::hashes::{sha256, Hash, HashEngine};
use chacha20_poly1305::{chacha20::ChaCha20, Key, Nonce};
use core::{f64, fmt::Display, time::Duration};

use crate::{
	ln::{channel::TOTAL_BITCOIN_SUPPLY_SATOSHIS, types::ChannelId},
	prelude::{hash_map::Entry, new_hash_map, HashMap, Vec},
	sign::EntropySource,
	sync::Mutex,
	util::math::{expf64, powf64, roundf64},
};

/// The minimum number of slots required for the general bucket to function.
const MIN_GENERAL_BUCKET_SLOTS: u16 = 5;

/// The minimum `max_htlc_value_in_flight_msat` required for a channel to be added to the resource
/// manager. This corresponds to the default `min_funding_satoshis` of 1000 in
/// [`crate::util::config::ChannelHandshakeLimits`], which is the smallest channel size LDK will
/// accept.
const MIN_MAX_IN_FLIGHT_MSAT: u64 = 1_000_000;

/// Resolution time in seconds that is considered "good". HTLCs resolved within this period are
/// considered normal and are rewarded in the reputation score.
const ACCEPTABLE_RESOLUTION_PERIOD_SECS: Duration = Duration::from_secs(90);

/// The maximum time (in seconds) that a HTLC can be held. Corresponds to the largest cltv delta
/// allowed in the protocol which is 2016 blocks. Assuming 10 minute blocks, this is roughly 2
/// weeks.
const REVENUE_WINDOW: Duration = Duration::from_secs(2016 * 10 * 60);

/// Configuration parameters for the resource manager.
///
/// This configuration controls how the resource manager allocates channel resources (HTLC slots
/// and liquidity) across three buckets (general, congestion, and protected).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ResourceManagerConfig {
	/// The percentage of channel resources allocated to the general bucket.
	/// The general bucket is available to all traffic with basic denial-of-service protections.
	///
	/// Default: 40%
	pub(crate) general_allocation_pct: u8,

	/// The percentage of channel resources allocated to the congestion bucket.
	/// The congestion bucket is used when the general bucket is saturated. It allows an outgoing
	/// channel that does not have reputation to have a chance of getting the HTLC forwarded.
	///
	/// Default: 20%
	pub(crate) congestion_allocation_pct: u8,

	/// The amount of time a HTLC is allowed to resolve in that classifies as "good" behavior.
	/// HTLCs resolved within this period are rewarded in the reputation score. HTLCs resolved
	/// slower than this will incur an opportunity cost penalty.
	///
	/// Default: 90 seconds
	pub(crate) resolution_period: Duration,

	/// The rolling window over which we track the revenue an incoming channel has earned us.
	///
	/// As an incoming link, a channel accrues revenue from the forwarding fees of the HTLCs it
	/// sends us over this window. That revenue is the bar an outgoing channel's reputation must
	/// clear before we grant its HTLCs access to our protected resources. We only extend
	/// protected access to a peer that has earned us more (over the longer reputation window, see
	/// [`reputation_multiplier`]) than this incoming channel earns us over `revenue_window`.
	///
	/// It is set to the largest cltv delta a node will allow before failing a HTLC with
	/// `expiry_too_far` (2016 blocks, ~2 weeks at 10 minute blocks). It is set to this value
	/// because it is the maximum time a single HTLC can be held before it must resolve, and
	/// therefore the maximum time an attacker can tie up our resources. When evaluating a HTLC
	/// forward and whether we should grant access to our protected resources, we size the window
	/// to this value to mean the revenue we put "at risk" since that is the revenue an attacker
	/// could deny us by holding HTLCs for the full ctlv expiry delta allowed.
	///
	/// Default: 2016 blocks * 10 minutes = ~2 weeks
	///
	/// [`reputation_multiplier`]: Self::reputation_multiplier
	pub(crate) revenue_window: Duration,

	/// A multiplier applied to [`revenue_window`] that sets the window over which we measure an
	/// outgoing channel's reputation, i.e. the history of revenue that channel has built up with
	/// us as an outgoing link. Reputation is tracked over `revenue_window * reputation_multiplier`.
	///
	/// When evaluating a HTLC forward, this reputation is compared against the [`revenue_window`]
	/// revenue of the incoming channel. The outgoing channel is only granted access to our
	/// protected resources if the reputation it has built over this window exceeds that revenue.
	/// Note that this window is a multiplier to [`revenue_window`] and it is intended to measure
	/// the track record of the outgoing channel by tracking the fees it has earned us as an
	/// outgoing link in HTLC forwards over this period. We only track forwards as an outgoing
	/// link because that is the peer that can hold the HTLC to perform a jamming attack.
	///
	/// Raising this value lengthens the history we remember when evaluating an outgoing
	/// channel's reputation. If lower, it means we reflect most recent forwards and getting
	/// access to protected resources can be harder to earn since the window over which we evaluate
	/// historical forward behaviour is shorter.
	///
	/// Default: 12 (meaning reputation is tracked over 12 * 2 weeks = 24 weeks)
	///
	/// [`revenue_window`]: Self::revenue_window
	pub(crate) reputation_multiplier: u8,
}

impl Default for ResourceManagerConfig {
	fn default() -> ResourceManagerConfig {
		Self {
			general_allocation_pct: 40,
			congestion_allocation_pct: 20,
			resolution_period: ACCEPTABLE_RESOLUTION_PERIOD_SECS,
			revenue_window: REVENUE_WINDOW,
			reputation_multiplier: 12,
		}
	}
}

impl ResourceManagerConfig {
	fn validate(&self) -> Result<(), ()> {
		if self.general_allocation_pct as u16 + self.congestion_allocation_pct as u16 >= 100 {
			return Err(());
		}
		if self.general_allocation_pct == 0 {
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

/// The minimum number that can be set for the `max_accepted_htlcs` value of a channel to be added
/// to the resource manager. Used to ensure that general bucket gets at least
/// [`MIN_GENERAL_BUCKET_SLOTS`] slots.
fn min_accepted_htlcs(general_pct: u8) -> u16 {
	(100 * MIN_GENERAL_BUCKET_SLOTS - 50).div_ceil(general_pct as u16)
}

/// The outcome of an HTLC forwarding decision.
#[derive(PartialEq, Eq, Debug)]
pub(crate) enum ForwardingOutcome {
	/// Forward the HTLC with the specified accountable signal.
	///
	/// When `true`, the downstream peer is told that slow resolution of this HTLC will be held
	/// against its reputation. When `false`, the HTLC is unaccountable so it can never lower the
	/// downstream peer's reputation, but it can only occupy general bucket resources.
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

/// Which bucket's resources a pending HTLC is holding, recorded so that those resources
/// are released on resolution.
#[derive(Clone, PartialEq, Eq, Debug)]
enum BucketAssigned {
	/// The specific general bucket slot indices occupied, as returned by
	/// [`GeneralBucket::available_slots`].
	General(Vec<u16>),
	Congestion,
	Protected,
}

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
	/// occupied (as recorded in its [`PendingHTLC`]).
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

/// Bucket resources used for congestion and protected buckets.
///
/// Different from [`GeneralBucket`], there is no per-channel-pair slot assignment, so any HTLC
/// admitted simply consumes slots and its amount from the shared totals. Admission is gated
/// before the HTLC gets here. For congestion, it is gated by [`Channel::can_use_incoming_congestion_slot`]
/// and for protected bucket it is restricted to peers with reputation.
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

/// A pending HTLC tracked against the outgoing channel.
#[derive(Debug, Clone)]
struct PendingHTLC {
	incoming_amount_msat: u64,
	fee: u64,
	/// The accountable signal we set on the outgoing HTLC. Only accountable HTLCs can affect a
	/// channel's reputation.
	outgoing_accountable: bool,
	added_at_unix_seconds: u64,
	/// The worst-case reputation damage this HTLC can do if held until its expiry, as computed by
	/// [`ResourceManager::htlc_in_flight_risk`].
	in_flight_risk: u64,
	bucket: BucketAssigned,
}

#[derive(Debug, PartialEq, Eq, Hash)]
struct HtlcRef {
	incoming_channel_id: ChannelId,
	htlc_id: u64,
}

/// Per-channel state. Note that this tracks state for the channel in the two roles that we use it.
/// As an incoming link, we track the revenue this channel has earned us. As an outgoing
/// link, we track the reputation this channel has accrued. Tracked this way because when evaluating
/// a HTLC forward, we compare the reputation of the outgoing channel to the revenue of the incoming
/// channel (+ the risk of the current pending HTLCs the outgoing channel has).
struct Channel {
	/// The reputation this channel has accrued as an outgoing link.
	outgoing_reputation: DecayingAverage,

	/// The revenue this channel has earned us as an incoming link.
	incoming_revenue: SmoothedDecayingAverage,

	/// HTLC Ref incoming channel -> pending HTLC outgoing.
	/// It tracks all the pending HTLCs where this channel is the outgoing link.
	pending_htlcs: HashMap<HtlcRef, PendingHTLC>,

	/// Bucket resources as an incoming channel
	// Tracked as incoming because when we look at a HTLC forward, we evaluate whether the
	// outgoing channel can take up resources in the incoming channel.
	incoming_general_bucket: GeneralBucket,
	incoming_congestion_bucket: BucketResources,
	incoming_protected_bucket: BucketResources,

	/// Channel id -> unix seconds timestamp
	/// Tracks which channels have misused the congestion bucket and the unix timestamp.
	last_congestion_misuse: HashMap<ChannelId, u64>,

	/// Whether this channel has been closed. We keep channels around until all its
	/// [`Self::pending_htlcs`] have been resolved. This ensures that HTLC resolutions that
	/// arrive after a force-close can still update reputation and revenue correctly.
	closed: bool,
}

impl Channel {
	/// Creates a channel, splitting its slot and liquidity limits across the three buckets by the
	/// percentages in `config`. The protected bucket takes whatever is left over, which the
	/// validated config guarantees to be non-negative.
	fn new(
		channel_id: ChannelId, node_salt: &[u8; 32], config: &ResourceManagerConfig,
		max_accepted_htlcs: u16, max_htlc_value_in_flight_msat: u64, timestamp_unix_secs: u64,
	) -> Result<Self, ()> {
		const REVENUE_WEEK_MULTIPLIER: u8 = 6;

		let general_pct = config.general_allocation_pct;
		let general_slots = (max_accepted_htlcs * general_pct as u16 + 50) / 100;
		let general_liquidity =
			((max_htlc_value_in_flight_msat as u128 * general_pct as u128 + 50) / 100) as u64;

		let congestion_pct = config.congestion_allocation_pct;
		let congestion_slots = (max_accepted_htlcs * congestion_pct as u16 + 50) / 100;
		let congestion_liquidity =
			((max_htlc_value_in_flight_msat as u128 * congestion_pct as u128 + 50) / 100) as u64;

		let protected_slots = max_accepted_htlcs - general_slots - congestion_slots;
		let protected_liquidity =
			max_htlc_value_in_flight_msat - general_liquidity - congestion_liquidity;

		let reputation_window = config.revenue_window * config.reputation_multiplier as u32;

		Ok(Channel {
			outgoing_reputation: DecayingAverage::new(timestamp_unix_secs, reputation_window),
			incoming_revenue: SmoothedDecayingAverage::new(
				config.revenue_window,
				REVENUE_WEEK_MULTIPLIER,
				timestamp_unix_secs,
			),
			pending_htlcs: new_hash_map(),
			incoming_general_bucket: GeneralBucket::new(
				channel_id,
				node_salt,
				general_slots,
				general_liquidity,
			)?,
			incoming_congestion_bucket: BucketResources::new(
				congestion_slots,
				congestion_liquidity,
			),
			incoming_protected_bucket: BucketResources::new(protected_slots, protected_liquidity),
			last_congestion_misuse: new_hash_map(),
			closed: false,
		})
	}

	/// Returns whether the outgoing channel can use the congestion bucket for the specified HTLC
	/// The HTLC is eligible if:
	/// - Congestion bucket resources are available
	/// - The outgoing channel does not have any pending HTLCs in the congestion bucket already
	/// - The outgoing channel has not misused the congestion bucket in the last two weeks
	/// - The HTLC amount fits in the slot.
	fn can_use_incoming_congestion_slot(
		&mut self, outgoing_channel: &Channel, incoming_amount_msat: u64, at_timestamp: u64,
	) -> bool {
		if self.incoming_congestion_bucket.slots_allocated == 0 {
			return false;
		}

		let congestion_resources_available =
			self.incoming_congestion_bucket.resources_available(incoming_amount_msat);
		let misused_congestion = self.has_misused_congestion(
			outgoing_channel.incoming_general_bucket.channel_id,
			at_timestamp,
		);

		let below_liquidity_limit = incoming_amount_msat
			<= self.incoming_congestion_bucket.liquidity_allocated
				/ self.incoming_congestion_bucket.slots_allocated as u64;

		let pending_htlcs_in_congestion = outgoing_channel.pending_htlcs_in_congestion();

		congestion_resources_available
			&& !pending_htlcs_in_congestion
			&& !misused_congestion
			&& below_liquidity_limit
	}

	/// Marks that an outgoing channel misused the congestion bucket.
	fn misused_congestion(&mut self, channel_id: ChannelId, misuse_timestamp: u64) {
		self.last_congestion_misuse.insert(channel_id, misuse_timestamp);
	}

	// Returns whether the outgoing channel has misused the congestion bucket in the last two
	// weeks.
	fn has_misused_congestion(
		&mut self, outgoing_channel_id: ChannelId, at_timestamp: u64,
	) -> bool {
		match self.last_congestion_misuse.entry(outgoing_channel_id) {
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

	/// Returns whether this channel (as an outgoing link) is responsible for any pending HTLCs
	/// in the congestion bucket.
	fn pending_htlcs_in_congestion(&self) -> bool {
		self.pending_htlcs
			.values()
			.any(|pending_htlc| pending_htlc.bucket == BucketAssigned::Congestion)
	}

	/// Returns the accumulated in-flight risk of this channel (as an outgoing link).
	fn outgoing_in_flight_risk(&self) -> u64 {
		// We only account the in-flight risk for HTLCs that are accountable
		self.pending_htlcs
			.iter()
			.map(|htlc| if htlc.1.outgoing_accountable { htlc.1.in_flight_risk } else { 0 })
			.sum()
	}

	/// Returns whether the outgoing channel's reputation is sufficient to use our protected
	/// bucket.
	///
	/// The outgoing channel's reputation must exceed the revenue this incoming channel has earned
	/// us, after subtracting the risk of all of its in-flight accountable HTLCs plus this one.
	///
	/// Note that in the check, revenue is a [`SmoothedDecayingAverage`] while the reputation
	/// is a [`DecayingAverage`]. This is because revenue is an *estimate* of what the channel
	/// typically earns us over a [`revenue_window`] (2 weeks). In order to protect against
	/// shocks or potentially attacker-induced bursts of traffic, we track it across several
	/// windows to then get the 2-week average. The warmup correction also serves to keep the
	/// estimate reasonable while the average is filling up.
	///
	/// Reputation, on the other hand, is not an estimate. It is the fees actually paid over
	/// the outgoing channel so we use a [`DecayingAverage`] with no smoothing. This means
	/// that a channel's reputation has no "correction" applied to it, so for newer channels it
	/// could be slightly more difficult to have reputation if it needs to get into the protected
	/// bucket. This is intended since newer channels should build reputation and as it keeps
	/// forwarding over time, the `DecayingAverage` will track the history of the channel.
	///
	/// [`revenue_window`]: ResourceManagerConfig::revenue_window
	fn sufficient_reputation(
		&self, outgoing_channel: &Channel, in_flight_htlc_risk: u64, at_timestamp: u64,
	) -> bool {
		let outgoing_reputation =
			outgoing_channel.outgoing_reputation.value_at_timestamp(at_timestamp);
		let incoming_revenue_threshold = self.incoming_revenue.value_at_timestamp(at_timestamp);
		let outgoing_channel_in_flight_risk = outgoing_channel.outgoing_in_flight_risk();

		outgoing_reputation
			.saturating_sub(i64::try_from(outgoing_channel_in_flight_risk).unwrap_or(i64::MAX))
			.saturating_sub(i64::try_from(in_flight_htlc_risk).unwrap_or(i64::MAX))
			>= incoming_revenue_threshold
	}
}

/// An implementation for managing channel resources and informing HTLC forwarding decisions. It
/// implements the core of the mitigation as proposed in <https://github.com/lightning/bolts/pull/1280>.
pub(crate) struct ResourceManager {
	config: ResourceManagerConfig,
	/// A salt used to generate per-channel general bucket slots.
	node_salt: [u8; 32],
	channels: Mutex<HashMap<ChannelId, Channel>>,
}

impl ResourceManager {
	pub(crate) fn new<ES: EntropySource>(
		config: ResourceManagerConfig, entropy_source: &ES,
	) -> Result<Self, ()> {
		config.validate()?;
		Ok(ResourceManager {
			config,
			node_salt: entropy_source.get_secure_random_bytes(),
			channels: Mutex::new(new_hash_map()),
		})
	}

	/// The worst-case reputation cost of an in-flight HTLC: the [`Self::opportunity_cost`] it would
	/// incur if the peer held it for the maximum time it can, i.e. until its incoming CLTV expiry.
	///
	/// This is subtracted from an outgoing channel's reputation for as long as the HTLC is in
	/// flight (see [`Channel::sufficient_reputation`]). Once resolved, the actual cost replaces
	/// this bound via [`Self::effective_fees`].
	///
	/// Block times are assumed to be 10 minutes when converting the remaining CLTV delta to a
	/// duration.
	///
	/// [`Channel::sufficient_reputation`]: Channel::sufficient_reputation
	fn htlc_in_flight_risk(&self, fee: u64, incoming_cltv_expiry: u32, height_added: u32) -> u64 {
		let maximum_hold_time = (incoming_cltv_expiry.saturating_sub(height_added)) * 10 * 60;
		self.opportunity_cost(Duration::from_secs(maximum_hold_time as u64), fee)
	}

	/// The cost of an HTLC occupying resources for `resolution_time`. Calculation:
	/// cost = max(0, (resolution_time - resolution_period) / resolution_period) * fee_msat
	fn opportunity_cost(&self, resolution_time: Duration, fee_msat: u64) -> u64 {
		// Computed using f64 as a linear function of how far resolution_time exceeds the
		// acceptable resolution_period, scaled by the fee. This is done instead of stepwise at
		// each resolution_period multiple because a stepwise function could possibly allow an
		// attacker to hold HTLCs just under the acceptable resolution_period without incurring
		// any cost but causing the next hop slower's resolution to get fully penalized by the
		// fee.
		let resolution_period = self.config.resolution_period.as_secs_f64();
		let opportunity_cost = roundf64(
			f64::max(
				0_f64,
				(resolution_time.as_secs_f64() - resolution_period) / resolution_period,
			) * fee_msat as f64,
		);

		opportunity_cost as u64
	}

	/// The value to add to the outgoing channel's reputation for a resolved HTLC.
	///
	/// Accountable and unaccountable HTLCs are treated asymmetrically:
	///
	/// | accountable | settled | value                    |
	/// |-------------|---------|--------------------------|
	/// | yes         | yes     | `fee - opportunity_cost` |
	/// | yes         | no      | `-opportunity_cost`      |
	/// | no          | yes     | `fee` if resolved within the resolution period, else `0` |
	/// | no          | no      | `0`                      |
	///
	/// Only accountable HTLCs can lower reputation; unaccountable ones can only raise it, and only
	/// on prompt success.
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
	pub(crate) fn add_channel(
		&self, channel_id: ChannelId, max_htlc_value_in_flight_msat: u64, max_accepted_htlcs: u16,
		timestamp_unix_secs: u64,
	) -> Result<(), ()> {
		if max_accepted_htlcs > 483
			|| max_htlc_value_in_flight_msat >= TOTAL_BITCOIN_SUPPLY_SATOSHIS * 1000
		{
			return Err(());
		}

		if max_accepted_htlcs < min_accepted_htlcs(self.config.general_allocation_pct)
			|| max_htlc_value_in_flight_msat < MIN_MAX_IN_FLIGHT_MSAT
		{
			return Err(());
		}

		let mut channels_lock = self.channels.lock().unwrap();
		match channels_lock.entry(channel_id) {
			Entry::Vacant(entry) => {
				let channel = Channel::new(
					channel_id,
					&self.node_salt,
					&self.config,
					max_accepted_htlcs,
					max_htlc_value_in_flight_msat,
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
	pub(crate) fn remove_channel(&self, channel_id: ChannelId) -> Result<(), ()> {
		let mut channels_lock = self.channels.lock().unwrap();

		// If the channel has pending HTLCs, it is soft-deleted and will be fully removed once
		// all its pending HTLCs have been resolved.
		if channels_lock.get(&channel_id).ok_or(())?.pending_htlcs.is_empty()
			&& !channels_lock.iter().any(|channel| {
				channel
					.1
					.pending_htlcs
					.iter()
					.any(|pending_htlc| pending_htlc.0.incoming_channel_id == channel_id)
			}) {
			// If the channel had no pending HTLCs, we can remove it.
			channels_lock.remove(&channel_id);
		} else {
			let channel = channels_lock.get_mut(&channel_id).ok_or(())?;
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
	pub(crate) fn add_htlc(
		&self, incoming_channel_id: ChannelId, incoming_amount_msat: u64,
		incoming_cltv_expiry: u32, outgoing_channel_id: ChannelId, outgoing_amount_msat: u64,
		incoming_accountable: bool, htlc_id: u64, height_added: u32, added_at: u64,
	) -> Result<ForwardingOutcome, ()> {
		if (outgoing_amount_msat > incoming_amount_msat) || (height_added >= incoming_cltv_expiry) {
			return Err(());
		}
		// A forward over the same channel is allowed by the protocol but this is somewhat
		// strange behavior and there is no good reason to allow it. When integrating
		// into the ChannelManager, we can return a specific error type for this and the
		// manager can decide to forward it but for reputation and revenue purposes here, we
		// will not track it.
		if incoming_channel_id == outgoing_channel_id {
			return Err(());
		}

		let mut channels_lock = self.channels.lock().unwrap();
		let [Some(incoming_channel), Some(outgoing_channel)] =
                // This method panics if the keys overlap, hence why we also error if channel ids
                // are the same.
		    channels_lock.get_disjoint_mut([&incoming_channel_id, &outgoing_channel_id])
		else {
			return Err(());
		};

		if incoming_channel.closed || outgoing_channel.closed {
			return Err(());
		}

		let htlc_ref = HtlcRef { incoming_channel_id, htlc_id };
		if outgoing_channel.pending_htlcs.get(&htlc_ref).is_some() {
			return Err(());
		}

		let fee = incoming_amount_msat - outgoing_amount_msat;
		let in_flight_htlc_risk = self.htlc_in_flight_risk(fee, incoming_cltv_expiry, height_added);

		let (accountable, bucket_assigned) = if !incoming_accountable {
			if let Some(slots) = incoming_channel
				.incoming_general_bucket
				.available_slots(outgoing_channel_id, incoming_amount_msat)
			{
				(false, BucketAssigned::General(slots))
			} else if incoming_channel.sufficient_reputation(
				outgoing_channel,
				in_flight_htlc_risk,
				added_at,
			) && incoming_channel
				.incoming_protected_bucket
				.resources_available(incoming_amount_msat)
			{
				(true, BucketAssigned::Protected)
			} else if incoming_channel.can_use_incoming_congestion_slot(
				outgoing_channel,
				incoming_amount_msat,
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
				outgoing_channel,
				in_flight_htlc_risk,
				added_at,
			) {
				if incoming_channel
					.incoming_protected_bucket
					.resources_available(incoming_amount_msat)
				{
					(true, BucketAssigned::Protected)
				} else if let Some(slots) = incoming_channel
					.incoming_general_bucket
					.available_slots(outgoing_channel_id, incoming_amount_msat)
				{
					(true, BucketAssigned::General(slots))
				} else {
					return Ok(ForwardingOutcome::Fail);
				}
			} else {
				return Ok(ForwardingOutcome::Fail);
			}
		};

		match &bucket_assigned {
			BucketAssigned::General(slots) => {
				incoming_channel.incoming_general_bucket.add_htlc(slots);
			},
			BucketAssigned::Congestion => {
				incoming_channel.incoming_congestion_bucket.add_htlc(incoming_amount_msat)?;
			},
			BucketAssigned::Protected => {
				incoming_channel.incoming_protected_bucket.add_htlc(incoming_amount_msat)?;
			},
		}

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
	/// [`add_htlc`]: ResourceManager::add_htlc
	pub(crate) fn resolve_htlc(
		&self, incoming_channel_id: ChannelId, htlc_id: u64, outgoing_channel_id: ChannelId,
		settled: bool, resolved_at: u64,
	) {
		let mut channels_lock = self.channels.lock().unwrap();
		let Some(outgoing_channel) = channels_lock.get_mut(&outgoing_channel_id) else {
			debug_assert!(false, "resolved HTLC on an outgoing channel we do not know about");
			return;
		};

		let htlc_ref = HtlcRef { incoming_channel_id, htlc_id };
		let Some(pending_htlc) = outgoing_channel.pending_htlcs.remove(&htlc_ref) else {
			debug_assert!(false, "resolved HTLC that we are not tracking");
			return;
		};

		// Resolution can't happen before the HTLC was added. We still release the bucket resources
		// below, but reputation and revenue are left untouched as they need accurate timestamps.
		debug_assert!(
			resolved_at >= pending_htlc.added_at_unix_seconds,
			"HTLC resolved before it was added"
		);

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

		let Some(incoming_channel) = channels_lock.get_mut(&incoming_channel_id) else {
			debug_assert!(false, "resolved HTLC on an incoming channel we do not know about");
			return;
		};
		let incoming_closed = incoming_channel.closed && incoming_channel.pending_htlcs.is_empty();
		match pending_htlc.bucket {
			BucketAssigned::General(slots) => {
				incoming_channel.incoming_general_bucket.remove_htlc(&slots)
			},
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

				let released = incoming_channel
					.incoming_congestion_bucket
					.remove_htlc(pending_htlc.incoming_amount_msat);
				debug_assert!(
					released.is_ok(),
					"released more congestion resources than were held"
				);
			},
			BucketAssigned::Protected => {
				let released = incoming_channel
					.incoming_protected_bucket
					.remove_htlc(pending_htlc.incoming_amount_msat);
				debug_assert!(released.is_ok(), "released more protected resources than were held");
			},
		}

		if settled && resolved_at >= pending_htlc.added_at_unix_seconds {
			let fee: i64 = i64::try_from(pending_htlc.fee).unwrap_or(i64::MAX);
			incoming_channel.incoming_revenue.add_value(fee, resolved_at);
		}

		let mut remove_channel = |closed: bool, channel_id: ChannelId| {
			// If the channel had been marked as closed and it does not have any other pending
			// HTLCs, it can be fully removed now.
			if closed {
				if !channels_lock.iter().any(|channel| {
					channel
						.1
						.pending_htlcs
						.iter()
						.any(|pending_htlc| pending_htlc.0.incoming_channel_id == channel_id)
				}) {
					channels_lock.remove(&channel_id);
				}
			}
		};
		remove_channel(incoming_closed, incoming_channel_id);
		remove_channel(outgoing_closed, outgoing_channel_id);
	}
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

#[cfg(test)]
mod tests {
	use core::time::Duration;

	use chacha20_poly1305::{chacha20::ChaCha20, Key, Nonce};

	use crate::{
		ln::{
			channel::TOTAL_BITCOIN_SUPPLY_SATOSHIS,
			resource_manager::{
				assign_slots_for_channel, derive_channel_salt, BucketAssigned, BucketResources,
				Channel, DecayingAverage, ForwardingOutcome, GeneralBucket, HtlcRef,
				ResourceManager, ResourceManagerConfig, SmoothedDecayingAverage,
			},
			types::ChannelId,
		},
		sign::EntropySource,
		util::{math::roundf64, test_utils::TestKeysInterface},
	};
	use bitcoin::Network;

	const WINDOW: Duration = Duration::from_secs(2016 * 10 * 60);
	const START_TIME: u64 = 0;

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
		assert_eq!(general_bucket.per_channel_slots, 5);
		assert_eq!(general_bucket.per_slot_msat, 100);

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
		let entropy_source = TestKeysInterface::new(&[0; 32], Network::Testnet);
		Channel::new(
			ChannelId::new_zero(),
			&entropy_source.get_secure_random_bytes(),
			config,
			100,
			100_000_000,
			START_TIME,
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
			// Zero general_allocation_pct
			ResourceManagerConfig { general_allocation_pct: 0, ..Default::default() },
		];

		let entropy_source = TestKeysInterface::new(&[0; 32], Network::Testnet);
		for config in configs {
			assert!(ResourceManager::new(config, &entropy_source).is_err());
		}
	}

	#[test]
	fn test_invalid_add_channel() {
		let entropy_source = TestKeysInterface::new(&[0; 32], Network::Testnet);
		let rm = ResourceManager::new(ResourceManagerConfig::default(), &entropy_source).unwrap();

		// (max_inflight, max_accepted_htlcs)
		let cases: Vec<(u64, u16)> = vec![
			// Invalid max_accepted_htlcs (> 483)
			(100_000_000, 500),
			// Invalid max_htlc_value_in_flight_msat (>= total bitcoin supply)
			(TOTAL_BITCOIN_SUPPLY_SATOSHIS * 1000, 483),
			// Invalid max_accepted_htlcs (< 12)
			(100_000_000, 11),
			// Invalid max_htlc_value_in_flight_msat (< 1000 sats)
			(999_999, 100),
		];

		for (max_inflight, max_htlcs) in cases {
			assert!(rm.add_channel(ChannelId::new_zero(), max_inflight, max_htlcs, 0).is_err());
		}
	}

	#[test]
	fn test_misuse_congestion_bucket() {
		let config = ResourceManagerConfig::default();
		let mut channel = test_channel(&config);
		let misusing_channel = ChannelId([1; 32]);

		assert_eq!(channel.has_misused_congestion(misusing_channel, START_TIME), false);

		channel.misused_congestion(misusing_channel, START_TIME);
		assert_eq!(channel.has_misused_congestion(misusing_channel, START_TIME + 5), true);

		// Congestion misuse is taken into account if the bucket has been misused in the last 2
		// weeks. Test that after 2 weeks since last misuse, it returns that the bucket has not
		// been misused.
		let two_weeks = config.revenue_window.as_secs();
		assert_eq!(channel.has_misused_congestion(misusing_channel, START_TIME + two_weeks), false);
	}

	#[test]
	fn test_opportunity_cost() {
		let config = ResourceManagerConfig::default();
		let entropy_source = TestKeysInterface::new(&[0; 32], Network::Testnet);
		let resource_manager = ResourceManager::new(config, &entropy_source).unwrap();

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

		let entropy_source = TestKeysInterface::new(&[0; 32], Network::Testnet);
		let resource_manager = ResourceManager::new(config, &entropy_source).unwrap();

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

	const INCOMING_CHANNEL_ID: ChannelId = ChannelId([100; 32]);
	const OUTGOING_CHANNEL_ID: ChannelId = ChannelId([200; 32]);
	const INCOMING_CHANNEL_ID_2: ChannelId = ChannelId([101; 32]);
	const OUTGOING_CHANNEL_ID_2: ChannelId = ChannelId([201; 32]);
	const HTLC_AMOUNT: u64 = 10_000_000;
	const FEE_AMOUNT: u64 = 1_000;
	const CURRENT_HEIGHT: u32 = 1000;
	const CLTV_EXPIRY: u32 = 1144;

	fn create_test_resource_manager_with_channel_pairs(n_pairs: u8) -> ResourceManager {
		let config = ResourceManagerConfig::default();
		let entropy_source = TestKeysInterface::new(&[0; 32], Network::Testnet);
		let rm = ResourceManager::new(config, &entropy_source).unwrap();
		for i in 0..n_pairs {
			// The ids of the i-th channel pair, matching INCOMING_CHANNEL_ID and
			// OUTGOING_CHANNEL_ID for i = 0.
			rm.add_channel(ChannelId([100 + i; 32]), 5_000_000_000, 114, START_TIME).unwrap();
			rm.add_channel(ChannelId([200 + i; 32]), 5_000_000_000, 114, START_TIME).unwrap();
		}
		rm
	}

	fn create_test_resource_manager_with_channels() -> ResourceManager {
		create_test_resource_manager_with_channel_pairs(1)
	}

	fn add_test_htlc(
		rm: &ResourceManager, accountable: bool, htlc_id: u64, added_at: Option<u64>,
	) -> Result<ForwardingOutcome, ()> {
		rm.add_htlc(
			INCOMING_CHANNEL_ID,
			HTLC_AMOUNT + FEE_AMOUNT,
			CLTV_EXPIRY,
			OUTGOING_CHANNEL_ID,
			HTLC_AMOUNT,
			accountable,
			htlc_id,
			CURRENT_HEIGHT,
			added_at.unwrap_or(START_TIME),
		)
	}

	fn add_reputation(
		rm: &ResourceManager, outgoing_channel_id: ChannelId, target_reputation: i64,
	) {
		let mut channels = rm.channels.lock().unwrap();
		let outgoing_channel = channels.get_mut(&outgoing_channel_id).unwrap();
		outgoing_channel.outgoing_reputation.add_value(target_reputation, START_TIME);
	}

	fn fill_general_bucket(rm: &ResourceManager, incoming_channel_id: ChannelId) {
		let mut channels = rm.channels.lock().unwrap();
		let incoming_channel = channels.get_mut(&incoming_channel_id).unwrap();
		incoming_channel.incoming_general_bucket.slots_occupied.iter_mut().for_each(|o| *o = true);
	}

	fn fill_congestion_bucket(rm: &ResourceManager, incoming_channel_id: ChannelId) {
		let mut channels = rm.channels.lock().unwrap();
		let incoming_channel = channels.get_mut(&incoming_channel_id).unwrap();
		let slots_allocated = incoming_channel.incoming_congestion_bucket.slots_allocated;
		let liquidity_allocated = incoming_channel.incoming_congestion_bucket.liquidity_allocated;
		incoming_channel.incoming_congestion_bucket.slots_used = slots_allocated;
		incoming_channel.incoming_congestion_bucket.liquidity_used = liquidity_allocated;
	}

	fn fill_protected_bucket(rm: &ResourceManager, incoming_channel_id: ChannelId) {
		let mut channels = rm.channels.lock().unwrap();
		let incoming_channel = channels.get_mut(&incoming_channel_id).unwrap();
		let slots_allocated = incoming_channel.incoming_protected_bucket.slots_allocated;
		let liquidity_allocated = incoming_channel.incoming_protected_bucket.liquidity_allocated;
		incoming_channel.incoming_protected_bucket.slots_used = slots_allocated;
		incoming_channel.incoming_protected_bucket.liquidity_used = liquidity_allocated;
	}

	fn mark_congestion_misused(
		rm: &ResourceManager, incoming_channel_id: ChannelId, outgoing_channel_id: ChannelId,
	) {
		let mut channels = rm.channels.lock().unwrap();
		let incoming_channel = channels.get_mut(&incoming_channel_id).unwrap();
		incoming_channel.misused_congestion(outgoing_channel_id, START_TIME);
	}

	/// A lightweight discriminant of [`BucketAssigned`] for test assertions, since
	/// [`BucketAssigned::General`] now carries its occupied slots and is no longer `Copy`.
	#[derive(PartialEq, Eq, Debug)]
	enum BucketKind {
		General,
		Congestion,
		Protected,
	}

	fn get_htlc_bucket(
		rm: &ResourceManager, incoming_channel_id: ChannelId, htlc_id: u64,
		outgoing_channel_id: ChannelId,
	) -> Option<BucketKind> {
		let channels = rm.channels.lock().unwrap();
		let htlc_ref = HtlcRef { incoming_channel_id, htlc_id };
		let htlc = channels.get(&outgoing_channel_id).unwrap().pending_htlcs.get(&htlc_ref);
		htlc.map(|htlc| match &htlc.bucket {
			BucketAssigned::General(_) => BucketKind::General,
			BucketAssigned::Congestion => BucketKind::Congestion,
			BucketAssigned::Protected => BucketKind::Protected,
		})
	}

	fn count_pending_htlcs(rm: &ResourceManager, outgoing_channel_id: ChannelId) -> usize {
		let channels = rm.channels.lock().unwrap();
		channels.get(&outgoing_channel_id).unwrap().pending_htlcs.len()
	}

	fn assert_general_bucket_slots_used(
		rm: &ResourceManager, incoming_channel_id: ChannelId, outgoing_channel_id: ChannelId,
		expected_count: usize,
	) {
		let channels = rm.channels.lock().unwrap();
		let incoming_general_bucket =
			&channels.get(&incoming_channel_id).unwrap().incoming_general_bucket;
		let outgoing_channel = channels.get(&outgoing_channel_id).unwrap();

		// The slots used by this (incoming, outgoing) pair are recorded on the pending HTLCs that
		// the outgoing channel holds and that arrived over `incoming_channel_id`.
		let mut used_count = 0;
		for (htlc_ref, pending_htlc) in outgoing_channel.pending_htlcs.iter() {
			if htlc_ref.incoming_channel_id != incoming_channel_id {
				continue;
			}
			if let BucketAssigned::General(slots) = &pending_htlc.bucket {
				for slot in slots {
					// Each slot recorded on the HTLC must be occupied in the incoming bucket.
					assert!(incoming_general_bucket.slots_occupied[*slot as usize]);
					used_count += 1;
				}
			}
		}
		assert_eq!(used_count, expected_count);
	}

	fn test_congestion_eligible(rm: &ResourceManager, incoming_htlc_amount: u64) -> bool {
		let mut channels_lock = rm.channels.lock().unwrap();
		let [Some(incoming_channel), Some(outgoing_channel)] =
			channels_lock.get_disjoint_mut([&INCOMING_CHANNEL_ID, &OUTGOING_CHANNEL_ID])
		else {
			panic!("channels not found");
		};

		incoming_channel.can_use_incoming_congestion_slot(
			outgoing_channel,
			incoming_htlc_amount,
			START_TIME,
		)
	}

	#[test]
	fn test_not_congestion_eligible() {
		// Test not congestion eligible for:
		// - Outgoing channel already has HTLC in congestion bucket.
		// - Congestion bucket is full
		// - Congestion bucket was misused
		let cases = vec![
			|rm: &ResourceManager| {
				fill_general_bucket(&rm, INCOMING_CHANNEL_ID);
				let htlc_id = 1;
				add_test_htlc(&rm, false, htlc_id, None).unwrap();
				assert_eq!(
					get_htlc_bucket(&rm, INCOMING_CHANNEL_ID, htlc_id, OUTGOING_CHANNEL_ID)
						.unwrap(),
					BucketKind::Congestion
				);
			},
			|rm: &ResourceManager| {
				fill_congestion_bucket(rm, INCOMING_CHANNEL_ID);
			},
			|rm: &ResourceManager| {
				mark_congestion_misused(rm, INCOMING_CHANNEL_ID, OUTGOING_CHANNEL_ID);
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
		let incoming_channel = channels.get(&INCOMING_CHANNEL_ID).unwrap();
		let slot_limit = incoming_channel.incoming_congestion_bucket.liquidity_allocated
			/ incoming_channel.incoming_congestion_bucket.slots_allocated as u64;
		drop(channels);

		// Try to add HTLC that exceeds the slot limit
		let htlc_amount_over_limit = slot_limit + 1000;
		assert!(!test_congestion_eligible(&rm, htlc_amount_over_limit));
	}

	fn test_sufficient_reputation(rm: &ResourceManager) -> bool {
		let mut channels_lock = rm.channels.lock().unwrap();

		let fee = FEE_AMOUNT;
		let in_flight_htlc_risk = rm.htlc_in_flight_risk(fee, CLTV_EXPIRY, CURRENT_HEIGHT);

		let [Some(incoming_channel), Some(outgoing_channel)] =
			channels_lock.get_disjoint_mut([&INCOMING_CHANNEL_ID, &OUTGOING_CHANNEL_ID])
		else {
			panic!("channels not found");
		};

		incoming_channel.sufficient_reputation(outgoing_channel, in_flight_htlc_risk, START_TIME)
	}

	#[test]
	fn test_insufficient_reputation_outgoing_in_flight_risk() {
		let rm = create_test_resource_manager_with_channels();
		let reputation = 50_000_000;
		add_reputation(&rm, OUTGOING_CHANNEL_ID, reputation);

		// Successfully add unaccountable HTLC that should not count in the outgoing
		// accumulated outgoing in-flight risk.
		assert!(add_test_htlc(&rm, false, 0, None).is_ok());

		let high_cltv_expiry = CURRENT_HEIGHT + 2000;

		// Add accountable HTLC that will add 49_329_633 to the in-flight risk. This is based
		// on the 3700 and CLTV delta added.
		assert!(rm
			.add_htlc(
				INCOMING_CHANNEL_ID,
				HTLC_AMOUNT + 3700,
				high_cltv_expiry,
				OUTGOING_CHANNEL_ID,
				HTLC_AMOUNT,
				true,
				1,
				CURRENT_HEIGHT,
				START_TIME,
			)
			.is_ok());

		// Since we have added an accountable HTLC with in-fligh risk that is close to the
		// reputation we added, the next accountable HTLC we try to add should fail.
		assert_eq!(test_sufficient_reputation(&rm), false);
	}

	#[test]
	fn test_insufficient_reputation_higher_incoming_revenue_threshold() {
		let rm = create_test_resource_manager_with_channels();

		// Give the outgoing channel enough reputation to cover the in-flight risk of the HTLC
		// being evaluated plus a small margin. With no incoming revenue this is sufficient.
		let in_flight_risk = rm.htlc_in_flight_risk(FEE_AMOUNT, CLTV_EXPIRY, CURRENT_HEIGHT);
		let margin = 10_000;
		add_reputation(&rm, OUTGOING_CHANNEL_ID, i64::try_from(in_flight_risk).unwrap() + margin);
		assert_eq!(test_sufficient_reputation(&rm), true);

		// Add revenue to the incoming channel above the margin, so the threshold now exceeds what
		// is left of the outgoing channel's reputation after subtracting the in-flight risk.
		let mut channels = rm.channels.lock().unwrap();
		let incoming_channel = channels.get_mut(&INCOMING_CHANNEL_ID).unwrap();
		incoming_channel.incoming_revenue.add_value(margin * 5, START_TIME);
		drop(channels);

		assert_eq!(test_sufficient_reputation(&rm), false);
	}

	#[test]
	fn test_sufficient_reputation_exactly_at_threshold() {
		let rm = create_test_resource_manager_with_channels();

		let in_flight_risk = rm.htlc_in_flight_risk(FEE_AMOUNT, CLTV_EXPIRY, CURRENT_HEIGHT);
		let mut channels = rm.channels.lock().unwrap();

		// Set incoming revenue threshold
		let threshold = 10_000_000;
		let incoming_channel = channels.get_mut(&INCOMING_CHANNEL_ID).unwrap();
		incoming_channel.incoming_revenue.add_value(threshold, START_TIME);

		// Set outgoing reputation to match threshold plus in-flight risk
		let reputation_needed = threshold + i64::try_from(in_flight_risk).unwrap();
		let outgoing_channel = channels.get_mut(&OUTGOING_CHANNEL_ID).unwrap();
		outgoing_channel.outgoing_reputation.add_value(reputation_needed, START_TIME);
		drop(channels);

		assert_eq!(test_sufficient_reputation(&rm), true);
	}

	#[test]
	fn test_add_htlc_unaccountable_forwarding_decisions() {
		struct TestCase {
			description: &'static str,
			setup: fn(&ResourceManager),
			expected_outcome: ForwardingOutcome,
			expected_bucket: Option<BucketKind>,
		}

		let cases = vec![
			TestCase {
				description: "general bucket available",
				setup: |_rm| {},
				expected_outcome: ForwardingOutcome::Forward(false),
				expected_bucket: Some(BucketKind::General),
			},
			TestCase {
				description: "general full, sufficient reputation goes to protected",
				setup: |rm| {
					add_reputation(rm, OUTGOING_CHANNEL_ID, HTLC_AMOUNT as i64);
					fill_general_bucket(rm, INCOMING_CHANNEL_ID);
				},
				expected_outcome: ForwardingOutcome::Forward(true),
				expected_bucket: Some(BucketKind::Protected),
			},
			TestCase {
				description: "general full, insufficient reputation goes to congestion",
				setup: |rm| fill_general_bucket(rm, INCOMING_CHANNEL_ID),
				expected_outcome: ForwardingOutcome::Forward(true),
				expected_bucket: Some(BucketKind::Congestion),
			},
			TestCase {
				description: "congestion misused recently fails",
				setup: |rm| {
					fill_general_bucket(rm, INCOMING_CHANNEL_ID);
					mark_congestion_misused(rm, INCOMING_CHANNEL_ID, OUTGOING_CHANNEL_ID);
				},
				expected_outcome: ForwardingOutcome::Fail,
				expected_bucket: None,
			},
		];

		let htlc_id = 1;
		for case in cases {
			let rm = create_test_resource_manager_with_channels();
			(case.setup)(&rm);

			let result = add_test_htlc(&rm, false, htlc_id, None);
			assert!(result.is_ok(), "case '{}': add_htlc returned Err", case.description);
			assert_eq!(
				result.unwrap(),
				case.expected_outcome,
				"case '{}': unexpected forwarding outcome",
				case.description
			);
			assert_eq!(
				get_htlc_bucket(&rm, INCOMING_CHANNEL_ID, htlc_id, OUTGOING_CHANNEL_ID),
				case.expected_bucket,
				"case '{}': unexpected bucket assignment",
				case.description
			);
		}
	}

	#[test]
	fn test_add_htlc_unaccountable_congestion_already_has_htlc() {
		let rm = create_test_resource_manager_with_channels();
		fill_general_bucket(&rm, INCOMING_CHANNEL_ID);

		// With general bucket full, adding HTLC here should go to congestion bucket.
		let mut htlc_id = 1;
		let result_1 = add_test_htlc(&rm, false, htlc_id, None);
		assert!(result_1.is_ok());
		assert_eq!(result_1.unwrap(), ForwardingOutcome::Forward(true));
		assert_eq!(
			get_htlc_bucket(&rm, INCOMING_CHANNEL_ID, htlc_id, OUTGOING_CHANNEL_ID).unwrap(),
			BucketKind::Congestion
		);

		// Adding a second HTLC should fail because outgoing channel is already using a slot in
		// the congestion bucket and it does not have sufficient reputation to get into the
		// protected bucket.
		htlc_id = 2;
		let result_2 = add_test_htlc(&rm, false, htlc_id, None);
		assert_eq!(result_2.unwrap(), ForwardingOutcome::Fail);
		assert!(get_htlc_bucket(&rm, INCOMING_CHANNEL_ID, htlc_id, OUTGOING_CHANNEL_ID).is_none());
	}

	#[test]
	fn test_add_htlc_accountable_forwarding_decisions() {
		struct TestCase {
			description: &'static str,
			setup: fn(&ResourceManager),
			expected_outcome: ForwardingOutcome,
			expected_bucket: Option<BucketKind>,
		}

		let cases = vec![
			TestCase {
				description: "sufficient reputation goes to protected",
				setup: |rm| add_reputation(rm, OUTGOING_CHANNEL_ID, HTLC_AMOUNT as i64),
				expected_outcome: ForwardingOutcome::Forward(true),
				expected_bucket: Some(BucketKind::Protected),
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
					add_reputation(rm, OUTGOING_CHANNEL_ID, HTLC_AMOUNT as i64);
					fill_protected_bucket(rm, INCOMING_CHANNEL_ID);
				},
				expected_outcome: ForwardingOutcome::Forward(true),
				expected_bucket: Some(BucketKind::General),
			},
			TestCase {
				description: "sufficient reputation, protected and general full, fails",
				setup: |rm| {
					add_reputation(rm, OUTGOING_CHANNEL_ID, HTLC_AMOUNT as i64);
					fill_general_bucket(rm, INCOMING_CHANNEL_ID);
					fill_protected_bucket(rm, INCOMING_CHANNEL_ID);
				},
				expected_outcome: ForwardingOutcome::Fail,
				expected_bucket: None,
			},
		];

		let htlc_id = 1;

		for case in cases {
			let rm = create_test_resource_manager_with_channels();
			(case.setup)(&rm);

			let result = add_test_htlc(&rm, true, htlc_id, None);
			assert!(result.is_ok(), "case '{}': add_htlc returned Err", case.description);
			assert_eq!(
				result.unwrap(),
				case.expected_outcome,
				"case '{}': unexpected forwarding outcome",
				case.description
			);
			assert_eq!(
				get_htlc_bucket(&rm, INCOMING_CHANNEL_ID, htlc_id, OUTGOING_CHANNEL_ID),
				case.expected_bucket,
				"case '{}': unexpected bucket assignment",
				case.description
			);
		}
	}

	#[test]
	fn test_add_htlc_stores_correct_pending_htlc_data() {
		let rm = create_test_resource_manager_with_channels();

		let htlc_id = 42;
		let result = rm.add_htlc(
			INCOMING_CHANNEL_ID,
			HTLC_AMOUNT + FEE_AMOUNT,
			CLTV_EXPIRY,
			OUTGOING_CHANNEL_ID,
			HTLC_AMOUNT,
			false,
			htlc_id,
			CURRENT_HEIGHT,
			START_TIME,
		);
		assert!(result.is_ok());

		let channels = rm.channels.lock().unwrap();
		let htlc_ref = HtlcRef { incoming_channel_id: INCOMING_CHANNEL_ID, htlc_id };
		let pending_htlc = channels.get(&OUTGOING_CHANNEL_ID).unwrap().pending_htlcs.get(&htlc_ref);
		assert!(pending_htlc.is_some());
		// HTLC should only get added to pending list for outgoing channel
		assert!(channels.get(&INCOMING_CHANNEL_ID).unwrap().pending_htlcs.get(&htlc_ref).is_none());

		let pending_htlc = pending_htlc.unwrap();
		assert_eq!(pending_htlc.incoming_amount_msat, HTLC_AMOUNT + FEE_AMOUNT);
		assert_eq!(pending_htlc.fee, FEE_AMOUNT);
		assert_eq!(pending_htlc.added_at_unix_seconds, START_TIME);

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

		for case in &cases {
			let rm = create_test_resource_manager_with_channels();
			let htlc_id = 1;

			assert_eq!(
				add_test_htlc(&rm, false, htlc_id, None).unwrap(),
				ForwardingOutcome::Forward(false),
			);

			let resolved_at = START_TIME + case.hold_time.as_secs();
			rm.resolve_htlc(
				INCOMING_CHANNEL_ID,
				htlc_id,
				OUTGOING_CHANNEL_ID,
				case.settled,
				resolved_at,
			);

			let channels = rm.channels.lock().unwrap();
			assert_eq!(
				channels.get(&OUTGOING_CHANNEL_ID).unwrap().outgoing_reputation.value,
				case.expected_reputation,
			);
			assert_eq!(
				channels
					.get(&INCOMING_CHANNEL_ID)
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
		let config = ResourceManagerConfig::default();
		let fast_resolve = config.resolution_period / 2;
		let slow_resolve = config.resolution_period * 3;

		let rm = create_test_resource_manager_with_channels();
		fill_general_bucket(&rm, INCOMING_CHANNEL_ID);
		let mut htlc_id = 1;
		assert_eq!(
			add_test_htlc(&rm, false, htlc_id, None).unwrap(),
			ForwardingOutcome::Forward(true),
		);
		assert_eq!(
			get_htlc_bucket(&rm, INCOMING_CHANNEL_ID, htlc_id, OUTGOING_CHANNEL_ID).unwrap(),
			BucketKind::Congestion,
		);

		let resolved_at = START_TIME + fast_resolve.as_secs();
		rm.resolve_htlc(INCOMING_CHANNEL_ID, htlc_id, OUTGOING_CHANNEL_ID, false, resolved_at);

		let mut channels = rm.channels.lock().unwrap();
		let incoming = channels.get_mut(&INCOMING_CHANNEL_ID).unwrap();

		// The HTLC in congestion bucket resolved fast so it does not count as having misused the
		// congestion bucket.
		assert!(!incoming.has_misused_congestion(OUTGOING_CHANNEL_ID, resolved_at));
		assert_eq!(incoming.incoming_congestion_bucket.slots_used, 0);

		drop(channels);

		// Since it does not count as congestion misused, this HTLC can be added to congestion
		htlc_id += 1;
		let added_at = resolved_at;
		assert_eq!(
			add_test_htlc(&rm, false, htlc_id, Some(added_at)).unwrap(),
			ForwardingOutcome::Forward(true),
		);
		assert_eq!(
			get_htlc_bucket(&rm, INCOMING_CHANNEL_ID, htlc_id, OUTGOING_CHANNEL_ID).unwrap(),
			BucketKind::Congestion,
		);

		// Slow resolution
		let resolved_at = added_at + slow_resolve.as_secs();
		rm.resolve_htlc(INCOMING_CHANNEL_ID, htlc_id, OUTGOING_CHANNEL_ID, false, resolved_at);

		let mut channels = rm.channels.lock().unwrap();
		let incoming = channels.get_mut(&INCOMING_CHANNEL_ID).unwrap();

		// The HTLC in congestion bucket resolved slowly so it does count as having misused the
		// congestion bucket.
		assert!(incoming.has_misused_congestion(OUTGOING_CHANNEL_ID, resolved_at));

		drop(channels);

		// Congestion was misused so trying to add an HTLC should fail because the channel does
		// not have reputation to get into protected.
		htlc_id += 1;
		let added_at = resolved_at;
		assert_eq!(
			add_test_htlc(&rm, false, htlc_id, Some(added_at)).unwrap(),
			ForwardingOutcome::Fail,
		);

		// After two weeks the misuse has expired, so the congestion bucket is available again.
		let after_two_weeks = added_at + config.revenue_window.as_secs();
		htlc_id += 1;
		assert_eq!(
			add_test_htlc(&rm, false, htlc_id, Some(after_two_weeks)).unwrap(),
			ForwardingOutcome::Forward(true),
		);
		assert_eq!(
			get_htlc_bucket(&rm, INCOMING_CHANNEL_ID, htlc_id, OUTGOING_CHANNEL_ID).unwrap(),
			BucketKind::Congestion,
		);

		// Checking the expired entry during that forward should have removed it.
		let channels = rm.channels.lock().unwrap();
		let incoming = channels.get(&INCOMING_CHANNEL_ID).unwrap();
		assert!(incoming.last_congestion_misuse.get(&OUTGOING_CHANNEL_ID).is_none());
	}

	#[test]
	fn test_resolve_htlc_accountable_outcomes() {
		let rm = create_test_resource_manager_with_channels();
		let fast_resolve = rm.config.resolution_period / 2;
		let accountable = true;

		add_reputation(&rm, OUTGOING_CHANNEL_ID, HTLC_AMOUNT as i64);

		let mut htlc_id = 1;
		let added_at = START_TIME;
		assert_eq!(
			add_test_htlc(&rm, accountable, htlc_id, Some(added_at)).unwrap(),
			ForwardingOutcome::Forward(true),
		);
		assert_eq!(
			get_htlc_bucket(&rm, INCOMING_CHANNEL_ID, htlc_id, OUTGOING_CHANNEL_ID).unwrap(),
			BucketKind::Protected,
		);

		let get_reputation = |at_timestamp: u64| -> i64 {
			let mut channels = rm.channels.lock().unwrap();
			channels
				.get_mut(&OUTGOING_CHANNEL_ID)
				.unwrap()
				.outgoing_reputation
				.value_at_timestamp(at_timestamp)
		};

		// Check fast settled resolution adds to reputation
		let resolved_at = added_at + fast_resolve.as_secs();
		let current_rep = get_reputation(resolved_at);

		rm.resolve_htlc(INCOMING_CHANNEL_ID, htlc_id, OUTGOING_CHANNEL_ID, true, resolved_at);

		let reputation_after_fast_resolve = get_reputation(resolved_at);
		assert_eq!(reputation_after_fast_resolve, (current_rep + FEE_AMOUNT as i64));

		let mut channels = rm.channels.lock().unwrap();
		let revenue = channels
			.get_mut(&INCOMING_CHANNEL_ID)
			.unwrap()
			.incoming_revenue
			.value_at_timestamp(resolved_at);
		assert_eq!(revenue, FEE_AMOUNT as i64,);
		drop(channels);

		// Fast failing accountable HTLC does not affect reputation
		htlc_id += 1;
		let added_at = resolved_at;
		assert_eq!(
			add_test_htlc(&rm, accountable, htlc_id, Some(added_at)).unwrap(),
			ForwardingOutcome::Forward(true),
		);
		assert_eq!(
			get_htlc_bucket(&rm, INCOMING_CHANNEL_ID, htlc_id, OUTGOING_CHANNEL_ID).unwrap(),
			BucketKind::Protected,
		);

		let resolved_at = added_at + fast_resolve.as_secs();
		let reputation_before_resolve = get_reputation(resolved_at);

		rm.resolve_htlc(INCOMING_CHANNEL_ID, htlc_id, OUTGOING_CHANNEL_ID, false, resolved_at);

		assert_eq!(get_reputation(resolved_at), reputation_before_resolve);

		// Slow resolution should decrease reputation by effective fee
		let slow_resolve = rm.config.resolution_period * 10;
		let added_at = resolved_at;
		assert_eq!(
			add_test_htlc(&rm, accountable, htlc_id, Some(added_at)).unwrap(),
			ForwardingOutcome::Forward(true),
		);
		assert_eq!(
			get_htlc_bucket(&rm, INCOMING_CHANNEL_ID, htlc_id, OUTGOING_CHANNEL_ID).unwrap(),
			BucketKind::Protected,
		);

		let resolved_at = added_at + slow_resolve.as_secs();
		let reputation_before_slow_resolve = get_reputation(resolved_at);
		let effective_fee_slow_resolve = rm.effective_fees(FEE_AMOUNT, slow_resolve, true, true);
		rm.resolve_htlc(INCOMING_CHANNEL_ID, htlc_id, OUTGOING_CHANNEL_ID, true, resolved_at);
		let reputation_after_slow_resolve = get_reputation(resolved_at);

		assert_eq!(
			reputation_after_slow_resolve,
			reputation_before_slow_resolve + effective_fee_slow_resolve
		);
	}

	#[test]
	fn test_multi_channel_general_bucket_saturation_flow() {
		let rm = create_test_resource_manager_with_channel_pairs(2);

		// Fill general bucket (it should have been assigned 5 slots)
		let mut htlc_ids = Vec::new();
		for i in 1..=5 {
			let result = add_test_htlc(&rm, false, i, None);
			assert!(result.is_ok());
			assert_eq!(result.unwrap(), ForwardingOutcome::Forward(false));
			assert_eq!(
				get_htlc_bucket(&rm, INCOMING_CHANNEL_ID, i, OUTGOING_CHANNEL_ID).unwrap(),
				BucketKind::General
			);
			htlc_ids.push(i);
		}
		assert_general_bucket_slots_used(&rm, INCOMING_CHANNEL_ID, OUTGOING_CHANNEL_ID, 5);

		// With the 5 slots in the general bucket used, the 6th HTLC goes to congestion
		let result = add_test_htlc(&rm, false, 6, None);
		assert!(result.is_ok());
		assert_eq!(result.unwrap(), ForwardingOutcome::Forward(true));
		assert_eq!(
			get_htlc_bucket(&rm, INCOMING_CHANNEL_ID, 6, OUTGOING_CHANNEL_ID).unwrap(),
			BucketKind::Congestion
		);

		// 7th HTLC fails because it is already using a congestion slot and channel does not
		// have sufficient reputation to get into protected bucket.
		let result = add_test_htlc(&rm, false, 7, None);
		assert_eq!(result.unwrap(), ForwardingOutcome::Fail);
		assert!(get_htlc_bucket(&rm, INCOMING_CHANNEL_ID, 7, OUTGOING_CHANNEL_ID).is_none());

		// Resolve 3 HTLCs that were assigned to the general bucket. It should end up with 2 in
		// general and one in congestion.
		let resolved_at = START_TIME;
		rm.resolve_htlc(INCOMING_CHANNEL_ID, htlc_ids[0], OUTGOING_CHANNEL_ID, true, resolved_at);
		rm.resolve_htlc(INCOMING_CHANNEL_ID, htlc_ids[2], OUTGOING_CHANNEL_ID, true, resolved_at);
		rm.resolve_htlc(INCOMING_CHANNEL_ID, htlc_ids[4], OUTGOING_CHANNEL_ID, true, resolved_at);
		assert_general_bucket_slots_used(&rm, INCOMING_CHANNEL_ID, OUTGOING_CHANNEL_ID, 2);
		assert_eq!(count_pending_htlcs(&rm, OUTGOING_CHANNEL_ID), 3);

		// Adding more HTLCs should now use the freed general slots.
		for i in 8..=10 {
			let result = add_test_htlc(&rm, false, i, None);
			assert!(result.is_ok());
			assert_eq!(result.unwrap(), ForwardingOutcome::Forward(false));
			assert_eq!(
				get_htlc_bucket(&rm, INCOMING_CHANNEL_ID, i, OUTGOING_CHANNEL_ID).unwrap(),
				BucketKind::General
			);
		}
		assert_general_bucket_slots_used(&rm, INCOMING_CHANNEL_ID, OUTGOING_CHANNEL_ID, 5);

		// Adding HTLCs to a different outgoing channel should use its own slots. Some
		// slots may conflict with OUTGOING_CHANNEL_ID's assigned slots, so we check how many
		// are actually available.
		let conflicting_slots = {
			let channels = rm.channels.lock().unwrap();
			let general_bucket =
				&channels.get(&INCOMING_CHANNEL_ID).unwrap().incoming_general_bucket;
			// Derive each outgoing channel's assigned slots the same way the bucket does, and
			// count the overlap between the two assignments.
			let assign = |outgoing_channel_id: ChannelId| {
				let salt = derive_channel_salt(&rm.node_salt, general_bucket.channel_id);
				assign_slots_for_channel(
					general_bucket.channel_id,
					outgoing_channel_id,
					salt,
					general_bucket.per_channel_slots,
					general_bucket.total_slots,
				)
			};
			let slots_1 = assign(OUTGOING_CHANNEL_ID);
			let slots_2 = assign(OUTGOING_CHANNEL_ID_2);
			slots_2.iter().filter(|s| slots_1.contains(s)).count()
		};

		let available_slots = 5 - conflicting_slots;
		for i in 11..11 + available_slots as u64 {
			let result = rm.add_htlc(
				INCOMING_CHANNEL_ID,
				HTLC_AMOUNT + FEE_AMOUNT,
				CLTV_EXPIRY,
				OUTGOING_CHANNEL_ID_2,
				HTLC_AMOUNT,
				false,
				i,
				CURRENT_HEIGHT,
				START_TIME,
			);
			assert!(result.is_ok());
			assert_eq!(
				get_htlc_bucket(&rm, INCOMING_CHANNEL_ID, i, OUTGOING_CHANNEL_ID_2).unwrap(),
				BucketKind::General
			);
		}
		assert_general_bucket_slots_used(
			&rm,
			INCOMING_CHANNEL_ID,
			OUTGOING_CHANNEL_ID_2,
			available_slots,
		);

		// Different incoming uses its own bucket
		for i in 12 + available_slots as u64..=20 {
			let result = rm.add_htlc(
				INCOMING_CHANNEL_ID_2,
				HTLC_AMOUNT + FEE_AMOUNT,
				CLTV_EXPIRY,
				OUTGOING_CHANNEL_ID,
				HTLC_AMOUNT,
				false,
				i,
				CURRENT_HEIGHT,
				START_TIME,
			);
			assert!(result.is_ok());
			assert_eq!(
				get_htlc_bucket(&rm, INCOMING_CHANNEL_ID_2, i, OUTGOING_CHANNEL_ID).unwrap(),
				BucketKind::General
			);
		}

		// Verify original channel pair still has 5 slots used
		assert_general_bucket_slots_used(&rm, INCOMING_CHANNEL_ID, OUTGOING_CHANNEL_ID, 5);
	}

	#[test]
	fn test_multi_channel_bucket_fallback_with_earned_reputation() {
		let rm = create_test_resource_manager_with_channel_pairs(2);

		let add_htlc_between = |incoming_channel_id: ChannelId,
		                        outgoing_channel_id: ChannelId,
		                        accountable: bool,
		                        htlc_id: u64| {
			rm.add_htlc(
				incoming_channel_id,
				HTLC_AMOUNT + FEE_AMOUNT,
				CLTV_EXPIRY,
				outgoing_channel_id,
				HTLC_AMOUNT,
				accountable,
				htlc_id,
				CURRENT_HEIGHT,
				START_TIME,
			)
		};

		// Build a revenue threshold of 5000 on INCOMING_CHANNEL_ID.
		for i in 1..=5_u64 {
			assert_eq!(
				add_htlc_between(INCOMING_CHANNEL_ID, OUTGOING_CHANNEL_ID_2, false, i).unwrap(),
				ForwardingOutcome::Forward(false),
			);
			rm.resolve_htlc(INCOMING_CHANNEL_ID, i, OUTGOING_CHANNEL_ID_2, true, START_TIME);
		}

		let saturate_into_congestion = |outgoing_channel_id: ChannelId, mut htlc_id: u64| -> u64 {
			loop {
				let outcome =
					add_htlc_between(INCOMING_CHANNEL_ID, outgoing_channel_id, false, htlc_id)
						.unwrap();
				let bucket =
					get_htlc_bucket(&rm, INCOMING_CHANNEL_ID, htlc_id, outgoing_channel_id)
						.unwrap();
				htlc_id += 1;
				if outcome == ForwardingOutcome::Forward(true) {
					assert_eq!(bucket, BucketKind::Congestion);
					break;
				}
				assert_eq!(bucket, BucketKind::General);
			}
			htlc_id
		};

		let mut htlc_id = 6_u64;
		htlc_id = saturate_into_congestion(OUTGOING_CHANNEL_ID, htlc_id);
		htlc_id = saturate_into_congestion(OUTGOING_CHANNEL_ID_2, htlc_id);

		// Build reputation for OUTGOING_CHANNEL_ID channel but not for OUTGOING_CHANNEL_ID_2.
		let rep_fee = 200_000_u64;
		let rep_htlc_amount = 1_000_000_u64;
		for i in htlc_id..htlc_id + 10 {
			assert_eq!(
				rm.add_htlc(
					INCOMING_CHANNEL_ID_2,
					rep_htlc_amount + rep_fee,
					CLTV_EXPIRY,
					OUTGOING_CHANNEL_ID,
					rep_htlc_amount,
					false,
					i,
					CURRENT_HEIGHT,
					START_TIME,
				)
				.unwrap(),
				ForwardingOutcome::Forward(false),
			);
			rm.resolve_htlc(INCOMING_CHANNEL_ID_2, i, OUTGOING_CHANNEL_ID, true, START_TIME);
		}
		htlc_id += 10;

		// Accountable HTLC forwarding decisions diverge based on earned reputation.
		//
		// - OUTGOING_CHANNEL_ID has reputation so accountable HTLC will get access to protected
		// bucket.
		// - OUTGOING_CHANNEL_ID_2 does not have reputation so it should fail.
		assert_eq!(
			add_htlc_between(INCOMING_CHANNEL_ID, OUTGOING_CHANNEL_ID, true, htlc_id).unwrap(),
			ForwardingOutcome::Forward(true),
		);
		assert_eq!(
			get_htlc_bucket(&rm, INCOMING_CHANNEL_ID, htlc_id, OUTGOING_CHANNEL_ID).unwrap(),
			BucketKind::Protected,
		);
		htlc_id += 1;

		assert_eq!(
			add_htlc_between(INCOMING_CHANNEL_ID, OUTGOING_CHANNEL_ID_2, true, htlc_id).unwrap(),
			ForwardingOutcome::Fail,
		);
		assert!(get_htlc_bucket(&rm, INCOMING_CHANNEL_ID, htlc_id, OUTGOING_CHANNEL_ID_2).is_none());
	}

	#[test]
	fn test_remove_channel_no_pending_htlcs() {
		let rm = create_test_resource_manager_with_channels();
		let channels = rm.channels.lock().unwrap();
		assert!(channels.get(&OUTGOING_CHANNEL_ID).is_some());
		drop(channels);

		rm.remove_channel(OUTGOING_CHANNEL_ID).unwrap();

		let channels = rm.channels.lock().unwrap();
		assert!(channels.get(&OUTGOING_CHANNEL_ID).is_none());
	}

	#[test]
	fn test_resolve_htlc_after_channel_close() {
		let rm = create_test_resource_manager_with_channel_pairs(2);

		let added_at = START_TIME;

		// HTLC 1: INCOMING_CHANNEL_ID (100) -> OUTGOING_CHANNEL_ID (200)
		assert_eq!(
			add_test_htlc(&rm, false, 1, Some(added_at)).unwrap(),
			ForwardingOutcome::Forward(false),
		);

		// HTLC 2: INCOMING_CHANNEL_ID_2 (101) -> OUTGOING_CHANNEL_ID_2 (201)
		assert_eq!(
			rm.add_htlc(
				INCOMING_CHANNEL_ID_2,
				HTLC_AMOUNT + FEE_AMOUNT,
				CLTV_EXPIRY,
				OUTGOING_CHANNEL_ID_2,
				HTLC_AMOUNT,
				false,
				1,
				CURRENT_HEIGHT,
				added_at,
			)
			.unwrap(),
			ForwardingOutcome::Forward(false),
		);

		// Close the outgoing channel for HTLC 1. It has a pending HTLC so it is soft-deleted.
		rm.remove_channel(OUTGOING_CHANNEL_ID).unwrap();
		{
			let channels = rm.channels.lock().unwrap();
			let outgoing = channels.get(&OUTGOING_CHANNEL_ID).unwrap();
			assert!(outgoing.closed);
			assert_eq!(outgoing.pending_htlcs.len(), 1);
		}

		// Close the incoming channel for HTLC 2. It is referenced as incoming by an HTLC on
		// OUTGOING_CHANNEL_ID_2, so it is soft-deleted.
		rm.remove_channel(INCOMING_CHANNEL_ID_2).unwrap();
		{
			let channels = rm.channels.lock().unwrap();
			let incoming = channels.get(&INCOMING_CHANNEL_ID_2).unwrap();
			assert!(incoming.closed);
		}

		// New HTLCs should be rejected on closed channels.
		assert!(add_test_htlc(&rm, false, 2, None).is_err());
		assert!(rm
			.add_htlc(
				INCOMING_CHANNEL_ID_2,
				HTLC_AMOUNT + FEE_AMOUNT,
				CLTV_EXPIRY,
				OUTGOING_CHANNEL_ID_2,
				HTLC_AMOUNT,
				false,
				2,
				CURRENT_HEIGHT,
				added_at,
			)
			.is_err());

		let resolved_at = added_at + 10;

		// Resolve HTLC 1. Outgoing channel (200) is closed and now has no pending HTLCs,
		// so it is fully removed. Incoming channel (100) gets revenue updated.
		rm.resolve_htlc(INCOMING_CHANNEL_ID, 1, OUTGOING_CHANNEL_ID, true, resolved_at);
		{
			let channels = rm.channels.lock().unwrap();
			assert!(channels.get(&OUTGOING_CHANNEL_ID).is_none());
			let incoming = channels.get(&INCOMING_CHANNEL_ID).unwrap();
			assert_eq!(
				incoming.incoming_revenue.aggregated_decaying_average.value,
				FEE_AMOUNT as i64,
			);
		}

		// Resolve HTLC 2. Incoming channel (101) is closed and has no pending HTLCs or
		// incoming references remaining, so it is fully removed. Outgoing channel (201)
		// gets reputation updated.
		rm.resolve_htlc(INCOMING_CHANNEL_ID_2, 1, OUTGOING_CHANNEL_ID_2, true, resolved_at);
		{
			let channels = rm.channels.lock().unwrap();
			assert!(channels.get(&INCOMING_CHANNEL_ID_2).is_none());
			let outgoing = channels.get(&OUTGOING_CHANNEL_ID_2).unwrap();
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
				roundf64(window_sums.iter().sum::<i64>() as f64 / window_sums.len() as f64) as i64
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
