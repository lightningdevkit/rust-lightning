// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Fuzz harness for the [`ResourceManager`].
//!
//! Interprets the fuzz input as a sequence of operations (add/remove channel, add/resolve HTLC,
//! advance time/height) driven against a [`ResourceManager`], while mirroring the expected state
//! in a shadow model. After every operation, [`check_invariants`] verifies the manager's
//! internal state against the model.
//!
//! This module lives inside the crate (rather than in the `fuzz` crate) so it can read the
//! private state needed for these checks without widening the module's visibility.

use super::{
	assign_slots_for_channel, min_accepted_htlcs, BucketAssigned, ForwardingOutcome, HtlcRef,
	ResourceManager, ResourceManagerConfig, MIN_MAX_IN_FLIGHT_MSAT,
};
use crate::{
	ln::{
		channel::TOTAL_BITCOIN_SUPPLY_SATOSHIS, channelmanager::CLTV_FAR_FAR_AWAY, types::ChannelId,
	},
	prelude::{new_hash_map, HashMap, Vec},
	sign::EntropySource,
};
use core::time::Duration;

const TWO_WEEKS_SECS: u64 = 2016 * 10 * 60;

struct FixedEntropy;
impl EntropySource for FixedEntropy {
	fn get_secure_random_bytes(&self) -> [u8; 32] {
		[42; 32]
	}
}

struct InputReader<'a> {
	data: &'a [u8],
	pos: usize,
}

impl<'a> InputReader<'a> {
	fn u8(&mut self) -> Option<u8> {
		let b = *self.data.get(self.pos)?;
		self.pos += 1;
		Some(b)
	}

	fn u16(&mut self) -> Option<u16> {
		Some(u16::from_le_bytes([self.u8()?, self.u8()?]))
	}

	fn u32(&mut self) -> Option<u32> {
		Some(u32::from_le_bytes([self.u8()?, self.u8()?, self.u8()?, self.u8()?]))
	}
}

/// Mantissa/shift encoding (24 mantissa bits, shift up to 38) so a small input mutation can
/// produce anything from single msats to amounts above the total bitcoin supply.
fn amount_msat(v: u32) -> u64 {
	((v & 0x00ff_ffff) as u64) << ((v >> 24) % 39)
}

/// Mantissa/shift encoding covering zero to ~4 years so decaying average windows get exercised.
fn delta_secs(v: u16) -> u64 {
	((v & 0x0fff) as u64) << (v >> 12)
}

/// Channels get ids from a small space so the fuzzer naturally hits reuse, unknown channels and
/// same-channel forwards.
fn channel_id(idx: u8) -> ChannelId {
	ChannelId([idx % 8 + 1; 32])
}

struct ModelChannel {
	max_accepted_htlcs: u16,
	max_in_flight_msat: u64,
	closed: bool,
}

struct ModelHtlc {
	incoming_channel_id: ChannelId,
	outgoing_channel_id: ChannelId,
	htlc_id: u64,
	incoming_amount_msat: u64,
	fee: u64,
	outgoing_accountable: bool,
	bucket: BucketAssigned,
	added_at: u64,
}

struct Model {
	channels: HashMap<ChannelId, ModelChannel>,
	pending: Vec<ModelHtlc>,
	congestion_misuse: HashMap<(ChannelId, ChannelId), u64>,
}

impl Model {
	fn references(&self, id: ChannelId) -> bool {
		self.pending.iter().any(|p| p.incoming_channel_id == id || p.outgoing_channel_id == id)
	}

	/// Mirrors the manager's removal rule: a closed channel is dropped once no pending HTLC
	/// references it as either the incoming or outgoing link, along with every misuse record
	/// naming it as either the incoming or the outgoing side.
	fn remove_if_unreferenced(&mut self, id: ChannelId) {
		if self.channels.get(&id).map_or(false, |c| c.closed) && !self.references(id) {
			self.channels.remove(&id);
			self.congestion_misuse
				.retain(|(incoming, outgoing), _| *incoming != id && *outgoing != id);
		}
	}
}

pub fn do_test(data: &[u8]) {
	let mut input = InputReader { data, pos: 0 };
	macro_rules! read {
		($e: expr) => {
			match $e {
				Some(v) => v,
				None => return,
			}
		};
	}

	let config = ResourceManagerConfig {
		general_allocation_pct: read!(input.u8()) % 128,
		congestion_allocation_pct: read!(input.u8()) % 128,
		resolution_period: Duration::from_secs(read!(input.u8()) as u64),
		revenue_window: Duration::from_secs(delta_secs(read!(input.u16()))),
		reputation_multiplier: read!(input.u8()),
	};
	let config_valid = config.general_allocation_pct > 0
		&& (config.general_allocation_pct as u16 + config.congestion_allocation_pct as u16) < 100
		&& config.resolution_period != Duration::ZERO
		&& config.revenue_window != Duration::ZERO
		&& config.reputation_multiplier > 0;
	let rm = match ResourceManager::new(config, &FixedEntropy) {
		Ok(rm) => {
			assert!(config_valid, "invalid config accepted");
			rm
		},
		Err(()) => {
			assert!(!config_valid, "valid config rejected");
			return;
		},
	};

	let mut model =
		Model { channels: new_hash_map(), pending: Vec::new(), congestion_misuse: new_hash_map() };
	let mut now: u64 = 1_700_000_000;
	let mut height: u32 = 800_000;
	let mut next_htlc_id: u64 = 0;

	while let Some(op) = input.u8() {
		match op % 6 {
			// Add channel
			0 => {
				let id = channel_id(read!(input.u8()));
				let max_accepted_htlcs = read!(input.u16()) % 1024;
				let max_in_flight_msat = amount_msat(read!(input.u32()));

				let limits_valid = max_accepted_htlcs <= 483
					&& max_in_flight_msat < TOTAL_BITCOIN_SUPPLY_SATOSHIS * 1000
					&& max_accepted_htlcs >= min_accepted_htlcs(config.general_allocation_pct)
					&& max_in_flight_msat >= MIN_MAX_IN_FLIGHT_MSAT;
				let expect_ok = limits_valid && !model.channels.contains_key(&id);

				let res = rm.add_channel(id, max_in_flight_msat, max_accepted_htlcs, now);
				assert_eq!(res.is_ok(), expect_ok, "add_channel result mismatch");
				if expect_ok {
					let channel =
						ModelChannel { max_accepted_htlcs, max_in_flight_msat, closed: false };
					model.channels.insert(id, channel);
				}
			},
			// Remove channel
			1 => {
				let id = channel_id(read!(input.u8()));
				let res = rm.remove_channel(id);
				match model.channels.get_mut(&id) {
					None => assert!(res.is_err(), "remove of unknown channel should fail"),
					Some(channel) => {
						assert!(res.is_ok(), "remove of known channel should succeed");
						channel.closed = true;
						model.remove_if_unreferenced(id);
					},
				}
			},
			// Add HTLC
			2 => {
				let in_idx = read!(input.u8());
				let out_id = channel_id(read!(input.u8()));
				let mut outgoing_amount = amount_msat(read!(input.u32()));
				let fee = amount_msat(read!(input.u32()));
				let cltv_delta = read!(input.u16());
				let flags = read!(input.u8());

				let mut incoming_amount = outgoing_amount.saturating_add(fee);
				if flags & 0x4 != 0 {
					// Exercise the outgoing > incoming rejection.
					core::mem::swap(&mut incoming_amount, &mut outgoing_amount);
				}
				// Optionally reuse the (incoming channel, htlc id) of a pending HTLC to hit the
				// duplicate rejection (when the outgoing channel matches too).
				let (in_id, htlc_id) = if flags & 0x2 != 0 && !model.pending.is_empty() {
					let p = &model.pending[read!(input.u8()) as usize % model.pending.len()];
					(p.incoming_channel_id, p.htlc_id)
				} else {
					next_htlc_id += 1;
					(channel_id(in_idx), next_htlc_id - 1)
				};
				let incoming_accountable = flags & 0x1 != 0;
				let cltv_expiry = height.saturating_add(cltv_delta as u32);

				let expect_err =
					outgoing_amount > incoming_amount
						|| height >= cltv_expiry || (cltv_expiry - height) > CLTV_FAR_FAR_AWAY
						|| in_id == out_id || model.channels.get(&in_id).map_or(true, |c| c.closed)
						|| model.channels.get(&out_id).map_or(true, |c| c.closed)
						|| model.pending.iter().any(|p| {
							p.incoming_channel_id == in_id
								&& p.htlc_id == htlc_id && p.outgoing_channel_id == out_id
						});

				let res = rm.add_htlc(
					in_id,
					incoming_amount,
					cltv_expiry,
					out_id,
					outgoing_amount,
					incoming_accountable,
					htlc_id,
					height,
					now,
				);
				assert_eq!(res.is_err(), expect_err, "add_htlc error mismatch");

				match res {
					Err(()) => {},
					Ok(ForwardingOutcome::Fail) => {
						// A failed add mutates no bucket or HTLC state (only stale misuse
						// records may have been lazily pruned, which changes no eligibility
						// answer), so the denial can be justified against the current state.
						let channels = rm.channels.lock().unwrap();
						let in_channel = channels.get(&in_id).unwrap();
						let out_channel = channels.get(&out_id).unwrap();
						let risk = rm.htlc_in_flight_risk(
							incoming_amount - outgoing_amount,
							cltv_expiry,
							height,
						);
						// Reuses the manager's own reputation predicate, so this verifies the
						// dispatch logic around it rather than the predicate itself.
						let sufficient = in_channel.sufficient_reputation(out_channel, risk, now);
						let protected_available = in_channel
							.incoming_protected_bucket
							.resources_available(incoming_amount);
						let general_slots = in_channel
							.incoming_general_bucket
							.available_slots(out_id, incoming_amount);
						if incoming_accountable {
							assert!(
								!sufficient || (!protected_available && general_slots.is_none()),
								"failed accountable HTLC despite available resources"
							);
						} else {
							assert!(
								general_slots.is_none(),
								"failed HTLC despite free general slots"
							);
							assert!(
								!sufficient || !protected_available,
								"failed unaccountable HTLC despite free protected resources"
							);
							// Congestion eligibility is fully deterministic; recompute it with
							// the misuse recency taken from the harness's own records.
							let congestion = &in_channel.incoming_congestion_bucket;
							let congestion_pending = model.pending.iter().any(|p| {
								p.outgoing_channel_id == out_id
									&& p.bucket == BucketAssigned::Congestion
							});
							let congestion_eligible = congestion.slots_allocated > 0
								&& congestion.resources_available(incoming_amount)
								&& incoming_amount
									<= congestion.liquidity_allocated
										/ congestion.slots_allocated as u64
								&& !congestion_pending && model
								.congestion_misuse
								.get(&(in_id, out_id))
								.map_or(true, |t| now - t >= TWO_WEEKS_SECS);
							assert!(
								!congestion_eligible,
								"failed HTLC despite congestion bucket eligibility"
							);
						}
					},
					Ok(ForwardingOutcome::Forward(outgoing_accountable)) => {
						let bucket = {
							let channels = rm.channels.lock().unwrap();
							let in_channel = channels.get(&in_id).unwrap();
							let out_channel = channels.get(&out_id).unwrap();
							let htlc_ref = HtlcRef { incoming_channel_id: in_id, htlc_id };
							let htlc = out_channel.pending_htlcs.get(&htlc_ref).unwrap();

							let is_general = matches!(htlc.bucket, BucketAssigned::General(_));
							assert_eq!(
								outgoing_accountable,
								incoming_accountable || !is_general,
								"accountable signal does not match assigned bucket"
							);
							match &htlc.bucket {
								BucketAssigned::General(_) => {
									if incoming_accountable {
										let available = in_channel
											.incoming_protected_bucket
											.resources_available(incoming_amount);
										assert!(!available, "skipped available protected bucket");
									}
								},
								BucketAssigned::Protected | BucketAssigned::Congestion => {
									if !incoming_accountable {
										let slots = in_channel
											.incoming_general_bucket
											.available_slots(out_id, incoming_amount);
										assert!(slots.is_none(), "skipped free general slots");
									}
									if let BucketAssigned::Congestion = htlc.bucket {
										assert!(!incoming_accountable);
										let last = model.congestion_misuse.get(&(in_id, out_id));
										assert!(
											last.map_or(true, |t| now - t >= TWO_WEEKS_SECS),
											"congestion bucket granted despite recent misuse"
										);
									}
								},
							}
							htlc.bucket.clone()
						};
						model.pending.push(ModelHtlc {
							incoming_channel_id: in_id,
							outgoing_channel_id: out_id,
							htlc_id,
							incoming_amount_msat: incoming_amount,
							fee: incoming_amount - outgoing_amount,
							outgoing_accountable,
							bucket,
							added_at: now,
						});
					},
				}
			},
			// Resolve HTLC
			3 => {
				let idx = read!(input.u8());
				let settled = read!(input.u8()) & 1 != 0;
				if model.pending.is_empty() {
					continue;
				}
				let htlc = model.pending.swap_remove(idx as usize % model.pending.len());

				let (reputation_before, revenue_raw_before, revenue_before) = {
					let channels = rm.channels.lock().unwrap();
					let out_channel = channels.get(&htlc.outgoing_channel_id).unwrap();
					let in_channel = channels.get(&htlc.incoming_channel_id).unwrap();
					let revenue = &in_channel.incoming_revenue.aggregated_decaying_average;
					(
						out_channel.outgoing_reputation.value_at_timestamp(now),
						revenue.value,
						revenue.value_at_timestamp(now),
					)
				};

				rm.resolve_htlc(
					htlc.incoming_channel_id,
					htlc.htlc_id,
					htlc.outgoing_channel_id,
					settled,
					now,
				);

				let fee = i64::try_from(htlc.fee).unwrap_or(i64::MAX);
				let resolved_promptly = now - htlc.added_at <= config.resolution_period.as_secs();
				let channels = rm.channels.lock().unwrap();
				// The channels may have been fully removed if they were closed and this was the
				// last HTLC referencing them; only check the ones still present.
				if let Some(out_channel) = channels.get(&htlc.outgoing_channel_id) {
					// The raw value equals the decayed pre-resolution value plus the effective
					// fee, since the resolution just updated it at `now`.
					let reputation_after = out_channel.outgoing_reputation.value;
					if !htlc.outgoing_accountable {
						if settled && resolved_promptly {
							assert_eq!(reputation_after, reputation_before.saturating_add(fee));
						} else {
							assert_eq!(reputation_after, reputation_before);
						}
					} else if settled && resolved_promptly {
						// No opportunity cost within the resolution period.
						assert_eq!(reputation_after, reputation_before.saturating_add(fee));
					} else if !settled {
						assert!(reputation_after <= reputation_before);
					}
				}
				if let Some(in_channel) = channels.get(&htlc.incoming_channel_id) {
					let revenue = &in_channel.incoming_revenue.aggregated_decaying_average;
					if settled {
						assert_eq!(revenue.value, revenue_before.saturating_add(fee));
					} else {
						assert_eq!(revenue.value, revenue_raw_before, "failed HTLC added revenue");
					}
				}
				drop(channels);

				if let BucketAssigned::Congestion = htlc.bucket {
					if now - htlc.added_at > config.resolution_period.as_secs() {
						let pair = (htlc.incoming_channel_id, htlc.outgoing_channel_id);
						model.congestion_misuse.insert(pair, now);
					}
				}
				model.remove_if_unreferenced(htlc.incoming_channel_id);
				model.remove_if_unreferenced(htlc.outgoing_channel_id);
			},
			// Advance time
			4 => {
				now = now.saturating_add(delta_secs(read!(input.u16())));
			},
			// Advance height
			5 => {
				height = height.saturating_add(read!(input.u16()) as u32);
			},
			_ => unreachable!(),
		}
		check_invariants(&rm, &model, now);
	}
}

fn f64_magnitude_bound(value: i64) -> u64 {
	// i64 as f64 always yields an integral float with magnitude <= 2^63, which fits in u64.
	(value as f64).abs() as u64
}

fn check_invariants(rm: &ResourceManager, model: &Model, now: u64) {
	let channels = rm.channels.lock().unwrap();

	assert_eq!(channels.len(), model.channels.len(), "channel set size mismatch");
	for (id, model_channel) in model.channels.iter() {
		let channel = channels.get(id).expect("model channel missing from manager");
		assert_eq!(channel.closed, model_channel.closed, "closed flag mismatch");
		if channel.closed {
			assert!(model.references(*id), "closed channel with no pending HTLCs leaked");
		}
	}

	let manager_pending: usize = channels.values().map(|c| c.pending_htlcs.len()).sum();
	assert_eq!(manager_pending, model.pending.len(), "pending HTLC count mismatch");
	for p in model.pending.iter() {
		let out_channel = channels.get(&p.outgoing_channel_id).unwrap();
		let htlc_ref = HtlcRef { incoming_channel_id: p.incoming_channel_id, htlc_id: p.htlc_id };
		let htlc = out_channel.pending_htlcs.get(&htlc_ref).expect("pending HTLC missing");
		assert_eq!(htlc.incoming_amount_msat, p.incoming_amount_msat);
		assert_eq!(htlc.fee, p.fee);
		assert_eq!(htlc.outgoing_accountable, p.outgoing_accountable);
		assert_eq!(htlc.added_at_unix_seconds, p.added_at);
		assert_eq!(htlc.bucket, p.bucket);
	}

	for (id, channel) in channels.iter() {
		// Recompute this channel's incoming bucket usage from the pending HTLCs and compare
		// against the tracked state.
		let mut congestion_slots = 0u16;
		let mut congestion_liquidity = 0u64;
		let mut protected_slots = 0u16;
		let mut protected_liquidity = 0u64;
		let general = &channel.incoming_general_bucket;
		let mut occupied = vec![false; general.slots_occupied.len()];
		let mut total_in_flight = 0u64;
		let mut htlcs_in_flight = 0usize;

		for p in model.pending.iter().filter(|p| p.incoming_channel_id == *id) {
			total_in_flight = total_in_flight.saturating_add(p.incoming_amount_msat);
			htlcs_in_flight += 1;
			match &p.bucket {
				BucketAssigned::General(slots) => {
					let needed =
						u64::max(1, p.incoming_amount_msat.div_ceil(general.per_slot_msat));
					assert_eq!(slots.len() as u64, needed, "wrong general slot count for amount");
					for slot in slots {
						assert!(!occupied[*slot as usize], "general slot double-booked");
						occupied[*slot as usize] = true;
					}
				},
				BucketAssigned::Congestion => {
					congestion_slots += 1;
					congestion_liquidity =
						congestion_liquidity.saturating_add(p.incoming_amount_msat);
					let bucket = &channel.incoming_congestion_bucket;
					assert!(bucket.slots_allocated > 0);
					assert!(
						p.incoming_amount_msat
							<= bucket.liquidity_allocated / bucket.slots_allocated as u64,
						"congestion HTLC over per-slot amount limit"
					);
				},
				BucketAssigned::Protected => {
					protected_slots += 1;
					protected_liquidity =
						protected_liquidity.saturating_add(p.incoming_amount_msat);
				},
			}
		}

		assert_eq!(occupied, general.slots_occupied, "general occupancy mismatch");
		let congestion = &channel.incoming_congestion_bucket;
		assert_eq!(congestion_slots, congestion.slots_used, "congestion slots mismatch");
		assert_eq!(
			congestion_liquidity, congestion.liquidity_used,
			"congestion liquidity mismatch"
		);
		assert!(congestion.slots_used <= congestion.slots_allocated);
		assert!(congestion.liquidity_used <= congestion.liquidity_allocated);
		let protected = &channel.incoming_protected_bucket;
		assert_eq!(protected_slots, protected.slots_used, "protected slots mismatch");
		assert_eq!(protected_liquidity, protected.liquidity_used, "protected liquidity mismatch");
		assert!(protected.slots_used <= protected.slots_allocated);
		assert!(protected.liquidity_used <= protected.liquidity_allocated);

		let model_channel = &model.channels[id];
		assert!(htlcs_in_flight <= model_channel.max_accepted_htlcs as usize, "slots overrun");
		assert!(total_in_flight <= model_channel.max_in_flight_msat, "liquidity overrun");

		// The manager's misuse records are a (lazily pruned) subset of the harness's.
		for (out_id, timestamp) in channel.last_congestion_misuse.iter() {
			assert_eq!(
				model.congestion_misuse.get(&(*id, *out_id)),
				Some(timestamp),
				"manager tracks a congestion misuse the harness never observed"
			);
		}

		// Decay moves a value toward zero, so it can never increase the magnitude.
		let revenue = &channel.incoming_revenue.aggregated_decaying_average;
		assert!(revenue.value >= 0, "negative revenue: {}", revenue.value);
		assert!(
			revenue.value_at_timestamp(now).unsigned_abs() <= f64_magnitude_bound(revenue.value),
			"decay amplified revenue: value {} at ts {} decayed to {} at now {}",
			revenue.value,
			revenue.last_updated_unix_secs,
			revenue.value_at_timestamp(now),
			now
		);
		let reputation = &channel.outgoing_reputation;
		assert!(
			reputation.value_at_timestamp(now).unsigned_abs()
				<= f64_magnitude_bound(reputation.value),
			"decay amplified reputation: value {} at ts {} decayed to {} at now {}",
			reputation.value,
			reputation.last_updated_unix_secs,
			reputation.value_at_timestamp(now),
			now
		);
	}

	for (out_id, _) in channels.iter() {
		let congestion_pending = model
			.pending
			.iter()
			.filter(|p| p.outgoing_channel_id == *out_id && p.bucket == BucketAssigned::Congestion)
			.count();
		assert!(congestion_pending <= 1, "multiple congestion HTLCs for one outgoing channel");

		for (in_id, in_channel) in channels.iter() {
			if in_id == out_id {
				continue;
			}
			let pair_slots: Vec<u16> = model
				.pending
				.iter()
				.filter(|p| p.incoming_channel_id == *in_id && p.outgoing_channel_id == *out_id)
				.filter_map(|p| match &p.bucket {
					BucketAssigned::General(slots) => Some(slots.iter().copied()),
					_ => None,
				})
				.flatten()
				.collect();
			if pair_slots.is_empty() {
				continue;
			}
			let general = &in_channel.incoming_general_bucket;
			assert!(pair_slots.len() <= general.per_channel_slots as usize, "pair slots overrun");
			let assigned = assign_slots_for_channel(
				*in_id,
				*out_id,
				general.salt,
				general.per_channel_slots,
				general.total_slots,
			);
			for slot in pair_slots {
				assert!(assigned.contains(&slot), "HTLC in a slot outside the pair's assignment");
			}
		}
	}
}
