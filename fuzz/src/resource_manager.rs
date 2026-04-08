// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

use crate::utils::test_logger;

use lightning::ln::resource_manager::{
	DefaultResourceManager, ForwardingOutcome, PendingHTLCReplay, ResourceManagerConfig,
};
use lightning::sign::EntropySource;
use lightning::util::ser::{ReadableArgs, Writeable};

use lightning::util::hash_tables::new_hash_map;

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

struct CountingEntropy {
	counter: AtomicU64,
}

impl CountingEntropy {
	fn new() -> Self {
		CountingEntropy { counter: AtomicU64::new(0) }
	}
}

impl EntropySource for CountingEntropy {
	fn get_secure_random_bytes(&self) -> [u8; 32] {
		let ctr = self.counter.fetch_add(1, Ordering::Relaxed);
		let mut bytes = [0u8; 32];
		bytes[..8].copy_from_slice(&ctr.to_le_bytes());
		bytes
	}
}

struct TrackedHtlc {
	incoming_channel_id: u64,
	htlc_id: u64,
	outgoing_channel_id: u64,
	incoming_amount_msat: u64,
	outgoing_amount_msat: u64,
	incoming_cltv_expiry: u32,
	height_added: u32,
	incoming_accountable: bool,
	added_at: u64,
}

const AMOUNT_TABLE: [u64; 4] = [1_000, 100_000, 500_000_000, 2_000_000_000];
const FEE_TABLE: [u64; 4] = [100, 1_000, 10_000, 100_000];
const TIME_DELTAS: [u64; 7] = [0, 1, 60, 3600, 86400, 604800, 1209600];
const CLTV_DELTAS: [u32; 4] = [20, 144, 500, 2016];
const MAX_HTLCS_TABLE: [u16; 4] = [12, 50, 114, 483];
const MAX_IN_FLIGHT_TABLE: [u64; 4] = [1_000_000, 100_000_000, 5_000_000_000, 500_000_000_000];
// (general_allocation_pct, congestion_allocation_pct)
const CONFIG_TABLE: [(u8, u8); 7] = [
	(30, 30),
	(60, 10),
	(10, 10),
	(20, 5),
	(50, 30),
	(5, 5),
	(70, 20),
];

#[inline]
pub fn do_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	let entropy_source = CountingEntropy::new();

	let mut read_pos = 0;
	macro_rules! get_slice {
		($len:expr) => {{
			let len = $len as usize;
			if data.len() < read_pos + len {
				return;
			}
			read_pos += len;
			&data[read_pos - len..read_pos]
		}};
	}
	let config_byte = get_slice!(1)[0];
	let (general_pct, congestion_pct) = if config_byte < 128 {
		(40_u8, 20_u8)
	} else {
		CONFIG_TABLE[((config_byte - 128) % 7) as usize]
	};
	let config = ResourceManagerConfig {
		general_allocation_pct: general_pct,
		congestion_allocation_pct: congestion_pct,
		..ResourceManagerConfig::default()
	};
	let mut rm = DefaultResourceManager::new(config);

	let mut current_time: u64 = 1_700_000_000;
	let current_height: u32 = 1000;
	let mut channel_limits: HashMap<u64, (u64, u16)> = HashMap::new();
	let mut pending_htlcs: Vec<TrackedHtlc> = Vec::new();
	let mut next_htlc_id: u64 = 0;

	loop {
		let action_byte = get_slice!(1)[0];
		match action_byte % 7 {
			// Add channel
			0 => {
				let params = get_slice!(2);
				let channel_id = (params[0] % 8) as u64 + 1;
				let max_htlcs = MAX_HTLCS_TABLE[(params[1] % 4) as usize];
				let max_in_flight = MAX_IN_FLIGHT_TABLE[(params[1] / 4 % 4) as usize];
				if rm.add_channel(channel_id, max_in_flight, max_htlcs, current_time).is_ok() {
					channel_limits.insert(channel_id, (max_in_flight, max_htlcs));
				}
			},
			// Remove channel
			1 => {
				let idx = get_slice!(1)[0];
				let channel_id = (idx % 8) as u64 + 1;
				let _ = rm.remove_channel(channel_id);
				channel_limits.remove(&channel_id);
				pending_htlcs.retain(|h| {
					h.incoming_channel_id != channel_id && h.outgoing_channel_id != channel_id
				});
			},
			// Add HTLC
			2 => {
				let params = get_slice!(4);
				let incoming_id = (params[0] % 8) as u64 + 1;
				let outgoing_id = (params[1] % 8) as u64 + 1;
				if incoming_id == outgoing_id {
					continue;
				}
				let outgoing_amount = AMOUNT_TABLE[(params[2] % 4) as usize];
				let fee = FEE_TABLE[(params[3] % 4) as usize];
				let incoming_amount = outgoing_amount + fee;
				let accountable = params[3] >= 4;
				let cltv_delta = CLTV_DELTAS[(params[2] / 4 % 4) as usize];
				let htlc_id = next_htlc_id;
				next_htlc_id += 1;
				let cltv_expiry = current_height + cltv_delta;

				let result = rm.add_htlc(
					incoming_id,
					incoming_amount,
					cltv_expiry,
					outgoing_id,
					outgoing_amount,
					accountable,
					htlc_id,
					current_height,
					current_time,
					&entropy_source,
				);
				match result {
					Ok(ForwardingOutcome::Forward(_)) => {
						pending_htlcs.push(TrackedHtlc {
							incoming_channel_id: incoming_id,
							htlc_id,
							outgoing_channel_id: outgoing_id,
							incoming_amount_msat: incoming_amount,
							outgoing_amount_msat: outgoing_amount,
							incoming_cltv_expiry: cltv_expiry,
							height_added: current_height,
							incoming_accountable: accountable,
							added_at: current_time,
						});
					},
					_ => {},
				}
			},
			// Resolve HTLC
			3 => {
				let params = get_slice!(2);
				if pending_htlcs.is_empty() {
					continue;
				}
				let idx = params[0] as usize % pending_htlcs.len();
				let settled = params[1] % 2 == 1;
				let htlc = &pending_htlcs[idx];
				let result = rm.resolve_htlc(
					htlc.incoming_channel_id,
					htlc.htlc_id,
					htlc.outgoing_channel_id,
					settled,
					current_time,
				);
				if result.is_ok() {
					pending_htlcs.swap_remove(idx);
				}
			},
			// Serialization roundtrip
			4 => {
				let mut buf = Vec::new();
				rm.write(&mut buf).unwrap();

				let mut ldk_channel_limits = new_hash_map();
				for (k, v) in &channel_limits {
					ldk_channel_limits.insert(*k, *v);
				}
				let deserialized = DefaultResourceManager::read(
					&mut &buf[..],
					(
						ResourceManagerConfig {
							general_allocation_pct: general_pct,
							congestion_allocation_pct: congestion_pct,
							..ResourceManagerConfig::default()
						},
						&entropy_source,
						&ldk_channel_limits,
					),
				);
				let deserialized = match deserialized {
					Ok(d) => d,
					Err(_) => continue,
				};

				let replays: Vec<PendingHTLCReplay> = pending_htlcs
					.iter()
					.map(|h| PendingHTLCReplay {
						incoming_channel_id: h.incoming_channel_id,
						incoming_amount_msat: h.incoming_amount_msat,
						incoming_htlc_id: h.htlc_id,
						incoming_cltv_expiry: h.incoming_cltv_expiry,
						incoming_accountable: h.incoming_accountable,
						outgoing_channel_id: h.outgoing_channel_id,
						outgoing_amount_msat: h.outgoing_amount_msat,
						added_at_unix_seconds: h.added_at,
						height_added: h.height_added,
					})
					.collect();

				if let Ok(outcomes) = deserialized.replay_pending_htlcs(&replays, &entropy_source) {
					let mut to_remove = Vec::new();
					for (i, outcome) in outcomes.iter().enumerate() {
						if *outcome == ForwardingOutcome::Fail {
							to_remove.push(i);
						}
					}
					for idx in to_remove.into_iter().rev() {
						pending_htlcs.swap_remove(idx);
					}
				}

				rm = deserialized;
			},
			// Advance time
			5 => {
				let delta_byte = get_slice!(1)[0];
				current_time += TIME_DELTAS[(delta_byte % 7) as usize];
			},
			// Resolve all pending HTLCs
			6 => {
				let settled = get_slice!(1)[0] % 2 == 1;
				let htlcs: Vec<TrackedHtlc> = pending_htlcs.drain(..).collect();
				for htlc in &htlcs {
					let _ = rm.resolve_htlc(
						htlc.incoming_channel_id,
						htlc.htlc_id,
						htlc.outgoing_channel_id,
						settled,
						current_time,
					);
				}
			},
			_ => unreachable!(),
		}
	}
}

pub fn resource_manager_test<Out: test_logger::Output>(data: &[u8], out: Out) {
	do_test(data, out);
}

#[no_mangle]
pub extern "C" fn resource_manager_run(data: *const u8, datalen: usize) {
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) }, test_logger::DevNull {});
}
