// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

extern crate bitcoin;
extern crate lightning;
extern crate lightning_rapid_gossip_sync;

#[cfg(not(fuzzing))]
compile_error!("Fuzz targets need cfg=fuzzing");

#[cfg(not(hashes_fuzz))]
compile_error!("Fuzz targets need cfg=hashes_fuzz");

#[cfg(not(secp256k1_fuzz))]
compile_error!("Fuzz targets need cfg=secp256k1_fuzz");

pub mod utils;

pub mod base32;
pub mod bech32_parse;
pub mod bolt11_deser;
pub mod chanmon_consistency;
pub mod chanmon_deser;
pub mod feature_flags;
pub mod fromstr_to_netaddress;
pub mod full_stack;
pub mod indexedmap;
pub mod invoice_deser;
pub mod invoice_request_deser;
pub mod offer_deser;
pub mod onion_hop_data;
pub mod onion_message;
pub mod peer_crypt;
pub mod process_network_graph;
pub mod process_onion_failure;
pub mod refund_deser;
pub mod router;
pub mod zbase32;

pub mod msg_targets;
