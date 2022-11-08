// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

#![crate_name = "lightning_htlc_scorer"]

//! This crates provides a module to control liquidity flows of a routing node,
//! among other managing congestion, arising from spontaneous or malicious activity.
//!
//! The HTLCScorer is the main chunk of channel jamming logic, implementing
//! the additional HTLC forward policy checks, maintaining credit score for the
//! HTLC forward, pushing policy updates over the gossip network and receiving
//! credentials proofs over the onion communication channels.

extern crate bitcoin;
extern crate lightning;
extern crate alloc;
#[cfg(any(test, feature = "std"))]
extern crate core;

mod prelude {
	#[cfg(feature = "hashbrown")]
	extern crate hashbrown;

	pub use alloc::{vec, vec::Vec, string::String, collections::VecDeque, boxed::Box};
	#[cfg(not(feature = "hashbrown"))]
	pub use std::collections::{HashMap, HashSet, hash_map};
	#[cfg(feature = "hashbrown")]
	pub use self::hashbrown::{HashMap, HashSet, hash_map};
}

/// Sync compat for std/no_std
#[cfg(feature = "std")]
mod sync {
	pub use ::std::sync::{Mutex, MutexGuard};
}

/// Sync compat for std/no_std
#[cfg(not(feature = "std"))]
mod sync;

use lightning::util::logger::Logger;
use lightning::util::events::Event;
use lightning::util::credentials_utils::SignedCredential;
use lightning::ln::channelmanager::InterceptId;

use bitcoin::secp256k1::{SecretKey, PublicKey, Secp256k1, Message};
use bitcoin::secp256k1;

use crate::prelude::*;
use crate::sync::Mutex;
use core::ops::Deref;

/// Routing policy which apply on a per-HTLC forward basis and may change at runtime.
///
/// Routing policy can be announced network-wide via gossips or on a HTLC sender basis
/// via onion communication channels.
#[derive(Copy, Clone, Debug)]
struct RoutingPolicy {
	/// The number of credentials we require to grant channel liquidity to a HTLC
	/// forward request.
	///
	/// Default value: 1 credential unit = 1 btc liquidity per block.
	credential_to_liquidity_unit: u64,
	/// Height at which all issues routing credentials are expiring.
	///
	/// Default value: 0 (never expires).
	credential_expiration_height: u32,
}

impl Default for RoutingPolicy {
	fn default() -> Self {
		RoutingPolicy {
			credential_to_liquidity_unit: 1,
			credential_expiration_height: 0
		}
	}
}

/// HTLC scorer which keeps track of the accepted HTLC forward requests and process
/// the settlement result accordingly when they're routed backward.
pub struct HTLCScorer<L: Deref>
	where L::Target: Logger,
{
	forward_state: Mutex<HashMap<InterceptId, Vec<SignedCredential>>>,
	// backward_state: Mutex<HashMap<InterceptId, Vec<UnsignedCredentials>>

	routing_policy: RoutingPolicy,

	scorer_pubkey: PublicKey,
	//TODO: move behind keysinterface
	scorer_seckey: SecretKey,

	secp_ctx: Secp256k1<secp256k1::All>,

	logger: L,
}

impl<L: Deref> HTLCScorer<L>
	where L::Target: Logger,
{
	pub fn new(logger: L, scorer_seckey: SecretKey) -> Self {
		let mut secp_ctx = Secp256k1::new();
		let scorer_pubkey = PublicKey::from_secret_key(&secp_ctx, &scorer_seckey);
		HTLCScorer {
			forward_state: Mutex::new(HashMap::new()),
			routing_policy: RoutingPolicy::default(),
			scorer_pubkey,
			scorer_seckey,
			secp_ctx,
			logger,
		}
	}

	pub fn process_htlc_forward(&self, event: &Event) -> bool {
		match event {
			Event::PaymentIntercepted { intercept_id, expected_outbound_amount_msat, outbound_block_value, forward_credentials, backward_credentials, .. } => {

				// Verify credentials authenticity
				for signed_credential in forward_credentials {
					let message = Message::from_slice(&signed_credential.credential).unwrap();
					match self.secp_ctx.verify_ecdsa(&message, &signed_credential.signature, &self.scorer_pubkey) {
						Ok(_) => {},
						Err(_) => { return false; }
					}
				}

				// Verify forward credentials satisfy routing policy.
				let requested_lockup_liquidity_units = expected_outbound_amount_msat * (*outbound_block_value) as u64 / 100_000_000_000;
				let credit_liquidity_units = self.routing_policy.credential_to_liquidity_unit * forward_credentials.len() as u64;
				if requested_lockup_liquidity_units > credit_liquidity_units {
					//TODO: introduce new onion error messages ?
					return false;
				}

				// Register the backward credentials when the HTLC is settled back (either `update_fulfill_htlc`/`update_fail_htlc`).
				let mut forward_state = self.forward_state.lock().unwrap();
				forward_state.insert(*intercept_id, backward_credentials.to_vec());
			},
			_ => { panic!("Received non compatible event for module !"); }
		}
		return true;
	}

	pub fn process_htlc_backward(&self, event: &Event) -> Result<Vec<SignedCredential>, ()> {
		match event {
			Event::HTLCBackwardIntercepted { intercept_id, result } => {

				// If the HTLC has successfully paid back fees, counter-sign the registered
				// credentials and relay them back to HTLC sender.
				//
				// Note, if the HTLC has been failed on our outgoing link, credentials *might*
				// be counter-signed, as the failure can be assigned to our channel peering
				// strategy.
				if *result {
					let mut forward_state = self.forward_state.lock().unwrap();
					if let Some(backward_credentials) = forward_state.remove(intercept_id) {
						let mut result_credentials = Vec::with_capacity(backward_credentials.len());
						for credential in backward_credentials {
							let message = Message::from_slice(&credential.credential).unwrap();
							let sig = self.secp_ctx.sign_ecdsa(&message, &self.scorer_seckey);
							let new_credential = SignedCredential {
								credential: credential.credential,
								signature: sig,
							};
							result_credentials.push(new_credential);
						}
						return Ok(result_credentials);
					}
				}
			}
			_ => { panic!("Receive non compatible event for module !"); }
		}
		return Err(());
	}
}
