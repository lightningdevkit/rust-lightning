// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Utilities to send payments and manage outbound payment information.

use bitcoin::hashes::Hash;
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::secp256k1::{self, Secp256k1, SecretKey};

use crate::chain::keysinterface::{EntropySource, KeysInterface, NodeSigner, Recipient};
use crate::ln::{PaymentHash, PaymentPreimage, PaymentSecret};
use crate::ln::channelmanager::{HTLCSource, IDEMPOTENCY_TIMEOUT_TICKS, PaymentId};
use crate::ln::msgs::DecodeError;
use crate::ln::onion_utils::HTLCFailReason;
use crate::routing::router::{PaymentParameters, Route, RouteHop, RouteParameters, RoutePath};
use crate::util::errors::APIError;
use crate::util::events;
use crate::util::logger::Logger;

use core::cmp;
use core::ops::Deref;
use crate::prelude::*;
use crate::sync::Mutex;

/// Stores the session_priv for each part of a payment that is still pending. For versions 0.0.102
/// and later, also stores information for retrying the payment.
pub(crate) enum PendingOutboundPayment {
	Legacy {
		session_privs: HashSet<[u8; 32]>,
	},
	Retryable {
		session_privs: HashSet<[u8; 32]>,
		payment_hash: PaymentHash,
		payment_secret: Option<PaymentSecret>,
		pending_amt_msat: u64,
		/// Used to track the fee paid. Only present if the payment was serialized on 0.0.103+.
		pending_fee_msat: Option<u64>,
		/// The total payment amount across all paths, used to verify that a retry is not overpaying.
		total_msat: u64,
		/// Our best known block height at the time this payment was initiated.
		starting_block_height: u32,
	},
	/// When a pending payment is fulfilled, we continue tracking it until all pending HTLCs have
	/// been resolved. This ensures we don't look up pending payments in ChannelMonitors on restart
	/// and add a pending payment that was already fulfilled.
	Fulfilled {
		session_privs: HashSet<[u8; 32]>,
		payment_hash: Option<PaymentHash>,
		timer_ticks_without_htlcs: u8,
	},
	/// When a payer gives up trying to retry a payment, they inform us, letting us generate a
	/// `PaymentFailed` event when all HTLCs have irrevocably failed. This avoids a number of race
	/// conditions in MPP-aware payment retriers (1), where the possibility of multiple
	/// `PaymentPathFailed` events with `all_paths_failed` can be pending at once, confusing a
	/// downstream event handler as to when a payment has actually failed.
	///
	/// (1) <https://github.com/lightningdevkit/rust-lightning/issues/1164>
	Abandoned {
		session_privs: HashSet<[u8; 32]>,
		payment_hash: PaymentHash,
	},
}

impl PendingOutboundPayment {
	pub(super) fn is_fulfilled(&self) -> bool {
		match self {
			PendingOutboundPayment::Fulfilled { .. } => true,
			_ => false,
		}
	}
	pub(super) fn abandoned(&self) -> bool {
		match self {
			PendingOutboundPayment::Abandoned { .. } => true,
			_ => false,
		}
	}
	fn get_pending_fee_msat(&self) -> Option<u64> {
		match self {
			PendingOutboundPayment::Retryable { pending_fee_msat, .. } => pending_fee_msat.clone(),
			_ => None,
		}
	}

	fn payment_hash(&self) -> Option<PaymentHash> {
		match self {
			PendingOutboundPayment::Legacy { .. } => None,
			PendingOutboundPayment::Retryable { payment_hash, .. } => Some(*payment_hash),
			PendingOutboundPayment::Fulfilled { payment_hash, .. } => *payment_hash,
			PendingOutboundPayment::Abandoned { payment_hash, .. } => Some(*payment_hash),
		}
	}

	fn mark_fulfilled(&mut self) {
		let mut session_privs = HashSet::new();
		core::mem::swap(&mut session_privs, match self {
			PendingOutboundPayment::Legacy { session_privs } |
				PendingOutboundPayment::Retryable { session_privs, .. } |
				PendingOutboundPayment::Fulfilled { session_privs, .. } |
				PendingOutboundPayment::Abandoned { session_privs, .. }
			=> session_privs,
		});
		let payment_hash = self.payment_hash();
		*self = PendingOutboundPayment::Fulfilled { session_privs, payment_hash, timer_ticks_without_htlcs: 0 };
	}

	fn mark_abandoned(&mut self) -> Result<(), ()> {
		let mut session_privs = HashSet::new();
		let our_payment_hash;
		core::mem::swap(&mut session_privs, match self {
			PendingOutboundPayment::Legacy { .. } |
				PendingOutboundPayment::Fulfilled { .. } =>
				return Err(()),
				PendingOutboundPayment::Retryable { session_privs, payment_hash, .. } |
					PendingOutboundPayment::Abandoned { session_privs, payment_hash, .. } => {
						our_payment_hash = *payment_hash;
						session_privs
					},
		});
		*self = PendingOutboundPayment::Abandoned { session_privs, payment_hash: our_payment_hash };
		Ok(())
	}

	/// panics if path is None and !self.is_fulfilled
	fn remove(&mut self, session_priv: &[u8; 32], path: Option<&Vec<RouteHop>>) -> bool {
		let remove_res = match self {
			PendingOutboundPayment::Legacy { session_privs } |
				PendingOutboundPayment::Retryable { session_privs, .. } |
				PendingOutboundPayment::Fulfilled { session_privs, .. } |
				PendingOutboundPayment::Abandoned { session_privs, .. } => {
					session_privs.remove(session_priv)
				}
		};
		if remove_res {
			if let PendingOutboundPayment::Retryable { ref mut pending_amt_msat, ref mut pending_fee_msat, .. } = self {
				let path = path.expect("Fulfilling a payment should always come with a path");
				let path_last_hop = path.last().expect("Outbound payments must have had a valid path");
				*pending_amt_msat -= path_last_hop.fee_msat;
				if let Some(fee_msat) = pending_fee_msat.as_mut() {
					*fee_msat -= path.get_path_fees();
				}
			}
		}
		remove_res
	}

	pub(super) fn insert(&mut self, session_priv: [u8; 32], path: &Vec<RouteHop>) -> bool {
		let insert_res = match self {
			PendingOutboundPayment::Legacy { session_privs } |
				PendingOutboundPayment::Retryable { session_privs, .. } => {
					session_privs.insert(session_priv)
				}
			PendingOutboundPayment::Fulfilled { .. } => false,
			PendingOutboundPayment::Abandoned { .. } => false,
		};
		if insert_res {
			if let PendingOutboundPayment::Retryable { ref mut pending_amt_msat, ref mut pending_fee_msat, .. } = self {
				let path_last_hop = path.last().expect("Outbound payments must have had a valid path");
				*pending_amt_msat += path_last_hop.fee_msat;
				if let Some(fee_msat) = pending_fee_msat.as_mut() {
					*fee_msat += path.get_path_fees();
				}
			}
		}
		insert_res
	}

	pub(super) fn remaining_parts(&self) -> usize {
		match self {
			PendingOutboundPayment::Legacy { session_privs } |
				PendingOutboundPayment::Retryable { session_privs, .. } |
				PendingOutboundPayment::Fulfilled { session_privs, .. } |
				PendingOutboundPayment::Abandoned { session_privs, .. } => {
					session_privs.len()
				}
		}
	}
}

/// If a payment fails to send, it can be in one of several states. This enum is returned as the
/// Err() type describing which state the payment is in, see the description of individual enum
/// states for more.
#[derive(Clone, Debug)]
pub enum PaymentSendFailure {
	/// A parameter which was passed to send_payment was invalid, preventing us from attempting to
	/// send the payment at all.
	///
	/// You can freely resend the payment in full (with the parameter error fixed).
	///
	/// Because the payment failed outright, no payment tracking is done, you do not need to call
	/// [`ChannelManager::abandon_payment`] and [`ChannelManager::retry_payment`] will *not* work
	/// for this payment.
	///
	/// [`ChannelManager::abandon_payment`]: crate::ln::channelmanager::ChannelManager::abandon_payment
	/// [`ChannelManager::retry_payment`]: crate::ln::channelmanager::ChannelManager::retry_payment
	ParameterError(APIError),
	/// A parameter in a single path which was passed to send_payment was invalid, preventing us
	/// from attempting to send the payment at all.
	///
	/// You can freely resend the payment in full (with the parameter error fixed).
	///
	/// The results here are ordered the same as the paths in the route object which was passed to
	/// send_payment.
	///
	/// Because the payment failed outright, no payment tracking is done, you do not need to call
	/// [`ChannelManager::abandon_payment`] and [`ChannelManager::retry_payment`] will *not* work
	/// for this payment.
	///
	/// [`ChannelManager::abandon_payment`]: crate::ln::channelmanager::ChannelManager::abandon_payment
	/// [`ChannelManager::retry_payment`]: crate::ln::channelmanager::ChannelManager::retry_payment
	PathParameterError(Vec<Result<(), APIError>>),
	/// All paths which were attempted failed to send, with no channel state change taking place.
	/// You can freely resend the payment in full (though you probably want to do so over different
	/// paths than the ones selected).
	///
	/// Because the payment failed outright, no payment tracking is done, you do not need to call
	/// [`ChannelManager::abandon_payment`] and [`ChannelManager::retry_payment`] will *not* work
	/// for this payment.
	///
	/// [`ChannelManager::abandon_payment`]: crate::ln::channelmanager::ChannelManager::abandon_payment
	/// [`ChannelManager::retry_payment`]: crate::ln::channelmanager::ChannelManager::retry_payment
	AllFailedResendSafe(Vec<APIError>),
	/// Indicates that a payment for the provided [`PaymentId`] is already in-flight and has not
	/// yet completed (i.e. generated an [`Event::PaymentSent`]) or been abandoned (via
	/// [`ChannelManager::abandon_payment`]).
	///
	/// [`PaymentId`]: crate::ln::channelmanager::PaymentId
	/// [`Event::PaymentSent`]: crate::util::events::Event::PaymentSent
	/// [`ChannelManager::abandon_payment`]: crate::ln::channelmanager::ChannelManager::abandon_payment
	DuplicatePayment,
	/// Some paths which were attempted failed to send, though possibly not all. At least some
	/// paths have irrevocably committed to the HTLC and retrying the payment in full would result
	/// in over-/re-payment.
	///
	/// The results here are ordered the same as the paths in the route object which was passed to
	/// send_payment, and any `Err`s which are not [`APIError::MonitorUpdateInProgress`] can be
	/// safely retried via [`ChannelManager::retry_payment`].
	///
	/// Any entries which contain `Err(APIError::MonitorUpdateInprogress)` or `Ok(())` MUST NOT be
	/// retried as they will result in over-/re-payment. These HTLCs all either successfully sent
	/// (in the case of `Ok(())`) or will send once a [`MonitorEvent::Completed`] is provided for
	/// the next-hop channel with the latest update_id.
	///
	/// [`ChannelManager::retry_payment`]: crate::ln::channelmanager::ChannelManager::retry_payment
	/// [`MonitorEvent::Completed`]: crate::chain::channelmonitor::MonitorEvent::Completed
	PartialFailure {
		/// The errors themselves, in the same order as the route hops.
		results: Vec<Result<(), APIError>>,
		/// If some paths failed without irrevocably committing to the new HTLC(s), this will
		/// contain a [`RouteParameters`] object which can be used to calculate a new route that
		/// will pay all remaining unpaid balance.
		failed_paths_retry: Option<RouteParameters>,
		/// The payment id for the payment, which is now at least partially pending.
		payment_id: PaymentId,
	},
}

pub(super) struct OutboundPayments {
	pub(super) pending_outbound_payments: Mutex<HashMap<PaymentId, PendingOutboundPayment>>,
}

impl OutboundPayments {
	pub(super) fn new() -> Self {
		Self {
			pending_outbound_payments: Mutex::new(HashMap::new())
		}
	}

	pub(super) fn send_payment_with_route<K: Deref, F>(
		&self, route: &Route, payment_hash: PaymentHash, payment_secret: &Option<PaymentSecret>,
		payment_id: PaymentId, keys_manager: &K, best_block_height: u32, send_payment_along_path: F
	) -> Result<(), PaymentSendFailure>
	where
		K::Target: KeysInterface,
		F: Fn(&Vec<RouteHop>, &Option<PaymentParameters>, &PaymentHash, &Option<PaymentSecret>, u64,
		   u32, PaymentId, &Option<PaymentPreimage>, [u8; 32]) -> Result<(), APIError>
	{
		let onion_session_privs = self.add_new_pending_payment(payment_hash, *payment_secret, payment_id, route, keys_manager, best_block_height)?;
		self.send_payment_internal(route, payment_hash, payment_secret, None, payment_id, None, onion_session_privs, keys_manager, best_block_height, send_payment_along_path)
	}

	pub(super) fn send_spontaneous_payment<K: Deref, F>(
		&self, route: &Route, payment_preimage: Option<PaymentPreimage>, payment_id: PaymentId,
		keys_manager: &K, best_block_height: u32, send_payment_along_path: F
	) -> Result<PaymentHash, PaymentSendFailure>
	where
		K::Target: KeysInterface,
		F: Fn(&Vec<RouteHop>, &Option<PaymentParameters>, &PaymentHash, &Option<PaymentSecret>, u64,
		   u32, PaymentId, &Option<PaymentPreimage>, [u8; 32]) -> Result<(), APIError>
	{
		let preimage = match payment_preimage {
			Some(p) => p,
			None => PaymentPreimage(keys_manager.get_secure_random_bytes()),
		};
		let payment_hash = PaymentHash(Sha256::hash(&preimage.0).into_inner());
		let onion_session_privs = self.add_new_pending_payment(payment_hash, None, payment_id, &route, keys_manager, best_block_height)?;

		match self.send_payment_internal(route, payment_hash, &None, Some(preimage), payment_id, None, onion_session_privs, keys_manager, best_block_height, send_payment_along_path) {
			Ok(()) => Ok(payment_hash),
			Err(e) => Err(e)
		}
	}

	pub(super) fn retry_payment_with_route<K: Deref, F>(
		&self, route: &Route, payment_id: PaymentId, keys_manager: &K, best_block_height: u32,
		send_payment_along_path: F
	) -> Result<(), PaymentSendFailure>
	where
		K::Target: KeysInterface,
		F: Fn(&Vec<RouteHop>, &Option<PaymentParameters>, &PaymentHash, &Option<PaymentSecret>, u64,
		   u32, PaymentId, &Option<PaymentPreimage>, [u8; 32]) -> Result<(), APIError>
	{
		const RETRY_OVERFLOW_PERCENTAGE: u64 = 10;
		for path in route.paths.iter() {
			if path.len() == 0 {
				return Err(PaymentSendFailure::ParameterError(APIError::APIMisuseError {
					err: "length-0 path in route".to_string()
				}))
			}
		}

		let mut onion_session_privs = Vec::with_capacity(route.paths.len());
		for _ in 0..route.paths.len() {
			onion_session_privs.push(keys_manager.get_secure_random_bytes());
		}

		let (total_msat, payment_hash, payment_secret) = {
			let mut outbounds = self.pending_outbound_payments.lock().unwrap();
			match outbounds.get_mut(&payment_id) {
				Some(payment) => {
					let res = match payment {
						PendingOutboundPayment::Retryable {
							total_msat, payment_hash, payment_secret, pending_amt_msat, ..
						} => {
							let retry_amt_msat: u64 = route.paths.iter().map(|path| path.last().unwrap().fee_msat).sum();
							if retry_amt_msat + *pending_amt_msat > *total_msat * (100 + RETRY_OVERFLOW_PERCENTAGE) / 100 {
								return Err(PaymentSendFailure::ParameterError(APIError::APIMisuseError {
									err: format!("retry_amt_msat of {} will put pending_amt_msat (currently: {}) more than 10% over total_payment_amt_msat of {}", retry_amt_msat, pending_amt_msat, total_msat).to_string()
								}))
							}
							(*total_msat, *payment_hash, *payment_secret)
						},
						PendingOutboundPayment::Legacy { .. } => {
							return Err(PaymentSendFailure::ParameterError(APIError::APIMisuseError {
								err: "Unable to retry payments that were initially sent on LDK versions prior to 0.0.102".to_string()
							}))
						},
						PendingOutboundPayment::Fulfilled { .. } => {
							return Err(PaymentSendFailure::ParameterError(APIError::APIMisuseError {
								err: "Payment already completed".to_owned()
							}));
						},
						PendingOutboundPayment::Abandoned { .. } => {
							return Err(PaymentSendFailure::ParameterError(APIError::APIMisuseError {
								err: "Payment already abandoned (with some HTLCs still pending)".to_owned()
							}));
						},
					};
					for (path, session_priv_bytes) in route.paths.iter().zip(onion_session_privs.iter()) {
						assert!(payment.insert(*session_priv_bytes, path));
					}
					res
				},
				None =>
					return Err(PaymentSendFailure::ParameterError(APIError::APIMisuseError {
						err: format!("Payment with ID {} not found", log_bytes!(payment_id.0)),
					})),
			}
		};
		self.send_payment_internal(route, payment_hash, &payment_secret, None, payment_id, Some(total_msat), onion_session_privs, keys_manager, best_block_height, send_payment_along_path)
	}

	pub(super) fn send_probe<K: Deref, F>(
		&self, hops: Vec<RouteHop>, probing_cookie_secret: [u8; 32], keys_manager: &K,
		best_block_height: u32, send_payment_along_path: F
	) -> Result<(PaymentHash, PaymentId), PaymentSendFailure>
	where
		K::Target: KeysInterface,
		F: Fn(&Vec<RouteHop>, &Option<PaymentParameters>, &PaymentHash, &Option<PaymentSecret>, u64,
		   u32, PaymentId, &Option<PaymentPreimage>, [u8; 32]) -> Result<(), APIError>
	{
		let payment_id = PaymentId(keys_manager.get_secure_random_bytes());

		let payment_hash = probing_cookie_from_id(&payment_id, probing_cookie_secret);

		if hops.len() < 2 {
			return Err(PaymentSendFailure::ParameterError(APIError::APIMisuseError {
				err: "No need probing a path with less than two hops".to_string()
			}))
		}

		let route = Route { paths: vec![hops], payment_params: None };
		let onion_session_privs = self.add_new_pending_payment(payment_hash, None, payment_id, &route, keys_manager, best_block_height)?;

		match self.send_payment_internal(&route, payment_hash, &None, None, payment_id, None, onion_session_privs, keys_manager, best_block_height, send_payment_along_path) {
			Ok(()) => Ok((payment_hash, payment_id)),
			Err(e) => Err(e)
		}
	}

	#[cfg(test)]
	pub(super) fn test_add_new_pending_payment<K: Deref>(
		&self, payment_hash: PaymentHash, payment_secret: Option<PaymentSecret>, payment_id: PaymentId,
		route: &Route, keys_manager: &K, best_block_height: u32
	) -> Result<Vec<[u8; 32]>, PaymentSendFailure> where K::Target: KeysInterface {
		self.add_new_pending_payment(payment_hash, payment_secret, payment_id, route, keys_manager, best_block_height)
	}

	fn add_new_pending_payment<K: Deref>(
		&self, payment_hash: PaymentHash, payment_secret: Option<PaymentSecret>, payment_id: PaymentId,
		route: &Route, keys_manager: &K, best_block_height: u32
	) -> Result<Vec<[u8; 32]>, PaymentSendFailure> where K::Target: KeysInterface {
		let mut onion_session_privs = Vec::with_capacity(route.paths.len());
		for _ in 0..route.paths.len() {
			onion_session_privs.push(keys_manager.get_secure_random_bytes());
		}

		let mut pending_outbounds = self.pending_outbound_payments.lock().unwrap();
		match pending_outbounds.entry(payment_id) {
			hash_map::Entry::Occupied(_) => Err(PaymentSendFailure::DuplicatePayment),
			hash_map::Entry::Vacant(entry) => {
				let payment = entry.insert(PendingOutboundPayment::Retryable {
					session_privs: HashSet::new(),
					pending_amt_msat: 0,
					pending_fee_msat: Some(0),
					payment_hash,
					payment_secret,
					starting_block_height: best_block_height,
					total_msat: route.get_total_amount(),
				});

				for (path, session_priv_bytes) in route.paths.iter().zip(onion_session_privs.iter()) {
					assert!(payment.insert(*session_priv_bytes, path));
				}

				Ok(onion_session_privs)
			},
		}
	}

	fn send_payment_internal<K: Deref, F>(
		&self, route: &Route, payment_hash: PaymentHash, payment_secret: &Option<PaymentSecret>,
		keysend_preimage: Option<PaymentPreimage>, payment_id: PaymentId, recv_value_msat: Option<u64>,
		onion_session_privs: Vec<[u8; 32]>, keys_manager: &K, best_block_height: u32,
		send_payment_along_path: F
	) -> Result<(), PaymentSendFailure>
	where
		K::Target: KeysInterface,
		F: Fn(&Vec<RouteHop>, &Option<PaymentParameters>, &PaymentHash, &Option<PaymentSecret>, u64,
		   u32, PaymentId, &Option<PaymentPreimage>, [u8; 32]) -> Result<(), APIError>
	{
		if route.paths.len() < 1 {
			return Err(PaymentSendFailure::ParameterError(APIError::InvalidRoute{err: "There must be at least one path to send over"}));
		}
		if payment_secret.is_none() && route.paths.len() > 1 {
			return Err(PaymentSendFailure::ParameterError(APIError::APIMisuseError{err: "Payment secret is required for multi-path payments".to_string()}));
		}
		let mut total_value = 0;
		let our_node_id = keys_manager.get_node_id(Recipient::Node).unwrap(); // TODO no unwrap
		let mut path_errs = Vec::with_capacity(route.paths.len());
		'path_check: for path in route.paths.iter() {
			if path.len() < 1 || path.len() > 20 {
				path_errs.push(Err(APIError::InvalidRoute{err: "Path didn't go anywhere/had bogus size"}));
				continue 'path_check;
			}
			for (idx, hop) in path.iter().enumerate() {
				if idx != path.len() - 1 && hop.pubkey == our_node_id {
					path_errs.push(Err(APIError::InvalidRoute{err: "Path went through us but wasn't a simple rebalance loop to us"}));
					continue 'path_check;
				}
			}
			total_value += path.last().unwrap().fee_msat;
			path_errs.push(Ok(()));
		}
		if path_errs.iter().any(|e| e.is_err()) {
			return Err(PaymentSendFailure::PathParameterError(path_errs));
		}
		if let Some(amt_msat) = recv_value_msat {
			debug_assert!(amt_msat >= total_value);
			total_value = amt_msat;
		}

		let cur_height = best_block_height + 1;
		let mut results = Vec::new();
		debug_assert_eq!(route.paths.len(), onion_session_privs.len());
		for (path, session_priv) in route.paths.iter().zip(onion_session_privs.into_iter()) {
			let mut path_res = send_payment_along_path(&path, &route.payment_params, &payment_hash, payment_secret, total_value, cur_height, payment_id, &keysend_preimage, session_priv);
			match path_res {
				Ok(_) => {},
				Err(APIError::MonitorUpdateInProgress) => {
					// While a MonitorUpdateInProgress is an Err(_), the payment is still
					// considered "in flight" and we shouldn't remove it from the
					// PendingOutboundPayment set.
				},
				Err(_) => {
					let mut pending_outbounds = self.pending_outbound_payments.lock().unwrap();
					if let Some(payment) = pending_outbounds.get_mut(&payment_id) {
						let removed = payment.remove(&session_priv, Some(path));
						debug_assert!(removed, "This can't happen as the payment has an entry for this path added by callers");
					} else {
						debug_assert!(false, "This can't happen as the payment was added by callers");
						path_res = Err(APIError::APIMisuseError { err: "Internal error: payment disappeared during processing. Please report this bug!".to_owned() });
					}
				}
			}
			results.push(path_res);
		}
		let mut has_ok = false;
		let mut has_err = false;
		let mut pending_amt_unsent = 0;
		let mut max_unsent_cltv_delta = 0;
		for (res, path) in results.iter().zip(route.paths.iter()) {
			if res.is_ok() { has_ok = true; }
			if res.is_err() { has_err = true; }
			if let &Err(APIError::MonitorUpdateInProgress) = res {
				// MonitorUpdateInProgress is inherently unsafe to retry, so we call it a
				// PartialFailure.
				has_err = true;
				has_ok = true;
			} else if res.is_err() {
				pending_amt_unsent += path.last().unwrap().fee_msat;
				max_unsent_cltv_delta = cmp::max(max_unsent_cltv_delta, path.last().unwrap().cltv_expiry_delta);
			}
		}
		if has_err && has_ok {
			Err(PaymentSendFailure::PartialFailure {
				results,
				payment_id,
				failed_paths_retry: if pending_amt_unsent != 0 {
					if let Some(payment_params) = &route.payment_params {
						Some(RouteParameters {
							payment_params: payment_params.clone(),
							final_value_msat: pending_amt_unsent,
							final_cltv_expiry_delta: max_unsent_cltv_delta,
						})
					} else { None }
				} else { None },
			})
		} else if has_err {
			// If we failed to send any paths, we should remove the new PaymentId from the
			// `pending_outbound_payments` map, as the user isn't expected to `abandon_payment`.
			let removed = self.pending_outbound_payments.lock().unwrap().remove(&payment_id).is_some();
			debug_assert!(removed, "We should always have a pending payment to remove here");
			Err(PaymentSendFailure::AllFailedResendSafe(results.drain(..).map(|r| r.unwrap_err()).collect()))
		} else {
			Ok(())
		}
	}

	#[cfg(test)]
	pub(super) fn test_send_payment_internal<K: Deref, F>(
		&self, route: &Route, payment_hash: PaymentHash, payment_secret: &Option<PaymentSecret>,
		keysend_preimage: Option<PaymentPreimage>, payment_id: PaymentId, recv_value_msat: Option<u64>,
		onion_session_privs: Vec<[u8; 32]>, keys_manager: &K, best_block_height: u32,
		send_payment_along_path: F
	) -> Result<(), PaymentSendFailure>
	where
		K::Target: KeysInterface,
		F: Fn(&Vec<RouteHop>, &Option<PaymentParameters>, &PaymentHash, &Option<PaymentSecret>, u64,
		   u32, PaymentId, &Option<PaymentPreimage>, [u8; 32]) -> Result<(), APIError>
	{
		self.send_payment_internal(route, payment_hash, payment_secret, keysend_preimage, payment_id,
			recv_value_msat, onion_session_privs, keys_manager, best_block_height,
			send_payment_along_path)
	}

	pub(super) fn claim_htlc<L: Deref>(
		&self, payment_id: PaymentId, payment_preimage: PaymentPreimage, session_priv: SecretKey,
		path: Vec<RouteHop>, from_onchain: bool, pending_events: &Mutex<Vec<events::Event>>, logger: &L
	) where L::Target: Logger {
		let mut session_priv_bytes = [0; 32];
		session_priv_bytes.copy_from_slice(&session_priv[..]);
		let mut outbounds = self.pending_outbound_payments.lock().unwrap();
		let mut pending_events = pending_events.lock().unwrap();
		if let hash_map::Entry::Occupied(mut payment) = outbounds.entry(payment_id) {
			if !payment.get().is_fulfilled() {
				let payment_hash = PaymentHash(Sha256::hash(&payment_preimage.0).into_inner());
				let fee_paid_msat = payment.get().get_pending_fee_msat();
				pending_events.push(
					events::Event::PaymentSent {
						payment_id: Some(payment_id),
						payment_preimage,
						payment_hash,
						fee_paid_msat,
					}
				);
				payment.get_mut().mark_fulfilled();
			}

			if from_onchain {
				// We currently immediately remove HTLCs which were fulfilled on-chain.
				// This could potentially lead to removing a pending payment too early,
				// with a reorg of one block causing us to re-add the fulfilled payment on
				// restart.
				// TODO: We should have a second monitor event that informs us of payments
				// irrevocably fulfilled.
				if payment.get_mut().remove(&session_priv_bytes, Some(&path)) {
					let payment_hash = Some(PaymentHash(Sha256::hash(&payment_preimage.0).into_inner()));
					pending_events.push(
						events::Event::PaymentPathSuccessful {
							payment_id,
							payment_hash,
							path,
						}
					);
				}
			}
		} else {
			log_trace!(logger, "Received duplicative fulfill for HTLC with payment_preimage {}", log_bytes!(payment_preimage.0));
		}
	}

	pub(super) fn finalize_claims(&self, sources: Vec<HTLCSource>, pending_events: &Mutex<Vec<events::Event>>) {
		let mut outbounds = self.pending_outbound_payments.lock().unwrap();
		let mut pending_events = pending_events.lock().unwrap();
		for source in sources {
			if let HTLCSource::OutboundRoute { session_priv, payment_id, path, .. } = source {
				let mut session_priv_bytes = [0; 32];
				session_priv_bytes.copy_from_slice(&session_priv[..]);
				if let hash_map::Entry::Occupied(mut payment) = outbounds.entry(payment_id) {
					assert!(payment.get().is_fulfilled());
					if payment.get_mut().remove(&session_priv_bytes, None) {
						pending_events.push(
							events::Event::PaymentPathSuccessful {
								payment_id,
								payment_hash: payment.get().payment_hash(),
								path,
							}
						);
					}
				}
			}
		}
	}

	pub(super) fn remove_stale_resolved_payments(&self, pending_events: &Mutex<Vec<events::Event>>) {
		// If an outbound payment was completed, and no pending HTLCs remain, we should remove it
		// from the map. However, if we did that immediately when the last payment HTLC is claimed,
		// this could race the user making a duplicate send_payment call and our idempotency
		// guarantees would be violated. Instead, we wait a few timer ticks to do the actual
		// removal. This should be more than sufficient to ensure the idempotency of any
		// `send_payment` calls that were made at the same time the `PaymentSent` event was being
		// processed.
		let mut pending_outbound_payments = self.pending_outbound_payments.lock().unwrap();
		let pending_events = pending_events.lock().unwrap();
		pending_outbound_payments.retain(|payment_id, payment| {
			if let PendingOutboundPayment::Fulfilled { session_privs, timer_ticks_without_htlcs, .. } = payment {
				let mut no_remaining_entries = session_privs.is_empty();
				if no_remaining_entries {
					for ev in pending_events.iter() {
						match ev {
							events::Event::PaymentSent { payment_id: Some(ev_payment_id), .. } |
								events::Event::PaymentPathSuccessful { payment_id: ev_payment_id, .. } |
								events::Event::PaymentPathFailed { payment_id: Some(ev_payment_id), .. } => {
									if payment_id == ev_payment_id {
										no_remaining_entries = false;
										break;
									}
								},
							_ => {},
						}
					}
				}
				if no_remaining_entries {
					*timer_ticks_without_htlcs += 1;
					*timer_ticks_without_htlcs <= IDEMPOTENCY_TIMEOUT_TICKS
				} else {
					*timer_ticks_without_htlcs = 0;
					true
				}
			} else { true }
		});
	}

	pub(super) fn fail_htlc<L: Deref>(
		&self, source: &HTLCSource, payment_hash: &PaymentHash, onion_error: &HTLCFailReason,
		path: &Vec<RouteHop>, session_priv: &SecretKey, payment_id: &PaymentId,
		payment_params: &Option<PaymentParameters>, probing_cookie_secret: [u8; 32],
		secp_ctx: &Secp256k1<secp256k1::All>, pending_events: &Mutex<Vec<events::Event>>, logger: &L
	) where L::Target: Logger {
		let mut session_priv_bytes = [0; 32];
		session_priv_bytes.copy_from_slice(&session_priv[..]);
		let mut outbounds = self.pending_outbound_payments.lock().unwrap();
		let mut all_paths_failed = false;
		let mut full_failure_ev = None;
		if let hash_map::Entry::Occupied(mut payment) = outbounds.entry(*payment_id) {
			if !payment.get_mut().remove(&session_priv_bytes, Some(&path)) {
				log_trace!(logger, "Received duplicative fail for HTLC with payment_hash {}", log_bytes!(payment_hash.0));
				return
			}
			if payment.get().is_fulfilled() {
				log_trace!(logger, "Received failure of HTLC with payment_hash {} after payment completion", log_bytes!(payment_hash.0));
				return
			}
			if payment.get().remaining_parts() == 0 {
				all_paths_failed = true;
				if payment.get().abandoned() {
					full_failure_ev = Some(events::Event::PaymentFailed {
						payment_id: *payment_id,
						payment_hash: payment.get().payment_hash().expect("PendingOutboundPayments::RetriesExceeded always has a payment hash set"),
					});
					payment.remove();
				}
			}
		} else {
			log_trace!(logger, "Received duplicative fail for HTLC with payment_hash {}", log_bytes!(payment_hash.0));
			return
		}
		let mut retry = if let Some(payment_params_data) = payment_params {
			let path_last_hop = path.last().expect("Outbound payments must have had a valid path");
			Some(RouteParameters {
				payment_params: payment_params_data.clone(),
				final_value_msat: path_last_hop.fee_msat,
				final_cltv_expiry_delta: path_last_hop.cltv_expiry_delta,
			})
		} else { None };
		log_trace!(logger, "Failing outbound payment HTLC with payment_hash {}", log_bytes!(payment_hash.0));

		let path_failure = {
			#[cfg(test)]
			let (network_update, short_channel_id, payment_retryable, onion_error_code, onion_error_data) = onion_error.decode_onion_failure(secp_ctx, logger, &source);
			#[cfg(not(test))]
			let (network_update, short_channel_id, payment_retryable, _, _) = onion_error.decode_onion_failure(secp_ctx, logger, &source);

			if payment_is_probe(payment_hash, &payment_id, probing_cookie_secret) {
				if !payment_retryable {
					events::Event::ProbeSuccessful {
						payment_id: *payment_id,
						payment_hash: payment_hash.clone(),
						path: path.clone(),
					}
				} else {
					events::Event::ProbeFailed {
						payment_id: *payment_id,
						payment_hash: payment_hash.clone(),
						path: path.clone(),
						short_channel_id,
					}
				}
			} else {
				// TODO: If we decided to blame ourselves (or one of our channels) in
				// process_onion_failure we should close that channel as it implies our
				// next-hop is needlessly blaming us!
				if let Some(scid) = short_channel_id {
					retry.as_mut().map(|r| r.payment_params.previously_failed_channels.push(scid));
				}
				events::Event::PaymentPathFailed {
					payment_id: Some(*payment_id),
					payment_hash: payment_hash.clone(),
					payment_failed_permanently: !payment_retryable,
					network_update,
					all_paths_failed,
					path: path.clone(),
					short_channel_id,
					retry,
					#[cfg(test)]
					error_code: onion_error_code,
					#[cfg(test)]
					error_data: onion_error_data
				}
			}
		};
		let mut pending_events = pending_events.lock().unwrap();
		pending_events.push(path_failure);
		if let Some(ev) = full_failure_ev { pending_events.push(ev); }
	}

	pub(super) fn abandon_payment(&self, payment_id: PaymentId) -> Option<events::Event> {
		let mut failed_ev = None;
		let mut outbounds = self.pending_outbound_payments.lock().unwrap();
		if let hash_map::Entry::Occupied(mut payment) = outbounds.entry(payment_id) {
			if let Ok(()) = payment.get_mut().mark_abandoned() {
				if payment.get().remaining_parts() == 0 {
					failed_ev = Some(events::Event::PaymentFailed {
						payment_id,
						payment_hash: payment.get().payment_hash().expect("PendingOutboundPayments::RetriesExceeded always has a payment hash set"),
					});
					payment.remove();
				}
			}
		}
		failed_ev
	}

	#[cfg(test)]
	pub fn has_pending_payments(&self) -> bool {
		!self.pending_outbound_payments.lock().unwrap().is_empty()
	}

	#[cfg(test)]
	pub fn clear_pending_payments(&self) {
		self.pending_outbound_payments.lock().unwrap().clear()
	}
}

/// Returns whether a payment with the given [`PaymentHash`] and [`PaymentId`] is, in fact, a
/// payment probe.
pub(super) fn payment_is_probe(payment_hash: &PaymentHash, payment_id: &PaymentId,
	probing_cookie_secret: [u8; 32]) -> bool
{
	let target_payment_hash = probing_cookie_from_id(payment_id, probing_cookie_secret);
	target_payment_hash == *payment_hash
}

/// Returns the 'probing cookie' for the given [`PaymentId`].
fn probing_cookie_from_id(payment_id: &PaymentId, probing_cookie_secret: [u8; 32]) -> PaymentHash {
	let mut preimage = [0u8; 64];
	preimage[..32].copy_from_slice(&probing_cookie_secret);
	preimage[32..].copy_from_slice(&payment_id.0);
	PaymentHash(Sha256::hash(&preimage).into_inner())
}

impl_writeable_tlv_based_enum_upgradable!(PendingOutboundPayment,
	(0, Legacy) => {
		(0, session_privs, required),
	},
	(1, Fulfilled) => {
		(0, session_privs, required),
		(1, payment_hash, option),
		(3, timer_ticks_without_htlcs, (default_value, 0)),
	},
	(2, Retryable) => {
		(0, session_privs, required),
		(1, pending_fee_msat, option),
		(2, payment_hash, required),
		(4, payment_secret, option),
		(6, total_msat, required),
		(8, pending_amt_msat, required),
		(10, starting_block_height, required),
	},
	(3, Abandoned) => {
		(0, session_privs, required),
		(2, payment_hash, required),
	},
);
