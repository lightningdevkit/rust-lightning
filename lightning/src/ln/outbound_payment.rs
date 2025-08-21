// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Utilities to send payments and manage outbound payment information.

use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{self, Secp256k1, SecretKey};
use lightning_invoice::Bolt11Invoice;

use crate::blinded_path::{IntroductionNode, NodeIdLookUp};
use crate::events::{self, PaidBolt12Invoice, PaymentFailureReason};
use crate::ln::channel_state::ChannelDetails;
use crate::ln::channelmanager::{EventCompletionAction, HTLCSource, PaymentId};
use crate::ln::onion_utils;
use crate::ln::onion_utils::{DecodedOnionFailure, HTLCFailReason};
use crate::offers::invoice::{Bolt12Invoice, DerivedSigningPubkey, InvoiceBuilder};
use crate::offers::invoice_request::InvoiceRequest;
use crate::offers::nonce::Nonce;
use crate::offers::static_invoice::StaticInvoice;
use crate::routing::router::{
	BlindedTail, InFlightHtlcs, Path, PaymentParameters, Route, RouteParameters,
	RouteParametersConfig, Router,
};
use crate::sign::{EntropySource, NodeSigner, Recipient};
use crate::types::features::Bolt12InvoiceFeatures;
use crate::types::payment::{PaymentHash, PaymentPreimage, PaymentSecret};
use crate::util::errors::APIError;
use crate::util::logger::Logger;
use crate::util::ser::ReadableArgs;
#[cfg(feature = "std")]
use crate::util::time::Instant;

use core::fmt::{self, Display, Formatter};
use core::ops::Deref;
use core::sync::atomic::{AtomicBool, Ordering};
use core::time::Duration;

use crate::prelude::*;
use crate::sync::Mutex;

/// The number of ticks of [`ChannelManager::timer_tick_occurred`] until we time-out the idempotency
/// of payments by [`PaymentId`]. See [`OutboundPayments::remove_stale_payments`].
///
/// [`ChannelManager::timer_tick_occurred`]: crate::ln::channelmanager::ChannelManager::timer_tick_occurred
pub(crate) const IDEMPOTENCY_TIMEOUT_TICKS: u8 = 7;

/// The default relative expiration to wait for a pending outbound HTLC to a often-offline
/// payee to fulfill.
const ASYNC_PAYMENT_TIMEOUT_RELATIVE_EXPIRY: Duration = Duration::from_secs(60 * 60 * 24 * 7);

#[cfg(test)]
pub(crate) const TEST_ASYNC_PAYMENT_TIMEOUT_RELATIVE_EXPIRY: Duration =
	ASYNC_PAYMENT_TIMEOUT_RELATIVE_EXPIRY;

/// Stores the session_priv for each part of a payment that is still pending. For versions 0.0.102
/// and later, also stores information for retrying the payment.
pub(crate) enum PendingOutboundPayment {
	Legacy {
		session_privs: HashSet<[u8; 32]>,
	},
	/// Used when we are waiting for an Offer to come back from a BIP 353 resolution
	AwaitingOffer {
		expiration: StaleExpiration,
		retry_strategy: Retry,
		route_params_config: RouteParametersConfig,
		/// Human Readable Names-originated payments should always specify an explicit amount to
		/// send up-front, which we track here and enforce once we receive the offer.
		amount_msats: u64,
		payer_note: Option<String>,
	},
	AwaitingInvoice {
		expiration: StaleExpiration,
		retry_strategy: Retry,
		route_params_config: RouteParametersConfig,
		retryable_invoice_request: Option<RetryableInvoiceRequest>,
	},
	// Represents the state after the invoice has been received, transitioning from the corresponding
	// `AwaitingInvoice` state.
	// Helps avoid holding the `OutboundPayments::pending_outbound_payments` lock during pathfinding.
	InvoiceReceived {
		payment_hash: PaymentHash,
		retry_strategy: Retry,
		// Currently unused, but replicated from `AwaitingInvoice` to avoid potential
		// race conditions where this field might be missing upon reload. It may be required
		// for future retries.
		route_params_config: RouteParametersConfig,
	},
	// This state applies when we are paying an often-offline recipient and another node on the
	// network served us a static invoice on the recipient's behalf in response to our invoice
	// request. As a result, once a payment gets in this state it will remain here until the recipient
	// comes back online, which may take hours or even days.
	StaticInvoiceReceived {
		payment_hash: PaymentHash,
		keysend_preimage: PaymentPreimage,
		retry_strategy: Retry,
		route_params: RouteParameters,
		invoice_request: InvoiceRequest,
		static_invoice: StaticInvoice,
		// Whether we should pay the static invoice asynchronously, i.e. by setting
		// [`UpdateAddHTLC::hold_htlc`] so our channel counterparty(s) hold the HTLC(s) for us until the
		// recipient comes online, allowing us to go offline after locking in the HTLC(s).
		hold_htlcs_at_next_hop: bool,
		// The deadline as duration since the Unix epoch for the async recipient to come online,
		// after which we'll fail the payment.
		//
		// Defaults to creation time + [`ASYNC_PAYMENT_TIMEOUT_RELATIVE_EXPIRY`].
		expiry_time: Duration,
	},
	Retryable {
		retry_strategy: Option<Retry>,
		attempts: PaymentAttempts,
		payment_params: Option<PaymentParameters>,
		session_privs: HashSet<[u8; 32]>,
		payment_hash: PaymentHash,
		payment_secret: Option<PaymentSecret>,
		payment_metadata: Option<Vec<u8>>,
		keysend_preimage: Option<PaymentPreimage>,
		invoice_request: Option<InvoiceRequest>,
		// Storing the BOLT 12 invoice here to allow Proof of Payment after
		// the payment is made.
		bolt12_invoice: Option<PaidBolt12Invoice>,
		custom_tlvs: Vec<(u64, Vec<u8>)>,
		pending_amt_msat: u64,
		/// Used to track the fee paid. Present iff the payment was serialized on 0.0.103+.
		pending_fee_msat: Option<u64>,
		/// The total payment amount across all paths, used to verify that a retry is not overpaying.
		total_msat: u64,
		/// Our best known block height at the time this payment was initiated.
		starting_block_height: u32,
		remaining_max_total_routing_fee_msat: Option<u64>,
	},
	/// When a pending payment is fulfilled, we continue tracking it until all pending HTLCs have
	/// been resolved. This ensures we don't look up pending payments in ChannelMonitors on restart
	/// and add a pending payment that was already fulfilled.
	Fulfilled {
		session_privs: HashSet<[u8; 32]>,
		/// Filled in for any payment which moved to `Fulfilled` on LDK 0.0.104 or later.
		payment_hash: Option<PaymentHash>,
		timer_ticks_without_htlcs: u8,
		/// The total payment amount across all paths, used to be able to issue `PaymentSent`.
		total_msat: Option<u64>,
	},
	/// When we've decided to give up retrying a payment, we mark it as abandoned so we can eventually
	/// generate a `PaymentFailed` event when all HTLCs have irrevocably failed.
	Abandoned {
		session_privs: HashSet<[u8; 32]>,
		payment_hash: PaymentHash,
		/// Will be `None` if the payment was serialized before 0.0.115 or if downgrading to 0.0.124
		/// or later with a reason that was added after.
		reason: Option<PaymentFailureReason>,
		/// The total payment amount across all paths, used to be able to issue `PaymentSent` if
		/// an HTLC still happens to succeed after we marked the payment as abandoned.
		total_msat: Option<u64>,
	},
}

#[derive(Clone)]
pub(crate) struct RetryableInvoiceRequest {
	pub(crate) invoice_request: InvoiceRequest,
	pub(crate) nonce: Nonce,
	pub(super) needs_retry: bool,
}

impl_writeable_tlv_based!(RetryableInvoiceRequest, {
	(0, invoice_request, required),
	(1, needs_retry, (default_value, true)),
	(2, nonce, required),
});

impl PendingOutboundPayment {
	fn bolt12_invoice(&self) -> Option<&PaidBolt12Invoice> {
		match self {
			PendingOutboundPayment::Retryable { bolt12_invoice, .. } => bolt12_invoice.as_ref(),
			_ => None,
		}
	}

	fn increment_attempts(&mut self) {
		if let PendingOutboundPayment::Retryable { attempts, .. } = self {
			attempts.count += 1;
		}
	}
	#[rustfmt::skip]
	fn is_auto_retryable_now(&self) -> bool {
		match self {
			PendingOutboundPayment::Retryable {
				retry_strategy: Some(strategy), attempts, payment_params: Some(_), ..
			} => {
				strategy.is_retryable_now(&attempts)
			},
			_ => false,
		}
	}
	#[rustfmt::skip]
	fn is_retryable_now(&self) -> bool {
		match self {
			PendingOutboundPayment::Retryable { retry_strategy: None, .. } => {
				// We're handling retries manually, we can always retry.
				true
			},
			PendingOutboundPayment::Retryable { retry_strategy: Some(strategy), attempts, .. } => {
				strategy.is_retryable_now(&attempts)
			},
			_ => false,
		}
	}
	pub fn insert_previously_failed_scid(&mut self, scid: u64) {
		if let PendingOutboundPayment::Retryable { payment_params: Some(params), .. } = self {
			params.previously_failed_channels.push(scid);
		}
	}
	pub fn insert_previously_failed_blinded_path(&mut self, blinded_tail: &BlindedTail) {
		if let PendingOutboundPayment::Retryable { payment_params: Some(params), .. } = self {
			params.insert_previously_failed_blinded_path(blinded_tail);
		}
	}
	fn is_awaiting_invoice(&self) -> bool {
		match self {
			PendingOutboundPayment::AwaitingInvoice { .. } => true,
			_ => false,
		}
	}
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

	fn total_msat(&self) -> Option<u64> {
		match self {
			PendingOutboundPayment::Retryable { total_msat, .. } => Some(*total_msat),
			PendingOutboundPayment::Fulfilled { total_msat, .. } => *total_msat,
			PendingOutboundPayment::Abandoned { total_msat, .. } => *total_msat,
			_ => None,
		}
	}

	#[rustfmt::skip]
	fn payment_hash(&self) -> Option<PaymentHash> {
		match self {
			PendingOutboundPayment::Legacy { .. } => None,
			PendingOutboundPayment::AwaitingOffer { .. } => None,
			PendingOutboundPayment::AwaitingInvoice { .. } => None,
			PendingOutboundPayment::InvoiceReceived { payment_hash, .. } => Some(*payment_hash),
			PendingOutboundPayment::StaticInvoiceReceived { payment_hash, .. } => Some(*payment_hash),
			PendingOutboundPayment::Retryable { payment_hash, .. } => Some(*payment_hash),
			PendingOutboundPayment::Fulfilled { payment_hash, .. } => *payment_hash,
			PendingOutboundPayment::Abandoned { payment_hash, .. } => Some(*payment_hash),
		}
	}

	#[rustfmt::skip]
	fn mark_fulfilled(&mut self) {
		let mut session_privs = new_hash_set();
		core::mem::swap(&mut session_privs, match self {
			PendingOutboundPayment::Legacy { session_privs } |
				PendingOutboundPayment::Retryable { session_privs, .. } |
				PendingOutboundPayment::Fulfilled { session_privs, .. } |
				PendingOutboundPayment::Abandoned { session_privs, .. } => session_privs,
			PendingOutboundPayment::AwaitingOffer { .. } |
				PendingOutboundPayment::AwaitingInvoice { .. } |
				PendingOutboundPayment::InvoiceReceived { .. } |
				PendingOutboundPayment::StaticInvoiceReceived { .. } => { debug_assert!(false); return; },
		});
		let payment_hash = self.payment_hash();
		let total_msat = self.total_msat();
		*self = PendingOutboundPayment::Fulfilled { session_privs, payment_hash, timer_ticks_without_htlcs: 0, total_msat };
	}

	#[rustfmt::skip]
	fn mark_abandoned(&mut self, reason: PaymentFailureReason) {
		let session_privs = match self {
			PendingOutboundPayment::Retryable { session_privs, .. } => {
				let mut our_session_privs = new_hash_set();
				core::mem::swap(&mut our_session_privs, session_privs);
				our_session_privs
			},
			_ => new_hash_set(),
		};
		let total_msat = self.total_msat();
		match self {
			Self::Retryable { payment_hash, .. } |
				Self::InvoiceReceived { payment_hash, .. } |
				Self::StaticInvoiceReceived { payment_hash, .. } =>
			{
				*self = Self::Abandoned {
					session_privs,
					payment_hash: *payment_hash,
					reason: Some(reason),
					total_msat,
				};
			},
			_ => {}
		}
	}

	/// panics if path is None and !self.is_fulfilled
	#[rustfmt::skip]
	fn remove(&mut self, session_priv: &[u8; 32], path: Option<&Path>) -> bool {
		let remove_res = match self {
			PendingOutboundPayment::Legacy { session_privs } |
				PendingOutboundPayment::Retryable { session_privs, .. } |
				PendingOutboundPayment::Fulfilled { session_privs, .. } |
				PendingOutboundPayment::Abandoned { session_privs, .. } => {
					session_privs.remove(session_priv)
				},
			PendingOutboundPayment::AwaitingOffer { .. } |
				PendingOutboundPayment::AwaitingInvoice { .. } |
				PendingOutboundPayment::InvoiceReceived { .. } |
				PendingOutboundPayment::StaticInvoiceReceived { .. } => { debug_assert!(false); false },
		};
		if remove_res {
			if let PendingOutboundPayment::Retryable {
				ref mut pending_amt_msat, ref mut pending_fee_msat,
				ref mut remaining_max_total_routing_fee_msat, ..
			} = self {
				let path = path.expect("Removing a failed payment should always come with a path");
				*pending_amt_msat -= path.final_value_msat();
				let path_fee_msat = path.fee_msat();
				if let Some(fee_msat) = pending_fee_msat.as_mut() {
					*fee_msat -= path_fee_msat;
				}

				if let Some(max_total_routing_fee_msat) = remaining_max_total_routing_fee_msat.as_mut() {
					*max_total_routing_fee_msat = max_total_routing_fee_msat.saturating_add(path_fee_msat);
				}
			}
		}
		remove_res
	}

	#[rustfmt::skip]
	pub(super) fn insert(&mut self, session_priv: [u8; 32], path: &Path) -> bool {
		let insert_res = match self {
			PendingOutboundPayment::Legacy { session_privs } |
				PendingOutboundPayment::Retryable { session_privs, .. } => {
					session_privs.insert(session_priv)
				},
			PendingOutboundPayment::AwaitingOffer { .. } |
				PendingOutboundPayment::AwaitingInvoice { .. } |
				PendingOutboundPayment::InvoiceReceived { .. } |
				PendingOutboundPayment::StaticInvoiceReceived { .. } => { debug_assert!(false); false },
			PendingOutboundPayment::Fulfilled { .. } => false,
			PendingOutboundPayment::Abandoned { .. } => false,
		};
		if insert_res {
			if let PendingOutboundPayment::Retryable {
				ref mut pending_amt_msat, ref mut pending_fee_msat,
				ref mut remaining_max_total_routing_fee_msat, ..
			} = self {
					*pending_amt_msat += path.final_value_msat();
					let path_fee_msat = path.fee_msat();
					if let Some(fee_msat) = pending_fee_msat.as_mut() {
						*fee_msat += path_fee_msat;
					}

					if let Some(max_total_routing_fee_msat) = remaining_max_total_routing_fee_msat.as_mut() {
						*max_total_routing_fee_msat = max_total_routing_fee_msat.saturating_sub(path_fee_msat);
					}
			}
		}
		insert_res
	}

	#[rustfmt::skip]
	pub(super) fn remaining_parts(&self) -> usize {
		match self {
			PendingOutboundPayment::Legacy { session_privs } |
				PendingOutboundPayment::Retryable { session_privs, .. } |
				PendingOutboundPayment::Fulfilled { session_privs, .. } |
				PendingOutboundPayment::Abandoned { session_privs, .. } => {
					session_privs.len()
				},
			PendingOutboundPayment::AwaitingInvoice { .. } => 0,
			PendingOutboundPayment::AwaitingOffer { .. } => 0,
			PendingOutboundPayment::InvoiceReceived { .. } => 0,
			PendingOutboundPayment::StaticInvoiceReceived { .. } => 0,
		}
	}
}

/// Strategies available to retry payment path failures.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Retry {
	/// Max number of attempts to retry payment.
	///
	/// Each attempt may be multiple HTLCs along multiple paths if the router decides to split up a
	/// retry, and may retry multiple failed HTLCs at once if they failed around the same time and
	/// were retried along a route from a single call to [`Router::find_route_with_id`].
	Attempts(u32),
	#[cfg(feature = "std")]
	/// Time elapsed before abandoning retries for a payment. At least one attempt at payment is made;
	/// see [`PaymentParameters::expiry_time`] to avoid any attempt at payment after a specific time.
	///
	/// [`PaymentParameters::expiry_time`]: crate::routing::router::PaymentParameters::expiry_time
	Timeout(core::time::Duration),
}

#[cfg(not(feature = "std"))]
impl_writeable_tlv_based_enum_legacy!(Retry,
	;
	(0, Attempts)
);

#[cfg(feature = "std")]
impl_writeable_tlv_based_enum_legacy!(Retry,
	;
	(0, Attempts),
	(2, Timeout)
);

impl Retry {
	#[rustfmt::skip]
	pub(crate) fn is_retryable_now(&self, attempts: &PaymentAttempts) -> bool {
		match (self, attempts) {
			(Retry::Attempts(max_retry_count), PaymentAttempts { count, .. }) => {
				max_retry_count > count
			},
			#[cfg(feature = "std")]
			(Retry::Timeout(max_duration), PaymentAttempts { first_attempted_at, .. }) =>
				*max_duration >= Instant::now().duration_since(*first_attempted_at),
		}
	}
}

#[cfg(feature = "std")]
#[rustfmt::skip]
pub(super) fn has_expired(route_params: &RouteParameters) -> bool {
	if let Some(expiry_time) = route_params.payment_params.expiry_time {
		if let Ok(elapsed) = std::time::SystemTime::UNIX_EPOCH.elapsed() {
			return elapsed > core::time::Duration::from_secs(expiry_time)
		}
	}
	false
}

/// Storing minimal payment attempts information required for determining if a outbound payment can
/// be retried.
pub(crate) struct PaymentAttempts {
	/// This count will be incremented only after the result of the attempt is known. When it's 0,
	/// it means the result of the first attempt is not known yet.
	pub(crate) count: u32,
	/// This field is only used when retry is `Retry::Timeout` which is only build with feature std
	#[cfg(feature = "std")]
	first_attempted_at: Instant,
}

impl PaymentAttempts {
	pub(crate) fn new() -> Self {
		PaymentAttempts {
			count: 0,
			#[cfg(feature = "std")]
			first_attempted_at: Instant::now(),
		}
	}
}

impl Display for PaymentAttempts {
	fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
		#[cfg(not(feature = "std"))]
		return write!(f, "attempts: {}", self.count);
		#[cfg(feature = "std")]
		return write!(
			f,
			"attempts: {}, duration: {}s",
			self.count,
			Instant::now().duration_since(self.first_attempted_at).as_secs()
		);
	}
}

/// How long before a [`PendingOutboundPayment::AwaitingInvoice`] or
/// [`PendingOutboundPayment::AwaitingOffer`] should be considered stale and candidate for removal
/// in [`OutboundPayments::remove_stale_payments`].
#[derive(Clone, Copy)]
pub(crate) enum StaleExpiration {
	/// Number of times [`OutboundPayments::remove_stale_payments`] is called.
	TimerTicks(u64),
	/// Duration since the Unix epoch.
	AbsoluteTimeout(core::time::Duration),
}

impl_writeable_tlv_based_enum_legacy!(StaleExpiration,
	;
	(0, TimerTicks),
	(2, AbsoluteTimeout)
);

/// Indicates an immediate error on [`ChannelManager::send_payment`]. Further errors may be
/// surfaced later via [`Event::PaymentPathFailed`] and [`Event::PaymentFailed`].
///
/// [`ChannelManager::send_payment`]: crate::ln::channelmanager::ChannelManager::send_payment
/// [`Event::PaymentPathFailed`]: crate::events::Event::PaymentPathFailed
/// [`Event::PaymentFailed`]: crate::events::Event::PaymentFailed
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RetryableSendFailure {
	/// The provided [`PaymentParameters::expiry_time`] indicated that the payment has expired or
	/// the BOLT 12 invoice paid to via [`ChannelManager::send_payment_for_bolt12_invoice`] was
	/// expired.
	#[cfg_attr(feature = "std", doc = "")]
	#[cfg_attr(
		feature = "std",
		doc = "Note that this error is *not* caused by [`Retry::Timeout`]."
	)]
	///
	/// [`PaymentParameters::expiry_time`]: crate::routing::router::PaymentParameters::expiry_time
	/// [`ChannelManager::send_payment_for_bolt12_invoice`]: crate::ln::channelmanager::ChannelManager::send_payment_for_bolt12_invoice
	PaymentExpired,
	/// We were unable to find a route to the destination.
	RouteNotFound,
	/// Indicates that a payment for the provided [`PaymentId`] is already in-flight and has not
	/// yet completed (i.e. generated an [`Event::PaymentSent`] or [`Event::PaymentFailed`]).
	///
	/// [`PaymentId`]: crate::ln::channelmanager::PaymentId
	/// [`Event::PaymentSent`]: crate::events::Event::PaymentSent
	/// [`Event::PaymentFailed`]: crate::events::Event::PaymentFailed
	DuplicatePayment,
	/// The [`RecipientOnionFields::payment_metadata`], [`RecipientOnionFields::custom_tlvs`], or
	/// [`BlindedPaymentPath`]s provided are too large and caused us to exceed the maximum onion
	/// packet size of 1300 bytes.
	///
	/// [`BlindedPaymentPath`]: crate::blinded_path::payment::BlindedPaymentPath
	OnionPacketSizeExceeded,
}

/// If a payment fails to send to a route, it can be in one of several states. This enum is returned
/// as the Err() type describing which state the payment is in, see the description of individual
/// enum states for more.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum PaymentSendFailure {
	/// A parameter which was passed to send_payment was invalid, preventing us from attempting to
	/// send the payment at all.
	///
	/// You can freely resend the payment in full (with the parameter error fixed).
	///
	/// Because the payment failed outright, no payment tracking is done and no
	/// [`Event::PaymentPathFailed`] or [`Event::PaymentFailed`] events will be generated.
	///
	/// [`Event::PaymentPathFailed`]: crate::events::Event::PaymentPathFailed
	/// [`Event::PaymentFailed`]: crate::events::Event::PaymentFailed
	ParameterError(APIError),
	/// A parameter in a single path which was passed to send_payment was invalid, preventing us
	/// from attempting to send the payment at all.
	///
	/// You can freely resend the payment in full (with the parameter error fixed).
	///
	/// Because the payment failed outright, no payment tracking is done and no
	/// [`Event::PaymentPathFailed`] or [`Event::PaymentFailed`] events will be generated.
	///
	/// The results here are ordered the same as the paths in the route object which was passed to
	/// send_payment.
	///
	/// [`Event::PaymentPathFailed`]: crate::events::Event::PaymentPathFailed
	/// [`Event::PaymentFailed`]: crate::events::Event::PaymentFailed
	PathParameterError(Vec<Result<(), APIError>>),
	/// All paths which were attempted failed to send, with no channel state change taking place.
	/// You can freely resend the payment in full (though you probably want to do so over different
	/// paths than the ones selected).
	///
	/// Because the payment failed outright, no payment tracking is done and no
	/// [`Event::PaymentPathFailed`] or [`Event::PaymentFailed`] events will be generated.
	///
	/// [`Event::PaymentPathFailed`]: crate::events::Event::PaymentPathFailed
	/// [`Event::PaymentFailed`]: crate::events::Event::PaymentFailed
	AllFailedResendSafe(Vec<APIError>),
	/// Indicates that a payment for the provided [`PaymentId`] is already in-flight and has not
	/// yet completed (i.e. generated an [`Event::PaymentSent`] or [`Event::PaymentFailed`]).
	///
	/// [`PaymentId`]: crate::ln::channelmanager::PaymentId
	/// [`Event::PaymentSent`]: crate::events::Event::PaymentSent
	/// [`Event::PaymentFailed`]: crate::events::Event::PaymentFailed
	DuplicatePayment,
	/// Some paths that were attempted failed to send, though some paths may have succeeded. At least
	/// some paths have irrevocably committed to the HTLC.
	///
	/// The results here are ordered the same as the paths in the route object that was passed to
	/// send_payment.
	///
	/// Any entries that contain `Err(APIError::MonitorUpdateInprogress)` will send once a
	/// [`MonitorEvent::Completed`] is provided for the next-hop channel with the latest update_id.
	///
	/// [`MonitorEvent::Completed`]: crate::chain::channelmonitor::MonitorEvent::Completed
	PartialFailure {
		/// The errors themselves, in the same order as the paths from the route.
		results: Vec<Result<(), APIError>>,
		/// If some paths failed without irrevocably committing to the new HTLC(s), this will
		/// contain a [`RouteParameters`] object for the failing paths.
		failed_paths_retry: Option<RouteParameters>,
		/// The payment id for the payment, which is now at least partially pending.
		payment_id: PaymentId,
	},
}

/// An error when attempting to pay a [`Bolt11Invoice`].
///
/// [`Bolt11Invoice`]: lightning_invoice::Bolt11Invoice
#[derive(Debug)]
pub enum Bolt11PaymentError {
	/// Incorrect amount was provided to [`ChannelManager::pay_for_bolt11_invoice`].
	/// This happens when the user-provided amount is less than an amount specified in the [`Bolt11Invoice`].
	///
	/// [`Bolt11Invoice`]: lightning_invoice::Bolt11Invoice
	/// [`ChannelManager::pay_for_bolt11_invoice`]: crate::ln::channelmanager::ChannelManager::pay_for_bolt11_invoice
	InvalidAmount,
	/// The invoice was valid for the corresponding [`PaymentId`], but sending the payment failed.
	SendingFailed(RetryableSendFailure),
}

/// An error when attempting to pay a [`Bolt12Invoice`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Bolt12PaymentError {
	/// The invoice was not requested.
	UnexpectedInvoice,
	/// Payment for an invoice with the corresponding [`PaymentId`] was already initiated.
	DuplicateInvoice,
	/// The invoice was valid for the corresponding [`PaymentId`], but required unknown features.
	UnknownRequiredFeatures,
	/// The invoice was valid for the corresponding [`PaymentId`], but sending the payment failed.
	SendingFailed(RetryableSendFailure),
	/// Failed to create a blinded path back to ourselves.
	///
	/// We attempted to initiate payment to a [`StaticInvoice`] but failed to create a reply path for
	/// our [`HeldHtlcAvailable`] message.
	///
	/// [`StaticInvoice`]: crate::offers::static_invoice::StaticInvoice
	/// [`HeldHtlcAvailable`]: crate::onion_message::async_payments::HeldHtlcAvailable
	BlindedPathCreationFailed,
}

/// Indicates that we failed to send a payment probe. Further errors may be surfaced later via
/// [`Event::ProbeFailed`].
///
/// [`Event::ProbeFailed`]: crate::events::Event::ProbeFailed
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProbeSendFailure {
	/// We were unable to find a route to the destination.
	RouteNotFound,
	/// A parameter which was passed to [`ChannelManager::send_probe`] was invalid, preventing us from
	/// attempting to send the probe at all.
	///
	/// You can freely resend the probe (with the parameter error fixed).
	///
	/// Because the probe failed outright, no payment tracking is done and no
	/// [`Event::ProbeFailed`] events will be generated.
	///
	/// [`ChannelManager::send_probe`]: crate::ln::channelmanager::ChannelManager::send_probe
	/// [`Event::ProbeFailed`]: crate::events::Event::ProbeFailed
	ParameterError(APIError),
	/// Indicates that a payment for the provided [`PaymentId`] is already in-flight and has not
	/// yet completed (i.e. generated an [`Event::ProbeSuccessful`] or [`Event::ProbeFailed`]).
	///
	/// [`PaymentId`]: crate::ln::channelmanager::PaymentId
	/// [`Event::ProbeSuccessful`]: crate::events::Event::ProbeSuccessful
	/// [`Event::ProbeFailed`]: crate::events::Event::ProbeFailed
	DuplicateProbe,
}

/// Information which is provided, encrypted, to the payment recipient when sending HTLCs.
///
/// This should generally be constructed with data communicated to us from the recipient (via a
/// BOLT11 or BOLT12 invoice).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecipientOnionFields {
	/// The [`PaymentSecret`] is an arbitrary 32 bytes provided by the recipient for us to repeat
	/// in the onion. It is unrelated to `payment_hash` (or [`PaymentPreimage`]) and exists to
	/// authenticate the sender to the recipient and prevent payment-probing (deanonymization)
	/// attacks.
	///
	/// If you do not have one, the [`Route`] you pay over must not contain multiple paths as
	/// multi-path payments require a recipient-provided secret.
	///
	/// Some implementations may reject spontaneous payments with payment secrets, so you may only
	/// want to provide a secret for a spontaneous payment if MPP is needed and you know your
	/// recipient will not reject it.
	pub payment_secret: Option<PaymentSecret>,
	/// The payment metadata serves a similar purpose as [`Self::payment_secret`] but is of
	/// arbitrary length. This gives recipients substantially more flexibility to receive
	/// additional data.
	///
	/// In LDK, while the [`Self::payment_secret`] is fixed based on an internal authentication
	/// scheme to authenticate received payments against expected payments and invoices, this field
	/// is not used in LDK for received payments, and can be used to store arbitrary data in
	/// invoices which will be received with the payment.
	///
	/// Note that this field was added to the lightning specification more recently than
	/// [`Self::payment_secret`] and while nearly all lightning senders support secrets, metadata
	/// may not be supported as universally.
	pub payment_metadata: Option<Vec<u8>>,
	/// See [`Self::custom_tlvs`] for more info.
	pub(super) custom_tlvs: Vec<(u64, Vec<u8>)>,
}

impl_writeable_tlv_based!(RecipientOnionFields, {
	(0, payment_secret, option),
	(1, custom_tlvs, optional_vec),
	(2, payment_metadata, option),
});

impl RecipientOnionFields {
	/// Creates a [`RecipientOnionFields`] from only a [`PaymentSecret`]. This is the most common
	/// set of onion fields for today's BOLT11 invoices - most nodes require a [`PaymentSecret`]
	/// but do not require or provide any further data.
	#[rustfmt::skip]
	pub fn secret_only(payment_secret: PaymentSecret) -> Self {
		Self { payment_secret: Some(payment_secret), payment_metadata: None, custom_tlvs: Vec::new() }
	}

	/// Creates a new [`RecipientOnionFields`] with no fields. This generally does not create
	/// payable HTLCs except for single-path spontaneous payments, i.e. this should generally
	/// only be used for calls to [`ChannelManager::send_spontaneous_payment`]. If you are sending
	/// a spontaneous MPP this will not work as all MPP require payment secrets; you may
	/// instead want to use [`RecipientOnionFields::secret_only`].
	///
	/// [`ChannelManager::send_spontaneous_payment`]: super::channelmanager::ChannelManager::send_spontaneous_payment
	/// [`RecipientOnionFields::secret_only`]: RecipientOnionFields::secret_only
	pub fn spontaneous_empty() -> Self {
		Self { payment_secret: None, payment_metadata: None, custom_tlvs: Vec::new() }
	}

	/// Creates a new [`RecipientOnionFields`] from an existing one, adding custom TLVs. Each
	/// TLV is provided as a `(u64, Vec<u8>)` for the type number and serialized value
	/// respectively. TLV type numbers must be unique and within the range
	/// reserved for custom types, i.e. >= 2^16, otherwise this method will return `Err(())`.
	///
	/// This method will also error for types in the experimental range which have been
	/// standardized within the protocol, which only includes 5482373484 (keysend) for now.
	///
	/// See [`Self::custom_tlvs`] for more info.
	#[rustfmt::skip]
	pub fn with_custom_tlvs(mut self, mut custom_tlvs: Vec<(u64, Vec<u8>)>) -> Result<Self, ()> {
		custom_tlvs.sort_unstable_by_key(|(typ, _)| *typ);
		let mut prev_type = None;
		for (typ, _) in custom_tlvs.iter() {
			if *typ < 1 << 16 { return Err(()); }
			if *typ == 5482373484 { return Err(()); } // keysend
			if *typ == 77_777 { return Err(()); } // invoice requests for async payments
			match prev_type {
				Some(prev) if prev >= *typ => return Err(()),
				_ => {},
			}
			prev_type = Some(*typ);
		}
		self.custom_tlvs = custom_tlvs;
		Ok(self)
	}

	/// Gets the custom TLVs that will be sent or have been received.
	///
	/// Custom TLVs allow sending extra application-specific data with a payment. They provide
	/// additional flexibility on top of payment metadata, as while other implementations may
	/// require `payment_metadata` to reflect metadata provided in an invoice, custom TLVs
	/// do not have this restriction.
	///
	/// Note that if this field is non-empty, it will contain strictly increasing TLVs, each
	/// represented by a `(u64, Vec<u8>)` for its type number and serialized value respectively.
	/// This is validated when setting this field using [`Self::with_custom_tlvs`].
	#[cfg(not(c_bindings))]
	pub fn custom_tlvs(&self) -> &Vec<(u64, Vec<u8>)> {
		&self.custom_tlvs
	}

	/// Gets the custom TLVs that will be sent or have been received.
	///
	/// Custom TLVs allow sending extra application-specific data with a payment. They provide
	/// additional flexibility on top of payment metadata, as while other implementations may
	/// require `payment_metadata` to reflect metadata provided in an invoice, custom TLVs
	/// do not have this restriction.
	///
	/// Note that if this field is non-empty, it will contain strictly increasing TLVs, each
	/// represented by a `(u64, Vec<u8>)` for its type number and serialized value respectively.
	/// This is validated when setting this field using [`Self::with_custom_tlvs`].
	#[cfg(c_bindings)]
	pub fn custom_tlvs(&self) -> Vec<(u64, Vec<u8>)> {
		self.custom_tlvs.clone()
	}

	/// When we have received some HTLC(s) towards an MPP payment, as we receive further HTLC(s) we
	/// have to make sure that some fields match exactly across the parts. For those that aren't
	/// required to match, if they don't match we should remove them so as to not expose data
	/// that's dependent on the HTLC receive order to users.
	///
	/// Here we implement this, first checking compatibility then mutating two objects and then
	/// dropping any remaining non-matching fields from both.
	#[rustfmt::skip]
	pub(super) fn check_merge(&mut self, further_htlc_fields: &mut Self) -> Result<(), ()> {
		if self.payment_secret != further_htlc_fields.payment_secret { return Err(()); }
		if self.payment_metadata != further_htlc_fields.payment_metadata { return Err(()); }

		let tlvs = &mut self.custom_tlvs;
		let further_tlvs = &mut further_htlc_fields.custom_tlvs;

		let even_tlvs = tlvs.iter().filter(|(typ, _)| *typ % 2 == 0);
		let further_even_tlvs = further_tlvs.iter().filter(|(typ, _)| *typ % 2 == 0);
		if even_tlvs.ne(further_even_tlvs) { return Err(()) }

		tlvs.retain(|tlv| further_tlvs.iter().any(|further_tlv| tlv == further_tlv));
		further_tlvs.retain(|further_tlv| tlvs.iter().any(|tlv| tlv == further_tlv));

		Ok(())
	}
}

/// Arguments for [`super::channelmanager::ChannelManager::send_payment_along_path`].
pub(super) struct SendAlongPathArgs<'a> {
	pub path: &'a Path,
	pub payment_hash: &'a PaymentHash,
	pub recipient_onion: &'a RecipientOnionFields,
	pub total_value: u64,
	pub cur_height: u32,
	pub payment_id: PaymentId,
	pub keysend_preimage: &'a Option<PaymentPreimage>,
	pub invoice_request: Option<&'a InvoiceRequest>,
	pub bolt12_invoice: Option<&'a PaidBolt12Invoice>,
	pub session_priv_bytes: [u8; 32],
}

pub(super) struct OutboundPayments {
	pub(super) pending_outbound_payments: Mutex<HashMap<PaymentId, PendingOutboundPayment>>,
	awaiting_invoice: AtomicBool,
	retry_lock: Mutex<()>,
}

impl OutboundPayments {
	pub(super) fn new(
		pending_outbound_payments: HashMap<PaymentId, PendingOutboundPayment>,
	) -> Self {
		let has_invoice_requests = pending_outbound_payments.values().any(|payment| {
			matches!(
				payment,
				PendingOutboundPayment::AwaitingInvoice {
					retryable_invoice_request: Some(invreq), ..
				} if invreq.needs_retry
			)
		});

		Self {
			pending_outbound_payments: Mutex::new(pending_outbound_payments),
			awaiting_invoice: AtomicBool::new(has_invoice_requests),
			retry_lock: Mutex::new(()),
		}
	}

	#[rustfmt::skip]
	pub(super) fn send_payment<R: Deref, ES: Deref, NS: Deref, IH, SP, L: Deref>(
		&self, payment_hash: PaymentHash, recipient_onion: RecipientOnionFields, payment_id: PaymentId,
		retry_strategy: Retry, route_params: RouteParameters, router: &R,
		first_hops: Vec<ChannelDetails>, compute_inflight_htlcs: IH, entropy_source: &ES,
		node_signer: &NS, best_block_height: u32, logger: &L,
		pending_events: &Mutex<VecDeque<(events::Event, Option<EventCompletionAction>)>>, send_payment_along_path: SP,
	) -> Result<(), RetryableSendFailure>
	where
		R::Target: Router,
		ES::Target: EntropySource,
		NS::Target: NodeSigner,
		L::Target: Logger,
		IH: Fn() -> InFlightHtlcs,
		SP: Fn(SendAlongPathArgs) -> Result<(), APIError>,
	{
		self.send_payment_for_non_bolt12_invoice(payment_id, payment_hash, recipient_onion, None, retry_strategy,
			route_params, router, first_hops, &compute_inflight_htlcs, entropy_source, node_signer,
			best_block_height, logger, pending_events, &send_payment_along_path)
	}

	#[rustfmt::skip]
	pub(super) fn send_spontaneous_payment<R: Deref, ES: Deref, NS: Deref, IH, SP, L: Deref>(
		&self, payment_preimage: Option<PaymentPreimage>, recipient_onion: RecipientOnionFields,
		payment_id: PaymentId, retry_strategy: Retry, route_params: RouteParameters, router: &R,
		first_hops: Vec<ChannelDetails>, inflight_htlcs: IH, entropy_source: &ES,
		node_signer: &NS, best_block_height: u32, logger: &L,
		pending_events: &Mutex<VecDeque<(events::Event, Option<EventCompletionAction>)>>, send_payment_along_path: SP
	) -> Result<PaymentHash, RetryableSendFailure>
	where
		R::Target: Router,
		ES::Target: EntropySource,
		NS::Target: NodeSigner,
		L::Target: Logger,
		IH: Fn() -> InFlightHtlcs,
		SP: Fn(SendAlongPathArgs) -> Result<(), APIError>,
	{
		let preimage = payment_preimage
			.unwrap_or_else(|| PaymentPreimage(entropy_source.get_secure_random_bytes()));
		let payment_hash = PaymentHash(Sha256::hash(&preimage.0).to_byte_array());
		self.send_payment_for_non_bolt12_invoice(payment_id, payment_hash, recipient_onion, Some(preimage),
			retry_strategy, route_params, router, first_hops, inflight_htlcs, entropy_source,
			node_signer, best_block_height, logger, pending_events, send_payment_along_path)
			.map(|()| payment_hash)
	}

	#[rustfmt::skip]
	pub(super) fn pay_for_bolt11_invoice<R: Deref, ES: Deref, NS: Deref, IH, SP, L: Deref>(
		&self, invoice: &Bolt11Invoice, payment_id: PaymentId,
		amount_msats: Option<u64>,
		route_params_config: RouteParametersConfig,
		retry_strategy: Retry,
		router: &R,
		first_hops: Vec<ChannelDetails>, compute_inflight_htlcs: IH, entropy_source: &ES,
		node_signer: &NS, best_block_height: u32, logger: &L,
		pending_events: &Mutex<VecDeque<(events::Event, Option<EventCompletionAction>)>>, send_payment_along_path: SP,
	) -> Result<(), Bolt11PaymentError>
	where
		R::Target: Router,
		ES::Target: EntropySource,
		NS::Target: NodeSigner,
		L::Target: Logger,
		IH: Fn() -> InFlightHtlcs,
		SP: Fn(SendAlongPathArgs) -> Result<(), APIError>,
	{
		let payment_hash = PaymentHash((*invoice.payment_hash()).to_byte_array());

		let amount = match (invoice.amount_milli_satoshis(), amount_msats) {
			(Some(amt), None) | (None, Some(amt)) => amt,
			(Some(inv_amt), Some(user_amt)) if user_amt < inv_amt => return Err(Bolt11PaymentError::InvalidAmount),
			(Some(_), Some(user_amt)) => user_amt,
			(None, None) => return Err(Bolt11PaymentError::InvalidAmount),
		};

		let mut recipient_onion = RecipientOnionFields::secret_only(*invoice.payment_secret());
		recipient_onion.payment_metadata = invoice.payment_metadata().map(|v| v.clone());

		let payment_params = PaymentParameters::from_bolt11_invoice(invoice)
			.with_user_config_ignoring_fee_limit(route_params_config);

		let mut route_params = RouteParameters::from_payment_params_and_value(payment_params, amount);

		if let Some(max_fee_msat) = route_params_config.max_total_routing_fee_msat {
			route_params.max_total_routing_fee_msat = Some(max_fee_msat);
		}

		self.send_payment_for_non_bolt12_invoice(payment_id, payment_hash, recipient_onion, None, retry_strategy, route_params,
			router, first_hops, compute_inflight_htlcs,
			entropy_source, node_signer, best_block_height, logger,
			pending_events, send_payment_along_path
		).map_err(|err| Bolt11PaymentError::SendingFailed(err))
	}

	#[rustfmt::skip]
	pub(super) fn send_payment_for_bolt12_invoice<
		R: Deref, ES: Deref, NS: Deref, NL: Deref, IH, SP, L: Deref
	>(
		&self, invoice: &Bolt12Invoice, payment_id: PaymentId, router: &R,
		first_hops: Vec<ChannelDetails>, features: Bolt12InvoiceFeatures, inflight_htlcs: IH,
		entropy_source: &ES, node_signer: &NS, node_id_lookup: &NL,
		secp_ctx: &Secp256k1<secp256k1::All>, best_block_height: u32, logger: &L,
		pending_events: &Mutex<VecDeque<(events::Event, Option<EventCompletionAction>)>>,
		send_payment_along_path: SP,
	) -> Result<(), Bolt12PaymentError>
	where
		R::Target: Router,
		ES::Target: EntropySource,
		NS::Target: NodeSigner,
		NL::Target: NodeIdLookUp,
		L::Target: Logger,
		IH: Fn() -> InFlightHtlcs,
		SP: Fn(SendAlongPathArgs) -> Result<(), APIError>,
	{

		let (payment_hash, retry_strategy, params_config, _) = self
			.mark_invoice_received_and_get_details(invoice, payment_id)?;

		if invoice.invoice_features().requires_unknown_bits_from(&features) {
			self.abandon_payment(
				payment_id, PaymentFailureReason::UnknownRequiredFeatures, pending_events,
			);
			return Err(Bolt12PaymentError::UnknownRequiredFeatures);
		}

		let mut route_params = RouteParameters::from_payment_params_and_value(
			PaymentParameters::from_bolt12_invoice(&invoice)
				.with_user_config_ignoring_fee_limit(params_config), invoice.amount_msats()
		);
		if let Some(max_fee_msat) = params_config.max_total_routing_fee_msat {
			route_params.max_total_routing_fee_msat = Some(max_fee_msat);
		}
		let invoice = PaidBolt12Invoice::Bolt12Invoice(invoice.clone());
		self.send_payment_for_bolt12_invoice_internal(
			payment_id, payment_hash, None, None, invoice, route_params, retry_strategy, router, first_hops,
			inflight_htlcs, entropy_source, node_signer, node_id_lookup, secp_ctx, best_block_height,
			logger, pending_events, send_payment_along_path
		)
	}

	#[rustfmt::skip]
	fn send_payment_for_bolt12_invoice_internal<
		R: Deref, ES: Deref, NS: Deref, NL: Deref, IH, SP, L: Deref
	>(
		&self, payment_id: PaymentId, payment_hash: PaymentHash,
		keysend_preimage: Option<PaymentPreimage>, invoice_request: Option<&InvoiceRequest>,
		bolt12_invoice: PaidBolt12Invoice,
		mut route_params: RouteParameters, retry_strategy: Retry, router: &R,
		first_hops: Vec<ChannelDetails>, inflight_htlcs: IH, entropy_source: &ES, node_signer: &NS,
		node_id_lookup: &NL, secp_ctx: &Secp256k1<secp256k1::All>, best_block_height: u32, logger: &L,
		pending_events: &Mutex<VecDeque<(events::Event, Option<EventCompletionAction>)>>,
		send_payment_along_path: SP,
	) -> Result<(), Bolt12PaymentError>
	where
		R::Target: Router,
		ES::Target: EntropySource,
		NS::Target: NodeSigner,
		NL::Target: NodeIdLookUp,
		L::Target: Logger,
		IH: Fn() -> InFlightHtlcs,
		SP: Fn(SendAlongPathArgs) -> Result<(), APIError>,
	{
		// Advance any blinded path where the introduction node is our node.
		if let Ok(our_node_id) = node_signer.get_node_id(Recipient::Node) {
			for path in route_params.payment_params.payee.blinded_route_hints_mut().iter_mut() {
				let introduction_node_id = match path.introduction_node() {
					IntroductionNode::NodeId(pubkey) => *pubkey,
					IntroductionNode::DirectedShortChannelId(direction, scid) => {
						match node_id_lookup.next_node_id(*scid) {
							Some(next_node_id) => *direction.select_pubkey(&our_node_id, &next_node_id),
							None => continue,
						}
					},
				};
				if introduction_node_id == our_node_id {
					let _ = path.advance_path_by_one(node_signer, node_id_lookup, secp_ctx);
				}
			}
		}

		let recipient_onion = RecipientOnionFields {
			payment_secret: None,
			payment_metadata: None,
			custom_tlvs: vec![],
		};
		let route = match self.find_initial_route(
			payment_id, payment_hash, &recipient_onion, keysend_preimage, invoice_request,
			&mut route_params, router, &first_hops, &inflight_htlcs, node_signer, best_block_height,
			logger,
		) {
			Ok(route) => route,
			Err(e) => {
				let reason = match e {
					RetryableSendFailure::PaymentExpired => PaymentFailureReason::PaymentExpired,
					RetryableSendFailure::RouteNotFound => PaymentFailureReason::RouteNotFound,
					RetryableSendFailure::DuplicatePayment => PaymentFailureReason::UnexpectedError,
					RetryableSendFailure::OnionPacketSizeExceeded => PaymentFailureReason::UnexpectedError,
				};
				self.abandon_payment(payment_id, reason, pending_events);
				return Err(Bolt12PaymentError::SendingFailed(e));
			},
		};

		let payment_params = Some(route_params.payment_params.clone());
		let mut outbounds = self.pending_outbound_payments.lock().unwrap();
		let onion_session_privs = match outbounds.entry(payment_id) {
			hash_map::Entry::Occupied(entry) => match entry.get() {
				PendingOutboundPayment::InvoiceReceived { .. } => {
					let (retryable_payment, onion_session_privs) = Self::create_pending_payment(
						payment_hash, recipient_onion.clone(), keysend_preimage, None, Some(bolt12_invoice.clone()), &route,
						Some(retry_strategy), payment_params, entropy_source, best_block_height,
					);
					*entry.into_mut() = retryable_payment;
					onion_session_privs
				},
				PendingOutboundPayment::StaticInvoiceReceived { .. } => {
					let invreq = if let PendingOutboundPayment::StaticInvoiceReceived { invoice_request, .. } = entry.remove() {
						invoice_request
					} else { unreachable!() };
					let (retryable_payment, onion_session_privs) = Self::create_pending_payment(
						payment_hash, recipient_onion.clone(), keysend_preimage, Some(invreq), Some(bolt12_invoice.clone()), &route,
						Some(retry_strategy), payment_params, entropy_source, best_block_height
					);
					outbounds.insert(payment_id, retryable_payment);
					onion_session_privs
				},
				_ => return Err(Bolt12PaymentError::DuplicateInvoice),
			},
			hash_map::Entry::Vacant(_) => return Err(Bolt12PaymentError::UnexpectedInvoice),
		};
		core::mem::drop(outbounds);

		let result = self.pay_route_internal(
			&route, payment_hash, &recipient_onion, keysend_preimage, invoice_request, Some(&bolt12_invoice), payment_id,
			Some(route_params.final_value_msat), &onion_session_privs, false, node_signer,
			best_block_height, &send_payment_along_path
		);
		log_info!(
			logger, "Sending payment with id {} and hash {} returned {:?}", payment_id,
			payment_hash, result
		);
		if let Err(e) = result {
			self.handle_pay_route_err(
				e, payment_id, payment_hash, route, route_params, onion_session_privs, router, first_hops,
				&inflight_htlcs, entropy_source, node_signer, best_block_height, logger, pending_events,
				&send_payment_along_path
			);
		}
		Ok(())
	}

	pub(super) fn static_invoice_received<ES: Deref>(
		&self, invoice: &StaticInvoice, payment_id: PaymentId, hold_htlcs_at_next_hop: bool,
		features: Bolt12InvoiceFeatures, best_block_height: u32, duration_since_epoch: Duration,
		entropy_source: ES,
		pending_events: &Mutex<VecDeque<(events::Event, Option<EventCompletionAction>)>>,
	) -> Result<(), Bolt12PaymentError>
	where
		ES::Target: EntropySource,
	{
		macro_rules! abandon_with_entry {
			($payment: expr, $reason: expr) => {
				assert!(
					matches!($payment.get(), PendingOutboundPayment::AwaitingInvoice { .. }),
					"Generating PaymentFailed for unexpected outbound payment type can result in funds loss"
				);
				pending_events.lock().unwrap().push_back((events::Event::PaymentFailed {
					payment_id,
					payment_hash: None,
					reason: Some($reason),
				}, None));
				$payment.remove();
			}
		}

		match self.pending_outbound_payments.lock().unwrap().entry(payment_id) {
			hash_map::Entry::Occupied(mut entry) => match entry.get_mut() {
				PendingOutboundPayment::AwaitingInvoice {
					retry_strategy,
					retryable_invoice_request,
					route_params_config,
					..
				} => {
					let invreq = &retryable_invoice_request
						.as_ref()
						.ok_or(Bolt12PaymentError::UnexpectedInvoice)?
						.invoice_request;
					if !invoice.is_from_same_offer(invreq) {
						return Err(Bolt12PaymentError::UnexpectedInvoice);
					}
					if invoice.invoice_features().requires_unknown_bits_from(&features) {
						abandon_with_entry!(entry, PaymentFailureReason::UnknownRequiredFeatures);
						return Err(Bolt12PaymentError::UnknownRequiredFeatures);
					}
					if duration_since_epoch
						> invoice.created_at().saturating_add(invoice.relative_expiry())
					{
						abandon_with_entry!(entry, PaymentFailureReason::PaymentExpired);
						return Err(Bolt12PaymentError::SendingFailed(
							RetryableSendFailure::PaymentExpired,
						));
					}

					let amount_msat = match InvoiceBuilder::<DerivedSigningPubkey>::amount_msats(
						invreq,
					) {
						Ok(amt) => amt,
						Err(_) => {
							// We check this during invoice request parsing, when constructing the invreq's
							// contents from its TLV stream.
							debug_assert!(false, "LDK requires an msat amount in either the invreq or the invreq's underlying offer");
							abandon_with_entry!(entry, PaymentFailureReason::UnexpectedError);
							return Err(Bolt12PaymentError::UnknownRequiredFeatures);
						},
					};
					let keysend_preimage =
						PaymentPreimage(entropy_source.get_secure_random_bytes());
					let payment_hash =
						PaymentHash(Sha256::hash(&keysend_preimage.0).to_byte_array());
					let pay_params = PaymentParameters::from_static_invoice(invoice)
						.with_user_config_ignoring_fee_limit(*route_params_config);
					let mut route_params =
						RouteParameters::from_payment_params_and_value(pay_params, amount_msat);
					route_params.max_total_routing_fee_msat =
						route_params_config.max_total_routing_fee_msat;

					if let Err(()) = onion_utils::set_max_path_length(
						&mut route_params,
						&RecipientOnionFields::spontaneous_empty(),
						Some(keysend_preimage),
						Some(invreq),
						best_block_height,
					) {
						abandon_with_entry!(entry, PaymentFailureReason::RouteNotFound);
						return Err(Bolt12PaymentError::SendingFailed(
							RetryableSendFailure::OnionPacketSizeExceeded,
						));
					}

					// If we expect the HTLCs for this payment to be held at our next-hop counterparty, don't
					// retry the payment. In future iterations of this feature, we will send this payment via
					// trampoline and the counterparty will retry on our behalf.
					if hold_htlcs_at_next_hop {
						*retry_strategy = Retry::Attempts(0);
					}
					let absolute_expiry =
						duration_since_epoch.saturating_add(ASYNC_PAYMENT_TIMEOUT_RELATIVE_EXPIRY);

					*entry.into_mut() = PendingOutboundPayment::StaticInvoiceReceived {
						payment_hash,
						keysend_preimage,
						retry_strategy: *retry_strategy,
						route_params,
						hold_htlcs_at_next_hop,
						invoice_request: retryable_invoice_request
							.take()
							.ok_or(Bolt12PaymentError::UnexpectedInvoice)?
							.invoice_request,
						static_invoice: invoice.clone(),
						expiry_time: absolute_expiry,
					};
					return Ok(());
				},
				_ => return Err(Bolt12PaymentError::DuplicateInvoice),
			},
			hash_map::Entry::Vacant(_) => return Err(Bolt12PaymentError::UnexpectedInvoice),
		};
	}

	pub(super) fn send_payment_for_static_invoice<
		R: Deref,
		ES: Deref,
		NS: Deref,
		NL: Deref,
		IH,
		SP,
		L: Deref,
	>(
		&self, payment_id: PaymentId, router: &R, first_hops: Vec<ChannelDetails>,
		inflight_htlcs: IH, entropy_source: &ES, node_signer: &NS, node_id_lookup: &NL,
		secp_ctx: &Secp256k1<secp256k1::All>, best_block_height: u32, logger: &L,
		pending_events: &Mutex<VecDeque<(events::Event, Option<EventCompletionAction>)>>,
		send_payment_along_path: SP,
	) -> Result<(), Bolt12PaymentError>
	where
		R::Target: Router,
		ES::Target: EntropySource,
		NS::Target: NodeSigner,
		NL::Target: NodeIdLookUp,
		L::Target: Logger,
		IH: Fn() -> InFlightHtlcs,
		SP: Fn(SendAlongPathArgs) -> Result<(), APIError>,
	{
		let (
			payment_hash,
			keysend_preimage,
			route_params,
			retry_strategy,
			invoice_request,
			invoice,
		) = match self.pending_outbound_payments.lock().unwrap().entry(payment_id) {
			hash_map::Entry::Occupied(entry) => match entry.get() {
				PendingOutboundPayment::StaticInvoiceReceived {
					payment_hash,
					route_params,
					retry_strategy,
					keysend_preimage,
					invoice_request,
					static_invoice,
					..
				} => (
					*payment_hash,
					*keysend_preimage,
					route_params.clone(),
					*retry_strategy,
					invoice_request.clone(),
					static_invoice.clone(),
				),
				_ => return Err(Bolt12PaymentError::DuplicateInvoice),
			},
			hash_map::Entry::Vacant(_) => return Err(Bolt12PaymentError::UnexpectedInvoice),
		};
		let invoice = PaidBolt12Invoice::StaticInvoice(invoice);
		self.send_payment_for_bolt12_invoice_internal(
			payment_id,
			payment_hash,
			Some(keysend_preimage),
			Some(&invoice_request),
			invoice,
			route_params,
			retry_strategy,
			router,
			first_hops,
			inflight_htlcs,
			entropy_source,
			node_signer,
			node_id_lookup,
			secp_ctx,
			best_block_height,
			logger,
			pending_events,
			send_payment_along_path,
		)
	}

	// Returns whether the data changed and needs to be repersisted.
	pub(super) fn check_retry_payments<R: Deref, ES: Deref, NS: Deref, SP, IH, FH, L: Deref>(
		&self, router: &R, first_hops: FH, inflight_htlcs: IH, entropy_source: &ES,
		node_signer: &NS, best_block_height: u32,
		pending_events: &Mutex<VecDeque<(events::Event, Option<EventCompletionAction>)>>,
		logger: &L, send_payment_along_path: SP,
	) -> bool
	where
		R::Target: Router,
		ES::Target: EntropySource,
		NS::Target: NodeSigner,
		SP: Fn(SendAlongPathArgs) -> Result<(), APIError>,
		IH: Fn() -> InFlightHtlcs,
		FH: Fn() -> Vec<ChannelDetails>,
		L::Target: Logger,
	{
		let _single_thread = self.retry_lock.lock().unwrap();
		let mut should_persist = false;
		loop {
			let mut outbounds = self.pending_outbound_payments.lock().unwrap();
			let mut retry_id_route_params = None;
			for (pmt_id, pmt) in outbounds.iter_mut() {
				if pmt.is_auto_retryable_now() {
					if let PendingOutboundPayment::Retryable {
						pending_amt_msat,
						total_msat,
						payment_params: Some(params),
						payment_hash,
						remaining_max_total_routing_fee_msat,
						..
					} = pmt
					{
						if pending_amt_msat < total_msat {
							retry_id_route_params = Some((
								*payment_hash,
								*pmt_id,
								RouteParameters {
									final_value_msat: *total_msat - *pending_amt_msat,
									payment_params: params.clone(),
									max_total_routing_fee_msat:
										*remaining_max_total_routing_fee_msat,
								},
							));
							break;
						}
					} else {
						debug_assert!(false);
					}
				}
			}
			core::mem::drop(outbounds);
			if let Some((payment_hash, payment_id, route_params)) = retry_id_route_params {
				self.find_route_and_send_payment(
					payment_hash,
					payment_id,
					route_params,
					router,
					first_hops(),
					&inflight_htlcs,
					entropy_source,
					node_signer,
					best_block_height,
					logger,
					pending_events,
					&send_payment_along_path,
				);
				should_persist = true;
			} else {
				break;
			}
		}

		let mut outbounds = self.pending_outbound_payments.lock().unwrap();
		outbounds.retain(|pmt_id, pmt| {
			let mut retain = true;
			if !pmt.is_auto_retryable_now()
				&& pmt.remaining_parts() == 0
				&& !pmt.is_awaiting_invoice()
			{
				pmt.mark_abandoned(PaymentFailureReason::RetriesExhausted);
				if let PendingOutboundPayment::Abandoned { payment_hash, reason, .. } = pmt {
					pending_events.lock().unwrap().push_back((
						events::Event::PaymentFailed {
							payment_id: *pmt_id,
							payment_hash: Some(*payment_hash),
							reason: *reason,
						},
						None,
					));
					retain = false;
					should_persist = true;
				}
			}
			retain
		});
		should_persist
	}

	pub(super) fn needs_abandon_or_retry(&self) -> bool {
		let outbounds = self.pending_outbound_payments.lock().unwrap();
		outbounds.iter().any(|(_, pmt)| {
			pmt.is_auto_retryable_now()
				|| !pmt.is_auto_retryable_now()
					&& pmt.remaining_parts() == 0
					&& !pmt.is_fulfilled()
					&& !pmt.is_awaiting_invoice()
		})
	}

	#[rustfmt::skip]
	fn find_initial_route<R: Deref, NS: Deref, IH, L: Deref>(
		&self, payment_id: PaymentId, payment_hash: PaymentHash, recipient_onion: &RecipientOnionFields,
		keysend_preimage: Option<PaymentPreimage>, invoice_request: Option<&InvoiceRequest>,
		route_params: &mut RouteParameters, router: &R, first_hops: &Vec<ChannelDetails>,
		inflight_htlcs: &IH, node_signer: &NS, best_block_height: u32, logger: &L,
	) -> Result<Route, RetryableSendFailure>
	where
		R::Target: Router,
		NS::Target: NodeSigner,
		L::Target: Logger,
		IH: Fn() -> InFlightHtlcs,
	{
		#[cfg(feature = "std")] {
			if has_expired(&route_params) {
				log_error!(logger, "Payment with id {} and hash {} had expired before we started paying",
					payment_id, payment_hash);
				return Err(RetryableSendFailure::PaymentExpired)
			}
		}

		onion_utils::set_max_path_length(
			route_params, recipient_onion, keysend_preimage, invoice_request, best_block_height
		)
			.map_err(|()| {
				log_error!(logger, "Can't construct an onion packet without exceeding 1300-byte onion \
					hop_data length for payment with id {} and hash {}", payment_id, payment_hash);
				RetryableSendFailure::OnionPacketSizeExceeded
			})?;

		let mut route = router.find_route_with_id(
			&node_signer.get_node_id(Recipient::Node).unwrap(), route_params,
			Some(&first_hops.iter().collect::<Vec<_>>()), inflight_htlcs(),
			payment_hash, payment_id,
		).map_err(|_| {
			log_error!(logger, "Failed to find route for payment with id {} and hash {}",
				payment_id, payment_hash);
			RetryableSendFailure::RouteNotFound
		})?;

		if route.route_params.as_ref() != Some(route_params) {
			debug_assert!(false,
				"Routers are expected to return a Route which includes the requested RouteParameters. Got {:?}, expected {:?}",
				route.route_params, route_params);
			route.route_params = Some(route_params.clone());
		}

		Ok(route)
	}

	/// Errors immediately on [`RetryableSendFailure`] error conditions. Otherwise, further errors may
	/// be surfaced asynchronously via [`Event::PaymentPathFailed`] and [`Event::PaymentFailed`].
	///
	/// [`Event::PaymentPathFailed`]: crate::events::Event::PaymentPathFailed
	/// [`Event::PaymentFailed`]: crate::events::Event::PaymentFailed
	#[rustfmt::skip]
	fn send_payment_for_non_bolt12_invoice<R: Deref, NS: Deref, ES: Deref, IH, SP, L: Deref>(
		&self, payment_id: PaymentId, payment_hash: PaymentHash, recipient_onion: RecipientOnionFields,
		keysend_preimage: Option<PaymentPreimage>, retry_strategy: Retry, mut route_params: RouteParameters,
		router: &R, first_hops: Vec<ChannelDetails>, inflight_htlcs: IH, entropy_source: &ES,
		node_signer: &NS, best_block_height: u32, logger: &L,
		pending_events: &Mutex<VecDeque<(events::Event, Option<EventCompletionAction>)>>, send_payment_along_path: SP,
	) -> Result<(), RetryableSendFailure>
	where
		R::Target: Router,
		ES::Target: EntropySource,
		NS::Target: NodeSigner,
		L::Target: Logger,
		IH: Fn() -> InFlightHtlcs,
		SP: Fn(SendAlongPathArgs) -> Result<(), APIError>,
	{
		let route = self.find_initial_route(
			payment_id, payment_hash, &recipient_onion, keysend_preimage, None, &mut route_params, router,
			&first_hops, &inflight_htlcs, node_signer, best_block_height, logger,
		)?;

		let onion_session_privs = self.add_new_pending_payment(payment_hash,
			recipient_onion.clone(), payment_id, keysend_preimage, &route, Some(retry_strategy),
			Some(route_params.payment_params.clone()), entropy_source, best_block_height, None)
			.map_err(|_| {
				log_error!(logger, "Payment with id {} is already pending. New payment had payment hash {}",
					payment_id, payment_hash);
				RetryableSendFailure::DuplicatePayment
			})?;

		let res = self.pay_route_internal(&route, payment_hash, &recipient_onion,
			keysend_preimage, None, None, payment_id, None, &onion_session_privs, false, node_signer,
			best_block_height, &send_payment_along_path);
		log_info!(logger, "Sending payment with id {} and hash {} returned {:?}",
			payment_id, payment_hash, res);
		if let Err(e) = res {
			self.handle_pay_route_err(
				e, payment_id, payment_hash, route, route_params, onion_session_privs, router, first_hops,
				&inflight_htlcs, entropy_source, node_signer, best_block_height, logger, pending_events,
				&send_payment_along_path
			);
		}
		Ok(())
	}

	#[rustfmt::skip]
	fn find_route_and_send_payment<R: Deref, NS: Deref, ES: Deref, IH, SP, L: Deref>(
		&self, payment_hash: PaymentHash, payment_id: PaymentId, route_params: RouteParameters,
		router: &R, first_hops: Vec<ChannelDetails>, inflight_htlcs: &IH, entropy_source: &ES,
		node_signer: &NS, best_block_height: u32, logger: &L,
		pending_events: &Mutex<VecDeque<(events::Event, Option<EventCompletionAction>)>>, send_payment_along_path: &SP,
	)
	where
		R::Target: Router,
		ES::Target: EntropySource,
		NS::Target: NodeSigner,
		L::Target: Logger,
		IH: Fn() -> InFlightHtlcs,
		SP: Fn(SendAlongPathArgs) -> Result<(), APIError>,
	{
		#[cfg(feature = "std")] {
			if has_expired(&route_params) {
				log_error!(logger, "Payment params expired on retry, abandoning payment {}", &payment_id);
				self.abandon_payment(payment_id, PaymentFailureReason::PaymentExpired, pending_events);
				return
			}
		}

		let mut route = match router.find_route_with_id(
			&node_signer.get_node_id(Recipient::Node).unwrap(), &route_params,
			Some(&first_hops.iter().collect::<Vec<_>>()), inflight_htlcs(),
			payment_hash, payment_id,
		) {
			Ok(route) => route,
			Err(e) => {
				log_error!(logger, "Failed to find a route on retry, abandoning payment {}: {:#?}", &payment_id, e);
				self.abandon_payment(payment_id, PaymentFailureReason::RouteNotFound, pending_events);
				return
			}
		};

		if route.route_params.as_ref() != Some(&route_params) {
			debug_assert!(false,
				"Routers are expected to return a Route which includes the requested RouteParameters");
			route.route_params = Some(route_params.clone());
		}

		for path in route.paths.iter() {
			if path.hops.len() == 0 {
				log_error!(logger, "Unusable path in route (path.hops.len() must be at least 1");
				self.abandon_payment(payment_id, PaymentFailureReason::UnexpectedError, pending_events);
				return
			}
		}

		macro_rules! abandon_with_entry {
			($payment: expr, $reason: expr) => {
				$payment.get_mut().mark_abandoned($reason);
				if let PendingOutboundPayment::Abandoned { reason, .. } = $payment.get() {
					if $payment.get().remaining_parts() == 0 {
						pending_events.lock().unwrap().push_back((events::Event::PaymentFailed {
							payment_id,
							payment_hash: Some(payment_hash),
							reason: *reason,
						}, None));
						$payment.remove();
					}
				}
			}
		}
		let (total_msat, recipient_onion, keysend_preimage, onion_session_privs, invoice_request, bolt12_invoice) = {
			let mut outbounds = self.pending_outbound_payments.lock().unwrap();
			match outbounds.entry(payment_id) {
				hash_map::Entry::Occupied(mut payment) => {
					match payment.get() {
						PendingOutboundPayment::Retryable {
							total_msat, keysend_preimage, payment_secret, payment_metadata,
							custom_tlvs, pending_amt_msat, invoice_request, ..
						} => {
							const RETRY_OVERFLOW_PERCENTAGE: u64 = 10;
							let retry_amt_msat = route.get_total_amount();
							if retry_amt_msat + *pending_amt_msat > *total_msat * (100 + RETRY_OVERFLOW_PERCENTAGE) / 100 {
								log_error!(logger, "retry_amt_msat of {} will put pending_amt_msat (currently: {}) more than 10% over total_payment_amt_msat of {}", retry_amt_msat, pending_amt_msat, total_msat);
								abandon_with_entry!(payment, PaymentFailureReason::UnexpectedError);
								return
							}

							if !payment.get().is_retryable_now() {
								log_error!(logger, "Retries exhausted for payment id {}", &payment_id);
								abandon_with_entry!(payment, PaymentFailureReason::RetriesExhausted);
								return
							}

							let total_msat = *total_msat;
							let recipient_onion = RecipientOnionFields {
								payment_secret: *payment_secret,
								payment_metadata: payment_metadata.clone(),
								custom_tlvs: custom_tlvs.clone(),
							};
							let keysend_preimage = *keysend_preimage;
							let invoice_request = invoice_request.clone();

							let mut onion_session_privs = Vec::with_capacity(route.paths.len());
							for _ in 0..route.paths.len() {
								onion_session_privs.push(entropy_source.get_secure_random_bytes());
							}

							for (path, session_priv_bytes) in route.paths.iter().zip(onion_session_privs.iter()) {
								assert!(payment.get_mut().insert(*session_priv_bytes, path));
							}

							payment.get_mut().increment_attempts();
							let bolt12_invoice = payment.get().bolt12_invoice();

							(total_msat, recipient_onion, keysend_preimage, onion_session_privs, invoice_request, bolt12_invoice.cloned())
						},
						PendingOutboundPayment::Legacy { .. } => {
							log_error!(logger, "Unable to retry payments that were initially sent on LDK versions prior to 0.0.102");
							return
						},
						PendingOutboundPayment::AwaitingInvoice { .. }
							| PendingOutboundPayment::AwaitingOffer { .. } =>
						{
							log_error!(logger, "Payment not yet sent");
							debug_assert!(false);
							return
						},
						PendingOutboundPayment::InvoiceReceived { .. } => {
							log_error!(logger, "Payment already initiating");
							debug_assert!(false);
							return
						},
						PendingOutboundPayment::StaticInvoiceReceived { .. } => {
							log_error!(logger, "Payment already initiating");
							debug_assert!(false);
							return
						},
						PendingOutboundPayment::Fulfilled { .. } => {
							log_error!(logger, "Payment already completed");
							return
						},
						PendingOutboundPayment::Abandoned { .. } => {
							log_error!(logger, "Payment already abandoned (with some HTLCs still pending)");
							return
						},
					}
				},
				hash_map::Entry::Vacant(_) => {
					log_error!(logger, "Payment with ID {} not found", &payment_id);
					return
				}
			}
		};
		let res = self.pay_route_internal(&route, payment_hash, &recipient_onion, keysend_preimage,
			invoice_request.as_ref(), bolt12_invoice.as_ref(), payment_id, Some(total_msat),
			&onion_session_privs, false, node_signer, best_block_height, &send_payment_along_path);
		log_info!(logger, "Result retrying payment id {}: {:?}", &payment_id, res);
		if let Err(e) = res {
			self.handle_pay_route_err(
				e, payment_id, payment_hash, route, route_params, onion_session_privs, router, first_hops,
				inflight_htlcs, entropy_source, node_signer, best_block_height, logger, pending_events,
				send_payment_along_path
			);
		}
	}

	#[rustfmt::skip]
	fn handle_pay_route_err<R: Deref, NS: Deref, ES: Deref, IH, SP, L: Deref>(
		&self, err: PaymentSendFailure, payment_id: PaymentId, payment_hash: PaymentHash, route: Route,
		mut route_params: RouteParameters, onion_session_privs: Vec<[u8; 32]>, router: &R,
		first_hops: Vec<ChannelDetails>, inflight_htlcs: &IH, entropy_source: &ES, node_signer: &NS,
		best_block_height: u32, logger: &L,
		pending_events: &Mutex<VecDeque<(events::Event, Option<EventCompletionAction>)>>,
		send_payment_along_path: &SP,
	)
	where
		R::Target: Router,
		ES::Target: EntropySource,
		NS::Target: NodeSigner,
		L::Target: Logger,
		IH: Fn() -> InFlightHtlcs,
		SP: Fn(SendAlongPathArgs) -> Result<(), APIError>,
	{
		match err {
			PaymentSendFailure::AllFailedResendSafe(errs) => {
				self.remove_session_privs(payment_id, route.paths.iter().zip(onion_session_privs.iter()));
				Self::push_path_failed_evs_and_scids(payment_id, payment_hash, &mut route_params, route.paths, errs.into_iter().map(|e| Err(e)), logger, pending_events);
				self.find_route_and_send_payment(payment_hash, payment_id, route_params, router, first_hops, inflight_htlcs, entropy_source, node_signer, best_block_height, logger, pending_events, send_payment_along_path);
			},
			PaymentSendFailure::PartialFailure { failed_paths_retry: Some(mut retry), results, .. } => {
				debug_assert_eq!(results.len(), route.paths.len());
				debug_assert_eq!(results.len(), onion_session_privs.len());
				let failed_paths = results.iter().zip(route.paths.iter().zip(onion_session_privs.iter()))
					.filter_map(|(path_res, (path, session_priv))| {
						match path_res {
							// While a MonitorUpdateInProgress is an Err(_), the payment is still
							// considered "in flight" and we shouldn't remove it from the
							// PendingOutboundPayment set.
							Ok(_) | Err(APIError::MonitorUpdateInProgress) => None,
							_ => Some((path, session_priv))
						}
					});
				self.remove_session_privs(payment_id, failed_paths);
				Self::push_path_failed_evs_and_scids(payment_id, payment_hash, &mut retry, route.paths, results.into_iter(), logger, pending_events);
				// Some paths were sent, even if we failed to send the full MPP value our recipient may
				// misbehave and claim the funds, at which point we have to consider the payment sent, so
				// return `Ok()` here, ignoring any retry errors.
				self.find_route_and_send_payment(payment_hash, payment_id, retry, router, first_hops, inflight_htlcs, entropy_source, node_signer, best_block_height, logger, pending_events, send_payment_along_path);
			},
			PaymentSendFailure::PartialFailure { failed_paths_retry: None, .. } => {
				// This may happen if we send a payment and some paths fail, but only due to a temporary
				// monitor failure or the like, implying they're really in-flight, but we haven't sent the
				// initial HTLC-Add messages yet.
			},
			PaymentSendFailure::PathParameterError(results) => {
				log_error!(logger, "Failed to send to route due to parameter error in a single path. Your router is buggy");
				self.remove_session_privs(payment_id, route.paths.iter().zip(onion_session_privs.iter()));
				Self::push_path_failed_evs_and_scids(payment_id, payment_hash, &mut route_params, route.paths, results.into_iter(), logger, pending_events);
				self.abandon_payment(payment_id, PaymentFailureReason::UnexpectedError, pending_events);
			},
			PaymentSendFailure::ParameterError(e) => {
				log_error!(logger, "Failed to send to route due to parameter error: {:?}. Your router is buggy", e);
				self.remove_session_privs(payment_id, route.paths.iter().zip(onion_session_privs.iter()));
				self.abandon_payment(payment_id, PaymentFailureReason::UnexpectedError, pending_events);
			},
			PaymentSendFailure::DuplicatePayment => debug_assert!(false), // unreachable
		}
	}

	fn push_path_failed_evs_and_scids<
		I: ExactSizeIterator + Iterator<Item = Result<(), APIError>>,
		L: Deref,
	>(
		payment_id: PaymentId, payment_hash: PaymentHash, route_params: &mut RouteParameters,
		paths: Vec<Path>, path_results: I, logger: &L,
		pending_events: &Mutex<VecDeque<(events::Event, Option<EventCompletionAction>)>>,
	) where
		L::Target: Logger,
	{
		let mut events = pending_events.lock().unwrap();
		debug_assert_eq!(paths.len(), path_results.len());
		for (path, path_res) in paths.into_iter().zip(path_results) {
			if let Err(e) = path_res {
				if let APIError::MonitorUpdateInProgress = e {
					continue;
				}
				log_error!(logger, "Failed to send along path due to error: {:?}", e);
				let mut failed_scid = None;
				if let APIError::ChannelUnavailable { .. } = e {
					let scid = path.hops[0].short_channel_id;
					failed_scid = Some(scid);
					route_params.payment_params.previously_failed_channels.push(scid);
				}
				let event = events::Event::PaymentPathFailed {
					payment_id: Some(payment_id),
					payment_hash,
					payment_failed_permanently: false,
					failure: events::PathFailure::InitialSend { err: e },
					path,
					short_channel_id: failed_scid,
					#[cfg(any(test, feature = "_test_utils"))]
					error_code: None,
					#[cfg(any(test, feature = "_test_utils"))]
					error_data: None,
					hold_times: Vec::new(),
				};
				events.push_back((event, None));
			}
		}
	}

	// If a payment fails after adding the pending payment but before any HTLCs are locked into
	// channels, we need to clear the session_privs in order for abandoning the payment to succeed.
	#[rustfmt::skip]
	fn remove_session_privs<'a, I: Iterator<Item = (&'a Path, &'a [u8; 32])>>(
		&self, payment_id: PaymentId, path_session_priv: I
	) {
		if let Some(payment) = self.pending_outbound_payments.lock().unwrap().get_mut(&payment_id) {
			for (path, session_priv_bytes) in path_session_priv {
				let removed = payment.remove(session_priv_bytes, Some(path));
				debug_assert!(removed, "This can't happen as the payment has an entry for this path added by callers");
			}
		} else {
			debug_assert!(false, "This can't happen as the payment was added by callers");
		}
	}

	#[rustfmt::skip]
	pub(super) fn send_probe<ES: Deref, NS: Deref, F>(
		&self, path: Path, probing_cookie_secret: [u8; 32], entropy_source: &ES, node_signer: &NS,
		best_block_height: u32, send_payment_along_path: F
	) -> Result<(PaymentHash, PaymentId), ProbeSendFailure>
	where
		ES::Target: EntropySource,
		NS::Target: NodeSigner,
		F: Fn(SendAlongPathArgs) -> Result<(), APIError>,
	{
		let payment_id = PaymentId(entropy_source.get_secure_random_bytes());
		let payment_secret = PaymentSecret(entropy_source.get_secure_random_bytes());

		let payment_hash = probing_cookie_from_id(&payment_id, probing_cookie_secret);

		if path.hops.len() < 2 && path.blinded_tail.is_none() {
			return Err(ProbeSendFailure::ParameterError(APIError::APIMisuseError {
				err: "No need probing a path with less than two hops".to_string()
			}))
		}

		let route = Route { paths: vec![path], route_params: None };
		let onion_session_privs = self.add_new_pending_payment(payment_hash,
			RecipientOnionFields::secret_only(payment_secret), payment_id, None, &route, None, None,
			entropy_source, best_block_height, None
		).map_err(|e| {
			debug_assert!(matches!(e, PaymentSendFailure::DuplicatePayment));
			ProbeSendFailure::DuplicateProbe
		})?;

		let recipient_onion_fields = RecipientOnionFields::spontaneous_empty();
		match self.pay_route_internal(&route, payment_hash, &recipient_onion_fields,
			None, None, None, payment_id, None, &onion_session_privs, false, node_signer,
			best_block_height, &send_payment_along_path
		) {
			Ok(()) => Ok((payment_hash, payment_id)),
			Err(e) => {
				self.remove_outbound_if_all_failed(payment_id, &e);
				match e {
					PaymentSendFailure::DuplicatePayment => Err(ProbeSendFailure::DuplicateProbe),
					PaymentSendFailure::ParameterError(err) => Err(ProbeSendFailure::ParameterError(err)),
					PaymentSendFailure::PartialFailure { results, .. }
					| PaymentSendFailure::PathParameterError(results) => {
						debug_assert_eq!(results.len(), 1);
						let err = results.into_iter()
							.find(|res| res.is_err())
							.map(|err| err.unwrap_err())
							.unwrap_or(APIError::APIMisuseError { err: "Unexpected error".to_owned() });
						Err(ProbeSendFailure::ParameterError(err))
					},
					PaymentSendFailure::AllFailedResendSafe(mut errors) => {
						debug_assert_eq!(errors.len(), 1);
						let err = errors
							.pop()
							.unwrap_or(APIError::APIMisuseError { err: "Unexpected error".to_owned() });
						Err(ProbeSendFailure::ParameterError(err))
					}
				}
			}
		}
	}

	#[cfg(test)]
	pub(super) fn test_set_payment_metadata(
		&self, payment_id: PaymentId, new_payment_metadata: Option<Vec<u8>>,
	) {
		match self.pending_outbound_payments.lock().unwrap().get_mut(&payment_id).unwrap() {
			PendingOutboundPayment::Retryable { payment_metadata, .. } => {
				*payment_metadata = new_payment_metadata;
			},
			_ => panic!("Need a retryable payment to update metadata on"),
		}
	}

	#[cfg(any(test, feature = "_externalize_tests"))]
	#[rustfmt::skip]
	pub(super) fn test_add_new_pending_payment<ES: Deref>(
		&self, payment_hash: PaymentHash, recipient_onion: RecipientOnionFields, payment_id: PaymentId,
		route: &Route, retry_strategy: Option<Retry>, entropy_source: &ES, best_block_height: u32
	) -> Result<Vec<[u8; 32]>, PaymentSendFailure> where ES::Target: EntropySource {
		self.add_new_pending_payment(payment_hash, recipient_onion, payment_id, None, route, retry_strategy, None, entropy_source, best_block_height, None)
	}

	#[rustfmt::skip]
	pub(super) fn add_new_pending_payment<ES: Deref>(
		&self, payment_hash: PaymentHash, recipient_onion: RecipientOnionFields, payment_id: PaymentId,
		keysend_preimage: Option<PaymentPreimage>, route: &Route, retry_strategy: Option<Retry>,
		payment_params: Option<PaymentParameters>, entropy_source: &ES, best_block_height: u32,
		bolt12_invoice: Option<PaidBolt12Invoice>
	) -> Result<Vec<[u8; 32]>, PaymentSendFailure> where ES::Target: EntropySource {
		let mut pending_outbounds = self.pending_outbound_payments.lock().unwrap();
		match pending_outbounds.entry(payment_id) {
			hash_map::Entry::Occupied(_) => Err(PaymentSendFailure::DuplicatePayment),
			hash_map::Entry::Vacant(entry) => {
				let (payment, onion_session_privs) = Self::create_pending_payment(
					payment_hash, recipient_onion, keysend_preimage, None, bolt12_invoice, route, retry_strategy,
					payment_params, entropy_source, best_block_height
				);
				entry.insert(payment);
				Ok(onion_session_privs)
			},
		}
	}

	#[rustfmt::skip]
	fn create_pending_payment<ES: Deref>(
		payment_hash: PaymentHash, recipient_onion: RecipientOnionFields,
		keysend_preimage: Option<PaymentPreimage>, invoice_request: Option<InvoiceRequest>,
		bolt12_invoice: Option<PaidBolt12Invoice>, route: &Route, retry_strategy: Option<Retry>,
		payment_params: Option<PaymentParameters>, entropy_source: &ES, best_block_height: u32
	) -> (PendingOutboundPayment, Vec<[u8; 32]>)
	where
		ES::Target: EntropySource,
	{
		let mut onion_session_privs = Vec::with_capacity(route.paths.len());
		for _ in 0..route.paths.len() {
			onion_session_privs.push(entropy_source.get_secure_random_bytes());
		}

		let mut payment = PendingOutboundPayment::Retryable {
			retry_strategy,
			attempts: PaymentAttempts::new(),
			payment_params,
			session_privs: new_hash_set(),
			pending_amt_msat: 0,
			pending_fee_msat: Some(0),
			payment_hash,
			payment_secret: recipient_onion.payment_secret,
			payment_metadata: recipient_onion.payment_metadata,
			keysend_preimage,
			invoice_request,
			bolt12_invoice,
			custom_tlvs: recipient_onion.custom_tlvs,
			starting_block_height: best_block_height,
			total_msat: route.get_total_amount(),
			remaining_max_total_routing_fee_msat:
				route.route_params.as_ref().and_then(|p| p.max_total_routing_fee_msat),
		};

		for (path, session_priv_bytes) in route.paths.iter().zip(onion_session_privs.iter()) {
			assert!(payment.insert(*session_priv_bytes, path));
		}

		(payment, onion_session_privs)
	}

	#[cfg(feature = "dnssec")]
	pub(super) fn add_new_awaiting_offer(
		&self, payment_id: PaymentId, expiration: StaleExpiration, retry_strategy: Retry,
		route_params_config: RouteParametersConfig, amount_msats: u64, payer_note: Option<String>,
	) -> Result<(), ()> {
		let mut pending_outbounds = self.pending_outbound_payments.lock().unwrap();
		match pending_outbounds.entry(payment_id) {
			hash_map::Entry::Occupied(_) => Err(()),
			hash_map::Entry::Vacant(entry) => {
				entry.insert(PendingOutboundPayment::AwaitingOffer {
					expiration,
					retry_strategy,
					route_params_config,
					amount_msats,
					payer_note,
				});

				Ok(())
			},
		}
	}

	#[cfg(feature = "dnssec")]
	#[rustfmt::skip]
	pub(super) fn params_for_payment_awaiting_offer(&self, payment_id: PaymentId) -> Result<(u64, Option<String>), ()> {
		match self.pending_outbound_payments.lock().unwrap().entry(payment_id) {
			hash_map::Entry::Occupied(entry) => match entry.get() {
				PendingOutboundPayment::AwaitingOffer { amount_msats, payer_note, .. } => Ok((*amount_msats, payer_note.clone())),
				_ => Err(()),
			},
			_ => Err(()),
		}
	}

	#[cfg(feature = "dnssec")]
	#[rustfmt::skip]
	pub(super) fn received_offer(
		&self, payment_id: PaymentId, retryable_invoice_request: Option<RetryableInvoiceRequest>,
	) -> Result<(), ()> {
		match self.pending_outbound_payments.lock().unwrap().entry(payment_id) {
			hash_map::Entry::Occupied(entry) => match entry.get() {
				PendingOutboundPayment::AwaitingOffer {
					expiration, retry_strategy, route_params_config, ..
				} => {
					let mut new_val = PendingOutboundPayment::AwaitingInvoice {
						expiration: *expiration,
						retry_strategy: *retry_strategy,
						route_params_config: *route_params_config,
						retryable_invoice_request,
					};
					core::mem::swap(&mut new_val, entry.into_mut());
					Ok(())
				},
				_ => Err(()),
			},
			hash_map::Entry::Vacant(_) => Err(()),
		}
	}

	pub(super) fn add_new_awaiting_invoice(
		&self, payment_id: PaymentId, expiration: StaleExpiration, retry_strategy: Retry,
		route_params_config: RouteParametersConfig,
		retryable_invoice_request: Option<RetryableInvoiceRequest>,
	) -> Result<(), ()> {
		let mut pending_outbounds = self.pending_outbound_payments.lock().unwrap();
		match pending_outbounds.entry(payment_id) {
			hash_map::Entry::Occupied(_) => Err(()),
			hash_map::Entry::Vacant(entry) => {
				if retryable_invoice_request.is_some() {
					self.awaiting_invoice.store(true, Ordering::Release);
				}
				entry.insert(PendingOutboundPayment::AwaitingInvoice {
					expiration,
					retry_strategy,
					route_params_config,
					retryable_invoice_request,
				});

				Ok(())
			},
		}
	}

	#[rustfmt::skip]
	pub(super) fn mark_invoice_received(
		&self, invoice: &Bolt12Invoice, payment_id: PaymentId
	) -> Result<(), Bolt12PaymentError> {
		self.mark_invoice_received_and_get_details(invoice, payment_id)
			.and_then(|(_, _, _, is_newly_marked)| {
				is_newly_marked
					.then_some(())
					.ok_or(Bolt12PaymentError::DuplicateInvoice)
			})
	}

	#[rustfmt::skip]
	fn mark_invoice_received_and_get_details(
		&self, invoice: &Bolt12Invoice, payment_id: PaymentId
	) -> Result<(PaymentHash, Retry, RouteParametersConfig, bool), Bolt12PaymentError> {
		match self.pending_outbound_payments.lock().unwrap().entry(payment_id) {
			hash_map::Entry::Occupied(entry) => match entry.get() {
				PendingOutboundPayment::AwaitingInvoice {
					retry_strategy: retry, route_params_config, ..
				} => {
					let payment_hash = invoice.payment_hash();
					let retry = *retry;
					let config = *route_params_config;
					*entry.into_mut() = PendingOutboundPayment::InvoiceReceived {
						payment_hash,
						retry_strategy: retry,
						route_params_config: config,
					};

					Ok((payment_hash, retry, config, true))
				},
				// When manual invoice handling is enabled, the corresponding `PendingOutboundPayment` entry
				// is already updated at the time the invoice is received. This ensures that `InvoiceReceived`
				// event generation remains idempotent, even if the same invoice is received again before the
				// event is handled by the user.
				PendingOutboundPayment::InvoiceReceived {
					retry_strategy, route_params_config, ..
				} => {
					Ok((invoice.payment_hash(), *retry_strategy, *route_params_config, false))
				},
				_ => Err(Bolt12PaymentError::DuplicateInvoice),
			},
			hash_map::Entry::Vacant(_) => Err(Bolt12PaymentError::UnexpectedInvoice),
		}
	}

	#[rustfmt::skip]
	fn pay_route_internal<NS: Deref, F>(
		&self, route: &Route, payment_hash: PaymentHash, recipient_onion: &RecipientOnionFields,
		keysend_preimage: Option<PaymentPreimage>, invoice_request: Option<&InvoiceRequest>, bolt12_invoice: Option<&PaidBolt12Invoice>,
		payment_id: PaymentId, recv_value_msat: Option<u64>, onion_session_privs: &Vec<[u8; 32]>,
		hold_htlcs_at_next_hop: bool, node_signer: &NS, best_block_height: u32, send_payment_along_path: &F
	) -> Result<(), PaymentSendFailure>
	where
		NS::Target: NodeSigner,
		F: Fn(SendAlongPathArgs) -> Result<(), APIError>,
	{
		if route.paths.len() < 1 {
			return Err(PaymentSendFailure::ParameterError(APIError::InvalidRoute{err: "There must be at least one path to send over".to_owned()}));
		}
		if recipient_onion.payment_secret.is_none() && route.paths.len() > 1
			&& !route.paths.iter().any(|p| p.blinded_tail.is_some())
		{
			return Err(PaymentSendFailure::ParameterError(APIError::APIMisuseError{err: "Payment secret is required for multi-path payments".to_owned()}));
		}
		let mut total_value = 0;
		let our_node_id = node_signer.get_node_id(Recipient::Node).unwrap(); // TODO no unwrap
		let mut path_errs = Vec::with_capacity(route.paths.len());
		'path_check: for path in route.paths.iter() {
			if path.hops.len() < 1 || path.hops.len() > 20 {
				path_errs.push(Err(APIError::InvalidRoute{err: "Path didn't go anywhere/had bogus size".to_owned()}));
				continue 'path_check;
			}
			let dest_hop_idx = if path.blinded_tail.is_some() && path.blinded_tail.as_ref().unwrap().hops.len() > 1 {
				usize::max_value() } else { path.hops.len() - 1 };
			for (idx, hop) in path.hops.iter().enumerate() {
				if idx != dest_hop_idx && hop.pubkey == our_node_id {
					path_errs.push(Err(APIError::InvalidRoute{err: "Path went through us but wasn't a simple rebalance loop to us".to_owned()}));
					continue 'path_check;
				}
			}
			for (i, hop) in path.hops.iter().enumerate() {
				// Check for duplicate channel_id in the remaining hops of the path
				if path.hops.iter().skip(i + 1).any(|other_hop| other_hop.short_channel_id == hop.short_channel_id) {
					path_errs.push(Err(APIError::InvalidRoute{err: "Path went through the same channel twice".to_owned()}));
					continue 'path_check;
				}
			}
			total_value += path.final_value_msat();
			path_errs.push(Ok(()));
		}
		if path_errs.iter().any(|e| e.is_err()) {
			return Err(PaymentSendFailure::PathParameterError(path_errs));
		}
		if let Some(amt_msat) = recv_value_msat {
			total_value = amt_msat;
		}

		let cur_height = best_block_height + 1;
		let mut results = Vec::new();
		debug_assert_eq!(route.paths.len(), onion_session_privs.len());
		for (path, session_priv_bytes) in route.paths.iter().zip(onion_session_privs.iter()) {
			let path_res = send_payment_along_path(SendAlongPathArgs {
				path: &path, payment_hash: &payment_hash, recipient_onion, total_value,
				cur_height, payment_id, keysend_preimage: &keysend_preimage, invoice_request,
				bolt12_invoice,
				session_priv_bytes: *session_priv_bytes
			});
			results.push(path_res);
		}
		let mut has_ok = false;
		let mut has_err = false;
		let mut has_unsent = false;
		let mut total_ok_fees_msat = 0;
		let mut total_ok_amt_sent_msat = 0;
		for (res, path) in results.iter().zip(route.paths.iter()) {
			if res.is_ok() {
				has_ok = true;
				total_ok_fees_msat += path.fee_msat();
				total_ok_amt_sent_msat += path.final_value_msat();
			}
			if res.is_err() { has_err = true; }
			if let &Err(APIError::MonitorUpdateInProgress) = res {
				// MonitorUpdateInProgress is inherently unsafe to retry, so we call it a
				// PartialFailure.
				has_err = true;
				has_ok = true;
				total_ok_fees_msat += path.fee_msat();
				total_ok_amt_sent_msat += path.final_value_msat();
			} else if res.is_err() {
				has_unsent = true;
			}
		}
		if has_err && has_ok {
			Err(PaymentSendFailure::PartialFailure {
				results,
				payment_id,
				failed_paths_retry: if has_unsent {
					if let Some(route_params) = &route.route_params {
						let mut route_params = route_params.clone();
						// We calculate the leftover fee budget we're allowed to spend by
						// subtracting the used fee from the total fee budget.
						route_params.max_total_routing_fee_msat = route_params
							.max_total_routing_fee_msat.map(|m| m.saturating_sub(total_ok_fees_msat));

						// We calculate the remaining target amount by subtracting the succeded
						// path values.
						route_params.final_value_msat = route_params.final_value_msat
							.saturating_sub(total_ok_amt_sent_msat);
						Some(route_params)
					} else { None }
				} else { None },
			})
		} else if has_err {
			Err(PaymentSendFailure::AllFailedResendSafe(results.drain(..).map(|r| r.unwrap_err()).collect()))
		} else {
			Ok(())
		}
	}

	#[cfg(any(test, feature = "_externalize_tests"))]
	#[rustfmt::skip]
	pub(super) fn test_send_payment_internal<NS: Deref, F>(
		&self, route: &Route, payment_hash: PaymentHash, recipient_onion: RecipientOnionFields,
		keysend_preimage: Option<PaymentPreimage>, payment_id: PaymentId, recv_value_msat: Option<u64>,
		onion_session_privs: Vec<[u8; 32]>, node_signer: &NS, best_block_height: u32,
		send_payment_along_path: F
	) -> Result<(), PaymentSendFailure>
	where
		NS::Target: NodeSigner,
		F: Fn(SendAlongPathArgs) -> Result<(), APIError>,
	{
		self.pay_route_internal(route, payment_hash, &recipient_onion,
			keysend_preimage, None, None, payment_id, recv_value_msat, &onion_session_privs,
			false, node_signer, best_block_height, &send_payment_along_path)
			.map_err(|e| { self.remove_outbound_if_all_failed(payment_id, &e); e })
	}

	// If we failed to send any paths, remove the new PaymentId from the `pending_outbound_payments`
	// map as the payment is free to be resent.
	#[rustfmt::skip]
	fn remove_outbound_if_all_failed(&self, payment_id: PaymentId, err: &PaymentSendFailure) {
		match err {
			PaymentSendFailure::AllFailedResendSafe(_)
				| PaymentSendFailure::ParameterError(_)
				| PaymentSendFailure::PathParameterError(_) =>
			{
				let removed = self.pending_outbound_payments.lock().unwrap().remove(&payment_id).is_some();
				debug_assert!(removed, "We should always have a pending payment to remove here");
			},
			PaymentSendFailure::DuplicatePayment | PaymentSendFailure::PartialFailure { .. }  => {}
		}
	}

	#[rustfmt::skip]
	pub(super) fn claim_htlc<L: Deref>(
		&self, payment_id: PaymentId, payment_preimage: PaymentPreimage, bolt12_invoice: Option<PaidBolt12Invoice>,
		session_priv: SecretKey, path: Path, from_onchain: bool, ev_completion_action: EventCompletionAction,
		pending_events: &Mutex<VecDeque<(events::Event, Option<EventCompletionAction>)>>,
		logger: &L,
	) where L::Target: Logger {
		let mut session_priv_bytes = [0; 32];
		session_priv_bytes.copy_from_slice(&session_priv[..]);
		let mut outbounds = self.pending_outbound_payments.lock().unwrap();
		let mut pending_events = pending_events.lock().unwrap();
		if let hash_map::Entry::Occupied(mut payment) = outbounds.entry(payment_id) {
			if !payment.get().is_fulfilled() {
				let payment_hash = PaymentHash(Sha256::hash(&payment_preimage.0).to_byte_array());
				log_info!(logger, "Payment with id {} and hash {} sent!", payment_id, payment_hash);
				let fee_paid_msat = payment.get().get_pending_fee_msat();
				let amount_msat = payment.get().total_msat();
				pending_events.push_back((events::Event::PaymentSent {
					payment_id: Some(payment_id),
					payment_preimage,
					payment_hash,
					amount_msat,
					fee_paid_msat,
					bolt12_invoice: bolt12_invoice,
				}, Some(ev_completion_action.clone())));
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
					let payment_hash = Some(PaymentHash(Sha256::hash(&payment_preimage.0).to_byte_array()));
					pending_events.push_back((events::Event::PaymentPathSuccessful {
						payment_id,
						payment_hash,
						path,
						hold_times: Vec::new(),
					}, Some(ev_completion_action)));
				}
			}
		} else {
			log_trace!(logger, "Received duplicative fulfill for HTLC with payment_preimage {}", &payment_preimage);
		}
	}

	#[rustfmt::skip]
	pub(super) fn finalize_claims<I: Iterator<Item = (HTLCSource, Vec<u32>)>>(&self, sources: I,
		pending_events: &Mutex<VecDeque<(events::Event, Option<EventCompletionAction>)>>)
	{
		let mut outbounds = self.pending_outbound_payments.lock().unwrap();
		let mut pending_events = pending_events.lock().unwrap();
		for (source, hold_times) in sources {
			if let HTLCSource::OutboundRoute { session_priv, payment_id, path, .. } = source {
				let mut session_priv_bytes = [0; 32];
				session_priv_bytes.copy_from_slice(&session_priv[..]);
				if let hash_map::Entry::Occupied(mut payment) = outbounds.entry(payment_id) {
					assert!(payment.get().is_fulfilled());
					if payment.get_mut().remove(&session_priv_bytes, None) {
						let payment_hash = payment.get().payment_hash();
						debug_assert!(payment_hash.is_some());
						pending_events.push_back((events::Event::PaymentPathSuccessful {
							payment_id,
							payment_hash,
							path,
							hold_times
						}, None));
					}
				}
			}
		}
	}

	#[rustfmt::skip]
	pub(super) fn remove_stale_payments(
		&self, duration_since_epoch: Duration,
		pending_events: &Mutex<VecDeque<(events::Event, Option<EventCompletionAction>)>>)
	{
		let mut pending_outbound_payments = self.pending_outbound_payments.lock().unwrap();
		let mut pending_events = pending_events.lock().unwrap();
		pending_outbound_payments.retain(|payment_id, payment| match payment {
			// If an outbound payment was completed, and no pending HTLCs remain, we should remove it
			// from the map. However, if we did that immediately when the last payment HTLC is claimed,
			// this could race the user making a duplicate send_payment call and our idempotency
			// guarantees would be violated. Instead, we wait a few timer ticks to do the actual
			// removal. This should be more than sufficient to ensure the idempotency of any
			// `send_payment` calls that were made at the same time the `PaymentSent` event was being
			// processed.
			PendingOutboundPayment::Fulfilled { session_privs, timer_ticks_without_htlcs, .. } => {
				let mut no_remaining_entries = session_privs.is_empty();
				if no_remaining_entries {
					for (ev, _) in pending_events.iter() {
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
			},
			PendingOutboundPayment::AwaitingInvoice { expiration, .. }
				| PendingOutboundPayment::AwaitingOffer { expiration, .. } =>
			{
				let is_stale = match expiration {
					StaleExpiration::AbsoluteTimeout(absolute_expiry) => {
						*absolute_expiry <= duration_since_epoch
					},
					StaleExpiration::TimerTicks(timer_ticks_remaining) => {
						if *timer_ticks_remaining > 0 {
							*timer_ticks_remaining -= 1;
							false
						} else {
							true
						}
					},
				};
				if is_stale {
					let event = events::Event::PaymentFailed {
						payment_id: *payment_id,
						payment_hash: None,
						reason: Some(PaymentFailureReason::InvoiceRequestExpired),
					};
					pending_events.push_back((event, None));
					false
				} else {
					true
				}
			},
			PendingOutboundPayment::StaticInvoiceReceived { route_params, payment_hash, expiry_time, .. } => {
				let is_stale = *expiry_time < duration_since_epoch;
				let is_static_invoice_stale =
					route_params.payment_params.expiry_time.unwrap_or(u64::MAX) <
					duration_since_epoch.as_secs();
				if is_stale || is_static_invoice_stale {
					let fail_ev = events::Event::PaymentFailed {
						payment_id: *payment_id,
						payment_hash: Some(*payment_hash),
						reason: Some(PaymentFailureReason::PaymentExpired)
					};
					pending_events.push_back((fail_ev, None));
					false
				} else {
					true
				}
			},
			_ => true,
		});
	}

	pub(super) fn fail_htlc<L: Deref>(
		&self, source: &HTLCSource, payment_hash: &PaymentHash, onion_error: &HTLCFailReason,
		path: &Path, session_priv: &SecretKey, payment_id: &PaymentId,
		probing_cookie_secret: [u8; 32], secp_ctx: &Secp256k1<secp256k1::All>,
		pending_events: &Mutex<VecDeque<(events::Event, Option<EventCompletionAction>)>>,
		logger: &L,
	) where
		L::Target: Logger,
	{
		#[cfg(any(test, feature = "_test_utils"))]
		let DecodedOnionFailure {
			network_update,
			short_channel_id,
			payment_failed_permanently,
			onion_error_code,
			onion_error_data,
			failed_within_blinded_path,
			hold_times,
			..
		} = onion_error.decode_onion_failure(secp_ctx, logger, &source);
		#[cfg(not(any(test, feature = "_test_utils")))]
		let DecodedOnionFailure {
			network_update,
			short_channel_id,
			payment_failed_permanently,
			failed_within_blinded_path,
			hold_times,
			..
		} = onion_error.decode_onion_failure(secp_ctx, logger, &source);

		let payment_is_probe = payment_is_probe(payment_hash, &payment_id, probing_cookie_secret);
		let mut session_priv_bytes = [0; 32];
		session_priv_bytes.copy_from_slice(&session_priv[..]);
		let mut outbounds = self.pending_outbound_payments.lock().unwrap();

		let already_awaiting_retry = outbounds.iter().any(|(_, pmt)| {
			let mut awaiting_retry = false;
			if pmt.is_auto_retryable_now() {
				if let PendingOutboundPayment::Retryable { pending_amt_msat, total_msat, .. } = pmt
				{
					if pending_amt_msat < total_msat {
						awaiting_retry = true;
					}
				}
			}
			awaiting_retry
		});

		let mut full_failure_ev = None;
		let attempts_remaining =
			if let hash_map::Entry::Occupied(mut payment) = outbounds.entry(*payment_id) {
				if !payment.get_mut().remove(&session_priv_bytes, Some(&path)) {
					log_trace!(
						logger,
						"Received duplicative fail for HTLC with payment_hash {}",
						&payment_hash
					);
					return;
				}
				if payment.get().is_fulfilled() {
					log_trace!(
						logger,
						"Received failure of HTLC with payment_hash {} after payment completion",
						&payment_hash
					);
					return;
				}
				let mut is_retryable_now = payment.get().is_auto_retryable_now();
				if let Some(scid) = short_channel_id {
					// TODO: If we decided to blame ourselves (or one of our channels) in
					// process_onion_failure we should close that channel as it implies our
					// next-hop is needlessly blaming us!
					payment.get_mut().insert_previously_failed_scid(scid);
				}
				if failed_within_blinded_path {
					debug_assert!(short_channel_id.is_none());
					if let Some(bt) = &path.blinded_tail {
						payment.get_mut().insert_previously_failed_blinded_path(&bt);
					} else {
						debug_assert!(false);
					}
				}

				if payment_is_probe || !is_retryable_now || payment_failed_permanently {
					let reason = if payment_failed_permanently {
						PaymentFailureReason::RecipientRejected
					} else {
						PaymentFailureReason::RetriesExhausted
					};
					payment.get_mut().mark_abandoned(reason);
					is_retryable_now = false;
				}
				if payment.get().remaining_parts() == 0 {
					if let PendingOutboundPayment::Abandoned { payment_hash, reason, .. } =
						payment.get()
					{
						if !payment_is_probe {
							full_failure_ev = Some(events::Event::PaymentFailed {
								payment_id: *payment_id,
								payment_hash: Some(*payment_hash),
								reason: *reason,
							});
						}
						payment.remove();
					}
				}
				is_retryable_now
			} else {
				log_trace!(
					logger,
					"Received duplicative fail for HTLC with payment_hash {}",
					&payment_hash
				);
				return;
			};
		core::mem::drop(outbounds);
		log_trace!(logger, "Failing outbound payment HTLC with payment_hash {}", &payment_hash);

		let path_failure = {
			if payment_is_probe {
				if payment_failed_permanently {
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
				// If we miss abandoning the payment above, we *must* generate an event here or else the
				// payment will sit in our outbounds forever.
				if attempts_remaining && !already_awaiting_retry {
					debug_assert!(full_failure_ev.is_none());
				}
				events::Event::PaymentPathFailed {
					payment_id: Some(*payment_id),
					payment_hash: payment_hash.clone(),
					payment_failed_permanently,
					failure: events::PathFailure::OnPath { network_update },
					path: path.clone(),
					short_channel_id,
					#[cfg(any(test, feature = "_test_utils"))]
					error_code: onion_error_code.map(|f| f.failure_code()),
					#[cfg(any(test, feature = "_test_utils"))]
					error_data: onion_error_data,
					hold_times,
				}
			}
		};
		let mut pending_events = pending_events.lock().unwrap();
		pending_events.push_back((path_failure, None));
		if let Some(ev) = full_failure_ev {
			pending_events.push_back((ev, None));
		}
	}

	#[rustfmt::skip]
	pub(super) fn abandon_payment(
		&self, payment_id: PaymentId, reason: PaymentFailureReason,
		pending_events: &Mutex<VecDeque<(events::Event, Option<EventCompletionAction>)>>
	) {
		let mut outbounds = self.pending_outbound_payments.lock().unwrap();
		if let hash_map::Entry::Occupied(mut payment) = outbounds.entry(payment_id) {
			payment.get_mut().mark_abandoned(reason);
			match payment.get() {
				PendingOutboundPayment::Abandoned { payment_hash, reason, .. } => {
					if payment.get().remaining_parts() == 0 {
						pending_events.lock().unwrap().push_back((events::Event::PaymentFailed {
							payment_id,
							payment_hash: Some(*payment_hash),
							reason: *reason,
						}, None));
						payment.remove();
					}
				},
				PendingOutboundPayment::AwaitingInvoice { .. }
					| PendingOutboundPayment::AwaitingOffer { .. } =>
				{
					pending_events.lock().unwrap().push_back((events::Event::PaymentFailed {
						payment_id,
						payment_hash: None,
						reason: Some(reason),
					}, None));
					payment.remove();
				},
				_ => {},
			}
		}
	}

	#[cfg(test)]
	pub fn has_pending_payments(&self) -> bool {
		!self.pending_outbound_payments.lock().unwrap().is_empty()
	}

	#[cfg(test)]
	pub fn clear_pending_payments(&self) {
		self.pending_outbound_payments.lock().unwrap().clear()
	}

	#[rustfmt::skip]
	pub fn release_invoice_requests_awaiting_invoice(&self) -> Vec<(PaymentId, RetryableInvoiceRequest)> {
		if !self.awaiting_invoice.load(Ordering::Acquire) {
			return vec![];
		}

		let mut pending_outbound_payments = self.pending_outbound_payments.lock().unwrap();
		let invoice_requests = pending_outbound_payments
			.iter_mut()
			.filter_map(|(payment_id, payment)| {
				if let PendingOutboundPayment::AwaitingInvoice {
					retryable_invoice_request: Some(invreq), ..
				} = payment {
					if invreq.needs_retry {
						invreq.needs_retry = false;
						Some((*payment_id, invreq.clone()))
					} else { None }
				} else {
					None
				}
			})
			.collect();

		self.awaiting_invoice.store(false, Ordering::Release);
		invoice_requests
	}

	pub(super) fn insert_from_monitor_on_startup<L: Logger>(
		&self, payment_id: PaymentId, payment_hash: PaymentHash, session_priv_bytes: [u8; 32],
		path: &Path, best_block_height: u32, logger: L,
	) {
		let path_amt = path.final_value_msat();
		let path_fee = path.fee_msat();

		macro_rules! new_retryable {
			() => {
				PendingOutboundPayment::Retryable {
					retry_strategy: None,
					attempts: PaymentAttempts::new(),
					payment_params: None,
					session_privs: hash_set_from_iter([session_priv_bytes]),
					payment_hash,
					payment_secret: None, // only used for retries, and we'll never retry on startup
					payment_metadata: None, // only used for retries, and we'll never retry on startup
					keysend_preimage: None, // only used for retries, and we'll never retry on startup
					invoice_request: None, // only used for retries, and we'll never retry on startup
					bolt12_invoice: None, // only used for retries, and we'll never retry on startup!
					custom_tlvs: Vec::new(), // only used for retries, and we'll never retry on startup
					pending_amt_msat: path_amt,
					pending_fee_msat: Some(path_fee),
					total_msat: path_amt,
					starting_block_height: best_block_height,
					remaining_max_total_routing_fee_msat: None, // only used for retries, and we'll never retry on startup
				}
			}
		}

		match self.pending_outbound_payments.lock().unwrap().entry(payment_id) {
			hash_map::Entry::Occupied(mut entry) => {
				let newly_added = match entry.get() {
					PendingOutboundPayment::AwaitingOffer { .. }
					| PendingOutboundPayment::AwaitingInvoice { .. }
					| PendingOutboundPayment::InvoiceReceived { .. }
					| PendingOutboundPayment::StaticInvoiceReceived { .. } => {
						// If we've reached this point, it means we initiated a payment to a BOLT 12 invoice and
						// locked the htlc(s) into the `ChannelMonitor`(s), but failed to persist the
						// `ChannelManager` after transitioning from this state to `Retryable` prior to shutdown.
						// Therefore, we need to move this payment to `Retryable` now to avoid double-paying if
						// the recipient sends a duplicate invoice or release_held_htlc onion message.
						*entry.get_mut() = new_retryable!();
						true
					},
					PendingOutboundPayment::Legacy { .. }
					| PendingOutboundPayment::Retryable { .. }
					| PendingOutboundPayment::Fulfilled { .. }
					| PendingOutboundPayment::Abandoned { .. } => {
						entry.get_mut().insert(session_priv_bytes, &path)
					},
				};
				log_info!(logger, "{} a pending payment path for {} msat for session priv {} on an existing pending payment with payment hash {}",
					if newly_added { "Added" } else { "Had" }, path_amt, log_bytes!(session_priv_bytes), payment_hash);
			},
			hash_map::Entry::Vacant(entry) => {
				entry.insert(new_retryable!());
				log_info!(logger, "Added a pending payment for {} msat with payment hash {} for path with session priv {}",
					path_amt, payment_hash,  log_bytes!(session_priv_bytes));
			},
		}
	}
}

/// Returns whether a payment with the given [`PaymentHash`] and [`PaymentId`] is, in fact, a
/// payment probe.
pub(super) fn payment_is_probe(
	payment_hash: &PaymentHash, payment_id: &PaymentId, probing_cookie_secret: [u8; 32],
) -> bool {
	let target_payment_hash = probing_cookie_from_id(payment_id, probing_cookie_secret);
	target_payment_hash == *payment_hash
}

/// Returns the 'probing cookie' for the given [`PaymentId`].
fn probing_cookie_from_id(payment_id: &PaymentId, probing_cookie_secret: [u8; 32]) -> PaymentHash {
	let mut preimage = [0u8; 64];
	preimage[..32].copy_from_slice(&probing_cookie_secret);
	preimage[32..].copy_from_slice(&payment_id.0);
	PaymentHash(Sha256::hash(&preimage).to_byte_array())
}

impl_writeable_tlv_based_enum_upgradable!(PendingOutboundPayment,
	(0, Legacy) => {
		(0, session_privs, required),
	},
	(1, Fulfilled) => {
		(0, session_privs, required),
		(1, payment_hash, option),
		(3, timer_ticks_without_htlcs, (default_value, 0)),
		(5, total_msat, option),
	},
	(2, Retryable) => {
		(0, session_privs, required),
		(1, pending_fee_msat, option),
		(2, payment_hash, required),
		// Note that while we "default" payment_param's final CLTV expiry delta to 0 we should
		// never see it - `payment_params` was added here after the field was added/required.
		(3, payment_params, (option: ReadableArgs, 0)),
		(4, payment_secret, option),
		(5, keysend_preimage, option),
		(6, total_msat, required),
		(7, payment_metadata, option),
		(8, pending_amt_msat, required),
		(9, custom_tlvs, optional_vec),
		(10, starting_block_height, required),
		(11, remaining_max_total_routing_fee_msat, option),
		(13, invoice_request, option),
		(15, bolt12_invoice, option),
		(not_written, retry_strategy, (static_value, None)),
		(not_written, attempts, (static_value, PaymentAttempts::new())),
	},
	(3, Abandoned) => {
		(0, session_privs, required),
		(1, reason, upgradable_option),
		(2, payment_hash, required),
		(3, total_msat, option),
	},
	(5, AwaitingInvoice) => {
		(0, expiration, required),
		(2, retry_strategy, required),
		(4, _max_total_routing_fee_msat, (legacy, u64,
			|us: &PendingOutboundPayment| match us {
				PendingOutboundPayment::AwaitingInvoice { route_params_config, .. } => route_params_config.max_total_routing_fee_msat,
				_ => None,
			}
		)),
		(5, retryable_invoice_request, option),
		(7, route_params_config, (default_value, (
			_max_total_routing_fee_msat.map_or(
				RouteParametersConfig::default(),
				|fee_msat| RouteParametersConfig::default().with_max_total_routing_fee_msat(fee_msat)
			)
		))),
	},
	(7, InvoiceReceived) => {
		(0, payment_hash, required),
		(2, retry_strategy, required),
		(4, _max_total_routing_fee_msat, (legacy, u64,
			|us: &PendingOutboundPayment| match us {
				PendingOutboundPayment::InvoiceReceived { route_params_config, .. } => route_params_config.max_total_routing_fee_msat,
				_ => None,
			}
		)),
		(5, route_params_config, (default_value, (
			_max_total_routing_fee_msat.map_or(
				RouteParametersConfig::default(),
				|fee_msat| RouteParametersConfig::default().with_max_total_routing_fee_msat(fee_msat)
			)
		))),
	},
	// Added in 0.1. Prior versions will drop these outbounds on downgrade, which is safe because no
	// HTLCs are in-flight.
	(9, StaticInvoiceReceived) => {
		(0, payment_hash, required),
		// Added in 0.2. If this field is set when this variant is created, the HTLCs are sent
		// immediately after and the pending outbound is also immediately transitioned to Retryable.
		// However, if we crash and then downgrade before the transition to Retryable, this payment will
		// sit in outbounds until it either times out in `remove_stale_payments` or is manually
		// abandoned.
		(1, hold_htlcs_at_next_hop, required),
		(2, keysend_preimage, required),
		(4, retry_strategy, required),
		(6, route_params, required),
		(8, invoice_request, required),
		(10, static_invoice, required),
		// Added in 0.2. Prior versions would have this TLV type defaulted to 0, which is safe because
		// the type is not used.
		(11, expiry_time, (default_value, Duration::from_secs(0))),
	},
	// Added in 0.1. Prior versions will drop these outbounds on downgrade, which is safe because
	// no HTLCs are in-flight.
	(11, AwaitingOffer) => {
		(0, expiration, required),
		(2, retry_strategy, required),
		(4, _max_total_routing_fee_msat, (legacy, u64,
			|us: &PendingOutboundPayment| match us {
				PendingOutboundPayment::AwaitingOffer { route_params_config, .. } => route_params_config.max_total_routing_fee_msat,
				_ => None,
			}
		)),
		(5, route_params_config, (default_value, (
			_max_total_routing_fee_msat.map_or(
				RouteParametersConfig::default(),
				|fee_msat| RouteParametersConfig::default().with_max_total_routing_fee_msat(fee_msat)
			)
		))),
		(6, amount_msats, required),
		(7, payer_note, option),
	},
);

#[cfg(test)]
mod tests {
	use bitcoin::network::Network;
	use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};

	use core::time::Duration;

	use crate::blinded_path::EmptyNodeIdLookUp;
	use crate::events::{Event, PathFailure, PaymentFailureReason};
	use crate::ln::channelmanager::{PaymentId, RecipientOnionFields};
	use crate::ln::inbound_payment::ExpandedKey;
	use crate::ln::outbound_payment::{
		Bolt12PaymentError, OutboundPayments, PendingOutboundPayment, Retry, RetryableSendFailure,
		StaleExpiration,
	};
	#[cfg(feature = "std")]
	use crate::offers::invoice::DEFAULT_RELATIVE_EXPIRY;
	use crate::offers::invoice_request::InvoiceRequest;
	use crate::offers::nonce::Nonce;
	use crate::offers::offer::OfferBuilder;
	use crate::offers::test_utils::*;
	use crate::routing::gossip::NetworkGraph;
	use crate::routing::router::{
		InFlightHtlcs, Path, PaymentParameters, Route, RouteHop, RouteParameters,
		RouteParametersConfig,
	};
	use crate::sync::{Arc, Mutex, RwLock};
	use crate::types::features::{Bolt12InvoiceFeatures, ChannelFeatures, NodeFeatures};
	use crate::types::payment::{PaymentHash, PaymentPreimage};
	use crate::util::errors::APIError;
	use crate::util::hash_tables::new_hash_map;
	use crate::util::test_utils;

	use alloc::collections::VecDeque;

	#[test]
	#[rustfmt::skip]
	fn test_recipient_onion_fields_with_custom_tlvs() {
		let onion_fields = RecipientOnionFields::spontaneous_empty();

		let bad_type_range_tlvs = vec![
			(0, vec![42]),
			(1, vec![42; 32]),
		];
		assert!(onion_fields.clone().with_custom_tlvs(bad_type_range_tlvs).is_err());

		let keysend_tlv = vec![
			(5482373484, vec![42; 32]),
		];
		assert!(onion_fields.clone().with_custom_tlvs(keysend_tlv).is_err());

		let good_tlvs = vec![
			((1 << 16) + 1, vec![42]),
			((1 << 16) + 3, vec![42; 32]),
		];
		assert!(onion_fields.with_custom_tlvs(good_tlvs).is_ok());
	}

	#[test]
	#[cfg(feature = "std")]
	fn fails_paying_after_expiration() {
		do_fails_paying_after_expiration(false);
		do_fails_paying_after_expiration(true);
	}
	#[cfg(feature = "std")]
	#[rustfmt::skip]
	fn do_fails_paying_after_expiration(on_retry: bool) {
		let outbound_payments = OutboundPayments::new(new_hash_map());
		let logger = test_utils::TestLogger::new();
		let network_graph = Arc::new(NetworkGraph::new(Network::Testnet, &logger));
		let scorer = RwLock::new(test_utils::TestScorer::new());
		let router = test_utils::TestRouter::new(network_graph, &logger, &scorer);
		let secp_ctx = Secp256k1::new();
		let keys_manager = test_utils::TestKeysInterface::new(&[0; 32], Network::Testnet);

		let past_expiry_time = std::time::SystemTime::UNIX_EPOCH.elapsed().unwrap().as_secs() - 2;
		let payment_params = PaymentParameters::from_node_id(
				PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[42; 32]).unwrap()),
				0
			).with_expiry_time(past_expiry_time);
		let expired_route_params = RouteParameters::from_payment_params_and_value(payment_params, 0);
		let pending_events = Mutex::new(VecDeque::new());
		if on_retry {
			outbound_payments.add_new_pending_payment(PaymentHash([0; 32]), RecipientOnionFields::spontaneous_empty(),
				PaymentId([0; 32]), None, &Route { paths: vec![], route_params: None },
				Some(Retry::Attempts(1)), Some(expired_route_params.payment_params.clone()),
				&&keys_manager, 0, None).unwrap();
			outbound_payments.find_route_and_send_payment(
				PaymentHash([0; 32]), PaymentId([0; 32]), expired_route_params, &&router, vec![],
				&|| InFlightHtlcs::new(), &&keys_manager, &&keys_manager, 0, &&logger, &pending_events,
				&|_| Ok(()));
			let events = pending_events.lock().unwrap();
			assert_eq!(events.len(), 1);
			if let Event::PaymentFailed { ref reason, .. } = events[0].0 {
				assert_eq!(reason.unwrap(), PaymentFailureReason::PaymentExpired);
			} else { panic!("Unexpected event"); }
		} else {
			let err = outbound_payments.send_payment(
				PaymentHash([0; 32]), RecipientOnionFields::spontaneous_empty(), PaymentId([0; 32]),
				Retry::Attempts(0), expired_route_params, &&router, vec![], || InFlightHtlcs::new(),
				&&keys_manager, &&keys_manager, 0, &&logger, &pending_events, |_| Ok(())).unwrap_err();
			if let RetryableSendFailure::PaymentExpired = err { } else { panic!("Unexpected error"); }
		}
	}

	#[test]
	fn find_route_error() {
		do_find_route_error(false);
		do_find_route_error(true);
	}
	#[rustfmt::skip]
	fn do_find_route_error(on_retry: bool) {
		let outbound_payments = OutboundPayments::new(new_hash_map());
		let logger = test_utils::TestLogger::new();
		let network_graph = Arc::new(NetworkGraph::new(Network::Testnet, &logger));
		let scorer = RwLock::new(test_utils::TestScorer::new());
		let router = test_utils::TestRouter::new(network_graph, &logger, &scorer);
		let secp_ctx = Secp256k1::new();
		let keys_manager = test_utils::TestKeysInterface::new(&[0; 32], Network::Testnet);

		let payment_params = PaymentParameters::from_node_id(
			PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[42; 32]).unwrap()), 0);
		let route_params = RouteParameters::from_payment_params_and_value(payment_params, 0);
		router.expect_find_route(route_params.clone(), Err(""));

		let pending_events = Mutex::new(VecDeque::new());
		if on_retry {
			outbound_payments.add_new_pending_payment(PaymentHash([0; 32]), RecipientOnionFields::spontaneous_empty(),
				PaymentId([0; 32]), None, &Route { paths: vec![], route_params: None },
				Some(Retry::Attempts(1)), Some(route_params.payment_params.clone()),
				&&keys_manager, 0, None).unwrap();
			outbound_payments.find_route_and_send_payment(
				PaymentHash([0; 32]), PaymentId([0; 32]), route_params, &&router, vec![],
				&|| InFlightHtlcs::new(), &&keys_manager, &&keys_manager, 0, &&logger, &pending_events,
				&|_| Ok(()));
			let events = pending_events.lock().unwrap();
			assert_eq!(events.len(), 1);
			if let Event::PaymentFailed { .. } = events[0].0 { } else { panic!("Unexpected event"); }
		} else {
			let err = outbound_payments.send_payment(
				PaymentHash([0; 32]), RecipientOnionFields::spontaneous_empty(), PaymentId([0; 32]),
				Retry::Attempts(0), route_params, &&router, vec![], || InFlightHtlcs::new(),
				&&keys_manager, &&keys_manager, 0, &&logger, &pending_events, |_| Ok(())).unwrap_err();
			if let RetryableSendFailure::RouteNotFound = err {
			} else { panic!("Unexpected error"); }
		}
	}

	#[test]
	#[rustfmt::skip]
	fn initial_send_payment_path_failed_evs() {
		let outbound_payments = OutboundPayments::new(new_hash_map());
		let logger = test_utils::TestLogger::new();
		let network_graph = Arc::new(NetworkGraph::new(Network::Testnet, &logger));
		let scorer = RwLock::new(test_utils::TestScorer::new());
		let router = test_utils::TestRouter::new(network_graph, &logger, &scorer);
		let secp_ctx = Secp256k1::new();
		let keys_manager = test_utils::TestKeysInterface::new(&[0; 32], Network::Testnet);

		let sender_pk = PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[42; 32]).unwrap());
		let receiver_pk = PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[43; 32]).unwrap());
		let payment_params = PaymentParameters::from_node_id(sender_pk, 0);
		let route_params = RouteParameters::from_payment_params_and_value(payment_params.clone(), 0);
		let failed_scid = 42;
		let route = Route {
			paths: vec![Path { hops: vec![RouteHop {
				pubkey: receiver_pk,
				node_features: NodeFeatures::empty(),
				short_channel_id: failed_scid,
				channel_features: ChannelFeatures::empty(),
				fee_msat: 0,
				cltv_expiry_delta: 0,
				maybe_announced_channel: true,
			}], blinded_tail: None }],
			route_params: Some(route_params.clone()),
		};
		router.expect_find_route(route_params.clone(), Ok(route.clone()));
		let mut route_params_w_failed_scid = route_params.clone();
		route_params_w_failed_scid.payment_params.previously_failed_channels.push(failed_scid);
		let mut route_w_failed_scid = route.clone();
		route_w_failed_scid.route_params = Some(route_params_w_failed_scid.clone());
		router.expect_find_route(route_params_w_failed_scid, Ok(route_w_failed_scid));
		router.expect_find_route(route_params.clone(), Ok(route.clone()));
		router.expect_find_route(route_params.clone(), Ok(route.clone()));

		// Ensure that a ChannelUnavailable error will result in blaming an scid in the
		// PaymentPathFailed event.
		let pending_events = Mutex::new(VecDeque::new());
		outbound_payments.send_payment(
			PaymentHash([0; 32]), RecipientOnionFields::spontaneous_empty(), PaymentId([0; 32]),
			Retry::Attempts(0), route_params.clone(), &&router, vec![], || InFlightHtlcs::new(),
			&&keys_manager, &&keys_manager, 0, &&logger, &pending_events,
			|_| Err(APIError::ChannelUnavailable { err: "test".to_owned() })).unwrap();
		let mut events = pending_events.lock().unwrap();
		assert_eq!(events.len(), 2);
		if let Event::PaymentPathFailed {
			short_channel_id,
			failure: PathFailure::InitialSend { err: APIError::ChannelUnavailable { .. }}, .. } = events[0].0
		{
			assert_eq!(short_channel_id, Some(failed_scid));
		} else { panic!("Unexpected event"); }
		if let Event::PaymentFailed { .. } = events[1].0 { } else { panic!("Unexpected event"); }
		events.clear();
		core::mem::drop(events);

		// Ensure that a MonitorUpdateInProgress "error" will not result in a PaymentPathFailed event.
		outbound_payments.send_payment(
			PaymentHash([0; 32]), RecipientOnionFields::spontaneous_empty(), PaymentId([0; 32]),
			Retry::Attempts(0), route_params.clone(), &&router, vec![], || InFlightHtlcs::new(),
			&&keys_manager, &&keys_manager, 0, &&logger, &pending_events,
			|_| Err(APIError::MonitorUpdateInProgress)).unwrap();
		assert_eq!(pending_events.lock().unwrap().len(), 0);

		// Ensure that any other error will result in a PaymentPathFailed event but no blamed scid.
		outbound_payments.send_payment(
			PaymentHash([0; 32]), RecipientOnionFields::spontaneous_empty(), PaymentId([1; 32]),
			Retry::Attempts(0), route_params.clone(), &&router, vec![], || InFlightHtlcs::new(),
			&&keys_manager, &&keys_manager, 0, &&logger, &pending_events,
			|_| Err(APIError::APIMisuseError { err: "test".to_owned() })).unwrap();
		let events = pending_events.lock().unwrap();
		assert_eq!(events.len(), 2);
		if let Event::PaymentPathFailed {
			short_channel_id,
			failure: PathFailure::InitialSend { err: APIError::APIMisuseError { .. }}, .. } = events[0].0
		{
			assert_eq!(short_channel_id, None);
		} else { panic!("Unexpected event"); }
		if let Event::PaymentFailed { .. } = events[1].0 { } else { panic!("Unexpected event"); }
	}

	#[test]
	#[rustfmt::skip]
	fn removes_stale_awaiting_invoice_using_absolute_timeout() {
		let pending_events = Mutex::new(VecDeque::new());
		let outbound_payments = OutboundPayments::new(new_hash_map());
		let payment_id = PaymentId([0; 32]);
		let absolute_expiry = 100;
		let tick_interval = 10;
		let expiration = StaleExpiration::AbsoluteTimeout(Duration::from_secs(absolute_expiry));

		assert!(!outbound_payments.has_pending_payments());
		assert!(
			outbound_payments.add_new_awaiting_invoice(
				payment_id, expiration, Retry::Attempts(0), RouteParametersConfig::default(), None,
			).is_ok()
		);
		assert!(outbound_payments.has_pending_payments());

		for seconds_since_epoch in (0..absolute_expiry).step_by(tick_interval) {
			let duration_since_epoch = Duration::from_secs(seconds_since_epoch);
			outbound_payments.remove_stale_payments(duration_since_epoch, &pending_events);

			assert!(outbound_payments.has_pending_payments());
			assert!(pending_events.lock().unwrap().is_empty());
		}

		let duration_since_epoch = Duration::from_secs(absolute_expiry);
		outbound_payments.remove_stale_payments(duration_since_epoch, &pending_events);

		assert!(!outbound_payments.has_pending_payments());
		assert!(!pending_events.lock().unwrap().is_empty());
		assert_eq!(
			pending_events.lock().unwrap().pop_front(),
			Some((Event::PaymentFailed {
				payment_id,
				payment_hash: None,
				reason: Some(PaymentFailureReason::InvoiceRequestExpired),
			}, None)),
		);
		assert!(pending_events.lock().unwrap().is_empty());

		assert!(
			outbound_payments.add_new_awaiting_invoice(
				payment_id, expiration, Retry::Attempts(0), RouteParametersConfig::default(), None,
			).is_ok()
		);
		assert!(outbound_payments.has_pending_payments());

		assert!(
			outbound_payments.add_new_awaiting_invoice(
				payment_id, expiration, Retry::Attempts(0), RouteParametersConfig::default(), None,
			).is_err()
		);
	}

	#[test]
	#[rustfmt::skip]
	fn removes_stale_awaiting_invoice_using_timer_ticks() {
		let pending_events = Mutex::new(VecDeque::new());
		let outbound_payments = OutboundPayments::new(new_hash_map());
		let payment_id = PaymentId([0; 32]);
		let timer_ticks = 3;
		let expiration = StaleExpiration::TimerTicks(timer_ticks);

		assert!(!outbound_payments.has_pending_payments());
		assert!(
			outbound_payments.add_new_awaiting_invoice(
				payment_id, expiration, Retry::Attempts(0), RouteParametersConfig::default(), None,
			).is_ok()
		);
		assert!(outbound_payments.has_pending_payments());

		for i in 0..timer_ticks {
			let duration_since_epoch = Duration::from_secs(i * 60);
			outbound_payments.remove_stale_payments(duration_since_epoch, &pending_events);

			assert!(outbound_payments.has_pending_payments());
			assert!(pending_events.lock().unwrap().is_empty());
		}

		let duration_since_epoch = Duration::from_secs(timer_ticks * 60);
		outbound_payments.remove_stale_payments(duration_since_epoch, &pending_events);

		assert!(!outbound_payments.has_pending_payments());
		assert!(!pending_events.lock().unwrap().is_empty());
		assert_eq!(
			pending_events.lock().unwrap().pop_front(),
			Some((Event::PaymentFailed {
				payment_id,
				payment_hash: None,
				reason: Some(PaymentFailureReason::InvoiceRequestExpired),
			}, None)),
		);
		assert!(pending_events.lock().unwrap().is_empty());

		assert!(
			outbound_payments.add_new_awaiting_invoice(
				payment_id, expiration, Retry::Attempts(0), RouteParametersConfig::default(), None,
			).is_ok()
		);
		assert!(outbound_payments.has_pending_payments());

		assert!(
			outbound_payments.add_new_awaiting_invoice(
				payment_id, expiration, Retry::Attempts(0), RouteParametersConfig::default(), None,
			).is_err()
		);
	}

	#[test]
	#[rustfmt::skip]
	fn removes_abandoned_awaiting_invoice() {
		let pending_events = Mutex::new(VecDeque::new());
		let outbound_payments = OutboundPayments::new(new_hash_map());
		let payment_id = PaymentId([0; 32]);
		let expiration = StaleExpiration::AbsoluteTimeout(Duration::from_secs(100));

		assert!(!outbound_payments.has_pending_payments());
		assert!(
			outbound_payments.add_new_awaiting_invoice(
				payment_id, expiration, Retry::Attempts(0), RouteParametersConfig::default(), None,
			).is_ok()
		);
		assert!(outbound_payments.has_pending_payments());

		outbound_payments.abandon_payment(
			payment_id, PaymentFailureReason::UserAbandoned, &pending_events
		);
		assert!(!outbound_payments.has_pending_payments());
		assert!(!pending_events.lock().unwrap().is_empty());
		assert_eq!(
			pending_events.lock().unwrap().pop_front(),
			Some((Event::PaymentFailed {
				payment_id, payment_hash: None, reason: Some(PaymentFailureReason::UserAbandoned),
			}, None)),
		);
		assert!(pending_events.lock().unwrap().is_empty());
	}

	#[cfg(feature = "std")]
	#[test]
	#[rustfmt::skip]
	fn fails_sending_payment_for_expired_bolt12_invoice() {
		let logger = test_utils::TestLogger::new();
		let network_graph = Arc::new(NetworkGraph::new(Network::Testnet, &logger));
		let scorer = RwLock::new(test_utils::TestScorer::new());
		let router = test_utils::TestRouter::new(network_graph, &logger, &scorer);
		let secp_ctx = Secp256k1::new();
		let keys_manager = test_utils::TestKeysInterface::new(&[0; 32], Network::Testnet);
		let expanded_key = ExpandedKey::new([42; 32]);
		let nonce = Nonce([0; 16]);

		let pending_events = Mutex::new(VecDeque::new());
		let outbound_payments = OutboundPayments::new(new_hash_map());
		let payment_id = PaymentId([0; 32]);
		let expiration = StaleExpiration::AbsoluteTimeout(Duration::from_secs(100));

		assert!(
			outbound_payments.add_new_awaiting_invoice(
				payment_id, expiration, Retry::Attempts(0), RouteParametersConfig::default(), None,
			).is_ok()
		);
		assert!(outbound_payments.has_pending_payments());

		let created_at = now() - DEFAULT_RELATIVE_EXPIRY;
		let invoice = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.build().unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id).unwrap()
			.build_and_sign().unwrap()
			.respond_with_no_std(payment_paths(), payment_hash(), created_at).unwrap()
			.build().unwrap()
			.sign(recipient_sign).unwrap();

		assert_eq!(
			outbound_payments.send_payment_for_bolt12_invoice(
				&invoice, payment_id, &&router, vec![], Bolt12InvoiceFeatures::empty(),
				|| InFlightHtlcs::new(), &&keys_manager, &&keys_manager, &EmptyNodeIdLookUp {},
				&secp_ctx, 0, &&logger, &pending_events, |_| panic!()
			),
			Err(Bolt12PaymentError::SendingFailed(RetryableSendFailure::PaymentExpired)),
		);
		assert!(!outbound_payments.has_pending_payments());

		let payment_hash = Some(invoice.payment_hash());
		let reason = Some(PaymentFailureReason::PaymentExpired);

		assert!(!pending_events.lock().unwrap().is_empty());
		assert_eq!(
			pending_events.lock().unwrap().pop_front(),
			Some((Event::PaymentFailed { payment_id, payment_hash, reason }, None)),
		);
		assert!(pending_events.lock().unwrap().is_empty());
	}

	#[test]
	#[rustfmt::skip]
	fn fails_finding_route_for_bolt12_invoice() {
		let logger = test_utils::TestLogger::new();
		let network_graph = Arc::new(NetworkGraph::new(Network::Testnet, &logger));
		let scorer = RwLock::new(test_utils::TestScorer::new());
		let router = test_utils::TestRouter::new(network_graph, &logger, &scorer);
		let secp_ctx = Secp256k1::new();
		let keys_manager = test_utils::TestKeysInterface::new(&[0; 32], Network::Testnet);

		let pending_events = Mutex::new(VecDeque::new());
		let outbound_payments = OutboundPayments::new(new_hash_map());
		let expanded_key = ExpandedKey::new([42; 32]);
		let nonce = Nonce([0; 16]);
		let payment_id = PaymentId([0; 32]);
		let expiration = StaleExpiration::AbsoluteTimeout(Duration::from_secs(100));

		let invoice = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.build().unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id).unwrap()
			.build_and_sign().unwrap()
			.respond_with_no_std(payment_paths(), payment_hash(), now()).unwrap()
			.build().unwrap()
			.sign(recipient_sign).unwrap();

		let route_params_config = RouteParametersConfig::default().with_max_total_routing_fee_msat(invoice.amount_msats() / 100 + 50_000);

		assert!(
			outbound_payments.add_new_awaiting_invoice(
				payment_id, expiration, Retry::Attempts(0),
				route_params_config, None,
			).is_ok()
		);
		assert!(outbound_payments.has_pending_payments());

		let route_params = RouteParameters::from_payment_params_and_value(
			PaymentParameters::from_bolt12_invoice(&invoice),
			invoice.amount_msats(),
		);
		router.expect_find_route(route_params, Err(""));

		assert_eq!(
			outbound_payments.send_payment_for_bolt12_invoice(
				&invoice, payment_id, &&router, vec![], Bolt12InvoiceFeatures::empty(),
				|| InFlightHtlcs::new(), &&keys_manager, &&keys_manager, &EmptyNodeIdLookUp {},
				&secp_ctx, 0, &&logger, &pending_events, |_| panic!()
			),
			Err(Bolt12PaymentError::SendingFailed(RetryableSendFailure::RouteNotFound)),
		);
		assert!(!outbound_payments.has_pending_payments());

		let payment_hash = Some(invoice.payment_hash());
		let reason = Some(PaymentFailureReason::RouteNotFound);

		assert!(!pending_events.lock().unwrap().is_empty());
		assert_eq!(
			pending_events.lock().unwrap().pop_front(),
			Some((Event::PaymentFailed { payment_id, payment_hash, reason }, None)),
		);
		assert!(pending_events.lock().unwrap().is_empty());
	}

	#[test]
	#[rustfmt::skip]
	fn sends_payment_for_bolt12_invoice() {
		let logger = test_utils::TestLogger::new();
		let network_graph = Arc::new(NetworkGraph::new(Network::Testnet, &logger));
		let scorer = RwLock::new(test_utils::TestScorer::new());
		let router = test_utils::TestRouter::new(network_graph, &logger, &scorer);
		let secp_ctx = Secp256k1::new();
		let keys_manager = test_utils::TestKeysInterface::new(&[0; 32], Network::Testnet);

		let pending_events = Mutex::new(VecDeque::new());
		let outbound_payments = OutboundPayments::new(new_hash_map());
		let expanded_key = ExpandedKey::new([42; 32]);
		let nonce = Nonce([0; 16]);
		let payment_id = PaymentId([0; 32]);
		let expiration = StaleExpiration::AbsoluteTimeout(Duration::from_secs(100));

		let invoice = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.build().unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id).unwrap()
			.build_and_sign().unwrap()
			.respond_with_no_std(payment_paths(), payment_hash(), now()).unwrap()
			.build().unwrap()
			.sign(recipient_sign).unwrap();

		let route_params = RouteParameters {
			payment_params: PaymentParameters::from_bolt12_invoice(&invoice),
			final_value_msat: invoice.amount_msats(),
			max_total_routing_fee_msat: Some(1234),
		};
		router.expect_find_route(
			route_params.clone(),
			Ok(Route {
				paths: vec![
					Path {
						hops: vec![
							RouteHop {
								pubkey: recipient_pubkey(),
								node_features: NodeFeatures::empty(),
								short_channel_id: 42,
								channel_features: ChannelFeatures::empty(),
								fee_msat: invoice.amount_msats(),
								cltv_expiry_delta: 0,
								maybe_announced_channel: true,
							}
						],
						blinded_tail: None,
					}
				],
				route_params: Some(route_params),
			})
		);

		assert!(!outbound_payments.has_pending_payments());
		assert_eq!(
			outbound_payments.send_payment_for_bolt12_invoice(
				&invoice, payment_id, &&router, vec![], Bolt12InvoiceFeatures::empty(),
				|| InFlightHtlcs::new(), &&keys_manager, &&keys_manager, &EmptyNodeIdLookUp {},
				&secp_ctx, 0, &&logger, &pending_events, |_| panic!()
			),
			Err(Bolt12PaymentError::UnexpectedInvoice),
		);
		assert!(!outbound_payments.has_pending_payments());
		assert!(pending_events.lock().unwrap().is_empty());

		let route_params_config = RouteParametersConfig::default().with_max_total_routing_fee_msat(1234);

		assert!(
			outbound_payments.add_new_awaiting_invoice(
				payment_id, expiration, Retry::Attempts(0), route_params_config, None,
			).is_ok()
		);
		assert!(outbound_payments.has_pending_payments());

		assert_eq!(
			outbound_payments.send_payment_for_bolt12_invoice(
				&invoice, payment_id, &&router, vec![], Bolt12InvoiceFeatures::empty(),
				|| InFlightHtlcs::new(), &&keys_manager, &&keys_manager, &EmptyNodeIdLookUp {},
				&secp_ctx, 0, &&logger, &pending_events, |_| Ok(())
			),
			Ok(()),
		);
		assert!(outbound_payments.has_pending_payments());
		assert!(pending_events.lock().unwrap().is_empty());

		assert_eq!(
			outbound_payments.send_payment_for_bolt12_invoice(
				&invoice, payment_id, &&router, vec![], Bolt12InvoiceFeatures::empty(),
				|| InFlightHtlcs::new(), &&keys_manager, &&keys_manager, &EmptyNodeIdLookUp {},
				&secp_ctx, 0, &&logger, &pending_events, |_| panic!()
			),
			Err(Bolt12PaymentError::DuplicateInvoice),
		);
		assert!(outbound_payments.has_pending_payments());
		assert!(pending_events.lock().unwrap().is_empty());
	}

	#[rustfmt::skip]
	fn dummy_invoice_request() -> InvoiceRequest {
		let expanded_key = ExpandedKey::new([42; 32]);
		let entropy = FixedEntropy {};
		let nonce = Nonce::from_entropy_source(&entropy);
		let secp_ctx = Secp256k1::new();
		let payment_id = PaymentId([1; 32]);

		OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.build().unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.build_and_sign()
			.unwrap()
	}

	#[test]
	#[rustfmt::skip]
	fn time_out_unreleased_async_payments() {
		let pending_events = Mutex::new(VecDeque::new());
		let outbound_payments = OutboundPayments::new(new_hash_map());
		let payment_id = PaymentId([0; 32]);
		let absolute_expiry = 60;

		let mut outbounds = outbound_payments.pending_outbound_payments.lock().unwrap();
		let payment_params = PaymentParameters::from_node_id(test_utils::pubkey(42), 0)
			.with_expiry_time(absolute_expiry);
		let route_params = RouteParameters {
			payment_params,
			final_value_msat: 0,
			max_total_routing_fee_msat: None,
		};
		let payment_hash = PaymentHash([0; 32]);
		let outbound = PendingOutboundPayment::StaticInvoiceReceived {
			payment_hash,
			keysend_preimage: PaymentPreimage([0; 32]),
			retry_strategy: Retry::Attempts(0),
			route_params,
			invoice_request: dummy_invoice_request(),
			static_invoice: dummy_static_invoice(),
			expiry_time: Duration::from_secs(absolute_expiry + 2),
			hold_htlcs_at_next_hop: false
		};
		outbounds.insert(payment_id, outbound);
		core::mem::drop(outbounds);

		// The payment will not be removed if it isn't expired yet.
		outbound_payments.remove_stale_payments(Duration::from_secs(absolute_expiry), &pending_events);
		let outbounds = outbound_payments.pending_outbound_payments.lock().unwrap();
		assert_eq!(outbounds.len(), 1);
		let events = pending_events.lock().unwrap();
		assert_eq!(events.len(), 0);
		core::mem::drop(outbounds);
		core::mem::drop(events);

		outbound_payments.remove_stale_payments(Duration::from_secs(absolute_expiry + 1), &pending_events);
		let outbounds = outbound_payments.pending_outbound_payments.lock().unwrap();
		assert_eq!(outbounds.len(), 0);
		let events = pending_events.lock().unwrap();
		assert_eq!(events.len(), 1);
		assert_eq!(events[0], (Event::PaymentFailed {
			payment_hash: Some(payment_hash),
			payment_id,
			reason: Some(PaymentFailureReason::PaymentExpired),
		}, None));
	}

	#[test]
	#[rustfmt::skip]
	fn abandon_unreleased_async_payment() {
		let pending_events = Mutex::new(VecDeque::new());
		let outbound_payments = OutboundPayments::new(new_hash_map());
		let payment_id = PaymentId([0; 32]);
		let absolute_expiry = 60;

		let mut outbounds = outbound_payments.pending_outbound_payments.lock().unwrap();
		let payment_params = PaymentParameters::from_node_id(test_utils::pubkey(42), 0)
			.with_expiry_time(absolute_expiry);
		let route_params = RouteParameters {
			payment_params,
			final_value_msat: 0,
			max_total_routing_fee_msat: None,
		};
		let payment_hash = PaymentHash([0; 32]);
		let outbound = PendingOutboundPayment::StaticInvoiceReceived {
			payment_hash,
			keysend_preimage: PaymentPreimage([0; 32]),
			retry_strategy: Retry::Attempts(0),
			route_params,
			invoice_request: dummy_invoice_request(),
			static_invoice: dummy_static_invoice(),
			expiry_time: now(),
			hold_htlcs_at_next_hop: false,
		};
		outbounds.insert(payment_id, outbound);
		core::mem::drop(outbounds);

		outbound_payments.abandon_payment(
			payment_id, PaymentFailureReason::UserAbandoned, &pending_events
		);
		let outbounds = outbound_payments.pending_outbound_payments.lock().unwrap();
		assert_eq!(outbounds.len(), 0);
		let events = pending_events.lock().unwrap();
		assert_eq!(events.len(), 1);
		assert_eq!(events[0], (Event::PaymentFailed {
			payment_hash: Some(payment_hash),
			payment_id,
			reason: Some(PaymentFailureReason::UserAbandoned),
		}, None));
	}
}
