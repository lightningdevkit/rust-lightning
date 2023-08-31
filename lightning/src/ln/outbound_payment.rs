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

use crate::sign::{EntropySource, NodeSigner, Recipient};
use crate::events::{self, PaymentFailureReason};
use crate::ln::{PaymentHash, PaymentPreimage, PaymentSecret};
use crate::ln::channelmanager::{ChannelDetails, EventCompletionAction, HTLCSource, PaymentId};
use crate::ln::onion_utils::{DecodedOnionFailure, HTLCFailReason};
use crate::offers::invoice::Bolt12Invoice;
use crate::routing::router::{InFlightHtlcs, Path, PaymentParameters, Route, RouteParameters, Router};
use crate::util::errors::APIError;
use crate::util::logger::Logger;
use crate::util::time::Time;
#[cfg(all(not(feature = "no-std"), test))]
use crate::util::time::tests::SinceEpoch;
use crate::util::ser::ReadableArgs;

use core::fmt::{self, Display, Formatter};
use core::ops::Deref;

use crate::prelude::*;
use crate::sync::Mutex;

/// The number of ticks of [`ChannelManager::timer_tick_occurred`] until we time-out the idempotency
/// of payments by [`PaymentId`]. See [`OutboundPayments::remove_stale_payments`].
///
/// [`ChannelManager::timer_tick_occurred`]: crate::ln::channelmanager::ChannelManager::timer_tick_occurred
pub(crate) const IDEMPOTENCY_TIMEOUT_TICKS: u8 = 7;

/// The number of ticks of [`ChannelManager::timer_tick_occurred`] until an invoice request without
/// a response is timed out.
///
/// [`ChannelManager::timer_tick_occurred`]: crate::ln::channelmanager::ChannelManager::timer_tick_occurred
const INVOICE_REQUEST_TIMEOUT_TICKS: u8 = 3;

/// Stores the session_priv for each part of a payment that is still pending. For versions 0.0.102
/// and later, also stores information for retrying the payment.
pub(crate) enum PendingOutboundPayment {
	Legacy {
		session_privs: HashSet<[u8; 32]>,
	},
	AwaitingInvoice {
		timer_ticks_without_response: u8,
	},
	InvoiceReceived {
		payment_hash: PaymentHash,
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
		custom_tlvs: Vec<(u64, Vec<u8>)>,
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
		/// Filled in for any payment which moved to `Fulfilled` on LDK 0.0.104 or later.
		payment_hash: Option<PaymentHash>,
		timer_ticks_without_htlcs: u8,
	},
	/// When we've decided to give up retrying a payment, we mark it as abandoned so we can eventually
	/// generate a `PaymentFailed` event when all HTLCs have irrevocably failed.
	Abandoned {
		session_privs: HashSet<[u8; 32]>,
		payment_hash: PaymentHash,
		/// Will be `None` if the payment was serialized before 0.0.115.
		reason: Option<PaymentFailureReason>,
	},
}

impl PendingOutboundPayment {
	fn increment_attempts(&mut self) {
		if let PendingOutboundPayment::Retryable { attempts, .. } = self {
			attempts.count += 1;
		}
	}
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

	fn payment_hash(&self) -> Option<PaymentHash> {
		match self {
			PendingOutboundPayment::Legacy { .. } => None,
			PendingOutboundPayment::AwaitingInvoice { .. } => None,
			PendingOutboundPayment::InvoiceReceived { payment_hash } => Some(*payment_hash),
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
				PendingOutboundPayment::Abandoned { session_privs, .. } => session_privs,
			PendingOutboundPayment::AwaitingInvoice { .. } |
				PendingOutboundPayment::InvoiceReceived { .. } => { debug_assert!(false); return; },
		});
		let payment_hash = self.payment_hash();
		*self = PendingOutboundPayment::Fulfilled { session_privs, payment_hash, timer_ticks_without_htlcs: 0 };
	}

	fn mark_abandoned(&mut self, reason: PaymentFailureReason) {
		if let PendingOutboundPayment::Retryable { session_privs, payment_hash, .. } = self {
			let mut our_session_privs = HashSet::new();
			core::mem::swap(&mut our_session_privs, session_privs);
			*self = PendingOutboundPayment::Abandoned {
				session_privs: our_session_privs,
				payment_hash: *payment_hash,
				reason: Some(reason)
			};
		} else if let PendingOutboundPayment::InvoiceReceived { payment_hash } = self {
			*self = PendingOutboundPayment::Abandoned {
				session_privs: HashSet::new(),
				payment_hash: *payment_hash,
				reason: Some(reason)
			};
		}
	}

	/// panics if path is None and !self.is_fulfilled
	fn remove(&mut self, session_priv: &[u8; 32], path: Option<&Path>) -> bool {
		let remove_res = match self {
			PendingOutboundPayment::Legacy { session_privs } |
				PendingOutboundPayment::Retryable { session_privs, .. } |
				PendingOutboundPayment::Fulfilled { session_privs, .. } |
				PendingOutboundPayment::Abandoned { session_privs, .. } => {
					session_privs.remove(session_priv)
				},
			PendingOutboundPayment::AwaitingInvoice { .. } |
				PendingOutboundPayment::InvoiceReceived { .. } => { debug_assert!(false); false },
		};
		if remove_res {
			if let PendingOutboundPayment::Retryable { ref mut pending_amt_msat, ref mut pending_fee_msat, .. } = self {
				let path = path.expect("Fulfilling a payment should always come with a path");
				*pending_amt_msat -= path.final_value_msat();
				if let Some(fee_msat) = pending_fee_msat.as_mut() {
					*fee_msat -= path.fee_msat();
				}
			}
		}
		remove_res
	}

	pub(super) fn insert(&mut self, session_priv: [u8; 32], path: &Path) -> bool {
		let insert_res = match self {
			PendingOutboundPayment::Legacy { session_privs } |
				PendingOutboundPayment::Retryable { session_privs, .. } => {
					session_privs.insert(session_priv)
				},
			PendingOutboundPayment::AwaitingInvoice { .. } |
				PendingOutboundPayment::InvoiceReceived { .. } => { debug_assert!(false); false },
			PendingOutboundPayment::Fulfilled { .. } => false,
			PendingOutboundPayment::Abandoned { .. } => false,
		};
		if insert_res {
			if let PendingOutboundPayment::Retryable { ref mut pending_amt_msat, ref mut pending_fee_msat, .. } = self {
				*pending_amt_msat += path.final_value_msat();
				if let Some(fee_msat) = pending_fee_msat.as_mut() {
					*fee_msat += path.fee_msat();
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
				},
			PendingOutboundPayment::AwaitingInvoice { .. } => 0,
			PendingOutboundPayment::InvoiceReceived { .. } => 0,
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
	Attempts(usize),
	#[cfg(not(feature = "no-std"))]
	/// Time elapsed before abandoning retries for a payment. At least one attempt at payment is made;
	/// see [`PaymentParameters::expiry_time`] to avoid any attempt at payment after a specific time.
	///
	/// [`PaymentParameters::expiry_time`]: crate::routing::router::PaymentParameters::expiry_time
	Timeout(core::time::Duration),
}

impl Retry {
	pub(crate) fn is_retryable_now(&self, attempts: &PaymentAttempts) -> bool {
		match (self, attempts) {
			(Retry::Attempts(max_retry_count), PaymentAttempts { count, .. }) => {
				max_retry_count > count
			},
			#[cfg(all(not(feature = "no-std"), not(test)))]
			(Retry::Timeout(max_duration), PaymentAttempts { first_attempted_at, .. }) =>
				*max_duration >= crate::util::time::MonotonicTime::now().duration_since(*first_attempted_at),
			#[cfg(all(not(feature = "no-std"), test))]
			(Retry::Timeout(max_duration), PaymentAttempts { first_attempted_at, .. }) =>
				*max_duration >= SinceEpoch::now().duration_since(*first_attempted_at),
		}
	}
}

#[cfg(feature = "std")]
pub(super) fn has_expired(route_params: &RouteParameters) -> bool {
	if let Some(expiry_time) = route_params.payment_params.expiry_time {
		if let Ok(elapsed) = std::time::SystemTime::UNIX_EPOCH.elapsed() {
			return elapsed > core::time::Duration::from_secs(expiry_time)
		}
	}
	false
}

pub(crate) type PaymentAttempts = PaymentAttemptsUsingTime<ConfiguredTime>;

/// Storing minimal payment attempts information required for determining if a outbound payment can
/// be retried.
pub(crate) struct PaymentAttemptsUsingTime<T: Time> {
	/// This count will be incremented only after the result of the attempt is known. When it's 0,
	/// it means the result of the first attempt is not known yet.
	pub(crate) count: usize,
	/// This field is only used when retry is `Retry::Timeout` which is only build with feature std
	#[cfg(not(feature = "no-std"))]
	first_attempted_at: T,
	#[cfg(feature = "no-std")]
	phantom: core::marker::PhantomData<T>,

}

#[cfg(not(any(feature = "no-std", test)))]
type ConfiguredTime = crate::util::time::MonotonicTime;
#[cfg(feature = "no-std")]
type ConfiguredTime = crate::util::time::Eternity;
#[cfg(all(not(feature = "no-std"), test))]
type ConfiguredTime = SinceEpoch;

impl<T: Time> PaymentAttemptsUsingTime<T> {
	pub(crate) fn new() -> Self {
		PaymentAttemptsUsingTime {
			count: 0,
			#[cfg(not(feature = "no-std"))]
			first_attempted_at: T::now(),
			#[cfg(feature = "no-std")]
			phantom: core::marker::PhantomData,
		}
	}
}

impl<T: Time> Display for PaymentAttemptsUsingTime<T> {
	fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
		#[cfg(feature = "no-std")]
		return write!(f, "attempts: {}", self.count);
		#[cfg(not(feature = "no-std"))]
		return write!(
			f,
			"attempts: {}, duration: {}s",
			self.count,
			T::now().duration_since(self.first_attempted_at).as_secs()
		);
	}
}

/// Indicates an immediate error on [`ChannelManager::send_payment`]. Further errors may be
/// surfaced later via [`Event::PaymentPathFailed`] and [`Event::PaymentFailed`].
///
/// [`ChannelManager::send_payment`]: crate::ln::channelmanager::ChannelManager::send_payment
/// [`Event::PaymentPathFailed`]: crate::events::Event::PaymentPathFailed
/// [`Event::PaymentFailed`]: crate::events::Event::PaymentFailed
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RetryableSendFailure {
	/// The provided [`PaymentParameters::expiry_time`] indicated that the payment has expired. Note
	/// that this error is *not* caused by [`Retry::Timeout`].
	///
	/// [`PaymentParameters::expiry_time`]: crate::routing::router::PaymentParameters::expiry_time
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
}

/// If a payment fails to send with [`ChannelManager::send_payment_with_route`], it can be in one
/// of several states. This enum is returned as the Err() type describing which state the payment
/// is in, see the description of individual enum states for more.
///
/// [`ChannelManager::send_payment_with_route`]: crate::ln::channelmanager::ChannelManager::send_payment_with_route
#[derive(Clone, Debug)]
pub enum PaymentSendFailure {
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

/// An error when attempting to pay a BOLT 12 invoice.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Bolt12PaymentError {
	/// The invoice was not requested.
	UnexpectedInvoice,
	/// Payment for an invoice with the corresponding [`PaymentId`] was already initiated.
	DuplicateInvoice,
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
	pub fn with_custom_tlvs(mut self, mut custom_tlvs: Vec<(u64, Vec<u8>)>) -> Result<Self, ()> {
		custom_tlvs.sort_unstable_by_key(|(typ, _)| *typ);
		let mut prev_type = None;
		for (typ, _) in custom_tlvs.iter() {
			if *typ < 1 << 16 { return Err(()); }
			if *typ == 5482373484 { return Err(()); } // keysend
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
	pub fn custom_tlvs(&self) -> &Vec<(u64, Vec<u8>)> {
		&self.custom_tlvs
	}

	/// When we have received some HTLC(s) towards an MPP payment, as we receive further HTLC(s) we
	/// have to make sure that some fields match exactly across the parts. For those that aren't
	/// required to match, if they don't match we should remove them so as to not expose data
	/// that's dependent on the HTLC receive order to users.
	///
	/// Here we implement this, first checking compatibility then mutating two objects and then
	/// dropping any remaining non-matching fields from both.
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
	pub recipient_onion: RecipientOnionFields,
	pub total_value: u64,
	pub cur_height: u32,
	pub payment_id: PaymentId,
	pub keysend_preimage: &'a Option<PaymentPreimage>,
	pub session_priv_bytes: [u8; 32],
}

const BOLT_12_INVOICE_RETRY_STRATEGY: Retry = Retry::Attempts(3);

pub(super) struct OutboundPayments {
	pub(super) pending_outbound_payments: Mutex<HashMap<PaymentId, PendingOutboundPayment>>,
	pub(super) retry_lock: Mutex<()>,
}

impl OutboundPayments {
	pub(super) fn new() -> Self {
		Self {
			pending_outbound_payments: Mutex::new(HashMap::new()),
			retry_lock: Mutex::new(()),
		}
	}

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
		self.send_payment_internal(payment_id, payment_hash, recipient_onion, None, retry_strategy,
			route_params, router, first_hops, &compute_inflight_htlcs, entropy_source, node_signer,
			best_block_height, logger, pending_events, &send_payment_along_path)
	}

	pub(super) fn send_payment_with_route<ES: Deref, NS: Deref, F>(
		&self, route: &Route, payment_hash: PaymentHash, recipient_onion: RecipientOnionFields,
		payment_id: PaymentId, entropy_source: &ES, node_signer: &NS, best_block_height: u32,
		send_payment_along_path: F
	) -> Result<(), PaymentSendFailure>
	where
		ES::Target: EntropySource,
		NS::Target: NodeSigner,
		F: Fn(SendAlongPathArgs) -> Result<(), APIError>
	{
		let onion_session_privs = self.add_new_pending_payment(payment_hash, recipient_onion.clone(), payment_id, None, route, None, None, entropy_source, best_block_height)?;
		self.pay_route_internal(route, payment_hash, recipient_onion, None, payment_id, None,
			onion_session_privs, node_signer, best_block_height, &send_payment_along_path)
			.map_err(|e| { self.remove_outbound_if_all_failed(payment_id, &e); e })
	}

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
		let payment_hash = PaymentHash(Sha256::hash(&preimage.0).into_inner());
		self.send_payment_internal(payment_id, payment_hash, recipient_onion, Some(preimage),
			retry_strategy, route_params, router, first_hops, inflight_htlcs, entropy_source,
			node_signer, best_block_height, logger, pending_events, send_payment_along_path)
			.map(|()| payment_hash)
	}

	pub(super) fn send_spontaneous_payment_with_route<ES: Deref, NS: Deref, F>(
		&self, route: &Route, payment_preimage: Option<PaymentPreimage>,
		recipient_onion: RecipientOnionFields, payment_id: PaymentId, entropy_source: &ES,
		node_signer: &NS, best_block_height: u32, send_payment_along_path: F
	) -> Result<PaymentHash, PaymentSendFailure>
	where
		ES::Target: EntropySource,
		NS::Target: NodeSigner,
		F: Fn(SendAlongPathArgs) -> Result<(), APIError>,
	{
		let preimage = payment_preimage
			.unwrap_or_else(|| PaymentPreimage(entropy_source.get_secure_random_bytes()));
		let payment_hash = PaymentHash(Sha256::hash(&preimage.0).into_inner());
		let onion_session_privs = self.add_new_pending_payment(payment_hash, recipient_onion.clone(),
			payment_id, Some(preimage), &route, None, None, entropy_source, best_block_height)?;

		match self.pay_route_internal(route, payment_hash, recipient_onion, Some(preimage),
			payment_id, None, onion_session_privs, node_signer, best_block_height, &send_payment_along_path
		) {
			Ok(()) => Ok(payment_hash),
			Err(e) => {
				self.remove_outbound_if_all_failed(payment_id, &e);
				Err(e)
			}
		}
	}

	#[allow(unused)]
	pub(super) fn send_payment_for_bolt12_invoice<R: Deref, ES: Deref, NS: Deref, IH, SP, L: Deref>(
		&self, invoice: &Bolt12Invoice, payment_id: PaymentId, router: &R,
		first_hops: Vec<ChannelDetails>, inflight_htlcs: IH, entropy_source: &ES, node_signer: &NS,
		best_block_height: u32, logger: &L,
		pending_events: &Mutex<VecDeque<(events::Event, Option<EventCompletionAction>)>>,
		send_payment_along_path: SP,
	) -> Result<(), Bolt12PaymentError>
	where
		R::Target: Router,
		ES::Target: EntropySource,
		NS::Target: NodeSigner,
		L::Target: Logger,
		IH: Fn() -> InFlightHtlcs,
		SP: Fn(SendAlongPathArgs) -> Result<(), APIError>,
	{
		let payment_hash = invoice.payment_hash();
		match self.pending_outbound_payments.lock().unwrap().entry(payment_id) {
			hash_map::Entry::Occupied(entry) if entry.get().is_awaiting_invoice() => {
				*entry.into_mut() = PendingOutboundPayment::InvoiceReceived { payment_hash };
			},
			hash_map::Entry::Occupied(_) => return Err(Bolt12PaymentError::DuplicateInvoice),
			hash_map::Entry::Vacant(_) => return Err(Bolt12PaymentError::UnexpectedInvoice),
		};

		let route_params = RouteParameters {
			payment_params: PaymentParameters::from_bolt12_invoice(&invoice),
			final_value_msat: invoice.amount_msats(),
		};

		self.find_route_and_send_payment(
			payment_hash, payment_id, route_params, router, first_hops, &inflight_htlcs,
			entropy_source, node_signer, best_block_height, logger, pending_events,
			&send_payment_along_path
		);

		Ok(())
	}

	pub(super) fn check_retry_payments<R: Deref, ES: Deref, NS: Deref, SP, IH, FH, L: Deref>(
		&self, router: &R, first_hops: FH, inflight_htlcs: IH, entropy_source: &ES, node_signer: &NS,
		best_block_height: u32,
		pending_events: &Mutex<VecDeque<(events::Event, Option<EventCompletionAction>)>>, logger: &L,
		send_payment_along_path: SP,
	)
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
		loop {
			let mut outbounds = self.pending_outbound_payments.lock().unwrap();
			let mut retry_id_route_params = None;
			for (pmt_id, pmt) in outbounds.iter_mut() {
				if pmt.is_auto_retryable_now() {
					if let PendingOutboundPayment::Retryable { pending_amt_msat, total_msat, payment_params: Some(params), payment_hash, .. } = pmt {
						if pending_amt_msat < total_msat {
							retry_id_route_params = Some((*payment_hash, *pmt_id, RouteParameters {
								final_value_msat: *total_msat - *pending_amt_msat,
								payment_params: params.clone(),
							}));
							break
						}
					} else { debug_assert!(false); }
				}
			}
			core::mem::drop(outbounds);
			if let Some((payment_hash, payment_id, route_params)) = retry_id_route_params {
				self.find_route_and_send_payment(payment_hash, payment_id, route_params, router, first_hops(), &inflight_htlcs, entropy_source, node_signer, best_block_height, logger, pending_events, &send_payment_along_path)
			} else { break }
		}

		let mut outbounds = self.pending_outbound_payments.lock().unwrap();
		outbounds.retain(|pmt_id, pmt| {
			let mut retain = true;
			if !pmt.is_auto_retryable_now() && pmt.remaining_parts() == 0 && !pmt.is_awaiting_invoice() {
				pmt.mark_abandoned(PaymentFailureReason::RetriesExhausted);
				if let PendingOutboundPayment::Abandoned { payment_hash, reason, .. } = pmt {
					pending_events.lock().unwrap().push_back((events::Event::PaymentFailed {
						payment_id: *pmt_id,
						payment_hash: *payment_hash,
						reason: *reason,
					}, None));
					retain = false;
				}
			}
			retain
		});
	}

	pub(super) fn needs_abandon(&self) -> bool {
		let outbounds = self.pending_outbound_payments.lock().unwrap();
		outbounds.iter().any(|(_, pmt)|
			!pmt.is_auto_retryable_now() && pmt.remaining_parts() == 0 && !pmt.is_fulfilled() &&
			!pmt.is_awaiting_invoice())
	}

	/// Errors immediately on [`RetryableSendFailure`] error conditions. Otherwise, further errors may
	/// be surfaced asynchronously via [`Event::PaymentPathFailed`] and [`Event::PaymentFailed`].
	///
	/// [`Event::PaymentPathFailed`]: crate::events::Event::PaymentPathFailed
	/// [`Event::PaymentFailed`]: crate::events::Event::PaymentFailed
	fn send_payment_internal<R: Deref, NS: Deref, ES: Deref, IH, SP, L: Deref>(
		&self, payment_id: PaymentId, payment_hash: PaymentHash, recipient_onion: RecipientOnionFields,
		keysend_preimage: Option<PaymentPreimage>, retry_strategy: Retry, route_params: RouteParameters,
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
		#[cfg(feature = "std")] {
			if has_expired(&route_params) {
				log_error!(logger, "Payment with id {} and hash {} had expired before we started paying",
					payment_id, payment_hash);
				return Err(RetryableSendFailure::PaymentExpired)
			}
		}

		let route = router.find_route_with_id(
			&node_signer.get_node_id(Recipient::Node).unwrap(), &route_params,
			Some(&first_hops.iter().collect::<Vec<_>>()), inflight_htlcs(),
			payment_hash, payment_id,
		).map_err(|_| {
			log_error!(logger, "Failed to find route for payment with id {} and hash {}",
				payment_id, payment_hash);
			RetryableSendFailure::RouteNotFound
		})?;

		let onion_session_privs = self.add_new_pending_payment(payment_hash,
			recipient_onion.clone(), payment_id, keysend_preimage, &route, Some(retry_strategy),
			Some(route_params.payment_params.clone()), entropy_source, best_block_height)
			.map_err(|_| {
				log_error!(logger, "Payment with id {} is already pending. New payment had payment hash {}",
					payment_id, payment_hash);
				RetryableSendFailure::DuplicatePayment
			})?;

		let res = self.pay_route_internal(&route, payment_hash, recipient_onion, keysend_preimage, payment_id, None,
			onion_session_privs, node_signer, best_block_height, &send_payment_along_path);
		log_info!(logger, "Sending payment with id {} and hash {} returned {:?}",
			payment_id, payment_hash, res);
		if let Err(e) = res {
			self.handle_pay_route_err(e, payment_id, payment_hash, route, route_params, router, first_hops, &inflight_htlcs, entropy_source, node_signer, best_block_height, logger, pending_events, &send_payment_along_path);
		}
		Ok(())
	}

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

		let route = match router.find_route_with_id(
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
							payment_hash,
							reason: *reason,
						}, None));
						$payment.remove();
					}
				}
			}
		}
		let (total_msat, recipient_onion, keysend_preimage, onion_session_privs) = {
			let mut outbounds = self.pending_outbound_payments.lock().unwrap();
			match outbounds.entry(payment_id) {
				hash_map::Entry::Occupied(mut payment) => {
					match payment.get() {
						PendingOutboundPayment::Retryable {
							total_msat, keysend_preimage, payment_secret, payment_metadata,
							custom_tlvs, pending_amt_msat, ..
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

							let mut onion_session_privs = Vec::with_capacity(route.paths.len());
							for _ in 0..route.paths.len() {
								onion_session_privs.push(entropy_source.get_secure_random_bytes());
							}

							for (path, session_priv_bytes) in route.paths.iter().zip(onion_session_privs.iter()) {
								assert!(payment.get_mut().insert(*session_priv_bytes, path));
							}

							payment.get_mut().increment_attempts();

							(total_msat, recipient_onion, keysend_preimage, onion_session_privs)
						},
						PendingOutboundPayment::Legacy { .. } => {
							log_error!(logger, "Unable to retry payments that were initially sent on LDK versions prior to 0.0.102");
							return
						},
						PendingOutboundPayment::AwaitingInvoice { .. } => {
							log_error!(logger, "Payment not yet sent");
							return
						},
						PendingOutboundPayment::InvoiceReceived { payment_hash } => {
							let total_amount = route_params.final_value_msat;
							let recipient_onion = RecipientOnionFields {
								payment_secret: None,
								payment_metadata: None,
								custom_tlvs: vec![],
							};
							let retry_strategy = Some(BOLT_12_INVOICE_RETRY_STRATEGY);
							let payment_params = Some(route_params.payment_params.clone());
							let (retryable_payment, onion_session_privs) = self.create_pending_payment(
								*payment_hash, recipient_onion.clone(), None, &route,
								retry_strategy, payment_params, entropy_source, best_block_height
							);
							*payment.into_mut() = retryable_payment;
							(total_amount, recipient_onion, None, onion_session_privs)
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
		let res = self.pay_route_internal(&route, payment_hash, recipient_onion, keysend_preimage,
			payment_id, Some(total_msat), onion_session_privs, node_signer, best_block_height,
			&send_payment_along_path);
		log_info!(logger, "Result retrying payment id {}: {:?}", &payment_id, res);
		if let Err(e) = res {
			self.handle_pay_route_err(e, payment_id, payment_hash, route, route_params, router, first_hops, inflight_htlcs, entropy_source, node_signer, best_block_height, logger, pending_events, send_payment_along_path);
		}
	}

	fn handle_pay_route_err<R: Deref, NS: Deref, ES: Deref, IH, SP, L: Deref>(
		&self, err: PaymentSendFailure, payment_id: PaymentId, payment_hash: PaymentHash, route: Route,
		mut route_params: RouteParameters, router: &R, first_hops: Vec<ChannelDetails>,
		inflight_htlcs: &IH, entropy_source: &ES, node_signer: &NS, best_block_height: u32, logger: &L,
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
		match err {
			PaymentSendFailure::AllFailedResendSafe(errs) => {
				Self::push_path_failed_evs_and_scids(payment_id, payment_hash, &mut route_params, route.paths, errs.into_iter().map(|e| Err(e)), logger, pending_events);
				self.find_route_and_send_payment(payment_hash, payment_id, route_params, router, first_hops, inflight_htlcs, entropy_source, node_signer, best_block_height, logger, pending_events, send_payment_along_path);
			},
			PaymentSendFailure::PartialFailure { failed_paths_retry: Some(mut retry), results, .. } => {
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
				Self::push_path_failed_evs_and_scids(payment_id, payment_hash, &mut route_params, route.paths, results.into_iter(), logger, pending_events);
				self.abandon_payment(payment_id, PaymentFailureReason::UnexpectedError, pending_events);
			},
			PaymentSendFailure::ParameterError(e) => {
				log_error!(logger, "Failed to send to route due to parameter error: {:?}. Your router is buggy", e);
				self.abandon_payment(payment_id, PaymentFailureReason::UnexpectedError, pending_events);
			},
			PaymentSendFailure::DuplicatePayment => debug_assert!(false), // unreachable
		}
	}

	fn push_path_failed_evs_and_scids<I: ExactSizeIterator + Iterator<Item = Result<(), APIError>>, L: Deref>(
		payment_id: PaymentId, payment_hash: PaymentHash, route_params: &mut RouteParameters,
		paths: Vec<Path>, path_results: I, logger: &L,
		pending_events: &Mutex<VecDeque<(events::Event, Option<EventCompletionAction>)>>,
	) where L::Target: Logger {
		let mut events = pending_events.lock().unwrap();
		debug_assert_eq!(paths.len(), path_results.len());
		for (path, path_res) in paths.into_iter().zip(path_results) {
			if let Err(e) = path_res {
				if let APIError::MonitorUpdateInProgress = e { continue }
				log_error!(logger, "Failed to send along path due to error: {:?}", e);
				let mut failed_scid = None;
				if let APIError::ChannelUnavailable { .. } = e {
					let scid = path.hops[0].short_channel_id;
					failed_scid = Some(scid);
					route_params.payment_params.previously_failed_channels.push(scid);
				}
				events.push_back((events::Event::PaymentPathFailed {
					payment_id: Some(payment_id),
					payment_hash,
					payment_failed_permanently: false,
					failure: events::PathFailure::InitialSend { err: e },
					path,
					short_channel_id: failed_scid,
					#[cfg(test)]
					error_code: None,
					#[cfg(test)]
					error_data: None,
				}, None));
			}
		}
	}

	pub(super) fn send_probe<ES: Deref, NS: Deref, F>(
		&self, path: Path, probing_cookie_secret: [u8; 32], entropy_source: &ES, node_signer: &NS,
		best_block_height: u32, send_payment_along_path: F
	) -> Result<(PaymentHash, PaymentId), PaymentSendFailure>
	where
		ES::Target: EntropySource,
		NS::Target: NodeSigner,
		F: Fn(SendAlongPathArgs) -> Result<(), APIError>,
	{
		let payment_id = PaymentId(entropy_source.get_secure_random_bytes());

		let payment_hash = probing_cookie_from_id(&payment_id, probing_cookie_secret);

		if path.hops.len() < 2 && path.blinded_tail.is_none() {
			return Err(PaymentSendFailure::ParameterError(APIError::APIMisuseError {
				err: "No need probing a path with less than two hops".to_string()
			}))
		}

		let route = Route { paths: vec![path], route_params: None };
		let onion_session_privs = self.add_new_pending_payment(payment_hash,
			RecipientOnionFields::spontaneous_empty(), payment_id, None, &route, None, None,
			entropy_source, best_block_height)?;

		match self.pay_route_internal(&route, payment_hash, RecipientOnionFields::spontaneous_empty(),
			None, payment_id, None, onion_session_privs, node_signer, best_block_height, &send_payment_along_path
		) {
			Ok(()) => Ok((payment_hash, payment_id)),
			Err(e) => {
				self.remove_outbound_if_all_failed(payment_id, &e);
				Err(e)
			}
		}
	}

	#[cfg(test)]
	pub(super) fn test_set_payment_metadata(
		&self, payment_id: PaymentId, new_payment_metadata: Option<Vec<u8>>
	) {
		match self.pending_outbound_payments.lock().unwrap().get_mut(&payment_id).unwrap() {
			PendingOutboundPayment::Retryable { payment_metadata, .. } => {
				*payment_metadata = new_payment_metadata;
			},
			_ => panic!("Need a retryable payment to update metadata on"),
		}
	}

	#[cfg(test)]
	pub(super) fn test_add_new_pending_payment<ES: Deref>(
		&self, payment_hash: PaymentHash, recipient_onion: RecipientOnionFields, payment_id: PaymentId,
		route: &Route, retry_strategy: Option<Retry>, entropy_source: &ES, best_block_height: u32
	) -> Result<Vec<[u8; 32]>, PaymentSendFailure> where ES::Target: EntropySource {
		self.add_new_pending_payment(payment_hash, recipient_onion, payment_id, None, route, retry_strategy, None, entropy_source, best_block_height)
	}

	pub(super) fn add_new_pending_payment<ES: Deref>(
		&self, payment_hash: PaymentHash, recipient_onion: RecipientOnionFields, payment_id: PaymentId,
		keysend_preimage: Option<PaymentPreimage>, route: &Route, retry_strategy: Option<Retry>,
		payment_params: Option<PaymentParameters>, entropy_source: &ES, best_block_height: u32
	) -> Result<Vec<[u8; 32]>, PaymentSendFailure> where ES::Target: EntropySource {
		let mut pending_outbounds = self.pending_outbound_payments.lock().unwrap();
		match pending_outbounds.entry(payment_id) {
			hash_map::Entry::Occupied(_) => Err(PaymentSendFailure::DuplicatePayment),
			hash_map::Entry::Vacant(entry) => {
				let (payment, onion_session_privs) = self.create_pending_payment(
					payment_hash, recipient_onion, keysend_preimage, route, retry_strategy,
					payment_params, entropy_source, best_block_height
				);
				entry.insert(payment);
				Ok(onion_session_privs)
			},
		}
	}

	fn create_pending_payment<ES: Deref>(
		&self, payment_hash: PaymentHash, recipient_onion: RecipientOnionFields,
		keysend_preimage: Option<PaymentPreimage>, route: &Route, retry_strategy: Option<Retry>,
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
			session_privs: HashSet::new(),
			pending_amt_msat: 0,
			pending_fee_msat: Some(0),
			payment_hash,
			payment_secret: recipient_onion.payment_secret,
			payment_metadata: recipient_onion.payment_metadata,
			keysend_preimage,
			custom_tlvs: recipient_onion.custom_tlvs,
			starting_block_height: best_block_height,
			total_msat: route.get_total_amount(),
		};

		for (path, session_priv_bytes) in route.paths.iter().zip(onion_session_privs.iter()) {
			assert!(payment.insert(*session_priv_bytes, path));
		}

		(payment, onion_session_privs)
	}

	#[allow(unused)]
	pub(super) fn add_new_awaiting_invoice(&self, payment_id: PaymentId) -> Result<(), ()> {
		let mut pending_outbounds = self.pending_outbound_payments.lock().unwrap();
		match pending_outbounds.entry(payment_id) {
			hash_map::Entry::Occupied(_) => Err(()),
			hash_map::Entry::Vacant(entry) => {
				entry.insert(PendingOutboundPayment::AwaitingInvoice {
					timer_ticks_without_response: 0,
				});

				Ok(())
			},
		}
	}

	fn pay_route_internal<NS: Deref, F>(
		&self, route: &Route, payment_hash: PaymentHash, recipient_onion: RecipientOnionFields,
		keysend_preimage: Option<PaymentPreimage>, payment_id: PaymentId, recv_value_msat: Option<u64>,
		onion_session_privs: Vec<[u8; 32]>, node_signer: &NS, best_block_height: u32,
		send_payment_along_path: &F
	) -> Result<(), PaymentSendFailure>
	where
		NS::Target: NodeSigner,
		F: Fn(SendAlongPathArgs) -> Result<(), APIError>,
	{
		if route.paths.len() < 1 {
			return Err(PaymentSendFailure::ParameterError(APIError::InvalidRoute{err: "There must be at least one path to send over".to_owned()}));
		}
		if recipient_onion.payment_secret.is_none() && route.paths.len() > 1 {
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
			if path.blinded_tail.is_some() {
				path_errs.push(Err(APIError::InvalidRoute{err: "Sending to blinded paths isn't supported yet".to_owned()}));
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
		for (path, session_priv_bytes) in route.paths.iter().zip(onion_session_privs.into_iter()) {
			let mut path_res = send_payment_along_path(SendAlongPathArgs {
				path: &path, payment_hash: &payment_hash, recipient_onion: recipient_onion.clone(),
				total_value, cur_height, payment_id, keysend_preimage: &keysend_preimage, session_priv_bytes
			});
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
						let removed = payment.remove(&session_priv_bytes, Some(path));
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
		for (res, path) in results.iter().zip(route.paths.iter()) {
			if res.is_ok() { has_ok = true; }
			if res.is_err() { has_err = true; }
			if let &Err(APIError::MonitorUpdateInProgress) = res {
				// MonitorUpdateInProgress is inherently unsafe to retry, so we call it a
				// PartialFailure.
				has_err = true;
				has_ok = true;
			} else if res.is_err() {
				pending_amt_unsent += path.final_value_msat();
			}
		}
		if has_err && has_ok {
			Err(PaymentSendFailure::PartialFailure {
				results,
				payment_id,
				failed_paths_retry: if pending_amt_unsent != 0 {
					if let Some(payment_params) = route.route_params.as_ref().map(|p| p.payment_params.clone()) {
						Some(RouteParameters {
							payment_params: payment_params,
							final_value_msat: pending_amt_unsent,
						})
					} else { None }
				} else { None },
			})
		} else if has_err {
			Err(PaymentSendFailure::AllFailedResendSafe(results.drain(..).map(|r| r.unwrap_err()).collect()))
		} else {
			Ok(())
		}
	}

	#[cfg(test)]
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
		self.pay_route_internal(route, payment_hash, recipient_onion, keysend_preimage, payment_id,
			recv_value_msat, onion_session_privs, node_signer, best_block_height,
			&send_payment_along_path)
			.map_err(|e| { self.remove_outbound_if_all_failed(payment_id, &e); e })
	}

	// If we failed to send any paths, remove the new PaymentId from the `pending_outbound_payments`
	// map as the payment is free to be resent.
	fn remove_outbound_if_all_failed(&self, payment_id: PaymentId, err: &PaymentSendFailure) {
		if let &PaymentSendFailure::AllFailedResendSafe(_) = err {
			let removed = self.pending_outbound_payments.lock().unwrap().remove(&payment_id).is_some();
			debug_assert!(removed, "We should always have a pending payment to remove here");
		}
	}

	pub(super) fn claim_htlc<L: Deref>(
		&self, payment_id: PaymentId, payment_preimage: PaymentPreimage, session_priv: SecretKey,
		path: Path, from_onchain: bool, ev_completion_action: EventCompletionAction,
		pending_events: &Mutex<VecDeque<(events::Event, Option<EventCompletionAction>)>>,
		logger: &L,
	) where L::Target: Logger {
		let mut session_priv_bytes = [0; 32];
		session_priv_bytes.copy_from_slice(&session_priv[..]);
		let mut outbounds = self.pending_outbound_payments.lock().unwrap();
		let mut pending_events = pending_events.lock().unwrap();
		if let hash_map::Entry::Occupied(mut payment) = outbounds.entry(payment_id) {
			if !payment.get().is_fulfilled() {
				let payment_hash = PaymentHash(Sha256::hash(&payment_preimage.0).into_inner());
				log_info!(logger, "Payment with id {} and hash {} sent!", payment_id, payment_hash);
				let fee_paid_msat = payment.get().get_pending_fee_msat();
				pending_events.push_back((events::Event::PaymentSent {
					payment_id: Some(payment_id),
					payment_preimage,
					payment_hash,
					fee_paid_msat,
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
					let payment_hash = Some(PaymentHash(Sha256::hash(&payment_preimage.0).into_inner()));
					pending_events.push_back((events::Event::PaymentPathSuccessful {
						payment_id,
						payment_hash,
						path,
					}, Some(ev_completion_action)));
				}
			}
		} else {
			log_trace!(logger, "Received duplicative fulfill for HTLC with payment_preimage {}", &payment_preimage);
		}
	}

	pub(super) fn finalize_claims(&self, sources: Vec<HTLCSource>,
		pending_events: &Mutex<VecDeque<(events::Event, Option<EventCompletionAction>)>>)
	{
		let mut outbounds = self.pending_outbound_payments.lock().unwrap();
		let mut pending_events = pending_events.lock().unwrap();
		for source in sources {
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
						}, None));
					}
				}
			}
		}
	}

	pub(super) fn remove_stale_payments(
		&self, pending_events: &Mutex<VecDeque<(events::Event, Option<EventCompletionAction>)>>)
	{
		let mut pending_outbound_payments = self.pending_outbound_payments.lock().unwrap();
		let mut pending_events = pending_events.lock().unwrap();
		pending_outbound_payments.retain(|payment_id, payment| {
			// If an outbound payment was completed, and no pending HTLCs remain, we should remove it
			// from the map. However, if we did that immediately when the last payment HTLC is claimed,
			// this could race the user making a duplicate send_payment call and our idempotency
			// guarantees would be violated. Instead, we wait a few timer ticks to do the actual
			// removal. This should be more than sufficient to ensure the idempotency of any
			// `send_payment` calls that were made at the same time the `PaymentSent` event was being
			// processed.
			if let PendingOutboundPayment::Fulfilled { session_privs, timer_ticks_without_htlcs, .. } = payment {
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
			} else if let PendingOutboundPayment::AwaitingInvoice { timer_ticks_without_response, .. } = payment {
				*timer_ticks_without_response += 1;
				if *timer_ticks_without_response <= INVOICE_REQUEST_TIMEOUT_TICKS {
					true
				} else {
					pending_events.push_back(
						(events::Event::InvoiceRequestFailed { payment_id: *payment_id }, None)
					);
					false
				}
			} else { true }
		});
	}

	// Returns a bool indicating whether a PendingHTLCsForwardable event should be generated.
	pub(super) fn fail_htlc<L: Deref>(
		&self, source: &HTLCSource, payment_hash: &PaymentHash, onion_error: &HTLCFailReason,
		path: &Path, session_priv: &SecretKey, payment_id: &PaymentId,
		probing_cookie_secret: [u8; 32], secp_ctx: &Secp256k1<secp256k1::All>,
		pending_events: &Mutex<VecDeque<(events::Event, Option<EventCompletionAction>)>>, logger: &L,
	) -> bool where L::Target: Logger {
		#[cfg(test)]
		let DecodedOnionFailure {
			network_update, short_channel_id, payment_retryable, onion_error_code, onion_error_data
		} = onion_error.decode_onion_failure(secp_ctx, logger, &source);
		#[cfg(not(test))]
		let DecodedOnionFailure { network_update, short_channel_id, payment_retryable } =
			onion_error.decode_onion_failure(secp_ctx, logger, &source);

		let payment_is_probe = payment_is_probe(payment_hash, &payment_id, probing_cookie_secret);
		let mut session_priv_bytes = [0; 32];
		session_priv_bytes.copy_from_slice(&session_priv[..]);
		let mut outbounds = self.pending_outbound_payments.lock().unwrap();

		// If any payments already need retry, there's no need to generate a redundant
		// `PendingHTLCsForwardable`.
		let already_awaiting_retry = outbounds.iter().any(|(_, pmt)| {
			let mut awaiting_retry = false;
			if pmt.is_auto_retryable_now() {
				if let PendingOutboundPayment::Retryable { pending_amt_msat, total_msat, .. } = pmt {
					if pending_amt_msat < total_msat {
						awaiting_retry = true;
					}
				}
			}
			awaiting_retry
		});

		let mut full_failure_ev = None;
		let mut pending_retry_ev = false;
		let attempts_remaining = if let hash_map::Entry::Occupied(mut payment) = outbounds.entry(*payment_id) {
			if !payment.get_mut().remove(&session_priv_bytes, Some(&path)) {
				log_trace!(logger, "Received duplicative fail for HTLC with payment_hash {}", &payment_hash);
				return false
			}
			if payment.get().is_fulfilled() {
				log_trace!(logger, "Received failure of HTLC with payment_hash {} after payment completion", &payment_hash);
				return false
			}
			let mut is_retryable_now = payment.get().is_auto_retryable_now();
			if let Some(scid) = short_channel_id {
				// TODO: If we decided to blame ourselves (or one of our channels) in
				// process_onion_failure we should close that channel as it implies our
				// next-hop is needlessly blaming us!
				payment.get_mut().insert_previously_failed_scid(scid);
			}

			if payment_is_probe || !is_retryable_now || !payment_retryable {
				let reason = if !payment_retryable {
					PaymentFailureReason::RecipientRejected
				} else {
					PaymentFailureReason::RetriesExhausted
				};
				payment.get_mut().mark_abandoned(reason);
				is_retryable_now = false;
			}
			if payment.get().remaining_parts() == 0 {
				if let PendingOutboundPayment::Abandoned { payment_hash, reason, .. }= payment.get() {
					if !payment_is_probe {
						full_failure_ev = Some(events::Event::PaymentFailed {
							payment_id: *payment_id,
							payment_hash: *payment_hash,
							reason: *reason,
						});
					}
					payment.remove();
				}
			}
			is_retryable_now
		} else {
			log_trace!(logger, "Received duplicative fail for HTLC with payment_hash {}", &payment_hash);
			return false
		};
		core::mem::drop(outbounds);
		log_trace!(logger, "Failing outbound payment HTLC with payment_hash {}", &payment_hash);

		let path_failure = {
			if payment_is_probe {
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
				// If we miss abandoning the payment above, we *must* generate an event here or else the
				// payment will sit in our outbounds forever.
				if attempts_remaining && !already_awaiting_retry {
					debug_assert!(full_failure_ev.is_none());
					pending_retry_ev = true;
				}
				events::Event::PaymentPathFailed {
					payment_id: Some(*payment_id),
					payment_hash: payment_hash.clone(),
					payment_failed_permanently: !payment_retryable,
					failure: events::PathFailure::OnPath { network_update },
					path: path.clone(),
					short_channel_id,
					#[cfg(test)]
					error_code: onion_error_code,
					#[cfg(test)]
					error_data: onion_error_data
				}
			}
		};
		let mut pending_events = pending_events.lock().unwrap();
		pending_events.push_back((path_failure, None));
		if let Some(ev) = full_failure_ev { pending_events.push_back((ev, None)); }
		pending_retry_ev
	}

	pub(super) fn abandon_payment(
		&self, payment_id: PaymentId, reason: PaymentFailureReason,
		pending_events: &Mutex<VecDeque<(events::Event, Option<EventCompletionAction>)>>
	) {
		let mut outbounds = self.pending_outbound_payments.lock().unwrap();
		if let hash_map::Entry::Occupied(mut payment) = outbounds.entry(payment_id) {
			payment.get_mut().mark_abandoned(reason);
			if let PendingOutboundPayment::Abandoned { payment_hash, reason, .. } = payment.get() {
				if payment.get().remaining_parts() == 0 {
					pending_events.lock().unwrap().push_back((events::Event::PaymentFailed {
						payment_id,
						payment_hash: *payment_hash,
						reason: *reason,
					}, None));
					payment.remove();
				}
			} else if let PendingOutboundPayment::AwaitingInvoice { .. } = payment.get() {
				pending_events.lock().unwrap().push_back((events::Event::InvoiceRequestFailed {
					payment_id,
				}, None));
				payment.remove();
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
		(not_written, retry_strategy, (static_value, None)),
		(not_written, attempts, (static_value, PaymentAttempts::new())),
	},
	(3, Abandoned) => {
		(0, session_privs, required),
		(1, reason, option),
		(2, payment_hash, required),
	},
	(5, AwaitingInvoice) => {
		(0, timer_ticks_without_response, required),
	},
	(7, InvoiceReceived) => {
		(0, payment_hash, required),
	},
);

#[cfg(test)]
mod tests {
	use bitcoin::network::constants::Network;
	use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};

	use crate::events::{Event, PathFailure, PaymentFailureReason};
	use crate::ln::PaymentHash;
	use crate::ln::channelmanager::{PaymentId, RecipientOnionFields};
	use crate::ln::features::{ChannelFeatures, NodeFeatures};
	use crate::ln::msgs::{ErrorAction, LightningError};
	use crate::ln::outbound_payment::{Bolt12PaymentError, INVOICE_REQUEST_TIMEOUT_TICKS, OutboundPayments, Retry, RetryableSendFailure};
	use crate::offers::invoice::DEFAULT_RELATIVE_EXPIRY;
	use crate::offers::offer::OfferBuilder;
	use crate::offers::test_utils::*;
	use crate::routing::gossip::NetworkGraph;
	use crate::routing::router::{InFlightHtlcs, Path, PaymentParameters, Route, RouteHop, RouteParameters};
	use crate::sync::{Arc, Mutex, RwLock};
	use crate::util::errors::APIError;
	use crate::util::test_utils;

	use alloc::collections::VecDeque;

	#[test]
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
	fn do_fails_paying_after_expiration(on_retry: bool) {
		let outbound_payments = OutboundPayments::new();
		let logger = test_utils::TestLogger::new();
		let network_graph = Arc::new(NetworkGraph::new(Network::Testnet, &logger));
		let scorer = RwLock::new(test_utils::TestScorer::new());
		let router = test_utils::TestRouter::new(network_graph, &scorer);
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
				&&keys_manager, 0).unwrap();
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
	fn do_find_route_error(on_retry: bool) {
		let outbound_payments = OutboundPayments::new();
		let logger = test_utils::TestLogger::new();
		let network_graph = Arc::new(NetworkGraph::new(Network::Testnet, &logger));
		let scorer = RwLock::new(test_utils::TestScorer::new());
		let router = test_utils::TestRouter::new(network_graph, &scorer);
		let secp_ctx = Secp256k1::new();
		let keys_manager = test_utils::TestKeysInterface::new(&[0; 32], Network::Testnet);

		let payment_params = PaymentParameters::from_node_id(
			PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[42; 32]).unwrap()), 0);
		let route_params = RouteParameters::from_payment_params_and_value(payment_params, 0);
		router.expect_find_route(route_params.clone(),
			Err(LightningError { err: String::new(), action: ErrorAction::IgnoreError }));

		let pending_events = Mutex::new(VecDeque::new());
		if on_retry {
			outbound_payments.add_new_pending_payment(PaymentHash([0; 32]), RecipientOnionFields::spontaneous_empty(),
				PaymentId([0; 32]), None, &Route { paths: vec![], route_params: None },
				Some(Retry::Attempts(1)), Some(route_params.payment_params.clone()),
				&&keys_manager, 0).unwrap();
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
	fn initial_send_payment_path_failed_evs() {
		let outbound_payments = OutboundPayments::new();
		let logger = test_utils::TestLogger::new();
		let network_graph = Arc::new(NetworkGraph::new(Network::Testnet, &logger));
		let scorer = RwLock::new(test_utils::TestScorer::new());
		let router = test_utils::TestRouter::new(network_graph, &scorer);
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
			}], blinded_tail: None }],
			route_params: Some(route_params.clone()),
		};
		router.expect_find_route(route_params.clone(), Ok(route.clone()));
		let mut route_params_w_failed_scid = route_params.clone();
		route_params_w_failed_scid.payment_params.previously_failed_channels.push(failed_scid);
		router.expect_find_route(route_params_w_failed_scid, Ok(route.clone()));
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
	fn removes_stale_awaiting_invoice() {
		let pending_events = Mutex::new(VecDeque::new());
		let outbound_payments = OutboundPayments::new();
		let payment_id = PaymentId([0; 32]);

		assert!(!outbound_payments.has_pending_payments());
		assert!(outbound_payments.add_new_awaiting_invoice(payment_id).is_ok());
		assert!(outbound_payments.has_pending_payments());

		for _ in 0..INVOICE_REQUEST_TIMEOUT_TICKS {
			outbound_payments.remove_stale_payments(&pending_events);
			assert!(outbound_payments.has_pending_payments());
			assert!(pending_events.lock().unwrap().is_empty());
		}

		outbound_payments.remove_stale_payments(&pending_events);
		assert!(!outbound_payments.has_pending_payments());
		assert!(!pending_events.lock().unwrap().is_empty());
		assert_eq!(
			pending_events.lock().unwrap().pop_front(),
			Some((Event::InvoiceRequestFailed { payment_id }, None)),
		);
		assert!(pending_events.lock().unwrap().is_empty());

		assert!(outbound_payments.add_new_awaiting_invoice(payment_id).is_ok());
		assert!(outbound_payments.has_pending_payments());

		assert!(outbound_payments.add_new_awaiting_invoice(payment_id).is_err());
	}

	#[test]
	fn removes_abandoned_awaiting_invoice() {
		let pending_events = Mutex::new(VecDeque::new());
		let outbound_payments = OutboundPayments::new();
		let payment_id = PaymentId([0; 32]);

		assert!(!outbound_payments.has_pending_payments());
		assert!(outbound_payments.add_new_awaiting_invoice(payment_id).is_ok());
		assert!(outbound_payments.has_pending_payments());

		outbound_payments.abandon_payment(
			payment_id, PaymentFailureReason::UserAbandoned, &pending_events
		);
		assert!(!outbound_payments.has_pending_payments());
		assert!(!pending_events.lock().unwrap().is_empty());
		assert_eq!(
			pending_events.lock().unwrap().pop_front(),
			Some((Event::InvoiceRequestFailed { payment_id }, None)),
		);
		assert!(pending_events.lock().unwrap().is_empty());
	}

	#[cfg(feature = "std")]
	#[test]
	fn fails_sending_payment_for_expired_bolt12_invoice() {
		let logger = test_utils::TestLogger::new();
		let network_graph = Arc::new(NetworkGraph::new(Network::Testnet, &logger));
		let scorer = RwLock::new(test_utils::TestScorer::new());
		let router = test_utils::TestRouter::new(network_graph, &scorer);
		let keys_manager = test_utils::TestKeysInterface::new(&[0; 32], Network::Testnet);

		let pending_events = Mutex::new(VecDeque::new());
		let outbound_payments = OutboundPayments::new();
		let payment_id = PaymentId([0; 32]);

		assert!(outbound_payments.add_new_awaiting_invoice(payment_id).is_ok());
		assert!(outbound_payments.has_pending_payments());

		let created_at = now() - DEFAULT_RELATIVE_EXPIRY;
		let invoice = OfferBuilder::new("foo".into(), recipient_pubkey())
			.amount_msats(1000)
			.build().unwrap()
			.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.build().unwrap()
			.sign(payer_sign).unwrap()
			.respond_with_no_std(payment_paths(), payment_hash(), created_at).unwrap()
			.build().unwrap()
			.sign(recipient_sign).unwrap();

		assert_eq!(
			outbound_payments.send_payment_for_bolt12_invoice(
				&invoice, payment_id, &&router, vec![], || InFlightHtlcs::new(), &&keys_manager,
				&&keys_manager, 0, &&logger, &pending_events, |_| panic!()
			),
			Ok(()),
		);
		assert!(!outbound_payments.has_pending_payments());

		let payment_hash = invoice.payment_hash();
		let reason = Some(PaymentFailureReason::PaymentExpired);

		assert!(!pending_events.lock().unwrap().is_empty());
		assert_eq!(
			pending_events.lock().unwrap().pop_front(),
			Some((Event::PaymentFailed { payment_id, payment_hash, reason }, None)),
		);
		assert!(pending_events.lock().unwrap().is_empty());
	}

	#[test]
	fn fails_finding_route_for_bolt12_invoice() {
		let logger = test_utils::TestLogger::new();
		let network_graph = Arc::new(NetworkGraph::new(Network::Testnet, &logger));
		let scorer = RwLock::new(test_utils::TestScorer::new());
		let router = test_utils::TestRouter::new(network_graph, &scorer);
		let keys_manager = test_utils::TestKeysInterface::new(&[0; 32], Network::Testnet);

		let pending_events = Mutex::new(VecDeque::new());
		let outbound_payments = OutboundPayments::new();
		let payment_id = PaymentId([0; 32]);

		assert!(outbound_payments.add_new_awaiting_invoice(payment_id).is_ok());
		assert!(outbound_payments.has_pending_payments());

		let invoice = OfferBuilder::new("foo".into(), recipient_pubkey())
			.amount_msats(1000)
			.build().unwrap()
			.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.build().unwrap()
			.sign(payer_sign).unwrap()
			.respond_with_no_std(payment_paths(), payment_hash(), now()).unwrap()
			.build().unwrap()
			.sign(recipient_sign).unwrap();

		router.expect_find_route(
			RouteParameters {
				payment_params: PaymentParameters::from_bolt12_invoice(&invoice),
				final_value_msat: invoice.amount_msats(),
			},
			Err(LightningError { err: String::new(), action: ErrorAction::IgnoreError }),
		);

		assert_eq!(
			outbound_payments.send_payment_for_bolt12_invoice(
				&invoice, payment_id, &&router, vec![], || InFlightHtlcs::new(), &&keys_manager,
				&&keys_manager, 0, &&logger, &pending_events, |_| panic!()
			),
			Ok(()),
		);
		assert!(!outbound_payments.has_pending_payments());

		let payment_hash = invoice.payment_hash();
		let reason = Some(PaymentFailureReason::RouteNotFound);

		assert!(!pending_events.lock().unwrap().is_empty());
		assert_eq!(
			pending_events.lock().unwrap().pop_front(),
			Some((Event::PaymentFailed { payment_id, payment_hash, reason }, None)),
		);
		assert!(pending_events.lock().unwrap().is_empty());
	}

	#[test]
	fn fails_paying_for_bolt12_invoice() {
		let logger = test_utils::TestLogger::new();
		let network_graph = Arc::new(NetworkGraph::new(Network::Testnet, &logger));
		let scorer = RwLock::new(test_utils::TestScorer::new());
		let router = test_utils::TestRouter::new(network_graph, &scorer);
		let keys_manager = test_utils::TestKeysInterface::new(&[0; 32], Network::Testnet);

		let pending_events = Mutex::new(VecDeque::new());
		let outbound_payments = OutboundPayments::new();
		let payment_id = PaymentId([0; 32]);

		assert!(outbound_payments.add_new_awaiting_invoice(payment_id).is_ok());
		assert!(outbound_payments.has_pending_payments());

		let invoice = OfferBuilder::new("foo".into(), recipient_pubkey())
			.amount_msats(1000)
			.build().unwrap()
			.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.build().unwrap()
			.sign(payer_sign).unwrap()
			.respond_with_no_std(payment_paths(), payment_hash(), now()).unwrap()
			.build().unwrap()
			.sign(recipient_sign).unwrap();

		let route_params = RouteParameters {
			payment_params: PaymentParameters::from_bolt12_invoice(&invoice),
			final_value_msat: invoice.amount_msats(),
		};
		router.expect_find_route(
			route_params.clone(), Ok(Route { paths: vec![], route_params: Some(route_params) })
		);

		assert_eq!(
			outbound_payments.send_payment_for_bolt12_invoice(
				&invoice, payment_id, &&router, vec![], || InFlightHtlcs::new(), &&keys_manager,
				&&keys_manager, 0, &&logger, &pending_events, |_| panic!()
			),
			Ok(()),
		);
		assert!(!outbound_payments.has_pending_payments());

		let payment_hash = invoice.payment_hash();
		let reason = Some(PaymentFailureReason::UnexpectedError);

		assert!(!pending_events.lock().unwrap().is_empty());
		assert_eq!(
			pending_events.lock().unwrap().pop_front(),
			Some((Event::PaymentFailed { payment_id, payment_hash, reason }, None)),
		);
		assert!(pending_events.lock().unwrap().is_empty());
	}

	#[test]
	fn sends_payment_for_bolt12_invoice() {
		let logger = test_utils::TestLogger::new();
		let network_graph = Arc::new(NetworkGraph::new(Network::Testnet, &logger));
		let scorer = RwLock::new(test_utils::TestScorer::new());
		let router = test_utils::TestRouter::new(network_graph, &scorer);
		let keys_manager = test_utils::TestKeysInterface::new(&[0; 32], Network::Testnet);

		let pending_events = Mutex::new(VecDeque::new());
		let outbound_payments = OutboundPayments::new();
		let payment_id = PaymentId([0; 32]);

		let invoice = OfferBuilder::new("foo".into(), recipient_pubkey())
			.amount_msats(1000)
			.build().unwrap()
			.request_invoice(vec![1; 32], payer_pubkey()).unwrap()
			.build().unwrap()
			.sign(payer_sign).unwrap()
			.respond_with_no_std(payment_paths(), payment_hash(), now()).unwrap()
			.build().unwrap()
			.sign(recipient_sign).unwrap();

		let route_params = RouteParameters {
			payment_params: PaymentParameters::from_bolt12_invoice(&invoice),
			final_value_msat: invoice.amount_msats(),
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
				&invoice, payment_id, &&router, vec![], || InFlightHtlcs::new(), &&keys_manager,
				&&keys_manager, 0, &&logger, &pending_events, |_| panic!()
			),
			Err(Bolt12PaymentError::UnexpectedInvoice),
		);
		assert!(!outbound_payments.has_pending_payments());
		assert!(pending_events.lock().unwrap().is_empty());

		assert!(outbound_payments.add_new_awaiting_invoice(payment_id).is_ok());
		assert!(outbound_payments.has_pending_payments());

		assert_eq!(
			outbound_payments.send_payment_for_bolt12_invoice(
				&invoice, payment_id, &&router, vec![], || InFlightHtlcs::new(), &&keys_manager,
				&&keys_manager, 0, &&logger, &pending_events, |_| Ok(())
			),
			Ok(()),
		);
		assert!(outbound_payments.has_pending_payments());
		assert!(pending_events.lock().unwrap().is_empty());

		assert_eq!(
			outbound_payments.send_payment_for_bolt12_invoice(
				&invoice, payment_id, &&router, vec![], || InFlightHtlcs::new(), &&keys_manager,
				&&keys_manager, 0, &&logger, &pending_events, |_| panic!()
			),
			Err(Bolt12PaymentError::DuplicateInvoice),
		);
		assert!(outbound_payments.has_pending_payments());
		assert!(pending_events.lock().unwrap().is_empty());
	}
}
