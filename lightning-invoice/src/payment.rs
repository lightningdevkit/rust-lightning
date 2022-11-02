// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! A module for paying Lightning invoices and sending spontaneous payments.
//!
//! Defines an [`InvoicePayer`] utility for sending payments, parameterized by [`Payer`] and
//! [`Router`] traits. Implementations of [`Payer`] provide the payer's node id, channels, and means
//! to send a payment over a [`Route`]. Implementations of [`Router`] find a [`Route`] between payer
//! and payee using information provided by the payer and from the payee's [`Invoice`], when
//! applicable.
//!
//! [`InvoicePayer`] uses its [`Router`] parameterization for optionally notifying scorers upon
//! receiving the [`Event::PaymentPathFailed`] and [`Event::PaymentPathSuccessful`] events.
//! It also does the same for payment probe failure and success events using [`Event::ProbeFailed`]
//! and [`Event::ProbeSuccessful`].
//!
//! [`InvoicePayer`] is capable of retrying failed payments. It accomplishes this by implementing
//! [`EventHandler`] which decorates a user-provided handler. It will intercept any
//! [`Event::PaymentPathFailed`] events and retry the failed paths for a fixed number of total
//! attempts or until retry is no longer possible. In such a situation, [`InvoicePayer`] will pass
//! along the events to the user-provided handler.
//!
//! # Example
//!
//! ```
//! # extern crate lightning;
//! # extern crate lightning_invoice;
//! # extern crate secp256k1;
//! #
//! # use lightning::io;
//! # use lightning::ln::{PaymentHash, PaymentPreimage, PaymentSecret};
//! # use lightning::ln::channelmanager::{ChannelDetails, PaymentId, PaymentSendFailure};
//! # use lightning::ln::msgs::LightningError;
//! # use lightning::routing::gossip::NodeId;
//! # use lightning::routing::router::{Route, RouteHop, RouteParameters};
//! # use lightning::routing::scoring::{ChannelUsage, Score};
//! # use lightning::util::events::{Event, EventHandler, EventsProvider};
//! # use lightning::util::logger::{Logger, Record};
//! # use lightning::util::ser::{Writeable, Writer};
//! # use lightning_invoice::Invoice;
//! # use lightning_invoice::payment::{InFlightHtlcs, InvoicePayer, Payer, Retry, Router};
//! # use secp256k1::PublicKey;
//! # use std::cell::RefCell;
//! # use std::ops::Deref;
//! #
//! # struct FakeEventProvider {}
//! # impl EventsProvider for FakeEventProvider {
//! #     fn process_pending_events<H: Deref>(&self, handler: H) where H::Target: EventHandler {}
//! # }
//! #
//! # struct FakePayer {}
//! # impl Payer for FakePayer {
//! #     fn node_id(&self) -> PublicKey { unimplemented!() }
//! #     fn first_hops(&self) -> Vec<ChannelDetails> { unimplemented!() }
//! #     fn send_payment(
//! #         &self, route: &Route, payment_hash: PaymentHash, payment_secret: &Option<PaymentSecret>,
//! #         payment_id: PaymentId
//! #     ) -> Result<(), PaymentSendFailure> { unimplemented!() }
//! #     fn send_spontaneous_payment(
//! #         &self, route: &Route, payment_preimage: PaymentPreimage, payment_id: PaymentId,
//! #     ) -> Result<(), PaymentSendFailure> { unimplemented!() }
//! #     fn retry_payment(
//! #         &self, route: &Route, payment_id: PaymentId
//! #     ) -> Result<(), PaymentSendFailure> { unimplemented!() }
//! #     fn abandon_payment(&self, payment_id: PaymentId) { unimplemented!() }
//! # }
//! #
//! # struct FakeRouter {}
//! # impl Router for FakeRouter {
//! #     fn find_route(
//! #         &self, payer: &PublicKey, params: &RouteParameters, payment_hash: &PaymentHash,
//! #         first_hops: Option<&[&ChannelDetails]>, _inflight_htlcs: InFlightHtlcs
//! #     ) -> Result<Route, LightningError> { unimplemented!() }
//! #
//! #     fn notify_payment_path_failed(&self, path: &[&RouteHop], short_channel_id: u64) {  unimplemented!() }
//! #     fn notify_payment_path_successful(&self, path: &[&RouteHop]) {  unimplemented!() }
//! #     fn notify_payment_probe_successful(&self, path: &[&RouteHop]) {  unimplemented!() }
//! #     fn notify_payment_probe_failed(&self, path: &[&RouteHop], short_channel_id: u64) { unimplemented!() }
//! # }
//! #
//! # struct FakeScorer {}
//! # impl Writeable for FakeScorer {
//! #     fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> { unimplemented!(); }
//! # }
//! # impl Score for FakeScorer {
//! #     fn channel_penalty_msat(
//! #         &self, _short_channel_id: u64, _source: &NodeId, _target: &NodeId, _usage: ChannelUsage
//! #     ) -> u64 { 0 }
//! #     fn payment_path_failed(&mut self, _path: &[&RouteHop], _short_channel_id: u64) {}
//! #     fn payment_path_successful(&mut self, _path: &[&RouteHop]) {}
//! #     fn probe_failed(&mut self, _path: &[&RouteHop], _short_channel_id: u64) {}
//! #     fn probe_successful(&mut self, _path: &[&RouteHop]) {}
//! # }
//! #
//! # struct FakeLogger {}
//! # impl Logger for FakeLogger {
//! #     fn log(&self, record: &Record) { unimplemented!() }
//! # }
//! #
//! # fn main() {
//! let event_handler = |event: &Event| {
//!     match event {
//!         Event::PaymentPathFailed { .. } => println!("payment failed after retries"),
//!         Event::PaymentSent { .. } => println!("payment successful"),
//!         _ => {},
//!     }
//! };
//! # let payer = FakePayer {};
//! # let router = FakeRouter {};
//! # let scorer = RefCell::new(FakeScorer {});
//! # let logger = FakeLogger {};
//! let invoice_payer = InvoicePayer::new(&payer, router, &logger, event_handler, Retry::Attempts(2));
//!
//! let invoice = "...";
//! if let Ok(invoice) = invoice.parse::<Invoice>() {
//!     invoice_payer.pay_invoice(&invoice).unwrap();
//!
//! # let event_provider = FakeEventProvider {};
//!     loop {
//!         event_provider.process_pending_events(&invoice_payer);
//!     }
//! }
//! # }
//! ```
//!
//! # Note
//!
//! The [`Route`] is computed before each payment attempt. Any updates affecting path finding such
//! as updates to the network graph or changes to channel scores should be applied prior to
//! retries, typically by way of composing [`EventHandler`]s accordingly.

use crate::Invoice;

use bitcoin_hashes::Hash;
use bitcoin_hashes::sha256::Hash as Sha256;

use crate::prelude::*;
use lightning::io;
use lightning::ln::{PaymentHash, PaymentPreimage, PaymentSecret};
use lightning::ln::channelmanager::{ChannelDetails, PaymentId, PaymentSendFailure};
use lightning::ln::msgs::LightningError;
use lightning::routing::gossip::NodeId;
use lightning::routing::router::{PaymentParameters, Route, RouteHop, RouteParameters};
use lightning::util::errors::APIError;
use lightning::util::events::{Event, EventHandler};
use lightning::util::logger::Logger;
use lightning::util::ser::Writeable;
use crate::time_utils::Time;
use crate::sync::Mutex;

use secp256k1::PublicKey;

use core::fmt;
use core::fmt::{Debug, Display, Formatter};
use core::ops::Deref;
use core::time::Duration;
#[cfg(feature = "std")]
use std::time::SystemTime;

/// A utility for paying [`Invoice`]s and sending spontaneous payments.
///
/// See [module-level documentation] for details.
///
/// [module-level documentation]: crate::payment
pub type InvoicePayer<P, R, L, E> = InvoicePayerUsingTime::<P, R, L, E, ConfiguredTime>;

#[cfg(not(feature = "no-std"))]
type ConfiguredTime = std::time::Instant;
#[cfg(feature = "no-std")]
use crate::time_utils;
#[cfg(feature = "no-std")]
type ConfiguredTime = time_utils::Eternity;

/// (C-not exported) generally all users should use the [`InvoicePayer`] type alias.
pub struct InvoicePayerUsingTime<P: Deref, R: Router, L: Deref, E: EventHandler, T: Time>
where
	P::Target: Payer,
	L::Target: Logger,
{
	payer: P,
	router: R,
	logger: L,
	event_handler: E,
	/// Caches the overall attempts at making a payment, which is updated prior to retrying.
	payment_cache: Mutex<HashMap<PaymentHash, PaymentInfo<T>>>,
	retry: Retry,
}

/// Used by [`InvoicePayerUsingTime::payment_cache`] to track the payments that are either
/// currently being made, or have outstanding paths that need retrying.
struct PaymentInfo<T: Time> {
	attempts: PaymentAttempts<T>,
	paths: Vec<Vec<RouteHop>>,
}

impl<T: Time> PaymentInfo<T> {
	fn new() -> Self {
		PaymentInfo {
			attempts: PaymentAttempts::new(),
			paths: vec![],
		}
	}
}

/// Storing minimal payment attempts information required for determining if a outbound payment can
/// be retried.
#[derive(Clone, Copy)]
struct PaymentAttempts<T: Time> {
	/// This count will be incremented only after the result of the attempt is known. When it's 0,
	/// it means the result of the first attempt is now known yet.
	count: usize,
	/// This field is only used when retry is [`Retry::Timeout`] which is only build with feature std
	first_attempted_at: T
}

impl<T: Time> PaymentAttempts<T> {
	fn new() -> Self {
		PaymentAttempts {
			count: 0,
			first_attempted_at: T::now()
		}
	}
}

impl<T: Time> Display for PaymentAttempts<T> {
	fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
		#[cfg(feature = "no-std")]
		return write!( f, "attempts: {}", self.count);
		#[cfg(not(feature = "no-std"))]
		return write!(
			f,
			"attempts: {}, duration: {}s",
			self.count,
			T::now().duration_since(self.first_attempted_at).as_secs()
		);
	}
}

/// A trait defining behavior of an [`Invoice`] payer.
///
/// While the behavior of [`InvoicePayer`] provides idempotency of duplicate `send_*payment` calls
/// with the same [`PaymentHash`], it is up to the `Payer` to provide idempotency across restarts.
///
/// [`ChannelManager`] provides idempotency for duplicate payments with the same [`PaymentId`].
///
/// In order to trivially ensure idempotency for payments, the default `Payer` implementation
/// reuses the [`PaymentHash`] bytes as the [`PaymentId`]. Custom implementations wishing to
/// provide payment idempotency with a different idempotency key (i.e. [`PaymentId`]) should map
/// the [`Invoice`] or spontaneous payment target pubkey to their own idempotency key.
///
/// [`ChannelManager`]: lightning::ln::channelmanager::ChannelManager
pub trait Payer {
	/// Returns the payer's node id.
	fn node_id(&self) -> PublicKey;

	/// Returns the payer's channels.
	fn first_hops(&self) -> Vec<ChannelDetails>;

	/// Sends a payment over the Lightning Network using the given [`Route`].
	fn send_payment(
		&self, route: &Route, payment_hash: PaymentHash, payment_secret: &Option<PaymentSecret>,
		payment_id: PaymentId
	) -> Result<(), PaymentSendFailure>;

	/// Sends a spontaneous payment over the Lightning Network using the given [`Route`].
	fn send_spontaneous_payment(
		&self, route: &Route, payment_preimage: PaymentPreimage, payment_id: PaymentId
	) -> Result<(), PaymentSendFailure>;

	/// Retries a failed payment path for the [`PaymentId`] using the given [`Route`].
	fn retry_payment(&self, route: &Route, payment_id: PaymentId) -> Result<(), PaymentSendFailure>;

	/// Signals that no further retries for the given payment will occur.
	fn abandon_payment(&self, payment_id: PaymentId);
}

/// A trait defining behavior for routing an [`Invoice`] payment.
pub trait Router {
	/// Finds a [`Route`] between `payer` and `payee` for a payment with the given values.
	fn find_route(
		&self, payer: &PublicKey, route_params: &RouteParameters, payment_hash: &PaymentHash,
		first_hops: Option<&[&ChannelDetails]>, inflight_htlcs: InFlightHtlcs
	) -> Result<Route, LightningError>;
	/// Lets the router know that payment through a specific path has failed.
	fn notify_payment_path_failed(&self, path: &[&RouteHop], short_channel_id: u64);
	/// Lets the router know that payment through a specific path was successful.
	fn notify_payment_path_successful(&self, path: &[&RouteHop]);
	/// Lets the router know that a payment probe was successful.
	fn notify_payment_probe_successful(&self, path: &[&RouteHop]);
	/// Lets the router know that a payment probe failed.
	fn notify_payment_probe_failed(&self, path: &[&RouteHop], short_channel_id: u64);
}

/// Strategies available to retry payment path failures for an [`Invoice`].
///
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Retry {
	/// Max number of attempts to retry payment.
	///
	/// Note that this is the number of *path* failures, not full payment retries. For multi-path
	/// payments, if this is less than the total number of paths, we will never even retry all of the
	/// payment's paths.
	Attempts(usize),
	#[cfg(feature = "std")]
	/// Time elapsed before abandoning retries for a payment.
	Timeout(Duration),
}

impl Retry {
	fn is_retryable_now<T: Time>(&self, attempts: &PaymentAttempts<T>) -> bool {
		match (self, attempts) {
			(Retry::Attempts(max_retry_count), PaymentAttempts { count, .. }) => {
				max_retry_count >= &count
			},
			#[cfg(feature = "std")]
			(Retry::Timeout(max_duration), PaymentAttempts { first_attempted_at, .. } ) =>
				*max_duration >= T::now().duration_since(*first_attempted_at),
		}
	}
}

/// An error that may occur when making a payment.
#[derive(Clone, Debug)]
pub enum PaymentError {
	/// An error resulting from the provided [`Invoice`] or payment hash.
	Invoice(&'static str),
	/// An error occurring when finding a route.
	Routing(LightningError),
	/// An error occurring when sending a payment.
	Sending(PaymentSendFailure),
}

impl<P: Deref, R: Router, L: Deref, E: EventHandler, T: Time> InvoicePayerUsingTime<P, R, L, E, T>
where
	P::Target: Payer,
	L::Target: Logger,
{
	/// Creates an invoice payer that retries failed payment paths.
	///
	/// Will forward any [`Event::PaymentPathFailed`] events to the decorated `event_handler` once
	/// `retry` has been exceeded for a given [`Invoice`].
	pub fn new(
		payer: P, router: R, logger: L, event_handler: E, retry: Retry
	) -> Self {
		Self {
			payer,
			router,
			logger,
			event_handler,
			payment_cache: Mutex::new(HashMap::new()),
			retry,
		}
	}

	/// Pays the given [`Invoice`], caching it for later use in case a retry is needed.
	///
	/// [`Invoice::payment_hash`] is used as the [`PaymentId`], which ensures idempotency as long
	/// as the payment is still pending. Once the payment completes or fails, you must ensure that
	/// a second payment with the same [`PaymentHash`] is never sent.
	///
	/// If you wish to use a different payment idempotency token, see
	/// [`Self::pay_invoice_with_id`].
	pub fn pay_invoice(&self, invoice: &Invoice) -> Result<PaymentId, PaymentError> {
		let payment_id = PaymentId(invoice.payment_hash().into_inner());
		self.pay_invoice_with_id(invoice, payment_id).map(|()| payment_id)
	}

	/// Pays the given [`Invoice`] with a custom idempotency key, caching the invoice for later use
	/// in case a retry is needed.
	///
	/// Note that idempotency is only guaranteed as long as the payment is still pending. Once the
	/// payment completes or fails, no idempotency guarantees are made.
	///
	/// You should ensure that the [`Invoice::payment_hash`] is unique and the same [`PaymentHash`]
	/// has never been paid before.
	///
	/// See [`Self::pay_invoice`] for a variant which uses the [`PaymentHash`] for the idempotency
	/// token.
	pub fn pay_invoice_with_id(&self, invoice: &Invoice, payment_id: PaymentId) -> Result<(), PaymentError> {
		if invoice.amount_milli_satoshis().is_none() {
			Err(PaymentError::Invoice("amount missing"))
		} else {
			self.pay_invoice_using_amount(invoice, None, payment_id)
		}
	}

	/// Pays the given zero-value [`Invoice`] using the given amount, caching it for later use in
	/// case a retry is needed.
	///
	/// [`Invoice::payment_hash`] is used as the [`PaymentId`], which ensures idempotency as long
	/// as the payment is still pending. Once the payment completes or fails, you must ensure that
	/// a second payment with the same [`PaymentHash`] is never sent.
	///
	/// If you wish to use a different payment idempotency token, see
	/// [`Self::pay_zero_value_invoice_with_id`].
	pub fn pay_zero_value_invoice(
		&self, invoice: &Invoice, amount_msats: u64
	) -> Result<PaymentId, PaymentError> {
		let payment_id = PaymentId(invoice.payment_hash().into_inner());
		self.pay_zero_value_invoice_with_id(invoice, amount_msats, payment_id).map(|()| payment_id)
	}

	/// Pays the given zero-value [`Invoice`] using the given amount and custom idempotency key,
	/// caching the invoice for later use in case a retry is needed.
	///
	/// Note that idempotency is only guaranteed as long as the payment is still pending. Once the
	/// payment completes or fails, no idempotency guarantees are made.
	///
	/// You should ensure that the [`Invoice::payment_hash`] is unique and the same [`PaymentHash`]
	/// has never been paid before.
	///
	/// See [`Self::pay_zero_value_invoice`] for a variant which uses the [`PaymentHash`] for the
	/// idempotency token.
	pub fn pay_zero_value_invoice_with_id(
		&self, invoice: &Invoice, amount_msats: u64, payment_id: PaymentId
	) -> Result<(), PaymentError> {
		if invoice.amount_milli_satoshis().is_some() {
			Err(PaymentError::Invoice("amount unexpected"))
		} else {
			self.pay_invoice_using_amount(invoice, Some(amount_msats), payment_id)
		}
	}

	fn pay_invoice_using_amount(
		&self, invoice: &Invoice, amount_msats: Option<u64>, payment_id: PaymentId
	) -> Result<(), PaymentError> {
		debug_assert!(invoice.amount_milli_satoshis().is_some() ^ amount_msats.is_some());

		let payment_hash = PaymentHash(invoice.payment_hash().clone().into_inner());
		match self.payment_cache.lock().unwrap().entry(payment_hash) {
			hash_map::Entry::Occupied(_) => return Err(PaymentError::Invoice("payment pending")),
			hash_map::Entry::Vacant(entry) => entry.insert(PaymentInfo::new()),
		};

		let payment_secret = Some(invoice.payment_secret().clone());
		let mut payment_params = PaymentParameters::from_node_id(invoice.recover_payee_pub_key())
			.with_expiry_time(expiry_time_from_unix_epoch(&invoice).as_secs())
			.with_route_hints(invoice.route_hints());
		if let Some(features) = invoice.features() {
			payment_params = payment_params.with_features(features.clone());
		}
		let route_params = RouteParameters {
			payment_params,
			final_value_msat: invoice.amount_milli_satoshis().or(amount_msats).unwrap(),
			final_cltv_expiry_delta: invoice.min_final_cltv_expiry() as u32,
		};

		let send_payment = |route: &Route| {
			self.payer.send_payment(route, payment_hash, &payment_secret, payment_id)
		};

		self.pay_internal(&route_params, payment_hash, send_payment)
			.map_err(|e| { self.payment_cache.lock().unwrap().remove(&payment_hash); e })
	}

	/// Pays `pubkey` an amount using the hash of the given preimage, caching it for later use in
	/// case a retry is needed.
	///
	/// The hash of the [`PaymentPreimage`] is used as the [`PaymentId`], which ensures idempotency
	/// as long as the payment is still pending. Once the payment completes or fails, you must
	/// ensure that a second payment with the same [`PaymentPreimage`] is never sent.
	pub fn pay_pubkey(
		&self, pubkey: PublicKey, payment_preimage: PaymentPreimage, amount_msats: u64,
		final_cltv_expiry_delta: u32
	) -> Result<PaymentId, PaymentError> {
		let payment_hash = PaymentHash(Sha256::hash(&payment_preimage.0).into_inner());
		let payment_id = PaymentId(payment_hash.0);
		self.do_pay_pubkey(pubkey, payment_preimage, payment_hash, payment_id, amount_msats,
				final_cltv_expiry_delta)
			.map(|()| payment_id)
	}

	/// Pays `pubkey` an amount using the hash of the given preimage and a custom idempotency key,
	/// caching the invoice for later use in case a retry is needed.
	///
	/// Note that idempotency is only guaranteed as long as the payment is still pending. Once the
	/// payment completes or fails, no idempotency guarantees are made.
	///
	/// You should ensure that the [`PaymentPreimage`] is unique and the corresponding
	/// [`PaymentHash`] has never been paid before.
	pub fn pay_pubkey_with_id(
		&self, pubkey: PublicKey, payment_preimage: PaymentPreimage, payment_id: PaymentId,
		amount_msats: u64, final_cltv_expiry_delta: u32
	) -> Result<(), PaymentError> {
		let payment_hash = PaymentHash(Sha256::hash(&payment_preimage.0).into_inner());
		self.do_pay_pubkey(pubkey, payment_preimage, payment_hash, payment_id, amount_msats,
				final_cltv_expiry_delta)
	}

	fn do_pay_pubkey(
		&self, pubkey: PublicKey, payment_preimage: PaymentPreimage, payment_hash: PaymentHash,
		payment_id: PaymentId, amount_msats: u64, final_cltv_expiry_delta: u32
	) -> Result<(), PaymentError> {
		match self.payment_cache.lock().unwrap().entry(payment_hash) {
			hash_map::Entry::Occupied(_) => return Err(PaymentError::Invoice("payment pending")),
			hash_map::Entry::Vacant(entry) => entry.insert(PaymentInfo::new()),
		};

		let route_params = RouteParameters {
			payment_params: PaymentParameters::for_keysend(pubkey),
			final_value_msat: amount_msats,
			final_cltv_expiry_delta,
		};

		let send_payment = |route: &Route| {
			self.payer.send_spontaneous_payment(route, payment_preimage, payment_id)
		};
		self.pay_internal(&route_params, payment_hash, send_payment)
			.map_err(|e| { self.payment_cache.lock().unwrap().remove(&payment_hash); e })
	}

	fn pay_internal<F: FnOnce(&Route) -> Result<(), PaymentSendFailure> + Copy>(
		&self, params: &RouteParameters, payment_hash: PaymentHash, send_payment: F,
	) -> Result<(), PaymentError> {
		#[cfg(feature = "std")] {
			if has_expired(params) {
				log_trace!(self.logger, "Invoice expired prior to send for payment {}", log_bytes!(payment_hash.0));
				return Err(PaymentError::Invoice("Invoice expired prior to send"));
			}
		}

		let payer = self.payer.node_id();
		let first_hops = self.payer.first_hops();
		let inflight_htlcs = self.create_inflight_map();
		let route = self.router.find_route(
			&payer, &params, &payment_hash, Some(&first_hops.iter().collect::<Vec<_>>()),
			inflight_htlcs
		).map_err(|e| PaymentError::Routing(e))?;

		match send_payment(&route) {
			Ok(()) => {
				for path in route.paths {
					self.process_path_inflight_htlcs(payment_hash, path);
				}
				Ok(())
			},
			Err(e) => match e {
				PaymentSendFailure::ParameterError(_) => Err(e),
				PaymentSendFailure::PathParameterError(_) => Err(e),
				PaymentSendFailure::DuplicatePayment => Err(e),
				PaymentSendFailure::AllFailedResendSafe(_) => {
					let mut payment_cache = self.payment_cache.lock().unwrap();
					let payment_info = payment_cache.get_mut(&payment_hash).unwrap();
					payment_info.attempts.count += 1;
					if self.retry.is_retryable_now(&payment_info.attempts) {
						core::mem::drop(payment_cache);
						Ok(self.pay_internal(params, payment_hash, send_payment)?)
					} else {
						Err(e)
					}
				},
				PaymentSendFailure::PartialFailure { failed_paths_retry, payment_id, results } => {
					// If a `PartialFailure` event returns a result that is an `Ok()`, it means that
					// part of our payment is retried. When we receive `MonitorUpdateInProgress`, it
					// means that we are still waiting for our channel monitor update to be completed.
					for (result, path) in results.iter().zip(route.paths.into_iter()) {
						match result {
							Ok(_) | Err(APIError::MonitorUpdateInProgress) => {
								self.process_path_inflight_htlcs(payment_hash, path);
							},
							_ => {},
						}
					}

					if let Some(retry_data) = failed_paths_retry {
						// Some paths were sent, even if we failed to send the full MPP value our
						// recipient may misbehave and claim the funds, at which point we have to
						// consider the payment sent, so return `Ok()` here, ignoring any retry
						// errors.
						let _ = self.retry_payment(payment_id, payment_hash, &retry_data);
						Ok(())
					} else {
						// This may happen if we send a payment and some paths fail, but
						// only due to a temporary monitor failure or the like, implying
						// they're really in-flight, but we haven't sent the initial
						// HTLC-Add messages yet.
						Ok(())
					}
				},
			},
		}.map_err(|e| PaymentError::Sending(e))
	}

	// Takes in a path to have its information stored in `payment_cache`. This is done for paths
	// that are pending retry.
	fn process_path_inflight_htlcs(&self, payment_hash: PaymentHash, path: Vec<RouteHop>) {
		self.payment_cache.lock().unwrap().entry(payment_hash)
			.or_insert_with(|| PaymentInfo::new())
			.paths.push(path);
	}

	// Find the path we want to remove in `payment_cache`. If it doesn't exist, do nothing.
	fn remove_path_inflight_htlcs(&self, payment_hash: PaymentHash, path: &Vec<RouteHop>) {
		self.payment_cache.lock().unwrap().entry(payment_hash)
			.and_modify(|payment_info| {
				if let Some(idx) = payment_info.paths.iter().position(|p| p == path) {
					payment_info.paths.swap_remove(idx);
				}
			});
	}

	fn retry_payment(
		&self, payment_id: PaymentId, payment_hash: PaymentHash, params: &RouteParameters
	) -> Result<(), ()> {
		let attempts = self.payment_cache.lock().unwrap().entry(payment_hash)
			.and_modify(|info| info.attempts.count += 1 )
			.or_insert_with(|| PaymentInfo {
				attempts: PaymentAttempts {
					count: 1,
					first_attempted_at: T::now(),
				},
				paths: vec![],
			}).attempts;

		if !self.retry.is_retryable_now(&attempts) {
			log_trace!(self.logger, "Payment {} exceeded maximum attempts; not retrying ({})", log_bytes!(payment_hash.0), attempts);
			return Err(());
		}

		#[cfg(feature = "std")] {
			if has_expired(params) {
				log_trace!(self.logger, "Invoice expired for payment {}; not retrying ({:})", log_bytes!(payment_hash.0), attempts);
				return Err(());
			}
		}

		let payer = self.payer.node_id();
		let first_hops = self.payer.first_hops();
		let inflight_htlcs = self.create_inflight_map();

		let route = self.router.find_route(
			&payer, &params, &payment_hash, Some(&first_hops.iter().collect::<Vec<_>>()),
			inflight_htlcs
		);

		if route.is_err() {
			log_trace!(self.logger, "Failed to find a route for payment {}; not retrying ({:})", log_bytes!(payment_hash.0), attempts);
			return Err(());
		}

		match self.payer.retry_payment(&route.as_ref().unwrap(), payment_id) {
			Ok(()) => {
				for path in route.unwrap().paths.into_iter() {
					self.process_path_inflight_htlcs(payment_hash, path);
				}
				Ok(())
			},
			Err(PaymentSendFailure::ParameterError(_)) |
			Err(PaymentSendFailure::PathParameterError(_)) => {
				log_trace!(self.logger, "Failed to retry for payment {} due to bogus route/payment data, not retrying.", log_bytes!(payment_hash.0));
				Err(())
			},
			Err(PaymentSendFailure::AllFailedResendSafe(_)) => {
				self.retry_payment(payment_id, payment_hash, params)
			},
			Err(PaymentSendFailure::DuplicatePayment) => {
				log_error!(self.logger, "Got a DuplicatePayment error when attempting to retry a payment, this shouldn't happen.");
				Err(())
			}
			Err(PaymentSendFailure::PartialFailure { failed_paths_retry, results, .. }) => {
				// If a `PartialFailure` error contains a result that is an `Ok()`, it means that
				// part of our payment is retried. When we receive `MonitorUpdateInProgress`, it
				// means that we are still waiting for our channel monitor update to complete.
				for (result, path) in results.iter().zip(route.unwrap().paths.into_iter()) {
					match result {
						Ok(_) | Err(APIError::MonitorUpdateInProgress) => {
							self.process_path_inflight_htlcs(payment_hash, path);
						},
						_ => {},
					}
				}

				if let Some(retry) = failed_paths_retry {
					// Always return Ok for the same reason as noted in pay_internal.
					let _ = self.retry_payment(payment_id, payment_hash, &retry);
				}
				Ok(())
			},
		}
	}

	/// Removes the payment cached by the given payment hash.
	///
	/// Should be called once a payment has failed or succeeded if not using [`InvoicePayer`] as an
	/// [`EventHandler`]. Otherwise, calling this method is unnecessary.
	pub fn remove_cached_payment(&self, payment_hash: &PaymentHash) {
		self.payment_cache.lock().unwrap().remove(payment_hash);
	}

	/// Given a [`PaymentHash`], this function looks up inflight path attempts in the payment_cache.
	/// Then, it uses the path information inside the cache to construct a HashMap mapping a channel's
	/// short channel id and direction to the amount being sent through it.
	///
	/// This function should be called whenever we need information about currently used up liquidity
	/// across payments.
	fn create_inflight_map(&self) -> InFlightHtlcs {
		let mut total_inflight_map: HashMap<(u64, bool), u64> = HashMap::new();
		// Make an attempt at finding existing payment information from `payment_cache`. If it
		// does not exist, it probably is a fresh payment and we can just return an empty
		// HashMap.
		for payment_info in self.payment_cache.lock().unwrap().values() {
			for path in &payment_info.paths {
				if path.is_empty() { break };
				// total_inflight_map needs to be direction-sensitive when keeping track of the HTLC value
				// that is held up. However, the `hops` array, which is a path returned by `find_route` in
				// the router excludes the payer node. In the following lines, the payer's information is
				// hardcoded with an inflight value of 0 so that we can correctly represent the first hop
				// in our sliding window of two.
				let our_node_id: PublicKey = self.payer.node_id();
				let reversed_hops_with_payer = path.iter().rev().skip(1)
					.map(|hop| hop.pubkey)
					.chain(core::iter::once(our_node_id));
				let mut cumulative_msat = 0;

				// Taking the reversed vector from above, we zip it with just the reversed hops list to
				// work "backwards" of the given path, since the last hop's `fee_msat` actually represents
				// the total amount sent.
				for (next_hop, prev_hop) in path.iter().rev().zip(reversed_hops_with_payer) {
					cumulative_msat += next_hop.fee_msat;
					total_inflight_map
						.entry((next_hop.short_channel_id, NodeId::from_pubkey(&prev_hop) < NodeId::from_pubkey(&next_hop.pubkey)))
						.and_modify(|used_liquidity_msat| *used_liquidity_msat += cumulative_msat)
						.or_insert(cumulative_msat);
				}
			}
		}

		InFlightHtlcs(total_inflight_map)
	}
}

fn expiry_time_from_unix_epoch(invoice: &Invoice) -> Duration {
	invoice.signed_invoice.raw_invoice.data.timestamp.0 + invoice.expiry_time()
}

#[cfg(feature = "std")]
fn has_expired(route_params: &RouteParameters) -> bool {
	if let Some(expiry_time) = route_params.payment_params.expiry_time {
		Invoice::is_expired_from_epoch(&SystemTime::UNIX_EPOCH, Duration::from_secs(expiry_time))
	} else { false }
}

impl<P: Deref, R: Router, L: Deref, E: EventHandler, T: Time> EventHandler for InvoicePayerUsingTime<P, R, L, E, T>
where
	P::Target: Payer,
	L::Target: Logger,
{
	fn handle_event(&self, event: &Event) {
		match event {
			Event::PaymentPathFailed { payment_hash, path, ..  }
			| Event::PaymentPathSuccessful { path, payment_hash: Some(payment_hash), .. }
			| Event::ProbeSuccessful { payment_hash, path, .. }
			| Event::ProbeFailed { payment_hash, path, .. } => {
				self.remove_path_inflight_htlcs(*payment_hash, path);
			},
			_ => {},
		}

		match event {
			Event::PaymentPathFailed {
				payment_id, payment_hash, payment_failed_permanently, path, short_channel_id, retry, ..
			} => {
				if let Some(short_channel_id) = short_channel_id {
					let path = path.iter().collect::<Vec<_>>();
					self.router.notify_payment_path_failed(&path, *short_channel_id)
				}

				if payment_id.is_none() {
					log_trace!(self.logger, "Payment {} has no id; not retrying", log_bytes!(payment_hash.0));
				} else if *payment_failed_permanently {
					log_trace!(self.logger, "Payment {} rejected by destination; not retrying", log_bytes!(payment_hash.0));
					self.payer.abandon_payment(payment_id.unwrap());
				} else if retry.is_none() {
					log_trace!(self.logger, "Payment {} missing retry params; not retrying", log_bytes!(payment_hash.0));
					self.payer.abandon_payment(payment_id.unwrap());
				} else if self.retry_payment(payment_id.unwrap(), *payment_hash, retry.as_ref().unwrap()).is_ok() {
					// We retried at least somewhat, don't provide the PaymentPathFailed event to the user.
					return;
				} else {
					self.payer.abandon_payment(payment_id.unwrap());
				}
			},
			Event::PaymentFailed { payment_hash, .. } => {
				self.remove_cached_payment(&payment_hash);
			},
			Event::PaymentPathSuccessful { path, .. } => {
				let path = path.iter().collect::<Vec<_>>();
				self.router.notify_payment_path_successful(&path);
			},
			Event::PaymentSent { payment_hash, .. } => {
				let mut payment_cache = self.payment_cache.lock().unwrap();
				let attempts = payment_cache
					.remove(payment_hash)
					.map_or(1, |payment_info| payment_info.attempts.count + 1);
				log_trace!(self.logger, "Payment {} succeeded (attempts: {})", log_bytes!(payment_hash.0), attempts);
			},
			Event::ProbeSuccessful { payment_hash, path, .. } => {
				log_trace!(self.logger, "Probe payment {} of {}msat was successful", log_bytes!(payment_hash.0), path.last().unwrap().fee_msat);
				let path = path.iter().collect::<Vec<_>>();
				self.router.notify_payment_probe_successful(&path);
			},
			Event::ProbeFailed { payment_hash, path, short_channel_id, .. } => {
				if let Some(short_channel_id) = short_channel_id {
					log_trace!(self.logger, "Probe payment {} of {}msat failed at channel {}", log_bytes!(payment_hash.0), path.last().unwrap().fee_msat, *short_channel_id);
					let path = path.iter().collect::<Vec<_>>();
					self.router.notify_payment_probe_failed(&path, *short_channel_id);
				}
			},
			_ => {},
		}

		// Delegate to the decorated event handler unless the payment is retried.
		self.event_handler.handle_event(event)
	}
}

/// A map with liquidity value (in msat) keyed by a short channel id and the direction the HTLC
/// is traveling in. The direction boolean is determined by checking if the HTLC source's public
/// key is less than its destination. See [`InFlightHtlcs::used_liquidity_msat`] for more
/// details.
pub struct InFlightHtlcs(HashMap<(u64, bool), u64>);

impl InFlightHtlcs {
	/// Returns liquidity in msat given the public key of the HTLC source, target, and short channel
	/// id.
	pub fn used_liquidity_msat(&self, source: &NodeId, target: &NodeId, channel_scid: u64) -> Option<u64> {
		self.0.get(&(channel_scid, source < target)).map(|v| *v)
	}
}

impl Writeable for InFlightHtlcs {
	fn write<W: lightning::util::ser::Writer>(&self, writer: &mut W) -> Result<(), io::Error> { self.0.write(writer) }
}

impl lightning::util::ser::Readable for InFlightHtlcs {
	fn read<R: io::Read>(reader: &mut R) -> Result<Self, lightning::ln::msgs::DecodeError> {
		let infight_map: HashMap<(u64, bool), u64> = lightning::util::ser::Readable::read(reader)?;
		Ok(Self(infight_map))
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::{InvoiceBuilder, Currency};
	use crate::utils::{ScorerAccountingForInFlightHtlcs, create_invoice_from_channelmanager_and_duration_since_epoch};
	use bitcoin_hashes::sha256::Hash as Sha256;
	use lightning::ln::PaymentPreimage;
	use lightning::ln::channelmanager;
	use lightning::ln::features::{ChannelFeatures, NodeFeatures};
	use lightning::ln::functional_test_utils::*;
	use lightning::ln::msgs::{ChannelMessageHandler, ErrorAction, LightningError};
	use lightning::routing::gossip::{EffectiveCapacity, NodeId};
	use lightning::routing::router::{PaymentParameters, Route, RouteHop};
	use lightning::routing::scoring::{ChannelUsage, LockableScore, Score};
	use lightning::util::test_utils::TestLogger;
	use lightning::util::errors::APIError;
	use lightning::util::events::{Event, EventsProvider, MessageSendEvent, MessageSendEventsProvider};
	use secp256k1::{SecretKey, PublicKey, Secp256k1};
	use std::cell::RefCell;
	use std::collections::VecDeque;
	use std::ops::DerefMut;
	use std::time::{SystemTime, Duration};
	use crate::time_utils::tests::SinceEpoch;
	use crate::DEFAULT_EXPIRY_TIME;
	use lightning::util::errors::APIError::{ChannelUnavailable, MonitorUpdateInProgress};

	fn invoice(payment_preimage: PaymentPreimage) -> Invoice {
		let payment_hash = Sha256::hash(&payment_preimage.0);
		let private_key = SecretKey::from_slice(&[42; 32]).unwrap();

		InvoiceBuilder::new(Currency::Bitcoin)
			.description("test".into())
			.payment_hash(payment_hash)
			.payment_secret(PaymentSecret([0; 32]))
			.duration_since_epoch(duration_since_epoch())
			.min_final_cltv_expiry(144)
			.amount_milli_satoshis(128)
			.build_signed(|hash| {
				Secp256k1::new().sign_ecdsa_recoverable(hash, &private_key)
			})
			.unwrap()
	}

	fn duration_since_epoch() -> Duration {
		#[cfg(feature = "std")]
			let duration_since_epoch =
			SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap();
		#[cfg(not(feature = "std"))]
			let duration_since_epoch = Duration::from_secs(1234567);
		duration_since_epoch
	}

	fn zero_value_invoice(payment_preimage: PaymentPreimage) -> Invoice {
		let payment_hash = Sha256::hash(&payment_preimage.0);
		let private_key = SecretKey::from_slice(&[42; 32]).unwrap();

		InvoiceBuilder::new(Currency::Bitcoin)
			.description("test".into())
			.payment_hash(payment_hash)
			.payment_secret(PaymentSecret([0; 32]))
			.duration_since_epoch(duration_since_epoch())
			.min_final_cltv_expiry(144)
			.build_signed(|hash| {
				Secp256k1::new().sign_ecdsa_recoverable(hash, &private_key)
			})
			.unwrap()
	}

	#[cfg(feature = "std")]
	fn expired_invoice(payment_preimage: PaymentPreimage) -> Invoice {
		let payment_hash = Sha256::hash(&payment_preimage.0);
		let private_key = SecretKey::from_slice(&[42; 32]).unwrap();
		let duration = duration_since_epoch()
			.checked_sub(Duration::from_secs(DEFAULT_EXPIRY_TIME * 2))
			.unwrap();
		InvoiceBuilder::new(Currency::Bitcoin)
			.description("test".into())
			.payment_hash(payment_hash)
			.payment_secret(PaymentSecret([0; 32]))
			.duration_since_epoch(duration)
			.min_final_cltv_expiry(144)
			.amount_milli_satoshis(128)
			.build_signed(|hash| {
				Secp256k1::new().sign_ecdsa_recoverable(hash, &private_key)
			})
			.unwrap()
	}

	fn pubkey() -> PublicKey {
		PublicKey::from_slice(&hex::decode("02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619").unwrap()[..]).unwrap()
	}

	#[test]
	fn pays_invoice_on_first_attempt() {
		let event_handled = core::cell::RefCell::new(false);
		let event_handler = |_: &_| { *event_handled.borrow_mut() = true; };

		let payment_preimage = PaymentPreimage([1; 32]);
		let invoice = invoice(payment_preimage);
		let payment_hash = PaymentHash(invoice.payment_hash().clone().into_inner());
		let final_value_msat = invoice.amount_milli_satoshis().unwrap();

		let payer = TestPayer::new().expect_send(Amount::ForInvoice(final_value_msat));
		let router = TestRouter::new(TestScorer::new());
		let logger = TestLogger::new();
		let invoice_payer =
			InvoicePayer::new(&payer, router, &logger, event_handler, Retry::Attempts(0));

		let payment_id = Some(invoice_payer.pay_invoice(&invoice).unwrap());
		assert_eq!(*payer.attempts.borrow(), 1);

		invoice_payer.handle_event(&Event::PaymentSent {
			payment_id, payment_preimage, payment_hash, fee_paid_msat: None
		});
		assert_eq!(*event_handled.borrow(), true);
		assert_eq!(*payer.attempts.borrow(), 1);
	}

	#[test]
	fn pays_invoice_on_retry() {
		let event_handled = core::cell::RefCell::new(false);
		let event_handler = |_: &_| { *event_handled.borrow_mut() = true; };

		let payment_preimage = PaymentPreimage([1; 32]);
		let invoice = invoice(payment_preimage);
		let payment_hash = PaymentHash(invoice.payment_hash().clone().into_inner());
		let final_value_msat = invoice.amount_milli_satoshis().unwrap();

		let payer = TestPayer::new()
			.expect_send(Amount::ForInvoice(final_value_msat))
			.expect_send(Amount::OnRetry(final_value_msat / 2));
		let router = TestRouter::new(TestScorer::new());
		let logger = TestLogger::new();
		let invoice_payer =
			InvoicePayer::new(&payer, router, &logger, event_handler, Retry::Attempts(2));

		let payment_id = Some(invoice_payer.pay_invoice(&invoice).unwrap());
		assert_eq!(*payer.attempts.borrow(), 1);

		let event = Event::PaymentPathFailed {
			payment_id,
			payment_hash,
			network_update: None,
			payment_failed_permanently: false,
			all_paths_failed: false,
			path: TestRouter::path_for_value(final_value_msat),
			short_channel_id: None,
			retry: Some(TestRouter::retry_for_invoice(&invoice)),
		};
		invoice_payer.handle_event(&event);
		assert_eq!(*event_handled.borrow(), false);
		assert_eq!(*payer.attempts.borrow(), 2);

		invoice_payer.handle_event(&Event::PaymentSent {
			payment_id, payment_preimage, payment_hash, fee_paid_msat: None
		});
		assert_eq!(*event_handled.borrow(), true);
		assert_eq!(*payer.attempts.borrow(), 2);
	}

	#[test]
	fn pays_invoice_on_partial_failure() {
		let event_handler = |_: &_| { panic!() };

		let payment_preimage = PaymentPreimage([1; 32]);
		let invoice = invoice(payment_preimage);
		let retry = TestRouter::retry_for_invoice(&invoice);
		let final_value_msat = invoice.amount_milli_satoshis().unwrap();

		let payer = TestPayer::new()
			.fails_with_partial_failure(retry.clone(), OnAttempt(1), None)
			.fails_with_partial_failure(retry, OnAttempt(2), None)
			.expect_send(Amount::ForInvoice(final_value_msat))
			.expect_send(Amount::OnRetry(final_value_msat / 2))
			.expect_send(Amount::OnRetry(final_value_msat / 2));
		let router = TestRouter::new(TestScorer::new());
		let logger = TestLogger::new();
		let invoice_payer =
			InvoicePayer::new(&payer, router, &logger, event_handler, Retry::Attempts(2));

		assert!(invoice_payer.pay_invoice(&invoice).is_ok());
	}

	#[test]
	fn retries_payment_path_for_unknown_payment() {
		let event_handled = core::cell::RefCell::new(false);
		let event_handler = |_: &_| { *event_handled.borrow_mut() = true; };

		let payment_preimage = PaymentPreimage([1; 32]);
		let invoice = invoice(payment_preimage);
		let payment_hash = PaymentHash(invoice.payment_hash().clone().into_inner());
		let final_value_msat = invoice.amount_milli_satoshis().unwrap();

		let payer = TestPayer::new()
			.expect_send(Amount::OnRetry(final_value_msat / 2))
			.expect_send(Amount::OnRetry(final_value_msat / 2));
		let router = TestRouter::new(TestScorer::new());
		let logger = TestLogger::new();
		let invoice_payer =
			InvoicePayer::new(&payer, router, &logger, event_handler, Retry::Attempts(2));

		let payment_id = Some(PaymentId([1; 32]));
		let event = Event::PaymentPathFailed {
			payment_id,
			payment_hash,
			network_update: None,
			payment_failed_permanently: false,
			all_paths_failed: false,
			path: TestRouter::path_for_value(final_value_msat),
			short_channel_id: None,
			retry: Some(TestRouter::retry_for_invoice(&invoice)),
		};
		invoice_payer.handle_event(&event);
		assert_eq!(*event_handled.borrow(), false);
		assert_eq!(*payer.attempts.borrow(), 1);

		invoice_payer.handle_event(&event);
		assert_eq!(*event_handled.borrow(), false);
		assert_eq!(*payer.attempts.borrow(), 2);

		invoice_payer.handle_event(&Event::PaymentSent {
			payment_id, payment_preimage, payment_hash, fee_paid_msat: None
		});
		assert_eq!(*event_handled.borrow(), true);
		assert_eq!(*payer.attempts.borrow(), 2);
	}

	#[test]
	fn fails_paying_invoice_after_max_retry_counts() {
		let event_handled = core::cell::RefCell::new(false);
		let event_handler = |_: &_| { *event_handled.borrow_mut() = true; };

		let payment_preimage = PaymentPreimage([1; 32]);
		let invoice = invoice(payment_preimage);
		let final_value_msat = invoice.amount_milli_satoshis().unwrap();

		let payer = TestPayer::new()
			.expect_send(Amount::ForInvoice(final_value_msat))
			.expect_send(Amount::OnRetry(final_value_msat / 2))
			.expect_send(Amount::OnRetry(final_value_msat / 2));
		let router = TestRouter::new(TestScorer::new());
		let logger = TestLogger::new();
		let invoice_payer =
			InvoicePayer::new(&payer, router, &logger, event_handler, Retry::Attempts(2));

		let payment_id = Some(invoice_payer.pay_invoice(&invoice).unwrap());
		assert_eq!(*payer.attempts.borrow(), 1);

		let event = Event::PaymentPathFailed {
			payment_id,
			payment_hash: PaymentHash(invoice.payment_hash().clone().into_inner()),
			network_update: None,
			payment_failed_permanently: false,
			all_paths_failed: true,
			path: TestRouter::path_for_value(final_value_msat),
			short_channel_id: None,
			retry: Some(TestRouter::retry_for_invoice(&invoice)),
		};
		invoice_payer.handle_event(&event);
		assert_eq!(*event_handled.borrow(), false);
		assert_eq!(*payer.attempts.borrow(), 2);

		let event = Event::PaymentPathFailed {
			payment_id,
			payment_hash: PaymentHash(invoice.payment_hash().clone().into_inner()),
			network_update: None,
			payment_failed_permanently: false,
			all_paths_failed: false,
			path: TestRouter::path_for_value(final_value_msat / 2),
			short_channel_id: None,
			retry: Some(RouteParameters {
				final_value_msat: final_value_msat / 2, ..TestRouter::retry_for_invoice(&invoice)
			}),
		};
		invoice_payer.handle_event(&event);
		assert_eq!(*event_handled.borrow(), false);
		assert_eq!(*payer.attempts.borrow(), 3);

		invoice_payer.handle_event(&event);
		assert_eq!(*event_handled.borrow(), true);
		assert_eq!(*payer.attempts.borrow(), 3);
	}

	#[cfg(feature = "std")]
	#[test]
	fn fails_paying_invoice_after_max_retry_timeout() {
		let event_handled = core::cell::RefCell::new(false);
		let event_handler = |_: &_| { *event_handled.borrow_mut() = true; };

		let payment_preimage = PaymentPreimage([1; 32]);
		let invoice = invoice(payment_preimage);
		let final_value_msat = invoice.amount_milli_satoshis().unwrap();

		let payer = TestPayer::new()
			.expect_send(Amount::ForInvoice(final_value_msat))
			.expect_send(Amount::OnRetry(final_value_msat / 2));

		let router = TestRouter::new(TestScorer::new());
		let logger = TestLogger::new();
		type InvoicePayerUsingSinceEpoch <P, R, L, E> = InvoicePayerUsingTime::<P, R, L, E, SinceEpoch>;

		let invoice_payer =
			InvoicePayerUsingSinceEpoch::new(&payer, router, &logger, event_handler, Retry::Timeout(Duration::from_secs(120)));

		let payment_id = Some(invoice_payer.pay_invoice(&invoice).unwrap());
		assert_eq!(*payer.attempts.borrow(), 1);

		let event = Event::PaymentPathFailed {
			payment_id,
			payment_hash: PaymentHash(invoice.payment_hash().clone().into_inner()),
			network_update: None,
			payment_failed_permanently: false,
			all_paths_failed: true,
			path: TestRouter::path_for_value(final_value_msat),
			short_channel_id: None,
			retry: Some(TestRouter::retry_for_invoice(&invoice)),
		};
		invoice_payer.handle_event(&event);
		assert_eq!(*event_handled.borrow(), false);
		assert_eq!(*payer.attempts.borrow(), 2);

		SinceEpoch::advance(Duration::from_secs(121));

		invoice_payer.handle_event(&event);
		assert_eq!(*event_handled.borrow(), true);
		assert_eq!(*payer.attempts.borrow(), 2);
	}

	#[test]
	fn fails_paying_invoice_with_missing_retry_params() {
		let event_handled = core::cell::RefCell::new(false);
		let event_handler = |_: &_| { *event_handled.borrow_mut() = true; };

		let payment_preimage = PaymentPreimage([1; 32]);
		let invoice = invoice(payment_preimage);
		let final_value_msat = invoice.amount_milli_satoshis().unwrap();

		let payer = TestPayer::new().expect_send(Amount::ForInvoice(final_value_msat));
		let router = TestRouter::new(TestScorer::new());
		let logger = TestLogger::new();
		let invoice_payer =
			InvoicePayer::new(&payer, router, &logger, event_handler, Retry::Attempts(2));

		let payment_id = Some(invoice_payer.pay_invoice(&invoice).unwrap());
		assert_eq!(*payer.attempts.borrow(), 1);

		let event = Event::PaymentPathFailed {
			payment_id,
			payment_hash: PaymentHash(invoice.payment_hash().clone().into_inner()),
			network_update: None,
			payment_failed_permanently: false,
			all_paths_failed: false,
			path: vec![],
			short_channel_id: None,
			retry: None,
		};
		invoice_payer.handle_event(&event);
		assert_eq!(*event_handled.borrow(), true);
		assert_eq!(*payer.attempts.borrow(), 1);
	}

	// Expiration is checked only in an std environment
	#[cfg(feature = "std")]
	#[test]
	fn fails_paying_invoice_after_expiration() {
		let event_handled = core::cell::RefCell::new(false);
		let event_handler = |_: &_| { *event_handled.borrow_mut() = true; };

		let payer = TestPayer::new();
		let router = TestRouter::new(TestScorer::new());
		let logger = TestLogger::new();
		let invoice_payer =
			InvoicePayer::new(&payer, router, &logger, event_handler, Retry::Attempts(2));

		let payment_preimage = PaymentPreimage([1; 32]);
		let invoice = expired_invoice(payment_preimage);
		if let PaymentError::Invoice(msg) = invoice_payer.pay_invoice(&invoice).unwrap_err() {
			assert_eq!(msg, "Invoice expired prior to send");
		} else { panic!("Expected Invoice Error"); }
	}

	// Expiration is checked only in an std environment
	#[cfg(feature = "std")]
	#[test]
	fn fails_retrying_invoice_after_expiration() {
		let event_handled = core::cell::RefCell::new(false);
		let event_handler = |_: &_| { *event_handled.borrow_mut() = true; };

		let payment_preimage = PaymentPreimage([1; 32]);
		let invoice = invoice(payment_preimage);
		let final_value_msat = invoice.amount_milli_satoshis().unwrap();

		let payer = TestPayer::new().expect_send(Amount::ForInvoice(final_value_msat));
		let router = TestRouter::new(TestScorer::new());
		let logger = TestLogger::new();
		let invoice_payer =
			InvoicePayer::new(&payer, router,  &logger, event_handler, Retry::Attempts(2));

		let payment_id = Some(invoice_payer.pay_invoice(&invoice).unwrap());
		assert_eq!(*payer.attempts.borrow(), 1);

		let mut retry_data = TestRouter::retry_for_invoice(&invoice);
		retry_data.payment_params.expiry_time = Some(SystemTime::now()
			.checked_sub(Duration::from_secs(2)).unwrap()
			.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs());
		let event = Event::PaymentPathFailed {
			payment_id,
			payment_hash: PaymentHash(invoice.payment_hash().clone().into_inner()),
			network_update: None,
			payment_failed_permanently: false,
			all_paths_failed: false,
			path: vec![],
			short_channel_id: None,
			retry: Some(retry_data),
		};
		invoice_payer.handle_event(&event);
		assert_eq!(*event_handled.borrow(), true);
		assert_eq!(*payer.attempts.borrow(), 1);
	}

	#[test]
	fn fails_paying_invoice_after_retry_error() {
		let event_handled = core::cell::RefCell::new(false);
		let event_handler = |_: &_| { *event_handled.borrow_mut() = true; };

		let payment_preimage = PaymentPreimage([1; 32]);
		let invoice = invoice(payment_preimage);
		let final_value_msat = invoice.amount_milli_satoshis().unwrap();

		let payer = TestPayer::new()
			.fails_on_attempt(2)
			.expect_send(Amount::ForInvoice(final_value_msat))
			.expect_send(Amount::OnRetry(final_value_msat / 2));
		let router = TestRouter::new(TestScorer::new());
		let logger = TestLogger::new();
		let invoice_payer =
			InvoicePayer::new(&payer, router, &logger, event_handler, Retry::Attempts(2));

		let payment_id = Some(invoice_payer.pay_invoice(&invoice).unwrap());
		assert_eq!(*payer.attempts.borrow(), 1);

		let event = Event::PaymentPathFailed {
			payment_id,
			payment_hash: PaymentHash(invoice.payment_hash().clone().into_inner()),
			network_update: None,
			payment_failed_permanently: false,
			all_paths_failed: false,
			path: TestRouter::path_for_value(final_value_msat / 2),
			short_channel_id: None,
			retry: Some(TestRouter::retry_for_invoice(&invoice)),
		};
		invoice_payer.handle_event(&event);
		assert_eq!(*event_handled.borrow(), true);
		assert_eq!(*payer.attempts.borrow(), 2);
	}

	#[test]
	fn fails_paying_invoice_after_rejected_by_payee() {
		let event_handled = core::cell::RefCell::new(false);
		let event_handler = |_: &_| { *event_handled.borrow_mut() = true; };

		let payment_preimage = PaymentPreimage([1; 32]);
		let invoice = invoice(payment_preimage);
		let final_value_msat = invoice.amount_milli_satoshis().unwrap();

		let payer = TestPayer::new().expect_send(Amount::ForInvoice(final_value_msat));
		let router = TestRouter::new(TestScorer::new());
		let logger = TestLogger::new();
		let invoice_payer =
			InvoicePayer::new(&payer, router, &logger, event_handler, Retry::Attempts(2));

		let payment_id = Some(invoice_payer.pay_invoice(&invoice).unwrap());
		assert_eq!(*payer.attempts.borrow(), 1);

		let event = Event::PaymentPathFailed {
			payment_id,
			payment_hash: PaymentHash(invoice.payment_hash().clone().into_inner()),
			network_update: None,
			payment_failed_permanently: true,
			all_paths_failed: false,
			path: vec![],
			short_channel_id: None,
			retry: Some(TestRouter::retry_for_invoice(&invoice)),
		};
		invoice_payer.handle_event(&event);
		assert_eq!(*event_handled.borrow(), true);
		assert_eq!(*payer.attempts.borrow(), 1);
	}

	#[test]
	fn fails_repaying_invoice_with_pending_payment() {
		let event_handled = core::cell::RefCell::new(false);
		let event_handler = |_: &_| { *event_handled.borrow_mut() = true; };

		let payment_preimage = PaymentPreimage([1; 32]);
		let invoice = invoice(payment_preimage);
		let final_value_msat = invoice.amount_milli_satoshis().unwrap();

		let payer = TestPayer::new()
			.expect_send(Amount::ForInvoice(final_value_msat))
			.expect_send(Amount::ForInvoice(final_value_msat));
		let router = TestRouter::new(TestScorer::new());
		let logger = TestLogger::new();
		let invoice_payer =
			InvoicePayer::new(&payer, router, &logger, event_handler, Retry::Attempts(0));

		let payment_id = Some(invoice_payer.pay_invoice(&invoice).unwrap());

		// Cannot repay an invoice pending payment.
		match invoice_payer.pay_invoice(&invoice) {
			Err(PaymentError::Invoice("payment pending")) => {},
			Err(_) => panic!("unexpected error"),
			Ok(_) => panic!("expected invoice error"),
		}

		// Can repay an invoice once cleared from cache.
		let payment_hash = PaymentHash(invoice.payment_hash().clone().into_inner());
		invoice_payer.remove_cached_payment(&payment_hash);
		assert!(invoice_payer.pay_invoice(&invoice).is_ok());

		// Cannot retry paying an invoice if cleared from cache.
		invoice_payer.remove_cached_payment(&payment_hash);
		let event = Event::PaymentPathFailed {
			payment_id,
			payment_hash,
			network_update: None,
			payment_failed_permanently: false,
			all_paths_failed: false,
			path: vec![],
			short_channel_id: None,
			retry: Some(TestRouter::retry_for_invoice(&invoice)),
		};
		invoice_payer.handle_event(&event);
		assert_eq!(*event_handled.borrow(), true);
	}

	#[test]
	fn fails_paying_invoice_with_routing_errors() {
		let payer = TestPayer::new();
		let router = FailingRouter {};
		let logger = TestLogger::new();
		let invoice_payer =
			InvoicePayer::new(&payer, router, &logger, |_: &_| {}, Retry::Attempts(0));

		let payment_preimage = PaymentPreimage([1; 32]);
		let invoice = invoice(payment_preimage);
		match invoice_payer.pay_invoice(&invoice) {
			Err(PaymentError::Routing(_)) => {},
			Err(_) => panic!("unexpected error"),
			Ok(_) => panic!("expected routing error"),
		}
	}

	#[test]
	fn fails_paying_invoice_with_sending_errors() {
		let payment_preimage = PaymentPreimage([1; 32]);
		let invoice = invoice(payment_preimage);
		let final_value_msat = invoice.amount_milli_satoshis().unwrap();

		let payer = TestPayer::new()
			.fails_on_attempt(1)
			.expect_send(Amount::ForInvoice(final_value_msat));
		let router = TestRouter::new(TestScorer::new());
		let logger = TestLogger::new();
		let invoice_payer =
			InvoicePayer::new(&payer, router, &logger, |_: &_| {}, Retry::Attempts(0));

		match invoice_payer.pay_invoice(&invoice) {
			Err(PaymentError::Sending(_)) => {},
			Err(_) => panic!("unexpected error"),
			Ok(_) => panic!("expected sending error"),
		}
	}

	#[test]
	fn pays_zero_value_invoice_using_amount() {
		let event_handled = core::cell::RefCell::new(false);
		let event_handler = |_: &_| { *event_handled.borrow_mut() = true; };

		let payment_preimage = PaymentPreimage([1; 32]);
		let invoice = zero_value_invoice(payment_preimage);
		let payment_hash = PaymentHash(invoice.payment_hash().clone().into_inner());
		let final_value_msat = 100;

		let payer = TestPayer::new().expect_send(Amount::ForInvoice(final_value_msat));
		let router = TestRouter::new(TestScorer::new());
		let logger = TestLogger::new();
		let invoice_payer =
			InvoicePayer::new(&payer, router, &logger, event_handler, Retry::Attempts(0));

		let payment_id =
			Some(invoice_payer.pay_zero_value_invoice(&invoice, final_value_msat).unwrap());
		assert_eq!(*payer.attempts.borrow(), 1);

		invoice_payer.handle_event(&Event::PaymentSent {
			payment_id, payment_preimage, payment_hash, fee_paid_msat: None
		});
		assert_eq!(*event_handled.borrow(), true);
		assert_eq!(*payer.attempts.borrow(), 1);
	}

	#[test]
	fn fails_paying_zero_value_invoice_with_amount() {
		let event_handled = core::cell::RefCell::new(false);
		let event_handler = |_: &_| { *event_handled.borrow_mut() = true; };

		let payer = TestPayer::new();
		let router = TestRouter::new(TestScorer::new());
		let logger = TestLogger::new();
		let invoice_payer =
			InvoicePayer::new(&payer, router,  &logger, event_handler, Retry::Attempts(0));

		let payment_preimage = PaymentPreimage([1; 32]);
		let invoice = invoice(payment_preimage);

		// Cannot repay an invoice pending payment.
		match invoice_payer.pay_zero_value_invoice(&invoice, 100) {
			Err(PaymentError::Invoice("amount unexpected")) => {},
			Err(_) => panic!("unexpected error"),
			Ok(_) => panic!("expected invoice error"),
		}
	}

	#[test]
	fn pays_pubkey_with_amount() {
		let event_handled = core::cell::RefCell::new(false);
		let event_handler = |_: &_| { *event_handled.borrow_mut() = true; };

		let pubkey = pubkey();
		let payment_preimage = PaymentPreimage([1; 32]);
		let payment_hash = PaymentHash(Sha256::hash(&payment_preimage.0).into_inner());
		let final_value_msat = 100;
		let final_cltv_expiry_delta = 42;

		let payer = TestPayer::new()
			.expect_send(Amount::Spontaneous(final_value_msat))
			.expect_send(Amount::OnRetry(final_value_msat));
		let router = TestRouter::new(TestScorer::new());
		let logger = TestLogger::new();
		let invoice_payer =
			InvoicePayer::new(&payer, router, &logger, event_handler, Retry::Attempts(2));

		let payment_id = Some(invoice_payer.pay_pubkey(
				pubkey, payment_preimage, final_value_msat, final_cltv_expiry_delta
			).unwrap());
		assert_eq!(*payer.attempts.borrow(), 1);

		let retry = RouteParameters {
			payment_params: PaymentParameters::for_keysend(pubkey),
			final_value_msat,
			final_cltv_expiry_delta,
		};
		let event = Event::PaymentPathFailed {
			payment_id,
			payment_hash,
			network_update: None,
			payment_failed_permanently: false,
			all_paths_failed: false,
			path: vec![],
			short_channel_id: None,
			retry: Some(retry),
		};
		invoice_payer.handle_event(&event);
		assert_eq!(*event_handled.borrow(), false);
		assert_eq!(*payer.attempts.borrow(), 2);

		invoice_payer.handle_event(&Event::PaymentSent {
			payment_id, payment_preimage, payment_hash, fee_paid_msat: None
		});
		assert_eq!(*event_handled.borrow(), true);
		assert_eq!(*payer.attempts.borrow(), 2);
	}

	#[test]
	fn scores_failed_channel() {
		let event_handled = core::cell::RefCell::new(false);
		let event_handler = |_: &_| { *event_handled.borrow_mut() = true; };

		let payment_preimage = PaymentPreimage([1; 32]);
		let invoice = invoice(payment_preimage);
		let payment_hash = PaymentHash(invoice.payment_hash().clone().into_inner());
		let final_value_msat = invoice.amount_milli_satoshis().unwrap();
		let path = TestRouter::path_for_value(final_value_msat);
		let short_channel_id = Some(path[0].short_channel_id);

		// Expect that scorer is given short_channel_id upon handling the event.
		let payer = TestPayer::new()
			.expect_send(Amount::ForInvoice(final_value_msat))
			.expect_send(Amount::OnRetry(final_value_msat / 2));
		let scorer = TestScorer::new().expect(TestResult::PaymentFailure {
			path: path.clone(), short_channel_id: path[0].short_channel_id,
		});
		let router = TestRouter::new(scorer);
		let logger = TestLogger::new();
		let invoice_payer =
			InvoicePayer::new(&payer, router, &logger, event_handler, Retry::Attempts(2));

		let payment_id = Some(invoice_payer.pay_invoice(&invoice).unwrap());
		let event = Event::PaymentPathFailed {
			payment_id,
			payment_hash,
			network_update: None,
			payment_failed_permanently: false,
			all_paths_failed: false,
			path,
			short_channel_id,
			retry: Some(TestRouter::retry_for_invoice(&invoice)),
		};
		invoice_payer.handle_event(&event);
	}

	#[test]
	fn scores_successful_channels() {
		let event_handled = core::cell::RefCell::new(false);
		let event_handler = |_: &_| { *event_handled.borrow_mut() = true; };

		let payment_preimage = PaymentPreimage([1; 32]);
		let invoice = invoice(payment_preimage);
		let payment_hash = Some(PaymentHash(invoice.payment_hash().clone().into_inner()));
		let final_value_msat = invoice.amount_milli_satoshis().unwrap();
		let route = TestRouter::route_for_value(final_value_msat);

		// Expect that scorer is given short_channel_id upon handling the event.
		let payer = TestPayer::new().expect_send(Amount::ForInvoice(final_value_msat));
		let scorer = TestScorer::new()
			.expect(TestResult::PaymentSuccess { path: route.paths[0].clone() })
			.expect(TestResult::PaymentSuccess { path: route.paths[1].clone() });
		let router = TestRouter::new(scorer);
		let logger = TestLogger::new();
		let invoice_payer =
			InvoicePayer::new(&payer, router, &logger, event_handler, Retry::Attempts(2));

		let payment_id = invoice_payer.pay_invoice(&invoice).unwrap();
		let event = Event::PaymentPathSuccessful {
			payment_id, payment_hash, path: route.paths[0].clone()
		};
		invoice_payer.handle_event(&event);
		let event = Event::PaymentPathSuccessful {
			payment_id, payment_hash, path: route.paths[1].clone()
		};
		invoice_payer.handle_event(&event);
	}

	#[test]
	fn generates_correct_inflight_map_data() {
		let event_handled = core::cell::RefCell::new(false);
		let event_handler = |_: &_| { *event_handled.borrow_mut() = true; };

		let payment_preimage = PaymentPreimage([1; 32]);
		let invoice = invoice(payment_preimage);
		let payment_hash = Some(PaymentHash(invoice.payment_hash().clone().into_inner()));
		let final_value_msat = invoice.amount_milli_satoshis().unwrap();

		let payer = TestPayer::new().expect_send(Amount::ForInvoice(final_value_msat));
		let final_value_msat = invoice.amount_milli_satoshis().unwrap();
		let route = TestRouter::route_for_value(final_value_msat);
		let router = TestRouter::new(TestScorer::new());
		let logger = TestLogger::new();
		let invoice_payer =
			InvoicePayer::new(&payer, router, &logger, event_handler, Retry::Attempts(0));

		let payment_id = invoice_payer.pay_invoice(&invoice).unwrap();

		let inflight_map = invoice_payer.create_inflight_map();
		// First path check
		assert_eq!(inflight_map.0.get(&(0, false)).unwrap().clone(), 94);
		assert_eq!(inflight_map.0.get(&(1, true)).unwrap().clone(), 84);
		assert_eq!(inflight_map.0.get(&(2, false)).unwrap().clone(), 64);

		// Second path check
		assert_eq!(inflight_map.0.get(&(3, false)).unwrap().clone(), 74);
		assert_eq!(inflight_map.0.get(&(4, false)).unwrap().clone(), 64);

		invoice_payer.handle_event(&Event::PaymentPathSuccessful {
			payment_id, payment_hash, path: route.paths[0].clone()
		});

		let inflight_map = invoice_payer.create_inflight_map();

		assert_eq!(inflight_map.0.get(&(0, false)), None);
		assert_eq!(inflight_map.0.get(&(1, true)), None);
		assert_eq!(inflight_map.0.get(&(2, false)), None);

		// Second path should still be inflight
		assert_eq!(inflight_map.0.get(&(3, false)).unwrap().clone(), 74);
		assert_eq!(inflight_map.0.get(&(4, false)).unwrap().clone(), 64)
	}

	#[test]
	fn considers_inflight_htlcs_between_invoice_payments_when_path_succeeds() {
		// First, let's just send a payment through, but only make sure one of the path completes
		let event_handled = core::cell::RefCell::new(false);
		let event_handler = |_: &_| { *event_handled.borrow_mut() = true; };

		let payment_preimage = PaymentPreimage([1; 32]);
		let payment_invoice = invoice(payment_preimage);
		let payment_hash = Some(PaymentHash(payment_invoice.payment_hash().clone().into_inner()));
		let final_value_msat = payment_invoice.amount_milli_satoshis().unwrap();

		let payer = TestPayer::new()
			.expect_send(Amount::ForInvoice(final_value_msat))
			.expect_send(Amount::ForInvoice(final_value_msat));
		let final_value_msat = payment_invoice.amount_milli_satoshis().unwrap();
		let route = TestRouter::route_for_value(final_value_msat);
		let scorer = TestScorer::new()
			// 1st invoice, 1st path
			.expect_usage(ChannelUsage { amount_msat: 64, inflight_htlc_msat: 0, effective_capacity: EffectiveCapacity::Unknown } )
			.expect_usage(ChannelUsage { amount_msat: 84, inflight_htlc_msat: 0, effective_capacity: EffectiveCapacity::Unknown } )
			.expect_usage(ChannelUsage { amount_msat: 94, inflight_htlc_msat: 0, effective_capacity: EffectiveCapacity::Unknown } )
			// 1st invoice, 2nd path
			.expect_usage(ChannelUsage { amount_msat: 64, inflight_htlc_msat: 0, effective_capacity: EffectiveCapacity::Unknown } )
			.expect_usage(ChannelUsage { amount_msat: 74, inflight_htlc_msat: 0, effective_capacity: EffectiveCapacity::Unknown } )
			// 2nd invoice, 1st path
			.expect_usage(ChannelUsage { amount_msat: 64, inflight_htlc_msat: 0, effective_capacity: EffectiveCapacity::Unknown } )
			.expect_usage(ChannelUsage { amount_msat: 84, inflight_htlc_msat: 0, effective_capacity: EffectiveCapacity::Unknown } )
			.expect_usage(ChannelUsage { amount_msat: 94, inflight_htlc_msat: 0, effective_capacity: EffectiveCapacity::Unknown } )
			// 2nd invoice, 2nd path
			.expect_usage(ChannelUsage { amount_msat: 64, inflight_htlc_msat: 64, effective_capacity: EffectiveCapacity::Unknown } )
			.expect_usage(ChannelUsage { amount_msat: 74, inflight_htlc_msat: 74, effective_capacity: EffectiveCapacity::Unknown } );
		let router = TestRouter::new(scorer);
		let logger = TestLogger::new();
		let invoice_payer =
			InvoicePayer::new(&payer, router, &logger, event_handler, Retry::Attempts(0));

		// Succeed 1st path, leave 2nd path inflight
		let payment_id = invoice_payer.pay_invoice(&payment_invoice).unwrap();
		invoice_payer.handle_event(&Event::PaymentPathSuccessful {
			payment_id, payment_hash, path: route.paths[0].clone()
		});

		// Let's pay a second invoice that will be using the same path. This should trigger the
		// assertions that expect the last 4 ChannelUsage values above where TestScorer is initialized.
		// Particularly, the 2nd path of the 1st payment, since it is not yet complete, should still
		// have 64 msats inflight for paths considering the channel with scid of 1.
		let payment_preimage_2 = PaymentPreimage([2; 32]);
		let payment_invoice_2 = invoice(payment_preimage_2);
		invoice_payer.pay_invoice(&payment_invoice_2).unwrap();
	}

	#[test]
	fn considers_inflight_htlcs_between_retries() {
		// First, let's just send a payment through, but only make sure one of the path completes
		let event_handled = core::cell::RefCell::new(false);
		let event_handler = |_: &_| { *event_handled.borrow_mut() = true; };

		let payment_preimage = PaymentPreimage([1; 32]);
		let payment_invoice = invoice(payment_preimage);
		let payment_hash = PaymentHash(payment_invoice.payment_hash().clone().into_inner());
		let final_value_msat = payment_invoice.amount_milli_satoshis().unwrap();

		let payer = TestPayer::new()
			.expect_send(Amount::ForInvoice(final_value_msat))
			.expect_send(Amount::OnRetry(final_value_msat / 2))
			.expect_send(Amount::OnRetry(final_value_msat / 4));
		let final_value_msat = payment_invoice.amount_milli_satoshis().unwrap();
		let scorer = TestScorer::new()
			// 1st invoice, 1st path
			.expect_usage(ChannelUsage { amount_msat: 64, inflight_htlc_msat: 0, effective_capacity: EffectiveCapacity::Unknown } )
			.expect_usage(ChannelUsage { amount_msat: 84, inflight_htlc_msat: 0, effective_capacity: EffectiveCapacity::Unknown } )
			.expect_usage(ChannelUsage { amount_msat: 94, inflight_htlc_msat: 0, effective_capacity: EffectiveCapacity::Unknown } )
			// 1st invoice, 2nd path
			.expect_usage(ChannelUsage { amount_msat: 64, inflight_htlc_msat: 0, effective_capacity: EffectiveCapacity::Unknown } )
			.expect_usage(ChannelUsage { amount_msat: 74, inflight_htlc_msat: 0, effective_capacity: EffectiveCapacity::Unknown } )
			// Retry 1, 1st path
			.expect_usage(ChannelUsage { amount_msat: 32, inflight_htlc_msat: 0, effective_capacity: EffectiveCapacity::Unknown } )
			.expect_usage(ChannelUsage { amount_msat: 52, inflight_htlc_msat: 0, effective_capacity: EffectiveCapacity::Unknown } )
			.expect_usage(ChannelUsage { amount_msat: 62, inflight_htlc_msat: 0, effective_capacity: EffectiveCapacity::Unknown } )
			// Retry 1, 2nd path
			.expect_usage(ChannelUsage { amount_msat: 32, inflight_htlc_msat: 64, effective_capacity: EffectiveCapacity::Unknown } )
			.expect_usage(ChannelUsage { amount_msat: 42, inflight_htlc_msat: 64 + 10, effective_capacity: EffectiveCapacity::Unknown } )
			// Retry 2, 1st path
			.expect_usage(ChannelUsage { amount_msat: 16, inflight_htlc_msat: 0, effective_capacity: EffectiveCapacity::Unknown } )
			.expect_usage(ChannelUsage { amount_msat: 36, inflight_htlc_msat: 0, effective_capacity: EffectiveCapacity::Unknown } )
			.expect_usage(ChannelUsage { amount_msat: 46, inflight_htlc_msat: 0, effective_capacity: EffectiveCapacity::Unknown } )
			// Retry 2, 2nd path
			.expect_usage(ChannelUsage { amount_msat: 16, inflight_htlc_msat: 64 + 32, effective_capacity: EffectiveCapacity::Unknown } )
			.expect_usage(ChannelUsage { amount_msat: 26, inflight_htlc_msat: 74 + 32 + 10, effective_capacity: EffectiveCapacity::Unknown } );
		let router = TestRouter::new(scorer);
		let logger = TestLogger::new();
		let invoice_payer =
			InvoicePayer::new(&payer, router, &logger, event_handler, Retry::Attempts(2));

		// Fail 1st path, leave 2nd path inflight
		let payment_id = Some(invoice_payer.pay_invoice(&payment_invoice).unwrap());
		invoice_payer.handle_event(&Event::PaymentPathFailed {
			payment_id,
			payment_hash,
			network_update: None,
			payment_failed_permanently: false,
			all_paths_failed: false,
			path: TestRouter::path_for_value(final_value_msat),
			short_channel_id: None,
			retry: Some(TestRouter::retry_for_invoice(&payment_invoice)),
		});

		// Fails again the 1st path of our retry
		invoice_payer.handle_event(&Event::PaymentPathFailed {
			payment_id,
			payment_hash,
			network_update: None,
			payment_failed_permanently: false,
			all_paths_failed: false,
			path: TestRouter::path_for_value(final_value_msat / 2),
			short_channel_id: None,
			retry: Some(RouteParameters {
				final_value_msat: final_value_msat / 4,
				..TestRouter::retry_for_invoice(&payment_invoice)
			}),
		});
	}

	#[test]
	fn accounts_for_some_inflight_htlcs_sent_during_partial_failure() {
		let event_handled = core::cell::RefCell::new(false);
		let event_handler = |_: &_| { *event_handled.borrow_mut() = true; };

		let payment_preimage = PaymentPreimage([1; 32]);
		let invoice_to_pay = invoice(payment_preimage);
		let final_value_msat = invoice_to_pay.amount_milli_satoshis().unwrap();

		let retry = TestRouter::retry_for_invoice(&invoice_to_pay);
		let payer = TestPayer::new()
			.fails_with_partial_failure(
				retry.clone(), OnAttempt(1),
				Some(vec![
					Err(ChannelUnavailable { err: "abc".to_string() }), Err(MonitorUpdateInProgress)
				]))
			.expect_send(Amount::ForInvoice(final_value_msat));

		let router = TestRouter::new(TestScorer::new());
		let logger = TestLogger::new();
		let invoice_payer =
			InvoicePayer::new(&payer, router, &logger, event_handler, Retry::Attempts(0));

		invoice_payer.pay_invoice(&invoice_to_pay).unwrap();
		let inflight_map = invoice_payer.create_inflight_map();

		// Only the second path, which failed with `MonitorUpdateInProgress` should be added to our
		// inflight map because retries are disabled.
		assert_eq!(inflight_map.0.len(), 2);
	}

	#[test]
	fn accounts_for_all_inflight_htlcs_sent_during_partial_failure() {
		let event_handled = core::cell::RefCell::new(false);
		let event_handler = |_: &_| { *event_handled.borrow_mut() = true; };

		let payment_preimage = PaymentPreimage([1; 32]);
		let invoice_to_pay = invoice(payment_preimage);
		let final_value_msat = invoice_to_pay.amount_milli_satoshis().unwrap();

		let retry = TestRouter::retry_for_invoice(&invoice_to_pay);
		let payer = TestPayer::new()
			.fails_with_partial_failure(
				retry.clone(), OnAttempt(1),
				Some(vec![
					Ok(()), Err(MonitorUpdateInProgress)
				]))
			.expect_send(Amount::ForInvoice(final_value_msat));

		let router = TestRouter::new(TestScorer::new());
		let logger = TestLogger::new();
		let invoice_payer =
			InvoicePayer::new(&payer, router, &logger, event_handler, Retry::Attempts(0));

		invoice_payer.pay_invoice(&invoice_to_pay).unwrap();
		let inflight_map = invoice_payer.create_inflight_map();

		// All paths successful, hence we check of the existence of all 5 hops.
		assert_eq!(inflight_map.0.len(), 5);
	}

	struct TestRouter {
		scorer: RefCell<TestScorer>,
	}

	impl TestRouter {
		fn new(scorer: TestScorer) -> Self {
			TestRouter { scorer: RefCell::new(scorer) }
		}

		fn route_for_value(final_value_msat: u64) -> Route {
			Route {
				paths: vec![
					vec![
						RouteHop {
							pubkey: PublicKey::from_slice(&hex::decode("02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619").unwrap()[..]).unwrap(),
							channel_features: ChannelFeatures::empty(),
							node_features: NodeFeatures::empty(),
							short_channel_id: 0,
							fee_msat: 10,
							cltv_expiry_delta: 0
						},
						RouteHop {
							pubkey: PublicKey::from_slice(&hex::decode("0324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c").unwrap()[..]).unwrap(),
							channel_features: ChannelFeatures::empty(),
							node_features: NodeFeatures::empty(),
							short_channel_id: 1,
							fee_msat: 20,
							cltv_expiry_delta: 0
						},
						RouteHop {
							pubkey: PublicKey::from_slice(&hex::decode("027f31ebc5462c1fdce1b737ecff52d37d75dea43ce11c74d25aa297165faa2007").unwrap()[..]).unwrap(),
							channel_features: ChannelFeatures::empty(),
							node_features: NodeFeatures::empty(),
							short_channel_id: 2,
							fee_msat: final_value_msat / 2,
							cltv_expiry_delta: 0
						},
					],
					vec![
						RouteHop {
							pubkey: PublicKey::from_slice(&hex::decode("029e03a901b85534ff1e92c43c74431f7ce72046060fcf7a95c37e148f78c77255").unwrap()[..]).unwrap(),
							channel_features: ChannelFeatures::empty(),
							node_features: NodeFeatures::empty(),
							short_channel_id: 3,
							fee_msat: 10,
							cltv_expiry_delta: 144
						},
						RouteHop {
							pubkey: PublicKey::from_slice(&hex::decode("027f31ebc5462c1fdce1b737ecff52d37d75dea43ce11c74d25aa297165faa2007").unwrap()[..]).unwrap(),
							channel_features: ChannelFeatures::empty(),
							node_features: NodeFeatures::empty(),
							short_channel_id: 4,
							fee_msat: final_value_msat / 2,
							cltv_expiry_delta: 144
						}
					],
				],
				payment_params: None,
			}
		}

		fn path_for_value(final_value_msat: u64) -> Vec<RouteHop> {
			TestRouter::route_for_value(final_value_msat).paths[0].clone()
		}

		fn retry_for_invoice(invoice: &Invoice) -> RouteParameters {
			let mut payment_params = PaymentParameters::from_node_id(invoice.recover_payee_pub_key())
				.with_expiry_time(expiry_time_from_unix_epoch(invoice).as_secs())
				.with_route_hints(invoice.route_hints());
			if let Some(features) = invoice.features() {
				payment_params = payment_params.with_features(features.clone());
			}
			let final_value_msat = invoice.amount_milli_satoshis().unwrap() / 2;
			RouteParameters {
				payment_params,
				final_value_msat,
				final_cltv_expiry_delta: invoice.min_final_cltv_expiry() as u32,
			}
		}
	}

	impl Router for TestRouter {
		fn find_route(
			&self, payer: &PublicKey, route_params: &RouteParameters, _payment_hash: &PaymentHash,
			_first_hops: Option<&[&ChannelDetails]>, inflight_htlcs: InFlightHtlcs
		) -> Result<Route, LightningError> {
			// Simulate calling the Scorer just as you would in find_route
			let route = Self::route_for_value(route_params.final_value_msat);
			let mut locked_scorer = self.scorer.lock();
			let scorer = ScorerAccountingForInFlightHtlcs::new(locked_scorer.deref_mut(), inflight_htlcs);
			for path in route.paths {
				let mut aggregate_msat = 0u64;
				for (idx, hop) in path.iter().rev().enumerate() {
					aggregate_msat += hop.fee_msat;
					let usage = ChannelUsage {
						amount_msat: aggregate_msat,
						inflight_htlc_msat: 0,
						effective_capacity: EffectiveCapacity::Unknown,
					};

					// Since the path is reversed, the last element in our iteration is the first
					// hop.
					if idx == path.len() - 1 {
						scorer.channel_penalty_msat(hop.short_channel_id, &NodeId::from_pubkey(payer), &NodeId::from_pubkey(&hop.pubkey), usage);
					} else {
						scorer.channel_penalty_msat(hop.short_channel_id, &NodeId::from_pubkey(&path[idx + 1].pubkey), &NodeId::from_pubkey(&hop.pubkey), usage);
					}
				}
			}

			Ok(Route {
				payment_params: Some(route_params.payment_params.clone()), ..Self::route_for_value(route_params.final_value_msat)
			})
		}

		fn notify_payment_path_failed(&self, path: &[&RouteHop], short_channel_id: u64) {
			self.scorer.lock().payment_path_failed(path, short_channel_id);
		}

		fn notify_payment_path_successful(&self, path: &[&RouteHop]) {
			self.scorer.lock().payment_path_successful(path);
		}

		fn notify_payment_probe_successful(&self, path: &[&RouteHop]) {
			self.scorer.lock().probe_successful(path);
		}

		fn notify_payment_probe_failed(&self, path: &[&RouteHop], short_channel_id: u64) {
			self.scorer.lock().probe_failed(path, short_channel_id);
		}
	}

	struct FailingRouter;

	impl Router for FailingRouter {
		fn find_route(
			&self, _payer: &PublicKey, _params: &RouteParameters, _payment_hash: &PaymentHash,
			_first_hops: Option<&[&ChannelDetails]>, _inflight_htlcs: InFlightHtlcs
		) -> Result<Route, LightningError> {
			Err(LightningError { err: String::new(), action: ErrorAction::IgnoreError })
		}

		fn notify_payment_path_failed(&self, _path: &[&RouteHop], _short_channel_id: u64) {}

		fn notify_payment_path_successful(&self, _path: &[&RouteHop]) {}

		fn notify_payment_probe_successful(&self, _path: &[&RouteHop]) {}

		fn notify_payment_probe_failed(&self, _path: &[&RouteHop], _short_channel_id: u64) {}
	}

	struct TestScorer {
		event_expectations: Option<VecDeque<TestResult>>,
		scorer_expectations: RefCell<Option<VecDeque<ChannelUsage>>>,
	}

	#[derive(Debug)]
	enum TestResult {
		PaymentFailure { path: Vec<RouteHop>, short_channel_id: u64 },
		PaymentSuccess { path: Vec<RouteHop> },
	}

	impl TestScorer {
		fn new() -> Self {
			Self {
				event_expectations: None,
				scorer_expectations: RefCell::new(None),
			}
		}

		fn expect(mut self, expectation: TestResult) -> Self {
			self.event_expectations.get_or_insert_with(|| VecDeque::new()).push_back(expectation);
			self
		}

		fn expect_usage(self, expectation: ChannelUsage) -> Self {
			self.scorer_expectations.borrow_mut().get_or_insert_with(|| VecDeque::new()).push_back(expectation);
			self
		}
	}

	#[cfg(c_bindings)]
	impl lightning::util::ser::Writeable for TestScorer {
		fn write<W: lightning::util::ser::Writer>(&self, _: &mut W) -> Result<(), lightning::io::Error> { unreachable!(); }
	}

	impl Score for TestScorer {
		fn channel_penalty_msat(
			&self, _short_channel_id: u64, _source: &NodeId, _target: &NodeId, usage: ChannelUsage
		) -> u64 {
			if let Some(scorer_expectations) = self.scorer_expectations.borrow_mut().as_mut() {
				match scorer_expectations.pop_front() {
					Some(expectation) => {
						assert_eq!(expectation.amount_msat, usage.amount_msat);
						assert_eq!(expectation.inflight_htlc_msat, usage.inflight_htlc_msat);
					},
					None => {},
				}
			}
			0
		}

		fn payment_path_failed(&mut self, actual_path: &[&RouteHop], actual_short_channel_id: u64) {
			if let Some(expectations) = &mut self.event_expectations {
				match expectations.pop_front() {
					Some(TestResult::PaymentFailure { path, short_channel_id }) => {
						assert_eq!(actual_path, &path.iter().collect::<Vec<_>>()[..]);
						assert_eq!(actual_short_channel_id, short_channel_id);
					},
					Some(TestResult::PaymentSuccess { path }) => {
						panic!("Unexpected successful payment path: {:?}", path)
					},
					None => panic!("Unexpected notify_payment_path_failed call: {:?}", actual_path),
				}
			}
		}

		fn payment_path_successful(&mut self, actual_path: &[&RouteHop]) {
			if let Some(expectations) = &mut self.event_expectations {
				match expectations.pop_front() {
					Some(TestResult::PaymentFailure { path, .. }) => {
						panic!("Unexpected payment path failure: {:?}", path)
					},
					Some(TestResult::PaymentSuccess { path }) => {
						assert_eq!(actual_path, &path.iter().collect::<Vec<_>>()[..]);
					},
					None => panic!("Unexpected notify_payment_path_successful call: {:?}", actual_path),
				}
			}
		}

		fn probe_failed(&mut self, actual_path: &[&RouteHop], _: u64) {
			if let Some(expectations) = &mut self.event_expectations {
				match expectations.pop_front() {
					Some(TestResult::PaymentFailure { path, .. }) => {
						panic!("Unexpected failed payment path: {:?}", path)
					},
					Some(TestResult::PaymentSuccess { path }) => {
						panic!("Unexpected successful payment path: {:?}", path)
					},
					None => panic!("Unexpected notify_payment_path_failed call: {:?}", actual_path),
				}
			}
		}
		fn probe_successful(&mut self, actual_path: &[&RouteHop]) {
			if let Some(expectations) = &mut self.event_expectations {
				match expectations.pop_front() {
					Some(TestResult::PaymentFailure { path, .. }) => {
						panic!("Unexpected payment path failure: {:?}", path)
					},
					Some(TestResult::PaymentSuccess { path }) => {
						panic!("Unexpected successful payment path: {:?}", path)
					},
					None => panic!("Unexpected notify_payment_path_successful call: {:?}", actual_path),
				}
			}
		}
	}

	impl Drop for TestScorer {
		fn drop(&mut self) {
			if std::thread::panicking() {
				return;
			}

			if let Some(event_expectations) = &self.event_expectations {
				if !event_expectations.is_empty() {
					panic!("Unsatisfied event expectations: {:?}", event_expectations);
				}
			}

			if let Some(scorer_expectations) = self.scorer_expectations.borrow().as_ref() {
				if !scorer_expectations.is_empty() {
					panic!("Unsatisfied scorer expectations: {:?}", scorer_expectations)
				}
			}
		}
	}

	struct TestPayer {
		expectations: core::cell::RefCell<VecDeque<Amount>>,
		attempts: core::cell::RefCell<usize>,
		failing_on_attempt: core::cell::RefCell<HashMap<usize, PaymentSendFailure>>,
	}

	#[derive(Clone, Debug, PartialEq, Eq)]
	enum Amount {
		ForInvoice(u64),
		Spontaneous(u64),
		OnRetry(u64),
	}

	struct OnAttempt(usize);

	impl TestPayer {
		fn new() -> Self {
			Self {
				expectations: core::cell::RefCell::new(VecDeque::new()),
				attempts: core::cell::RefCell::new(0),
				failing_on_attempt: core::cell::RefCell::new(HashMap::new()),
			}
		}

		fn expect_send(self, value_msat: Amount) -> Self {
			self.expectations.borrow_mut().push_back(value_msat);
			self
		}

		fn fails_on_attempt(self, attempt: usize) -> Self {
			let failure = PaymentSendFailure::ParameterError(APIError::MonitorUpdateInProgress);
			self.fails_with(failure, OnAttempt(attempt))
		}

		fn fails_with_partial_failure(self, retry: RouteParameters, attempt: OnAttempt, results: Option<Vec<Result<(), APIError>>>) -> Self {
			self.fails_with(PaymentSendFailure::PartialFailure {
				results: results.unwrap_or(vec![]),
				failed_paths_retry: Some(retry),
				payment_id: PaymentId([1; 32]),
			}, attempt)
		}

		fn fails_with(self, failure: PaymentSendFailure, attempt: OnAttempt) -> Self {
			self.failing_on_attempt.borrow_mut().insert(attempt.0, failure);
			self
		}

		fn check_attempts(&self) -> Result<(), PaymentSendFailure> {
			let mut attempts = self.attempts.borrow_mut();
			*attempts += 1;

			match self.failing_on_attempt.borrow_mut().remove(&*attempts) {
				Some(failure) => Err(failure),
				None => Ok(())
			}
		}

		fn check_value_msats(&self, actual_value_msats: Amount) {
			let expected_value_msats = self.expectations.borrow_mut().pop_front();
			if let Some(expected_value_msats) = expected_value_msats {
				assert_eq!(actual_value_msats, expected_value_msats);
			} else {
				panic!("Unexpected amount: {:?}", actual_value_msats);
			}
		}
	}

	impl Drop for TestPayer {
		fn drop(&mut self) {
			if std::thread::panicking() {
				return;
			}

			if !self.expectations.borrow().is_empty() {
				panic!("Unsatisfied payment expectations: {:?}", self.expectations.borrow());
			}
		}
	}

	impl Payer for TestPayer {
		fn node_id(&self) -> PublicKey {
			let secp_ctx = Secp256k1::new();
			PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[42; 32]).unwrap())
		}

		fn first_hops(&self) -> Vec<ChannelDetails> {
			Vec::new()
		}

		fn send_payment(
			&self, route: &Route, _payment_hash: PaymentHash,
			_payment_secret: &Option<PaymentSecret>, _payment_id: PaymentId,
		) -> Result<(), PaymentSendFailure> {
			self.check_value_msats(Amount::ForInvoice(route.get_total_amount()));
			self.check_attempts()
		}

		fn send_spontaneous_payment(
			&self, route: &Route, _payment_preimage: PaymentPreimage, _payment_id: PaymentId,
		) -> Result<(), PaymentSendFailure> {
			self.check_value_msats(Amount::Spontaneous(route.get_total_amount()));
			self.check_attempts()
		}

		fn retry_payment(
			&self, route: &Route, _payment_id: PaymentId
		) -> Result<(), PaymentSendFailure> {
			self.check_value_msats(Amount::OnRetry(route.get_total_amount()));
			self.check_attempts()
		}

		fn abandon_payment(&self, _payment_id: PaymentId) { }
	}

	// *** Full Featured Functional Tests with a Real ChannelManager ***
	struct ManualRouter(RefCell<VecDeque<Result<Route, LightningError>>>);

	impl Router for ManualRouter {
		fn find_route(
			&self, _payer: &PublicKey, _params: &RouteParameters, _payment_hash: &PaymentHash,
			_first_hops: Option<&[&ChannelDetails]>, _inflight_htlcs: InFlightHtlcs
		) -> Result<Route, LightningError> {
			self.0.borrow_mut().pop_front().unwrap()
		}

		fn notify_payment_path_failed(&self, _path: &[&RouteHop], _short_channel_id: u64) {}

		fn notify_payment_path_successful(&self, _path: &[&RouteHop]) {}

		fn notify_payment_probe_successful(&self, _path: &[&RouteHop]) {}

		fn notify_payment_probe_failed(&self, _path: &[&RouteHop], _short_channel_id: u64) {}
	}
	impl ManualRouter {
		fn expect_find_route(&self, result: Result<Route, LightningError>) {
			self.0.borrow_mut().push_back(result);
		}
	}
	impl Drop for ManualRouter {
		fn drop(&mut self) {
			if std::thread::panicking() {
				return;
			}
			assert!(self.0.borrow_mut().is_empty());
		}
	}

	#[test]
	fn retry_multi_path_single_failed_payment() {
		// Tests that we can/will retry after a single path of an MPP payment failed immediately
		let chanmon_cfgs = create_chanmon_cfgs(2);
		let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
		let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None, None]);
		let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

		create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 0, channelmanager::provided_init_features(), channelmanager::provided_init_features());
		create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 0, channelmanager::provided_init_features(), channelmanager::provided_init_features());
		let chans = nodes[0].node.list_usable_channels();
		let mut route = Route {
			paths: vec![
				vec![RouteHop {
					pubkey: nodes[1].node.get_our_node_id(),
					node_features: channelmanager::provided_node_features(),
					short_channel_id: chans[0].short_channel_id.unwrap(),
					channel_features: channelmanager::provided_channel_features(),
					fee_msat: 10_000,
					cltv_expiry_delta: 100,
				}],
				vec![RouteHop {
					pubkey: nodes[1].node.get_our_node_id(),
					node_features: channelmanager::provided_node_features(),
					short_channel_id: chans[1].short_channel_id.unwrap(),
					channel_features: channelmanager::provided_channel_features(),
					fee_msat: 100_000_001, // Our default max-HTLC-value is 10% of the channel value, which this is one more than
					cltv_expiry_delta: 100,
				}],
			],
			payment_params: Some(PaymentParameters::from_node_id(nodes[1].node.get_our_node_id())),
		};
		let router = ManualRouter(RefCell::new(VecDeque::new()));
		router.expect_find_route(Ok(route.clone()));
		// On retry, split the payment across both channels.
		route.paths[0][0].fee_msat = 50_000_001;
		route.paths[1][0].fee_msat = 50_000_000;
		router.expect_find_route(Ok(route.clone()));

		let event_handler = |_: &_| { panic!(); };
		let invoice_payer = InvoicePayer::new(nodes[0].node, router, nodes[0].logger, event_handler, Retry::Attempts(1));

		assert!(invoice_payer.pay_invoice(&create_invoice_from_channelmanager_and_duration_since_epoch(
			&nodes[1].node, nodes[1].keys_manager, nodes[1].logger, Currency::Bitcoin,
			Some(100_010_000), "Invoice".to_string(), duration_since_epoch(), 3600).unwrap())
			.is_ok());
		let htlc_msgs = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(htlc_msgs.len(), 2);
		check_added_monitors!(nodes[0], 2);
	}

	#[test]
	fn immediate_retry_on_failure() {
		// Tests that we can/will retry immediately after a failure
		let chanmon_cfgs = create_chanmon_cfgs(2);
		let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
		let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None, None]);
		let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

		create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 0, channelmanager::provided_init_features(), channelmanager::provided_init_features());
		create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 0, channelmanager::provided_init_features(), channelmanager::provided_init_features());
		let chans = nodes[0].node.list_usable_channels();
		let mut route = Route {
			paths: vec![
				vec![RouteHop {
					pubkey: nodes[1].node.get_our_node_id(),
					node_features: channelmanager::provided_node_features(),
					short_channel_id: chans[0].short_channel_id.unwrap(),
					channel_features: channelmanager::provided_channel_features(),
					fee_msat: 100_000_001, // Our default max-HTLC-value is 10% of the channel value, which this is one more than
					cltv_expiry_delta: 100,
				}],
			],
			payment_params: Some(PaymentParameters::from_node_id(nodes[1].node.get_our_node_id())),
		};
		let router = ManualRouter(RefCell::new(VecDeque::new()));
		router.expect_find_route(Ok(route.clone()));
		// On retry, split the payment across both channels.
		route.paths.push(route.paths[0].clone());
		route.paths[0][0].short_channel_id = chans[1].short_channel_id.unwrap();
		route.paths[0][0].fee_msat = 50_000_000;
		route.paths[1][0].fee_msat = 50_000_001;
		router.expect_find_route(Ok(route.clone()));

		let event_handler = |_: &_| { panic!(); };
		let invoice_payer = InvoicePayer::new(nodes[0].node, router, nodes[0].logger, event_handler, Retry::Attempts(1));

		assert!(invoice_payer.pay_invoice(&create_invoice_from_channelmanager_and_duration_since_epoch(
			&nodes[1].node, nodes[1].keys_manager, nodes[1].logger, Currency::Bitcoin,
			Some(100_010_000), "Invoice".to_string(), duration_since_epoch(), 3600).unwrap())
			.is_ok());
		let htlc_msgs = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(htlc_msgs.len(), 2);
		check_added_monitors!(nodes[0], 2);
	}

	#[test]
	fn no_extra_retries_on_back_to_back_fail() {
		// In a previous release, we had a race where we may exceed the payment retry count if we
		// get two failures in a row with the second having `all_paths_failed` set.
		// Generally, when we give up trying to retry a payment, we don't know for sure what the
		// current state of the ChannelManager event queue is. Specifically, we cannot be sure that
		// there are not multiple additional `PaymentPathFailed` or even `PaymentSent` events
		// pending which we will see later. Thus, when we previously removed the retry tracking map
		// entry after a `all_paths_failed` `PaymentPathFailed` event, we may have dropped the
		// retry entry even though more events for the same payment were still pending. This led to
		// us retrying a payment again even though we'd already given up on it.
		//
		// We now have a separate event - `PaymentFailed` which indicates no HTLCs remain and which
		// is used to remove the payment retry counter entries instead. This tests for the specific
		// excess-retry case while also testing `PaymentFailed` generation.

		let chanmon_cfgs = create_chanmon_cfgs(3);
		let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
		let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
		let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

		let chan_1_scid = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 10_000_000, 0, channelmanager::provided_init_features(), channelmanager::provided_init_features()).0.contents.short_channel_id;
		let chan_2_scid = create_announced_chan_between_nodes_with_value(&nodes, 1, 2, 10_000_000, 0, channelmanager::provided_init_features(), channelmanager::provided_init_features()).0.contents.short_channel_id;

		let mut route = Route {
			paths: vec![
				vec![RouteHop {
					pubkey: nodes[1].node.get_our_node_id(),
					node_features: channelmanager::provided_node_features(),
					short_channel_id: chan_1_scid,
					channel_features: channelmanager::provided_channel_features(),
					fee_msat: 0,
					cltv_expiry_delta: 100,
				}, RouteHop {
					pubkey: nodes[2].node.get_our_node_id(),
					node_features: channelmanager::provided_node_features(),
					short_channel_id: chan_2_scid,
					channel_features: channelmanager::provided_channel_features(),
					fee_msat: 100_000_000,
					cltv_expiry_delta: 100,
				}],
				vec![RouteHop {
					pubkey: nodes[1].node.get_our_node_id(),
					node_features: channelmanager::provided_node_features(),
					short_channel_id: chan_1_scid,
					channel_features: channelmanager::provided_channel_features(),
					fee_msat: 0,
					cltv_expiry_delta: 100,
				}, RouteHop {
					pubkey: nodes[2].node.get_our_node_id(),
					node_features: channelmanager::provided_node_features(),
					short_channel_id: chan_2_scid,
					channel_features: channelmanager::provided_channel_features(),
					fee_msat: 100_000_000,
					cltv_expiry_delta: 100,
				}]
			],
			payment_params: Some(PaymentParameters::from_node_id(nodes[2].node.get_our_node_id())),
		};
		let router = ManualRouter(RefCell::new(VecDeque::new()));
		router.expect_find_route(Ok(route.clone()));
		// On retry, we'll only be asked for one path
		route.paths.remove(1);
		router.expect_find_route(Ok(route.clone()));

		let expected_events: RefCell<VecDeque<&dyn Fn(&Event)>> = RefCell::new(VecDeque::new());
		let event_handler = |event: &Event| {
			let event_checker = expected_events.borrow_mut().pop_front().unwrap();
			event_checker(event);
		};
		let invoice_payer = InvoicePayer::new(nodes[0].node, router, nodes[0].logger, event_handler, Retry::Attempts(1));

		assert!(invoice_payer.pay_invoice(&create_invoice_from_channelmanager_and_duration_since_epoch(
			&nodes[1].node, nodes[1].keys_manager, nodes[1].logger, Currency::Bitcoin,
			Some(100_010_000), "Invoice".to_string(), duration_since_epoch(), 3600).unwrap())
			.is_ok());
		let htlc_updates = SendEvent::from_node(&nodes[0]);
		check_added_monitors!(nodes[0], 1);
		assert_eq!(htlc_updates.msgs.len(), 1);

		nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &htlc_updates.msgs[0]);
		nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &htlc_updates.commitment_msg);
		check_added_monitors!(nodes[1], 1);
		let (bs_first_raa, bs_first_cs) = get_revoke_commit_msgs!(nodes[1], nodes[0].node.get_our_node_id());

		nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_first_raa);
		check_added_monitors!(nodes[0], 1);
		let second_htlc_updates = SendEvent::from_node(&nodes[0]);

		nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &bs_first_cs);
		check_added_monitors!(nodes[0], 1);
		let as_first_raa = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());

		nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &second_htlc_updates.msgs[0]);
		nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &second_htlc_updates.commitment_msg);
		check_added_monitors!(nodes[1], 1);
		let bs_second_raa = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[0].node.get_our_node_id());

		nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_first_raa);
		check_added_monitors!(nodes[1], 1);
		let bs_fail_update = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());

		nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_second_raa);
		check_added_monitors!(nodes[0], 1);

		nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &bs_fail_update.update_fail_htlcs[0]);
		nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &bs_fail_update.commitment_signed);
		check_added_monitors!(nodes[0], 1);
		let (as_second_raa, as_third_cs) = get_revoke_commit_msgs!(nodes[0], nodes[1].node.get_our_node_id());

		nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_second_raa);
		check_added_monitors!(nodes[1], 1);
		let bs_second_fail_update = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());

		nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &as_third_cs);
		check_added_monitors!(nodes[1], 1);
		let bs_third_raa = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[0].node.get_our_node_id());

		nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &bs_second_fail_update.update_fail_htlcs[0]);
		nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &bs_second_fail_update.commitment_signed);
		check_added_monitors!(nodes[0], 1);

		nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_third_raa);
		check_added_monitors!(nodes[0], 1);
		let (as_third_raa, as_fourth_cs) = get_revoke_commit_msgs!(nodes[0], nodes[1].node.get_our_node_id());

		nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_third_raa);
		check_added_monitors!(nodes[1], 1);
		nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &as_fourth_cs);
		check_added_monitors!(nodes[1], 1);
		let bs_fourth_raa = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[0].node.get_our_node_id());

		nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_fourth_raa);
		check_added_monitors!(nodes[0], 1);

		// At this point A has sent two HTLCs which both failed due to lack of fee. It now has two
		// pending `PaymentPathFailed` events, one with `all_paths_failed` unset, and the second
		// with it set. The first event will use up the only retry we are allowed, with the second
		// `PaymentPathFailed` being passed up to the user (us, in this case). Previously, we'd
		// treated this as "HTLC complete" and dropped the retry counter, causing us to retry again
		// if the final HTLC failed.
		expected_events.borrow_mut().push_back(&|ev: &Event| {
			if let Event::PaymentPathFailed { payment_failed_permanently, all_paths_failed, .. } = ev {
				assert!(!payment_failed_permanently);
				assert!(all_paths_failed);
			} else { panic!("Unexpected event"); }
		});
		nodes[0].node.process_pending_events(&invoice_payer);
		assert!(expected_events.borrow().is_empty());

		let retry_htlc_updates = SendEvent::from_node(&nodes[0]);
		check_added_monitors!(nodes[0], 1);

		nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &retry_htlc_updates.msgs[0]);
		commitment_signed_dance!(nodes[1], nodes[0], &retry_htlc_updates.commitment_msg, false, true);
		let bs_fail_update = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
		nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &bs_fail_update.update_fail_htlcs[0]);
		commitment_signed_dance!(nodes[0], nodes[1], &bs_fail_update.commitment_signed, false, true);

		expected_events.borrow_mut().push_back(&|ev: &Event| {
			if let Event::PaymentPathFailed { payment_failed_permanently, all_paths_failed, .. } = ev {
				assert!(!payment_failed_permanently);
				assert!(all_paths_failed);
			} else { panic!("Unexpected event"); }
		});
		expected_events.borrow_mut().push_back(&|ev: &Event| {
			if let Event::PaymentFailed { .. } = ev {
			} else { panic!("Unexpected event"); }
		});
		nodes[0].node.process_pending_events(&invoice_payer);
		assert!(expected_events.borrow().is_empty());
	}
}
