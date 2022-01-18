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
//! [`InvoicePayer`] is parameterized by a [`LockableScore`], which it uses for scoring failed and
//! successful payment paths upon receiving [`Event::PaymentPathFailed`] and
//! [`Event::PaymentPathSuccessful`] events, respectively.
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
//! # #[cfg(feature = "no-std")]
//! # extern crate core2;
//! #
//! # use lightning::ln::{PaymentHash, PaymentPreimage, PaymentSecret};
//! # use lightning::ln::channelmanager::{ChannelDetails, PaymentId, PaymentSendFailure};
//! # use lightning::ln::msgs::LightningError;
//! # use lightning::routing::scoring::Score;
//! # use lightning::routing::network_graph::NodeId;
//! # use lightning::routing::router::{Route, RouteHop, RouteParameters};
//! # use lightning::util::events::{Event, EventHandler, EventsProvider};
//! # use lightning::util::logger::{Logger, Record};
//! # use lightning::util::ser::{Writeable, Writer};
//! # use lightning_invoice::Invoice;
//! # use lightning_invoice::payment::{InvoicePayer, Payer, RetryAttempts, Router};
//! # use secp256k1::key::PublicKey;
//! # use std::cell::RefCell;
//! # use std::ops::Deref;
//! #
//! # #[cfg(not(feature = "std"))]
//! # use core2::io;
//! # #[cfg(feature = "std")]
//! # use std::io;
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
//! #         &self, route: &Route, payment_hash: PaymentHash, payment_secret: &Option<PaymentSecret>
//! #     ) -> Result<PaymentId, PaymentSendFailure> { unimplemented!() }
//! #     fn send_spontaneous_payment(
//! #         &self, route: &Route, payment_preimage: PaymentPreimage
//! #     ) -> Result<PaymentId, PaymentSendFailure> { unimplemented!() }
//! #     fn retry_payment(
//! #         &self, route: &Route, payment_id: PaymentId
//! #     ) -> Result<(), PaymentSendFailure> { unimplemented!() }
//! #     fn abandon_payment(&self, payment_id: PaymentId) { unimplemented!() }
//! # }
//! #
//! # struct FakeRouter {}
//! # impl<S: Score> Router<S> for FakeRouter {
//! #     fn find_route(
//! #         &self, payer: &PublicKey, params: &RouteParameters, payment_hash: &PaymentHash,
//! #         first_hops: Option<&[&ChannelDetails]>, scorer: &S
//! #     ) -> Result<Route, LightningError> { unimplemented!() }
//! # }
//! #
//! # struct FakeScorer {}
//! # impl Writeable for FakeScorer {
//! #     fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> { unimplemented!(); }
//! # }
//! # impl Score for FakeScorer {
//! #     fn channel_penalty_msat(
//! #         &self, _short_channel_id: u64, _send_amt: u64, _chan_amt: Option<u64>, _source: &NodeId, _target: &NodeId
//! #     ) -> u64 { 0 }
//! #     fn payment_path_failed(&mut self, _path: &[&RouteHop], _short_channel_id: u64) {}
//! #     fn payment_path_successful(&mut self, _path: &[&RouteHop]) {}
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
//! let invoice_payer = InvoicePayer::new(&payer, router, &scorer, &logger, event_handler, RetryAttempts(2));
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
use lightning::ln::{PaymentHash, PaymentPreimage, PaymentSecret};
use lightning::ln::channelmanager::{ChannelDetails, PaymentId, PaymentSendFailure};
use lightning::ln::msgs::LightningError;
use lightning::routing::scoring::{LockableScore, Score};
use lightning::routing::router::{Payee, Route, RouteParameters};
use lightning::util::events::{Event, EventHandler};
use lightning::util::logger::Logger;
use crate::sync::Mutex;

use secp256k1::key::PublicKey;

use core::ops::Deref;
use core::time::Duration;
#[cfg(feature = "std")]
use std::time::SystemTime;

/// A utility for paying [`Invoice`]s and sending spontaneous payments.
///
/// See [module-level documentation] for details.
///
/// [module-level documentation]: crate::payment
pub struct InvoicePayer<P: Deref, R, S: Deref, L: Deref, E: EventHandler>
where
	P::Target: Payer,
	R: for <'a> Router<<<S as Deref>::Target as LockableScore<'a>>::Locked>,
	S::Target: for <'a> LockableScore<'a>,
	L::Target: Logger,
{
	payer: P,
	router: R,
	scorer: S,
	logger: L,
	event_handler: E,
	/// Caches the overall attempts at making a payment, which is updated prior to retrying.
	payment_cache: Mutex<HashMap<PaymentHash, usize>>,
	retry_attempts: RetryAttempts,
}

/// A trait defining behavior of an [`Invoice`] payer.
pub trait Payer {
	/// Returns the payer's node id.
	fn node_id(&self) -> PublicKey;

	/// Returns the payer's channels.
	fn first_hops(&self) -> Vec<ChannelDetails>;

	/// Sends a payment over the Lightning Network using the given [`Route`].
	fn send_payment(
		&self, route: &Route, payment_hash: PaymentHash, payment_secret: &Option<PaymentSecret>
	) -> Result<PaymentId, PaymentSendFailure>;

	/// Sends a spontaneous payment over the Lightning Network using the given [`Route`].
	fn send_spontaneous_payment(
		&self, route: &Route, payment_preimage: PaymentPreimage
	) -> Result<PaymentId, PaymentSendFailure>;

	/// Retries a failed payment path for the [`PaymentId`] using the given [`Route`].
	fn retry_payment(&self, route: &Route, payment_id: PaymentId) -> Result<(), PaymentSendFailure>;

	/// Signals that no further retries for the given payment will occur.
	fn abandon_payment(&self, payment_id: PaymentId);
}

/// A trait defining behavior for routing an [`Invoice`] payment.
pub trait Router<S: Score> {
	/// Finds a [`Route`] between `payer` and `payee` for a payment with the given values.
	fn find_route(
		&self, payer: &PublicKey, params: &RouteParameters, payment_hash: &PaymentHash,
		first_hops: Option<&[&ChannelDetails]>, scorer: &S
	) -> Result<Route, LightningError>;
}

/// Number of attempts to retry payment path failures for an [`Invoice`].
///
/// Note that this is the number of *path* failures, not full payment retries. For multi-path
/// payments, if this is less than the total number of paths, we will never even retry all of the
/// payment's paths.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RetryAttempts(pub usize);

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

impl<P: Deref, R, S: Deref, L: Deref, E: EventHandler> InvoicePayer<P, R, S, L, E>
where
	P::Target: Payer,
	R: for <'a> Router<<<S as Deref>::Target as LockableScore<'a>>::Locked>,
	S::Target: for <'a> LockableScore<'a>,
	L::Target: Logger,
{
	/// Creates an invoice payer that retries failed payment paths.
	///
	/// Will forward any [`Event::PaymentPathFailed`] events to the decorated `event_handler` once
	/// `retry_attempts` has been exceeded for a given [`Invoice`].
	pub fn new(
		payer: P, router: R, scorer: S, logger: L, event_handler: E, retry_attempts: RetryAttempts
	) -> Self {
		Self {
			payer,
			router,
			scorer,
			logger,
			event_handler,
			payment_cache: Mutex::new(HashMap::new()),
			retry_attempts,
		}
	}

	/// Pays the given [`Invoice`], caching it for later use in case a retry is needed.
	///
	/// You should ensure that the `invoice.payment_hash()` is unique and the same payment_hash has
	/// never been paid before. Because [`InvoicePayer`] is stateless no effort is made to do so
	/// for you.
	pub fn pay_invoice(&self, invoice: &Invoice) -> Result<PaymentId, PaymentError> {
		if invoice.amount_milli_satoshis().is_none() {
			Err(PaymentError::Invoice("amount missing"))
		} else {
			self.pay_invoice_using_amount(invoice, None)
		}
	}

	/// Pays the given zero-value [`Invoice`] using the given amount, caching it for later use in
	/// case a retry is needed.
	///
	/// You should ensure that the `invoice.payment_hash()` is unique and the same payment_hash has
	/// never been paid before. Because [`InvoicePayer`] is stateless no effort is made to do so
	/// for you.
	pub fn pay_zero_value_invoice(
		&self, invoice: &Invoice, amount_msats: u64
	) -> Result<PaymentId, PaymentError> {
		if invoice.amount_milli_satoshis().is_some() {
			Err(PaymentError::Invoice("amount unexpected"))
		} else {
			self.pay_invoice_using_amount(invoice, Some(amount_msats))
		}
	}

	fn pay_invoice_using_amount(
		&self, invoice: &Invoice, amount_msats: Option<u64>
	) -> Result<PaymentId, PaymentError> {
		debug_assert!(invoice.amount_milli_satoshis().is_some() ^ amount_msats.is_some());

		let payment_hash = PaymentHash(invoice.payment_hash().clone().into_inner());
		match self.payment_cache.lock().unwrap().entry(payment_hash) {
			hash_map::Entry::Occupied(_) => return Err(PaymentError::Invoice("payment pending")),
			hash_map::Entry::Vacant(entry) => entry.insert(0),
		};

		let payment_secret = Some(invoice.payment_secret().clone());
		let mut payee = Payee::from_node_id(invoice.recover_payee_pub_key())
			.with_expiry_time(expiry_time_from_unix_epoch(&invoice).as_secs())
			.with_route_hints(invoice.route_hints());
		if let Some(features) = invoice.features() {
			payee = payee.with_features(features.clone());
		}
		let params = RouteParameters {
			payee,
			final_value_msat: invoice.amount_milli_satoshis().or(amount_msats).unwrap(),
			final_cltv_expiry_delta: invoice.min_final_cltv_expiry() as u32,
		};

		let send_payment = |route: &Route| {
			self.payer.send_payment(route, payment_hash, &payment_secret)
		};
		self.pay_internal(&params, payment_hash, send_payment)
			.map_err(|e| { self.payment_cache.lock().unwrap().remove(&payment_hash); e })
	}

	/// Pays `pubkey` an amount using the hash of the given preimage, caching it for later use in
	/// case a retry is needed.
	///
	/// You should ensure that `payment_preimage` is unique and that its `payment_hash` has never
	/// been paid before. Because [`InvoicePayer`] is stateless no effort is made to do so for you.
	pub fn pay_pubkey(
		&self, pubkey: PublicKey, payment_preimage: PaymentPreimage, amount_msats: u64,
		final_cltv_expiry_delta: u32
	) -> Result<PaymentId, PaymentError> {
		let payment_hash = PaymentHash(Sha256::hash(&payment_preimage.0).into_inner());
		match self.payment_cache.lock().unwrap().entry(payment_hash) {
			hash_map::Entry::Occupied(_) => return Err(PaymentError::Invoice("payment pending")),
			hash_map::Entry::Vacant(entry) => entry.insert(0),
		};

		let params = RouteParameters {
			payee: Payee::for_keysend(pubkey),
			final_value_msat: amount_msats,
			final_cltv_expiry_delta,
		};

		let send_payment = |route: &Route| {
			self.payer.send_spontaneous_payment(route, payment_preimage)
		};
		self.pay_internal(&params, payment_hash, send_payment)
			.map_err(|e| { self.payment_cache.lock().unwrap().remove(&payment_hash); e })
	}

	fn pay_internal<F: FnOnce(&Route) -> Result<PaymentId, PaymentSendFailure> + Copy>(
		&self, params: &RouteParameters, payment_hash: PaymentHash, send_payment: F,
	) -> Result<PaymentId, PaymentError> {
		#[cfg(feature = "std")] {
			if has_expired(params) {
				log_trace!(self.logger, "Invoice expired prior to send for payment {}", log_bytes!(payment_hash.0));
				return Err(PaymentError::Invoice("Invoice expired prior to send"));
			}
		}

		let payer = self.payer.node_id();
		let first_hops = self.payer.first_hops();
		let route = self.router.find_route(
			&payer, params, &payment_hash, Some(&first_hops.iter().collect::<Vec<_>>()),
			&self.scorer.lock()
		).map_err(|e| PaymentError::Routing(e))?;

		match send_payment(&route) {
			Ok(payment_id) => Ok(payment_id),
			Err(e) => match e {
				PaymentSendFailure::ParameterError(_) => Err(e),
				PaymentSendFailure::PathParameterError(_) => Err(e),
				PaymentSendFailure::AllFailedRetrySafe(_) => {
					let mut payment_cache = self.payment_cache.lock().unwrap();
					let retry_count = payment_cache.get_mut(&payment_hash).unwrap();
					if *retry_count >= self.retry_attempts.0 {
						Err(e)
					} else {
						*retry_count += 1;
						core::mem::drop(payment_cache);
						Ok(self.pay_internal(params, payment_hash, send_payment)?)
					}
				},
				PaymentSendFailure::PartialFailure { failed_paths_retry, payment_id, .. } => {
					if let Some(retry_data) = failed_paths_retry {
						// Some paths were sent, even if we failed to send the full MPP value our
						// recipient may misbehave and claim the funds, at which point we have to
						// consider the payment sent, so return `Ok()` here, ignoring any retry
						// errors.
						let _ = self.retry_payment(payment_id, payment_hash, &retry_data, None);
						Ok(payment_id)
					} else {
						// This may happen if we send a payment and some paths fail, but
						// only due to a temporary monitor failure or the like, implying
						// they're really in-flight, but we haven't sent the initial
						// HTLC-Add messages yet.
						Ok(payment_id)
					}
				},
			},
		}.map_err(|e| PaymentError::Sending(e))
	}

	fn retry_payment(&self, payment_id: PaymentId, payment_hash: PaymentHash,
		params: &RouteParameters, avoid_scid: Option<u64>
	) -> Result<(), ()> {
		let max_payment_attempts = self.retry_attempts.0 + 1;
		let attempts = *self.payment_cache.lock().unwrap()
			.entry(payment_hash)
			.and_modify(|attempts| *attempts += 1)
			.or_insert(1);

		if attempts >= max_payment_attempts {
			log_trace!(self.logger, "Payment {} exceeded maximum attempts; not retrying (attempts: {})", log_bytes!(payment_hash.0), attempts);
			return Err(());
		}

		#[cfg(feature = "std")] {
			if has_expired(params) {
				log_trace!(self.logger, "Invoice expired for payment {}; not retrying (attempts: {})", log_bytes!(payment_hash.0), attempts);
				return Err(());
			}
		}

		let payer = self.payer.node_id();
		let first_hops = self.payer.first_hops();
		let route = match self.router.find_route(
			&payer, &params, &payment_hash, Some(&first_hops.iter().collect::<Vec<_>>()), &self.scorer.lock()
		) {
			Ok(r) => r,
			Err(_) => {
				log_trace!(self.logger, "Failed to find a route for payment {}; not retrying (attempts: {})", log_bytes!(payment_hash.0), attempts);
				return Err(());
			}
		};

		if route.paths.iter().any(|path| path.iter().any(|hop| Some(hop.short_channel_id) == avoid_scid)) {
			// While hopefully there is a Scor being used to avoid taking channels which *just*
			// failed, its possible that there is simply no other route. This is common in cases
			// where we're paying a node which is behind some form of LSP - there is a single route
			// hint which we are required to pay through. If that route hint failed (ie the node we
			// are trying to pay is offline), we shouldn't try to pay the node again and again
			// through the same hop.
			log_trace!(self.logger, "Route found for payment {} re-uses just-failed channel {}; not retrying (attempts: {})",
				log_bytes!(payment_hash.0), avoid_scid.unwrap_or(0),attempts);
			return Err(());
		}

		match self.payer.retry_payment(&route, payment_id) {
			Ok(()) => Ok(()),
			Err(PaymentSendFailure::ParameterError(_)) |
			Err(PaymentSendFailure::PathParameterError(_)) => {
				log_trace!(self.logger, "Failed to retry for payment {} due to bogus route/payment data, not retrying.", log_bytes!(payment_hash.0));
				Err(())
			},
			Err(PaymentSendFailure::AllFailedRetrySafe(_)) => {
				self.retry_payment(payment_id, payment_hash, params, avoid_scid)
			},
			Err(PaymentSendFailure::PartialFailure { failed_paths_retry, .. }) => {
				if let Some(retry) = failed_paths_retry {
					// Always return Ok for the same reason as noted in pay_internal.
					let _ = self.retry_payment(payment_id, payment_hash, &retry, avoid_scid);
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
}

fn expiry_time_from_unix_epoch(invoice: &Invoice) -> Duration {
	invoice.signed_invoice.raw_invoice.data.timestamp.0 + invoice.expiry_time()
}

#[cfg(feature = "std")]
fn has_expired(params: &RouteParameters) -> bool {
	if let Some(expiry_time) = params.payee.expiry_time {
		Invoice::is_expired_from_epoch(&SystemTime::UNIX_EPOCH, Duration::from_secs(expiry_time))
	} else { false }
}

impl<P: Deref, R, S: Deref, L: Deref, E: EventHandler> EventHandler for InvoicePayer<P, R, S, L, E>
where
	P::Target: Payer,
	R: for <'a> Router<<<S as Deref>::Target as LockableScore<'a>>::Locked>,
	S::Target: for <'a> LockableScore<'a>,
	L::Target: Logger,
{
	fn handle_event(&self, event: &Event) {
		match event {
			Event::PaymentPathFailed {
				payment_id, payment_hash, rejected_by_dest, path, short_channel_id, retry, ..
			} => {
				if let Some(short_channel_id) = short_channel_id {
					let path = path.iter().collect::<Vec<_>>();
					self.scorer.lock().payment_path_failed(&path, *short_channel_id);
				}

				if payment_id.is_none() {
					log_trace!(self.logger, "Payment {} has no id; not retrying", log_bytes!(payment_hash.0));
				} else if *rejected_by_dest {
					log_trace!(self.logger, "Payment {} rejected by destination; not retrying", log_bytes!(payment_hash.0));
					self.payer.abandon_payment(payment_id.unwrap());
				} else if retry.is_none() {
					log_trace!(self.logger, "Payment {} missing retry params; not retrying", log_bytes!(payment_hash.0));
					self.payer.abandon_payment(payment_id.unwrap());
				} else if self.retry_payment(payment_id.unwrap(), *payment_hash, retry.as_ref().unwrap(), *short_channel_id).is_ok() {
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
				self.scorer.lock().payment_path_successful(&path);
			},
			Event::PaymentSent { payment_hash, .. } => {
				let mut payment_cache = self.payment_cache.lock().unwrap();
				let attempts = payment_cache
					.remove(payment_hash)
					.map_or(1, |attempts| attempts + 1);
				log_trace!(self.logger, "Payment {} succeeded (attempts: {})", log_bytes!(payment_hash.0), attempts);
			},
			_ => {},
		}

		// Delegate to the decorated event handler unless the payment is retried.
		self.event_handler.handle_event(event)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::{InvoiceBuilder, Currency};
	use utils::create_invoice_from_channelmanager_and_duration_since_epoch;
	use bitcoin_hashes::sha256::Hash as Sha256;
	use lightning::ln::PaymentPreimage;
	use lightning::ln::features::{ChannelFeatures, NodeFeatures, InitFeatures};
	use lightning::ln::functional_test_utils::*;
	use lightning::ln::msgs::{ChannelMessageHandler, ErrorAction, LightningError};
	use lightning::routing::network_graph::NodeId;
	use lightning::routing::router::{Payee, Route, RouteHop};
	use lightning::util::test_utils::TestLogger;
	use lightning::util::errors::APIError;
	use lightning::util::events::{Event, EventsProvider, MessageSendEvent, MessageSendEventsProvider};
	use secp256k1::{SecretKey, PublicKey, Secp256k1};
	use std::cell::RefCell;
	use std::collections::VecDeque;
	use std::time::{SystemTime, Duration};
	use DEFAULT_EXPIRY_TIME;

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
				Secp256k1::new().sign_recoverable(hash, &private_key)
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
				Secp256k1::new().sign_recoverable(hash, &private_key)
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
				Secp256k1::new().sign_recoverable(hash, &private_key)
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
		let router = TestRouter {};
		let scorer = RefCell::new(TestScorer::new());
		let logger = TestLogger::new();
		let invoice_payer =
			InvoicePayer::new(&payer, router, &scorer, &logger, event_handler, RetryAttempts(0));

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
		let router = TestRouter {};
		let scorer = RefCell::new(TestScorer::new());
		let logger = TestLogger::new();
		let invoice_payer =
			InvoicePayer::new(&payer, router, &scorer, &logger, event_handler, RetryAttempts(2));

		let payment_id = Some(invoice_payer.pay_invoice(&invoice).unwrap());
		assert_eq!(*payer.attempts.borrow(), 1);

		let event = Event::PaymentPathFailed {
			payment_id,
			payment_hash,
			network_update: None,
			rejected_by_dest: false,
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
			.fails_with_partial_failure(retry.clone(), OnAttempt(1))
			.fails_with_partial_failure(retry, OnAttempt(2))
			.expect_send(Amount::ForInvoice(final_value_msat))
			.expect_send(Amount::OnRetry(final_value_msat / 2))
			.expect_send(Amount::OnRetry(final_value_msat / 2));
		let router = TestRouter {};
		let scorer = RefCell::new(TestScorer::new());
		let logger = TestLogger::new();
		let invoice_payer =
			InvoicePayer::new(&payer, router, &scorer, &logger, event_handler, RetryAttempts(2));

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
		let router = TestRouter {};
		let scorer = RefCell::new(TestScorer::new());
		let logger = TestLogger::new();
		let invoice_payer =
			InvoicePayer::new(&payer, router, &scorer, &logger, event_handler, RetryAttempts(2));

		let payment_id = Some(PaymentId([1; 32]));
		let event = Event::PaymentPathFailed {
			payment_id,
			payment_hash,
			network_update: None,
			rejected_by_dest: false,
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
	fn fails_paying_invoice_after_max_retries() {
		let event_handled = core::cell::RefCell::new(false);
		let event_handler = |_: &_| { *event_handled.borrow_mut() = true; };

		let payment_preimage = PaymentPreimage([1; 32]);
		let invoice = invoice(payment_preimage);
		let final_value_msat = invoice.amount_milli_satoshis().unwrap();

		let payer = TestPayer::new()
			.expect_send(Amount::ForInvoice(final_value_msat))
			.expect_send(Amount::OnRetry(final_value_msat / 2))
			.expect_send(Amount::OnRetry(final_value_msat / 2));
		let router = TestRouter {};
		let scorer = RefCell::new(TestScorer::new());
		let logger = TestLogger::new();
		let invoice_payer =
			InvoicePayer::new(&payer, router, &scorer, &logger, event_handler, RetryAttempts(2));

		let payment_id = Some(invoice_payer.pay_invoice(&invoice).unwrap());
		assert_eq!(*payer.attempts.borrow(), 1);

		let event = Event::PaymentPathFailed {
			payment_id,
			payment_hash: PaymentHash(invoice.payment_hash().clone().into_inner()),
			network_update: None,
			rejected_by_dest: false,
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
			rejected_by_dest: false,
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

	#[test]
	fn fails_paying_invoice_with_missing_retry_params() {
		let event_handled = core::cell::RefCell::new(false);
		let event_handler = |_: &_| { *event_handled.borrow_mut() = true; };

		let payment_preimage = PaymentPreimage([1; 32]);
		let invoice = invoice(payment_preimage);
		let final_value_msat = invoice.amount_milli_satoshis().unwrap();

		let payer = TestPayer::new().expect_send(Amount::ForInvoice(final_value_msat));
		let router = TestRouter {};
		let scorer = RefCell::new(TestScorer::new());
		let logger = TestLogger::new();
		let invoice_payer =
			InvoicePayer::new(&payer, router, &scorer, &logger, event_handler, RetryAttempts(2));

		let payment_id = Some(invoice_payer.pay_invoice(&invoice).unwrap());
		assert_eq!(*payer.attempts.borrow(), 1);

		let event = Event::PaymentPathFailed {
			payment_id,
			payment_hash: PaymentHash(invoice.payment_hash().clone().into_inner()),
			network_update: None,
			rejected_by_dest: false,
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
		let router = TestRouter {};
		let scorer = RefCell::new(TestScorer::new());
		let logger = TestLogger::new();
		let invoice_payer =
			InvoicePayer::new(&payer, router, &scorer, &logger, event_handler, RetryAttempts(2));

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
		let router = TestRouter {};
		let scorer = RefCell::new(TestScorer::new());
		let logger = TestLogger::new();
		let invoice_payer =
			InvoicePayer::new(&payer, router, &scorer, &logger, event_handler, RetryAttempts(2));

		let payment_id = Some(invoice_payer.pay_invoice(&invoice).unwrap());
		assert_eq!(*payer.attempts.borrow(), 1);

		let mut retry_data = TestRouter::retry_for_invoice(&invoice);
		retry_data.payee.expiry_time = Some(SystemTime::now()
			.checked_sub(Duration::from_secs(2)).unwrap()
			.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs());
		let event = Event::PaymentPathFailed {
			payment_id,
			payment_hash: PaymentHash(invoice.payment_hash().clone().into_inner()),
			network_update: None,
			rejected_by_dest: false,
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
		let router = TestRouter {};
		let scorer = RefCell::new(TestScorer::new());
		let logger = TestLogger::new();
		let invoice_payer =
			InvoicePayer::new(&payer, router, &scorer, &logger, event_handler, RetryAttempts(2));

		let payment_id = Some(invoice_payer.pay_invoice(&invoice).unwrap());
		assert_eq!(*payer.attempts.borrow(), 1);

		let event = Event::PaymentPathFailed {
			payment_id,
			payment_hash: PaymentHash(invoice.payment_hash().clone().into_inner()),
			network_update: None,
			rejected_by_dest: false,
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
		let router = TestRouter {};
		let scorer = RefCell::new(TestScorer::new());
		let logger = TestLogger::new();
		let invoice_payer =
			InvoicePayer::new(&payer, router, &scorer, &logger, event_handler, RetryAttempts(2));

		let payment_id = Some(invoice_payer.pay_invoice(&invoice).unwrap());
		assert_eq!(*payer.attempts.borrow(), 1);

		let event = Event::PaymentPathFailed {
			payment_id,
			payment_hash: PaymentHash(invoice.payment_hash().clone().into_inner()),
			network_update: None,
			rejected_by_dest: true,
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
	fn fails_paying_invoice_after_rejected_at_only_last_hop() {
		let event_handled = core::cell::RefCell::new(false);
		let event_handler = |_: &_| { *event_handled.borrow_mut() = true; };

		let payment_preimage = PaymentPreimage([1; 32]);
		let invoice = invoice(payment_preimage);
		let final_value_msat = invoice.amount_milli_satoshis().unwrap();

		let payer = TestPayer::new().expect_send(Amount::ForInvoice(final_value_msat));
		let router = TestRouter {};
		let scorer = RefCell::new(TestScorer::new());
		let logger = TestLogger::new();
		let invoice_payer =
			InvoicePayer::new(&payer, router, &scorer, &logger, event_handler, RetryAttempts(2));

		let payment_id = Some(invoice_payer.pay_invoice(&invoice).unwrap());
		assert_eq!(*payer.attempts.borrow(), 1);

		let event = Event::PaymentPathFailed {
			payment_id,
			payment_hash: PaymentHash(invoice.payment_hash().clone().into_inner()),
			network_update: None,
			rejected_by_dest: false,
			all_paths_failed: false,
			path: vec![],
			short_channel_id: Some(1),
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
		let router = TestRouter {};
		let scorer = RefCell::new(TestScorer::new());
		let logger = TestLogger::new();
		let invoice_payer =
			InvoicePayer::new(&payer, router, &scorer, &logger, event_handler, RetryAttempts(0));

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
			rejected_by_dest: false,
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
		let scorer = RefCell::new(TestScorer::new());
		let logger = TestLogger::new();
		let invoice_payer =
			InvoicePayer::new(&payer, router, &scorer, &logger, |_: &_| {}, RetryAttempts(0));

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
		let router = TestRouter {};
		let scorer = RefCell::new(TestScorer::new());
		let logger = TestLogger::new();
		let invoice_payer =
			InvoicePayer::new(&payer, router, &scorer, &logger, |_: &_| {}, RetryAttempts(0));

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
		let router = TestRouter {};
		let scorer = RefCell::new(TestScorer::new());
		let logger = TestLogger::new();
		let invoice_payer =
			InvoicePayer::new(&payer, router, &scorer, &logger, event_handler, RetryAttempts(0));

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
		let router = TestRouter {};
		let scorer = RefCell::new(TestScorer::new());
		let logger = TestLogger::new();
		let invoice_payer =
			InvoicePayer::new(&payer, router, &scorer, &logger, event_handler, RetryAttempts(0));

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
		let router = TestRouter {};
		let scorer = RefCell::new(TestScorer::new());
		let logger = TestLogger::new();
		let invoice_payer =
			InvoicePayer::new(&payer, router, &scorer, &logger, event_handler, RetryAttempts(2));

		let payment_id = Some(invoice_payer.pay_pubkey(
				pubkey, payment_preimage, final_value_msat, final_cltv_expiry_delta
			).unwrap());
		assert_eq!(*payer.attempts.borrow(), 1);

		let retry = RouteParameters {
			payee: Payee::for_keysend(pubkey),
			final_value_msat,
			final_cltv_expiry_delta,
		};
		let event = Event::PaymentPathFailed {
			payment_id,
			payment_hash,
			network_update: None,
			rejected_by_dest: false,
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
			.expect_send(Amount::ForInvoice(final_value_msat));
		let router = TestRouter {};
		let scorer = RefCell::new(TestScorer::new().expect(PaymentPath::Failure {
			path: path.clone(), short_channel_id: path[0].short_channel_id,
		}));
		let logger = TestLogger::new();
		let invoice_payer =
			InvoicePayer::new(&payer, router, &scorer, &logger, event_handler, RetryAttempts(2));

		let payment_id = Some(invoice_payer.pay_invoice(&invoice).unwrap());
		let event = Event::PaymentPathFailed {
			payment_id,
			payment_hash,
			network_update: None,
			rejected_by_dest: false,
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
		let router = TestRouter {};
		let scorer = RefCell::new(TestScorer::new()
			.expect(PaymentPath::Success { path: route.paths[0].clone() })
			.expect(PaymentPath::Success { path: route.paths[1].clone() })
		);
		let logger = TestLogger::new();
		let invoice_payer =
			InvoicePayer::new(&payer, router, &scorer, &logger, event_handler, RetryAttempts(2));

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

	struct TestRouter;

	impl TestRouter {
		fn route_for_value(final_value_msat: u64) -> Route {
			Route {
				paths: vec![
					vec![RouteHop {
						pubkey: PublicKey::from_slice(&hex::decode("02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619").unwrap()[..]).unwrap(),
						channel_features: ChannelFeatures::empty(),
						node_features: NodeFeatures::empty(),
						short_channel_id: 0, fee_msat: final_value_msat / 2, cltv_expiry_delta: 144
					}],
					vec![RouteHop {
						pubkey: PublicKey::from_slice(&hex::decode("0324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c").unwrap()[..]).unwrap(),
						channel_features: ChannelFeatures::empty(),
						node_features: NodeFeatures::empty(),
						short_channel_id: 1, fee_msat: final_value_msat / 2, cltv_expiry_delta: 144
					}],
				],
				payee: None,
			}
		}

		fn path_for_value(final_value_msat: u64) -> Vec<RouteHop> {
			TestRouter::route_for_value(final_value_msat).paths[0].clone()
		}

		fn retry_for_invoice(invoice: &Invoice) -> RouteParameters {
			let mut payee = Payee::from_node_id(invoice.recover_payee_pub_key())
				.with_expiry_time(expiry_time_from_unix_epoch(invoice).as_secs())
				.with_route_hints(invoice.route_hints());
			if let Some(features) = invoice.features() {
				payee = payee.with_features(features.clone());
			}
			let final_value_msat = invoice.amount_milli_satoshis().unwrap() / 2;
			RouteParameters {
				payee,
				final_value_msat,
				final_cltv_expiry_delta: invoice.min_final_cltv_expiry() as u32,
			}
		}
	}

	impl<S: Score> Router<S> for TestRouter {
		fn find_route(
			&self, _payer: &PublicKey, params: &RouteParameters, _payment_hash: &PaymentHash,
			_first_hops: Option<&[&ChannelDetails]>, _scorer: &S
		) -> Result<Route, LightningError> {
			Ok(Route {
				payee: Some(params.payee.clone()), ..Self::route_for_value(params.final_value_msat)
			})
		}
	}

	struct FailingRouter;

	impl<S: Score> Router<S> for FailingRouter {
		fn find_route(
			&self, _payer: &PublicKey, _params: &RouteParameters, _payment_hash: &PaymentHash,
			_first_hops: Option<&[&ChannelDetails]>, _scorer: &S
		) -> Result<Route, LightningError> {
			Err(LightningError { err: String::new(), action: ErrorAction::IgnoreError })
		}
	}

	struct TestScorer {
		expectations: Option<VecDeque<PaymentPath>>,
	}

	#[derive(Debug)]
	enum PaymentPath {
		Failure { path: Vec<RouteHop>, short_channel_id: u64 },
		Success { path: Vec<RouteHop> },
	}

	impl TestScorer {
		fn new() -> Self {
			Self {
				expectations: None,
			}
		}

		fn expect(mut self, expectation: PaymentPath) -> Self {
			self.expectations.get_or_insert_with(|| VecDeque::new()).push_back(expectation);
			self
		}
	}

	#[cfg(c_bindings)]
	impl lightning::util::ser::Writeable for TestScorer {
		fn write<W: lightning::util::ser::Writer>(&self, _: &mut W) -> Result<(), std::io::Error> { unreachable!(); }
	}

	impl Score for TestScorer {
		fn channel_penalty_msat(
			&self, _short_channel_id: u64, _send_amt: u64, _chan_amt: Option<u64>, _source: &NodeId, _target: &NodeId
		) -> u64 { 0 }

		fn payment_path_failed(&mut self, actual_path: &[&RouteHop], actual_short_channel_id: u64) {
			if let Some(expectations) = &mut self.expectations {
				match expectations.pop_front() {
					Some(PaymentPath::Failure { path, short_channel_id }) => {
						assert_eq!(actual_path, &path.iter().collect::<Vec<_>>()[..]);
						assert_eq!(actual_short_channel_id, short_channel_id);
					},
					Some(PaymentPath::Success { path }) => {
						panic!("Unexpected successful payment path: {:?}", path)
					},
					None => panic!("Unexpected payment_path_failed call: {:?}", actual_path),
				}
			}
		}

		fn payment_path_successful(&mut self, actual_path: &[&RouteHop]) {
			if let Some(expectations) = &mut self.expectations {
				match expectations.pop_front() {
					Some(PaymentPath::Failure { path, .. }) => {
						panic!("Unexpected payment path failure: {:?}", path)
					},
					Some(PaymentPath::Success { path }) => {
						assert_eq!(actual_path, &path.iter().collect::<Vec<_>>()[..]);
					},
					None => panic!("Unexpected payment_path_successful call: {:?}", actual_path),
				}
			}
		}
	}

	impl Drop for TestScorer {
		fn drop(&mut self) {
			if std::thread::panicking() {
				return;
			}

			if let Some(expectations) = &self.expectations {
				if !expectations.is_empty() {
					panic!("Unsatisfied scorer expectations: {:?}", expectations);
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
			let failure = PaymentSendFailure::ParameterError(APIError::MonitorUpdateFailed);
			self.fails_with(failure, OnAttempt(attempt))
		}

		fn fails_with_partial_failure(self, retry: RouteParameters, attempt: OnAttempt) -> Self {
			self.fails_with(PaymentSendFailure::PartialFailure {
				results: vec![],
				failed_paths_retry: Some(retry),
				payment_id: PaymentId([1; 32]),
			}, attempt)
		}

		fn fails_with(self, failure: PaymentSendFailure, attempt: OnAttempt) -> Self {
			self.failing_on_attempt.borrow_mut().insert(attempt.0, failure);
			self
		}

		fn check_attempts(&self) -> Result<PaymentId, PaymentSendFailure> {
			let mut attempts = self.attempts.borrow_mut();
			*attempts += 1;

			match self.failing_on_attempt.borrow_mut().remove(&*attempts) {
				Some(failure) => Err(failure),
				None => Ok(PaymentId([1; 32])),
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
			_payment_secret: &Option<PaymentSecret>
		) -> Result<PaymentId, PaymentSendFailure> {
			self.check_value_msats(Amount::ForInvoice(route.get_total_amount()));
			self.check_attempts()
		}

		fn send_spontaneous_payment(
			&self, route: &Route, _payment_preimage: PaymentPreimage,
		) -> Result<PaymentId, PaymentSendFailure> {
			self.check_value_msats(Amount::Spontaneous(route.get_total_amount()));
			self.check_attempts()
		}

		fn retry_payment(
			&self, route: &Route, _payment_id: PaymentId
		) -> Result<(), PaymentSendFailure> {
			self.check_value_msats(Amount::OnRetry(route.get_total_amount()));
			self.check_attempts().map(|_| ())
		}

		fn abandon_payment(&self, _payment_id: PaymentId) { }
	}

	// *** Full Featured Functional Tests with a Real ChannelManager ***
	struct ManualRouter(RefCell<VecDeque<Result<Route, LightningError>>>);

	impl<S: Score> Router<S> for ManualRouter {
		fn find_route(
			&self, _payer: &PublicKey, _params: &RouteParameters, _payment_hash: &PaymentHash,
			_first_hops: Option<&[&ChannelDetails]>, _scorer: &S
		) -> Result<Route, LightningError> {
			self.0.borrow_mut().pop_front().unwrap()
		}
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

		create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 0, InitFeatures::known(), InitFeatures::known());
		create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 0, InitFeatures::known(), InitFeatures::known());
		let chans = nodes[0].node.list_usable_channels();
		let mut route = Route {
			paths: vec![
				vec![RouteHop {
					pubkey: nodes[1].node.get_our_node_id(),
					node_features: NodeFeatures::known(),
					short_channel_id: chans[0].short_channel_id.unwrap(),
					channel_features: ChannelFeatures::known(),
					fee_msat: 10_000,
					cltv_expiry_delta: 100,
				}],
				vec![RouteHop {
					pubkey: nodes[1].node.get_our_node_id(),
					node_features: NodeFeatures::known(),
					short_channel_id: chans[1].short_channel_id.unwrap(),
					channel_features: ChannelFeatures::known(),
					fee_msat: 100_000_001, // Our default max-HTLC-value is 10% of the channel value, which this is one more than
					cltv_expiry_delta: 100,
				}],
			],
			payee: Some(Payee::from_node_id(nodes[1].node.get_our_node_id())),
		};
		let router = ManualRouter(RefCell::new(VecDeque::new()));
		router.expect_find_route(Ok(route.clone()));
		// On retry, split the payment across both channels.
		route.paths[0][0].fee_msat = 50_000_001;
		route.paths[1][0].fee_msat = 50_000_000;
		router.expect_find_route(Ok(route.clone()));

		let event_handler = |_: &_| { panic!(); };
		let scorer = RefCell::new(TestScorer::new());
		let invoice_payer = InvoicePayer::new(nodes[0].node, router, &scorer, nodes[0].logger, event_handler, RetryAttempts(1));

		assert!(invoice_payer.pay_invoice(&create_invoice_from_channelmanager_and_duration_since_epoch(
			&nodes[1].node, nodes[1].keys_manager, Currency::Bitcoin, Some(100_010_000), "Invoice".to_string(),
			duration_since_epoch()).unwrap())
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

		create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 0, InitFeatures::known(), InitFeatures::known());
		create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 0, InitFeatures::known(), InitFeatures::known());
		let chans = nodes[0].node.list_usable_channels();
		let mut route = Route {
			paths: vec![
				vec![RouteHop {
					pubkey: nodes[1].node.get_our_node_id(),
					node_features: NodeFeatures::known(),
					short_channel_id: chans[0].short_channel_id.unwrap(),
					channel_features: ChannelFeatures::known(),
					fee_msat: 100_000_001, // Our default max-HTLC-value is 10% of the channel value, which this is one more than
					cltv_expiry_delta: 100,
				}],
			],
			payee: Some(Payee::from_node_id(nodes[1].node.get_our_node_id())),
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
		let scorer = RefCell::new(TestScorer::new());
		let invoice_payer = InvoicePayer::new(nodes[0].node, router, &scorer, nodes[0].logger, event_handler, RetryAttempts(1));

		assert!(invoice_payer.pay_invoice(&create_invoice_from_channelmanager_and_duration_since_epoch(
			&nodes[1].node, nodes[1].keys_manager, Currency::Bitcoin, Some(100_010_000), "Invoice".to_string(),
			duration_since_epoch()).unwrap())
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

		let chan_1_scid = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 10_000_000, 0, InitFeatures::known(), InitFeatures::known()).0.contents.short_channel_id;
		let chan_2_scid = create_announced_chan_between_nodes_with_value(&nodes, 1, 2, 10_000_000, 0, InitFeatures::known(), InitFeatures::known()).0.contents.short_channel_id;
		let chan_3_scid = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 10_000_000, 0, InitFeatures::known(), InitFeatures::known()).0.contents.short_channel_id;
		let chan_4_scid = create_announced_chan_between_nodes_with_value(&nodes, 1, 2, 10_000_000, 0, InitFeatures::known(), InitFeatures::known()).0.contents.short_channel_id;

		let mut route = Route {
			paths: vec![
				vec![RouteHop {
					pubkey: nodes[1].node.get_our_node_id(),
					node_features: NodeFeatures::known(),
					short_channel_id: chan_1_scid,
					channel_features: ChannelFeatures::known(),
					fee_msat: 0,
					cltv_expiry_delta: 100,
				}, RouteHop {
					pubkey: nodes[2].node.get_our_node_id(),
					node_features: NodeFeatures::known(),
					short_channel_id: chan_2_scid,
					channel_features: ChannelFeatures::known(),
					fee_msat: 100_000_000,
					cltv_expiry_delta: 100,
				}],
				vec![RouteHop {
					pubkey: nodes[1].node.get_our_node_id(),
					node_features: NodeFeatures::known(),
					short_channel_id: chan_1_scid,
					channel_features: ChannelFeatures::known(),
					fee_msat: 0,
					cltv_expiry_delta: 100,
				}, RouteHop {
					pubkey: nodes[2].node.get_our_node_id(),
					node_features: NodeFeatures::known(),
					short_channel_id: chan_2_scid,
					channel_features: ChannelFeatures::known(),
					fee_msat: 100_000_000,
					cltv_expiry_delta: 100,
				}]
			],
			payee: Some(Payee::from_node_id(nodes[2].node.get_our_node_id())),
		};
		let router = ManualRouter(RefCell::new(VecDeque::new()));
		router.expect_find_route(Ok(route.clone()));
		// On retry, we'll only be asked for one path. We also give it a diffferent SCID set as the
		// InvoicePayer will refuse to retry using a just-failed channel.
		route.paths.remove(1);
		route.paths[0][0].short_channel_id = chan_3_scid;
		route.paths[0][1].short_channel_id = chan_4_scid;
		router.expect_find_route(Ok(route.clone()));

		let expected_events: RefCell<VecDeque<&dyn Fn(&Event)>> = RefCell::new(VecDeque::new());
		let event_handler = |event: &Event| {
			let event_checker = expected_events.borrow_mut().pop_front().unwrap();
			event_checker(event);
		};
		let scorer = RefCell::new(TestScorer::new());
		let invoice_payer = InvoicePayer::new(nodes[0].node, router, &scorer, nodes[0].logger, event_handler, RetryAttempts(1));

		assert!(invoice_payer.pay_invoice(&create_invoice_from_channelmanager_and_duration_since_epoch(
			&nodes[1].node, nodes[1].keys_manager, Currency::Bitcoin, Some(100_010_000), "Invoice".to_string(),
			duration_since_epoch()).unwrap())
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
			if let Event::PaymentPathFailed { rejected_by_dest, all_paths_failed, .. } = ev {
				assert!(!rejected_by_dest);
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
			if let Event::PaymentPathFailed { rejected_by_dest, all_paths_failed, .. } = ev {
				assert!(!rejected_by_dest);
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
