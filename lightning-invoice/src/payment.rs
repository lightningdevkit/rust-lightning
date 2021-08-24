// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! A module for paying Lightning invoices.
//!
//! Defines an [`InvoicePayer`] utility for paying invoices, parameterized by [`Payer`] and
//! [`Router`] traits. Implementations of [`Payer`] provide the payer's node id, channels, and means
//! to send a payment over a [`Route`]. Implementations of [`Router`] find a [`Route`] between payer
//! and payee using information provided by the payer and from the payee's [`Invoice`].
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
//! # use lightning::ln::{PaymentHash, PaymentSecret};
//! # use lightning::ln::channelmanager::{ChannelDetails, PaymentId, PaymentSendFailure};
//! # use lightning::ln::msgs::LightningError;
//! # use lightning::routing::router::{Route, RouteParameters};
//! # use lightning::util::events::{Event, EventHandler, EventsProvider};
//! # use lightning::util::logger::{Logger, Record};
//! # use lightning_invoice::Invoice;
//! # use lightning_invoice::payment::{InvoicePayer, Payer, RetryAttempts, Router};
//! # use secp256k1::key::PublicKey;
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
//! #         &self, route: &Route, payment_hash: PaymentHash, payment_secret: &Option<PaymentSecret>
//! #     ) -> Result<PaymentId, PaymentSendFailure> { unimplemented!() }
//! #     fn retry_payment(
//! #         &self, route: &Route, payment_id: PaymentId
//! #     ) -> Result<(), PaymentSendFailure> { unimplemented!() }
//! # }
//! #
//! # struct FakeRouter {};
//! # impl Router for FakeRouter {
//! #     fn find_route(
//! #         &self, payer: &PublicKey, params: &RouteParameters,
//! #         first_hops: Option<&[&ChannelDetails]>
//! #     ) -> Result<Route, LightningError> { unimplemented!() }
//! # }
//! #
//! # struct FakeLogger {};
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
//! # let logger = FakeLogger {};
//! let invoice_payer = InvoicePayer::new(&payer, router, &logger, event_handler, RetryAttempts(2));
//!
//! let invoice = "...";
//! let invoice = invoice.parse::<Invoice>().unwrap();
//! invoice_payer.pay_invoice(&invoice).unwrap();
//!
//! # let event_provider = FakeEventProvider {};
//! loop {
//!     event_provider.process_pending_events(&invoice_payer);
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

use lightning::ln::{PaymentHash, PaymentSecret};
use lightning::ln::channelmanager::{ChannelDetails, PaymentId, PaymentSendFailure};
use lightning::ln::msgs::LightningError;
use lightning::routing::router::{Payee, Route, RouteParameters};
use lightning::util::events::{Event, EventHandler};
use lightning::util::logger::Logger;

use secp256k1::key::PublicKey;

use std::collections::hash_map::{self, HashMap};
use std::ops::Deref;
use std::sync::Mutex;

/// A utility for paying [`Invoice]`s.
pub struct InvoicePayer<P: Deref, R, L: Deref, E>
where
	P::Target: Payer,
	R: Router,
	L::Target: Logger,
	E: EventHandler,
{
	payer: P,
	router: R,
	logger: L,
	event_handler: E,
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

	/// Retries a failed payment path for the [`PaymentId`] using the given [`Route`].
	fn retry_payment(&self, route: &Route, payment_id: PaymentId) -> Result<(), PaymentSendFailure>;
}

/// A trait defining behavior for routing an [`Invoice`] payment.
pub trait Router {
	/// Finds a [`Route`] between `payer` and `payee` for a payment with the given values.
	fn find_route(
		&self, payer: &PublicKey, params: &RouteParameters, first_hops: Option<&[&ChannelDetails]>
	) -> Result<Route, LightningError>;
}

/// Number of attempts to retry payment path failures for an [`Invoice`].
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

impl<P: Deref, R, L: Deref, E> InvoicePayer<P, R, L, E>
where
	P::Target: Payer,
	R: Router,
	L::Target: Logger,
	E: EventHandler,
{
	/// Creates an invoice payer that retries failed payment paths.
	///
	/// Will forward any [`Event::PaymentPathFailed`] events to the decorated `event_handler` once
	/// `retry_attempts` has been exceeded for a given [`Invoice`].
	pub fn new(
		payer: P, router: R, logger: L, event_handler: E, retry_attempts: RetryAttempts
	) -> Self {
		Self {
			payer,
			router,
			logger,
			event_handler,
			payment_cache: Mutex::new(HashMap::new()),
			retry_attempts,
		}
	}

	/// Pays the given [`Invoice`], caching it for later use in case a retry is needed.
	pub fn pay_invoice(&self, invoice: &Invoice) -> Result<PaymentId, PaymentError> {
		let payment_hash = PaymentHash(invoice.payment_hash().clone().into_inner());
		let mut payment_cache = self.payment_cache.lock().unwrap();
		match payment_cache.entry(payment_hash) {
			hash_map::Entry::Vacant(entry) => {
				let payer = self.payer.node_id();
				let mut payee = Payee::new(invoice.recover_payee_pub_key())
					.with_route_hints(invoice.route_hints());
				if let Some(features) = invoice.features() {
					payee = payee.with_features(features.clone());
				}
				let final_value_msat = invoice.amount_milli_satoshis()
					.ok_or(PaymentError::Invoice("amount missing"))?;
				let params = RouteParameters {
					payee,
					final_value_msat,
					final_cltv_expiry_delta: invoice.min_final_cltv_expiry() as u32,
				};
				let first_hops = self.payer.first_hops();
				let route = self.router.find_route(
					&payer,
					&params,
					Some(&first_hops.iter().collect::<Vec<_>>()),
				).map_err(|e| PaymentError::Routing(e))?;

				let payment_hash = PaymentHash(invoice.payment_hash().clone().into_inner());
				let payment_secret = Some(invoice.payment_secret().clone());
				let payment_id = self.payer.send_payment(&route, payment_hash, &payment_secret)
					.map_err(|e| PaymentError::Sending(e))?;
				entry.insert(0);
				Ok(payment_id)
			},
			hash_map::Entry::Occupied(_) => Err(PaymentError::Invoice("payment pending")),
		}
	}

	fn retry_payment(
		&self, payment_id: PaymentId, params: &RouteParameters
	) -> Result<(), PaymentError> {
		let payer = self.payer.node_id();
		let first_hops = self.payer.first_hops();
		let route = self.router.find_route(
			&payer, &params, Some(&first_hops.iter().collect::<Vec<_>>())
		).map_err(|e| PaymentError::Routing(e))?;
		self.payer.retry_payment(&route, payment_id).map_err(|e| PaymentError::Sending(e))
	}

	/// Removes the payment cached by the given payment hash.
	///
	/// Should be called once a payment has failed or succeeded if not using [`InvoicePayer`] as an
	/// [`EventHandler`]. Otherwise, calling this method is unnecessary.
	pub fn remove_cached_payment(&self, payment_hash: &PaymentHash) {
		self.payment_cache.lock().unwrap().remove(payment_hash);
	}
}

impl<P: Deref, R, L: Deref, E> EventHandler for InvoicePayer<P, R, L, E>
where
	P::Target: Payer,
	R: Router,
	L::Target: Logger,
	E: EventHandler,
{
	fn handle_event(&self, event: &Event) {
		match event {
			Event::PaymentPathFailed { payment_id, payment_hash, rejected_by_dest, retry, .. } => {
				let mut payment_cache = self.payment_cache.lock().unwrap();
				let entry = loop {
					let entry = payment_cache.entry(*payment_hash);
					match entry {
						hash_map::Entry::Occupied(_) => break entry,
						hash_map::Entry::Vacant(entry) => entry.insert(0),
					};
				};
				if let hash_map::Entry::Occupied(mut entry) = entry {
					let max_payment_attempts = self.retry_attempts.0 + 1;
					let attempts = entry.get_mut();
					*attempts += 1;

					if *rejected_by_dest {
						log_trace!(self.logger, "Payment {} rejected by destination; not retrying (attempts: {})", log_bytes!(payment_hash.0), attempts);
					} else if payment_id.is_none() {
						log_trace!(self.logger, "Payment {} has no id; not retrying (attempts: {})", log_bytes!(payment_hash.0), attempts);
					} else if *attempts >= max_payment_attempts {
						log_trace!(self.logger, "Payment {} exceeded maximum attempts; not retrying (attempts: {})", log_bytes!(payment_hash.0), attempts);
					} else if retry.is_none() {
						log_trace!(self.logger, "Payment {} missing retry params; not retrying (attempts: {})", log_bytes!(payment_hash.0), attempts);
					} else if self.retry_payment(*payment_id.as_ref().unwrap(), retry.as_ref().unwrap()).is_err() {
						log_trace!(self.logger, "Error retrying payment {}; not retrying (attempts: {})", log_bytes!(payment_hash.0), attempts);
					} else {
						log_trace!(self.logger, "Payment {} failed; retrying (attempts: {})", log_bytes!(payment_hash.0), attempts);
						return;
					}

					// Either the payment was rejected, the maximum attempts were exceeded, or an
					// error occurred when attempting to retry.
					entry.remove();
				} else {
					unreachable!();
				}
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
	use bitcoin_hashes::sha256::Hash as Sha256;
	use lightning::ln::PaymentPreimage;
	use lightning::ln::features::{ChannelFeatures, NodeFeatures};
	use lightning::ln::msgs::{ErrorAction, LightningError};
	use lightning::routing::router::{Route, RouteHop};
	use lightning::util::test_utils::TestLogger;
	use lightning::util::errors::APIError;
	use lightning::util::events::Event;
	use secp256k1::{SecretKey, PublicKey, Secp256k1};

	fn invoice(payment_preimage: PaymentPreimage) -> Invoice {
		let payment_hash = Sha256::hash(&payment_preimage.0);
		let private_key = SecretKey::from_slice(&[42; 32]).unwrap();
		InvoiceBuilder::new(Currency::Bitcoin)
			.description("test".into())
			.payment_hash(payment_hash)
			.payment_secret(PaymentSecret([0; 32]))
			.current_timestamp()
			.min_final_cltv_expiry(144)
			.amount_milli_satoshis(128)
			.build_signed(|hash| {
				Secp256k1::new().sign_recoverable(hash, &private_key)
			})
			.unwrap()
	}

	#[test]
	fn pays_invoice_on_first_attempt() {
		let event_handled = core::cell::RefCell::new(false);
		let event_handler = |_: &_| { *event_handled.borrow_mut() = true; };

		let payment_preimage = PaymentPreimage([1; 32]);
		let invoice = invoice(payment_preimage);
		let payment_hash = PaymentHash(invoice.payment_hash().clone().into_inner());

		let payer = TestPayer::new();
		let router = TestRouter {};
		let logger = TestLogger::new();
		let invoice_payer =
			InvoicePayer::new(&payer, router, &logger, event_handler, RetryAttempts(0));

		let payment_id = Some(invoice_payer.pay_invoice(&invoice).unwrap());
		assert_eq!(*payer.attempts.borrow(), 1);

		invoice_payer.handle_event(&Event::PaymentSent {
			payment_id, payment_preimage, payment_hash
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
			.expect_value_msat(final_value_msat)
			.expect_value_msat(final_value_msat / 2);
		let router = TestRouter {};
		let logger = TestLogger::new();
		let invoice_payer =
			InvoicePayer::new(&payer, router, &logger, event_handler, RetryAttempts(2));

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
			payment_id, payment_preimage, payment_hash
		});
		assert_eq!(*event_handled.borrow(), true);
		assert_eq!(*payer.attempts.borrow(), 2);
	}

	#[test]
	fn retries_payment_path_for_unknown_payment() {
		let event_handled = core::cell::RefCell::new(false);
		let event_handler = |_: &_| { *event_handled.borrow_mut() = true; };

		let payment_preimage = PaymentPreimage([1; 32]);
		let invoice = invoice(payment_preimage);
		let payment_hash = PaymentHash(invoice.payment_hash().clone().into_inner());
		let final_value_msat = invoice.amount_milli_satoshis().unwrap();

		let payer = TestPayer::new();
		let router = TestRouter {};
		let logger = TestLogger::new();
		let invoice_payer =
			InvoicePayer::new(&payer, router, &logger, event_handler, RetryAttempts(2));

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
			payment_id, payment_preimage, payment_hash
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
			.expect_value_msat(final_value_msat)
			.expect_value_msat(final_value_msat / 2)
			.expect_value_msat(final_value_msat / 2);
		let router = TestRouter {};
		let logger = TestLogger::new();
		let invoice_payer =
			InvoicePayer::new(&payer, router, &logger, event_handler, RetryAttempts(2));

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

		let payer = TestPayer::new();
		let router = TestRouter {};
		let logger = TestLogger::new();
		let invoice_payer =
			InvoicePayer::new(&payer, router, &logger, event_handler, RetryAttempts(2));

		let payment_preimage = PaymentPreimage([1; 32]);
		let invoice = invoice(payment_preimage);
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

	#[test]
	fn fails_paying_invoice_after_retry_error() {
		let event_handled = core::cell::RefCell::new(false);
		let event_handler = |_: &_| { *event_handled.borrow_mut() = true; };

		let payment_preimage = PaymentPreimage([1; 32]);
		let invoice = invoice(payment_preimage);
		let final_value_msat = invoice.amount_milli_satoshis().unwrap();

		let payer = TestPayer::new()
			.fails_on_attempt(2)
			.expect_value_msat(final_value_msat);
		let router = TestRouter {};
		let logger = TestLogger::new();
		let invoice_payer =
			InvoicePayer::new(&payer, router, &logger, event_handler, RetryAttempts(2));

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

		let payer = TestPayer::new();
		let router = TestRouter {};
		let logger = TestLogger::new();
		let invoice_payer =
			InvoicePayer::new(&payer, router, &logger, event_handler, RetryAttempts(2));

		let payment_preimage = PaymentPreimage([1; 32]);
		let invoice = invoice(payment_preimage);
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
	fn fails_repaying_invoice_with_pending_payment() {
		let event_handled = core::cell::RefCell::new(false);
		let event_handler = |_: &_| { *event_handled.borrow_mut() = true; };

		let payer = TestPayer::new();
		let router = TestRouter {};
		let logger = TestLogger::new();
		let invoice_payer =
			InvoicePayer::new(&payer, router, &logger, event_handler, RetryAttempts(0));

		let payment_preimage = PaymentPreimage([1; 32]);
		let invoice = invoice(payment_preimage);
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
		let logger = TestLogger::new();
		let invoice_payer =
			InvoicePayer::new(&payer, router, &logger, |_: &_| {}, RetryAttempts(0));

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
		let payer = TestPayer::new().fails_on_attempt(1);
		let router = TestRouter {};
		let logger = TestLogger::new();
		let invoice_payer =
			InvoicePayer::new(&payer, router, &logger, |_: &_| {}, RetryAttempts(0));

		let payment_preimage = PaymentPreimage([1; 32]);
		let invoice = invoice(payment_preimage);
		match invoice_payer.pay_invoice(&invoice) {
			Err(PaymentError::Sending(_)) => {},
			Err(_) => panic!("unexpected error"),
			Ok(_) => panic!("expected sending error"),
		}
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
			let mut payee = Payee::new(invoice.recover_payee_pub_key())
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

	impl Router for TestRouter {
		fn find_route(
			&self,
			_payer: &PublicKey,
			params: &RouteParameters,
			_first_hops: Option<&[&ChannelDetails]>,
		) -> Result<Route, LightningError> {
			Ok(Route {
				payee: Some(params.payee.clone()), ..Self::route_for_value(params.final_value_msat)
			})
		}
	}

	struct FailingRouter;

	impl Router for FailingRouter {
		fn find_route(
			&self,
			_payer: &PublicKey,
			_params: &RouteParameters,
			_first_hops: Option<&[&ChannelDetails]>,
		) -> Result<Route, LightningError> {
			Err(LightningError { err: String::new(), action: ErrorAction::IgnoreError })
		}
	}

	struct TestPayer {
		expectations: core::cell::RefCell<std::collections::VecDeque<u64>>,
		attempts: core::cell::RefCell<usize>,
		failing_on_attempt: Option<usize>,
	}

	impl TestPayer {
		fn new() -> Self {
			Self {
				expectations: core::cell::RefCell::new(std::collections::VecDeque::new()),
				attempts: core::cell::RefCell::new(0),
				failing_on_attempt: None,
			}
		}

		fn expect_value_msat(self, value_msat: u64) -> Self {
			self.expectations.borrow_mut().push_back(value_msat);
			self
		}

		fn fails_on_attempt(self, attempt: usize) -> Self {
			Self {
				expectations: core::cell::RefCell::new(self.expectations.borrow().clone()),
				attempts: core::cell::RefCell::new(0),
				failing_on_attempt: Some(attempt),
			}
		}

		fn check_attempts(&self) -> bool {
			let mut attempts = self.attempts.borrow_mut();
			*attempts += 1;
			match self.failing_on_attempt {
				None => true,
				Some(attempt) if attempt != *attempts => true,
				Some(_) => false,
			}
		}

		fn check_value_msats(&self, route: &Route) {
			let expected_value_msats = self.expectations.borrow_mut().pop_front();
			if let Some(expected_value_msats) = expected_value_msats {
				let actual_value_msats = route.get_total_amount();
				assert_eq!(actual_value_msats, expected_value_msats);
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
			&self,
			route: &Route,
			_payment_hash: PaymentHash,
			_payment_secret: &Option<PaymentSecret>
		) -> Result<PaymentId, PaymentSendFailure> {
			if self.check_attempts() {
				self.check_value_msats(route);
				Ok(PaymentId([1; 32]))
			} else {
				Err(PaymentSendFailure::ParameterError(APIError::MonitorUpdateFailed))
			}
		}

		fn retry_payment(
			&self, route: &Route, _payment_id: PaymentId
		) -> Result<(), PaymentSendFailure> {
			if self.check_attempts() {
				self.check_value_msats(route);
				Ok(())
			} else {
				Err(PaymentSendFailure::ParameterError(APIError::MonitorUpdateFailed))
			}
		}
	}
}
