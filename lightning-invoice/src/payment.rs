// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Convenient utilities for paying Lightning invoices and sending spontaneous payments.

use crate::Invoice;

use bitcoin_hashes::Hash;

use lightning::chain;
use lightning::chain::chaininterface::{BroadcasterInterface, FeeEstimator};
use lightning::chain::keysinterface::{NodeSigner, SignerProvider, EntropySource};
use lightning::ln::{PaymentHash, PaymentSecret};
use lightning::ln::channelmanager::{ChannelManager, PaymentId, Retry, RetryableSendFailure};
use lightning::routing::router::{PaymentParameters, RouteParameters, Router};
use lightning::util::logger::Logger;

use core::fmt::Debug;
use core::ops::Deref;
use core::time::Duration;

/// Pays the given [`Invoice`], retrying if needed based on [`Retry`].
///
/// [`Invoice::payment_hash`] is used as the [`PaymentId`], which ensures idempotency as long
/// as the payment is still pending. Once the payment completes or fails, you must ensure that
/// a second payment with the same [`PaymentHash`] is never sent.
///
/// If you wish to use a different payment idempotency token, see [`pay_invoice_with_id`].
pub fn pay_invoice<M: Deref, T: Deref, ES: Deref, NS: Deref, SP: Deref, F: Deref, R: Deref, L: Deref>(
	invoice: &Invoice, retry_strategy: Retry,
	channelmanager: &ChannelManager<M, T, ES, NS, SP, F, R, L>
) -> Result<PaymentId, PaymentError>
where
		M::Target: chain::Watch<<SP::Target as SignerProvider>::Signer>,
		T::Target: BroadcasterInterface,
		ES::Target: EntropySource,
		NS::Target: NodeSigner,
		SP::Target: SignerProvider,
		F::Target: FeeEstimator,
		R::Target: Router,
		L::Target: Logger,
{
	let payment_id = PaymentId(invoice.payment_hash().into_inner());
	pay_invoice_with_id(invoice, payment_id, retry_strategy, channelmanager)
		.map(|()| payment_id)
}

/// Pays the given [`Invoice`] with a custom idempotency key, retrying if needed based on [`Retry`].
///
/// Note that idempotency is only guaranteed as long as the payment is still pending. Once the
/// payment completes or fails, no idempotency guarantees are made.
///
/// You should ensure that the [`Invoice::payment_hash`] is unique and the same [`PaymentHash`]
/// has never been paid before.
///
/// See [`pay_invoice`] for a variant which uses the [`PaymentHash`] for the idempotency token.
pub fn pay_invoice_with_id<M: Deref, T: Deref, ES: Deref, NS: Deref, SP: Deref, F: Deref, R: Deref, L: Deref>(
	invoice: &Invoice, payment_id: PaymentId, retry_strategy: Retry,
	channelmanager: &ChannelManager<M, T, ES, NS, SP, F, R, L>
) -> Result<(), PaymentError>
where
		M::Target: chain::Watch<<SP::Target as SignerProvider>::Signer>,
		T::Target: BroadcasterInterface,
		ES::Target: EntropySource,
		NS::Target: NodeSigner,
		SP::Target: SignerProvider,
		F::Target: FeeEstimator,
		R::Target: Router,
		L::Target: Logger,
{
	let amt_msat = invoice.amount_milli_satoshis().ok_or(PaymentError::Invoice("amount missing"))?;
	pay_invoice_using_amount(invoice, amt_msat, payment_id, retry_strategy, channelmanager)
}

/// Pays the given zero-value [`Invoice`] using the given amount, retrying if needed based on
/// [`Retry`].
///
/// [`Invoice::payment_hash`] is used as the [`PaymentId`], which ensures idempotency as long
/// as the payment is still pending. Once the payment completes or fails, you must ensure that
/// a second payment with the same [`PaymentHash`] is never sent.
///
/// If you wish to use a different payment idempotency token, see
/// [`pay_zero_value_invoice_with_id`].
pub fn pay_zero_value_invoice<M: Deref, T: Deref, ES: Deref, NS: Deref, SP: Deref, F: Deref, R: Deref, L: Deref>(
	invoice: &Invoice, amount_msats: u64, retry_strategy: Retry,
	channelmanager: &ChannelManager<M, T, ES, NS, SP, F, R, L>
) -> Result<PaymentId, PaymentError>
where
		M::Target: chain::Watch<<SP::Target as SignerProvider>::Signer>,
		T::Target: BroadcasterInterface,
		ES::Target: EntropySource,
		NS::Target: NodeSigner,
		SP::Target: SignerProvider,
		F::Target: FeeEstimator,
		R::Target: Router,
		L::Target: Logger,
{
	let payment_id = PaymentId(invoice.payment_hash().into_inner());
	pay_zero_value_invoice_with_id(invoice, amount_msats, payment_id, retry_strategy,
		channelmanager)
		.map(|()| payment_id)
}

/// Pays the given zero-value [`Invoice`] using the given amount and custom idempotency key,
/// , retrying if needed based on [`Retry`].
///
/// Note that idempotency is only guaranteed as long as the payment is still pending. Once the
/// payment completes or fails, no idempotency guarantees are made.
///
/// You should ensure that the [`Invoice::payment_hash`] is unique and the same [`PaymentHash`]
/// has never been paid before.
///
/// See [`pay_zero_value_invoice`] for a variant which uses the [`PaymentHash`] for the
/// idempotency token.
pub fn pay_zero_value_invoice_with_id<M: Deref, T: Deref, ES: Deref, NS: Deref, SP: Deref, F: Deref, R: Deref, L: Deref>(
	invoice: &Invoice, amount_msats: u64, payment_id: PaymentId, retry_strategy: Retry,
	channelmanager: &ChannelManager<M, T, ES, NS, SP, F, R, L>
) -> Result<(), PaymentError>
where
		M::Target: chain::Watch<<SP::Target as SignerProvider>::Signer>,
		T::Target: BroadcasterInterface,
		ES::Target: EntropySource,
		NS::Target: NodeSigner,
		SP::Target: SignerProvider,
		F::Target: FeeEstimator,
		R::Target: Router,
		L::Target: Logger,
{
	if invoice.amount_milli_satoshis().is_some() {
		Err(PaymentError::Invoice("amount unexpected"))
	} else {
		pay_invoice_using_amount(invoice, amount_msats, payment_id, retry_strategy,
			channelmanager)
	}
}

fn pay_invoice_using_amount<P: Deref>(
	invoice: &Invoice, amount_msats: u64, payment_id: PaymentId, retry_strategy: Retry,
	payer: P
) -> Result<(), PaymentError> where P::Target: Payer {
	let payment_hash = PaymentHash(invoice.payment_hash().clone().into_inner());
	let payment_secret = Some(invoice.payment_secret().clone());
	let mut payment_params = PaymentParameters::from_node_id(invoice.recover_payee_pub_key(),
		invoice.min_final_cltv_expiry_delta() as u32)
		.with_expiry_time(expiry_time_from_unix_epoch(&invoice).as_secs())
		.with_route_hints(invoice.route_hints());
	if let Some(features) = invoice.features() {
		payment_params = payment_params.with_features(features.clone());
	}
	let route_params = RouteParameters {
		payment_params,
		final_value_msat: amount_msats,
	};

	payer.send_payment(payment_hash, &payment_secret, payment_id, route_params, retry_strategy)
}

fn expiry_time_from_unix_epoch(invoice: &Invoice) -> Duration {
	invoice.signed_invoice.raw_invoice.data.timestamp.0 + invoice.expiry_time()
}

/// An error that may occur when making a payment.
#[derive(Clone, Debug)]
pub enum PaymentError {
	/// An error resulting from the provided [`Invoice`] or payment hash.
	Invoice(&'static str),
	/// An error occurring when sending a payment.
	Sending(RetryableSendFailure),
}

/// A trait defining behavior of an [`Invoice`] payer.
///
/// Useful for unit testing internal methods.
trait Payer {
	/// Sends a payment over the Lightning Network using the given [`Route`].
	///
	/// [`Route`]: lightning::routing::router::Route
	fn send_payment(
		&self, payment_hash: PaymentHash, payment_secret: &Option<PaymentSecret>,
		payment_id: PaymentId, route_params: RouteParameters, retry_strategy: Retry
	) -> Result<(), PaymentError>;
}

impl<M: Deref, T: Deref, ES: Deref, NS: Deref, SP: Deref, F: Deref, R: Deref, L: Deref> Payer for ChannelManager<M, T, ES, NS, SP, F, R, L>
where
		M::Target: chain::Watch<<SP::Target as SignerProvider>::Signer>,
		T::Target: BroadcasterInterface,
		ES::Target: EntropySource,
		NS::Target: NodeSigner,
		SP::Target: SignerProvider,
		F::Target: FeeEstimator,
		R::Target: Router,
		L::Target: Logger,
{
	fn send_payment(
		&self, payment_hash: PaymentHash, payment_secret: &Option<PaymentSecret>,
		payment_id: PaymentId, route_params: RouteParameters, retry_strategy: Retry
	) -> Result<(), PaymentError> {
		self.send_payment_with_retry(payment_hash, payment_secret, payment_id, route_params, retry_strategy)
			.map_err(|e| PaymentError::Sending(e))
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::{InvoiceBuilder, Currency};
	use bitcoin_hashes::sha256::Hash as Sha256;
	use lightning::ln::PaymentPreimage;
	use lightning::ln::functional_test_utils::*;
	use secp256k1::{SecretKey, Secp256k1};
	use std::collections::VecDeque;
	use std::time::{SystemTime, Duration};

	struct TestPayer {
		expectations: core::cell::RefCell<VecDeque<Amount>>,
	}

	impl TestPayer {
		fn new() -> Self {
			Self {
				expectations: core::cell::RefCell::new(VecDeque::new()),
			}
		}

		fn expect_send(self, value_msat: Amount) -> Self {
			self.expectations.borrow_mut().push_back(value_msat);
			self
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

	#[derive(Clone, Debug, PartialEq, Eq)]
	struct Amount(u64); // msat

	impl Payer for TestPayer {
		fn send_payment(
			&self, _payment_hash: PaymentHash, _payment_secret: &Option<PaymentSecret>,
			_payment_id: PaymentId, route_params: RouteParameters, _retry_strategy: Retry
		) -> Result<(), PaymentError> {
			self.check_value_msats(Amount(route_params.final_value_msat));
			Ok(())
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

	fn duration_since_epoch() -> Duration {
		#[cfg(feature = "std")]
		let duration_since_epoch =
			SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap();
		#[cfg(not(feature = "std"))]
		let duration_since_epoch = Duration::from_secs(1234567);
		duration_since_epoch
	}

	fn invoice(payment_preimage: PaymentPreimage) -> Invoice {
		let payment_hash = Sha256::hash(&payment_preimage.0);
		let private_key = SecretKey::from_slice(&[42; 32]).unwrap();

		InvoiceBuilder::new(Currency::Bitcoin)
			.description("test".into())
			.payment_hash(payment_hash)
			.payment_secret(PaymentSecret([0; 32]))
			.duration_since_epoch(duration_since_epoch())
			.min_final_cltv_expiry_delta(144)
			.amount_milli_satoshis(128)
			.build_signed(|hash| {
				Secp256k1::new().sign_ecdsa_recoverable(hash, &private_key)
			})
			.unwrap()
	}

	fn zero_value_invoice(payment_preimage: PaymentPreimage) -> Invoice {
		let payment_hash = Sha256::hash(&payment_preimage.0);
		let private_key = SecretKey::from_slice(&[42; 32]).unwrap();

		InvoiceBuilder::new(Currency::Bitcoin)
			.description("test".into())
			.payment_hash(payment_hash)
			.payment_secret(PaymentSecret([0; 32]))
			.duration_since_epoch(duration_since_epoch())
			.min_final_cltv_expiry_delta(144)
			.build_signed(|hash| {
				Secp256k1::new().sign_ecdsa_recoverable(hash, &private_key)
			})
		.unwrap()
	}

	#[test]
	fn pays_invoice() {
		let payment_id = PaymentId([42; 32]);
		let payment_preimage = PaymentPreimage([1; 32]);
		let invoice = invoice(payment_preimage);
		let final_value_msat = invoice.amount_milli_satoshis().unwrap();

		let payer = TestPayer::new().expect_send(Amount(final_value_msat));
		pay_invoice_using_amount(&invoice, final_value_msat, payment_id, Retry::Attempts(0), &payer).unwrap();
	}

	#[test]
	fn pays_zero_value_invoice() {
		let payment_id = PaymentId([42; 32]);
		let payment_preimage = PaymentPreimage([1; 32]);
		let invoice = zero_value_invoice(payment_preimage);
		let amt_msat = 10_000;

		let payer = TestPayer::new().expect_send(Amount(amt_msat));
		pay_invoice_using_amount(&invoice, amt_msat, payment_id, Retry::Attempts(0), &payer).unwrap();
	}

	#[test]
	fn fails_paying_zero_value_invoice_with_amount() {
		let chanmon_cfgs = create_chanmon_cfgs(1);
		let node_cfgs = create_node_cfgs(1, &chanmon_cfgs);
		let node_chanmgrs = create_node_chanmgrs(1, &node_cfgs, &[None]);
		let nodes = create_network(1, &node_cfgs, &node_chanmgrs);

		let payment_preimage = PaymentPreimage([1; 32]);
		let invoice = invoice(payment_preimage);
		let amt_msat = 10_000;

		match pay_zero_value_invoice(&invoice, amt_msat, Retry::Attempts(0), &nodes[0].node) {
			Err(PaymentError::Invoice("amount unexpected")) => {},
			_ => panic!()
		}
	}
}
