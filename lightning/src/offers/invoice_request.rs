// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Data structures and encoding for `invoice_request` messages.

use bitcoin::blockdata::constants::ChainHash;
use bitcoin::secp256k1::PublicKey;
use bitcoin::secp256k1::schnorr::Signature;
use crate::ln::features::InvoiceRequestFeatures;
use crate::offers::offer::OfferContents;
use crate::offers::payer::PayerContents;
use crate::util::string::PrintableString;

use crate::prelude::*;

/// An `InvoiceRequest` is a request for an `Invoice` formulated from an [`Offer`].
///
/// An offer may provide choices such as quantity, amount, chain, features, etc. An invoice request
/// specifies these such that its recipient can send an invoice for payment.
///
/// [`Offer`]: crate::offers::offer::Offer
#[derive(Clone, Debug)]
pub struct InvoiceRequest {
	bytes: Vec<u8>,
	contents: InvoiceRequestContents,
	signature: Option<Signature>,
}

/// The contents of an [`InvoiceRequest`], which may be shared with an `Invoice`.
#[derive(Clone, Debug)]
pub(crate) struct InvoiceRequestContents {
	payer: PayerContents,
	offer: OfferContents,
	chain: Option<ChainHash>,
	amount_msats: Option<u64>,
	features: InvoiceRequestFeatures,
	quantity: Option<u64>,
	payer_id: PublicKey,
	payer_note: Option<String>,
}

impl InvoiceRequest {
	/// An unpredictable series of bytes, typically containing information about the derivation of
	/// [`payer_id`].
	///
	/// [`payer_id`]: Self::payer_id
	pub fn metadata(&self) -> &[u8] {
		&self.contents.payer.0[..]
	}

	/// A chain from [`Offer::chains`] that the offer is valid for.
	///
	/// [`Offer::chains`]: crate::offers::offer::Offer::chains
	pub fn chain(&self) -> ChainHash {
		self.contents.chain.unwrap_or_else(|| self.contents.offer.implied_chain())
	}

	/// The amount to pay in msats (i.e., the minimum lightning-payable unit for [`chain`]), which
	/// must be greater than or equal to [`Offer::amount`], converted if necessary.
	///
	/// [`chain`]: Self::chain
	/// [`Offer::amount`]: crate::offers::offer::Offer::amount
	pub fn amount_msats(&self) -> Option<u64> {
		self.contents.amount_msats
	}

	/// Features for paying the invoice.
	pub fn features(&self) -> &InvoiceRequestFeatures {
		&self.contents.features
	}

	/// The quantity of the offer's item conforming to [`Offer::supported_quantity`].
	///
	/// [`Offer::supported_quantity`]: crate::offers::offer::Offer::supported_quantity
	pub fn quantity(&self) -> Option<u64> {
		self.contents.quantity
	}

	/// A possibly transient pubkey used to sign the invoice request.
	pub fn payer_id(&self) -> PublicKey {
		self.contents.payer_id
	}

	/// Payer provided note to include in the invoice.
	pub fn payer_note(&self) -> Option<PrintableString> {
		self.contents.payer_note.as_ref().map(|payer_note| PrintableString(payer_note.as_str()))
	}

	/// Signature of the invoice request using [`payer_id`].
	///
	/// [`payer_id`]: Self::payer_id
	pub fn signature(&self) -> Option<Signature> {
		self.signature
	}
}
