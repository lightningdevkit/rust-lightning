// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Implementation of Lightning Offers
//! ([BOLT 12](https://github.com/lightning/bolts/blob/master/12-offer-encoding.md)).
//!
//! Offers are a flexible protocol for Lightning payments.

#[macro_use]
pub mod offer;

pub mod invoice;
pub mod invoice_error;
mod invoice_macros;
pub mod invoice_request;
pub mod merkle;
pub mod nonce;
pub mod parse;
mod payer;
pub mod refund;
pub(crate) mod signer;
#[cfg(async_payments)]
pub mod static_invoice;
#[cfg(test)]
pub(crate) mod test_utils;

/// Wrapper time to move the bolt12 invoice and the static invoice across the same event as a unique
/// type.
// P.S: `OfferInvoice` is confusing, offer is containing the info for asking an invoice :) but I will leave
// this up to the reviewer that I am sure that will find a better name!
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum OfferInvoice {
	/// Bolt12 invoice
	Bolt12Invoice(invoice::Bolt12Invoice),
	#[cfg(async_payments)]
	/// Static invoice
	StaticInvoice(static_invoice::StaticInvoice),
 }

// FIXME(vincenzopalazzo): I do not think there is a way (easy and trivial) that adds cfg to the macro, so
// when we remove the cfg will be removed we can merge these two macro in two.
impl_writeable_tlv_based_enum_legacy!(OfferInvoice,
	;
	(0, Bolt12Invoice),
);

#[cfg(async_payments)]
impl_writeable_tlv_based_enum_legacy!(OfferInvoice,
	;
	(0, Bolt12Invoice),
	(2, StaticInvoice)
);
