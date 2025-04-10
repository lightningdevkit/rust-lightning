// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Data structures and methods for caching offers that we interactively build with a static invoice
//! server as an async recipient. The static invoice server will serve the resulting invoices to
//! payers on our behalf when we're offline.

use crate::io;
use crate::io::Read;
use crate::ln::msgs::DecodeError;
use crate::offers::nonce::Nonce;
use crate::offers::offer::Offer;
use crate::onion_message::messenger::Responder;
use crate::prelude::*;
use crate::util::ser::{Readable, Writeable, Writer};
use core::time::Duration;

struct AsyncReceiveOffer {
	offer: Offer,
	/// We determine whether an offer is expiring "soon" based on how far the offer is into its total
	/// lifespan, using this field.
	offer_created_at: Duration,

	/// The below fields are used to generate and persist a new static invoice with the invoice
	/// server, if the invoice is expiring prior to the corresponding offer. We support automatically
	/// rotating the invoice for long-lived offers so users don't have to update the offer they've
	/// posted on e.g. their website if fees change or the invoices' payment paths become otherwise
	/// outdated.
	offer_nonce: Nonce,
	update_static_invoice_path: Responder,
	static_invoice_absolute_expiry: Duration,
	invoice_update_attempts: u8,
}

impl_writeable_tlv_based!(AsyncReceiveOffer, {
	(0, offer, required),
	(2, offer_nonce, required),
	(4, offer_created_at, required),
	(6, update_static_invoice_path, required),
	(8, static_invoice_absolute_expiry, required),
	(10, invoice_update_attempts, (static_value, 0)),
});

/// If we are an often-offline recipient, we'll want to interactively build offers and static
/// invoices with an always-online node that will serve those static invoices to payers on our
/// behalf when we are offline.
///
/// This struct is used to cache those interactively built offers, and should be passed into
/// [`OffersMessageFlow`] on startup as well as persisted whenever an offer or invoice is updated
/// with the static invoice server.
///
/// [`OffersMessageFlow`]: crate::offers::flow::OffersMessageFlow
pub struct AsyncReceiveOfferCache {
	offers: Vec<AsyncReceiveOffer>,
	/// Used to limit the number of times we request paths for our offer from the static invoice
	/// server.
	#[allow(unused)] // TODO: remove when we get rid of async payments cfg flag
	offer_paths_request_attempts: u8,
	/// Used to determine whether enough time has passed since our last request for offer paths that
	/// more requests should be allowed to go out.
	#[allow(unused)] // TODO: remove when we get rid of async payments cfg flag
	last_offer_paths_request_timestamp: Duration,
}

impl AsyncReceiveOfferCache {
	/// Creates an empty [`AsyncReceiveOfferCache`] to be passed into [`OffersMessageFlow`].
	///
	/// [`OffersMessageFlow`]: crate::offers::flow::OffersMessageFlow
	pub fn new() -> Self {
		Self {
			offers: Vec::new(),
			offer_paths_request_attempts: 0,
			last_offer_paths_request_timestamp: Duration::from_secs(0),
		}
	}
}

impl Writeable for AsyncReceiveOfferCache {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		write_tlv_fields!(w, {
			(0, self.offers, required_vec),
			// offer paths request retry info always resets on restart
		});
		Ok(())
	}
}

impl Readable for AsyncReceiveOfferCache {
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		_init_and_read_len_prefixed_tlv_fields!(r, {
			(0, offers, required_vec),
		});
		let offers: Vec<AsyncReceiveOffer> = offers;
		Ok(Self {
			offers,
			offer_paths_request_attempts: 0,
			last_offer_paths_request_timestamp: Duration::from_secs(0),
		})
	}
}
