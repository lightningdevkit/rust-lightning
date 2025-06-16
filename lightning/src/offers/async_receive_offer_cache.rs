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

use crate::blinded_path::message::BlindedMessagePath;
use crate::io;
use crate::io::Read;
use crate::ln::msgs::DecodeError;
use crate::offers::nonce::Nonce;
use crate::offers::offer::Offer;
use crate::onion_message::messenger::Responder;
use crate::prelude::*;
use crate::util::ser::{Readable, Writeable, Writer};
use core::time::Duration;

/// The status of this offer in the cache.
#[derive(Clone)]
enum OfferStatus {
	/// This offer has been returned to the user from the cache, so it needs to be stored until it
	/// expires and its invoice needs to be kept updated.
	Used,
	/// This offer has not yet been returned to the user, and is safe to replace to ensure we always
	/// have a maximally fresh offer. We always want to have at least 1 offer in this state,
	/// preferably a few so we can respond to user requests for new offers without returning the same
	/// one multiple times. Returning a new offer each time is better for privacy.
	Ready {
		/// If this offer's invoice has been persisted for some time, it's safe to replace to ensure we
		/// always have the freshest possible offer available when the user goes to pull an offer from
		/// the cache.
		invoice_confirmed_persisted_at: Duration,
	},
	/// This offer's invoice is not yet confirmed as persisted by the static invoice server, so it is
	/// not yet ready to receive payments.
	Pending,
}

#[derive(Clone)]
struct AsyncReceiveOffer {
	offer: Offer,
	/// Whether this offer is used, ready for use, or pending invoice persistence with the static
	/// invoice server.
	status: OfferStatus,

	/// The below fields are used to generate and persist a new static invoice with the invoice
	/// server. We support automatically rotating the invoice for long-lived offers so users don't
	/// have to update the offer they've posted on e.g. their website if fees change or the invoices'
	/// payment paths become otherwise outdated.
	offer_nonce: Nonce,
	update_static_invoice_path: Responder,
}

impl_writeable_tlv_based_enum!(OfferStatus,
	(0, Used) => {},
	(1, Ready) => {
		(0, invoice_confirmed_persisted_at, required),
	},
	(2, Pending) => {},
);

impl_writeable_tlv_based!(AsyncReceiveOffer, {
	(0, offer, required),
	(2, offer_nonce, required),
	(4, status, required),
	(6, update_static_invoice_path, required),
});

/// If we are an often-offline recipient, we'll want to interactively build offers and static
/// invoices with an always-online node that will serve those static invoices to payers on our
/// behalf when we are offline.
///
/// This struct is used to cache those interactively built offers, and should be passed into
/// [`OffersMessageFlow`] on startup as well as persisted whenever an offer or invoice is updated.
///
/// ## Lifecycle of a cached offer
///
/// 1. On initial startup, recipients will request offer paths from the static invoice server
/// 2. Once a set of offer paths is received, recipients will build an offer and corresponding
///    static invoice, cache the offer as pending, and send the invoice to the server for
///    persistence
/// 3. Once the invoice is confirmed as persisted by the server, the recipient will mark the
///    corresponding offer as ready to receive payments
/// 4. If the offer is later returned to the user, it will be kept cached and its invoice will be
///    kept up-to-date until the offer expires
/// 5. If the offer does not get returned to the user within a certain timeframe, it will be
///    replaced with a new one using fresh offer paths requested from the static invoice server
///
/// ## Staying in sync with the Static Invoice Server
///
/// * Pending offers: for a given cached offer where a corresponding invoice is not yet confirmed as
/// persisted by the static invoice server, we will retry persisting an invoice for that offer until
/// it succeeds, once per timer tick
/// * Confirmed offers that have not yet been returned to the user: we will periodically replace an
/// unused confirmed offer with a new one, to try to always have a fresh offer available. We wait
/// several hours in between replacements to ensure the new offer replacement doesn't conflict with
/// the old one
/// * Confirmed offers that have been returned to the user: we will send the server a fresh invoice
/// corresponding to each used offer once per timer tick until the offer expires
///
/// [`OffersMessageFlow`]: crate::offers::flow::OffersMessageFlow
pub struct AsyncReceiveOfferCache {
	/// The cache is allocated up-front with a fixed number of slots for offers, where each slot is
	/// filled in with an AsyncReceiveOffer as they are interactively built.
	///
	/// We only want to store a limited number of static invoices with the server, and those stored
	/// invoices need to regularly be replaced with new ones. When sending a replacement invoice to
	/// the server, we indicate which invoice is being replaced by the invoice's "slot number",
	/// see [`ServeStaticInvoice::invoice_slot`]. So rather than internally tracking which cached
	/// offer corresponds to what invoice slot number on the server's end, we always set the slot
	/// number to the index of the offer in the cache.
	///
	/// [`ServeStaticInvoice::invoice_slot`]: crate::onion_message::async_payments::ServeStaticInvoice
	offers: Vec<Option<AsyncReceiveOffer>>,
	/// Used to limit the number of times we request paths for our offer from the static invoice
	/// server.
	#[allow(unused)] // TODO: remove when we get rid of async payments cfg flag
	offer_paths_request_attempts: u8,
	/// Blinded paths used to request offer paths from the static invoice server.
	#[allow(unused)] // TODO: remove when we get rid of async payments cfg flag
	paths_to_static_invoice_server: Vec<BlindedMessagePath>,
}

impl AsyncReceiveOfferCache {
	/// Creates an empty [`AsyncReceiveOfferCache`] to be passed into [`OffersMessageFlow`].
	///
	/// [`OffersMessageFlow`]: crate::offers::flow::OffersMessageFlow
	pub fn new() -> Self {
		Self {
			offers: Vec::new(),
			offer_paths_request_attempts: 0,
			paths_to_static_invoice_server: Vec::new(),
		}
	}

	pub(super) fn paths_to_static_invoice_server(&self) -> Vec<BlindedMessagePath> {
		self.paths_to_static_invoice_server.clone()
	}

	/// Sets the [`BlindedMessagePath`]s that we will use as an async recipient to interactively build
	/// [`Offer`]s with a static invoice server, so the server can serve [`StaticInvoice`]s to payers
	/// on our behalf when we're offline.
	///
	/// [`StaticInvoice`]: crate::offers::static_invoice::StaticInvoice
	#[cfg(async_payments)]
	pub fn set_paths_to_static_invoice_server(
		&mut self, paths_to_static_invoice_server: Vec<BlindedMessagePath>,
	) -> Result<(), ()> {
		if paths_to_static_invoice_server.is_empty() {
			return Err(());
		}

		self.paths_to_static_invoice_server = paths_to_static_invoice_server;
		if self.offers.is_empty() {
			// See `AsyncReceiveOfferCache::offers`.
			self.offers = vec![None; MAX_CACHED_OFFERS_TARGET];
		}
		Ok(())
	}
}

// The target number of offers we want to have cached at any given time, to mitigate too much
// reuse of the same offer while also limiting the amount of space our offers take up on the
// server's end.
#[cfg(async_payments)]
const MAX_CACHED_OFFERS_TARGET: usize = 10;

impl Writeable for AsyncReceiveOfferCache {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		write_tlv_fields!(w, {
			(0, self.offers, required_vec),
			(2, self.paths_to_static_invoice_server, required_vec),
			// offer paths request retry info always resets on restart
		});
		Ok(())
	}
}

impl Readable for AsyncReceiveOfferCache {
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		_init_and_read_len_prefixed_tlv_fields!(r, {
			(0, offers, required_vec),
			(2, paths_to_static_invoice_server, required_vec),
		});
		let offers: Vec<Option<AsyncReceiveOffer>> = offers;
		Ok(Self { offers, offer_paths_request_attempts: 0, paths_to_static_invoice_server })
	}
}
