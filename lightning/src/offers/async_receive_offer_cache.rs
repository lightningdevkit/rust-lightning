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

use crate::blinded_path::message::{AsyncPaymentsContext, BlindedMessagePath};
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
#[derive(Clone, PartialEq)]
enum OfferStatus {
	/// This offer has been returned to the user from the cache, so it needs to be stored until it
	/// expires and its invoice needs to be kept updated.
	Used {
		/// The creation time of the invoice that was last confirmed as persisted by the server. Useful
		/// to know when the invoice needs refreshing.
		invoice_created_at: Duration,
	},
	/// This offer has not yet been returned to the user, and is safe to replace to ensure we always
	/// have a maximally fresh offer. We always want to have at least 1 offer in this state,
	/// preferably a few so we can respond to user requests for new offers without returning the same
	/// one multiple times. Returning a new offer each time is better for privacy.
	Ready {
		/// The creation time of the invoice that was last confirmed as persisted by the server. Useful
		/// to know when the invoice needs refreshing.
		invoice_created_at: Duration,
	},
	/// This offer's invoice is not yet confirmed as persisted by the static invoice server, so it is
	/// not yet ready to receive payments.
	Pending,
}

#[derive(Clone)]
struct AsyncReceiveOffer {
	offer: Offer,
	/// The time as duration since the Unix epoch at which this offer was created. Useful when
	/// refreshing unused offers.
	created_at: Duration,
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

impl AsyncReceiveOffer {
	/// An offer needs to be refreshed if it is unused and has been cached longer than
	/// `OFFER_REFRESH_THRESHOLD`.
	fn needs_refresh(&self, duration_since_epoch: Duration) -> bool {
		let awhile_ago = duration_since_epoch.saturating_sub(OFFER_REFRESH_THRESHOLD);
		match self.status {
			OfferStatus::Ready { .. } => self.created_at < awhile_ago,
			_ => false,
		}
	}
}

impl_writeable_tlv_based_enum!(OfferStatus,
	(0, Used) => {
		(0, invoice_created_at, required),
	},
	(1, Ready) => {
		(0, invoice_created_at, required),
	},
	(2, Pending) => {},
);

impl_writeable_tlv_based!(AsyncReceiveOffer, {
	(0, offer, required),
	(2, offer_nonce, required),
	(4, status, required),
	(6, update_static_invoice_path, required),
	(8, created_at, required),
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

	pub(super) fn paths_to_static_invoice_server(&self) -> &[BlindedMessagePath] {
		&self.paths_to_static_invoice_server[..]
	}

	/// Sets the [`BlindedMessagePath`]s that we will use as an async recipient to interactively build
	/// [`Offer`]s with a static invoice server, so the server can serve [`StaticInvoice`]s to payers
	/// on our behalf when we're offline.
	///
	/// [`StaticInvoice`]: crate::offers::static_invoice::StaticInvoice
	pub(crate) fn set_paths_to_static_invoice_server(
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
const MAX_CACHED_OFFERS_TARGET: usize = 10;

// The max number of times we'll attempt to request offer paths per timer tick.
const MAX_UPDATE_ATTEMPTS: u8 = 3;

// If we have an offer that is replaceable and is more than 2 hours old, we can go ahead and refresh
// it because we always want to have the freshest offer possible when a user goes to retrieve a
// cached offer.
//
// We avoid replacing unused offers too quickly -- this prevents the case where we send multiple
// invoices from different offers competing for the same slot to the server, messages are received
// delayed or out-of-order, and we end up providing an offer to the user that the server just
// deleted and replaced.
const OFFER_REFRESH_THRESHOLD: Duration = Duration::from_secs(2 * 60 * 60);

/// Invoices stored with the static invoice server may become stale due to outdated channel and fee
/// info, so they should be updated regularly.
const INVOICE_REFRESH_THRESHOLD: Duration = Duration::from_secs(2 * 60 * 60);

// Require offer paths that we receive to last at least 3 months.
const MIN_OFFER_PATHS_RELATIVE_EXPIRY_SECS: u64 = 3 * 30 * 24 * 60 * 60;

#[cfg(test)]
pub(crate) const TEST_MAX_CACHED_OFFERS_TARGET: usize = MAX_CACHED_OFFERS_TARGET;
#[cfg(test)]
pub(crate) const TEST_MAX_UPDATE_ATTEMPTS: u8 = MAX_UPDATE_ATTEMPTS;
#[cfg(test)]
pub(crate) const TEST_OFFER_REFRESH_THRESHOLD: Duration = OFFER_REFRESH_THRESHOLD;
#[cfg(test)]
pub(crate) const TEST_INVOICE_REFRESH_THRESHOLD: Duration = INVOICE_REFRESH_THRESHOLD;
#[cfg(test)]
pub(crate) const TEST_MIN_OFFER_PATHS_RELATIVE_EXPIRY_SECS: u64 =
	MIN_OFFER_PATHS_RELATIVE_EXPIRY_SECS;

impl AsyncReceiveOfferCache {
	/// Retrieve a cached [`Offer`] for receiving async payments as an often-offline recipient, as
	/// well as returning a bool indicating whether the cache needs to be re-persisted.
	///
	// We need to re-persist the cache if a fresh offer was just marked as used to ensure we continue
	// to keep this offer's invoice updated and don't replace it with the server.
	pub(crate) fn get_async_receive_offer(
		&mut self, duration_since_epoch: Duration,
	) -> Result<(Offer, bool), ()> {
		self.prune_expired_offers(duration_since_epoch, false);

		// Find the freshest unused offer. See `OfferStatus::Ready`.
		let newest_unused_offer_opt = self
			.unused_ready_offers()
			.max_by(|(_, offer_a, _), (_, offer_b, _)| offer_a.created_at.cmp(&offer_b.created_at))
			.map(|(idx, offer, invoice_created_at)| (idx, offer.offer.clone(), invoice_created_at));
		if let Some((idx, newest_ready_offer, invoice_created_at)) = newest_unused_offer_opt {
			self.offers[idx]
				.as_mut()
				.map(|offer| offer.status = OfferStatus::Used { invoice_created_at });
			return Ok((newest_ready_offer, true));
		}

		// If no unused offers are available, return the used offer with the latest absolute expiry
		self.offers_with_idx()
			.filter(|(_, offer)| matches!(offer.status, OfferStatus::Used { .. }))
			.max_by(|a, b| {
				let abs_expiry_a = a.1.offer.absolute_expiry().unwrap_or(Duration::MAX);
				let abs_expiry_b = b.1.offer.absolute_expiry().unwrap_or(Duration::MAX);
				abs_expiry_a.cmp(&abs_expiry_b)
			})
			.map(|(_, cache_offer)| (cache_offer.offer.clone(), false))
			.ok_or(())
	}

	/// Remove expired offers from the cache, returning the first slot number in the cache that needs
	/// a new offer, if any exist.
	pub(super) fn prune_expired_offers(
		&mut self, duration_since_epoch: Duration, force_reset_request_attempts: bool,
	) -> Option<u16> {
		// Remove expired offers from the cache.
		let mut offer_was_removed = false;
		for offer_opt in self.offers.iter_mut() {
			let offer_is_expired = offer_opt
				.as_ref()
				.is_some_and(|offer| offer.offer.is_expired_no_std(duration_since_epoch));
			if offer_is_expired {
				offer_opt.take();
				offer_was_removed = true;
			}
		}

		// Allow up to `MAX_UPDATE_ATTEMPTS` offer paths requests to be sent out roughly once per
		// minute, or if an offer was removed.
		if force_reset_request_attempts || offer_was_removed {
			self.reset_offer_paths_request_attempts()
		}

		if self.offer_paths_request_attempts >= MAX_UPDATE_ATTEMPTS {
			return None;
		}

		self.needs_new_offer_idx(duration_since_epoch).and_then(|idx| {
			debug_assert!(idx < MAX_CACHED_OFFERS_TARGET);
			idx.try_into().ok()
		})
	}

	/// Returns whether the new paths we've just received from the static invoice server should be used
	/// to build a new offer.
	pub(super) fn should_build_offer_with_paths(
		&self, offer_paths: &[BlindedMessagePath], offer_paths_absolute_expiry_secs: Option<u64>,
		slot: u16, duration_since_epoch: Duration,
	) -> bool {
		if !self.slot_needs_offer(slot, duration_since_epoch) {
			return false;
		}

		// Require the offer that would be built using these paths to last at least
		// `MIN_OFFER_PATHS_RELATIVE_EXPIRY_SECS`.
		let min_offer_paths_absolute_expiry =
			duration_since_epoch.as_secs().saturating_add(MIN_OFFER_PATHS_RELATIVE_EXPIRY_SECS);
		let offer_paths_absolute_expiry = offer_paths_absolute_expiry_secs.unwrap_or(u64::MAX);
		if offer_paths_absolute_expiry < min_offer_paths_absolute_expiry {
			return false;
		}

		// Check that we don't have any current offers that already contain these paths
		self.offers_with_idx().all(|(_, offer)| offer.offer.paths() != offer_paths)
	}

	/// We've sent a static invoice to the static invoice server for persistence. Cache the
	/// corresponding pending offer so we can retry persisting a corresponding invoice with the server
	/// until it succeeds, see [`AsyncReceiveOfferCache`] docs.
	pub(super) fn cache_pending_offer(
		&mut self, offer: Offer, offer_paths_absolute_expiry_secs: Option<u64>, offer_nonce: Nonce,
		update_static_invoice_path: Responder, duration_since_epoch: Duration, slot: u16,
	) -> Result<(), ()> {
		self.prune_expired_offers(duration_since_epoch, false);

		if !self.should_build_offer_with_paths(
			offer.paths(),
			offer_paths_absolute_expiry_secs,
			slot,
			duration_since_epoch,
		) {
			return Err(());
		}

		match self.offers.get_mut(slot as usize) {
			Some(slot) => {
				*slot = Some(AsyncReceiveOffer {
					offer,
					created_at: duration_since_epoch,
					offer_nonce,
					status: OfferStatus::Pending,
					update_static_invoice_path,
				})
			},
			None => {
				debug_assert!(false, "Slot in cache was invalid but should'be been checked above");
				return Err(());
			},
		}

		Ok(())
	}

	fn slot_needs_offer(&self, slot: u16, duration_since_epoch: Duration) -> bool {
		match self.offers.get(slot as usize) {
			Some(Some(offer)) => offer.needs_refresh(duration_since_epoch),
			// This slot in the cache was pre-allocated as needing an offer in
			// `set_paths_to_static_invoice_server` and is currently vacant
			Some(None) => true,
			// `slot` is out-of-range. Note that the cache only has `MAX_CACHED_OFFERS_TARGET` slots
			// total, so any slots outside of that range are invalid.
			None => {
				debug_assert!(false, "Got offer paths for a non-existent slot in the cache");
				false
			},
		}
	}

	/// If we have any empty slots in the cache or offers that can and should be replaced with a fresh
	/// offer, here we return the index of the slot that needs a new offer. The index is used for
	/// setting [`OfferPathsRequest::invoice_slot`] when requesting offer paths from the server, so
	/// the server can include the slot in the offer paths and reply paths that they create in
	/// response.
	///
	/// Returns `None` if the cache is full and no offers can currently be replaced.
	///
	/// [`OfferPathsRequest::invoice_slot`]: crate::onion_message::async_payments::OfferPathsRequest::invoice_slot
	fn needs_new_offer_idx(&self, duration_since_epoch: Duration) -> Option<usize> {
		// If we have any empty offer slots, return the first one we find
		let empty_slot_idx_opt = self.offers.iter().position(|offer_opt| offer_opt.is_none());
		if empty_slot_idx_opt.is_some() {
			return empty_slot_idx_opt;
		}

		// If all of our offers are already used or pending, then none are available to be replaced
		let no_replaceable_offers = self.offers_with_idx().all(|(_, offer)| {
			matches!(offer.status, OfferStatus::Used { .. } | OfferStatus::Pending)
		});
		if no_replaceable_offers {
			return None;
		}

		// All offers are pending except for one, so we shouldn't request an update of the only usable
		// offer
		let num_payable_offers = self
			.offers_with_idx()
			.filter(|(_, offer)| {
				matches!(offer.status, OfferStatus::Used { .. } | OfferStatus::Ready { .. })
			})
			.count();
		if num_payable_offers <= 1 {
			return None;
		}

		// Filter for unused offers where longer than OFFER_REFRESH_THRESHOLD time has passed since they
		// were last updated, so they are stale enough to warrant replacement.
		self.offers_with_idx()
			.filter(|(_, offer)| offer.needs_refresh(duration_since_epoch))
			// Get the stalest offer and return its index
			.min_by(|(_, offer_a), (_, offer_b)| offer_a.created_at.cmp(&offer_b.created_at))
			.map(|(idx, _)| idx)
	}

	/// Returns an iterator over (offer_idx, offer)
	fn offers_with_idx(&self) -> impl Iterator<Item = (usize, &AsyncReceiveOffer)> {
		self.offers.iter().enumerate().filter_map(|(idx, offer_opt)| {
			if let Some(offer) = offer_opt {
				Some((idx, offer))
			} else {
				None
			}
		})
	}

	/// Returns an iterator over (offer_idx, offer, invoice_created_at) where all returned offers are
	/// [`OfferStatus::Ready`]
	fn unused_ready_offers(&self) -> impl Iterator<Item = (usize, &AsyncReceiveOffer, Duration)> {
		self.offers_with_idx().filter_map(|(idx, offer)| match offer.status {
			OfferStatus::Ready { invoice_created_at } => Some((idx, offer, invoice_created_at)),
			_ => None,
		})
	}

	// Indicates that onion messages requesting new offer paths have been sent to the static invoice
	// server. Calling this method allows the cache to self-limit how many requests are sent.
	pub(super) fn new_offers_requested(&mut self) {
		self.offer_paths_request_attempts += 1;
	}

	/// Called on timer tick (roughly once per minute) to allow another [`MAX_UPDATE_ATTEMPTS`] offer
	/// paths requests to go out.
	fn reset_offer_paths_request_attempts(&mut self) {
		self.offer_paths_request_attempts = 0;
	}

	/// Returns an iterator over the list of cached offers where we need to send an updated invoice to
	/// the static invoice server.
	pub(super) fn offers_needing_invoice_refresh(
		&self, duration_since_epoch: Duration,
	) -> impl Iterator<Item = (&Offer, Nonce, &Responder)> {
		// For any offers which are either in use or pending confirmation by the server, we should send
		// them a fresh invoice on each timer tick.
		self.offers_with_idx().filter_map(move |(_, offer)| {
			let needs_invoice_update = match offer.status {
				OfferStatus::Used { invoice_created_at } => {
					invoice_created_at.saturating_add(INVOICE_REFRESH_THRESHOLD)
						< duration_since_epoch
				},
				OfferStatus::Pending => true,
				// Don't bother updating `Ready` offers' invoices on a timer because the offers themselves
				// are regularly rotated anyway.
				OfferStatus::Ready { .. } => false,
			};
			if needs_invoice_update {
				Some((&offer.offer, offer.offer_nonce, &offer.update_static_invoice_path))
			} else {
				None
			}
		})
	}

	/// Should be called when we receive a [`StaticInvoicePersisted`] message from the static invoice
	/// server, which indicates that a new offer was persisted by the server and they are ready to
	/// serve the corresponding static invoice to payers on our behalf.
	///
	/// Returns a bool indicating whether an offer was added/updated and re-persistence of the cache
	/// is needed.
	///
	/// [`StaticInvoicePersisted`]: crate::onion_message::async_payments::StaticInvoicePersisted
	pub(super) fn static_invoice_persisted(&mut self, context: AsyncPaymentsContext) -> bool {
		let (invoice_created_at, offer_id) = match context {
			AsyncPaymentsContext::StaticInvoicePersisted { invoice_created_at, offer_id } => {
				(invoice_created_at, offer_id)
			},
			_ => return false,
		};

		let mut offers = self.offers.iter_mut();
		let offer_entry = offers.find(|o| o.as_ref().is_some_and(|o| o.offer.id() == offer_id));
		if let Some(Some(ref mut offer)) = offer_entry {
			match offer.status {
				OfferStatus::Used { invoice_created_at: ref mut inv_created_at }
				| OfferStatus::Ready { invoice_created_at: ref mut inv_created_at } => {
					*inv_created_at = core::cmp::min(invoice_created_at, *inv_created_at);
				},
				OfferStatus::Pending => offer.status = OfferStatus::Ready { invoice_created_at },
			}

			return true;
		}

		false
	}

	#[cfg(test)]
	pub(super) fn test_get_payable_offers(&self) -> Vec<Offer> {
		self.offers_with_idx()
			.filter_map(|(_, offer)| {
				if matches!(offer.status, OfferStatus::Ready { .. })
					|| matches!(offer.status, OfferStatus::Used { .. })
				{
					Some(offer.offer.clone())
				} else {
					None
				}
			})
			.collect()
	}
}

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
