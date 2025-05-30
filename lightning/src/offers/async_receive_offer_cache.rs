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
#[cfg(async_payments)]
use {
	crate::blinded_path::message::AsyncPaymentsContext, crate::offers::offer::OfferId,
	crate::onion_message::async_payments::OfferPaths,
};

struct AsyncReceiveOffer {
	offer: Offer,
	/// We determine whether an offer is expiring "soon" based on how far the offer is into its total
	/// lifespan, using this field.
	offer_created_at: Duration,

	/// The below fields are used to generate and persist a new static invoice with the invoice
	/// server, if the invoice is expiring prior to the corresponding offer.
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

#[cfg(async_payments)]
impl AsyncReceiveOfferCache {
	// The target number of offers we want to have cached at any given time, to mitigate too much
	// reuse of the same offer.
	const NUM_CACHED_OFFERS_TARGET: usize = 3;

	// The max number of times we'll attempt to request offer paths or attempt to refresh a static
	// invoice before giving up.
	const MAX_UPDATE_ATTEMPTS: u8 = 3;

	/// Retrieve our cached [`Offer`]s for receiving async payments as an often-offline recipient.
	pub fn offers(&self, duration_since_epoch: Duration) -> Vec<Offer> {
		const NEVER_EXPIRES: Duration = Duration::from_secs(u64::MAX);

		self.offers
			.iter()
			.filter_map(|offer| {
				if offer.static_invoice_absolute_expiry < duration_since_epoch {
					None
				} else if offer.offer.absolute_expiry().unwrap_or(NEVER_EXPIRES)
					< duration_since_epoch
				{
					None
				} else {
					Some(offer.offer.clone())
				}
			})
			.collect()
	}

	/// Remove expired offers from the cache.
	pub(super) fn prune_expired_offers(&mut self, duration_since_epoch: Duration) {
		// Remove expired offers from the cache.
		let mut offer_was_removed = false;
		self.offers.retain(|offer| {
			if offer.offer.is_expired_no_std(duration_since_epoch) {
				offer_was_removed = true;
				return false;
			}
			true
		});

		// If we just removed a newly expired offer, force allowing more paths request attempts.
		if offer_was_removed {
			self.reset_offer_paths_request_attempts();
		}

		// If we haven't attempted to request new paths in a long time, allow more requests to go out
		// if/when needed.
		self.check_reset_offer_paths_request_attempts(duration_since_epoch);
	}

	/// Checks whether we should request new offer paths from the always-online static invoice server.
	pub(super) fn should_request_offer_paths(&self, duration_since_epoch: Duration) -> bool {
		self.needs_new_offers(duration_since_epoch)
			&& self.offer_paths_request_attempts < Self::MAX_UPDATE_ATTEMPTS
	}

	/// Returns whether the new paths we've just received from the static invoice server should be used
	/// to build a new offer.
	pub(super) fn should_build_offer_with_paths(
		&self, message: &OfferPaths, duration_since_epoch: Duration,
	) -> bool {
		if !self.needs_new_offers(duration_since_epoch) {
			return false;
		}

		// Require the offer that would be built using these paths to last at least a few hours.
		let min_offer_paths_absolute_expiry =
			duration_since_epoch.as_secs().saturating_add(3 * 60 * 60);
		let offer_paths_absolute_expiry =
			message.paths_absolute_expiry.map(|exp| exp.as_secs()).unwrap_or(u64::MAX);
		if offer_paths_absolute_expiry < min_offer_paths_absolute_expiry {
			return false;
		}

		// Check that we don't have any current offers that already contain these paths
		self.offers.iter().all(|offer| offer.offer.paths() != message.paths)
	}

	/// Returns a bool indicating whether new offers are needed in the cache.
	fn needs_new_offers(&self, duration_since_epoch: Duration) -> bool {
		// If we have fewer than NUM_CACHED_OFFERS_TARGET offers that aren't expiring soon, indicate
		// that new offers should be interactively built.
		let num_unexpiring_offers = self
			.offers
			.iter()
			.filter(|offer| {
				let offer_absolute_expiry = offer.offer.absolute_expiry().unwrap_or(Duration::MAX);
				let offer_created_at = offer.offer_created_at;
				let offer_lifespan =
					offer_absolute_expiry.saturating_sub(offer_created_at).as_secs();
				let elapsed = duration_since_epoch.saturating_sub(offer_created_at).as_secs();

				// If an offer is in the last 10% of its lifespan, it's expiring soon.
				elapsed.saturating_mul(10) >= offer_lifespan.saturating_mul(9)
			})
			.count();

		num_unexpiring_offers < Self::NUM_CACHED_OFFERS_TARGET
	}

	// Indicates that onion messages requesting new offer paths have been sent to the static invoice
	// server. Calling this method allows the cache to self-limit how many requests are sent, in case
	// the server goes unresponsive.
	pub(super) fn new_offers_requested(&mut self, duration_since_epoch: Duration) {
		self.offer_paths_request_attempts += 1;
		self.last_offer_paths_request_timestamp = duration_since_epoch;
	}

	/// If we haven't sent an offer paths request in a long time, reset the limit to allow more
	/// requests to be sent out if/when needed.
	fn check_reset_offer_paths_request_attempts(&mut self, duration_since_epoch: Duration) {
		const REQUESTS_TIME_BUFFER: Duration = Duration::from_secs(3 * 60 * 60);
		let should_reset =
			self.last_offer_paths_request_timestamp.saturating_add(REQUESTS_TIME_BUFFER)
				< duration_since_epoch;
		if should_reset {
			self.reset_offer_paths_request_attempts();
		}
	}

	fn reset_offer_paths_request_attempts(&mut self) {
		self.offer_paths_request_attempts = 0;
		self.last_offer_paths_request_timestamp = Duration::from_secs(0);
	}

	/// Returns an iterator over the list of cached offers where the invoice is expiring soon and we
	/// need to send an updated one to the static invoice server.
	pub(super) fn offers_needing_invoice_refresh(
		&self, duration_since_epoch: Duration,
	) -> impl Iterator<Item = (&Offer, Nonce, Duration, &Responder)> {
		self.offers.iter().filter_map(move |offer| {
			const ONE_DAY: Duration = Duration::from_secs(24 * 60 * 60);

			if offer.offer.is_expired_no_std(duration_since_epoch) {
				return None;
			}
			if offer.invoice_update_attempts >= Self::MAX_UPDATE_ATTEMPTS {
				return None;
			}

			let time_until_invoice_expiry =
				offer.static_invoice_absolute_expiry.saturating_sub(duration_since_epoch);
			let time_until_offer_expiry = offer
				.offer
				.absolute_expiry()
				.unwrap_or_else(|| Duration::from_secs(u64::MAX))
				.saturating_sub(duration_since_epoch);

			// Update the invoice if it expires in less than a day, as long as the offer has a longer
			// expiry than that.
			let needs_update = time_until_invoice_expiry < ONE_DAY
				&& time_until_offer_expiry > time_until_invoice_expiry;
			if needs_update {
				Some((
					&offer.offer,
					offer.offer_nonce,
					offer.offer_created_at,
					&offer.update_static_invoice_path,
				))
			} else {
				None
			}
		})
	}

	/// Indicates that we've sent onion messages attempting to update the static invoice corresponding
	/// to the provided offer_id. Calling this method allows the cache to self-limit how many invoice
	/// update requests are sent.
	///
	/// Errors if the offer corresponding to the provided offer_id could not be found.
	pub(super) fn increment_invoice_update_attempts(
		&mut self, offer_id: OfferId,
	) -> Result<(), ()> {
		match self.offers.iter_mut().find(|offer| offer.offer.id() == offer_id) {
			Some(offer) => {
				offer.invoice_update_attempts += 1;
				Ok(())
			},
			None => return Err(()),
		}
	}

	/// Should be called when we receive a [`StaticInvoicePersisted`] message from the static invoice
	/// server, which indicates that a new offer was persisted by the server and they are ready to
	/// serve the corresponding static invoice to payers on our behalf.
	///
	/// Returns a bool indicating whether an offer was added/updated and re-persistence of the cache
	/// is needed.
	pub(super) fn static_invoice_persisted(
		&mut self, context: AsyncPaymentsContext, duration_since_epoch: Duration,
	) -> bool {
		let (
			candidate_offer,
			candidate_offer_nonce,
			offer_created_at,
			update_static_invoice_path,
			static_invoice_absolute_expiry,
		) = match context {
			AsyncPaymentsContext::StaticInvoicePersisted {
				offer,
				offer_nonce,
				offer_created_at,
				update_static_invoice_path,
				static_invoice_absolute_expiry,
				..
			} => (
				offer,
				offer_nonce,
				offer_created_at,
				update_static_invoice_path,
				static_invoice_absolute_expiry,
			),
			_ => return false,
		};

		if candidate_offer.is_expired_no_std(duration_since_epoch) {
			return false;
		}
		if static_invoice_absolute_expiry < duration_since_epoch {
			return false;
		}

		// If the candidate offer is known, either this is a duplicate message or we updated the
		// corresponding static invoice that is stored with the server.
		if let Some(existing_offer) =
			self.offers.iter_mut().find(|cached_offer| cached_offer.offer == candidate_offer)
		{
			// The blinded path used to update the static invoice corresponding to an offer should never
			// change because we reuse the same path every time we update.
			debug_assert_eq!(existing_offer.update_static_invoice_path, update_static_invoice_path);
			debug_assert_eq!(existing_offer.offer_nonce, candidate_offer_nonce);

			let needs_persist =
				existing_offer.static_invoice_absolute_expiry != static_invoice_absolute_expiry;

			// Since this is the most recent update we've received from the static invoice server, assume
			// that the invoice that was just persisted is the only invoice that the server has stored
			// corresponding to this offer.
			existing_offer.static_invoice_absolute_expiry = static_invoice_absolute_expiry;
			existing_offer.invoice_update_attempts = 0;

			return needs_persist;
		}

		let candidate_offer = AsyncReceiveOffer {
			offer: candidate_offer,
			offer_nonce: candidate_offer_nonce,
			offer_created_at,
			update_static_invoice_path,
			static_invoice_absolute_expiry,
			invoice_update_attempts: 0,
		};

		// An offer with 2 2-hop blinded paths has ~700 bytes, so this cache limit would allow up to
		// ~100 offers of that size.
		const MAX_CACHE_SIZE: usize = (1 << 10) * 70; // 70KiB
		const MAX_OFFERS: usize = 100;
		// If we have room in the cache, go ahead and add this new offer so we have more options. We
		// should generally never get close to the cache limit because we limit the number of requests
		// for offer persistence that are sent to begin with.
		if self.offers.len() < MAX_OFFERS && self.serialized_length() < MAX_CACHE_SIZE {
			self.offers.push(candidate_offer);
			return true;
		}

		// Swap out our lowest expiring offer for this candidate offer if needed. Otherwise we'd be
		// risking a situation where all of our existing offers expire soon but we still ignore this one
		// even though it's fresh.
		const NEVER_EXPIRES: Duration = Duration::from_secs(u64::MAX);
		let (soonest_expiring_offer_idx, soonest_offer_expiry) = self
			.offers
			.iter()
			.map(|offer| offer.offer.absolute_expiry().unwrap_or(NEVER_EXPIRES))
			.enumerate()
			.min_by(|(_, offer_exp_a), (_, offer_exp_b)| offer_exp_a.cmp(offer_exp_b))
			.unwrap_or_else(|| {
				debug_assert!(false);
				(0, NEVER_EXPIRES)
			});

		if soonest_offer_expiry < candidate_offer.offer.absolute_expiry().unwrap_or(NEVER_EXPIRES) {
			self.offers[soonest_expiring_offer_idx] = candidate_offer;
			return true;
		}

		false
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
