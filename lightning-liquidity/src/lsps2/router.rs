// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Router helpers for combining LSPS2 with BOLT12 offer flows.

use alloc::vec::Vec;

use crate::prelude::{new_hash_map, HashMap};
use crate::sync::Mutex;

use bitcoin::secp256k1::{self, PublicKey, Secp256k1};

use lightning::blinded_path::message::{
	BlindedMessagePath, MessageContext, MessageForwardNode, OffersContext,
};
use lightning::blinded_path::payment::{
	BlindedPaymentPath, Bolt12OfferContext, ForwardTlvs, PaymentConstraints, PaymentContext,
	PaymentForwardNode, PaymentRelay, ReceiveTlvs,
};
use lightning::ln::channel_state::ChannelDetails;
use lightning::ln::channelmanager::{PaymentId, MIN_FINAL_CLTV_EXPIRY_DELTA};
use lightning::offers::offer::OfferId;
use lightning::onion_message::messenger::{Destination, MessageRouter, OnionMessagePath};
use lightning::routing::router::{InFlightHtlcs, Route, RouteParameters, Router};
use lightning::sign::{EntropySource, ReceiveAuthKey};
use lightning::types::features::BlindedHopFeatures;
use lightning::types::payment::PaymentHash;

/// LSPS2 invoice parameters required to construct BOLT12 blinded payment paths through an LSP.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LSPS2Bolt12InvoiceParameters {
	/// The LSP node id to use as the blinded path introduction node.
	pub counterparty_node_id: PublicKey,
	/// The LSPS2 intercept short channel id.
	pub intercept_scid: u64,
	/// The CLTV expiry delta the LSP requires for forwarding over `intercept_scid`.
	pub cltv_expiry_delta: u32,
}

/// A router wrapper that injects LSPS2-specific BOLT12 blinded paths for registered offer ids
/// while delegating all other routing behavior to the inner routers.
///
/// For **payment** blinded paths (in invoices), it injects the intercept SCID as the forwarding
/// hop so that the LSP can intercept the HTLC and open a JIT channel.
///
/// For **message** blinded paths (in offers), it injects the intercept SCID as the
/// [`MessageForwardNode::short_channel_id`] so that [`Event::HTLCIntercepted`] is emitted when the
/// HTLC arrives, prompting the LSP to open the channel just-in-time.
///
/// The LSP must use an [`OnionMessenger`] that is setup via
/// [`OnionMessenger::new_with_offline_peer_interception`] so that forwarded messages are
/// intercepted rather than dropped.
///
/// [`OnionMessenger`]: lightning::onion_message::messenger::OnionMessenger
/// [`OnionMessenger::new_with_offline_peer_interception`]: lightning::onion_message::messenger::OnionMessenger::new_with_offline_peer_interception
/// [`Event::HTLCIntercepted`]: lightning::events::Event::HTLCIntercepted
pub struct LSPS2BOLT12Router<R: Router, MR: MessageRouter, ES: EntropySource + Send + Sync> {
	inner_router: R,
	inner_message_router: MR,
	entropy_source: ES,
	offer_to_invoice_params: Mutex<HashMap<[u8; 32], LSPS2Bolt12InvoiceParameters>>,
}

impl<R: Router, MR: MessageRouter, ES: EntropySource + Send + Sync> LSPS2BOLT12Router<R, MR, ES> {
	/// Constructs a new wrapper around `inner_router` and `inner_message_router`.
	pub fn new(inner_router: R, inner_message_router: MR, entropy_source: ES) -> Self {
		Self {
			inner_router,
			inner_message_router,
			entropy_source,
			offer_to_invoice_params: Mutex::new(new_hash_map()),
		}
	}

	/// Registers LSPS2 parameters to be used when generating blinded payment paths for `offer_id`.
	pub fn register_offer(
		&self, offer_id: OfferId, invoice_params: LSPS2Bolt12InvoiceParameters,
	) -> Option<LSPS2Bolt12InvoiceParameters> {
		self.offer_to_invoice_params.lock().unwrap().insert(offer_id.0, invoice_params)
	}

	/// Removes any previously registered LSPS2 parameters for `offer_id`.
	pub fn unregister_offer(&self, offer_id: &OfferId) -> Option<LSPS2Bolt12InvoiceParameters> {
		self.offer_to_invoice_params.lock().unwrap().remove(&offer_id.0)
	}

	/// Clears all LSPS2 parameters previously registered via [`Self::register_offer`].
	pub fn clear_registered_offers(&self) {
		self.offer_to_invoice_params.lock().unwrap().clear();
	}

	fn registered_lsps2_params(
		&self, payment_context: &PaymentContext,
	) -> Option<LSPS2Bolt12InvoiceParameters> {
		// We intentionally only match `Bolt12Offer` here and not `AsyncBolt12Offer`, as LSPS2
		// JIT channels are not applicable to async (always-online) BOLT12 offer flows.
		let Bolt12OfferContext { offer_id, .. } = match payment_context {
			PaymentContext::Bolt12Offer(context) => context,
			_ => return None,
		};

		self.offer_to_invoice_params.lock().unwrap().get(&offer_id.0).copied()
	}
}

impl<R: Router, MR: MessageRouter, ES: EntropySource + Send + Sync> Router
	for LSPS2BOLT12Router<R, MR, ES>
{
	fn find_route(
		&self, payer: &PublicKey, route_params: &RouteParameters,
		first_hops: Option<&[&ChannelDetails]>, inflight_htlcs: InFlightHtlcs,
	) -> Result<Route, &'static str> {
		self.inner_router.find_route(payer, route_params, first_hops, inflight_htlcs)
	}

	fn find_route_with_id(
		&self, payer: &PublicKey, route_params: &RouteParameters,
		first_hops: Option<&[&ChannelDetails]>, inflight_htlcs: InFlightHtlcs,
		payment_hash: PaymentHash, payment_id: PaymentId,
	) -> Result<Route, &'static str> {
		self.inner_router.find_route_with_id(
			payer,
			route_params,
			first_hops,
			inflight_htlcs,
			payment_hash,
			payment_id,
		)
	}

	fn create_blinded_payment_paths<T: secp256k1::Signing + secp256k1::Verification>(
		&self, recipient: PublicKey, local_node_receive_key: ReceiveAuthKey,
		first_hops: Vec<ChannelDetails>, tlvs: ReceiveTlvs, amount_msats: Option<u64>,
		secp_ctx: &Secp256k1<T>,
	) -> Result<Vec<BlindedPaymentPath>, ()> {
		let lsps2_invoice_params = match self.registered_lsps2_params(&tlvs.payment_context) {
			Some(params) => params,
			None => {
				return self.inner_router.create_blinded_payment_paths(
					recipient,
					local_node_receive_key,
					first_hops,
					tlvs,
					amount_msats,
					secp_ctx,
				)
			},
		};

		let payment_relay = PaymentRelay {
			cltv_expiry_delta: u16::try_from(lsps2_invoice_params.cltv_expiry_delta)
				.map_err(|_| ())?,
			fee_proportional_millionths: 0,
			fee_base_msat: 0,
		};
		let payment_constraints = PaymentConstraints {
			max_cltv_expiry: tlvs
				.payment_constraints
				.max_cltv_expiry
				.saturating_add(lsps2_invoice_params.cltv_expiry_delta),
			htlc_minimum_msat: 0,
		};

		let forward_node = PaymentForwardNode {
			tlvs: ForwardTlvs {
				short_channel_id: lsps2_invoice_params.intercept_scid,
				payment_relay,
				payment_constraints,
				features: BlindedHopFeatures::empty(),
				next_blinding_override: None,
			},
			node_id: lsps2_invoice_params.counterparty_node_id,
			htlc_maximum_msat: u64::MAX,
		};

		// We deliberately use `BlindedPaymentPath::new` without dummy hops here. Since the LSP
		// is the introduction node and already knows the recipient, adding dummy hops would not
		// provide meaningful privacy benefits in the LSPS2 JIT channel context.
		let path = BlindedPaymentPath::new(
			&[forward_node],
			recipient,
			local_node_receive_key,
			tlvs,
			u64::MAX,
			MIN_FINAL_CLTV_EXPIRY_DELTA,
			&self.entropy_source,
			secp_ctx,
		)?;

		Ok(vec![path])
	}
}

impl<R: Router, MR: MessageRouter, ES: EntropySource + Send + Sync> MessageRouter
	for LSPS2BOLT12Router<R, MR, ES>
{
	fn find_path(
		&self, sender: PublicKey, peers: Vec<PublicKey>, destination: Destination,
	) -> Result<OnionMessagePath, ()> {
		self.inner_message_router.find_path(sender, peers, destination)
	}

	fn create_blinded_paths<T: secp256k1::Signing + secp256k1::Verification>(
		&self, recipient: PublicKey, local_node_receive_key: ReceiveAuthKey,
		context: MessageContext, peers: Vec<MessageForwardNode>, secp_ctx: &Secp256k1<T>,
	) -> Result<Vec<BlindedMessagePath>, ()> {
		// Inject intercept SCIDs to have the payer use them when sending HTLCs, prompting the LSP
		// node to emit Event::HTLCIntercepted and hence trigger channel open
		let peers = match &context {
			MessageContext::Offers(OffersContext::InvoiceRequest { .. }) => {
				let params = self.offer_to_invoice_params.lock().unwrap();
				peers
					.into_iter()
					.map(|mut peer| {
						if let Some(p) =
							params.values().find(|p| p.counterparty_node_id == peer.node_id)
						{
							peer.short_channel_id = Some(p.intercept_scid);
						}
						peer
					})
					.collect()
			},
			_ => peers,
		};

		self.inner_message_router.create_blinded_paths(
			recipient,
			local_node_receive_key,
			context,
			peers,
			secp_ctx,
		)
	}
}

#[cfg(test)]
mod tests {
	use super::{LSPS2BOLT12Router, LSPS2Bolt12InvoiceParameters};

	use bitcoin::network::Network;
	use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};

	use lightning::blinded_path::payment::{
		Bolt12OfferContext, Bolt12RefundContext, PaymentConstraints, PaymentContext, ReceiveTlvs,
	};
	use lightning::blinded_path::NodeIdLookUp;
	use lightning::ln::channel_state::ChannelDetails;
	use lightning::ln::channelmanager::MIN_FINAL_CLTV_EXPIRY_DELTA;
	use lightning::offers::invoice_request::InvoiceRequestFields;
	use lightning::offers::offer::OfferId;
	use lightning::routing::router::{InFlightHtlcs, Route, RouteParameters, Router};
	use lightning::sign::{EntropySource, NodeSigner, ReceiveAuthKey, Recipient};
	use lightning::types::payment::PaymentSecret;
	use lightning::util::test_utils::TestKeysInterface;

	use crate::sync::Mutex;

	use core::sync::atomic::{AtomicUsize, Ordering};

	struct RecordingLookup {
		next_node_id: PublicKey,
		short_channel_id: Mutex<Option<u64>>,
	}

	impl NodeIdLookUp for RecordingLookup {
		fn next_node_id(&self, short_channel_id: u64) -> Option<PublicKey> {
			*self.short_channel_id.lock().unwrap() = Some(short_channel_id);
			Some(self.next_node_id)
		}
	}

	#[derive(Clone)]
	struct TestEntropy;

	impl EntropySource for TestEntropy {
		fn get_secure_random_bytes(&self) -> [u8; 32] {
			[42; 32]
		}
	}

	struct MockMessageRouter;

	impl lightning::onion_message::messenger::MessageRouter for MockMessageRouter {
		fn find_path(
			&self, _sender: PublicKey, _peers: Vec<PublicKey>,
			_destination: lightning::onion_message::messenger::Destination,
		) -> Result<lightning::onion_message::messenger::OnionMessagePath, ()> {
			Err(())
		}

		fn create_blinded_paths<
			T: bitcoin::secp256k1::Signing + bitcoin::secp256k1::Verification,
		>(
			&self, _recipient: PublicKey, _local_node_receive_key: lightning::sign::ReceiveAuthKey,
			_context: lightning::blinded_path::message::MessageContext,
			_peers: Vec<lightning::blinded_path::message::MessageForwardNode>,
			_secp_ctx: &Secp256k1<T>,
		) -> Result<Vec<lightning::blinded_path::message::BlindedMessagePath>, ()> {
			Err(())
		}
	}

	struct MockRouter {
		create_blinded_payment_paths_calls: AtomicUsize,
	}

	impl MockRouter {
		fn new() -> Self {
			Self { create_blinded_payment_paths_calls: AtomicUsize::new(0) }
		}

		fn create_blinded_payment_paths_calls(&self) -> usize {
			self.create_blinded_payment_paths_calls.load(Ordering::Acquire)
		}
	}

	impl Router for MockRouter {
		fn find_route(
			&self, _payer: &PublicKey, _route_params: &RouteParameters,
			_first_hops: Option<&[&ChannelDetails]>, _inflight_htlcs: InFlightHtlcs,
		) -> Result<Route, &'static str> {
			Err("mock router")
		}

		fn create_blinded_payment_paths<
			T: bitcoin::secp256k1::Signing + bitcoin::secp256k1::Verification,
		>(
			&self, _recipient: PublicKey, _local_node_receive_key: ReceiveAuthKey,
			_first_hops: Vec<ChannelDetails>, _tlvs: ReceiveTlvs, _amount_msats: Option<u64>,
			_secp_ctx: &Secp256k1<T>,
		) -> Result<Vec<lightning::blinded_path::payment::BlindedPaymentPath>, ()> {
			self.create_blinded_payment_paths_calls.fetch_add(1, Ordering::AcqRel);
			Err(())
		}
	}

	fn pubkey(byte: u8) -> PublicKey {
		let secret_key = SecretKey::from_slice(&[byte; 32]).unwrap();
		PublicKey::from_secret_key(&Secp256k1::new(), &secret_key)
	}

	fn bolt12_offer_tlvs(offer_id: OfferId) -> ReceiveTlvs {
		ReceiveTlvs {
			payment_secret: PaymentSecret([2; 32]),
			payment_constraints: PaymentConstraints { max_cltv_expiry: 100, htlc_minimum_msat: 1 },
			payment_context: PaymentContext::Bolt12Offer(Bolt12OfferContext {
				offer_id,
				invoice_request: InvoiceRequestFields {
					payer_signing_pubkey: pubkey(9),
					quantity: None,
					payer_note_truncated: None,
					human_readable_name: None,
				},
			}),
		}
	}

	fn bolt12_refund_tlvs() -> ReceiveTlvs {
		ReceiveTlvs {
			payment_secret: PaymentSecret([2; 32]),
			payment_constraints: PaymentConstraints { max_cltv_expiry: 100, htlc_minimum_msat: 1 },
			payment_context: PaymentContext::Bolt12Refund(Bolt12RefundContext {}),
		}
	}

	#[test]
	fn creates_lsps2_blinded_path_for_registered_offer() {
		let inner_router = MockRouter::new();
		let entropy_source = TestEntropy;
		let router = LSPS2BOLT12Router::new(inner_router, MockMessageRouter, entropy_source);

		let offer_id = OfferId([8; 32]);
		let lsp_keys = TestKeysInterface::new(&[43; 32], Network::Testnet);
		let lsp_node_id = lsp_keys.get_node_id(Recipient::Node).unwrap();

		let expected_scid = 42;
		let expected_cltv_delta = 48;
		let recipient = pubkey(10);

		router.register_offer(
			offer_id,
			LSPS2Bolt12InvoiceParameters {
				counterparty_node_id: lsp_node_id,
				intercept_scid: expected_scid,
				cltv_expiry_delta: expected_cltv_delta,
			},
		);

		let secp_ctx = Secp256k1::new();
		let mut paths = router
			.create_blinded_payment_paths(
				recipient,
				ReceiveAuthKey([3; 32]),
				Vec::new(),
				bolt12_offer_tlvs(offer_id),
				Some(5_000),
				&secp_ctx,
			)
			.unwrap();

		assert_eq!(paths.len(), 1);
		let mut path = paths.pop().unwrap();
		assert_eq!(
			path.introduction_node(),
			&lightning::blinded_path::IntroductionNode::NodeId(lsp_node_id)
		);
		assert_eq!(path.payinfo.fee_base_msat, 0);
		assert_eq!(path.payinfo.fee_proportional_millionths, 0);
		assert_eq!(
			path.payinfo.cltv_expiry_delta,
			expected_cltv_delta as u16 + MIN_FINAL_CLTV_EXPIRY_DELTA
		);

		let lookup =
			RecordingLookup { next_node_id: recipient, short_channel_id: Mutex::new(None) };
		path.advance_path_by_one(&lsp_keys, &lookup, &secp_ctx).unwrap();
		assert_eq!(*lookup.short_channel_id.lock().unwrap(), Some(expected_scid));
	}

	#[test]
	fn delegates_when_offer_is_not_registered() {
		let inner_router = MockRouter::new();
		let entropy_source = TestEntropy;
		let router = LSPS2BOLT12Router::new(inner_router, MockMessageRouter, entropy_source);
		let secp_ctx = Secp256k1::new();

		let result = router.create_blinded_payment_paths(
			pubkey(10),
			ReceiveAuthKey([3; 32]),
			Vec::new(),
			bolt12_refund_tlvs(),
			Some(10_000),
			&secp_ctx,
		);

		assert!(result.is_err());
		assert_eq!(router.inner_router.create_blinded_payment_paths_calls(), 1);
	}

	#[test]
	fn delegates_when_offer_id_is_not_registered() {
		let inner_router = MockRouter::new();
		let entropy_source = TestEntropy;
		let router = LSPS2BOLT12Router::new(inner_router, MockMessageRouter, entropy_source);
		let secp_ctx = Secp256k1::new();

		// Use a Bolt12Offer context with an OfferId that was never registered.
		let unregistered_offer_id = OfferId([99; 32]);
		let result = router.create_blinded_payment_paths(
			pubkey(10),
			ReceiveAuthKey([3; 32]),
			Vec::new(),
			bolt12_offer_tlvs(unregistered_offer_id),
			Some(10_000),
			&secp_ctx,
		);

		assert!(result.is_err());
		assert_eq!(router.inner_router.create_blinded_payment_paths_calls(), 1);
	}

	#[test]
	fn rejects_out_of_range_cltv_delta() {
		let inner_router = MockRouter::new();
		let entropy_source = TestEntropy;
		let router = LSPS2BOLT12Router::new(inner_router, MockMessageRouter, entropy_source);

		let offer_id = OfferId([11; 32]);
		router.register_offer(
			offer_id,
			LSPS2Bolt12InvoiceParameters {
				counterparty_node_id: pubkey(12),
				intercept_scid: 21,
				cltv_expiry_delta: u32::from(u16::MAX) + 1,
			},
		);

		let secp_ctx = Secp256k1::new();
		let result = router.create_blinded_payment_paths(
			pubkey(13),
			ReceiveAuthKey([3; 32]),
			Vec::new(),
			bolt12_offer_tlvs(offer_id),
			Some(1_000),
			&secp_ctx,
		);

		assert!(result.is_err());
	}

	#[test]
	fn can_unregister_offer() {
		let inner_router = MockRouter::new();
		let entropy_source = TestEntropy;
		let router = LSPS2BOLT12Router::new(inner_router, MockMessageRouter, entropy_source);

		let offer_id = OfferId([1; 32]);
		let params = LSPS2Bolt12InvoiceParameters {
			counterparty_node_id: pubkey(2),
			intercept_scid: 7,
			cltv_expiry_delta: 40,
		};
		assert_eq!(router.register_offer(offer_id, params), None);
		assert_eq!(router.unregister_offer(&offer_id), Some(params));
		assert_eq!(router.unregister_offer(&offer_id), None);
	}

	#[test]
	fn can_clear_registered_offers() {
		let inner_router = MockRouter::new();
		let entropy_source = TestEntropy;
		let router = LSPS2BOLT12Router::new(inner_router, MockMessageRouter, entropy_source);

		router.register_offer(
			OfferId([1; 32]),
			LSPS2Bolt12InvoiceParameters {
				counterparty_node_id: pubkey(2),
				intercept_scid: 7,
				cltv_expiry_delta: 40,
			},
		);
		router.register_offer(
			OfferId([2; 32]),
			LSPS2Bolt12InvoiceParameters {
				counterparty_node_id: pubkey(3),
				intercept_scid: 8,
				cltv_expiry_delta: 41,
			},
		);

		router.clear_registered_offers();
		assert_eq!(router.unregister_offer(&OfferId([1; 32])), None);
		assert_eq!(router.unregister_offer(&OfferId([2; 32])), None);
	}
}
