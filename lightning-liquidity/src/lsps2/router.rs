// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Router helpers for combining LSPS2 with BOLT12 offer flows.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use bitcoin::secp256k1::{self, PublicKey, Secp256k1};

use lightning::blinded_path::payment::{
	BlindedPaymentPath, ForwardTlvs, PaymentConstraints, PaymentContext, PaymentForwardNode,
	PaymentRelay, ReceiveTlvs,
};
use lightning::impl_ser_tlv_based;
use lightning::ln::channel_state::ChannelDetails;
use lightning::ln::channelmanager::{PaymentId, MIN_FINAL_CLTV_EXPIRY_DELTA};
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
	pub cltv_expiry_delta: u16,
}

impl_ser_tlv_based!(LSPS2Bolt12InvoiceParameters, {
	(0, counterparty_node_id, required),
	(2, intercept_scid, required),
	(4, cltv_expiry_delta, required),
});

/// Decodes LSPS2 BOLT12 invoice parameters from BOLT12 payment metadata.
///
/// LDK does not assign a key for LSPS2 metadata. Integrations should choose an application-specific
/// key, encode their data there, and provide a decoder that extracts any LSPS2 parameters which
/// should be converted into blinded payment paths.
pub trait LSPS2Bolt12PaymentMetadataDecoder {
	/// Returns all LSPS2 invoice parameters encoded in `payment_metadata`.
	fn decode_lsps2_invoice_parameters(
		&self, payment_metadata: &BTreeMap<u64, Vec<u8>>,
	) -> Vec<LSPS2Bolt12InvoiceParameters>;
}

impl LSPS2Bolt12PaymentMetadataDecoder for () {
	fn decode_lsps2_invoice_parameters(
		&self, _payment_metadata: &BTreeMap<u64, Vec<u8>>,
	) -> Vec<LSPS2Bolt12InvoiceParameters> {
		Vec::new()
	}
}

impl<F> LSPS2Bolt12PaymentMetadataDecoder for F
where
	F: Fn(&BTreeMap<u64, Vec<u8>>) -> Vec<LSPS2Bolt12InvoiceParameters>,
{
	fn decode_lsps2_invoice_parameters(
		&self, payment_metadata: &BTreeMap<u64, Vec<u8>>,
	) -> Vec<LSPS2Bolt12InvoiceParameters> {
		self(payment_metadata)
	}
}

/// A router wrapper that injects LSPS2-specific BOLT12 blinded payment paths based on the
/// payment metadata attached to BOLT12 offer contexts while delegating all other blinded path
/// creation behaviors to the inner router.
///
/// For **payment** blinded paths (in invoices), it appends paths using the intercept SCID as the
/// forwarding hop so that the LSP can intercept the HTLC and open a JIT channel. Paths from the
/// inner router (e.g., through pre-existing channels) are included as well, allowing payers to
/// use existing inbound liquidity when available.
///
/// This wrapper does **not** modify blinded onion-message paths. Async static-invoice and LSPS5
/// users should rely on their normal [`MessageRouter`] integration and any out-of-band SCID to
/// node-id resolution they maintain when handling [`Event::OnionMessageIntercepted`].
///
/// [`MessageRouter`]: lightning::onion_message::messenger::MessageRouter
/// [`Event::OnionMessageIntercepted`]: lightning::events::Event::OnionMessageIntercepted
/// [`Event::HTLCIntercepted`]: lightning::events::Event::HTLCIntercepted
pub struct LSPS2BOLT12Router<
	R: Router,
	ES: EntropySource,
	MD: LSPS2Bolt12PaymentMetadataDecoder = (),
> {
	inner_router: R,
	entropy_source: ES,
	payment_metadata_decoder: MD,
}

impl<R: Router, ES: EntropySource> LSPS2BOLT12Router<R, ES> {
	/// Constructs a new wrapper around `inner_router`.
	pub fn new(inner_router: R, entropy_source: ES) -> Self {
		Self { inner_router, entropy_source, payment_metadata_decoder: () }
	}
}

impl<R: Router, ES: EntropySource, MD: LSPS2Bolt12PaymentMetadataDecoder>
	LSPS2BOLT12Router<R, ES, MD>
{
	/// Constructs a new wrapper around `inner_router` which decodes LSPS2 parameters from BOLT12
	/// payment metadata using `payment_metadata_decoder`.
	pub fn new_with_payment_metadata_decoder(
		inner_router: R, entropy_source: ES, payment_metadata_decoder: MD,
	) -> Self {
		Self { inner_router, entropy_source, payment_metadata_decoder }
	}

	fn metadata_lsps2_params(
		&self, payment_context: &PaymentContext,
	) -> Vec<LSPS2Bolt12InvoiceParameters> {
		// LSPS2 paths are applicable both to normal offers and async offers that resolve via a
		// static invoice server. In both cases the intercept SCID lets the LSP intercept the HTLC
		// and open the JIT channel before forwarding the payment.
		match payment_context {
			PaymentContext::Bolt12Offer(_) | PaymentContext::AsyncBolt12Offer(_) => {},
			_ => return Vec::new(),
		};

		match payment_context.payment_metadata() {
			Some(metadata) => {
				self.payment_metadata_decoder.decode_lsps2_invoice_parameters(metadata)
			},
			None => Vec::new(),
		}
	}
}

impl<R: Router, ES: EntropySource, MD: LSPS2Bolt12PaymentMetadataDecoder> Router
	for LSPS2BOLT12Router<R, ES, MD>
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
		let all_params = self.metadata_lsps2_params(&tlvs.payment_context);
		if all_params.is_empty()
			&& first_hops.is_empty()
			&& matches!(&tlvs.payment_context, PaymentContext::AsyncBolt12Offer(_))
		{
			return Err(());
		}

		// Retrieve paths through existing channels from the inner router.
		let inner_res = self.inner_router.create_blinded_payment_paths(
			recipient,
			local_node_receive_key,
			first_hops,
			tlvs.clone(),
			amount_msats,
			secp_ctx,
		);

		// If no LSPS2 parameters were present in the payment metadata, just fallback to the inner
		// router's paths.
		if all_params.is_empty() {
			return inner_res;
		}

		// For metadata-derived parameters, add paths with intercept SCIDs to have the payer use
		// them when sending payments, prompting the LSP node to emit Event::HTLCIntercepted, hence
		// triggering channel open. We however also keep the inner paths so the payer can use
		// pre-existing inbound liquidity when available rather than always triggering a JIT channel
		// open. As BOLT12 specifies that paths should be ordered by preference, adding JIT-paths to
		// the end of the list *should* have the payer prefer pre-existing channels. However, there
		// of course is no guarantee that the payer's router will actually process the paths in this
		// exact order.
		let mut paths = inner_res.unwrap_or_default();
		for lsps2_invoice_params in all_params {
			let payment_relay = PaymentRelay {
				cltv_expiry_delta: lsps2_invoice_params.cltv_expiry_delta,
				fee_proportional_millionths: 0,
				fee_base_msat: 0,
			};
			let payment_constraints = PaymentConstraints {
				max_cltv_expiry: tlvs
					.payment_constraints
					.max_cltv_expiry
					.saturating_add(lsps2_invoice_params.cltv_expiry_delta as u32),
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
			// is a publicly-exposed introduction node and already knows the recipient, adding
			// dummy hops would not provide meaningful privacy benefits in the LSPS2 JIT channel
			// context.
			let path = match BlindedPaymentPath::new(
				&[forward_node],
				recipient,
				local_node_receive_key,
				tlvs.clone(),
				u64::MAX,
				MIN_FINAL_CLTV_EXPIRY_DELTA,
				&self.entropy_source,
				secp_ctx,
			) {
				Ok(path) => path,
				Err(()) => continue,
			};
			paths.push(path);
		}

		if paths.is_empty() {
			return Err(());
		}

		Ok(paths)
	}
}

#[cfg(test)]
mod tests {
	use super::{
		LSPS2BOLT12Router, LSPS2Bolt12InvoiceParameters, LSPS2Bolt12PaymentMetadataDecoder,
	};

	use alloc::collections::BTreeMap;
	use bitcoin::network::Network;
	use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};

	use lightning::blinded_path::payment::{
		AsyncBolt12OfferContext, BlindedPaymentPath, Bolt12OfferContext, Bolt12RefundContext,
		PaymentConstraints, PaymentContext, ReceiveTlvs,
	};
	use lightning::blinded_path::NodeIdLookUp;
	use lightning::ln::channel_state::ChannelDetails;
	use lightning::ln::channelmanager::MIN_FINAL_CLTV_EXPIRY_DELTA;
	use lightning::offers::invoice_request::InvoiceRequestFields;
	use lightning::offers::nonce::Nonce;
	use lightning::offers::offer::OfferId;
	use lightning::routing::router::{InFlightHtlcs, Route, RouteParameters, Router};
	use lightning::sign::{EntropySource, NodeSigner, ReceiveAuthKey, Recipient};
	use lightning::types::payment::PaymentSecret;
	use lightning::util::ser::{Readable, Writeable};
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

	#[derive(Clone, Copy)]
	struct TestMetadataDecoder;

	impl LSPS2Bolt12PaymentMetadataDecoder for TestMetadataDecoder {
		fn decode_lsps2_invoice_parameters(
			&self, payment_metadata: &BTreeMap<u64, Vec<u8>>,
		) -> Vec<LSPS2Bolt12InvoiceParameters> {
			payment_metadata
				.values()
				.filter_map(|encoded| {
					let mut reader = &encoded[..];
					LSPS2Bolt12InvoiceParameters::read(&mut reader).ok()
				})
				.collect()
		}
	}

	struct MockRouter {
		create_blinded_payment_paths_calls: AtomicUsize,
		paths_to_return: Mutex<Option<Vec<lightning::blinded_path::payment::BlindedPaymentPath>>>,
	}

	impl MockRouter {
		fn new() -> Self {
			Self {
				create_blinded_payment_paths_calls: AtomicUsize::new(0),
				paths_to_return: Mutex::new(None),
			}
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
			match self.paths_to_return.lock().unwrap().take() {
				Some(paths) => Ok(paths),
				None => Err(()),
			}
		}
	}

	fn pubkey(byte: u8) -> PublicKey {
		let secret_key = SecretKey::from_slice(&[byte; 32]).unwrap();
		PublicKey::from_secret_key(&Secp256k1::new(), &secret_key)
	}

	fn bolt12_offer_tlvs(offer_id: OfferId) -> ReceiveTlvs {
		bolt12_offer_tlvs_with_metadata(offer_id, None)
	}

	fn bolt12_offer_tlvs_with_metadata(
		offer_id: OfferId, payment_metadata: Option<BTreeMap<u64, Vec<u8>>>,
	) -> ReceiveTlvs {
		ReceiveTlvs {
			payment_secret: PaymentSecret([2; 32]),
			payment_constraints: PaymentConstraints { max_cltv_expiry: 100, htlc_minimum_msat: 1 },
			payment_context: PaymentContext::Bolt12Offer(Bolt12OfferContext {
				offer_id,
				payment_metadata,
				invoice_request: InvoiceRequestFields {
					payer_signing_pubkey: pubkey(9),
					quantity: None,
					payer_note_truncated: None,
					human_readable_name: None,
				},
			}),
		}
	}

	fn async_bolt12_offer_tlvs(
		offer_nonce: Nonce, payment_metadata: Option<BTreeMap<u64, Vec<u8>>>,
	) -> ReceiveTlvs {
		ReceiveTlvs {
			payment_secret: PaymentSecret([2; 32]),
			payment_constraints: PaymentConstraints { max_cltv_expiry: 100, htlc_minimum_msat: 1 },
			payment_context: PaymentContext::AsyncBolt12Offer(AsyncBolt12OfferContext {
				offer_nonce,
				payment_metadata,
			}),
		}
	}

	fn bolt12_refund_tlvs() -> ReceiveTlvs {
		ReceiveTlvs {
			payment_secret: PaymentSecret([2; 32]),
			payment_constraints: PaymentConstraints { max_cltv_expiry: 100, htlc_minimum_msat: 1 },
			payment_context: PaymentContext::Bolt12Refund(Bolt12RefundContext {
				payment_metadata: None,
			}),
		}
	}

	fn metadata_for_params(params: LSPS2Bolt12InvoiceParameters) -> BTreeMap<u64, Vec<u8>> {
		let mut encoded_params = Vec::new();
		params.write(&mut encoded_params).unwrap();
		let mut metadata = BTreeMap::new();
		metadata.insert(42, encoded_params);
		metadata
	}

	#[test]
	fn creates_lsps2_blinded_path_from_payment_metadata() {
		let inner_router = MockRouter::new();
		let entropy_source = TestEntropy;
		let router = LSPS2BOLT12Router::new_with_payment_metadata_decoder(
			inner_router,
			entropy_source,
			TestMetadataDecoder,
		);

		let offer_id = OfferId([8; 32]);
		let lsp_keys = TestKeysInterface::new(&[43; 32], Network::Testnet);
		let lsp_node_id = lsp_keys.get_node_id(Recipient::Node).unwrap();

		let expected_scid = 42;
		let expected_cltv_delta = 48;
		let recipient = pubkey(10);

		let metadata = metadata_for_params(LSPS2Bolt12InvoiceParameters {
			counterparty_node_id: lsp_node_id,
			intercept_scid: expected_scid,
			cltv_expiry_delta: expected_cltv_delta,
		});

		let secp_ctx = Secp256k1::new();
		let mut paths = router
			.create_blinded_payment_paths(
				recipient,
				ReceiveAuthKey([3; 32]),
				Vec::new(),
				bolt12_offer_tlvs_with_metadata(offer_id, Some(metadata)),
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
			expected_cltv_delta + MIN_FINAL_CLTV_EXPIRY_DELTA
		);

		let lookup =
			RecordingLookup { next_node_id: recipient, short_channel_id: Mutex::new(None) };
		path.advance_path_by_one(&lsp_keys, &lookup, &secp_ctx).unwrap();
		assert_eq!(*lookup.short_channel_id.lock().unwrap(), Some(expected_scid));
	}

	#[test]
	fn delegates_when_context_is_not_bolt12_offer() {
		let inner_router = MockRouter::new();
		let entropy_source = TestEntropy;
		let router = LSPS2BOLT12Router::new(inner_router, entropy_source);
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
	fn delegates_when_no_intercept_scid_is_registered() {
		let inner_router = MockRouter::new();
		let entropy_source = TestEntropy;
		let router = LSPS2BOLT12Router::new(inner_router, entropy_source);
		let secp_ctx = Secp256k1::new();

		// Use a Bolt12Offer context without any registered intercept SCIDs.
		let offer_id = OfferId([99; 32]);
		let result = router.create_blinded_payment_paths(
			pubkey(10),
			ReceiveAuthKey([3; 32]),
			Vec::new(),
			bolt12_offer_tlvs(offer_id),
			Some(10_000),
			&secp_ctx,
		);

		assert!(result.is_err());
		assert_eq!(router.inner_router.create_blinded_payment_paths_calls(), 1);
	}

	#[test]
	fn errors_for_async_offer_without_metadata_or_first_hops() {
		let inner_router = MockRouter::new();
		let recipient = pubkey(10);
		let secp_ctx = Secp256k1::new();
		let tlvs = async_bolt12_offer_tlvs(Nonce::from_entropy_source(TestEntropy), None);
		let inner_path = BlindedPaymentPath::new(
			&[],
			recipient,
			ReceiveAuthKey([3; 32]),
			tlvs.clone(),
			u64::MAX,
			MIN_FINAL_CLTV_EXPIRY_DELTA,
			&TestEntropy,
			&secp_ctx,
		)
		.unwrap();
		*inner_router.paths_to_return.lock().unwrap() = Some(vec![inner_path]);

		let router = LSPS2BOLT12Router::new_with_payment_metadata_decoder(
			inner_router,
			TestEntropy,
			TestMetadataDecoder,
		);
		let result = router.create_blinded_payment_paths(
			recipient,
			ReceiveAuthKey([3; 32]),
			Vec::new(),
			tlvs,
			Some(10_000),
			&secp_ctx,
		);

		assert!(result.is_err());
		assert_eq!(router.inner_router.create_blinded_payment_paths_calls(), 0);
	}

	#[test]
	fn creates_paths_for_all_metadata_intercept_scids() {
		let inner_router = MockRouter::new();
		let entropy_source = TestEntropy;
		let router = LSPS2BOLT12Router::new_with_payment_metadata_decoder(
			inner_router,
			entropy_source,
			TestMetadataDecoder,
		);

		let lsp_keys_a = TestKeysInterface::new(&[43; 32], Network::Testnet);
		let lsp_node_id_a = lsp_keys_a.get_node_id(Recipient::Node).unwrap();
		let scid_a = 100;

		let lsp_keys_b = TestKeysInterface::new(&[44; 32], Network::Testnet);
		let lsp_node_id_b = lsp_keys_b.get_node_id(Recipient::Node).unwrap();
		let scid_b = 200;

		let mut metadata = metadata_for_params(LSPS2Bolt12InvoiceParameters {
			counterparty_node_id: lsp_node_id_a,
			intercept_scid: scid_a,
			cltv_expiry_delta: 48,
		});
		let mut encoded_b = Vec::new();
		LSPS2Bolt12InvoiceParameters {
			counterparty_node_id: lsp_node_id_b,
			intercept_scid: scid_b,
			cltv_expiry_delta: 72,
		}
		.write(&mut encoded_b)
		.unwrap();
		metadata.insert(43, encoded_b);

		let recipient = pubkey(10);
		let secp_ctx = Secp256k1::new();
		let paths = router
			.create_blinded_payment_paths(
				recipient,
				ReceiveAuthKey([3; 32]),
				Vec::new(),
				bolt12_offer_tlvs_with_metadata(OfferId([8; 32]), Some(metadata)),
				Some(5_000),
				&secp_ctx,
			)
			.unwrap();

		assert_eq!(paths.len(), 2);

		// Verify each path uses a distinct intercept SCID by advancing through the LSP hop.
		let mut seen_scids = std::collections::HashSet::new();
		for mut path in paths {
			let (keys, node_id) = if path.introduction_node()
				== &lightning::blinded_path::IntroductionNode::NodeId(lsp_node_id_a)
			{
				(&lsp_keys_a, lsp_node_id_a)
			} else {
				(&lsp_keys_b, lsp_node_id_b)
			};
			let _ = node_id;

			let lookup =
				RecordingLookup { next_node_id: recipient, short_channel_id: Mutex::new(None) };
			path.advance_path_by_one(keys, &lookup, &secp_ctx).unwrap();
			let scid = lookup.short_channel_id.lock().unwrap().unwrap();
			seen_scids.insert(scid);
		}

		assert!(seen_scids.contains(&scid_a), "Path for SCID {} missing", scid_a);
		assert!(seen_scids.contains(&scid_b), "Path for SCID {} missing", scid_b);

		// Inner router is always called to include paths through existing channels.
		// It returned Err here, so only the LSPS2 paths are present.
		assert_eq!(router.inner_router.create_blinded_payment_paths_calls(), 1);
	}

	#[test]
	fn includes_inner_router_paths_alongside_lsps2_paths() {
		let inner_router = MockRouter::new();
		let lsp_keys = TestKeysInterface::new(&[43; 32], Network::Testnet);
		let lsp_node_id = lsp_keys.get_node_id(Recipient::Node).unwrap();
		let recipient = pubkey(10);
		let secp_ctx = Secp256k1::new();

		// Pre-create a blinded path as if the inner router built it from an existing channel.
		let existing_tlvs = bolt12_offer_tlvs(OfferId([8; 32]));
		let existing_path = lightning::blinded_path::payment::BlindedPaymentPath::new(
			&[],
			recipient,
			ReceiveAuthKey([3; 32]),
			existing_tlvs,
			u64::MAX,
			MIN_FINAL_CLTV_EXPIRY_DELTA,
			&TestEntropy,
			&secp_ctx,
		)
		.unwrap();
		*inner_router.paths_to_return.lock().unwrap() = Some(vec![existing_path]);

		let router = LSPS2BOLT12Router::new_with_payment_metadata_decoder(
			inner_router,
			TestEntropy,
			TestMetadataDecoder,
		);

		let intercept_scid = 42;
		let metadata = metadata_for_params(LSPS2Bolt12InvoiceParameters {
			counterparty_node_id: lsp_node_id,
			intercept_scid,
			cltv_expiry_delta: 48,
		});

		let paths = router
			.create_blinded_payment_paths(
				recipient,
				ReceiveAuthKey([3; 32]),
				Vec::new(),
				bolt12_offer_tlvs_with_metadata(OfferId([8; 32]), Some(metadata)),
				Some(5_000),
				&secp_ctx,
			)
			.unwrap();

		// Should contain both the LSPS2 intercept path and the inner router's existing
		// channel path.
		assert_eq!(paths.len(), 2);
		assert_eq!(router.inner_router.create_blinded_payment_paths_calls(), 1);
	}

	#[test]
	fn lsps2_paths_returned_even_when_inner_router_fails() {
		let inner_router = MockRouter::new();
		// paths_to_return is None, so inner router returns Err(())
		let lsp_keys = TestKeysInterface::new(&[43; 32], Network::Testnet);
		let lsp_node_id = lsp_keys.get_node_id(Recipient::Node).unwrap();
		let recipient = pubkey(10);
		let secp_ctx = Secp256k1::new();

		let router = LSPS2BOLT12Router::new_with_payment_metadata_decoder(
			inner_router,
			TestEntropy,
			TestMetadataDecoder,
		);

		let intercept_scid = 42;
		let metadata = metadata_for_params(LSPS2Bolt12InvoiceParameters {
			counterparty_node_id: lsp_node_id,
			intercept_scid,
			cltv_expiry_delta: 48,
		});

		let paths = router
			.create_blinded_payment_paths(
				recipient,
				ReceiveAuthKey([3; 32]),
				Vec::new(),
				bolt12_offer_tlvs_with_metadata(OfferId([8; 32]), Some(metadata)),
				Some(5_000),
				&secp_ctx,
			)
			.unwrap();

		// Only the LSPS2 path, since the inner router failed.
		assert_eq!(paths.len(), 1);
		assert_eq!(router.inner_router.create_blinded_payment_paths_calls(), 1);
	}
}
