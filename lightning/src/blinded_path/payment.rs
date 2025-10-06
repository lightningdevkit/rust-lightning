// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Data structures and methods for constructing [`BlindedPaymentPath`]s to send a payment over.

use bitcoin::hashes::hmac::Hmac;
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::secp256k1::ecdh::SharedSecret;
use bitcoin::secp256k1::{self, PublicKey, Secp256k1, SecretKey};

use crate::blinded_path::utils::{self, BlindedPathWithPadding};
use crate::blinded_path::{BlindedHop, BlindedPath, IntroductionNode, NodeIdLookUp};
use crate::crypto::streams::ChaChaDualPolyReadAdapter;
use crate::io;
use crate::io::Cursor;
use crate::ln::channel_state::CounterpartyForwardingInfo;
use crate::ln::channelmanager::Verification;
use crate::ln::inbound_payment::ExpandedKey;
use crate::ln::msgs::DecodeError;
use crate::ln::onion_utils;
use crate::offers::invoice_request::InvoiceRequestFields;
use crate::offers::nonce::Nonce;
use crate::offers::offer::OfferId;
use crate::routing::gossip::{NodeId, ReadOnlyNetworkGraph};
use crate::sign::{EntropySource, NodeSigner, ReceiveAuthKey, Recipient};
use crate::types::features::BlindedHopFeatures;
use crate::types::payment::PaymentSecret;
use crate::types::routing::RoutingFees;
use crate::util::ser::{
	FixedLengthReader, HighZeroBytesDroppedBigSize, LengthReadableArgs, Readable, WithoutLength,
	Writeable, Writer,
};

use core::mem;
use core::ops::Deref;

#[allow(unused_imports)]
use crate::prelude::*;

/// Information needed to route a payment across a [`BlindedPaymentPath`].
#[derive(Clone, Debug, Hash, Eq, PartialEq)]
pub struct BlindedPayInfo {
	/// Base fee charged (in millisatoshi) for the entire blinded path.
	pub fee_base_msat: u32,

	/// Liquidity fee charged (in millionths of the amount transferred) for the entire blinded path
	/// (i.e., 10,000 is 1%).
	pub fee_proportional_millionths: u32,

	/// Number of blocks subtracted from an incoming HTLC's `cltv_expiry` for the entire blinded
	/// path.
	pub cltv_expiry_delta: u16,

	/// The minimum HTLC value (in millisatoshi) that is acceptable to all channel peers on the
	/// blinded path from the introduction node to the recipient, accounting for any fees, i.e., as
	/// seen by the recipient.
	pub htlc_minimum_msat: u64,

	/// The maximum HTLC value (in millisatoshi) that is acceptable to all channel peers on the
	/// blinded path from the introduction node to the recipient, accounting for any fees, i.e., as
	/// seen by the recipient.
	pub htlc_maximum_msat: u64,

	/// Features set in `encrypted_data_tlv` for the `encrypted_recipient_data` TLV record in an
	/// onion payload.
	pub features: BlindedHopFeatures,
}

impl_writeable!(BlindedPayInfo, {
	fee_base_msat,
	fee_proportional_millionths,
	cltv_expiry_delta,
	htlc_minimum_msat,
	htlc_maximum_msat,
	features
});

/// A blinded path to be used for sending or receiving a payment, hiding the identity of the
/// recipient.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct BlindedPaymentPath {
	pub(super) inner_path: BlindedPath,
	/// The [`BlindedPayInfo`] used to pay this blinded path.
	pub payinfo: BlindedPayInfo,
}

impl BlindedPaymentPath {
	/// Create a one-hop blinded path for a payment.
	pub fn one_hop<ES: Deref, T: secp256k1::Signing + secp256k1::Verification>(
		payee_node_id: PublicKey, receive_auth_key: ReceiveAuthKey, payee_tlvs: ReceiveTlvs,
		min_final_cltv_expiry_delta: u16, entropy_source: ES, secp_ctx: &Secp256k1<T>,
	) -> Result<Self, ()>
	where
		ES::Target: EntropySource,
	{
		// This value is not considered in pathfinding for 1-hop blinded paths, because it's intended to
		// be in relation to a specific channel.
		let htlc_maximum_msat = u64::max_value();
		Self::new(
			&[],
			payee_node_id,
			receive_auth_key,
			payee_tlvs,
			htlc_maximum_msat,
			min_final_cltv_expiry_delta,
			entropy_source,
			secp_ctx,
		)
	}

	/// Create a blinded path for a payment, to be forwarded along `intermediate_nodes`.
	///
	/// Errors if:
	/// * [`BlindedPayInfo`] calculation results in an integer overflow
	/// * any unknown features are required in the provided [`ForwardTlvs`]
	//  TODO: make all payloads the same size with padding + add dummy hops
	pub fn new<ES: Deref, T: secp256k1::Signing + secp256k1::Verification>(
		intermediate_nodes: &[PaymentForwardNode], payee_node_id: PublicKey,
		receive_auth_key: ReceiveAuthKey, payee_tlvs: ReceiveTlvs, htlc_maximum_msat: u64,
		min_final_cltv_expiry_delta: u16, entropy_source: ES, secp_ctx: &Secp256k1<T>,
	) -> Result<Self, ()>
	where
		ES::Target: EntropySource,
	{
		let introduction_node = IntroductionNode::NodeId(
			intermediate_nodes.first().map_or(payee_node_id, |n| n.node_id),
		);
		let blinding_secret_bytes = entropy_source.get_secure_random_bytes();
		let blinding_secret =
			SecretKey::from_slice(&blinding_secret_bytes[..]).expect("RNG is busted");

		let blinded_payinfo = compute_payinfo(
			intermediate_nodes,
			&payee_tlvs.tlvs,
			htlc_maximum_msat,
			min_final_cltv_expiry_delta,
		)?;
		Ok(Self {
			inner_path: BlindedPath {
				introduction_node,
				blinding_point: PublicKey::from_secret_key(secp_ctx, &blinding_secret),
				blinded_hops: blinded_hops(
					secp_ctx,
					intermediate_nodes,
					payee_node_id,
					payee_tlvs,
					&blinding_secret,
					receive_auth_key,
				),
			},
			payinfo: blinded_payinfo,
		})
	}

	/// Returns the introduction [`NodeId`] of the blinded path, if it is publicly reachable (i.e.,
	/// it is found in the network graph).
	pub fn public_introduction_node_id<'a>(
		&self, network_graph: &'a ReadOnlyNetworkGraph,
	) -> Option<&'a NodeId> {
		self.inner_path.public_introduction_node_id(network_graph)
	}

	/// The [`IntroductionNode`] of the blinded path.
	pub fn introduction_node(&self) -> &IntroductionNode {
		&self.inner_path.introduction_node
	}

	/// Used by the [`IntroductionNode`] to decrypt its [`encrypted_payload`] to forward the payment.
	///
	/// [`encrypted_payload`]: BlindedHop::encrypted_payload
	pub fn blinding_point(&self) -> PublicKey {
		self.inner_path.blinding_point
	}

	/// The [`BlindedHop`]s within the blinded path.
	pub fn blinded_hops(&self) -> &[BlindedHop] {
		&self.inner_path.blinded_hops
	}

	/// Advance the blinded onion payment path by one hop, making the second hop into the new
	/// introduction node.
	///
	/// Will only modify `self` when returning `Ok`.
	pub fn advance_path_by_one<NS: Deref, NL: Deref, T>(
		&mut self, node_signer: &NS, node_id_lookup: &NL, secp_ctx: &Secp256k1<T>,
	) -> Result<(), ()>
	where
		NS::Target: NodeSigner,
		NL::Target: NodeIdLookUp,
		T: secp256k1::Signing + secp256k1::Verification,
	{
		match self.decrypt_intro_payload::<NS>(node_signer) {
			Ok((
				BlindedPaymentTlvs::Forward(ForwardTlvs { short_channel_id, .. }),
				control_tlvs_ss,
			)) => {
				let next_node_id = match node_id_lookup.next_node_id(short_channel_id) {
					Some(node_id) => node_id,
					None => return Err(()),
				};
				let mut new_blinding_point = onion_utils::next_hop_pubkey(
					secp_ctx,
					self.inner_path.blinding_point,
					control_tlvs_ss.as_ref(),
				)
				.map_err(|_| ())?;
				mem::swap(&mut self.inner_path.blinding_point, &mut new_blinding_point);
				self.inner_path.introduction_node = IntroductionNode::NodeId(next_node_id);
				self.inner_path.blinded_hops.remove(0);
				Ok(())
			},
			_ => Err(()),
		}
	}

	pub(crate) fn decrypt_intro_payload<NS: Deref>(
		&self, node_signer: &NS,
	) -> Result<(BlindedPaymentTlvs, SharedSecret), ()>
	where
		NS::Target: NodeSigner,
	{
		let control_tlvs_ss =
			node_signer.ecdh(Recipient::Node, &self.inner_path.blinding_point, None)?;
		let rho = onion_utils::gen_rho_from_shared_secret(&control_tlvs_ss.secret_bytes());
		let receive_auth_key = node_signer.get_receive_auth_key();
		let encrypted_control_tlvs =
			&self.inner_path.blinded_hops.get(0).ok_or(())?.encrypted_payload;
		let mut s = Cursor::new(encrypted_control_tlvs);
		let mut reader = FixedLengthReader::new(&mut s, encrypted_control_tlvs.len() as u64);
		match ChaChaDualPolyReadAdapter::read(&mut reader, (rho, receive_auth_key.0)) {
			Ok(ChaChaDualPolyReadAdapter { readable, .. }) => Ok((readable, control_tlvs_ss)),
			_ => Err(()),
		}
	}

	pub(crate) fn inner_blinded_path(&self) -> &BlindedPath {
		&self.inner_path
	}

	pub(crate) fn from_parts(inner_path: BlindedPath, payinfo: BlindedPayInfo) -> Self {
		Self { inner_path, payinfo }
	}

	/// Builds a new [`BlindedPaymentPath`] from its constituent parts.
	///
	/// Useful when reconstructing a blinded path from previously serialized components.
	///
	/// Parameters:
	/// * `introduction_node_id`: The public key of the introduction node in the path.
	/// * `blinding_point`: The public key used for blinding the path.
	/// * `blinded_hops`: The encrypted routing information for each hop in the path.
	/// * `payinfo`: The [`BlindedPayInfo`] for the blinded path.
	pub fn from_blinded_path_and_payinfo(
		introduction_node_id: PublicKey, blinding_point: PublicKey, blinded_hops: Vec<BlindedHop>,
		payinfo: BlindedPayInfo,
	) -> Self {
		Self::from_parts(
			BlindedPath {
				introduction_node: IntroductionNode::NodeId(introduction_node_id),
				blinding_point,
				blinded_hops,
			},
			payinfo,
		)
	}

	#[cfg(test)]
	pub fn clear_blinded_hops(&mut self) {
		self.inner_path.blinded_hops.clear()
	}
}

/// An intermediate node, its outbound channel, and relay parameters.
#[derive(Clone, Debug)]
pub struct PaymentForwardNode {
	/// The TLVs for this node's [`BlindedHop`], where the fee parameters contained within are also
	/// used for [`BlindedPayInfo`] construction.
	pub tlvs: ForwardTlvs,
	/// This node's pubkey.
	pub node_id: PublicKey,
	/// The maximum value, in msat, that may be accepted by this node.
	pub htlc_maximum_msat: u64,
}

/// Data to construct a [`BlindedHop`] for forwarding a payment.
#[derive(Clone, Debug)]
pub struct ForwardTlvs {
	/// The short channel id this payment should be forwarded out over.
	pub short_channel_id: u64,
	/// Payment parameters for relaying over [`Self::short_channel_id`].
	pub payment_relay: PaymentRelay,
	/// Payment constraints for relaying over [`Self::short_channel_id`].
	pub payment_constraints: PaymentConstraints,
	/// Supported and required features when relaying a payment onion containing this object's
	/// corresponding [`BlindedHop::encrypted_payload`].
	///
	/// [`BlindedHop::encrypted_payload`]: crate::blinded_path::BlindedHop::encrypted_payload
	pub features: BlindedHopFeatures,
	/// Set if this [`BlindedPaymentPath`] is concatenated to another, to indicate the
	/// [`BlindedPaymentPath::blinding_point`] of the appended blinded path.
	pub next_blinding_override: Option<PublicKey>,
}

/// Data to construct a [`BlindedHop`] for forwarding a Trampoline payment.
#[derive(Clone, Debug)]
pub struct TrampolineForwardTlvs {
	/// The node id to which the trampoline node must find a route.
	pub next_trampoline: PublicKey,
	/// Payment parameters for relaying over [`Self::next_trampoline`].
	pub payment_relay: PaymentRelay,
	/// Payment constraints for relaying over [`Self::next_trampoline`].
	pub payment_constraints: PaymentConstraints,
	/// Supported and required features when relaying a payment onion containing this object's
	/// corresponding [`BlindedHop::encrypted_payload`].
	///
	/// [`BlindedHop::encrypted_payload`]: crate::blinded_path::BlindedHop::encrypted_payload
	pub features: BlindedHopFeatures,
	/// Set if this [`BlindedPaymentPath`] is concatenated to another, to indicate the
	/// [`BlindedPaymentPath::blinding_point`] of the appended blinded path.
	pub next_blinding_override: Option<PublicKey>,
}

/// Data to construct a [`BlindedHop`] for receiving a payment. This payload is custom to LDK and
/// may not be valid if received by another lightning implementation.
///
/// Can only be constructed by calling [`UnauthenticatedReceiveTlvs::authenticate`].
#[derive(Clone, Debug)]
pub struct ReceiveTlvs {
	/// The TLVs for which the HMAC in `authentication` is derived.
	pub(crate) tlvs: UnauthenticatedReceiveTlvs,
	/// An HMAC of `tlvs` along with a nonce used to construct it.
	pub(crate) authentication: (Hmac<Sha256>, Nonce),
}

impl ReceiveTlvs {
	/// Returns the underlying TLVs.
	pub fn tlvs(&self) -> &UnauthenticatedReceiveTlvs {
		&self.tlvs
	}
}

/// An unauthenticated [`ReceiveTlvs`].
#[derive(Clone, Debug)]
pub struct UnauthenticatedReceiveTlvs {
	/// Used to authenticate the sender of a payment to the receiver and tie MPP HTLCs together.
	pub payment_secret: PaymentSecret,
	/// Constraints for the receiver of this payment.
	pub payment_constraints: PaymentConstraints,
	/// Context for the receiver of this payment.
	pub payment_context: PaymentContext,
}

impl UnauthenticatedReceiveTlvs {
	/// Creates an authenticated [`ReceiveTlvs`], which includes an HMAC and the provide [`Nonce`]
	/// that can be use later to verify it authenticity.
	pub fn authenticate(self, nonce: Nonce, expanded_key: &ExpandedKey) -> ReceiveTlvs {
		ReceiveTlvs {
			authentication: (self.hmac_for_offer_payment(nonce, expanded_key), nonce),
			tlvs: self,
		}
	}
}

/// Data to construct a [`BlindedHop`] for sending a payment over.
///
/// [`BlindedHop`]: crate::blinded_path::BlindedHop
pub(crate) enum BlindedPaymentTlvs {
	/// This blinded payment data is for a forwarding node.
	Forward(ForwardTlvs),
	/// This blinded payment data is for the receiving node.
	Receive(ReceiveTlvs),
}

/// Data to construct a [`BlindedHop`] for sending a Trampoline payment over.
///
/// [`BlindedHop`]: crate::blinded_path::BlindedHop
pub(crate) enum BlindedTrampolineTlvs {
	/// This blinded payment data is for a forwarding node.
	Forward(TrampolineForwardTlvs),
	/// This blinded payment data is for the receiving node.
	Receive(ReceiveTlvs),
}

// Used to include forward and receive TLVs in the same iterator for encoding.
enum BlindedPaymentTlvsRef<'a> {
	Forward(&'a ForwardTlvs),
	Receive(&'a ReceiveTlvs),
}

/// Parameters for relaying over a given [`BlindedHop`].
///
/// [`BlindedHop`]: crate::blinded_path::BlindedHop
#[derive(Clone, Debug, PartialEq)]
pub struct PaymentRelay {
	/// Number of blocks subtracted from an incoming HTLC's `cltv_expiry` for this [`BlindedHop`].
	pub cltv_expiry_delta: u16,
	/// Liquidity fee charged (in millionths of the amount transferred) for relaying a payment over
	/// this [`BlindedHop`], (i.e., 10,000 is 1%).
	pub fee_proportional_millionths: u32,
	/// Base fee charged (in millisatoshi) for relaying a payment over this [`BlindedHop`].
	pub fee_base_msat: u32,
}

/// Constraints for relaying over a given [`BlindedHop`].
///
/// [`BlindedHop`]: crate::blinded_path::BlindedHop
#[derive(Clone, Debug, PartialEq)]
pub struct PaymentConstraints {
	/// The maximum total CLTV that is acceptable when relaying a payment over this [`BlindedHop`].
	pub max_cltv_expiry: u32,
	/// The minimum value, in msat, that may be accepted by the node corresponding to this
	/// [`BlindedHop`].
	pub htlc_minimum_msat: u64,
}

/// The context of an inbound payment, which is included in a [`BlindedPaymentPath`] via
/// [`ReceiveTlvs`] and surfaced in [`PaymentPurpose`].
///
/// [`PaymentPurpose`]: crate::events::PaymentPurpose
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PaymentContext {
	/// The payment was made for an invoice requested from a BOLT 12 [`Offer`].
	///
	/// [`Offer`]: crate::offers::offer::Offer
	Bolt12Offer(Bolt12OfferContext),

	/// The payment was made for a static invoice requested from a BOLT 12 [`Offer`].
	///
	/// [`Offer`]: crate::offers::offer::Offer
	AsyncBolt12Offer(AsyncBolt12OfferContext),

	/// The payment was made for an invoice sent for a BOLT 12 [`Refund`].
	///
	/// [`Refund`]: crate::offers::refund::Refund
	Bolt12Refund(Bolt12RefundContext),
}

// Used when writing PaymentContext in Event::PaymentClaimable to avoid cloning.
pub(crate) enum PaymentContextRef<'a> {
	Bolt12Offer(&'a Bolt12OfferContext),
	Bolt12Refund(&'a Bolt12RefundContext),
}

/// The context of a payment made for an invoice requested from a BOLT 12 [`Offer`].
///
/// [`Offer`]: crate::offers::offer::Offer
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Bolt12OfferContext {
	/// The identifier of the [`Offer`].
	///
	/// [`Offer`]: crate::offers::offer::Offer
	pub offer_id: OfferId,

	/// Fields from an [`InvoiceRequest`] sent for a [`Bolt12Invoice`].
	///
	/// [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
	/// [`Bolt12Invoice`]: crate::offers::invoice::Bolt12Invoice
	pub invoice_request: InvoiceRequestFields,
}

/// The context of a payment made for a static invoice requested from a BOLT 12 [`Offer`].
///
/// [`Offer`]: crate::offers::offer::Offer
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AsyncBolt12OfferContext {
	/// The [`Nonce`] used to verify that an inbound [`InvoiceRequest`] corresponds to this static
	/// invoice's offer.
	///
	/// [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
	pub offer_nonce: Nonce,
}

/// The context of a payment made for an invoice sent for a BOLT 12 [`Refund`].
///
/// [`Refund`]: crate::offers::refund::Refund
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Bolt12RefundContext {}

impl TryFrom<CounterpartyForwardingInfo> for PaymentRelay {
	type Error = ();

	fn try_from(info: CounterpartyForwardingInfo) -> Result<Self, ()> {
		let CounterpartyForwardingInfo {
			fee_base_msat,
			fee_proportional_millionths,
			cltv_expiry_delta,
		} = info;

		// Avoid exposing esoteric CLTV expiry deltas
		let cltv_expiry_delta = match cltv_expiry_delta {
			0..=40 => 40,
			41..=80 => 80,
			81..=144 => 144,
			145..=216 => 216,
			_ => return Err(()),
		};

		Ok(Self { cltv_expiry_delta, fee_proportional_millionths, fee_base_msat })
	}
}

impl Writeable for ForwardTlvs {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		let features_opt = if self.features == BlindedHopFeatures::empty() {
			None
		} else {
			Some(WithoutLength(&self.features))
		};
		encode_tlv_stream!(w, {
			(2, self.short_channel_id, required),
			(10, self.payment_relay, required),
			(12, self.payment_constraints, required),
			(14, features_opt, option)
		});
		Ok(())
	}
}

impl Writeable for TrampolineForwardTlvs {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		let features_opt = if self.features == BlindedHopFeatures::empty() {
			None
		} else {
			Some(WithoutLength(&self.features))
		};
		encode_tlv_stream!(w, {
			(4, self.next_trampoline, required),
			(10, self.payment_relay, required),
			(12, self.payment_constraints, required),
			(14, features_opt, option)
		});
		Ok(())
	}
}

impl Writeable for ReceiveTlvs {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		encode_tlv_stream!(w, {
			(12, self.tlvs.payment_constraints, required),
			(65536, self.tlvs.payment_secret, required),
			(65537, self.tlvs.payment_context, required),
			(65539, self.authentication, required),
		});
		Ok(())
	}
}

impl Writeable for UnauthenticatedReceiveTlvs {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		encode_tlv_stream!(w, {
			(12, self.payment_constraints, required),
			(65536, self.payment_secret, required),
			(65537, self.payment_context, required),
		});
		Ok(())
	}
}

impl<'a> Writeable for BlindedPaymentTlvsRef<'a> {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		match self {
			Self::Forward(tlvs) => tlvs.write(w)?,
			Self::Receive(tlvs) => tlvs.write(w)?,
		}
		Ok(())
	}
}

impl Readable for BlindedPaymentTlvs {
	fn read<R: io::Read>(r: &mut R) -> Result<Self, DecodeError> {
		_init_and_read_tlv_stream!(r, {
			// Reasoning: Padding refers to filler data added to a packet to increase
			// its size and obscure its actual length. Since padding contains no meaningful
			// information, we can safely omit reading it here.
			// (1, _padding, option),
			(2, scid, option),
			(8, next_blinding_override, option),
			(10, payment_relay, option),
			(12, payment_constraints, required),
			(14, features, (option, encoding: (BlindedHopFeatures, WithoutLength))),
			(65536, payment_secret, option),
			(65537, payment_context, option),
			(65539, authentication, option),
		});

		if let Some(short_channel_id) = scid {
			if payment_secret.is_some() {
				return Err(DecodeError::InvalidValue);
			}
			Ok(BlindedPaymentTlvs::Forward(ForwardTlvs {
				short_channel_id,
				payment_relay: payment_relay.ok_or(DecodeError::InvalidValue)?,
				payment_constraints: payment_constraints.0.unwrap(),
				next_blinding_override,
				features: features.unwrap_or_else(BlindedHopFeatures::empty),
			}))
		} else {
			if payment_relay.is_some() || features.is_some() {
				return Err(DecodeError::InvalidValue);
			}
			Ok(BlindedPaymentTlvs::Receive(ReceiveTlvs {
				tlvs: UnauthenticatedReceiveTlvs {
					payment_secret: payment_secret.ok_or(DecodeError::InvalidValue)?,
					payment_constraints: payment_constraints.0.unwrap(),
					payment_context: payment_context.ok_or(DecodeError::InvalidValue)?,
				},
				authentication: authentication.ok_or(DecodeError::InvalidValue)?,
			}))
		}
	}
}

impl Readable for BlindedTrampolineTlvs {
	fn read<R: io::Read>(r: &mut R) -> Result<Self, DecodeError> {
		_init_and_read_tlv_stream!(r, {
			(4, next_trampoline, option),
			(8, next_blinding_override, option),
			(10, payment_relay, option),
			(12, payment_constraints, required),
			(14, features, (option, encoding: (BlindedHopFeatures, WithoutLength))),
			(65536, payment_secret, option),
			(65537, payment_context, option),
			(65539, authentication, option),
		});

		if let Some(next_trampoline) = next_trampoline {
			if payment_secret.is_some() {
				return Err(DecodeError::InvalidValue);
			}
			Ok(BlindedTrampolineTlvs::Forward(TrampolineForwardTlvs {
				next_trampoline,
				payment_relay: payment_relay.ok_or(DecodeError::InvalidValue)?,
				payment_constraints: payment_constraints.0.unwrap(),
				next_blinding_override,
				features: features.unwrap_or_else(BlindedHopFeatures::empty),
			}))
		} else {
			if payment_relay.is_some() || features.is_some() {
				return Err(DecodeError::InvalidValue);
			}
			Ok(BlindedTrampolineTlvs::Receive(ReceiveTlvs {
				tlvs: UnauthenticatedReceiveTlvs {
					payment_secret: payment_secret.ok_or(DecodeError::InvalidValue)?,
					payment_constraints: payment_constraints.0.unwrap(),
					payment_context: payment_context.ok_or(DecodeError::InvalidValue)?,
				},
				authentication: authentication.ok_or(DecodeError::InvalidValue)?,
			}))
		}
	}
}

/// Represents the padding round off size (in bytes) that
/// is used to pad payment bilnded path's [`BlindedHop`]
pub(crate) const PAYMENT_PADDING_ROUND_OFF: usize = 30;

/// Construct blinded payment hops for the given `intermediate_nodes` and payee info.
pub(super) fn blinded_hops<T: secp256k1::Signing + secp256k1::Verification>(
	secp_ctx: &Secp256k1<T>, intermediate_nodes: &[PaymentForwardNode], payee_node_id: PublicKey,
	payee_tlvs: ReceiveTlvs, session_priv: &SecretKey, local_node_receive_key: ReceiveAuthKey,
) -> Vec<BlindedHop> {
	let pks = intermediate_nodes
		.iter()
		.map(|node| (node.node_id, None))
		.chain(core::iter::once((payee_node_id, Some(local_node_receive_key))));
	let tlvs = intermediate_nodes
		.iter()
		.map(|node| BlindedPaymentTlvsRef::Forward(&node.tlvs))
		.chain(core::iter::once(BlindedPaymentTlvsRef::Receive(&payee_tlvs)));

	let path = pks.zip(
		tlvs.map(|tlv| BlindedPathWithPadding { tlvs: tlv, round_off: PAYMENT_PADDING_ROUND_OFF }),
	);

	utils::construct_blinded_hops(secp_ctx, path, session_priv)
}

/// `None` if underflow occurs.
pub(crate) fn amt_to_forward_msat(
	inbound_amt_msat: u64, payment_relay: &PaymentRelay,
) -> Option<u64> {
	let inbound_amt = inbound_amt_msat as u128;
	let base = payment_relay.fee_base_msat as u128;
	let prop = payment_relay.fee_proportional_millionths as u128;

	let post_base_fee_inbound_amt =
		if let Some(amt) = inbound_amt.checked_sub(base) { amt } else { return None };
	let mut amt_to_forward =
		(post_base_fee_inbound_amt * 1_000_000 + 1_000_000 + prop - 1) / (prop + 1_000_000);

	let fee = ((amt_to_forward * prop) / 1_000_000) + base;
	if inbound_amt - fee < amt_to_forward {
		// Rounding up the forwarded amount resulted in underpaying this node, so take an extra 1 msat
		// in fee to compensate.
		amt_to_forward -= 1;
	}
	debug_assert_eq!(amt_to_forward + fee, inbound_amt);
	u64::try_from(amt_to_forward).ok()
}

// Returns (aggregated_base_fee, aggregated_proportional_fee)
pub(crate) fn compute_aggregated_base_prop_fee<I>(hops_fees: I) -> Result<(u64, u64), ()>
where
	I: DoubleEndedIterator<Item = RoutingFees>,
{
	let mut curr_base_fee: u64 = 0;
	let mut curr_prop_mil: u64 = 0;
	for fees in hops_fees.rev() {
		let next_base_fee = fees.base_msat as u64;
		let next_prop_mil = fees.proportional_millionths as u64;

		// Use integer arithmetic to compute `ceil(a/b)` as `(a+b-1)/b`
		// ((curr_base_fee * (1_000_000 + next_prop_mil)) / 1_000_000) + next_base_fee
		curr_base_fee = curr_base_fee
			.checked_mul(1_000_000 + next_prop_mil)
			.and_then(|f| f.checked_add(1_000_000 - 1))
			.map(|f| f / 1_000_000)
			.and_then(|f| f.checked_add(next_base_fee))
			.ok_or(())?;
		// ceil(((curr_prop_mil + 1_000_000) * (next_prop_mil + 1_000_000)) / 1_000_000) - 1_000_000
		curr_prop_mil = curr_prop_mil
			.checked_add(1_000_000)
			.and_then(|f1| next_prop_mil.checked_add(1_000_000).and_then(|f2| f2.checked_mul(f1)))
			.and_then(|f| f.checked_add(1_000_000 - 1))
			.map(|f| f / 1_000_000)
			.and_then(|f| f.checked_sub(1_000_000))
			.ok_or(())?;
	}

	Ok((curr_base_fee, curr_prop_mil))
}

pub(super) fn compute_payinfo(
	intermediate_nodes: &[PaymentForwardNode], payee_tlvs: &UnauthenticatedReceiveTlvs,
	payee_htlc_maximum_msat: u64, min_final_cltv_expiry_delta: u16,
) -> Result<BlindedPayInfo, ()> {
	let (aggregated_base_fee, aggregated_prop_fee) =
		compute_aggregated_base_prop_fee(intermediate_nodes.iter().map(|node| RoutingFees {
			base_msat: node.tlvs.payment_relay.fee_base_msat,
			proportional_millionths: node.tlvs.payment_relay.fee_proportional_millionths,
		}))?;

	let mut htlc_minimum_msat: u64 = 1;
	let mut htlc_maximum_msat: u64 = 21_000_000 * 100_000_000 * 1_000; // Total bitcoin supply
	let mut cltv_expiry_delta: u16 = min_final_cltv_expiry_delta;
	for node in intermediate_nodes.iter() {
		// In the future, we'll want to take the intersection of all supported features for the
		// `BlindedPayInfo`, but there are no features in that context right now.
		if node.tlvs.features.requires_unknown_bits_from(&BlindedHopFeatures::empty()) {
			return Err(());
		}

		cltv_expiry_delta =
			cltv_expiry_delta.checked_add(node.tlvs.payment_relay.cltv_expiry_delta).ok_or(())?;

		// The min htlc for an intermediate node is that node's min minus the fees charged by all of the
		// following hops for forwarding that min, since that fee amount will automatically be included
		// in the amount that this node receives and contribute towards reaching its min.
		htlc_minimum_msat = amt_to_forward_msat(
			core::cmp::max(node.tlvs.payment_constraints.htlc_minimum_msat, htlc_minimum_msat),
			&node.tlvs.payment_relay,
		)
		.unwrap_or(1); // If underflow occurs, we definitely reached this node's min
		htlc_maximum_msat = amt_to_forward_msat(
			core::cmp::min(node.htlc_maximum_msat, htlc_maximum_msat),
			&node.tlvs.payment_relay,
		)
		.ok_or(())?; // If underflow occurs, we cannot send to this hop without exceeding their max
	}
	htlc_minimum_msat =
		core::cmp::max(payee_tlvs.payment_constraints.htlc_minimum_msat, htlc_minimum_msat);
	htlc_maximum_msat = core::cmp::min(payee_htlc_maximum_msat, htlc_maximum_msat);

	if htlc_maximum_msat < htlc_minimum_msat {
		return Err(());
	}
	Ok(BlindedPayInfo {
		fee_base_msat: u32::try_from(aggregated_base_fee).map_err(|_| ())?,
		fee_proportional_millionths: u32::try_from(aggregated_prop_fee).map_err(|_| ())?,
		cltv_expiry_delta,
		htlc_minimum_msat,
		htlc_maximum_msat,
		features: BlindedHopFeatures::empty(),
	})
}

impl Writeable for PaymentRelay {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		self.cltv_expiry_delta.write(w)?;
		self.fee_proportional_millionths.write(w)?;
		HighZeroBytesDroppedBigSize(self.fee_base_msat).write(w)
	}
}
impl Readable for PaymentRelay {
	fn read<R: io::Read>(r: &mut R) -> Result<Self, DecodeError> {
		let cltv_expiry_delta: u16 = Readable::read(r)?;
		let fee_proportional_millionths: u32 = Readable::read(r)?;
		let fee_base_msat: HighZeroBytesDroppedBigSize<u32> = Readable::read(r)?;
		Ok(Self { cltv_expiry_delta, fee_proportional_millionths, fee_base_msat: fee_base_msat.0 })
	}
}

impl Writeable for PaymentConstraints {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		self.max_cltv_expiry.write(w)?;
		HighZeroBytesDroppedBigSize(self.htlc_minimum_msat).write(w)
	}
}
impl Readable for PaymentConstraints {
	fn read<R: io::Read>(r: &mut R) -> Result<Self, DecodeError> {
		let max_cltv_expiry: u32 = Readable::read(r)?;
		let htlc_minimum_msat: HighZeroBytesDroppedBigSize<u64> = Readable::read(r)?;
		Ok(Self { max_cltv_expiry, htlc_minimum_msat: htlc_minimum_msat.0 })
	}
}

impl_writeable_tlv_based_enum_legacy!(PaymentContext,
	;
	// 0 for Unknown removed in version 0.1.
	(1, Bolt12Offer),
	(2, Bolt12Refund),
	(3, AsyncBolt12Offer),
);

impl<'a> Writeable for PaymentContextRef<'a> {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		match self {
			PaymentContextRef::Bolt12Offer(context) => {
				1u8.write(w)?;
				context.write(w)?;
			},
			PaymentContextRef::Bolt12Refund(context) => {
				2u8.write(w)?;
				context.write(w)?;
			},
		}

		Ok(())
	}
}

impl_writeable_tlv_based!(Bolt12OfferContext, {
	(0, offer_id, required),
	(2, invoice_request, required),
});

impl_writeable_tlv_based!(AsyncBolt12OfferContext, {
	(0, offer_nonce, required),
});

impl_writeable_tlv_based!(Bolt12RefundContext, {});

#[cfg(test)]
mod tests {
	use crate::blinded_path::payment::{
		Bolt12RefundContext, ForwardTlvs, PaymentConstraints, PaymentContext, PaymentForwardNode,
		PaymentRelay, UnauthenticatedReceiveTlvs,
	};
	use crate::ln::functional_test_utils::TEST_FINAL_CLTV;
	use crate::types::features::BlindedHopFeatures;
	use crate::types::payment::PaymentSecret;
	use bitcoin::secp256k1::PublicKey;

	#[test]
	fn compute_payinfo() {
		// Taken from the spec example for aggregating blinded payment info. See
		// https://github.com/lightning/bolts/blob/master/proposals/route-blinding.md#blinded-payments
		let dummy_pk = PublicKey::from_slice(&[2; 33]).unwrap();
		let intermediate_nodes = vec![
			PaymentForwardNode {
				node_id: dummy_pk,
				tlvs: ForwardTlvs {
					short_channel_id: 0,
					payment_relay: PaymentRelay {
						cltv_expiry_delta: 144,
						fee_proportional_millionths: 500,
						fee_base_msat: 100,
					},
					payment_constraints: PaymentConstraints {
						max_cltv_expiry: 0,
						htlc_minimum_msat: 100,
					},
					next_blinding_override: None,
					features: BlindedHopFeatures::empty(),
				},
				htlc_maximum_msat: u64::max_value(),
			},
			PaymentForwardNode {
				node_id: dummy_pk,
				tlvs: ForwardTlvs {
					short_channel_id: 0,
					payment_relay: PaymentRelay {
						cltv_expiry_delta: 144,
						fee_proportional_millionths: 500,
						fee_base_msat: 100,
					},
					payment_constraints: PaymentConstraints {
						max_cltv_expiry: 0,
						htlc_minimum_msat: 1_000,
					},
					next_blinding_override: None,
					features: BlindedHopFeatures::empty(),
				},
				htlc_maximum_msat: u64::max_value(),
			},
		];
		let recv_tlvs = UnauthenticatedReceiveTlvs {
			payment_secret: PaymentSecret([0; 32]),
			payment_constraints: PaymentConstraints { max_cltv_expiry: 0, htlc_minimum_msat: 1 },
			payment_context: PaymentContext::Bolt12Refund(Bolt12RefundContext {}),
		};
		let htlc_maximum_msat = 100_000;
		let blinded_payinfo =
			super::compute_payinfo(&intermediate_nodes[..], &recv_tlvs, htlc_maximum_msat, 12)
				.unwrap();
		assert_eq!(blinded_payinfo.fee_base_msat, 201);
		assert_eq!(blinded_payinfo.fee_proportional_millionths, 1001);
		assert_eq!(blinded_payinfo.cltv_expiry_delta, 300);
		assert_eq!(blinded_payinfo.htlc_minimum_msat, 900);
		assert_eq!(blinded_payinfo.htlc_maximum_msat, htlc_maximum_msat);
	}

	#[test]
	fn compute_payinfo_1_hop() {
		let recv_tlvs = UnauthenticatedReceiveTlvs {
			payment_secret: PaymentSecret([0; 32]),
			payment_constraints: PaymentConstraints { max_cltv_expiry: 0, htlc_minimum_msat: 1 },
			payment_context: PaymentContext::Bolt12Refund(Bolt12RefundContext {}),
		};
		let blinded_payinfo =
			super::compute_payinfo(&[], &recv_tlvs, 4242, TEST_FINAL_CLTV as u16).unwrap();
		assert_eq!(blinded_payinfo.fee_base_msat, 0);
		assert_eq!(blinded_payinfo.fee_proportional_millionths, 0);
		assert_eq!(blinded_payinfo.cltv_expiry_delta, TEST_FINAL_CLTV as u16);
		assert_eq!(blinded_payinfo.htlc_minimum_msat, 1);
		assert_eq!(blinded_payinfo.htlc_maximum_msat, 4242);
	}

	#[test]
	fn simple_aggregated_htlc_min() {
		// If no hops charge fees, the htlc_minimum_msat should just be the maximum htlc_minimum_msat
		// along the path.
		let dummy_pk = PublicKey::from_slice(&[2; 33]).unwrap();
		let intermediate_nodes = vec![
			PaymentForwardNode {
				node_id: dummy_pk,
				tlvs: ForwardTlvs {
					short_channel_id: 0,
					payment_relay: PaymentRelay {
						cltv_expiry_delta: 0,
						fee_proportional_millionths: 0,
						fee_base_msat: 0,
					},
					payment_constraints: PaymentConstraints {
						max_cltv_expiry: 0,
						htlc_minimum_msat: 1,
					},
					next_blinding_override: None,
					features: BlindedHopFeatures::empty(),
				},
				htlc_maximum_msat: u64::max_value(),
			},
			PaymentForwardNode {
				node_id: dummy_pk,
				tlvs: ForwardTlvs {
					short_channel_id: 0,
					payment_relay: PaymentRelay {
						cltv_expiry_delta: 0,
						fee_proportional_millionths: 0,
						fee_base_msat: 0,
					},
					payment_constraints: PaymentConstraints {
						max_cltv_expiry: 0,
						htlc_minimum_msat: 2_000,
					},
					next_blinding_override: None,
					features: BlindedHopFeatures::empty(),
				},
				htlc_maximum_msat: u64::max_value(),
			},
		];
		let recv_tlvs = UnauthenticatedReceiveTlvs {
			payment_secret: PaymentSecret([0; 32]),
			payment_constraints: PaymentConstraints { max_cltv_expiry: 0, htlc_minimum_msat: 3 },
			payment_context: PaymentContext::Bolt12Refund(Bolt12RefundContext {}),
		};
		let htlc_maximum_msat = 100_000;
		let blinded_payinfo = super::compute_payinfo(
			&intermediate_nodes[..],
			&recv_tlvs,
			htlc_maximum_msat,
			TEST_FINAL_CLTV as u16,
		)
		.unwrap();
		assert_eq!(blinded_payinfo.htlc_minimum_msat, 2_000);
	}

	#[test]
	fn aggregated_htlc_min() {
		// Create a path with varying fees and htlc_mins, and make sure htlc_minimum_msat ends up as the
		// max (htlc_min - following_fees) along the path.
		let dummy_pk = PublicKey::from_slice(&[2; 33]).unwrap();
		let intermediate_nodes = vec![
			PaymentForwardNode {
				node_id: dummy_pk,
				tlvs: ForwardTlvs {
					short_channel_id: 0,
					payment_relay: PaymentRelay {
						cltv_expiry_delta: 0,
						fee_proportional_millionths: 500,
						fee_base_msat: 1_000,
					},
					payment_constraints: PaymentConstraints {
						max_cltv_expiry: 0,
						htlc_minimum_msat: 5_000,
					},
					next_blinding_override: None,
					features: BlindedHopFeatures::empty(),
				},
				htlc_maximum_msat: u64::max_value(),
			},
			PaymentForwardNode {
				node_id: dummy_pk,
				tlvs: ForwardTlvs {
					short_channel_id: 0,
					payment_relay: PaymentRelay {
						cltv_expiry_delta: 0,
						fee_proportional_millionths: 500,
						fee_base_msat: 200,
					},
					payment_constraints: PaymentConstraints {
						max_cltv_expiry: 0,
						htlc_minimum_msat: 2_000,
					},
					next_blinding_override: None,
					features: BlindedHopFeatures::empty(),
				},
				htlc_maximum_msat: u64::max_value(),
			},
		];
		let recv_tlvs = UnauthenticatedReceiveTlvs {
			payment_secret: PaymentSecret([0; 32]),
			payment_constraints: PaymentConstraints { max_cltv_expiry: 0, htlc_minimum_msat: 1 },
			payment_context: PaymentContext::Bolt12Refund(Bolt12RefundContext {}),
		};
		let htlc_minimum_msat = 3798;
		assert!(super::compute_payinfo(
			&intermediate_nodes[..],
			&recv_tlvs,
			htlc_minimum_msat - 1,
			TEST_FINAL_CLTV as u16
		)
		.is_err());

		let htlc_maximum_msat = htlc_minimum_msat + 1;
		let blinded_payinfo = super::compute_payinfo(
			&intermediate_nodes[..],
			&recv_tlvs,
			htlc_maximum_msat,
			TEST_FINAL_CLTV as u16,
		)
		.unwrap();
		assert_eq!(blinded_payinfo.htlc_minimum_msat, htlc_minimum_msat);
		assert_eq!(blinded_payinfo.htlc_maximum_msat, htlc_maximum_msat);
	}

	#[test]
	fn aggregated_htlc_max() {
		// Create a path with varying fees and `htlc_maximum_msat`s, and make sure the aggregated max
		// htlc ends up as the min (htlc_max - following_fees) along the path.
		let dummy_pk = PublicKey::from_slice(&[2; 33]).unwrap();
		let intermediate_nodes = vec![
			PaymentForwardNode {
				node_id: dummy_pk,
				tlvs: ForwardTlvs {
					short_channel_id: 0,
					payment_relay: PaymentRelay {
						cltv_expiry_delta: 0,
						fee_proportional_millionths: 500,
						fee_base_msat: 1_000,
					},
					payment_constraints: PaymentConstraints {
						max_cltv_expiry: 0,
						htlc_minimum_msat: 1,
					},
					next_blinding_override: None,
					features: BlindedHopFeatures::empty(),
				},
				htlc_maximum_msat: 5_000,
			},
			PaymentForwardNode {
				node_id: dummy_pk,
				tlvs: ForwardTlvs {
					short_channel_id: 0,
					payment_relay: PaymentRelay {
						cltv_expiry_delta: 0,
						fee_proportional_millionths: 500,
						fee_base_msat: 1,
					},
					payment_constraints: PaymentConstraints {
						max_cltv_expiry: 0,
						htlc_minimum_msat: 1,
					},
					next_blinding_override: None,
					features: BlindedHopFeatures::empty(),
				},
				htlc_maximum_msat: 10_000,
			},
		];
		let recv_tlvs = UnauthenticatedReceiveTlvs {
			payment_secret: PaymentSecret([0; 32]),
			payment_constraints: PaymentConstraints { max_cltv_expiry: 0, htlc_minimum_msat: 1 },
			payment_context: PaymentContext::Bolt12Refund(Bolt12RefundContext {}),
		};

		let blinded_payinfo = super::compute_payinfo(
			&intermediate_nodes[..],
			&recv_tlvs,
			10_000,
			TEST_FINAL_CLTV as u16,
		)
		.unwrap();
		assert_eq!(blinded_payinfo.htlc_maximum_msat, 3997);
	}
}
