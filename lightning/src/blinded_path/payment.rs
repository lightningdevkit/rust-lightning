// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Data structures and methods for constructing [`BlindedPaymentPath`]s to send a payment over.

use bitcoin::secp256k1::{self, PublicKey, Secp256k1, SecretKey};

use crate::blinded_path::{BlindedHop, BlindedPath, IntroductionNode, NodeIdLookUp};
use crate::blinded_path::utils;
use crate::crypto::streams::ChaChaPolyReadAdapter;
use crate::io;
use crate::io::Cursor;
use crate::ln::types::PaymentSecret;
use crate::ln::channel_state::CounterpartyForwardingInfo;
use crate::ln::features::BlindedHopFeatures;
use crate::ln::msgs::DecodeError;
use crate::ln::onion_utils;
use crate::offers::invoice::BlindedPayInfo;
use crate::offers::invoice_request::InvoiceRequestFields;
use crate::offers::offer::OfferId;
use crate::routing::gossip::{NodeId, ReadOnlyNetworkGraph};
use crate::sign::{EntropySource, NodeSigner, Recipient};
use crate::util::ser::{FixedLengthReader, LengthReadableArgs, HighZeroBytesDroppedBigSize, Readable, WithoutLength, Writeable, Writer};

use core::mem;
use core::ops::Deref;

#[allow(unused_imports)]
use crate::prelude::*;

/// A blinded path to be used for sending or receiving a payment, hiding the identity of the
/// recipient.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct BlindedPaymentPath(pub(super) BlindedPath);

impl Writeable for BlindedPaymentPath {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		self.0.write(w)
	}
}

impl Readable for BlindedPaymentPath {
	fn read<R: io::Read>(r: &mut R) -> Result<Self, DecodeError> {
		Ok(Self(BlindedPath::read(r)?))
	}
}

impl BlindedPaymentPath {
	/// Create a one-hop blinded path for a payment.
	pub fn one_hop<ES: Deref, T: secp256k1::Signing + secp256k1::Verification>(
		payee_node_id: PublicKey, payee_tlvs: ReceiveTlvs, min_final_cltv_expiry_delta: u16,
		entropy_source: ES, secp_ctx: &Secp256k1<T>
	) -> Result<(BlindedPayInfo, Self), ()> where ES::Target: EntropySource {
		// This value is not considered in pathfinding for 1-hop blinded paths, because it's intended to
		// be in relation to a specific channel.
		let htlc_maximum_msat = u64::max_value();
		Self::new(
			&[], payee_node_id, payee_tlvs, htlc_maximum_msat, min_final_cltv_expiry_delta,
			entropy_source, secp_ctx
		)
	}

	/// Create a blinded path for a payment, to be forwarded along `intermediate_nodes`.
	///
	/// Errors if:
	/// * a provided node id is invalid
	/// * [`BlindedPayInfo`] calculation results in an integer overflow
	/// * any unknown features are required in the provided [`ForwardTlvs`]
	//  TODO: make all payloads the same size with padding + add dummy hops
	pub fn new<ES: Deref, T: secp256k1::Signing + secp256k1::Verification>(
		intermediate_nodes: &[ForwardNode], payee_node_id: PublicKey, payee_tlvs: ReceiveTlvs,
		htlc_maximum_msat: u64, min_final_cltv_expiry_delta: u16, entropy_source: ES,
		secp_ctx: &Secp256k1<T>
	) -> Result<(BlindedPayInfo, Self), ()> where ES::Target: EntropySource {
		let introduction_node = IntroductionNode::NodeId(
			intermediate_nodes.first().map_or(payee_node_id, |n| n.node_id)
		);
		let blinding_secret_bytes = entropy_source.get_secure_random_bytes();
		let blinding_secret = SecretKey::from_slice(&blinding_secret_bytes[..]).expect("RNG is busted");

		let blinded_payinfo = compute_payinfo(
			intermediate_nodes, &payee_tlvs, htlc_maximum_msat, min_final_cltv_expiry_delta
		)?;
		Ok((blinded_payinfo, Self(BlindedPath {
			introduction_node,
			blinding_point: PublicKey::from_secret_key(secp_ctx, &blinding_secret),
			blinded_hops: blinded_hops(
				secp_ctx, intermediate_nodes, payee_node_id, payee_tlvs, &blinding_secret
			).map_err(|_| ())?,
		})))
	}

	/// Returns the introduction [`NodeId`] of the blinded path, if it is publicly reachable (i.e.,
	/// it is found in the network graph).
	pub fn public_introduction_node_id<'a>(
		&self, network_graph: &'a ReadOnlyNetworkGraph
	) -> Option<&'a NodeId> {
		self.0.public_introduction_node_id(network_graph)
	}

	/// The [`IntroductionNode`] of the blinded path.
	pub fn introduction_node(&self) -> &IntroductionNode {
		&self.0.introduction_node
	}

	/// Used by the [`IntroductionNode`] to decrypt its [`encrypted_payload`] to forward the payment.
	///
	/// [`encrypted_payload`]: BlindedHop::encrypted_payload
	pub fn blinding_point(&self) -> PublicKey {
		self.0.blinding_point
	}

	/// The [`BlindedHop`]s within the blinded path.
	pub fn blinded_hops(&self) -> &[BlindedHop] {
		&self.0.blinded_hops
	}

	/// Advance the blinded onion payment path by one hop, making the second hop into the new
	/// introduction node.
	///
	/// Will only modify `self` when returning `Ok`.
	pub fn advance_path_by_one<NS: Deref, NL: Deref, T>(
		&mut self, node_signer: &NS, node_id_lookup: &NL, secp_ctx: &Secp256k1<T>
	) -> Result<(), ()>
	where
		NS::Target: NodeSigner,
		NL::Target: NodeIdLookUp,
		T: secp256k1::Signing + secp256k1::Verification,
	{
		let control_tlvs_ss = node_signer.ecdh(Recipient::Node, &self.0.blinding_point, None)?;
		let rho = onion_utils::gen_rho_from_shared_secret(&control_tlvs_ss.secret_bytes());
		let encrypted_control_tlvs = &self.0.blinded_hops.get(0).ok_or(())?.encrypted_payload;
		let mut s = Cursor::new(encrypted_control_tlvs);
		let mut reader = FixedLengthReader::new(&mut s, encrypted_control_tlvs.len() as u64);
		match ChaChaPolyReadAdapter::read(&mut reader, rho) {
			Ok(ChaChaPolyReadAdapter {
				readable: BlindedPaymentTlvs::Forward(ForwardTlvs { short_channel_id, .. })
			}) => {
				let next_node_id = match node_id_lookup.next_node_id(short_channel_id) {
					Some(node_id) => node_id,
					None => return Err(()),
				};
				let mut new_blinding_point = onion_utils::next_hop_pubkey(
					secp_ctx, self.0.blinding_point, control_tlvs_ss.as_ref()
				).map_err(|_| ())?;
				mem::swap(&mut self.0.blinding_point, &mut new_blinding_point);
				self.0.introduction_node = IntroductionNode::NodeId(next_node_id);
				self.0.blinded_hops.remove(0);
				Ok(())
			},
			_ => Err(())
		}
	}

	#[cfg(any(test, fuzzing))]
	pub fn from_raw(
		introduction_node_id: PublicKey, blinding_point: PublicKey, blinded_hops: Vec<BlindedHop>
	) -> Self {
		Self(BlindedPath {
			introduction_node: IntroductionNode::NodeId(introduction_node_id),
			blinding_point,
			blinded_hops,
		})
	}

	#[cfg(test)]
	pub fn clear_blinded_hops(&mut self) {
		self.0.blinded_hops.clear()
	}
}

/// An intermediate node, its outbound channel, and relay parameters.
#[derive(Clone, Debug)]
pub struct ForwardNode {
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

/// Data to construct a [`BlindedHop`] for receiving a payment. This payload is custom to LDK and
/// may not be valid if received by another lightning implementation.
#[derive(Clone, Debug)]
pub struct ReceiveTlvs {
	/// Used to authenticate the sender of a payment to the receiver and tie MPP HTLCs together.
	pub payment_secret: PaymentSecret,
	/// Constraints for the receiver of this payment.
	pub payment_constraints: PaymentConstraints,
	/// Context for the receiver of this payment.
	pub payment_context: PaymentContext,
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

// Used to include forward and receive TLVs in the same iterator for encoding.
enum BlindedPaymentTlvsRef<'a> {
	Forward(&'a ForwardTlvs),
	Receive(&'a ReceiveTlvs),
}

/// Parameters for relaying over a given [`BlindedHop`].
///
/// [`BlindedHop`]: crate::blinded_path::BlindedHop
#[derive(Clone, Debug)]
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
#[derive(Clone, Debug)]
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
	/// The payment context was unknown.
	Unknown(UnknownPaymentContext),

	/// The payment was made for an invoice requested from a BOLT 12 [`Offer`].
	///
	/// [`Offer`]: crate::offers::offer::Offer
	Bolt12Offer(Bolt12OfferContext),

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

/// An unknown payment context.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnknownPaymentContext(());

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

/// The context of a payment made for an invoice sent for a BOLT 12 [`Refund`].
///
/// [`Refund`]: crate::offers::refund::Refund
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Bolt12RefundContext {}

impl PaymentContext {
	pub(crate) fn unknown() -> Self {
		PaymentContext::Unknown(UnknownPaymentContext(()))
	}
}

impl TryFrom<CounterpartyForwardingInfo> for PaymentRelay {
	type Error = ();

	fn try_from(info: CounterpartyForwardingInfo) -> Result<Self, ()> {
		let CounterpartyForwardingInfo {
			fee_base_msat, fee_proportional_millionths, cltv_expiry_delta
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
		let features_opt =
			if self.features == BlindedHopFeatures::empty() { None }
			else { Some(WithoutLength(&self.features)) };
		encode_tlv_stream!(w, {
			(2, self.short_channel_id, required),
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
			(12, self.payment_constraints, required),
			(65536, self.payment_secret, required),
			(65537, self.payment_context, required)
		});
		Ok(())
	}
}

impl<'a> Writeable for BlindedPaymentTlvsRef<'a> {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		// TODO: write padding
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
			(1, _padding, option),
			(2, scid, option),
			(8, next_blinding_override, option),
			(10, payment_relay, option),
			(12, payment_constraints, required),
			(14, features, (option, encoding: (BlindedHopFeatures, WithoutLength))),
			(65536, payment_secret, option),
			(65537, payment_context, (default_value, PaymentContext::unknown())),
		});
		let _padding: Option<utils::Padding> = _padding;

		if let Some(short_channel_id) = scid {
			if payment_secret.is_some() {
				return Err(DecodeError::InvalidValue)
			}
			Ok(BlindedPaymentTlvs::Forward(ForwardTlvs {
				short_channel_id,
				payment_relay: payment_relay.ok_or(DecodeError::InvalidValue)?,
				payment_constraints: payment_constraints.0.unwrap(),
				next_blinding_override,
				features: features.unwrap_or_else(BlindedHopFeatures::empty),
			}))
		} else {
			if payment_relay.is_some() || features.is_some() { return Err(DecodeError::InvalidValue) }
			Ok(BlindedPaymentTlvs::Receive(ReceiveTlvs {
				payment_secret: payment_secret.ok_or(DecodeError::InvalidValue)?,
				payment_constraints: payment_constraints.0.unwrap(),
				payment_context: payment_context.0.unwrap(),
			}))
		}
	}
}

/// Construct blinded payment hops for the given `intermediate_nodes` and payee info.
pub(super) fn blinded_hops<T: secp256k1::Signing + secp256k1::Verification>(
	secp_ctx: &Secp256k1<T>, intermediate_nodes: &[ForwardNode],
	payee_node_id: PublicKey, payee_tlvs: ReceiveTlvs, session_priv: &SecretKey
) -> Result<Vec<BlindedHop>, secp256k1::Error> {
	let pks = intermediate_nodes.iter().map(|node| &node.node_id)
		.chain(core::iter::once(&payee_node_id));
	let tlvs = intermediate_nodes.iter().map(|node| BlindedPaymentTlvsRef::Forward(&node.tlvs))
		.chain(core::iter::once(BlindedPaymentTlvsRef::Receive(&payee_tlvs)));
	utils::construct_blinded_hops(secp_ctx, pks, tlvs, session_priv)
}

/// `None` if underflow occurs.
pub(crate) fn amt_to_forward_msat(inbound_amt_msat: u64, payment_relay: &PaymentRelay) -> Option<u64> {
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

pub(super) fn compute_payinfo(
	intermediate_nodes: &[ForwardNode], payee_tlvs: &ReceiveTlvs, payee_htlc_maximum_msat: u64,
	min_final_cltv_expiry_delta: u16
) -> Result<BlindedPayInfo, ()> {
	let mut curr_base_fee: u64 = 0;
	let mut curr_prop_mil: u64 = 0;
	let mut cltv_expiry_delta: u16 = min_final_cltv_expiry_delta;
	for tlvs in intermediate_nodes.iter().rev().map(|n| &n.tlvs) {
		// In the future, we'll want to take the intersection of all supported features for the
		// `BlindedPayInfo`, but there are no features in that context right now.
		if tlvs.features.requires_unknown_bits_from(&BlindedHopFeatures::empty()) { return Err(()) }

		let next_base_fee = tlvs.payment_relay.fee_base_msat as u64;
		let next_prop_mil = tlvs.payment_relay.fee_proportional_millionths as u64;
		// Use integer arithmetic to compute `ceil(a/b)` as `(a+b-1)/b`
		// ((curr_base_fee * (1_000_000 + next_prop_mil)) / 1_000_000) + next_base_fee
		curr_base_fee = curr_base_fee.checked_mul(1_000_000 + next_prop_mil)
			.and_then(|f| f.checked_add(1_000_000 - 1))
			.map(|f| f / 1_000_000)
			.and_then(|f| f.checked_add(next_base_fee))
			.ok_or(())?;
		// ceil(((curr_prop_mil + 1_000_000) * (next_prop_mil + 1_000_000)) / 1_000_000) - 1_000_000
		curr_prop_mil = curr_prop_mil.checked_add(1_000_000)
			.and_then(|f1| next_prop_mil.checked_add(1_000_000).and_then(|f2| f2.checked_mul(f1)))
			.and_then(|f| f.checked_add(1_000_000 - 1))
			.map(|f| f / 1_000_000)
			.and_then(|f| f.checked_sub(1_000_000))
			.ok_or(())?;

		cltv_expiry_delta = cltv_expiry_delta.checked_add(tlvs.payment_relay.cltv_expiry_delta).ok_or(())?;
	}

	let mut htlc_minimum_msat: u64 = 1;
	let mut htlc_maximum_msat: u64 = 21_000_000 * 100_000_000 * 1_000; // Total bitcoin supply
	for node in intermediate_nodes.iter() {
		// The min htlc for an intermediate node is that node's min minus the fees charged by all of the
		// following hops for forwarding that min, since that fee amount will automatically be included
		// in the amount that this node receives and contribute towards reaching its min.
		htlc_minimum_msat = amt_to_forward_msat(
			core::cmp::max(node.tlvs.payment_constraints.htlc_minimum_msat, htlc_minimum_msat),
			&node.tlvs.payment_relay
		).unwrap_or(1); // If underflow occurs, we definitely reached this node's min
		htlc_maximum_msat = amt_to_forward_msat(
			core::cmp::min(node.htlc_maximum_msat, htlc_maximum_msat), &node.tlvs.payment_relay
		).ok_or(())?; // If underflow occurs, we cannot send to this hop without exceeding their max
	}
	htlc_minimum_msat = core::cmp::max(
		payee_tlvs.payment_constraints.htlc_minimum_msat, htlc_minimum_msat
	);
	htlc_maximum_msat = core::cmp::min(payee_htlc_maximum_msat, htlc_maximum_msat);

	if htlc_maximum_msat < htlc_minimum_msat { return Err(()) }
	Ok(BlindedPayInfo {
		fee_base_msat: u32::try_from(curr_base_fee).map_err(|_| ())?,
		fee_proportional_millionths: u32::try_from(curr_prop_mil).map_err(|_| ())?,
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
	(0, Unknown),
	(1, Bolt12Offer),
	(2, Bolt12Refund),
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

impl Writeable for UnknownPaymentContext {
	fn write<W: Writer>(&self, _w: &mut W) -> Result<(), io::Error> {
		Ok(())
	}
}

impl Readable for UnknownPaymentContext {
	fn read<R: io::Read>(_r: &mut R) -> Result<Self, DecodeError> {
		Ok(UnknownPaymentContext(()))
	}
}

impl_writeable_tlv_based!(Bolt12OfferContext, {
	(0, offer_id, required),
	(2, invoice_request, required),
});

impl_writeable_tlv_based!(Bolt12RefundContext, {});

#[cfg(test)]
mod tests {
	use bitcoin::secp256k1::PublicKey;
	use crate::blinded_path::payment::{ForwardNode, ForwardTlvs, ReceiveTlvs, PaymentConstraints, PaymentContext, PaymentRelay};
	use crate::ln::types::PaymentSecret;
	use crate::ln::features::BlindedHopFeatures;
	use crate::ln::functional_test_utils::TEST_FINAL_CLTV;

	#[test]
	fn compute_payinfo() {
		// Taken from the spec example for aggregating blinded payment info. See
		// https://github.com/lightning/bolts/blob/master/proposals/route-blinding.md#blinded-payments
		let dummy_pk = PublicKey::from_slice(&[2; 33]).unwrap();
		let intermediate_nodes = vec![ForwardNode {
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
		}, ForwardNode {
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
		}];
		let recv_tlvs = ReceiveTlvs {
			payment_secret: PaymentSecret([0; 32]),
			payment_constraints: PaymentConstraints {
				max_cltv_expiry: 0,
				htlc_minimum_msat: 1,
			},
			payment_context: PaymentContext::unknown(),
		};
		let htlc_maximum_msat = 100_000;
		let blinded_payinfo = super::compute_payinfo(&intermediate_nodes[..], &recv_tlvs, htlc_maximum_msat, 12).unwrap();
		assert_eq!(blinded_payinfo.fee_base_msat, 201);
		assert_eq!(blinded_payinfo.fee_proportional_millionths, 1001);
		assert_eq!(blinded_payinfo.cltv_expiry_delta, 300);
		assert_eq!(blinded_payinfo.htlc_minimum_msat, 900);
		assert_eq!(blinded_payinfo.htlc_maximum_msat, htlc_maximum_msat);
	}

	#[test]
	fn compute_payinfo_1_hop() {
		let recv_tlvs = ReceiveTlvs {
			payment_secret: PaymentSecret([0; 32]),
			payment_constraints: PaymentConstraints {
				max_cltv_expiry: 0,
				htlc_minimum_msat: 1,
			},
			payment_context: PaymentContext::unknown(),
		};
		let blinded_payinfo = super::compute_payinfo(&[], &recv_tlvs, 4242, TEST_FINAL_CLTV as u16).unwrap();
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
		let intermediate_nodes = vec![ForwardNode {
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
			htlc_maximum_msat: u64::max_value()
		}, ForwardNode {
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
			htlc_maximum_msat: u64::max_value()
		}];
		let recv_tlvs = ReceiveTlvs {
			payment_secret: PaymentSecret([0; 32]),
			payment_constraints: PaymentConstraints {
				max_cltv_expiry: 0,
				htlc_minimum_msat: 3,
			},
			payment_context: PaymentContext::unknown(),
		};
		let htlc_maximum_msat = 100_000;
		let blinded_payinfo = super::compute_payinfo(&intermediate_nodes[..], &recv_tlvs, htlc_maximum_msat, TEST_FINAL_CLTV as u16).unwrap();
		assert_eq!(blinded_payinfo.htlc_minimum_msat, 2_000);
	}

	#[test]
	fn aggregated_htlc_min() {
		// Create a path with varying fees and htlc_mins, and make sure htlc_minimum_msat ends up as the
		// max (htlc_min - following_fees) along the path.
		let dummy_pk = PublicKey::from_slice(&[2; 33]).unwrap();
		let intermediate_nodes = vec![ForwardNode {
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
			htlc_maximum_msat: u64::max_value()
		}, ForwardNode {
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
			htlc_maximum_msat: u64::max_value()
		}];
		let recv_tlvs = ReceiveTlvs {
			payment_secret: PaymentSecret([0; 32]),
			payment_constraints: PaymentConstraints {
				max_cltv_expiry: 0,
				htlc_minimum_msat: 1,
			},
			payment_context: PaymentContext::unknown(),
		};
		let htlc_minimum_msat = 3798;
		assert!(super::compute_payinfo(&intermediate_nodes[..], &recv_tlvs, htlc_minimum_msat - 1, TEST_FINAL_CLTV as u16).is_err());

		let htlc_maximum_msat = htlc_minimum_msat + 1;
		let blinded_payinfo = super::compute_payinfo(&intermediate_nodes[..], &recv_tlvs, htlc_maximum_msat, TEST_FINAL_CLTV as u16).unwrap();
		assert_eq!(blinded_payinfo.htlc_minimum_msat, htlc_minimum_msat);
		assert_eq!(blinded_payinfo.htlc_maximum_msat, htlc_maximum_msat);
	}

	#[test]
	fn aggregated_htlc_max() {
		// Create a path with varying fees and `htlc_maximum_msat`s, and make sure the aggregated max
		// htlc ends up as the min (htlc_max - following_fees) along the path.
		let dummy_pk = PublicKey::from_slice(&[2; 33]).unwrap();
		let intermediate_nodes = vec![ForwardNode {
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
		}, ForwardNode {
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
			htlc_maximum_msat: 10_000
		}];
		let recv_tlvs = ReceiveTlvs {
			payment_secret: PaymentSecret([0; 32]),
			payment_constraints: PaymentConstraints {
				max_cltv_expiry: 0,
				htlc_minimum_msat: 1,
			},
			payment_context: PaymentContext::unknown(),
		};

		let blinded_payinfo = super::compute_payinfo(&intermediate_nodes[..], &recv_tlvs, 10_000, TEST_FINAL_CLTV as u16).unwrap();
		assert_eq!(blinded_payinfo.htlc_maximum_msat, 3997);
	}
}
