// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Data structures and methods for constructing [`BlindedPath`]s to send a payment over.
//!
//! [`BlindedPath`]: crate::blinded_path::BlindedPath

use bitcoin::secp256k1::{self, PublicKey, Secp256k1, SecretKey};

use crate::blinded_path::BlindedHop;
use crate::blinded_path::utils;
use crate::io;
use crate::ln::types::PaymentSecret;
use crate::ln::channel_state::CounterpartyForwardingInfo;
use crate::ln::features::BlindedHopFeatures;
use crate::ln::msgs::DecodeError;
use crate::offers::invoice::BlindedPayInfo;
use crate::offers::invoice_request::InvoiceRequestFields;
use crate::offers::offer::OfferId;
use crate::routing::gossip::DirectedChannelInfo;
use crate::util::ser::{HighZeroBytesDroppedBigSize, Readable, Writeable, Writer};

#[allow(unused_imports)]
use crate::prelude::*;

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

/// The context of an inbound payment, which is included in a [`BlindedPath`] via [`ReceiveTlvs`]
/// and surfaced in [`PaymentPurpose`].
///
/// [`BlindedPath`]: crate::blinded_path::BlindedPath
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

impl PaymentRelay {
	fn normalize_cltv_expiry_delta(cltv_expiry_delta: u16) -> Result<u16, ()> {
		// Avoid exposing esoteric CLTV expiry deltas, which could de-anonymize the path.
		match cltv_expiry_delta {
			0..=40 => Ok(40),
			41..=80 => Ok(80),
			81..=144 => Ok(144),
			145..=216 => Ok(216),
			_ => Err(()),
		}
	}
}

impl TryFrom<CounterpartyForwardingInfo> for PaymentRelay {
	type Error = ();

	fn try_from(info: CounterpartyForwardingInfo) -> Result<Self, ()> {
		let CounterpartyForwardingInfo {
			fee_base_msat, fee_proportional_millionths, cltv_expiry_delta
		} = info;

		Ok(Self {
			cltv_expiry_delta: Self::normalize_cltv_expiry_delta(cltv_expiry_delta)?,
			fee_proportional_millionths,
			fee_base_msat
		})
	}
}

impl<'a> TryFrom<DirectedChannelInfo<'a>> for PaymentRelay {
	type Error = ();

	fn try_from(info: DirectedChannelInfo<'a>) -> Result<Self, ()> {
		let direction = info.direction();

		Ok(Self {
			cltv_expiry_delta: Self::normalize_cltv_expiry_delta(direction.cltv_expiry_delta)?,
			fee_proportional_millionths: direction.fees.proportional_millionths,
			fee_base_msat: direction.fees.base_msat,
		})
	}
}

impl Writeable for ForwardTlvs {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		let features_opt =
			if self.features == BlindedHopFeatures::empty() { None }
			else { Some(&self.features) };
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
			(10, payment_relay, option),
			(12, payment_constraints, required),
			(14, features, option),
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

impl_writeable_tlv_based_enum!(PaymentContext,
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
