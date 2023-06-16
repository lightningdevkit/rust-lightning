//! Data structures and methods for constructing [`BlindedPath`]s to send a payment over.
//!
//! [`BlindedPath`]: crate::blinded_path::BlindedPath

use bitcoin::secp256k1::{self, PublicKey, Secp256k1, SecretKey};

use crate::blinded_path::BlindedHop;
use crate::blinded_path::utils;
use crate::io;
use crate::ln::PaymentSecret;
use crate::ln::features::BlindedHopFeatures;
use crate::ln::msgs::DecodeError;
use crate::prelude::*;
use crate::util::ser::{Readable, Writeable, Writer};

/// Data to construct a [`BlindedHop`] for forwarding a payment.
pub struct ForwardTlvs {
	/// The short channel id this payment should be forwarded out over.
	short_channel_id: u64,
	/// Payment parameters for relaying over [`Self::short_channel_id`].
	payment_relay: PaymentRelay,
	/// Payment constraints for relaying over [`Self::short_channel_id`].
	payment_constraints: PaymentConstraints,
	/// Supported and required features when relaying a payment onion containing this object's
	/// corresponding [`BlindedHop::encrypted_payload`].
	///
	/// [`BlindedHop::encrypted_payload`]: crate::blinded_path::BlindedHop::encrypted_payload
	features: BlindedHopFeatures,
}

/// Data to construct a [`BlindedHop`] for receiving a payment. This payload is custom to LDK and
/// may not be valid if received by another lightning implementation.
pub struct ReceiveTlvs {
	/// Used to authenticate the sender of a payment to the receiver and tie MPP HTLCs together.
	payment_secret: PaymentSecret,
	/// Constraints for the receiver of this payment.
	payment_constraints: PaymentConstraints,
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
pub struct PaymentRelay {
	/// Number of blocks subtracted from an incoming HTLC's `cltv_expiry` for this [`BlindedHop`].
	///
	///[`BlindedHop`]: crate::blinded_path::BlindedHop
	pub cltv_expiry_delta: u16,
	/// Liquidity fee charged (in millionths of the amount transferred) for relaying a payment over
	/// this [`BlindedHop`], (i.e., 10,000 is 1%).
	///
	///[`BlindedHop`]: crate::blinded_path::BlindedHop
	pub fee_proportional_millionths: u32,
	/// Base fee charged (in millisatoshi) for relaying a payment over this [`BlindedHop`].
	///
	///[`BlindedHop`]: crate::blinded_path::BlindedHop
	pub fee_base_msat: u32,
}

/// Constraints for relaying over a given [`BlindedHop`].
///
/// [`BlindedHop`]: crate::blinded_path::BlindedHop
pub struct PaymentConstraints {
	/// The maximum total CLTV delta that is acceptable when relaying a payment over this
	/// [`BlindedHop`].
	///
	///[`BlindedHop`]: crate::blinded_path::BlindedHop
	pub max_cltv_expiry: u32,
	/// The minimum value, in msat, that may be relayed over this [`BlindedHop`].
	pub htlc_minimum_msat: u64,
}

impl_writeable_tlv_based!(ForwardTlvs, {
	(2, short_channel_id, required),
	(10, payment_relay, required),
	(12, payment_constraints, required),
	(14, features, required),
});

impl_writeable_tlv_based!(ReceiveTlvs, {
	(12, payment_constraints, required),
	(65536, payment_secret, required),
});

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
		});
		let _padding: Option<utils::Padding> = _padding;

		if let Some(short_channel_id) = scid {
			if payment_secret.is_some() { return Err(DecodeError::InvalidValue) }
			Ok(BlindedPaymentTlvs::Forward(ForwardTlvs {
				short_channel_id,
				payment_relay: payment_relay.ok_or(DecodeError::InvalidValue)?,
				payment_constraints: payment_constraints.0.unwrap(),
				features: features.ok_or(DecodeError::InvalidValue)?,
			}))
		} else {
			if payment_relay.is_some() || features.is_some() { return Err(DecodeError::InvalidValue) }
			Ok(BlindedPaymentTlvs::Receive(ReceiveTlvs {
				payment_secret: payment_secret.ok_or(DecodeError::InvalidValue)?,
				payment_constraints: payment_constraints.0.unwrap(),
			}))
		}
	}
}

/// Construct blinded payment hops for the given `intermediate_nodes` and payee info.
pub(super) fn blinded_hops<T: secp256k1::Signing + secp256k1::Verification>(
	secp_ctx: &Secp256k1<T>, intermediate_nodes: &[(PublicKey, ForwardTlvs)],
	payee_node_id: PublicKey, payee_tlvs: ReceiveTlvs, session_priv: &SecretKey
) -> Result<Vec<BlindedHop>, secp256k1::Error> {
	let pks = intermediate_nodes.iter().map(|(pk, _)| pk)
		.chain(core::iter::once(&payee_node_id));
	let tlvs = intermediate_nodes.iter().map(|(_, tlvs)| BlindedPaymentTlvsRef::Forward(tlvs))
		.chain(core::iter::once(BlindedPaymentTlvsRef::Receive(&payee_tlvs)));
	utils::construct_blinded_hops(secp_ctx, pks, tlvs, session_priv)
}

impl_writeable_msg!(PaymentRelay, {
	cltv_expiry_delta,
	fee_proportional_millionths,
	fee_base_msat
}, {});

impl_writeable_msg!(PaymentConstraints, {
	max_cltv_expiry,
	htlc_minimum_msat
}, {});
