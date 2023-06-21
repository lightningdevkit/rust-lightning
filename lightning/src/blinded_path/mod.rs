// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Creating blinded paths and related utilities live here.

pub mod payment;
pub(crate) mod message;
pub(crate) mod utils;

use bitcoin::secp256k1::{self, PublicKey, Secp256k1, SecretKey};

use crate::ln::msgs::DecodeError;
use crate::offers::invoice::BlindedPayInfo;
use crate::sign::EntropySource;
use crate::util::ser::{Readable, Writeable, Writer};

use crate::io;
use crate::prelude::*;

/// Onion messages and payments can be sent and received to blinded paths, which serve to hide the
/// identity of the recipient.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct BlindedPath {
	/// To send to a blinded path, the sender first finds a route to the unblinded
	/// `introduction_node_id`, which can unblind its [`encrypted_payload`] to find out the onion
	/// message or payment's next hop and forward it along.
	///
	/// [`encrypted_payload`]: BlindedHop::encrypted_payload
	pub introduction_node_id: PublicKey,
	/// Used by the introduction node to decrypt its [`encrypted_payload`] to forward the onion
	/// message or payment.
	///
	/// [`encrypted_payload`]: BlindedHop::encrypted_payload
	pub blinding_point: PublicKey,
	/// The hops composing the blinded path.
	pub blinded_hops: Vec<BlindedHop>,
}

/// An encrypted payload and node id corresponding to a hop in a payment or onion message path, to
/// be encoded in the sender's onion packet. These hops cannot be identified by outside observers
/// and thus can be used to hide the identity of the recipient.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct BlindedHop {
	/// The blinded node id of this hop in a [`BlindedPath`].
	pub blinded_node_id: PublicKey,
	/// The encrypted payload intended for this hop in a [`BlindedPath`].
	// The node sending to this blinded path will later encode this payload into the onion packet for
	// this hop.
	pub encrypted_payload: Vec<u8>,
}

impl BlindedPath {
	/// Create a blinded path for an onion message, to be forwarded along `node_pks`. The last node
	/// pubkey in `node_pks` will be the destination node.
	///
	/// Errors if less than two hops are provided or if `node_pk`(s) are invalid.
	//  TODO: make all payloads the same size with padding + add dummy hops
	pub fn new_for_message<ES: EntropySource, T: secp256k1::Signing + secp256k1::Verification>
		(node_pks: &[PublicKey], entropy_source: &ES, secp_ctx: &Secp256k1<T>) -> Result<Self, ()>
	{
		if node_pks.len() < 2 { return Err(()) }
		let blinding_secret_bytes = entropy_source.get_secure_random_bytes();
		let blinding_secret = SecretKey::from_slice(&blinding_secret_bytes[..]).expect("RNG is busted");
		let introduction_node_id = node_pks[0];

		Ok(BlindedPath {
			introduction_node_id,
			blinding_point: PublicKey::from_secret_key(secp_ctx, &blinding_secret),
			blinded_hops: message::blinded_hops(secp_ctx, node_pks, &blinding_secret).map_err(|_| ())?,
		})
	}

	/// Create a blinded path for a payment, to be forwarded along `intermediate_nodes`.
	///
	/// Errors if:
	/// * a provided node id is invalid
	/// * [`BlindedPayInfo`] calculation results in an integer overflow
	/// * any unknown features are required in the provided [`ForwardTlvs`]
	///
	/// [`ForwardTlvs`]: crate::blinded_path::payment::ForwardTlvs
	//  TODO: make all payloads the same size with padding + add dummy hops
	pub fn new_for_payment<ES: EntropySource, T: secp256k1::Signing + secp256k1::Verification>(
		intermediate_nodes: &[(PublicKey, payment::ForwardTlvs)], payee_node_id: PublicKey,
		payee_tlvs: payment::ReceiveTlvs, entropy_source: &ES, secp_ctx: &Secp256k1<T>
	) -> Result<(BlindedPayInfo, Self), ()> {
		let blinding_secret_bytes = entropy_source.get_secure_random_bytes();
		let blinding_secret = SecretKey::from_slice(&blinding_secret_bytes[..]).expect("RNG is busted");

		let blinded_payinfo = payment::compute_payinfo(intermediate_nodes, &payee_tlvs)?;
		Ok((blinded_payinfo, BlindedPath {
			introduction_node_id: intermediate_nodes.first().map_or(payee_node_id, |n| n.0),
			blinding_point: PublicKey::from_secret_key(secp_ctx, &blinding_secret),
			blinded_hops: payment::blinded_hops(
				secp_ctx, intermediate_nodes, payee_node_id, payee_tlvs, &blinding_secret
			).map_err(|_| ())?,
		}))
	}
}

impl Writeable for BlindedPath {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		self.introduction_node_id.write(w)?;
		self.blinding_point.write(w)?;
		(self.blinded_hops.len() as u8).write(w)?;
		for hop in &self.blinded_hops {
			hop.write(w)?;
		}
		Ok(())
	}
}

impl Readable for BlindedPath {
	fn read<R: io::Read>(r: &mut R) -> Result<Self, DecodeError> {
		let introduction_node_id = Readable::read(r)?;
		let blinding_point = Readable::read(r)?;
		let num_hops: u8 = Readable::read(r)?;
		if num_hops == 0 { return Err(DecodeError::InvalidValue) }
		let mut blinded_hops: Vec<BlindedHop> = Vec::with_capacity(num_hops.into());
		for _ in 0..num_hops {
			blinded_hops.push(Readable::read(r)?);
		}
		Ok(BlindedPath {
			introduction_node_id,
			blinding_point,
			blinded_hops,
		})
	}
}

impl_writeable!(BlindedHop, {
	blinded_node_id,
	encrypted_payload
});

