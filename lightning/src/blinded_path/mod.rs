// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Creating blinded paths and related utilities live here.

pub(crate) mod message;
pub(crate) mod utils;

use bitcoin::secp256k1::{self, PublicKey, Secp256k1, SecretKey};

use crate::sign::{EntropySource, NodeSigner, Recipient};
use crate::onion_message::ControlTlvs;
use crate::ln::msgs::DecodeError;
use crate::ln::onion_utils;
use crate::util::chacha20poly1305rfc::ChaChaPolyReadAdapter;
use crate::util::ser::{FixedLengthReader, LengthReadableArgs, Readable, Writeable, Writer};

use core::mem;
use core::ops::Deref;
use crate::io::{self, Cursor};
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

/// Used to construct the blinded hops portion of a blinded path. These hops cannot be identified
/// by outside observers and thus can be used to hide the identity of the recipient.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct BlindedHop {
	/// The blinded node id of this hop in a blinded path.
	pub blinded_node_id: PublicKey,
	/// The encrypted payload intended for this hop in a blinded path.
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

	// Advance the blinded onion message path by one hop, so make the second hop into the new
	// introduction node.
	pub(super) fn advance_message_path_by_one<NS: Deref, T: secp256k1::Signing + secp256k1::Verification>
		(&mut self, node_signer: &NS, secp_ctx: &Secp256k1<T>) -> Result<(), ()>
		where NS::Target: NodeSigner
	{
		let control_tlvs_ss = node_signer.ecdh(Recipient::Node, &self.blinding_point, None)?;
		let rho = onion_utils::gen_rho_from_shared_secret(&control_tlvs_ss.secret_bytes());
		let encrypted_control_tlvs = self.blinded_hops.remove(0).encrypted_payload;
		let mut s = Cursor::new(&encrypted_control_tlvs);
		let mut reader = FixedLengthReader::new(&mut s, encrypted_control_tlvs.len() as u64);
		match ChaChaPolyReadAdapter::read(&mut reader, rho) {
			Ok(ChaChaPolyReadAdapter { readable: ControlTlvs::Forward(message::ForwardTlvs {
				mut next_node_id, next_blinding_override,
			})}) => {
				let mut new_blinding_point = match next_blinding_override {
					Some(blinding_point) => blinding_point,
					None => {
						onion_utils::next_hop_pubkey(secp_ctx, self.blinding_point,
							control_tlvs_ss.as_ref()).map_err(|_| ())?
					}
				};
				mem::swap(&mut self.blinding_point, &mut new_blinding_point);
				mem::swap(&mut self.introduction_node_id, &mut next_node_id);
				Ok(())
			},
			_ => Err(())
		}
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

