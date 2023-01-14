// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Creating blinded paths and related utilities live here.

use bitcoin::hashes::{Hash, HashEngine};
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::secp256k1::{self, PublicKey, Scalar, Secp256k1, SecretKey};

use crate::chain::keysinterface::{EntropySource, NodeSigner, Recipient};
use super::packet::ControlTlvs;
use super::utils;
use crate::ln::msgs::DecodeError;
use crate::ln::onion_utils;
use crate::util::chacha20poly1305rfc::{ChaChaPolyReadAdapter, ChaChaPolyWriteAdapter};
use crate::util::ser::{FixedLengthReader, LengthReadableArgs, Readable, VecWriter, Writeable, Writer};

use core::mem;
use core::ops::Deref;
use crate::io::{self, Cursor};
use crate::prelude::*;

/// Onion messages can be sent and received to blinded paths, which serve to hide the identity of
/// the recipient.
#[derive(Clone, Debug, PartialEq)]
pub struct BlindedPath {
	/// To send to a blinded path, the sender first finds a route to the unblinded
	/// `introduction_node_id`, which can unblind its [`encrypted_payload`] to find out the onion
	/// message's next hop and forward it along.
	///
	/// [`encrypted_payload`]: BlindedHop::encrypted_payload
	pub(crate) introduction_node_id: PublicKey,
	/// Used by the introduction node to decrypt its [`encrypted_payload`] to forward the onion
	/// message.
	///
	/// [`encrypted_payload`]: BlindedHop::encrypted_payload
	pub(crate) blinding_point: PublicKey,
	/// The hops composing the blinded path.
	pub(crate) blinded_hops: Vec<BlindedHop>,
}

/// Used to construct the blinded hops portion of a blinded path. These hops cannot be identified
/// by outside observers and thus can be used to hide the identity of the recipient.
#[derive(Clone, Debug, PartialEq)]
pub struct BlindedHop {
	/// The blinded node id of this hop in a blinded path.
	pub(crate) blinded_node_id: PublicKey,
	/// The encrypted payload intended for this hop in a blinded path.
	// The node sending to this blinded path will later encode this payload into the onion packet for
	// this hop.
	pub(crate) encrypted_payload: Vec<u8>,
}

impl BlindedPath {
	/// Create a blinded path to be forwarded along `node_pks`. The last node pubkey in `node_pks`
	/// will be the destination node.
	///
	/// Errors if less than two hops are provided or if `node_pk`(s) are invalid.
	//  TODO: make all payloads the same size with padding + add dummy hops
	pub fn new<ES: EntropySource, T: secp256k1::Signing + secp256k1::Verification>
		(node_pks: &[PublicKey], entropy_source: &ES, secp_ctx: &Secp256k1<T>) -> Result<Self, ()>
	{
		if node_pks.len() < 2 { return Err(()) }
		let blinding_secret_bytes = entropy_source.get_secure_random_bytes();
		let blinding_secret = SecretKey::from_slice(&blinding_secret_bytes[..]).expect("RNG is busted");
		let introduction_node_id = node_pks[0];

		Ok(BlindedPath {
			introduction_node_id,
			blinding_point: PublicKey::from_secret_key(secp_ctx, &blinding_secret),
			blinded_hops: blinded_hops(secp_ctx, node_pks, &blinding_secret).map_err(|_| ())?,
		})
	}

	// Advance the blinded path by one hop, so make the second hop into the new introduction node.
	pub(super) fn advance_by_one<NS: Deref, T: secp256k1::Signing + secp256k1::Verification>
		(&mut self, node_signer: &NS, secp_ctx: &Secp256k1<T>) -> Result<(), ()>
		where NS::Target: NodeSigner
	{
		let control_tlvs_ss = node_signer.ecdh(Recipient::Node, &self.blinding_point, None)?;
		let rho = onion_utils::gen_rho_from_shared_secret(&control_tlvs_ss.secret_bytes());
		let encrypted_control_tlvs = self.blinded_hops.remove(0).encrypted_payload;
		let mut s = Cursor::new(&encrypted_control_tlvs);
		let mut reader = FixedLengthReader::new(&mut s, encrypted_control_tlvs.len() as u64);
		match ChaChaPolyReadAdapter::read(&mut reader, rho) {
			Ok(ChaChaPolyReadAdapter { readable: ControlTlvs::Forward(ForwardTlvs {
				mut next_node_id, next_blinding_override,
			})}) => {
				let mut new_blinding_point = match next_blinding_override {
					Some(blinding_point) => blinding_point,
					None => {
						let blinding_factor = {
							let mut sha = Sha256::engine();
							sha.input(&self.blinding_point.serialize()[..]);
							sha.input(control_tlvs_ss.as_ref());
							Sha256::from_engine(sha).into_inner()
						};
						self.blinding_point.mul_tweak(secp_ctx, &Scalar::from_be_bytes(blinding_factor).unwrap())
							.map_err(|_| ())?
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

/// Construct blinded hops for the given `unblinded_path`.
fn blinded_hops<T: secp256k1::Signing + secp256k1::Verification>(
	secp_ctx: &Secp256k1<T>, unblinded_path: &[PublicKey], session_priv: &SecretKey
) -> Result<Vec<BlindedHop>, secp256k1::Error> {
	let mut blinded_hops = Vec::with_capacity(unblinded_path.len());

	let mut prev_ss_and_blinded_node_id = None;
	utils::construct_keys_callback(secp_ctx, unblinded_path, None, session_priv, |blinded_node_id, _, _, encrypted_payload_ss, unblinded_pk, _| {
		if let Some((prev_ss, prev_blinded_node_id)) = prev_ss_and_blinded_node_id {
			if let Some(pk) = unblinded_pk {
				let payload = ForwardTlvs {
					next_node_id: pk,
					next_blinding_override: None,
				};
				blinded_hops.push(BlindedHop {
					blinded_node_id: prev_blinded_node_id,
					encrypted_payload: encrypt_payload(payload, prev_ss),
				});
			} else { debug_assert!(false); }
		}
		prev_ss_and_blinded_node_id = Some((encrypted_payload_ss, blinded_node_id));
	})?;

	if let Some((final_ss, final_blinded_node_id)) = prev_ss_and_blinded_node_id {
		let final_payload = ReceiveTlvs { path_id: None };
		blinded_hops.push(BlindedHop {
			blinded_node_id: final_blinded_node_id,
			encrypted_payload: encrypt_payload(final_payload, final_ss),
		});
	} else { debug_assert!(false) }

	Ok(blinded_hops)
}

/// Encrypt TLV payload to be used as a [`BlindedHop::encrypted_payload`].
fn encrypt_payload<P: Writeable>(payload: P, encrypted_tlvs_ss: [u8; 32]) -> Vec<u8> {
	let mut writer = VecWriter(Vec::new());
	let write_adapter = ChaChaPolyWriteAdapter::new(encrypted_tlvs_ss, &payload);
	write_adapter.write(&mut writer).expect("In-memory writes cannot fail");
	writer.0
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

/// TLVs to encode in an intermediate onion message packet's hop data. When provided in a blinded
/// route, they are encoded into [`BlindedHop::encrypted_payload`].
pub(crate) struct ForwardTlvs {
	/// The node id of the next hop in the onion message's path.
	pub(super) next_node_id: PublicKey,
	/// Senders to a blinded path use this value to concatenate the route they find to the
	/// introduction node with the blinded path.
	pub(super) next_blinding_override: Option<PublicKey>,
}

/// Similar to [`ForwardTlvs`], but these TLVs are for the final node.
pub(crate) struct ReceiveTlvs {
	/// If `path_id` is `Some`, it is used to identify the blinded path that this onion message is
	/// sending to. This is useful for receivers to check that said blinded path is being used in
	/// the right context.
	pub(super) path_id: Option<[u8; 32]>,
}

impl Writeable for ForwardTlvs {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		// TODO: write padding
		encode_tlv_stream!(writer, {
			(4, self.next_node_id, required),
			(8, self.next_blinding_override, option)
		});
		Ok(())
	}
}

impl Writeable for ReceiveTlvs {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		// TODO: write padding
		encode_tlv_stream!(writer, {
			(6, self.path_id, option),
		});
		Ok(())
	}
}
