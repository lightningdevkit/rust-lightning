use bitcoin::secp256k1::{self, PublicKey, Secp256k1, SecretKey};

use crate::blinded_path::{BlindedHop, BlindedPath};
use crate::blinded_path::utils;
use crate::io;
use crate::io::Cursor;
use crate::ln::onion_utils;
use crate::onion_message::ControlTlvs;
use crate::prelude::*;
use crate::sign::{NodeSigner, Recipient};
use crate::util::chacha20poly1305rfc::ChaChaPolyReadAdapter;
use crate::util::ser::{FixedLengthReader, LengthReadableArgs, Writeable, Writer};

use core::mem;
use core::ops::Deref;

/// TLVs to encode in an intermediate onion message packet's hop data. When provided in a blinded
/// route, they are encoded into [`BlindedHop::encrypted_payload`].
pub(crate) struct ForwardTlvs {
	/// The node id of the next hop in the onion message's path.
	pub(crate) next_node_id: PublicKey,
	/// Senders to a blinded path use this value to concatenate the route they find to the
	/// introduction node with the blinded path.
	pub(crate) next_blinding_override: Option<PublicKey>,
}

/// Similar to [`ForwardTlvs`], but these TLVs are for the final node.
pub(crate) struct ReceiveTlvs {
	/// If `path_id` is `Some`, it is used to identify the blinded path that this onion message is
	/// sending to. This is useful for receivers to check that said blinded path is being used in
	/// the right context.
	pub(crate) path_id: Option<[u8; 32]>,
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

/// Construct blinded onion message hops for the given `unblinded_path`.
pub(super) fn blinded_hops<T: secp256k1::Signing + secp256k1::Verification>(
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
					encrypted_payload: utils::encrypt_payload(payload, prev_ss),
				});
			} else { debug_assert!(false); }
		}
		prev_ss_and_blinded_node_id = Some((encrypted_payload_ss, blinded_node_id));
	})?;

	if let Some((final_ss, final_blinded_node_id)) = prev_ss_and_blinded_node_id {
		let final_payload = ReceiveTlvs { path_id: None };
		blinded_hops.push(BlindedHop {
			blinded_node_id: final_blinded_node_id,
			encrypted_payload: utils::encrypt_payload(final_payload, final_ss),
		});
	} else { debug_assert!(false) }

	Ok(blinded_hops)
}

// Advance the blinded onion message path by one hop, so make the second hop into the new
// introduction node.
pub(crate) fn advance_path_by_one<NS: Deref, T: secp256k1::Signing + secp256k1::Verification>(
	path: &mut BlindedPath, node_signer: &NS, secp_ctx: &Secp256k1<T>
) -> Result<(), ()> where NS::Target: NodeSigner {
	let control_tlvs_ss = node_signer.ecdh(Recipient::Node, &path.blinding_point, None)?;
	let rho = onion_utils::gen_rho_from_shared_secret(&control_tlvs_ss.secret_bytes());
	let encrypted_control_tlvs = path.blinded_hops.remove(0).encrypted_payload;
	let mut s = Cursor::new(&encrypted_control_tlvs);
	let mut reader = FixedLengthReader::new(&mut s, encrypted_control_tlvs.len() as u64);
	match ChaChaPolyReadAdapter::read(&mut reader, rho) {
		Ok(ChaChaPolyReadAdapter { readable: ControlTlvs::Forward(ForwardTlvs {
			mut next_node_id, next_blinding_override,
		})}) => {
			let mut new_blinding_point = match next_blinding_override {
				Some(blinding_point) => blinding_point,
				None => {
					onion_utils::next_hop_pubkey(secp_ctx, path.blinding_point,
						control_tlvs_ss.as_ref()).map_err(|_| ())?
				}
			};
			mem::swap(&mut path.blinding_point, &mut new_blinding_point);
			mem::swap(&mut path.introduction_node_id, &mut next_node_id);
			Ok(())
		},
		_ => Err(())
	}
}
