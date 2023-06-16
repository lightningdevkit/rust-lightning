use bitcoin::secp256k1::{self, PublicKey, Secp256k1, SecretKey};
use crate::blinded_path::BlindedHop;
use crate::blinded_path::utils;
use crate::io;
use crate::prelude::*;
use crate::util::ser::{Writeable, Writer};

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
