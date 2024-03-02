use bitcoin::secp256k1::{self, PublicKey, Secp256k1, SecretKey};

#[allow(unused_imports)]
use crate::prelude::*;

use crate::blinded_path::{BlindedHop, BlindedPath};
use crate::blinded_path::utils;
use crate::io;
use crate::io::Cursor;
use crate::ln::onion_utils;
use crate::onion_message::packet::ControlTlvs;
use crate::sign::{NodeSigner, Recipient};
use crate::crypto::streams::ChaChaPolyReadAdapter;
use crate::util::ser::{FixedLengthReader, LengthReadableArgs, Writeable, Writer};

use core::mem;
use core::ops::Deref;

/// TLVs to encode in an intermediate onion message packet's hop data. When provided in a blinded
/// route, they are encoded into [`BlindedHop::encrypted_payload`].
pub(crate) struct ForwardTlvs {
	/// The next hop in the onion message's path.
	pub(crate) next_hop: NextHop,
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

/// The next hop to forward the onion message along its path.
#[derive(Debug)]
pub enum NextHop {
	/// The node id of the next hop.
	NodeId(PublicKey),
	/// The short channel id leading to the next hop.
	ShortChannelId(u64),
}

impl Writeable for ForwardTlvs {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		let (next_node_id, short_channel_id) = match self.next_hop {
			NextHop::NodeId(pubkey) => (Some(pubkey), None),
			NextHop::ShortChannelId(scid) => (None, Some(scid)),
		};
		// TODO: write padding
		encode_tlv_stream!(writer, {
			(2, short_channel_id, option),
			(4, next_node_id, option),
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
	let blinded_tlvs = unblinded_path.iter()
		.skip(1) // The first node's TLVs contains the next node's pubkey
		.map(|pk| ForwardTlvs { next_hop: NextHop::NodeId(*pk), next_blinding_override: None })
		.map(|tlvs| ControlTlvs::Forward(tlvs))
		.chain(core::iter::once(ControlTlvs::Receive(ReceiveTlvs { path_id: None })));

	utils::construct_blinded_hops(secp_ctx, unblinded_path.iter(), blinded_tlvs, session_priv)
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
		Ok(ChaChaPolyReadAdapter {
			readable: ControlTlvs::Forward(ForwardTlvs { next_hop, next_blinding_override })
		}) => {
			let mut next_node_id = match next_hop {
				NextHop::NodeId(pubkey) => pubkey,
				NextHop::ShortChannelId(_) => todo!(),
			};
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
