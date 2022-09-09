// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Creating blinded routes and related utilities live here.

use bitcoin::secp256k1::{self, PublicKey, Secp256k1, SecretKey};

use chain::keysinterface::KeysInterface;
use super::utils;
use ::get_control_tlv_length;
use ln::msgs::DecodeError;
use util::chacha20poly1305rfc::ChaChaPolyWriteAdapter;
use util::ser::{Readable, VecWriter, Writeable, Writer};
use super::packet::{ControlTlvs, Padding};

use io;
use prelude::*;

/// Onion messages can be sent and received to blinded routes, which serve to hide the identity of
/// the recipient.
pub struct BlindedRoute {
	/// To send to a blinded route, the sender first finds a route to the unblinded
	/// `introduction_node_id`, which can unblind its [`encrypted_payload`] to find out the onion
	/// message's next hop and forward it along.
	///
	/// [`encrypted_payload`]: BlindedHop::encrypted_payload
	pub(super) introduction_node_id: PublicKey,
	/// Used by the introduction node to decrypt its [`encrypted_payload`] to forward the onion
	/// message.
	///
	/// [`encrypted_payload`]: BlindedHop::encrypted_payload
	pub(super) blinding_point: PublicKey,
	/// The hops composing the blinded route.
	pub(super) blinded_hops: Vec<BlindedHop>,
}

/// Used to construct the blinded hops portion of a blinded route. These hops cannot be identified
/// by outside observers and thus can be used to hide the identity of the recipient.
pub struct BlindedHop {
	/// The blinded node id of this hop in a blinded route.
	pub(super) blinded_node_id: PublicKey,
	/// The encrypted payload intended for this hop in a blinded route.
	// The node sending to this blinded route will later encode this payload into the onion packet for
	// this hop.
	pub(super) encrypted_payload: Vec<u8>,
}

impl BlindedRoute {
	/// Create a blinded route to be forwarded along `node_pks`. The last node pubkey in `node_pks`
	/// will be the destination node.
	///
	/// Errors if less than two hops are provided or if `node_pk`(s) are invalid.
	//  TODO: Add dummy hops
	pub fn new<K: KeysInterface, T: secp256k1::Signing + secp256k1::Verification> (
		node_pks: &[PublicKey], keys_manager: &K, secp_ctx: &Secp256k1<T>,
		include_next_blinding_override_padding: bool
	) -> Result<Self, ()> {
		if node_pks.len() < 2 { return Err(()) }
		let blinding_secret_bytes = keys_manager.get_secure_random_bytes();
		let blinding_secret = SecretKey::from_slice(&blinding_secret_bytes[..]).expect("RNG is busted");
		let introduction_node_id = node_pks[0];

		Ok(BlindedRoute {
			introduction_node_id,
			blinding_point: PublicKey::from_secret_key(secp_ctx, &blinding_secret),
			blinded_hops: blinded_hops(secp_ctx, node_pks, &blinding_secret, include_next_blinding_override_padding).map_err(|_| ())?,
		})
	}
}

/// Construct blinded hops for the given `unblinded_path`.
fn blinded_hops<T: secp256k1::Signing + secp256k1::Verification>(
	secp_ctx: &Secp256k1<T>, unblinded_path: &[PublicKey], session_priv: &SecretKey,
	include_next_blinding_override_padding: bool
) -> Result<Vec<BlindedHop>, secp256k1::Error> {
	let mut blinded_hops = Vec::with_capacity(unblinded_path.len());
	let max_length = get_control_tlv_length!(true, include_next_blinding_override_padding);

	let mut prev_ss_and_blinded_node_id = None;
	utils::construct_keys_callback(secp_ctx, unblinded_path, None, session_priv, |blinded_node_id, _, _, encrypted_payload_ss, unblinded_pk, _| {
		if let Some((prev_ss, prev_blinded_node_id)) = prev_ss_and_blinded_node_id {
			if let Some(pk) = unblinded_pk {
				let payload = ForwardTlvs {
					next_node_id: pk,
					next_blinding_override: None,
					total_length: max_length,
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
		let final_payload = ReceiveTlvs { path_id: None, total_length: max_length, };
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

impl Writeable for BlindedRoute {
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

impl Readable for BlindedRoute {
	fn read<R: io::Read>(r: &mut R) -> Result<Self, DecodeError> {
		let introduction_node_id = Readable::read(r)?;
		let blinding_point = Readable::read(r)?;
		let num_hops: u8 = Readable::read(r)?;
		if num_hops == 0 { return Err(DecodeError::InvalidValue) }
		let mut blinded_hops: Vec<BlindedHop> = Vec::with_capacity(num_hops.into());
		for _ in 0..num_hops {
			blinded_hops.push(Readable::read(r)?);
		}
		Ok(BlindedRoute {
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
#[derive(Clone, Copy)]
pub(crate) struct ForwardTlvs {
	/// The node id of the next hop in the onion message's path.
	pub(super) next_node_id: PublicKey,
	/// Senders to a blinded route use this value to concatenate the route they find to the
	/// introduction node with the blinded route.
	pub(super) next_blinding_override: Option<PublicKey>,
	/// The length the tlv should have when it's serialized, with padding included if needed.
	/// Used to ensure that all control tlvs in a blinded route have the same length.
	pub(super) total_length: u16,
}

/// Similar to [`ForwardTlvs`], but these TLVs are for the final node.
#[derive(Clone, Copy)]
pub(crate) struct ReceiveTlvs {
	/// If `path_id` is `Some`, it is used to identify the blinded route that this onion message is
	/// sending to. This is useful for receivers to check that said blinded route is being used in
	/// the right context.
	pub(super) path_id: Option<[u8; 32]>,
	/// The length the tlv should have when it's serialized, with padding included if needed.
	/// Used to ensure that all control tlvs in a blinded route have the same length.
	pub(super) total_length: u16,
}

impl Writeable for ForwardTlvs {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		encode_tlv_stream!(writer, {
			(1, Padding::new_from_tlv(ControlTlvs::Forward(*self)), option),
			(4, self.next_node_id, required),
			(8, self.next_blinding_override, option),
		});
		Ok(())
	}
}

impl Writeable for ReceiveTlvs {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		encode_tlv_stream!(writer, {
			(1, Padding::new_from_tlv(ControlTlvs::Receive(*self)), option),
			(6, self.path_id, option),
		});
		Ok(())
	}
}

#[cfg(test)]
mod test {
	use bitcoin::secp256k1::{PublicKey, SecretKey, Secp256k1};
	use ::get_control_tlv_length;
	use super::{ForwardTlvs, ReceiveTlvs, blinded_hops};
	use util::ser::{VecWriter, Writeable};

	#[test]
	fn padding_is_correctly_serialized() {
		let max_length = get_control_tlv_length!(true, true);

		let dummy_next_node_id = PublicKey::from_slice(&hex::decode("030101010101010101010101010101010101010101010101010101010101010101").unwrap()[..]).unwrap();
		let dummy_blinding_override = PublicKey::from_slice(&hex::decode("030202020202020202020202020202020202020202020202020202020202020202").unwrap()[..]).unwrap();
		let dummy_path_id = [1; 32];

		let no_padding_tlv = ForwardTlvs {
			next_node_id: dummy_next_node_id,
			next_blinding_override: Some(dummy_blinding_override),
			total_length: max_length,
		};

		let blinding_override_padding_tlv = ForwardTlvs {
			next_node_id: dummy_next_node_id,
			next_blinding_override: None,
			total_length: max_length,
		};

		let recieve_tlv_padding_tlv = ReceiveTlvs {
			path_id: Some(dummy_path_id),
			total_length: max_length,
		};

		let full_padding_tlv = ReceiveTlvs {
			path_id: None,
			total_length: max_length,
		};

		let mut w = VecWriter(Vec::new());
		no_padding_tlv.write(&mut w).unwrap();
		let serialized_no_padding_tlv = w.0;
		// As `serialized_no_padding_tlv` is the longest tlv, no padding is expected.
		// Expected data tlv is:
		// 1. 4 (type) for `next_node_id`
		// 2. 33 (length) for the length of a point/public key
		// 3. 33 bytes of the `dummy_next_node_id`
		// 4. 8 (type) for `next_blinding_override`
		// 5. 33 (length) for the length of a point/public key
		// 6. 33 bytes of the `dummy_blinding_override`
		let expected_serialized_no_padding_tlv_payload = &hex::decode("04210301010101010101010101010101010101010101010101010101010101010101010821030202020202020202020202020202020202020202020202020202020202020202").unwrap()[..];
		assert_eq!(serialized_no_padding_tlv, expected_serialized_no_padding_tlv_payload);
		assert_eq!(serialized_no_padding_tlv.len(), max_length as usize);

		w = VecWriter(Vec::new());
		blinding_override_padding_tlv.write(&mut w).unwrap();
		let serialized_blinding_override_padding_tlv = w.0;
		// As `serialized_blinding_override_padding_tlv` has no `next_blinding_override`, 35 bytes
		// of padding is expected (the serialized length of `next_blinding_override`).
		// Expected data tlv is:
		// 1. 1 (type) for padding
		// 2. 33 (length) given the length of a the missing `next_blinding_override`
		// 3. 33 0 bytes of padding
		// 4. 4 (type) for `next_node_id`
		// 5. 33 (length) for the length of a point/public key
		// 6. 33 bytes of the `dummy_next_node_id`
		let expected_serialized_blinding_override_padding_tlv = &hex::decode("01210000000000000000000000000000000000000000000000000000000000000000000421030101010101010101010101010101010101010101010101010101010101010101").unwrap()[..];
		assert_eq!(serialized_blinding_override_padding_tlv, expected_serialized_blinding_override_padding_tlv);
		assert_eq!(serialized_blinding_override_padding_tlv.len(), max_length as usize);

		w = VecWriter(Vec::new());
		recieve_tlv_padding_tlv.write(&mut w).unwrap();
		let serialized_recieve_tlv_padding_tlv = w.0;
		// As `recieve_tlv_padding_tlv` is a `ReceiveTlv` and has a `path_id`, 36 bytes of padding
		// is expected, ie. 70 (value of `max_length`) - 34 (the serialized length of `path_id`).
		// Expected data tlv is:
		// 1. 1 (type) for padding
		// 2. 34 (length) given 70 - 34
		// 3. 34 0 bytes of padding
		// 4. 6 (type) for `path_id`
		// 5. 32 (length) for the length of a `path_id`
		// 6. 32 bytes of the `path_id`
		let expected_serialized_recieve_tlv_padding_tlv_payload = &hex::decode("01220000000000000000000000000000000000000000000000000000000000000000000006200101010101010101010101010101010101010101010101010101010101010101").unwrap()[..];
		assert_eq!(serialized_recieve_tlv_padding_tlv, expected_serialized_recieve_tlv_padding_tlv_payload);
		assert_eq!(serialized_recieve_tlv_padding_tlv.len(), max_length as usize);

		w = VecWriter(Vec::new());
		full_padding_tlv.write(&mut w).unwrap();
		let serialized_full_padding_tlv = w.0;
		// As `serialized_full_padding_tlv` is a `ReceiveTlv` with no data at alll, 70 bytes of
		// padding is expected (value of `max_length`).
		// Expected data tlv is:
		// 1. 1 (type) for padding
		// 2. 68 (length) the length of the padding minus the prefix
		// 3. 68 0 bytes of padding
		let expected_serialized_full_padding_tlv_payload = &hex::decode("01440000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").unwrap()[..];
		assert_eq!(serialized_full_padding_tlv, expected_serialized_full_padding_tlv_payload);
		assert_eq!(serialized_full_padding_tlv.len(), max_length as usize);
	}

	#[test]
	fn blinded_hops_are_same_length() {
		let secp_ctx = Secp256k1::new();
		let first_node_id = PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&hex::decode(format!("{:02}", 41).repeat(32)).unwrap()[..]).unwrap());
		let middle_node_id = PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&hex::decode(format!("{:02}", 42).repeat(32)).unwrap()[..]).unwrap());
		let recieve_node_id = PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&hex::decode(format!("{:02}", 43).repeat(32)).unwrap()[..]).unwrap());
		let session_priv = SecretKey::from_slice(&hex::decode(format!("{:02}", 3).repeat(32)).unwrap()[..]).unwrap();

		let blinded_hops = blinded_hops(&secp_ctx, &[first_node_id, middle_node_id, recieve_node_id], &session_priv, false).unwrap();

		// Verify that the blinded hops returned from `blinded_hops` have the same
		// `encrypted_payload` length, regardless of which type of payload it is.
		let mut expected_encrypted_payload_len = None;
		for blinded_hop in blinded_hops {
			match expected_encrypted_payload_len {
				None => {
					expected_encrypted_payload_len = Some(blinded_hop.encrypted_payload.len());
				},
				Some(expected_len) => {
					assert_eq!(blinded_hop.encrypted_payload.len(), expected_len)
				}
			}
		}
	}
}
