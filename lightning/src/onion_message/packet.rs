// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Structs and enums useful for constructing and reading an onion message packet.

use bitcoin::secp256k1::PublicKey;

use ln::msgs::DecodeError;
use ln::onion_utils;
use super::blinded_route::{ForwardTlvs, ReceiveTlvs};
use util::chacha20poly1305rfc::ChaChaPolyWriteAdapter;
use util::ser::{LengthRead, LengthReadable, Readable, Writeable, Writer};

use core::cmp;
use io;
use prelude::*;

// Per the spec, an onion message packet's `hop_data` field length should be
// SMALL_PACKET_HOP_DATA_LEN if it fits, else BIG_PACKET_HOP_DATA_LEN if it fits.
pub(super) const SMALL_PACKET_HOP_DATA_LEN: usize = 1300;
pub(super) const BIG_PACKET_HOP_DATA_LEN: usize = 32768;

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Packet {
	version: u8,
	public_key: PublicKey,
	// Unlike the onion packets used for payments, onion message packets can have payloads greater
	// than 1300 bytes.
	// TODO: if 1300 ends up being the most common size, optimize this to be:
	// enum { ThirteenHundred([u8; 1300]), VarLen(Vec<u8>) }
	hop_data: Vec<u8>,
	hmac: [u8; 32],
}

impl onion_utils::Packet for Packet {
	type Data = Vec<u8>;
	fn new(public_key: PublicKey, hop_data: Vec<u8>, hmac: [u8; 32]) -> Packet {
		Self {
			version: 0,
			public_key,
			hop_data,
			hmac,
		}
	}
}

impl Writeable for Packet {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		self.version.write(w)?;
		self.public_key.write(w)?;
		w.write_all(&self.hop_data)?;
		self.hmac.write(w)?;
		Ok(())
	}
}

impl LengthReadable for Packet {
	fn read<R: LengthRead>(r: &mut R) -> Result<Self, DecodeError> {
		const READ_BUFFER_SIZE: usize = 4096;

		let version = Readable::read(r)?;
		let public_key = Readable::read(r)?;

		let mut hop_data = Vec::new();
		let hop_data_len = r.total_bytes() as usize - 66; // 1 (version) + 33 (pubkey) + 32 (HMAC) = 66
		let mut read_idx = 0;
		while read_idx < hop_data_len {
			let mut read_buffer = [0; READ_BUFFER_SIZE];
			let read_amt = cmp::min(hop_data_len - read_idx, READ_BUFFER_SIZE);
			r.read_exact(&mut read_buffer[..read_amt]);
			hop_data.extend_from_slice(&read_buffer[..read_amt]);
			read_idx += read_amt;
		}

		let hmac = Readable::read(r)?;
		Ok(Packet {
			version,
			public_key,
			hop_data,
			hmac,
		})
	}
}

/// Onion message payloads contain "control" TLVs and "data" TLVs. Control TLVs are used to route
/// the onion message from hop to hop and for path verification, whereas data TLVs contain the onion
/// message content itself, such as an invoice request.
pub(super) enum Payload {
	/// This payload is for an intermediate hop.
	Forward(ForwardControlTlvs),
	/// This payload is for the final hop.
	Receive {
		control_tlvs: ReceiveControlTlvs,
		// Coming soon:
		// reply_path: Option<BlindedRoute>,
		// message: Message,
	}
}

// Coming soon:
// enum Message {
// 	InvoiceRequest(InvoiceRequest),
// 	Invoice(Invoice),
//	InvoiceError(InvoiceError),
//	CustomMessage<T>,
// }

/// Forward control TLVs in their blinded and unblinded form.
pub(super) enum ForwardControlTlvs {
	/// If we're sending to a blinded route, the node that constructed the blinded route has provided
	/// this hop's control TLVs, already encrypted into bytes.
	Blinded(Vec<u8>),
	/// If we're constructing an onion message hop through an intermediate unblinded node, we'll need
	/// to construct the intermediate hop's control TLVs in their unblinded state to avoid encoding
	/// them into an intermediate Vec. See [`super::blinded_route::ForwardTlvs`] for more info.
	Unblinded(ForwardTlvs),
}

/// Receive control TLVs in their blinded and unblinded form.
pub(super) enum ReceiveControlTlvs {
	/// See [`ForwardControlTlvs::Blinded`].
	Blinded(Vec<u8>),
	/// See [`ForwardControlTlvs::Unblinded`] and [`super::blinded_route::ReceiveTlvs`].
	Unblinded(ReceiveTlvs),
}

// Uses the provided secret to simultaneously encode and encrypt the unblinded control TLVs.
impl Writeable for (Payload, [u8; 32]) {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		match &self.0 {
			Payload::Forward(ForwardControlTlvs::Blinded(encrypted_bytes)) |
			Payload::Receive { control_tlvs: ReceiveControlTlvs::Blinded(encrypted_bytes)} => {
				encode_varint_length_prefixed_tlv!(w, {
					(4, encrypted_bytes, vec_type)
				})
			},
			Payload::Forward(ForwardControlTlvs::Unblinded(control_tlvs)) => {
				let write_adapter = ChaChaPolyWriteAdapter::new(self.1, &control_tlvs);
				encode_varint_length_prefixed_tlv!(w, {
					(4, write_adapter, required)
				})
			},
			Payload::Receive { control_tlvs: ReceiveControlTlvs::Unblinded(control_tlvs)} => {
				let write_adapter = ChaChaPolyWriteAdapter::new(self.1, &control_tlvs);
				encode_varint_length_prefixed_tlv!(w, {
					(4, write_adapter, required)
				})
			},
		}
		Ok(())
	}
}
