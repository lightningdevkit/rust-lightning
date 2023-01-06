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
use bitcoin::secp256k1::ecdh::SharedSecret;

use crate::ln::msgs::DecodeError;
use crate::ln::onion_utils;
use super::blinded_path::{BlindedPath, ForwardTlvs, ReceiveTlvs};
use super::messenger::CustomOnionMessageHandler;
use crate::util::chacha20poly1305rfc::{ChaChaPolyReadAdapter, ChaChaPolyWriteAdapter};
use crate::util::ser::{BigSize, FixedLengthReader, LengthRead, LengthReadable, LengthReadableArgs, Readable, ReadableArgs, Writeable, Writer};

use core::cmp;
use crate::io::{self, Read};
use crate::prelude::*;

// Per the spec, an onion message packet's `hop_data` field length should be
// SMALL_PACKET_HOP_DATA_LEN if it fits, else BIG_PACKET_HOP_DATA_LEN if it fits.
pub(super) const SMALL_PACKET_HOP_DATA_LEN: usize = 1300;
pub(super) const BIG_PACKET_HOP_DATA_LEN: usize = 32768;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Packet {
	pub(super) version: u8,
	pub(super) public_key: PublicKey,
	// Unlike the onion packets used for payments, onion message packets can have payloads greater
	// than 1300 bytes.
	// TODO: if 1300 ends up being the most common size, optimize this to be:
	// enum { ThirteenHundred([u8; 1300]), VarLen(Vec<u8>) }
	pub(super) hop_data: Vec<u8>,
	pub(super) hmac: [u8; 32],
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
		let hop_data_len = r.total_bytes().saturating_sub(66) as usize; // 1 (version) + 33 (pubkey) + 32 (HMAC) = 66
		let mut read_idx = 0;
		while read_idx < hop_data_len {
			let mut read_buffer = [0; READ_BUFFER_SIZE];
			let read_amt = cmp::min(hop_data_len - read_idx, READ_BUFFER_SIZE);
			r.read_exact(&mut read_buffer[..read_amt])?;
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
pub(super) enum Payload<T: CustomOnionMessageContents> {
	/// This payload is for an intermediate hop.
	Forward(ForwardControlTlvs),
	/// This payload is for the final hop.
	Receive {
		control_tlvs: ReceiveControlTlvs,
		reply_path: Option<BlindedPath>,
		message: OnionMessageContents<T>,
	}
}

#[derive(Debug)]
/// The contents of an onion message. In the context of offers, this would be the invoice, invoice
/// request, or invoice error.
pub enum OnionMessageContents<T: CustomOnionMessageContents> {
	// Coming soon:
	// Invoice,
	// InvoiceRequest,
	// InvoiceError,
	/// A custom onion message specified by the user.
	Custom(T),
}

impl<T: CustomOnionMessageContents> OnionMessageContents<T> {
	/// Returns the type that was used to decode the message payload.
	///
	/// (C-not exported) as methods on non-cloneable enums are not currently exportable
	pub fn tlv_type(&self) -> u64 {
		match self {
			&OnionMessageContents::Custom(ref msg) => msg.tlv_type(),
		}
	}
}

/// (C-not exported) as methods on non-cloneable enums are not currently exportable
impl<T: CustomOnionMessageContents> Writeable for OnionMessageContents<T> {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		match self {
			OnionMessageContents::Custom(msg) => Ok(msg.write(w)?),
		}
	}
}

/// The contents of a custom onion message.
pub trait CustomOnionMessageContents: Writeable {
	/// Returns the TLV type identifying the message contents. MUST be >= 64.
	fn tlv_type(&self) -> u64;
}

/// Forward control TLVs in their blinded and unblinded form.
pub(super) enum ForwardControlTlvs {
	/// If we're sending to a blinded path, the node that constructed the blinded path has provided
	/// this hop's control TLVs, already encrypted into bytes.
	Blinded(Vec<u8>),
	/// If we're constructing an onion message hop through an intermediate unblinded node, we'll need
	/// to construct the intermediate hop's control TLVs in their unblinded state to avoid encoding
	/// them into an intermediate Vec. See [`super::blinded_path::ForwardTlvs`] for more info.
	Unblinded(ForwardTlvs),
}

/// Receive control TLVs in their blinded and unblinded form.
pub(super) enum ReceiveControlTlvs {
	/// See [`ForwardControlTlvs::Blinded`].
	Blinded(Vec<u8>),
	/// See [`ForwardControlTlvs::Unblinded`] and [`super::blinded_path::ReceiveTlvs`].
	Unblinded(ReceiveTlvs),
}

// Uses the provided secret to simultaneously encode and encrypt the unblinded control TLVs.
impl<T: CustomOnionMessageContents> Writeable for (Payload<T>, [u8; 32]) {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		match &self.0 {
			Payload::Forward(ForwardControlTlvs::Blinded(encrypted_bytes)) => {
				_encode_varint_length_prefixed_tlv!(w, {
					(4, *encrypted_bytes, vec_type)
				})
			},
			Payload::Receive {
				control_tlvs: ReceiveControlTlvs::Blinded(encrypted_bytes), reply_path, message,
			} => {
				_encode_varint_length_prefixed_tlv!(w, {
					(2, reply_path, option),
					(4, *encrypted_bytes, vec_type),
					(message.tlv_type(), message, required)
				})
			},
			Payload::Forward(ForwardControlTlvs::Unblinded(control_tlvs)) => {
				let write_adapter = ChaChaPolyWriteAdapter::new(self.1, &control_tlvs);
				_encode_varint_length_prefixed_tlv!(w, {
					(4, write_adapter, required)
				})
			},
			Payload::Receive {
				control_tlvs: ReceiveControlTlvs::Unblinded(control_tlvs), reply_path, message,
			} => {
				let write_adapter = ChaChaPolyWriteAdapter::new(self.1, &control_tlvs);
				_encode_varint_length_prefixed_tlv!(w, {
					(2, reply_path, option),
					(4, write_adapter, required),
					(message.tlv_type(), message, required)
				})
			},
		}
		Ok(())
	}
}

// Uses the provided secret to simultaneously decode and decrypt the control TLVs and data TLV.
impl<H: CustomOnionMessageHandler> ReadableArgs<(SharedSecret, &H)> for Payload<<H as CustomOnionMessageHandler>::CustomMessage> {
	fn read<R: Read>(r: &mut R, args: (SharedSecret, &H)) -> Result<Self, DecodeError> {
		let (encrypted_tlvs_ss, handler) = args;

		let v: BigSize = Readable::read(r)?;
		let mut rd = FixedLengthReader::new(r, v.0);
		let mut reply_path: Option<BlindedPath> = None;
		let mut read_adapter: Option<ChaChaPolyReadAdapter<ControlTlvs>> = None;
		let rho = onion_utils::gen_rho_from_shared_secret(&encrypted_tlvs_ss.secret_bytes());
		let mut message_type: Option<u64> = None;
		let mut message = None;
		decode_tlv_stream_with_custom_tlv_decode!(&mut rd, {
			(2, reply_path, option),
			(4, read_adapter, (option: LengthReadableArgs, rho)),
		}, |msg_type, msg_reader| {
			if msg_type < 64 { return Ok(false) }
			// Don't allow reading more than one data TLV from an onion message.
			if message_type.is_some() { return Err(DecodeError::InvalidValue) }

			message_type = Some(msg_type);
			match handler.read_custom_message(msg_type, msg_reader) {
				Ok(Some(msg)) => {
					message = Some(msg);
					Ok(true)
				},
				Ok(None) => Ok(false),
				Err(e) => Err(e),
			}
		});
		rd.eat_remaining().map_err(|_| DecodeError::ShortRead)?;

		match read_adapter {
			None => return Err(DecodeError::InvalidValue),
			Some(ChaChaPolyReadAdapter { readable: ControlTlvs::Forward(tlvs)}) => {
				if message_type.is_some() {
					return Err(DecodeError::InvalidValue)
				}
				Ok(Payload::Forward(ForwardControlTlvs::Unblinded(tlvs)))
			},
			Some(ChaChaPolyReadAdapter { readable: ControlTlvs::Receive(tlvs)}) => {
				if message.is_none() { return Err(DecodeError::InvalidValue) }
				Ok(Payload::Receive {
					control_tlvs: ReceiveControlTlvs::Unblinded(tlvs),
					reply_path,
					message: OnionMessageContents::Custom(message.unwrap()),
				})
			}
		}
	}
}

/// When reading a packet off the wire, we don't know a priori whether the packet is to be forwarded
/// or received. Thus we read a ControlTlvs rather than reading a ForwardControlTlvs or
/// ReceiveControlTlvs directly.
pub(super) enum ControlTlvs {
	/// This onion message is intended to be forwarded.
	Forward(ForwardTlvs),
	/// This onion message is intended to be received.
	Receive(ReceiveTlvs),
}

impl Readable for ControlTlvs {
	fn read<R: Read>(mut r: &mut R) -> Result<Self, DecodeError> {
		let mut _padding: Option<Padding> = None;
		let mut _short_channel_id: Option<u64> = None;
		let mut next_node_id: Option<PublicKey> = None;
		let mut path_id: Option<[u8; 32]> = None;
		let mut next_blinding_override: Option<PublicKey> = None;
		decode_tlv_stream!(&mut r, {
			(1, _padding, option),
			(2, _short_channel_id, option),
			(4, next_node_id, option),
			(6, path_id, option),
			(8, next_blinding_override, option),
		});

		let valid_fwd_fmt  = next_node_id.is_some() && path_id.is_none();
		let valid_recv_fmt = next_node_id.is_none() && next_blinding_override.is_none();

		let payload_fmt = if valid_fwd_fmt {
			ControlTlvs::Forward(ForwardTlvs {
				next_node_id: next_node_id.unwrap(),
				next_blinding_override,
			})
		} else if valid_recv_fmt {
			ControlTlvs::Receive(ReceiveTlvs {
				path_id,
			})
		} else {
			return Err(DecodeError::InvalidValue)
		};

		Ok(payload_fmt)
	}
}

/// Reads padding to the end, ignoring what's read.
pub(crate) struct Padding {}
impl Readable for Padding {
	#[inline]
	fn read<R: Read>(reader: &mut R) -> Result<Self, DecodeError> {
		loop {
			let mut buf = [0; 8192];
			if reader.read(&mut buf[..])? == 0 { break; }
		}
		Ok(Self {})
	}
}
