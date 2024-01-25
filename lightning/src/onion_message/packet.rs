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

use crate::blinded_path::BlindedPath;
use crate::blinded_path::message::{ForwardTlvs, ReceiveTlvs};
use crate::blinded_path::utils::Padding;
use crate::ln::msgs::DecodeError;
use crate::ln::onion_utils;
use super::messenger::CustomOnionMessageHandler;
use super::offers::OffersMessage;
use crate::crypto::streams::{ChaChaPolyReadAdapter, ChaChaPolyWriteAdapter};
use crate::util::logger::Logger;
use crate::util::ser::{BigSize, FixedLengthReader, LengthRead, LengthReadable, LengthReadableArgs, Readable, ReadableArgs, Writeable, Writer};

use core::cmp;
use crate::io::{self, Read};
use crate::prelude::*;

// Per the spec, an onion message packet's `hop_data` field length should be
// SMALL_PACKET_HOP_DATA_LEN if it fits, else BIG_PACKET_HOP_DATA_LEN if it fits.
pub(super) const SMALL_PACKET_HOP_DATA_LEN: usize = 1300;
pub(super) const BIG_PACKET_HOP_DATA_LEN: usize = 32768;

/// Packet of hop data for next peer
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct Packet {
	/// Bolt 04 version number
	pub version: u8,
	/// A random sepc256k1 point, used to build the ECDH shared secret to decrypt hop_data
	pub public_key: PublicKey,
	/// Encrypted payload for the next hop
	//
	// Unlike the onion packets used for payments, onion message packets can have payloads greater
	// than 1300 bytes.
	// TODO: if 1300 ends up being the most common size, optimize this to be:
	// enum { ThirteenHundred([u8; 1300]), VarLen(Vec<u8>) }
	pub hop_data: Vec<u8>,
	/// HMAC to verify the integrity of hop_data
	pub hmac: [u8; 32],
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
pub(super) enum Payload<T: OnionMessageContents> {
	/// This payload is for an intermediate hop.
	Forward(ForwardControlTlvs),
	/// This payload is for the final hop.
	Receive {
		control_tlvs: ReceiveControlTlvs,
		reply_path: Option<BlindedPath>,
		message: T,
	}
}

/// The contents of an [`OnionMessage`] as read from the wire.
///
/// [`OnionMessage`]: crate::ln::msgs::OnionMessage
#[derive(Clone, Debug)]
pub enum ParsedOnionMessageContents<T: OnionMessageContents> {
	/// A message related to BOLT 12 Offers.
	Offers(OffersMessage),
	/// A custom onion message specified by the user.
	Custom(T),
}

impl<T: OnionMessageContents> OnionMessageContents for ParsedOnionMessageContents<T> {
	/// Returns the type that was used to decode the message payload.
	///
	/// This is not exported to bindings users as methods on non-cloneable enums are not currently exportable
	fn tlv_type(&self) -> u64 {
		match self {
			&ParsedOnionMessageContents::Offers(ref msg) => msg.tlv_type(),
			&ParsedOnionMessageContents::Custom(ref msg) => msg.tlv_type(),
		}
	}
}

impl<T: OnionMessageContents> Writeable for ParsedOnionMessageContents<T> {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		match self {
			ParsedOnionMessageContents::Offers(msg) => Ok(msg.write(w)?),
			ParsedOnionMessageContents::Custom(msg) => Ok(msg.write(w)?),
		}
	}
}

/// The contents of an onion message.
pub trait OnionMessageContents: Writeable + core::fmt::Debug + Clone {
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
	/// them into an intermediate Vec. See [`crate::blinded_path::message::ForwardTlvs`] for more
	/// info.
	Unblinded(ForwardTlvs),
}

/// Receive control TLVs in their blinded and unblinded form.
pub(super) enum ReceiveControlTlvs {
	/// See [`ForwardControlTlvs::Blinded`].
	Blinded(Vec<u8>),
	/// See [`ForwardControlTlvs::Unblinded`] and [`crate::blinded_path::message::ReceiveTlvs`].
	Unblinded(ReceiveTlvs),
}

// Uses the provided secret to simultaneously encode and encrypt the unblinded control TLVs.
impl<T: OnionMessageContents> Writeable for (Payload<T>, [u8; 32]) {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		match &self.0 {
			Payload::Forward(ForwardControlTlvs::Blinded(encrypted_bytes)) => {
				_encode_varint_length_prefixed_tlv!(w, {
					(4, *encrypted_bytes, required_vec)
				})
			},
			Payload::Receive {
				control_tlvs: ReceiveControlTlvs::Blinded(encrypted_bytes), reply_path, message,
			} => {
				_encode_varint_length_prefixed_tlv!(w, {
					(2, reply_path, option),
					(4, *encrypted_bytes, required_vec),
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
impl<H: CustomOnionMessageHandler + ?Sized, L: Logger + ?Sized> ReadableArgs<(SharedSecret, &H, &L)>
for Payload<ParsedOnionMessageContents<<H as CustomOnionMessageHandler>::CustomMessage>> {
	fn read<R: Read>(r: &mut R, args: (SharedSecret, &H, &L)) -> Result<Self, DecodeError> {
		let (encrypted_tlvs_ss, handler, logger) = args;

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
			match msg_type {
				tlv_type if OffersMessage::is_known_type(tlv_type) => {
					let msg = OffersMessage::read(msg_reader, (tlv_type, logger))?;
					message = Some(ParsedOnionMessageContents::Offers(msg));
					Ok(true)
				},
				_ => match handler.read_custom_message(msg_type, msg_reader)? {
					Some(msg) => {
						message = Some(ParsedOnionMessageContents::Custom(msg));
						Ok(true)
					},
					None => Ok(false),
				},
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
				Ok(Payload::Receive {
					control_tlvs: ReceiveControlTlvs::Unblinded(tlvs),
					reply_path,
					message: message.ok_or(DecodeError::InvalidValue)?,
				})
			},
		}
	}
}

/// When reading a packet off the wire, we don't know a priori whether the packet is to be forwarded
/// or received. Thus we read a `ControlTlvs` rather than reading a [`ForwardTlvs`] or
/// [`ReceiveTlvs`] directly. Also useful on the encoding side to keep forward and receive TLVs in
/// the same iterator.
pub(crate) enum ControlTlvs {
	/// This onion message is intended to be forwarded.
	Forward(ForwardTlvs),
	/// This onion message is intended to be received.
	Receive(ReceiveTlvs),
}

impl Readable for ControlTlvs {
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		_init_and_read_tlv_stream!(r, {
			(1, _padding, option),
			(2, _short_channel_id, option),
			(4, next_node_id, option),
			(6, path_id, option),
			(8, next_blinding_override, option),
		});
		let _padding: Option<Padding> = _padding;
		let _short_channel_id: Option<u64> = _short_channel_id;

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

impl Writeable for ControlTlvs {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		match self {
			Self::Forward(tlvs) => tlvs.write(w),
			Self::Receive(tlvs) => tlvs.write(w),
		}
	}
}
