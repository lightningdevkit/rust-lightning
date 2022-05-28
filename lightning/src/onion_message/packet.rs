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
use util::ser::{LengthRead, LengthReadable, Readable, Writeable, Writer};

use core::cmp;
use io;
use prelude::*;

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
