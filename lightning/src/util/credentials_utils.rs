// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Credentials utilities for HTLC scoring live here.

use crate::io;
use crate::io::Read;
use crate::util::ser::{Readable, Writeable, Writer};
use crate::ln::msgs::DecodeError;
use bitcoin::secp256k1::ecdsa::Signature;

/// A credential (random 32-byte) and the issuer signature
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SignedCredential {
	/// 32-byte random string issued by the HTLC sender
	pub credential: [u8; 32],
	/// ECDSA Signature from routing node scorer
	pub signature: Signature, //TODO: make signature optional
}

impl Writeable for SignedCredential {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		write_tlv_fields!(writer, {
			(0, self.credential, required),
			(2, self.signature, required),
		});
		Ok(())
	}

	fn serialized_length(&self) -> usize {
		self.credential.serialized_length() + self.signature.serialized_length()
	}
}

impl Readable for SignedCredential {
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		Ok(Self {
			credential: Readable::read(r)?,
			signature: Readable::read(r)?,
		})
	}
}
