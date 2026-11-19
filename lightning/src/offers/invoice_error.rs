// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Data structures and encoding for `invoice_error` messages.

use crate::io;
use crate::ln::msgs::DecodeError;
use crate::offers::merkle::SignError;
use crate::offers::parse::Bolt12SemanticError;
use crate::types::string::UntrustedString;
use crate::util::ser::{HighZeroBytesDroppedBigSize, Readable, WithoutLength, Writeable, Writer};

#[allow(unused_imports)]
use crate::prelude::*;

/// An error in response to an [`InvoiceRequest`] or an [`Bolt12Invoice`].
///
/// [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
/// [`Bolt12Invoice`]: crate::offers::invoice::Bolt12Invoice
#[derive(Clone, Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct InvoiceError {
	/// The field in the [`InvoiceRequest`] or the [`Bolt12Invoice`] that contained an error.
	///
	/// [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
	/// [`Bolt12Invoice`]: crate::offers::invoice::Bolt12Invoice
	pub erroneous_field: Option<ErroneousField>,

	/// An explanation of the error.
	pub message: UntrustedString,
}

/// The field in the [`InvoiceRequest`] or the [`Bolt12Invoice`] that contained an error.
///
/// [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
/// [`Bolt12Invoice`]: crate::offers::invoice::Bolt12Invoice
#[derive(Clone, Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct ErroneousField {
	/// The type number of the TLV field containing the error.
	pub tlv_fieldnum: u64,

	/// A value to use for the TLV field to avoid the error.
	pub suggested_value: Option<Vec<u8>>,
}

impl InvoiceError {
	/// Creates an [`InvoiceError`] with the given message.
	pub fn from_string(s: String) -> Self {
		Self { erroneous_field: None, message: UntrustedString(s) }
	}
}

impl core::fmt::Display for InvoiceError {
	fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
		self.message.fmt(f)
	}
}

impl Writeable for InvoiceError {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		let tlv_fieldnum = self.erroneous_field.as_ref().map(|f| f.tlv_fieldnum);
		let suggested_value =
			self.erroneous_field.as_ref().and_then(|f| f.suggested_value.as_ref());
		// The BOLT 12 `invoice_error` message is carried in an onion message TLV record, which
		// already delimits the message, so the TLV stream itself is not length-prefixed.
		encode_tlv_stream!(writer, {
			(1, tlv_fieldnum, (option, encoding: (u64, HighZeroBytesDroppedBigSize))),
			(3, suggested_value, (option, encoding: (Vec<u8>, WithoutLength))),
			(5, WithoutLength(&self.message), required),
		});
		Ok(())
	}
}

impl Readable for InvoiceError {
	fn read<R: io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
		_init_and_read_tlv_stream!(reader, {
			(1, erroneous_field, (option, encoding: (u64, HighZeroBytesDroppedBigSize))),
			(3, suggested_value, (option, encoding: (Vec<u8>, WithoutLength))),
			(5, error, (option, encoding: (UntrustedString, WithoutLength))),
		});

		let erroneous_field = match (erroneous_field, suggested_value) {
			(None, None) => None,
			(None, Some(_)) => return Err(DecodeError::InvalidValue),
			(Some(tlv_fieldnum), suggested_value) => {
				Some(ErroneousField { tlv_fieldnum, suggested_value })
			},
		};

		let message = match error {
			None => return Err(DecodeError::InvalidValue),
			Some(error) => error,
		};

		Ok(InvoiceError { erroneous_field, message })
	}
}

impl From<Bolt12SemanticError> for InvoiceError {
	fn from(error: Bolt12SemanticError) -> Self {
		InvoiceError { erroneous_field: None, message: UntrustedString(format!("{:?}", error)) }
	}
}

impl From<SignError> for InvoiceError {
	fn from(error: SignError) -> Self {
		let message = match error {
			SignError::Signing => "Failed signing invoice",
			SignError::Verification(_) => "Failed invoice signature verification",
		};
		InvoiceError { erroneous_field: None, message: UntrustedString(message.to_string()) }
	}
}

#[cfg(test)]
mod tests {
	use super::{ErroneousField, InvoiceError};

	use crate::ln::msgs::DecodeError;
	use crate::types::string::UntrustedString;
	use crate::util::ser::{
		HighZeroBytesDroppedBigSize, Readable, VecWriter, WithoutLength, Writeable,
	};

	#[test]
	fn parses_invoice_error_without_erroneous_field() {
		let mut writer = VecWriter(Vec::new());
		let invoice_error = InvoiceError {
			erroneous_field: None,
			message: UntrustedString("Invalid value".to_string()),
		};
		invoice_error.write(&mut writer).unwrap();

		let buffer = writer.0;
		match InvoiceError::read(&mut &buffer[..]) {
			Ok(invoice_error) => {
				assert_eq!(invoice_error.message, UntrustedString("Invalid value".to_string()));
				assert_eq!(invoice_error.erroneous_field, None);
			},
			Err(e) => panic!("Unexpected error: {:?}", e),
		}
	}

	#[test]
	fn parses_invoice_error_with_erroneous_field() {
		let mut writer = VecWriter(Vec::new());
		let invoice_error = InvoiceError {
			erroneous_field: Some(ErroneousField {
				tlv_fieldnum: 42,
				suggested_value: Some(vec![42; 32]),
			}),
			message: UntrustedString("Invalid value".to_string()),
		};
		invoice_error.write(&mut writer).unwrap();

		let buffer = writer.0;
		match InvoiceError::read(&mut &buffer[..]) {
			Ok(invoice_error) => {
				assert_eq!(invoice_error.message, UntrustedString("Invalid value".to_string()));
				assert_eq!(
					invoice_error.erroneous_field,
					Some(ErroneousField { tlv_fieldnum: 42, suggested_value: Some(vec![42; 32]) }),
				);
			},
			Err(e) => panic!("Unexpected error: {:?}", e),
		}
	}

	#[test]
	fn parses_invoice_error_without_suggested_value() {
		let mut writer = VecWriter(Vec::new());
		let invoice_error = InvoiceError {
			erroneous_field: Some(ErroneousField { tlv_fieldnum: 42, suggested_value: None }),
			message: UntrustedString("Invalid value".to_string()),
		};
		invoice_error.write(&mut writer).unwrap();

		let buffer = writer.0;
		match InvoiceError::read(&mut &buffer[..]) {
			Ok(invoice_error) => {
				assert_eq!(invoice_error.message, UntrustedString("Invalid value".to_string()));
				assert_eq!(
					invoice_error.erroneous_field,
					Some(ErroneousField { tlv_fieldnum: 42, suggested_value: None }),
				);
			},
			Err(e) => panic!("Unexpected error: {:?}", e),
		}
	}

	#[test]
	fn fails_parsing_invoice_error_without_message() {
		let tlv_fieldnum: Option<u64> = None;
		let suggested_value: Option<&Vec<u8>> = None;
		let error: Option<&String> = None;

		let mut writer = VecWriter(Vec::new());
		let mut write_tlv = || -> Result<(), crate::io::Error> {
			encode_tlv_stream!(&mut writer, {
				(1, tlv_fieldnum, (option, encoding: (u64, HighZeroBytesDroppedBigSize))),
				(3, suggested_value, (option, encoding: (Vec<u8>, WithoutLength))),
				(5, error, (option, encoding: (String, WithoutLength))),
			});
			Ok(())
		};
		write_tlv().unwrap();

		let buffer = writer.0;
		match InvoiceError::read(&mut &buffer[..]) {
			Ok(_) => panic!("Expected error"),
			Err(e) => {
				assert_eq!(e, DecodeError::InvalidValue);
			},
		}
	}

	#[test]
	fn fails_parsing_invoice_error_without_field() {
		let tlv_fieldnum: Option<u64> = None;
		let suggested_value = vec![42; 32];
		let error = "Invalid value".to_string();

		let mut writer = VecWriter(Vec::new());
		let mut write_tlv = || -> Result<(), crate::io::Error> {
			encode_tlv_stream!(&mut writer, {
				(1, tlv_fieldnum, (option, encoding: (u64, HighZeroBytesDroppedBigSize))),
				(3, Some(&suggested_value), (option, encoding: (Vec<u8>, WithoutLength))),
				(5, Some(&error), (option, encoding: (String, WithoutLength))),
			});
			Ok(())
		};
		write_tlv().unwrap();

		let buffer = writer.0;
		match InvoiceError::read(&mut &buffer[..]) {
			Ok(_) => panic!("Expected error"),
			Err(e) => {
				assert_eq!(e, DecodeError::InvalidValue);
			},
		}
	}

	#[test]
	fn parses_bolt12_invoice_error_bytes() {
		// The BOLT 12 `invoice_error` message for the error text "out of stock": a bare TLV
		// stream containing only the required type 5 `error` field.
		let bytes = [
			0x05, // type: error
			0x0c, // length: 12
			0x6f, 0x75, 0x74, 0x20, 0x6f, 0x66, 0x20, 0x73, 0x74, 0x6f, 0x63,
			0x6b, // "out of stock"
		];

		let invoice_error = InvoiceError::read(&mut &bytes[..]).unwrap();
		assert_eq!(invoice_error.message, UntrustedString("out of stock".to_string()));
		assert_eq!(invoice_error.erroneous_field, None);

		let mut writer = VecWriter(Vec::new());
		InvoiceError::from_string("out of stock".to_string()).write(&mut writer).unwrap();
		assert_eq!(writer.0, &bytes[..]);
	}
}
