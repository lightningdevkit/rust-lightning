// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Parsing and formatting for bech32 message encoding.

use bitcoin::bech32;
use bitcoin::bech32::{FromBase32, ToBase32};
use core::convert::TryFrom;
use core::fmt;
use crate::ln::msgs::DecodeError;

use crate::prelude::*;

/// Indicates a message can be encoded using bech32.
pub(crate) trait Bech32Encode: AsRef<[u8]> + TryFrom<Vec<u8>, Error=ParseError> {
	/// Human readable part of the message's bech32 encoding.
	const BECH32_HRP: &'static str;

	/// Parses a bech32-encoded message into a TLV stream.
	fn from_bech32_str(s: &str) -> Result<Self, ParseError> {
		// Offer encoding may be split by '+' followed by optional whitespace.
		let encoded = match s.split('+').skip(1).next() {
			Some(_) => {
				for chunk in s.split('+') {
					let chunk = chunk.trim_start();
					if chunk.is_empty() || chunk.contains(char::is_whitespace) {
						return Err(ParseError::InvalidContinuation);
					}
				}

				let s = s.chars().filter(|c| *c != '+' && !c.is_whitespace()).collect::<String>();
				Bech32String::Owned(s)
			},
			None => Bech32String::Borrowed(s),
		};

		let (hrp, data) = bech32::decode_without_checksum(encoded.as_ref())?;

		if hrp != Self::BECH32_HRP {
			return Err(ParseError::InvalidBech32Hrp);
		}

		let data = Vec::<u8>::from_base32(&data)?;
		Self::try_from(data)
	}

	/// Formats the message using bech32-encoding.
	fn fmt_bech32_str(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
		bech32::encode_without_checksum_to_fmt(f, Self::BECH32_HRP, self.as_ref().to_base32())
			.expect("HRP is invalid").unwrap();

		Ok(())
	}
}

// Used to avoid copying a bech32 string not containing the continuation character (+).
enum Bech32String<'a> {
	Borrowed(&'a str),
	Owned(String),
}

impl<'a> AsRef<str> for Bech32String<'a> {
	fn as_ref(&self) -> &str {
		match self {
			Bech32String::Borrowed(s) => s,
			Bech32String::Owned(s) => s,
		}
	}
}

/// Error when parsing a bech32 encoded message using [`str::parse`].
#[derive(Debug, PartialEq)]
pub enum ParseError {
	/// The bech32 encoding does not conform to the BOLT 12 requirements for continuing messages
	/// across multiple parts (i.e., '+' followed by whitespace).
	InvalidContinuation,
	/// The bech32 encoding's human-readable part does not match what was expected for the message
	/// being parsed.
	InvalidBech32Hrp,
	/// The string could not be bech32 decoded.
	Bech32(bech32::Error),
	/// The bech32 decoded string could not be decoded as the expected message type.
	Decode(DecodeError),
	/// The parsed message has invalid semantics.
	InvalidSemantics(SemanticError),
}

/// Error when interpreting a TLV stream as a specific type.
#[derive(Debug, PartialEq)]
pub enum SemanticError {
	/// An amount was expected but was missing.
	MissingAmount,
	/// The amount exceeded the total bitcoin supply.
	InvalidAmount,
	/// A currency was provided that is not supported.
	UnsupportedCurrency,
	/// A required description was not provided.
	MissingDescription,
	/// A signing pubkey was not provided.
	MissingSigningPubkey,
	/// An unsupported quantity was provided.
	InvalidQuantity,
}

impl From<bech32::Error> for ParseError {
	fn from(error: bech32::Error) -> Self {
		Self::Bech32(error)
	}
}

impl From<DecodeError> for ParseError {
	fn from(error: DecodeError) -> Self {
		Self::Decode(error)
	}
}

impl From<SemanticError> for ParseError {
	fn from(error: SemanticError) -> Self {
		Self::InvalidSemantics(error)
	}
}
