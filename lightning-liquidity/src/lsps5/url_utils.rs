// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! URL utilities for LSPS5 webhook notifications.

use super::msgs::LSPS5ProtocolError;

use bitreq::Url;
use lightning::ln::msgs::DecodeError;
use lightning::util::ser::{Readable, Writeable};

use alloc::string::String;
use core::hash::{Hash, Hasher};

/// Represents a parsed URL for LSPS5 webhook notifications.
#[derive(Debug, Clone, Eq)]
pub struct LSPSUrl(Url);

impl PartialEq for LSPSUrl {
	fn eq(&self, other: &Self) -> bool {
		self.0.as_str() == other.0.as_str()
	}
}

impl Hash for LSPSUrl {
	fn hash<H: Hasher>(&self, state: &mut H) {
		self.0.as_str().hash(state)
	}
}

impl LSPSUrl {
	/// Parses a URL string into a URL instance.
	///
	/// # Arguments
	/// * `url_str` - The URL string to parse
	///
	/// # Returns
	/// A Result containing either the parsed URL or an error message.
	pub fn parse(url_str: String) -> Result<Self, LSPS5ProtocolError> {
		let url = Url::parse(&url_str).map_err(|_| LSPS5ProtocolError::UrlParse)?;

		if url.scheme() != "https" {
			return Err(LSPS5ProtocolError::UnsupportedProtocol);
		}

		Ok(LSPSUrl(url))
	}

	/// Returns URL length in bytes.
	pub fn url_length(&self) -> usize {
		self.0.as_str().len()
	}

	/// Returns the full URL string.
	pub fn url(&self) -> &str {
		self.0.as_str()
	}
}

impl Writeable for LSPSUrl {
	fn write<W: lightning::util::ser::Writer>(
		&self, writer: &mut W,
	) -> Result<(), lightning::io::Error> {
		self.0.as_str().write(writer)
	}
}

impl Readable for LSPSUrl {
	fn read<R: lightning::io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
		let s: String = Readable::read(reader)?;
		Self::parse(s).map_err(|_| DecodeError::InvalidValue)
	}
}
