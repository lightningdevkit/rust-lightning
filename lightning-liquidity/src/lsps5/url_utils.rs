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

use lightning::ln::msgs::DecodeError;
use lightning::util::ser::{Readable, Writeable};
use lightning_types::string::UntrustedString;

use alloc::string::String;

/// Represents a parsed URL for LSPS5 webhook notifications.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LSPSUrl(UntrustedString);

impl LSPSUrl {
	/// Parses a URL string into a URL instance.
	///
	/// # Arguments
	/// * `url_str` - The URL string to parse
	///
	/// # Returns
	/// A Result containing either the parsed URL or an error message.
	pub fn parse(url_str: String) -> Result<Self, LSPS5ProtocolError> {
		if url_str.chars().any(|c| !Self::is_valid_url_char(c)) {
			return Err(LSPS5ProtocolError::UrlParse);
		}

		let (scheme, remainder) =
			url_str.split_once("://").ok_or_else(|| LSPS5ProtocolError::UrlParse)?;

		if !scheme.eq_ignore_ascii_case("https") {
			return Err(LSPS5ProtocolError::UnsupportedProtocol);
		}

		let host_section =
			remainder.split(['/', '?', '#']).next().ok_or_else(|| LSPS5ProtocolError::UrlParse)?;

		let host_without_auth = host_section
			.split('@')
			.next_back()
			.filter(|s| !s.is_empty())
			.ok_or_else(|| LSPS5ProtocolError::UrlParse)?;

		if host_without_auth.is_empty()
			|| host_without_auth.chars().any(|c| !Self::is_valid_host_char(c))
		{
			return Err(LSPS5ProtocolError::UrlParse);
		}

		match host_without_auth.rsplit_once(':') {
			Some((hostname, _)) if hostname.is_empty() => return Err(LSPS5ProtocolError::UrlParse),
			Some((_, port)) => {
				if !port.is_empty() && port.parse::<u16>().is_err() {
					return Err(LSPS5ProtocolError::UrlParse);
				}
			},
			None => {},
		};

		Ok(LSPSUrl(UntrustedString(url_str)))
	}

	/// Returns URL length.
	pub fn url_length(&self) -> usize {
		self.0 .0.chars().count()
	}

	/// Returns the full URL string.
	pub fn url(&self) -> &str {
		self.0 .0.as_str()
	}

	fn is_valid_url_char(c: char) -> bool {
		c.is_ascii_alphanumeric()
			|| matches!(c, ':' | '/' | '.' | '@' | '?' | '#' | '%' | '-' | '_' | '&' | '=')
	}

	fn is_valid_host_char(c: char) -> bool {
		c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '_')
	}
}

impl Writeable for LSPSUrl {
	fn write<W: lightning::util::ser::Writer>(
		&self, writer: &mut W,
	) -> Result<(), lightning::io::Error> {
		self.0.write(writer)
	}
}

impl Readable for LSPSUrl {
	fn read<R: lightning::io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
		Ok(Self(Readable::read(reader)?))
	}
}
