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

use lightning_types::string::UntrustedString;

use alloc::string::String;

/// Represents a parsed URL for LSPS5 webhook notifications.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LSPSUrl {
	url: UntrustedString,
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
		if url_str.chars().any(|c| !Self::is_valid_url_char(c)) {
			return Err(LSPS5ProtocolError::UrlParse);
		}

		let (scheme, remainder) =
			url_str.split_once("://").ok_or_else(|| (LSPS5ProtocolError::UrlParse))?;

		if !scheme.eq_ignore_ascii_case("https") {
			return Err(LSPS5ProtocolError::UnsupportedProtocol);
		}

		let host_section = remainder
			.split(['/', '?', '#'])
			.next()
			.ok_or_else(|| (LSPS5ProtocolError::UrlParse))?;

		let host_without_auth = host_section
			.split('@')
			.next_back()
			.filter(|s| !s.is_empty())
			.ok_or_else(|| (LSPS5ProtocolError::UrlParse))?;

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

		Ok(LSPSUrl { url: UntrustedString(url_str) })
	}

	/// Returns URL length.
	pub fn url_length(&self) -> usize {
		self.url.0.chars().count()
	}

	/// Returns the full URL string.
	pub fn url(&self) -> &str {
		self.url.0.as_str()
	}

	fn is_valid_url_char(c: char) -> bool {
		c.is_ascii_alphanumeric()
			|| matches!(c, ':' | '/' | '.' | '@' | '?' | '#' | '%' | '-' | '_' | '&' | '=')
	}

	fn is_valid_host_char(c: char) -> bool {
		c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '_')
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::alloc::string::ToString;
	use alloc::vec::Vec;
	use proptest::prelude::*;

	#[test]
	fn test_extremely_long_url() {
		let url_str = format!("https://{}/path", "a".repeat(1000)).to_string();
		let url_chars = url_str.chars().count();
		let result = LSPSUrl::parse(url_str);

		assert!(result.is_ok());
		let url = result.unwrap();
		assert_eq!(url.url.0.chars().count(), url_chars);
	}

	#[test]
	fn test_parse_http_url() {
		let url_str = "http://example.com/path".to_string();
		let url = LSPSUrl::parse(url_str).unwrap_err();
		assert_eq!(url, LSPS5ProtocolError::UnsupportedProtocol);
	}

	#[test]
	fn valid_lsps_url() {
		let test_vec: Vec<&'static str> = vec![
			"https://www.example.org/push?l=1234567890abcopqrstuv&c=best",
			"https://www.example.com/path",
			"https://example.org",
			"https://example.com:8080/path",
			"https://api.example.com/v1/resources",
			"https://example.com/page#section1",
			"https://example.com/search?q=test#results",
			"https://user:pass@example.com/",
			"https://192.168.1.1/admin",
			"https://example.com://path",
			"https://example.com/path%20with%20spaces",
			"https://example_example.com/path?query=with&spaces=true",
		];
		for url_str in test_vec {
			let url = LSPSUrl::parse(url_str.to_string());
			assert!(url.is_ok(), "Failed to parse URL: {}", url_str);
		}
	}

	#[test]
	fn invalid_lsps_url() {
		let test_vec = vec![
			"ftp://ftp.example.org/pub/files/document.pdf",
			"sftp://user:password@sftp.example.com:22/uploads/",
			"ssh://username@host.com:2222",
			"lightning://03a.example.com/invoice?amount=10000",
			"ftp://user@ftp.example.com/files/",
			"https://例子.测试/path",
			"a123+-.://example.com",
			"a123+-.://example.com",
			"https:\\\\example.com\\path",
			"https:///whatever",
			"https://example.com/path with spaces",
		];
		for url_str in test_vec {
			let url = LSPSUrl::parse(url_str.to_string());
			assert!(url.is_err(), "Expected error for URL: {}", url_str);
		}
	}

	#[test]
	fn parsing_errors() {
		let test_vec = vec![
			"example.com/path",
			"https://bad domain.com/",
			"https://example.com\0/path",
			"https://",
			"ht@ps://example.com",
			"http!://example.com",
			"1https://example.com",
			"https://://example.com",
			"https://example.com:port/path",
			"https://:8080/path",
			"https:",
			"://",
			"https://example.com\0/path",
		];
		for url_str in test_vec {
			let url = LSPSUrl::parse(url_str.to_string());
			assert!(url.is_err(), "Expected error for URL: {}", url_str);
		}
	}

	fn host_strategy() -> impl Strategy<Value = String> {
		prop_oneof![
			proptest::string::string_regex(
				"[a-z0-9]+(?:-[a-z0-9]+)*(?:\\.[a-z0-9]+(?:-[a-z0-9]+)*)*"
			)
			.unwrap(),
			(0u8..=255u8, 0u8..=255u8, 0u8..=255u8, 0u8..=255u8)
				.prop_map(|(a, b, c, d)| format!("{}.{}.{}.{}", a, b, c, d))
		]
	}

	proptest! {
		#[test]
		fn proptest_parse_round_trip(
			host in host_strategy(),
			port in proptest::option::of(0u16..=65535u16),
			path in proptest::option::of(proptest::string::string_regex("[a-zA-Z0-9._%&=:@/-]{0,20}").unwrap()),
			query in proptest::option::of(proptest::string::string_regex("[a-zA-Z0-9._%&=:@/-]{0,20}").unwrap()),
			fragment in proptest::option::of(proptest::string::string_regex("[a-zA-Z0-9._%&=:@/-]{0,20}").unwrap())
		) {
			let mut url = format!("https://{}", host);
			if let Some(p) = port {
				url.push_str(&format!(":{}", p));
			}
			if let Some(pth) = &path {
				url.push('/');
				url.push_str(pth);
			}
			if let Some(q) = &query {
				url.push('?');
				url.push_str(q);
			}
			if let Some(f) = &fragment {
				url.push('#');
				url.push_str(f);
			}

			let parsed = LSPSUrl::parse(url.clone()).expect("should parse");
			prop_assert_eq!(parsed.url(), url.as_str());
			prop_assert_eq!(parsed.url_length(), url.chars().count());
		}
	}
}
