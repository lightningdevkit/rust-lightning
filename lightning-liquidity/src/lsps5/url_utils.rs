// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! URL utilities for LSPS5 webhook notifications

use crate::alloc::string::ToString;
use crate::prelude::String;
use crate::prelude::Vec;

/// A URL implementation for scheme and host extraction
/// Simplified representation of a URL with just scheme and host components.
/// This struct provides parsing and access to these core parts of a URL string.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LSPSUrl {
	scheme: String,
	host: String,
	url: String,
}

/// Implementation of methods for the Url struct
impl LSPSUrl {
	/// Parses a URL string into a URL instance
	/// Extracts the scheme and host from any standard URL
	///
	/// # Arguments
	/// * `url_str` - The URL string to parse
	///
	/// # Returns
	/// A Result containing either the parsed URL or an error message
	pub fn parse(url_str: &str) -> Result<Self, String> {
		let parts: Vec<&str> = url_str.splitn(2, "://").collect();
		if parts.len() != 2 {
			return Err("URL must contain scheme separator '://'".to_string());
		}

		let scheme = parts[0].to_string();
		if scheme.is_empty() {
			return Err("URL scheme cannot be empty".to_string());
		}

		if !validate_scheme(&scheme) {
			return Err(format!("Invalid URL scheme: {}", scheme));
		}

		let remainder = parts[1];
		if remainder.is_empty() {
			return Err("URL host cannot be empty".to_string());
		}

		let host = match remainder.find('/') {
			Some(idx) => &remainder[0..idx],
			None => match remainder.find('?') {
				Some(idx) => &remainder[0..idx],
				None => match remainder.find('#') {
					Some(idx) => &remainder[0..idx],
					None => remainder,
				},
			},
		};

		let mut clean_host = host;
		if let Some(auth_idx) = host.rfind('@') {
			clean_host = &host[auth_idx + 1..];
		}

		let mut final_host = clean_host;
		if let Some(port_idx) = clean_host.rfind(':') {
			final_host = &clean_host[0..port_idx];
		}

		if final_host.is_empty() {
			return Err("URL host cannot be empty".to_string());
		}

		Ok(LSPSUrl { scheme, host: final_host.to_string(), url: url_str.to_string() })
	}

	/// Returns the scheme part of the URL (http, https, etc.)
	pub fn scheme(&self) -> &str {
		&self.scheme
	}

	/// Returns the host as an Option, None if empty
	pub fn host(&self) -> Option<&str> {
		if self.host.is_empty() {
			None
		} else {
			Some(&self.host)
		}
	}

	/// Returns the host string directly if available
	pub fn host_str(&self) -> Option<&str> {
		self.host()
	}

	/// Returns the full URL string
	pub fn url(&self) -> &str {
		&self.url
	}
}

/// Validates a URL scheme according to RFC specifications
///
/// According to RFC 1738, a scheme must:
/// 1. Start with a letter (a-z, A-Z)
/// 2. Contain only letters, digits, plus (+), period (.), or hyphen (-)
fn validate_scheme(scheme: &str) -> bool {
	if scheme.is_empty() {
		return false;
	}

	let mut chars = scheme.chars();

	let first = match chars.next() {
		Some(c) => c,
		None => return false, // No characters (empty string)
	};

	if !first.is_ascii_alphabetic() {
		return false;
	}

	chars.all(|c| c.is_ascii_alphabetic() || c.is_ascii_digit() || c == '+' || c == '.' || c == '-')
}

#[cfg(test)]
mod tests {
	use super::*;
	#[test]
	fn test_parse_url_with_query_params() {
		let url_str = "https://www.example.org/push?l=1234567890abcdefghijklmnopqrstuv&c=best";
		let url = LSPSUrl::parse(url_str).unwrap();

		assert_eq!(url.scheme(), "https");
		assert_eq!(url.host(), Some("www.example.org"));
	}

	#[test]
	fn test_parse_https_url() {
		let url_str = "https://example.com/path";
		let url = LSPSUrl::parse(url_str).unwrap();

		assert_eq!(url.scheme(), "https");
		assert_eq!(url.host(), Some("example.com"));
	}

	#[test]
	fn test_parse_http_url() {
		let url_str = "http://example.com/path";
		let url = LSPSUrl::parse(url_str).unwrap();

		assert_eq!(url.scheme(), "http");
		assert_eq!(url.host(), Some("example.com"));
	}

	#[test]
	fn test_parse_url_with_no_path() {
		let url_str = "https://example.com";
		let url = LSPSUrl::parse(url_str).unwrap();

		assert_eq!(url.scheme(), "https");
		assert_eq!(url.host(), Some("example.com"));
	}

	#[test]
	fn test_parse_url_with_port() {
		let url_str = "https://example.com:8080/path";
		let url = LSPSUrl::parse(url_str).unwrap();

		assert_eq!(url.scheme(), "https");
		assert_eq!(url.host(), Some("example.com"));
	}

	#[test]
	fn test_parse_url_with_subdomain_and_path() {
		let url_str = "https://api.example.com/v1/resources";
		let url = LSPSUrl::parse(url_str).unwrap();

		assert_eq!(url.scheme(), "https");
		assert_eq!(url.host(), Some("api.example.com"));
	}

	#[test]
	fn test_invalid_url_no_scheme() {
		let url_str = "example.com/path";
		let result = LSPSUrl::parse(url_str);

		assert!(result.is_err());
	}

	#[test]
	fn test_invalid_url_empty_host() {
		let url_str = "https:///path";
		let result = LSPSUrl::parse(url_str);

		assert!(result.is_err());
	}

	#[test]
	fn test_parse_protocol_with_path() {
		let url_str = "ftp://ftp.example.org/pub/files/document.pdf";
		let url = LSPSUrl::parse(url_str).unwrap();

		assert_eq!(url.scheme(), "ftp");
		assert_eq!(url.host(), Some("ftp.example.org"));
	}

	#[test]
	fn test_parse_protocol_with_auth() {
		let url_str = "sftp://user:password@sftp.example.com:22/uploads/";
		let url = LSPSUrl::parse(url_str).unwrap();

		assert_eq!(url.scheme(), "sftp");
		assert_eq!(url.host(), Some("sftp.example.com"));
	}

	#[test]
	fn test_parse_ssh_url() {
		let url_str = "ssh://username@host.com:2222";
		let url = LSPSUrl::parse(url_str).unwrap();

		assert_eq!(url.scheme(), "ssh");
		assert_eq!(url.host(), Some("host.com"));
	}

	#[test]
	fn test_parse_custom_protocol() {
		let url_str = "lightning://03a.example.com/invoice?amount=10000";
		let url = LSPSUrl::parse(url_str).unwrap();

		assert_eq!(url.scheme(), "lightning");
		assert_eq!(url.host(), Some("03a.example.com"));
	}

	#[test]
	fn test_parse_url_with_fragment() {
		let url_str = "https://example.com/page#section1";
		let url = LSPSUrl::parse(url_str).unwrap();

		assert_eq!(url.scheme(), "https");
		assert_eq!(url.host(), Some("example.com"));
	}

	#[test]
	fn test_parse_url_with_query_and_fragment() {
		let url_str = "https://example.com/search?q=test#results";
		let url = LSPSUrl::parse(url_str).unwrap();

		assert_eq!(url.scheme(), "https");
		assert_eq!(url.host(), Some("example.com"));
	}

	#[test]
	fn test_parse_url_with_username_only() {
		let url_str = "ftp://user@ftp.example.com/files/";
		let url = LSPSUrl::parse(url_str).unwrap();

		assert_eq!(url.scheme(), "ftp");
		assert_eq!(url.host(), Some("ftp.example.com"));
	}

	#[test]
	fn test_parse_url_with_credentials() {
		let url_str = "http://user:pass@example.com/";
		let url = LSPSUrl::parse(url_str).unwrap();

		assert_eq!(url.scheme(), "http");
		assert_eq!(url.host(), Some("example.com"));
	}

	#[test]
	fn test_parse_url_with_ipv4_host() {
		let url_str = "http://192.168.1.1/admin";
		let url = LSPSUrl::parse(url_str).unwrap();

		assert_eq!(url.scheme(), "http");
		assert_eq!(url.host(), Some("192.168.1.1"));
	}

	#[test]
	fn test_check_https_scheme() {
		let url_str = "https://example.com/path";
		let url = LSPSUrl::parse(url_str).unwrap();
		assert_eq!(url.scheme(), "https");

		let url_str = "http://example.com/path";
		let url = LSPSUrl::parse(url_str).unwrap();
		assert_ne!(url.scheme(), "https");
	}

	#[test]
	fn test_empty_remainder_error() {
		let url_str = "https://";
		let result = LSPSUrl::parse(url_str);
		assert!(result.is_err());
		assert_eq!(result.unwrap_err(), "URL host cannot be empty");
	}

	#[test]
	fn test_malformed_scheme_chars() {
		let url_str = "ht@ps://example.com";
		let result = LSPSUrl::parse(url_str);
		assert!(result.is_err());

		let url_str = "http!://example.com";
		let result = LSPSUrl::parse(url_str);
		assert!(result.is_err());
	}

	// Update this test since the RFC requires schemes to start with a letter
	#[test]
	fn test_scheme_starting_with_digit() {
		let url_str = "1https://example.com";
		let result = LSPSUrl::parse(url_str);

		// According to RFC, schemes must start with a letter
		assert!(result.is_err());
	}

	#[test]
	fn test_valid_scheme_chars() {
		let valid_schemes = vec![
			"http",
			"https",
			"ftp",
			"sftp",
			"ssh",
			"h123",
			"scheme-with-dash",
			"scheme.with.dots",
			"scheme+plus",
		];

		for scheme in valid_schemes {
			let url_str = format!("{}://example.com", scheme);
			let result = LSPSUrl::parse(&url_str);
			assert!(result.is_ok(), "Valid scheme '{}' was rejected", scheme);
			assert_eq!(result.unwrap().scheme(), scheme);
		}
	}

	#[test]
	fn test_extremely_long_url() {
		let host = "a".repeat(10000);
		let url_str = format!("https://{}/path", host);
		let result = LSPSUrl::parse(&url_str);

		assert!(result.is_ok());
		let url = result.unwrap();
		assert_eq!(url.scheme(), "https");
		assert_eq!(url.host().unwrap().len(), 10000);
	}

	#[test]
	fn test_unicode_characters() {
		let url_str = "https://例子.测试/path";
		let result = LSPSUrl::parse(url_str);

		assert!(result.is_ok());
		let url = result.unwrap();
		assert_eq!(url.host(), Some("例子.测试"));
	}

	#[test]
	fn test_weird_but_valid_scheme() {
		let url_str = "a123+-.://example.com";
		let result = LSPSUrl::parse(url_str);

		assert!(result.is_ok());
		assert_eq!(result.unwrap().scheme(), "a123+-.");
	}

	#[test]
	fn test_url_with_spaces() {
		let url_str = "https://example.com/path with spaces";
		let result = LSPSUrl::parse(url_str);

		assert!(result.is_ok());
		assert_eq!(result.unwrap().host(), Some("example.com"));

		let url_str = "https://bad domain.com/";
		let result = LSPSUrl::parse(url_str);

		assert!(result.is_ok());
		assert_eq!(result.unwrap().host(), Some("bad domain.com"));
	}

	#[test]
	fn test_multiple_scheme_separators() {
		let url_str = "https://example.com://path";
		let result = LSPSUrl::parse(url_str);

		assert!(result.is_ok());
		assert_eq!(result.unwrap().host(), Some("example.com"));

		let url_str = "https://://example.com";
		let result = LSPSUrl::parse(url_str);

		assert!(result.is_err());
	}

	#[test]
	fn test_invalid_port() {
		let url_str = "https://example.com:port/path";
		let result = LSPSUrl::parse(url_str);

		assert!(result.is_ok());
		assert_eq!(result.unwrap().host(), Some("example.com"));

		let url_str = "https://example.com:65536/path";
		let result = LSPSUrl::parse(url_str);

		assert!(result.is_ok());
		assert_eq!(result.unwrap().host(), Some("example.com"));
	}

	#[test]
	fn test_missing_host_domain() {
		let url_str = "https://:8080/path";
		let result = LSPSUrl::parse(url_str);

		assert!(result.is_err());
	}

	#[test]
	fn test_scheme_only() {
		let url_str = "https:";
		let result = LSPSUrl::parse(url_str);

		assert!(result.is_err());
	}

	#[test]
	fn test_null_characters() {
		let url_str = "https://example.com\0/path";
		let result = LSPSUrl::parse(url_str);

		assert!(result.is_ok());
		assert_eq!(result.unwrap().host(), Some("example.com\0"));
	}

	#[test]
	fn test_url_with_backslashes() {
		let url_str = "https:\\\\example.com\\path";
		let result = LSPSUrl::parse(url_str);

		assert!(result.is_err());
	}

	#[test]
	fn test_just_scheme_and_authority_markers() {
		let url_str = "://";
		let result = LSPSUrl::parse(url_str);

		assert!(result.is_err());
	}
}
