// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! URL utilities for LSPS5 webhook notifications.

use crate::alloc::string::ToString;
use alloc::string::String;
use lightning_types::string::UntrustedString;

/// A URL implementation for scheme and host extraction.
/// Simplified representation of a URL with just scheme and host components.
/// This struct provides parsing and access to these core parts of a URL string.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LSPSUrl {
	scheme: UntrustedString,
	host: UntrustedString,
	/// The full URL string.
	pub url: UntrustedString,
}

impl LSPSUrl {
	/// Parses a URL string into a URL instance.
	/// Extracts the scheme and host from any standard URL.
	///
	/// # Arguments
	/// * `url_str` - The URL string to parse
	///
	/// # Returns
	/// A Result containing either the parsed URL or an error message.
	pub fn parse(url_str: String) -> Result<Self, ()> {
		if !url_str.is_ascii() {
			return Err(());
		}

		let (scheme, remainder) = url_str.split_once("://").ok_or_else(|| ())?;

		if !is_valid_scheme(scheme) {
			return Err(());
		}

		let host_section = remainder.split(['/', '?', '#']).next().ok_or_else(|| ())?;

		let host_without_auth =
			host_section.split('@').next_back().filter(|s| !s.is_empty()).ok_or_else(|| ())?;

		if host_without_auth.is_empty() {
			return Err(());
		}

		match host_without_auth.rsplit_once(':') {
			Some((hostname, _port)) if hostname.is_empty() => return Err(()),
			Some((_hostname, port)) if !port.is_empty() && port.parse::<u32>().is_err() => {
				return Err(())
			},
			_ => (),
		};

		Ok(LSPSUrl {
			scheme: UntrustedString(scheme.to_string()),
			host: UntrustedString(host_without_auth.to_string()),
			url: UntrustedString(url_str.to_string()),
		})
	}

	/// Returns if the URL scheme is "https".
	pub fn is_https(&self) -> bool {
		self.scheme.0 == "https"
	}

	/// Returns URL length.
	pub fn url_length(&self) -> usize {
		self.url.0.chars().count()
	}

	/// Returns whether the URL points to a public host.
	///
	/// A host is considered non-public if it is:
	/// - "localhost", or loopback addresses ("127.*", "::1")
	/// - in the private range 10.*
	/// - in the private range 192.168.*
	/// - in the private range 172.16.0.0 to 172.31.255.255
	pub fn is_public(&self) -> bool {
		let host = self.host.0.clone();

		if host == "localhost" || host.starts_with("127.") || host == "::1" {
			return false;
		}

		if host.starts_with("10.") || host.starts_with("192.168.") {
			return false;
		}

		if host.starts_with("172.") {
			if let Some(second_octet) = host.split('.').nth(1) {
				if let Ok(num) = second_octet.parse::<u8>() {
					if (16..=31).contains(&num) {
						return false;
					}
				}
			}
		}

		true
	}

	/// Returns the full URL string.
	pub fn url(&self) -> &str {
		self.url.0.as_str()
	}
}

/// Validates a URL scheme according to RFC specifications.
///
/// According to RFC 1738, a scheme must:
/// 1. Start with a letter (a-z, A-Z)
/// 2. Contain only letters, digits, plus (+), period (.), or hyphen (-)
fn is_valid_scheme(scheme: &str) -> bool {
	let mut chars = scheme.chars();

	if !chars.next().map_or(false, |c| c.is_ascii_alphabetic()) {
		return false;
	}

	chars.all(|c| c.is_ascii_alphabetic() || c.is_ascii_digit() || c == '+' || c == '.' || c == '-')
}

#[cfg(test)]
mod tests {
	use super::*;
	use alloc::vec::Vec;
	use proptest::prelude::*;

	#[test]
	fn test_parse_url_with_query_params() {
		let url_str =
			"https://www.example.org/push?l=1234567890abcdefghijklmnopqrstuv&c=best".to_string();
		let url = LSPSUrl::parse(url_str).unwrap();
		assert!(url.is_https());
		assert_eq!(url.scheme.0, "https");
		assert_eq!(url.host.0, "www.example.org");
	}

	#[test]
	fn test_parse_https_url() {
		let url_str = "https://example.com/path".to_string();
		let url = LSPSUrl::parse(url_str).unwrap();
		assert!(url.is_https());
		assert_eq!(url.scheme.0, "https");
		assert_eq!(url.host.0, "example.com");
	}

	#[test]
	fn test_parse_http_url() {
		let url_str = "http://example.com/path".to_string();
		let url = LSPSUrl::parse(url_str).unwrap();
		assert!(!url.is_https());
		assert_eq!(url.scheme.0, "http");
		assert_eq!(url.host.0, "example.com");
	}

	#[test]
	fn test_parse_url_with_no_path() {
		let url_str = "https://example.com".to_string();
		let url = LSPSUrl::parse(url_str).unwrap();
		assert!(url.is_https());
		assert_eq!(url.scheme.0, "https");
		assert_eq!(url.host.0, "example.com");
	}

	#[test]
	fn test_parse_url_with_port() {
		let url_str = "https://example.com:8080/path".to_string();
		let url = LSPSUrl::parse(url_str).unwrap();

		assert_eq!(url.scheme.0, "https");
		assert_eq!(url.host.0, "example.com:8080");
	}

	#[test]
	fn test_parse_url_with_subdomain_and_path() {
		let url_str = "https://api.example.com/v1/resources".to_string();
		let url = LSPSUrl::parse(url_str).unwrap();

		assert_eq!(url.scheme.0, "https");
		assert_eq!(url.host.0, "api.example.com");
	}

	#[test]
	fn test_invalid_url_no_scheme() {
		let url_str = "example.com/path".to_string();
		let result = LSPSUrl::parse(url_str);

		assert!(result.is_err());
	}

	#[test]
	fn test_invalid_url_empty_host() {
		let url_str = "https:///path".to_string();
		let result = LSPSUrl::parse(url_str);

		assert!(result.is_err());
	}

	#[test]
	fn test_parse_protocol_with_path() {
		let url_str = "ftp://ftp.example.org/pub/files/document.pdf".to_string();
		let url = LSPSUrl::parse(url_str).unwrap();

		assert_eq!(url.scheme.0, "ftp");
		assert_eq!(url.host.0, "ftp.example.org");
	}

	#[test]
	fn test_parse_protocol_with_auth() {
		let url_str = "sftp://user:password@sftp.example.com:22/uploads/".to_string();
		let url = LSPSUrl::parse(url_str).unwrap();

		assert_eq!(url.scheme.0, "sftp");
		assert_eq!(url.host.0, "sftp.example.com:22");
	}

	#[test]
	fn test_parse_ssh_url() {
		let url_str = "ssh://username@host.com:2222".to_string();
		let url = LSPSUrl::parse(url_str).unwrap();

		assert_eq!(url.scheme.0, "ssh");
		assert_eq!(url.host.0, "host.com:2222");
	}

	#[test]
	fn test_parse_custom_protocol() {
		let url_str = "lightning://03a.example.com/invoice?amount=10000".to_string();
		let url = LSPSUrl::parse(url_str).unwrap();

		assert_eq!(url.scheme.0, "lightning");
		assert_eq!(url.host.0, "03a.example.com");
	}

	#[test]
	fn test_parse_url_with_fragment() {
		let url_str = "https://example.com/page#section1".to_string();
		let url = LSPSUrl::parse(url_str).unwrap();

		assert_eq!(url.scheme.0, "https");
		assert_eq!(url.host.0, "example.com");
	}

	#[test]
	fn test_parse_url_with_query_and_fragment() {
		let url_str = "https://example.com/search?q=test#results".to_string();
		let url = LSPSUrl::parse(url_str).unwrap();

		assert_eq!(url.scheme.0, "https");
		assert_eq!(url.host.0, "example.com");
	}

	#[test]
	fn test_parse_url_with_username_only() {
		let url_str = "ftp://user@ftp.example.com/files/".to_string();
		let url = LSPSUrl::parse(url_str).unwrap();

		assert_eq!(url.scheme.0, "ftp");
		assert_eq!(url.host.0, "ftp.example.com");
	}

	#[test]
	fn test_parse_url_with_credentials() {
		let url_str = "http://user:pass@example.com/".to_string();
		let url = LSPSUrl::parse(url_str).unwrap();

		assert_eq!(url.scheme.0, "http");
		assert_eq!(url.host.0, "example.com");
	}

	#[test]
	fn test_parse_url_with_ipv4_host() {
		let url_str = "http://192.168.1.1/admin".to_string();
		let url = LSPSUrl::parse(url_str).unwrap();

		assert_eq!(url.scheme.0, "http");
		assert_eq!(url.host.0, "192.168.1.1");
	}

	#[test]
	fn test_check_https_scheme() {
		let url_str = "https://example.com/path".to_string();
		let url = LSPSUrl::parse(url_str).unwrap();
		assert_eq!(url.scheme.0, "https");

		let url_str = "http://example.com/path".to_string();
		let url = LSPSUrl::parse(url_str).unwrap();
		assert_ne!(url.scheme.0, "https");
	}

	#[test]
	fn test_empty_remainder_error() {
		let url_str = "https://".to_string();
		let result = LSPSUrl::parse(url_str);
		assert!(result.is_err());
	}

	#[test]
	fn test_malformed_scheme_chars() {
		let url_str = "ht@ps://example.com".to_string();
		let result = LSPSUrl::parse(url_str);
		assert!(result.is_err());

		let url_str = "http!://example.com".to_string();
		let result = LSPSUrl::parse(url_str);
		assert!(result.is_err());
	}

	// Update this test since the RFC requires schemes to start with a letter
	#[test]
	fn test_scheme_starting_with_digit() {
		let url_str = "1https://example.com".to_string();
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
			let result = LSPSUrl::parse(UntrustedString(url_str).to_string());
			assert!(result.is_ok(), "Valid scheme '{}' was rejected", scheme);
			assert_eq!(result.unwrap().scheme.0, scheme);
		}
	}

	#[test]
	fn test_extremely_long_url() {
		let host = "a".repeat(10000);
		let url_str = format!("https://{}/path", host).to_string();
		let result = LSPSUrl::parse(url_str);

		assert!(result.is_ok());
		let url = result.unwrap();
		assert_eq!(url.scheme.0, "https");
		assert_eq!(url.host.0.chars().count(), 10000);
	}

	#[test]
	fn test_unicode_characters() {
		let url_str = "https://例子.测试/path".to_string();
		let result = LSPSUrl::parse(url_str);

		assert!(result.is_err());
	}

	#[test]
	fn test_weird_but_valid_scheme() {
		let url_str = "a123+-.://example.com".to_string();
		let result = LSPSUrl::parse(url_str);

		assert!(result.is_ok());
		assert_eq!(result.unwrap().scheme.0, "a123+-.");
	}

	#[test]
	fn test_url_with_spaces() {
		let url_str = "https://example.com/path with spaces".to_string();
		let result = LSPSUrl::parse(url_str);

		assert!(result.is_ok());
		assert_eq!(result.unwrap().host.0, "example.com");

		let url_str = "https://bad domain.com/".to_string();
		let result = LSPSUrl::parse(url_str);

		assert!(result.is_ok());
		assert_eq!(result.unwrap().host.0, "bad domain.com");
	}

	#[test]
	fn test_multiple_scheme_separators() {
		let url_str = "https://example.com://path".to_string();
		let result = LSPSUrl::parse(url_str);

		assert!(result.is_ok());

		let url_str = "https://://example.com".to_string();
		let result = LSPSUrl::parse(url_str);

		assert!(result.is_err());
	}

	#[test]
	fn test_invalid_port() {
		let url_str = "https://example.com:port/path".to_string();
		let result = LSPSUrl::parse(url_str);

		assert!(!result.is_ok());

		let url_str = "https://example.com:65536/path".to_string();
		let result = LSPSUrl::parse(url_str);

		assert!(result.is_ok());
		assert_eq!(result.unwrap().host.0, "example.com:65536");
	}

	#[test]
	fn test_missing_host_domain() {
		let url_str = "https://:8080/path".to_string();
		let result = LSPSUrl::parse(url_str);

		assert!(result.is_err());
	}

	#[test]
	fn test_scheme_only() {
		let url_str = "https:".to_string();
		let result = LSPSUrl::parse(url_str);

		assert!(result.is_err());
	}

	#[test]
	fn test_null_characters() {
		let url_str = "https://example.com\0/path".to_string();
		let result = LSPSUrl::parse(url_str);

		assert!(result.is_ok());
		assert_eq!(result.unwrap().host.0, "example.com\0");
	}

	#[test]
	fn test_url_with_backslashes() {
		let url_str = "https:\\\\example.com\\path".to_string();
		let result = LSPSUrl::parse(url_str);

		assert!(result.is_err());
	}

	#[test]
	fn test_just_scheme_and_authority_markers() {
		let url_str = "://".to_string();
		let result = LSPSUrl::parse(url_str);

		assert!(result.is_err());
	}

	proptest! {
		/// For any valid URL matching the regex: if it parses, then
		/// - round-trip .url() == original,
		/// - url_length() == .chars().count()
		/// - original starts with "{scheme}://",
		/// - host and scheme are non-empty and substrings of the original,
		/// - host never empty,
		/// - port (if present) is numeric,
		/// - IPv4 hosts match expected pattern,
		/// - is_public() is correct for localhost/private IPs,
		/// - is_https() is correct for https scheme.
		#[test]
		fn test_url_properties(
			url_str in proptest::string::string_regex(
				r"([a-z][a-z0-9+.-]*)://((?:[a-z0-9._~%!$&()*+,;=-]+@)?(?:localhost|\d{1,3}(?:\.\d{1,3}){3}|\[[a-fA-F0-9:.]+\]|[a-z0-9._~%+-]+(?:\.[a-z0-9._~%+-]+)*))(?::\d{1,5})?(/[a-z0-9._~%!$&()*+,;=:@/-]*)?(\?[a-z0-9._~%!$&()*+,;=:@/?-]*)?(\#[a-z0-9._~%!$&()*+,;=:@/?-]*)?"
			).unwrap()
		) {
			if let Ok(u) = LSPSUrl::parse(url_str.to_string()) {
				prop_assert_eq!(u.url(), url_str.clone());
				prop_assert_eq!(u.url_length(), url_str.chars().count());
				let scheme_prefix = format!("{}://", u.scheme);
				prop_assert!(url_str.starts_with(&scheme_prefix));

				prop_assert!(!u.scheme.0.is_empty());
				prop_assert!(!u.host.0.is_empty());
				prop_assert!(url_str.contains(&u.scheme.0));
				prop_assert!(url_str.contains(&u.host.0));

				prop_assert!(!u.host.0.is_empty());

				if let Some(idx) = u.host.0.rfind(':') {
					let (host_part, port_part) = u.host.0.split_at(idx);
					if !host_part.is_empty() && port_part.len() > 1 {
						let port_str = &port_part[1..];
						prop_assert!(port_str.chars().all(|c| c.is_ascii_digit()));
						// Port must be in 0..=u32::MAX (parseable as u32)
						prop_assert!(port_str.parse::<u32>().is_ok());
					}
				}

				if u.host.0.chars().all(|c| c.is_ascii_digit() || c == '.') && u.host.0.matches('.').count() == 3 {
					let octets: Vec<_> = u.host.0.split('.').collect();
					prop_assert_eq!(octets.len(), 4);
					for octet in octets {
						prop_assert!(!octet.is_empty());
					}
				}
				if u.host.0 == "localhost" || u.host.0.starts_with("127.") || u.host.0 == "::1" {
					prop_assert!(!u.is_public());
				}
				if u.host.0.starts_with("10.") || u.host.0.starts_with("192.168.") {
					prop_assert!(!u.is_public());
				}
				if u.host.0.starts_with("172.") {
					if let Some(second_octet) = u.host.0.split('.').nth(1) {
						if let Ok(num) = second_octet.parse::<u8>() {
							if (16..=31).contains(&num) {
								prop_assert!(!u.is_public());
							}
						}
					}
				}

				if u.scheme.0 == "https" {
					prop_assert!(u.is_https());
				} else {
					prop_assert_eq!(u.is_https(), u.scheme.0 == "https");
				}
			}
		}
	}
}
