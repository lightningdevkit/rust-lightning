use http;
use http::uri::{Scheme, Uri};

/// Endpoint for interacting with an HTTP-based API.
#[derive(Debug)]
pub struct HttpEndpoint {
	uri: Uri,
}

/// Error when creating an `HttpEndpoint`.
#[derive(Debug)]
pub enum HttpEndpointError {
	InvalidUri(http::uri::InvalidUri),
	RelativeUri,
	InvalidScheme(http::uri::Scheme),
}

impl HttpEndpoint {
	/// Creates a new endpoint from the given URI.
	pub fn new(uri: &str) -> Result<HttpEndpoint, HttpEndpointError> {
		let uri = uri.parse::<Uri>()?;
		match uri.scheme() {
			None => Err(HttpEndpointError::RelativeUri),
			Some(scheme) => {
				if scheme != &Scheme::HTTP && scheme != &Scheme::HTTPS {
					Err(HttpEndpointError::InvalidScheme(scheme.clone()))
				} else {
					Ok(Self { uri })
				}
			},
		}
	}

	/// Returns the endpoint host.
	pub fn host(&self) -> &str {
		self.uri.host().unwrap()
	}

	/// Returns the endpoint port.
	pub fn port(&self) -> u16 {
		match self.uri.port_u16() {
			None => {
				let scheme = self.uri.scheme().unwrap();
				if scheme == &Scheme::HTTP { 80 }
				else if scheme == &Scheme::HTTPS { 443 }
				else { unreachable!() }
			},
			Some(port) => port,
		}
	}

	/// Returns the endpoint path.
	pub fn path(&self) -> &str {
		self.uri.path()
	}
}

impl<'a> std::net::ToSocketAddrs for &'a HttpEndpoint {
	type Iter = <(&'a str, u16) as std::net::ToSocketAddrs>::Iter;

	fn to_socket_addrs(&self) -> std::io::Result<Self::Iter> {
		(self.host(), self.port()).to_socket_addrs()
	}
}

impl From<http::uri::InvalidUri> for HttpEndpointError {
	fn from(error: http::uri::InvalidUri) -> Self {
		HttpEndpointError::InvalidUri(error)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn parse_invalid_uri() {
		match HttpEndpoint::new("::") {
			Err(HttpEndpointError::InvalidUri(_)) => (),
			Err(e) => panic!("Unexpected error: {:?}", e),
			Ok(endpoint) => panic!("Expected error; found endpoint: {:?}", endpoint),
		}
	}

	#[test]
	fn parse_relative_uri() {
		match HttpEndpoint::new("path") {
			Err(HttpEndpointError::RelativeUri) => (),
			Err(e) => panic!("Unexpected error: {:?}", e),
			Ok(endpoint) => panic!("Expected error; found endpoint: {:?}", endpoint),
		}
	}

	#[test]
	fn parse_invalid_scheme() {
		match HttpEndpoint::new("ftp://foo.com") {
			Err(HttpEndpointError::InvalidScheme(_)) => (),
			Err(e) => panic!("Unexpected error: {:?}", e),
			Ok(endpoint) => panic!("Expected error; found endpoint: {:?}", endpoint),
		}
	}

	#[test]
	fn parse_insecure_uri() {
		match HttpEndpoint::new("http://foo.com") {
			Err(e) => panic!("Unexpected error: {:?}", e),
			Ok(endpoint) => {
				assert_eq!(endpoint.host(), "foo.com");
				assert_eq!(endpoint.port(), 80);
			},
		}
	}

	#[test]
	fn parse_secure_uri() {
		match HttpEndpoint::new("https://foo.com") {
			Err(e) => panic!("Unexpected error: {:?}", e),
			Ok(endpoint) => {
				assert_eq!(endpoint.host(), "foo.com");
				assert_eq!(endpoint.port(), 443);
			},
		}
	}

	#[test]
	fn parse_uri_with_port() {
		match HttpEndpoint::new("http://foo.com:8080") {
			Err(e) => panic!("Unexpected error: {:?}", e),
			Ok(endpoint) => {
				assert_eq!(endpoint.host(), "foo.com");
				assert_eq!(endpoint.port(), 8080);
			},
		}
	}

	#[test]
	fn parse_uri_with_path() {
		match HttpEndpoint::new("http://foo.com/path") {
			Err(e) => panic!("Unexpected error: {:?}", e),
			Ok(endpoint) => {
				assert_eq!(endpoint.host(), "foo.com");
				assert_eq!(endpoint.path(), "/path");
			},
		}
	}

	#[test]
	fn parse_uri_without_path() {
		match HttpEndpoint::new("http://foo.com") {
			Err(e) => panic!("Unexpected error: {:?}", e),
			Ok(endpoint) => {
				assert_eq!(endpoint.host(), "foo.com");
				assert_eq!(endpoint.path(), "/");
			},
		}
	}

	#[test]
	fn convert_to_socket_addrs() {
		let endpoint = HttpEndpoint::new("http://foo.com").unwrap();
		let host = endpoint.host();
		let port = endpoint.port();

		use std::net::ToSocketAddrs;
		match (&endpoint).to_socket_addrs() {
			Err(e) => panic!("Unexpected error: {:?}", e),
			Ok(mut socket_addrs) => {
				match socket_addrs.next() {
					None => panic!("Expected socket address"),
					Some(addr) => {
						assert_eq!(addr, (host, port).to_socket_addrs().unwrap().next().unwrap());
						assert!(socket_addrs.next().is_none());
					}
				}
			}
		}
	}
}
