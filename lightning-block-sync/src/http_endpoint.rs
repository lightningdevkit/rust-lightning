/// Endpoint for interacting with an HTTP-based API.
#[derive(Debug)]
pub struct HttpEndpoint {
	scheme: Scheme,
	host: String,
	port: Option<u16>,
	path: String,
}

/// URI scheme compatible with an HTTP endpoint.
#[derive(Debug)]
pub enum Scheme {
	HTTP,
	HTTPS,
}

impl HttpEndpoint {
	/// Creates an endpoint using the HTTP scheme.
	pub fn insecure_host(host: String) -> Self {
		Self {
			scheme: Scheme::HTTP,
			host,
			port: None,
			path: String::from("/"),
		}
	}

	/// Creates an endpoint using the HTTPS scheme.
	pub fn secure_host(host: String) -> Self {
		Self {
			scheme: Scheme::HTTPS,
			host,
			port: None,
			path: String::from("/"),
		}
	}

	/// Specifies a port to use with the endpoint.
	pub fn with_port(mut self, port: u16) -> Self {
		self.port = Some(port);
		self
	}

	/// Specifies a path to use with the endpoint.
	pub fn with_path(mut self, path: String) -> Self {
		self.path = path;
		self
	}

	/// Returns the endpoint host.
	pub fn host(&self) -> &str {
		&self.host
	}

	/// Returns the endpoint port.
	pub fn port(&self) -> u16 {
		match self.port {
			None => match self.scheme {
				Scheme::HTTP => 80,
				Scheme::HTTPS => 443,
			},
			Some(port) => port,
		}
	}

	/// Returns the endpoint path.
	pub fn path(&self) -> &str {
		&self.path
	}
}

impl<'a> std::net::ToSocketAddrs for &'a HttpEndpoint {
	type Iter = <(&'a str, u16) as std::net::ToSocketAddrs>::Iter;

	fn to_socket_addrs(&self) -> std::io::Result<Self::Iter> {
		(self.host(), self.port()).to_socket_addrs()
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn to_insecure_host() {
		let endpoint = HttpEndpoint::insecure_host("foo.com".into());
		assert_eq!(endpoint.host(), "foo.com");
		assert_eq!(endpoint.port(), 80);
	}

	#[test]
	fn to_secure_host() {
		let endpoint = HttpEndpoint::secure_host("foo.com".into());
		assert_eq!(endpoint.host(), "foo.com");
		assert_eq!(endpoint.port(), 443);
	}

	#[test]
	fn with_custom_port() {
		let endpoint = HttpEndpoint::insecure_host("foo.com".into()).with_port(8080);
		assert_eq!(endpoint.host(), "foo.com");
		assert_eq!(endpoint.port(), 8080);
	}

	#[test]
	fn with_uri_path() {
		let endpoint = HttpEndpoint::insecure_host("foo.com".into()).with_path("/path".into());
		assert_eq!(endpoint.host(), "foo.com");
		assert_eq!(endpoint.path(), "/path");
	}

	#[test]
	fn without_uri_path() {
		let endpoint = HttpEndpoint::insecure_host("foo.com".into());
		assert_eq!(endpoint.host(), "foo.com");
		assert_eq!(endpoint.path(), "/");
	}

	#[test]
	fn convert_to_socket_addrs() {
		let endpoint = HttpEndpoint::insecure_host("foo.com".into());
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
