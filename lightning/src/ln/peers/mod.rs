// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Everything that has to do with over-the-wire peer communication.
//! The handshake module exposes mechanisms to conduct inbound and outbound handshakes.
//! When a handshake completes, it returns an instance of CompletedPeerHandshake containing an
//! Encryptor/Decryptor used for encrypted communication and the remote static public key used for
//! identification.

#[cfg(test)]
#[macro_use]
mod test_util;

#[cfg(test)]
#[macro_use]
mod test_message_macros;

mod chacha;
pub mod handler;
mod hkdf5869rfc;
mod outbound_queue;

#[cfg(feature = "fuzztarget")]
pub mod encryption;
#[cfg(not(feature = "fuzztarget"))]
mod encryption;

#[cfg(feature = "fuzztarget")]
pub mod handshake;
#[cfg(not(feature = "fuzztarget"))]
mod handshake;

#[cfg(feature = "fuzztarget")]
pub mod transport;
#[cfg(not(feature = "fuzztarget"))]
mod transport;
