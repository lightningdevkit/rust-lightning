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
