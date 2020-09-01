//! Everything that has to do with over-the-wire peer communication.
//! The handshake module exposes mechanisms to conduct inbound and outbound handshakes.
//! When a handshake completes, it returns an instance of Conduit.
//! Conduit enables message encryption and decryption, and automatically handles key rotation.

mod chacha;
pub mod handler;
mod hkdf5869rfc;
mod outbound_queue;

#[cfg(feature = "fuzztarget")]
pub mod conduit;
#[cfg(not(feature = "fuzztarget"))]
mod conduit;

#[cfg(feature = "fuzztarget")]
pub mod handshake;
#[cfg(not(feature = "fuzztarget"))]
mod handshake;
