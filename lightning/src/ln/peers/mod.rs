//! Everything that has to do with over-the-wire peer communication.
//! The handshake module exposes mechanisms to conduct inbound and outbound handshakes.
//! When a handshake completes, it returns an instance of Conduit.
//! Conduit enables message encryption and decryption, and automatically handles key rotation.

mod chacha;
pub mod conduit;
pub mod handshake;
pub mod handler;
mod hkdf;
