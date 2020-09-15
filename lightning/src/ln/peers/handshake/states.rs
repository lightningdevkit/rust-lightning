use ln::peers::handshake::hash::HandshakeHash;
use bitcoin::secp256k1::{SecretKey, PublicKey};

pub enum HandshakeState {
	Uninitiated,
	AwaitingActOne(ActOneExpectation),
	AwaitingActTwo(ActTwoExpectation),
	AwaitingActThree(ActThreeExpectation),
	Complete,
}

pub struct ActOneExpectation {
	pub(super) hash: HandshakeHash,
	pub(super) chaining_key: [u8; 32],
}

pub struct ActTwoExpectation {
	pub(super) hash: HandshakeHash,
	pub(super) chaining_key: [u8; 32],
	pub(super) temporary_key: [u8; 32],
	pub(super) ephemeral_private_key: SecretKey,
}

pub struct ActThreeExpectation {
	pub(super) hash: HandshakeHash,
	pub(super) chaining_key: [u8; 32],
	pub(super) temporary_key: [u8; 32],
	pub(super) ephemeral_private_key: SecretKey,
	pub(super) remote_ephemeral_public_key: PublicKey,
}
