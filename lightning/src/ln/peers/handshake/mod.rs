//! Execute handshakes for peer-to-peer connection establishment.
//! Handshake states can be advanced automatically, or by manually calling the appropriate step.
//! Once complete, returns an instance of Conduit.

use secp256k1;

use bitcoin_hashes::{Hash, HashEngine};
use bitcoin_hashes::sha256::Hash as Sha256;
use secp256k1::{PublicKey, SecretKey};

use ln::peers::{chacha, hkdf};
use ln::peers::conduit::{Conduit, SymmetricKey};
use ln::peers::handshake::acts::{ActOne, ActThree, ActTwo, ACT_ONE_LENGTH, ACT_TWO_LENGTH, ACT_THREE_LENGTH, Act};
use ln::peers::handshake::hash::HandshakeHash;
use ln::peers::handshake::states::{ActOneExpectation, ActThreeExpectation, ActTwoExpectation, HandshakeState};

pub(crate) mod acts;
mod hash;
mod states;
mod tests;

/// Object for managing handshakes.
/// Currently requires explicit ephemeral private key specification.
pub struct PeerHandshake {
	state: Option<HandshakeState>,
	private_key: SecretKey,
	remote_public_key: Option<PublicKey>,
	ephemeral_private_key: SecretKey,

	read_buffer: Vec<u8>,
}

impl PeerHandshake {
	/// Instantiate a new handshake with a node identity secret key and an ephemeral private key
	pub fn new_outbound(private_key: &SecretKey, remote_public_key: &PublicKey, ephemeral_private_key: &SecretKey) -> Self {
		Self {
			state: Some(HandshakeState::Uninitiated),
			private_key: (*private_key).clone(),
			remote_public_key: Some(remote_public_key.clone()),
			ephemeral_private_key: (*ephemeral_private_key).clone(),
			read_buffer: Vec::new(),
		}
	}

	/// Instantiate a new handshake in anticipation of a peer's first handshake act
	pub fn new_inbound(private_key: &SecretKey, ephemeral_private_key: &SecretKey) -> Self {
		let mut handshake = Self {
			state: Some(HandshakeState::Uninitiated),
			private_key: (*private_key).clone(),
			remote_public_key: None,
			ephemeral_private_key: (*ephemeral_private_key).clone(),
			read_buffer: Vec::new(),
		};
		let public_key = Self::private_key_to_public_key(&private_key);
		let (hash, chaining_key) = Self::initialize_state(&public_key);
		handshake.state = Some(HandshakeState::AwaitingActOne(ActOneExpectation {
			hash,
			chaining_key,
		}));
		handshake
	}

	/// Return the remote public key once it has been extracted from the third act.
	/// Potentially useful for inbound connections
	pub fn get_remote_pubkey(&self) -> Option<PublicKey> {
		self.remote_public_key
	}

	fn initialize_state(public_key: &PublicKey) -> (HandshakeHash, [u8; 32]) {
		let protocol_name = b"Noise_XK_secp256k1_ChaChaPoly_SHA256";
		let prologue = b"lightning";

		let mut sha = Sha256::engine();
		sha.input(protocol_name);
		let chaining_key = Sha256::from_engine(sha).into_inner();

		let mut initial_hash_preimage = chaining_key.to_vec();
		initial_hash_preimage.extend_from_slice(prologue.as_ref());

		let mut hash = HandshakeHash::new(initial_hash_preimage.as_slice());
		hash.update(&public_key.serialize());

		(hash, chaining_key)
	}

	/// Process act dynamically
	/// # Arguments
	/// `input`: Byte slice received from peer as part of the handshake protocol
	///
	/// # Return values
	/// Returns a tuple with the following components:
	/// `.0`: Byte vector containing the next act to send back to the peer per the handshake protocol
	/// `.1`: Conduit option if the handshake was just processed to completion and messages can now be encrypted and decrypted
	pub fn process_act(&mut self, input: &[u8]) -> Result<(Option<Act>, Option<Conduit>), String> {
		let mut response = None;
		let mut connected_peer = None;

		self.read_buffer.extend_from_slice(input);
		let read_buffer_length = self.read_buffer.len();

		match &self.state {
			&Some(HandshakeState::Uninitiated) => {
				let remote_public_key = &self.remote_public_key.ok_or("outbound connections must be initialized with new_outbound")?;
				let act_one = self.initiate(&remote_public_key)?;
				response = Some(Act::One(act_one));
			}
			&Some(HandshakeState::AwaitingActOne(_)) => {
				if read_buffer_length < ACT_ONE_LENGTH {
					return Err("need at least 50 bytes".to_string());
				}

				let mut act_one_buffer = [0u8; ACT_ONE_LENGTH];
				act_one_buffer.copy_from_slice(&self.read_buffer[..ACT_ONE_LENGTH]);
				self.read_buffer.drain(..ACT_ONE_LENGTH);

				let act_two = self.process_act_one(ActOne(act_one_buffer))?;
				response = Some(Act::Two(act_two));
			}
			&Some(HandshakeState::AwaitingActTwo(_)) => {
				if read_buffer_length < ACT_TWO_LENGTH {
					return Err("need at least 50 bytes".to_string());
				}

				let mut act_two_buffer = [0u8; ACT_TWO_LENGTH];
				act_two_buffer.copy_from_slice(&self.read_buffer[..ACT_TWO_LENGTH]);
				self.read_buffer.drain(..ACT_TWO_LENGTH);

				let (act_three, mut conduit) = self.process_act_two(ActTwo(act_two_buffer))?;

				if self.read_buffer.len() > 0 { // have we received more data still?
					conduit.read(&self.read_buffer[..]);
					self.read_buffer.drain(..);
				}

				response = Some(Act::Three(act_three));
				connected_peer = Some(conduit);
			}
			&Some(HandshakeState::AwaitingActThree(_)) => {
				if read_buffer_length < ACT_THREE_LENGTH {
					return Err("need at least 66 bytes".to_string());
				}

				let mut act_three_buffer = [0u8; ACT_THREE_LENGTH];
				act_three_buffer.copy_from_slice(&self.read_buffer[..ACT_THREE_LENGTH]);
				self.read_buffer.drain(..ACT_THREE_LENGTH);

				let (public_key, mut conduit) = self.process_act_three(ActThree(act_three_buffer))?;

				if self.read_buffer.len() > 0 { // have we received more data still?
					conduit.read(&self.read_buffer[..]);
					self.read_buffer.drain(..);
				}

				connected_peer = Some(conduit);
				self.remote_public_key = Some(public_key);
			}
			_ => {
				panic!("no acts left to process");
			}
		};
		Ok((response, connected_peer))
	}

	/// Initiate the handshake with a peer and return the first act
	pub fn initiate(&mut self, remote_public_key: &PublicKey) -> Result<ActOne, String> {
		if let &Some(HandshakeState::Uninitiated) = &self.state {} else {
			return Err("Handshakes can only be initiated from the uninitiated state".to_string());
		}

		let (mut hash, chaining_key) = Self::initialize_state(&remote_public_key);

		// serialize act one
		let (act_one, chaining_key, temporary_key) = Self::calculate_act_message(
			&self.ephemeral_private_key,
			remote_public_key,
			chaining_key,
			&mut hash,
		);

		self.state = Some(HandshakeState::AwaitingActTwo(ActTwoExpectation {
			hash,
			chaining_key,
			temporary_key,
			ephemeral_private_key: (*&self.ephemeral_private_key).clone(),
		}));

		Ok(ActOne(act_one))
	}

	/// Process a peer's incoming first act and return the second act
	pub(crate) fn process_act_one(&mut self, act: ActOne) -> Result<ActTwo, String> {
		let state = self.state.take();
		let act_one_expectation = match state {
			Some(HandshakeState::AwaitingActOne(act_state)) => act_state,
			Some(HandshakeState::Uninitiated) => {
				let public_key = Self::private_key_to_public_key(&self.private_key);
				let (hash, chaining_key) = Self::initialize_state(&public_key);
				ActOneExpectation {
					hash,
					chaining_key,
				}
			}
			_ => {
				self.state = state;
				panic!("unexpected state");
			}
		};

		let mut hash = act_one_expectation.hash;
		let (remote_ephemeral_public_key, chaining_key, _) = Self::process_act_message(
			act.0,
			&self.private_key,
			act_one_expectation.chaining_key,
			&mut hash,
		)?;

		let ephemeral_private_key = (*&self.ephemeral_private_key).clone();

		let (act_two, chaining_key, temporary_key) = Self::calculate_act_message(
			&ephemeral_private_key,
			&remote_ephemeral_public_key,
			chaining_key,
			&mut hash,
		);

		self.state = Some(HandshakeState::AwaitingActThree(ActThreeExpectation {
			hash,
			chaining_key,
			temporary_key,
			ephemeral_private_key,
			remote_ephemeral_public_key,
		}));

		Ok(ActTwo(act_two))
	}

	/// Process a peer's incoming second act and return the third act alongside a Conduit instance
	pub(crate) fn process_act_two(&mut self, act: ActTwo) -> Result<(ActThree, Conduit), String> {
		let state = self.state.take();
		let act_two_expectation = match state {
			Some(HandshakeState::AwaitingActTwo(act_state)) => act_state,
			_ => {
				self.state = state;
				panic!("unexpected state".to_string());
			}
		};

		let mut hash = act_two_expectation.hash;
		let (remote_ephemeral_public_key, chaining_key, temporary_key) = Self::process_act_message(
			act.0,
			&act_two_expectation.ephemeral_private_key,
			act_two_expectation.chaining_key,
			&mut hash,
		)?;

		self.state = Some(HandshakeState::Complete);

		// start serializing act three

		let static_public_key = Self::private_key_to_public_key(&self.private_key);
		let tagged_encrypted_pubkey = chacha::encrypt(&temporary_key, 1, &hash.value, &static_public_key.serialize());
		hash.update(&tagged_encrypted_pubkey);

		let ecdh = Self::ecdh(&self.private_key, &remote_ephemeral_public_key);
		let (chaining_key, temporary_key) = hkdf::derive(&chaining_key, &ecdh);
		let authentication_tag = chacha::encrypt(&temporary_key, 0, &hash.value, &[0; 0]);
		let (sending_key, receiving_key) = hkdf::derive(&chaining_key, &[0; 0]);

		let mut act_three = [0u8; ACT_THREE_LENGTH];
		act_three[1..50].copy_from_slice(&tagged_encrypted_pubkey);
		act_three[50..].copy_from_slice(authentication_tag.as_slice());

		let connected_peer = Conduit {
			sending_key,
			receiving_key,
			sending_chaining_key: chaining_key,
			receiving_chaining_key: chaining_key,
			sending_nonce: 0,
			receiving_nonce: 0,
			read_buffer: None,
		};
		Ok((ActThree(act_three), connected_peer))
	}

	/// Process a peer's incoming third act and return a Conduit instance
	pub(crate) fn process_act_three(&mut self, act: ActThree) -> Result<(PublicKey, Conduit), String> {
		let state = self.state.take();
		let act_three_expectation = match state {
			Some(HandshakeState::AwaitingActThree(act_state)) => act_state,
			_ => {
				self.state = state;
				panic!("unexpected state".to_string());
			}
		};

		let version = act.0[0];
		if version != 0 {
			// this should not crash the process, hence no panic
			return Err("unexpected version".to_string());
		}

		let mut tagged_encrypted_pubkey = [0u8; 49];
		tagged_encrypted_pubkey.copy_from_slice(&act.0[1..50]);

		let mut chacha_tag = [0u8; 16];
		chacha_tag.copy_from_slice(&act.0[50..66]);

		let mut hash = act_three_expectation.hash;

		let remote_pubkey_vec = chacha::decrypt(&act_three_expectation.temporary_key, 1, &hash.value, &tagged_encrypted_pubkey)?;
		let mut remote_pubkey_bytes = [0u8; 33];
		remote_pubkey_bytes.copy_from_slice(remote_pubkey_vec.as_slice());
		// todo: replace unwrap with handleable error type
		let remote_pubkey = PublicKey::from_slice(&remote_pubkey_bytes).unwrap();

		hash.update(&tagged_encrypted_pubkey);

		let ecdh = Self::ecdh(&act_three_expectation.ephemeral_private_key, &remote_pubkey);
		let (chaining_key, temporary_key) = hkdf::derive(&act_three_expectation.chaining_key, &ecdh);
		let _tag_check = chacha::decrypt(&temporary_key, 0, &hash.value, &chacha_tag)?;
		let (receiving_key, sending_key) = hkdf::derive(&chaining_key, &[0; 0]);

		let connected_peer = Conduit {
			sending_key,
			receiving_key,
			sending_chaining_key: chaining_key,
			receiving_chaining_key: chaining_key,
			sending_nonce: 0,
			receiving_nonce: 0,
			read_buffer: None,
		};
		Ok((remote_pubkey, connected_peer))
	}

	fn calculate_act_message(local_private_key: &SecretKey, remote_public_key: &PublicKey, chaining_key: [u8; 32], hash: &mut HandshakeHash) -> ([u8; 50], SymmetricKey, SymmetricKey) {
		let local_public_key = Self::private_key_to_public_key(local_private_key);

		hash.update(&local_public_key.serialize());

		let ecdh = Self::ecdh(local_private_key, &remote_public_key);
		let (chaining_key, temporary_key) = hkdf::derive(&chaining_key, &ecdh);
		let tagged_ciphertext = chacha::encrypt(&temporary_key, 0, &hash.value, &[0; 0]);

		hash.update(&tagged_ciphertext);

		let mut act = [0u8; 50];
		act[1..34].copy_from_slice(&local_public_key.serialize());
		act[34..].copy_from_slice(tagged_ciphertext.as_slice());

		(act, chaining_key, temporary_key)
	}

	// Due to the very high similarity of acts 1 and 2, this method is used to process both
	fn process_act_message(act_bytes: [u8; 50], local_private_key: &SecretKey, chaining_key: SymmetricKey, hash: &mut HandshakeHash) -> Result<(PublicKey, SymmetricKey, SymmetricKey), String> {
		let version = act_bytes[0];
		if version != 0 {
			// this should not crash the process, hence no panic
			return Err("unexpected version".to_string());
		}

		let mut ephemeral_public_key_bytes = [0u8; 33];
		ephemeral_public_key_bytes.copy_from_slice(&act_bytes[1..34]);
		// todo: replace unwrap with handleable error type
		let ephemeral_public_key = PublicKey::from_slice(&ephemeral_public_key_bytes).unwrap();

		let mut chacha_tag = [0u8; 16];
		chacha_tag.copy_from_slice(&act_bytes[34..50]);

		// process the act message

		// update hash with partner's pubkey
		hash.update(&ephemeral_public_key.serialize());

		// calculate ECDH with partner's pubkey and local privkey
		let ecdh = Self::ecdh(local_private_key, &ephemeral_public_key);

		// HKDF(chaining key, ECDH) -> chaining key' + next temporary key
		let (chaining_key, temporary_key) = hkdf::derive(&chaining_key, &ecdh);

		// Validate chacha tag (temporary key, 0, hash, chacha_tag)
		let _tag_check = chacha::decrypt(&temporary_key, 0, &hash.value, &chacha_tag)?;

		hash.update(&chacha_tag);

		Ok((ephemeral_public_key, chaining_key, temporary_key))
	}

	fn private_key_to_public_key(private_key: &SecretKey) -> PublicKey {
		let curve = secp256k1::Secp256k1::new();
		let pk_object = PublicKey::from_secret_key(&curve, &private_key);
		pk_object
	}

	fn ecdh(private_key: &SecretKey, public_key: &PublicKey) -> SymmetricKey {
		let curve = secp256k1::Secp256k1::new();
		let mut pk_object = public_key.clone();
		pk_object.mul_assign(&curve, &private_key[..]).expect("invalid multiplication");

		let preimage = pk_object.serialize();
		let mut sha = Sha256::engine();
		sha.input(preimage.as_ref());
		Sha256::from_engine(sha).into_inner()
	}
}