//! Execute handshakes for peer-to-peer connection establishment.
//! Handshake states can be advanced automatically, or by manually calling the appropriate step.
//! Once complete, returns an instance of Conduit.

use bitcoin::secp256k1;

use bitcoin::hashes::{Hash, HashEngine};
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::secp256k1::{PublicKey, SecretKey};

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

		let connected_peer = Conduit::new(sending_key, receiving_key, chaining_key);
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
		let remote_pubkey = if let Ok(public_key) = PublicKey::from_slice(&remote_pubkey_bytes) {
			public_key
		} else {
			return Err("invalid remote public key".to_string());
		};

		hash.update(&tagged_encrypted_pubkey);

		let ecdh = Self::ecdh(&act_three_expectation.ephemeral_private_key, &remote_pubkey);
		let (chaining_key, temporary_key) = hkdf::derive(&act_three_expectation.chaining_key, &ecdh);
		let _tag_check = chacha::decrypt(&temporary_key, 0, &hash.value, &chacha_tag)?;
		let (receiving_key, sending_key) = hkdf::derive(&chaining_key, &[0; 0]);

		let connected_peer = Conduit::new(sending_key, receiving_key, chaining_key);
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
		let ephemeral_public_key = if let Ok(public_key) = PublicKey::from_slice(&ephemeral_public_key_bytes) {
			public_key
		} else {
			return Err("invalid remote ephemeral public key".to_string());
		};

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

#[cfg(test)]
mod test {
	use hex;

	use bitcoin::secp256k1;
	use bitcoin::secp256k1::key::{PublicKey, SecretKey};

	use ln::peers::handshake::PeerHandshake;
	use ln::peers::handshake::acts::Act;
	use ln::peers::handshake::states::HandshakeState;

	struct TestCtx {
		outbound_handshake: PeerHandshake,
		outbound_public_key: PublicKey,
		inbound_handshake: PeerHandshake,
		inbound_public_key: PublicKey
	}

	impl TestCtx {
		fn new() -> TestCtx {
			let curve = secp256k1::Secp256k1::new();

			let outbound_private_key = SecretKey::from_slice(&[0x_11_u8; 32]).unwrap();
			let outbound_public_key = PublicKey::from_secret_key(&curve, &outbound_private_key);
			let outbound_ephemeral_key = SecretKey::from_slice(&[0x_12_u8; 32]).unwrap();

			let inbound_private_key = SecretKey::from_slice(&[0x_21_u8; 32]).unwrap();
			let inbound_public_key = PublicKey::from_secret_key(&curve, &inbound_private_key);
			let inbound_ephemeral_key = SecretKey::from_slice(&[0x_22_u8; 32]).unwrap();

			let outbound_handshake = PeerHandshake::new_outbound(&outbound_private_key, &inbound_public_key, &outbound_ephemeral_key);
			let inbound_handshake = PeerHandshake::new_inbound(&inbound_private_key, &inbound_ephemeral_key);

			TestCtx {
				outbound_handshake,
				outbound_public_key,
				inbound_handshake,
				inbound_public_key
			}
		}
	}

	macro_rules! assert_matches {
		($e:expr, $state_match:pat) => {
			match $e {
				$state_match => (),
				_ => panic!()
			}
		}
	}

	macro_rules! do_process_act_or_panic {
		($handshake:expr, $input:expr) => {
			$handshake.process_act($input).unwrap().0.unwrap().serialize()
		}
	}

	// Default Outbound::Uninitiated
	#[test]
	fn peer_handshake_new_outbound() {
		let test_ctx = TestCtx::new();

		assert_matches!(test_ctx.outbound_handshake.state, Some(HandshakeState::Uninitiated));
		assert_eq!(test_ctx.outbound_handshake.get_remote_pubkey(), Some(test_ctx.inbound_public_key));
	}

	// Default Inbound::AwaitingActOne
	#[test]
	fn peer_handshake_new_inbound() {
		let test_ctx = TestCtx::new();

		assert_matches!(test_ctx.inbound_handshake.state, Some(HandshakeState::AwaitingActOne(_)));
		assert!(test_ctx.inbound_handshake.get_remote_pubkey().is_none());
	}

	/*
	 * PeerHandshake::process_act() tests
	 */

	// Outbound::Uninitiated -> AwaitingActTwo
	#[test]
	fn peer_handshake_outbound_uninitiated_to_awaiting_act_two() {
		let mut test_ctx = TestCtx::new();

		assert_matches!(test_ctx.outbound_handshake.process_act(&[]).unwrap(), (Some(Act::One(_)), None));
		assert_matches!(test_ctx.outbound_handshake.state, Some(HandshakeState::AwaitingActTwo(_)));
		assert_eq!(test_ctx.outbound_handshake.get_remote_pubkey(), Some(test_ctx.inbound_public_key));
	}

	// Outbound::Uninitiated -> AwaitingActTwo (extra bytes in argument)
	#[test]
	fn peer_handshake_outbound_uninitiated_to_awaiting_act_two_nonempty_input() {
		let mut test_ctx = TestCtx::new();

		// TODO: process_act() should error if state does not use vec, but it is non-empty
		assert_matches!(test_ctx.outbound_handshake.process_act(&[1]).unwrap(), (Some(Act::One(_)), None));
		assert_matches!(test_ctx.outbound_handshake.state, Some(HandshakeState::AwaitingActTwo(_)));
		assert_eq!(test_ctx.outbound_handshake.get_remote_pubkey(), Some(test_ctx.inbound_public_key));
	}

	// Inbound::AwaitingActOne -> Error (input too small)
	#[test]
	fn peer_handshake_new_inbound_awaiting_act_one_input_too_small() {
		let mut test_ctx = TestCtx::new();

		assert_eq!(test_ctx.inbound_handshake.process_act(&[]).err(), Some(String::from("need at least 50 bytes")));
	}

	// Inbound::AwaitingActOne -> AwaitingActThree (excess bytes)
	// TODO: This should error early if we receive act3 data prior to sending act2
	#[test]
	fn peer_handshake_new_inbound_awaiting_act_one_input_too_large() {
		let mut test_ctx = TestCtx::new();
		let mut act1 = do_process_act_or_panic!(test_ctx.outbound_handshake, &[]);
		act1.extend_from_slice(&[1]);

		assert_matches!(test_ctx.inbound_handshake.process_act(&act1).unwrap(), (Some(Act::Two(_)), None));
		assert_matches!(test_ctx.inbound_handshake.state, Some(HandshakeState::AwaitingActThree(_)));
		assert!(test_ctx.inbound_handshake.get_remote_pubkey().is_none());
	}

	// Inbound::AwaitingActOne -> Error (bad version byte)
	#[test]
	fn peer_handshake_new_inbound_awaiting_act_one_bad_version() {
		let mut test_ctx = TestCtx::new();
		let mut act1 = do_process_act_or_panic!(test_ctx.outbound_handshake, &[]);
		// Set bad version byte
		act1[0] = 1;

		assert_eq!(test_ctx.inbound_handshake.process_act(&act1).err(), Some(String::from("unexpected version")));
	}

	// Inbound::AwaitingActOne -> Error (invalid hmac)
	#[test]
	fn peer_handshake_new_inbound_awaiting_act_invalid_hmac() {
		let mut test_ctx = TestCtx::new();
		let mut act1 = do_process_act_or_panic!(test_ctx.outbound_handshake, &[]);
		// corrupt the ciphertext
		act1[34] = 0;

		assert_eq!(test_ctx.inbound_handshake.process_act(&act1).err(), Some(String::from("invalid hmac")));
	}

	// Inbound::AwaitingActOne -> Error (invalid remote ephemeral key)
	#[test]
	fn peer_handshake_new_inbound_awaiting_act_invalid_remote_ephemeral_key() {
		let mut test_ctx = TestCtx::new();
		let mut act1 = do_process_act_or_panic!(test_ctx.outbound_handshake, &[]);
		// corrupt the ephemeral public key
		act1[1] = 0;

		assert_eq!(test_ctx.inbound_handshake.process_act(&act1).err(), Some(String::from("invalid remote ephemeral public key")));
	}

	// Inbound::AwaitingActOne -> AwaitingActThree
	#[test]
	fn peer_handshake_new_inbound_awaiting_act_one_to_awaiting_act_three() {
		let mut test_ctx = TestCtx::new();
		let act1 = do_process_act_or_panic!(test_ctx.outbound_handshake, &[]);

		assert_matches!(test_ctx.inbound_handshake.process_act(&act1).unwrap(), (Some(Act::Two(_)), None));
		assert_matches!(test_ctx.inbound_handshake.state, Some(HandshakeState::AwaitingActThree(_)));
		assert_eq!(test_ctx.inbound_handshake.get_remote_pubkey(), None);
	}

	// Outbound::AwaitingActTwo -> Complete (valid conduit)
	#[test]
	fn peer_handshake_outbound_awaiting_act_two_process() {
		let mut test_ctx = TestCtx::new();
		let act1 = do_process_act_or_panic!(test_ctx.outbound_handshake, &[]);
		let act2 = do_process_act_or_panic!(test_ctx.inbound_handshake, &act1);

		assert_matches!(test_ctx.outbound_handshake.process_act(&act2).unwrap(), (Some(Act::Three(_)), Some(_)));
		assert_matches!(test_ctx.outbound_handshake.state, Some(HandshakeState::Complete));
		assert_eq!(test_ctx.outbound_handshake.get_remote_pubkey(), Some(test_ctx.inbound_public_key));
	}


	// Outbound::AwaitingActTwo -> Complete (with extra data)
	// Ensures that any remaining data in the read buffer is transferred to the conduit once
	// the handshake is complete
	// TODO: Is this valid? Don't we expect peers to need ActThree before sending additional data?
	#[test]
	fn peer_handshake_new_outbound_excess_bytes_after_complete_are_in_conduit() {
		let mut test_ctx = TestCtx::new();
		let act1 = do_process_act_or_panic!(test_ctx.outbound_handshake, &[]);
		let mut act2 = do_process_act_or_panic!(test_ctx.inbound_handshake, &act1);
		act2.extend_from_slice(&[1; 100]);

		let conduit = if let (_, Some(conduit)) = test_ctx.outbound_handshake.process_act(&act2).unwrap() {
			conduit
		} else {
			panic!();
		};

		assert_eq!(100, conduit.decryptor.read_buffer_length());
		assert_eq!(test_ctx.outbound_handshake.get_remote_pubkey(), Some(test_ctx.inbound_public_key));
	}

	// Outbound::AwaitingActTwo -> Error (input too small)
	#[test]
	fn peer_handshake_outbound_awaiting_act_two_input_too_small() {
		let mut test_ctx = TestCtx::new();
		let _act1 = do_process_act_or_panic!(test_ctx.outbound_handshake, &[]);

		assert_eq!(test_ctx.outbound_handshake.process_act(&[1]).err(), Some(String::from("need at least 50 bytes")));
	}

	// Outbound::AwaitingActTwo -> Error (bad version byte)
	#[test]
	fn peer_handshake_outbound_awaiting_act_two_bad_version() {
		let mut test_ctx = TestCtx::new();
		let act1 = do_process_act_or_panic!(test_ctx.outbound_handshake, &[]);
		let mut act2 = do_process_act_or_panic!(test_ctx.inbound_handshake, &act1);
		// Set version byte to 1
		act2[0] = 1;

		assert_eq!(test_ctx.outbound_handshake.process_act(&act2).err(), Some(String::from("unexpected version")));
	}

	// Outbound::AwaitingActTwo -> Error (invalid hmac)
	#[test]
	fn peer_handshake_outbound_awaiting_act_two_invalid_hmac() {
		let mut test_ctx = TestCtx::new();
		let act1 = do_process_act_or_panic!(test_ctx.outbound_handshake, &[]);
		let mut act2 = do_process_act_or_panic!(test_ctx.inbound_handshake, &act1);
		// corrupt the ciphertext
		act2[34] = 1;

		assert_eq!(test_ctx.outbound_handshake.process_act(&act2).err(), Some(String::from("invalid hmac")));
	}

	// Outbound::AwaitingActTwo -> Error (invalid remote ephemeral key)
	#[test]
	fn peer_handshake_outbound_awaiting_act_two_invalid_remote_ephemeral_key() {
		let mut test_ctx = TestCtx::new();
		let act1 = do_process_act_or_panic!(test_ctx.outbound_handshake, &[]);
		let mut act2 = do_process_act_or_panic!(test_ctx.inbound_handshake, &act1);
		// corrupt the ephemeral public key
		act2[1] = 1;

		assert_eq!(test_ctx.outbound_handshake.process_act(&act2).err(), Some(String::from("invalid remote ephemeral public key")));
	}

	// Inbound::AwaitingActThree -> None
	// TODO: should this transition to Complete instead of None?
	#[test]
	fn peer_handshake_new_inbound_awaiting_act_three_to_awaiting_act_three() {
		let mut test_ctx = TestCtx::new();
		let act1 = do_process_act_or_panic!(test_ctx.outbound_handshake, &[]);
		let act2 = do_process_act_or_panic!(test_ctx.inbound_handshake, &act1);
		let act3 = do_process_act_or_panic!(test_ctx.outbound_handshake, &act2);

		assert_matches!(test_ctx.inbound_handshake.process_act(&act3).unwrap(), (None, Some(_)));
		assert_eq!(test_ctx.inbound_handshake.get_remote_pubkey(), Some(test_ctx.outbound_public_key));
	}

	// Inbound::AwaitingActThree -> None (with extra bytes)
	// Ensures that any remaining data in the read buffer is transferred to the conduit once
	// the handshake is complete
	#[test]
	fn peer_handshake_new_inbound_excess_bytes_after_complete_are_in_conduit() {
		let mut test_ctx = TestCtx::new();
		let act1 = do_process_act_or_panic!(test_ctx.outbound_handshake, &[]);
		let act2 = do_process_act_or_panic!(test_ctx.inbound_handshake, &act1);
		let mut act3 = do_process_act_or_panic!(test_ctx.outbound_handshake, &act2);
		act3.extend_from_slice(&[2; 100]);

		let conduit = if let (None, Some(conduit)) = test_ctx.inbound_handshake.process_act(&act3).unwrap() {
			conduit
		} else {
			panic!();
		};

		assert_eq!(100, conduit.decryptor.read_buffer_length());
	}

	// Inbound::AwaitingActThree -> Error (input too small)
	#[test]
	fn peer_handshake_new_inbound_awaiting_act_three_input_too_small() {
		let mut test_ctx = TestCtx::new();
		let act1 = do_process_act_or_panic!(test_ctx.outbound_handshake, &[]);
		let act2 = do_process_act_or_panic!(test_ctx.inbound_handshake, &act1);
		let act3 = do_process_act_or_panic!(test_ctx.outbound_handshake, &act2);

		assert_eq!(test_ctx.inbound_handshake.process_act(&act3[..65]).err(), Some(String::from("need at least 66 bytes")));
	}

	// Inbound::AwaitingActThree -> Error (bad version byte)
	#[test]
	fn peer_handshake_new_inbound_awaiting_act_three_bad_version() {
		let mut test_ctx = TestCtx::new();
		let act1 = do_process_act_or_panic!(test_ctx.outbound_handshake, &[]);
		let act2 = do_process_act_or_panic!(test_ctx.inbound_handshake, &act1);
		let mut act3 = do_process_act_or_panic!(test_ctx.outbound_handshake, &act2);
		// set version byte to 1
		act3[0] = 1;

		assert_eq!(test_ctx.inbound_handshake.process_act(&act3).err(), Some(String::from("unexpected version")));
	}

	// Inbound::AwaitingActThree -> Error (invalid hmac)
	#[test]
	fn peer_handshake_new_inbound_awaiting_act_three_invalid_hmac() {
		let mut test_ctx = TestCtx::new();
		let act1 = do_process_act_or_panic!(test_ctx.outbound_handshake, &[]);
		let act2 = do_process_act_or_panic!(test_ctx.inbound_handshake, &act1);
		let mut act3 = do_process_act_or_panic!(test_ctx.outbound_handshake, &act2);
		// trigger decryption error by corrupting byte 1
		act3[1] = 0;

		assert_eq!(test_ctx.inbound_handshake.process_act(&act3).err(), Some(String::from("invalid hmac")));
	}

	// Inbound::AwaitingActThree -> Error (invalid tag hmac)
	#[test]
	fn peer_handshake_new_inbound_awaiting_act_three_invalid_tag_hmac() {
		let mut test_ctx = TestCtx::new();
		let act1 = do_process_act_or_panic!(test_ctx.outbound_handshake, &[]);
		let act2 = do_process_act_or_panic!(test_ctx.inbound_handshake, &act1);
		let mut act3 = do_process_act_or_panic!(test_ctx.outbound_handshake, &act2);
		// trigger tag decryption error by corrupting byte 50
		act3[50] = 0;

		assert_eq!(test_ctx.inbound_handshake.process_act(&act3).err(), Some(String::from("invalid hmac")));
	}

	// Inbound::Complete -> Panic
	#[test]
	#[should_panic(expected = "no acts left to process")]
	fn peer_handshake_new_inbound_complete_then_process_act() {
		let mut test_ctx = TestCtx::new();
		let act1 = do_process_act_or_panic!(test_ctx.outbound_handshake, &[]);
		let act2 = do_process_act_or_panic!(test_ctx.inbound_handshake, &act1);
		let act3 = do_process_act_or_panic!(test_ctx.outbound_handshake, &act2);
		test_ctx.inbound_handshake.process_act(&act3).unwrap();

		do_process_act_or_panic!(test_ctx.inbound_handshake, &[]);
	}

	// Outbound::None -> Panic
	#[test]
	#[should_panic(expected = "no acts left to process")]
	fn peer_handshake_new_outbound_complete_then_process_act() {
		let mut test_ctx = TestCtx::new();
		let act1 = do_process_act_or_panic!(test_ctx.outbound_handshake, &[]);
		let act2 = do_process_act_or_panic!(test_ctx.inbound_handshake, &act1);
		let act3 = do_process_act_or_panic!(test_ctx.outbound_handshake, &act2);
		test_ctx.inbound_handshake.process_act(&act3).unwrap();

		do_process_act_or_panic!(test_ctx.outbound_handshake, &[]);
	}

	// Test the Act byte generation against known good hard-coded values in case the implementation
	// changes in a symmetric way that makes the other tests useless
	#[test]
	fn peer_handshake_external_spec() {
		let mut test_ctx = TestCtx::new();
		let act1 = do_process_act_or_panic!(test_ctx.outbound_handshake, &[]);
		let act2 = do_process_act_or_panic!(test_ctx.inbound_handshake, &act1);
		let act3 = do_process_act_or_panic!(test_ctx.outbound_handshake, &act2);

		assert_eq!(hex::encode(&act1),
				   "00036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f70df6086551151f58b8afe6c195782c6a");
		assert_eq!(hex::encode(&act2),
				   "0002466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f276e2470b93aac583c9ef6eafca3f730ae");
		assert_eq!(hex::encode(&act3),
				   "00b9e3a702e93e3a9948c2ed6e5fd7590a6e1c3a0344cfc9d5b57357049aa22355361aa02e55a8fc28fef5bd6d71ad0c38228dc68b1c466263b47fdf31e560e139ba");
	}
}
