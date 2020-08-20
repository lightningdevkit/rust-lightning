//! Execute handshakes for peer-to-peer connection establishment.
//! Handshake states can be advanced automatically, or by manually calling the appropriate step.
//! Once complete, returns an instance of Conduit.

use bitcoin::secp256k1::{PublicKey, SecretKey};

use ln::peers::conduit::Conduit;
use ln::peers::handshake::acts::Act;
use ln::peers::handshake::states::{HandshakeState2, UninitiatedHandshakeState, AwaitingActOneHandshakeState};

mod acts;
mod states;

/// Object for managing handshakes.
/// Currently requires explicit ephemeral private key specification.
pub struct PeerHandshake {
	state: Option<HandshakeState2>,
	remote_public_key: Option<PublicKey>,
}

impl PeerHandshake {
	/// Instantiate a new handshake with a node identity secret key and an ephemeral private key
	pub fn new_outbound(private_key: &SecretKey, remote_public_key: &PublicKey, ephemeral_private_key: &SecretKey) -> Self {
		Self {
			state: Some(HandshakeState2::Uninitiated2(UninitiatedHandshakeState::new(private_key.clone(), ephemeral_private_key.clone(), remote_public_key.clone()))),
			remote_public_key: Some(remote_public_key.clone()),
		}
	}

	/// Instantiate a new handshake in anticipation of a peer's first handshake act
	pub fn new_inbound(private_key: &SecretKey, ephemeral_private_key: &SecretKey) -> Self {
		Self {
			state: Some(HandshakeState2::AwaitingActOne2(AwaitingActOneHandshakeState::new(private_key.clone(), ephemeral_private_key.clone()))),
			remote_public_key: None,
		}
	}

	/// Return the remote public key once it has been extracted from the third act.
	/// Potentially useful for inbound connections
	pub fn get_remote_pubkey(&self) -> Option<PublicKey> {
		self.remote_public_key
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
		let cur_state = self.state.take().unwrap();

		let (act_opt, mut next_state) = cur_state.next(input)?;

		let result = match next_state {
			HandshakeState2::Complete2(ref mut conduit_and_pubkey) => {
				let (conduit, remote_pubkey) = conduit_and_pubkey.take().unwrap();
				self.remote_public_key = Some(remote_pubkey);

				Ok((act_opt, Some(conduit)))
			},
			_ => { Ok((act_opt, None)) }
		};

		self.state = Some(next_state);

		result
	}
}

#[cfg(test)]
mod test {
	use hex;

	use bitcoin::secp256k1;
	use bitcoin::secp256k1::key::{PublicKey, SecretKey};

	use ln::peers::handshake::PeerHandshake;
	use ln::peers::handshake::acts::Act;
	use ln::peers::handshake::states::HandshakeState2;

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

		assert_matches!(test_ctx.outbound_handshake.state, Some(HandshakeState2::Uninitiated2(_)));
		assert_eq!(test_ctx.outbound_handshake.get_remote_pubkey(), Some(test_ctx.inbound_public_key));
	}

	// Default Inbound::AwaitingActOne
	#[test]
	fn peer_handshake_new_inbound() {
		let test_ctx = TestCtx::new();

		assert_matches!(test_ctx.inbound_handshake.state, Some(HandshakeState2::AwaitingActOne2(_)));
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
		assert_matches!(test_ctx.outbound_handshake.state, Some(HandshakeState2::AwaitingActTwo2(_)));
		assert_eq!(test_ctx.outbound_handshake.get_remote_pubkey(), Some(test_ctx.inbound_public_key));
	}

	// Outbound::Uninitiated -> AwaitingActTwo (extra bytes in argument)
	#[test]
	fn peer_handshake_outbound_uninitiated_to_awaiting_act_two_nonempty_input() {
		let mut test_ctx = TestCtx::new();

		// TODO: process_act() should error if state does not use vec, but it is non-empty
		assert_matches!(test_ctx.outbound_handshake.process_act(&[1]).unwrap(), (Some(Act::One(_)), None));
		assert_matches!(test_ctx.outbound_handshake.state, Some(HandshakeState2::AwaitingActTwo2(_)));
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
		assert_matches!(test_ctx.inbound_handshake.state, Some(HandshakeState2::AwaitingActThree2(_)));
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
		assert_matches!(test_ctx.inbound_handshake.state, Some(HandshakeState2::AwaitingActThree2(_)));
		assert!(test_ctx.inbound_handshake.get_remote_pubkey().is_none());
	}

	// Outbound::AwaitingActTwo -> Complete (valid conduit)
	#[test]
	fn peer_handshake_outbound_awaiting_act_two_process() {
		let mut test_ctx = TestCtx::new();
		let act1 = do_process_act_or_panic!(test_ctx.outbound_handshake, &[]);
		let act2 = do_process_act_or_panic!(test_ctx.inbound_handshake, &act1);

		assert_matches!(test_ctx.outbound_handshake.process_act(&act2).unwrap(), (Some(Act::Three(_)), Some(_)));
		assert_matches!(test_ctx.outbound_handshake.state, Some(HandshakeState2::Complete2(_)));
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

	// Inbound::AwaitingActThree -> Complete
	#[test]
	fn peer_handshake_new_inbound_awaiting_act_three_to_awaiting_act_three() {
		let mut test_ctx = TestCtx::new();
		let act1 = do_process_act_or_panic!(test_ctx.outbound_handshake, &[]);
		let act2 = do_process_act_or_panic!(test_ctx.inbound_handshake, &act1);
		let act3 = do_process_act_or_panic!(test_ctx.outbound_handshake, &act2);

		assert_matches!(test_ctx.inbound_handshake.process_act(&act3).unwrap(), (None, Some(_)));
		assert_matches!(test_ctx.inbound_handshake.state, Some(HandshakeState2::Complete2(_)));
		assert_eq!(test_ctx.inbound_handshake.get_remote_pubkey(), Some(test_ctx.outbound_public_key));
	}

	// Inbound::AwaitingActThree -> Complete (with extra bytes)
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
