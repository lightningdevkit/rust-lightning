//! Execute handshakes for peer-to-peer connection establishment.
//! Handshake states can be advanced automatically, or by manually calling the appropriate step.
//! Once complete, returns an instance of Conduit.

use bitcoin::secp256k1::{PublicKey, SecretKey};

use ln::peers::conduit::Conduit;
use ln::peers::handshake::states::{HandshakeState, IHandshakeState};

mod states;

/// Object for managing handshakes.
/// Currently requires explicit ephemeral private key specification.
pub struct PeerHandshake {
	state: Option<HandshakeState>,
}

impl PeerHandshake {
	/// Instantiate a new handshake with a node identity secret key and an ephemeral private key
	pub fn new_outbound(initiator_static_private_key: &SecretKey, responder_static_public_key: &PublicKey, initiator_ephemeral_private_key: &SecretKey) -> Self {
		Self {
			state: Some(HandshakeState::new_initiator(initiator_static_private_key, responder_static_public_key, initiator_ephemeral_private_key))
		}
	}

	/// Instantiate a new handshake in anticipation of a peer's first handshake act
	pub fn new_inbound(responder_static_private_key: &SecretKey, responder_ephemeral_private_key: &SecretKey) -> Self {
		Self {
			state: Some(HandshakeState::new_responder(responder_static_private_key, responder_ephemeral_private_key))
		}
	}

	/// Process act dynamically
	/// # Arguments
	/// `input`: Byte slice received from peer as part of the handshake protocol
	///
	/// # Return values
	/// Returns a tuple with the following components:
	/// `.0`: Byte vector containing the next act to send back to the peer per the handshake protocol
	/// `.1`: Some(Conduit, PublicKey) if the handshake was just processed to completion and messages can now be encrypted and decrypted
	pub fn process_act(&mut self, input: &[u8]) -> Result<(Option<Vec<u8>>, Option<(Conduit, PublicKey)>), String> {
		let cur_state = self.state.take().unwrap();

		let (act_opt, mut next_state) = cur_state.next(input)?;

		let result = match next_state {
			HandshakeState::Complete(ref mut conduit_and_pubkey) => {
				Ok((act_opt, conduit_and_pubkey.take()))
			},
			_ => { Ok((act_opt, None)) }
		};

		self.state = Some(next_state);

		result
	}
}

#[cfg(test)]
mod test {
	use super::*;

	use bitcoin::secp256k1;
	use bitcoin::secp256k1::key::{PublicKey, SecretKey};

	struct TestCtx {
		outbound_handshake: PeerHandshake,
		outbound_static_public_key: PublicKey,
		inbound_handshake: PeerHandshake,
		inbound_static_public_key: PublicKey
	}

	impl TestCtx {
		fn new() -> TestCtx {
			let curve = secp256k1::Secp256k1::new();

			let outbound_static_private_key = SecretKey::from_slice(&[0x_11_u8; 32]).unwrap();
			let outbound_static_public_key = PublicKey::from_secret_key(&curve, &outbound_static_private_key);
			let outbound_ephemeral_private_key = SecretKey::from_slice(&[0x_12_u8; 32]).unwrap();

			let inbound_static_private_key = SecretKey::from_slice(&[0x_21_u8; 32]).unwrap();
			let inbound_static_public_key = PublicKey::from_secret_key(&curve, &inbound_static_private_key);
			let inbound_ephemeral_private_key = SecretKey::from_slice(&[0x_22_u8; 32]).unwrap();

			let outbound_handshake = PeerHandshake::new_outbound(&outbound_static_private_key, &inbound_static_public_key, &outbound_ephemeral_private_key);
			let inbound_handshake = PeerHandshake::new_inbound(&inbound_static_private_key, &inbound_ephemeral_private_key);

			TestCtx {
				outbound_handshake,
				outbound_static_public_key,
				inbound_handshake,
				inbound_static_public_key,
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
			$handshake.process_act($input).unwrap().0.unwrap()
		}
	}

	// Default Outbound::Uninitiated
	#[test]
	fn peer_handshake_new_outbound() {
		let test_ctx = TestCtx::new();

		assert_matches!(test_ctx.outbound_handshake.state, Some(HandshakeState::InitiatorStarting(_)));
	}

	// Default Inbound::AwaitingActOne
	#[test]
	fn peer_handshake_new_inbound() {
		let test_ctx = TestCtx::new();

		assert_matches!(test_ctx.inbound_handshake.state, Some(HandshakeState::ResponderAwaitingActOne(_)));
	}

	/*
	 * PeerHandshake::process_act() tests
	 */

	// Full sequence from initiator and responder as a sanity test. State machine is tested in states.rs
	#[test]
	fn full_sequence_sanity_test() {
		let mut test_ctx = TestCtx::new();
		let act1 = do_process_act_or_panic!(test_ctx.outbound_handshake, &[]);
		let act2 = do_process_act_or_panic!(test_ctx.inbound_handshake, &act1);

		let (act3, inbound_remote_pubkey) = if let (Some(act3), Some((_, remote_pubkey))) = test_ctx.outbound_handshake.process_act(&act2).unwrap() {
			(act3, remote_pubkey)
		} else {
			panic!();
		};

		let outbound_remote_pubkey = if let (None, Some((_, remote_pubkey))) = test_ctx.inbound_handshake.process_act(&act3).unwrap() {
			remote_pubkey
		} else {
			panic!();
		};

		assert_eq!(inbound_remote_pubkey, test_ctx.inbound_static_public_key);
		assert_eq!(outbound_remote_pubkey, test_ctx.outbound_static_public_key);
	}

	// Test that the internal state object matches the return from state_machine.next()
	// This could make use of a mocking library to remove the dependency on the state machine. All
	// that needs to be tested is that the expected state (returned) from state_machine.next() matchse
	// the internal set state.
	#[test]
	fn process_act_properly_updates_state() {
		let mut test_ctx = TestCtx::new();
		do_process_act_or_panic!(test_ctx.outbound_handshake, &[]);
		assert_matches!(test_ctx.outbound_handshake.state, Some(HandshakeState::InitiatorAwaitingActTwo(_)));
	}

	// Test that any errors from the state machine are passed back to the caller
	// This could make use of a mocking library to remove the dependency on the state machine
	// logic. All that needs to be tested is that an error from state_machine.next()
	// results in an error in process_act()
	#[test]
	fn errors_properly_returned() {
		let mut test_ctx = TestCtx::new();
		assert_matches!(test_ctx.inbound_handshake.process_act(&[]).err(), Some(_));
	}

	// Test that any use of the PeerHandshake after returning an error panics
	#[test]
	#[should_panic(expected = "called `Option::unwrap()` on a `None` value")]
	fn use_after_error_panics() {
		let mut test_ctx = TestCtx::new();
		assert_matches!(test_ctx.inbound_handshake.process_act(&[]).err(), Some(_));
		test_ctx.inbound_handshake.process_act(&[]).unwrap();
	}
}
