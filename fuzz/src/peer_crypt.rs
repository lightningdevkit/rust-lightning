// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

use bitcoin::secp256k1;

use bitcoin::secp256k1::key::{PublicKey,SecretKey};
use lightning::ln::peers::conduit::Conduit;
use lightning::ln::peers::handshake::PeerHandshake;
use utils::test_logger;

// Test structure used to generate "random" values based on input data. It is used throughout
// the various test cases to send random messages between nodes and to ensure the code does not fail
// unexpectedly.
pub struct FuzzGen<'a> {
	read_pos: usize,
	data: &'a [u8],
}

impl<'a> FuzzGen<'a> {
	pub fn new(data: &'a [u8]) -> Self {
		Self {
			read_pos: 0,
			data
		}
	}

	pub fn generate_bytes(&mut self,  num: usize) -> Result<&'a [u8], String> {
		if self.data.len() < self.read_pos + num {
			return Err("out of bytes".to_string());
		}

		self.read_pos += num;
		Ok(&self.data[self.read_pos - num..self.read_pos])
	}

	pub fn generate_secret_key(&mut self) -> Result<SecretKey, String> {
		// Loop through the input 32 bytes at a time until a valid
		// secret key can be created or we run out of bytes
		loop {
			match SecretKey::from_slice(self.generate_bytes(32)?) {
				Ok(key) => { return Ok(key) },
				_ => {}
			}
		}
	}

	pub fn generate_bool(&mut self) -> Result<bool, String> {
		let next_byte = self.generate_bytes(1)?;
		Ok(next_byte[0] & 1 == 1)
	}
}

struct TestCtx {
	initiator_static_public_key: PublicKey,
	initiator_handshake: PeerHandshake,
	responder_static_public_key: PublicKey,
	responder_handshake: PeerHandshake,
	act1: Vec<u8>
}

impl TestCtx {
	fn make(generator: &mut FuzzGen) -> Result<Self, String> {
		let curve = secp256k1::Secp256k1::new();

		// Generate needed keys for successful handshake
		let initiator_static_private_key = generator.generate_secret_key()?;
		let initiator_static_public_key = PublicKey::from_secret_key(&curve, &initiator_static_private_key);
		let initiator_ephemeral_private_key = generator.generate_secret_key()?;
		let responder_static_private_key = generator.generate_secret_key()?;
		let responder_static_public_key = PublicKey::from_secret_key(&curve, &responder_static_private_key);
		let responder_ephemeral_private_key = generator.generate_secret_key()?;

		let (act1, initiator_handshake) = PeerHandshake::create_and_initialize_outbound(&initiator_static_private_key, &responder_static_public_key, &initiator_ephemeral_private_key);
		let responder_handshake = PeerHandshake::new_inbound(&responder_static_private_key, &responder_ephemeral_private_key);

		Ok(TestCtx {
			initiator_static_public_key,
			initiator_handshake,
			responder_static_public_key,
			responder_handshake,
			act1
		})
	}
}

// Common test function that sends encrypted messages between two conduits until the source data
// runs out.
#[inline]
fn do_conduit_tests(generator: &mut FuzzGen, initiator_conduit: &mut Conduit, responder_conduit: &mut Conduit) -> Result<(), String> {
	// Keep sending messages back and forth until the input data is consumed
	loop {
		// Randomly generate message length
		let msg_len_raw = generator.generate_bytes(1)?;
		let msg_len = msg_len_raw[0] as usize;

		// Randomly generate message
		let sender_unencrypted_msg = generator.generate_bytes(msg_len)?;

		// randomly choose sender of message
		let receiver_unencrypted_msg = if generator.generate_bool()? {
			let encrypted_msg = initiator_conduit.encrypt(sender_unencrypted_msg);
			responder_conduit.decrypt_single_message(Some(&encrypted_msg))
		} else {
			let encrypted_msg = responder_conduit.encrypt(sender_unencrypted_msg);
			initiator_conduit.decrypt_single_message(Some(&encrypted_msg))
		};

		assert_eq!(sender_unencrypted_msg, receiver_unencrypted_msg.unwrap().unwrap().as_slice());
	}
}

// This test completes a valid handshake based on "random" private keys and then sends variable
// length encrypted messages between two conduits to validate that they can communicate.
#[inline]
fn do_completed_handshake_test(generator: &mut FuzzGen) -> Result<(), String> {
	let mut test_ctx = TestCtx::make(generator)?;

	// The handshake should complete with any valid private keys
	let act2 = test_ctx.responder_handshake.process_act(&test_ctx.act1).unwrap().0.unwrap();
	let (act3, (mut initiator_conduit, responder_pubkey)) = match test_ctx.initiator_handshake.process_act(&act2) {
		Ok((Some(act3), Some((conduit, remote_pubkey)))) => {
			(act3, (conduit, remote_pubkey))
		}
		_ => panic!("handshake failed")
	};

	let (mut responder_conduit, initiator_pubkey) = match test_ctx.responder_handshake.process_act(&act3) {
		Ok((None, Some((conduit, remote_pubkey)))) => {
			(conduit, remote_pubkey)
		}
		_ => panic!("handshake failed")
	};

	// The handshake should complete with each peer knowing the static_public_key of the remote peer
	assert_eq!(initiator_pubkey, test_ctx.initiator_static_public_key);
	assert_eq!(responder_pubkey, test_ctx.responder_static_public_key);

	// The nodes should be able to communicate over the conduit
	do_conduit_tests(generator, &mut initiator_conduit, &mut responder_conduit)?;

	unreachable!();
}

// This test variant goes through the peer handshake between the initiator and responder with
// "random" failures to verify that nothing panics.
// In the event of an error from process_act() we validate that the input data was generated
// randomly to ensure real act generation still produces valid transitions.
#[inline]
fn do_handshake_test(generator: &mut FuzzGen) -> Result<(), String> {
	let mut test_ctx = TestCtx::make(generator)?;
	let mut used_generated_data = false;

	// Possibly generate bad data for act1 and ensure that the responder does not panic
	let mut act1 = test_ctx.act1;
	if generator.generate_bool()? {
		act1 = (generator.generate_bytes(50)?).to_vec();
		used_generated_data = true;
	}

	let mut act2 = match test_ctx.responder_handshake.process_act(&act1) {
		Ok((Some(act2), None)) => {
			act2
		}
		Err(_) => {
			assert!(used_generated_data);
			return Err("generated expected failure with bad data".to_string());
		}
		_ => panic!("responder required to output act bytes and no conduit/pubkey")
	};

	// Possibly generate bad data for act2 and ensure that the initiator does not panic
	if generator.generate_bool()? {
		act2 = (generator.generate_bytes(50)?).to_vec();
		used_generated_data = true;
	}

	let (mut act3, (mut initiator_conduit, responder_pubkey)) = match test_ctx.initiator_handshake.process_act(&act2) {
		Ok((Some(act3), Some((conduit, remote_pubkey)))) => {
			(act3, (conduit, remote_pubkey))
		}
		Err(_) => {
			assert!(used_generated_data);
			return Err("generated expected failure with bad data".to_string());
		}
		_ => panic!("initiator required to output act bytes and no conduit/pubkey")
	};

	// Possibly generate bad data for act3 and ensure that the responder does not panic
	if generator.generate_bool()? {
		act3 = (generator.generate_bytes(66)?).to_vec();
		used_generated_data = true;
	}

	let (mut responder_conduit, initiator_pubkey) = match test_ctx.responder_handshake.process_act(&act3) {
		Ok((None, Some((conduit, remote_pubkey)))) => {
			(conduit, remote_pubkey)
		}
		Err(_) => {
			// extremely unlikely we randomly generate a correct act3, but if so.. reset this
			assert!(used_generated_data);
			return Err("generated expected failure with bad data".to_string());
		},
		_ => panic!("responder required to output conduit/remote pubkey and no act bytes")
	};

	// The handshake should complete with each peer knowing the static_public_key of the remote peer
	if initiator_pubkey != test_ctx.initiator_static_public_key {
		assert!(used_generated_data);
		return Ok(());
	}
	if responder_pubkey != test_ctx.responder_static_public_key {
		assert!(used_generated_data);
		return Ok(());
	}

	// The nodes should be able to communicate over the conduit
	do_conduit_tests(generator, &mut initiator_conduit, &mut responder_conduit)?;

	unreachable!();
}

#[inline]
fn do_test(data: &[u8]) {
	let mut generator = FuzzGen::new(data);

	// Based on a "random" bool, decide which test variant to run
	let do_valid_handshake = match generator.generate_bool() {
		Ok(value) => { value },
		_ => { return }
	};

	if do_valid_handshake {
		match do_completed_handshake_test(&mut generator) {
			_ => {}
		}
	} else {
		match do_handshake_test(&mut generator) {
			_ => {}
		}
	}
}

pub fn peer_crypt_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}

#[no_mangle]
pub extern "C" fn peer_crypt_run(data: *const u8, datalen: usize) {
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) });
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn data_generator_empty() {
		let mut generator = FuzzGen::new(&[]);
		assert_eq!(generator.generate_bool().err(), Some("out of bytes".to_string()));
	}

	#[test]
	fn data_generator_bool_true() {
		let mut generator = FuzzGen::new(&[1]);
		assert!(generator.generate_bool().unwrap());
	}

	#[test]
	fn data_generator_bool_false() {
		let mut generator = FuzzGen::new(&[0]);
		assert!(!generator.generate_bool().unwrap());
	}

	#[test]
	fn data_generator_bool_then_error() {
		let mut generator = FuzzGen::new(&[1]);
		assert!(generator.generate_bool().unwrap());
		assert_eq!(generator.generate_bool().err(), Some("out of bytes".to_string()));
	}

	#[test]
	fn data_generator_bytes_too_many() {
		let mut generator = FuzzGen::new(&[1, 2, 3, 4]);
		assert_eq!(generator.generate_bytes(5).err(), Some("out of bytes".to_string()));
	}

	#[test]
	fn data_generator_bytes() {
		let input = [1, 2, 3, 4];
		let mut generator = FuzzGen::new(&input);
		let result = generator.generate_bytes(4).unwrap();
		assert_eq!(result, input);
	}

	#[test]
	fn data_generator_bytes_sequential() {
		let input = [1, 2, 3, 4];
		let mut generator = FuzzGen::new(&input);
		let result = generator.generate_bytes(2).unwrap();
		assert_eq!(result, &input[..2]);
		let result = generator.generate_bytes(2).unwrap();
		assert_eq!(result, &input[2..]);
		assert_eq!(generator.generate_bytes(1).err(), Some("out of bytes".to_string()));
	}
}