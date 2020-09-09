// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

use std::cmp;
use std::{error, fmt};

use bitcoin::secp256k1;

use bitcoin::secp256k1::key::{PublicKey,SecretKey};
use lightning::ln::peers::handshake::{CompletedHandshakeInfo, PeerHandshake};
use lightning::ln::peers::transport::IPeerHandshake;
use utils::test_logger;

// Test structure used to generate "random" values based on input data. It is used throughout
// the various test cases to send random messages between nodes and to ensure the code does not fail
// unexpectedly.
pub struct FuzzGen<'a> {
	read_pos: usize,
	data: &'a [u8],
}

impl<'a> FuzzGen<'a> {
	fn new(data: &'a [u8]) -> Self {
		Self {
			read_pos: 0,
			data
		}
	}

	fn generate_bytes(&mut self,  num: usize) -> Result<&'a [u8], GeneratorFinishedError> {
		if self.data.len() < self.read_pos + num {
			return Err(GeneratorFinishedError { });
		}

		self.read_pos += num;
		Ok(&self.data[self.read_pos - num..self.read_pos])
	}

	fn generate_secret_key(&mut self) -> Result<SecretKey, GeneratorFinishedError> {
		// Loop through the input 32 bytes at a time until a valid
		// secret key can be created or we run out of bytes
		loop {
			match SecretKey::from_slice(self.generate_bytes(32)?) {
				Ok(key) => { return Ok(key) },
				_ => { }
			}
		}
	}

	fn generate_bool(&mut self) -> Result<bool, GeneratorFinishedError> {
		let next_byte = self.generate_bytes(1)?;
		Ok(next_byte[0] & 1 == 1)
	}
}

#[derive(PartialEq)]
struct GeneratorFinishedError { }

impl fmt::Debug for GeneratorFinishedError {
	fn fmt(&self, formatter: &mut fmt::Formatter) -> Result<(), fmt::Error> {
		formatter.write_str("Generator out of bytes")
	}
}
impl fmt::Display for GeneratorFinishedError {
	fn fmt(&self, formatter: &mut fmt::Formatter) -> Result<(), fmt::Error> {
		formatter.write_str("Generator out of bytes")
	}
}
impl error::Error for GeneratorFinishedError {
	fn description(&self) -> &str { "Generator out of bytes" }
}

struct TestCtx {
	initiator_static_public_key: PublicKey,
	initiator_handshake: PeerHandshake,
	responder_static_public_key: PublicKey,
	responder_handshake: PeerHandshake,
	act1: Vec<u8>
}

impl TestCtx {
	// At the completion of this call each handshake has the following state:
	// initiator_handshake: HandshakeState::InitiatorStarting
	// responder_handshake: HandshakeState::ResponderAwaitingActOne
	fn make(generator: &mut FuzzGen) -> Result<Self, GeneratorFinishedError> {
		let curve = secp256k1::Secp256k1::new();

		// Generate needed keys for successful handshake
		let initiator_static_private_key = generator.generate_secret_key()?;
		let initiator_static_public_key = PublicKey::from_secret_key(&curve, &initiator_static_private_key);
		let initiator_ephemeral_private_key = generator.generate_secret_key()?;
		let responder_static_private_key = generator.generate_secret_key()?;
		let responder_static_public_key = PublicKey::from_secret_key(&curve, &responder_static_private_key);
		let responder_ephemeral_private_key = generator.generate_secret_key()?;

		let mut initiator_handshake = PeerHandshake::new_outbound(&initiator_static_private_key, &responder_static_public_key, &initiator_ephemeral_private_key);
		let act1 = initiator_handshake.set_up_outbound();

		// Sanity checks around initialization to catch errors before we get to the fuzzing

		// act 1 is the correct size
		assert_eq!(act1.len(), 50);

		// act 1 has the correct version
		assert_eq!(act1[0], 0);
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

// Common test function that sends encrypted messages between an encryptor/decryptor until the
// source data runs out.
#[inline]
fn do_encrypted_communication_tests(generator: &mut FuzzGen,
                                    initiator_completed_handshake_info: &mut CompletedHandshakeInfo,
                                    responder_completed_handshake_info: &mut CompletedHandshakeInfo,
                                    failures_expected: bool) -> Result<(), GeneratorFinishedError> {
	// Keep sending messages back and forth until the input data is consumed
	loop {
		// Randomly generate message length
		let msg_len_raw = generator.generate_bytes(1)?;
		let msg_len = msg_len_raw[0] as usize;

		// Randomly generate message
		let sender_unencrypted_msg = generator.generate_bytes(msg_len)?;

		// randomly choose sender of message
		let receiver_unencrypted_msg = if generator.generate_bool()? {
			let encrypted_msg = initiator_completed_handshake_info.encryptor.encrypt(sender_unencrypted_msg);
			if let Ok(_) = responder_completed_handshake_info.decryptor.read(&encrypted_msg) {
				if let Some(msg) = responder_completed_handshake_info.decryptor.next() {
					msg
				} else {
					assert!(failures_expected);
					return Ok(());
				}
			} else {
				assert!(failures_expected);
				return Ok(());
			}
		} else {
			let encrypted_msg = responder_completed_handshake_info.encryptor.encrypt(sender_unencrypted_msg);
			if let Ok(_) = initiator_completed_handshake_info.decryptor.read(&encrypted_msg) {
				if let Some(msg) = initiator_completed_handshake_info.decryptor.next() {
					msg
				} else {
					assert!(failures_expected);
					return Ok(());
				}
			} else {
				assert!(failures_expected);
				return Ok(());
			}
		};

		assert_eq!(sender_unencrypted_msg, receiver_unencrypted_msg.as_slice());
	}
}

// This test completes a valid handshake based on fuzzer-provided private keys and then sends
// variable length encrypted messages between two encryptor/decryptor to verify they can communicate.
#[inline]
fn do_completed_handshake_test(generator: &mut FuzzGen) -> Result<(), GeneratorFinishedError> {
	let mut test_ctx = TestCtx::make(generator)?;

	// The handshake should complete with any valid private keys
	let act2 = test_ctx.responder_handshake.process_act(&test_ctx.act1).unwrap().0.unwrap();
	let (act3, mut initiator_completed_handshake_info) = match test_ctx.initiator_handshake.process_act(&act2) {
		Ok((Some(act3), Some(completed_handshake_info))) => {
			(act3, completed_handshake_info)
		}
		_ => panic!("handshake failed")
	};

	let mut responder_completed_handshake_info = match test_ctx.responder_handshake.process_act(&act3) {
		Ok((None, Some(completed_handshake_info))) => {
			completed_handshake_info
		}
		_ => panic!("handshake failed")
	};

	// The handshake should complete with each peer knowing the static_public_key of the remote peer
	assert_eq!(responder_completed_handshake_info.their_node_id, test_ctx.initiator_static_public_key);
	assert_eq!(initiator_completed_handshake_info.their_node_id, test_ctx.responder_static_public_key);

	// The nodes should be able to communicate with the Encryptor/Decryptors
	do_encrypted_communication_tests(generator, &mut initiator_completed_handshake_info, &mut responder_completed_handshake_info, false)
}

// Either returns (act, false) or (random_bytes, true) where random_bytes is the same len as act
fn maybe_generate_bad_act(generator: &mut FuzzGen, act: Vec<u8>) -> Result<(Vec<u8>, bool), GeneratorFinishedError> {
	if generator.generate_bool()? {
		Ok(((generator.generate_bytes(act.len())?).to_vec(), true))
	} else {
		Ok((act, false))
	}
}

// Add between 0..15 bytes of garbage to a vec and returns whether or not it added bytes
fn maybe_add_garbage(generator: &mut FuzzGen, input: &mut Vec<u8>) -> Result<bool, GeneratorFinishedError> {
	let garbage_amount = (generator.generate_bytes(1)?)[0] >> 4;

	if garbage_amount != 0 {
		input.extend(generator.generate_bytes(garbage_amount as usize)?);
		Ok(true)
	} else {
		Ok(false)
	}
}

// Splits a Vec into between 1..7 chunks returning a Vec of slices into the original data
fn split_vec<'a>(generator: &mut FuzzGen, input: &'a Vec<u8>) -> Result<Vec<&'a [u8]>, GeneratorFinishedError> {
	let num_chunks = cmp::max(1, ((generator.generate_bytes(1)?)[0] as u8) >> 5) as usize;
	let chunk_size = input.len() / num_chunks;

	Ok(input.chunks(chunk_size).collect())
}

// This test variant goes through the peer handshake between the initiator and responder with
// "random" failures to verify that nothing panics.
// In the event of an error from process_act() we validate that the input data was generated
// randomly to ensure real act generation still produces valid transitions.
#[inline]
fn do_handshake_test(generator: &mut FuzzGen) -> Result<(), GeneratorFinishedError> {
	let mut test_ctx = TestCtx::make(generator)?;

	// Possibly generate bad data for act1
	let (mut act1, mut used_generated_data) = maybe_generate_bad_act(generator, test_ctx.act1)?;

	// Optionally, add garbage data to the end
	used_generated_data |= maybe_add_garbage(generator, &mut act1)?;

	// Split act1 into between 1..7 chunks
	let act1_chunks = split_vec(generator, &act1)?;

	let mut act2_option = None;
	for partial_act1 in act1_chunks {
		match test_ctx.responder_handshake.process_act(&partial_act1) {
			// Save valid act2 for initiator
			Ok((Some(act2_option_inner), None)) => {
				act2_option = Some(act2_option_inner);
			},
			// Partial act
			Ok((None, None)) => { }
			// errors are fine as long as they happened due to using bad data
			Err(_) => {
				assert!(used_generated_data);
				return Ok(());
			}
			_ => panic!("responder required to output act bytes and no completed_handshake_info")
		};
	}
	let act2 = act2_option.unwrap();

	// Possibly generate bad data for act2
	let (mut act2, is_bad_data) = maybe_generate_bad_act(generator, act2)?;

	// Optionally, add garbage data to the end
	let did_add_garbage = maybe_add_garbage(generator, &mut act2)?;

	// Keep track of whether or not we have generated bad data up to this point
	used_generated_data |= is_bad_data | did_add_garbage;

	// Split act2 into between 1..7 chunks
	let act2_chunks = split_vec(generator, &act2)?;

	let mut act3_option = None;
	let mut initiator_completed_handshake_info_option = None;
	for partial_act2 in act2_chunks {
		match test_ctx.initiator_handshake.process_act(&partial_act2) {
			Ok((Some(act3), Some(completed_handshake_info_option_inner))) => {
				act3_option = Some(act3);
				initiator_completed_handshake_info_option = Some(completed_handshake_info_option_inner);

				// Valid completed_handshake_info indicates handshake is over
				break;
			}
			// Partial act
			Ok((None, None)) => { },
			// errors are fine as long as they happened due to using bad data
			Err(_) => {
				assert!(used_generated_data);
				return Ok(());
			}
			_ => panic!("initiator required to output act bytes and completed_handshake_info")
		};
	}

	// Ensure we actually received act3 bytes, completed_handshake_info from process_act()
	let act3 = act3_option.unwrap();
	let mut initiator_completed_handshake_info = initiator_completed_handshake_info_option.unwrap();

	// Possibly generate bad data for act3
	let (mut act3, is_bad_data) = maybe_generate_bad_act(generator, act3)?;

	// Optionally, add garbage data to the end
	let did_add_garbage = maybe_add_garbage(generator, &mut act3)?;

	// Keep track of whether or not we have generated bad data up to this point
	used_generated_data |= is_bad_data | did_add_garbage;

	// Split act3 into between 1..7 chunks
	let act3_chunks = split_vec(generator, &act3)?;

	let mut responder_completed_handshake_info = None;
	for partial_act3 in act3_chunks {
		match test_ctx.responder_handshake.process_act(&partial_act3) {
			Ok((None, Some(completed_handshake_info_inner))) => {
				responder_completed_handshake_info = Some(completed_handshake_info_inner);

				// Valid completed_handshake_info indicates handshake is over
				break;
			},
			// partial act
			Ok((None, None)) => { },
			// errors are fine as long as they happened due to using bad data
			Err(_) => {
				assert!(used_generated_data);
				return Ok(());
			},
			_ => panic!("responder required to output completed_handshake_info")
		};
	}
	// Ensure we actually received completed_handshake_info from process_act()
	let mut responder_completed_handshake_info = responder_completed_handshake_info.unwrap();

	// The handshake should complete with each peer knowing the static_public_key of the remote peer
	if responder_completed_handshake_info.their_node_id != test_ctx.initiator_static_public_key {
		assert!(used_generated_data);
		return Ok(());
	}
	if initiator_completed_handshake_info.their_node_id != test_ctx.responder_static_public_key {
		assert!(used_generated_data);
		return Ok(());
	}

	// The nodes should be able to communicate over the encryptor/decryptor
	do_encrypted_communication_tests(generator, &mut initiator_completed_handshake_info, &mut responder_completed_handshake_info, used_generated_data)
}

#[inline]
fn do_test(data: &[u8]) {
	let mut generator = FuzzGen::new(data);

	// Based on a "random" bool, decide which test variant to run
	let do_valid_handshake = match generator.generate_bool() {
		Ok(value) => { value },
		_ => { return }
	};

	// The only valid error that can leak here is the FuzzGen error to indicate
	// the input bytes have been exhausted and the test can't proceed. Everything
	// else should be caught and handled by the individual tests to validate any
	// errors.
	if do_valid_handshake {
		match do_completed_handshake_test(&mut generator) {
			Err(_) => { }
			_ => { }
		}
	} else {
		match do_handshake_test(&mut generator) {
			Err(_) => { }
			_ => { }
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
		assert_eq!(generator.generate_bool(), Err(GeneratorFinishedError { }));
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
		assert_eq!(generator.generate_bool(), Err(GeneratorFinishedError { }));
	}

	#[test]
	fn data_generator_bytes_too_many() {
		let mut generator = FuzzGen::new(&[1, 2, 3, 4]);
		assert_eq!(generator.generate_bytes(5), Err(GeneratorFinishedError { }));
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
		assert_eq!(generator.generate_bytes(1), Err(GeneratorFinishedError { }));
	}

	#[test]
	fn maybe_generate_bad_act_gen_bad() {
		// 1 is used to take bad branch and 2 is used to generate bad act
		let input = [1, 2];
		let mut generator = FuzzGen::new(&input);

		let original_act = &[5];

		let (act, is_bad) = maybe_generate_bad_act(&mut generator, original_act.to_vec()).unwrap();
		assert!(is_bad);
		assert_eq!(act, &[2]);
	}

	#[test]
	fn maybe_generate_bad_act_gen_good() {
		// 0 is used to take good branch
		let input = [0];
		let mut generator = FuzzGen::new(&input);
		let original_act = &[5];

		let (act, is_bad) = maybe_generate_bad_act(&mut generator, original_act.to_vec()).unwrap();
		assert!(!is_bad);
		assert_eq!(act, &[5]);
	}

	#[test]
	fn maybe_add_garbage_did_add() {
		// 0x10 consumed to specify amount of garbage (1 byte) and 2 is consumed to add garbage
		let input = [0x10, 2];
		let mut generator = FuzzGen::new(&input);
		let mut act = vec![5];

		let did_add_garbage = maybe_add_garbage(&mut generator, &mut act).unwrap();
		assert!(did_add_garbage);
		assert_eq!(act, &[5, 2]);
	}

	#[test]
	fn maybe_add_garbage_no_add() {
		// 0x10 consumed to specify amount of garbage (1 byte) and 2 is consumed to add garbage
		let input = [0];
		let mut generator = FuzzGen::new(&input);
		let mut act = vec![5];

		let did_add_garbage = maybe_add_garbage(&mut generator, &mut act).unwrap();
		assert!(!did_add_garbage);
		assert_eq!(act, &[5]);
	}

	#[test]
	fn split_vec_1_chunk() {
		// 0 consumed for number of chunks (1 is min)
		let input = [0];
		let mut generator = FuzzGen::new(&input);
		let act = vec![5, 6];

		let act_parts = split_vec(&mut generator, &act).unwrap();
		assert_eq!(act_parts.len(), 1);
		assert_eq!(act_parts[0], &[5, 6]);
	}

	#[test]
	fn split_vec_2_chunks() {
		// 40 consumed for number of chunks. Chunk size is equal to the high three bits (2)
		let input = [0x40];
		let mut generator = FuzzGen::new(&input);
		let act = vec![5, 6];

		let act_parts = split_vec(&mut generator, &act).unwrap();
		assert_eq!(act_parts.len(), 2);
		assert_eq!(act_parts[0], &[5]);
		assert_eq!(act_parts[1], &[6]);
	}
	#[test]
	fn split_vec_2_chunks_odd() {
		// 40 consumed for number of chunks. Chunk size is equal to the high three bits (2)
		let input = [0x40];
		let mut generator = FuzzGen::new(&input);
		let act = vec![5, 6, 7, 8, 9];

		let act_parts = split_vec(&mut generator, &act).unwrap();
		assert_eq!(act_parts.len(), 3);
		assert_eq!(act_parts[0], &[5, 6]);
		assert_eq!(act_parts[1], &[7, 8]);
		assert_eq!(act_parts[2], &[9]);
	}
}