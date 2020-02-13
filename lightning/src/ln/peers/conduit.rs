//! Handles all over the wire message encryption and decryption upon handshake completion.

use ln::peers::{chacha, hkdf};
use util::byte_utils;

/// Returned after a successful handshake to encrypt and decrypt communication with peer nodes.
/// It should not normally be manually instantiated.
/// Automatically handles key rotation.
/// For decryption, it is recommended to call `decrypt_message_stream` for automatic buffering.
pub struct Conduit {
	pub(crate) sending_key: [u8; 32],
	pub(crate) receiving_key: [u8; 32],

	pub(crate) sending_chaining_key: [u8; 32],
	pub(crate) receiving_chaining_key: [u8; 32],

	pub(crate) receiving_nonce: u32,
	pub(crate) sending_nonce: u32,

	pub(super) read_buffer: Option<Vec<u8>>,
}

impl Conduit {
	/// Encrypt data to be sent to peer
	pub fn encrypt(&mut self, buffer: &[u8]) -> Vec<u8> {
		let length = buffer.len() as u16;
		let length_bytes = byte_utils::be16_to_array(length);

		let mut ciphertext = vec![0u8; 18 + length as usize + 16];

		ciphertext[0..18].copy_from_slice(&chacha::encrypt(&self.sending_key, self.sending_nonce as u64, &[0; 0], &length_bytes));
		self.increment_sending_nonce();

		ciphertext[18..].copy_from_slice(&chacha::encrypt(&self.sending_key, self.sending_nonce as u64, &[0; 0], buffer));
		self.increment_sending_nonce();

		ciphertext
	}

	pub(super) fn read(&mut self, data: &[u8]) {
		let mut read_buffer = self.read_buffer.get_or_insert(Vec::new());
		read_buffer.extend_from_slice(data);
	}

	/// Add newly received data from the peer node to the buffer and decrypt all possible messages
	pub fn decrypt_message_stream(&mut self, new_data: Option<&[u8]>) -> Vec<Vec<u8>> {
		let mut read_buffer = if let Some(buffer) = self.read_buffer.take() {
			buffer
		} else {
			Vec::new()
		};

		if let Some(data) = new_data {
			read_buffer.extend_from_slice(data);
		}

		let mut messages = Vec::new();

		loop {
			// todo: find way that won't require cloning the entire buffer
			let (current_message, offset) = self.decrypt(&read_buffer[..]);
			if offset == 0 {
				break;
			}

			read_buffer.drain(0..offset);

			if let Some(message) = current_message {
				messages.push(message);
			} else {
				break;
			}
		}

		messages
	}

	/// Decrypt a single message. Buffer is an undelimited amount of bytes
	pub(crate) fn decrypt(&mut self, buffer: &[u8]) -> (Option<Vec<u8>>, usize) { // the response slice should have the same lifetime as the argument. It's the slice data is read from
		if buffer.len() < 18 {
			return (None, 0);
		}

		let encrypted_length = &buffer[0..18]; // todo: abort if too short
		let length_vec = chacha::decrypt(&self.receiving_key, self.receiving_nonce as u64, &[0; 0], encrypted_length).unwrap();
		let mut length_bytes = [0u8; 2];
		length_bytes.copy_from_slice(length_vec.as_slice());
		let message_length = byte_utils::slice_to_be16(&length_bytes) as usize;

		let message_end_index = message_length + 18 + 16; // todo: abort if too short
		if buffer.len() < message_end_index {
			return (None, 0);
		}

		let encrypted_message = &buffer[18..message_end_index];

		self.increment_receiving_nonce();

		let message = chacha::decrypt(&self.receiving_key, self.receiving_nonce as u64, &[0; 0], encrypted_message).unwrap();

		self.increment_receiving_nonce();

		(Some(message), message_end_index)
	}

	fn increment_sending_nonce(&mut self) {
		Self::increment_nonce(&mut self.sending_nonce, &mut self.sending_chaining_key, &mut self.sending_key);
	}

	fn increment_receiving_nonce(&mut self) {
		Self::increment_nonce(&mut self.receiving_nonce, &mut self.receiving_chaining_key, &mut self.receiving_key);
	}

	fn increment_nonce(nonce: &mut u32, chaining_key: &mut [u8; 32], key: &mut [u8; 32]) {
		*nonce += 1;
		if *nonce == 1000 {
			Self::rotate_key(chaining_key, key);
			*nonce = 0;
		}
	}

	fn rotate_key(chaining_key: &mut [u8; 32], key: &mut [u8; 32]) {
		let (new_chaining_key, new_key) = hkdf::derive(chaining_key, key);
		chaining_key.copy_from_slice(&new_chaining_key);
		key.copy_from_slice(&new_key);
	}
}

#[cfg(test)]
mod tests {
	use hex;
	use ln::peers::conduit::Conduit;

	#[test]
	fn test_chaining() {
		let chaining_key_vec = hex::decode("919219dbb2920afa8db80f9a51787a840bcf111ed8d588caf9ab4be716e42b01").unwrap();
		let mut chaining_key = [0u8; 32];
		chaining_key.copy_from_slice(&chaining_key_vec);

		let sending_key_vec = hex::decode("969ab31b4d288cedf6218839b27a3e2140827047f2c0f01bf5c04435d43511a9").unwrap();
		let mut sending_key = [0u8; 32];
		sending_key.copy_from_slice(&sending_key_vec);

		let receiving_key_vec = hex::decode("bb9020b8965f4df047e07f955f3c4b88418984aadc5cdb35096b9ea8fa5c3442").unwrap();
		let mut receiving_key = [0u8; 32];
		receiving_key.copy_from_slice(&receiving_key_vec);

		let mut connected_peer = Conduit {
			sending_key,
			receiving_key,
			sending_chaining_key: chaining_key,
			receiving_chaining_key: chaining_key,
			sending_nonce: 0,
			receiving_nonce: 0,
			read_buffer: None,
		};

		let mut remote_peer = Conduit {
			sending_key: receiving_key,
			receiving_key: sending_key,
			sending_chaining_key: chaining_key,
			receiving_chaining_key: chaining_key,
			sending_nonce: 0,
			receiving_nonce: 0,
			read_buffer: None,
		};

		let message = hex::decode("68656c6c6f").unwrap();
		let mut encrypted_messages: Vec<Vec<u8>> = Vec::new();

		for _ in 0..1002 {
			let encrypted_message = connected_peer.encrypt(&message);
			encrypted_messages.push(encrypted_message);
		}

		assert_eq!(encrypted_messages[0], hex::decode("cf2b30ddf0cf3f80e7c35a6e6730b59fe802473180f396d88a8fb0db8cbcf25d2f214cf9ea1d95").unwrap());
		assert_eq!(encrypted_messages[1], hex::decode("72887022101f0b6753e0c7de21657d35a4cb2a1f5cde2650528bbc8f837d0f0d7ad833b1a256a1").unwrap());
		assert_eq!(encrypted_messages[500], hex::decode("178cb9d7387190fa34db9c2d50027d21793c9bc2d40b1e14dcf30ebeeeb220f48364f7a4c68bf8").unwrap());
		assert_eq!(encrypted_messages[501], hex::decode("1b186c57d44eb6de4c057c49940d79bb838a145cb528d6e8fd26dbe50a60ca2c104b56b60e45bd").unwrap());
		assert_eq!(encrypted_messages[1000], hex::decode("4a2f3cc3b5e78ddb83dcb426d9863d9d9a723b0337c89dd0b005d89f8d3c05c52b76b29b740f09").unwrap());
		assert_eq!(encrypted_messages[1001], hex::decode("2ecd8c8a5629d0d02ab457a0fdd0f7b90a192cd46be5ecb6ca570bfc5e268338b1a16cf4ef2d36").unwrap());

		for _ in 0..1002 {
			let encrypted_message = encrypted_messages.remove(0);
			let mut decrypted_messages = remote_peer.decrypt_message_stream(Some(&encrypted_message));
			assert_eq!(decrypted_messages.len(), 1);
			let decrypted_message = decrypted_messages.remove(0);
			assert_eq!(decrypted_message, hex::decode("68656c6c6f").unwrap());
		}
	}
}