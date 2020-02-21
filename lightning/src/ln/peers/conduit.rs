//! Handles all over the wire message encryption and decryption upon handshake completion.

use ln::peers::{chacha, hkdf};
use util::byte_utils;

pub(super) type SymmetricKey = [u8; 32];

const MESSAGE_LENGTH_HEADER_SIZE: usize = 2;
const TAGGED_MESSAGE_LENGTH_HEADER_SIZE: usize = MESSAGE_LENGTH_HEADER_SIZE + chacha::TAG_SIZE;

const KEY_ROTATION_INDEX: u32 = 1000;

/// Returned after a successful handshake to encrypt and decrypt communication with peer nodes.
/// It should not normally be manually instantiated.
/// Automatically handles key rotation.
/// For decryption, it is recommended to call `decrypt_message_stream` for automatic buffering.
pub struct Conduit {
	pub(crate) sending_key: SymmetricKey,
	pub(crate) receiving_key: SymmetricKey,

	pub(crate) sending_chaining_key: SymmetricKey,
	pub(crate) receiving_chaining_key: SymmetricKey,

	pub(crate) receiving_nonce: u32,
	pub(crate) sending_nonce: u32,

	pub(super) read_buffer: Option<Vec<u8>>,
}

impl Conduit {
	/// Encrypt data to be sent to peer
	pub fn encrypt(&mut self, buffer: &[u8]) -> Vec<u8> {
		let length = buffer.len() as u16;
		let length_bytes = byte_utils::be16_to_array(length);

		let mut ciphertext = vec![0u8; TAGGED_MESSAGE_LENGTH_HEADER_SIZE + length as usize + chacha::TAG_SIZE];

		ciphertext[0..TAGGED_MESSAGE_LENGTH_HEADER_SIZE].copy_from_slice(&chacha::encrypt(&self.sending_key, self.sending_nonce as u64, &[0; 0], &length_bytes));
		self.increment_sending_nonce();

		ciphertext[TAGGED_MESSAGE_LENGTH_HEADER_SIZE..].copy_from_slice(&chacha::encrypt(&self.sending_key, self.sending_nonce as u64, &[0; 0], buffer));
		self.increment_sending_nonce();

		ciphertext
	}

	pub(super) fn read(&mut self, data: &[u8]) {
		let read_buffer = self.read_buffer.get_or_insert(Vec::new());
		read_buffer.extend_from_slice(data);
	}

	/// Decrypt a single message. If data containing more than one message has been received,
	/// only the first message will be returned, and the rest stored in the internal buffer.
	/// If a message pending in the buffer still hasn't been decrypted, that message will be
	/// returned in lieu of anything new, even if new data is provided.
	pub fn decrypt_single_message(&mut self, new_data: Option<&[u8]>) -> Option<Vec<u8>> {
		let mut read_buffer = if let Some(buffer) = self.read_buffer.take() {
			buffer
		} else {
			Vec::new()
		};

		if let Some(data) = new_data {
			read_buffer.extend_from_slice(data);
		}

		let (current_message, offset) = self.decrypt(&read_buffer[..]);
		read_buffer.drain(..offset); // drain the read buffer
		self.read_buffer = Some(read_buffer); // assign the new value to the built-in buffer
		current_message
	}

	/// Decrypt a message from the beginning of the provided buffer. Returns the consumed number of bytes.
	fn decrypt(&mut self, buffer: &[u8]) -> (Option<Vec<u8>>, usize) {
		if buffer.len() < TAGGED_MESSAGE_LENGTH_HEADER_SIZE {
			// A message must be at least 18 bytes (2 for encrypted length, 16 for the tag)
			return (None, 0);
		}

		let encrypted_length = &buffer[0..TAGGED_MESSAGE_LENGTH_HEADER_SIZE];
		let mut length_bytes = [0u8; MESSAGE_LENGTH_HEADER_SIZE];
		length_bytes.copy_from_slice(&chacha::decrypt(&self.receiving_key, self.receiving_nonce as u64, &[0; 0], encrypted_length).unwrap());
		// message_length is the length of the encrypted message excluding its trailing 16-byte tag
		let message_length = byte_utils::slice_to_be16(&length_bytes) as usize;

		let message_end_index = TAGGED_MESSAGE_LENGTH_HEADER_SIZE + message_length + chacha::TAG_SIZE;
		if buffer.len() < message_end_index {
			return (None, 0);
		}

		let encrypted_message = &buffer[TAGGED_MESSAGE_LENGTH_HEADER_SIZE..message_end_index];

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

	fn increment_nonce(nonce: &mut u32, chaining_key: &mut SymmetricKey, key: &mut SymmetricKey) {
		*nonce += 1;
		if *nonce == KEY_ROTATION_INDEX {
			Self::rotate_key(chaining_key, key);
			*nonce = 0;
		}
	}

	fn rotate_key(chaining_key: &mut SymmetricKey, key: &mut SymmetricKey) {
		let (new_chaining_key, new_key) = hkdf::derive(chaining_key, key);
		chaining_key.copy_from_slice(&new_chaining_key);
		key.copy_from_slice(&new_key);
	}
}

#[cfg(test)]
mod tests {
	use hex;
	use ln::peers::conduit::Conduit;

	fn setup_peers() -> (Conduit, Conduit) {
		let chaining_key_vec = hex::decode("919219dbb2920afa8db80f9a51787a840bcf111ed8d588caf9ab4be716e42b01").unwrap();
		let mut chaining_key = [0u8; 32];
		chaining_key.copy_from_slice(&chaining_key_vec);

		let sending_key_vec = hex::decode("969ab31b4d288cedf6218839b27a3e2140827047f2c0f01bf5c04435d43511a9").unwrap();
		let mut sending_key = [0u8; 32];
		sending_key.copy_from_slice(&sending_key_vec);

		let receiving_key_vec = hex::decode("bb9020b8965f4df047e07f955f3c4b88418984aadc5cdb35096b9ea8fa5c3442").unwrap();
		let mut receiving_key = [0u8; 32];
		receiving_key.copy_from_slice(&receiving_key_vec);

		let connected_peer = Conduit {
			sending_key,
			receiving_key,
			sending_chaining_key: chaining_key,
			receiving_chaining_key: chaining_key,
			sending_nonce: 0,
			receiving_nonce: 0,
			read_buffer: None,
		};

		let remote_peer = Conduit {
			sending_key: receiving_key,
			receiving_key: sending_key,
			sending_chaining_key: chaining_key,
			receiving_chaining_key: chaining_key,
			sending_nonce: 0,
			receiving_nonce: 0,
			read_buffer: None,
		};

		(connected_peer, remote_peer)
	}

	#[test]
	fn test_empty_message() {
		let (mut connected_peer, mut remote_peer) = setup_peers();

		let message: Vec<u8> = vec![];
		let encrypted_message = connected_peer.encrypt(&message);
		assert_eq!(encrypted_message.len(), 2 + 16 + 16);

		let decrypted_message = remote_peer.decrypt_single_message(Some(&encrypted_message)).unwrap();
		assert_eq!(decrypted_message, vec![]);
	}

	#[test]
	fn test_nonce_chaining() {
		let (mut connected_peer, mut remote_peer) = setup_peers();
		let message = hex::decode("68656c6c6f").unwrap();

		let encrypted_message = connected_peer.encrypt(&message);
		assert_eq!(encrypted_message, hex::decode("cf2b30ddf0cf3f80e7c35a6e6730b59fe802473180f396d88a8fb0db8cbcf25d2f214cf9ea1d95").unwrap());

		// the second time the same message is encrypted, the ciphertext should be different
		let encrypted_message = connected_peer.encrypt(&message);
		assert_eq!(encrypted_message, hex::decode("72887022101f0b6753e0c7de21657d35a4cb2a1f5cde2650528bbc8f837d0f0d7ad833b1a256a1").unwrap());
	}

	#[test]
	/// Based on RFC test vectors: https://github.com/lightningnetwork/lightning-rfc/blob/master/08-transport.md#message-encryption-tests
	fn test_key_rotation() {
		let (mut connected_peer, mut remote_peer) = setup_peers();

		let message = hex::decode("68656c6c6f").unwrap();
		let mut encrypted_messages: Vec<Vec<u8>> = Vec::new();

		for _ in 0..1002 {
			let encrypted_message = connected_peer.encrypt(&message);
			encrypted_messages.push(encrypted_message);
		}

		assert_eq!(encrypted_messages[500], hex::decode("178cb9d7387190fa34db9c2d50027d21793c9bc2d40b1e14dcf30ebeeeb220f48364f7a4c68bf8").unwrap());
		assert_eq!(encrypted_messages[501], hex::decode("1b186c57d44eb6de4c057c49940d79bb838a145cb528d6e8fd26dbe50a60ca2c104b56b60e45bd").unwrap());
		assert_eq!(encrypted_messages[1000], hex::decode("4a2f3cc3b5e78ddb83dcb426d9863d9d9a723b0337c89dd0b005d89f8d3c05c52b76b29b740f09").unwrap());
		assert_eq!(encrypted_messages[1001], hex::decode("2ecd8c8a5629d0d02ab457a0fdd0f7b90a192cd46be5ecb6ca570bfc5e268338b1a16cf4ef2d36").unwrap());
	}

	#[test]
	fn test_decryption_buffering() {
		let (mut connected_peer, mut remote_peer) = setup_peers();

		let message = hex::decode("68656c6c6f").unwrap();
		let mut encrypted_messages: Vec<Vec<u8>> = Vec::new();

		for _ in 0..1002 {
			let encrypted_message = connected_peer.encrypt(&message);
			encrypted_messages.push(encrypted_message);
		}

		for _ in 0..501 {
			// read two messages at once, filling buffer
			let mut current_encrypted_message = encrypted_messages.remove(0);
			let mut next_encrypted_message = encrypted_messages.remove(0);
			current_encrypted_message.extend_from_slice(&next_encrypted_message);
			let decrypted_message = remote_peer.decrypt_single_message(Some(&current_encrypted_message)).unwrap();
			assert_eq!(decrypted_message, message);
		}

		for _ in 0..501 {
			// decrypt messages directly from buffer without adding to it
			let decrypted_message = remote_peer.decrypt_single_message(None).unwrap();
			assert_eq!(decrypted_message, message);
		}
	}
}