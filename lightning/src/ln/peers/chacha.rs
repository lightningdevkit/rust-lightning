use util::byte_utils;
use util::chacha20poly1305rfc::ChaCha20Poly1305RFC;

pub const TAG_SIZE: usize = 16;

pub fn encrypt(key: &[u8], nonce: u64, associated_data: &[u8], plaintext: &[u8], ciphertext_out: &mut [u8]) {
	let mut nonce_bytes = [0; 12];
	nonce_bytes[4..].copy_from_slice(&byte_utils::le64_to_array(nonce));

	let mut chacha = ChaCha20Poly1305RFC::new(key, &nonce_bytes, associated_data);
	let mut authentication_tag = [0u8; 16];
	chacha.encrypt(plaintext, &mut ciphertext_out[..plaintext.len()], &mut authentication_tag);

	ciphertext_out[plaintext.len()..].copy_from_slice(&authentication_tag);
}

pub fn decrypt(key: &[u8], nonce: u64, associated_data: &[u8], tagged_ciphertext: &[u8], plaintext_out: &mut [u8]) -> Result<(), String> {
	let mut nonce_bytes = [0; 12];
	nonce_bytes[4..].copy_from_slice(&byte_utils::le64_to_array(nonce));

	let length = tagged_ciphertext.len();
	if length < 16 {
		return Err("ciphertext cannot be shorter than tag length of 16 bytes".to_string());
	}
	let end_index = length - 16;
	let ciphertext = &tagged_ciphertext[0..end_index];
	let authentication_tag = &tagged_ciphertext[end_index..];

	let mut chacha = ChaCha20Poly1305RFC::new(key, &nonce_bytes, associated_data);
	let success = chacha.decrypt(ciphertext, plaintext_out, authentication_tag);

	if !success {
		Err("invalid hmac".to_string())
	} else {
		Ok(())
	}
}
