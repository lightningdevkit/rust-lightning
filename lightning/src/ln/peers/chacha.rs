use util::chacha20poly1305rfc::ChaCha20Poly1305RFC;

pub fn encrypt(key: &[u8], nonce: u64, associated_data: &[u8], plaintext: &[u8]) -> Vec<u8> {
	let mut nonce_bytes = [0; 12];
	nonce_bytes[4..].copy_from_slice(&nonce.to_le_bytes());

	let mut chacha = ChaCha20Poly1305RFC::new(key, &nonce_bytes, associated_data);
	let mut ciphertext = vec![0u8; plaintext.len()];
	let mut authentication_tag = [0u8; 16];
	chacha.encrypt(plaintext, &mut ciphertext, &mut authentication_tag);

	let mut tagged_ciphertext = ciphertext;
	tagged_ciphertext.extend_from_slice(&authentication_tag);
	tagged_ciphertext
}


pub fn decrypt(key: &[u8], nonce: u64, associated_data: &[u8], tagged_ciphertext: &[u8]) -> Result<Vec<u8>, String> {
	let mut nonce_bytes = [0; 12];
	nonce_bytes[4..].copy_from_slice(&nonce.to_le_bytes());

	let length = tagged_ciphertext.len();
	let ciphertext = &tagged_ciphertext[0..length - 16];
	let authentication_tag = &tagged_ciphertext[length - 16..length];

	let mut chacha = ChaCha20Poly1305RFC::new(key, &nonce_bytes, associated_data);
	let mut plaintext = vec![0u8; length - 16];
	let success = chacha.decrypt(ciphertext, &mut plaintext, authentication_tag);
	if success {
		Ok(plaintext.to_vec())
	} else {
		Err("invalid hmac".to_string())
	}
}
