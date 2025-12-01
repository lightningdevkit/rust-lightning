// src/pq.rs

//! PQ overlay primitives for the hybrid node.

use std::fmt;

// FIX: Use OsRng from rand::rngs (provided by the 'rand' crate)
use rand::rngs::OsRng;

// ML-KEM (Kyber) imports
use ml_kem::{MlKem768, MlKem768Params, KemCore, EncodedSizeUser}; 
use ml_kem::kem::{DecapsulationKey, EncapsulationKey};

// ML-DSA (Dilithium) imports
use ml_dsa::{MlDsa65, KeyPair, KeyGen};

use hkdf::Hkdf;
use sha3::Sha3_256;

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};

/// The length of AEAD keys in bytes (256 bits for ChaCha20-Poly1305).
pub const AEAD_KEY_LEN: usize = 32;

/// The length of AEAD nonces in bytes (96 bits for ChaCha20-Poly1305).
pub const AEAD_NONCE_LEN: usize = 12;

/// Post-quantum static keypairs for both key encapsulation (ML-KEM-768) and digital signatures (ML-DSA-65).
///
/// This structure holds the long-term cryptographic keys used for post-quantum secure communications.
/// The KEM keys are used for key agreement, while the DSA keys are used for authentication.
pub struct PqStaticKeys {
    /// The ML-KEM-768 decapsulation key (private key for KEM).
    pub kem_dk: DecapsulationKey<MlKem768Params>,
    /// The ML-KEM-768 encapsulation key (public key for KEM).
    pub kem_ek: EncapsulationKey<MlKem768Params>,
    /// The ML-DSA-65 keypair used for signing and verification.
    pub dsa_keypair: KeyPair<MlDsa65>,
}

impl fmt::Debug for PqStaticKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let vkey = self.dsa_keypair.verifying_key();
        let enc = vkey.encode(); // EncodedVerifyingKey<MlDsa65>

        f.debug_struct("PqStaticKeys")
            .field("kem_algo", &"ML-KEM-768")
            .field("dsa_algo", &"ML-DSA-65")
            .field("kem_pk_bytes", &self.kem_ek.as_bytes().len())
            .field("dsa_pk_bytes", &enc.as_slice().len())
            .finish()
    }
}


impl PqStaticKeys {
    /// Generates a new set of post-quantum static keys.
    ///
    /// This creates fresh ML-KEM-768 and ML-DSA-65 keypairs using a cryptographically secure RNG.
    ///
    /// # Returns
    /// A new `PqStaticKeys` instance with randomly generated keys.
    pub fn generate() -> Self {
        let mut rng = OsRng;

        // Kyber (ML-KEM) static keys
        let (kem_dk, kem_ek) = MlKem768::generate(&mut rng);

        // ML-DSA keypair
        let dsa_keypair = MlDsa65::key_gen(&mut rng);

        Self { kem_dk, kem_ek, dsa_keypair }
    }

    /// Returns the ML-KEM-768 public key as a byte vector.
    ///
    /// This key can be transmitted to other parties for key encapsulation.
    pub fn kem_public_key_bytes(&self) -> Vec<u8> {
        self.kem_ek.as_bytes().to_vec()
    }

    /// Returns the ML-DSA-65 public key (verifying key) as a byte vector.
    ///
    /// This key can be transmitted to other parties for signature verification.
    pub fn dsa_public_key_bytes(&self) -> Vec<u8> {
        let enc = self.dsa_keypair.verifying_key().encode();
        enc.as_slice().to_vec()
    }

}

/// An authenticated encryption session using ChaCha20-Poly1305.
///
/// This structure wraps an AEAD cipher that has been initialized with a key derived
/// from a shared secret (typically obtained through a KEM operation).
pub struct PqAeadSession {
    aead: ChaCha20Poly1305,
}

impl fmt::Debug for PqAeadSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PqAeadSession")
            .field("aead", &"[ChaCha20-Poly1305]")
            .finish()
    }
}

impl PqAeadSession {
    /// Creates a new AEAD session from a shared secret.
    ///
    /// The shared secret is processed through HKDF-SHA3-256 with the provided context
    /// to derive a ChaCha20-Poly1305 key.
    ///
    /// # Arguments
    /// * `shared` - The shared secret bytes (typically from a KEM decapsulation)
    /// * `context` - Additional context information for key derivation
    ///
    /// # Returns
    /// A new `PqAeadSession` ready for encryption and decryption.
    pub fn from_shared_secret(shared: &[u8], context: &[u8]) -> Self {
        let hk = Hkdf::<Sha3_256>::new(None, shared);
        let mut key_bytes = [0u8; AEAD_KEY_LEN];
        hk.expand(context, &mut key_bytes)
            .expect("hkdf expand should not fail with correct length");
        let key = Key::from_slice(&key_bytes);
        let aead = ChaCha20Poly1305::new(key);
        Self { aead }
    }

    /// Encrypts plaintext with the given nonce.
    ///
    /// # Arguments
    /// * `nonce_bytes` - A 12-byte nonce (must be unique for each encryption with the same key)
    /// * `plaintext` - The data to encrypt
    ///
    /// # Returns
    /// The ciphertext with authentication tag appended, or an error if encryption fails.
    pub fn encrypt(
        &self,
        nonce_bytes: &[u8; AEAD_NONCE_LEN],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, chacha20poly1305::aead::Error> {
        let nonce = Nonce::from_slice(nonce_bytes);
        self.aead.encrypt(nonce, plaintext)
    }

    /// Decrypts ciphertext with the given nonce.
    ///
    /// # Arguments
    /// * `nonce_bytes` - The same 12-byte nonce used during encryption
    /// * `ciphertext` - The encrypted data with authentication tag
    ///
    /// # Returns
    /// The decrypted plaintext, or an error if decryption or authentication fails.
    pub fn decrypt(
        &self,
        nonce_bytes: &[u8; AEAD_NONCE_LEN],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, chacha20poly1305::aead::Error> {
        let nonce = Nonce::from_slice(nonce_bytes);
        self.aead.decrypt(nonce, ciphertext)
    }
}

/// Generates a 12-byte nonce from a counter value.
///
/// The counter is encoded as big-endian bytes in the last 8 bytes of the nonce,
/// with the first 4 bytes set to zero.
///
/// # Arguments
/// * `counter` - A monotonically increasing counter value
///
/// # Returns
/// A 12-byte array suitable for use as an AEAD nonce.
pub fn nonce_from_counter(counter: u64) -> [u8; AEAD_NONCE_LEN] {
    let mut out = [0u8; AEAD_NONCE_LEN];
    out[4..].copy_from_slice(&counter.to_be_bytes());
    out
}