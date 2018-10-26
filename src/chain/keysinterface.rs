//! keysinterface provides keys into rust-lightning and defines some useful enums which describe
//! spendable on-chain outputs which the user owns and is responsible for using just as any other
//! on-chain output which is theirs.

use bitcoin::blockdata::transaction::{OutPoint, TxOut};
use bitcoin::blockdata::script::Script;

use secp256k1::key::{SecretKey, PublicKey};
use secp256k1::Secp256k1;

use crypto::hkdf::{hkdf_extract,hkdf_expand};

use util::sha2::Sha256;

/// When on-chain outputs are created by rust-lightning an event is generated which informs the
/// user thereof. This enum describes the format of the output and provides the OutPoint.
pub enum SpendableOutputDescriptor {
	/// Outpoint with an output to a script which was provided via KeysInterface, thus you should
	/// have stored somewhere how to spend script_pubkey!
	/// Outputs from a justice tx, claim tx or preimage tx
	StaticOutput {
		/// The outpoint spendable by user wallet
		outpoint: OutPoint,
		/// The output which is referenced by the given outpoint
		output: TxOut,
	},
	/// Outpoint commits to a P2WSH, should be spend by the following witness :
	/// <local_delayedsig> 0 <witnessScript>
	/// With input nSequence set to_self_delay.
	/// Outputs from a HTLC-Success/Timeout tx
	DynamicOutput {
		/// Outpoint spendable by user wallet
		outpoint: OutPoint,
		/// local_delayedkey = delayed_payment_basepoint_secret + SHA256(per_commitment_point || delayed_payment_basepoint
		local_delayedkey: SecretKey,
		/// witness redeemScript encumbering output
		witness_script: Script,
		/// nSequence input must commit to self_delay to satisfy script's OP_CSV
		to_self_delay: u16,
	}
}

/// A trait to describe an object which can get user secrets and key material.
pub trait KeysInterface: Send + Sync {
	/// Get node secret key (aka node_id or network_key)
	fn get_node_secret(&self) -> SecretKey;
	/// Get destination redeemScript to encumber static protocol exit points.
	fn get_destination_script(&self) -> Script;
	/// Get shutdown_pubkey to use as PublicKey at channel closure
	fn get_shutdown_pubkey(&self) -> PublicKey;
	/// Get a new set of ChannelKeys for per-channel secrets. These MUST be unique even if you
	/// restarted with some stale data!
	fn get_channel_keys(&self, inbound: bool) -> ChannelKeys;
}

/// Set of lightning keys needed to operate a channel as described in BOLT 3
pub struct ChannelKeys {
	/// Private key of anchor tx
	pub funding_key: SecretKey,
	/// Local secret key for blinded revocation pubkey
	pub revocation_base_key: SecretKey,
	/// Local secret key used in commitment tx htlc outputs
	pub payment_base_key: SecretKey,
	/// Local secret key used in HTLC tx
	pub delayed_payment_base_key: SecretKey,
	/// Local htlc secret key used in commitment tx htlc outputs
	pub htlc_base_key: SecretKey,
	/// Local secret key used for closing tx
	pub channel_close_key: SecretKey,
	/// Local secret key used in justice tx, claim tx and preimage tx outputs
	pub channel_monitor_claim_key: SecretKey,
	/// Commitment seed
	pub commitment_seed: [u8; 32],
}

impl ChannelKeys {
	/// Generate a set of lightning keys needed to operate a channel by HKDF-expanding a given
	/// random 32-byte seed
	pub fn new_from_seed(seed: &[u8; 32]) -> ChannelKeys {
		let mut prk = [0; 32];
		hkdf_extract(Sha256::new(), b"rust-lightning key gen salt", seed, &mut prk);
		let secp_ctx = Secp256k1::without_caps();

		let mut okm = [0; 32];
		hkdf_expand(Sha256::new(), &prk, b"rust-lightning funding key info", &mut okm);
		let funding_key = SecretKey::from_slice(&secp_ctx, &okm).expect("Sha256 is broken");

		hkdf_expand(Sha256::new(), &prk, b"rust-lightning revocation base key info", &mut okm);
		let revocation_base_key = SecretKey::from_slice(&secp_ctx, &okm).expect("Sha256 is broken");

		hkdf_expand(Sha256::new(), &prk, b"rust-lightning payment base key info", &mut okm);
		let payment_base_key = SecretKey::from_slice(&secp_ctx, &okm).expect("Sha256 is broken");

		hkdf_expand(Sha256::new(), &prk, b"rust-lightning delayed payment base key info", &mut okm);
		let delayed_payment_base_key = SecretKey::from_slice(&secp_ctx, &okm).expect("Sha256 is broken");

		hkdf_expand(Sha256::new(), &prk, b"rust-lightning htlc base key info", &mut okm);
		let htlc_base_key = SecretKey::from_slice(&secp_ctx, &okm).expect("Sha256 is broken");

		hkdf_expand(Sha256::new(), &prk, b"rust-lightning channel close key info", &mut okm);
		let channel_close_key = SecretKey::from_slice(&secp_ctx, &okm).expect("Sha256 is broken");

		hkdf_expand(Sha256::new(), &prk, b"rust-lightning channel monitor claim key info", &mut okm);
		let channel_monitor_claim_key = SecretKey::from_slice(&secp_ctx, &okm).expect("Sha256 is broken");

		hkdf_expand(Sha256::new(), &prk, b"rust-lightning local commitment seed info", &mut okm);

		ChannelKeys {
			funding_key: funding_key,
			revocation_base_key: revocation_base_key,
			payment_base_key: payment_base_key,
			delayed_payment_base_key: delayed_payment_base_key,
			htlc_base_key: htlc_base_key,
			channel_close_key: channel_close_key,
			channel_monitor_claim_key: channel_monitor_claim_key,
			commitment_seed: okm
		}
	}
}
