//! WalletInterface is *not* a wallet, only an interface to bridge between
//! user wallet and ChannelMonitor. If this last one discover on-chain outputs they will
//! be send with associate data as events::Event::SpendableOutputs to be at the disposal of wallet.
//!
//! KeysInterface is no more a wallet, just an entity to get secret from user wallet and derive
//! appropriate keyring materials to others lightning components, as such node_id, destination_script.
//!

use bitcoin::blockdata::transaction::OutPoint;
use bitcoin::blockdata::script::Script;

use secp256k1::key::{SecretKey, PublicKey};
use secp256k1::Secp256k1;
use secp256k1;

use crypto::hkdf::{hkdf_extract,hkdf_expand};

use util::events;
use util::sha2::Sha256;

/// A trait to describe a wallet which sould receive data to be able to spend onchain outputs
/// fron a lightning channel
pub trait WalletInterface: Send + Sync {
	/// Handle an incoming SpendableOutputs event from SimpleManyChannelMonitor containing a 
	/// CustomOutputScriptDesctitpor. Follow doc of the latter to know how to spend the output.
	fn handle_spendable_output(&self, event: events::Event);
}

/// Hacky custom output script descriptors to ease spending of onchain outputs by user wallet
/// Maybe should be changed by real ones when merged into rust-bitcoin.
/// StaticOutputs commit to a static pubkey, i.e one derived once for node operation lifetime.
/// DynamicOutputs commit to a dynamic local_delayedpubkey, i.e one which change for each per_commitment_point
pub enum CustomOutputScriptDescriptor {
	/// Outpoint commits to a P2PWKH, should be spend by the following witness :
	/// <signature> <pubkey>
	/// With pubkey being bip32 /1' from HMAC-Sha512 of user-provided seed as master private key
	StaticOutput {
		/// Outpoint spendable by user wallet
		outpoint: OutPoint,
	},
	/// Outpoint commits to a P2WSH, should be spend by the following witness :
	/// <local_delayedsig> 0 <witnessScript>
	/// With input nSequence set to_self_delay.
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

impl CustomOutputScriptDescriptor {
	/// Build a StaticOuput descriptor
	pub fn static_key(outpoint: OutPoint) -> Self {
		CustomOutputScriptDescriptor::StaticOutput {
			outpoint,
		}
	}

	/// Build a DynamicOuput descriptor
	pub fn dynamic_key(outpoint: OutPoint, local_delayedkey: SecretKey, witness_script: Script, to_self_delay: u16) -> Self {
		CustomOutputScriptDescriptor::DynamicOutput {
			outpoint,
			local_delayedkey,
			witness_script,
			to_self_delay,
		}
	}
}

/// A trait to describe an object which should get secrets from user wallet and apply derivation
/// to provide keys materials downstream
/// node_id /0'
/// destination_pubkey /1'
/// shutdown_pubkey /2'
/// channel_master_pubkey /3/N'
pub trait KeysInterface: Send + Sync {
	/// Get node secret key to derive node_id
	fn get_node_secret(&self) -> SecretKey;
	/// Get destination redeemScript to encumber static protocol exit points. For now
	/// redeemScript is a pay-2-public-key-hash.
	fn get_destination_script(&self) -> Script;
	/// Get shutdown_pubkey to use as PublicKey at channel closure
	fn get_shutdown_pubkey(&self) -> PublicKey;
	/// Get a new set of ChannelKeys from per-channel random key /3/N'
	/// For Channel N, keys correspond to ChannelKeys::new_from_seed(/3/N')
	fn get_channel_keys(&self) -> Option<ChannelKeys>;
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
	/// Generate a set of lightning keys needed to operate a channel as described in BOLT 3 from
	/// used-provided seed
	pub fn new_from_seed(seed: &[u8; 32]) -> Result<ChannelKeys, secp256k1::Error> {
		let mut prk = [0; 32];
		hkdf_extract(Sha256::new(), b"rust-lightning key gen salt", seed, &mut prk);
		let secp_ctx = Secp256k1::without_caps();

		let mut okm = [0; 32];
		hkdf_expand(Sha256::new(), &prk, b"rust-lightning funding key info", &mut okm);
		let funding_key = SecretKey::from_slice(&secp_ctx, &okm)?;

		hkdf_expand(Sha256::new(), &prk, b"rust-lightning revocation base key info", &mut okm);
		let revocation_base_key = SecretKey::from_slice(&secp_ctx, &okm)?;

		hkdf_expand(Sha256::new(), &prk, b"rust-lightning payment base key info", &mut okm);
		let payment_base_key = SecretKey::from_slice(&secp_ctx, &okm)?;

		hkdf_expand(Sha256::new(), &prk, b"rust-lightning delayed payment base key info", &mut okm);
		let delayed_payment_base_key = SecretKey::from_slice(&secp_ctx, &okm)?;

		hkdf_expand(Sha256::new(), &prk, b"rust-lightning htlc base key info", &mut okm);
		let htlc_base_key = SecretKey::from_slice(&secp_ctx, &okm)?;

		hkdf_expand(Sha256::new(), &prk, b"rust-lightning channel close key info", &mut okm);
		let channel_close_key = SecretKey::from_slice(&secp_ctx, &okm)?;

		hkdf_expand(Sha256::new(), &prk, b"rust-lightning channel monitor claim key info", &mut okm);
		let channel_monitor_claim_key = SecretKey::from_slice(&secp_ctx, &okm)?;

		hkdf_expand(Sha256::new(), &prk, b"rust-lightning local commitment seed info", &mut okm);

		Ok(ChannelKeys {
			funding_key: funding_key,
			revocation_base_key: revocation_base_key,
			payment_base_key: payment_base_key,
			delayed_payment_base_key: delayed_payment_base_key,
			htlc_base_key: htlc_base_key,
			channel_close_key: channel_close_key,
			channel_monitor_claim_key: channel_monitor_claim_key,
			commitment_seed: okm
		})
	}
}
