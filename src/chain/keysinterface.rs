//! keysinterface provides keys into rust-lightning and defines some useful enums which describe
//! spendable on-chain outputs which the user owns and is responsible for using just as any other
//! on-chain output which is theirs.

use bitcoin::blockdata::transaction::{OutPoint, TxOut};
use bitcoin::blockdata::script::{Script, Builder};
use bitcoin::blockdata::opcodes;
use bitcoin::network::constants::Network;
use bitcoin::util::hash::Hash160;
use bitcoin::util::bip32::{ExtendedPrivKey, ExtendedPubKey, ChildNumber};

use secp256k1::key::{SecretKey, PublicKey};
use secp256k1::Secp256k1;
use secp256k1;

use crypto::hkdf::{hkdf_extract,hkdf_expand};
use crypto::digest::Digest;

use util::sha2::Sha256;
use util::logger::Logger;
use util::rng;
use util::byte_utils;

use std::time::{SystemTime, UNIX_EPOCH};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

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
		/// local_delayedkey = delayed_payment_basepoint_secret + SHA256(per_commitment_point || delayed_payment_basepoint)
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
#[derive(Clone)]
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
	/// Commitment seed
	pub commitment_seed: [u8; 32],
}

impl_writeable!(ChannelKeys, 0, {
	funding_key,
	revocation_base_key,
	payment_base_key,
	delayed_payment_base_key,
	htlc_base_key,
	commitment_seed
});

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

		hkdf_expand(Sha256::new(), &prk, b"rust-lightning local commitment seed info", &mut okm);

		ChannelKeys {
			funding_key: funding_key,
			revocation_base_key: revocation_base_key,
			payment_base_key: payment_base_key,
			delayed_payment_base_key: delayed_payment_base_key,
			htlc_base_key: htlc_base_key,
			commitment_seed: okm
		}
	}
}

/// Simple KeysInterface implementor that takes a 32-byte seed for use as a BIP 32 extended key
/// and derives keys from that.
///
/// Your node_id is seed/0'
/// ChannelMonitor closes may use seed/1'
/// Cooperative closes may use seed/2'
/// The two close keys may be needed to claim on-chain funds!
pub struct KeysManager {
	secp_ctx: Secp256k1<secp256k1::All>,
	node_secret: SecretKey,
	destination_script: Script,
	shutdown_pubkey: PublicKey,
	channel_master_key: ExtendedPrivKey,
	channel_child_index: AtomicUsize,

	logger: Arc<Logger>,
}

impl KeysManager {
	/// Constructs a KeysManager from a 32-byte seed. If the seed is in some way biased (eg your
	/// RNG is busted) this may panic.
	pub fn new(seed: &[u8; 32], network: Network, logger: Arc<Logger>) -> KeysManager {
		let secp_ctx = Secp256k1::new();
		match ExtendedPrivKey::new_master(&secp_ctx, network.clone(), seed) {
			Ok(master_key) => {
				let node_secret = master_key.ckd_priv(&secp_ctx, ChildNumber::from_hardened_idx(0)).expect("Your RNG is busted").secret_key;
				let destination_script = match master_key.ckd_priv(&secp_ctx, ChildNumber::from_hardened_idx(1)) {
					Ok(destination_key) => {
						let pubkey_hash160 = Hash160::from_data(&ExtendedPubKey::from_private(&secp_ctx, &destination_key).public_key.serialize()[..]);
						Builder::new().push_opcode(opcodes::All::OP_PUSHBYTES_0)
						              .push_slice(pubkey_hash160.as_bytes())
						              .into_script()
					},
					Err(_) => panic!("Your RNG is busted"),
				};
				let shutdown_pubkey = match master_key.ckd_priv(&secp_ctx, ChildNumber::from_hardened_idx(2)) {
					Ok(shutdown_key) => ExtendedPubKey::from_private(&secp_ctx, &shutdown_key).public_key,
					Err(_) => panic!("Your RNG is busted"),
				};
				let channel_master_key = master_key.ckd_priv(&secp_ctx, ChildNumber::from_hardened_idx(3)).expect("Your RNG is busted");
				KeysManager {
					secp_ctx,
					node_secret,
					destination_script,
					shutdown_pubkey,
					channel_master_key,
					channel_child_index: AtomicUsize::new(0),

					logger,
				}
			},
			Err(_) => panic!("Your rng is busted"),
		}
	}
}

impl KeysInterface for KeysManager {
	fn get_node_secret(&self) -> SecretKey {
		self.node_secret.clone()
	}

	fn get_destination_script(&self) -> Script {
		self.destination_script.clone()
	}

	fn get_shutdown_pubkey(&self) -> PublicKey {
		self.shutdown_pubkey.clone()
	}

	fn get_channel_keys(&self, _inbound: bool) -> ChannelKeys {
		// We only seriously intend to rely on the channel_master_key for true secure
		// entropy, everything else just ensures uniqueness. We generally don't expect
		// all clients to have non-broken RNGs here, so we also include the current
		// time as a fallback to get uniqueness.
		let mut sha = Sha256::new();

		let mut seed = [0u8; 32];
		rng::fill_bytes(&mut seed[..]);
		sha.input(&seed);

		let now = SystemTime::now().duration_since(UNIX_EPOCH).expect("Time went backwards");
		sha.input(&byte_utils::be32_to_array(now.subsec_nanos()));
		sha.input(&byte_utils::be64_to_array(now.as_secs()));

		let child_ix = self.channel_child_index.fetch_add(1, Ordering::AcqRel);
		let child_privkey = self.channel_master_key.ckd_priv(&self.secp_ctx, ChildNumber::from_hardened_idx(child_ix as u32)).expect("Your RNG is busted");
		sha.input(&child_privkey.secret_key[..]);

		sha.result(&mut seed);
		ChannelKeys::new_from_seed(&seed)
	}
}
