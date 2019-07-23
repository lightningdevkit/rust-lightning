//! keysinterface provides keys into rust-lightning and defines some useful enums which describe
//! spendable on-chain outputs which the user owns and is responsible for using just as any other
//! on-chain output which is theirs.

use bitcoin::blockdata::transaction::{OutPoint, TxOut};
use bitcoin::blockdata::script::{Script, Builder};
use bitcoin::blockdata::opcodes;
use bitcoin::network::constants::Network;
use bitcoin::util::bip32::{ExtendedPrivKey, ExtendedPubKey, ChildNumber};

use bitcoin_hashes::{Hash, HashEngine};
use bitcoin_hashes::sha256::HashEngine as Sha256State;
use bitcoin_hashes::sha256::Hash as Sha256;
use bitcoin_hashes::hash160::Hash as Hash160;

use secp256k1::key::{SecretKey, PublicKey};
use secp256k1::Secp256k1;
use secp256k1;

use util::byte_utils;
use util::logger::Logger;

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
	/// Outpoint commits to a P2WSH
	/// P2WSH should be spend by the following witness :
	/// <local_delayedsig> 0 <witnessScript>
	/// With input nSequence set to_self_delay.
	/// Outputs from a HTLC-Success/Timeout tx/commitment tx
	DynamicOutputP2WSH {
		/// Outpoint spendable by user wallet
		outpoint: OutPoint,
		/// local_delayedkey = delayed_payment_basepoint_secret + SHA256(per_commitment_point || delayed_payment_basepoint) OR
		key: SecretKey,
		/// witness redeemScript encumbering output.
		witness_script: Script,
		/// nSequence input must commit to self_delay to satisfy script's OP_CSV
		to_self_delay: u16,
		/// The output which is referenced by the given outpoint
		output: TxOut,
	},
	/// Outpoint commits to a P2WPKH
	/// P2WPKH should be spend by the following witness :
	/// <local_sig> <local_pubkey>
	/// Outputs to_remote from a commitment tx
	DynamicOutputP2WPKH {
		/// Outpoint spendable by user wallet
		outpoint: OutPoint,
		/// localkey = payment_basepoint_secret + SHA256(per_commitment_point || payment_basepoint
		key: SecretKey,
		/// The output which is reference by the given outpoint
		output: TxOut,
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
	/// Get a secret for construting an onion packet
	fn get_session_key(&self) -> SecretKey;
	/// Get a unique temporary channel id. Channels will be referred to by this until the funding
	/// transaction is created, at which point they will use the outpoint in the funding
	/// transaction.
	fn get_channel_id(&self) -> [u8; 32];
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

/// Simple KeysInterface implementor that takes a 32-byte seed for use as a BIP 32 extended key
/// and derives keys from that.
///
/// Your node_id is seed/0'
/// ChannelMonitor closes may use seed/1'
/// Cooperative closes may use seed/2'
/// The two close keys may be needed to claim on-chain funds!
pub struct KeysManager {
	secp_ctx: Secp256k1<secp256k1::SignOnly>,
	node_secret: SecretKey,
	destination_script: Script,
	shutdown_pubkey: PublicKey,
	channel_master_key: ExtendedPrivKey,
	channel_child_index: AtomicUsize,
	session_master_key: ExtendedPrivKey,
	session_child_index: AtomicUsize,
	channel_id_master_key: ExtendedPrivKey,
	channel_id_child_index: AtomicUsize,

	unique_start: Sha256State,
	logger: Arc<Logger>,
}

impl KeysManager {
	/// Constructs a KeysManager from a 32-byte seed. If the seed is in some way biased (eg your
	/// RNG is busted) this may panic (but more importantly, you will possibly lose funds).
	/// starting_time isn't strictly required to actually be a time, but it must absolutely,
	/// without a doubt, be unique to this instance. ie if you start multiple times with the same
	/// seed, starting_time must be unique to each run. Thus, the easiest way to achieve this is to
	/// simply use the current time (with very high precision).
	///
	/// The seed MUST be backed up safely prior to use so that the keys can be re-created, however,
	/// obviously, starting_time should be unique every time you reload the library - it is only
	/// used to generate new ephemeral key data (which will be stored by the individual channel if
	/// necessary).
	///
	/// Note that the seed is required to recover certain on-chain funds independent of
	/// ChannelMonitor data, though a current copy of ChannelMonitor data is also required for any
	/// channel, and some on-chain during-closing funds.
	///
	/// Note that until the 0.1 release there is no guarantee of backward compatibility between
	/// versions. Once the library is more fully supported, the docs will be updated to include a
	/// detailed description of the guarantee.
	pub fn new(seed: &[u8; 32], network: Network, logger: Arc<Logger>, starting_time_secs: u64, starting_time_nanos: u32) -> KeysManager {
		let secp_ctx = Secp256k1::signing_only();
		match ExtendedPrivKey::new_master(network.clone(), seed) {
			Ok(master_key) => {
				let node_secret = master_key.ckd_priv(&secp_ctx, ChildNumber::from_hardened_idx(0).unwrap()).expect("Your RNG is busted").private_key.key;
				let destination_script = match master_key.ckd_priv(&secp_ctx, ChildNumber::from_hardened_idx(1).unwrap()) {
					Ok(destination_key) => {
						let pubkey_hash160 = Hash160::hash(&ExtendedPubKey::from_private(&secp_ctx, &destination_key).public_key.key.serialize()[..]);
						Builder::new().push_opcode(opcodes::all::OP_PUSHBYTES_0)
						              .push_slice(&pubkey_hash160.into_inner())
						              .into_script()
					},
					Err(_) => panic!("Your RNG is busted"),
				};
				let shutdown_pubkey = match master_key.ckd_priv(&secp_ctx, ChildNumber::from_hardened_idx(2).unwrap()) {
					Ok(shutdown_key) => ExtendedPubKey::from_private(&secp_ctx, &shutdown_key).public_key.key,
					Err(_) => panic!("Your RNG is busted"),
				};
				let channel_master_key = master_key.ckd_priv(&secp_ctx, ChildNumber::from_hardened_idx(3).unwrap()).expect("Your RNG is busted");
				let session_master_key = master_key.ckd_priv(&secp_ctx, ChildNumber::from_hardened_idx(4).unwrap()).expect("Your RNG is busted");
				let channel_id_master_key = master_key.ckd_priv(&secp_ctx, ChildNumber::from_hardened_idx(5).unwrap()).expect("Your RNG is busted");

				let mut unique_start = Sha256::engine();
				unique_start.input(&byte_utils::be64_to_array(starting_time_secs));
				unique_start.input(&byte_utils::be32_to_array(starting_time_nanos));
				unique_start.input(seed);

				KeysManager {
					secp_ctx,
					node_secret,
					destination_script,
					shutdown_pubkey,
					channel_master_key,
					channel_child_index: AtomicUsize::new(0),
					session_master_key,
					session_child_index: AtomicUsize::new(0),
					channel_id_master_key,
					channel_id_child_index: AtomicUsize::new(0),

					unique_start,
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
		// entropy, everything else just ensures uniqueness. We rely on the unique_start (ie
		// starting_time provided in the constructor) to be unique.
		let mut sha = self.unique_start.clone();

		let child_ix = self.channel_child_index.fetch_add(1, Ordering::AcqRel);
		let child_privkey = self.channel_master_key.ckd_priv(&self.secp_ctx, ChildNumber::from_hardened_idx(child_ix as u32).expect("key space exhausted")).expect("Your RNG is busted");
		sha.input(&child_privkey.private_key.key[..]);

		let seed = Sha256::from_engine(sha).into_inner();

		let commitment_seed = {
			let mut sha = Sha256::engine();
			sha.input(&seed);
			sha.input(&b"commitment seed"[..]);
			Sha256::from_engine(sha).into_inner()
		};
		macro_rules! key_step {
			($info: expr, $prev_key: expr) => {{
				let mut sha = Sha256::engine();
				sha.input(&seed);
				sha.input(&$prev_key[..]);
				sha.input(&$info[..]);
				SecretKey::from_slice(&Sha256::from_engine(sha).into_inner()).expect("SHA-256 is busted")
			}}
		}
		let funding_key = key_step!(b"funding key", commitment_seed);
		let revocation_base_key = key_step!(b"revocation base key", funding_key);
		let payment_base_key = key_step!(b"payment base key", revocation_base_key);
		let delayed_payment_base_key = key_step!(b"delayed payment base key", payment_base_key);
		let htlc_base_key = key_step!(b"HTLC base key", delayed_payment_base_key);

		ChannelKeys {
			funding_key,
			revocation_base_key,
			payment_base_key,
			delayed_payment_base_key,
			htlc_base_key,
			commitment_seed,
		}
	}

	fn get_session_key(&self) -> SecretKey {
		let mut sha = self.unique_start.clone();

		let child_ix = self.session_child_index.fetch_add(1, Ordering::AcqRel);
		let child_privkey = self.session_master_key.ckd_priv(&self.secp_ctx, ChildNumber::from_hardened_idx(child_ix as u32).expect("key space exhausted")).expect("Your RNG is busted");
		sha.input(&child_privkey.private_key.key[..]);
		SecretKey::from_slice(&Sha256::from_engine(sha).into_inner()).expect("Your RNG is busted")
	}

	fn get_channel_id(&self) -> [u8; 32] {
		let mut sha = self.unique_start.clone();

		let child_ix = self.channel_id_child_index.fetch_add(1, Ordering::AcqRel);
		let child_privkey = self.channel_id_master_key.ckd_priv(&self.secp_ctx, ChildNumber::from_hardened_idx(child_ix as u32).expect("key space exhausted")).expect("Your RNG is busted");
		sha.input(&child_privkey.private_key.key[..]);

		(Sha256::from_engine(sha).into_inner())
	}
}
