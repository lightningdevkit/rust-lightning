//! keysinterface provides keys into rust-lightning and defines some useful enums which describe
//! spendable on-chain outputs which the user owns and is responsible for using just as any other
//! on-chain output which is theirs.

use bitcoin::blockdata::transaction::{Transaction, OutPoint, TxOut};
use bitcoin::blockdata::script::{Script, Builder};
use bitcoin::blockdata::opcodes;
use bitcoin::network::constants::Network;
use bitcoin::util::bip32::{ExtendedPrivKey, ExtendedPubKey, ChildNumber};
use bitcoin::util::bip143;

use bitcoin_hashes::{Hash, HashEngine};
use bitcoin_hashes::sha256::HashEngine as Sha256State;
use bitcoin_hashes::sha256::Hash as Sha256;
use bitcoin_hashes::sha256d::Hash as Sha256dHash;
use bitcoin_hashes::hash160::Hash as Hash160;

use secp256k1::key::{SecretKey, PublicKey};
use secp256k1::{Secp256k1, Signature, Signing};
use secp256k1;

use util::byte_utils;
use util::logger::Logger;
use util::ser::{Writeable, Writer, Readable};

use ln::chan_utils;
use ln::chan_utils::{TxCreationKeys, HTLCOutputInCommitment, make_funding_redeemscript, ChannelPublicKeys};
use ln::msgs;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::io::Error;
use ln::msgs::DecodeError;

/// When on-chain outputs are created by rust-lightning (which our counterparty is not able to
/// claim at any point in the future) an event is generated which you must track and be able to
/// spend on-chain. The information needed to do this is provided in this enum, including the
/// outpoint describing which txid and output index is available, the full output which exists at
/// that txid/index, and any keys or other information required to sign.
pub enum SpendableOutputDescriptor {
	/// An output to a script which was provided via KeysInterface, thus you should already know
	/// how to spend it. No keys are provided as rust-lightning was never given any keys - only the
	/// script_pubkey as it appears in the output.
	/// These may include outputs from a transaction punishing our counterparty or claiming an HTLC
	/// on-chain using the payment preimage or after it has timed out.
	StaticOutput {
		/// The outpoint which is spendable
		outpoint: OutPoint,
		/// The output which is referenced by the given outpoint.
		output: TxOut,
	},
	/// An output to a P2WSH script which can be spent with a single signature after a CSV delay.
	/// The private key which should be used to sign the transaction is provided, as well as the
	/// full witness redeemScript which is hashed in the output script_pubkey.
	/// The witness in the spending input should be:
	/// <BIP 143 signature generated with the given key> <one zero byte aka OP_0>
	/// <witness_script as provided>
	/// Note that the nSequence field in the input must be set to_self_delay (which corresponds to
	/// the transaction not being broadcastable until at least to_self_delay blocks after the input
	/// confirms).
	/// These are generally the result of a "revocable" output to us, spendable only by us unless
	/// it is an output from us having broadcast an old state (which should never happen).
	DynamicOutputP2WSH {
		/// The outpoint which is spendable
		outpoint: OutPoint,
		/// The secret key which must be used to sign the spending transaction
		key: SecretKey,
		/// The witness redeemScript which is hashed to create the script_pubkey in the given output
		witness_script: Script,
		/// The nSequence value which must be set in the spending input to satisfy the OP_CSV in
		/// the witness_script.
		to_self_delay: u16,
		/// The output which is referenced by the given outpoint
		output: TxOut,
	},
	/// An output to a P2WPKH, spendable exclusively by the given private key.
	/// The witness in the spending input, is, thus, simply:
	/// <BIP 143 signature generated with the given key> <public key derived from the given key>
	/// These are generally the result of our counterparty having broadcast the current state,
	/// allowing us to claim the non-HTLC-encumbered outputs immediately.
	DynamicOutputP2WPKH {
		/// The outpoint which is spendable
		outpoint: OutPoint,
		/// The secret key which must be used to sign the spending transaction
		key: SecretKey,
		/// The output which is reference by the given outpoint
		output: TxOut,
	}
}

impl Writeable for SpendableOutputDescriptor {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
		match self {
			&SpendableOutputDescriptor::StaticOutput { ref outpoint, ref output } => {
				0u8.write(writer)?;
				outpoint.write(writer)?;
				output.write(writer)?;
			},
			&SpendableOutputDescriptor::DynamicOutputP2WSH { ref outpoint, ref key, ref witness_script, ref to_self_delay, ref output } => {
				1u8.write(writer)?;
				outpoint.write(writer)?;
				key.write(writer)?;
				witness_script.write(writer)?;
				to_self_delay.write(writer)?;
				output.write(writer)?;
			},
			&SpendableOutputDescriptor::DynamicOutputP2WPKH { ref outpoint, ref key, ref output } => {
				2u8.write(writer)?;
				outpoint.write(writer)?;
				key.write(writer)?;
				output.write(writer)?;
			},
		}
		Ok(())
	}
}

impl<R: ::std::io::Read> Readable<R> for SpendableOutputDescriptor {
	fn read(reader: &mut R) -> Result<Self, DecodeError> {
		match Readable::read(reader)? {
			0u8 => Ok(SpendableOutputDescriptor::StaticOutput {
				outpoint: Readable::read(reader)?,
				output: Readable::read(reader)?,
			}),
			1u8 => Ok(SpendableOutputDescriptor::DynamicOutputP2WSH {
				outpoint: Readable::read(reader)?,
				key: Readable::read(reader)?,
				witness_script: Readable::read(reader)?,
				to_self_delay: Readable::read(reader)?,
				output: Readable::read(reader)?,
			}),
			2u8 => Ok(SpendableOutputDescriptor::DynamicOutputP2WPKH {
				outpoint: Readable::read(reader)?,
				key: Readable::read(reader)?,
				output: Readable::read(reader)?,
			}),
			_ => Err(DecodeError::InvalidValue),
		}
	}
}

/// A trait to describe an object which can get user secrets and key material.
pub trait KeysInterface: Send + Sync {
	/// A type which implements ChannelKeys which will be returned by get_channel_keys.
	type ChanKeySigner : ChannelKeys;

	/// Get node secret key (aka node_id or network_key)
	fn get_node_secret(&self) -> SecretKey;
	/// Get destination redeemScript to encumber static protocol exit points.
	fn get_destination_script(&self) -> Script;
	/// Get shutdown_pubkey to use as PublicKey at channel closure
	fn get_shutdown_pubkey(&self) -> PublicKey;
	/// Get a new set of ChannelKeys for per-channel secrets. These MUST be unique even if you
	/// restarted with some stale data!
	fn get_channel_keys(&self, inbound: bool, channel_value_satoshis: u64) -> Self::ChanKeySigner;
	/// Get a secret and PRNG seed for construting an onion packet
	fn get_onion_rand(&self) -> (SecretKey, [u8; 32]);
	/// Get a unique temporary channel id. Channels will be referred to by this until the funding
	/// transaction is created, at which point they will use the outpoint in the funding
	/// transaction.
	fn get_channel_id(&self) -> [u8; 32];
}

/// Set of lightning keys needed to operate a channel as described in BOLT 3.
///
/// Signing services could be implemented on a hardware wallet. In this case,
/// the current ChannelKeys would be a front-end on top of a communication
/// channel connected to your secure device and lightning key material wouldn't
/// reside on a hot server. Nevertheless, a this deployment would still need
/// to trust the ChannelManager to avoid loss of funds as this latest component
/// could ask to sign commitment transaction with HTLCs paying to attacker pubkeys.
///
/// A more secure iteration would be to use hashlock (or payment points) to pair
/// invoice/incoming HTLCs with outgoing HTLCs to implement a no-trust-ChannelManager
/// at the price of more state and computation on the hardware wallet side. In the future,
/// we are looking forward to design such interface.
///
/// In any case, ChannelMonitor or fallback watchtowers are always going to be trusted
/// to act, as liveness and breach reply correctness are always going to be hard requirements
/// of LN security model, orthogonal of key management issues.
///
/// If you're implementing a custom signer, you almost certainly want to implement
/// Readable/Writable to serialize out a unique reference to this set of keys so
/// that you can serialize the full ChannelManager object.
///
/// (TODO: We shouldn't require that, and should have an API to get them at deser time, due mostly
/// to the possibility of reentrancy issues by calling the user's code during our deserialization
/// routine).
/// TODO: We should remove Clone by instead requesting a new ChannelKeys copy when we create
/// ChannelMonitors instead of expecting to clone the one out of the Channel into the monitors.
pub trait ChannelKeys : Send+Clone {
	/// Gets the private key for the anchor tx
	fn funding_key<'a>(&'a self) -> &'a SecretKey;
	/// Gets the local secret key for blinded revocation pubkey
	fn revocation_base_key<'a>(&'a self) -> &'a SecretKey;
	/// Gets the local secret key used in to_remote output of remote commitment tx
	/// (and also as part of obscured commitment number)
	fn payment_base_key<'a>(&'a self) -> &'a SecretKey;
	/// Gets the local secret key used in HTLC-Success/HTLC-Timeout txn and to_local output
	fn delayed_payment_base_key<'a>(&'a self) -> &'a SecretKey;
	/// Gets the local htlc secret key used in commitment tx htlc outputs
	fn htlc_base_key<'a>(&'a self) -> &'a SecretKey;
	/// Gets the commitment seed
	fn commitment_seed<'a>(&'a self) -> &'a [u8; 32];
	/// Gets the local channel public keys and basepoints
	fn pubkeys<'a>(&'a self) -> &'a ChannelPublicKeys;

	/// Create a signature for a remote commitment transaction and associated HTLC transactions.
	///
	/// Note that if signing fails or is rejected, the channel will be force-closed.
	///
	/// TODO: Document the things someone using this interface should enforce before signing.
	/// TODO: Add more input vars to enable better checking (preferably removing commitment_tx and
	/// making the callee generate it via some util function we expose)!
	fn sign_remote_commitment<T: secp256k1::Signing + secp256k1::Verification>(&self, feerate_per_kw: u64, commitment_tx: &Transaction, keys: &TxCreationKeys, htlcs: &[&HTLCOutputInCommitment], to_self_delay: u16, secp_ctx: &Secp256k1<T>) -> Result<(Signature, Vec<Signature>), ()>;

	/// Create a signature for a (proposed) closing transaction.
	///
	/// Note that, due to rounding, there may be one "missing" satoshi, and either party may have
	/// chosen to forgo their output as dust.
	fn sign_closing_transaction<T: secp256k1::Signing>(&self, closing_tx: &Transaction, secp_ctx: &Secp256k1<T>) -> Result<Signature, ()>;

	/// Signs a channel announcement message with our funding key, proving it comes from one
	/// of the channel participants.
	///
	/// Note that if this fails or is rejected, the channel will not be publicly announced and
	/// our counterparty may (though likely will not) close the channel on us for violating the
	/// protocol.
	fn sign_channel_announcement<T: secp256k1::Signing>(&self, msg: &msgs::UnsignedChannelAnnouncement, secp_ctx: &Secp256k1<T>) -> Result<Signature, ()>;

	/// Set the remote channel basepoints.  This is done immediately on incoming channels
	/// and as soon as the channel is accepted on outgoing channels.
	///
	/// Will be called before any signatures are applied.
	fn set_remote_channel_pubkeys(&mut self, channel_points: &ChannelPublicKeys);
}

#[derive(Clone)]
/// A simple implementation of ChannelKeys that just keeps the private keys in memory.
pub struct InMemoryChannelKeys {
	/// Private key of anchor tx
	funding_key: SecretKey,
	/// Local secret key for blinded revocation pubkey
	revocation_base_key: SecretKey,
	/// Local secret key used in commitment tx htlc outputs
	payment_base_key: SecretKey,
	/// Local secret key used in HTLC tx
	delayed_payment_base_key: SecretKey,
	/// Local htlc secret key used in commitment tx htlc outputs
	htlc_base_key: SecretKey,
	/// Commitment seed
	commitment_seed: [u8; 32],
	/// Local public keys and basepoints
	pub(crate) local_channel_pubkeys: ChannelPublicKeys,
	/// Remote public keys and base points
	pub(crate) remote_channel_pubkeys: Option<ChannelPublicKeys>,
	/// The total value of this channel
	channel_value_satoshis: u64,
}

impl InMemoryChannelKeys {
	/// Create a new InMemoryChannelKeys
	pub fn new<C: Signing>(
		secp_ctx: &Secp256k1<C>,
		funding_key: SecretKey,
		revocation_base_key: SecretKey,
		payment_base_key: SecretKey,
		delayed_payment_base_key: SecretKey,
		htlc_base_key: SecretKey,
		commitment_seed: [u8; 32],
		channel_value_satoshis: u64) -> InMemoryChannelKeys {
		let local_channel_pubkeys =
			InMemoryChannelKeys::make_local_keys(secp_ctx, &funding_key, &revocation_base_key,
			                                     &payment_base_key, &delayed_payment_base_key,
			                                     &htlc_base_key);
		InMemoryChannelKeys {
			funding_key,
			revocation_base_key,
			payment_base_key,
			delayed_payment_base_key,
			htlc_base_key,
			commitment_seed,
			channel_value_satoshis,
			local_channel_pubkeys,
			remote_channel_pubkeys: None,
		}
	}

	fn make_local_keys<C: Signing>(secp_ctx: &Secp256k1<C>,
	                               funding_key: &SecretKey,
	                               revocation_base_key: &SecretKey,
	                               payment_base_key: &SecretKey,
	                               delayed_payment_base_key: &SecretKey,
	                               htlc_base_key: &SecretKey) -> ChannelPublicKeys {
		let from_secret = |s: &SecretKey| PublicKey::from_secret_key(secp_ctx, s);
		ChannelPublicKeys {
			funding_pubkey: from_secret(&funding_key),
			revocation_basepoint: from_secret(&revocation_base_key),
			payment_basepoint: from_secret(&payment_base_key),
			delayed_payment_basepoint: from_secret(&delayed_payment_base_key),
			htlc_basepoint: from_secret(&htlc_base_key),
		}
	}
}

impl ChannelKeys for InMemoryChannelKeys {
	fn funding_key(&self) -> &SecretKey { &self.funding_key }
	fn revocation_base_key(&self) -> &SecretKey { &self.revocation_base_key }
	fn payment_base_key(&self) -> &SecretKey { &self.payment_base_key }
	fn delayed_payment_base_key(&self) -> &SecretKey { &self.delayed_payment_base_key }
	fn htlc_base_key(&self) -> &SecretKey { &self.htlc_base_key }
	fn commitment_seed(&self) -> &[u8; 32] { &self.commitment_seed }
	fn pubkeys<'a>(&'a self) -> &'a ChannelPublicKeys { &self.local_channel_pubkeys }

	fn sign_remote_commitment<T: secp256k1::Signing + secp256k1::Verification>(&self, feerate_per_kw: u64, commitment_tx: &Transaction, keys: &TxCreationKeys, htlcs: &[&HTLCOutputInCommitment], to_self_delay: u16, secp_ctx: &Secp256k1<T>) -> Result<(Signature, Vec<Signature>), ()> {
		if commitment_tx.input.len() != 1 { return Err(()); }

		let funding_pubkey = PublicKey::from_secret_key(secp_ctx, &self.funding_key);
		let remote_channel_pubkeys = self.remote_channel_pubkeys.as_ref().expect("must set remote channel pubkeys before signing");
		let channel_funding_redeemscript = make_funding_redeemscript(&funding_pubkey, &remote_channel_pubkeys.funding_pubkey);

		let commitment_sighash = hash_to_message!(&bip143::SighashComponents::new(&commitment_tx).sighash_all(&commitment_tx.input[0], &channel_funding_redeemscript, self.channel_value_satoshis)[..]);
		let commitment_sig = secp_ctx.sign(&commitment_sighash, &self.funding_key);

		let commitment_txid = commitment_tx.txid();

		let mut htlc_sigs = Vec::with_capacity(htlcs.len());
		for ref htlc in htlcs {
			if let Some(_) = htlc.transaction_output_index {
				let htlc_tx = chan_utils::build_htlc_transaction(&commitment_txid, feerate_per_kw, to_self_delay, htlc, &keys.a_delayed_payment_key, &keys.revocation_key);
				let htlc_redeemscript = chan_utils::get_htlc_redeemscript(&htlc, &keys);
				let htlc_sighash = hash_to_message!(&bip143::SighashComponents::new(&htlc_tx).sighash_all(&htlc_tx.input[0], &htlc_redeemscript, htlc.amount_msat / 1000)[..]);
				let our_htlc_key = match chan_utils::derive_private_key(&secp_ctx, &keys.per_commitment_point, &self.htlc_base_key) {
					Ok(s) => s,
					Err(_) => return Err(()),
				};
				htlc_sigs.push(secp_ctx.sign(&htlc_sighash, &our_htlc_key));
			}
		}

		Ok((commitment_sig, htlc_sigs))
	}

	fn sign_closing_transaction<T: secp256k1::Signing>(&self, closing_tx: &Transaction, secp_ctx: &Secp256k1<T>) -> Result<Signature, ()> {
		if closing_tx.input.len() != 1 { return Err(()); }
		if closing_tx.input[0].witness.len() != 0 { return Err(()); }
		if closing_tx.output.len() > 2 { return Err(()); }

		let remote_channel_pubkeys = self.remote_channel_pubkeys.as_ref().expect("must set remote channel pubkeys before signing");
		let funding_pubkey = PublicKey::from_secret_key(secp_ctx, &self.funding_key);
		let channel_funding_redeemscript = make_funding_redeemscript(&funding_pubkey, &remote_channel_pubkeys.funding_pubkey);

		let sighash = hash_to_message!(&bip143::SighashComponents::new(closing_tx)
			.sighash_all(&closing_tx.input[0], &channel_funding_redeemscript, self.channel_value_satoshis)[..]);
		Ok(secp_ctx.sign(&sighash, &self.funding_key))
	}

	fn sign_channel_announcement<T: secp256k1::Signing>(&self, msg: &msgs::UnsignedChannelAnnouncement, secp_ctx: &Secp256k1<T>) -> Result<Signature, ()> {
		let msghash = hash_to_message!(&Sha256dHash::hash(&msg.encode()[..])[..]);
		Ok(secp_ctx.sign(&msghash, &self.funding_key))
	}

	fn set_remote_channel_pubkeys(&mut self, channel_pubkeys: &ChannelPublicKeys) {
		assert!(self.remote_channel_pubkeys.is_none(), "Already set remote channel pubkeys");
		self.remote_channel_pubkeys = Some(channel_pubkeys.clone());
	}
}

impl Writeable for InMemoryChannelKeys {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), Error> {
		self.funding_key.write(writer)?;
		self.revocation_base_key.write(writer)?;
		self.payment_base_key.write(writer)?;
		self.delayed_payment_base_key.write(writer)?;
		self.htlc_base_key.write(writer)?;
		self.commitment_seed.write(writer)?;
		self.remote_channel_pubkeys.write(writer)?;
		self.channel_value_satoshis.write(writer)?;

		Ok(())
	}
}

impl<R: ::std::io::Read> Readable<R> for InMemoryChannelKeys {
	fn read(reader: &mut R) -> Result<Self, DecodeError> {
		let funding_key = Readable::read(reader)?;
		let revocation_base_key = Readable::read(reader)?;
		let payment_base_key = Readable::read(reader)?;
		let delayed_payment_base_key = Readable::read(reader)?;
		let htlc_base_key = Readable::read(reader)?;
		let commitment_seed = Readable::read(reader)?;
		let remote_channel_pubkeys = Readable::read(reader)?;
		let channel_value_satoshis = Readable::read(reader)?;
		let secp_ctx = Secp256k1::signing_only();
		let local_channel_pubkeys =
			InMemoryChannelKeys::make_local_keys(&secp_ctx, &funding_key, &revocation_base_key,
			                                     &payment_base_key, &delayed_payment_base_key,
			                                     &htlc_base_key);

		Ok(InMemoryChannelKeys {
			funding_key,
			revocation_base_key,
			payment_base_key,
			delayed_payment_base_key,
			htlc_base_key,
			commitment_seed,
			channel_value_satoshis,
			local_channel_pubkeys,
			remote_channel_pubkeys
		})
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
	type ChanKeySigner = InMemoryChannelKeys;

	fn get_node_secret(&self) -> SecretKey {
		self.node_secret.clone()
	}

	fn get_destination_script(&self) -> Script {
		self.destination_script.clone()
	}

	fn get_shutdown_pubkey(&self) -> PublicKey {
		self.shutdown_pubkey.clone()
	}

	fn get_channel_keys(&self, _inbound: bool, channel_value_satoshis: u64) -> InMemoryChannelKeys {
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

		InMemoryChannelKeys::new(
			&self.secp_ctx,
			funding_key,
			revocation_base_key,
			payment_base_key,
			delayed_payment_base_key,
			htlc_base_key,
			commitment_seed,
			channel_value_satoshis
		)
	}

	fn get_onion_rand(&self) -> (SecretKey, [u8; 32]) {
		let mut sha = self.unique_start.clone();

		let child_ix = self.session_child_index.fetch_add(1, Ordering::AcqRel);
		let child_privkey = self.session_master_key.ckd_priv(&self.secp_ctx, ChildNumber::from_hardened_idx(child_ix as u32).expect("key space exhausted")).expect("Your RNG is busted");
		sha.input(&child_privkey.private_key.key[..]);

		let mut rng_seed = sha.clone();
		// Not exactly the most ideal construction, but the second value will get fed into
		// ChaCha so it is another step harder to break.
		rng_seed.input(b"RNG Seed Salt");
		sha.input(b"Session Key Salt");
		(SecretKey::from_slice(&Sha256::from_engine(sha).into_inner()).expect("Your RNG is busted"),
		Sha256::from_engine(rng_seed).into_inner())
	}

	fn get_channel_id(&self) -> [u8; 32] {
		let mut sha = self.unique_start.clone();

		let child_ix = self.channel_id_child_index.fetch_add(1, Ordering::AcqRel);
		let child_privkey = self.channel_id_master_key.ckd_priv(&self.secp_ctx, ChildNumber::from_hardened_idx(child_ix as u32).expect("key space exhausted")).expect("Your RNG is busted");
		sha.input(&child_privkey.private_key.key[..]);

		(Sha256::from_engine(sha).into_inner())
	}
}
