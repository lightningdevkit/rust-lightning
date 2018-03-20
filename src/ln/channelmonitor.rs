use bitcoin::blockdata::block::BlockHeader;
use bitcoin::blockdata::transaction::{TxIn,TxOut,SigHashType,Transaction};
use bitcoin::blockdata::script::Script;
use bitcoin::util::hash::Sha256dHash;
use bitcoin::util::bip143;

use crypto::digest::Digest;

use secp256k1::{Secp256k1,Message,Signature};
use secp256k1::key::{SecretKey,PublicKey};

use ln::msgs::HandleError;
use ln::chan_utils;
use ln::chan_utils::HTLCOutputInCommitment;
use chain::chaininterface::{ChainListener, ChainWatchInterface, BroadcasterInterface};
use util::sha2::Sha256;

use std::collections::HashMap;
use std::sync::{Arc,Mutex};
use std::{hash,cmp};

/// Simple trait indicating ability to track a set of ChannelMonitors and multiplex events between
/// them. Generally should be implemented by keeping a local SimpleManyChannelMonitor and passing
/// events to it, while also taking any add_update_monitor events and passing them to some remote
/// server(s).
pub trait ManyChannelMonitor: Send + Sync {
	/// Adds or updates a monitor for the given funding_txid+funding_output_index.
	fn add_update_monitor(&self, funding_txo: (Sha256dHash, u16), monitor: ChannelMonitor) -> Result<(), HandleError>;
}

/// A simple implementation of a ManyChannelMonitor and ChainListener. Can be used to create a
/// watchtower or watch our own channels.
/// Note that you must provide your own key by which to refer to channels.
/// If you're accepting remote monitors (ie are implementing a watchtower), you must verify that
/// users cannot overwrite a given channel by providing a duplicate key. ie you should probably
/// index by a PublicKey which is required to sign any updates.
/// If you're using this for local monitoring of your own channels, you probably want to use
/// (Sha256dHash, u16) as the key, which will give you a ManyChannelMonitor implementation.
pub struct SimpleManyChannelMonitor<Key> {
	monitors: Mutex<HashMap<Key, ChannelMonitor>>,
	chain_monitor: Arc<ChainWatchInterface>,
	broadcaster: Arc<BroadcasterInterface>
}

impl<Key : Send + cmp::Eq + hash::Hash> ChainListener for SimpleManyChannelMonitor<Key> {
	fn block_connected(&self, _header: &BlockHeader, height: u32, txn_matched: &[&Transaction], _indexes_of_txn_matched: &[u32]) {
		let monitors = self.monitors.lock().unwrap();
		for monitor in monitors.values() {
			monitor.block_connected(txn_matched, height, &*self.broadcaster);
		}
	}

	fn block_disconnected(&self, _: &BlockHeader) { }
}

impl<Key : Send + cmp::Eq + hash::Hash + 'static> SimpleManyChannelMonitor<Key> {
	pub fn new(chain_monitor: Arc<ChainWatchInterface>, broadcaster: Arc<BroadcasterInterface>) -> Arc<SimpleManyChannelMonitor<Key>> {
		let res = Arc::new(SimpleManyChannelMonitor {
			monitors: Mutex::new(HashMap::new()),
			chain_monitor,
			broadcaster
		});
		let weak_res = Arc::downgrade(&res);
		res.chain_monitor.register_listener(weak_res);
		res
	}

	pub fn add_update_monitor_by_key(&self, key: Key, monitor: ChannelMonitor) -> Result<(), HandleError> {
		let mut monitors = self.monitors.lock().unwrap();
		match monitors.get_mut(&key) {
			Some(orig_monitor) => return orig_monitor.insert_combine(monitor),
			None => {}
		};
		match monitor.funding_txo {
			None => self.chain_monitor.watch_all_txn(),
			Some((funding_txid, funding_output_index)) => self.chain_monitor.install_watch_outpoint((funding_txid, funding_output_index as u32)),
		}
		monitors.insert(key, monitor);
		Ok(())
	}
}

impl ManyChannelMonitor for SimpleManyChannelMonitor<(Sha256dHash, u16)> {
	fn add_update_monitor(&self, funding_txo: (Sha256dHash, u16), monitor: ChannelMonitor) -> Result<(), HandleError> {
		self.add_update_monitor_by_key(funding_txo, monitor)
	}
}

/// If an HTLC expires within this many blocks, don't try to claim it directly, instead broadcast
/// the HTLC-Success/HTLC-Timeout transaction and claim the revocation from that.
const CLTV_CLAIM_BUFFER: u32 = 12;

#[derive(Clone)]
enum RevocationStorage {
	PrivMode {
		revocation_base_key: SecretKey,
	},
	SigsMode {
		revocation_base_key: PublicKey,
		sigs: HashMap<Sha256dHash, Signature>,
	}
}

#[derive(Clone)]
struct PerCommitmentTransactionData {
	revoked_output_index: u32,
	htlcs: Vec<(HTLCOutputInCommitment, Signature)>,
}

#[derive(Clone)]
pub struct ChannelMonitor {
	funding_txo: Option<(Sha256dHash, u16)>,
	commitment_transaction_number_obscure_factor: u64,

	revocation_base_key: RevocationStorage,
	delayed_payment_base_key: PublicKey,
	htlc_base_key: PublicKey,
	their_htlc_base_key: Option<PublicKey>,
	to_self_delay: u16,

	old_secrets: [([u8; 32], u64); 49],
	claimable_outpoints: HashMap<Sha256dHash, PerCommitmentTransactionData>,
	payment_preimages: Vec<[u8; 32]>,

	destination_script: Script,
	secp_ctx: Secp256k1, //TODO: dedup this a bit...
}

impl ChannelMonitor {
	pub fn new(revocation_base_key: &SecretKey, delayed_payment_base_key: &PublicKey, htlc_base_key: &PublicKey, to_self_delay: u16, destination_script: Script) -> ChannelMonitor {
		ChannelMonitor {
			funding_txo: None,
			commitment_transaction_number_obscure_factor: 0,

			revocation_base_key: RevocationStorage::PrivMode {
				revocation_base_key: revocation_base_key.clone(),
			},
			delayed_payment_base_key: delayed_payment_base_key.clone(),
			htlc_base_key: htlc_base_key.clone(),
			their_htlc_base_key: None,
			to_self_delay: to_self_delay,

			old_secrets: [([0; 32], 1 << 48); 49],
			claimable_outpoints: HashMap::new(),
			payment_preimages: Vec::new(),

			destination_script: destination_script,
			secp_ctx: Secp256k1::new(),
		}
	}

	#[inline]
	fn place_secret(idx: u64) -> u8 {
		for i in 0..48 {
			if idx & (1 << i) == (1 << i) {
				return i
			}
		}
		48
	}

	#[inline]
	fn derive_secret(secret: [u8; 32], bits: u8, idx: u64) -> [u8; 32] {
		let mut res: [u8; 32] = secret;
		for i in 0..bits {
			let bitpos = bits - 1 - i;
			if idx & (1 << bitpos) == (1 << bitpos) {
				res[(bitpos / 8) as usize] ^= 1 << (bitpos & 7);
				let mut sha = Sha256::new();
				sha.input(&res);
				sha.result(&mut res);
			}
		}
		res
	}

	/// Inserts a revocation secret into this channel monitor. Requires the revocation_base_key of
	/// the node which we are monitoring the channel on behalf of in order to generate signatures
	/// over revocation-claim transactions.
	pub fn provide_secret(&mut self, idx: u64, secret: [u8; 32]) -> Result<(), HandleError> {
		let pos = ChannelMonitor::place_secret(idx);
		for i in 0..pos {
			let (old_secret, old_idx) = self.old_secrets[i as usize];
			if ChannelMonitor::derive_secret(secret, pos, old_idx) != old_secret {
				return Err(HandleError{err: "Previous secret did not match new one", msg: None})
			}
		}
		self.old_secrets[pos as usize] = (secret, idx);
		Ok(())
	}

	/// Informs this watcher of the set of HTLC outputs in a commitment transaction which our
	/// counterparty may broadcast. This allows us to reconstruct the commitment transaction's
	/// outputs fully, claiming revoked, unexpired HTLC outputs as well as revoked refund outputs.
	/// TODO: Doc new params!
	/// TODO: This seems to be wrong...we should be calling this from commitment_signed, but we
	/// should be calling this about remote transactions, ie ones that they can revoke_and_ack...
	pub fn provide_tx_info(&mut self, commitment_tx: &Transaction, revokeable_out_index: u32, htlc_outputs: Vec<(HTLCOutputInCommitment, Signature)>) {
		// TODO: Encrypt the htlc_outputs data with the single-hash of the commitment transaction
		// so that a remote monitor doesn't learn anything unless there is a malicious close.
		self.claimable_outpoints.insert(commitment_tx.txid(), PerCommitmentTransactionData{
			revoked_output_index: revokeable_out_index,
			htlcs: htlc_outputs
		});
	}

	pub fn insert_combine(&mut self, other: ChannelMonitor) -> Result<(), HandleError> {
		match self.funding_txo {
			Some(txo) => if other.funding_txo.is_some() && other.funding_txo.unwrap() != txo {
				return Err(HandleError{err: "Funding transaction outputs are not identical!", msg: None});
			},
			None => if other.funding_txo.is_some() {
				self.funding_txo = other.funding_txo;
			}
		}
		let other_max_secret = other.get_min_seen_secret();
		if self.get_min_seen_secret() > other_max_secret {
			self.provide_secret(other_max_secret, other.get_secret(other_max_secret).unwrap())
		} else { Ok(()) }
	}

	/// Panics if commitment_transaction_number_obscure_factor doesn't fit in 48 bits
	pub fn set_commitment_obscure_factor(&mut self, commitment_transaction_number_obscure_factor: u64) {
		assert!(commitment_transaction_number_obscure_factor < (1 << 48));
		self.commitment_transaction_number_obscure_factor = commitment_transaction_number_obscure_factor;
	}

	/// Allows this monitor to scan only for transactions which are applicable. Note that this is
	/// optional, without it this monitor cannot be used in an SPV client, but you may wish to
	/// avoid this (or call unset_funding_info) on a monitor you wish to send to a watchtower as it
	/// provides slightly better privacy.
	pub fn set_funding_info(&mut self, funding_txid: Sha256dHash, funding_output_index: u16) {
		self.funding_txo = Some((funding_txid, funding_output_index));
	}

	pub fn set_their_htlc_base_key(&mut self, their_htlc_base_key: &PublicKey) {
		self.their_htlc_base_key = Some(their_htlc_base_key.clone());
	}

	pub fn unset_funding_info(&mut self) {
		self.funding_txo = None;
	}

	pub fn get_funding_txo(&self) -> Option<(Sha256dHash, u16)> {
		self.funding_txo
	}

	//TODO: Functions to serialize/deserialize (with different forms depending on which information
	//we want to leave out (eg funding_txo, etc).

	/// Can only fail if idx is < get_min_seen_secret
	pub fn get_secret(&self, idx: u64) -> Result<[u8; 32], HandleError> {
		for i in 0..self.old_secrets.len() {
			if (idx & (!((1 << i) - 1))) == self.old_secrets[i].1 {
				return Ok(ChannelMonitor::derive_secret(self.old_secrets[i].0, i as u8, idx))
			}
		}
		assert!(idx < self.get_min_seen_secret());
		Err(HandleError{err: "idx too low", msg: None})
	}

	pub fn get_min_seen_secret(&self) -> u64 {
		//TODO This can be optimized?
		let mut min = 1 << 48;
		for &(_, idx) in self.old_secrets.iter() {
			if idx < min {
				min = idx;
			}
		}
		min
	}

	#[inline]
	fn check_spend_transaction(&self, tx: &Transaction, height: u32) -> Vec<Transaction> {
		// Most secp and related errors trying to create keys means we have no hope of constructing
		// a spend transaction...so we return no transactions to broadcast
		macro_rules! ignore_error {
			( $thing : expr ) => {
				match $thing {
					Ok(a) => a,
					Err(_) => return Vec::new()
				}
			};
		}

		let mut txn_to_broadcast = Vec::new();

		let commitment_number = (((tx.input[0].sequence as u64 & 0xffffff) << 3*8) | (tx.lock_time as u64 & 0xffffff)) ^ self.commitment_transaction_number_obscure_factor;
		if commitment_number >= self.get_min_seen_secret() {
			let secret = self.get_secret(commitment_number).unwrap();
			let per_commitment_key = ignore_error!(SecretKey::from_slice(&self.secp_ctx, &secret));
			let revocation_pubkey = match self.revocation_base_key {
				RevocationStorage::PrivMode { ref revocation_base_key } => {
					ignore_error!(chan_utils::derive_public_revocation_key(&self.secp_ctx, &ignore_error!(PublicKey::from_secret_key(&self.secp_ctx, &per_commitment_key)), &ignore_error!(PublicKey::from_secret_key(&self.secp_ctx, &revocation_base_key))))
				},
				RevocationStorage::SigsMode { ref revocation_base_key, .. } => {
					ignore_error!(chan_utils::derive_public_revocation_key(&self.secp_ctx, &ignore_error!(PublicKey::from_secret_key(&self.secp_ctx, &per_commitment_key)), &revocation_base_key))
				},
			};
			let delayed_key = ignore_error!(chan_utils::derive_public_key(&self.secp_ctx, &ignore_error!(PublicKey::from_secret_key(&self.secp_ctx, &per_commitment_key)), &self.delayed_payment_base_key));
			let a_htlc_key = ignore_error!(chan_utils::derive_public_key(&self.secp_ctx, &ignore_error!(PublicKey::from_secret_key(&self.secp_ctx, &per_commitment_key)), &self.htlc_base_key));
			let b_htlc_key = match self.their_htlc_base_key {
				None => return Vec::new(),
				Some(their_htlc_base_key) => ignore_error!(chan_utils::derive_public_key(&self.secp_ctx, &ignore_error!(PublicKey::from_secret_key(&self.secp_ctx, &per_commitment_key)), &their_htlc_base_key)),
			};

			let revokeable_redeemscript = chan_utils::get_revokeable_redeemscript(&revocation_pubkey, self.to_self_delay, &delayed_key);

			let commitment_txid = tx.txid();

			let mut total_value = 0;
			let mut values = Vec::new();
			let inputs = match self.claimable_outpoints.get(&commitment_txid) {
				Some(per_commitment_data) => {
					let mut inp = Vec::with_capacity(per_commitment_data.htlcs.len() + 1);

					if per_commitment_data.revoked_output_index as usize >= tx.output.len() || tx.output[per_commitment_data.revoked_output_index as usize].script_pubkey != revokeable_redeemscript.to_v0_p2wsh() {
						return Vec::new(); // Corrupted per_commitment_data, not much we can do
					}

					inp.push(TxIn {
						prev_hash: commitment_txid,
						prev_index: per_commitment_data.revoked_output_index,
						script_sig: Script::new(),
						sequence: 0xffffffff,
					});
					values.push(tx.output[per_commitment_data.revoked_output_index as usize].value);
					total_value += tx.output[per_commitment_data.revoked_output_index as usize].value;

					for &(ref htlc, ref _next_tx_sig) in per_commitment_data.htlcs.iter() {
						let expected_script = chan_utils::get_htlc_redeemscript_with_explicit_keys(&htlc, &a_htlc_key, &b_htlc_key, &revocation_pubkey, htlc.offered);
						if htlc.transaction_output_index as usize >= tx.output.len() ||
								tx.output[htlc.transaction_output_index as usize].value != htlc.amount_msat / 1000 ||
								tx.output[htlc.transaction_output_index as usize].script_pubkey != expected_script.to_v0_p2wsh() {
							return Vec::new(); // Corrupted per_commitment_data, fuck this user
						}
						if htlc.cltv_expiry > height + CLTV_CLAIM_BUFFER {
							inp.push(TxIn {
								prev_hash: commitment_txid,
								prev_index: htlc.transaction_output_index,
								script_sig: Script::new(),
								sequence: 0xffffffff,
							});
							values.push(tx.output[htlc.transaction_output_index as usize].value);
							total_value += htlc.amount_msat / 1000;
						} else {
							//TODO: Mark as "bad"
							//then broadcast using next_tx_sig
						}
					}
					inp
				}, None => {
					let mut inp = Vec::new(); // This is unlikely to succeed
					for (idx, outp) in tx.output.iter().enumerate() {
						if outp.script_pubkey == revokeable_redeemscript.to_v0_p2wsh() {
							inp.push(TxIn {
								prev_hash: commitment_txid,
								prev_index: idx as u32,
								script_sig: Script::new(),
								sequence: 0xffffffff,
							});
							values.push(outp.value);
							total_value += outp.value;
							break; // There can only be one of these
						}
					}
					if inp.is_empty() { return Vec::new(); } // Nothing to be done...probably a false positive
					inp
				}
			};

			let outputs = vec!(TxOut {
				script_pubkey: self.destination_script.clone(),
				value: total_value, //TODO: - fee
			});
			let mut spend_tx = Transaction {
				version: 2,
				lock_time: 0,
				input: inputs,
				output: outputs,
				witness: Vec::new(),
			};

			let mut values_drain = values.drain(..);

			// First input is the generic revokeable_redeemscript
			// TODO: Make one SighashComponents and use that throughout instead of re-building it
			// each time.
			{
				let sig = match self.revocation_base_key {
					RevocationStorage::PrivMode { ref revocation_base_key } => {
						let sighash = ignore_error!(Message::from_slice(&bip143::SighashComponents::new(&spend_tx).sighash_all(&spend_tx, 0, &revokeable_redeemscript, values_drain.next().unwrap())[..]));
						let revocation_key = ignore_error!(chan_utils::derive_private_revocation_key(&self.secp_ctx, &per_commitment_key, &revocation_base_key));
						ignore_error!(self.secp_ctx.sign(&sighash, &revocation_key))
					},
					RevocationStorage::SigsMode { .. } => {
						unimplemented!();
					}
				};

				spend_tx.witness.push(Vec::new());
				spend_tx.witness[0].push(sig.serialize_der(&self.secp_ctx).to_vec());
				spend_tx.witness[0][0].push(SigHashType::All as u8);
				spend_tx.witness[0].push(vec!(1)); // First if branch is revocation_key
			}

			match self.claimable_outpoints.get(&commitment_txid) {
				None => {},
				Some(per_commitment_data) => {
					let mut htlc_idx = 0;
					for (idx, _) in spend_tx.input.iter().enumerate() {
						if idx == 0 { continue; } // We already signed the first input

						let mut htlc;
						while {
							htlc = &per_commitment_data.htlcs[htlc_idx].0;
							htlc_idx += 1;
							htlc.cltv_expiry > height + CLTV_CLAIM_BUFFER
						} {}

						let sig = match self.revocation_base_key {
							RevocationStorage::PrivMode { ref revocation_base_key } => {
								let htlc_redeemscript = chan_utils::get_htlc_redeemscript_with_explicit_keys(htlc, &a_htlc_key, &b_htlc_key, &revocation_pubkey, htlc.offered);
								let sighash = ignore_error!(Message::from_slice(&bip143::SighashComponents::new(&spend_tx).sighash_all(&spend_tx, idx, &htlc_redeemscript, values_drain.next().unwrap())[..]));

								let revocation_key = ignore_error!(chan_utils::derive_private_revocation_key(&self.secp_ctx, &per_commitment_key, &revocation_base_key));
								ignore_error!(self.secp_ctx.sign(&sighash, &revocation_key))
							},
							RevocationStorage::SigsMode { .. } => {
								unimplemented!();
							}
						};

						spend_tx.witness.push(Vec::new());
						spend_tx.witness[0].push(revocation_pubkey.serialize().to_vec()); // First if branch is revocation_key
						spend_tx.witness[0].push(sig.serialize_der(&self.secp_ctx).to_vec());
						spend_tx.witness[0][0].push(SigHashType::All as u8);
					}
				}
			}

			txn_to_broadcast.push(spend_tx);
		}

		txn_to_broadcast
	}

	fn block_connected(&self, txn_matched: &[&Transaction], height: u32, broadcaster: &BroadcasterInterface) {
		for tx in txn_matched {
			if tx.input.len() != 1 {
				// We currently only ever sign something spending a commitment or HTLC
				// transaction with 1 input, so we can skip most transactions trivially.
				continue;
			}

			for txin in tx.input.iter() {
				if self.funding_txo.is_none() || (txin.prev_hash == self.funding_txo.unwrap().0 && txin.prev_index == self.funding_txo.unwrap().1 as u32) {
					for tx in self.check_spend_transaction(tx, height).iter() {
						broadcaster.broadcast_transaction(tx);
					}
				}
			}
		}
	}
}

#[cfg(test)]
mod tests {
	use bitcoin::util::misc::hex_bytes;
	use bitcoin::blockdata::script::Script;
	use ln::channelmonitor::ChannelMonitor;
	use secp256k1::key::{SecretKey,PublicKey};
	use secp256k1::Secp256k1;

	#[test]
	fn test_per_commitment_storage() {
		// Test vectors from BOLT 3:
		let mut secrets: Vec<[u8; 32]> = Vec::new();
		let mut monitor: ChannelMonitor;
		let secp_ctx = Secp256k1::new();

		macro_rules! test_secrets {
			() => {
				let mut idx = 281474976710655;
				for secret in secrets.iter() {
					assert_eq!(monitor.get_secret(idx).unwrap(), *secret);
					idx -= 1;
				}
				assert_eq!(monitor.get_min_seen_secret(), idx + 1);
				assert!(monitor.get_secret(idx).is_err());
			};
		}

		{
			// insert_secret correct sequence
			monitor = ChannelMonitor::new(&SecretKey::from_slice(&secp_ctx, &[42; 32]).unwrap(), &PublicKey::new(), &PublicKey::new(), 0, Script::new());
			secrets.clear();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("7cc854b54e3e0dcdb010d7a3fee464a9687be6e8db3be6854c475621e007a5dc").unwrap());
			monitor.provide_secret(281474976710655, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("c7518c8ae4660ed02894df8976fa1a3659c1a8b4b5bec0c4b872abeba4cb8964").unwrap());
			monitor.provide_secret(281474976710654, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("2273e227a5b7449b6e70f1fb4652864038b1cbf9cd7c043a7d6456b7fc275ad8").unwrap());
			monitor.provide_secret(281474976710653, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("27cddaa5624534cb6cb9d7da077cf2b22ab21e9b506fd4998a51d54502e99116").unwrap());
			monitor.provide_secret(281474976710652, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("c65716add7aa98ba7acb236352d665cab17345fe45b55fb879ff80e6bd0c41dd").unwrap());
			monitor.provide_secret(281474976710651, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("969660042a28f32d9be17344e09374b379962d03db1574df5a8a5a47e19ce3f2").unwrap());
			monitor.provide_secret(281474976710650, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("a5a64476122ca0925fb344bdc1854c1c0a59fc614298e50a33e331980a220f32").unwrap());
			monitor.provide_secret(281474976710649, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("05cde6323d949933f7f7b78776bcc1ea6d9b31447732e3802e1f7ac44b650e17").unwrap());
			monitor.provide_secret(281474976710648, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();
		}

		{
			// insert_secret #1 incorrect
			monitor = ChannelMonitor::new(&SecretKey::from_slice(&secp_ctx, &[42; 32]).unwrap(), &PublicKey::new(), &PublicKey::new(), 0, Script::new());
			secrets.clear();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("02a40c85b6f28da08dfdbe0926c53fab2de6d28c10301f8f7c4073d5e42e3148").unwrap());
			monitor.provide_secret(281474976710655, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("c7518c8ae4660ed02894df8976fa1a3659c1a8b4b5bec0c4b872abeba4cb8964").unwrap());
			assert_eq!(monitor.provide_secret(281474976710654, secrets.last().unwrap().clone()).unwrap_err().err,
					"Previous secret did not match new one");
		}

		{
			// insert_secret #2 incorrect (#1 derived from incorrect)
			monitor = ChannelMonitor::new(&SecretKey::from_slice(&secp_ctx, &[42; 32]).unwrap(), &PublicKey::new(), &PublicKey::new(), 0, Script::new());
			secrets.clear();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("02a40c85b6f28da08dfdbe0926c53fab2de6d28c10301f8f7c4073d5e42e3148").unwrap());
			monitor.provide_secret(281474976710655, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("dddc3a8d14fddf2b68fa8c7fbad2748274937479dd0f8930d5ebb4ab6bd866a3").unwrap());
			monitor.provide_secret(281474976710654, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("2273e227a5b7449b6e70f1fb4652864038b1cbf9cd7c043a7d6456b7fc275ad8").unwrap());
			monitor.provide_secret(281474976710653, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("27cddaa5624534cb6cb9d7da077cf2b22ab21e9b506fd4998a51d54502e99116").unwrap());
			assert_eq!(monitor.provide_secret(281474976710652, secrets.last().unwrap().clone()).unwrap_err().err,
					"Previous secret did not match new one");
		}

		{
			// insert_secret #3 incorrect
			monitor = ChannelMonitor::new(&SecretKey::from_slice(&secp_ctx, &[42; 32]).unwrap(), &PublicKey::new(), &PublicKey::new(), 0, Script::new());
			secrets.clear();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("7cc854b54e3e0dcdb010d7a3fee464a9687be6e8db3be6854c475621e007a5dc").unwrap());
			monitor.provide_secret(281474976710655, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("c7518c8ae4660ed02894df8976fa1a3659c1a8b4b5bec0c4b872abeba4cb8964").unwrap());
			monitor.provide_secret(281474976710654, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("c51a18b13e8527e579ec56365482c62f180b7d5760b46e9477dae59e87ed423a").unwrap());
			monitor.provide_secret(281474976710653, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("27cddaa5624534cb6cb9d7da077cf2b22ab21e9b506fd4998a51d54502e99116").unwrap());
			assert_eq!(monitor.provide_secret(281474976710652, secrets.last().unwrap().clone()).unwrap_err().err,
					"Previous secret did not match new one");
		}

		{
			// insert_secret #4 incorrect (1,2,3 derived from incorrect)
			monitor = ChannelMonitor::new(&SecretKey::from_slice(&secp_ctx, &[42; 32]).unwrap(), &PublicKey::new(), &PublicKey::new(), 0, Script::new());
			secrets.clear();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("02a40c85b6f28da08dfdbe0926c53fab2de6d28c10301f8f7c4073d5e42e3148").unwrap());
			monitor.provide_secret(281474976710655, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("dddc3a8d14fddf2b68fa8c7fbad2748274937479dd0f8930d5ebb4ab6bd866a3").unwrap());
			monitor.provide_secret(281474976710654, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("c51a18b13e8527e579ec56365482c62f180b7d5760b46e9477dae59e87ed423a").unwrap());
			monitor.provide_secret(281474976710653, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("ba65d7b0ef55a3ba300d4e87af29868f394f8f138d78a7011669c79b37b936f4").unwrap());
			monitor.provide_secret(281474976710652, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("c65716add7aa98ba7acb236352d665cab17345fe45b55fb879ff80e6bd0c41dd").unwrap());
			monitor.provide_secret(281474976710651, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("969660042a28f32d9be17344e09374b379962d03db1574df5a8a5a47e19ce3f2").unwrap());
			monitor.provide_secret(281474976710650, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("a5a64476122ca0925fb344bdc1854c1c0a59fc614298e50a33e331980a220f32").unwrap());
			monitor.provide_secret(281474976710649, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("05cde6323d949933f7f7b78776bcc1ea6d9b31447732e3802e1f7ac44b650e17").unwrap());
			assert_eq!(monitor.provide_secret(281474976710648, secrets.last().unwrap().clone()).unwrap_err().err,
					"Previous secret did not match new one");
		}

		{
			// insert_secret #5 incorrect
			monitor = ChannelMonitor::new(&SecretKey::from_slice(&secp_ctx, &[42; 32]).unwrap(), &PublicKey::new(), &PublicKey::new(), 0, Script::new());
			secrets.clear();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("7cc854b54e3e0dcdb010d7a3fee464a9687be6e8db3be6854c475621e007a5dc").unwrap());
			monitor.provide_secret(281474976710655, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("c7518c8ae4660ed02894df8976fa1a3659c1a8b4b5bec0c4b872abeba4cb8964").unwrap());
			monitor.provide_secret(281474976710654, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("2273e227a5b7449b6e70f1fb4652864038b1cbf9cd7c043a7d6456b7fc275ad8").unwrap());
			monitor.provide_secret(281474976710653, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("27cddaa5624534cb6cb9d7da077cf2b22ab21e9b506fd4998a51d54502e99116").unwrap());
			monitor.provide_secret(281474976710652, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("631373ad5f9ef654bb3dade742d09504c567edd24320d2fcd68e3cc47e2ff6a6").unwrap());
			monitor.provide_secret(281474976710651, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("969660042a28f32d9be17344e09374b379962d03db1574df5a8a5a47e19ce3f2").unwrap());
			assert_eq!(monitor.provide_secret(281474976710650, secrets.last().unwrap().clone()).unwrap_err().err,
					"Previous secret did not match new one");
		}

		{
			// insert_secret #6 incorrect (5 derived from incorrect)
			monitor = ChannelMonitor::new(&SecretKey::from_slice(&secp_ctx, &[42; 32]).unwrap(), &PublicKey::new(), &PublicKey::new(), 0, Script::new());
			secrets.clear();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("7cc854b54e3e0dcdb010d7a3fee464a9687be6e8db3be6854c475621e007a5dc").unwrap());
			monitor.provide_secret(281474976710655, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("c7518c8ae4660ed02894df8976fa1a3659c1a8b4b5bec0c4b872abeba4cb8964").unwrap());
			monitor.provide_secret(281474976710654, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("2273e227a5b7449b6e70f1fb4652864038b1cbf9cd7c043a7d6456b7fc275ad8").unwrap());
			monitor.provide_secret(281474976710653, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("27cddaa5624534cb6cb9d7da077cf2b22ab21e9b506fd4998a51d54502e99116").unwrap());
			monitor.provide_secret(281474976710652, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("631373ad5f9ef654bb3dade742d09504c567edd24320d2fcd68e3cc47e2ff6a6").unwrap());
			monitor.provide_secret(281474976710651, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("b7e76a83668bde38b373970155c868a653304308f9896692f904a23731224bb1").unwrap());
			monitor.provide_secret(281474976710650, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("a5a64476122ca0925fb344bdc1854c1c0a59fc614298e50a33e331980a220f32").unwrap());
			monitor.provide_secret(281474976710649, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("05cde6323d949933f7f7b78776bcc1ea6d9b31447732e3802e1f7ac44b650e17").unwrap());
			assert_eq!(monitor.provide_secret(281474976710648, secrets.last().unwrap().clone()).unwrap_err().err,
					"Previous secret did not match new one");
		}

		{
			// insert_secret #7 incorrect
			monitor = ChannelMonitor::new(&SecretKey::from_slice(&secp_ctx, &[42; 32]).unwrap(), &PublicKey::new(), &PublicKey::new(), 0, Script::new());
			secrets.clear();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("7cc854b54e3e0dcdb010d7a3fee464a9687be6e8db3be6854c475621e007a5dc").unwrap());
			monitor.provide_secret(281474976710655, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("c7518c8ae4660ed02894df8976fa1a3659c1a8b4b5bec0c4b872abeba4cb8964").unwrap());
			monitor.provide_secret(281474976710654, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("2273e227a5b7449b6e70f1fb4652864038b1cbf9cd7c043a7d6456b7fc275ad8").unwrap());
			monitor.provide_secret(281474976710653, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("27cddaa5624534cb6cb9d7da077cf2b22ab21e9b506fd4998a51d54502e99116").unwrap());
			monitor.provide_secret(281474976710652, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("c65716add7aa98ba7acb236352d665cab17345fe45b55fb879ff80e6bd0c41dd").unwrap());
			monitor.provide_secret(281474976710651, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("969660042a28f32d9be17344e09374b379962d03db1574df5a8a5a47e19ce3f2").unwrap());
			monitor.provide_secret(281474976710650, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("e7971de736e01da8ed58b94c2fc216cb1dca9e326f3a96e7194fe8ea8af6c0a3").unwrap());
			monitor.provide_secret(281474976710649, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("05cde6323d949933f7f7b78776bcc1ea6d9b31447732e3802e1f7ac44b650e17").unwrap());
			assert_eq!(monitor.provide_secret(281474976710648, secrets.last().unwrap().clone()).unwrap_err().err,
					"Previous secret did not match new one");
		}

		{
			// insert_secret #8 incorrect
			monitor = ChannelMonitor::new(&SecretKey::from_slice(&secp_ctx, &[42; 32]).unwrap(), &PublicKey::new(), &PublicKey::new(), 0, Script::new());
			secrets.clear();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("7cc854b54e3e0dcdb010d7a3fee464a9687be6e8db3be6854c475621e007a5dc").unwrap());
			monitor.provide_secret(281474976710655, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("c7518c8ae4660ed02894df8976fa1a3659c1a8b4b5bec0c4b872abeba4cb8964").unwrap());
			monitor.provide_secret(281474976710654, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("2273e227a5b7449b6e70f1fb4652864038b1cbf9cd7c043a7d6456b7fc275ad8").unwrap());
			monitor.provide_secret(281474976710653, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("27cddaa5624534cb6cb9d7da077cf2b22ab21e9b506fd4998a51d54502e99116").unwrap());
			monitor.provide_secret(281474976710652, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("c65716add7aa98ba7acb236352d665cab17345fe45b55fb879ff80e6bd0c41dd").unwrap());
			monitor.provide_secret(281474976710651, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("969660042a28f32d9be17344e09374b379962d03db1574df5a8a5a47e19ce3f2").unwrap());
			monitor.provide_secret(281474976710650, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("a5a64476122ca0925fb344bdc1854c1c0a59fc614298e50a33e331980a220f32").unwrap());
			monitor.provide_secret(281474976710649, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("a7efbc61aac46d34f77778bac22c8a20c6a46ca460addc49009bda875ec88fa4").unwrap());
			assert_eq!(monitor.provide_secret(281474976710648, secrets.last().unwrap().clone()).unwrap_err().err,
					"Previous secret did not match new one");
		}
	}
}
