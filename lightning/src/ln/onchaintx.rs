//! The logic to build claims and bump in-flight transactions until confirmations.
//!
//! OnchainTxHandler objetcs are fully-part of ChannelMonitor and encapsulates all
//! building, tracking, bumping and notifications functions.

use bitcoin::blockdata::transaction::{Transaction, TxIn, TxOut, SigHashType};
use bitcoin::blockdata::transaction::OutPoint as BitcoinOutPoint;
use bitcoin::blockdata::script::Script;
use bitcoin::util::bip143;

use bitcoin_hashes::sha256d::Hash as Sha256dHash;

use secp256k1::Secp256k1;
use secp256k1;

use ln::msgs::DecodeError;
use ln::channelmonitor::{ANTI_REORG_DELAY, CLTV_SHARED_CLAIM_BUFFER, InputMaterial, ClaimRequest};
use ln::channelmanager::PaymentPreimage;
use ln::chan_utils::{HTLCType, LocalCommitmentTransaction};
use chain::chaininterface::{FeeEstimator, BroadcasterInterface, ConfirmationTarget, MIN_RELAY_FEE_SAT_PER_1000_WEIGHT};
use chain::keysinterface::ChannelKeys;
use util::logger::Logger;
use util::ser::{ReadableArgs, Readable, Writer, Writeable};
use util::byte_utils;

use std::collections::{HashMap, hash_map};
use std::sync::Arc;
use std::cmp;
use std::ops::Deref;

const MAX_ALLOC_SIZE: usize = 64*1024;

/// Upon discovering of some classes of onchain tx by ChannelMonitor, we may have to take actions on it
/// once they mature to enough confirmations (ANTI_REORG_DELAY)
#[derive(Clone, PartialEq)]
enum OnchainEvent {
	/// Outpoint under claim process by our own tx, once this one get enough confirmations, we remove it from
	/// bump-txn candidate buffer.
	Claim {
		claim_request: Sha256dHash,
	},
	/// Claim tx aggregate multiple claimable outpoints. One of the outpoint may be claimed by a remote party tx.
	/// In this case, we need to drop the outpoint and regenerate a new claim tx. By safety, we keep tracking
	/// the outpoint to be sure to resurect it back to the claim tx if reorgs happen.
	ContentiousOutpoint {
		outpoint: BitcoinOutPoint,
		input_material: InputMaterial,
	}
}

/// Higher-level cache structure needed to re-generate bumped claim txn if needed
#[derive(Clone, PartialEq)]
pub struct ClaimTxBumpMaterial {
	// At every block tick, used to check if pending claiming tx is taking too
	// much time for confirmation and we need to bump it.
	height_timer: Option<u32>,
	// Tracked in case of reorg to wipe out now-superflous bump material
	feerate_previous: u64,
	// Soonest timelocks among set of outpoints claimed, used to compute
	// a priority of not feerate
	soonest_timelock: u32,
	// Cache of script, pubkey, sig or key to solve claimable outputs scriptpubkey.
	per_input_material: HashMap<BitcoinOutPoint, InputMaterial>,
}

impl Writeable for ClaimTxBumpMaterial  {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
		self.height_timer.write(writer)?;
		writer.write_all(&byte_utils::be64_to_array(self.feerate_previous))?;
		writer.write_all(&byte_utils::be32_to_array(self.soonest_timelock))?;
		writer.write_all(&byte_utils::be64_to_array(self.per_input_material.len() as u64))?;
		for (outp, tx_material) in self.per_input_material.iter() {
			outp.write(writer)?;
			tx_material.write(writer)?;
		}
		Ok(())
	}
}

impl Readable for ClaimTxBumpMaterial {
	fn read<R: ::std::io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
		let height_timer = Readable::read(reader)?;
		let feerate_previous = Readable::read(reader)?;
		let soonest_timelock = Readable::read(reader)?;
		let per_input_material_len: u64 = Readable::read(reader)?;
		let mut per_input_material = HashMap::with_capacity(cmp::min(per_input_material_len as usize, MAX_ALLOC_SIZE / 128));
		for _ in 0 ..per_input_material_len {
			let outpoint = Readable::read(reader)?;
			let input_material = Readable::read(reader)?;
			per_input_material.insert(outpoint, input_material);
		}
		Ok(Self { height_timer, feerate_previous, soonest_timelock, per_input_material })
	}
}

#[derive(PartialEq)]
pub(super) enum InputDescriptors {
	RevokedOfferedHTLC,
	RevokedReceivedHTLC,
	OfferedHTLC,
	ReceivedHTLC,
	RevokedOutput, // either a revoked to_local output on commitment tx, a revoked HTLC-Timeout output or a revoked HTLC-Success output
}

macro_rules! subtract_high_prio_fee {
	($self: ident, $fee_estimator: expr, $value: expr, $predicted_weight: expr, $used_feerate: expr) => {
		{
			$used_feerate = $fee_estimator.get_est_sat_per_1000_weight(ConfirmationTarget::HighPriority);
			let mut fee = $used_feerate * ($predicted_weight as u64) / 1000;
			if $value <= fee {
				$used_feerate = $fee_estimator.get_est_sat_per_1000_weight(ConfirmationTarget::Normal);
				fee = $used_feerate * ($predicted_weight as u64) / 1000;
				if $value <= fee {
					$used_feerate = $fee_estimator.get_est_sat_per_1000_weight(ConfirmationTarget::Background);
					fee = $used_feerate * ($predicted_weight as u64) / 1000;
					if $value <= fee {
						log_error!($self, "Failed to generate an on-chain punishment tx as even low priority fee ({} sat) was more than the entire claim balance ({} sat)",
							fee, $value);
						false
					} else {
						log_warn!($self, "Used low priority fee for on-chain punishment tx as high priority fee was more than the entire claim balance ({} sat)",
							$value);
						$value -= fee;
						true
					}
				} else {
					log_warn!($self, "Used medium priority fee for on-chain punishment tx as high priority fee was more than the entire claim balance ({} sat)",
						$value);
					$value -= fee;
					true
				}
			} else {
				$value -= fee;
				true
			}
		}
	}
}


/// OnchainTxHandler receives claiming requests, aggregates them if it's sound, broadcast and
/// do RBF bumping if possible.
pub struct OnchainTxHandler<ChanSigner: ChannelKeys> {
	destination_script: Script,
	funding_redeemscript: Script,
	local_commitment: Option<LocalCommitmentTransaction>,
	prev_local_commitment: Option<LocalCommitmentTransaction>,
	local_csv: u16,

	key_storage: ChanSigner,

	// Used to track claiming requests. If claim tx doesn't confirm before height timer expiration we need to bump
	// it (RBF or CPFP). If an input has been part of an aggregate tx at first claim try, we need to keep it within
	// another bumped aggregate tx to comply with RBF rules. We may have multiple claiming txn in the flight for the
	// same set of outpoints. One of the outpoints may be spent by a transaction not issued by us. That's why at
	// block connection we scan all inputs and if any of them is among a set of a claiming request we test for set
	// equality between spending transaction and claim request. If true, it means transaction was one our claiming one
	// after a security delay of 6 blocks we remove pending claim request. If false, it means transaction wasn't and
	// we need to regenerate new claim request with reduced set of still-claimable outpoints.
	// Key is identifier of the pending claim request, i.e the txid of the initial claiming transaction generated by
	// us and is immutable until all outpoint of the claimable set are post-anti-reorg-delay solved.
	// Entry is cache of elements need to generate a bumped claiming transaction (see ClaimTxBumpMaterial)
	#[cfg(test)] // Used in functional_test to verify sanitization
	pub pending_claim_requests: HashMap<Sha256dHash, ClaimTxBumpMaterial>,
	#[cfg(not(test))]
	pending_claim_requests: HashMap<Sha256dHash, ClaimTxBumpMaterial>,

	// Used to link outpoints claimed in a connected block to a pending claim request.
	// Key is outpoint than monitor parsing has detected we have keys/scripts to claim
	// Value is (pending claim request identifier, confirmation_block), identifier
	// is txid of the initial claiming transaction and is immutable until outpoint is
	// post-anti-reorg-delay solved, confirmaiton_block is used to erase entry if
	// block with output gets disconnected.
	#[cfg(test)] // Used in functional_test to verify sanitization
	pub claimable_outpoints: HashMap<BitcoinOutPoint, (Sha256dHash, u32)>,
	#[cfg(not(test))]
	claimable_outpoints: HashMap<BitcoinOutPoint, (Sha256dHash, u32)>,

	onchain_events_waiting_threshold_conf: HashMap<u32, Vec<OnchainEvent>>,

	secp_ctx: Secp256k1<secp256k1::All>,
	logger: Arc<Logger>
}

impl<ChanSigner: ChannelKeys + Writeable> OnchainTxHandler<ChanSigner> {
	pub(crate) fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
		self.destination_script.write(writer)?;
		self.funding_redeemscript.write(writer)?;
		self.local_commitment.write(writer)?;
		self.prev_local_commitment.write(writer)?;

		self.local_csv.write(writer)?;

		self.key_storage.write(writer)?;

		writer.write_all(&byte_utils::be64_to_array(self.pending_claim_requests.len() as u64))?;
		for (ref ancestor_claim_txid, claim_tx_data) in self.pending_claim_requests.iter() {
			ancestor_claim_txid.write(writer)?;
			claim_tx_data.write(writer)?;
		}

		writer.write_all(&byte_utils::be64_to_array(self.claimable_outpoints.len() as u64))?;
		for (ref outp, ref claim_and_height) in self.claimable_outpoints.iter() {
			outp.write(writer)?;
			claim_and_height.0.write(writer)?;
			claim_and_height.1.write(writer)?;
		}

		writer.write_all(&byte_utils::be64_to_array(self.onchain_events_waiting_threshold_conf.len() as u64))?;
		for (ref target, ref events) in self.onchain_events_waiting_threshold_conf.iter() {
			writer.write_all(&byte_utils::be32_to_array(**target))?;
			writer.write_all(&byte_utils::be64_to_array(events.len() as u64))?;
			for ev in events.iter() {
				match *ev {
					OnchainEvent::Claim { ref claim_request } => {
						writer.write_all(&[0; 1])?;
						claim_request.write(writer)?;
					},
					OnchainEvent::ContentiousOutpoint { ref outpoint, ref input_material } => {
						writer.write_all(&[1; 1])?;
						outpoint.write(writer)?;
						input_material.write(writer)?;
					}
				}
			}
		}
		Ok(())
	}
}

impl<ChanSigner: ChannelKeys + Readable> ReadableArgs<Arc<Logger>> for OnchainTxHandler<ChanSigner> {
	fn read<R: ::std::io::Read>(reader: &mut R, logger: Arc<Logger>) -> Result<Self, DecodeError> {
		let destination_script = Readable::read(reader)?;
		let funding_redeemscript = Readable::read(reader)?;

		let local_commitment = Readable::read(reader)?;
		let prev_local_commitment = Readable::read(reader)?;

		let local_csv = Readable::read(reader)?;

		let key_storage = Readable::read(reader)?;

		let pending_claim_requests_len: u64 = Readable::read(reader)?;
		let mut pending_claim_requests = HashMap::with_capacity(cmp::min(pending_claim_requests_len as usize, MAX_ALLOC_SIZE / 128));
		for _ in 0..pending_claim_requests_len {
			pending_claim_requests.insert(Readable::read(reader)?, Readable::read(reader)?);
		}

		let claimable_outpoints_len: u64 = Readable::read(reader)?;
		let mut claimable_outpoints = HashMap::with_capacity(cmp::min(pending_claim_requests_len as usize, MAX_ALLOC_SIZE / 128));
		for _ in 0..claimable_outpoints_len {
			let outpoint = Readable::read(reader)?;
			let ancestor_claim_txid = Readable::read(reader)?;
			let height = Readable::read(reader)?;
			claimable_outpoints.insert(outpoint, (ancestor_claim_txid, height));
		}
		let waiting_threshold_conf_len: u64 = Readable::read(reader)?;
		let mut onchain_events_waiting_threshold_conf = HashMap::with_capacity(cmp::min(waiting_threshold_conf_len as usize, MAX_ALLOC_SIZE / 128));
		for _ in 0..waiting_threshold_conf_len {
			let height_target = Readable::read(reader)?;
			let events_len: u64 = Readable::read(reader)?;
			let mut events = Vec::with_capacity(cmp::min(events_len as usize, MAX_ALLOC_SIZE / 128));
			for _ in 0..events_len {
				let ev = match <u8 as Readable>::read(reader)? {
					0 => {
						let claim_request = Readable::read(reader)?;
						OnchainEvent::Claim {
							claim_request
						}
					},
					1 => {
						let outpoint = Readable::read(reader)?;
						let input_material = Readable::read(reader)?;
						OnchainEvent::ContentiousOutpoint {
							outpoint,
							input_material
						}
					}
					_ => return Err(DecodeError::InvalidValue),
				};
				events.push(ev);
			}
			onchain_events_waiting_threshold_conf.insert(height_target, events);
		}

		Ok(OnchainTxHandler {
			destination_script,
			funding_redeemscript,
			local_commitment,
			prev_local_commitment,
			local_csv,
			key_storage,
			claimable_outpoints,
			pending_claim_requests,
			onchain_events_waiting_threshold_conf,
			secp_ctx: Secp256k1::new(),
			logger,
		})
	}
}

impl<ChanSigner: ChannelKeys> OnchainTxHandler<ChanSigner> {
	pub(super) fn new(destination_script: Script, keys: ChanSigner, funding_redeemscript: Script, local_csv: u16, logger: Arc<Logger>) -> Self {

		let key_storage = keys;

		OnchainTxHandler {
			destination_script,
			funding_redeemscript,
			local_commitment: None,
			prev_local_commitment: None,
			local_csv,
			key_storage,
			pending_claim_requests: HashMap::new(),
			claimable_outpoints: HashMap::new(),
			onchain_events_waiting_threshold_conf: HashMap::new(),

			secp_ctx: Secp256k1::new(),
			logger,
		}
	}

	pub(super) fn get_witnesses_weight(inputs: &[InputDescriptors]) -> usize {
		let mut tx_weight = 2; // count segwit flags
		for inp in inputs {
			// We use expected weight (and not actual) as signatures and time lock delays may vary
			tx_weight +=  match inp {
				// number_of_witness_elements + sig_length + revocation_sig + pubkey_length + revocationpubkey + witness_script_length + witness_script
				&InputDescriptors::RevokedOfferedHTLC => {
					1 + 1 + 73 + 1 + 33 + 1 + 133
				},
				// number_of_witness_elements + sig_length + revocation_sig + pubkey_length + revocationpubkey + witness_script_length + witness_script
				&InputDescriptors::RevokedReceivedHTLC => {
					1 + 1 + 73 + 1 + 33 + 1 + 139
				},
				// number_of_witness_elements + sig_length + remotehtlc_sig  + preimage_length + preimage + witness_script_length + witness_script
				&InputDescriptors::OfferedHTLC => {
					1 + 1 + 73 + 1 + 32 + 1 + 133
				},
				// number_of_witness_elements + sig_length + revocation_sig + pubkey_length + revocationpubkey + witness_script_length + witness_script
				&InputDescriptors::ReceivedHTLC => {
					1 + 1 + 73 + 1 + 1 + 1 + 139
				},
				// number_of_witness_elements + sig_length + revocation_sig + true_length + op_true + witness_script_length + witness_script
				&InputDescriptors::RevokedOutput => {
					1 + 1 + 73 + 1 + 1 + 1 + 77
				},
			};
		}
		tx_weight
	}

	/// In LN, output claimed are time-sensitive, which means we have to spend them before reaching some timelock expiration. At in-channel
	/// output detection, we generate a first version of a claim tx and associate to it a height timer. A height timer is an absolute block
	/// height than once reached we should generate a new bumped "version" of the claim tx to be sure than we safely claim outputs before
	/// than our counterparty can do it too. If timelock expires soon, height timer is going to be scale down in consequence to increase
	/// frequency of the bump and so increase our bets of success.
	fn get_height_timer(current_height: u32, timelock_expiration: u32) -> u32 {
		if timelock_expiration <= current_height + 3 {
			return current_height + 1
		} else if timelock_expiration - current_height <= 15 {
			return current_height + 3
		}
		current_height + 15
	}

	/// Lightning security model (i.e being able to redeem/timeout HTLC or penalize coutnerparty onchain) lays on the assumption of claim transactions getting confirmed before timelock expiration
	/// (CSV or CLTV following cases). In case of high-fee spikes, claim tx may stuck in the mempool, so you need to bump its feerate quickly using Replace-By-Fee or Child-Pay-For-Parent.
	fn generate_claim_tx<F: Deref>(&mut self, height: u32, cached_claim_datas: &ClaimTxBumpMaterial, fee_estimator: F) -> Option<(Option<u32>, u64, Transaction)>
		where F::Target: FeeEstimator
	{
		if cached_claim_datas.per_input_material.len() == 0 { return None } // But don't prune pending claiming request yet, we may have to resurrect HTLCs
		let mut inputs = Vec::new();
		for outp in cached_claim_datas.per_input_material.keys() {
			log_trace!(self, "Outpoint {}:{}", outp.txid, outp.vout);
			inputs.push(TxIn {
				previous_output: *outp,
				script_sig: Script::new(),
				sequence: 0xfffffffd,
				witness: Vec::new(),
			});
		}
		let mut bumped_tx = Transaction {
			version: 2,
			lock_time: 0,
			input: inputs,
			output: vec![TxOut {
				script_pubkey: self.destination_script.clone(),
				value: 0
			}],
		};

		macro_rules! RBF_bump {
			($amount: expr, $old_feerate: expr, $fee_estimator: expr, $predicted_weight: expr) => {
				{
					let mut used_feerate;
					// If old feerate inferior to actual one given back by Fee Estimator, use it to compute new fee...
					let new_fee = if $old_feerate < $fee_estimator.get_est_sat_per_1000_weight(ConfirmationTarget::HighPriority) {
						let mut value = $amount;
						if subtract_high_prio_fee!(self, $fee_estimator, value, $predicted_weight, used_feerate) {
							// Overflow check is done in subtract_high_prio_fee
							$amount - value
						} else {
							log_trace!(self, "Can't new-estimation bump new claiming tx, amount {} is too small", $amount);
							return None;
						}
					// ...else just increase the previous feerate by 25% (because that's a nice number)
					} else {
						let fee = $old_feerate * $predicted_weight / 750;
						if $amount <= fee {
							log_trace!(self, "Can't 25% bump new claiming tx, amount {} is too small", $amount);
							return None;
						}
						fee
					};

					let previous_fee = $old_feerate * $predicted_weight / 1000;
					let min_relay_fee = MIN_RELAY_FEE_SAT_PER_1000_WEIGHT * $predicted_weight / 1000;
					// BIP 125 Opt-in Full Replace-by-Fee Signaling
					// 	* 3. The replacement transaction pays an absolute fee of at least the sum paid by the original transactions.
					//	* 4. The replacement transaction must also pay for its own bandwidth at or above the rate set by the node's minimum relay fee setting.
					let new_fee = if new_fee < previous_fee + min_relay_fee {
						new_fee + previous_fee + min_relay_fee - new_fee
					} else {
						new_fee
					};
					Some((new_fee, new_fee * 1000 / $predicted_weight))
				}
			}
		}

		// Compute new height timer to decide when we need to regenerate a new bumped version of the claim tx (if we
		// didn't receive confirmation of it before, or not enough reorg-safe depth on top of it).
		let new_timer = Some(Self::get_height_timer(height, cached_claim_datas.soonest_timelock));
		let mut inputs_witnesses_weight = 0;
		let mut amt = 0;
		let mut dynamic_fee = true;
		for per_outp_material in cached_claim_datas.per_input_material.values() {
			match per_outp_material {
				&InputMaterial::Revoked { ref witness_script, ref is_htlc, ref amount, .. } => {
					inputs_witnesses_weight += Self::get_witnesses_weight(if !is_htlc { &[InputDescriptors::RevokedOutput] } else if HTLCType::scriptlen_to_htlctype(witness_script.len()) == Some(HTLCType::OfferedHTLC) { &[InputDescriptors::RevokedOfferedHTLC] } else if HTLCType::scriptlen_to_htlctype(witness_script.len()) == Some(HTLCType::AcceptedHTLC) { &[InputDescriptors::RevokedReceivedHTLC] } else { unreachable!() });
					amt += *amount;
				},
				&InputMaterial::RemoteHTLC { ref preimage, ref amount, .. } => {
					inputs_witnesses_weight += Self::get_witnesses_weight(if preimage.is_some() { &[InputDescriptors::OfferedHTLC] } else { &[InputDescriptors::ReceivedHTLC] });
					amt += *amount;
				},
				&InputMaterial::LocalHTLC { .. } => {
					dynamic_fee = false;
				},
				&InputMaterial::Funding { .. } => {
					dynamic_fee = false;
				}
			}
		}
		if dynamic_fee {
			let predicted_weight = bumped_tx.get_weight() + inputs_witnesses_weight;
			let mut new_feerate;
			// If old feerate is 0, first iteration of this claim, use normal fee calculation
			if cached_claim_datas.feerate_previous != 0 {
				if let Some((new_fee, feerate)) = RBF_bump!(amt, cached_claim_datas.feerate_previous, fee_estimator, predicted_weight as u64) {
					// If new computed fee is superior at the whole claimable amount burn all in fees
					if new_fee > amt {
						bumped_tx.output[0].value = 0;
					} else {
						bumped_tx.output[0].value = amt - new_fee;
					}
					new_feerate = feerate;
				} else { return None; }
			} else {
				if subtract_high_prio_fee!(self, fee_estimator, amt, predicted_weight, new_feerate) {
					bumped_tx.output[0].value = amt;
				} else { return None; }
			}
			assert!(new_feerate != 0);

			for (i, (outp, per_outp_material)) in cached_claim_datas.per_input_material.iter().enumerate() {
				match per_outp_material {
					&InputMaterial::Revoked { ref witness_script, ref pubkey, ref key, ref is_htlc, ref amount } => {
						let sighash_parts = bip143::SighashComponents::new(&bumped_tx);
						let sighash = hash_to_message!(&sighash_parts.sighash_all(&bumped_tx.input[i], &witness_script, *amount)[..]);
						let sig = self.secp_ctx.sign(&sighash, &key);
						bumped_tx.input[i].witness.push(sig.serialize_der().to_vec());
						bumped_tx.input[i].witness[0].push(SigHashType::All as u8);
						if *is_htlc {
							bumped_tx.input[i].witness.push(pubkey.unwrap().clone().serialize().to_vec());
						} else {
							bumped_tx.input[i].witness.push(vec!(1));
						}
						bumped_tx.input[i].witness.push(witness_script.clone().into_bytes());
						log_trace!(self, "Going to broadcast Penalty Transaction {} claiming revoked {} output {} from {} with new feerate {}...", bumped_tx.txid(), if !is_htlc { "to_local" } else if HTLCType::scriptlen_to_htlctype(witness_script.len()) == Some(HTLCType::OfferedHTLC) { "offered" } else if HTLCType::scriptlen_to_htlctype(witness_script.len()) == Some(HTLCType::AcceptedHTLC) { "received" } else { "" }, outp.vout, outp.txid, new_feerate);
					},
					&InputMaterial::RemoteHTLC { ref witness_script, ref key, ref preimage, ref amount, ref locktime } => {
						if !preimage.is_some() { bumped_tx.lock_time = *locktime }; // Right now we don't aggregate time-locked transaction, if we do we should set lock_time before to avoid breaking hash computation
						let sighash_parts = bip143::SighashComponents::new(&bumped_tx);
						let sighash = hash_to_message!(&sighash_parts.sighash_all(&bumped_tx.input[i], &witness_script, *amount)[..]);
						let sig = self.secp_ctx.sign(&sighash, &key);
						bumped_tx.input[i].witness.push(sig.serialize_der().to_vec());
						bumped_tx.input[i].witness[0].push(SigHashType::All as u8);
						if let &Some(preimage) = preimage {
							bumped_tx.input[i].witness.push(preimage.clone().0.to_vec());
						} else {
							bumped_tx.input[i].witness.push(vec![]);
						}
						bumped_tx.input[i].witness.push(witness_script.clone().into_bytes());
						log_trace!(self, "Going to broadcast Claim Transaction {} claiming remote {} htlc output {} from {} with new feerate {}...", bumped_tx.txid(), if preimage.is_some() { "offered" } else { "received" }, outp.vout, outp.txid, new_feerate);
					},
					_ => unreachable!()
				}
			}
			log_trace!(self, "...with timer {}", new_timer.unwrap());
			assert!(predicted_weight >= bumped_tx.get_weight());
			return Some((new_timer, new_feerate, bumped_tx))
		} else {
			for (_, (outp, per_outp_material)) in cached_claim_datas.per_input_material.iter().enumerate() {
				match per_outp_material {
					&InputMaterial::LocalHTLC { ref preimage, ref amount } => {
						let mut htlc_tx = None;
						if let Some(ref mut local_commitment) = self.local_commitment {
							if local_commitment.txid() == outp.txid {
								self.key_storage.sign_htlc_transaction(local_commitment, outp.vout, *preimage, self.local_csv, &self.secp_ctx);
								htlc_tx = local_commitment.htlc_with_valid_witness(outp.vout).clone();
							}
						}
						if let Some(ref mut prev_local_commitment) = self.prev_local_commitment {
							if prev_local_commitment.txid() == outp.txid {
								self.key_storage.sign_htlc_transaction(prev_local_commitment, outp.vout, *preimage, self.local_csv, &self.secp_ctx);
								htlc_tx = prev_local_commitment.htlc_with_valid_witness(outp.vout).clone();
							}
						}
						if let Some(htlc_tx) = htlc_tx {
							let feerate = (amount - htlc_tx.output[0].value) * 1000 / htlc_tx.get_weight() as u64;
							// Timer set to $NEVER given we can't bump tx without anchor outputs
							log_trace!(self, "Going to broadcast Local HTLC-{} claiming HTLC output {} from {}...", if preimage.is_some() { "Success" } else { "Timeout" }, outp.vout, outp.txid);
							return Some((None, feerate, htlc_tx));
						}
						return None;
					},
					&InputMaterial::Funding { ref channel_value } => {
						if let Some(ref mut local_commitment) = self.local_commitment {
							self.key_storage.sign_local_commitment(local_commitment, &self.funding_redeemscript, *channel_value, &self.secp_ctx);
							let signed_tx = local_commitment.with_valid_witness().clone();
							let mut amt_outputs = 0;
							for outp in signed_tx.output.iter() {
								amt_outputs += outp.value;
							}
							let feerate = (channel_value - amt_outputs) * 1000 / signed_tx.get_weight() as u64;
							// Timer set to $NEVER given we can't bump tx without anchor outputs
							log_trace!(self, "Going to broadcast Local Transaction {} claiming funding output {} from {}...", signed_tx.txid(), outp.vout, outp.txid);
							return Some((None, feerate, signed_tx));
						}
					}
					_ => unreachable!()
				}
			}
		}
		None
	}

	pub(super) fn block_connected<B: Deref, F: Deref>(&mut self, txn_matched: &[&Transaction], claimable_outpoints: Vec<ClaimRequest>, height: u32, broadcaster: B, fee_estimator: F)
		where B::Target: BroadcasterInterface,
		      F::Target: FeeEstimator
	{
		log_trace!(self, "Block at height {} connected with {} claim requests", height, claimable_outpoints.len());
		let mut new_claims = Vec::new();
		let mut aggregated_claim = HashMap::new();
		let mut aggregated_soonest = ::std::u32::MAX;

		// Try to aggregate outputs if their timelock expiration isn't imminent (absolute_timelock
		// <= CLTV_SHARED_CLAIM_BUFFER) and they don't require an immediate nLockTime (aggregable).
		for req in claimable_outpoints {
			// Don't claim a outpoint twice that would be bad for privacy and may uselessly lock a CPFP input for a while
			if let Some(_) = self.claimable_outpoints.get(&req.outpoint) { log_trace!(self, "Bouncing off outpoint {}:{}, already registered its claiming request", req.outpoint.txid, req.outpoint.vout); } else {
				log_trace!(self, "Test if outpoint can be aggregated with expiration {} against {}", req.absolute_timelock, height + CLTV_SHARED_CLAIM_BUFFER);
				if req.absolute_timelock <= height + CLTV_SHARED_CLAIM_BUFFER || !req.aggregable { // Don't aggregate if outpoint absolute timelock is soon or marked as non-aggregable
					let mut single_input = HashMap::new();
					single_input.insert(req.outpoint, req.witness_data);
					new_claims.push((req.absolute_timelock, single_input));
				} else {
					aggregated_claim.insert(req.outpoint, req.witness_data);
					if req.absolute_timelock < aggregated_soonest {
						aggregated_soonest = req.absolute_timelock;
					}
				}
			}
		}
		new_claims.push((aggregated_soonest, aggregated_claim));

		// Generate claim transactions and track them to bump if necessary at
		// height timer expiration (i.e in how many blocks we're going to take action).
		for claim in new_claims {
			let mut claim_material = ClaimTxBumpMaterial { height_timer: None, feerate_previous: 0, soonest_timelock: claim.0, per_input_material: claim.1.clone() };
			if let Some((new_timer, new_feerate, tx)) = self.generate_claim_tx(height, &claim_material, &*fee_estimator) {
				claim_material.height_timer = new_timer;
				claim_material.feerate_previous = new_feerate;
				let txid = tx.txid();
				self.pending_claim_requests.insert(txid, claim_material);
				for k in claim.1.keys() {
					log_trace!(self, "Registering claiming request for {}:{}", k.txid, k.vout);
					self.claimable_outpoints.insert(k.clone(), (txid, height));
				}
				log_trace!(self, "Broadcast onchain {}", log_tx!(tx));
				broadcaster.broadcast_transaction(&tx);
			}
		}

		let mut bump_candidates = HashMap::new();
		for tx in txn_matched {
			// Scan all input to verify is one of the outpoint spent is of interest for us
			let mut claimed_outputs_material = Vec::new();
			for inp in &tx.input {
				if let Some(first_claim_txid_height) = self.claimable_outpoints.get(&inp.previous_output) {
					// If outpoint has claim request pending on it...
					if let Some(claim_material) = self.pending_claim_requests.get_mut(&first_claim_txid_height.0) {
						//... we need to verify equality between transaction outpoints and claim request
						// outpoints to know if transaction is the original claim or a bumped one issued
						// by us.
						let mut set_equality = true;
						if claim_material.per_input_material.len() != tx.input.len() {
							set_equality = false;
						} else {
							for (claim_inp, tx_inp) in claim_material.per_input_material.keys().zip(tx.input.iter()) {
								if *claim_inp != tx_inp.previous_output {
									set_equality = false;
								}
							}
						}

						macro_rules! clean_claim_request_after_safety_delay {
							() => {
								let new_event = OnchainEvent::Claim { claim_request: first_claim_txid_height.0.clone() };
								match self.onchain_events_waiting_threshold_conf.entry(height + ANTI_REORG_DELAY - 1) {
									hash_map::Entry::Occupied(mut entry) => {
										if !entry.get().contains(&new_event) {
											entry.get_mut().push(new_event);
										}
									},
									hash_map::Entry::Vacant(entry) => {
										entry.insert(vec![new_event]);
									}
								}
							}
						}

						// If this is our transaction (or our counterparty spent all the outputs
						// before we could anyway with same inputs order than us), wait for
						// ANTI_REORG_DELAY and clean the RBF tracking map.
						if set_equality {
							clean_claim_request_after_safety_delay!();
						} else { // If false, generate new claim request with update outpoint set
							let mut at_least_one_drop = false;
							for input in tx.input.iter() {
								if let Some(input_material) = claim_material.per_input_material.remove(&input.previous_output) {
									claimed_outputs_material.push((input.previous_output, input_material));
									at_least_one_drop = true;
								}
								// If there are no outpoints left to claim in this request, drop it entirely after ANTI_REORG_DELAY.
								if claim_material.per_input_material.is_empty() {
									clean_claim_request_after_safety_delay!();
								}
							}
							//TODO: recompute soonest_timelock to avoid wasting a bit on fees
							if at_least_one_drop {
								bump_candidates.insert(first_claim_txid_height.0.clone(), claim_material.clone());
							}
						}
						break; //No need to iterate further, either tx is our or their
					} else {
						panic!("Inconsistencies between pending_claim_requests map and claimable_outpoints map");
					}
				}
			}
			for (outpoint, input_material) in claimed_outputs_material.drain(..) {
				let new_event = OnchainEvent::ContentiousOutpoint { outpoint, input_material };
				match self.onchain_events_waiting_threshold_conf.entry(height + ANTI_REORG_DELAY - 1) {
					hash_map::Entry::Occupied(mut entry) => {
						if !entry.get().contains(&new_event) {
							entry.get_mut().push(new_event);
						}
					},
					hash_map::Entry::Vacant(entry) => {
						entry.insert(vec![new_event]);
					}
				}
			}
		}

		// After security delay, either our claim tx got enough confs or outpoint is definetely out of reach
		if let Some(events) = self.onchain_events_waiting_threshold_conf.remove(&height) {
			for ev in events {
				match ev {
					OnchainEvent::Claim { claim_request } => {
						// We may remove a whole set of claim outpoints here, as these one may have
						// been aggregated in a single tx and claimed so atomically
						if let Some(bump_material) = self.pending_claim_requests.remove(&claim_request) {
							for outpoint in bump_material.per_input_material.keys() {
								self.claimable_outpoints.remove(&outpoint);
							}
						}
					},
					OnchainEvent::ContentiousOutpoint { outpoint, .. } => {
						self.claimable_outpoints.remove(&outpoint);
					}
				}
			}
		}

		// Check if any pending claim request must be rescheduled
		for (first_claim_txid, ref claim_data) in self.pending_claim_requests.iter() {
			if let Some(h) = claim_data.height_timer {
				if h == height {
					bump_candidates.insert(*first_claim_txid, (*claim_data).clone());
				}
			}
		}

		// Build, bump and rebroadcast tx accordingly
		log_trace!(self, "Bumping {} candidates", bump_candidates.len());
		let mut pending_claim_updates = Vec::with_capacity(bump_candidates.len());
		for (first_claim_txid, claim_material) in bump_candidates.iter() {
			if let Some((new_timer, new_feerate, bump_tx)) = self.generate_claim_tx(height, &claim_material, &*fee_estimator) {
				log_trace!(self, "Broadcast onchain {}", log_tx!(bump_tx));
				broadcaster.broadcast_transaction(&bump_tx);
				pending_claim_updates.push((*first_claim_txid, new_timer, new_feerate));
			}
		}
		for updates in pending_claim_updates {
			if let Some(claim_material) = self.pending_claim_requests.get_mut(&updates.0) {
				claim_material.height_timer = updates.1;
				claim_material.feerate_previous = updates.2;
			}
		}
	}

	pub(super) fn block_disconnected<B: Deref, F: Deref>(&mut self, height: u32, broadcaster: B, fee_estimator: F)
		where B::Target: BroadcasterInterface,
		      F::Target: FeeEstimator
	{
		let mut bump_candidates = HashMap::new();
		if let Some(events) = self.onchain_events_waiting_threshold_conf.remove(&(height + ANTI_REORG_DELAY - 1)) {
			//- our claim tx on a commitment tx output
			//- resurect outpoint back in its claimable set and regenerate tx
			for ev in events {
				match ev {
					OnchainEvent::ContentiousOutpoint { outpoint, input_material } => {
						if let Some(ancestor_claimable_txid) = self.claimable_outpoints.get(&outpoint) {
							if let Some(claim_material) = self.pending_claim_requests.get_mut(&ancestor_claimable_txid.0) {
								claim_material.per_input_material.insert(outpoint, input_material);
								// Using a HashMap guarantee us than if we have multiple outpoints getting
								// resurrected only one bump claim tx is going to be broadcast
								bump_candidates.insert(ancestor_claimable_txid.clone(), claim_material.clone());
							}
						}
					},
					_ => {},
				}
			}
		}
		for (_, claim_material) in bump_candidates.iter_mut() {
			if let Some((new_timer, new_feerate, bump_tx)) = self.generate_claim_tx(height, &claim_material, &*fee_estimator) {
				claim_material.height_timer = new_timer;
				claim_material.feerate_previous = new_feerate;
				broadcaster.broadcast_transaction(&bump_tx);
			}
		}
		for (ancestor_claim_txid, claim_material) in bump_candidates.drain() {
			self.pending_claim_requests.insert(ancestor_claim_txid.0, claim_material);
		}
		//TODO: if we implement cross-block aggregated claim transaction we need to refresh set of outpoints and regenerate tx but
		// right now if one of the outpoint get disconnected, just erase whole pending claim request.
		let mut remove_request = Vec::new();
		self.claimable_outpoints.retain(|_, ref v|
			if v.1 == height {
			remove_request.push(v.0.clone());
			false
			} else { true });
		for req in remove_request {
			self.pending_claim_requests.remove(&req);
		}
	}

	pub(super) fn provide_latest_local_tx(&mut self, tx: LocalCommitmentTransaction) -> Result<(), ()> {
		// To prevent any unsafe state discrepancy between offchain and onchain, once local
		// commitment transaction has been signed due to an event (either block height for
		// HTLC-timeout or channel force-closure), don't allow any further update of local
		// commitment transaction view to avoid delivery of revocation secret to counterparty
		// for the aformentionned signed transaction.
		if let Some(ref local_commitment) = self.local_commitment {
			if local_commitment.has_local_sig() { return Err(()) }
		}
		self.prev_local_commitment = self.local_commitment.take();
		self.local_commitment = Some(tx);
		Ok(())
	}

	pub(super) fn get_fully_signed_local_tx(&mut self, channel_value_satoshis: u64) -> Option<Transaction> {
		if let Some(ref mut local_commitment) = self.local_commitment {
			self.key_storage.sign_local_commitment(local_commitment, &self.funding_redeemscript, channel_value_satoshis, &self.secp_ctx);
			return Some(local_commitment.with_valid_witness().clone());
		}
		None
	}

	#[cfg(test)]
	pub(super) fn get_fully_signed_copy_local_tx(&mut self, channel_value_satoshis: u64) -> Option<Transaction> {
		if let Some(ref mut local_commitment) = self.local_commitment {
			let mut local_commitment = local_commitment.clone();
			self.key_storage.unsafe_sign_local_commitment(&mut local_commitment, &self.funding_redeemscript, channel_value_satoshis, &self.secp_ctx);
			return Some(local_commitment.with_valid_witness().clone());
		}
		None
	}

	pub(super) fn get_fully_signed_htlc_tx(&mut self, txid: Sha256dHash, htlc_index: u32, preimage: Option<PaymentPreimage>) -> Option<Transaction> {
		//TODO: store preimage in OnchainTxHandler
		if let Some(ref mut local_commitment) = self.local_commitment {
			if local_commitment.txid() == txid {
				self.key_storage.sign_htlc_transaction(local_commitment, htlc_index, preimage, self.local_csv, &self.secp_ctx);
				return local_commitment.htlc_with_valid_witness(htlc_index).clone();
			}
		}
		None
	}
}
