//! Utilities for computing witnesses weight and feerate computation for onchain operation

use bitcoin::blockdata::transaction::{TxOut,TxIn, Transaction, SigHashType};
use bitcoin::blockdata::transaction::OutPoint as BitcoinOutPoint;
use bitcoin::blockdata::script::Script;

use bitcoin::hash_types::Txid;

use bitcoin::secp256k1::key::{SecretKey,PublicKey};

use ln::channel::ANCHOR_OUTPUT_VALUE;
use ln::channelmanager::PaymentPreimage;
use ln::chan_utils::{TxCreationKeys, HTLCOutputInCommitment};
use ln::chan_utils;
use ln::msgs::DecodeError;
use ln::onchaintx::OnchainTxHandler;
use chain::chaininterface::{FeeEstimator, ConfirmationTarget, MIN_RELAY_FEE_SAT_PER_1000_WEIGHT};
use chain::keysinterface::ChannelKeys;
use chain::utxointerface::UtxoPool;
use util::byte_utils;
use util::logger::Logger;
use util::ser::{Readable, Writer, Writeable};

use std::collections::HashMap;
use std::cmp;
use std::ops::Deref;

const MAX_ALLOC_SIZE: usize = 64*1024;

#[derive(PartialEq, Clone, Copy)]
pub(crate) enum InputDescriptors {
	RevokedOfferedHTLC,
	RevokedReceivedHTLC,
	OfferedHTLC,
	ReceivedHTLC,
	RevokedOutput, // either a revoked to_holder output on commitment tx, a revoked HTLC-Timeout output or a revoked HTLC-Success output
}

impl Writeable for InputDescriptors {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
		match self {
			&InputDescriptors::RevokedOfferedHTLC => {
				writer.write_all(&[0; 1])?;
			},
			&InputDescriptors::RevokedReceivedHTLC => {
				writer.write_all(&[1; 1])?;
			},
			&InputDescriptors::OfferedHTLC => {
				writer.write_all(&[2; 1])?;
			},
			&InputDescriptors::ReceivedHTLC => {
				writer.write_all(&[3; 1])?;
			}
			&InputDescriptors::RevokedOutput => {
				writer.write_all(&[4; 1])?;
			}
		}
		Ok(())
	}
}

impl Readable for InputDescriptors {
	fn read<R: ::std::io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
		let input_descriptor = match <u8 as Readable>::read(reader)? {
			0 => {
				InputDescriptors::RevokedOfferedHTLC
			},
			1 => {
				InputDescriptors::RevokedReceivedHTLC
			},
			2 => {
				InputDescriptors::OfferedHTLC
			},
			3 => {
				InputDescriptors::ReceivedHTLC
			},
			4 => {
				InputDescriptors::RevokedOutput
			}
			_ => return Err(DecodeError::InvalidValue),
		};
		Ok(input_descriptor)
	}
}

pub(crate) fn get_witnesses_weight(inputs: &[InputDescriptors]) -> usize {
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
			// number_of_witness_elements + sig_length + counterpartyhtlc_sig  + preimage_length + preimage + witness_script_length + witness_script
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

/// A struct to describe a revoked output, the templated witnessScript variables to claim it
/// (hash, timelock, pubkeys) and per_commitment_key to generate a solving witness. It is used by
/// OnchainTxHandler to generate a valid transaction claiming this output.
#[derive(Clone, PartialEq)]
pub(crate) struct RevokedOutput {
	per_commitment_point: PublicKey,
	counterparty_delayed_payment_base_key: PublicKey,
	counterparty_htlc_base_key: PublicKey,
	per_commitment_key: SecretKey,
	input_descriptor: InputDescriptors,
	amount: u64,
	htlc: Option<HTLCOutputInCommitment>,
	on_counterparty_tx_csv: u16,
}

impl Writeable for RevokedOutput {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
		self.per_commitment_point.write(writer)?;
		self.counterparty_delayed_payment_base_key.write(writer)?;
		self.counterparty_htlc_base_key.write(writer)?;
		writer.write_all(&self.per_commitment_key[..])?;
		self.input_descriptor.write(writer)?;
		writer.write_all(&byte_utils::be64_to_array(self.amount))?;
		self.htlc.write(writer)?;
		self.on_counterparty_tx_csv.write(writer)?;
		Ok(())
	}
}

impl Readable for RevokedOutput {
	fn read<R: ::std::io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
		let per_commitment_point = Readable::read(reader)?;
		let counterparty_delayed_payment_base_key = Readable::read(reader)?;
		let counterparty_htlc_base_key = Readable::read(reader)?;
		let per_commitment_key = Readable::read(reader)?;
		let input_descriptor = Readable::read(reader)?;
		let amount = Readable::read(reader)?;
		let htlc = Readable::read(reader)?;
		let on_counterparty_tx_csv = Readable::read(reader)?;
		Ok(RevokedOutput {
			per_commitment_point,
			counterparty_delayed_payment_base_key,
			counterparty_htlc_base_key,
			per_commitment_key,
			input_descriptor,
			amount,
			htlc,
			on_counterparty_tx_csv
		})
	}
}

/// A struct to describe a counterparty htlc output, the templated witnessScript variables to claim it (hash,
/// timelock, pubkeys) and preimage to generate a solving witness. It is used by OnchainTxHandler
/// to generate a valid transaction claiming this output.
#[derive(Clone, PartialEq)]
pub(crate) struct CounterpartyHTLCOutput {
	per_commitment_point: PublicKey,
	counterparty_delayed_payment_base_key: PublicKey,
	counterparty_htlc_base_key: PublicKey,
	preimage: Option<PaymentPreimage>,
	htlc: HTLCOutputInCommitment
}

impl Writeable for CounterpartyHTLCOutput {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
		self.per_commitment_point.write(writer)?;
		self.counterparty_delayed_payment_base_key.write(writer)?;
		self.counterparty_htlc_base_key.write(writer)?;
		self.preimage.write(writer)?;
		self.htlc.write(writer)?;
		Ok(())
	}
}

impl Readable for CounterpartyHTLCOutput {
	fn read<R: ::std::io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
		let per_commitment_point = Readable::read(reader)?;
		let counterparty_delayed_payment_base_key = Readable::read(reader)?;
		let counterparty_htlc_base_key = Readable::read(reader)?;
		let preimage = Readable::read(reader)?;
		let htlc = Readable::read(reader)?;
		Ok(CounterpartyHTLCOutput {
			per_commitment_point,
			counterparty_delayed_payment_base_key,
			counterparty_htlc_base_key,
			preimage,
			htlc
		})
	}
}

/// A struct to describe a holder htlc output, amount and preimage to generate a signature and
/// solving witness. It is used by OnchainTxHandler to finalize a HTLC transaction claiming this
/// output.
#[derive(Clone, PartialEq)]
pub(crate) struct HolderHTLCOutput {
	preimage: Option<PaymentPreimage>,
	amount: u64,
}

impl Writeable for HolderHTLCOutput {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
		self.preimage.write(writer)?;
		writer.write_all(&byte_utils::be64_to_array(self.amount))?;
		Ok(())
	}
}

impl Readable for HolderHTLCOutput {
	fn read<R: ::std::io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
		let preimage = Readable::read(reader)?;
		let amount = Readable::read(reader)?;
		Ok(HolderHTLCOutput {
			preimage,
			amount,
		})
	}
}

/// A struct to describe a holder funding output with the static witnessScript to claim it. It is
/// used by OnchainTxHandler to finalize a holder commitment transaction claiming this output.
#[derive(Clone, PartialEq)]
pub(crate) struct HolderFundingOutput {
	funding_redeemscript: Script,
}

impl Writeable for HolderFundingOutput {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
		self.funding_redeemscript.write(writer)?;
		Ok(())
	}
}

impl Readable for HolderFundingOutput {
	fn read<R: ::std::io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
		Ok(HolderFundingOutput {
			funding_redeemscript: Readable::read(reader)?,
		})
	}
}

/// A struct to describe a bumping output with the amount and witness weight. It is used by
/// OnchainTxHandler to build a CPFP transaction to drag a local commitment transaction.
#[derive(Clone, PartialEq)]
pub struct BumpingOutput {
	amount: u64,
	witness_weight: u64,
}

impl BumpingOutput {
	pub(crate) fn new(amount: u64, witness_weight: u64) -> Self {
		BumpingOutput {
			amount,
			witness_weight,
		}
	}
}

impl Writeable for BumpingOutput {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
		self.amount.write(writer)?;
		self.witness_weight.write(writer)?;
		Ok(())
	}
}

impl Readable for BumpingOutput {
	fn read<R: ::std::io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
		Ok(BumpingOutput {
			amount: Readable::read(reader)?,
			witness_weight: Readable::read(reader)?,
		})
	}
}

/// An enum to describe a claim content which is generated by ChannelMonitor and
/// used by OnchainTxHandler to regenerate feerate-bump transactions to settle claims.
///
/// Template may be either malleable (a justice tx, a counterparty HTLC tx) or lockdown (a holder htlc
/// tx, a holder commitment tx, a pre-signed justice tx). Bumping can be a Replace-by-Fee, that way
/// the claim-settlement tx in itself has its feerate increased or Child-Pay-For-Parent, a child
/// of the claim tx has its feerate increased. For the latter case, access to the whole package
/// sizea and pre-committed fee is required to compute an efficient bump.
#[derive(Clone, PartialEq)]
pub(crate) enum PackageTemplate {
	MalleableJusticeTx {
		inputs: HashMap<BitcoinOutPoint, RevokedOutput>,
	},
	CounterpartyHTLCTx {
		inputs: HashMap<BitcoinOutPoint, CounterpartyHTLCOutput>,
	},
	HolderHTLCTx {
		input: (BitcoinOutPoint, HolderHTLCOutput),
	},
	HolderCommitmentTx {
		input: (BitcoinOutPoint, HolderFundingOutput),
		utxo_input: Option<(BitcoinOutPoint, BumpingOutput)>
	}
}

impl PackageTemplate {
	pub(crate) fn outpoints(&self) -> Vec<&BitcoinOutPoint> {
		match self {
			PackageTemplate::MalleableJusticeTx { ref inputs } => {
				inputs.keys().collect()
			},
			PackageTemplate::CounterpartyHTLCTx { ref inputs } => {
				inputs.keys().collect()
			},
			PackageTemplate::HolderHTLCTx { ref input } => {
				let mut outpoints = Vec::with_capacity(1);
				outpoints.push(&input.0);
				return outpoints;
			},
			PackageTemplate::HolderCommitmentTx { ref input, ..  } => {
				let mut outpoints = Vec::with_capacity(1);
				outpoints.push(&input.0);
				return outpoints;
			},
		}
	}
	pub(crate) fn package_split(&mut self, outp: &BitcoinOutPoint) -> Option<PackageTemplate> {
		match self {
			PackageTemplate::MalleableJusticeTx { ref mut inputs } => {
				if let Some(removed) = inputs.remove(outp) {
					let mut input_splitted = HashMap::with_capacity(1);
					input_splitted.insert(*outp, removed);
					return Some(PackageTemplate::MalleableJusticeTx {
						inputs: input_splitted,
					});
				}
				None
			},
			PackageTemplate::CounterpartyHTLCTx { ref mut inputs } => {
				if let Some(removed) = inputs.remove(outp) {
					let mut input_splitted = HashMap::with_capacity(1);
					input_splitted.insert(*outp, removed);
					return Some(PackageTemplate::CounterpartyHTLCTx {
						inputs: input_splitted,
					});
				}
				None
			},
			_ => {
				// Note, we may try to split on remote transaction for
				// which we don't have a competing one (HTLC-Success before
				// timelock expiration). This explain we don't panic!.
				// We should refactor OnchainTxHandler::block_connected to
				// only test equality on competing claims.
				return None;
			}
		}
	}
	pub(crate) fn package_merge(&mut self, mut template: PackageTemplate) {
		match self {
			PackageTemplate::MalleableJusticeTx { ref mut inputs } => {
				let base_inputs = inputs;
				match template {
					PackageTemplate::MalleableJusticeTx { ref mut inputs } => {
						for (k, v) in inputs.drain() {
							base_inputs.insert(k, v);
						}
					},
					_ => panic!("Merging templates of different types")
				}
			},
			PackageTemplate::CounterpartyHTLCTx { ref mut inputs } => {
				let base_inputs = inputs;
				match template {
					PackageTemplate::CounterpartyHTLCTx { ref mut inputs } => {
						for (k, v) in inputs.drain() {
							base_inputs.insert(k, v);
						}
					},
					_ => panic!("Merging templates of different types")
				}
			},
			_ => panic!("Merging template on non-malleable packages")
		}
	}
	pub(crate) fn package_amounts(&self) -> u64 {
		let amounts = match self {
			PackageTemplate::MalleableJusticeTx { ref inputs } => {
				let mut amounts = 0;
				for outp in inputs.values() {
					amounts += outp.amount;
				}
				amounts
			},
			PackageTemplate::CounterpartyHTLCTx { ref inputs } => {
				let mut amounts = 0;
				for outp in inputs.values() {
					amounts += outp.htlc.amount_msat / 1000;
				}
				amounts
			},
			PackageTemplate::HolderCommitmentTx { ref utxo_input, .. } => {
				if let Some(utxo_input) = utxo_input {
					return utxo_input.1.amount + ANCHOR_OUTPUT_VALUE;
				} else { return 0 }
			},
			PackageTemplate::HolderHTLCTx { ref input } => {
				input.1.amount
			},
		};
		amounts
	}
	pub(crate) fn package_weight(&self, destination_script: &Script, local_commitment: &Transaction) -> usize {
		let mut input = Vec::new();
		let witnesses_weight = match self {
			PackageTemplate::MalleableJusticeTx { ref inputs } => {
				let mut weight = 0;
				for (outpoint, outp) in inputs.iter() {
					input.push(TxIn {
						previous_output: *outpoint,
						script_sig: Script::new(),
						sequence: 0xfffffffd,
						witness: Vec::new(),
					});
					weight += get_witnesses_weight(&[outp.input_descriptor]);
				}
				weight
			},
			PackageTemplate::CounterpartyHTLCTx { ref inputs } => {
				let mut weight = 0;
				for (outpoint, outp) in inputs.iter() {
					input.push(TxIn {
						previous_output: *outpoint,
						script_sig: Script::new(),
						sequence: 0xfffffffd,
						witness: Vec::new(),
					});

					weight += get_witnesses_weight(if outp.preimage.is_some() { &[InputDescriptors::OfferedHTLC] } else { &[InputDescriptors::ReceivedHTLC] });
				}
				weight
			},
			PackageTemplate::HolderCommitmentTx { ref utxo_input, .. } => {
				// Post-Anchor Commitment Package weight accoutning:
				let commitment_weight =
					900					// base commitment tx (900 WU)
					+ local_commitment.output.len()	* 172	// num-htlc-outputs  * htlc-output (172 WU)
					+ 224;					// funding spending witness (224 WU)
				// If a feerate-bump is required:
				let cpfp_weight: usize = if let Some(utxo_input) = utxo_input {
					40 					// CPFP transaction basic fields (40 WU)
					+ 2					// witness marker (2 WU)
					+ 164					// anchor input (164 WU)
					+ 115 					// anchor witness (115 WU)
					+ 164					// bumping input (164 WU)
					+ utxo_input.1.witness_weight as usize  // bumping witness (`utxo_input.1.witness_weight`)
					+ 32					// output amount (32 WU)
					+ 4 					// output scriptpubkey-length (4 WU)
					+ destination_script.len() * 4		// output scriptpubkey (`destination_script.len() * 4`)
				} else { 0 };
				return commitment_weight + cpfp_weight;
			},
			PackageTemplate::HolderHTLCTx { ref input } => {
				if input.1.preimage.is_some() {
					return 706; // HTLC-Success with option_anchor_outputs
				} else {
					return 666; // HTLC-Timeout with option_anchor_outputs
				}
			},
		};
		let bumped_tx = Transaction {
			version: 2,
			lock_time: 0,
			input,
			output: vec![TxOut {
				script_pubkey: destination_script.clone(),
				value: 0
			}],
		};
		bumped_tx.get_weight() + witnesses_weight
	}
	pub(crate) fn package_finalize<L: Deref, ChanSigner: ChannelKeys, U: Deref>(&self, onchain_handler: &mut OnchainTxHandler<ChanSigner>, value: u64, destination_script: Script, logger: &L, utxo_pool: &U) -> Option<Vec<Transaction>>
		where L::Target: Logger,
		      U::Target: UtxoPool,
	{
		let mut bumped_tx = Transaction {
			version: 2,
			lock_time: 0,
			input: vec![],
			output: vec![TxOut {
				script_pubkey: destination_script.clone(),
				value,
			}],
		};
		match self {
			PackageTemplate::MalleableJusticeTx { ref inputs } => {
				for outp in inputs.keys() {
					bumped_tx.input.push(TxIn {
						previous_output: *outp,
						script_sig: Script::new(),
						sequence: 0xfffffffd,
						witness: Vec::new(),
					});
				}
				for (i, (outp, revk)) in inputs.iter().enumerate() {
					log_trace!(logger, "Claiming outpoint {}:{}", outp.txid, outp.vout);
					if let Ok(chan_keys) = TxCreationKeys::derive_new(&onchain_handler.secp_ctx, &revk.per_commitment_point, &revk.counterparty_delayed_payment_base_key, &revk.counterparty_htlc_base_key, &onchain_handler.key_storage.pubkeys().revocation_basepoint, &onchain_handler.key_storage.pubkeys().htlc_basepoint) {
						let witness_script = if let Some(ref htlc) = revk.htlc {
							chan_utils::get_htlc_redeemscript_with_explicit_keys(&htlc, &chan_keys.broadcaster_htlc_key, &chan_keys.countersignatory_htlc_key, &chan_keys.revocation_key)
						} else {
							chan_utils::get_revokeable_redeemscript(&chan_keys.revocation_key, revk.on_counterparty_tx_csv, &chan_keys.broadcaster_delayed_payment_key)
						};

						if let Ok(sig) = onchain_handler.key_storage.sign_justice_transaction(&bumped_tx, i, revk.amount, &revk.per_commitment_key, &revk.htlc, &onchain_handler.secp_ctx) {
							bumped_tx.input[i].witness.push(sig.serialize_der().to_vec());
							bumped_tx.input[i].witness[0].push(SigHashType::All as u8);
							if revk.htlc.is_some() {
								bumped_tx.input[i].witness.push(chan_keys.revocation_key.clone().serialize().to_vec());
							} else {
								bumped_tx.input[i].witness.push(vec!(1));
							}
							bumped_tx.input[i].witness.push(witness_script.clone().into_bytes());
						} else { return None; }
						//TODO: panic ?
					}
				}
				log_trace!(logger, "Going to broadcast Penalty Transaction {}...", bumped_tx.txid());
				return Some(vec![bumped_tx]);
			},
			PackageTemplate::CounterpartyHTLCTx { ref inputs } => {
				for outp in inputs.keys() {
					bumped_tx.input.push(TxIn {
						previous_output: *outp,
						script_sig: Script::new(),
						sequence: 0xfffffffd,
						witness: Vec::new(),
					});
				}
				for (i, (outp, rem)) in inputs.iter().enumerate() {
					log_trace!(logger, "Claiming outpoint {}:{}", outp.txid, outp.vout);
					if let Ok(chan_keys) = TxCreationKeys::derive_new(&onchain_handler.secp_ctx, &rem.per_commitment_point, &rem.counterparty_delayed_payment_base_key, &rem.counterparty_htlc_base_key, &onchain_handler.key_storage.pubkeys().revocation_basepoint, &onchain_handler.key_storage.pubkeys().htlc_basepoint) {
						let witness_script = chan_utils::get_htlc_redeemscript_with_explicit_keys(&rem.htlc, &chan_keys.broadcaster_htlc_key, &chan_keys.countersignatory_htlc_key, &chan_keys.revocation_key);

						if !rem.preimage.is_some() { bumped_tx.lock_time = rem.htlc.cltv_expiry }; // Right now we don't aggregate time-locked transaction, if we do we should set lock_time before to avoid breaking hash computation
						if let Ok(sig) = onchain_handler.key_storage.sign_counterparty_htlc_transaction(&bumped_tx, i, &rem.htlc.amount_msat / 1000, &rem.per_commitment_point, &rem.htlc, &onchain_handler.secp_ctx) {
							bumped_tx.input[i].witness.push(sig.serialize_der().to_vec());
							bumped_tx.input[i].witness[0].push(SigHashType::All as u8);
							if let Some(preimage) = rem.preimage {
								bumped_tx.input[i].witness.push(preimage.0.to_vec());
							} else {
								// Due to BIP146 (MINIMALIF) this must be a zero-length element to relay.
								bumped_tx.input[i].witness.push(vec![]);
							}
							bumped_tx.input[i].witness.push(witness_script.clone().into_bytes());
						}
					}
				}
				log_trace!(logger, "Going to broadcast Claim Transaction {} claiming counterparty htlc output...", bumped_tx.txid());
				return Some(vec![bumped_tx]);
			},
			PackageTemplate::HolderHTLCTx { ref input } => {
				let htlc_tx = onchain_handler.get_fully_signed_htlc_tx(&input.0, &input.1.preimage);
				if let Some(htlc_tx) = htlc_tx {
					// Timer set to $NEVER given we can't bump tx without anchor outputs
					log_trace!(logger, "Going to broadcast Local HTLC-{} claiming HTLC output {} from {}...", if input.1.preimage.is_some() { "Success" } else { "Timeout" }, input.0.vout, input.0.txid);
					return Some(vec![htlc_tx]);
				}
				return None;
			},
			PackageTemplate::HolderCommitmentTx { ref input, ref utxo_input } => {

				// We sign our commitment transaction
				let signed_tx = onchain_handler.get_fully_signed_holder_tx(&input.1.funding_redeemscript).unwrap();
				let mut cpfp_tx = Transaction {
					version: 2,
					lock_time: 0,
					input: Vec::with_capacity(2),
					output: vec![TxOut {
						script_pubkey: destination_script.clone(),
						value,
					}],
				};
				// TODO: make CPFP generation conditional on utxo input
				if let Some(ref holder_tx) = onchain_handler.holder_commitment.as_ref() {
					// We find & select our anchor output
					let our_anchor_output_script = chan_utils::get_anchor_redeemscript(&onchain_handler.key_storage.pubkeys().funding_pubkey);
					let mut vout = ::std::u32::MAX;
					for (idx, outp) in holder_tx.unsigned_tx.output.iter().enumerate() {
						if outp.script_pubkey == our_anchor_output_script.to_v0_p2wsh() {
							vout = idx as u32;
						}
					}
					if vout == ::std::u32::MAX { return None; }
					let anchor_outpoint = BitcoinOutPoint {
						txid: holder_tx.unsigned_tx.txid(),
						vout,
					};
					// We take our bumping outpoint
					let bumping_outpoint = utxo_input.as_ref().unwrap().0;
					// We build our CPFP transaction
					cpfp_tx.input.push(TxIn {
						previous_output: anchor_outpoint,
						script_sig: Script::new(),
						sequence: 0xfffffffd,
						witness: Vec::new(),
					});
					cpfp_tx.input.push(TxIn {
						previous_output: bumping_outpoint,
						script_sig: Script::new(),
						sequence: 0xfffffffd,
						witness: Vec::new(),
					});
					// We sign and witness finalize anchor input
					if let Ok(anchor_sig) = onchain_handler.key_storage.sign_cpfp(&cpfp_tx, 0, ANCHOR_OUTPUT_VALUE, &onchain_handler.secp_ctx) {
						cpfp_tx.input[0].witness.push(anchor_sig.serialize_der().to_vec());
						cpfp_tx.input[0].witness[0].push(SigHashType::All as u8);
						cpfp_tx.input[0].witness.push(our_anchor_output_script.into_bytes());
					}
					//// We sign and witness finalize bumping input
					if let Ok(witness) = utxo_pool.provide_utxo_witness(&cpfp_tx, 1) {
						cpfp_tx.input[1].witness = witness;
					}
				}
				log_trace!(logger, "Going to broadcast Holder Transaction {} claiming funding output {} from {}...", signed_tx.txid(), input.0.vout, input.0.txid);
				return Some(vec![signed_tx, cpfp_tx]);
			}
		}
	}
	pub(crate) fn package_cpfp<U: Deref>(&mut self, utxo_pool: &U)
		where U::Target: UtxoPool,
	{
		match self {
			PackageTemplate::HolderCommitmentTx { ref mut utxo_input, .. } => {
				if utxo_input.is_some() { return; }
				*utxo_input = utxo_pool.allocate_utxo(0);
			},
			PackageTemplate::HolderHTLCTx { .. } => {
				return; //TODO: Should we anchor output HTLC-txn?
			},
			_  => panic!("Package template should be bumped through RBF")
		}
	}
	pub(crate) fn build_malleable_justice_tx(per_commitment_point: PublicKey, per_commitment_key: SecretKey, counterparty_delayed_payment_base_key: PublicKey, counterparty_htlc_base_key: PublicKey, input_descriptor: InputDescriptors, txid: Txid, vout: u32, amount: u64, htlc: Option<HTLCOutputInCommitment>, on_counterparty_tx_csv: u16) -> Self {
		let revk_outp = RevokedOutput {
			per_commitment_point,
			counterparty_delayed_payment_base_key,
			counterparty_htlc_base_key,
			per_commitment_key,
			input_descriptor,
			amount,
			htlc,
			on_counterparty_tx_csv,
		};
		let mut inputs = HashMap::with_capacity(1);
		inputs.insert(BitcoinOutPoint { txid, vout }, revk_outp);
		PackageTemplate::MalleableJusticeTx {
			inputs,
		}
	}
	pub(crate) fn build_counterparty_htlc_tx(per_commitment_point: PublicKey, counterparty_delayed_payment_base_key: PublicKey, counterparty_htlc_base_key: PublicKey, preimage: Option<PaymentPreimage>, htlc: HTLCOutputInCommitment, txid: Txid, vout: u32) -> Self {
		let counterparty_outp = CounterpartyHTLCOutput {
			per_commitment_point,
			counterparty_delayed_payment_base_key,
			counterparty_htlc_base_key,
			preimage,
			htlc
		};
		let mut inputs = HashMap::with_capacity(1);
		inputs.insert(BitcoinOutPoint { txid, vout }, counterparty_outp);
		PackageTemplate::CounterpartyHTLCTx  {
			inputs,
		}
	}
	pub(crate) fn build_holder_htlc_tx(preimage: Option<PaymentPreimage>, amount: u64, txid: Txid, vout: u32) -> Self {
		let htlc_outp = HolderHTLCOutput {
			preimage,
			amount,
		};
		PackageTemplate::HolderHTLCTx {
			input: (BitcoinOutPoint { txid, vout }, htlc_outp)
		}
	}
	pub(crate) fn build_holder_commitment_tx(funding_redeemscript: Script, txid: Txid, vout: u32) -> Self {
		let funding_outp = HolderFundingOutput {
			funding_redeemscript,
		};
		PackageTemplate::HolderCommitmentTx {
			input: (BitcoinOutPoint { txid, vout }, funding_outp),
			utxo_input: None,
		}
	}
}

impl Default for PackageTemplate {
	fn default() -> Self {
		PackageTemplate::MalleableJusticeTx {
			inputs: HashMap::new(),
		}
	}
}

impl Writeable for PackageTemplate {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
		match self {
			&PackageTemplate::MalleableJusticeTx { ref inputs } => {
				writer.write_all(&[0; 1])?;
				writer.write_all(&byte_utils::be64_to_array(inputs.len() as u64))?;
				for (ref outpoint, ref rev_outp) in inputs.iter() {
					outpoint.write(writer)?;
					rev_outp.write(writer)?;
				}
			},
			&PackageTemplate::CounterpartyHTLCTx { ref inputs } => {
				writer.write_all(&[1; 1])?;
				writer.write_all(&byte_utils::be64_to_array(inputs.len() as u64))?;
				for (ref outpoint, ref counterparty_outp) in inputs.iter() {
					outpoint.write(writer)?;
					counterparty_outp.write(writer)?;
				}
			},
			&PackageTemplate::HolderHTLCTx { ref input } => {
				writer.write_all(&[2; 1])?;
				input.0.write(writer)?;
				input.1.write(writer)?;
			},
			&PackageTemplate::HolderCommitmentTx { ref input, ref utxo_input } => {
				writer.write_all(&[3; 1])?;
				input.0.write(writer)?;
				input.1.write(writer)?;
				utxo_input.write(writer)?;
			}
		}
		Ok(())
	}
}

impl Readable for PackageTemplate {
	fn read<R: ::std::io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
		let package = match <u8 as Readable>::read(reader)? {
			0 => {
				let inputs_count = <u64 as Readable>::read(reader)?;
				let mut inputs = HashMap::with_capacity(cmp::min(inputs_count as usize, MAX_ALLOC_SIZE / 128));
				for _ in 0..inputs_count {
					let outpoint = Readable::read(reader)?;
					let rev_outp = Readable::read(reader)?;
					inputs.insert(outpoint, rev_outp);
				}
				PackageTemplate::MalleableJusticeTx {
					inputs,
				}
			},
			1 => {
				let inputs_count = <u64 as Readable>::read(reader)?;
				let mut inputs = HashMap::with_capacity(cmp::min(inputs_count as usize, MAX_ALLOC_SIZE / 128));
				for _ in 0..inputs_count {
					let outpoint = Readable::read(reader)?;
					let counterparty_outp = Readable::read(reader)?;
					inputs.insert(outpoint, counterparty_outp);
				}
				PackageTemplate::CounterpartyHTLCTx {
					inputs,
				}
			},
			2 => {
				let outpoint = Readable::read(reader)?;
				let htlc_outp = Readable::read(reader)?;
				PackageTemplate::HolderHTLCTx {
					input: (outpoint, htlc_outp)
				}
			},
			3 => {
				let outpoint = Readable::read(reader)?;
				let funding_outp = Readable::read(reader)?;
				let utxo_input = Readable::read(reader)?;
				PackageTemplate::HolderCommitmentTx {
					input: (outpoint, funding_outp),
					utxo_input,
				}
			},
			_ => return Err(DecodeError::InvalidValue),
		};
		Ok(package)
	}
}

/// BumpStrategy is a basic enum to encode a fee-committing strategy. We
/// may extend it in the future with other stategies like BYOF-input.
#[derive(PartialEq, Clone)]
pub(crate) enum BumpStrategy {
	RBF,
	CPFP
}

impl Writeable for BumpStrategy {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
		match self {
			BumpStrategy::RBF => {
				writer.write_all(&[0; 1])?;
			},
			BumpStrategy::CPFP => {
				writer.write_all(&[1; 1])?;
			}
		}
		Ok(())
	}
}

impl Readable for BumpStrategy {
	fn read<R: ::std::io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
		let bump_strategy = match <u8 as Readable>::read(reader)? {
			0 => {
				BumpStrategy::RBF
			},
			1 => {
				BumpStrategy::CPFP
			},
			_ => return Err(DecodeError::InvalidValue),
		};
		Ok(bump_strategy)
	}
}

/// A structure to describe a claim content and its metadatas which is generated
/// by ChannelMonitor and used by OnchainTxHandler to generate feerate-competive
/// transactions.
///
/// Metadatas are related to multiple fields playing a role in packet lifetime.
/// Once issued, it may be aggregated with other requests if it's judged safe
/// and feerate opportunistic.
/// Current LN fees model, pre-committed fees with update_fee adjustement, means
/// that counter-signed transactions must be CPFP to be dynamically confirmed as a
/// bumping strategy. If transactions aren't lockdown (i.e justice transactions) we
/// may RBF them.
/// Feerate previous will serve as a feerate floor between different bumping attempts.
/// Height timer clocks these different bumping attempts.
/// Absolute timelock defines the block barrier at which claiming isn't exclusive
/// to us anymore and thus we MUST have get it solved before.
/// Height original serves as a packet timestamps to prune out claim in case of reorg.
/// Content embeds transactions elements to generate transaction. See PackageTemplate.
#[derive(PartialEq, Clone)]
pub struct OnchainRequest {
	// Timeout tx must have nLocktime set which means aggregating multiple
	// ones must take the higher nLocktime among them to satisfy all of them.
	// Sadly it has few pitfalls, a) it takes longuer to get fund back b) CLTV_DELTA
	// of a sooner-HTLC could be swallowed by the highest nLocktime of the HTLC set.
	// Do simplify we mark them as non-aggregable.
	pub(crate) aggregation: bool,
	// Content may lockdown with counter-signature of our counterparty
	// or fully-malleable by our own. Depending on this bumping strategy
	// must be adapted.
	pub(crate) bump_strategy: BumpStrategy,
	// Based feerate of previous broadcast. If resources available (either
	// output value or utxo bumping).
	pub(crate) feerate_previous: u64,
	// At every block tick, used to check if pending claiming tx is taking too
	// much time for confirmation and we need to bump it.
	pub(crate) height_timer: Option<u32>,
	// Block height before which claiming is exclusive to one party,
	// after reaching it, claiming may be contentious.
	pub(crate) absolute_timelock: u32,
	// Tracked in case of reorg to wipe out now-superflous request.
	pub(crate) height_original: u32,
	// Content of request.
	pub(crate) content: PackageTemplate,
}

impl OnchainRequest {
	pub(crate) fn request_merge(&mut self, req: OnchainRequest) {
		// We init default onchain request with first merge content
		if self.absolute_timelock == ::std::u32::MAX {
			println!("Init merging {}", req.height_original);
			self.height_original = req.height_original;
			self.content = req.content;
			self.absolute_timelock = req.absolute_timelock;
			return;
		}
		assert_eq!(self.height_original, req.height_original);
		if self.absolute_timelock > req.absolute_timelock {
			self.absolute_timelock = req.absolute_timelock;
		}
		self.content.package_merge(req.content);
	}
}

impl Default for OnchainRequest {
	fn default() -> Self {
		OnchainRequest {
			aggregation: true,
			bump_strategy: BumpStrategy::RBF,
			feerate_previous: 0,
			height_timer: None,
			absolute_timelock: ::std::u32::MAX,
			height_original: 0,
			content: PackageTemplate::default()
		}
	}
}

impl Writeable for OnchainRequest {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
		self.aggregation.write(writer)?;
		self.bump_strategy.write(writer)?;
		self.feerate_previous.write(writer)?;
		self.height_timer.write(writer)?;
		self.absolute_timelock.write(writer)?;
		self.height_original.write(writer)?;
		self.content.write(writer)?;

		Ok(())
	}
}

impl Readable for OnchainRequest {
	fn read<R: ::std::io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
		let aggregation = Readable::read(reader)?;
		let bump_strategy = Readable::read(reader)?;
		let feerate_previous = Readable::read(reader)?;
		let height_timer = Readable::read(reader)?;
		let absolute_timelock = Readable::read(reader)?;
		let height_original = Readable::read(reader)?;
		let content = Readable::read(reader)?;

		Ok(OnchainRequest {
			aggregation,
			bump_strategy,
			feerate_previous,
			height_timer,
			absolute_timelock,
			height_original,
			content
		})
	}
}

fn subtract_high_prio_fee<F: Deref, L: Deref>(input_amounts: u64, predicted_weight: usize, fee_estimator: &F, logger: &L) -> Option<(u64, u64)>
	where F::Target: FeeEstimator,
	      L::Target: Logger,
{
	let mut updated_feerate = fee_estimator.get_est_sat_per_1000_weight(ConfirmationTarget::HighPriority) as u64;
	let mut fee = updated_feerate * (predicted_weight as u64) / 1000;
	if input_amounts <= fee {
		updated_feerate = fee_estimator.get_est_sat_per_1000_weight(ConfirmationTarget::Normal) as u64;
		fee = updated_feerate * (predicted_weight as u64) / 1000;
		if input_amounts <= fee {
			updated_feerate = fee_estimator.get_est_sat_per_1000_weight(ConfirmationTarget::Background) as u64;
			fee = updated_feerate * (predicted_weight as u64) / 1000;
			if input_amounts <= fee {
				log_error!(logger, "Failed to generate an on-chain punishment tx as even low priority fee ({} sat) was more than the entire claim balance ({} sat)",
					fee, input_amounts);
				None
			} else {
				log_warn!(logger, "Used low priority fee for on-chain punishment tx as high priority fee was more than the entire claim balance ({} sat)",
					input_amounts);
				Some((fee, updated_feerate))
			}
		} else {
			log_warn!(logger, "Used medium priority fee for on-chain punishment tx as high priority fee was more than the entire claim balance ({} sat)",
				input_amounts);
			Some((fee, updated_feerate))
		}
	} else {
		Some((fee, updated_feerate))
	}
}

fn feerate_bump<F: Deref, L: Deref>(predicted_weight: usize, input_amounts: u64, previous_feerate: u64, fee_estimator: &F, logger: &L) -> Option<(u64, u64)>
	where F::Target: FeeEstimator,
	      L::Target: Logger,
{
	// If old feerate inferior to actual one given back by Fee Estimator, use it to compute new fee...
	let new_fee = if previous_feerate < fee_estimator.get_est_sat_per_1000_weight(ConfirmationTarget::HighPriority) as u64 {
		if let Some((new_fee, _)) = subtract_high_prio_fee(input_amounts, predicted_weight, fee_estimator, logger) {
			new_fee
		} else {
			log_trace!(logger, "Can't new-estimation bump new claiming tx, amount {} is too small", input_amounts);
			return None;
		}
	// ...else just increase the previous feerate by 25% (because that's a nice number)
	} else {
		let fee = previous_feerate * (predicted_weight as u64) / 750;
		if input_amounts <= fee {
			log_trace!(logger, "Can't 25% bump new claiming tx, amount {} is too small", input_amounts);
			return None;
		}
		fee
	};

	let previous_fee = previous_feerate * (predicted_weight as u64) / 1000;
	let min_relay_fee = MIN_RELAY_FEE_SAT_PER_1000_WEIGHT * (predicted_weight as u64) / 1000;
	// BIP 125 Opt-in Full Replace-by-Fee Signaling
	// 	* 3. The replacement transaction pays an absolute fee of at least the sum paid by the original transactions.
	//	* 4. The replacement transaction must also pay for its own bandwidth at or above the rate set by the node's minimum relay fee setting.
	let new_fee = if new_fee < previous_fee + min_relay_fee {
		new_fee + previous_fee + min_relay_fee - new_fee
	} else {
		new_fee
	};
	Some((new_fee, new_fee * 1000 / (predicted_weight as u64)))
}

pub(crate) fn compute_output_value<F: Deref, L: Deref>(predicted_weight: usize, input_amounts: u64, previous_feerate: u64, fee_estimator: &F, logger: &L) -> Option<(u64, u64)>
	where F::Target: FeeEstimator,
	      L::Target: Logger,
{
	// If transaction is still relying ont its pre-committed feerate to get confirmed return
	// a 0-value output-value as it won't be consumed further
	if input_amounts == 0 {
	        return Some((0, previous_feerate));
	}

	// If old feerate is 0, first iteration of this claim, use normal fee calculation
	if previous_feerate != 0 {
		if let Some((new_fee, feerate)) = feerate_bump(predicted_weight, input_amounts, previous_feerate, fee_estimator, logger) {
			// If new computed fee is superior at the whole claimable amount burn all in fees
			if new_fee > input_amounts {
				return Some((0, feerate));
			} else {
				return Some((input_amounts - new_fee, feerate));
			}
		}
	} else {
		if let Some((new_fee, feerate)) = subtract_high_prio_fee(input_amounts, predicted_weight, fee_estimator, logger) {
				return Some((input_amounts - new_fee, feerate));
		}
	}
	None
}
