//! Utilities for computing witnesses weight and feerate computation for onchain operation

use bitcoin::blockdata::transaction::{TxOut,TxIn, Transaction, SigHashType};
use bitcoin::blockdata::transaction::OutPoint as BitcoinOutPoint;
use bitcoin::blockdata::script::Script;

use bitcoin::hash_types::Txid;

use bitcoin::secp256k1::key::{SecretKey,PublicKey};

use ln::channelmanager::PaymentPreimage;
use ln::chan_utils::{TxCreationKeys, HTLCOutputInCommitment};
use ln::chan_utils;
use ln::msgs::DecodeError;
use ln::onchaintx::OnchainTxHandler;
use chain::keysinterface::ChannelKeys;
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
	}
}

impl PackageTemplate {
	pub(crate) fn outpoints(&self) -> Vec<&BitcoinOutPoint> {
		match self {
			PackageTemplate::MalleableJusticeTx { ref inputs } => {
				assert_ne!(inputs.len(), 0);
				inputs.keys().collect()
			},
			PackageTemplate::CounterpartyHTLCTx { ref inputs } => {
				assert_ne!(inputs.len(), 0);
				inputs.keys().collect()
			},
			PackageTemplate::HolderHTLCTx { ref input } => {
				let mut outpoints = Vec::with_capacity(1);
				outpoints.push(&input.0);
				return outpoints;
			},
			PackageTemplate::HolderCommitmentTx { ref input } => {
				let mut outpoints = Vec::with_capacity(1);
				outpoints.push(&input.0);
				return outpoints;
			},
		}
	}
	pub(crate) fn package_split(&mut self, outp: &BitcoinOutPoint) -> PackageTemplate {
		let package = match self {
			PackageTemplate::MalleableJusticeTx { ref mut inputs } => {
				assert_ne!(inputs.len(), 0);
				let removed = inputs.remove(outp).unwrap();
				let mut input_splitted = HashMap::with_capacity(1);
				input_splitted.insert(*outp, removed);
				PackageTemplate::MalleableJusticeTx {
					inputs: input_splitted,
				}
			},
			PackageTemplate::CounterpartyHTLCTx { ref mut inputs } => {
				assert_ne!(inputs.len(), 0);
				let removed = inputs.remove(outp).unwrap();
				let mut input_splitted = HashMap::with_capacity(1);
				input_splitted.insert(*outp, removed);
				PackageTemplate::CounterpartyHTLCTx {
					inputs: input_splitted,
				}
			},
			_ => panic!("Removing outpoints from non-malleable packages")
		};
		package
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
			_ => 0,
		};
		amounts
	}
	pub(crate) fn package_weight(&self, destination_script: &Script) -> usize {
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
			_ => { return 0 }
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
	pub(crate) fn package_finalize<L: Deref, ChanSigner: ChannelKeys>(&self, onchain_handler: &mut OnchainTxHandler<ChanSigner>, amount: u64, destination_script: Script, logger: &L) -> Option<Transaction>
		where L::Target: Logger,
	{
		let mut bumped_tx = Transaction {
			version: 2,
			lock_time: 0,
			input: vec![],
			output: vec![TxOut {
				script_pubkey: destination_script,
				value: 0
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

						if let Ok(sig) = onchain_handler.key_storage.sign_justice_transaction(&bumped_tx, i, amount, &revk.per_commitment_key, &revk.htlc, &onchain_handler.secp_ctx) {
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
				return Some(bumped_tx);
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
				return Some(bumped_tx);
			},
			PackageTemplate::HolderHTLCTx { ref input } => {
				let htlc_tx = onchain_handler.get_fully_signed_htlc_tx(&input.0, &input.1.preimage);
				if let Some(htlc_tx) = htlc_tx {
					// Timer set to $NEVER given we can't bump tx without anchor outputs
					log_trace!(logger, "Going to broadcast Holder HTLC-{} claiming HTLC output {} from {}...", if input.1.preimage.is_some() { "Success" } else { "Timeout" }, input.0.vout, input.0.txid);
					return Some(htlc_tx);
				}
				return None;
			},
			PackageTemplate::HolderCommitmentTx { ref input } => {
				let signed_tx = onchain_handler.get_fully_signed_holder_tx(&input.1.funding_redeemscript).unwrap();
				// Timer set to $NEVER given we can't bump tx without anchor outputs
				log_trace!(logger, "Going to broadcast Holder Transaction {} claiming funding output {} from {}...", signed_tx.txid(), input.0.vout, input.0.txid);
				return Some(signed_tx);
			}
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
			input: (BitcoinOutPoint { txid, vout }, funding_outp)
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
			&PackageTemplate::HolderCommitmentTx { ref input } => {
				writer.write_all(&[3; 1])?;
				input.0.write(writer)?;
				input.1.write(writer)?;
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
				PackageTemplate::HolderCommitmentTx {
					input: (outpoint, funding_outp)
				}
			},
			_ => return Err(DecodeError::InvalidValue),
		};
		Ok(package)
	}
}
