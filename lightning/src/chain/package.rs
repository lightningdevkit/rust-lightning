// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Various utilities to assemble claimable outpoints in package of one or more transactions. Those
//! packages are attached metadata, guiding their aggregable or fee-bumping re-schedule. This file
//! also includes witness weight computation and fee computation methods.

use bitcoin::blockdata::constants::WITNESS_SCALE_FACTOR;
use bitcoin::blockdata::transaction::{TxOut,TxIn, Transaction, SigHashType};
use bitcoin::blockdata::transaction::OutPoint as BitcoinOutPoint;
use bitcoin::blockdata::script::Script;

use bitcoin::hash_types::Txid;

use bitcoin::secp256k1::key::{SecretKey,PublicKey};

use ln::PaymentPreimage;
use ln::chan_utils::{TxCreationKeys, HTLCOutputInCommitment, HTLC_OUTPUT_IN_COMMITMENT_SIZE};
use ln::chan_utils;
use ln::msgs::DecodeError;
use chain::chaininterface::{FeeEstimator, ConfirmationTarget, MIN_RELAY_FEE_SAT_PER_1000_WEIGHT};
use chain::keysinterface::Sign;
use chain::onchaintx::OnchainTxHandler;
use util::byte_utils;
use util::logger::Logger;
use util::ser::{Readable, Writer, Writeable};

use std::cmp;
use std::mem;
use std::ops::Deref;

const MAX_ALLOC_SIZE: usize = 64*1024;


// number_of_witness_elements + sig_length + revocation_sig + pubkey_length + revocationpubkey + witness_script_length + witness_script
pub(crate) const WEIGHT_REVOKED_OFFERED_HTLC: u64 = 1 + 1 + 73 + 1 + 33 + 1 + 133;
// number_of_witness_elements + sig_length + revocation_sig + pubkey_length + revocationpubkey + witness_script_length + witness_script
pub(crate) const WEIGHT_REVOKED_RECEIVED_HTLC: u64 = 1 + 1 + 73 + 1 + 33 + 1 +  139;
// number_of_witness_elements + sig_length + counterpartyhtlc_sig  + preimage_length + preimage + witness_script_length + witness_script
pub(crate) const WEIGHT_OFFERED_HTLC: u64 = 1 + 1 + 73 + 1 + 32 + 1 + 133;
// number_of_witness_elements + sig_length + revocation_sig + pubkey_length + revocationpubkey + witness_script_length + witness_script
pub(crate) const WEIGHT_RECEIVED_HTLC: u64 = 1 + 1 + 73 + 1 + 1 + 1 + 139;
// number_of_witness_elements + sig_length + revocation_sig + true_length + op_true + witness_script_length + witness_script
pub(crate) const WEIGHT_REVOKED_OUTPUT: u64 = 1 + 1 + 73 + 1 + 1 + 1 + 77;

/// Height delay at which transactions are fee-bumped/rebroadcasted with a low priority.
const LOW_FREQUENCY_BUMP_INTERVAL: u32 = 15;
/// Height delay at which transactions are fee-bumped/rebroadcasted with a middle priority.
const MIDDLE_FREQUENCY_BUMP_INTERVAL: u32 = 3;
/// Height delay at which transactions are fee-bumped/rebroadcasted with a high priority.
const HIGH_FREQUENCY_BUMP_INTERVAL: u32 = 1;

/// A struct to describe a revoked output and corresponding information to generate a solving
/// witness spending a commitment `to_local` output or a second-stage HTLC transaction output.
///
/// CSV and pubkeys are used as part of a witnessScript redeeming a balance output, amount is used
/// as part of the signature hash and revocation secret to generate a satisfying witness.
#[derive(Clone, PartialEq)]
pub(crate) struct RevokedOutput {
	per_commitment_point: PublicKey,
	counterparty_delayed_payment_base_key: PublicKey,
	counterparty_htlc_base_key: PublicKey,
	per_commitment_key: SecretKey,
	weight: u64,
	amount: u64,
	on_counterparty_tx_csv: u16,
}

impl RevokedOutput {
	pub(crate) fn build(per_commitment_point: PublicKey, counterparty_delayed_payment_base_key: PublicKey, counterparty_htlc_base_key: PublicKey, per_commitment_key: SecretKey, amount: u64, on_counterparty_tx_csv: u16) -> Self {
		RevokedOutput {
			per_commitment_point,
			counterparty_delayed_payment_base_key,
			counterparty_htlc_base_key,
			per_commitment_key,
			weight: WEIGHT_REVOKED_OUTPUT,
			amount,
			on_counterparty_tx_csv
		}
	}
}

impl_writeable!(RevokedOutput, 33*3 + 32 + 8 + 8 + 2, {
	per_commitment_point,
	counterparty_delayed_payment_base_key,
	counterparty_htlc_base_key,
	per_commitment_key,
	weight,
	amount,
	on_counterparty_tx_csv
});

/// A struct to describe a revoked offered output and corresponding information to generate a
/// solving witness.
///
/// HTLCOuputInCommitment (hash timelock, direction) and pubkeys are used to generate a suitable
/// witnessScript.
///
/// CSV is used as part of a witnessScript redeeming a balance output, amount is used as part
/// of the signature hash and revocation secret to generate a satisfying witness.
#[derive(Clone, PartialEq)]
pub(crate) struct RevokedHTLCOutput {
	per_commitment_point: PublicKey,
	counterparty_delayed_payment_base_key: PublicKey,
	counterparty_htlc_base_key: PublicKey,
	per_commitment_key: SecretKey,
	weight: u64,
	amount: u64,
	htlc: HTLCOutputInCommitment,
}

impl RevokedHTLCOutput {
	pub(crate) fn build(per_commitment_point: PublicKey, counterparty_delayed_payment_base_key: PublicKey, counterparty_htlc_base_key: PublicKey, per_commitment_key: SecretKey, amount: u64, htlc: HTLCOutputInCommitment) -> Self {
		let weight = if htlc.offered { WEIGHT_REVOKED_OFFERED_HTLC } else { WEIGHT_REVOKED_RECEIVED_HTLC };
		RevokedHTLCOutput {
			per_commitment_point,
			counterparty_delayed_payment_base_key,
			counterparty_htlc_base_key,
			per_commitment_key,
			weight,
			amount,
			htlc
		}
	}
}

impl_writeable!(RevokedHTLCOutput, 33*3 + 32 + 8 + 8 + HTLC_OUTPUT_IN_COMMITMENT_SIZE, {
	per_commitment_point,
	counterparty_delayed_payment_base_key,
	counterparty_htlc_base_key,
	per_commitment_key,
	weight,
	amount,
	htlc
});

/// A struct to describe a HTLC output on a counterparty commitment transaction.
///
/// HTLCOutputInCommitment (hash, timelock, directon) and pubkeys are used to generate a suitable
/// witnessScript.
///
/// The preimage is used as part of the witness.
#[derive(Clone, PartialEq)]
pub(crate) struct CounterpartyOfferedHTLCOutput {
	per_commitment_point: PublicKey,
	counterparty_delayed_payment_base_key: PublicKey,
	counterparty_htlc_base_key: PublicKey,
	preimage: PaymentPreimage,
	htlc: HTLCOutputInCommitment
}

impl CounterpartyOfferedHTLCOutput {
	pub(crate) fn build(per_commitment_point: PublicKey, counterparty_delayed_payment_base_key: PublicKey, counterparty_htlc_base_key: PublicKey, preimage: PaymentPreimage, htlc: HTLCOutputInCommitment) -> Self {
		CounterpartyOfferedHTLCOutput {
			per_commitment_point,
			counterparty_delayed_payment_base_key,
			counterparty_htlc_base_key,
			preimage,
			htlc
		}
	}
}

impl_writeable!(CounterpartyOfferedHTLCOutput, 33*3 + 32 + HTLC_OUTPUT_IN_COMMITMENT_SIZE, {
	per_commitment_point,
	counterparty_delayed_payment_base_key,
	counterparty_htlc_base_key,
	preimage,
	htlc
});

/// A struct to describe a HTLC output on a counterparty commitment transaction.
///
/// HTLCOutputInCommitment (hash, timelock, directon) and pubkeys are used to generate a suitable
/// witnessScript.
#[derive(Clone, PartialEq)]
pub(crate) struct CounterpartyReceivedHTLCOutput {
	per_commitment_point: PublicKey,
	counterparty_delayed_payment_base_key: PublicKey,
	counterparty_htlc_base_key: PublicKey,
	htlc: HTLCOutputInCommitment
}

impl CounterpartyReceivedHTLCOutput {
	pub(crate) fn build(per_commitment_point: PublicKey, counterparty_delayed_payment_base_key: PublicKey, counterparty_htlc_base_key: PublicKey, htlc: HTLCOutputInCommitment) -> Self {
		CounterpartyReceivedHTLCOutput {
			per_commitment_point,
			counterparty_delayed_payment_base_key,
			counterparty_htlc_base_key,
			htlc
		}
	}
}

impl_writeable!(CounterpartyReceivedHTLCOutput, 33*3 + HTLC_OUTPUT_IN_COMMITMENT_SIZE, {
	per_commitment_point,
	counterparty_delayed_payment_base_key,
	counterparty_htlc_base_key,
	htlc
});

/// A struct to describe a HTLC output on holder commitment transaction.
///
/// Either offered or received, the amount is always used as part of the bip143 sighash.
/// Preimage is only included as part of the witness in former case.
#[derive(Clone, PartialEq)]
pub(crate) struct HolderHTLCOutput {
	preimage: Option<PaymentPreimage>,
	amount: u64,
}

impl HolderHTLCOutput {
	pub(crate) fn build(preimage: Option<PaymentPreimage>, amount: u64) -> Self {
		HolderHTLCOutput {
			preimage,
			amount
		}
	}
}

impl_writeable!(HolderHTLCOutput, 0, {
	preimage,
	amount
});

/// A struct to describe the channel output on the funding transaction.
///
/// witnessScript is used as part of the witness redeeming the funding utxo.
#[derive(Clone, PartialEq)]
pub(crate) struct HolderFundingOutput {
	funding_redeemscript: Script,
}

impl HolderFundingOutput {
	pub(crate) fn build(funding_redeemscript: Script) -> Self {
		HolderFundingOutput {
			funding_redeemscript,
		}
	}
}

impl_writeable!(HolderFundingOutput, 0, {
	funding_redeemscript
});

/// A wrapper encapsulating all in-protocol differing outputs types.
///
/// The generic API offers access to an outputs common attributes or allow transformation such as
/// finalizing an input claiming the output.
#[derive(Clone, PartialEq)]
pub(crate) enum PackageSolvingData {
	RevokedOutput(RevokedOutput),
	RevokedHTLCOutput(RevokedHTLCOutput),
	CounterpartyOfferedHTLCOutput(CounterpartyOfferedHTLCOutput),
	CounterpartyReceivedHTLCOutput(CounterpartyReceivedHTLCOutput),
	HolderHTLCOutput(HolderHTLCOutput),
	HolderFundingOutput(HolderFundingOutput),
}

impl PackageSolvingData {
	fn amount(&self) -> u64 {
		let amt = match self {
			PackageSolvingData::RevokedOutput(ref outp) => { outp.amount },
			PackageSolvingData::RevokedHTLCOutput(ref outp) => { outp.amount },
			PackageSolvingData::CounterpartyOfferedHTLCOutput(ref outp) => { outp.htlc.amount_msat / 1000 },
			PackageSolvingData::CounterpartyReceivedHTLCOutput(ref outp) => { outp.htlc.amount_msat / 1000 },
			// Note: Currently, amounts of holder outputs spending witnesses aren't used
			// as we can't malleate spending package to increase their feerate. This
			// should change with the remaining anchor output patchset.
			PackageSolvingData::HolderHTLCOutput(..) => { 0 },
			PackageSolvingData::HolderFundingOutput(..) => { 0 },
		};
		amt
	}
	fn weight(&self) -> usize {
		let weight = match self {
			PackageSolvingData::RevokedOutput(ref outp) => { outp.weight as usize },
			PackageSolvingData::RevokedHTLCOutput(ref outp) => { outp.weight as usize },
			PackageSolvingData::CounterpartyOfferedHTLCOutput(..) => { WEIGHT_OFFERED_HTLC as usize },
			PackageSolvingData::CounterpartyReceivedHTLCOutput(..) => { WEIGHT_RECEIVED_HTLC as usize },
			// Note: Currently, weights of holder outputs spending witnesses aren't used
			// as we can't malleate spending package to increase their feerate. This
			// should change with the remaining anchor output patchset.
			PackageSolvingData::HolderHTLCOutput(..) => { debug_assert!(false); 0 },
			PackageSolvingData::HolderFundingOutput(..) => { debug_assert!(false); 0 },
		};
		weight
	}
	fn is_compatible(&self, input: &PackageSolvingData) -> bool {
		match self {
			PackageSolvingData::RevokedOutput(..) => {
				match input {
					PackageSolvingData::RevokedHTLCOutput(..) => { true },
					PackageSolvingData::RevokedOutput(..) => { true },
					_ => { false }
				}
			},
			PackageSolvingData::RevokedHTLCOutput(..) => {
				match input {
					PackageSolvingData::RevokedOutput(..) => { true },
					PackageSolvingData::RevokedHTLCOutput(..) => { true },
					_ => { false }
				}
			},
			_ => { mem::discriminant(self) == mem::discriminant(&input) }
		}
	}
	fn finalize_input<Signer: Sign>(&self, bumped_tx: &mut Transaction, i: usize, onchain_handler: &mut OnchainTxHandler<Signer>) -> bool {
		match self {
			PackageSolvingData::RevokedOutput(ref outp) => {
				if let Ok(chan_keys) = TxCreationKeys::derive_new(&onchain_handler.secp_ctx, &outp.per_commitment_point, &outp.counterparty_delayed_payment_base_key, &outp.counterparty_htlc_base_key, &onchain_handler.signer.pubkeys().revocation_basepoint, &onchain_handler.signer.pubkeys().htlc_basepoint) {
					let witness_script = chan_utils::get_revokeable_redeemscript(&chan_keys.revocation_key, outp.on_counterparty_tx_csv, &chan_keys.broadcaster_delayed_payment_key);
					//TODO: should we panic on signer failure ?
					if let Ok(sig) = onchain_handler.signer.sign_justice_revoked_output(&bumped_tx, i, outp.amount, &outp.per_commitment_key, &onchain_handler.secp_ctx) {
						bumped_tx.input[i].witness.push(sig.serialize_der().to_vec());
						bumped_tx.input[i].witness[0].push(SigHashType::All as u8);
						bumped_tx.input[i].witness.push(vec!(1));
						bumped_tx.input[i].witness.push(witness_script.clone().into_bytes());
					} else { return false; }
				}
			},
			PackageSolvingData::RevokedHTLCOutput(ref outp) => {
				if let Ok(chan_keys) = TxCreationKeys::derive_new(&onchain_handler.secp_ctx, &outp.per_commitment_point, &outp.counterparty_delayed_payment_base_key, &outp.counterparty_htlc_base_key, &onchain_handler.signer.pubkeys().revocation_basepoint, &onchain_handler.signer.pubkeys().htlc_basepoint) {
					let witness_script = chan_utils::get_htlc_redeemscript_with_explicit_keys(&outp.htlc, &chan_keys.broadcaster_htlc_key, &chan_keys.countersignatory_htlc_key, &chan_keys.revocation_key);
					//TODO: should we panic on signer failure ?
					if let Ok(sig) = onchain_handler.signer.sign_justice_revoked_htlc(&bumped_tx, i, outp.amount, &outp.per_commitment_key, &outp.htlc, &onchain_handler.secp_ctx) {
						bumped_tx.input[i].witness.push(sig.serialize_der().to_vec());
						bumped_tx.input[i].witness[0].push(SigHashType::All as u8);
						bumped_tx.input[i].witness.push(chan_keys.revocation_key.clone().serialize().to_vec());
						bumped_tx.input[i].witness.push(witness_script.clone().into_bytes());
					} else { return false; }
				}
			},
			PackageSolvingData::CounterpartyOfferedHTLCOutput(ref outp) => {
				if let Ok(chan_keys) = TxCreationKeys::derive_new(&onchain_handler.secp_ctx, &outp.per_commitment_point, &outp.counterparty_delayed_payment_base_key, &outp.counterparty_htlc_base_key, &onchain_handler.signer.pubkeys().revocation_basepoint, &onchain_handler.signer.pubkeys().htlc_basepoint) {
					let witness_script = chan_utils::get_htlc_redeemscript_with_explicit_keys(&outp.htlc, &chan_keys.broadcaster_htlc_key, &chan_keys.countersignatory_htlc_key, &chan_keys.revocation_key);

					if let Ok(sig) = onchain_handler.signer.sign_counterparty_htlc_transaction(&bumped_tx, i, &outp.htlc.amount_msat / 1000, &outp.per_commitment_point, &outp.htlc, &onchain_handler.secp_ctx) {
						bumped_tx.input[i].witness.push(sig.serialize_der().to_vec());
						bumped_tx.input[i].witness[0].push(SigHashType::All as u8);
						bumped_tx.input[i].witness.push(outp.preimage.0.to_vec());
						bumped_tx.input[i].witness.push(witness_script.clone().into_bytes());
					}
				}
			},
			PackageSolvingData::CounterpartyReceivedHTLCOutput(ref outp) => {
				if let Ok(chan_keys) = TxCreationKeys::derive_new(&onchain_handler.secp_ctx, &outp.per_commitment_point, &outp.counterparty_delayed_payment_base_key, &outp.counterparty_htlc_base_key, &onchain_handler.signer.pubkeys().revocation_basepoint, &onchain_handler.signer.pubkeys().htlc_basepoint) {
					let witness_script = chan_utils::get_htlc_redeemscript_with_explicit_keys(&outp.htlc, &chan_keys.broadcaster_htlc_key, &chan_keys.countersignatory_htlc_key, &chan_keys.revocation_key);

					bumped_tx.lock_time = outp.htlc.cltv_expiry; // Right now we don't aggregate time-locked transaction, if we do we should set lock_time before to avoid breaking hash computation
					if let Ok(sig) = onchain_handler.signer.sign_counterparty_htlc_transaction(&bumped_tx, i, &outp.htlc.amount_msat / 1000, &outp.per_commitment_point, &outp.htlc, &onchain_handler.secp_ctx) {
						bumped_tx.input[i].witness.push(sig.serialize_der().to_vec());
						bumped_tx.input[i].witness[0].push(SigHashType::All as u8);
						// Due to BIP146 (MINIMALIF) this must be a zero-length element to relay.
						bumped_tx.input[i].witness.push(vec![]);
						bumped_tx.input[i].witness.push(witness_script.clone().into_bytes());
					}
				}
			},
			_ => { panic!("API Error!"); }
		}
		true
	}
	fn get_finalized_tx<Signer: Sign>(&self, outpoint: &BitcoinOutPoint, onchain_handler: &mut OnchainTxHandler<Signer>) -> Option<Transaction> {
		match self {
			PackageSolvingData::HolderHTLCOutput(ref outp) => { return onchain_handler.get_fully_signed_htlc_tx(outpoint, &outp.preimage); }
			PackageSolvingData::HolderFundingOutput(ref outp) => { return Some(onchain_handler.get_fully_signed_holder_tx(&outp.funding_redeemscript)); }
			_ => { panic!("API Error!"); }
		}
	}
}

impl Writeable for PackageSolvingData {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
		match self {
			PackageSolvingData::RevokedOutput(ref revoked_outp) => {
				0u8.write(writer)?;
				revoked_outp.write(writer)?;
			},
			PackageSolvingData::RevokedHTLCOutput(ref revoked_outp) => {
				1u8.write(writer)?;
				revoked_outp.write(writer)?;
			},
			PackageSolvingData::CounterpartyOfferedHTLCOutput(ref counterparty_outp) => {
				2u8.write(writer)?;
				counterparty_outp.write(writer)?;
			},
			PackageSolvingData::CounterpartyReceivedHTLCOutput(ref counterparty_outp) => {
				3u8.write(writer)?;
				counterparty_outp.write(writer)?;
			},
			PackageSolvingData::HolderHTLCOutput(ref holder_outp) => {
				4u8.write(writer)?;
				holder_outp.write(writer)?;
			},
			PackageSolvingData::HolderFundingOutput(ref funding_outp) => {
				5u8.write(writer)?;
				funding_outp.write(writer)?;
			}
		}
		Ok(())
	}
}

impl Readable for PackageSolvingData {
	fn read<R: ::std::io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
		let byte = <u8 as Readable>::read(reader)?;
		let solving_data = match byte {
			0 => {
				PackageSolvingData::RevokedOutput(Readable::read(reader)?)
			},
			1 => {
				PackageSolvingData::RevokedHTLCOutput(Readable::read(reader)?)
			},
			2 => {
				PackageSolvingData::CounterpartyOfferedHTLCOutput(Readable::read(reader)?)
			},
			3 => {
				PackageSolvingData::CounterpartyReceivedHTLCOutput(Readable::read(reader)?)
			},
			4 => {
				PackageSolvingData::HolderHTLCOutput(Readable::read(reader)?)
			},
			5 => {
				PackageSolvingData::HolderFundingOutput(Readable::read(reader)?)
			}
			_ => return Err(DecodeError::UnknownVersion)
		};
		Ok(solving_data)
	}
}

/// A malleable package might be aggregated with other packages to save on fees.
/// A untractable package has been counter-signed and aggregable will break cached counterparty
/// signatures.
#[derive(Clone, PartialEq)]
pub(crate) enum PackageMalleability {
	Malleable,
	Untractable,
}

/// A structure to describe a package content that is generated by ChannelMonitor and
/// used by OnchainTxHandler to generate and broadcast transactions settling onchain claims.
///
/// A package is defined as one or more transactions claiming onchain outputs in reaction
/// to confirmation of a channel transaction. Those packages might be aggregated to save on
/// fees, if satisfaction of outputs's witnessScript let's us do so.
///
/// As packages are time-sensitive, we fee-bump and rebroadcast them at scheduled intervals.
/// Failing to confirm a package translate as a loss of funds for the user.
#[derive(Clone, PartialEq)]
pub struct PackageTemplate {
	// List of onchain outputs and solving data to generate satisfying witnesses.
	inputs: Vec<(BitcoinOutPoint, PackageSolvingData)>,
	// Packages are deemed as malleable if we have local knwoledge of at least one set of
	// private keys yielding a satisfying witnesses. Malleability implies that we can aggregate
	// packages among them to save on fees or rely on RBF to bump their feerates.
	// Untractable packages have been counter-signed and thus imply that we can't aggregate
	// them without breaking signatures. Fee-bumping strategy will also rely on CPFP.
	malleability: PackageMalleability,
	// Block height after which the earlier-output belonging to this package is mature for a
	// competing claim by the counterparty. As our chain tip becomes nearer from the timelock,
	// the fee-bumping frequency will increase. See `OnchainTxHandler::get_height_timer`.
	soonest_conf_deadline: u32,
	// Determines if this package can be aggregated.
	// Timelocked outputs belonging to the same transaction might have differing
	// satisfying heights. Picking up the later height among the output set would be a valid
	// aggregable strategy but it comes with at least 2 trade-offs :
	// * earlier-output fund are going to take longer to come back
	// * CLTV delta backing up a corresponding HTLC on an upstream channel could be swallowed
	// by the requirement of the later-output part of the set
	// For now, we mark such timelocked outputs as non-aggregable, though we might introduce
	// smarter aggregable strategy in the future.
	aggregable: bool,
	// Cache of package feerate committed at previous (re)broadcast. If bumping resources
	// (either claimed output value or external utxo), it will keep increasing until holder
	// or counterparty successful claim.
	feerate_previous: u64,
	// Cache of next height at which fee-bumping and rebroadcast will be attempted. In
	// the future, we might abstract it to an observed mempool fluctuation.
	height_timer: Option<u32>,
	// Confirmation height of the claimed outputs set transaction. In case of reorg reaching
	// it, we wipe out and forget the package.
	height_original: u32,
}

impl PackageTemplate {
	pub(crate) fn is_malleable(&self) -> bool {
		self.malleability == PackageMalleability::Malleable
	}
	pub(crate) fn timelock(&self) -> u32 {
		self.soonest_conf_deadline
	}
	pub(crate) fn aggregable(&self) -> bool {
		self.aggregable
	}
	pub(crate) fn feerate(&self) -> u64 {
		self.feerate_previous
	}
	pub(crate) fn set_feerate(&mut self, new_feerate: u64) {
		self.feerate_previous = new_feerate;
	}
	pub(crate) fn timer(&self) -> Option<u32> {
		if let Some(ref timer) = self.height_timer {
			return Some(*timer);
		}
		None
	}
	pub(crate) fn set_timer(&mut self, new_timer: Option<u32>) {
		self.height_timer = new_timer;
	}
	pub(crate) fn outpoints(&self) -> Vec<&BitcoinOutPoint> {
		self.inputs.iter().map(|(o, _)| o).collect()
	}
	pub(crate) fn split_package(&mut self, split_outp: &BitcoinOutPoint) -> Option<PackageTemplate> {
		match self.malleability {
			PackageMalleability::Malleable => {
				let mut split_package = None;
				let timelock = self.soonest_conf_deadline;
				let aggregable = self.aggregable;
				let feerate_previous = self.feerate_previous;
				let height_timer = self.height_timer;
				let height_original = self.height_original;
				self.inputs.retain(|outp| {
					if *split_outp == outp.0 {
						split_package = Some(PackageTemplate {
							inputs: vec![(outp.0, outp.1.clone())],
							malleability: PackageMalleability::Malleable,
							soonest_conf_deadline: timelock,
							aggregable,
							feerate_previous,
							height_timer,
							height_original,
						});
						return false;
					}
					return true;
				});
				return split_package;
			},
			_ => {
				// Note, we may try to split on remote transaction for
				// which we don't have a competing one (HTLC-Success before
				// timelock expiration). This explain we don't panic!
				// We should refactor OnchainTxHandler::block_connected to
				// only test equality on competing claims.
				return None;
			}
		}
	}
	pub(crate) fn merge_package(&mut self, mut merge_from: PackageTemplate) {
		assert_eq!(self.height_original, merge_from.height_original);
		if self.malleability == PackageMalleability::Untractable || merge_from.malleability == PackageMalleability::Untractable {
			panic!("Merging template on untractable packages");
		}
		if !self.aggregable || !merge_from.aggregable {
			panic!("Merging non aggregatable packages");
		}
		if let Some((_, lead_input)) = self.inputs.first() {
			for (_, v) in merge_from.inputs.iter() {
				if !lead_input.is_compatible(v) { panic!("Merging outputs from differing types !"); }
			}
		} else { panic!("Merging template on an empty package"); }
		for (k, v) in merge_from.inputs.drain(..) {
			self.inputs.push((k, v));
		}
		//TODO: verify coverage and sanity?
		if self.soonest_conf_deadline > merge_from.soonest_conf_deadline {
			self.soonest_conf_deadline = merge_from.soonest_conf_deadline;
		}
		if self.feerate_previous > merge_from.feerate_previous {
			self.feerate_previous = merge_from.feerate_previous;
		}
		self.height_timer = cmp::min(self.height_timer, merge_from.height_timer);
	}
	pub(crate) fn package_amount(&self) -> u64 {
		let mut amounts = 0;
		for (_, outp) in self.inputs.iter() {
			amounts += outp.amount();
		}
		amounts
	}
	pub(crate) fn package_weight(&self, destination_script: &Script) -> usize {
		let mut inputs_weight = 0;
		let mut witnesses_weight = 2; // count segwit flags
		for (_, outp) in self.inputs.iter() {
			// previous_out_point: 36 bytes ; var_int: 1 byte ; sequence: 4 bytes
			inputs_weight += 41 * WITNESS_SCALE_FACTOR;
			witnesses_weight += outp.weight();
		}
		// version: 4 bytes ; count_tx_in: 1 byte ; count_tx_out: 1 byte ; lock_time: 4 bytes
		let transaction_weight = 10 * WITNESS_SCALE_FACTOR;
		// value: 8 bytes ; var_int: 1 byte ; pk_script: `destination_script.len()`
		let output_weight = (8 + 1 + destination_script.len()) * WITNESS_SCALE_FACTOR;
		inputs_weight + witnesses_weight + transaction_weight + output_weight
	}
	pub(crate) fn finalize_package<L: Deref, Signer: Sign>(&self, onchain_handler: &mut OnchainTxHandler<Signer>, value: u64, destination_script: Script, logger: &L) -> Option<Transaction>
		where L::Target: Logger,
	{
		match self.malleability {
			PackageMalleability::Malleable => {
				let mut bumped_tx = Transaction {
					version: 2,
					lock_time: 0,
					input: vec![],
					output: vec![TxOut {
						script_pubkey: destination_script,
						value,
					}],
				};
				for (outpoint, _) in self.inputs.iter() {
					bumped_tx.input.push(TxIn {
						previous_output: *outpoint,
						script_sig: Script::new(),
						sequence: 0xfffffffd,
						witness: Vec::new(),
					});
				}
				for (i, (outpoint, out)) in self.inputs.iter().enumerate() {
					log_trace!(logger, "Adding claiming input for outpoint {}:{}", outpoint.txid, outpoint.vout);
					if !out.finalize_input(&mut bumped_tx, i, onchain_handler) { return None; }
				}
				log_trace!(logger, "Finalized transaction {} ready to broadcast", bumped_tx.txid());
				return Some(bumped_tx);
			},
			PackageMalleability::Untractable => {
				if let Some((outpoint, outp)) = self.inputs.first() {
					if let Some(final_tx) = outp.get_finalized_tx(outpoint, onchain_handler) {
						log_trace!(logger, "Adding claiming input for outpoint {}:{}", outpoint.txid, outpoint.vout);
						log_trace!(logger, "Finalized transaction {} ready to broadcast", final_tx.txid());
						return Some(final_tx);
					}
					return None;
				} else { panic!("API Error: Package must not be inputs empty"); }
			},
		}
	}
	/// In LN, output claimed are time-sensitive, which means we have to spend them before reaching some timelock expiration. At in-channel
	/// output detection, we generate a first version of a claim tx and associate to it a height timer. A height timer is an absolute block
	/// height that once reached we should generate a new bumped "version" of the claim tx to be sure that we safely claim outputs before
	/// that our counterparty can do so. If timelock expires soon, height timer is going to be scaled down in consequence to increase
	/// frequency of the bump and so increase our bets of success.
	pub(crate) fn get_height_timer(&self, current_height: u32) -> u32 {
		if self.soonest_conf_deadline <= current_height + MIDDLE_FREQUENCY_BUMP_INTERVAL {
			return current_height + HIGH_FREQUENCY_BUMP_INTERVAL
		} else if self.soonest_conf_deadline - current_height <= LOW_FREQUENCY_BUMP_INTERVAL {
			return current_height + MIDDLE_FREQUENCY_BUMP_INTERVAL
		}
		current_height + LOW_FREQUENCY_BUMP_INTERVAL
	}
	pub (crate) fn build_package(txid: Txid, vout: u32, input_solving_data: PackageSolvingData, soonest_conf_deadline: u32, aggregable: bool, height_original: u32) -> Self {
		let malleability = match input_solving_data {
			PackageSolvingData::RevokedOutput(..) => { PackageMalleability::Malleable },
			PackageSolvingData::RevokedHTLCOutput(..) => { PackageMalleability::Malleable },
			PackageSolvingData::CounterpartyOfferedHTLCOutput(..) => { PackageMalleability::Malleable },
			PackageSolvingData::CounterpartyReceivedHTLCOutput(..) => { PackageMalleability::Malleable },
			PackageSolvingData::HolderHTLCOutput(..) => { PackageMalleability::Untractable },
			PackageSolvingData::HolderFundingOutput(..) => { PackageMalleability::Untractable },
		};
		let mut inputs = Vec::with_capacity(1);
		inputs.push((BitcoinOutPoint { txid, vout }, input_solving_data));
		PackageTemplate {
			inputs,
			malleability,
			soonest_conf_deadline,
			aggregable,
			feerate_previous: 0,
			height_timer: None,
			height_original,
		}
	}
}

impl Writeable for PackageTemplate {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
		writer.write_all(&byte_utils::be64_to_array(self.inputs.len() as u64))?;
		for (ref outpoint, ref rev_outp) in self.inputs.iter() {
			outpoint.write(writer)?;
			rev_outp.write(writer)?;
		}
		self.soonest_conf_deadline.write(writer)?;
		self.feerate_previous.write(writer)?;
		self.height_timer.write(writer)?;
		self.height_original.write(writer)?;
		Ok(())
	}
}

impl Readable for PackageTemplate {
	fn read<R: ::std::io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
		let inputs_count = <u64 as Readable>::read(reader)?;
		let mut inputs: Vec<(BitcoinOutPoint, PackageSolvingData)> = Vec::with_capacity(cmp::min(inputs_count as usize, MAX_ALLOC_SIZE / 128));
		for _ in 0..inputs_count {
			let outpoint = Readable::read(reader)?;
			let rev_outp = Readable::read(reader)?;
			inputs.push((outpoint, rev_outp));
		}
		let (malleability, aggregable) = if let Some((_, lead_input)) = inputs.first() {
			match lead_input {
				PackageSolvingData::RevokedOutput(..) => { (PackageMalleability::Malleable, true) },
				PackageSolvingData::RevokedHTLCOutput(..) => { (PackageMalleability::Malleable, true) },
				PackageSolvingData::CounterpartyOfferedHTLCOutput(..) => { (PackageMalleability::Malleable, true) },
				PackageSolvingData::CounterpartyReceivedHTLCOutput(..) => { (PackageMalleability::Malleable, false) },
				PackageSolvingData::HolderHTLCOutput(..) => { (PackageMalleability::Untractable, false) },
				PackageSolvingData::HolderFundingOutput(..) => { (PackageMalleability::Untractable, false) },
			}
		} else { return Err(DecodeError::InvalidValue); };
		let soonest_conf_deadline = Readable::read(reader)?;
		let feerate_previous = Readable::read(reader)?;
		let height_timer = Readable::read(reader)?;
		let height_original = Readable::read(reader)?;
		Ok(PackageTemplate {
			inputs,
			malleability,
			soonest_conf_deadline,
			aggregable,
			feerate_previous,
			height_timer,
			height_original,
		})
	}
}

/// Attempt to propose a bumping fee for a transaction from its spent output's values and predicted
/// weight. We start with the highest priority feerate returned by the node's fee estimator then
/// fall-back to lower priorities until we have enough value available to suck from.
///
/// If the proposed fee is less than the available spent output's values, we return the proposed
/// fee and the corresponding updated feerate. If the proposed fee is equal or more than the
/// available spent output's values, we return nothing
fn compute_fee_from_spent_amounts<F: Deref, L: Deref>(input_amounts: u64, predicted_weight: usize, fee_estimator: &F, logger: &L) -> Option<(u64, u64)>
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

/// Attempt to propose a bumping fee for a transaction from its spent output's values and predicted
/// weight. If feerates proposed by the fee-estimator have been increasing since last fee-bumping
/// attempt, use them. Otherwise, blindly bump the feerate by 25% of the previous feerate. We also
/// verify that those bumping heuristics respect BIP125 rules 3) and 4) and if required adjust
/// the new fee to meet the RBF policy requirement.
fn feerate_bump<F: Deref, L: Deref>(predicted_weight: usize, input_amounts: u64, previous_feerate: u64, fee_estimator: &F, logger: &L) -> Option<(u64, u64)>
	where F::Target: FeeEstimator,
	      L::Target: Logger,
{
	// If old feerate inferior to actual one given back by Fee Estimator, use it to compute new fee...
	let new_fee = if let Some((new_fee, _)) = compute_fee_from_spent_amounts(input_amounts, predicted_weight, fee_estimator, logger) {
		let updated_feerate = new_fee / (predicted_weight as u64 * 1000);
		if updated_feerate > previous_feerate {
			new_fee
		} else {
			// ...else just increase the previous feerate by 25% (because that's a nice number)
			let new_fee = previous_feerate * (predicted_weight as u64) / 750;
			if input_amounts <= new_fee {
				log_trace!(logger, "Can't 25% bump new claiming tx, amount {} is too small", input_amounts);
				return None;
			}
			new_fee
		}
	} else {
		log_trace!(logger, "Can't new-estimation bump new claiming tx, amount {} is too small", input_amounts);
		return None;
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

/// Deduce a new proposed fee from the claiming transaction output value.
/// If the new proposed fee is superior to the consumed outpoint's value, burn everything in miner's
/// fee to deter counterparties attacker.
pub(crate) fn compute_output_value<F: Deref, L: Deref>(predicted_weight: usize, input_amounts: u64, previous_feerate: u64, fee_estimator: &F, logger: &L) -> Option<(u64, u64)>
	where F::Target: FeeEstimator,
	      L::Target: Logger,
{
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
		if let Some((new_fee, feerate)) = compute_fee_from_spent_amounts(input_amounts, predicted_weight, fee_estimator, logger) {
				return Some((input_amounts - new_fee, feerate));
		}
	}
	None
}

