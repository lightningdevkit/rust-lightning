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
use bitcoin::blockdata::transaction::{TxOut,TxIn, Transaction, EcdsaSighashType};
use bitcoin::blockdata::transaction::OutPoint as BitcoinOutPoint;
use bitcoin::blockdata::script::Script;

use bitcoin::hash_types::Txid;

use bitcoin::secp256k1::{SecretKey,PublicKey};

use crate::ln::PaymentPreimage;
use crate::ln::chan_utils::{TxCreationKeys, HTLCOutputInCommitment};
use crate::ln::chan_utils;
use crate::ln::msgs::DecodeError;
use crate::chain::chaininterface::{FeeEstimator, ConfirmationTarget, MIN_RELAY_FEE_SAT_PER_1000_WEIGHT};
use crate::chain::keysinterface::WriteableEcdsaChannelSigner;
#[cfg(anchors)]
use crate::chain::onchaintx::ExternalHTLCClaim;
use crate::chain::onchaintx::OnchainTxHandler;
use crate::util::logger::Logger;
use crate::util::ser::{Readable, Writer, Writeable};

use crate::io;
use crate::prelude::*;
use core::cmp;
#[cfg(anchors)]
use core::convert::TryInto;
use core::mem;
use core::ops::Deref;
use bitcoin::{PackedLockTime, Sequence, Witness};

use super::chaininterface::LowerBoundedFeeEstimator;

const MAX_ALLOC_SIZE: usize = 64*1024;


pub(crate) fn weight_revoked_offered_htlc(opt_anchors: bool) -> u64 {
	// number_of_witness_elements + sig_length + revocation_sig + pubkey_length + revocationpubkey + witness_script_length + witness_script
	const WEIGHT_REVOKED_OFFERED_HTLC: u64 = 1 + 1 + 73 + 1 + 33 + 1 + 133;
	const WEIGHT_REVOKED_OFFERED_HTLC_ANCHORS: u64 = WEIGHT_REVOKED_OFFERED_HTLC + 3; // + OP_1 + OP_CSV + OP_DROP
	if opt_anchors { WEIGHT_REVOKED_OFFERED_HTLC_ANCHORS } else { WEIGHT_REVOKED_OFFERED_HTLC }
}

pub(crate) fn weight_revoked_received_htlc(opt_anchors: bool) -> u64 {
	// number_of_witness_elements + sig_length + revocation_sig + pubkey_length + revocationpubkey + witness_script_length + witness_script
	const WEIGHT_REVOKED_RECEIVED_HTLC: u64 = 1 + 1 + 73 + 1 + 33 + 1 +  139;
	const WEIGHT_REVOKED_RECEIVED_HTLC_ANCHORS: u64 = WEIGHT_REVOKED_RECEIVED_HTLC + 3; // + OP_1 + OP_CSV + OP_DROP
	if opt_anchors { WEIGHT_REVOKED_RECEIVED_HTLC_ANCHORS } else { WEIGHT_REVOKED_RECEIVED_HTLC }
}

pub(crate) fn weight_offered_htlc(opt_anchors: bool) -> u64 {
	// number_of_witness_elements + sig_length + counterpartyhtlc_sig  + preimage_length + preimage + witness_script_length + witness_script
	const WEIGHT_OFFERED_HTLC: u64 = 1 + 1 + 73 + 1 + 32 + 1 + 133;
	const WEIGHT_OFFERED_HTLC_ANCHORS: u64 = WEIGHT_OFFERED_HTLC + 3; // + OP_1 + OP_CSV + OP_DROP
	if opt_anchors { WEIGHT_OFFERED_HTLC_ANCHORS } else { WEIGHT_OFFERED_HTLC }
}

pub(crate) fn weight_received_htlc(opt_anchors: bool) -> u64 {
	// number_of_witness_elements + sig_length + counterpartyhtlc_sig + empty_vec_length + empty_vec + witness_script_length + witness_script
	const WEIGHT_RECEIVED_HTLC: u64 = 1 + 1 + 73 + 1 + 1 + 1 + 139;
	const WEIGHT_RECEIVED_HTLC_ANCHORS: u64 = WEIGHT_RECEIVED_HTLC + 3; // + OP_1 + OP_CSV + OP_DROP
	if opt_anchors { WEIGHT_RECEIVED_HTLC_ANCHORS } else { WEIGHT_RECEIVED_HTLC }
}

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
#[derive(Clone, PartialEq, Eq)]
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

impl_writeable_tlv_based!(RevokedOutput, {
	(0, per_commitment_point, required),
	(2, counterparty_delayed_payment_base_key, required),
	(4, counterparty_htlc_base_key, required),
	(6, per_commitment_key, required),
	(8, weight, required),
	(10, amount, required),
	(12, on_counterparty_tx_csv, required),
});

/// A struct to describe a revoked offered output and corresponding information to generate a
/// solving witness.
///
/// HTLCOuputInCommitment (hash timelock, direction) and pubkeys are used to generate a suitable
/// witnessScript.
///
/// CSV is used as part of a witnessScript redeeming a balance output, amount is used as part
/// of the signature hash and revocation secret to generate a satisfying witness.
#[derive(Clone, PartialEq, Eq)]
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
	pub(crate) fn build(per_commitment_point: PublicKey, counterparty_delayed_payment_base_key: PublicKey, counterparty_htlc_base_key: PublicKey, per_commitment_key: SecretKey, amount: u64, htlc: HTLCOutputInCommitment, opt_anchors: bool) -> Self {
		let weight = if htlc.offered { weight_revoked_offered_htlc(opt_anchors) } else { weight_revoked_received_htlc(opt_anchors) };
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

impl_writeable_tlv_based!(RevokedHTLCOutput, {
	(0, per_commitment_point, required),
	(2, counterparty_delayed_payment_base_key, required),
	(4, counterparty_htlc_base_key, required),
	(6, per_commitment_key, required),
	(8, weight, required),
	(10, amount, required),
	(12, htlc, required),
});

/// A struct to describe a HTLC output on a counterparty commitment transaction.
///
/// HTLCOutputInCommitment (hash, timelock, directon) and pubkeys are used to generate a suitable
/// witnessScript.
///
/// The preimage is used as part of the witness.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct CounterpartyOfferedHTLCOutput {
	per_commitment_point: PublicKey,
	counterparty_delayed_payment_base_key: PublicKey,
	counterparty_htlc_base_key: PublicKey,
	preimage: PaymentPreimage,
	htlc: HTLCOutputInCommitment,
	opt_anchors: Option<()>,
}

impl CounterpartyOfferedHTLCOutput {
	pub(crate) fn build(per_commitment_point: PublicKey, counterparty_delayed_payment_base_key: PublicKey, counterparty_htlc_base_key: PublicKey, preimage: PaymentPreimage, htlc: HTLCOutputInCommitment, opt_anchors: bool) -> Self {
		CounterpartyOfferedHTLCOutput {
			per_commitment_point,
			counterparty_delayed_payment_base_key,
			counterparty_htlc_base_key,
			preimage,
			htlc,
			opt_anchors: if opt_anchors { Some(()) } else { None },
		}
	}

	fn opt_anchors(&self) -> bool {
		self.opt_anchors.is_some()
	}
}

impl_writeable_tlv_based!(CounterpartyOfferedHTLCOutput, {
	(0, per_commitment_point, required),
	(2, counterparty_delayed_payment_base_key, required),
	(4, counterparty_htlc_base_key, required),
	(6, preimage, required),
	(8, htlc, required),
	(10, opt_anchors, option),
});

/// A struct to describe a HTLC output on a counterparty commitment transaction.
///
/// HTLCOutputInCommitment (hash, timelock, directon) and pubkeys are used to generate a suitable
/// witnessScript.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct CounterpartyReceivedHTLCOutput {
	per_commitment_point: PublicKey,
	counterparty_delayed_payment_base_key: PublicKey,
	counterparty_htlc_base_key: PublicKey,
	htlc: HTLCOutputInCommitment,
	opt_anchors: Option<()>,
}

impl CounterpartyReceivedHTLCOutput {
	pub(crate) fn build(per_commitment_point: PublicKey, counterparty_delayed_payment_base_key: PublicKey, counterparty_htlc_base_key: PublicKey, htlc: HTLCOutputInCommitment, opt_anchors: bool) -> Self {
		CounterpartyReceivedHTLCOutput {
			per_commitment_point,
			counterparty_delayed_payment_base_key,
			counterparty_htlc_base_key,
			htlc,
			opt_anchors: if opt_anchors { Some(()) } else { None },
		}
	}

	fn opt_anchors(&self) -> bool {
		self.opt_anchors.is_some()
	}
}

impl_writeable_tlv_based!(CounterpartyReceivedHTLCOutput, {
	(0, per_commitment_point, required),
	(2, counterparty_delayed_payment_base_key, required),
	(4, counterparty_htlc_base_key, required),
	(6, htlc, required),
	(8, opt_anchors, option),
});

/// A struct to describe a HTLC output on holder commitment transaction.
///
/// Either offered or received, the amount is always used as part of the bip143 sighash.
/// Preimage is only included as part of the witness in former case.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct HolderHTLCOutput {
	preimage: Option<PaymentPreimage>,
	amount_msat: u64,
	/// Defaults to 0 for HTLC-Success transactions, which have no expiry
	cltv_expiry: u32,
	opt_anchors: Option<()>,
}

impl HolderHTLCOutput {
	pub(crate) fn build_offered(amount_msat: u64, cltv_expiry: u32, opt_anchors: bool) -> Self {
		HolderHTLCOutput {
			preimage: None,
			amount_msat,
			cltv_expiry,
			opt_anchors: if opt_anchors { Some(()) } else { None } ,
		}
	}

	pub(crate) fn build_accepted(preimage: PaymentPreimage, amount_msat: u64, opt_anchors: bool) -> Self {
		HolderHTLCOutput {
			preimage: Some(preimage),
			amount_msat,
			cltv_expiry: 0,
			opt_anchors: if opt_anchors { Some(()) } else { None } ,
		}
	}

	fn opt_anchors(&self) -> bool {
		self.opt_anchors.is_some()
	}
}

impl_writeable_tlv_based!(HolderHTLCOutput, {
	(0, amount_msat, required),
	(2, cltv_expiry, required),
	(4, preimage, option),
	(6, opt_anchors, option)
});

/// A struct to describe the channel output on the funding transaction.
///
/// witnessScript is used as part of the witness redeeming the funding utxo.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct HolderFundingOutput {
	funding_redeemscript: Script,
	funding_amount: Option<u64>,
	opt_anchors: Option<()>,
}


impl HolderFundingOutput {
	pub(crate) fn build(funding_redeemscript: Script, funding_amount: u64, opt_anchors: bool) -> Self {
		HolderFundingOutput {
			funding_redeemscript,
			funding_amount: Some(funding_amount),
			opt_anchors: if opt_anchors { Some(()) } else { None },
		}
	}

	fn opt_anchors(&self) -> bool {
		self.opt_anchors.is_some()
	}
}

impl_writeable_tlv_based!(HolderFundingOutput, {
	(0, funding_redeemscript, required),
	(2, opt_anchors, option),
	(3, funding_amount, option),
});

/// A wrapper encapsulating all in-protocol differing outputs types.
///
/// The generic API offers access to an outputs common attributes or allow transformation such as
/// finalizing an input claiming the output.
#[derive(Clone, PartialEq, Eq)]
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
			PackageSolvingData::RevokedOutput(ref outp) => outp.amount,
			PackageSolvingData::RevokedHTLCOutput(ref outp) => outp.amount,
			PackageSolvingData::CounterpartyOfferedHTLCOutput(ref outp) => outp.htlc.amount_msat / 1000,
			PackageSolvingData::CounterpartyReceivedHTLCOutput(ref outp) => outp.htlc.amount_msat / 1000,
			PackageSolvingData::HolderHTLCOutput(ref outp) => {
				debug_assert!(outp.opt_anchors());
				outp.amount_msat / 1000
			},
			PackageSolvingData::HolderFundingOutput(ref outp) => {
				debug_assert!(outp.opt_anchors());
				outp.funding_amount.unwrap()
			}
		};
		amt
	}
	fn weight(&self) -> usize {
		match self {
			PackageSolvingData::RevokedOutput(ref outp) => outp.weight as usize,
			PackageSolvingData::RevokedHTLCOutput(ref outp) => outp.weight as usize,
			PackageSolvingData::CounterpartyOfferedHTLCOutput(ref outp) => weight_offered_htlc(outp.opt_anchors()) as usize,
			PackageSolvingData::CounterpartyReceivedHTLCOutput(ref outp) => weight_received_htlc(outp.opt_anchors()) as usize,
			PackageSolvingData::HolderHTLCOutput(ref outp) => {
				debug_assert!(outp.opt_anchors());
				if outp.preimage.is_none() {
					weight_offered_htlc(true) as usize
				} else {
					weight_received_htlc(true) as usize
				}
			},
			// Since HolderFundingOutput maps to an untractable package that is already signed, its
			// weight can be determined from the transaction itself.
			PackageSolvingData::HolderFundingOutput(..) => unreachable!(),
		}
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
	fn finalize_input<Signer: WriteableEcdsaChannelSigner>(&self, bumped_tx: &mut Transaction, i: usize, onchain_handler: &mut OnchainTxHandler<Signer>) -> bool {
		match self {
			PackageSolvingData::RevokedOutput(ref outp) => {
				let chan_keys = TxCreationKeys::derive_new(&onchain_handler.secp_ctx, &outp.per_commitment_point, &outp.counterparty_delayed_payment_base_key, &outp.counterparty_htlc_base_key, &onchain_handler.signer.pubkeys().revocation_basepoint, &onchain_handler.signer.pubkeys().htlc_basepoint);
				let witness_script = chan_utils::get_revokeable_redeemscript(&chan_keys.revocation_key, outp.on_counterparty_tx_csv, &chan_keys.broadcaster_delayed_payment_key);
				//TODO: should we panic on signer failure ?
				if let Ok(sig) = onchain_handler.signer.sign_justice_revoked_output(&bumped_tx, i, outp.amount, &outp.per_commitment_key, &onchain_handler.secp_ctx) {
					let mut ser_sig = sig.serialize_der().to_vec();
					ser_sig.push(EcdsaSighashType::All as u8);
					bumped_tx.input[i].witness.push(ser_sig);
					bumped_tx.input[i].witness.push(vec!(1));
					bumped_tx.input[i].witness.push(witness_script.clone().into_bytes());
				} else { return false; }
			},
			PackageSolvingData::RevokedHTLCOutput(ref outp) => {
				let chan_keys = TxCreationKeys::derive_new(&onchain_handler.secp_ctx, &outp.per_commitment_point, &outp.counterparty_delayed_payment_base_key, &outp.counterparty_htlc_base_key, &onchain_handler.signer.pubkeys().revocation_basepoint, &onchain_handler.signer.pubkeys().htlc_basepoint);
				let witness_script = chan_utils::get_htlc_redeemscript_with_explicit_keys(&outp.htlc, onchain_handler.opt_anchors(), &chan_keys.broadcaster_htlc_key, &chan_keys.countersignatory_htlc_key, &chan_keys.revocation_key);
				//TODO: should we panic on signer failure ?
				if let Ok(sig) = onchain_handler.signer.sign_justice_revoked_htlc(&bumped_tx, i, outp.amount, &outp.per_commitment_key, &outp.htlc, &onchain_handler.secp_ctx) {
					let mut ser_sig = sig.serialize_der().to_vec();
					ser_sig.push(EcdsaSighashType::All as u8);
					bumped_tx.input[i].witness.push(ser_sig);
					bumped_tx.input[i].witness.push(chan_keys.revocation_key.clone().serialize().to_vec());
					bumped_tx.input[i].witness.push(witness_script.clone().into_bytes());
				} else { return false; }
			},
			PackageSolvingData::CounterpartyOfferedHTLCOutput(ref outp) => {
				let chan_keys = TxCreationKeys::derive_new(&onchain_handler.secp_ctx, &outp.per_commitment_point, &outp.counterparty_delayed_payment_base_key, &outp.counterparty_htlc_base_key, &onchain_handler.signer.pubkeys().revocation_basepoint, &onchain_handler.signer.pubkeys().htlc_basepoint);
				let witness_script = chan_utils::get_htlc_redeemscript_with_explicit_keys(&outp.htlc, onchain_handler.opt_anchors(), &chan_keys.broadcaster_htlc_key, &chan_keys.countersignatory_htlc_key, &chan_keys.revocation_key);

				if let Ok(sig) = onchain_handler.signer.sign_counterparty_htlc_transaction(&bumped_tx, i, &outp.htlc.amount_msat / 1000, &outp.per_commitment_point, &outp.htlc, &onchain_handler.secp_ctx) {
					let mut ser_sig = sig.serialize_der().to_vec();
					ser_sig.push(EcdsaSighashType::All as u8);
					bumped_tx.input[i].witness.push(ser_sig);
					bumped_tx.input[i].witness.push(outp.preimage.0.to_vec());
					bumped_tx.input[i].witness.push(witness_script.clone().into_bytes());
				}
			},
			PackageSolvingData::CounterpartyReceivedHTLCOutput(ref outp) => {
				let chan_keys = TxCreationKeys::derive_new(&onchain_handler.secp_ctx, &outp.per_commitment_point, &outp.counterparty_delayed_payment_base_key, &outp.counterparty_htlc_base_key, &onchain_handler.signer.pubkeys().revocation_basepoint, &onchain_handler.signer.pubkeys().htlc_basepoint);
				let witness_script = chan_utils::get_htlc_redeemscript_with_explicit_keys(&outp.htlc, onchain_handler.opt_anchors(), &chan_keys.broadcaster_htlc_key, &chan_keys.countersignatory_htlc_key, &chan_keys.revocation_key);

				bumped_tx.lock_time = PackedLockTime(outp.htlc.cltv_expiry); // Right now we don't aggregate time-locked transaction, if we do we should set lock_time before to avoid breaking hash computation
				if let Ok(sig) = onchain_handler.signer.sign_counterparty_htlc_transaction(&bumped_tx, i, &outp.htlc.amount_msat / 1000, &outp.per_commitment_point, &outp.htlc, &onchain_handler.secp_ctx) {
					let mut ser_sig = sig.serialize_der().to_vec();
					ser_sig.push(EcdsaSighashType::All as u8);
					bumped_tx.input[i].witness.push(ser_sig);
					// Due to BIP146 (MINIMALIF) this must be a zero-length element to relay.
					bumped_tx.input[i].witness.push(vec![]);
					bumped_tx.input[i].witness.push(witness_script.clone().into_bytes());
				}
			},
			_ => { panic!("API Error!"); }
		}
		true
	}
	fn get_finalized_tx<Signer: WriteableEcdsaChannelSigner>(&self, outpoint: &BitcoinOutPoint, onchain_handler: &mut OnchainTxHandler<Signer>) -> Option<Transaction> {
		match self {
			PackageSolvingData::HolderHTLCOutput(ref outp) => {
				debug_assert!(!outp.opt_anchors());
				return onchain_handler.get_fully_signed_htlc_tx(outpoint, &outp.preimage);
			}
			PackageSolvingData::HolderFundingOutput(ref outp) => {
				return Some(onchain_handler.get_fully_signed_holder_tx(&outp.funding_redeemscript));
			}
			_ => { panic!("API Error!"); }
		}
	}
	fn absolute_tx_timelock(&self, output_conf_height: u32) -> u32 {
		// Get the absolute timelock at which this output can be spent given the height at which
		// this output was confirmed. We use `output_conf_height + 1` as a safe default as we can
		// be confirmed in the next block and transactions with time lock `current_height + 1`
		// always propagate.
		let absolute_timelock = match self {
			PackageSolvingData::RevokedOutput(_) => output_conf_height + 1,
			PackageSolvingData::RevokedHTLCOutput(_) => output_conf_height + 1,
			PackageSolvingData::CounterpartyOfferedHTLCOutput(_) => output_conf_height + 1,
			PackageSolvingData::CounterpartyReceivedHTLCOutput(ref outp) => cmp::max(outp.htlc.cltv_expiry, output_conf_height + 1),
			PackageSolvingData::HolderHTLCOutput(ref outp) => cmp::max(outp.cltv_expiry, output_conf_height + 1),
			PackageSolvingData::HolderFundingOutput(_) => output_conf_height + 1,
		};
		absolute_timelock
	}
}

impl_writeable_tlv_based_enum!(PackageSolvingData, ;
	(0, RevokedOutput),
	(1, RevokedHTLCOutput),
	(2, CounterpartyOfferedHTLCOutput),
	(3, CounterpartyReceivedHTLCOutput),
	(4, HolderHTLCOutput),
	(5, HolderFundingOutput),
);

/// A malleable package might be aggregated with other packages to save on fees.
/// A untractable package has been counter-signed and aggregable will break cached counterparty
/// signatures.
#[derive(Clone, PartialEq, Eq)]
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
#[derive(Clone, PartialEq, Eq)]
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
	pub(crate) fn inputs(&self) -> impl ExactSizeIterator<Item = &PackageSolvingData> {
		self.inputs.iter().map(|(_, i)| i)
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
	/// Gets the amount of all outptus being spent by this package, only valid for malleable
	/// packages.
	pub(crate) fn package_amount(&self) -> u64 {
		let mut amounts = 0;
		for (_, outp) in self.inputs.iter() {
			amounts += outp.amount();
		}
		amounts
	}
	pub(crate) fn package_timelock(&self) -> u32 {
		self.inputs.iter().map(|(_, outp)| outp.absolute_tx_timelock(self.height_original))
			.max().expect("There must always be at least one output to spend in a PackageTemplate")
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
	#[cfg(anchors)]
	pub(crate) fn construct_malleable_package_with_external_funding<Signer: WriteableEcdsaChannelSigner>(
		&self, onchain_handler: &mut OnchainTxHandler<Signer>,
	) -> Option<Vec<ExternalHTLCClaim>> {
		debug_assert!(self.requires_external_funding());
		let mut htlcs: Option<Vec<ExternalHTLCClaim>> = None;
		for (previous_output, input) in &self.inputs {
			match input {
				PackageSolvingData::HolderHTLCOutput(ref outp) => {
					debug_assert!(outp.opt_anchors());
					onchain_handler.generate_external_htlc_claim(&previous_output, &outp.preimage).map(|htlc| {
						htlcs.get_or_insert_with(|| Vec::with_capacity(self.inputs.len())).push(htlc);
					});
				}
				_ => debug_assert!(false, "Expected HolderHTLCOutputs to not be aggregated with other input types"),
			}
		}
		htlcs
	}
	pub(crate) fn finalize_malleable_package<L: Deref, Signer: WriteableEcdsaChannelSigner>(
		&self, onchain_handler: &mut OnchainTxHandler<Signer>, value: u64, destination_script: Script, logger: &L
	) -> Option<Transaction> where L::Target: Logger {
		debug_assert!(self.is_malleable());
		let mut bumped_tx = Transaction {
			version: 2,
			lock_time: PackedLockTime::ZERO,
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
				sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
				witness: Witness::new(),
			});
		}
		for (i, (outpoint, out)) in self.inputs.iter().enumerate() {
			log_debug!(logger, "Adding claiming input for outpoint {}:{}", outpoint.txid, outpoint.vout);
			if !out.finalize_input(&mut bumped_tx, i, onchain_handler) { return None; }
		}
		log_debug!(logger, "Finalized transaction {} ready to broadcast", bumped_tx.txid());
		Some(bumped_tx)
	}
	pub(crate) fn finalize_untractable_package<L: Deref, Signer: WriteableEcdsaChannelSigner>(
		&self, onchain_handler: &mut OnchainTxHandler<Signer>, logger: &L,
	) -> Option<Transaction> where L::Target: Logger {
		debug_assert!(!self.is_malleable());
		if let Some((outpoint, outp)) = self.inputs.first() {
			if let Some(final_tx) = outp.get_finalized_tx(outpoint, onchain_handler) {
				log_debug!(logger, "Adding claiming input for outpoint {}:{}", outpoint.txid, outpoint.vout);
				log_debug!(logger, "Finalized transaction {} ready to broadcast", final_tx.txid());
				return Some(final_tx);
			}
			return None;
		} else { panic!("API Error: Package must not be inputs empty"); }
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

	/// Returns value in satoshis to be included as package outgoing output amount and feerate
	/// which was used to generate the value. Will not return less than `dust_limit_sats` for the
	/// value.
	pub(crate) fn compute_package_output<F: Deref, L: Deref>(&self, predicted_weight: usize, dust_limit_sats: u64, fee_estimator: &LowerBoundedFeeEstimator<F>, logger: &L) -> Option<(u64, u64)>
		where F::Target: FeeEstimator,
		      L::Target: Logger,
	{
		debug_assert!(self.malleability == PackageMalleability::Malleable, "The package output is fixed for non-malleable packages");
		let input_amounts = self.package_amount();
		assert!(dust_limit_sats as i64 > 0, "Output script must be broadcastable/have a 'real' dust limit.");
		// If old feerate is 0, first iteration of this claim, use normal fee calculation
		if self.feerate_previous != 0 {
			if let Some((new_fee, feerate)) = feerate_bump(predicted_weight, input_amounts, self.feerate_previous, fee_estimator, logger) {
				return Some((cmp::max(input_amounts as i64 - new_fee as i64, dust_limit_sats as i64) as u64, feerate));
			}
		} else {
			if let Some((new_fee, feerate)) = compute_fee_from_spent_amounts(input_amounts, predicted_weight, fee_estimator, logger) {
				return Some((cmp::max(input_amounts as i64 - new_fee as i64, dust_limit_sats as i64) as u64, feerate));
			}
		}
		None
	}

	#[cfg(anchors)]
	/// Computes a feerate based on the given confirmation target. If a previous feerate was used,
	/// and the new feerate is below it, we'll use a 25% increase of the previous feerate instead of
	/// the new one.
	pub(crate) fn compute_package_feerate<F: Deref>(
		&self, fee_estimator: &LowerBoundedFeeEstimator<F>, conf_target: ConfirmationTarget,
	) -> u32 where F::Target: FeeEstimator {
		let feerate_estimate = fee_estimator.bounded_sat_per_1000_weight(conf_target);
		if self.feerate_previous != 0 {
			// If old feerate inferior to actual one given back by Fee Estimator, use it to compute new fee...
			if feerate_estimate as u64 > self.feerate_previous {
				feerate_estimate
			} else {
				// ...else just increase the previous feerate by 25% (because that's a nice number)
				(self.feerate_previous + (self.feerate_previous / 4)).try_into().unwrap_or(u32::max_value())
			}
		} else {
			feerate_estimate
		}
	}

	/// Determines whether a package contains an input which must have additional external inputs
	/// attached to help the spending transaction reach confirmation.
	pub(crate) fn requires_external_funding(&self) -> bool {
		self.inputs.iter().find(|input| match input.1 {
			PackageSolvingData::HolderFundingOutput(ref outp) => outp.opt_anchors(),
			PackageSolvingData::HolderHTLCOutput(ref outp) => outp.opt_anchors(),
			_ => false,
		}).is_some()
	}

	pub (crate) fn build_package(txid: Txid, vout: u32, input_solving_data: PackageSolvingData, soonest_conf_deadline: u32, aggregable: bool, height_original: u32) -> Self {
		let malleability = match input_solving_data {
			PackageSolvingData::RevokedOutput(..) => PackageMalleability::Malleable,
			PackageSolvingData::RevokedHTLCOutput(..) => PackageMalleability::Malleable,
			PackageSolvingData::CounterpartyOfferedHTLCOutput(..) => PackageMalleability::Malleable,
			PackageSolvingData::CounterpartyReceivedHTLCOutput(..) => PackageMalleability::Malleable,
			PackageSolvingData::HolderHTLCOutput(ref outp) => if outp.opt_anchors() {
				PackageMalleability::Malleable
			} else {
				PackageMalleability::Untractable
			},
			PackageSolvingData::HolderFundingOutput(..) => PackageMalleability::Untractable,
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
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		writer.write_all(&(self.inputs.len() as u64).to_be_bytes())?;
		for (ref outpoint, ref rev_outp) in self.inputs.iter() {
			outpoint.write(writer)?;
			rev_outp.write(writer)?;
		}
		write_tlv_fields!(writer, {
			(0, self.soonest_conf_deadline, required),
			(2, self.feerate_previous, required),
			(4, self.height_original, required),
			(6, self.height_timer, option)
		});
		Ok(())
	}
}

impl Readable for PackageTemplate {
	fn read<R: io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
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
				PackageSolvingData::HolderHTLCOutput(ref outp) => if outp.opt_anchors() {
					(PackageMalleability::Malleable, outp.preimage.is_some())
				} else {
					(PackageMalleability::Untractable, false)
				},
				PackageSolvingData::HolderFundingOutput(..) => { (PackageMalleability::Untractable, false) },
			}
		} else { return Err(DecodeError::InvalidValue); };
		let mut soonest_conf_deadline = 0;
		let mut feerate_previous = 0;
		let mut height_timer = None;
		let mut height_original = 0;
		read_tlv_fields!(reader, {
			(0, soonest_conf_deadline, required),
			(2, feerate_previous, required),
			(4, height_original, required),
			(6, height_timer, option),
		});
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
fn compute_fee_from_spent_amounts<F: Deref, L: Deref>(input_amounts: u64, predicted_weight: usize, fee_estimator: &LowerBoundedFeeEstimator<F>, logger: &L) -> Option<(u64, u64)>
	where F::Target: FeeEstimator,
	      L::Target: Logger,
{
	let mut updated_feerate = fee_estimator.bounded_sat_per_1000_weight(ConfirmationTarget::HighPriority) as u64;
	let mut fee = updated_feerate * (predicted_weight as u64) / 1000;
	if input_amounts <= fee {
		updated_feerate = fee_estimator.bounded_sat_per_1000_weight(ConfirmationTarget::Normal) as u64;
		fee = updated_feerate * (predicted_weight as u64) / 1000;
		if input_amounts <= fee {
			updated_feerate = fee_estimator.bounded_sat_per_1000_weight(ConfirmationTarget::Background) as u64;
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
fn feerate_bump<F: Deref, L: Deref>(predicted_weight: usize, input_amounts: u64, previous_feerate: u64, fee_estimator: &LowerBoundedFeeEstimator<F>, logger: &L) -> Option<(u64, u64)>
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
				log_warn!(logger, "Can't 25% bump new claiming tx, amount {} is too small", input_amounts);
				return None;
			}
			new_fee
		}
	} else {
		log_warn!(logger, "Can't new-estimation bump new claiming tx, amount {} is too small", input_amounts);
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

#[cfg(test)]
mod tests {
	use crate::chain::package::{CounterpartyOfferedHTLCOutput, CounterpartyReceivedHTLCOutput, HolderHTLCOutput, PackageTemplate, PackageSolvingData, RevokedOutput, WEIGHT_REVOKED_OUTPUT, weight_offered_htlc, weight_received_htlc};
	use crate::chain::Txid;
	use crate::ln::chan_utils::HTLCOutputInCommitment;
	use crate::ln::{PaymentPreimage, PaymentHash};

	use bitcoin::blockdata::constants::WITNESS_SCALE_FACTOR;
	use bitcoin::blockdata::script::Script;
	use bitcoin::blockdata::transaction::OutPoint as BitcoinOutPoint;

	use bitcoin::hashes::hex::FromHex;

	use bitcoin::secp256k1::{PublicKey,SecretKey};
	use bitcoin::secp256k1::Secp256k1;

	macro_rules! dumb_revk_output {
		($secp_ctx: expr) => {
			{
				let dumb_scalar = SecretKey::from_slice(&hex::decode("0101010101010101010101010101010101010101010101010101010101010101").unwrap()[..]).unwrap();
				let dumb_point = PublicKey::from_secret_key(&$secp_ctx, &dumb_scalar);
				PackageSolvingData::RevokedOutput(RevokedOutput::build(dumb_point, dumb_point, dumb_point, dumb_scalar, 0, 0))
			}
		}
	}

	macro_rules! dumb_counterparty_output {
		($secp_ctx: expr, $amt: expr, $opt_anchors: expr) => {
			{
				let dumb_scalar = SecretKey::from_slice(&hex::decode("0101010101010101010101010101010101010101010101010101010101010101").unwrap()[..]).unwrap();
				let dumb_point = PublicKey::from_secret_key(&$secp_ctx, &dumb_scalar);
				let hash = PaymentHash([1; 32]);
				let htlc = HTLCOutputInCommitment { offered: true, amount_msat: $amt, cltv_expiry: 0, payment_hash: hash, transaction_output_index: None };
				PackageSolvingData::CounterpartyReceivedHTLCOutput(CounterpartyReceivedHTLCOutput::build(dumb_point, dumb_point, dumb_point, htlc, $opt_anchors))
			}
		}
	}

	macro_rules! dumb_counterparty_offered_output {
		($secp_ctx: expr, $amt: expr, $opt_anchors: expr) => {
			{
				let dumb_scalar = SecretKey::from_slice(&hex::decode("0101010101010101010101010101010101010101010101010101010101010101").unwrap()[..]).unwrap();
				let dumb_point = PublicKey::from_secret_key(&$secp_ctx, &dumb_scalar);
				let hash = PaymentHash([1; 32]);
				let preimage = PaymentPreimage([2;32]);
				let htlc = HTLCOutputInCommitment { offered: false, amount_msat: $amt, cltv_expiry: 1000, payment_hash: hash, transaction_output_index: None };
				PackageSolvingData::CounterpartyOfferedHTLCOutput(CounterpartyOfferedHTLCOutput::build(dumb_point, dumb_point, dumb_point, preimage, htlc, $opt_anchors))
			}
		}
	}

	macro_rules! dumb_htlc_output {
		() => {
			{
				let preimage = PaymentPreimage([2;32]);
				PackageSolvingData::HolderHTLCOutput(HolderHTLCOutput::build_accepted(preimage, 0, false))
			}
		}
	}

	#[test]
	#[should_panic]
	fn test_package_differing_heights() {
		let txid = Txid::from_hex("c2d4449afa8d26140898dd54d3390b057ba2a5afcf03ba29d7dc0d8b9ffe966e").unwrap();
		let secp_ctx = Secp256k1::new();
		let revk_outp = dumb_revk_output!(secp_ctx);

		let mut package_one_hundred = PackageTemplate::build_package(txid, 0, revk_outp.clone(), 1000, true, 100);
		let package_two_hundred = PackageTemplate::build_package(txid, 1, revk_outp.clone(), 1000, true, 200);
		package_one_hundred.merge_package(package_two_hundred);
	}

	#[test]
	#[should_panic]
	fn test_package_untractable_merge_to() {
		let txid = Txid::from_hex("c2d4449afa8d26140898dd54d3390b057ba2a5afcf03ba29d7dc0d8b9ffe966e").unwrap();
		let secp_ctx = Secp256k1::new();
		let revk_outp = dumb_revk_output!(secp_ctx);
		let htlc_outp = dumb_htlc_output!();

		let mut untractable_package = PackageTemplate::build_package(txid, 0, revk_outp.clone(), 1000, true, 100);
		let malleable_package = PackageTemplate::build_package(txid, 1, htlc_outp.clone(), 1000, true, 100);
		untractable_package.merge_package(malleable_package);
	}

	#[test]
	#[should_panic]
	fn test_package_untractable_merge_from() {
		let txid = Txid::from_hex("c2d4449afa8d26140898dd54d3390b057ba2a5afcf03ba29d7dc0d8b9ffe966e").unwrap();
		let secp_ctx = Secp256k1::new();
		let htlc_outp = dumb_htlc_output!();
		let revk_outp = dumb_revk_output!(secp_ctx);

		let mut malleable_package = PackageTemplate::build_package(txid, 0, htlc_outp.clone(), 1000, true, 100);
		let untractable_package = PackageTemplate::build_package(txid, 1, revk_outp.clone(), 1000, true, 100);
		malleable_package.merge_package(untractable_package);
	}

	#[test]
	#[should_panic]
	fn test_package_noaggregation_to() {
		let txid = Txid::from_hex("c2d4449afa8d26140898dd54d3390b057ba2a5afcf03ba29d7dc0d8b9ffe966e").unwrap();
		let secp_ctx = Secp256k1::new();
		let revk_outp = dumb_revk_output!(secp_ctx);

		let mut noaggregation_package = PackageTemplate::build_package(txid, 0, revk_outp.clone(), 1000, false, 100);
		let aggregation_package = PackageTemplate::build_package(txid, 1, revk_outp.clone(), 1000, true, 100);
		noaggregation_package.merge_package(aggregation_package);
	}

	#[test]
	#[should_panic]
	fn test_package_noaggregation_from() {
		let txid = Txid::from_hex("c2d4449afa8d26140898dd54d3390b057ba2a5afcf03ba29d7dc0d8b9ffe966e").unwrap();
		let secp_ctx = Secp256k1::new();
		let revk_outp = dumb_revk_output!(secp_ctx);

		let mut aggregation_package = PackageTemplate::build_package(txid, 0, revk_outp.clone(), 1000, true, 100);
		let noaggregation_package = PackageTemplate::build_package(txid, 1, revk_outp.clone(), 1000, false, 100);
		aggregation_package.merge_package(noaggregation_package);
	}

	#[test]
	#[should_panic]
	fn test_package_empty() {
		let txid = Txid::from_hex("c2d4449afa8d26140898dd54d3390b057ba2a5afcf03ba29d7dc0d8b9ffe966e").unwrap();
		let secp_ctx = Secp256k1::new();
		let revk_outp = dumb_revk_output!(secp_ctx);

		let mut empty_package = PackageTemplate::build_package(txid, 0, revk_outp.clone(), 1000, true, 100);
		empty_package.inputs = vec![];
		let package = PackageTemplate::build_package(txid, 1, revk_outp.clone(), 1000, true, 100);
		empty_package.merge_package(package);
	}

	#[test]
	#[should_panic]
	fn test_package_differing_categories() {
		let txid = Txid::from_hex("c2d4449afa8d26140898dd54d3390b057ba2a5afcf03ba29d7dc0d8b9ffe966e").unwrap();
		let secp_ctx = Secp256k1::new();
		let revk_outp = dumb_revk_output!(secp_ctx);
		let counterparty_outp = dumb_counterparty_output!(secp_ctx, 0, false);

		let mut revoked_package = PackageTemplate::build_package(txid, 0, revk_outp, 1000, true, 100);
		let counterparty_package = PackageTemplate::build_package(txid, 1, counterparty_outp, 1000, true, 100);
		revoked_package.merge_package(counterparty_package);
	}

	#[test]
	fn test_package_split_malleable() {
		let txid = Txid::from_hex("c2d4449afa8d26140898dd54d3390b057ba2a5afcf03ba29d7dc0d8b9ffe966e").unwrap();
		let secp_ctx = Secp256k1::new();
		let revk_outp_one = dumb_revk_output!(secp_ctx);
		let revk_outp_two = dumb_revk_output!(secp_ctx);
		let revk_outp_three = dumb_revk_output!(secp_ctx);

		let mut package_one = PackageTemplate::build_package(txid, 0, revk_outp_one, 1000, true, 100);
		let package_two = PackageTemplate::build_package(txid, 1, revk_outp_two, 1000, true, 100);
		let package_three = PackageTemplate::build_package(txid, 2, revk_outp_three, 1000, true, 100);

		package_one.merge_package(package_two);
		package_one.merge_package(package_three);
		assert_eq!(package_one.outpoints().len(), 3);

		if let Some(split_package) = package_one.split_package(&BitcoinOutPoint { txid, vout: 1 }) {
			// Packages attributes should be identical
			assert!(split_package.is_malleable());
			assert_eq!(split_package.soonest_conf_deadline, package_one.soonest_conf_deadline);
			assert_eq!(split_package.aggregable, package_one.aggregable);
			assert_eq!(split_package.feerate_previous, package_one.feerate_previous);
			assert_eq!(split_package.height_timer, package_one.height_timer);
			assert_eq!(split_package.height_original, package_one.height_original);
		} else { panic!(); }
		assert_eq!(package_one.outpoints().len(), 2);
	}

	#[test]
	fn test_package_split_untractable() {
		let txid = Txid::from_hex("c2d4449afa8d26140898dd54d3390b057ba2a5afcf03ba29d7dc0d8b9ffe966e").unwrap();
		let htlc_outp_one = dumb_htlc_output!();

		let mut package_one = PackageTemplate::build_package(txid, 0, htlc_outp_one, 1000, true, 100);
		let ret_split = package_one.split_package(&BitcoinOutPoint { txid, vout: 0});
		assert!(ret_split.is_none());
	}

	#[test]
	fn test_package_timer() {
		let txid = Txid::from_hex("c2d4449afa8d26140898dd54d3390b057ba2a5afcf03ba29d7dc0d8b9ffe966e").unwrap();
		let secp_ctx = Secp256k1::new();
		let revk_outp = dumb_revk_output!(secp_ctx);

		let mut package = PackageTemplate::build_package(txid, 0, revk_outp, 1000, true, 100);
		let timer_none = package.timer();
		assert!(timer_none.is_none());
		package.set_timer(Some(100));
		if let Some(timer_some) = package.timer() {
			assert_eq!(timer_some, 100);
		} else { panic!() }
	}

	#[test]
	fn test_package_amounts() {
		let txid = Txid::from_hex("c2d4449afa8d26140898dd54d3390b057ba2a5afcf03ba29d7dc0d8b9ffe966e").unwrap();
		let secp_ctx = Secp256k1::new();
		let counterparty_outp = dumb_counterparty_output!(secp_ctx, 1_000_000, false);

		let package = PackageTemplate::build_package(txid, 0, counterparty_outp, 1000, true, 100);
		assert_eq!(package.package_amount(), 1000);
	}

	#[test]
	fn test_package_weight() {
		let txid = Txid::from_hex("c2d4449afa8d26140898dd54d3390b057ba2a5afcf03ba29d7dc0d8b9ffe966e").unwrap();
		let secp_ctx = Secp256k1::new();

		// (nVersion (4) + nLocktime (4) + count_tx_in (1) + prevout (36) + sequence (4) + script_length (1) + count_tx_out (1) + value (8) + var_int (1)) * WITNESS_SCALE_FACTOR + witness marker (2)
		let weight_sans_output = (4 + 4 + 1 + 36 + 4 + 1 + 1 + 8 + 1) * WITNESS_SCALE_FACTOR + 2;

		{
			let revk_outp = dumb_revk_output!(secp_ctx);
			let package = PackageTemplate::build_package(txid, 0, revk_outp, 0, true, 100);
			assert_eq!(package.package_weight(&Script::new()),  weight_sans_output + WEIGHT_REVOKED_OUTPUT as usize);
		}

		{
			for &opt_anchors in [false, true].iter() {
				let counterparty_outp = dumb_counterparty_output!(secp_ctx, 1_000_000, opt_anchors);
				let package = PackageTemplate::build_package(txid, 0, counterparty_outp, 1000, true, 100);
				assert_eq!(package.package_weight(&Script::new()), weight_sans_output + weight_received_htlc(opt_anchors) as usize);
			}
		}

		{
			for &opt_anchors in [false, true].iter() {
				let counterparty_outp = dumb_counterparty_offered_output!(secp_ctx, 1_000_000, opt_anchors);
				let package = PackageTemplate::build_package(txid, 0, counterparty_outp, 1000, true, 100);
				assert_eq!(package.package_weight(&Script::new()), weight_sans_output + weight_offered_htlc(opt_anchors) as usize);
			}
		}
	}
}
