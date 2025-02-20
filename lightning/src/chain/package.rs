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


use bitcoin::{Sequence, Witness};
use bitcoin::amount::Amount;
use bitcoin::constants::WITNESS_SCALE_FACTOR;
use bitcoin::locktime::absolute::LockTime;
use bitcoin::transaction::{TxOut,TxIn, Transaction};
use bitcoin::transaction::OutPoint as BitcoinOutPoint;
use bitcoin::script::{Script, ScriptBuf};
use bitcoin::hash_types::Txid;
use bitcoin::secp256k1::{SecretKey,PublicKey};
use bitcoin::sighash::EcdsaSighashType;
use bitcoin::transaction::Version;

use crate::types::payment::PaymentPreimage;
use crate::ln::chan_utils::{self, TxCreationKeys, HTLCOutputInCommitment};
use crate::types::features::ChannelTypeFeatures;
use crate::ln::channel_keys::{DelayedPaymentBasepoint, HtlcBasepoint};
use crate::ln::channelmanager::MIN_CLTV_EXPIRY_DELTA;
use crate::ln::msgs::DecodeError;
use crate::chain::channelmonitor::COUNTERPARTY_CLAIMABLE_WITHIN_BLOCKS_PINNABLE;
use crate::chain::chaininterface::{FeeEstimator, ConfirmationTarget, INCREMENTAL_RELAY_FEE_SAT_PER_1000_WEIGHT, compute_feerate_sat_per_1000_weight, FEERATE_FLOOR_SATS_PER_KW};
use crate::chain::transaction::MaybeSignedTransaction;
use crate::sign::ecdsa::EcdsaChannelSigner;
use crate::chain::onchaintx::{FeerateStrategy, ExternalHTLCClaim, OnchainTxHandler};
use crate::util::logger::Logger;
use crate::util::ser::{Readable, Writer, Writeable, RequiredWrapper};

use crate::io;
use core::cmp;
use core::ops::Deref;

#[allow(unused_imports)]
use crate::prelude::*;

use super::chaininterface::LowerBoundedFeeEstimator;

const MAX_ALLOC_SIZE: usize = 64*1024;


pub(crate) fn weight_revoked_offered_htlc(channel_type_features: &ChannelTypeFeatures) -> u64 {
	// number_of_witness_elements + sig_length + revocation_sig + pubkey_length + revocationpubkey + witness_script_length + witness_script
	const WEIGHT_REVOKED_OFFERED_HTLC: u64 = 1 + 1 + 73 + 1 + 33 + 1 + 133;
	const WEIGHT_REVOKED_OFFERED_HTLC_ANCHORS: u64 = WEIGHT_REVOKED_OFFERED_HTLC + 3; // + OP_1 + OP_CSV + OP_DROP
	if channel_type_features.supports_anchors_zero_fee_htlc_tx() { WEIGHT_REVOKED_OFFERED_HTLC_ANCHORS } else { WEIGHT_REVOKED_OFFERED_HTLC }
}

pub(crate) fn weight_revoked_received_htlc(channel_type_features: &ChannelTypeFeatures) -> u64 {
	// number_of_witness_elements + sig_length + revocation_sig + pubkey_length + revocationpubkey + witness_script_length + witness_script
	const WEIGHT_REVOKED_RECEIVED_HTLC: u64 = 1 + 1 + 73 + 1 + 33 + 1 +  139;
	const WEIGHT_REVOKED_RECEIVED_HTLC_ANCHORS: u64 = WEIGHT_REVOKED_RECEIVED_HTLC + 3; // + OP_1 + OP_CSV + OP_DROP
	if channel_type_features.supports_anchors_zero_fee_htlc_tx() { WEIGHT_REVOKED_RECEIVED_HTLC_ANCHORS } else { WEIGHT_REVOKED_RECEIVED_HTLC }
}

pub(crate) fn weight_offered_htlc(channel_type_features: &ChannelTypeFeatures) -> u64 {
	// number_of_witness_elements + sig_length + counterpartyhtlc_sig  + preimage_length + preimage + witness_script_length + witness_script
	const WEIGHT_OFFERED_HTLC: u64 = 1 + 1 + 73 + 1 + 32 + 1 + 133;
	const WEIGHT_OFFERED_HTLC_ANCHORS: u64 = WEIGHT_OFFERED_HTLC + 3; // + OP_1 + OP_CSV + OP_DROP
	if channel_type_features.supports_anchors_zero_fee_htlc_tx() { WEIGHT_OFFERED_HTLC_ANCHORS } else { WEIGHT_OFFERED_HTLC }
}

pub(crate) fn weight_received_htlc(channel_type_features: &ChannelTypeFeatures) -> u64 {
	// number_of_witness_elements + sig_length + counterpartyhtlc_sig + empty_vec_length + empty_vec + witness_script_length + witness_script
	const WEIGHT_RECEIVED_HTLC: u64 = 1 + 1 + 73 + 1 + 1 + 1 + 139;
	const WEIGHT_RECEIVED_HTLC_ANCHORS: u64 = WEIGHT_RECEIVED_HTLC + 3; // + OP_1 + OP_CSV + OP_DROP
	if channel_type_features.supports_anchors_zero_fee_htlc_tx() { WEIGHT_RECEIVED_HTLC_ANCHORS } else { WEIGHT_RECEIVED_HTLC }
}

/// Verifies deserializable channel type features
pub(crate) fn verify_channel_type_features(channel_type_features: &Option<ChannelTypeFeatures>, additional_permitted_features: Option<&ChannelTypeFeatures>) -> Result<(), DecodeError> {
	if let Some(features) = channel_type_features.as_ref() {
		if features.requires_unknown_bits() {
			return Err(DecodeError::UnknownRequiredFeature);
		}

		let mut supported_feature_set = ChannelTypeFeatures::anchors_zero_htlc_fee_and_dependencies();
		supported_feature_set.set_scid_privacy_required();
		supported_feature_set.set_zero_conf_required();

		// allow the passing of an additional necessary permitted flag
		if let Some(additional_permitted_features) = additional_permitted_features {
			supported_feature_set |= additional_permitted_features;
		}

		if features.requires_unknown_bits_from(&supported_feature_set) {
			return Err(DecodeError::UnknownRequiredFeature);
		}
	}

	Ok(())
}

// number_of_witness_elements + sig_length + revocation_sig + true_length + op_true + witness_script_length + witness_script
pub(crate) const WEIGHT_REVOKED_OUTPUT: u64 = 1 + 1 + 73 + 1 + 1 + 1 + 77;

#[cfg(not(test))]
/// Height delay at which transactions are fee-bumped/rebroadcasted with a low priority.
const LOW_FREQUENCY_BUMP_INTERVAL: u32 = 15;
#[cfg(test)]
/// Height delay at which transactions are fee-bumped/rebroadcasted with a low priority.
pub(crate) const LOW_FREQUENCY_BUMP_INTERVAL: u32 = 15;

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
	counterparty_delayed_payment_base_key: DelayedPaymentBasepoint,
	counterparty_htlc_base_key: HtlcBasepoint,
	per_commitment_key: SecretKey,
	weight: u64,
	amount: Amount,
	on_counterparty_tx_csv: u16,
	is_counterparty_balance_on_anchors: Option<()>,
}

impl RevokedOutput {
	pub(crate) fn build(per_commitment_point: PublicKey, counterparty_delayed_payment_base_key: DelayedPaymentBasepoint, counterparty_htlc_base_key: HtlcBasepoint, per_commitment_key: SecretKey, amount: Amount, on_counterparty_tx_csv: u16, is_counterparty_balance_on_anchors: bool) -> Self {
		RevokedOutput {
			per_commitment_point,
			counterparty_delayed_payment_base_key,
			counterparty_htlc_base_key,
			per_commitment_key,
			weight: WEIGHT_REVOKED_OUTPUT,
			amount,
			on_counterparty_tx_csv,
			is_counterparty_balance_on_anchors: if is_counterparty_balance_on_anchors { Some(()) } else { None }
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
	(14, is_counterparty_balance_on_anchors, option)
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
	counterparty_delayed_payment_base_key: DelayedPaymentBasepoint,
	counterparty_htlc_base_key: HtlcBasepoint,
	per_commitment_key: SecretKey,
	weight: u64,
	amount: u64,
	htlc: HTLCOutputInCommitment,
}

impl RevokedHTLCOutput {
	pub(crate) fn build(per_commitment_point: PublicKey, counterparty_delayed_payment_base_key: DelayedPaymentBasepoint, counterparty_htlc_base_key: HtlcBasepoint, per_commitment_key: SecretKey, amount: u64, htlc: HTLCOutputInCommitment, channel_type_features: &ChannelTypeFeatures) -> Self {
		let weight = if htlc.offered { weight_revoked_offered_htlc(channel_type_features) } else { weight_revoked_received_htlc(channel_type_features) };
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
///
/// Note that on upgrades, some features of existing outputs may be missed.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct CounterpartyOfferedHTLCOutput {
	per_commitment_point: PublicKey,
	counterparty_delayed_payment_base_key: DelayedPaymentBasepoint,
	counterparty_htlc_base_key: HtlcBasepoint,
	preimage: PaymentPreimage,
	htlc: HTLCOutputInCommitment,
	channel_type_features: ChannelTypeFeatures,
}

impl CounterpartyOfferedHTLCOutput {
	pub(crate) fn build(per_commitment_point: PublicKey, counterparty_delayed_payment_base_key: DelayedPaymentBasepoint, counterparty_htlc_base_key: HtlcBasepoint, preimage: PaymentPreimage, htlc: HTLCOutputInCommitment, channel_type_features: ChannelTypeFeatures) -> Self {
		CounterpartyOfferedHTLCOutput {
			per_commitment_point,
			counterparty_delayed_payment_base_key,
			counterparty_htlc_base_key,
			preimage,
			htlc,
			channel_type_features,
		}
	}
}

impl Writeable for CounterpartyOfferedHTLCOutput {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		let legacy_deserialization_prevention_marker = chan_utils::legacy_deserialization_prevention_marker_for_channel_type_features(&self.channel_type_features);
		write_tlv_fields!(writer, {
			(0, self.per_commitment_point, required),
			(2, self.counterparty_delayed_payment_base_key, required),
			(4, self.counterparty_htlc_base_key, required),
			(6, self.preimage, required),
			(8, self.htlc, required),
			(10, legacy_deserialization_prevention_marker, option),
			(11, self.channel_type_features, required),
		});
		Ok(())
	}
}

impl Readable for CounterpartyOfferedHTLCOutput {
	fn read<R: io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
		let mut per_commitment_point = RequiredWrapper(None);
		let mut counterparty_delayed_payment_base_key = RequiredWrapper(None);
		let mut counterparty_htlc_base_key = RequiredWrapper(None);
		let mut preimage = RequiredWrapper(None);
		let mut htlc = RequiredWrapper(None);
		let mut _legacy_deserialization_prevention_marker: Option<()> = None;
		let mut channel_type_features = None;

		read_tlv_fields!(reader, {
			(0, per_commitment_point, required),
			(2, counterparty_delayed_payment_base_key, required),
			(4, counterparty_htlc_base_key, required),
			(6, preimage, required),
			(8, htlc, required),
			(10, _legacy_deserialization_prevention_marker, option),
			(11, channel_type_features, option),
		});

		verify_channel_type_features(&channel_type_features, None)?;

		Ok(Self {
			per_commitment_point: per_commitment_point.0.unwrap(),
			counterparty_delayed_payment_base_key: counterparty_delayed_payment_base_key.0.unwrap(),
			counterparty_htlc_base_key: counterparty_htlc_base_key.0.unwrap(),
			preimage: preimage.0.unwrap(),
			htlc: htlc.0.unwrap(),
			channel_type_features: channel_type_features.unwrap_or(ChannelTypeFeatures::only_static_remote_key())
		})
	}
}

/// A struct to describe a HTLC output on a counterparty commitment transaction.
///
/// HTLCOutputInCommitment (hash, timelock, directon) and pubkeys are used to generate a suitable
/// witnessScript.
///
/// Note that on upgrades, some features of existing outputs may be missed.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct CounterpartyReceivedHTLCOutput {
	per_commitment_point: PublicKey,
	counterparty_delayed_payment_base_key: DelayedPaymentBasepoint,
	counterparty_htlc_base_key: HtlcBasepoint,
	htlc: HTLCOutputInCommitment,
	channel_type_features: ChannelTypeFeatures,
}

impl CounterpartyReceivedHTLCOutput {
	pub(crate) fn build(per_commitment_point: PublicKey, counterparty_delayed_payment_base_key: DelayedPaymentBasepoint, counterparty_htlc_base_key: HtlcBasepoint, htlc: HTLCOutputInCommitment, channel_type_features: ChannelTypeFeatures) -> Self {
		CounterpartyReceivedHTLCOutput {
			per_commitment_point,
			counterparty_delayed_payment_base_key,
			counterparty_htlc_base_key,
			htlc,
			channel_type_features
		}
	}
}

impl Writeable for CounterpartyReceivedHTLCOutput {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		let legacy_deserialization_prevention_marker = chan_utils::legacy_deserialization_prevention_marker_for_channel_type_features(&self.channel_type_features);
		write_tlv_fields!(writer, {
			(0, self.per_commitment_point, required),
			(2, self.counterparty_delayed_payment_base_key, required),
			(4, self.counterparty_htlc_base_key, required),
			(6, self.htlc, required),
			(8, legacy_deserialization_prevention_marker, option),
			(9, self.channel_type_features, required),
		});
		Ok(())
	}
}

impl Readable for CounterpartyReceivedHTLCOutput {
	fn read<R: io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
		let mut per_commitment_point = RequiredWrapper(None);
		let mut counterparty_delayed_payment_base_key = RequiredWrapper(None);
		let mut counterparty_htlc_base_key = RequiredWrapper(None);
		let mut htlc = RequiredWrapper(None);
		let mut _legacy_deserialization_prevention_marker: Option<()> = None;
		let mut channel_type_features = None;

		read_tlv_fields!(reader, {
			(0, per_commitment_point, required),
			(2, counterparty_delayed_payment_base_key, required),
			(4, counterparty_htlc_base_key, required),
			(6, htlc, required),
			(8, _legacy_deserialization_prevention_marker, option),
			(9, channel_type_features, option),
		});

		verify_channel_type_features(&channel_type_features, None)?;

		Ok(Self {
			per_commitment_point: per_commitment_point.0.unwrap(),
			counterparty_delayed_payment_base_key: counterparty_delayed_payment_base_key.0.unwrap(),
			counterparty_htlc_base_key: counterparty_htlc_base_key.0.unwrap(),
			htlc: htlc.0.unwrap(),
			channel_type_features: channel_type_features.unwrap_or(ChannelTypeFeatures::only_static_remote_key())
		})
	}
}

/// A struct to describe a HTLC output on holder commitment transaction.
///
/// Either offered or received, the amount is always used as part of the bip143 sighash.
/// Preimage is only included as part of the witness in former case.
///
/// Note that on upgrades, some features of existing outputs may be missed.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct HolderHTLCOutput {
	preimage: Option<PaymentPreimage>,
	amount_msat: u64,
	/// Defaults to 0 for HTLC-Success transactions, which have no expiry
	cltv_expiry: u32,
	channel_type_features: ChannelTypeFeatures,
}

impl HolderHTLCOutput {
	pub(crate) fn build_offered(amount_msat: u64, cltv_expiry: u32, channel_type_features: ChannelTypeFeatures) -> Self {
		HolderHTLCOutput {
			preimage: None,
			amount_msat,
			cltv_expiry,
			channel_type_features,
		}
	}

	pub(crate) fn build_accepted(preimage: PaymentPreimage, amount_msat: u64, channel_type_features: ChannelTypeFeatures) -> Self {
		HolderHTLCOutput {
			preimage: Some(preimage),
			amount_msat,
			cltv_expiry: 0,
			channel_type_features,
		}
	}
}

impl Writeable for HolderHTLCOutput {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		let legacy_deserialization_prevention_marker = chan_utils::legacy_deserialization_prevention_marker_for_channel_type_features(&self.channel_type_features);
		write_tlv_fields!(writer, {
			(0, self.amount_msat, required),
			(2, self.cltv_expiry, required),
			(4, self.preimage, option),
			(6, legacy_deserialization_prevention_marker, option),
			(7, self.channel_type_features, required),
		});
		Ok(())
	}
}

impl Readable for HolderHTLCOutput {
	fn read<R: io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
		let mut amount_msat = RequiredWrapper(None);
		let mut cltv_expiry = RequiredWrapper(None);
		let mut preimage = None;
		let mut _legacy_deserialization_prevention_marker: Option<()> = None;
		let mut channel_type_features = None;

		read_tlv_fields!(reader, {
			(0, amount_msat, required),
			(2, cltv_expiry, required),
			(4, preimage, option),
			(6, _legacy_deserialization_prevention_marker, option),
			(7, channel_type_features, option),
		});

		verify_channel_type_features(&channel_type_features, None)?;

		Ok(Self {
			amount_msat: amount_msat.0.unwrap(),
			cltv_expiry: cltv_expiry.0.unwrap(),
			preimage,
			channel_type_features: channel_type_features.unwrap_or(ChannelTypeFeatures::only_static_remote_key())
		})
	}
}

/// A struct to describe the channel output on the funding transaction.
///
/// witnessScript is used as part of the witness redeeming the funding utxo.
///
/// Note that on upgrades, some features of existing outputs may be missed.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct HolderFundingOutput {
	funding_redeemscript: ScriptBuf,
	pub(crate) funding_amount: Option<u64>,
	channel_type_features: ChannelTypeFeatures,
}


impl HolderFundingOutput {
	pub(crate) fn build(funding_redeemscript: ScriptBuf, funding_amount: u64, channel_type_features: ChannelTypeFeatures) -> Self {
		HolderFundingOutput {
			funding_redeemscript,
			funding_amount: Some(funding_amount),
			channel_type_features,
		}
	}
}

impl Writeable for HolderFundingOutput {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		let legacy_deserialization_prevention_marker = chan_utils::legacy_deserialization_prevention_marker_for_channel_type_features(&self.channel_type_features);
		write_tlv_fields!(writer, {
			(0, self.funding_redeemscript, required),
			(1, self.channel_type_features, required),
			(2, legacy_deserialization_prevention_marker, option),
			(3, self.funding_amount, option),
		});
		Ok(())
	}
}

impl Readable for HolderFundingOutput {
	fn read<R: io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
		let mut funding_redeemscript = RequiredWrapper(None);
		let mut _legacy_deserialization_prevention_marker: Option<()> = None;
		let mut channel_type_features = None;
		let mut funding_amount = None;

		read_tlv_fields!(reader, {
			(0, funding_redeemscript, required),
			(1, channel_type_features, option),
			(2, _legacy_deserialization_prevention_marker, option),
			(3, funding_amount, option),
		});

		verify_channel_type_features(&channel_type_features, None)?;

		Ok(Self {
			funding_redeemscript: funding_redeemscript.0.unwrap(),
			channel_type_features: channel_type_features.unwrap_or(ChannelTypeFeatures::only_static_remote_key()),
			funding_amount
		})
	}
}

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
			PackageSolvingData::RevokedOutput(ref outp) => outp.amount.to_sat(),
			PackageSolvingData::RevokedHTLCOutput(ref outp) => outp.amount,
			PackageSolvingData::CounterpartyOfferedHTLCOutput(ref outp) => outp.htlc.amount_msat / 1000,
			PackageSolvingData::CounterpartyReceivedHTLCOutput(ref outp) => outp.htlc.amount_msat / 1000,
			PackageSolvingData::HolderHTLCOutput(ref outp) => {
				debug_assert!(outp.channel_type_features.supports_anchors_zero_fee_htlc_tx());
				outp.amount_msat / 1000
			},
			PackageSolvingData::HolderFundingOutput(ref outp) => {
				debug_assert!(outp.channel_type_features.supports_anchors_zero_fee_htlc_tx());
				outp.funding_amount.unwrap()
			}
		};
		amt
	}
	fn weight(&self) -> usize {
		match self {
			PackageSolvingData::RevokedOutput(ref outp) => outp.weight as usize,
			PackageSolvingData::RevokedHTLCOutput(ref outp) => outp.weight as usize,
			PackageSolvingData::CounterpartyOfferedHTLCOutput(ref outp) => weight_offered_htlc(&outp.channel_type_features) as usize,
			PackageSolvingData::CounterpartyReceivedHTLCOutput(ref outp) => weight_received_htlc(&outp.channel_type_features) as usize,
			PackageSolvingData::HolderHTLCOutput(ref outp) => {
				debug_assert!(outp.channel_type_features.supports_anchors_zero_fee_htlc_tx());
				if outp.preimage.is_none() {
					weight_offered_htlc(&outp.channel_type_features) as usize
				} else {
					weight_received_htlc(&outp.channel_type_features) as usize
				}
			},
			// Since HolderFundingOutput maps to an untractable package that is already signed, its
			// weight can be determined from the transaction itself.
			PackageSolvingData::HolderFundingOutput(..) => unreachable!(),
		}
	}

	/// Checks if this and `other` are spending types of inputs which could have descended from the
	/// same commitment transaction(s) and thus could both be spent without requiring a
	/// double-spend.
	fn is_possibly_from_same_tx_tree(&self, other: &PackageSolvingData) -> bool {
		match self {
			PackageSolvingData::RevokedOutput(_)|PackageSolvingData::RevokedHTLCOutput(_) => {
				match other {
					PackageSolvingData::RevokedOutput(_)|
					PackageSolvingData::RevokedHTLCOutput(_) => true,
					_ => false,
				}
			},
			PackageSolvingData::CounterpartyOfferedHTLCOutput(_)|
			PackageSolvingData::CounterpartyReceivedHTLCOutput(_) => {
				match other {
					PackageSolvingData::CounterpartyOfferedHTLCOutput(_)|
					PackageSolvingData::CounterpartyReceivedHTLCOutput(_) => true,
					_ => false,
				}
			},
			PackageSolvingData::HolderHTLCOutput(_)|
			PackageSolvingData::HolderFundingOutput(_) => {
				match other {
					PackageSolvingData::HolderHTLCOutput(_)|
					PackageSolvingData::HolderFundingOutput(_) => true,
					_ => false,
				}
			},
		}
	}

	fn as_tx_input(&self, previous_output: BitcoinOutPoint) -> TxIn {
		let sequence = match self {
			PackageSolvingData::RevokedOutput(_) => Sequence::ENABLE_RBF_NO_LOCKTIME,
			PackageSolvingData::RevokedHTLCOutput(_) => Sequence::ENABLE_RBF_NO_LOCKTIME,
			PackageSolvingData::CounterpartyOfferedHTLCOutput(outp) => if outp.channel_type_features.supports_anchors_zero_fee_htlc_tx() {
				Sequence::from_consensus(1)
			} else {
				Sequence::ENABLE_RBF_NO_LOCKTIME
			},
			PackageSolvingData::CounterpartyReceivedHTLCOutput(outp) => if outp.channel_type_features.supports_anchors_zero_fee_htlc_tx() {
				Sequence::from_consensus(1)
			} else {
				Sequence::ENABLE_RBF_NO_LOCKTIME
			},
			_ => {
				debug_assert!(false, "This should not be reachable by 'untractable' or 'malleable with external funding' packages");
				Sequence::ENABLE_RBF_NO_LOCKTIME
			},
		};
		TxIn {
			previous_output,
			script_sig: ScriptBuf::new(),
			sequence,
			witness: Witness::new(),
		}
	}
	fn finalize_input<Signer: EcdsaChannelSigner>(&self, bumped_tx: &mut Transaction, i: usize, onchain_handler: &mut OnchainTxHandler<Signer>) -> bool {
		let channel_parameters = &onchain_handler.channel_transaction_parameters;
		match self {
			PackageSolvingData::RevokedOutput(ref outp) => {
				let chan_keys = TxCreationKeys::derive_new(&onchain_handler.secp_ctx, &outp.per_commitment_point, &outp.counterparty_delayed_payment_base_key, &outp.counterparty_htlc_base_key, &onchain_handler.signer.pubkeys().revocation_basepoint, &onchain_handler.signer.pubkeys().htlc_basepoint);
				let witness_script = chan_utils::get_revokeable_redeemscript(&chan_keys.revocation_key, outp.on_counterparty_tx_csv, &chan_keys.broadcaster_delayed_payment_key);
				//TODO: should we panic on signer failure ?
				if let Ok(sig) = onchain_handler.signer.sign_justice_revoked_output(channel_parameters, &bumped_tx, i, outp.amount.to_sat(), &outp.per_commitment_key, &onchain_handler.secp_ctx) {
					let mut ser_sig = sig.serialize_der().to_vec();
					ser_sig.push(EcdsaSighashType::All as u8);
					bumped_tx.input[i].witness.push(ser_sig);
					bumped_tx.input[i].witness.push(vec!(1));
					bumped_tx.input[i].witness.push(witness_script.clone().into_bytes());
				} else { return false; }
			},
			PackageSolvingData::RevokedHTLCOutput(ref outp) => {
				let chan_keys = TxCreationKeys::derive_new(&onchain_handler.secp_ctx, &outp.per_commitment_point, &outp.counterparty_delayed_payment_base_key, &outp.counterparty_htlc_base_key, &onchain_handler.signer.pubkeys().revocation_basepoint, &onchain_handler.signer.pubkeys().htlc_basepoint);
				let witness_script = chan_utils::get_htlc_redeemscript_with_explicit_keys(&outp.htlc, &onchain_handler.channel_type_features(), &chan_keys.broadcaster_htlc_key, &chan_keys.countersignatory_htlc_key, &chan_keys.revocation_key);
				//TODO: should we panic on signer failure ?
				if let Ok(sig) = onchain_handler.signer.sign_justice_revoked_htlc(&bumped_tx, i, outp.amount, &outp.per_commitment_key, &outp.htlc, &onchain_handler.secp_ctx) {
					let mut ser_sig = sig.serialize_der().to_vec();
					ser_sig.push(EcdsaSighashType::All as u8);
					bumped_tx.input[i].witness.push(ser_sig);
					bumped_tx.input[i].witness.push(chan_keys.revocation_key.to_public_key().serialize().to_vec());
					bumped_tx.input[i].witness.push(witness_script.clone().into_bytes());
				} else { return false; }
			},
			PackageSolvingData::CounterpartyOfferedHTLCOutput(ref outp) => {
				let chan_keys = TxCreationKeys::derive_new(&onchain_handler.secp_ctx, &outp.per_commitment_point, &outp.counterparty_delayed_payment_base_key, &outp.counterparty_htlc_base_key, &onchain_handler.signer.pubkeys().revocation_basepoint, &onchain_handler.signer.pubkeys().htlc_basepoint);
				let witness_script = chan_utils::get_htlc_redeemscript_with_explicit_keys(&outp.htlc, &onchain_handler.channel_type_features(), &chan_keys.broadcaster_htlc_key, &chan_keys.countersignatory_htlc_key, &chan_keys.revocation_key);

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
				let witness_script = chan_utils::get_htlc_redeemscript_with_explicit_keys(&outp.htlc, &onchain_handler.channel_type_features(), &chan_keys.broadcaster_htlc_key, &chan_keys.countersignatory_htlc_key, &chan_keys.revocation_key);

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
	fn get_maybe_finalized_tx<Signer: EcdsaChannelSigner>(&self, outpoint: &BitcoinOutPoint, onchain_handler: &mut OnchainTxHandler<Signer>) -> Option<MaybeSignedTransaction> {
		match self {
			PackageSolvingData::HolderHTLCOutput(ref outp) => {
				debug_assert!(!outp.channel_type_features.supports_anchors_zero_fee_htlc_tx());
				onchain_handler.get_maybe_signed_htlc_tx(outpoint, &outp.preimage)
			}
			PackageSolvingData::HolderFundingOutput(ref outp) => {
				Some(onchain_handler.get_maybe_signed_holder_tx(&outp.funding_redeemscript))
			}
			_ => { panic!("API Error!"); }
		}
	}
	/// Some output types are locked with CHECKLOCKTIMEVERIFY and the spending transaction must
	/// have a minimum locktime, which is returned here.
	fn minimum_locktime(&self) -> Option<u32> {
		match self {
			PackageSolvingData::CounterpartyReceivedHTLCOutput(ref outp) => Some(outp.htlc.cltv_expiry),
			_ => None,
		}
	}
	/// Some output types are pre-signed in such a way that the spending transaction must have an
	/// exact locktime. This returns that locktime for such outputs.
	fn signed_locktime(&self) -> Option<u32> {
		match self {
			PackageSolvingData::HolderHTLCOutput(ref outp) => {
				if outp.preimage.is_some() {
					debug_assert_eq!(outp.cltv_expiry, 0);
				}
				Some(outp.cltv_expiry)
			},
			_ => None,
		}
	}

	fn map_output_type_flags(&self) -> PackageMalleability {
		// We classify claims into not-mergeable (i.e. transactions that have to be broadcasted
		// as-is) or merge-able (i.e. transactions we can merge with others and claim in batches),
		// which we then sub-categorize into pinnable (where our counterparty could potentially
		// also claim the transaction right now) or unpinnable (where only we can claim this
		// output). We assume we are claiming in a timely manner.
		match self {
			PackageSolvingData::RevokedOutput(RevokedOutput { .. }) =>
				PackageMalleability::Malleable(AggregationCluster::Unpinnable),
			PackageSolvingData::RevokedHTLCOutput(RevokedHTLCOutput { htlc, .. }) => {
				if htlc.offered {
					PackageMalleability::Malleable(AggregationCluster::Unpinnable)
				} else {
					PackageMalleability::Malleable(AggregationCluster::Pinnable)
				}
			},
			PackageSolvingData::CounterpartyOfferedHTLCOutput(..) =>
				PackageMalleability::Malleable(AggregationCluster::Unpinnable),
			PackageSolvingData::CounterpartyReceivedHTLCOutput(..) =>
				PackageMalleability::Malleable(AggregationCluster::Pinnable),
			PackageSolvingData::HolderHTLCOutput(ref outp) if outp.channel_type_features.supports_anchors_zero_fee_htlc_tx() => {
				if outp.preimage.is_some() {
					PackageMalleability::Malleable(AggregationCluster::Unpinnable)
				} else {
					PackageMalleability::Malleable(AggregationCluster::Pinnable)
				}
			},
			PackageSolvingData::HolderHTLCOutput(..) => PackageMalleability::Untractable,
			PackageSolvingData::HolderFundingOutput(..) => PackageMalleability::Untractable,
		}
	}
}

impl_writeable_tlv_based_enum_legacy!(PackageSolvingData, ;
	(0, RevokedOutput),
	(1, RevokedHTLCOutput),
	(2, CounterpartyOfferedHTLCOutput),
	(3, CounterpartyReceivedHTLCOutput),
	(4, HolderHTLCOutput),
	(5, HolderFundingOutput),
);

/// We aggregate claims into clusters based on if we think the output is potentially pinnable by
/// our counterparty and whether the CLTVs required make sense to aggregate into one claim.
/// That way we avoid claiming in too many discrete transactions while also avoiding
/// unnecessarily exposing ourselves to pinning attacks or delaying claims when we could have
/// claimed at least part of the available outputs quickly and without risk.
#[derive(Copy, Clone, PartialEq, Eq)]
enum AggregationCluster {
	/// Our counterparty can potentially claim this output.
	Pinnable,
	/// We are the only party that can claim these funds, thus we believe they are not pinnable
	/// until they reach a CLTV/CSV expiry where our counterparty could also claim them.
	Unpinnable,
}

/// A malleable package might be aggregated with other packages to save on fees.
/// A untractable package has been counter-signed and aggregable will break cached counterparty signatures.
#[derive(Copy, Clone, PartialEq, Eq)]
enum PackageMalleability {
	Malleable(AggregationCluster),
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
	/// Block height at which our counterparty can potentially claim this output as well (assuming
	/// they have the keys or information required to do so).
	///
	/// This is used primarily to decide when an output becomes "pinnable" because the counterparty
	/// can potentially spend it. It is also used internally by [`Self::get_height_timer`] to
	/// identify when an output must be claimed by, depending on the type of output.
	///
	/// Note that for revoked counterparty HTLC outputs the value may be zero in some cases where
	/// we upgraded from LDK 0.1 or prior.
	counterparty_spendable_height: u32,
	// Cache of package feerate committed at previous (re)broadcast. If bumping resources
	// (either claimed output value or external utxo), it will keep increasing until holder
	// or counterparty successful claim.
	feerate_previous: u64,
	// Cache of next height at which fee-bumping and rebroadcast will be attempted. In
	// the future, we might abstract it to an observed mempool fluctuation.
	height_timer: u32,
}

impl PackageTemplate {
	pub(crate) fn can_merge_with(&self, other: &PackageTemplate, cur_height: u32) -> bool {
		match (self.malleability, other.malleability) {
			(PackageMalleability::Untractable, _) => false,
			(_, PackageMalleability::Untractable) => false,
			(PackageMalleability::Malleable(self_cluster), PackageMalleability::Malleable(other_cluster)) => {
				if self.inputs.is_empty() {
					return false;
				}
				if other.inputs.is_empty() {
					return false;
				}

				// First check the types of the inputs and don't merge if they are possibly claiming
				// from different commitment transactions at the same time.
				// This shouldn't ever happen, but if we do end up with packages trying to claim
				// funds from two different commitment transactions (which cannot possibly be
				// on-chain at the same time), we definitely shouldn't merge them.
				#[cfg(debug_assertions)]
				{
					for i in 0..self.inputs.len() {
						for j in 0..i {
							debug_assert!(self.inputs[i].1.is_possibly_from_same_tx_tree(&self.inputs[j].1));
						}
					}
					for i in 0..other.inputs.len() {
						for j in 0..i {
							assert!(other.inputs[i].1.is_possibly_from_same_tx_tree(&other.inputs[j].1));
						}
					}
				}
				if !self.inputs[0].1.is_possibly_from_same_tx_tree(&other.inputs[0].1) {
					debug_assert!(false, "We shouldn't have packages from different tx trees");
					return false;
				}

				// Check if the packages have signed locktimes. If they do, we only want to aggregate
				// packages with the same, signed locktime.
				if self.signed_locktime() != other.signed_locktime() {
					return false;
				}
				// Check if the two packages have compatible minimum locktimes.
				if self.package_locktime(cur_height) != other.package_locktime(cur_height) {
					return false;
				}

				// Now check that we only merge packages if they are both unpinnable or both
				// pinnable.
				let self_pinnable = self_cluster == AggregationCluster::Pinnable ||
					self.counterparty_spendable_height <= cur_height + COUNTERPARTY_CLAIMABLE_WITHIN_BLOCKS_PINNABLE;
				let other_pinnable = other_cluster == AggregationCluster::Pinnable ||
					other.counterparty_spendable_height <= cur_height + COUNTERPARTY_CLAIMABLE_WITHIN_BLOCKS_PINNABLE;
				if self_pinnable && other_pinnable {
					return true;
				}

				let self_unpinnable = self_cluster == AggregationCluster::Unpinnable &&
					self.counterparty_spendable_height > cur_height + COUNTERPARTY_CLAIMABLE_WITHIN_BLOCKS_PINNABLE;
				let other_unpinnable = other_cluster == AggregationCluster::Unpinnable &&
					other.counterparty_spendable_height > cur_height + COUNTERPARTY_CLAIMABLE_WITHIN_BLOCKS_PINNABLE;
				if self_unpinnable && other_unpinnable {
					return true;
				}
				false
			},
		}
	}
	pub(crate) fn is_malleable(&self) -> bool {
		matches!(self.malleability, PackageMalleability::Malleable(..))
	}
	pub(crate) fn previous_feerate(&self) -> u64 {
		self.feerate_previous
	}
	pub(crate) fn set_feerate(&mut self, new_feerate: u64) {
		self.feerate_previous = new_feerate;
	}
	pub(crate) fn timer(&self) -> u32 {
		self.height_timer
	}
	pub(crate) fn set_timer(&mut self, new_timer: u32) {
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
			PackageMalleability::Malleable(cluster) => {
				let mut split_package = None;
				let feerate_previous = self.feerate_previous;
				let height_timer = self.height_timer;
				self.inputs.retain(|outp| {
					if *split_outp == outp.0 {
						split_package = Some(PackageTemplate {
							inputs: vec![(outp.0, outp.1.clone())],
							malleability: PackageMalleability::Malleable(cluster),
							counterparty_spendable_height: self.counterparty_spendable_height,
							feerate_previous,
							height_timer,
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
	pub(crate) fn merge_package(&mut self, mut merge_from: PackageTemplate, cur_height: u32) -> Result<(), PackageTemplate> {
		if !self.can_merge_with(&merge_from, cur_height) {
			return Err(merge_from);
		}
		for (k, v) in merge_from.inputs.drain(..) {
			self.inputs.push((k, v));
		}
		//TODO: verify coverage and sanity?
		if self.counterparty_spendable_height > merge_from.counterparty_spendable_height {
			self.counterparty_spendable_height = merge_from.counterparty_spendable_height;
		}
		if self.feerate_previous > merge_from.feerate_previous {
			self.feerate_previous = merge_from.feerate_previous;
		}
		self.height_timer = cmp::min(self.height_timer, merge_from.height_timer);
		Ok(())
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
	fn signed_locktime(&self) -> Option<u32> {
		let signed_locktime = self.inputs.iter().find_map(|(_, outp)| outp.signed_locktime());
		#[cfg(debug_assertions)]
		for (_, outp) in &self.inputs {
			debug_assert!(outp.signed_locktime().is_none() || outp.signed_locktime() == signed_locktime);
		}
		signed_locktime
	}
	pub(crate) fn package_locktime(&self, current_height: u32) -> u32 {
		let minimum_locktime = self.inputs.iter().filter_map(|(_, outp)| outp.minimum_locktime()).max();

		if let Some(signed_locktime) = self.signed_locktime() {
			debug_assert!(minimum_locktime.is_none());
			signed_locktime
		} else {
			core::cmp::max(current_height, minimum_locktime.unwrap_or(0))
		}
	}
	pub(crate) fn package_weight(&self, destination_script: &Script) -> u64 {
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
		(inputs_weight + witnesses_weight + transaction_weight + output_weight) as u64
	}
	pub(crate) fn construct_malleable_package_with_external_funding<Signer: EcdsaChannelSigner>(
		&self, onchain_handler: &mut OnchainTxHandler<Signer>,
	) -> Option<Vec<ExternalHTLCClaim>> {
		debug_assert!(self.requires_external_funding());
		let mut htlcs: Option<Vec<ExternalHTLCClaim>> = None;
		for (previous_output, input) in &self.inputs {
			match input {
				PackageSolvingData::HolderHTLCOutput(ref outp) => {
					debug_assert!(outp.channel_type_features.supports_anchors_zero_fee_htlc_tx());
					onchain_handler.generate_external_htlc_claim(&previous_output, &outp.preimage).map(|htlc| {
						htlcs.get_or_insert_with(|| Vec::with_capacity(self.inputs.len())).push(htlc);
					});
				}
				_ => debug_assert!(false, "Expected HolderHTLCOutputs to not be aggregated with other input types"),
			}
		}
		htlcs
	}
	pub(crate) fn maybe_finalize_malleable_package<L: Logger, Signer: EcdsaChannelSigner>(
		&self, current_height: u32, onchain_handler: &mut OnchainTxHandler<Signer>, value: Amount,
		destination_script: ScriptBuf, logger: &L
	) -> Option<MaybeSignedTransaction> {
		debug_assert!(self.is_malleable());
		let mut bumped_tx = Transaction {
			version: Version::TWO,
			lock_time: LockTime::from_consensus(self.package_locktime(current_height)),
			input: vec![],
			output: vec![TxOut {
				script_pubkey: destination_script,
				value,
			}],
		};
		for (outpoint, outp) in self.inputs.iter() {
			bumped_tx.input.push(outp.as_tx_input(*outpoint));
		}
		for (i, (outpoint, out)) in self.inputs.iter().enumerate() {
			log_debug!(logger, "Adding claiming input for outpoint {}:{}", outpoint.txid, outpoint.vout);
			if !out.finalize_input(&mut bumped_tx, i, onchain_handler) { continue; }
		}
		Some(MaybeSignedTransaction(bumped_tx))
	}
	pub(crate) fn maybe_finalize_untractable_package<L: Logger, Signer: EcdsaChannelSigner>(
		&self, onchain_handler: &mut OnchainTxHandler<Signer>, logger: &L,
	) -> Option<MaybeSignedTransaction> {
		debug_assert!(!self.is_malleable());
		if let Some((outpoint, outp)) = self.inputs.first() {
			if let Some(final_tx) = outp.get_maybe_finalized_tx(outpoint, onchain_handler) {
				log_debug!(logger, "Adding claiming input for outpoint {}:{}", outpoint.txid, outpoint.vout);
				return Some(final_tx);
			}
			return None;
		} else { panic!("API Error: Package must not be inputs empty"); }
	}
	/// Gets the next height at which we should fee-bump this package, assuming we can do so and
	/// the package is last fee-bumped at `current_height`.
	///
	/// As the deadline with which to get a claim confirmed approaches, the rate at which the timer
	/// ticks increases.
	pub(crate) fn get_height_timer(&self, current_height: u32) -> u32 {
		let mut height_timer = current_height + LOW_FREQUENCY_BUMP_INTERVAL;
		let timer_for_target_conf = |target_conf| -> u32 {
			if target_conf <= current_height + MIDDLE_FREQUENCY_BUMP_INTERVAL {
				current_height + HIGH_FREQUENCY_BUMP_INTERVAL
			} else if target_conf <= current_height + LOW_FREQUENCY_BUMP_INTERVAL {
				current_height + MIDDLE_FREQUENCY_BUMP_INTERVAL
			} else {
				current_height + LOW_FREQUENCY_BUMP_INTERVAL
			}
		};
		for (_, input) in self.inputs.iter() {
			match input {
				PackageSolvingData::RevokedOutput(_) => {
					// Revoked Outputs will become spendable by our counterparty at the height
					// where the CSV expires, which is also our `counterparty_spendable_height`.
					height_timer = cmp::min(
						height_timer,
						timer_for_target_conf(self.counterparty_spendable_height),
					);
				},
				PackageSolvingData::RevokedHTLCOutput(_) => {
					// Revoked HTLC Outputs may be spendable by our counterparty right now, but
					// after they spend them they still have to wait for an additional CSV delta
					// before they can claim the full funds. Thus, we leave the timer at
					// `LOW_FREQUENCY_BUMP_INTERVAL` until the HTLC output is spent, creating a
					// `RevokedOutput`.
				},
				PackageSolvingData::CounterpartyOfferedHTLCOutput(outp) => {
					// Incoming HTLCs being claimed by preimage should be claimed by the time their
					// CLTV unlocks.
					height_timer = cmp::min(
						height_timer,
						timer_for_target_conf(outp.htlc.cltv_expiry),
					);
				},
				PackageSolvingData::HolderHTLCOutput(outp) if outp.preimage.is_some() => {
					// We have the same deadline here as for `CounterpartyOfferedHTLCOutput`. Note
					// that `outp.cltv_expiry` is always 0 in this case, but
					// `counterparty_spendable_height` holds the real HTLC expiry.
					height_timer = cmp::min(
						height_timer,
						timer_for_target_conf(self.counterparty_spendable_height),
					);
				},
				PackageSolvingData::CounterpartyReceivedHTLCOutput(outp) => {
					// Outgoing HTLCs being claimed through their timeout should be claimed fast
					// enough to allow us to claim before the CLTV lock expires on the inbound
					// edge (assuming the HTLC was forwarded).
					height_timer = cmp::min(
						height_timer,
						timer_for_target_conf(outp.htlc.cltv_expiry + MIN_CLTV_EXPIRY_DELTA as u32),
					);
				},
				PackageSolvingData::HolderHTLCOutput(outp) => {
					// We have the same deadline for holder timeout claims as for
					// `CounterpartyReceivedHTLCOutput`
					height_timer = cmp::min(
						height_timer,
						timer_for_target_conf(outp.cltv_expiry + MIN_CLTV_EXPIRY_DELTA as u32),
					);
				},
				PackageSolvingData::HolderFundingOutput(_) => {
					// We should apply a smart heuristic here based on the HTLCs in the commitment
					// transaction, but we don't currently have that information available so
					// instead we just bump once per block.
					height_timer =
						cmp::min(height_timer, current_height + HIGH_FREQUENCY_BUMP_INTERVAL);
				},
			}
		}
		height_timer
	}

	/// Returns value in satoshis to be included as package outgoing output amount and feerate
	/// which was used to generate the value. Will not return less than `dust_limit_sats` for the
	/// value.
	pub(crate) fn compute_package_output<F: Deref, L: Logger>(
		&self, predicted_weight: u64, dust_limit_sats: u64, feerate_strategy: &FeerateStrategy,
		conf_target: ConfirmationTarget, fee_estimator: &LowerBoundedFeeEstimator<F>, logger: &L,
	) -> Option<(u64, u64)>
	where F::Target: FeeEstimator,
	{
		debug_assert!(matches!(self.malleability, PackageMalleability::Malleable(..)),
			"The package output is fixed for non-malleable packages");
		let input_amounts = self.package_amount();
		assert!(dust_limit_sats as i64 > 0, "Output script must be broadcastable/have a 'real' dust limit.");
		// If old feerate is 0, first iteration of this claim, use normal fee calculation
		if self.feerate_previous != 0 {
			if let Some((new_fee, feerate)) = feerate_bump(
				predicted_weight, input_amounts, dust_limit_sats, self.feerate_previous,
				feerate_strategy, conf_target, fee_estimator, logger,
			) {
				return Some((input_amounts.saturating_sub(new_fee), feerate));
			}
		} else {
			if let Some((new_fee, feerate)) = compute_fee_from_spent_amounts(input_amounts, predicted_weight, conf_target, fee_estimator, logger) {
				return Some((cmp::max(input_amounts as i64 - new_fee as i64, dust_limit_sats as i64) as u64, feerate));
			}
		}
		None
	}

	/// Computes a feerate based on the given confirmation target and feerate strategy.
	pub(crate) fn compute_package_feerate<F: Deref>(
		&self, fee_estimator: &LowerBoundedFeeEstimator<F>, conf_target: ConfirmationTarget,
		feerate_strategy: &FeerateStrategy,
	) -> u32 where F::Target: FeeEstimator {
		let feerate_estimate = fee_estimator.bounded_sat_per_1000_weight(conf_target);
		if self.feerate_previous != 0 {
			let previous_feerate = self.feerate_previous.try_into().unwrap_or(u32::max_value());
			match feerate_strategy {
				FeerateStrategy::RetryPrevious => previous_feerate,
				FeerateStrategy::HighestOfPreviousOrNew => cmp::max(previous_feerate, feerate_estimate),
				FeerateStrategy::ForceBump => if feerate_estimate > previous_feerate {
					feerate_estimate
				} else {
					// Our fee estimate has decreased, but our transaction remains unconfirmed after
					// using our previous fee estimate. This may point to an unreliable fee estimator,
					// so we choose to bump our previous feerate by 25%, making sure we don't use a
					// lower feerate or overpay by a large margin by limiting it to 5x the new fee
					// estimate.
					let previous_feerate = self.feerate_previous.try_into().unwrap_or(u32::max_value());
					let mut new_feerate = previous_feerate.saturating_add(previous_feerate / 4);
					if new_feerate > feerate_estimate * 5 {
						new_feerate = cmp::max(feerate_estimate * 5, previous_feerate);
					}
					new_feerate
				},
			}
		} else {
			feerate_estimate
		}
	}

	/// Determines whether a package contains an input which must have additional external inputs
	/// attached to help the spending transaction reach confirmation.
	pub(crate) fn requires_external_funding(&self) -> bool {
		self.inputs.iter().find(|input| match input.1 {
			PackageSolvingData::HolderFundingOutput(ref outp) => outp.channel_type_features.supports_anchors_zero_fee_htlc_tx(),
			PackageSolvingData::HolderHTLCOutput(ref outp) => outp.channel_type_features.supports_anchors_zero_fee_htlc_tx(),
			_ => false,
		}).is_some()
	}

	pub (crate) fn build_package(txid: Txid, vout: u32, input_solving_data: PackageSolvingData, counterparty_spendable_height: u32) -> Self {
		let malleability = PackageSolvingData::map_output_type_flags(&input_solving_data);
		let inputs = vec![(BitcoinOutPoint { txid, vout }, input_solving_data)];
		PackageTemplate {
			inputs,
			malleability,
			counterparty_spendable_height,
			feerate_previous: 0,
			height_timer: 0,
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
			(0, self.counterparty_spendable_height, required),
			(2, self.feerate_previous, required),
			// Prior to 0.1, the height at which the package's inputs were mined, but was always unused
			(4, 0u32, required),
			(6, self.height_timer, required)
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
		let malleability = if let Some((_, lead_input)) = inputs.first() {
			PackageSolvingData::map_output_type_flags(&lead_input)
		} else { return Err(DecodeError::InvalidValue); };
		let mut counterparty_spendable_height = 0;
		let mut feerate_previous = 0;
		let mut height_timer = None;
		let mut _height_original: Option<u32> = None;
		read_tlv_fields!(reader, {
			(0, counterparty_spendable_height, required),
			(2, feerate_previous, required),
			(4, _height_original, option), // Written with a dummy value since 0.1
			(6, height_timer, option),
		});
		for (_, input) in &inputs {
			if let PackageSolvingData::RevokedHTLCOutput(RevokedHTLCOutput { htlc, .. }) = input {
				// LDK versions through 0.1 set the wrong counterparty_spendable_height for
				// non-offered revoked HTLCs (ie HTLCs we sent to our counterparty which they can
				// claim with a preimage immediately). Here we detect this and reset the value to
				// zero, as the value is unused except for merging decisions which doesn't care
				// about any values below the current height.
				if !htlc.offered && htlc.cltv_expiry == counterparty_spendable_height {
					counterparty_spendable_height = 0;
				}
			}
		}
		Ok(PackageTemplate {
			inputs,
			malleability,
			counterparty_spendable_height,
			feerate_previous,
			height_timer: height_timer.unwrap_or(0),
		})
	}
}

/// Attempt to propose a bumping fee for a transaction from its spent output's values and predicted
/// weight. We first try our estimator's feerate, if it's not enough we try to sweep half of the
/// input amounts.
///
/// If the proposed fee is less than the available spent output's values, we return the proposed
/// fee and the corresponding updated feerate. If fee is under [`FEERATE_FLOOR_SATS_PER_KW`],
/// we return nothing.
fn compute_fee_from_spent_amounts<F: Deref, L: Logger>(
	input_amounts: u64, predicted_weight: u64, conf_target: ConfirmationTarget, fee_estimator: &LowerBoundedFeeEstimator<F>, logger: &L
) -> Option<(u64, u64)>
	where F::Target: FeeEstimator,
{
	let sweep_feerate = fee_estimator.bounded_sat_per_1000_weight(conf_target);
	let fee_rate = cmp::min(sweep_feerate, compute_feerate_sat_per_1000_weight(input_amounts / 2, predicted_weight));
	let fee = fee_rate as u64 * (predicted_weight) / 1000;

	// if the fee rate is below the floor, we don't sweep
	if fee_rate < FEERATE_FLOOR_SATS_PER_KW {
		log_error!(logger, "Failed to generate an on-chain tx with fee ({} sat/kw) was less than the floor ({} sat/kw)",
					fee_rate, FEERATE_FLOOR_SATS_PER_KW);
		None
	} else {
		Some((fee, fee_rate as u64))
	}
}

/// Attempt to propose a bumping fee for a transaction from its spent output's values and predicted
/// weight. If feerates proposed by the fee-estimator have been increasing since last fee-bumping
/// attempt, use them. If we need to force a feerate bump, we manually bump the feerate by 25% of
/// the previous feerate. If a feerate bump did happen, we also verify that those bumping heuristics
/// respect BIP125 rules 3) and 4) and if required adjust the new fee to meet the RBF policy
/// requirement.
fn feerate_bump<F: Deref, L: Logger>(
	predicted_weight: u64, input_amounts: u64, dust_limit_sats: u64, previous_feerate: u64,
	feerate_strategy: &FeerateStrategy, conf_target: ConfirmationTarget,
	fee_estimator: &LowerBoundedFeeEstimator<F>, logger: &L,
) -> Option<(u64, u64)>
where
	F::Target: FeeEstimator,
{
	let previous_fee = previous_feerate * predicted_weight / 1000;

	// If old feerate inferior to actual one given back by Fee Estimator, use it to compute new fee...
	let (new_fee, new_feerate) = if let Some((new_fee, new_feerate)) =
		compute_fee_from_spent_amounts(input_amounts, predicted_weight, conf_target, fee_estimator, logger)
	{
		log_debug!(logger, "Initiating fee rate bump from {} s/kWU ({} s) to {} s/kWU ({} s) using {:?} strategy", previous_feerate, previous_fee, new_feerate, new_fee, feerate_strategy);
		match feerate_strategy {
			FeerateStrategy::RetryPrevious => {
				let previous_fee = previous_feerate * predicted_weight / 1000;
				(previous_fee, previous_feerate)
			},
			FeerateStrategy::HighestOfPreviousOrNew => if new_feerate > previous_feerate {
				(new_fee, new_feerate)
			} else {
				let previous_fee = previous_feerate * predicted_weight / 1000;
				(previous_fee, previous_feerate)
			},
			FeerateStrategy::ForceBump => if new_feerate > previous_feerate {
				(new_fee, new_feerate)
			} else {
				// ...else just increase the previous feerate by 25% (because that's a nice number)
				let bumped_feerate = previous_feerate + (previous_feerate / 4);
				let bumped_fee = bumped_feerate * predicted_weight / 1000;

				(bumped_fee, bumped_feerate)
			},
		}
	} else {
		log_warn!(logger, "Can't bump new claiming tx, input amount {} is too small", input_amounts);
		return None;
	};

	// Our feerates should never decrease. If it hasn't changed though, we just need to
	// rebroadcast/re-sign the previous claim.
	debug_assert!(new_feerate >= previous_feerate);
	if new_feerate == previous_feerate {
		return Some((new_fee, new_feerate));
	}

	let min_relay_fee = INCREMENTAL_RELAY_FEE_SAT_PER_1000_WEIGHT * predicted_weight / 1000;
	// BIP 125 Opt-in Full Replace-by-Fee Signaling
	// 	* 3. The replacement transaction pays an absolute fee of at least the sum paid by the original transactions.
	//	* 4. The replacement transaction must also pay for its own bandwidth at or above the rate set by the node's minimum relay fee setting.
	let naive_new_fee = new_fee;
	let new_fee = cmp::max(new_fee, previous_fee + min_relay_fee);

	if new_fee > naive_new_fee {
		log_debug!(logger, "Naive fee bump of {}s does not meet min relay fee requirements of {}s", naive_new_fee - previous_fee, min_relay_fee);
	}

	let remaining_output_amount = input_amounts.saturating_sub(new_fee);
	if remaining_output_amount < dust_limit_sats {
		log_warn!(logger, "Can't bump new claiming tx, output amount {} would end up below dust threshold {}", remaining_output_amount, dust_limit_sats);
		return None;
	}

	let new_feerate = new_fee * 1000 / predicted_weight;
	log_debug!(logger, "Fee rate bumped by {}s from {} s/KWU ({} s) to {} s/KWU ({} s)", new_fee - previous_fee, previous_feerate, previous_fee, new_feerate, new_fee);
	Some((new_fee, new_feerate))
}

#[cfg(test)]
mod tests {
	use crate::chain::package::{CounterpartyOfferedHTLCOutput, CounterpartyReceivedHTLCOutput, HolderFundingOutput, HolderHTLCOutput, PackageTemplate, PackageSolvingData, RevokedHTLCOutput, RevokedOutput, WEIGHT_REVOKED_OUTPUT, weight_offered_htlc, weight_received_htlc, feerate_bump};
	use crate::chain::Txid;
	use crate::ln::chan_utils::HTLCOutputInCommitment;
	use crate::types::payment::{PaymentPreimage, PaymentHash};
	use crate::ln::channel_keys::{DelayedPaymentBasepoint, HtlcBasepoint};

	use bitcoin::absolute::LockTime;
	use bitcoin::amount::Amount;
	use bitcoin::constants::WITNESS_SCALE_FACTOR;
	use bitcoin::script::ScriptBuf;
	use bitcoin::transaction::OutPoint as BitcoinOutPoint;
	use bitcoin::transaction::Version;
	use bitcoin::{Transaction, TxOut};

	use bitcoin::hex::FromHex;

	use bitcoin::secp256k1::{PublicKey,SecretKey};
	use bitcoin::secp256k1::Secp256k1;
	use crate::chain::chaininterface::{ConfirmationTarget, FeeEstimator, FEERATE_FLOOR_SATS_PER_KW, LowerBoundedFeeEstimator};
	use crate::chain::onchaintx::FeerateStrategy;
	use crate::types::features::ChannelTypeFeatures;
	use crate::util::test_utils::TestLogger;

	fn fake_txid(n: u64) -> Txid {
		Transaction {
			version: Version(0),
			lock_time: LockTime::ZERO,
			input: vec![],
			output: vec![TxOut {
				value: Amount::from_sat(n),
				script_pubkey: ScriptBuf::new(),
			}],
		}.compute_txid()
	}

	macro_rules! dumb_revk_output {
		($is_counterparty_balance_on_anchors: expr) => {
			{
				let secp_ctx = Secp256k1::new();
				let dumb_scalar = SecretKey::from_slice(&<Vec<u8>>::from_hex("0101010101010101010101010101010101010101010101010101010101010101").unwrap()[..]).unwrap();
				let dumb_point = PublicKey::from_secret_key(&secp_ctx, &dumb_scalar);
				PackageSolvingData::RevokedOutput(RevokedOutput::build(dumb_point, DelayedPaymentBasepoint::from(dumb_point), HtlcBasepoint::from(dumb_point), dumb_scalar, Amount::ZERO, 0, $is_counterparty_balance_on_anchors))
			}
		}
	}

	macro_rules! dumb_revk_htlc_output {
		() => {
			{
				let secp_ctx = Secp256k1::new();
				let dumb_scalar = SecretKey::from_slice(&<Vec<u8>>::from_hex("0101010101010101010101010101010101010101010101010101010101010101").unwrap()[..]).unwrap();
				let dumb_point = PublicKey::from_secret_key(&secp_ctx, &dumb_scalar);
				let hash = PaymentHash([1; 32]);
				let htlc = HTLCOutputInCommitment { offered: false, amount_msat: 1_000_000, cltv_expiry: 0, payment_hash: hash, transaction_output_index: None };
				PackageSolvingData::RevokedHTLCOutput(RevokedHTLCOutput::build(dumb_point, DelayedPaymentBasepoint::from(dumb_point), HtlcBasepoint::from(dumb_point), dumb_scalar, 1_000_000 / 1_000, htlc, &ChannelTypeFeatures::anchors_zero_htlc_fee_and_dependencies()))
			}
		}
	}

	macro_rules! dumb_counterparty_received_output {
		($amt: expr, $expiry: expr, $features: expr) => {
			{
				let secp_ctx = Secp256k1::new();
				let dumb_scalar = SecretKey::from_slice(&<Vec<u8>>::from_hex("0101010101010101010101010101010101010101010101010101010101010101").unwrap()[..]).unwrap();
				let dumb_point = PublicKey::from_secret_key(&secp_ctx, &dumb_scalar);
				let hash = PaymentHash([1; 32]);
				let htlc = HTLCOutputInCommitment { offered: true, amount_msat: $amt, cltv_expiry: $expiry, payment_hash: hash, transaction_output_index: None };
				PackageSolvingData::CounterpartyReceivedHTLCOutput(CounterpartyReceivedHTLCOutput::build(dumb_point, DelayedPaymentBasepoint::from(dumb_point), HtlcBasepoint::from(dumb_point), htlc, $features))
			}
		}
	}

	macro_rules! dumb_counterparty_offered_output {
		($amt: expr, $features: expr) => {
			{
				let secp_ctx = Secp256k1::new();
				let dumb_scalar = SecretKey::from_slice(&<Vec<u8>>::from_hex("0101010101010101010101010101010101010101010101010101010101010101").unwrap()[..]).unwrap();
				let dumb_point = PublicKey::from_secret_key(&secp_ctx, &dumb_scalar);
				let hash = PaymentHash([1; 32]);
				let preimage = PaymentPreimage([2;32]);
				let htlc = HTLCOutputInCommitment { offered: false, amount_msat: $amt, cltv_expiry: 0, payment_hash: hash, transaction_output_index: None };
				PackageSolvingData::CounterpartyOfferedHTLCOutput(CounterpartyOfferedHTLCOutput::build(dumb_point, DelayedPaymentBasepoint::from(dumb_point), HtlcBasepoint::from(dumb_point), preimage, htlc, $features))
			}
		}
	}

	macro_rules! dumb_accepted_htlc_output {
		($features: expr) => {
			{
				let preimage = PaymentPreimage([2;32]);
				PackageSolvingData::HolderHTLCOutput(HolderHTLCOutput::build_accepted(preimage, 0, $features))
			}
		}
	}

	macro_rules! dumb_offered_htlc_output {
		($cltv_expiry: expr, $features: expr) => {
			{
				PackageSolvingData::HolderHTLCOutput(HolderHTLCOutput::build_offered(0, $cltv_expiry, $features))
			}
		}
	}

	macro_rules! dumb_funding_output {
		() => {
			PackageSolvingData::HolderFundingOutput(HolderFundingOutput::build(ScriptBuf::new(), 0, ChannelTypeFeatures::only_static_remote_key()))
		}
	}

	#[test]
	fn test_merge_package_untractable_funding_output() {
		let funding_outp = dumb_funding_output!();
		let htlc_outp = dumb_accepted_htlc_output!(ChannelTypeFeatures::anchors_zero_htlc_fee_and_dependencies());

		let mut untractable_package = PackageTemplate::build_package(fake_txid(1), 0, funding_outp.clone(), 0);
		let mut malleable_package = PackageTemplate::build_package(fake_txid(2), 0, htlc_outp.clone(), 1100);

		assert!(!untractable_package.can_merge_with(&malleable_package, 1000));
		assert!(untractable_package.merge_package(malleable_package.clone(), 1000).is_err());

		assert!(!malleable_package.can_merge_with(&untractable_package, 1000));
		assert!(malleable_package.merge_package(untractable_package.clone(), 1000).is_err());
	}

	#[test]
	fn test_merge_empty_package() {
		let revk_outp = dumb_revk_htlc_output!();

		let mut empty_package = PackageTemplate::build_package(fake_txid(1), 0, revk_outp.clone(), 0);
		empty_package.inputs = vec![];
		let mut package = PackageTemplate::build_package(fake_txid(1), 1, revk_outp.clone(), 1100);
		assert!(empty_package.merge_package(package.clone(), 1000).is_err());
		assert!(package.merge_package(empty_package.clone(), 1000).is_err());
	}

	#[test]
	fn test_merge_package_different_signed_locktimes() {
		// Malleable HTLC transactions are signed over the locktime, and can't be aggregated with
		// different locktimes.
		let offered_htlc_1 = dumb_offered_htlc_output!(900, ChannelTypeFeatures::anchors_zero_htlc_fee_and_dependencies());
		let offered_htlc_2 = dumb_offered_htlc_output!(901, ChannelTypeFeatures::anchors_zero_htlc_fee_and_dependencies());
		let accepted_htlc = dumb_accepted_htlc_output!(ChannelTypeFeatures::anchors_zero_htlc_fee_and_dependencies());

		let mut offered_htlc_1_package = PackageTemplate::build_package(fake_txid(1), 0, offered_htlc_1.clone(), 0);
		let mut offered_htlc_2_package = PackageTemplate::build_package(fake_txid(1), 1, offered_htlc_2.clone(), 0);
		let mut accepted_htlc_package = PackageTemplate::build_package(fake_txid(1), 2, accepted_htlc.clone(), 1001);

		assert!(!offered_htlc_2_package.can_merge_with(&offered_htlc_1_package, 1000));
		assert!(offered_htlc_2_package.merge_package(offered_htlc_1_package.clone(), 1000).is_err());
		assert!(!offered_htlc_1_package.can_merge_with(&offered_htlc_2_package, 1000));
		assert!(offered_htlc_1_package.merge_package(offered_htlc_2_package.clone(), 1000).is_err());

		assert!(!accepted_htlc_package.can_merge_with(&offered_htlc_1_package, 1000));
		assert!(accepted_htlc_package.merge_package(offered_htlc_1_package.clone(), 1000).is_err());
		assert!(!offered_htlc_1_package.can_merge_with(&accepted_htlc_package, 1000));
		assert!(offered_htlc_1_package.merge_package(accepted_htlc_package.clone(), 1000).is_err());
	}

	#[test]
	fn test_merge_package_different_effective_locktimes() {
		// Spends of outputs can have different minimum locktimes, and are not mergeable if they are in the
		// future.
		let old_outp_1 = dumb_counterparty_received_output!(1_000_000, 900, ChannelTypeFeatures::only_static_remote_key());
		let old_outp_2 = dumb_counterparty_received_output!(1_000_000, 901, ChannelTypeFeatures::only_static_remote_key());
		let future_outp_1 = dumb_counterparty_received_output!(1_000_000, 1001, ChannelTypeFeatures::only_static_remote_key());
		let future_outp_2 = dumb_counterparty_received_output!(1_000_000, 1002, ChannelTypeFeatures::only_static_remote_key());

		let old_outp_1_package = PackageTemplate::build_package(fake_txid(1), 0, old_outp_1.clone(), 0);
		let old_outp_2_package = PackageTemplate::build_package(fake_txid(1), 1, old_outp_2.clone(), 0);
		let future_outp_1_package = PackageTemplate::build_package(fake_txid(1), 2, future_outp_1.clone(), 0);
		let future_outp_2_package = PackageTemplate::build_package(fake_txid(1), 3, future_outp_2.clone(), 0);

		assert!(old_outp_1_package.can_merge_with(&old_outp_2_package, 1000));
		assert!(old_outp_2_package.can_merge_with(&old_outp_1_package, 1000));
		assert!(old_outp_1_package.clone().merge_package(old_outp_2_package.clone(), 1000).is_ok());
		assert!(old_outp_2_package.clone().merge_package(old_outp_1_package.clone(), 1000).is_ok());

		assert!(!future_outp_1_package.can_merge_with(&future_outp_2_package, 1000));
		assert!(!future_outp_2_package.can_merge_with(&future_outp_1_package, 1000));
		assert!(future_outp_1_package.clone().merge_package(future_outp_2_package.clone(), 1000).is_err());
		assert!(future_outp_2_package.clone().merge_package(future_outp_1_package.clone(), 1000).is_err());
	}

	#[test]
	fn test_merge_package_holder_htlc_output_clusters() {
		// Signed locktimes of 0.
		let unpinnable_1 = dumb_accepted_htlc_output!(ChannelTypeFeatures::anchors_zero_htlc_fee_and_dependencies());
		let unpinnable_2 = dumb_accepted_htlc_output!(ChannelTypeFeatures::anchors_zero_htlc_fee_and_dependencies());
		let considered_pinnable = dumb_accepted_htlc_output!(ChannelTypeFeatures::anchors_zero_htlc_fee_and_dependencies());
		// Signed locktimes of 1000.
		let pinnable_1 = dumb_offered_htlc_output!(1000, ChannelTypeFeatures::anchors_zero_htlc_fee_and_dependencies());
		let pinnable_2 = dumb_offered_htlc_output!(1000, ChannelTypeFeatures::anchors_zero_htlc_fee_and_dependencies());

		let mut unpinnable_1_package = PackageTemplate::build_package(fake_txid(1), 0, unpinnable_1.clone(), 1100);
		let mut unpinnable_2_package = PackageTemplate::build_package(fake_txid(1), 1, unpinnable_2.clone(), 1100);
		let mut considered_pinnable_package = PackageTemplate::build_package(fake_txid(1), 2, considered_pinnable.clone(), 1001);
		let mut pinnable_1_package = PackageTemplate::build_package(fake_txid(1), 3, pinnable_1.clone(), 0);
		let mut pinnable_2_package = PackageTemplate::build_package(fake_txid(1), 4, pinnable_2.clone(), 0);

		// Unpinnable with signed locktimes of 0.
		let unpinnable_cluster = [&mut unpinnable_1_package, &mut unpinnable_2_package];
		// Pinnables with signed locktime of 1000.
		let pinnable_cluster = [&mut pinnable_1_package, &mut pinnable_2_package];
		// Pinnable with signed locktime of 0.
		let considered_pinnable_cluster = [&mut considered_pinnable_package];
		// Pinnable and unpinnable malleable packages are kept separate. A package is considered
		// unpinnable if it can only be claimed by the counterparty a given amount of time in the
		// future.
		let clusters = [unpinnable_cluster.as_slice(), pinnable_cluster.as_slice(), considered_pinnable_cluster.as_slice()];

		for a in 0..clusters.len() {
			for b in 0..clusters.len() {
				for i in 0..clusters[a].len() {
					for j in 0..clusters[b].len() {
						if a != b {
							assert!(!clusters[a][i].can_merge_with(clusters[b][j], 1000));
						} else {
							if i != j {
								assert!(clusters[a][i].can_merge_with(clusters[b][j], 1000));
							}
						}
					}
				}
			}
		}

		let mut packages = vec![
			unpinnable_1_package, unpinnable_2_package, considered_pinnable_package,
			pinnable_1_package, pinnable_2_package,
		];
		for i in (1..packages.len()).rev() {
			for j in 0..i {
				if packages[i].can_merge_with(&packages[j], 1000) {
					let merge = packages.remove(i);
					assert!(packages[j].merge_package(merge, 1000).is_ok());
				}
			}
		}
		assert_eq!(packages.len(), 3);
	}

	#[test]
	#[should_panic]
	fn test_merge_package_different_tx_trees() {
		let offered_htlc = dumb_offered_htlc_output!(900, ChannelTypeFeatures::anchors_zero_htlc_fee_and_dependencies());
		let mut offered_htlc_package = PackageTemplate::build_package(fake_txid(1), 0, offered_htlc.clone(), 0);
		let counterparty_received_htlc = dumb_counterparty_received_output!(1_000_000, 900, ChannelTypeFeatures::only_static_remote_key());
		let counterparty_received_htlc_package = PackageTemplate::build_package(fake_txid(2), 0, counterparty_received_htlc.clone(), 0);

		assert!(!offered_htlc_package.can_merge_with(&counterparty_received_htlc_package, 1000));
		assert!(offered_htlc_package.merge_package(counterparty_received_htlc_package.clone(), 1000).is_err());
	}

	#[test]
	fn test_package_split_malleable() {
		let revk_outp_one = dumb_revk_output!(false);
		let revk_outp_two = dumb_revk_output!(false);
		let revk_outp_three = dumb_revk_output!(false);

		let mut package_one = PackageTemplate::build_package(fake_txid(1), 0, revk_outp_one, 1100);
		let package_two = PackageTemplate::build_package(fake_txid(1), 1, revk_outp_two, 1100);
		let package_three = PackageTemplate::build_package(fake_txid(1), 2, revk_outp_three, 1100);

		assert!(package_one.merge_package(package_two, 1000).is_ok());
		assert!(package_one.merge_package(package_three, 1000).is_ok());
		assert_eq!(package_one.outpoints().len(), 3);

		if let Some(split_package) = package_one.split_package(&BitcoinOutPoint { txid: fake_txid(1), vout: 1 }) {
			// Packages attributes should be identical
			assert!(split_package.is_malleable());
			assert_eq!(split_package.counterparty_spendable_height, package_one.counterparty_spendable_height);
			assert_eq!(split_package.feerate_previous, package_one.feerate_previous);
			assert_eq!(split_package.height_timer, package_one.height_timer);
		} else { panic!(); }
		assert_eq!(package_one.outpoints().len(), 2);
	}

	#[test]
	fn test_package_split_untractable() {
		let htlc_outp_one = dumb_accepted_htlc_output!(ChannelTypeFeatures::only_static_remote_key());

		let mut package_one = PackageTemplate::build_package(fake_txid(1), 0, htlc_outp_one, 1000);
		let ret_split = package_one.split_package(&BitcoinOutPoint { txid: fake_txid(1), vout: 0 });
		assert!(ret_split.is_none());
	}

	#[test]
	fn test_package_timer() {
		let revk_outp = dumb_revk_output!(false);

		let mut package = PackageTemplate::build_package(fake_txid(1), 0, revk_outp, 1000);
		assert_eq!(package.timer(), 0);
		package.set_timer(101);
		assert_eq!(package.timer(), 101);
	}

	#[test]
	fn test_package_amounts() {
		let counterparty_outp = dumb_counterparty_received_output!(1_000_000, 1000, ChannelTypeFeatures::only_static_remote_key());

		let package = PackageTemplate::build_package(fake_txid(1), 0, counterparty_outp, 1000);
		assert_eq!(package.package_amount(), 1000);
	}

	#[test]
	fn test_package_weight() {
		// (nVersion (4) + nLocktime (4) + count_tx_in (1) + prevout (36) + sequence (4) + script_length (1) + count_tx_out (1) + value (8) + var_int (1)) * WITNESS_SCALE_FACTOR + witness marker (2)
		let weight_sans_output = (4 + 4 + 1 + 36 + 4 + 1 + 1 + 8 + 1) * WITNESS_SCALE_FACTOR as u64 + 2;

		{
			let revk_outp = dumb_revk_output!(false);
			let package = PackageTemplate::build_package(fake_txid(1), 0, revk_outp, 0);
			assert_eq!(package.package_weight(&ScriptBuf::new()),  weight_sans_output + WEIGHT_REVOKED_OUTPUT);
		}

		{
			for channel_type_features in [ChannelTypeFeatures::only_static_remote_key(), ChannelTypeFeatures::anchors_zero_htlc_fee_and_dependencies()].iter() {
				let counterparty_outp = dumb_counterparty_received_output!(1_000_000, 1000, channel_type_features.clone());
				let package = PackageTemplate::build_package(fake_txid(1), 0, counterparty_outp, 1000);
				assert_eq!(package.package_weight(&ScriptBuf::new()), weight_sans_output + weight_received_htlc(channel_type_features));
			}
		}

		{
			for channel_type_features in [ChannelTypeFeatures::only_static_remote_key(), ChannelTypeFeatures::anchors_zero_htlc_fee_and_dependencies()].iter() {
				let counterparty_outp = dumb_counterparty_offered_output!(1_000_000, channel_type_features.clone());
				let package = PackageTemplate::build_package(fake_txid(1), 0, counterparty_outp, 1000);
				assert_eq!(package.package_weight(&ScriptBuf::new()), weight_sans_output + weight_offered_htlc(channel_type_features));
			}
		}
	}

	struct TestFeeEstimator {
		sat_per_kw: u32,
	}

	impl FeeEstimator for TestFeeEstimator {
		fn get_est_sat_per_1000_weight(&self, _: ConfirmationTarget) -> u32 {
			self.sat_per_kw
		}
	}

	#[test]
	fn test_feerate_bump() {
		let sat_per_kw = FEERATE_FLOOR_SATS_PER_KW;
		let test_fee_estimator = &TestFeeEstimator { sat_per_kw };
		let fee_estimator = LowerBoundedFeeEstimator::new(test_fee_estimator);
		let fee_rate_strategy = FeerateStrategy::ForceBump;
		let confirmation_target = ConfirmationTarget::UrgentOnChainSweep;

		{
			// Check underflow doesn't occur
			let predicted_weight_units = 1000;
			let input_satoshis = 505;

			let logger = TestLogger::new();
			let bumped_fee_rate = feerate_bump(predicted_weight_units, input_satoshis, 546, 253, &fee_rate_strategy, confirmation_target, &fee_estimator, &logger);
			assert!(bumped_fee_rate.is_none());
			logger.assert_log_regex("lightning::chain::package", regex::Regex::new(r"Can't bump new claiming tx, input amount 505 is too small").unwrap(), 1);
		}

		{
			// Check post-25%-bump-underflow scenario satisfying the following constraints:
			// input - fee = 546
			// input - fee * 1.25 = -1

			// We accomplish that scenario with the following values:
			// input = 2734
			// fee = 2188

			let predicted_weight_units = 1000;
			let input_satoshis = 2734;

			let logger = TestLogger::new();
			let bumped_fee_rate = feerate_bump(predicted_weight_units, input_satoshis, 546, 2188, &fee_rate_strategy, confirmation_target, &fee_estimator, &logger);
			assert!(bumped_fee_rate.is_none());
			logger.assert_log_regex("lightning::chain::package", regex::Regex::new(r"Can't bump new claiming tx, output amount 0 would end up below dust threshold 546").unwrap(), 1);
		}

		{
			// Check that an output amount of 0 is caught
			let predicted_weight_units = 1000;
			let input_satoshis = 506;

			let logger = TestLogger::new();
			let bumped_fee_rate = feerate_bump(predicted_weight_units, input_satoshis, 546, 253, &fee_rate_strategy, confirmation_target, &fee_estimator, &logger);
			assert!(bumped_fee_rate.is_none());
			logger.assert_log_regex("lightning::chain::package", regex::Regex::new(r"Can't bump new claiming tx, output amount 0 would end up below dust threshold 546").unwrap(), 1);
		}

		{
			// Check that dust_threshold - 1 is blocked
			let predicted_weight_units = 1000;
			let input_satoshis = 1051;

			let logger = TestLogger::new();
			let bumped_fee_rate = feerate_bump(predicted_weight_units, input_satoshis, 546, 253, &fee_rate_strategy, confirmation_target, &fee_estimator, &logger);
			assert!(bumped_fee_rate.is_none());
			logger.assert_log_regex("lightning::chain::package", regex::Regex::new(r"Can't bump new claiming tx, output amount 545 would end up below dust threshold 546").unwrap(), 1);
		}

		{
			let predicted_weight_units = 1000;
			let input_satoshis = 1052;

			let logger = TestLogger::new();
			let bumped_fee_rate = feerate_bump(predicted_weight_units, input_satoshis, 546, 253, &fee_rate_strategy, confirmation_target, &fee_estimator, &logger).unwrap();
			assert_eq!(bumped_fee_rate, (506, 506));
			logger.assert_log_regex("lightning::chain::package", regex::Regex::new(r"Naive fee bump of 63s does not meet min relay fee requirements of 253s").unwrap(), 1);
		}
	}
}
