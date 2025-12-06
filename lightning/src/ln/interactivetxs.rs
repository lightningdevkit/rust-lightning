// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

use crate::chain::transaction::OutPoint;
use crate::io_extras::sink;
use crate::prelude::*;

use bitcoin::absolute::LockTime as AbsoluteLockTime;
use bitcoin::amount::{Amount, SignedAmount};
use bitcoin::consensus::Encodable;
use bitcoin::constants::WITNESS_SCALE_FACTOR;
use bitcoin::ecdsa::Signature as BitcoinSignature;
use bitcoin::key::Secp256k1;
use bitcoin::policy::MAX_STANDARD_TX_WEIGHT;
use bitcoin::secp256k1::{Message, PublicKey};
use bitcoin::sighash::SighashCache;
use bitcoin::transaction::Version;
use bitcoin::{
	sighash, EcdsaSighashType, OutPoint as BitcoinOutPoint, ScriptBuf, Sequence, TapSighashType,
	Transaction, TxIn, TxOut, Txid, Weight, Witness, XOnlyPublicKey,
};

use crate::chain::chaininterface::fee_for_weight;
use crate::ln::chan_utils::{
	BASE_INPUT_WEIGHT, EMPTY_SCRIPT_SIG_WEIGHT, FUNDING_TRANSACTION_WITNESS_WEIGHT,
	SEGWIT_MARKER_FLAG_WEIGHT,
};
use crate::ln::channel::{FundingNegotiationContext, TOTAL_BITCOIN_SUPPLY_SATOSHIS};
use crate::ln::funding::FundingTxInput;
use crate::ln::msgs;
use crate::ln::msgs::{MessageSendEvent, SerialId, TxSignatures};
use crate::ln::types::ChannelId;
use crate::sign::{EntropySource, P2TR_KEY_PATH_WITNESS_WEIGHT, P2WPKH_WITNESS_WEIGHT};

use core::fmt::Display;
use core::ops::Deref;

/// The number of received `tx_add_input` messages during a negotiation at which point the
/// negotiation MUST be failed.
const MAX_RECEIVED_TX_ADD_INPUT_COUNT: u16 = 4096;

/// The number of received `tx_add_output` messages during a negotiation at which point the
/// negotiation MUST be failed.
const MAX_RECEIVED_TX_ADD_OUTPUT_COUNT: u16 = 4096;

/// The number of inputs or outputs that the state machine can have, before it MUST fail the
/// negotiation.
const MAX_INPUTS_OUTPUTS_COUNT: usize = 252;

/// The total weight of the common fields whose fee is paid by the initiator of the interactive
/// transaction construction protocol.
pub(crate) const TX_COMMON_FIELDS_WEIGHT: u64 = (4 /* version */ + 4 /* locktime */ + 1 /* input count */ +
	1 /* output count */) * WITNESS_SCALE_FACTOR as u64 + 2 /* segwit marker + flag */;

// BOLT 3 - Lower bounds for input weights

/// Lower bound for P2WPKH input weight
pub(crate) const P2WPKH_INPUT_WEIGHT_LOWER_BOUND: u64 =
	BASE_INPUT_WEIGHT + EMPTY_SCRIPT_SIG_WEIGHT + P2WPKH_WITNESS_WEIGHT;

/// Lower bound for P2WSH input weight is chosen as same as P2WPKH input weight in BOLT 3
pub(crate) const P2WSH_INPUT_WEIGHT_LOWER_BOUND: u64 = P2WPKH_INPUT_WEIGHT_LOWER_BOUND;

/// Lower bound for P2TR input weight is chosen as the key spend path.
/// Not specified in BOLT 3, but a reasonable lower bound.
pub(crate) const P2TR_INPUT_WEIGHT_LOWER_BOUND: u64 =
	BASE_INPUT_WEIGHT + EMPTY_SCRIPT_SIG_WEIGHT + P2TR_KEY_PATH_WITNESS_WEIGHT;

/// Lower bound for unknown segwit version input weight is chosen the same as P2WPKH in BOLT 3
pub(crate) const UNKNOWN_SEGWIT_VERSION_INPUT_WEIGHT_LOWER_BOUND: u64 =
	P2WPKH_INPUT_WEIGHT_LOWER_BOUND;

trait SerialIdExt {
	fn is_for_initiator(&self) -> bool;
	fn is_for_non_initiator(&self) -> bool;
}

impl SerialIdExt for SerialId {
	fn is_for_initiator(&self) -> bool {
		self % 2 == 0
	}

	fn is_for_non_initiator(&self) -> bool {
		!self.is_for_initiator()
	}
}

#[derive(Clone, Debug)]
pub(crate) struct NegotiationError {
	pub reason: AbortReason,
	pub contributed_inputs: Vec<BitcoinOutPoint>,
	pub contributed_outputs: Vec<TxOut>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AbortReason {
	InvalidStateTransition,
	UnexpectedCounterpartyMessage,
	ReceivedTooManyTxAddInputs,
	ReceivedTooManyTxAddOutputs,
	IncorrectInputSequenceValue,
	IncorrectSerialIdParity,
	SerialIdUnknown,
	DuplicateSerialId,
	/// Invalid provided inputs and previous transactions, several possible reasons:
	/// - nonexisting `vout`, or
	/// - mismatching `TxId`'s
	/// - duplicate input,
	/// - not a witness program,
	/// etc.
	PrevTxOutInvalid,
	ExceededMaximumSatsAllowed,
	ExceededNumberOfInputsOrOutputs,
	TransactionTooLarge,
	BelowDustLimit,
	InvalidOutputScript,
	InsufficientFees,
	OutputsValueExceedsInputsValue,
	InvalidTx,
	/// No funding (shared) input found.
	MissingFundingInput,
	/// A funding (shared) input was seen, but we don't expect one
	UnexpectedFundingInput,
	/// In tx_add_input, the prev_tx field must be filled in case of non-shared input
	MissingPrevTx,
	/// In tx_add_input, the prev_tx field should not be filled in case of shared input
	UnexpectedPrevTx,
	/// No funding (shared) output found.
	MissingFundingOutput,
	/// More than one funding (shared) output found.
	DuplicateFundingOutput,
	/// More than one funding (shared) input found.
	DuplicateFundingInput,
	/// Internal error
	InternalError(&'static str),
}

impl AbortReason {
	pub fn into_tx_abort_msg(self, channel_id: ChannelId) -> msgs::TxAbort {
		msgs::TxAbort { channel_id, data: self.to_string().into_bytes() }
	}
}

impl Display for AbortReason {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		match self {
			AbortReason::InvalidStateTransition => f.write_str("State transition was invalid"),
			AbortReason::UnexpectedCounterpartyMessage => f.write_str("Unexpected message"),
			AbortReason::ReceivedTooManyTxAddInputs => {
				f.write_str("Too many `tx_add_input`s received")
			},
			AbortReason::ReceivedTooManyTxAddOutputs => {
				f.write_str("Too many `tx_add_output`s received")
			},
			AbortReason::IncorrectInputSequenceValue => {
				f.write_str("Input has a sequence value greater than 0xFFFFFFFD")
			},
			AbortReason::IncorrectSerialIdParity => {
				f.write_str("Parity for `serial_id` was incorrect")
			},
			AbortReason::SerialIdUnknown => f.write_str("The `serial_id` is unknown"),
			AbortReason::DuplicateSerialId => f.write_str("The `serial_id` already exists"),
			AbortReason::PrevTxOutInvalid => f.write_str("Invalid previous transaction output"),
			AbortReason::ExceededMaximumSatsAllowed => {
				f.write_str("Output amount exceeded total bitcoin supply")
			},
			AbortReason::ExceededNumberOfInputsOrOutputs => {
				f.write_str("Too many inputs or outputs")
			},
			AbortReason::TransactionTooLarge => f.write_str("Transaction weight is too large"),
			AbortReason::BelowDustLimit => f.write_str("Output amount is below the dust limit"),
			AbortReason::InvalidOutputScript => f.write_str("The output script is non-standard"),
			AbortReason::InsufficientFees => f.write_str("Insufficient fees paid"),
			AbortReason::OutputsValueExceedsInputsValue => {
				f.write_str("Total value of outputs exceeds total value of inputs")
			},
			AbortReason::InvalidTx => f.write_str("The transaction is invalid"),
			AbortReason::MissingFundingInput => f.write_str("No shared funding input found"),
			AbortReason::UnexpectedFundingInput => {
				f.write_str("A funding (shared) input was seen, but we don't expect one")
			},
			AbortReason::MissingPrevTx => f.write_str(
				"In tx_add_input, the prev_tx field must be filled in case of non-shared input",
			),
			AbortReason::UnexpectedPrevTx => f.write_str(
				"In tx_add_input, the prev_tx should not be filled in case of shared input",
			),
			AbortReason::MissingFundingOutput => f.write_str("No shared funding output found"),
			AbortReason::DuplicateFundingOutput => {
				f.write_str("More than one funding output found")
			},
			AbortReason::DuplicateFundingInput => f.write_str("More than one funding input found"),
			AbortReason::InternalError(text) => {
				f.write_fmt(format_args!("Internal error: {}", text))
			},
		}
	}
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConstructedTransaction {
	holder_is_initiator: bool,
	input_metadata: Vec<TxInMetadata>,
	output_metadata: Vec<TxOutMetadata>,
	tx: Transaction,
	shared_input_index: Option<u16>,
	shared_output_index: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TxInMetadata {
	serial_id: SerialId,
	prev_output: TxOut,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TxOutMetadata {
	serial_id: SerialId,
}

impl TxInMetadata {
	pub(super) fn is_local(&self, holder_is_initiator: bool) -> bool {
		!is_serial_id_valid_for_counterparty(holder_is_initiator, self.serial_id)
	}

	pub(super) fn prev_output(&self) -> &TxOut {
		&self.prev_output
	}
}

impl TxOutMetadata {
	pub(super) fn is_local(&self, holder_is_initiator: bool) -> bool {
		!is_serial_id_valid_for_counterparty(holder_is_initiator, self.serial_id)
	}
}

impl_writeable_tlv_based!(TxInMetadata, {
	(1, serial_id, required),
	(3, prev_output, required),
});

impl_writeable_tlv_based!(TxOutMetadata, {
	(1, serial_id, required),
});

impl_writeable_tlv_based!(ConstructedTransaction, {
	(1, holder_is_initiator, required),
	(3, input_metadata, required),
	(5, output_metadata, required),
	(7, tx, required),
	(9, shared_input_index, option),
	(11, shared_output_index, required),
});

/// The percent tolerance given to the remote when estimating if they paid enough fees.
const REMOTE_FEE_TOLERANCE_PERCENT: u64 = 95;

impl ConstructedTransaction {
	fn new(context: NegotiationContext) -> Result<Self, AbortReason> {
		let remote_inputs_value = context.remote_inputs_value();
		let remote_outputs_value = context.remote_outputs_value();
		let remote_weight_contributed = context.remote_weight_contributed();

		let expected_witness_weight = context.inputs.iter().fold(0u64, |value, (_, input)| {
			value
				.saturating_add(input.satisfaction_weight().to_wu())
				.saturating_sub(EMPTY_SCRIPT_SIG_WEIGHT)
		});

		let lock_time = context.tx_locktime;

		let mut inputs: Vec<(TxIn, TxInMetadata)> =
			context.inputs.into_values().map(|input| input.into_txin_and_metadata()).collect();
		let mut outputs: Vec<(TxOut, TxOutMetadata)> =
			context.outputs.into_values().map(|output| output.into_txout_and_metadata()).collect();
		inputs.sort_unstable_by_key(|(_, input)| input.serial_id);
		outputs.sort_unstable_by_key(|(_, output)| output.serial_id);

		let (input, input_metadata): (Vec<TxIn>, Vec<TxInMetadata>) = inputs.into_iter().unzip();
		let (output, output_metadata): (Vec<TxOut>, Vec<TxOutMetadata>) =
			outputs.into_iter().unzip();

		let shared_input_index =
			context.shared_funding_input.as_ref().and_then(|shared_funding_input| {
				input
					.iter()
					.position(|txin| {
						txin.previous_output == shared_funding_input.input.previous_output
					})
					.map(|position| position as u16)
			});

		let shared_output_index = output
			.iter()
			.position(|txout| *txout == context.shared_funding_output.tx_out)
			.map(|position| position as u16)
			.unwrap_or(u16::MAX);

		let tx = ConstructedTransaction {
			holder_is_initiator: context.holder_is_initiator,
			input_metadata,
			output_metadata,
			tx: Transaction { version: Version::TWO, lock_time, input, output },
			shared_input_index,
			shared_output_index,
		};

		// The receiving node:
		// MUST fail the negotiation if:
		// - the peer's total input satoshis is less than their outputs
		if remote_inputs_value < remote_outputs_value {
			return Err(AbortReason::OutputsValueExceedsInputsValue);
		}

		// - the peer's paid feerate does not meet or exceed the agreed feerate (based on the minimum fee).
		let remote_fees_contributed = remote_inputs_value.saturating_sub(remote_outputs_value);
		let required_remote_contribution_fee = fee_for_weight(
			(context.feerate_sat_per_kw as u64 * REMOTE_FEE_TOLERANCE_PERCENT / 100) as u32,
			remote_weight_contributed,
		);
		if remote_fees_contributed < required_remote_contribution_fee {
			return Err(AbortReason::InsufficientFees);
		}

		// - there are more than 252 inputs
		// - there are more than 252 outputs
		if tx.tx.input.len() > MAX_INPUTS_OUTPUTS_COUNT
			|| tx.tx.output.len() > MAX_INPUTS_OUTPUTS_COUNT
		{
			return Err(AbortReason::ExceededNumberOfInputsOrOutputs);
		}

		if context.shared_funding_input.is_some() && tx.shared_input_index.is_none() {
			return Err(AbortReason::MissingFundingInput);
		}

		if tx.shared_output_index == u16::MAX {
			return Err(AbortReason::MissingFundingOutput);
		}

		let tx_weight = tx
			.tx
			.weight()
			.to_wu()
			.saturating_add(SEGWIT_MARKER_FLAG_WEIGHT)
			.saturating_add(expected_witness_weight);
		if tx_weight > MAX_STANDARD_TX_WEIGHT as u64 {
			return Err(AbortReason::TransactionTooLarge);
		}

		Ok(tx)
	}

	fn into_negotiation_error(self, reason: AbortReason) -> NegotiationError {
		let (contributed_inputs, contributed_outputs) = self.into_contributed_inputs_and_outputs();
		NegotiationError { reason, contributed_inputs, contributed_outputs }
	}

	fn to_contributed_inputs_and_outputs(&self) -> (Vec<BitcoinOutPoint>, Vec<TxOut>) {
		let contributed_inputs = self
			.tx
			.input
			.iter()
			.zip(self.input_metadata.iter())
			.enumerate()
			.filter(|(_, (_, input))| input.is_local(self.holder_is_initiator))
			.filter(|(index, _)| {
				self.shared_input_index
					.map(|shared_index| *index != shared_index as usize)
					.unwrap_or(true)
			})
			.map(|(_, (txin, _))| txin.previous_output)
			.collect();

		let contributed_outputs = self
			.tx
			.output
			.iter()
			.zip(self.output_metadata.iter())
			.enumerate()
			.filter(|(_, (_, output))| output.is_local(self.holder_is_initiator))
			.filter(|(index, _)| *index != self.shared_output_index as usize)
			.map(|(_, (txout, _))| txout.clone())
			.collect();

		(contributed_inputs, contributed_outputs)
	}

	fn into_contributed_inputs_and_outputs(self) -> (Vec<BitcoinOutPoint>, Vec<TxOut>) {
		let contributed_inputs = self
			.tx
			.input
			.into_iter()
			.zip(self.input_metadata.iter())
			.enumerate()
			.filter(|(_, (_, input))| input.is_local(self.holder_is_initiator))
			.filter(|(index, _)| {
				self.shared_input_index
					.map(|shared_index| *index != shared_index as usize)
					.unwrap_or(true)
			})
			.map(|(_, (txin, _))| txin.previous_output)
			.collect();

		let contributed_outputs = self
			.tx
			.output
			.into_iter()
			.zip(self.output_metadata.iter())
			.enumerate()
			.filter(|(_, (_, output))| output.is_local(self.holder_is_initiator))
			.filter(|(index, _)| *index != self.shared_output_index as usize)
			.map(|(_, (txout, _))| txout)
			.collect();

		(contributed_inputs, contributed_outputs)
	}

	pub fn tx(&self) -> &Transaction {
		&self.tx
	}

	fn input_metadata(&self) -> impl Iterator<Item = &TxInMetadata> {
		self.input_metadata.iter()
	}

	pub fn compute_txid(&self) -> Txid {
		self.tx().compute_txid()
	}

	fn funding_outpoint(&self) -> OutPoint {
		OutPoint { txid: self.compute_txid(), index: self.shared_output_index }
	}

	/// Returns the total input value from all local contributions, including the entire shared
	/// input value if applicable.
	fn local_contributed_input_value(&self) -> Amount {
		self.input_metadata
			.iter()
			.filter(|input| input.is_local(self.holder_is_initiator))
			.map(|input| input.prev_output.value)
			.sum()
	}

	/// Returns the total input value from all remote contributions, including the entire shared
	/// input value if applicable.
	fn remote_contributed_input_value(&self) -> Amount {
		self.input_metadata
			.iter()
			.filter(|input| !input.is_local(self.holder_is_initiator))
			.map(|input| input.prev_output.value)
			.sum()
	}

	fn finalize(
		&self, holder_tx_signatures: &TxSignatures, counterparty_tx_signatures: &TxSignatures,
		shared_input_sig: Option<&SharedInputSignature>,
	) -> Option<Transaction> {
		let mut tx = self.tx.clone();
		self.add_local_witnesses(&mut tx, holder_tx_signatures.witnesses.clone());
		self.add_remote_witnesses(&mut tx, counterparty_tx_signatures.witnesses.clone());

		if let Some(shared_input_index) = self.shared_input_index {
			let holder_shared_input_sig =
				holder_tx_signatures.shared_input_signature.or_else(|| {
					debug_assert!(false);
					None
				})?;
			let counterparty_shared_input_sig =
				counterparty_tx_signatures.shared_input_signature.or_else(|| {
					debug_assert!(false);
					None
				})?;

			let shared_input_sig = shared_input_sig.or_else(|| {
				debug_assert!(false);
				None
			})?;

			let mut witness = Witness::new();
			witness.push(Vec::new());
			let holder_sig = BitcoinSignature::sighash_all(holder_shared_input_sig);
			let counterparty_sig = BitcoinSignature::sighash_all(counterparty_shared_input_sig);
			if shared_input_sig.holder_signature_first {
				witness.push_ecdsa_signature(&holder_sig);
				witness.push_ecdsa_signature(&counterparty_sig);
			} else {
				witness.push_ecdsa_signature(&counterparty_sig);
				witness.push_ecdsa_signature(&holder_sig);
			}
			witness.push(&shared_input_sig.witness_script);
			tx.input[shared_input_index as usize].witness = witness;
		}

		Some(tx)
	}

	/// Adds provided holder witnesses to holder inputs of unsigned transaction.
	///
	/// Note that it is assumed that the witness count equals the holder input count.
	fn add_local_witnesses(&self, transaction: &mut Transaction, witnesses: Vec<Witness>) {
		transaction
			.input
			.iter_mut()
			.zip(self.input_metadata.iter())
			.enumerate()
			.filter(|(_, (_, input))| input.is_local(self.holder_is_initiator))
			.filter(|(index, _)| {
				self.shared_input_index
					.map(|shared_index| *index != shared_index as usize)
					.unwrap_or(true)
			})
			.map(|(_, (txin, _))| txin)
			.zip(witnesses)
			.for_each(|(input, witness)| input.witness = witness);
	}

	/// Adds counterparty witnesses to counterparty inputs of unsigned transaction.
	///
	/// Note that it is assumed that the witness count equals the counterparty input count.
	fn add_remote_witnesses(&self, transaction: &mut Transaction, witnesses: Vec<Witness>) {
		transaction
			.input
			.iter_mut()
			.zip(self.input_metadata.iter())
			.enumerate()
			.filter(|(_, (_, input))| !input.is_local(self.holder_is_initiator))
			.filter(|(index, _)| {
				self.shared_input_index
					.map(|shared_index| *index != shared_index as usize)
					.unwrap_or(true)
			})
			.map(|(_, (txin, _))| txin)
			.zip(witnesses)
			.for_each(|(input, witness)| input.witness = witness);
	}

	fn holder_is_initiator(&self) -> bool {
		self.holder_is_initiator
	}

	pub fn shared_input_index(&self) -> Option<u16> {
		self.shared_input_index
	}
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SharedInputSignature {
	holder_signature_first: bool,
	witness_script: ScriptBuf,
}

impl_writeable_tlv_based!(SharedInputSignature, {
	(1, holder_signature_first, required),
	(3, witness_script, required),
});

/// The InteractiveTxSigningSession coordinates the signing flow of interactively constructed
/// transactions from exhange of `commitment_signed` to ensuring proper ordering of `tx_signature`
/// message exchange.
///
/// See the specification for more details:
/// https://github.com/lightning/bolts/blob/master/02-peer-protocol.md#the-commitment_signed-message
/// https://github.com/lightning/bolts/blob/master/02-peer-protocol.md#sharing-funding-signatures-tx_signatures
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InteractiveTxSigningSession {
	unsigned_tx: ConstructedTransaction,
	holder_sends_tx_signatures_first: bool,
	has_received_commitment_signed: bool,
	shared_input_signature: Option<SharedInputSignature>,
	holder_tx_signatures: Option<TxSignatures>,
	counterparty_tx_signatures: Option<TxSignatures>,
}

impl InteractiveTxSigningSession {
	pub fn unsigned_tx(&self) -> &ConstructedTransaction {
		&self.unsigned_tx
	}

	pub fn holder_sends_tx_signatures_first(&self) -> bool {
		self.holder_sends_tx_signatures_first
	}

	pub fn has_received_commitment_signed(&self) -> bool {
		self.has_received_commitment_signed
	}

	pub fn has_received_tx_signatures(&self) -> bool {
		self.counterparty_tx_signatures.is_some()
	}

	pub fn holder_tx_signatures(&self) -> &Option<TxSignatures> {
		&self.holder_tx_signatures
	}

	pub fn received_commitment_signed(&mut self) {
		self.has_received_commitment_signed = true;
	}

	/// Handles a `tx_signatures` message received from the counterparty.
	///
	/// If the holder is required to send their `tx_signatures` message and these signatures have
	/// already been provided to the signing session, then this return value will be `Some`, otherwise
	/// None.
	///
	/// If the holder has already provided their `tx_signatures` to the signing session, a funding
	/// transaction will be finalized and returned as Some, otherwise None.
	///
	/// Returns an error if the witness count does not equal the counterparty's input count in the
	/// unsigned transaction or if the counterparty already provided their `tx_signatures`.
	pub fn received_tx_signatures(
		&mut self, tx_signatures: &TxSignatures,
	) -> Result<(Option<TxSignatures>, Option<Transaction>), String> {
		if self.has_received_tx_signatures() {
			return Err("Already received a tx_signatures message".to_string());
		}
		if self.remote_inputs_count() != tx_signatures.witnesses.len() {
			return Err("Witness count did not match contributed input count".to_string());
		}
		if self.shared_input().is_some() && tx_signatures.shared_input_signature.is_none() {
			return Err("Missing shared input signature".to_string());
		}
		if self.shared_input().is_none() && tx_signatures.shared_input_signature.is_some() {
			return Err("Unexpected shared input signature".to_string());
		}

		self.counterparty_tx_signatures = Some(tx_signatures.clone());

		let holder_tx_signatures = if !self.holder_sends_tx_signatures_first {
			self.holder_tx_signatures.clone()
		} else {
			None
		};

		let funding_tx_opt = self.maybe_finalize_funding_tx();

		Ok((holder_tx_signatures, funding_tx_opt))
	}

	/// Provides the holder witnesses for the unsigned transaction.
	///
	/// Returns an error if the witness count does not equal the holder's input count in the
	/// unsigned transaction.
	pub fn provide_holder_witnesses<C: bitcoin::secp256k1::Verification>(
		&mut self, tx_signatures: TxSignatures, secp_ctx: &Secp256k1<C>,
	) -> Result<(Option<TxSignatures>, Option<Transaction>), String> {
		if self.holder_tx_signatures.is_some() {
			return Err("Holder witnesses were already provided".to_string());
		}

		let local_inputs_count = self.local_inputs_count();
		if tx_signatures.witnesses.len() != local_inputs_count {
			return Err(format!(
				"Provided witness count of {} does not match required count for {} non-shared inputs",
				tx_signatures.witnesses.len(),
				local_inputs_count
			));
		}

		self.verify_interactive_tx_signatures(secp_ctx, &tx_signatures.witnesses)?;

		self.holder_tx_signatures = Some(tx_signatures);

		let funding_tx_opt = self.maybe_finalize_funding_tx();
		let holder_tx_signatures = (self.holder_sends_tx_signatures_first
			|| self.has_received_tx_signatures())
		.then(|| {
			debug_assert!(self.has_received_commitment_signed);
			self.holder_tx_signatures.clone().expect("Holder tx_signatures were just provided")
		});

		Ok((holder_tx_signatures, funding_tx_opt))
	}

	pub fn remote_inputs_count(&self) -> usize {
		let shared_index = self.unsigned_tx.shared_input_index.as_ref();
		self.unsigned_tx
			.input_metadata
			.iter()
			.enumerate()
			.filter(|(_, input)| !input.is_local(self.unsigned_tx.holder_is_initiator))
			.filter(|(index, _)| {
				shared_index.map(|shared_index| *index != *shared_index as usize).unwrap_or(true)
			})
			.count()
	}

	pub fn local_inputs_count(&self) -> usize {
		self.unsigned_tx
			.input_metadata
			.iter()
			.enumerate()
			.filter(|(_, input)| input.is_local(self.unsigned_tx.holder_is_initiator))
			.filter(|(index, _)| {
				self.unsigned_tx
					.shared_input_index
					.map(|shared_index| *index != shared_index as usize)
					.unwrap_or(true)
			})
			.count()
	}

	fn local_outputs_count(&self) -> usize {
		self.unsigned_tx
			.output_metadata
			.iter()
			.enumerate()
			.filter(|(_, output)| output.is_local(self.unsigned_tx.holder_is_initiator))
			.count()
	}

	pub fn has_local_contribution(&self) -> bool {
		self.local_inputs_count() > 0 || self.local_outputs_count() > 0
	}

	pub fn shared_input(&self) -> Option<&TxInMetadata> {
		self.unsigned_tx.shared_input_index.and_then(|shared_input_index| {
			self.unsigned_tx.input_metadata.get(shared_input_index as usize)
		})
	}

	fn maybe_finalize_funding_tx(&mut self) -> Option<Transaction> {
		let holder_tx_signatures = self.holder_tx_signatures.as_ref()?;
		let counterparty_tx_signatures = self.counterparty_tx_signatures.as_ref()?;
		let shared_input_signature = self.shared_input_signature.as_ref();
		self.unsigned_tx.finalize(
			holder_tx_signatures,
			counterparty_tx_signatures,
			shared_input_signature,
		)
	}

	fn verify_interactive_tx_signatures<C: bitcoin::secp256k1::Verification>(
		&self, secp_ctx: &Secp256k1<C>, witnesses: &Vec<Witness>,
	) -> Result<(), String> {
		let unsigned_tx = self.unsigned_tx();
		let built_tx = unsigned_tx.tx();
		let prev_outputs: Vec<&TxOut> =
			unsigned_tx.input_metadata().map(|input| input.prev_output()).collect::<Vec<_>>();
		let all_prevouts = sighash::Prevouts::All(&prev_outputs[..]);

		let mut cache = SighashCache::new(built_tx);

		let script_pubkeys = unsigned_tx
			.input_metadata()
			.enumerate()
			.filter(|(_, input)| input.is_local(unsigned_tx.holder_is_initiator()))
			.filter(|(index, _)| {
				unsigned_tx
					.shared_input_index
					.map(|shared_index| *index != shared_index as usize)
					.unwrap_or(true)
			});

		for ((input_idx, input), witness) in script_pubkeys.zip(witnesses) {
			if witness.is_empty() {
				let err = format!("The witness for input at index {input_idx} is empty");
				return Err(err);
			}

			let prev_output = input.prev_output();
			let script_pubkey = &prev_output.script_pubkey;

			// P2WPKH
			if script_pubkey.is_p2wpkh() {
				if witness.len() != 2 {
					let err = format!("The witness for input at index {input_idx} does not have the correct number of elements for a P2WPKH spend. Expected 2 got {}", witness.len());
					return Err(err);
				}
				let pubkey = PublicKey::from_slice(&witness[1]).map_err(|_| {
					format!("The witness for input at index {input_idx} contains an invalid ECDSA public key")
				})?;

				let sig =
					bitcoin::ecdsa::Signature::from_slice(&witness[0]).map_err(|_| {
						format!("The witness for input at index {input_idx} contains an invalid signature")
					})?;
				if !matches!(sig.sighash_type, EcdsaSighashType::All) {
					let err = format!("Signature does not use SIGHASH_ALL for input at index {input_idx} for P2WPKH spend");
					return Err(err);
				}

				let sighash = cache
					.p2wpkh_signature_hash(
						input_idx,
						script_pubkey,
						prev_output.value,
						EcdsaSighashType::All,
					)
					.map_err(|_| {
						debug_assert!(false, "Funding transaction sighash should be calculable");
						"The transaction sighash could not be calculated".to_string()
					})?;
				let msg = Message::from_digest_slice(&sighash[..])
					.expect("Sighash is a SHA256 which is 32 bytes long");
				secp_ctx.verify_ecdsa(&msg, &sig.signature, &pubkey).map_err(|_| {
					format!("Failed signature verification for input at index {input_idx} for P2WPKH spend")
				})?;

				continue;
			}

			// P2TR key path spend witness includes signature and optional annex
			if script_pubkey.is_p2tr() && witness.len() == 1 {
				let pubkey = match script_pubkey.instructions().nth(1) {
						Some(Ok(bitcoin::script::Instruction::PushBytes(push_bytes))) => {
							XOnlyPublicKey::from_slice(push_bytes.as_bytes())
						},
						_ => {
							let err = format!("The scriptPubKey of the previous output for input at index {input_idx} for a P2TR key path spend is invalid");
							return Err(err)
						},
					}.map_err(|_| {
						format!("The scriptPubKey of the previous output for input at index {input_idx} for a P2TR key path spend has an invalid public key")
					})?;

				let sig = bitcoin::taproot::Signature::from_slice(&witness[0]).map_err(|_| {
					format!("The witness for input at index {input_idx} for a P2TR key path spend has an invalid signature")
				})?;
				if !matches!(sig.sighash_type, TapSighashType::Default | TapSighashType::All) {
					let err = format!("Signature does not use SIGHASH_DEFAULT or SIGHASH_ALL for input at index {input_idx} for P2TR key path spend");
					return Err(err);
				}

				let sighash = cache
					.taproot_key_spend_signature_hash(input_idx, &all_prevouts, sig.sighash_type)
					.map_err(|_| {
						debug_assert!(false, "Funding transaction sighash should be calculable");
						"The transaction sighash could not be calculated".to_string()
					})?;
				let msg = Message::from_digest_slice(&sighash[..])
					.expect("Sighash is a SHA256 which is 32 bytes long");
				secp_ctx.verify_schnorr(&sig.signature, &msg, &pubkey).map_err(|_| {
					format!("Failed signature verification for input at index {input_idx} for P2TR key path spend")
				})?;

				continue;
			}

			// P2WSH - No validation just sighash checks
			if script_pubkey.is_p2wsh() {
				for element in witness {
					match element.len() {
						// Possibly a DER-encoded ECDSA signature with a sighash type byte assuming low-S
						70..=73 => {
							if !bitcoin::ecdsa::Signature::from_slice(element)
								.map(|sig| matches!(sig.sighash_type, EcdsaSighashType::All))
								.unwrap_or(true)
							{
								let err = format!("An ECDSA signature in the witness for input {input_idx} does not use SIGHASH_ALL");
								return Err(err);
							}
						},
						_ => (),
					}
				}
				continue;
			}

			// P2TR script path - No validation, just sighash checks
			if script_pubkey.is_p2tr() {
				for element in witness {
					match element.len() {
						// Schnorr sig + sighash type byte.
						// If this were just 64 bytes, it would implicitly be SIGHASH_DEFAULT (= SIGHASH_ALL)
						65 => {
							if !bitcoin::taproot::Signature::from_slice(element)
								.map(|sig| matches!(sig.sighash_type, TapSighashType::All))
								.unwrap_or(true)
							{
								let err = format!("A (likely) Schnorr signature in the witness for input {input_idx} does not use SIGHASH_DEFAULT or SIGHASH_ALL");
								return Err(err);
							}
						},
						_ => (),
					}
				}
				continue;
			}

			debug_assert!(
				false,
				"We don't allow contributing inputs that are not spending P2WPKH, P2WSH, or P2TR"
			);
			let err = format!(
				"Input at index {input_idx} does not spend from one of P2WPKH, P2WSH, or P2TR"
			);
			return Err(err);
		}

		Ok(())
	}

	pub(crate) fn into_negotiation_error(self, reason: AbortReason) -> NegotiationError {
		self.unsigned_tx.into_negotiation_error(reason)
	}

	pub(super) fn to_contributed_inputs_and_outputs(&self) -> (Vec<BitcoinOutPoint>, Vec<TxOut>) {
		self.unsigned_tx.to_contributed_inputs_and_outputs()
	}

	pub(super) fn into_contributed_inputs_and_outputs(self) -> (Vec<BitcoinOutPoint>, Vec<TxOut>) {
		self.unsigned_tx.into_contributed_inputs_and_outputs()
	}
}

impl_writeable_tlv_based!(InteractiveTxSigningSession, {
	(1, unsigned_tx, required),
	(3, has_received_commitment_signed, required),
	(5, holder_tx_signatures, required),
	(7, counterparty_tx_signatures, required),
	(9, holder_sends_tx_signatures_first, required),
	(11, shared_input_signature, required),
});

#[derive(Debug, Clone, PartialEq, Eq)]
struct NegotiationContext {
	holder_node_id: PublicKey,
	counterparty_node_id: PublicKey,
	holder_is_initiator: bool,
	received_tx_add_input_count: u16,
	received_tx_add_output_count: u16,
	inputs: HashMap<SerialId, InteractiveTxInput>,
	/// Optional intended/expected funding input, used during splicing.
	/// The funding input is shared, it is usually co-owned by both peers.
	/// - For the initiator:
	/// The intended previous funding input. This will be added alongside
	/// the provided inputs.
	/// - For the acceptor:
	/// The expected previous funding input. It should be added by the initiator node.
	shared_funding_input: Option<SharedOwnedInput>,
	/// The intended/expected funding output, potentially co-owned by both peers (shared).
	/// - For the initiator:
	/// The output intended to be the new funding output. This will be added alongside
	/// the provided outputs.
	/// - For the acceptor:
	/// The output expected as new funding output. It should be added by the initiator node.
	shared_funding_output: SharedOwnedOutput,
	prevtx_outpoints: HashSet<BitcoinOutPoint>,
	/// The outputs added so far.
	outputs: HashMap<SerialId, InteractiveTxOutput>,
	/// The locktime of the funding transaction.
	tx_locktime: AbsoluteLockTime,
	/// The fee rate used for the transaction
	feerate_sat_per_kw: u32,
}

fn estimate_input_satisfaction_weight(prev_output: &TxOut) -> Weight {
	Weight::from_wu(
		if prev_output.script_pubkey.is_p2wpkh() {
			P2WPKH_INPUT_WEIGHT_LOWER_BOUND
		} else if prev_output.script_pubkey.is_p2wsh() {
			P2WSH_INPUT_WEIGHT_LOWER_BOUND
		} else if prev_output.script_pubkey.is_p2tr() {
			P2TR_INPUT_WEIGHT_LOWER_BOUND
		} else {
			UNKNOWN_SEGWIT_VERSION_INPUT_WEIGHT_LOWER_BOUND
		} - BASE_INPUT_WEIGHT,
	)
}

pub(crate) fn get_output_weight(script_pubkey: &ScriptBuf) -> Weight {
	Weight::from_wu(
		(8 /* value */ + script_pubkey.consensus_encode(&mut sink()).unwrap() as u64)
			* WITNESS_SCALE_FACTOR as u64,
	)
}

fn is_serial_id_valid_for_counterparty(holder_is_initiator: bool, serial_id: SerialId) -> bool {
	// A received `SerialId`'s parity must match the role of the counterparty.
	holder_is_initiator == serial_id.is_for_non_initiator()
}

impl NegotiationContext {
	fn new(
		holder_node_id: PublicKey, counterparty_node_id: PublicKey, holder_is_initiator: bool,
		shared_funding_input: Option<SharedOwnedInput>, shared_funding_output: SharedOwnedOutput,
		tx_locktime: AbsoluteLockTime, feerate_sat_per_kw: u32,
	) -> Self {
		NegotiationContext {
			holder_node_id,
			counterparty_node_id,
			holder_is_initiator,
			received_tx_add_input_count: 0,
			received_tx_add_output_count: 0,
			inputs: new_hash_map(),
			shared_funding_input,
			shared_funding_output,
			prevtx_outpoints: new_hash_set(),
			outputs: new_hash_map(),
			tx_locktime,
			feerate_sat_per_kw,
		}
	}

	fn is_serial_id_valid_for_counterparty(&self, serial_id: &SerialId) -> bool {
		is_serial_id_valid_for_counterparty(self.holder_is_initiator, *serial_id)
	}

	fn remote_inputs_value(&self) -> u64 {
		self.inputs.iter().fold(0u64, |acc, (_, input)| acc.saturating_add(input.remote_value()))
	}

	fn remote_outputs_value(&self) -> u64 {
		self.outputs.iter().fold(0u64, |acc, (_, output)| acc.saturating_add(output.remote_value()))
	}

	fn remote_inputs_weight(&self) -> Weight {
		Weight::from_wu(
			self.inputs
				.iter()
				.filter(|(serial_id, _)| self.is_serial_id_valid_for_counterparty(serial_id))
				.fold(0u64, |weight, (_, input)| {
					weight
						.saturating_add(BASE_INPUT_WEIGHT)
						.saturating_add(input.satisfaction_weight().to_wu())
				}),
		)
	}

	fn remote_weight_contributed(&self) -> u64 {
		self.remote_inputs_weight()
			.to_wu()
			.saturating_add(self.remote_outputs_weight().to_wu())
			// The receiving node:
			// - MUST fail the negotiation if
			//   - if is the non-initiator:
			//     - the initiator's fees do not cover the common fields (version, segwit marker + flag,
			//       input count, output count, locktime)
			.saturating_add(if !self.holder_is_initiator { TX_COMMON_FIELDS_WEIGHT } else { 0 })
	}

	fn remote_outputs_weight(&self) -> Weight {
		Weight::from_wu(
			self.outputs
				.iter()
				.filter(|(serial_id, _)| self.is_serial_id_valid_for_counterparty(serial_id))
				.fold(0u64, |weight, (_, output)| {
					weight.saturating_add(get_output_weight(output.script_pubkey()).to_wu())
				}),
		)
	}

	fn local_inputs_value(&self) -> u64 {
		self.inputs.iter().fold(0u64, |acc, (_, input)| acc.saturating_add(input.value()))
	}

	fn received_tx_add_input(&mut self, msg: &msgs::TxAddInput) -> Result<(), AbortReason> {
		// The interactive-txs spec calls for us to fail negotiation if the `prevtx` we receive is
		// invalid. However, we would not need to account for this explicit negotiation failure
		// mode here since `PeerManager` would already disconnect the peer if the `prevtx` is
		// invalid; implicitly ending the negotiation.

		if !self.is_serial_id_valid_for_counterparty(&msg.serial_id) {
			// The receiving node:
			//  - MUST fail the negotiation if:
			//     - the `serial_id` has the wrong parity
			return Err(AbortReason::IncorrectSerialIdParity);
		}

		self.received_tx_add_input_count += 1;
		if self.received_tx_add_input_count > MAX_RECEIVED_TX_ADD_INPUT_COUNT {
			// The receiving node:
			//  - MUST fail the negotiation if:
			//     - if has received 4096 `tx_add_input` messages during this negotiation
			return Err(AbortReason::ReceivedTooManyTxAddInputs);
		}

		if msg.sequence >= 0xFFFFFFFE {
			// The receiving node:
			//  - MUST fail the negotiation if:
			//    - `sequence` is set to `0xFFFFFFFE` or `0xFFFFFFFF`
			return Err(AbortReason::IncorrectInputSequenceValue);
		}

		// Extract info from msg, check if shared
		let (input, prev_outpoint) = if let Some(shared_txid) = &msg.shared_input_txid {
			if self.holder_is_initiator {
				return Err(AbortReason::DuplicateFundingInput);
			}
			if msg.prevtx.is_some() {
				return Err(AbortReason::UnexpectedPrevTx);
			}
			if let Some(shared_funding_input) = &self.shared_funding_input {
				if self.inputs.values().any(|input| matches!(input.input, InputOwned::Shared(_))) {
					return Err(AbortReason::DuplicateFundingInput);
				}

				let previous_output = BitcoinOutPoint { txid: *shared_txid, vout: msg.prevtx_out };
				if previous_output != shared_funding_input.input.previous_output {
					return Err(AbortReason::UnexpectedFundingInput);
				}

				(InputOwned::Shared(shared_funding_input.clone()), previous_output)
			} else {
				return Err(AbortReason::UnexpectedFundingInput);
			}
		} else if let Some(prevtx) = &msg.prevtx {
			let txid = prevtx.compute_txid();

			if let Some(tx_out) = prevtx.output.get(msg.prevtx_out as usize) {
				if !tx_out.script_pubkey.is_witness_program() {
					// The receiving node:
					//  - MUST fail the negotiation if:
					//     - the `scriptPubKey` is not a witness program
					return Err(AbortReason::PrevTxOutInvalid);
				}

				let prev_outpoint = BitcoinOutPoint { txid, vout: msg.prevtx_out };
				let txin = TxIn {
					previous_output: prev_outpoint,
					sequence: Sequence(msg.sequence),
					..Default::default()
				};
				(
					InputOwned::Single(SingleOwnedInput {
						input: txin,
						prev_tx: prevtx.clone(),
						prev_output: tx_out.clone(),
						satisfaction_weight: estimate_input_satisfaction_weight(&tx_out),
					}),
					prev_outpoint,
				)
			} else {
				// The receiving node:
				//  - MUST fail the negotiation if:
				//     - `prevtx_vout` is greater or equal to the number of outputs on `prevtx`
				return Err(AbortReason::PrevTxOutInvalid);
			}
		} else {
			return Err(AbortReason::MissingPrevTx);
		};

		match self.inputs.entry(msg.serial_id) {
			hash_map::Entry::Occupied(_) => {
				// The receiving node:
				//  - MUST fail the negotiation if:
				//    - the `serial_id` is already included in the transaction
				Err(AbortReason::DuplicateSerialId)
			},
			hash_map::Entry::Vacant(entry) => {
				if !self.prevtx_outpoints.insert(prev_outpoint) {
					// The receiving node:
					//  - MUST fail the negotiation if:
					//     - the `prevtx` and `prevtx_vout` are identical to a previously added
					//       (and not removed) input's
					return Err(AbortReason::PrevTxOutInvalid);
				}
				entry.insert(InteractiveTxInput {
					serial_id: msg.serial_id,
					added_by: AddingRole::Remote,
					input,
				});
				Ok(())
			},
		}
	}

	fn received_tx_remove_input(&mut self, msg: &msgs::TxRemoveInput) -> Result<(), AbortReason> {
		if !self.is_serial_id_valid_for_counterparty(&msg.serial_id) {
			return Err(AbortReason::IncorrectSerialIdParity);
		}

		self.inputs
			.remove(&msg.serial_id)
			// The receiving node:
			//  - MUST fail the negotiation if:
			//    - the input or output identified by the `serial_id` was not added by the sender
			//    - the `serial_id` does not correspond to a currently added input
			.ok_or(AbortReason::SerialIdUnknown)
			.map(|_| ())
	}

	fn received_tx_add_output(&mut self, msg: &msgs::TxAddOutput) -> Result<(), AbortReason> {
		// The receiving node:
		//  - MUST fail the negotiation if:
		//     - the serial_id has the wrong parity
		if !self.is_serial_id_valid_for_counterparty(&msg.serial_id) {
			return Err(AbortReason::IncorrectSerialIdParity);
		}

		self.received_tx_add_output_count += 1;
		if self.received_tx_add_output_count > MAX_RECEIVED_TX_ADD_OUTPUT_COUNT {
			// The receiving node:
			//  - MUST fail the negotiation if:
			//     - if has received 4096 `tx_add_output` messages during this negotiation
			return Err(AbortReason::ReceivedTooManyTxAddOutputs);
		}

		if msg.sats < msg.script.minimal_non_dust().to_sat() {
			// The receiving node:
			// - MUST fail the negotiation if:
			//		- the sats amount is less than the dust_limit
			return Err(AbortReason::BelowDustLimit);
		}

		// Check that adding this output would not cause the total output value to exceed the total
		// bitcoin supply.
		let mut outputs_value: u64 = 0;
		for output in self.outputs.iter() {
			outputs_value = outputs_value.saturating_add(output.1.value());
		}
		if outputs_value.saturating_add(msg.sats) > TOTAL_BITCOIN_SUPPLY_SATOSHIS {
			// The receiving node:
			// - MUST fail the negotiation if:
			//		- the sats amount is greater than 2,100,000,000,000,000 (TOTAL_BITCOIN_SUPPLY_SATOSHIS)
			return Err(AbortReason::ExceededMaximumSatsAllowed);
		}

		// The receiving node:
		//   - MUST accept P2WSH, P2WPKH, P2TR scripts
		//   - MAY fail the negotiation if script is non-standard
		//
		// We can actually be a bit looser than the above as only witness version 0 has special
		// length-based standardness constraints to match similar consensus rules. All witness scripts
		// with witness versions V1 and up are always considered standard. Yes, the scripts can be
		// anyone-can-spend-able, but if our counterparty wants to add an output like that then it's none
		// of our concern really ¯\_(ツ)_/¯
		//
		// TODO: The last check would be simplified when https://github.com/rust-bitcoin/rust-bitcoin/commit/1656e1a09a1959230e20af90d20789a4a8f0a31b
		// hits the next release of rust-bitcoin.
		if !(msg.script.is_p2wpkh()
			|| msg.script.is_p2wsh()
			|| (msg.script.is_witness_program()
				&& msg.script.witness_version().map(|v| v.to_num() >= 1).unwrap_or(false)))
		{
			return Err(AbortReason::InvalidOutputScript);
		}

		let txout = TxOut { value: Amount::from_sat(msg.sats), script_pubkey: msg.script.clone() };
		let output = if txout == self.shared_funding_output.tx_out {
			if self.holder_is_initiator {
				return Err(AbortReason::DuplicateFundingOutput);
			}
			if self.outputs.values().any(|output| matches!(output.output, OutputOwned::Shared(_))) {
				return Err(AbortReason::DuplicateFundingOutput);
			}
			OutputOwned::Shared(self.shared_funding_output.clone())
		} else {
			OutputOwned::Single(txout)
		};
		let output =
			InteractiveTxOutput { serial_id: msg.serial_id, added_by: AddingRole::Remote, output };
		match self.outputs.entry(msg.serial_id) {
			hash_map::Entry::Occupied(_) => {
				// The receiving node:
				//  - MUST fail the negotiation if:
				//    - the `serial_id` is already included in the transaction
				Err(AbortReason::DuplicateSerialId)
			},
			hash_map::Entry::Vacant(entry) => {
				entry.insert(output);
				Ok(())
			},
		}
	}

	fn received_tx_remove_output(&mut self, msg: &msgs::TxRemoveOutput) -> Result<(), AbortReason> {
		if !self.is_serial_id_valid_for_counterparty(&msg.serial_id) {
			return Err(AbortReason::IncorrectSerialIdParity);
		}
		if self.outputs.remove(&msg.serial_id).is_some() {
			Ok(())
		} else {
			// The receiving node:
			//  - MUST fail the negotiation if:
			//    - the input or output identified by the `serial_id` was not added by the sender
			//    - the `serial_id` does not correspond to a currently added input
			Err(AbortReason::SerialIdUnknown)
		}
	}

	fn sent_tx_add_input(
		&mut self, (msg, satisfaction_weight): (&msgs::TxAddInput, Weight),
	) -> Result<(), AbortReason> {
		let vout = msg.prevtx_out as usize;
		let (prev_outpoint, input) = if let Some(shared_input_txid) = msg.shared_input_txid {
			let prev_outpoint = BitcoinOutPoint { txid: shared_input_txid, vout: msg.prevtx_out };
			if let Some(shared_funding_input) = &self.shared_funding_input {
				(prev_outpoint, InputOwned::Shared(shared_funding_input.clone()))
			} else {
				return Err(AbortReason::UnexpectedFundingInput);
			}
		} else if let Some(prevtx) = &msg.prevtx {
			let prev_txid = prevtx.compute_txid();
			let prev_outpoint = BitcoinOutPoint { txid: prev_txid, vout: msg.prevtx_out };
			let prev_output = prevtx.output.get(vout).ok_or(AbortReason::PrevTxOutInvalid)?.clone();
			let txin = TxIn {
				previous_output: prev_outpoint,
				sequence: Sequence(msg.sequence),
				..Default::default()
			};
			let single_input = SingleOwnedInput {
				input: txin,
				prev_tx: prevtx.clone(),
				prev_output,
				satisfaction_weight,
			};
			(prev_outpoint, InputOwned::Single(single_input))
		} else {
			return Err(AbortReason::MissingPrevTx);
		};
		if !self.prevtx_outpoints.insert(prev_outpoint) {
			// We have added an input that already exists
			return Err(AbortReason::PrevTxOutInvalid);
		}
		let input =
			InteractiveTxInput { serial_id: msg.serial_id, added_by: AddingRole::Local, input };
		self.inputs.insert(msg.serial_id, input);
		Ok(())
	}

	fn sent_tx_add_output(&mut self, msg: &msgs::TxAddOutput) -> Result<(), AbortReason> {
		let txout = TxOut { value: Amount::from_sat(msg.sats), script_pubkey: msg.script.clone() };
		let output = if txout == self.shared_funding_output.tx_out {
			OutputOwned::Shared(self.shared_funding_output.clone())
		} else {
			OutputOwned::Single(txout)
		};
		let output =
			InteractiveTxOutput { serial_id: msg.serial_id, added_by: AddingRole::Local, output };
		self.outputs.insert(msg.serial_id, output);
		Ok(())
	}

	fn sent_tx_remove_input(&mut self, msg: &msgs::TxRemoveInput) -> Result<(), AbortReason> {
		self.inputs.remove(&msg.serial_id);
		Ok(())
	}

	fn sent_tx_remove_output(&mut self, msg: &msgs::TxRemoveOutput) -> Result<(), AbortReason> {
		self.outputs.remove(&msg.serial_id);
		Ok(())
	}
}

// The interactive transaction construction protocol allows two peers to collaboratively build a
// transaction for broadcast.
//
// The protocol is turn-based, so we define different states here that we store depending on whose
// turn it is to send the next message. The states are defined so that their types ensure we only
// perform actions (only send messages) via defined state transitions that do not violate the
// protocol.
//
// An example of a full negotiation and associated states follows:
//
//     +------------+                         +------------------+---- Holder state after message sent/received ----+
//     |            |--(1)- tx_add_input ---->|                  |                  SentChangeMsg                   +
//     |            |<-(2)- tx_complete ------|                  |                ReceivedTxComplete                +
//     |            |--(3)- tx_add_output --->|                  |                  SentChangeMsg                   +
//     |            |<-(4)- tx_complete ------|                  |                ReceivedTxComplete                +
//     |            |--(5)- tx_add_input ---->|                  |                  SentChangeMsg                   +
//     |   Holder   |<-(6)- tx_add_input -----|   Counterparty   |                ReceivedChangeMsg                 +
//     |            |--(7)- tx_remove_output >|                  |                  SentChangeMsg                   +
//     |            |<-(8)- tx_add_output ----|                  |                ReceivedChangeMsg                 +
//     |            |--(9)- tx_complete ----->|                  |                  SentTxComplete                  +
//     |            |<-(10) tx_complete ------|                  |                NegotiationComplete               +
//     +------------+                         +------------------+--------------------------------------------------+

/// Negotiation states that can send & receive `tx_(add|remove)_(input|output)` and `tx_complete`
trait State {}

/// Category of states where we have sent some message to the counterparty, and we are waiting for
/// a response.
trait SentMsgState: State {
	fn into_negotiation_context(self) -> NegotiationContext;
}

/// Category of states that our counterparty has put us in after we receive a message from them.
trait ReceivedMsgState: State {
	fn into_negotiation_context(self) -> NegotiationContext;
}

// This macro is a helper for implementing the above state traits for various states subsequently
// defined below the macro.
macro_rules! define_state {
	(SENT_MSG_STATE, $state: ident, $doc: expr) => {
		define_state!($state, NegotiationContext, $doc);
		impl SentMsgState for $state {
			fn into_negotiation_context(self) -> NegotiationContext {
				self.0
			}
		}
	};
	(RECEIVED_MSG_STATE, $state: ident, $doc: expr) => {
		define_state!($state, NegotiationContext, $doc);
		impl ReceivedMsgState for $state {
			fn into_negotiation_context(self) -> NegotiationContext {
				self.0
			}
		}
	};
	($state: ident, $inner: ident, $doc: expr) => {
		#[doc = $doc]
		#[derive(Debug, Clone, PartialEq, Eq)]
		struct $state($inner);
		impl State for $state {}
	};
}

define_state!(
	SENT_MSG_STATE,
	SentChangeMsg,
	"We have sent a message to the counterparty that has affected our negotiation state."
);
define_state!(
	SENT_MSG_STATE,
	SentTxComplete,
	"We have sent a `tx_complete` message and are awaiting the counterparty's."
);
define_state!(
	RECEIVED_MSG_STATE,
	ReceivedChangeMsg,
	"We have received a message from the counterparty that has affected our negotiation state."
);
define_state!(
	RECEIVED_MSG_STATE,
	ReceivedTxComplete,
	"We have received a `tx_complete` message and the counterparty is awaiting ours."
);
define_state!(NegotiationComplete, InteractiveTxSigningSession, "We have exchanged consecutive `tx_complete` messages with the counterparty and the transaction negotiation is complete.");
define_state!(
	NegotiationAborted,
	AbortReason,
	"The negotiation has failed and cannot be continued."
);

type StateTransitionResult<S> = Result<S, AbortReason>;

trait StateTransition<NewState: State, TransitionData> {
	fn transition(self, data: TransitionData) -> StateTransitionResult<NewState>;
}

// This macro helps define the legal transitions between the states above by implementing
// the `StateTransition` trait for each of the states that follow this declaration.
macro_rules! define_state_transitions {
	(SENT_MSG_STATE, [$(DATA $data: ty, TRANSITION $transition: ident),+]) => {
		$(
			impl<S: SentMsgState> StateTransition<ReceivedChangeMsg, $data> for S {
				fn transition(self, data: $data) -> StateTransitionResult<ReceivedChangeMsg> {
					let mut context = self.into_negotiation_context();
					context.$transition(data)?;
					Ok(ReceivedChangeMsg(context))
				}
			}
		 )*
	};
	(RECEIVED_MSG_STATE, [$(DATA $data: ty, TRANSITION $transition: ident),+]) => {
		$(
			impl<S: ReceivedMsgState> StateTransition<SentChangeMsg, $data> for S {
				fn transition(self, data: $data) -> StateTransitionResult<SentChangeMsg> {
					let mut context = self.into_negotiation_context();
					context.$transition(data)?;
					Ok(SentChangeMsg(context))
				}
			}
		 )*
	};
	(TX_COMPLETE, $from_state: ident, $tx_complete_state: ident) => {
		impl StateTransition<NegotiationComplete, &msgs::TxComplete> for $tx_complete_state {
			fn transition(self, _data: &msgs::TxComplete) -> StateTransitionResult<NegotiationComplete> {
				let context = self.into_negotiation_context();
				let shared_input_signature = context
					.shared_funding_input
					.as_ref()
					.map(|shared_input| SharedInputSignature {
						holder_signature_first: shared_input.holder_sig_first,
						witness_script: shared_input.witness_script.clone(),
					});
				let holder_node_id = context.holder_node_id;
				let counterparty_node_id = context.counterparty_node_id;

				let tx = ConstructedTransaction::new(context)?;

				// Strict ordering prevents deadlocks during tx_signatures exchange
				let local_contributed_input_value = tx.local_contributed_input_value();
				let remote_contributed_input_value = tx.remote_contributed_input_value();
				let holder_sends_tx_signatures_first =
					if local_contributed_input_value == remote_contributed_input_value {
						holder_node_id.serialize() < counterparty_node_id.serialize()
					} else {
						local_contributed_input_value < remote_contributed_input_value
					};

				let signing_session = InteractiveTxSigningSession {
					unsigned_tx: tx,
					holder_sends_tx_signatures_first,
					has_received_commitment_signed: false,
					shared_input_signature,
					holder_tx_signatures: None,
					counterparty_tx_signatures: None,
				};
				Ok(NegotiationComplete(signing_session))
			}
		}

		impl StateTransition<$tx_complete_state, &msgs::TxComplete> for $from_state {
			fn transition(self, _data: &msgs::TxComplete) -> StateTransitionResult<$tx_complete_state> {
				Ok($tx_complete_state(self.into_negotiation_context()))
			}
		}
	};
}

// State transitions when we have sent our counterparty some messages and are waiting for them
// to respond.
define_state_transitions!(SENT_MSG_STATE, [
	DATA &msgs::TxAddInput, TRANSITION received_tx_add_input,
	DATA &msgs::TxRemoveInput, TRANSITION received_tx_remove_input,
	DATA &msgs::TxAddOutput, TRANSITION received_tx_add_output,
	DATA &msgs::TxRemoveOutput, TRANSITION received_tx_remove_output
]);
// State transitions when we have received some messages from our counterparty and we should
// respond.
define_state_transitions!(RECEIVED_MSG_STATE, [
	DATA (&msgs::TxAddInput, Weight), TRANSITION sent_tx_add_input,
	DATA &msgs::TxRemoveInput, TRANSITION sent_tx_remove_input,
	DATA &msgs::TxAddOutput, TRANSITION sent_tx_add_output,
	DATA &msgs::TxRemoveOutput, TRANSITION sent_tx_remove_output
]);
define_state_transitions!(TX_COMPLETE, SentChangeMsg, ReceivedTxComplete);
define_state_transitions!(TX_COMPLETE, ReceivedChangeMsg, SentTxComplete);

#[derive(Debug, Clone, PartialEq, Eq)]
enum StateMachine {
	Indeterminate,
	SentChangeMsg(SentChangeMsg),
	ReceivedChangeMsg(ReceivedChangeMsg),
	SentTxComplete(SentTxComplete),
	ReceivedTxComplete(ReceivedTxComplete),
	NegotiationComplete(NegotiationComplete),
	NegotiationAborted(NegotiationAborted),
}

// The `StateMachine` internally executes the actual transition between two states and keeps
// track of the current state. This macro defines _how_ those state transitions happen to
// update the internal state.
macro_rules! define_state_machine_transitions {
	($transition: ident, $msg: ty, [$(FROM $from_state: ident, TO $to_state: ident),+]) => {
		fn $transition(self, msg: $msg) -> StateMachine {
			match self {
				$(
					Self::$from_state(s) => match s.transition(msg) {
						Ok(new_state) => StateMachine::$to_state(new_state),
						Err(abort_reason) => StateMachine::NegotiationAborted(NegotiationAborted(abort_reason)),
					}
				 )*
				_ => StateMachine::NegotiationAborted(NegotiationAborted(AbortReason::UnexpectedCounterpartyMessage)),
			}
		}
	};
}

impl StateMachine {
	fn new(
		holder_node_id: PublicKey, counterparty_node_id: PublicKey, feerate_sat_per_kw: u32,
		is_initiator: bool, tx_locktime: AbsoluteLockTime,
		shared_funding_input: Option<SharedOwnedInput>, shared_funding_output: SharedOwnedOutput,
	) -> Self {
		let context = NegotiationContext::new(
			holder_node_id,
			counterparty_node_id,
			is_initiator,
			shared_funding_input,
			shared_funding_output,
			tx_locktime,
			feerate_sat_per_kw,
		);
		if is_initiator {
			Self::ReceivedChangeMsg(ReceivedChangeMsg(context))
		} else {
			Self::SentChangeMsg(SentChangeMsg(context))
		}
	}

	// TxAddInput
	define_state_machine_transitions!(sent_tx_add_input, (&msgs::TxAddInput, Weight), [
		FROM ReceivedChangeMsg, TO SentChangeMsg,
		FROM ReceivedTxComplete, TO SentChangeMsg
	]);
	define_state_machine_transitions!(received_tx_add_input, &msgs::TxAddInput, [
		FROM SentChangeMsg, TO ReceivedChangeMsg,
		FROM SentTxComplete, TO ReceivedChangeMsg
	]);

	// TxAddOutput
	define_state_machine_transitions!(sent_tx_add_output, &msgs::TxAddOutput, [
		FROM ReceivedChangeMsg, TO SentChangeMsg,
		FROM ReceivedTxComplete, TO SentChangeMsg
	]);
	define_state_machine_transitions!(received_tx_add_output, &msgs::TxAddOutput, [
		FROM SentChangeMsg, TO ReceivedChangeMsg,
		FROM SentTxComplete, TO ReceivedChangeMsg
	]);

	// TxRemoveInput
	define_state_machine_transitions!(sent_tx_remove_input, &msgs::TxRemoveInput, [
		FROM ReceivedChangeMsg, TO SentChangeMsg,
		FROM ReceivedTxComplete, TO SentChangeMsg
	]);
	define_state_machine_transitions!(received_tx_remove_input, &msgs::TxRemoveInput, [
		FROM SentChangeMsg, TO ReceivedChangeMsg,
		FROM SentTxComplete, TO ReceivedChangeMsg
	]);

	// TxRemoveOutput
	define_state_machine_transitions!(sent_tx_remove_output, &msgs::TxRemoveOutput, [
		FROM ReceivedChangeMsg, TO SentChangeMsg,
		FROM ReceivedTxComplete, TO SentChangeMsg
	]);
	define_state_machine_transitions!(received_tx_remove_output, &msgs::TxRemoveOutput, [
		FROM SentChangeMsg, TO ReceivedChangeMsg,
		FROM SentTxComplete, TO ReceivedChangeMsg
	]);

	// TxComplete
	define_state_machine_transitions!(sent_tx_complete, &msgs::TxComplete, [
		FROM ReceivedChangeMsg, TO SentTxComplete,
		FROM ReceivedTxComplete, TO NegotiationComplete
	]);
	define_state_machine_transitions!(received_tx_complete, &msgs::TxComplete, [
		FROM SentChangeMsg, TO ReceivedTxComplete,
		FROM SentTxComplete, TO NegotiationComplete
	]);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AddingRole {
	Local,
	Remote,
}

impl_writeable_tlv_based_enum!(AddingRole,
	(1, Local) => {},
	(3, Remote) => {},
);

/// Represents an input -- local or remote (both have the same fields)
#[derive(Clone, Debug, Eq, PartialEq)]
struct SingleOwnedInput {
	input: TxIn,
	prev_tx: Transaction,
	prev_output: TxOut,
	satisfaction_weight: Weight,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct SharedOwnedInput {
	input: TxIn,
	prev_output: TxOut,
	local_owned: u64,
	holder_sig_first: bool,
	witness_script: ScriptBuf,
}

impl SharedOwnedInput {
	pub fn new(
		input: TxIn, prev_output: TxOut, local_owned: u64, holder_sig_first: bool,
		witness_script: ScriptBuf,
	) -> Self {
		let value = prev_output.value.to_sat();
		debug_assert!(
			local_owned <= value,
			"SharedOwnedInput: Inconsistent local_owned value {}, larger than prev out value {}",
			local_owned,
			value,
		);
		Self { input, prev_output, local_owned, holder_sig_first, witness_script }
	}

	fn remote_owned(&self) -> u64 {
		self.prev_output.value.to_sat().saturating_sub(self.local_owned)
	}
}

/// A transaction input, differentiated by ownership:
/// - exclusive by the adder, or
/// - shared
#[derive(Clone, Debug, Eq, PartialEq)]
enum InputOwned {
	/// Belongs to a single party -- controlled exclusively and fully belonging to a single party
	/// Includes the input and the previous output
	Single(SingleOwnedInput),
	/// Input with shared control and value split between the counterparties (or fully by one).
	Shared(SharedOwnedInput),
}

impl InputOwned {
	pub fn tx_in(&self) -> &TxIn {
		match &self {
			InputOwned::Single(single) => &single.input,
			InputOwned::Shared(shared) => &shared.input,
		}
	}

	pub fn tx_in_mut(&mut self) -> &mut TxIn {
		match self {
			InputOwned::Single(ref mut single) => &mut single.input,
			InputOwned::Shared(shared) => &mut shared.input,
		}
	}

	fn into_tx_in(self) -> TxIn {
		match self {
			InputOwned::Single(single) => single.input,
			InputOwned::Shared(shared) => shared.input,
		}
	}

	pub fn value(&self) -> u64 {
		match self {
			InputOwned::Single(single) => single.prev_output.value.to_sat(),
			InputOwned::Shared(shared) => shared.prev_output.value.to_sat(),
		}
	}

	fn is_shared(&self) -> bool {
		match self {
			InputOwned::Single(_) => false,
			InputOwned::Shared(_) => true,
		}
	}

	fn local_value(&self, local_role: AddingRole) -> u64 {
		match self {
			InputOwned::Single(single) => match local_role {
				AddingRole::Local => single.prev_output.value.to_sat(),
				AddingRole::Remote => 0,
			},
			InputOwned::Shared(shared) => shared.local_owned,
		}
	}

	fn remote_value(&self, local_role: AddingRole) -> u64 {
		match self {
			InputOwned::Single(single) => match local_role {
				AddingRole::Local => 0,
				AddingRole::Remote => single.prev_output.value.to_sat(),
			},
			InputOwned::Shared(shared) => shared.remote_owned(),
		}
	}

	fn satisfaction_weight(&self) -> Weight {
		match self {
			InputOwned::Single(single) => single.satisfaction_weight,
			// TODO(taproot): Needs to consider different weights based on channel type
			InputOwned::Shared(_) => {
				let mut weight = 0;
				weight += EMPTY_SCRIPT_SIG_WEIGHT + FUNDING_TRANSACTION_WITNESS_WEIGHT;
				#[cfg(feature = "grind_signatures")]
				{
					// Guarantees a low R signature
					weight -= 1;
				}

				Weight::from_wu(weight)
			},
		}
	}

	fn into_tx_in_with_prev_output(self) -> (TxIn, TxOut) {
		match self {
			InputOwned::Single(single) => (single.input, single.prev_output),
			InputOwned::Shared(shared) => (shared.input, shared.prev_output),
		}
	}
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct InteractiveTxInput {
	serial_id: SerialId,
	added_by: AddingRole,
	input: InputOwned,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct SharedOwnedOutput {
	tx_out: TxOut,
	local_owned: u64,
}

impl_writeable_tlv_based!(SharedOwnedOutput, {
	(1, tx_out, required),
	(3, local_owned, required),
});

impl SharedOwnedOutput {
	pub fn new(tx_out: TxOut, local_owned: u64) -> Self {
		debug_assert!(
			local_owned <= tx_out.value.to_sat(),
			"SharedOwnedOutput: Inconsistent local_owned value {}, larger than output value {}",
			local_owned,
			tx_out.value.to_sat(),
		);
		Self { tx_out, local_owned }
	}

	fn remote_owned(&self) -> u64 {
		self.tx_out.value.to_sat().saturating_sub(self.local_owned)
	}
}

/// A transaction output, differentiated by ownership: exclusive by the adder or shared.
#[derive(Clone, Debug, Eq, PartialEq)]
enum OutputOwned {
	/// Belongs to a single party -- controlled exclusively and fully belonging to a single party
	Single(TxOut),
	/// Output with shared control and value split between the two ends (or fully at one side)
	Shared(SharedOwnedOutput),
}

impl_writeable_tlv_based_enum!(OutputOwned,
	{1, Single} => (),
	{3, Shared} => (),
);

impl OutputOwned {
	pub fn tx_out(&self) -> &TxOut {
		match self {
			OutputOwned::Single(tx_out) => tx_out,
			OutputOwned::Shared(output) => &output.tx_out,
		}
	}

	fn into_tx_out(self) -> TxOut {
		match self {
			OutputOwned::Single(tx_out) => tx_out,
			OutputOwned::Shared(output) => output.tx_out,
		}
	}

	fn value(&self) -> u64 {
		self.tx_out().value.to_sat()
	}

	fn is_shared(&self) -> bool {
		match self {
			OutputOwned::Single(_) => false,
			OutputOwned::Shared(_) => true,
		}
	}

	fn local_value(&self, local_role: AddingRole) -> u64 {
		match self {
			OutputOwned::Single(tx_out) => match local_role {
				AddingRole::Local => tx_out.value.to_sat(),
				AddingRole::Remote => 0,
			},
			OutputOwned::Shared(output) => output.local_owned,
		}
	}

	fn remote_value(&self, local_role: AddingRole) -> u64 {
		match self {
			OutputOwned::Single(tx_out) => match local_role {
				AddingRole::Local => 0,
				AddingRole::Remote => tx_out.value.to_sat(),
			},
			OutputOwned::Shared(output) => output.remote_owned(),
		}
	}
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct InteractiveTxOutput {
	serial_id: SerialId,
	added_by: AddingRole,
	output: OutputOwned,
}

impl InteractiveTxOutput {
	pub fn tx_out(&self) -> &TxOut {
		self.output.tx_out()
	}

	pub fn into_tx_out(self) -> TxOut {
		self.output.into_tx_out()
	}

	pub fn value(&self) -> u64 {
		self.tx_out().value.to_sat()
	}

	pub fn local_value(&self) -> u64 {
		self.output.local_value(self.added_by)
	}

	pub fn remote_value(&self) -> u64 {
		self.output.remote_value(self.added_by)
	}

	pub fn script_pubkey(&self) -> &ScriptBuf {
		&self.output.tx_out().script_pubkey
	}

	fn into_txout_and_metadata(self) -> (TxOut, TxOutMetadata) {
		let txout = self.output.into_tx_out();
		(txout, TxOutMetadata { serial_id: self.serial_id })
	}
}

impl InteractiveTxInput {
	pub fn serial_id(&self) -> SerialId {
		self.serial_id
	}

	pub fn txin(&self) -> &TxIn {
		self.input.tx_in()
	}

	pub fn txin_mut(&mut self) -> &mut TxIn {
		self.input.tx_in_mut()
	}

	pub fn value(&self) -> u64 {
		self.input.value()
	}

	pub fn local_value(&self) -> u64 {
		self.input.local_value(self.added_by)
	}

	pub fn remote_value(&self) -> u64 {
		self.input.remote_value(self.added_by)
	}

	pub fn satisfaction_weight(&self) -> Weight {
		self.input.satisfaction_weight()
	}

	fn into_txin_and_metadata(self) -> (TxIn, TxInMetadata) {
		let (txin, prev_output) = self.input.into_tx_in_with_prev_output();
		(txin, TxInMetadata { serial_id: self.serial_id, prev_output })
	}
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct InteractiveTxConstructor {
	state_machine: StateMachine,
	is_initiator: bool,
	initiator_first_message: Option<InteractiveTxMessageSend>,
	channel_id: ChannelId,
	inputs_to_contribute: Vec<(SerialId, InputOwned)>,
	outputs_to_contribute: Vec<(SerialId, OutputOwned)>,
	next_input_index: Option<usize>,
	next_output_index: Option<usize>,
}

#[allow(clippy::enum_variant_names)] // Clippy doesn't like the repeated `Tx` prefix here
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum InteractiveTxMessageSend {
	TxAddInput(msgs::TxAddInput),
	TxAddOutput(msgs::TxAddOutput),
	TxComplete(msgs::TxComplete),
}

impl InteractiveTxMessageSend {
	pub fn into_msg_send_event(self, counterparty_node_id: PublicKey) -> MessageSendEvent {
		match self {
			InteractiveTxMessageSend::TxAddInput(msg) => {
				MessageSendEvent::SendTxAddInput { node_id: counterparty_node_id, msg }
			},
			InteractiveTxMessageSend::TxAddOutput(msg) => {
				MessageSendEvent::SendTxAddOutput { node_id: counterparty_node_id, msg }
			},
			InteractiveTxMessageSend::TxComplete(msg) => {
				MessageSendEvent::SendTxComplete { node_id: counterparty_node_id, msg }
			},
		}
	}
}

// This macro executes a state machine transition based on a provided action.
macro_rules! do_state_transition {
	($self: ident, $transition: ident, $msg: expr) => {{
		let mut state_machine = StateMachine::Indeterminate;
		core::mem::swap(&mut state_machine, &mut $self.state_machine);
		$self.state_machine = state_machine.$transition($msg);
		match &$self.state_machine {
			StateMachine::NegotiationAborted(state) => Err(state.0.clone()),
			_ => Ok(()),
		}
	}};
}

fn generate_holder_serial_id<ES: Deref>(entropy_source: &ES, is_initiator: bool) -> SerialId
where
	ES::Target: EntropySource,
{
	let rand_bytes = entropy_source.get_secure_random_bytes();
	let mut serial_id_bytes = [0u8; 8];
	serial_id_bytes.copy_from_slice(&rand_bytes[..8]);
	let mut serial_id = u64::from_be_bytes(serial_id_bytes);
	if serial_id.is_for_initiator() != is_initiator {
		serial_id ^= 1;
	}
	serial_id
}

pub(super) enum HandleTxCompleteValue {
	SendTxMessage(InteractiveTxMessageSend),
	NegotiationComplete(Option<InteractiveTxMessageSend>, OutPoint),
}

pub(super) struct InteractiveTxConstructorArgs<'a, ES: Deref>
where
	ES::Target: EntropySource,
{
	pub entropy_source: &'a ES,
	pub holder_node_id: PublicKey,
	pub counterparty_node_id: PublicKey,
	pub channel_id: ChannelId,
	pub feerate_sat_per_kw: u32,
	pub is_initiator: bool,
	pub funding_tx_locktime: AbsoluteLockTime,
	pub inputs_to_contribute: Vec<FundingTxInput>,
	pub shared_funding_input: Option<SharedOwnedInput>,
	pub shared_funding_output: SharedOwnedOutput,
	pub outputs_to_contribute: Vec<TxOut>,
}

impl InteractiveTxConstructor {
	/// Instantiates a new `InteractiveTxConstructor`.
	///
	/// If the holder is the initiator, they need to send the first message which is a `TxAddInput`
	/// message.
	pub fn new<ES: Deref>(args: InteractiveTxConstructorArgs<ES>) -> Result<Self, NegotiationError>
	where
		ES::Target: EntropySource,
	{
		let InteractiveTxConstructorArgs {
			entropy_source,
			holder_node_id,
			counterparty_node_id,
			channel_id,
			feerate_sat_per_kw,
			is_initiator,
			funding_tx_locktime,
			inputs_to_contribute,
			shared_funding_input,
			shared_funding_output,
			outputs_to_contribute,
		} = args;

		let state_machine = StateMachine::new(
			holder_node_id,
			counterparty_node_id,
			feerate_sat_per_kw,
			is_initiator,
			funding_tx_locktime,
			shared_funding_input.clone(),
			shared_funding_output.clone(),
		);

		let mut inputs_to_contribute: Vec<(SerialId, InputOwned)> = inputs_to_contribute
			.into_iter()
			.map(|FundingTxInput { utxo, sequence, prevtx: prev_tx }| {
				let serial_id = generate_holder_serial_id(entropy_source, is_initiator);
				let txin = TxIn { previous_output: utxo.outpoint, sequence, ..Default::default() };
				let prev_output = utxo.output;
				let input = InputOwned::Single(SingleOwnedInput {
					input: txin,
					prev_tx,
					prev_output,
					satisfaction_weight: Weight::from_wu(utxo.satisfaction_weight),
				});
				(serial_id, input)
			})
			.collect();
		if let Some(shared_funding_input) = &shared_funding_input {
			if is_initiator {
				// Add shared funding input
				let serial_id = generate_holder_serial_id(entropy_source, is_initiator);
				inputs_to_contribute
					.push((serial_id, InputOwned::Shared(shared_funding_input.clone())));
			}
		}
		// We'll sort by the randomly generated serial IDs, effectively shuffling the order of the inputs
		// as the user passed them to us to avoid leaking any potential categorization of transactions
		// before we pass any of the inputs to the counterparty.
		inputs_to_contribute.sort_unstable_by_key(|(serial_id, _)| *serial_id);

		let mut outputs_to_contribute: Vec<_> = outputs_to_contribute
			.into_iter()
			.map(|output| {
				let serial_id = generate_holder_serial_id(entropy_source, is_initiator);
				let output = OutputOwned::Single(output);
				(serial_id, output)
			})
			.collect();
		if is_initiator {
			// Add shared funding output
			let serial_id = generate_holder_serial_id(entropy_source, is_initiator);
			let output = OutputOwned::Shared(shared_funding_output);
			outputs_to_contribute.push((serial_id, output));
		}
		// In the same manner and for the same rationale as the inputs above, we'll shuffle the outputs.
		outputs_to_contribute.sort_unstable_by_key(|(serial_id, _)| *serial_id);

		let next_input_index = (!inputs_to_contribute.is_empty()).then_some(0);
		let next_output_index = (!outputs_to_contribute.is_empty()).then_some(0);

		let mut constructor = Self {
			state_machine,
			is_initiator,
			initiator_first_message: None,
			channel_id,
			inputs_to_contribute,
			outputs_to_contribute,
			next_input_index,
			next_output_index,
		};
		// We'll store the first message for the initiator.
		if is_initiator {
			match constructor.maybe_send_message() {
				Ok(message) => {
					constructor.initiator_first_message = Some(message);
				},
				Err(reason) => {
					return Err(constructor.into_negotiation_error(reason));
				},
			}
		}
		Ok(constructor)
	}

	fn into_negotiation_error(self, reason: AbortReason) -> NegotiationError {
		let (contributed_inputs, contributed_outputs) = self.into_contributed_inputs_and_outputs();
		NegotiationError { reason, contributed_inputs, contributed_outputs }
	}

	pub(super) fn into_contributed_inputs_and_outputs(self) -> (Vec<BitcoinOutPoint>, Vec<TxOut>) {
		let contributed_inputs = self
			.inputs_to_contribute
			.into_iter()
			.filter(|(_, input)| !input.is_shared())
			.map(|(_, input)| input.into_tx_in().previous_output)
			.collect();
		let contributed_outputs = self
			.outputs_to_contribute
			.into_iter()
			.filter(|(_, output)| !output.is_shared())
			.map(|(_, output)| output.into_tx_out())
			.collect();
		(contributed_inputs, contributed_outputs)
	}

	pub(super) fn to_contributed_inputs_and_outputs(&self) -> (Vec<BitcoinOutPoint>, Vec<TxOut>) {
		let contributed_inputs = self
			.inputs_to_contribute
			.iter()
			.filter(|(_, input)| !input.is_shared())
			.map(|(_, input)| input.tx_in().previous_output)
			.collect();
		let contributed_outputs = self
			.outputs_to_contribute
			.iter()
			.filter(|(_, output)| !output.is_shared())
			.map(|(_, output)| output.tx_out().clone())
			.collect();
		(contributed_inputs, contributed_outputs)
	}

	pub fn is_initiator(&self) -> bool {
		self.is_initiator
	}

	pub fn take_initiator_first_message(&mut self) -> Option<InteractiveTxMessageSend> {
		self.initiator_first_message.take()
	}

	fn maybe_send_message(&mut self) -> Result<InteractiveTxMessageSend, AbortReason> {
		let channel_id = self.channel_id;

		// We first attempt to send inputs we want to add, then outputs. Once we are done sending
		// them both, then we always send tx_complete.
		if let Some((serial_id, input)) = self.next_input_to_contribute() {
			let satisfaction_weight = input.satisfaction_weight();
			let msg = match input {
				InputOwned::Single(single) => msgs::TxAddInput {
					channel_id,
					serial_id: *serial_id,
					prevtx: Some(single.prev_tx.clone()),
					prevtx_out: single.input.previous_output.vout,
					sequence: single.input.sequence.to_consensus_u32(),
					shared_input_txid: None,
				},
				InputOwned::Shared(shared) => msgs::TxAddInput {
					channel_id,
					serial_id: *serial_id,
					prevtx: None,
					prevtx_out: shared.input.previous_output.vout,
					sequence: shared.input.sequence.to_consensus_u32(),
					shared_input_txid: Some(shared.input.previous_output.txid),
				},
			};
			do_state_transition!(self, sent_tx_add_input, (&msg, satisfaction_weight))?;
			Ok(InteractiveTxMessageSend::TxAddInput(msg))
		} else if let Some((serial_id, output)) = self.next_output_to_contribute() {
			let msg = msgs::TxAddOutput {
				channel_id,
				serial_id: *serial_id,
				sats: output.tx_out().value.to_sat(),
				script: output.tx_out().script_pubkey.clone(),
			};
			do_state_transition!(self, sent_tx_add_output, &msg)?;
			Ok(InteractiveTxMessageSend::TxAddOutput(msg))
		} else {
			let msg = msgs::TxComplete { channel_id };
			do_state_transition!(self, sent_tx_complete, &msg)?;
			Ok(InteractiveTxMessageSend::TxComplete(msg))
		}
	}

	fn next_input_to_contribute(&mut self) -> Option<&(SerialId, InputOwned)> {
		match self.next_input_index {
			Some(index) => {
				self.next_input_index =
					index.checked_add(1).filter(|index| *index < self.inputs_to_contribute.len());
				self.inputs_to_contribute.get(index)
			},
			None => None,
		}
	}

	fn next_output_to_contribute(&mut self) -> Option<&(SerialId, OutputOwned)> {
		match self.next_output_index {
			Some(index) => {
				self.next_output_index =
					index.checked_add(1).filter(|index| *index < self.outputs_to_contribute.len());
				self.outputs_to_contribute.get(index)
			},
			None => None,
		}
	}

	pub fn handle_tx_add_input(
		&mut self, msg: &msgs::TxAddInput,
	) -> Result<InteractiveTxMessageSend, AbortReason> {
		do_state_transition!(self, received_tx_add_input, msg)?;
		self.maybe_send_message()
	}

	pub fn handle_tx_remove_input(
		&mut self, msg: &msgs::TxRemoveInput,
	) -> Result<InteractiveTxMessageSend, AbortReason> {
		do_state_transition!(self, received_tx_remove_input, msg)?;
		self.maybe_send_message()
	}

	pub fn handle_tx_add_output(
		&mut self, msg: &msgs::TxAddOutput,
	) -> Result<InteractiveTxMessageSend, AbortReason> {
		do_state_transition!(self, received_tx_add_output, msg)?;
		self.maybe_send_message()
	}

	pub fn handle_tx_remove_output(
		&mut self, msg: &msgs::TxRemoveOutput,
	) -> Result<InteractiveTxMessageSend, AbortReason> {
		do_state_transition!(self, received_tx_remove_output, msg)?;
		self.maybe_send_message()
	}

	pub fn handle_tx_complete(
		&mut self, msg: &msgs::TxComplete,
	) -> Result<HandleTxCompleteValue, AbortReason> {
		do_state_transition!(self, received_tx_complete, msg)?;
		match &self.state_machine {
			StateMachine::ReceivedTxComplete(_) => {
				let msg_send = self.maybe_send_message()?;
				match &self.state_machine {
					StateMachine::NegotiationComplete(NegotiationComplete(signing_session)) => {
						let funding_outpoint = signing_session.unsigned_tx.funding_outpoint();
						debug_assert!(matches!(msg_send, InteractiveTxMessageSend::TxComplete(_)));
						Ok(HandleTxCompleteValue::NegotiationComplete(
							Some(msg_send),
							funding_outpoint,
						))
					},
					StateMachine::SentChangeMsg(_) => {
						Ok(HandleTxCompleteValue::SendTxMessage(msg_send))
					}, // We either had an input or output to contribute.
					_ => {
						debug_assert!(false, "We cannot transition to any other states after receiving `tx_complete` and responding");
						Err(AbortReason::InvalidStateTransition)
					},
				}
			},
			StateMachine::NegotiationComplete(NegotiationComplete(signing_session)) => {
				let funding_outpoint = signing_session.unsigned_tx.funding_outpoint();
				Ok(HandleTxCompleteValue::NegotiationComplete(None, funding_outpoint))
			},
			_ => {
				debug_assert!(
					false,
					"We cannot transition to any other states after receiving `tx_complete`"
				);
				Err(AbortReason::InvalidStateTransition)
			},
		}
	}

	pub fn into_signing_session(self) -> InteractiveTxSigningSession {
		match self.state_machine {
			StateMachine::NegotiationComplete(s) => s.0,
			_ => panic!("Signing session is not ready yet"),
		}
	}
}

/// Determine whether a change output should be added, and if yes, of what size, considering our
/// given inputs and outputs, and intended contribution. Takes into account the fees and the dust
/// limit.
///
/// Three outcomes are possible:
/// - Inputs are sufficient for intended contribution, fees, and a larger-than-dust change:
///   `Ok(Some(change_amount))`
/// - Inputs are sufficient for intended contribution and fees, and a change output isn't needed:
///   `Ok(None)`
/// - Inputs are not sufficient to cover contribution and fees:
///   `Err(AbortReason::InsufficientFees)`
///
/// Parameters:
/// - `context` - Context of the funding negotiation, including non-shared inputs and feerate.
/// - `is_splice` - Whether we splicing an existing channel or dual-funding a new one.
/// - `shared_output_funding_script` - The script of the shared output.
/// - `funding_outputs` - Our funding outputs.
/// - `change_output_dust_limit` - The dust limit (in sats) to consider.
pub(super) fn calculate_change_output_value(
	context: &FundingNegotiationContext, is_splice: bool, shared_output_funding_script: &ScriptBuf,
	change_output_dust_limit: u64,
) -> Result<Option<u64>, AbortReason> {
	assert!(context.our_funding_contribution > SignedAmount::ZERO);
	let our_funding_contribution_satoshis = context.our_funding_contribution.to_sat() as u64;

	let mut total_input_satoshis = 0u64;
	let mut our_funding_inputs_weight = 0u64;
	for FundingTxInput { utxo, .. } in context.our_funding_inputs.iter() {
		total_input_satoshis = total_input_satoshis.saturating_add(utxo.output.value.to_sat());

		let weight = BASE_INPUT_WEIGHT + utxo.satisfaction_weight;
		our_funding_inputs_weight = our_funding_inputs_weight.saturating_add(weight);
	}

	let funding_outputs = &context.our_funding_outputs;
	let total_output_satoshis =
		funding_outputs.iter().fold(0u64, |total, out| total.saturating_add(out.value.to_sat()));
	let our_funding_outputs_weight = funding_outputs.iter().fold(0u64, |weight, out| {
		weight.saturating_add(get_output_weight(&out.script_pubkey).to_wu())
	});
	let mut weight = our_funding_outputs_weight.saturating_add(our_funding_inputs_weight);

	// If we are the initiator, we must pay for the weight of the funding output and
	// all common fields in the funding transaction.
	if context.is_initiator {
		weight = weight.saturating_add(get_output_weight(shared_output_funding_script).to_wu());
		weight = weight.saturating_add(TX_COMMON_FIELDS_WEIGHT);
		if is_splice {
			// TODO(taproot): Needs to consider different weights based on channel type
			weight = weight.saturating_add(BASE_INPUT_WEIGHT);
			weight = weight.saturating_add(EMPTY_SCRIPT_SIG_WEIGHT);
			weight = weight.saturating_add(FUNDING_TRANSACTION_WITNESS_WEIGHT);
			#[cfg(feature = "grind_signatures")]
			{
				// Guarantees a low R signature
				weight -= 1;
			}
		}
	}

	let fees_sats = fee_for_weight(context.funding_feerate_sat_per_1000_weight, weight);
	let net_total_less_fees =
		total_input_satoshis.saturating_sub(total_output_satoshis).saturating_sub(fees_sats);
	if net_total_less_fees < our_funding_contribution_satoshis {
		// Not enough to cover contribution plus fees
		return Err(AbortReason::InsufficientFees);
	}
	let remaining_value = net_total_less_fees.saturating_sub(our_funding_contribution_satoshis);
	if remaining_value < change_output_dust_limit {
		// Enough to cover contribution plus fees, but leftover is below dust limit; no change
		Ok(None)
	} else {
		// Enough to have over-dust change
		Ok(Some(remaining_value))
	}
}

#[cfg(test)]
mod tests {
	use crate::chain::chaininterface::{fee_for_weight, FEERATE_FLOOR_SATS_PER_KW};
	use crate::ln::channel::{FundingNegotiationContext, TOTAL_BITCOIN_SUPPLY_SATOSHIS};
	use crate::ln::funding::FundingTxInput;
	use crate::ln::interactivetxs::{
		calculate_change_output_value, generate_holder_serial_id, AbortReason,
		HandleTxCompleteValue, InteractiveTxConstructor, InteractiveTxConstructorArgs,
		InteractiveTxMessageSend, SharedOwnedInput, SharedOwnedOutput, MAX_INPUTS_OUTPUTS_COUNT,
		MAX_RECEIVED_TX_ADD_INPUT_COUNT, MAX_RECEIVED_TX_ADD_OUTPUT_COUNT,
	};
	use crate::ln::types::ChannelId;
	use crate::sign::EntropySource;
	use crate::util::atomic_counter::AtomicCounter;
	use bitcoin::absolute::LockTime as AbsoluteLockTime;
	use bitcoin::amount::Amount;
	use bitcoin::hashes::Hash;
	use bitcoin::hex::FromHex;
	use bitcoin::key::{TweakedPublicKey, UntweakedPublicKey};
	use bitcoin::script::Builder;
	use bitcoin::secp256k1::{Keypair, PublicKey, Secp256k1, SecretKey};
	use bitcoin::transaction::Version;
	use bitcoin::{opcodes, WScriptHash, Weight, XOnlyPublicKey};
	use bitcoin::{
		OutPoint, PubkeyHash, ScriptBuf, Sequence, SignedAmount, Transaction, TxIn, TxOut,
		WPubkeyHash,
	};
	use core::ops::Deref;

	use super::{
		get_output_weight, ConstructedTransaction, InteractiveTxSigningSession, TxInMetadata,
		P2TR_INPUT_WEIGHT_LOWER_BOUND, P2WPKH_INPUT_WEIGHT_LOWER_BOUND,
		P2WSH_INPUT_WEIGHT_LOWER_BOUND, REMOTE_FEE_TOLERANCE_PERCENT, TX_COMMON_FIELDS_WEIGHT,
	};

	const TEST_FEERATE_SATS_PER_KW: u32 = FEERATE_FLOOR_SATS_PER_KW * 10;

	// A simple entropy source that works based on an atomic counter.
	struct TestEntropySource(AtomicCounter);
	impl EntropySource for TestEntropySource {
		fn get_secure_random_bytes(&self) -> [u8; 32] {
			let mut res = [0u8; 32];
			let increment = self.0.next();
			for (i, byte) in res.iter_mut().enumerate() {
				// Rotate the increment value by 'i' bits to the right, to avoid clashes
				// when `generate_local_serial_id` does a parity flip on consecutive calls for the
				// same party.
				let rotated_increment = increment.rotate_right(i as u32);
				*byte = (rotated_increment & 0xff) as u8;
			}
			res
		}
	}

	// An entropy source that deliberately returns you the same seed every time. We use this
	// to test if the constructor would catch inputs/outputs that are attempting to be added
	// with duplicate serial ids.
	struct DuplicateEntropySource;
	impl EntropySource for DuplicateEntropySource {
		fn get_secure_random_bytes(&self) -> [u8; 32] {
			let mut res = [0u8; 32];
			let count = 1u64;
			res[0..8].copy_from_slice(&count.to_be_bytes());
			res
		}
	}

	#[derive(Debug, PartialEq, Eq)]
	enum ErrorCulprit {
		NodeA,
		NodeB,
		// Some error values are only checked at the end of the negotiation and are not easy to attribute
		// to a particular party. Both parties would indicate an `AbortReason` in this case.
		// e.g. Exceeded max inputs and outputs after negotiation.
		Indeterminate,
	}

	struct TestSession {
		description: &'static str,
		inputs_a: Vec<FundingTxInput>,
		a_shared_input: Option<(OutPoint, TxOut, u64)>,
		/// The funding output, with the value contributed
		shared_output_a: (TxOut, u64),
		outputs_a: Vec<TxOut>,
		inputs_b: Vec<FundingTxInput>,
		b_shared_input: Option<(OutPoint, TxOut, u64)>,
		/// The funding output, with the value contributed
		shared_output_b: (TxOut, u64),
		outputs_b: Vec<TxOut>,
		expect_error: Option<(AbortReason, ErrorCulprit)>,
	}

	fn do_test_interactive_tx_constructor(session: TestSession) {
		let entropy_source = TestEntropySource(AtomicCounter::new());
		do_test_interactive_tx_constructor_internal(session, &&entropy_source);
	}

	fn do_test_interactive_tx_constructor_with_entropy_source<ES: Deref>(
		session: TestSession, entropy_source: ES,
	) where
		ES::Target: EntropySource,
	{
		do_test_interactive_tx_constructor_internal(session, &entropy_source);
	}

	fn do_test_interactive_tx_constructor_internal<ES: Deref>(
		session: TestSession, entropy_source: &ES,
	) where
		ES::Target: EntropySource,
	{
		let channel_id = ChannelId(entropy_source.get_secure_random_bytes());
		let funding_tx_locktime = AbsoluteLockTime::from_height(1337).unwrap();
		let holder_node_id = PublicKey::from_secret_key(
			&Secp256k1::signing_only(),
			&SecretKey::from_slice(&[42; 32]).unwrap(),
		);
		let counterparty_node_id = PublicKey::from_secret_key(
			&Secp256k1::signing_only(),
			&SecretKey::from_slice(&[43; 32]).unwrap(),
		);

		let mut constructor_a = match InteractiveTxConstructor::new(InteractiveTxConstructorArgs {
			entropy_source,
			channel_id,
			feerate_sat_per_kw: TEST_FEERATE_SATS_PER_KW,
			holder_node_id,
			counterparty_node_id,
			is_initiator: true,
			funding_tx_locktime,
			inputs_to_contribute: session.inputs_a,
			shared_funding_input: session.a_shared_input.map(|(op, prev_output, lo)| {
				SharedOwnedInput::new(
					TxIn {
						previous_output: op,
						sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
						..Default::default()
					},
					prev_output,
					lo,
					true,                             // holder_sig_first
					generate_funding_script_pubkey(), // witness_script for test
				)
			}),
			shared_funding_output: SharedOwnedOutput::new(
				session.shared_output_a.0,
				session.shared_output_a.1,
			),
			outputs_to_contribute: session.outputs_a,
		}) {
			Ok(r) => Some(r),
			Err(e) => {
				assert_eq!(
					Some((e.reason, ErrorCulprit::NodeA)),
					session.expect_error,
					"Test: {}",
					session.description
				);
				return;
			},
		};
		let mut constructor_b = match InteractiveTxConstructor::new(InteractiveTxConstructorArgs {
			entropy_source,
			holder_node_id,
			counterparty_node_id,
			channel_id,
			feerate_sat_per_kw: TEST_FEERATE_SATS_PER_KW,
			is_initiator: false,
			funding_tx_locktime,
			inputs_to_contribute: session.inputs_b,
			shared_funding_input: session.b_shared_input.map(|(op, prev_output, lo)| {
				SharedOwnedInput::new(
					TxIn {
						previous_output: op,
						sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
						..Default::default()
					},
					prev_output,
					lo,
					false,                            // holder_sig_first
					generate_funding_script_pubkey(), // witness_script for test
				)
			}),
			shared_funding_output: SharedOwnedOutput::new(
				session.shared_output_b.0,
				session.shared_output_b.1,
			),
			outputs_to_contribute: session.outputs_b,
		}) {
			Ok(r) => Some(r),
			Err(e) => {
				assert_eq!(
					Some((e.reason, ErrorCulprit::NodeB)),
					session.expect_error,
					"Test: {}",
					session.description
				);
				return;
			},
		};

		let handle_message_send =
			|msg: InteractiveTxMessageSend, for_constructor: &mut InteractiveTxConstructor| {
				match msg {
					InteractiveTxMessageSend::TxAddInput(msg) => for_constructor
						.handle_tx_add_input(&msg)
						.map(|msg_send| (Some(msg_send), false)),
					InteractiveTxMessageSend::TxAddOutput(msg) => for_constructor
						.handle_tx_add_output(&msg)
						.map(|msg_send| (Some(msg_send), false)),
					InteractiveTxMessageSend::TxComplete(msg) => {
						for_constructor.handle_tx_complete(&msg).map(|value| match value {
							HandleTxCompleteValue::SendTxMessage(msg_send) => {
								(Some(msg_send), false)
							},
							HandleTxCompleteValue::NegotiationComplete(msg_send, _) => {
								(msg_send, true)
							},
						})
					},
				}
			};

		let mut message_send_a = constructor_a.as_mut().unwrap().take_initiator_first_message();
		let mut message_send_b = None;
		let mut final_tx_a = None;
		let mut final_tx_b = None;
		while constructor_a.is_some() || constructor_b.is_some() {
			if let Some(message_send_a) = message_send_a.take() {
				match handle_message_send(message_send_a, constructor_b.as_mut().unwrap()) {
					Ok((msg_send, negotiation_complete)) => {
						message_send_b = msg_send;
						if negotiation_complete {
							final_tx_b = Some(
								constructor_b
									.take()
									.unwrap()
									.into_signing_session()
									.unsigned_tx
									.compute_txid(),
							);
						}
					},
					Err(abort_reason) => {
						let error_culprit = match abort_reason {
							AbortReason::ExceededNumberOfInputsOrOutputs => {
								ErrorCulprit::Indeterminate
							},
							_ => ErrorCulprit::NodeA,
						};
						assert_eq!(
							Some((abort_reason, error_culprit)),
							session.expect_error,
							"Test: {}",
							session.description
						);
						assert!(message_send_b.is_none(), "Test: {}", session.description);
						return;
					},
				}
			}
			if let Some(message_send_b) = message_send_b.take() {
				match handle_message_send(message_send_b, constructor_a.as_mut().unwrap()) {
					Ok((msg_send, negotiation_complete)) => {
						message_send_a = msg_send;
						if negotiation_complete {
							final_tx_a = Some(
								constructor_a
									.take()
									.unwrap()
									.into_signing_session()
									.unsigned_tx
									.compute_txid(),
							);
						}
					},
					Err(abort_reason) => {
						let error_culprit = match abort_reason {
							AbortReason::ExceededNumberOfInputsOrOutputs => {
								ErrorCulprit::Indeterminate
							},
							_ => ErrorCulprit::NodeB,
						};
						assert_eq!(
							Some((abort_reason, error_culprit)),
							session.expect_error,
							"Test: {}",
							session.description
						);
						assert!(message_send_a.is_none(), "Test: {}", session.description);
						return;
					},
				}
			}
		}
		assert!(message_send_a.is_none());
		assert!(message_send_b.is_none());
		assert_eq!(final_tx_a.unwrap(), final_tx_b.unwrap());
		assert!(
			session.expect_error.is_none(),
			"Missing expected error {:?}, Test: {}",
			session.expect_error,
			session.description,
		);
	}

	#[derive(Debug, Clone, Copy)]
	enum TestOutput {
		P2WPKH(u64),
		/// P2WSH, but with the specific script used for the funding output
		P2WSH(u64),
		P2TR(u64),
		// Non-witness type to test rejection.
		P2PKH(u64),
	}

	fn generate_tx(outputs: &[TestOutput]) -> Transaction {
		generate_tx_with_locktime(outputs, 1337)
	}

	fn generate_txout(output: &TestOutput) -> TxOut {
		let secp_ctx = Secp256k1::new();
		let (value, script_pubkey) = match output {
			TestOutput::P2WPKH(value) => (*value, generate_p2wpkh_script_pubkey()),
			TestOutput::P2WSH(value) => (*value, generate_funding_script_pubkey()),
			TestOutput::P2TR(value) => (
				*value,
				ScriptBuf::new_p2tr(
					&secp_ctx,
					UntweakedPublicKey::from_keypair(
						&Keypair::from_seckey_slice(&secp_ctx, &[3; 32]).unwrap(),
					)
					.0,
					None,
				),
			),
			TestOutput::P2PKH(value) => {
				(*value, ScriptBuf::new_p2pkh(&PubkeyHash::from_slice(&[4; 20]).unwrap()))
			},
		};

		TxOut { value: Amount::from_sat(value), script_pubkey }
	}

	fn generate_tx_with_locktime(outputs: &[TestOutput], locktime: u32) -> Transaction {
		Transaction {
			version: Version::TWO,
			lock_time: AbsoluteLockTime::from_height(locktime).unwrap(),
			input: vec![TxIn { ..Default::default() }],
			output: outputs.iter().map(generate_txout).collect(),
		}
	}

	fn generate_inputs(outputs: &[TestOutput]) -> Vec<FundingTxInput> {
		let tx = generate_tx(outputs);
		outputs
			.iter()
			.enumerate()
			.map(|(idx, output)| match output {
				TestOutput::P2WPKH(_) => {
					FundingTxInput::new_p2wpkh(tx.clone(), idx as u32).unwrap()
				},
				TestOutput::P2WSH(_) => {
					FundingTxInput::new_p2wsh(tx.clone(), idx as u32, Weight::from_wu(42)).unwrap()
				},
				TestOutput::P2TR(_) => {
					FundingTxInput::new_p2tr_key_spend(tx.clone(), idx as u32).unwrap()
				},
				TestOutput::P2PKH(_) => FundingTxInput::new_p2pkh(tx.clone(), idx as u32).unwrap(),
			})
			.collect()
	}

	fn generate_shared_input(
		prev_funding_tx: &Transaction, vout: u32, local_owned: u64,
	) -> (OutPoint, TxOut, u64) {
		let txid = prev_funding_tx.compute_txid();
		let prev_output = prev_funding_tx.output.get(vout as usize).unwrap();
		let value = prev_output.value.to_sat();
		assert!(
			local_owned <= value,
			"local owned > value for shared input, {} {}",
			local_owned,
			value,
		);
		(OutPoint { txid, vout }, prev_output.clone(), local_owned)
	}

	fn generate_p2wsh_script_pubkey() -> ScriptBuf {
		Builder::new().push_opcode(opcodes::OP_TRUE).into_script().to_p2wsh()
	}

	fn generate_p2wpkh_script_pubkey() -> ScriptBuf {
		ScriptBuf::new_p2wpkh(&WPubkeyHash::from_slice(&[1; 20]).unwrap())
	}

	fn generate_funding_script_pubkey() -> ScriptBuf {
		Builder::new().push_int(33).into_script().to_p2wsh()
	}

	fn generate_output_nonfunding_one(output: &TestOutput) -> TxOut {
		generate_txout(output)
	}

	fn generate_outputs(outputs: &[TestOutput]) -> Vec<TxOut> {
		outputs.iter().map(generate_output_nonfunding_one).collect()
	}

	/// Generate a single P2WSH output that is the funding output, with local contributions
	fn generate_funding_txout(value: u64, local_value: u64) -> (TxOut, u64) {
		if local_value > value {
			println!("Warning: Invalid local value, {} {}", value, local_value);
		}
		(generate_txout(&TestOutput::P2WSH(value)), local_value)
	}

	fn generate_fixed_number_of_inputs(count: u16) -> Vec<FundingTxInput> {
		// Generate transactions with a total `count` number of outputs such that no transaction has a
		// serialized length greater than u16::MAX.
		let max_outputs_per_prevtx = 1_500;
		let mut remaining = count;
		let mut inputs: Vec<FundingTxInput> = Vec::with_capacity(count as usize);

		while remaining > 0 {
			let tx_output_count = remaining.min(max_outputs_per_prevtx);
			remaining -= tx_output_count;

			let outputs = vec![TestOutput::P2WPKH(1_000_000); tx_output_count as usize];

			// Use unique locktime for each tx so outpoints are different across transactions
			let tx = generate_tx_with_locktime(&outputs, (1337 + remaining).into());

			let mut temp: Vec<FundingTxInput> = outputs
				.iter()
				.enumerate()
				.map(|(idx, _)| FundingTxInput::new_p2wpkh(tx.clone(), idx as u32).unwrap())
				.collect();

			inputs.append(&mut temp);
		}

		inputs
	}

	fn generate_fixed_number_of_outputs(count: u16) -> Vec<TxOut> {
		// Set a constant value for each TxOut
		generate_outputs(&vec![TestOutput::P2WPKH(1_000_000); count as usize])
	}

	fn generate_p2sh_script_pubkey() -> ScriptBuf {
		Builder::new().push_opcode(opcodes::OP_TRUE).into_script().to_p2sh()
	}

	fn generate_non_witness_output(value: u64) -> TxOut {
		TxOut { value: Amount::from_sat(value), script_pubkey: generate_p2sh_script_pubkey() }
	}

	#[test]
	fn test_interactive_tx_constructor() {
		// A transaction that can be used as a previous funding transaction
		let prev_funding_tx_1 = Transaction {
			input: Vec::new(),
			output: vec![TxOut {
				value: Amount::from_sat(60_000),
				script_pubkey: ScriptBuf::new(),
			}],
			lock_time: AbsoluteLockTime::ZERO,
			version: Version::TWO,
		};

		do_test_interactive_tx_constructor(TestSession {
			description: "Single contribution, no initiator inputs",
			inputs_a: vec![],
			a_shared_input: None,
			shared_output_a: generate_funding_txout(1_000_000, 1_000_000),
			outputs_a: vec![],
			inputs_b: vec![],
			b_shared_input: None,
			shared_output_b: generate_funding_txout(1_000_000, 0),
			outputs_b: vec![],
			expect_error: Some((AbortReason::OutputsValueExceedsInputsValue, ErrorCulprit::NodeA)),
		});

		do_test_interactive_tx_constructor(TestSession {
			description: "Single contribution, no fees",
			inputs_a: generate_inputs(&[TestOutput::P2WPKH(1_000_000)]),
			a_shared_input: None,
			shared_output_a: generate_funding_txout(1_000_000, 1_000_000),
			outputs_a: vec![],
			inputs_b: vec![],
			b_shared_input: None,
			shared_output_b: generate_funding_txout(1_000_000, 0),
			outputs_b: vec![],
			expect_error: Some((AbortReason::InsufficientFees, ErrorCulprit::NodeA)),
		});
		let outputs_weight = get_output_weight(&generate_p2wsh_script_pubkey()).to_wu();
		let amount_adjusted_with_p2wpkh_fee = 1_000_000
			- fee_for_weight(
				(TEST_FEERATE_SATS_PER_KW as u64 * REMOTE_FEE_TOLERANCE_PERCENT / 100) as u32,
				P2WPKH_INPUT_WEIGHT_LOWER_BOUND + TX_COMMON_FIELDS_WEIGHT + outputs_weight,
			);
		do_test_interactive_tx_constructor(TestSession {
			description: "Single contribution, with P2WPKH input, insufficient fees",
			inputs_a: generate_inputs(&[TestOutput::P2WPKH(1_000_000)]),
			a_shared_input: None,
			// makes initiator inputs insufficient to cover fees
			shared_output_a: generate_funding_txout(
				amount_adjusted_with_p2wpkh_fee + 1,
				amount_adjusted_with_p2wpkh_fee + 1,
			),
			outputs_a: vec![],
			inputs_b: vec![],
			b_shared_input: None,
			shared_output_b: generate_funding_txout(amount_adjusted_with_p2wpkh_fee + 1, 0),
			outputs_b: vec![],
			expect_error: Some((AbortReason::InsufficientFees, ErrorCulprit::NodeA)),
		});
		do_test_interactive_tx_constructor(TestSession {
			description: "Single contribution with P2WPKH input, sufficient fees",
			inputs_a: generate_inputs(&[TestOutput::P2WPKH(1_000_000)]),
			a_shared_input: None,
			shared_output_a: generate_funding_txout(
				amount_adjusted_with_p2wpkh_fee,
				amount_adjusted_with_p2wpkh_fee,
			),
			outputs_a: vec![],
			inputs_b: vec![],
			b_shared_input: None,
			shared_output_b: generate_funding_txout(amount_adjusted_with_p2wpkh_fee, 0),
			outputs_b: vec![],
			expect_error: None,
		});
		let amount_adjusted_with_p2wsh_fee = 1_000_000
			- fee_for_weight(
				(TEST_FEERATE_SATS_PER_KW as u64 * REMOTE_FEE_TOLERANCE_PERCENT / 100) as u32,
				P2WSH_INPUT_WEIGHT_LOWER_BOUND + TX_COMMON_FIELDS_WEIGHT + outputs_weight,
			);
		do_test_interactive_tx_constructor(TestSession {
			description: "Single contribution, with P2WSH input, insufficient fees",
			inputs_a: generate_inputs(&[TestOutput::P2WSH(1_000_000)]),
			a_shared_input: None,
			// makes initiator inputs insufficient to cover fees
			shared_output_a: generate_funding_txout(
				amount_adjusted_with_p2wsh_fee + 1,
				amount_adjusted_with_p2wsh_fee + 1,
			),
			outputs_a: vec![],
			inputs_b: vec![],
			b_shared_input: None,
			shared_output_b: generate_funding_txout(amount_adjusted_with_p2wsh_fee + 1, 0),
			outputs_b: vec![],
			expect_error: Some((AbortReason::InsufficientFees, ErrorCulprit::NodeA)),
		});
		do_test_interactive_tx_constructor(TestSession {
			description: "Single contribution with P2WSH input, sufficient fees",
			inputs_a: generate_inputs(&[TestOutput::P2WSH(1_000_000)]),
			a_shared_input: None,
			shared_output_a: generate_funding_txout(
				amount_adjusted_with_p2wsh_fee,
				amount_adjusted_with_p2wsh_fee,
			),
			outputs_a: vec![],
			inputs_b: vec![],
			b_shared_input: None,
			shared_output_b: generate_funding_txout(amount_adjusted_with_p2wsh_fee, 0),
			outputs_b: vec![],
			expect_error: None,
		});
		let amount_adjusted_with_p2tr_fee = 1_000_000
			- fee_for_weight(
				(TEST_FEERATE_SATS_PER_KW as u64 * REMOTE_FEE_TOLERANCE_PERCENT / 100) as u32,
				P2TR_INPUT_WEIGHT_LOWER_BOUND + TX_COMMON_FIELDS_WEIGHT + outputs_weight,
			);
		do_test_interactive_tx_constructor(TestSession {
			description: "Single contribution, with P2TR input, insufficient fees",
			inputs_a: generate_inputs(&[TestOutput::P2TR(1_000_000)]),
			a_shared_input: None,
			// makes initiator inputs insufficient to cover fees
			shared_output_a: generate_funding_txout(
				amount_adjusted_with_p2tr_fee + 1,
				amount_adjusted_with_p2tr_fee + 1,
			),
			outputs_a: vec![],
			inputs_b: vec![],
			b_shared_input: None,
			shared_output_b: generate_funding_txout(amount_adjusted_with_p2tr_fee + 1, 0),
			outputs_b: vec![],
			expect_error: Some((AbortReason::InsufficientFees, ErrorCulprit::NodeA)),
		});
		do_test_interactive_tx_constructor(TestSession {
			description: "Single contribution with P2TR input, sufficient fees",
			inputs_a: generate_inputs(&[TestOutput::P2TR(1_000_000)]),
			a_shared_input: None,
			shared_output_a: generate_funding_txout(
				amount_adjusted_with_p2tr_fee,
				amount_adjusted_with_p2tr_fee,
			),
			outputs_a: vec![],
			inputs_b: vec![],
			b_shared_input: None,
			shared_output_b: generate_funding_txout(amount_adjusted_with_p2tr_fee, 0),
			outputs_b: vec![],
			expect_error: None,
		});
		do_test_interactive_tx_constructor(TestSession {
			description: "Initiator contributes sufficient fees, but non-initiator does not",
			inputs_a: generate_inputs(&[TestOutput::P2WPKH(1_000_000)]),
			a_shared_input: None,
			shared_output_a: generate_funding_txout(100_000, 0),
			outputs_a: vec![],
			inputs_b: generate_inputs(&[TestOutput::P2WPKH(100_000)]),
			b_shared_input: None,
			shared_output_b: generate_funding_txout(100_000, 100_000),
			outputs_b: vec![],
			expect_error: Some((AbortReason::InsufficientFees, ErrorCulprit::NodeB)),
		});
		do_test_interactive_tx_constructor(TestSession {
			description: "Multi-input-output contributions from both sides",
			inputs_a: generate_inputs(&[TestOutput::P2WPKH(1_000_000); 2]),
			a_shared_input: None,
			shared_output_a: generate_funding_txout(1_000_000, 200_000),
			outputs_a: vec![generate_output_nonfunding_one(&TestOutput::P2WPKH(200_000))],
			inputs_b: generate_inputs(&[
				TestOutput::P2WPKH(1_000_000),
				TestOutput::P2WPKH(500_000),
			]),
			b_shared_input: None,
			shared_output_b: generate_funding_txout(1_000_000, 800_000),
			outputs_b: vec![generate_output_nonfunding_one(&TestOutput::P2WPKH(400_000))],
			expect_error: None,
		});

		do_test_interactive_tx_constructor(TestSession {
			description: "Prevout from initiator is not a witness program",
			inputs_a: generate_inputs(&[TestOutput::P2PKH(1_000_000)]),
			a_shared_input: None,
			shared_output_a: generate_funding_txout(1_000_000, 1_000_000),
			outputs_a: vec![],
			inputs_b: vec![],
			b_shared_input: None,
			shared_output_b: generate_funding_txout(1_000_000, 0),
			outputs_b: vec![],
			expect_error: Some((AbortReason::PrevTxOutInvalid, ErrorCulprit::NodeA)),
		});

		let tx = generate_tx(&[TestOutput::P2WPKH(1_000_000)]);
		let mut invalid_sequence_input = FundingTxInput::new_p2wpkh(tx.clone(), 0).unwrap();
		invalid_sequence_input.set_sequence(Default::default());
		do_test_interactive_tx_constructor(TestSession {
			description: "Invalid input sequence from initiator",
			inputs_a: vec![invalid_sequence_input],
			a_shared_input: None,
			shared_output_a: generate_funding_txout(1_000_000, 1_000_000),
			outputs_a: vec![],
			inputs_b: vec![],
			b_shared_input: None,
			shared_output_b: generate_funding_txout(1_000_000, 0),
			outputs_b: vec![],
			expect_error: Some((AbortReason::IncorrectInputSequenceValue, ErrorCulprit::NodeA)),
		});
		let duplicate_input = FundingTxInput::new_p2wpkh(tx.clone(), 0).unwrap();
		do_test_interactive_tx_constructor(TestSession {
			description: "Duplicate prevout from initiator",
			inputs_a: vec![duplicate_input.clone(), duplicate_input],
			a_shared_input: None,
			shared_output_a: generate_funding_txout(1_000_000, 1_000_000),
			outputs_a: vec![],
			inputs_b: vec![],
			b_shared_input: None,
			shared_output_b: generate_funding_txout(1_000_000, 0),
			outputs_b: vec![],
			expect_error: Some((AbortReason::PrevTxOutInvalid, ErrorCulprit::NodeB)),
		});
		// Non-initiator uses same prevout as initiator.
		let duplicate_input = FundingTxInput::new_p2wpkh(tx.clone(), 0).unwrap();
		do_test_interactive_tx_constructor(TestSession {
			description: "Non-initiator uses same prevout as initiator",
			inputs_a: vec![duplicate_input.clone()],
			a_shared_input: None,
			shared_output_a: generate_funding_txout(1_000_000, 905_000),
			outputs_a: vec![],
			inputs_b: vec![duplicate_input],
			b_shared_input: None,
			shared_output_b: generate_funding_txout(1_000_000, 95_000),
			outputs_b: vec![],
			expect_error: Some((AbortReason::PrevTxOutInvalid, ErrorCulprit::NodeA)),
		});
		let duplicate_input = FundingTxInput::new_p2wpkh(tx.clone(), 0).unwrap();
		do_test_interactive_tx_constructor(TestSession {
			description: "Non-initiator uses same prevout as initiator",
			inputs_a: vec![duplicate_input.clone()],
			a_shared_input: None,
			shared_output_a: generate_funding_txout(1_000_000, 1_000_000),
			outputs_a: vec![],
			inputs_b: vec![duplicate_input],
			b_shared_input: None,
			shared_output_b: generate_funding_txout(1_000_000, 0),
			outputs_b: vec![],
			expect_error: Some((AbortReason::PrevTxOutInvalid, ErrorCulprit::NodeA)),
		});
		do_test_interactive_tx_constructor(TestSession {
			description: "Initiator sends too many TxAddInputs",
			inputs_a: generate_fixed_number_of_inputs(MAX_RECEIVED_TX_ADD_INPUT_COUNT + 1),
			a_shared_input: None,
			shared_output_a: generate_funding_txout(1_000_000, 1_000_000),
			outputs_a: vec![],
			inputs_b: vec![],
			b_shared_input: None,
			shared_output_b: generate_funding_txout(1_000_000, 0),
			outputs_b: vec![],
			expect_error: Some((AbortReason::ReceivedTooManyTxAddInputs, ErrorCulprit::NodeA)),
		});
		do_test_interactive_tx_constructor_with_entropy_source(
			TestSession {
				// We use a deliberately bad entropy source, `DuplicateEntropySource` to simulate this.
				description: "Attempt to queue up two inputs with duplicate serial ids",
				inputs_a: generate_fixed_number_of_inputs(2),
				a_shared_input: None,
				shared_output_a: generate_funding_txout(1_000_000, 1_000_000),
				outputs_a: vec![],
				inputs_b: vec![],
				b_shared_input: None,
				shared_output_b: generate_funding_txout(1_000_000, 0),
				outputs_b: vec![],
				expect_error: Some((AbortReason::DuplicateSerialId, ErrorCulprit::NodeA)),
			},
			&DuplicateEntropySource,
		);
		do_test_interactive_tx_constructor(TestSession {
			description: "Initiator sends too many TxAddOutputs",
			inputs_a: vec![],
			a_shared_input: None,
			shared_output_a: generate_funding_txout(1_000_000, 1_000_000),
			outputs_a: generate_fixed_number_of_outputs(MAX_RECEIVED_TX_ADD_OUTPUT_COUNT),
			inputs_b: vec![],
			b_shared_input: None,
			shared_output_b: generate_funding_txout(1_000_000, 0),
			outputs_b: vec![],
			expect_error: Some((AbortReason::ReceivedTooManyTxAddOutputs, ErrorCulprit::NodeA)),
		});
		let dust_amount = generate_p2wsh_script_pubkey().minimal_non_dust().to_sat() - 1;
		do_test_interactive_tx_constructor(TestSession {
			description: "Initiator sends an output below dust value",
			inputs_a: vec![],
			a_shared_input: None,
			shared_output_a: generate_funding_txout(dust_amount, dust_amount),
			outputs_a: vec![],
			inputs_b: vec![],
			b_shared_input: None,
			shared_output_b: generate_funding_txout(dust_amount, 0),
			outputs_b: vec![],
			expect_error: Some((AbortReason::BelowDustLimit, ErrorCulprit::NodeA)),
		});
		do_test_interactive_tx_constructor(TestSession {
			description: "Initiator sends an output above maximum sats allowed",
			inputs_a: vec![],
			a_shared_input: None,
			shared_output_a: generate_funding_txout(
				TOTAL_BITCOIN_SUPPLY_SATOSHIS + 1,
				TOTAL_BITCOIN_SUPPLY_SATOSHIS + 1,
			),
			outputs_a: vec![],
			inputs_b: vec![],
			b_shared_input: None,
			shared_output_b: generate_funding_txout(TOTAL_BITCOIN_SUPPLY_SATOSHIS + 1, 0),
			outputs_b: vec![],
			expect_error: Some((AbortReason::ExceededMaximumSatsAllowed, ErrorCulprit::NodeA)),
		});
		do_test_interactive_tx_constructor(TestSession {
			description: "Initiator sends an output without a witness program",
			inputs_a: vec![],
			a_shared_input: None,
			shared_output_a: generate_funding_txout(1_000_000, 1_000_000),
			outputs_a: vec![generate_non_witness_output(1_000_000)],
			inputs_b: vec![],
			b_shared_input: None,
			shared_output_b: generate_funding_txout(1_000_000, 0),
			outputs_b: vec![],
			expect_error: Some((AbortReason::InvalidOutputScript, ErrorCulprit::NodeA)),
		});
		do_test_interactive_tx_constructor_with_entropy_source(
			TestSession {
				// We use a deliberately bad entropy source, `DuplicateEntropySource` to simulate this.
				description: "Attempt to queue up two outputs with duplicate serial ids",
				inputs_a: vec![],
				a_shared_input: None,
				shared_output_a: generate_funding_txout(1_000_000, 1_000_000),
				outputs_a: generate_fixed_number_of_outputs(2),
				inputs_b: vec![],
				b_shared_input: None,
				shared_output_b: generate_funding_txout(1_000_000, 0),
				outputs_b: vec![],
				expect_error: Some((AbortReason::DuplicateSerialId, ErrorCulprit::NodeA)),
			},
			&DuplicateEntropySource,
		);

		do_test_interactive_tx_constructor(TestSession {
			description: "Peer contributed more output value than inputs",
			inputs_a: generate_inputs(&[TestOutput::P2WPKH(100_000)]),
			a_shared_input: None,
			shared_output_a: generate_funding_txout(1_000_000, 1_000_000),
			outputs_a: vec![],
			inputs_b: vec![],
			b_shared_input: None,
			shared_output_b: generate_funding_txout(1_000_000, 0),
			outputs_b: vec![],
			expect_error: Some((AbortReason::OutputsValueExceedsInputsValue, ErrorCulprit::NodeA)),
		});

		do_test_interactive_tx_constructor(TestSession {
			description: "Peer contributed more than allowed number of inputs",
			inputs_a: generate_fixed_number_of_inputs(MAX_INPUTS_OUTPUTS_COUNT as u16 + 1),
			a_shared_input: None,
			shared_output_a: generate_funding_txout(1_000_000, 1_000_000),
			outputs_a: vec![],
			inputs_b: vec![],
			b_shared_input: None,
			shared_output_b: generate_funding_txout(1_000_000, 0),
			outputs_b: vec![],
			expect_error: Some((
				AbortReason::ExceededNumberOfInputsOrOutputs,
				ErrorCulprit::Indeterminate,
			)),
		});
		do_test_interactive_tx_constructor(TestSession {
			description: "Peer contributed more than allowed number of outputs",
			inputs_a: generate_inputs(&[TestOutput::P2WPKH(TOTAL_BITCOIN_SUPPLY_SATOSHIS)]),
			a_shared_input: None,
			shared_output_a: generate_funding_txout(1_000_000, 1_000_000),
			outputs_a: generate_fixed_number_of_outputs(MAX_INPUTS_OUTPUTS_COUNT as u16),
			inputs_b: vec![],
			b_shared_input: None,
			shared_output_b: generate_funding_txout(1_000_000, 0),
			outputs_b: vec![],
			expect_error: Some((
				AbortReason::ExceededNumberOfInputsOrOutputs,
				ErrorCulprit::Indeterminate,
			)),
		});

		// We add the funding output, but we contribute a little
		do_test_interactive_tx_constructor(TestSession {
			description: "Funding output by us, small contribution",
			inputs_a: generate_inputs(&[TestOutput::P2WPKH(12_000)]),
			a_shared_input: None,
			shared_output_a: generate_funding_txout(1_000_000, 10_000),
			outputs_a: vec![],
			inputs_b: generate_inputs(&[TestOutput::P2WPKH(992_000)]),
			b_shared_input: None,
			shared_output_b: generate_funding_txout(1_000_000, 990_000),
			outputs_b: vec![],
			expect_error: None,
		});

		// They add the funding output, and we contribute a little
		do_test_interactive_tx_constructor(TestSession {
			description: "Funding output by them, small contribution",
			inputs_a: generate_inputs(&[TestOutput::P2WPKH(12_000)]),
			a_shared_input: None,
			shared_output_a: generate_funding_txout(1_000_000, 10_000),
			outputs_a: vec![],
			inputs_b: generate_inputs(&[TestOutput::P2WPKH(992_000)]),
			b_shared_input: None,
			shared_output_b: generate_funding_txout(1_000_000, 990_000),
			outputs_b: vec![],
			expect_error: None,
		});

		// We add the funding output, and we contribute most
		do_test_interactive_tx_constructor(TestSession {
			description: "Funding output by us, large contribution",
			inputs_a: generate_inputs(&[TestOutput::P2WPKH(992_000)]),
			a_shared_input: None,
			shared_output_a: generate_funding_txout(1_000_000, 990_000),
			outputs_a: vec![],
			inputs_b: generate_inputs(&[TestOutput::P2WPKH(12_000)]),
			b_shared_input: None,
			shared_output_b: generate_funding_txout(1_000_000, 10_000),
			outputs_b: vec![],
			expect_error: None,
		});

		// They add the funding output, but we contribute most
		do_test_interactive_tx_constructor(TestSession {
			description: "Funding output by them, large contribution",
			inputs_a: generate_inputs(&[TestOutput::P2WPKH(992_000)]),
			a_shared_input: None,
			shared_output_a: generate_funding_txout(1_000_000, 990_000),
			outputs_a: vec![],
			inputs_b: generate_inputs(&[TestOutput::P2WPKH(12_000)]),
			b_shared_input: None,
			shared_output_b: generate_funding_txout(1_000_000, 10_000),
			outputs_b: vec![],
			expect_error: None,
		});

		// During a splice-out, with peer providing more output value than input value
		// but still pays enough fees due to their to_remote_value_satoshis portion in
		// the shared input.
		do_test_interactive_tx_constructor(TestSession {
			description: "Splice out with sufficient initiator balance",
			inputs_a: generate_inputs(&[TestOutput::P2WPKH(100_000), TestOutput::P2WPKH(50_000)]),
			a_shared_input: None,
			shared_output_a: generate_funding_txout(120_000, 120_000),
			outputs_a: vec![],
			inputs_b: generate_inputs(&[TestOutput::P2WPKH(50_000)]),
			b_shared_input: None,
			shared_output_b: generate_funding_txout(120_000, 0),
			outputs_b: vec![],
			expect_error: None,
		});

		// During a splice-out, with peer providing more output value than input value
		// and the to_remote_value_satoshis portion in
		// the shared input cannot cover fees
		do_test_interactive_tx_constructor(TestSession {
			description: "Splice out with insufficient initiator balance",
			inputs_a: generate_inputs(&[TestOutput::P2WPKH(100_000), TestOutput::P2WPKH(15_000)]),
			a_shared_input: None,
			shared_output_a: generate_funding_txout(120_000, 120_000),
			outputs_a: vec![],
			inputs_b: generate_inputs(&[TestOutput::P2WPKH(85_000)]),
			b_shared_input: None,
			shared_output_b: generate_funding_txout(120_000, 0),
			outputs_b: vec![],
			expect_error: Some((AbortReason::OutputsValueExceedsInputsValue, ErrorCulprit::NodeA)),
		});

		// The intended&expected shared output value differ
		do_test_interactive_tx_constructor(TestSession {
			description: "Splice in, invalid intended local contribution",
			inputs_a: generate_inputs(&[TestOutput::P2WPKH(100_000), TestOutput::P2WPKH(15_000)]),
			a_shared_input: None,
			shared_output_a: generate_funding_txout(100_000, 100_000),
			outputs_a: vec![],
			inputs_b: generate_inputs(&[TestOutput::P2WPKH(85_000)]),
			b_shared_input: None,
			shared_output_b: generate_funding_txout(120_000, 0), // value different
			outputs_b: vec![],
			expect_error: Some((AbortReason::MissingFundingOutput, ErrorCulprit::NodeA)),
		});

		// Provide and expect a shared input
		do_test_interactive_tx_constructor(TestSession {
			description: "Provide and expect a shared input",
			inputs_a: generate_inputs(&[TestOutput::P2WPKH(100_000)]),
			a_shared_input: Some(generate_shared_input(&prev_funding_tx_1, 0, 60_000)),
			shared_output_a: generate_funding_txout(108_000, 108_000),
			outputs_a: vec![],
			inputs_b: vec![],
			b_shared_input: Some(generate_shared_input(&prev_funding_tx_1, 0, 0)),
			shared_output_b: generate_funding_txout(108_000, 0),
			outputs_b: vec![],
			expect_error: None,
		});

		// Expect a shared input, but it's missing
		do_test_interactive_tx_constructor(TestSession {
			description: "Expect a shared input, but it's missing",
			inputs_a: generate_inputs(&[TestOutput::P2WPKH(110_000)]),
			a_shared_input: None,
			shared_output_a: generate_funding_txout(108_000, 108_000),
			outputs_a: vec![],
			inputs_b: vec![],
			b_shared_input: Some(generate_shared_input(&prev_funding_tx_1, 0, 0)),
			shared_output_b: generate_funding_txout(108_000, 0),
			outputs_b: vec![],
			expect_error: Some((AbortReason::MissingFundingInput, ErrorCulprit::NodeA)),
		});

		// Provide a shared input, but it's not expected
		do_test_interactive_tx_constructor(TestSession {
			description: "Provide a shared input, but it's not expected",
			inputs_a: generate_inputs(&[TestOutput::P2WPKH(50_000)]),
			a_shared_input: Some(generate_shared_input(&prev_funding_tx_1, 0, 60_000)),
			shared_output_a: generate_funding_txout(108_000, 108_000),
			outputs_a: vec![],
			inputs_b: vec![],
			b_shared_input: None,
			shared_output_b: generate_funding_txout(108_000, 0),
			outputs_b: vec![],
			expect_error: Some((AbortReason::UnexpectedFundingInput, ErrorCulprit::NodeA)),
		});
	}

	#[test]
	fn test_generate_local_serial_id() {
		let entropy_source = TestEntropySource(AtomicCounter::new());

		// Initiators should have even serial id, non-initiators should have odd serial id.
		assert_eq!(generate_holder_serial_id(&&entropy_source, true) % 2, 0);
		assert_eq!(generate_holder_serial_id(&&entropy_source, false) % 2, 1)
	}

	#[test]
	fn test_calculate_change_output_value_open() {
		let input_prevouts = [
			TxOut {
				value: Amount::from_sat(70_000),
				script_pubkey: ScriptBuf::new_p2wpkh(&WPubkeyHash::all_zeros()),
			},
			TxOut {
				value: Amount::from_sat(60_000),
				script_pubkey: ScriptBuf::new_p2wpkh(&WPubkeyHash::all_zeros()),
			},
		];
		let inputs = input_prevouts
			.iter()
			.map(|txout| {
				let prevtx = Transaction {
					input: Vec::new(),
					output: vec![(*txout).clone()],
					lock_time: AbsoluteLockTime::ZERO,
					version: Version::TWO,
				};

				FundingTxInput::new_p2wpkh(prevtx, 0).unwrap()
			})
			.collect();
		let txout = TxOut { value: Amount::from_sat(10_000), script_pubkey: ScriptBuf::new() };
		let outputs = vec![txout];
		let funding_feerate_sat_per_1000_weight = 3000;

		let total_inputs: Amount = input_prevouts.iter().map(|o| o.value).sum();
		let total_outputs: Amount = outputs.iter().map(|o| o.value).sum();
		let fees = if cfg!(feature = "grind_signatures") {
			Amount::from_sat(1734)
		} else {
			Amount::from_sat(1740)
		};
		let common_fees = Amount::from_sat(234);

		// There is leftover for change
		let context = FundingNegotiationContext {
			is_initiator: true,
			our_funding_contribution: SignedAmount::from_sat(110_000),
			funding_tx_locktime: AbsoluteLockTime::ZERO,
			funding_feerate_sat_per_1000_weight,
			shared_funding_input: None,
			our_funding_inputs: inputs,
			our_funding_outputs: outputs,
			change_script: None,
		};
		let gross_change =
			total_inputs - total_outputs - context.our_funding_contribution.to_unsigned().unwrap();
		assert_eq!(
			calculate_change_output_value(&context, false, &ScriptBuf::new(), 300),
			Ok(Some((gross_change - fees - common_fees).to_sat())),
		);

		// There is leftover for change, without common fees
		let context = FundingNegotiationContext { is_initiator: false, ..context };
		assert_eq!(
			calculate_change_output_value(&context, false, &ScriptBuf::new(), 300),
			Ok(Some((gross_change - fees).to_sat())),
		);

		// Insufficient inputs, no leftover
		let context = FundingNegotiationContext {
			is_initiator: false,
			our_funding_contribution: SignedAmount::from_sat(130_000),
			..context
		};
		assert_eq!(
			calculate_change_output_value(&context, false, &ScriptBuf::new(), 300),
			Err(AbortReason::InsufficientFees),
		);

		// Very small leftover
		let context = FundingNegotiationContext {
			is_initiator: false,
			our_funding_contribution: SignedAmount::from_sat(118_000),
			..context
		};
		assert_eq!(
			calculate_change_output_value(&context, false, &ScriptBuf::new(), 300),
			Ok(None),
		);

		// Small leftover, but not dust
		let context = FundingNegotiationContext {
			is_initiator: false,
			our_funding_contribution: SignedAmount::from_sat(117_992),
			..context
		};
		let gross_change =
			total_inputs - total_outputs - context.our_funding_contribution.to_unsigned().unwrap();
		assert_eq!(
			calculate_change_output_value(&context, false, &ScriptBuf::new(), 100),
			Ok(Some((gross_change - fees).to_sat())),
		);

		// Larger fee, smaller change
		let context = FundingNegotiationContext {
			is_initiator: true,
			our_funding_contribution: SignedAmount::from_sat(110_000),
			funding_feerate_sat_per_1000_weight: funding_feerate_sat_per_1000_weight * 3,
			..context
		};
		let gross_change =
			total_inputs - total_outputs - context.our_funding_contribution.to_unsigned().unwrap();
		assert_eq!(
			calculate_change_output_value(&context, false, &ScriptBuf::new(), 300),
			Ok(Some((gross_change - fees * 3 - common_fees * 3).to_sat())),
		);
	}

	fn do_verify_tx_signatures(
		transaction: Transaction, prev_outputs: Vec<TxOut>,
	) -> Result<(), String> {
		let input_metadata: Vec<TxInMetadata> = prev_outputs
			.into_iter()
			.enumerate()
			.map(|(idx, prev_output)| {
				TxInMetadata {
					serial_id: idx as u64, // even values will be holder (initiator in this test)
					prev_output,
				}
			})
			.collect();

		let unsigned_tx = ConstructedTransaction {
			holder_is_initiator: true,
			input_metadata,
			output_metadata: vec![], // N/A for test
			tx: transaction.clone(),
			shared_input_index: None,
			shared_output_index: 0,
		};

		let secp_ctx = Secp256k1::new();

		InteractiveTxSigningSession {
			unsigned_tx,
			holder_sends_tx_signatures_first: false, // N/A for test
			has_received_commitment_signed: false,   // N/A for test
			shared_input_signature: None,
			holder_tx_signatures: None,
			counterparty_tx_signatures: None,
		}
		.verify_interactive_tx_signatures(
			&secp_ctx,
			&transaction
				.input
				.into_iter()
				.enumerate()
				.filter(|(idx, _)| idx % 2 == 0) // we only want initiator inputs (corresponds to even serial_id)
				.map(|(_, txin)| txin.witness)
				.collect(),
		)
	}

	#[test]
	fn test_verify_tx_signatures_p2tr_key_path_p2wsh_no_sig() {
		// Uses transaction https://mempool.space/tx/c28d01b47b8426039306e4209534fc5235da4a31406179639c54c48212be7655
		let transaction: Transaction = bitcoin::consensus::encode::deserialize_hex("02000000000105d08ef8a4eac88a9568d660732d6e1bd8f216fecb46b7ebc7fc7b5a85e3ba1da50000000000ffffffff3ae09cc085873112f0602cac61e005827e7f21ce03595c6bf1e5ab41643e2e240000000000ffffffff030d20d2b28c4f27797e90ab2259392e99070307f0ee14a621025f8adc9054720000000000100000007d2e78b06110de8ac2298e71fa6fd96e24a287597f3a3fbfaa60837e40453a990000000000100000007d2e78b06110de8ac2298e71fa6fd96e24a287597f3a3fbfaa60837e40453a990100000000100000000104310d01000000002251207434164bd41e2185651f084b6a79e11ce57abe69093b7f939bb1c8786e5d233b0140e612c3728bcc6ed6c4ef67238e57f0332fa77a4c2e76db183e28b7f3cea5eab6b235b6f0cbab8035fd79b3c1990c5c3f3a56e2c7d5e4609b390ddaad8ac1c1d7024730440220036e88464b21c8bd819d97ae746622da00053ec1374a932f33aa1ab60170c9da022041cabc146ebdd12f6316a2f72f870771e8e6ff51f3cadad4027eab2e443770110121030c7196376bc1df61b6da6ee711868fd30e370dd273332bfb02a2287d11e2e9c50200282102fd481d39bdbc090313b530fddfd1aa004a9e3263da1406cf806670fdeb8ebb91ac736460b2680200282102092f44ee333630b985e490dbbc69865e499853cba15a51426d0f4e5906087e55ac736460b26802002821021dadb5ffb2cb74f5427f039e2913738e5cd8e93cc0d12db4cfa4f555005c326aac736460b26800000000").unwrap();
		let prev_outputs =
			vec![
				// Added by holder
				TxOut {
					value: Amount::from_sat(17414236),
					script_pubkey: ScriptBuf::new_p2tr_tweaked(
						TweakedPublicKey::dangerous_assume_tweaked(XOnlyPublicKey::from_slice(
							&<[u8; 32]>::from_hex(
								"7434164bd41e2185651f084b6a79e11ce57abe69093b7f939bb1c8786e5d233b",
							)
							.unwrap(),
						).unwrap()),
					),
				},
				// Added by remote (corresponding input should not be checked)
				TxOut {
					value: Amount::from_sat(227321),
					script_pubkey: ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array(
						<[u8; 20]>::from_hex("92b8c3a56fac121ddcdffbc85b02fb9ef681038a").unwrap(),
					)),
				},
				// Added by holder
				TxOut {
					value: Amount::from_sat(330),
					script_pubkey: ScriptBuf::new_p2wsh(&WScriptHash::from_byte_array(
						<[u8; 32]>::from_hex(
							"97a4f4b73947411e18486b7182063f160f9b3a238664b91ff70a56eaffca8b9d",
						)
						.unwrap(),
					)),
				},
				// Added by remote (corresponding input should not be checked)
				TxOut {
					value: Amount::from_sat(330),
					script_pubkey: ScriptBuf::new_p2wsh(&WScriptHash::from_byte_array(
						<[u8; 32]>::from_hex(
							"0d0f49839e6bbf78271ea31d979895758ed66312b4fbab215da8a68a951f36ee",
						)
						.unwrap(),
					)),
				},
				// Added by holder
				TxOut {
					value: Amount::from_sat(330),
					script_pubkey: ScriptBuf::new_p2wsh(&WScriptHash::from_byte_array(
						<[u8; 32]>::from_hex(
							"f2c42991382f63a20308c35ce67133cd8564ede8f8615062d814ec69112ddd46",
						)
						.unwrap(),
					)),
				}
			];

		assert!(do_verify_tx_signatures(transaction, prev_outputs).is_ok());
	}

	#[test]
	fn test_verify_tx_signatures_p2wpkh_anyonecanpay_should_fail() {
		// Using on-chain transaction: https://mempool.space/tx/fe62d242fbdd57a3bdb0d158b80e3c77754f17653eb23e3b64203076e6966cae
		let transaction: Transaction = bitcoin::consensus::encode::deserialize_hex("020000000001010889a9a8424c16e069d0690b10a035f166ecb0788434703776b8ccf3209cb6c00000000000fdffffff052302000000000000160014bd42e2a4f83e5d905bccf4dcff7bb88e514749054a01000000000000220020003d7374616d703a7b2270223a227372632d3230222c226f70223a227472616e4a0100000000000022002073666572222c227469636b223a2249524f4e42222c22616d74223a3130307d0064530300000000002251202838c8f586f4dcdb5fb080a9c28497287e46cab65c8dcf9de27e659afe2564a61423000000000000160014cc054f448ca15a5aa1b21f2adb6607fec4410b6d02483045022100d84f8fb0f82c22128ba75b54e6c1be27aeee967acfe0a6e624a47acdf20cf3c102200248271599dba21f24ab8593529ca95a2f27aebd953b12c5f8aff3809c9743998121025ede2bca4b5a86da349fb8827eec4bb95afb513bb8c260867bbd55e7d0a2f48d00000000").unwrap();

		let prev_outputs = vec![
			// Added by holder
			TxOut {
				value: Amount::from_sat(228980),
				script_pubkey: ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array(
					<[u8; 20]>::from_hex("cc054f448ca15a5aa1b21f2adb6607fec4410b6d").unwrap(),
				)),
			},
		];

		match do_verify_tx_signatures(transaction, prev_outputs) {
			Ok(_) => panic!("Should not be valid"),
			Err(err) => {
				assert_eq!(
					&err,
					"Signature does not use SIGHASH_ALL for input at index 0 for P2WPKH spend"
				);
			},
		}
	}

	#[test]
	fn test_verify_tx_signatures_p2wsh_with_anyonecanpay_should_fail() {
		// Using on-chain transaction: https://mempool.space/tx/c28d01b47b8426039306e4209534fc5235da4a31406179639c54c48212be7655
		let transaction: Transaction = bitcoin::consensus::encode::deserialize_hex("0200000000010163c80d9fe4cfd02c6e0521a3818ecc1593573c85f0026dd0a57f16c61101d2a10000000000fdffffff02838ef72e0000000022002054313a8b88c0b1f408f8e4ba2a7c71909ebb35ec3e5cc81518c5a797afb48e9d00000000000000000a6a0853594d423a62643304473044022039c1263f05745d0a1c3c7afe40cbaf39a0445f66985c700b5bb7161ac8eece54022057a20fe506aadc254efd4686dd15037be22be965f758ab83498c86893bf8f4a68101010103d55388632103024f3166b9833e75cb2d0695b221e7a86170b9900d43aaa9d62172c51f796fe1ac675321030d8e88d0f843d2671f0762cd8010cb6e96ddf3d1558f593d607f7f261b1b031b210388b5390d3d2a24762d0680474dd26149ab1ae050e18b01ec831cbf0a5914537721023a0ddacf091d5d9430467be66f4a0ecb6ced6bb255ae89b626b9fa74966d42ea21023a0363a3f5afcf71ae05c84f09edb48c2101625a08abc3b8467854cc100187f521029e7fdb5297ff32dd34c52b99aeb09ca64015c787f5e0958c68c25eb8c5de265955ae6800000000").unwrap();

		let prev_outputs = vec![
			// Added by holder
			TxOut {
				value: Amount::from_sat(787976283),
				script_pubkey: ScriptBuf::new_p2wsh(&WScriptHash::from_byte_array(
					<[u8; 32]>::from_hex(
						"54313a8b88c0b1f408f8e4ba2a7c71909ebb35ec3e5cc81518c5a797afb48e9d",
					)
					.unwrap(),
				)),
			},
		];

		match do_verify_tx_signatures(transaction, prev_outputs) {
			Ok(_) => panic!("Should not be valid"),
			Err(err) => {
				assert_eq!(
					&err,
					"An ECDSA signature in the witness for input 0 does not use SIGHASH_ALL"
				);
			},
		}
	}

	#[test]
	fn test_verify_tx_signatures_p2tr_key_path_anyonecanpay_should_fail() {
		// Using on-chain transaction: https://mempool.space/tx/f7636876156f3a8a48a6cddb150e07363c1641495f4b319faab1e8c4527e58db
		let transaction: Transaction = bitcoin::consensus::encode::deserialize_hex("02000000000102977aba41d493f93acc890e49c292dad6cbe423cb1356c6e6191cb93eed3f60c20200000000ffffffff1d956f8838a87c551c308f49fe80da594bfb888209ae8159bc77c6f471dd3b540000000000ffffffff022202000000000000225120fcb2498c6a6a335951f4c96fc89266c388e1ef4c416a2c6fca438a2f5cbb7ffe26d0030000000000225120cbc74f986822b48c4801ef5a1cadc44b27f7d23e699d8244c391d5defd69802a0141b7b9685f6b790e24392670fa06b9af34331bd3308a58b4d8b2cd86a4bcea19a2a780565b410062b58fbff026ab74513f0bac00711eba9f80e3d6b2a7cf3887a1810140a5ae4d75b89e54cfe470eb152e527a403e30b2fb3fdf5dcad1019f015827a1871431dd7202cb520ddcd3b0205cc2b9aafcb6b52522562d381d05cac4522f258100000000").unwrap();

		let prev_outputs =
			vec![
			// Added by holder (SIGHASH_ALL | ACP)
			TxOut {
				value: Amount::from_sat(546),
				script_pubkey: ScriptBuf::new_p2tr_tweaked(
					TweakedPublicKey::dangerous_assume_tweaked(XOnlyPublicKey::from_slice(
						&<[u8; 32]>::from_hex(
							"cbc74f986822b48c4801ef5a1cadc44b27f7d23e699d8244c391d5defd69802a",
						)
						.unwrap(),
					).unwrap()),
				),
			},
			// Added by remote (corresponding input should not be checked)
			TxOut {
				value: Amount::from_sat(250148),
				script_pubkey: ScriptBuf::new_p2tr_tweaked(
					TweakedPublicKey::dangerous_assume_tweaked(XOnlyPublicKey::from_slice(
						&<[u8; 32]>::from_hex(
							"56cee5ccf725d94a428100de365fdfa134ff4deb1a0dca14470e70b4a64ff32b",
						)
						.unwrap(),
					).unwrap()),
				),
			},
		];

		match do_verify_tx_signatures(transaction, prev_outputs) {
			Ok(_) => panic!("Should not be valid"),
			Err(err) => {
				assert_eq!(
					&err,
					"Signature does not use SIGHASH_DEFAULT or SIGHASH_ALL for input at index 0 for P2TR key path spend"
				);
			},
		}
	}

	#[test]
	fn test_verify_tx_signatures_p2wsh_multisig() {
		// Using on-chain transaction: https://mempool.space/tx/c28d01b47b8426039306e4209534fc5235da4a31406179639c54c48212be7655
		let transaction: Transaction = bitcoin::consensus::encode::deserialize_hex("02000000000101d457eb6d1d7b9d0921d24449aede5f45a1e14e8f90aefd12f429e80741c0410d0100000000fdffffff02242c00000000000022002033476d89781e0006ce6a15f0b916cd5d53cf1a0f34d9d44273821148f8299db550340300000000001600146283a887af0a60239b5e18c5409a60cdf0404b8f0400473044022045fa871b357509376288e1933c010c988a55c370182a3d82cf4541a4850ee28c02203f22903165cccc06a124d5058c07c097fca3faf6048b62a9770a2c2eb23078810147304402202bd94f4be066f81ec8dffdef137c8ea99fdd6dcb8f69ee6ce95f8b4b237566f20220080e392372323b383efde7e013f570545103cdb04bf641587350d11cb4c4585b01695221030e17c0365f9f933b5fe08711069fb0e83af497eff9aa69488e13d04698e12c95210383b4b6d2e49bc7f3d211393193ae4a8b0d34d076632764950feb0f11451dcad22103de6d5d777364d5a7b92cf1ae3f45d2f71f2ec88289938e267f2cbc8a88eff33253aeb4d60d00").unwrap();

		let prev_outputs = vec![
			// Added by holder
			TxOut {
				value: Amount::from_sat(221691),
				script_pubkey: ScriptBuf::new_p2wsh(&WScriptHash::from_byte_array(
					<[u8; 32]>::from_hex(
						"dca8b773bb8a3beb76dff2c2998642449ec989d158ce049ec94a1af29b69b008",
					)
					.unwrap(),
				)),
			},
		];

		assert!(do_verify_tx_signatures(transaction, prev_outputs).is_ok());
	}

	#[test]
	fn test_verify_tx_signatures_p2wpkh() {
		// Using on-chain transaction: https://mempool.space/tx/3db96e0b60bb823c55e35560521ec4bb05962ac109400f1e5c56b8fe642958e6
		let transaction: Transaction = bitcoin::consensus::encode::deserialize_hex("02000000000102939dd4cba8ca232c39647e7366c4f1a05ad0102a563b1df4f3befc351ca8c65d0000000000ffffffff58f776fcc31c6b9bfbd5839ea7a6b5da1bfc9bcc9e948f3b4be0792483b7d0e10100000000ffffffff029ad30000000000001600140b29de1e14f8ebc26b65d307b66d521ceb8d40b0e97d01000000000017a9149be05916325c1333820ebc00c80d6bf5c60a52b48702483045022100867147fa982ec6bc73fea19f68efea136f85de113d782bd6810d8b441454c89d02206e14c424bfc99c4edc041c226b1298bdeb2637733fa994d1aba5124befc2f04a012103c297c5a04f842757d1b4a8115c86dedf6e271afff8185eb73d21b45fe3d00e8402483045022100ccc1e6d1b30afa65069e5228e8e962552177e60f25b56f17d31363baaf9c7a5c022056d661653a5ad31760ec8e0bb1be50faa23883aebf4646fabadcdb628766d8a6012103c297c5a04f842757d1b4a8115c86dedf6e271afff8185eb73d21b45fe3d00e8400000000").unwrap();

		let prev_outputs = vec![
			// Added by holder
			TxOut {
				value: Amount::from_sat(104127),
				script_pubkey: ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array(
					<[u8; 20]>::from_hex("0b29de1e14f8ebc26b65d307b66d521ceb8d40b0").unwrap(),
				)),
			},
			// Added by remote (corresponding input should not be checked)
			TxOut {
				value: Amount::from_sat(48509),
				script_pubkey: ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array(
					<[u8; 20]>::from_hex("0b29de1e14f8ebc26b65d307b66d521ceb8d40b0").unwrap(),
				)),
			},
		];

		assert!(do_verify_tx_signatures(transaction, prev_outputs).is_ok());
	}

	#[test]
	fn test_verify_tx_signatures_p2tr_key_path() {
		// Using on-chain transaction: https://mempool.space/tx/d26108e025ada641e4f1163e372c74087c0e471f3756bd3c736854bee9b5a06a
		let transaction: Transaction = bitcoin::consensus::encode::deserialize_hex("020000000001025f17ea06dd80e90a7c59bf2710903d938561f45c08cd3187d379e988f282d3c30000000000fdffffff10146764d4bb7e5fe0503df41a042ff39b175070ab1dd05345cbe1a12ac6fbbd0100000000fdffffff01a04f020000000000220020d55050579d2bcdf9ecfdf75df7741b8ac16d572b5cdf326028b4f3538ad34b5e0140e769ec44d5e30fe84ff5d873ed20d1a8ffa8b444e208b0584e24cb94b798286f46f4ba0d4dedfa279870c6b2e43aee45802128e7227e45a043c6193743c1c3240400483045022100cdf0cedd4e35d23af24e0c786bce5bbb47147e867e72fdb49b165a0fa7cac668022035493bb8f280115846c3475f51f7e1b56ec67dfb73744faa74b47d049e20436f01473044022034e60933f7a42effe174dbbb33ec60c1e4b06df1f0356caffbfae053944b552702207b59f352bb8a6100ca14c6dc486eb17145bde714c26766cd8bc2e0a139b06789014752210329a0c88d99fa89cb9497205a237da07b26737e5382dafca6cf40a3fd454b955021032e80b176382ccb76832cd773cf76cbb89883ea74a5b1bb5fa0e30b0bfc87ed8452ae7ed70d00").unwrap();

		let prev_outputs =
			vec![
			// Added by holder
			TxOut {
				value: Amount::from_sat(25841),
				script_pubkey: ScriptBuf::new_p2tr_tweaked(
					TweakedPublicKey::dangerous_assume_tweaked(XOnlyPublicKey::from_slice(
						&<[u8; 32]>::from_hex(
							"ce78617dd8b31b96b24e89140639f9d87b6c6cf3b2cc8f3ff2b3afa0e505d7ec",
						)
						.unwrap(),
					).unwrap()),
				),
			},
			// Added by remote (corresponding input should not be checked)
			TxOut {
				value: Amount::from_sat(126239),
				script_pubkey: ScriptBuf::new_p2wsh(&WScriptHash::from_byte_array(
					<[u8; 32]>::from_hex(
						"c9b4e860479f930f054949e5a0be58d25958204e819cc1c62f89c48216eaab27",
					)
					.unwrap(),
				)),
			},
		];

		assert!(do_verify_tx_signatures(transaction, prev_outputs).is_ok());
	}

	#[test]
	fn test_verify_tx_signatures_p2tr_script_path() {
		// Using on-chain transaction: https://mempool.space/tx/905ecdf95a84804b192f4dc221cfed4d77959b81ed66013a7e41a6e61e7ed530
		let transaction: Transaction = bitcoin::consensus::encode::deserialize_hex("02000000000101b41b20295ac85fd2ae3e3d02900f1a1e7ddd6139b12e341386189c03d6f5795b0000000000fdffffff0100000000000000003c6a3a546878205361746f7368692120e2889e2f32316d696c20466972737420546170726f6f74206d756c7469736967207370656e64202d426974476f044123b1d4ff27b16af4b0fcb9672df671701a1a7f5a6bb7352b051f461edbc614aa6068b3e5313a174f90f3d95dc4e06f69bebd9cf5a3098fde034b01e69e8e788901400fd4a0d3f36a1f1074cb15838a48f572dc18d412d0f0f0fc1eeda9fa4820c942abb77e4d1a3c2b99ccf4ad29d9189e6e04a017fe611748464449f681bc38cf394420febe583fa77e49089f89b78fa8c116710715d6e40cc5f5a075ef1681550dd3c4ad20d0fa46cb883e940ac3dc5421f05b03859972639f51ed2eccbf3dc5a62e2e1b15ac41c02e44c9e47eaeb4bb313adecd11012dfad435cd72ce71f525329f24d75c5b9432774e148e9209baf3f1656a46986d5f38ddf4e20912c6ac28f48d6bf747469fb100000000").unwrap();

		let prev_outputs =
			vec![
			// Added by holder
			TxOut {
				value: Amount::from_sat(7500),
				script_pubkey: ScriptBuf::new_p2tr_tweaked(
					TweakedPublicKey::dangerous_assume_tweaked(XOnlyPublicKey::from_slice(
						&<[u8; 32]>::from_hex(
							"2fcad7470279652cc5f88b8908678d6f4d57af5627183b03fc8404cb4e16d889",
						)
						.unwrap(),
					).unwrap()),
				),
			},
		];

		assert!(do_verify_tx_signatures(transaction, prev_outputs).is_ok());
	}
}
