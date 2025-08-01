// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

use crate::io_extras::sink;
use crate::prelude::*;

use bitcoin::absolute::LockTime as AbsoluteLockTime;
use bitcoin::amount::Amount;
use bitcoin::consensus::Encodable;
use bitcoin::constants::WITNESS_SCALE_FACTOR;
use bitcoin::policy::MAX_STANDARD_TX_WEIGHT;
use bitcoin::secp256k1::PublicKey;
use bitcoin::transaction::Version;
use bitcoin::{OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Weight, Witness};

use crate::chain::chaininterface::fee_for_weight;
use crate::events::bump_transaction::{BASE_INPUT_WEIGHT, EMPTY_SCRIPT_SIG_WEIGHT};
use crate::ln::chan_utils::FUNDING_TRANSACTION_WITNESS_WEIGHT;
use crate::ln::channel::{FundingNegotiationContext, TOTAL_BITCOIN_SUPPLY_SATOSHIS};
use crate::ln::msgs;
use crate::ln::msgs::{MessageSendEvent, SerialId, TxSignatures};
use crate::ln::types::ChannelId;
use crate::sign::{EntropySource, P2TR_KEY_PATH_WITNESS_WEIGHT, P2WPKH_WITNESS_WEIGHT};
use crate::util::ser::TransactionU16LenLimited;

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

#[derive(Debug, Clone, PartialEq)]
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

	inputs: Vec<NegotiatedTxInput>,
	outputs: Vec<InteractiveTxOutput>,

	local_inputs_value_satoshis: u64,
	local_outputs_value_satoshis: u64,

	remote_inputs_value_satoshis: u64,
	remote_outputs_value_satoshis: u64,

	lock_time: AbsoluteLockTime,
	holder_sends_tx_signatures_first: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NegotiatedTxInput {
	serial_id: SerialId,
	txin: TxIn,
	// The weight of the input including an estimate of its witness weight.
	weight: Weight,
}

impl_writeable_tlv_based!(NegotiatedTxInput, {
	(1, serial_id, required),
	(3, txin, required),
	(5, weight, required),
});

impl_writeable_tlv_based!(ConstructedTransaction, {
	(1, holder_is_initiator, required),
	(3, inputs, required),
	(5, outputs, required),
	(7, local_inputs_value_satoshis, required),
	(9, local_outputs_value_satoshis, required),
	(11, remote_inputs_value_satoshis, required),
	(13, remote_outputs_value_satoshis, required),
	(15, lock_time, required),
	(17, holder_sends_tx_signatures_first, required),
});

impl ConstructedTransaction {
	fn new(context: NegotiationContext) -> Result<Self, AbortReason> {
		if let Some(shared_funding_input) = &context.shared_funding_input {
			if !context.inputs.iter().any(|(_, input)| {
				input.txin().previous_output == shared_funding_input.input.previous_output
			}) {
				return Err(AbortReason::MissingFundingInput);
			}
		}
		if !context
			.outputs
			.iter()
			.any(|(_, output)| *output.tx_out() == context.shared_funding_output.tx_out)
		{
			return Err(AbortReason::MissingFundingOutput);
		}

		let local_inputs_value_satoshis = context
			.inputs
			.iter()
			.fold(0u64, |value, (_, input)| value.saturating_add(input.local_value()));

		let local_outputs_value_satoshis = context
			.outputs
			.iter()
			.fold(0u64, |value, (_, output)| value.saturating_add(output.local_value()));

		let remote_inputs_value_satoshis = context.remote_inputs_value();
		let remote_outputs_value_satoshis = context.remote_outputs_value();
		let mut inputs: Vec<NegotiatedTxInput> =
			context.inputs.into_values().map(|tx_input| tx_input.into_negotiated_input()).collect();
		let mut outputs: Vec<InteractiveTxOutput> = context.outputs.into_values().collect();
		// Inputs and outputs must be sorted by serial_id
		inputs.sort_unstable_by_key(|input| input.serial_id);
		outputs.sort_unstable_by_key(|output| output.serial_id);

		// There is a strict ordering for `tx_signatures` exchange to prevent deadlocks.
		let holder_sends_tx_signatures_first =
			if local_inputs_value_satoshis == remote_inputs_value_satoshis {
				// If the amounts are the same then the peer with the lowest pubkey lexicographically sends its
				// tx_signatures first
				context.holder_node_id.serialize() < context.counterparty_node_id.serialize()
			} else {
				// Otherwise the peer with the lowest contributed input value sends its tx_signatures first.
				local_inputs_value_satoshis < remote_inputs_value_satoshis
			};

		let constructed_tx = Self {
			holder_is_initiator: context.holder_is_initiator,

			local_inputs_value_satoshis,
			local_outputs_value_satoshis,

			remote_inputs_value_satoshis,
			remote_outputs_value_satoshis,

			inputs,
			outputs,

			lock_time: context.tx_locktime,
			holder_sends_tx_signatures_first,
		};

		if constructed_tx.weight().to_wu() > MAX_STANDARD_TX_WEIGHT as u64 {
			return Err(AbortReason::TransactionTooLarge);
		}

		Ok(constructed_tx)
	}

	pub fn weight(&self) -> Weight {
		let inputs_weight = self.inputs.iter().fold(Weight::from_wu(0), |weight, input| {
			weight.checked_add(input.weight).unwrap_or(Weight::MAX)
		});
		let outputs_weight = self.outputs.iter().fold(Weight::from_wu(0), |weight, output| {
			weight.checked_add(get_output_weight(output.script_pubkey())).unwrap_or(Weight::MAX)
		});
		Weight::from_wu(TX_COMMON_FIELDS_WEIGHT)
			.checked_add(inputs_weight)
			.and_then(|weight| weight.checked_add(outputs_weight))
			.unwrap_or(Weight::MAX)
	}

	pub fn build_unsigned_tx(&self) -> Transaction {
		let ConstructedTransaction { inputs, outputs, .. } = self;

		let input: Vec<TxIn> = inputs.iter().map(|input| input.txin.clone()).collect();
		let output: Vec<TxOut> = outputs.iter().map(|output| output.tx_out().clone()).collect();

		Transaction { version: Version::TWO, lock_time: self.lock_time, input, output }
	}

	pub fn outputs(&self) -> impl Iterator<Item = &InteractiveTxOutput> {
		self.outputs.iter()
	}

	pub fn inputs(&self) -> impl Iterator<Item = &NegotiatedTxInput> {
		self.inputs.iter()
	}

	pub fn compute_txid(&self) -> Txid {
		self.build_unsigned_tx().compute_txid()
	}

	/// Adds provided holder witnesses to holder inputs of unsigned transaction.
	///
	/// Note that it is assumed that the witness count equals the holder input count.
	fn add_local_witnesses(&mut self, witnesses: Vec<Witness>) {
		self.inputs
			.iter_mut()
			.filter(|input| {
				!is_serial_id_valid_for_counterparty(self.holder_is_initiator, input.serial_id)
			})
			.map(|input| &mut input.txin)
			.zip(witnesses)
			.for_each(|(input, witness)| input.witness = witness);
	}

	/// Adds counterparty witnesses to counterparty inputs of unsigned transaction.
	///
	/// Note that it is assumed that the witness count equals the counterparty input count.
	fn add_remote_witnesses(&mut self, witnesses: Vec<Witness>) {
		self.inputs
			.iter_mut()
			.filter(|input| {
				is_serial_id_valid_for_counterparty(self.holder_is_initiator, input.serial_id)
			})
			.map(|input| &mut input.txin)
			.zip(witnesses)
			.for_each(|(input, witness)| input.witness = witness);
	}
}

/// The InteractiveTxSigningSession coordinates the signing flow of interactively constructed
/// transactions from exhange of `commitment_signed` to ensuring proper ordering of `tx_signature`
/// message exchange.
///
/// See the specification for more details:
/// https://github.com/lightning/bolts/blob/master/02-peer-protocol.md#the-commitment_signed-message
/// https://github.com/lightning/bolts/blob/master/02-peer-protocol.md#sharing-funding-signatures-tx_signatures
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct InteractiveTxSigningSession {
	unsigned_tx: ConstructedTransaction,
	holder_sends_tx_signatures_first: bool,
	has_received_commitment_signed: bool,
	holder_tx_signatures: Option<TxSignatures>,
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

	pub fn holder_tx_signatures(&self) -> &Option<TxSignatures> {
		&self.holder_tx_signatures
	}

	pub fn received_commitment_signed(&mut self) -> Option<TxSignatures> {
		self.has_received_commitment_signed = true;
		if self.holder_sends_tx_signatures_first {
			self.holder_tx_signatures.clone()
		} else {
			None
		}
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
	/// unsigned transaction.
	pub fn received_tx_signatures(
		&mut self, tx_signatures: TxSignatures,
	) -> Result<(Option<TxSignatures>, Option<Transaction>), ()> {
		if self.remote_inputs_count() != tx_signatures.witnesses.len() {
			return Err(());
		}
		self.unsigned_tx.add_remote_witnesses(tx_signatures.witnesses.clone());

		let holder_tx_signatures = if !self.holder_sends_tx_signatures_first {
			self.holder_tx_signatures.clone()
		} else {
			None
		};

		// Check if the holder has provided its signatures and if so,
		// return the finalized funding transaction.
		let funding_tx_opt = if self.holder_tx_signatures.is_some() {
			Some(self.finalize_funding_tx())
		} else {
			// This means we're still waiting for the holder to provide their signatures.
			None
		};

		Ok((holder_tx_signatures, funding_tx_opt))
	}

	/// Provides the holder witnesses for the unsigned transaction.
	///
	/// Returns an error if the witness count does not equal the holder's input count in the
	/// unsigned transaction.
	pub fn provide_holder_witnesses(
		&mut self, channel_id: ChannelId, witnesses: Vec<Witness>,
	) -> Result<(), ()> {
		if self.local_inputs_count() != witnesses.len() {
			return Err(());
		}

		self.unsigned_tx.add_local_witnesses(witnesses.clone());
		self.holder_tx_signatures = Some(TxSignatures {
			channel_id,
			tx_hash: self.unsigned_tx.compute_txid(),
			witnesses: witnesses.into_iter().collect(),
			shared_input_signature: None,
		});

		Ok(())
	}

	pub fn remote_inputs_count(&self) -> usize {
		self.unsigned_tx
			.inputs
			.iter()
			.filter(|input| {
				is_serial_id_valid_for_counterparty(
					self.unsigned_tx.holder_is_initiator,
					input.serial_id,
				)
			})
			.count()
	}

	pub fn local_inputs_count(&self) -> usize {
		self.unsigned_tx
			.inputs
			.iter()
			.filter(|input| {
				!is_serial_id_valid_for_counterparty(
					self.unsigned_tx.holder_is_initiator,
					input.serial_id,
				)
			})
			.count()
	}

	fn finalize_funding_tx(&mut self) -> Transaction {
		let lock_time = self.unsigned_tx.lock_time;
		let ConstructedTransaction { inputs, outputs, .. } = &mut self.unsigned_tx;

		Transaction {
			version: Version::TWO,
			lock_time,
			input: inputs.iter().cloned().map(|input| input.txin).collect(),
			output: outputs.iter().cloned().map(|output| output.into_tx_out()).collect(),
		}
	}
}

impl_writeable_tlv_based!(InteractiveTxSigningSession, {
	(1, unsigned_tx, required),
	(3, holder_sends_tx_signatures_first, required),
	(5, has_received_commitment_signed, required),
	(7, holder_tx_signatures, required),
});

#[derive(Debug)]
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
	prevtx_outpoints: HashSet<OutPoint>,
	/// The outputs added so far.
	outputs: HashMap<SerialId, InteractiveTxOutput>,
	/// The locktime of the funding transaction.
	tx_locktime: AbsoluteLockTime,
	/// The fee rate used for the transaction
	feerate_sat_per_kw: u32,
}

pub(crate) fn estimate_input_weight(prev_output: &TxOut) -> Weight {
	Weight::from_wu(if prev_output.script_pubkey.is_p2wpkh() {
		P2WPKH_INPUT_WEIGHT_LOWER_BOUND
	} else if prev_output.script_pubkey.is_p2wsh() {
		P2WSH_INPUT_WEIGHT_LOWER_BOUND
	} else if prev_output.script_pubkey.is_p2tr() {
		P2TR_INPUT_WEIGHT_LOWER_BOUND
	} else {
		UNKNOWN_SEGWIT_VERSION_INPUT_WEIGHT_LOWER_BOUND
	})
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
					weight.saturating_add(input.estimate_input_weight().to_wu())
				}),
		)
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

				let previous_output = OutPoint { txid: *shared_txid, vout: msg.prevtx_out };
				if previous_output != shared_funding_input.input.previous_output {
					return Err(AbortReason::UnexpectedFundingInput);
				}

				(InputOwned::Shared(shared_funding_input.clone()), previous_output)
			} else {
				return Err(AbortReason::UnexpectedFundingInput);
			}
		} else if let Some(prevtx) = &msg.prevtx {
			let transaction = prevtx.as_transaction();
			let txid = transaction.compute_txid();

			if let Some(tx_out) = transaction.output.get(msg.prevtx_out as usize) {
				if !tx_out.script_pubkey.is_witness_program() {
					// The receiving node:
					//  - MUST fail the negotiation if:
					//     - the `scriptPubKey` is not a witness program
					return Err(AbortReason::PrevTxOutInvalid);
				}

				let prev_outpoint = OutPoint { txid, vout: msg.prevtx_out };
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

	fn sent_tx_add_input(&mut self, msg: &msgs::TxAddInput) -> Result<(), AbortReason> {
		let vout = msg.prevtx_out as usize;
		let (prev_outpoint, input) = if let Some(shared_input_txid) = msg.shared_input_txid {
			let prev_outpoint = OutPoint { txid: shared_input_txid, vout: msg.prevtx_out };
			if let Some(shared_funding_input) = &self.shared_funding_input {
				(prev_outpoint, InputOwned::Shared(shared_funding_input.clone()))
			} else {
				return Err(AbortReason::UnexpectedFundingInput);
			}
		} else if let Some(prevtx) = &msg.prevtx {
			let prev_txid = prevtx.as_transaction().compute_txid();
			let prev_outpoint = OutPoint { txid: prev_txid, vout: msg.prevtx_out };
			let prev_output = prevtx
				.as_transaction()
				.output
				.get(vout)
				.ok_or(AbortReason::PrevTxOutInvalid)?
				.clone();
			let txin = TxIn {
				previous_output: prev_outpoint,
				sequence: Sequence(msg.sequence),
				..Default::default()
			};
			let single_input =
				SingleOwnedInput { input: txin, prev_tx: prevtx.clone(), prev_output };
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

	fn check_counterparty_fees(
		&self, counterparty_fees_contributed: u64,
	) -> Result<(), AbortReason> {
		let mut counterparty_weight_contributed = self
			.remote_inputs_weight()
			.to_wu()
			.saturating_add(self.remote_outputs_weight().to_wu());
		if !self.holder_is_initiator {
			// if is the non-initiator:
			// 	- the initiator's fees do not cover the common fields (version, segwit marker + flag,
			// 		input count, output count, locktime)
			counterparty_weight_contributed += TX_COMMON_FIELDS_WEIGHT;
		}
		let required_counterparty_contribution_fee =
			fee_for_weight(self.feerate_sat_per_kw, counterparty_weight_contributed);
		if counterparty_fees_contributed < required_counterparty_contribution_fee {
			return Err(AbortReason::InsufficientFees);
		}
		Ok(())
	}

	fn validate_tx(self) -> Result<ConstructedTransaction, AbortReason> {
		// The receiving node:
		// MUST fail the negotiation if:

		// - the peer's total input satoshis is less than their outputs
		let remote_inputs_value = self.remote_inputs_value();
		let remote_outputs_value = self.remote_outputs_value();
		if remote_inputs_value < remote_outputs_value {
			return Err(AbortReason::OutputsValueExceedsInputsValue);
		}

		// - there are more than 252 inputs
		// - there are more than 252 outputs
		if self.inputs.len() > MAX_INPUTS_OUTPUTS_COUNT
			|| self.outputs.len() > MAX_INPUTS_OUTPUTS_COUNT
		{
			return Err(AbortReason::ExceededNumberOfInputsOrOutputs);
		}

		// - the peer's paid feerate does not meet or exceed the agreed feerate (based on the minimum fee).
		self.check_counterparty_fees(remote_inputs_value.saturating_sub(remote_outputs_value))?;

		ConstructedTransaction::new(self)
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
		#[derive(Debug)]
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
				let tx = context.validate_tx()?;
				let signing_session = InteractiveTxSigningSession {
					holder_sends_tx_signatures_first: tx.holder_sends_tx_signatures_first,
					unsigned_tx: tx,
					has_received_commitment_signed: false,
					holder_tx_signatures: None,
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
	DATA &msgs::TxAddInput, TRANSITION sent_tx_add_input,
	DATA &msgs::TxRemoveInput, TRANSITION sent_tx_remove_input,
	DATA &msgs::TxAddOutput, TRANSITION sent_tx_add_output,
	DATA &msgs::TxRemoveOutput, TRANSITION sent_tx_remove_output
]);
define_state_transitions!(TX_COMPLETE, SentChangeMsg, ReceivedTxComplete);
define_state_transitions!(TX_COMPLETE, ReceivedChangeMsg, SentTxComplete);

#[derive(Debug)]
enum StateMachine {
	Indeterminate,
	SentChangeMsg(SentChangeMsg),
	ReceivedChangeMsg(ReceivedChangeMsg),
	SentTxComplete(SentTxComplete),
	ReceivedTxComplete(ReceivedTxComplete),
	NegotiationComplete(NegotiationComplete),
	NegotiationAborted(NegotiationAborted),
}

impl Default for StateMachine {
	fn default() -> Self {
		Self::Indeterminate
	}
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
	define_state_machine_transitions!(sent_tx_add_input, &msgs::TxAddInput, [
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
	prev_tx: TransactionU16LenLimited,
	prev_output: TxOut,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct SharedOwnedInput {
	input: TxIn,
	prev_output: TxOut,
	local_owned: u64,
}

impl SharedOwnedInput {
	pub fn new(input: TxIn, prev_output: TxOut, local_owned: u64) -> Self {
		let value = prev_output.value.to_sat();
		debug_assert!(
			local_owned <= value,
			"SharedOwnedInput: Inconsistent local_owned value {}, larger than prev out value {}",
			local_owned,
			value,
		);
		Self { input, prev_output, local_owned }
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

	pub fn into_tx_in(self) -> TxIn {
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

	fn estimate_input_weight(&self) -> Weight {
		match self {
			InputOwned::Single(single) => estimate_input_weight(&single.prev_output),
			InputOwned::Shared(shared) => estimate_input_weight(&shared.prev_output),
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

impl_writeable_tlv_based!(InteractiveTxOutput, {
	(1, serial_id, required),
	(3, added_by, required),
	(5, output, required),
});

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

	pub fn into_txin(self) -> TxIn {
		self.input.into_tx_in()
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

	pub fn estimate_input_weight(&self) -> Weight {
		self.input.estimate_input_weight()
	}

	fn into_negotiated_input(self) -> NegotiatedTxInput {
		let weight = self.input.estimate_input_weight();
		NegotiatedTxInput { serial_id: self.serial_id, txin: self.input.into_tx_in(), weight }
	}
}

pub(super) struct InteractiveTxConstructor {
	state_machine: StateMachine,
	initiator_first_message: Option<InteractiveTxMessageSend>,
	channel_id: ChannelId,
	inputs_to_contribute: Vec<(SerialId, InputOwned)>,
	outputs_to_contribute: Vec<(SerialId, OutputOwned)>,
}

#[allow(clippy::enum_variant_names)] // Clippy doesn't like the repeated `Tx` prefix here
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

pub(super) struct InteractiveTxMessageSendResult(
	pub Result<InteractiveTxMessageSend, msgs::TxAbort>,
);

impl InteractiveTxMessageSendResult {
	pub fn into_msg_send_event(self, counterparty_node_id: PublicKey) -> MessageSendEvent {
		match self.0 {
			Ok(interactive_tx_msg_send) => {
				interactive_tx_msg_send.into_msg_send_event(counterparty_node_id)
			},
			Err(tx_abort_msg) => {
				MessageSendEvent::SendTxAbort { node_id: counterparty_node_id, msg: tx_abort_msg }
			},
		}
	}
}

// This macro executes a state machine transition based on a provided action.
macro_rules! do_state_transition {
	($self: ident, $transition: ident, $msg: expr) => {{
		let state_machine = core::mem::take(&mut $self.state_machine);
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
	SendTxComplete(InteractiveTxMessageSend, bool),
	NegotiationComplete,
}

impl HandleTxCompleteValue {
	pub fn into_msg_send_event(
		self, counterparty_node_id: PublicKey,
	) -> (Option<MessageSendEvent>, bool) {
		match self {
			HandleTxCompleteValue::SendTxMessage(msg) => {
				(Some(msg.into_msg_send_event(counterparty_node_id)), false)
			},
			HandleTxCompleteValue::SendTxComplete(msg, negotiation_complete) => {
				(Some(msg.into_msg_send_event(counterparty_node_id)), negotiation_complete)
			},
			HandleTxCompleteValue::NegotiationComplete => (None, true),
		}
	}
}

pub(super) struct HandleTxCompleteResult(pub Result<HandleTxCompleteValue, msgs::TxAbort>);

impl HandleTxCompleteResult {
	pub fn into_msg_send_event(
		self, counterparty_node_id: PublicKey,
	) -> (Option<MessageSendEvent>, bool) {
		match self.0 {
			Ok(interactive_tx_msg_send) => {
				interactive_tx_msg_send.into_msg_send_event(counterparty_node_id)
			},
			Err(tx_abort_msg) => (
				Some(MessageSendEvent::SendTxAbort {
					node_id: counterparty_node_id,
					msg: tx_abort_msg,
				}),
				false,
			),
		}
	}
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
	pub inputs_to_contribute: Vec<(TxIn, TransactionU16LenLimited)>,
	pub shared_funding_input: Option<SharedOwnedInput>,
	pub shared_funding_output: SharedOwnedOutput,
	pub outputs_to_contribute: Vec<TxOut>,
}

impl InteractiveTxConstructor {
	/// Instantiates a new `InteractiveTxConstructor`.
	///
	/// If the holder is the initiator, they need to send the first message which is a `TxAddInput`
	/// message.
	pub fn new<ES: Deref>(args: InteractiveTxConstructorArgs<ES>) -> Result<Self, AbortReason>
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

		// Check for the existence of prevouts'
		for (txin, tx) in inputs_to_contribute.iter() {
			let vout = txin.previous_output.vout as usize;
			if tx.as_transaction().output.get(vout).is_none() {
				return Err(AbortReason::PrevTxOutInvalid);
			}
		}
		let mut inputs_to_contribute: Vec<(SerialId, InputOwned)> = inputs_to_contribute
			.into_iter()
			.map(|(txin, tx)| {
				let serial_id = generate_holder_serial_id(entropy_source, is_initiator);
				let vout = txin.previous_output.vout as usize;
				let prev_output = tx.as_transaction().output.get(vout).unwrap().clone(); // checked above
				let input =
					InputOwned::Single(SingleOwnedInput { input: txin, prev_tx: tx, prev_output });
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

		let mut constructor = Self {
			state_machine,
			initiator_first_message: None,
			channel_id,
			inputs_to_contribute,
			outputs_to_contribute,
		};
		// We'll store the first message for the initiator.
		if is_initiator {
			constructor.initiator_first_message = Some(constructor.maybe_send_message()?);
		}
		Ok(constructor)
	}

	pub fn take_initiator_first_message(&mut self) -> Option<InteractiveTxMessageSend> {
		self.initiator_first_message.take()
	}

	fn maybe_send_message(&mut self) -> Result<InteractiveTxMessageSend, AbortReason> {
		// We first attempt to send inputs we want to add, then outputs. Once we are done sending
		// them both, then we always send tx_complete.
		if let Some((serial_id, input)) = self.inputs_to_contribute.pop() {
			let msg = match input {
				InputOwned::Single(single) => msgs::TxAddInput {
					channel_id: self.channel_id,
					serial_id,
					prevtx: Some(single.prev_tx),
					prevtx_out: single.input.previous_output.vout,
					sequence: single.input.sequence.to_consensus_u32(),
					shared_input_txid: None,
				},
				InputOwned::Shared(shared) => msgs::TxAddInput {
					channel_id: self.channel_id,
					serial_id,
					prevtx: None,
					prevtx_out: shared.input.previous_output.vout,
					sequence: shared.input.sequence.to_consensus_u32(),
					shared_input_txid: Some(shared.input.previous_output.txid),
				},
			};
			do_state_transition!(self, sent_tx_add_input, &msg)?;
			Ok(InteractiveTxMessageSend::TxAddInput(msg))
		} else if let Some((serial_id, output)) = self.outputs_to_contribute.pop() {
			let msg = msgs::TxAddOutput {
				channel_id: self.channel_id,
				serial_id,
				sats: output.tx_out().value.to_sat(),
				script: output.tx_out().script_pubkey.clone(),
			};
			do_state_transition!(self, sent_tx_add_output, &msg)?;
			Ok(InteractiveTxMessageSend::TxAddOutput(msg))
		} else {
			let msg = msgs::TxComplete { channel_id: self.channel_id };
			do_state_transition!(self, sent_tx_complete, &msg)?;
			Ok(InteractiveTxMessageSend::TxComplete(msg))
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
					StateMachine::NegotiationComplete(_) => {
						Ok(HandleTxCompleteValue::SendTxComplete(msg_send, true))
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
			StateMachine::NegotiationComplete(_) => Ok(HandleTxCompleteValue::NegotiationComplete),
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
	funding_outputs: &Vec<TxOut>, change_output_dust_limit: u64,
) -> Result<Option<u64>, AbortReason> {
	assert!(context.our_funding_contribution_satoshis > 0);
	let our_funding_contribution_satoshis = context.our_funding_contribution_satoshis as u64;

	let mut total_input_satoshis = 0u64;
	let mut our_funding_inputs_weight = 0u64;
	for (txin, tx) in context.our_funding_inputs.iter() {
		let txid = tx.as_transaction().compute_txid();
		if txin.previous_output.txid != txid {
			return Err(AbortReason::PrevTxOutInvalid);
		}
		let output = tx
			.as_transaction()
			.output
			.get(txin.previous_output.vout as usize)
			.ok_or(AbortReason::PrevTxOutInvalid)?;
		total_input_satoshis = total_input_satoshis.saturating_add(output.value.to_sat());
		let weight = estimate_input_weight(output).to_wu();
		our_funding_inputs_weight = our_funding_inputs_weight.saturating_add(weight);
	}

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
			weight = weight.saturating_add(FUNDING_TRANSACTION_WITNESS_WEIGHT);
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
	use crate::ln::interactivetxs::{
		calculate_change_output_value, generate_holder_serial_id, AbortReason,
		HandleTxCompleteValue, InteractiveTxConstructor, InteractiveTxConstructorArgs,
		InteractiveTxMessageSend, SharedOwnedInput, SharedOwnedOutput, MAX_INPUTS_OUTPUTS_COUNT,
		MAX_RECEIVED_TX_ADD_INPUT_COUNT, MAX_RECEIVED_TX_ADD_OUTPUT_COUNT,
	};
	use crate::ln::types::ChannelId;
	use crate::sign::EntropySource;
	use crate::util::atomic_counter::AtomicCounter;
	use crate::util::ser::TransactionU16LenLimited;
	use bitcoin::absolute::LockTime as AbsoluteLockTime;
	use bitcoin::amount::Amount;
	use bitcoin::hashes::Hash;
	use bitcoin::key::UntweakedPublicKey;
	use bitcoin::opcodes;
	use bitcoin::script::Builder;
	use bitcoin::secp256k1::{Keypair, PublicKey, Secp256k1, SecretKey};
	use bitcoin::transaction::Version;
	use bitcoin::{
		OutPoint, PubkeyHash, ScriptBuf, Sequence, Transaction, TxIn, TxOut, WPubkeyHash, Witness,
	};
	use core::ops::Deref;

	use super::{
		get_output_weight, P2TR_INPUT_WEIGHT_LOWER_BOUND, P2WPKH_INPUT_WEIGHT_LOWER_BOUND,
		P2WSH_INPUT_WEIGHT_LOWER_BOUND, TX_COMMON_FIELDS_WEIGHT,
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
		inputs_a: Vec<(TxIn, TransactionU16LenLimited)>,
		a_shared_input: Option<(OutPoint, TxOut, u64)>,
		/// The funding output, with the value contributed
		shared_output_a: (TxOut, u64),
		outputs_a: Vec<TxOut>,
		inputs_b: Vec<(TxIn, TransactionU16LenLimited)>,
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
				)
			}),
			shared_funding_output: SharedOwnedOutput::new(
				session.shared_output_a.0,
				session.shared_output_a.1,
			),
			outputs_to_contribute: session.outputs_a,
		}) {
			Ok(r) => Some(r),
			Err(abort_reason) => {
				assert_eq!(
					Some((abort_reason, ErrorCulprit::NodeA)),
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
				)
			}),
			shared_funding_output: SharedOwnedOutput::new(
				session.shared_output_b.0,
				session.shared_output_b.1,
			),
			outputs_to_contribute: session.outputs_b,
		}) {
			Ok(r) => Some(r),
			Err(abort_reason) => {
				assert_eq!(
					Some((abort_reason, ErrorCulprit::NodeB)),
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
							HandleTxCompleteValue::SendTxComplete(
								msg_send,
								negotiation_complete,
							) => (Some(msg_send), negotiation_complete),
							HandleTxCompleteValue::NegotiationComplete => (None, true),
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

	fn generate_inputs(outputs: &[TestOutput]) -> Vec<(TxIn, TransactionU16LenLimited)> {
		let tx = generate_tx(outputs);
		let txid = tx.compute_txid();
		tx.output
			.iter()
			.enumerate()
			.map(|(idx, _)| {
				let txin = TxIn {
					previous_output: OutPoint { txid, vout: idx as u32 },
					script_sig: Default::default(),
					sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
					witness: Default::default(),
				};
				(txin, TransactionU16LenLimited::new(tx.clone()).unwrap())
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

	fn generate_fixed_number_of_inputs(count: u16) -> Vec<(TxIn, TransactionU16LenLimited)> {
		// Generate transactions with a total `count` number of outputs such that no transaction has a
		// serialized length greater than u16::MAX.
		let max_outputs_per_prevtx = 1_500;
		let mut remaining = count;
		let mut inputs: Vec<(TxIn, TransactionU16LenLimited)> = Vec::with_capacity(count as usize);

		while remaining > 0 {
			let tx_output_count = remaining.min(max_outputs_per_prevtx);
			remaining -= tx_output_count;

			// Use unique locktime for each tx so outpoints are different across transactions
			let tx = generate_tx_with_locktime(
				&vec![TestOutput::P2WPKH(1_000_000); tx_output_count as usize],
				(1337 + remaining).into(),
			);
			let txid = tx.compute_txid();

			let mut temp: Vec<(TxIn, TransactionU16LenLimited)> = tx
				.output
				.iter()
				.enumerate()
				.map(|(idx, _)| {
					let input = TxIn {
						previous_output: OutPoint { txid, vout: idx as u32 },
						script_sig: Default::default(),
						sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
						witness: Default::default(),
					};
					(input, TransactionU16LenLimited::new(tx.clone()).unwrap())
				})
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
				TEST_FEERATE_SATS_PER_KW,
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
				TEST_FEERATE_SATS_PER_KW,
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
				TEST_FEERATE_SATS_PER_KW,
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

		let tx =
			TransactionU16LenLimited::new(generate_tx(&[TestOutput::P2WPKH(1_000_000)])).unwrap();
		let invalid_sequence_input = TxIn {
			previous_output: OutPoint { txid: tx.as_transaction().compute_txid(), vout: 0 },
			..Default::default()
		};
		do_test_interactive_tx_constructor(TestSession {
			description: "Invalid input sequence from initiator",
			inputs_a: vec![(invalid_sequence_input, tx.clone())],
			a_shared_input: None,
			shared_output_a: generate_funding_txout(1_000_000, 1_000_000),
			outputs_a: vec![],
			inputs_b: vec![],
			b_shared_input: None,
			shared_output_b: generate_funding_txout(1_000_000, 0),
			outputs_b: vec![],
			expect_error: Some((AbortReason::IncorrectInputSequenceValue, ErrorCulprit::NodeA)),
		});
		let duplicate_input = TxIn {
			previous_output: OutPoint { txid: tx.as_transaction().compute_txid(), vout: 0 },
			sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
			..Default::default()
		};
		do_test_interactive_tx_constructor(TestSession {
			description: "Duplicate prevout from initiator",
			inputs_a: vec![(duplicate_input.clone(), tx.clone()), (duplicate_input, tx.clone())],
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
		let duplicate_input = TxIn {
			previous_output: OutPoint { txid: tx.as_transaction().compute_txid(), vout: 0 },
			sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
			..Default::default()
		};
		do_test_interactive_tx_constructor(TestSession {
			description: "Non-initiator uses same prevout as initiator",
			inputs_a: vec![(duplicate_input.clone(), tx.clone())],
			a_shared_input: None,
			shared_output_a: generate_funding_txout(1_000_000, 905_000),
			outputs_a: vec![],
			inputs_b: vec![(duplicate_input.clone(), tx.clone())],
			b_shared_input: None,
			shared_output_b: generate_funding_txout(1_000_000, 95_000),
			outputs_b: vec![],
			expect_error: Some((AbortReason::PrevTxOutInvalid, ErrorCulprit::NodeA)),
		});
		let duplicate_input = TxIn {
			previous_output: OutPoint { txid: tx.as_transaction().compute_txid(), vout: 0 },
			sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
			..Default::default()
		};
		do_test_interactive_tx_constructor(TestSession {
			description: "Non-initiator uses same prevout as initiator",
			inputs_a: vec![(duplicate_input.clone(), tx.clone())],
			a_shared_input: None,
			shared_output_a: generate_funding_txout(1_000_000, 1_000_000),
			outputs_a: vec![],
			inputs_b: vec![(duplicate_input.clone(), tx.clone())],
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
			inputs_a: generate_inputs(&[TestOutput::P2WPKH(50_000)]),
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
			TxOut { value: Amount::from_sat(70_000), script_pubkey: ScriptBuf::new() },
			TxOut { value: Amount::from_sat(60_000), script_pubkey: ScriptBuf::new() },
		];
		let inputs = input_prevouts
			.iter()
			.map(|txout| {
				let tx = Transaction {
					input: Vec::new(),
					output: vec![(*txout).clone()],
					lock_time: AbsoluteLockTime::ZERO,
					version: Version::TWO,
				};
				let txid = tx.compute_txid();
				let txin = TxIn {
					previous_output: OutPoint { txid, vout: 0 },
					script_sig: ScriptBuf::new(),
					sequence: Sequence::ZERO,
					witness: Witness::new(),
				};
				(txin, TransactionU16LenLimited::new(tx).unwrap())
			})
			.collect::<Vec<(TxIn, TransactionU16LenLimited)>>();
		let our_contributed = 110_000;
		let txout = TxOut { value: Amount::from_sat(10_000), script_pubkey: ScriptBuf::new() };
		let outputs = vec![txout];
		let funding_feerate_sat_per_1000_weight = 3000;

		let total_inputs: u64 = input_prevouts.iter().map(|o| o.value.to_sat()).sum();
		let total_outputs: u64 = outputs.iter().map(|o| o.value.to_sat()).sum();
		let gross_change = total_inputs - total_outputs - our_contributed;
		let fees = 1746;
		let common_fees = 234;

		// There is leftover for change
		let context = FundingNegotiationContext {
			is_initiator: true,
			our_funding_contribution_satoshis: our_contributed as i64,
			their_funding_contribution_satoshis: None,
			funding_tx_locktime: AbsoluteLockTime::ZERO,
			funding_feerate_sat_per_1000_weight,
			shared_funding_input: None,
			our_funding_inputs: inputs,
			change_script: None,
		};
		assert_eq!(
			calculate_change_output_value(&context, false, &ScriptBuf::new(), &outputs, 300),
			Ok(Some(gross_change - fees - common_fees)),
		);

		// There is leftover for change, without common fees
		let context = FundingNegotiationContext { is_initiator: false, ..context };
		assert_eq!(
			calculate_change_output_value(&context, false, &ScriptBuf::new(), &outputs, 300),
			Ok(Some(gross_change - fees)),
		);

		// Insufficient inputs, no leftover
		let context = FundingNegotiationContext {
			is_initiator: false,
			our_funding_contribution_satoshis: 130_000,
			..context
		};
		assert_eq!(
			calculate_change_output_value(&context, false, &ScriptBuf::new(), &outputs, 300),
			Err(AbortReason::InsufficientFees),
		);

		// Very small leftover
		let context = FundingNegotiationContext {
			is_initiator: false,
			our_funding_contribution_satoshis: 118_000,
			..context
		};
		assert_eq!(
			calculate_change_output_value(&context, false, &ScriptBuf::new(), &outputs, 300),
			Ok(None),
		);

		// Small leftover, but not dust
		let context = FundingNegotiationContext {
			is_initiator: false,
			our_funding_contribution_satoshis: 117_992,
			..context
		};
		assert_eq!(
			calculate_change_output_value(&context, false, &ScriptBuf::new(), &outputs, 100),
			Ok(Some(262)),
		);

		// Larger fee, smaller change
		let context = FundingNegotiationContext {
			is_initiator: true,
			our_funding_contribution_satoshis: our_contributed as i64,
			funding_feerate_sat_per_1000_weight: funding_feerate_sat_per_1000_weight * 3,
			..context
		};
		assert_eq!(
			calculate_change_output_value(&context, false, &ScriptBuf::new(), &outputs, 300),
			Ok(Some(4060)),
		);
	}
}
