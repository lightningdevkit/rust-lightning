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
use core::ops::Deref;

use bitcoin::blockdata::constants::WITNESS_SCALE_FACTOR;
use bitcoin::consensus::Encodable;
use bitcoin::policy::MAX_STANDARD_TX_WEIGHT;
use bitcoin::secp256k1::PublicKey;
use bitcoin::secp256k1::ecdsa::Signature;
use bitcoin::{
	absolute::LockTime as AbsoluteLockTime, OutPoint, ScriptBuf, Sequence, Transaction, TxIn,
	TxOut, Txid, Weight, Witness,
};

use crate::chain::chaininterface::fee_for_weight;
use crate::events::bump_transaction::{BASE_INPUT_WEIGHT, EMPTY_SCRIPT_SIG_WEIGHT};
use crate::ln::channel::TOTAL_BITCOIN_SUPPLY_SATOSHIS;
use crate::ln::msgs::{CommitmentSigned, SerialId, TxSignatures};
use crate::ln::{msgs, ChannelId};
use crate::sign::{EntropySource, P2TR_KEY_PATH_WITNESS_WEIGHT, P2WPKH_WITNESS_WEIGHT};
use crate::util::ser::TransactionU16LenLimited;

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
	PrevTxOutInvalid,
	ExceededMaximumSatsAllowed,
	ExceededNumberOfInputsOrOutputs,
	TransactionTooLarge,
	BelowDustLimit,
	InvalidOutputScript,
	InsufficientFees,
	OutputsValueExceedsInputsValue,
	InvalidTx,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InteractiveTxInput {
	serial_id: SerialId,
	input: TxIn,
	prev_output: TxOut,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InteractiveTxOutput {
	serial_id: SerialId,
	tx_out: TxOut,
}

impl InteractiveTxOutput {
	pub fn tx_out(&self) -> &TxOut {
		&self.tx_out
	}
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConstructedTransaction {
	holder_is_initiator: bool,

	inputs: Vec<InteractiveTxInput>,
	outputs: Vec<InteractiveTxOutput>,

	local_inputs_value_satoshis: u64,
	local_outputs_value_satoshis: u64,

	remote_inputs_value_satoshis: u64,
	remote_outputs_value_satoshis: u64,

	lock_time: AbsoluteLockTime,
}

impl ConstructedTransaction {
	fn new(context: NegotiationContext) -> Self {
		let local_inputs_value_satoshis = context
			.inputs
			.iter()
			.filter(|(serial_id, _)| {
				!is_serial_id_valid_for_counterparty(context.holder_is_initiator, serial_id)
			})
			.fold(0u64, |value, (_, input)| value.saturating_add(input.prev_output.value));

		let local_outputs_value_satoshis = context
			.outputs
			.iter()
			.filter(|(serial_id, _)| {
				!is_serial_id_valid_for_counterparty(context.holder_is_initiator, serial_id)
			})
			.fold(0u64, |value, (_, output)| value.saturating_add(output.tx_out.value));

		// Keep the inputs&outputs sorted by SerialId
		let mut inputs: Vec<_> = context.inputs.clone().into_values().collect();
		inputs.sort_unstable_by_key(|InteractiveTxInput { serial_id, .. }| *serial_id);
		let mut outputs: Vec<_> = context.outputs.clone().into_values().collect();
		outputs.sort_unstable_by_key(|InteractiveTxOutput { serial_id, .. }| *serial_id);

		Self {
			holder_is_initiator: context.holder_is_initiator,

			local_inputs_value_satoshis,
			local_outputs_value_satoshis,

			remote_inputs_value_satoshis: context.remote_inputs_value(),
			remote_outputs_value_satoshis: context.remote_outputs_value(),

			inputs,
			outputs,

			lock_time: context.tx_locktime,
		}
	}

	pub fn weight(&self) -> Weight {
		let inputs_weight = self.inputs.iter().fold(
			Weight::from_wu(0),
			|weight, InteractiveTxInput { prev_output, .. }| {
				weight.checked_add(estimate_input_weight(prev_output)).unwrap_or(Weight::MAX)
			},
		);
		let outputs_weight = self.outputs.iter().fold(
			Weight::from_wu(0),
			|weight, InteractiveTxOutput { tx_out, .. }| {
				weight.checked_add(get_output_weight(&tx_out.script_pubkey)).unwrap_or(Weight::MAX)
			},
		);
		Weight::from_wu(TX_COMMON_FIELDS_WEIGHT)
			.checked_add(inputs_weight)
			.and_then(|weight| weight.checked_add(outputs_weight))
			.unwrap_or(Weight::MAX)
	}

	pub fn into_unsigned_tx(self) -> Transaction {
		// TODO: remove note
		// Note: no need to sort any more
		let input: Vec<TxIn> =
			self.inputs.into_iter()
			.map(|InteractiveTxInput { input, .. }| input).collect();
		let output: Vec<TxOut> =
			self.outputs.into_iter()
			.map(|InteractiveTxOutput { tx_out, .. }| tx_out).collect();

		Transaction { version: 2, lock_time: self.lock_time, input, output }
	}

	pub fn outputs(&self) -> impl Iterator<Item = &InteractiveTxOutput> {
		self.outputs.iter()
	}

	/// Return all outputs and their index that match the given script pubkey and optionally value.
	pub fn find_output_by_script(&self, script_pubkey: &ScriptBuf, value: Option<u64>) -> Vec<(usize, TxOut)> {
		// TODO: remove note
		// Note: no need to sort any more
		self.outputs.iter()
			.enumerate()
			.filter(|(_idx, outp)| 
				outp.tx_out().script_pubkey == *script_pubkey
				&& (if let Some(v) = value { outp.tx_out().value == v } else { true }) // optionally match value as well
			)
			.map(|(idx, outp)| (idx, outp.tx_out().clone()))
			.collect()
	}

	pub fn inputs(&self) -> impl Iterator<Item = &InteractiveTxInput> {
		self.inputs.iter()
	}

	pub fn txid(&self) -> Txid {
		self.clone().into_unsigned_tx().txid()
	}

	pub fn add_local_witnesses(&mut self, witnesses: Vec<Witness>) {
		self.inputs
			.iter_mut()
			.filter(|InteractiveTxInput { serial_id, .. }| {
				!is_serial_id_valid_for_counterparty(self.holder_is_initiator, serial_id)
			})
			.map(|InteractiveTxInput { input, .. }| input)
			.zip(witnesses.into_iter())
			.for_each(|(input, witness)| input.witness = witness);
	}

	pub fn add_remote_witnesses(&mut self, witnesses: Vec<Witness>) {
		self.inputs
			.iter_mut()
			.filter(|InteractiveTxInput { serial_id, .. }| {
				is_serial_id_valid_for_counterparty(self.holder_is_initiator, serial_id)
			})
			.map(|InteractiveTxInput { input, .. }| input)
			.zip(witnesses.into_iter())
			.for_each(|(input, witness)| input.witness = witness);
	}
}

#[derive(Debug, Clone, PartialEq)]
pub struct InteractiveTxSigningSession {
	pub unsigned_tx: ConstructedTransaction,
	holder_sends_tx_signatures_first: bool,
	sent_commitment_signed: Option<CommitmentSigned>,
	received_commitment_signed: Option<CommitmentSigned>,
	holder_tx_signatures: Option<TxSignatures>,
	counterparty_tx_signatures: Option<TxSignatures>,
	/// #SPLICING
	pub(crate) shared_signature: Option<Signature>,
}

impl InteractiveTxSigningSession {
	pub fn received_commitment_signed(
		&mut self, commitment_signed: CommitmentSigned,
	) -> Option<TxSignatures> {
		self.received_commitment_signed = Some(commitment_signed);
		if self.holder_sends_tx_signatures_first {
			self.holder_tx_signatures.clone()
		} else {
			None
		}
	}

	pub fn received_tx_signatures(
		&mut self, tx_signatures: TxSignatures,
	) -> (Option<TxSignatures>, Option<Transaction>) {
		if self.counterparty_tx_signatures.is_some() {
			return (None, None);
		};
		self.counterparty_tx_signatures = Some(tx_signatures.clone());
		self.unsigned_tx.add_remote_witnesses(tx_signatures.witnesses.clone());

		let holder_tx_signatures = if !self.holder_sends_tx_signatures_first {
			self.holder_tx_signatures.clone()
		} else {
			None
		};

		let funding_tx = if self.holder_tx_signatures.is_some() {
			Some(self.finalize_funding_tx())
		} else {
			None
		};

		(holder_tx_signatures, funding_tx)
	}

	pub fn provide_holder_witnesses(
		&mut self, channel_id: ChannelId, witnesses: Vec<Witness>, shared_signature: Option<Signature>,
	) -> Option<TxSignatures> {
		self.unsigned_tx.add_local_witnesses(witnesses.clone());
		self.holder_tx_signatures = Some(TxSignatures {
			channel_id,
			tx_hash: self.unsigned_tx.txid(),
			witnesses: witnesses.into_iter().map(|witness| witness).collect(),
			funding_outpoint_sig: shared_signature,
		});
		if self.received_commitment_signed.is_some()
			&& (self.holder_sends_tx_signatures_first || self.counterparty_tx_signatures.is_some())
		{
			self.holder_tx_signatures.clone()
		} else {
			None
		}
	}

	pub fn remote_inputs_count(&self) -> usize {
		self.unsigned_tx
			.inputs
			.iter()
			.filter(|InteractiveTxInput { serial_id, .. }| {
				is_serial_id_valid_for_counterparty(self.unsigned_tx.holder_is_initiator, serial_id)
			})
			.count()
	}

	pub fn local_inputs_count(&self) -> usize {
		self.unsigned_tx
			.inputs
			.iter()
			.filter(|InteractiveTxInput { serial_id, .. }| {
				!is_serial_id_valid_for_counterparty(
					self.unsigned_tx.holder_is_initiator,
					serial_id,
				)
			})
			.count()
	}

	fn finalize_funding_tx(&mut self) -> Transaction {
		let lock_time = self.unsigned_tx.lock_time;
		// TODO: remove note
		// Note: no need to sort any more
		let input = self.unsigned_tx.inputs.iter().cloned()
			.map(|InteractiveTxInput { input, .. }| input).collect();
		let output = self.unsigned_tx.outputs.iter().cloned()
			.map(|InteractiveTxOutput { tx_out, .. }| tx_out).collect();

		Transaction {
			version: 2,
			lock_time,
			input,
			output,
		}
	}

	pub fn counterparty_tx_signatures(&self) -> Option<TxSignatures> {
		self.counterparty_tx_signatures.clone()
	}
}

#[derive(Debug)]
struct NegotiationContext {
	holder_node_id: PublicKey,
	counterparty_node_id: PublicKey,
	holder_is_initiator: bool,
	received_tx_add_input_count: u16,
	received_tx_add_output_count: u16,
	inputs: HashMap<SerialId, InteractiveTxInput>,
	prevtx_outpoints: HashSet<OutPoint>,
	outputs: HashMap<SerialId, InteractiveTxOutput>,
	tx_locktime: AbsoluteLockTime,
	feerate_sat_per_kw: u32,
}

pub(crate) fn estimate_input_weight(prev_output: &TxOut) -> Weight {
	Weight::from_wu(if prev_output.script_pubkey.is_v0_p2wpkh() {
		P2WPKH_INPUT_WEIGHT_LOWER_BOUND
	} else if prev_output.script_pubkey.is_v0_p2wsh() {
		P2WSH_INPUT_WEIGHT_LOWER_BOUND
	} else if prev_output.script_pubkey.is_v1_p2tr() {
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

fn is_serial_id_valid_for_counterparty(holder_is_initiator: bool, serial_id: &SerialId) -> bool {
	// A received `SerialId`'s parity must match the role of the counterparty.
	holder_is_initiator == serial_id.is_for_non_initiator()
}

impl NegotiationContext {
	fn is_serial_id_valid_for_counterparty(&self, serial_id: &SerialId) -> bool {
		is_serial_id_valid_for_counterparty(self.holder_is_initiator, serial_id)
	}

	fn remote_inputs_value(&self) -> u64 {
		self.inputs
			.iter()
			.filter(|(serial_id, _)| self.is_serial_id_valid_for_counterparty(serial_id))
			.fold(0u64, |acc, (_, InteractiveTxInput { prev_output, .. })| {
				acc.saturating_add(prev_output.value)
			})
	}

	fn remote_outputs_value(&self) -> u64 {
		self.outputs
			.iter()
			.filter(|(serial_id, _)| self.is_serial_id_valid_for_counterparty(serial_id))
			.fold(0u64, |acc, (_, InteractiveTxOutput { tx_out, .. })| {
				acc.saturating_add(tx_out.value)
			})
	}

	fn remote_inputs_weight(&self) -> Weight {
		Weight::from_wu(
			self.inputs
				.iter()
				.filter(|(serial_id, _)| self.is_serial_id_valid_for_counterparty(serial_id))
				.fold(0u64, |weight, (_, InteractiveTxInput { prev_output, .. })| {
					weight.saturating_add(estimate_input_weight(prev_output).to_wu())
				}),
		)
	}

	fn remote_outputs_weight(&self) -> Weight {
		Weight::from_wu(
			self.outputs
				.iter()
				.filter(|(serial_id, _)| self.is_serial_id_valid_for_counterparty(serial_id))
				.fold(0u64, |weight, (_, InteractiveTxOutput { tx_out, .. })| {
					weight.saturating_add(get_output_weight(&tx_out.script_pubkey).to_wu())
				}),
		)
	}

	fn local_inputs_value(&self) -> u64 {
		self.inputs
			.iter()
			.filter(|(serial_id, _)| !self.is_serial_id_valid_for_counterparty(serial_id))
			.fold(0u64, |acc, (_, InteractiveTxInput { prev_output, .. })| {
				acc.saturating_add(prev_output.value)
			})
	}

	fn should_holder_send_tx_signatures_first(&self) -> bool {
		// There is a strict ordering for `tx_signatures` exchange to prevent deadlocks.
		let holder_inputs_value = self.local_inputs_value();
		let counterparty_inputs_value = self.remote_inputs_value();

		if holder_inputs_value == counterparty_inputs_value {
			// If the amounts are the same then the peer with the lowest pubkey lexicographically sends its
			// tx_signatures first
			self.holder_node_id < self.counterparty_node_id
		} else {
			// Otherwise the peer with the lowest contributed input value sends its tx_signatures first.
			holder_inputs_value < counterparty_inputs_value
		}
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

		let transaction = msg.prevtx.as_transaction();
		let txid = transaction.txid();

		if let Some(tx_out) = transaction.output.get(msg.prevtx_out as usize) {
			if !tx_out.script_pubkey.is_witness_program() {
				// The receiving node:
				//  - MUST fail the negotiation if:
				//     - the `scriptPubKey` is not a witness program
				return Err(AbortReason::PrevTxOutInvalid);
			}

			if !self.prevtx_outpoints.insert(OutPoint { txid, vout: msg.prevtx_out }) {
				// The receiving node:
				//  - MUST fail the negotiation if:
				//     - the `prevtx` and `prevtx_vout` are identical to a previously added
				//       (and not removed) input's
				return Err(AbortReason::PrevTxOutInvalid);
			}
		} else {
			// The receiving node:
			//  - MUST fail the negotiation if:
			//     - `prevtx_vout` is greater or equal to the number of outputs on `prevtx`
			return Err(AbortReason::PrevTxOutInvalid);
		}

		let prev_out = if let Some(prev_out) = transaction.output.get(msg.prevtx_out as usize) {
			prev_out.clone()
		} else {
			return Err(AbortReason::PrevTxOutInvalid);
		};
		match self.inputs.entry(msg.serial_id) {
			hash_map::Entry::Occupied(_) => {
				// The receiving node:
				//  - MUST fail the negotiation if:
				//    - the `serial_id` is already included in the transaction
				Err(AbortReason::DuplicateSerialId)
			},
			hash_map::Entry::Vacant(entry) => {
				let prev_outpoint = OutPoint { txid, vout: msg.prevtx_out };
				entry.insert(InteractiveTxInput {
					serial_id: msg.serial_id,
					input: TxIn {
						previous_output: prev_outpoint,
						sequence: Sequence(msg.sequence),
						..Default::default()
					},
					prev_output: prev_out,
				});
				self.prevtx_outpoints.insert(prev_outpoint);
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

		if msg.sats < msg.script.dust_value().to_sat() {
			// The receiving node:
			// - MUST fail the negotiation if:
			//		- the sats amount is less than the dust_limit
			return Err(AbortReason::BelowDustLimit);
		}

		// Check that adding this output would not cause the total output value to exceed the total
		// bitcoin supply.
		let mut outputs_value: u64 = 0;
		for output in self.outputs.iter() {
			outputs_value = outputs_value.saturating_add(output.1.tx_out.value);
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
		if !(msg.script.is_v0_p2wpkh()
			|| msg.script.is_v0_p2wsh()
			|| (msg.script.is_witness_program()
				&& msg.script.witness_version().map(|v| v.to_num() >= 1).unwrap_or(false)))
		{
			return Err(AbortReason::InvalidOutputScript);
		}

		match self.outputs.entry(msg.serial_id) {
			hash_map::Entry::Occupied(_) => {
				// The receiving node:
				//  - MUST fail the negotiation if:
				//    - the `serial_id` is already included in the transaction
				Err(AbortReason::DuplicateSerialId)
			},
			hash_map::Entry::Vacant(entry) => {
				entry.insert(InteractiveTxOutput {
					serial_id: msg.serial_id,
					tx_out: TxOut { value: msg.sats, script_pubkey: msg.script.clone() },
				});
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
		let tx = msg.prevtx.as_transaction();
		let input = TxIn {
			previous_output: OutPoint { txid: tx.txid(), vout: msg.prevtx_out },
			sequence: Sequence(msg.sequence),
			..Default::default()
		};
		let prev_output =
			tx.output.get(msg.prevtx_out as usize).ok_or(AbortReason::PrevTxOutInvalid)?.clone();
		if !self.prevtx_outpoints.insert(input.previous_output) {
			// We have added an input that already exists
			return Err(AbortReason::PrevTxOutInvalid);
		}
		self.inputs.insert(
			msg.serial_id,
			InteractiveTxInput { serial_id: msg.serial_id, input, prev_output },
		);
		Ok(())
	}

	fn sent_tx_add_output(&mut self, msg: &msgs::TxAddOutput) -> Result<(), AbortReason> {
		self.outputs.insert(
			msg.serial_id,
			InteractiveTxOutput {
				serial_id: msg.serial_id,
				tx_out: TxOut { value: msg.sats, script_pubkey: msg.script.clone() },
			},
		);
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
		let counterparty_weight_contributed = self
			.remote_inputs_weight()
			.to_wu()
			.saturating_add(self.remote_outputs_weight().to_wu());
		let mut required_counterparty_contribution_fee =
			fee_for_weight(self.feerate_sat_per_kw, counterparty_weight_contributed);
		if !self.holder_is_initiator {
			// if is the non-initiator:
			// 	- the initiator's fees do not cover the common fields (version, segwit marker + flag,
			// 		input count, output count, locktime)
			let tx_common_fields_fee =
				fee_for_weight(self.feerate_sat_per_kw, TX_COMMON_FIELDS_WEIGHT);
			required_counterparty_contribution_fee += tx_common_fields_fee;
		}
		if counterparty_fees_contributed < required_counterparty_contribution_fee {
			return Err(AbortReason::InsufficientFees);
		}
		Ok(())
	}

	fn validate_tx(self) -> Result<(ConstructedTransaction, bool), AbortReason> {
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

		let holder_sends_tx_signatures_first = self.should_holder_send_tx_signatures_first();

		let constructed_tx = ConstructedTransaction::new(self);

		if constructed_tx.weight().to_wu() > MAX_STANDARD_TX_WEIGHT as u64 {
			return Err(AbortReason::TransactionTooLarge);
		}

		Ok((constructed_tx, holder_sends_tx_signatures_first))
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
				let (tx, holder_sends_tx_signatures_first) = context.validate_tx()?;
				let signing_session = InteractiveTxSigningSession {
					holder_sends_tx_signatures_first,
					unsigned_tx: tx,
					sent_commitment_signed: None,
					received_commitment_signed: None,
					holder_tx_signatures: None,
					counterparty_tx_signatures: None,
					shared_signature: None,
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
	) -> Self {
		let context = NegotiationContext {
			tx_locktime,
			holder_node_id,
			counterparty_node_id,
			holder_is_initiator: is_initiator,
			received_tx_add_input_count: 0,
			received_tx_add_output_count: 0,
			inputs: new_hash_map(),
			prevtx_outpoints: new_hash_set(),
			outputs: new_hash_map(),
			feerate_sat_per_kw,
		};
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

pub(crate) struct InteractiveTxConstructor {
	state_machine: StateMachine,
	channel_id: ChannelId,
	inputs_to_contribute: Vec<(SerialId, TxIn, TransactionU16LenLimited)>,
	outputs_to_contribute: Vec<(SerialId, TxOut)>,
}

pub(crate) enum InteractiveTxMessageSend {
	TxAddInput(msgs::TxAddInput),
	TxAddOutput(msgs::TxAddOutput),
	TxComplete(msgs::TxComplete),
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

pub(crate) enum HandleTxCompleteValue {
	SendTxMessage(InteractiveTxMessageSend),
	SendTxComplete(InteractiveTxMessageSend, InteractiveTxSigningSession),
	NegotiationComplete(InteractiveTxSigningSession),
}

impl InteractiveTxConstructor {
	/// Instantiates a new `InteractiveTxConstructor`.
	///
	/// A tuple is returned containing the newly instantiate `InteractiveTxConstructor` and optionally
	/// an initial wrapped `Tx_` message which the holder needs to send to the counterparty.
	pub fn new<ES: Deref>(
		entropy_source: &ES, channel_id: ChannelId, feerate_sat_per_kw: u32,
		holder_node_id: PublicKey, counterparty_node_id: PublicKey, is_initiator: bool,
		funding_tx_locktime: AbsoluteLockTime,
		inputs_to_contribute: Vec<(TxIn, TransactionU16LenLimited)>,
		outputs_to_contribute: Vec<TxOut>,
	) -> (Self, Option<InteractiveTxMessageSend>)
	where
		ES::Target: EntropySource,
	{
		let state_machine = StateMachine::new(
			holder_node_id,
			counterparty_node_id,
			feerate_sat_per_kw,
			is_initiator,
			funding_tx_locktime,
		);
		let mut inputs_to_contribute: Vec<(SerialId, TxIn, TransactionU16LenLimited)> =
			inputs_to_contribute
				.into_iter()
				.map(|(input, tx)| {
					let serial_id = generate_holder_serial_id(entropy_source, is_initiator);
					(serial_id, input, tx)
				})
				.collect();
		// We'll sort by the randomly generated serial IDs, effectively shuffling the order of the inputs
		// as the user passed them to us to avoid leaking any potential categorization of transactions
		// before we pass any of the inputs to the counterparty.
		inputs_to_contribute.sort_unstable_by_key(|(serial_id, _, _)| *serial_id);
		let mut outputs_to_contribute: Vec<(SerialId, TxOut)> = outputs_to_contribute
			.into_iter()
			.map(|output| {
				let serial_id = generate_holder_serial_id(entropy_source, is_initiator);
				(serial_id, output)
			})
			.collect();
		// In the same manner and for the same rationale as the inputs above, we'll shuffle the outputs.
		outputs_to_contribute.sort_unstable_by_key(|(serial_id, _)| *serial_id);
		let mut constructor =
			Self { state_machine, channel_id, inputs_to_contribute, outputs_to_contribute };
		let message_send = if is_initiator {
			match constructor.maybe_send_message() {
				Ok(msg_send) => Some(msg_send),
				Err(_) => {
					debug_assert!(
						false,
						"We should always be able to start our state machine successfully"
					);
					None
				},
			}
		} else {
			None
		};
		(constructor, message_send)
	}

	fn maybe_send_message(&mut self) -> Result<InteractiveTxMessageSend, AbortReason> {
		// We first attempt to send inputs we want to add, then outputs. Once we are done sending
		// them both, then we always send tx_complete.
		if let Some((serial_id, input, prevtx)) = self.inputs_to_contribute.pop() {
			let msg = msgs::TxAddInput {
				channel_id: self.channel_id,
				serial_id,
				prevtx,
				prevtx_out: input.previous_output.vout,
				sequence: input.sequence.to_consensus_u32(),
			};
			do_state_transition!(self, sent_tx_add_input, &msg)?;
			Ok(InteractiveTxMessageSend::TxAddInput(msg))
		} else if let Some((serial_id, output)) = self.outputs_to_contribute.pop() {
			let msg = msgs::TxAddOutput {
				channel_id: self.channel_id,
				serial_id,
				sats: output.value,
				script: output.script_pubkey,
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
					StateMachine::NegotiationComplete(s) => {
						Ok(HandleTxCompleteValue::SendTxComplete(msg_send, s.0.clone()))
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
			StateMachine::NegotiationComplete(s) => {
				Ok(HandleTxCompleteValue::NegotiationComplete(s.0.clone()))
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
}

#[cfg(test)]
mod tests {
	use crate::chain::chaininterface::{fee_for_weight, FEERATE_FLOOR_SATS_PER_KW};
	use crate::ln::channel::TOTAL_BITCOIN_SUPPLY_SATOSHIS;
	use crate::ln::interactivetxs::{
		generate_holder_serial_id, AbortReason, HandleTxCompleteValue, InteractiveTxConstructor,
		InteractiveTxMessageSend, MAX_INPUTS_OUTPUTS_COUNT, MAX_RECEIVED_TX_ADD_INPUT_COUNT,
		MAX_RECEIVED_TX_ADD_OUTPUT_COUNT,
	};
	use crate::ln::ChannelId;
	use crate::sign::EntropySource;
	use crate::util::atomic_counter::AtomicCounter;
	use crate::util::ser::TransactionU16LenLimited;
	use bitcoin::blockdata::opcodes;
	use bitcoin::blockdata::script::Builder;
	use bitcoin::hashes::Hash;
	use bitcoin::key::UntweakedPublicKey;
	use bitcoin::secp256k1::{KeyPair, PublicKey, Secp256k1, SecretKey};
	use bitcoin::{
		absolute::LockTime as AbsoluteLockTime, OutPoint, Sequence, Transaction, TxIn, TxOut,
	};
	use bitcoin::{PubkeyHash, ScriptBuf, WPubkeyHash, WScriptHash};
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
			let increment = self.0.get_increment();
			for i in 0..32 {
				// Rotate the increment value by 'i' bits to the right, to avoid clashes
				// when `generate_local_serial_id` does a parity flip on consecutive calls for the
				// same party.
				let rotated_increment = increment.rotate_right(i as u32);
				res[i] = (rotated_increment & 0xff) as u8;
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
		outputs_a: Vec<TxOut>,
		inputs_b: Vec<(TxIn, TransactionU16LenLimited)>,
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
		let tx_locktime = AbsoluteLockTime::from_height(1337).unwrap();
		let holder_node_id = PublicKey::from_secret_key(
			&Secp256k1::signing_only(),
			&SecretKey::from_slice(&[42; 32]).unwrap(),
		);
		let counterparty_node_id = PublicKey::from_secret_key(
			&Secp256k1::signing_only(),
			&SecretKey::from_slice(&[43; 32]).unwrap(),
		);

		let (mut constructor_a, first_message_a) = InteractiveTxConstructor::new(
			entropy_source,
			channel_id,
			TEST_FEERATE_SATS_PER_KW,
			holder_node_id,
			counterparty_node_id,
			true, // is_initiator
			tx_locktime,
			session.inputs_a,
			session.outputs_a,
		);
		let (mut constructor_b, first_message_b) = InteractiveTxConstructor::new(
			entropy_source,
			channel_id,
			TEST_FEERATE_SATS_PER_KW,
			holder_node_id,
			counterparty_node_id,
			false, // is_initiator
			tx_locktime,
			session.inputs_b,
			session.outputs_b,
		);

		let handle_message_send =
			|msg: InteractiveTxMessageSend, for_constructor: &mut InteractiveTxConstructor| {
				match msg {
					InteractiveTxMessageSend::TxAddInput(msg) => for_constructor
						.handle_tx_add_input(&msg)
						.map(|msg_send| (Some(msg_send), None)),
					InteractiveTxMessageSend::TxAddOutput(msg) => for_constructor
						.handle_tx_add_output(&msg)
						.map(|msg_send| (Some(msg_send), None)),
					InteractiveTxMessageSend::TxComplete(msg) => {
						for_constructor.handle_tx_complete(&msg).map(|value| match value {
							HandleTxCompleteValue::SendTxMessage(msg_send) => {
								(Some(msg_send), None)
							},
							HandleTxCompleteValue::SendTxComplete(msg_send, tx) => {
								(Some(msg_send), Some(tx))
							},
							HandleTxCompleteValue::NegotiationComplete(tx) => (None, Some(tx)),
						})
					},
				}
			};

		assert!(first_message_b.is_none());
		let mut message_send_a = first_message_a;
		let mut message_send_b = None;
		let mut final_tx_a = None;
		let mut final_tx_b = None;
		while final_tx_a.is_none() || final_tx_b.is_none() {
			if let Some(message_send_a) = message_send_a.take() {
				match handle_message_send(message_send_a, &mut constructor_b) {
					Ok((msg_send, interactive_signing_session)) => {
						message_send_b = msg_send;
						final_tx_b =
							interactive_signing_session.map(|session| session.unsigned_tx.txid());
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
						assert!(message_send_b.is_none());
						return;
					},
				}
			}
			if let Some(message_send_b) = message_send_b.take() {
				match handle_message_send(message_send_b, &mut constructor_a) {
					Ok((msg_send, interactive_signing_session)) => {
						message_send_a = msg_send;
						final_tx_a =
							interactive_signing_session.map(|session| session.unsigned_tx.txid());
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
						assert!(message_send_a.is_none());
						return;
					},
				}
			}
		}
		assert!(message_send_a.is_none());
		assert!(message_send_b.is_none());
		assert_eq!(final_tx_a.unwrap(), final_tx_b.unwrap());
		assert!(session.expect_error.is_none(), "Test: {}", session.description);
	}

	#[derive(Debug, Clone, Copy)]
	enum TestOutput {
		P2WPKH(u64),
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
			TestOutput::P2WPKH(value) => {
				(*value, ScriptBuf::new_v0_p2wpkh(&WPubkeyHash::from_slice(&[1; 20]).unwrap()))
			},
			TestOutput::P2WSH(value) => {
				(*value, ScriptBuf::new_v0_p2wsh(&WScriptHash::from_slice(&[2; 32]).unwrap()))
			},
			TestOutput::P2TR(value) => (
				*value,
				ScriptBuf::new_v1_p2tr(
					&secp_ctx,
					UntweakedPublicKey::from_keypair(
						&KeyPair::from_seckey_slice(&secp_ctx, &[3; 32]).unwrap(),
					)
					.0,
					None,
				),
			),
			TestOutput::P2PKH(value) => {
				(*value, ScriptBuf::new_p2pkh(&PubkeyHash::from_slice(&[4; 20]).unwrap()))
			},
		};

		TxOut { value, script_pubkey }
	}

	fn generate_tx_with_locktime(outputs: &[TestOutput], locktime: u32) -> Transaction {
		Transaction {
			version: 2,
			lock_time: AbsoluteLockTime::from_height(locktime).unwrap(),
			input: vec![TxIn { ..Default::default() }],
			output: outputs.iter().map(generate_txout).collect(),
		}
	}

	fn generate_inputs(outputs: &[TestOutput]) -> Vec<(TxIn, TransactionU16LenLimited)> {
		let tx = generate_tx(outputs);
		let txid = tx.txid();
		tx.output
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
			.collect()
	}

	fn generate_p2wsh_script_pubkey() -> ScriptBuf {
		Builder::new().push_opcode(opcodes::OP_TRUE).into_script().to_v0_p2wsh()
	}

	fn generate_p2wpkh_script_pubkey() -> ScriptBuf {
		ScriptBuf::new_v0_p2wpkh(&WPubkeyHash::from_slice(&[1; 20]).unwrap())
	}

	fn generate_outputs(outputs: &[TestOutput]) -> Vec<TxOut> {
		outputs.iter().map(generate_txout).collect()
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
			let txid = tx.txid();

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
		TxOut { value, script_pubkey: generate_p2sh_script_pubkey() }
	}

	#[test]
	fn test_interactive_tx_constructor() {
		do_test_interactive_tx_constructor(TestSession {
			description: "No contributions",
			inputs_a: vec![],
			outputs_a: vec![],
			inputs_b: vec![],
			outputs_b: vec![],
			expect_error: Some((AbortReason::InsufficientFees, ErrorCulprit::NodeA)),
		});
		do_test_interactive_tx_constructor(TestSession {
			description: "Single contribution, no initiator inputs",
			inputs_a: vec![],
			outputs_a: generate_outputs(&[TestOutput::P2WPKH(1_000_000)]),
			inputs_b: vec![],
			outputs_b: vec![],
			expect_error: Some((AbortReason::OutputsValueExceedsInputsValue, ErrorCulprit::NodeA)),
		});
		do_test_interactive_tx_constructor(TestSession {
			description: "Single contribution, no initiator outputs",
			inputs_a: generate_inputs(&[TestOutput::P2WPKH(1_000_000)]),
			outputs_a: vec![],
			inputs_b: vec![],
			outputs_b: vec![],
			expect_error: None,
		});
		do_test_interactive_tx_constructor(TestSession {
			description: "Single contribution, no fees",
			inputs_a: generate_inputs(&[TestOutput::P2WPKH(1_000_000)]),
			outputs_a: generate_outputs(&[TestOutput::P2WPKH(1_000_000)]),
			inputs_b: vec![],
			outputs_b: vec![],
			expect_error: Some((AbortReason::InsufficientFees, ErrorCulprit::NodeA)),
		});
		let p2wpkh_fee = fee_for_weight(TEST_FEERATE_SATS_PER_KW, P2WPKH_INPUT_WEIGHT_LOWER_BOUND);
		let outputs_fee = fee_for_weight(
			TEST_FEERATE_SATS_PER_KW,
			get_output_weight(&generate_p2wpkh_script_pubkey()).to_wu(),
		);
		let tx_common_fields_fee =
			fee_for_weight(TEST_FEERATE_SATS_PER_KW, TX_COMMON_FIELDS_WEIGHT);
		do_test_interactive_tx_constructor(TestSession {
			description: "Single contribution, with P2WPKH input, insufficient fees",
			inputs_a: generate_inputs(&[TestOutput::P2WPKH(1_000_000)]),
			outputs_a: generate_outputs(&[TestOutput::P2WPKH(
				1_000_000 - p2wpkh_fee - outputs_fee - tx_common_fields_fee + 1, /* makes fees insuffcient for initiator */
			)]),
			inputs_b: vec![],
			outputs_b: vec![],
			expect_error: Some((AbortReason::InsufficientFees, ErrorCulprit::NodeA)),
		});
		do_test_interactive_tx_constructor(TestSession {
			description: "Single contribution with P2WPKH input, sufficient fees",
			inputs_a: generate_inputs(&[TestOutput::P2WPKH(1_000_000)]),
			outputs_a: generate_outputs(&[TestOutput::P2WPKH(
				1_000_000 - p2wpkh_fee - outputs_fee - tx_common_fields_fee,
			)]),
			inputs_b: vec![],
			outputs_b: vec![],
			expect_error: None,
		});
		let p2wsh_fee = fee_for_weight(TEST_FEERATE_SATS_PER_KW, P2WSH_INPUT_WEIGHT_LOWER_BOUND);
		do_test_interactive_tx_constructor(TestSession {
			description: "Single contribution, with P2WSH input, insufficient fees",
			inputs_a: generate_inputs(&[TestOutput::P2WSH(1_000_000)]),
			outputs_a: generate_outputs(&[TestOutput::P2WPKH(
				1_000_000 - p2wsh_fee - outputs_fee - tx_common_fields_fee + 1, /* makes fees insuffcient for initiator */
			)]),
			inputs_b: vec![],
			outputs_b: vec![],
			expect_error: Some((AbortReason::InsufficientFees, ErrorCulprit::NodeA)),
		});
		do_test_interactive_tx_constructor(TestSession {
			description: "Single contribution with P2WSH input, sufficient fees",
			inputs_a: generate_inputs(&[TestOutput::P2WSH(1_000_000)]),
			outputs_a: generate_outputs(&[TestOutput::P2WPKH(
				1_000_000 - p2wsh_fee - outputs_fee - tx_common_fields_fee,
			)]),
			inputs_b: vec![],
			outputs_b: vec![],
			expect_error: None,
		});
		let p2tr_fee = fee_for_weight(TEST_FEERATE_SATS_PER_KW, P2TR_INPUT_WEIGHT_LOWER_BOUND);
		do_test_interactive_tx_constructor(TestSession {
			description: "Single contribution, with P2TR input, insufficient fees",
			inputs_a: generate_inputs(&[TestOutput::P2TR(1_000_000)]),
			outputs_a: generate_outputs(&[TestOutput::P2WPKH(
				1_000_000 - p2tr_fee - outputs_fee - tx_common_fields_fee + 1, /* makes fees insuffcient for initiator */
			)]),
			inputs_b: vec![],
			outputs_b: vec![],
			expect_error: Some((AbortReason::InsufficientFees, ErrorCulprit::NodeA)),
		});
		do_test_interactive_tx_constructor(TestSession {
			description: "Single contribution with P2TR input, sufficient fees",
			inputs_a: generate_inputs(&[TestOutput::P2TR(1_000_000)]),
			outputs_a: generate_outputs(&[TestOutput::P2WPKH(
				1_000_000 - p2tr_fee - outputs_fee - tx_common_fields_fee,
			)]),
			inputs_b: vec![],
			outputs_b: vec![],
			expect_error: None,
		});
		do_test_interactive_tx_constructor(TestSession {
			description: "Initiator contributes sufficient fees, but non-initiator does not",
			inputs_a: generate_inputs(&[TestOutput::P2WPKH(1_000_000)]),
			outputs_a: vec![],
			inputs_b: generate_inputs(&[TestOutput::P2WPKH(100_000)]),
			outputs_b: generate_outputs(&[TestOutput::P2WPKH(100_000)]),
			expect_error: Some((AbortReason::InsufficientFees, ErrorCulprit::NodeB)),
		});
		do_test_interactive_tx_constructor(TestSession {
			description: "Multi-input-output contributions from both sides",
			inputs_a: generate_inputs(&[TestOutput::P2WPKH(1_000_000); 2]),
			outputs_a: generate_outputs(&[
				TestOutput::P2WPKH(1_000_000),
				TestOutput::P2WPKH(200_000),
			]),
			inputs_b: generate_inputs(&[
				TestOutput::P2WPKH(1_000_000),
				TestOutput::P2WPKH(500_000),
			]),
			outputs_b: generate_outputs(&[
				TestOutput::P2WPKH(1_000_000),
				TestOutput::P2WPKH(400_000),
			]),
			expect_error: None,
		});

		do_test_interactive_tx_constructor(TestSession {
			description: "Prevout from initiator is not a witness program",
			inputs_a: generate_inputs(&[TestOutput::P2PKH(1_000_000)]),
			outputs_a: vec![],
			inputs_b: vec![],
			outputs_b: vec![],
			expect_error: Some((AbortReason::PrevTxOutInvalid, ErrorCulprit::NodeA)),
		});

		let tx =
			TransactionU16LenLimited::new(generate_tx(&[TestOutput::P2WPKH(1_000_000)])).unwrap();
		let invalid_sequence_input = TxIn {
			previous_output: OutPoint { txid: tx.as_transaction().txid(), vout: 0 },
			..Default::default()
		};
		do_test_interactive_tx_constructor(TestSession {
			description: "Invalid input sequence from initiator",
			inputs_a: vec![(invalid_sequence_input, tx.clone())],
			outputs_a: generate_outputs(&[TestOutput::P2WPKH(1_000_000)]),
			inputs_b: vec![],
			outputs_b: vec![],
			expect_error: Some((AbortReason::IncorrectInputSequenceValue, ErrorCulprit::NodeA)),
		});
		let duplicate_input = TxIn {
			previous_output: OutPoint { txid: tx.as_transaction().txid(), vout: 0 },
			sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
			..Default::default()
		};
		do_test_interactive_tx_constructor(TestSession {
			description: "Duplicate prevout from initiator",
			inputs_a: vec![(duplicate_input.clone(), tx.clone()), (duplicate_input, tx.clone())],
			outputs_a: generate_outputs(&[TestOutput::P2WPKH(1_000_000)]),
			inputs_b: vec![],
			outputs_b: vec![],
			expect_error: Some((AbortReason::PrevTxOutInvalid, ErrorCulprit::NodeB)),
		});
		let duplicate_input = TxIn {
			previous_output: OutPoint { txid: tx.as_transaction().txid(), vout: 0 },
			sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
			..Default::default()
		};
		do_test_interactive_tx_constructor(TestSession {
			description: "Non-initiator uses same prevout as initiator",
			inputs_a: vec![(duplicate_input.clone(), tx.clone())],
			outputs_a: generate_outputs(&[TestOutput::P2WPKH(1_000_000)]),
			inputs_b: vec![(duplicate_input.clone(), tx.clone())],
			outputs_b: vec![],
			expect_error: Some((AbortReason::PrevTxOutInvalid, ErrorCulprit::NodeA)),
		});
		do_test_interactive_tx_constructor(TestSession {
			description: "Initiator sends too many TxAddInputs",
			inputs_a: generate_fixed_number_of_inputs(MAX_RECEIVED_TX_ADD_INPUT_COUNT + 1),
			outputs_a: vec![],
			inputs_b: vec![],
			outputs_b: vec![],
			expect_error: Some((AbortReason::ReceivedTooManyTxAddInputs, ErrorCulprit::NodeA)),
		});
		do_test_interactive_tx_constructor_with_entropy_source(
			TestSession {
				// We use a deliberately bad entropy source, `DuplicateEntropySource` to simulate this.
				description: "Attempt to queue up two inputs with duplicate serial ids",
				inputs_a: generate_fixed_number_of_inputs(2),
				outputs_a: vec![],
				inputs_b: vec![],
				outputs_b: vec![],
				expect_error: Some((AbortReason::DuplicateSerialId, ErrorCulprit::NodeA)),
			},
			&DuplicateEntropySource,
		);
		do_test_interactive_tx_constructor(TestSession {
			description: "Initiator sends too many TxAddOutputs",
			inputs_a: vec![],
			outputs_a: generate_fixed_number_of_outputs(MAX_RECEIVED_TX_ADD_OUTPUT_COUNT + 1),
			inputs_b: vec![],
			outputs_b: vec![],
			expect_error: Some((AbortReason::ReceivedTooManyTxAddOutputs, ErrorCulprit::NodeA)),
		});
		do_test_interactive_tx_constructor(TestSession {
			description: "Initiator sends an output below dust value",
			inputs_a: vec![],
			outputs_a: generate_outputs(&[TestOutput::P2WSH(
				generate_p2wsh_script_pubkey().dust_value().to_sat() - 1,
			)]),
			inputs_b: vec![],
			outputs_b: vec![],
			expect_error: Some((AbortReason::BelowDustLimit, ErrorCulprit::NodeA)),
		});
		do_test_interactive_tx_constructor(TestSession {
			description: "Initiator sends an output above maximum sats allowed",
			inputs_a: vec![],
			outputs_a: generate_outputs(&[TestOutput::P2WPKH(TOTAL_BITCOIN_SUPPLY_SATOSHIS + 1)]),
			inputs_b: vec![],
			outputs_b: vec![],
			expect_error: Some((AbortReason::ExceededMaximumSatsAllowed, ErrorCulprit::NodeA)),
		});
		do_test_interactive_tx_constructor(TestSession {
			description: "Initiator sends an output without a witness program",
			inputs_a: vec![],
			outputs_a: vec![generate_non_witness_output(1_000_000)],
			inputs_b: vec![],
			outputs_b: vec![],
			expect_error: Some((AbortReason::InvalidOutputScript, ErrorCulprit::NodeA)),
		});
		do_test_interactive_tx_constructor_with_entropy_source(
			TestSession {
				// We use a deliberately bad entropy source, `DuplicateEntropySource` to simulate this.
				description: "Attempt to queue up two outputs with duplicate serial ids",
				inputs_a: vec![],
				outputs_a: generate_fixed_number_of_outputs(2),
				inputs_b: vec![],
				outputs_b: vec![],
				expect_error: Some((AbortReason::DuplicateSerialId, ErrorCulprit::NodeA)),
			},
			&DuplicateEntropySource,
		);

		do_test_interactive_tx_constructor(TestSession {
			description: "Peer contributed more output value than inputs",
			inputs_a: generate_inputs(&[TestOutput::P2WPKH(100_000)]),
			outputs_a: generate_outputs(&[TestOutput::P2WPKH(1_000_000)]),
			inputs_b: vec![],
			outputs_b: vec![],
			expect_error: Some((AbortReason::OutputsValueExceedsInputsValue, ErrorCulprit::NodeA)),
		});

		do_test_interactive_tx_constructor(TestSession {
			description: "Peer contributed more than allowed number of inputs",
			inputs_a: generate_fixed_number_of_inputs(MAX_INPUTS_OUTPUTS_COUNT as u16 + 1),
			outputs_a: vec![],
			inputs_b: vec![],
			outputs_b: vec![],
			expect_error: Some((
				AbortReason::ExceededNumberOfInputsOrOutputs,
				ErrorCulprit::Indeterminate,
			)),
		});
		do_test_interactive_tx_constructor(TestSession {
			description: "Peer contributed more than allowed number of outputs",
			inputs_a: generate_inputs(&[TestOutput::P2WPKH(TOTAL_BITCOIN_SUPPLY_SATOSHIS)]),
			outputs_a: generate_fixed_number_of_outputs(MAX_INPUTS_OUTPUTS_COUNT as u16 + 1),
			inputs_b: vec![],
			outputs_b: vec![],
			expect_error: Some((
				AbortReason::ExceededNumberOfInputsOrOutputs,
				ErrorCulprit::Indeterminate,
			)),
		});
	}

	#[test]
	fn test_generate_local_serial_id() {
		let entropy_source = TestEntropySource(AtomicCounter::new());

		// Initiators should have even serial id, non-initiators should have odd serial id.
		assert_eq!(generate_holder_serial_id(&&entropy_source, true) % 2, 0);
		assert_eq!(generate_holder_serial_id(&&entropy_source, false) % 2, 1)
	}
}
