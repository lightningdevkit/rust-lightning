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
use bitcoin::Witness;
use bitcoin::{
	absolute::LockTime as AbsoluteLockTime, OutPoint, Sequence, Transaction, TxIn, TxOut,
};

use crate::chain::chaininterface::fee_for_weight;
use crate::events::bump_transaction::{BASE_INPUT_WEIGHT, EMPTY_SCRIPT_SIG_WEIGHT};
use crate::ln::channel::TOTAL_BITCOIN_SUPPLY_SATOSHIS;
use crate::ln::msgs::{CommitmentSigned, SerialId, TxSignatures};
use crate::ln::{msgs, ChannelId};
use crate::sign::EntropySource;
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

trait SerialIdExt {
	fn is_for_initiator(&self) -> bool;
}

impl SerialIdExt for SerialId {
	fn is_for_initiator(&self) -> bool {
		self % 2 == 0
	}
}

#[derive(Debug, Clone, PartialEq)]
pub enum AbortReason {
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

#[derive(Debug, Clone, PartialEq)]
pub struct TxInputWithPrevOutput {
	input: TxIn,
	prev_output: TxOut,
}

#[derive(Debug, Clone, PartialEq)]
pub enum InteractiveTxInput {
	HolderInput(TxInputWithPrevOutput),
	CounterpartyInput(TxInputWithPrevOutput),
}

#[derive(Debug, Clone, PartialEq)]
pub struct InteractiveTxSigningSession {
	pub constructed_transaction: Transaction,
	holder_sends_tx_signatures_first: bool,
	inputs: Vec<InteractiveTxInput>,
	sent_commitment_signed: Option<CommitmentSigned>,
	received_commitment_signed: Option<CommitmentSigned>,
	holder_tx_signatures: Option<TxSignatures>,
	counterparty_tx_signatures: Option<TxSignatures>,
	/// TODO comment
	pub shared_signature: Option<Signature>,
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

	pub fn counterparty_tx_signatures(&self) -> Option<TxSignatures> { self.counterparty_tx_signatures.clone() }

	pub fn received_tx_signatures(
		&mut self, tx_signatures: TxSignatures,
	) -> (Option<TxSignatures>, Option<Transaction>) {
		if self.counterparty_tx_signatures.is_some() {
			// It looks like this is called the 2nd time, do it nonetheless, otherwise we have problems at the call site
		};
		self.counterparty_tx_signatures = Some(tx_signatures.clone());
		self.inputs
			.iter_mut()
			.filter_map(|input| match input {
				InteractiveTxInput::CounterpartyInput(TxInputWithPrevOutput { input, .. }) => {
					Some(input)
				},
				_ => None,
			})
			.zip(tx_signatures.witnesses.into_iter())
			.for_each(|(input, witness)| input.witness = witness);

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

	/// witnesses: The witnesses for each holder input
	/// shared_signature: optional signature on the shared (co-signed) input, included in the
	/// TxSignature.tlvs field. Used in splicing.
	pub fn provide_holder_witnesses(
		&mut self, channel_id: ChannelId, witnesses: Vec<Witness>, shared_signature: Option<Signature>,
	) -> Option<TxSignatures> {
		self.inputs
			.iter_mut()
			.filter_map(|input| match input {
				InteractiveTxInput::HolderInput(TxInputWithPrevOutput { input, .. }) => Some(input),
				_ => None,
			})
			.zip(witnesses.iter())
			.for_each(|(input, witness)| input.witness = witness.clone());
		self.holder_tx_signatures = Some(TxSignatures {
			channel_id,
			tx_hash: self.constructed_transaction.txid(),
			witnesses: witnesses.into_iter().map(|witness| witness).collect(),
			tlvs: shared_signature,
		});
		if self.received_commitment_signed.is_some()
			&& (self.holder_sends_tx_signatures_first || self.counterparty_tx_signatures.is_some())
		{
			self.holder_tx_signatures.clone()
		} else {
			None
		}
	}

	pub fn counterparty_inputs_count(&self) -> usize {
		self.inputs
			.iter()
			.filter(|input| match input {
				InteractiveTxInput::CounterpartyInput(_) => true,
				_ => false,
			})
			.count()
	}

	pub fn holder_inputs_count(&self) -> usize {
		self.inputs
			.iter()
			.filter(|input| match input {
				InteractiveTxInput::HolderInput(_) => true,
				_ => false,
			})
			.count()
	}

	fn finalize_funding_tx(&mut self) -> Transaction {
		self.constructed_transaction.input = self
			.inputs
			.iter()
			.map(|interactive_tx_input| match interactive_tx_input {
				InteractiveTxInput::HolderInput(input_with_prevout) => {
					input_with_prevout.input.clone()
				},
				InteractiveTxInput::CounterpartyInput(input_with_prevout) => {
					input_with_prevout.input.clone()
				},
			})
			.collect();
		self.constructed_transaction.clone()
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
	outputs: HashMap<SerialId, TxOut>,
	tx_locktime: AbsoluteLockTime,
	feerate_sat_per_kw: u32,
	to_remote_value: u64,
}

impl NegotiationContext {
	fn is_serial_id_valid_for_counterparty(&self, serial_id: &SerialId) -> bool {
		// A received `SerialId`'s parity must match the role of the counterparty.
		self.holder_is_initiator == !serial_id.is_for_initiator()
	}

	fn holder_inputs_contributed(&self) -> impl Iterator<Item = &TxInputWithPrevOutput> + Clone {
		self.inputs.iter().filter_map(move |(_, input)| match input {
			InteractiveTxInput::HolderInput(tx_input_with_prev_output) => {
				Some(tx_input_with_prev_output)
			},
			_ => None,
		})
	}

	fn counterparty_inputs_contributed(
		&self,
	) -> impl Iterator<Item = &TxInputWithPrevOutput> + Clone {
		self.inputs.iter().filter_map(move |(_, input)| match input {
			InteractiveTxInput::CounterpartyInput(tx_input_with_prev_output) => {
				Some(tx_input_with_prev_output)
			},
			_ => None,
		})
	}

	fn counterparty_outputs_contributed(&self) -> impl Iterator<Item = &TxOut> + Clone {
		self.outputs
			.iter()
			.filter(move |(serial_id, _)| self.is_serial_id_valid_for_counterparty(serial_id))
			.map(|(_, output)| output)
	}

	fn should_holder_send_tx_signatures_first(
		&self, holder_inputs_value: u64, counterparty_inputs_value: u64,
	) -> bool {
		// There is a strict ordering for `tx_signatures` exchange to prevent deadlocks.
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
		if self.inputs.iter().any(|(serial_id, _)| *serial_id == msg.serial_id) {
			// The receiving node:
			//  - MUST fail the negotiation if:
			//    - the `serial_id` is already included in the transaction
			return Err(AbortReason::DuplicateSerialId);
		}
		let prev_outpoint = OutPoint { txid, vout: msg.prevtx_out };
		self.inputs.entry(msg.serial_id).or_insert_with(|| {
			InteractiveTxInput::CounterpartyInput(TxInputWithPrevOutput {
				input: TxIn {
					previous_output: prev_outpoint.clone(),
					sequence: Sequence(msg.sequence),
					..Default::default()
				},
				prev_output: prev_out,
			})
		});
		self.prevtx_outpoints.insert(prev_outpoint);
		Ok(())
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
			outputs_value = outputs_value.saturating_add(output.1.value);
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
		if !msg.script.is_v0_p2wpkh()
			&& !msg.script.is_v0_p2wsh()
			&& msg.script.witness_version().map(|v| v.to_num() < 1).unwrap_or(true)
		{
			return Err(AbortReason::InvalidOutputScript);
		}

		if self.outputs.iter().any(|(serial_id, _)| *serial_id == msg.serial_id) {
			// The receiving node:
			//  - MUST fail the negotiation if:
			//    - the `serial_id` is already included in the transaction
			return Err(AbortReason::DuplicateSerialId);
		}

		let output = TxOut { value: msg.sats, script_pubkey: msg.script.clone() };
		self.outputs.entry(msg.serial_id).or_insert(output);
		Ok(())
	}

	fn received_tx_remove_output(&mut self, msg: &msgs::TxRemoveOutput) -> Result<(), AbortReason> {
		if !self.is_serial_id_valid_for_counterparty(&msg.serial_id) {
			return Err(AbortReason::IncorrectSerialIdParity);
		}
		if let Some(_) = self.outputs.remove(&msg.serial_id) {
			Ok(())
		} else {
			// The receiving node:
			//  - MUST fail the negotiation if:
			//    - the input or output identified by the `serial_id` was not added by the sender
			//    - the `serial_id` does not correspond to a currently added input
			Err(AbortReason::SerialIdUnknown)
		}
	}

	fn sent_tx_add_input(&mut self, msg: &msgs::TxAddInput) {
		let tx = msg.prevtx.as_transaction();
		let input = TxIn {
			previous_output: OutPoint { txid: tx.txid(), vout: msg.prevtx_out },
			sequence: Sequence(msg.sequence),
			..Default::default()
		};
		debug_assert!((msg.prevtx_out as usize) < tx.output.len());
		let prev_output = &tx.output[msg.prevtx_out as usize];
		self.prevtx_outpoints.insert(input.previous_output.clone());
		self.inputs.insert(
			msg.serial_id,
			InteractiveTxInput::HolderInput(TxInputWithPrevOutput {
				input,
				prev_output: prev_output.clone(),
			}),
		);
	}

	fn sent_tx_add_output(&mut self, msg: &msgs::TxAddOutput) {
		self.outputs
			.insert(msg.serial_id, TxOut { value: msg.sats, script_pubkey: msg.script.clone() });
	}

	fn sent_tx_remove_input(&mut self, msg: &msgs::TxRemoveInput) {
		self.inputs.remove(&msg.serial_id);
	}

	fn sent_tx_remove_output(&mut self, msg: &msgs::TxRemoveOutput) {
		self.outputs.remove(&msg.serial_id);
	}

	fn build_transaction(self) -> Result<(Vec<InteractiveTxInput>, Transaction), AbortReason> {
		// The receiving node:
		// MUST fail the negotiation if:

		// - the peer's total input satoshis is less than their outputs
		let mut counterparty_inputs_value: u64 = 0;
		let mut counterparty_outputs_value: u64 = 0;
		for input in self.counterparty_inputs_contributed() {
			counterparty_inputs_value =
				counterparty_inputs_value.saturating_add(input.prev_output.value);
		}
		for output in self.counterparty_outputs_contributed() {
			counterparty_outputs_value = counterparty_outputs_value.saturating_add(output.value);
		}
		// ...actually the counterparty might be splicing out, so that their balance also contributes
		// to the total input value.
		if counterparty_inputs_value.saturating_add(self.to_remote_value)
			< counterparty_outputs_value
		{
			return Err(AbortReason::OutputsValueExceedsInputsValue);
		}

		// - there are more than 252 inputs
		// - there are more than 252 outputs
		if self.inputs.len() > MAX_INPUTS_OUTPUTS_COUNT
			|| self.outputs.len() > MAX_INPUTS_OUTPUTS_COUNT
		{
			return Err(AbortReason::ExceededNumberOfInputsOrOutputs);
		}

		// TODO: How do we enforce their fees cover the witness without knowing its expected length?
		const INPUT_WEIGHT: u64 = BASE_INPUT_WEIGHT + EMPTY_SCRIPT_SIG_WEIGHT;

		// - the peer's paid feerate does not meet or exceed the agreed feerate (based on the minimum fee).
		let counterparty_output_weight_contributed: u64 = self
			.counterparty_outputs_contributed()
			.map(|output| {
				(8 /* value */ + output.script_pubkey.consensus_encode(&mut sink()).unwrap() as u64)
					* WITNESS_SCALE_FACTOR as u64
			})
			.sum();
		let counterparty_weight_contributed = counterparty_output_weight_contributed
			+ self.counterparty_inputs_contributed().count() as u64 * INPUT_WEIGHT;
		let counterparty_fees_contributed =
			counterparty_inputs_value.saturating_sub(counterparty_outputs_value);
		let mut required_counterparty_contribution_fee =
			fee_for_weight(self.feerate_sat_per_kw, counterparty_weight_contributed);
		if !self.holder_is_initiator {
			// if is the non-initiator:
			// 	- the initiator's fees do not cover the common fields (version, segwit marker + flag,
			// 		input count, output count, locktime)
			let tx_common_fields_weight =
		        (4 /* version */ + 4 /* locktime */ + 1 /* input count */ + 1 /* output count */) *
		            WITNESS_SCALE_FACTOR as u64 + 2 /* segwit marker + flag */;
			let tx_common_fields_fee =
				fee_for_weight(self.feerate_sat_per_kw, tx_common_fields_weight);
			required_counterparty_contribution_fee += tx_common_fields_fee;
		}
		if counterparty_fees_contributed < required_counterparty_contribution_fee {
			return Err(AbortReason::InsufficientFees);
		}

		// Inputs and outputs must be sorted by serial_id
		let mut inputs = self.inputs.into_iter().collect::<Vec<_>>();
		let mut outputs = self.outputs.into_iter().collect::<Vec<_>>();
		inputs.sort_unstable_by_key(|(serial_id, _)| *serial_id);
		outputs.sort_unstable_by_key(|(serial_id, _)| *serial_id);

		let tx_input = inputs
			.iter()
			.filter_map(|(_, input)| match input {
				InteractiveTxInput::HolderInput(TxInputWithPrevOutput { input, .. }) => {
					Some(input.clone())
				},
				InteractiveTxInput::CounterpartyInput(TxInputWithPrevOutput { input, .. }) => {
					Some(input.clone())
				},
			})
			.collect();

		let tx_to_validate = Transaction {
			version: 2,
			lock_time: self.tx_locktime,
			input: tx_input,
			output: outputs.into_iter().map(|(_, output)| output).collect(),
		};
		if tx_to_validate.weight().to_wu() > MAX_STANDARD_TX_WEIGHT as u64 {
			return Err(AbortReason::TransactionTooLarge);
		}

		let interactive_tx_inputs = inputs.into_iter().map(|(_, input)| input.clone()).collect();
		Ok((interactive_tx_inputs, tx_to_validate))
	}
}

/// Channel states that can send & receive `tx_(add|remove)_(input|output)` and `tx_complete`
trait State {}

/// Category of states where we have sent some message to the counterparty, and we are waiting for
/// a response.
trait MsgSentState: State {
	fn into_negotiation_context(self) -> NegotiationContext;
}

/// Category of states that our counterparty has put us in after we receive a message from them.
trait MsgReceivedState: State {
	fn into_negotiation_context(self) -> NegotiationContext;
}

macro_rules! define_state {
	(MSG_SENT_STATE, $state: ident, $doc: expr) => {
		define_state!($state, NegotiationContext, $doc);
		impl MsgSentState for $state {
			fn into_negotiation_context(self) -> NegotiationContext {
				self.0
			}
		}
	};
	(MSG_RECEIVED_STATE, $state: ident, $doc: expr) => {
		define_state!($state, NegotiationContext, $doc);
		impl MsgReceivedState for $state {
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
	MSG_SENT_STATE,
	MsgSentChange,
	"We have sent a message to the counterparty that has affected our negotiation state."
);
define_state!(
	MSG_SENT_STATE,
	SentTxComplete,
	"We have sent a `tx_complete` message and are awaiting the counterparty's."
);
define_state!(
	MSG_RECEIVED_STATE,
	MsgReceivedChange,
	"We have received a message from the counterparty that has affected our negotiation state."
);
define_state!(
	MSG_RECEIVED_STATE,
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

macro_rules! define_state_transitions {
	(MSG_SENT_STATE, [$(DATA $data: ty, TRANSITION $transition: ident),+]) => {
		$(
			impl<S: MsgSentState> StateTransition<MsgReceivedChange, $data> for S {
				fn transition(self, data: $data) -> StateTransitionResult<MsgReceivedChange> {
					let mut context = self.into_negotiation_context();
					context.$transition(data)?;
					Ok(MsgReceivedChange(context))
				}
			}
		 )*
	};
	(MSG_RECEIVED_STATE, [$(DATA $data: ty, TRANSITION $transition: ident),+]) => {
		$(
			impl<S: MsgReceivedState> StateTransition<MsgSentChange, $data> for S {
				fn transition(self, data: $data) -> StateTransitionResult<MsgSentChange> {
					let mut context = self.into_negotiation_context();
					context.$transition(data);
					Ok(MsgSentChange(context))
				}
			}
		 )*
	};
	(TX_COMPLETE, $from_state: ident, $tx_complete_state: ident) => {
		impl StateTransition<NegotiationComplete, &msgs::TxComplete> for $tx_complete_state {
			fn transition(self, _data: &msgs::TxComplete) -> StateTransitionResult<NegotiationComplete> {
				let context = self.into_negotiation_context();
				let holder_inputs_value = context.holder_inputs_contributed()
					.fold(0, |value, input| value + input.prev_output.value);
				let counterparty_inputs_value = context.counterparty_inputs_contributed()
					.fold(0, |value, input| value + input.prev_output.value);
				let holder_sends_tx_signatures_first = context.should_holder_send_tx_signatures_first(
					holder_inputs_value, counterparty_inputs_value);
				let (inputs, tx) = context.build_transaction()?;
				let signing_session = InteractiveTxSigningSession {
					inputs,
					holder_sends_tx_signatures_first,
					constructed_transaction: tx,
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
define_state_transitions!(MSG_SENT_STATE, [
	DATA &msgs::TxAddInput, TRANSITION received_tx_add_input,
	DATA &msgs::TxRemoveInput, TRANSITION received_tx_remove_input,
	DATA &msgs::TxAddOutput, TRANSITION received_tx_add_output,
	DATA &msgs::TxRemoveOutput, TRANSITION received_tx_remove_output
]);
// State transitions when we have received some messages from our counterparty and we should
// respond.
define_state_transitions!(MSG_RECEIVED_STATE, [
	DATA &msgs::TxAddInput, TRANSITION sent_tx_add_input,
	DATA &msgs::TxRemoveInput, TRANSITION sent_tx_remove_input,
	DATA &msgs::TxAddOutput, TRANSITION sent_tx_add_output,
	DATA &msgs::TxRemoveOutput, TRANSITION sent_tx_remove_output
]);
define_state_transitions!(TX_COMPLETE, MsgSentChange, ReceivedTxComplete);
define_state_transitions!(TX_COMPLETE, MsgReceivedChange, SentTxComplete);

#[derive(Debug)]
enum StateMachine {
	Indeterminate,
	MsgSentChange(MsgSentChange),
	MsgReceivedChange(MsgReceivedChange),
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
		is_initiator: bool, tx_locktime: AbsoluteLockTime, to_remote_value: u64,
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
			to_remote_value,
		};
		if is_initiator {
			Self::MsgReceivedChange(MsgReceivedChange(context))
		} else {
			Self::MsgSentChange(MsgSentChange(context))
		}
	}

	// TxAddInput
	define_state_machine_transitions!(sent_tx_add_input, &msgs::TxAddInput, [
		FROM MsgReceivedChange, TO MsgSentChange,
		FROM ReceivedTxComplete, TO MsgSentChange
	]);
	define_state_machine_transitions!(received_tx_add_input, &msgs::TxAddInput, [
		FROM MsgSentChange, TO MsgReceivedChange,
		FROM SentTxComplete, TO MsgReceivedChange
	]);

	// TxAddOutput
	define_state_machine_transitions!(sent_tx_add_output, &msgs::TxAddOutput, [
		FROM MsgReceivedChange, TO MsgSentChange,
		FROM ReceivedTxComplete, TO MsgSentChange
	]);
	define_state_machine_transitions!(received_tx_add_output, &msgs::TxAddOutput, [
		FROM MsgSentChange, TO MsgReceivedChange,
		FROM SentTxComplete, TO MsgReceivedChange
	]);

	// TxRemoveInput
	define_state_machine_transitions!(sent_tx_remove_input, &msgs::TxRemoveInput, [
		FROM MsgReceivedChange, TO MsgSentChange,
		FROM ReceivedTxComplete, TO MsgSentChange
	]);
	define_state_machine_transitions!(received_tx_remove_input, &msgs::TxRemoveInput, [
		FROM MsgSentChange, TO MsgReceivedChange,
		FROM SentTxComplete, TO MsgReceivedChange
	]);

	// TxRemoveOutput
	define_state_machine_transitions!(sent_tx_remove_output, &msgs::TxRemoveOutput, [
		FROM MsgReceivedChange, TO MsgSentChange,
		FROM ReceivedTxComplete, TO MsgSentChange
	]);
	define_state_machine_transitions!(received_tx_remove_output, &msgs::TxRemoveOutput, [
		FROM MsgSentChange, TO MsgReceivedChange,
		FROM SentTxComplete, TO MsgReceivedChange
	]);

	// TxComplete
	define_state_machine_transitions!(sent_tx_complete, &msgs::TxComplete, [
		FROM MsgReceivedChange, TO SentTxComplete,
		FROM ReceivedTxComplete, TO NegotiationComplete
	]);
	define_state_machine_transitions!(received_tx_complete, &msgs::TxComplete, [
		FROM MsgSentChange, TO ReceivedTxComplete,
		FROM SentTxComplete, TO NegotiationComplete
	]);
}

pub struct InteractiveTxConstructor {
	state_machine: StateMachine,
	channel_id: ChannelId,
	inputs_to_contribute: Vec<(SerialId, TxIn, TransactionU16LenLimited)>,
	outputs_to_contribute: Vec<(SerialId, TxOut)>,
}

pub enum InteractiveTxMessageSend {
	TxAddInput(msgs::TxAddInput),
	TxAddOutput(msgs::TxAddOutput),
	TxComplete(msgs::TxComplete),
}

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

impl InteractiveTxConstructor {
	pub fn new<ES: Deref>(
		entropy_source: &ES, channel_id: ChannelId, feerate_sat_per_kw: u32,
		holder_node_id: PublicKey, counterparty_node_id: PublicKey, is_initiator: bool,
		tx_locktime: AbsoluteLockTime, inputs_to_contribute: Vec<(TxIn, TransactionU16LenLimited)>,
		outputs_to_contribute: Vec<TxOut>, to_remote_value: u64,
	) -> (Self, Option<InteractiveTxMessageSend>)
	where
		ES::Target: EntropySource,
	{
		let state_machine = StateMachine::new(
			holder_node_id,
			counterparty_node_id,
			feerate_sat_per_kw,
			is_initiator,
			tx_locktime,
			to_remote_value,
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
			match constructor.do_sent_state_transition() {
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

	fn do_sent_state_transition(&mut self) -> Result<InteractiveTxMessageSend, AbortReason> {
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
		self.do_sent_state_transition()
	}

	pub fn handle_tx_remove_input(
		&mut self, msg: &msgs::TxRemoveInput,
	) -> Result<InteractiveTxMessageSend, AbortReason> {
		do_state_transition!(self, received_tx_remove_input, msg)?;
		self.do_sent_state_transition()
	}

	pub fn handle_tx_add_output(
		&mut self, msg: &msgs::TxAddOutput,
	) -> Result<InteractiveTxMessageSend, AbortReason> {
		do_state_transition!(self, received_tx_add_output, msg)?;
		self.do_sent_state_transition()
	}

	pub fn handle_tx_remove_output(
		&mut self, msg: &msgs::TxRemoveOutput,
	) -> Result<InteractiveTxMessageSend, AbortReason> {
		do_state_transition!(self, received_tx_remove_output, msg)?;
		self.do_sent_state_transition()
	}

	pub fn handle_tx_complete(
		&mut self, msg: &msgs::TxComplete,
	) -> Result<(Option<InteractiveTxMessageSend>, Option<InteractiveTxSigningSession>), AbortReason>
	{
		let _ = do_state_transition!(self, received_tx_complete, msg)?;
		match &self.state_machine {
			StateMachine::ReceivedTxComplete(_) => {
				let msg_send = self.do_sent_state_transition()?;
				let success_result = match &self.state_machine {
					StateMachine::NegotiationComplete(s) => Some(s.0.clone()),
					StateMachine::MsgSentChange(_) => None, // We either had an input or output to contribute.
					_ => {
						debug_assert!(false, "We cannot transition to any other states after receiving `tx_complete` and responding");
						return Err(AbortReason::InvalidStateTransition);
					},
				};
				Ok((Some(msg_send), success_result))
			},
			StateMachine::NegotiationComplete(s) => Ok((None, Some(s.0.clone()))),
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
	use crate::chain::chaininterface::FEERATE_FLOOR_SATS_PER_KW;
	use crate::ln::channel::TOTAL_BITCOIN_SUPPLY_SATOSHIS;
	use crate::ln::interactivetxs::{
		generate_holder_serial_id, AbortReason, InteractiveTxConstructor, InteractiveTxMessageSend,
		MAX_INPUTS_OUTPUTS_COUNT, MAX_RECEIVED_TX_ADD_INPUT_COUNT,
		MAX_RECEIVED_TX_ADD_OUTPUT_COUNT,
	};
	use crate::ln::ChannelId;
	use crate::sign::EntropySource;
	use crate::util::atomic_counter::AtomicCounter;
	use crate::util::ser::TransactionU16LenLimited;
	use bitcoin::blockdata::opcodes;
	use bitcoin::blockdata::script::Builder;
	use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
	use bitcoin::{
		absolute::LockTime as AbsoluteLockTime, OutPoint, Sequence, Transaction, TxIn, TxOut,
	};
	use core::ops::Deref;

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

	struct TestSession {
		inputs_a: Vec<(TxIn, TransactionU16LenLimited)>,
		outputs_a: Vec<TxOut>,
		inputs_b: Vec<(TxIn, TransactionU16LenLimited)>,
		outputs_b: Vec<TxOut>,
		expect_error: Option<AbortReason>,
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
			FEERATE_FLOOR_SATS_PER_KW * 10,
			holder_node_id,
			counterparty_node_id,
			true, // is_initiator
			tx_locktime,
			session.inputs_a,
			session.outputs_a,
			0,
		);
		let (mut constructor_b, first_message_b) = InteractiveTxConstructor::new(
			entropy_source,
			channel_id,
			FEERATE_FLOOR_SATS_PER_KW * 10,
			holder_node_id,
			counterparty_node_id,
			false, // is_initiator
			tx_locktime,
			session.inputs_b,
			session.outputs_b,
			0,
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
						for_constructor.handle_tx_complete(&msg)
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
						final_tx_b = interactive_signing_session
							.map(|session| session.constructed_transaction);
					},
					Err(abort_reason) => {
						assert_eq!(Some(abort_reason), session.expect_error);
						return;
					},
				}
			}
			if let Some(message_send_b) = message_send_b.take() {
				match handle_message_send(message_send_b, &mut constructor_a) {
					Ok((msg_send, interactive_signing_session)) => {
						message_send_a = msg_send;
						final_tx_a = interactive_signing_session
							.map(|session| session.constructed_transaction);
					},
					Err(abort_reason) => {
						assert_eq!(Some(abort_reason), session.expect_error);
						return;
					},
				}
			}
		}
		assert!(message_send_a.is_none());
		assert!(message_send_b.is_none());
		assert_eq!(final_tx_a, final_tx_b);
		assert!(session.expect_error.is_none());
	}

	fn generate_tx(values: &[u64]) -> Transaction {
		generate_tx_with_locktime(values, 1337)
	}

	fn generate_tx_with_locktime(values: &[u64], locktime: u32) -> Transaction {
		Transaction {
			version: 2,
			lock_time: AbsoluteLockTime::from_height(locktime).unwrap(),
			input: vec![TxIn { ..Default::default() }],
			output: values
				.iter()
				.map(|value| TxOut {
					value: *value,
					script_pubkey: Builder::new()
						.push_opcode(opcodes::OP_TRUE)
						.into_script()
						.to_v0_p2wsh(),
				})
				.collect(),
		}
	}

	fn generate_inputs(values: &[u64]) -> Vec<(TxIn, TransactionU16LenLimited)> {
		let tx = generate_tx(values);
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

	fn generate_outputs(values: &[u64]) -> Vec<TxOut> {
		values
			.iter()
			.map(|value| TxOut {
				value: *value,
				script_pubkey: Builder::new()
					.push_opcode(opcodes::OP_TRUE)
					.into_script()
					.to_v0_p2wsh(),
			})
			.collect()
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
				&vec![1_000_000; tx_output_count as usize],
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
		generate_outputs(&vec![1_000_000; count as usize])
	}

	fn generate_non_witness_output(value: u64) -> TxOut {
		TxOut {
			value,
			script_pubkey: Builder::new().push_opcode(opcodes::OP_TRUE).into_script().to_p2sh(),
		}
	}

	#[test]
	fn test_interactive_tx_constructor() {
		// No contributions.
		do_test_interactive_tx_constructor(TestSession {
			inputs_a: vec![],
			outputs_a: vec![],
			inputs_b: vec![],
			outputs_b: vec![],
			expect_error: Some(AbortReason::InsufficientFees),
		});
		// Single contribution, no initiator inputs.
		do_test_interactive_tx_constructor(TestSession {
			inputs_a: vec![],
			outputs_a: generate_outputs(&[1_000_000]),
			inputs_b: vec![],
			outputs_b: vec![],
			expect_error: Some(AbortReason::OutputsValueExceedsInputsValue),
		});
		// Single contribution, no initiator outputs.
		do_test_interactive_tx_constructor(TestSession {
			inputs_a: generate_inputs(&[1_000_000]),
			outputs_a: vec![],
			inputs_b: vec![],
			outputs_b: vec![],
			expect_error: None,
		});
		// Single contribution, insufficient fees.
		do_test_interactive_tx_constructor(TestSession {
			inputs_a: generate_inputs(&[1_000_000]),
			outputs_a: generate_outputs(&[1_000_000]),
			inputs_b: vec![],
			outputs_b: vec![],
			expect_error: Some(AbortReason::InsufficientFees),
		});
		// Initiator contributes sufficient fees, but non-initiator does not.
		do_test_interactive_tx_constructor(TestSession {
			inputs_a: generate_inputs(&[1_000_000]),
			outputs_a: vec![],
			inputs_b: generate_inputs(&[100_000]),
			outputs_b: generate_outputs(&[100_000]),
			expect_error: Some(AbortReason::InsufficientFees),
		});
		// Multi-input-output contributions from both sides.
		do_test_interactive_tx_constructor(TestSession {
			inputs_a: generate_inputs(&[1_000_000, 1_000_000]),
			outputs_a: generate_outputs(&[1_000_000, 200_000]),
			inputs_b: generate_inputs(&[1_000_000, 500_000]),
			outputs_b: generate_outputs(&[1_000_000, 400_000]),
			expect_error: None,
		});

		// Prevout from initiator is not a witness program
		let non_segwit_output_tx = {
			let mut tx = generate_tx(&[1_000_000]);
			tx.output.push(TxOut {
				script_pubkey: Builder::new()
					.push_opcode(opcodes::all::OP_RETURN)
					.into_script()
					.to_p2sh(),
				..Default::default()
			});

			TransactionU16LenLimited::new(tx).unwrap()
		};
		let non_segwit_input = TxIn {
			previous_output: OutPoint {
				txid: non_segwit_output_tx.as_transaction().txid(),
				vout: 1,
			},
			sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
			..Default::default()
		};
		do_test_interactive_tx_constructor(TestSession {
			inputs_a: vec![(non_segwit_input, non_segwit_output_tx)],
			outputs_a: vec![],
			inputs_b: vec![],
			outputs_b: vec![],
			expect_error: Some(AbortReason::PrevTxOutInvalid),
		});

		// Invalid input sequence from initiator.
		let tx = TransactionU16LenLimited::new(generate_tx(&[1_000_000])).unwrap();
		let invalid_sequence_input = TxIn {
			previous_output: OutPoint { txid: tx.as_transaction().txid(), vout: 0 },
			..Default::default()
		};
		do_test_interactive_tx_constructor(TestSession {
			inputs_a: vec![(invalid_sequence_input, tx.clone())],
			outputs_a: generate_outputs(&[1_000_000]),
			inputs_b: vec![],
			outputs_b: vec![],
			expect_error: Some(AbortReason::IncorrectInputSequenceValue),
		});
		// Duplicate prevout from initiator.
		let duplicate_input = TxIn {
			previous_output: OutPoint { txid: tx.as_transaction().txid(), vout: 0 },
			sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
			..Default::default()
		};
		do_test_interactive_tx_constructor(TestSession {
			inputs_a: vec![(duplicate_input.clone(), tx.clone()), (duplicate_input, tx.clone())],
			outputs_a: generate_outputs(&[1_000_000]),
			inputs_b: vec![],
			outputs_b: vec![],
			expect_error: Some(AbortReason::PrevTxOutInvalid),
		});
		// Non-initiator uses same prevout as initiator.
		let duplicate_input = TxIn {
			previous_output: OutPoint { txid: tx.as_transaction().txid(), vout: 0 },
			sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
			..Default::default()
		};
		do_test_interactive_tx_constructor(TestSession {
			inputs_a: vec![(duplicate_input.clone(), tx.clone())],
			outputs_a: generate_outputs(&[1_000_000]),
			inputs_b: vec![(duplicate_input.clone(), tx.clone())],
			outputs_b: vec![],
			expect_error: Some(AbortReason::PrevTxOutInvalid),
		});
		// Initiator sends too many TxAddInputs
		do_test_interactive_tx_constructor(TestSession {
			inputs_a: generate_fixed_number_of_inputs(MAX_RECEIVED_TX_ADD_INPUT_COUNT + 1),
			outputs_a: vec![],
			inputs_b: vec![],
			outputs_b: vec![],
			expect_error: Some(AbortReason::ReceivedTooManyTxAddInputs),
		});
		// Attempt to queue up two inputs with duplicate serial ids. We use a deliberately bad
		// entropy source, `DuplicateEntropySource` to simulate this.
		do_test_interactive_tx_constructor_with_entropy_source(
			TestSession {
				inputs_a: generate_fixed_number_of_inputs(2),
				outputs_a: vec![],
				inputs_b: vec![],
				outputs_b: vec![],
				expect_error: Some(AbortReason::DuplicateSerialId),
			},
			&DuplicateEntropySource,
		);
		// Initiator sends too many TxAddOutputs.
		do_test_interactive_tx_constructor(TestSession {
			inputs_a: vec![],
			outputs_a: generate_fixed_number_of_outputs(MAX_RECEIVED_TX_ADD_OUTPUT_COUNT + 1),
			inputs_b: vec![],
			outputs_b: vec![],
			expect_error: Some(AbortReason::ReceivedTooManyTxAddOutputs),
		});
		// Initiator sends an output below dust value.
		do_test_interactive_tx_constructor(TestSession {
			inputs_a: vec![],
			outputs_a: generate_outputs(&[1]),
			inputs_b: vec![],
			outputs_b: vec![],
			expect_error: Some(AbortReason::BelowDustLimit),
		});
		// Initiator sends an output above maximum sats allowed.
		do_test_interactive_tx_constructor(TestSession {
			inputs_a: vec![],
			outputs_a: generate_outputs(&[TOTAL_BITCOIN_SUPPLY_SATOSHIS + 1]),
			inputs_b: vec![],
			outputs_b: vec![],
			expect_error: Some(AbortReason::ExceededMaximumSatsAllowed),
		});
		// Initiator sends an output without a witness program.
		do_test_interactive_tx_constructor(TestSession {
			inputs_a: vec![],
			outputs_a: vec![generate_non_witness_output(1_000_000)],
			inputs_b: vec![],
			outputs_b: vec![],
			expect_error: Some(AbortReason::InvalidOutputScript),
		});
		// Attempt to queue up two outputs with duplicate serial ids. We use a deliberately bad
		// entropy source, `DuplicateEntropySource` to simulate this.
		do_test_interactive_tx_constructor_with_entropy_source(
			TestSession {
				inputs_a: vec![],
				outputs_a: generate_fixed_number_of_outputs(2),
				inputs_b: vec![],
				outputs_b: vec![],
				expect_error: Some(AbortReason::DuplicateSerialId),
			},
			&DuplicateEntropySource,
		);

		// Peer contributed more output value than inputs
		do_test_interactive_tx_constructor(TestSession {
			inputs_a: generate_inputs(&[100_000]),
			outputs_a: generate_outputs(&[1_000_000]),
			inputs_b: vec![],
			outputs_b: vec![],
			expect_error: Some(AbortReason::OutputsValueExceedsInputsValue),
		});

		// Peer contributed more than allowed number of inputs.
		do_test_interactive_tx_constructor(TestSession {
			inputs_a: generate_fixed_number_of_inputs(MAX_INPUTS_OUTPUTS_COUNT as u16 + 1),
			outputs_a: vec![],
			inputs_b: vec![],
			outputs_b: vec![],
			expect_error: Some(AbortReason::ExceededNumberOfInputsOrOutputs),
		});
		// Peer contributed more than allowed number of outputs.
		do_test_interactive_tx_constructor(TestSession {
			inputs_a: generate_inputs(&[TOTAL_BITCOIN_SUPPLY_SATOSHIS]),
			outputs_a: generate_fixed_number_of_outputs(MAX_INPUTS_OUTPUTS_COUNT as u16 + 1),
			inputs_b: vec![],
			outputs_b: vec![],
			expect_error: Some(AbortReason::ExceededNumberOfInputsOrOutputs),
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
