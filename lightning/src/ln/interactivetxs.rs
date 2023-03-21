// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

use std::collections::{HashMap, HashSet};

use bitcoin::{psbt::Psbt, TxIn, Sequence, Transaction, TxOut, OutPoint};

use super::msgs::TxAddInput;

/// The number of received `tx_add_input` messages during a negotiation at which point the
/// negotiation MUST be failed.
const MAX_RECEIVED_TX_ADD_INPUT_COUNT: u16 = 4096;

/// The number of received `tx_add_output` messages during a negotiation at which point the
/// negotiation MUST be failed.
const MAX_RECEIVED_TX_ADD_OUTPUT_COUNT: u16 = 4096;

type SerialId = u64;
trait SerialIdExt {
	fn is_valid_for_initiator(&self) -> bool;
}
impl SerialIdExt for SerialId {
	fn is_valid_for_initiator(&self) -> bool { self % 2 == 0 }
}

pub(crate) enum InteractiveTxConstructionError {
	InputsNotConfirmed,
	ReceivedTooManyTxAddInputs,
	ReceivedTooManyTxAddOutputs,
	IncorrectInputSequenceValue,
	IncorrectSerialIdParity,
	SerialIdUnknown,
	DuplicateSerialId,
	PrevTxOutInvalid,
}

// States
// TODO: ASCII state machine
pub(crate) trait AcceptingChanges {}

/// We are currently in the process of negotiating the transaction.
pub(crate) struct Negotiating;
/// We have sent a `tx_complete` message and are awaiting the counterparty's.
pub(crate) struct OurTxComplete;
/// We have received a `tx_complete` message and the counterparty is awaiting ours.
pub(crate) struct TheirTxComplete;
/// We have exchanged consecutive `tx_complete` messages with the counterparty and the transaction
/// negotiation is complete.
pub(crate) struct NegotiationComplete;
/// We have sent a `tx_signatures` message and the counterparty is awaiting ours.
pub(crate) struct OurTxSignatures;
/// We have received a `tx_signatures` message from the counterparty
pub(crate) struct TheirTxSignatures;
/// The negotiation has failed and cannot be continued.
pub(crate) struct NegotiationFailed {
	error: InteractiveTxConstructionError,
}

// TODO: Add RBF negotiation

impl AcceptingChanges for Negotiating {}
impl AcceptingChanges for OurTxComplete {}

struct NegotiationContext {
	channel_id: [u8; 32],
	require_confirmed_inputs: bool,
	holder_is_initiator: bool,
	received_tx_add_input_count: u16,
	received_tx_add_output_count: u16,
	inputs: HashMap<u64, TxIn>,
	prevtx_outpoints: HashSet<OutPoint>,
	outputs: HashMap<u64, TxOut>,
	base_tx: Transaction,
}

pub(crate) struct InteractiveTxConstructor<S> {
	inner: Box<NegotiationContext>,
	state: S,
}

impl InteractiveTxConstructor<Negotiating> {
	fn new(channel_id: [u8; 32], require_confirmed_inputs: bool, is_initiator: bool, base_tx: Transaction) -> Self {
		Self {
			inner: Box::new(NegotiationContext {
				channel_id,
				require_confirmed_inputs,
				holder_is_initiator: is_initiator,
				received_tx_add_input_count: 0,
				received_tx_add_output_count: 0,
				inputs: HashMap::new(),
				prevtx_outpoints: HashSet::new(),
				outputs: HashMap::new(),
				base_tx,
			}),
			state: Negotiating,
		}
	}
}

impl<S> InteractiveTxConstructor<S>
	where S: AcceptingChanges {
	fn fail_negotiation(self, error: InteractiveTxConstructionError) ->
	Result<InteractiveTxConstructor<Negotiating>, InteractiveTxConstructor<NegotiationFailed>> {
		Err(InteractiveTxConstructor { inner: self.inner, state: NegotiationFailed { error } })
	}

	fn receive_tx_add_input(mut self, serial_id: SerialId, msg: TxAddInput, confirmed: bool) ->
	Result<InteractiveTxConstructor<Negotiating>, InteractiveTxConstructor<NegotiationFailed>> {
		// - TODO: MUST fail the negotiation if:
		//   - `prevtx` is not a valid transaction
		if !self.is_valid_counterparty_serial_id(serial_id) {
			// The receiving node:
			//  - MUST fail the negotiation if:
			//     - the `serial_id` has the wrong parity
			return self.fail_negotiation(InteractiveTxConstructionError::IncorrectSerialIdParity);
		}

		if msg.sequence >= 0xFFFFFFFE {
			// The receiving node:
			//  - MUST fail the negotiation if:
			//    - `sequence` is set to `0xFFFFFFFE` or `0xFFFFFFFF`
			return self.fail_negotiation(InteractiveTxConstructionError::IncorrectInputSequenceValue);
		}

		if self.inner.require_confirmed_inputs && !confirmed {
			return self.fail_negotiation(InteractiveTxConstructionError::InputsNotConfirmed);
		}

		if let Some(tx_out) = msg.prevtx.output.get(msg.prevtx_out as usize) {
			if !tx_out.script_pubkey.is_witness_program() {
				// The receiving node:
				//  - MUST fail the negotiation if:
				//     - the `scriptPubKey` is not a witness program
				return self.fail_negotiation(InteractiveTxConstructionError::PrevTxOutInvalid);
			} else if !self.inner.prevtx_outpoints.insert(OutPoint { txid: msg.prevtx.txid(), vout: msg.prevtx_out }) {
				// The receiving node:
				//  - MUST fail the negotiation if:
				//     - the `prevtx` and `prevtx_vout` are identical to a previously added
				//       (and not removed) input's
				return self.fail_negotiation(InteractiveTxConstructionError::PrevTxOutInvalid);
			}
		} else {
			// The receiving node:
			//  - MUST fail the negotiation if:
			//     - `prevtx_vout` is greater or equal to the number of outputs on `prevtx`
			return self.fail_negotiation(InteractiveTxConstructionError::PrevTxOutInvalid);
		}

		self.inner.received_tx_add_input_count += 1;
		if self.inner.received_tx_add_input_count > MAX_RECEIVED_TX_ADD_INPUT_COUNT {
			// The receiving node:
			//  - MUST fail the negotiation if:
			//     - if has received 4096 `tx_add_input` messages during this negotiation
			return self.fail_negotiation(InteractiveTxConstructionError::ReceivedTooManyTxAddInputs);
		}

		if let None = self.inner.inputs.insert(serial_id, TxIn {
			previous_output: OutPoint { txid: msg.prevtx.txid(), vout: msg.prevtx_out },
			sequence: Sequence(msg.sequence),
			..Default::default()
		}) {
			Ok(InteractiveTxConstructor { inner: self.inner, state: Negotiating {} })
		} else {
			// The receiving node:
			//  - MUST fail the negotiation if:
			//    - the `serial_id` is already included in the transaction
			self.fail_negotiation(InteractiveTxConstructionError::DuplicateSerialId)
		}
	}

	fn receive_tx_remove_input(mut self, serial_id: SerialId) ->
	Result<InteractiveTxConstructor<Negotiating>, InteractiveTxConstructor<NegotiationFailed>> {
		if !self.is_valid_counterparty_serial_id(serial_id) {
			return self.fail_negotiation(InteractiveTxConstructionError::IncorrectSerialIdParity);
		}

		if let Some(input) = self.inner.inputs.remove(&serial_id) {
			self.inner.prevtx_outpoints.remove(&input.previous_output);
			Ok(InteractiveTxConstructor { inner: self.inner, state: Negotiating {} })
		} else {
			// The receiving node:
			//  - MUST fail the negotiation if:
			//    - the input or output identified by the `serial_id` was not added by the sender
			//    - the `serial_id` does not correspond to a currently added input
			self.fail_negotiation(InteractiveTxConstructionError::SerialIdUnknown)
		}
	}

	fn receive_tx_add_output(mut self, serial_id: u64, output: TxOut) ->
	Result<InteractiveTxConstructor<Negotiating>, InteractiveTxConstructor<NegotiationFailed>> {
		self.inner.received_tx_add_output_count += 1;
		if self.inner.received_tx_add_output_count > MAX_RECEIVED_TX_ADD_OUTPUT_COUNT {
			// The receiving node:
			//  - MUST fail the negotiation if:
			//     - if has received 4096 `tx_add_output` messages during this negotiation
			return self.fail_negotiation(InteractiveTxConstructionError::ReceivedTooManyTxAddOutputs);
		}

		if let None = self.inner.outputs.insert(serial_id, output) {
			Ok(InteractiveTxConstructor { inner: self.inner, state: Negotiating {} })
		} else {
			// The receiving node:
			//  - MUST fail the negotiation if:
			//    - the `serial_id` is already included in the transaction
			self.fail_negotiation(InteractiveTxConstructionError::DuplicateSerialId)
		}
	}


	fn send_tx_add_input(mut self, serial_id: u64, input: TxIn) -> InteractiveTxConstructor<Negotiating> {
		self.inner.inputs.insert(serial_id, input);
		InteractiveTxConstructor { inner: self.inner, state: Negotiating {} }
	}

	pub(crate) fn send_tx_add_output(mut self, serial_id: u64, output: TxOut) -> InteractiveTxConstructor<Negotiating> {
		self.inner.outputs.insert(serial_id, output);
		InteractiveTxConstructor { inner: self.inner, state: Negotiating {} }
	}

	pub(crate) fn send_tx_abort(mut self) -> InteractiveTxConstructor<NegotiationFailed> {
		todo!();
	}

	pub(crate) fn receive_tx_abort(mut self) -> InteractiveTxConstructor<NegotiationFailed> {
		todo!();
	}

	fn is_valid_counterparty_serial_id(&self, serial_id: SerialId) -> bool {
		// A received `SerialId`'s parity must match the role of the counterparty.
		self.inner.holder_is_initiator == !serial_id.is_valid_for_initiator()
	}
}

impl InteractiveTxConstructor<TheirTxComplete> {
	fn send_tx_complete(self) -> InteractiveTxConstructor<NegotiationComplete> {
		InteractiveTxConstructor {
			inner: self.inner,
			state: NegotiationComplete {}
		}
	}
}

impl InteractiveTxConstructor<OurTxComplete> {
	fn receive_tx_complete(self) -> InteractiveTxConstructor<NegotiationComplete> {
		InteractiveTxConstructor {
			inner: self.inner,
			state: NegotiationComplete {}
		}
	}
}

impl InteractiveTxConstructor<NegotiationComplete> {
	fn get_psbt(&self) -> Result<Psbt, InteractiveTxConstructionError> {
		// Build PSBT from inputs & outputs
		todo!();
	}
}
