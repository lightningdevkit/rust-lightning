// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

use std::collections::{HashMap, HashSet};

use bitcoin::{TxIn, Sequence, Transaction, TxOut, OutPoint};
use crate::ln::interactivetxs::ChannelMode::Indeterminate;

use super::msgs::TxAddInput;

/// The number of received `tx_add_input` messages during a negotiation at which point the
/// negotiation MUST be failed.
const MAX_RECEIVED_TX_ADD_INPUT_COUNT: u16 = 4096;

/// The number of received `tx_add_output` messages during a negotiation at which point the
/// negotiation MUST be failed.
const MAX_RECEIVED_TX_ADD_OUTPUT_COUNT: u16 = 4096;
const MAX_MONEY: u64 = 2_100_000_000_000_000;

type SerialId = u64;
trait SerialIdExt {
	fn is_valid_for_initiator(&self) -> bool;
}
impl SerialIdExt for SerialId {
	fn is_valid_for_initiator(&self) -> bool { self % 2 == 0 }
}

pub(crate) enum AbortReason {
	CounterpartyAborted,
	InputsNotConfirmed,
	ReceivedTooManyTxAddInputs,
	ReceivedTooManyTxAddOutputs,
	IncorrectInputSequenceValue,
	IncorrectSerialIdParity,
	SerialIdUnknown,
	DuplicateSerialId,
	PrevTxOutInvalid,
	ExceededMaximumSatsAllowed,
}

//                   Interactive Transaction Construction negotiation
//                           from the perspective of a holder
//
//                               AcceptingChanges
//                        ┌──────────────────────────────┐
//                        │                              │
//                        │           ┌────────────────┐ │
//                        │           │(sent/received) │ │
//                        │           │tx_add_input    │ │
//                        │           │tx_add_output   │ │
//                        │           │tx_remove_input │ │
//                        │           │tx_remove_output│ │
//                        │           └───┐       ┌────┘ │
//                        │               │       ▼      │
//            ────────────┼──────────►┌───┴───────────┐  │        received_tx_complete                   ┌─────────────────────┐
//    accept_channel2     │           │               ├──┼───────────────────┐          sent_tx_complete │                     │
// or splice_ack          │     ┌─────┤  Negotiating  │  │                   ▼          ┌───────────────►│ NegotiationComplete │◄──┐
// or tx_ack_rbf          │     │     │               │  │          ┌─────────────────┐ │                │                     │   │
//    (sent or received)  │     │ ┌──►└───────────────┘  │          │                 │ │                └─────────────────────┘   │
//                              │ │                      │          │ TheirTxComplete ├─┘                                          │
//             sent_tx_complete │ │ received_tx_add_*    │          │                 │                   ┌────────────────────┐   │
//                              │ │ received_tx_remove_* │          └─────────────────┘                   │                    │   │
//                        │     │ │                      │                                            ┌──►│ NegotiationAborted │   │
//                        │     │ └───┬───────────────┐  │        (sent/received)_tx_abort            │   │                    │   │
//                        │     │     │               │  ├────────────────────────────────────────────┘   └────────────────────┘   │
//                        │     └────►│ OurTxComplete │  │                                                                         │
//                        │           │               ├──┼──┐                                                                      │
//                        │           └───────────────┘  │  └──────────────────────────────────────────────────────────────────────┘
//                        │                              │                         received_tx_complete
//                        │                              │
//                        └──────────────────────────────┘
//
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
/// The negotiation has failed and cannot be continued.
pub(crate) struct NegotiationAborted(AbortReason);

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
	did_send_tx_signatures: bool,
}

pub(crate) struct InteractiveTxConstructor<S> {
	context: NegotiationContext,
	state: S,
}

impl InteractiveTxConstructor<Negotiating> {
	fn new(
		channel_id: [u8; 32],
		require_confirmed_inputs: bool,
		is_initiator: bool,
		base_tx: Transaction,
		did_send_tx_signatures: bool,
	) -> Self {
		Self {
			context: NegotiationContext {
				channel_id,
				require_confirmed_inputs,
				base_tx,
				did_send_tx_signatures,
				holder_is_initiator: is_initiator,
				received_tx_add_input_count: 0,
				received_tx_add_output_count: 0,
				inputs: HashMap::new(),
				prevtx_outpoints: HashSet::new(),
				outputs: HashMap::new(),
			},
			state: Negotiating,
		}
	}
}

impl<S> InteractiveTxConstructor<S>
	where S: AcceptingChanges {
	fn abort_negotiation(self, reason: AbortReason) ->
	Result<InteractiveTxConstructor<Negotiating>, InteractiveTxConstructor<NegotiationAborted>> {

		Err(InteractiveTxConstructor { context: self.context, state: NegotiationAborted(reason) })
	}

	fn receive_tx_add_input(mut self, serial_id: SerialId, msg: TxAddInput, confirmed: bool) ->
	Result<InteractiveTxConstructor<Negotiating>, InteractiveTxConstructor<NegotiationAborted>> {
		// - TODO: MUST fail the negotiation if:
		//   - `prevtx` is not a valid transaction
		if !self.is_valid_counterparty_serial_id(serial_id) {
			// The receiving node:
			//  - MUST fail the negotiation if:
			//     - the `serial_id` has the wrong parity
			return self.abort_negotiation(AbortReason::IncorrectSerialIdParity);
		}

		if msg.sequence >= 0xFFFFFFFE {
			// The receiving node:
			//  - MUST fail the negotiation if:
			//    - `sequence` is set to `0xFFFFFFFE` or `0xFFFFFFFF`
			return self.abort_negotiation(AbortReason::IncorrectInputSequenceValue);
		}

		if self.context.require_confirmed_inputs && !confirmed {
			return self.abort_negotiation(AbortReason::InputsNotConfirmed);
		}

		if let Some(tx_out) = msg.prevtx.output.get(msg.prevtx_out as usize) {
			if !tx_out.script_pubkey.is_witness_program() {
				// The receiving node:
				//  - MUST fail the negotiation if:
				//     - the `scriptPubKey` is not a witness program
				return self.abort_negotiation(AbortReason::PrevTxOutInvalid);
			} else if !self.context.prevtx_outpoints.insert(OutPoint { txid: msg.prevtx.txid(), vout: msg.prevtx_out }) {
				// The receiving node:
				//  - MUST fail the negotiation if:
				//     - the `prevtx` and `prevtx_vout` are identical to a previously added
				//       (and not removed) input's
				return self.abort_negotiation(AbortReason::PrevTxOutInvalid);
			}
		} else {
			// The receiving node:
			//  - MUST fail the negotiation if:
			//     - `prevtx_vout` is greater or equal to the number of outputs on `prevtx`
			return self.abort_negotiation(AbortReason::PrevTxOutInvalid);
		}

		self.context.received_tx_add_input_count += 1;
		if self.context.received_tx_add_input_count > MAX_RECEIVED_TX_ADD_INPUT_COUNT {
			// The receiving node:
			//  - MUST fail the negotiation if:
			//     - if has received 4096 `tx_add_input` messages during this negotiation
			return self.abort_negotiation(AbortReason::ReceivedTooManyTxAddInputs);
		}

		if let None = self.context.inputs.insert(serial_id, TxIn {
			previous_output: OutPoint { txid: msg.prevtx.txid(), vout: msg.prevtx_out },
			sequence: Sequence(msg.sequence),
			..Default::default()
		}) {
			Ok(InteractiveTxConstructor { context: self.context, state: Negotiating {} })
		} else {
			// The receiving node:
			//  - MUST fail the negotiation if:
			//    - the `serial_id` is already included in the transaction
			self.abort_negotiation(AbortReason::DuplicateSerialId)
		}
	}

	fn receive_tx_remove_input(mut self, serial_id: SerialId) ->
	Result<InteractiveTxConstructor<Negotiating>, InteractiveTxConstructor<NegotiationAborted>> {
		if !self.is_valid_counterparty_serial_id(serial_id) {
			return self.abort_negotiation(AbortReason::IncorrectSerialIdParity);
		}

		if let Some(input) = self.context.inputs.remove(&serial_id) {
			self.context.prevtx_outpoints.remove(&input.previous_output);
			Ok(InteractiveTxConstructor { context: self.context, state: Negotiating {} })
		} else {
			// The receiving node:
			//  - MUST fail the negotiation if:
			//    - the input or output identified by the `serial_id` was not added by the sender
			//    - the `serial_id` does not correspond to a currently added input
			self.abort_negotiation(AbortReason::SerialIdUnknown)
		}
	}

	fn receive_tx_add_output(mut self, serial_id: u64, output: TxOut) ->
	Result<InteractiveTxConstructor<Negotiating>, InteractiveTxConstructor<NegotiationAborted>> {
		// TODO: the sats amount is less than the dust_limit
		self.context.received_tx_add_output_count += 1;
		if self.context.received_tx_add_output_count > MAX_RECEIVED_TX_ADD_OUTPUT_COUNT {
			// The receiving node:
			//  - MUST fail the negotiation if:
			//     - if has received 4096 `tx_add_output` messages during this negotiation
			return self.abort_negotiation(AbortReason::ReceivedTooManyTxAddOutputs);
		}

		if output.value > MAX_MONEY {
			// The receiving node:
			// - MUST fail the negotiation if:
			//		- the sats amount is greater than 2,100,000,000,000,000 (MAX_MONEY)
			return self.abort_negotiation(AbortReason::ExceededMaximumSatsAllowed);
		}

		if let None = self.context.outputs.insert(serial_id, output) {
			Ok(InteractiveTxConstructor { context: self.context, state: Negotiating {} })
		} else {
			// The receiving node:
			//  - MUST fail the negotiation if:
			//    - the `serial_id` is already included in the transaction
			self.abort_negotiation(AbortReason::DuplicateSerialId)
		}
	}

	pub(crate) fn receive_tx_abort(mut self) -> InteractiveTxConstructor<NegotiationAborted> {
		todo!();
	}

	fn send_tx_add_input(mut self, serial_id: u64, input: TxIn) -> InteractiveTxConstructor<Negotiating> {
		self.context.inputs.insert(serial_id, input);
		InteractiveTxConstructor { context: self.context, state: Negotiating {} }
	}

	pub(crate) fn send_tx_add_output(mut self, serial_id: u64, output: TxOut) -> InteractiveTxConstructor<Negotiating> {
		self.context.outputs.insert(serial_id, output);
		InteractiveTxConstructor { context: self.context, state: Negotiating {} }
	}

	pub(crate) fn send_tx_abort(mut self) -> InteractiveTxConstructor<NegotiationAborted> {
		// A sending node:
		// 	- MUST NOT have already transmitted tx_signatures
		// 	- SHOULD forget the current negotiation and reset their state.
		todo!();
	}

	fn is_valid_counterparty_serial_id(&self, serial_id: SerialId) -> bool {
		// A received `SerialId`'s parity must match the role of the counterparty.
		self.context.holder_is_initiator == !serial_id.is_valid_for_initiator()
	}
}

impl InteractiveTxConstructor<TheirTxComplete> {
	fn send_tx_complete(self) -> InteractiveTxConstructor<NegotiationComplete> {
		InteractiveTxConstructor {
			context: self.context,
			state: NegotiationComplete {}
		}
	}
}

impl InteractiveTxConstructor<OurTxComplete> {
	fn receive_tx_complete(self) -> InteractiveTxConstructor<NegotiationComplete> {
		InteractiveTxConstructor {
			context: self.context,
			state: NegotiationComplete {}
		}
	}
}

impl InteractiveTxConstructor<NegotiationComplete> {
	fn get_psbt(&self) -> Result<Transaction, AbortReason> {
		// Build transaction from inputs & outputs in `NegotiationContext`.
		return Ok(Transaction {
			version: self.context.base_tx.version,
			lock_time: self.context.base_tx.lock_time,
			input: self.context.inputs.values().cloned().collect(),
			output: self.context.outputs.values().cloned().collect(),
		})
	}
}

enum ChannelMode {
	Negotiating(InteractiveTxConstructor<Negotiating>),
	OurTxComplete(InteractiveTxConstructor<OurTxComplete>),
	TheirTxComplete(InteractiveTxConstructor<TheirTxComplete>),
	NegotiationComplete(InteractiveTxConstructor<NegotiationComplete>),
	NegotiationAborted(InteractiveTxConstructor<NegotiationAborted>),
	Indeterminate,
}

impl Default for ChannelMode {
	fn default() -> Self { Indeterminate }
}

#[cfg(test)]
mod tests {
	use core::str::FromStr;
	use std::collections::HashMap;
	use crate::ln::interactivetxs::ChannelMode::{Negotiating, NegotiationAborted};
	use crate::ln::interactivetxs::{ChannelMode, InteractiveTxConstructor};
	use crate::ln::msgs::TransactionU16LenLimited;
	use bitcoin::consensus::encode;
	use bitcoin::{Address, PackedLockTime, Script, Sequence, Transaction, Txid, TxIn, TxOut, Witness};
	use bitcoin::hashes::hex::FromHex;
	use crate::chain::transaction::OutPoint;
	use crate::ln::msgs::TxAddInput;

	struct DummyChannel {
		mode: ChannelMode,
	}

	impl DummyChannel {
		fn new() -> Self {
			let tx: Transaction = encode::deserialize(&hex::decode("020000000001010e0ade\
			f48412e4361325ac1c6e36411299ab09d4f083b9d8ddb55fbc06e1b0c00000000000feffffff0220a107000\
			0000000220020f81d95e040bd0a493e38bae27bff52fe2bb58b93b293eb579c01c31b05c5af1dc072cfee54\
			a3000016001434b1d6211af5551905dc2642d05f5b04d25a8fe80247304402207f570e3f0de50546aad25a8\
			72e3df059d277e776dda4269fa0d2cc8c2ee6ec9a022054e7fae5ca94d47534c86705857c24ceea3ad51c69\
			dd6051c5850304880fc43a012103cb11a1bacc223d98d91f1946c6752e358a5eb1a1c983b3e6fb15378f453\
			b76bd00000000").unwrap()[..]).unwrap();
			Self {
				mode: Negotiating(InteractiveTxConstructor::new(
					[0; 32],
					true,
					true,
					tx,
					false,
				))
			}
		}

		fn handle_add_tx_input(&mut self) {
			// We use mem::take here because we want to update `self.mode` based on its value and
			// avoid cloning `ChannelMode`.
			// By moving the value out of the struct, we can now safely modify it in this scope.
			let mut mode = core::mem::take(&mut self.mode);
			self.mode = if let Negotiating(constructor) = mode {
				match constructor.receive_tx_add_input(
					1234,
					get_sample_tx_add_input(),
					true
				) {
					Ok(c) => Negotiating(c),
					Err(c) => NegotiationAborted(c),
				}
			} else {
				mode
			}
		}
	}

	// Fixtures
	fn get_sample_tx_add_input() -> TxAddInput {
		let prevtx = TransactionU16LenLimited::new(
			Transaction {
				version: 2,
				lock_time: PackedLockTime(0),
				input: vec![TxIn {
					previous_output: OutPoint { txid: Txid::from_hex("305bab643ee297b8b6b76b320792c8223d55082122cb606bf89382146ced9c77").unwrap(), index: 2 }.into_bitcoin_outpoint(),
					script_sig: Script::new(),
					sequence: Sequence(0xfffffffd),
					witness: Witness::from_vec(vec![
						hex::decode("304402206af85b7dd67450ad12c979302fac49dfacbc6a8620f49c5da2b5721cf9565ca502207002b32fed9ce1bf095f57aeb10c36928ac60b12e723d97d2964a54640ceefa701").unwrap(),
						hex::decode("0301ab7dc16488303549bfcdd80f6ae5ee4c20bf97ab5410bbd6b1bfa85dcd6944").unwrap()]),
				}],
				output: vec![
					TxOut {
						value: 12704566,
						script_pubkey: Address::from_str("bc1qzlffunw52jav8vwdu5x3jfk6sr8u22rmq3xzw2").unwrap().script_pubkey(),
					},
					TxOut {
						value: 245148,
						script_pubkey: Address::from_str("bc1qxmk834g5marzm227dgqvynd23y2nvt2ztwcw2z").unwrap().script_pubkey(),
					},
				],
			}
		).unwrap();

		return TxAddInput {
			channel_id: [2; 32],
			serial_id: 4886718345,
			prevtx,
			prevtx_out: 305419896,
			sequence: 305419896,
		};
	}
}

