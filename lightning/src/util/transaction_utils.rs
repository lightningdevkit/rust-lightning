// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

use bitcoin::amount::Amount;
use bitcoin::consensus::encode::VarInt;
use bitcoin::consensus::Encodable;
use bitcoin::script::ScriptBuf;
use bitcoin::transaction::{Transaction, TxOut};

#[allow(unused_imports)]
use crate::prelude::*;

use crate::io_extras::sink;
use core::cmp::Ordering;

pub fn sort_outputs<T, C: Fn(&T, &T) -> Ordering>(outputs: &mut Vec<(TxOut, T)>, tie_breaker: C) {
	outputs.sort_unstable_by(|a, b| {
		a.0.value.cmp(&b.0.value).then_with(|| {
			a.0.script_pubkey[..].cmp(&b.0.script_pubkey[..]).then_with(|| tie_breaker(&a.1, &b.1))
		})
	});
}

/// Possibly adds a change output to the given transaction, always doing so if there are excess
/// funds available beyond the requested feerate.
/// Assumes at least one input will have a witness (ie spends a segwit output).
/// Returns an Err(()) if the requested feerate cannot be met.
/// Returns the expected maximum weight of the fully signed transaction on success.
pub(crate) fn maybe_add_change_output(
	tx: &mut Transaction, input_value: Amount, witness_max_weight: u64,
	feerate_sat_per_1000_weight: u32, change_destination_script: ScriptBuf,
) -> Result<u64, ()> {
	if input_value > Amount::MAX_MONEY {
		return Err(());
	}

	const WITNESS_FLAG_BYTES: u64 = 2;

	let mut output_value = Amount::ZERO;
	for output in tx.output.iter() {
		output_value += output.value;
		if output_value >= input_value {
			return Err(());
		}
	}

	let dust_value = change_destination_script.minimal_non_dust();
	let mut change_output = TxOut { script_pubkey: change_destination_script, value: Amount::ZERO };
	let change_len = change_output.consensus_encode(&mut sink()).unwrap();
	let starting_weight = tx.weight().to_wu() + WITNESS_FLAG_BYTES + witness_max_weight as u64;
	let mut weight_with_change: i64 = starting_weight as i64 + change_len as i64 * 4;
	// Include any extra bytes required to push an extra output.
	weight_with_change += (VarInt(tx.output.len() as u64 + 1).size()
		- VarInt(tx.output.len() as u64).size()) as i64
		* 4;
	// When calculating weight, add two for the flag bytes
	let change_value: i64 = (input_value - output_value).to_sat() as i64
		- weight_with_change * feerate_sat_per_1000_weight as i64 / 1000;
	if change_value >= dust_value.to_sat() as i64 {
		change_output.value = Amount::from_sat(change_value as u64);
		tx.output.push(change_output);
		Ok(weight_with_change as u64)
	} else if (input_value - output_value).to_sat() as i64
		- (starting_weight as i64) * feerate_sat_per_1000_weight as i64 / 1000
		< 0
	{
		Err(())
	} else {
		Ok(starting_weight)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	use bitcoin::amount::Amount;
	use bitcoin::hash_types::Txid;
	use bitcoin::hashes::Hash;
	use bitcoin::hex::FromHex;
	use bitcoin::locktime::absolute::LockTime;
	use bitcoin::script::Builder;
	use bitcoin::transaction::{OutPoint, TxIn, Version};
	use bitcoin::{PubkeyHash, Sequence, Witness};

	use alloc::vec;

	#[test]
	fn sort_output_by_value() {
		let txout1 = TxOut {
			value: Amount::from_sat(100),
			script_pubkey: Builder::new().push_int(0).into_script(),
		};
		let txout1_ = txout1.clone();

		let txout2 = TxOut {
			value: Amount::from_sat(99),
			script_pubkey: Builder::new().push_int(0).into_script(),
		};
		let txout2_ = txout2.clone();

		let mut outputs = vec![(txout1, "ignore"), (txout2, "ignore")];
		sort_outputs(&mut outputs, |_, _| {
			unreachable!();
		});

		assert_eq!(&outputs, &vec![(txout2_, "ignore"), (txout1_, "ignore")]);
	}

	#[test]
	fn sort_output_by_script_pubkey() {
		let txout1 = TxOut {
			value: Amount::from_sat(100),
			script_pubkey: Builder::new().push_int(3).into_script(),
		};
		let txout1_ = txout1.clone();

		let txout2 = TxOut {
			value: Amount::from_sat(100),
			script_pubkey: Builder::new().push_int(1).push_int(2).into_script(),
		};
		let txout2_ = txout2.clone();

		let mut outputs = vec![(txout1, "ignore"), (txout2, "ignore")];
		sort_outputs(&mut outputs, |_, _| {
			unreachable!();
		});

		assert_eq!(&outputs, &vec![(txout2_, "ignore"), (txout1_, "ignore")]);
	}

	#[test]
	fn sort_output_by_bip_test() {
		let txout1 = TxOut {
			value: Amount::from_sat(100000000),
			script_pubkey: script_from_hex("41046a0765b5865641ce08dd39690aade26dfbf5511430ca428a3089261361cef170e3929a68aee3d8d4848b0c5111b0a37b82b86ad559fd2a745b44d8e8d9dfdc0cac")
		};
		let txout1_ = txout1.clone();

		// doesn't deserialize cleanly:
		let txout2 = TxOut {
			value: Amount::from_sat(2400000000),
			script_pubkey: script_from_hex("41044a656f065871a353f216ca26cef8dde2f03e8c16202d2e8ad769f02032cb86a5eb5e56842e92e19141d60a01928f8dd2c875a390f67c1f6c94cfc617c0ea45afac")
		};
		let txout2_ = txout2.clone();

		let mut outputs = vec![(txout1, "ignore"), (txout2, "ignore")];
		sort_outputs(&mut outputs, |_, _| {
			unreachable!();
		});

		assert_eq!(&outputs, &vec![(txout1_, "ignore"), (txout2_, "ignore")]);
	}

	#[test]
	fn sort_output_tie_breaker_test() {
		let txout1 = TxOut {
			value: Amount::from_sat(100),
			script_pubkey: Builder::new().push_int(1).push_int(2).into_script(),
		};
		let txout1_ = txout1.clone();

		let txout2 = txout1.clone();
		let txout2_ = txout1.clone();

		let mut outputs = vec![(txout1, 420), (txout2, 69)];
		sort_outputs(&mut outputs, |a, b| a.cmp(b));

		assert_eq!(&outputs, &vec![(txout2_, 69), (txout1_, 420)]);
	}

	fn script_from_hex(hex_str: &str) -> ScriptBuf {
		ScriptBuf::from(<Vec<u8>>::from_hex(hex_str).unwrap())
	}

	macro_rules! bip_txout_tests {
		($($name:ident: $value:expr,)*) => {
			$(
				#[test]
				fn $name() {
					let expected_raw: Vec<(u64, &str)> = $value;
					let expected: Vec<(TxOut, &str)> = expected_raw.iter()
						.map(|txout_raw| TxOut {
							value: Amount::from_sat(txout_raw.0),
							script_pubkey: script_from_hex(txout_raw.1)
						}).map(|txout| (txout, "ignore"))
					.collect();

					let mut outputs = expected.clone();
					outputs.reverse(); // prep it

					// actually do the work!
					sort_outputs(&mut outputs, |_, _| { unreachable!(); });

					assert_eq!(outputs, expected);
				}
			)*
		}
	}

	const TXOUT1: [(u64, &str); 2] = [
		(400057456, "76a9144a5fba237213a062f6f57978f796390bdcf8d01588ac"),
		(40000000000, "76a9145be32612930b8323add2212a4ec03c1562084f8488ac"),
	];
	const TXOUT2: [(u64, &str); 2] = [
		(100000000, "41046a0765b5865641ce08dd39690aade26dfbf5511430ca428a3089261361cef170e3929a68aee3d8d4848b0c5111b0a37b82b86ad559fd2a745b44d8e8d9dfdc0cac"),
		(2400000000, "41044a656f065871a353f216ca26cef8dde2f03e8c16202d2e8ad769f02032cb86a5eb5e56842e92e19141d60a01928f8dd2c875a390f67c1f6c94cfc617c0ea45afac"),
	];
	bip_txout_tests! {
		bip69_txout_test_1: TXOUT1.to_vec(),
		bip69_txout_test_2: TXOUT2.to_vec(),
	}

	#[test]
	fn test_tx_value_overrun() {
		// If we have a bogus input amount or outputs valued more than inputs, we should fail
		let mut tx = Transaction {
			version: Version::TWO,
			lock_time: LockTime::ZERO,
			input: Vec::new(),
			output: vec![TxOut { script_pubkey: ScriptBuf::new(), value: Amount::from_sat(1000) }],
		};
		assert!(maybe_add_change_output(
			&mut tx,
			Amount::from_sat(21_000_000_0000_0001),
			0,
			253,
			ScriptBuf::new()
		)
		.is_err());
		assert!(maybe_add_change_output(&mut tx, Amount::from_sat(400), 0, 253, ScriptBuf::new())
			.is_err());
		assert!(maybe_add_change_output(&mut tx, Amount::from_sat(4000), 0, 253, ScriptBuf::new())
			.is_ok());
	}

	#[test]
	fn test_tx_change_edge() {
		// Check that we never add dust outputs
		let mut tx = Transaction {
			version: Version::TWO,
			lock_time: LockTime::ZERO,
			input: Vec::new(),
			output: Vec::new(),
		};
		let orig_wtxid = tx.compute_wtxid();
		let output_spk = ScriptBuf::new_p2pkh(&PubkeyHash::hash(&[0; 0]));
		assert_eq!(output_spk.minimal_non_dust().to_sat(), 546);
		// base size = version size + varint[input count] + input size + varint[output count] + output size + lock time size
		// total size = version size + marker + flag + varint[input count] + input size + varint[output count] + output size + lock time size
		// weight = 3 * base size + total size = 3 * (4 + 1 + 0 + 1 + 0 + 4) + (4 + 1 + 1 + 1 + 0 + 1 + 0 + 4) = 3 * 10 + 12 = 42
		assert_eq!(tx.weight().to_wu(), 42);
		// 10 sats isn't enough to pay fee on a dummy transaction...
		assert!(maybe_add_change_output(&mut tx, Amount::from_sat(10), 0, 250, output_spk.clone())
			.is_err());
		assert_eq!(tx.compute_wtxid(), orig_wtxid); // Failure doesn't change the transaction
											// but 11 (= ceil(42 * 250 / 1000)) is, just not enough to add a change output...
		assert!(maybe_add_change_output(&mut tx, Amount::from_sat(11), 0, 250, output_spk.clone())
			.is_ok());
		assert_eq!(tx.output.len(), 0);
		assert_eq!(tx.compute_wtxid(), orig_wtxid); // If we don't add an output, we don't change the transaction
		assert!(maybe_add_change_output(
			&mut tx,
			Amount::from_sat(549),
			0,
			250,
			output_spk.clone()
		)
		.is_ok());
		assert_eq!(tx.output.len(), 0);
		assert_eq!(tx.compute_wtxid(), orig_wtxid); // If we don't add an output, we don't change the transaction
											// 590 is also not enough
		assert!(maybe_add_change_output(
			&mut tx,
			Amount::from_sat(590),
			0,
			250,
			output_spk.clone()
		)
		.is_ok());
		assert_eq!(tx.output.len(), 0);
		assert_eq!(tx.compute_wtxid(), orig_wtxid); // If we don't add an output, we don't change the transaction
											// at 591 we can afford the change output at the dust limit (546)
		assert!(maybe_add_change_output(
			&mut tx,
			Amount::from_sat(591),
			0,
			250,
			output_spk.clone()
		)
		.is_ok());
		assert_eq!(tx.output.len(), 1);
		assert_eq!(tx.output[0].value.to_sat(), 546);
		assert_eq!(tx.output[0].script_pubkey, output_spk);
		assert_eq!(tx.weight().to_wu() / 4, 590 - 546); // New weight is exactly the fee we wanted.

		tx.output.pop();
		assert_eq!(tx.compute_wtxid(), orig_wtxid); // The only change is the addition of one output.
	}

	#[test]
	fn test_tx_extra_outputs() {
		// Check that we correctly handle existing outputs
		let mut tx = Transaction {
			version: Version::TWO,
			lock_time: LockTime::ZERO,
			input: vec![TxIn {
				previous_output: OutPoint::new(Txid::all_zeros(), 0),
				script_sig: ScriptBuf::new(),
				witness: Witness::new(),
				sequence: Sequence::ZERO,
			}],
			output: vec![TxOut {
				script_pubkey: Builder::new().push_int(1).into_script(),
				value: Amount::from_sat(1000),
			}],
		};
		let orig_wtxid = tx.compute_wtxid();
		let orig_weight = tx.weight().to_wu();
		assert_eq!(orig_weight / 4, 61);

		assert_eq!(Builder::new().push_int(2).into_script().minimal_non_dust().to_sat(), 474);

		// Input value of the output value + fee - 1 should fail:
		assert!(maybe_add_change_output(
			&mut tx,
			Amount::from_sat(1000 + 61 + 100 - 1),
			400,
			250,
			Builder::new().push_int(2).into_script()
		)
		.is_err());
		assert_eq!(tx.compute_wtxid(), orig_wtxid); // Failure doesn't change the transaction
											// but one more input sat should succeed, without changing the transaction
		assert!(maybe_add_change_output(
			&mut tx,
			Amount::from_sat(1000 + 61 + 100),
			400,
			250,
			Builder::new().push_int(2).into_script()
		)
		.is_ok());
		assert_eq!(tx.compute_wtxid(), orig_wtxid); // If we don't add an output, we don't change the transaction
											// In order to get a change output, we need to add 474 plus the output's weight / 4 (10)...
		assert!(maybe_add_change_output(
			&mut tx,
			Amount::from_sat(1000 + 61 + 100 + 474 + 9),
			400,
			250,
			Builder::new().push_int(2).into_script()
		)
		.is_ok());
		assert_eq!(tx.compute_wtxid(), orig_wtxid); // If we don't add an output, we don't change the transaction

		assert!(maybe_add_change_output(
			&mut tx,
			Amount::from_sat(1000 + 61 + 100 + 474 + 10),
			400,
			250,
			Builder::new().push_int(2).into_script()
		)
		.is_ok());
		assert_eq!(tx.output.len(), 2);
		assert_eq!(tx.output[1].value.to_sat(), 474);
		assert_eq!(tx.output[1].script_pubkey, Builder::new().push_int(2).into_script());
		assert_eq!(tx.weight().to_wu() - orig_weight, 40); // Weight difference matches what we had to add above
		tx.output.pop();
		assert_eq!(tx.compute_wtxid(), orig_wtxid); // The only change is the addition of one output.
	}
}
