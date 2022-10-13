// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

use bitcoin::blockdata::transaction::{Transaction, TxOut};
use bitcoin::blockdata::script::Script;
use bitcoin::consensus::Encodable;
use bitcoin::consensus::encode::VarInt;

use crate::ln::msgs::MAX_VALUE_MSAT;

use crate::prelude::*;
use crate::io_extras::sink;
use core::cmp::Ordering;

pub fn sort_outputs<T, C : Fn(&T, &T) -> Ordering>(outputs: &mut Vec<(TxOut, T)>, tie_breaker: C) {
	outputs.sort_unstable_by(|a, b| {
		a.0.value.cmp(&b.0.value).then_with(|| {
			a.0.script_pubkey[..].cmp(&b.0.script_pubkey[..]).then_with(|| {
				tie_breaker(&a.1, &b.1)
			})
		})
	});
}

/// Possibly adds a change output to the given transaction, always doing so if there are excess
/// funds available beyond the requested feerate.
/// Assumes at least one input will have a witness (ie spends a segwit output).
/// Returns an Err(()) if the requested feerate cannot be met.
/// Returns the expected maximum weight of the fully signed transaction on success.
pub(crate) fn maybe_add_change_output(tx: &mut Transaction, input_value: u64, witness_max_weight: usize, feerate_sat_per_1000_weight: u32, change_destination_script: Script) -> Result<usize, ()> {
	if input_value > MAX_VALUE_MSAT / 1000 { return Err(()); }

	const WITNESS_FLAG_BYTES: i64 = 2;

	let mut output_value = 0;
	for output in tx.output.iter() {
		output_value += output.value;
		if output_value >= input_value { return Err(()); }
	}

	let dust_value = change_destination_script.dust_value();
	let mut change_output = TxOut {
		script_pubkey: change_destination_script,
		value: 0,
	};
	let change_len = change_output.consensus_encode(&mut sink()).unwrap();
	let starting_weight = tx.weight() + WITNESS_FLAG_BYTES as usize + witness_max_weight;
	let mut weight_with_change: i64 = starting_weight as i64 + change_len as i64 * 4;
	// Include any extra bytes required to push an extra output.
	weight_with_change += (VarInt(tx.output.len() as u64 + 1).len() - VarInt(tx.output.len() as u64).len()) as i64 * 4;
	// When calculating weight, add two for the flag bytes
	let change_value: i64 = (input_value - output_value) as i64 - weight_with_change * feerate_sat_per_1000_weight as i64 / 1000;
	if change_value >= dust_value.to_sat() as i64 {
		change_output.value = change_value as u64;
		tx.output.push(change_output);
		Ok(weight_with_change as usize)
	} else if (input_value - output_value) as i64 - (starting_weight as i64) * feerate_sat_per_1000_weight as i64 / 1000 < 0 {
		Err(())
	} else {
		Ok(starting_weight)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	use bitcoin::blockdata::transaction::{Transaction, TxOut, TxIn, OutPoint};
	use bitcoin::blockdata::script::{Script, Builder};
	use bitcoin::hash_types::{PubkeyHash, Txid};

	use bitcoin::hashes::Hash;
	use bitcoin::{PackedLockTime, Sequence, Witness};

	use hex::decode;

	use alloc::vec;

	#[test]
	fn sort_output_by_value() {
		let txout1 = TxOut {
			value:  100,
			script_pubkey: Builder::new().push_int(0).into_script()
		};
		let txout1_ = txout1.clone();

		let txout2 = TxOut {
			value: 99,
			script_pubkey: Builder::new().push_int(0).into_script()
		};
		let txout2_ = txout2.clone();

		let mut outputs = vec![(txout1, "ignore"), (txout2, "ignore")];
		sort_outputs(&mut outputs, |_, _| { unreachable!(); });

		assert_eq!(
			&outputs,
			&vec![(txout2_, "ignore"), (txout1_, "ignore")]
			);
	}

	#[test]
	fn sort_output_by_script_pubkey() {
		let txout1 = TxOut {
			value:  100,
			script_pubkey: Builder::new().push_int(3).into_script(),
		};
		let txout1_ = txout1.clone();

		let txout2 = TxOut {
			value: 100,
			script_pubkey: Builder::new().push_int(1).push_int(2).into_script()
		};
		let txout2_ = txout2.clone();

		let mut outputs = vec![(txout1, "ignore"), (txout2, "ignore")];
		sort_outputs(&mut outputs, |_, _| { unreachable!(); });

		assert_eq!(
			&outputs,
			&vec![(txout2_, "ignore"), (txout1_, "ignore")]
			);
	}

	#[test]
	fn sort_output_by_bip_test() {
		let txout1 = TxOut {
			value: 100000000,
			script_pubkey: script_from_hex("41046a0765b5865641ce08dd39690aade26dfbf5511430ca428a3089261361cef170e3929a68aee3d8d4848b0c5111b0a37b82b86ad559fd2a745b44d8e8d9dfdc0cac")
		};
		let txout1_ = txout1.clone();

		// doesn't deserialize cleanly:
		let txout2 = TxOut {
			value: 2400000000,
			script_pubkey: script_from_hex("41044a656f065871a353f216ca26cef8dde2f03e8c16202d2e8ad769f02032cb86a5eb5e56842e92e19141d60a01928f8dd2c875a390f67c1f6c94cfc617c0ea45afac")
		};
		let txout2_ = txout2.clone();

		let mut outputs = vec![(txout1, "ignore"), (txout2, "ignore")];
		sort_outputs(&mut outputs, |_, _| { unreachable!(); });

		assert_eq!(&outputs, &vec![(txout1_, "ignore"), (txout2_, "ignore")]);
	}

	#[test]
	fn sort_output_tie_breaker_test() {
		let txout1 = TxOut {
			value:  100,
			script_pubkey: Builder::new().push_int(1).push_int(2).into_script()
		};
		let txout1_ = txout1.clone();

		let txout2 = txout1.clone();
		let txout2_ = txout1.clone();

		let mut outputs = vec![(txout1, 420), (txout2, 69)];
		sort_outputs(&mut outputs, |a, b| { a.cmp(b) });

		assert_eq!(
			&outputs,
			&vec![(txout2_, 69), (txout1_, 420)]
		);
	}

	fn script_from_hex(hex_str: &str) -> Script {
		Script::from(decode(hex_str).unwrap())
	}

	macro_rules! bip_txout_tests {
		($($name:ident: $value:expr,)*) => {
			$(
				#[test]
				fn $name() {
					let expected_raw: Vec<(u64, &str)> = $value;
					let expected: Vec<(TxOut, &str)> = expected_raw.iter()
						.map(|txout_raw| TxOut {
							value: txout_raw.0,
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
		let mut tx = Transaction { version: 2, lock_time: PackedLockTime::ZERO, input: Vec::new(), output: vec![TxOut {
			script_pubkey: Script::new(), value: 1000
		}] };
		assert!(maybe_add_change_output(&mut tx, 21_000_000_0000_0001, 0, 253, Script::new()).is_err());
		assert!(maybe_add_change_output(&mut tx, 400, 0, 253, Script::new()).is_err());
		assert!(maybe_add_change_output(&mut tx, 4000, 0, 253, Script::new()).is_ok());
	}

	#[test]
	fn test_tx_change_edge() {
		// Check that we never add dust outputs
		let mut tx = Transaction { version: 2, lock_time: PackedLockTime::ZERO, input: Vec::new(), output: Vec::new() };
		let orig_wtxid = tx.wtxid();
		let output_spk = Script::new_p2pkh(&PubkeyHash::hash(&[0; 0]));
		assert_eq!(output_spk.dust_value().to_sat(), 546);
		// 9 sats isn't enough to pay fee on a dummy transaction...
		assert_eq!(tx.weight() as u64, 40); // ie 10 vbytes
		assert!(maybe_add_change_output(&mut tx, 9, 0, 250, output_spk.clone()).is_err());
		assert_eq!(tx.wtxid(), orig_wtxid); // Failure doesn't change the transaction
		// but 10-564 is, just not enough to add a change output...
		assert!(maybe_add_change_output(&mut tx, 10, 0, 250, output_spk.clone()).is_ok());
		assert_eq!(tx.output.len(), 0);
		assert_eq!(tx.wtxid(), orig_wtxid); // If we don't add an output, we don't change the transaction
		assert!(maybe_add_change_output(&mut tx, 549, 0, 250, output_spk.clone()).is_ok());
		assert_eq!(tx.output.len(), 0);
		assert_eq!(tx.wtxid(), orig_wtxid); // If we don't add an output, we don't change the transaction
		// 590 is also not enough, if we anticipate 2 more weight units pushing us up to the next vbyte
		// (considering the two bytes for segwit flags)
		assert!(maybe_add_change_output(&mut tx, 590, 2, 250, output_spk.clone()).is_ok());
		assert_eq!(tx.output.len(), 0);
		assert_eq!(tx.wtxid(), orig_wtxid); // If we don't add an output, we don't change the transaction
		// at 590 we can afford the change output at the dust limit (546)
		assert!(maybe_add_change_output(&mut tx, 590, 0, 250, output_spk.clone()).is_ok());
		assert_eq!(tx.output.len(), 1);
		assert_eq!(tx.output[0].value, 546);
		assert_eq!(tx.output[0].script_pubkey, output_spk);
		assert_eq!(tx.weight() / 4, 590-546); // New weight is exactly the fee we wanted.

		tx.output.pop();
		assert_eq!(tx.wtxid(), orig_wtxid); // The only change is the addition of one output.
	}

	#[test]
	fn test_tx_extra_outputs() {
		// Check that we correctly handle existing outputs
		let mut tx = Transaction { version: 2, lock_time: PackedLockTime::ZERO, input: vec![TxIn {
			previous_output: OutPoint::new(Txid::all_zeros(), 0), script_sig: Script::new(), witness: Witness::new(), sequence: Sequence::ZERO,
		}], output: vec![TxOut {
			script_pubkey: Builder::new().push_int(1).into_script(), value: 1000
		}] };
		let orig_wtxid = tx.wtxid();
		let orig_weight = tx.weight();
		assert_eq!(orig_weight / 4, 61);

		assert_eq!(Builder::new().push_int(2).into_script().dust_value().to_sat(), 474);

		// Input value of the output value + fee - 1 should fail:
		assert!(maybe_add_change_output(&mut tx, 1000 + 61 + 100 - 1, 400, 250, Builder::new().push_int(2).into_script()).is_err());
		assert_eq!(tx.wtxid(), orig_wtxid); // Failure doesn't change the transaction
		// but one more input sat should succeed, without changing the transaction
		assert!(maybe_add_change_output(&mut tx, 1000 + 61 + 100, 400, 250, Builder::new().push_int(2).into_script()).is_ok());
		assert_eq!(tx.wtxid(), orig_wtxid); // If we don't add an output, we don't change the transaction
		// In order to get a change output, we need to add 474 plus the output's weight / 4 (10)...
		assert!(maybe_add_change_output(&mut tx, 1000 + 61 + 100 + 474 + 9, 400, 250, Builder::new().push_int(2).into_script()).is_ok());
		assert_eq!(tx.wtxid(), orig_wtxid); // If we don't add an output, we don't change the transaction

		assert!(maybe_add_change_output(&mut tx, 1000 + 61 + 100 + 474 + 10, 400, 250, Builder::new().push_int(2).into_script()).is_ok());
		assert_eq!(tx.output.len(), 2);
		assert_eq!(tx.output[1].value, 474);
		assert_eq!(tx.output[1].script_pubkey, Builder::new().push_int(2).into_script());
		assert_eq!(tx.weight() - orig_weight, 40); // Weight difference matches what we had to add above
		tx.output.pop();
		assert_eq!(tx.wtxid(), orig_wtxid); // The only change is the addition of one output.
	}
}
