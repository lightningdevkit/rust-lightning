use bitcoin::blockdata::transaction::TxOut;

use std::cmp::Ordering;

pub fn sort_outputs<T, C : Fn(&T, &T) -> Ordering>(outputs: &mut Vec<(TxOut, T)>, tie_breaker: C) {
	outputs.sort_unstable_by(|a, b| {
		a.0.value.cmp(&b.0.value).then_with(|| {
			a.0.script_pubkey[..].cmp(&b.0.script_pubkey[..]).then_with(|| {
				tie_breaker(&a.1, &b.1)
			})
		})
	});
}

#[cfg(test)]
mod tests {
	use super::*;

	use bitcoin::blockdata::script::{Script, Builder};
	use bitcoin::blockdata::transaction::TxOut;

	use hex::decode;

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
}
