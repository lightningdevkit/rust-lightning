use bitcoin::blockdata::transaction::{TxIn, TxOut};

use std::cmp::Ordering;

pub fn sort_outputs<T>(outputs: &mut Vec<(TxOut, T)>) {
	outputs.sort_unstable_by(|a, b| {
		if a.0.value < b.0.value {
			Ordering::Less
		} else if b.0.value < a.0.value {
			Ordering::Greater
		} else if a.0.script_pubkey[..] < b.0.script_pubkey[..] {
			Ordering::Less
		} else if b.0.script_pubkey[..] < a.0.script_pubkey[..] {
			Ordering::Greater
		} else {
			Ordering::Equal
		}
	});
}

// TODO savil. Add tests.
pub fn sort_inputs<T>(inputs: &mut Vec<(TxIn, T)>) {
    inputs.sort_unstable_by(|a, b| {
        if a.0.prev_hash.into_le() < b.0.prev_hash.into_le() {
            Ordering::Less
        } else if b.0.prev_hash.into_le() < a.0.prev_hash.into_le() {
            Ordering::Greater
        } else if a.0.prev_index < b.0.prev_index {
            Ordering::Less
        } else if b.0.prev_index < a.0.prev_index {
            Ordering::Greater
        } else {
            Ordering::Equal
        }
    });
}


#[cfg(test)]
mod tests {
    use super::*;

    use bitcoin::blockdata::opcodes;
    use bitcoin::blockdata::script::Builder;
    use bitcoin::blockdata::transaction::TxOut;

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
        sort_outputs(&mut outputs);

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
        sort_outputs(&mut outputs);

        assert_eq!(
            &outputs,
            &vec![(txout2_, "ignore"), (txout1_, "ignore")]
        );
    }
}
