use bitcoin::blockdata::transaction::TxOut;

use std::cmp::Ordering;

pub fn sort_outputs<T>(outputs: &mut Vec<(TxOut, T)>) { //TODO: Make static and put it in some utils somewhere (+inputs sorting)
	outputs.sort_unstable_by(|a, b| {
		if a.0.value < b.0.value {
			Ordering::Less
		} else if b.0.value < a.0.value {
			Ordering::Greater
		} else if a.0.script_pubkey[..] < b.0.script_pubkey[..] { //TODO: ordering of scripts shouldn't be len-based
			Ordering::Less
		} else if b.0.script_pubkey[..] < a.0.script_pubkey[..] { //TODO: ordering of scripts shouldn't be len-based
			Ordering::Greater
		} else {
			Ordering::Equal
		}
	});
}
