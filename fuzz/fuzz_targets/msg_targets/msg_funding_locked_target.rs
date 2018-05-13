extern crate lightning;

use lightning::ln::msgs;
use lightning::util::reset_rng_state;

use lightning::ln::msgs::{MsgEncodable, MsgDecodable};

mod utils;
use utils::slice_to_be16;

#[inline]
pub fn do_test(data: &[u8]) {
	reset_rng_state();
	let mut read_pos = 0;
	loop {
		test_msg!(msgs::FundingLocked, data, read_pos);
	}
}

#[cfg(feature = "afl")]
extern crate afl;
#[cfg(feature = "afl")]
fn main() {
	afl::read_stdio_bytes(|data| {
		do_test(&data);
	});
}

#[cfg(feature = "honggfuzz")]
#[macro_use] extern crate honggfuzz;
#[cfg(feature = "honggfuzz")]
fn main() {
	loop {
		fuzz!(|data| {
			do_test(data);
		});
	}
}

#[cfg(test)]
mod tests {
	use utils::extend_vec_from_hex;
	#[test]
	fn duplicate_crash() {
		let mut a = Vec::new();
		extend_vec_from_hex("00", &mut a);
		super::do_test(&a);
	}
}
