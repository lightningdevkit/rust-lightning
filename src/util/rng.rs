#[cfg(not(feature = "fuzztarget"))]
mod real_rng {
	use rand::{thread_rng,Rng};
	use bitcoin::util::uint::Uint256;

	pub fn fill_bytes(data: &mut [u8]) {
		let mut rng = thread_rng();
		rng.fill_bytes(data);
	}

	pub fn rand_uint256() -> Uint256 {
		let mut rng = thread_rng();
		Uint256([rng.gen(), rng.gen(), rng.gen(), rng.gen()])
	}

	pub fn rand_f32() -> f32 {
		let mut rng = thread_rng();
		rng.next_f32()
	}
}
#[cfg(not(feature = "fuzztarget"))]
pub use self::real_rng::*;

#[cfg(feature = "fuzztarget")]
mod fuzzy_rng {
	use bitcoin::util::uint::Uint256;

	pub fn fill_bytes(data: &mut [u8]) {
		for i in 0..data.len() {
			data[i] = 0x42;
		}
	}

	pub fn rand_uint256() -> Uint256 {
		Uint256([0xdeadbeef, 0x1badcafe, 0xbadbeef, 0xdeadcafe])
	}

	pub fn rand_f32() -> f32 {
		0.42
	}
}
#[cfg(feature = "fuzztarget")]
pub use self::fuzzy_rng::*;
