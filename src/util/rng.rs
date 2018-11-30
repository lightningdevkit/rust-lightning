#[cfg(not(feature = "fuzztarget"))]
mod real_rng {
	use rand::{thread_rng,Rng};

	pub fn fill_bytes(data: &mut [u8]) {
		let mut rng = thread_rng();
		rng.fill_bytes(data);
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
	use util::byte_utils;

	static mut RNG_ITER: u64 = 0;

	pub fn fill_bytes(data: &mut [u8]) {
		let rng = unsafe { RNG_ITER += 1; RNG_ITER -1 };
		for i in 0..data.len() / 8 {
			data[i*8..(i+1)*8].copy_from_slice(&byte_utils::be64_to_array(rng));
		}
		let rem = data.len() % 8;
		let off = data.len() - rem;
		data[off..].copy_from_slice(&byte_utils::be64_to_array(rng)[0..rem]);
	}

	pub fn rand_f32() -> f32 {
		let rng = unsafe { RNG_ITER += 1; RNG_ITER - 1 };
		f64::from_bits(rng) as f32
	}

	pub fn reset_rng_state() {
		unsafe { RNG_ITER = 0; }
	}
}
#[cfg(feature = "fuzztarget")]
pub use self::fuzzy_rng::*;
