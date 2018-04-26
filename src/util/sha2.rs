#[cfg(not(feature = "fuzztarget"))]
pub use crypto::sha2::Sha256;

#[cfg(feature = "fuzztarget")]
mod fuzzy_sha {
	use crypto::digest::Digest;

	pub struct Sha256 {
		state: u8,
	}

	impl Sha256 {
		pub fn new() -> Sha256 {
			Sha256 {
				state: 0,
			}
		}
	}

	impl Digest for Sha256 {
		fn result(&mut self, data: &mut [u8]) {
			data[0] = self.state;
			for i in 1..32 {
				data[i] = 0;
			}
		}

		fn input(&mut self, data: &[u8]) { for i in data { self.state ^= i; } }
		fn reset(&mut self) { self.state = 0; }
		fn output_bits(&self) -> usize { 256 }
		fn block_size(&self) -> usize { 64 }
	}
}
#[cfg(feature = "fuzztarget")]
pub use self::fuzzy_sha::Sha256;
