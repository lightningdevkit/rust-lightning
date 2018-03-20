#[cfg(not(feature = "fuzztarget"))]
pub use crypto::sha2::Sha256;

#[cfg(feature = "fuzztarget")]
mod fuzzy_sha {
	use crypto::digest::Digest;
	use crypto::sha2;

	#[derive(Clone, Copy)]
	pub struct Sha256 {
		state: sha2::Sha256,
	}

	impl Sha256 {
		pub fn new() -> Sha256 {
			Sha256 {
				state: sha2::Sha256::new(),
			}
		}
	}

	impl Digest for Sha256 {
		fn result(&mut self, data: &mut [u8]) {
			self.state.result(data);
			for i in 1..32 {
				data[i] = 0;
			}
		}

		fn input(&mut self, data: &[u8]) { self.state.input(data); }
		fn reset(&mut self) { self.state.reset(); }
		fn output_bits(&self) -> usize { self.state.output_bits() }
		fn block_size(&self) -> usize { self.state.block_size() }
	}
}
#[cfg(feature = "fuzztarget")]
pub use self::fuzzy_sha::Sha256;
