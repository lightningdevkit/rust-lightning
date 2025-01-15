// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

/// Trait for rounding the size of memory allocations in order to reduce heap fragmentation.
pub(super) trait WithRoundedCapacity {
	fn with_rounded_capacity(capacity: usize) -> Self;
}

const MIN_ALLOCATION: usize = 512;
const MAX_ALLOCATION: usize = 1 << 16;

impl WithRoundedCapacity for Vec<u8> {
	fn with_rounded_capacity(capacity: usize) -> Self {
		let capacity = if capacity == 0 {
			0
		} else if capacity <= MIN_ALLOCATION {
			MIN_ALLOCATION
		} else if capacity >= MAX_ALLOCATION {
			MAX_ALLOCATION
		} else {
			capacity.next_power_of_two()
		};

		Vec::with_capacity(capacity)
	}
}

#[cfg(test)]
mod tests {
	use super::{WithRoundedCapacity, MAX_ALLOCATION, MIN_ALLOCATION};

	#[test]
	fn rounds_capacity_to_power_of_two() {
		assert_eq!(Vec::with_rounded_capacity(0).capacity(), 0);
		assert_eq!(Vec::with_rounded_capacity(1).capacity(), MIN_ALLOCATION);
		assert_eq!(Vec::with_rounded_capacity(512).capacity(), MIN_ALLOCATION);
		assert_eq!(Vec::with_rounded_capacity(4095).capacity(), 4096);
		assert_eq!(Vec::with_rounded_capacity(4096).capacity(), 4096);
		assert_eq!(Vec::with_rounded_capacity(4097).capacity(), 8192);
		assert_eq!(Vec::with_rounded_capacity(65537).capacity(), MAX_ALLOCATION);
		assert_eq!(Vec::with_rounded_capacity(usize::MAX).capacity(), MAX_ALLOCATION);
	}
}
