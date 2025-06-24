// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

use core::time::Duration;

pub(crate) struct BatchDelay {
	next_batch_delay_millis: u16,
}

impl BatchDelay {
	pub(crate) fn new() -> Self {
		let next_batch_delay_millis = rand_batch_delay_millis();
		Self { next_batch_delay_millis }
	}

	pub(crate) fn get(&self) -> Duration {
		Duration::from_millis(self.next_batch_delay_millis as u64)
	}

	pub(crate) fn next(&mut self) -> Duration {
		let next = rand_batch_delay_millis();
		self.next_batch_delay_millis = next;
		Duration::from_millis(next as u64)
	}
}

fn rand_batch_delay_millis() -> u16 {
	// TODO: actually randomize the result.
	100
}
