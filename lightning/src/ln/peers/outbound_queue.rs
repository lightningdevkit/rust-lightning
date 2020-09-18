// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

/// Abstracts the buffer used to write data through a SocketDescriptor handling partial writes and
/// flow control.

use ln::peers::handler::{IOutboundQueue, SocketDescriptor};
use std::collections::LinkedList;
use std::cmp;

pub(super) struct OutboundQueue {
	blocked: bool,
	soft_limit: usize,
	buffer: LinkedList<Vec<u8>>,
	buffer_first_msg_offset: usize,
}

impl OutboundQueue {
	pub(super) fn new(soft_limit: usize) -> Self {
		Self {
			blocked: false,
			soft_limit,
			buffer: LinkedList::new(),
			buffer_first_msg_offset: 0,
		}
	}
}

impl IOutboundQueue for OutboundQueue {

	fn push_back(&mut self, item: Vec<u8>) {
		self.buffer.push_back(item);
	}

	fn is_empty(&self) -> bool {
		self.buffer.is_empty()
	}

	fn queue_space(&self) -> usize {
		self.soft_limit - cmp::min(self.soft_limit, self.buffer.len())
	}

	fn try_flush(&mut self, descriptor: &mut impl SocketDescriptor) -> bool {
		// Exit early if  a previous full write failed and haven't heard that there may be more
		// room available
		if self.blocked {
			return false;
		}

		loop {
			if self.buffer.is_empty() {
				return true;
			}

			let full_write_succeeded = match self.buffer.front() {
				None => true,
				Some(next_buff) => {
					let should_be_reading = self.buffer.len() < self.soft_limit;
					let pending = &next_buff[self.buffer_first_msg_offset..];
					let data_sent = descriptor.send_data(pending, should_be_reading);
					self.buffer_first_msg_offset += data_sent;
					self.buffer_first_msg_offset == next_buff.len()
				}
			};

			if full_write_succeeded {
				self.buffer_first_msg_offset = 0;
				self.buffer.pop_front();
			} else {
				self.blocked = true;
				return false;
			}
		}
	}

	fn unblock(&mut self) {
		self.blocked = false;
	}

	fn is_blocked(&self) -> bool {
		self.blocked
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use ln::peers::test_util::*;

	// Test that a try_flush() call with no queued data doesn't write anything
	#[test]
	fn empty_does_not_write() {
		let mut descriptor = SocketDescriptorMock::new();
		let mut empty = OutboundQueue::new(10);

		assert!(empty.try_flush(&mut descriptor));
		descriptor.assert_called_with(vec![]);

	}

	// Test that try_flush() sends the push_back
	#[test]
	fn push_back_drain() {
		let mut descriptor = SocketDescriptorMock::new();
		let mut queue = OutboundQueue::new(10);

		queue.push_back(vec![1]);
		assert!(queue.try_flush(&mut descriptor));

		descriptor.assert_called_with(vec![(vec![1], true)]);
	}

	// Test that try_flush() sends all
	#[test]
	fn push_back_push_back_drain_drain() {
		let mut descriptor = SocketDescriptorMock::new();
		let mut queue = OutboundQueue::new(10);

		queue.push_back(vec![1]);
		queue.push_back(vec![2]);
		assert!(queue.try_flush(&mut descriptor));

		descriptor.assert_called_with(vec![(vec![1], true), (vec![2], true)]);
	}

	// Test that descriptor that can't write all bytes returns valid response
	#[test]
	fn push_back_drain_partial() {
		let mut descriptor = SocketDescriptorMock::with_fixed_size(1);
		let mut queue = OutboundQueue::new(10);

		queue.push_back(vec![1, 2, 3]);
		assert!(!queue.try_flush(&mut descriptor));

		descriptor.assert_called_with(vec![(vec![1, 2, 3], true)]);
	}

	// Test that descriptor that can't write all bytes (in second pushed item) returns valid response
	#[test]
	fn push_back_drain_partial_multiple_push() {
		let mut descriptor = SocketDescriptorMock::with_fixed_size(2);
		let mut queue = OutboundQueue::new(10);

		queue.push_back(vec![1]);
		queue.push_back(vec![2, 3]);
		assert!(!queue.try_flush(&mut descriptor));

		descriptor.assert_called_with(vec![(vec![1], true), (vec![2, 3], true)]);
	}

	// Test the bookkeeping for multiple partial writes
	#[test]
	fn push_back_drain_partial_drain_partial_try_flush() {
		let mut descriptor = SocketDescriptorMock::with_fixed_size(1);
		let mut queue = OutboundQueue::new(10);

		queue.push_back(vec![1, 2, 3]);
		assert!(!queue.try_flush(&mut descriptor));

		descriptor.make_room(1);
		queue.unblock();
		assert!(!queue.try_flush(&mut descriptor));

		descriptor.make_room(1);
		queue.unblock();
		assert!(queue.try_flush(&mut descriptor));

		descriptor.assert_called_with(vec![(vec![1, 2, 3], true), (vec![2, 3], true), (vec![3], true)]);
	}

	#[test]
	fn push_back_drain_blocks() {
		let mut descriptor = SocketDescriptorMock::with_fixed_size(0);
		let mut queue = OutboundQueue::new(10);

		// Fail write and move to blocked state
		queue.push_back(vec![1, 2]);
		assert!(!queue.try_flush(&mut descriptor));
		descriptor.assert_called_with(vec![(vec![1, 2], true)]);

		// Make room but don't signal
		descriptor.make_room(1);
		assert!(!queue.try_flush(&mut descriptor));
		assert!(queue.is_blocked());
		descriptor.assert_called_with(vec![(vec![1, 2], true)]);

		// Unblock and try again
		queue.unblock();

		// Partial write will succeed, but still move to blocked
		assert!(!queue.try_flush(&mut descriptor));
		assert!(queue.is_blocked());
		descriptor.assert_called_with(vec![(vec![1, 2], true), (vec![1, 2], true)]);

		// Make room and signal which will succeed in writing the final piece
		descriptor.make_room(1);
		queue.unblock();
		assert!(queue.try_flush(&mut descriptor));
		assert!(!queue.is_blocked());
		descriptor.assert_called_with(vec![(vec![1, 2], true), (vec![1, 2], true), (vec![2], true)]);
	}

	// Test resume_reading argument to send_data when queue is above soft limit
	#[test]
	fn push_back_above_limit_resume_reading_false() {
		let mut descriptor = SocketDescriptorMock::with_fixed_size(10);
		let mut queue = OutboundQueue::new(1);

		queue.push_back(vec![1]);
		assert!(queue.try_flush(&mut descriptor));
		descriptor.assert_called_with(vec![(vec![1], false)]);
	}

	// Test that push_back works above soft limit, but send_read() is informed of the correct state
	#[test]
	fn push_back_above_limit_is_ok() {
		let mut descriptor = SocketDescriptorMock::with_fixed_size(10);
		let mut queue = OutboundQueue::new(2);

		queue.push_back(vec![1]);
		queue.push_back(vec![2]);
		queue.push_back(vec![3]);
		assert!(queue.try_flush(&mut descriptor));
		descriptor.assert_called_with(vec![(vec![1], false), (vec![2], false), (vec![3], true)]);
	}

	// Test is_empty()
	#[test]
	fn is_empty() {
		let mut descriptor = SocketDescriptorMock::with_fixed_size(10);
		let mut queue = OutboundQueue::new(1);
		assert!(queue.is_empty());

		queue.push_back(vec![1]);
		assert!(!queue.is_empty());

		assert!(queue.try_flush(&mut descriptor));
		assert!(queue.is_empty());
	}

	// Test queue_space()
	#[test]
	fn queue_space() {
		let mut descriptor = SocketDescriptorMock::with_fixed_size(10);
		let mut queue = OutboundQueue::new(1);

		// below soft limit
		assert_eq!(queue.queue_space(), 1);

		// at soft limit
		queue.push_back(vec![1]);
		assert_eq!(queue.queue_space(), 0);

		// above soft limit
		queue.push_back(vec![2]);
		assert_eq!(queue.queue_space(), 0);

		// below soft limt
		assert!(queue.try_flush(&mut descriptor));
		assert_eq!(queue.queue_space(), 1);
	}
}