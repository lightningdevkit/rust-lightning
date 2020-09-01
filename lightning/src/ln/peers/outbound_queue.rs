/// Abstracts the buffer used to write data through a SocketDescriptor handling partial writes and
/// flow control.

use ln::peers::handler::{SocketDescriptor, PayloadQueuer, SocketDescriptorFlusher};
use std::collections::LinkedList;
use std::cmp;

pub(super) struct OutboundQueue {
	blocked: bool,
	soft_limit: usize,
	buffer: LinkedList<Vec<u8>>,
	buffer_first_msg_offset: usize,
}

impl PayloadQueuer for OutboundQueue {
	/// Unconditionally queue item. May increase queue above soft limit.
	fn push_back(&mut self, item: Vec<u8>) {
		self.buffer.push_back(item);
	}

	/// Returns true if the queue is empty
	fn is_empty(&self) -> bool {
		self.buffer.is_empty()
	}

	/// Returns the amount of free space in the queue before the soft limit
	fn queue_space(&self) -> usize {
		self.soft_limit - cmp::min(self.soft_limit, self.buffer.len())
	}
}
impl SocketDescriptorFlusher for OutboundQueue {
	fn try_flush_one(&mut self, descriptor: &mut impl SocketDescriptor) -> bool {
		// Exit early if  a previous full write failed and haven't heard that there may be more
		// room available
		if self.blocked {
			return false;
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
		}

		full_write_succeeded
	}

	fn unblock(&mut self) {
		self.blocked = false;
	}

	fn is_blocked(&self) -> bool {
		self.blocked
	}
}

impl OutboundQueue {

	/// Create a new writer with a soft limit that is used to notify the SocketDescriptor when
	/// it is OK to resume reading if it was paused
	pub(super) fn new(soft_limit: usize) -> Self {
		Self {
			blocked: false,
			soft_limit,
			buffer: LinkedList::new(),
			buffer_first_msg_offset: 0,
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::rc::Rc;
	use std::cell::RefCell;
	use std::hash::Hash;
	use std::cmp;

	/// Mock implementation of the SocketDescriptor trait that can be used in tests to finely control
	/// the send_data() behavior.
	///
	///Additionally, records the actual calls to send_data() for later validation.
	#[derive(Debug, Eq)]
	struct SocketDescriptorMock {
		/// If true, all send_data() calls will succeed
		unbounded: Rc<RefCell<bool>>,

		/// Amount of free space in the descriptor for send_data() bytes
		free_space: Rc<RefCell<usize>>,

		/// Vector of arguments and return values to send_data() used for validation
		send_recording: Rc<RefCell<Vec<(Vec<u8>, bool)>>>,
	}

	impl SocketDescriptorMock {
		/// Basic unbounded implementation where send_data() will always succeed
		fn new() -> Self {
			Self {
				unbounded: Rc::new(RefCell::new(true)),
				send_recording: Rc::new(RefCell::new(Vec::new())),
				free_space: Rc::new(RefCell::new(0))
			}
		}

		/// Used for tests that want to return partial sends after a certain amount of data is sent through send_data()
		fn with_fixed_size(limit: usize) -> Self {
			let mut descriptor = Self::new();
			descriptor.unbounded = Rc::new(RefCell::new(false));
			descriptor.free_space = Rc::new(RefCell::new(limit));

			descriptor
		}

		/// Standard Mock api to verify actual vs. expected calls
		fn assert_called_with(&self, expectation: Vec<(Vec<u8>, bool)>) {
			assert_eq!(expectation.as_slice(), self.send_recording.borrow().as_slice())
		}

		/// Allow future send_data() calls to succeed for the next added_room bytes. Not valid for
		/// unbounded mock descriptors
		fn make_room(&mut self, added_room: usize) {
			assert!(!*self.unbounded.borrow());
			let mut free_space = self.free_space.borrow_mut();

			*free_space += added_room;
		}
	}

	impl SocketDescriptor for SocketDescriptorMock {
		fn send_data(&mut self, data: &[u8], resume_read: bool) -> usize {
			self.send_recording.borrow_mut().push((data.to_vec(), resume_read));

			let mut free_space = self.free_space.borrow_mut();

			// Unbounded just flush everything
			return if *self.unbounded.borrow() {
				data.len()
			}
			// Bounded flush up to the free_space limit
			else {
				let write_len = cmp::min(data.len(), *free_space);
				*free_space -= write_len;
				write_len
			}
		}

		fn disconnect_socket(&mut self) {
			unimplemented!()
		}
	}

	impl Clone for SocketDescriptorMock {
		fn clone(&self) -> Self {
			Self {
				unbounded: self.unbounded.clone(),
				send_recording: self.send_recording.clone(),
				free_space: self.free_space.clone()
			}
		}
	}

	impl PartialEq for SocketDescriptorMock {
		fn eq(&self, o: &Self) -> bool {
			Rc::ptr_eq(&self.send_recording, &o.send_recording)
		}
	}
	impl Hash for SocketDescriptorMock {
		fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
			self.send_recording.as_ptr().hash(state)
		}
	}

	// Test that a try_flush_one() call with no queued data doesn't write anything
	#[test]
	fn empty_does_not_write() {
		let mut descriptor = SocketDescriptorMock::new();
		let mut empty = OutboundQueue::new(10);

		assert!(empty.try_flush_one(&mut descriptor));
		descriptor.assert_called_with(vec![]);

	}

	// Test that try_flush_one() sends the push_back
	#[test]
	fn push_back_drain() {
		let mut descriptor = SocketDescriptorMock::new();
		let mut queue = OutboundQueue::new(10);

		queue.push_back(vec![1]);
		assert!(queue.try_flush_one(&mut descriptor));

		descriptor.assert_called_with(vec![(vec![1], true)]);
	}

	// Test that try_flush_one() sends just first push_back
	#[test]
	fn push_back_push_back_drain_drain() {
		let mut descriptor = SocketDescriptorMock::new();
		let mut queue = OutboundQueue::new(10);

		queue.push_back(vec![1]);
		queue.push_back(vec![2]);
		assert!(queue.try_flush_one(&mut descriptor));

		descriptor.assert_called_with(vec![(vec![1], true)]);
	}

	// Test that descriptor that can't write all bytes returns valid response
	#[test]
	fn push_back_drain_partial() {
		let mut descriptor = SocketDescriptorMock::with_fixed_size(1);
		let mut queue = OutboundQueue::new(10);

		queue.push_back(vec![1, 2, 3]);
		assert!(!queue.try_flush_one(&mut descriptor));

		descriptor.assert_called_with(vec![(vec![1, 2, 3], true)]);
	}

	// Test the bookkeeping for multiple partial writes
	#[test]
	fn push_back_drain_partial_drain_partial_try_flush_one() {
		let mut descriptor = SocketDescriptorMock::with_fixed_size(1);
		let mut queue = OutboundQueue::new(10);

		queue.push_back(vec![1, 2, 3]);
		assert!(!queue.try_flush_one(&mut descriptor));

		descriptor.make_room(1);
		queue.unblock();
		assert!(!queue.try_flush_one(&mut descriptor));

		descriptor.make_room(1);
		queue.unblock();
		assert!(queue.try_flush_one(&mut descriptor));

		descriptor.assert_called_with(vec![(vec![1, 2, 3], true), (vec![2, 3], true), (vec![3], true)]);
	}

	#[test]
	fn push_back_drain_blocks() {
		let mut descriptor = SocketDescriptorMock::with_fixed_size(0);
		let mut queue = OutboundQueue::new(10);

		// Fail write and move to blocked state
		queue.push_back(vec![1, 2]);
		assert!(!queue.try_flush_one(&mut descriptor));
		descriptor.assert_called_with(vec![(vec![1, 2], true)]);

		// Make room but don't signal
		descriptor.make_room(1);
		assert!(!queue.try_flush_one(&mut descriptor));
		assert!(queue.is_blocked());
		descriptor.assert_called_with(vec![(vec![1, 2], true)]);

		// Unblock and try again
		queue.unblock();

		// Partial write will succeed, but still move to blocked
		assert!(!queue.try_flush_one(&mut descriptor));
		assert!(queue.is_blocked());
		descriptor.assert_called_with(vec![(vec![1, 2], true), (vec![1, 2], true)]);

		// Make room and signal which will succeed in writing the final piece
		descriptor.make_room(1);
		queue.unblock();
		assert!(queue.try_flush_one(&mut descriptor));
		assert!(!queue.is_blocked());
		descriptor.assert_called_with(vec![(vec![1, 2], true), (vec![1, 2], true), (vec![2], true)]);
	}

	// Test resume_reading argument to send_data when queue is above soft limit
	#[test]
	fn push_back_above_limit_resume_reading_false() {
		let mut descriptor = SocketDescriptorMock::with_fixed_size(10);
		let mut queue = OutboundQueue::new(1);

		queue.push_back(vec![1]);
		assert!(queue.try_flush_one(&mut descriptor));
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
		assert!(queue.try_flush_one(&mut descriptor));
		assert!(queue.try_flush_one(&mut descriptor));
		assert!(queue.try_flush_one(&mut descriptor));
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

		assert!(queue.try_flush_one(&mut descriptor));
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

		// at soft limit
		assert!(queue.try_flush_one(&mut descriptor));
		assert_eq!(queue.queue_space(), 0);

		// below soft limt
		assert!(queue.try_flush_one(&mut descriptor));
		assert_eq!(queue.queue_space(), 1);
	}
}