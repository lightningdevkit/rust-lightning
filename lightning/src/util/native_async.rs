// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! This module contains a few public utility which are used to run LDK in a native Rust async
//! environment.

#[cfg(all(test, feature = "std"))]
use crate::sync::Mutex;
use crate::util::async_poll::{MaybeSend, MaybeSync};

#[cfg(all(test, not(feature = "std")))]
use core::cell::RefCell;
use core::future::Future;
#[cfg(test)]
use core::pin::Pin;

/// A generic trait which is able to spawn futures in the background.
pub trait FutureSpawner: MaybeSend + MaybeSync + 'static {
	/// Spawns the given future as a background task.
	///
	/// This method MUST NOT block on the given future immediately.
	fn spawn<T: Future<Output = ()> + MaybeSend + 'static>(&self, future: T);
}

#[cfg(test)]
trait MaybeSendableFuture: Future<Output = ()> + MaybeSend + 'static {}
#[cfg(test)]
impl<F: Future<Output = ()> + MaybeSend + 'static> MaybeSendableFuture for F {}

/// A simple [`FutureSpawner`] which holds [`Future`]s until they are manually polled via
/// [`Self::poll_futures`].
#[cfg(all(test, feature = "std"))]
pub(crate) struct FutureQueue(Mutex<Vec<Pin<Box<dyn MaybeSendableFuture>>>>);
#[cfg(all(test, not(feature = "std")))]
pub(crate) struct FutureQueue(RefCell<Vec<Pin<Box<dyn MaybeSendableFuture>>>>);

#[cfg(test)]
impl FutureQueue {
	pub(crate) fn new() -> Self {
		#[cfg(feature = "std")]
		{
			FutureQueue(Mutex::new(Vec::new()))
		}
		#[cfg(not(feature = "std"))]
		{
			FutureQueue(RefCell::new(Vec::new()))
		}
	}

	pub(crate) fn pending_futures(&self) -> usize {
		#[cfg(feature = "std")]
		{
			self.0.lock().unwrap().len()
		}
		#[cfg(not(feature = "std"))]
		{
			self.0.borrow().len()
		}
	}

	pub(crate) fn poll_futures(&self) {
		let mut futures;
		#[cfg(feature = "std")]
		{
			futures = self.0.lock().unwrap();
		}
		#[cfg(not(feature = "std"))]
		{
			futures = self.0.borrow_mut();
		}
		futures.retain_mut(|fut| {
			use core::task::{Context, Poll};
			let waker = crate::util::async_poll::dummy_waker();
			match fut.as_mut().poll(&mut Context::from_waker(&waker)) {
				Poll::Ready(()) => false,
				Poll::Pending => true,
			}
		});
	}
}

#[cfg(test)]
impl FutureSpawner for FutureQueue {
	fn spawn<T: Future<Output = ()> + MaybeSend + 'static>(&self, future: T) {
		#[cfg(feature = "std")]
		{
			self.0.lock().unwrap().push(Box::pin(future));
		}
		#[cfg(not(feature = "std"))]
		{
			self.0.borrow_mut().push(Box::pin(future));
		}
	}
}

#[cfg(test)]
impl<D: core::ops::Deref<Target = FutureQueue> + MaybeSend + MaybeSync + 'static> FutureSpawner
	for D
{
	fn spawn<T: Future<Output = ()> + MaybeSend + 'static>(&self, future: T) {
		#[cfg(feature = "std")]
		{
			self.0.lock().unwrap().push(Box::pin(future));
		}
		#[cfg(not(feature = "std"))]
		{
			self.0.borrow_mut().push(Box::pin(future));
		}
	}
}
