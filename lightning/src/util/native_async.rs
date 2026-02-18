// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! This module contains a few public utility which are used to run LDK in a native Rust async
//! environment.

#[cfg(all(test, feature = "std"))]
use crate::sync::{Arc, Mutex};

#[cfg(test)]
use alloc::boxed::Box;
#[cfg(all(test, not(feature = "std")))]
use alloc::rc::Rc;

#[cfg(all(test, not(feature = "std")))]
use core::cell::RefCell;
#[cfg(test)]
use core::convert::Infallible;
use core::future::Future;
#[cfg(test)]
use core::pin::Pin;
#[cfg(test)]
use core::task::{Context, Poll};

/// A generic trait which is able to spawn futures to be polled in the background.
///
/// When the spawned future completes, the returned [`Self::SpawnedFutureResult`] should resolve
/// with the output of the spawned future.
///
/// Spawned futures must be polled independently in the background even if the returned
/// [`Self::SpawnedFutureResult`] is dropped without being polled. This matches the semantics of
/// `tokio::spawn`.
///
/// This is not exported to bindings users as async is only supported in Rust.
pub trait FutureSpawner: MaybeSend + MaybeSync + 'static {
	/// The error type of [`Self::SpawnedFutureResult`]. This can be used to indicate that the
	/// spawned future was cancelled or panicked.
	type E;
	/// The result of [`Self::spawn`], a future which completes when the spawned future completes.
	type SpawnedFutureResult<O>: Future<Output = Result<O, Self::E>> + Unpin;
	/// Spawns the given future as a background task.
	///
	/// This method MUST NOT block on the given future immediately.
	fn spawn<O: MaybeSend + 'static, T: Future<Output = O> + MaybeSend + 'static>(
		&self, future: T,
	) -> Self::SpawnedFutureResult<O>;
}

#[cfg(test)]
trait MaybeSendableFuture: Future<Output = ()> + MaybeSend + 'static {}
#[cfg(test)]
impl<F: Future<Output = ()> + MaybeSend + 'static> MaybeSendableFuture for F {}

/// Marker trait to optionally implement `Sync` under std.
///
/// This is not exported to bindings users as async is only supported in Rust.
#[cfg(feature = "std")]
pub use core::marker::Sync as MaybeSync;

#[cfg(not(feature = "std"))]
/// Marker trait to optionally implement `Sync` under std.
///
/// This is not exported to bindings users as async is only supported in Rust.
pub trait MaybeSync {}
#[cfg(not(feature = "std"))]
impl<T> MaybeSync for T where T: ?Sized {}

/// Marker trait to optionally implement `Send` under std.
///
/// This is not exported to bindings users as async is only supported in Rust.
#[cfg(feature = "std")]
pub use core::marker::Send as MaybeSend;

#[cfg(not(feature = "std"))]
/// Marker trait to optionally implement `Send` under std.
///
/// This is not exported to bindings users as async is only supported in Rust.
pub trait MaybeSend {}
#[cfg(not(feature = "std"))]
impl<T> MaybeSend for T where T: ?Sized {}

/// A simple [`FutureSpawner`] which holds [`Future`]s until they are manually polled via
/// [`Self::poll_futures`].
#[cfg(all(test, feature = "std"))]
pub(crate) struct FutureQueue(Mutex<Vec<Pin<Box<dyn MaybeSendableFuture>>>>);
#[cfg(all(test, not(feature = "std")))]
pub(crate) struct FutureQueue(RefCell<Vec<Pin<Box<dyn MaybeSendableFuture>>>>);

/// A simple future which can be completed later. Used to implement [`FutureQueue`].
#[cfg(all(test, feature = "std"))]
pub struct FutureQueueCompletion<O>(Arc<Mutex<Option<O>>>);
#[cfg(all(test, not(feature = "std")))]
pub struct FutureQueueCompletion<O>(Rc<RefCell<Option<O>>>);

#[cfg(all(test, feature = "std"))]
impl<O> FutureQueueCompletion<O> {
	fn new() -> Self {
		Self(Arc::new(Mutex::new(None)))
	}

	fn complete(&self, o: O) {
		*self.0.lock().unwrap() = Some(o);
	}
}

#[cfg(all(test, feature = "std"))]
impl<O> Clone for FutureQueueCompletion<O> {
	fn clone(&self) -> Self {
		#[cfg(all(test, feature = "std"))]
		{
			Self(Arc::clone(&self.0))
		}
		#[cfg(all(test, not(feature = "std")))]
		{
			Self(Rc::clone(&self.0))
		}
	}
}

#[cfg(all(test, not(feature = "std")))]
impl<O> FutureQueueCompletion<O> {
	fn new() -> Self {
		Self(Rc::new(RefCell::new(None)))
	}

	fn complete(&self, o: O) {
		*self.0.borrow_mut() = Some(o);
	}
}

#[cfg(all(test, not(feature = "std")))]
impl<O> Clone for FutureQueueCompletion<O> {
	fn clone(&self) -> Self {
		Self(self.0.clone())
	}
}

#[cfg(all(test, feature = "std"))]
impl<O> Future for FutureQueueCompletion<O> {
	type Output = Result<O, Infallible>;
	fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<O, Infallible>> {
		match Pin::into_inner(self).0.lock().unwrap().take() {
			None => Poll::Pending,
			Some(o) => Poll::Ready(Ok(o)),
		}
	}
}

#[cfg(all(test, not(feature = "std")))]
impl<O> Future for FutureQueueCompletion<O> {
	type Output = Result<O, Infallible>;
	fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<O, Infallible>> {
		match Pin::into_inner(self).0.borrow_mut().take() {
			None => Poll::Pending,
			Some(o) => Poll::Ready(Ok(o)),
		}
	}
}

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
	type E = Infallible;
	type SpawnedFutureResult<O> = FutureQueueCompletion<O>;
	fn spawn<O: MaybeSend + 'static, F: Future<Output = O> + MaybeSend + 'static>(
		&self, f: F,
	) -> FutureQueueCompletion<O> {
		let completion = FutureQueueCompletion::new();
		let compl_ref = completion.clone();
		let future = async move {
			compl_ref.complete(f.await);
		};
		#[cfg(feature = "std")]
		{
			self.0.lock().unwrap().push(Box::pin(future));
		}
		#[cfg(not(feature = "std"))]
		{
			self.0.borrow_mut().push(Box::pin(future));
		}
		completion
	}
}

#[cfg(test)]
impl<D: core::ops::Deref<Target = FutureQueue> + MaybeSend + MaybeSync + 'static> FutureSpawner
	for D
{
	type E = Infallible;
	type SpawnedFutureResult<O> = FutureQueueCompletion<O>;
	fn spawn<O: MaybeSend + 'static, F: Future<Output = O> + MaybeSend + 'static>(
		&self, f: F,
	) -> FutureQueueCompletion<O> {
		let completion = FutureQueueCompletion::new();
		let compl_ref = completion.clone();
		let future = async move {
			compl_ref.complete(f.await);
		};
		#[cfg(feature = "std")]
		{
			self.0.lock().unwrap().push(Box::pin(future));
		}
		#[cfg(not(feature = "std"))]
		{
			self.0.borrow_mut().push(Box::pin(future));
		}
		completion
	}
}
