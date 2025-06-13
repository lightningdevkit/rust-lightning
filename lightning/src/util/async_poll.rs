// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Some utilities to make working with the standard library's [`Future`]s easier

use crate::prelude::*;
use core::future::Future;
use core::marker::Unpin;
use core::pin::Pin;
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

pub(crate) enum ResultFuture<F: Future<Output = Result<(), E>>, E: Copy + Unpin> {
	Pending(F),
	Ready(Result<(), E>),
}

pub(crate) struct MultiResultFuturePoller<
	F: Future<Output = Result<(), E>> + Unpin,
	E: Copy + Unpin,
> {
	futures_state: Vec<ResultFuture<F, E>>,
}

impl<F: Future<Output = Result<(), E>> + Unpin, E: Copy + Unpin> MultiResultFuturePoller<F, E> {
	pub fn new(futures_state: Vec<ResultFuture<F, E>>) -> Self {
		Self { futures_state }
	}
}

impl<F: Future<Output = Result<(), E>> + Unpin, E: Copy + Unpin> Future
	for MultiResultFuturePoller<F, E>
{
	type Output = Vec<Result<(), E>>;
	fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Vec<Result<(), E>>> {
		let mut have_pending_futures = false;
		let futures_state = &mut self.get_mut().futures_state;
		for state in futures_state.iter_mut() {
			match state {
				ResultFuture::Pending(ref mut fut) => match Pin::new(fut).poll(cx) {
					Poll::Ready(res) => {
						*state = ResultFuture::Ready(res);
					},
					Poll::Pending => {
						have_pending_futures = true;
					},
				},
				ResultFuture::Ready(_) => continue,
			}
		}

		if have_pending_futures {
			Poll::Pending
		} else {
			let results = futures_state
				.drain(..)
				.filter_map(|e| match e {
					ResultFuture::Ready(res) => Some(res),
					ResultFuture::Pending(_) => {
						debug_assert!(
							false,
							"All futures are expected to be ready if none are pending"
						);
						None
					},
				})
				.collect();
			Poll::Ready(results)
		}
	}
}

// If we want to poll a future without an async context to figure out if it has completed or
// not without awaiting, we need a Waker, which needs a vtable...we fill it with dummy values
// but sadly there's a good bit of boilerplate here.
//
// Waker::noop() would be preferable, but requires an MSRV of 1.85.
fn dummy_waker_clone(_: *const ()) -> RawWaker {
	RawWaker::new(core::ptr::null(), &DUMMY_WAKER_VTABLE)
}
fn dummy_waker_action(_: *const ()) {}

const DUMMY_WAKER_VTABLE: RawWakerVTable = RawWakerVTable::new(
	dummy_waker_clone,
	dummy_waker_action,
	dummy_waker_action,
	dummy_waker_action,
);

pub(crate) fn dummy_waker() -> Waker {
	unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &DUMMY_WAKER_VTABLE)) }
}

/// A type alias for a future that returns nothing.
pub type AsyncVoid = Pin<Box<dyn Future<Output = ()> + 'static + Send>>;

/// A type alias for a future that returns a result of type T.
#[cfg(feature = "std")]
pub type AsyncResult<'a, T> = Pin<Box<dyn Future<Output = Result<T, ()>> + 'a + Send>>;
#[cfg(not(feature = "std"))]
pub type AsyncResult<'a, T> = Pin<Box<dyn Future<Output = Result<T, ()>> + 'a>>;

// Marker trait to optionally implement `Sync` under std.
#[cfg(feature = "std")]
pub use core::marker::Sync as MaybeSync;

#[cfg(not(feature = "std"))]
pub trait MaybeSync {}
#[cfg(not(feature = "std"))]
impl<T> MaybeSync for T where T: ?Sized {}

// Marker trait to optionally implement `Send` under std.
#[cfg(feature = "std")]
pub use core::marker::Send as MaybeSend;
#[cfg(not(feature = "std"))]
pub trait MaybeSend {}
#[cfg(not(feature = "std"))]
impl<T> MaybeSend for T where T: ?Sized {}

/// A type alias for a future that returns a result of type T with error type V.
pub type AsyncResultType<'a, T, V> = Pin<Box<dyn Future<Output = Result<T, V>> + 'a + Send>>;

/// A type alias for a future that returns a result of type T.
pub trait FutureSpawner: Send + Sync + 'static {
	/// Spawns a future on a runtime.
	fn spawn<T: Future<Output = ()> + Send + 'static>(&self, future: T);
}

/// Polls a future and either returns true if it is ready or spawns it on the tokio runtime if it is not.
pub fn poll_or_spawn<F, C, S>(
	mut fut: Pin<Box<F>>, callback: C, future_spawner: &S,
) -> Result<bool, ()>
where
	F: Future<Output = Result<(), ()>> + Send + 'static + ?Sized,
	C: FnOnce() + Send + 'static,
	S: FutureSpawner,
{
	let waker = dummy_waker();
	let mut cx = Context::from_waker(&waker);

	match fut.as_mut().poll(&mut cx) {
		Poll::Ready(Ok(())) => Ok(true),
		Poll::Ready(Err(_)) => Err(()),
		Poll::Pending => {
			println!("Future not ready, using tokio runtime");

			let callback = Box::new(callback);
			future_spawner.spawn(async move {
				fut.await;
				callback();
			});

			Ok(false)
		},
	}
}
