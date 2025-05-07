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

/// A type alias for a future that returns a result of type T.
pub type AsyncResult<'a, T> = Pin<Box<dyn Future<Output = Result<T, ()>> + 'a + Send>>;
