// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Some utilities to make working with the standard library's [`Future`]s easier

use alloc::vec::Vec;
use core::future::Future;
use core::marker::Unpin;
use core::pin::Pin;
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

pub(crate) enum ResultFuture<F: Future<Output = O> + Unpin, O> {
	Pending(F),
	Ready(O),
}

pub(crate) struct TwoFutureJoiner<
	AO,
	BO,
	AF: Future<Output = AO> + Unpin,
	BF: Future<Output = BO> + Unpin,
> {
	a: Option<ResultFuture<AF, AO>>,
	b: Option<ResultFuture<BF, BO>>,
}

impl<AO, BO, AF: Future<Output = AO> + Unpin, BF: Future<Output = BO> + Unpin>
	TwoFutureJoiner<AO, BO, AF, BF>
{
	pub fn new(future_a: AF, future_b: BF) -> Self {
		Self { a: Some(ResultFuture::Pending(future_a)), b: Some(ResultFuture::Pending(future_b)) }
	}
}

impl<AO, BO, AF: Future<Output = AO> + Unpin, BF: Future<Output = BO> + Unpin> Future
	for TwoFutureJoiner<AO, BO, AF, BF>
{
	type Output = (AO, BO);
	fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<(AO, BO)> {
		let mut have_pending_futures = false;
		// SAFETY: While we are pinned, we can't get direct access to our internal state because we
		// aren't `Unpin`. However, we don't actually need the `Pin` - we only use it below on the
		// `Future` in the `ResultFuture::Pending` case, and the `Future` is bound by `Unpin`.
		// Thus, the `Pin` is not actually used, and its safe to bypass it and access the inner
		// reference directly.
		let state = unsafe { &mut self.get_unchecked_mut() };
		macro_rules! poll_future {
			($future: ident) => {
				match state.$future {
					Some(ResultFuture::Pending(ref mut fut)) => match Pin::new(fut).poll(cx) {
						Poll::Ready(res) => {
							state.$future = Some(ResultFuture::Ready(res));
						},
						Poll::Pending => {
							have_pending_futures = true;
						},
					},
					Some(ResultFuture::Ready(_)) => {},
					None => {
						debug_assert!(false, "Future polled after Ready");
						return Poll::Pending;
					},
				}
			};
		}
		poll_future!(a);
		poll_future!(b);

		if have_pending_futures {
			Poll::Pending
		} else {
			Poll::Ready((
				match state.a.take() {
					Some(ResultFuture::Ready(a)) => a,
					_ => unreachable!(),
				},
				match state.b.take() {
					Some(ResultFuture::Ready(b)) => b,
					_ => unreachable!(),
				},
			))
		}
	}
}

pub(crate) struct MultiResultFuturePoller<F: Future<Output = O> + Unpin, O> {
	futures_state: Vec<ResultFuture<F, O>>,
}

impl<F: Future<Output = O> + Unpin, O> MultiResultFuturePoller<F, O> {
	pub fn new(futures_state: Vec<ResultFuture<F, O>>) -> Self {
		Self { futures_state }
	}
}

impl<F: Future<Output = O> + Unpin, O> Future for MultiResultFuturePoller<F, O> {
	type Output = Vec<O>;
	fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Vec<O>> {
		let mut have_pending_futures = false;
		// SAFETY: While we are pinned, we can't get direct access to `futures_state` because we
		// aren't `Unpin`. However, we don't actually need the `Pin` - we only use it below on the
		// `Future` in the `ResultFuture::Pending` case, and the `Future` is bound by `Unpin`.
		// Thus, the `Pin` is not actually used, and its safe to bypass it and access the inner
		// reference directly.
		let futures_state = unsafe { &mut self.get_unchecked_mut().futures_state };
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
