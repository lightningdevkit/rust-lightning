// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Some utilities to make working with the standard library's [`Future`]s easier

// The `unsafe` in this module is required to support `!Unpin` futures without
// lots of extra unnecessary boxing.
#![allow(unsafe_code)]

use crate::prelude::*;
use core::future::Future;
use core::marker::Unpin;
use core::mem;
use core::pin::Pin;
use core::task::{Context, Poll};

pub(crate) enum ResultFuture<F: Future<Output = Result<(), E>>, E: Unpin> {
	Pending(/* #[pin] */ F),
	Ready(Result<(), E>),
}

/// A future that polls a set of futures concurrently and returns their results.
///
/// This implementation is effectively `futures::future::join_all` with no "Big"
/// set optimization:
/// <https://github.com/rust-lang/futures-rs/blob/6f9a15f6e30cb3a2a79aabb9386dfaf282ef174d/futures-util/src/future/join_all.rs>
pub(crate) struct MultiResultFuturePoller<F: Future<Output = Result<(), E>>, E: Unpin> {
	// Use a pinned boxed slice instead of a Vec to make it harder to accidentally
	// move the inner values. Someone could easily resize the Vec, thus moving all
	// the inner values and violating the Pin contract.
	futures_state: Pin<Box<[ResultFuture<F, E>]>>,
}

impl<F: Future<Output = Result<(), E>>, E: Unpin> MultiResultFuturePoller<F, E> {
	pub fn new(futures_state: Vec<ResultFuture<F, E>>) -> Self {
		Self { futures_state: Box::into_pin(futures_state.into_boxed_slice()) }
	}
}

impl<F: Future<Output = Result<(), E>>, E: Unpin> Future for MultiResultFuturePoller<F, E> {
	type Output = Vec<Result<(), E>>;

	fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Vec<Result<(), E>>> {
		let mut any_pending_futures = false;
		let futures_state: &mut Pin<Box<[_]>> = &mut self.futures_state;

		// Poll all the inner futures in order.
		for state in iter_pin_mut(futures_state.as_mut()) {
			if state.poll(cx).is_pending() {
				any_pending_futures = true;
			}
		}

		if !any_pending_futures {
			// Reuse the Box<[_]> allocation for the output Vec<_>.
			let results: Pin<Box<[_]>> = mem::replace(futures_state, Box::pin([]));
			// SAFETY: all the inner values are simple `Ready(Result<(), E>)`
			// values, which are `Unpin`.
			let results: Box<[_]> = unsafe { Pin::into_inner_unchecked(results) };
			let results = Vec::from(results);

			let result = results
				.into_iter()
				.map(|state| match state {
					ResultFuture::Ready(res) => res,
					ResultFuture::Pending(_) => {
						unreachable!("All futures are expected to be ready if none are pending")
					},
				})
				.collect();

			Poll::Ready(result)
		} else {
			Poll::Pending
		}
	}
}

impl<F: Future<Output = Result<(), E>>, E: Unpin> Future for ResultFuture<F, E> {
	type Output = ();

	fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
		// SAFETY: just a standard enum pin-project, which is safe as we don't
		// move anything during Pin<&mut Self> -> &mut Self -> Pin<&mut F>.
		let this: &mut Self = unsafe { self.as_mut().get_unchecked_mut() };
		match this {
			ResultFuture::Pending(fut) => {
				let fut: Pin<&mut F> = unsafe { Pin::new_unchecked(fut) };
				match fut.poll(cx) {
					Poll::Ready(res) => {
						self.set(ResultFuture::Ready(res));
						Poll::Ready(())
					},
					Poll::Pending => Poll::Pending,
				}
			},
			ResultFuture::Ready(_) => Poll::Ready(()),
		}
	}
}

// Pin project from a pinned mut slice into an iterator of pinned mut entries.
fn iter_pin_mut<T>(slice: Pin<&mut [T]>) -> impl Iterator<Item = Pin<&mut T>> {
	// quoted from `futures::future::join_all`:
	// > SAFETY: `std` _could_ make this unsound if it were to decide Pin's
	// > invariants aren't required to transmit through slices. Otherwise this has
	// > the same safety as a normal field pin projection.
	let slice: &mut [T] = unsafe { Pin::get_unchecked_mut(slice) };
	slice.iter_mut().map(|x| unsafe { Pin::new_unchecked(x) })
}
