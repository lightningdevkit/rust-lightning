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
use core::task::{Context, Poll};

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
