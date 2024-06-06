// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Some utilities to make working with the standard library's [`Future`]s easier

use crate::events::ReplayEvent;
use crate::prelude::*;
use core::future::Future;
use core::marker::Unpin;
use core::pin::Pin;
use core::task::{Context, Poll};

enum EventFuture<F: Future<Output = Result<(), ReplayEvent>>> {
	Pending(F),
	Ready(Result<(), ReplayEvent>),
}

pub(crate) struct MultiEventFuturePoller<F: Future<Output = Result<(), ReplayEvent>> + Unpin> {
	futures_state: Vec<EventFuture<F>>,
}

impl<F: Future<Output = Result<(), ReplayEvent>> + Unpin> MultiEventFuturePoller<F> {
	pub fn new(futures: Vec<F>) -> Self {
		let futures_state = futures.into_iter().map(|f| EventFuture::Pending(f)).collect();
		Self { futures_state }
	}
}

impl<F: Future<Output = Result<(), ReplayEvent>> + Unpin> Future for MultiEventFuturePoller<F> {
	type Output = Vec<Result<(), ReplayEvent>>;
	fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Vec<Result<(), ReplayEvent>>> {
		let mut have_pending_futures = false;
		let futures_state = &mut self.get_mut().futures_state;
		for state in futures_state.iter_mut() {
			match state {
				EventFuture::Pending(ref mut fut) => match Pin::new(fut).poll(cx) {
					Poll::Ready(res) => {
						*state = EventFuture::Ready(res);
					},
					Poll::Pending => {
						have_pending_futures = true;
					},
				},
				EventFuture::Ready(_) => continue,
			}
		}

		if have_pending_futures {
			Poll::Pending
		} else {
			let results = futures_state
				.iter()
				.filter_map(|e| match e {
					EventFuture::Ready(res) => Some(res),
					EventFuture::Pending(_) => {
						debug_assert!(
							false,
							"All futures are expected to be ready if none are pending"
						);
						None
					},
				})
				.cloned()
				.collect();
			Poll::Ready(results)
		}
	}
}
