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

pub(crate) struct MultiFuturePoller<F: Future<Output = ()> + Unpin>(pub Vec<Option<F>>);

impl<F: Future<Output = ()> + Unpin> Future for MultiFuturePoller<F> {
	type Output = ();
	fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
		let mut have_pending_futures = false;
		for fut_option in self.get_mut().0.iter_mut() {
			let mut fut = match fut_option.take() {
				None => continue,
				Some(fut) => fut,
			};
			match Pin::new(&mut fut).poll(cx) {
				Poll::Ready(()) => {},
				Poll::Pending => {
					have_pending_futures = true;
					*fut_option = Some(fut);
				},
			}
		}
		if have_pending_futures {
			Poll::Pending
		} else {
			Poll::Ready(())
		}
	}
}
