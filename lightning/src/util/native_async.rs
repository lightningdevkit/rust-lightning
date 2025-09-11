// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! This module contains a few public utility which are used to run LDK in a native Rust async
//! environment.

use crate::util::async_poll::MaybeSend;
use core::future::Future;

/// A generic trait which is able to spawn futures in the background.
pub trait FutureSpawner: Send + Sync + 'static {
	/// Spawns the given future as a background task.
	///
	/// This method MUST NOT block on the given future immediately.
	fn spawn<T: Future<Output = ()> + MaybeSend + 'static>(&self, future: T);
}
