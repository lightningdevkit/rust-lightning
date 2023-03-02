// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Utilities which allow users to block on some future notification from LDK. These are
//! specifically used by [`ChannelManager`] to allow waiting until the [`ChannelManager`] needs to
//! be re-persisted.
//!
//! [`ChannelManager`]: crate::ln::channelmanager::ChannelManager

use alloc::sync::Arc;
use core::mem;
use crate::sync::{Condvar, Mutex, MutexGuard};

use crate::prelude::*;

#[cfg(any(test, feature = "std"))]
use std::time::{Duration, Instant};

use core::future::Future as StdFuture;
use core::task::{Context, Poll};
use core::pin::Pin;


/// Used to signal to one of many waiters that the condition they're waiting on has happened.
pub(crate) struct Notifier {
	notify_pending: Mutex<(bool, Option<Arc<Mutex<FutureState>>>)>,
	condvar: Condvar,
}

macro_rules! check_woken {
	($guard: expr, $retval: expr) => { {
		if $guard.0 {
			$guard.0 = false;
			if $guard.1.as_ref().map(|l| l.lock().unwrap().complete).unwrap_or(false) {
				// If we're about to return as woken, and the future state is marked complete, wipe
				// the future state and let the next future wait until we get a new notify.
				$guard.1.take();
			}
			return $retval;
		}
	} }
}

impl Notifier {
	pub(crate) fn new() -> Self {
		Self {
			notify_pending: Mutex::new((false, None)),
			condvar: Condvar::new(),
		}
	}

	fn propagate_future_state_to_notify_flag(&self) -> MutexGuard<(bool, Option<Arc<Mutex<FutureState>>>)> {
		let mut lock = self.notify_pending.lock().unwrap();
		if let Some(existing_state) = &lock.1 {
			if existing_state.lock().unwrap().callbacks_made {
				// If the existing `FutureState` has completed and actually made callbacks,
				// consider the notification flag to have been cleared and reset the future state.
				lock.1.take();
				lock.0 = false;
			}
		}
		lock
	}

	pub(crate) fn wait(&self) {
		loop {
			let mut guard = self.propagate_future_state_to_notify_flag();
			check_woken!(guard, ());
			guard = self.condvar.wait(guard).unwrap();
			check_woken!(guard, ());
		}
	}

	#[cfg(any(test, feature = "std"))]
	pub(crate) fn wait_timeout(&self, max_wait: Duration) -> bool {
		let current_time = Instant::now();
		loop {
			let mut guard = self.propagate_future_state_to_notify_flag();
			check_woken!(guard, true);
			guard = self.condvar.wait_timeout(guard, max_wait).unwrap().0;
			check_woken!(guard, true);
			// Due to spurious wakeups that can happen on `wait_timeout`, here we need to check if the
			// desired wait time has actually passed, and if not then restart the loop with a reduced wait
			// time. Note that this logic can be highly simplified through the use of
			// `Condvar::wait_while` and `Condvar::wait_timeout_while`, if and when our MSRV is raised to
			// 1.42.0.
			let elapsed = current_time.elapsed();
			if elapsed >= max_wait {
				return false;
			}
			match max_wait.checked_sub(elapsed) {
				None => return false,
				Some(_) => continue
			}
		}
	}

	/// Wake waiters, tracking that wake needs to occur even if there are currently no waiters.
	pub(crate) fn notify(&self) {
		let mut lock = self.notify_pending.lock().unwrap();
		if let Some(future_state) = &lock.1 {
			if future_state.lock().unwrap().complete() {
				lock.1 = None;
				return;
			}
		}
		lock.0 = true;
		mem::drop(lock);
		self.condvar.notify_all();
	}

	/// Gets a [`Future`] that will get woken up with any waiters
	pub(crate) fn get_future(&self) -> Future {
		let mut lock = self.propagate_future_state_to_notify_flag();
		if let Some(existing_state) = &lock.1 {
			Future { state: Arc::clone(&existing_state) }
		} else {
			let state = Arc::new(Mutex::new(FutureState {
				callbacks: Vec::new(),
				complete: lock.0,
				callbacks_made: false,
			}));
			lock.1 = Some(Arc::clone(&state));
			Future { state }
		}
	}

	#[cfg(any(test, feature = "_test_utils"))]
	pub fn notify_pending(&self) -> bool {
		self.notify_pending.lock().unwrap().0
	}
}

/// A callback which is called when a [`Future`] completes.
///
/// Note that this MUST NOT call back into LDK directly, it must instead schedule actions to be
/// taken later. Rust users should use the [`std::future::Future`] implementation for [`Future`]
/// instead.
///
/// Note that the [`std::future::Future`] implementation may only work for runtimes which schedule
/// futures when they receive a wake, rather than immediately executing them.
pub trait FutureCallback : Send {
	/// The method which is called.
	fn call(&self);
}

impl<F: Fn() + Send> FutureCallback for F {
	fn call(&self) { (self)(); }
}

pub(crate) struct FutureState {
	// When we're tracking whether a callback counts as having woken the user's code, we check the
	// first bool - set to false if we're just calling a Waker, and true if we're calling an actual
	// user-provided function.
	callbacks: Vec<(bool, Box<dyn FutureCallback>)>,
	complete: bool,
	callbacks_made: bool,
}

impl FutureState {
	fn complete(&mut self) -> bool {
		for (counts_as_call, callback) in self.callbacks.drain(..) {
			callback.call();
			self.callbacks_made |= counts_as_call;
		}
		self.complete = true;
		self.callbacks_made
	}
}

/// A simple future which can complete once, and calls some callback(s) when it does so.
pub struct Future {
	state: Arc<Mutex<FutureState>>,
}

impl Future {
	/// Registers a callback to be called upon completion of this future. If the future has already
	/// completed, the callback will be called immediately.
	///
	/// (C-not exported) use the bindings-only `register_callback_fn` instead
	pub fn register_callback(&self, callback: Box<dyn FutureCallback>) {
		let mut state = self.state.lock().unwrap();
		if state.complete {
			state.callbacks_made = true;
			mem::drop(state);
			callback.call();
		} else {
			state.callbacks.push((true, callback));
		}
	}

	// C bindings don't (currently) know how to map `Box<dyn Trait>`, and while it could add the
	// following wrapper, doing it in the bindings is currently much more work than simply doing it
	// here.
	/// Registers a callback to be called upon completion of this future. If the future has already
	/// completed, the callback will be called immediately.
	#[cfg(c_bindings)]
	pub fn register_callback_fn<F: 'static + FutureCallback>(&self, callback: F) {
		self.register_callback(Box::new(callback));
	}
}

use core::task::Waker;
struct StdWaker(pub Waker);
impl FutureCallback for StdWaker {
	fn call(&self) { self.0.wake_by_ref() }
}

/// (C-not exported) as Rust Futures aren't usable in language bindings.
impl<'a> StdFuture for Future {
	type Output = ();

	fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
		let mut state = self.state.lock().unwrap();
		if state.complete {
			state.callbacks_made = true;
			Poll::Ready(())
		} else {
			let waker = cx.waker().clone();
			state.callbacks.push((false, Box::new(StdWaker(waker))));
			Poll::Pending
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use core::sync::atomic::{AtomicBool, Ordering};
	use core::future::Future as FutureTrait;
	use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

	#[test]
	fn notifier_pre_notified_future() {
		// Previously, if we generated a future after a `Notifier` had been notified, the future
		// would never complete. This tests this behavior, ensuring the future instead completes
		// immediately.
		let notifier = Notifier::new();
		notifier.notify();

		let callback = Arc::new(AtomicBool::new(false));
		let callback_ref = Arc::clone(&callback);
		notifier.get_future().register_callback(Box::new(move || assert!(!callback_ref.fetch_or(true, Ordering::SeqCst))));
		assert!(callback.load(Ordering::SeqCst));
	}

	#[test]
	fn notifier_future_completes_wake() {
		// Previously, if we were only using the `Future` interface to learn when a `Notifier` has
		// been notified, we'd never mark the notifier as not-awaiting-notify. This caused the
		// `lightning-background-processor` to persist in a tight loop.
		let notifier = Notifier::new();

		// First check the simple case, ensuring if we get notified a new future isn't woken until
		// a second `notify`.
		let callback = Arc::new(AtomicBool::new(false));
		let callback_ref = Arc::clone(&callback);
		notifier.get_future().register_callback(Box::new(move || assert!(!callback_ref.fetch_or(true, Ordering::SeqCst))));
		assert!(!callback.load(Ordering::SeqCst));

		notifier.notify();
		assert!(callback.load(Ordering::SeqCst));

		let callback = Arc::new(AtomicBool::new(false));
		let callback_ref = Arc::clone(&callback);
		notifier.get_future().register_callback(Box::new(move || assert!(!callback_ref.fetch_or(true, Ordering::SeqCst))));
		assert!(!callback.load(Ordering::SeqCst));

		notifier.notify();
		assert!(callback.load(Ordering::SeqCst));

		// Then check the case where the future is fetched before the notification, but a callback
		// is only registered after the `notify`, ensuring that it is still sufficient to ensure we
		// don't get an instant-wake when we get a new future.
		let future = notifier.get_future();
		notifier.notify();

		let callback = Arc::new(AtomicBool::new(false));
		let callback_ref = Arc::clone(&callback);
		future.register_callback(Box::new(move || assert!(!callback_ref.fetch_or(true, Ordering::SeqCst))));
		assert!(callback.load(Ordering::SeqCst));

		let callback = Arc::new(AtomicBool::new(false));
		let callback_ref = Arc::clone(&callback);
		notifier.get_future().register_callback(Box::new(move || assert!(!callback_ref.fetch_or(true, Ordering::SeqCst))));
		assert!(!callback.load(Ordering::SeqCst));
	}

	#[test]
	fn new_future_wipes_notify_bit() {
		// Previously, if we were only using the `Future` interface to learn when a `Notifier` has
		// been notified, we'd never mark the notifier as not-awaiting-notify if a `Future` is
		// fetched after the notify bit has been set.
		let notifier = Notifier::new();
		notifier.notify();

		let callback = Arc::new(AtomicBool::new(false));
		let callback_ref = Arc::clone(&callback);
		notifier.get_future().register_callback(Box::new(move || assert!(!callback_ref.fetch_or(true, Ordering::SeqCst))));
		assert!(callback.load(Ordering::SeqCst));

		let callback = Arc::new(AtomicBool::new(false));
		let callback_ref = Arc::clone(&callback);
		notifier.get_future().register_callback(Box::new(move || assert!(!callback_ref.fetch_or(true, Ordering::SeqCst))));
		assert!(!callback.load(Ordering::SeqCst));

		notifier.notify();
		assert!(callback.load(Ordering::SeqCst));
	}

	#[cfg(feature = "std")]
	#[test]
	fn test_wait_timeout() {
		use crate::sync::Arc;
		use std::thread;

		let persistence_notifier = Arc::new(Notifier::new());
		let thread_notifier = Arc::clone(&persistence_notifier);

		let exit_thread = Arc::new(AtomicBool::new(false));
		let exit_thread_clone = exit_thread.clone();
		thread::spawn(move || {
			loop {
				let mut lock = thread_notifier.notify_pending.lock().unwrap();
				lock.0 = true;
				thread_notifier.condvar.notify_all();

				if exit_thread_clone.load(Ordering::SeqCst) {
					break
				}
			}
		});

		// Check that we can block indefinitely until updates are available.
		let _ = persistence_notifier.wait();

		// Check that the Notifier will return after the given duration if updates are
		// available.
		loop {
			if persistence_notifier.wait_timeout(Duration::from_millis(100)) {
				break
			}
		}

		exit_thread.store(true, Ordering::SeqCst);

		// Check that the Notifier will return after the given duration even if no updates
		// are available.
		loop {
			if !persistence_notifier.wait_timeout(Duration::from_millis(100)) {
				break
			}
		}
	}

	#[test]
	fn test_future_callbacks() {
		let future = Future {
			state: Arc::new(Mutex::new(FutureState {
				callbacks: Vec::new(),
				complete: false,
				callbacks_made: false,
			}))
		};
		let callback = Arc::new(AtomicBool::new(false));
		let callback_ref = Arc::clone(&callback);
		future.register_callback(Box::new(move || assert!(!callback_ref.fetch_or(true, Ordering::SeqCst))));

		assert!(!callback.load(Ordering::SeqCst));
		future.state.lock().unwrap().complete();
		assert!(callback.load(Ordering::SeqCst));
		future.state.lock().unwrap().complete();
	}

	#[test]
	fn test_pre_completed_future_callbacks() {
		let future = Future {
			state: Arc::new(Mutex::new(FutureState {
				callbacks: Vec::new(),
				complete: false,
				callbacks_made: false,
			}))
		};
		future.state.lock().unwrap().complete();

		let callback = Arc::new(AtomicBool::new(false));
		let callback_ref = Arc::clone(&callback);
		future.register_callback(Box::new(move || assert!(!callback_ref.fetch_or(true, Ordering::SeqCst))));

		assert!(callback.load(Ordering::SeqCst));
		assert!(future.state.lock().unwrap().callbacks.is_empty());
	}

	// Rather annoyingly, there's no safe way in Rust std to construct a Waker despite it being
	// totally possible to construct from a trait implementation (though somewhat less effecient
	// compared to a raw VTable). Instead, we have to write out a lot of boilerplate to build a
	// waker, which we do here with a trivial Arc<AtomicBool> data element to track woke-ness.
	const WAKER_V_TABLE: RawWakerVTable = RawWakerVTable::new(waker_clone, wake, wake_by_ref, drop);
	unsafe fn wake_by_ref(ptr: *const ()) { let p = ptr as *const Arc<AtomicBool>; assert!(!(*p).fetch_or(true, Ordering::SeqCst)); }
	unsafe fn drop(ptr: *const ()) { let p = ptr as *mut Arc<AtomicBool>; let _freed = Box::from_raw(p); }
	unsafe fn wake(ptr: *const ()) { wake_by_ref(ptr); drop(ptr); }
	unsafe fn waker_clone(ptr: *const ()) -> RawWaker {
		let p = ptr as *const Arc<AtomicBool>;
		RawWaker::new(Box::into_raw(Box::new(Arc::clone(&*p))) as *const (), &WAKER_V_TABLE)
	}

	fn create_waker() -> (Arc<AtomicBool>, Waker) {
		let a = Arc::new(AtomicBool::new(false));
		let waker = unsafe { Waker::from_raw(waker_clone((&a as *const Arc<AtomicBool>) as *const ())) };
		(a, waker)
	}

	#[test]
	fn test_future() {
		let mut future = Future {
			state: Arc::new(Mutex::new(FutureState {
				callbacks: Vec::new(),
				complete: false,
				callbacks_made: false,
			}))
		};
		let mut second_future = Future { state: Arc::clone(&future.state) };

		let (woken, waker) = create_waker();
		assert_eq!(Pin::new(&mut future).poll(&mut Context::from_waker(&waker)), Poll::Pending);
		assert!(!woken.load(Ordering::SeqCst));

		let (second_woken, second_waker) = create_waker();
		assert_eq!(Pin::new(&mut second_future).poll(&mut Context::from_waker(&second_waker)), Poll::Pending);
		assert!(!second_woken.load(Ordering::SeqCst));

		future.state.lock().unwrap().complete();
		assert!(woken.load(Ordering::SeqCst));
		assert!(second_woken.load(Ordering::SeqCst));
		assert_eq!(Pin::new(&mut future).poll(&mut Context::from_waker(&waker)), Poll::Ready(()));
		assert_eq!(Pin::new(&mut second_future).poll(&mut Context::from_waker(&second_waker)), Poll::Ready(()));
	}

	#[test]
	fn test_dropped_future_doesnt_count() {
		// Tests that if a Future gets drop'd before it is poll()ed `Ready` it doesn't count as
		// having been woken, leaving the notify-required flag set.
		let notifier = Notifier::new();
		notifier.notify();

		// If we get a future and don't touch it we're definitely still notify-required.
		notifier.get_future();
		assert!(notifier.wait_timeout(Duration::from_millis(1)));
		assert!(!notifier.wait_timeout(Duration::from_millis(1)));

		// Even if we poll'd once but didn't observe a `Ready`, we should be notify-required.
		let mut future = notifier.get_future();
		let (woken, waker) = create_waker();
		assert_eq!(Pin::new(&mut future).poll(&mut Context::from_waker(&waker)), Poll::Pending);

		notifier.notify();
		assert!(woken.load(Ordering::SeqCst));
		assert!(notifier.wait_timeout(Duration::from_millis(1)));

		// However, once we do poll `Ready` it should wipe the notify-required flag.
		let mut future = notifier.get_future();
		let (woken, waker) = create_waker();
		assert_eq!(Pin::new(&mut future).poll(&mut Context::from_waker(&waker)), Poll::Pending);

		notifier.notify();
		assert!(woken.load(Ordering::SeqCst));
		assert_eq!(Pin::new(&mut future).poll(&mut Context::from_waker(&waker)), Poll::Ready(()));
		assert!(!notifier.wait_timeout(Duration::from_millis(1)));
	}

	#[test]
	fn test_poll_post_notify_completes() {
		// Tests that if we have a future state that has completed, and we haven't yet requested a
		// new future, if we get a notify prior to requesting that second future it is generated
		// pre-completed.
		let notifier = Notifier::new();

		notifier.notify();
		let mut future = notifier.get_future();
		let (woken, waker) = create_waker();
		assert_eq!(Pin::new(&mut future).poll(&mut Context::from_waker(&waker)), Poll::Ready(()));
		assert!(!woken.load(Ordering::SeqCst));

		notifier.notify();
		let mut future = notifier.get_future();
		let (woken, waker) = create_waker();
		assert_eq!(Pin::new(&mut future).poll(&mut Context::from_waker(&waker)), Poll::Ready(()));
		assert!(!woken.load(Ordering::SeqCst));

		let mut future = notifier.get_future();
		let (woken, waker) = create_waker();
		assert_eq!(Pin::new(&mut future).poll(&mut Context::from_waker(&waker)), Poll::Pending);
		assert!(!woken.load(Ordering::SeqCst));

		notifier.notify();
		assert!(woken.load(Ordering::SeqCst));
		assert_eq!(Pin::new(&mut future).poll(&mut Context::from_waker(&waker)), Poll::Ready(()));
	}

	#[test]
	fn test_poll_post_notify_completes_initial_notified() {
		// Identical to the previous test, but the first future completes via a wake rather than an
		// immediate `Poll::Ready`.
		let notifier = Notifier::new();

		let mut future = notifier.get_future();
		let (woken, waker) = create_waker();
		assert_eq!(Pin::new(&mut future).poll(&mut Context::from_waker(&waker)), Poll::Pending);

		notifier.notify();
		assert!(woken.load(Ordering::SeqCst));
		assert_eq!(Pin::new(&mut future).poll(&mut Context::from_waker(&waker)), Poll::Ready(()));

		notifier.notify();
		let mut future = notifier.get_future();
		let (woken, waker) = create_waker();
		assert_eq!(Pin::new(&mut future).poll(&mut Context::from_waker(&waker)), Poll::Ready(()));
		assert!(!woken.load(Ordering::SeqCst));

		let mut future = notifier.get_future();
		let (woken, waker) = create_waker();
		assert_eq!(Pin::new(&mut future).poll(&mut Context::from_waker(&waker)), Poll::Pending);
		assert!(!woken.load(Ordering::SeqCst));

		notifier.notify();
		assert!(woken.load(Ordering::SeqCst));
		assert_eq!(Pin::new(&mut future).poll(&mut Context::from_waker(&waker)), Poll::Ready(()));
	}
}
