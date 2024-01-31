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

use crate::sync::Mutex;
use alloc::sync::Arc;
use core::mem;

use crate::prelude::*;

#[cfg(feature = "std")]
use crate::sync::Condvar;
#[cfg(feature = "std")]
use std::time::Duration;

use core::future::Future as StdFuture;
use core::pin::Pin;
use core::task::{Context, Poll};

/// Used to signal to one of many waiters that the condition they're waiting on has happened.
pub(crate) struct Notifier {
	notify_pending: Mutex<(bool, Option<Arc<Mutex<FutureState>>>)>,
}

impl Notifier {
	pub(crate) fn new() -> Self {
		Self { notify_pending: Mutex::new((false, None)) }
	}

	/// Wake waiters, tracking that wake needs to occur even if there are currently no waiters.
	pub(crate) fn notify(&self) {
		let mut lock = self.notify_pending.lock().unwrap();
		if let Some(future_state) = &lock.1 {
			if complete_future(future_state) {
				lock.1 = None;
				return;
			}
		}
		lock.0 = true;
	}

	/// Gets a [`Future`] that will get woken up with any waiters
	pub(crate) fn get_future(&self) -> Future {
		let mut lock = self.notify_pending.lock().unwrap();
		if let Some(existing_state) = &lock.1 {
			if existing_state.lock().unwrap().callbacks_made {
				// If the existing `FutureState` has completed and actually made callbacks,
				// consider the notification flag to have been cleared and reset the future state.
				lock.1.take();
				lock.0 = false;
			}
		}
		if let Some(existing_state) = &lock.1 {
			Future { state: Arc::clone(&existing_state) }
		} else {
			let state = Arc::new(Mutex::new(FutureState {
				callbacks: Vec::new(),
				callbacks_with_state: Vec::new(),
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

macro_rules! define_callback { ($($bounds: path),*) => {
/// A callback which is called when a [`Future`] completes.
///
/// Note that this MUST NOT call back into LDK directly, it must instead schedule actions to be
/// taken later. Rust users should use the [`std::future::Future`] implementation for [`Future`]
/// instead.
///
/// Note that the [`std::future::Future`] implementation may only work for runtimes which schedule
/// futures when they receive a wake, rather than immediately executing them.
pub trait FutureCallback : $($bounds +)* {
	/// The method which is called.
	fn call(&self);
}

impl<F: Fn() $(+ $bounds)*> FutureCallback for F {
	fn call(&self) { (self)(); }
}
} }

#[cfg(feature = "std")]
define_callback!(Send);
#[cfg(not(feature = "std"))]
define_callback!();

pub(crate) struct FutureState {
	// When we're tracking whether a callback counts as having woken the user's code, we check the
	// first bool - set to false if we're just calling a Waker, and true if we're calling an actual
	// user-provided function.
	callbacks: Vec<(bool, Box<dyn FutureCallback>)>,
	callbacks_with_state: Vec<(bool, Box<dyn Fn(&Arc<Mutex<FutureState>>) -> () + Send>)>,
	complete: bool,
	callbacks_made: bool,
}

fn complete_future(this: &Arc<Mutex<FutureState>>) -> bool {
	let mut state_lock = this.lock().unwrap();
	let state = &mut *state_lock;
	for (counts_as_call, callback) in state.callbacks.drain(..) {
		callback.call();
		state.callbacks_made |= counts_as_call;
	}
	for (counts_as_call, callback) in state.callbacks_with_state.drain(..) {
		(callback)(this);
		state.callbacks_made |= counts_as_call;
	}
	state.complete = true;
	state.callbacks_made
}

/// A simple future which can complete once, and calls some callback(s) when it does so.
///
/// Clones can be made and all futures cloned from the same source will complete at the same time.
#[derive(Clone)]
pub struct Future {
	state: Arc<Mutex<FutureState>>,
}

impl Future {
	/// Registers a callback to be called upon completion of this future. If the future has already
	/// completed, the callback will be called immediately.
	///
	/// This is not exported to bindings users, use the bindings-only `register_callback_fn` instead
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

	/// Waits until this [`Future`] completes.
	#[cfg(feature = "std")]
	pub fn wait(self) {
		Sleeper::from_single_future(self).wait();
	}

	/// Waits until this [`Future`] completes or the given amount of time has elapsed.
	///
	/// Returns true if the [`Future`] completed, false if the time elapsed.
	#[cfg(feature = "std")]
	pub fn wait_timeout(self, max_wait: Duration) -> bool {
		Sleeper::from_single_future(self).wait_timeout(max_wait)
	}

	#[cfg(test)]
	pub fn poll_is_complete(&self) -> bool {
		let mut state = self.state.lock().unwrap();
		if state.complete {
			state.callbacks_made = true;
			true
		} else {
			false
		}
	}
}

use core::task::Waker;
struct StdWaker(pub Waker);
impl FutureCallback for StdWaker {
	fn call(&self) {
		self.0.wake_by_ref()
	}
}

/// This is not exported to bindings users as Rust Futures aren't usable in language bindings.
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

/// A struct which can be used to select across many [`Future`]s at once without relying on a full
/// async context.
#[cfg(feature = "std")]
pub struct Sleeper {
	notifiers: Vec<Arc<Mutex<FutureState>>>,
}

#[cfg(feature = "std")]
impl Sleeper {
	/// Constructs a new sleeper from one future, allowing blocking on it.
	pub fn from_single_future(future: Future) -> Self {
		Self { notifiers: vec![future.state] }
	}
	/// Constructs a new sleeper from two futures, allowing blocking on both at once.
	// Note that this is the common case - a ChannelManager and ChainMonitor.
	pub fn from_two_futures(fut_a: Future, fut_b: Future) -> Self {
		Self { notifiers: vec![fut_a.state, fut_b.state] }
	}
	/// Constructs a new sleeper on many futures, allowing blocking on all at once.
	pub fn new(futures: Vec<Future>) -> Self {
		Self { notifiers: futures.into_iter().map(|f| f.state).collect() }
	}
	/// Prepares to go into a wait loop body, creating a condition variable which we can block on
	/// and an `Arc<Mutex<Option<_>>>` which gets set to the waking `Future`'s state prior to the
	/// condition variable being woken.
	fn setup_wait(&self) -> (Arc<Condvar>, Arc<Mutex<Option<Arc<Mutex<FutureState>>>>>) {
		let cv = Arc::new(Condvar::new());
		let notified_fut_mtx = Arc::new(Mutex::new(None));
		{
			for notifier_mtx in self.notifiers.iter() {
				let cv_ref = Arc::clone(&cv);
				let notified_fut_ref = Arc::clone(&notified_fut_mtx);
				let mut notifier = notifier_mtx.lock().unwrap();
				if notifier.complete {
					*notified_fut_mtx.lock().unwrap() = Some(Arc::clone(&notifier_mtx));
					break;
				}
				notifier.callbacks_with_state.push((
					false,
					Box::new(move |notifier_ref| {
						*notified_fut_ref.lock().unwrap() = Some(Arc::clone(notifier_ref));
						cv_ref.notify_all();
					}),
				));
			}
		}
		(cv, notified_fut_mtx)
	}

	/// Wait until one of the [`Future`]s registered with this [`Sleeper`] has completed.
	pub fn wait(&self) {
		let (cv, notified_fut_mtx) = self.setup_wait();
		let notified_fut = cv
			.wait_while(notified_fut_mtx.lock().unwrap(), |fut_opt| fut_opt.is_none())
			.unwrap()
			.take()
			.expect("CV wait shouldn't have returned until the notifying future was set");
		notified_fut.lock().unwrap().callbacks_made = true;
	}

	/// Wait until one of the [`Future`]s registered with this [`Sleeper`] has completed or the
	/// given amount of time has elapsed. Returns true if a [`Future`] completed, false if the time
	/// elapsed.
	pub fn wait_timeout(&self, max_wait: Duration) -> bool {
		let (cv, notified_fut_mtx) = self.setup_wait();
		let notified_fut =
			match cv.wait_timeout_while(notified_fut_mtx.lock().unwrap(), max_wait, |fut_opt| {
				fut_opt.is_none()
			}) {
				Ok((_, e)) if e.timed_out() => return false,
				Ok((mut notified_fut, _)) => notified_fut
					.take()
					.expect("CV wait shouldn't have returned until the notifying future was set"),
				Err(_) => panic!("Previous panic while a lock was held led to a lock panic"),
			};
		notified_fut.lock().unwrap().callbacks_made = true;
		true
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use core::future::Future as FutureTrait;
	use core::sync::atomic::{AtomicBool, Ordering};
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
		notifier.get_future().register_callback(Box::new(move || {
			assert!(!callback_ref.fetch_or(true, Ordering::SeqCst))
		}));
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
		notifier.get_future().register_callback(Box::new(move || {
			assert!(!callback_ref.fetch_or(true, Ordering::SeqCst))
		}));
		assert!(!callback.load(Ordering::SeqCst));

		notifier.notify();
		assert!(callback.load(Ordering::SeqCst));

		let callback = Arc::new(AtomicBool::new(false));
		let callback_ref = Arc::clone(&callback);
		notifier.get_future().register_callback(Box::new(move || {
			assert!(!callback_ref.fetch_or(true, Ordering::SeqCst))
		}));
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
		future.register_callback(Box::new(move || {
			assert!(!callback_ref.fetch_or(true, Ordering::SeqCst))
		}));
		assert!(callback.load(Ordering::SeqCst));

		let callback = Arc::new(AtomicBool::new(false));
		let callback_ref = Arc::clone(&callback);
		notifier.get_future().register_callback(Box::new(move || {
			assert!(!callback_ref.fetch_or(true, Ordering::SeqCst))
		}));
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
		notifier.get_future().register_callback(Box::new(move || {
			assert!(!callback_ref.fetch_or(true, Ordering::SeqCst))
		}));
		assert!(callback.load(Ordering::SeqCst));

		let callback = Arc::new(AtomicBool::new(false));
		let callback_ref = Arc::clone(&callback);
		notifier.get_future().register_callback(Box::new(move || {
			assert!(!callback_ref.fetch_or(true, Ordering::SeqCst))
		}));
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
		thread::spawn(move || loop {
			thread_notifier.notify();
			if exit_thread_clone.load(Ordering::SeqCst) {
				break;
			}
		});

		// Check that we can block indefinitely until updates are available.
		let _ = persistence_notifier.get_future().wait();

		// Check that the Notifier will return after the given duration if updates are
		// available.
		loop {
			if persistence_notifier.get_future().wait_timeout(Duration::from_millis(100)) {
				break;
			}
		}

		exit_thread.store(true, Ordering::SeqCst);

		// Check that the Notifier will return after the given duration even if no updates
		// are available.
		loop {
			if !persistence_notifier.get_future().wait_timeout(Duration::from_millis(100)) {
				break;
			}
		}
	}

	#[cfg(feature = "std")]
	#[test]
	fn test_state_drops() {
		// Previously, there was a leak if a `Notifier` was `drop`ed without ever being notified
		// but after having been slept-on. This tests for that leak.
		use crate::sync::Arc;
		use std::thread;

		let notifier_a = Arc::new(Notifier::new());
		let notifier_b = Arc::new(Notifier::new());

		let thread_notifier_a = Arc::clone(&notifier_a);

		let future_a = notifier_a.get_future();
		let future_state_a = Arc::downgrade(&future_a.state);

		let future_b = notifier_b.get_future();
		let future_state_b = Arc::downgrade(&future_b.state);

		let join_handle = thread::spawn(move || {
			// Let the other thread get to the wait point, then notify it.
			std::thread::sleep(Duration::from_millis(50));
			thread_notifier_a.notify();
		});

		// Wait on the other thread to finish its sleep, note that the leak only happened if we
		// actually have to sleep here, not if we immediately return.
		Sleeper::from_two_futures(future_a, future_b).wait();

		join_handle.join().unwrap();

		// then drop the notifiers and make sure the future states are gone.
		mem::drop(notifier_a);
		mem::drop(notifier_b);

		assert!(future_state_a.upgrade().is_none() && future_state_b.upgrade().is_none());
	}

	#[test]
	fn test_future_callbacks() {
		let future = Future {
			state: Arc::new(Mutex::new(FutureState {
				callbacks: Vec::new(),
				callbacks_with_state: Vec::new(),
				complete: false,
				callbacks_made: false,
			})),
		};
		let callback = Arc::new(AtomicBool::new(false));
		let callback_ref = Arc::clone(&callback);
		future.register_callback(Box::new(move || {
			assert!(!callback_ref.fetch_or(true, Ordering::SeqCst))
		}));

		assert!(!callback.load(Ordering::SeqCst));
		complete_future(&future.state);
		assert!(callback.load(Ordering::SeqCst));
		complete_future(&future.state);
	}

	#[test]
	fn test_pre_completed_future_callbacks() {
		let future = Future {
			state: Arc::new(Mutex::new(FutureState {
				callbacks: Vec::new(),
				callbacks_with_state: Vec::new(),
				complete: false,
				callbacks_made: false,
			})),
		};
		complete_future(&future.state);

		let callback = Arc::new(AtomicBool::new(false));
		let callback_ref = Arc::clone(&callback);
		future.register_callback(Box::new(move || {
			assert!(!callback_ref.fetch_or(true, Ordering::SeqCst))
		}));

		assert!(callback.load(Ordering::SeqCst));
		assert!(future.state.lock().unwrap().callbacks.is_empty());
	}

	// Rather annoyingly, there's no safe way in Rust std to construct a Waker despite it being
	// totally possible to construct from a trait implementation (though somewhat less efficient
	// compared to a raw VTable). Instead, we have to write out a lot of boilerplate to build a
	// waker, which we do here with a trivial Arc<AtomicBool> data element to track woke-ness.
	const WAKER_V_TABLE: RawWakerVTable = RawWakerVTable::new(waker_clone, wake, wake_by_ref, drop);
	unsafe fn wake_by_ref(ptr: *const ()) {
		let p = ptr as *const Arc<AtomicBool>;
		assert!(!(*p).fetch_or(true, Ordering::SeqCst));
	}
	unsafe fn drop(ptr: *const ()) {
		let p = ptr as *mut Arc<AtomicBool>;
		let _freed = Box::from_raw(p);
	}
	unsafe fn wake(ptr: *const ()) {
		wake_by_ref(ptr);
		drop(ptr);
	}
	unsafe fn waker_clone(ptr: *const ()) -> RawWaker {
		let p = ptr as *const Arc<AtomicBool>;
		RawWaker::new(Box::into_raw(Box::new(Arc::clone(&*p))) as *const (), &WAKER_V_TABLE)
	}

	fn create_waker() -> (Arc<AtomicBool>, Waker) {
		let a = Arc::new(AtomicBool::new(false));
		let waker =
			unsafe { Waker::from_raw(waker_clone((&a as *const Arc<AtomicBool>) as *const ())) };
		(a, waker)
	}

	#[test]
	fn test_future() {
		let mut future = Future {
			state: Arc::new(Mutex::new(FutureState {
				callbacks: Vec::new(),
				callbacks_with_state: Vec::new(),
				complete: false,
				callbacks_made: false,
			})),
		};
		let mut second_future = Future { state: Arc::clone(&future.state) };

		let (woken, waker) = create_waker();
		assert_eq!(Pin::new(&mut future).poll(&mut Context::from_waker(&waker)), Poll::Pending);
		assert!(!woken.load(Ordering::SeqCst));

		let (second_woken, second_waker) = create_waker();
		assert_eq!(
			Pin::new(&mut second_future).poll(&mut Context::from_waker(&second_waker)),
			Poll::Pending
		);
		assert!(!second_woken.load(Ordering::SeqCst));

		complete_future(&future.state);
		assert!(woken.load(Ordering::SeqCst));
		assert!(second_woken.load(Ordering::SeqCst));
		assert_eq!(Pin::new(&mut future).poll(&mut Context::from_waker(&waker)), Poll::Ready(()));
		assert_eq!(
			Pin::new(&mut second_future).poll(&mut Context::from_waker(&second_waker)),
			Poll::Ready(())
		);
	}

	#[test]
	#[cfg(feature = "std")]
	fn test_dropped_future_doesnt_count() {
		// Tests that if a Future gets drop'd before it is poll()ed `Ready` it doesn't count as
		// having been woken, leaving the notify-required flag set.
		let notifier = Notifier::new();
		notifier.notify();

		// If we get a future and don't touch it we're definitely still notify-required.
		notifier.get_future();
		assert!(notifier.get_future().wait_timeout(Duration::from_millis(1)));
		assert!(!notifier.get_future().wait_timeout(Duration::from_millis(1)));

		// Even if we poll'd once but didn't observe a `Ready`, we should be notify-required.
		let mut future = notifier.get_future();
		let (woken, waker) = create_waker();
		assert_eq!(Pin::new(&mut future).poll(&mut Context::from_waker(&waker)), Poll::Pending);

		notifier.notify();
		assert!(woken.load(Ordering::SeqCst));
		assert!(notifier.get_future().wait_timeout(Duration::from_millis(1)));

		// However, once we do poll `Ready` it should wipe the notify-required flag.
		let mut future = notifier.get_future();
		let (woken, waker) = create_waker();
		assert_eq!(Pin::new(&mut future).poll(&mut Context::from_waker(&waker)), Poll::Pending);

		notifier.notify();
		assert!(woken.load(Ordering::SeqCst));
		assert_eq!(Pin::new(&mut future).poll(&mut Context::from_waker(&waker)), Poll::Ready(()));
		assert!(!notifier.get_future().wait_timeout(Duration::from_millis(1)));
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

	#[test]
	#[cfg(feature = "std")]
	fn test_multi_future_sleep() {
		// Tests the `Sleeper` with multiple futures.
		let notifier_a = Notifier::new();
		let notifier_b = Notifier::new();

		// Set both notifiers as woken without sleeping yet.
		notifier_a.notify();
		notifier_b.notify();
		Sleeper::from_two_futures(notifier_a.get_future(), notifier_b.get_future()).wait();

		// One future has woken us up, but the other should still have a pending notification.
		Sleeper::from_two_futures(notifier_a.get_future(), notifier_b.get_future()).wait();

		// However once we've slept twice, we should no longer have any pending notifications
		assert!(!Sleeper::from_two_futures(notifier_a.get_future(), notifier_b.get_future())
			.wait_timeout(Duration::from_millis(10)));

		// Test ordering somewhat more.
		notifier_a.notify();
		Sleeper::from_two_futures(notifier_a.get_future(), notifier_b.get_future()).wait();
	}

	#[test]
	#[cfg(feature = "std")]
	fn sleeper_with_pending_callbacks() {
		// This is similar to the above `test_multi_future_sleep` test, but in addition registers
		// "normal" callbacks which will cause the futures to assume notification has occurred,
		// rather than waiting for a woken sleeper.
		let notifier_a = Notifier::new();
		let notifier_b = Notifier::new();

		// Set both notifiers as woken without sleeping yet.
		notifier_a.notify();
		notifier_b.notify();

		// After sleeping one future (not guaranteed which one, however) will have its notification
		// bit cleared.
		Sleeper::from_two_futures(notifier_a.get_future(), notifier_b.get_future()).wait();

		// By registering a callback on the futures for both notifiers, one will complete
		// immediately, but one will remain tied to the notifier, and will complete once the
		// notifier is next woken, which will be considered the completion of the notification.
		let callback_a = Arc::new(AtomicBool::new(false));
		let callback_b = Arc::new(AtomicBool::new(false));
		let callback_a_ref = Arc::clone(&callback_a);
		let callback_b_ref = Arc::clone(&callback_b);
		notifier_a.get_future().register_callback(Box::new(move || {
			assert!(!callback_a_ref.fetch_or(true, Ordering::SeqCst))
		}));
		notifier_b.get_future().register_callback(Box::new(move || {
			assert!(!callback_b_ref.fetch_or(true, Ordering::SeqCst))
		}));
		assert!(callback_a.load(Ordering::SeqCst) ^ callback_b.load(Ordering::SeqCst));

		// If we now notify both notifiers again, the other callback will fire, completing the
		// notification, and we'll be back to one pending notification.
		notifier_a.notify();
		notifier_b.notify();

		assert!(callback_a.load(Ordering::SeqCst) && callback_b.load(Ordering::SeqCst));
		Sleeper::from_two_futures(notifier_a.get_future(), notifier_b.get_future()).wait();
		assert!(!Sleeper::from_two_futures(notifier_a.get_future(), notifier_b.get_future())
			.wait_timeout(Duration::from_millis(10)));
	}
}
