use crate::sync::debug_sync::{Mutex, RwLock};

use super::{LockHeldState, LockTestExt};

use std::sync::Arc;

#[test]
#[should_panic]
#[cfg(not(feature = "backtrace"))]
fn recursive_lock_fail() {
	let mutex = Mutex::new(());
	let _a = mutex.lock().unwrap();
	let _b = mutex.lock().unwrap();
}

#[test]
#[should_panic]
#[cfg(not(feature = "backtrace"))]
fn recursive_read() {
	let lock = RwLock::new(());
	let _a = lock.read().unwrap();
	let _b = lock.read().unwrap();
}

#[test]
#[should_panic]
fn lockorder_fail() {
	let a = Mutex::new(());
	let b = Mutex::new(());
	{
		let _a = a.lock().unwrap();
		let _b = b.lock().unwrap();
	}
	{
		let _b = b.lock().unwrap();
		let _a = a.lock().unwrap();
	}
}

#[test]
#[should_panic]
fn write_lockorder_fail() {
	let a = RwLock::new(());
	let b = RwLock::new(());
	{
		let _a = a.write().unwrap();
		let _b = b.write().unwrap();
	}
	{
		let _b = b.write().unwrap();
		let _a = a.write().unwrap();
	}
}

#[test]
#[should_panic]
fn read_lockorder_fail() {
	let a = RwLock::new(());
	let b = RwLock::new(());
	{
		let _a = a.read().unwrap();
		let _b = b.read().unwrap();
	}
	{
		let _b = b.read().unwrap();
		let _a = a.read().unwrap();
	}
}

#[test]
#[should_panic]
fn read_write_lockorder_fail() {
	let a = RwLock::new(());
	let b = RwLock::new(());
	{
		let _a = a.write().unwrap();
		let _b = b.read().unwrap();
	}
	{
		let _b = b.read().unwrap();
		let _a = a.write().unwrap();
	}
}

#[test]
fn test_thread_locked_state() {
	let mtx = Arc::new(Mutex::new(()));
	let mtx_ref = Arc::clone(&mtx);
	assert_eq!(mtx.held_by_thread(), LockHeldState::NotHeldByThread);

	let lck = mtx.lock().unwrap();
	assert_eq!(mtx.held_by_thread(), LockHeldState::HeldByThread);

	let thrd = std::thread::spawn(move || {
		assert_eq!(mtx_ref.held_by_thread(), LockHeldState::NotHeldByThread);
	});
	thrd.join().unwrap();
	assert_eq!(mtx.held_by_thread(), LockHeldState::HeldByThread);

	std::mem::drop(lck);
	assert_eq!(mtx.held_by_thread(), LockHeldState::NotHeldByThread);
}
