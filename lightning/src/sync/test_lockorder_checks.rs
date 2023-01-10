use crate::sync::debug_sync::{RwLock, Mutex};

#[test]
#[should_panic]
#[cfg(not(feature = "backtrace"))]
fn recursive_lock_fail() {
	let mutex = Mutex::new(());
	let _a = mutex.lock().unwrap();
	let _b = mutex.lock().unwrap();
}

#[test]
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
fn read_recursive_no_lockorder() {
	// Like the above, but note that no lockorder is implied when we recursively read-lock a
	// RwLock, causing this to pass just fine.
	let a = RwLock::new(());
	let b = RwLock::new(());
	let _outer = a.read().unwrap();
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
