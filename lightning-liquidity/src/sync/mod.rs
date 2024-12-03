#![allow(unused_imports)]

#[cfg(feature = "std")]
pub use std::sync::{Arc, Condvar, Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};

#[cfg(not(feature = "std"))]
mod nostd_sync;
#[cfg(not(feature = "std"))]
pub use nostd_sync::*;
