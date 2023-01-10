#[cfg(all(feature = "std", not(feature = "_bench_unstable"), test))]
mod debug_sync;
#[cfg(all(feature = "std", not(feature = "_bench_unstable"), test))]
pub use debug_sync::*;

#[cfg(all(feature = "std", any(feature = "_bench_unstable", not(test))))]
pub use ::std::sync::{Arc, Mutex, Condvar, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};
#[cfg(all(feature = "std", any(feature = "_bench_unstable", not(test))))]
pub use crate::util::fairrwlock::FairRwLock;

#[cfg(not(feature = "std"))]
mod nostd_sync;
#[cfg(not(feature = "std"))]
pub use nostd_sync::*;
