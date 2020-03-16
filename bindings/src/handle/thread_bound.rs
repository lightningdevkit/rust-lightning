use std::mem;
use std::panic::{UnwindSafe, RefUnwindSafe};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::marker::PhantomData;
use std::cell::UnsafeCell;
use std::collections::HashMap;
use std::ops::{Deref, DerefMut};

use crate::lazy_static;

type ThreadId = usize;
type ValueId = usize;

static GLOBAL_ID: AtomicUsize = AtomicUsize::new(0);
thread_local!(static THREAD_ID: usize = next_thread_id());

fn next_thread_id() -> usize {
    GLOBAL_ID.fetch_add(1, Ordering::SeqCst)
}

fn get_thread_id() -> usize {
    THREAD_ID.with(|x| *x)
}

thread_local!(static VALUE_ID: UnsafeCell<usize> = UnsafeCell::new(0));

fn next_value_id() -> usize {
    VALUE_ID.with(|x| {
        unsafe_block!("The value never has overlapping mutable aliases" => {
            let x = x.get();
            let next = *x;
            *x += 1;

            next
        })
    })
}

struct Registry(HashMap<ValueId, (UnsafeCell<*mut ()>, Box<dyn Fn(&UnsafeCell<*mut ()>)>)>);

impl Drop for Registry {
    fn drop(&mut self) {
        // Remove this thread from the garbage list
        let thread_id = get_thread_id();
        {
            let mut garbage = GARBAGE.lock().expect("failed to lock garbage queue");
            let _ = garbage.remove(&thread_id);
        }

        // Drop any remaining values in the registry
        for (_, value) in self.0.iter() {
            (value.1)(&value.0);
        }
    }
}

thread_local!(static REGISTRY: UnsafeCell<Registry> = UnsafeCell::new(Registry(Default::default())));

lazy_static! {
    static ref GARBAGE: Mutex<HashMap<ThreadId, Vec<ValueId>>> = Mutex::new(HashMap::new());
}

/**
A value that's bound to the thread it's created on.

In pure rust, `Send` and `Sync` are good enough to protect against data races between threads.
But since this is a compile time contract, nothing stops from foreign caller to copy references to multiple
threads.
To prevent this, ThreadBound checks that it has not been sent across threads at runtime, and panics if it is.
It is pretty much the same to [fragile](https://docs.rs/fragile/1.0.0/fragile/)

This is used for single-threaded handle for an FFI object, i.e. `HandleExclusive`.
*/
pub struct ThreadBound<T: ?Sized> {
    thread_id: ThreadId,
    inner: UnsafeCell<T>,
}

impl<T> ThreadBound<T> {
    pub(super) fn new(inner: T) -> Self {
        ThreadBound {
            thread_id: get_thread_id(),
            inner: UnsafeCell::new(inner),
        }
    }
}

/*
We don't need to check the thread id when moving out of the inner
value so long as the inner value is itself `Send`. This allows
the .NET runtime to potentially finalize a value on another thread.
*/
impl<T: Send> ThreadBound<T> {
    pub(super) fn into_inner(self) -> T {
        self.inner.into_inner()
    }
}

impl<T: ?Sized> ThreadBound<T> {
    fn check(&self) {
        let current = get_thread_id();

        if self.thread_id != current {
            panic!("attempted to access resource from a different thread");
        }
    }

    pub(super) fn get_raw(&self) -> *mut T {
        self.check();
        self.inner.get()
    }
}

impl<T: ?Sized + UnwindSafe> UnwindSafe for ThreadBound<T> {}
impl<T: ?Sized + RefUnwindSafe> RefUnwindSafe for ThreadBound<T> {}

unsafe_impl!("The inner value is safe to send to another thread" => impl<T: ?Sized + Send> Send for ThreadBound<T> {});
unsafe_impl!("The inner value can't actually be accessed concurrently" => impl<T: ?Sized> Sync for ThreadBound<T> {});

/**
A thread-bound value that can be safely dropped from a different thread.

The value is allocated in thread-local storage. When dropping, if the value
is being accessed from a different thread it will be put onto a garbage queue
for cleanup instead of being moved onto the current thread.

NOTE: We require `T: 'static` because the value may live as long
as the current thread
*/
pub(crate) struct DeferredCleanup<T: 'static> {
    thread_id: ThreadId,
    value_id: ValueId,
    _m: PhantomData<*mut T>,
}

impl<T: 'static> Drop for DeferredCleanup<T> {
    fn drop(&mut self) {
        if mem::needs_drop::<T>() {
            if self.is_valid() {
                unsafe_block!("The value exists on the current thread" => {
                    self.into_inner_unchecked();
                });
            } else {
                let mut garbage = GARBAGE.lock().expect("failed to lock garbage queue");
                let garbage = garbage.entry(self.thread_id).or_insert_with(|| Vec::new());

                garbage.push(self.value_id);
            }
        }
    }
}

impl<T: 'static> DeferredCleanup<T> {
    pub fn new(value: T) -> Self {
        let thread_id = get_thread_id();
        let value_id = next_value_id();

        // Check for any garbage that needs cleaning up
        // If we can't acquire a lock to the global queue
        // then we just continue on.
        let garbage = {
            GARBAGE
                .try_lock()
                .ok()
                .and_then(|mut garbage| garbage.remove(&thread_id))
        };

        if let Some(garbage) = garbage {
            let remove = |value_id: ValueId| {
                REGISTRY.with(|registry| {
                    unsafe_block!("The value never has overlapping mutable aliases" => {
                        let registry = &mut (*registry.get()).0;
                        registry.remove(&value_id)
                    })
                })
            };

            for value_id in garbage {
                if let Some((data, drop)) = remove(value_id) {
                    drop(&data);
                }
            }
        }

        REGISTRY.with(|registry| {
            unsafe_block!("The value never has overlapping mutable aliases" => {
                (*registry.get()).0.insert(
                    value_id,
                    (
                        UnsafeCell::new(Box::into_raw(Box::new(value)) as *mut _),
                        Box::new(|cell| {
                            let b: Box<T> = Box::from_raw(*(cell.get() as *mut *mut T));
                            mem::drop(b);
                        }),
                    ),
                );
            })
        });

        DeferredCleanup {
            thread_id,
            value_id,
            _m: PhantomData,
        }
    }

    fn with_value<F: FnOnce(&UnsafeCell<Box<T>>) -> R, R>(&self, f: F) -> R {
        let current_thread = get_thread_id();

        if current_thread != self.thread_id {
            panic!("attempted to access resource from a different thread");
        }

        REGISTRY.with(|registry| {
            unsafe_block!("There are no active mutable references" => {
                let registry = &(*registry.get()).0;

                if let Some(item) = registry.get(&self.value_id) {
                    f(mem::transmute(&item.0))
                } else {
                    panic!("attempted to access resource from a different thread");
                }
            })
        })
    }

    fn is_valid(&self) -> bool {
        let current_thread = get_thread_id();
        let has_value = unsafe_block!("There are no active mutable references" => {
            REGISTRY
                .try_with(|registry| (*registry.get()).0.contains_key(&self.value_id))
                .unwrap_or(false)
        });

        self.thread_id == current_thread && has_value
    }

    unsafe_fn!("The value must originate on the current thread" => fn into_inner_unchecked(&mut self) -> T {
        let ptr = REGISTRY
            .with(|registry| (*registry.get()).0.remove(&self.value_id))
            .unwrap()
            .0
            .into_inner();
        let value = Box::from_raw(ptr as *mut T);
        *value
    });
}

unsafe_impl!(
    "The inner value is pinned to the current thread and isn't actually sent. \
     Dropping from another thread will signal cleanup on the original" =>
    impl<T: 'static> Send for DeferredCleanup<T> {});

impl<T: 'static> Deref for DeferredCleanup<T> {
    type Target = T;

    fn deref(&self) -> &T {
        self.with_value(|value| unsafe_block!("The borrow of self protects the inner value" => { &*value.get() }))
    }
}

impl<T: 'static> DerefMut for DeferredCleanup<T> {
    fn deref_mut(&mut self) -> &mut T {
        self.with_value(|value| unsafe_block!("The borrow of self protects the inner value" => { &mut *value.get() }))
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Arc,
            Mutex,
        },
        thread,
    };

    use super::*;

    struct NeedsDrop(Arc<Mutex<bool>>);

    impl Drop for NeedsDrop {
        fn drop(&mut self) {
            *self.0.lock().expect("failed to lock") = true;
        }
    }

    #[test]
    fn garbage_queue_is_cleaned_when_thread_exits() {
        let dropped = Arc::new(Mutex::new(false));

        let (pre_clean_len, thread_id) = {
            let dropped = dropped.clone();

            thread::spawn(move || {
                let dropped = dropped.clone();

                let deferred = DeferredCleanup::new(NeedsDrop(dropped.clone()));
                let thread_id = get_thread_id();

                // Move the deferred into another thread
                // This will signal that it needs to be dropped
                thread::spawn(move || {
                    drop(deferred);
                })
                .join()
                .expect("failed to run inner thread");

                // Ensure the value hasn't been dropped yet
                {
                    assert!(!*dropped.lock().expect("failed to lock"));
                }

                // Ensure we have garbage in the queue
                let pre_clean_len = {
                    let garbage = GARBAGE.lock().expect("failed to lock garbage");
                    garbage.get(&thread_id).map(|queue| queue.len())
                };

                (pre_clean_len, thread_id)
            })
            .join()
            .expect("failed to run thread")
        };

        // Ensure the garbage has been cleaned
        {
            assert!(*dropped.lock().expect("failed to lock"));
        }

        // Ensure we had some garbage to clean
        assert_eq!(Some(1), pre_clean_len);

        // Ensure the queue for the thread is now gone
        let len = {
            let garbage = GARBAGE.lock().expect("failed to lock garbage");
            garbage.get(&thread_id).map(|queue| queue.len())
        };

        assert_eq!(None, len);
    }
}