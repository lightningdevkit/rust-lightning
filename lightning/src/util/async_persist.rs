use ::futures::task::noop_waker;
use futures_timer::Delay;
use tokio::runtime::Runtime;
use std::future::Future;
use std::task::{Context, Poll};
use std::time::Duration;

#[derive(Debug)]
pub enum UpdateStatus {
    Completed,
    InProgress,
}

// Use this boolean to control whether the store operation is async or sync.
const ASYNC_STORE: bool = true;

// Simulate an async store operation.
async fn store() {
    if ASYNC_STORE {
        Delay::new(Duration::from_secs(1)).await;
    } else {
        std::thread::sleep(Duration::from_secs(1));
    }

    println!("Stored data...");
}

struct AsyncKVStoreWrapper {
    runtime: Runtime,
}

impl AsyncKVStoreWrapper {
    fn store<F>(&self, callback: F) -> UpdateStatus
    where
        F: FnOnce() + Send + 'static,
    {
        let mut fut = Box::pin(store());

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        match fut.as_mut().poll(&mut cx) {
            Poll::Ready(_) => {
                UpdateStatus::Completed
            }
            Poll::Pending => {
                println!("Future not ready, using tokio runtime");

                self.runtime.spawn(async move {
                    fut.await;
                    callback();
                });

                UpdateStatus::InProgress
            }
        }
    }
}

fn main() {
    let async_kv_store = AsyncKVStoreWrapper {
        runtime: Runtime::new().unwrap(),
    };

    let status = async_kv_store.store(|| {
        println!("Callback: Store operation completed!");

        // Call channel_monitor_updated here.
    });

    println!("Store status: {:?}", status);

    // Sleep to give async task time to complete before main exits
    std::thread::sleep(Duration::from_secs(2));
}
