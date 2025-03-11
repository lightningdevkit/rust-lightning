use super::LiquidityEvent;
use crate::sync::{Arc, Mutex};
use alloc::collections::VecDeque;
use alloc::vec::Vec;

use core::future::Future;
use core::task::{Poll, Waker};

/// The maximum queue size we allow before starting to drop events.
pub const MAX_EVENT_QUEUE_SIZE: usize = 1000;

pub(crate) struct EventQueue {
	queue: Arc<Mutex<VecDeque<LiquidityEvent>>>,
	waker: Arc<Mutex<Option<Waker>>>,
	#[cfg(feature = "std")]
	condvar: Arc<crate::sync::Condvar>,
}

impl EventQueue {
	pub fn new() -> Self {
		let queue = Arc::new(Mutex::new(VecDeque::new()));
		let waker = Arc::new(Mutex::new(None));
		Self {
			queue,
			waker,
			#[cfg(feature = "std")]
			condvar: Arc::new(crate::sync::Condvar::new()),
		}
	}

	pub fn next_event(&self) -> Option<LiquidityEvent> {
		self.queue.lock().unwrap().pop_front()
	}

	pub async fn next_event_async(&self) -> LiquidityEvent {
		EventFuture { event_queue: Arc::clone(&self.queue), waker: Arc::clone(&self.waker) }.await
	}

	#[cfg(feature = "std")]
	pub fn wait_next_event(&self) -> LiquidityEvent {
		let mut queue = self
			.condvar
			.wait_while(self.queue.lock().unwrap(), |queue: &mut VecDeque<LiquidityEvent>| {
				queue.is_empty()
			})
			.unwrap();

		let event = queue.pop_front().expect("non-empty queue");
		let should_notify = !queue.is_empty();

		drop(queue);

		if should_notify {
			if let Some(waker) = self.waker.lock().unwrap().take() {
				waker.wake();
			}

			self.condvar.notify_one();
		}

		event
	}

	pub fn get_and_clear_pending_events(&self) -> Vec<LiquidityEvent> {
		self.queue.lock().unwrap().split_off(0).into()
	}

	// Returns an [`EventQueueNotifierGuard`] that will notify about new event when dropped.
	pub fn notifier(&self) -> EventQueueNotifierGuard {
		EventQueueNotifierGuard(self)
	}
}

// A guard type that will notify about new events when dropped.
#[must_use]
pub(crate) struct EventQueueNotifierGuard<'a>(&'a EventQueue);

impl<'a> EventQueueNotifierGuard<'a> {
	pub fn enqueue<E: Into<LiquidityEvent>>(&self, event: E) {
		let mut queue = self.0.queue.lock().unwrap();
		if queue.len() < MAX_EVENT_QUEUE_SIZE {
			queue.push_back(event.into());
		} else {
			return;
		}
	}
}

impl<'a> Drop for EventQueueNotifierGuard<'a> {
	fn drop(&mut self) {
		let should_notify = !self.0.queue.lock().unwrap().is_empty();

		if should_notify {
			if let Some(waker) = self.0.waker.lock().unwrap().take() {
				waker.wake();
			}

			#[cfg(feature = "std")]
			self.0.condvar.notify_one();
		}
	}
}

struct EventFuture {
	event_queue: Arc<Mutex<VecDeque<LiquidityEvent>>>,
	waker: Arc<Mutex<Option<Waker>>>,
}

impl Future for EventFuture {
	type Output = LiquidityEvent;

	fn poll(
		self: core::pin::Pin<&mut Self>, cx: &mut core::task::Context<'_>,
	) -> core::task::Poll<Self::Output> {
		if let Some(event) = self.event_queue.lock().unwrap().pop_front() {
			Poll::Ready(event)
		} else {
			*self.waker.lock().unwrap() = Some(cx.waker().clone());
			Poll::Pending
		}
	}
}

#[cfg(test)]
mod tests {
	#[tokio::test]
	#[cfg(feature = "std")]
	async fn event_queue_works() {
		use super::*;
		use crate::lsps0::event::LSPS0ClientEvent;
		use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
		use core::sync::atomic::{AtomicU16, Ordering};
		use std::sync::Arc;
		use std::time::Duration;

		let event_queue = Arc::new(EventQueue::new());
		assert_eq!(event_queue.next_event(), None);

		let secp_ctx = Secp256k1::new();
		let counterparty_node_id =
			PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[42; 32]).unwrap());
		let expected_event = LiquidityEvent::LSPS0Client(LSPS0ClientEvent::ListProtocolsResponse {
			counterparty_node_id,
			protocols: Vec::new(),
		});

		for _ in 0..3 {
			let guard = event_queue.notifier();
			guard.enqueue(expected_event.clone());
		}

		assert_eq!(event_queue.wait_next_event(), expected_event);
		assert_eq!(event_queue.next_event_async().await, expected_event);
		assert_eq!(event_queue.next_event(), Some(expected_event.clone()));
		assert_eq!(event_queue.next_event(), None);

		// Check `next_event_async` won't return if the queue is empty and always rather timeout.
		tokio::select! {
			_ = tokio::time::sleep(Duration::from_millis(10)) => {
				// Timeout
			}
			_ = event_queue.next_event_async() => {
				panic!();
			}
		}
		assert_eq!(event_queue.next_event(), None);

		// Check we get the expected number of events when polling/enqueuing concurrently.
		let enqueued_events = AtomicU16::new(0);
		let received_events = AtomicU16::new(0);
		let mut delayed_enqueue = false;

		for _ in 0..25 {
			let guard = event_queue.notifier();
			guard.enqueue(expected_event.clone());
			enqueued_events.fetch_add(1, Ordering::SeqCst);
		}

		loop {
			tokio::select! {
				_ = tokio::time::sleep(Duration::from_millis(10)), if !delayed_enqueue => {
					let guard = event_queue.notifier();
					guard.enqueue(expected_event.clone());
					enqueued_events.fetch_add(1, Ordering::SeqCst);
					delayed_enqueue = true;
				}
				e = event_queue.next_event_async() => {
					assert_eq!(e, expected_event);
					received_events.fetch_add(1, Ordering::SeqCst);

					let guard = event_queue.notifier();
					guard.enqueue(expected_event.clone());
					enqueued_events.fetch_add(1, Ordering::SeqCst);
				}
				e = event_queue.next_event_async() => {
					assert_eq!(e, expected_event);
					received_events.fetch_add(1, Ordering::SeqCst);
				}
			}

			if delayed_enqueue
				&& received_events.load(Ordering::SeqCst) == enqueued_events.load(Ordering::SeqCst)
			{
				break;
			}
		}
		assert_eq!(event_queue.next_event(), None);

		// Check we operate correctly, even when mixing and matching blocking and async API calls.
		let (tx, mut rx) = tokio::sync::watch::channel(());
		let thread_queue = Arc::clone(&event_queue);
		let thread_event = expected_event.clone();
		std::thread::spawn(move || {
			let e = thread_queue.wait_next_event();
			assert_eq!(e, thread_event);
			tx.send(()).unwrap();
		});

		let thread_queue = Arc::clone(&event_queue);
		let thread_event = expected_event.clone();
		std::thread::spawn(move || {
			// Sleep a bit before we enqueue the events everybody is waiting for.
			std::thread::sleep(Duration::from_millis(20));
			let guard = thread_queue.notifier();
			guard.enqueue(thread_event.clone());
			guard.enqueue(thread_event.clone());
		});

		let e = event_queue.next_event_async().await;
		assert_eq!(e, expected_event.clone());

		rx.changed().await.unwrap();
		assert_eq!(event_queue.next_event(), None);
	}
}
