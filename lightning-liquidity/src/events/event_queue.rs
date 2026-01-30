use super::LiquidityEvent;

use crate::lsps2::event::LSPS2ServiceEvent;
use crate::persist::{
	LIQUIDITY_MANAGER_EVENT_QUEUE_PERSISTENCE_KEY,
	LIQUIDITY_MANAGER_EVENT_QUEUE_PERSISTENCE_SECONDARY_NAMESPACE,
	LIQUIDITY_MANAGER_PERSISTENCE_PRIMARY_NAMESPACE,
};
use crate::sync::{Arc, Mutex};

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use core::future::Future;
use core::task::{Poll, Waker};

use lightning::ln::msgs::DecodeError;
use lightning::util::persist::KVStore;
use lightning::util::ser::{
	BigSize, CollectionLength, FixedLengthReader, Readable, Writeable, Writer,
};
use lightning::util::wakers::Notifier;

/// The maximum queue size we allow before starting to drop events.
pub const MAX_EVENT_QUEUE_SIZE: usize = 1000;

pub(crate) struct EventQueue<K: KVStore + Clone> {
	state: Mutex<QueueState>,
	waker: Mutex<Option<Waker>>,
	#[cfg(feature = "std")]
	condvar: crate::sync::Condvar,
	kv_store: K,
	persist_notifier: Arc<Notifier>,
}

impl<K: KVStore + Clone> EventQueue<K> {
	pub fn new(
		queue: VecDeque<LiquidityEvent>, kv_store: K, persist_notifier: Arc<Notifier>,
	) -> Self {
		let state = Mutex::new(QueueState { queue, needs_persist: false });
		let waker = Mutex::new(None);
		Self {
			state,
			waker,
			#[cfg(feature = "std")]
			condvar: crate::sync::Condvar::new(),
			kv_store,
			persist_notifier,
		}
	}

	pub fn next_event(&self) -> Option<LiquidityEvent> {
		let event_opt = {
			let mut state_lock = self.state.lock().unwrap();
			if state_lock.queue.is_empty() {
				// Skip notifying below if nothing changed.
				return None;
			}

			state_lock.needs_persist = true;
			state_lock.queue.pop_front()
		};

		self.persist_notifier.notify();

		event_opt
	}

	pub async fn next_event_async(&self) -> LiquidityEvent {
		EventFuture(self).await
	}

	#[cfg(feature = "std")]
	pub fn wait_next_event(&self) -> LiquidityEvent {
		let mut state_lock = self
			.condvar
			.wait_while(self.state.lock().unwrap(), |state_lock: &mut QueueState| {
				state_lock.queue.is_empty()
			})
			.unwrap();

		let event = state_lock.queue.pop_front().expect("non-empty queue");
		let should_notify = !state_lock.queue.is_empty();
		state_lock.needs_persist = true;

		drop(state_lock);

		if should_notify {
			if let Some(waker) = self.waker.lock().unwrap().take() {
				waker.wake();
			}

			self.condvar.notify_one();
		}

		self.persist_notifier.notify();

		event
	}

	pub fn get_and_clear_pending_events(&self) -> Vec<LiquidityEvent> {
		let mut state_lock = self.state.lock().unwrap();

		let needs_persist = !state_lock.queue.is_empty();
		let events = state_lock.queue.split_off(0).into();

		if needs_persist {
			state_lock.needs_persist = true;
		}

		drop(state_lock);

		if needs_persist {
			self.persist_notifier.notify();
		}

		events
	}

	// Returns an [`EventQueueNotifierGuard`] that will notify about new event when dropped.
	pub fn notifier(&self) -> EventQueueNotifierGuard<'_, K> {
		EventQueueNotifierGuard(self)
	}

	pub async fn persist(&self) -> Result<bool, lightning::io::Error> {
		let fut = {
			let mut state_lock = self.state.lock().unwrap();

			if !state_lock.needs_persist {
				return Ok(false);
			}

			state_lock.needs_persist = false;
			let encoded = EventQueueSerWrapper(&state_lock.queue).encode();

			self.kv_store.write(
				LIQUIDITY_MANAGER_PERSISTENCE_PRIMARY_NAMESPACE,
				LIQUIDITY_MANAGER_EVENT_QUEUE_PERSISTENCE_SECONDARY_NAMESPACE,
				LIQUIDITY_MANAGER_EVENT_QUEUE_PERSISTENCE_KEY,
				encoded,
			)
		};

		fut.await.map_err(|e| {
			self.state.lock().unwrap().needs_persist = true;
			e
		})?;

		Ok(true)
	}
}

struct QueueState {
	queue: VecDeque<LiquidityEvent>,
	needs_persist: bool,
}

// A guard type that will notify about new events when dropped.
#[must_use]
pub(crate) struct EventQueueNotifierGuard<'a, K: KVStore + Clone>(&'a EventQueue<K>);

impl<'a, K: KVStore + Clone> EventQueueNotifierGuard<'a, K> {
	pub fn enqueue<E: Into<LiquidityEvent>>(&self, event: E) {
		let mut state_lock = self.0.state.lock().unwrap();
		if state_lock.queue.len() < MAX_EVENT_QUEUE_SIZE {
			state_lock.queue.push_back(event.into());
			state_lock.needs_persist = true;
		} else {
			return;
		}
	}
}

impl<'a, K: KVStore + Clone> Drop for EventQueueNotifierGuard<'a, K> {
	fn drop(&mut self) {
		let (should_notify, should_persist_notify) = {
			let state_lock = self.0.state.lock().unwrap();
			(!state_lock.queue.is_empty(), state_lock.needs_persist)
		};

		if should_notify {
			if let Some(waker) = self.0.waker.lock().unwrap().take() {
				waker.wake();
			}

			#[cfg(feature = "std")]
			self.0.condvar.notify_one();
		}

		if should_persist_notify {
			self.0.persist_notifier.notify();
		}
	}
}

struct EventFuture<'a, K: KVStore + Clone>(&'a EventQueue<K>);

impl<K: KVStore + Clone> Future for EventFuture<'_, K> {
	type Output = LiquidityEvent;

	fn poll(
		self: core::pin::Pin<&mut Self>, cx: &mut core::task::Context<'_>,
	) -> core::task::Poll<Self::Output> {
		let (res, should_persist_notify) = {
			let mut state_lock = self.0.state.lock().unwrap();
			if let Some(event) = state_lock.queue.pop_front() {
				state_lock.needs_persist = true;
				(Poll::Ready(event), true)
			} else {
				*self.0.waker.lock().unwrap() = Some(cx.waker().clone());
				(Poll::Pending, false)
			}
		};

		if should_persist_notify {
			self.0.persist_notifier.notify();
		}

		res
	}
}

pub(crate) struct EventQueueDeserWrapper(pub VecDeque<LiquidityEvent>);

impl Readable for EventQueueDeserWrapper {
	fn read<R: lightning::io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
		let len: CollectionLength = Readable::read(reader)?;
		let mut queue = VecDeque::with_capacity(len.0 as usize);
		for _ in 0..len.0 {
			let event = match Readable::read(reader)? {
				0u8 => {
					let ev = Readable::read(reader)?;
					LiquidityEvent::LSPS2Service(ev)
				},
				2u8 => {
					let ev = Readable::read(reader)?;
					LiquidityEvent::LSPS5Service(ev)
				},
				x if x % 2 == 1 => {
					// If the event is of unknown type, assume it was written with `write_tlv_fields`,
					// which prefixes the whole thing with a length BigSize. Because the event is
					// odd-type unknown, we should treat it as `Ok(None)` even if it has some TLV
					// fields that are even. Thus, we avoid using `read_tlv_fields` and simply read
					// exactly the number of bytes specified, ignoring them entirely.
					let tlv_len: BigSize = Readable::read(reader)?;
					FixedLengthReader::new(reader, tlv_len.0)
						.eat_remaining()
						.map_err(|_| DecodeError::ShortRead)?;
					continue;
				},
				_ => return Err(DecodeError::InvalidValue),
			};
			queue.push_back(event);
		}
		Ok(Self(queue))
	}
}

struct EventQueueSerWrapper<'a>(&'a VecDeque<LiquidityEvent>);

impl Writeable for EventQueueSerWrapper<'_> {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), lightning::io::Error> {
		let maybe_process_event = |event: &LiquidityEvent,
		                           writer: Option<&mut W>|
		 -> Result<bool, lightning::io::Error> {
			match event {
				LiquidityEvent::LSPS2Service(event) => {
					if matches!(event, LSPS2ServiceEvent::GetInfo { .. })
						|| matches!(event, LSPS2ServiceEvent::BuyRequest { .. })
					{
						// Skip persisting GetInfoRequest and BuyRequest events as we prune the pending
						// request state currently anyways.
						Ok(false)
					} else {
						if let Some(writer) = writer {
							0u8.write(writer)?;
							event.write(writer)?;
						}
						Ok(true)
					}
				},
				LiquidityEvent::LSPS5Service(event) => {
					if let Some(writer) = writer {
						2u8.write(writer)?;
						event.write(writer)?;
					}
					Ok(true)
				},
				_ => Ok(false),
			}
		};

		let mut persisted_events_len = 0;
		for e in self.0.iter() {
			if maybe_process_event(e, None)? {
				persisted_events_len += 1;
			}
		}

		CollectionLength(persisted_events_len).write(writer)?;
		for e in self.0.iter() {
			maybe_process_event(e, Some(writer))?;
		}
		Ok(())
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
		use lightning::util::persist::KVStoreSyncWrapper;
		use lightning::util::test_utils::TestStore;
		use std::sync::Arc;
		use std::time::Duration;

		let kv_store = Arc::new(KVStoreSyncWrapper(Arc::new(TestStore::new(false))));
		let persist_notifier = Arc::new(Notifier::new());
		let event_queue = Arc::new(EventQueue::new(VecDeque::new(), kv_store, persist_notifier));
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
