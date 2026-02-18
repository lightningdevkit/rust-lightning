// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! This module provides synchronous wrappers around [`BumpTransactionEventHandler`] and related types.

use core::future::Future;
use core::ops::Deref;
use core::pin::pin;
use core::task;

use crate::chain::chaininterface::BroadcasterInterface;
use crate::sign::SignerProvider;
use crate::util::async_poll::dummy_waker;
use crate::util::logger::Logger;
use crate::util::wallet_utils::{CoinSelectionSourceSync, CoinSelectionSourceSyncWrapper};

use super::{BumpTransactionEvent, BumpTransactionEventHandler};

/// A handler for [`Event::BumpTransaction`] events that sources confirmed UTXOs from a
/// [`CoinSelectionSourceSync`] to fee bump transactions via Child-Pays-For-Parent (CPFP) or
/// Replace-By-Fee (RBF).
///
/// For an asynchronous version of this handler, see [`BumpTransactionEventHandler`].
///
/// [`Event::BumpTransaction`]: crate::events::Event::BumpTransaction
// Note that updates to documentation on this struct should be copied to the synchronous version.
pub struct BumpTransactionEventHandlerSync<
	B: BroadcasterInterface,
	C: Deref,
	SP: SignerProvider,
	L: Logger,
> where
	C::Target: CoinSelectionSourceSync,
{
	bump_transaction_event_handler:
		BumpTransactionEventHandler<B, CoinSelectionSourceSyncWrapper<C>, SP, L>,
}

impl<B: BroadcasterInterface, C: Deref, SP: SignerProvider, L: Logger>
	BumpTransactionEventHandlerSync<B, C, SP, L>
where
	C::Target: CoinSelectionSourceSync,
{
	/// Constructs a new instance of [`BumpTransactionEventHandlerSync`].
	pub fn new(broadcaster: B, utxo_source: C, signer_provider: SP, logger: L) -> Self {
		let bump_transaction_event_handler = BumpTransactionEventHandler::new(
			broadcaster,
			CoinSelectionSourceSyncWrapper(utxo_source),
			signer_provider,
			logger,
		);
		Self { bump_transaction_event_handler }
	}

	/// Handles all variants of [`BumpTransactionEvent`].
	pub fn handle_event(&self, event: &BumpTransactionEvent) {
		let mut fut = pin!(self.bump_transaction_event_handler.handle_event(event));
		let mut waker = dummy_waker();
		let mut ctx = task::Context::from_waker(&mut waker);
		match fut.as_mut().poll(&mut ctx) {
			task::Poll::Ready(result) => result,
			task::Poll::Pending => {
				// In a sync context, we can't wait for the future to complete.
				unreachable!("BumpTransactionEventHandlerSync::handle_event should not be pending in a sync context");
			},
		}
	}
}
