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
use core::task;

use crate::chain::chaininterface::BroadcasterInterface;
use crate::chain::ClaimId;
use crate::prelude::*;
use crate::sign::SignerProvider;
use crate::util::async_poll::{dummy_waker, AsyncResult, MaybeSend, MaybeSync};
use crate::util::logger::Logger;

use bitcoin::{Psbt, ScriptBuf, Transaction, TxOut};

use super::BumpTransactionEvent;
use super::{
	BumpTransactionEventHandler, CoinSelection, CoinSelectionSource, Input, Utxo, Wallet,
	WalletSource,
};

/// A synchronous version of the [`WalletSource`] trait.
pub trait WalletSourceSync {
	/// A synchronous version of [`WalletSource::list_confirmed_utxos`].
	fn list_confirmed_utxos(&self) -> Result<Vec<Utxo>, ()>;
	/// A synchronous version of [`WalletSource::get_change_script`].
	fn get_change_script(&self) -> Result<ScriptBuf, ()>;
	/// A Synchronous version of [`WalletSource::sign_psbt`].
	fn sign_psbt(&self, psbt: Psbt) -> Result<Transaction, ()>;
}

pub(crate) struct WalletSourceSyncWrapper<T: Deref>(T)
where
	T::Target: WalletSourceSync;

// Implement `Deref` directly on WalletSourceSyncWrapper so that it can be used directly
// below, rather than via a wrapper.
impl<T: Deref> Deref for WalletSourceSyncWrapper<T>
where
	T::Target: WalletSourceSync,
{
	type Target = Self;
	fn deref(&self) -> &Self {
		self
	}
}

impl<T: Deref> WalletSource for WalletSourceSyncWrapper<T>
where
	T::Target: WalletSourceSync,
{
	fn list_confirmed_utxos<'a>(&'a self) -> AsyncResult<'a, Vec<Utxo>> {
		let utxos = self.0.list_confirmed_utxos();
		Box::pin(async move { utxos })
	}

	fn get_change_script<'a>(&'a self) -> AsyncResult<'a, ScriptBuf> {
		let script = self.0.get_change_script();
		Box::pin(async move { script })
	}

	fn sign_psbt<'a>(&'a self, psbt: Psbt) -> AsyncResult<'a, Transaction> {
		let signed_psbt = self.0.sign_psbt(psbt);
		Box::pin(async move { signed_psbt })
	}
}

/// A synchronous wrapper around [`Wallet`] to be used in contexts where async is not available.
pub struct WalletSync<W: Deref + MaybeSync + MaybeSend, L: Deref + MaybeSync + MaybeSend>
where
	W::Target: WalletSourceSync + MaybeSend,
	L::Target: Logger + MaybeSend,
{
	wallet: Wallet<WalletSourceSyncWrapper<W>, L>,
}

impl<W: Deref + MaybeSync + MaybeSend, L: Deref + MaybeSync + MaybeSend> WalletSync<W, L>
where
	W::Target: WalletSourceSync + MaybeSend,
	L::Target: Logger + MaybeSend,
{
	/// Constructs a new [`WalletSync`] instance.
	pub fn new(source: W, logger: L) -> Self {
		Self { wallet: Wallet::new(WalletSourceSyncWrapper(source), logger) }
	}
}

impl<W: Deref + MaybeSync + MaybeSend, L: Deref + MaybeSync + MaybeSend> CoinSelectionSourceSync
	for WalletSync<W, L>
where
	W::Target: WalletSourceSync + MaybeSend + MaybeSync,
	L::Target: Logger + MaybeSend + MaybeSync,
{
	fn select_confirmed_utxos(
		&self, claim_id: ClaimId, must_spend: Vec<Input>, must_pay_to: &[TxOut],
		target_feerate_sat_per_1000_weight: u32,
	) -> Result<CoinSelection, ()> {
		let mut fut = self.wallet.select_confirmed_utxos(
			claim_id,
			must_spend,
			must_pay_to,
			target_feerate_sat_per_1000_weight,
		);
		let mut waker = dummy_waker();
		let mut ctx = task::Context::from_waker(&mut waker);
		match fut.as_mut().poll(&mut ctx) {
			task::Poll::Ready(result) => result,
			task::Poll::Pending => {
				unreachable!(
					"Wallet::select_confirmed_utxos should not be pending in a sync context"
				);
			},
		}
	}

	fn sign_psbt(&self, psbt: Psbt) -> Result<Transaction, ()> {
		let mut fut = self.wallet.sign_psbt(psbt);
		let mut waker = dummy_waker();
		let mut ctx = task::Context::from_waker(&mut waker);
		match fut.as_mut().poll(&mut ctx) {
			task::Poll::Ready(result) => result,
			task::Poll::Pending => {
				unreachable!("Wallet::sign_psbt should not be pending in a sync context");
			},
		}
	}
}

/// A synchronous version of the [`CoinSelectionSource`] trait.
pub trait CoinSelectionSourceSync {
	/// A synchronous version of [`CoinSelectionSource::select_confirmed_utxos`].
	fn select_confirmed_utxos(
		&self, claim_id: ClaimId, must_spend: Vec<Input>, must_pay_to: &[TxOut],
		target_feerate_sat_per_1000_weight: u32,
	) -> Result<CoinSelection, ()>;

	/// A synchronous version of [`CoinSelectionSource::sign_psbt`].
	fn sign_psbt(&self, psbt: Psbt) -> Result<Transaction, ()>;
}

struct CoinSelectionSourceSyncWrapper<T: Deref>(T)
where
	T::Target: CoinSelectionSourceSync;

// Implement `Deref` directly on CoinSelectionSourceSyncWrapper so that it can be used directly
// below, rather than via a wrapper.
impl<T: Deref> Deref for CoinSelectionSourceSyncWrapper<T>
where
	T::Target: CoinSelectionSourceSync,
{
	type Target = Self;
	fn deref(&self) -> &Self {
		self
	}
}

impl<T: Deref> CoinSelectionSource for CoinSelectionSourceSyncWrapper<T>
where
	T::Target: CoinSelectionSourceSync,
{
	fn select_confirmed_utxos<'a>(
		&'a self, claim_id: ClaimId, must_spend: Vec<Input>, must_pay_to: &'a [TxOut],
		target_feerate_sat_per_1000_weight: u32,
	) -> AsyncResult<'a, CoinSelection> {
		let coins = self.0.select_confirmed_utxos(
			claim_id,
			must_spend,
			must_pay_to,
			target_feerate_sat_per_1000_weight,
		);
		Box::pin(async move { coins })
	}

	fn sign_psbt<'a>(&'a self, psbt: Psbt) -> AsyncResult<'a, Transaction> {
		let psbt = self.0.sign_psbt(psbt);
		Box::pin(async move { psbt })
	}
}

/// A synchronous wrapper around [`BumpTransactionEventHandler`] to be used in contexts where async is not available.
pub struct BumpTransactionEventHandlerSync<B: Deref, C: Deref, SP: Deref, L: Deref>
where
	B::Target: BroadcasterInterface,
	C::Target: CoinSelectionSourceSync,
	SP::Target: SignerProvider,
	L::Target: Logger,
{
	bump_transaction_event_handler:
		BumpTransactionEventHandler<B, CoinSelectionSourceSyncWrapper<C>, SP, L>,
}

impl<B: Deref, C: Deref, SP: Deref, L: Deref> BumpTransactionEventHandlerSync<B, C, SP, L>
where
	B::Target: BroadcasterInterface,
	C::Target: CoinSelectionSourceSync,
	SP::Target: SignerProvider,
	L::Target: Logger,
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
		let mut fut = Box::pin(self.bump_transaction_event_handler.handle_event(event));
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
