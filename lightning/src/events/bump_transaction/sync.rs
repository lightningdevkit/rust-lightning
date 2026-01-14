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
use crate::chain::ClaimId;
use crate::prelude::*;
use crate::sign::SignerProvider;
use crate::util::async_poll::{dummy_waker, MaybeSend, MaybeSync};
use crate::util::logger::Logger;

use bitcoin::{OutPoint, Psbt, ScriptBuf, Transaction, TxOut};

use super::BumpTransactionEvent;
use super::{
	BumpTransactionEventHandler, CoinSelection, CoinSelectionSource, Input, Utxo, Wallet,
	WalletSource,
};

/// An alternative to [`CoinSelectionSourceSync`] that can be implemented and used along
/// [`WalletSync`] to provide a default implementation to [`CoinSelectionSourceSync`].
///
/// For an asynchronous version of this trait, see [`WalletSource`].
// Note that updates to documentation on this trait should be copied to the asynchronous version.
pub trait WalletSourceSync {
	/// Returns all UTXOs, with at least 1 confirmation each, that are available to spend.
	fn list_confirmed_utxos(&self) -> Result<Vec<Utxo>, ()>;

	/// Returns the previous transaction containing the UTXO referenced by the outpoint.
	fn get_prevtx(&self, outpoint: OutPoint) -> Result<Transaction, ()>;

	/// Returns a script to use for change above dust resulting from a successful coin selection
	/// attempt.
	fn get_change_script(&self) -> Result<ScriptBuf, ()>;

	/// Signs and provides the full [`TxIn::script_sig`] and [`TxIn::witness`] for all inputs within
	/// the transaction known to the wallet (i.e., any provided via
	/// [`WalletSource::list_confirmed_utxos`]).
	///
	/// If your wallet does not support signing PSBTs you can call `psbt.extract_tx()` to get the
	/// unsigned transaction and then sign it with your wallet.
	///
	/// [`TxIn::script_sig`]: bitcoin::TxIn::script_sig
	/// [`TxIn::witness`]: bitcoin::TxIn::witness
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
	fn list_confirmed_utxos<'a>(
		&'a self,
	) -> impl Future<Output = Result<Vec<Utxo>, ()>> + MaybeSend + 'a {
		let utxos = self.0.list_confirmed_utxos();
		async move { utxos }
	}

	fn get_prevtx<'a>(
		&'a self, outpoint: OutPoint,
	) -> impl Future<Output = Result<Transaction, ()>> + MaybeSend + 'a {
		let prevtx = self.0.get_prevtx(outpoint);
		Box::pin(async move { prevtx })
	}

	fn get_change_script<'a>(
		&'a self,
	) -> impl Future<Output = Result<ScriptBuf, ()>> + MaybeSend + 'a {
		let script = self.0.get_change_script();
		async move { script }
	}

	fn sign_psbt<'a>(
		&'a self, psbt: Psbt,
	) -> impl Future<Output = Result<Transaction, ()>> + MaybeSend + 'a {
		let signed_psbt = self.0.sign_psbt(psbt);
		async move { signed_psbt }
	}
}

/// A wrapper over [`WalletSourceSync`] that implements [`CoinSelectionSourceSync`] by preferring
/// UTXOs that would avoid conflicting double spends. If not enough UTXOs are available to do so,
/// conflicting double spends may happen.
///
/// For an asynchronous version of this wrapper, see [`Wallet`].
// Note that updates to documentation on this struct should be copied to the asynchronous version.
pub struct WalletSync<W: Deref + MaybeSync + MaybeSend, L: Logger + MaybeSync + MaybeSend>
where
	W::Target: WalletSourceSync + MaybeSend,
{
	wallet: Wallet<WalletSourceSyncWrapper<W>, L>,
}

impl<W: Deref + MaybeSync + MaybeSend, L: Logger + MaybeSync + MaybeSend> WalletSync<W, L>
where
	W::Target: WalletSourceSync + MaybeSend,
{
	/// Constructs a new [`WalletSync`] instance.
	pub fn new(source: W, logger: L) -> Self {
		Self { wallet: Wallet::new(WalletSourceSyncWrapper(source), logger) }
	}
}

impl<W: Deref + MaybeSync + MaybeSend, L: Logger + MaybeSync + MaybeSend> CoinSelectionSourceSync
	for WalletSync<W, L>
where
	W::Target: WalletSourceSync + MaybeSend + MaybeSync,
{
	fn select_confirmed_utxos(
		&self, claim_id: ClaimId, must_spend: Vec<Input>, must_pay_to: &[TxOut],
		target_feerate_sat_per_1000_weight: u32, max_tx_weight: u64,
	) -> Result<CoinSelection, ()> {
		let fut = self.wallet.select_confirmed_utxos(
			claim_id,
			must_spend,
			must_pay_to,
			target_feerate_sat_per_1000_weight,
			max_tx_weight,
		);
		let mut waker = dummy_waker();
		let mut ctx = task::Context::from_waker(&mut waker);
		match pin!(fut).poll(&mut ctx) {
			task::Poll::Ready(result) => result,
			task::Poll::Pending => {
				unreachable!(
					"Wallet::select_confirmed_utxos should not be pending in a sync context"
				);
			},
		}
	}

	fn sign_psbt(&self, psbt: Psbt) -> Result<Transaction, ()> {
		let fut = self.wallet.sign_psbt(psbt);
		let mut waker = dummy_waker();
		let mut ctx = task::Context::from_waker(&mut waker);
		match pin!(fut).poll(&mut ctx) {
			task::Poll::Ready(result) => result,
			task::Poll::Pending => {
				unreachable!("Wallet::sign_psbt should not be pending in a sync context");
			},
		}
	}
}

/// An abstraction over a bitcoin wallet that can perform coin selection over a set of UTXOs and can
/// sign for them. The coin selection method aims to mimic Bitcoin Core's `fundrawtransaction` RPC,
/// which most wallets should be able to satisfy. Otherwise, consider implementing
/// [`WalletSourceSync`], which can provide a default implementation of this trait when used with
/// [`WalletSync`].
///
/// For an asynchronous version of this trait, see [`CoinSelectionSource`].
// Note that updates to documentation on this trait should be copied to the asynchronous version.
pub trait CoinSelectionSourceSync {
	/// Performs coin selection of a set of UTXOs, with at least 1 confirmation each, that are
	/// available to spend. Implementations are free to pick their coin selection algorithm of
	/// choice, as long as the following requirements are met:
	///
	/// 1. `must_spend` contains a set of [`Input`]s that must be included in the transaction
	///    throughout coin selection, but must not be returned as part of the result.
	/// 2. `must_pay_to` contains a set of [`TxOut`]s that must be included in the transaction
	///    throughout coin selection. In some cases, like when funding an anchor transaction, this
	///    set is empty. Implementations should ensure they handle this correctly on their end,
	///    e.g., Bitcoin Core's `fundrawtransaction` RPC requires at least one output to be
	///    provided, in which case a zero-value empty OP_RETURN output can be used instead.
	/// 3. Enough inputs must be selected/contributed for the resulting transaction (including the
	///    inputs and outputs noted above) to meet `target_feerate_sat_per_1000_weight`.
	/// 4. The final transaction must have a weight smaller than `max_tx_weight`; if this
	///    constraint can't be met, return an `Err`. In the case of counterparty-signed HTLC
	///    transactions, we will remove a chunk of HTLCs and try your algorithm again. As for
	///    anchor transactions, we will try your coin selection again with the same input-output
	///    set when you call [`ChannelMonitor::rebroadcast_pending_claims`], as anchor transactions
	///    cannot be downsized.
	///
	/// Implementations must take note that [`Input::satisfaction_weight`] only tracks the weight of
	/// the input's `script_sig` and `witness`. Some wallets, like Bitcoin Core's, may require
	/// providing the full input weight. Failing to do so may lead to underestimating fee bumps and
	/// delaying block inclusion.
	///
	/// The `claim_id` must map to the set of external UTXOs assigned to the claim, such that they
	/// can be re-used within new fee-bumped iterations of the original claiming transaction,
	/// ensuring that claims don't double spend each other. If a specific `claim_id` has never had a
	/// transaction associated with it, and all of the available UTXOs have already been assigned to
	/// other claims, implementations must be willing to double spend their UTXOs. The choice of
	/// which UTXOs to double spend is left to the implementation, but it must strive to keep the
	/// set of other claims being double spent to a minimum.
	///
	/// [`ChannelMonitor::rebroadcast_pending_claims`]: crate::chain::channelmonitor::ChannelMonitor::rebroadcast_pending_claims
	fn select_confirmed_utxos(
		&self, claim_id: ClaimId, must_spend: Vec<Input>, must_pay_to: &[TxOut],
		target_feerate_sat_per_1000_weight: u32, max_tx_weight: u64,
	) -> Result<CoinSelection, ()>;

	/// Signs and provides the full witness for all inputs within the transaction known to the
	/// trait (i.e., any provided via [`CoinSelectionSourceSync::select_confirmed_utxos`]).
	///
	/// If your wallet does not support signing PSBTs you can call `psbt.extract_tx()` to get the
	/// unsigned transaction and then sign it with your wallet.
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
		target_feerate_sat_per_1000_weight: u32, max_tx_weight: u64,
	) -> impl Future<Output = Result<CoinSelection, ()>> + MaybeSend + 'a {
		let coins = self.0.select_confirmed_utxos(
			claim_id,
			must_spend,
			must_pay_to,
			target_feerate_sat_per_1000_weight,
			max_tx_weight,
		);
		async move { coins }
	}

	fn sign_psbt<'a>(
		&'a self, psbt: Psbt,
	) -> impl Future<Output = Result<Transaction, ()>> + MaybeSend + 'a {
		let psbt = self.0.sign_psbt(psbt);
		async move { psbt }
	}
}

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
