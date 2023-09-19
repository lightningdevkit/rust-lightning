// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Todo: fill this in
use bitcoin::secp256k1::ecdsa::Signature;
use crate::chain::chaininterface::BroadcasterInterface;
use crate::ln::chan_utils::HolderCommitmentTransaction;

use core::ops::Deref;


/// The result of a request for a signature. A call may resolve either synchronously,
/// returning the `Sync` variant, or asynchronously, returning a [`SignatureFuture`] in the `Async`
/// variant.
#[derive(Clone)]
pub enum SignatureResult<B: Deref> where B::Target: BroadcasterInterface{
	/// A result which was resolved synchronously. It either includes a [`Signature`] for the
    /// transaction requested or an error.
	Sync(Result<(Signature, Vec<Signature>), ()>),
	/// A result which will be resolved asynchronously. It includes a [`SignatureFuture`], a `clone` of
	/// which you must keep locally and call [`SignatureFuture::resolve`] on once a signature is provided.
	Async(SignatureFuture<B>),
}

/// Represents a future signature
///
#[derive(Clone)]
pub struct SignatureFuture<B: Deref> where B::Target: BroadcasterInterface {
    holder_commitment_tx: HolderCommitmentTransaction,
	broadcaster: B,
}

impl <B: Deref> SignatureFuture<B> where B::Target: BroadcasterInterface {
	/// Builds a new future for later resolution.
	pub fn new(broadcaster: B, holder_commitment_tx: HolderCommitmentTransaction) -> Self {
		Self { 
            holder_commitment_tx,
            broadcaster,
        }
	}

	/// Resolves this future 
	pub fn resolve(&self, res: Result<(Signature, Vec<Signature>), ()>) {
        // Add signature to the transaction and broadcast
    }
}