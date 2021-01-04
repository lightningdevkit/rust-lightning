// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

use ln::chan_utils::{HTLCOutputInCommitment, ChannelPublicKeys, HolderCommitmentTransaction, CommitmentTransaction, ChannelTransactionParameters, TrustedCommitmentTransaction};
use ln::{chan_utils, msgs};
use chain::keysinterface::{ChannelKeys, InMemoryChannelKeys};

use std::cmp;
use std::sync::{Mutex, Arc};

use bitcoin::blockdata::transaction::{Transaction, SigHashType};
use bitcoin::util::bip143;

use bitcoin::secp256k1;
use bitcoin::secp256k1::key::{SecretKey, PublicKey};
use bitcoin::secp256k1::{Secp256k1, Signature};
use util::ser::{Writeable, Writer, Readable};
use std::io::Error;
use ln::msgs::DecodeError;

/// An implementation of ChannelKeys that enforces some policy checks.
///
/// Eventually we will probably want to expose a variant of this which would essentially
/// be what you'd want to run on a hardware wallet.
#[derive(Clone)]
pub struct EnforcingChannelKeys {
	pub inner: InMemoryChannelKeys,
	last_commitment_number: Arc<Mutex<Option<u64>>>,
}

impl EnforcingChannelKeys {
	pub fn new(inner: InMemoryChannelKeys) -> Self {
		Self {
			inner,
			last_commitment_number: Arc::new(Mutex::new(None)),
		}
	}
}

impl ChannelKeys for EnforcingChannelKeys {
	fn get_per_commitment_point<T: secp256k1::Signing + secp256k1::Verification>(&self, idx: u64, secp_ctx: &Secp256k1<T>) -> PublicKey {
		self.inner.get_per_commitment_point(idx, secp_ctx)
	}

	fn release_commitment_secret(&self, idx: u64) -> [u8; 32] {
		// TODO: enforce the ChannelKeys contract - error here if we already signed this commitment
		self.inner.release_commitment_secret(idx)
	}

	fn pubkeys(&self) -> &ChannelPublicKeys { self.inner.pubkeys() }
	fn key_derivation_params(&self) -> (u64, u64) { self.inner.key_derivation_params() }

	fn sign_counterparty_commitment<T: secp256k1::Signing + secp256k1::Verification>(&self, commitment_tx: &CommitmentTransaction, secp_ctx: &Secp256k1<T>) -> Result<(Signature, Vec<Signature>), ()> {
		self.verify_counterparty_commitment_tx(commitment_tx, secp_ctx);

		{
			let mut last_commitment_number_guard = self.last_commitment_number.lock().unwrap();
			let actual_commitment_number = commitment_tx.commitment_number();
			let last_commitment_number = last_commitment_number_guard.unwrap_or(actual_commitment_number);
			// These commitment numbers are backwards counting.  We expect either the same as the previously encountered,
			// or the next one.
			assert!(last_commitment_number == actual_commitment_number || last_commitment_number - 1 == actual_commitment_number, "{} doesn't come after {}", actual_commitment_number, last_commitment_number);
			*last_commitment_number_guard = Some(cmp::min(last_commitment_number, actual_commitment_number))
		}

		Ok(self.inner.sign_counterparty_commitment(commitment_tx, secp_ctx).unwrap())
	}

	fn sign_holder_commitment<T: secp256k1::Signing + secp256k1::Verification>(&self, commitment_tx: &HolderCommitmentTransaction, secp_ctx: &Secp256k1<T>) -> Result<Signature, ()> {
		self.verify_holder_commitment_tx(commitment_tx, secp_ctx);

		// TODO: enforce the ChannelKeys contract - error if this commitment was already revoked
		// TODO: need the commitment number
		Ok(self.inner.sign_holder_commitment(commitment_tx, secp_ctx).unwrap())
	}

	#[cfg(any(test,feature = "unsafe_revoked_tx_signing"))]
	fn unsafe_sign_holder_commitment<T: secp256k1::Signing + secp256k1::Verification>(&self, commitment_tx: &HolderCommitmentTransaction, secp_ctx: &Secp256k1<T>) -> Result<Signature, ()> {
		Ok(self.inner.unsafe_sign_holder_commitment(commitment_tx, secp_ctx).unwrap())
	}

	fn sign_holder_commitment_htlc_transactions<T: secp256k1::Signing + secp256k1::Verification>(&self, commitment_tx: &HolderCommitmentTransaction, secp_ctx: &Secp256k1<T>) -> Result<Vec<Signature>, ()> {
		let trusted_tx = self.verify_holder_commitment_tx(commitment_tx, secp_ctx);
		let commitment_txid = trusted_tx.txid();
		let holder_csv = self.inner.counterparty_selected_contest_delay();

		for (this_htlc, sig) in trusted_tx.htlcs().iter().zip(&commitment_tx.counterparty_htlc_sigs) {
			assert!(this_htlc.transaction_output_index.is_some());
			let keys = trusted_tx.keys();
			let htlc_tx = chan_utils::build_htlc_transaction(&commitment_txid, trusted_tx.feerate_per_kw(), holder_csv, &this_htlc, &keys.broadcaster_delayed_payment_key, &keys.revocation_key);

			let htlc_redeemscript = chan_utils::get_htlc_redeemscript(&this_htlc, &keys);

			let sighash = hash_to_message!(&bip143::SigHashCache::new(&htlc_tx).signature_hash(0, &htlc_redeemscript, this_htlc.amount_msat / 1000, SigHashType::All)[..]);
			secp_ctx.verify(&sighash, sig, &keys.countersignatory_htlc_key).unwrap();
		}

		Ok(self.inner.sign_holder_commitment_htlc_transactions(commitment_tx, secp_ctx).unwrap())
	}

	fn sign_justice_transaction<T: secp256k1::Signing + secp256k1::Verification>(&self, justice_tx: &Transaction, input: usize, amount: u64, per_commitment_key: &SecretKey, htlc: &Option<HTLCOutputInCommitment>, secp_ctx: &Secp256k1<T>) -> Result<Signature, ()> {
		Ok(self.inner.sign_justice_transaction(justice_tx, input, amount, per_commitment_key, htlc, secp_ctx).unwrap())
	}

	fn sign_counterparty_htlc_transaction<T: secp256k1::Signing + secp256k1::Verification>(&self, htlc_tx: &Transaction, input: usize, amount: u64, per_commitment_point: &PublicKey, htlc: &HTLCOutputInCommitment, secp_ctx: &Secp256k1<T>) -> Result<Signature, ()> {
		Ok(self.inner.sign_counterparty_htlc_transaction(htlc_tx, input, amount, per_commitment_point, htlc, secp_ctx).unwrap())
	}

	fn sign_closing_transaction<T: secp256k1::Signing>(&self, closing_tx: &Transaction, secp_ctx: &Secp256k1<T>) -> Result<Signature, ()> {
		Ok(self.inner.sign_closing_transaction(closing_tx, secp_ctx).unwrap())
	}

	fn sign_channel_announcement<T: secp256k1::Signing>(&self, msg: &msgs::UnsignedChannelAnnouncement, secp_ctx: &Secp256k1<T>) -> Result<Signature, ()> {
		self.inner.sign_channel_announcement(msg, secp_ctx)
	}

	fn ready_channel(&mut self, channel_parameters: &ChannelTransactionParameters) {
		self.inner.ready_channel(channel_parameters)
	}
}


impl Writeable for EnforcingChannelKeys {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), Error> {
		self.inner.write(writer)?;
		let last = *self.last_commitment_number.lock().unwrap();
		last.write(writer)?;
		Ok(())
	}
}

impl Readable for EnforcingChannelKeys {
	fn read<R: ::std::io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
		let inner = Readable::read(reader)?;
		let last_commitment_number = Readable::read(reader)?;
		Ok(EnforcingChannelKeys {
			inner,
			last_commitment_number: Arc::new(Mutex::new(last_commitment_number))
		})
	}
}

impl EnforcingChannelKeys {
	fn verify_counterparty_commitment_tx<'a, T: secp256k1::Signing + secp256k1::Verification>(&self, commitment_tx: &'a CommitmentTransaction, secp_ctx: &Secp256k1<T>) -> TrustedCommitmentTransaction<'a> {
		commitment_tx.verify(&self.inner.get_channel_parameters().as_counterparty_broadcastable(),
		                     self.inner.counterparty_pubkeys(), self.inner.pubkeys(), secp_ctx)
			.expect("derived different per-tx keys or built transaction")
	}

	fn verify_holder_commitment_tx<'a, T: secp256k1::Signing + secp256k1::Verification>(&self, commitment_tx: &'a CommitmentTransaction, secp_ctx: &Secp256k1<T>) -> TrustedCommitmentTransaction<'a> {
		commitment_tx.verify(&self.inner.get_channel_parameters().as_holder_broadcastable(),
		                     self.inner.pubkeys(), self.inner.counterparty_pubkeys(), secp_ctx)
			.expect("derived different per-tx keys or built transaction")
	}
}
