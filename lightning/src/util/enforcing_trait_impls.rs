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
use chain::keysinterface::{Sign, InMemorySigner, BaseSign};

use prelude::*;
use core::cmp;
use sync::{Mutex, Arc};

use bitcoin::blockdata::transaction::{Transaction, SigHashType};
use bitcoin::util::bip143;

use bitcoin::secp256k1;
use bitcoin::secp256k1::key::{SecretKey, PublicKey};
use bitcoin::secp256k1::{Secp256k1, Signature};
use util::ser::{Writeable, Writer, Readable};
use std::io::Error;
use ln::msgs::DecodeError;

/// Initial value for revoked commitment downward counter
pub const INITIAL_REVOKED_COMMITMENT_NUMBER: u64 = 1 << 48;

/// An implementation of Sign that enforces some policy checks.  The current checks
/// are an incomplete set.  They include:
///
/// - When signing, the holder transaction has not been revoked
/// - When revoking, the holder transaction has not been signed
/// - The holder commitment number is monotonic and without gaps
/// - The counterparty commitment number is monotonic and without gaps
/// - The pre-derived keys and pre-built transaction in CommitmentTransaction were correctly built
///
/// Eventually we will probably want to expose a variant of this which would essentially
/// be what you'd want to run on a hardware wallet.
///
/// Note that before we do so we should ensure its serialization format has backwards- and
/// forwards-compatibility prefix/suffixes!
#[derive(Clone)]
pub struct EnforcingSigner {
	pub inner: InMemorySigner,
	/// The last counterparty commitment number we signed, backwards counting
	pub last_commitment_number: Arc<Mutex<Option<u64>>>,
	/// The last holder commitment number we revoked, backwards counting
	pub revoked_commitment: Arc<Mutex<u64>>,
	pub disable_revocation_policy_check: bool,
}

impl EnforcingSigner {
	/// Construct an EnforcingSigner
	pub fn new(inner: InMemorySigner) -> Self {
		Self {
			inner,
			last_commitment_number: Arc::new(Mutex::new(None)),
			revoked_commitment: Arc::new(Mutex::new(INITIAL_REVOKED_COMMITMENT_NUMBER)),
			disable_revocation_policy_check: false
		}
	}

	/// Construct an EnforcingSigner with externally managed storage
	///
	/// Since there are multiple copies of this struct for each channel, some coordination is needed
	/// so that all copies are aware of revocations.  A pointer to this state is provided here, usually
	/// by an implementation of KeysInterface.
	pub fn new_with_revoked(inner: InMemorySigner, revoked_commitment: Arc<Mutex<u64>>, disable_revocation_policy_check: bool) -> Self {
		Self {
			inner,
			last_commitment_number: Arc::new(Mutex::new(None)),
			revoked_commitment,
			disable_revocation_policy_check
		}
	}
}

impl BaseSign for EnforcingSigner {
	fn get_per_commitment_point(&self, idx: u64, secp_ctx: &Secp256k1<secp256k1::All>) -> PublicKey {
		self.inner.get_per_commitment_point(idx, secp_ctx)
	}

	fn release_commitment_secret(&self, idx: u64) -> [u8; 32] {
		{
			let mut revoked = self.revoked_commitment.lock().unwrap();
			assert!(idx == *revoked || idx == *revoked - 1, "can only revoke the current or next unrevoked commitment - trying {}, revoked {}", idx, *revoked);
			*revoked = idx;
		}
		self.inner.release_commitment_secret(idx)
	}

	fn pubkeys(&self) -> &ChannelPublicKeys { self.inner.pubkeys() }
	fn channel_keys_id(&self) -> [u8; 32] { self.inner.channel_keys_id() }

	fn sign_counterparty_commitment(&self, commitment_tx: &CommitmentTransaction, secp_ctx: &Secp256k1<secp256k1::All>) -> Result<(Signature, Vec<Signature>), ()> {
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

	fn sign_holder_commitment_and_htlcs(&self, commitment_tx: &HolderCommitmentTransaction, secp_ctx: &Secp256k1<secp256k1::All>) -> Result<(Signature, Vec<Signature>), ()> {
		let trusted_tx = self.verify_holder_commitment_tx(commitment_tx, secp_ctx);
		let commitment_txid = trusted_tx.txid();
		let holder_csv = self.inner.counterparty_selected_contest_delay();

		let revoked = self.revoked_commitment.lock().unwrap();
		let commitment_number = trusted_tx.commitment_number();
		if *revoked - 1 != commitment_number && *revoked - 2 != commitment_number {
			if !self.disable_revocation_policy_check {
				panic!("can only sign the next two unrevoked commitment numbers, revoked={} vs requested={} for {}",
				       *revoked, commitment_number, self.inner.commitment_seed[0])
			}
		}

		for (this_htlc, sig) in trusted_tx.htlcs().iter().zip(&commitment_tx.counterparty_htlc_sigs) {
			assert!(this_htlc.transaction_output_index.is_some());
			let keys = trusted_tx.keys();
			let htlc_tx = chan_utils::build_htlc_transaction(&commitment_txid, trusted_tx.feerate_per_kw(), holder_csv, &this_htlc, &keys.broadcaster_delayed_payment_key, &keys.revocation_key);

			let htlc_redeemscript = chan_utils::get_htlc_redeemscript(&this_htlc, &keys);

			let sighash = hash_to_message!(&bip143::SigHashCache::new(&htlc_tx).signature_hash(0, &htlc_redeemscript, this_htlc.amount_msat / 1000, SigHashType::All)[..]);
			secp_ctx.verify(&sighash, sig, &keys.countersignatory_htlc_key).unwrap();
		}

		Ok(self.inner.sign_holder_commitment_and_htlcs(commitment_tx, secp_ctx).unwrap())
	}

	#[cfg(any(test,feature = "unsafe_revoked_tx_signing"))]
	fn unsafe_sign_holder_commitment_and_htlcs(&self, commitment_tx: &HolderCommitmentTransaction, secp_ctx: &Secp256k1<secp256k1::All>) -> Result<(Signature, Vec<Signature>), ()> {
		Ok(self.inner.unsafe_sign_holder_commitment_and_htlcs(commitment_tx, secp_ctx).unwrap())
	}

	fn sign_justice_revoked_output(&self, justice_tx: &Transaction, input: usize, amount: u64, per_commitment_key: &SecretKey, secp_ctx: &Secp256k1<secp256k1::All>) -> Result<Signature, ()> {
		Ok(self.inner.sign_justice_revoked_output(justice_tx, input, amount, per_commitment_key, secp_ctx).unwrap())
	}

	fn sign_justice_revoked_htlc(&self, justice_tx: &Transaction, input: usize, amount: u64, per_commitment_key: &SecretKey, htlc: &HTLCOutputInCommitment, secp_ctx: &Secp256k1<secp256k1::All>) -> Result<Signature, ()> {
		Ok(self.inner.sign_justice_revoked_htlc(justice_tx, input, amount, per_commitment_key, htlc, secp_ctx).unwrap())
	}

	fn sign_counterparty_htlc_transaction(&self, htlc_tx: &Transaction, input: usize, amount: u64, per_commitment_point: &PublicKey, htlc: &HTLCOutputInCommitment, secp_ctx: &Secp256k1<secp256k1::All>) -> Result<Signature, ()> {
		Ok(self.inner.sign_counterparty_htlc_transaction(htlc_tx, input, amount, per_commitment_point, htlc, secp_ctx).unwrap())
	}

	fn sign_closing_transaction(&self, closing_tx: &Transaction, secp_ctx: &Secp256k1<secp256k1::All>) -> Result<Signature, ()> {
		Ok(self.inner.sign_closing_transaction(closing_tx, secp_ctx).unwrap())
	}

	fn sign_channel_announcement(&self, msg: &msgs::UnsignedChannelAnnouncement, secp_ctx: &Secp256k1<secp256k1::All>) -> Result<Signature, ()> {
		self.inner.sign_channel_announcement(msg, secp_ctx)
	}

	fn ready_channel(&mut self, channel_parameters: &ChannelTransactionParameters) {
		self.inner.ready_channel(channel_parameters)
	}
}

impl Sign for EnforcingSigner {}

impl Writeable for EnforcingSigner {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), Error> {
		self.inner.write(writer)?;
		let last = *self.last_commitment_number.lock().unwrap();
		last.write(writer)?;
		Ok(())
	}
}

impl Readable for EnforcingSigner {
	fn read<R: ::std::io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
		let inner = Readable::read(reader)?;
		let last_commitment_number = Readable::read(reader)?;
		Ok(EnforcingSigner {
			inner,
			last_commitment_number: Arc::new(Mutex::new(last_commitment_number)),
			revoked_commitment: Arc::new(Mutex::new(INITIAL_REVOKED_COMMITMENT_NUMBER)),
			disable_revocation_policy_check: false,
		})
	}
}

impl EnforcingSigner {
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
