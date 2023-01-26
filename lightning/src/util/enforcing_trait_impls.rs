// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

use crate::ln::channel::{ANCHOR_OUTPUT_VALUE_SATOSHI, MIN_CHAN_DUST_LIMIT_SATOSHIS};
use crate::ln::chan_utils::{HTLCOutputInCommitment, ChannelPublicKeys, HolderCommitmentTransaction, CommitmentTransaction, ChannelTransactionParameters, TrustedCommitmentTransaction, ClosingTransaction};
use crate::ln::{chan_utils, msgs, PaymentPreimage};
use crate::chain::keysinterface::{WriteableEcdsaChannelSigner, InMemorySigner, ChannelSigner, EcdsaChannelSigner};

use crate::prelude::*;
use core::cmp;
use crate::sync::{Mutex, Arc};
#[cfg(test)] use crate::sync::MutexGuard;

use bitcoin::blockdata::transaction::{Transaction, EcdsaSighashType};
use bitcoin::util::sighash;

use bitcoin::secp256k1;
use bitcoin::secp256k1::{SecretKey, PublicKey};
use bitcoin::secp256k1::{Secp256k1, ecdsa::Signature};
#[cfg(anchors)]
use crate::util::events::HTLCDescriptor;
use crate::util::ser::{Writeable, Writer};
use crate::io::Error;

/// Initial value for revoked commitment downward counter
pub const INITIAL_REVOKED_COMMITMENT_NUMBER: u64 = 1 << 48;

/// An implementation of Sign that enforces some policy checks.  The current checks
/// are an incomplete set.  They include:
///
/// - When signing, the holder transaction has not been revoked
/// - When revoking, the holder transaction has not been signed
/// - The holder commitment number is monotonic and without gaps
/// - The revoked holder commitment number is monotonic and without gaps
/// - There is at least one unrevoked holder transaction at all times
/// - The counterparty commitment number is monotonic and without gaps
/// - The pre-derived keys and pre-built transaction in CommitmentTransaction were correctly built
///
/// Eventually we will probably want to expose a variant of this which would essentially
/// be what you'd want to run on a hardware wallet.
///
/// Note that counterparty signatures on the holder transaction are not checked, but it should
/// be in a complete implementation.
///
/// Note that before we do so we should ensure its serialization format has backwards- and
/// forwards-compatibility prefix/suffixes!
#[derive(Clone)]
pub struct EnforcingSigner {
	pub inner: InMemorySigner,
	/// Channel state used for policy enforcement
	pub state: Arc<Mutex<EnforcementState>>,
	pub disable_revocation_policy_check: bool,
}

impl PartialEq for EnforcingSigner {
	fn eq(&self, o: &Self) -> bool {
		Arc::ptr_eq(&self.state, &o.state)
	}
}

impl EnforcingSigner {
	/// Construct an EnforcingSigner
	pub fn new(inner: InMemorySigner) -> Self {
		let state = Arc::new(Mutex::new(EnforcementState::new()));
		Self {
			inner,
			state,
			disable_revocation_policy_check: false
		}
	}

	/// Construct an EnforcingSigner with externally managed storage
	///
	/// Since there are multiple copies of this struct for each channel, some coordination is needed
	/// so that all copies are aware of enforcement state.  A pointer to this state is provided
	/// here, usually by an implementation of KeysInterface.
	pub fn new_with_revoked(inner: InMemorySigner, state: Arc<Mutex<EnforcementState>>, disable_revocation_policy_check: bool) -> Self {
		Self {
			inner,
			state,
			disable_revocation_policy_check
		}
	}

	pub fn opt_anchors(&self) -> bool { self.inner.opt_anchors() }

	#[cfg(test)]
	pub fn get_enforcement_state(&self) -> MutexGuard<EnforcementState> {
		self.state.lock().unwrap()
	}
}

impl ChannelSigner for EnforcingSigner {
	fn get_per_commitment_point(&self, idx: u64, secp_ctx: &Secp256k1<secp256k1::All>) -> PublicKey {
		self.inner.get_per_commitment_point(idx, secp_ctx)
	}

	fn release_commitment_secret(&self, idx: u64) -> [u8; 32] {
		{
			let mut state = self.state.lock().unwrap();
			assert!(idx == state.last_holder_revoked_commitment || idx == state.last_holder_revoked_commitment - 1, "can only revoke the current or next unrevoked commitment - trying {}, last revoked {}", idx, state.last_holder_revoked_commitment);
			assert!(idx > state.last_holder_commitment, "cannot revoke the last holder commitment - attempted to revoke {} last commitment {}", idx, state.last_holder_commitment);
			state.last_holder_revoked_commitment = idx;
		}
		self.inner.release_commitment_secret(idx)
	}

	fn validate_holder_commitment(&self, holder_tx: &HolderCommitmentTransaction, _preimages: Vec<PaymentPreimage>) -> Result<(), ()> {
		let mut state = self.state.lock().unwrap();
		let idx = holder_tx.commitment_number();
		assert!(idx == state.last_holder_commitment || idx == state.last_holder_commitment - 1, "expecting to validate the current or next holder commitment - trying {}, current {}", idx, state.last_holder_commitment);
		state.last_holder_commitment = idx;
		Ok(())
	}

	fn pubkeys(&self) -> &ChannelPublicKeys { self.inner.pubkeys() }

	fn channel_keys_id(&self) -> [u8; 32] { self.inner.channel_keys_id() }

	fn provide_channel_parameters(&mut self, channel_parameters: &ChannelTransactionParameters) {
		self.inner.provide_channel_parameters(channel_parameters)
	}
}

impl EcdsaChannelSigner for EnforcingSigner {
	fn sign_counterparty_commitment(&self, commitment_tx: &CommitmentTransaction, preimages: Vec<PaymentPreimage>, secp_ctx: &Secp256k1<secp256k1::All>) -> Result<(Signature, Vec<Signature>), ()> {
		self.verify_counterparty_commitment_tx(commitment_tx, secp_ctx);

		{
			let mut state = self.state.lock().unwrap();
			let actual_commitment_number = commitment_tx.commitment_number();
			let last_commitment_number = state.last_counterparty_commitment;
			// These commitment numbers are backwards counting.  We expect either the same as the previously encountered,
			// or the next one.
			assert!(last_commitment_number == actual_commitment_number || last_commitment_number - 1 == actual_commitment_number, "{} doesn't come after {}", actual_commitment_number, last_commitment_number);
			// Ensure that the counterparty doesn't get more than two broadcastable commitments -
			// the last and the one we are trying to sign
			assert!(actual_commitment_number >= state.last_counterparty_revoked_commitment - 2, "cannot sign a commitment if second to last wasn't revoked - signing {} revoked {}", actual_commitment_number, state.last_counterparty_revoked_commitment);
			state.last_counterparty_commitment = cmp::min(last_commitment_number, actual_commitment_number)
		}

		Ok(self.inner.sign_counterparty_commitment(commitment_tx, preimages, secp_ctx).unwrap())
	}

	fn validate_counterparty_revocation(&self, idx: u64, _secret: &SecretKey) -> Result<(), ()> {
		let mut state = self.state.lock().unwrap();
		assert!(idx == state.last_counterparty_revoked_commitment || idx == state.last_counterparty_revoked_commitment - 1, "expecting to validate the current or next counterparty revocation - trying {}, current {}", idx, state.last_counterparty_revoked_commitment);
		state.last_counterparty_revoked_commitment = idx;
		Ok(())
	}

	fn sign_holder_commitment_and_htlcs(&self, commitment_tx: &HolderCommitmentTransaction, secp_ctx: &Secp256k1<secp256k1::All>) -> Result<(Signature, Vec<Signature>), ()> {
		let trusted_tx = self.verify_holder_commitment_tx(commitment_tx, secp_ctx);
		let commitment_txid = trusted_tx.txid();
		let holder_csv = self.inner.counterparty_selected_contest_delay();

		let state = self.state.lock().unwrap();
		let commitment_number = trusted_tx.commitment_number();
		if state.last_holder_revoked_commitment - 1 != commitment_number && state.last_holder_revoked_commitment - 2 != commitment_number {
			if !self.disable_revocation_policy_check {
				panic!("can only sign the next two unrevoked commitment numbers, revoked={} vs requested={} for {}",
				       state.last_holder_revoked_commitment, commitment_number, self.inner.commitment_seed[0])
			}
		}

		for (this_htlc, sig) in trusted_tx.htlcs().iter().zip(&commitment_tx.counterparty_htlc_sigs) {
			assert!(this_htlc.transaction_output_index.is_some());
			let keys = trusted_tx.keys();
			let htlc_tx = chan_utils::build_htlc_transaction(&commitment_txid, trusted_tx.feerate_per_kw(), holder_csv, &this_htlc, self.opt_anchors(), false, &keys.broadcaster_delayed_payment_key, &keys.revocation_key);

			let htlc_redeemscript = chan_utils::get_htlc_redeemscript(&this_htlc, self.opt_anchors(), &keys);

			let sighash_type = if self.opt_anchors() {
				EcdsaSighashType::SinglePlusAnyoneCanPay
			} else {
				EcdsaSighashType::All
			};
			let sighash = hash_to_message!(
				&sighash::SighashCache::new(&htlc_tx).segwit_signature_hash(
					0, &htlc_redeemscript, this_htlc.amount_msat / 1000, sighash_type,
				).unwrap()[..]
			);
			secp_ctx.verify_ecdsa(&sighash, sig, &keys.countersignatory_htlc_key).unwrap();
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

	#[cfg(anchors)]
	fn sign_holder_htlc_transaction(
		&self, htlc_tx: &Transaction, input: usize, htlc_descriptor: &HTLCDescriptor,
		secp_ctx: &Secp256k1<secp256k1::All>
	) -> Result<Signature, ()> {
		let per_commitment_point = self.get_per_commitment_point(htlc_descriptor.per_commitment_number, secp_ctx);
		assert_eq!(htlc_tx.input[input], htlc_descriptor.unsigned_tx_input());
		assert_eq!(htlc_tx.output[input], htlc_descriptor.tx_output(&per_commitment_point, secp_ctx));
		Ok(self.inner.sign_holder_htlc_transaction(htlc_tx, input, htlc_descriptor, secp_ctx).unwrap())
	}

	fn sign_counterparty_htlc_transaction(&self, htlc_tx: &Transaction, input: usize, amount: u64, per_commitment_point: &PublicKey, htlc: &HTLCOutputInCommitment, secp_ctx: &Secp256k1<secp256k1::All>) -> Result<Signature, ()> {
		Ok(self.inner.sign_counterparty_htlc_transaction(htlc_tx, input, amount, per_commitment_point, htlc, secp_ctx).unwrap())
	}

	fn sign_closing_transaction(&self, closing_tx: &ClosingTransaction, secp_ctx: &Secp256k1<secp256k1::All>) -> Result<Signature, ()> {
		closing_tx.verify(self.inner.funding_outpoint().into_bitcoin_outpoint())
			.expect("derived different closing transaction");
		Ok(self.inner.sign_closing_transaction(closing_tx, secp_ctx).unwrap())
	}

	fn sign_holder_anchor_input(
		&self, anchor_tx: &Transaction, input: usize, secp_ctx: &Secp256k1<secp256k1::All>,
	) -> Result<Signature, ()> {
		debug_assert!(MIN_CHAN_DUST_LIMIT_SATOSHIS > ANCHOR_OUTPUT_VALUE_SATOSHI);
		// As long as our minimum dust limit is enforced and is greater than our anchor output
		// value, an anchor output can only have an index within [0, 1].
		assert!(anchor_tx.input[input].previous_output.vout == 0 || anchor_tx.input[input].previous_output.vout == 1);
		self.inner.sign_holder_anchor_input(anchor_tx, input, secp_ctx)
	}

	fn sign_channel_announcement_with_funding_key(
		&self, msg: &msgs::UnsignedChannelAnnouncement, secp_ctx: &Secp256k1<secp256k1::All>
	) -> Result<Signature, ()> {
		self.inner.sign_channel_announcement_with_funding_key(msg, secp_ctx)
	}
}

impl WriteableEcdsaChannelSigner for EnforcingSigner {}

impl Writeable for EnforcingSigner {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), Error> {
		// EnforcingSigner has two fields - `inner` ([`InMemorySigner`]) and `state`
		// ([`EnforcementState`]). `inner` is serialized here and deserialized by
		// [`SignerProvider::read_chan_signer`]. `state` is managed by [`SignerProvider`]
		// and will be serialized as needed by the implementation of that trait.
		self.inner.write(writer)?;
		Ok(())
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

/// The state used by [`EnforcingSigner`] in order to enforce policy checks
///
/// This structure is maintained by KeysInterface since we may have multiple copies of
/// the signer and they must coordinate their state.
#[derive(Clone)]
pub struct EnforcementState {
	/// The last counterparty commitment number we signed, backwards counting
	pub last_counterparty_commitment: u64,
	/// The last counterparty commitment they revoked, backwards counting
	pub last_counterparty_revoked_commitment: u64,
	/// The last holder commitment number we revoked, backwards counting
	pub last_holder_revoked_commitment: u64,
	/// The last validated holder commitment number, backwards counting
	pub last_holder_commitment: u64,
}

impl EnforcementState {
	/// Enforcement state for a new channel
	pub fn new() -> Self {
		EnforcementState {
			last_counterparty_commitment: INITIAL_REVOKED_COMMITMENT_NUMBER,
			last_counterparty_revoked_commitment: INITIAL_REVOKED_COMMITMENT_NUMBER,
			last_holder_revoked_commitment: INITIAL_REVOKED_COMMITMENT_NUMBER,
			last_holder_commitment: INITIAL_REVOKED_COMMITMENT_NUMBER,
		}
	}
}
