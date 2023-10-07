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
use crate::ln::channel_keys::{HtlcKey};
use crate::ln::{msgs, PaymentPreimage};
use crate::sign::{InMemorySigner, ChannelSigner};
use crate::sign::ecdsa::{EcdsaChannelSigner, WriteableEcdsaChannelSigner};

use crate::prelude::*;
use core::cmp;
use crate::sync::{Mutex, Arc};
#[cfg(test)] use crate::sync::MutexGuard;

use bitcoin::blockdata::transaction::Transaction;
use bitcoin::hashes::Hash;
use bitcoin::sighash;
use bitcoin::sighash::EcdsaSighashType;

use bitcoin::secp256k1;
#[cfg(taproot)]
use bitcoin::secp256k1::All;
use bitcoin::secp256k1::{SecretKey, PublicKey};
use bitcoin::secp256k1::{Secp256k1, ecdsa::Signature};
#[cfg(taproot)]
use musig2::types::{PartialSignature, PublicNonce, SecretNonce};
use crate::sign::HTLCDescriptor;
use crate::util::ser::{Writeable, Writer};
use crate::io::Error;
use crate::ln::features::ChannelTypeFeatures;
#[cfg(taproot)]
use crate::ln::msgs::PartialSignatureWithNonce;
#[cfg(taproot)]
use crate::sign::taproot::TaprootChannelSigner;

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
pub struct TestChannelSigner {
	pub inner: InMemorySigner,
	/// Channel state used for policy enforcement
	pub state: Arc<Mutex<EnforcementState>>,
	pub disable_revocation_policy_check: bool,
}

/// Channel signer operations that can be individually enabled and disabled. If a particular value
/// is set in the `TestChannelSigner::unavailable` bitmask, then that operation will return an
/// error.
pub mod ops {
	pub const GET_PER_COMMITMENT_POINT: u32                  = 1 << 0;
	pub const RELEASE_COMMITMENT_SECRET: u32                 = 1 << 1;
	pub const VALIDATE_HOLDER_COMMITMENT: u32                = 1 << 2;
	pub const SIGN_COUNTERPARTY_COMMITMENT: u32              = 1 << 3;
	pub const VALIDATE_COUNTERPARTY_REVOCATION: u32          = 1 << 4;
	pub const SIGN_HOLDER_COMMITMENT_AND_HTLCS: u32          = 1 << 5;
	pub const SIGN_JUSTICE_REVOKED_OUTPUT: u32               = 1 << 6;
	pub const SIGN_JUSTICE_REVOKED_HTLC: u32                 = 1 << 7;
	pub const SIGN_HOLDER_HTLC_TRANSACTION: u32              = 1 << 8;
	pub const SIGN_COUNTERPARTY_HTLC_TRANSATION: u32         = 1 << 9;
	pub const SIGN_CLOSING_TRANSACTION: u32                  = 1 << 10;
	pub const SIGN_HOLDER_ANCHOR_INPUT: u32                  = 1 << 11;
	pub const SIGN_CHANNEL_ANNOUNCMENT_WITH_FUNDING_KEY: u32 = 1 << 12;

	#[cfg(test)]
	pub fn string_from(mask: u32) -> String {
		if mask == 0 {
			return "nothing".to_owned();
		}
		if mask == !(0 as u32) {
			return "everything".to_owned();
		}

		vec![
			if (mask & GET_PER_COMMITMENT_POINT) != 0 { Some("get_per_commitment_point") } else { None },
			if (mask & RELEASE_COMMITMENT_SECRET) != 0 { Some("release_commitment_secret") } else { None },
			if (mask & VALIDATE_HOLDER_COMMITMENT) != 0 { Some("validate_holder_commitment") } else { None },
			if (mask & SIGN_COUNTERPARTY_COMMITMENT) != 0 { Some("sign_counterparty_commitment") } else { None },
			if (mask & VALIDATE_COUNTERPARTY_REVOCATION) != 0 { Some("validate_counterparty_revocation") } else { None },
			if (mask & SIGN_HOLDER_COMMITMENT_AND_HTLCS) != 0 { Some("sign_holder_commitment_and_htlcs") } else { None },
			if (mask & SIGN_JUSTICE_REVOKED_OUTPUT) != 0 { Some("sign_justice_revoked_output") } else { None },
			if (mask & SIGN_JUSTICE_REVOKED_HTLC) != 0 { Some("sign_justice_revoked_htlc") } else { None },
			if (mask & SIGN_HOLDER_HTLC_TRANSACTION) != 0 { Some("sign_holder_htlc_transaction") } else { None },
			if (mask & SIGN_COUNTERPARTY_HTLC_TRANSATION) != 0 { Some("sign_counterparty_htlc_transation") } else { None },
			if (mask & SIGN_CLOSING_TRANSACTION) != 0 { Some("sign_closing_transaction") } else { None },
			if (mask & SIGN_HOLDER_ANCHOR_INPUT) != 0 { Some("sign_holder_anchor_input") } else { None },
			if (mask & SIGN_CHANNEL_ANNOUNCMENT_WITH_FUNDING_KEY) != 0 { Some("sign_channel_announcment_with_funding_key") } else { None },
		].iter().flatten().map(|s| s.to_string()).collect::<Vec<_>>().join(", ")
	}
}

impl PartialEq for TestChannelSigner {
	fn eq(&self, o: &Self) -> bool {
		Arc::ptr_eq(&self.state, &o.state)
	}
}

impl TestChannelSigner {
	/// Construct an TestChannelSigner
	pub fn new(inner: InMemorySigner) -> Self {
		let state = Arc::new(Mutex::new(EnforcementState::new()));
		Self {
			inner,
			state,
			disable_revocation_policy_check: false,
		}
	}

	/// Construct an TestChannelSigner with externally managed storage
	///
	/// Since there are multiple copies of this struct for each channel, some coordination is needed
	/// so that all copies are aware of enforcement state.  A pointer to this state is provided
	/// here, usually by an implementation of KeysInterface.
	pub fn new_with_revoked(inner: InMemorySigner, state: Arc<Mutex<EnforcementState>>, disable_revocation_policy_check: bool) -> Self {
		Self {
			inner,
			state,
			disable_revocation_policy_check,
		}
	}

	pub fn channel_type_features(&self) -> &ChannelTypeFeatures { self.inner.channel_type_features().unwrap() }

	#[cfg(test)]
	pub fn get_enforcement_state(&self) -> MutexGuard<EnforcementState> {
		self.state.lock().unwrap()
	}

	/// Marks the signer's availability.
	#[cfg(test)]
	pub fn set_ops_available(&self, mask: u32, available: bool) {
		let mut state = self.get_enforcement_state();
		if available {
			state.unavailable_signer_ops &= !mask;  // clear the bits that are now available
		} else {
			state.unavailable_signer_ops |= mask;   // set the bits that are now unavailable
		}
	}

	fn is_signer_available(&self, ops_mask: u32) -> bool {
		self.state.lock().unwrap().is_signer_available(ops_mask)
	}
}

impl ChannelSigner for TestChannelSigner {
	fn get_per_commitment_point(&self, idx: u64, secp_ctx: &Secp256k1<secp256k1::All>) -> Result<PublicKey, ()> {
		if !self.is_signer_available(ops::GET_PER_COMMITMENT_POINT) {
			return Err(());
		}
		self.inner.get_per_commitment_point(idx, secp_ctx)
	}

	fn release_commitment_secret(&self, idx: u64) -> Result<[u8; 32], ()> {
		if !self.is_signer_available(ops::RELEASE_COMMITMENT_SECRET) {
			return Err(());
		}
		{
			let mut state = self.state.lock().unwrap();
			assert!(idx == state.last_holder_revoked_commitment || idx == state.last_holder_revoked_commitment - 1, "can only revoke the current or next unrevoked commitment - trying {}, last revoked {}", idx, state.last_holder_revoked_commitment);
			assert!(idx > state.last_holder_commitment, "cannot revoke the last holder commitment - attempted to revoke {} last commitment {}", idx, state.last_holder_commitment);
			state.last_holder_revoked_commitment = idx;
		}
		self.inner.release_commitment_secret(idx)
	}

	fn validate_holder_commitment(&self, holder_tx: &HolderCommitmentTransaction, _outbound_htlc_preimages: Vec<PaymentPreimage>) -> Result<(), ()> {
		if !self.is_signer_available(ops::VALIDATE_HOLDER_COMMITMENT) {
			return Err(());
		}
		let mut state = self.state.lock().unwrap();
		let idx = holder_tx.commitment_number();
		assert!(idx == state.last_holder_commitment || idx == state.last_holder_commitment - 1, "expecting to validate the current or next holder commitment - trying {}, current {}", idx, state.last_holder_commitment);
		state.last_holder_commitment = idx;
		Ok(())
	}

	fn validate_counterparty_revocation(&self, idx: u64, _secret: &SecretKey) -> Result<(), ()> {
		if !self.is_signer_available(ops::VALIDATE_COUNTERPARTY_REVOCATION) {
			return Err(());
		}
		let mut state = self.state.lock().unwrap();
		assert!(idx == state.last_counterparty_revoked_commitment || idx == state.last_counterparty_revoked_commitment - 1, "expecting to validate the current or next counterparty revocation - trying {}, current {}", idx, state.last_counterparty_revoked_commitment);
		state.last_counterparty_revoked_commitment = idx;
		Ok(())
	}

	fn pubkeys(&self) -> &ChannelPublicKeys { self.inner.pubkeys() }

	fn channel_keys_id(&self) -> [u8; 32] { self.inner.channel_keys_id() }

	fn provide_channel_parameters(&mut self, channel_parameters: &ChannelTransactionParameters) {
		self.inner.provide_channel_parameters(channel_parameters)
	}
}

impl EcdsaChannelSigner for TestChannelSigner {
	fn sign_counterparty_commitment(&self, commitment_tx: &CommitmentTransaction, inbound_htlc_preimages: Vec<PaymentPreimage>, outbound_htlc_preimages: Vec<PaymentPreimage>, secp_ctx: &Secp256k1<secp256k1::All>) -> Result<(Signature, Vec<Signature>), ()> {
		self.verify_counterparty_commitment_tx(commitment_tx, secp_ctx);

		{
			if !self.is_signer_available(ops::SIGN_COUNTERPARTY_COMMITMENT) {
				return Err(());
			}
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

		Ok(self.inner.sign_counterparty_commitment(commitment_tx, inbound_htlc_preimages, outbound_htlc_preimages, secp_ctx).unwrap())
	}

	fn sign_holder_commitment(&self, commitment_tx: &HolderCommitmentTransaction, secp_ctx: &Secp256k1<secp256k1::All>) -> Result<Signature, ()> {
		if !self.is_signer_available(ops::SIGN_HOLDER_COMMITMENT_AND_HTLCS) {
			return Err(());
		}
		let trusted_tx = self.verify_holder_commitment_tx(commitment_tx, secp_ctx);
		let state = self.state.lock().unwrap();
		let commitment_number = trusted_tx.commitment_number();
		if state.last_holder_revoked_commitment - 1 != commitment_number && state.last_holder_revoked_commitment - 2 != commitment_number {
			if !self.disable_revocation_policy_check {
				panic!("can only sign the next two unrevoked commitment numbers, revoked={} vs requested={} for {}",
				       state.last_holder_revoked_commitment, commitment_number, self.inner.commitment_seed[0])
			}
		}
		Ok(self.inner.sign_holder_commitment(commitment_tx, secp_ctx).unwrap())
	}

	#[cfg(any(test,feature = "unsafe_revoked_tx_signing"))]
	fn unsafe_sign_holder_commitment(&self, commitment_tx: &HolderCommitmentTransaction, secp_ctx: &Secp256k1<secp256k1::All>) -> Result<Signature, ()> {
		Ok(self.inner.unsafe_sign_holder_commitment(commitment_tx, secp_ctx).unwrap())
	}

	fn sign_justice_revoked_output(&self, justice_tx: &Transaction, input: usize, amount: u64, per_commitment_key: &SecretKey, secp_ctx: &Secp256k1<secp256k1::All>) -> Result<Signature, ()> {
		Ok(EcdsaChannelSigner::sign_justice_revoked_output(&self.inner, justice_tx, input, amount, per_commitment_key, secp_ctx).unwrap())
	}

	fn sign_justice_revoked_htlc(&self, justice_tx: &Transaction, input: usize, amount: u64, per_commitment_key: &SecretKey, htlc: &HTLCOutputInCommitment, secp_ctx: &Secp256k1<secp256k1::All>) -> Result<Signature, ()> {
		Ok(EcdsaChannelSigner::sign_justice_revoked_htlc(&self.inner, justice_tx, input, amount, per_commitment_key, htlc, secp_ctx).unwrap())
	}

	fn sign_holder_htlc_transaction(
		&self, htlc_tx: &Transaction, input: usize, htlc_descriptor: &HTLCDescriptor,
		secp_ctx: &Secp256k1<secp256k1::All>
	) -> Result<Signature, ()> {
		let state = self.state.lock().unwrap();
		if state.last_holder_revoked_commitment - 1 != htlc_descriptor.per_commitment_number &&
			state.last_holder_revoked_commitment - 2 != htlc_descriptor.per_commitment_number
		{
			if !self.disable_revocation_policy_check {
				panic!("can only sign the next two unrevoked commitment numbers, revoked={} vs requested={} for {}",
				       state.last_holder_revoked_commitment, htlc_descriptor.per_commitment_number, self.inner.commitment_seed[0])
			}
		}
		assert_eq!(htlc_tx.input[input], htlc_descriptor.unsigned_tx_input());
		assert_eq!(htlc_tx.output[input], htlc_descriptor.tx_output(secp_ctx));
		{
			let witness_script = htlc_descriptor.witness_script(secp_ctx);
			let sighash_type = if self.channel_type_features().supports_anchors_zero_fee_htlc_tx() {
				EcdsaSighashType::SinglePlusAnyoneCanPay
			} else {
				EcdsaSighashType::All
			};
			let sighash = &sighash::SighashCache::new(&*htlc_tx).segwit_signature_hash(
				input, &witness_script, htlc_descriptor.htlc.amount_msat / 1000, sighash_type
			).unwrap();
			let countersignatory_htlc_key = HtlcKey::from_basepoint(
				&secp_ctx, &self.inner.counterparty_pubkeys().unwrap().htlc_basepoint, &htlc_descriptor.per_commitment_point,
			);

			secp_ctx.verify_ecdsa(
				&hash_to_message!(sighash.as_byte_array()), &htlc_descriptor.counterparty_sig, &countersignatory_htlc_key.to_public_key()
			).unwrap();
		}
		Ok(EcdsaChannelSigner::sign_holder_htlc_transaction(&self.inner, htlc_tx, input, htlc_descriptor, secp_ctx).unwrap())
	}

	fn sign_counterparty_htlc_transaction(&self, htlc_tx: &Transaction, input: usize, amount: u64, per_commitment_point: &PublicKey, htlc: &HTLCOutputInCommitment, secp_ctx: &Secp256k1<secp256k1::All>) -> Result<Signature, ()> {
		Ok(EcdsaChannelSigner::sign_counterparty_htlc_transaction(&self.inner, htlc_tx, input, amount, per_commitment_point, htlc, secp_ctx).unwrap())
	}

	fn sign_closing_transaction(&self, closing_tx: &ClosingTransaction, secp_ctx: &Secp256k1<secp256k1::All>) -> Result<Signature, ()> {
		closing_tx.verify(self.inner.funding_outpoint().unwrap().into_bitcoin_outpoint())
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
		EcdsaChannelSigner::sign_holder_anchor_input(&self.inner, anchor_tx, input, secp_ctx)
	}

	fn sign_channel_announcement_with_funding_key(
		&self, msg: &msgs::UnsignedChannelAnnouncement, secp_ctx: &Secp256k1<secp256k1::All>
	) -> Result<Signature, ()> {
		self.inner.sign_channel_announcement_with_funding_key(msg, secp_ctx)
	}
}

impl WriteableEcdsaChannelSigner for TestChannelSigner {}

#[cfg(taproot)]
impl TaprootChannelSigner for TestChannelSigner {
	fn generate_local_nonce_pair(&self, commitment_number: u64, secp_ctx: &Secp256k1<All>) -> PublicNonce {
		todo!()
	}

	fn partially_sign_counterparty_commitment(&self, counterparty_nonce: PublicNonce, commitment_tx: &CommitmentTransaction, inbound_htlc_preimages: Vec<PaymentPreimage>, outbound_htlc_preimages: Vec<PaymentPreimage>, secp_ctx: &Secp256k1<All>) -> Result<(PartialSignatureWithNonce, Vec<secp256k1::schnorr::Signature>), ()> {
		todo!()
	}

	fn finalize_holder_commitment(&self, commitment_tx: &HolderCommitmentTransaction, counterparty_partial_signature: PartialSignatureWithNonce, secp_ctx: &Secp256k1<All>) -> Result<PartialSignature, ()> {
		todo!()
	}

	fn sign_justice_revoked_output(&self, justice_tx: &Transaction, input: usize, amount: u64, per_commitment_key: &SecretKey, secp_ctx: &Secp256k1<All>) -> Result<secp256k1::schnorr::Signature, ()> {
		todo!()
	}

	fn sign_justice_revoked_htlc(&self, justice_tx: &Transaction, input: usize, amount: u64, per_commitment_key: &SecretKey, htlc: &HTLCOutputInCommitment, secp_ctx: &Secp256k1<All>) -> Result<secp256k1::schnorr::Signature, ()> {
		todo!()
	}

	fn sign_holder_htlc_transaction(&self, htlc_tx: &Transaction, input: usize, htlc_descriptor: &HTLCDescriptor, secp_ctx: &Secp256k1<All>) -> Result<secp256k1::schnorr::Signature, ()> {
		todo!()
	}

	fn sign_counterparty_htlc_transaction(&self, htlc_tx: &Transaction, input: usize, amount: u64, per_commitment_point: &PublicKey, htlc: &HTLCOutputInCommitment, secp_ctx: &Secp256k1<All>) -> Result<secp256k1::schnorr::Signature, ()> {
		todo!()
	}

	fn partially_sign_closing_transaction(&self, closing_tx: &ClosingTransaction, secp_ctx: &Secp256k1<All>) -> Result<PartialSignature, ()> {
		todo!()
	}

	fn sign_holder_anchor_input(&self, anchor_tx: &Transaction, input: usize, secp_ctx: &Secp256k1<All>) -> Result<secp256k1::schnorr::Signature, ()> {
		todo!()
	}
}

impl Writeable for TestChannelSigner {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), Error> {
		// TestChannelSigner has two fields - `inner` ([`InMemorySigner`]) and `state`
		// ([`EnforcementState`]). `inner` is serialized here and deserialized by
		// [`SignerProvider::read_chan_signer`]. `state` is managed by [`SignerProvider`]
		// and will be serialized as needed by the implementation of that trait.
		self.inner.write(writer)?;
		Ok(())
	}
}

impl TestChannelSigner {
	fn verify_counterparty_commitment_tx<'a, T: secp256k1::Signing + secp256k1::Verification>(&self, commitment_tx: &'a CommitmentTransaction, secp_ctx: &Secp256k1<T>) -> TrustedCommitmentTransaction<'a> {
		commitment_tx.verify(
			&self.inner.get_channel_parameters().unwrap().as_counterparty_broadcastable(),
			self.inner.counterparty_pubkeys().unwrap(), self.inner.pubkeys(), secp_ctx
		).expect("derived different per-tx keys or built transaction")
	}

	fn verify_holder_commitment_tx<'a, T: secp256k1::Signing + secp256k1::Verification>(&self, commitment_tx: &'a CommitmentTransaction, secp_ctx: &Secp256k1<T>) -> TrustedCommitmentTransaction<'a> {
		commitment_tx.verify(
			&self.inner.get_channel_parameters().unwrap().as_holder_broadcastable(),
			self.inner.pubkeys(), self.inner.counterparty_pubkeys().unwrap(), secp_ctx
		).expect("derived different per-tx keys or built transaction")
	}
}

/// The state used by [`TestChannelSigner`] in order to enforce policy checks
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
	/// A flag array that indicates which signing operations are currently *not* available in the
	/// channel. When a method's bit is set, then the signer will act as if the signature is
	/// unavailable and return an error result.
	pub unavailable_signer_ops: u32,
}

impl EnforcementState {
	/// Enforcement state for a new channel
	pub fn new() -> Self {
		EnforcementState {
			last_counterparty_commitment: INITIAL_REVOKED_COMMITMENT_NUMBER,
			last_counterparty_revoked_commitment: INITIAL_REVOKED_COMMITMENT_NUMBER,
			last_holder_revoked_commitment: INITIAL_REVOKED_COMMITMENT_NUMBER,
			last_holder_commitment: INITIAL_REVOKED_COMMITMENT_NUMBER,
			unavailable_signer_ops: 0,
		}
	}

	pub fn set_signer_available(&mut self, ops_mask: u32) {
		self.unavailable_signer_ops &= !ops_mask;  // clear the bits that are now available
	}

	pub fn set_signer_unavailable(&mut self, ops_mask: u32) {
		self.unavailable_signer_ops |= ops_mask;   // set the bits that are now unavailable
	}

	pub fn is_signer_available(&self, ops_mask: u32) -> bool {
		(self.unavailable_signer_ops & ops_mask) == 0
	}
}
