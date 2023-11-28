//! Defines a Taproot-specific signer type.

use alloc::vec::Vec;
use bitcoin::blockdata::transaction::Transaction;
use bitcoin::secp256k1;
use bitcoin::secp256k1::{PublicKey, schnorr::Signature, Secp256k1, SecretKey};

use musig2::types::{PartialSignature, PublicNonce};

use crate::ln::chan_utils::{ClosingTransaction, CommitmentTransaction, HolderCommitmentTransaction, HTLCOutputInCommitment};
use crate::ln::msgs::PartialSignatureWithNonce;
use crate::ln::PaymentPreimage;
use crate::sign::{ChannelSigner, HTLCDescriptor};

/// A Taproot-specific signer type that defines signing-related methods that are either unique to
/// Taproot or have argument or return types that differ from the ones an ECDSA signer would be
/// expected to have.
pub trait TaprootChannelSigner: ChannelSigner {
	/// Generate a local nonce pair, which requires committing to ahead of time.
	/// The counterparty needs the public nonce generated herein to compute a partial signature.
	fn generate_local_nonce_pair(&self, commitment_number: u64, secp_ctx: &Secp256k1<secp256k1::All>) -> PublicNonce;

	/// Create a signature for a counterparty's commitment transaction and associated HTLC transactions.
	///
	/// Note that if signing fails or is rejected, the channel will be force-closed.
	///
	/// Policy checks should be implemented in this function, including checking the amount
	/// sent to us and checking the HTLCs.
	///
	/// The preimages of outbound and inbound HTLCs that were fulfilled since the last commitment
	/// are provided. A validating signer should ensure that an outbound HTLC output is removed
	/// only when the matching preimage is provided and after the corresponding inbound HTLC has
	/// been removed for forwarded payments.
	///
	/// Note that all the relevant preimages will be provided, but there may also be additional
	/// irrelevant or duplicate preimages.
	//
	// TODO: Document the things someone using this interface should enforce before signing.
	fn partially_sign_counterparty_commitment(&self, counterparty_nonce: PublicNonce,
		commitment_tx: &CommitmentTransaction,
		inbound_htlc_preimages: Vec<PaymentPreimage>,
		outbound_htlc_preimages: Vec<PaymentPreimage>, secp_ctx: &Secp256k1<secp256k1::All>,
	) -> Result<(PartialSignatureWithNonce, Vec<Signature>), ()>;

	/// Creates a signature for a holder's commitment transaction.
	///
	/// This will be called
	/// - with a non-revoked `commitment_tx`.
	/// - with the latest `commitment_tx` when we initiate a force-close.
	///
	/// This may be called multiple times for the same transaction.
	///
	/// An external signer implementation should check that the commitment has not been revoked.
	///
	// TODO: Document the things someone using this interface should enforce before signing.
	fn finalize_holder_commitment(&self, commitment_number: u64,
		commitment_tx: &HolderCommitmentTransaction,
		counterparty_partial_signature: PartialSignatureWithNonce,
		secp_ctx: &Secp256k1<secp256k1::All>
	) -> Result<PartialSignature, ()>;

	/// Create a signature for the given input in a transaction spending an HTLC transaction output
	/// or a commitment transaction `to_local` output when our counterparty broadcasts an old state.
	///
	/// A justice transaction may claim multiple outputs at the same time if timelocks are
	/// similar, but only a signature for the input at index `input` should be signed for here.
	/// It may be called multiple times for same output(s) if a fee-bump is needed with regards
	/// to an upcoming timelock expiration.
	///
	/// Amount is value of the output spent by this input, committed to in the BIP 341 signature.
	///
	/// `per_commitment_key` is revocation secret which was provided by our counterparty when they
	/// revoked the state which they eventually broadcast. It's not a _holder_ secret key and does
	/// not allow the spending of any funds by itself (you need our holder `revocation_secret` to do
	/// so).
	fn sign_justice_revoked_output(&self, justice_tx: &Transaction, input: usize, amount: u64,
		per_commitment_key: &SecretKey, secp_ctx: &Secp256k1<secp256k1::All>,
	) -> Result<Signature, ()>;

	/// Create a signature for the given input in a transaction spending a commitment transaction
	/// HTLC output when our counterparty broadcasts an old state.
	///
	/// A justice transaction may claim multiple outputs at the same time if timelocks are
	/// similar, but only a signature for the input at index `input` should be signed for here.
	/// It may be called multiple times for same output(s) if a fee-bump is needed with regards
	/// to an upcoming timelock expiration.
	///
	/// `amount` is the value of the output spent by this input, committed to in the BIP 341
	/// signature.
	///
	/// `per_commitment_key` is revocation secret which was provided by our counterparty when they
	/// revoked the state which they eventually broadcast. It's not a _holder_ secret key and does
	/// not allow the spending of any funds by itself (you need our holder revocation_secret to do
	/// so).
	///
	/// `htlc` holds HTLC elements (hash, timelock), thus changing the format of the witness script
	/// (which is committed to in the BIP 341 signatures).
	fn sign_justice_revoked_htlc(&self, justice_tx: &Transaction, input: usize, amount: u64,
		per_commitment_key: &SecretKey, htlc: &HTLCOutputInCommitment,
		secp_ctx: &Secp256k1<secp256k1::All>) -> Result<Signature, ()>;

	/// Computes the signature for a commitment transaction's HTLC output used as an input within
	/// `htlc_tx`, which spends the commitment transaction at index `input`. The signature returned
	/// must be be computed using [`TapSighashType::Default`].
	///
	/// Note that this may be called for HTLCs in the penultimate commitment transaction if a
	/// [`ChannelMonitor`] [replica](https://github.com/lightningdevkit/rust-lightning/blob/main/GLOSSARY.md#monitor-replicas)
	/// broadcasts it before receiving the update for the latest commitment transaction.
	///
	///
	/// [`TapSighashType::Default`]: bitcoin::sighash::TapSighashType::Default
	/// [`ChannelMonitor`]: crate::chain::channelmonitor::ChannelMonitor
	fn sign_holder_htlc_transaction(&self, htlc_tx: &Transaction, input: usize,
		htlc_descriptor: &HTLCDescriptor, secp_ctx: &Secp256k1<secp256k1::All>,
	) -> Result<Signature, ()>;

	/// Create a signature for a claiming transaction for a HTLC output on a counterparty's commitment
	/// transaction, either offered or received.
	///
	/// Such a transaction may claim multiples offered outputs at same time if we know the
	/// preimage for each when we create it, but only the input at index `input` should be
	/// signed for here. It may be called multiple times for same output(s) if a fee-bump is
	/// needed with regards to an upcoming timelock expiration.
	///
	/// `witness_script` is either an offered or received script as defined in BOLT3 for HTLC
	/// outputs.
	///
	/// `amount` is value of the output spent by this input, committed to in the BIP 341 signature.
	///
	/// `per_commitment_point` is the dynamic point corresponding to the channel state
	/// detected onchain. It has been generated by our counterparty and is used to derive
	/// channel state keys, which are then included in the witness script and committed to in the
	/// BIP 341 signature.
	fn sign_counterparty_htlc_transaction(&self, htlc_tx: &Transaction, input: usize, amount: u64,
		per_commitment_point: &PublicKey, htlc: &HTLCOutputInCommitment,
		secp_ctx: &Secp256k1<secp256k1::All>) -> Result<Signature, ()>;

	/// Create a signature for a (proposed) closing transaction.
	///
	/// Note that, due to rounding, there may be one "missing" satoshi, and either party may have
	/// chosen to forgo their output as dust.
	fn partially_sign_closing_transaction(&self, closing_tx: &ClosingTransaction,
		secp_ctx: &Secp256k1<secp256k1::All>) -> Result<PartialSignature, ()>;

	/// Computes the signature for a commitment transaction's anchor output used as an
	/// input within `anchor_tx`, which spends the commitment transaction, at index `input`.
	fn sign_holder_anchor_input(
		&self, anchor_tx: &Transaction, input: usize, secp_ctx: &Secp256k1<secp256k1::All>,
	) -> Result<Signature, ()>;

	// TODO: sign channel announcement
}
