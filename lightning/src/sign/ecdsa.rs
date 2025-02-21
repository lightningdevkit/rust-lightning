//! Defines ECDSA-specific signer types.

use bitcoin::transaction::Transaction;

use bitcoin::secp256k1;
use bitcoin::secp256k1::ecdsa::Signature;
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};

use crate::ln::chan_utils::{
	ClosingTransaction, CommitmentTransaction, HTLCOutputInCommitment, HolderCommitmentTransaction,
};
use crate::ln::msgs::UnsignedChannelAnnouncement;
use crate::types::payment::PaymentPreimage;

#[allow(unused_imports)]
use crate::prelude::*;

use crate::sign::{ChannelSigner, ChannelTransactionParameters, HTLCDescriptor};

/// A trait to sign Lightning channel transactions as described in
/// [BOLT 3](https://github.com/lightning/bolts/blob/master/03-transactions.md).
///
/// Signing services could be implemented on a hardware wallet and should implement signing
/// policies in order to be secure. Please refer to the [VLS Policy
/// Controls](https://gitlab.com/lightning-signer/validating-lightning-signer/-/blob/main/docs/policy-controls.md)
/// for an example of such policies.
///
/// Like [`ChannelSigner`], many of the methods allow errors to be returned to support async
/// signing. In such cases, the signing operation can be replayed by calling
/// [`ChannelManager::signer_unblocked`] or [`ChainMonitor::signer_unblocked`] (see individual
/// method documentation for which method should be called) once the result is ready, at which
/// point the channel operation will resume.
///
/// [`ChannelManager::signer_unblocked`]: crate::ln::channelmanager::ChannelManager::signer_unblocked
/// [`ChainMonitor::signer_unblocked`]: crate::chain::chainmonitor::ChainMonitor::signer_unblocked
pub trait EcdsaChannelSigner: ChannelSigner {
	/// Create a signature for a counterparty's commitment transaction and associated HTLC transactions.
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
	///
	/// An `Err` can be returned to signal that the signer is unavailable/cannot produce a valid
	/// signature and should be retried later. Once the signer is ready to provide a signature after
	/// previously returning an `Err`, [`ChannelManager::signer_unblocked`] must be called.
	///
	/// [`ChannelManager::signer_unblocked`]: crate::ln::channelmanager::ChannelManager::signer_unblocked
	fn sign_counterparty_commitment(
		&self, channel_parameters: &ChannelTransactionParameters,
		commitment_tx: &CommitmentTransaction, inbound_htlc_preimages: Vec<PaymentPreimage>,
		outbound_htlc_preimages: Vec<PaymentPreimage>, secp_ctx: &Secp256k1<secp256k1::All>,
	) -> Result<(Signature, Vec<Signature>), ()>;
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
	/// An `Err` can be returned to signal that the signer is unavailable/cannot produce a valid
	/// signature and should be retried later. Once the signer is ready to provide a signature after
	/// previously returning an `Err`, [`ChannelMonitor::signer_unblocked`] must be called on its
	/// monitor or [`ChainMonitor::signer_unblocked`] called to attempt unblocking all monitors.
	///
	/// [`ChannelMonitor::signer_unblocked`]: crate::chain::channelmonitor::ChannelMonitor::signer_unblocked
	/// [`ChainMonitor::signer_unblocked`]: crate::chain::chainmonitor::ChainMonitor::signer_unblocked
	fn sign_holder_commitment(
		&self, channel_parameters: &ChannelTransactionParameters,
		commitment_tx: &HolderCommitmentTransaction, secp_ctx: &Secp256k1<secp256k1::All>,
	) -> Result<Signature, ()>;
	/// Same as [`sign_holder_commitment`], but exists only for tests to get access to holder
	/// commitment transactions which will be broadcasted later, after the channel has moved on to a
	/// newer state. Thus, needs its own method as [`sign_holder_commitment`] may enforce that we
	/// only ever get called once.
	///
	/// This method is *not* async as it is intended only for testing purposes.
	#[cfg(any(test, feature = "unsafe_revoked_tx_signing"))]
	fn unsafe_sign_holder_commitment(
		&self, channel_parameters: &ChannelTransactionParameters,
		commitment_tx: &HolderCommitmentTransaction, secp_ctx: &Secp256k1<secp256k1::All>,
	) -> Result<Signature, ()>;
	/// Create a signature for the given input in a transaction spending an HTLC transaction output
	/// or a commitment transaction `to_local` output when our counterparty broadcasts an old state.
	///
	/// A justice transaction may claim multiple outputs at the same time if timelocks are
	/// similar, but only a signature for the input at index `input` should be signed for here.
	/// It may be called multiple times for same output(s) if a fee-bump is needed with regards
	/// to an upcoming timelock expiration.
	///
	/// Amount is value of the output spent by this input, committed to in the BIP 143 signature.
	///
	/// `per_commitment_key` is revocation secret which was provided by our counterparty when they
	/// revoked the state which they eventually broadcast. It's not a _holder_ secret key and does
	/// not allow the spending of any funds by itself (you need our holder `revocation_secret` to do
	/// so).
	///
	/// An `Err` can be returned to signal that the signer is unavailable/cannot produce a valid
	/// signature and should be retried later. Once the signer is ready to provide a signature after
	/// previously returning an `Err`, [`ChannelMonitor::signer_unblocked`] must be called on its
	/// monitor or [`ChainMonitor::signer_unblocked`] called to attempt unblocking all monitors.
	///
	/// [`ChannelMonitor::signer_unblocked`]: crate::chain::channelmonitor::ChannelMonitor::signer_unblocked
	/// [`ChainMonitor::signer_unblocked`]: crate::chain::chainmonitor::ChainMonitor::signer_unblocked
	fn sign_justice_revoked_output(
		&self, channel_parameters: &ChannelTransactionParameters, justice_tx: &Transaction,
		input: usize, amount: u64, per_commitment_key: &SecretKey,
		secp_ctx: &Secp256k1<secp256k1::All>,
	) -> Result<Signature, ()>;
	/// Create a signature for the given input in a transaction spending a commitment transaction
	/// HTLC output when our counterparty broadcasts an old state.
	///
	/// A justice transaction may claim multiple outputs at the same time if timelocks are
	/// similar, but only a signature for the input at index `input` should be signed for here.
	/// It may be called multiple times for same output(s) if a fee-bump is needed with regards
	/// to an upcoming timelock expiration.
	///
	/// `amount` is the value of the output spent by this input, committed to in the BIP 143
	/// signature.
	///
	/// `per_commitment_key` is revocation secret which was provided by our counterparty when they
	/// revoked the state which they eventually broadcast. It's not a _holder_ secret key and does
	/// not allow the spending of any funds by itself (you need our holder revocation_secret to do
	/// so).
	///
	/// `htlc` holds HTLC elements (hash, timelock), thus changing the format of the witness script
	/// (which is committed to in the BIP 143 signatures).
	///
	/// An `Err` can be returned to signal that the signer is unavailable/cannot produce a valid
	/// signature and should be retried later. Once the signer is ready to provide a signature after
	/// previously returning an `Err`, [`ChannelMonitor::signer_unblocked`] must be called on its
	/// monitor or [`ChainMonitor::signer_unblocked`] called to attempt unblocking all monitors.
	///
	/// [`ChannelMonitor::signer_unblocked`]: crate::chain::channelmonitor::ChannelMonitor::signer_unblocked
	/// [`ChainMonitor::signer_unblocked`]: crate::chain::chainmonitor::ChainMonitor::signer_unblocked
	fn sign_justice_revoked_htlc(
		&self, channel_parameters: &ChannelTransactionParameters, justice_tx: &Transaction,
		input: usize, amount: u64, per_commitment_key: &SecretKey, htlc: &HTLCOutputInCommitment,
		secp_ctx: &Secp256k1<secp256k1::All>,
	) -> Result<Signature, ()>;
	/// Computes the signature for a commitment transaction's HTLC output used as an input within
	/// `htlc_tx`, which spends the commitment transaction at index `input`. The signature returned
	/// must be be computed using [`EcdsaSighashType::All`].
	///
	/// Note that this may be called for HTLCs in the penultimate commitment transaction if a
	/// [`ChannelMonitor`] [replica](https://github.com/lightningdevkit/rust-lightning/blob/main/GLOSSARY.md#monitor-replicas)
	/// broadcasts it before receiving the update for the latest commitment transaction.
	///
	/// An `Err` can be returned to signal that the signer is unavailable/cannot produce a valid
	/// signature and should be retried later. Once the signer is ready to provide a signature after
	/// previously returning an `Err`, [`ChannelMonitor::signer_unblocked`] must be called on its
	/// monitor or [`ChainMonitor::signer_unblocked`] called to attempt unblocking all monitors.
	///
	/// [`EcdsaSighashType::All`]: bitcoin::sighash::EcdsaSighashType::All
	/// [`ChannelMonitor`]: crate::chain::channelmonitor::ChannelMonitor
	/// [`ChannelMonitor::signer_unblocked`]: crate::chain::channelmonitor::ChannelMonitor::signer_unblocked
	/// [`ChainMonitor::signer_unblocked`]: crate::chain::chainmonitor::ChainMonitor::signer_unblocked
	fn sign_holder_htlc_transaction(
		&self, htlc_tx: &Transaction, input: usize, htlc_descriptor: &HTLCDescriptor,
		secp_ctx: &Secp256k1<secp256k1::All>,
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
	/// `amount` is value of the output spent by this input, committed to in the BIP 143 signature.
	///
	/// `per_commitment_point` is the dynamic point corresponding to the channel state
	/// detected onchain. It has been generated by our counterparty and is used to derive
	/// channel state keys, which are then included in the witness script and committed to in the
	/// BIP 143 signature.
	///
	/// An `Err` can be returned to signal that the signer is unavailable/cannot produce a valid
	/// signature and should be retried later. Once the signer is ready to provide a signature after
	/// previously returning an `Err`, [`ChannelMonitor::signer_unblocked`] must be called on its
	/// monitor or [`ChainMonitor::signer_unblocked`] called to attempt unblocking all monitors.
	///
	/// [`ChannelMonitor::signer_unblocked`]: crate::chain::channelmonitor::ChannelMonitor::signer_unblocked
	/// [`ChainMonitor::signer_unblocked`]: crate::chain::chainmonitor::ChainMonitor::signer_unblocked
	fn sign_counterparty_htlc_transaction(
		&self, channel_parameters: &ChannelTransactionParameters, htlc_tx: &Transaction,
		input: usize, amount: u64, per_commitment_point: &PublicKey, htlc: &HTLCOutputInCommitment,
		secp_ctx: &Secp256k1<secp256k1::All>,
	) -> Result<Signature, ()>;
	/// Create a signature for a (proposed) closing transaction.
	///
	/// Note that, due to rounding, there may be one "missing" satoshi, and either party may have
	/// chosen to forgo their output as dust.
	///
	/// An `Err` can be returned to signal that the signer is unavailable/cannot produce a valid
	/// signature and should be retried later. Once the signer is ready to provide a signature after
	/// previously returning an `Err`, [`ChannelManager::signer_unblocked`] must be called.
	///
	/// [`ChannelManager::signer_unblocked`]: crate::ln::channelmanager::ChannelManager::signer_unblocked
	fn sign_closing_transaction(
		&self, channel_parameters: &ChannelTransactionParameters, closing_tx: &ClosingTransaction,
		secp_ctx: &Secp256k1<secp256k1::All>,
	) -> Result<Signature, ()>;
	/// Computes the signature for a commitment transaction's anchor output used as an
	/// input within `anchor_tx`, which spends the commitment transaction, at index `input`.
	///
	/// An `Err` can be returned to signal that the signer is unavailable/cannot produce a valid
	/// signature and should be retried later. Once the signer is ready to provide a signature after
	/// previously returning an `Err`, [`ChannelMonitor::signer_unblocked`] must be called on its
	/// monitor or [`ChainMonitor::signer_unblocked`] called to attempt unblocking all monitors.
	///
	/// [`ChannelMonitor::signer_unblocked`]: crate::chain::channelmonitor::ChannelMonitor::signer_unblocked
	/// [`ChainMonitor::signer_unblocked`]: crate::chain::chainmonitor::ChainMonitor::signer_unblocked
	fn sign_holder_anchor_input(
		&self, anchor_tx: &Transaction, input: usize, secp_ctx: &Secp256k1<secp256k1::All>,
	) -> Result<Signature, ()>;
	/// Signs a channel announcement message with our funding key proving it comes from one of the
	/// channel participants.
	///
	/// Channel announcements also require a signature from each node's network key. Our node
	/// signature is computed through [`NodeSigner::sign_gossip_message`].
	///
	/// This method is *not* asynchronous. If an `Err` is returned, the channel will not be
	/// publicly announced and our counterparty may (though likely will not) close the channel on
	/// us for violating the protocol.
	///
	/// [`NodeSigner::sign_gossip_message`]: crate::sign::NodeSigner::sign_gossip_message
	fn sign_channel_announcement_with_funding_key(
		&self, msg: &UnsignedChannelAnnouncement, secp_ctx: &Secp256k1<secp256k1::All>,
	) -> Result<Signature, ()>;

	/// Signs the input of a splicing funding transaction with our funding key.
	///
	/// In splicing, the previous funding transaction output is spent as the input of
	/// the new funding transaction, and is a 2-of-2 multisig.
	///
	/// `input_index`: The index of the input within the new funding transaction `tx`,
	///    spending the previous funding transaction's output
	///
	/// `input_value`: The value of the previous funding transaction output.
	///
	/// This method is *not* asynchronous. If an `Err` is returned, the channel will be immediately
	/// closed.
	fn sign_splicing_funding_input(
		&self, tx: &Transaction, input_index: usize, input_value: u64,
		secp_ctx: &Secp256k1<secp256k1::All>,
	) -> Result<Signature, ()>;
}
