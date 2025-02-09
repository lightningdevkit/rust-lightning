//! Defines ECDSA-specific signer types.

use bitcoin::transaction::Transaction;

use bitcoin::secp256k1;
use bitcoin::secp256k1::ecdsa::Signature;
use bitcoin::secp256k1::Secp256k1;

use crate::ln::chan_utils::CommitmentTransaction;
use crate::ln::msgs::UnsignedChannelAnnouncement;
use crate::types::payment::PaymentPreimage;

#[allow(unused_imports)]
use crate::prelude::*;

use crate::sign::ChannelSigner;

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
		&self, commitment_tx: &CommitmentTransaction, inbound_htlc_preimages: Vec<PaymentPreimage>,
		outbound_htlc_preimages: Vec<PaymentPreimage>, secp_ctx: &Secp256k1<secp256k1::All>,
	) -> Result<(Signature, Vec<Signature>), ()>;
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
