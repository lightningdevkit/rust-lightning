// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Events are returned from various bits in the library which indicate some action must be taken
//! by the client.
//!
//! Because we don't have a built-in runtime, it's up to the client to call events at a time in the
//! future, as well as generate and broadcast funding transactions handle payment preimages and a
//! few other things.

use crate::chain::keysinterface::SpendableOutputDescriptor;
#[cfg(anchors)]
use crate::ln::chan_utils::{self, ChannelTransactionParameters, HTLCOutputInCommitment};
use crate::ln::channelmanager::{InterceptId, PaymentId};
use crate::ln::channel::FUNDING_CONF_DEADLINE_BLOCKS;
use crate::ln::features::ChannelTypeFeatures;
use crate::ln::msgs;
use crate::ln::{PaymentPreimage, PaymentHash, PaymentSecret};
use crate::routing::gossip::NetworkUpdate;
use crate::util::errors::APIError;
use crate::util::ser::{BigSize, FixedLengthReader, Writeable, Writer, MaybeReadable, Readable, RequiredWrapper, UpgradableRequired, WithoutLength};
use crate::routing::router::{RouteHop, RouteParameters};

use bitcoin::{PackedLockTime, Transaction};
#[cfg(anchors)]
use bitcoin::{OutPoint, Txid, TxIn, TxOut, Witness};
use bitcoin::blockdata::script::Script;
use bitcoin::hashes::Hash;
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::secp256k1::PublicKey;
#[cfg(anchors)]
use bitcoin::secp256k1::{self, Secp256k1};
#[cfg(anchors)]
use bitcoin::secp256k1::ecdsa::Signature;
use crate::io;
use crate::prelude::*;
use core::time::Duration;
use core::ops::Deref;
use crate::sync::Arc;

/// Some information provided on receipt of payment depends on whether the payment received is a
/// spontaneous payment or a "conventional" lightning payment that's paying an invoice.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PaymentPurpose {
	/// Information for receiving a payment that we generated an invoice for.
	InvoicePayment {
		/// The preimage to the payment_hash, if the payment hash (and secret) were fetched via
		/// [`ChannelManager::create_inbound_payment`]. If provided, this can be handed directly to
		/// [`ChannelManager::claim_funds`].
		///
		/// [`ChannelManager::create_inbound_payment`]: crate::ln::channelmanager::ChannelManager::create_inbound_payment
		/// [`ChannelManager::claim_funds`]: crate::ln::channelmanager::ChannelManager::claim_funds
		payment_preimage: Option<PaymentPreimage>,
		/// The "payment secret". This authenticates the sender to the recipient, preventing a
		/// number of deanonymization attacks during the routing process.
		/// It is provided here for your reference, however its accuracy is enforced directly by
		/// [`ChannelManager`] using the values you previously provided to
		/// [`ChannelManager::create_inbound_payment`] or
		/// [`ChannelManager::create_inbound_payment_for_hash`].
		///
		/// [`ChannelManager`]: crate::ln::channelmanager::ChannelManager
		/// [`ChannelManager::create_inbound_payment`]: crate::ln::channelmanager::ChannelManager::create_inbound_payment
		/// [`ChannelManager::create_inbound_payment_for_hash`]: crate::ln::channelmanager::ChannelManager::create_inbound_payment_for_hash
		payment_secret: PaymentSecret,
	},
	/// Because this is a spontaneous payment, the payer generated their own preimage rather than us
	/// (the payee) providing a preimage.
	SpontaneousPayment(PaymentPreimage),
}

impl_writeable_tlv_based_enum!(PaymentPurpose,
	(0, InvoicePayment) => {
		(0, payment_preimage, option),
		(2, payment_secret, required),
	};
	(2, SpontaneousPayment)
);

/// When the payment path failure took place and extra details about it. [`PathFailure::OnPath`] may
/// contain a [`NetworkUpdate`] that needs to be applied to the [`NetworkGraph`].
///
/// [`NetworkUpdate`]: crate::routing::gossip::NetworkUpdate
/// [`NetworkGraph`]: crate::routing::gossip::NetworkGraph
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PathFailure {
	/// We failed to initially send the payment and no HTLC was committed to. Contains the relevant
	/// error.
	InitialSend {
		/// The error surfaced from initial send.
		err: APIError,
	},
	/// A hop on the path failed to forward our payment.
	OnPath {
		/// If present, this [`NetworkUpdate`] should be applied to the [`NetworkGraph`] so that routing
		/// decisions can take into account the update.
		///
		/// [`NetworkUpdate`]: crate::routing::gossip::NetworkUpdate
		/// [`NetworkGraph`]: crate::routing::gossip::NetworkGraph
		network_update: Option<NetworkUpdate>,
	},
}

impl_writeable_tlv_based_enum_upgradable!(PathFailure,
	(0, OnPath) => {
		(0, network_update, upgradable_option),
	},
	(2, InitialSend) => {
		(0, err, upgradable_required),
	},
);

#[derive(Clone, Debug, PartialEq, Eq)]
/// The reason the channel was closed. See individual variants more details.
pub enum ClosureReason {
	/// Closure generated from receiving a peer error message.
	///
	/// Our counterparty may have broadcasted their latest commitment state, and we have
	/// as well.
	CounterpartyForceClosed {
		/// The error which the peer sent us.
		///
		/// The string should be sanitized before it is used (e.g emitted to logs
		/// or printed to stdout). Otherwise, a well crafted error message may exploit
		/// a security vulnerability in the terminal emulator or the logging subsystem.
		peer_msg: String,
	},
	/// Closure generated from [`ChannelManager::force_close_channel`], called by the user.
	///
	/// [`ChannelManager::force_close_channel`]: crate::ln::channelmanager::ChannelManager::force_close_channel.
	HolderForceClosed,
	/// The channel was closed after negotiating a cooperative close and we've now broadcasted
	/// the cooperative close transaction. Note the shutdown may have been initiated by us.
	//TODO: split between CounterpartyInitiated/LocallyInitiated
	CooperativeClosure,
	/// A commitment transaction was confirmed on chain, closing the channel. Most likely this
	/// commitment transaction came from our counterparty, but it may also have come from
	/// a copy of our own `ChannelMonitor`.
	CommitmentTxConfirmed,
	/// The funding transaction failed to confirm in a timely manner on an inbound channel.
	FundingTimedOut,
	/// Closure generated from processing an event, likely a HTLC forward/relay/reception.
	ProcessingError {
		/// A developer-readable error message which we generated.
		err: String,
	},
	/// The peer disconnected prior to funding completing. In this case the spec mandates that we
	/// forget the channel entirely - we can attempt again if the peer reconnects.
	///
	/// This includes cases where we restarted prior to funding completion, including prior to the
	/// initial [`ChannelMonitor`] persistence completing.
	///
	/// In LDK versions prior to 0.0.107 this could also occur if we were unable to connect to the
	/// peer because of mutual incompatibility between us and our channel counterparty.
	///
	/// [`ChannelMonitor`]: crate::chain::channelmonitor::ChannelMonitor
	DisconnectedPeer,
	/// Closure generated from `ChannelManager::read` if the [`ChannelMonitor`] is newer than
	/// the [`ChannelManager`] deserialized.
	///
	/// [`ChannelMonitor`]: crate::chain::channelmonitor::ChannelMonitor
	/// [`ChannelManager`]: crate::ln::channelmanager::ChannelManager
	OutdatedChannelManager
}

impl core::fmt::Display for ClosureReason {
	fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
		f.write_str("Channel closed because ")?;
		match self {
			ClosureReason::CounterpartyForceClosed { peer_msg } => {
				f.write_str("counterparty force-closed with message ")?;
				f.write_str(&peer_msg)
			},
			ClosureReason::HolderForceClosed => f.write_str("user manually force-closed the channel"),
			ClosureReason::CooperativeClosure => f.write_str("the channel was cooperatively closed"),
			ClosureReason::CommitmentTxConfirmed => f.write_str("commitment or closing transaction was confirmed on chain."),
			ClosureReason::FundingTimedOut => write!(f, "funding transaction failed to confirm within {} blocks", FUNDING_CONF_DEADLINE_BLOCKS),
			ClosureReason::ProcessingError { err } => {
				f.write_str("of an exception: ")?;
				f.write_str(&err)
			},
			ClosureReason::DisconnectedPeer => f.write_str("the peer disconnected prior to the channel being funded"),
			ClosureReason::OutdatedChannelManager => f.write_str("the ChannelManager read from disk was stale compared to ChannelMonitor(s)"),
		}
	}
}

impl_writeable_tlv_based_enum_upgradable!(ClosureReason,
	(0, CounterpartyForceClosed) => { (1, peer_msg, required) },
	(1, FundingTimedOut) => {},
	(2, HolderForceClosed) => {},
	(6, CommitmentTxConfirmed) => {},
	(4, CooperativeClosure) => {},
	(8, ProcessingError) => { (1, err, required) },
	(10, DisconnectedPeer) => {},
	(12, OutdatedChannelManager) => {},
);

/// Intended destination of a failed HTLC as indicated in [`Event::HTLCHandlingFailed`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HTLCDestination {
	/// We tried forwarding to a channel but failed to do so. An example of such an instance is when
	/// there is insufficient capacity in our outbound channel.
	NextHopChannel {
		/// The `node_id` of the next node. For backwards compatibility, this field is
		/// marked as optional, versions prior to 0.0.110 may not always be able to provide
		/// counterparty node information.
		node_id: Option<PublicKey>,
		/// The outgoing `channel_id` between us and the next node.
		channel_id: [u8; 32],
	},
	/// Scenario where we are unsure of the next node to forward the HTLC to.
	UnknownNextHop {
		/// Short channel id we are requesting to forward an HTLC to.
		requested_forward_scid: u64,
	},
	/// We couldn't forward to the outgoing scid. An example would be attempting to send a duplicate
	/// intercept HTLC.
	InvalidForward {
		/// Short channel id we are requesting to forward an HTLC to.
		requested_forward_scid: u64
	},
	/// Failure scenario where an HTLC may have been forwarded to be intended for us,
	/// but is invalid for some reason, so we reject it.
	///
	/// Some of the reasons may include:
	/// * HTLC Timeouts
	/// * Expected MPP amount to claim does not equal HTLC total
	/// * Claimable amount does not match expected amount
	FailedPayment {
		/// The payment hash of the payment we attempted to process.
		payment_hash: PaymentHash
	},
}

impl_writeable_tlv_based_enum_upgradable!(HTLCDestination,
	(0, NextHopChannel) => {
		(0, node_id, required),
		(2, channel_id, required),
	},
	(1, InvalidForward) => {
		(0, requested_forward_scid, required),
	},
	(2, UnknownNextHop) => {
		(0, requested_forward_scid, required),
	},
	(4, FailedPayment) => {
		(0, payment_hash, required),
	},
);

#[cfg(anchors)]
/// A descriptor used to sign for a commitment transaction's anchor output.
#[derive(Clone, Debug)]
pub struct AnchorDescriptor {
	/// A unique identifier used along with `channel_value_satoshis` to re-derive the
	/// [`InMemorySigner`] required to sign `input`.
	///
	/// [`InMemorySigner`]: crate::chain::keysinterface::InMemorySigner
	pub channel_keys_id: [u8; 32],
	/// The value in satoshis of the channel we're attempting to spend the anchor output of. This is
	/// used along with `channel_keys_id` to re-derive the [`InMemorySigner`] required to sign
	/// `input`.
	///
	/// [`InMemorySigner`]: crate::chain::keysinterface::InMemorySigner
	pub channel_value_satoshis: u64,
	/// The transaction input's outpoint corresponding to the commitment transaction's anchor
	/// output.
	pub outpoint: OutPoint,
}

#[cfg(anchors)]
/// A descriptor used to sign for a commitment transaction's HTLC output.
#[derive(Clone, Debug)]
pub struct HTLCDescriptor {
	/// A unique identifier used along with `channel_value_satoshis` to re-derive the
	/// [`InMemorySigner`] required to sign `input`.
	///
	/// [`InMemorySigner`]: crate::chain::keysinterface::InMemorySigner
	pub channel_keys_id: [u8; 32],
	/// The value in satoshis of the channel we're attempting to spend the anchor output of. This is
	/// used along with `channel_keys_id` to re-derive the [`InMemorySigner`] required to sign
	/// `input`.
	///
	/// [`InMemorySigner`]: crate::chain::keysinterface::InMemorySigner
	pub channel_value_satoshis: u64,
	/// The necessary channel parameters that need to be provided to the re-derived
	/// [`InMemorySigner`] through [`BaseSign::provide_channel_parameters`].
	///
	/// [`InMemorySigner`]: crate::chain::keysinterface::InMemorySigner
	/// [`BaseSign::provide_channel_parameters`]: crate::chain::keysinterface::BaseSign::provide_channel_parameters
	pub channel_parameters: ChannelTransactionParameters,
	/// The txid of the commitment transaction in which the HTLC output lives.
	pub commitment_txid: Txid,
	/// The number of the commitment transaction in which the HTLC output lives.
	pub per_commitment_number: u64,
	/// The details of the HTLC as it appears in the commitment transaction.
	pub htlc: HTLCOutputInCommitment,
	/// The preimage, if `Some`, to claim the HTLC output with. If `None`, the timeout path must be
	/// taken.
	pub preimage: Option<PaymentPreimage>,
	/// The counterparty's signature required to spend the HTLC output.
	pub counterparty_sig: Signature
}

#[cfg(anchors)]
impl HTLCDescriptor {
	/// Returns the unsigned transaction input spending the HTLC output in the commitment
	/// transaction.
	pub fn unsigned_tx_input(&self) -> TxIn {
		chan_utils::build_htlc_input(&self.commitment_txid, &self.htlc, true /* opt_anchors */)
	}

	/// Returns the delayed output created as a result of spending the HTLC output in the commitment
	/// transaction.
	pub fn tx_output<C: secp256k1::Signing + secp256k1::Verification>(
		&self, per_commitment_point: &PublicKey, secp: &Secp256k1<C>
	) -> TxOut {
		let channel_params = self.channel_parameters.as_holder_broadcastable();
		let broadcaster_keys = channel_params.broadcaster_pubkeys();
		let counterparty_keys = channel_params.countersignatory_pubkeys();
		let broadcaster_delayed_key = chan_utils::derive_public_key(
			secp, per_commitment_point, &broadcaster_keys.delayed_payment_basepoint
		);
		let counterparty_revocation_key = chan_utils::derive_public_revocation_key(
			secp, per_commitment_point, &counterparty_keys.revocation_basepoint
		);
		chan_utils::build_htlc_output(
			0 /* feerate_per_kw */, channel_params.contest_delay(), &self.htlc, true /* opt_anchors */,
			false /* use_non_zero_fee_anchors */, &broadcaster_delayed_key, &counterparty_revocation_key
		)
	}

	/// Returns the witness script of the HTLC output in the commitment transaction.
	pub fn witness_script<C: secp256k1::Signing + secp256k1::Verification>(
		&self, per_commitment_point: &PublicKey, secp: &Secp256k1<C>
	) -> Script {
		let channel_params = self.channel_parameters.as_holder_broadcastable();
		let broadcaster_keys = channel_params.broadcaster_pubkeys();
		let counterparty_keys = channel_params.countersignatory_pubkeys();
		let broadcaster_htlc_key = chan_utils::derive_public_key(
			secp, per_commitment_point, &broadcaster_keys.htlc_basepoint
		);
		let counterparty_htlc_key = chan_utils::derive_public_key(
			secp, per_commitment_point, &counterparty_keys.htlc_basepoint
		);
		let counterparty_revocation_key = chan_utils::derive_public_revocation_key(
			secp, per_commitment_point, &counterparty_keys.revocation_basepoint
		);
		chan_utils::get_htlc_redeemscript_with_explicit_keys(
			&self.htlc, true /* opt_anchors */, &broadcaster_htlc_key, &counterparty_htlc_key,
			&counterparty_revocation_key,
		)
	}

	/// Returns the fully signed witness required to spend the HTLC output in the commitment
	/// transaction.
	pub fn tx_input_witness(&self, signature: &Signature, witness_script: &Script) -> Witness {
		chan_utils::build_htlc_input_witness(
			signature, &self.counterparty_sig, &self.preimage, witness_script, true /* opt_anchors */
		)
	}
}

#[cfg(anchors)]
/// Represents the different types of transactions, originating from LDK, to be bumped.
#[derive(Clone, Debug)]
pub enum BumpTransactionEvent {
	/// Indicates that a channel featuring anchor outputs is to be closed by broadcasting the local
	/// commitment transaction. Since commitment transactions have a static feerate pre-agreed upon,
	/// they may need additional fees to be attached through a child transaction using the popular
	/// [Child-Pays-For-Parent](https://bitcoinops.org/en/topics/cpfp) fee bumping technique. This
	/// child transaction must include the anchor input described within `anchor_descriptor` along
	/// with additional inputs to meet the target feerate. Failure to meet the target feerate
	/// decreases the confirmation odds of the transaction package (which includes the commitment
	/// and child anchor transactions), possibly resulting in a loss of funds. Once the transaction
	/// is constructed, it must be fully signed for and broadcast by the consumer of the event
	/// along with the `commitment_tx` enclosed. Note that the `commitment_tx` must always be
	/// broadcast first, as the child anchor transaction depends on it.
	///
	/// The consumer should be able to sign for any of the additional inputs included within the
	/// child anchor transaction. To sign its anchor input, an [`InMemorySigner`] should be
	/// re-derived through [`KeysManager::derive_channel_keys`] with the help of
	/// [`AnchorDescriptor::channel_keys_id`] and [`AnchorDescriptor::channel_value_satoshis`]. The
	/// anchor input signature can be computed with [`BaseSign::sign_holder_anchor_input`],
	/// which can then be provided to [`build_anchor_input_witness`] along with the `funding_pubkey`
	/// to obtain the full witness required to spend.
	///
	/// It is possible to receive more than one instance of this event if a valid child anchor
	/// transaction is never broadcast or is but not with a sufficient fee to be mined. Care should
	/// be taken by the consumer of the event to ensure any future iterations of the child anchor
	/// transaction adhere to the [Replace-By-Fee
	/// rules](https://github.com/bitcoin/bitcoin/blob/master/doc/policy/mempool-replacements.md)
	/// for fee bumps to be accepted into the mempool, and eventually the chain. As the frequency of
	/// these events is not user-controlled, users may ignore/drop the event if they are no longer
	/// able to commit external confirmed funds to the child anchor transaction.
	///
	/// The set of `pending_htlcs` on the commitment transaction to be broadcast can be inspected to
	/// determine whether a significant portion of the channel's funds are allocated to HTLCs,
	/// enabling users to make their own decisions regarding the importance of the commitment
	/// transaction's confirmation. Note that this is not required, but simply exists as an option
	/// for users to override LDK's behavior. On commitments with no HTLCs (indicated by those with
	/// an empty `pending_htlcs`), confirmation of the commitment transaction can be considered to
	/// be not urgent.
	///
	/// [`InMemorySigner`]: crate::chain::keysinterface::InMemorySigner
	/// [`KeysManager::derive_channel_keys`]: crate::chain::keysinterface::KeysManager::derive_channel_keys
	/// [`BaseSign::sign_holder_anchor_input`]: crate::chain::keysinterface::BaseSign::sign_holder_anchor_input
	/// [`build_anchor_input_witness`]: crate::ln::chan_utils::build_anchor_input_witness
	ChannelClose {
		/// The target feerate that the transaction package, which consists of the commitment
		/// transaction and the to-be-crafted child anchor transaction, must meet.
		package_target_feerate_sat_per_1000_weight: u32,
		/// The channel's commitment transaction to bump the fee of. This transaction should be
		/// broadcast along with the anchor transaction constructed as a result of consuming this
		/// event.
		commitment_tx: Transaction,
		/// The absolute fee in satoshis of the commitment transaction. This can be used along the
		/// with weight of the commitment transaction to determine its feerate.
		commitment_tx_fee_satoshis: u64,
		/// The descriptor to sign the anchor input of the anchor transaction constructed as a
		/// result of consuming this event.
		anchor_descriptor: AnchorDescriptor,
		/// The set of pending HTLCs on the commitment transaction that need to be resolved once the
		/// commitment transaction confirms.
		pending_htlcs: Vec<HTLCOutputInCommitment>,
	},
	/// Indicates that a channel featuring anchor outputs has unilaterally closed on-chain by a
	/// holder commitment transaction and its HTLC(s) need to be resolved on-chain. With the
	/// zero-HTLC-transaction-fee variant of anchor outputs, the pre-signed HTLC
	/// transactions have a zero fee, thus requiring additional inputs and/or outputs to be attached
	/// for a timely confirmation within the chain. These additional inputs and/or outputs must be
	/// appended to the resulting HTLC transaction to meet the target feerate. Failure to meet the
	/// target feerate decreases the confirmation odds of the transaction, possibly resulting in a
	/// loss of funds. Once the transaction meets the target feerate, it must be signed for and
	/// broadcast by the consumer of the event.
	///
	/// The consumer should be able to sign for any of the non-HTLC inputs added to the resulting
	/// HTLC transaction. To sign HTLC inputs, an [`InMemorySigner`] should be re-derived through
	/// [`KeysManager::derive_channel_keys`] with the help of `channel_keys_id` and
	/// `channel_value_satoshis`. Each HTLC input's signature can be computed with
	/// [`BaseSign::sign_holder_htlc_transaction`], which can then be provided to
	/// [`HTLCDescriptor::tx_input_witness`] to obtain the fully signed witness required to spend.
	///
	/// It is possible to receive more than one instance of this event if a valid HTLC transaction
	/// is never broadcast or is but not with a sufficient fee to be mined. Care should be taken by
	/// the consumer of the event to ensure any future iterations of the HTLC transaction adhere to
	/// the [Replace-By-Fee
	/// rules](https://github.com/bitcoin/bitcoin/blob/master/doc/policy/mempool-replacements.md)
	/// for fee bumps to be accepted into the mempool, and eventually the chain. As the frequency of
	/// these events is not user-controlled, users may ignore/drop the event if either they are no
	/// longer able to commit external confirmed funds to the HTLC transaction or the fee committed
	/// to the HTLC transaction is greater in value than the HTLCs being claimed.
	///
	/// [`InMemorySigner`]: crate::chain::keysinterface::InMemorySigner
	/// [`KeysManager::derive_channel_keys`]: crate::chain::keysinterface::KeysManager::derive_channel_keys
	/// [`BaseSign::sign_holder_htlc_transaction`]: crate::chain::keysinterface::BaseSign::sign_holder_htlc_transaction
	/// [`HTLCDescriptor::tx_input_witness`]: HTLCDescriptor::tx_input_witness
	HTLCResolution {
		target_feerate_sat_per_1000_weight: u32,
		htlc_descriptors: Vec<HTLCDescriptor>,
	},
}

/// Will be used in [`Event::HTLCIntercepted`] to identify the next hop in the HTLC's path.
/// Currently only used in serialization for the sake of maintaining compatibility. More variants
/// will be added for general-purpose HTLC forward intercepts as well as trampoline forward
/// intercepts in upcoming work.
enum InterceptNextHop {
	FakeScid {
		requested_next_hop_scid: u64,
	},
}

impl_writeable_tlv_based_enum!(InterceptNextHop,
	(0, FakeScid) => {
		(0, requested_next_hop_scid, required),
	};
);

/// An Event which you should probably take some action in response to.
///
/// Note that while Writeable and Readable are implemented for Event, you probably shouldn't use
/// them directly as they don't round-trip exactly (for example FundingGenerationReady is never
/// written as it makes no sense to respond to it after reconnecting to peers).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
	/// Used to indicate that the client should generate a funding transaction with the given
	/// parameters and then call [`ChannelManager::funding_transaction_generated`].
	/// Generated in [`ChannelManager`] message handling.
	/// Note that *all inputs* in the funding transaction must spend SegWit outputs or your
	/// counterparty can steal your funds!
	///
	/// [`ChannelManager`]: crate::ln::channelmanager::ChannelManager
	/// [`ChannelManager::funding_transaction_generated`]: crate::ln::channelmanager::ChannelManager::funding_transaction_generated
	FundingGenerationReady {
		/// The random channel_id we picked which you'll need to pass into
		/// [`ChannelManager::funding_transaction_generated`].
		///
		/// [`ChannelManager::funding_transaction_generated`]: crate::ln::channelmanager::ChannelManager::funding_transaction_generated
		temporary_channel_id: [u8; 32],
		/// The counterparty's node_id, which you'll need to pass back into
		/// [`ChannelManager::funding_transaction_generated`].
		///
		/// [`ChannelManager::funding_transaction_generated`]: crate::ln::channelmanager::ChannelManager::funding_transaction_generated
		counterparty_node_id: PublicKey,
		/// The value, in satoshis, that the output should have.
		channel_value_satoshis: u64,
		/// The script which should be used in the transaction output.
		output_script: Script,
		/// The `user_channel_id` value passed in to [`ChannelManager::create_channel`], or a
		/// random value for an inbound channel. This may be zero for objects serialized with LDK
		/// versions prior to 0.0.113.
		///
		/// [`ChannelManager::create_channel`]: crate::ln::channelmanager::ChannelManager::create_channel
		user_channel_id: u128,
	},
	/// Indicates that we've been offered a payment and it needs to be claimed via calling
	/// [`ChannelManager::claim_funds`] with the preimage given in [`PaymentPurpose`].
	///
	/// Note that if the preimage is not known, you should call
	/// [`ChannelManager::fail_htlc_backwards`] or [`ChannelManager::fail_htlc_backwards_with_reason`]
	/// to free up resources for this HTLC and avoid network congestion.
	/// If you fail to call either [`ChannelManager::claim_funds`], [`ChannelManager::fail_htlc_backwards`],
	/// or [`ChannelManager::fail_htlc_backwards_with_reason`] within the HTLC's timeout, the HTLC will be
	/// automatically failed.
	///
	/// # Note
	/// LDK will not stop an inbound payment from being paid multiple times, so multiple
	/// `PaymentClaimable` events may be generated for the same payment.
	///
	/// # Note
	/// This event used to be called `PaymentReceived` in LDK versions 0.0.112 and earlier.
	///
	/// [`ChannelManager::claim_funds`]: crate::ln::channelmanager::ChannelManager::claim_funds
	/// [`ChannelManager::fail_htlc_backwards`]: crate::ln::channelmanager::ChannelManager::fail_htlc_backwards
	/// [`ChannelManager::fail_htlc_backwards_with_reason`]: crate::ln::channelmanager::ChannelManager::fail_htlc_backwards_with_reason
	PaymentClaimable {
		/// The node that will receive the payment after it has been claimed.
		/// This is useful to identify payments received via [phantom nodes].
		/// This field will always be filled in when the event was generated by LDK versions
		/// 0.0.113 and above.
		///
		/// [phantom nodes]: crate::chain::keysinterface::PhantomKeysManager
		receiver_node_id: Option<PublicKey>,
		/// The hash for which the preimage should be handed to the ChannelManager. Note that LDK will
		/// not stop you from registering duplicate payment hashes for inbound payments.
		payment_hash: PaymentHash,
		/// The value, in thousandths of a satoshi, that this payment is for.
		amount_msat: u64,
		/// Information for claiming this received payment, based on whether the purpose of the
		/// payment is to pay an invoice or to send a spontaneous payment.
		purpose: PaymentPurpose,
		/// The `channel_id` indicating over which channel we received the payment.
		via_channel_id: Option<[u8; 32]>,
		/// The `user_channel_id` indicating over which channel we received the payment.
		via_user_channel_id: Option<u128>,
	},
	/// Indicates a payment has been claimed and we've received money!
	///
	/// This most likely occurs when [`ChannelManager::claim_funds`] has been called in response
	/// to an [`Event::PaymentClaimable`]. However, if we previously crashed during a
	/// [`ChannelManager::claim_funds`] call you may see this event without a corresponding
	/// [`Event::PaymentClaimable`] event.
	///
	/// # Note
	/// LDK will not stop an inbound payment from being paid multiple times, so multiple
	/// `PaymentClaimable` events may be generated for the same payment. If you then call
	/// [`ChannelManager::claim_funds`] twice for the same [`Event::PaymentClaimable`] you may get
	/// multiple `PaymentClaimed` events.
	///
	/// [`ChannelManager::claim_funds`]: crate::ln::channelmanager::ChannelManager::claim_funds
	PaymentClaimed {
		/// The node that received the payment.
		/// This is useful to identify payments which were received via [phantom nodes].
		/// This field will always be filled in when the event was generated by LDK versions
		/// 0.0.113 and above.
		///
		/// [phantom nodes]: crate::chain::keysinterface::PhantomKeysManager
		receiver_node_id: Option<PublicKey>,
		/// The payment hash of the claimed payment. Note that LDK will not stop you from
		/// registering duplicate payment hashes for inbound payments.
		payment_hash: PaymentHash,
		/// The value, in thousandths of a satoshi, that this payment is for.
		amount_msat: u64,
		/// The purpose of the claimed payment, i.e. whether the payment was for an invoice or a
		/// spontaneous payment.
		purpose: PaymentPurpose,
	},
	/// Indicates an outbound payment we made succeeded (i.e. it made it all the way to its target
	/// and we got back the payment preimage for it).
	///
	/// Note for MPP payments: in rare cases, this event may be preceded by a `PaymentPathFailed`
	/// event. In this situation, you SHOULD treat this payment as having succeeded.
	PaymentSent {
		/// The id returned by [`ChannelManager::send_payment`].
		///
		/// [`ChannelManager::send_payment`]: crate::ln::channelmanager::ChannelManager::send_payment
		payment_id: Option<PaymentId>,
		/// The preimage to the hash given to ChannelManager::send_payment.
		/// Note that this serves as a payment receipt, if you wish to have such a thing, you must
		/// store it somehow!
		payment_preimage: PaymentPreimage,
		/// The hash that was given to [`ChannelManager::send_payment`].
		///
		/// [`ChannelManager::send_payment`]: crate::ln::channelmanager::ChannelManager::send_payment
		payment_hash: PaymentHash,
		/// The total fee which was spent at intermediate hops in this payment, across all paths.
		///
		/// Note that, like [`Route::get_total_fees`] this does *not* include any potential
		/// overpayment to the recipient node.
		///
		/// If the recipient or an intermediate node misbehaves and gives us free money, this may
		/// overstate the amount paid, though this is unlikely.
		///
		/// [`Route::get_total_fees`]: crate::routing::router::Route::get_total_fees
		fee_paid_msat: Option<u64>,
	},
	/// Indicates an outbound payment failed. Individual [`Event::PaymentPathFailed`] events
	/// provide failure information for each path attempt in the payment, including retries.
	///
	/// This event is provided once there are no further pending HTLCs for the payment and the
	/// payment is no longer retryable, due either to the [`Retry`] provided or
	/// [`ChannelManager::abandon_payment`] having been called for the corresponding payment.
	///
	/// [`Retry`]: crate::ln::channelmanager::Retry
	/// [`ChannelManager::abandon_payment`]: crate::ln::channelmanager::ChannelManager::abandon_payment
	PaymentFailed {
		/// The id returned by [`ChannelManager::send_payment`] and used with
		/// [`ChannelManager::abandon_payment`].
		///
		/// [`ChannelManager::send_payment`]: crate::ln::channelmanager::ChannelManager::send_payment
		/// [`ChannelManager::abandon_payment`]: crate::ln::channelmanager::ChannelManager::abandon_payment
		payment_id: PaymentId,
		/// The hash that was given to [`ChannelManager::send_payment`].
		///
		/// [`ChannelManager::send_payment`]: crate::ln::channelmanager::ChannelManager::send_payment
		payment_hash: PaymentHash,
	},
	/// Indicates that a path for an outbound payment was successful.
	///
	/// Always generated after [`Event::PaymentSent`] and thus useful for scoring channels. See
	/// [`Event::PaymentSent`] for obtaining the payment preimage.
	PaymentPathSuccessful {
		/// The id returned by [`ChannelManager::send_payment`].
		///
		/// [`ChannelManager::send_payment`]: crate::ln::channelmanager::ChannelManager::send_payment
		payment_id: PaymentId,
		/// The hash that was given to [`ChannelManager::send_payment`].
		///
		/// [`ChannelManager::send_payment`]: crate::ln::channelmanager::ChannelManager::send_payment
		payment_hash: Option<PaymentHash>,
		/// The payment path that was successful.
		///
		/// May contain a closed channel if the HTLC sent along the path was fulfilled on chain.
		path: Vec<RouteHop>,
	},
	/// Indicates an outbound HTLC we sent failed, likely due to an intermediary node being unable to
	/// handle the HTLC.
	///
	/// Note that this does *not* indicate that all paths for an MPP payment have failed, see
	/// [`Event::PaymentFailed`].
	///
	/// See [`ChannelManager::abandon_payment`] for giving up on this payment before its retries have
	/// been exhausted.
	///
	/// [`ChannelManager::abandon_payment`]: crate::ln::channelmanager::ChannelManager::abandon_payment
	PaymentPathFailed {
		/// The id returned by [`ChannelManager::send_payment`] and used with
		/// [`ChannelManager::abandon_payment`].
		///
		/// [`ChannelManager::send_payment`]: crate::ln::channelmanager::ChannelManager::send_payment
		/// [`ChannelManager::abandon_payment`]: crate::ln::channelmanager::ChannelManager::abandon_payment
		payment_id: Option<PaymentId>,
		/// The hash that was given to [`ChannelManager::send_payment`].
		///
		/// [`ChannelManager::send_payment`]: crate::ln::channelmanager::ChannelManager::send_payment
		payment_hash: PaymentHash,
		/// Indicates the payment was rejected for some reason by the recipient. This implies that
		/// the payment has failed, not just the route in question. If this is not set, the payment may
		/// be retried via a different route.
		payment_failed_permanently: bool,
		/// Extra error details based on the failure type. May contain an update that needs to be
		/// applied to the [`NetworkGraph`].
		///
		/// [`NetworkGraph`]: crate::routing::gossip::NetworkGraph
		failure: PathFailure,
		/// The payment path that failed.
		path: Vec<RouteHop>,
		/// The channel responsible for the failed payment path.
		///
		/// Note that for route hints or for the first hop in a path this may be an SCID alias and
		/// may not refer to a channel in the public network graph. These aliases may also collide
		/// with channels in the public network graph.
		///
		/// If this is `Some`, then the corresponding channel should be avoided when the payment is
		/// retried. May be `None` for older [`Event`] serializations.
		short_channel_id: Option<u64>,
		/// Parameters used by LDK to compute a new [`Route`] when retrying the failed payment path.
		///
		/// [`Route`]: crate::routing::router::Route
		retry: Option<RouteParameters>,
#[cfg(test)]
		error_code: Option<u16>,
#[cfg(test)]
		error_data: Option<Vec<u8>>,
	},
	/// Indicates that a probe payment we sent returned successful, i.e., only failed at the destination.
	ProbeSuccessful {
		/// The id returned by [`ChannelManager::send_probe`].
		///
		/// [`ChannelManager::send_probe`]: crate::ln::channelmanager::ChannelManager::send_probe
		payment_id: PaymentId,
		/// The hash generated by [`ChannelManager::send_probe`].
		///
		/// [`ChannelManager::send_probe`]: crate::ln::channelmanager::ChannelManager::send_probe
		payment_hash: PaymentHash,
		/// The payment path that was successful.
		path: Vec<RouteHop>,
	},
	/// Indicates that a probe payment we sent failed at an intermediary node on the path.
	ProbeFailed {
		/// The id returned by [`ChannelManager::send_probe`].
		///
		/// [`ChannelManager::send_probe`]: crate::ln::channelmanager::ChannelManager::send_probe
		payment_id: PaymentId,
		/// The hash generated by [`ChannelManager::send_probe`].
		///
		/// [`ChannelManager::send_probe`]: crate::ln::channelmanager::ChannelManager::send_probe
		payment_hash: PaymentHash,
		/// The payment path that failed.
		path: Vec<RouteHop>,
		/// The channel responsible for the failed probe.
		///
		/// Note that for route hints or for the first hop in a path this may be an SCID alias and
		/// may not refer to a channel in the public network graph. These aliases may also collide
		/// with channels in the public network graph.
		short_channel_id: Option<u64>,
	},
	/// Used to indicate that [`ChannelManager::process_pending_htlc_forwards`] should be called at
	/// a time in the future.
	///
	/// [`ChannelManager::process_pending_htlc_forwards`]: crate::ln::channelmanager::ChannelManager::process_pending_htlc_forwards
	PendingHTLCsForwardable {
		/// The minimum amount of time that should be waited prior to calling
		/// process_pending_htlc_forwards. To increase the effort required to correlate payments,
		/// you should wait a random amount of time in roughly the range (now + time_forwardable,
		/// now + 5*time_forwardable).
		time_forwardable: Duration,
	},
	/// Used to indicate that we've intercepted an HTLC forward. This event will only be generated if
	/// you've encoded an intercept scid in the receiver's invoice route hints using
	/// [`ChannelManager::get_intercept_scid`] and have set [`UserConfig::accept_intercept_htlcs`].
	///
	/// [`ChannelManager::forward_intercepted_htlc`] or
	/// [`ChannelManager::fail_intercepted_htlc`] MUST be called in response to this event. See
	/// their docs for more information.
	///
	/// [`ChannelManager::get_intercept_scid`]: crate::ln::channelmanager::ChannelManager::get_intercept_scid
	/// [`UserConfig::accept_intercept_htlcs`]: crate::util::config::UserConfig::accept_intercept_htlcs
	/// [`ChannelManager::forward_intercepted_htlc`]: crate::ln::channelmanager::ChannelManager::forward_intercepted_htlc
	/// [`ChannelManager::fail_intercepted_htlc`]: crate::ln::channelmanager::ChannelManager::fail_intercepted_htlc
	HTLCIntercepted {
		/// An id to help LDK identify which HTLC is being forwarded or failed.
		intercept_id: InterceptId,
		/// The fake scid that was programmed as the next hop's scid, generated using
		/// [`ChannelManager::get_intercept_scid`].
		///
		/// [`ChannelManager::get_intercept_scid`]: crate::ln::channelmanager::ChannelManager::get_intercept_scid
		requested_next_hop_scid: u64,
		/// The payment hash used for this HTLC.
		payment_hash: PaymentHash,
		/// How many msats were received on the inbound edge of this HTLC.
		inbound_amount_msat: u64,
		/// How many msats the payer intended to route to the next node. Depending on the reason you are
		/// intercepting this payment, you might take a fee by forwarding less than this amount.
		///
		/// Note that LDK will NOT check that expected fees were factored into this value. You MUST
		/// check that whatever fee you want has been included here or subtract it as required. Further,
		/// LDK will not stop you from forwarding more than you received.
		expected_outbound_amount_msat: u64,
	},
	/// Used to indicate that an output which you should know how to spend was confirmed on chain
	/// and is now spendable.
	/// Such an output will *not* ever be spent by rust-lightning, and are not at risk of your
	/// counterparty spending them due to some kind of timeout. Thus, you need to store them
	/// somewhere and spend them when you create on-chain transactions.
	SpendableOutputs {
		/// The outputs which you should store as spendable by you.
		outputs: Vec<SpendableOutputDescriptor>,
	},
	/// This event is generated when a payment has been successfully forwarded through us and a
	/// forwarding fee earned.
	PaymentForwarded {
		/// The incoming channel between the previous node and us. This is only `None` for events
		/// generated or serialized by versions prior to 0.0.107.
		prev_channel_id: Option<[u8; 32]>,
		/// The outgoing channel between the next node and us. This is only `None` for events
		/// generated or serialized by versions prior to 0.0.107.
		next_channel_id: Option<[u8; 32]>,
		/// The fee, in milli-satoshis, which was earned as a result of the payment.
		///
		/// Note that if we force-closed the channel over which we forwarded an HTLC while the HTLC
		/// was pending, the amount the next hop claimed will have been rounded down to the nearest
		/// whole satoshi. Thus, the fee calculated here may be higher than expected as we still
		/// claimed the full value in millisatoshis from the source. In this case,
		/// `claim_from_onchain_tx` will be set.
		///
		/// If the channel which sent us the payment has been force-closed, we will claim the funds
		/// via an on-chain transaction. In that case we do not yet know the on-chain transaction
		/// fees which we will spend and will instead set this to `None`. It is possible duplicate
		/// `PaymentForwarded` events are generated for the same payment iff `fee_earned_msat` is
		/// `None`.
		fee_earned_msat: Option<u64>,
		/// If this is `true`, the forwarded HTLC was claimed by our counterparty via an on-chain
		/// transaction.
		claim_from_onchain_tx: bool,
	},
	/// Used to indicate that a channel with the given `channel_id` is ready to
	/// be used. This event is emitted either when the funding transaction has been confirmed
	/// on-chain, or, in case of a 0conf channel, when both parties have confirmed the channel
	/// establishment.
	ChannelReady {
		/// The channel_id of the channel that is ready.
		channel_id: [u8; 32],
		/// The `user_channel_id` value passed in to [`ChannelManager::create_channel`] for outbound
		/// channels, or to [`ChannelManager::accept_inbound_channel`] for inbound channels if
		/// [`UserConfig::manually_accept_inbound_channels`] config flag is set to true. Otherwise
		/// `user_channel_id` will be randomized for an inbound channel.
		///
		/// [`ChannelManager::create_channel`]: crate::ln::channelmanager::ChannelManager::create_channel
		/// [`ChannelManager::accept_inbound_channel`]: crate::ln::channelmanager::ChannelManager::accept_inbound_channel
		/// [`UserConfig::manually_accept_inbound_channels`]: crate::util::config::UserConfig::manually_accept_inbound_channels
		user_channel_id: u128,
		/// The node_id of the channel counterparty.
		counterparty_node_id: PublicKey,
		/// The features that this channel will operate with.
		channel_type: ChannelTypeFeatures,
	},
	/// Used to indicate that a previously opened channel with the given `channel_id` is in the
	/// process of closure.
	ChannelClosed  {
		/// The channel_id of the channel which has been closed. Note that on-chain transactions
		/// resolving the channel are likely still awaiting confirmation.
		channel_id: [u8; 32],
		/// The `user_channel_id` value passed in to [`ChannelManager::create_channel`] for outbound
		/// channels, or to [`ChannelManager::accept_inbound_channel`] for inbound channels if
		/// [`UserConfig::manually_accept_inbound_channels`] config flag is set to true. Otherwise
		/// `user_channel_id` will be randomized for inbound channels.
		/// This may be zero for inbound channels serialized prior to 0.0.113 and will always be
		/// zero for objects serialized with LDK versions prior to 0.0.102.
		///
		/// [`ChannelManager::create_channel`]: crate::ln::channelmanager::ChannelManager::create_channel
		/// [`ChannelManager::accept_inbound_channel`]: crate::ln::channelmanager::ChannelManager::accept_inbound_channel
		/// [`UserConfig::manually_accept_inbound_channels`]: crate::util::config::UserConfig::manually_accept_inbound_channels
		user_channel_id: u128,
		/// The reason the channel was closed.
		reason: ClosureReason
	},
	/// Used to indicate to the user that they can abandon the funding transaction and recycle the
	/// inputs for another purpose.
	DiscardFunding {
		/// The channel_id of the channel which has been closed.
		channel_id: [u8; 32],
		/// The full transaction received from the user
		transaction: Transaction
	},
	/// Indicates a request to open a new channel by a peer.
	///
	/// To accept the request, call [`ChannelManager::accept_inbound_channel`]. To reject the
	/// request, call [`ChannelManager::force_close_without_broadcasting_txn`].
	///
	/// The event is only triggered when a new open channel request is received and the
	/// [`UserConfig::manually_accept_inbound_channels`] config flag is set to true.
	///
	/// [`ChannelManager::accept_inbound_channel`]: crate::ln::channelmanager::ChannelManager::accept_inbound_channel
	/// [`ChannelManager::force_close_without_broadcasting_txn`]: crate::ln::channelmanager::ChannelManager::force_close_without_broadcasting_txn
	/// [`UserConfig::manually_accept_inbound_channels`]: crate::util::config::UserConfig::manually_accept_inbound_channels
	OpenChannelRequest {
		/// The temporary channel ID of the channel requested to be opened.
		///
		/// When responding to the request, the `temporary_channel_id` should be passed
		/// back to the ChannelManager through [`ChannelManager::accept_inbound_channel`] to accept,
		/// or through [`ChannelManager::force_close_without_broadcasting_txn`] to reject.
		///
		/// [`ChannelManager::accept_inbound_channel`]: crate::ln::channelmanager::ChannelManager::accept_inbound_channel
		/// [`ChannelManager::force_close_without_broadcasting_txn`]: crate::ln::channelmanager::ChannelManager::force_close_without_broadcasting_txn
		temporary_channel_id: [u8; 32],
		/// The node_id of the counterparty requesting to open the channel.
		///
		/// When responding to the request, the `counterparty_node_id` should be passed
		/// back to the `ChannelManager` through [`ChannelManager::accept_inbound_channel`] to
		/// accept the request, or through [`ChannelManager::force_close_without_broadcasting_txn`] to reject the
		/// request.
		///
		/// [`ChannelManager::accept_inbound_channel`]: crate::ln::channelmanager::ChannelManager::accept_inbound_channel
		/// [`ChannelManager::force_close_without_broadcasting_txn`]: crate::ln::channelmanager::ChannelManager::force_close_without_broadcasting_txn
		counterparty_node_id: PublicKey,
		/// The channel value of the requested channel.
		funding_satoshis: u64,
		/// Our starting balance in the channel if the request is accepted, in milli-satoshi.
		push_msat: u64,
		/// The features that this channel will operate with. If you reject the channel, a
		/// well-behaved counterparty may automatically re-attempt the channel with a new set of
		/// feature flags.
		///
		/// Note that if [`ChannelTypeFeatures::supports_scid_privacy`] returns true on this type,
		/// the resulting [`ChannelManager`] will not be readable by versions of LDK prior to
		/// 0.0.106.
		///
		/// Furthermore, note that if [`ChannelTypeFeatures::supports_zero_conf`] returns true on this type,
		/// the resulting [`ChannelManager`] will not be readable by versions of LDK prior to
		/// 0.0.107. Channels setting this type also need to get manually accepted via
		/// [`crate::ln::channelmanager::ChannelManager::accept_inbound_channel_from_trusted_peer_0conf`],
		/// or will be rejected otherwise.
		///
		/// [`ChannelManager`]: crate::ln::channelmanager::ChannelManager
		channel_type: ChannelTypeFeatures,
	},
	/// Indicates that the HTLC was accepted, but could not be processed when or after attempting to
	/// forward it.
	///
	/// Some scenarios where this event may be sent include:
	/// * Insufficient capacity in the outbound channel
	/// * While waiting to forward the HTLC, the channel it is meant to be forwarded through closes
	/// * When an unknown SCID is requested for forwarding a payment.
	/// * Claiming an amount for an MPP payment that exceeds the HTLC total
	/// * The HTLC has timed out
	///
	/// This event, however, does not get generated if an HTLC fails to meet the forwarding
	/// requirements (i.e. insufficient fees paid, or a CLTV that is too soon).
	HTLCHandlingFailed {
		/// The channel over which the HTLC was received.
		prev_channel_id: [u8; 32],
		/// Destination of the HTLC that failed to be processed.
		failed_next_destination: HTLCDestination,
	},
	#[cfg(anchors)]
	/// Indicates that a transaction originating from LDK needs to have its fee bumped. This event
	/// requires confirmed external funds to be readily available to spend.
	///
	/// LDK does not currently generate this event. It is limited to the scope of channels with
	/// anchor outputs, which will be introduced in a future release.
	BumpTransaction(BumpTransactionEvent),
}

impl Writeable for Event {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		match self {
			&Event::FundingGenerationReady { .. } => {
				0u8.write(writer)?;
				// We never write out FundingGenerationReady events as, upon disconnection, peers
				// drop any channels which have not yet exchanged funding_signed.
			},
			&Event::PaymentClaimable { ref payment_hash, ref amount_msat, ref purpose, ref receiver_node_id, ref via_channel_id, ref via_user_channel_id } => {
				1u8.write(writer)?;
				let mut payment_secret = None;
				let payment_preimage;
				match &purpose {
					PaymentPurpose::InvoicePayment { payment_preimage: preimage, payment_secret: secret } => {
						payment_secret = Some(secret);
						payment_preimage = *preimage;
					},
					PaymentPurpose::SpontaneousPayment(preimage) => {
						payment_preimage = Some(*preimage);
					}
				}
				write_tlv_fields!(writer, {
					(0, payment_hash, required),
					(1, receiver_node_id, option),
					(2, payment_secret, option),
					(3, via_channel_id, option),
					(4, amount_msat, required),
					(5, via_user_channel_id, option),
					(6, 0u64, required), // user_payment_id required for compatibility with 0.0.103 and earlier
					(8, payment_preimage, option),
				});
			},
			&Event::PaymentSent { ref payment_id, ref payment_preimage, ref payment_hash, ref fee_paid_msat } => {
				2u8.write(writer)?;
				write_tlv_fields!(writer, {
					(0, payment_preimage, required),
					(1, payment_hash, required),
					(3, payment_id, option),
					(5, fee_paid_msat, option),
				});
			},
			&Event::PaymentPathFailed {
				ref payment_id, ref payment_hash, ref payment_failed_permanently, ref failure,
				ref path, ref short_channel_id, ref retry,
				#[cfg(test)]
				ref error_code,
				#[cfg(test)]
				ref error_data,
			} => {
				3u8.write(writer)?;
				#[cfg(test)]
				error_code.write(writer)?;
				#[cfg(test)]
				error_data.write(writer)?;
				write_tlv_fields!(writer, {
					(0, payment_hash, required),
					(1, None::<NetworkUpdate>, option), // network_update in LDK versions prior to 0.0.114
					(2, payment_failed_permanently, required),
					(3, false, required), // all_paths_failed in LDK versions prior to 0.0.114
					(5, *path, vec_type),
					(7, short_channel_id, option),
					(9, retry, option),
					(11, payment_id, option),
					(13, failure, required),
				});
			},
			&Event::PendingHTLCsForwardable { time_forwardable: _ } => {
				4u8.write(writer)?;
				// Note that we now ignore these on the read end as we'll re-generate them in
				// ChannelManager, we write them here only for backwards compatibility.
			},
			&Event::SpendableOutputs { ref outputs } => {
				5u8.write(writer)?;
				write_tlv_fields!(writer, {
					(0, WithoutLength(outputs), required),
				});
			},
			&Event::HTLCIntercepted { requested_next_hop_scid, payment_hash, inbound_amount_msat, expected_outbound_amount_msat, intercept_id } => {
				6u8.write(writer)?;
				let intercept_scid = InterceptNextHop::FakeScid { requested_next_hop_scid };
				write_tlv_fields!(writer, {
					(0, intercept_id, required),
					(2, intercept_scid, required),
					(4, payment_hash, required),
					(6, inbound_amount_msat, required),
					(8, expected_outbound_amount_msat, required),
				});
			}
			&Event::PaymentForwarded { fee_earned_msat, prev_channel_id, claim_from_onchain_tx, next_channel_id } => {
				7u8.write(writer)?;
				write_tlv_fields!(writer, {
					(0, fee_earned_msat, option),
					(1, prev_channel_id, option),
					(2, claim_from_onchain_tx, required),
					(3, next_channel_id, option),
				});
			},
			&Event::ChannelClosed { ref channel_id, ref user_channel_id, ref reason } => {
				9u8.write(writer)?;
				// `user_channel_id` used to be a single u64 value. In order to remain backwards
				// compatible with versions prior to 0.0.113, the u128 is serialized as two
				// separate u64 values.
				let user_channel_id_low = *user_channel_id as u64;
				let user_channel_id_high = (*user_channel_id >> 64) as u64;
				write_tlv_fields!(writer, {
					(0, channel_id, required),
					(1, user_channel_id_low, required),
					(2, reason, required),
					(3, user_channel_id_high, required),
				});
			},
			&Event::DiscardFunding { ref channel_id, ref transaction } => {
				11u8.write(writer)?;
				write_tlv_fields!(writer, {
					(0, channel_id, required),
					(2, transaction, required)
				})
			},
			&Event::PaymentPathSuccessful { ref payment_id, ref payment_hash, ref path } => {
				13u8.write(writer)?;
				write_tlv_fields!(writer, {
					(0, payment_id, required),
					(2, payment_hash, option),
					(4, *path, vec_type)
				})
			},
			&Event::PaymentFailed { ref payment_id, ref payment_hash } => {
				15u8.write(writer)?;
				write_tlv_fields!(writer, {
					(0, payment_id, required),
					(2, payment_hash, required),
				})
			},
			&Event::OpenChannelRequest { .. } => {
				17u8.write(writer)?;
				// We never write the OpenChannelRequest events as, upon disconnection, peers
				// drop any channels which have not yet exchanged funding_signed.
			},
			&Event::PaymentClaimed { ref payment_hash, ref amount_msat, ref purpose, ref receiver_node_id } => {
				19u8.write(writer)?;
				write_tlv_fields!(writer, {
					(0, payment_hash, required),
					(1, receiver_node_id, option),
					(2, purpose, required),
					(4, amount_msat, required),
				});
			},
			&Event::ProbeSuccessful { ref payment_id, ref payment_hash, ref path } => {
				21u8.write(writer)?;
				write_tlv_fields!(writer, {
					(0, payment_id, required),
					(2, payment_hash, required),
					(4, *path, vec_type)
				})
			},
			&Event::ProbeFailed { ref payment_id, ref payment_hash, ref path, ref short_channel_id } => {
				23u8.write(writer)?;
				write_tlv_fields!(writer, {
					(0, payment_id, required),
					(2, payment_hash, required),
					(4, *path, vec_type),
					(6, short_channel_id, option),
				})
			},
			&Event::HTLCHandlingFailed { ref prev_channel_id, ref failed_next_destination } => {
				25u8.write(writer)?;
				write_tlv_fields!(writer, {
					(0, prev_channel_id, required),
					(2, failed_next_destination, required),
				})
			},
			#[cfg(anchors)]
			&Event::BumpTransaction(ref event)=> {
				27u8.write(writer)?;
				match event {
					// We never write the ChannelClose|HTLCResolution events as they'll be replayed
					// upon restarting anyway if they remain unresolved.
					BumpTransactionEvent::ChannelClose { .. } => {}
					BumpTransactionEvent::HTLCResolution { .. } => {}
				}
				write_tlv_fields!(writer, {}); // Write a length field for forwards compat
			}
			&Event::ChannelReady { ref channel_id, ref user_channel_id, ref counterparty_node_id, ref channel_type } => {
				29u8.write(writer)?;
				write_tlv_fields!(writer, {
					(0, channel_id, required),
					(2, user_channel_id, required),
					(4, counterparty_node_id, required),
					(6, channel_type, required),
				});
			},
			// Note that, going forward, all new events must only write data inside of
			// `write_tlv_fields`. Versions 0.0.101+ will ignore odd-numbered events that write
			// data via `write_tlv_fields`.
		}
		Ok(())
	}
}
impl MaybeReadable for Event {
	fn read<R: io::Read>(reader: &mut R) -> Result<Option<Self>, msgs::DecodeError> {
		match Readable::read(reader)? {
			// Note that we do not write a length-prefixed TLV for FundingGenerationReady events,
			// unlike all other events, thus we return immediately here.
			0u8 => Ok(None),
			1u8 => {
				let f = || {
					let mut payment_hash = PaymentHash([0; 32]);
					let mut payment_preimage = None;
					let mut payment_secret = None;
					let mut amount_msat = 0;
					let mut receiver_node_id = None;
					let mut _user_payment_id = None::<u64>; // For compatibility with 0.0.103 and earlier
					let mut via_channel_id = None;
					let mut via_user_channel_id = None;
					read_tlv_fields!(reader, {
						(0, payment_hash, required),
						(1, receiver_node_id, option),
						(2, payment_secret, option),
						(3, via_channel_id, option),
						(4, amount_msat, required),
						(5, via_user_channel_id, option),
						(6, _user_payment_id, option),
						(8, payment_preimage, option),
					});
					let purpose = match payment_secret {
						Some(secret) => PaymentPurpose::InvoicePayment {
							payment_preimage,
							payment_secret: secret
						},
						None if payment_preimage.is_some() => PaymentPurpose::SpontaneousPayment(payment_preimage.unwrap()),
						None => return Err(msgs::DecodeError::InvalidValue),
					};
					Ok(Some(Event::PaymentClaimable {
						receiver_node_id,
						payment_hash,
						amount_msat,
						purpose,
						via_channel_id,
						via_user_channel_id,
					}))
				};
				f()
			},
			2u8 => {
				let f = || {
					let mut payment_preimage = PaymentPreimage([0; 32]);
					let mut payment_hash = None;
					let mut payment_id = None;
					let mut fee_paid_msat = None;
					read_tlv_fields!(reader, {
						(0, payment_preimage, required),
						(1, payment_hash, option),
						(3, payment_id, option),
						(5, fee_paid_msat, option),
					});
					if payment_hash.is_none() {
						payment_hash = Some(PaymentHash(Sha256::hash(&payment_preimage.0[..]).into_inner()));
					}
					Ok(Some(Event::PaymentSent {
						payment_id,
						payment_preimage,
						payment_hash: payment_hash.unwrap(),
						fee_paid_msat,
					}))
				};
				f()
			},
			3u8 => {
				let f = || {
					#[cfg(test)]
					let error_code = Readable::read(reader)?;
					#[cfg(test)]
					let error_data = Readable::read(reader)?;
					let mut payment_hash = PaymentHash([0; 32]);
					let mut payment_failed_permanently = false;
					let mut network_update = None;
					let mut path: Option<Vec<RouteHop>> = Some(vec![]);
					let mut short_channel_id = None;
					let mut retry = None;
					let mut payment_id = None;
					let mut failure_opt = None;
					read_tlv_fields!(reader, {
						(0, payment_hash, required),
						(1, network_update, upgradable_option),
						(2, payment_failed_permanently, required),
						(5, path, vec_type),
						(7, short_channel_id, option),
						(9, retry, option),
						(11, payment_id, option),
						(13, failure_opt, upgradable_option),
					});
					let failure = failure_opt.unwrap_or_else(|| PathFailure::OnPath { network_update });
					Ok(Some(Event::PaymentPathFailed {
						payment_id,
						payment_hash,
						payment_failed_permanently,
						failure,
						path: path.unwrap(),
						short_channel_id,
						retry,
						#[cfg(test)]
						error_code,
						#[cfg(test)]
						error_data,
					}))
				};
				f()
			},
			4u8 => Ok(None),
			5u8 => {
				let f = || {
					let mut outputs = WithoutLength(Vec::new());
					read_tlv_fields!(reader, {
						(0, outputs, required),
					});
					Ok(Some(Event::SpendableOutputs { outputs: outputs.0 }))
				};
				f()
			},
			6u8 => {
				let mut payment_hash = PaymentHash([0; 32]);
				let mut intercept_id = InterceptId([0; 32]);
				let mut requested_next_hop_scid = InterceptNextHop::FakeScid { requested_next_hop_scid: 0 };
				let mut inbound_amount_msat = 0;
				let mut expected_outbound_amount_msat = 0;
				read_tlv_fields!(reader, {
					(0, intercept_id, required),
					(2, requested_next_hop_scid, required),
					(4, payment_hash, required),
					(6, inbound_amount_msat, required),
					(8, expected_outbound_amount_msat, required),
				});
				let next_scid = match requested_next_hop_scid {
					InterceptNextHop::FakeScid { requested_next_hop_scid: scid } => scid
				};
				Ok(Some(Event::HTLCIntercepted {
					payment_hash,
					requested_next_hop_scid: next_scid,
					inbound_amount_msat,
					expected_outbound_amount_msat,
					intercept_id,
				}))
			},
			7u8 => {
				let f = || {
					let mut fee_earned_msat = None;
					let mut prev_channel_id = None;
					let mut claim_from_onchain_tx = false;
					let mut next_channel_id = None;
					read_tlv_fields!(reader, {
						(0, fee_earned_msat, option),
						(1, prev_channel_id, option),
						(2, claim_from_onchain_tx, required),
						(3, next_channel_id, option),
					});
					Ok(Some(Event::PaymentForwarded { fee_earned_msat, prev_channel_id, claim_from_onchain_tx, next_channel_id }))
				};
				f()
			},
			9u8 => {
				let f = || {
					let mut channel_id = [0; 32];
					let mut reason = UpgradableRequired(None);
					let mut user_channel_id_low_opt: Option<u64> = None;
					let mut user_channel_id_high_opt: Option<u64> = None;
					read_tlv_fields!(reader, {
						(0, channel_id, required),
						(1, user_channel_id_low_opt, option),
						(2, reason, upgradable_required),
						(3, user_channel_id_high_opt, option),
					});

					// `user_channel_id` used to be a single u64 value. In order to remain
					// backwards compatible with versions prior to 0.0.113, the u128 is serialized
					// as two separate u64 values.
					let user_channel_id = (user_channel_id_low_opt.unwrap_or(0) as u128) +
						((user_channel_id_high_opt.unwrap_or(0) as u128) << 64);

					Ok(Some(Event::ChannelClosed { channel_id, user_channel_id, reason: _init_tlv_based_struct_field!(reason, upgradable_required) }))
				};
				f()
			},
			11u8 => {
				let f = || {
					let mut channel_id = [0; 32];
					let mut transaction = Transaction{ version: 2, lock_time: PackedLockTime::ZERO, input: Vec::new(), output: Vec::new() };
					read_tlv_fields!(reader, {
						(0, channel_id, required),
						(2, transaction, required),
					});
					Ok(Some(Event::DiscardFunding { channel_id, transaction } ))
				};
				f()
			},
			13u8 => {
				let f = || {
					let mut payment_id = PaymentId([0; 32]);
					let mut payment_hash = None;
					let mut path: Option<Vec<RouteHop>> = Some(vec![]);
					read_tlv_fields!(reader, {
						(0, payment_id, required),
						(2, payment_hash, option),
						(4, path, vec_type),
					});
					Ok(Some(Event::PaymentPathSuccessful {
						payment_id,
						payment_hash,
						path: path.unwrap(),
					}))
				};
				f()
			},
			15u8 => {
				let f = || {
					let mut payment_hash = PaymentHash([0; 32]);
					let mut payment_id = PaymentId([0; 32]);
					read_tlv_fields!(reader, {
						(0, payment_id, required),
						(2, payment_hash, required),
					});
					Ok(Some(Event::PaymentFailed {
						payment_id,
						payment_hash,
					}))
				};
				f()
			},
			17u8 => {
				// Value 17 is used for `Event::OpenChannelRequest`.
				Ok(None)
			},
			19u8 => {
				let f = || {
					let mut payment_hash = PaymentHash([0; 32]);
					let mut purpose = UpgradableRequired(None);
					let mut amount_msat = 0;
					let mut receiver_node_id = None;
					read_tlv_fields!(reader, {
						(0, payment_hash, required),
						(1, receiver_node_id, option),
						(2, purpose, upgradable_required),
						(4, amount_msat, required),
					});
					Ok(Some(Event::PaymentClaimed {
						receiver_node_id,
						payment_hash,
						purpose: _init_tlv_based_struct_field!(purpose, upgradable_required),
						amount_msat,
					}))
				};
				f()
			},
			21u8 => {
				let f = || {
					let mut payment_id = PaymentId([0; 32]);
					let mut payment_hash = PaymentHash([0; 32]);
					let mut path: Option<Vec<RouteHop>> = Some(vec![]);
					read_tlv_fields!(reader, {
						(0, payment_id, required),
						(2, payment_hash, required),
						(4, path, vec_type),
					});
					Ok(Some(Event::ProbeSuccessful {
						payment_id,
						payment_hash,
						path: path.unwrap(),
					}))
				};
				f()
			},
			23u8 => {
				let f = || {
					let mut payment_id = PaymentId([0; 32]);
					let mut payment_hash = PaymentHash([0; 32]);
					let mut path: Option<Vec<RouteHop>> = Some(vec![]);
					let mut short_channel_id = None;
					read_tlv_fields!(reader, {
						(0, payment_id, required),
						(2, payment_hash, required),
						(4, path, vec_type),
						(6, short_channel_id, option),
					});
					Ok(Some(Event::ProbeFailed {
						payment_id,
						payment_hash,
						path: path.unwrap(),
						short_channel_id,
					}))
				};
				f()
			},
			25u8 => {
				let f = || {
					let mut prev_channel_id = [0; 32];
					let mut failed_next_destination_opt = UpgradableRequired(None);
					read_tlv_fields!(reader, {
						(0, prev_channel_id, required),
						(2, failed_next_destination_opt, upgradable_required),
					});
					Ok(Some(Event::HTLCHandlingFailed {
						prev_channel_id,
						failed_next_destination: _init_tlv_based_struct_field!(failed_next_destination_opt, upgradable_required),
					}))
				};
				f()
			},
			27u8 => Ok(None),
			29u8 => {
				let f = || {
					let mut channel_id = [0; 32];
					let mut user_channel_id: u128 = 0;
					let mut counterparty_node_id = RequiredWrapper(None);
					let mut channel_type = RequiredWrapper(None);
					read_tlv_fields!(reader, {
						(0, channel_id, required),
						(2, user_channel_id, required),
						(4, counterparty_node_id, required),
						(6, channel_type, required),
					});

					Ok(Some(Event::ChannelReady {
						channel_id,
						user_channel_id,
						counterparty_node_id: counterparty_node_id.0.unwrap(),
						channel_type: channel_type.0.unwrap()
					}))
				};
				f()
			},
			// Versions prior to 0.0.100 did not ignore odd types, instead returning InvalidValue.
			// Version 0.0.100 failed to properly ignore odd types, possibly resulting in corrupt
			// reads.
			x if x % 2 == 1 => {
				// If the event is of unknown type, assume it was written with `write_tlv_fields`,
				// which prefixes the whole thing with a length BigSize. Because the event is
				// odd-type unknown, we should treat it as `Ok(None)` even if it has some TLV
				// fields that are even. Thus, we avoid using `read_tlv_fields` and simply read
				// exactly the number of bytes specified, ignoring them entirely.
				let tlv_len: BigSize = Readable::read(reader)?;
				FixedLengthReader::new(reader, tlv_len.0)
					.eat_remaining().map_err(|_| msgs::DecodeError::ShortRead)?;
				Ok(None)
			},
			_ => Err(msgs::DecodeError::InvalidValue)
		}
	}
}

/// An event generated by ChannelManager which indicates a message should be sent to a peer (or
/// broadcast to most peers).
/// These events are handled by PeerManager::process_events if you are using a PeerManager.
#[derive(Clone, Debug)]
pub enum MessageSendEvent {
	/// Used to indicate that we've accepted a channel open and should send the accept_channel
	/// message provided to the given peer.
	SendAcceptChannel {
		/// The node_id of the node which should receive this message
		node_id: PublicKey,
		/// The message which should be sent.
		msg: msgs::AcceptChannel,
	},
	/// Used to indicate that we've initiated a channel open and should send the open_channel
	/// message provided to the given peer.
	SendOpenChannel {
		/// The node_id of the node which should receive this message
		node_id: PublicKey,
		/// The message which should be sent.
		msg: msgs::OpenChannel,
	},
	/// Used to indicate that a funding_created message should be sent to the peer with the given node_id.
	SendFundingCreated {
		/// The node_id of the node which should receive this message
		node_id: PublicKey,
		/// The message which should be sent.
		msg: msgs::FundingCreated,
	},
	/// Used to indicate that a funding_signed message should be sent to the peer with the given node_id.
	SendFundingSigned {
		/// The node_id of the node which should receive this message
		node_id: PublicKey,
		/// The message which should be sent.
		msg: msgs::FundingSigned,
	},
	/// Used to indicate that a channel_ready message should be sent to the peer with the given node_id.
	SendChannelReady {
		/// The node_id of the node which should receive these message(s)
		node_id: PublicKey,
		/// The channel_ready message which should be sent.
		msg: msgs::ChannelReady,
	},
	/// Used to indicate that an announcement_signatures message should be sent to the peer with the given node_id.
	SendAnnouncementSignatures {
		/// The node_id of the node which should receive these message(s)
		node_id: PublicKey,
		/// The announcement_signatures message which should be sent.
		msg: msgs::AnnouncementSignatures,
	},
	/// Used to indicate that a series of HTLC update messages, as well as a commitment_signed
	/// message should be sent to the peer with the given node_id.
	UpdateHTLCs {
		/// The node_id of the node which should receive these message(s)
		node_id: PublicKey,
		/// The update messages which should be sent. ALL messages in the struct should be sent!
		updates: msgs::CommitmentUpdate,
	},
	/// Used to indicate that a revoke_and_ack message should be sent to the peer with the given node_id.
	SendRevokeAndACK {
		/// The node_id of the node which should receive this message
		node_id: PublicKey,
		/// The message which should be sent.
		msg: msgs::RevokeAndACK,
	},
	/// Used to indicate that a closing_signed message should be sent to the peer with the given node_id.
	SendClosingSigned {
		/// The node_id of the node which should receive this message
		node_id: PublicKey,
		/// The message which should be sent.
		msg: msgs::ClosingSigned,
	},
	/// Used to indicate that a shutdown message should be sent to the peer with the given node_id.
	SendShutdown {
		/// The node_id of the node which should receive this message
		node_id: PublicKey,
		/// The message which should be sent.
		msg: msgs::Shutdown,
	},
	/// Used to indicate that a channel_reestablish message should be sent to the peer with the given node_id.
	SendChannelReestablish {
		/// The node_id of the node which should receive this message
		node_id: PublicKey,
		/// The message which should be sent.
		msg: msgs::ChannelReestablish,
	},
	/// Used to send a channel_announcement and channel_update to a specific peer, likely on
	/// initial connection to ensure our peers know about our channels.
	SendChannelAnnouncement {
		/// The node_id of the node which should receive this message
		node_id: PublicKey,
		/// The channel_announcement which should be sent.
		msg: msgs::ChannelAnnouncement,
		/// The followup channel_update which should be sent.
		update_msg: msgs::ChannelUpdate,
	},
	/// Used to indicate that a channel_announcement and channel_update should be broadcast to all
	/// peers (except the peer with node_id either msg.contents.node_id_1 or msg.contents.node_id_2).
	///
	/// Note that after doing so, you very likely (unless you did so very recently) want to
	/// broadcast a node_announcement (e.g. via [`PeerManager::broadcast_node_announcement`]). This
	/// ensures that any nodes which see our channel_announcement also have a relevant
	/// node_announcement, including relevant feature flags which may be important for routing
	/// through or to us.
	///
	/// [`PeerManager::broadcast_node_announcement`]: crate::ln::peer_handler::PeerManager::broadcast_node_announcement
	BroadcastChannelAnnouncement {
		/// The channel_announcement which should be sent.
		msg: msgs::ChannelAnnouncement,
		/// The followup channel_update which should be sent.
		update_msg: Option<msgs::ChannelUpdate>,
	},
	/// Used to indicate that a channel_update should be broadcast to all peers.
	BroadcastChannelUpdate {
		/// The channel_update which should be sent.
		msg: msgs::ChannelUpdate,
	},
	/// Used to indicate that a node_announcement should be broadcast to all peers.
	BroadcastNodeAnnouncement {
		/// The node_announcement which should be sent.
		msg: msgs::NodeAnnouncement,
	},
	/// Used to indicate that a channel_update should be sent to a single peer.
	/// In contrast to [`Self::BroadcastChannelUpdate`], this is used when the channel is a
	/// private channel and we shouldn't be informing all of our peers of channel parameters.
	SendChannelUpdate {
		/// The node_id of the node which should receive this message
		node_id: PublicKey,
		/// The channel_update which should be sent.
		msg: msgs::ChannelUpdate,
	},
	/// Broadcast an error downstream to be handled
	HandleError {
		/// The node_id of the node which should receive this message
		node_id: PublicKey,
		/// The action which should be taken.
		action: msgs::ErrorAction
	},
	/// Query a peer for channels with funding transaction UTXOs in a block range.
	SendChannelRangeQuery {
		/// The node_id of this message recipient
		node_id: PublicKey,
		/// The query_channel_range which should be sent.
		msg: msgs::QueryChannelRange,
	},
	/// Request routing gossip messages from a peer for a list of channels identified by
	/// their short_channel_ids.
	SendShortIdsQuery {
		/// The node_id of this message recipient
		node_id: PublicKey,
		/// The query_short_channel_ids which should be sent.
		msg: msgs::QueryShortChannelIds,
	},
	/// Sends a reply to a channel range query. This may be one of several SendReplyChannelRange events
	/// emitted during processing of the query.
	SendReplyChannelRange {
		/// The node_id of this message recipient
		node_id: PublicKey,
		/// The reply_channel_range which should be sent.
		msg: msgs::ReplyChannelRange,
	},
	/// Sends a timestamp filter for inbound gossip. This should be sent on each new connection to
	/// enable receiving gossip messages from the peer.
	SendGossipTimestampFilter {
		/// The node_id of this message recipient
		node_id: PublicKey,
		/// The gossip_timestamp_filter which should be sent.
		msg: msgs::GossipTimestampFilter,
	},
}

/// A trait indicating an object may generate message send events
pub trait MessageSendEventsProvider {
	/// Gets the list of pending events which were generated by previous actions, clearing the list
	/// in the process.
	fn get_and_clear_pending_msg_events(&self) -> Vec<MessageSendEvent>;
}

/// A trait indicating an object may generate onion messages to send
pub trait OnionMessageProvider {
	/// Gets the next pending onion message for the peer with the given node id.
	fn next_onion_message_for_peer(&self, peer_node_id: PublicKey) -> Option<msgs::OnionMessage>;
}

/// A trait indicating an object may generate events.
///
/// Events are processed by passing an [`EventHandler`] to [`process_pending_events`].
///
/// Implementations of this trait may also feature an async version of event handling, as shown with
/// [`ChannelManager::process_pending_events_async`] and
/// [`ChainMonitor::process_pending_events_async`].
///
/// # Requirements
///
/// When using this trait, [`process_pending_events`] will call [`handle_event`] for each pending
/// event since the last invocation.
///
/// In order to ensure no [`Event`]s are lost, implementors of this trait will persist [`Event`]s
/// and replay any unhandled events on startup. An [`Event`] is considered handled when
/// [`process_pending_events`] returns, thus handlers MUST fully handle [`Event`]s and persist any
/// relevant changes to disk *before* returning.
///
/// Further, because an application may crash between an [`Event`] being handled and the
/// implementor of this trait being re-serialized, [`Event`] handling must be idempotent - in
/// effect, [`Event`]s may be replayed.
///
/// Note, handlers may call back into the provider and thus deadlocking must be avoided. Be sure to
/// consult the provider's documentation on the implication of processing events and how a handler
/// may safely use the provider (e.g., see [`ChannelManager::process_pending_events`] and
/// [`ChainMonitor::process_pending_events`]).
///
/// (C-not implementable) As there is likely no reason for a user to implement this trait on their
/// own type(s).
///
/// [`process_pending_events`]: Self::process_pending_events
/// [`handle_event`]: EventHandler::handle_event
/// [`ChannelManager::process_pending_events`]: crate::ln::channelmanager::ChannelManager#method.process_pending_events
/// [`ChainMonitor::process_pending_events`]: crate::chain::chainmonitor::ChainMonitor#method.process_pending_events
/// [`ChannelManager::process_pending_events_async`]: crate::ln::channelmanager::ChannelManager::process_pending_events_async
/// [`ChainMonitor::process_pending_events_async`]: crate::chain::chainmonitor::ChainMonitor::process_pending_events_async
pub trait EventsProvider {
	/// Processes any events generated since the last call using the given event handler.
	///
	/// See the trait-level documentation for requirements.
	fn process_pending_events<H: Deref>(&self, handler: H) where H::Target: EventHandler;
}

/// A trait implemented for objects handling events from [`EventsProvider`].
///
/// An async variation also exists for implementations of [`EventsProvider`] that support async
/// event handling. The async event handler should satisfy the generic bounds: `F:
/// core::future::Future, H: Fn(Event) -> F`.
pub trait EventHandler {
	/// Handles the given [`Event`].
	///
	/// See [`EventsProvider`] for details that must be considered when implementing this method.
	fn handle_event(&self, event: Event);
}

impl<F> EventHandler for F where F: Fn(Event) {
	fn handle_event(&self, event: Event) {
		self(event)
	}
}

impl<T: EventHandler> EventHandler for Arc<T> {
	fn handle_event(&self, event: Event) {
		self.deref().handle_event(event)
	}
}
