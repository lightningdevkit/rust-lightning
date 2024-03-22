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

pub mod bump_transaction;

pub use bump_transaction::BumpTransactionEvent;

use crate::sign::SpendableOutputDescriptor;
use crate::ln::channelmanager::{InterceptId, PaymentId, RecipientOnionFields};
use crate::ln::channel::FUNDING_CONF_DEADLINE_BLOCKS;
use crate::ln::features::ChannelTypeFeatures;
use crate::ln::msgs;
use crate::ln::{ChannelId, PaymentPreimage, PaymentHash, PaymentSecret};
use crate::chain::transaction;
use crate::routing::gossip::NetworkUpdate;
use crate::util::errors::APIError;
use crate::util::ser::{BigSize, FixedLengthReader, Writeable, Writer, MaybeReadable, Readable, RequiredWrapper, UpgradableRequired, WithoutLength};
use crate::util::string::UntrustedString;
use crate::routing::router::{BlindedTail, Path, RouteHop, RouteParameters};

use bitcoin::{Transaction, OutPoint};
use bitcoin::blockdata::locktime::absolute::LockTime;
use bitcoin::blockdata::script::ScriptBuf;
use bitcoin::hashes::Hash;
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::secp256k1::PublicKey;
use crate::io;
use core::time::Duration;
use core::ops::Deref;
use crate::sync::Arc;

#[allow(unused_imports)]
use crate::prelude::*;

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

impl PaymentPurpose {
	/// Returns the preimage for this payment, if it is known.
	pub fn preimage(&self) -> Option<PaymentPreimage> {
		match self {
			PaymentPurpose::InvoicePayment { payment_preimage, .. } => *payment_preimage,
			PaymentPurpose::SpontaneousPayment(preimage) => Some(*preimage),
		}
	}
}

impl_writeable_tlv_based_enum!(PaymentPurpose,
	(0, InvoicePayment) => {
		(0, payment_preimage, option),
		(2, payment_secret, required),
	};
	(2, SpontaneousPayment)
);

/// Information about an HTLC that is part of a payment that can be claimed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClaimedHTLC {
	/// The `channel_id` of the channel over which the HTLC was received.
	pub channel_id: ChannelId,
	/// The `user_channel_id` of the channel over which the HTLC was received. This is the value
	/// passed in to [`ChannelManager::create_channel`] for outbound channels, or to
	/// [`ChannelManager::accept_inbound_channel`] for inbound channels if
	/// [`UserConfig::manually_accept_inbound_channels`] config flag is set to true. Otherwise
	/// `user_channel_id` will be randomized for an inbound channel.
	///
	/// This field will be zero for a payment that was serialized prior to LDK version 0.0.117. (This
	/// should only happen in the case that a payment was claimable prior to LDK version 0.0.117, but
	/// was not actually claimed until after upgrading.)
	///
	/// [`ChannelManager::create_channel`]: crate::ln::channelmanager::ChannelManager::create_channel
	/// [`ChannelManager::accept_inbound_channel`]: crate::ln::channelmanager::ChannelManager::accept_inbound_channel
	/// [`UserConfig::manually_accept_inbound_channels`]: crate::util::config::UserConfig::manually_accept_inbound_channels
	pub user_channel_id: u128,
	/// The block height at which this HTLC expires.
	pub cltv_expiry: u32,
	/// The amount (in msats) of this part of an MPP.
	pub value_msat: u64,
	/// The extra fee our counterparty skimmed off the top of this HTLC, if any.
	///
	/// This value will always be 0 for [`ClaimedHTLC`]s serialized with LDK versions prior to
	/// 0.0.119.
	pub counterparty_skimmed_fee_msat: u64,
}
impl_writeable_tlv_based!(ClaimedHTLC, {
	(0, channel_id, required),
	(1, counterparty_skimmed_fee_msat, (default_value, 0u64)),
	(2, user_channel_id, required),
	(4, cltv_expiry, required),
	(6, value_msat, required),
});

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
/// The reason the channel was closed. See individual variants for more details.
pub enum ClosureReason {
	/// Closure generated from receiving a peer error message.
	///
	/// Our counterparty may have broadcasted their latest commitment state, and we have
	/// as well.
	CounterpartyForceClosed {
		/// The error which the peer sent us.
		///
		/// Be careful about printing the peer_msg, a well-crafted message could exploit
		/// a security vulnerability in the terminal emulator or the logging subsystem.
		/// To be safe, use `Display` on `UntrustedString`
		///
		/// [`UntrustedString`]: crate::util::string::UntrustedString
		peer_msg: UntrustedString,
	},
	/// Closure generated from [`ChannelManager::force_close_channel`], called by the user.
	///
	/// [`ChannelManager::force_close_channel`]: crate::ln::channelmanager::ChannelManager::force_close_channel.
	HolderForceClosed,
	/// The channel was closed after negotiating a cooperative close and we've now broadcasted
	/// the cooperative close transaction. Note the shutdown may have been initiated by us.
	///
	/// This was only set in versions of LDK prior to 0.0.122.
	// Can be removed once we disallow downgrading to 0.0.121
	LegacyCooperativeClosure,
	/// The channel was closed after negotiating a cooperative close and we've now broadcasted
	/// the cooperative close transaction. This indicates that the shutdown was initiated by our
	/// counterparty.
	///
	/// In rare cases where we initiated closure immediately prior to shutting down without
	/// persisting, this value may be provided for channels we initiated closure for.
	CounterpartyInitiatedCooperativeClosure,
	/// The channel was closed after negotiating a cooperative close and we've now broadcasted
	/// the cooperative close transaction. This indicates that the shutdown was initiated by us.
	LocallyInitiatedCooperativeClosure,
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
	OutdatedChannelManager,
	/// The counterparty requested a cooperative close of a channel that had not been funded yet.
	/// The channel has been immediately closed.
	CounterpartyCoopClosedUnfundedChannel,
	/// Another channel in the same funding batch closed before the funding transaction
	/// was ready to be broadcast.
	FundingBatchClosure,
	/// One of our HTLCs timed out in a channel, causing us to force close the channel.
	HTLCsTimedOut,
}

impl core::fmt::Display for ClosureReason {
	fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
		f.write_str("Channel closed because ")?;
		match self {
			ClosureReason::CounterpartyForceClosed { peer_msg } => {
				f.write_fmt(format_args!("counterparty force-closed with message: {}", peer_msg))
			},
			ClosureReason::HolderForceClosed => f.write_str("user force-closed the channel"),
			ClosureReason::LegacyCooperativeClosure => f.write_str("the channel was cooperatively closed"),
			ClosureReason::CounterpartyInitiatedCooperativeClosure => f.write_str("the channel was cooperatively closed by our peer"),
			ClosureReason::LocallyInitiatedCooperativeClosure => f.write_str("the channel was cooperatively closed by us"),
			ClosureReason::CommitmentTxConfirmed => f.write_str("commitment or closing transaction was confirmed on chain."),
			ClosureReason::FundingTimedOut => write!(f, "funding transaction failed to confirm within {} blocks", FUNDING_CONF_DEADLINE_BLOCKS),
			ClosureReason::ProcessingError { err } => {
				f.write_str("of an exception: ")?;
				f.write_str(&err)
			},
			ClosureReason::DisconnectedPeer => f.write_str("the peer disconnected prior to the channel being funded"),
			ClosureReason::OutdatedChannelManager => f.write_str("the ChannelManager read from disk was stale compared to ChannelMonitor(s)"),
			ClosureReason::CounterpartyCoopClosedUnfundedChannel => f.write_str("the peer requested the unfunded channel be closed"),
			ClosureReason::FundingBatchClosure => f.write_str("another channel in the same funding batch closed"),
			ClosureReason::HTLCsTimedOut => f.write_str("htlcs on the channel timed out"),
		}
	}
}

impl_writeable_tlv_based_enum_upgradable!(ClosureReason,
	(0, CounterpartyForceClosed) => { (1, peer_msg, required) },
	(1, FundingTimedOut) => {},
	(2, HolderForceClosed) => {},
	(6, CommitmentTxConfirmed) => {},
	(4, LegacyCooperativeClosure) => {},
	(8, ProcessingError) => { (1, err, required) },
	(10, DisconnectedPeer) => {},
	(12, OutdatedChannelManager) => {},
	(13, CounterpartyCoopClosedUnfundedChannel) => {},
	(15, FundingBatchClosure) => {},
	(17, CounterpartyInitiatedCooperativeClosure) => {},
	(19, LocallyInitiatedCooperativeClosure) => {},
	(21, HTLCsTimedOut) => {},
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
		channel_id: ChannelId,
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
	/// We couldn't decode the incoming onion to obtain the forwarding details.
	InvalidOnion,
	/// Failure scenario where an HTLC may have been forwarded to be intended for us,
	/// but is invalid for some reason, so we reject it.
	///
	/// Some of the reasons may include:
	/// * HTLC Timeouts
	/// * Excess HTLCs for a payment that we have already fully received, over-paying for the
	///   payment,
	/// * The counterparty node modified the HTLC in transit,
	/// * A probing attack where an intermediary node is trying to detect if we are the ultimate
	///   recipient for a payment.
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
	(3, InvalidOnion) => {},
	(4, FailedPayment) => {
		(0, payment_hash, required),
	},
);

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

/// The reason the payment failed. Used in [`Event::PaymentFailed`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PaymentFailureReason {
	/// The intended recipient rejected our payment.
	RecipientRejected,
	/// The user chose to abandon this payment by calling [`ChannelManager::abandon_payment`].
	///
	/// [`ChannelManager::abandon_payment`]: crate::ln::channelmanager::ChannelManager::abandon_payment
	UserAbandoned,
	/// We exhausted all of our retry attempts while trying to send the payment, or we
	/// exhausted the [`Retry::Timeout`] if the user set one. If at any point a retry
	/// attempt failed while being forwarded along the path, an [`Event::PaymentPathFailed`] will
	/// have come before this.
	///
	/// [`Retry::Timeout`]: crate::ln::channelmanager::Retry::Timeout
	RetriesExhausted,
	/// The payment expired while retrying, based on the provided
	/// [`PaymentParameters::expiry_time`].
	///
	/// [`PaymentParameters::expiry_time`]: crate::routing::router::PaymentParameters::expiry_time
	PaymentExpired,
	/// We failed to find a route while retrying the payment.
	///
	/// Note that this generally indicates that we've exhausted the available set of possible
	/// routes - we tried the payment over a few routes but were not able to find any further
	/// candidate routes beyond those.
	RouteNotFound,
	/// This error should generally never happen. This likely means that there is a problem with
	/// your router.
	UnexpectedError,
}

impl_writeable_tlv_based_enum!(PaymentFailureReason,
	(0, RecipientRejected) => {},
	(2, UserAbandoned) => {},
	(4, RetriesExhausted) => {},
	(6, PaymentExpired) => {},
	(8, RouteNotFound) => {},
	(10, UnexpectedError) => {}, ;
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
		temporary_channel_id: ChannelId,
		/// The counterparty's node_id, which you'll need to pass back into
		/// [`ChannelManager::funding_transaction_generated`].
		///
		/// [`ChannelManager::funding_transaction_generated`]: crate::ln::channelmanager::ChannelManager::funding_transaction_generated
		counterparty_node_id: PublicKey,
		/// The value, in satoshis, that the output should have.
		channel_value_satoshis: u64,
		/// The script which should be used in the transaction output.
		output_script: ScriptBuf,
		/// The `user_channel_id` value passed in to [`ChannelManager::create_channel`] for outbound
		/// channels, or to [`ChannelManager::accept_inbound_channel`] for inbound channels if
		/// [`UserConfig::manually_accept_inbound_channels`] config flag is set to true. Otherwise
		/// `user_channel_id` will be randomized for an inbound channel.  This may be zero for objects
		/// serialized with LDK versions prior to 0.0.113.
		///
		/// [`ChannelManager::create_channel`]: crate::ln::channelmanager::ChannelManager::create_channel
		/// [`ChannelManager::accept_inbound_channel`]: crate::ln::channelmanager::ChannelManager::accept_inbound_channel
		/// [`UserConfig::manually_accept_inbound_channels`]: crate::util::config::UserConfig::manually_accept_inbound_channels
		user_channel_id: u128,
	},
	/// Indicates that we've been offered a payment and it needs to be claimed via calling
	/// [`ChannelManager::claim_funds`] with the preimage given in [`PaymentPurpose`].
	///
	/// Note that if the preimage is not known, you should call
	/// [`ChannelManager::fail_htlc_backwards`] or [`ChannelManager::fail_htlc_backwards_with_reason`]
	/// to free up resources for this HTLC and avoid network congestion.
	///
	/// If [`Event::PaymentClaimable::onion_fields`] is `Some`, and includes custom TLVs with even type
	/// numbers, you should use [`ChannelManager::fail_htlc_backwards_with_reason`] with
	/// [`FailureCode::InvalidOnionPayload`] if you fail to understand and handle the contents, or
	/// [`ChannelManager::claim_funds_with_known_custom_tlvs`] upon successful handling.
	/// If you don't intend to check for custom TLVs, you can simply use
	/// [`ChannelManager::claim_funds`], which will automatically fail back even custom TLVs.
	///
	/// If you fail to call [`ChannelManager::claim_funds`],
	/// [`ChannelManager::claim_funds_with_known_custom_tlvs`],
	/// [`ChannelManager::fail_htlc_backwards`], or
	/// [`ChannelManager::fail_htlc_backwards_with_reason`] within the HTLC's timeout, the HTLC will
	/// be automatically failed.
	///
	/// # Note
	/// LDK will not stop an inbound payment from being paid multiple times, so multiple
	/// `PaymentClaimable` events may be generated for the same payment. In such a case it is
	/// polite (and required in the lightning specification) to fail the payment the second time
	/// and give the sender their money back rather than accepting double payment.
	///
	/// # Note
	/// This event used to be called `PaymentReceived` in LDK versions 0.0.112 and earlier.
	///
	/// [`ChannelManager::claim_funds`]: crate::ln::channelmanager::ChannelManager::claim_funds
	/// [`ChannelManager::claim_funds_with_known_custom_tlvs`]: crate::ln::channelmanager::ChannelManager::claim_funds_with_known_custom_tlvs
	/// [`FailureCode::InvalidOnionPayload`]: crate::ln::channelmanager::FailureCode::InvalidOnionPayload
	/// [`ChannelManager::fail_htlc_backwards`]: crate::ln::channelmanager::ChannelManager::fail_htlc_backwards
	/// [`ChannelManager::fail_htlc_backwards_with_reason`]: crate::ln::channelmanager::ChannelManager::fail_htlc_backwards_with_reason
	PaymentClaimable {
		/// The node that will receive the payment after it has been claimed.
		/// This is useful to identify payments received via [phantom nodes].
		/// This field will always be filled in when the event was generated by LDK versions
		/// 0.0.113 and above.
		///
		/// [phantom nodes]: crate::sign::PhantomKeysManager
		receiver_node_id: Option<PublicKey>,
		/// The hash for which the preimage should be handed to the ChannelManager. Note that LDK will
		/// not stop you from registering duplicate payment hashes for inbound payments.
		payment_hash: PaymentHash,
		/// The fields in the onion which were received with each HTLC. Only fields which were
		/// identical in each HTLC involved in the payment will be included here.
		///
		/// Payments received on LDK versions prior to 0.0.115 will have this field unset.
		onion_fields: Option<RecipientOnionFields>,
		/// The value, in thousandths of a satoshi, that this payment is claimable for. May be greater
		/// than the invoice amount.
		///
		/// May be less than the invoice amount if [`ChannelConfig::accept_underpaying_htlcs`] is set
		/// and the previous hop took an extra fee.
		///
		/// # Note
		/// If [`ChannelConfig::accept_underpaying_htlcs`] is set and you claim without verifying this
		/// field, you may lose money!
		///
		/// [`ChannelConfig::accept_underpaying_htlcs`]: crate::util::config::ChannelConfig::accept_underpaying_htlcs
		amount_msat: u64,
		/// The value, in thousands of a satoshi, that was skimmed off of this payment as an extra fee
		/// taken by our channel counterparty.
		///
		/// Will always be 0 unless [`ChannelConfig::accept_underpaying_htlcs`] is set.
		///
		/// [`ChannelConfig::accept_underpaying_htlcs`]: crate::util::config::ChannelConfig::accept_underpaying_htlcs
		counterparty_skimmed_fee_msat: u64,
		/// Information for claiming this received payment, based on whether the purpose of the
		/// payment is to pay an invoice or to send a spontaneous payment.
		purpose: PaymentPurpose,
		/// The `channel_id` indicating over which channel we received the payment.
		via_channel_id: Option<ChannelId>,
		/// The `user_channel_id` indicating over which channel we received the payment.
		via_user_channel_id: Option<u128>,
		/// The block height at which this payment will be failed back and will no longer be
		/// eligible for claiming.
		///
		/// Prior to this height, a call to [`ChannelManager::claim_funds`] is guaranteed to
		/// succeed, however you should wait for [`Event::PaymentClaimed`] to be sure.
		///
		/// [`ChannelManager::claim_funds`]: crate::ln::channelmanager::ChannelManager::claim_funds
		claim_deadline: Option<u32>,
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
		/// [phantom nodes]: crate::sign::PhantomKeysManager
		receiver_node_id: Option<PublicKey>,
		/// The payment hash of the claimed payment. Note that LDK will not stop you from
		/// registering duplicate payment hashes for inbound payments.
		payment_hash: PaymentHash,
		/// The value, in thousandths of a satoshi, that this payment is for. May be greater than the
		/// invoice amount.
		amount_msat: u64,
		/// The purpose of the claimed payment, i.e. whether the payment was for an invoice or a
		/// spontaneous payment.
		purpose: PaymentPurpose,
		/// The HTLCs that comprise the claimed payment. This will be empty for events serialized prior
		/// to LDK version 0.0.117.
		htlcs: Vec<ClaimedHTLC>,
		/// The sender-intended sum total of all the MPP parts. This will be `None` for events
		/// serialized prior to LDK version 0.0.117.
		sender_intended_total_msat: Option<u64>,
	},
	/// Indicates that a peer connection with a node is needed in order to send an [`OnionMessage`].
	///
	/// Typically, this happens when a [`MessageRouter`] is unable to find a complete path to a
	/// [`Destination`]. Once a connection is established, any messages buffered by an
	/// [`OnionMessageHandler`] may be sent.
	///
	/// This event will not be generated for onion message forwards; only for sends including
	/// replies. Handlers should connect to the node otherwise any buffered messages may be lost.
	///
	/// [`OnionMessage`]: msgs::OnionMessage
	/// [`MessageRouter`]: crate::onion_message::messenger::MessageRouter
	/// [`Destination`]: crate::onion_message::messenger::Destination
	/// [`OnionMessageHandler`]: crate::ln::msgs::OnionMessageHandler
	ConnectionNeeded {
		/// The node id for the node needing a connection.
		node_id: PublicKey,
		/// Sockets for connecting to the node.
		addresses: Vec<msgs::SocketAddress>,
	},
	/// Indicates a request for an invoice failed to yield a response in a reasonable amount of time
	/// or was explicitly abandoned by [`ChannelManager::abandon_payment`]. This may be for an
	/// [`InvoiceRequest`] sent for an [`Offer`] or for a [`Refund`] that hasn't been redeemed.
	///
	/// [`ChannelManager::abandon_payment`]: crate::ln::channelmanager::ChannelManager::abandon_payment
	/// [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
	/// [`Offer`]: crate::offers::offer::Offer
	/// [`Refund`]: crate::offers::refund::Refund
	InvoiceRequestFailed {
		/// The `payment_id` to have been associated with payment for the requested invoice.
		payment_id: PaymentId,
	},
	/// Indicates an outbound payment we made succeeded (i.e. it made it all the way to its target
	/// and we got back the payment preimage for it).
	///
	/// Note for MPP payments: in rare cases, this event may be preceded by a `PaymentPathFailed`
	/// event. In this situation, you SHOULD treat this payment as having succeeded.
	PaymentSent {
		/// The `payment_id` passed to [`ChannelManager::send_payment`].
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
	/// In exceedingly rare cases, it is possible that an [`Event::PaymentFailed`] is generated for
	/// a payment after an [`Event::PaymentSent`] event for this same payment has already been
	/// received and processed. In this case, the [`Event::PaymentFailed`] event MUST be ignored,
	/// and the payment MUST be treated as having succeeded.
	///
	/// [`Retry`]: crate::ln::channelmanager::Retry
	/// [`ChannelManager::abandon_payment`]: crate::ln::channelmanager::ChannelManager::abandon_payment
	PaymentFailed {
		/// The `payment_id` passed to [`ChannelManager::send_payment`].
		///
		/// [`ChannelManager::send_payment`]: crate::ln::channelmanager::ChannelManager::send_payment
		payment_id: PaymentId,
		/// The hash that was given to [`ChannelManager::send_payment`].
		///
		/// [`ChannelManager::send_payment`]: crate::ln::channelmanager::ChannelManager::send_payment
		payment_hash: PaymentHash,
		/// The reason the payment failed. This is only `None` for events generated or serialized
		/// by versions prior to 0.0.115.
		reason: Option<PaymentFailureReason>,
	},
	/// Indicates that a path for an outbound payment was successful.
	///
	/// Always generated after [`Event::PaymentSent`] and thus useful for scoring channels. See
	/// [`Event::PaymentSent`] for obtaining the payment preimage.
	PaymentPathSuccessful {
		/// The `payment_id` passed to [`ChannelManager::send_payment`].
		///
		/// [`ChannelManager::send_payment`]: crate::ln::channelmanager::ChannelManager::send_payment
		payment_id: PaymentId,
		/// The hash that was given to [`ChannelManager::send_payment`].
		///
		/// This will be `Some` for all payments which completed on LDK 0.0.104 or later.
		///
		/// [`ChannelManager::send_payment`]: crate::ln::channelmanager::ChannelManager::send_payment
		payment_hash: Option<PaymentHash>,
		/// The payment path that was successful.
		///
		/// May contain a closed channel if the HTLC sent along the path was fulfilled on chain.
		path: Path,
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
		/// The `payment_id` passed to [`ChannelManager::send_payment`].
		///
		/// This will be `Some` for all payment paths which failed on LDK 0.0.103 or later.
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
		path: Path,
		/// The channel responsible for the failed payment path.
		///
		/// Note that for route hints or for the first hop in a path this may be an SCID alias and
		/// may not refer to a channel in the public network graph. These aliases may also collide
		/// with channels in the public network graph.
		///
		/// If this is `Some`, then the corresponding channel should be avoided when the payment is
		/// retried. May be `None` for older [`Event`] serializations.
		short_channel_id: Option<u64>,
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
		path: Path,
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
		path: Path,
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
		/// Forwarding less than this amount may break compatibility with LDK versions prior to 0.0.116.
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
		/// The `channel_id` indicating which channel the spendable outputs belong to.
		///
		/// This will always be `Some` for events generated by LDK versions 0.0.117 and above.
		channel_id: Option<ChannelId>,
	},
	/// This event is generated when a payment has been successfully forwarded through us and a
	/// forwarding fee earned.
	PaymentForwarded {
		/// The channel id of the incoming channel between the previous node and us.
		///
		/// This is only `None` for events generated or serialized by versions prior to 0.0.107.
		prev_channel_id: Option<ChannelId>,
		/// The channel id of the outgoing channel between the next node and us.
		///
		/// This is only `None` for events generated or serialized by versions prior to 0.0.107.
		next_channel_id: Option<ChannelId>,
		/// The `user_channel_id` of the incoming channel between the previous node and us.
		///
		/// This is only `None` for events generated or serialized by versions prior to 0.0.122.
		prev_user_channel_id: Option<u128>,
		/// The `user_channel_id` of the outgoing channel between the next node and us.
		///
		/// This will be `None` if the payment was settled via an on-chain transaction. See the
		/// caveat described for the `total_fee_earned_msat` field. Moreover it will be `None` for
		/// events generated or serialized by versions prior to 0.0.122.
		next_user_channel_id: Option<u128>,
		/// The total fee, in milli-satoshis, which was earned as a result of the payment.
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
		/// `PaymentForwarded` events are generated for the same payment iff `total_fee_earned_msat` is
		/// `None`.
		total_fee_earned_msat: Option<u64>,
		/// The share of the total fee, in milli-satoshis, which was withheld in addition to the
		/// forwarding fee.
		///
		/// This will only be `Some` if we forwarded an intercepted HTLC with less than the
		/// expected amount. This means our counterparty accepted to receive less than the invoice
		/// amount, e.g., by claiming the payment featuring a corresponding
		/// [`PaymentClaimable::counterparty_skimmed_fee_msat`].
		///
		/// Will also always be `None` for events serialized with LDK prior to version 0.0.122.
		///
		/// The caveat described above the `total_fee_earned_msat` field applies here as well.
		///
		/// [`PaymentClaimable::counterparty_skimmed_fee_msat`]: Self::PaymentClaimable::counterparty_skimmed_fee_msat
		skimmed_fee_msat: Option<u64>,
		/// If this is `true`, the forwarded HTLC was claimed by our counterparty via an on-chain
		/// transaction.
		claim_from_onchain_tx: bool,
		/// The final amount forwarded, in milli-satoshis, after the fee is deducted.
		///
		/// The caveat described above the `total_fee_earned_msat` field applies here as well.
		outbound_amount_forwarded_msat: Option<u64>,
	},
	/// Used to indicate that a channel with the given `channel_id` is being opened and pending
	/// confirmation on-chain.
	///
	/// This event is emitted when the funding transaction has been signed and is broadcast to the
	/// network. For 0conf channels it will be immediately followed by the corresponding
	/// [`Event::ChannelReady`] event.
	ChannelPending {
		/// The `channel_id` of the channel that is pending confirmation.
		channel_id: ChannelId,
		/// The `user_channel_id` value passed in to [`ChannelManager::create_channel`] for outbound
		/// channels, or to [`ChannelManager::accept_inbound_channel`] for inbound channels if
		/// [`UserConfig::manually_accept_inbound_channels`] config flag is set to true. Otherwise
		/// `user_channel_id` will be randomized for an inbound channel.
		///
		/// [`ChannelManager::create_channel`]: crate::ln::channelmanager::ChannelManager::create_channel
		/// [`ChannelManager::accept_inbound_channel`]: crate::ln::channelmanager::ChannelManager::accept_inbound_channel
		/// [`UserConfig::manually_accept_inbound_channels`]: crate::util::config::UserConfig::manually_accept_inbound_channels
		user_channel_id: u128,
		/// The `temporary_channel_id` this channel used to be known by during channel establishment.
		///
		/// Will be `None` for channels created prior to LDK version 0.0.115.
		former_temporary_channel_id: Option<ChannelId>,
		/// The `node_id` of the channel counterparty.
		counterparty_node_id: PublicKey,
		/// The outpoint of the channel's funding transaction.
		funding_txo: OutPoint,
		/// The features that this channel will operate with.
		///
		/// Will be `None` for channels created prior to LDK version 0.0.122.
		channel_type: Option<ChannelTypeFeatures>,
	},
	/// Used to indicate that a channel with the given `channel_id` is ready to
	/// be used. This event is emitted either when the funding transaction has been confirmed
	/// on-chain, or, in case of a 0conf channel, when both parties have confirmed the channel
	/// establishment.
	ChannelReady {
		/// The `channel_id` of the channel that is ready.
		channel_id: ChannelId,
		/// The `user_channel_id` value passed in to [`ChannelManager::create_channel`] for outbound
		/// channels, or to [`ChannelManager::accept_inbound_channel`] for inbound channels if
		/// [`UserConfig::manually_accept_inbound_channels`] config flag is set to true. Otherwise
		/// `user_channel_id` will be randomized for an inbound channel.
		///
		/// [`ChannelManager::create_channel`]: crate::ln::channelmanager::ChannelManager::create_channel
		/// [`ChannelManager::accept_inbound_channel`]: crate::ln::channelmanager::ChannelManager::accept_inbound_channel
		/// [`UserConfig::manually_accept_inbound_channels`]: crate::util::config::UserConfig::manually_accept_inbound_channels
		user_channel_id: u128,
		/// The `node_id` of the channel counterparty.
		counterparty_node_id: PublicKey,
		/// The features that this channel will operate with.
		channel_type: ChannelTypeFeatures,
	},
	/// Used to indicate that a previously opened channel with the given `channel_id` is in the
	/// process of closure.
	///
	/// Note that this event is only triggered for accepted channels: if the
	/// [`UserConfig::manually_accept_inbound_channels`] config flag is set to true and the channel is
	/// rejected, no `ChannelClosed` event will be sent.
	///
	/// [`ChannelManager::accept_inbound_channel`]: crate::ln::channelmanager::ChannelManager::accept_inbound_channel
	/// [`UserConfig::manually_accept_inbound_channels`]: crate::util::config::UserConfig::manually_accept_inbound_channels
	ChannelClosed {
		/// The `channel_id` of the channel which has been closed. Note that on-chain transactions
		/// resolving the channel are likely still awaiting confirmation.
		channel_id: ChannelId,
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
		reason: ClosureReason,
		/// Counterparty in the closed channel.
		///
		/// This field will be `None` for objects serialized prior to LDK 0.0.117.
		counterparty_node_id: Option<PublicKey>,
		/// Channel capacity of the closing channel (sats).
		///
		/// This field will be `None` for objects serialized prior to LDK 0.0.117.
		channel_capacity_sats: Option<u64>,
		/// The original channel funding TXO; this helps checking for the existence and confirmation
		/// status of the closing tx.
		/// Note that for instances serialized in v0.0.119 or prior this will be missing (None).
		channel_funding_txo: Option<transaction::OutPoint>,
	},
	/// Used to indicate to the user that they can abandon the funding transaction and recycle the
	/// inputs for another purpose.
	///
	/// This event is not guaranteed to be generated for channels that are closed due to a restart.
	DiscardFunding {
		/// The channel_id of the channel which has been closed.
		channel_id: ChannelId,
		/// The full transaction received from the user
		transaction: Transaction
	},
	/// Indicates a request to open a new channel by a peer.
	///
	/// To accept the request, call [`ChannelManager::accept_inbound_channel`]. To reject the request,
	/// call [`ChannelManager::force_close_without_broadcasting_txn`]. Note that a ['ChannelClosed`]
	/// event will _not_ be triggered if the channel is rejected.
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
		temporary_channel_id: ChannelId,
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
	/// * Expected MPP amount has already been reached
	/// * The HTLC has timed out
	///
	/// This event, however, does not get generated if an HTLC fails to meet the forwarding
	/// requirements (i.e. insufficient fees paid, or a CLTV that is too soon).
	HTLCHandlingFailed {
		/// The channel over which the HTLC was received.
		prev_channel_id: ChannelId,
		/// Destination of the HTLC that failed to be processed.
		failed_next_destination: HTLCDestination,
	},
	/// Indicates that a transaction originating from LDK needs to have its fee bumped. This event
	/// requires confirmed external funds to be readily available to spend.
	///
	/// LDK does not currently generate this event unless the
	/// [`ChannelHandshakeConfig::negotiate_anchors_zero_fee_htlc_tx`] config flag is set to true.
	/// It is limited to the scope of channels with anchor outputs.
	///
	/// [`ChannelHandshakeConfig::negotiate_anchors_zero_fee_htlc_tx`]: crate::util::config::ChannelHandshakeConfig::negotiate_anchors_zero_fee_htlc_tx
	BumpTransaction(BumpTransactionEvent),
	/// We received an onion message that is intended to be forwarded to a peer
	/// that is currently offline. This event will only be generated if the
	/// `OnionMessenger` was initialized with
	/// [`OnionMessenger::new_with_offline_peer_interception`], see its docs.
	///
	/// [`OnionMessenger::new_with_offline_peer_interception`]: crate::onion_message::messenger::OnionMessenger::new_with_offline_peer_interception
	OnionMessageIntercepted {
		/// The node id of the offline peer.
		peer_node_id: PublicKey,
		/// The onion message intended to be forwarded to `peer_node_id`.
		message: msgs::OnionMessage,
	},
	/// Indicates that an onion message supporting peer has come online and it may
	/// be time to forward any onion messages that were previously intercepted for
	/// them. This event will only be generated if the `OnionMessenger` was
	/// initialized with
	/// [`OnionMessenger::new_with_offline_peer_interception`], see its docs.
	///
	/// [`OnionMessenger::new_with_offline_peer_interception`]: crate::onion_message::messenger::OnionMessenger::new_with_offline_peer_interception
	OnionMessagePeerConnected {
		/// The node id of the peer we just connected to, who advertises support for
		/// onion messages.
		peer_node_id: PublicKey,
	}
}

impl Writeable for Event {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		match self {
			&Event::FundingGenerationReady { .. } => {
				0u8.write(writer)?;
				// We never write out FundingGenerationReady events as, upon disconnection, peers
				// drop any channels which have not yet exchanged funding_signed.
			},
			&Event::PaymentClaimable { ref payment_hash, ref amount_msat, counterparty_skimmed_fee_msat,
				ref purpose, ref receiver_node_id, ref via_channel_id, ref via_user_channel_id,
				ref claim_deadline, ref onion_fields
			} => {
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
				let skimmed_fee_opt = if counterparty_skimmed_fee_msat == 0 { None }
					else { Some(counterparty_skimmed_fee_msat) };
				write_tlv_fields!(writer, {
					(0, payment_hash, required),
					(1, receiver_node_id, option),
					(2, payment_secret, option),
					(3, via_channel_id, option),
					(4, amount_msat, required),
					(5, via_user_channel_id, option),
					// Type 6 was `user_payment_id` on 0.0.103 and earlier
					(7, claim_deadline, option),
					(8, payment_preimage, option),
					(9, onion_fields, option),
					(10, skimmed_fee_opt, option),
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
				ref path, ref short_channel_id,
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
					(4, path.blinded_tail, option),
					(5, path.hops, required_vec),
					(7, short_channel_id, option),
					(9, None::<RouteParameters>, option), // retry in LDK versions prior to 0.0.115
					(11, payment_id, option),
					(13, failure, required),
				});
			},
			&Event::PendingHTLCsForwardable { time_forwardable: _ } => {
				4u8.write(writer)?;
				// Note that we now ignore these on the read end as we'll re-generate them in
				// ChannelManager, we write them here only for backwards compatibility.
			},
			&Event::SpendableOutputs { ref outputs, channel_id } => {
				5u8.write(writer)?;
				write_tlv_fields!(writer, {
					(0, WithoutLength(outputs), required),
					(1, channel_id, option),
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
			&Event::PaymentForwarded {
				prev_channel_id, next_channel_id, prev_user_channel_id, next_user_channel_id,
				total_fee_earned_msat, skimmed_fee_msat, claim_from_onchain_tx,
				outbound_amount_forwarded_msat,
			} => {
				7u8.write(writer)?;
				write_tlv_fields!(writer, {
					(0, total_fee_earned_msat, option),
					(1, prev_channel_id, option),
					(2, claim_from_onchain_tx, required),
					(3, next_channel_id, option),
					(5, outbound_amount_forwarded_msat, option),
					(7, skimmed_fee_msat, option),
					(9, prev_user_channel_id, option),
					(11, next_user_channel_id, option),
				});
			},
			&Event::ChannelClosed { ref channel_id, ref user_channel_id, ref reason,
				ref counterparty_node_id, ref channel_capacity_sats, ref channel_funding_txo
			} => {
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
					(5, counterparty_node_id, option),
					(7, channel_capacity_sats, option),
					(9, channel_funding_txo, option),
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
					(4, path.hops, required_vec),
					(6, path.blinded_tail, option),
				})
			},
			&Event::PaymentFailed { ref payment_id, ref payment_hash, ref reason } => {
				15u8.write(writer)?;
				write_tlv_fields!(writer, {
					(0, payment_id, required),
					(1, reason, option),
					(2, payment_hash, required),
				})
			},
			&Event::OpenChannelRequest { .. } => {
				17u8.write(writer)?;
				// We never write the OpenChannelRequest events as, upon disconnection, peers
				// drop any channels which have not yet exchanged funding_signed.
			},
			&Event::PaymentClaimed { ref payment_hash, ref amount_msat, ref purpose, ref receiver_node_id, ref htlcs, ref sender_intended_total_msat } => {
				19u8.write(writer)?;
				write_tlv_fields!(writer, {
					(0, payment_hash, required),
					(1, receiver_node_id, option),
					(2, purpose, required),
					(4, amount_msat, required),
					(5, *htlcs, optional_vec),
					(7, sender_intended_total_msat, option),
				});
			},
			&Event::ProbeSuccessful { ref payment_id, ref payment_hash, ref path } => {
				21u8.write(writer)?;
				write_tlv_fields!(writer, {
					(0, payment_id, required),
					(2, payment_hash, required),
					(4, path.hops, required_vec),
					(6, path.blinded_tail, option),
				})
			},
			&Event::ProbeFailed { ref payment_id, ref payment_hash, ref path, ref short_channel_id } => {
				23u8.write(writer)?;
				write_tlv_fields!(writer, {
					(0, payment_id, required),
					(2, payment_hash, required),
					(4, path.hops, required_vec),
					(6, short_channel_id, option),
					(8, path.blinded_tail, option),
				})
			},
			&Event::HTLCHandlingFailed { ref prev_channel_id, ref failed_next_destination } => {
				25u8.write(writer)?;
				write_tlv_fields!(writer, {
					(0, prev_channel_id, required),
					(2, failed_next_destination, required),
				})
			},
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
			&Event::ChannelPending { ref channel_id, ref user_channel_id,
				ref former_temporary_channel_id, ref counterparty_node_id, ref funding_txo,
				ref channel_type
			} => {
				31u8.write(writer)?;
				write_tlv_fields!(writer, {
					(0, channel_id, required),
					(1, channel_type, option),
					(2, user_channel_id, required),
					(4, former_temporary_channel_id, required),
					(6, counterparty_node_id, required),
					(8, funding_txo, required),
				});
			},
			&Event::InvoiceRequestFailed { ref payment_id } => {
				33u8.write(writer)?;
				write_tlv_fields!(writer, {
					(0, payment_id, required),
				})
			},
			&Event::ConnectionNeeded { .. } => {
				35u8.write(writer)?;
				// Never write ConnectionNeeded events as buffered onion messages aren't serialized.
			},
			&Event::OnionMessageIntercepted { ref peer_node_id, ref message } => {
				37u8.write(writer)?;
				write_tlv_fields!(writer, {
					(0, peer_node_id, required),
					(2, message, required),
				});
			},
			&Event::OnionMessagePeerConnected { ref peer_node_id } => {
				39u8.write(writer)?;
				write_tlv_fields!(writer, {
					(0, peer_node_id, required),
				});
			}
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
			// Note that we do not write a length-prefixed TLV for FundingGenerationReady events.
			0u8 => Ok(None),
			1u8 => {
				let mut f = || {
					let mut payment_hash = PaymentHash([0; 32]);
					let mut payment_preimage = None;
					let mut payment_secret = None;
					let mut amount_msat = 0;
					let mut counterparty_skimmed_fee_msat_opt = None;
					let mut receiver_node_id = None;
					let mut _user_payment_id = None::<u64>; // Used in 0.0.103 and earlier, no longer written in 0.0.116+.
					let mut via_channel_id = None;
					let mut claim_deadline = None;
					let mut via_user_channel_id = None;
					let mut onion_fields = None;
					read_tlv_fields!(reader, {
						(0, payment_hash, required),
						(1, receiver_node_id, option),
						(2, payment_secret, option),
						(3, via_channel_id, option),
						(4, amount_msat, required),
						(5, via_user_channel_id, option),
						(6, _user_payment_id, option),
						(7, claim_deadline, option),
						(8, payment_preimage, option),
						(9, onion_fields, option),
						(10, counterparty_skimmed_fee_msat_opt, option),
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
						counterparty_skimmed_fee_msat: counterparty_skimmed_fee_msat_opt.unwrap_or(0),
						purpose,
						via_channel_id,
						via_user_channel_id,
						claim_deadline,
						onion_fields,
					}))
				};
				f()
			},
			2u8 => {
				let mut f = || {
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
						payment_hash = Some(PaymentHash(Sha256::hash(&payment_preimage.0[..]).to_byte_array()));
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
				let mut f = || {
					#[cfg(test)]
					let error_code = Readable::read(reader)?;
					#[cfg(test)]
					let error_data = Readable::read(reader)?;
					let mut payment_hash = PaymentHash([0; 32]);
					let mut payment_failed_permanently = false;
					let mut network_update = None;
					let mut blinded_tail: Option<BlindedTail> = None;
					let mut path: Option<Vec<RouteHop>> = Some(vec![]);
					let mut short_channel_id = None;
					let mut payment_id = None;
					let mut failure_opt = None;
					read_tlv_fields!(reader, {
						(0, payment_hash, required),
						(1, network_update, upgradable_option),
						(2, payment_failed_permanently, required),
						(4, blinded_tail, option),
						// Added as a part of LDK 0.0.101 and always filled in since.
						// Defaults to an empty Vec, though likely should have been `Option`al.
						(5, path, optional_vec),
						(7, short_channel_id, option),
						(11, payment_id, option),
						(13, failure_opt, upgradable_option),
					});
					let failure = failure_opt.unwrap_or_else(|| PathFailure::OnPath { network_update });
					Ok(Some(Event::PaymentPathFailed {
						payment_id,
						payment_hash,
						payment_failed_permanently,
						failure,
						path: Path { hops: path.unwrap(), blinded_tail },
						short_channel_id,
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
				let mut f = || {
					let mut outputs = WithoutLength(Vec::new());
					let mut channel_id: Option<ChannelId> = None;
					read_tlv_fields!(reader, {
						(0, outputs, required),
						(1, channel_id, option),
					});
					Ok(Some(Event::SpendableOutputs { outputs: outputs.0, channel_id }))
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
				let mut f = || {
					let mut prev_channel_id = None;
					let mut next_channel_id = None;
					let mut prev_user_channel_id = None;
					let mut next_user_channel_id = None;
					let mut total_fee_earned_msat = None;
					let mut skimmed_fee_msat = None;
					let mut claim_from_onchain_tx = false;
					let mut outbound_amount_forwarded_msat = None;
					read_tlv_fields!(reader, {
						(0, total_fee_earned_msat, option),
						(1, prev_channel_id, option),
						(2, claim_from_onchain_tx, required),
						(3, next_channel_id, option),
						(5, outbound_amount_forwarded_msat, option),
						(7, skimmed_fee_msat, option),
						(9, prev_user_channel_id, option),
						(11, next_user_channel_id, option),
					});
					Ok(Some(Event::PaymentForwarded {
						prev_channel_id, next_channel_id, prev_user_channel_id,
						next_user_channel_id, total_fee_earned_msat, skimmed_fee_msat,
						claim_from_onchain_tx, outbound_amount_forwarded_msat,
					}))
				};
				f()
			},
			9u8 => {
				let mut f = || {
					let mut channel_id = ChannelId::new_zero();
					let mut reason = UpgradableRequired(None);
					let mut user_channel_id_low_opt: Option<u64> = None;
					let mut user_channel_id_high_opt: Option<u64> = None;
					let mut counterparty_node_id = None;
					let mut channel_capacity_sats = None;
					let mut channel_funding_txo = None;
					read_tlv_fields!(reader, {
						(0, channel_id, required),
						(1, user_channel_id_low_opt, option),
						(2, reason, upgradable_required),
						(3, user_channel_id_high_opt, option),
						(5, counterparty_node_id, option),
						(7, channel_capacity_sats, option),
						(9, channel_funding_txo, option),
					});

					// `user_channel_id` used to be a single u64 value. In order to remain
					// backwards compatible with versions prior to 0.0.113, the u128 is serialized
					// as two separate u64 values.
					let user_channel_id = (user_channel_id_low_opt.unwrap_or(0) as u128) +
						((user_channel_id_high_opt.unwrap_or(0) as u128) << 64);

					Ok(Some(Event::ChannelClosed { channel_id, user_channel_id, reason: _init_tlv_based_struct_field!(reason, upgradable_required),
						counterparty_node_id, channel_capacity_sats, channel_funding_txo }))
				};
				f()
			},
			11u8 => {
				let mut f = || {
					let mut channel_id = ChannelId::new_zero();
					let mut transaction = Transaction{ version: 2, lock_time: LockTime::ZERO, input: Vec::new(), output: Vec::new() };
					read_tlv_fields!(reader, {
						(0, channel_id, required),
						(2, transaction, required),
					});
					Ok(Some(Event::DiscardFunding { channel_id, transaction } ))
				};
				f()
			},
			13u8 => {
				let mut f = || {
					_init_and_read_len_prefixed_tlv_fields!(reader, {
						(0, payment_id, required),
						(2, payment_hash, option),
						(4, path, required_vec),
						(6, blinded_tail, option),
					});
					Ok(Some(Event::PaymentPathSuccessful {
						payment_id: payment_id.0.unwrap(),
						payment_hash,
						path: Path { hops: path, blinded_tail },
					}))
				};
				f()
			},
			15u8 => {
				let mut f = || {
					let mut payment_hash = PaymentHash([0; 32]);
					let mut payment_id = PaymentId([0; 32]);
					let mut reason = None;
					read_tlv_fields!(reader, {
						(0, payment_id, required),
						(1, reason, upgradable_option),
						(2, payment_hash, required),
					});
					Ok(Some(Event::PaymentFailed {
						payment_id,
						payment_hash,
						reason,
					}))
				};
				f()
			},
			17u8 => {
				// Value 17 is used for `Event::OpenChannelRequest`.
				Ok(None)
			},
			19u8 => {
				let mut f = || {
					let mut payment_hash = PaymentHash([0; 32]);
					let mut purpose = UpgradableRequired(None);
					let mut amount_msat = 0;
					let mut receiver_node_id = None;
					let mut htlcs: Option<Vec<ClaimedHTLC>> = Some(vec![]);
					let mut sender_intended_total_msat: Option<u64> = None;
					read_tlv_fields!(reader, {
						(0, payment_hash, required),
						(1, receiver_node_id, option),
						(2, purpose, upgradable_required),
						(4, amount_msat, required),
						(5, htlcs, optional_vec),
						(7, sender_intended_total_msat, option),
					});
					Ok(Some(Event::PaymentClaimed {
						receiver_node_id,
						payment_hash,
						purpose: _init_tlv_based_struct_field!(purpose, upgradable_required),
						amount_msat,
						htlcs: htlcs.unwrap_or(vec![]),
						sender_intended_total_msat,
					}))
				};
				f()
			},
			21u8 => {
				let mut f = || {
					_init_and_read_len_prefixed_tlv_fields!(reader, {
						(0, payment_id, required),
						(2, payment_hash, required),
						(4, path, required_vec),
						(6, blinded_tail, option),
					});
					Ok(Some(Event::ProbeSuccessful {
						payment_id: payment_id.0.unwrap(),
						payment_hash: payment_hash.0.unwrap(),
						path: Path { hops: path, blinded_tail },
					}))
				};
				f()
			},
			23u8 => {
				let mut f = || {
					_init_and_read_len_prefixed_tlv_fields!(reader, {
						(0, payment_id, required),
						(2, payment_hash, required),
						(4, path, required_vec),
						(6, short_channel_id, option),
						(8, blinded_tail, option),
					});
					Ok(Some(Event::ProbeFailed {
						payment_id: payment_id.0.unwrap(),
						payment_hash: payment_hash.0.unwrap(),
						path: Path { hops: path, blinded_tail },
						short_channel_id,
					}))
				};
				f()
			},
			25u8 => {
				let mut f = || {
					let mut prev_channel_id = ChannelId::new_zero();
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
				let mut f = || {
					let mut channel_id = ChannelId::new_zero();
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
			31u8 => {
				let mut f = || {
					let mut channel_id = ChannelId::new_zero();
					let mut user_channel_id: u128 = 0;
					let mut former_temporary_channel_id = None;
					let mut counterparty_node_id = RequiredWrapper(None);
					let mut funding_txo = RequiredWrapper(None);
					let mut channel_type = None;
					read_tlv_fields!(reader, {
						(0, channel_id, required),
						(1, channel_type, option),
						(2, user_channel_id, required),
						(4, former_temporary_channel_id, required),
						(6, counterparty_node_id, required),
						(8, funding_txo, required),
					});

					Ok(Some(Event::ChannelPending {
						channel_id,
						user_channel_id,
						former_temporary_channel_id,
						counterparty_node_id: counterparty_node_id.0.unwrap(),
						funding_txo: funding_txo.0.unwrap(),
						channel_type,
					}))
				};
				f()
			},
			33u8 => {
				let mut f = || {
					_init_and_read_len_prefixed_tlv_fields!(reader, {
						(0, payment_id, required),
					});
					Ok(Some(Event::InvoiceRequestFailed {
						payment_id: payment_id.0.unwrap(),
					}))
				};
				f()
			},
			// Note that we do not write a length-prefixed TLV for ConnectionNeeded events.
			35u8 => Ok(None),
			37u8 => {
				let mut f = || {
					_init_and_read_len_prefixed_tlv_fields!(reader, {
						(0, peer_node_id, required),
						(2, message, required),
					});
					Ok(Some(Event::OnionMessageIntercepted {
						peer_node_id: peer_node_id.0.unwrap(), message: message.0.unwrap()
					}))
				};
				f()
			},
			39u8 => {
				let mut f = || {
					_init_and_read_len_prefixed_tlv_fields!(reader, {
						(0, peer_node_id, required),
					});
					Ok(Some(Event::OnionMessagePeerConnected {
						peer_node_id: peer_node_id.0.unwrap()
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
#[cfg_attr(test, derive(PartialEq))]
pub enum MessageSendEvent {
	/// Used to indicate that we've accepted a channel open and should send the accept_channel
	/// message provided to the given peer.
	SendAcceptChannel {
		/// The node_id of the node which should receive this message
		node_id: PublicKey,
		/// The message which should be sent.
		msg: msgs::AcceptChannel,
	},
	/// Used to indicate that we've accepted a V2 channel open and should send the accept_channel2
	/// message provided to the given peer.
	SendAcceptChannelV2 {
		/// The node_id of the node which should receive this message
		node_id: PublicKey,
		/// The message which should be sent.
		msg: msgs::AcceptChannelV2,
	},
	/// Used to indicate that we've initiated a channel open and should send the open_channel
	/// message provided to the given peer.
	SendOpenChannel {
		/// The node_id of the node which should receive this message
		node_id: PublicKey,
		/// The message which should be sent.
		msg: msgs::OpenChannel,
	},
	/// Used to indicate that we've initiated a V2 channel open and should send the open_channel2
	/// message provided to the given peer.
	SendOpenChannelV2 {
		/// The node_id of the node which should receive this message
		node_id: PublicKey,
		/// The message which should be sent.
		msg: msgs::OpenChannelV2,
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
	/// Used to indicate that a stfu message should be sent to the peer with the given node id.
	SendStfu {
		/// The node_id of the node which should receive this message
		node_id: PublicKey,
		/// The message which should be sent.
		msg: msgs::Stfu,
	},
	/// Used to indicate that a splice message should be sent to the peer with the given node id.
	SendSplice {
		/// The node_id of the node which should receive this message
		node_id: PublicKey,
		/// The message which should be sent.
		msg: msgs::Splice,
	},
	/// Used to indicate that a splice_ack message should be sent to the peer with the given node id.
	SendSpliceAck {
		/// The node_id of the node which should receive this message
		node_id: PublicKey,
		/// The message which should be sent.
		msg: msgs::SpliceAck,
	},
	/// Used to indicate that a splice_locked message should be sent to the peer with the given node id.
	SendSpliceLocked {
		/// The node_id of the node which should receive this message
		node_id: PublicKey,
		/// The message which should be sent.
		msg: msgs::SpliceLocked,
	},
	/// Used to indicate that a tx_add_input message should be sent to the peer with the given node_id.
	SendTxAddInput {
		/// The node_id of the node which should receive this message
		node_id: PublicKey,
		/// The message which should be sent.
		msg: msgs::TxAddInput,
	},
	/// Used to indicate that a tx_add_output message should be sent to the peer with the given node_id.
	SendTxAddOutput {
		/// The node_id of the node which should receive this message
		node_id: PublicKey,
		/// The message which should be sent.
		msg: msgs::TxAddOutput,
	},
	/// Used to indicate that a tx_remove_input message should be sent to the peer with the given node_id.
	SendTxRemoveInput {
		/// The node_id of the node which should receive this message
		node_id: PublicKey,
		/// The message which should be sent.
		msg: msgs::TxRemoveInput,
	},
	/// Used to indicate that a tx_remove_output message should be sent to the peer with the given node_id.
	SendTxRemoveOutput {
		/// The node_id of the node which should receive this message
		node_id: PublicKey,
		/// The message which should be sent.
		msg: msgs::TxRemoveOutput,
	},
	/// Used to indicate that a tx_complete message should be sent to the peer with the given node_id.
	SendTxComplete {
		/// The node_id of the node which should receive this message
		node_id: PublicKey,
		/// The message which should be sent.
		msg: msgs::TxComplete,
	},
	/// Used to indicate that a tx_signatures message should be sent to the peer with the given node_id.
	SendTxSignatures {
		/// The node_id of the node which should receive this message
		node_id: PublicKey,
		/// The message which should be sent.
		msg: msgs::TxSignatures,
	},
	/// Used to indicate that a tx_init_rbf message should be sent to the peer with the given node_id.
	SendTxInitRbf {
		/// The node_id of the node which should receive this message
		node_id: PublicKey,
		/// The message which should be sent.
		msg: msgs::TxInitRbf,
	},
	/// Used to indicate that a tx_ack_rbf message should be sent to the peer with the given node_id.
	SendTxAckRbf {
		/// The node_id of the node which should receive this message
		node_id: PublicKey,
		/// The message which should be sent.
		msg: msgs::TxAckRbf,
	},
	/// Used to indicate that a tx_abort message should be sent to the peer with the given node_id.
	SendTxAbort {
		/// The node_id of the node which should receive this message
		node_id: PublicKey,
		/// The message which should be sent.
		msg: msgs::TxAbort,
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
