// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Information about the state of a channel.

use alloc::vec::Vec;

use bitcoin::secp256k1::PublicKey;

use crate::chain::chaininterface::{FeeEstimator, LowerBoundedFeeEstimator};
use crate::chain::transaction::OutPoint;
use crate::io;
use crate::ln::channel::ChannelContext;
use crate::ln::features::{ChannelTypeFeatures, InitFeatures};
use crate::ln::msgs::DecodeError;
use crate::ln::types::{ChannelId, PaymentHash};
use crate::sign::SignerProvider;
use crate::util::config::ChannelConfig;
use crate::util::ser::{Readable, Writeable, Writer};

use core::ops::Deref;

/// Exposes the state of pending inbound HTLCs.
///
/// At a high level, an HTLC being forwarded from one Lightning node to another Lightning node goes
/// through the following states in the state machine:
/// - Announced for addition by the originating node through the update_add_htlc message.
/// - Added to the commitment transaction of the receiving node and originating node in turn
///   through the exchange of commitment_signed and revoke_and_ack messages.
/// - Announced for resolution (fulfillment or failure) by the receiving node through either one of
///   the update_fulfill_htlc, update_fail_htlc, and update_fail_malformed_htlc messages.
/// - Removed from the commitment transaction of the originating node and receiving node in turn
///   through the exchange of commitment_signed and revoke_and_ack messages.
///
/// This can be used to inspect what next message an HTLC is waiting for to advance its state.
#[derive(Clone, Debug, PartialEq)]
pub enum InboundHTLCStateDetails {
	/// We have added this HTLC in our commitment transaction by receiving commitment_signed and
	/// returning revoke_and_ack. We are awaiting the appropriate revoke_and_ack's from the remote
	/// before this HTLC is included on the remote commitment transaction.
	AwaitingRemoteRevokeToAdd,
	/// This HTLC has been included in the commitment_signed and revoke_and_ack messages on both sides
	/// and is included in both commitment transactions.
	///
	/// This HTLC is now safe to either forward or be claimed as a payment by us. The HTLC will
	/// remain in this state until the forwarded upstream HTLC has been resolved and we resolve this
	/// HTLC correspondingly, or until we claim it as a payment. If it is part of a multipart
	/// payment, it will only be claimed together with other required parts.
	Committed,
	/// We have received the preimage for this HTLC and it is being removed by fulfilling it with
	/// update_fulfill_htlc. This HTLC is still on both commitment transactions, but we are awaiting
	/// the appropriate revoke_and_ack's from the remote before this HTLC is removed from the remote
	/// commitment transaction after update_fulfill_htlc.
	AwaitingRemoteRevokeToRemoveFulfill,
	/// The HTLC is being removed by failing it with update_fail_htlc or update_fail_malformed_htlc.
	/// This HTLC is still on both commitment transactions, but we are awaiting the appropriate
	/// revoke_and_ack's from the remote before this HTLC is removed from the remote commitment
	/// transaction.
	AwaitingRemoteRevokeToRemoveFail,
}

impl_writeable_tlv_based_enum_upgradable!(InboundHTLCStateDetails,
	(0, AwaitingRemoteRevokeToAdd) => {},
	(2, Committed) => {},
	(4, AwaitingRemoteRevokeToRemoveFulfill) => {},
	(6, AwaitingRemoteRevokeToRemoveFail) => {},
);

/// Exposes details around pending inbound HTLCs.
#[derive(Clone, Debug, PartialEq)]
pub struct InboundHTLCDetails {
	/// The HTLC ID.
	/// The IDs are incremented by 1 starting from 0 for each offered HTLC.
	/// They are unique per channel and inbound/outbound direction, unless an HTLC was only announced
	/// and not part of any commitment transaction.
	pub htlc_id: u64,
	/// The amount in msat.
	pub amount_msat: u64,
	/// The block height at which this HTLC expires.
	pub cltv_expiry: u32,
	/// The payment hash.
	pub payment_hash: PaymentHash,
	/// The state of the HTLC in the state machine.
	///
	/// Determines on which commitment transactions the HTLC is included and what message the HTLC is
	/// waiting for to advance to the next state.
	///
	/// See [`InboundHTLCStateDetails`] for information on the specific states.
	///
	/// LDK will always fill this field in, but when downgrading to prior versions of LDK, new
	/// states may result in `None` here.
	pub state: Option<InboundHTLCStateDetails>,
	/// Whether the HTLC has an output below the local dust limit. If so, the output will be trimmed
	/// from the local commitment transaction and added to the commitment transaction fee.
	/// For non-anchor channels, this takes into account the cost of the second-stage HTLC
	/// transactions as well.
	///
	/// When the local commitment transaction is broadcasted as part of a unilateral closure,
	/// the value of this HTLC will therefore not be claimable but instead burned as a transaction
	/// fee.
	///
	/// Note that dust limits are specific to each party. An HTLC can be dust for the local
	/// commitment transaction but not for the counterparty's commitment transaction and vice versa.
	pub is_dust: bool,
}

impl_writeable_tlv_based!(InboundHTLCDetails, {
	(0, htlc_id, required),
	(2, amount_msat, required),
	(4, cltv_expiry, required),
	(6, payment_hash, required),
	(7, state, upgradable_option),
	(8, is_dust, required),
});

/// Exposes the state of pending outbound HTLCs.
///
/// At a high level, an HTLC being forwarded from one Lightning node to another Lightning node goes
/// through the following states in the state machine:
/// - Announced for addition by the originating node through the update_add_htlc message.
/// - Added to the commitment transaction of the receiving node and originating node in turn
///   through the exchange of commitment_signed and revoke_and_ack messages.
/// - Announced for resolution (fulfillment or failure) by the receiving node through either one of
///   the update_fulfill_htlc, update_fail_htlc, and update_fail_malformed_htlc messages.
/// - Removed from the commitment transaction of the originating node and receiving node in turn
///   through the exchange of commitment_signed and revoke_and_ack messages.
///
/// This can be used to inspect what next message an HTLC is waiting for to advance its state.
#[derive(Clone, Debug, PartialEq)]
pub enum OutboundHTLCStateDetails {
	/// We are awaiting the appropriate revoke_and_ack's from the remote before the HTLC is added
	/// on the remote's commitment transaction after update_add_htlc.
	AwaitingRemoteRevokeToAdd,
	/// The HTLC has been added to the remote's commitment transaction by sending commitment_signed
	/// and receiving revoke_and_ack in return.
	///
	/// The HTLC will remain in this state until the remote node resolves the HTLC, or until we
	/// unilaterally close the channel due to a timeout with an uncooperative remote node.
	Committed,
	/// The HTLC has been fulfilled successfully by the remote with a preimage in update_fulfill_htlc,
	/// and we removed the HTLC from our commitment transaction by receiving commitment_signed and
	/// returning revoke_and_ack. We are awaiting the appropriate revoke_and_ack's from the remote
	/// for the removal from its commitment transaction.
	AwaitingRemoteRevokeToRemoveSuccess,
	/// The HTLC has been failed by the remote with update_fail_htlc or update_fail_malformed_htlc,
	/// and we removed the HTLC from our commitment transaction by receiving commitment_signed and
	/// returning revoke_and_ack. We are awaiting the appropriate revoke_and_ack's from the remote
	/// for the removal from its commitment transaction.
	AwaitingRemoteRevokeToRemoveFailure,
}

impl_writeable_tlv_based_enum_upgradable!(OutboundHTLCStateDetails,
	(0, AwaitingRemoteRevokeToAdd) => {},
	(2, Committed) => {},
	(4, AwaitingRemoteRevokeToRemoveSuccess) => {},
	(6, AwaitingRemoteRevokeToRemoveFailure) => {},
);

/// Exposes details around pending outbound HTLCs.
#[derive(Clone, Debug, PartialEq)]
pub struct OutboundHTLCDetails {
	/// The HTLC ID.
	/// The IDs are incremented by 1 starting from 0 for each offered HTLC.
	/// They are unique per channel and inbound/outbound direction, unless an HTLC was only announced
	/// and not part of any commitment transaction.
	///
	/// Not present when we are awaiting a remote revocation and the HTLC is not added yet.
	pub htlc_id: Option<u64>,
	/// The amount in msat.
	pub amount_msat: u64,
	/// The block height at which this HTLC expires.
	pub cltv_expiry: u32,
	/// The payment hash.
	pub payment_hash: PaymentHash,
	/// The state of the HTLC in the state machine.
	///
	/// Determines on which commitment transactions the HTLC is included and what message the HTLC is
	/// waiting for to advance to the next state.
	///
	/// See [`OutboundHTLCStateDetails`] for information on the specific states.
	///
	/// LDK will always fill this field in, but when downgrading to prior versions of LDK, new
	/// states may result in `None` here.
	pub state: Option<OutboundHTLCStateDetails>,
	/// The extra fee being skimmed off the top of this HTLC.
	pub skimmed_fee_msat: Option<u64>,
	/// Whether the HTLC has an output below the local dust limit. If so, the output will be trimmed
	/// from the local commitment transaction and added to the commitment transaction fee.
	/// For non-anchor channels, this takes into account the cost of the second-stage HTLC
	/// transactions as well.
	///
	/// When the local commitment transaction is broadcasted as part of a unilateral closure,
	/// the value of this HTLC will therefore not be claimable but instead burned as a transaction
	/// fee.
	///
	/// Note that dust limits are specific to each party. An HTLC can be dust for the local
	/// commitment transaction but not for the counterparty's commitment transaction and vice versa.
	pub is_dust: bool,
}

impl_writeable_tlv_based!(OutboundHTLCDetails, {
	(0, htlc_id, required),
	(2, amount_msat, required),
	(4, cltv_expiry, required),
	(6, payment_hash, required),
	(7, state, upgradable_option),
	(8, skimmed_fee_msat, required),
	(10, is_dust, required),
});

/// Information needed for constructing an invoice route hint for this channel.
#[derive(Clone, Debug, PartialEq)]
pub struct CounterpartyForwardingInfo {
	/// Base routing fee in millisatoshis.
	pub fee_base_msat: u32,
	/// Amount in millionths of a satoshi the channel will charge per transferred satoshi.
	pub fee_proportional_millionths: u32,
	/// The minimum difference in cltv_expiry between an ingoing HTLC and its outgoing counterpart,
	/// such that the outgoing HTLC is forwardable to this counterparty. See `msgs::ChannelUpdate`'s
	/// `cltv_expiry_delta` for more details.
	pub cltv_expiry_delta: u16,
}

impl_writeable_tlv_based!(CounterpartyForwardingInfo, {
	(2, fee_base_msat, required),
	(4, fee_proportional_millionths, required),
	(6, cltv_expiry_delta, required),
});

/// Channel parameters which apply to our counterparty. These are split out from [`ChannelDetails`]
/// to better separate parameters.
#[derive(Clone, Debug, PartialEq)]
pub struct ChannelCounterparty {
	/// The node_id of our counterparty
	pub node_id: PublicKey,
	/// The Features the channel counterparty provided upon last connection.
	/// Useful for routing as it is the most up-to-date copy of the counterparty's features and
	/// many routing-relevant features are present in the init context.
	pub features: InitFeatures,
	/// The value, in satoshis, that must always be held in the channel for our counterparty. This
	/// value ensures that if our counterparty broadcasts a revoked state, we can punish them by
	/// claiming at least this value on chain.
	///
	/// This value is not included in [`inbound_capacity_msat`] as it can never be spent.
	///
	/// [`inbound_capacity_msat`]: ChannelDetails::inbound_capacity_msat
	pub unspendable_punishment_reserve: u64,
	/// Information on the fees and requirements that the counterparty requires when forwarding
	/// payments to us through this channel.
	pub forwarding_info: Option<CounterpartyForwardingInfo>,
	/// The smallest value HTLC (in msat) the remote peer will accept, for this channel. This field
	/// is only `None` before we have received either the `OpenChannel` or `AcceptChannel` message
	/// from the remote peer, or for `ChannelCounterparty` objects serialized prior to LDK 0.0.107.
	pub outbound_htlc_minimum_msat: Option<u64>,
	/// The largest value HTLC (in msat) the remote peer currently will accept, for this channel.
	pub outbound_htlc_maximum_msat: Option<u64>,
}

impl_writeable_tlv_based!(ChannelCounterparty, {
	(2, node_id, required),
	(4, features, required),
	(6, unspendable_punishment_reserve, required),
	(8, forwarding_info, option),
	(9, outbound_htlc_minimum_msat, option),
	(11, outbound_htlc_maximum_msat, option),
});

/// Details of a channel, as returned by [`ChannelManager::list_channels`] and [`ChannelManager::list_usable_channels`]
///
/// [`ChannelManager::list_channels`]: crate::ln::channelmanager::ChannelManager::list_channels
/// [`ChannelManager::list_usable_channels`]: crate::ln::channelmanager::ChannelManager::list_usable_channels
#[derive(Clone, Debug, PartialEq)]
pub struct ChannelDetails {
	/// The channel's ID (prior to funding transaction generation, this is a random 32 bytes,
	/// thereafter this is the txid of the funding transaction xor the funding transaction output).
	/// Note that this means this value is *not* persistent - it can change once during the
	/// lifetime of the channel.
	pub channel_id: ChannelId,
	/// Parameters which apply to our counterparty. See individual fields for more information.
	pub counterparty: ChannelCounterparty,
	/// The Channel's funding transaction output, if we've negotiated the funding transaction with
	/// our counterparty already.
	pub funding_txo: Option<OutPoint>,
	/// The features which this channel operates with. See individual features for more info.
	///
	/// `None` until negotiation completes and the channel type is finalized.
	pub channel_type: Option<ChannelTypeFeatures>,
	/// The position of the funding transaction in the chain. None if the funding transaction has
	/// not yet been confirmed and the channel fully opened.
	///
	/// Note that if [`inbound_scid_alias`] is set, it must be used for invoices and inbound
	/// payments instead of this. See [`get_inbound_payment_scid`].
	///
	/// For channels with [`confirmations_required`] set to `Some(0)`, [`outbound_scid_alias`] may
	/// be used in place of this in outbound routes. See [`get_outbound_payment_scid`].
	///
	/// [`inbound_scid_alias`]: Self::inbound_scid_alias
	/// [`outbound_scid_alias`]: Self::outbound_scid_alias
	/// [`get_inbound_payment_scid`]: Self::get_inbound_payment_scid
	/// [`get_outbound_payment_scid`]: Self::get_outbound_payment_scid
	/// [`confirmations_required`]: Self::confirmations_required
	pub short_channel_id: Option<u64>,
	/// An optional [`short_channel_id`] alias for this channel, randomly generated by us and
	/// usable in place of [`short_channel_id`] to reference the channel in outbound routes when
	/// the channel has not yet been confirmed (as long as [`confirmations_required`] is
	/// `Some(0)`).
	///
	/// This will be `None` as long as the channel is not available for routing outbound payments.
	///
	/// [`short_channel_id`]: Self::short_channel_id
	/// [`confirmations_required`]: Self::confirmations_required
	pub outbound_scid_alias: Option<u64>,
	/// An optional [`short_channel_id`] alias for this channel, randomly generated by our
	/// counterparty and usable in place of [`short_channel_id`] in invoice route hints. Our
	/// counterparty will recognize the alias provided here in place of the [`short_channel_id`]
	/// when they see a payment to be routed to us.
	///
	/// Our counterparty may choose to rotate this value at any time, though will always recognize
	/// previous values for inbound payment forwarding.
	///
	/// [`short_channel_id`]: Self::short_channel_id
	pub inbound_scid_alias: Option<u64>,
	/// The value, in satoshis, of this channel as appears in the funding output
	pub channel_value_satoshis: u64,
	/// The value, in satoshis, that must always be held in the channel for us. This value ensures
	/// that if we broadcast a revoked state, our counterparty can punish us by claiming at least
	/// this value on chain.
	///
	/// This value is not included in [`outbound_capacity_msat`] as it can never be spent.
	///
	/// This value will be `None` for outbound channels until the counterparty accepts the channel.
	///
	/// [`outbound_capacity_msat`]: ChannelDetails::outbound_capacity_msat
	pub unspendable_punishment_reserve: Option<u64>,
	/// The `user_channel_id` value passed in to [`ChannelManager::create_channel`] for outbound
	/// channels, or to [`ChannelManager::accept_inbound_channel`] for inbound channels if
	/// [`UserConfig::manually_accept_inbound_channels`] config flag is set to true. Otherwise
	/// `user_channel_id` will be randomized for an inbound channel.  This may be zero for objects
	/// serialized with LDK versions prior to 0.0.113.
	///
	/// [`ChannelManager::create_channel`]: crate::ln::channelmanager::ChannelManager::create_channel
	/// [`ChannelManager::accept_inbound_channel`]: crate::ln::channelmanager::ChannelManager::accept_inbound_channel
	/// [`UserConfig::manually_accept_inbound_channels`]: crate::util::config::UserConfig::manually_accept_inbound_channels
	pub user_channel_id: u128,
	/// The currently negotiated fee rate denominated in satoshi per 1000 weight units,
	/// which is applied to commitment and HTLC transactions.
	///
	/// This value will be `None` for objects serialized with LDK versions prior to 0.0.115.
	pub feerate_sat_per_1000_weight: Option<u32>,
	/// Our total balance.  This is the amount we would get if we close the channel.
	/// This value is not exact. Due to various in-flight changes and feerate changes, exactly this
	/// amount is not likely to be recoverable on close.
	///
	/// This does not include any pending HTLCs which are not yet fully resolved (and, thus, whose
	/// balance is not available for inclusion in new outbound HTLCs). This further does not include
	/// any pending outgoing HTLCs which are awaiting some other resolution to be sent.
	/// This does not consider any on-chain fees.
	///
	/// See also [`ChannelDetails::outbound_capacity_msat`]
	pub balance_msat: u64,
	/// The available outbound capacity for sending HTLCs to the remote peer. This does not include
	/// any pending HTLCs which are not yet fully resolved (and, thus, whose balance is not
	/// available for inclusion in new outbound HTLCs). This further does not include any pending
	/// outgoing HTLCs which are awaiting some other resolution to be sent.
	///
	/// See also [`ChannelDetails::balance_msat`]
	///
	/// This value is not exact. Due to various in-flight changes, feerate changes, and our
	/// conflict-avoidance policy, exactly this amount is not likely to be spendable. However, we
	/// should be able to spend nearly this amount.
	pub outbound_capacity_msat: u64,
	/// The available outbound capacity for sending a single HTLC to the remote peer. This is
	/// similar to [`ChannelDetails::outbound_capacity_msat`] but it may be further restricted by
	/// the current state and per-HTLC limit(s). This is intended for use when routing, allowing us
	/// to use a limit as close as possible to the HTLC limit we can currently send.
	///
	/// See also [`ChannelDetails::next_outbound_htlc_minimum_msat`],
	/// [`ChannelDetails::balance_msat`], and [`ChannelDetails::outbound_capacity_msat`].
	pub next_outbound_htlc_limit_msat: u64,
	/// The minimum value for sending a single HTLC to the remote peer. This is the equivalent of
	/// [`ChannelDetails::next_outbound_htlc_limit_msat`] but represents a lower-bound, rather than
	/// an upper-bound. This is intended for use when routing, allowing us to ensure we pick a
	/// route which is valid.
	pub next_outbound_htlc_minimum_msat: u64,
	/// The available inbound capacity for the remote peer to send HTLCs to us. This does not
	/// include any pending HTLCs which are not yet fully resolved (and, thus, whose balance is not
	/// available for inclusion in new inbound HTLCs).
	/// Note that there are some corner cases not fully handled here, so the actual available
	/// inbound capacity may be slightly higher than this.
	///
	/// This value is not exact. Due to various in-flight changes, feerate changes, and our
	/// counterparty's conflict-avoidance policy, exactly this amount is not likely to be spendable.
	/// However, our counterparty should be able to spend nearly this amount.
	pub inbound_capacity_msat: u64,
	/// The number of required confirmations on the funding transaction before the funding will be
	/// considered "locked". This number is selected by the channel fundee (i.e. us if
	/// [`is_outbound`] is *not* set), and can be selected for inbound channels with
	/// [`ChannelHandshakeConfig::minimum_depth`] or limited for outbound channels with
	/// [`ChannelHandshakeLimits::max_minimum_depth`].
	///
	/// This value will be `None` for outbound channels until the counterparty accepts the channel.
	///
	/// [`is_outbound`]: ChannelDetails::is_outbound
	/// [`ChannelHandshakeConfig::minimum_depth`]: crate::util::config::ChannelHandshakeConfig::minimum_depth
	/// [`ChannelHandshakeLimits::max_minimum_depth`]: crate::util::config::ChannelHandshakeLimits::max_minimum_depth
	pub confirmations_required: Option<u32>,
	/// The current number of confirmations on the funding transaction.
	///
	/// This value will be `None` for objects serialized with LDK versions prior to 0.0.113.
	pub confirmations: Option<u32>,
	/// The number of blocks (after our commitment transaction confirms) that we will need to wait
	/// until we can claim our funds after we force-close the channel. During this time our
	/// counterparty is allowed to punish us if we broadcasted a stale state. If our counterparty
	/// force-closes the channel and broadcasts a commitment transaction we do not have to wait any
	/// time to claim our non-HTLC-encumbered funds.
	///
	/// This value will be `None` for outbound channels until the counterparty accepts the channel.
	pub force_close_spend_delay: Option<u16>,
	/// True if the channel was initiated (and thus funded) by us.
	pub is_outbound: bool,
	/// True if the channel is confirmed, channel_ready messages have been exchanged, and the
	/// channel is not currently being shut down. `channel_ready` message exchange implies the
	/// required confirmation count has been reached (and we were connected to the peer at some
	/// point after the funding transaction received enough confirmations). The required
	/// confirmation count is provided in [`confirmations_required`].
	///
	/// [`confirmations_required`]: ChannelDetails::confirmations_required
	pub is_channel_ready: bool,
	/// The stage of the channel's shutdown.
	/// `None` for `ChannelDetails` serialized on LDK versions prior to 0.0.116.
	pub channel_shutdown_state: Option<ChannelShutdownState>,
	/// True if the channel is (a) confirmed and channel_ready messages have been exchanged, (b)
	/// the peer is connected, and (c) the channel is not currently negotiating a shutdown.
	///
	/// This is a strict superset of `is_channel_ready`.
	pub is_usable: bool,
	/// True if this channel is (or will be) publicly-announced.
	pub is_public: bool,
	/// The smallest value HTLC (in msat) we will accept, for this channel. This field
	/// is only `None` for `ChannelDetails` objects serialized prior to LDK 0.0.107
	pub inbound_htlc_minimum_msat: Option<u64>,
	/// The largest value HTLC (in msat) we currently will accept, for this channel.
	pub inbound_htlc_maximum_msat: Option<u64>,
	/// Set of configurable parameters that affect channel operation.
	///
	/// This field is only `None` for `ChannelDetails` objects serialized prior to LDK 0.0.109.
	pub config: Option<ChannelConfig>,
	/// Pending inbound HTLCs.
	///
	/// This field is empty for objects serialized with LDK versions prior to 0.0.122.
	pub pending_inbound_htlcs: Vec<InboundHTLCDetails>,
	/// Pending outbound HTLCs.
	///
	/// This field is empty for objects serialized with LDK versions prior to 0.0.122.
	pub pending_outbound_htlcs: Vec<OutboundHTLCDetails>,
}

impl ChannelDetails {
	/// Gets the current SCID which should be used to identify this channel for inbound payments.
	/// This should be used for providing invoice hints or in any other context where our
	/// counterparty will forward a payment to us.
	///
	/// This is either the [`ChannelDetails::inbound_scid_alias`], if set, or the
	/// [`ChannelDetails::short_channel_id`]. See those for more information.
	pub fn get_inbound_payment_scid(&self) -> Option<u64> {
		self.inbound_scid_alias.or(self.short_channel_id)
	}

	/// Gets the current SCID which should be used to identify this channel for outbound payments.
	/// This should be used in [`Route`]s to describe the first hop or in other contexts where
	/// we're sending or forwarding a payment outbound over this channel.
	///
	/// This is either the [`ChannelDetails::short_channel_id`], if set, or the
	/// [`ChannelDetails::outbound_scid_alias`]. See those for more information.
	///
	/// [`Route`]: crate::routing::router::Route
	pub fn get_outbound_payment_scid(&self) -> Option<u64> {
		self.short_channel_id.or(self.outbound_scid_alias)
	}

	pub(super) fn from_channel_context<SP: Deref, F: Deref>(
		context: &ChannelContext<SP>, best_block_height: u32, latest_features: InitFeatures,
		fee_estimator: &LowerBoundedFeeEstimator<F>,
	) -> Self
	where
		SP::Target: SignerProvider,
		F::Target: FeeEstimator,
	{
		let balance = context.get_available_balances(fee_estimator);
		let (to_remote_reserve_satoshis, to_self_reserve_satoshis) =
			context.get_holder_counterparty_selected_channel_reserve_satoshis();
		ChannelDetails {
			channel_id: context.channel_id(),
			counterparty: ChannelCounterparty {
				node_id: context.get_counterparty_node_id(),
				features: latest_features,
				unspendable_punishment_reserve: to_remote_reserve_satoshis,
				forwarding_info: context.counterparty_forwarding_info(),
				// Ensures that we have actually received the `htlc_minimum_msat` value
				// from the counterparty through the `OpenChannel` or `AcceptChannel`
				// message (as they are always the first message from the counterparty).
				// Else `Channel::get_counterparty_htlc_minimum_msat` could return the
				// default `0` value set by `Channel::new_outbound`.
				outbound_htlc_minimum_msat: if context.have_received_message() {
					Some(context.get_counterparty_htlc_minimum_msat())
				} else {
					None
				},
				outbound_htlc_maximum_msat: context.get_counterparty_htlc_maximum_msat(),
			},
			funding_txo: context.get_funding_txo(),
			// Note that accept_channel (or open_channel) is always the first message, so
			// `have_received_message` indicates that type negotiation has completed.
			channel_type: if context.have_received_message() {
				Some(context.get_channel_type().clone())
			} else {
				None
			},
			short_channel_id: context.get_short_channel_id(),
			outbound_scid_alias: if context.is_usable() {
				Some(context.outbound_scid_alias())
			} else {
				None
			},
			inbound_scid_alias: context.latest_inbound_scid_alias(),
			channel_value_satoshis: context.get_value_satoshis(),
			feerate_sat_per_1000_weight: Some(context.get_feerate_sat_per_1000_weight()),
			unspendable_punishment_reserve: to_self_reserve_satoshis,
			balance_msat: balance.balance_msat,
			inbound_capacity_msat: balance.inbound_capacity_msat,
			outbound_capacity_msat: balance.outbound_capacity_msat,
			next_outbound_htlc_limit_msat: balance.next_outbound_htlc_limit_msat,
			next_outbound_htlc_minimum_msat: balance.next_outbound_htlc_minimum_msat,
			user_channel_id: context.get_user_id(),
			confirmations_required: context.minimum_depth(),
			confirmations: Some(context.get_funding_tx_confirmations(best_block_height)),
			force_close_spend_delay: context.get_counterparty_selected_contest_delay(),
			is_outbound: context.is_outbound(),
			is_channel_ready: context.is_usable(),
			is_usable: context.is_live(),
			is_public: context.should_announce(),
			inbound_htlc_minimum_msat: Some(context.get_holder_htlc_minimum_msat()),
			inbound_htlc_maximum_msat: context.get_holder_htlc_maximum_msat(),
			config: Some(context.config()),
			channel_shutdown_state: Some(context.shutdown_state()),
			pending_inbound_htlcs: context.get_pending_inbound_htlc_details(),
			pending_outbound_htlcs: context.get_pending_outbound_htlc_details(),
		}
	}
}

impl Writeable for ChannelDetails {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		// `user_channel_id` used to be a single u64 value. In order to remain backwards compatible with
		// versions prior to 0.0.113, the u128 is serialized as two separate u64 values.
		let user_channel_id_low = self.user_channel_id as u64;
		let user_channel_id_high_opt = Some((self.user_channel_id >> 64) as u64);
		write_tlv_fields!(writer, {
			(1, self.inbound_scid_alias, option),
			(2, self.channel_id, required),
			(3, self.channel_type, option),
			(4, self.counterparty, required),
			(5, self.outbound_scid_alias, option),
			(6, self.funding_txo, option),
			(7, self.config, option),
			(8, self.short_channel_id, option),
			(9, self.confirmations, option),
			(10, self.channel_value_satoshis, required),
			(12, self.unspendable_punishment_reserve, option),
			(14, user_channel_id_low, required),
			(16, self.balance_msat, required),
			(18, self.outbound_capacity_msat, required),
			(19, self.next_outbound_htlc_limit_msat, required),
			(20, self.inbound_capacity_msat, required),
			(21, self.next_outbound_htlc_minimum_msat, required),
			(22, self.confirmations_required, option),
			(24, self.force_close_spend_delay, option),
			(26, self.is_outbound, required),
			(28, self.is_channel_ready, required),
			(30, self.is_usable, required),
			(32, self.is_public, required),
			(33, self.inbound_htlc_minimum_msat, option),
			(35, self.inbound_htlc_maximum_msat, option),
			(37, user_channel_id_high_opt, option),
			(39, self.feerate_sat_per_1000_weight, option),
			(41, self.channel_shutdown_state, option),
			(43, self.pending_inbound_htlcs, optional_vec),
			(45, self.pending_outbound_htlcs, optional_vec),
		});
		Ok(())
	}
}

impl Readable for ChannelDetails {
	fn read<R: io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
		_init_and_read_len_prefixed_tlv_fields!(reader, {
			(1, inbound_scid_alias, option),
			(2, channel_id, required),
			(3, channel_type, option),
			(4, counterparty, required),
			(5, outbound_scid_alias, option),
			(6, funding_txo, option),
			(7, config, option),
			(8, short_channel_id, option),
			(9, confirmations, option),
			(10, channel_value_satoshis, required),
			(12, unspendable_punishment_reserve, option),
			(14, user_channel_id_low, required),
			(16, balance_msat, required),
			(18, outbound_capacity_msat, required),
			// Note that by the time we get past the required read above, outbound_capacity_msat will be
			// filled in, so we can safely unwrap it here.
			(19, next_outbound_htlc_limit_msat, (default_value, outbound_capacity_msat.0.unwrap() as u64)),
			(20, inbound_capacity_msat, required),
			(21, next_outbound_htlc_minimum_msat, (default_value, 0)),
			(22, confirmations_required, option),
			(24, force_close_spend_delay, option),
			(26, is_outbound, required),
			(28, is_channel_ready, required),
			(30, is_usable, required),
			(32, is_public, required),
			(33, inbound_htlc_minimum_msat, option),
			(35, inbound_htlc_maximum_msat, option),
			(37, user_channel_id_high_opt, option),
			(39, feerate_sat_per_1000_weight, option),
			(41, channel_shutdown_state, option),
			(43, pending_inbound_htlcs, optional_vec),
			(45, pending_outbound_htlcs, optional_vec),
		});

		// `user_channel_id` used to be a single u64 value. In order to remain backwards compatible with
		// versions prior to 0.0.113, the u128 is serialized as two separate u64 values.
		let user_channel_id_low: u64 = user_channel_id_low.0.unwrap();
		let user_channel_id = user_channel_id_low as u128
			+ ((user_channel_id_high_opt.unwrap_or(0 as u64) as u128) << 64);

		Ok(Self {
			inbound_scid_alias,
			channel_id: channel_id.0.unwrap(),
			channel_type,
			counterparty: counterparty.0.unwrap(),
			outbound_scid_alias,
			funding_txo,
			config,
			short_channel_id,
			channel_value_satoshis: channel_value_satoshis.0.unwrap(),
			unspendable_punishment_reserve,
			user_channel_id,
			balance_msat: balance_msat.0.unwrap(),
			outbound_capacity_msat: outbound_capacity_msat.0.unwrap(),
			next_outbound_htlc_limit_msat: next_outbound_htlc_limit_msat.0.unwrap(),
			next_outbound_htlc_minimum_msat: next_outbound_htlc_minimum_msat.0.unwrap(),
			inbound_capacity_msat: inbound_capacity_msat.0.unwrap(),
			confirmations_required,
			confirmations,
			force_close_spend_delay,
			is_outbound: is_outbound.0.unwrap(),
			is_channel_ready: is_channel_ready.0.unwrap(),
			is_usable: is_usable.0.unwrap(),
			is_public: is_public.0.unwrap(),
			inbound_htlc_minimum_msat,
			inbound_htlc_maximum_msat,
			feerate_sat_per_1000_weight,
			channel_shutdown_state,
			pending_inbound_htlcs: pending_inbound_htlcs.unwrap_or(Vec::new()),
			pending_outbound_htlcs: pending_outbound_htlcs.unwrap_or(Vec::new()),
		})
	}
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Further information on the details of the channel shutdown.
/// Upon channels being forced closed (i.e. commitment transaction confirmation detected
/// by `ChainMonitor`), ChannelShutdownState will be set to `ShutdownComplete` or
/// the channel will be removed shortly.
/// Also note, that in normal operation, peers could disconnect at any of these states
/// and require peer re-connection before making progress onto other states
pub enum ChannelShutdownState {
	/// Channel has not sent or received a shutdown message.
	NotShuttingDown,
	/// Local node has sent a shutdown message for this channel.
	ShutdownInitiated,
	/// Shutdown message exchanges have concluded and the channels are in the midst of
	/// resolving all existing open HTLCs before closing can continue.
	ResolvingHTLCs,
	/// All HTLCs have been resolved, nodes are currently negotiating channel close onchain fee rates.
	NegotiatingClosingFee,
	/// We've successfully negotiated a closing_signed dance. At this point `ChannelManager` is about
	/// to drop the channel.
	ShutdownComplete,
}

impl_writeable_tlv_based_enum!(ChannelShutdownState,
	(0, NotShuttingDown) => {},
	(2, ShutdownInitiated) => {},
	(4, ResolvingHTLCs) => {},
	(6, NegotiatingClosingFee) => {},
	(8, ShutdownComplete) => {},
);
