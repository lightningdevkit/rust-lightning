// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Various user-configurable channel limits and settings which ChannelManager
//! applies for you.

use ln::channelmanager::{BREAKDOWN_TIMEOUT, MAX_LOCAL_BREAKDOWN_TIMEOUT};

/// Configuration we set when applicable.
///
/// Default::default() provides sane defaults.
#[derive(Copy, Clone, Debug)]
pub struct ChannelHandshakeConfig {
	/// Confirmations we will wait for before considering the channel locked in.
	/// Applied only for inbound channels (see ChannelHandshakeLimits::max_minimum_depth for the
	/// equivalent limit applied to outbound channels).
	///
	/// Default value: 6.
	pub minimum_depth: u32,
	/// Set to the number of blocks we require our counterparty to wait to claim their money (ie
	/// the number of blocks we have to punish our counterparty if they broadcast a revoked
	/// transaction).
	///
	/// This is one of the main parameters of our security model. We (or one of our watchtowers) MUST
	/// be online to check for revoked transactions on-chain at least once every our_to_self_delay
	/// blocks (minus some margin to allow us enough time to broadcast and confirm a transaction,
	/// possibly with time in between to RBF the spending transaction).
	///
	/// Meanwhile, asking for a too high delay, we bother peer to freeze funds for nothing in
	/// case of an honest unilateral channel close, which implicitly decrease the economic value of
	/// our channel.
	///
	/// Default value: [`BREAKDOWN_TIMEOUT`], we enforce it as a minimum at channel opening so you
	/// can tweak config to ask for more security, not less.
	pub our_to_self_delay: u16,
	/// Set to the smallest value HTLC we will accept to process.
	///
	/// This value is sent to our counterparty on channel-open and we close the channel any time
	/// our counterparty misbehaves by sending us an HTLC with a value smaller than this.
	///
	/// Default value: 1. If the value is less than 1, it is ignored and set to 1, as is required
	/// by the protocol.
	pub our_htlc_minimum_msat: u64,
}

impl Default for ChannelHandshakeConfig {
	fn default() -> ChannelHandshakeConfig {
		ChannelHandshakeConfig {
			minimum_depth: 6,
			our_to_self_delay: BREAKDOWN_TIMEOUT,
			our_htlc_minimum_msat: 1,
		}
	}
}

/// Optional channel limits which are applied during channel creation.
///
/// These limits are only applied to our counterparty's limits, not our own.
///
/// Use 0/<type>::max_value() as appropriate to skip checking.
///
/// Provides sane defaults for most configurations.
///
/// Most additional limits are disabled except those with which specify a default in individual
/// field documentation. Note that this may result in barely-usable channels, but since they
/// are applied mostly only to incoming channels that's not much of a problem.
#[derive(Copy, Clone, Debug)]
pub struct ChannelHandshakeLimits {
	/// Minimum allowed satoshis when a channel is funded, this is supplied by the sender and so
	/// only applies to inbound channels.
	///
	/// Default value: 0.
	pub min_funding_satoshis: u64,
	/// The remote node sets a limit on the minimum size of HTLCs we can send to them. This allows
	/// you to limit the maximum minimum-size they can require.
	///
	/// Default value: u64::max_value.
	pub max_htlc_minimum_msat: u64,
	/// The remote node sets a limit on the maximum value of pending HTLCs to them at any given
	/// time to limit their funds exposure to HTLCs. This allows you to set a minimum such value.
	///
	/// Default value: 0.
	pub min_max_htlc_value_in_flight_msat: u64,
	/// The remote node will require we keep a certain amount in direct payment to ourselves at all
	/// time, ensuring that we are able to be punished if we broadcast an old state. This allows to
	/// you limit the amount which we will have to keep to ourselves (and cannot use for HTLCs).
	///
	/// Default value: u64::max_value.
	pub max_channel_reserve_satoshis: u64,
	/// The remote node sets a limit on the maximum number of pending HTLCs to them at any given
	/// time. This allows you to set a minimum such value.
	///
	/// Default value: 0.
	pub min_max_accepted_htlcs: u16,
	/// Before a channel is usable the funding transaction will need to be confirmed by at least a
	/// certain number of blocks, specified by the node which is not the funder (as the funder can
	/// assume they aren't going to double-spend themselves).
	/// This config allows you to set a limit on the maximum amount of time to wait.
	///
	/// Default value: 144, or roughly one day and only applies to outbound channels.
	pub max_minimum_depth: u32,
	/// Set to force an incoming channel to match our announced channel preference in
	/// [`ChannelConfig::announced_channel`].
	///
	/// For a node which is not online reliably, this should be set to true and
	/// [`ChannelConfig::announced_channel`] set to false, ensuring that no announced (aka public)
	/// channels will ever be opened.
	///
	/// Default value: true.
	pub force_announced_channel_preference: bool,
	/// Set to the amount of time we're willing to wait to claim money back to us.
	///
	/// Not checking this value would be a security issue, as our peer would be able to set it to
	/// max relative lock-time (a year) and we would "lose" money as it would be locked for a long time.
	///
	/// Default value: 2016, which we also enforce as a maximum value so you can tweak config to
	/// reduce the loss of having useless locked funds (if your peer accepts)
	pub their_to_self_delay: u16
}

impl Default for ChannelHandshakeLimits {
	fn default() -> Self {
		ChannelHandshakeLimits {
			min_funding_satoshis: 0,
			max_htlc_minimum_msat: <u64>::max_value(),
			min_max_htlc_value_in_flight_msat: 0,
			max_channel_reserve_satoshis: <u64>::max_value(),
			min_max_accepted_htlcs: 0,
			max_minimum_depth: 144,
			force_announced_channel_preference: true,
			their_to_self_delay: MAX_LOCAL_BREAKDOWN_TIMEOUT,
		}
	}
}

/// Options which apply on a per-channel basis and may change at runtime or based on negotiation
/// with our counterparty.
#[derive(Copy, Clone, Debug)]
pub struct ChannelConfig {
	/// Amount (in millionths of a satoshi) charged per satoshi for payments forwarded outbound
	/// over the channel.
	/// This may be allowed to change at runtime in a later update, however doing so must result in
	/// update messages sent to notify all nodes of our updated relay fee.
	///
	/// Default value: 0.
	pub forwarding_fee_proportional_millionths: u32,
	/// Amount (in milli-satoshi) charged for payments forwarded outbound over the channel, in
	/// excess of [`forwarding_fee_proportional_millionths`].
	/// This may be allowed to change at runtime in a later update, however doing so must result in
	/// update messages sent to notify all nodes of our updated relay fee.
	///
	/// The default value of a single satoshi roughly matches the market rate on many routing nodes
	/// as of July 2021. Adjusting it upwards or downwards may change whether nodes route through
	/// this node.
	///
	/// Default value: 1000.
	///
	/// [`forwarding_fee_proportional_millionths`]: ChannelConfig::forwarding_fee_proportional_millionths
	pub forwarding_fee_base_msat: u32,
	/// The difference in the CLTV value between incoming HTLCs and an outbound HTLC forwarded over
	/// the channel this config applies to.
	///
	/// This is analogous to [`ChannelHandshakeConfig::our_to_self_delay`] but applies to in-flight
	/// HTLC balance when a channel appears on-chain whereas
	/// [`ChannelHandshakeConfig::our_to_self_delay`] applies to the remaining
	/// (non-HTLC-encumbered) balance.
	///
	/// Thus, for HTLC-encumbered balances to be enforced on-chain when a channel is force-closed,
	/// we (or one of our watchtowers) MUST be online to check for broadcast of the current
	/// commitment transaction at least once per this many blocks (minus some margin to allow us
	/// enough time to broadcast and confirm a transaction, possibly with time in between to RBF
	/// the spending transaction).
	///
	/// Default value: 72 (12 hours at an average of 6 blocks/hour).
	/// Minimum value: [`MIN_CLTV_EXPIRY_DELTA`], any values less than this will be treated as
	///                [`MIN_CLTV_EXPIRY_DELTA`] instead.
	///
	/// [`MIN_CLTV_EXPIRY_DELTA`]: crate::ln::channelmanager::MIN_CLTV_EXPIRY_DELTA
	pub cltv_expiry_delta: u16,
	/// Set to announce the channel publicly and notify all nodes that they can route via this
	/// channel.
	///
	/// This should only be set to true for nodes which expect to be online reliably.
	///
	/// As the node which funds a channel picks this value this will only apply for new outbound
	/// channels unless [`ChannelHandshakeLimits::force_announced_channel_preference`] is set.
	///
	/// This cannot be changed after the initial channel handshake.
	///
	/// Default value: false.
	pub announced_channel: bool,
	/// When set, we commit to an upfront shutdown_pubkey at channel open. If our counterparty
	/// supports it, they will then enforce the mutual-close output to us matches what we provided
	/// at intialization, preventing us from closing to an alternate pubkey.
	///
	/// This is set to true by default to provide a slight increase in security, though ultimately
	/// any attacker who is able to take control of a channel can just as easily send the funds via
	/// lightning payments, so we never require that our counterparties support this option.
	///
	/// This cannot be changed after a channel has been initialized.
	///
	/// Default value: true.
	pub commit_upfront_shutdown_pubkey: bool,
	/// Limit our total exposure to in-flight HTLCs which are burned to fees as they are too
	/// small to claim on-chain.
	///
	/// When an HTLC present in one of our channels is below a "dust" threshold, the HTLC will
	/// not be claimable on-chain, instead being turned into additional miner fees if either
	/// party force-closes the channel. Because the threshold is per-HTLC, our total exposure
	/// to such payments may be sustantial if there are many dust HTLCs present when the
	/// channel is force-closed.
	///
	/// This limit is applied for sent, forwarded, and received HTLCs and limits the total
	/// exposure across all three types per-channel. Setting this too low may prevent the
	/// sending or receipt of low-value HTLCs on high-traffic nodes, and this limit is very
	/// important to prevent stealing of dust HTLCs by miners.
	///
	/// Default value: 5_000_000 msat.
	pub max_dust_htlc_exposure_msat: u64,
	/// The additional fee we're willing to pay to avoid waiting for the counterparty's
	/// `to_self_delay` to reclaim funds.
	///
	/// When we close a channel cooperatively with our counterparty, we negotiate a fee for the
	/// closing transaction which both sides find acceptable, ultimately paid by the channel
	/// funder/initiator.
	///
	/// When we are the funder, because we have to pay the channel closing fee, we bound the
	/// acceptable fee by our [`Background`] and [`Normal`] fees, with the upper bound increased by
	/// this value. Because the on-chain fee we'd pay to force-close the channel is kept near our
	/// [`Normal`] feerate during normal operation, this value represents the additional fee we're
	/// willing to pay in order to avoid waiting for our counterparty's to_self_delay to reclaim our
	/// funds.
	///
	/// When we are not the funder, we require the closing transaction fee pay at least our
	/// [`Background`] fee estimate, but allow our counterparty to pay as much fee as they like.
	/// Thus, this value is ignored when we are not the funder.
	///
	/// Default value: 1000 satoshis.
	///
	/// [`Normal`]: crate::chain::chaininterface::ConfirmationTarget::Normal
	/// [`Background`]: crate::chain::chaininterface::ConfirmationTarget::Background
	pub force_close_avoidance_max_fee_satoshis: u64,
}

impl Default for ChannelConfig {
	/// Provides sane defaults for most configurations (but with zero relay fees!).
	fn default() -> Self {
		ChannelConfig {
			forwarding_fee_proportional_millionths: 0,
			forwarding_fee_base_msat: 1000,
			cltv_expiry_delta: 6 * 12, // 6 blocks/hour * 12 hours
			announced_channel: false,
			commit_upfront_shutdown_pubkey: true,
			max_dust_htlc_exposure_msat: 5_000_000,
			force_close_avoidance_max_fee_satoshis: 1000,
		}
	}
}

impl_writeable_tlv_based!(ChannelConfig, {
	(0, forwarding_fee_proportional_millionths, required),
	(1, max_dust_htlc_exposure_msat, (default_value, 5_000_000)),
	(2, cltv_expiry_delta, required),
	(3, force_close_avoidance_max_fee_satoshis, (default_value, 1000)),
	(4, announced_channel, required),
	(6, commit_upfront_shutdown_pubkey, required),
	(8, forwarding_fee_base_msat, required),
});

/// Top-level config which holds ChannelHandshakeLimits and ChannelConfig.
///
/// Default::default() provides sane defaults for most configurations
/// (but currently with 0 relay fees!)
#[derive(Copy, Clone, Debug)]
pub struct UserConfig {
	/// Channel config that we propose to our counterparty.
	pub own_channel_config: ChannelHandshakeConfig,
	/// Limits applied to our counterparty's proposed channel config settings.
	pub peer_channel_config_limits: ChannelHandshakeLimits,
	/// Channel config which affects behavior during channel lifetime.
	pub channel_options: ChannelConfig,
	/// If this is set to false, we will reject any HTLCs which were to be forwarded over private
	/// channels. This prevents us from taking on HTLC-forwarding risk when we intend to run as a
	/// node which is not online reliably.
	///
	/// For nodes which are not online reliably, you should set all channels to *not* be announced
	/// (using [`ChannelConfig::announced_channel`] and
	/// [`ChannelHandshakeLimits::force_announced_channel_preference`]) and set this to false to
	/// ensure you are not exposed to any forwarding risk.
	///
	/// Note that because you cannot change a channel's announced state after creation, there is no
	/// way to disable forwarding on public channels retroactively. Thus, in order to change a node
	/// from a publicly-announced forwarding node to a private non-forwarding node you must close
	/// all your channels and open new ones. For privacy, you should also change your node_id
	/// (swapping all private and public key material for new ones) at that time.
	///
	/// Default value: false.
	pub accept_forwards_to_priv_channels: bool,
}

impl Default for UserConfig {
	fn default() -> Self {
		UserConfig {
			own_channel_config: ChannelHandshakeConfig::default(),
			peer_channel_config_limits: ChannelHandshakeLimits::default(),
			channel_options: ChannelConfig::default(),
			accept_forwards_to_priv_channels: false,
		}
	}
}
