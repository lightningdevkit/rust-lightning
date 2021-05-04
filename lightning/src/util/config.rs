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
	/// Set to force the incoming channel to match our announced channel preference in
	/// ChannelConfig.
	///
	/// Default value: true, to make the default that no announced channels are possible (which is
	/// appropriate for any nodes which are not online very reliably).
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
	/// Amount (in millionths of a satoshi) the channel will charge per transferred satoshi.
	/// This may be allowed to change at runtime in a later update, however doing so must result in
	/// update messages sent to notify all nodes of our updated relay fee.
	///
	/// Default value: 0.
	pub fee_proportional_millionths: u32,
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
	/// channels unless ChannelHandshakeLimits::force_announced_channel_preferences is set.
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
	pub commit_upfront_shutdown_pubkey: bool
}

impl Default for ChannelConfig {
	/// Provides sane defaults for most configurations (but with zero relay fees!).
	fn default() -> Self {
		ChannelConfig {
			fee_proportional_millionths: 0,
			cltv_expiry_delta: 6 * 12, // 6 blocks/hour * 12 hours
			announced_channel: false,
			commit_upfront_shutdown_pubkey: true,
		}
	}
}

//Add write and readable traits to channelconfig
impl_writeable!(ChannelConfig, 4+2+1+1, {
	fee_proportional_millionths,
	cltv_expiry_delta,
	announced_channel,
	commit_upfront_shutdown_pubkey
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
}

impl Default for UserConfig {
	fn default() -> Self {
		UserConfig {
			own_channel_config: ChannelHandshakeConfig::default(),
			peer_channel_config_limits: ChannelHandshakeLimits::default(),
			channel_options: ChannelConfig::default(),
		}
	}
}
