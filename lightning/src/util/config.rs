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

use crate::ln::channel::MAX_FUNDING_SATOSHIS_NO_WUMBO;
use crate::ln::channelmanager::{BREAKDOWN_TIMEOUT, MAX_LOCAL_BREAKDOWN_TIMEOUT};

#[cfg(fuzzing)]
use crate::util::ser::Readable;

/// Configuration we set when applicable.
///
/// `Default::default()` provides sane defaults.
#[derive(Copy, Clone, Debug)]
pub struct ChannelHandshakeConfig {
	/// Confirmations we will wait for before considering the channel locked in.
	/// Applied only for inbound channels (see [`ChannelHandshakeLimits::max_minimum_depth`] for the
	/// equivalent limit applied to outbound channels).
	///
	/// A lower-bound of `1` is applied, requiring all channels to have a confirmed commitment
	/// transaction before operation. If you wish to accept channels with zero confirmations, see
	/// [`UserConfig::manually_accept_inbound_channels`] and
	/// [`ChannelManager::accept_inbound_channel_from_trusted_peer_0conf`].
	///
	/// Default value: `6`
	///
	/// [`ChannelManager::accept_inbound_channel`]: crate::ln::channelmanager::ChannelManager::accept_inbound_channel
	/// [`ChannelManager::accept_inbound_channel_from_trusted_peer_0conf`]: crate::ln::channelmanager::ChannelManager::accept_inbound_channel_from_trusted_peer_0conf
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
	/// Default value: [`BREAKDOWN_TIMEOUT`] (We enforce it as a minimum at channel opening so you
	/// can tweak config to ask for more security, not less.)
	pub our_to_self_delay: u16,
	/// Set to the smallest value HTLC we will accept to process.
	///
	/// This value is sent to our counterparty on channel-open and we close the channel any time
	/// our counterparty misbehaves by sending us an HTLC with a value smaller than this.
	///
	/// Default value: `1` (If the value is less than `1`, it is ignored and set to `1`, as is
	/// required by the protocol.
	pub our_htlc_minimum_msat: u64,
	/// Sets the percentage of the channel value we will cap the total value of outstanding inbound
	/// HTLCs to.
	///
	/// This can be set to a value between 1-100, where the value corresponds to the percent of the
	/// channel value in whole percentages.
	///
	/// Note that:
	/// * If configured to another value than the default value `10`, any new channels created with
	///   the non default value will cause versions of LDK prior to 0.0.104 to refuse to read the
	///   `ChannelManager`.
	///
	/// * This caps the total value for inbound HTLCs in-flight only, and there's currently
	///   no way to configure the cap for the total value of outbound HTLCs in-flight.
	///
	/// * The requirements for your node being online to ensure the safety of HTLC-encumbered funds
	///   are different from the non-HTLC-encumbered funds. This makes this an important knob to
	///   restrict exposure to loss due to being offline for too long.
	///   See [`ChannelHandshakeConfig::our_to_self_delay`] and [`ChannelConfig::cltv_expiry_delta`]
	///   for more information.
	///
	/// Default value: `10`
	///
	/// Minimum value: `1` (Any values less will be treated as `1` instead.)
	///
	/// Maximum value: `100` (Any values larger will be treated as `100` instead.)
	pub max_inbound_htlc_value_in_flight_percent_of_channel: u8,
	/// If set, we attempt to negotiate the `scid_privacy` (referred to as `scid_alias` in the
	/// BOLTs) option for outbound private channels. This provides better privacy by not including
	/// our real on-chain channel UTXO in each invoice and requiring that our counterparty only
	/// relay HTLCs to us using the channel's SCID alias.
	///
	/// If this option is set, channels may be created that will not be readable by LDK versions
	/// prior to 0.0.106, causing [`ChannelManager`]'s read method to return a
	/// [`DecodeError::InvalidValue`].
	///
	/// Note that setting this to true does *not* prevent us from opening channels with
	/// counterparties that do not support the `scid_alias` option; we will simply fall back to a
	/// private channel without that option.
	///
	/// Ignored if the channel is negotiated to be announced, see
	/// [`ChannelHandshakeConfig::announce_for_forwarding`] and
	/// [`ChannelHandshakeLimits::force_announced_channel_preference`] for more.
	///
	/// Default value: `false` (This value is likely to change to `true` in the future.)
	///
	/// [`ChannelManager`]: crate::ln::channelmanager::ChannelManager
	/// [`DecodeError::InvalidValue`]: crate::ln::msgs::DecodeError::InvalidValue
	pub negotiate_scid_privacy: bool,
	/// Set to announce the channel publicly and notify all nodes that they can route via this
	/// channel.
	///
	/// This should only be set to true for nodes which expect to be online reliably.
	///
	/// As the node which funds a channel picks this value this will only apply for new outbound
	/// channels unless [`ChannelHandshakeLimits::force_announced_channel_preference`] is set.
	///
	/// Default value: `false`
	pub announce_for_forwarding: bool,
	/// When set, we commit to an upfront shutdown_pubkey at channel open. If our counterparty
	/// supports it, they will then enforce the mutual-close output to us matches what we provided
	/// at intialization, preventing us from closing to an alternate pubkey.
	///
	/// This is set to true by default to provide a slight increase in security, though ultimately
	/// any attacker who is able to take control of a channel can just as easily send the funds via
	/// lightning payments, so we never require that our counterparties support this option.
	///
	/// The upfront key committed is provided from [`SignerProvider::get_shutdown_scriptpubkey`].
	///
	/// Default value: `true`
	///
	/// [`SignerProvider::get_shutdown_scriptpubkey`]: crate::sign::SignerProvider::get_shutdown_scriptpubkey
	pub commit_upfront_shutdown_pubkey: bool,
	/// The Proportion of the channel value to configure as counterparty's channel reserve,
	/// i.e., `their_channel_reserve_satoshis` for both outbound and inbound channels.
	///
	/// `their_channel_reserve_satoshis` is the minimum balance that the other node has to maintain
	/// on their side, at all times.
	/// This ensures that if our counterparty broadcasts a revoked state, we can punish them by
	/// claiming at least this value on chain.
	///
	/// Channel reserve values greater than 30% could be considered highly unreasonable, since that
	/// amount can never be used for payments.
	/// Also, if our selected channel reserve for counterparty and counterparty's selected
	/// channel reserve for us sum up to equal or greater than channel value, channel negotiations
	/// will fail.
	///
	/// Note: Versions of LDK earlier than v0.0.104 will fail to read channels with any channel reserve
	/// other than the default value.
	///
	/// Default value: `10_000` millionths (i.e., 1% of channel value)
	///
	/// Minimum value: If the calculated proportional value is less than `1000` sats, it will be
	///                treated as `1000` sats instead, which is a safe implementation-specific lower
	///                bound.
	///
	/// Maximum value: `1_000_000` (i.e., 100% of channel value. Any values larger than one million
	///                will be treated as one million instead, although channel negotiations will
	///                fail in that case.)
	pub their_channel_reserve_proportional_millionths: u32,
	/// If set, we attempt to negotiate the `anchors_zero_fee_htlc_tx`option for all future
	/// channels. This feature requires having a reserve of onchain funds readily available to bump
	/// transactions in the event of a channel force close to avoid the possibility of losing funds.
	///
	/// Note that if you wish accept inbound channels with anchor outputs, you must enable
	/// [`UserConfig::manually_accept_inbound_channels`] and manually accept them with
	/// [`ChannelManager::accept_inbound_channel`]. This is done to give you the chance to check
	/// whether your reserve of onchain funds is enough to cover the fees for all existing and new
	/// channels featuring anchor outputs in the event of a force close.
	///
	/// If this option is set, channels may be created that will not be readable by LDK versions
	/// prior to 0.0.116, causing [`ChannelManager`]'s read method to return a
	/// [`DecodeError::InvalidValue`].
	///
	/// Note that setting this to true does *not* prevent us from opening channels with
	/// counterparties that do not support the `anchors_zero_fee_htlc_tx` option; we will simply
	/// fall back to a `static_remote_key` channel.
	///
	/// LDK will not support the legacy `option_anchors` commitment version due to a discovered
	/// vulnerability after its deployment. For more context, see the [`SIGHASH_SINGLE + update_fee
	/// Considered Harmful`] mailing list post.
	///
	/// Default value: `false` (This value is likely to change to `true` in the future.)
	///
	/// [`ChannelManager`]: crate::ln::channelmanager::ChannelManager
	/// [`ChannelManager::accept_inbound_channel`]: crate::ln::channelmanager::ChannelManager::accept_inbound_channel
	/// [`DecodeError::InvalidValue`]: crate::ln::msgs::DecodeError::InvalidValue
	/// [`SIGHASH_SINGLE + update_fee Considered Harmful`]: https://lists.linuxfoundation.org/pipermail/lightning-dev/2020-September/002796.html
	pub negotiate_anchors_zero_fee_htlc_tx: bool,

	/// The maximum number of HTLCs in-flight from our counterparty towards us at the same time.
	///
	/// Increasing the value can help improve liquidity and stability in
	/// routing at the cost of higher long term disk / DB usage.
	///
	/// Note: Versions of LDK earlier than v0.0.115 will fail to read channels with a configuration
	/// other than the default value.
	///
	/// Default value: `50`
	///
	/// Maximum value: `483` (Any values larger will be treated as `483`. This is the BOLT #2 spec
	/// limit on `max_accepted_htlcs`.)
	pub our_max_accepted_htlcs: u16,
}

impl Default for ChannelHandshakeConfig {
	fn default() -> ChannelHandshakeConfig {
		ChannelHandshakeConfig {
			minimum_depth: 6,
			our_to_self_delay: BREAKDOWN_TIMEOUT,
			our_htlc_minimum_msat: 1,
			max_inbound_htlc_value_in_flight_percent_of_channel: 10,
			negotiate_scid_privacy: false,
			announce_for_forwarding: false,
			commit_upfront_shutdown_pubkey: true,
			their_channel_reserve_proportional_millionths: 10_000,
			negotiate_anchors_zero_fee_htlc_tx: false,
			our_max_accepted_htlcs: 50,
		}
	}
}

// When fuzzing, we want to allow the fuzzer to pick any configuration parameters. Thus, we
// implement Readable here in a naive way (which is a bit easier for the fuzzer to handle). We
// don't really want to ever expose this to users (if we did we'd want to use TLVs).
#[cfg(fuzzing)]
impl Readable for ChannelHandshakeConfig {
	fn read<R: crate::io::Read>(reader: &mut R) -> Result<Self, crate::ln::msgs::DecodeError> {
		Ok(Self {
			minimum_depth: Readable::read(reader)?,
			our_to_self_delay: Readable::read(reader)?,
			our_htlc_minimum_msat: Readable::read(reader)?,
			max_inbound_htlc_value_in_flight_percent_of_channel: Readable::read(reader)?,
			negotiate_scid_privacy: Readable::read(reader)?,
			announce_for_forwarding: Readable::read(reader)?,
			commit_upfront_shutdown_pubkey: Readable::read(reader)?,
			their_channel_reserve_proportional_millionths: Readable::read(reader)?,
			negotiate_anchors_zero_fee_htlc_tx: Readable::read(reader)?,
			our_max_accepted_htlcs: Readable::read(reader)?,
		})
	}
}

/// Optional channel limits which are applied during channel creation.
///
/// These limits are only applied to our counterparty's limits, not our own.
///
/// Use `0` or `<type>::max_value()` as appropriate to skip checking.
///
/// Provides sane defaults for most configurations.
///
/// Most additional limits are disabled except those with which specify a default in individual
/// field documentation. Note that this may result in barely-usable channels, but since they
/// are applied mostly only to incoming channels that's not much of a problem.
#[derive(Copy, Clone, Debug)]
pub struct ChannelHandshakeLimits {
	/// Minimum allowed satoshis when a channel is funded. This is supplied by the sender and so
	/// only applies to inbound channels.
	///
	/// Default value: `1000`
	/// (Minimum of [`ChannelHandshakeConfig::their_channel_reserve_proportional_millionths`])
	pub min_funding_satoshis: u64,
	/// Maximum allowed satoshis when a channel is funded. This is supplied by the sender and so
	/// only applies to inbound channels.
	///
	/// Default value: `2^24 - 1`
	pub max_funding_satoshis: u64,
	/// The remote node sets a limit on the minimum size of HTLCs we can send to them. This allows
	/// you to limit the maximum minimum-size they can require.
	///
	/// Default value: `u64::max_value`
	pub max_htlc_minimum_msat: u64,
	/// The remote node sets a limit on the maximum value of pending HTLCs to them at any given
	/// time to limit their funds exposure to HTLCs. This allows you to set a minimum such value.
	///
	/// Default value: `0`
	pub min_max_htlc_value_in_flight_msat: u64,
	/// The remote node will require we keep a certain amount in direct payment to ourselves at all
	/// time, ensuring that we are able to be punished if we broadcast an old state. This allows to
	/// you limit the amount which we will have to keep to ourselves (and cannot use for HTLCs).
	///
	/// Default value: `u64::max_value`.
	pub max_channel_reserve_satoshis: u64,
	/// The remote node sets a limit on the maximum number of pending HTLCs to them at any given
	/// time. This allows you to set a minimum such value.
	///
	/// Default value: `0`
	pub min_max_accepted_htlcs: u16,
	/// Before a channel is usable the funding transaction will need to be confirmed by at least a
	/// certain number of blocks, specified by the node which is not the funder (as the funder can
	/// assume they aren't going to double-spend themselves).
	/// This config allows you to set a limit on the maximum amount of time to wait.
	///
	/// Default value: `144`, or roughly one day and only applies to outbound channels
	pub max_minimum_depth: u32,
	/// Whether we implicitly trust funding transactions generated by us for our own outbound
	/// channels to not be double-spent.
	///
	/// If this is set, we assume that our own funding transactions are *never* double-spent, and
	/// thus we can trust them without any confirmations. This is generally a reasonable
	/// assumption, given we're the only ones who could ever double-spend it (assuming we have sole
	/// control of the signing keys).
	///
	/// You may wish to un-set this if you allow the user to (or do in an automated fashion)
	/// double-spend the funding transaction to RBF with an alternative channel open.
	///
	/// This only applies if our counterparty set their confirmations-required value to `0`, and we
	/// always trust our own funding transaction at `1` confirmation irrespective of this value.
	/// Thus, this effectively acts as a `min_minimum_depth`, with the only possible values being
	/// `true` (`0`) and `false` (`1`).
	///
	/// Default value: `true`
	pub trust_own_funding_0conf: bool,
	/// Set to force an incoming channel to match our announced channel preference in
	/// [`ChannelHandshakeConfig::announce_for_forwarding`].
	///
	/// For a node which is not online reliably, this should be set to true and
	/// [`ChannelHandshakeConfig::announce_for_forwarding`] set to false, ensuring that no announced (aka public)
	/// channels will ever be opened.
	///
	/// Default value: `true`
	pub force_announced_channel_preference: bool,
	/// Set to the amount of time we're willing to wait to claim money back to us.
	///
	/// Not checking this value would be a security issue, as our peer would be able to set it to
	/// max relative lock-time (a year) and we would "lose" money as it would be locked for a long time.
	///
	/// Default value: `2016`, which we also enforce as a maximum value so you can tweak config to
	/// reduce the loss of having useless locked funds (if your peer accepts)
	pub their_to_self_delay: u16,
}

impl Default for ChannelHandshakeLimits {
	fn default() -> Self {
		ChannelHandshakeLimits {
			min_funding_satoshis: 1000,
			max_funding_satoshis: MAX_FUNDING_SATOSHIS_NO_WUMBO,
			max_htlc_minimum_msat: u64::MAX,
			min_max_htlc_value_in_flight_msat: 0,
			max_channel_reserve_satoshis: u64::MAX,
			min_max_accepted_htlcs: 0,
			trust_own_funding_0conf: true,
			max_minimum_depth: 144,
			force_announced_channel_preference: true,
			their_to_self_delay: MAX_LOCAL_BREAKDOWN_TIMEOUT,
		}
	}
}

// When fuzzing, we want to allow the fuzzer to pick any configuration parameters. Thus, we
// implement Readable here in a naive way (which is a bit easier for the fuzzer to handle). We
// don't really want to ever expose this to users (if we did we'd want to use TLVs).
#[cfg(fuzzing)]
impl Readable for ChannelHandshakeLimits {
	fn read<R: crate::io::Read>(reader: &mut R) -> Result<Self, crate::ln::msgs::DecodeError> {
		Ok(Self {
			min_funding_satoshis: Readable::read(reader)?,
			max_funding_satoshis: Readable::read(reader)?,
			max_htlc_minimum_msat: Readable::read(reader)?,
			min_max_htlc_value_in_flight_msat: Readable::read(reader)?,
			max_channel_reserve_satoshis: Readable::read(reader)?,
			min_max_accepted_htlcs: Readable::read(reader)?,
			trust_own_funding_0conf: Readable::read(reader)?,
			max_minimum_depth: Readable::read(reader)?,
			force_announced_channel_preference: Readable::read(reader)?,
			their_to_self_delay: Readable::read(reader)?,
		})
	}
}

/// Options for how to set the max dust exposure allowed on a channel. See
/// [`ChannelConfig::max_dust_htlc_exposure`] for details.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MaxDustHTLCExposure {
	/// This sets a fixed limit on the total dust exposure in millisatoshis. Setting this too low
	/// may prevent the sending or receipt of low-value HTLCs on high-traffic nodes, however this
	/// limit is very important to prevent stealing of large amounts of dust HTLCs by miners
	/// through [fee griefing
	/// attacks](https://lists.linuxfoundation.org/pipermail/lightning-dev/2020-May/002714.html).
	///
	/// Note that if the feerate increases significantly, without a manual increase
	/// to this maximum the channel may be unable to send/receive HTLCs between the maximum dust
	/// exposure and the new minimum value for HTLCs to be economically viable to claim.
	FixedLimitMsat(u64),
	/// This sets a multiplier on the [`ConfirmationTarget::MaximumFeeEstimate`] feerate (in
	/// sats/KW) to determine the maximum allowed dust exposure. If this variant is used then the
	/// maximum dust exposure in millisatoshis is calculated as:
	/// `feerate_per_kw * value`. For example, with our default value
	/// `FeeRateMultiplier(10_000)`:
	///
	/// - For the minimum fee rate of 1 sat/vByte (250 sat/KW, although the minimum
	///   defaults to 253 sats/KW for rounding, see [`FeeEstimator`]), the max dust exposure would
	///   be 253 * 10_000 = 2,530,000 msats.
	/// - For a fee rate of 30 sat/vByte (7500 sat/KW), the max dust exposure would be
	///   7500 * 50_000 = 75,000,000 msats (0.00075 BTC).
	///
	/// Note, if you're using a third-party fee estimator, this may leave you more exposed to a
	/// fee griefing attack, where your fee estimator may purposely overestimate the fee rate,
	/// causing you to accept more dust HTLCs than you would otherwise.
	///
	/// This variant is primarily meant to serve pre-anchor channels, as HTLC fees being included
	/// on HTLC outputs means your channel may be subject to more dust exposure in the event of
	/// increases in fee rate.
	///
	/// # Backwards Compatibility
	/// This variant only became available in LDK 0.0.116, so if you downgrade to a prior version
	/// by default this will be set to a [`Self::FixedLimitMsat`] of 5,000,000 msat.
	///
	/// [`FeeEstimator`]: crate::chain::chaininterface::FeeEstimator
	/// [`ConfirmationTarget::MaximumFeeEstimate`]: crate::chain::chaininterface::ConfirmationTarget::MaximumFeeEstimate
	FeeRateMultiplier(u64),
}

impl_writeable_tlv_based_enum_legacy!(MaxDustHTLCExposure, ;
	(1, FixedLimitMsat),
	(3, FeeRateMultiplier),
);

/// Options which apply on a per-channel basis and may change at runtime or based on negotiation
/// with our counterparty.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ChannelConfig {
	/// Amount (in millionths of a satoshi) charged per satoshi for payments forwarded outbound
	/// over the channel.
	/// This may be allowed to change at runtime in a later update, however doing so must result in
	/// update messages sent to notify all nodes of our updated relay fee.
	///
	/// Default value: `0`
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
	/// Default value: `1000`
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
	/// Default value: `72` (12 hours at an average of 6 blocks/hour)
	///
	/// Minimum value: [`MIN_CLTV_EXPIRY_DELTA`] (Any values less than this will be treated as
	///                [`MIN_CLTV_EXPIRY_DELTA`] instead.)
	///
	/// [`MIN_CLTV_EXPIRY_DELTA`]: crate::ln::channelmanager::MIN_CLTV_EXPIRY_DELTA
	pub cltv_expiry_delta: u16,
	/// Limit our total exposure to potential loss to on-chain fees on close, including in-flight
	/// HTLCs which are burned to fees as they are too small to claim on-chain and fees on
	/// commitment transaction(s) broadcasted by our counterparty in excess of our own fee estimate.
	///
	/// # HTLC-based Dust Exposure
	///
	/// When an HTLC present in one of our channels is below a "dust" threshold, the HTLC will
	/// not be claimable on-chain, instead being turned into additional miner fees if either
	/// party force-closes the channel. Because the threshold is per-HTLC, our total exposure
	/// to such payments may be substantial if there are many dust HTLCs present when the
	/// channel is force-closed.
	///
	/// The dust threshold for each HTLC is based on the `dust_limit_satoshis` for each party in a
	/// channel negotiated throughout the channel open process, along with the fees required to have
	/// a broadcastable HTLC spending transaction. When a channel supports anchor outputs
	/// (specifically the zero fee HTLC transaction variant), this threshold no longer takes into
	/// account the HTLC transaction fee as it is zero. Because of this, you may want to set this
	/// value to a fixed limit for channels using anchor outputs, while the fee rate multiplier
	/// variant is primarily intended for use with pre-anchor channels.
	///
	/// The selected limit is applied for sent, forwarded, and received HTLCs and limits the total
	/// exposure across all three types per-channel.
	///
	/// # Transaction Fee Dust Exposure
	///
	/// Further, counterparties broadcasting a commitment transaction in a force-close may result
	/// in other balance being burned to fees, and thus all fees on commitment and HTLC
	/// transactions in excess of our local fee estimates are included in the dust calculation.
	///
	/// Because of this, another way to look at this limit is to divide it by 43,000 (or 218,750
	/// for non-anchor channels) and see it as the maximum feerate disagreement (in sats/vB) per
	/// non-dust HTLC we're allowed to have with our peers before risking a force-closure for
	/// inbound channels.
	// This works because, for anchor channels the on-chain cost is 172 weight (172+703 for
	// non-anchors with an HTLC-Success transaction), i.e.
	// dust_exposure_limit_msat / 1000 = 172 * feerate_in_sat_per_vb / 4 * HTLC count
	// dust_exposure_limit_msat = 43,000 * feerate_in_sat_per_vb * HTLC count
	// dust_exposure_limit_msat / HTLC count / 43,000 = feerate_in_sat_per_vb
	///
	/// Thus, for the default value of 10_000 * a current feerate estimate of 10 sat/vB (or 2,500
	/// sat/KW), we risk force-closure if we disagree with our peer by:
	/// * `10_000 * 2_500 / 43_000 / (483*2)` = 0.6 sat/vB for anchor channels with 483 HTLCs in
	///   both directions (the maximum),
	/// * `10_000 * 2_500 / 43_000 / (50*2)` = 5.8 sat/vB for anchor channels with 50 HTLCs in both
	///   directions (the LDK default max from [`ChannelHandshakeConfig::our_max_accepted_htlcs`])
	/// * `10_000 * 2_500 / 218_750 / (483*2)` = 0.1 sat/vB for non-anchor channels with 483 HTLCs
	///   in both directions (the maximum),
	/// * `10_000 * 2_500 / 218_750 / (50*2)` = 1.1 sat/vB for non-anchor channels with 50 HTLCs
	///   in both (the LDK default maximum from [`ChannelHandshakeConfig::our_max_accepted_htlcs`])
	///
	/// Note that when using [`MaxDustHTLCExposure::FeeRateMultiplier`] this maximum disagreement
	/// will scale linearly with increases (or decreases) in the our feerate estimates. Further,
	/// for anchor channels we expect our counterparty to use a relatively low feerate estimate
	/// while we use [`ConfirmationTarget::MaximumFeeEstimate`] (which should be relatively high)
	/// and feerate disagreement force-closures should only occur when theirs is higher than ours.
	///
	/// Default value: [`MaxDustHTLCExposure::FeeRateMultiplier`] with a multiplier of `10_000`
	///
	/// [`ConfirmationTarget::MaximumFeeEstimate`]: crate::chain::chaininterface::ConfirmationTarget::MaximumFeeEstimate
	pub max_dust_htlc_exposure: MaxDustHTLCExposure,
	/// The additional fee we're willing to pay to avoid waiting for the counterparty's
	/// `to_self_delay` to reclaim funds.
	///
	/// When we close a channel cooperatively with our counterparty, we negotiate a fee for the
	/// closing transaction which both sides find acceptable, ultimately paid by the channel
	/// funder/initiator.
	///
	/// When we are the funder, because we have to pay the channel closing fee, we bound the
	/// acceptable fee by our [`ChannelCloseMinimum`] and [`NonAnchorChannelFee`] fees, with the upper bound increased by
	/// this value. Because the on-chain fee we'd pay to force-close the channel is kept near our
	/// [`NonAnchorChannelFee`] feerate during normal operation, this value represents the additional fee we're
	/// willing to pay in order to avoid waiting for our counterparty's to_self_delay to reclaim our
	/// funds.
	///
	/// When we are not the funder, we require the closing transaction fee pay at least our
	/// [`ChannelCloseMinimum`] fee estimate, but allow our counterparty to pay as much fee as they like.
	/// Thus, this value is ignored when we are not the funder.
	///
	/// Default value: `1000`
	///
	/// [`NonAnchorChannelFee`]: crate::chain::chaininterface::ConfirmationTarget::NonAnchorChannelFee
	/// [`ChannelCloseMinimum`]: crate::chain::chaininterface::ConfirmationTarget::ChannelCloseMinimum
	pub force_close_avoidance_max_fee_satoshis: u64,
	/// If set, allows this channel's counterparty to skim an additional fee off this node's inbound
	/// HTLCs. Useful for liquidity providers to offload on-chain channel costs to end users.
	///
	/// Usage:
	/// - The payee will set this option and set its invoice route hints to use [intercept scids]
	///   generated by this channel's counterparty.
	/// - The counterparty will get an [`HTLCIntercepted`] event upon payment forward, and call
	///   [`forward_intercepted_htlc`] with less than the amount provided in
	///   [`HTLCIntercepted::expected_outbound_amount_msat`]. The difference between the expected and
	///   actual forward amounts is their fee. See
	///   <https://github.com/BitcoinAndLightningLayerSpecs/lsp/tree/main/LSPS2#flow-lsp-trusts-client-model>
	///   for how this feature may be used in the LSP use case.
	///
	/// # Note
	/// It's important for payee wallet software to verify that [`PaymentClaimable::amount_msat`] is
	/// as-expected if this feature is activated, otherwise they may lose money!
	/// [`PaymentClaimable::counterparty_skimmed_fee_msat`] provides the fee taken by the
	/// counterparty.
	///
	/// # Note
	/// Switching this config flag on may break compatibility with versions of LDK prior to 0.0.116.
	/// Unsetting this flag between restarts may lead to payment receive failures.
	///
	/// Default value: `false`
	///
	/// [intercept scids]: crate::ln::channelmanager::ChannelManager::get_intercept_scid
	/// [`forward_intercepted_htlc`]: crate::ln::channelmanager::ChannelManager::forward_intercepted_htlc
	/// [`HTLCIntercepted`]: crate::events::Event::HTLCIntercepted
	/// [`HTLCIntercepted::expected_outbound_amount_msat`]: crate::events::Event::HTLCIntercepted::expected_outbound_amount_msat
	/// [`PaymentClaimable::amount_msat`]: crate::events::Event::PaymentClaimable::amount_msat
	/// [`PaymentClaimable::counterparty_skimmed_fee_msat`]: crate::events::Event::PaymentClaimable::counterparty_skimmed_fee_msat
	//  TODO: link to bLIP when it's merged
	pub accept_underpaying_htlcs: bool,
}

impl ChannelConfig {
	/// Applies the given [`ChannelConfigUpdate`] as a partial update to the [`ChannelConfig`].
	pub fn apply(&mut self, update: &ChannelConfigUpdate) {
		if let Some(forwarding_fee_proportional_millionths) =
			update.forwarding_fee_proportional_millionths
		{
			self.forwarding_fee_proportional_millionths = forwarding_fee_proportional_millionths;
		}
		if let Some(forwarding_fee_base_msat) = update.forwarding_fee_base_msat {
			self.forwarding_fee_base_msat = forwarding_fee_base_msat;
		}
		if let Some(cltv_expiry_delta) = update.cltv_expiry_delta {
			self.cltv_expiry_delta = cltv_expiry_delta;
		}
		if let Some(max_dust_htlc_exposure_msat) = update.max_dust_htlc_exposure_msat {
			self.max_dust_htlc_exposure = max_dust_htlc_exposure_msat;
		}
		if let Some(force_close_avoidance_max_fee_satoshis) =
			update.force_close_avoidance_max_fee_satoshis
		{
			self.force_close_avoidance_max_fee_satoshis = force_close_avoidance_max_fee_satoshis;
		}
	}
}

impl Default for ChannelConfig {
	/// Provides sane defaults for most configurations (but with zero relay fees!).
	fn default() -> Self {
		ChannelConfig {
			forwarding_fee_proportional_millionths: 0,
			forwarding_fee_base_msat: 1000,
			cltv_expiry_delta: 6 * 12, // 6 blocks/hour * 12 hours
			max_dust_htlc_exposure: MaxDustHTLCExposure::FeeRateMultiplier(10000),
			force_close_avoidance_max_fee_satoshis: 1000,
			accept_underpaying_htlcs: false,
		}
	}
}

impl crate::util::ser::Writeable for ChannelConfig {
	fn write<W: crate::util::ser::Writer>(&self, writer: &mut W) -> Result<(), crate::io::Error> {
		let max_dust_htlc_exposure_msat_fixed_limit = match self.max_dust_htlc_exposure {
			MaxDustHTLCExposure::FixedLimitMsat(limit) => limit,
			MaxDustHTLCExposure::FeeRateMultiplier(_) => 5_000_000,
		};
		write_tlv_fields!(writer, {
			(0, self.forwarding_fee_proportional_millionths, required),
			(1, self.accept_underpaying_htlcs, (default_value, false)),
			(2, self.forwarding_fee_base_msat, required),
			(3, self.max_dust_htlc_exposure, required),
			(4, self.cltv_expiry_delta, required),
			(6, max_dust_htlc_exposure_msat_fixed_limit, required),
			// ChannelConfig serialized this field with a required type of 8 prior to the introduction of
			// LegacyChannelConfig. To make sure that serialization is not compatible with this one, we use
			// the next required type of 10, which if seen by the old serialization will always fail.
			(10, self.force_close_avoidance_max_fee_satoshis, required),
		});
		Ok(())
	}
}

impl crate::util::ser::Readable for ChannelConfig {
	fn read<R: crate::io::Read>(reader: &mut R) -> Result<Self, crate::ln::msgs::DecodeError> {
		let mut forwarding_fee_proportional_millionths = 0;
		let mut accept_underpaying_htlcs = false;
		let mut forwarding_fee_base_msat = 1000;
		let mut cltv_expiry_delta = 6 * 12;
		let mut max_dust_htlc_exposure_msat = None;
		let mut max_dust_htlc_exposure_enum = None;
		let mut force_close_avoidance_max_fee_satoshis = 1000;
		read_tlv_fields!(reader, {
			(0, forwarding_fee_proportional_millionths, required),
			(1, accept_underpaying_htlcs, (default_value, false)),
			(2, forwarding_fee_base_msat, required),
			(3, max_dust_htlc_exposure_enum, option),
			(4, cltv_expiry_delta, required),
			// Has always been written, but became optionally read in 0.0.116
			(6, max_dust_htlc_exposure_msat, option),
			(10, force_close_avoidance_max_fee_satoshis, required),
		});
		let max_dust_htlc_fixed_limit = max_dust_htlc_exposure_msat.unwrap_or(5_000_000);
		let max_dust_htlc_exposure_msat = max_dust_htlc_exposure_enum
			.unwrap_or(MaxDustHTLCExposure::FixedLimitMsat(max_dust_htlc_fixed_limit));
		Ok(Self {
			forwarding_fee_proportional_millionths,
			accept_underpaying_htlcs,
			forwarding_fee_base_msat,
			cltv_expiry_delta,
			max_dust_htlc_exposure: max_dust_htlc_exposure_msat,
			force_close_avoidance_max_fee_satoshis,
		})
	}
}

/// A parallel struct to [`ChannelConfig`] to define partial updates.
#[allow(missing_docs)]
#[derive(Default)]
pub struct ChannelConfigUpdate {
	pub forwarding_fee_proportional_millionths: Option<u32>,
	pub forwarding_fee_base_msat: Option<u32>,
	pub cltv_expiry_delta: Option<u16>,
	pub max_dust_htlc_exposure_msat: Option<MaxDustHTLCExposure>,
	pub force_close_avoidance_max_fee_satoshis: Option<u64>,
}

impl From<ChannelConfig> for ChannelConfigUpdate {
	fn from(config: ChannelConfig) -> ChannelConfigUpdate {
		ChannelConfigUpdate {
			forwarding_fee_proportional_millionths: Some(
				config.forwarding_fee_proportional_millionths,
			),
			forwarding_fee_base_msat: Some(config.forwarding_fee_base_msat),
			cltv_expiry_delta: Some(config.cltv_expiry_delta),
			max_dust_htlc_exposure_msat: Some(config.max_dust_htlc_exposure),
			force_close_avoidance_max_fee_satoshis: Some(
				config.force_close_avoidance_max_fee_satoshis,
			),
		}
	}
}

/// Legacy version of [`ChannelConfig`] that stored the static
/// [`ChannelHandshakeConfig::announce_for_forwarding`] and
/// [`ChannelHandshakeConfig::commit_upfront_shutdown_pubkey`] fields.
#[derive(Copy, Clone, Debug)]
pub(crate) struct LegacyChannelConfig {
	pub(crate) options: ChannelConfig,
	/// Deprecated but may still be read from. See [`ChannelHandshakeConfig::announce_for_forwarding`] to
	/// set this when opening/accepting a channel.
	pub(crate) announce_for_forwarding: bool,
	/// Deprecated but may still be read from. See
	/// [`ChannelHandshakeConfig::commit_upfront_shutdown_pubkey`] to set this when
	/// opening/accepting a channel.
	pub(crate) commit_upfront_shutdown_pubkey: bool,
}

impl Default for LegacyChannelConfig {
	fn default() -> Self {
		Self {
			options: ChannelConfig::default(),
			announce_for_forwarding: false,
			commit_upfront_shutdown_pubkey: true,
		}
	}
}

impl crate::util::ser::Writeable for LegacyChannelConfig {
	fn write<W: crate::util::ser::Writer>(&self, writer: &mut W) -> Result<(), crate::io::Error> {
		let max_dust_htlc_exposure_msat_fixed_limit = match self.options.max_dust_htlc_exposure {
			MaxDustHTLCExposure::FixedLimitMsat(limit) => limit,
			MaxDustHTLCExposure::FeeRateMultiplier(_) => 5_000_000,
		};
		write_tlv_fields!(writer, {
			(0, self.options.forwarding_fee_proportional_millionths, required),
			(1, max_dust_htlc_exposure_msat_fixed_limit, required),
			(2, self.options.cltv_expiry_delta, required),
			(3, self.options.force_close_avoidance_max_fee_satoshis, (default_value, 1000)),
			(4, self.announce_for_forwarding, required),
			(5, self.options.max_dust_htlc_exposure, required),
			(6, self.commit_upfront_shutdown_pubkey, required),
			(8, self.options.forwarding_fee_base_msat, required),
		});
		Ok(())
	}
}

impl crate::util::ser::Readable for LegacyChannelConfig {
	fn read<R: crate::io::Read>(reader: &mut R) -> Result<Self, crate::ln::msgs::DecodeError> {
		let mut forwarding_fee_proportional_millionths = 0;
		let mut max_dust_htlc_exposure_msat_fixed_limit = None;
		let mut cltv_expiry_delta = 0;
		let mut force_close_avoidance_max_fee_satoshis = 1000;
		let mut announce_for_forwarding = false;
		let mut commit_upfront_shutdown_pubkey = false;
		let mut forwarding_fee_base_msat = 0;
		let mut max_dust_htlc_exposure_enum = None;
		read_tlv_fields!(reader, {
			(0, forwarding_fee_proportional_millionths, required),
			// Has always been written, but became optionally read in 0.0.116
			(1, max_dust_htlc_exposure_msat_fixed_limit, option),
			(2, cltv_expiry_delta, required),
			(3, force_close_avoidance_max_fee_satoshis, (default_value, 1000u64)),
			(4, announce_for_forwarding, required),
			(5, max_dust_htlc_exposure_enum, option),
			(6, commit_upfront_shutdown_pubkey, required),
			(8, forwarding_fee_base_msat, required),
		});
		let max_dust_htlc_exposure_msat_fixed_limit =
			max_dust_htlc_exposure_msat_fixed_limit.unwrap_or(5_000_000);
		let max_dust_htlc_exposure_msat = max_dust_htlc_exposure_enum.unwrap_or(
			MaxDustHTLCExposure::FixedLimitMsat(max_dust_htlc_exposure_msat_fixed_limit),
		);
		Ok(Self {
			options: ChannelConfig {
				forwarding_fee_proportional_millionths,
				max_dust_htlc_exposure: max_dust_htlc_exposure_msat,
				cltv_expiry_delta,
				force_close_avoidance_max_fee_satoshis,
				forwarding_fee_base_msat,
				accept_underpaying_htlcs: false,
			},
			announce_for_forwarding,
			commit_upfront_shutdown_pubkey,
		})
	}
}

/// Top-level config which holds ChannelHandshakeLimits and ChannelConfig.
///
/// `Default::default()` provides sane defaults for most configurations
/// (but currently with zero relay fees!)
#[derive(Copy, Clone, Debug)]
pub struct UserConfig {
	/// Channel handshake config that we propose to our counterparty.
	pub channel_handshake_config: ChannelHandshakeConfig,
	/// Limits applied to our counterparty's proposed channel handshake config settings.
	pub channel_handshake_limits: ChannelHandshakeLimits,
	/// Channel config which affects behavior during channel lifetime.
	pub channel_config: ChannelConfig,
	/// If this is set to `false`, we will reject any HTLCs which were to be forwarded over private
	/// channels. This prevents us from taking on HTLC-forwarding risk when we intend to run as a
	/// node which is not online reliably.
	///
	/// For nodes which are not online reliably, you should set all channels to *not* be announced
	/// (using [`ChannelHandshakeConfig::announce_for_forwarding`] and
	/// [`ChannelHandshakeLimits::force_announced_channel_preference`]) and set this to `false` to
	/// ensure you are not exposed to any forwarding risk.
	///
	/// Note that because you cannot change a channel's announced state after creation, there is no
	/// way to disable forwarding on public channels retroactively. Thus, in order to change a node
	/// from a publicly-announced forwarding node to a private non-forwarding node you must close
	/// all your channels and open new ones. For privacy, you should also change your node_id
	/// (swapping all private and public key material for new ones) at that time.
	///
	/// Default value: `false`
	pub accept_forwards_to_priv_channels: bool,
	/// If this is set to `false`, we do not accept inbound requests to open a new channel.
	///
	/// Default value: `true`
	pub accept_inbound_channels: bool,
	/// If this is set to `true`, the user needs to manually accept inbound requests to open a new
	/// channel.
	///
	/// When set to `true`, [`Event::OpenChannelRequest`] will be triggered once a request to open a
	/// new inbound channel is received through a [`msgs::OpenChannel`] message. In that case, a
	/// [`msgs::AcceptChannel`] message will not be sent back to the counterparty node unless the
	/// user explicitly chooses to accept the request.
	///
	/// Default value: `false`
	///
	/// [`Event::OpenChannelRequest`]: crate::events::Event::OpenChannelRequest
	/// [`msgs::OpenChannel`]: crate::ln::msgs::OpenChannel
	/// [`msgs::AcceptChannel`]: crate::ln::msgs::AcceptChannel
	pub manually_accept_inbound_channels: bool,
	///  If this is set to `true`, LDK will intercept HTLCs that are attempting to be forwarded over
	///  fake short channel ids generated via [`ChannelManager::get_intercept_scid`]. Upon HTLC
	///  intercept, LDK will generate an [`Event::HTLCIntercepted`] which MUST be handled by the user.
	///
	///  Setting this to `true` may break backwards compatibility with LDK versions < 0.0.113.
	///
	///  Default value: `false`
	///
	/// [`ChannelManager::get_intercept_scid`]: crate::ln::channelmanager::ChannelManager::get_intercept_scid
	/// [`Event::HTLCIntercepted`]: crate::events::Event::HTLCIntercepted
	pub accept_intercept_htlcs: bool,
	/// If this is set to `false`, when receiving a keysend payment we'll fail it if it has multiple
	/// parts. If this is set to `true`, we'll accept the payment.
	///
	/// Setting this to `true` will break backwards compatibility upon downgrading to an LDK
	/// version prior to 0.0.116 while receiving an MPP keysend. If we have already received an MPP
	/// keysend, downgrading will cause us to fail to deserialize [`ChannelManager`].
	///
	/// Default value: `false`
	///
	/// [`ChannelManager`]: crate::ln::channelmanager::ChannelManager
	pub accept_mpp_keysend: bool,
	/// If this is set to `true`, the user needs to manually pay [`Bolt12Invoice`]s when received.
	///
	/// When set to `true`, [`Event::InvoiceReceived`] will be generated for each received
	/// [`Bolt12Invoice`] instead of being automatically paid after verification. Use
	/// [`ChannelManager::send_payment_for_bolt12_invoice`] to pay the invoice or
	/// [`ChannelManager::abandon_payment`] to abandon the associated payment.
	///
	/// Default value: `false`
	///
	/// [`Bolt12Invoice`]: crate::offers::invoice::Bolt12Invoice
	/// [`Event::InvoiceReceived`]: crate::events::Event::InvoiceReceived
	/// [`ChannelManager::send_payment_for_bolt12_invoice`]: crate::ln::channelmanager::ChannelManager::send_payment_for_bolt12_invoice
	/// [`ChannelManager::abandon_payment`]: crate::ln::channelmanager::ChannelManager::abandon_payment
	pub manually_handle_bolt12_invoices: bool,
}

impl Default for UserConfig {
	fn default() -> Self {
		UserConfig {
			channel_handshake_config: ChannelHandshakeConfig::default(),
			channel_handshake_limits: ChannelHandshakeLimits::default(),
			channel_config: ChannelConfig::default(),
			accept_forwards_to_priv_channels: false,
			accept_inbound_channels: true,
			manually_accept_inbound_channels: false,
			accept_intercept_htlcs: false,
			accept_mpp_keysend: false,
			manually_handle_bolt12_invoices: false,
		}
	}
}

// When fuzzing, we want to allow the fuzzer to pick any configuration parameters. Thus, we
// implement Readable here in a naive way (which is a bit easier for the fuzzer to handle). We
// don't really want to ever expose this to users (if we did we'd want to use TLVs).
#[cfg(fuzzing)]
impl Readable for UserConfig {
	fn read<R: crate::io::Read>(reader: &mut R) -> Result<Self, crate::ln::msgs::DecodeError> {
		Ok(Self {
			channel_handshake_config: Readable::read(reader)?,
			channel_handshake_limits: Readable::read(reader)?,
			channel_config: Readable::read(reader)?,
			accept_forwards_to_priv_channels: Readable::read(reader)?,
			accept_inbound_channels: Readable::read(reader)?,
			manually_accept_inbound_channels: Readable::read(reader)?,
			accept_intercept_htlcs: Readable::read(reader)?,
			accept_mpp_keysend: Readable::read(reader)?,
			manually_handle_bolt12_invoices: Readable::read(reader)?,
		})
	}
}
