// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

use bitcoin::blockdata::script::{Script,Builder};
use bitcoin::blockdata::transaction::{Transaction, EcdsaSighashType};
use bitcoin::util::sighash;
use bitcoin::consensus::encode;

use bitcoin::hashes::Hash;
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::sha256d::Hash as Sha256d;
use bitcoin::hash_types::{Txid, BlockHash};

use bitcoin::secp256k1::constants::PUBLIC_KEY_SIZE;
use bitcoin::secp256k1::{PublicKey,SecretKey};
use bitcoin::secp256k1::{Secp256k1,ecdsa::Signature};
use bitcoin::secp256k1;

use crate::ln::{PaymentPreimage, PaymentHash};
use crate::ln::features::{ChannelTypeFeatures, InitFeatures};
use crate::ln::msgs;
use crate::ln::msgs::{DecodeError, OptionalField, DataLossProtect};
use crate::ln::script::{self, ShutdownScript};
use crate::ln::channelmanager::{self, CounterpartyForwardingInfo, PendingHTLCStatus, HTLCSource, SentHTLCId, HTLCFailureMsg, PendingHTLCInfo, RAACommitmentOrder, BREAKDOWN_TIMEOUT, MIN_CLTV_EXPIRY_DELTA, MAX_LOCAL_BREAKDOWN_TIMEOUT};
use crate::ln::chan_utils::{CounterpartyCommitmentSecrets, TxCreationKeys, HTLCOutputInCommitment, htlc_success_tx_weight, htlc_timeout_tx_weight, make_funding_redeemscript, ChannelPublicKeys, CommitmentTransaction, HolderCommitmentTransaction, ChannelTransactionParameters, CounterpartyChannelTransactionParameters, MAX_HTLCS, get_commitment_transaction_number_obscure_factor, ClosingTransaction};
use crate::ln::chan_utils;
use crate::ln::onion_utils::HTLCFailReason;
use crate::chain::BestBlock;
use crate::chain::chaininterface::{FeeEstimator, ConfirmationTarget, LowerBoundedFeeEstimator};
use crate::chain::channelmonitor::{ChannelMonitor, ChannelMonitorUpdate, ChannelMonitorUpdateStep, LATENCY_GRACE_PERIOD_BLOCKS};
use crate::chain::transaction::{OutPoint, TransactionData};
use crate::chain::keysinterface::{WriteableEcdsaChannelSigner, EntropySource, ChannelSigner, SignerProvider, NodeSigner, Recipient};
use crate::routing::gossip::NodeId;
use crate::util::events::ClosureReason;
use crate::util::ser::{Readable, ReadableArgs, Writeable, Writer, VecWriter};
use crate::util::logger::Logger;
use crate::util::errors::APIError;
use crate::util::config::{UserConfig, ChannelConfig, LegacyChannelConfig, ChannelHandshakeConfig, ChannelHandshakeLimits};
use crate::util::scid_utils::scid_from_parts;

use crate::io;
use crate::prelude::*;
use core::{cmp,mem,fmt};
use core::ops::Deref;
#[cfg(any(test, fuzzing, debug_assertions))]
use crate::sync::Mutex;
use bitcoin::hashes::hex::ToHex;

#[cfg(test)]
pub struct ChannelValueStat {
	pub value_to_self_msat: u64,
	pub channel_value_msat: u64,
	pub channel_reserve_msat: u64,
	pub pending_outbound_htlcs_amount_msat: u64,
	pub pending_inbound_htlcs_amount_msat: u64,
	pub holding_cell_outbound_amount_msat: u64,
	pub counterparty_max_htlc_value_in_flight_msat: u64, // outgoing
	pub counterparty_dust_limit_msat: u64,
}

pub struct AvailableBalances {
	/// The amount that would go to us if we close the channel, ignoring any on-chain fees.
	pub balance_msat: u64,
	/// Total amount available for our counterparty to send to us.
	pub inbound_capacity_msat: u64,
	/// Total amount available for us to send to our counterparty.
	pub outbound_capacity_msat: u64,
	/// The maximum value we can assign to the next outbound HTLC
	pub next_outbound_htlc_limit_msat: u64,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum FeeUpdateState {
	// Inbound states mirroring InboundHTLCState
	RemoteAnnounced,
	AwaitingRemoteRevokeToAnnounce,
	// Note that we do not have a AwaitingAnnouncedRemoteRevoke variant here as it is universally
	// handled the same as `Committed`, with the only exception in `InboundHTLCState` being the
	// distinction of when we allow ourselves to forward the HTLC. Because we aren't "forwarding"
	// the fee update anywhere, we can simply consider the fee update `Committed` immediately
	// instead of setting it to AwaitingAnnouncedRemoteRevoke.

	// Outbound state can only be `LocalAnnounced` or `Committed`
	Outbound,
}

enum InboundHTLCRemovalReason {
	FailRelay(msgs::OnionErrorPacket),
	FailMalformed(([u8; 32], u16)),
	Fulfill(PaymentPreimage),
}

enum InboundHTLCState {
	/// Offered by remote, to be included in next local commitment tx. I.e., the remote sent an
	/// update_add_htlc message for this HTLC.
	RemoteAnnounced(PendingHTLCStatus),
	/// Included in a received commitment_signed message (implying we've
	/// revoke_and_ack'd it), but the remote hasn't yet revoked their previous
	/// state (see the example below). We have not yet included this HTLC in a
	/// commitment_signed message because we are waiting on the remote's
	/// aforementioned state revocation. One reason this missing remote RAA
	/// (revoke_and_ack) blocks us from constructing a commitment_signed message
	/// is because every time we create a new "state", i.e. every time we sign a
	/// new commitment tx (see [BOLT #2]), we need a new per_commitment_point,
	/// which are provided one-at-a-time in each RAA. E.g., the last RAA they
	/// sent provided the per_commitment_point for our current commitment tx.
	/// The other reason we should not send a commitment_signed without their RAA
	/// is because their RAA serves to ACK our previous commitment_signed.
	///
	/// Here's an example of how an HTLC could come to be in this state:
	/// remote --> update_add_htlc(prev_htlc)   --> local
	/// remote --> commitment_signed(prev_htlc) --> local
	/// remote <-- revoke_and_ack               <-- local
	/// remote <-- commitment_signed(prev_htlc) <-- local
	/// [note that here, the remote does not respond with a RAA]
	/// remote --> update_add_htlc(this_htlc)   --> local
	/// remote --> commitment_signed(prev_htlc, this_htlc) --> local
	/// Now `this_htlc` will be assigned this state. It's unable to be officially
	/// accepted, i.e. included in a commitment_signed, because we're missing the
	/// RAA that provides our next per_commitment_point. The per_commitment_point
	/// is used to derive commitment keys, which are used to construct the
	/// signatures in a commitment_signed message.
	/// Implies AwaitingRemoteRevoke.
	///
	/// [BOLT #2]: https://github.com/lightning/bolts/blob/master/02-peer-protocol.md
	AwaitingRemoteRevokeToAnnounce(PendingHTLCStatus),
	/// Included in a received commitment_signed message (implying we've revoke_and_ack'd it).
	/// We have also included this HTLC in our latest commitment_signed and are now just waiting
	/// on the remote's revoke_and_ack to make this HTLC an irrevocable part of the state of the
	/// channel (before it can then get forwarded and/or removed).
	/// Implies AwaitingRemoteRevoke.
	AwaitingAnnouncedRemoteRevoke(PendingHTLCStatus),
	Committed,
	/// Removed by us and a new commitment_signed was sent (if we were AwaitingRemoteRevoke when we
	/// created it we would have put it in the holding cell instead). When they next revoke_and_ack
	/// we'll drop it.
	/// Note that we have to keep an eye on the HTLC until we've received a broadcastable
	/// commitment transaction without it as otherwise we'll have to force-close the channel to
	/// claim it before the timeout (obviously doesn't apply to revoked HTLCs that we can't claim
	/// anyway). That said, ChannelMonitor does this for us (see
	/// ChannelMonitor::should_broadcast_holder_commitment_txn) so we actually remove the HTLC from
	/// our own local state before then, once we're sure that the next commitment_signed and
	/// ChannelMonitor::provide_latest_local_commitment_tx will not include this HTLC.
	LocalRemoved(InboundHTLCRemovalReason),
}

struct InboundHTLCOutput {
	htlc_id: u64,
	amount_msat: u64,
	cltv_expiry: u32,
	payment_hash: PaymentHash,
	state: InboundHTLCState,
}

enum OutboundHTLCState {
	/// Added by us and included in a commitment_signed (if we were AwaitingRemoteRevoke when we
	/// created it we would have put it in the holding cell instead). When they next revoke_and_ack
	/// we will promote to Committed (note that they may not accept it until the next time we
	/// revoke, but we don't really care about that:
	///  * they've revoked, so worst case we can announce an old state and get our (option on)
	///    money back (though we won't), and,
	///  * we'll send them a revoke when they send a commitment_signed, and since only they're
	///    allowed to remove it, the "can only be removed once committed on both sides" requirement
	///    doesn't matter to us and it's up to them to enforce it, worst-case they jump ahead but
	///    we'll never get out of sync).
	/// Note that we Box the OnionPacket as it's rather large and we don't want to blow up
	/// OutboundHTLCOutput's size just for a temporary bit
	LocalAnnounced(Box<msgs::OnionPacket>),
	Committed,
	/// Remote removed this (outbound) HTLC. We're waiting on their commitment_signed to finalize
	/// the change (though they'll need to revoke before we fail the payment).
	RemoteRemoved(OutboundHTLCOutcome),
	/// Remote removed this and sent a commitment_signed (implying we've revoke_and_ack'ed it), but
	/// the remote side hasn't yet revoked their previous state, which we need them to do before we
	/// can do any backwards failing. Implies AwaitingRemoteRevoke.
	/// We also have not yet removed this HTLC in a commitment_signed message, and are waiting on a
	/// remote revoke_and_ack on a previous state before we can do so.
	AwaitingRemoteRevokeToRemove(OutboundHTLCOutcome),
	/// Remote removed this and sent a commitment_signed (implying we've revoke_and_ack'ed it), but
	/// the remote side hasn't yet revoked their previous state, which we need them to do before we
	/// can do any backwards failing. Implies AwaitingRemoteRevoke.
	/// We have removed this HTLC in our latest commitment_signed and are now just waiting on a
	/// revoke_and_ack to drop completely.
	AwaitingRemovedRemoteRevoke(OutboundHTLCOutcome),
}

#[derive(Clone)]
enum OutboundHTLCOutcome {
	/// LDK version 0.0.105+ will always fill in the preimage here.
	Success(Option<PaymentPreimage>),
	Failure(HTLCFailReason),
}

impl From<Option<HTLCFailReason>> for OutboundHTLCOutcome {
	fn from(o: Option<HTLCFailReason>) -> Self {
		match o {
			None => OutboundHTLCOutcome::Success(None),
			Some(r) => OutboundHTLCOutcome::Failure(r)
		}
	}
}

impl<'a> Into<Option<&'a HTLCFailReason>> for &'a OutboundHTLCOutcome {
	fn into(self) -> Option<&'a HTLCFailReason> {
		match self {
			OutboundHTLCOutcome::Success(_) => None,
			OutboundHTLCOutcome::Failure(ref r) => Some(r)
		}
	}
}

struct OutboundHTLCOutput {
	htlc_id: u64,
	amount_msat: u64,
	cltv_expiry: u32,
	payment_hash: PaymentHash,
	state: OutboundHTLCState,
	source: HTLCSource,
}

/// See AwaitingRemoteRevoke ChannelState for more info
enum HTLCUpdateAwaitingACK {
	AddHTLC { // TODO: Time out if we're getting close to cltv_expiry
		// always outbound
		amount_msat: u64,
		cltv_expiry: u32,
		payment_hash: PaymentHash,
		source: HTLCSource,
		onion_routing_packet: msgs::OnionPacket,
	},
	ClaimHTLC {
		payment_preimage: PaymentPreimage,
		htlc_id: u64,
	},
	FailHTLC {
		htlc_id: u64,
		err_packet: msgs::OnionErrorPacket,
	},
}

/// There are a few "states" and then a number of flags which can be applied:
/// We first move through init with OurInitSent -> TheirInitSent -> FundingCreated -> FundingSent.
/// TheirChannelReady and OurChannelReady then get set on FundingSent, and when both are set we
/// move on to ChannelReady.
/// Note that PeerDisconnected can be set on both ChannelReady and FundingSent.
/// ChannelReady can then get all remaining flags set on it, until we finish shutdown, then we
/// move on to ShutdownComplete, at which point most calls into this channel are disallowed.
enum ChannelState {
	/// Implies we have (or are prepared to) send our open_channel/accept_channel message
	OurInitSent = 1 << 0,
	/// Implies we have received their open_channel/accept_channel message
	TheirInitSent = 1 << 1,
	/// We have sent funding_created and are awaiting a funding_signed to advance to FundingSent.
	/// Note that this is nonsense for an inbound channel as we immediately generate funding_signed
	/// upon receipt of funding_created, so simply skip this state.
	FundingCreated = 4,
	/// Set when we have received/sent funding_created and funding_signed and are thus now waiting
	/// on the funding transaction to confirm. The ChannelReady flags are set to indicate when we
	/// and our counterparty consider the funding transaction confirmed.
	FundingSent = 8,
	/// Flag which can be set on FundingSent to indicate they sent us a channel_ready message.
	/// Once both TheirChannelReady and OurChannelReady are set, state moves on to ChannelReady.
	TheirChannelReady = 1 << 4,
	/// Flag which can be set on FundingSent to indicate we sent them a channel_ready message.
	/// Once both TheirChannelReady and OurChannelReady are set, state moves on to ChannelReady.
	OurChannelReady = 1 << 5,
	ChannelReady = 64,
	/// Flag which is set on ChannelReady and FundingSent indicating remote side is considered
	/// "disconnected" and no updates are allowed until after we've done a channel_reestablish
	/// dance.
	PeerDisconnected = 1 << 7,
	/// Flag which is set on ChannelReady, FundingCreated, and FundingSent indicating the user has
	/// told us a ChannelMonitor update is pending async persistence somewhere and we should pause
	/// sending any outbound messages until they've managed to finish.
	MonitorUpdateInProgress = 1 << 8,
	/// Flag which implies that we have sent a commitment_signed but are awaiting the responding
	/// revoke_and_ack message. During this time period, we can't generate new commitment_signed
	/// messages as then we will be unable to determine which HTLCs they included in their
	/// revoke_and_ack implicit ACK, so instead we have to hold them away temporarily to be sent
	/// later.
	/// Flag is set on ChannelReady.
	AwaitingRemoteRevoke = 1 << 9,
	/// Flag which is set on ChannelReady or FundingSent after receiving a shutdown message from
	/// the remote end. If set, they may not add any new HTLCs to the channel, and we are expected
	/// to respond with our own shutdown message when possible.
	RemoteShutdownSent = 1 << 10,
	/// Flag which is set on ChannelReady or FundingSent after sending a shutdown message. At this
	/// point, we may not add any new HTLCs to the channel.
	LocalShutdownSent = 1 << 11,
	/// We've successfully negotiated a closing_signed dance. At this point ChannelManager is about
	/// to drop us, but we store this anyway.
	ShutdownComplete = 4096,
}
const BOTH_SIDES_SHUTDOWN_MASK: u32 = ChannelState::LocalShutdownSent as u32 | ChannelState::RemoteShutdownSent as u32;
const MULTI_STATE_FLAGS: u32 = BOTH_SIDES_SHUTDOWN_MASK | ChannelState::PeerDisconnected as u32 | ChannelState::MonitorUpdateInProgress as u32;

pub const INITIAL_COMMITMENT_NUMBER: u64 = (1 << 48) - 1;

/// The "channel disabled" bit in channel_update must be set based on whether we are connected to
/// our counterparty or not. However, we don't want to announce updates right away to avoid
/// spamming the network with updates if the connection is flapping. Instead, we "stage" updates to
/// our channel_update message and track the current state here.
/// See implementation at [`super::channelmanager::ChannelManager::timer_tick_occurred`].
#[derive(Clone, Copy, PartialEq)]
pub(super) enum ChannelUpdateStatus {
	/// We've announced the channel as enabled and are connected to our peer.
	Enabled,
	/// Our channel is no longer live, but we haven't announced the channel as disabled yet.
	DisabledStaged,
	/// Our channel is live again, but we haven't announced the channel as enabled yet.
	EnabledStaged,
	/// We've announced the channel as disabled.
	Disabled,
}

/// We track when we sent an `AnnouncementSignatures` to our peer in a few states, described here.
#[derive(PartialEq)]
pub enum AnnouncementSigsState {
	/// We have not sent our peer an `AnnouncementSignatures` yet, or our peer disconnected since
	/// we sent the last `AnnouncementSignatures`.
	NotSent,
	/// We sent an `AnnouncementSignatures` to our peer since the last time our peer disconnected.
	/// This state never appears on disk - instead we write `NotSent`.
	MessageSent,
	/// We sent a `CommitmentSigned` after the last `AnnouncementSignatures` we sent. Because we
	/// only ever have a single `CommitmentSigned` pending at once, if we sent one after sending
	/// `AnnouncementSignatures` then we know the peer received our `AnnouncementSignatures` if
	/// they send back a `RevokeAndACK`.
	/// This state never appears on disk - instead we write `NotSent`.
	Committed,
	/// We received a `RevokeAndACK`, effectively ack-ing our `AnnouncementSignatures`, at this
	/// point we no longer need to re-send our `AnnouncementSignatures` again on reconnect.
	PeerReceived,
}

/// An enum indicating whether the local or remote side offered a given HTLC.
enum HTLCInitiator {
	LocalOffered,
	RemoteOffered,
}

/// An enum gathering stats on pending HTLCs, either inbound or outbound side.
struct HTLCStats {
	pending_htlcs: u32,
	pending_htlcs_value_msat: u64,
	on_counterparty_tx_dust_exposure_msat: u64,
	on_holder_tx_dust_exposure_msat: u64,
	holding_cell_msat: u64,
	on_holder_tx_holding_cell_htlcs_count: u32, // dust HTLCs *non*-included
}

/// An enum gathering stats on commitment transaction, either local or remote.
struct CommitmentStats<'a> {
	tx: CommitmentTransaction, // the transaction info
	feerate_per_kw: u32, // the feerate included to build the transaction
	total_fee_sat: u64, // the total fee included in the transaction
	num_nondust_htlcs: usize,  // the number of HTLC outputs (dust HTLCs *non*-included)
	htlcs_included: Vec<(HTLCOutputInCommitment, Option<&'a HTLCSource>)>, // the list of HTLCs (dust HTLCs *included*) which were not ignored when building the transaction
	local_balance_msat: u64, // local balance before fees but considering dust limits
	remote_balance_msat: u64, // remote balance before fees but considering dust limits
	preimages: Vec<PaymentPreimage>, // preimages for successful offered HTLCs since last commitment
}

/// Used when calculating whether we or the remote can afford an additional HTLC.
struct HTLCCandidate {
	amount_msat: u64,
	origin: HTLCInitiator,
}

impl HTLCCandidate {
	fn new(amount_msat: u64, origin: HTLCInitiator) -> Self {
		Self {
			amount_msat,
			origin,
		}
	}
}

/// A return value enum for get_update_fulfill_htlc. See UpdateFulfillCommitFetch variants for
/// description
enum UpdateFulfillFetch {
	NewClaim {
		monitor_update: ChannelMonitorUpdate,
		htlc_value_msat: u64,
		msg: Option<msgs::UpdateFulfillHTLC>,
	},
	DuplicateClaim {},
}

/// The return type of get_update_fulfill_htlc_and_commit.
pub enum UpdateFulfillCommitFetch<'a> {
	/// Indicates the HTLC fulfill is new, and either generated an update_fulfill message, placed
	/// it in the holding cell, or re-generated the update_fulfill message after the same claim was
	/// previously placed in the holding cell (and has since been removed).
	NewClaim {
		/// The ChannelMonitorUpdate which places the new payment preimage in the channel monitor
		monitor_update: &'a ChannelMonitorUpdate,
		/// The value of the HTLC which was claimed, in msat.
		htlc_value_msat: u64,
	},
	/// Indicates the HTLC fulfill is duplicative and already existed either in the holding cell
	/// or has been forgotten (presumably previously claimed).
	DuplicateClaim {},
}

/// The return value of `monitor_updating_restored`
pub(super) struct MonitorRestoreUpdates {
	pub raa: Option<msgs::RevokeAndACK>,
	pub commitment_update: Option<msgs::CommitmentUpdate>,
	pub order: RAACommitmentOrder,
	pub accepted_htlcs: Vec<(PendingHTLCInfo, u64)>,
	pub failed_htlcs: Vec<(HTLCSource, PaymentHash, HTLCFailReason)>,
	pub finalized_claimed_htlcs: Vec<HTLCSource>,
	pub funding_broadcastable: Option<Transaction>,
	pub channel_ready: Option<msgs::ChannelReady>,
	pub announcement_sigs: Option<msgs::AnnouncementSignatures>,
}

/// The return value of `channel_reestablish`
pub(super) struct ReestablishResponses {
	pub channel_ready: Option<msgs::ChannelReady>,
	pub raa: Option<msgs::RevokeAndACK>,
	pub commitment_update: Option<msgs::CommitmentUpdate>,
	pub order: RAACommitmentOrder,
	pub announcement_sigs: Option<msgs::AnnouncementSignatures>,
	pub shutdown_msg: Option<msgs::Shutdown>,
}

/// If the majority of the channels funds are to the fundee and the initiator holds only just
/// enough funds to cover their reserve value, channels are at risk of getting "stuck". Because the
/// initiator controls the feerate, if they then go to increase the channel fee, they may have no
/// balance but the fundee is unable to send a payment as the increase in fee more than drains
/// their reserve value. Thus, neither side can send a new HTLC and the channel becomes useless.
/// Thus, before sending an HTLC when we are the initiator, we check that the feerate can increase
/// by this multiple without hitting this case, before sending.
/// This multiple is effectively the maximum feerate "jump" we expect until more HTLCs flow over
/// the channel. Sadly, there isn't really a good number for this - if we expect to have no new
/// HTLCs for days we may need this to suffice for feerate increases across days, but that may
/// leave the channel less usable as we hold a bigger reserve.
#[cfg(any(fuzzing, test))]
pub const FEE_SPIKE_BUFFER_FEE_INCREASE_MULTIPLE: u64 = 2;
#[cfg(not(any(fuzzing, test)))]
const FEE_SPIKE_BUFFER_FEE_INCREASE_MULTIPLE: u64 = 2;

/// If we fail to see a funding transaction confirmed on-chain within this many blocks after the
/// channel creation on an inbound channel, we simply force-close and move on.
/// This constant is the one suggested in BOLT 2.
pub(crate) const FUNDING_CONF_DEADLINE_BLOCKS: u32 = 2016;

/// In case of a concurrent update_add_htlc proposed by our counterparty, we might
/// not have enough balance value remaining to cover the onchain cost of this new
/// HTLC weight. If this happens, our counterparty fails the reception of our
/// commitment_signed including this new HTLC due to infringement on the channel
/// reserve.
/// To prevent this case, we compute our outbound update_fee with an HTLC buffer of
/// size 2. However, if the number of concurrent update_add_htlc is higher, this still
/// leads to a channel force-close. Ultimately, this is an issue coming from the
/// design of LN state machines, allowing asynchronous updates.
pub(crate) const CONCURRENT_INBOUND_HTLC_FEE_BUFFER: u32 = 2;

/// When a channel is opened, we check that the funding amount is enough to pay for relevant
/// commitment transaction fees, with at least this many HTLCs present on the commitment
/// transaction (not counting the value of the HTLCs themselves).
pub(crate) const MIN_AFFORDABLE_HTLC_COUNT: usize = 4;

/// When a [`Channel`] has its [`ChannelConfig`] updated, its existing one is stashed for up to this
/// number of ticks to allow forwarding HTLCs by nodes that have yet to receive the new
/// ChannelUpdate prompted by the config update. This value was determined as follows:
///
///   * The expected interval between ticks (1 minute).
///   * The average convergence delay of updates across the network, i.e., ~300 seconds on average
///      for a node to see an update as seen on `<https://arxiv.org/pdf/2205.12737.pdf>`.
///   * `EXPIRE_PREV_CONFIG_TICKS` = convergence_delay / tick_interval
pub(crate) const EXPIRE_PREV_CONFIG_TICKS: usize = 5;

// TODO: We should refactor this to be an Inbound/OutboundChannel until initial setup handshaking
// has been completed, and then turn into a Channel to get compiler-time enforcement of things like
// calling channel_id() before we're set up or things like get_outbound_funding_signed on an
// inbound channel.
//
// Holder designates channel data owned for the benefice of the user client.
// Counterparty designates channel data owned by the another channel participant entity.
pub(super) struct Channel<Signer: ChannelSigner> {
	config: LegacyChannelConfig,

	// Track the previous `ChannelConfig` so that we can continue forwarding HTLCs that were
	// constructed using it. The second element in the tuple corresponds to the number of ticks that
	// have elapsed since the update occurred.
	prev_config: Option<(ChannelConfig, usize)>,

	inbound_handshake_limits_override: Option<ChannelHandshakeLimits>,

	user_id: u128,

	channel_id: [u8; 32],
	channel_state: u32,

	// When we reach max(6 blocks, minimum_depth), we need to send an AnnouncementSigs message to
	// our peer. However, we want to make sure they received it, or else rebroadcast it when we
	// next connect.
	// We do so here, see `AnnouncementSigsSent` for more details on the state(s).
	// Note that a number of our tests were written prior to the behavior here which retransmits
	// AnnouncementSignatures until after an RAA completes, so the behavior is short-circuited in
	// many tests.
	#[cfg(any(test, feature = "_test_utils"))]
	pub(crate) announcement_sigs_state: AnnouncementSigsState,
	#[cfg(not(any(test, feature = "_test_utils")))]
	announcement_sigs_state: AnnouncementSigsState,

	secp_ctx: Secp256k1<secp256k1::All>,
	channel_value_satoshis: u64,

	latest_monitor_update_id: u64,

	holder_signer: Signer,
	shutdown_scriptpubkey: Option<ShutdownScript>,
	destination_script: Script,

	// Our commitment numbers start at 2^48-1 and count down, whereas the ones used in transaction
	// generation start at 0 and count up...this simplifies some parts of implementation at the
	// cost of others, but should really just be changed.

	cur_holder_commitment_transaction_number: u64,
	cur_counterparty_commitment_transaction_number: u64,
	value_to_self_msat: u64, // Excluding all pending_htlcs, excluding fees
	pending_inbound_htlcs: Vec<InboundHTLCOutput>,
	pending_outbound_htlcs: Vec<OutboundHTLCOutput>,
	holding_cell_htlc_updates: Vec<HTLCUpdateAwaitingACK>,

	/// When resending CS/RAA messages on channel monitor restoration or on reconnect, we always
	/// need to ensure we resend them in the order we originally generated them. Note that because
	/// there can only ever be one in-flight CS and/or one in-flight RAA at any time, it is
	/// sufficient to simply set this to the opposite of any message we are generating as we
	/// generate it. ie when we generate a CS, we set this to RAAFirst as, if there is a pending
	/// in-flight RAA to resend, it will have been the first thing we generated, and thus we should
	/// send it first.
	resend_order: RAACommitmentOrder,

	monitor_pending_channel_ready: bool,
	monitor_pending_revoke_and_ack: bool,
	monitor_pending_commitment_signed: bool,

	// TODO: If a channel is drop'd, we don't know whether the `ChannelMonitor` is ultimately
	// responsible for some of the HTLCs here or not - we don't know whether the update in question
	// completed or not. We currently ignore these fields entirely when force-closing a channel,
	// but need to handle this somehow or we run the risk of losing HTLCs!
	monitor_pending_forwards: Vec<(PendingHTLCInfo, u64)>,
	monitor_pending_failures: Vec<(HTLCSource, PaymentHash, HTLCFailReason)>,
	monitor_pending_finalized_fulfills: Vec<HTLCSource>,

	// pending_update_fee is filled when sending and receiving update_fee.
	//
	// Because it follows the same commitment flow as HTLCs, `FeeUpdateState` is either `Outbound`
	// or matches a subset of the `InboundHTLCOutput` variants. It is then updated/used when
	// generating new commitment transactions with exactly the same criteria as inbound/outbound
	// HTLCs with similar state.
	pending_update_fee: Option<(u32, FeeUpdateState)>,
	// If a `send_update_fee()` call is made with ChannelState::AwaitingRemoteRevoke set, we place
	// it here instead of `pending_update_fee` in the same way as we place outbound HTLC updates in
	// `holding_cell_htlc_updates` instead of `pending_outbound_htlcs`. It is released into
	// `pending_update_fee` with the same criteria as outbound HTLC updates but can be updated by
	// further `send_update_fee` calls, dropping the previous holding cell update entirely.
	holding_cell_update_fee: Option<u32>,
	next_holder_htlc_id: u64,
	next_counterparty_htlc_id: u64,
	feerate_per_kw: u32,

	/// The timestamp set on our latest `channel_update` message for this channel. It is updated
	/// when the channel is updated in ways which may impact the `channel_update` message or when a
	/// new block is received, ensuring it's always at least moderately close to the current real
	/// time.
	update_time_counter: u32,

	#[cfg(debug_assertions)]
	/// Max to_local and to_remote outputs in a locally-generated commitment transaction
	holder_max_commitment_tx_output: Mutex<(u64, u64)>,
	#[cfg(debug_assertions)]
	/// Max to_local and to_remote outputs in a remote-generated commitment transaction
	counterparty_max_commitment_tx_output: Mutex<(u64, u64)>,

	last_sent_closing_fee: Option<(u64, Signature)>, // (fee, holder_sig)
	target_closing_feerate_sats_per_kw: Option<u32>,

	/// If our counterparty sent us a closing_signed while we were waiting for a `ChannelMonitor`
	/// update, we need to delay processing it until later. We do that here by simply storing the
	/// closing_signed message and handling it in `maybe_propose_closing_signed`.
	pending_counterparty_closing_signed: Option<msgs::ClosingSigned>,

	/// The minimum and maximum absolute fee, in satoshis, we are willing to place on the closing
	/// transaction. These are set once we reach `closing_negotiation_ready`.
	#[cfg(test)]
	pub(crate) closing_fee_limits: Option<(u64, u64)>,
	#[cfg(not(test))]
	closing_fee_limits: Option<(u64, u64)>,

	/// Flag that ensures that `accept_inbound_channel` must be called before `funding_created`
	/// is executed successfully. The reason for this flag is that when the
	/// `UserConfig::manually_accept_inbound_channels` config flag is set to true, inbound channels
	/// are required to be manually accepted by the node operator before the `msgs::AcceptChannel`
	/// message is created and sent out. During the manual accept process, `accept_inbound_channel`
	/// is called by `ChannelManager::accept_inbound_channel`.
	///
	/// The flag counteracts that a counterparty node could theoretically send a
	/// `msgs::FundingCreated` message before the node operator has manually accepted an inbound
	/// channel request made by the counterparty node. That would execute `funding_created` before
	/// `accept_inbound_channel`, and `funding_created` should therefore not execute successfully.
	inbound_awaiting_accept: bool,

	/// The hash of the block in which the funding transaction was included.
	funding_tx_confirmed_in: Option<BlockHash>,
	funding_tx_confirmation_height: u32,
	short_channel_id: Option<u64>,
	/// Either the height at which this channel was created or the height at which it was last
	/// serialized if it was serialized by versions prior to 0.0.103.
	/// We use this to close if funding is never broadcasted.
	channel_creation_height: u32,

	counterparty_dust_limit_satoshis: u64,

	#[cfg(test)]
	pub(super) holder_dust_limit_satoshis: u64,
	#[cfg(not(test))]
	holder_dust_limit_satoshis: u64,

	#[cfg(test)]
	pub(super) counterparty_max_htlc_value_in_flight_msat: u64,
	#[cfg(not(test))]
	counterparty_max_htlc_value_in_flight_msat: u64,

	#[cfg(test)]
	pub(super) holder_max_htlc_value_in_flight_msat: u64,
	#[cfg(not(test))]
	holder_max_htlc_value_in_flight_msat: u64,

	/// minimum channel reserve for self to maintain - set by them.
	counterparty_selected_channel_reserve_satoshis: Option<u64>,

	#[cfg(test)]
	pub(super) holder_selected_channel_reserve_satoshis: u64,
	#[cfg(not(test))]
	holder_selected_channel_reserve_satoshis: u64,

	counterparty_htlc_minimum_msat: u64,
	holder_htlc_minimum_msat: u64,
	#[cfg(test)]
	pub counterparty_max_accepted_htlcs: u16,
	#[cfg(not(test))]
	counterparty_max_accepted_htlcs: u16,
	//implied by OUR_MAX_HTLCS: max_accepted_htlcs: u16,
	minimum_depth: Option<u32>,

	counterparty_forwarding_info: Option<CounterpartyForwardingInfo>,

	pub(crate) channel_transaction_parameters: ChannelTransactionParameters,
	funding_transaction: Option<Transaction>,

	counterparty_cur_commitment_point: Option<PublicKey>,
	counterparty_prev_commitment_point: Option<PublicKey>,
	counterparty_node_id: PublicKey,

	counterparty_shutdown_scriptpubkey: Option<Script>,

	commitment_secrets: CounterpartyCommitmentSecrets,

	channel_update_status: ChannelUpdateStatus,
	/// Once we reach `closing_negotiation_ready`, we set this, indicating if closing_signed does
	/// not complete within a single timer tick (one minute), we should force-close the channel.
	/// This prevents us from keeping unusable channels around forever if our counterparty wishes
	/// to DoS us.
	/// Note that this field is reset to false on deserialization to give us a chance to connect to
	/// our peer and start the closing_signed negotiation fresh.
	closing_signed_in_flight: bool,

	/// Our counterparty's channel_announcement signatures provided in announcement_signatures.
	/// This can be used to rebroadcast the channel_announcement message later.
	announcement_sigs: Option<(Signature, Signature)>,

	// We save these values so we can make sure `next_local_commit_tx_fee_msat` and
	// `next_remote_commit_tx_fee_msat` properly predict what the next commitment transaction fee will
	// be, by comparing the cached values to the fee of the tranaction generated by
	// `build_commitment_transaction`.
	#[cfg(any(test, fuzzing))]
	next_local_commitment_tx_fee_info_cached: Mutex<Option<CommitmentTxInfoCached>>,
	#[cfg(any(test, fuzzing))]
	next_remote_commitment_tx_fee_info_cached: Mutex<Option<CommitmentTxInfoCached>>,

	/// lnd has a long-standing bug where, upon reconnection, if the channel is not yet confirmed
	/// they will not send a channel_reestablish until the channel locks in. Then, they will send a
	/// channel_ready *before* sending the channel_reestablish (which is clearly a violation of
	/// the BOLT specs). We copy c-lightning's workaround here and simply store the channel_ready
	/// message until we receive a channel_reestablish.
	///
	/// See-also <https://github.com/lightningnetwork/lnd/issues/4006>
	pub workaround_lnd_bug_4006: Option<msgs::ChannelReady>,

	#[cfg(any(test, fuzzing))]
	// When we receive an HTLC fulfill on an outbound path, we may immediately fulfill the
	// corresponding HTLC on the inbound path. If, then, the outbound path channel is
	// disconnected and reconnected (before we've exchange commitment_signed and revoke_and_ack
	// messages), they may re-broadcast their update_fulfill_htlc, causing a duplicate claim. This
	// is fine, but as a sanity check in our failure to generate the second claim, we check here
	// that the original was a claim, and that we aren't now trying to fulfill a failed HTLC.
	historical_inbound_htlc_fulfills: HashSet<u64>,

	/// This channel's type, as negotiated during channel open
	channel_type: ChannelTypeFeatures,

	// Our counterparty can offer us SCID aliases which they will map to this channel when routing
	// outbound payments. These can be used in invoice route hints to avoid explicitly revealing
	// the channel's funding UTXO.
	//
	// We also use this when sending our peer a channel_update that isn't to be broadcasted
	// publicly - allowing them to re-use their map of SCID -> channel for channel_update ->
	// associated channel mapping.
	//
	// We only bother storing the most recent SCID alias at any time, though our counterparty has
	// to store all of them.
	latest_inbound_scid_alias: Option<u64>,

	// We always offer our counterparty a static SCID alias, which we recognize as for this channel
	// if we see it in HTLC forwarding instructions. We don't bother rotating the alias given we
	// don't currently support node id aliases and eventually privacy should be provided with
	// blinded paths instead of simple scid+node_id aliases.
	outbound_scid_alias: u64,

	// We track whether we already emitted a `ChannelReady` event.
	channel_ready_event_emitted: bool,

	/// The unique identifier used to re-derive the private key material for the channel through
	/// [`SignerProvider::derive_channel_signer`].
	channel_keys_id: [u8; 32],

	/// When we generate [`ChannelMonitorUpdate`]s to persist, they may not be persisted immediately.
	/// If we then persist the [`channelmanager::ChannelManager`] and crash before the persistence
	/// completes we still need to be able to complete the persistence. Thus, we have to keep a
	/// copy of the [`ChannelMonitorUpdate`] here until it is complete.
	pending_monitor_updates: Vec<ChannelMonitorUpdate>,
}

#[cfg(any(test, fuzzing))]
struct CommitmentTxInfoCached {
	fee: u64,
	total_pending_htlcs: usize,
	next_holder_htlc_id: u64,
	next_counterparty_htlc_id: u64,
	feerate: u32,
}

pub const OUR_MAX_HTLCS: u16 = 50; //TODO

pub(crate) fn commitment_tx_base_weight(opt_anchors: bool) -> u64 {
	const COMMITMENT_TX_BASE_WEIGHT: u64 = 724;
	const COMMITMENT_TX_BASE_ANCHOR_WEIGHT: u64 = 1124;
	if opt_anchors { COMMITMENT_TX_BASE_ANCHOR_WEIGHT } else { COMMITMENT_TX_BASE_WEIGHT }
}

#[cfg(not(test))]
const COMMITMENT_TX_WEIGHT_PER_HTLC: u64 = 172;
#[cfg(test)]
pub const COMMITMENT_TX_WEIGHT_PER_HTLC: u64 = 172;

pub const ANCHOR_OUTPUT_VALUE_SATOSHI: u64 = 330;

/// The percentage of the channel value `holder_max_htlc_value_in_flight_msat` used to be set to,
/// before this was made configurable. The percentage was made configurable in LDK 0.0.107,
/// although LDK 0.0.104+ enabled serialization of channels with a different value set for
/// `holder_max_htlc_value_in_flight_msat`.
pub const MAX_IN_FLIGHT_PERCENT_LEGACY: u8 = 10;

/// Maximum `funding_satoshis` value according to the BOLT #2 specification, if
/// `option_support_large_channel` (aka wumbo channels) is not supported.
/// It's 2^24 - 1.
pub const MAX_FUNDING_SATOSHIS_NO_WUMBO: u64 = (1 << 24) - 1;

/// Total bitcoin supply in satoshis.
pub const TOTAL_BITCOIN_SUPPLY_SATOSHIS: u64 = 21_000_000 * 1_0000_0000;

/// The maximum network dust limit for standard script formats. This currently represents the
/// minimum output value for a P2SH output before Bitcoin Core 22 considers the entire
/// transaction non-standard and thus refuses to relay it.
/// We also use this as the maximum counterparty `dust_limit_satoshis` allowed, given many
/// implementations use this value for their dust limit today.
pub const MAX_STD_OUTPUT_DUST_LIMIT_SATOSHIS: u64 = 546;

/// The maximum channel dust limit we will accept from our counterparty.
pub const MAX_CHAN_DUST_LIMIT_SATOSHIS: u64 = MAX_STD_OUTPUT_DUST_LIMIT_SATOSHIS;

/// The dust limit is used for both the commitment transaction outputs as well as the closing
/// transactions. For cooperative closing transactions, we require segwit outputs, though accept
/// *any* segwit scripts, which are allowed to be up to 42 bytes in length.
/// In order to avoid having to concern ourselves with standardness during the closing process, we
/// simply require our counterparty to use a dust limit which will leave any segwit output
/// standard.
/// See <https://github.com/lightning/bolts/issues/905> for more details.
pub const MIN_CHAN_DUST_LIMIT_SATOSHIS: u64 = 354;

// Just a reasonable implementation-specific safe lower bound, higher than the dust limit.
pub const MIN_THEIR_CHAN_RESERVE_SATOSHIS: u64 = 1000;

/// Used to return a simple Error back to ChannelManager. Will get converted to a
/// msgs::ErrorAction::SendErrorMessage or msgs::ErrorAction::IgnoreError as appropriate with our
/// channel_id in ChannelManager.
pub(super) enum ChannelError {
	Ignore(String),
	Warn(String),
	Close(String),
}

impl fmt::Debug for ChannelError {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self {
			&ChannelError::Ignore(ref e) => write!(f, "Ignore : {}", e),
			&ChannelError::Warn(ref e) => write!(f, "Warn : {}", e),
			&ChannelError::Close(ref e) => write!(f, "Close : {}", e),
		}
	}
}

macro_rules! secp_check {
	($res: expr, $err: expr) => {
		match $res {
			Ok(thing) => thing,
			Err(_) => return Err(ChannelError::Close($err)),
		}
	};
}

impl<Signer: WriteableEcdsaChannelSigner> Channel<Signer> {
	/// Returns the value to use for `holder_max_htlc_value_in_flight_msat` as a percentage of the
	/// `channel_value_satoshis` in msat, set through
	/// [`ChannelHandshakeConfig::max_inbound_htlc_value_in_flight_percent_of_channel`]
	///
	/// The effective percentage is lower bounded by 1% and upper bounded by 100%.
	///
	/// [`ChannelHandshakeConfig::max_inbound_htlc_value_in_flight_percent_of_channel`]: crate::util::config::ChannelHandshakeConfig::max_inbound_htlc_value_in_flight_percent_of_channel
	fn get_holder_max_htlc_value_in_flight_msat(channel_value_satoshis: u64, config: &ChannelHandshakeConfig) -> u64 {
		let configured_percent = if config.max_inbound_htlc_value_in_flight_percent_of_channel < 1 {
			1
		} else if config.max_inbound_htlc_value_in_flight_percent_of_channel > 100 {
			100
		} else {
			config.max_inbound_htlc_value_in_flight_percent_of_channel as u64
		};
		channel_value_satoshis * 10 * configured_percent
	}

	/// Returns a minimum channel reserve value the remote needs to maintain,
	/// required by us according to the configured or default
	/// [`ChannelHandshakeConfig::their_channel_reserve_proportional_millionths`]
	///
	/// Guaranteed to return a value no larger than channel_value_satoshis
	///
	/// This is used both for outbound and inbound channels and has lower bound
	/// of `MIN_THEIR_CHAN_RESERVE_SATOSHIS`.
	pub(crate) fn get_holder_selected_channel_reserve_satoshis(channel_value_satoshis: u64, config: &UserConfig) -> u64 {
		let calculated_reserve = channel_value_satoshis.saturating_mul(config.channel_handshake_config.their_channel_reserve_proportional_millionths as u64) / 1_000_000;
		cmp::min(channel_value_satoshis, cmp::max(calculated_reserve, MIN_THEIR_CHAN_RESERVE_SATOSHIS))
	}

	/// This is for legacy reasons, present for forward-compatibility.
	/// LDK versions older than 0.0.104 don't know how read/handle values other than default
	/// from storage. Hence, we use this function to not persist default values of
	/// `holder_selected_channel_reserve_satoshis` for channels into storage.
	pub(crate) fn get_legacy_default_holder_selected_channel_reserve_satoshis(channel_value_satoshis: u64) -> u64 {
		let (q, _) = channel_value_satoshis.overflowing_div(100);
		cmp::min(channel_value_satoshis, cmp::max(q, 1000))
	}

	pub(crate) fn opt_anchors(&self) -> bool {
		self.channel_transaction_parameters.opt_anchors.is_some()
	}

	fn get_initial_channel_type(config: &UserConfig, their_features: &InitFeatures) -> ChannelTypeFeatures {
		// The default channel type (ie the first one we try) depends on whether the channel is
		// public - if it is, we just go with `only_static_remotekey` as it's the only option
		// available. If it's private, we first try `scid_privacy` as it provides better privacy
		// with no other changes, and fall back to `only_static_remotekey`.
		let mut ret = ChannelTypeFeatures::only_static_remote_key();
		if !config.channel_handshake_config.announced_channel &&
			config.channel_handshake_config.negotiate_scid_privacy &&
			their_features.supports_scid_privacy() {
			ret.set_scid_privacy_required();
		}

		// Optionally, if the user would like to negotiate the `anchors_zero_fee_htlc_tx` option, we
		// set it now. If they don't understand it, we'll fall back to our default of
		// `only_static_remotekey`.
		#[cfg(anchors)]
		{ // Attributes are not allowed on if expressions on our current MSRV of 1.41.
			if config.channel_handshake_config.negotiate_anchors_zero_fee_htlc_tx &&
				their_features.supports_anchors_zero_fee_htlc_tx() {
				ret.set_anchors_zero_fee_htlc_tx_required();
			}
		}

		ret
	}

	/// If we receive an error message, it may only be a rejection of the channel type we tried,
	/// not of our ability to open any channel at all. Thus, on error, we should first call this
	/// and see if we get a new `OpenChannel` message, otherwise the channel is failed.
	pub(crate) fn maybe_handle_error_without_close(&mut self, chain_hash: BlockHash) -> Result<msgs::OpenChannel, ()> {
		if !self.is_outbound() || self.channel_state != ChannelState::OurInitSent as u32 { return Err(()); }
		if self.channel_type == ChannelTypeFeatures::only_static_remote_key() {
			// We've exhausted our options
			return Err(());
		}
		// We support opening a few different types of channels. Try removing our additional
		// features one by one until we've either arrived at our default or the counterparty has
		// accepted one.
		//
		// Due to the order below, we may not negotiate `option_anchors_zero_fee_htlc_tx` if the
		// counterparty doesn't support `option_scid_privacy`. Since `get_initial_channel_type`
		// checks whether the counterparty supports every feature, this would only happen if the
		// counterparty is advertising the feature, but rejecting channels proposing the feature for
		// whatever reason.
		if self.channel_type.supports_anchors_zero_fee_htlc_tx() {
			self.channel_type.clear_anchors_zero_fee_htlc_tx();
			assert!(self.channel_transaction_parameters.opt_non_zero_fee_anchors.is_none());
			self.channel_transaction_parameters.opt_anchors = None;
		} else if self.channel_type.supports_scid_privacy() {
			self.channel_type.clear_scid_privacy();
		} else {
			self.channel_type = ChannelTypeFeatures::only_static_remote_key();
		}
		Ok(self.get_open_channel(chain_hash))
	}

	// Constructors:
	pub fn new_outbound<ES: Deref, SP: Deref, F: Deref>(
		fee_estimator: &LowerBoundedFeeEstimator<F>, entropy_source: &ES, signer_provider: &SP, counterparty_node_id: PublicKey, their_features: &InitFeatures,
		channel_value_satoshis: u64, push_msat: u64, user_id: u128, config: &UserConfig, current_chain_height: u32,
		outbound_scid_alias: u64
	) -> Result<Channel<Signer>, APIError>
	where ES::Target: EntropySource,
	      SP::Target: SignerProvider<Signer = Signer>,
	      F::Target: FeeEstimator,
	{
		let holder_selected_contest_delay = config.channel_handshake_config.our_to_self_delay;
		let channel_keys_id = signer_provider.generate_channel_keys_id(false, channel_value_satoshis, user_id);
		let holder_signer = signer_provider.derive_channel_signer(channel_value_satoshis, channel_keys_id);
		let pubkeys = holder_signer.pubkeys().clone();

		if !their_features.supports_wumbo() && channel_value_satoshis > MAX_FUNDING_SATOSHIS_NO_WUMBO {
			return Err(APIError::APIMisuseError{err: format!("funding_value must not exceed {}, it was {}", MAX_FUNDING_SATOSHIS_NO_WUMBO, channel_value_satoshis)});
		}
		if channel_value_satoshis >= TOTAL_BITCOIN_SUPPLY_SATOSHIS {
			return Err(APIError::APIMisuseError{err: format!("funding_value must be smaller than the total bitcoin supply, it was {}", channel_value_satoshis)});
		}
		let channel_value_msat = channel_value_satoshis * 1000;
		if push_msat > channel_value_msat {
			return Err(APIError::APIMisuseError { err: format!("Push value ({}) was larger than channel_value ({})", push_msat, channel_value_msat) });
		}
		if holder_selected_contest_delay < BREAKDOWN_TIMEOUT {
			return Err(APIError::APIMisuseError {err: format!("Configured with an unreasonable our_to_self_delay ({}) putting user funds at risks", holder_selected_contest_delay)});
		}
		let holder_selected_channel_reserve_satoshis = Channel::<Signer>::get_holder_selected_channel_reserve_satoshis(channel_value_satoshis, config);
		if holder_selected_channel_reserve_satoshis < MIN_CHAN_DUST_LIMIT_SATOSHIS {
			// Protocol level safety check in place, although it should never happen because
			// of `MIN_THEIR_CHAN_RESERVE_SATOSHIS`
			return Err(APIError::APIMisuseError { err: format!("Holder selected channel  reserve below implemention limit dust_limit_satoshis {}", holder_selected_channel_reserve_satoshis) });
		}

		let channel_type = Self::get_initial_channel_type(&config, their_features);
		debug_assert!(channel_type.is_subset(&channelmanager::provided_channel_type_features(&config)));

		let feerate = fee_estimator.bounded_sat_per_1000_weight(ConfirmationTarget::Normal);

		let value_to_self_msat = channel_value_satoshis * 1000 - push_msat;
		let commitment_tx_fee = Self::commit_tx_fee_msat(feerate, MIN_AFFORDABLE_HTLC_COUNT, channel_type.requires_anchors_zero_fee_htlc_tx());
		if value_to_self_msat < commitment_tx_fee {
			return Err(APIError::APIMisuseError{ err: format!("Funding amount ({}) can't even pay fee for initial commitment transaction fee of {}.", value_to_self_msat / 1000, commitment_tx_fee / 1000) });
		}

		let mut secp_ctx = Secp256k1::new();
		secp_ctx.seeded_randomize(&entropy_source.get_secure_random_bytes());

		let shutdown_scriptpubkey = if config.channel_handshake_config.commit_upfront_shutdown_pubkey {
			Some(signer_provider.get_shutdown_scriptpubkey())
		} else { None };

		if let Some(shutdown_scriptpubkey) = &shutdown_scriptpubkey {
			if !shutdown_scriptpubkey.is_compatible(&their_features) {
				return Err(APIError::IncompatibleShutdownScript { script: shutdown_scriptpubkey.clone() });
			}
		}

		Ok(Channel {
			user_id,

			config: LegacyChannelConfig {
				options: config.channel_config.clone(),
				announced_channel: config.channel_handshake_config.announced_channel,
				commit_upfront_shutdown_pubkey: config.channel_handshake_config.commit_upfront_shutdown_pubkey,
			},

			prev_config: None,

			inbound_handshake_limits_override: Some(config.channel_handshake_limits.clone()),

			channel_id: entropy_source.get_secure_random_bytes(),
			channel_state: ChannelState::OurInitSent as u32,
			announcement_sigs_state: AnnouncementSigsState::NotSent,
			secp_ctx,
			channel_value_satoshis,

			latest_monitor_update_id: 0,

			holder_signer,
			shutdown_scriptpubkey,
			destination_script: signer_provider.get_destination_script(),

			cur_holder_commitment_transaction_number: INITIAL_COMMITMENT_NUMBER,
			cur_counterparty_commitment_transaction_number: INITIAL_COMMITMENT_NUMBER,
			value_to_self_msat,

			pending_inbound_htlcs: Vec::new(),
			pending_outbound_htlcs: Vec::new(),
			holding_cell_htlc_updates: Vec::new(),
			pending_update_fee: None,
			holding_cell_update_fee: None,
			next_holder_htlc_id: 0,
			next_counterparty_htlc_id: 0,
			update_time_counter: 1,

			resend_order: RAACommitmentOrder::CommitmentFirst,

			monitor_pending_channel_ready: false,
			monitor_pending_revoke_and_ack: false,
			monitor_pending_commitment_signed: false,
			monitor_pending_forwards: Vec::new(),
			monitor_pending_failures: Vec::new(),
			monitor_pending_finalized_fulfills: Vec::new(),

			#[cfg(debug_assertions)]
			holder_max_commitment_tx_output: Mutex::new((channel_value_satoshis * 1000 - push_msat, push_msat)),
			#[cfg(debug_assertions)]
			counterparty_max_commitment_tx_output: Mutex::new((channel_value_satoshis * 1000 - push_msat, push_msat)),

			last_sent_closing_fee: None,
			pending_counterparty_closing_signed: None,
			closing_fee_limits: None,
			target_closing_feerate_sats_per_kw: None,

			inbound_awaiting_accept: false,

			funding_tx_confirmed_in: None,
			funding_tx_confirmation_height: 0,
			short_channel_id: None,
			channel_creation_height: current_chain_height,

			feerate_per_kw: feerate,
			counterparty_dust_limit_satoshis: 0,
			holder_dust_limit_satoshis: MIN_CHAN_DUST_LIMIT_SATOSHIS,
			counterparty_max_htlc_value_in_flight_msat: 0,
			holder_max_htlc_value_in_flight_msat: Self::get_holder_max_htlc_value_in_flight_msat(channel_value_satoshis, &config.channel_handshake_config),
			counterparty_selected_channel_reserve_satoshis: None, // Filled in in accept_channel
			holder_selected_channel_reserve_satoshis,
			counterparty_htlc_minimum_msat: 0,
			holder_htlc_minimum_msat: if config.channel_handshake_config.our_htlc_minimum_msat == 0 { 1 } else { config.channel_handshake_config.our_htlc_minimum_msat },
			counterparty_max_accepted_htlcs: 0,
			minimum_depth: None, // Filled in in accept_channel

			counterparty_forwarding_info: None,

			channel_transaction_parameters: ChannelTransactionParameters {
				holder_pubkeys: pubkeys,
				holder_selected_contest_delay: config.channel_handshake_config.our_to_self_delay,
				is_outbound_from_holder: true,
				counterparty_parameters: None,
				funding_outpoint: None,
				opt_anchors: if channel_type.requires_anchors_zero_fee_htlc_tx() { Some(()) } else { None },
				opt_non_zero_fee_anchors: None
			},
			funding_transaction: None,

			counterparty_cur_commitment_point: None,
			counterparty_prev_commitment_point: None,
			counterparty_node_id,

			counterparty_shutdown_scriptpubkey: None,

			commitment_secrets: CounterpartyCommitmentSecrets::new(),

			channel_update_status: ChannelUpdateStatus::Enabled,
			closing_signed_in_flight: false,

			announcement_sigs: None,

			#[cfg(any(test, fuzzing))]
			next_local_commitment_tx_fee_info_cached: Mutex::new(None),
			#[cfg(any(test, fuzzing))]
			next_remote_commitment_tx_fee_info_cached: Mutex::new(None),

			workaround_lnd_bug_4006: None,

			latest_inbound_scid_alias: None,
			outbound_scid_alias,

			channel_ready_event_emitted: false,

			#[cfg(any(test, fuzzing))]
			historical_inbound_htlc_fulfills: HashSet::new(),

			channel_type,
			channel_keys_id,

			pending_monitor_updates: Vec::new(),
		})
	}

	fn check_remote_fee<F: Deref, L: Deref>(fee_estimator: &LowerBoundedFeeEstimator<F>,
		feerate_per_kw: u32, cur_feerate_per_kw: Option<u32>, logger: &L)
		-> Result<(), ChannelError> where F::Target: FeeEstimator, L::Target: Logger,
	{
		// We only bound the fee updates on the upper side to prevent completely absurd feerates,
		// always accepting up to 25 sat/vByte or 10x our fee estimator's "High Priority" fee.
		// We generally don't care too much if they set the feerate to something very high, but it
		// could result in the channel being useless due to everything being dust.
		let upper_limit = cmp::max(250 * 25,
			fee_estimator.bounded_sat_per_1000_weight(ConfirmationTarget::HighPriority) as u64 * 10);
		if feerate_per_kw as u64 > upper_limit {
			return Err(ChannelError::Close(format!("Peer's feerate much too high. Actual: {}. Our expected upper limit: {}", feerate_per_kw, upper_limit)));
		}
		let lower_limit = fee_estimator.bounded_sat_per_1000_weight(ConfirmationTarget::Background);
		// Some fee estimators round up to the next full sat/vbyte (ie 250 sats per kw), causing
		// occasional issues with feerate disagreements between an initiator that wants a feerate
		// of 1.1 sat/vbyte and a receiver that wants 1.1 rounded up to 2. Thus, we always add 250
		// sat/kw before the comparison here.
		if feerate_per_kw + 250 < lower_limit {
			if let Some(cur_feerate) = cur_feerate_per_kw {
				if feerate_per_kw > cur_feerate {
					log_warn!(logger,
						"Accepting feerate that may prevent us from closing this channel because it's higher than what we have now. Had {} s/kW, now {} s/kW.",
						cur_feerate, feerate_per_kw);
					return Ok(());
				}
			}
			return Err(ChannelError::Close(format!("Peer's feerate much too low. Actual: {}. Our expected lower limit: {} (- 250)", feerate_per_kw, lower_limit)));
		}
		Ok(())
	}

	/// Creates a new channel from a remote sides' request for one.
	/// Assumes chain_hash has already been checked and corresponds with what we expect!
	pub fn new_from_req<ES: Deref, SP: Deref, F: Deref, L: Deref>(
		fee_estimator: &LowerBoundedFeeEstimator<F>, entropy_source: &ES, signer_provider: &SP,
		counterparty_node_id: PublicKey, our_supported_features: &ChannelTypeFeatures,
		their_features: &InitFeatures, msg: &msgs::OpenChannel, user_id: u128, config: &UserConfig,
		current_chain_height: u32, logger: &L, outbound_scid_alias: u64
	) -> Result<Channel<Signer>, ChannelError>
		where ES::Target: EntropySource,
			  SP::Target: SignerProvider<Signer = Signer>,
			  F::Target: FeeEstimator,
			  L::Target: Logger,
	{
		let announced_channel = if (msg.channel_flags & 1) == 1 { true } else { false };

		// First check the channel type is known, failing before we do anything else if we don't
		// support this channel type.
		let channel_type = if let Some(channel_type) = &msg.channel_type {
			if channel_type.supports_any_optional_bits() {
				return Err(ChannelError::Close("Channel Type field contained optional bits - this is not allowed".to_owned()));
			}

			// We only support the channel types defined by the `ChannelManager` in
			// `provided_channel_type_features`. The channel type must always support
			// `static_remote_key`.
			if !channel_type.requires_static_remote_key() {
				return Err(ChannelError::Close("Channel Type was not understood - we require static remote key".to_owned()));
			}
			// Make sure we support all of the features behind the channel type.
			if !channel_type.is_subset(our_supported_features) {
				return Err(ChannelError::Close("Channel Type contains unsupported features".to_owned()));
			}
			if channel_type.requires_scid_privacy() && announced_channel {
				return Err(ChannelError::Close("SCID Alias/Privacy Channel Type cannot be set on a public channel".to_owned()));
			}
			channel_type.clone()
		} else {
			let channel_type = ChannelTypeFeatures::from_init(&their_features);
			if channel_type != ChannelTypeFeatures::only_static_remote_key() {
				return Err(ChannelError::Close("Only static_remote_key is supported for non-negotiated channel types".to_owned()));
			}
			channel_type
		};
		let opt_anchors = channel_type.supports_anchors_zero_fee_htlc_tx();

		let channel_keys_id = signer_provider.generate_channel_keys_id(true, msg.funding_satoshis, user_id);
		let holder_signer = signer_provider.derive_channel_signer(msg.funding_satoshis, channel_keys_id);
		let pubkeys = holder_signer.pubkeys().clone();
		let counterparty_pubkeys = ChannelPublicKeys {
			funding_pubkey: msg.funding_pubkey,
			revocation_basepoint: msg.revocation_basepoint,
			payment_point: msg.payment_point,
			delayed_payment_basepoint: msg.delayed_payment_basepoint,
			htlc_basepoint: msg.htlc_basepoint
		};

		if config.channel_handshake_config.our_to_self_delay < BREAKDOWN_TIMEOUT {
			return Err(ChannelError::Close(format!("Configured with an unreasonable our_to_self_delay ({}) putting user funds at risks. It must be greater than {}", config.channel_handshake_config.our_to_self_delay, BREAKDOWN_TIMEOUT)));
		}

		// Check sanity of message fields:
		if msg.funding_satoshis > config.channel_handshake_limits.max_funding_satoshis {
			return Err(ChannelError::Close(format!("Per our config, funding must be at most {}. It was {}", config.channel_handshake_limits.max_funding_satoshis, msg.funding_satoshis)));
		}
		if msg.funding_satoshis >= TOTAL_BITCOIN_SUPPLY_SATOSHIS {
			return Err(ChannelError::Close(format!("Funding must be smaller than the total bitcoin supply. It was {}", msg.funding_satoshis)));
		}
		if msg.channel_reserve_satoshis > msg.funding_satoshis {
			return Err(ChannelError::Close(format!("Bogus channel_reserve_satoshis ({}). Must be not greater than funding_satoshis: {}", msg.channel_reserve_satoshis, msg.funding_satoshis)));
		}
		let full_channel_value_msat = (msg.funding_satoshis - msg.channel_reserve_satoshis) * 1000;
		if msg.push_msat > full_channel_value_msat {
			return Err(ChannelError::Close(format!("push_msat {} was larger than channel amount minus reserve ({})", msg.push_msat, full_channel_value_msat)));
		}
		if msg.dust_limit_satoshis > msg.funding_satoshis {
			return Err(ChannelError::Close(format!("dust_limit_satoshis {} was larger than funding_satoshis {}. Peer never wants payout outputs?", msg.dust_limit_satoshis, msg.funding_satoshis)));
		}
		if msg.htlc_minimum_msat >= full_channel_value_msat {
			return Err(ChannelError::Close(format!("Minimum htlc value ({}) was larger than full channel value ({})", msg.htlc_minimum_msat, full_channel_value_msat)));
		}
		Channel::<Signer>::check_remote_fee(fee_estimator, msg.feerate_per_kw, None, logger)?;

		let max_counterparty_selected_contest_delay = u16::min(config.channel_handshake_limits.their_to_self_delay, MAX_LOCAL_BREAKDOWN_TIMEOUT);
		if msg.to_self_delay > max_counterparty_selected_contest_delay {
			return Err(ChannelError::Close(format!("They wanted our payments to be delayed by a needlessly long period. Upper limit: {}. Actual: {}", max_counterparty_selected_contest_delay, msg.to_self_delay)));
		}
		if msg.max_accepted_htlcs < 1 {
			return Err(ChannelError::Close("0 max_accepted_htlcs makes for a useless channel".to_owned()));
		}
		if msg.max_accepted_htlcs > MAX_HTLCS {
			return Err(ChannelError::Close(format!("max_accepted_htlcs was {}. It must not be larger than {}", msg.max_accepted_htlcs, MAX_HTLCS)));
		}

		// Now check against optional parameters as set by config...
		if msg.funding_satoshis < config.channel_handshake_limits.min_funding_satoshis {
			return Err(ChannelError::Close(format!("Funding satoshis ({}) is less than the user specified limit ({})", msg.funding_satoshis, config.channel_handshake_limits.min_funding_satoshis)));
		}
		if msg.htlc_minimum_msat > config.channel_handshake_limits.max_htlc_minimum_msat {
			return Err(ChannelError::Close(format!("htlc_minimum_msat ({}) is higher than the user specified limit ({})", msg.htlc_minimum_msat,  config.channel_handshake_limits.max_htlc_minimum_msat)));
		}
		if msg.max_htlc_value_in_flight_msat < config.channel_handshake_limits.min_max_htlc_value_in_flight_msat {
			return Err(ChannelError::Close(format!("max_htlc_value_in_flight_msat ({}) is less than the user specified limit ({})", msg.max_htlc_value_in_flight_msat, config.channel_handshake_limits.min_max_htlc_value_in_flight_msat)));
		}
		if msg.channel_reserve_satoshis > config.channel_handshake_limits.max_channel_reserve_satoshis {
			return Err(ChannelError::Close(format!("channel_reserve_satoshis ({}) is higher than the user specified limit ({})", msg.channel_reserve_satoshis, config.channel_handshake_limits.max_channel_reserve_satoshis)));
		}
		if msg.max_accepted_htlcs < config.channel_handshake_limits.min_max_accepted_htlcs {
			return Err(ChannelError::Close(format!("max_accepted_htlcs ({}) is less than the user specified limit ({})", msg.max_accepted_htlcs, config.channel_handshake_limits.min_max_accepted_htlcs)));
		}
		if msg.dust_limit_satoshis < MIN_CHAN_DUST_LIMIT_SATOSHIS {
			return Err(ChannelError::Close(format!("dust_limit_satoshis ({}) is less than the implementation limit ({})", msg.dust_limit_satoshis, MIN_CHAN_DUST_LIMIT_SATOSHIS)));
		}
		if msg.dust_limit_satoshis >  MAX_CHAN_DUST_LIMIT_SATOSHIS {
			return Err(ChannelError::Close(format!("dust_limit_satoshis ({}) is greater than the implementation limit ({})", msg.dust_limit_satoshis, MAX_CHAN_DUST_LIMIT_SATOSHIS)));
		}

		// Convert things into internal flags and prep our state:

		if config.channel_handshake_limits.force_announced_channel_preference {
			if config.channel_handshake_config.announced_channel != announced_channel {
				return Err(ChannelError::Close("Peer tried to open channel but their announcement preference is different from ours".to_owned()));
			}
		}

		let holder_selected_channel_reserve_satoshis = Channel::<Signer>::get_holder_selected_channel_reserve_satoshis(msg.funding_satoshis, config);
		if holder_selected_channel_reserve_satoshis < MIN_CHAN_DUST_LIMIT_SATOSHIS {
			// Protocol level safety check in place, although it should never happen because
			// of `MIN_THEIR_CHAN_RESERVE_SATOSHIS`
			return Err(ChannelError::Close(format!("Suitable channel reserve not found. remote_channel_reserve was ({}). dust_limit_satoshis is ({}).", holder_selected_channel_reserve_satoshis, MIN_CHAN_DUST_LIMIT_SATOSHIS)));
		}
		if holder_selected_channel_reserve_satoshis * 1000 >= full_channel_value_msat {
			return Err(ChannelError::Close(format!("Suitable channel reserve not found. remote_channel_reserve was ({})msats. Channel value is ({} - {})msats.", holder_selected_channel_reserve_satoshis * 1000, full_channel_value_msat, msg.push_msat)));
		}
		if msg.channel_reserve_satoshis < MIN_CHAN_DUST_LIMIT_SATOSHIS {
			log_debug!(logger, "channel_reserve_satoshis ({}) is smaller than our dust limit ({}). We can broadcast stale states without any risk, implying this channel is very insecure for our counterparty.",
				msg.channel_reserve_satoshis, MIN_CHAN_DUST_LIMIT_SATOSHIS);
		}
		if holder_selected_channel_reserve_satoshis < msg.dust_limit_satoshis {
			return Err(ChannelError::Close(format!("Dust limit ({}) too high for the channel reserve we require the remote to keep ({})", msg.dust_limit_satoshis, holder_selected_channel_reserve_satoshis)));
		}

		// check if the funder's amount for the initial commitment tx is sufficient
		// for full fee payment plus a few HTLCs to ensure the channel will be useful.
		let funders_amount_msat = msg.funding_satoshis * 1000 - msg.push_msat;
		let commitment_tx_fee = Self::commit_tx_fee_msat(msg.feerate_per_kw, MIN_AFFORDABLE_HTLC_COUNT, opt_anchors) / 1000;
		if funders_amount_msat / 1000 < commitment_tx_fee {
			return Err(ChannelError::Close(format!("Funding amount ({} sats) can't even pay fee for initial commitment transaction fee of {} sats.", funders_amount_msat / 1000, commitment_tx_fee)));
		}

		let to_remote_satoshis = funders_amount_msat / 1000 - commitment_tx_fee;
		// While it's reasonable for us to not meet the channel reserve initially (if they don't
		// want to push much to us), our counterparty should always have more than our reserve.
		if to_remote_satoshis < holder_selected_channel_reserve_satoshis {
			return Err(ChannelError::Close("Insufficient funding amount for initial reserve".to_owned()));
		}

		let counterparty_shutdown_scriptpubkey = if their_features.supports_upfront_shutdown_script() {
			match &msg.shutdown_scriptpubkey {
				&OptionalField::Present(ref script) => {
					// Peer is signaling upfront_shutdown and has opt-out with a 0-length script. We don't enforce anything
					if script.len() == 0 {
						None
					} else {
						if !script::is_bolt2_compliant(&script, their_features) {
							return Err(ChannelError::Close(format!("Peer is signaling upfront_shutdown but has provided an unacceptable scriptpubkey format: {}", script)))
						}
						Some(script.clone())
					}
				},
				// Peer is signaling upfront shutdown but don't opt-out with correct mechanism (a.k.a 0-length script). Peer looks buggy, we fail the channel
				&OptionalField::Absent => {
					return Err(ChannelError::Close("Peer is signaling upfront_shutdown but we don't get any script. Use 0-length script to opt-out".to_owned()));
				}
			}
		} else { None };

		let shutdown_scriptpubkey = if config.channel_handshake_config.commit_upfront_shutdown_pubkey {
			Some(signer_provider.get_shutdown_scriptpubkey())
		} else { None };

		if let Some(shutdown_scriptpubkey) = &shutdown_scriptpubkey {
			if !shutdown_scriptpubkey.is_compatible(&their_features) {
				return Err(ChannelError::Close(format!("Provided a scriptpubkey format not accepted by peer: {}", shutdown_scriptpubkey)));
			}
		}

		let mut secp_ctx = Secp256k1::new();
		secp_ctx.seeded_randomize(&entropy_source.get_secure_random_bytes());

		let chan = Channel {
			user_id,

			config: LegacyChannelConfig {
				options: config.channel_config.clone(),
				announced_channel,
				commit_upfront_shutdown_pubkey: config.channel_handshake_config.commit_upfront_shutdown_pubkey,
			},

			prev_config: None,

			inbound_handshake_limits_override: None,

			channel_id: msg.temporary_channel_id,
			channel_state: (ChannelState::OurInitSent as u32) | (ChannelState::TheirInitSent as u32),
			announcement_sigs_state: AnnouncementSigsState::NotSent,
			secp_ctx,

			latest_monitor_update_id: 0,

			holder_signer,
			shutdown_scriptpubkey,
			destination_script: signer_provider.get_destination_script(),

			cur_holder_commitment_transaction_number: INITIAL_COMMITMENT_NUMBER,
			cur_counterparty_commitment_transaction_number: INITIAL_COMMITMENT_NUMBER,
			value_to_self_msat: msg.push_msat,

			pending_inbound_htlcs: Vec::new(),
			pending_outbound_htlcs: Vec::new(),
			holding_cell_htlc_updates: Vec::new(),
			pending_update_fee: None,
			holding_cell_update_fee: None,
			next_holder_htlc_id: 0,
			next_counterparty_htlc_id: 0,
			update_time_counter: 1,

			resend_order: RAACommitmentOrder::CommitmentFirst,

			monitor_pending_channel_ready: false,
			monitor_pending_revoke_and_ack: false,
			monitor_pending_commitment_signed: false,
			monitor_pending_forwards: Vec::new(),
			monitor_pending_failures: Vec::new(),
			monitor_pending_finalized_fulfills: Vec::new(),

			#[cfg(debug_assertions)]
			holder_max_commitment_tx_output: Mutex::new((msg.push_msat, msg.funding_satoshis * 1000 - msg.push_msat)),
			#[cfg(debug_assertions)]
			counterparty_max_commitment_tx_output: Mutex::new((msg.push_msat, msg.funding_satoshis * 1000 - msg.push_msat)),

			last_sent_closing_fee: None,
			pending_counterparty_closing_signed: None,
			closing_fee_limits: None,
			target_closing_feerate_sats_per_kw: None,

			inbound_awaiting_accept: true,

			funding_tx_confirmed_in: None,
			funding_tx_confirmation_height: 0,
			short_channel_id: None,
			channel_creation_height: current_chain_height,

			feerate_per_kw: msg.feerate_per_kw,
			channel_value_satoshis: msg.funding_satoshis,
			counterparty_dust_limit_satoshis: msg.dust_limit_satoshis,
			holder_dust_limit_satoshis: MIN_CHAN_DUST_LIMIT_SATOSHIS,
			counterparty_max_htlc_value_in_flight_msat: cmp::min(msg.max_htlc_value_in_flight_msat, msg.funding_satoshis * 1000),
			holder_max_htlc_value_in_flight_msat: Self::get_holder_max_htlc_value_in_flight_msat(msg.funding_satoshis, &config.channel_handshake_config),
			counterparty_selected_channel_reserve_satoshis: Some(msg.channel_reserve_satoshis),
			holder_selected_channel_reserve_satoshis,
			counterparty_htlc_minimum_msat: msg.htlc_minimum_msat,
			holder_htlc_minimum_msat: if config.channel_handshake_config.our_htlc_minimum_msat == 0 { 1 } else { config.channel_handshake_config.our_htlc_minimum_msat },
			counterparty_max_accepted_htlcs: msg.max_accepted_htlcs,
			minimum_depth: Some(cmp::max(config.channel_handshake_config.minimum_depth, 1)),

			counterparty_forwarding_info: None,

			channel_transaction_parameters: ChannelTransactionParameters {
				holder_pubkeys: pubkeys,
				holder_selected_contest_delay: config.channel_handshake_config.our_to_self_delay,
				is_outbound_from_holder: false,
				counterparty_parameters: Some(CounterpartyChannelTransactionParameters {
					selected_contest_delay: msg.to_self_delay,
					pubkeys: counterparty_pubkeys,
				}),
				funding_outpoint: None,
				opt_anchors: if opt_anchors { Some(()) } else { None },
				opt_non_zero_fee_anchors: None
			},
			funding_transaction: None,

			counterparty_cur_commitment_point: Some(msg.first_per_commitment_point),
			counterparty_prev_commitment_point: None,
			counterparty_node_id,

			counterparty_shutdown_scriptpubkey,

			commitment_secrets: CounterpartyCommitmentSecrets::new(),

			channel_update_status: ChannelUpdateStatus::Enabled,
			closing_signed_in_flight: false,

			announcement_sigs: None,

			#[cfg(any(test, fuzzing))]
			next_local_commitment_tx_fee_info_cached: Mutex::new(None),
			#[cfg(any(test, fuzzing))]
			next_remote_commitment_tx_fee_info_cached: Mutex::new(None),

			workaround_lnd_bug_4006: None,

			latest_inbound_scid_alias: None,
			outbound_scid_alias,

			channel_ready_event_emitted: false,

			#[cfg(any(test, fuzzing))]
			historical_inbound_htlc_fulfills: HashSet::new(),

			channel_type,
			channel_keys_id,

			pending_monitor_updates: Vec::new(),
		};

		Ok(chan)
	}

	/// Transaction nomenclature is somewhat confusing here as there are many different cases - a
	/// transaction is referred to as "a's transaction" implying that a will be able to broadcast
	/// the transaction. Thus, b will generally be sending a signature over such a transaction to
	/// a, and a can revoke the transaction by providing b the relevant per_commitment_secret. As
	/// such, a transaction is generally the result of b increasing the amount paid to a (or adding
	/// an HTLC to a).
	/// @local is used only to convert relevant internal structures which refer to remote vs local
	/// to decide value of outputs and direction of HTLCs.
	/// @generated_by_local is used to determine *which* HTLCs to include - noting that the HTLC
	/// state may indicate that one peer has informed the other that they'd like to add an HTLC but
	/// have not yet committed it. Such HTLCs will only be included in transactions which are being
	/// generated by the peer which proposed adding the HTLCs, and thus we need to understand both
	/// which peer generated this transaction and "to whom" this transaction flows.
	#[inline]
	fn build_commitment_transaction<L: Deref>(&self, commitment_number: u64, keys: &TxCreationKeys, local: bool, generated_by_local: bool, logger: &L) -> CommitmentStats
		where L::Target: Logger
	{
		let mut included_dust_htlcs: Vec<(HTLCOutputInCommitment, Option<&HTLCSource>)> = Vec::new();
		let num_htlcs = self.pending_inbound_htlcs.len() + self.pending_outbound_htlcs.len();
		let mut included_non_dust_htlcs: Vec<(HTLCOutputInCommitment, Option<&HTLCSource>)> = Vec::with_capacity(num_htlcs);

		let broadcaster_dust_limit_satoshis = if local { self.holder_dust_limit_satoshis } else { self.counterparty_dust_limit_satoshis };
		let mut remote_htlc_total_msat = 0;
		let mut local_htlc_total_msat = 0;
		let mut value_to_self_msat_offset = 0;

		let mut feerate_per_kw = self.feerate_per_kw;
		if let Some((feerate, update_state)) = self.pending_update_fee {
			if match update_state {
				// Note that these match the inclusion criteria when scanning
				// pending_inbound_htlcs below.
				FeeUpdateState::RemoteAnnounced => { debug_assert!(!self.is_outbound()); !generated_by_local },
				FeeUpdateState::AwaitingRemoteRevokeToAnnounce => { debug_assert!(!self.is_outbound()); !generated_by_local },
				FeeUpdateState::Outbound => { assert!(self.is_outbound());  generated_by_local },
			} {
				feerate_per_kw = feerate;
			}
		}

		log_trace!(logger, "Building commitment transaction number {} (really {} xor {}) for channel {} for {}, generated by {} with fee {}...",
			commitment_number, (INITIAL_COMMITMENT_NUMBER - commitment_number),
			get_commitment_transaction_number_obscure_factor(&self.get_holder_pubkeys().payment_point, &self.get_counterparty_pubkeys().payment_point, self.is_outbound()),
			log_bytes!(self.channel_id), if local { "us" } else { "remote" }, if generated_by_local { "us" } else { "remote" }, feerate_per_kw);

		macro_rules! get_htlc_in_commitment {
			($htlc: expr, $offered: expr) => {
				HTLCOutputInCommitment {
					offered: $offered,
					amount_msat: $htlc.amount_msat,
					cltv_expiry: $htlc.cltv_expiry,
					payment_hash: $htlc.payment_hash,
					transaction_output_index: None
				}
			}
		}

		macro_rules! add_htlc_output {
			($htlc: expr, $outbound: expr, $source: expr, $state_name: expr) => {
				if $outbound == local { // "offered HTLC output"
					let htlc_in_tx = get_htlc_in_commitment!($htlc, true);
					let htlc_tx_fee = if self.opt_anchors() {
						0
					} else {
						feerate_per_kw as u64 * htlc_timeout_tx_weight(false) / 1000
					};
					if $htlc.amount_msat / 1000 >= broadcaster_dust_limit_satoshis + htlc_tx_fee {
						log_trace!(logger, "   ...including {} {} HTLC {} (hash {}) with value {}", if $outbound { "outbound" } else { "inbound" }, $state_name, $htlc.htlc_id, log_bytes!($htlc.payment_hash.0), $htlc.amount_msat);
						included_non_dust_htlcs.push((htlc_in_tx, $source));
					} else {
						log_trace!(logger, "   ...including {} {} dust HTLC {} (hash {}) with value {} due to dust limit", if $outbound { "outbound" } else { "inbound" }, $state_name, $htlc.htlc_id, log_bytes!($htlc.payment_hash.0), $htlc.amount_msat);
						included_dust_htlcs.push((htlc_in_tx, $source));
					}
				} else {
					let htlc_in_tx = get_htlc_in_commitment!($htlc, false);
					let htlc_tx_fee = if self.opt_anchors() {
						0
					} else {
						feerate_per_kw as u64 * htlc_success_tx_weight(false) / 1000
					};
					if $htlc.amount_msat / 1000 >= broadcaster_dust_limit_satoshis + htlc_tx_fee {
						log_trace!(logger, "   ...including {} {} HTLC {} (hash {}) with value {}", if $outbound { "outbound" } else { "inbound" }, $state_name, $htlc.htlc_id, log_bytes!($htlc.payment_hash.0), $htlc.amount_msat);
						included_non_dust_htlcs.push((htlc_in_tx, $source));
					} else {
						log_trace!(logger, "   ...including {} {} dust HTLC {} (hash {}) with value {}", if $outbound { "outbound" } else { "inbound" }, $state_name, $htlc.htlc_id, log_bytes!($htlc.payment_hash.0), $htlc.amount_msat);
						included_dust_htlcs.push((htlc_in_tx, $source));
					}
				}
			}
		}

		for ref htlc in self.pending_inbound_htlcs.iter() {
			let (include, state_name) = match htlc.state {
				InboundHTLCState::RemoteAnnounced(_) => (!generated_by_local, "RemoteAnnounced"),
				InboundHTLCState::AwaitingRemoteRevokeToAnnounce(_) => (!generated_by_local, "AwaitingRemoteRevokeToAnnounce"),
				InboundHTLCState::AwaitingAnnouncedRemoteRevoke(_) => (true, "AwaitingAnnouncedRemoteRevoke"),
				InboundHTLCState::Committed => (true, "Committed"),
				InboundHTLCState::LocalRemoved(_) => (!generated_by_local, "LocalRemoved"),
			};

			if include {
				add_htlc_output!(htlc, false, None, state_name);
				remote_htlc_total_msat += htlc.amount_msat;
			} else {
				log_trace!(logger, "   ...not including inbound HTLC {} (hash {}) with value {} due to state ({})", htlc.htlc_id, log_bytes!(htlc.payment_hash.0), htlc.amount_msat, state_name);
				match &htlc.state {
					&InboundHTLCState::LocalRemoved(ref reason) => {
						if generated_by_local {
							if let &InboundHTLCRemovalReason::Fulfill(_) = reason {
								value_to_self_msat_offset += htlc.amount_msat as i64;
							}
						}
					},
					_ => {},
				}
			}
		}

		let mut preimages: Vec<PaymentPreimage> = Vec::new();

		for ref htlc in self.pending_outbound_htlcs.iter() {
			let (include, state_name) = match htlc.state {
				OutboundHTLCState::LocalAnnounced(_) => (generated_by_local, "LocalAnnounced"),
				OutboundHTLCState::Committed => (true, "Committed"),
				OutboundHTLCState::RemoteRemoved(_) => (generated_by_local, "RemoteRemoved"),
				OutboundHTLCState::AwaitingRemoteRevokeToRemove(_) => (generated_by_local, "AwaitingRemoteRevokeToRemove"),
				OutboundHTLCState::AwaitingRemovedRemoteRevoke(_) => (false, "AwaitingRemovedRemoteRevoke"),
			};

			let preimage_opt = match htlc.state {
				OutboundHTLCState::RemoteRemoved(OutboundHTLCOutcome::Success(p)) => p,
				OutboundHTLCState::AwaitingRemoteRevokeToRemove(OutboundHTLCOutcome::Success(p)) => p,
				OutboundHTLCState::AwaitingRemovedRemoteRevoke(OutboundHTLCOutcome::Success(p)) => p,
				_ => None,
			};

			if let Some(preimage) = preimage_opt {
				preimages.push(preimage);
			}

			if include {
				add_htlc_output!(htlc, true, Some(&htlc.source), state_name);
				local_htlc_total_msat += htlc.amount_msat;
			} else {
				log_trace!(logger, "   ...not including outbound HTLC {} (hash {}) with value {} due to state ({})", htlc.htlc_id, log_bytes!(htlc.payment_hash.0), htlc.amount_msat, state_name);
				match htlc.state {
					OutboundHTLCState::AwaitingRemoteRevokeToRemove(OutboundHTLCOutcome::Success(_))|OutboundHTLCState::AwaitingRemovedRemoteRevoke(OutboundHTLCOutcome::Success(_)) => {
						value_to_self_msat_offset -= htlc.amount_msat as i64;
					},
					OutboundHTLCState::RemoteRemoved(OutboundHTLCOutcome::Success(_)) => {
						if !generated_by_local {
							value_to_self_msat_offset -= htlc.amount_msat as i64;
						}
					},
					_ => {},
				}
			}
		}

		let mut value_to_self_msat: i64 = (self.value_to_self_msat - local_htlc_total_msat) as i64 + value_to_self_msat_offset;
		assert!(value_to_self_msat >= 0);
		// Note that in case they have several just-awaiting-last-RAA fulfills in-progress (ie
		// AwaitingRemoteRevokeToRemove or AwaitingRemovedRemoteRevoke) we may have allowed them to
		// "violate" their reserve value by couting those against it. Thus, we have to convert
		// everything to i64 before subtracting as otherwise we can overflow.
		let mut value_to_remote_msat: i64 = (self.channel_value_satoshis * 1000) as i64 - (self.value_to_self_msat as i64) - (remote_htlc_total_msat as i64) - value_to_self_msat_offset;
		assert!(value_to_remote_msat >= 0);

		#[cfg(debug_assertions)]
		{
			// Make sure that the to_self/to_remote is always either past the appropriate
			// channel_reserve *or* it is making progress towards it.
			let mut broadcaster_max_commitment_tx_output = if generated_by_local {
				self.holder_max_commitment_tx_output.lock().unwrap()
			} else {
				self.counterparty_max_commitment_tx_output.lock().unwrap()
			};
			debug_assert!(broadcaster_max_commitment_tx_output.0 <= value_to_self_msat as u64 || value_to_self_msat / 1000 >= self.counterparty_selected_channel_reserve_satoshis.unwrap() as i64);
			broadcaster_max_commitment_tx_output.0 = cmp::max(broadcaster_max_commitment_tx_output.0, value_to_self_msat as u64);
			debug_assert!(broadcaster_max_commitment_tx_output.1 <= value_to_remote_msat as u64 || value_to_remote_msat / 1000 >= self.holder_selected_channel_reserve_satoshis as i64);
			broadcaster_max_commitment_tx_output.1 = cmp::max(broadcaster_max_commitment_tx_output.1, value_to_remote_msat as u64);
		}

		let total_fee_sat = Channel::<Signer>::commit_tx_fee_sat(feerate_per_kw, included_non_dust_htlcs.len(), self.channel_transaction_parameters.opt_anchors.is_some());
		let anchors_val = if self.channel_transaction_parameters.opt_anchors.is_some() { ANCHOR_OUTPUT_VALUE_SATOSHI * 2 } else { 0 } as i64;
		let (value_to_self, value_to_remote) = if self.is_outbound() {
			(value_to_self_msat / 1000 - anchors_val - total_fee_sat as i64, value_to_remote_msat / 1000)
		} else {
			(value_to_self_msat / 1000, value_to_remote_msat / 1000 - anchors_val - total_fee_sat as i64)
		};

		let mut value_to_a = if local { value_to_self } else { value_to_remote };
		let mut value_to_b = if local { value_to_remote } else { value_to_self };
		let (funding_pubkey_a, funding_pubkey_b) = if local {
			(self.get_holder_pubkeys().funding_pubkey, self.get_counterparty_pubkeys().funding_pubkey)
		} else {
			(self.get_counterparty_pubkeys().funding_pubkey, self.get_holder_pubkeys().funding_pubkey)
		};

		if value_to_a >= (broadcaster_dust_limit_satoshis as i64) {
			log_trace!(logger, "   ...including {} output with value {}", if local { "to_local" } else { "to_remote" }, value_to_a);
		} else {
			value_to_a = 0;
		}

		if value_to_b >= (broadcaster_dust_limit_satoshis as i64) {
			log_trace!(logger, "   ...including {} output with value {}", if local { "to_remote" } else { "to_local" }, value_to_b);
		} else {
			value_to_b = 0;
		}

		let num_nondust_htlcs = included_non_dust_htlcs.len();

		let channel_parameters =
			if local { self.channel_transaction_parameters.as_holder_broadcastable() }
			else { self.channel_transaction_parameters.as_counterparty_broadcastable() };
		let tx = CommitmentTransaction::new_with_auxiliary_htlc_data(commitment_number,
		                                                             value_to_a as u64,
		                                                             value_to_b as u64,
		                                                             self.channel_transaction_parameters.opt_anchors.is_some(),
		                                                             funding_pubkey_a,
		                                                             funding_pubkey_b,
		                                                             keys.clone(),
		                                                             feerate_per_kw,
		                                                             &mut included_non_dust_htlcs,
		                                                             &channel_parameters
		);
		let mut htlcs_included = included_non_dust_htlcs;
		// The unwrap is safe, because all non-dust HTLCs have been assigned an output index
		htlcs_included.sort_unstable_by_key(|h| h.0.transaction_output_index.unwrap());
		htlcs_included.append(&mut included_dust_htlcs);

		// For the stats, trimmed-to-0 the value in msats accordingly
		value_to_self_msat = if (value_to_self_msat * 1000) < broadcaster_dust_limit_satoshis as i64 { 0 } else { value_to_self_msat };
		value_to_remote_msat = if (value_to_remote_msat * 1000) < broadcaster_dust_limit_satoshis as i64 { 0 } else { value_to_remote_msat };

		CommitmentStats {
			tx,
			feerate_per_kw,
			total_fee_sat,
			num_nondust_htlcs,
			htlcs_included,
			local_balance_msat: value_to_self_msat as u64,
			remote_balance_msat: value_to_remote_msat as u64,
			preimages
		}
	}

	#[inline]
	fn get_closing_scriptpubkey(&self) -> Script {
		// The shutdown scriptpubkey is set on channel opening when option_upfront_shutdown_script
		// is signaled. Otherwise, it is set when sending a shutdown message. Calling this method
		// outside of those situations will fail.
		self.shutdown_scriptpubkey.clone().unwrap().into_inner()
	}

	#[inline]
	fn get_closing_transaction_weight(&self, a_scriptpubkey: Option<&Script>, b_scriptpubkey: Option<&Script>) -> u64 {
		let mut ret =
		(4 +                                           // version
		 1 +                                           // input count
		 36 +                                          // prevout
		 1 +                                           // script length (0)
		 4 +                                           // sequence
		 1 +                                           // output count
		 4                                             // lock time
		 )*4 +                                         // * 4 for non-witness parts
		2 +                                            // witness marker and flag
		1 +                                            // witness element count
		4 +                                            // 4 element lengths (2 sigs, multisig dummy, and witness script)
		self.get_funding_redeemscript().len() as u64 + // funding witness script
		2*(1 + 71);                                    // two signatures + sighash type flags
		if let Some(spk) = a_scriptpubkey {
			ret += ((8+1) +                            // output values and script length
				spk.len() as u64) * 4;                 // scriptpubkey and witness multiplier
		}
		if let Some(spk) = b_scriptpubkey {
			ret += ((8+1) +                            // output values and script length
				spk.len() as u64) * 4;                 // scriptpubkey and witness multiplier
		}
		ret
	}

	#[inline]
	fn build_closing_transaction(&self, proposed_total_fee_satoshis: u64, skip_remote_output: bool) -> (ClosingTransaction, u64) {
		assert!(self.pending_inbound_htlcs.is_empty());
		assert!(self.pending_outbound_htlcs.is_empty());
		assert!(self.pending_update_fee.is_none());

		let mut total_fee_satoshis = proposed_total_fee_satoshis;
		let mut value_to_holder: i64 = (self.value_to_self_msat as i64) / 1000 - if self.is_outbound() { total_fee_satoshis as i64 } else { 0 };
		let mut value_to_counterparty: i64 = ((self.channel_value_satoshis * 1000 - self.value_to_self_msat) as i64 / 1000) - if self.is_outbound() { 0 } else { total_fee_satoshis as i64 };

		if value_to_holder < 0 {
			assert!(self.is_outbound());
			total_fee_satoshis += (-value_to_holder) as u64;
		} else if value_to_counterparty < 0 {
			assert!(!self.is_outbound());
			total_fee_satoshis += (-value_to_counterparty) as u64;
		}

		if skip_remote_output || value_to_counterparty as u64 <= self.holder_dust_limit_satoshis {
			value_to_counterparty = 0;
		}

		if value_to_holder as u64 <= self.holder_dust_limit_satoshis {
			value_to_holder = 0;
		}

		assert!(self.shutdown_scriptpubkey.is_some());
		let holder_shutdown_script = self.get_closing_scriptpubkey();
		let counterparty_shutdown_script = self.counterparty_shutdown_scriptpubkey.clone().unwrap();
		let funding_outpoint = self.funding_outpoint().into_bitcoin_outpoint();

		let closing_transaction = ClosingTransaction::new(value_to_holder as u64, value_to_counterparty as u64, holder_shutdown_script, counterparty_shutdown_script, funding_outpoint);
		(closing_transaction, total_fee_satoshis)
	}

	fn funding_outpoint(&self) -> OutPoint {
		self.channel_transaction_parameters.funding_outpoint.unwrap()
	}

	#[inline]
	/// Creates a set of keys for build_commitment_transaction to generate a transaction which our
	/// counterparty will sign (ie DO NOT send signatures over a transaction created by this to
	/// our counterparty!)
	/// The result is a transaction which we can revoke broadcastership of (ie a "local" transaction)
	/// TODO Some magic rust shit to compile-time check this?
	fn build_holder_transaction_keys(&self, commitment_number: u64) -> TxCreationKeys {
		let per_commitment_point = self.holder_signer.get_per_commitment_point(commitment_number, &self.secp_ctx);
		let delayed_payment_base = &self.get_holder_pubkeys().delayed_payment_basepoint;
		let htlc_basepoint = &self.get_holder_pubkeys().htlc_basepoint;
		let counterparty_pubkeys = self.get_counterparty_pubkeys();

		TxCreationKeys::derive_new(&self.secp_ctx, &per_commitment_point, delayed_payment_base, htlc_basepoint, &counterparty_pubkeys.revocation_basepoint, &counterparty_pubkeys.htlc_basepoint)
	}

	#[inline]
	/// Creates a set of keys for build_commitment_transaction to generate a transaction which we
	/// will sign and send to our counterparty.
	/// If an Err is returned, it is a ChannelError::Close (for get_outbound_funding_created)
	fn build_remote_transaction_keys(&self) -> TxCreationKeys {
		//TODO: Ensure that the payment_key derived here ends up in the library users' wallet as we
		//may see payments to it!
		let revocation_basepoint = &self.get_holder_pubkeys().revocation_basepoint;
		let htlc_basepoint = &self.get_holder_pubkeys().htlc_basepoint;
		let counterparty_pubkeys = self.get_counterparty_pubkeys();

		TxCreationKeys::derive_new(&self.secp_ctx, &self.counterparty_cur_commitment_point.unwrap(), &counterparty_pubkeys.delayed_payment_basepoint, &counterparty_pubkeys.htlc_basepoint, revocation_basepoint, htlc_basepoint)
	}

	/// Gets the redeemscript for the funding transaction output (ie the funding transaction output
	/// pays to get_funding_redeemscript().to_v0_p2wsh()).
	/// Panics if called before accept_channel/new_from_req
	pub fn get_funding_redeemscript(&self) -> Script {
		make_funding_redeemscript(&self.get_holder_pubkeys().funding_pubkey, self.counterparty_funding_pubkey())
	}

	/// Claims an HTLC while we're disconnected from a peer, dropping the [`ChannelMonitorUpdate`]
	/// entirely.
	///
	/// The [`ChannelMonitor`] for this channel MUST be updated out-of-band with the preimage
	/// provided (i.e. without calling [`crate::chain::Watch::update_channel`]).
	///
	/// The HTLC claim will end up in the holding cell (because the caller must ensure the peer is
	/// disconnected).
	pub fn claim_htlc_while_disconnected_dropping_mon_update<L: Deref>
		(&mut self, htlc_id_arg: u64, payment_preimage_arg: PaymentPreimage, logger: &L)
	where L::Target: Logger {
		// Assert that we'll add the HTLC claim to the holding cell in `get_update_fulfill_htlc`
		// (see equivalent if condition there).
		assert!(self.channel_state & (ChannelState::AwaitingRemoteRevoke as u32 | ChannelState::PeerDisconnected as u32 | ChannelState::MonitorUpdateInProgress as u32) != 0);
		let mon_update_id = self.latest_monitor_update_id; // Forget the ChannelMonitor update
		let fulfill_resp = self.get_update_fulfill_htlc(htlc_id_arg, payment_preimage_arg, logger);
		self.latest_monitor_update_id = mon_update_id;
		if let UpdateFulfillFetch::NewClaim { msg, .. } = fulfill_resp {
			assert!(msg.is_none()); // The HTLC must have ended up in the holding cell.
		}
	}

	fn get_update_fulfill_htlc<L: Deref>(&mut self, htlc_id_arg: u64, payment_preimage_arg: PaymentPreimage, logger: &L) -> UpdateFulfillFetch where L::Target: Logger {
		// Either ChannelReady got set (which means it won't be unset) or there is no way any
		// caller thought we could have something claimed (cause we wouldn't have accepted in an
		// incoming HTLC anyway). If we got to ShutdownComplete, callers aren't allowed to call us,
		// either.
		if (self.channel_state & (ChannelState::ChannelReady as u32)) != (ChannelState::ChannelReady as u32) {
			panic!("Was asked to fulfill an HTLC when channel was not in an operational state");
		}
		assert_eq!(self.channel_state & ChannelState::ShutdownComplete as u32, 0);

		let payment_hash_calc = PaymentHash(Sha256::hash(&payment_preimage_arg.0[..]).into_inner());

		// ChannelManager may generate duplicate claims/fails due to HTLC update events from
		// on-chain ChannelsMonitors during block rescan. Ideally we'd figure out a way to drop
		// these, but for now we just have to treat them as normal.

		let mut pending_idx = core::usize::MAX;
		let mut htlc_value_msat = 0;
		for (idx, htlc) in self.pending_inbound_htlcs.iter().enumerate() {
			if htlc.htlc_id == htlc_id_arg {
				assert_eq!(htlc.payment_hash, payment_hash_calc);
				match htlc.state {
					InboundHTLCState::Committed => {},
					InboundHTLCState::LocalRemoved(ref reason) => {
						if let &InboundHTLCRemovalReason::Fulfill(_) = reason {
						} else {
							log_warn!(logger, "Have preimage and want to fulfill HTLC with payment hash {} we already failed against channel {}", log_bytes!(htlc.payment_hash.0), log_bytes!(self.channel_id()));
							debug_assert!(false, "Tried to fulfill an HTLC that was already failed");
						}
						return UpdateFulfillFetch::DuplicateClaim {};
					},
					_ => {
						debug_assert!(false, "Have an inbound HTLC we tried to claim before it was fully committed to");
						// Don't return in release mode here so that we can update channel_monitor
					}
				}
				pending_idx = idx;
				htlc_value_msat = htlc.amount_msat;
				break;
			}
		}
		if pending_idx == core::usize::MAX {
			#[cfg(any(test, fuzzing))]
			// If we failed to find an HTLC to fulfill, make sure it was previously fulfilled and
			// this is simply a duplicate claim, not previously failed and we lost funds.
			debug_assert!(self.historical_inbound_htlc_fulfills.contains(&htlc_id_arg));
			return UpdateFulfillFetch::DuplicateClaim {};
		}

		// Now update local state:
		//
		// We have to put the payment_preimage in the channel_monitor right away here to ensure we
		// can claim it even if the channel hits the chain before we see their next commitment.
		self.latest_monitor_update_id += 1;
		let monitor_update = ChannelMonitorUpdate {
			update_id: self.latest_monitor_update_id,
			updates: vec![ChannelMonitorUpdateStep::PaymentPreimage {
				payment_preimage: payment_preimage_arg.clone(),
			}],
		};

		if (self.channel_state & (ChannelState::AwaitingRemoteRevoke as u32 | ChannelState::PeerDisconnected as u32 | ChannelState::MonitorUpdateInProgress as u32)) != 0 {
			// Note that this condition is the same as the assertion in
			// `claim_htlc_while_disconnected_dropping_mon_update` and must match exactly -
			// `claim_htlc_while_disconnected_dropping_mon_update` would not work correctly if we
			// do not not get into this branch.
			for pending_update in self.holding_cell_htlc_updates.iter() {
				match pending_update {
					&HTLCUpdateAwaitingACK::ClaimHTLC { htlc_id, .. } => {
						if htlc_id_arg == htlc_id {
							// Make sure we don't leave latest_monitor_update_id incremented here:
							self.latest_monitor_update_id -= 1;
							#[cfg(any(test, fuzzing))]
							debug_assert!(self.historical_inbound_htlc_fulfills.contains(&htlc_id_arg));
							return UpdateFulfillFetch::DuplicateClaim {};
						}
					},
					&HTLCUpdateAwaitingACK::FailHTLC { htlc_id, .. } => {
						if htlc_id_arg == htlc_id {
							log_warn!(logger, "Have preimage and want to fulfill HTLC with pending failure against channel {}", log_bytes!(self.channel_id()));
							// TODO: We may actually be able to switch to a fulfill here, though its
							// rare enough it may not be worth the complexity burden.
							debug_assert!(false, "Tried to fulfill an HTLC that was already failed");
							return UpdateFulfillFetch::NewClaim { monitor_update, htlc_value_msat, msg: None };
						}
					},
					_ => {}
				}
			}
			log_trace!(logger, "Adding HTLC claim to holding_cell in channel {}! Current state: {}", log_bytes!(self.channel_id()), self.channel_state);
			self.holding_cell_htlc_updates.push(HTLCUpdateAwaitingACK::ClaimHTLC {
				payment_preimage: payment_preimage_arg, htlc_id: htlc_id_arg,
			});
			#[cfg(any(test, fuzzing))]
			self.historical_inbound_htlc_fulfills.insert(htlc_id_arg);
			return UpdateFulfillFetch::NewClaim { monitor_update, htlc_value_msat, msg: None };
		}
		#[cfg(any(test, fuzzing))]
		self.historical_inbound_htlc_fulfills.insert(htlc_id_arg);

		{
			let htlc = &mut self.pending_inbound_htlcs[pending_idx];
			if let InboundHTLCState::Committed = htlc.state {
			} else {
				debug_assert!(false, "Have an inbound HTLC we tried to claim before it was fully committed to");
				return UpdateFulfillFetch::NewClaim { monitor_update, htlc_value_msat, msg: None };
			}
			log_trace!(logger, "Upgrading HTLC {} to LocalRemoved with a Fulfill in channel {}!", log_bytes!(htlc.payment_hash.0), log_bytes!(self.channel_id));
			htlc.state = InboundHTLCState::LocalRemoved(InboundHTLCRemovalReason::Fulfill(payment_preimage_arg.clone()));
		}

		UpdateFulfillFetch::NewClaim {
			monitor_update,
			htlc_value_msat,
			msg: Some(msgs::UpdateFulfillHTLC {
				channel_id: self.channel_id(),
				htlc_id: htlc_id_arg,
				payment_preimage: payment_preimage_arg,
			}),
		}
	}

	pub fn get_update_fulfill_htlc_and_commit<L: Deref>(&mut self, htlc_id: u64, payment_preimage: PaymentPreimage, logger: &L) -> UpdateFulfillCommitFetch where L::Target: Logger {
		match self.get_update_fulfill_htlc(htlc_id, payment_preimage, logger) {
			UpdateFulfillFetch::NewClaim { mut monitor_update, htlc_value_msat, msg: Some(_) } => {
				let mut additional_update = self.build_commitment_no_status_check(logger);
				// build_commitment_no_status_check may bump latest_monitor_id but we want them to be
				// strictly increasing by one, so decrement it here.
				self.latest_monitor_update_id = monitor_update.update_id;
				monitor_update.updates.append(&mut additional_update.updates);
				self.monitor_updating_paused(false, true, false, Vec::new(), Vec::new(), Vec::new());
				self.pending_monitor_updates.push(monitor_update);
				UpdateFulfillCommitFetch::NewClaim {
					monitor_update: self.pending_monitor_updates.last().unwrap(),
					htlc_value_msat,
				}
			},
			UpdateFulfillFetch::NewClaim { monitor_update, htlc_value_msat, msg: None } => {
				self.monitor_updating_paused(false, false, false, Vec::new(), Vec::new(), Vec::new());
				self.pending_monitor_updates.push(monitor_update);
				UpdateFulfillCommitFetch::NewClaim {
					monitor_update: self.pending_monitor_updates.last().unwrap(),
					htlc_value_msat,
				}
			}
			UpdateFulfillFetch::DuplicateClaim {} => UpdateFulfillCommitFetch::DuplicateClaim {},
		}
	}

	/// We can only have one resolution per HTLC. In some cases around reconnect, we may fulfill
	/// an HTLC more than once or fulfill once and then attempt to fail after reconnect. We cannot,
	/// however, fail more than once as we wait for an upstream failure to be irrevocably committed
	/// before we fail backwards.
	///
	/// If we do fail twice, we `debug_assert!(false)` and return `Ok(None)`. Thus, this will always
	/// return `Ok(_)` if preconditions are met. In any case, `Err`s will only be
	/// [`ChannelError::Ignore`].
	pub fn queue_fail_htlc<L: Deref>(&mut self, htlc_id_arg: u64, err_packet: msgs::OnionErrorPacket, logger: &L)
	-> Result<(), ChannelError> where L::Target: Logger {
		self.fail_htlc(htlc_id_arg, err_packet, true, logger)
			.map(|msg_opt| assert!(msg_opt.is_none(), "We forced holding cell?"))
	}

	/// We can only have one resolution per HTLC. In some cases around reconnect, we may fulfill
	/// an HTLC more than once or fulfill once and then attempt to fail after reconnect. We cannot,
	/// however, fail more than once as we wait for an upstream failure to be irrevocably committed
	/// before we fail backwards.
	///
	/// If we do fail twice, we `debug_assert!(false)` and return `Ok(None)`. Thus, this will always
	/// return `Ok(_)` if preconditions are met. In any case, `Err`s will only be
	/// [`ChannelError::Ignore`].
	fn fail_htlc<L: Deref>(&mut self, htlc_id_arg: u64, err_packet: msgs::OnionErrorPacket, mut force_holding_cell: bool, logger: &L)
	-> Result<Option<msgs::UpdateFailHTLC>, ChannelError> where L::Target: Logger {
		if (self.channel_state & (ChannelState::ChannelReady as u32)) != (ChannelState::ChannelReady as u32) {
			panic!("Was asked to fail an HTLC when channel was not in an operational state");
		}
		assert_eq!(self.channel_state & ChannelState::ShutdownComplete as u32, 0);

		// ChannelManager may generate duplicate claims/fails due to HTLC update events from
		// on-chain ChannelsMonitors during block rescan. Ideally we'd figure out a way to drop
		// these, but for now we just have to treat them as normal.

		let mut pending_idx = core::usize::MAX;
		for (idx, htlc) in self.pending_inbound_htlcs.iter().enumerate() {
			if htlc.htlc_id == htlc_id_arg {
				match htlc.state {
					InboundHTLCState::Committed => {},
					InboundHTLCState::LocalRemoved(ref reason) => {
						if let &InboundHTLCRemovalReason::Fulfill(_) = reason {
						} else {
							debug_assert!(false, "Tried to fail an HTLC that was already failed");
						}
						return Ok(None);
					},
					_ => {
						debug_assert!(false, "Have an inbound HTLC we tried to claim before it was fully committed to");
						return Err(ChannelError::Ignore(format!("Unable to find a pending HTLC which matched the given HTLC ID ({})", htlc.htlc_id)));
					}
				}
				pending_idx = idx;
			}
		}
		if pending_idx == core::usize::MAX {
			#[cfg(any(test, fuzzing))]
			// If we failed to find an HTLC to fail, make sure it was previously fulfilled and this
			// is simply a duplicate fail, not previously failed and we failed-back too early.
			debug_assert!(self.historical_inbound_htlc_fulfills.contains(&htlc_id_arg));
			return Ok(None);
		}

		if (self.channel_state & (ChannelState::AwaitingRemoteRevoke as u32 | ChannelState::PeerDisconnected as u32 | ChannelState::MonitorUpdateInProgress as u32)) != 0 {
			debug_assert!(force_holding_cell, "!force_holding_cell is only called when emptying the holding cell, so we shouldn't end up back in it!");
			force_holding_cell = true;
		}

		// Now update local state:
		if force_holding_cell {
			for pending_update in self.holding_cell_htlc_updates.iter() {
				match pending_update {
					&HTLCUpdateAwaitingACK::ClaimHTLC { htlc_id, .. } => {
						if htlc_id_arg == htlc_id {
							#[cfg(any(test, fuzzing))]
							debug_assert!(self.historical_inbound_htlc_fulfills.contains(&htlc_id_arg));
							return Ok(None);
						}
					},
					&HTLCUpdateAwaitingACK::FailHTLC { htlc_id, .. } => {
						if htlc_id_arg == htlc_id {
							debug_assert!(false, "Tried to fail an HTLC that was already failed");
							return Err(ChannelError::Ignore("Unable to find a pending HTLC which matched the given HTLC ID".to_owned()));
						}
					},
					_ => {}
				}
			}
			log_trace!(logger, "Placing failure for HTLC ID {} in holding cell in channel {}.", htlc_id_arg, log_bytes!(self.channel_id()));
			self.holding_cell_htlc_updates.push(HTLCUpdateAwaitingACK::FailHTLC {
				htlc_id: htlc_id_arg,
				err_packet,
			});
			return Ok(None);
		}

		log_trace!(logger, "Failing HTLC ID {} back with a update_fail_htlc message in channel {}.", htlc_id_arg, log_bytes!(self.channel_id()));
		{
			let htlc = &mut self.pending_inbound_htlcs[pending_idx];
			htlc.state = InboundHTLCState::LocalRemoved(InboundHTLCRemovalReason::FailRelay(err_packet.clone()));
		}

		Ok(Some(msgs::UpdateFailHTLC {
			channel_id: self.channel_id(),
			htlc_id: htlc_id_arg,
			reason: err_packet
		}))
	}

	// Message handlers:

	pub fn accept_channel(&mut self, msg: &msgs::AcceptChannel, default_limits: &ChannelHandshakeLimits, their_features: &InitFeatures) -> Result<(), ChannelError> {
		let peer_limits = if let Some(ref limits) = self.inbound_handshake_limits_override { limits } else { default_limits };

		// Check sanity of message fields:
		if !self.is_outbound() {
			return Err(ChannelError::Close("Got an accept_channel message from an inbound peer".to_owned()));
		}
		if self.channel_state != ChannelState::OurInitSent as u32 {
			return Err(ChannelError::Close("Got an accept_channel message at a strange time".to_owned()));
		}
		if msg.dust_limit_satoshis > 21000000 * 100000000 {
			return Err(ChannelError::Close(format!("Peer never wants payout outputs? dust_limit_satoshis was {}", msg.dust_limit_satoshis)));
		}
		if msg.channel_reserve_satoshis > self.channel_value_satoshis {
			return Err(ChannelError::Close(format!("Bogus channel_reserve_satoshis ({}). Must not be greater than ({})", msg.channel_reserve_satoshis, self.channel_value_satoshis)));
		}
		if msg.dust_limit_satoshis > self.holder_selected_channel_reserve_satoshis {
			return Err(ChannelError::Close(format!("Dust limit ({}) is bigger than our channel reserve ({})", msg.dust_limit_satoshis, self.holder_selected_channel_reserve_satoshis)));
		}
		if msg.channel_reserve_satoshis > self.channel_value_satoshis - self.holder_selected_channel_reserve_satoshis {
			return Err(ChannelError::Close(format!("Bogus channel_reserve_satoshis ({}). Must not be greater than channel value minus our reserve ({})",
				msg.channel_reserve_satoshis, self.channel_value_satoshis - self.holder_selected_channel_reserve_satoshis)));
		}
		let full_channel_value_msat = (self.channel_value_satoshis - msg.channel_reserve_satoshis) * 1000;
		if msg.htlc_minimum_msat >= full_channel_value_msat {
			return Err(ChannelError::Close(format!("Minimum htlc value ({}) is full channel value ({})", msg.htlc_minimum_msat, full_channel_value_msat)));
		}
		let max_delay_acceptable = u16::min(peer_limits.their_to_self_delay, MAX_LOCAL_BREAKDOWN_TIMEOUT);
		if msg.to_self_delay > max_delay_acceptable {
			return Err(ChannelError::Close(format!("They wanted our payments to be delayed by a needlessly long period. Upper limit: {}. Actual: {}", max_delay_acceptable, msg.to_self_delay)));
		}
		if msg.max_accepted_htlcs < 1 {
			return Err(ChannelError::Close("0 max_accepted_htlcs makes for a useless channel".to_owned()));
		}
		if msg.max_accepted_htlcs > MAX_HTLCS {
			return Err(ChannelError::Close(format!("max_accepted_htlcs was {}. It must not be larger than {}", msg.max_accepted_htlcs, MAX_HTLCS)));
		}

		// Now check against optional parameters as set by config...
		if msg.htlc_minimum_msat > peer_limits.max_htlc_minimum_msat {
			return Err(ChannelError::Close(format!("htlc_minimum_msat ({}) is higher than the user specified limit ({})", msg.htlc_minimum_msat, peer_limits.max_htlc_minimum_msat)));
		}
		if msg.max_htlc_value_in_flight_msat < peer_limits.min_max_htlc_value_in_flight_msat {
			return Err(ChannelError::Close(format!("max_htlc_value_in_flight_msat ({}) is less than the user specified limit ({})", msg.max_htlc_value_in_flight_msat, peer_limits.min_max_htlc_value_in_flight_msat)));
		}
		if msg.channel_reserve_satoshis > peer_limits.max_channel_reserve_satoshis {
			return Err(ChannelError::Close(format!("channel_reserve_satoshis ({}) is higher than the user specified limit ({})", msg.channel_reserve_satoshis, peer_limits.max_channel_reserve_satoshis)));
		}
		if msg.max_accepted_htlcs < peer_limits.min_max_accepted_htlcs {
			return Err(ChannelError::Close(format!("max_accepted_htlcs ({}) is less than the user specified limit ({})", msg.max_accepted_htlcs, peer_limits.min_max_accepted_htlcs)));
		}
		if msg.dust_limit_satoshis < MIN_CHAN_DUST_LIMIT_SATOSHIS {
			return Err(ChannelError::Close(format!("dust_limit_satoshis ({}) is less than the implementation limit ({})", msg.dust_limit_satoshis, MIN_CHAN_DUST_LIMIT_SATOSHIS)));
		}
		if msg.dust_limit_satoshis > MAX_CHAN_DUST_LIMIT_SATOSHIS {
			return Err(ChannelError::Close(format!("dust_limit_satoshis ({}) is greater than the implementation limit ({})", msg.dust_limit_satoshis, MAX_CHAN_DUST_LIMIT_SATOSHIS)));
		}
		if msg.minimum_depth > peer_limits.max_minimum_depth {
			return Err(ChannelError::Close(format!("We consider the minimum depth to be unreasonably large. Expected minimum: ({}). Actual: ({})", peer_limits.max_minimum_depth, msg.minimum_depth)));
		}

		if let Some(ty) = &msg.channel_type {
			if *ty != self.channel_type {
				return Err(ChannelError::Close("Channel Type in accept_channel didn't match the one sent in open_channel.".to_owned()));
			}
		} else if their_features.supports_channel_type() {
			// Assume they've accepted the channel type as they said they understand it.
		} else {
			let channel_type = ChannelTypeFeatures::from_init(&their_features);
			if channel_type != ChannelTypeFeatures::only_static_remote_key() {
				return Err(ChannelError::Close("Only static_remote_key is supported for non-negotiated channel types".to_owned()));
			}
			self.channel_type = channel_type;
		}

		let counterparty_shutdown_scriptpubkey = if their_features.supports_upfront_shutdown_script() {
			match &msg.shutdown_scriptpubkey {
				&OptionalField::Present(ref script) => {
					// Peer is signaling upfront_shutdown and has opt-out with a 0-length script. We don't enforce anything
					if script.len() == 0 {
						None
					} else {
						if !script::is_bolt2_compliant(&script, their_features) {
							return Err(ChannelError::Close(format!("Peer is signaling upfront_shutdown but has provided an unacceptable scriptpubkey format: {}", script)));
						}
						Some(script.clone())
					}
				},
				// Peer is signaling upfront shutdown but don't opt-out with correct mechanism (a.k.a 0-length script). Peer looks buggy, we fail the channel
				&OptionalField::Absent => {
					return Err(ChannelError::Close("Peer is signaling upfront_shutdown but we don't get any script. Use 0-length script to opt-out".to_owned()));
				}
			}
		} else { None };

		self.counterparty_dust_limit_satoshis = msg.dust_limit_satoshis;
		self.counterparty_max_htlc_value_in_flight_msat = cmp::min(msg.max_htlc_value_in_flight_msat, self.channel_value_satoshis * 1000);
		self.counterparty_selected_channel_reserve_satoshis = Some(msg.channel_reserve_satoshis);
		self.counterparty_htlc_minimum_msat = msg.htlc_minimum_msat;
		self.counterparty_max_accepted_htlcs = msg.max_accepted_htlcs;

		if peer_limits.trust_own_funding_0conf {
			self.minimum_depth = Some(msg.minimum_depth);
		} else {
			self.minimum_depth = Some(cmp::max(1, msg.minimum_depth));
		}

		let counterparty_pubkeys = ChannelPublicKeys {
			funding_pubkey: msg.funding_pubkey,
			revocation_basepoint: msg.revocation_basepoint,
			payment_point: msg.payment_point,
			delayed_payment_basepoint: msg.delayed_payment_basepoint,
			htlc_basepoint: msg.htlc_basepoint
		};

		self.channel_transaction_parameters.counterparty_parameters = Some(CounterpartyChannelTransactionParameters {
			selected_contest_delay: msg.to_self_delay,
			pubkeys: counterparty_pubkeys,
		});

		self.counterparty_cur_commitment_point = Some(msg.first_per_commitment_point);
		self.counterparty_shutdown_scriptpubkey = counterparty_shutdown_scriptpubkey;

		self.channel_state = ChannelState::OurInitSent as u32 | ChannelState::TheirInitSent as u32;
		self.inbound_handshake_limits_override = None; // We're done enforcing limits on our peer's handshake now.

		Ok(())
	}

	fn funding_created_signature<L: Deref>(&mut self, sig: &Signature, logger: &L) -> Result<(Txid, CommitmentTransaction, Signature), ChannelError> where L::Target: Logger {
		let funding_script = self.get_funding_redeemscript();

		let keys = self.build_holder_transaction_keys(self.cur_holder_commitment_transaction_number);
		let initial_commitment_tx = self.build_commitment_transaction(self.cur_holder_commitment_transaction_number, &keys, true, false, logger).tx;
		{
			let trusted_tx = initial_commitment_tx.trust();
			let initial_commitment_bitcoin_tx = trusted_tx.built_transaction();
			let sighash = initial_commitment_bitcoin_tx.get_sighash_all(&funding_script, self.channel_value_satoshis);
			// They sign the holder commitment transaction...
			log_trace!(logger, "Checking funding_created tx signature {} by key {} against tx {} (sighash {}) with redeemscript {} for channel {}.",
				log_bytes!(sig.serialize_compact()[..]), log_bytes!(self.counterparty_funding_pubkey().serialize()),
				encode::serialize_hex(&initial_commitment_bitcoin_tx.transaction), log_bytes!(sighash[..]),
				encode::serialize_hex(&funding_script), log_bytes!(self.channel_id()));
			secp_check!(self.secp_ctx.verify_ecdsa(&sighash, &sig, self.counterparty_funding_pubkey()), "Invalid funding_created signature from peer".to_owned());
		}

		let counterparty_keys = self.build_remote_transaction_keys();
		let counterparty_initial_commitment_tx = self.build_commitment_transaction(self.cur_counterparty_commitment_transaction_number, &counterparty_keys, false, false, logger).tx;

		let counterparty_trusted_tx = counterparty_initial_commitment_tx.trust();
		let counterparty_initial_bitcoin_tx = counterparty_trusted_tx.built_transaction();
		log_trace!(logger, "Initial counterparty tx for channel {} is: txid {} tx {}",
			log_bytes!(self.channel_id()), counterparty_initial_bitcoin_tx.txid, encode::serialize_hex(&counterparty_initial_bitcoin_tx.transaction));

		let counterparty_signature = self.holder_signer.sign_counterparty_commitment(&counterparty_initial_commitment_tx, Vec::new(), &self.secp_ctx)
				.map_err(|_| ChannelError::Close("Failed to get signatures for new commitment_signed".to_owned()))?.0;

		// We sign "counterparty" commitment transaction, allowing them to broadcast the tx if they wish.
		Ok((counterparty_initial_bitcoin_tx.txid, initial_commitment_tx, counterparty_signature))
	}

	fn counterparty_funding_pubkey(&self) -> &PublicKey {
		&self.get_counterparty_pubkeys().funding_pubkey
	}

	pub fn funding_created<SP: Deref, L: Deref>(
		&mut self, msg: &msgs::FundingCreated, best_block: BestBlock, signer_provider: &SP, logger: &L
	) -> Result<(msgs::FundingSigned, ChannelMonitor<Signer>), ChannelError>
	where
		SP::Target: SignerProvider<Signer = Signer>,
		L::Target: Logger
	{
		if self.is_outbound() {
			return Err(ChannelError::Close("Received funding_created for an outbound channel?".to_owned()));
		}
		if self.channel_state != (ChannelState::OurInitSent as u32 | ChannelState::TheirInitSent as u32) {
			// BOLT 2 says that if we disconnect before we send funding_signed we SHOULD NOT
			// remember the channel, so it's safe to just send an error_message here and drop the
			// channel.
			return Err(ChannelError::Close("Received funding_created after we got the channel!".to_owned()));
		}
		if self.inbound_awaiting_accept {
			return Err(ChannelError::Close("FundingCreated message received before the channel was accepted".to_owned()));
		}
		if self.commitment_secrets.get_min_seen_secret() != (1 << 48) ||
				self.cur_counterparty_commitment_transaction_number != INITIAL_COMMITMENT_NUMBER ||
				self.cur_holder_commitment_transaction_number != INITIAL_COMMITMENT_NUMBER {
			panic!("Should not have advanced channel commitment tx numbers prior to funding_created");
		}

		let funding_txo = OutPoint { txid: msg.funding_txid, index: msg.funding_output_index };
		self.channel_transaction_parameters.funding_outpoint = Some(funding_txo);
		// This is an externally observable change before we finish all our checks.  In particular
		// funding_created_signature may fail.
		self.holder_signer.provide_channel_parameters(&self.channel_transaction_parameters);

		let (counterparty_initial_commitment_txid, initial_commitment_tx, signature) = match self.funding_created_signature(&msg.signature, logger) {
			Ok(res) => res,
			Err(ChannelError::Close(e)) => {
				self.channel_transaction_parameters.funding_outpoint = None;
				return Err(ChannelError::Close(e));
			},
			Err(e) => {
				// The only error we know how to handle is ChannelError::Close, so we fall over here
				// to make sure we don't continue with an inconsistent state.
				panic!("unexpected error type from funding_created_signature {:?}", e);
			}
		};

		let holder_commitment_tx = HolderCommitmentTransaction::new(
			initial_commitment_tx,
			msg.signature,
			Vec::new(),
			&self.get_holder_pubkeys().funding_pubkey,
			self.counterparty_funding_pubkey()
		);

		self.holder_signer.validate_holder_commitment(&holder_commitment_tx, Vec::new())
			.map_err(|_| ChannelError::Close("Failed to validate our commitment".to_owned()))?;

		// Now that we're past error-generating stuff, update our local state:

		let funding_redeemscript = self.get_funding_redeemscript();
		let funding_txo_script = funding_redeemscript.to_v0_p2wsh();
		let obscure_factor = get_commitment_transaction_number_obscure_factor(&self.get_holder_pubkeys().payment_point, &self.get_counterparty_pubkeys().payment_point, self.is_outbound());
		let shutdown_script = self.shutdown_scriptpubkey.clone().map(|script| script.into_inner());
		let mut monitor_signer = signer_provider.derive_channel_signer(self.channel_value_satoshis, self.channel_keys_id);
		monitor_signer.provide_channel_parameters(&self.channel_transaction_parameters);
		let channel_monitor = ChannelMonitor::new(self.secp_ctx.clone(), monitor_signer,
		                                          shutdown_script, self.get_holder_selected_contest_delay(),
		                                          &self.destination_script, (funding_txo, funding_txo_script.clone()),
		                                          &self.channel_transaction_parameters,
		                                          funding_redeemscript.clone(), self.channel_value_satoshis,
		                                          obscure_factor,
		                                          holder_commitment_tx, best_block, self.counterparty_node_id);

		channel_monitor.provide_latest_counterparty_commitment_tx(counterparty_initial_commitment_txid, Vec::new(), self.cur_counterparty_commitment_transaction_number, self.counterparty_cur_commitment_point.unwrap(), logger);

		self.channel_state = ChannelState::FundingSent as u32;
		self.channel_id = funding_txo.to_channel_id();
		self.cur_counterparty_commitment_transaction_number -= 1;
		self.cur_holder_commitment_transaction_number -= 1;

		log_info!(logger, "Generated funding_signed for peer for channel {}", log_bytes!(self.channel_id()));

		let need_channel_ready = self.check_get_channel_ready(0).is_some();
		self.monitor_updating_paused(false, false, need_channel_ready, Vec::new(), Vec::new(), Vec::new());

		Ok((msgs::FundingSigned {
			channel_id: self.channel_id,
			signature
		}, channel_monitor))
	}

	/// Handles a funding_signed message from the remote end.
	/// If this call is successful, broadcast the funding transaction (and not before!)
	pub fn funding_signed<SP: Deref, L: Deref>(
		&mut self, msg: &msgs::FundingSigned, best_block: BestBlock, signer_provider: &SP, logger: &L
	) -> Result<ChannelMonitor<Signer>, ChannelError>
	where
		SP::Target: SignerProvider<Signer = Signer>,
		L::Target: Logger
	{
		if !self.is_outbound() {
			return Err(ChannelError::Close("Received funding_signed for an inbound channel?".to_owned()));
		}
		if self.channel_state & !(ChannelState::MonitorUpdateInProgress as u32) != ChannelState::FundingCreated as u32 {
			return Err(ChannelError::Close("Received funding_signed in strange state!".to_owned()));
		}
		if self.commitment_secrets.get_min_seen_secret() != (1 << 48) ||
				self.cur_counterparty_commitment_transaction_number != INITIAL_COMMITMENT_NUMBER ||
				self.cur_holder_commitment_transaction_number != INITIAL_COMMITMENT_NUMBER {
			panic!("Should not have advanced channel commitment tx numbers prior to funding_created");
		}

		let funding_script = self.get_funding_redeemscript();

		let counterparty_keys = self.build_remote_transaction_keys();
		let counterparty_initial_commitment_tx = self.build_commitment_transaction(self.cur_counterparty_commitment_transaction_number, &counterparty_keys, false, false, logger).tx;
		let counterparty_trusted_tx = counterparty_initial_commitment_tx.trust();
		let counterparty_initial_bitcoin_tx = counterparty_trusted_tx.built_transaction();

		log_trace!(logger, "Initial counterparty tx for channel {} is: txid {} tx {}",
			log_bytes!(self.channel_id()), counterparty_initial_bitcoin_tx.txid, encode::serialize_hex(&counterparty_initial_bitcoin_tx.transaction));

		let holder_signer = self.build_holder_transaction_keys(self.cur_holder_commitment_transaction_number);
		let initial_commitment_tx = self.build_commitment_transaction(self.cur_holder_commitment_transaction_number, &holder_signer, true, false, logger).tx;
		{
			let trusted_tx = initial_commitment_tx.trust();
			let initial_commitment_bitcoin_tx = trusted_tx.built_transaction();
			let sighash = initial_commitment_bitcoin_tx.get_sighash_all(&funding_script, self.channel_value_satoshis);
			// They sign our commitment transaction, allowing us to broadcast the tx if we wish.
			if let Err(_) = self.secp_ctx.verify_ecdsa(&sighash, &msg.signature, &self.get_counterparty_pubkeys().funding_pubkey) {
				return Err(ChannelError::Close("Invalid funding_signed signature from peer".to_owned()));
			}
		}

		let holder_commitment_tx = HolderCommitmentTransaction::new(
			initial_commitment_tx,
			msg.signature,
			Vec::new(),
			&self.get_holder_pubkeys().funding_pubkey,
			self.counterparty_funding_pubkey()
		);

		self.holder_signer.validate_holder_commitment(&holder_commitment_tx, Vec::new())
			.map_err(|_| ChannelError::Close("Failed to validate our commitment".to_owned()))?;


		let funding_redeemscript = self.get_funding_redeemscript();
		let funding_txo = self.get_funding_txo().unwrap();
		let funding_txo_script = funding_redeemscript.to_v0_p2wsh();
		let obscure_factor = get_commitment_transaction_number_obscure_factor(&self.get_holder_pubkeys().payment_point, &self.get_counterparty_pubkeys().payment_point, self.is_outbound());
		let shutdown_script = self.shutdown_scriptpubkey.clone().map(|script| script.into_inner());
		let mut monitor_signer = signer_provider.derive_channel_signer(self.channel_value_satoshis, self.channel_keys_id);
		monitor_signer.provide_channel_parameters(&self.channel_transaction_parameters);
		let channel_monitor = ChannelMonitor::new(self.secp_ctx.clone(), monitor_signer,
		                                          shutdown_script, self.get_holder_selected_contest_delay(),
		                                          &self.destination_script, (funding_txo, funding_txo_script),
		                                          &self.channel_transaction_parameters,
		                                          funding_redeemscript.clone(), self.channel_value_satoshis,
		                                          obscure_factor,
		                                          holder_commitment_tx, best_block, self.counterparty_node_id);

		channel_monitor.provide_latest_counterparty_commitment_tx(counterparty_initial_bitcoin_tx.txid, Vec::new(), self.cur_counterparty_commitment_transaction_number, self.counterparty_cur_commitment_point.unwrap(), logger);

		assert_eq!(self.channel_state & (ChannelState::MonitorUpdateInProgress as u32), 0); // We have no had any monitor(s) yet to fail update!
		self.channel_state = ChannelState::FundingSent as u32;
		self.cur_holder_commitment_transaction_number -= 1;
		self.cur_counterparty_commitment_transaction_number -= 1;

		log_info!(logger, "Received funding_signed from peer for channel {}", log_bytes!(self.channel_id()));

		let need_channel_ready = self.check_get_channel_ready(0).is_some();
		self.monitor_updating_paused(false, false, need_channel_ready, Vec::new(), Vec::new(), Vec::new());
		Ok(channel_monitor)
	}

	/// Handles a channel_ready message from our peer. If we've already sent our channel_ready
	/// and the channel is now usable (and public), this may generate an announcement_signatures to
	/// reply with.
	pub fn channel_ready<NS: Deref, L: Deref>(
		&mut self, msg: &msgs::ChannelReady, node_signer: &NS, genesis_block_hash: BlockHash,
		user_config: &UserConfig, best_block: &BestBlock, logger: &L
	) -> Result<Option<msgs::AnnouncementSignatures>, ChannelError>
	where
		NS::Target: NodeSigner,
		L::Target: Logger
	{
		if self.channel_state & (ChannelState::PeerDisconnected as u32) == ChannelState::PeerDisconnected as u32 {
			self.workaround_lnd_bug_4006 = Some(msg.clone());
			return Err(ChannelError::Ignore("Peer sent channel_ready when we needed a channel_reestablish. The peer is likely lnd, see https://github.com/lightningnetwork/lnd/issues/4006".to_owned()));
		}

		if let Some(scid_alias) = msg.short_channel_id_alias {
			if Some(scid_alias) != self.short_channel_id {
				// The scid alias provided can be used to route payments *from* our counterparty,
				// i.e. can be used for inbound payments and provided in invoices, but is not used
				// when routing outbound payments.
				self.latest_inbound_scid_alias = Some(scid_alias);
			}
		}

		let non_shutdown_state = self.channel_state & (!MULTI_STATE_FLAGS);

		if non_shutdown_state == ChannelState::FundingSent as u32 {
			self.channel_state |= ChannelState::TheirChannelReady as u32;
		} else if non_shutdown_state == (ChannelState::FundingSent as u32 | ChannelState::OurChannelReady as u32) {
			self.channel_state = ChannelState::ChannelReady as u32 | (self.channel_state & MULTI_STATE_FLAGS);
			self.update_time_counter += 1;
		} else if self.channel_state & (ChannelState::ChannelReady as u32) != 0 ||
			// If we reconnected before sending our `channel_ready` they may still resend theirs:
			(self.channel_state & (ChannelState::FundingSent as u32 | ChannelState::TheirChannelReady as u32) ==
			                      (ChannelState::FundingSent as u32 | ChannelState::TheirChannelReady as u32))
		{
			// They probably disconnected/reconnected and re-sent the channel_ready, which is
			// required, or they're sending a fresh SCID alias.
			let expected_point =
				if self.cur_counterparty_commitment_transaction_number == INITIAL_COMMITMENT_NUMBER - 1 {
					// If they haven't ever sent an updated point, the point they send should match
					// the current one.
					self.counterparty_cur_commitment_point
				} else if self.cur_counterparty_commitment_transaction_number == INITIAL_COMMITMENT_NUMBER - 2 {
					// If we've advanced the commitment number once, the second commitment point is
					// at `counterparty_prev_commitment_point`, which is not yet revoked.
					debug_assert!(self.counterparty_prev_commitment_point.is_some());
					self.counterparty_prev_commitment_point
				} else {
					// If they have sent updated points, channel_ready is always supposed to match
					// their "first" point, which we re-derive here.
					Some(PublicKey::from_secret_key(&self.secp_ctx, &SecretKey::from_slice(
							&self.commitment_secrets.get_secret(INITIAL_COMMITMENT_NUMBER - 1).expect("We should have all prev secrets available")
						).expect("We already advanced, so previous secret keys should have been validated already")))
				};
			if expected_point != Some(msg.next_per_commitment_point) {
				return Err(ChannelError::Close("Peer sent a reconnect channel_ready with a different point".to_owned()));
			}
			return Ok(None);
		} else {
			return Err(ChannelError::Close("Peer sent a channel_ready at a strange time".to_owned()));
		}

		self.counterparty_prev_commitment_point = self.counterparty_cur_commitment_point;
		self.counterparty_cur_commitment_point = Some(msg.next_per_commitment_point);

		log_info!(logger, "Received channel_ready from peer for channel {}", log_bytes!(self.channel_id()));

		Ok(self.get_announcement_sigs(node_signer, genesis_block_hash, user_config, best_block.height(), logger))
	}

	/// Returns transaction if there is pending funding transaction that is yet to broadcast
	pub fn unbroadcasted_funding(&self) -> Option<Transaction> {
		if self.channel_state & (ChannelState::FundingCreated as u32) != 0 {
			self.funding_transaction.clone()
		} else {
			None
		}
	}

	/// Returns a HTLCStats about inbound pending htlcs
	fn get_inbound_pending_htlc_stats(&self, outbound_feerate_update: Option<u32>) -> HTLCStats {
		let mut stats = HTLCStats {
			pending_htlcs: self.pending_inbound_htlcs.len() as u32,
			pending_htlcs_value_msat: 0,
			on_counterparty_tx_dust_exposure_msat: 0,
			on_holder_tx_dust_exposure_msat: 0,
			holding_cell_msat: 0,
			on_holder_tx_holding_cell_htlcs_count: 0,
		};

		let (htlc_timeout_dust_limit, htlc_success_dust_limit) = if self.opt_anchors() {
			(0, 0)
		} else {
			let dust_buffer_feerate = self.get_dust_buffer_feerate(outbound_feerate_update) as u64;
			(dust_buffer_feerate * htlc_timeout_tx_weight(false) / 1000,
				dust_buffer_feerate * htlc_success_tx_weight(false) / 1000)
		};
		let counterparty_dust_limit_timeout_sat = htlc_timeout_dust_limit + self.counterparty_dust_limit_satoshis;
		let holder_dust_limit_success_sat = htlc_success_dust_limit + self.holder_dust_limit_satoshis;
		for ref htlc in self.pending_inbound_htlcs.iter() {
			stats.pending_htlcs_value_msat += htlc.amount_msat;
			if htlc.amount_msat / 1000 < counterparty_dust_limit_timeout_sat {
				stats.on_counterparty_tx_dust_exposure_msat += htlc.amount_msat;
			}
			if htlc.amount_msat / 1000 < holder_dust_limit_success_sat {
				stats.on_holder_tx_dust_exposure_msat += htlc.amount_msat;
			}
		}
		stats
	}

	/// Returns a HTLCStats about pending outbound htlcs, *including* pending adds in our holding cell.
	fn get_outbound_pending_htlc_stats(&self, outbound_feerate_update: Option<u32>) -> HTLCStats {
		let mut stats = HTLCStats {
			pending_htlcs: self.pending_outbound_htlcs.len() as u32,
			pending_htlcs_value_msat: 0,
			on_counterparty_tx_dust_exposure_msat: 0,
			on_holder_tx_dust_exposure_msat: 0,
			holding_cell_msat: 0,
			on_holder_tx_holding_cell_htlcs_count: 0,
		};

		let (htlc_timeout_dust_limit, htlc_success_dust_limit) = if self.opt_anchors() {
			(0, 0)
		} else {
			let dust_buffer_feerate = self.get_dust_buffer_feerate(outbound_feerate_update) as u64;
			(dust_buffer_feerate * htlc_timeout_tx_weight(false) / 1000,
				dust_buffer_feerate * htlc_success_tx_weight(false) / 1000)
		};
		let counterparty_dust_limit_success_sat = htlc_success_dust_limit + self.counterparty_dust_limit_satoshis;
		let holder_dust_limit_timeout_sat = htlc_timeout_dust_limit + self.holder_dust_limit_satoshis;
		for ref htlc in self.pending_outbound_htlcs.iter() {
			stats.pending_htlcs_value_msat += htlc.amount_msat;
			if htlc.amount_msat / 1000 < counterparty_dust_limit_success_sat {
				stats.on_counterparty_tx_dust_exposure_msat += htlc.amount_msat;
			}
			if htlc.amount_msat / 1000 < holder_dust_limit_timeout_sat {
				stats.on_holder_tx_dust_exposure_msat += htlc.amount_msat;
			}
		}

		for update in self.holding_cell_htlc_updates.iter() {
			if let &HTLCUpdateAwaitingACK::AddHTLC { ref amount_msat, .. } = update {
				stats.pending_htlcs += 1;
				stats.pending_htlcs_value_msat += amount_msat;
				stats.holding_cell_msat += amount_msat;
				if *amount_msat / 1000 < counterparty_dust_limit_success_sat {
					stats.on_counterparty_tx_dust_exposure_msat += amount_msat;
				}
				if *amount_msat / 1000 < holder_dust_limit_timeout_sat {
					stats.on_holder_tx_dust_exposure_msat += amount_msat;
				} else {
					stats.on_holder_tx_holding_cell_htlcs_count += 1;
				}
			}
		}
		stats
	}

	/// Get the available balances, see [`AvailableBalances`]'s fields for more info.
	/// Doesn't bother handling the
	/// if-we-removed-it-already-but-haven't-fully-resolved-they-can-still-send-an-inbound-HTLC
	/// corner case properly.
	pub fn get_available_balances(&self) -> AvailableBalances {
		// Note that we have to handle overflow due to the above case.
		let outbound_stats = self.get_outbound_pending_htlc_stats(None);

		let mut balance_msat = self.value_to_self_msat;
		for ref htlc in self.pending_inbound_htlcs.iter() {
			if let InboundHTLCState::LocalRemoved(InboundHTLCRemovalReason::Fulfill(_)) = htlc.state {
				balance_msat += htlc.amount_msat;
			}
		}
		balance_msat -= outbound_stats.pending_htlcs_value_msat;

		let outbound_capacity_msat = cmp::max(self.value_to_self_msat as i64
				- outbound_stats.pending_htlcs_value_msat as i64
				- self.counterparty_selected_channel_reserve_satoshis.unwrap_or(0) as i64 * 1000,
			0) as u64;
		AvailableBalances {
			inbound_capacity_msat: cmp::max(self.channel_value_satoshis as i64 * 1000
					- self.value_to_self_msat as i64
					- self.get_inbound_pending_htlc_stats(None).pending_htlcs_value_msat as i64
					- self.holder_selected_channel_reserve_satoshis as i64 * 1000,
				0) as u64,
			outbound_capacity_msat,
			next_outbound_htlc_limit_msat: cmp::max(cmp::min(outbound_capacity_msat as i64,
					self.counterparty_max_htlc_value_in_flight_msat as i64
						- outbound_stats.pending_htlcs_value_msat as i64),
				0) as u64,
			balance_msat,
		}
	}

	pub fn get_holder_counterparty_selected_channel_reserve_satoshis(&self) -> (u64, Option<u64>) {
		(self.holder_selected_channel_reserve_satoshis, self.counterparty_selected_channel_reserve_satoshis)
	}

	// Get the fee cost in MSATS of a commitment tx with a given number of HTLC outputs.
	// Note that num_htlcs should not include dust HTLCs.
	fn commit_tx_fee_msat(feerate_per_kw: u32, num_htlcs: usize, opt_anchors: bool) -> u64 {
		// Note that we need to divide before multiplying to round properly,
		// since the lowest denomination of bitcoin on-chain is the satoshi.
		(commitment_tx_base_weight(opt_anchors) + num_htlcs as u64 * COMMITMENT_TX_WEIGHT_PER_HTLC) * feerate_per_kw as u64 / 1000 * 1000
	}

	// Get the fee cost in SATS of a commitment tx with a given number of HTLC outputs.
	// Note that num_htlcs should not include dust HTLCs.
	#[inline]
	fn commit_tx_fee_sat(feerate_per_kw: u32, num_htlcs: usize, opt_anchors: bool) -> u64 {
		feerate_per_kw as u64 * (commitment_tx_base_weight(opt_anchors) + num_htlcs as u64 * COMMITMENT_TX_WEIGHT_PER_HTLC) / 1000
	}

	// Get the commitment tx fee for the local's (i.e. our) next commitment transaction based on the
	// number of pending HTLCs that are on track to be in our next commitment tx, plus an additional
	// HTLC if `fee_spike_buffer_htlc` is Some, plus a new HTLC given by `new_htlc_amount`. Dust HTLCs
	// are excluded.
	fn next_local_commit_tx_fee_msat(&self, htlc: HTLCCandidate, fee_spike_buffer_htlc: Option<()>) -> u64 {
		assert!(self.is_outbound());

		let (htlc_success_dust_limit, htlc_timeout_dust_limit) = if self.opt_anchors() {
			(0, 0)
		} else {
			(self.feerate_per_kw as u64 * htlc_success_tx_weight(false) / 1000,
				self.feerate_per_kw as u64 * htlc_timeout_tx_weight(false) / 1000)
		};
		let real_dust_limit_success_sat = htlc_success_dust_limit + self.holder_dust_limit_satoshis;
		let real_dust_limit_timeout_sat = htlc_timeout_dust_limit + self.holder_dust_limit_satoshis;

		let mut addl_htlcs = 0;
		if fee_spike_buffer_htlc.is_some() { addl_htlcs += 1; }
		match htlc.origin {
			HTLCInitiator::LocalOffered => {
				if htlc.amount_msat / 1000 >= real_dust_limit_timeout_sat {
					addl_htlcs += 1;
				}
			},
			HTLCInitiator::RemoteOffered => {
				if htlc.amount_msat / 1000 >= real_dust_limit_success_sat {
					addl_htlcs += 1;
				}
			}
		}

		let mut included_htlcs = 0;
		for ref htlc in self.pending_inbound_htlcs.iter() {
			if htlc.amount_msat / 1000 < real_dust_limit_success_sat {
				continue
			}
			// We include LocalRemoved HTLCs here because we may still need to broadcast a commitment
			// transaction including this HTLC if it times out before they RAA.
			included_htlcs += 1;
		}

		for ref htlc in self.pending_outbound_htlcs.iter() {
			if htlc.amount_msat / 1000 < real_dust_limit_timeout_sat {
				continue
			}
			match htlc.state {
				OutboundHTLCState::LocalAnnounced {..} => included_htlcs += 1,
				OutboundHTLCState::Committed => included_htlcs += 1,
				OutboundHTLCState::RemoteRemoved {..} => included_htlcs += 1,
				// We don't include AwaitingRemoteRevokeToRemove HTLCs because our next commitment
				// transaction won't be generated until they send us their next RAA, which will mean
				// dropping any HTLCs in this state.
				_ => {},
			}
		}

		for htlc in self.holding_cell_htlc_updates.iter() {
			match htlc {
				&HTLCUpdateAwaitingACK::AddHTLC { amount_msat, .. } => {
					if amount_msat / 1000 < real_dust_limit_timeout_sat {
						continue
					}
					included_htlcs += 1
				},
				_ => {}, // Don't include claims/fails that are awaiting ack, because once we get the
				         // ack we're guaranteed to never include them in commitment txs anymore.
			}
		}

		let num_htlcs = included_htlcs + addl_htlcs;
		let res = Self::commit_tx_fee_msat(self.feerate_per_kw, num_htlcs, self.opt_anchors());
		#[cfg(any(test, fuzzing))]
		{
			let mut fee = res;
			if fee_spike_buffer_htlc.is_some() {
				fee = Self::commit_tx_fee_msat(self.feerate_per_kw, num_htlcs - 1, self.opt_anchors());
			}
			let total_pending_htlcs = self.pending_inbound_htlcs.len() + self.pending_outbound_htlcs.len()
				+ self.holding_cell_htlc_updates.len();
			let commitment_tx_info = CommitmentTxInfoCached {
				fee,
				total_pending_htlcs,
				next_holder_htlc_id: match htlc.origin {
					HTLCInitiator::LocalOffered => self.next_holder_htlc_id + 1,
					HTLCInitiator::RemoteOffered => self.next_holder_htlc_id,
				},
				next_counterparty_htlc_id: match htlc.origin {
					HTLCInitiator::LocalOffered => self.next_counterparty_htlc_id,
					HTLCInitiator::RemoteOffered => self.next_counterparty_htlc_id + 1,
				},
				feerate: self.feerate_per_kw,
			};
			*self.next_local_commitment_tx_fee_info_cached.lock().unwrap() = Some(commitment_tx_info);
		}
		res
	}

	// Get the commitment tx fee for the remote's next commitment transaction based on the number of
	// pending HTLCs that are on track to be in their next commitment tx, plus an additional HTLC if
	// `fee_spike_buffer_htlc` is Some, plus a new HTLC given by `new_htlc_amount`. Dust HTLCs are
	// excluded.
	fn next_remote_commit_tx_fee_msat(&self, htlc: HTLCCandidate, fee_spike_buffer_htlc: Option<()>) -> u64 {
		assert!(!self.is_outbound());

		let (htlc_success_dust_limit, htlc_timeout_dust_limit) = if self.opt_anchors() {
			(0, 0)
		} else {
			(self.feerate_per_kw as u64 * htlc_success_tx_weight(false) / 1000,
				self.feerate_per_kw as u64 * htlc_timeout_tx_weight(false) / 1000)
		};
		let real_dust_limit_success_sat = htlc_success_dust_limit + self.counterparty_dust_limit_satoshis;
		let real_dust_limit_timeout_sat = htlc_timeout_dust_limit + self.counterparty_dust_limit_satoshis;

		let mut addl_htlcs = 0;
		if fee_spike_buffer_htlc.is_some() { addl_htlcs += 1; }
		match htlc.origin {
			HTLCInitiator::LocalOffered => {
				if htlc.amount_msat / 1000 >= real_dust_limit_success_sat {
					addl_htlcs += 1;
				}
			},
			HTLCInitiator::RemoteOffered => {
				if htlc.amount_msat / 1000 >= real_dust_limit_timeout_sat {
					addl_htlcs += 1;
				}
			}
		}

		// When calculating the set of HTLCs which will be included in their next commitment_signed, all
		// non-dust inbound HTLCs are included (as all states imply it will be included) and only
		// committed outbound HTLCs, see below.
		let mut included_htlcs = 0;
		for ref htlc in self.pending_inbound_htlcs.iter() {
			if htlc.amount_msat / 1000 <= real_dust_limit_timeout_sat {
				continue
			}
			included_htlcs += 1;
		}

		for ref htlc in self.pending_outbound_htlcs.iter() {
			if htlc.amount_msat / 1000 <= real_dust_limit_success_sat {
				continue
			}
			// We only include outbound HTLCs if it will not be included in their next commitment_signed,
			// i.e. if they've responded to us with an RAA after announcement.
			match htlc.state {
				OutboundHTLCState::Committed => included_htlcs += 1,
				OutboundHTLCState::RemoteRemoved {..} => included_htlcs += 1,
				OutboundHTLCState::LocalAnnounced { .. } => included_htlcs += 1,
				_ => {},
			}
		}

		let num_htlcs = included_htlcs + addl_htlcs;
		let res = Self::commit_tx_fee_msat(self.feerate_per_kw, num_htlcs, self.opt_anchors());
		#[cfg(any(test, fuzzing))]
		{
			let mut fee = res;
			if fee_spike_buffer_htlc.is_some() {
				fee = Self::commit_tx_fee_msat(self.feerate_per_kw, num_htlcs - 1, self.opt_anchors());
			}
			let total_pending_htlcs = self.pending_inbound_htlcs.len() + self.pending_outbound_htlcs.len();
			let commitment_tx_info = CommitmentTxInfoCached {
				fee,
				total_pending_htlcs,
				next_holder_htlc_id: match htlc.origin {
					HTLCInitiator::LocalOffered => self.next_holder_htlc_id + 1,
					HTLCInitiator::RemoteOffered => self.next_holder_htlc_id,
				},
				next_counterparty_htlc_id: match htlc.origin {
					HTLCInitiator::LocalOffered => self.next_counterparty_htlc_id,
					HTLCInitiator::RemoteOffered => self.next_counterparty_htlc_id + 1,
				},
				feerate: self.feerate_per_kw,
			};
			*self.next_remote_commitment_tx_fee_info_cached.lock().unwrap() = Some(commitment_tx_info);
		}
		res
	}

	pub fn update_add_htlc<F, L: Deref>(&mut self, msg: &msgs::UpdateAddHTLC, mut pending_forward_status: PendingHTLCStatus, create_pending_htlc_status: F, logger: &L) -> Result<(), ChannelError>
	where F: for<'a> Fn(&'a Self, PendingHTLCStatus, u16) -> PendingHTLCStatus, L::Target: Logger {
		// We can't accept HTLCs sent after we've sent a shutdown.
		let local_sent_shutdown = (self.channel_state & (ChannelState::ChannelReady as u32 | ChannelState::LocalShutdownSent as u32)) != (ChannelState::ChannelReady as u32);
		if local_sent_shutdown {
			pending_forward_status = create_pending_htlc_status(self, pending_forward_status, 0x4000|8);
		}
		// If the remote has sent a shutdown prior to adding this HTLC, then they are in violation of the spec.
		let remote_sent_shutdown = (self.channel_state & (ChannelState::ChannelReady as u32 | ChannelState::RemoteShutdownSent as u32)) != (ChannelState::ChannelReady as u32);
		if remote_sent_shutdown {
			return Err(ChannelError::Close("Got add HTLC message when channel was not in an operational state".to_owned()));
		}
		if self.channel_state & (ChannelState::PeerDisconnected as u32) == ChannelState::PeerDisconnected as u32 {
			return Err(ChannelError::Close("Peer sent update_add_htlc when we needed a channel_reestablish".to_owned()));
		}
		if msg.amount_msat > self.channel_value_satoshis * 1000 {
			return Err(ChannelError::Close("Remote side tried to send more than the total value of the channel".to_owned()));
		}
		if msg.amount_msat == 0 {
			return Err(ChannelError::Close("Remote side tried to send a 0-msat HTLC".to_owned()));
		}
		if msg.amount_msat < self.holder_htlc_minimum_msat {
			return Err(ChannelError::Close(format!("Remote side tried to send less than our minimum HTLC value. Lower limit: ({}). Actual: ({})", self.holder_htlc_minimum_msat, msg.amount_msat)));
		}

		let inbound_stats = self.get_inbound_pending_htlc_stats(None);
		let outbound_stats = self.get_outbound_pending_htlc_stats(None);
		if inbound_stats.pending_htlcs + 1 > OUR_MAX_HTLCS as u32 {
			return Err(ChannelError::Close(format!("Remote tried to push more than our max accepted HTLCs ({})", OUR_MAX_HTLCS)));
		}
		if inbound_stats.pending_htlcs_value_msat + msg.amount_msat > self.holder_max_htlc_value_in_flight_msat {
			return Err(ChannelError::Close(format!("Remote HTLC add would put them over our max HTLC value ({})", self.holder_max_htlc_value_in_flight_msat)));
		}
		// Check holder_selected_channel_reserve_satoshis (we're getting paid, so they have to at least meet
		// the reserve_satoshis we told them to always have as direct payment so that they lose
		// something if we punish them for broadcasting an old state).
		// Note that we don't really care about having a small/no to_remote output in our local
		// commitment transactions, as the purpose of the channel reserve is to ensure we can
		// punish *them* if they misbehave, so we discount any outbound HTLCs which will not be
		// present in the next commitment transaction we send them (at least for fulfilled ones,
		// failed ones won't modify value_to_self).
		// Note that we will send HTLCs which another instance of rust-lightning would think
		// violate the reserve value if we do not do this (as we forget inbound HTLCs from the
		// Channel state once they will not be present in the next received commitment
		// transaction).
		let mut removed_outbound_total_msat = 0;
		for ref htlc in self.pending_outbound_htlcs.iter() {
			if let OutboundHTLCState::AwaitingRemoteRevokeToRemove(OutboundHTLCOutcome::Success(_)) = htlc.state {
				removed_outbound_total_msat += htlc.amount_msat;
			} else if let OutboundHTLCState::AwaitingRemovedRemoteRevoke(OutboundHTLCOutcome::Success(_)) = htlc.state {
				removed_outbound_total_msat += htlc.amount_msat;
			}
		}

		let (htlc_timeout_dust_limit, htlc_success_dust_limit) = if self.opt_anchors() {
			(0, 0)
		} else {
			let dust_buffer_feerate = self.get_dust_buffer_feerate(None) as u64;
			(dust_buffer_feerate * htlc_timeout_tx_weight(false) / 1000,
				dust_buffer_feerate * htlc_success_tx_weight(false) / 1000)
		};
		let exposure_dust_limit_timeout_sats = htlc_timeout_dust_limit + self.counterparty_dust_limit_satoshis;
		if msg.amount_msat / 1000 < exposure_dust_limit_timeout_sats {
			let on_counterparty_tx_dust_htlc_exposure_msat = inbound_stats.on_counterparty_tx_dust_exposure_msat + outbound_stats.on_counterparty_tx_dust_exposure_msat + msg.amount_msat;
			if on_counterparty_tx_dust_htlc_exposure_msat > self.get_max_dust_htlc_exposure_msat() {
				log_info!(logger, "Cannot accept value that would put our exposure to dust HTLCs at {} over the limit {} on counterparty commitment tx",
					on_counterparty_tx_dust_htlc_exposure_msat, self.get_max_dust_htlc_exposure_msat());
				pending_forward_status = create_pending_htlc_status(self, pending_forward_status, 0x1000|7);
			}
		}

		let exposure_dust_limit_success_sats = htlc_success_dust_limit + self.holder_dust_limit_satoshis;
		if msg.amount_msat / 1000 < exposure_dust_limit_success_sats {
			let on_holder_tx_dust_htlc_exposure_msat = inbound_stats.on_holder_tx_dust_exposure_msat + outbound_stats.on_holder_tx_dust_exposure_msat + msg.amount_msat;
			if on_holder_tx_dust_htlc_exposure_msat > self.get_max_dust_htlc_exposure_msat() {
				log_info!(logger, "Cannot accept value that would put our exposure to dust HTLCs at {} over the limit {} on holder commitment tx",
					on_holder_tx_dust_htlc_exposure_msat, self.get_max_dust_htlc_exposure_msat());
				pending_forward_status = create_pending_htlc_status(self, pending_forward_status, 0x1000|7);
			}
		}

		let pending_value_to_self_msat =
			self.value_to_self_msat + inbound_stats.pending_htlcs_value_msat - removed_outbound_total_msat;
		let pending_remote_value_msat =
			self.channel_value_satoshis * 1000 - pending_value_to_self_msat;
		if pending_remote_value_msat < msg.amount_msat {
			return Err(ChannelError::Close("Remote HTLC add would overdraw remaining funds".to_owned()));
		}

		// Check that the remote can afford to pay for this HTLC on-chain at the current
		// feerate_per_kw, while maintaining their channel reserve (as required by the spec).
		let remote_commit_tx_fee_msat = if self.is_outbound() { 0 } else {
			let htlc_candidate = HTLCCandidate::new(msg.amount_msat, HTLCInitiator::RemoteOffered);
			self.next_remote_commit_tx_fee_msat(htlc_candidate, None) // Don't include the extra fee spike buffer HTLC in calculations
		};
		if pending_remote_value_msat - msg.amount_msat < remote_commit_tx_fee_msat {
			return Err(ChannelError::Close("Remote HTLC add would not leave enough to pay for fees".to_owned()));
		};

		if pending_remote_value_msat - msg.amount_msat - remote_commit_tx_fee_msat < self.holder_selected_channel_reserve_satoshis * 1000 {
			return Err(ChannelError::Close("Remote HTLC add would put them under remote reserve value".to_owned()));
		}

		if !self.is_outbound() {
			// `2 *` and `Some(())` is for the fee spike buffer we keep for the remote. This deviates from
			// the spec because in the spec, the fee spike buffer requirement doesn't exist on the
			// receiver's side, only on the sender's.
			// Note that when we eventually remove support for fee updates and switch to anchor output
			// fees, we will drop the `2 *`, since we no longer be as sensitive to fee spikes. But, keep
			// the extra htlc when calculating the next remote commitment transaction fee as we should
			// still be able to afford adding this HTLC plus one more future HTLC, regardless of being
			// sensitive to fee spikes.
			let htlc_candidate = HTLCCandidate::new(msg.amount_msat, HTLCInitiator::RemoteOffered);
			let remote_fee_cost_incl_stuck_buffer_msat = 2 * self.next_remote_commit_tx_fee_msat(htlc_candidate, Some(()));
			if pending_remote_value_msat - msg.amount_msat - self.holder_selected_channel_reserve_satoshis * 1000 < remote_fee_cost_incl_stuck_buffer_msat {
				// Note that if the pending_forward_status is not updated here, then it's because we're already failing
				// the HTLC, i.e. its status is already set to failing.
				log_info!(logger, "Attempting to fail HTLC due to fee spike buffer violation in channel {}. Rebalancing is required.", log_bytes!(self.channel_id()));
				pending_forward_status = create_pending_htlc_status(self, pending_forward_status, 0x1000|7);
			}
		} else {
			// Check that they won't violate our local required channel reserve by adding this HTLC.
			let htlc_candidate = HTLCCandidate::new(msg.amount_msat, HTLCInitiator::RemoteOffered);
			let local_commit_tx_fee_msat = self.next_local_commit_tx_fee_msat(htlc_candidate, None);
			if self.value_to_self_msat < self.counterparty_selected_channel_reserve_satoshis.unwrap() * 1000 + local_commit_tx_fee_msat {
				return Err(ChannelError::Close("Cannot accept HTLC that would put our balance under counterparty-announced channel reserve value".to_owned()));
			}
		}
		if self.next_counterparty_htlc_id != msg.htlc_id {
			return Err(ChannelError::Close(format!("Remote skipped HTLC ID (skipped ID: {})", self.next_counterparty_htlc_id)));
		}
		if msg.cltv_expiry >= 500000000 {
			return Err(ChannelError::Close("Remote provided CLTV expiry in seconds instead of block height".to_owned()));
		}

		if self.channel_state & ChannelState::LocalShutdownSent as u32 != 0 {
			if let PendingHTLCStatus::Forward(_) = pending_forward_status {
				panic!("ChannelManager shouldn't be trying to add a forwardable HTLC after we've started closing");
			}
		}

		// Now update local state:
		self.next_counterparty_htlc_id += 1;
		self.pending_inbound_htlcs.push(InboundHTLCOutput {
			htlc_id: msg.htlc_id,
			amount_msat: msg.amount_msat,
			payment_hash: msg.payment_hash,
			cltv_expiry: msg.cltv_expiry,
			state: InboundHTLCState::RemoteAnnounced(pending_forward_status),
		});
		Ok(())
	}

	/// Marks an outbound HTLC which we have received update_fail/fulfill/malformed
	#[inline]
	fn mark_outbound_htlc_removed(&mut self, htlc_id: u64, check_preimage: Option<PaymentPreimage>, fail_reason: Option<HTLCFailReason>) -> Result<&OutboundHTLCOutput, ChannelError> {
		assert!(!(check_preimage.is_some() && fail_reason.is_some()), "cannot fail while we have a preimage");
		for htlc in self.pending_outbound_htlcs.iter_mut() {
			if htlc.htlc_id == htlc_id {
				let outcome = match check_preimage {
					None => fail_reason.into(),
					Some(payment_preimage) => {
						let payment_hash = PaymentHash(Sha256::hash(&payment_preimage.0[..]).into_inner());
						if payment_hash != htlc.payment_hash {
							return Err(ChannelError::Close(format!("Remote tried to fulfill HTLC ({}) with an incorrect preimage", htlc_id)));
						}
						OutboundHTLCOutcome::Success(Some(payment_preimage))
					}
				};
				match htlc.state {
					OutboundHTLCState::LocalAnnounced(_) =>
						return Err(ChannelError::Close(format!("Remote tried to fulfill/fail HTLC ({}) before it had been committed", htlc_id))),
					OutboundHTLCState::Committed => {
						htlc.state = OutboundHTLCState::RemoteRemoved(outcome);
					},
					OutboundHTLCState::AwaitingRemoteRevokeToRemove(_) | OutboundHTLCState::AwaitingRemovedRemoteRevoke(_) | OutboundHTLCState::RemoteRemoved(_) =>
						return Err(ChannelError::Close(format!("Remote tried to fulfill/fail HTLC ({}) that they'd already fulfilled/failed", htlc_id))),
				}
				return Ok(htlc);
			}
		}
		Err(ChannelError::Close("Remote tried to fulfill/fail an HTLC we couldn't find".to_owned()))
	}

	pub fn update_fulfill_htlc(&mut self, msg: &msgs::UpdateFulfillHTLC) -> Result<(HTLCSource, u64), ChannelError> {
		if (self.channel_state & (ChannelState::ChannelReady as u32)) != (ChannelState::ChannelReady as u32) {
			return Err(ChannelError::Close("Got fulfill HTLC message when channel was not in an operational state".to_owned()));
		}
		if self.channel_state & (ChannelState::PeerDisconnected as u32) == ChannelState::PeerDisconnected as u32 {
			return Err(ChannelError::Close("Peer sent update_fulfill_htlc when we needed a channel_reestablish".to_owned()));
		}

		self.mark_outbound_htlc_removed(msg.htlc_id, Some(msg.payment_preimage), None).map(|htlc| (htlc.source.clone(), htlc.amount_msat))
	}

	pub fn update_fail_htlc(&mut self, msg: &msgs::UpdateFailHTLC, fail_reason: HTLCFailReason) -> Result<(), ChannelError> {
		if (self.channel_state & (ChannelState::ChannelReady as u32)) != (ChannelState::ChannelReady as u32) {
			return Err(ChannelError::Close("Got fail HTLC message when channel was not in an operational state".to_owned()));
		}
		if self.channel_state & (ChannelState::PeerDisconnected as u32) == ChannelState::PeerDisconnected as u32 {
			return Err(ChannelError::Close("Peer sent update_fail_htlc when we needed a channel_reestablish".to_owned()));
		}

		self.mark_outbound_htlc_removed(msg.htlc_id, None, Some(fail_reason))?;
		Ok(())
	}

	pub fn update_fail_malformed_htlc(&mut self, msg: &msgs::UpdateFailMalformedHTLC, fail_reason: HTLCFailReason) -> Result<(), ChannelError> {
		if (self.channel_state & (ChannelState::ChannelReady as u32)) != (ChannelState::ChannelReady as u32) {
			return Err(ChannelError::Close("Got fail malformed HTLC message when channel was not in an operational state".to_owned()));
		}
		if self.channel_state & (ChannelState::PeerDisconnected as u32) == ChannelState::PeerDisconnected as u32 {
			return Err(ChannelError::Close("Peer sent update_fail_malformed_htlc when we needed a channel_reestablish".to_owned()));
		}

		self.mark_outbound_htlc_removed(msg.htlc_id, None, Some(fail_reason))?;
		Ok(())
	}

	pub fn commitment_signed<L: Deref>(&mut self, msg: &msgs::CommitmentSigned, logger: &L) -> Result<&ChannelMonitorUpdate, ChannelError>
		where L::Target: Logger
	{
		if (self.channel_state & (ChannelState::ChannelReady as u32)) != (ChannelState::ChannelReady as u32) {
			return Err(ChannelError::Close("Got commitment signed message when channel was not in an operational state".to_owned()));
		}
		if self.channel_state & (ChannelState::PeerDisconnected as u32) == ChannelState::PeerDisconnected as u32 {
			return Err(ChannelError::Close("Peer sent commitment_signed when we needed a channel_reestablish".to_owned()));
		}
		if self.channel_state & BOTH_SIDES_SHUTDOWN_MASK == BOTH_SIDES_SHUTDOWN_MASK && self.last_sent_closing_fee.is_some() {
			return Err(ChannelError::Close("Peer sent commitment_signed after we'd started exchanging closing_signeds".to_owned()));
		}

		let funding_script = self.get_funding_redeemscript();

		let keys = self.build_holder_transaction_keys(self.cur_holder_commitment_transaction_number);

		let commitment_stats = self.build_commitment_transaction(self.cur_holder_commitment_transaction_number, &keys, true, false, logger);
		let commitment_txid = {
			let trusted_tx = commitment_stats.tx.trust();
			let bitcoin_tx = trusted_tx.built_transaction();
			let sighash = bitcoin_tx.get_sighash_all(&funding_script, self.channel_value_satoshis);

			log_trace!(logger, "Checking commitment tx signature {} by key {} against tx {} (sighash {}) with redeemscript {} in channel {}",
				log_bytes!(msg.signature.serialize_compact()[..]),
				log_bytes!(self.counterparty_funding_pubkey().serialize()), encode::serialize_hex(&bitcoin_tx.transaction),
				log_bytes!(sighash[..]), encode::serialize_hex(&funding_script), log_bytes!(self.channel_id()));
			if let Err(_) = self.secp_ctx.verify_ecdsa(&sighash, &msg.signature, &self.counterparty_funding_pubkey()) {
				return Err(ChannelError::Close("Invalid commitment tx signature from peer".to_owned()));
			}
			bitcoin_tx.txid
		};
		let mut htlcs_cloned: Vec<_> = commitment_stats.htlcs_included.iter().map(|htlc| (htlc.0.clone(), htlc.1.map(|h| h.clone()))).collect();

		// If our counterparty updated the channel fee in this commitment transaction, check that
		// they can actually afford the new fee now.
		let update_fee = if let Some((_, update_state)) = self.pending_update_fee {
			update_state == FeeUpdateState::RemoteAnnounced
		} else { false };
		if update_fee {
			debug_assert!(!self.is_outbound());
			let counterparty_reserve_we_require_msat = self.holder_selected_channel_reserve_satoshis * 1000;
			if commitment_stats.remote_balance_msat < commitment_stats.total_fee_sat * 1000 + counterparty_reserve_we_require_msat {
				return Err(ChannelError::Close("Funding remote cannot afford proposed new fee".to_owned()));
			}
		}
		#[cfg(any(test, fuzzing))]
		{
			if self.is_outbound() {
				let projected_commit_tx_info = self.next_local_commitment_tx_fee_info_cached.lock().unwrap().take();
				*self.next_remote_commitment_tx_fee_info_cached.lock().unwrap() = None;
				if let Some(info) = projected_commit_tx_info {
					let total_pending_htlcs = self.pending_inbound_htlcs.len() + self.pending_outbound_htlcs.len()
						+ self.holding_cell_htlc_updates.len();
					if info.total_pending_htlcs == total_pending_htlcs
						&& info.next_holder_htlc_id == self.next_holder_htlc_id
						&& info.next_counterparty_htlc_id == self.next_counterparty_htlc_id
						&& info.feerate == self.feerate_per_kw {
							assert_eq!(commitment_stats.total_fee_sat, info.fee / 1000);
						}
				}
			}
		}

		if msg.htlc_signatures.len() != commitment_stats.num_nondust_htlcs {
			return Err(ChannelError::Close(format!("Got wrong number of HTLC signatures ({}) from remote. It must be {}", msg.htlc_signatures.len(), commitment_stats.num_nondust_htlcs)));
		}

		// TODO: Sadly, we pass HTLCs twice to ChannelMonitor: once via the HolderCommitmentTransaction and once via the update
		let mut htlcs_and_sigs = Vec::with_capacity(htlcs_cloned.len());
		for (idx, (htlc, source)) in htlcs_cloned.drain(..).enumerate() {
			if let Some(_) = htlc.transaction_output_index {
				let htlc_tx = chan_utils::build_htlc_transaction(&commitment_txid, commitment_stats.feerate_per_kw,
					self.get_counterparty_selected_contest_delay().unwrap(), &htlc, self.opt_anchors(),
					false, &keys.broadcaster_delayed_payment_key, &keys.revocation_key);

				let htlc_redeemscript = chan_utils::get_htlc_redeemscript(&htlc, self.opt_anchors(), &keys);
				let htlc_sighashtype = if self.opt_anchors() { EcdsaSighashType::SinglePlusAnyoneCanPay } else { EcdsaSighashType::All };
				let htlc_sighash = hash_to_message!(&sighash::SighashCache::new(&htlc_tx).segwit_signature_hash(0, &htlc_redeemscript, htlc.amount_msat / 1000, htlc_sighashtype).unwrap()[..]);
				log_trace!(logger, "Checking HTLC tx signature {} by key {} against tx {} (sighash {}) with redeemscript {} in channel {}.",
					log_bytes!(msg.htlc_signatures[idx].serialize_compact()[..]), log_bytes!(keys.countersignatory_htlc_key.serialize()),
					encode::serialize_hex(&htlc_tx), log_bytes!(htlc_sighash[..]), encode::serialize_hex(&htlc_redeemscript), log_bytes!(self.channel_id()));
				if let Err(_) = self.secp_ctx.verify_ecdsa(&htlc_sighash, &msg.htlc_signatures[idx], &keys.countersignatory_htlc_key) {
					return Err(ChannelError::Close("Invalid HTLC tx signature from peer".to_owned()));
				}
				htlcs_and_sigs.push((htlc, Some(msg.htlc_signatures[idx]), source));
			} else {
				htlcs_and_sigs.push((htlc, None, source));
			}
		}

		let holder_commitment_tx = HolderCommitmentTransaction::new(
			commitment_stats.tx,
			msg.signature,
			msg.htlc_signatures.clone(),
			&self.get_holder_pubkeys().funding_pubkey,
			self.counterparty_funding_pubkey()
		);

		self.holder_signer.validate_holder_commitment(&holder_commitment_tx, commitment_stats.preimages)
			.map_err(|_| ChannelError::Close("Failed to validate our commitment".to_owned()))?;

		// Update state now that we've passed all the can-fail calls...
		let mut need_commitment = false;
		if let &mut Some((_, ref mut update_state)) = &mut self.pending_update_fee {
			if *update_state == FeeUpdateState::RemoteAnnounced {
				*update_state = FeeUpdateState::AwaitingRemoteRevokeToAnnounce;
				need_commitment = true;
			}
		}

		for htlc in self.pending_inbound_htlcs.iter_mut() {
			let new_forward = if let &InboundHTLCState::RemoteAnnounced(ref forward_info) = &htlc.state {
				Some(forward_info.clone())
			} else { None };
			if let Some(forward_info) = new_forward {
				log_trace!(logger, "Updating HTLC {} to AwaitingRemoteRevokeToAnnounce due to commitment_signed in channel {}.",
					log_bytes!(htlc.payment_hash.0), log_bytes!(self.channel_id));
				htlc.state = InboundHTLCState::AwaitingRemoteRevokeToAnnounce(forward_info);
				need_commitment = true;
			}
		}
		let mut claimed_htlcs = Vec::new();
		for htlc in self.pending_outbound_htlcs.iter_mut() {
			if let &mut OutboundHTLCState::RemoteRemoved(ref mut outcome) = &mut htlc.state {
				log_trace!(logger, "Updating HTLC {} to AwaitingRemoteRevokeToRemove due to commitment_signed in channel {}.",
					log_bytes!(htlc.payment_hash.0), log_bytes!(self.channel_id));
				// Grab the preimage, if it exists, instead of cloning
				let mut reason = OutboundHTLCOutcome::Success(None);
				mem::swap(outcome, &mut reason);
				if let OutboundHTLCOutcome::Success(Some(preimage)) = reason {
					// If a user (a) receives an HTLC claim using LDK 0.0.104 or before, then (b)
					// upgrades to LDK 0.0.114 or later before the HTLC is fully resolved, we could
					// have a `Success(None)` reason. In this case we could forget some HTLC
					// claims, but such an upgrade is unlikely and including claimed HTLCs here
					// fixes a bug which the user was exposed to on 0.0.104 when they started the
					// claim anyway.
					claimed_htlcs.push((SentHTLCId::from_source(&htlc.source), preimage));
				}
				htlc.state = OutboundHTLCState::AwaitingRemoteRevokeToRemove(reason);
				need_commitment = true;
			}
		}

		self.latest_monitor_update_id += 1;
		let mut monitor_update = ChannelMonitorUpdate {
			update_id: self.latest_monitor_update_id,
			updates: vec![ChannelMonitorUpdateStep::LatestHolderCommitmentTXInfo {
				commitment_tx: holder_commitment_tx,
				htlc_outputs: htlcs_and_sigs,
				claimed_htlcs,
			}]
		};

		self.cur_holder_commitment_transaction_number -= 1;
		// Note that if we need_commitment & !AwaitingRemoteRevoke we'll call
		// build_commitment_no_status_check() next which will reset this to RAAFirst.
		self.resend_order = RAACommitmentOrder::CommitmentFirst;

		if (self.channel_state & ChannelState::MonitorUpdateInProgress as u32) != 0 {
			// In case we initially failed monitor updating without requiring a response, we need
			// to make sure the RAA gets sent first.
			self.monitor_pending_revoke_and_ack = true;
			if need_commitment && (self.channel_state & (ChannelState::AwaitingRemoteRevoke as u32)) == 0 {
				// If we were going to send a commitment_signed after the RAA, go ahead and do all
				// the corresponding HTLC status updates so that get_last_commitment_update
				// includes the right HTLCs.
				self.monitor_pending_commitment_signed = true;
				let mut additional_update = self.build_commitment_no_status_check(logger);
				// build_commitment_no_status_check may bump latest_monitor_id but we want them to be
				// strictly increasing by one, so decrement it here.
				self.latest_monitor_update_id = monitor_update.update_id;
				monitor_update.updates.append(&mut additional_update.updates);
			}
			log_debug!(logger, "Received valid commitment_signed from peer in channel {}, updated HTLC state but awaiting a monitor update resolution to reply.",
				log_bytes!(self.channel_id));
			self.pending_monitor_updates.push(monitor_update);
			return Ok(self.pending_monitor_updates.last().unwrap());
		}

		let need_commitment_signed = if need_commitment && (self.channel_state & (ChannelState::AwaitingRemoteRevoke as u32)) == 0 {
			// If we're AwaitingRemoteRevoke we can't send a new commitment here, but that's ok -
			// we'll send one right away when we get the revoke_and_ack when we
			// free_holding_cell_htlcs().
			let mut additional_update = self.build_commitment_no_status_check(logger);
			// build_commitment_no_status_check may bump latest_monitor_id but we want them to be
			// strictly increasing by one, so decrement it here.
			self.latest_monitor_update_id = monitor_update.update_id;
			monitor_update.updates.append(&mut additional_update.updates);
			true
		} else { false };

		log_debug!(logger, "Received valid commitment_signed from peer in channel {}, updating HTLC state and responding with{} a revoke_and_ack.",
			log_bytes!(self.channel_id()), if need_commitment_signed { " our own commitment_signed and" } else { "" });
		self.pending_monitor_updates.push(monitor_update);
		self.monitor_updating_paused(true, need_commitment_signed, false, Vec::new(), Vec::new(), Vec::new());
		return Ok(self.pending_monitor_updates.last().unwrap());
	}

	/// Public version of the below, checking relevant preconditions first.
	/// If we're not in a state where freeing the holding cell makes sense, this is a no-op and
	/// returns `(None, Vec::new())`.
	pub fn maybe_free_holding_cell_htlcs<L: Deref>(&mut self, logger: &L) -> (Option<&ChannelMonitorUpdate>, Vec<(HTLCSource, PaymentHash)>) where L::Target: Logger {
		if self.channel_state >= ChannelState::ChannelReady as u32 &&
		   (self.channel_state & (ChannelState::AwaitingRemoteRevoke as u32 | ChannelState::PeerDisconnected as u32 | ChannelState::MonitorUpdateInProgress as u32)) == 0 {
			self.free_holding_cell_htlcs(logger)
		} else { (None, Vec::new()) }
	}

	/// Frees any pending commitment updates in the holding cell, generating the relevant messages
	/// for our counterparty.
	fn free_holding_cell_htlcs<L: Deref>(&mut self, logger: &L) -> (Option<&ChannelMonitorUpdate>, Vec<(HTLCSource, PaymentHash)>) where L::Target: Logger {
		assert_eq!(self.channel_state & ChannelState::MonitorUpdateInProgress as u32, 0);
		if self.holding_cell_htlc_updates.len() != 0 || self.holding_cell_update_fee.is_some() {
			log_trace!(logger, "Freeing holding cell with {} HTLC updates{} in channel {}", self.holding_cell_htlc_updates.len(),
				if self.holding_cell_update_fee.is_some() { " and a fee update" } else { "" }, log_bytes!(self.channel_id()));

			let mut monitor_update = ChannelMonitorUpdate {
				update_id: self.latest_monitor_update_id + 1, // We don't increment this yet!
				updates: Vec::new(),
			};

			let mut htlc_updates = Vec::new();
			mem::swap(&mut htlc_updates, &mut self.holding_cell_htlc_updates);
			let mut update_add_htlcs = Vec::with_capacity(htlc_updates.len());
			let mut update_fulfill_htlcs = Vec::with_capacity(htlc_updates.len());
			let mut update_fail_htlcs = Vec::with_capacity(htlc_updates.len());
			let mut htlcs_to_fail = Vec::new();
			for htlc_update in htlc_updates.drain(..) {
				// Note that this *can* fail, though it should be due to rather-rare conditions on
				// fee races with adding too many outputs which push our total payments just over
				// the limit. In case it's less rare than I anticipate, we may want to revisit
				// handling this case better and maybe fulfilling some of the HTLCs while attempting
				// to rebalance channels.
				match &htlc_update {
					&HTLCUpdateAwaitingACK::AddHTLC {amount_msat, cltv_expiry, ref payment_hash, ref source, ref onion_routing_packet, ..} => {
						match self.send_htlc(amount_msat, *payment_hash, cltv_expiry, source.clone(), onion_routing_packet.clone(), false, logger) {
							Ok(update_add_msg_option) => update_add_htlcs.push(update_add_msg_option.unwrap()),
							Err(e) => {
								match e {
									ChannelError::Ignore(ref msg) => {
										log_info!(logger, "Failed to send HTLC with payment_hash {} due to {} in channel {}",
											log_bytes!(payment_hash.0), msg, log_bytes!(self.channel_id()));
										// If we fail to send here, then this HTLC should
										// be failed backwards. Failing to send here
										// indicates that this HTLC may keep being put back
										// into the holding cell without ever being
										// successfully forwarded/failed/fulfilled, causing
										// our counterparty to eventually close on us.
										htlcs_to_fail.push((source.clone(), *payment_hash));
									},
									_ => {
										panic!("Got a non-IgnoreError action trying to send holding cell HTLC");
									},
								}
							}
						}
					},
					&HTLCUpdateAwaitingACK::ClaimHTLC { ref payment_preimage, htlc_id, .. } => {
						// If an HTLC claim was previously added to the holding cell (via
						// `get_update_fulfill_htlc`, then generating the claim message itself must
						// not fail - any in between attempts to claim the HTLC will have resulted
						// in it hitting the holding cell again and we cannot change the state of a
						// holding cell HTLC from fulfill to anything else.
						let (update_fulfill_msg_option, mut additional_monitor_update) =
							if let UpdateFulfillFetch::NewClaim { msg, monitor_update, .. } = self.get_update_fulfill_htlc(htlc_id, *payment_preimage, logger) {
								(msg, monitor_update)
							} else { unreachable!() };
						update_fulfill_htlcs.push(update_fulfill_msg_option.unwrap());
						monitor_update.updates.append(&mut additional_monitor_update.updates);
					},
					&HTLCUpdateAwaitingACK::FailHTLC { htlc_id, ref err_packet } => {
						match self.fail_htlc(htlc_id, err_packet.clone(), false, logger) {
							Ok(update_fail_msg_option) => {
								// If an HTLC failure was previously added to the holding cell (via
								// `queue_fail_htlc`) then generating the fail message itself must
								// not fail - we should never end up in a state where we double-fail
								// an HTLC or fail-then-claim an HTLC as it indicates we didn't wait
								// for a full revocation before failing.
								update_fail_htlcs.push(update_fail_msg_option.unwrap())
							},
							Err(e) => {
								if let ChannelError::Ignore(_) = e {}
								else {
									panic!("Got a non-IgnoreError action trying to fail holding cell HTLC");
								}
							}
						}
					},
				}
			}
			if update_add_htlcs.is_empty() && update_fulfill_htlcs.is_empty() && update_fail_htlcs.is_empty() && self.holding_cell_update_fee.is_none() {
				return (None, htlcs_to_fail);
			}
			let update_fee = if let Some(feerate) = self.holding_cell_update_fee.take() {
				self.send_update_fee(feerate, false, logger)
			} else {
				None
			};

			let mut additional_update = self.build_commitment_no_status_check(logger);
			// build_commitment_no_status_check and get_update_fulfill_htlc may bump latest_monitor_id
			// but we want them to be strictly increasing by one, so reset it here.
			self.latest_monitor_update_id = monitor_update.update_id;
			monitor_update.updates.append(&mut additional_update.updates);

			log_debug!(logger, "Freeing holding cell in channel {} resulted in {}{} HTLCs added, {} HTLCs fulfilled, and {} HTLCs failed.",
				log_bytes!(self.channel_id()), if update_fee.is_some() { "a fee update, " } else { "" },
				update_add_htlcs.len(), update_fulfill_htlcs.len(), update_fail_htlcs.len());

			self.monitor_updating_paused(false, true, false, Vec::new(), Vec::new(), Vec::new());
			self.pending_monitor_updates.push(monitor_update);
			(Some(self.pending_monitor_updates.last().unwrap()), htlcs_to_fail)
		} else {
			(None, Vec::new())
		}
	}

	/// Handles receiving a remote's revoke_and_ack. Note that we may return a new
	/// commitment_signed message here in case we had pending outbound HTLCs to add which were
	/// waiting on this revoke_and_ack. The generation of this new commitment_signed may also fail,
	/// generating an appropriate error *after* the channel state has been updated based on the
	/// revoke_and_ack message.
	pub fn revoke_and_ack<L: Deref>(&mut self, msg: &msgs::RevokeAndACK, logger: &L) -> Result<(Vec<(HTLCSource, PaymentHash)>, &ChannelMonitorUpdate), ChannelError>
		where L::Target: Logger,
	{
		if (self.channel_state & (ChannelState::ChannelReady as u32)) != (ChannelState::ChannelReady as u32) {
			return Err(ChannelError::Close("Got revoke/ACK message when channel was not in an operational state".to_owned()));
		}
		if self.channel_state & (ChannelState::PeerDisconnected as u32) == ChannelState::PeerDisconnected as u32 {
			return Err(ChannelError::Close("Peer sent revoke_and_ack when we needed a channel_reestablish".to_owned()));
		}
		if self.channel_state & BOTH_SIDES_SHUTDOWN_MASK == BOTH_SIDES_SHUTDOWN_MASK && self.last_sent_closing_fee.is_some() {
			return Err(ChannelError::Close("Peer sent revoke_and_ack after we'd started exchanging closing_signeds".to_owned()));
		}

		let secret = secp_check!(SecretKey::from_slice(&msg.per_commitment_secret), "Peer provided an invalid per_commitment_secret".to_owned());

		if let Some(counterparty_prev_commitment_point) = self.counterparty_prev_commitment_point {
			if PublicKey::from_secret_key(&self.secp_ctx, &secret) != counterparty_prev_commitment_point {
				return Err(ChannelError::Close("Got a revoke commitment secret which didn't correspond to their current pubkey".to_owned()));
			}
		}

		if self.channel_state & ChannelState::AwaitingRemoteRevoke as u32 == 0 {
			// Our counterparty seems to have burned their coins to us (by revoking a state when we
			// haven't given them a new commitment transaction to broadcast). We should probably
			// take advantage of this by updating our channel monitor, sending them an error, and
			// waiting for them to broadcast their latest (now-revoked claim). But, that would be a
			// lot of work, and there's some chance this is all a misunderstanding anyway.
			// We have to do *something*, though, since our signer may get mad at us for otherwise
			// jumping a remote commitment number, so best to just force-close and move on.
			return Err(ChannelError::Close("Received an unexpected revoke_and_ack".to_owned()));
		}

		#[cfg(any(test, fuzzing))]
		{
			*self.next_local_commitment_tx_fee_info_cached.lock().unwrap() = None;
			*self.next_remote_commitment_tx_fee_info_cached.lock().unwrap() = None;
		}

		self.holder_signer.validate_counterparty_revocation(
			self.cur_counterparty_commitment_transaction_number + 1,
			&secret
		).map_err(|_| ChannelError::Close("Failed to validate revocation from peer".to_owned()))?;

		self.commitment_secrets.provide_secret(self.cur_counterparty_commitment_transaction_number + 1, msg.per_commitment_secret)
			.map_err(|_| ChannelError::Close("Previous secrets did not match new one".to_owned()))?;
		self.latest_monitor_update_id += 1;
		let mut monitor_update = ChannelMonitorUpdate {
			update_id: self.latest_monitor_update_id,
			updates: vec![ChannelMonitorUpdateStep::CommitmentSecret {
				idx: self.cur_counterparty_commitment_transaction_number + 1,
				secret: msg.per_commitment_secret,
			}],
		};

		// Update state now that we've passed all the can-fail calls...
		// (note that we may still fail to generate the new commitment_signed message, but that's
		// OK, we step the channel here and *then* if the new generation fails we can fail the
		// channel based on that, but stepping stuff here should be safe either way.
		self.channel_state &= !(ChannelState::AwaitingRemoteRevoke as u32);
		self.counterparty_prev_commitment_point = self.counterparty_cur_commitment_point;
		self.counterparty_cur_commitment_point = Some(msg.next_per_commitment_point);
		self.cur_counterparty_commitment_transaction_number -= 1;

		if self.announcement_sigs_state == AnnouncementSigsState::Committed {
			self.announcement_sigs_state = AnnouncementSigsState::PeerReceived;
		}

		log_trace!(logger, "Updating HTLCs on receipt of RAA in channel {}...", log_bytes!(self.channel_id()));
		let mut to_forward_infos = Vec::new();
		let mut revoked_htlcs = Vec::new();
		let mut finalized_claimed_htlcs = Vec::new();
		let mut update_fail_htlcs = Vec::new();
		let mut update_fail_malformed_htlcs = Vec::new();
		let mut require_commitment = false;
		let mut value_to_self_msat_diff: i64 = 0;

		{
			// Take references explicitly so that we can hold multiple references to self.
			let pending_inbound_htlcs: &mut Vec<_> = &mut self.pending_inbound_htlcs;
			let pending_outbound_htlcs: &mut Vec<_> = &mut self.pending_outbound_htlcs;

			// We really shouldnt have two passes here, but retain gives a non-mutable ref (Rust bug)
			pending_inbound_htlcs.retain(|htlc| {
				if let &InboundHTLCState::LocalRemoved(ref reason) = &htlc.state {
					log_trace!(logger, " ...removing inbound LocalRemoved {}", log_bytes!(htlc.payment_hash.0));
					if let &InboundHTLCRemovalReason::Fulfill(_) = reason {
						value_to_self_msat_diff += htlc.amount_msat as i64;
					}
					false
				} else { true }
			});
			pending_outbound_htlcs.retain(|htlc| {
				if let &OutboundHTLCState::AwaitingRemovedRemoteRevoke(ref outcome) = &htlc.state {
					log_trace!(logger, " ...removing outbound AwaitingRemovedRemoteRevoke {}", log_bytes!(htlc.payment_hash.0));
					if let OutboundHTLCOutcome::Failure(reason) = outcome.clone() { // We really want take() here, but, again, non-mut ref :(
						revoked_htlcs.push((htlc.source.clone(), htlc.payment_hash, reason));
					} else {
						finalized_claimed_htlcs.push(htlc.source.clone());
						// They fulfilled, so we sent them money
						value_to_self_msat_diff -= htlc.amount_msat as i64;
					}
					false
				} else { true }
			});
			for htlc in pending_inbound_htlcs.iter_mut() {
				let swap = if let &InboundHTLCState::AwaitingRemoteRevokeToAnnounce(_) = &htlc.state {
					true
				} else if let &InboundHTLCState::AwaitingAnnouncedRemoteRevoke(_) = &htlc.state {
					true
				} else { false };
				if swap {
					let mut state = InboundHTLCState::Committed;
					mem::swap(&mut state, &mut htlc.state);

					if let InboundHTLCState::AwaitingRemoteRevokeToAnnounce(forward_info) = state {
						log_trace!(logger, " ...promoting inbound AwaitingRemoteRevokeToAnnounce {} to AwaitingAnnouncedRemoteRevoke", log_bytes!(htlc.payment_hash.0));
						htlc.state = InboundHTLCState::AwaitingAnnouncedRemoteRevoke(forward_info);
						require_commitment = true;
					} else if let InboundHTLCState::AwaitingAnnouncedRemoteRevoke(forward_info) = state {
						match forward_info {
							PendingHTLCStatus::Fail(fail_msg) => {
								log_trace!(logger, " ...promoting inbound AwaitingAnnouncedRemoteRevoke {} to LocalRemoved due to PendingHTLCStatus indicating failure", log_bytes!(htlc.payment_hash.0));
								require_commitment = true;
								match fail_msg {
									HTLCFailureMsg::Relay(msg) => {
										htlc.state = InboundHTLCState::LocalRemoved(InboundHTLCRemovalReason::FailRelay(msg.reason.clone()));
										update_fail_htlcs.push(msg)
									},
									HTLCFailureMsg::Malformed(msg) => {
										htlc.state = InboundHTLCState::LocalRemoved(InboundHTLCRemovalReason::FailMalformed((msg.sha256_of_onion, msg.failure_code)));
										update_fail_malformed_htlcs.push(msg)
									},
								}
							},
							PendingHTLCStatus::Forward(forward_info) => {
								log_trace!(logger, " ...promoting inbound AwaitingAnnouncedRemoteRevoke {} to Committed", log_bytes!(htlc.payment_hash.0));
								to_forward_infos.push((forward_info, htlc.htlc_id));
								htlc.state = InboundHTLCState::Committed;
							}
						}
					}
				}
			}
			for htlc in pending_outbound_htlcs.iter_mut() {
				if let OutboundHTLCState::LocalAnnounced(_) = htlc.state {
					log_trace!(logger, " ...promoting outbound LocalAnnounced {} to Committed", log_bytes!(htlc.payment_hash.0));
					htlc.state = OutboundHTLCState::Committed;
				}
				if let &mut OutboundHTLCState::AwaitingRemoteRevokeToRemove(ref mut outcome) = &mut htlc.state {
					log_trace!(logger, " ...promoting outbound AwaitingRemoteRevokeToRemove {} to AwaitingRemovedRemoteRevoke", log_bytes!(htlc.payment_hash.0));
					// Grab the preimage, if it exists, instead of cloning
					let mut reason = OutboundHTLCOutcome::Success(None);
					mem::swap(outcome, &mut reason);
					htlc.state = OutboundHTLCState::AwaitingRemovedRemoteRevoke(reason);
					require_commitment = true;
				}
			}
		}
		self.value_to_self_msat = (self.value_to_self_msat as i64 + value_to_self_msat_diff) as u64;

		if let Some((feerate, update_state)) = self.pending_update_fee {
			match update_state {
				FeeUpdateState::Outbound => {
					debug_assert!(self.is_outbound());
					log_trace!(logger, " ...promoting outbound fee update {} to Committed", feerate);
					self.feerate_per_kw = feerate;
					self.pending_update_fee = None;
				},
				FeeUpdateState::RemoteAnnounced => { debug_assert!(!self.is_outbound()); },
				FeeUpdateState::AwaitingRemoteRevokeToAnnounce => {
					debug_assert!(!self.is_outbound());
					log_trace!(logger, " ...promoting inbound AwaitingRemoteRevokeToAnnounce fee update {} to Committed", feerate);
					require_commitment = true;
					self.feerate_per_kw = feerate;
					self.pending_update_fee = None;
				},
			}
		}

		if (self.channel_state & ChannelState::MonitorUpdateInProgress as u32) == ChannelState::MonitorUpdateInProgress as u32 {
			// We can't actually generate a new commitment transaction (incl by freeing holding
			// cells) while we can't update the monitor, so we just return what we have.
			if require_commitment {
				self.monitor_pending_commitment_signed = true;
				// When the monitor updating is restored we'll call get_last_commitment_update(),
				// which does not update state, but we're definitely now awaiting a remote revoke
				// before we can step forward any more, so set it here.
				let mut additional_update = self.build_commitment_no_status_check(logger);
				// build_commitment_no_status_check may bump latest_monitor_id but we want them to be
				// strictly increasing by one, so decrement it here.
				self.latest_monitor_update_id = monitor_update.update_id;
				monitor_update.updates.append(&mut additional_update.updates);
			}
			self.monitor_pending_forwards.append(&mut to_forward_infos);
			self.monitor_pending_failures.append(&mut revoked_htlcs);
			self.monitor_pending_finalized_fulfills.append(&mut finalized_claimed_htlcs);
			log_debug!(logger, "Received a valid revoke_and_ack for channel {} but awaiting a monitor update resolution to reply.", log_bytes!(self.channel_id()));
			self.pending_monitor_updates.push(monitor_update);
			return Ok((Vec::new(), self.pending_monitor_updates.last().unwrap()));
		}

		match self.free_holding_cell_htlcs(logger) {
			(Some(_), htlcs_to_fail) => {
				let mut additional_update = self.pending_monitor_updates.pop().unwrap();
				// free_holding_cell_htlcs may bump latest_monitor_id multiple times but we want them to be
				// strictly increasing by one, so decrement it here.
				self.latest_monitor_update_id = monitor_update.update_id;
				monitor_update.updates.append(&mut additional_update.updates);

				self.monitor_updating_paused(false, true, false, to_forward_infos, revoked_htlcs, finalized_claimed_htlcs);
				self.pending_monitor_updates.push(monitor_update);
				Ok((htlcs_to_fail, self.pending_monitor_updates.last().unwrap()))
			},
			(None, htlcs_to_fail) => {
				if require_commitment {
					let mut additional_update = self.build_commitment_no_status_check(logger);

					// build_commitment_no_status_check may bump latest_monitor_id but we want them to be
					// strictly increasing by one, so decrement it here.
					self.latest_monitor_update_id = monitor_update.update_id;
					monitor_update.updates.append(&mut additional_update.updates);

					log_debug!(logger, "Received a valid revoke_and_ack for channel {}. Responding with a commitment update with {} HTLCs failed.",
						log_bytes!(self.channel_id()), update_fail_htlcs.len() + update_fail_malformed_htlcs.len());
					self.monitor_updating_paused(false, true, false, to_forward_infos, revoked_htlcs, finalized_claimed_htlcs);
					self.pending_monitor_updates.push(monitor_update);
					Ok((htlcs_to_fail, self.pending_monitor_updates.last().unwrap()))
				} else {
					log_debug!(logger, "Received a valid revoke_and_ack for channel {} with no reply necessary.", log_bytes!(self.channel_id()));
					self.monitor_updating_paused(false, false, false, to_forward_infos, revoked_htlcs, finalized_claimed_htlcs);
					self.pending_monitor_updates.push(monitor_update);
					Ok((htlcs_to_fail, self.pending_monitor_updates.last().unwrap()))
				}
			}
		}
	}

	/// Queues up an outbound update fee by placing it in the holding cell. You should call
	/// [`Self::maybe_free_holding_cell_htlcs`] in order to actually generate and send the
	/// commitment update.
	pub fn queue_update_fee<L: Deref>(&mut self, feerate_per_kw: u32, logger: &L) where L::Target: Logger {
		let msg_opt = self.send_update_fee(feerate_per_kw, true, logger);
		assert!(msg_opt.is_none(), "We forced holding cell?");
	}

	/// Adds a pending update to this channel. See the doc for send_htlc for
	/// further details on the optionness of the return value.
	/// If our balance is too low to cover the cost of the next commitment transaction at the
	/// new feerate, the update is cancelled.
	///
	/// You MUST call [`Self::send_commitment_no_state_update`] prior to any other calls on this
	/// [`Channel`] if `force_holding_cell` is false.
	fn send_update_fee<L: Deref>(&mut self, feerate_per_kw: u32, mut force_holding_cell: bool, logger: &L) -> Option<msgs::UpdateFee> where L::Target: Logger {
		if !self.is_outbound() {
			panic!("Cannot send fee from inbound channel");
		}
		if !self.is_usable() {
			panic!("Cannot update fee until channel is fully established and we haven't started shutting down");
		}
		if !self.is_live() {
			panic!("Cannot update fee while peer is disconnected/we're awaiting a monitor update (ChannelManager should have caught this)");
		}

		// Before proposing a feerate update, check that we can actually afford the new fee.
		let inbound_stats = self.get_inbound_pending_htlc_stats(Some(feerate_per_kw));
		let outbound_stats = self.get_outbound_pending_htlc_stats(Some(feerate_per_kw));
		let keys = self.build_holder_transaction_keys(self.cur_holder_commitment_transaction_number);
		let commitment_stats = self.build_commitment_transaction(self.cur_holder_commitment_transaction_number, &keys, true, true, logger);
		let buffer_fee_msat = Channel::<Signer>::commit_tx_fee_sat(feerate_per_kw, commitment_stats.num_nondust_htlcs + outbound_stats.on_holder_tx_holding_cell_htlcs_count as usize + CONCURRENT_INBOUND_HTLC_FEE_BUFFER as usize, self.opt_anchors()) * 1000;
		let holder_balance_msat = commitment_stats.local_balance_msat - outbound_stats.holding_cell_msat;
		if holder_balance_msat < buffer_fee_msat  + self.counterparty_selected_channel_reserve_satoshis.unwrap() * 1000 {
			//TODO: auto-close after a number of failures?
			log_debug!(logger, "Cannot afford to send new feerate at {}", feerate_per_kw);
			return None;
		}

		// Note, we evaluate pending htlc "preemptive" trimmed-to-dust threshold at the proposed `feerate_per_kw`.
		let holder_tx_dust_exposure = inbound_stats.on_holder_tx_dust_exposure_msat + outbound_stats.on_holder_tx_dust_exposure_msat;
		let counterparty_tx_dust_exposure = inbound_stats.on_counterparty_tx_dust_exposure_msat + outbound_stats.on_counterparty_tx_dust_exposure_msat;
		if holder_tx_dust_exposure > self.get_max_dust_htlc_exposure_msat() {
			log_debug!(logger, "Cannot afford to send new feerate at {} without infringing max dust htlc exposure", feerate_per_kw);
			return None;
		}
		if counterparty_tx_dust_exposure > self.get_max_dust_htlc_exposure_msat() {
			log_debug!(logger, "Cannot afford to send new feerate at {} without infringing max dust htlc exposure", feerate_per_kw);
			return None;
		}

		if (self.channel_state & (ChannelState::AwaitingRemoteRevoke as u32 | ChannelState::MonitorUpdateInProgress as u32)) != 0 {
			force_holding_cell = true;
		}

		if force_holding_cell {
			self.holding_cell_update_fee = Some(feerate_per_kw);
			return None;
		}

		debug_assert!(self.pending_update_fee.is_none());
		self.pending_update_fee = Some((feerate_per_kw, FeeUpdateState::Outbound));

		Some(msgs::UpdateFee {
			channel_id: self.channel_id,
			feerate_per_kw,
		})
	}

	/// Removes any uncommitted inbound HTLCs and resets the state of uncommitted outbound HTLC
	/// updates, to be used on peer disconnection. After this, update_*_htlc messages need to be
	/// resent.
	/// No further message handling calls may be made until a channel_reestablish dance has
	/// completed.
	pub fn remove_uncommitted_htlcs_and_mark_paused<L: Deref>(&mut self, logger: &L)  where L::Target: Logger {
		assert_eq!(self.channel_state & ChannelState::ShutdownComplete as u32, 0);
		if self.channel_state < ChannelState::FundingSent as u32 {
			self.channel_state = ChannelState::ShutdownComplete as u32;
			return;
		}

		if self.channel_state & (ChannelState::PeerDisconnected as u32) == (ChannelState::PeerDisconnected as u32) {
			// While the below code should be idempotent, it's simpler to just return early, as
			// redundant disconnect events can fire, though they should be rare.
			return;
		}

		if self.announcement_sigs_state == AnnouncementSigsState::MessageSent || self.announcement_sigs_state == AnnouncementSigsState::Committed {
			self.announcement_sigs_state = AnnouncementSigsState::NotSent;
		}

		// Upon reconnect we have to start the closing_signed dance over, but shutdown messages
		// will be retransmitted.
		self.last_sent_closing_fee = None;
		self.pending_counterparty_closing_signed = None;
		self.closing_fee_limits = None;

		let mut inbound_drop_count = 0;
		self.pending_inbound_htlcs.retain(|htlc| {
			match htlc.state {
				InboundHTLCState::RemoteAnnounced(_) => {
					// They sent us an update_add_htlc but we never got the commitment_signed.
					// We'll tell them what commitment_signed we're expecting next and they'll drop
					// this HTLC accordingly
					inbound_drop_count += 1;
					false
				},
				InboundHTLCState::AwaitingRemoteRevokeToAnnounce(_)|InboundHTLCState::AwaitingAnnouncedRemoteRevoke(_) => {
					// We received a commitment_signed updating this HTLC and (at least hopefully)
					// sent a revoke_and_ack (which we can re-transmit) and have heard nothing
					// in response to it yet, so don't touch it.
					true
				},
				InboundHTLCState::Committed => true,
				InboundHTLCState::LocalRemoved(_) => {
					// We (hopefully) sent a commitment_signed updating this HTLC (which we can
					// re-transmit if needed) and they may have even sent a revoke_and_ack back
					// (that we missed). Keep this around for now and if they tell us they missed
					// the commitment_signed we can re-transmit the update then.
					true
				},
			}
		});
		self.next_counterparty_htlc_id -= inbound_drop_count;

		if let Some((_, update_state)) = self.pending_update_fee {
			if update_state == FeeUpdateState::RemoteAnnounced {
				debug_assert!(!self.is_outbound());
				self.pending_update_fee = None;
			}
		}

		for htlc in self.pending_outbound_htlcs.iter_mut() {
			if let OutboundHTLCState::RemoteRemoved(_) = htlc.state {
				// They sent us an update to remove this but haven't yet sent the corresponding
				// commitment_signed, we need to move it back to Committed and they can re-send
				// the update upon reconnection.
				htlc.state = OutboundHTLCState::Committed;
			}
		}

		self.channel_state |= ChannelState::PeerDisconnected as u32;
		log_trace!(logger, "Peer disconnection resulted in {} remote-announced HTLC drops on channel {}", inbound_drop_count, log_bytes!(self.channel_id()));
	}

	/// Indicates that a ChannelMonitor update is in progress and has not yet been fully persisted.
	/// This must be called before we return the [`ChannelMonitorUpdate`] back to the
	/// [`ChannelManager`], which will call [`Self::monitor_updating_restored`] once the monitor
	/// update completes (potentially immediately).
	/// The messages which were generated with the monitor update must *not* have been sent to the
	/// remote end, and must instead have been dropped. They will be regenerated when
	/// [`Self::monitor_updating_restored`] is called.
	///
	/// [`ChannelManager`]: super::channelmanager::ChannelManager
	/// [`chain::Watch`]: crate::chain::Watch
	/// [`ChannelMonitorUpdateStatus::InProgress`]: crate::chain::ChannelMonitorUpdateStatus::InProgress
	fn monitor_updating_paused(&mut self, resend_raa: bool, resend_commitment: bool,
		resend_channel_ready: bool, mut pending_forwards: Vec<(PendingHTLCInfo, u64)>,
		mut pending_fails: Vec<(HTLCSource, PaymentHash, HTLCFailReason)>,
		mut pending_finalized_claimed_htlcs: Vec<HTLCSource>
	) {
		self.monitor_pending_revoke_and_ack |= resend_raa;
		self.monitor_pending_commitment_signed |= resend_commitment;
		self.monitor_pending_channel_ready |= resend_channel_ready;
		self.monitor_pending_forwards.append(&mut pending_forwards);
		self.monitor_pending_failures.append(&mut pending_fails);
		self.monitor_pending_finalized_fulfills.append(&mut pending_finalized_claimed_htlcs);
		self.channel_state |= ChannelState::MonitorUpdateInProgress as u32;
	}

	/// Indicates that the latest ChannelMonitor update has been committed by the client
	/// successfully and we should restore normal operation. Returns messages which should be sent
	/// to the remote side.
	pub fn monitor_updating_restored<L: Deref, NS: Deref>(
		&mut self, logger: &L, node_signer: &NS, genesis_block_hash: BlockHash,
		user_config: &UserConfig, best_block_height: u32
	) -> MonitorRestoreUpdates
	where
		L::Target: Logger,
		NS::Target: NodeSigner
	{
		assert_eq!(self.channel_state & ChannelState::MonitorUpdateInProgress as u32, ChannelState::MonitorUpdateInProgress as u32);
		self.channel_state &= !(ChannelState::MonitorUpdateInProgress as u32);
		self.pending_monitor_updates.clear();

		// If we're past (or at) the FundingSent stage on an outbound channel, try to
		// (re-)broadcast the funding transaction as we may have declined to broadcast it when we
		// first received the funding_signed.
		let mut funding_broadcastable =
			if self.is_outbound() && self.channel_state & !MULTI_STATE_FLAGS >= ChannelState::FundingSent as u32 {
				self.funding_transaction.take()
			} else { None };
		// That said, if the funding transaction is already confirmed (ie we're active with a
		// minimum_depth over 0) don't bother re-broadcasting the confirmed funding tx.
		if self.channel_state & !MULTI_STATE_FLAGS >= ChannelState::ChannelReady as u32 && self.minimum_depth != Some(0) {
			funding_broadcastable = None;
		}

		// We will never broadcast the funding transaction when we're in MonitorUpdateInProgress
		// (and we assume the user never directly broadcasts the funding transaction and waits for
		// us to do it). Thus, we can only ever hit monitor_pending_channel_ready when we're
		// * an inbound channel that failed to persist the monitor on funding_created and we got
		//   the funding transaction confirmed before the monitor was persisted, or
		// * a 0-conf channel and intended to send the channel_ready before any broadcast at all.
		let channel_ready = if self.monitor_pending_channel_ready {
			assert!(!self.is_outbound() || self.minimum_depth == Some(0),
				"Funding transaction broadcast by the local client before it should have - LDK didn't do it!");
			self.monitor_pending_channel_ready = false;
			let next_per_commitment_point = self.holder_signer.get_per_commitment_point(self.cur_holder_commitment_transaction_number, &self.secp_ctx);
			Some(msgs::ChannelReady {
				channel_id: self.channel_id(),
				next_per_commitment_point,
				short_channel_id_alias: Some(self.outbound_scid_alias),
			})
		} else { None };

		let announcement_sigs = self.get_announcement_sigs(node_signer, genesis_block_hash, user_config, best_block_height, logger);

		let mut accepted_htlcs = Vec::new();
		mem::swap(&mut accepted_htlcs, &mut self.monitor_pending_forwards);
		let mut failed_htlcs = Vec::new();
		mem::swap(&mut failed_htlcs, &mut self.monitor_pending_failures);
		let mut finalized_claimed_htlcs = Vec::new();
		mem::swap(&mut finalized_claimed_htlcs, &mut self.monitor_pending_finalized_fulfills);

		if self.channel_state & (ChannelState::PeerDisconnected as u32) != 0 {
			self.monitor_pending_revoke_and_ack = false;
			self.monitor_pending_commitment_signed = false;
			return MonitorRestoreUpdates {
				raa: None, commitment_update: None, order: RAACommitmentOrder::RevokeAndACKFirst,
				accepted_htlcs, failed_htlcs, finalized_claimed_htlcs, funding_broadcastable, channel_ready, announcement_sigs
			};
		}

		let raa = if self.monitor_pending_revoke_and_ack {
			Some(self.get_last_revoke_and_ack())
		} else { None };
		let commitment_update = if self.monitor_pending_commitment_signed {
			Some(self.get_last_commitment_update(logger))
		} else { None };

		self.monitor_pending_revoke_and_ack = false;
		self.monitor_pending_commitment_signed = false;
		let order = self.resend_order.clone();
		log_debug!(logger, "Restored monitor updating in channel {} resulting in {}{} commitment update and {} RAA, with {} first",
			log_bytes!(self.channel_id()), if funding_broadcastable.is_some() { "a funding broadcastable, " } else { "" },
			if commitment_update.is_some() { "a" } else { "no" }, if raa.is_some() { "an" } else { "no" },
			match order { RAACommitmentOrder::CommitmentFirst => "commitment", RAACommitmentOrder::RevokeAndACKFirst => "RAA"});
		MonitorRestoreUpdates {
			raa, commitment_update, order, accepted_htlcs, failed_htlcs, finalized_claimed_htlcs, funding_broadcastable, channel_ready, announcement_sigs
		}
	}

	pub fn update_fee<F: Deref, L: Deref>(&mut self, fee_estimator: &LowerBoundedFeeEstimator<F>, msg: &msgs::UpdateFee, logger: &L) -> Result<(), ChannelError>
		where F::Target: FeeEstimator, L::Target: Logger
	{
		if self.is_outbound() {
			return Err(ChannelError::Close("Non-funding remote tried to update channel fee".to_owned()));
		}
		if self.channel_state & (ChannelState::PeerDisconnected as u32) == ChannelState::PeerDisconnected as u32 {
			return Err(ChannelError::Close("Peer sent update_fee when we needed a channel_reestablish".to_owned()));
		}
		Channel::<Signer>::check_remote_fee(fee_estimator, msg.feerate_per_kw, Some(self.feerate_per_kw), logger)?;
		let feerate_over_dust_buffer = msg.feerate_per_kw > self.get_dust_buffer_feerate(None);

		self.pending_update_fee = Some((msg.feerate_per_kw, FeeUpdateState::RemoteAnnounced));
		self.update_time_counter += 1;
		// If the feerate has increased over the previous dust buffer (note that
		// `get_dust_buffer_feerate` considers the `pending_update_fee` status), check that we
		// won't be pushed over our dust exposure limit by the feerate increase.
		if feerate_over_dust_buffer {
			let inbound_stats = self.get_inbound_pending_htlc_stats(None);
			let outbound_stats = self.get_outbound_pending_htlc_stats(None);
			let holder_tx_dust_exposure = inbound_stats.on_holder_tx_dust_exposure_msat + outbound_stats.on_holder_tx_dust_exposure_msat;
			let counterparty_tx_dust_exposure = inbound_stats.on_counterparty_tx_dust_exposure_msat + outbound_stats.on_counterparty_tx_dust_exposure_msat;
			if holder_tx_dust_exposure > self.get_max_dust_htlc_exposure_msat() {
				return Err(ChannelError::Close(format!("Peer sent update_fee with a feerate ({}) which may over-expose us to dust-in-flight on our own transactions (totaling {} msat)",
					msg.feerate_per_kw, holder_tx_dust_exposure)));
			}
			if counterparty_tx_dust_exposure > self.get_max_dust_htlc_exposure_msat() {
				return Err(ChannelError::Close(format!("Peer sent update_fee with a feerate ({}) which may over-expose us to dust-in-flight on our counterparty's transactions (totaling {} msat)",
					msg.feerate_per_kw, counterparty_tx_dust_exposure)));
			}
		}
		Ok(())
	}

	fn get_last_revoke_and_ack(&self) -> msgs::RevokeAndACK {
		let next_per_commitment_point = self.holder_signer.get_per_commitment_point(self.cur_holder_commitment_transaction_number, &self.secp_ctx);
		let per_commitment_secret = self.holder_signer.release_commitment_secret(self.cur_holder_commitment_transaction_number + 2);
		msgs::RevokeAndACK {
			channel_id: self.channel_id,
			per_commitment_secret,
			next_per_commitment_point,
		}
	}

	fn get_last_commitment_update<L: Deref>(&self, logger: &L) -> msgs::CommitmentUpdate where L::Target: Logger {
		let mut update_add_htlcs = Vec::new();
		let mut update_fulfill_htlcs = Vec::new();
		let mut update_fail_htlcs = Vec::new();
		let mut update_fail_malformed_htlcs = Vec::new();

		for htlc in self.pending_outbound_htlcs.iter() {
			if let &OutboundHTLCState::LocalAnnounced(ref onion_packet) = &htlc.state {
				update_add_htlcs.push(msgs::UpdateAddHTLC {
					channel_id: self.channel_id(),
					htlc_id: htlc.htlc_id,
					amount_msat: htlc.amount_msat,
					payment_hash: htlc.payment_hash,
					cltv_expiry: htlc.cltv_expiry,
					onion_routing_packet: (**onion_packet).clone(),
				});
			}
		}

		for htlc in self.pending_inbound_htlcs.iter() {
			if let &InboundHTLCState::LocalRemoved(ref reason) = &htlc.state {
				match reason {
					&InboundHTLCRemovalReason::FailRelay(ref err_packet) => {
						update_fail_htlcs.push(msgs::UpdateFailHTLC {
							channel_id: self.channel_id(),
							htlc_id: htlc.htlc_id,
							reason: err_packet.clone()
						});
					},
					&InboundHTLCRemovalReason::FailMalformed((ref sha256_of_onion, ref failure_code)) => {
						update_fail_malformed_htlcs.push(msgs::UpdateFailMalformedHTLC {
							channel_id: self.channel_id(),
							htlc_id: htlc.htlc_id,
							sha256_of_onion: sha256_of_onion.clone(),
							failure_code: failure_code.clone(),
						});
					},
					&InboundHTLCRemovalReason::Fulfill(ref payment_preimage) => {
						update_fulfill_htlcs.push(msgs::UpdateFulfillHTLC {
							channel_id: self.channel_id(),
							htlc_id: htlc.htlc_id,
							payment_preimage: payment_preimage.clone(),
						});
					},
				}
			}
		}

		let update_fee = if self.is_outbound() && self.pending_update_fee.is_some() {
			Some(msgs::UpdateFee {
				channel_id: self.channel_id(),
				feerate_per_kw: self.pending_update_fee.unwrap().0,
			})
		} else { None };

		log_trace!(logger, "Regenerated latest commitment update in channel {} with{} {} update_adds, {} update_fulfills, {} update_fails, and {} update_fail_malformeds",
				log_bytes!(self.channel_id()), if update_fee.is_some() { " update_fee," } else { "" },
				update_add_htlcs.len(), update_fulfill_htlcs.len(), update_fail_htlcs.len(), update_fail_malformed_htlcs.len());
		msgs::CommitmentUpdate {
			update_add_htlcs, update_fulfill_htlcs, update_fail_htlcs, update_fail_malformed_htlcs, update_fee,
			commitment_signed: self.send_commitment_no_state_update(logger).expect("It looks like we failed to re-generate a commitment_signed we had previously sent?").0,
		}
	}

	/// May panic if some calls other than message-handling calls (which will all Err immediately)
	/// have been called between remove_uncommitted_htlcs_and_mark_paused and this call.
	///
	/// Some links printed in log lines are included here to check them during build (when run with
	/// `cargo doc --document-private-items`):
	/// [`super::channelmanager::ChannelManager::force_close_without_broadcasting_txn`] and
	/// [`super::channelmanager::ChannelManager::force_close_all_channels_without_broadcasting_txn`].
	pub fn channel_reestablish<L: Deref, NS: Deref>(
		&mut self, msg: &msgs::ChannelReestablish, logger: &L, node_signer: &NS,
		genesis_block_hash: BlockHash, user_config: &UserConfig, best_block: &BestBlock
	) -> Result<ReestablishResponses, ChannelError>
	where
		L::Target: Logger,
		NS::Target: NodeSigner
	{
		if self.channel_state & (ChannelState::PeerDisconnected as u32) == 0 {
			// While BOLT 2 doesn't indicate explicitly we should error this channel here, it
			// almost certainly indicates we are going to end up out-of-sync in some way, so we
			// just close here instead of trying to recover.
			return Err(ChannelError::Close("Peer sent a loose channel_reestablish not after reconnect".to_owned()));
		}

		if msg.next_local_commitment_number >= INITIAL_COMMITMENT_NUMBER || msg.next_remote_commitment_number >= INITIAL_COMMITMENT_NUMBER ||
			msg.next_local_commitment_number == 0 {
			return Err(ChannelError::Close("Peer sent a garbage channel_reestablish".to_owned()));
		}

		if msg.next_remote_commitment_number > 0 {
			match msg.data_loss_protect {
				OptionalField::Present(ref data_loss) => {
					let expected_point = self.holder_signer.get_per_commitment_point(INITIAL_COMMITMENT_NUMBER - msg.next_remote_commitment_number + 1, &self.secp_ctx);
					let given_secret = SecretKey::from_slice(&data_loss.your_last_per_commitment_secret)
						.map_err(|_| ChannelError::Close("Peer sent a garbage channel_reestablish with unparseable secret key".to_owned()))?;
					if expected_point != PublicKey::from_secret_key(&self.secp_ctx, &given_secret) {
						return Err(ChannelError::Close("Peer sent a garbage channel_reestablish with secret key not matching the commitment height provided".to_owned()));
					}
					if msg.next_remote_commitment_number > INITIAL_COMMITMENT_NUMBER - self.cur_holder_commitment_transaction_number {
						macro_rules! log_and_panic {
							($err_msg: expr) => {
								log_error!(logger, $err_msg, log_bytes!(self.channel_id), log_pubkey!(self.counterparty_node_id));
								panic!($err_msg, log_bytes!(self.channel_id), log_pubkey!(self.counterparty_node_id));
							}
						}
						log_and_panic!("We have fallen behind - we have received proof that if we broadcast our counterparty is going to claim all our funds.\n\
							This implies you have restarted with lost ChannelMonitor and ChannelManager state, the first of which is a violation of the LDK chain::Watch requirements.\n\
							More specifically, this means you have a bug in your implementation that can cause loss of funds, or you are running with an old backup, which is unsafe.\n\
							If you have restored from an old backup and wish to force-close channels and return to operation, you should start up, call\n\
							ChannelManager::force_close_without_broadcasting_txn on channel {} with counterparty {} or\n\
							ChannelManager::force_close_all_channels_without_broadcasting_txn, then reconnect to peer(s).\n\
							Note that due to a long-standing bug in lnd you may have to reach out to peers running lnd-based nodes to ask them to manually force-close channels\n\
							See https://github.com/lightningdevkit/rust-lightning/issues/1565 for more info.");
					}
				},
				OptionalField::Absent => {}
			}
		}

		// Before we change the state of the channel, we check if the peer is sending a very old
		// commitment transaction number, if yes we send a warning message.
		let our_commitment_transaction = INITIAL_COMMITMENT_NUMBER - self.cur_holder_commitment_transaction_number - 1;
		if  msg.next_remote_commitment_number + 1 < our_commitment_transaction {
			return Err(
				ChannelError::Warn(format!("Peer attempted to reestablish channel with a very old local commitment transaction: {} (received) vs {} (expected)", msg.next_remote_commitment_number, our_commitment_transaction))
			);
		}

		// Go ahead and unmark PeerDisconnected as various calls we may make check for it (and all
		// remaining cases either succeed or ErrorMessage-fail).
		self.channel_state &= !(ChannelState::PeerDisconnected as u32);

		let shutdown_msg = if self.channel_state & (ChannelState::LocalShutdownSent as u32) != 0 {
			assert!(self.shutdown_scriptpubkey.is_some());
			Some(msgs::Shutdown {
				channel_id: self.channel_id,
				scriptpubkey: self.get_closing_scriptpubkey(),
			})
		} else { None };

		let announcement_sigs = self.get_announcement_sigs(node_signer, genesis_block_hash, user_config, best_block.height(), logger);

		if self.channel_state & (ChannelState::FundingSent as u32) == ChannelState::FundingSent as u32 {
			// If we're waiting on a monitor update, we shouldn't re-send any channel_ready's.
			if self.channel_state & (ChannelState::OurChannelReady as u32) == 0 ||
					self.channel_state & (ChannelState::MonitorUpdateInProgress as u32) != 0 {
				if msg.next_remote_commitment_number != 0 {
					return Err(ChannelError::Close("Peer claimed they saw a revoke_and_ack but we haven't sent channel_ready yet".to_owned()));
				}
				// Short circuit the whole handler as there is nothing we can resend them
				return Ok(ReestablishResponses {
					channel_ready: None,
					raa: None, commitment_update: None,
					order: RAACommitmentOrder::CommitmentFirst,
					shutdown_msg, announcement_sigs,
				});
			}

			// We have OurChannelReady set!
			let next_per_commitment_point = self.holder_signer.get_per_commitment_point(self.cur_holder_commitment_transaction_number, &self.secp_ctx);
			return Ok(ReestablishResponses {
				channel_ready: Some(msgs::ChannelReady {
					channel_id: self.channel_id(),
					next_per_commitment_point,
					short_channel_id_alias: Some(self.outbound_scid_alias),
				}),
				raa: None, commitment_update: None,
				order: RAACommitmentOrder::CommitmentFirst,
				shutdown_msg, announcement_sigs,
			});
		}

		let required_revoke = if msg.next_remote_commitment_number + 1 == INITIAL_COMMITMENT_NUMBER - self.cur_holder_commitment_transaction_number {
			// Remote isn't waiting on any RevokeAndACK from us!
			// Note that if we need to repeat our ChannelReady we'll do that in the next if block.
			None
		} else if msg.next_remote_commitment_number + 1 == (INITIAL_COMMITMENT_NUMBER - 1) - self.cur_holder_commitment_transaction_number {
			if self.channel_state & (ChannelState::MonitorUpdateInProgress as u32) != 0 {
				self.monitor_pending_revoke_and_ack = true;
				None
			} else {
				Some(self.get_last_revoke_and_ack())
			}
		} else {
			return Err(ChannelError::Close("Peer attempted to reestablish channel with a very old local commitment transaction".to_owned()));
		};

		// We increment cur_counterparty_commitment_transaction_number only upon receipt of
		// revoke_and_ack, not on sending commitment_signed, so we add one if have
		// AwaitingRemoteRevoke set, which indicates we sent a commitment_signed but haven't gotten
		// the corresponding revoke_and_ack back yet.
		let next_counterparty_commitment_number = INITIAL_COMMITMENT_NUMBER - self.cur_counterparty_commitment_transaction_number + if (self.channel_state & ChannelState::AwaitingRemoteRevoke as u32) != 0 { 1 } else { 0 };

		let channel_ready = if msg.next_local_commitment_number == 1 && INITIAL_COMMITMENT_NUMBER - self.cur_holder_commitment_transaction_number == 1 {
			// We should never have to worry about MonitorUpdateInProgress resending ChannelReady
			let next_per_commitment_point = self.holder_signer.get_per_commitment_point(self.cur_holder_commitment_transaction_number, &self.secp_ctx);
			Some(msgs::ChannelReady {
				channel_id: self.channel_id(),
				next_per_commitment_point,
				short_channel_id_alias: Some(self.outbound_scid_alias),
			})
		} else { None };

		if msg.next_local_commitment_number == next_counterparty_commitment_number {
			if required_revoke.is_some() {
				log_debug!(logger, "Reconnected channel {} with only lost outbound RAA", log_bytes!(self.channel_id()));
			} else {
				log_debug!(logger, "Reconnected channel {} with no loss", log_bytes!(self.channel_id()));
			}

			Ok(ReestablishResponses {
				channel_ready, shutdown_msg, announcement_sigs,
				raa: required_revoke,
				commitment_update: None,
				order: self.resend_order.clone(),
			})
		} else if msg.next_local_commitment_number == next_counterparty_commitment_number - 1 {
			if required_revoke.is_some() {
				log_debug!(logger, "Reconnected channel {} with lost outbound RAA and lost remote commitment tx", log_bytes!(self.channel_id()));
			} else {
				log_debug!(logger, "Reconnected channel {} with only lost remote commitment tx", log_bytes!(self.channel_id()));
			}

			if self.channel_state & (ChannelState::MonitorUpdateInProgress as u32) != 0 {
				self.monitor_pending_commitment_signed = true;
				Ok(ReestablishResponses {
					channel_ready, shutdown_msg, announcement_sigs,
					commitment_update: None, raa: None,
					order: self.resend_order.clone(),
				})
			} else {
				Ok(ReestablishResponses {
					channel_ready, shutdown_msg, announcement_sigs,
					raa: required_revoke,
					commitment_update: Some(self.get_last_commitment_update(logger)),
					order: self.resend_order.clone(),
				})
			}
		} else {
			Err(ChannelError::Close("Peer attempted to reestablish channel with a very old remote commitment transaction".to_owned()))
		}
	}

	/// Calculates and returns our minimum and maximum closing transaction fee amounts, in whole
	/// satoshis. The amounts remain consistent unless a peer disconnects/reconnects or we restart,
	/// at which point they will be recalculated.
	fn calculate_closing_fee_limits<F: Deref>(&mut self, fee_estimator: &LowerBoundedFeeEstimator<F>)
		-> (u64, u64)
		where F::Target: FeeEstimator
	{
		if let Some((min, max)) = self.closing_fee_limits { return (min, max); }

		// Propose a range from our current Background feerate to our Normal feerate plus our
		// force_close_avoidance_max_fee_satoshis.
		// If we fail to come to consensus, we'll have to force-close.
		let mut proposed_feerate = fee_estimator.bounded_sat_per_1000_weight(ConfirmationTarget::Background);
		let normal_feerate = fee_estimator.bounded_sat_per_1000_weight(ConfirmationTarget::Normal);
		let mut proposed_max_feerate = if self.is_outbound() { normal_feerate } else { u32::max_value() };

		// The spec requires that (when the channel does not have anchors) we only send absolute
		// channel fees no greater than the absolute channel fee on the current commitment
		// transaction. It's unclear *which* commitment transaction this refers to, and there isn't
		// very good reason to apply such a limit in any case. We don't bother doing so, risking
		// some force-closure by old nodes, but we wanted to close the channel anyway.

		if let Some(target_feerate) = self.target_closing_feerate_sats_per_kw {
			let min_feerate = if self.is_outbound() { target_feerate } else { cmp::min(self.feerate_per_kw, target_feerate) };
			proposed_feerate = cmp::max(proposed_feerate, min_feerate);
			proposed_max_feerate = cmp::max(proposed_max_feerate, min_feerate);
		}

		// Note that technically we could end up with a lower minimum fee if one sides' balance is
		// below our dust limit, causing the output to disappear. We don't bother handling this
		// case, however, as this should only happen if a channel is closed before any (material)
		// payments have been made on it. This may cause slight fee overpayment and/or failure to
		// come to consensus with our counterparty on appropriate fees, however it should be a
		// relatively rare case. We can revisit this later, though note that in order to determine
		// if the funders' output is dust we have to know the absolute fee we're going to use.
		let tx_weight = self.get_closing_transaction_weight(Some(&self.get_closing_scriptpubkey()), Some(self.counterparty_shutdown_scriptpubkey.as_ref().unwrap()));
		let proposed_total_fee_satoshis = proposed_feerate as u64 * tx_weight / 1000;
		let proposed_max_total_fee_satoshis = if self.is_outbound() {
				// We always add force_close_avoidance_max_fee_satoshis to our normal
				// feerate-calculated fee, but allow the max to be overridden if we're using a
				// target feerate-calculated fee.
				cmp::max(normal_feerate as u64 * tx_weight / 1000 + self.config.options.force_close_avoidance_max_fee_satoshis,
					proposed_max_feerate as u64 * tx_weight / 1000)
			} else {
				self.channel_value_satoshis - (self.value_to_self_msat + 999) / 1000
			};

		self.closing_fee_limits = Some((proposed_total_fee_satoshis, proposed_max_total_fee_satoshis));
		self.closing_fee_limits.clone().unwrap()
	}

	/// Returns true if we're ready to commence the closing_signed negotiation phase. This is true
	/// after both sides have exchanged a `shutdown` message and all HTLCs have been drained. At
	/// this point if we're the funder we should send the initial closing_signed, and in any case
	/// shutdown should complete within a reasonable timeframe.
	fn closing_negotiation_ready(&self) -> bool {
		self.pending_inbound_htlcs.is_empty() && self.pending_outbound_htlcs.is_empty() &&
			self.channel_state &
				(BOTH_SIDES_SHUTDOWN_MASK | ChannelState::AwaitingRemoteRevoke as u32 |
				 ChannelState::PeerDisconnected as u32 | ChannelState::MonitorUpdateInProgress as u32)
				== BOTH_SIDES_SHUTDOWN_MASK &&
			self.pending_update_fee.is_none()
	}

	/// Checks if the closing_signed negotiation is making appropriate progress, possibly returning
	/// an Err if no progress is being made and the channel should be force-closed instead.
	/// Should be called on a one-minute timer.
	pub fn timer_check_closing_negotiation_progress(&mut self) -> Result<(), ChannelError> {
		if self.closing_negotiation_ready() {
			if self.closing_signed_in_flight {
				return Err(ChannelError::Close("closing_signed negotiation failed to finish within two timer ticks".to_owned()));
			} else {
				self.closing_signed_in_flight = true;
			}
		}
		Ok(())
	}

	pub fn maybe_propose_closing_signed<F: Deref, L: Deref>(
		&mut self, fee_estimator: &LowerBoundedFeeEstimator<F>, logger: &L)
		-> Result<(Option<msgs::ClosingSigned>, Option<Transaction>), ChannelError>
		where F::Target: FeeEstimator, L::Target: Logger
	{
		if self.last_sent_closing_fee.is_some() || !self.closing_negotiation_ready() {
			return Ok((None, None));
		}

		if !self.is_outbound() {
			if let Some(msg) = &self.pending_counterparty_closing_signed.take() {
				return self.closing_signed(fee_estimator, &msg);
			}
			return Ok((None, None));
		}

		let (our_min_fee, our_max_fee) = self.calculate_closing_fee_limits(fee_estimator);

		assert!(self.shutdown_scriptpubkey.is_some());
		let (closing_tx, total_fee_satoshis) = self.build_closing_transaction(our_min_fee, false);
		log_trace!(logger, "Proposing initial closing_signed for our counterparty with a fee range of {}-{} sat (with initial proposal {} sats)",
			our_min_fee, our_max_fee, total_fee_satoshis);

		let sig = self.holder_signer
			.sign_closing_transaction(&closing_tx, &self.secp_ctx)
			.map_err(|()| ChannelError::Close("Failed to get signature for closing transaction.".to_owned()))?;

		self.last_sent_closing_fee = Some((total_fee_satoshis, sig.clone()));
		Ok((Some(msgs::ClosingSigned {
			channel_id: self.channel_id,
			fee_satoshis: total_fee_satoshis,
			signature: sig,
			fee_range: Some(msgs::ClosingSignedFeeRange {
				min_fee_satoshis: our_min_fee,
				max_fee_satoshis: our_max_fee,
			}),
		}), None))
	}

	pub fn shutdown<SP: Deref>(
		&mut self, signer_provider: &SP, their_features: &InitFeatures, msg: &msgs::Shutdown
	) -> Result<(Option<msgs::Shutdown>, Option<&ChannelMonitorUpdate>, Vec<(HTLCSource, PaymentHash)>), ChannelError>
	where SP::Target: SignerProvider
	{
		if self.channel_state & (ChannelState::PeerDisconnected as u32) == ChannelState::PeerDisconnected as u32 {
			return Err(ChannelError::Close("Peer sent shutdown when we needed a channel_reestablish".to_owned()));
		}
		if self.channel_state < ChannelState::FundingSent as u32 {
			// Spec says we should fail the connection, not the channel, but that's nonsense, there
			// are plenty of reasons you may want to fail a channel pre-funding, and spec says you
			// can do that via error message without getting a connection fail anyway...
			return Err(ChannelError::Close("Peer sent shutdown pre-funding generation".to_owned()));
		}
		for htlc in self.pending_inbound_htlcs.iter() {
			if let InboundHTLCState::RemoteAnnounced(_) = htlc.state {
				return Err(ChannelError::Close("Got shutdown with remote pending HTLCs".to_owned()));
			}
		}
		assert_eq!(self.channel_state & ChannelState::ShutdownComplete as u32, 0);

		if !script::is_bolt2_compliant(&msg.scriptpubkey, their_features) {
			return Err(ChannelError::Warn(format!("Got a nonstandard scriptpubkey ({}) from remote peer", msg.scriptpubkey.to_bytes().to_hex())));
		}

		if self.counterparty_shutdown_scriptpubkey.is_some() {
			if Some(&msg.scriptpubkey) != self.counterparty_shutdown_scriptpubkey.as_ref() {
				return Err(ChannelError::Warn(format!("Got shutdown request with a scriptpubkey ({}) which did not match their previous scriptpubkey.", msg.scriptpubkey.to_bytes().to_hex())));
			}
		} else {
			self.counterparty_shutdown_scriptpubkey = Some(msg.scriptpubkey.clone());
		}

		// If we have any LocalAnnounced updates we'll probably just get back an update_fail_htlc
		// immediately after the commitment dance, but we can send a Shutdown because we won't send
		// any further commitment updates after we set LocalShutdownSent.
		let send_shutdown = (self.channel_state & ChannelState::LocalShutdownSent as u32) != ChannelState::LocalShutdownSent as u32;

		let update_shutdown_script = match self.shutdown_scriptpubkey {
			Some(_) => false,
			None => {
				assert!(send_shutdown);
				let shutdown_scriptpubkey = signer_provider.get_shutdown_scriptpubkey();
				if !shutdown_scriptpubkey.is_compatible(their_features) {
					return Err(ChannelError::Close(format!("Provided a scriptpubkey format not accepted by peer: {}", shutdown_scriptpubkey)));
				}
				self.shutdown_scriptpubkey = Some(shutdown_scriptpubkey);
				true
			},
		};

		// From here on out, we may not fail!

		self.channel_state |= ChannelState::RemoteShutdownSent as u32;
		self.update_time_counter += 1;

		let monitor_update = if update_shutdown_script {
			self.latest_monitor_update_id += 1;
			let monitor_update = ChannelMonitorUpdate {
				update_id: self.latest_monitor_update_id,
				updates: vec![ChannelMonitorUpdateStep::ShutdownScript {
					scriptpubkey: self.get_closing_scriptpubkey(),
				}],
			};
			self.monitor_updating_paused(false, false, false, Vec::new(), Vec::new(), Vec::new());
			self.pending_monitor_updates.push(monitor_update);
			Some(self.pending_monitor_updates.last().unwrap())
		} else { None };
		let shutdown = if send_shutdown {
			Some(msgs::Shutdown {
				channel_id: self.channel_id,
				scriptpubkey: self.get_closing_scriptpubkey(),
			})
		} else { None };

		// We can't send our shutdown until we've committed all of our pending HTLCs, but the
		// remote side is unlikely to accept any new HTLCs, so we go ahead and "free" any holding
		// cell HTLCs and return them to fail the payment.
		self.holding_cell_update_fee = None;
		let mut dropped_outbound_htlcs = Vec::with_capacity(self.holding_cell_htlc_updates.len());
		self.holding_cell_htlc_updates.retain(|htlc_update| {
			match htlc_update {
				&HTLCUpdateAwaitingACK::AddHTLC { ref payment_hash, ref source, .. } => {
					dropped_outbound_htlcs.push((source.clone(), payment_hash.clone()));
					false
				},
				_ => true
			}
		});

		self.channel_state |= ChannelState::LocalShutdownSent as u32;
		self.update_time_counter += 1;

		Ok((shutdown, monitor_update, dropped_outbound_htlcs))
	}

	fn build_signed_closing_transaction(&self, closing_tx: &ClosingTransaction, counterparty_sig: &Signature, sig: &Signature) -> Transaction {
		let mut tx = closing_tx.trust().built_transaction().clone();

		tx.input[0].witness.push(Vec::new()); // First is the multisig dummy

		let funding_key = self.get_holder_pubkeys().funding_pubkey.serialize();
		let counterparty_funding_key = self.counterparty_funding_pubkey().serialize();
		let mut holder_sig = sig.serialize_der().to_vec();
		holder_sig.push(EcdsaSighashType::All as u8);
		let mut cp_sig = counterparty_sig.serialize_der().to_vec();
		cp_sig.push(EcdsaSighashType::All as u8);
		if funding_key[..] < counterparty_funding_key[..] {
			tx.input[0].witness.push(holder_sig);
			tx.input[0].witness.push(cp_sig);
		} else {
			tx.input[0].witness.push(cp_sig);
			tx.input[0].witness.push(holder_sig);
		}

		tx.input[0].witness.push(self.get_funding_redeemscript().into_bytes());
		tx
	}

	pub fn closing_signed<F: Deref>(
		&mut self, fee_estimator: &LowerBoundedFeeEstimator<F>, msg: &msgs::ClosingSigned)
		-> Result<(Option<msgs::ClosingSigned>, Option<Transaction>), ChannelError>
		where F::Target: FeeEstimator
	{
		if self.channel_state & BOTH_SIDES_SHUTDOWN_MASK != BOTH_SIDES_SHUTDOWN_MASK {
			return Err(ChannelError::Close("Remote end sent us a closing_signed before both sides provided a shutdown".to_owned()));
		}
		if self.channel_state & (ChannelState::PeerDisconnected as u32) == ChannelState::PeerDisconnected as u32 {
			return Err(ChannelError::Close("Peer sent closing_signed when we needed a channel_reestablish".to_owned()));
		}
		if !self.pending_inbound_htlcs.is_empty() || !self.pending_outbound_htlcs.is_empty() {
			return Err(ChannelError::Close("Remote end sent us a closing_signed while there were still pending HTLCs".to_owned()));
		}
		if msg.fee_satoshis > TOTAL_BITCOIN_SUPPLY_SATOSHIS { // this is required to stop potential overflow in build_closing_transaction
			return Err(ChannelError::Close("Remote tried to send us a closing tx with > 21 million BTC fee".to_owned()));
		}

		if self.is_outbound() && self.last_sent_closing_fee.is_none() {
			return Err(ChannelError::Close("Remote tried to send a closing_signed when we were supposed to propose the first one".to_owned()));
		}

		if self.channel_state & ChannelState::MonitorUpdateInProgress as u32 != 0 {
			self.pending_counterparty_closing_signed = Some(msg.clone());
			return Ok((None, None));
		}

		let funding_redeemscript = self.get_funding_redeemscript();
		let (mut closing_tx, used_total_fee) = self.build_closing_transaction(msg.fee_satoshis, false);
		if used_total_fee != msg.fee_satoshis {
			return Err(ChannelError::Close(format!("Remote sent us a closing_signed with a fee other than the value they can claim. Fee in message: {}. Actual closing tx fee: {}", msg.fee_satoshis, used_total_fee)));
		}
		let sighash = closing_tx.trust().get_sighash_all(&funding_redeemscript, self.channel_value_satoshis);

		match self.secp_ctx.verify_ecdsa(&sighash, &msg.signature, &self.get_counterparty_pubkeys().funding_pubkey) {
			Ok(_) => {},
			Err(_e) => {
				// The remote end may have decided to revoke their output due to inconsistent dust
				// limits, so check for that case by re-checking the signature here.
				closing_tx = self.build_closing_transaction(msg.fee_satoshis, true).0;
				let sighash = closing_tx.trust().get_sighash_all(&funding_redeemscript, self.channel_value_satoshis);
				secp_check!(self.secp_ctx.verify_ecdsa(&sighash, &msg.signature, self.counterparty_funding_pubkey()), "Invalid closing tx signature from peer".to_owned());
			},
		};

		for outp in closing_tx.trust().built_transaction().output.iter() {
			if !outp.script_pubkey.is_witness_program() && outp.value < MAX_STD_OUTPUT_DUST_LIMIT_SATOSHIS {
				return Err(ChannelError::Close("Remote sent us a closing_signed with a dust output. Always use segwit closing scripts!".to_owned()));
			}
		}

		assert!(self.shutdown_scriptpubkey.is_some());
		if let Some((last_fee, sig)) = self.last_sent_closing_fee {
			if last_fee == msg.fee_satoshis {
				let tx = self.build_signed_closing_transaction(&mut closing_tx, &msg.signature, &sig);
				self.channel_state = ChannelState::ShutdownComplete as u32;
				self.update_time_counter += 1;
				return Ok((None, Some(tx)));
			}
		}

		let (our_min_fee, our_max_fee) = self.calculate_closing_fee_limits(fee_estimator);

		macro_rules! propose_fee {
			($new_fee: expr) => {
				let (closing_tx, used_fee) = if $new_fee == msg.fee_satoshis {
					(closing_tx, $new_fee)
				} else {
					self.build_closing_transaction($new_fee, false)
				};

				let sig = self.holder_signer
					.sign_closing_transaction(&closing_tx, &self.secp_ctx)
					.map_err(|_| ChannelError::Close("External signer refused to sign closing transaction".to_owned()))?;

				let signed_tx = if $new_fee == msg.fee_satoshis {
					self.channel_state = ChannelState::ShutdownComplete as u32;
					self.update_time_counter += 1;
					let tx = self.build_signed_closing_transaction(&closing_tx, &msg.signature, &sig);
					Some(tx)
				} else { None };

				self.last_sent_closing_fee = Some((used_fee, sig.clone()));
				return Ok((Some(msgs::ClosingSigned {
					channel_id: self.channel_id,
					fee_satoshis: used_fee,
					signature: sig,
					fee_range: Some(msgs::ClosingSignedFeeRange {
						min_fee_satoshis: our_min_fee,
						max_fee_satoshis: our_max_fee,
					}),
				}), signed_tx))
			}
		}

		if let Some(msgs::ClosingSignedFeeRange { min_fee_satoshis, max_fee_satoshis }) = msg.fee_range {
			if msg.fee_satoshis < min_fee_satoshis || msg.fee_satoshis > max_fee_satoshis {
				return Err(ChannelError::Close(format!("Peer sent a bogus closing_signed - suggested fee of {} sat was not in their desired range of {} sat - {} sat", msg.fee_satoshis, min_fee_satoshis, max_fee_satoshis)));
			}
			if max_fee_satoshis < our_min_fee {
				return Err(ChannelError::Warn(format!("Unable to come to consensus about closing feerate, remote's max fee ({} sat) was smaller than our min fee ({} sat)", max_fee_satoshis, our_min_fee)));
			}
			if min_fee_satoshis > our_max_fee {
				return Err(ChannelError::Warn(format!("Unable to come to consensus about closing feerate, remote's min fee ({} sat) was greater than our max fee ({} sat)", min_fee_satoshis, our_max_fee)));
			}

			if !self.is_outbound() {
				// They have to pay, so pick the highest fee in the overlapping range.
				// We should never set an upper bound aside from their full balance
				debug_assert_eq!(our_max_fee, self.channel_value_satoshis - (self.value_to_self_msat + 999) / 1000);
				propose_fee!(cmp::min(max_fee_satoshis, our_max_fee));
			} else {
				if msg.fee_satoshis < our_min_fee || msg.fee_satoshis > our_max_fee {
					return Err(ChannelError::Close(format!("Peer sent a bogus closing_signed - suggested fee of {} sat was not in our desired range of {} sat - {} sat after we informed them of our range.",
						msg.fee_satoshis, our_min_fee, our_max_fee)));
				}
				// The proposed fee is in our acceptable range, accept it and broadcast!
				propose_fee!(msg.fee_satoshis);
			}
		} else {
			// Old fee style negotiation. We don't bother to enforce whether they are complying
			// with the "making progress" requirements, we just comply and hope for the best.
			if let Some((last_fee, _)) = self.last_sent_closing_fee {
				if msg.fee_satoshis > last_fee {
					if msg.fee_satoshis < our_max_fee {
						propose_fee!(msg.fee_satoshis);
					} else if last_fee < our_max_fee {
						propose_fee!(our_max_fee);
					} else {
						return Err(ChannelError::Close(format!("Unable to come to consensus about closing feerate, remote wants something ({} sat) higher than our max fee ({} sat)", msg.fee_satoshis, our_max_fee)));
					}
				} else {
					if msg.fee_satoshis > our_min_fee {
						propose_fee!(msg.fee_satoshis);
					} else if last_fee > our_min_fee {
						propose_fee!(our_min_fee);
					} else {
						return Err(ChannelError::Close(format!("Unable to come to consensus about closing feerate, remote wants something ({} sat) lower than our min fee ({} sat)", msg.fee_satoshis, our_min_fee)));
					}
				}
			} else {
				if msg.fee_satoshis < our_min_fee {
					propose_fee!(our_min_fee);
				} else if msg.fee_satoshis > our_max_fee {
					propose_fee!(our_max_fee);
				} else {
					propose_fee!(msg.fee_satoshis);
				}
			}
		}
	}

	// Public utilities:

	pub fn channel_id(&self) -> [u8; 32] {
		self.channel_id
	}

	pub fn minimum_depth(&self) -> Option<u32> {
		self.minimum_depth
	}

	/// Gets the "user_id" value passed into the construction of this channel. It has no special
	/// meaning and exists only to allow users to have a persistent identifier of a channel.
	pub fn get_user_id(&self) -> u128 {
		self.user_id
	}

	/// Gets the channel's type
	pub fn get_channel_type(&self) -> &ChannelTypeFeatures {
		&self.channel_type
	}

	/// Guaranteed to be Some after both ChannelReady messages have been exchanged (and, thus,
	/// is_usable() returns true).
	/// Allowed in any state (including after shutdown)
	pub fn get_short_channel_id(&self) -> Option<u64> {
		self.short_channel_id
	}

	/// Allowed in any state (including after shutdown)
	pub fn latest_inbound_scid_alias(&self) -> Option<u64> {
		self.latest_inbound_scid_alias
	}

	/// Allowed in any state (including after shutdown)
	pub fn outbound_scid_alias(&self) -> u64 {
		self.outbound_scid_alias
	}
	/// Only allowed immediately after deserialization if get_outbound_scid_alias returns 0,
	/// indicating we were written by LDK prior to 0.0.106 which did not set outbound SCID aliases.
	pub fn set_outbound_scid_alias(&mut self, outbound_scid_alias: u64) {
		assert_eq!(self.outbound_scid_alias, 0);
		self.outbound_scid_alias = outbound_scid_alias;
	}

	/// Returns the funding_txo we either got from our peer, or were given by
	/// get_outbound_funding_created.
	pub fn get_funding_txo(&self) -> Option<OutPoint> {
		self.channel_transaction_parameters.funding_outpoint
	}

	/// Returns the block hash in which our funding transaction was confirmed.
	pub fn get_funding_tx_confirmed_in(&self) -> Option<BlockHash> {
		self.funding_tx_confirmed_in
	}

	/// Returns the current number of confirmations on the funding transaction.
	pub fn get_funding_tx_confirmations(&self, height: u32) -> u32 {
		if self.funding_tx_confirmation_height == 0 {
			// We either haven't seen any confirmation yet, or observed a reorg.
			return 0;
		}

		height.checked_sub(self.funding_tx_confirmation_height).map_or(0, |c| c + 1)
	}

	fn get_holder_selected_contest_delay(&self) -> u16 {
		self.channel_transaction_parameters.holder_selected_contest_delay
	}

	fn get_holder_pubkeys(&self) -> &ChannelPublicKeys {
		&self.channel_transaction_parameters.holder_pubkeys
	}

	pub fn get_counterparty_selected_contest_delay(&self) -> Option<u16> {
		self.channel_transaction_parameters.counterparty_parameters
			.as_ref().map(|params| params.selected_contest_delay)
	}

	fn get_counterparty_pubkeys(&self) -> &ChannelPublicKeys {
		&self.channel_transaction_parameters.counterparty_parameters.as_ref().unwrap().pubkeys
	}

	/// Allowed in any state (including after shutdown)
	pub fn get_counterparty_node_id(&self) -> PublicKey {
		self.counterparty_node_id
	}

	/// Allowed in any state (including after shutdown)
	pub fn get_holder_htlc_minimum_msat(&self) -> u64 {
		self.holder_htlc_minimum_msat
	}

	/// Allowed in any state (including after shutdown), but will return none before TheirInitSent
	pub fn get_holder_htlc_maximum_msat(&self) -> Option<u64> {
		self.get_htlc_maximum_msat(self.holder_max_htlc_value_in_flight_msat)
	}

	/// Allowed in any state (including after shutdown)
	pub fn get_announced_htlc_max_msat(&self) -> u64 {
		return cmp::min(
			// Upper bound by capacity. We make it a bit less than full capacity to prevent attempts
			// to use full capacity. This is an effort to reduce routing failures, because in many cases
			// channel might have been used to route very small values (either by honest users or as DoS).
			self.channel_value_satoshis * 1000 * 9 / 10,

			self.counterparty_max_htlc_value_in_flight_msat
		);
	}

	/// Allowed in any state (including after shutdown)
	pub fn get_counterparty_htlc_minimum_msat(&self) -> u64 {
		self.counterparty_htlc_minimum_msat
	}

	/// Allowed in any state (including after shutdown), but will return none before TheirInitSent
	pub fn get_counterparty_htlc_maximum_msat(&self) -> Option<u64> {
		self.get_htlc_maximum_msat(self.counterparty_max_htlc_value_in_flight_msat)
	}

	fn get_htlc_maximum_msat(&self, party_max_htlc_value_in_flight_msat: u64) -> Option<u64> {
		self.counterparty_selected_channel_reserve_satoshis.map(|counterparty_reserve| {
			let holder_reserve = self.holder_selected_channel_reserve_satoshis;
			cmp::min(
				(self.channel_value_satoshis - counterparty_reserve - holder_reserve) * 1000,
				party_max_htlc_value_in_flight_msat
			)
		})
	}

	pub fn get_value_satoshis(&self) -> u64 {
		self.channel_value_satoshis
	}

	pub fn get_fee_proportional_millionths(&self) -> u32 {
		self.config.options.forwarding_fee_proportional_millionths
	}

	pub fn get_cltv_expiry_delta(&self) -> u16 {
		cmp::max(self.config.options.cltv_expiry_delta, MIN_CLTV_EXPIRY_DELTA)
	}

	pub fn get_max_dust_htlc_exposure_msat(&self) -> u64 {
		self.config.options.max_dust_htlc_exposure_msat
	}

	/// Returns the previous [`ChannelConfig`] applied to this channel, if any.
	pub fn prev_config(&self) -> Option<ChannelConfig> {
		self.prev_config.map(|prev_config| prev_config.0)
	}

	// Checks whether we should emit a `ChannelReady` event.
	pub(crate) fn should_emit_channel_ready_event(&mut self) -> bool {
		self.is_usable() && !self.channel_ready_event_emitted
	}

	// Remembers that we already emitted a `ChannelReady` event.
	pub(crate) fn set_channel_ready_event_emitted(&mut self) {
		self.channel_ready_event_emitted = true;
	}

	/// Tracks the number of ticks elapsed since the previous [`ChannelConfig`] was updated. Once
	/// [`EXPIRE_PREV_CONFIG_TICKS`] is reached, the previous config is considered expired and will
	/// no longer be considered when forwarding HTLCs.
	pub fn maybe_expire_prev_config(&mut self) {
		if self.prev_config.is_none() {
			return;
		}
		let prev_config = self.prev_config.as_mut().unwrap();
		prev_config.1 += 1;
		if prev_config.1 == EXPIRE_PREV_CONFIG_TICKS {
			self.prev_config = None;
		}
	}

	/// Returns the current [`ChannelConfig`] applied to the channel.
	pub fn config(&self) -> ChannelConfig {
		self.config.options
	}

	/// Updates the channel's config. A bool is returned indicating whether the config update
	/// applied resulted in a new ChannelUpdate message.
	pub fn update_config(&mut self, config: &ChannelConfig) -> bool {
		let did_channel_update =
			self.config.options.forwarding_fee_proportional_millionths != config.forwarding_fee_proportional_millionths ||
			self.config.options.forwarding_fee_base_msat != config.forwarding_fee_base_msat ||
			self.config.options.cltv_expiry_delta != config.cltv_expiry_delta;
		if did_channel_update {
			self.prev_config = Some((self.config.options, 0));
			// Update the counter, which backs the ChannelUpdate timestamp, to allow the relay
			// policy change to propagate throughout the network.
			self.update_time_counter += 1;
		}
		self.config.options = *config;
		did_channel_update
	}

	fn internal_htlc_satisfies_config(
		&self, htlc: &msgs::UpdateAddHTLC, amt_to_forward: u64, outgoing_cltv_value: u32, config: &ChannelConfig,
	) -> Result<(), (&'static str, u16)> {
		let fee = amt_to_forward.checked_mul(config.forwarding_fee_proportional_millionths as u64)
			.and_then(|prop_fee| (prop_fee / 1000000).checked_add(config.forwarding_fee_base_msat as u64));
		if fee.is_none() || htlc.amount_msat < fee.unwrap() ||
			(htlc.amount_msat - fee.unwrap()) < amt_to_forward {
			return Err((
				"Prior hop has deviated from specified fees parameters or origin node has obsolete ones",
				0x1000 | 12, // fee_insufficient
			));
		}
		if (htlc.cltv_expiry as u64) < outgoing_cltv_value as u64 + config.cltv_expiry_delta as u64 {
			return Err((
				"Forwarding node has tampered with the intended HTLC values or origin node has an obsolete cltv_expiry_delta",
				0x1000 | 13, // incorrect_cltv_expiry
			));
		}
		Ok(())
	}

	/// Determines whether the parameters of an incoming HTLC to be forwarded satisfy the channel's
	/// [`ChannelConfig`]. This first looks at the channel's current [`ChannelConfig`], and if
	/// unsuccessful, falls back to the previous one if one exists.
	pub fn htlc_satisfies_config(
		&self, htlc: &msgs::UpdateAddHTLC, amt_to_forward: u64, outgoing_cltv_value: u32,
	) -> Result<(), (&'static str, u16)> {
		self.internal_htlc_satisfies_config(&htlc, amt_to_forward, outgoing_cltv_value, &self.config())
			.or_else(|err| {
				if let Some(prev_config) = self.prev_config() {
					self.internal_htlc_satisfies_config(htlc, amt_to_forward, outgoing_cltv_value, &prev_config)
				} else {
					Err(err)
				}
			})
	}

	pub fn get_feerate(&self) -> u32 {
		self.feerate_per_kw
	}

	pub fn get_dust_buffer_feerate(&self, outbound_feerate_update: Option<u32>) -> u32 {
		// When calculating our exposure to dust HTLCs, we assume that the channel feerate
		// may, at any point, increase by at least 10 sat/vB (i.e 2530 sat/kWU) or 25%,
		// whichever is higher. This ensures that we aren't suddenly exposed to significantly
		// more dust balance if the feerate increases when we have several HTLCs pending
		// which are near the dust limit.
		let mut feerate_per_kw = self.feerate_per_kw;
		// If there's a pending update fee, use it to ensure we aren't under-estimating
		// potential feerate updates coming soon.
		if let Some((feerate, _)) = self.pending_update_fee {
			feerate_per_kw = cmp::max(feerate_per_kw, feerate);
		}
		if let Some(feerate) = outbound_feerate_update {
			feerate_per_kw = cmp::max(feerate_per_kw, feerate);
		}
		cmp::max(2530, feerate_per_kw * 1250 / 1000)
	}

	pub fn get_cur_holder_commitment_transaction_number(&self) -> u64 {
		self.cur_holder_commitment_transaction_number + 1
	}

	pub fn get_cur_counterparty_commitment_transaction_number(&self) -> u64 {
		self.cur_counterparty_commitment_transaction_number + 1 - if self.channel_state & (ChannelState::AwaitingRemoteRevoke as u32) != 0 { 1 } else { 0 }
	}

	pub fn get_revoked_counterparty_commitment_transaction_number(&self) -> u64 {
		self.cur_counterparty_commitment_transaction_number + 2
	}

	#[cfg(test)]
	pub fn get_signer(&self) -> &Signer {
		&self.holder_signer
	}

	#[cfg(test)]
	pub fn get_value_stat(&self) -> ChannelValueStat {
		ChannelValueStat {
			value_to_self_msat: self.value_to_self_msat,
			channel_value_msat: self.channel_value_satoshis * 1000,
			channel_reserve_msat: self.counterparty_selected_channel_reserve_satoshis.unwrap() * 1000,
			pending_outbound_htlcs_amount_msat: self.pending_outbound_htlcs.iter().map(|ref h| h.amount_msat).sum::<u64>(),
			pending_inbound_htlcs_amount_msat: self.pending_inbound_htlcs.iter().map(|ref h| h.amount_msat).sum::<u64>(),
			holding_cell_outbound_amount_msat: {
				let mut res = 0;
				for h in self.holding_cell_htlc_updates.iter() {
					match h {
						&HTLCUpdateAwaitingACK::AddHTLC{amount_msat, .. } => {
							res += amount_msat;
						}
						_ => {}
					}
				}
				res
			},
			counterparty_max_htlc_value_in_flight_msat: self.counterparty_max_htlc_value_in_flight_msat,
			counterparty_dust_limit_msat: self.counterparty_dust_limit_satoshis * 1000,
		}
	}

	/// Allowed in any state (including after shutdown)
	pub fn get_update_time_counter(&self) -> u32 {
		self.update_time_counter
	}

	pub fn get_latest_monitor_update_id(&self) -> u64 {
		self.latest_monitor_update_id
	}

	pub fn should_announce(&self) -> bool {
		self.config.announced_channel
	}

	pub fn is_outbound(&self) -> bool {
		self.channel_transaction_parameters.is_outbound_from_holder
	}

	/// Gets the fee we'd want to charge for adding an HTLC output to this Channel
	/// Allowed in any state (including after shutdown)
	pub fn get_outbound_forwarding_fee_base_msat(&self) -> u32 {
		self.config.options.forwarding_fee_base_msat
	}

	/// Returns true if we've ever received a message from the remote end for this Channel
	pub fn have_received_message(&self) -> bool {
		self.channel_state > (ChannelState::OurInitSent as u32)
	}

	/// Returns true if this channel is fully established and not known to be closing.
	/// Allowed in any state (including after shutdown)
	pub fn is_usable(&self) -> bool {
		let mask = ChannelState::ChannelReady as u32 | BOTH_SIDES_SHUTDOWN_MASK;
		(self.channel_state & mask) == (ChannelState::ChannelReady as u32) && !self.monitor_pending_channel_ready
	}

	/// Returns true if this channel is currently available for use. This is a superset of
	/// is_usable() and considers things like the channel being temporarily disabled.
	/// Allowed in any state (including after shutdown)
	pub fn is_live(&self) -> bool {
		self.is_usable() && (self.channel_state & (ChannelState::PeerDisconnected as u32) == 0)
	}

	/// Returns true if this channel has been marked as awaiting a monitor update to move forward.
	/// Allowed in any state (including after shutdown)
	pub fn is_awaiting_monitor_update(&self) -> bool {
		(self.channel_state & ChannelState::MonitorUpdateInProgress as u32) != 0
	}

	pub fn get_next_monitor_update(&self) -> Option<&ChannelMonitorUpdate> {
		self.pending_monitor_updates.first()
	}

	/// Returns true if funding_created was sent/received.
	pub fn is_funding_initiated(&self) -> bool {
		self.channel_state >= ChannelState::FundingSent as u32
	}

	/// Returns true if the channel is awaiting the persistence of the initial ChannelMonitor.
	/// If the channel is outbound, this implies we have not yet broadcasted the funding
	/// transaction. If the channel is inbound, this implies simply that the channel has not
	/// advanced state.
	pub fn is_awaiting_initial_mon_persist(&self) -> bool {
		if !self.is_awaiting_monitor_update() { return false; }
		if self.channel_state &
			!(ChannelState::TheirChannelReady as u32 | ChannelState::PeerDisconnected as u32 | ChannelState::MonitorUpdateInProgress as u32)
				== ChannelState::FundingSent as u32 {
			// If we're not a 0conf channel, we'll be waiting on a monitor update with only
			// FundingSent set, though our peer could have sent their channel_ready.
			debug_assert!(self.minimum_depth.unwrap_or(1) > 0);
			return true;
		}
		if self.cur_holder_commitment_transaction_number == INITIAL_COMMITMENT_NUMBER - 1 &&
			self.cur_counterparty_commitment_transaction_number == INITIAL_COMMITMENT_NUMBER - 1 {
			// If we're a 0-conf channel, we'll move beyond FundingSent immediately even while
			// waiting for the initial monitor persistence. Thus, we check if our commitment
			// transaction numbers have both been iterated only exactly once (for the
			// funding_signed), and we're awaiting monitor update.
			//
			// If we got here, we shouldn't have yet broadcasted the funding transaction (as the
			// only way to get an awaiting-monitor-update state during initial funding is if the
			// initial monitor persistence is still pending).
			//
			// Because deciding we're awaiting initial broadcast spuriously could result in
			// funds-loss (as we don't have a monitor, but have the funding transaction confirmed),
			// we hard-assert here, even in production builds.
			if self.is_outbound() { assert!(self.funding_transaction.is_some()); }
			assert!(self.monitor_pending_channel_ready);
			assert_eq!(self.latest_monitor_update_id, 0);
			return true;
		}
		false
	}

	/// Returns true if our channel_ready has been sent
	pub fn is_our_channel_ready(&self) -> bool {
		(self.channel_state & ChannelState::OurChannelReady as u32) != 0 || self.channel_state >= ChannelState::ChannelReady as u32
	}

	/// Returns true if our peer has either initiated or agreed to shut down the channel.
	pub fn received_shutdown(&self) -> bool {
		(self.channel_state & ChannelState::RemoteShutdownSent as u32) != 0
	}

	/// Returns true if we either initiated or agreed to shut down the channel.
	pub fn sent_shutdown(&self) -> bool {
		(self.channel_state & ChannelState::LocalShutdownSent as u32) != 0
	}

	/// Returns true if this channel is fully shut down. True here implies that no further actions
	/// may/will be taken on this channel, and thus this object should be freed. Any future changes
	/// will be handled appropriately by the chain monitor.
	pub fn is_shutdown(&self) -> bool {
		if (self.channel_state & ChannelState::ShutdownComplete as u32) == ChannelState::ShutdownComplete as u32  {
			assert!(self.channel_state == ChannelState::ShutdownComplete as u32);
			true
		} else { false }
	}

	pub fn channel_update_status(&self) -> ChannelUpdateStatus {
		self.channel_update_status
	}

	pub fn set_channel_update_status(&mut self, status: ChannelUpdateStatus) {
		self.update_time_counter += 1;
		self.channel_update_status = status;
	}

	fn check_get_channel_ready(&mut self, height: u32) -> Option<msgs::ChannelReady> {
		// Called:
		//  * always when a new block/transactions are confirmed with the new height
		//  * when funding is signed with a height of 0
		if self.funding_tx_confirmation_height == 0 && self.minimum_depth != Some(0) {
			return None;
		}

		let funding_tx_confirmations = height as i64 - self.funding_tx_confirmation_height as i64 + 1;
		if funding_tx_confirmations <= 0 {
			self.funding_tx_confirmation_height = 0;
		}

		if funding_tx_confirmations < self.minimum_depth.unwrap_or(0) as i64 {
			return None;
		}

		let non_shutdown_state = self.channel_state & (!MULTI_STATE_FLAGS);
		let need_commitment_update = if non_shutdown_state == ChannelState::FundingSent as u32 {
			self.channel_state |= ChannelState::OurChannelReady as u32;
			true
		} else if non_shutdown_state == (ChannelState::FundingSent as u32 | ChannelState::TheirChannelReady as u32) {
			self.channel_state = ChannelState::ChannelReady as u32 | (self.channel_state & MULTI_STATE_FLAGS);
			self.update_time_counter += 1;
			true
		} else if non_shutdown_state == (ChannelState::FundingSent as u32 | ChannelState::OurChannelReady as u32) {
			// We got a reorg but not enough to trigger a force close, just ignore.
			false
		} else {
			if self.funding_tx_confirmation_height != 0 && self.channel_state < ChannelState::ChannelReady as u32 {
				// We should never see a funding transaction on-chain until we've received
				// funding_signed (if we're an outbound channel), or seen funding_generated (if we're
				// an inbound channel - before that we have no known funding TXID). The fuzzer,
				// however, may do this and we shouldn't treat it as a bug.
				#[cfg(not(fuzzing))]
				panic!("Started confirming a channel in a state pre-FundingSent: {}.\n\
					Do NOT broadcast a funding transaction manually - let LDK do it for you!",
					self.channel_state);
			}
			// We got a reorg but not enough to trigger a force close, just ignore.
			false
		};

		if need_commitment_update {
			if self.channel_state & (ChannelState::MonitorUpdateInProgress as u32) == 0 {
				if self.channel_state & (ChannelState::PeerDisconnected as u32) == 0 {
					let next_per_commitment_point =
						self.holder_signer.get_per_commitment_point(INITIAL_COMMITMENT_NUMBER - 1, &self.secp_ctx);
					return Some(msgs::ChannelReady {
						channel_id: self.channel_id,
						next_per_commitment_point,
						short_channel_id_alias: Some(self.outbound_scid_alias),
					});
				}
			} else {
				self.monitor_pending_channel_ready = true;
			}
		}
		None
	}

	/// When a transaction is confirmed, we check whether it is or spends the funding transaction
	/// In the first case, we store the confirmation height and calculating the short channel id.
	/// In the second, we simply return an Err indicating we need to be force-closed now.
	pub fn transactions_confirmed<NS: Deref, L: Deref>(
		&mut self, block_hash: &BlockHash, height: u32, txdata: &TransactionData,
		genesis_block_hash: BlockHash, node_signer: &NS, user_config: &UserConfig, logger: &L
	) -> Result<(Option<msgs::ChannelReady>, Option<msgs::AnnouncementSignatures>), ClosureReason>
	where
		NS::Target: NodeSigner,
		L::Target: Logger
	{
		if let Some(funding_txo) = self.get_funding_txo() {
			for &(index_in_block, tx) in txdata.iter() {
				// Check if the transaction is the expected funding transaction, and if it is,
				// check that it pays the right amount to the right script.
				if self.funding_tx_confirmation_height == 0 {
					if tx.txid() == funding_txo.txid {
						let txo_idx = funding_txo.index as usize;
						if txo_idx >= tx.output.len() || tx.output[txo_idx].script_pubkey != self.get_funding_redeemscript().to_v0_p2wsh() ||
								tx.output[txo_idx].value != self.channel_value_satoshis {
							if self.is_outbound() {
								// If we generated the funding transaction and it doesn't match what it
								// should, the client is really broken and we should just panic and
								// tell them off. That said, because hash collisions happen with high
								// probability in fuzzing mode, if we're fuzzing we just close the
								// channel and move on.
								#[cfg(not(fuzzing))]
								panic!("Client called ChannelManager::funding_transaction_generated with bogus transaction!");
							}
							self.update_time_counter += 1;
							let err_reason = "funding tx had wrong script/value or output index";
							return Err(ClosureReason::ProcessingError { err: err_reason.to_owned() });
						} else {
							if self.is_outbound() {
								for input in tx.input.iter() {
									if input.witness.is_empty() {
										// We generated a malleable funding transaction, implying we've
										// just exposed ourselves to funds loss to our counterparty.
										#[cfg(not(fuzzing))]
										panic!("Client called ChannelManager::funding_transaction_generated with bogus transaction!");
									}
								}
							}
							self.funding_tx_confirmation_height = height;
							self.funding_tx_confirmed_in = Some(*block_hash);
							self.short_channel_id = match scid_from_parts(height as u64, index_in_block as u64, txo_idx as u64) {
								Ok(scid) => Some(scid),
								Err(_) => panic!("Block was bogus - either height was > 16 million, had > 16 million transactions, or had > 65k outputs"),
							}
						}
					}
					// If we allow 1-conf funding, we may need to check for channel_ready here and
					// send it immediately instead of waiting for a best_block_updated call (which
					// may have already happened for this block).
					if let Some(channel_ready) = self.check_get_channel_ready(height) {
						log_info!(logger, "Sending a channel_ready to our peer for channel {}", log_bytes!(self.channel_id));
						let announcement_sigs = self.get_announcement_sigs(node_signer, genesis_block_hash, user_config, height, logger);
						return Ok((Some(channel_ready), announcement_sigs));
					}
				}
				for inp in tx.input.iter() {
					if inp.previous_output == funding_txo.into_bitcoin_outpoint() {
						log_info!(logger, "Detected channel-closing tx {} spending {}:{}, closing channel {}", tx.txid(), inp.previous_output.txid, inp.previous_output.vout, log_bytes!(self.channel_id()));
						return Err(ClosureReason::CommitmentTxConfirmed);
					}
				}
			}
		}
		Ok((None, None))
	}

	/// When a new block is connected, we check the height of the block against outbound holding
	/// cell HTLCs in case we need to give up on them prematurely and time them out. Everything
	/// else (e.g. commitment transaction broadcasts, HTLC transaction broadcasting, etc) is
	/// handled by the ChannelMonitor.
	///
	/// If we return Err, the channel may have been closed, at which point the standard
	/// requirements apply - no calls may be made except those explicitly stated to be allowed
	/// post-shutdown.
	///
	/// May return some HTLCs (and their payment_hash) which have timed out and should be failed
	/// back.
	pub fn best_block_updated<NS: Deref, L: Deref>(
		&mut self, height: u32, highest_header_time: u32, genesis_block_hash: BlockHash,
		node_signer: &NS, user_config: &UserConfig, logger: &L
	) -> Result<(Option<msgs::ChannelReady>, Vec<(HTLCSource, PaymentHash)>, Option<msgs::AnnouncementSignatures>), ClosureReason>
	where
		NS::Target: NodeSigner,
		L::Target: Logger
	{
		self.do_best_block_updated(height, highest_header_time, Some((genesis_block_hash, node_signer, user_config)), logger)
	}

	fn do_best_block_updated<NS: Deref, L: Deref>(
		&mut self, height: u32, highest_header_time: u32,
		genesis_node_signer: Option<(BlockHash, &NS, &UserConfig)>, logger: &L
	) -> Result<(Option<msgs::ChannelReady>, Vec<(HTLCSource, PaymentHash)>, Option<msgs::AnnouncementSignatures>), ClosureReason>
	where
		NS::Target: NodeSigner,
		L::Target: Logger
	{
		let mut timed_out_htlcs = Vec::new();
		// This mirrors the check in ChannelManager::decode_update_add_htlc_onion, refusing to
		// forward an HTLC when our counterparty should almost certainly just fail it for expiring
		// ~now.
		let unforwarded_htlc_cltv_limit = height + LATENCY_GRACE_PERIOD_BLOCKS;
		self.holding_cell_htlc_updates.retain(|htlc_update| {
			match htlc_update {
				&HTLCUpdateAwaitingACK::AddHTLC { ref payment_hash, ref source, ref cltv_expiry, .. } => {
					if *cltv_expiry <= unforwarded_htlc_cltv_limit {
						timed_out_htlcs.push((source.clone(), payment_hash.clone()));
						false
					} else { true }
				},
				_ => true
			}
		});

		self.update_time_counter = cmp::max(self.update_time_counter, highest_header_time);

		if let Some(channel_ready) = self.check_get_channel_ready(height) {
			let announcement_sigs = if let Some((genesis_block_hash, node_signer, user_config)) = genesis_node_signer {
				self.get_announcement_sigs(node_signer, genesis_block_hash, user_config, height, logger)
			} else { None };
			log_info!(logger, "Sending a channel_ready to our peer for channel {}", log_bytes!(self.channel_id));
			return Ok((Some(channel_ready), timed_out_htlcs, announcement_sigs));
		}

		let non_shutdown_state = self.channel_state & (!MULTI_STATE_FLAGS);
		if non_shutdown_state >= ChannelState::ChannelReady as u32 ||
		   (non_shutdown_state & ChannelState::OurChannelReady as u32) == ChannelState::OurChannelReady as u32 {
			let mut funding_tx_confirmations = height as i64 - self.funding_tx_confirmation_height as i64 + 1;
			if self.funding_tx_confirmation_height == 0 {
				// Note that check_get_channel_ready may reset funding_tx_confirmation_height to
				// zero if it has been reorged out, however in either case, our state flags
				// indicate we've already sent a channel_ready
				funding_tx_confirmations = 0;
			}

			// If we've sent channel_ready (or have both sent and received channel_ready), and
			// the funding transaction has become unconfirmed,
			// close the channel and hope we can get the latest state on chain (because presumably
			// the funding transaction is at least still in the mempool of most nodes).
			//
			// Note that ideally we wouldn't force-close if we see *any* reorg on a 1-conf or
			// 0-conf channel, but not doing so may lead to the
			// `ChannelManager::short_to_chan_info` map  being inconsistent, so we currently have
			// to.
			if funding_tx_confirmations == 0 && self.funding_tx_confirmed_in.is_some() {
				let err_reason = format!("Funding transaction was un-confirmed. Locked at {} confs, now have {} confs.",
					self.minimum_depth.unwrap(), funding_tx_confirmations);
				return Err(ClosureReason::ProcessingError { err: err_reason });
			}
		} else if !self.is_outbound() && self.funding_tx_confirmed_in.is_none() &&
				height >= self.channel_creation_height + FUNDING_CONF_DEADLINE_BLOCKS {
			log_info!(logger, "Closing channel {} due to funding timeout", log_bytes!(self.channel_id));
			// If funding_tx_confirmed_in is unset, the channel must not be active
			assert!(non_shutdown_state <= ChannelState::ChannelReady as u32);
			assert_eq!(non_shutdown_state & ChannelState::OurChannelReady as u32, 0);
			return Err(ClosureReason::FundingTimedOut);
		}

		let announcement_sigs = if let Some((genesis_block_hash, node_signer, user_config)) = genesis_node_signer {
			self.get_announcement_sigs(node_signer, genesis_block_hash, user_config, height, logger)
		} else { None };
		Ok((None, timed_out_htlcs, announcement_sigs))
	}

	/// Indicates the funding transaction is no longer confirmed in the main chain. This may
	/// force-close the channel, but may also indicate a harmless reorganization of a block or two
	/// before the channel has reached channel_ready and we can just wait for more blocks.
	pub fn funding_transaction_unconfirmed<L: Deref>(&mut self, logger: &L) -> Result<(), ClosureReason> where L::Target: Logger {
		if self.funding_tx_confirmation_height != 0 {
			// We handle the funding disconnection by calling best_block_updated with a height one
			// below where our funding was connected, implying a reorg back to conf_height - 1.
			let reorg_height = self.funding_tx_confirmation_height - 1;
			// We use the time field to bump the current time we set on channel updates if its
			// larger. If we don't know that time has moved forward, we can just set it to the last
			// time we saw and it will be ignored.
			let best_time = self.update_time_counter;
			match self.do_best_block_updated(reorg_height, best_time, None::<(BlockHash, &&NodeSigner, &UserConfig)>, logger) {
				Ok((channel_ready, timed_out_htlcs, announcement_sigs)) => {
					assert!(channel_ready.is_none(), "We can't generate a funding with 0 confirmations?");
					assert!(timed_out_htlcs.is_empty(), "We can't have accepted HTLCs with a timeout before our funding confirmation?");
					assert!(announcement_sigs.is_none(), "We can't generate an announcement_sigs with 0 confirmations?");
					Ok(())
				},
				Err(e) => Err(e)
			}
		} else {
			// We never learned about the funding confirmation anyway, just ignore
			Ok(())
		}
	}

	// Methods to get unprompted messages to send to the remote end (or where we already returned
	// something in the handler for the message that prompted this message):

	pub fn get_open_channel(&self, chain_hash: BlockHash) -> msgs::OpenChannel {
		if !self.is_outbound() {
			panic!("Tried to open a channel for an inbound channel?");
		}
		if self.channel_state != ChannelState::OurInitSent as u32 {
			panic!("Cannot generate an open_channel after we've moved forward");
		}

		if self.cur_holder_commitment_transaction_number != INITIAL_COMMITMENT_NUMBER {
			panic!("Tried to send an open_channel for a channel that has already advanced");
		}

		let first_per_commitment_point = self.holder_signer.get_per_commitment_point(self.cur_holder_commitment_transaction_number, &self.secp_ctx);
		let keys = self.get_holder_pubkeys();

		msgs::OpenChannel {
			chain_hash,
			temporary_channel_id: self.channel_id,
			funding_satoshis: self.channel_value_satoshis,
			push_msat: self.channel_value_satoshis * 1000 - self.value_to_self_msat,
			dust_limit_satoshis: self.holder_dust_limit_satoshis,
			max_htlc_value_in_flight_msat: self.holder_max_htlc_value_in_flight_msat,
			channel_reserve_satoshis: self.holder_selected_channel_reserve_satoshis,
			htlc_minimum_msat: self.holder_htlc_minimum_msat,
			feerate_per_kw: self.feerate_per_kw as u32,
			to_self_delay: self.get_holder_selected_contest_delay(),
			max_accepted_htlcs: OUR_MAX_HTLCS,
			funding_pubkey: keys.funding_pubkey,
			revocation_basepoint: keys.revocation_basepoint,
			payment_point: keys.payment_point,
			delayed_payment_basepoint: keys.delayed_payment_basepoint,
			htlc_basepoint: keys.htlc_basepoint,
			first_per_commitment_point,
			channel_flags: if self.config.announced_channel {1} else {0},
			shutdown_scriptpubkey: OptionalField::Present(match &self.shutdown_scriptpubkey {
				Some(script) => script.clone().into_inner(),
				None => Builder::new().into_script(),
			}),
			channel_type: Some(self.channel_type.clone()),
		}
	}

	pub fn inbound_is_awaiting_accept(&self) -> bool {
		self.inbound_awaiting_accept
	}

	/// Sets this channel to accepting 0conf, must be done before `get_accept_channel`
	pub fn set_0conf(&mut self) {
		assert!(self.inbound_awaiting_accept);
		self.minimum_depth = Some(0);
	}

	/// Marks an inbound channel as accepted and generates a [`msgs::AcceptChannel`] message which
	/// should be sent back to the counterparty node.
	///
	/// [`msgs::AcceptChannel`]: crate::ln::msgs::AcceptChannel
	pub fn accept_inbound_channel(&mut self, user_id: u128) -> msgs::AcceptChannel {
		if self.is_outbound() {
			panic!("Tried to send accept_channel for an outbound channel?");
		}
		if self.channel_state != (ChannelState::OurInitSent as u32) | (ChannelState::TheirInitSent as u32) {
			panic!("Tried to send accept_channel after channel had moved forward");
		}
		if self.cur_holder_commitment_transaction_number != INITIAL_COMMITMENT_NUMBER {
			panic!("Tried to send an accept_channel for a channel that has already advanced");
		}
		if !self.inbound_awaiting_accept {
			panic!("The inbound channel has already been accepted");
		}

		self.user_id = user_id;
		self.inbound_awaiting_accept = false;

		self.generate_accept_channel_message()
	}

	/// This function is used to explicitly generate a [`msgs::AcceptChannel`] message for an
	/// inbound channel. If the intention is to accept an inbound channel, use
	/// [`Channel::accept_inbound_channel`] instead.
	///
	/// [`msgs::AcceptChannel`]: crate::ln::msgs::AcceptChannel
	fn generate_accept_channel_message(&self) -> msgs::AcceptChannel {
		let first_per_commitment_point = self.holder_signer.get_per_commitment_point(self.cur_holder_commitment_transaction_number, &self.secp_ctx);
		let keys = self.get_holder_pubkeys();

		msgs::AcceptChannel {
			temporary_channel_id: self.channel_id,
			dust_limit_satoshis: self.holder_dust_limit_satoshis,
			max_htlc_value_in_flight_msat: self.holder_max_htlc_value_in_flight_msat,
			channel_reserve_satoshis: self.holder_selected_channel_reserve_satoshis,
			htlc_minimum_msat: self.holder_htlc_minimum_msat,
			minimum_depth: self.minimum_depth.unwrap(),
			to_self_delay: self.get_holder_selected_contest_delay(),
			max_accepted_htlcs: OUR_MAX_HTLCS,
			funding_pubkey: keys.funding_pubkey,
			revocation_basepoint: keys.revocation_basepoint,
			payment_point: keys.payment_point,
			delayed_payment_basepoint: keys.delayed_payment_basepoint,
			htlc_basepoint: keys.htlc_basepoint,
			first_per_commitment_point,
			shutdown_scriptpubkey: OptionalField::Present(match &self.shutdown_scriptpubkey {
				Some(script) => script.clone().into_inner(),
				None => Builder::new().into_script(),
			}),
			channel_type: Some(self.channel_type.clone()),
		}
	}

	/// Enables the possibility for tests to extract a [`msgs::AcceptChannel`] message for an
	/// inbound channel without accepting it.
	///
	/// [`msgs::AcceptChannel`]: crate::ln::msgs::AcceptChannel
	#[cfg(test)]
	pub fn get_accept_channel_message(&self) -> msgs::AcceptChannel {
		self.generate_accept_channel_message()
	}

	/// If an Err is returned, it is a ChannelError::Close (for get_outbound_funding_created)
	fn get_outbound_funding_created_signature<L: Deref>(&mut self, logger: &L) -> Result<Signature, ChannelError> where L::Target: Logger {
		let counterparty_keys = self.build_remote_transaction_keys();
		let counterparty_initial_commitment_tx = self.build_commitment_transaction(self.cur_counterparty_commitment_transaction_number, &counterparty_keys, false, false, logger).tx;
		Ok(self.holder_signer.sign_counterparty_commitment(&counterparty_initial_commitment_tx, Vec::new(), &self.secp_ctx)
				.map_err(|_| ChannelError::Close("Failed to get signatures for new commitment_signed".to_owned()))?.0)
	}

	/// Updates channel state with knowledge of the funding transaction's txid/index, and generates
	/// a funding_created message for the remote peer.
	/// Panics if called at some time other than immediately after initial handshake, if called twice,
	/// or if called on an inbound channel.
	/// Note that channel_id changes during this call!
	/// Do NOT broadcast the funding transaction until after a successful funding_signed call!
	/// If an Err is returned, it is a ChannelError::Close.
	pub fn get_outbound_funding_created<L: Deref>(&mut self, funding_transaction: Transaction, funding_txo: OutPoint, logger: &L) -> Result<msgs::FundingCreated, ChannelError> where L::Target: Logger {
		if !self.is_outbound() {
			panic!("Tried to create outbound funding_created message on an inbound channel!");
		}
		if self.channel_state != (ChannelState::OurInitSent as u32 | ChannelState::TheirInitSent as u32) {
			panic!("Tried to get a funding_created messsage at a time other than immediately after initial handshake completion (or tried to get funding_created twice)");
		}
		if self.commitment_secrets.get_min_seen_secret() != (1 << 48) ||
				self.cur_counterparty_commitment_transaction_number != INITIAL_COMMITMENT_NUMBER ||
				self.cur_holder_commitment_transaction_number != INITIAL_COMMITMENT_NUMBER {
			panic!("Should not have advanced channel commitment tx numbers prior to funding_created");
		}

		self.channel_transaction_parameters.funding_outpoint = Some(funding_txo);
		self.holder_signer.provide_channel_parameters(&self.channel_transaction_parameters);

		let signature = match self.get_outbound_funding_created_signature(logger) {
			Ok(res) => res,
			Err(e) => {
				log_error!(logger, "Got bad signatures: {:?}!", e);
				self.channel_transaction_parameters.funding_outpoint = None;
				return Err(e);
			}
		};

		let temporary_channel_id = self.channel_id;

		// Now that we're past error-generating stuff, update our local state:

		self.channel_state = ChannelState::FundingCreated as u32;
		self.channel_id = funding_txo.to_channel_id();
		self.funding_transaction = Some(funding_transaction);

		Ok(msgs::FundingCreated {
			temporary_channel_id,
			funding_txid: funding_txo.txid,
			funding_output_index: funding_txo.index,
			signature
		})
	}

	/// Gets an UnsignedChannelAnnouncement for this channel. The channel must be publicly
	/// announceable and available for use (have exchanged ChannelReady messages in both
	/// directions). Should be used for both broadcasted announcements and in response to an
	/// AnnouncementSignatures message from the remote peer.
	///
	/// Will only fail if we're not in a state where channel_announcement may be sent (including
	/// closing).
	///
	/// This will only return ChannelError::Ignore upon failure.
	fn get_channel_announcement<NS: Deref>(
		&self, node_signer: &NS, chain_hash: BlockHash, user_config: &UserConfig,
	) -> Result<msgs::UnsignedChannelAnnouncement, ChannelError> where NS::Target: NodeSigner {
		if !self.config.announced_channel {
			return Err(ChannelError::Ignore("Channel is not available for public announcements".to_owned()));
		}
		if !self.is_usable() {
			return Err(ChannelError::Ignore("Cannot get a ChannelAnnouncement if the channel is not currently usable".to_owned()));
		}

		let node_id = NodeId::from_pubkey(&node_signer.get_node_id(Recipient::Node)
			.map_err(|_| ChannelError::Ignore("Failed to retrieve own public key".to_owned()))?);
		let counterparty_node_id = NodeId::from_pubkey(&self.get_counterparty_node_id());
		let were_node_one = node_id.as_slice() < counterparty_node_id.as_slice();

		let msg = msgs::UnsignedChannelAnnouncement {
			features: channelmanager::provided_channel_features(&user_config),
			chain_hash,
			short_channel_id: self.get_short_channel_id().unwrap(),
			node_id_1: if were_node_one { node_id } else { counterparty_node_id },
			node_id_2: if were_node_one { counterparty_node_id } else { node_id },
			bitcoin_key_1: NodeId::from_pubkey(if were_node_one { &self.get_holder_pubkeys().funding_pubkey } else { self.counterparty_funding_pubkey() }),
			bitcoin_key_2: NodeId::from_pubkey(if were_node_one { self.counterparty_funding_pubkey() } else { &self.get_holder_pubkeys().funding_pubkey }),
			excess_data: Vec::new(),
		};

		Ok(msg)
	}

	fn get_announcement_sigs<NS: Deref, L: Deref>(
		&mut self, node_signer: &NS, genesis_block_hash: BlockHash, user_config: &UserConfig,
		best_block_height: u32, logger: &L
	) -> Option<msgs::AnnouncementSignatures>
	where
		NS::Target: NodeSigner,
		L::Target: Logger
	{
		if self.funding_tx_confirmation_height == 0 || self.funding_tx_confirmation_height + 5 > best_block_height {
			return None;
		}

		if !self.is_usable() {
			return None;
		}

		if self.channel_state & ChannelState::PeerDisconnected as u32 != 0 {
			log_trace!(logger, "Cannot create an announcement_signatures as our peer is disconnected");
			return None;
		}

		if self.announcement_sigs_state != AnnouncementSigsState::NotSent {
			return None;
		}

		log_trace!(logger, "Creating an announcement_signatures message for channel {}", log_bytes!(self.channel_id()));
		let announcement = match self.get_channel_announcement(node_signer, genesis_block_hash, user_config) {
			Ok(a) => a,
			Err(e) => {
				log_trace!(logger, "{:?}", e);
				return None;
			}
		};
		let our_node_sig = match node_signer.sign_gossip_message(msgs::UnsignedGossipMessage::ChannelAnnouncement(&announcement)) {
			Err(_) => {
				log_error!(logger, "Failed to generate node signature for channel_announcement. Channel will not be announced!");
				return None;
			},
			Ok(v) => v
		};
		let our_bitcoin_sig = match self.holder_signer.sign_channel_announcement_with_funding_key(&announcement, &self.secp_ctx) {
			Err(_) => {
				log_error!(logger, "Signer rejected channel_announcement signing. Channel will not be announced!");
				return None;
			},
			Ok(v) => v
		};
		self.announcement_sigs_state = AnnouncementSigsState::MessageSent;

		Some(msgs::AnnouncementSignatures {
			channel_id: self.channel_id(),
			short_channel_id: self.get_short_channel_id().unwrap(),
			node_signature: our_node_sig,
			bitcoin_signature: our_bitcoin_sig,
		})
	}

	/// Signs the given channel announcement, returning a ChannelError::Ignore if no keys are
	/// available.
	fn sign_channel_announcement<NS: Deref>(
		&self, node_signer: &NS, announcement: msgs::UnsignedChannelAnnouncement
	) -> Result<msgs::ChannelAnnouncement, ChannelError> where NS::Target: NodeSigner {
		if let Some((their_node_sig, their_bitcoin_sig)) = self.announcement_sigs {
			let our_node_key = NodeId::from_pubkey(&node_signer.get_node_id(Recipient::Node)
				.map_err(|_| ChannelError::Ignore("Signer failed to retrieve own public key".to_owned()))?);
			let were_node_one = announcement.node_id_1 == our_node_key;

			let our_node_sig = node_signer.sign_gossip_message(msgs::UnsignedGossipMessage::ChannelAnnouncement(&announcement))
				.map_err(|_| ChannelError::Ignore("Failed to generate node signature for channel_announcement".to_owned()))?;
			let our_bitcoin_sig = self.holder_signer.sign_channel_announcement_with_funding_key(&announcement, &self.secp_ctx)
				.map_err(|_| ChannelError::Ignore("Signer rejected channel_announcement".to_owned()))?;
			Ok(msgs::ChannelAnnouncement {
				node_signature_1: if were_node_one { our_node_sig } else { their_node_sig },
				node_signature_2: if were_node_one { their_node_sig } else { our_node_sig },
				bitcoin_signature_1: if were_node_one { our_bitcoin_sig } else { their_bitcoin_sig },
				bitcoin_signature_2: if were_node_one { their_bitcoin_sig } else { our_bitcoin_sig },
				contents: announcement,
			})
		} else {
			Err(ChannelError::Ignore("Attempted to sign channel announcement before we'd received announcement_signatures".to_string()))
		}
	}

	/// Processes an incoming announcement_signatures message, providing a fully-signed
	/// channel_announcement message which we can broadcast and storing our counterparty's
	/// signatures for later reconstruction/rebroadcast of the channel_announcement.
	pub fn announcement_signatures<NS: Deref>(
		&mut self, node_signer: &NS, chain_hash: BlockHash, best_block_height: u32,
		msg: &msgs::AnnouncementSignatures, user_config: &UserConfig
	) -> Result<msgs::ChannelAnnouncement, ChannelError> where NS::Target: NodeSigner {
		let announcement = self.get_channel_announcement(node_signer, chain_hash, user_config)?;

		let msghash = hash_to_message!(&Sha256d::hash(&announcement.encode()[..])[..]);

		if self.secp_ctx.verify_ecdsa(&msghash, &msg.node_signature, &self.get_counterparty_node_id()).is_err() {
			return Err(ChannelError::Close(format!(
				"Bad announcement_signatures. Failed to verify node_signature. UnsignedChannelAnnouncement used for verification is {:?}. their_node_key is {:?}",
				 &announcement, self.get_counterparty_node_id())));
		}
		if self.secp_ctx.verify_ecdsa(&msghash, &msg.bitcoin_signature, self.counterparty_funding_pubkey()).is_err() {
			return Err(ChannelError::Close(format!(
				"Bad announcement_signatures. Failed to verify bitcoin_signature. UnsignedChannelAnnouncement used for verification is {:?}. their_bitcoin_key is ({:?})",
				&announcement, self.counterparty_funding_pubkey())));
		}

		self.announcement_sigs = Some((msg.node_signature, msg.bitcoin_signature));
		if self.funding_tx_confirmation_height == 0 || self.funding_tx_confirmation_height + 5 > best_block_height {
			return Err(ChannelError::Ignore(
				"Got announcement_signatures prior to the required six confirmations - we may not have received a block yet that our peer has".to_owned()));
		}

		self.sign_channel_announcement(node_signer, announcement)
	}

	/// Gets a signed channel_announcement for this channel, if we previously received an
	/// announcement_signatures from our counterparty.
	pub fn get_signed_channel_announcement<NS: Deref>(
		&self, node_signer: &NS, chain_hash: BlockHash, best_block_height: u32, user_config: &UserConfig
	) -> Option<msgs::ChannelAnnouncement> where NS::Target: NodeSigner {
		if self.funding_tx_confirmation_height == 0 || self.funding_tx_confirmation_height + 5 > best_block_height {
			return None;
		}
		let announcement = match self.get_channel_announcement(node_signer, chain_hash, user_config) {
			Ok(res) => res,
			Err(_) => return None,
		};
		match self.sign_channel_announcement(node_signer, announcement) {
			Ok(res) => Some(res),
			Err(_) => None,
		}
	}

	/// May panic if called on a channel that wasn't immediately-previously
	/// self.remove_uncommitted_htlcs_and_mark_paused()'d
	pub fn get_channel_reestablish<L: Deref>(&self, logger: &L) -> msgs::ChannelReestablish where L::Target: Logger {
		assert_eq!(self.channel_state & ChannelState::PeerDisconnected as u32, ChannelState::PeerDisconnected as u32);
		assert_ne!(self.cur_counterparty_commitment_transaction_number, INITIAL_COMMITMENT_NUMBER);
		// Prior to static_remotekey, my_current_per_commitment_point was critical to claiming
		// current to_remote balances. However, it no longer has any use, and thus is now simply
		// set to a dummy (but valid, as required by the spec) public key.
		// fuzzing mode marks a subset of pubkeys as invalid so that we can hit "invalid pubkey"
		// branches, but we unwrap it below, so we arbitrarily select a dummy pubkey which is both
		// valid, and valid in fuzzing mode's arbitrary validity criteria:
		let mut pk = [2; 33]; pk[1] = 0xff;
		let dummy_pubkey = PublicKey::from_slice(&pk).unwrap();
		let data_loss_protect = if self.cur_counterparty_commitment_transaction_number + 1 < INITIAL_COMMITMENT_NUMBER {
			let remote_last_secret = self.commitment_secrets.get_secret(self.cur_counterparty_commitment_transaction_number + 2).unwrap();
			log_trace!(logger, "Enough info to generate a Data Loss Protect with per_commitment_secret {} for channel {}", log_bytes!(remote_last_secret), log_bytes!(self.channel_id()));
			OptionalField::Present(DataLossProtect {
				your_last_per_commitment_secret: remote_last_secret,
				my_current_per_commitment_point: dummy_pubkey
			})
		} else {
			log_info!(logger, "Sending a data_loss_protect with no previous remote per_commitment_secret for channel {}", log_bytes!(self.channel_id()));
			OptionalField::Present(DataLossProtect {
				your_last_per_commitment_secret: [0;32],
				my_current_per_commitment_point: dummy_pubkey,
			})
		};
		msgs::ChannelReestablish {
			channel_id: self.channel_id(),
			// The protocol has two different commitment number concepts - the "commitment
			// transaction number", which starts from 0 and counts up, and the "revocation key
			// index" which starts at INITIAL_COMMITMENT_NUMBER and counts down. We track
			// commitment transaction numbers by the index which will be used to reveal the
			// revocation key for that commitment transaction, which means we have to convert them
			// to protocol-level commitment numbers here...

			// next_local_commitment_number is the next commitment_signed number we expect to
			// receive (indicating if they need to resend one that we missed).
			next_local_commitment_number: INITIAL_COMMITMENT_NUMBER - self.cur_holder_commitment_transaction_number,
			// We have to set next_remote_commitment_number to the next revoke_and_ack we expect to
			// receive, however we track it by the next commitment number for a remote transaction
			// (which is one further, as they always revoke previous commitment transaction, not
			// the one we send) so we have to decrement by 1. Note that if
			// cur_counterparty_commitment_transaction_number is INITIAL_COMMITMENT_NUMBER we will have
			// dropped this channel on disconnect as it hasn't yet reached FundingSent so we can't
			// overflow here.
			next_remote_commitment_number: INITIAL_COMMITMENT_NUMBER - self.cur_counterparty_commitment_transaction_number - 1,
			data_loss_protect,
		}
	}


	// Send stuff to our remote peers:

	/// Queues up an outbound HTLC to send by placing it in the holding cell. You should call
	/// [`Self::maybe_free_holding_cell_htlcs`] in order to actually generate and send the
	/// commitment update.
	///
	/// `Err`s will only be [`ChannelError::Ignore`].
	pub fn queue_add_htlc<L: Deref>(&mut self, amount_msat: u64, payment_hash: PaymentHash, cltv_expiry: u32, source: HTLCSource,
		onion_routing_packet: msgs::OnionPacket, logger: &L)
	-> Result<(), ChannelError> where L::Target: Logger {
		self
			.send_htlc(amount_msat, payment_hash, cltv_expiry, source, onion_routing_packet, true, logger)
			.map(|msg_opt| assert!(msg_opt.is_none(), "We forced holding cell?"))
			.map_err(|err| {
				if let ChannelError::Ignore(_) = err { /* fine */ }
				else { debug_assert!(false, "Queueing cannot trigger channel failure"); }
				err
			})
	}

	/// Adds a pending outbound HTLC to this channel, note that you probably want
	/// [`Self::send_htlc_and_commit`] instead cause you'll want both messages at once.
	///
	/// This returns an optional UpdateAddHTLC as we may be in a state where we cannot add HTLCs on
	/// the wire:
	/// * In cases where we're waiting on the remote peer to send us a revoke_and_ack, we
	///   wouldn't be able to determine what they actually ACK'ed if we have two sets of updates
	///   awaiting ACK.
	/// * In cases where we're marked MonitorUpdateInProgress, we cannot commit to a new state as
	///   we may not yet have sent the previous commitment update messages and will need to
	///   regenerate them.
	///
	/// You MUST call [`Self::send_commitment_no_state_update`] prior to calling any other methods
	/// on this [`Channel`] if `force_holding_cell` is false.
	///
	/// `Err`s will only be [`ChannelError::Ignore`].
	fn send_htlc<L: Deref>(&mut self, amount_msat: u64, payment_hash: PaymentHash, cltv_expiry: u32, source: HTLCSource,
		onion_routing_packet: msgs::OnionPacket, mut force_holding_cell: bool, logger: &L)
	-> Result<Option<msgs::UpdateAddHTLC>, ChannelError> where L::Target: Logger {
		if (self.channel_state & (ChannelState::ChannelReady as u32 | BOTH_SIDES_SHUTDOWN_MASK)) != (ChannelState::ChannelReady as u32) {
			return Err(ChannelError::Ignore("Cannot send HTLC until channel is fully established and we haven't started shutting down".to_owned()));
		}
		let channel_total_msat = self.channel_value_satoshis * 1000;
		if amount_msat > channel_total_msat {
			return Err(ChannelError::Ignore(format!("Cannot send amount {}, because it is more than the total value of the channel {}", amount_msat, channel_total_msat)));
		}

		if amount_msat == 0 {
			return Err(ChannelError::Ignore("Cannot send 0-msat HTLC".to_owned()));
		}

		if amount_msat < self.counterparty_htlc_minimum_msat {
			return Err(ChannelError::Ignore(format!("Cannot send less than their minimum HTLC value ({})", self.counterparty_htlc_minimum_msat)));
		}

		if (self.channel_state & (ChannelState::PeerDisconnected as u32)) != 0 {
			// Note that this should never really happen, if we're !is_live() on receipt of an
			// incoming HTLC for relay will result in us rejecting the HTLC and we won't allow
			// the user to send directly into a !is_live() channel. However, if we
			// disconnected during the time the previous hop was doing the commitment dance we may
			// end up getting here after the forwarding delay. In any case, returning an
			// IgnoreError will get ChannelManager to do the right thing and fail backwards now.
			return Err(ChannelError::Ignore("Cannot send an HTLC while disconnected from channel counterparty".to_owned()));
		}

		let inbound_stats = self.get_inbound_pending_htlc_stats(None);
		let outbound_stats = self.get_outbound_pending_htlc_stats(None);
		if outbound_stats.pending_htlcs + 1 > self.counterparty_max_accepted_htlcs as u32 {
			return Err(ChannelError::Ignore(format!("Cannot push more than their max accepted HTLCs ({})", self.counterparty_max_accepted_htlcs)));
		}
		// Check their_max_htlc_value_in_flight_msat
		if outbound_stats.pending_htlcs_value_msat + amount_msat > self.counterparty_max_htlc_value_in_flight_msat {
			return Err(ChannelError::Ignore(format!("Cannot send value that would put us over the max HTLC value in flight our peer will accept ({})", self.counterparty_max_htlc_value_in_flight_msat)));
		}

		let keys = self.build_holder_transaction_keys(self.cur_holder_commitment_transaction_number);
		let commitment_stats = self.build_commitment_transaction(self.cur_holder_commitment_transaction_number, &keys, true, true, logger);
		if !self.is_outbound() {
			// Check that we won't violate the remote channel reserve by adding this HTLC.
			let htlc_candidate = HTLCCandidate::new(amount_msat, HTLCInitiator::LocalOffered);
			let counterparty_commit_tx_fee_msat = self.next_remote_commit_tx_fee_msat(htlc_candidate, None);
			let holder_selected_chan_reserve_msat = self.holder_selected_channel_reserve_satoshis * 1000;
			if commitment_stats.remote_balance_msat < counterparty_commit_tx_fee_msat + holder_selected_chan_reserve_msat {
				return Err(ChannelError::Ignore("Cannot send value that would put counterparty balance under holder-announced channel reserve value".to_owned()));
			}
		}

		let (htlc_success_dust_limit, htlc_timeout_dust_limit) = if self.opt_anchors() {
			(0, 0)
		} else {
			let dust_buffer_feerate = self.get_dust_buffer_feerate(None) as u64;
			(dust_buffer_feerate * htlc_success_tx_weight(false) / 1000,
				dust_buffer_feerate * htlc_timeout_tx_weight(false) / 1000)
		};
		let exposure_dust_limit_success_sats = htlc_success_dust_limit + self.counterparty_dust_limit_satoshis;
		if amount_msat / 1000 < exposure_dust_limit_success_sats {
			let on_counterparty_dust_htlc_exposure_msat = inbound_stats.on_counterparty_tx_dust_exposure_msat + outbound_stats.on_counterparty_tx_dust_exposure_msat + amount_msat;
			if on_counterparty_dust_htlc_exposure_msat > self.get_max_dust_htlc_exposure_msat() {
				return Err(ChannelError::Ignore(format!("Cannot send value that would put our exposure to dust HTLCs at {} over the limit {} on counterparty commitment tx",
					on_counterparty_dust_htlc_exposure_msat, self.get_max_dust_htlc_exposure_msat())));
			}
		}

		let exposure_dust_limit_timeout_sats = htlc_timeout_dust_limit + self.holder_dust_limit_satoshis;
		if amount_msat / 1000 <  exposure_dust_limit_timeout_sats {
			let on_holder_dust_htlc_exposure_msat = inbound_stats.on_holder_tx_dust_exposure_msat + outbound_stats.on_holder_tx_dust_exposure_msat + amount_msat;
			if on_holder_dust_htlc_exposure_msat > self.get_max_dust_htlc_exposure_msat() {
				return Err(ChannelError::Ignore(format!("Cannot send value that would put our exposure to dust HTLCs at {} over the limit {} on holder commitment tx",
					on_holder_dust_htlc_exposure_msat, self.get_max_dust_htlc_exposure_msat())));
			}
		}

		let holder_balance_msat = commitment_stats.local_balance_msat - outbound_stats.holding_cell_msat;
		if holder_balance_msat < amount_msat {
			return Err(ChannelError::Ignore(format!("Cannot send value that would overdraw remaining funds. Amount: {}, pending value to self {}", amount_msat, holder_balance_msat)));
		}

		// `2 *` and extra HTLC are for the fee spike buffer.
		let commit_tx_fee_msat = if self.is_outbound() {
			let htlc_candidate = HTLCCandidate::new(amount_msat, HTLCInitiator::LocalOffered);
			FEE_SPIKE_BUFFER_FEE_INCREASE_MULTIPLE * self.next_local_commit_tx_fee_msat(htlc_candidate, Some(()))
		} else { 0 };
		if holder_balance_msat - amount_msat < commit_tx_fee_msat {
			return Err(ChannelError::Ignore(format!("Cannot send value that would not leave enough to pay for fees. Pending value to self: {}. local_commit_tx_fee {}", holder_balance_msat, commit_tx_fee_msat)));
		}

		// Check self.counterparty_selected_channel_reserve_satoshis (the amount we must keep as
		// reserve for the remote to have something to claim if we misbehave)
		let chan_reserve_msat = self.counterparty_selected_channel_reserve_satoshis.unwrap() * 1000;
		if holder_balance_msat - amount_msat - commit_tx_fee_msat < chan_reserve_msat {
			return Err(ChannelError::Ignore(format!("Cannot send value that would put our balance under counterparty-announced channel reserve value ({})", chan_reserve_msat)));
		}

		if (self.channel_state & (ChannelState::AwaitingRemoteRevoke as u32 | ChannelState::MonitorUpdateInProgress as u32)) != 0 {
			force_holding_cell = true;
		}

		// Now update local state:
		if force_holding_cell {
			self.holding_cell_htlc_updates.push(HTLCUpdateAwaitingACK::AddHTLC {
				amount_msat,
				payment_hash,
				cltv_expiry,
				source,
				onion_routing_packet,
			});
			return Ok(None);
		}

		self.pending_outbound_htlcs.push(OutboundHTLCOutput {
			htlc_id: self.next_holder_htlc_id,
			amount_msat,
			payment_hash: payment_hash.clone(),
			cltv_expiry,
			state: OutboundHTLCState::LocalAnnounced(Box::new(onion_routing_packet.clone())),
			source,
		});

		let res = msgs::UpdateAddHTLC {
			channel_id: self.channel_id,
			htlc_id: self.next_holder_htlc_id,
			amount_msat,
			payment_hash,
			cltv_expiry,
			onion_routing_packet,
		};
		self.next_holder_htlc_id += 1;

		Ok(Some(res))
	}

	fn build_commitment_no_status_check<L: Deref>(&mut self, logger: &L) -> ChannelMonitorUpdate where L::Target: Logger {
		log_trace!(logger, "Updating HTLC state for a newly-sent commitment_signed...");
		// We can upgrade the status of some HTLCs that are waiting on a commitment, even if we
		// fail to generate this, we still are at least at a position where upgrading their status
		// is acceptable.
		for htlc in self.pending_inbound_htlcs.iter_mut() {
			let new_state = if let &InboundHTLCState::AwaitingRemoteRevokeToAnnounce(ref forward_info) = &htlc.state {
				Some(InboundHTLCState::AwaitingAnnouncedRemoteRevoke(forward_info.clone()))
			} else { None };
			if let Some(state) = new_state {
				log_trace!(logger, " ...promoting inbound AwaitingRemoteRevokeToAnnounce {} to AwaitingAnnouncedRemoteRevoke", log_bytes!(htlc.payment_hash.0));
				htlc.state = state;
			}
		}
		for htlc in self.pending_outbound_htlcs.iter_mut() {
			if let &mut OutboundHTLCState::AwaitingRemoteRevokeToRemove(ref mut outcome) = &mut htlc.state {
				log_trace!(logger, " ...promoting outbound AwaitingRemoteRevokeToRemove {} to AwaitingRemovedRemoteRevoke", log_bytes!(htlc.payment_hash.0));
				// Grab the preimage, if it exists, instead of cloning
				let mut reason = OutboundHTLCOutcome::Success(None);
				mem::swap(outcome, &mut reason);
				htlc.state = OutboundHTLCState::AwaitingRemovedRemoteRevoke(reason);
			}
		}
		if let Some((feerate, update_state)) = self.pending_update_fee {
			if update_state == FeeUpdateState::AwaitingRemoteRevokeToAnnounce {
				debug_assert!(!self.is_outbound());
				log_trace!(logger, " ...promoting inbound AwaitingRemoteRevokeToAnnounce fee update {} to Committed", feerate);
				self.feerate_per_kw = feerate;
				self.pending_update_fee = None;
			}
		}
		self.resend_order = RAACommitmentOrder::RevokeAndACKFirst;

		let (counterparty_commitment_txid, mut htlcs_ref) = self.build_commitment_no_state_update(logger);
		let htlcs: Vec<(HTLCOutputInCommitment, Option<Box<HTLCSource>>)> =
			htlcs_ref.drain(..).map(|(htlc, htlc_source)| (htlc, htlc_source.map(|source_ref| Box::new(source_ref.clone())))).collect();

		if self.announcement_sigs_state == AnnouncementSigsState::MessageSent {
			self.announcement_sigs_state = AnnouncementSigsState::Committed;
		}

		self.latest_monitor_update_id += 1;
		let monitor_update = ChannelMonitorUpdate {
			update_id: self.latest_monitor_update_id,
			updates: vec![ChannelMonitorUpdateStep::LatestCounterpartyCommitmentTXInfo {
				commitment_txid: counterparty_commitment_txid,
				htlc_outputs: htlcs.clone(),
				commitment_number: self.cur_counterparty_commitment_transaction_number,
				their_per_commitment_point: self.counterparty_cur_commitment_point.unwrap()
			}]
		};
		self.channel_state |= ChannelState::AwaitingRemoteRevoke as u32;
		monitor_update
	}

	fn build_commitment_no_state_update<L: Deref>(&self, logger: &L) -> (Txid, Vec<(HTLCOutputInCommitment, Option<&HTLCSource>)>) where L::Target: Logger {
		let counterparty_keys = self.build_remote_transaction_keys();
		let commitment_stats = self.build_commitment_transaction(self.cur_counterparty_commitment_transaction_number, &counterparty_keys, false, true, logger);
		let counterparty_commitment_txid = commitment_stats.tx.trust().txid();

		#[cfg(any(test, fuzzing))]
		{
			if !self.is_outbound() {
				let projected_commit_tx_info = self.next_remote_commitment_tx_fee_info_cached.lock().unwrap().take();
				*self.next_local_commitment_tx_fee_info_cached.lock().unwrap() = None;
				if let Some(info) = projected_commit_tx_info {
					let total_pending_htlcs = self.pending_inbound_htlcs.len() + self.pending_outbound_htlcs.len();
					if info.total_pending_htlcs == total_pending_htlcs
						&& info.next_holder_htlc_id == self.next_holder_htlc_id
						&& info.next_counterparty_htlc_id == self.next_counterparty_htlc_id
						&& info.feerate == self.feerate_per_kw {
							let actual_fee = Self::commit_tx_fee_msat(self.feerate_per_kw, commitment_stats.num_nondust_htlcs, self.opt_anchors());
							assert_eq!(actual_fee, info.fee);
						}
				}
			}
		}

		(counterparty_commitment_txid, commitment_stats.htlcs_included)
	}

	/// Only fails in case of signer rejection. Used for channel_reestablish commitment_signed
	/// generation when we shouldn't change HTLC/channel state.
	fn send_commitment_no_state_update<L: Deref>(&self, logger: &L) -> Result<(msgs::CommitmentSigned, (Txid, Vec<(HTLCOutputInCommitment, Option<&HTLCSource>)>)), ChannelError> where L::Target: Logger {
		// Get the fee tests from `build_commitment_no_state_update`
		#[cfg(any(test, fuzzing))]
		self.build_commitment_no_state_update(logger);

		let counterparty_keys = self.build_remote_transaction_keys();
		let commitment_stats = self.build_commitment_transaction(self.cur_counterparty_commitment_transaction_number, &counterparty_keys, false, true, logger);
		let counterparty_commitment_txid = commitment_stats.tx.trust().txid();
		let (signature, htlc_signatures);

		{
			let mut htlcs = Vec::with_capacity(commitment_stats.htlcs_included.len());
			for &(ref htlc, _) in commitment_stats.htlcs_included.iter() {
				htlcs.push(htlc);
			}

			let res = self.holder_signer.sign_counterparty_commitment(&commitment_stats.tx, commitment_stats.preimages, &self.secp_ctx)
				.map_err(|_| ChannelError::Close("Failed to get signatures for new commitment_signed".to_owned()))?;
			signature = res.0;
			htlc_signatures = res.1;

			log_trace!(logger, "Signed remote commitment tx {} (txid {}) with redeemscript {} -> {} in channel {}",
				encode::serialize_hex(&commitment_stats.tx.trust().built_transaction().transaction),
				&counterparty_commitment_txid, encode::serialize_hex(&self.get_funding_redeemscript()),
				log_bytes!(signature.serialize_compact()[..]), log_bytes!(self.channel_id()));

			for (ref htlc_sig, ref htlc) in htlc_signatures.iter().zip(htlcs) {
				log_trace!(logger, "Signed remote HTLC tx {} with redeemscript {} with pubkey {} -> {} in channel {}",
					encode::serialize_hex(&chan_utils::build_htlc_transaction(&counterparty_commitment_txid, commitment_stats.feerate_per_kw, self.get_holder_selected_contest_delay(), htlc, self.opt_anchors(), false, &counterparty_keys.broadcaster_delayed_payment_key, &counterparty_keys.revocation_key)),
					encode::serialize_hex(&chan_utils::get_htlc_redeemscript(&htlc, self.opt_anchors(), &counterparty_keys)),
					log_bytes!(counterparty_keys.broadcaster_htlc_key.serialize()),
					log_bytes!(htlc_sig.serialize_compact()[..]), log_bytes!(self.channel_id()));
			}
		}

		Ok((msgs::CommitmentSigned {
			channel_id: self.channel_id,
			signature,
			htlc_signatures,
		}, (counterparty_commitment_txid, commitment_stats.htlcs_included)))
	}

	/// Adds a pending outbound HTLC to this channel, and builds a new remote commitment
	/// transaction and generates the corresponding [`ChannelMonitorUpdate`] in one go.
	///
	/// Shorthand for calling [`Self::send_htlc`] followed by a commitment update, see docs on
	/// [`Self::send_htlc`] and [`Self::build_commitment_no_state_update`] for more info.
	pub fn send_htlc_and_commit<L: Deref>(&mut self, amount_msat: u64, payment_hash: PaymentHash, cltv_expiry: u32, source: HTLCSource, onion_routing_packet: msgs::OnionPacket, logger: &L) -> Result<Option<&ChannelMonitorUpdate>, ChannelError> where L::Target: Logger {
		let send_res = self.send_htlc(amount_msat, payment_hash, cltv_expiry, source, onion_routing_packet, false, logger);
		if let Err(e) = &send_res { if let ChannelError::Ignore(_) = e {} else { debug_assert!(false, "Sending cannot trigger channel failure"); } }
		match send_res? {
			Some(_) => {
				let monitor_update = self.build_commitment_no_status_check(logger);
				self.monitor_updating_paused(false, true, false, Vec::new(), Vec::new(), Vec::new());
				self.pending_monitor_updates.push(monitor_update);
				Ok(Some(self.pending_monitor_updates.last().unwrap()))
			},
			None => Ok(None)
		}
	}

	/// Get forwarding information for the counterparty.
	pub fn counterparty_forwarding_info(&self) -> Option<CounterpartyForwardingInfo> {
		self.counterparty_forwarding_info.clone()
	}

	pub fn channel_update(&mut self, msg: &msgs::ChannelUpdate) -> Result<(), ChannelError> {
		if msg.contents.htlc_minimum_msat >= self.channel_value_satoshis * 1000 {
			return Err(ChannelError::Close("Minimum htlc value is greater than channel value".to_string()));
		}
		self.counterparty_forwarding_info = Some(CounterpartyForwardingInfo {
			fee_base_msat: msg.contents.fee_base_msat,
			fee_proportional_millionths: msg.contents.fee_proportional_millionths,
			cltv_expiry_delta: msg.contents.cltv_expiry_delta
		});

		Ok(())
	}

	/// Begins the shutdown process, getting a message for the remote peer and returning all
	/// holding cell HTLCs for payment failure.
	///
	/// May jump to the channel being fully shutdown (see [`Self::is_shutdown`]) in which case no
	/// [`ChannelMonitorUpdate`] will be returned).
	pub fn get_shutdown<SP: Deref>(&mut self, signer_provider: &SP, their_features: &InitFeatures,
		target_feerate_sats_per_kw: Option<u32>)
	-> Result<(msgs::Shutdown, Option<&ChannelMonitorUpdate>, Vec<(HTLCSource, PaymentHash)>), APIError>
	where SP::Target: SignerProvider {
		for htlc in self.pending_outbound_htlcs.iter() {
			if let OutboundHTLCState::LocalAnnounced(_) = htlc.state {
				return Err(APIError::APIMisuseError{err: "Cannot begin shutdown with pending HTLCs. Process pending events first".to_owned()});
			}
		}
		if self.channel_state & BOTH_SIDES_SHUTDOWN_MASK != 0 {
			if (self.channel_state & ChannelState::LocalShutdownSent as u32) == ChannelState::LocalShutdownSent as u32 {
				return Err(APIError::APIMisuseError{err: "Shutdown already in progress".to_owned()});
			}
			else if (self.channel_state & ChannelState::RemoteShutdownSent as u32) == ChannelState::RemoteShutdownSent as u32 {
				return Err(APIError::ChannelUnavailable{err: "Shutdown already in progress by remote".to_owned()});
			}
		}
		assert_eq!(self.channel_state & ChannelState::ShutdownComplete as u32, 0);
		if self.channel_state & (ChannelState::PeerDisconnected as u32 | ChannelState::MonitorUpdateInProgress as u32) != 0 {
			return Err(APIError::ChannelUnavailable{err: "Cannot begin shutdown while peer is disconnected or we're waiting on a monitor update, maybe force-close instead?".to_owned()});
		}

		// If we haven't funded the channel yet, we don't need to bother ensuring the shutdown
		// script is set, we just force-close and call it a day.
		let mut chan_closed = false;
		if self.channel_state < ChannelState::FundingSent as u32 {
			chan_closed = true;
		}

		let update_shutdown_script = match self.shutdown_scriptpubkey {
			Some(_) => false,
			None if !chan_closed => {
				let shutdown_scriptpubkey = signer_provider.get_shutdown_scriptpubkey();
				if !shutdown_scriptpubkey.is_compatible(their_features) {
					return Err(APIError::IncompatibleShutdownScript { script: shutdown_scriptpubkey.clone() });
				}
				self.shutdown_scriptpubkey = Some(shutdown_scriptpubkey);
				true
			},
			None => false,
		};

		// From here on out, we may not fail!
		self.target_closing_feerate_sats_per_kw = target_feerate_sats_per_kw;
		if self.channel_state < ChannelState::FundingSent as u32 {
			self.channel_state = ChannelState::ShutdownComplete as u32;
		} else {
			self.channel_state |= ChannelState::LocalShutdownSent as u32;
		}
		self.update_time_counter += 1;

		let monitor_update = if update_shutdown_script {
			self.latest_monitor_update_id += 1;
			let monitor_update = ChannelMonitorUpdate {
				update_id: self.latest_monitor_update_id,
				updates: vec![ChannelMonitorUpdateStep::ShutdownScript {
					scriptpubkey: self.get_closing_scriptpubkey(),
				}],
			};
			self.monitor_updating_paused(false, false, false, Vec::new(), Vec::new(), Vec::new());
			self.pending_monitor_updates.push(monitor_update);
			Some(self.pending_monitor_updates.last().unwrap())
		} else { None };
		let shutdown = msgs::Shutdown {
			channel_id: self.channel_id,
			scriptpubkey: self.get_closing_scriptpubkey(),
		};

		// Go ahead and drop holding cell updates as we'd rather fail payments than wait to send
		// our shutdown until we've committed all of the pending changes.
		self.holding_cell_update_fee = None;
		let mut dropped_outbound_htlcs = Vec::with_capacity(self.holding_cell_htlc_updates.len());
		self.holding_cell_htlc_updates.retain(|htlc_update| {
			match htlc_update {
				&HTLCUpdateAwaitingACK::AddHTLC { ref payment_hash, ref source, .. } => {
					dropped_outbound_htlcs.push((source.clone(), payment_hash.clone()));
					false
				},
				_ => true
			}
		});

		debug_assert!(!self.is_shutdown() || monitor_update.is_none(),
			"we can't both complete shutdown and return a monitor update");

		Ok((shutdown, monitor_update, dropped_outbound_htlcs))
	}

	/// Gets the latest commitment transaction and any dependent transactions for relay (forcing
	/// shutdown of this channel - no more calls into this Channel may be made afterwards except
	/// those explicitly stated to be allowed after shutdown completes, eg some simple getters).
	/// Also returns the list of payment_hashes for channels which we can safely fail backwards
	/// immediately (others we will have to allow to time out).
	pub fn force_shutdown(&mut self, should_broadcast: bool) -> (Option<(OutPoint, ChannelMonitorUpdate)>, Vec<(HTLCSource, PaymentHash, PublicKey, [u8; 32])>) {
		// Note that we MUST only generate a monitor update that indicates force-closure - we're
		// called during initialization prior to the chain_monitor in the encompassing ChannelManager
		// being fully configured in some cases. Thus, its likely any monitor events we generate will
		// be delayed in being processed! See the docs for `ChannelManagerReadArgs` for more.
		assert!(self.channel_state != ChannelState::ShutdownComplete as u32);

		// We go ahead and "free" any holding cell HTLCs or HTLCs we haven't yet committed to and
		// return them to fail the payment.
		let mut dropped_outbound_htlcs = Vec::with_capacity(self.holding_cell_htlc_updates.len());
		let counterparty_node_id = self.get_counterparty_node_id();
		for htlc_update in self.holding_cell_htlc_updates.drain(..) {
			match htlc_update {
				HTLCUpdateAwaitingACK::AddHTLC { source, payment_hash, .. } => {
					dropped_outbound_htlcs.push((source, payment_hash, counterparty_node_id, self.channel_id));
				},
				_ => {}
			}
		}
		let monitor_update = if let Some(funding_txo) = self.get_funding_txo() {
			// If we haven't yet exchanged funding signatures (ie channel_state < FundingSent),
			// returning a channel monitor update here would imply a channel monitor update before
			// we even registered the channel monitor to begin with, which is invalid.
			// Thus, if we aren't actually at a point where we could conceivably broadcast the
			// funding transaction, don't return a funding txo (which prevents providing the
			// monitor update to the user, even if we return one).
			// See test_duplicate_chan_id and test_pre_lockin_no_chan_closed_update for more.
			if self.channel_state & (ChannelState::FundingSent as u32 | ChannelState::ChannelReady as u32 | ChannelState::ShutdownComplete as u32) != 0 {
				self.latest_monitor_update_id += 1;
				Some((funding_txo, ChannelMonitorUpdate {
					update_id: self.latest_monitor_update_id,
					updates: vec![ChannelMonitorUpdateStep::ChannelForceClosed { should_broadcast }],
				}))
			} else { None }
		} else { None };

		self.channel_state = ChannelState::ShutdownComplete as u32;
		self.update_time_counter += 1;
		(monitor_update, dropped_outbound_htlcs)
	}

	pub fn inflight_htlc_sources(&self) -> impl Iterator<Item=(&HTLCSource, &PaymentHash)> {
		self.holding_cell_htlc_updates.iter()
			.flat_map(|htlc_update| {
				match htlc_update {
					HTLCUpdateAwaitingACK::AddHTLC { source, payment_hash, .. }
						=> Some((source, payment_hash)),
					_ => None,
				}
			})
			.chain(self.pending_outbound_htlcs.iter().map(|htlc| (&htlc.source, &htlc.payment_hash)))
	}
}

const SERIALIZATION_VERSION: u8 = 3;
const MIN_SERIALIZATION_VERSION: u8 = 2;

impl_writeable_tlv_based_enum!(InboundHTLCRemovalReason,;
	(0, FailRelay),
	(1, FailMalformed),
	(2, Fulfill),
);

impl Writeable for ChannelUpdateStatus {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		// We only care about writing out the current state as it was announced, ie only either
		// Enabled or Disabled. In the case of DisabledStaged, we most recently announced the
		// channel as enabled, so we write 0. For EnabledStaged, we similarly write a 1.
		match self {
			ChannelUpdateStatus::Enabled => 0u8.write(writer)?,
			ChannelUpdateStatus::DisabledStaged => 0u8.write(writer)?,
			ChannelUpdateStatus::EnabledStaged => 1u8.write(writer)?,
			ChannelUpdateStatus::Disabled => 1u8.write(writer)?,
		}
		Ok(())
	}
}

impl Readable for ChannelUpdateStatus {
	fn read<R: io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
		Ok(match <u8 as Readable>::read(reader)? {
			0 => ChannelUpdateStatus::Enabled,
			1 => ChannelUpdateStatus::Disabled,
			_ => return Err(DecodeError::InvalidValue),
		})
	}
}

impl Writeable for AnnouncementSigsState {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		// We only care about writing out the current state as if we had just disconnected, at
		// which point we always set anything but AnnouncementSigsReceived to NotSent.
		match self {
			AnnouncementSigsState::NotSent => 0u8.write(writer),
			AnnouncementSigsState::MessageSent => 0u8.write(writer),
			AnnouncementSigsState::Committed => 0u8.write(writer),
			AnnouncementSigsState::PeerReceived => 1u8.write(writer),
		}
	}
}

impl Readable for AnnouncementSigsState {
	fn read<R: io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
		Ok(match <u8 as Readable>::read(reader)? {
			0 => AnnouncementSigsState::NotSent,
			1 => AnnouncementSigsState::PeerReceived,
			_ => return Err(DecodeError::InvalidValue),
		})
	}
}

impl<Signer: WriteableEcdsaChannelSigner> Writeable for Channel<Signer> {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		// Note that we write out as if remove_uncommitted_htlcs_and_mark_paused had just been
		// called.

		write_ver_prefix!(writer, MIN_SERIALIZATION_VERSION, MIN_SERIALIZATION_VERSION);

		// `user_id` used to be a single u64 value. In order to remain backwards compatible with
		// versions prior to 0.0.113, the u128 is serialized as two separate u64 values. We write
		// the low bytes now and the optional high bytes later.
		let user_id_low = self.user_id as u64;
		user_id_low.write(writer)?;

		// Version 1 deserializers expected to read parts of the config object here. Version 2
		// deserializers (0.0.99) now read config through TLVs, and as we now require them for
		// `minimum_depth` we simply write dummy values here.
		writer.write_all(&[0; 8])?;

		self.channel_id.write(writer)?;
		(self.channel_state | ChannelState::PeerDisconnected as u32).write(writer)?;
		self.channel_value_satoshis.write(writer)?;

		self.latest_monitor_update_id.write(writer)?;

		let mut key_data = VecWriter(Vec::new());
		self.holder_signer.write(&mut key_data)?;
		assert!(key_data.0.len() < core::usize::MAX);
		assert!(key_data.0.len() < core::u32::MAX as usize);
		(key_data.0.len() as u32).write(writer)?;
		writer.write_all(&key_data.0[..])?;

		// Write out the old serialization for shutdown_pubkey for backwards compatibility, if
		// deserialized from that format.
		match self.shutdown_scriptpubkey.as_ref().and_then(|script| script.as_legacy_pubkey()) {
			Some(shutdown_pubkey) => shutdown_pubkey.write(writer)?,
			None => [0u8; PUBLIC_KEY_SIZE].write(writer)?,
		}
		self.destination_script.write(writer)?;

		self.cur_holder_commitment_transaction_number.write(writer)?;
		self.cur_counterparty_commitment_transaction_number.write(writer)?;
		self.value_to_self_msat.write(writer)?;

		let mut dropped_inbound_htlcs = 0;
		for htlc in self.pending_inbound_htlcs.iter() {
			if let InboundHTLCState::RemoteAnnounced(_) = htlc.state {
				dropped_inbound_htlcs += 1;
			}
		}
		(self.pending_inbound_htlcs.len() as u64 - dropped_inbound_htlcs).write(writer)?;
		for htlc in self.pending_inbound_htlcs.iter() {
			if let &InboundHTLCState::RemoteAnnounced(_) = &htlc.state {
				continue; // Drop
			}
			htlc.htlc_id.write(writer)?;
			htlc.amount_msat.write(writer)?;
			htlc.cltv_expiry.write(writer)?;
			htlc.payment_hash.write(writer)?;
			match &htlc.state {
				&InboundHTLCState::RemoteAnnounced(_) => unreachable!(),
				&InboundHTLCState::AwaitingRemoteRevokeToAnnounce(ref htlc_state) => {
					1u8.write(writer)?;
					htlc_state.write(writer)?;
				},
				&InboundHTLCState::AwaitingAnnouncedRemoteRevoke(ref htlc_state) => {
					2u8.write(writer)?;
					htlc_state.write(writer)?;
				},
				&InboundHTLCState::Committed => {
					3u8.write(writer)?;
				},
				&InboundHTLCState::LocalRemoved(ref removal_reason) => {
					4u8.write(writer)?;
					removal_reason.write(writer)?;
				},
			}
		}

		let mut preimages: Vec<&Option<PaymentPreimage>> = vec![];

		(self.pending_outbound_htlcs.len() as u64).write(writer)?;
		for htlc in self.pending_outbound_htlcs.iter() {
			htlc.htlc_id.write(writer)?;
			htlc.amount_msat.write(writer)?;
			htlc.cltv_expiry.write(writer)?;
			htlc.payment_hash.write(writer)?;
			htlc.source.write(writer)?;
			match &htlc.state {
				&OutboundHTLCState::LocalAnnounced(ref onion_packet) => {
					0u8.write(writer)?;
					onion_packet.write(writer)?;
				},
				&OutboundHTLCState::Committed => {
					1u8.write(writer)?;
				},
				&OutboundHTLCState::RemoteRemoved(_) => {
					// Treat this as a Committed because we haven't received the CS - they'll
					// resend the claim/fail on reconnect as we all (hopefully) the missing CS.
					1u8.write(writer)?;
				},
				&OutboundHTLCState::AwaitingRemoteRevokeToRemove(ref outcome) => {
					3u8.write(writer)?;
					if let OutboundHTLCOutcome::Success(preimage) = outcome {
						preimages.push(preimage);
					}
					let reason: Option<&HTLCFailReason> = outcome.into();
					reason.write(writer)?;
				}
				&OutboundHTLCState::AwaitingRemovedRemoteRevoke(ref outcome) => {
					4u8.write(writer)?;
					if let OutboundHTLCOutcome::Success(preimage) = outcome {
						preimages.push(preimage);
					}
					let reason: Option<&HTLCFailReason> = outcome.into();
					reason.write(writer)?;
				}
			}
		}

		(self.holding_cell_htlc_updates.len() as u64).write(writer)?;
		for update in self.holding_cell_htlc_updates.iter() {
			match update {
				&HTLCUpdateAwaitingACK::AddHTLC { ref amount_msat, ref cltv_expiry, ref payment_hash, ref source, ref onion_routing_packet } => {
					0u8.write(writer)?;
					amount_msat.write(writer)?;
					cltv_expiry.write(writer)?;
					payment_hash.write(writer)?;
					source.write(writer)?;
					onion_routing_packet.write(writer)?;
				},
				&HTLCUpdateAwaitingACK::ClaimHTLC { ref payment_preimage, ref htlc_id } => {
					1u8.write(writer)?;
					payment_preimage.write(writer)?;
					htlc_id.write(writer)?;
				},
				&HTLCUpdateAwaitingACK::FailHTLC { ref htlc_id, ref err_packet } => {
					2u8.write(writer)?;
					htlc_id.write(writer)?;
					err_packet.write(writer)?;
				}
			}
		}

		match self.resend_order {
			RAACommitmentOrder::CommitmentFirst => 0u8.write(writer)?,
			RAACommitmentOrder::RevokeAndACKFirst => 1u8.write(writer)?,
		}

		self.monitor_pending_channel_ready.write(writer)?;
		self.monitor_pending_revoke_and_ack.write(writer)?;
		self.monitor_pending_commitment_signed.write(writer)?;

		(self.monitor_pending_forwards.len() as u64).write(writer)?;
		for &(ref pending_forward, ref htlc_id) in self.monitor_pending_forwards.iter() {
			pending_forward.write(writer)?;
			htlc_id.write(writer)?;
		}

		(self.monitor_pending_failures.len() as u64).write(writer)?;
		for &(ref htlc_source, ref payment_hash, ref fail_reason) in self.monitor_pending_failures.iter() {
			htlc_source.write(writer)?;
			payment_hash.write(writer)?;
			fail_reason.write(writer)?;
		}

		if self.is_outbound() {
			self.pending_update_fee.map(|(a, _)| a).write(writer)?;
		} else if let Some((feerate, FeeUpdateState::AwaitingRemoteRevokeToAnnounce)) = self.pending_update_fee {
			Some(feerate).write(writer)?;
		} else {
			// As for inbound HTLCs, if the update was only announced and never committed in a
			// commitment_signed, drop it.
			None::<u32>.write(writer)?;
		}
		self.holding_cell_update_fee.write(writer)?;

		self.next_holder_htlc_id.write(writer)?;
		(self.next_counterparty_htlc_id - dropped_inbound_htlcs).write(writer)?;
		self.update_time_counter.write(writer)?;
		self.feerate_per_kw.write(writer)?;

		// Versions prior to 0.0.100 expected to read the fields of `last_sent_closing_fee` here,
		// however we are supposed to restart shutdown fee negotiation on reconnect (and wipe
		// `last_send_closing_fee` in `remove_uncommitted_htlcs_and_mark_paused`) so we should never
		// consider the stale state on reload.
		0u8.write(writer)?;

		self.funding_tx_confirmed_in.write(writer)?;
		self.funding_tx_confirmation_height.write(writer)?;
		self.short_channel_id.write(writer)?;

		self.counterparty_dust_limit_satoshis.write(writer)?;
		self.holder_dust_limit_satoshis.write(writer)?;
		self.counterparty_max_htlc_value_in_flight_msat.write(writer)?;

		// Note that this field is ignored by 0.0.99+ as the TLV Optional variant is used instead.
		self.counterparty_selected_channel_reserve_satoshis.unwrap_or(0).write(writer)?;

		self.counterparty_htlc_minimum_msat.write(writer)?;
		self.holder_htlc_minimum_msat.write(writer)?;
		self.counterparty_max_accepted_htlcs.write(writer)?;

		// Note that this field is ignored by 0.0.99+ as the TLV Optional variant is used instead.
		self.minimum_depth.unwrap_or(0).write(writer)?;

		match &self.counterparty_forwarding_info {
			Some(info) => {
				1u8.write(writer)?;
				info.fee_base_msat.write(writer)?;
				info.fee_proportional_millionths.write(writer)?;
				info.cltv_expiry_delta.write(writer)?;
			},
			None => 0u8.write(writer)?
		}

		self.channel_transaction_parameters.write(writer)?;
		self.funding_transaction.write(writer)?;

		self.counterparty_cur_commitment_point.write(writer)?;
		self.counterparty_prev_commitment_point.write(writer)?;
		self.counterparty_node_id.write(writer)?;

		self.counterparty_shutdown_scriptpubkey.write(writer)?;

		self.commitment_secrets.write(writer)?;

		self.channel_update_status.write(writer)?;

		#[cfg(any(test, fuzzing))]
		(self.historical_inbound_htlc_fulfills.len() as u64).write(writer)?;
		#[cfg(any(test, fuzzing))]
		for htlc in self.historical_inbound_htlc_fulfills.iter() {
			htlc.write(writer)?;
		}

		// If the channel type is something other than only-static-remote-key, then we need to have
		// older clients fail to deserialize this channel at all. If the type is
		// only-static-remote-key, we simply consider it "default" and don't write the channel type
		// out at all.
		let chan_type = if self.channel_type != ChannelTypeFeatures::only_static_remote_key() {
			Some(&self.channel_type) } else { None };

		// The same logic applies for `holder_selected_channel_reserve_satoshis` values other than
		// the default, and when `holder_max_htlc_value_in_flight_msat` is configured to be set to
		// a different percentage of the channel value then 10%, which older versions of LDK used
		// to set it to before the percentage was made configurable.
		let serialized_holder_selected_reserve =
			if self.holder_selected_channel_reserve_satoshis != Self::get_legacy_default_holder_selected_channel_reserve_satoshis(self.channel_value_satoshis)
			{ Some(self.holder_selected_channel_reserve_satoshis) } else { None };

		let mut old_max_in_flight_percent_config = UserConfig::default().channel_handshake_config;
		old_max_in_flight_percent_config.max_inbound_htlc_value_in_flight_percent_of_channel = MAX_IN_FLIGHT_PERCENT_LEGACY;
		let serialized_holder_htlc_max_in_flight =
			if self.holder_max_htlc_value_in_flight_msat != Self::get_holder_max_htlc_value_in_flight_msat(self.channel_value_satoshis, &old_max_in_flight_percent_config)
			{ Some(self.holder_max_htlc_value_in_flight_msat) } else { None };

		let channel_ready_event_emitted = Some(self.channel_ready_event_emitted);

		// `user_id` used to be a single u64 value. In order to remain backwards compatible with
		// versions prior to 0.0.113, the u128 is serialized as two separate u64 values. Therefore,
		// we write the high bytes as an option here.
		let user_id_high_opt = Some((self.user_id >> 64) as u64);

		write_tlv_fields!(writer, {
			(0, self.announcement_sigs, option),
			// minimum_depth and counterparty_selected_channel_reserve_satoshis used to have a
			// default value instead of being Option<>al. Thus, to maintain compatibility we write
			// them twice, once with their original default values above, and once as an option
			// here. On the read side, old versions will simply ignore the odd-type entries here,
			// and new versions map the default values to None and allow the TLV entries here to
			// override that.
			(1, self.minimum_depth, option),
			(2, chan_type, option),
			(3, self.counterparty_selected_channel_reserve_satoshis, option),
			(4, serialized_holder_selected_reserve, option),
			(5, self.config, required),
			(6, serialized_holder_htlc_max_in_flight, option),
			(7, self.shutdown_scriptpubkey, option),
			(9, self.target_closing_feerate_sats_per_kw, option),
			(11, self.monitor_pending_finalized_fulfills, vec_type),
			(13, self.channel_creation_height, required),
			(15, preimages, vec_type),
			(17, self.announcement_sigs_state, required),
			(19, self.latest_inbound_scid_alias, option),
			(21, self.outbound_scid_alias, required),
			(23, channel_ready_event_emitted, option),
			(25, user_id_high_opt, option),
			(27, self.channel_keys_id, required),
		});

		Ok(())
	}
}

const MAX_ALLOC_SIZE: usize = 64*1024;
impl<'a, 'b, 'c, ES: Deref, SP: Deref> ReadableArgs<(&'a ES, &'b SP, u32, &'c ChannelTypeFeatures)> for Channel<<SP::Target as SignerProvider>::Signer>
		where
			ES::Target: EntropySource,
			SP::Target: SignerProvider
{
	fn read<R : io::Read>(reader: &mut R, args: (&'a ES, &'b SP, u32, &'c ChannelTypeFeatures)) -> Result<Self, DecodeError> {
		let (entropy_source, signer_provider, serialized_height, our_supported_features) = args;
		let ver = read_ver_prefix!(reader, SERIALIZATION_VERSION);

		// `user_id` used to be a single u64 value. In order to remain backwards compatible with
		// versions prior to 0.0.113, the u128 is serialized as two separate u64 values. We read
		// the low bytes now and the high bytes later.
		let user_id_low: u64 = Readable::read(reader)?;

		let mut config = Some(LegacyChannelConfig::default());
		if ver == 1 {
			// Read the old serialization of the ChannelConfig from version 0.0.98.
			config.as_mut().unwrap().options.forwarding_fee_proportional_millionths = Readable::read(reader)?;
			config.as_mut().unwrap().options.cltv_expiry_delta = Readable::read(reader)?;
			config.as_mut().unwrap().announced_channel = Readable::read(reader)?;
			config.as_mut().unwrap().commit_upfront_shutdown_pubkey = Readable::read(reader)?;
		} else {
			// Read the 8 bytes of backwards-compatibility ChannelConfig data.
			let mut _val: u64 = Readable::read(reader)?;
		}

		let channel_id = Readable::read(reader)?;
		let channel_state = Readable::read(reader)?;
		let channel_value_satoshis = Readable::read(reader)?;

		let latest_monitor_update_id = Readable::read(reader)?;

		let mut keys_data = None;
		if ver <= 2 {
			// Read the serialize signer bytes. We'll choose to deserialize them or not based on whether
			// the `channel_keys_id` TLV is present below.
			let keys_len: u32 = Readable::read(reader)?;
			keys_data = Some(Vec::with_capacity(cmp::min(keys_len as usize, MAX_ALLOC_SIZE)));
			while keys_data.as_ref().unwrap().len() != keys_len as usize {
				// Read 1KB at a time to avoid accidentally allocating 4GB on corrupted channel keys
				let mut data = [0; 1024];
				let read_slice = &mut data[0..cmp::min(1024, keys_len as usize - keys_data.as_ref().unwrap().len())];
				reader.read_exact(read_slice)?;
				keys_data.as_mut().unwrap().extend_from_slice(read_slice);
			}
		}

		// Read the old serialization for shutdown_pubkey, preferring the TLV field later if set.
		let mut shutdown_scriptpubkey = match <PublicKey as Readable>::read(reader) {
			Ok(pubkey) => Some(ShutdownScript::new_p2wpkh_from_pubkey(pubkey)),
			Err(_) => None,
		};
		let destination_script = Readable::read(reader)?;

		let cur_holder_commitment_transaction_number = Readable::read(reader)?;
		let cur_counterparty_commitment_transaction_number = Readable::read(reader)?;
		let value_to_self_msat = Readable::read(reader)?;

		let pending_inbound_htlc_count: u64 = Readable::read(reader)?;
		let mut pending_inbound_htlcs = Vec::with_capacity(cmp::min(pending_inbound_htlc_count as usize, OUR_MAX_HTLCS as usize));
		for _ in 0..pending_inbound_htlc_count {
			pending_inbound_htlcs.push(InboundHTLCOutput {
				htlc_id: Readable::read(reader)?,
				amount_msat: Readable::read(reader)?,
				cltv_expiry: Readable::read(reader)?,
				payment_hash: Readable::read(reader)?,
				state: match <u8 as Readable>::read(reader)? {
					1 => InboundHTLCState::AwaitingRemoteRevokeToAnnounce(Readable::read(reader)?),
					2 => InboundHTLCState::AwaitingAnnouncedRemoteRevoke(Readable::read(reader)?),
					3 => InboundHTLCState::Committed,
					4 => InboundHTLCState::LocalRemoved(Readable::read(reader)?),
					_ => return Err(DecodeError::InvalidValue),
				},
			});
		}

		let pending_outbound_htlc_count: u64 = Readable::read(reader)?;
		let mut pending_outbound_htlcs = Vec::with_capacity(cmp::min(pending_outbound_htlc_count as usize, OUR_MAX_HTLCS as usize));
		for _ in 0..pending_outbound_htlc_count {
			pending_outbound_htlcs.push(OutboundHTLCOutput {
				htlc_id: Readable::read(reader)?,
				amount_msat: Readable::read(reader)?,
				cltv_expiry: Readable::read(reader)?,
				payment_hash: Readable::read(reader)?,
				source: Readable::read(reader)?,
				state: match <u8 as Readable>::read(reader)? {
					0 => OutboundHTLCState::LocalAnnounced(Box::new(Readable::read(reader)?)),
					1 => OutboundHTLCState::Committed,
					2 => {
						let option: Option<HTLCFailReason> = Readable::read(reader)?;
						OutboundHTLCState::RemoteRemoved(option.into())
					},
					3 => {
						let option: Option<HTLCFailReason> = Readable::read(reader)?;
						OutboundHTLCState::AwaitingRemoteRevokeToRemove(option.into())
					},
					4 => {
						let option: Option<HTLCFailReason> = Readable::read(reader)?;
						OutboundHTLCState::AwaitingRemovedRemoteRevoke(option.into())
					},
					_ => return Err(DecodeError::InvalidValue),
				},
			});
		}

		let holding_cell_htlc_update_count: u64 = Readable::read(reader)?;
		let mut holding_cell_htlc_updates = Vec::with_capacity(cmp::min(holding_cell_htlc_update_count as usize, OUR_MAX_HTLCS as usize*2));
		for _ in 0..holding_cell_htlc_update_count {
			holding_cell_htlc_updates.push(match <u8 as Readable>::read(reader)? {
				0 => HTLCUpdateAwaitingACK::AddHTLC {
					amount_msat: Readable::read(reader)?,
					cltv_expiry: Readable::read(reader)?,
					payment_hash: Readable::read(reader)?,
					source: Readable::read(reader)?,
					onion_routing_packet: Readable::read(reader)?,
				},
				1 => HTLCUpdateAwaitingACK::ClaimHTLC {
					payment_preimage: Readable::read(reader)?,
					htlc_id: Readable::read(reader)?,
				},
				2 => HTLCUpdateAwaitingACK::FailHTLC {
					htlc_id: Readable::read(reader)?,
					err_packet: Readable::read(reader)?,
				},
				_ => return Err(DecodeError::InvalidValue),
			});
		}

		let resend_order = match <u8 as Readable>::read(reader)? {
			0 => RAACommitmentOrder::CommitmentFirst,
			1 => RAACommitmentOrder::RevokeAndACKFirst,
			_ => return Err(DecodeError::InvalidValue),
		};

		let monitor_pending_channel_ready = Readable::read(reader)?;
		let monitor_pending_revoke_and_ack = Readable::read(reader)?;
		let monitor_pending_commitment_signed = Readable::read(reader)?;

		let monitor_pending_forwards_count: u64 = Readable::read(reader)?;
		let mut monitor_pending_forwards = Vec::with_capacity(cmp::min(monitor_pending_forwards_count as usize, OUR_MAX_HTLCS as usize));
		for _ in 0..monitor_pending_forwards_count {
			monitor_pending_forwards.push((Readable::read(reader)?, Readable::read(reader)?));
		}

		let monitor_pending_failures_count: u64 = Readable::read(reader)?;
		let mut monitor_pending_failures = Vec::with_capacity(cmp::min(monitor_pending_failures_count as usize, OUR_MAX_HTLCS as usize));
		for _ in 0..monitor_pending_failures_count {
			monitor_pending_failures.push((Readable::read(reader)?, Readable::read(reader)?, Readable::read(reader)?));
		}

		let pending_update_fee_value: Option<u32> = Readable::read(reader)?;

		let holding_cell_update_fee = Readable::read(reader)?;

		let next_holder_htlc_id = Readable::read(reader)?;
		let next_counterparty_htlc_id = Readable::read(reader)?;
		let update_time_counter = Readable::read(reader)?;
		let feerate_per_kw = Readable::read(reader)?;

		// Versions prior to 0.0.100 expected to read the fields of `last_sent_closing_fee` here,
		// however we are supposed to restart shutdown fee negotiation on reconnect (and wipe
		// `last_send_closing_fee` in `remove_uncommitted_htlcs_and_mark_paused`) so we should never
		// consider the stale state on reload.
		match <u8 as Readable>::read(reader)? {
			0 => {},
			1 => {
				let _: u32 = Readable::read(reader)?;
				let _: u64 = Readable::read(reader)?;
				let _: Signature = Readable::read(reader)?;
			},
			_ => return Err(DecodeError::InvalidValue),
		}

		let funding_tx_confirmed_in = Readable::read(reader)?;
		let funding_tx_confirmation_height = Readable::read(reader)?;
		let short_channel_id = Readable::read(reader)?;

		let counterparty_dust_limit_satoshis = Readable::read(reader)?;
		let holder_dust_limit_satoshis = Readable::read(reader)?;
		let counterparty_max_htlc_value_in_flight_msat = Readable::read(reader)?;
		let mut counterparty_selected_channel_reserve_satoshis = None;
		if ver == 1 {
			// Read the old serialization from version 0.0.98.
			counterparty_selected_channel_reserve_satoshis = Some(Readable::read(reader)?);
		} else {
			// Read the 8 bytes of backwards-compatibility data.
			let _dummy: u64 = Readable::read(reader)?;
		}
		let counterparty_htlc_minimum_msat = Readable::read(reader)?;
		let holder_htlc_minimum_msat = Readable::read(reader)?;
		let counterparty_max_accepted_htlcs = Readable::read(reader)?;

		let mut minimum_depth = None;
		if ver == 1 {
			// Read the old serialization from version 0.0.98.
			minimum_depth = Some(Readable::read(reader)?);
		} else {
			// Read the 4 bytes of backwards-compatibility data.
			let _dummy: u32 = Readable::read(reader)?;
		}

		let counterparty_forwarding_info = match <u8 as Readable>::read(reader)? {
			0 => None,
			1 => Some(CounterpartyForwardingInfo {
				fee_base_msat: Readable::read(reader)?,
				fee_proportional_millionths: Readable::read(reader)?,
				cltv_expiry_delta: Readable::read(reader)?,
			}),
			_ => return Err(DecodeError::InvalidValue),
		};

		let channel_parameters: ChannelTransactionParameters = Readable::read(reader)?;
		let funding_transaction = Readable::read(reader)?;

		let counterparty_cur_commitment_point = Readable::read(reader)?;

		let counterparty_prev_commitment_point = Readable::read(reader)?;
		let counterparty_node_id = Readable::read(reader)?;

		let counterparty_shutdown_scriptpubkey = Readable::read(reader)?;
		let commitment_secrets = Readable::read(reader)?;

		let channel_update_status = Readable::read(reader)?;

		#[cfg(any(test, fuzzing))]
		let mut historical_inbound_htlc_fulfills = HashSet::new();
		#[cfg(any(test, fuzzing))]
		{
			let htlc_fulfills_len: u64 = Readable::read(reader)?;
			for _ in 0..htlc_fulfills_len {
				assert!(historical_inbound_htlc_fulfills.insert(Readable::read(reader)?));
			}
		}

		let pending_update_fee = if let Some(feerate) = pending_update_fee_value {
			Some((feerate, if channel_parameters.is_outbound_from_holder {
				FeeUpdateState::Outbound
			} else {
				FeeUpdateState::AwaitingRemoteRevokeToAnnounce
			}))
		} else {
			None
		};

		let mut announcement_sigs = None;
		let mut target_closing_feerate_sats_per_kw = None;
		let mut monitor_pending_finalized_fulfills = Some(Vec::new());
		let mut holder_selected_channel_reserve_satoshis = Some(Self::get_legacy_default_holder_selected_channel_reserve_satoshis(channel_value_satoshis));
		let mut holder_max_htlc_value_in_flight_msat = Some(Self::get_holder_max_htlc_value_in_flight_msat(channel_value_satoshis, &UserConfig::default().channel_handshake_config));
		// Prior to supporting channel type negotiation, all of our channels were static_remotekey
		// only, so we default to that if none was written.
		let mut channel_type = Some(ChannelTypeFeatures::only_static_remote_key());
		let mut channel_creation_height = Some(serialized_height);
		let mut preimages_opt: Option<Vec<Option<PaymentPreimage>>> = None;

		// If we read an old Channel, for simplicity we just treat it as "we never sent an
		// AnnouncementSignatures" which implies we'll re-send it on reconnect, but that's fine.
		let mut announcement_sigs_state = Some(AnnouncementSigsState::NotSent);
		let mut latest_inbound_scid_alias = None;
		let mut outbound_scid_alias = None;
		let mut channel_ready_event_emitted = None;

		let mut user_id_high_opt: Option<u64> = None;
		let mut channel_keys_id: Option<[u8; 32]> = None;

		read_tlv_fields!(reader, {
			(0, announcement_sigs, option),
			(1, minimum_depth, option),
			(2, channel_type, option),
			(3, counterparty_selected_channel_reserve_satoshis, option),
			(4, holder_selected_channel_reserve_satoshis, option),
			(5, config, option), // Note that if none is provided we will *not* overwrite the existing one.
			(6, holder_max_htlc_value_in_flight_msat, option),
			(7, shutdown_scriptpubkey, option),
			(9, target_closing_feerate_sats_per_kw, option),
			(11, monitor_pending_finalized_fulfills, vec_type),
			(13, channel_creation_height, option),
			(15, preimages_opt, vec_type),
			(17, announcement_sigs_state, option),
			(19, latest_inbound_scid_alias, option),
			(21, outbound_scid_alias, option),
			(23, channel_ready_event_emitted, option),
			(25, user_id_high_opt, option),
			(27, channel_keys_id, option),
		});

		let (channel_keys_id, holder_signer) = if let Some(channel_keys_id) = channel_keys_id {
			let mut holder_signer = signer_provider.derive_channel_signer(channel_value_satoshis, channel_keys_id);
			// If we've gotten to the funding stage of the channel, populate the signer with its
			// required channel parameters.
			let non_shutdown_state = channel_state & (!MULTI_STATE_FLAGS);
			if non_shutdown_state >= (ChannelState::FundingCreated as u32) {
				holder_signer.provide_channel_parameters(&channel_parameters);
			}
			(channel_keys_id, holder_signer)
		} else {
			// `keys_data` can be `None` if we had corrupted data.
			let keys_data = keys_data.ok_or(DecodeError::InvalidValue)?;
			let holder_signer = signer_provider.read_chan_signer(&keys_data)?;
			(holder_signer.channel_keys_id(), holder_signer)
		};

		if let Some(preimages) = preimages_opt {
			let mut iter = preimages.into_iter();
			for htlc in pending_outbound_htlcs.iter_mut() {
				match &htlc.state {
					OutboundHTLCState::AwaitingRemoteRevokeToRemove(OutboundHTLCOutcome::Success(None)) => {
						htlc.state = OutboundHTLCState::AwaitingRemoteRevokeToRemove(OutboundHTLCOutcome::Success(iter.next().ok_or(DecodeError::InvalidValue)?));
					}
					OutboundHTLCState::AwaitingRemovedRemoteRevoke(OutboundHTLCOutcome::Success(None)) => {
						htlc.state = OutboundHTLCState::AwaitingRemovedRemoteRevoke(OutboundHTLCOutcome::Success(iter.next().ok_or(DecodeError::InvalidValue)?));
					}
					_ => {}
				}
			}
			// We expect all preimages to be consumed above
			if iter.next().is_some() {
				return Err(DecodeError::InvalidValue);
			}
		}

		let chan_features = channel_type.as_ref().unwrap();
		if !chan_features.is_subset(our_supported_features) {
			// If the channel was written by a new version and negotiated with features we don't
			// understand yet, refuse to read it.
			return Err(DecodeError::UnknownRequiredFeature);
		}

		let mut secp_ctx = Secp256k1::new();
		secp_ctx.seeded_randomize(&entropy_source.get_secure_random_bytes());

		// `user_id` used to be a single u64 value. In order to remain backwards
		// compatible with versions prior to 0.0.113, the u128 is serialized as two
		// separate u64 values.
		let user_id = user_id_low as u128 + ((user_id_high_opt.unwrap_or(0) as u128) << 64);

		Ok(Channel {
			user_id,

			config: config.unwrap(),

			prev_config: None,

			// Note that we don't care about serializing handshake limits as we only ever serialize
			// channel data after the handshake has completed.
			inbound_handshake_limits_override: None,

			channel_id,
			channel_state,
			announcement_sigs_state: announcement_sigs_state.unwrap(),
			secp_ctx,
			channel_value_satoshis,

			latest_monitor_update_id,

			holder_signer,
			shutdown_scriptpubkey,
			destination_script,

			cur_holder_commitment_transaction_number,
			cur_counterparty_commitment_transaction_number,
			value_to_self_msat,

			pending_inbound_htlcs,
			pending_outbound_htlcs,
			holding_cell_htlc_updates,

			resend_order,

			monitor_pending_channel_ready,
			monitor_pending_revoke_and_ack,
			monitor_pending_commitment_signed,
			monitor_pending_forwards,
			monitor_pending_failures,
			monitor_pending_finalized_fulfills: monitor_pending_finalized_fulfills.unwrap(),

			pending_update_fee,
			holding_cell_update_fee,
			next_holder_htlc_id,
			next_counterparty_htlc_id,
			update_time_counter,
			feerate_per_kw,

			#[cfg(debug_assertions)]
			holder_max_commitment_tx_output: Mutex::new((0, 0)),
			#[cfg(debug_assertions)]
			counterparty_max_commitment_tx_output: Mutex::new((0, 0)),

			last_sent_closing_fee: None,
			pending_counterparty_closing_signed: None,
			closing_fee_limits: None,
			target_closing_feerate_sats_per_kw,

			inbound_awaiting_accept: false,

			funding_tx_confirmed_in,
			funding_tx_confirmation_height,
			short_channel_id,
			channel_creation_height: channel_creation_height.unwrap(),

			counterparty_dust_limit_satoshis,
			holder_dust_limit_satoshis,
			counterparty_max_htlc_value_in_flight_msat,
			holder_max_htlc_value_in_flight_msat: holder_max_htlc_value_in_flight_msat.unwrap(),
			counterparty_selected_channel_reserve_satoshis,
			holder_selected_channel_reserve_satoshis: holder_selected_channel_reserve_satoshis.unwrap(),
			counterparty_htlc_minimum_msat,
			holder_htlc_minimum_msat,
			counterparty_max_accepted_htlcs,
			minimum_depth,

			counterparty_forwarding_info,

			channel_transaction_parameters: channel_parameters,
			funding_transaction,

			counterparty_cur_commitment_point,
			counterparty_prev_commitment_point,
			counterparty_node_id,

			counterparty_shutdown_scriptpubkey,

			commitment_secrets,

			channel_update_status,
			closing_signed_in_flight: false,

			announcement_sigs,

			#[cfg(any(test, fuzzing))]
			next_local_commitment_tx_fee_info_cached: Mutex::new(None),
			#[cfg(any(test, fuzzing))]
			next_remote_commitment_tx_fee_info_cached: Mutex::new(None),

			workaround_lnd_bug_4006: None,

			latest_inbound_scid_alias,
			// Later in the ChannelManager deserialization phase we scan for channels and assign scid aliases if its missing
			outbound_scid_alias: outbound_scid_alias.unwrap_or(0),

			channel_ready_event_emitted: channel_ready_event_emitted.unwrap_or(true),

			#[cfg(any(test, fuzzing))]
			historical_inbound_htlc_fulfills,

			channel_type: channel_type.unwrap(),
			channel_keys_id,

			pending_monitor_updates: Vec::new(),
		})
	}
}

#[cfg(test)]
mod tests {
	use std::cmp;
	use bitcoin::blockdata::script::{Script, Builder};
	use bitcoin::blockdata::transaction::{Transaction, TxOut};
	use bitcoin::blockdata::constants::genesis_block;
	use bitcoin::blockdata::opcodes;
	use bitcoin::network::constants::Network;
	use hex;
	use crate::ln::PaymentHash;
	use crate::ln::channelmanager::{self, HTLCSource, PaymentId};
	#[cfg(anchors)]
	use crate::ln::channel::InitFeatures;
	use crate::ln::channel::{Channel, InboundHTLCOutput, OutboundHTLCOutput, InboundHTLCState, OutboundHTLCState, HTLCCandidate, HTLCInitiator};
	use crate::ln::channel::{MAX_FUNDING_SATOSHIS_NO_WUMBO, TOTAL_BITCOIN_SUPPLY_SATOSHIS, MIN_THEIR_CHAN_RESERVE_SATOSHIS};
	use crate::ln::features::ChannelTypeFeatures;
	use crate::ln::msgs::{ChannelUpdate, DataLossProtect, DecodeError, OptionalField, UnsignedChannelUpdate, MAX_VALUE_MSAT};
	use crate::ln::script::ShutdownScript;
	use crate::ln::chan_utils;
	use crate::ln::chan_utils::{htlc_success_tx_weight, htlc_timeout_tx_weight};
	use crate::chain::BestBlock;
	use crate::chain::chaininterface::{FeeEstimator, LowerBoundedFeeEstimator, ConfirmationTarget};
	use crate::chain::keysinterface::{ChannelSigner, InMemorySigner, EntropySource, SignerProvider};
	use crate::chain::transaction::OutPoint;
	use crate::util::config::UserConfig;
	use crate::util::enforcing_trait_impls::EnforcingSigner;
	use crate::util::errors::APIError;
	use crate::util::test_utils;
	use crate::util::test_utils::OnGetShutdownScriptpubkey;
	use bitcoin::secp256k1::{Secp256k1, ecdsa::Signature};
	use bitcoin::secp256k1::ffi::Signature as FFISignature;
	use bitcoin::secp256k1::{SecretKey,PublicKey};
	use bitcoin::hashes::sha256::Hash as Sha256;
	use bitcoin::hashes::Hash;
	use bitcoin::hash_types::WPubkeyHash;
	use bitcoin::PackedLockTime;
	use bitcoin::util::address::WitnessVersion;
	use crate::prelude::*;

	struct TestFeeEstimator {
		fee_est: u32
	}
	impl FeeEstimator for TestFeeEstimator {
		fn get_est_sat_per_1000_weight(&self, _: ConfirmationTarget) -> u32 {
			self.fee_est
		}
	}

	#[test]
	fn test_max_funding_satoshis_no_wumbo() {
		assert_eq!(TOTAL_BITCOIN_SUPPLY_SATOSHIS, 21_000_000 * 100_000_000);
		assert!(MAX_FUNDING_SATOSHIS_NO_WUMBO <= TOTAL_BITCOIN_SUPPLY_SATOSHIS,
		        "MAX_FUNDING_SATOSHIS_NO_WUMBO is greater than all satoshis in existence");
	}

	#[test]
	fn test_no_fee_check_overflow() {
		// Previously, calling `check_remote_fee` with a fee of 0xffffffff would overflow in
		// arithmetic, causing a panic with debug assertions enabled.
		let fee_est = TestFeeEstimator { fee_est: 42 };
		let bounded_fee_estimator = LowerBoundedFeeEstimator::new(&fee_est);
		assert!(Channel::<InMemorySigner>::check_remote_fee(&bounded_fee_estimator,
			u32::max_value(), None, &&test_utils::TestLogger::new()).is_err());
	}

	struct Keys {
		signer: InMemorySigner,
	}

	impl EntropySource for Keys {
		fn get_secure_random_bytes(&self) -> [u8; 32] { [0; 32] }
	}

	impl SignerProvider for Keys {
		type Signer = InMemorySigner;

		fn generate_channel_keys_id(&self, _inbound: bool, _channel_value_satoshis: u64, _user_channel_id: u128) -> [u8; 32] {
			self.signer.channel_keys_id()
		}

		fn derive_channel_signer(&self, _channel_value_satoshis: u64, _channel_keys_id: [u8; 32]) -> Self::Signer {
			self.signer.clone()
		}

		fn read_chan_signer(&self, _data: &[u8]) -> Result<Self::Signer, DecodeError> { panic!(); }

		fn get_destination_script(&self) -> Script {
			let secp_ctx = Secp256k1::signing_only();
			let channel_monitor_claim_key = SecretKey::from_slice(&hex::decode("0fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").unwrap()[..]).unwrap();
			let channel_monitor_claim_key_hash = WPubkeyHash::hash(&PublicKey::from_secret_key(&secp_ctx, &channel_monitor_claim_key).serialize());
			Builder::new().push_opcode(opcodes::all::OP_PUSHBYTES_0).push_slice(&channel_monitor_claim_key_hash[..]).into_script()
		}

		fn get_shutdown_scriptpubkey(&self) -> ShutdownScript {
			let secp_ctx = Secp256k1::signing_only();
			let channel_close_key = SecretKey::from_slice(&hex::decode("0fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").unwrap()[..]).unwrap();
			ShutdownScript::new_p2wpkh_from_pubkey(PublicKey::from_secret_key(&secp_ctx, &channel_close_key))
		}
	}

	#[cfg(not(feature = "grind_signatures"))]
	fn public_from_secret_hex(secp_ctx: &Secp256k1<bitcoin::secp256k1::All>, hex: &str) -> PublicKey {
		PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&hex::decode(hex).unwrap()[..]).unwrap())
	}

	#[test]
	fn upfront_shutdown_script_incompatibility() {
		let features = channelmanager::provided_init_features(&UserConfig::default()).clear_shutdown_anysegwit();
		let non_v0_segwit_shutdown_script =
			ShutdownScript::new_witness_program(WitnessVersion::V16, &[0, 40]).unwrap();

		let seed = [42; 32];
		let network = Network::Testnet;
		let keys_provider = test_utils::TestKeysInterface::new(&seed, network);
		keys_provider.expect(OnGetShutdownScriptpubkey {
			returns: non_v0_segwit_shutdown_script.clone(),
		});

		let secp_ctx = Secp256k1::new();
		let node_id = PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[42; 32]).unwrap());
		let config = UserConfig::default();
		match Channel::<EnforcingSigner>::new_outbound(&LowerBoundedFeeEstimator::new(&TestFeeEstimator { fee_est: 253 }), &&keys_provider, &&keys_provider, node_id, &features, 10000000, 100000, 42, &config, 0, 42) {
			Err(APIError::IncompatibleShutdownScript { script }) => {
				assert_eq!(script.into_inner(), non_v0_segwit_shutdown_script.into_inner());
			},
			Err(e) => panic!("Unexpected error: {:?}", e),
			Ok(_) => panic!("Expected error"),
		}
	}

	// Check that, during channel creation, we use the same feerate in the open channel message
	// as we do in the Channel object creation itself.
	#[test]
	fn test_open_channel_msg_fee() {
		let original_fee = 253;
		let mut fee_est = TestFeeEstimator{fee_est: original_fee };
		let bounded_fee_estimator = LowerBoundedFeeEstimator::new(&fee_est);
		let secp_ctx = Secp256k1::new();
		let seed = [42; 32];
		let network = Network::Testnet;
		let keys_provider = test_utils::TestKeysInterface::new(&seed, network);

		let node_a_node_id = PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[42; 32]).unwrap());
		let config = UserConfig::default();
		let node_a_chan = Channel::<EnforcingSigner>::new_outbound(&bounded_fee_estimator, &&keys_provider, &&keys_provider, node_a_node_id, &channelmanager::provided_init_features(&config), 10000000, 100000, 42, &config, 0, 42).unwrap();

		// Now change the fee so we can check that the fee in the open_channel message is the
		// same as the old fee.
		fee_est.fee_est = 500;
		let open_channel_msg = node_a_chan.get_open_channel(genesis_block(network).header.block_hash());
		assert_eq!(open_channel_msg.feerate_per_kw, original_fee);
	}

	#[test]
	fn test_holder_vs_counterparty_dust_limit() {
		// Test that when calculating the local and remote commitment transaction fees, the correct
		// dust limits are used.
		let feeest = LowerBoundedFeeEstimator::new(&TestFeeEstimator{fee_est: 15000});
		let secp_ctx = Secp256k1::new();
		let seed = [42; 32];
		let network = Network::Testnet;
		let keys_provider = test_utils::TestKeysInterface::new(&seed, network);
		let logger = test_utils::TestLogger::new();

		// Go through the flow of opening a channel between two nodes, making sure
		// they have different dust limits.

		// Create Node A's channel pointing to Node B's pubkey
		let node_b_node_id = PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[42; 32]).unwrap());
		let config = UserConfig::default();
		let mut node_a_chan = Channel::<EnforcingSigner>::new_outbound(&feeest, &&keys_provider, &&keys_provider, node_b_node_id, &channelmanager::provided_init_features(&config), 10000000, 100000, 42, &config, 0, 42).unwrap();

		// Create Node B's channel by receiving Node A's open_channel message
		// Make sure A's dust limit is as we expect.
		let open_channel_msg = node_a_chan.get_open_channel(genesis_block(network).header.block_hash());
		let node_b_node_id = PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[7; 32]).unwrap());
		let mut node_b_chan = Channel::<EnforcingSigner>::new_from_req(&feeest, &&keys_provider, &&keys_provider, node_b_node_id, &channelmanager::provided_channel_type_features(&config), &channelmanager::provided_init_features(&config), &open_channel_msg, 7, &config, 0, &&logger, 42).unwrap();

		// Node B --> Node A: accept channel, explicitly setting B's dust limit.
		let mut accept_channel_msg = node_b_chan.accept_inbound_channel(0);
		accept_channel_msg.dust_limit_satoshis = 546;
		node_a_chan.accept_channel(&accept_channel_msg, &config.channel_handshake_limits, &channelmanager::provided_init_features(&config)).unwrap();
		node_a_chan.holder_dust_limit_satoshis = 1560;

		// Put some inbound and outbound HTLCs in A's channel.
		let htlc_amount_msat = 11_092_000; // put an amount below A's effective dust limit but above B's.
		node_a_chan.pending_inbound_htlcs.push(InboundHTLCOutput {
			htlc_id: 0,
			amount_msat: htlc_amount_msat,
			payment_hash: PaymentHash(Sha256::hash(&[42; 32]).into_inner()),
			cltv_expiry: 300000000,
			state: InboundHTLCState::Committed,
		});

		node_a_chan.pending_outbound_htlcs.push(OutboundHTLCOutput {
			htlc_id: 1,
			amount_msat: htlc_amount_msat, // put an amount below A's dust amount but above B's.
			payment_hash: PaymentHash(Sha256::hash(&[43; 32]).into_inner()),
			cltv_expiry: 200000000,
			state: OutboundHTLCState::Committed,
			source: HTLCSource::OutboundRoute {
				path: Vec::new(),
				session_priv: SecretKey::from_slice(&hex::decode("0fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").unwrap()[..]).unwrap(),
				first_hop_htlc_msat: 548,
				payment_id: PaymentId([42; 32]),
				payment_secret: None,
				payment_params: None,
			}
		});

		// Make sure when Node A calculates their local commitment transaction, none of the HTLCs pass
		// the dust limit check.
		let htlc_candidate = HTLCCandidate::new(htlc_amount_msat, HTLCInitiator::LocalOffered);
		let local_commit_tx_fee = node_a_chan.next_local_commit_tx_fee_msat(htlc_candidate, None);
		let local_commit_fee_0_htlcs = Channel::<EnforcingSigner>::commit_tx_fee_msat(node_a_chan.feerate_per_kw, 0, node_a_chan.opt_anchors());
		assert_eq!(local_commit_tx_fee, local_commit_fee_0_htlcs);

		// Finally, make sure that when Node A calculates the remote's commitment transaction fees, all
		// of the HTLCs are seen to be above the dust limit.
		node_a_chan.channel_transaction_parameters.is_outbound_from_holder = false;
		let remote_commit_fee_3_htlcs = Channel::<EnforcingSigner>::commit_tx_fee_msat(node_a_chan.feerate_per_kw, 3, node_a_chan.opt_anchors());
		let htlc_candidate = HTLCCandidate::new(htlc_amount_msat, HTLCInitiator::LocalOffered);
		let remote_commit_tx_fee = node_a_chan.next_remote_commit_tx_fee_msat(htlc_candidate, None);
		assert_eq!(remote_commit_tx_fee, remote_commit_fee_3_htlcs);
	}

	#[test]
	fn test_timeout_vs_success_htlc_dust_limit() {
		// Make sure that when `next_remote_commit_tx_fee_msat` and `next_local_commit_tx_fee_msat`
		// calculate the real dust limits for HTLCs (i.e. the dust limit given by the counterparty
		// *plus* the fees paid for the HTLC) they don't swap `HTLC_SUCCESS_TX_WEIGHT` for
		// `HTLC_TIMEOUT_TX_WEIGHT`, and vice versa.
		let fee_est = LowerBoundedFeeEstimator::new(&TestFeeEstimator{fee_est: 253 });
		let secp_ctx = Secp256k1::new();
		let seed = [42; 32];
		let network = Network::Testnet;
		let keys_provider = test_utils::TestKeysInterface::new(&seed, network);

		let node_id = PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[42; 32]).unwrap());
		let config = UserConfig::default();
		let mut chan = Channel::<EnforcingSigner>::new_outbound(&fee_est, &&keys_provider, &&keys_provider, node_id, &channelmanager::provided_init_features(&config), 10000000, 100000, 42, &config, 0, 42).unwrap();

		let commitment_tx_fee_0_htlcs = Channel::<EnforcingSigner>::commit_tx_fee_msat(chan.feerate_per_kw, 0, chan.opt_anchors());
		let commitment_tx_fee_1_htlc = Channel::<EnforcingSigner>::commit_tx_fee_msat(chan.feerate_per_kw, 1, chan.opt_anchors());

		// If HTLC_SUCCESS_TX_WEIGHT and HTLC_TIMEOUT_TX_WEIGHT were swapped: then this HTLC would be
		// counted as dust when it shouldn't be.
		let htlc_amt_above_timeout = ((253 * htlc_timeout_tx_weight(chan.opt_anchors()) / 1000) + chan.holder_dust_limit_satoshis + 1) * 1000;
		let htlc_candidate = HTLCCandidate::new(htlc_amt_above_timeout, HTLCInitiator::LocalOffered);
		let commitment_tx_fee = chan.next_local_commit_tx_fee_msat(htlc_candidate, None);
		assert_eq!(commitment_tx_fee, commitment_tx_fee_1_htlc);

		// If swapped: this HTLC would be counted as non-dust when it shouldn't be.
		let dust_htlc_amt_below_success = ((253 * htlc_success_tx_weight(chan.opt_anchors()) / 1000) + chan.holder_dust_limit_satoshis - 1) * 1000;
		let htlc_candidate = HTLCCandidate::new(dust_htlc_amt_below_success, HTLCInitiator::RemoteOffered);
		let commitment_tx_fee = chan.next_local_commit_tx_fee_msat(htlc_candidate, None);
		assert_eq!(commitment_tx_fee, commitment_tx_fee_0_htlcs);

		chan.channel_transaction_parameters.is_outbound_from_holder = false;

		// If swapped: this HTLC would be counted as non-dust when it shouldn't be.
		let dust_htlc_amt_above_timeout = ((253 * htlc_timeout_tx_weight(chan.opt_anchors()) / 1000) + chan.counterparty_dust_limit_satoshis + 1) * 1000;
		let htlc_candidate = HTLCCandidate::new(dust_htlc_amt_above_timeout, HTLCInitiator::LocalOffered);
		let commitment_tx_fee = chan.next_remote_commit_tx_fee_msat(htlc_candidate, None);
		assert_eq!(commitment_tx_fee, commitment_tx_fee_0_htlcs);

		// If swapped: this HTLC would be counted as dust when it shouldn't be.
		let htlc_amt_below_success = ((253 * htlc_success_tx_weight(chan.opt_anchors()) / 1000) + chan.counterparty_dust_limit_satoshis - 1) * 1000;
		let htlc_candidate = HTLCCandidate::new(htlc_amt_below_success, HTLCInitiator::RemoteOffered);
		let commitment_tx_fee = chan.next_remote_commit_tx_fee_msat(htlc_candidate, None);
		assert_eq!(commitment_tx_fee, commitment_tx_fee_1_htlc);
	}

	#[test]
	fn channel_reestablish_no_updates() {
		let feeest = LowerBoundedFeeEstimator::new(&TestFeeEstimator{fee_est: 15000});
		let logger = test_utils::TestLogger::new();
		let secp_ctx = Secp256k1::new();
		let seed = [42; 32];
		let network = Network::Testnet;
		let best_block = BestBlock::from_network(network);
		let chain_hash = best_block.block_hash();
		let keys_provider = test_utils::TestKeysInterface::new(&seed, network);

		// Go through the flow of opening a channel between two nodes.

		// Create Node A's channel pointing to Node B's pubkey
		let node_b_node_id = PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[42; 32]).unwrap());
		let config = UserConfig::default();
		let mut node_a_chan = Channel::<EnforcingSigner>::new_outbound(&feeest, &&keys_provider, &&keys_provider, node_b_node_id, &channelmanager::provided_init_features(&config), 10000000, 100000, 42, &config, 0, 42).unwrap();

		// Create Node B's channel by receiving Node A's open_channel message
		let open_channel_msg = node_a_chan.get_open_channel(chain_hash);
		let node_b_node_id = PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[7; 32]).unwrap());
		let mut node_b_chan = Channel::<EnforcingSigner>::new_from_req(&feeest, &&keys_provider, &&keys_provider, node_b_node_id, &channelmanager::provided_channel_type_features(&config), &channelmanager::provided_init_features(&config), &open_channel_msg, 7, &config, 0, &&logger, 42).unwrap();

		// Node B --> Node A: accept channel
		let accept_channel_msg = node_b_chan.accept_inbound_channel(0);
		node_a_chan.accept_channel(&accept_channel_msg, &config.channel_handshake_limits, &channelmanager::provided_init_features(&config)).unwrap();

		// Node A --> Node B: funding created
		let output_script = node_a_chan.get_funding_redeemscript();
		let tx = Transaction { version: 1, lock_time: PackedLockTime::ZERO, input: Vec::new(), output: vec![TxOut {
			value: 10000000, script_pubkey: output_script.clone(),
		}]};
		let funding_outpoint = OutPoint{ txid: tx.txid(), index: 0 };
		let funding_created_msg = node_a_chan.get_outbound_funding_created(tx.clone(), funding_outpoint, &&logger).unwrap();
		let (funding_signed_msg, _) = node_b_chan.funding_created(&funding_created_msg, best_block, &&keys_provider, &&logger).unwrap();

		// Node B --> Node A: funding signed
		let _ = node_a_chan.funding_signed(&funding_signed_msg, best_block, &&keys_provider, &&logger);

		// Now disconnect the two nodes and check that the commitment point in
		// Node B's channel_reestablish message is sane.
		node_b_chan.remove_uncommitted_htlcs_and_mark_paused(&&logger);
		let msg = node_b_chan.get_channel_reestablish(&&logger);
		assert_eq!(msg.next_local_commitment_number, 1); // now called next_commitment_number
		assert_eq!(msg.next_remote_commitment_number, 0); // now called next_revocation_number
		match msg.data_loss_protect {
			OptionalField::Present(DataLossProtect { your_last_per_commitment_secret, .. }) => {
				assert_eq!(your_last_per_commitment_secret, [0; 32]);
			},
			_ => panic!()
		}

		// Check that the commitment point in Node A's channel_reestablish message
		// is sane.
		node_a_chan.remove_uncommitted_htlcs_and_mark_paused(&&logger);
		let msg = node_a_chan.get_channel_reestablish(&&logger);
		assert_eq!(msg.next_local_commitment_number, 1); // now called next_commitment_number
		assert_eq!(msg.next_remote_commitment_number, 0); // now called next_revocation_number
		match msg.data_loss_protect {
			OptionalField::Present(DataLossProtect { your_last_per_commitment_secret, .. }) => {
				assert_eq!(your_last_per_commitment_secret, [0; 32]);
			},
			_ => panic!()
		}
	}

	#[test]
	fn test_configured_holder_max_htlc_value_in_flight() {
		let feeest = LowerBoundedFeeEstimator::new(&TestFeeEstimator{fee_est: 15000});
		let logger = test_utils::TestLogger::new();
		let secp_ctx = Secp256k1::new();
		let seed = [42; 32];
		let network = Network::Testnet;
		let keys_provider = test_utils::TestKeysInterface::new(&seed, network);
		let outbound_node_id = PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[42; 32]).unwrap());
		let inbound_node_id = PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[7; 32]).unwrap());

		let mut config_2_percent = UserConfig::default();
		config_2_percent.channel_handshake_config.max_inbound_htlc_value_in_flight_percent_of_channel = 2;
		let mut config_99_percent = UserConfig::default();
		config_99_percent.channel_handshake_config.max_inbound_htlc_value_in_flight_percent_of_channel = 99;
		let mut config_0_percent = UserConfig::default();
		config_0_percent.channel_handshake_config.max_inbound_htlc_value_in_flight_percent_of_channel = 0;
		let mut config_101_percent = UserConfig::default();
		config_101_percent.channel_handshake_config.max_inbound_htlc_value_in_flight_percent_of_channel = 101;

		// Test that `new_outbound` creates a channel with the correct value for
		// `holder_max_htlc_value_in_flight_msat`, when configured with a valid percentage value,
		// which is set to the lower bound + 1 (2%) of the `channel_value`.
		let chan_1 = Channel::<EnforcingSigner>::new_outbound(&feeest, &&keys_provider, &&keys_provider, outbound_node_id, &channelmanager::provided_init_features(&config_2_percent), 10000000, 100000, 42, &config_2_percent, 0, 42).unwrap();
		let chan_1_value_msat = chan_1.channel_value_satoshis * 1000;
		assert_eq!(chan_1.holder_max_htlc_value_in_flight_msat, (chan_1_value_msat as f64 * 0.02) as u64);

		// Test with the upper bound - 1 of valid values (99%).
		let chan_2 = Channel::<EnforcingSigner>::new_outbound(&feeest, &&keys_provider, &&keys_provider, outbound_node_id, &channelmanager::provided_init_features(&config_99_percent), 10000000, 100000, 42, &config_99_percent, 0, 42).unwrap();
		let chan_2_value_msat = chan_2.channel_value_satoshis * 1000;
		assert_eq!(chan_2.holder_max_htlc_value_in_flight_msat, (chan_2_value_msat as f64 * 0.99) as u64);

		let chan_1_open_channel_msg = chan_1.get_open_channel(genesis_block(network).header.block_hash());

		// Test that `new_from_req` creates a channel with the correct value for
		// `holder_max_htlc_value_in_flight_msat`, when configured with a valid percentage value,
		// which is set to the lower bound - 1 (2%) of the `channel_value`.
		let chan_3 = Channel::<EnforcingSigner>::new_from_req(&feeest, &&keys_provider, &&keys_provider, inbound_node_id, &channelmanager::provided_channel_type_features(&config_2_percent), &channelmanager::provided_init_features(&config_2_percent), &chan_1_open_channel_msg, 7, &config_2_percent, 0, &&logger, 42).unwrap();
		let chan_3_value_msat = chan_3.channel_value_satoshis * 1000;
		assert_eq!(chan_3.holder_max_htlc_value_in_flight_msat, (chan_3_value_msat as f64 * 0.02) as u64);

		// Test with the upper bound - 1 of valid values (99%).
		let chan_4 = Channel::<EnforcingSigner>::new_from_req(&feeest, &&keys_provider, &&keys_provider, inbound_node_id, &channelmanager::provided_channel_type_features(&config_99_percent), &channelmanager::provided_init_features(&config_99_percent), &chan_1_open_channel_msg, 7, &config_99_percent, 0, &&logger, 42).unwrap();
		let chan_4_value_msat = chan_4.channel_value_satoshis * 1000;
		assert_eq!(chan_4.holder_max_htlc_value_in_flight_msat, (chan_4_value_msat as f64 * 0.99) as u64);

		// Test that `new_outbound` uses the lower bound of the configurable percentage values (1%)
		// if `max_inbound_htlc_value_in_flight_percent_of_channel` is set to a value less than 1.
		let chan_5 = Channel::<EnforcingSigner>::new_outbound(&feeest, &&keys_provider, &&keys_provider, outbound_node_id, &channelmanager::provided_init_features(&config_0_percent), 10000000, 100000, 42, &config_0_percent, 0, 42).unwrap();
		let chan_5_value_msat = chan_5.channel_value_satoshis * 1000;
		assert_eq!(chan_5.holder_max_htlc_value_in_flight_msat, (chan_5_value_msat as f64 * 0.01) as u64);

		// Test that `new_outbound` uses the upper bound of the configurable percentage values
		// (100%) if `max_inbound_htlc_value_in_flight_percent_of_channel` is set to a larger value
		// than 100.
		let chan_6 = Channel::<EnforcingSigner>::new_outbound(&feeest, &&keys_provider, &&keys_provider, outbound_node_id, &channelmanager::provided_init_features(&config_101_percent), 10000000, 100000, 42, &config_101_percent, 0, 42).unwrap();
		let chan_6_value_msat = chan_6.channel_value_satoshis * 1000;
		assert_eq!(chan_6.holder_max_htlc_value_in_flight_msat, chan_6_value_msat);

		// Test that `new_from_req` uses the lower bound of the configurable percentage values (1%)
		// if `max_inbound_htlc_value_in_flight_percent_of_channel` is set to a value less than 1.
		let chan_7 = Channel::<EnforcingSigner>::new_from_req(&feeest, &&keys_provider, &&keys_provider, inbound_node_id, &channelmanager::provided_channel_type_features(&config_0_percent), &channelmanager::provided_init_features(&config_0_percent), &chan_1_open_channel_msg, 7, &config_0_percent, 0, &&logger, 42).unwrap();
		let chan_7_value_msat = chan_7.channel_value_satoshis * 1000;
		assert_eq!(chan_7.holder_max_htlc_value_in_flight_msat, (chan_7_value_msat as f64 * 0.01) as u64);

		// Test that `new_from_req` uses the upper bound of the configurable percentage values
		// (100%) if `max_inbound_htlc_value_in_flight_percent_of_channel` is set to a larger value
		// than 100.
		let chan_8 = Channel::<EnforcingSigner>::new_from_req(&feeest, &&keys_provider, &&keys_provider, inbound_node_id, &channelmanager::provided_channel_type_features(&config_101_percent), &channelmanager::provided_init_features(&config_101_percent), &chan_1_open_channel_msg, 7, &config_101_percent, 0, &&logger, 42).unwrap();
		let chan_8_value_msat = chan_8.channel_value_satoshis * 1000;
		assert_eq!(chan_8.holder_max_htlc_value_in_flight_msat, chan_8_value_msat);
	}

	#[test]
	fn test_configured_holder_selected_channel_reserve_satoshis() {

		// Test that `new_outbound` and `new_from_req` create a channel with the correct
		// channel reserves, when `their_channel_reserve_proportional_millionths` is configured.
		test_self_and_counterparty_channel_reserve(10_000_000, 0.02, 0.02);

		// Test with valid but unreasonably high channel reserves
		// Requesting and accepting parties have requested for 49%-49% and 60%-30% channel reserve
		test_self_and_counterparty_channel_reserve(10_000_000, 0.49, 0.49);
		test_self_and_counterparty_channel_reserve(10_000_000, 0.60, 0.30);

		// Test with calculated channel reserve less than lower bound
		// i.e `MIN_THEIR_CHAN_RESERVE_SATOSHIS`
		test_self_and_counterparty_channel_reserve(100_000, 0.00002, 0.30);

		// Test with invalid channel reserves since sum of both is greater than or equal
		// to channel value
		test_self_and_counterparty_channel_reserve(10_000_000, 0.50, 0.50);
		test_self_and_counterparty_channel_reserve(10_000_000, 0.60, 0.50);
	}

	fn test_self_and_counterparty_channel_reserve(channel_value_satoshis: u64, outbound_selected_channel_reserve_perc: f64, inbound_selected_channel_reserve_perc: f64) {
		let fee_est = LowerBoundedFeeEstimator::new(&TestFeeEstimator { fee_est: 15_000 });
		let logger = test_utils::TestLogger::new();
		let secp_ctx = Secp256k1::new();
		let seed = [42; 32];
		let network = Network::Testnet;
		let keys_provider = test_utils::TestKeysInterface::new(&seed, network);
		let outbound_node_id = PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[42; 32]).unwrap());
		let inbound_node_id = PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[7; 32]).unwrap());


		let mut outbound_node_config = UserConfig::default();
		outbound_node_config.channel_handshake_config.their_channel_reserve_proportional_millionths = (outbound_selected_channel_reserve_perc * 1_000_000.0) as u32;
		let chan = Channel::<EnforcingSigner>::new_outbound(&&fee_est, &&keys_provider, &&keys_provider, outbound_node_id, &channelmanager::provided_init_features(&outbound_node_config), channel_value_satoshis, 100_000, 42, &outbound_node_config, 0, 42).unwrap();

		let expected_outbound_selected_chan_reserve = cmp::max(MIN_THEIR_CHAN_RESERVE_SATOSHIS, (chan.channel_value_satoshis as f64 * outbound_selected_channel_reserve_perc) as u64);
		assert_eq!(chan.holder_selected_channel_reserve_satoshis, expected_outbound_selected_chan_reserve);

		let chan_open_channel_msg = chan.get_open_channel(genesis_block(network).header.block_hash());
		let mut inbound_node_config = UserConfig::default();
		inbound_node_config.channel_handshake_config.their_channel_reserve_proportional_millionths = (inbound_selected_channel_reserve_perc * 1_000_000.0) as u32;

		if outbound_selected_channel_reserve_perc + inbound_selected_channel_reserve_perc < 1.0 {
			let chan_inbound_node = Channel::<EnforcingSigner>::new_from_req(&&fee_est, &&keys_provider, &&keys_provider, inbound_node_id, &channelmanager::provided_channel_type_features(&inbound_node_config), &channelmanager::provided_init_features(&outbound_node_config), &chan_open_channel_msg, 7, &inbound_node_config, 0, &&logger, 42).unwrap();

			let expected_inbound_selected_chan_reserve = cmp::max(MIN_THEIR_CHAN_RESERVE_SATOSHIS, (chan.channel_value_satoshis as f64 * inbound_selected_channel_reserve_perc) as u64);

			assert_eq!(chan_inbound_node.holder_selected_channel_reserve_satoshis, expected_inbound_selected_chan_reserve);
			assert_eq!(chan_inbound_node.counterparty_selected_channel_reserve_satoshis.unwrap(), expected_outbound_selected_chan_reserve);
		} else {
			// Channel Negotiations failed
			let result = Channel::<EnforcingSigner>::new_from_req(&&fee_est, &&keys_provider, &&keys_provider, inbound_node_id, &channelmanager::provided_channel_type_features(&inbound_node_config), &channelmanager::provided_init_features(&outbound_node_config), &chan_open_channel_msg, 7, &inbound_node_config, 0, &&logger, 42);
			assert!(result.is_err());
		}
	}

	#[test]
	fn channel_update() {
		let feeest = LowerBoundedFeeEstimator::new(&TestFeeEstimator{fee_est: 15000});
		let secp_ctx = Secp256k1::new();
		let seed = [42; 32];
		let network = Network::Testnet;
		let chain_hash = genesis_block(network).header.block_hash();
		let keys_provider = test_utils::TestKeysInterface::new(&seed, network);

		// Create a channel.
		let node_b_node_id = PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[42; 32]).unwrap());
		let config = UserConfig::default();
		let mut node_a_chan = Channel::<EnforcingSigner>::new_outbound(&feeest, &&keys_provider, &&keys_provider, node_b_node_id, &channelmanager::provided_init_features(&config), 10000000, 100000, 42, &config, 0, 42).unwrap();
		assert!(node_a_chan.counterparty_forwarding_info.is_none());
		assert_eq!(node_a_chan.holder_htlc_minimum_msat, 1); // the default
		assert!(node_a_chan.counterparty_forwarding_info().is_none());

		// Make sure that receiving a channel update will update the Channel as expected.
		let update = ChannelUpdate {
			contents: UnsignedChannelUpdate {
				chain_hash,
				short_channel_id: 0,
				timestamp: 0,
				flags: 0,
				cltv_expiry_delta: 100,
				htlc_minimum_msat: 5,
				htlc_maximum_msat: MAX_VALUE_MSAT,
				fee_base_msat: 110,
				fee_proportional_millionths: 11,
				excess_data: Vec::new(),
			},
			signature: Signature::from(unsafe { FFISignature::new() })
		};
		node_a_chan.channel_update(&update).unwrap();

		// The counterparty can send an update with a higher minimum HTLC, but that shouldn't
		// change our official htlc_minimum_msat.
		assert_eq!(node_a_chan.holder_htlc_minimum_msat, 1);
		match node_a_chan.counterparty_forwarding_info() {
			Some(info) => {
				assert_eq!(info.cltv_expiry_delta, 100);
				assert_eq!(info.fee_base_msat, 110);
				assert_eq!(info.fee_proportional_millionths, 11);
			},
			None => panic!("expected counterparty forwarding info to be Some")
		}
	}

	#[cfg(not(feature = "grind_signatures"))]
	#[test]
	fn outbound_commitment_test() {
		use bitcoin::util::sighash;
		use bitcoin::consensus::encode::serialize;
		use bitcoin::blockdata::transaction::EcdsaSighashType;
		use bitcoin::hashes::hex::FromHex;
		use bitcoin::hash_types::Txid;
		use bitcoin::secp256k1::Message;
		use crate::chain::keysinterface::EcdsaChannelSigner;
		use crate::ln::PaymentPreimage;
		use crate::ln::channel::{HTLCOutputInCommitment ,TxCreationKeys};
		use crate::ln::chan_utils::{ChannelPublicKeys, HolderCommitmentTransaction, CounterpartyChannelTransactionParameters};
		use crate::util::logger::Logger;
		use crate::sync::Arc;

		// Test vectors from BOLT 3 Appendices C and F (anchors):
		let feeest = TestFeeEstimator{fee_est: 15000};
		let logger : Arc<Logger> = Arc::new(test_utils::TestLogger::new());
		let secp_ctx = Secp256k1::new();

		let mut signer = InMemorySigner::new(
			&secp_ctx,
			SecretKey::from_slice(&hex::decode("30ff4956bbdd3222d44cc5e8a1261dab1e07957bdac5ae88fe3261ef321f3749").unwrap()[..]).unwrap(),
			SecretKey::from_slice(&hex::decode("0fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").unwrap()[..]).unwrap(),
			SecretKey::from_slice(&hex::decode("1111111111111111111111111111111111111111111111111111111111111111").unwrap()[..]).unwrap(),
			SecretKey::from_slice(&hex::decode("3333333333333333333333333333333333333333333333333333333333333333").unwrap()[..]).unwrap(),
			SecretKey::from_slice(&hex::decode("1111111111111111111111111111111111111111111111111111111111111111").unwrap()[..]).unwrap(),

			// These aren't set in the test vectors:
			[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
			10_000_000,
			[0; 32],
		);

		assert_eq!(signer.pubkeys().funding_pubkey.serialize()[..],
				hex::decode("023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb").unwrap()[..]);
		let keys_provider = Keys { signer: signer.clone() };

		let counterparty_node_id = PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[42; 32]).unwrap());
		let mut config = UserConfig::default();
		config.channel_handshake_config.announced_channel = false;
		let mut chan = Channel::<InMemorySigner>::new_outbound(&LowerBoundedFeeEstimator::new(&feeest), &&keys_provider, &&keys_provider, counterparty_node_id, &channelmanager::provided_init_features(&config), 10_000_000, 100000, 42, &config, 0, 42).unwrap(); // Nothing uses their network key in this test
		chan.holder_dust_limit_satoshis = 546;
		chan.counterparty_selected_channel_reserve_satoshis = Some(0); // Filled in in accept_channel

		let funding_info = OutPoint{ txid: Txid::from_hex("8984484a580b825b9972d7adb15050b3ab624ccd731946b3eeddb92f4e7ef6be").unwrap(), index: 0 };

		let counterparty_pubkeys = ChannelPublicKeys {
			funding_pubkey: public_from_secret_hex(&secp_ctx, "1552dfba4f6cf29a62a0af13c8d6981d36d0ef8d61ba10fb0fe90da7634d7e13"),
			revocation_basepoint: PublicKey::from_slice(&hex::decode("02466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27").unwrap()[..]).unwrap(),
			payment_point: public_from_secret_hex(&secp_ctx, "4444444444444444444444444444444444444444444444444444444444444444"),
			delayed_payment_basepoint: public_from_secret_hex(&secp_ctx, "1552dfba4f6cf29a62a0af13c8d6981d36d0ef8d61ba10fb0fe90da7634d7e13"),
			htlc_basepoint: public_from_secret_hex(&secp_ctx, "4444444444444444444444444444444444444444444444444444444444444444")
		};
		chan.channel_transaction_parameters.counterparty_parameters = Some(
			CounterpartyChannelTransactionParameters {
				pubkeys: counterparty_pubkeys.clone(),
				selected_contest_delay: 144
			});
		chan.channel_transaction_parameters.funding_outpoint = Some(funding_info);
		signer.provide_channel_parameters(&chan.channel_transaction_parameters);

		assert_eq!(counterparty_pubkeys.payment_point.serialize()[..],
		           hex::decode("032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991").unwrap()[..]);

		assert_eq!(counterparty_pubkeys.funding_pubkey.serialize()[..],
		           hex::decode("030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c1").unwrap()[..]);

		assert_eq!(counterparty_pubkeys.htlc_basepoint.serialize()[..],
		           hex::decode("032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991").unwrap()[..]);

		// We can't just use build_holder_transaction_keys here as the per_commitment_secret is not
		// derived from a commitment_seed, so instead we copy it here and call
		// build_commitment_transaction.
		let delayed_payment_base = &chan.holder_signer.pubkeys().delayed_payment_basepoint;
		let per_commitment_secret = SecretKey::from_slice(&hex::decode("1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100").unwrap()[..]).unwrap();
		let per_commitment_point = PublicKey::from_secret_key(&secp_ctx, &per_commitment_secret);
		let htlc_basepoint = &chan.holder_signer.pubkeys().htlc_basepoint;
		let keys = TxCreationKeys::derive_new(&secp_ctx, &per_commitment_point, delayed_payment_base, htlc_basepoint, &counterparty_pubkeys.revocation_basepoint, &counterparty_pubkeys.htlc_basepoint);

		macro_rules! test_commitment {
			( $counterparty_sig_hex: expr, $sig_hex: expr, $tx_hex: expr, $($remain:tt)* ) => {
				chan.channel_transaction_parameters.opt_anchors = None;
				test_commitment_common!($counterparty_sig_hex, $sig_hex, $tx_hex, false, $($remain)*);
			};
		}

		macro_rules! test_commitment_with_anchors {
			( $counterparty_sig_hex: expr, $sig_hex: expr, $tx_hex: expr, $($remain:tt)* ) => {
				chan.channel_transaction_parameters.opt_anchors = Some(());
				test_commitment_common!($counterparty_sig_hex, $sig_hex, $tx_hex, true, $($remain)*);
			};
		}

		macro_rules! test_commitment_common {
			( $counterparty_sig_hex: expr, $sig_hex: expr, $tx_hex: expr, $opt_anchors: expr, {
				$( { $htlc_idx: expr, $counterparty_htlc_sig_hex: expr, $htlc_sig_hex: expr, $htlc_tx_hex: expr } ), *
			} ) => { {
				let (commitment_tx, htlcs): (_, Vec<HTLCOutputInCommitment>) = {
					let mut commitment_stats = chan.build_commitment_transaction(0xffffffffffff - 42, &keys, true, false, &logger);

					let htlcs = commitment_stats.htlcs_included.drain(..)
						.filter_map(|(htlc, _)| if htlc.transaction_output_index.is_some() { Some(htlc) } else { None })
						.collect();
					(commitment_stats.tx, htlcs)
				};
				let trusted_tx = commitment_tx.trust();
				let unsigned_tx = trusted_tx.built_transaction();
				let redeemscript = chan.get_funding_redeemscript();
				let counterparty_signature = Signature::from_der(&hex::decode($counterparty_sig_hex).unwrap()[..]).unwrap();
				let sighash = unsigned_tx.get_sighash_all(&redeemscript, chan.channel_value_satoshis);
				log_trace!(logger, "unsigned_tx = {}", hex::encode(serialize(&unsigned_tx.transaction)));
				assert!(secp_ctx.verify_ecdsa(&sighash, &counterparty_signature, chan.counterparty_funding_pubkey()).is_ok(), "verify counterparty commitment sig");

				let mut per_htlc: Vec<(HTLCOutputInCommitment, Option<Signature>)> = Vec::new();
				per_htlc.clear(); // Don't warn about excess mut for no-HTLC calls
				let mut counterparty_htlc_sigs = Vec::new();
				counterparty_htlc_sigs.clear(); // Don't warn about excess mut for no-HTLC calls
				$({
					let remote_signature = Signature::from_der(&hex::decode($counterparty_htlc_sig_hex).unwrap()[..]).unwrap();
					per_htlc.push((htlcs[$htlc_idx].clone(), Some(remote_signature)));
					counterparty_htlc_sigs.push(remote_signature);
				})*
				assert_eq!(htlcs.len(), per_htlc.len());

				let holder_commitment_tx = HolderCommitmentTransaction::new(
					commitment_tx.clone(),
					counterparty_signature,
					counterparty_htlc_sigs,
					&chan.holder_signer.pubkeys().funding_pubkey,
					chan.counterparty_funding_pubkey()
				);
				let (holder_sig, htlc_sigs) = signer.sign_holder_commitment_and_htlcs(&holder_commitment_tx, &secp_ctx).unwrap();
				assert_eq!(Signature::from_der(&hex::decode($sig_hex).unwrap()[..]).unwrap(), holder_sig, "holder_sig");

				let funding_redeemscript = chan.get_funding_redeemscript();
				let tx = holder_commitment_tx.add_holder_sig(&funding_redeemscript, holder_sig);
				assert_eq!(serialize(&tx)[..], hex::decode($tx_hex).unwrap()[..], "tx");

				// ((htlc, counterparty_sig), (index, holder_sig))
				let mut htlc_sig_iter = holder_commitment_tx.htlcs().iter().zip(&holder_commitment_tx.counterparty_htlc_sigs).zip(htlc_sigs.iter().enumerate());

				$({
					log_trace!(logger, "verifying htlc {}", $htlc_idx);
					let remote_signature = Signature::from_der(&hex::decode($counterparty_htlc_sig_hex).unwrap()[..]).unwrap();

					let ref htlc = htlcs[$htlc_idx];
					let htlc_tx = chan_utils::build_htlc_transaction(&unsigned_tx.txid, chan.feerate_per_kw,
						chan.get_counterparty_selected_contest_delay().unwrap(),
						&htlc, $opt_anchors, false, &keys.broadcaster_delayed_payment_key, &keys.revocation_key);
					let htlc_redeemscript = chan_utils::get_htlc_redeemscript(&htlc, $opt_anchors, &keys);
					let htlc_sighashtype = if $opt_anchors { EcdsaSighashType::SinglePlusAnyoneCanPay } else { EcdsaSighashType::All };
					let htlc_sighash = Message::from_slice(&sighash::SighashCache::new(&htlc_tx).segwit_signature_hash(0, &htlc_redeemscript, htlc.amount_msat / 1000, htlc_sighashtype).unwrap()[..]).unwrap();
					assert!(secp_ctx.verify_ecdsa(&htlc_sighash, &remote_signature, &keys.countersignatory_htlc_key).is_ok(), "verify counterparty htlc sig");

					let mut preimage: Option<PaymentPreimage> = None;
					if !htlc.offered {
						for i in 0..5 {
							let out = PaymentHash(Sha256::hash(&[i; 32]).into_inner());
							if out == htlc.payment_hash {
								preimage = Some(PaymentPreimage([i; 32]));
							}
						}

						assert!(preimage.is_some());
					}

					let htlc_sig = htlc_sig_iter.next().unwrap();
					let num_anchors = if $opt_anchors { 2 } else { 0 };
					assert_eq!((htlc_sig.0).0.transaction_output_index, Some($htlc_idx + num_anchors), "output index");

					let signature = Signature::from_der(&hex::decode($htlc_sig_hex).unwrap()[..]).unwrap();
					assert_eq!(signature, *(htlc_sig.1).1, "htlc sig");
					let index = (htlc_sig.1).0;
					let channel_parameters = chan.channel_transaction_parameters.as_holder_broadcastable();
					let trusted_tx = holder_commitment_tx.trust();
					log_trace!(logger, "htlc_tx = {}", hex::encode(serialize(&trusted_tx.get_signed_htlc_tx(&channel_parameters, index, &(htlc_sig.0).1, (htlc_sig.1).1, &preimage))));
					assert_eq!(serialize(&trusted_tx.get_signed_htlc_tx(&channel_parameters, index, &(htlc_sig.0).1, (htlc_sig.1).1, &preimage))[..],
							hex::decode($htlc_tx_hex).unwrap()[..], "htlc tx");
				})*
				assert!(htlc_sig_iter.next().is_none());
			} }
		}

		// simple commitment tx with no HTLCs
		chan.value_to_self_msat = 7000000000;

		test_commitment!("3045022100c3127b33dcc741dd6b05b1e63cbd1a9a7d816f37af9b6756fa2376b056f032370220408b96279808fe57eb7e463710804cdf4f108388bc5cf722d8c848d2c7f9f3b0",
						 "30440220616210b2cc4d3afb601013c373bbd8aac54febd9f15400379a8cb65ce7deca60022034236c010991beb7ff770510561ae8dc885b8d38d1947248c38f2ae055647142",
						 "02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b8002c0c62d0000000000160014cc1b07838e387deacd0e5232e1e8b49f4c29e48454a56a00000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e04004730440220616210b2cc4d3afb601013c373bbd8aac54febd9f15400379a8cb65ce7deca60022034236c010991beb7ff770510561ae8dc885b8d38d1947248c38f2ae05564714201483045022100c3127b33dcc741dd6b05b1e63cbd1a9a7d816f37af9b6756fa2376b056f032370220408b96279808fe57eb7e463710804cdf4f108388bc5cf722d8c848d2c7f9f3b001475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae3e195220", {});

		// anchors: simple commitment tx with no HTLCs
		test_commitment_with_anchors!("3045022100f89034eba16b2be0e5581f750a0a6309192b75cce0f202f0ee2b4ec0cc394850022076c65dc507fe42276152b7a3d90e961e678adbe966e916ecfe85e64d430e75f3",
						 "30450221008266ac6db5ea71aac3c95d97b0e172ff596844851a3216eb88382a8dddfd33d2022050e240974cfd5d708708b4365574517c18e7ae535ef732a3484d43d0d82be9f7",
						 "02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b80044a010000000000002200202b1b5854183c12d3316565972c4668929d314d81c5dcdbb21cb45fe8a9a8114f4a01000000000000220020e9e86e4823faa62e222ebc858a226636856158f07e69898da3b0d1af0ddb3994c0c62d0000000000220020f3394e1e619b0eca1f91be2fb5ab4dfc59ba5b84ebe014ad1d43a564d012994a508b6a00000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e04004830450221008266ac6db5ea71aac3c95d97b0e172ff596844851a3216eb88382a8dddfd33d2022050e240974cfd5d708708b4365574517c18e7ae535ef732a3484d43d0d82be9f701483045022100f89034eba16b2be0e5581f750a0a6309192b75cce0f202f0ee2b4ec0cc394850022076c65dc507fe42276152b7a3d90e961e678adbe966e916ecfe85e64d430e75f301475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae3e195220", {});

		chan.pending_inbound_htlcs.push({
			let mut out = InboundHTLCOutput{
				htlc_id: 0,
				amount_msat: 1000000,
				cltv_expiry: 500,
				payment_hash: PaymentHash([0; 32]),
				state: InboundHTLCState::Committed,
			};
			out.payment_hash.0 = Sha256::hash(&hex::decode("0000000000000000000000000000000000000000000000000000000000000000").unwrap()).into_inner();
			out
		});
		chan.pending_inbound_htlcs.push({
			let mut out = InboundHTLCOutput{
				htlc_id: 1,
				amount_msat: 2000000,
				cltv_expiry: 501,
				payment_hash: PaymentHash([0; 32]),
				state: InboundHTLCState::Committed,
			};
			out.payment_hash.0 = Sha256::hash(&hex::decode("0101010101010101010101010101010101010101010101010101010101010101").unwrap()).into_inner();
			out
		});
		chan.pending_outbound_htlcs.push({
			let mut out = OutboundHTLCOutput{
				htlc_id: 2,
				amount_msat: 2000000,
				cltv_expiry: 502,
				payment_hash: PaymentHash([0; 32]),
				state: OutboundHTLCState::Committed,
				source: HTLCSource::dummy(),
			};
			out.payment_hash.0 = Sha256::hash(&hex::decode("0202020202020202020202020202020202020202020202020202020202020202").unwrap()).into_inner();
			out
		});
		chan.pending_outbound_htlcs.push({
			let mut out = OutboundHTLCOutput{
				htlc_id: 3,
				amount_msat: 3000000,
				cltv_expiry: 503,
				payment_hash: PaymentHash([0; 32]),
				state: OutboundHTLCState::Committed,
				source: HTLCSource::dummy(),
			};
			out.payment_hash.0 = Sha256::hash(&hex::decode("0303030303030303030303030303030303030303030303030303030303030303").unwrap()).into_inner();
			out
		});
		chan.pending_inbound_htlcs.push({
			let mut out = InboundHTLCOutput{
				htlc_id: 4,
				amount_msat: 4000000,
				cltv_expiry: 504,
				payment_hash: PaymentHash([0; 32]),
				state: InboundHTLCState::Committed,
			};
			out.payment_hash.0 = Sha256::hash(&hex::decode("0404040404040404040404040404040404040404040404040404040404040404").unwrap()).into_inner();
			out
		});

		// commitment tx with all five HTLCs untrimmed (minimum feerate)
		chan.value_to_self_msat = 6993000000; // 7000000000 - 7000000
		chan.feerate_per_kw = 0;

		test_commitment!("3044022009b048187705a8cbc9ad73adbe5af148c3d012e1f067961486c822c7af08158c022006d66f3704cfab3eb2dc49dae24e4aa22a6910fc9b424007583204e3621af2e5",
		                 "304402206fc2d1f10ea59951eefac0b4b7c396a3c3d87b71ff0b019796ef4535beaf36f902201765b0181e514d04f4c8ad75659d7037be26cdb3f8bb6f78fe61decef484c3ea",
		                 "02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b8007e80300000000000022002052bfef0479d7b293c27e0f1eb294bea154c63a3294ef092c19af51409bce0e2ad007000000000000220020403d394747cae42e98ff01734ad5c08f82ba123d3d9a620abda88989651e2ab5d007000000000000220020748eba944fedc8827f6b06bc44678f93c0f9e6078b35c6331ed31e75f8ce0c2db80b000000000000220020c20b5d1f8584fd90443e7b7b720136174fa4b9333c261d04dbbd012635c0f419a00f0000000000002200208c48d15160397c9731df9bc3b236656efb6665fbfe92b4a6878e88a499f741c4c0c62d0000000000160014cc1b07838e387deacd0e5232e1e8b49f4c29e484e0a06a00000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e040047304402206fc2d1f10ea59951eefac0b4b7c396a3c3d87b71ff0b019796ef4535beaf36f902201765b0181e514d04f4c8ad75659d7037be26cdb3f8bb6f78fe61decef484c3ea01473044022009b048187705a8cbc9ad73adbe5af148c3d012e1f067961486c822c7af08158c022006d66f3704cfab3eb2dc49dae24e4aa22a6910fc9b424007583204e3621af2e501475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae3e195220", {

		                  { 0,
		                  "3045022100d9e29616b8f3959f1d3d7f7ce893ffedcdc407717d0de8e37d808c91d3a7c50d022078c3033f6d00095c8720a4bc943c1b45727818c082e4e3ddbc6d3116435b624b",
		                  "30440220636de5682ef0c5b61f124ec74e8aa2461a69777521d6998295dcea36bc3338110220165285594b23c50b28b82df200234566628a27bcd17f7f14404bd865354eb3ce",
		                  "02000000000101ab84ff284f162cfbfef241f853b47d4368d171f9e2a1445160cd591c4c7d882b00000000000000000001e8030000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0500483045022100d9e29616b8f3959f1d3d7f7ce893ffedcdc407717d0de8e37d808c91d3a7c50d022078c3033f6d00095c8720a4bc943c1b45727818c082e4e3ddbc6d3116435b624b014730440220636de5682ef0c5b61f124ec74e8aa2461a69777521d6998295dcea36bc3338110220165285594b23c50b28b82df200234566628a27bcd17f7f14404bd865354eb3ce012000000000000000000000000000000000000000000000000000000000000000008a76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a914b8bcb07f6344b42ab04250c86a6e8b75d3fdbbc688527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f401b175ac686800000000" },

		                  { 1,
		                  "30440220649fe8b20e67e46cbb0d09b4acea87dbec001b39b08dee7bdd0b1f03922a8640022037c462dff79df501cecfdb12ea7f4de91f99230bb544726f6e04527b1f896004",
		                  "3045022100803159dee7935dba4a1d36a61055ce8fd62caa528573cc221ae288515405a252022029c59e7cffce374fe860100a4a63787e105c3cf5156d40b12dd53ff55ac8cf3f",
		                  "02000000000101ab84ff284f162cfbfef241f853b47d4368d171f9e2a1445160cd591c4c7d882b01000000000000000001d0070000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e05004730440220649fe8b20e67e46cbb0d09b4acea87dbec001b39b08dee7bdd0b1f03922a8640022037c462dff79df501cecfdb12ea7f4de91f99230bb544726f6e04527b1f89600401483045022100803159dee7935dba4a1d36a61055ce8fd62caa528573cc221ae288515405a252022029c59e7cffce374fe860100a4a63787e105c3cf5156d40b12dd53ff55ac8cf3f01008576a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a914b43e1b38138a41b37f7cd9a1d274bc63e3a9b5d188ac6868f6010000" },

		                  { 2,
		                  "30440220770fc321e97a19f38985f2e7732dd9fe08d16a2efa4bcbc0429400a447faf49102204d40b417f3113e1b0944ae0986f517564ab4acd3d190503faf97a6e420d43352",
		                  "3045022100a437cc2ce77400ecde441b3398fea3c3ad8bdad8132be818227fe3c5b8345989022069d45e7fa0ae551ec37240845e2c561ceb2567eacf3076a6a43a502d05865faa",
		                  "02000000000101ab84ff284f162cfbfef241f853b47d4368d171f9e2a1445160cd591c4c7d882b02000000000000000001d0070000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e05004730440220770fc321e97a19f38985f2e7732dd9fe08d16a2efa4bcbc0429400a447faf49102204d40b417f3113e1b0944ae0986f517564ab4acd3d190503faf97a6e420d4335201483045022100a437cc2ce77400ecde441b3398fea3c3ad8bdad8132be818227fe3c5b8345989022069d45e7fa0ae551ec37240845e2c561ceb2567eacf3076a6a43a502d05865faa012001010101010101010101010101010101010101010101010101010101010101018a76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a9144b6b2e5444c2639cc0fb7bcea5afba3f3cdce23988527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f501b175ac686800000000" },

		                  { 3,
		                  "304402207bcbf4f60a9829b05d2dbab84ed593e0291836be715dc7db6b72a64caf646af802201e489a5a84f7c5cc130398b841d138d031a5137ac8f4c49c770a4959dc3c1363",
		                  "304402203121d9b9c055f354304b016a36662ee99e1110d9501cb271b087ddb6f382c2c80220549882f3f3b78d9c492de47543cb9a697cecc493174726146536c5954dac7487",
		                  "02000000000101ab84ff284f162cfbfef241f853b47d4368d171f9e2a1445160cd591c4c7d882b03000000000000000001b80b0000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e050047304402207bcbf4f60a9829b05d2dbab84ed593e0291836be715dc7db6b72a64caf646af802201e489a5a84f7c5cc130398b841d138d031a5137ac8f4c49c770a4959dc3c13630147304402203121d9b9c055f354304b016a36662ee99e1110d9501cb271b087ddb6f382c2c80220549882f3f3b78d9c492de47543cb9a697cecc493174726146536c5954dac748701008576a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a9148a486ff2e31d6158bf39e2608864d63fefd09d5b88ac6868f7010000" },

		                  { 4,
		                  "3044022076dca5cb81ba7e466e349b7128cdba216d4d01659e29b96025b9524aaf0d1899022060de85697b88b21c749702b7d2cfa7dfeaa1f472c8f1d7d9c23f2bf968464b87",
		                  "3045022100d9080f103cc92bac15ec42464a95f070c7fb6925014e673ee2ea1374d36a7f7502200c65294d22eb20d48564954d5afe04a385551919d8b2ddb4ae2459daaeee1d95",
		                  "02000000000101ab84ff284f162cfbfef241f853b47d4368d171f9e2a1445160cd591c4c7d882b04000000000000000001a00f0000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0500473044022076dca5cb81ba7e466e349b7128cdba216d4d01659e29b96025b9524aaf0d1899022060de85697b88b21c749702b7d2cfa7dfeaa1f472c8f1d7d9c23f2bf968464b8701483045022100d9080f103cc92bac15ec42464a95f070c7fb6925014e673ee2ea1374d36a7f7502200c65294d22eb20d48564954d5afe04a385551919d8b2ddb4ae2459daaeee1d95012004040404040404040404040404040404040404040404040404040404040404048a76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a91418bc1a114ccf9c052d3d23e28d3b0a9d1227434288527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f801b175ac686800000000" }
		} );

		// commitment tx with seven outputs untrimmed (maximum feerate)
		chan.value_to_self_msat = 6993000000; // 7000000000 - 7000000
		chan.feerate_per_kw = 647;

		test_commitment!("3045022100a135f9e8a5ed25f7277446c67956b00ce6f610ead2bdec2c2f686155b7814772022059f1f6e1a8b336a68efcc1af3fe4d422d4827332b5b067501b099c47b7b5b5ee",
		                 "30450221009ec15c687898bb4da8b3a833e5ab8bfc51ec6e9202aaa8e66611edfd4a85ed1102203d7183e45078b9735c93450bc3415d3e5a8c576141a711ec6ddcb4a893926bb7",
		                 "02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b8007e80300000000000022002052bfef0479d7b293c27e0f1eb294bea154c63a3294ef092c19af51409bce0e2ad007000000000000220020403d394747cae42e98ff01734ad5c08f82ba123d3d9a620abda88989651e2ab5d007000000000000220020748eba944fedc8827f6b06bc44678f93c0f9e6078b35c6331ed31e75f8ce0c2db80b000000000000220020c20b5d1f8584fd90443e7b7b720136174fa4b9333c261d04dbbd012635c0f419a00f0000000000002200208c48d15160397c9731df9bc3b236656efb6665fbfe92b4a6878e88a499f741c4c0c62d0000000000160014cc1b07838e387deacd0e5232e1e8b49f4c29e484e09c6a00000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e04004830450221009ec15c687898bb4da8b3a833e5ab8bfc51ec6e9202aaa8e66611edfd4a85ed1102203d7183e45078b9735c93450bc3415d3e5a8c576141a711ec6ddcb4a893926bb701483045022100a135f9e8a5ed25f7277446c67956b00ce6f610ead2bdec2c2f686155b7814772022059f1f6e1a8b336a68efcc1af3fe4d422d4827332b5b067501b099c47b7b5b5ee01475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae3e195220", {

		                  { 0,
		                  "30450221008437627f9ad84ac67052e2a414a4367b8556fd1f94d8b02590f89f50525cd33502205b9c21ff6e7fc864f2352746ad8ba59182510819acb644e25b8a12fc37bbf24f",
		                  "30440220344b0deb055230d01703e6c7acd45853c4af2328b49b5d8af4f88a060733406602202ea64f2a43d5751edfe75503cbc35a62e3141b5ed032fa03360faf4ca66f670b",
		                  "020000000001012cfb3e4788c206881d38f2996b6cb2109b5935acb527d14bdaa7b908afa9b2fe0000000000000000000122020000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e05004830450221008437627f9ad84ac67052e2a414a4367b8556fd1f94d8b02590f89f50525cd33502205b9c21ff6e7fc864f2352746ad8ba59182510819acb644e25b8a12fc37bbf24f014730440220344b0deb055230d01703e6c7acd45853c4af2328b49b5d8af4f88a060733406602202ea64f2a43d5751edfe75503cbc35a62e3141b5ed032fa03360faf4ca66f670b012000000000000000000000000000000000000000000000000000000000000000008a76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a914b8bcb07f6344b42ab04250c86a6e8b75d3fdbbc688527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f401b175ac686800000000" },

		                  { 1,
		                  "304402205a67f92bf6845cf2892b48d874ac1daf88a36495cf8a06f93d83180d930a6f75022031da1621d95c3f335cc06a3056cf960199dae600b7cf89088f65fc53cdbef28c",
		                  "30450221009e5e3822b0185c6799a95288c597b671d6cc69ab80f43740f00c6c3d0752bdda02206da947a74bd98f3175324dc56fdba86cc783703a120a6f0297537e60632f4c7f",
		                  "020000000001012cfb3e4788c206881d38f2996b6cb2109b5935acb527d14bdaa7b908afa9b2fe0100000000000000000124060000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e050047304402205a67f92bf6845cf2892b48d874ac1daf88a36495cf8a06f93d83180d930a6f75022031da1621d95c3f335cc06a3056cf960199dae600b7cf89088f65fc53cdbef28c014830450221009e5e3822b0185c6799a95288c597b671d6cc69ab80f43740f00c6c3d0752bdda02206da947a74bd98f3175324dc56fdba86cc783703a120a6f0297537e60632f4c7f01008576a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a914b43e1b38138a41b37f7cd9a1d274bc63e3a9b5d188ac6868f6010000" },

		                  { 2,
		                  "30440220437e21766054a3eef7f65690c5bcfa9920babbc5af92b819f772f6ea96df6c7402207173622024bd97328cfb26c6665e25c2f5d67c319443ccdc60c903217005d8c8",
		                  "3045022100fcfc47e36b712624677626cef3dc1d67f6583bd46926a6398fe6b00b0c9a37760220525788257b187fc775c6370d04eadf34d06f3650a63f8df851cee0ecb47a1673",
		                  "020000000001012cfb3e4788c206881d38f2996b6cb2109b5935acb527d14bdaa7b908afa9b2fe020000000000000000010a060000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e05004730440220437e21766054a3eef7f65690c5bcfa9920babbc5af92b819f772f6ea96df6c7402207173622024bd97328cfb26c6665e25c2f5d67c319443ccdc60c903217005d8c801483045022100fcfc47e36b712624677626cef3dc1d67f6583bd46926a6398fe6b00b0c9a37760220525788257b187fc775c6370d04eadf34d06f3650a63f8df851cee0ecb47a1673012001010101010101010101010101010101010101010101010101010101010101018a76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a9144b6b2e5444c2639cc0fb7bcea5afba3f3cdce23988527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f501b175ac686800000000" },

		                  { 3,
		                  "304402207436e10737e4df499fc051686d3e11a5bb2310e4d1f1e691d287cef66514791202207cb58e71a6b7a42dd001b7e3ae672ea4f71ea3e1cd412b742e9124abb0739c64",
		                  "3045022100e78211b8409afb7255ffe37337da87f38646f1faebbdd61bc1920d69e3ead67a02201a626305adfcd16bfb7e9340928d9b6305464eab4aa4c4a3af6646e9b9f69dee",
		                  "020000000001012cfb3e4788c206881d38f2996b6cb2109b5935acb527d14bdaa7b908afa9b2fe030000000000000000010c0a0000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e050047304402207436e10737e4df499fc051686d3e11a5bb2310e4d1f1e691d287cef66514791202207cb58e71a6b7a42dd001b7e3ae672ea4f71ea3e1cd412b742e9124abb0739c6401483045022100e78211b8409afb7255ffe37337da87f38646f1faebbdd61bc1920d69e3ead67a02201a626305adfcd16bfb7e9340928d9b6305464eab4aa4c4a3af6646e9b9f69dee01008576a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a9148a486ff2e31d6158bf39e2608864d63fefd09d5b88ac6868f7010000" },

		                  { 4,
		                  "30450221009acd6a827a76bfee50806178dfe0495cd4e1d9c58279c194c7b01520fe68cb8d022024d439047c368883e570997a7d40f0b430cb5a742f507965e7d3063ae3feccca",
		                  "3044022048762cf546bbfe474f1536365ea7c416e3c0389d60558bc9412cb148fb6ab68202207215d7083b75c96ff9d2b08c59c34e287b66820f530b486a9aa4cdd9c347d5b9",
		                  "020000000001012cfb3e4788c206881d38f2996b6cb2109b5935acb527d14bdaa7b908afa9b2fe04000000000000000001da0d0000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e05004830450221009acd6a827a76bfee50806178dfe0495cd4e1d9c58279c194c7b01520fe68cb8d022024d439047c368883e570997a7d40f0b430cb5a742f507965e7d3063ae3feccca01473044022048762cf546bbfe474f1536365ea7c416e3c0389d60558bc9412cb148fb6ab68202207215d7083b75c96ff9d2b08c59c34e287b66820f530b486a9aa4cdd9c347d5b9012004040404040404040404040404040404040404040404040404040404040404048a76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a91418bc1a114ccf9c052d3d23e28d3b0a9d1227434288527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f801b175ac686800000000" }
		} );

		// commitment tx with six outputs untrimmed (minimum feerate)
		chan.value_to_self_msat = 6993000000; // 7000000000 - 7000000
		chan.feerate_per_kw = 648;

		test_commitment!("304402203948f900a5506b8de36a4d8502f94f21dd84fd9c2314ab427d52feaa7a0a19f2022059b6a37a4adaa2c5419dc8aea63c6e2a2ec4c4bde46207f6dc1fcd22152fc6e5",
		                 "3045022100b15f72908ba3382a34ca5b32519240a22300cc6015b6f9418635fb41f3d01d8802207adb331b9ed1575383dca0f2355e86c173802feecf8298fbea53b9d4610583e9",
		                 "02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b8006d007000000000000220020403d394747cae42e98ff01734ad5c08f82ba123d3d9a620abda88989651e2ab5d007000000000000220020748eba944fedc8827f6b06bc44678f93c0f9e6078b35c6331ed31e75f8ce0c2db80b000000000000220020c20b5d1f8584fd90443e7b7b720136174fa4b9333c261d04dbbd012635c0f419a00f0000000000002200208c48d15160397c9731df9bc3b236656efb6665fbfe92b4a6878e88a499f741c4c0c62d0000000000160014cc1b07838e387deacd0e5232e1e8b49f4c29e4844e9d6a00000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0400483045022100b15f72908ba3382a34ca5b32519240a22300cc6015b6f9418635fb41f3d01d8802207adb331b9ed1575383dca0f2355e86c173802feecf8298fbea53b9d4610583e90147304402203948f900a5506b8de36a4d8502f94f21dd84fd9c2314ab427d52feaa7a0a19f2022059b6a37a4adaa2c5419dc8aea63c6e2a2ec4c4bde46207f6dc1fcd22152fc6e501475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae3e195220", {

		                  { 0,
		                  "3045022100a031202f3be94678f0e998622ee95ebb6ada8da1e9a5110228b5e04a747351e4022010ca6a21e18314ed53cfaae3b1f51998552a61a468e596368829a50ce40110e0",
		                  "304502210097e1873b57267730154595187a34949d3744f52933070c74757005e61ce2112e02204ecfba2aa42d4f14bdf8bad4206bb97217b702e6c433e0e1b0ce6587e6d46ec6",
		                  "020000000001010f44041fdfba175987cf4e6135ba2a154e3b7fb96483dc0ed5efc0678e5b6bf10000000000000000000123060000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0500483045022100a031202f3be94678f0e998622ee95ebb6ada8da1e9a5110228b5e04a747351e4022010ca6a21e18314ed53cfaae3b1f51998552a61a468e596368829a50ce40110e00148304502210097e1873b57267730154595187a34949d3744f52933070c74757005e61ce2112e02204ecfba2aa42d4f14bdf8bad4206bb97217b702e6c433e0e1b0ce6587e6d46ec601008576a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a914b43e1b38138a41b37f7cd9a1d274bc63e3a9b5d188ac6868f6010000" },

		                  { 1,
		                  "304402202361012a634aee7835c5ecdd6413dcffa8f404b7e77364c792cff984e4ee71e90220715c5e90baa08daa45a7439b1ee4fa4843ed77b19c058240b69406606d384124",
		                  "3044022019de73b00f1d818fb388e83b2c8c31f6bce35ac624e215bc12f88f9dc33edf48022006ff814bb9f700ee6abc3294e146fac3efd4f13f0005236b41c0a946ee00c9ae",
		                  "020000000001010f44041fdfba175987cf4e6135ba2a154e3b7fb96483dc0ed5efc0678e5b6bf10100000000000000000109060000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e050047304402202361012a634aee7835c5ecdd6413dcffa8f404b7e77364c792cff984e4ee71e90220715c5e90baa08daa45a7439b1ee4fa4843ed77b19c058240b69406606d38412401473044022019de73b00f1d818fb388e83b2c8c31f6bce35ac624e215bc12f88f9dc33edf48022006ff814bb9f700ee6abc3294e146fac3efd4f13f0005236b41c0a946ee00c9ae012001010101010101010101010101010101010101010101010101010101010101018a76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a9144b6b2e5444c2639cc0fb7bcea5afba3f3cdce23988527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f501b175ac686800000000" },

		                  { 2,
		                  "304402207e8e82cd71ed4febeb593732c260456836e97d81896153ecd2b3cf320ca6861702202dd4a30f68f98ced7cc56a36369ac1fdd978248c5ff4ed204fc00cc625532989",
		                  "3045022100bd0be6100c4fd8f102ec220e1b053e4c4e2ecca25615490150007b40d314dc3902201a1e0ea266965b43164d9e6576f58fa6726d42883dd1c3996d2925c2e2260796",
		                  "020000000001010f44041fdfba175987cf4e6135ba2a154e3b7fb96483dc0ed5efc0678e5b6bf1020000000000000000010b0a0000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e050047304402207e8e82cd71ed4febeb593732c260456836e97d81896153ecd2b3cf320ca6861702202dd4a30f68f98ced7cc56a36369ac1fdd978248c5ff4ed204fc00cc62553298901483045022100bd0be6100c4fd8f102ec220e1b053e4c4e2ecca25615490150007b40d314dc3902201a1e0ea266965b43164d9e6576f58fa6726d42883dd1c3996d2925c2e226079601008576a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a9148a486ff2e31d6158bf39e2608864d63fefd09d5b88ac6868f7010000" },

		                  { 3,
		                  "3044022024cd52e4198c8ae0e414a86d86b5a65ea7450f2eb4e783096736d93395eca5ce022078f0094745b45be4d4b2b04dd5978c9e66ba49109e5704403e84aaf5f387d6be",
		                  "3045022100bbfb9d0a946d420807c86e985d636cceb16e71c3694ed186316251a00cbd807202207773223f9a337e145f64673825be9b30d07ef1542c82188b264bedcf7cda78c6",
		                  "020000000001010f44041fdfba175987cf4e6135ba2a154e3b7fb96483dc0ed5efc0678e5b6bf103000000000000000001d90d0000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0500473044022024cd52e4198c8ae0e414a86d86b5a65ea7450f2eb4e783096736d93395eca5ce022078f0094745b45be4d4b2b04dd5978c9e66ba49109e5704403e84aaf5f387d6be01483045022100bbfb9d0a946d420807c86e985d636cceb16e71c3694ed186316251a00cbd807202207773223f9a337e145f64673825be9b30d07ef1542c82188b264bedcf7cda78c6012004040404040404040404040404040404040404040404040404040404040404048a76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a91418bc1a114ccf9c052d3d23e28d3b0a9d1227434288527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f801b175ac686800000000" }
		} );

		// anchors: commitment tx with six outputs untrimmed (minimum dust limit)
		chan.value_to_self_msat = 6993000000; // 7000000000 - 7000000
		chan.feerate_per_kw = 645;
		chan.holder_dust_limit_satoshis = 1001;

		test_commitment_with_anchors!("3044022025d97466c8049e955a5afce28e322f4b34d2561118e52332fb400f9b908cc0a402205dc6fba3a0d67ee142c428c535580cd1f2ff42e2f89b47e0c8a01847caffc312",
		                 "3045022100d57697c707b6f6d053febf24b98e8989f186eea42e37e9e91663ec2c70bb8f70022079b0715a472118f262f43016a674f59c015d9cafccec885968e76d9d9c5d0051",
		                 "02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b80084a010000000000002200202b1b5854183c12d3316565972c4668929d314d81c5dcdbb21cb45fe8a9a8114f4a01000000000000220020e9e86e4823faa62e222ebc858a226636856158f07e69898da3b0d1af0ddb3994d0070000000000002200203e68115ae0b15b8de75b6c6bc9af5ac9f01391544e0870dae443a1e8fe7837ead007000000000000220020fe0598d74fee2205cc3672e6e6647706b4f3099713b4661b62482c3addd04a5eb80b000000000000220020f96d0334feb64a4f40eb272031d07afcb038db56aa57446d60308c9f8ccadef9a00f000000000000220020ce6e751274836ff59622a0d1e07f8831d80bd6730bd48581398bfadd2bb8da9ac0c62d0000000000220020f3394e1e619b0eca1f91be2fb5ab4dfc59ba5b84ebe014ad1d43a564d012994abc996a00000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0400483045022100d57697c707b6f6d053febf24b98e8989f186eea42e37e9e91663ec2c70bb8f70022079b0715a472118f262f43016a674f59c015d9cafccec885968e76d9d9c5d005101473044022025d97466c8049e955a5afce28e322f4b34d2561118e52332fb400f9b908cc0a402205dc6fba3a0d67ee142c428c535580cd1f2ff42e2f89b47e0c8a01847caffc31201475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae3e195220", {

		                  { 0,
		                  "3045022100e04d160a326432659fe9fb127304c1d348dfeaba840081bdc57d8efd902a48d8022008a824e7cf5492b97e4d9e03c06a09f822775a44f6b5b2533a2088904abfc282",
		                  "3045022100b7c49846466b13b190ff739bbe3005c105482fc55539e55b1c561f76b6982b6c02200e5c35808619cf543c8405cff9fedd25f333a4a2f6f6d5e8af8150090c40ef09",
		                  "02000000000101104f394af4c4fad78337f95e3e9f802f4c0d86ab231853af09b285348561320002000000000100000001d0070000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0500483045022100e04d160a326432659fe9fb127304c1d348dfeaba840081bdc57d8efd902a48d8022008a824e7cf5492b97e4d9e03c06a09f822775a44f6b5b2533a2088904abfc28283483045022100b7c49846466b13b190ff739bbe3005c105482fc55539e55b1c561f76b6982b6c02200e5c35808619cf543c8405cff9fedd25f333a4a2f6f6d5e8af8150090c40ef0901008876a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a914b43e1b38138a41b37f7cd9a1d274bc63e3a9b5d188ac6851b27568f6010000" },

		                  { 1,
		                  "3045022100fbdc3c367ce3bf30796025cc590ee1f2ce0e72ae1ac19f5986d6d0a4fc76211f02207e45ae9267e8e820d188569604f71d1abd11bd385d58853dd7dc034cdb3e9a6e",
		                  "3045022100d29330f24db213b262068706099b39c15fa7e070c3fcdf8836c09723fc4d365602203ce57d01e9f28601e461a0b5c4a50119b270bde8b70148d133a6849c70b115ac",
		                  "02000000000101104f394af4c4fad78337f95e3e9f802f4c0d86ab231853af09b285348561320003000000000100000001d0070000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0500483045022100fbdc3c367ce3bf30796025cc590ee1f2ce0e72ae1ac19f5986d6d0a4fc76211f02207e45ae9267e8e820d188569604f71d1abd11bd385d58853dd7dc034cdb3e9a6e83483045022100d29330f24db213b262068706099b39c15fa7e070c3fcdf8836c09723fc4d365602203ce57d01e9f28601e461a0b5c4a50119b270bde8b70148d133a6849c70b115ac012001010101010101010101010101010101010101010101010101010101010101018d76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a9144b6b2e5444c2639cc0fb7bcea5afba3f3cdce23988527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f501b175ac6851b2756800000000" },

		                  { 2,
		                  "3044022066c5ef625cee3ddd2bc7b6bfb354b5834cf1cc6d52dd972fb41b7b225437ae4a022066cb85647df65c6b87a54e416dcdcca778a776c36a9643d2b5dc793c9b29f4c1",
		                  "304402202d4ce515cd9000ec37575972d70b8d24f73909fb7012e8ebd8c2066ef6fe187902202830b53e64ea565fecd0f398100691da6bb2a5cf9bb0d1926f1d71d05828a11e",
		                  "02000000000101104f394af4c4fad78337f95e3e9f802f4c0d86ab231853af09b285348561320004000000000100000001b80b0000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0500473044022066c5ef625cee3ddd2bc7b6bfb354b5834cf1cc6d52dd972fb41b7b225437ae4a022066cb85647df65c6b87a54e416dcdcca778a776c36a9643d2b5dc793c9b29f4c18347304402202d4ce515cd9000ec37575972d70b8d24f73909fb7012e8ebd8c2066ef6fe187902202830b53e64ea565fecd0f398100691da6bb2a5cf9bb0d1926f1d71d05828a11e01008876a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a9148a486ff2e31d6158bf39e2608864d63fefd09d5b88ac6851b27568f7010000" },

		                  { 3,
		                  "3044022022c7e11595c53ee89a57ca76baf0aed730da035952d6ab3fe6459f5eff3b337a022075e10cc5f5fd724a35ce4087a5d03cd616698626c69814032132b50bb97dc615",
		                  "3045022100b20cd63e0587d1711beaebda4730775c4ac8b8b2ec78fe18a0c44c3f168c25230220079abb7fc4924e2fca5950842e5b9e416735585026914570078c4ef62f286226",
		                  "02000000000101104f394af4c4fad78337f95e3e9f802f4c0d86ab231853af09b285348561320005000000000100000001a00f0000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0500473044022022c7e11595c53ee89a57ca76baf0aed730da035952d6ab3fe6459f5eff3b337a022075e10cc5f5fd724a35ce4087a5d03cd616698626c69814032132b50bb97dc61583483045022100b20cd63e0587d1711beaebda4730775c4ac8b8b2ec78fe18a0c44c3f168c25230220079abb7fc4924e2fca5950842e5b9e416735585026914570078c4ef62f286226012004040404040404040404040404040404040404040404040404040404040404048d76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a91418bc1a114ccf9c052d3d23e28d3b0a9d1227434288527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f801b175ac6851b2756800000000" }
		} );

		// commitment tx with six outputs untrimmed (maximum feerate)
		chan.value_to_self_msat = 6993000000; // 7000000000 - 7000000
		chan.feerate_per_kw = 2069;
		chan.holder_dust_limit_satoshis = 546;

		test_commitment!("304502210090b96a2498ce0c0f2fadbec2aab278fed54c1a7838df793ec4d2c78d96ec096202204fdd439c50f90d483baa7b68feeef4bd33bc277695405447bcd0bfb2ca34d7bc",
		                 "3045022100ad9a9bbbb75d506ca3b716b336ee3cf975dd7834fcf129d7dd188146eb58a8b4022061a759ee417339f7fe2ea1e8deb83abb6a74db31a09b7648a932a639cda23e33",
		                 "02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b8006d007000000000000220020403d394747cae42e98ff01734ad5c08f82ba123d3d9a620abda88989651e2ab5d007000000000000220020748eba944fedc8827f6b06bc44678f93c0f9e6078b35c6331ed31e75f8ce0c2db80b000000000000220020c20b5d1f8584fd90443e7b7b720136174fa4b9333c261d04dbbd012635c0f419a00f0000000000002200208c48d15160397c9731df9bc3b236656efb6665fbfe92b4a6878e88a499f741c4c0c62d0000000000160014cc1b07838e387deacd0e5232e1e8b49f4c29e48477956a00000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0400483045022100ad9a9bbbb75d506ca3b716b336ee3cf975dd7834fcf129d7dd188146eb58a8b4022061a759ee417339f7fe2ea1e8deb83abb6a74db31a09b7648a932a639cda23e330148304502210090b96a2498ce0c0f2fadbec2aab278fed54c1a7838df793ec4d2c78d96ec096202204fdd439c50f90d483baa7b68feeef4bd33bc277695405447bcd0bfb2ca34d7bc01475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae3e195220", {

		                  { 0,
		                  "3045022100f33513ee38abf1c582876f921f8fddc06acff48e04515532a32d3938de938ffd02203aa308a2c1863b7d6fdf53159a1465bf2e115c13152546cc5d74483ceaa7f699",
		                  "3045022100a637902a5d4c9ba9e7c472a225337d5aac9e2e3f6744f76e237132e7619ba0400220035c60d784a031c0d9f6df66b7eab8726a5c25397399ee4aa960842059eb3f9d",
		                  "02000000000101adbe717a63fb658add30ada1e6e12ed257637581898abe475c11d7bbcd65bd4d0000000000000000000175020000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0500483045022100f33513ee38abf1c582876f921f8fddc06acff48e04515532a32d3938de938ffd02203aa308a2c1863b7d6fdf53159a1465bf2e115c13152546cc5d74483ceaa7f69901483045022100a637902a5d4c9ba9e7c472a225337d5aac9e2e3f6744f76e237132e7619ba0400220035c60d784a031c0d9f6df66b7eab8726a5c25397399ee4aa960842059eb3f9d01008576a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a914b43e1b38138a41b37f7cd9a1d274bc63e3a9b5d188ac6868f6010000" },

		                  { 1,
		                  "3045022100ce07682cf4b90093c22dc2d9ab2a77ad6803526b655ef857221cc96af5c9e0bf02200f501cee22e7a268af40b555d15a8237c9f36ad67ef1841daf9f6a0267b1e6df",
		                  "3045022100e57e46234f8782d3ff7aa593b4f7446fb5316c842e693dc63ee324fd49f6a1c302204a2f7b44c48bd26e1554422afae13153eb94b29d3687b733d18930615fb2db61",
		                  "02000000000101adbe717a63fb658add30ada1e6e12ed257637581898abe475c11d7bbcd65bd4d0100000000000000000122020000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0500483045022100ce07682cf4b90093c22dc2d9ab2a77ad6803526b655ef857221cc96af5c9e0bf02200f501cee22e7a268af40b555d15a8237c9f36ad67ef1841daf9f6a0267b1e6df01483045022100e57e46234f8782d3ff7aa593b4f7446fb5316c842e693dc63ee324fd49f6a1c302204a2f7b44c48bd26e1554422afae13153eb94b29d3687b733d18930615fb2db61012001010101010101010101010101010101010101010101010101010101010101018a76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a9144b6b2e5444c2639cc0fb7bcea5afba3f3cdce23988527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f501b175ac686800000000" },

		                  { 2,
		                  "3045022100e3e35492e55f82ec0bc2f317ffd7a486d1f7024330fe9743c3559fc39f32ef0c02203d1d4db651fc388a91d5ad8ecdd8e83673063bc8eefe27cfd8c189090e3a23e0",
		                  "3044022068613fb1b98eb3aec7f44c5b115b12343c2f066c4277c82b5f873dfe68f37f50022028109b4650f3f528ca4bfe9a467aff2e3e43893b61b5159157119d5d95cf1c18",
		                  "02000000000101adbe717a63fb658add30ada1e6e12ed257637581898abe475c11d7bbcd65bd4d020000000000000000015d060000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0500483045022100e3e35492e55f82ec0bc2f317ffd7a486d1f7024330fe9743c3559fc39f32ef0c02203d1d4db651fc388a91d5ad8ecdd8e83673063bc8eefe27cfd8c189090e3a23e001473044022068613fb1b98eb3aec7f44c5b115b12343c2f066c4277c82b5f873dfe68f37f50022028109b4650f3f528ca4bfe9a467aff2e3e43893b61b5159157119d5d95cf1c1801008576a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a9148a486ff2e31d6158bf39e2608864d63fefd09d5b88ac6868f7010000" },

		                  { 3,
		                  "304402207475aeb0212ef9bf5130b60937817ad88c9a87976988ef1f323f026148cc4a850220739fea17ad3257dcad72e509c73eebe86bee30b178467b9fdab213d631b109df",
		                  "3045022100d315522e09e7d53d2a659a79cb67fef56d6c4bddf3f46df6772d0d20a7beb7c8022070bcc17e288607b6a72be0bd83368bb6d53488db266c1cdb4d72214e4f02ac33",
		                  "02000000000101adbe717a63fb658add30ada1e6e12ed257637581898abe475c11d7bbcd65bd4d03000000000000000001f2090000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e050047304402207475aeb0212ef9bf5130b60937817ad88c9a87976988ef1f323f026148cc4a850220739fea17ad3257dcad72e509c73eebe86bee30b178467b9fdab213d631b109df01483045022100d315522e09e7d53d2a659a79cb67fef56d6c4bddf3f46df6772d0d20a7beb7c8022070bcc17e288607b6a72be0bd83368bb6d53488db266c1cdb4d72214e4f02ac33012004040404040404040404040404040404040404040404040404040404040404048a76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a91418bc1a114ccf9c052d3d23e28d3b0a9d1227434288527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f801b175ac686800000000" }
		} );

		// commitment tx with five outputs untrimmed (minimum feerate)
		chan.value_to_self_msat = 6993000000; // 7000000000 - 7000000
		chan.feerate_per_kw = 2070;

		test_commitment!("304402204ca1ba260dee913d318271d86e10ca0f5883026fb5653155cff600fb40895223022037b145204b7054a40e08bb1fefbd826f827b40838d3e501423bcc57924bcb50c",
		                 "3044022001014419b5ba00e083ac4e0a85f19afc848aacac2d483b4b525d15e2ae5adbfe022015ebddad6ee1e72b47cb09f3e78459da5be01ccccd95dceca0e056a00cc773c1",
		                 "02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b8005d007000000000000220020403d394747cae42e98ff01734ad5c08f82ba123d3d9a620abda88989651e2ab5b80b000000000000220020c20b5d1f8584fd90443e7b7b720136174fa4b9333c261d04dbbd012635c0f419a00f0000000000002200208c48d15160397c9731df9bc3b236656efb6665fbfe92b4a6878e88a499f741c4c0c62d0000000000160014cc1b07838e387deacd0e5232e1e8b49f4c29e484da966a00000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0400473044022001014419b5ba00e083ac4e0a85f19afc848aacac2d483b4b525d15e2ae5adbfe022015ebddad6ee1e72b47cb09f3e78459da5be01ccccd95dceca0e056a00cc773c10147304402204ca1ba260dee913d318271d86e10ca0f5883026fb5653155cff600fb40895223022037b145204b7054a40e08bb1fefbd826f827b40838d3e501423bcc57924bcb50c01475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae3e195220", {

		                  { 0,
		                  "304402205f6b6d12d8d2529fb24f4445630566cf4abbd0f9330ab6c2bdb94222d6a2a0c502202f556258ae6f05b193749e4c541dfcc13b525a5422f6291f073f15617ba8579b",
		                  "30440220150b11069454da70caf2492ded9e0065c9a57f25ac2a4c52657b1d15b6c6ed85022068a38833b603c8892717206383611bad210f1cbb4b1f87ea29c6c65b9e1cb3e5",
		                  "02000000000101403ad7602b43293497a3a2235a12ecefda4f3a1f1d06e49b1786d945685de1ff0000000000000000000174020000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e050047304402205f6b6d12d8d2529fb24f4445630566cf4abbd0f9330ab6c2bdb94222d6a2a0c502202f556258ae6f05b193749e4c541dfcc13b525a5422f6291f073f15617ba8579b014730440220150b11069454da70caf2492ded9e0065c9a57f25ac2a4c52657b1d15b6c6ed85022068a38833b603c8892717206383611bad210f1cbb4b1f87ea29c6c65b9e1cb3e501008576a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a914b43e1b38138a41b37f7cd9a1d274bc63e3a9b5d188ac6868f6010000" },

		                  { 1,
		                  "3045022100f960dfb1c9aee7ce1437efa65b523e399383e8149790e05d8fed27ff6e42fe0002202fe8613e062ffe0b0c518cc4101fba1c6de70f64a5bcc7ae663f2efae43b8546",
		                  "30450221009a6ed18e6873bc3644332a6ee21c152a5b102821865350df7a8c74451a51f9f2022050d801fb4895d7d7fbf452824c0168347f5c0cbe821cf6a97a63af5b8b2563c6",
		                  "02000000000101403ad7602b43293497a3a2235a12ecefda4f3a1f1d06e49b1786d945685de1ff010000000000000000015c060000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0500483045022100f960dfb1c9aee7ce1437efa65b523e399383e8149790e05d8fed27ff6e42fe0002202fe8613e062ffe0b0c518cc4101fba1c6de70f64a5bcc7ae663f2efae43b8546014830450221009a6ed18e6873bc3644332a6ee21c152a5b102821865350df7a8c74451a51f9f2022050d801fb4895d7d7fbf452824c0168347f5c0cbe821cf6a97a63af5b8b2563c601008576a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a9148a486ff2e31d6158bf39e2608864d63fefd09d5b88ac6868f7010000" },

		                  { 2,
		                  "3045022100ae5fc7717ae684bc1fcf9020854e5dbe9842c9e7472879ac06ff95ac2bb10e4e022057728ada4c00083a3e65493fb5d50a232165948a1a0f530ef63185c2c8c56504",
		                  "30440220408ad3009827a8fccf774cb285587686bfb2ed041f89a89453c311ce9c8ee0f902203c7392d9f8306d3a46522a66bd2723a7eb2628cb2d9b34d4c104f1766bf37502",
		                  "02000000000101403ad7602b43293497a3a2235a12ecefda4f3a1f1d06e49b1786d945685de1ff02000000000000000001f1090000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0500483045022100ae5fc7717ae684bc1fcf9020854e5dbe9842c9e7472879ac06ff95ac2bb10e4e022057728ada4c00083a3e65493fb5d50a232165948a1a0f530ef63185c2c8c56504014730440220408ad3009827a8fccf774cb285587686bfb2ed041f89a89453c311ce9c8ee0f902203c7392d9f8306d3a46522a66bd2723a7eb2628cb2d9b34d4c104f1766bf37502012004040404040404040404040404040404040404040404040404040404040404048a76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a91418bc1a114ccf9c052d3d23e28d3b0a9d1227434288527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f801b175ac686800000000" }
		} );

		// commitment tx with five outputs untrimmed (maximum feerate)
		chan.value_to_self_msat = 6993000000; // 7000000000 - 7000000
		chan.feerate_per_kw = 2194;

		test_commitment!("304402204bb3d6e279d71d9da414c82de42f1f954267c762b2e2eb8b76bc3be4ea07d4b0022014febc009c5edc8c3fc5d94015de163200f780046f1c293bfed8568f08b70fb3",
		                 "3044022072c2e2b1c899b2242656a537dde2892fa3801be0d6df0a87836c550137acde8302201654aa1974d37a829083c3ba15088689f30b56d6a4f6cb14c7bad0ee3116d398",
		                 "02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b8005d007000000000000220020403d394747cae42e98ff01734ad5c08f82ba123d3d9a620abda88989651e2ab5b80b000000000000220020c20b5d1f8584fd90443e7b7b720136174fa4b9333c261d04dbbd012635c0f419a00f0000000000002200208c48d15160397c9731df9bc3b236656efb6665fbfe92b4a6878e88a499f741c4c0c62d0000000000160014cc1b07838e387deacd0e5232e1e8b49f4c29e48440966a00000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0400473044022072c2e2b1c899b2242656a537dde2892fa3801be0d6df0a87836c550137acde8302201654aa1974d37a829083c3ba15088689f30b56d6a4f6cb14c7bad0ee3116d3980147304402204bb3d6e279d71d9da414c82de42f1f954267c762b2e2eb8b76bc3be4ea07d4b0022014febc009c5edc8c3fc5d94015de163200f780046f1c293bfed8568f08b70fb301475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae3e195220", {

		                  { 0,
		                  "3045022100939726680351a7856c1bc386d4a1f422c7d29bd7b56afc139570f508474e6c40022023175a799ccf44c017fbaadb924c40b2a12115a5b7d0dfd3228df803a2de8450",
		                  "304502210099c98c2edeeee6ec0fb5f3bea8b79bb016a2717afa9b5072370f34382de281d302206f5e2980a995e045cf90a547f0752a7ee99d48547bc135258fe7bc07e0154301",
		                  "02000000000101153cd825fdb3aa624bfe513e8031d5d08c5e582fb3d1d1fe8faf27d3eed410cd0000000000000000000122020000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0500483045022100939726680351a7856c1bc386d4a1f422c7d29bd7b56afc139570f508474e6c40022023175a799ccf44c017fbaadb924c40b2a12115a5b7d0dfd3228df803a2de84500148304502210099c98c2edeeee6ec0fb5f3bea8b79bb016a2717afa9b5072370f34382de281d302206f5e2980a995e045cf90a547f0752a7ee99d48547bc135258fe7bc07e015430101008576a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a914b43e1b38138a41b37f7cd9a1d274bc63e3a9b5d188ac6868f6010000" },

		                  { 1,
		                  "3044022021bb883bf324553d085ba2e821cad80c28ef8b303dbead8f98e548783c02d1600220638f9ef2a9bba25869afc923f4b5dc38be3bb459f9efa5d869392d5f7779a4a0",
		                  "3045022100fd85bd7697b89c08ec12acc8ba89b23090637d83abd26ca37e01ae93e67c367302202b551fe69386116c47f984aab9c8dfd25d864dcde5d3389cfbef2447a85c4b77",
		                  "02000000000101153cd825fdb3aa624bfe513e8031d5d08c5e582fb3d1d1fe8faf27d3eed410cd010000000000000000010a060000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0500473044022021bb883bf324553d085ba2e821cad80c28ef8b303dbead8f98e548783c02d1600220638f9ef2a9bba25869afc923f4b5dc38be3bb459f9efa5d869392d5f7779a4a001483045022100fd85bd7697b89c08ec12acc8ba89b23090637d83abd26ca37e01ae93e67c367302202b551fe69386116c47f984aab9c8dfd25d864dcde5d3389cfbef2447a85c4b7701008576a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a9148a486ff2e31d6158bf39e2608864d63fefd09d5b88ac6868f7010000" },

		                  { 2,
		                  "3045022100c9e6f0454aa598b905a35e641a70cc9f67b5f38cc4b00843a041238c4a9f1c4a0220260a2822a62da97e44583e837245995ca2e36781769c52f19e498efbdcca262b",
		                  "30450221008a9f2ea24cd455c2b64c1472a5fa83865b0a5f49a62b661801e884cf2849af8302204d44180e50bf6adfcf1c1e581d75af91aba4e28681ce4a5ee5f3cbf65eca10f3",
		                  "02000000000101153cd825fdb3aa624bfe513e8031d5d08c5e582fb3d1d1fe8faf27d3eed410cd020000000000000000019a090000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0500483045022100c9e6f0454aa598b905a35e641a70cc9f67b5f38cc4b00843a041238c4a9f1c4a0220260a2822a62da97e44583e837245995ca2e36781769c52f19e498efbdcca262b014830450221008a9f2ea24cd455c2b64c1472a5fa83865b0a5f49a62b661801e884cf2849af8302204d44180e50bf6adfcf1c1e581d75af91aba4e28681ce4a5ee5f3cbf65eca10f3012004040404040404040404040404040404040404040404040404040404040404048a76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a91418bc1a114ccf9c052d3d23e28d3b0a9d1227434288527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f801b175ac686800000000" }
		} );

		// commitment tx with four outputs untrimmed (minimum feerate)
		chan.value_to_self_msat = 6993000000; // 7000000000 - 7000000
		chan.feerate_per_kw = 2195;

		test_commitment!("304402201a8c1b1f9671cd9e46c7323a104d7047cc48d3ee80d40d4512e0c72b8dc65666022066d7f9a2ce18c9eb22d2739ffcce05721c767f9b607622a31b6ea5793ddce403",
		                 "3044022044d592025b610c0d678f65032e87035cdfe89d1598c522cc32524ae8172417c30220749fef9d5b2ae8cdd91ece442ba8809bc891efedae2291e578475f97715d1767",
		                 "02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b8004b80b000000000000220020c20b5d1f8584fd90443e7b7b720136174fa4b9333c261d04dbbd012635c0f419a00f0000000000002200208c48d15160397c9731df9bc3b236656efb6665fbfe92b4a6878e88a499f741c4c0c62d0000000000160014cc1b07838e387deacd0e5232e1e8b49f4c29e484b8976a00000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0400473044022044d592025b610c0d678f65032e87035cdfe89d1598c522cc32524ae8172417c30220749fef9d5b2ae8cdd91ece442ba8809bc891efedae2291e578475f97715d17670147304402201a8c1b1f9671cd9e46c7323a104d7047cc48d3ee80d40d4512e0c72b8dc65666022066d7f9a2ce18c9eb22d2739ffcce05721c767f9b607622a31b6ea5793ddce40301475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae3e195220", {

		                  { 0,
		                  "3045022100e57b845066a06ee7c2cbfc29eabffe52daa9bf6f6de760066d04df9f9b250e0002202ffb197f0e6e0a77a75a9aff27014bd3de83b7f748d7efef986abe655e1dd50e",
		                  "3045022100ecc8c6529d0b2316d046f0f0757c1e1c25a636db168ec4f3aa1b9278df685dc0022067ae6b65e936f1337091f7b18a15935b608c5f2cdddb2f892ed0babfdd376d76",
		                  "020000000001018130a10f09b13677ba2885a8bca32860f3a952e5912b829a473639b5a2c07b900000000000000000000109060000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0500483045022100e57b845066a06ee7c2cbfc29eabffe52daa9bf6f6de760066d04df9f9b250e0002202ffb197f0e6e0a77a75a9aff27014bd3de83b7f748d7efef986abe655e1dd50e01483045022100ecc8c6529d0b2316d046f0f0757c1e1c25a636db168ec4f3aa1b9278df685dc0022067ae6b65e936f1337091f7b18a15935b608c5f2cdddb2f892ed0babfdd376d7601008576a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a9148a486ff2e31d6158bf39e2608864d63fefd09d5b88ac6868f7010000" },

		                  { 1,
		                  "3045022100d193b7ecccad8057571620a0b1ffa6c48e9483311723b59cf536043b20bc51550220546d4bd37b3b101ecda14f6c907af46ec391abce1cd9c7ce22b1a62b534f2f2a",
		                  "3044022014d66f11f9cacf923807eba49542076c5fe5cccf252fb08fe98c78ef3ca6ab5402201b290dbe043cc512d9d78de074a5a129b8759bc6a6c546b190d120b690bd6e82",
		                  "020000000001018130a10f09b13677ba2885a8bca32860f3a952e5912b829a473639b5a2c07b900100000000000000000199090000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0500483045022100d193b7ecccad8057571620a0b1ffa6c48e9483311723b59cf536043b20bc51550220546d4bd37b3b101ecda14f6c907af46ec391abce1cd9c7ce22b1a62b534f2f2a01473044022014d66f11f9cacf923807eba49542076c5fe5cccf252fb08fe98c78ef3ca6ab5402201b290dbe043cc512d9d78de074a5a129b8759bc6a6c546b190d120b690bd6e82012004040404040404040404040404040404040404040404040404040404040404048a76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a91418bc1a114ccf9c052d3d23e28d3b0a9d1227434288527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f801b175ac686800000000" }
		} );

		// anchors: commitment tx with four outputs untrimmed (minimum dust limit)
		chan.value_to_self_msat = 6993000000; // 7000000000 - 7000000
		chan.feerate_per_kw = 2185;
		chan.holder_dust_limit_satoshis = 2001;

		test_commitment_with_anchors!("3044022040f63a16148cf35c8d3d41827f5ae7f7c3746885bb64d4d1b895892a83812b3e02202fcf95c2bf02c466163b3fa3ced6a24926fbb4035095a96842ef516e86ba54c0",
		                 "3045022100cd8479cfe1edb1e5a1d487391e0451a469c7171e51e680183f19eb4321f20e9b02204eab7d5a6384b1b08e03baa6e4d9748dfd2b5ab2bae7e39604a0d0055bbffdd5",
		                 "02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b80064a010000000000002200202b1b5854183c12d3316565972c4668929d314d81c5dcdbb21cb45fe8a9a8114f4a01000000000000220020e9e86e4823faa62e222ebc858a226636856158f07e69898da3b0d1af0ddb3994b80b000000000000220020f96d0334feb64a4f40eb272031d07afcb038db56aa57446d60308c9f8ccadef9a00f000000000000220020ce6e751274836ff59622a0d1e07f8831d80bd6730bd48581398bfadd2bb8da9ac0c62d0000000000220020f3394e1e619b0eca1f91be2fb5ab4dfc59ba5b84ebe014ad1d43a564d012994ac5916a00000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0400483045022100cd8479cfe1edb1e5a1d487391e0451a469c7171e51e680183f19eb4321f20e9b02204eab7d5a6384b1b08e03baa6e4d9748dfd2b5ab2bae7e39604a0d0055bbffdd501473044022040f63a16148cf35c8d3d41827f5ae7f7c3746885bb64d4d1b895892a83812b3e02202fcf95c2bf02c466163b3fa3ced6a24926fbb4035095a96842ef516e86ba54c001475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae3e195220", {

		                  { 0,
		                  "304402206870514a72ad6e723ff7f1e0370d7a33c1cd2a0b9272674143ebaf6a1d02dee102205bd953c34faf5e7322e9a1c0103581cb090280fda4f1039ee8552668afa90ebb",
		                  "30440220669de9ca7910eff65a7773ebd14a9fc371fe88cde5b8e2a81609d85c87ac939b02201ac29472fa4067322e92d75b624942d60be5050139b20bb363db75be79eb946f",
		                  "02000000000101ac13a7715f80b8e52dda43c6929cade5521bdced3a405da02b443f1ffb1e33cc02000000000100000001b80b0000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e050047304402206870514a72ad6e723ff7f1e0370d7a33c1cd2a0b9272674143ebaf6a1d02dee102205bd953c34faf5e7322e9a1c0103581cb090280fda4f1039ee8552668afa90ebb834730440220669de9ca7910eff65a7773ebd14a9fc371fe88cde5b8e2a81609d85c87ac939b02201ac29472fa4067322e92d75b624942d60be5050139b20bb363db75be79eb946f01008876a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a9148a486ff2e31d6158bf39e2608864d63fefd09d5b88ac6851b27568f7010000" },

		                  { 1,
		                  "3045022100949e8dd938da56445b1cdfdebe1b7efea086edd05d89910d205a1e2e033ce47102202cbd68b5262ab144d9ec12653f87dfb0bb6bd05d1f58ae1e523f028eaefd7271",
		                  "3045022100e3104ed8b239f8019e5f0a1a73d7782a94a8c36e7984f476c3a0b3cb0e62e27902207e3d52884600985f8a2098e53a5c30dd6a5e857733acfaa07ab2162421ed2688",
		                  "02000000000101ac13a7715f80b8e52dda43c6929cade5521bdced3a405da02b443f1ffb1e33cc03000000000100000001a00f0000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0500483045022100949e8dd938da56445b1cdfdebe1b7efea086edd05d89910d205a1e2e033ce47102202cbd68b5262ab144d9ec12653f87dfb0bb6bd05d1f58ae1e523f028eaefd727183483045022100e3104ed8b239f8019e5f0a1a73d7782a94a8c36e7984f476c3a0b3cb0e62e27902207e3d52884600985f8a2098e53a5c30dd6a5e857733acfaa07ab2162421ed2688012004040404040404040404040404040404040404040404040404040404040404048d76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a91418bc1a114ccf9c052d3d23e28d3b0a9d1227434288527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f801b175ac6851b2756800000000" }
		} );

		// commitment tx with four outputs untrimmed (maximum feerate)
		chan.value_to_self_msat = 6993000000; // 7000000000 - 7000000
		chan.feerate_per_kw = 3702;
		chan.holder_dust_limit_satoshis = 546;

		test_commitment!("304502210092a587aeb777f869e7ff0d7898ea619ee26a3dacd1f3672b945eea600be431100220077ee9eae3528d15251f2a52b607b189820e57a6ccfac8d1af502b132ee40169",
		                 "3045022100e5efb73c32d32da2d79702299b6317de6fb24a60476e3855926d78484dd1b3c802203557cb66a42c944ef06e00bcc4da35a5bcb2f185aab0f8e403e519e1d66aaf75",
		                 "02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b8004b80b000000000000220020c20b5d1f8584fd90443e7b7b720136174fa4b9333c261d04dbbd012635c0f419a00f0000000000002200208c48d15160397c9731df9bc3b236656efb6665fbfe92b4a6878e88a499f741c4c0c62d0000000000160014cc1b07838e387deacd0e5232e1e8b49f4c29e4846f916a00000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0400483045022100e5efb73c32d32da2d79702299b6317de6fb24a60476e3855926d78484dd1b3c802203557cb66a42c944ef06e00bcc4da35a5bcb2f185aab0f8e403e519e1d66aaf750148304502210092a587aeb777f869e7ff0d7898ea619ee26a3dacd1f3672b945eea600be431100220077ee9eae3528d15251f2a52b607b189820e57a6ccfac8d1af502b132ee4016901475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae3e195220", {

		                  { 0,
		                  "304402206fa54c11f98c3bae1e93df43fc7affeb05b476bf8060c03e29c377c69bc08e8b0220672701cce50d5c379ff45a5d2cfe48ac44973adb066ac32608e21221d869bb89",
		                  "304402206e36c683ebf2cb16bcef3d5439cf8b53cd97280a365ed8acd7abb85a8ba5f21c02206e8621edfc2a5766cbc96eb67fd501127ff163eb6b85518a39f7d4974aef126f",
		                  "020000000001018db483bff65c70ee71d8282aeec5a880e2e2b39e45772bda5460403095c62e3f0000000000000000000122020000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e050047304402206fa54c11f98c3bae1e93df43fc7affeb05b476bf8060c03e29c377c69bc08e8b0220672701cce50d5c379ff45a5d2cfe48ac44973adb066ac32608e21221d869bb890147304402206e36c683ebf2cb16bcef3d5439cf8b53cd97280a365ed8acd7abb85a8ba5f21c02206e8621edfc2a5766cbc96eb67fd501127ff163eb6b85518a39f7d4974aef126f01008576a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a9148a486ff2e31d6158bf39e2608864d63fefd09d5b88ac6868f7010000" },

		                  { 1,
		                  "3044022057649739b0eb74d541ead0dfdb3d4b2c15aa192720031044c3434c67812e5ca902201e5ede42d960ae551707f4a6b34b09393cf4dee2418507daa022e3550dbb5817",
		                  "304402207faad26678c8850e01b4a0696d60841f7305e1832b786110ee9075cb92ed14a30220516ef8ee5dfa80824ea28cbcec0dd95f8b847146257c16960db98507db15ffdc",
		                  "020000000001018db483bff65c70ee71d8282aeec5a880e2e2b39e45772bda5460403095c62e3f0100000000000000000176050000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0500473044022057649739b0eb74d541ead0dfdb3d4b2c15aa192720031044c3434c67812e5ca902201e5ede42d960ae551707f4a6b34b09393cf4dee2418507daa022e3550dbb58170147304402207faad26678c8850e01b4a0696d60841f7305e1832b786110ee9075cb92ed14a30220516ef8ee5dfa80824ea28cbcec0dd95f8b847146257c16960db98507db15ffdc012004040404040404040404040404040404040404040404040404040404040404048a76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a91418bc1a114ccf9c052d3d23e28d3b0a9d1227434288527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f801b175ac686800000000" }
		} );

		// commitment tx with three outputs untrimmed (minimum feerate)
		chan.value_to_self_msat = 6993000000; // 7000000000 - 7000000
		chan.feerate_per_kw = 3703;

		test_commitment!("3045022100b495d239772a237ff2cf354b1b11be152fd852704cb184e7356d13f2fb1e5e430220723db5cdb9cbd6ead7bfd3deb419cf41053a932418cbb22a67b581f40bc1f13e",
		                 "304402201b736d1773a124c745586217a75bed5f66c05716fbe8c7db4fdb3c3069741cdd02205083f39c321c1bcadfc8d97e3c791a66273d936abac0c6a2fde2ed46019508e1",
		                 "02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b8003a00f0000000000002200208c48d15160397c9731df9bc3b236656efb6665fbfe92b4a6878e88a499f741c4c0c62d0000000000160014cc1b07838e387deacd0e5232e1e8b49f4c29e484eb936a00000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e040047304402201b736d1773a124c745586217a75bed5f66c05716fbe8c7db4fdb3c3069741cdd02205083f39c321c1bcadfc8d97e3c791a66273d936abac0c6a2fde2ed46019508e101483045022100b495d239772a237ff2cf354b1b11be152fd852704cb184e7356d13f2fb1e5e430220723db5cdb9cbd6ead7bfd3deb419cf41053a932418cbb22a67b581f40bc1f13e01475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae3e195220", {

		                  { 0,
		                  "3045022100c34c61735f93f2e324cc873c3b248111ccf8f6db15d5969583757010d4ad2b4602207867bb919b2ddd6387873e425345c9b7fd18d1d66aba41f3607bc2896ef3c30a",
		                  "3045022100988c143e2110067117d2321bdd4bd16ca1734c98b29290d129384af0962b634e02206c1b02478878c5f547018b833986578f90c3e9be669fe5788ad0072a55acbb05",
		                  "0200000000010120060e4a29579d429f0f27c17ee5f1ee282f20d706d6f90b63d35946d8f3029a0000000000000000000175050000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0500483045022100c34c61735f93f2e324cc873c3b248111ccf8f6db15d5969583757010d4ad2b4602207867bb919b2ddd6387873e425345c9b7fd18d1d66aba41f3607bc2896ef3c30a01483045022100988c143e2110067117d2321bdd4bd16ca1734c98b29290d129384af0962b634e02206c1b02478878c5f547018b833986578f90c3e9be669fe5788ad0072a55acbb05012004040404040404040404040404040404040404040404040404040404040404048a76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a91418bc1a114ccf9c052d3d23e28d3b0a9d1227434288527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f801b175ac686800000000" }
		} );

		// anchors: commitment tx with three outputs untrimmed (minimum dust limit)
		chan.value_to_self_msat = 6993000000; // 7000000000 - 7000000
		chan.feerate_per_kw = 3687;
		chan.holder_dust_limit_satoshis = 3001;

		test_commitment_with_anchors!("3045022100ad6c71569856b2d7ff42e838b4abe74a713426b37f22fa667a195a4c88908c6902202b37272b02a42dc6d9f4f82cab3eaf84ac882d9ed762859e1e75455c2c228377",
		                 "3045022100c970799bcb33f43179eb43b3378a0a61991cf2923f69b36ef12548c3df0e6d500220413dc27d2e39ee583093adfcb7799be680141738babb31cc7b0669a777a31f5d",
		                 "02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b80054a010000000000002200202b1b5854183c12d3316565972c4668929d314d81c5dcdbb21cb45fe8a9a8114f4a01000000000000220020e9e86e4823faa62e222ebc858a226636856158f07e69898da3b0d1af0ddb3994a00f000000000000220020ce6e751274836ff59622a0d1e07f8831d80bd6730bd48581398bfadd2bb8da9ac0c62d0000000000220020f3394e1e619b0eca1f91be2fb5ab4dfc59ba5b84ebe014ad1d43a564d012994aa28b6a00000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0400483045022100c970799bcb33f43179eb43b3378a0a61991cf2923f69b36ef12548c3df0e6d500220413dc27d2e39ee583093adfcb7799be680141738babb31cc7b0669a777a31f5d01483045022100ad6c71569856b2d7ff42e838b4abe74a713426b37f22fa667a195a4c88908c6902202b37272b02a42dc6d9f4f82cab3eaf84ac882d9ed762859e1e75455c2c22837701475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae3e195220", {

		                  { 0,
		                  "3044022017b558a3cf5f0cb94269e2e927b29ed22bd2416abb8a7ce6de4d1256f359b93602202e9ca2b1a23ea3e69f433c704e327739e219804b8c188b1d52f74fd5a9de954c",
		                  "3045022100af7a8b7c7ff2080c68995254cb66d64d9954edcc5baac3bb4f27ed2d29aaa6120220421c27da7a60574a9263f271e0f3bd34594ec6011095190022b3b54596ea03de",
		                  "02000000000101542562b326c08e3a076d9cfca2be175041366591da334d8d513ff1686fd95a6002000000000100000001a00f0000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0500473044022017b558a3cf5f0cb94269e2e927b29ed22bd2416abb8a7ce6de4d1256f359b93602202e9ca2b1a23ea3e69f433c704e327739e219804b8c188b1d52f74fd5a9de954c83483045022100af7a8b7c7ff2080c68995254cb66d64d9954edcc5baac3bb4f27ed2d29aaa6120220421c27da7a60574a9263f271e0f3bd34594ec6011095190022b3b54596ea03de012004040404040404040404040404040404040404040404040404040404040404048d76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a91418bc1a114ccf9c052d3d23e28d3b0a9d1227434288527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f801b175ac6851b2756800000000" }
		} );

		// commitment tx with three outputs untrimmed (maximum feerate)
		chan.value_to_self_msat = 6993000000; // 7000000000 - 7000000
		chan.feerate_per_kw = 4914;
		chan.holder_dust_limit_satoshis = 546;

		test_commitment!("3045022100b4b16d5f8cc9fc4c1aff48831e832a0d8990e133978a66e302c133550954a44d022073573ce127e2200d316f6b612803a5c0c97b8d20e1e44dbe2ac0dd2fb8c95244",
		                 "3045022100d72638bc6308b88bb6d45861aae83e5b9ff6e10986546e13bce769c70036e2620220320be7c6d66d22f30b9fcd52af66531505b1310ca3b848c19285b38d8a1a8c19",
		                 "02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b8003a00f0000000000002200208c48d15160397c9731df9bc3b236656efb6665fbfe92b4a6878e88a499f741c4c0c62d0000000000160014cc1b07838e387deacd0e5232e1e8b49f4c29e484ae8f6a00000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0400483045022100d72638bc6308b88bb6d45861aae83e5b9ff6e10986546e13bce769c70036e2620220320be7c6d66d22f30b9fcd52af66531505b1310ca3b848c19285b38d8a1a8c1901483045022100b4b16d5f8cc9fc4c1aff48831e832a0d8990e133978a66e302c133550954a44d022073573ce127e2200d316f6b612803a5c0c97b8d20e1e44dbe2ac0dd2fb8c9524401475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae3e195220", {

		                  { 0,
		                  "3045022100f43591c156038ba217756006bb3c55f7d113a325cdd7d9303c82115372858d68022016355b5aadf222bc8d12e426c75f4a03423917b2443a103eb2a498a3a2234374",
		                  "30440220585dee80fafa264beac535c3c0bb5838ac348b156fdc982f86adc08dfc9bfd250220130abb82f9f295cc9ef423dcfef772fde2acd85d9df48cc538981d26a10a9c10",
		                  "02000000000101a9172908eace869cc35128c31fc2ab502f72e4dff31aab23e0244c4b04b11ab00000000000000000000122020000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0500483045022100f43591c156038ba217756006bb3c55f7d113a325cdd7d9303c82115372858d68022016355b5aadf222bc8d12e426c75f4a03423917b2443a103eb2a498a3a2234374014730440220585dee80fafa264beac535c3c0bb5838ac348b156fdc982f86adc08dfc9bfd250220130abb82f9f295cc9ef423dcfef772fde2acd85d9df48cc538981d26a10a9c10012004040404040404040404040404040404040404040404040404040404040404048a76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a91418bc1a114ccf9c052d3d23e28d3b0a9d1227434288527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f801b175ac686800000000" }
		} );

		// commitment tx with two outputs untrimmed (minimum feerate)
		chan.value_to_self_msat = 6993000000; // 7000000000 - 7000000
		chan.feerate_per_kw = 4915;
		chan.holder_dust_limit_satoshis = 546;

		test_commitment!("304402203a286936e74870ca1459c700c71202af0381910a6bfab687ef494ef1bc3e02c902202506c362d0e3bee15e802aa729bf378e051644648253513f1c085b264cc2a720",
		                 "30450221008a953551f4d67cb4df3037207fc082ddaf6be84d417b0bd14c80aab66f1b01a402207508796dc75034b2dee876fe01dc05a08b019f3e5d689ac8842ade2f1befccf5",
		                 "02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b8002c0c62d0000000000160014cc1b07838e387deacd0e5232e1e8b49f4c29e484fa926a00000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e04004830450221008a953551f4d67cb4df3037207fc082ddaf6be84d417b0bd14c80aab66f1b01a402207508796dc75034b2dee876fe01dc05a08b019f3e5d689ac8842ade2f1befccf50147304402203a286936e74870ca1459c700c71202af0381910a6bfab687ef494ef1bc3e02c902202506c362d0e3bee15e802aa729bf378e051644648253513f1c085b264cc2a72001475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae3e195220", {});

		// anchors: commitment tx with two outputs untrimmed (minimum dust limit)
		chan.value_to_self_msat = 6993000000; // 7000000000 - 7000000
		chan.feerate_per_kw = 4894;
		chan.holder_dust_limit_satoshis = 4001;

		test_commitment_with_anchors!("3045022100e784a66b1588575801e237d35e510fd92a81ae3a4a2a1b90c031ad803d07b3f3022021bc5f16501f167607d63b681442da193eb0a76b4b7fd25c2ed4f8b28fd35b95",
		                 "30450221009f16ac85d232e4eddb3fcd750a68ebf0b58e3356eaada45d3513ede7e817bf4c02207c2b043b4e5f971261975406cb955219fa56bffe5d834a833694b5abc1ce4cfd",
		                 "02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b80044a010000000000002200202b1b5854183c12d3316565972c4668929d314d81c5dcdbb21cb45fe8a9a8114f4a01000000000000220020e9e86e4823faa62e222ebc858a226636856158f07e69898da3b0d1af0ddb3994c0c62d0000000000220020f3394e1e619b0eca1f91be2fb5ab4dfc59ba5b84ebe014ad1d43a564d012994ad0886a00000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e04004830450221009f16ac85d232e4eddb3fcd750a68ebf0b58e3356eaada45d3513ede7e817bf4c02207c2b043b4e5f971261975406cb955219fa56bffe5d834a833694b5abc1ce4cfd01483045022100e784a66b1588575801e237d35e510fd92a81ae3a4a2a1b90c031ad803d07b3f3022021bc5f16501f167607d63b681442da193eb0a76b4b7fd25c2ed4f8b28fd35b9501475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae3e195220", {});

		// commitment tx with two outputs untrimmed (maximum feerate)
		chan.value_to_self_msat = 6993000000; // 7000000000 - 7000000
		chan.feerate_per_kw = 9651180;
		chan.holder_dust_limit_satoshis = 546;

		test_commitment!("304402200a8544eba1d216f5c5e530597665fa9bec56943c0f66d98fc3d028df52d84f7002201e45fa5c6bc3a506cc2553e7d1c0043a9811313fc39c954692c0d47cfce2bbd3",
		                 "3045022100e11b638c05c650c2f63a421d36ef8756c5ce82f2184278643520311cdf50aa200220259565fb9c8e4a87ccaf17f27a3b9ca4f20625754a0920d9c6c239d8156a11de",
		                 "02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b800222020000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80ec0c62d0000000000160014cc1b07838e387deacd0e5232e1e8b49f4c29e4840400483045022100e11b638c05c650c2f63a421d36ef8756c5ce82f2184278643520311cdf50aa200220259565fb9c8e4a87ccaf17f27a3b9ca4f20625754a0920d9c6c239d8156a11de0147304402200a8544eba1d216f5c5e530597665fa9bec56943c0f66d98fc3d028df52d84f7002201e45fa5c6bc3a506cc2553e7d1c0043a9811313fc39c954692c0d47cfce2bbd301475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae3e195220", {});

		// commitment tx with one output untrimmed (minimum feerate)
		chan.value_to_self_msat = 6993000000; // 7000000000 - 7000000
		chan.feerate_per_kw = 9651181;

		test_commitment!("304402202ade0142008309eb376736575ad58d03e5b115499709c6db0b46e36ff394b492022037b63d78d66404d6504d4c4ac13be346f3d1802928a6d3ad95a6a944227161a2",
		                 "304402207e8d51e0c570a5868a78414f4e0cbfaed1106b171b9581542c30718ee4eb95ba02203af84194c97adf98898c9afe2f2ed4a7f8dba05a2dfab28ac9d9c604aa49a379",
		                 "02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b8001c0c62d0000000000160014cc1b07838e387deacd0e5232e1e8b49f4c29e484040047304402207e8d51e0c570a5868a78414f4e0cbfaed1106b171b9581542c30718ee4eb95ba02203af84194c97adf98898c9afe2f2ed4a7f8dba05a2dfab28ac9d9c604aa49a3790147304402202ade0142008309eb376736575ad58d03e5b115499709c6db0b46e36ff394b492022037b63d78d66404d6504d4c4ac13be346f3d1802928a6d3ad95a6a944227161a201475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae3e195220", {});

		// anchors: commitment tx with one output untrimmed (minimum dust limit)
		chan.value_to_self_msat = 6993000000; // 7000000000 - 7000000
		chan.feerate_per_kw = 6216010;
		chan.holder_dust_limit_satoshis = 4001;

		test_commitment_with_anchors!("30450221008fd5dbff02e4b59020d4cd23a3c30d3e287065fda75a0a09b402980adf68ccda022001e0b8b620cd915ddff11f1de32addf23d81d51b90e6841b2cb8dcaf3faa5ecf",
		                 "30450221009ad80792e3038fe6968d12ff23e6888a565c3ddd065037f357445f01675d63f3022018384915e5f1f4ae157e15debf4f49b61c8d9d2b073c7d6f97c4a68caa3ed4c1",
		                 "02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b80024a01000000000000220020e9e86e4823faa62e222ebc858a226636856158f07e69898da3b0d1af0ddb3994c0c62d0000000000220020f3394e1e619b0eca1f91be2fb5ab4dfc59ba5b84ebe014ad1d43a564d012994a04004830450221009ad80792e3038fe6968d12ff23e6888a565c3ddd065037f357445f01675d63f3022018384915e5f1f4ae157e15debf4f49b61c8d9d2b073c7d6f97c4a68caa3ed4c1014830450221008fd5dbff02e4b59020d4cd23a3c30d3e287065fda75a0a09b402980adf68ccda022001e0b8b620cd915ddff11f1de32addf23d81d51b90e6841b2cb8dcaf3faa5ecf01475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae3e195220", {});

		// commitment tx with fee greater than funder amount
		chan.value_to_self_msat = 6993000000; // 7000000000 - 7000000
		chan.feerate_per_kw = 9651936;
		chan.holder_dust_limit_satoshis = 546;

		test_commitment!("304402202ade0142008309eb376736575ad58d03e5b115499709c6db0b46e36ff394b492022037b63d78d66404d6504d4c4ac13be346f3d1802928a6d3ad95a6a944227161a2",
		                 "304402207e8d51e0c570a5868a78414f4e0cbfaed1106b171b9581542c30718ee4eb95ba02203af84194c97adf98898c9afe2f2ed4a7f8dba05a2dfab28ac9d9c604aa49a379",
		                 "02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b8001c0c62d0000000000160014cc1b07838e387deacd0e5232e1e8b49f4c29e484040047304402207e8d51e0c570a5868a78414f4e0cbfaed1106b171b9581542c30718ee4eb95ba02203af84194c97adf98898c9afe2f2ed4a7f8dba05a2dfab28ac9d9c604aa49a3790147304402202ade0142008309eb376736575ad58d03e5b115499709c6db0b46e36ff394b492022037b63d78d66404d6504d4c4ac13be346f3d1802928a6d3ad95a6a944227161a201475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae3e195220", {});

		// commitment tx with 3 htlc outputs, 2 offered having the same amount and preimage
		chan.value_to_self_msat = 7_000_000_000 - 2_000_000;
		chan.feerate_per_kw = 253;
		chan.pending_inbound_htlcs.clear();
		chan.pending_inbound_htlcs.push({
			let mut out = InboundHTLCOutput{
				htlc_id: 1,
				amount_msat: 2000000,
				cltv_expiry: 501,
				payment_hash: PaymentHash([0; 32]),
				state: InboundHTLCState::Committed,
			};
			out.payment_hash.0 = Sha256::hash(&hex::decode("0101010101010101010101010101010101010101010101010101010101010101").unwrap()).into_inner();
			out
		});
		chan.pending_outbound_htlcs.clear();
		chan.pending_outbound_htlcs.push({
			let mut out = OutboundHTLCOutput{
				htlc_id: 6,
				amount_msat: 5000000,
				cltv_expiry: 506,
				payment_hash: PaymentHash([0; 32]),
				state: OutboundHTLCState::Committed,
				source: HTLCSource::dummy(),
			};
			out.payment_hash.0 = Sha256::hash(&hex::decode("0505050505050505050505050505050505050505050505050505050505050505").unwrap()).into_inner();
			out
		});
		chan.pending_outbound_htlcs.push({
			let mut out = OutboundHTLCOutput{
				htlc_id: 5,
				amount_msat: 5000000,
				cltv_expiry: 505,
				payment_hash: PaymentHash([0; 32]),
				state: OutboundHTLCState::Committed,
				source: HTLCSource::dummy(),
			};
			out.payment_hash.0 = Sha256::hash(&hex::decode("0505050505050505050505050505050505050505050505050505050505050505").unwrap()).into_inner();
			out
		});

		test_commitment!("30440220048705bec5288d28b3f29344b8d124853b1af423a568664d2c6f02c8ea886525022060f998a461052a2476b912db426ea2a06700953a241135c7957f2e79bc222df9",
		                 "3045022100c4f1d60b6fca9febc8b39de1a31e84c5f7c4b41c97239ef05f4350aa484c6b5e02200c5134ac8b20eb7a29d0dd4a501f6aa8fefb8489171f4cb408bd2a32324ab03f",
		                 "02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b8005d007000000000000220020748eba944fedc8827f6b06bc44678f93c0f9e6078b35c6331ed31e75f8ce0c2d8813000000000000220020305c12e1a0bc21e283c131cea1c66d68857d28b7b2fce0a6fbc40c164852121b8813000000000000220020305c12e1a0bc21e283c131cea1c66d68857d28b7b2fce0a6fbc40c164852121bc0c62d0000000000160014cc1b07838e387deacd0e5232e1e8b49f4c29e484a79f6a00000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0400483045022100c4f1d60b6fca9febc8b39de1a31e84c5f7c4b41c97239ef05f4350aa484c6b5e02200c5134ac8b20eb7a29d0dd4a501f6aa8fefb8489171f4cb408bd2a32324ab03f014730440220048705bec5288d28b3f29344b8d124853b1af423a568664d2c6f02c8ea886525022060f998a461052a2476b912db426ea2a06700953a241135c7957f2e79bc222df901475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae3e195220", {

		                  { 0,
		                  "304502210081cbb94121761d34c189cd4e6a281feea6f585060ad0ba2632e8d6b3c6bb8a6c02201007981bbd16539d63df2805b5568f1f5688cd2a885d04706f50db9b77ba13c6",
		                  "304502210090ed76aeb21b53236a598968abc66e2024691d07b62f53ddbeca8f93144af9c602205f873af5a0c10e62690e9aba09740550f194a9dc455ba4c1c23f6cde7704674c",
		                  "0200000000010189a326e23addc28323dbadcb4e71c2c17088b6e8fa184103e552f44075dddc34000000000000000000011f070000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e050048304502210081cbb94121761d34c189cd4e6a281feea6f585060ad0ba2632e8d6b3c6bb8a6c02201007981bbd16539d63df2805b5568f1f5688cd2a885d04706f50db9b77ba13c60148304502210090ed76aeb21b53236a598968abc66e2024691d07b62f53ddbeca8f93144af9c602205f873af5a0c10e62690e9aba09740550f194a9dc455ba4c1c23f6cde7704674c012001010101010101010101010101010101010101010101010101010101010101018a76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a9144b6b2e5444c2639cc0fb7bcea5afba3f3cdce23988527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f501b175ac686800000000" },
		                  { 1,
		                  "304402201d0f09d2bf7bc245a4f17980e1e9164290df16c70c6a2ff1592f5030d6108581022061e744a7dc151b36bf0aff7a4f1812ba90b8b03633bb979a270d19858fd960c5",
		                  "30450221009aef000d2e843a4202c1b1a2bf554abc9a7902bf49b2cb0759bc507456b7ebad02204e7c3d193ede2fd2b4cd6b39f51a920e581e35575e357e44d7b699c40ce61d39",
		                  "0200000000010189a326e23addc28323dbadcb4e71c2c17088b6e8fa184103e552f44075dddc3401000000000000000001e1120000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e050047304402201d0f09d2bf7bc245a4f17980e1e9164290df16c70c6a2ff1592f5030d6108581022061e744a7dc151b36bf0aff7a4f1812ba90b8b03633bb979a270d19858fd960c5014830450221009aef000d2e843a4202c1b1a2bf554abc9a7902bf49b2cb0759bc507456b7ebad02204e7c3d193ede2fd2b4cd6b39f51a920e581e35575e357e44d7b699c40ce61d3901008576a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a9142002cc93ebefbb1b73f0af055dcc27a0b504ad7688ac6868f9010000" },
		                  { 2,
		                  "30440220010bf035d5823596e50dce2076a4d9f942d8d28031c9c428b901a02b6b8140de02203250e8e4a08bc5b4ecdca4d0eedf98223e02e3ac1c0206b3a7ffdb374aa21e5f",
		                  "30440220073de0067b88e425b3018b30366bfeda0ccb703118ccd3d02ead08c0f53511d002203fac50ac0e4cf8a3af0b4b1b12e801650591f748f8ddf1e089c160f10b69e511",
		                  "0200000000010189a326e23addc28323dbadcb4e71c2c17088b6e8fa184103e552f44075dddc3402000000000000000001e1120000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e05004730440220010bf035d5823596e50dce2076a4d9f942d8d28031c9c428b901a02b6b8140de02203250e8e4a08bc5b4ecdca4d0eedf98223e02e3ac1c0206b3a7ffdb374aa21e5f014730440220073de0067b88e425b3018b30366bfeda0ccb703118ccd3d02ead08c0f53511d002203fac50ac0e4cf8a3af0b4b1b12e801650591f748f8ddf1e089c160f10b69e51101008576a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a9142002cc93ebefbb1b73f0af055dcc27a0b504ad7688ac6868fa010000" }
		} );

		test_commitment_with_anchors!("3045022100c592f6b80d35b4f5d1e3bc9788f51141a0065be6013bad53a1977f7c444651660220278ac06ead9016bfb8dc476f186eabace2b02793b2f308442f5b0d5f24a68948",
		                 "3045022100c37ac4fc8538677631230c4b286f36b6f54c51fb4b34ef0bd0ba219ba47452630220278e09a745454ea380f3694392ed113762c68dd209b48360f547541088be9e45",
		                 "02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b80074a010000000000002200202b1b5854183c12d3316565972c4668929d314d81c5dcdbb21cb45fe8a9a8114f4a01000000000000220020e9e86e4823faa62e222ebc858a226636856158f07e69898da3b0d1af0ddb3994d007000000000000220020fe0598d74fee2205cc3672e6e6647706b4f3099713b4661b62482c3addd04a5e881300000000000022002018e40f9072c44350f134bdc887bab4d9bdfc8aa468a25616c80e21757ba5dac7881300000000000022002018e40f9072c44350f134bdc887bab4d9bdfc8aa468a25616c80e21757ba5dac7c0c62d0000000000220020f3394e1e619b0eca1f91be2fb5ab4dfc59ba5b84ebe014ad1d43a564d012994aae9c6a00000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0400483045022100c37ac4fc8538677631230c4b286f36b6f54c51fb4b34ef0bd0ba219ba47452630220278e09a745454ea380f3694392ed113762c68dd209b48360f547541088be9e4501483045022100c592f6b80d35b4f5d1e3bc9788f51141a0065be6013bad53a1977f7c444651660220278ac06ead9016bfb8dc476f186eabace2b02793b2f308442f5b0d5f24a6894801475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae3e195220", {

		                  { 0,
		                  "3045022100de8a0649d54fd2e4fc04502c77df9b65da839bbd01854f818f129338b99564b2022009528dbb12c00e874cb2149b1dccc600c69ea5e4042ebf584984fcb029c2d1ec",
		                  "304402203e7c2622fa3ca29355d37a0ea991bfd7cdb54e6122a1d98d3229d092131f55cd022055263f7f8f32f4cd2f86da63ca106bd7badf0b19ee9833d80cd3b9216eeafd74",
		                  "02000000000101aa443fb63abc1e8c754f98a7b96c27cb02b21d891d1242a16b630dc32c2afe2902000000000100000001d0070000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0500483045022100de8a0649d54fd2e4fc04502c77df9b65da839bbd01854f818f129338b99564b2022009528dbb12c00e874cb2149b1dccc600c69ea5e4042ebf584984fcb029c2d1ec8347304402203e7c2622fa3ca29355d37a0ea991bfd7cdb54e6122a1d98d3229d092131f55cd022055263f7f8f32f4cd2f86da63ca106bd7badf0b19ee9833d80cd3b9216eeafd74012001010101010101010101010101010101010101010101010101010101010101018d76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a9144b6b2e5444c2639cc0fb7bcea5afba3f3cdce23988527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f501b175ac6851b2756800000000" },
		                  { 1,
		                  "3045022100de6eee8474376ea316d007b33103b4543a46bdf6fda5cbd5902b28a5bc14584f022002989e7b4f7813b77acbe4babcf96d7ffbbe0bf14cba24672364f8e591479edb",
		                  "3045022100c10688346a9d84647bde7027da07f0d79c6d4129307e4c6c9aea7bdbf25ac3350220269104209793c32c47491698c4e46ebea9c3293a1e4403f9abda39f79698f6b5",
		                  "02000000000101aa443fb63abc1e8c754f98a7b96c27cb02b21d891d1242a16b630dc32c2afe290300000000010000000188130000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0500483045022100de6eee8474376ea316d007b33103b4543a46bdf6fda5cbd5902b28a5bc14584f022002989e7b4f7813b77acbe4babcf96d7ffbbe0bf14cba24672364f8e591479edb83483045022100c10688346a9d84647bde7027da07f0d79c6d4129307e4c6c9aea7bdbf25ac3350220269104209793c32c47491698c4e46ebea9c3293a1e4403f9abda39f79698f6b501008876a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a9142002cc93ebefbb1b73f0af055dcc27a0b504ad7688ac6851b27568f9010000" },
		                  { 2,
		                  "3045022100fe87da8124ceecbcabb9d599c5339f40277c7c7406514fafbccbf180c7c09cf40220429c7fb6d0fd3705e931ab1219ab0432af38ae4d676008cc1964fbeb8cd35d2e",
		                  "3044022040ac769a851da31d8e4863e5f94719204f716c82a1ce6d6c52193d9a33b84bce022035df97b078ce80f20dca2109e4c6075af0b50148811452e7290e68b2680fced4",
		                  "02000000000101aa443fb63abc1e8c754f98a7b96c27cb02b21d891d1242a16b630dc32c2afe290400000000010000000188130000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0500483045022100fe87da8124ceecbcabb9d599c5339f40277c7c7406514fafbccbf180c7c09cf40220429c7fb6d0fd3705e931ab1219ab0432af38ae4d676008cc1964fbeb8cd35d2e83473044022040ac769a851da31d8e4863e5f94719204f716c82a1ce6d6c52193d9a33b84bce022035df97b078ce80f20dca2109e4c6075af0b50148811452e7290e68b2680fced401008876a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a9142002cc93ebefbb1b73f0af055dcc27a0b504ad7688ac6851b27568fa010000" }
		} );
	}

	#[test]
	fn test_per_commitment_secret_gen() {
		// Test vectors from BOLT 3 Appendix D:

		let mut seed = [0; 32];
		seed[0..32].clone_from_slice(&hex::decode("0000000000000000000000000000000000000000000000000000000000000000").unwrap());
		assert_eq!(chan_utils::build_commitment_secret(&seed, 281474976710655),
		           hex::decode("02a40c85b6f28da08dfdbe0926c53fab2de6d28c10301f8f7c4073d5e42e3148").unwrap()[..]);

		seed[0..32].clone_from_slice(&hex::decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF").unwrap());
		assert_eq!(chan_utils::build_commitment_secret(&seed, 281474976710655),
		           hex::decode("7cc854b54e3e0dcdb010d7a3fee464a9687be6e8db3be6854c475621e007a5dc").unwrap()[..]);

		assert_eq!(chan_utils::build_commitment_secret(&seed, 0xaaaaaaaaaaa),
		           hex::decode("56f4008fb007ca9acf0e15b054d5c9fd12ee06cea347914ddbaed70d1c13a528").unwrap()[..]);

		assert_eq!(chan_utils::build_commitment_secret(&seed, 0x555555555555),
		           hex::decode("9015daaeb06dba4ccc05b91b2f73bd54405f2be9f217fbacd3c5ac2e62327d31").unwrap()[..]);

		seed[0..32].clone_from_slice(&hex::decode("0101010101010101010101010101010101010101010101010101010101010101").unwrap());
		assert_eq!(chan_utils::build_commitment_secret(&seed, 1),
		           hex::decode("915c75942a26bb3a433a8ce2cb0427c29ec6c1775cfc78328b57f6ba7bfeaa9c").unwrap()[..]);
	}

	#[test]
	fn test_key_derivation() {
		// Test vectors from BOLT 3 Appendix E:
		let secp_ctx = Secp256k1::new();

		let base_secret = SecretKey::from_slice(&hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap()[..]).unwrap();
		let per_commitment_secret = SecretKey::from_slice(&hex::decode("1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100").unwrap()[..]).unwrap();

		let base_point = PublicKey::from_secret_key(&secp_ctx, &base_secret);
		assert_eq!(base_point.serialize()[..], hex::decode("036d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a95b216691468e2").unwrap()[..]);

		let per_commitment_point = PublicKey::from_secret_key(&secp_ctx, &per_commitment_secret);
		assert_eq!(per_commitment_point.serialize()[..], hex::decode("025f7117a78150fe2ef97db7cfc83bd57b2e2c0d0dd25eaf467a4a1c2a45ce1486").unwrap()[..]);

		assert_eq!(chan_utils::derive_public_key(&secp_ctx, &per_commitment_point, &base_point).serialize()[..],
				hex::decode("0235f2dbfaa89b57ec7b055afe29849ef7ddfeb1cefdb9ebdc43f5494984db29e5").unwrap()[..]);

		assert_eq!(chan_utils::derive_private_key(&secp_ctx, &per_commitment_point, &base_secret),
				SecretKey::from_slice(&hex::decode("cbced912d3b21bf196a766651e436aff192362621ce317704ea2f75d87e7be0f").unwrap()[..]).unwrap());

		assert_eq!(chan_utils::derive_public_revocation_key(&secp_ctx, &per_commitment_point, &base_point).serialize()[..],
				hex::decode("02916e326636d19c33f13e8c0c3a03dd157f332f3e99c317c141dd865eb01f8ff0").unwrap()[..]);

		assert_eq!(chan_utils::derive_private_revocation_key(&secp_ctx, &per_commitment_secret, &base_secret),
				SecretKey::from_slice(&hex::decode("d09ffff62ddb2297ab000cc85bcb4283fdeb6aa052affbc9dddcf33b61078110").unwrap()[..]).unwrap());
	}

	#[test]
	fn test_zero_conf_channel_type_support() {
		let feeest = LowerBoundedFeeEstimator::new(&TestFeeEstimator{fee_est: 15000});
		let secp_ctx = Secp256k1::new();
		let seed = [42; 32];
		let network = Network::Testnet;
		let keys_provider = test_utils::TestKeysInterface::new(&seed, network);
		let logger = test_utils::TestLogger::new();

		let node_b_node_id = PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[42; 32]).unwrap());
		let config = UserConfig::default();
		let node_a_chan = Channel::<EnforcingSigner>::new_outbound(&feeest, &&keys_provider, &&keys_provider,
			node_b_node_id, &channelmanager::provided_init_features(&config), 10000000, 100000, 42, &config, 0, 42).unwrap();

		let mut channel_type_features = ChannelTypeFeatures::only_static_remote_key();
		channel_type_features.set_zero_conf_required();

		let mut open_channel_msg = node_a_chan.get_open_channel(genesis_block(network).header.block_hash());
		open_channel_msg.channel_type = Some(channel_type_features);
		let node_b_node_id = PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[7; 32]).unwrap());
		let res = Channel::<EnforcingSigner>::new_from_req(&feeest, &&keys_provider, &&keys_provider,
			node_b_node_id, &channelmanager::provided_channel_type_features(&config),
			&channelmanager::provided_init_features(&config), &open_channel_msg, 7, &config, 0, &&logger, 42);
		assert!(res.is_ok());
	}

	#[cfg(anchors)]
	#[test]
	fn test_supports_anchors_zero_htlc_tx_fee() {
		// Tests that if both sides support and negotiate `anchors_zero_fee_htlc_tx`, it is the
		// resulting `channel_type`.
		let secp_ctx = Secp256k1::new();
		let fee_estimator = LowerBoundedFeeEstimator::new(&TestFeeEstimator{fee_est: 15000});
		let network = Network::Testnet;
		let keys_provider = test_utils::TestKeysInterface::new(&[42; 32], network);
		let logger = test_utils::TestLogger::new();

		let node_id_a = PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[1; 32]).unwrap());
		let node_id_b = PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[2; 32]).unwrap());

		let mut config = UserConfig::default();
		config.channel_handshake_config.negotiate_anchors_zero_fee_htlc_tx = true;

		// It is not enough for just the initiator to signal `option_anchors_zero_fee_htlc_tx`, both
		// need to signal it.
		let channel_a = Channel::<EnforcingSigner>::new_outbound(
			&fee_estimator, &&keys_provider, &&keys_provider, node_id_b,
			&channelmanager::provided_init_features(&UserConfig::default()), 10000000, 100000, 42,
			&config, 0, 42
		).unwrap();
		assert!(!channel_a.channel_type.supports_anchors_zero_fee_htlc_tx());

		let mut expected_channel_type = ChannelTypeFeatures::empty();
		expected_channel_type.set_static_remote_key_required();
		expected_channel_type.set_anchors_zero_fee_htlc_tx_required();

		let channel_a = Channel::<EnforcingSigner>::new_outbound(
			&fee_estimator, &&keys_provider, &&keys_provider, node_id_b,
			&channelmanager::provided_init_features(&config), 10000000, 100000, 42, &config, 0, 42
		).unwrap();

		let open_channel_msg = channel_a.get_open_channel(genesis_block(network).header.block_hash());
		let channel_b = Channel::<EnforcingSigner>::new_from_req(
			&fee_estimator, &&keys_provider, &&keys_provider, node_id_a,
			&channelmanager::provided_channel_type_features(&config), &channelmanager::provided_init_features(&config),
			&open_channel_msg, 7, &config, 0, &&logger, 42
		).unwrap();

		assert_eq!(channel_a.channel_type, expected_channel_type);
		assert_eq!(channel_b.channel_type, expected_channel_type);
	}

	#[cfg(anchors)]
	#[test]
	fn test_rejects_implicit_simple_anchors() {
		// Tests that if `option_anchors` is being negotiated implicitly through the intersection of
		// each side's `InitFeatures`, it is rejected.
		let secp_ctx = Secp256k1::new();
		let fee_estimator = LowerBoundedFeeEstimator::new(&TestFeeEstimator{fee_est: 15000});
		let network = Network::Testnet;
		let keys_provider = test_utils::TestKeysInterface::new(&[42; 32], network);
		let logger = test_utils::TestLogger::new();

		let node_id_a = PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[1; 32]).unwrap());
		let node_id_b = PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[2; 32]).unwrap());

		let config = UserConfig::default();

		// See feature bit assignments: https://github.com/lightning/bolts/blob/master/09-features.md
		let static_remote_key_required: u64 = 1 << 12;
		let simple_anchors_required: u64 = 1 << 20;
		let raw_init_features = static_remote_key_required | simple_anchors_required;
		let init_features_with_simple_anchors = InitFeatures::from_le_bytes(raw_init_features.to_le_bytes().to_vec());

		let channel_a = Channel::<EnforcingSigner>::new_outbound(
			&fee_estimator, &&keys_provider, &&keys_provider, node_id_b,
			&channelmanager::provided_init_features(&config), 10000000, 100000, 42, &config, 0, 42
		).unwrap();

		// Set `channel_type` to `None` to force the implicit feature negotiation.
		let mut open_channel_msg = channel_a.get_open_channel(genesis_block(network).header.block_hash());
		open_channel_msg.channel_type = None;

		// Since A supports both `static_remote_key` and `option_anchors`, but B only accepts
		// `static_remote_key`, it will fail the channel.
		let channel_b = Channel::<EnforcingSigner>::new_from_req(
			&fee_estimator, &&keys_provider, &&keys_provider, node_id_a,
			&channelmanager::provided_channel_type_features(&config), &init_features_with_simple_anchors,
			&open_channel_msg, 7, &config, 0, &&logger, 42
		);
		assert!(channel_b.is_err());
	}

	#[cfg(anchors)]
	#[test]
	fn test_rejects_simple_anchors_channel_type() {
		// Tests that if `option_anchors` is being negotiated through the `channel_type` feature,
		// it is rejected.
		let secp_ctx = Secp256k1::new();
		let fee_estimator = LowerBoundedFeeEstimator::new(&TestFeeEstimator{fee_est: 15000});
		let network = Network::Testnet;
		let keys_provider = test_utils::TestKeysInterface::new(&[42; 32], network);
		let logger = test_utils::TestLogger::new();

		let node_id_a = PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[1; 32]).unwrap());
		let node_id_b = PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[2; 32]).unwrap());

		let config = UserConfig::default();

		// See feature bit assignments: https://github.com/lightning/bolts/blob/master/09-features.md
		let static_remote_key_required: u64 = 1 << 12;
		let simple_anchors_required: u64 = 1 << 20;
		let simple_anchors_raw_features = static_remote_key_required | simple_anchors_required;
		let simple_anchors_init = InitFeatures::from_le_bytes(simple_anchors_raw_features.to_le_bytes().to_vec());
		let simple_anchors_channel_type = ChannelTypeFeatures::from_le_bytes(simple_anchors_raw_features.to_le_bytes().to_vec());
		assert!(simple_anchors_init.requires_unknown_bits());
		assert!(simple_anchors_channel_type.requires_unknown_bits());

		// First, we'll try to open a channel between A and B where A requests a channel type for
		// the original `option_anchors` feature (non zero fee htlc tx). This should be rejected by
		// B as it's not supported by LDK.
		let channel_a = Channel::<EnforcingSigner>::new_outbound(
			&fee_estimator, &&keys_provider, &&keys_provider, node_id_b,
			&channelmanager::provided_init_features(&config), 10000000, 100000, 42, &config, 0, 42
		).unwrap();

		let mut open_channel_msg = channel_a.get_open_channel(genesis_block(network).header.block_hash());
		open_channel_msg.channel_type = Some(simple_anchors_channel_type.clone());

		let res = Channel::<EnforcingSigner>::new_from_req(
			&fee_estimator, &&keys_provider, &&keys_provider, node_id_a,
			&channelmanager::provided_channel_type_features(&config), &simple_anchors_init,
			&open_channel_msg, 7, &config, 0, &&logger, 42
		);
		assert!(res.is_err());

		// Then, we'll try to open another channel where A requests a channel type for
		// `anchors_zero_fee_htlc_tx`. B is malicious and tries to downgrade the channel type to the
		// original `option_anchors` feature, which should be rejected by A as it's not supported by
		// LDK.
		let mut channel_a = Channel::<EnforcingSigner>::new_outbound(
			&fee_estimator, &&keys_provider, &&keys_provider, node_id_b, &simple_anchors_init,
			10000000, 100000, 42, &config, 0, 42
		).unwrap();

		let open_channel_msg = channel_a.get_open_channel(genesis_block(network).header.block_hash());

		let channel_b = Channel::<EnforcingSigner>::new_from_req(
			&fee_estimator, &&keys_provider, &&keys_provider, node_id_a,
			&channelmanager::provided_channel_type_features(&config), &channelmanager::provided_init_features(&config),
			&open_channel_msg, 7, &config, 0, &&logger, 42
		).unwrap();

		let mut accept_channel_msg = channel_b.get_accept_channel_message();
		accept_channel_msg.channel_type = Some(simple_anchors_channel_type.clone());

		let res = channel_a.accept_channel(
			&accept_channel_msg, &config.channel_handshake_limits, &simple_anchors_init
		);
		assert!(res.is_err());
	}
}
