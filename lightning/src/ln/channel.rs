use bitcoin::blockdata::block::BlockHeader;
use bitcoin::blockdata::script::{Script,Builder};
use bitcoin::blockdata::transaction::{TxIn, TxOut, Transaction, SigHashType};
use bitcoin::blockdata::opcodes;
use bitcoin::util::hash::BitcoinHash;
use bitcoin::util::bip143;
use bitcoin::consensus::encode;

use bitcoin::hashes::{Hash, HashEngine};
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hash_types::{Txid, BlockHash, WPubkeyHash};

use bitcoin::secp256k1::key::{PublicKey,SecretKey};
use bitcoin::secp256k1::{Secp256k1,Signature};
use bitcoin::secp256k1;

use ln::features::{ChannelFeatures, InitFeatures};
use ln::msgs;
use ln::msgs::{DecodeError, OptionalField, DataLossProtect};
use ln::channelmonitor::{ChannelMonitor, ChannelMonitorUpdate, ChannelMonitorUpdateStep, HTLC_FAIL_BACK_BUFFER};
use ln::channelmanager::{PendingHTLCStatus, HTLCSource, HTLCFailReason, HTLCFailureMsg, PendingHTLCInfo, RAACommitmentOrder, PaymentPreimage, PaymentHash, BREAKDOWN_TIMEOUT, MAX_LOCAL_BREAKDOWN_TIMEOUT};
use ln::chan_utils::{CounterpartyCommitmentSecrets, LocalCommitmentTransaction, TxCreationKeys, HTLCOutputInCommitment, HTLC_SUCCESS_TX_WEIGHT, HTLC_TIMEOUT_TX_WEIGHT, make_funding_redeemscript, ChannelPublicKeys};
use ln::chan_utils;
use chain::chaininterface::{FeeEstimator,ConfirmationTarget};
use chain::transaction::OutPoint;
use chain::keysinterface::{ChannelKeys, KeysInterface};
use util::transaction_utils;
use util::ser::{Readable, Writeable, Writer};
use util::logger::Logger;
use util::errors::APIError;
use util::config::{UserConfig,ChannelConfig};

use std;
use std::default::Default;
use std::{cmp,mem,fmt};
use std::ops::Deref;

#[cfg(test)]
pub struct ChannelValueStat {
	pub value_to_self_msat: u64,
	pub channel_value_msat: u64,
	pub channel_reserve_msat: u64,
	pub pending_outbound_htlcs_amount_msat: u64,
	pub pending_inbound_htlcs_amount_msat: u64,
	pub holding_cell_outbound_amount_msat: u64,
	pub their_max_htlc_value_in_flight_msat: u64, // outgoing
}

enum InboundHTLCRemovalReason {
	FailRelay(msgs::OnionErrorPacket),
	FailMalformed(([u8; 32], u16)),
	Fulfill(PaymentPreimage),
}

enum InboundHTLCState {
	/// Added by remote, to be included in next local commitment tx.
	RemoteAnnounced(PendingHTLCStatus),
	/// Included in a received commitment_signed message (implying we've revoke_and_ack'ed it), but
	/// the remote side hasn't yet revoked their previous state, which we need them to do before we
	/// accept this HTLC. Implies AwaitingRemoteRevoke.
	/// We also have not yet included this HTLC in a commitment_signed message, and are waiting on
	/// a remote revoke_and_ack on a previous state before we can do so.
	AwaitingRemoteRevokeToAnnounce(PendingHTLCStatus),
	/// Included in a received commitment_signed message (implying we've revoke_and_ack'ed it), but
	/// the remote side hasn't yet revoked their previous state, which we need them to do before we
	/// accept this HTLC. Implies AwaitingRemoteRevoke.
	/// We have included this HTLC in our latest commitment_signed and are now just waiting on a
	/// revoke_and_ack.
	AwaitingAnnouncedRemoteRevoke(PendingHTLCStatus),
	Committed,
	/// Removed by us and a new commitment_signed was sent (if we were AwaitingRemoteRevoke when we
	/// created it we would have put it in the holding cell instead). When they next revoke_and_ack
	/// we'll drop it.
	/// Note that we have to keep an eye on the HTLC until we've received a broadcastable
	/// commitment transaction without it as otherwise we'll have to force-close the channel to
	/// claim it before the timeout (obviously doesn't apply to revoked HTLCs that we can't claim
	/// anyway). That said, ChannelMonitor does this for us (see
	/// ChannelMonitor::would_broadcast_at_height) so we actually remove the HTLC from our own
	/// local state before then, once we're sure that the next commitment_signed and
	/// ChannelMonitor::provide_latest_local_commitment_tx_info will not include this HTLC.
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
	RemoteRemoved(Option<HTLCFailReason>),
	/// Remote removed this and sent a commitment_signed (implying we've revoke_and_ack'ed it), but
	/// the remote side hasn't yet revoked their previous state, which we need them to do before we
	/// can do any backwards failing. Implies AwaitingRemoteRevoke.
	/// We also have not yet removed this HTLC in a commitment_signed message, and are waiting on a
	/// remote revoke_and_ack on a previous state before we can do so.
	AwaitingRemoteRevokeToRemove(Option<HTLCFailReason>),
	/// Remote removed this and sent a commitment_signed (implying we've revoke_and_ack'ed it), but
	/// the remote side hasn't yet revoked their previous state, which we need them to do before we
	/// can do any backwards failing. Implies AwaitingRemoteRevoke.
	/// We have removed this HTLC in our latest commitment_signed and are now just waiting on a
	/// revoke_and_ack to drop completely.
	AwaitingRemovedRemoteRevoke(Option<HTLCFailReason>),
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
/// TheirFundingLocked and OurFundingLocked then get set on FundingSent, and when both are set we
/// move on to ChannelFunded.
/// Note that PeerDisconnected can be set on both ChannelFunded and FundingSent.
/// ChannelFunded can then get all remaining flags set on it, until we finish shutdown, then we
/// move on to ShutdownComplete, at which point most calls into this channel are disallowed.
enum ChannelState {
	/// Implies we have (or are prepared to) send our open_channel/accept_channel message
	OurInitSent = (1 << 0),
	/// Implies we have received their open_channel/accept_channel message
	TheirInitSent = (1 << 1),
	/// We have sent funding_created and are awaiting a funding_signed to advance to FundingSent.
	/// Note that this is nonsense for an inbound channel as we immediately generate funding_signed
	/// upon receipt of funding_created, so simply skip this state.
	FundingCreated = 4,
	/// Set when we have received/sent funding_created and funding_signed and are thus now waiting
	/// on the funding transaction to confirm. The FundingLocked flags are set to indicate when we
	/// and our counterparty consider the funding transaction confirmed.
	FundingSent = 8,
	/// Flag which can be set on FundingSent to indicate they sent us a funding_locked message.
	/// Once both TheirFundingLocked and OurFundingLocked are set, state moves on to ChannelFunded.
	TheirFundingLocked = (1 << 4),
	/// Flag which can be set on FundingSent to indicate we sent them a funding_locked message.
	/// Once both TheirFundingLocked and OurFundingLocked are set, state moves on to ChannelFunded.
	OurFundingLocked = (1 << 5),
	ChannelFunded = 64,
	/// Flag which is set on ChannelFunded and FundingSent indicating remote side is considered
	/// "disconnected" and no updates are allowed until after we've done a channel_reestablish
	/// dance.
	PeerDisconnected = (1 << 7),
	/// Flag which is set on ChannelFunded, FundingCreated, and FundingSent indicating the user has
	/// told us they failed to update our ChannelMonitor somewhere and we should pause sending any
	/// outbound messages until they've managed to do so.
	MonitorUpdateFailed = (1 << 8),
	/// Flag which implies that we have sent a commitment_signed but are awaiting the responding
	/// revoke_and_ack message. During this time period, we can't generate new commitment_signed
	/// messages as then we will be unable to determine which HTLCs they included in their
	/// revoke_and_ack implicit ACK, so instead we have to hold them away temporarily to be sent
	/// later.
	/// Flag is set on ChannelFunded.
	AwaitingRemoteRevoke = (1 << 9),
	/// Flag which is set on ChannelFunded or FundingSent after receiving a shutdown message from
	/// the remote end. If set, they may not add any new HTLCs to the channel, and we are expected
	/// to respond with our own shutdown message when possible.
	RemoteShutdownSent = (1 << 10),
	/// Flag which is set on ChannelFunded or FundingSent after sending a shutdown message. At this
	/// point, we may not add any new HTLCs to the channel.
	/// TODO: Investigate some kind of timeout mechanism by which point the remote end must provide
	/// us their shutdown.
	LocalShutdownSent = (1 << 11),
	/// We've successfully negotiated a closing_signed dance. At this point ChannelManager is about
	/// to drop us, but we store this anyway.
	ShutdownComplete = 4096,
}
const BOTH_SIDES_SHUTDOWN_MASK: u32 = ChannelState::LocalShutdownSent as u32 | ChannelState::RemoteShutdownSent as u32;
const MULTI_STATE_FLAGS: u32 = BOTH_SIDES_SHUTDOWN_MASK | ChannelState::PeerDisconnected as u32 | ChannelState::MonitorUpdateFailed as u32;

const INITIAL_COMMITMENT_NUMBER: u64 = (1 << 48) - 1;

/// Liveness is called to fluctuate given peer disconnecton/monitor failures/closing.
/// If channel is public, network should have a liveness view announced by us on a
/// best-effort, which means we may filter out some status transitions to avoid spam.
/// See further timer_chan_freshness_every_min.
#[derive(PartialEq)]
enum UpdateStatus {
	/// Status has been gossiped.
	Fresh,
	/// Status has been changed.
	DisabledMarked,
	/// Status has been marked to be gossiped at next flush
	DisabledStaged,
}

// TODO: We should refactor this to be an Inbound/OutboundChannel until initial setup handshaking
// has been completed, and then turn into a Channel to get compiler-time enforcement of things like
// calling channel_id() before we're set up or things like get_outbound_funding_signed on an
// inbound channel.
pub(super) struct Channel<ChanSigner: ChannelKeys> {
	config: ChannelConfig,

	user_id: u64,

	channel_id: [u8; 32],
	channel_state: u32,
	channel_outbound: bool,
	secp_ctx: Secp256k1<secp256k1::All>,
	channel_value_satoshis: u64,

	latest_monitor_update_id: u64,

	#[cfg(not(test))]
	local_keys: ChanSigner,
	#[cfg(test)]
	pub(super) local_keys: ChanSigner,
	shutdown_pubkey: PublicKey,
	destination_script: Script,

	// Our commitment numbers start at 2^48-1 and count down, whereas the ones used in transaction
	// generation start at 0 and count up...this simplifies some parts of implementation at the
	// cost of others, but should really just be changed.

	cur_local_commitment_transaction_number: u64,
	cur_remote_commitment_transaction_number: u64,
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

	monitor_pending_funding_locked: bool,
	monitor_pending_revoke_and_ack: bool,
	monitor_pending_commitment_signed: bool,
	monitor_pending_forwards: Vec<(PendingHTLCInfo, u64)>,
	monitor_pending_failures: Vec<(HTLCSource, PaymentHash, HTLCFailReason)>,

	// pending_update_fee is filled when sending and receiving update_fee
	// For outbound channel, feerate_per_kw is updated with the value from
	// pending_update_fee when revoke_and_ack is received
	//
	// For inbound channel, feerate_per_kw is updated when it receives
	// commitment_signed and revoke_and_ack is generated
	// The pending value is kept when another pair of update_fee and commitment_signed
	// is received during AwaitingRemoteRevoke and relieved when the expected
	// revoke_and_ack is received and new commitment_signed is generated to be
	// sent to the funder. Otherwise, the pending value is removed when receiving
	// commitment_signed.
	pending_update_fee: Option<u64>,
	// update_fee() during ChannelState::AwaitingRemoteRevoke is hold in
	// holdina_cell_update_fee then moved to pending_udpate_fee when revoke_and_ack
	// is received. holding_cell_update_fee is updated when there are additional
	// update_fee() during ChannelState::AwaitingRemoteRevoke.
	holding_cell_update_fee: Option<u64>,
	next_local_htlc_id: u64,
	next_remote_htlc_id: u64,
	update_time_counter: u32,
	feerate_per_kw: u64,

	#[cfg(debug_assertions)]
	/// Max to_local and to_remote outputs in a locally-generated commitment transaction
	max_commitment_tx_output_local: ::std::sync::Mutex<(u64, u64)>,
	#[cfg(debug_assertions)]
	/// Max to_local and to_remote outputs in a remote-generated commitment transaction
	max_commitment_tx_output_remote: ::std::sync::Mutex<(u64, u64)>,

	last_sent_closing_fee: Option<(u64, u64, Signature)>, // (feerate, fee, our_sig)

	funding_txo: Option<OutPoint>,

	/// The hash of the block in which the funding transaction reached our CONF_TARGET. We use this
	/// to detect unconfirmation after a serialize-unserialize roundtrip where we may not see a full
	/// series of block_connected/block_disconnected calls. Obviously this is not a guarantee as we
	/// could miss the funding_tx_confirmed_in block as well, but it serves as a useful fallback.
	funding_tx_confirmed_in: Option<BlockHash>,
	short_channel_id: Option<u64>,
	/// Used to deduplicate block_connected callbacks, also used to verify consistency during
	/// ChannelManager deserialization (hence pub(super))
	pub(super) last_block_connected: BlockHash,
	funding_tx_confirmations: u64,

	their_dust_limit_satoshis: u64,
	#[cfg(test)]
	pub(super) our_dust_limit_satoshis: u64,
	#[cfg(not(test))]
	our_dust_limit_satoshis: u64,
	#[cfg(test)]
	pub(super) their_max_htlc_value_in_flight_msat: u64,
	#[cfg(not(test))]
	their_max_htlc_value_in_flight_msat: u64,
	//get_our_max_htlc_value_in_flight_msat(): u64,
	/// minimum channel reserve for self to maintain - set by them.
	local_channel_reserve_satoshis: u64,
	// get_remote_channel_reserve_satoshis(channel_value_sats: u64): u64
	their_htlc_minimum_msat: u64,
	our_htlc_minimum_msat: u64,
	their_to_self_delay: u16,
	our_to_self_delay: u16,
	#[cfg(test)]
	pub their_max_accepted_htlcs: u16,
	#[cfg(not(test))]
	their_max_accepted_htlcs: u16,
	//implied by OUR_MAX_HTLCS: our_max_accepted_htlcs: u16,
	minimum_depth: u32,

	their_pubkeys: Option<ChannelPublicKeys>,

	their_cur_commitment_point: Option<PublicKey>,

	their_prev_commitment_point: Option<PublicKey>,
	their_node_id: PublicKey,

	their_shutdown_scriptpubkey: Option<Script>,

	/// Used exclusively to broadcast the latest local state, mostly a historical quirk that this
	/// is here:
	channel_monitor: Option<ChannelMonitor<ChanSigner>>,
	commitment_secrets: CounterpartyCommitmentSecrets,

	network_sync: UpdateStatus,
}

pub const OUR_MAX_HTLCS: u16 = 50; //TODO
/// Confirmation count threshold at which we close a channel. Ideally we'd keep the channel around
/// on ice until the funding transaction gets more confirmations, but the LN protocol doesn't
/// really allow for this, so instead we're stuck closing it out at that point.
const UNCONF_THRESHOLD: u32 = 6;
const SPENDING_INPUT_FOR_A_OUTPUT_WEIGHT: u64 = 79; // prevout: 36, nSequence: 4, script len: 1, witness lengths: (3+1)/4, sig: 73/4, if-selector: 1, redeemScript: (6 ops + 2*33 pubkeys + 1*2 delay)/4
const B_OUTPUT_PLUS_SPENDING_INPUT_WEIGHT: u64 = 104; // prevout: 40, nSequence: 4, script len: 1, witness lengths: 3/4, sig: 73/4, pubkey: 33/4, output: 31 (TODO: Wrong? Useless?)

#[cfg(not(test))]
const COMMITMENT_TX_BASE_WEIGHT: u64 = 724;
#[cfg(test)]
pub const COMMITMENT_TX_BASE_WEIGHT: u64 = 724;
#[cfg(not(test))]
const COMMITMENT_TX_WEIGHT_PER_HTLC: u64 = 172;
#[cfg(test)]
pub const COMMITMENT_TX_WEIGHT_PER_HTLC: u64 = 172;

/// Maximmum `funding_satoshis` value, according to the BOLT #2 specification
/// it's 2^24.
pub const MAX_FUNDING_SATOSHIS: u64 = 1 << 24;

/// Used to return a simple Error back to ChannelManager. Will get converted to a
/// msgs::ErrorAction::SendErrorMessage or msgs::ErrorAction::IgnoreError as appropriate with our
/// channel_id in ChannelManager.
pub(super) enum ChannelError {
	Ignore(&'static str),
	Close(&'static str),
	CloseDelayBroadcast(&'static str),
}

impl fmt::Debug for ChannelError {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self {
			&ChannelError::Ignore(e) => write!(f, "Ignore : {}", e),
			&ChannelError::Close(e) => write!(f, "Close : {}", e),
			&ChannelError::CloseDelayBroadcast(e) => write!(f, "CloseDelayBroadcast : {}", e)
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

impl<ChanSigner: ChannelKeys> Channel<ChanSigner> {
	// Convert constants + channel value to limits:
	fn get_our_max_htlc_value_in_flight_msat(channel_value_satoshis: u64) -> u64 {
		channel_value_satoshis * 1000 / 10 //TODO
	}

	/// Returns a minimum channel reserve value the remote needs to maintain,
	/// required by us.
	///
	/// Guaranteed to return a value no larger than channel_value_satoshis
	pub(crate) fn get_remote_channel_reserve_satoshis(channel_value_satoshis: u64) -> u64 {
		let (q, _) = channel_value_satoshis.overflowing_div(100);
		cmp::min(channel_value_satoshis, cmp::max(q, 1000)) //TODO
	}

	fn derive_our_dust_limit_satoshis(at_open_background_feerate: u64) -> u64 {
		cmp::max(at_open_background_feerate * B_OUTPUT_PLUS_SPENDING_INPUT_WEIGHT / 1000, 546) //TODO
	}

	// Constructors:
	pub fn new_outbound<K: Deref, F: Deref>(fee_estimator: &F, keys_provider: &K, their_node_id: PublicKey, channel_value_satoshis: u64, push_msat: u64, user_id: u64, config: &UserConfig) -> Result<Channel<ChanSigner>, APIError>
	where K::Target: KeysInterface<ChanKeySigner = ChanSigner>,
	      F::Target: FeeEstimator,
	{
		let chan_keys = keys_provider.get_channel_keys(false, channel_value_satoshis);

		if channel_value_satoshis >= MAX_FUNDING_SATOSHIS {
			return Err(APIError::APIMisuseError{err: "funding value > 2^24"});
		}

		if push_msat > channel_value_satoshis * 1000 {
			return Err(APIError::APIMisuseError{err: "push value > channel value"});
		}
		if config.own_channel_config.our_to_self_delay < BREAKDOWN_TIMEOUT {
			return Err(APIError::APIMisuseError{err: "Configured with an unreasonable our_to_self_delay putting user funds at risks"});
		}


		let background_feerate = fee_estimator.get_est_sat_per_1000_weight(ConfirmationTarget::Background);
		if Channel::<ChanSigner>::get_remote_channel_reserve_satoshis(channel_value_satoshis) < Channel::<ChanSigner>::derive_our_dust_limit_satoshis(background_feerate) {
			return Err(APIError::FeeRateTooHigh{err: format!("Not enough reserve above dust limit can be found at current fee rate({})", background_feerate), feerate: background_feerate});
		}

		let feerate = fee_estimator.get_est_sat_per_1000_weight(ConfirmationTarget::Normal);

		Ok(Channel {
			user_id: user_id,
			config: config.channel_options.clone(),

			channel_id: keys_provider.get_channel_id(),
			channel_state: ChannelState::OurInitSent as u32,
			channel_outbound: true,
			secp_ctx: Secp256k1::new(),
			channel_value_satoshis: channel_value_satoshis,

			latest_monitor_update_id: 0,

			local_keys: chan_keys,
			shutdown_pubkey: keys_provider.get_shutdown_pubkey(),
			destination_script: keys_provider.get_destination_script(),

			cur_local_commitment_transaction_number: INITIAL_COMMITMENT_NUMBER,
			cur_remote_commitment_transaction_number: INITIAL_COMMITMENT_NUMBER,
			value_to_self_msat: channel_value_satoshis * 1000 - push_msat,

			pending_inbound_htlcs: Vec::new(),
			pending_outbound_htlcs: Vec::new(),
			holding_cell_htlc_updates: Vec::new(),
			pending_update_fee: None,
			holding_cell_update_fee: None,
			next_local_htlc_id: 0,
			next_remote_htlc_id: 0,
			update_time_counter: 1,

			resend_order: RAACommitmentOrder::CommitmentFirst,

			monitor_pending_funding_locked: false,
			monitor_pending_revoke_and_ack: false,
			monitor_pending_commitment_signed: false,
			monitor_pending_forwards: Vec::new(),
			monitor_pending_failures: Vec::new(),

			#[cfg(debug_assertions)]
			max_commitment_tx_output_local: ::std::sync::Mutex::new((channel_value_satoshis * 1000 - push_msat, push_msat)),
			#[cfg(debug_assertions)]
			max_commitment_tx_output_remote: ::std::sync::Mutex::new((channel_value_satoshis * 1000 - push_msat, push_msat)),

			last_sent_closing_fee: None,

			funding_txo: None,
			funding_tx_confirmed_in: None,
			short_channel_id: None,
			last_block_connected: Default::default(),
			funding_tx_confirmations: 0,

			feerate_per_kw: feerate,
			their_dust_limit_satoshis: 0,
			our_dust_limit_satoshis: Channel::<ChanSigner>::derive_our_dust_limit_satoshis(background_feerate),
			their_max_htlc_value_in_flight_msat: 0,
			local_channel_reserve_satoshis: 0,
			their_htlc_minimum_msat: 0,
			our_htlc_minimum_msat: if config.own_channel_config.our_htlc_minimum_msat == 0 { 1 } else { config.own_channel_config.our_htlc_minimum_msat },
			their_to_self_delay: 0,
			our_to_self_delay: config.own_channel_config.our_to_self_delay,
			their_max_accepted_htlcs: 0,
			minimum_depth: 0, // Filled in in accept_channel

			their_pubkeys: None,
			their_cur_commitment_point: None,

			their_prev_commitment_point: None,
			their_node_id: their_node_id,

			their_shutdown_scriptpubkey: None,

			channel_monitor: None,
			commitment_secrets: CounterpartyCommitmentSecrets::new(),

			network_sync: UpdateStatus::Fresh,
		})
	}

	fn check_remote_fee<F: Deref>(fee_estimator: &F, feerate_per_kw: u32) -> Result<(), ChannelError>
		where F::Target: FeeEstimator
	{
		if (feerate_per_kw as u64) < fee_estimator.get_est_sat_per_1000_weight(ConfirmationTarget::Background) {
			return Err(ChannelError::Close("Peer's feerate much too low"));
		}
		if (feerate_per_kw as u64) > fee_estimator.get_est_sat_per_1000_weight(ConfirmationTarget::HighPriority) * 2 {
			return Err(ChannelError::Close("Peer's feerate much too high"));
		}
		Ok(())
	}

	/// Creates a new channel from a remote sides' request for one.
	/// Assumes chain_hash has already been checked and corresponds with what we expect!
	pub fn new_from_req<K: Deref, F: Deref>(fee_estimator: &F, keys_provider: &K, their_node_id: PublicKey, their_features: InitFeatures, msg: &msgs::OpenChannel, user_id: u64, config: &UserConfig) -> Result<Channel<ChanSigner>, ChannelError>
		where K::Target: KeysInterface<ChanKeySigner = ChanSigner>,
          F::Target: FeeEstimator
	{
		let mut chan_keys = keys_provider.get_channel_keys(true, msg.funding_satoshis);
		let their_pubkeys = ChannelPublicKeys {
			funding_pubkey: msg.funding_pubkey,
			revocation_basepoint: msg.revocation_basepoint,
			payment_point: msg.payment_point,
			delayed_payment_basepoint: msg.delayed_payment_basepoint,
			htlc_basepoint: msg.htlc_basepoint
		};
		chan_keys.set_remote_channel_pubkeys(&their_pubkeys);
		let mut local_config = (*config).channel_options.clone();

		if config.own_channel_config.our_to_self_delay < BREAKDOWN_TIMEOUT {
			return Err(ChannelError::Close("Configured with an unreasonable our_to_self_delay putting user funds at risks"));
		}

		// Check sanity of message fields:
		if msg.funding_satoshis >= MAX_FUNDING_SATOSHIS {
			return Err(ChannelError::Close("funding value > 2^24"));
		}
		if msg.channel_reserve_satoshis > msg.funding_satoshis {
			return Err(ChannelError::Close("Bogus channel_reserve_satoshis"));
		}
		if msg.push_msat > (msg.funding_satoshis - msg.channel_reserve_satoshis) * 1000 {
			return Err(ChannelError::Close("push_msat larger than funding value"));
		}
		if msg.dust_limit_satoshis > msg.funding_satoshis {
			return Err(ChannelError::Close("Peer never wants payout outputs?"));
		}
		if msg.dust_limit_satoshis > msg.channel_reserve_satoshis {
			return Err(ChannelError::Close("Bogus; channel reserve is less than dust limit"));
		}
		if msg.htlc_minimum_msat >= (msg.funding_satoshis - msg.channel_reserve_satoshis) * 1000 {
			return Err(ChannelError::Close("Minimum htlc value is full channel value"));
		}
		Channel::<ChanSigner>::check_remote_fee(fee_estimator, msg.feerate_per_kw)?;

		if msg.to_self_delay > config.peer_channel_config_limits.their_to_self_delay || msg.to_self_delay > MAX_LOCAL_BREAKDOWN_TIMEOUT {
			return Err(ChannelError::Close("They wanted our payments to be delayed by a needlessly long period"));
		}
		if msg.max_accepted_htlcs < 1 {
			return Err(ChannelError::Close("0 max_accpted_htlcs makes for a useless channel"));
		}
		if msg.max_accepted_htlcs > 483 {
			return Err(ChannelError::Close("max_accpted_htlcs > 483"));
		}

		// Now check against optional parameters as set by config...
		if msg.funding_satoshis < config.peer_channel_config_limits.min_funding_satoshis {
			return Err(ChannelError::Close("funding satoshis is less than the user specified limit"));
		}
		if msg.htlc_minimum_msat > config.peer_channel_config_limits.max_htlc_minimum_msat {
			return Err(ChannelError::Close("htlc minimum msat is higher than the user specified limit"));
		}
		if msg.max_htlc_value_in_flight_msat < config.peer_channel_config_limits.min_max_htlc_value_in_flight_msat {
			return Err(ChannelError::Close("max htlc value in flight msat is less than the user specified limit"));
		}
		if msg.channel_reserve_satoshis > config.peer_channel_config_limits.max_channel_reserve_satoshis {
			return Err(ChannelError::Close("channel reserve satoshis is higher than the user specified limit"));
		}
		if msg.max_accepted_htlcs < config.peer_channel_config_limits.min_max_accepted_htlcs {
			return Err(ChannelError::Close("max accepted htlcs is less than the user specified limit"));
		}
		if msg.dust_limit_satoshis < config.peer_channel_config_limits.min_dust_limit_satoshis {
			return Err(ChannelError::Close("dust limit satoshis is less than the user specified limit"));
		}
		if msg.dust_limit_satoshis > config.peer_channel_config_limits.max_dust_limit_satoshis {
			return Err(ChannelError::Close("dust limit satoshis is greater than the user specified limit"));
		}

		// Convert things into internal flags and prep our state:

		let their_announce = if (msg.channel_flags & 1) == 1 { true } else { false };
		if config.peer_channel_config_limits.force_announced_channel_preference {
			if local_config.announced_channel != their_announce {
				return Err(ChannelError::Close("Peer tried to open channel but their announcement preference is different from ours"));
			}
		}
		// we either accept their preference or the preferences match
		local_config.announced_channel = their_announce;

		let background_feerate = fee_estimator.get_est_sat_per_1000_weight(ConfirmationTarget::Background);

		let our_dust_limit_satoshis = Channel::<ChanSigner>::derive_our_dust_limit_satoshis(background_feerate);
		let remote_channel_reserve_satoshis = Channel::<ChanSigner>::get_remote_channel_reserve_satoshis(msg.funding_satoshis);
		if remote_channel_reserve_satoshis < our_dust_limit_satoshis {
			return Err(ChannelError::Close("Suitable channel reserve not found. aborting"));
		}
		if msg.channel_reserve_satoshis < our_dust_limit_satoshis {
			return Err(ChannelError::Close("channel_reserve_satoshis too small"));
		}
		if remote_channel_reserve_satoshis < msg.dust_limit_satoshis {
			return Err(ChannelError::Close("Dust limit too high for the channel reserve we require the remote to keep"));
		}

		// check if the funder's amount for the initial commitment tx is sufficient
		// for full fee payment
		let funders_amount_msat = msg.funding_satoshis * 1000 - msg.push_msat;
		if funders_amount_msat < background_feerate * COMMITMENT_TX_BASE_WEIGHT {
			return Err(ChannelError::Close("Insufficient funding amount for initial commitment"));
		}

		let to_local_msat = msg.push_msat;
		let to_remote_msat = funders_amount_msat - background_feerate * COMMITMENT_TX_BASE_WEIGHT;
		if to_local_msat <= msg.channel_reserve_satoshis * 1000 && to_remote_msat <= remote_channel_reserve_satoshis * 1000 {
			return Err(ChannelError::Close("Insufficient funding amount for initial commitment"));
		}

		let their_shutdown_scriptpubkey = if their_features.supports_upfront_shutdown_script() {
			match &msg.shutdown_scriptpubkey {
				&OptionalField::Present(ref script) => {
					// Peer is signaling upfront_shutdown and has provided a non-accepted scriptpubkey format. We enforce it while receiving shutdown msg
					if script.is_p2pkh() || script.is_p2sh() || script.is_v0_p2wsh() || script.is_v0_p2wpkh() {
						Some(script.clone())
					// Peer is signaling upfront_shutdown and has opt-out with a 0-length script. We don't enforce anything
					} else if script.len() == 0 {
						None
					// Peer is signaling upfront_shutdown and has provided a non-accepted scriptpubkey format. Fail the channel
					} else {
						return Err(ChannelError::Close("Peer is signaling upfront_shutdown but has provided a non-accepted scriptpubkey format"));
					}
				},
				// Peer is signaling upfront shutdown but don't opt-out with correct mechanism (a.k.a 0-length script). Peer looks buggy, we fail the channel
				&OptionalField::Absent => {
					return Err(ChannelError::Close("Peer is signaling upfront_shutdown but we don't get any script. Use 0-length script to opt-out"));
				}
			}
		} else { None };

		let chan = Channel {
			user_id: user_id,
			config: local_config,

			channel_id: msg.temporary_channel_id,
			channel_state: (ChannelState::OurInitSent as u32) | (ChannelState::TheirInitSent as u32),
			channel_outbound: false,
			secp_ctx: Secp256k1::new(),

			latest_monitor_update_id: 0,

			local_keys: chan_keys,
			shutdown_pubkey: keys_provider.get_shutdown_pubkey(),
			destination_script: keys_provider.get_destination_script(),

			cur_local_commitment_transaction_number: INITIAL_COMMITMENT_NUMBER,
			cur_remote_commitment_transaction_number: INITIAL_COMMITMENT_NUMBER,
			value_to_self_msat: msg.push_msat,

			pending_inbound_htlcs: Vec::new(),
			pending_outbound_htlcs: Vec::new(),
			holding_cell_htlc_updates: Vec::new(),
			pending_update_fee: None,
			holding_cell_update_fee: None,
			next_local_htlc_id: 0,
			next_remote_htlc_id: 0,
			update_time_counter: 1,

			resend_order: RAACommitmentOrder::CommitmentFirst,

			monitor_pending_funding_locked: false,
			monitor_pending_revoke_and_ack: false,
			monitor_pending_commitment_signed: false,
			monitor_pending_forwards: Vec::new(),
			monitor_pending_failures: Vec::new(),

			#[cfg(debug_assertions)]
			max_commitment_tx_output_local: ::std::sync::Mutex::new((msg.push_msat, msg.funding_satoshis * 1000 - msg.push_msat)),
			#[cfg(debug_assertions)]
			max_commitment_tx_output_remote: ::std::sync::Mutex::new((msg.push_msat, msg.funding_satoshis * 1000 - msg.push_msat)),

			last_sent_closing_fee: None,

			funding_txo: None,
			funding_tx_confirmed_in: None,
			short_channel_id: None,
			last_block_connected: Default::default(),
			funding_tx_confirmations: 0,

			feerate_per_kw: msg.feerate_per_kw as u64,
			channel_value_satoshis: msg.funding_satoshis,
			their_dust_limit_satoshis: msg.dust_limit_satoshis,
			our_dust_limit_satoshis: our_dust_limit_satoshis,
			their_max_htlc_value_in_flight_msat: cmp::min(msg.max_htlc_value_in_flight_msat, msg.funding_satoshis * 1000),
			local_channel_reserve_satoshis: msg.channel_reserve_satoshis,
			their_htlc_minimum_msat: msg.htlc_minimum_msat,
			our_htlc_minimum_msat: if config.own_channel_config.our_htlc_minimum_msat == 0 { 1 } else { config.own_channel_config.our_htlc_minimum_msat },
			their_to_self_delay: msg.to_self_delay,
			our_to_self_delay: config.own_channel_config.our_to_self_delay,
			their_max_accepted_htlcs: msg.max_accepted_htlcs,
			minimum_depth: config.own_channel_config.minimum_depth,

			their_pubkeys: Some(their_pubkeys),
			their_cur_commitment_point: Some(msg.first_per_commitment_point),

			their_prev_commitment_point: None,
			their_node_id: their_node_id,

			their_shutdown_scriptpubkey,

			channel_monitor: None,
			commitment_secrets: CounterpartyCommitmentSecrets::new(),

			network_sync: UpdateStatus::Fresh,
		};

		Ok(chan)
	}

	// Utilities to derive keys:

	fn build_local_commitment_secret(&self, idx: u64) -> SecretKey {
		let res = chan_utils::build_commitment_secret(self.local_keys.commitment_seed(), idx);
		SecretKey::from_slice(&res).unwrap()
	}

	// Utilities to build transactions:

	fn get_commitment_transaction_number_obscure_factor(&self) -> u64 {
		let mut sha = Sha256::engine();
		let our_payment_point = PublicKey::from_secret_key(&self.secp_ctx, self.local_keys.payment_key());

		let their_payment_point = &self.their_pubkeys.as_ref().unwrap().payment_point.serialize();
		if self.channel_outbound {
			sha.input(&our_payment_point.serialize());
			sha.input(their_payment_point);
		} else {
			sha.input(their_payment_point);
			sha.input(&our_payment_point.serialize());
		}
		let res = Sha256::from_engine(sha).into_inner();

		((res[26] as u64) << 5*8) |
		((res[27] as u64) << 4*8) |
		((res[28] as u64) << 3*8) |
		((res[29] as u64) << 2*8) |
		((res[30] as u64) << 1*8) |
		((res[31] as u64) << 0*8)
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
	/// Returns (the transaction built, the number of HTLC outputs which were present in the
	/// transaction, the list of HTLCs which were not ignored when building the transaction).
	/// Note that below-dust HTLCs are included in the third return value, but not the second, and
	/// sources are provided only for outbound HTLCs in the third return value.
	#[inline]
	fn build_commitment_transaction<L: Deref>(&self, commitment_number: u64, keys: &TxCreationKeys, local: bool, generated_by_local: bool, feerate_per_kw: u64, logger: &L) -> (Transaction, usize, Vec<(HTLCOutputInCommitment, Option<&HTLCSource>)>) where L::Target: Logger {
		let obscured_commitment_transaction_number = self.get_commitment_transaction_number_obscure_factor() ^ (INITIAL_COMMITMENT_NUMBER - commitment_number);

		let txins = {
			let mut ins: Vec<TxIn> = Vec::new();
			ins.push(TxIn {
				previous_output: self.funding_txo.unwrap().into_bitcoin_outpoint(),
				script_sig: Script::new(),
				sequence: ((0x80 as u32) << 8*3) | ((obscured_commitment_transaction_number >> 3*8) as u32),
				witness: Vec::new(),
			});
			ins
		};

		let mut txouts: Vec<(TxOut, Option<(HTLCOutputInCommitment, Option<&HTLCSource>)>)> = Vec::with_capacity(self.pending_inbound_htlcs.len() + self.pending_outbound_htlcs.len() + 2);
		let mut included_dust_htlcs: Vec<(HTLCOutputInCommitment, Option<&HTLCSource>)> = Vec::new();

		let dust_limit_satoshis = if local { self.our_dust_limit_satoshis } else { self.their_dust_limit_satoshis };
		let mut remote_htlc_total_msat = 0;
		let mut local_htlc_total_msat = 0;
		let mut value_to_self_msat_offset = 0;

		log_trace!(logger, "Building commitment transaction number {} (really {} xor {}) for {}, generated by {} with fee {}...", commitment_number, (INITIAL_COMMITMENT_NUMBER - commitment_number), self.get_commitment_transaction_number_obscure_factor(), if local { "us" } else { "remote" }, if generated_by_local { "us" } else { "remote" }, feerate_per_kw);

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
					if $htlc.amount_msat / 1000 >= dust_limit_satoshis + (feerate_per_kw * HTLC_TIMEOUT_TX_WEIGHT / 1000) {
						log_trace!(logger, "   ...including {} {} HTLC {} (hash {}) with value {}", if $outbound { "outbound" } else { "inbound" }, $state_name, $htlc.htlc_id, log_bytes!($htlc.payment_hash.0), $htlc.amount_msat);
						txouts.push((TxOut {
							script_pubkey: chan_utils::get_htlc_redeemscript(&htlc_in_tx, &keys).to_v0_p2wsh(),
							value: $htlc.amount_msat / 1000
						}, Some((htlc_in_tx, $source))));
					} else {
						log_trace!(logger, "   ...including {} {} dust HTLC {} (hash {}) with value {} due to dust limit", if $outbound { "outbound" } else { "inbound" }, $state_name, $htlc.htlc_id, log_bytes!($htlc.payment_hash.0), $htlc.amount_msat);
						included_dust_htlcs.push((htlc_in_tx, $source));
					}
				} else {
					let htlc_in_tx = get_htlc_in_commitment!($htlc, false);
					if $htlc.amount_msat / 1000 >= dust_limit_satoshis + (feerate_per_kw * HTLC_SUCCESS_TX_WEIGHT / 1000) {
						log_trace!(logger, "   ...including {} {} HTLC {} (hash {}) with value {}", if $outbound { "outbound" } else { "inbound" }, $state_name, $htlc.htlc_id, log_bytes!($htlc.payment_hash.0), $htlc.amount_msat);
						txouts.push((TxOut { // "received HTLC output"
							script_pubkey: chan_utils::get_htlc_redeemscript(&htlc_in_tx, &keys).to_v0_p2wsh(),
							value: $htlc.amount_msat / 1000
						}, Some((htlc_in_tx, $source))));
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

		for ref htlc in self.pending_outbound_htlcs.iter() {
			let (include, state_name) = match htlc.state {
				OutboundHTLCState::LocalAnnounced(_) => (generated_by_local, "LocalAnnounced"),
				OutboundHTLCState::Committed => (true, "Committed"),
				OutboundHTLCState::RemoteRemoved(_) => (generated_by_local, "RemoteRemoved"),
				OutboundHTLCState::AwaitingRemoteRevokeToRemove(_) => (generated_by_local, "AwaitingRemoteRevokeToRemove"),
				OutboundHTLCState::AwaitingRemovedRemoteRevoke(_) => (false, "AwaitingRemovedRemoteRevoke"),
			};

			if include {
				add_htlc_output!(htlc, true, Some(&htlc.source), state_name);
				local_htlc_total_msat += htlc.amount_msat;
			} else {
				log_trace!(logger, "   ...not including outbound HTLC {} (hash {}) with value {} due to state ({})", htlc.htlc_id, log_bytes!(htlc.payment_hash.0), htlc.amount_msat, state_name);
				match htlc.state {
					OutboundHTLCState::AwaitingRemoteRevokeToRemove(None)|OutboundHTLCState::AwaitingRemovedRemoteRevoke(None) => {
						value_to_self_msat_offset -= htlc.amount_msat as i64;
					},
					OutboundHTLCState::RemoteRemoved(None) => {
						if !generated_by_local {
							value_to_self_msat_offset -= htlc.amount_msat as i64;
						}
					},
					_ => {},
				}
			}
		}

		let value_to_self_msat: i64 = (self.value_to_self_msat - local_htlc_total_msat) as i64 + value_to_self_msat_offset;
		assert!(value_to_self_msat >= 0);
		// Note that in case they have several just-awaiting-last-RAA fulfills in-progress (ie
		// AwaitingRemoteRevokeToRemove or AwaitingRemovedRemoteRevoke) we may have allowed them to
		// "violate" their reserve value by couting those against it. Thus, we have to convert
		// everything to i64 before subtracting as otherwise we can overflow.
		let value_to_remote_msat: i64 = (self.channel_value_satoshis * 1000) as i64 - (self.value_to_self_msat as i64) - (remote_htlc_total_msat as i64) - value_to_self_msat_offset;
		assert!(value_to_remote_msat >= 0);

		#[cfg(debug_assertions)]
		{
			// Make sure that the to_self/to_remote is always either past the appropriate
			// channel_reserve *or* it is making progress towards it.
			let mut max_commitment_tx_output = if generated_by_local {
				self.max_commitment_tx_output_local.lock().unwrap()
			} else {
				self.max_commitment_tx_output_remote.lock().unwrap()
			};
			debug_assert!(max_commitment_tx_output.0 <= value_to_self_msat as u64 || value_to_self_msat / 1000 >= self.local_channel_reserve_satoshis as i64);
			max_commitment_tx_output.0 = cmp::max(max_commitment_tx_output.0, value_to_self_msat as u64);
			debug_assert!(max_commitment_tx_output.1 <= value_to_remote_msat as u64 || value_to_remote_msat / 1000 >= Channel::<ChanSigner>::get_remote_channel_reserve_satoshis(self.channel_value_satoshis) as i64);
			max_commitment_tx_output.1 = cmp::max(max_commitment_tx_output.1, value_to_remote_msat as u64);
		}

		let total_fee: u64 = feerate_per_kw * (COMMITMENT_TX_BASE_WEIGHT + (txouts.len() as u64) * COMMITMENT_TX_WEIGHT_PER_HTLC) / 1000;
		let (value_to_self, value_to_remote) = if self.channel_outbound {
			(value_to_self_msat / 1000 - total_fee as i64, value_to_remote_msat / 1000)
		} else {
			(value_to_self_msat / 1000, value_to_remote_msat / 1000 - total_fee as i64)
		};

		let value_to_a = if local { value_to_self } else { value_to_remote };
		let value_to_b = if local { value_to_remote } else { value_to_self };

		if value_to_a >= (dust_limit_satoshis as i64) {
			log_trace!(logger, "   ...including {} output with value {}", if local { "to_local" } else { "to_remote" }, value_to_a);
			txouts.push((TxOut {
				script_pubkey: chan_utils::get_revokeable_redeemscript(&keys.revocation_key,
				                                                       if local { self.their_to_self_delay } else { self.our_to_self_delay },
				                                                       &keys.a_delayed_payment_key).to_v0_p2wsh(),
				value: value_to_a as u64
			}, None));
		}

		if value_to_b >= (dust_limit_satoshis as i64) {
			log_trace!(logger, "   ...including {} output with value {}", if local { "to_remote" } else { "to_local" }, value_to_b);
			let static_payment_pk = if local {
				self.their_pubkeys.as_ref().unwrap().payment_point
			} else {
				self.local_keys.pubkeys().payment_point
			}.serialize();
			txouts.push((TxOut {
				script_pubkey: Builder::new().push_opcode(opcodes::all::OP_PUSHBYTES_0)
				                             .push_slice(&WPubkeyHash::hash(&static_payment_pk)[..])
				                             .into_script(),
				value: value_to_b as u64
			}, None));
		}

		transaction_utils::sort_outputs(&mut txouts, |a, b| {
			if let &Some(ref a_htlc) = a {
				if let &Some(ref b_htlc) = b {
					a_htlc.0.cltv_expiry.cmp(&b_htlc.0.cltv_expiry)
						// Note that due to hash collisions, we have to have a fallback comparison
						// here for fuzztarget mode (otherwise at least chanmon_fail_consistency
						// may fail)!
						.then(a_htlc.0.payment_hash.0.cmp(&b_htlc.0.payment_hash.0))
				// For non-HTLC outputs, if they're copying our SPK we don't really care if we
				// close the channel due to mismatches - they're doing something dumb:
				} else { cmp::Ordering::Equal }
			} else { cmp::Ordering::Equal }
		});

		let mut outputs: Vec<TxOut> = Vec::with_capacity(txouts.len());
		let mut htlcs_included: Vec<(HTLCOutputInCommitment, Option<&HTLCSource>)> = Vec::with_capacity(txouts.len() + included_dust_htlcs.len());
		for (idx, mut out) in txouts.drain(..).enumerate() {
			outputs.push(out.0);
			if let Some((mut htlc, source_option)) = out.1.take() {
				htlc.transaction_output_index = Some(idx as u32);
				htlcs_included.push((htlc, source_option));
			}
		}
		let non_dust_htlc_count = htlcs_included.len();
		htlcs_included.append(&mut included_dust_htlcs);

		(Transaction {
			version: 2,
			lock_time: ((0x20 as u32) << 8*3) | ((obscured_commitment_transaction_number & 0xffffffu64) as u32),
			input: txins,
			output: outputs,
		}, non_dust_htlc_count, htlcs_included)
	}

	#[inline]
	fn get_closing_scriptpubkey(&self) -> Script {
		let our_channel_close_key_hash = WPubkeyHash::hash(&self.shutdown_pubkey.serialize());
		Builder::new().push_opcode(opcodes::all::OP_PUSHBYTES_0).push_slice(&our_channel_close_key_hash[..]).into_script()
	}

	#[inline]
	fn get_closing_transaction_weight(a_scriptpubkey: &Script, b_scriptpubkey: &Script) -> u64 {
		(4 + 1 + 36 + 4 + 1 + 1 + 2*(8+1) + 4 + a_scriptpubkey.len() as u64 + b_scriptpubkey.len() as u64)*4 + 2 + 1 + 1 + 2*(1 + 72)
	}

	#[inline]
	fn build_closing_transaction(&self, proposed_total_fee_satoshis: u64, skip_remote_output: bool) -> (Transaction, u64) {
		let txins = {
			let mut ins: Vec<TxIn> = Vec::new();
			ins.push(TxIn {
				previous_output: self.funding_txo.unwrap().into_bitcoin_outpoint(),
				script_sig: Script::new(),
				sequence: 0xffffffff,
				witness: Vec::new(),
			});
			ins
		};

		assert!(self.pending_inbound_htlcs.is_empty());
		assert!(self.pending_outbound_htlcs.is_empty());
		let mut txouts: Vec<(TxOut, ())> = Vec::new();

		let mut total_fee_satoshis = proposed_total_fee_satoshis;
		let value_to_self: i64 = (self.value_to_self_msat as i64) / 1000 - if self.channel_outbound { total_fee_satoshis as i64 } else { 0 };
		let value_to_remote: i64 = ((self.channel_value_satoshis * 1000 - self.value_to_self_msat) as i64 / 1000) - if self.channel_outbound { 0 } else { total_fee_satoshis as i64 };

		if value_to_self < 0 {
			assert!(self.channel_outbound);
			total_fee_satoshis += (-value_to_self) as u64;
		} else if value_to_remote < 0 {
			assert!(!self.channel_outbound);
			total_fee_satoshis += (-value_to_remote) as u64;
		}

		if !skip_remote_output && value_to_remote as u64 > self.our_dust_limit_satoshis {
			txouts.push((TxOut {
				script_pubkey: self.their_shutdown_scriptpubkey.clone().unwrap(),
				value: value_to_remote as u64
			}, ()));
		}

		if value_to_self as u64 > self.our_dust_limit_satoshis {
			txouts.push((TxOut {
				script_pubkey: self.get_closing_scriptpubkey(),
				value: value_to_self as u64
			}, ()));
		}

		transaction_utils::sort_outputs(&mut txouts, |_, _| { cmp::Ordering::Equal }); // Ordering doesnt matter if they used our pubkey...

		let mut outputs: Vec<TxOut> = Vec::new();
		for out in txouts.drain(..) {
			outputs.push(out.0);
		}

		(Transaction {
			version: 2,
			lock_time: 0,
			input: txins,
			output: outputs,
		}, total_fee_satoshis)
	}

	#[inline]
	/// Creates a set of keys for build_commitment_transaction to generate a transaction which our
	/// counterparty will sign (ie DO NOT send signatures over a transaction created by this to
	/// our counterparty!)
	/// The result is a transaction which we can revoke ownership of (ie a "local" transaction)
	/// TODO Some magic rust shit to compile-time check this?
	fn build_local_transaction_keys(&self, commitment_number: u64) -> Result<TxCreationKeys, ChannelError> {
		let per_commitment_point = PublicKey::from_secret_key(&self.secp_ctx, &self.build_local_commitment_secret(commitment_number));
		let delayed_payment_base = PublicKey::from_secret_key(&self.secp_ctx, self.local_keys.delayed_payment_base_key());
		let htlc_basepoint = PublicKey::from_secret_key(&self.secp_ctx, self.local_keys.htlc_base_key());
		let their_pubkeys = self.their_pubkeys.as_ref().unwrap();

		Ok(secp_check!(TxCreationKeys::new(&self.secp_ctx, &per_commitment_point, &delayed_payment_base, &htlc_basepoint, &their_pubkeys.revocation_basepoint, &their_pubkeys.htlc_basepoint), "Local tx keys generation got bogus keys"))
	}

	#[inline]
	/// Creates a set of keys for build_commitment_transaction to generate a transaction which we
	/// will sign and send to our counterparty.
	/// If an Err is returned, it is a ChannelError::Close (for get_outbound_funding_created)
	fn build_remote_transaction_keys(&self) -> Result<TxCreationKeys, ChannelError> {
		//TODO: Ensure that the payment_key derived here ends up in the library users' wallet as we
		//may see payments to it!
		let revocation_basepoint = PublicKey::from_secret_key(&self.secp_ctx, self.local_keys.revocation_base_key());
		let htlc_basepoint = PublicKey::from_secret_key(&self.secp_ctx, self.local_keys.htlc_base_key());
		let their_pubkeys = self.their_pubkeys.as_ref().unwrap();

		Ok(secp_check!(TxCreationKeys::new(&self.secp_ctx, &self.their_cur_commitment_point.unwrap(), &their_pubkeys.delayed_payment_basepoint, &their_pubkeys.htlc_basepoint, &revocation_basepoint, &htlc_basepoint), "Remote tx keys generation got bogus keys"))
	}

	/// Gets the redeemscript for the funding transaction output (ie the funding transaction output
	/// pays to get_funding_redeemscript().to_v0_p2wsh()).
	/// Panics if called before accept_channel/new_from_req
	pub fn get_funding_redeemscript(&self) -> Script {
		let our_funding_key = PublicKey::from_secret_key(&self.secp_ctx, self.local_keys.funding_key());
		make_funding_redeemscript(&our_funding_key, self.their_funding_pubkey())
	}

	/// Builds the htlc-success or htlc-timeout transaction which spends a given HTLC output
	/// @local is used only to convert relevant internal structures which refer to remote vs local
	/// to decide value of outputs and direction of HTLCs.
	fn build_htlc_transaction(&self, prev_hash: &Txid, htlc: &HTLCOutputInCommitment, local: bool, keys: &TxCreationKeys, feerate_per_kw: u64) -> Transaction {
		chan_utils::build_htlc_transaction(prev_hash, feerate_per_kw, if local { self.their_to_self_delay } else { self.our_to_self_delay }, htlc, &keys.a_delayed_payment_key, &keys.revocation_key)
	}

	/// Per HTLC, only one get_update_fail_htlc or get_update_fulfill_htlc call may be made.
	/// In such cases we debug_assert!(false) and return a ChannelError::Ignore. Thus, will always
	/// return Ok(_) if debug assertions are turned on or preconditions are met.
	///
	/// Note that it is still possible to hit these assertions in case we find a preimage on-chain
	/// but then have a reorg which settles on an HTLC-failure on chain.
	fn get_update_fulfill_htlc<L: Deref>(&mut self, htlc_id_arg: u64, payment_preimage_arg: PaymentPreimage, logger: &L) -> Result<(Option<msgs::UpdateFulfillHTLC>, Option<ChannelMonitorUpdate>), ChannelError> where L::Target: Logger {
		// Either ChannelFunded got set (which means it won't be unset) or there is no way any
		// caller thought we could have something claimed (cause we wouldn't have accepted in an
		// incoming HTLC anyway). If we got to ShutdownComplete, callers aren't allowed to call us,
		// either.
		if (self.channel_state & (ChannelState::ChannelFunded as u32)) != (ChannelState::ChannelFunded as u32) {
			panic!("Was asked to fulfill an HTLC when channel was not in an operational state");
		}
		assert_eq!(self.channel_state & ChannelState::ShutdownComplete as u32, 0);

		let payment_hash_calc = PaymentHash(Sha256::hash(&payment_preimage_arg.0[..]).into_inner());

		// ChannelManager may generate duplicate claims/fails due to HTLC update events from
		// on-chain ChannelsMonitors during block rescan. Ideally we'd figure out a way to drop
		// these, but for now we just have to treat them as normal.

		let mut pending_idx = std::usize::MAX;
		for (idx, htlc) in self.pending_inbound_htlcs.iter().enumerate() {
			if htlc.htlc_id == htlc_id_arg {
				assert_eq!(htlc.payment_hash, payment_hash_calc);
				match htlc.state {
					InboundHTLCState::Committed => {},
					InboundHTLCState::LocalRemoved(ref reason) => {
						if let &InboundHTLCRemovalReason::Fulfill(_) = reason {
						} else {
							log_warn!(logger, "Have preimage and want to fulfill HTLC with payment hash {} we already failed against channel {}", log_bytes!(htlc.payment_hash.0), log_bytes!(self.channel_id()));
						}
						debug_assert!(false, "Tried to fulfill an HTLC that was already fail/fulfilled");
						return Ok((None, None));
					},
					_ => {
						debug_assert!(false, "Have an inbound HTLC we tried to claim before it was fully committed to");
						// Don't return in release mode here so that we can update channel_monitor
					}
				}
				pending_idx = idx;
				break;
			}
		}
		if pending_idx == std::usize::MAX {
			return Err(ChannelError::Ignore("Unable to find a pending HTLC which matched the given HTLC ID"));
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
		self.channel_monitor.as_mut().unwrap().update_monitor_ooo(monitor_update.clone(), logger).unwrap();

		if (self.channel_state & (ChannelState::AwaitingRemoteRevoke as u32 | ChannelState::PeerDisconnected as u32 | ChannelState::MonitorUpdateFailed as u32)) != 0 {
			for pending_update in self.holding_cell_htlc_updates.iter() {
				match pending_update {
					&HTLCUpdateAwaitingACK::ClaimHTLC { htlc_id, .. } => {
						if htlc_id_arg == htlc_id {
							// Make sure we don't leave latest_monitor_update_id incremented here:
							self.latest_monitor_update_id -= 1;
							debug_assert!(false, "Tried to fulfill an HTLC that was already fulfilled");
							return Ok((None, None));
						}
					},
					&HTLCUpdateAwaitingACK::FailHTLC { htlc_id, .. } => {
						if htlc_id_arg == htlc_id {
							log_warn!(logger, "Have preimage and want to fulfill HTLC with pending failure against channel {}", log_bytes!(self.channel_id()));
							// TODO: We may actually be able to switch to a fulfill here, though its
							// rare enough it may not be worth the complexity burden.
							debug_assert!(false, "Tried to fulfill an HTLC that was already failed");
							return Ok((None, Some(monitor_update)));
						}
					},
					_ => {}
				}
			}
			log_trace!(logger, "Adding HTLC claim to holding_cell! Current state: {}", self.channel_state);
			self.holding_cell_htlc_updates.push(HTLCUpdateAwaitingACK::ClaimHTLC {
				payment_preimage: payment_preimage_arg, htlc_id: htlc_id_arg,
			});
			return Ok((None, Some(monitor_update)));
		}

		{
			let htlc = &mut self.pending_inbound_htlcs[pending_idx];
			if let InboundHTLCState::Committed = htlc.state {
			} else {
				debug_assert!(false, "Have an inbound HTLC we tried to claim before it was fully committed to");
				return Ok((None, Some(monitor_update)));
			}
			log_trace!(logger, "Upgrading HTLC {} to LocalRemoved with a Fulfill!", log_bytes!(htlc.payment_hash.0));
			htlc.state = InboundHTLCState::LocalRemoved(InboundHTLCRemovalReason::Fulfill(payment_preimage_arg.clone()));
		}

		Ok((Some(msgs::UpdateFulfillHTLC {
			channel_id: self.channel_id(),
			htlc_id: htlc_id_arg,
			payment_preimage: payment_preimage_arg,
		}), Some(monitor_update)))
	}

	pub fn get_update_fulfill_htlc_and_commit<L: Deref>(&mut self, htlc_id: u64, payment_preimage: PaymentPreimage, logger: &L) -> Result<(Option<(msgs::UpdateFulfillHTLC, msgs::CommitmentSigned)>, Option<ChannelMonitorUpdate>), ChannelError> where L::Target: Logger {
		match self.get_update_fulfill_htlc(htlc_id, payment_preimage, logger)? {
			(Some(update_fulfill_htlc), Some(mut monitor_update)) => {
				let (commitment, mut additional_update) = self.send_commitment_no_status_check(logger)?;
				// send_commitment_no_status_check may bump latest_monitor_id but we want them to be
				// strictly increasing by one, so decrement it here.
				self.latest_monitor_update_id = monitor_update.update_id;
				monitor_update.updates.append(&mut additional_update.updates);
				Ok((Some((update_fulfill_htlc, commitment)), Some(monitor_update)))
			},
			(Some(update_fulfill_htlc), None) => {
				let (commitment, monitor_update) = self.send_commitment_no_status_check(logger)?;
				Ok((Some((update_fulfill_htlc, commitment)), Some(monitor_update)))
			},
			(None, Some(monitor_update)) => Ok((None, Some(monitor_update))),
			(None, None) => Ok((None, None))
		}
	}

	/// Per HTLC, only one get_update_fail_htlc or get_update_fulfill_htlc call may be made.
	/// In such cases we debug_assert!(false) and return a ChannelError::Ignore. Thus, will always
	/// return Ok(_) if debug assertions are turned on or preconditions are met.
	///
	/// Note that it is still possible to hit these assertions in case we find a preimage on-chain
	/// but then have a reorg which settles on an HTLC-failure on chain.
	pub fn get_update_fail_htlc(&mut self, htlc_id_arg: u64, err_packet: msgs::OnionErrorPacket) -> Result<Option<msgs::UpdateFailHTLC>, ChannelError> {
		if (self.channel_state & (ChannelState::ChannelFunded as u32)) != (ChannelState::ChannelFunded as u32) {
			panic!("Was asked to fail an HTLC when channel was not in an operational state");
		}
		assert_eq!(self.channel_state & ChannelState::ShutdownComplete as u32, 0);

		// ChannelManager may generate duplicate claims/fails due to HTLC update events from
		// on-chain ChannelsMonitors during block rescan. Ideally we'd figure out a way to drop
		// these, but for now we just have to treat them as normal.

		let mut pending_idx = std::usize::MAX;
		for (idx, htlc) in self.pending_inbound_htlcs.iter().enumerate() {
			if htlc.htlc_id == htlc_id_arg {
				match htlc.state {
					InboundHTLCState::Committed => {},
					InboundHTLCState::LocalRemoved(_) => {
						debug_assert!(false, "Tried to fail an HTLC that was already fail/fulfilled");
						return Ok(None);
					},
					_ => {
						debug_assert!(false, "Have an inbound HTLC we tried to claim before it was fully committed to");
						return Err(ChannelError::Ignore("Unable to find a pending HTLC which matched the given HTLC ID"));
					}
				}
				pending_idx = idx;
			}
		}
		if pending_idx == std::usize::MAX {
			return Err(ChannelError::Ignore("Unable to find a pending HTLC which matched the given HTLC ID"));
		}

		// Now update local state:
		if (self.channel_state & (ChannelState::AwaitingRemoteRevoke as u32 | ChannelState::PeerDisconnected as u32 | ChannelState::MonitorUpdateFailed as u32)) != 0 {
			for pending_update in self.holding_cell_htlc_updates.iter() {
				match pending_update {
					&HTLCUpdateAwaitingACK::ClaimHTLC { htlc_id, .. } => {
						if htlc_id_arg == htlc_id {
							debug_assert!(false, "Tried to fail an HTLC that was already fulfilled");
							return Err(ChannelError::Ignore("Unable to find a pending HTLC which matched the given HTLC ID"));
						}
					},
					&HTLCUpdateAwaitingACK::FailHTLC { htlc_id, .. } => {
						if htlc_id_arg == htlc_id {
							debug_assert!(false, "Tried to fail an HTLC that was already failed");
							return Err(ChannelError::Ignore("Unable to find a pending HTLC which matched the given HTLC ID"));
						}
					},
					_ => {}
				}
			}
			self.holding_cell_htlc_updates.push(HTLCUpdateAwaitingACK::FailHTLC {
				htlc_id: htlc_id_arg,
				err_packet,
			});
			return Ok(None);
		}

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

	pub fn accept_channel(&mut self, msg: &msgs::AcceptChannel, config: &UserConfig, their_features: InitFeatures) -> Result<(), ChannelError> {
		// Check sanity of message fields:
		if !self.channel_outbound {
			return Err(ChannelError::Close("Got an accept_channel message from an inbound peer"));
		}
		if self.channel_state != ChannelState::OurInitSent as u32 {
			return Err(ChannelError::Close("Got an accept_channel message at a strange time"));
		}
		if msg.dust_limit_satoshis > 21000000 * 100000000 {
			return Err(ChannelError::Close("Peer never wants payout outputs?"));
		}
		if msg.channel_reserve_satoshis > self.channel_value_satoshis {
			return Err(ChannelError::Close("Bogus channel_reserve_satoshis"));
		}
		if msg.dust_limit_satoshis > msg.channel_reserve_satoshis {
			return Err(ChannelError::Close("Bogus channel_reserve and dust_limit"));
		}
		if msg.channel_reserve_satoshis < self.our_dust_limit_satoshis {
			return Err(ChannelError::Close("Peer never wants payout outputs?"));
		}
		if msg.dust_limit_satoshis > Channel::<ChanSigner>::get_remote_channel_reserve_satoshis(self.channel_value_satoshis) {
			return Err(ChannelError::Close("Dust limit is bigger than our channel reverse"));
		}
		if msg.htlc_minimum_msat >= (self.channel_value_satoshis - msg.channel_reserve_satoshis) * 1000 {
			return Err(ChannelError::Close("Minimum htlc value is full channel value"));
		}
		if msg.to_self_delay > config.peer_channel_config_limits.their_to_self_delay || msg.to_self_delay > MAX_LOCAL_BREAKDOWN_TIMEOUT {
			return Err(ChannelError::Close("They wanted our payments to be delayed by a needlessly long period"));
		}
		if msg.max_accepted_htlcs < 1 {
			return Err(ChannelError::Close("0 max_accepted_htlcs makes for a useless channel"));
		}
		if msg.max_accepted_htlcs > 483 {
			return Err(ChannelError::Close("max_accepted_htlcs > 483"));
		}

		// Now check against optional parameters as set by config...
		if msg.htlc_minimum_msat > config.peer_channel_config_limits.max_htlc_minimum_msat {
			return Err(ChannelError::Close("htlc minimum msat is higher than the user specified limit"));
		}
		if msg.max_htlc_value_in_flight_msat < config.peer_channel_config_limits.min_max_htlc_value_in_flight_msat {
			return Err(ChannelError::Close("max htlc value in flight msat is less than the user specified limit"));
		}
		if msg.channel_reserve_satoshis > config.peer_channel_config_limits.max_channel_reserve_satoshis {
			return Err(ChannelError::Close("channel reserve satoshis is higher than the user specified limit"));
		}
		if msg.max_accepted_htlcs < config.peer_channel_config_limits.min_max_accepted_htlcs {
			return Err(ChannelError::Close("max accepted htlcs is less than the user specified limit"));
		}
		if msg.dust_limit_satoshis < config.peer_channel_config_limits.min_dust_limit_satoshis {
			return Err(ChannelError::Close("dust limit satoshis is less than the user specified limit"));
		}
		if msg.dust_limit_satoshis > config.peer_channel_config_limits.max_dust_limit_satoshis {
			return Err(ChannelError::Close("dust limit satoshis is greater than the user specified limit"));
		}
		if msg.minimum_depth > config.peer_channel_config_limits.max_minimum_depth {
			return Err(ChannelError::Close("We consider the minimum depth to be unreasonably large"));
		}

		let their_shutdown_scriptpubkey = if their_features.supports_upfront_shutdown_script() {
			match &msg.shutdown_scriptpubkey {
				&OptionalField::Present(ref script) => {
					// Peer is signaling upfront_shutdown and has provided a non-accepted scriptpubkey format. We enforce it while receiving shutdown msg
					if script.is_p2pkh() || script.is_p2sh() || script.is_v0_p2wsh() || script.is_v0_p2wpkh() {
						Some(script.clone())
					// Peer is signaling upfront_shutdown and has opt-out with a 0-length script. We don't enforce anything
					} else if script.len() == 0 {
						None
					// Peer is signaling upfront_shutdown and has provided a non-accepted scriptpubkey format. Fail the channel
					} else {
						return Err(ChannelError::Close("Peer is signaling upfront_shutdown but has provided a non-accepted scriptpubkey format"));
					}
				},
				// Peer is signaling upfront shutdown but don't opt-out with correct mechanism (a.k.a 0-length script). Peer looks buggy, we fail the channel
				&OptionalField::Absent => {
					return Err(ChannelError::Close("Peer is signaling upfront_shutdown but we don't get any script. Use 0-length script to opt-out"));
				}
			}
		} else { None };

		self.their_dust_limit_satoshis = msg.dust_limit_satoshis;
		self.their_max_htlc_value_in_flight_msat = cmp::min(msg.max_htlc_value_in_flight_msat, self.channel_value_satoshis * 1000);
		self.local_channel_reserve_satoshis = msg.channel_reserve_satoshis;
		self.their_htlc_minimum_msat = msg.htlc_minimum_msat;
		self.their_to_self_delay = msg.to_self_delay;
		self.their_max_accepted_htlcs = msg.max_accepted_htlcs;
		self.minimum_depth = msg.minimum_depth;

		let their_pubkeys = ChannelPublicKeys {
			funding_pubkey: msg.funding_pubkey,
			revocation_basepoint: msg.revocation_basepoint,
			payment_point: msg.payment_point,
			delayed_payment_basepoint: msg.delayed_payment_basepoint,
			htlc_basepoint: msg.htlc_basepoint
		};

		self.local_keys.set_remote_channel_pubkeys(&their_pubkeys);
		self.their_pubkeys = Some(their_pubkeys);

		self.their_cur_commitment_point = Some(msg.first_per_commitment_point);
		self.their_shutdown_scriptpubkey = their_shutdown_scriptpubkey;

		self.channel_state = ChannelState::OurInitSent as u32 | ChannelState::TheirInitSent as u32;

		Ok(())
	}

	fn funding_created_signature<L: Deref>(&mut self, sig: &Signature, logger: &L) -> Result<(Transaction, LocalCommitmentTransaction, Signature), ChannelError> where L::Target: Logger {
		let funding_script = self.get_funding_redeemscript();

		let local_keys = self.build_local_transaction_keys(self.cur_local_commitment_transaction_number)?;
		let local_initial_commitment_tx = self.build_commitment_transaction(self.cur_local_commitment_transaction_number, &local_keys, true, false, self.feerate_per_kw, logger).0;
		let local_sighash = hash_to_message!(&bip143::SighashComponents::new(&local_initial_commitment_tx).sighash_all(&local_initial_commitment_tx.input[0], &funding_script, self.channel_value_satoshis)[..]);

		// They sign the "local" commitment transaction...
		log_trace!(logger, "Checking funding_created tx signature {} by key {} against tx {} (sighash {}) with redeemscript {}", log_bytes!(sig.serialize_compact()[..]), log_bytes!(self.their_funding_pubkey().serialize()), encode::serialize_hex(&local_initial_commitment_tx), log_bytes!(local_sighash[..]), encode::serialize_hex(&funding_script));
		secp_check!(self.secp_ctx.verify(&local_sighash, &sig, self.their_funding_pubkey()), "Invalid funding_created signature from peer");

		let localtx = LocalCommitmentTransaction::new_missing_local_sig(local_initial_commitment_tx, sig.clone(), &PublicKey::from_secret_key(&self.secp_ctx, self.local_keys.funding_key()), self.their_funding_pubkey(), local_keys, self.feerate_per_kw, Vec::new());

		let remote_keys = self.build_remote_transaction_keys()?;
		let remote_initial_commitment_tx = self.build_commitment_transaction(self.cur_remote_commitment_transaction_number, &remote_keys, false, false, self.feerate_per_kw, logger).0;
		let remote_signature = self.local_keys.sign_remote_commitment(self.feerate_per_kw, &remote_initial_commitment_tx, &remote_keys, &Vec::new(), self.our_to_self_delay, &self.secp_ctx)
				.map_err(|_| ChannelError::Close("Failed to get signatures for new commitment_signed"))?.0;

		// We sign the "remote" commitment transaction, allowing them to broadcast the tx if they wish.
		Ok((remote_initial_commitment_tx, localtx, remote_signature))
	}

	fn their_funding_pubkey(&self) -> &PublicKey {
		&self.their_pubkeys.as_ref().expect("their_funding_pubkey() only allowed after accept_channel").funding_pubkey
	}

	pub fn funding_created<L: Deref>(&mut self, msg: &msgs::FundingCreated, logger: &L) -> Result<(msgs::FundingSigned, ChannelMonitor<ChanSigner>), ChannelError> where L::Target: Logger {
		if self.channel_outbound {
			return Err(ChannelError::Close("Received funding_created for an outbound channel?"));
		}
		if self.channel_state != (ChannelState::OurInitSent as u32 | ChannelState::TheirInitSent as u32) {
			// BOLT 2 says that if we disconnect before we send funding_signed we SHOULD NOT
			// remember the channel, so it's safe to just send an error_message here and drop the
			// channel.
			return Err(ChannelError::Close("Received funding_created after we got the channel!"));
		}
		if self.commitment_secrets.get_min_seen_secret() != (1 << 48) ||
				self.cur_remote_commitment_transaction_number != INITIAL_COMMITMENT_NUMBER ||
				self.cur_local_commitment_transaction_number != INITIAL_COMMITMENT_NUMBER {
			panic!("Should not have advanced channel commitment tx numbers prior to funding_created");
		}

		let funding_txo = OutPoint::new(msg.funding_txid, msg.funding_output_index);
		self.funding_txo = Some(funding_txo.clone());

		let (remote_initial_commitment_tx, local_initial_commitment_tx, our_signature) = match self.funding_created_signature(&msg.signature, logger) {
			Ok(res) => res,
			Err(e) => {
				self.funding_txo = None;
				return Err(e);
			}
		};

		// Now that we're past error-generating stuff, update our local state:

		let their_pubkeys = self.their_pubkeys.as_ref().unwrap();
		let funding_redeemscript = self.get_funding_redeemscript();
		let funding_txo_script = funding_redeemscript.to_v0_p2wsh();
		macro_rules! create_monitor {
			() => { {
				let mut channel_monitor = ChannelMonitor::new(self.local_keys.clone(),
				                                              &self.shutdown_pubkey, self.our_to_self_delay,
				                                              &self.destination_script, (funding_txo, funding_txo_script.clone()),
				                                              &their_pubkeys.htlc_basepoint, &their_pubkeys.delayed_payment_basepoint,
				                                              self.their_to_self_delay, funding_redeemscript.clone(), self.channel_value_satoshis,
				                                              self.get_commitment_transaction_number_obscure_factor(),
				                                              local_initial_commitment_tx.clone());

				channel_monitor.provide_latest_remote_commitment_tx_info(&remote_initial_commitment_tx, Vec::new(), self.cur_remote_commitment_transaction_number, self.their_cur_commitment_point.unwrap(), logger);
				channel_monitor
			} }
		}

		self.channel_monitor = Some(create_monitor!());
		let channel_monitor = create_monitor!();

		self.channel_state = ChannelState::FundingSent as u32;
		self.channel_id = funding_txo.to_channel_id();
		self.cur_remote_commitment_transaction_number -= 1;
		self.cur_local_commitment_transaction_number -= 1;

		Ok((msgs::FundingSigned {
			channel_id: self.channel_id,
			signature: our_signature
		}, channel_monitor))
	}

	/// Handles a funding_signed message from the remote end.
	/// If this call is successful, broadcast the funding transaction (and not before!)
	pub fn funding_signed<L: Deref>(&mut self, msg: &msgs::FundingSigned, logger: &L) -> Result<ChannelMonitor<ChanSigner>, ChannelError> where L::Target: Logger {
		if !self.channel_outbound {
			return Err(ChannelError::Close("Received funding_signed for an inbound channel?"));
		}
		if self.channel_state & !(ChannelState::MonitorUpdateFailed as u32) != ChannelState::FundingCreated as u32 {
			return Err(ChannelError::Close("Received funding_signed in strange state!"));
		}
		if self.commitment_secrets.get_min_seen_secret() != (1 << 48) ||
				self.cur_remote_commitment_transaction_number != INITIAL_COMMITMENT_NUMBER ||
				self.cur_local_commitment_transaction_number != INITIAL_COMMITMENT_NUMBER {
			panic!("Should not have advanced channel commitment tx numbers prior to funding_created");
		}

		let funding_script = self.get_funding_redeemscript();

		let remote_keys = self.build_remote_transaction_keys()?;
		let remote_initial_commitment_tx = self.build_commitment_transaction(self.cur_remote_commitment_transaction_number, &remote_keys, false, false, self.feerate_per_kw, logger).0;

		let local_keys = self.build_local_transaction_keys(self.cur_local_commitment_transaction_number)?;
		let local_initial_commitment_tx = self.build_commitment_transaction(self.cur_local_commitment_transaction_number, &local_keys, true, false, self.feerate_per_kw, logger).0;
		let local_sighash = hash_to_message!(&bip143::SighashComponents::new(&local_initial_commitment_tx).sighash_all(&local_initial_commitment_tx.input[0], &funding_script, self.channel_value_satoshis)[..]);

		let their_funding_pubkey = &self.their_pubkeys.as_ref().unwrap().funding_pubkey;

		// They sign the "local" commitment transaction, allowing us to broadcast the tx if we wish.
		if let Err(_) = self.secp_ctx.verify(&local_sighash, &msg.signature, their_funding_pubkey) {
			return Err(ChannelError::Close("Invalid funding_signed signature from peer"));
		}

		let their_pubkeys = self.their_pubkeys.as_ref().unwrap();
		let funding_redeemscript = self.get_funding_redeemscript();
		let funding_txo = self.funding_txo.as_ref().unwrap();
		let funding_txo_script = funding_redeemscript.to_v0_p2wsh();
		macro_rules! create_monitor {
			() => { {
				let local_commitment_tx = LocalCommitmentTransaction::new_missing_local_sig(local_initial_commitment_tx.clone(), msg.signature.clone(), &PublicKey::from_secret_key(&self.secp_ctx, self.local_keys.funding_key()), their_funding_pubkey, local_keys.clone(), self.feerate_per_kw, Vec::new());
				let mut channel_monitor = ChannelMonitor::new(self.local_keys.clone(),
				                                              &self.shutdown_pubkey, self.our_to_self_delay,
				                                              &self.destination_script, (funding_txo.clone(), funding_txo_script.clone()),
				                                              &their_pubkeys.htlc_basepoint, &their_pubkeys.delayed_payment_basepoint,
				                                              self.their_to_self_delay, funding_redeemscript.clone(), self.channel_value_satoshis,
				                                              self.get_commitment_transaction_number_obscure_factor(),
				                                              local_commitment_tx);

				channel_monitor.provide_latest_remote_commitment_tx_info(&remote_initial_commitment_tx, Vec::new(), self.cur_remote_commitment_transaction_number, self.their_cur_commitment_point.unwrap(), logger);

				channel_monitor
			} }
		}

		self.channel_monitor = Some(create_monitor!());
		let channel_monitor = create_monitor!();

		assert_eq!(self.channel_state & (ChannelState::MonitorUpdateFailed as u32), 0); // We have no had any monitor(s) yet to fail update!
		self.channel_state = ChannelState::FundingSent as u32;
		self.cur_local_commitment_transaction_number -= 1;
		self.cur_remote_commitment_transaction_number -= 1;

		Ok(channel_monitor)
	}

	pub fn funding_locked(&mut self, msg: &msgs::FundingLocked) -> Result<(), ChannelError> {
		if self.channel_state & (ChannelState::PeerDisconnected as u32) == ChannelState::PeerDisconnected as u32 {
			return Err(ChannelError::Close("Peer sent funding_locked when we needed a channel_reestablish"));
		}

		let non_shutdown_state = self.channel_state & (!MULTI_STATE_FLAGS);

		if non_shutdown_state == ChannelState::FundingSent as u32 {
			self.channel_state |= ChannelState::TheirFundingLocked as u32;
		} else if non_shutdown_state == (ChannelState::FundingSent as u32 | ChannelState::OurFundingLocked as u32) {
			self.channel_state = ChannelState::ChannelFunded as u32 | (self.channel_state & MULTI_STATE_FLAGS);
			self.update_time_counter += 1;
		} else if (self.channel_state & (ChannelState::ChannelFunded as u32) != 0 &&
				 // Note that funding_signed/funding_created will have decremented both by 1!
				 self.cur_local_commitment_transaction_number == INITIAL_COMMITMENT_NUMBER - 1 &&
				 self.cur_remote_commitment_transaction_number == INITIAL_COMMITMENT_NUMBER - 1) ||
				// If we reconnected before sending our funding locked they may still resend theirs:
				(self.channel_state & (ChannelState::FundingSent as u32 | ChannelState::TheirFundingLocked as u32) ==
				                      (ChannelState::FundingSent as u32 | ChannelState::TheirFundingLocked as u32)) {
			if self.their_cur_commitment_point != Some(msg.next_per_commitment_point) {
				return Err(ChannelError::Close("Peer sent a reconnect funding_locked with a different point"));
			}
			// They probably disconnected/reconnected and re-sent the funding_locked, which is required
			return Ok(());
		} else {
			return Err(ChannelError::Close("Peer sent a funding_locked at a strange time"));
		}

		self.their_prev_commitment_point = self.their_cur_commitment_point;
		self.their_cur_commitment_point = Some(msg.next_per_commitment_point);
		Ok(())
	}

	/// Returns (inbound_htlc_count, htlc_inbound_value_msat)
	fn get_inbound_pending_htlc_stats(&self) -> (u32, u64) {
		let mut htlc_inbound_value_msat = 0;
		for ref htlc in self.pending_inbound_htlcs.iter() {
			htlc_inbound_value_msat += htlc.amount_msat;
		}
		(self.pending_inbound_htlcs.len() as u32, htlc_inbound_value_msat)
	}

	/// Returns (outbound_htlc_count, htlc_outbound_value_msat) *including* pending adds in our
	/// holding cell.
	fn get_outbound_pending_htlc_stats(&self) -> (u32, u64) {
		let mut htlc_outbound_value_msat = 0;
		for ref htlc in self.pending_outbound_htlcs.iter() {
			htlc_outbound_value_msat += htlc.amount_msat;
		}

		let mut htlc_outbound_count = self.pending_outbound_htlcs.len();
		for update in self.holding_cell_htlc_updates.iter() {
			if let &HTLCUpdateAwaitingACK::AddHTLC { ref amount_msat, .. } = update {
				htlc_outbound_count += 1;
				htlc_outbound_value_msat += amount_msat;
			}
		}

		(htlc_outbound_count as u32, htlc_outbound_value_msat)
	}

	/// Get the available (ie not including pending HTLCs) inbound and outbound balance in msat.
	/// Doesn't bother handling the
	/// if-we-removed-it-already-but-haven't-fully-resolved-they-can-still-send-an-inbound-HTLC
	/// corner case properly.
	pub fn get_inbound_outbound_available_balance_msat(&self) -> (u64, u64) {
		// Note that we have to handle overflow due to the above case.
		(cmp::min(self.channel_value_satoshis as i64 * 1000 - self.value_to_self_msat as i64 - self.get_inbound_pending_htlc_stats().1 as i64, 0) as u64,
		cmp::min(self.value_to_self_msat as i64 - self.get_outbound_pending_htlc_stats().1 as i64, 0) as u64)
	}

	pub fn update_add_htlc(&mut self, msg: &msgs::UpdateAddHTLC, pending_forward_state: PendingHTLCStatus) -> Result<(), ChannelError> {
		if (self.channel_state & (ChannelState::ChannelFunded as u32 | ChannelState::RemoteShutdownSent as u32)) != (ChannelState::ChannelFunded as u32) {
			return Err(ChannelError::Close("Got add HTLC message when channel was not in an operational state"));
		}
		if self.channel_state & (ChannelState::PeerDisconnected as u32) == ChannelState::PeerDisconnected as u32 {
			return Err(ChannelError::Close("Peer sent update_add_htlc when we needed a channel_reestablish"));
		}
		if msg.amount_msat > self.channel_value_satoshis * 1000 {
			return Err(ChannelError::Close("Remote side tried to send more than the total value of the channel"));
		}
		if msg.amount_msat == 0 {
			return Err(ChannelError::Close("Remote side tried to send a 0-msat HTLC"));
		}
		if msg.amount_msat < self.our_htlc_minimum_msat {
			return Err(ChannelError::Close("Remote side tried to send less than our minimum HTLC value"));
		}

		let (inbound_htlc_count, htlc_inbound_value_msat) = self.get_inbound_pending_htlc_stats();
		if inbound_htlc_count + 1 > OUR_MAX_HTLCS as u32 {
			return Err(ChannelError::Close("Remote tried to push more than our max accepted HTLCs"));
		}
		// Check our_max_htlc_value_in_flight_msat
		if htlc_inbound_value_msat + msg.amount_msat > Channel::<ChanSigner>::get_our_max_htlc_value_in_flight_msat(self.channel_value_satoshis) {
			return Err(ChannelError::Close("Remote HTLC add would put them over our max HTLC value"));
		}
		// Check remote_channel_reserve_satoshis (we're getting paid, so they have to at least meet
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
			if let OutboundHTLCState::AwaitingRemoteRevokeToRemove(None) = htlc.state {
				removed_outbound_total_msat += htlc.amount_msat;
			} else if let OutboundHTLCState::AwaitingRemovedRemoteRevoke(None) = htlc.state {
				removed_outbound_total_msat += htlc.amount_msat;
			}
		}
		if htlc_inbound_value_msat + msg.amount_msat + self.value_to_self_msat > (self.channel_value_satoshis - Channel::<ChanSigner>::get_remote_channel_reserve_satoshis(self.channel_value_satoshis)) * 1000 + removed_outbound_total_msat {
			return Err(ChannelError::Close("Remote HTLC add would put them under their reserve value"));
		}
		if self.next_remote_htlc_id != msg.htlc_id {
			return Err(ChannelError::Close("Remote skipped HTLC ID"));
		}
		if msg.cltv_expiry >= 500000000 {
			return Err(ChannelError::Close("Remote provided CLTV expiry in seconds instead of block height"));
		}

		if self.channel_state & ChannelState::LocalShutdownSent as u32 != 0 {
			if let PendingHTLCStatus::Forward(_) = pending_forward_state {
				panic!("ChannelManager shouldn't be trying to add a forwardable HTLC after we've started closing");
			}
		}

		// Now update local state:
		self.next_remote_htlc_id += 1;
		self.pending_inbound_htlcs.push(InboundHTLCOutput {
			htlc_id: msg.htlc_id,
			amount_msat: msg.amount_msat,
			payment_hash: msg.payment_hash,
			cltv_expiry: msg.cltv_expiry,
			state: InboundHTLCState::RemoteAnnounced(pending_forward_state),
		});
		Ok(())
	}

	/// Marks an outbound HTLC which we have received update_fail/fulfill/malformed
	#[inline]
	fn mark_outbound_htlc_removed(&mut self, htlc_id: u64, check_preimage: Option<PaymentHash>, fail_reason: Option<HTLCFailReason>) -> Result<&HTLCSource, ChannelError> {
		for htlc in self.pending_outbound_htlcs.iter_mut() {
			if htlc.htlc_id == htlc_id {
				match check_preimage {
					None => {},
					Some(payment_hash) =>
						if payment_hash != htlc.payment_hash {
							return Err(ChannelError::Close("Remote tried to fulfill HTLC with an incorrect preimage"));
						}
				};
				match htlc.state {
					OutboundHTLCState::LocalAnnounced(_) =>
						return Err(ChannelError::Close("Remote tried to fulfill/fail HTLC before it had been committed")),
					OutboundHTLCState::Committed => {
						htlc.state = OutboundHTLCState::RemoteRemoved(fail_reason);
					},
					OutboundHTLCState::AwaitingRemoteRevokeToRemove(_) | OutboundHTLCState::AwaitingRemovedRemoteRevoke(_) | OutboundHTLCState::RemoteRemoved(_) =>
						return Err(ChannelError::Close("Remote tried to fulfill/fail HTLC that they'd already fulfilled/failed")),
				}
				return Ok(&htlc.source);
			}
		}
		Err(ChannelError::Close("Remote tried to fulfill/fail an HTLC we couldn't find"))
	}

	pub fn update_fulfill_htlc(&mut self, msg: &msgs::UpdateFulfillHTLC) -> Result<HTLCSource, ChannelError> {
		if (self.channel_state & (ChannelState::ChannelFunded as u32)) != (ChannelState::ChannelFunded as u32) {
			return Err(ChannelError::Close("Got fulfill HTLC message when channel was not in an operational state"));
		}
		if self.channel_state & (ChannelState::PeerDisconnected as u32) == ChannelState::PeerDisconnected as u32 {
			return Err(ChannelError::Close("Peer sent update_fulfill_htlc when we needed a channel_reestablish"));
		}

		let payment_hash = PaymentHash(Sha256::hash(&msg.payment_preimage.0[..]).into_inner());
		self.mark_outbound_htlc_removed(msg.htlc_id, Some(payment_hash), None).map(|source| source.clone())
	}

	pub fn update_fail_htlc(&mut self, msg: &msgs::UpdateFailHTLC, fail_reason: HTLCFailReason) -> Result<(), ChannelError> {
		if (self.channel_state & (ChannelState::ChannelFunded as u32)) != (ChannelState::ChannelFunded as u32) {
			return Err(ChannelError::Close("Got fail HTLC message when channel was not in an operational state"));
		}
		if self.channel_state & (ChannelState::PeerDisconnected as u32) == ChannelState::PeerDisconnected as u32 {
			return Err(ChannelError::Close("Peer sent update_fail_htlc when we needed a channel_reestablish"));
		}

		self.mark_outbound_htlc_removed(msg.htlc_id, None, Some(fail_reason))?;
		Ok(())
	}

	pub fn update_fail_malformed_htlc(&mut self, msg: &msgs::UpdateFailMalformedHTLC, fail_reason: HTLCFailReason) -> Result<(), ChannelError> {
		if (self.channel_state & (ChannelState::ChannelFunded as u32)) != (ChannelState::ChannelFunded as u32) {
			return Err(ChannelError::Close("Got fail malformed HTLC message when channel was not in an operational state"));
		}
		if self.channel_state & (ChannelState::PeerDisconnected as u32) == ChannelState::PeerDisconnected as u32 {
			return Err(ChannelError::Close("Peer sent update_fail_malformed_htlc when we needed a channel_reestablish"));
		}

		self.mark_outbound_htlc_removed(msg.htlc_id, None, Some(fail_reason))?;
		Ok(())
	}

	pub fn commitment_signed<F: Deref, L: Deref>(&mut self, msg: &msgs::CommitmentSigned, fee_estimator: &F, logger: &L) -> Result<(msgs::RevokeAndACK, Option<msgs::CommitmentSigned>, Option<msgs::ClosingSigned>, ChannelMonitorUpdate), (Option<ChannelMonitorUpdate>, ChannelError)>
	where F::Target: FeeEstimator,
				L::Target: Logger
	{
		if (self.channel_state & (ChannelState::ChannelFunded as u32)) != (ChannelState::ChannelFunded as u32) {
			return Err((None, ChannelError::Close("Got commitment signed message when channel was not in an operational state")));
		}
		if self.channel_state & (ChannelState::PeerDisconnected as u32) == ChannelState::PeerDisconnected as u32 {
			return Err((None, ChannelError::Close("Peer sent commitment_signed when we needed a channel_reestablish")));
		}
		if self.channel_state & BOTH_SIDES_SHUTDOWN_MASK == BOTH_SIDES_SHUTDOWN_MASK && self.last_sent_closing_fee.is_some() {
			return Err((None, ChannelError::Close("Peer sent commitment_signed after we'd started exchanging closing_signeds")));
		}

		let funding_script = self.get_funding_redeemscript();

		let local_keys = self.build_local_transaction_keys(self.cur_local_commitment_transaction_number).map_err(|e| (None, e))?;

		let mut update_fee = false;
		let feerate_per_kw = if !self.channel_outbound && self.pending_update_fee.is_some() {
			update_fee = true;
			self.pending_update_fee.unwrap()
		} else {
			self.feerate_per_kw
		};

		let mut local_commitment_tx = {
			let mut commitment_tx = self.build_commitment_transaction(self.cur_local_commitment_transaction_number, &local_keys, true, false, feerate_per_kw, logger);
			let htlcs_cloned: Vec<_> = commitment_tx.2.drain(..).map(|htlc| (htlc.0, htlc.1.map(|h| h.clone()))).collect();
			(commitment_tx.0, commitment_tx.1, htlcs_cloned)
		};
		let local_commitment_txid = local_commitment_tx.0.txid();
		let local_sighash = hash_to_message!(&bip143::SighashComponents::new(&local_commitment_tx.0).sighash_all(&local_commitment_tx.0.input[0], &funding_script, self.channel_value_satoshis)[..]);
		log_trace!(logger, "Checking commitment tx signature {} by key {} against tx {} (sighash {}) with redeemscript {}", log_bytes!(msg.signature.serialize_compact()[..]), log_bytes!(self.their_funding_pubkey().serialize()), encode::serialize_hex(&local_commitment_tx.0), log_bytes!(local_sighash[..]), encode::serialize_hex(&funding_script));
		if let Err(_) = self.secp_ctx.verify(&local_sighash, &msg.signature, &self.their_funding_pubkey()) {
			return Err((None, ChannelError::Close("Invalid commitment tx signature from peer")));
		}

		//If channel fee was updated by funder confirm funder can afford the new fee rate when applied to the current local commitment transaction
		if update_fee {
			let num_htlcs = local_commitment_tx.1;
			let total_fee: u64 = feerate_per_kw as u64 * (COMMITMENT_TX_BASE_WEIGHT + (num_htlcs as u64) * COMMITMENT_TX_WEIGHT_PER_HTLC) / 1000;

			let remote_reserve_we_require = Channel::<ChanSigner>::get_remote_channel_reserve_satoshis(self.channel_value_satoshis);
			if self.channel_value_satoshis - self.value_to_self_msat / 1000 < total_fee + remote_reserve_we_require {
				return Err((None, ChannelError::Close("Funding remote cannot afford proposed new fee")));
			}
		}

		if msg.htlc_signatures.len() != local_commitment_tx.1 {
			return Err((None, ChannelError::Close("Got wrong number of HTLC signatures from remote")));
		}

		// TODO: Merge these two, sadly they are currently both required to be passed separately to
		// ChannelMonitor:
		let mut htlcs_without_source = Vec::with_capacity(local_commitment_tx.2.len());
		let mut htlcs_and_sigs = Vec::with_capacity(local_commitment_tx.2.len());
		for (idx, (htlc, source)) in local_commitment_tx.2.drain(..).enumerate() {
			if let Some(_) = htlc.transaction_output_index {
				let htlc_tx = self.build_htlc_transaction(&local_commitment_txid, &htlc, true, &local_keys, feerate_per_kw);
				let htlc_redeemscript = chan_utils::get_htlc_redeemscript(&htlc, &local_keys);
				let htlc_sighash = hash_to_message!(&bip143::SighashComponents::new(&htlc_tx).sighash_all(&htlc_tx.input[0], &htlc_redeemscript, htlc.amount_msat / 1000)[..]);
				log_trace!(logger, "Checking HTLC tx signature {} by key {} against tx {} (sighash {}) with redeemscript {}", log_bytes!(msg.htlc_signatures[idx].serialize_compact()[..]), log_bytes!(local_keys.b_htlc_key.serialize()), encode::serialize_hex(&htlc_tx), log_bytes!(htlc_sighash[..]), encode::serialize_hex(&htlc_redeemscript));
				if let Err(_) = self.secp_ctx.verify(&htlc_sighash, &msg.htlc_signatures[idx], &local_keys.b_htlc_key) {
					return Err((None, ChannelError::Close("Invalid HTLC tx signature from peer")));
				}
				htlcs_without_source.push((htlc.clone(), Some(msg.htlc_signatures[idx])));
				htlcs_and_sigs.push((htlc, Some(msg.htlc_signatures[idx]), source));
			} else {
				htlcs_without_source.push((htlc.clone(), None));
				htlcs_and_sigs.push((htlc, None, source));
			}
		}

		let next_per_commitment_point = PublicKey::from_secret_key(&self.secp_ctx, &self.build_local_commitment_secret(self.cur_local_commitment_transaction_number - 1));
		let per_commitment_secret = chan_utils::build_commitment_secret(self.local_keys.commitment_seed(), self.cur_local_commitment_transaction_number + 1);

		// Update state now that we've passed all the can-fail calls...
		let mut need_our_commitment = false;
		if !self.channel_outbound {
			if let Some(fee_update) = self.pending_update_fee {
				self.feerate_per_kw = fee_update;
				// We later use the presence of pending_update_fee to indicate we should generate a
				// commitment_signed upon receipt of revoke_and_ack, so we can only set it to None
				// if we're not awaiting a revoke (ie will send a commitment_signed now).
				if (self.channel_state & ChannelState::AwaitingRemoteRevoke as u32) == 0 {
					need_our_commitment = true;
					self.pending_update_fee = None;
				}
			}
		}

		let their_funding_pubkey = self.their_pubkeys.as_ref().unwrap().funding_pubkey;

		self.latest_monitor_update_id += 1;
		let mut monitor_update = ChannelMonitorUpdate {
			update_id: self.latest_monitor_update_id,
			updates: vec![ChannelMonitorUpdateStep::LatestLocalCommitmentTXInfo {
				commitment_tx: LocalCommitmentTransaction::new_missing_local_sig(local_commitment_tx.0, msg.signature.clone(), &PublicKey::from_secret_key(&self.secp_ctx, self.local_keys.funding_key()), &their_funding_pubkey, local_keys, self.feerate_per_kw, htlcs_without_source),
				htlc_outputs: htlcs_and_sigs
			}]
		};
		self.channel_monitor.as_mut().unwrap().update_monitor_ooo(monitor_update.clone(), logger).unwrap();

		for htlc in self.pending_inbound_htlcs.iter_mut() {
			let new_forward = if let &InboundHTLCState::RemoteAnnounced(ref forward_info) = &htlc.state {
				Some(forward_info.clone())
			} else { None };
			if let Some(forward_info) = new_forward {
				htlc.state = InboundHTLCState::AwaitingRemoteRevokeToAnnounce(forward_info);
				need_our_commitment = true;
			}
		}
		for htlc in self.pending_outbound_htlcs.iter_mut() {
			if let Some(fail_reason) = if let &mut OutboundHTLCState::RemoteRemoved(ref mut fail_reason) = &mut htlc.state {
				Some(fail_reason.take())
			} else { None } {
				htlc.state = OutboundHTLCState::AwaitingRemoteRevokeToRemove(fail_reason);
				need_our_commitment = true;
			}
		}

		self.cur_local_commitment_transaction_number -= 1;
		// Note that if we need_our_commitment & !AwaitingRemoteRevoke we'll call
		// send_commitment_no_status_check() next which will reset this to RAAFirst.
		self.resend_order = RAACommitmentOrder::CommitmentFirst;

		if (self.channel_state & ChannelState::MonitorUpdateFailed as u32) != 0 {
			// In case we initially failed monitor updating without requiring a response, we need
			// to make sure the RAA gets sent first.
			self.monitor_pending_revoke_and_ack = true;
			if need_our_commitment && (self.channel_state & (ChannelState::AwaitingRemoteRevoke as u32)) == 0 {
				// If we were going to send a commitment_signed after the RAA, go ahead and do all
				// the corresponding HTLC status updates so that get_last_commitment_update
				// includes the right HTLCs.
				self.monitor_pending_commitment_signed = true;
				let (_, mut additional_update) = self.send_commitment_no_status_check(logger).map_err(|e| (None, e))?;
				// send_commitment_no_status_check may bump latest_monitor_id but we want them to be
				// strictly increasing by one, so decrement it here.
				self.latest_monitor_update_id = monitor_update.update_id;
				monitor_update.updates.append(&mut additional_update.updates);
			}
			// TODO: Call maybe_propose_first_closing_signed on restoration (or call it here and
			// re-send the message on restoration)
			return Err((Some(monitor_update), ChannelError::Ignore("Previous monitor update failure prevented generation of RAA")));
		}

		let (our_commitment_signed, closing_signed) = if need_our_commitment && (self.channel_state & (ChannelState::AwaitingRemoteRevoke as u32)) == 0 {
			// If we're AwaitingRemoteRevoke we can't send a new commitment here, but that's ok -
			// we'll send one right away when we get the revoke_and_ack when we
			// free_holding_cell_htlcs().
			let (msg, mut additional_update) = self.send_commitment_no_status_check(logger).map_err(|e| (None, e))?;
			// send_commitment_no_status_check may bump latest_monitor_id but we want them to be
			// strictly increasing by one, so decrement it here.
			self.latest_monitor_update_id = monitor_update.update_id;
			monitor_update.updates.append(&mut additional_update.updates);
			(Some(msg), None)
		} else if !need_our_commitment {
			(None, self.maybe_propose_first_closing_signed(fee_estimator))
		} else { (None, None) };

		Ok((msgs::RevokeAndACK {
			channel_id: self.channel_id,
			per_commitment_secret: per_commitment_secret,
			next_per_commitment_point: next_per_commitment_point,
		}, our_commitment_signed, closing_signed, monitor_update))
	}

	/// Used to fulfill holding_cell_htlcs when we get a remote ack (or implicitly get it by them
	/// fulfilling or failing the last pending HTLC)
	fn free_holding_cell_htlcs<L: Deref>(&mut self, logger: &L) -> Result<Option<(msgs::CommitmentUpdate, ChannelMonitorUpdate)>, ChannelError> where L::Target: Logger {
		assert_eq!(self.channel_state & ChannelState::MonitorUpdateFailed as u32, 0);
		if self.holding_cell_htlc_updates.len() != 0 || self.holding_cell_update_fee.is_some() {
			log_trace!(logger, "Freeing holding cell with {} HTLC updates{}", self.holding_cell_htlc_updates.len(), if self.holding_cell_update_fee.is_some() { " and a fee update" } else { "" });

			let mut monitor_update = ChannelMonitorUpdate {
				update_id: self.latest_monitor_update_id + 1, // We don't increment this yet!
				updates: Vec::new(),
			};

			let mut htlc_updates = Vec::new();
			mem::swap(&mut htlc_updates, &mut self.holding_cell_htlc_updates);
			let mut update_add_htlcs = Vec::with_capacity(htlc_updates.len());
			let mut update_fulfill_htlcs = Vec::with_capacity(htlc_updates.len());
			let mut update_fail_htlcs = Vec::with_capacity(htlc_updates.len());
			let mut err = None;
			for htlc_update in htlc_updates.drain(..) {
				// Note that this *can* fail, though it should be due to rather-rare conditions on
				// fee races with adding too many outputs which push our total payments just over
				// the limit. In case it's less rare than I anticipate, we may want to revisit
				// handling this case better and maybe fulfilling some of the HTLCs while attempting
				// to rebalance channels.
				if err.is_some() { // We're back to AwaitingRemoteRevoke (or are about to fail the channel)
					self.holding_cell_htlc_updates.push(htlc_update);
				} else {
					match &htlc_update {
						&HTLCUpdateAwaitingACK::AddHTLC {amount_msat, cltv_expiry, ref payment_hash, ref source, ref onion_routing_packet, ..} => {
							match self.send_htlc(amount_msat, *payment_hash, cltv_expiry, source.clone(), onion_routing_packet.clone()) {
								Ok(update_add_msg_option) => update_add_htlcs.push(update_add_msg_option.unwrap()),
								Err(e) => {
									match e {
										ChannelError::Ignore(ref msg) => {
											log_info!(logger, "Failed to send HTLC with payment_hash {} due to {}", log_bytes!(payment_hash.0), msg);
										},
										_ => {
											log_info!(logger, "Failed to send HTLC with payment_hash {} resulting in a channel closure during holding_cell freeing", log_bytes!(payment_hash.0));
										},
									}
									err = Some(e);
								}
							}
						},
						&HTLCUpdateAwaitingACK::ClaimHTLC { ref payment_preimage, htlc_id, .. } => {
							match self.get_update_fulfill_htlc(htlc_id, *payment_preimage, logger) {
								Ok((update_fulfill_msg_option, additional_monitor_update_opt)) => {
									update_fulfill_htlcs.push(update_fulfill_msg_option.unwrap());
									if let Some(mut additional_monitor_update) = additional_monitor_update_opt {
										monitor_update.updates.append(&mut additional_monitor_update.updates);
									}
								},
								Err(e) => {
									if let ChannelError::Ignore(_) = e {}
									else {
										panic!("Got a non-IgnoreError action trying to fulfill holding cell HTLC");
									}
								}
							}
						},
						&HTLCUpdateAwaitingACK::FailHTLC { htlc_id, ref err_packet } => {
							match self.get_update_fail_htlc(htlc_id, err_packet.clone()) {
								Ok(update_fail_msg_option) => update_fail_htlcs.push(update_fail_msg_option.unwrap()),
								Err(e) => {
									if let ChannelError::Ignore(_) = e {}
									else {
										panic!("Got a non-IgnoreError action trying to fail holding cell HTLC");
									}
								}
							}
						},
					}
					if err.is_some() {
						self.holding_cell_htlc_updates.push(htlc_update);
						if let Some(ChannelError::Ignore(_)) = err {
							// If we failed to add the HTLC, but got an Ignore error, we should
							// still send the new commitment_signed, so reset the err to None.
							err = None;
						}
					}
				}
			}
			//TODO: Need to examine the type of err - if it's a fee issue or similar we may want to
			//fail it back the route, if it's a temporary issue we can ignore it...
			match err {
				None => {
					if update_add_htlcs.is_empty() && update_fulfill_htlcs.is_empty() && update_fail_htlcs.is_empty() && self.holding_cell_update_fee.is_none() {
						// This should never actually happen and indicates we got some Errs back
						// from update_fulfill_htlc/update_fail_htlc, but we handle it anyway in
						// case there is some strange way to hit duplicate HTLC removes.
						return Ok(None);
					}
					let update_fee = if let Some(feerate) = self.holding_cell_update_fee {
							self.pending_update_fee = self.holding_cell_update_fee.take();
							Some(msgs::UpdateFee {
								channel_id: self.channel_id,
								feerate_per_kw: feerate as u32,
							})
						} else {
							None
						};

					let (commitment_signed, mut additional_update) = self.send_commitment_no_status_check(logger)?;
					// send_commitment_no_status_check and get_update_fulfill_htlc may bump latest_monitor_id
					// but we want them to be strictly increasing by one, so reset it here.
					self.latest_monitor_update_id = monitor_update.update_id;
					monitor_update.updates.append(&mut additional_update.updates);

					Ok(Some((msgs::CommitmentUpdate {
						update_add_htlcs,
						update_fulfill_htlcs,
						update_fail_htlcs,
						update_fail_malformed_htlcs: Vec::new(),
						update_fee: update_fee,
						commitment_signed,
					}, monitor_update)))
				},
				Some(e) => Err(e)
			}
		} else {
			Ok(None)
		}
	}

	/// Handles receiving a remote's revoke_and_ack. Note that we may return a new
	/// commitment_signed message here in case we had pending outbound HTLCs to add which were
	/// waiting on this revoke_and_ack. The generation of this new commitment_signed may also fail,
	/// generating an appropriate error *after* the channel state has been updated based on the
	/// revoke_and_ack message.
	pub fn revoke_and_ack<F: Deref, L: Deref>(&mut self, msg: &msgs::RevokeAndACK, fee_estimator: &F, logger: &L) -> Result<(Option<msgs::CommitmentUpdate>, Vec<(PendingHTLCInfo, u64)>, Vec<(HTLCSource, PaymentHash, HTLCFailReason)>, Option<msgs::ClosingSigned>, ChannelMonitorUpdate), ChannelError>
		where F::Target: FeeEstimator,
					L::Target: Logger,
	{
		if (self.channel_state & (ChannelState::ChannelFunded as u32)) != (ChannelState::ChannelFunded as u32) {
			return Err(ChannelError::Close("Got revoke/ACK message when channel was not in an operational state"));
		}
		if self.channel_state & (ChannelState::PeerDisconnected as u32) == ChannelState::PeerDisconnected as u32 {
			return Err(ChannelError::Close("Peer sent revoke_and_ack when we needed a channel_reestablish"));
		}
		if self.channel_state & BOTH_SIDES_SHUTDOWN_MASK == BOTH_SIDES_SHUTDOWN_MASK && self.last_sent_closing_fee.is_some() {
			return Err(ChannelError::Close("Peer sent revoke_and_ack after we'd started exchanging closing_signeds"));
		}

		if let Some(their_prev_commitment_point) = self.their_prev_commitment_point {
			if PublicKey::from_secret_key(&self.secp_ctx, &secp_check!(SecretKey::from_slice(&msg.per_commitment_secret), "Peer provided an invalid per_commitment_secret")) != their_prev_commitment_point {
				return Err(ChannelError::Close("Got a revoke commitment secret which didn't correspond to their current pubkey"));
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
			return Err(ChannelError::Close("Received an unexpected revoke_and_ack"));
		}

		self.commitment_secrets.provide_secret(self.cur_remote_commitment_transaction_number + 1, msg.per_commitment_secret)
			.map_err(|_| ChannelError::Close("Previous secrets did not match new one"))?;
		self.latest_monitor_update_id += 1;
		let mut monitor_update = ChannelMonitorUpdate {
			update_id: self.latest_monitor_update_id,
			updates: vec![ChannelMonitorUpdateStep::CommitmentSecret {
				idx: self.cur_remote_commitment_transaction_number + 1,
				secret: msg.per_commitment_secret,
			}],
		};
		self.channel_monitor.as_mut().unwrap().update_monitor_ooo(monitor_update.clone(), logger).unwrap();

		// Update state now that we've passed all the can-fail calls...
		// (note that we may still fail to generate the new commitment_signed message, but that's
		// OK, we step the channel here and *then* if the new generation fails we can fail the
		// channel based on that, but stepping stuff here should be safe either way.
		self.channel_state &= !(ChannelState::AwaitingRemoteRevoke as u32);
		self.their_prev_commitment_point = self.their_cur_commitment_point;
		self.their_cur_commitment_point = Some(msg.next_per_commitment_point);
		self.cur_remote_commitment_transaction_number -= 1;

		log_trace!(logger, "Updating HTLCs on receipt of RAA...");
		let mut to_forward_infos = Vec::new();
		let mut revoked_htlcs = Vec::new();
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
				if let &OutboundHTLCState::AwaitingRemovedRemoteRevoke(ref fail_reason) = &htlc.state {
					log_trace!(logger, " ...removing outbound AwaitingRemovedRemoteRevoke {}", log_bytes!(htlc.payment_hash.0));
					if let Some(reason) = fail_reason.clone() { // We really want take() here, but, again, non-mut ref :(
						revoked_htlcs.push((htlc.source.clone(), htlc.payment_hash, reason));
					} else {
						// They fulfilled, so we sent them money
						value_to_self_msat_diff -= htlc.amount_msat as i64;
					}
					false
				} else { true }
			});
			for htlc in pending_inbound_htlcs.iter_mut() {
				let swap = if let &InboundHTLCState::AwaitingRemoteRevokeToAnnounce(_) = &htlc.state {
					log_trace!(logger, " ...promoting inbound AwaitingRemoteRevokeToAnnounce {} to Committed", log_bytes!(htlc.payment_hash.0));
					true
				} else if let &InboundHTLCState::AwaitingAnnouncedRemoteRevoke(_) = &htlc.state {
					log_trace!(logger, " ...promoting inbound AwaitingAnnouncedRemoteRevoke {} to Committed", log_bytes!(htlc.payment_hash.0));
					true
				} else { false };
				if swap {
					let mut state = InboundHTLCState::Committed;
					mem::swap(&mut state, &mut htlc.state);

					if let InboundHTLCState::AwaitingRemoteRevokeToAnnounce(forward_info) = state {
						htlc.state = InboundHTLCState::AwaitingAnnouncedRemoteRevoke(forward_info);
						require_commitment = true;
					} else if let InboundHTLCState::AwaitingAnnouncedRemoteRevoke(forward_info) = state {
						match forward_info {
							PendingHTLCStatus::Fail(fail_msg) => {
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
				if let Some(fail_reason) = if let &mut OutboundHTLCState::AwaitingRemoteRevokeToRemove(ref mut fail_reason) = &mut htlc.state {
					Some(fail_reason.take())
				} else { None } {
					log_trace!(logger, " ...promoting outbound AwaitingRemoteRevokeToRemove {} to AwaitingRemovedRemoteRevoke", log_bytes!(htlc.payment_hash.0));
					htlc.state = OutboundHTLCState::AwaitingRemovedRemoteRevoke(fail_reason);
					require_commitment = true;
				}
			}
		}
		self.value_to_self_msat = (self.value_to_self_msat as i64 + value_to_self_msat_diff) as u64;

		if self.channel_outbound {
			if let Some(feerate) = self.pending_update_fee.take() {
				self.feerate_per_kw = feerate;
			}
		} else {
			if let Some(feerate) = self.pending_update_fee {
				// Because a node cannot send two commitment_signeds in a row without getting a
				// revoke_and_ack from us (as it would otherwise not know the per_commitment_point
				// it should use to create keys with) and because a node can't send a
				// commitment_signed without changes, checking if the feerate is equal to the
				// pending feerate update is sufficient to detect require_commitment.
				if feerate == self.feerate_per_kw {
					require_commitment = true;
					self.pending_update_fee = None;
				}
			}
		}

		if (self.channel_state & ChannelState::MonitorUpdateFailed as u32) == ChannelState::MonitorUpdateFailed as u32 {
			// We can't actually generate a new commitment transaction (incl by freeing holding
			// cells) while we can't update the monitor, so we just return what we have.
			if require_commitment {
				self.monitor_pending_commitment_signed = true;
				// When the monitor updating is restored we'll call get_last_commitment_update(),
				// which does not update state, but we're definitely now awaiting a remote revoke
				// before we can step forward any more, so set it here.
				let (_, mut additional_update) = self.send_commitment_no_status_check(logger)?;
				// send_commitment_no_status_check may bump latest_monitor_id but we want them to be
				// strictly increasing by one, so decrement it here.
				self.latest_monitor_update_id = monitor_update.update_id;
				monitor_update.updates.append(&mut additional_update.updates);
			}
			self.monitor_pending_forwards.append(&mut to_forward_infos);
			self.monitor_pending_failures.append(&mut revoked_htlcs);
			return Ok((None, Vec::new(), Vec::new(), None, monitor_update))
		}

		match self.free_holding_cell_htlcs(logger)? {
			Some((mut commitment_update, mut additional_update)) => {
				commitment_update.update_fail_htlcs.reserve(update_fail_htlcs.len());
				for fail_msg in update_fail_htlcs.drain(..) {
					commitment_update.update_fail_htlcs.push(fail_msg);
				}
				commitment_update.update_fail_malformed_htlcs.reserve(update_fail_malformed_htlcs.len());
				for fail_msg in update_fail_malformed_htlcs.drain(..) {
					commitment_update.update_fail_malformed_htlcs.push(fail_msg);
				}

				// free_holding_cell_htlcs may bump latest_monitor_id multiple times but we want them to be
				// strictly increasing by one, so decrement it here.
				self.latest_monitor_update_id = monitor_update.update_id;
				monitor_update.updates.append(&mut additional_update.updates);

				Ok((Some(commitment_update), to_forward_infos, revoked_htlcs, None, monitor_update))
			},
			None => {
				if require_commitment {
					let (commitment_signed, mut additional_update) = self.send_commitment_no_status_check(logger)?;

					// send_commitment_no_status_check may bump latest_monitor_id but we want them to be
					// strictly increasing by one, so decrement it here.
					self.latest_monitor_update_id = monitor_update.update_id;
					monitor_update.updates.append(&mut additional_update.updates);

					Ok((Some(msgs::CommitmentUpdate {
						update_add_htlcs: Vec::new(),
						update_fulfill_htlcs: Vec::new(),
						update_fail_htlcs,
						update_fail_malformed_htlcs,
						update_fee: None,
						commitment_signed
					}), to_forward_infos, revoked_htlcs, None, monitor_update))
				} else {
					Ok((None, to_forward_infos, revoked_htlcs, self.maybe_propose_first_closing_signed(fee_estimator), monitor_update))
				}
			}
		}

	}

	/// Adds a pending update to this channel. See the doc for send_htlc for
	/// further details on the optionness of the return value.
	/// You MUST call send_commitment prior to any other calls on this Channel
	fn send_update_fee(&mut self, feerate_per_kw: u64) -> Option<msgs::UpdateFee> {
		if !self.channel_outbound {
			panic!("Cannot send fee from inbound channel");
		}
		if !self.is_usable() {
			panic!("Cannot update fee until channel is fully established and we haven't started shutting down");
		}
		if !self.is_live() {
			panic!("Cannot update fee while peer is disconnected/we're awaiting a monitor update (ChannelManager should have caught this)");
		}

		if (self.channel_state & (ChannelState::AwaitingRemoteRevoke as u32)) == (ChannelState::AwaitingRemoteRevoke as u32) {
			self.holding_cell_update_fee = Some(feerate_per_kw);
			return None;
		}

		debug_assert!(self.pending_update_fee.is_none());
		self.pending_update_fee = Some(feerate_per_kw);

		Some(msgs::UpdateFee {
			channel_id: self.channel_id,
			feerate_per_kw: feerate_per_kw as u32,
		})
	}

	pub fn send_update_fee_and_commit<L: Deref>(&mut self, feerate_per_kw: u64, logger: &L) -> Result<Option<(msgs::UpdateFee, msgs::CommitmentSigned, ChannelMonitorUpdate)>, ChannelError> where L::Target: Logger {
		match self.send_update_fee(feerate_per_kw) {
			Some(update_fee) => {
				let (commitment_signed, monitor_update) = self.send_commitment_no_status_check(logger)?;
				Ok(Some((update_fee, commitment_signed, monitor_update)))
			},
			None => Ok(None)
		}
	}

	/// Removes any uncommitted HTLCs, to be used on peer disconnection, including any pending
	/// HTLCs that we intended to add but haven't as we were waiting on a remote revoke.
	/// Returns the set of PendingHTLCStatuses from remote uncommitted HTLCs (which we're
	/// implicitly dropping) and the payment_hashes of HTLCs we tried to add but are dropping.
	/// No further message handling calls may be made until a channel_reestablish dance has
	/// completed.
	pub fn remove_uncommitted_htlcs_and_mark_paused<L: Deref>(&mut self, logger: &L) -> Vec<(HTLCSource, PaymentHash)> where L::Target: Logger {
		let mut outbound_drops = Vec::new();

		assert_eq!(self.channel_state & ChannelState::ShutdownComplete as u32, 0);
		if self.channel_state < ChannelState::FundingSent as u32 {
			self.channel_state = ChannelState::ShutdownComplete as u32;
			return outbound_drops;
		}
		// Upon reconnect we have to start the closing_signed dance over, but shutdown messages
		// will be retransmitted.
		self.last_sent_closing_fee = None;

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
		self.next_remote_htlc_id -= inbound_drop_count;

		for htlc in self.pending_outbound_htlcs.iter_mut() {
			if let OutboundHTLCState::RemoteRemoved(_) = htlc.state {
				// They sent us an update to remove this but haven't yet sent the corresponding
				// commitment_signed, we need to move it back to Committed and they can re-send
				// the update upon reconnection.
				htlc.state = OutboundHTLCState::Committed;
			}
		}

		self.holding_cell_htlc_updates.retain(|htlc_update| {
			match htlc_update {
				&HTLCUpdateAwaitingACK::AddHTLC { ref payment_hash, ref source, .. } => {
					outbound_drops.push((source.clone(), payment_hash.clone()));
					false
				},
				&HTLCUpdateAwaitingACK::ClaimHTLC {..} | &HTLCUpdateAwaitingACK::FailHTLC {..} => true,
			}
		});
		self.channel_state |= ChannelState::PeerDisconnected as u32;
		log_debug!(logger, "Peer disconnection resulted in {} remote-announced HTLC drops and {} waiting-to-locally-announced HTLC drops on channel {}", outbound_drops.len(), inbound_drop_count, log_bytes!(self.channel_id()));
		outbound_drops
	}

	/// Indicates that a ChannelMonitor update failed to be stored by the client and further
	/// updates are partially paused.
	/// This must be called immediately after the call which generated the ChannelMonitor update
	/// which failed. The messages which were generated from that call which generated the
	/// monitor update failure must *not* have been sent to the remote end, and must instead
	/// have been dropped. They will be regenerated when monitor_updating_restored is called.
	pub fn monitor_update_failed(&mut self, resend_raa: bool, resend_commitment: bool, mut pending_forwards: Vec<(PendingHTLCInfo, u64)>, mut pending_fails: Vec<(HTLCSource, PaymentHash, HTLCFailReason)>) {
		assert_eq!(self.channel_state & ChannelState::MonitorUpdateFailed as u32, 0);
		self.monitor_pending_revoke_and_ack = resend_raa;
		self.monitor_pending_commitment_signed = resend_commitment;
		assert!(self.monitor_pending_forwards.is_empty());
		mem::swap(&mut pending_forwards, &mut self.monitor_pending_forwards);
		assert!(self.monitor_pending_failures.is_empty());
		mem::swap(&mut pending_fails, &mut self.monitor_pending_failures);
		self.channel_state |= ChannelState::MonitorUpdateFailed as u32;
	}

	/// Indicates that the latest ChannelMonitor update has been committed by the client
	/// successfully and we should restore normal operation. Returns messages which should be sent
	/// to the remote side.
	pub fn monitor_updating_restored<L: Deref>(&mut self, logger: &L) -> (Option<msgs::RevokeAndACK>, Option<msgs::CommitmentUpdate>, RAACommitmentOrder, Vec<(PendingHTLCInfo, u64)>, Vec<(HTLCSource, PaymentHash, HTLCFailReason)>, bool, Option<msgs::FundingLocked>) where L::Target: Logger {
		assert_eq!(self.channel_state & ChannelState::MonitorUpdateFailed as u32, ChannelState::MonitorUpdateFailed as u32);
		self.channel_state &= !(ChannelState::MonitorUpdateFailed as u32);

		let needs_broadcast_safe = self.channel_state & (ChannelState::FundingSent as u32) != 0 && self.channel_outbound;

		// Because we will never generate a FundingBroadcastSafe event when we're in
		// MonitorUpdateFailed, if we assume the user only broadcast the funding transaction when
		// they received the FundingBroadcastSafe event, we can only ever hit
		// monitor_pending_funding_locked when we're an inbound channel which failed to persist the
		// monitor on funding_created, and we even got the funding transaction confirmed before the
		// monitor was persisted.
		let funding_locked = if self.monitor_pending_funding_locked {
			assert!(!self.channel_outbound, "Funding transaction broadcast without FundingBroadcastSafe!");
			self.monitor_pending_funding_locked = false;
			let next_per_commitment_secret = self.build_local_commitment_secret(self.cur_local_commitment_transaction_number);
			let next_per_commitment_point = PublicKey::from_secret_key(&self.secp_ctx, &next_per_commitment_secret);
			Some(msgs::FundingLocked {
				channel_id: self.channel_id(),
				next_per_commitment_point: next_per_commitment_point,
			})
		} else { None };

		let mut forwards = Vec::new();
		mem::swap(&mut forwards, &mut self.monitor_pending_forwards);
		let mut failures = Vec::new();
		mem::swap(&mut failures, &mut self.monitor_pending_failures);

		if self.channel_state & (ChannelState::PeerDisconnected as u32) != 0 {
			self.monitor_pending_revoke_and_ack = false;
			self.monitor_pending_commitment_signed = false;
			return (None, None, RAACommitmentOrder::RevokeAndACKFirst, forwards, failures, needs_broadcast_safe, funding_locked);
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
		log_trace!(logger, "Restored monitor updating resulting in {}{} commitment update and {} RAA, with {} first",
			if needs_broadcast_safe { "a funding broadcast safe, " } else { "" },
			if commitment_update.is_some() { "a" } else { "no" },
			if raa.is_some() { "an" } else { "no" },
			match order { RAACommitmentOrder::CommitmentFirst => "commitment", RAACommitmentOrder::RevokeAndACKFirst => "RAA"});
		(raa, commitment_update, order, forwards, failures, needs_broadcast_safe, funding_locked)
	}

	pub fn update_fee<F: Deref>(&mut self, fee_estimator: &F, msg: &msgs::UpdateFee) -> Result<(), ChannelError>
		where F::Target: FeeEstimator
	{
		if self.channel_outbound {
			return Err(ChannelError::Close("Non-funding remote tried to update channel fee"));
		}
		if self.channel_state & (ChannelState::PeerDisconnected as u32) == ChannelState::PeerDisconnected as u32 {
			return Err(ChannelError::Close("Peer sent update_fee when we needed a channel_reestablish"));
		}
		Channel::<ChanSigner>::check_remote_fee(fee_estimator, msg.feerate_per_kw)?;
		self.pending_update_fee = Some(msg.feerate_per_kw as u64);
		self.update_time_counter += 1;
		Ok(())
	}

	fn get_last_revoke_and_ack(&self) -> msgs::RevokeAndACK {
		let next_per_commitment_point = PublicKey::from_secret_key(&self.secp_ctx, &self.build_local_commitment_secret(self.cur_local_commitment_transaction_number));
		let per_commitment_secret = chan_utils::build_commitment_secret(self.local_keys.commitment_seed(), self.cur_local_commitment_transaction_number + 2);
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

		log_trace!(logger, "Regenerated latest commitment update with {} update_adds, {} update_fulfills, {} update_fails, and {} update_fail_malformeds",
				update_add_htlcs.len(), update_fulfill_htlcs.len(), update_fail_htlcs.len(), update_fail_malformed_htlcs.len());
		msgs::CommitmentUpdate {
			update_add_htlcs, update_fulfill_htlcs, update_fail_htlcs, update_fail_malformed_htlcs,
			update_fee: None,
			commitment_signed: self.send_commitment_no_state_update(logger).expect("It looks like we failed to re-generate a commitment_signed we had previously sent?").0,
		}
	}

	/// May panic if some calls other than message-handling calls (which will all Err immediately)
	/// have been called between remove_uncommitted_htlcs_and_mark_paused and this call.
	pub fn channel_reestablish<L: Deref>(&mut self, msg: &msgs::ChannelReestablish, logger: &L) -> Result<(Option<msgs::FundingLocked>, Option<msgs::RevokeAndACK>, Option<msgs::CommitmentUpdate>, Option<ChannelMonitorUpdate>, RAACommitmentOrder, Option<msgs::Shutdown>), ChannelError> where L::Target: Logger {
		if self.channel_state & (ChannelState::PeerDisconnected as u32) == 0 {
			// While BOLT 2 doesn't indicate explicitly we should error this channel here, it
			// almost certainly indicates we are going to end up out-of-sync in some way, so we
			// just close here instead of trying to recover.
			return Err(ChannelError::Close("Peer sent a loose channel_reestablish not after reconnect"));
		}

		if msg.next_local_commitment_number >= INITIAL_COMMITMENT_NUMBER || msg.next_remote_commitment_number >= INITIAL_COMMITMENT_NUMBER ||
			msg.next_local_commitment_number == 0 {
			return Err(ChannelError::Close("Peer sent a garbage channel_reestablish"));
		}

		if msg.next_remote_commitment_number > 0 {
			match msg.data_loss_protect {
				OptionalField::Present(ref data_loss) => {
					if chan_utils::build_commitment_secret(self.local_keys.commitment_seed(), INITIAL_COMMITMENT_NUMBER - msg.next_remote_commitment_number + 1) != data_loss.your_last_per_commitment_secret {
						return Err(ChannelError::Close("Peer sent a garbage channel_reestablish with secret key not matching the commitment height provided"));
					}
					if msg.next_remote_commitment_number > INITIAL_COMMITMENT_NUMBER - self.cur_local_commitment_transaction_number {
						return Err(ChannelError::CloseDelayBroadcast(
							"We have fallen behind - we have received proof that if we broadcast remote is going to claim our funds - we can't do any automated broadcasting"
						));
					}
				},
				OptionalField::Absent => {}
			}
		}

		// Go ahead and unmark PeerDisconnected as various calls we may make check for it (and all
		// remaining cases either succeed or ErrorMessage-fail).
		self.channel_state &= !(ChannelState::PeerDisconnected as u32);

		let shutdown_msg = if self.channel_state & (ChannelState::LocalShutdownSent as u32) != 0 {
			Some(msgs::Shutdown {
				channel_id: self.channel_id,
				scriptpubkey: self.get_closing_scriptpubkey(),
			})
		} else { None };

		if self.channel_state & (ChannelState::FundingSent as u32) == ChannelState::FundingSent as u32 {
			// If we're waiting on a monitor update, we shouldn't re-send any funding_locked's.
			if self.channel_state & (ChannelState::OurFundingLocked as u32) == 0 ||
					self.channel_state & (ChannelState::MonitorUpdateFailed as u32) != 0 {
				if msg.next_remote_commitment_number != 0 {
					return Err(ChannelError::Close("Peer claimed they saw a revoke_and_ack but we haven't sent funding_locked yet"));
				}
				// Short circuit the whole handler as there is nothing we can resend them
				return Ok((None, None, None, None, RAACommitmentOrder::CommitmentFirst, shutdown_msg));
			}

			// We have OurFundingLocked set!
			let next_per_commitment_secret = self.build_local_commitment_secret(self.cur_local_commitment_transaction_number);
			let next_per_commitment_point = PublicKey::from_secret_key(&self.secp_ctx, &next_per_commitment_secret);
			return Ok((Some(msgs::FundingLocked {
				channel_id: self.channel_id(),
				next_per_commitment_point: next_per_commitment_point,
			}), None, None, None, RAACommitmentOrder::CommitmentFirst, shutdown_msg));
		}

		let required_revoke = if msg.next_remote_commitment_number + 1 == INITIAL_COMMITMENT_NUMBER - self.cur_local_commitment_transaction_number {
			// Remote isn't waiting on any RevokeAndACK from us!
			// Note that if we need to repeat our FundingLocked we'll do that in the next if block.
			None
		} else if msg.next_remote_commitment_number + 1 == (INITIAL_COMMITMENT_NUMBER - 1) - self.cur_local_commitment_transaction_number {
			if self.channel_state & (ChannelState::MonitorUpdateFailed as u32) != 0 {
				self.monitor_pending_revoke_and_ack = true;
				None
			} else {
				Some(self.get_last_revoke_and_ack())
			}
		} else {
			return Err(ChannelError::Close("Peer attempted to reestablish channel with a very old local commitment transaction"));
		};

		// We increment cur_remote_commitment_transaction_number only upon receipt of
		// revoke_and_ack, not on sending commitment_signed, so we add one if have
		// AwaitingRemoteRevoke set, which indicates we sent a commitment_signed but haven't gotten
		// the corresponding revoke_and_ack back yet.
		let our_next_remote_commitment_number = INITIAL_COMMITMENT_NUMBER - self.cur_remote_commitment_transaction_number + if (self.channel_state & ChannelState::AwaitingRemoteRevoke as u32) != 0 { 1 } else { 0 };

		let resend_funding_locked = if msg.next_local_commitment_number == 1 && INITIAL_COMMITMENT_NUMBER - self.cur_local_commitment_transaction_number == 1 {
			// We should never have to worry about MonitorUpdateFailed resending FundingLocked
			let next_per_commitment_secret = self.build_local_commitment_secret(self.cur_local_commitment_transaction_number);
			let next_per_commitment_point = PublicKey::from_secret_key(&self.secp_ctx, &next_per_commitment_secret);
			Some(msgs::FundingLocked {
				channel_id: self.channel_id(),
				next_per_commitment_point: next_per_commitment_point,
			})
		} else { None };

		if msg.next_local_commitment_number == our_next_remote_commitment_number {
			if required_revoke.is_some() {
				log_debug!(logger, "Reconnected channel {} with only lost outbound RAA", log_bytes!(self.channel_id()));
			} else {
				log_debug!(logger, "Reconnected channel {} with no loss", log_bytes!(self.channel_id()));
			}

			if (self.channel_state & (ChannelState::AwaitingRemoteRevoke as u32 | ChannelState::MonitorUpdateFailed as u32)) == 0 {
				// We're up-to-date and not waiting on a remote revoke (if we are our
				// channel_reestablish should result in them sending a revoke_and_ack), but we may
				// have received some updates while we were disconnected. Free the holding cell
				// now!
				match self.free_holding_cell_htlcs(logger) {
					Err(ChannelError::Close(msg)) => return Err(ChannelError::Close(msg)),
					Err(ChannelError::Ignore(_)) | Err(ChannelError::CloseDelayBroadcast(_)) => panic!("Got non-channel-failing result from free_holding_cell_htlcs"),
					Ok(Some((commitment_update, monitor_update))) => return Ok((resend_funding_locked, required_revoke, Some(commitment_update), Some(monitor_update), self.resend_order.clone(), shutdown_msg)),
					Ok(None) => return Ok((resend_funding_locked, required_revoke, None, None, self.resend_order.clone(), shutdown_msg)),
				}
			} else {
				return Ok((resend_funding_locked, required_revoke, None, None, self.resend_order.clone(), shutdown_msg));
			}
		} else if msg.next_local_commitment_number == our_next_remote_commitment_number - 1 {
			if required_revoke.is_some() {
				log_debug!(logger, "Reconnected channel {} with lost outbound RAA and lost remote commitment tx", log_bytes!(self.channel_id()));
			} else {
				log_debug!(logger, "Reconnected channel {} with only lost remote commitment tx", log_bytes!(self.channel_id()));
			}

			if self.channel_state & (ChannelState::MonitorUpdateFailed as u32) != 0 {
				self.monitor_pending_commitment_signed = true;
				return Ok((resend_funding_locked, None, None, None, self.resend_order.clone(), shutdown_msg));
			}

			return Ok((resend_funding_locked, required_revoke, Some(self.get_last_commitment_update(logger)), None, self.resend_order.clone(), shutdown_msg));
		} else {
			return Err(ChannelError::Close("Peer attempted to reestablish channel with a very old remote commitment transaction"));
		}
	}

	fn maybe_propose_first_closing_signed<F: Deref>(&mut self, fee_estimator: &F) -> Option<msgs::ClosingSigned>
		where F::Target: FeeEstimator
	{
		if !self.channel_outbound || !self.pending_inbound_htlcs.is_empty() || !self.pending_outbound_htlcs.is_empty() ||
				self.channel_state & (BOTH_SIDES_SHUTDOWN_MASK | ChannelState::AwaitingRemoteRevoke as u32) != BOTH_SIDES_SHUTDOWN_MASK ||
				self.last_sent_closing_fee.is_some() || self.pending_update_fee.is_some() {
			return None;
		}

		let mut proposed_feerate = fee_estimator.get_est_sat_per_1000_weight(ConfirmationTarget::Background);
		if self.feerate_per_kw > proposed_feerate {
			proposed_feerate = self.feerate_per_kw;
		}
		let tx_weight = Self::get_closing_transaction_weight(&self.get_closing_scriptpubkey(), self.their_shutdown_scriptpubkey.as_ref().unwrap());
		let proposed_total_fee_satoshis = proposed_feerate * tx_weight / 1000;

		let (closing_tx, total_fee_satoshis) = self.build_closing_transaction(proposed_total_fee_satoshis, false);
		let our_sig = self.local_keys
			.sign_closing_transaction(&closing_tx, &self.secp_ctx)
			.ok();
		if our_sig.is_none() { return None; }

		self.last_sent_closing_fee = Some((proposed_feerate, total_fee_satoshis, our_sig.clone().unwrap()));
		Some(msgs::ClosingSigned {
			channel_id: self.channel_id,
			fee_satoshis: total_fee_satoshis,
			signature: our_sig.unwrap(),
		})
	}

	pub fn shutdown<F: Deref>(&mut self, fee_estimator: &F, msg: &msgs::Shutdown) -> Result<(Option<msgs::Shutdown>, Option<msgs::ClosingSigned>, Vec<(HTLCSource, PaymentHash)>), ChannelError>
		where F::Target: FeeEstimator
	{
		if self.channel_state & (ChannelState::PeerDisconnected as u32) == ChannelState::PeerDisconnected as u32 {
			return Err(ChannelError::Close("Peer sent shutdown when we needed a channel_reestablish"));
		}
		if self.channel_state < ChannelState::FundingSent as u32 {
			// Spec says we should fail the connection, not the channel, but that's nonsense, there
			// are plenty of reasons you may want to fail a channel pre-funding, and spec says you
			// can do that via error message without getting a connection fail anyway...
			return Err(ChannelError::Close("Peer sent shutdown pre-funding generation"));
		}
		for htlc in self.pending_inbound_htlcs.iter() {
			if let InboundHTLCState::RemoteAnnounced(_) = htlc.state {
				return Err(ChannelError::Close("Got shutdown with remote pending HTLCs"));
			}
		}
		assert_eq!(self.channel_state & ChannelState::ShutdownComplete as u32, 0);

		// BOLT 2 says we must only send a scriptpubkey of certain standard forms, which are up to
		// 34 bytes in length, so don't let the remote peer feed us some super fee-heavy script.
		if self.channel_outbound && msg.scriptpubkey.len() > 34 {
			return Err(ChannelError::Close("Got shutdown_scriptpubkey of absurd length from remote peer"));
		}

		//Check shutdown_scriptpubkey form as BOLT says we must
		if !msg.scriptpubkey.is_p2pkh() && !msg.scriptpubkey.is_p2sh() && !msg.scriptpubkey.is_v0_p2wpkh() && !msg.scriptpubkey.is_v0_p2wsh() {
			return Err(ChannelError::Close("Got a nonstandard scriptpubkey from remote peer"));
		}

		if self.their_shutdown_scriptpubkey.is_some() {
			if Some(&msg.scriptpubkey) != self.their_shutdown_scriptpubkey.as_ref() {
				return Err(ChannelError::Close("Got shutdown request with a scriptpubkey which did not match their previous scriptpubkey"));
			}
		} else {
			self.their_shutdown_scriptpubkey = Some(msg.scriptpubkey.clone());
		}

		// From here on out, we may not fail!

		self.channel_state |= ChannelState::RemoteShutdownSent as u32;
		self.update_time_counter += 1;

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
		// If we have any LocalAnnounced updates we'll probably just get back a update_fail_htlc
		// immediately after the commitment dance, but we can send a Shutdown cause we won't send
		// any further commitment updates after we set LocalShutdownSent.

		let our_shutdown = if (self.channel_state & ChannelState::LocalShutdownSent as u32) == ChannelState::LocalShutdownSent as u32 {
			None
		} else {
			Some(msgs::Shutdown {
				channel_id: self.channel_id,
				scriptpubkey: self.get_closing_scriptpubkey(),
			})
		};

		self.channel_state |= ChannelState::LocalShutdownSent as u32;
		self.update_time_counter += 1;

		Ok((our_shutdown, self.maybe_propose_first_closing_signed(fee_estimator), dropped_outbound_htlcs))
	}

	fn build_signed_closing_transaction(&self, tx: &mut Transaction, their_sig: &Signature, our_sig: &Signature) {
		if tx.input.len() != 1 { panic!("Tried to sign closing transaction that had input count != 1!"); }
		if tx.input[0].witness.len() != 0 { panic!("Tried to re-sign closing transaction"); }
		if tx.output.len() > 2 { panic!("Tried to sign bogus closing transaction"); }

		tx.input[0].witness.push(Vec::new()); // First is the multisig dummy

		let our_funding_key = PublicKey::from_secret_key(&self.secp_ctx, self.local_keys.funding_key()).serialize();
		let their_funding_key = self.their_funding_pubkey().serialize();
		if our_funding_key[..] < their_funding_key[..] {
			tx.input[0].witness.push(our_sig.serialize_der().to_vec());
			tx.input[0].witness.push(their_sig.serialize_der().to_vec());
		} else {
			tx.input[0].witness.push(their_sig.serialize_der().to_vec());
			tx.input[0].witness.push(our_sig.serialize_der().to_vec());
		}
		tx.input[0].witness[1].push(SigHashType::All as u8);
		tx.input[0].witness[2].push(SigHashType::All as u8);

		tx.input[0].witness.push(self.get_funding_redeemscript().into_bytes());
	}

	pub fn closing_signed<F: Deref>(&mut self, fee_estimator: &F, msg: &msgs::ClosingSigned) -> Result<(Option<msgs::ClosingSigned>, Option<Transaction>), ChannelError>
		where F::Target: FeeEstimator
	{
		if self.channel_state & BOTH_SIDES_SHUTDOWN_MASK != BOTH_SIDES_SHUTDOWN_MASK {
			return Err(ChannelError::Close("Remote end sent us a closing_signed before both sides provided a shutdown"));
		}
		if self.channel_state & (ChannelState::PeerDisconnected as u32) == ChannelState::PeerDisconnected as u32 {
			return Err(ChannelError::Close("Peer sent closing_signed when we needed a channel_reestablish"));
		}
		if !self.pending_inbound_htlcs.is_empty() || !self.pending_outbound_htlcs.is_empty() {
			return Err(ChannelError::Close("Remote end sent us a closing_signed while there were still pending HTLCs"));
		}
		if msg.fee_satoshis > 21000000 * 10000000 { //this is required to stop potential overflow in build_closing_transaction
			return Err(ChannelError::Close("Remote tried to send us a closing tx with > 21 million BTC fee"));
		}

		let funding_redeemscript = self.get_funding_redeemscript();
		let (mut closing_tx, used_total_fee) = self.build_closing_transaction(msg.fee_satoshis, false);
		if used_total_fee != msg.fee_satoshis {
			return Err(ChannelError::Close("Remote sent us a closing_signed with a fee greater than the value they can claim"));
		}
		let mut sighash = hash_to_message!(&bip143::SighashComponents::new(&closing_tx).sighash_all(&closing_tx.input[0], &funding_redeemscript, self.channel_value_satoshis)[..]);

		let their_funding_pubkey = &self.their_pubkeys.as_ref().unwrap().funding_pubkey;

		match self.secp_ctx.verify(&sighash, &msg.signature, their_funding_pubkey) {
			Ok(_) => {},
			Err(_e) => {
				// The remote end may have decided to revoke their output due to inconsistent dust
				// limits, so check for that case by re-checking the signature here.
				closing_tx = self.build_closing_transaction(msg.fee_satoshis, true).0;
				sighash = hash_to_message!(&bip143::SighashComponents::new(&closing_tx).sighash_all(&closing_tx.input[0], &funding_redeemscript, self.channel_value_satoshis)[..]);
				secp_check!(self.secp_ctx.verify(&sighash, &msg.signature, self.their_funding_pubkey()), "Invalid closing tx signature from peer");
			},
		};

		if let Some((_, last_fee, our_sig)) = self.last_sent_closing_fee {
			if last_fee == msg.fee_satoshis {
				self.build_signed_closing_transaction(&mut closing_tx, &msg.signature, &our_sig);
				self.channel_state = ChannelState::ShutdownComplete as u32;
				self.update_time_counter += 1;
				return Ok((None, Some(closing_tx)));
			}
		}

		macro_rules! propose_new_feerate {
			($new_feerate: expr) => {
				let closing_tx_max_weight = Self::get_closing_transaction_weight(&self.get_closing_scriptpubkey(), self.their_shutdown_scriptpubkey.as_ref().unwrap());
				let (closing_tx, used_total_fee) = self.build_closing_transaction($new_feerate * closing_tx_max_weight / 1000, false);
				let our_sig = self.local_keys
					.sign_closing_transaction(&closing_tx, &self.secp_ctx)
					.map_err(|_| ChannelError::Close("External signer refused to sign closing transaction"))?;
				self.last_sent_closing_fee = Some(($new_feerate, used_total_fee, our_sig.clone()));
				return Ok((Some(msgs::ClosingSigned {
					channel_id: self.channel_id,
					fee_satoshis: used_total_fee,
					signature: our_sig,
				}), None))
			}
		}

		let proposed_sat_per_kw = msg.fee_satoshis * 1000 / closing_tx.get_weight() as u64;
		if self.channel_outbound {
			let our_max_feerate = fee_estimator.get_est_sat_per_1000_weight(ConfirmationTarget::Normal);
			if proposed_sat_per_kw > our_max_feerate {
				if let Some((last_feerate, _, _)) = self.last_sent_closing_fee {
					if our_max_feerate <= last_feerate {
						return Err(ChannelError::Close("Unable to come to consensus about closing feerate, remote wanted something higher than our Normal feerate"));
					}
				}
				propose_new_feerate!(our_max_feerate);
			}
		} else {
			let our_min_feerate = fee_estimator.get_est_sat_per_1000_weight(ConfirmationTarget::Background);
			if proposed_sat_per_kw < our_min_feerate {
				if let Some((last_feerate, _, _)) = self.last_sent_closing_fee {
					if our_min_feerate >= last_feerate {
						return Err(ChannelError::Close("Unable to come to consensus about closing feerate, remote wanted something lower than our Background feerate"));
					}
				}
				propose_new_feerate!(our_min_feerate);
			}
		}

		let our_sig = self.local_keys
			.sign_closing_transaction(&closing_tx, &self.secp_ctx)
			.map_err(|_| ChannelError::Close("External signer refused to sign closing transaction"))?;
		self.build_signed_closing_transaction(&mut closing_tx, &msg.signature, &our_sig);

		self.channel_state = ChannelState::ShutdownComplete as u32;
		self.update_time_counter += 1;

		Ok((Some(msgs::ClosingSigned {
			channel_id: self.channel_id,
			fee_satoshis: msg.fee_satoshis,
			signature: our_sig,
		}), Some(closing_tx)))
	}

	// Public utilities:

	pub fn channel_id(&self) -> [u8; 32] {
		self.channel_id
	}

	/// Gets the "user_id" value passed into the construction of this channel. It has no special
	/// meaning and exists only to allow users to have a persistent identifier of a channel.
	pub fn get_user_id(&self) -> u64 {
		self.user_id
	}

	/// May only be called after funding has been initiated (ie is_funding_initiated() is true)
	pub fn channel_monitor(&mut self) -> &mut ChannelMonitor<ChanSigner> {
		if self.channel_state < ChannelState::FundingSent as u32 {
			panic!("Can't get a channel monitor until funding has been created");
		}
		self.channel_monitor.as_mut().unwrap()
	}

	/// Guaranteed to be Some after both FundingLocked messages have been exchanged (and, thus,
	/// is_usable() returns true).
	/// Allowed in any state (including after shutdown)
	pub fn get_short_channel_id(&self) -> Option<u64> {
		self.short_channel_id
	}

	/// Returns the funding_txo we either got from our peer, or were given by
	/// get_outbound_funding_created.
	pub fn get_funding_txo(&self) -> Option<OutPoint> {
		self.funding_txo
	}

	/// Allowed in any state (including after shutdown)
	pub fn get_their_node_id(&self) -> PublicKey {
		self.their_node_id
	}

	/// Allowed in any state (including after shutdown)
	pub fn get_our_htlc_minimum_msat(&self) -> u64 {
		self.our_htlc_minimum_msat
	}

	/// Allowed in any state (including after shutdown)
	pub fn get_their_htlc_minimum_msat(&self) -> u64 {
		self.our_htlc_minimum_msat
	}

	pub fn get_value_satoshis(&self) -> u64 {
		self.channel_value_satoshis
	}

	pub fn get_fee_proportional_millionths(&self) -> u32 {
		self.config.fee_proportional_millionths
	}

	#[cfg(test)]
	pub fn get_feerate(&self) -> u64 {
		self.feerate_per_kw
	}

	pub fn get_cur_local_commitment_transaction_number(&self) -> u64 {
		self.cur_local_commitment_transaction_number + 1
	}

	pub fn get_cur_remote_commitment_transaction_number(&self) -> u64 {
		self.cur_remote_commitment_transaction_number + 1 - if self.channel_state & (ChannelState::AwaitingRemoteRevoke as u32) != 0 { 1 } else { 0 }
	}

	pub fn get_revoked_remote_commitment_transaction_number(&self) -> u64 {
		self.cur_remote_commitment_transaction_number + 2
	}

	#[cfg(test)]
	pub fn get_local_keys(&self) -> &ChanSigner {
		&self.local_keys
	}

	#[cfg(test)]
	pub fn get_value_stat(&self) -> ChannelValueStat {
		ChannelValueStat {
			value_to_self_msat: self.value_to_self_msat,
			channel_value_msat: self.channel_value_satoshis * 1000,
			channel_reserve_msat: self.local_channel_reserve_satoshis * 1000,
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
			their_max_htlc_value_in_flight_msat: self.their_max_htlc_value_in_flight_msat,
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
		self.channel_outbound
	}

	/// Gets the fee we'd want to charge for adding an HTLC output to this Channel
	/// Allowed in any state (including after shutdown)
	pub fn get_our_fee_base_msat<F: Deref>(&self, fee_estimator: &F) -> u32
		where F::Target: FeeEstimator
	{
		// For lack of a better metric, we calculate what it would cost to consolidate the new HTLC
		// output value back into a transaction with the regular channel output:

		// the fee cost of the HTLC-Success/HTLC-Timeout transaction:
		let mut res = self.feerate_per_kw * cmp::max(HTLC_TIMEOUT_TX_WEIGHT, HTLC_SUCCESS_TX_WEIGHT) / 1000;

		if self.channel_outbound {
			// + the marginal fee increase cost to us in the commitment transaction:
			res += self.feerate_per_kw * COMMITMENT_TX_WEIGHT_PER_HTLC / 1000;
		}

		// + the marginal cost of an input which spends the HTLC-Success/HTLC-Timeout output:
		res += fee_estimator.get_est_sat_per_1000_weight(ConfirmationTarget::Normal) * SPENDING_INPUT_FOR_A_OUTPUT_WEIGHT / 1000;

		res as u32
	}

	/// Returns true if we've ever received a message from the remote end for this Channel
	pub fn have_received_message(&self) -> bool {
		self.channel_state > (ChannelState::OurInitSent as u32)
	}

	/// Returns true if this channel is fully established and not known to be closing.
	/// Allowed in any state (including after shutdown)
	pub fn is_usable(&self) -> bool {
		let mask = ChannelState::ChannelFunded as u32 | BOTH_SIDES_SHUTDOWN_MASK;
		(self.channel_state & mask) == (ChannelState::ChannelFunded as u32)
	}

	/// Returns true if this channel is currently available for use. This is a superset of
	/// is_usable() and considers things like the channel being temporarily disabled.
	/// Allowed in any state (including after shutdown)
	pub fn is_live(&self) -> bool {
		self.is_usable() && (self.channel_state & (ChannelState::PeerDisconnected as u32 | ChannelState::MonitorUpdateFailed as u32) == 0)
	}

	/// Returns true if this channel has been marked as awaiting a monitor update to move forward.
	/// Allowed in any state (including after shutdown)
	pub fn is_awaiting_monitor_update(&self) -> bool {
		(self.channel_state & ChannelState::MonitorUpdateFailed as u32) != 0
	}

	/// Returns true if funding_created was sent/received.
	pub fn is_funding_initiated(&self) -> bool {
		self.channel_state >= ChannelState::FundingSent as u32
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

	pub fn to_disabled_staged(&mut self) {
		self.network_sync = UpdateStatus::DisabledStaged;
	}

	pub fn to_disabled_marked(&mut self) {
		self.network_sync = UpdateStatus::DisabledMarked;
	}

	pub fn to_fresh(&mut self) {
		self.network_sync = UpdateStatus::Fresh;
	}

	pub fn is_disabled_staged(&self) -> bool {
		self.network_sync == UpdateStatus::DisabledStaged
	}

	pub fn is_disabled_marked(&self) -> bool {
		self.network_sync == UpdateStatus::DisabledMarked
	}

	/// When we receive a new block, we (a) check whether the block contains the funding
	/// transaction (which would start us counting blocks until we send the funding_signed), and
	/// (b) check the height of the block against outbound holding cell HTLCs in case we need to
	/// give up on them prematurely and time them out. Everything else (e.g. commitment
	/// transaction broadcasts, channel closure detection, HTLC transaction broadcasting, etc) is
	/// handled by the ChannelMonitor.
	///
	/// If we return Err, the channel may have been closed, at which point the standard
	/// requirements apply - no calls may be made except those explicitly stated to be allowed
	/// post-shutdown.
	/// Only returns an ErrorAction of DisconnectPeer, if Err.
	///
	/// May return some HTLCs (and their payment_hash) which have timed out and should be failed
	/// back.
	pub fn block_connected(&mut self, header: &BlockHeader, height: u32, txn_matched: &[&Transaction], indexes_of_txn_matched: &[u32]) -> Result<(Option<msgs::FundingLocked>, Vec<(HTLCSource, PaymentHash)>), msgs::ErrorMessage> {
		let mut timed_out_htlcs = Vec::new();
		self.holding_cell_htlc_updates.retain(|htlc_update| {
			match htlc_update {
				&HTLCUpdateAwaitingACK::AddHTLC { ref payment_hash, ref source, ref cltv_expiry, .. } => {
					if *cltv_expiry <= height + HTLC_FAIL_BACK_BUFFER {
						timed_out_htlcs.push((source.clone(), payment_hash.clone()));
						false
					} else { true }
				},
				_ => true
			}
		});
		let non_shutdown_state = self.channel_state & (!MULTI_STATE_FLAGS);
		if header.bitcoin_hash() != self.last_block_connected {
			if self.funding_tx_confirmations > 0 {
				self.funding_tx_confirmations += 1;
			}
		}
		if non_shutdown_state & !(ChannelState::TheirFundingLocked as u32) == ChannelState::FundingSent as u32 {
			for (ref tx, index_in_block) in txn_matched.iter().zip(indexes_of_txn_matched) {
				if tx.txid() == self.funding_txo.unwrap().txid {
					let txo_idx = self.funding_txo.unwrap().index as usize;
					if txo_idx >= tx.output.len() || tx.output[txo_idx].script_pubkey != self.get_funding_redeemscript().to_v0_p2wsh() ||
							tx.output[txo_idx].value != self.channel_value_satoshis {
						if self.channel_outbound {
							// If we generated the funding transaction and it doesn't match what it
							// should, the client is really broken and we should just panic and
							// tell them off. That said, because hash collisions happen with high
							// probability in fuzztarget mode, if we're fuzzing we just close the
							// channel and move on.
							#[cfg(not(feature = "fuzztarget"))]
							panic!("Client called ChannelManager::funding_transaction_generated with bogus transaction!");
						}
						self.channel_state = ChannelState::ShutdownComplete as u32;
						self.update_time_counter += 1;
						return Err(msgs::ErrorMessage {
							channel_id: self.channel_id(),
							data: "funding tx had wrong script/value".to_owned()
						});
					} else {
						if self.channel_outbound {
							for input in tx.input.iter() {
								if input.witness.is_empty() {
									// We generated a malleable funding transaction, implying we've
									// just exposed ourselves to funds loss to our counterparty.
									#[cfg(not(feature = "fuzztarget"))]
									panic!("Client called ChannelManager::funding_transaction_generated with bogus transaction!");
								}
							}
						}
						self.funding_tx_confirmations = 1;
						self.short_channel_id = Some(((height as u64)          << (5*8)) |
						                             ((*index_in_block as u64) << (2*8)) |
						                             ((txo_idx as u64)         << (0*8)));
					}
				}
			}
		}
		if header.bitcoin_hash() != self.last_block_connected {
			self.last_block_connected = header.bitcoin_hash();
			self.update_time_counter = cmp::max(self.update_time_counter, header.time);
			if let Some(channel_monitor) = self.channel_monitor.as_mut() {
				channel_monitor.last_block_hash = self.last_block_connected;
			}
			if self.funding_tx_confirmations > 0 {
				if self.funding_tx_confirmations == self.minimum_depth as u64 {
					let need_commitment_update = if non_shutdown_state == ChannelState::FundingSent as u32 {
						self.channel_state |= ChannelState::OurFundingLocked as u32;
						true
					} else if non_shutdown_state == (ChannelState::FundingSent as u32 | ChannelState::TheirFundingLocked as u32) {
						self.channel_state = ChannelState::ChannelFunded as u32 | (self.channel_state & MULTI_STATE_FLAGS);
						self.update_time_counter += 1;
						true
					} else if non_shutdown_state == (ChannelState::FundingSent as u32 | ChannelState::OurFundingLocked as u32) {
						// We got a reorg but not enough to trigger a force close, just update
						// funding_tx_confirmed_in and return.
						false
					} else if self.channel_state < ChannelState::ChannelFunded as u32 {
						panic!("Started confirming a channel in a state pre-FundingSent?: {}", self.channel_state);
					} else {
						// We got a reorg but not enough to trigger a force close, just update
						// funding_tx_confirmed_in and return.
						false
					};
					self.funding_tx_confirmed_in = Some(header.bitcoin_hash());

					//TODO: Note that this must be a duplicate of the previous commitment point they sent us,
					//as otherwise we will have a commitment transaction that they can't revoke (well, kinda,
					//they can by sending two revoke_and_acks back-to-back, but not really). This appears to be
					//a protocol oversight, but I assume I'm just missing something.
					if need_commitment_update {
						if self.channel_state & (ChannelState::MonitorUpdateFailed as u32) == 0 {
							let next_per_commitment_secret = self.build_local_commitment_secret(self.cur_local_commitment_transaction_number);
							let next_per_commitment_point = PublicKey::from_secret_key(&self.secp_ctx, &next_per_commitment_secret);
							return Ok((Some(msgs::FundingLocked {
								channel_id: self.channel_id,
								next_per_commitment_point: next_per_commitment_point,
							}), timed_out_htlcs));
						} else {
							self.monitor_pending_funding_locked = true;
							return Ok((None, timed_out_htlcs));
						}
					}
				}
			}
		}
		Ok((None, timed_out_htlcs))
	}

	/// Called by channelmanager based on chain blocks being disconnected.
	/// Returns true if we need to close the channel now due to funding transaction
	/// unconfirmation/reorg.
	pub fn block_disconnected(&mut self, header: &BlockHeader) -> bool {
		if self.funding_tx_confirmations > 0 {
			self.funding_tx_confirmations -= 1;
			if self.funding_tx_confirmations == UNCONF_THRESHOLD as u64 {
				return true;
			}
		}
		if Some(header.bitcoin_hash()) == self.funding_tx_confirmed_in {
			self.funding_tx_confirmations = self.minimum_depth as u64 - 1;
		}
		self.last_block_connected = header.bitcoin_hash();
		if let Some(channel_monitor) = self.channel_monitor.as_mut() {
			channel_monitor.last_block_hash = self.last_block_connected;
		}
		false
	}

	// Methods to get unprompted messages to send to the remote end (or where we already returned
	// something in the handler for the message that prompted this message):

	pub fn get_open_channel<F: Deref>(&self, chain_hash: BlockHash, fee_estimator: &F) -> msgs::OpenChannel
		where F::Target: FeeEstimator
	{
		if !self.channel_outbound {
			panic!("Tried to open a channel for an inbound channel?");
		}
		if self.channel_state != ChannelState::OurInitSent as u32 {
			panic!("Cannot generate an open_channel after we've moved forward");
		}

		if self.cur_local_commitment_transaction_number != INITIAL_COMMITMENT_NUMBER {
			panic!("Tried to send an open_channel for a channel that has already advanced");
		}

		let local_commitment_secret = self.build_local_commitment_secret(self.cur_local_commitment_transaction_number);

		msgs::OpenChannel {
			chain_hash: chain_hash,
			temporary_channel_id: self.channel_id,
			funding_satoshis: self.channel_value_satoshis,
			push_msat: self.channel_value_satoshis * 1000 - self.value_to_self_msat,
			dust_limit_satoshis: self.our_dust_limit_satoshis,
			max_htlc_value_in_flight_msat: Channel::<ChanSigner>::get_our_max_htlc_value_in_flight_msat(self.channel_value_satoshis),
			channel_reserve_satoshis: Channel::<ChanSigner>::get_remote_channel_reserve_satoshis(self.channel_value_satoshis),
			htlc_minimum_msat: self.our_htlc_minimum_msat,
			feerate_per_kw: fee_estimator.get_est_sat_per_1000_weight(ConfirmationTarget::Background) as u32,
			to_self_delay: self.our_to_self_delay,
			max_accepted_htlcs: OUR_MAX_HTLCS,
			funding_pubkey: PublicKey::from_secret_key(&self.secp_ctx, self.local_keys.funding_key()),
			revocation_basepoint: PublicKey::from_secret_key(&self.secp_ctx, self.local_keys.revocation_base_key()),
			payment_point: PublicKey::from_secret_key(&self.secp_ctx, self.local_keys.payment_key()),
			delayed_payment_basepoint: PublicKey::from_secret_key(&self.secp_ctx, self.local_keys.delayed_payment_base_key()),
			htlc_basepoint: PublicKey::from_secret_key(&self.secp_ctx, self.local_keys.htlc_base_key()),
			first_per_commitment_point: PublicKey::from_secret_key(&self.secp_ctx, &local_commitment_secret),
			channel_flags: if self.config.announced_channel {1} else {0},
			shutdown_scriptpubkey: OptionalField::Present(if self.config.commit_upfront_shutdown_pubkey { self.get_closing_scriptpubkey() } else { Builder::new().into_script() })
		}
	}

	pub fn get_accept_channel(&self) -> msgs::AcceptChannel {
		if self.channel_outbound {
			panic!("Tried to send accept_channel for an outbound channel?");
		}
		if self.channel_state != (ChannelState::OurInitSent as u32) | (ChannelState::TheirInitSent as u32) {
			panic!("Tried to send accept_channel after channel had moved forward");
		}
		if self.cur_local_commitment_transaction_number != INITIAL_COMMITMENT_NUMBER {
			panic!("Tried to send an accept_channel for a channel that has already advanced");
		}

		let local_commitment_secret = self.build_local_commitment_secret(self.cur_local_commitment_transaction_number);

		msgs::AcceptChannel {
			temporary_channel_id: self.channel_id,
			dust_limit_satoshis: self.our_dust_limit_satoshis,
			max_htlc_value_in_flight_msat: Channel::<ChanSigner>::get_our_max_htlc_value_in_flight_msat(self.channel_value_satoshis),
			channel_reserve_satoshis: Channel::<ChanSigner>::get_remote_channel_reserve_satoshis(self.channel_value_satoshis),
			htlc_minimum_msat: self.our_htlc_minimum_msat,
			minimum_depth: self.minimum_depth,
			to_self_delay: self.our_to_self_delay,
			max_accepted_htlcs: OUR_MAX_HTLCS,
			funding_pubkey: PublicKey::from_secret_key(&self.secp_ctx, self.local_keys.funding_key()),
			revocation_basepoint: PublicKey::from_secret_key(&self.secp_ctx, self.local_keys.revocation_base_key()),
			payment_point: PublicKey::from_secret_key(&self.secp_ctx, self.local_keys.payment_key()),
			delayed_payment_basepoint: PublicKey::from_secret_key(&self.secp_ctx, self.local_keys.delayed_payment_base_key()),
			htlc_basepoint: PublicKey::from_secret_key(&self.secp_ctx, self.local_keys.htlc_base_key()),
			first_per_commitment_point: PublicKey::from_secret_key(&self.secp_ctx, &local_commitment_secret),
			shutdown_scriptpubkey: OptionalField::Present(if self.config.commit_upfront_shutdown_pubkey { self.get_closing_scriptpubkey() } else { Builder::new().into_script() })
		}
	}

	/// If an Err is returned, it is a ChannelError::Close (for get_outbound_funding_created)
	fn get_outbound_funding_created_signature<L: Deref>(&mut self, logger: &L) -> Result<Signature, ChannelError> where L::Target: Logger {
		let remote_keys = self.build_remote_transaction_keys()?;
		let remote_initial_commitment_tx = self.build_commitment_transaction(self.cur_remote_commitment_transaction_number, &remote_keys, false, false, self.feerate_per_kw, logger).0;
		Ok(self.local_keys.sign_remote_commitment(self.feerate_per_kw, &remote_initial_commitment_tx, &remote_keys, &Vec::new(), self.our_to_self_delay, &self.secp_ctx)
				.map_err(|_| ChannelError::Close("Failed to get signatures for new commitment_signed"))?.0)
	}

	/// Updates channel state with knowledge of the funding transaction's txid/index, and generates
	/// a funding_created message for the remote peer.
	/// Panics if called at some time other than immediately after initial handshake, if called twice,
	/// or if called on an inbound channel.
	/// Note that channel_id changes during this call!
	/// Do NOT broadcast the funding transaction until after a successful funding_signed call!
	/// If an Err is returned, it is a ChannelError::Close.
	pub fn get_outbound_funding_created<L: Deref>(&mut self, funding_txo: OutPoint, logger: &L) -> Result<msgs::FundingCreated, ChannelError> where L::Target: Logger {
		if !self.channel_outbound {
			panic!("Tried to create outbound funding_created message on an inbound channel!");
		}
		if self.channel_state != (ChannelState::OurInitSent as u32 | ChannelState::TheirInitSent as u32) {
			panic!("Tried to get a funding_created messsage at a time other than immediately after initial handshake completion (or tried to get funding_created twice)");
		}
		if self.commitment_secrets.get_min_seen_secret() != (1 << 48) ||
				self.cur_remote_commitment_transaction_number != INITIAL_COMMITMENT_NUMBER ||
				self.cur_local_commitment_transaction_number != INITIAL_COMMITMENT_NUMBER {
			panic!("Should not have advanced channel commitment tx numbers prior to funding_created");
		}

		self.funding_txo = Some(funding_txo.clone());
		let our_signature = match self.get_outbound_funding_created_signature(logger) {
			Ok(res) => res,
			Err(e) => {
				log_error!(logger, "Got bad signatures: {:?}!", e);
				self.funding_txo = None;
				return Err(e);
			}
		};

		let temporary_channel_id = self.channel_id;

		// Now that we're past error-generating stuff, update our local state:

		self.channel_state = ChannelState::FundingCreated as u32;
		self.channel_id = funding_txo.to_channel_id();

		Ok(msgs::FundingCreated {
			temporary_channel_id,
			funding_txid: funding_txo.txid,
			funding_output_index: funding_txo.index,
			signature: our_signature
		})
	}

	/// Gets an UnsignedChannelAnnouncement, as well as a signature covering it using our
	/// bitcoin_key, if available, for this channel. The channel must be publicly announceable and
	/// available for use (have exchanged FundingLocked messages in both directions). Should be used
	/// for both loose and in response to an AnnouncementSignatures message from the remote peer.
	/// Will only fail if we're not in a state where channel_announcement may be sent (including
	/// closing).
	/// Note that the "channel must be funded" requirement is stricter than BOLT 7 requires - see
	/// https://github.com/lightningnetwork/lightning-rfc/issues/468
	pub fn get_channel_announcement(&self, our_node_id: PublicKey, chain_hash: BlockHash) -> Result<(msgs::UnsignedChannelAnnouncement, Signature), ChannelError> {
		if !self.config.announced_channel {
			return Err(ChannelError::Ignore("Channel is not available for public announcements"));
		}
		if self.channel_state & (ChannelState::ChannelFunded as u32) == 0 {
			return Err(ChannelError::Ignore("Cannot get a ChannelAnnouncement until the channel funding has been locked"));
		}
		if (self.channel_state & (ChannelState::LocalShutdownSent as u32 | ChannelState::ShutdownComplete as u32)) != 0 {
			return Err(ChannelError::Ignore("Cannot get a ChannelAnnouncement once the channel is closing"));
		}

		let were_node_one = our_node_id.serialize()[..] < self.their_node_id.serialize()[..];
		let our_bitcoin_key = PublicKey::from_secret_key(&self.secp_ctx, self.local_keys.funding_key());

		let msg = msgs::UnsignedChannelAnnouncement {
			features: ChannelFeatures::known(),
			chain_hash: chain_hash,
			short_channel_id: self.get_short_channel_id().unwrap(),
			node_id_1: if were_node_one { our_node_id } else { self.get_their_node_id() },
			node_id_2: if were_node_one { self.get_their_node_id() } else { our_node_id },
			bitcoin_key_1: if were_node_one { our_bitcoin_key } else { self.their_funding_pubkey().clone() },
			bitcoin_key_2: if were_node_one { self.their_funding_pubkey().clone() } else { our_bitcoin_key },
			excess_data: Vec::new(),
		};

		let sig = self.local_keys.sign_channel_announcement(&msg, &self.secp_ctx)
			.map_err(|_| ChannelError::Ignore("Signer rejected channel_announcement"))?;

		Ok((msg, sig))
	}

	/// May panic if called on a channel that wasn't immediately-previously
	/// self.remove_uncommitted_htlcs_and_mark_paused()'d
	pub fn get_channel_reestablish<L: Deref>(&self, logger: &L) -> msgs::ChannelReestablish where L::Target: Logger {
		assert_eq!(self.channel_state & ChannelState::PeerDisconnected as u32, ChannelState::PeerDisconnected as u32);
		assert_ne!(self.cur_remote_commitment_transaction_number, INITIAL_COMMITMENT_NUMBER);
		// Prior to static_remotekey, my_current_per_commitment_point was critical to claiming
		// current to_remote balances. However, it no longer has any use, and thus is now simply
		// set to a dummy (but valid, as required by the spec) public key.
		// fuzztarget mode marks a subset of pubkeys as invalid so that we can hit "invalid pubkey"
		// branches, but we unwrap it below, so we arbitrarily select a dummy pubkey which is both
		// valid, and valid in fuzztarget mode's arbitrary validity criteria:
		let mut pk = [2; 33]; pk[1] = 0xff;
		let dummy_pubkey = PublicKey::from_slice(&pk).unwrap();
		let data_loss_protect = if self.cur_remote_commitment_transaction_number + 1 < INITIAL_COMMITMENT_NUMBER {
			let remote_last_secret = self.commitment_secrets.get_secret(self.cur_remote_commitment_transaction_number + 2).unwrap();
			log_trace!(logger, "Enough info to generate a Data Loss Protect with per_commitment_secret {}", log_bytes!(remote_last_secret));
			OptionalField::Present(DataLossProtect {
				your_last_per_commitment_secret: remote_last_secret,
				my_current_per_commitment_point: dummy_pubkey
			})
		} else {
			log_info!(logger, "Sending a data_loss_protect with no previous remote per_commitment_secret");
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
			next_local_commitment_number: INITIAL_COMMITMENT_NUMBER - self.cur_local_commitment_transaction_number,
			// We have to set next_remote_commitment_number to the next revoke_and_ack we expect to
			// receive, however we track it by the next commitment number for a remote transaction
			// (which is one further, as they always revoke previous commitment transaction, not
			// the one we send) so we have to decrement by 1. Note that if
			// cur_remote_commitment_transaction_number is INITIAL_COMMITMENT_NUMBER we will have
			// dropped this channel on disconnect as it hasn't yet reached FundingSent so we can't
			// overflow here.
			next_remote_commitment_number: INITIAL_COMMITMENT_NUMBER - self.cur_remote_commitment_transaction_number - 1,
			data_loss_protect,
		}
	}


	// Send stuff to our remote peers:

	/// Adds a pending outbound HTLC to this channel, note that you probably want
	/// send_htlc_and_commit instead cause you'll want both messages at once.
	/// This returns an option instead of a pure UpdateAddHTLC as we may be in a state where we are
	/// waiting on the remote peer to send us a revoke_and_ack during which time we cannot add new
	/// HTLCs on the wire or we wouldn't be able to determine what they actually ACK'ed.
	/// You MUST call send_commitment prior to any other calls on this Channel
	/// If an Err is returned, it's a ChannelError::Ignore!
	pub fn send_htlc(&mut self, amount_msat: u64, payment_hash: PaymentHash, cltv_expiry: u32, source: HTLCSource, onion_routing_packet: msgs::OnionPacket) -> Result<Option<msgs::UpdateAddHTLC>, ChannelError> {
		if (self.channel_state & (ChannelState::ChannelFunded as u32 | BOTH_SIDES_SHUTDOWN_MASK)) != (ChannelState::ChannelFunded as u32) {
			return Err(ChannelError::Ignore("Cannot send HTLC until channel is fully established and we haven't started shutting down"));
		}

		if amount_msat > self.channel_value_satoshis * 1000 {
			return Err(ChannelError::Ignore("Cannot send more than the total value of the channel"));
		}

		if amount_msat == 0 {
			return Err(ChannelError::Ignore("Cannot send 0-msat HTLC"));
		}

		if amount_msat < self.their_htlc_minimum_msat {
			return Err(ChannelError::Ignore("Cannot send less than their minimum HTLC value"));
		}

		if (self.channel_state & (ChannelState::PeerDisconnected as u32 | ChannelState::MonitorUpdateFailed as u32)) != 0 {
			// Note that this should never really happen, if we're !is_live() on receipt of an
			// incoming HTLC for relay will result in us rejecting the HTLC and we won't allow
			// the user to send directly into a !is_live() channel. However, if we
			// disconnected during the time the previous hop was doing the commitment dance we may
			// end up getting here after the forwarding delay. In any case, returning an
			// IgnoreError will get ChannelManager to do the right thing and fail backwards now.
			return Err(ChannelError::Ignore("Cannot send an HTLC while disconnected/frozen for channel monitor update"));
		}

		let (outbound_htlc_count, htlc_outbound_value_msat) = self.get_outbound_pending_htlc_stats();
		if outbound_htlc_count + 1 > self.their_max_accepted_htlcs as u32 {
			return Err(ChannelError::Ignore("Cannot push more than their max accepted HTLCs"));
		}
		// Check their_max_htlc_value_in_flight_msat
		if htlc_outbound_value_msat + amount_msat > self.their_max_htlc_value_in_flight_msat {
			return Err(ChannelError::Ignore("Cannot send value that would put us over the max HTLC value in flight our peer will accept"));
		}

		// Check self.local_channel_reserve_satoshis (the amount we must keep as
		// reserve for the remote to have something to claim if we misbehave)
		if self.value_to_self_msat < self.local_channel_reserve_satoshis * 1000 + amount_msat + htlc_outbound_value_msat {
			return Err(ChannelError::Ignore("Cannot send value that would put us under local channel reserve value"));
		}

		// Now update local state:
		if (self.channel_state & (ChannelState::AwaitingRemoteRevoke as u32)) == (ChannelState::AwaitingRemoteRevoke as u32) {
			self.holding_cell_htlc_updates.push(HTLCUpdateAwaitingACK::AddHTLC {
				amount_msat: amount_msat,
				payment_hash: payment_hash,
				cltv_expiry: cltv_expiry,
				source,
				onion_routing_packet: onion_routing_packet,
			});
			return Ok(None);
		}

		self.pending_outbound_htlcs.push(OutboundHTLCOutput {
			htlc_id: self.next_local_htlc_id,
			amount_msat: amount_msat,
			payment_hash: payment_hash.clone(),
			cltv_expiry: cltv_expiry,
			state: OutboundHTLCState::LocalAnnounced(Box::new(onion_routing_packet.clone())),
			source,
		});

		let res = msgs::UpdateAddHTLC {
			channel_id: self.channel_id,
			htlc_id: self.next_local_htlc_id,
			amount_msat: amount_msat,
			payment_hash: payment_hash,
			cltv_expiry: cltv_expiry,
			onion_routing_packet: onion_routing_packet,
		};
		self.next_local_htlc_id += 1;

		Ok(Some(res))
	}

	/// Creates a signed commitment transaction to send to the remote peer.
	/// Always returns a ChannelError::Close if an immediately-preceding (read: the
	/// last call to this Channel) send_htlc returned Ok(Some(_)) and there is an Err.
	/// May panic if called except immediately after a successful, Ok(Some(_))-returning send_htlc.
	pub fn send_commitment<L: Deref>(&mut self, logger: &L) -> Result<(msgs::CommitmentSigned, ChannelMonitorUpdate), ChannelError> where L::Target: Logger {
		if (self.channel_state & (ChannelState::ChannelFunded as u32)) != (ChannelState::ChannelFunded as u32) {
			panic!("Cannot create commitment tx until channel is fully established");
		}
		if (self.channel_state & (ChannelState::AwaitingRemoteRevoke as u32)) == (ChannelState::AwaitingRemoteRevoke as u32) {
			panic!("Cannot create commitment tx until remote revokes their previous commitment");
		}
		if (self.channel_state & (ChannelState::PeerDisconnected as u32)) == (ChannelState::PeerDisconnected as u32) {
			panic!("Cannot create commitment tx while disconnected, as send_htlc will have returned an Err so a send_commitment precondition has been violated");
		}
		if (self.channel_state & (ChannelState::MonitorUpdateFailed as u32)) == (ChannelState::MonitorUpdateFailed as u32) {
			panic!("Cannot create commitment tx while awaiting monitor update unfreeze, as send_htlc will have returned an Err so a send_commitment precondition has been violated");
		}
		let mut have_updates = self.pending_update_fee.is_some();
		for htlc in self.pending_outbound_htlcs.iter() {
			if let OutboundHTLCState::LocalAnnounced(_) = htlc.state {
				have_updates = true;
			}
			if have_updates { break; }
		}
		for htlc in self.pending_inbound_htlcs.iter() {
			if let InboundHTLCState::LocalRemoved(_) = htlc.state {
				have_updates = true;
			}
			if have_updates { break; }
		}
		if !have_updates {
			panic!("Cannot create commitment tx until we have some updates to send");
		}
		self.send_commitment_no_status_check(logger)
	}
	/// Only fails in case of bad keys
	fn send_commitment_no_status_check<L: Deref>(&mut self, logger: &L) -> Result<(msgs::CommitmentSigned, ChannelMonitorUpdate), ChannelError> where L::Target: Logger {
		// We can upgrade the status of some HTLCs that are waiting on a commitment, even if we
		// fail to generate this, we still are at least at a position where upgrading their status
		// is acceptable.
		for htlc in self.pending_inbound_htlcs.iter_mut() {
			let new_state = if let &InboundHTLCState::AwaitingRemoteRevokeToAnnounce(ref forward_info) = &htlc.state {
				Some(InboundHTLCState::AwaitingAnnouncedRemoteRevoke(forward_info.clone()))
			} else { None };
			if let Some(state) = new_state {
				htlc.state = state;
			}
		}
		for htlc in self.pending_outbound_htlcs.iter_mut() {
			if let Some(fail_reason) = if let &mut OutboundHTLCState::AwaitingRemoteRevokeToRemove(ref mut fail_reason) = &mut htlc.state {
				Some(fail_reason.take())
			} else { None } {
				htlc.state = OutboundHTLCState::AwaitingRemovedRemoteRevoke(fail_reason);
			}
		}
		self.resend_order = RAACommitmentOrder::RevokeAndACKFirst;

		let (res, remote_commitment_tx, htlcs) = match self.send_commitment_no_state_update(logger) {
			Ok((res, (remote_commitment_tx, mut htlcs))) => {
				// Update state now that we've passed all the can-fail calls...
				let htlcs_no_ref: Vec<(HTLCOutputInCommitment, Option<Box<HTLCSource>>)> =
					htlcs.drain(..).map(|(htlc, htlc_source)| (htlc, htlc_source.map(|source_ref| Box::new(source_ref.clone())))).collect();
				(res, remote_commitment_tx, htlcs_no_ref)
			},
			Err(e) => return Err(e),
		};

		self.latest_monitor_update_id += 1;
		let monitor_update = ChannelMonitorUpdate {
			update_id: self.latest_monitor_update_id,
			updates: vec![ChannelMonitorUpdateStep::LatestRemoteCommitmentTXInfo {
				unsigned_commitment_tx: remote_commitment_tx.clone(),
				htlc_outputs: htlcs.clone(),
				commitment_number: self.cur_remote_commitment_transaction_number,
				their_revocation_point: self.their_cur_commitment_point.unwrap()
			}]
		};
		self.channel_monitor.as_mut().unwrap().update_monitor_ooo(monitor_update.clone(), logger).unwrap();
		self.channel_state |= ChannelState::AwaitingRemoteRevoke as u32;
		Ok((res, monitor_update))
	}

	/// Only fails in case of bad keys. Used for channel_reestablish commitment_signed generation
	/// when we shouldn't change HTLC/channel state.
	fn send_commitment_no_state_update<L: Deref>(&self, logger: &L) -> Result<(msgs::CommitmentSigned, (Transaction, Vec<(HTLCOutputInCommitment, Option<&HTLCSource>)>)), ChannelError> where L::Target: Logger {
		let mut feerate_per_kw = self.feerate_per_kw;
		if let Some(feerate) = self.pending_update_fee {
			if self.channel_outbound {
				feerate_per_kw = feerate;
			}
		}

		let remote_keys = self.build_remote_transaction_keys()?;
		let remote_commitment_tx = self.build_commitment_transaction(self.cur_remote_commitment_transaction_number, &remote_keys, false, true, feerate_per_kw, logger);
		let (signature, htlc_signatures);

		{
			let mut htlcs = Vec::with_capacity(remote_commitment_tx.2.len());
			for &(ref htlc, _) in remote_commitment_tx.2.iter() {
				htlcs.push(htlc);
			}

			let res = self.local_keys.sign_remote_commitment(feerate_per_kw, &remote_commitment_tx.0, &remote_keys, &htlcs, self.our_to_self_delay, &self.secp_ctx)
				.map_err(|_| ChannelError::Close("Failed to get signatures for new commitment_signed"))?;
			signature = res.0;
			htlc_signatures = res.1;

			log_trace!(logger, "Signed remote commitment tx {} with redeemscript {} -> {}",
				encode::serialize_hex(&remote_commitment_tx.0),
				encode::serialize_hex(&self.get_funding_redeemscript()),
				log_bytes!(signature.serialize_compact()[..]));

			for (ref htlc_sig, ref htlc) in htlc_signatures.iter().zip(htlcs) {
				log_trace!(logger, "Signed remote HTLC tx {} with redeemscript {} with pubkey {} -> {}",
					encode::serialize_hex(&chan_utils::build_htlc_transaction(&remote_commitment_tx.0.txid(), feerate_per_kw, self.our_to_self_delay, htlc, &remote_keys.a_delayed_payment_key, &remote_keys.revocation_key)),
					encode::serialize_hex(&chan_utils::get_htlc_redeemscript(&htlc, &remote_keys)),
					log_bytes!(remote_keys.a_htlc_key.serialize()),
					log_bytes!(htlc_sig.serialize_compact()[..]));
			}
		}

		Ok((msgs::CommitmentSigned {
			channel_id: self.channel_id,
			signature,
			htlc_signatures,
		}, (remote_commitment_tx.0, remote_commitment_tx.2)))
	}

	/// Adds a pending outbound HTLC to this channel, and creates a signed commitment transaction
	/// to send to the remote peer in one go.
	/// Shorthand for calling send_htlc() followed by send_commitment(), see docs on those for
	/// more info.
	pub fn send_htlc_and_commit<L: Deref>(&mut self, amount_msat: u64, payment_hash: PaymentHash, cltv_expiry: u32, source: HTLCSource, onion_routing_packet: msgs::OnionPacket, logger: &L) -> Result<Option<(msgs::UpdateAddHTLC, msgs::CommitmentSigned, ChannelMonitorUpdate)>, ChannelError> where L::Target: Logger {
		match self.send_htlc(amount_msat, payment_hash, cltv_expiry, source, onion_routing_packet)? {
			Some(update_add_htlc) => {
				let (commitment_signed, monitor_update) = self.send_commitment_no_status_check(logger)?;
				Ok(Some((update_add_htlc, commitment_signed, monitor_update)))
			},
			None => Ok(None)
		}
	}

	/// Begins the shutdown process, getting a message for the remote peer and returning all
	/// holding cell HTLCs for payment failure.
	pub fn get_shutdown(&mut self) -> Result<(msgs::Shutdown, Vec<(HTLCSource, PaymentHash)>), APIError> {
		for htlc in self.pending_outbound_htlcs.iter() {
			if let OutboundHTLCState::LocalAnnounced(_) = htlc.state {
				return Err(APIError::APIMisuseError{err: "Cannot begin shutdown with pending HTLCs. Process pending events first"});
			}
		}
		if self.channel_state & BOTH_SIDES_SHUTDOWN_MASK != 0 {
			if (self.channel_state & ChannelState::LocalShutdownSent as u32) == ChannelState::LocalShutdownSent as u32 {
				return Err(APIError::APIMisuseError{err: "Shutdown already in progress"});
			}
			else if (self.channel_state & ChannelState::RemoteShutdownSent as u32) == ChannelState::RemoteShutdownSent as u32 {
				return Err(APIError::ChannelUnavailable{err: "Shutdown already in progress by remote"});
			}
		}
		assert_eq!(self.channel_state & ChannelState::ShutdownComplete as u32, 0);
		if self.channel_state & (ChannelState::PeerDisconnected as u32 | ChannelState::MonitorUpdateFailed as u32) != 0 {
			return Err(APIError::ChannelUnavailable{err: "Cannot begin shutdown while peer is disconnected or we're waiting on a monitor update, maybe force-close instead?"});
		}

		let our_closing_script = self.get_closing_scriptpubkey();

		// From here on out, we may not fail!
		if self.channel_state < ChannelState::FundingSent as u32 {
			self.channel_state = ChannelState::ShutdownComplete as u32;
		} else {
			self.channel_state |= ChannelState::LocalShutdownSent as u32;
		}
		self.update_time_counter += 1;

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

		Ok((msgs::Shutdown {
			channel_id: self.channel_id,
			scriptpubkey: our_closing_script,
		}, dropped_outbound_htlcs))
	}

	/// Gets the latest commitment transaction and any dependent transactions for relay (forcing
	/// shutdown of this channel - no more calls into this Channel may be made afterwards except
	/// those explicitly stated to be allowed after shutdown completes, eg some simple getters).
	/// Also returns the list of payment_hashes for channels which we can safely fail backwards
	/// immediately (others we will have to allow to time out).
	pub fn force_shutdown(&mut self, should_broadcast: bool) -> (Option<OutPoint>, ChannelMonitorUpdate, Vec<(HTLCSource, PaymentHash)>) {
		assert!(self.channel_state != ChannelState::ShutdownComplete as u32);

		// We go ahead and "free" any holding cell HTLCs or HTLCs we haven't yet committed to and
		// return them to fail the payment.
		let mut dropped_outbound_htlcs = Vec::with_capacity(self.holding_cell_htlc_updates.len());
		for htlc_update in self.holding_cell_htlc_updates.drain(..) {
			match htlc_update {
				HTLCUpdateAwaitingACK::AddHTLC { source, payment_hash, .. } => {
					dropped_outbound_htlcs.push((source, payment_hash));
				},
				_ => {}
			}
		}

		for _htlc in self.pending_outbound_htlcs.drain(..) {
			//TODO: Do something with the remaining HTLCs
			//(we need to have the ChannelManager monitor them so we can claim the inbound HTLCs
			//which correspond)
		}

		self.channel_state = ChannelState::ShutdownComplete as u32;
		self.update_time_counter += 1;
		self.latest_monitor_update_id += 1;
		(self.funding_txo.clone(), ChannelMonitorUpdate {
			update_id: self.latest_monitor_update_id,
			updates: vec![ChannelMonitorUpdateStep::ChannelForceClosed { should_broadcast }],
		}, dropped_outbound_htlcs)
	}
}

const SERIALIZATION_VERSION: u8 = 1;
const MIN_SERIALIZATION_VERSION: u8 = 1;

impl Writeable for InboundHTLCRemovalReason {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
		match self {
			&InboundHTLCRemovalReason::FailRelay(ref error_packet) => {
				0u8.write(writer)?;
				error_packet.write(writer)?;
			},
			&InboundHTLCRemovalReason::FailMalformed((ref onion_hash, ref err_code)) => {
				1u8.write(writer)?;
				onion_hash.write(writer)?;
				err_code.write(writer)?;
			},
			&InboundHTLCRemovalReason::Fulfill(ref payment_preimage) => {
				2u8.write(writer)?;
				payment_preimage.write(writer)?;
			},
		}
		Ok(())
	}
}

impl Readable for InboundHTLCRemovalReason {
	fn read<R: ::std::io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
		Ok(match <u8 as Readable>::read(reader)? {
			0 => InboundHTLCRemovalReason::FailRelay(Readable::read(reader)?),
			1 => InboundHTLCRemovalReason::FailMalformed((Readable::read(reader)?, Readable::read(reader)?)),
			2 => InboundHTLCRemovalReason::Fulfill(Readable::read(reader)?),
			_ => return Err(DecodeError::InvalidValue),
		})
	}
}

impl<ChanSigner: ChannelKeys + Writeable> Writeable for Channel<ChanSigner> {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
		// Note that we write out as if remove_uncommitted_htlcs_and_mark_paused had just been
		// called but include holding cell updates (and obviously we don't modify self).

		writer.write_all(&[SERIALIZATION_VERSION; 1])?;
		writer.write_all(&[MIN_SERIALIZATION_VERSION; 1])?;

		self.user_id.write(writer)?;
		self.config.write(writer)?;

		self.channel_id.write(writer)?;
		(self.channel_state | ChannelState::PeerDisconnected as u32).write(writer)?;
		self.channel_outbound.write(writer)?;
		self.channel_value_satoshis.write(writer)?;

		self.latest_monitor_update_id.write(writer)?;

		self.local_keys.write(writer)?;
		self.shutdown_pubkey.write(writer)?;
		self.destination_script.write(writer)?;

		self.cur_local_commitment_transaction_number.write(writer)?;
		self.cur_remote_commitment_transaction_number.write(writer)?;
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
				&OutboundHTLCState::RemoteRemoved(ref fail_reason) => {
					2u8.write(writer)?;
					fail_reason.write(writer)?;
				},
				&OutboundHTLCState::AwaitingRemoteRevokeToRemove(ref fail_reason) => {
					3u8.write(writer)?;
					fail_reason.write(writer)?;
				},
				&OutboundHTLCState::AwaitingRemovedRemoteRevoke(ref fail_reason) => {
					4u8.write(writer)?;
					fail_reason.write(writer)?;
				},
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

		self.monitor_pending_funding_locked.write(writer)?;
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

		self.pending_update_fee.write(writer)?;
		self.holding_cell_update_fee.write(writer)?;

		self.next_local_htlc_id.write(writer)?;
		(self.next_remote_htlc_id - dropped_inbound_htlcs).write(writer)?;
		self.update_time_counter.write(writer)?;
		self.feerate_per_kw.write(writer)?;

		match self.last_sent_closing_fee {
			Some((feerate, fee, sig)) => {
				1u8.write(writer)?;
				feerate.write(writer)?;
				fee.write(writer)?;
				sig.write(writer)?;
			},
			None => 0u8.write(writer)?,
		}

		self.funding_txo.write(writer)?;
		self.funding_tx_confirmed_in.write(writer)?;
		self.short_channel_id.write(writer)?;

		self.last_block_connected.write(writer)?;
		self.funding_tx_confirmations.write(writer)?;

		self.their_dust_limit_satoshis.write(writer)?;
		self.our_dust_limit_satoshis.write(writer)?;
		self.their_max_htlc_value_in_flight_msat.write(writer)?;
		self.local_channel_reserve_satoshis.write(writer)?;
		self.their_htlc_minimum_msat.write(writer)?;
		self.our_htlc_minimum_msat.write(writer)?;
		self.their_to_self_delay.write(writer)?;
		self.our_to_self_delay.write(writer)?;
		self.their_max_accepted_htlcs.write(writer)?;
		self.minimum_depth.write(writer)?;

		self.their_pubkeys.write(writer)?;
		self.their_cur_commitment_point.write(writer)?;

		self.their_prev_commitment_point.write(writer)?;
		self.their_node_id.write(writer)?;

		self.their_shutdown_scriptpubkey.write(writer)?;

		self.commitment_secrets.write(writer)?;

		self.channel_monitor.as_ref().unwrap().write_for_disk(writer)?;
		Ok(())
	}
}

impl<ChanSigner: ChannelKeys + Readable> Readable for Channel<ChanSigner> {
	fn read<R : ::std::io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
		let _ver: u8 = Readable::read(reader)?;
		let min_ver: u8 = Readable::read(reader)?;
		if min_ver > SERIALIZATION_VERSION {
			return Err(DecodeError::UnknownVersion);
		}

		let user_id = Readable::read(reader)?;
		let config: ChannelConfig = Readable::read(reader)?;

		let channel_id = Readable::read(reader)?;
		let channel_state = Readable::read(reader)?;
		let channel_outbound = Readable::read(reader)?;
		let channel_value_satoshis = Readable::read(reader)?;

		let latest_monitor_update_id = Readable::read(reader)?;

		let local_keys = Readable::read(reader)?;
		let shutdown_pubkey = Readable::read(reader)?;
		let destination_script = Readable::read(reader)?;

		let cur_local_commitment_transaction_number = Readable::read(reader)?;
		let cur_remote_commitment_transaction_number = Readable::read(reader)?;
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
					2 => OutboundHTLCState::RemoteRemoved(Readable::read(reader)?),
					3 => OutboundHTLCState::AwaitingRemoteRevokeToRemove(Readable::read(reader)?),
					4 => OutboundHTLCState::AwaitingRemovedRemoteRevoke(Readable::read(reader)?),
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

		let monitor_pending_funding_locked = Readable::read(reader)?;
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

		let pending_update_fee = Readable::read(reader)?;
		let holding_cell_update_fee = Readable::read(reader)?;

		let next_local_htlc_id = Readable::read(reader)?;
		let next_remote_htlc_id = Readable::read(reader)?;
		let update_time_counter = Readable::read(reader)?;
		let feerate_per_kw = Readable::read(reader)?;

		let last_sent_closing_fee = match <u8 as Readable>::read(reader)? {
			0 => None,
			1 => Some((Readable::read(reader)?, Readable::read(reader)?, Readable::read(reader)?)),
			_ => return Err(DecodeError::InvalidValue),
		};

		let funding_txo = Readable::read(reader)?;
		let funding_tx_confirmed_in = Readable::read(reader)?;
		let short_channel_id = Readable::read(reader)?;

		let last_block_connected = Readable::read(reader)?;
		let funding_tx_confirmations = Readable::read(reader)?;

		let their_dust_limit_satoshis = Readable::read(reader)?;
		let our_dust_limit_satoshis = Readable::read(reader)?;
		let their_max_htlc_value_in_flight_msat = Readable::read(reader)?;
		let local_channel_reserve_satoshis = Readable::read(reader)?;
		let their_htlc_minimum_msat = Readable::read(reader)?;
		let our_htlc_minimum_msat = Readable::read(reader)?;
		let their_to_self_delay = Readable::read(reader)?;
		let our_to_self_delay = Readable::read(reader)?;
		let their_max_accepted_htlcs = Readable::read(reader)?;
		let minimum_depth = Readable::read(reader)?;

		let their_pubkeys = Readable::read(reader)?;
		let their_cur_commitment_point = Readable::read(reader)?;

		let their_prev_commitment_point = Readable::read(reader)?;
		let their_node_id = Readable::read(reader)?;

		let their_shutdown_scriptpubkey = Readable::read(reader)?;
		let commitment_secrets = Readable::read(reader)?;

		let (monitor_last_block, channel_monitor) = Readable::read(reader)?;
		// We drop the ChannelMonitor's last block connected hash cause we don't actually bother
		// doing full block connection operations on the internal ChannelMonitor copies
		if monitor_last_block != last_block_connected {
			return Err(DecodeError::InvalidValue);
		}

		Ok(Channel {
			user_id,

			config,
			channel_id,
			channel_state,
			channel_outbound,
			secp_ctx: Secp256k1::new(),
			channel_value_satoshis,

			latest_monitor_update_id,

			local_keys,
			shutdown_pubkey,
			destination_script,

			cur_local_commitment_transaction_number,
			cur_remote_commitment_transaction_number,
			value_to_self_msat,

			pending_inbound_htlcs,
			pending_outbound_htlcs,
			holding_cell_htlc_updates,

			resend_order,

			monitor_pending_funding_locked,
			monitor_pending_revoke_and_ack,
			monitor_pending_commitment_signed,
			monitor_pending_forwards,
			monitor_pending_failures,

			pending_update_fee,
			holding_cell_update_fee,
			next_local_htlc_id,
			next_remote_htlc_id,
			update_time_counter,
			feerate_per_kw,

			#[cfg(debug_assertions)]
			max_commitment_tx_output_local: ::std::sync::Mutex::new((0, 0)),
			#[cfg(debug_assertions)]
			max_commitment_tx_output_remote: ::std::sync::Mutex::new((0, 0)),

			last_sent_closing_fee,

			funding_txo,
			funding_tx_confirmed_in,
			short_channel_id,
			last_block_connected,
			funding_tx_confirmations,

			their_dust_limit_satoshis,
			our_dust_limit_satoshis,
			their_max_htlc_value_in_flight_msat,
			local_channel_reserve_satoshis,
			their_htlc_minimum_msat,
			our_htlc_minimum_msat,
			their_to_self_delay,
			our_to_self_delay,
			their_max_accepted_htlcs,
			minimum_depth,

			their_pubkeys,
			their_cur_commitment_point,

			their_prev_commitment_point,
			their_node_id,

			their_shutdown_scriptpubkey,

			channel_monitor: Some(channel_monitor),
			commitment_secrets,

			network_sync: UpdateStatus::Fresh,
		})
	}
}

#[cfg(test)]
mod tests {
	use bitcoin::BitcoinHash;
	use bitcoin::util::bip143;
	use bitcoin::consensus::encode::serialize;
	use bitcoin::blockdata::script::{Script, Builder};
	use bitcoin::blockdata::transaction::{Transaction, TxOut};
	use bitcoin::blockdata::constants::genesis_block;
	use bitcoin::blockdata::opcodes;
	use bitcoin::network::constants::Network;
	use bitcoin::hashes::hex::FromHex;
	use hex;
	use ln::channelmanager::{HTLCSource, PaymentPreimage, PaymentHash};
	use ln::channel::{Channel,ChannelKeys,InboundHTLCOutput,OutboundHTLCOutput,InboundHTLCState,OutboundHTLCState,HTLCOutputInCommitment,TxCreationKeys};
	use ln::channel::MAX_FUNDING_SATOSHIS;
	use ln::features::InitFeatures;
	use ln::msgs::{OptionalField, DataLossProtect};
	use ln::chan_utils;
	use ln::chan_utils::{LocalCommitmentTransaction, ChannelPublicKeys};
	use chain::chaininterface::{FeeEstimator,ConfirmationTarget};
	use chain::keysinterface::{InMemoryChannelKeys, KeysInterface};
	use chain::transaction::OutPoint;
	use util::config::UserConfig;
	use util::enforcing_trait_impls::EnforcingChannelKeys;
	use util::test_utils;
	use util::logger::Logger;
	use bitcoin::secp256k1::{Secp256k1, Message, Signature, All};
	use bitcoin::secp256k1::key::{SecretKey,PublicKey};
	use bitcoin::hashes::sha256::Hash as Sha256;
	use bitcoin::hashes::Hash;
	use bitcoin::hash_types::{Txid, WPubkeyHash};
	use std::sync::Arc;
	use rand::{thread_rng,Rng};

	struct TestFeeEstimator {
		fee_est: u64
	}
	impl FeeEstimator for TestFeeEstimator {
		fn get_est_sat_per_1000_weight(&self, _: ConfirmationTarget) -> u64 {
			self.fee_est
		}
	}

	#[test]
	fn test_max_funding_satoshis() {
		assert!(MAX_FUNDING_SATOSHIS <= 21_000_000 * 100_000_000,
		        "MAX_FUNDING_SATOSHIS is greater than all satoshis in existence");
	}

	struct Keys {
		chan_keys: InMemoryChannelKeys,
	}
	impl KeysInterface for Keys {
		type ChanKeySigner = InMemoryChannelKeys;

		fn get_node_secret(&self) -> SecretKey { panic!(); }
		fn get_destination_script(&self) -> Script {
			let secp_ctx = Secp256k1::signing_only();
			let channel_monitor_claim_key = SecretKey::from_slice(&hex::decode("0fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").unwrap()[..]).unwrap();
			let our_channel_monitor_claim_key_hash = WPubkeyHash::hash(&PublicKey::from_secret_key(&secp_ctx, &channel_monitor_claim_key).serialize());
			Builder::new().push_opcode(opcodes::all::OP_PUSHBYTES_0).push_slice(&our_channel_monitor_claim_key_hash[..]).into_script()
		}

		fn get_shutdown_pubkey(&self) -> PublicKey {
			let secp_ctx = Secp256k1::signing_only();
			let channel_close_key = SecretKey::from_slice(&hex::decode("0fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").unwrap()[..]).unwrap();
			PublicKey::from_secret_key(&secp_ctx, &channel_close_key)
		}

		fn get_channel_keys(&self, _inbound: bool, _channel_value_satoshis: u64) -> InMemoryChannelKeys {
			self.chan_keys.clone()
		}
		fn get_onion_rand(&self) -> (SecretKey, [u8; 32]) { panic!(); }
		fn get_channel_id(&self) -> [u8; 32] { [0; 32] }
	}

	fn public_from_secret_hex(secp_ctx: &Secp256k1<All>, hex: &str) -> PublicKey {
		PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&hex::decode(hex).unwrap()[..]).unwrap())
	}

	#[test]
	fn channel_reestablish_no_updates() {
		let feeest = TestFeeEstimator{fee_est: 15000};
		let logger = test_utils::TestLogger::new();
		let secp_ctx = Secp256k1::new();
		let mut seed = [0; 32];
		let mut rng = thread_rng();
		rng.fill_bytes(&mut seed);
		let network = Network::Testnet;
		let keys_provider = test_utils::TestKeysInterface::new(&seed, network);

		// Go through the flow of opening a channel between two nodes.

		// Create Node A's channel
		let node_a_node_id = PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[42; 32]).unwrap());
		let config = UserConfig::default();
		let mut node_a_chan = Channel::<EnforcingChannelKeys>::new_outbound(&&feeest, &&keys_provider, node_a_node_id, 10000000, 100000, 42, &config).unwrap();

		// Create Node B's channel by receiving Node A's open_channel message
		let open_channel_msg = node_a_chan.get_open_channel(genesis_block(network).header.bitcoin_hash(), &&feeest);
		let node_b_node_id = PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[7; 32]).unwrap());
		let mut node_b_chan = Channel::<EnforcingChannelKeys>::new_from_req(&&feeest, &&keys_provider, node_b_node_id, InitFeatures::known(), &open_channel_msg, 7, &config).unwrap();

		// Node B --> Node A: accept channel
		let accept_channel_msg = node_b_chan.get_accept_channel();
		node_a_chan.accept_channel(&accept_channel_msg, &config, InitFeatures::known()).unwrap();

		// Node A --> Node B: funding created
		let output_script = node_a_chan.get_funding_redeemscript();
		let tx = Transaction { version: 1, lock_time: 0, input: Vec::new(), output: vec![TxOut {
			value: 10000000, script_pubkey: output_script.clone(),
		}]};
		let funding_outpoint = OutPoint::new(tx.txid(), 0);
		let funding_created_msg = node_a_chan.get_outbound_funding_created(funding_outpoint, &&logger).unwrap();
		let (funding_signed_msg, _) = node_b_chan.funding_created(&funding_created_msg, &&logger).unwrap();

		// Node B --> Node A: funding signed
		let _ = node_a_chan.funding_signed(&funding_signed_msg, &&logger);

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
	fn outbound_commitment_test() {
		// Test vectors from BOLT 3 Appendix C:
		let feeest = TestFeeEstimator{fee_est: 15000};
		let logger : Arc<Logger> = Arc::new(test_utils::TestLogger::new());
		let secp_ctx = Secp256k1::new();

		let mut chan_keys = InMemoryChannelKeys::new(
			&secp_ctx,
			SecretKey::from_slice(&hex::decode("30ff4956bbdd3222d44cc5e8a1261dab1e07957bdac5ae88fe3261ef321f3749").unwrap()[..]).unwrap(),
			SecretKey::from_slice(&hex::decode("0fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").unwrap()[..]).unwrap(),
			SecretKey::from_slice(&hex::decode("1111111111111111111111111111111111111111111111111111111111111111").unwrap()[..]).unwrap(),
			SecretKey::from_slice(&hex::decode("3333333333333333333333333333333333333333333333333333333333333333").unwrap()[..]).unwrap(),
			SecretKey::from_slice(&hex::decode("1111111111111111111111111111111111111111111111111111111111111111").unwrap()[..]).unwrap(),

			// These aren't set in the test vectors:
			[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
			10_000_000,
		);

		assert_eq!(PublicKey::from_secret_key(&secp_ctx, chan_keys.funding_key()).serialize()[..],
				hex::decode("023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb").unwrap()[..]);
		let keys_provider = Keys { chan_keys: chan_keys.clone() };

		let their_node_id = PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[42; 32]).unwrap());
		let mut config = UserConfig::default();
		config.channel_options.announced_channel = false;
		let mut chan = Channel::<InMemoryChannelKeys>::new_outbound(&&feeest, &&keys_provider, their_node_id, 10_000_000, 100000, 42, &config).unwrap(); // Nothing uses their network key in this test
		chan.their_to_self_delay = 144;
		chan.our_dust_limit_satoshis = 546;

		let funding_info = OutPoint::new(Txid::from_hex("8984484a580b825b9972d7adb15050b3ab624ccd731946b3eeddb92f4e7ef6be").unwrap(), 0);
		chan.funding_txo = Some(funding_info);

		let their_pubkeys = ChannelPublicKeys {
			funding_pubkey: public_from_secret_hex(&secp_ctx, "1552dfba4f6cf29a62a0af13c8d6981d36d0ef8d61ba10fb0fe90da7634d7e13"),
			revocation_basepoint: PublicKey::from_slice(&hex::decode("02466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27").unwrap()[..]).unwrap(),
			payment_point: public_from_secret_hex(&secp_ctx, "4444444444444444444444444444444444444444444444444444444444444444"),
			delayed_payment_basepoint: public_from_secret_hex(&secp_ctx, "1552dfba4f6cf29a62a0af13c8d6981d36d0ef8d61ba10fb0fe90da7634d7e13"),
			htlc_basepoint: public_from_secret_hex(&secp_ctx, "4444444444444444444444444444444444444444444444444444444444444444")
		};
		chan_keys.set_remote_channel_pubkeys(&their_pubkeys);

		assert_eq!(their_pubkeys.payment_point.serialize()[..],
		           hex::decode("032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991").unwrap()[..]);

		assert_eq!(their_pubkeys.funding_pubkey.serialize()[..],
		           hex::decode("030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c1").unwrap()[..]);

		assert_eq!(their_pubkeys.htlc_basepoint.serialize()[..],
		           hex::decode("032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991").unwrap()[..]);

		// We can't just use build_local_transaction_keys here as the per_commitment_secret is not
		// derived from a commitment_seed, so instead we copy it here and call
		// build_commitment_transaction.
		let delayed_payment_base = PublicKey::from_secret_key(&secp_ctx, chan.local_keys.delayed_payment_base_key());
		let per_commitment_secret = SecretKey::from_slice(&hex::decode("1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100").unwrap()[..]).unwrap();
		let per_commitment_point = PublicKey::from_secret_key(&secp_ctx, &per_commitment_secret);
		let htlc_basepoint = PublicKey::from_secret_key(&secp_ctx, chan.local_keys.htlc_base_key());
		let keys = TxCreationKeys::new(&secp_ctx, &per_commitment_point, &delayed_payment_base, &htlc_basepoint, &their_pubkeys.revocation_basepoint, &their_pubkeys.htlc_basepoint).unwrap();

		chan.their_pubkeys = Some(their_pubkeys);

		let mut unsigned_tx: (Transaction, Vec<HTLCOutputInCommitment>);

		let mut localtx;
		macro_rules! test_commitment {
			( $their_sig_hex: expr, $our_sig_hex: expr, $tx_hex: expr, {
				$( { $htlc_idx: expr, $their_htlc_sig_hex: expr, $our_htlc_sig_hex: expr, $htlc_tx_hex: expr } ), *
			} ) => { {
				unsigned_tx = {
					let mut res = chan.build_commitment_transaction(0xffffffffffff - 42, &keys, true, false, chan.feerate_per_kw, &logger);
					let htlcs = res.2.drain(..)
						.filter_map(|(htlc, _)| if htlc.transaction_output_index.is_some() { Some(htlc) } else { None })
						.collect();
					(res.0, htlcs)
				};
				let redeemscript = chan.get_funding_redeemscript();
				let their_signature = Signature::from_der(&hex::decode($their_sig_hex).unwrap()[..]).unwrap();
				let sighash = Message::from_slice(&bip143::SighashComponents::new(&unsigned_tx.0).sighash_all(&unsigned_tx.0.input[0], &redeemscript, chan.channel_value_satoshis)[..]).unwrap();
				secp_ctx.verify(&sighash, &their_signature, chan.their_funding_pubkey()).unwrap();

				let mut per_htlc = Vec::new();
				per_htlc.clear(); // Don't warn about excess mut for no-HTLC calls
				$({
					let remote_signature = Signature::from_der(&hex::decode($their_htlc_sig_hex).unwrap()[..]).unwrap();
					per_htlc.push((unsigned_tx.1[$htlc_idx].clone(), Some(remote_signature)));
				})*
				assert_eq!(unsigned_tx.1.len(), per_htlc.len());

				localtx = LocalCommitmentTransaction::new_missing_local_sig(unsigned_tx.0.clone(), their_signature.clone(), &PublicKey::from_secret_key(&secp_ctx, chan.local_keys.funding_key()), chan.their_funding_pubkey(), keys.clone(), chan.feerate_per_kw, per_htlc);
				let local_sig = chan_keys.sign_local_commitment(&localtx, &chan.secp_ctx).unwrap();
				assert_eq!(Signature::from_der(&hex::decode($our_sig_hex).unwrap()[..]).unwrap(), local_sig);

				assert_eq!(serialize(&localtx.add_local_sig(&redeemscript, local_sig))[..],
						hex::decode($tx_hex).unwrap()[..]);

				let htlc_sigs = chan_keys.sign_local_commitment_htlc_transactions(&localtx, chan.their_to_self_delay, &chan.secp_ctx).unwrap();
				let mut htlc_sig_iter = localtx.per_htlc.iter().zip(htlc_sigs.iter().enumerate());

				$({
					let remote_signature = Signature::from_der(&hex::decode($their_htlc_sig_hex).unwrap()[..]).unwrap();

					let ref htlc = unsigned_tx.1[$htlc_idx];
					let htlc_tx = chan.build_htlc_transaction(&unsigned_tx.0.txid(), &htlc, true, &keys, chan.feerate_per_kw);
					let htlc_redeemscript = chan_utils::get_htlc_redeemscript(&htlc, &keys);
					let htlc_sighash = Message::from_slice(&bip143::SighashComponents::new(&htlc_tx).sighash_all(&htlc_tx.input[0], &htlc_redeemscript, htlc.amount_msat / 1000)[..]).unwrap();
					secp_ctx.verify(&htlc_sighash, &remote_signature, &keys.b_htlc_key).unwrap();

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

					let mut htlc_sig = htlc_sig_iter.next().unwrap();
					while (htlc_sig.1).1.is_none() { htlc_sig = htlc_sig_iter.next().unwrap(); }
					assert_eq!((htlc_sig.0).0.transaction_output_index, Some($htlc_idx));

					let our_signature = Signature::from_der(&hex::decode($our_htlc_sig_hex).unwrap()[..]).unwrap();
					assert_eq!(Some(our_signature), *(htlc_sig.1).1);
					assert_eq!(serialize(&localtx.get_signed_htlc_tx((htlc_sig.1).0, &(htlc_sig.1).1.unwrap(), &preimage, chan.their_to_self_delay))[..],
							hex::decode($htlc_tx_hex).unwrap()[..]);
				})*
				loop {
					let htlc_sig = htlc_sig_iter.next();
					if htlc_sig.is_none() { break; }
					assert!((htlc_sig.unwrap().1).1.is_none());
				}
			} }
		}

		// simple commitment tx with no HTLCs
		chan.value_to_self_msat = 7000000000;

		test_commitment!("3045022100c3127b33dcc741dd6b05b1e63cbd1a9a7d816f37af9b6756fa2376b056f032370220408b96279808fe57eb7e463710804cdf4f108388bc5cf722d8c848d2c7f9f3b0",
						 "30440220616210b2cc4d3afb601013c373bbd8aac54febd9f15400379a8cb65ce7deca60022034236c010991beb7ff770510561ae8dc885b8d38d1947248c38f2ae055647142",
						 "02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b8002c0c62d0000000000160014cc1b07838e387deacd0e5232e1e8b49f4c29e48454a56a00000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e04004730440220616210b2cc4d3afb601013c373bbd8aac54febd9f15400379a8cb65ce7deca60022034236c010991beb7ff770510561ae8dc885b8d38d1947248c38f2ae05564714201483045022100c3127b33dcc741dd6b05b1e63cbd1a9a7d816f37af9b6756fa2376b056f032370220408b96279808fe57eb7e463710804cdf4f108388bc5cf722d8c848d2c7f9f3b001475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae3e195220", {});

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

		// commitment tx with six outputs untrimmed (maximum feerate)
		chan.value_to_self_msat = 6993000000; // 7000000000 - 7000000
		chan.feerate_per_kw = 2069;

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

		// commitment tx with four outputs untrimmed (maximum feerate)
		chan.value_to_self_msat = 6993000000; // 7000000000 - 7000000
		chan.feerate_per_kw = 3702;

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

		// commitment tx with three outputs untrimmed (maximum feerate)
		chan.value_to_self_msat = 6993000000; // 7000000000 - 7000000
		chan.feerate_per_kw = 4914;

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

		test_commitment!("304402203a286936e74870ca1459c700c71202af0381910a6bfab687ef494ef1bc3e02c902202506c362d0e3bee15e802aa729bf378e051644648253513f1c085b264cc2a720",
		                 "30450221008a953551f4d67cb4df3037207fc082ddaf6be84d417b0bd14c80aab66f1b01a402207508796dc75034b2dee876fe01dc05a08b019f3e5d689ac8842ade2f1befccf5",
		                 "02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b8002c0c62d0000000000160014cc1b07838e387deacd0e5232e1e8b49f4c29e484fa926a00000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e04004830450221008a953551f4d67cb4df3037207fc082ddaf6be84d417b0bd14c80aab66f1b01a402207508796dc75034b2dee876fe01dc05a08b019f3e5d689ac8842ade2f1befccf50147304402203a286936e74870ca1459c700c71202af0381910a6bfab687ef494ef1bc3e02c902202506c362d0e3bee15e802aa729bf378e051644648253513f1c085b264cc2a72001475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae3e195220", {});

		// commitment tx with two outputs untrimmed (maximum feerate)
		chan.value_to_self_msat = 6993000000; // 7000000000 - 7000000
		chan.feerate_per_kw = 9651180;

		test_commitment!("304402200a8544eba1d216f5c5e530597665fa9bec56943c0f66d98fc3d028df52d84f7002201e45fa5c6bc3a506cc2553e7d1c0043a9811313fc39c954692c0d47cfce2bbd3",
		                 "3045022100e11b638c05c650c2f63a421d36ef8756c5ce82f2184278643520311cdf50aa200220259565fb9c8e4a87ccaf17f27a3b9ca4f20625754a0920d9c6c239d8156a11de",
		                 "02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b800222020000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80ec0c62d0000000000160014cc1b07838e387deacd0e5232e1e8b49f4c29e4840400483045022100e11b638c05c650c2f63a421d36ef8756c5ce82f2184278643520311cdf50aa200220259565fb9c8e4a87ccaf17f27a3b9ca4f20625754a0920d9c6c239d8156a11de0147304402200a8544eba1d216f5c5e530597665fa9bec56943c0f66d98fc3d028df52d84f7002201e45fa5c6bc3a506cc2553e7d1c0043a9811313fc39c954692c0d47cfce2bbd301475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae3e195220", {});

		// commitment tx with one output untrimmed (minimum feerate)
		chan.value_to_self_msat = 6993000000; // 7000000000 - 7000000
		chan.feerate_per_kw = 9651181;

		test_commitment!("304402202ade0142008309eb376736575ad58d03e5b115499709c6db0b46e36ff394b492022037b63d78d66404d6504d4c4ac13be346f3d1802928a6d3ad95a6a944227161a2",
		                 "304402207e8d51e0c570a5868a78414f4e0cbfaed1106b171b9581542c30718ee4eb95ba02203af84194c97adf98898c9afe2f2ed4a7f8dba05a2dfab28ac9d9c604aa49a379",
		                 "02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b8001c0c62d0000000000160014cc1b07838e387deacd0e5232e1e8b49f4c29e484040047304402207e8d51e0c570a5868a78414f4e0cbfaed1106b171b9581542c30718ee4eb95ba02203af84194c97adf98898c9afe2f2ed4a7f8dba05a2dfab28ac9d9c604aa49a3790147304402202ade0142008309eb376736575ad58d03e5b115499709c6db0b46e36ff394b492022037b63d78d66404d6504d4c4ac13be346f3d1802928a6d3ad95a6a944227161a201475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae3e195220", {});

		// commitment tx with fee greater than funder amount
		chan.value_to_self_msat = 6993000000; // 7000000000 - 7000000
		chan.feerate_per_kw = 9651936;

		test_commitment!("304402202ade0142008309eb376736575ad58d03e5b115499709c6db0b46e36ff394b492022037b63d78d66404d6504d4c4ac13be346f3d1802928a6d3ad95a6a944227161a2",
		                 "304402207e8d51e0c570a5868a78414f4e0cbfaed1106b171b9581542c30718ee4eb95ba02203af84194c97adf98898c9afe2f2ed4a7f8dba05a2dfab28ac9d9c604aa49a379",
		                 "02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b8001c0c62d0000000000160014cc1b07838e387deacd0e5232e1e8b49f4c29e484040047304402207e8d51e0c570a5868a78414f4e0cbfaed1106b171b9581542c30718ee4eb95ba02203af84194c97adf98898c9afe2f2ed4a7f8dba05a2dfab28ac9d9c604aa49a3790147304402202ade0142008309eb376736575ad58d03e5b115499709c6db0b46e36ff394b492022037b63d78d66404d6504d4c4ac13be346f3d1802928a6d3ad95a6a944227161a201475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae3e195220", {});
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

		assert_eq!(chan_utils::derive_public_key(&secp_ctx, &per_commitment_point, &base_point).unwrap().serialize()[..],
				hex::decode("0235f2dbfaa89b57ec7b055afe29849ef7ddfeb1cefdb9ebdc43f5494984db29e5").unwrap()[..]);

		assert_eq!(chan_utils::derive_private_key(&secp_ctx, &per_commitment_point, &base_secret).unwrap(),
				SecretKey::from_slice(&hex::decode("cbced912d3b21bf196a766651e436aff192362621ce317704ea2f75d87e7be0f").unwrap()[..]).unwrap());

		assert_eq!(chan_utils::derive_public_revocation_key(&secp_ctx, &per_commitment_point, &base_point).unwrap().serialize()[..],
				hex::decode("02916e326636d19c33f13e8c0c3a03dd157f332f3e99c317c141dd865eb01f8ff0").unwrap()[..]);

		assert_eq!(chan_utils::derive_private_revocation_key(&secp_ctx, &per_commitment_secret, &base_secret).unwrap(),
				SecretKey::from_slice(&hex::decode("d09ffff62ddb2297ab000cc85bcb4283fdeb6aa052affbc9dddcf33b61078110").unwrap()[..]).unwrap());
	}
}
