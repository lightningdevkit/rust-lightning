use bitcoin::blockdata::block::BlockHeader;
use bitcoin::blockdata::script::{Script,Builder};
use bitcoin::blockdata::transaction::{TxIn, TxOut, Transaction, SigHashType};
use bitcoin::blockdata::opcodes;
use bitcoin::util::hash::BitcoinHash;
use bitcoin::util::bip143;
use bitcoin::consensus::encode::{self, Encodable, Decodable};

use bitcoin_hashes::{Hash, HashEngine};
use bitcoin_hashes::sha256::Hash as Sha256;
use bitcoin_hashes::hash160::Hash as Hash160;
use bitcoin_hashes::sha256d::Hash as Sha256dHash;

use secp256k1::key::{PublicKey,SecretKey};
use secp256k1::{Secp256k1,Signature};
use secp256k1;

use ln::msgs;
use ln::msgs::{DecodeError, OptionalField, LocalFeatures, DataLossProtect};
use ln::channelmonitor::ChannelMonitor;
use ln::channelmanager::{PendingHTLCStatus, HTLCSource, HTLCFailReason, HTLCFailureMsg, PendingForwardHTLCInfo, RAACommitmentOrder, PaymentPreimage, PaymentHash, BREAKDOWN_TIMEOUT, MAX_LOCAL_BREAKDOWN_TIMEOUT};
use ln::chan_utils::{TxCreationKeys,HTLCOutputInCommitment,HTLC_SUCCESS_TX_WEIGHT,HTLC_TIMEOUT_TX_WEIGHT};
use ln::chan_utils;
use chain::chaininterface::{FeeEstimator,ConfirmationTarget};
use chain::transaction::OutPoint;
use chain::keysinterface::{ChannelKeys, KeysInterface};
use util::transaction_utils;
use util::ser::{Readable, ReadableArgs, Writeable, Writer, WriterWriteAdaptor};
use util::logger::{Logger, LogHolder};
use util::errors::APIError;
use util::config::{UserConfig,ChannelConfig};

use std;
use std::default::Default;
use std::{cmp,mem,fmt};
use std::sync::{Arc};

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
const BOTH_SIDES_SHUTDOWN_MASK: u32 = (ChannelState::LocalShutdownSent as u32 | ChannelState::RemoteShutdownSent as u32);
const MULTI_STATE_FLAGS: u32 = (BOTH_SIDES_SHUTDOWN_MASK | ChannelState::PeerDisconnected as u32 | ChannelState::MonitorUpdateFailed as u32);

const INITIAL_COMMITMENT_NUMBER: u64 = (1 << 48) - 1;

// TODO: We should refactor this to be an Inbound/OutboundChannel until initial setup handshaking
// has been completed, and then turn into a Channel to get compiler-time enforcement of things like
// calling channel_id() before we're set up or things like get_outbound_funding_signed on an
// inbound channel.
pub(super) struct Channel {
	config: ChannelConfig,

	user_id: u64,

	channel_id: [u8; 32],
	channel_state: u32,
	channel_outbound: bool,
	secp_ctx: Secp256k1<secp256k1::All>,
	channel_value_satoshis: u64,

	local_keys: ChannelKeys,
	shutdown_pubkey: PublicKey,

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
	monitor_pending_forwards: Vec<(PendingForwardHTLCInfo, u64)>,
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
	channel_update_count: u32,
	feerate_per_kw: u64,

	#[cfg(debug_assertions)]
	/// Max to_local and to_remote outputs in a locally-generated commitment transaction
	max_commitment_tx_output_local: ::std::sync::Mutex<(u64, u64)>,
	#[cfg(debug_assertions)]
	/// Max to_local and to_remote outputs in a remote-generated commitment transaction
	max_commitment_tx_output_remote: ::std::sync::Mutex<(u64, u64)>,

	#[cfg(test)]
	// Used in ChannelManager's tests to send a revoked transaction
	pub last_local_commitment_txn: Vec<Transaction>,
	#[cfg(not(test))]
	last_local_commitment_txn: Vec<Transaction>,

	last_sent_closing_fee: Option<(u64, u64)>, // (feerate, fee)

	/// The hash of the block in which the funding transaction reached our CONF_TARGET. We use this
	/// to detect unconfirmation after a serialize-unserialize roundtrip where we may not see a full
	/// series of block_connected/block_disconnected calls. Obviously this is not a guarantee as we
	/// could miss the funding_tx_confirmed_in block as well, but it serves as a useful fallback.
	funding_tx_confirmed_in: Option<Sha256dHash>,
	short_channel_id: Option<u64>,
	/// Used to deduplicate block_connected callbacks, also used to verify consistency during
	/// ChannelManager deserialization (hence pub(super))
	pub(super) last_block_connected: Sha256dHash,
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
	/// minimum channel reserve for **self** to maintain - set by them.
	their_channel_reserve_satoshis: u64,
	//get_our_channel_reserve_satoshis(): u64,
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

	their_funding_pubkey: Option<PublicKey>,
	their_revocation_basepoint: Option<PublicKey>,
	their_payment_basepoint: Option<PublicKey>,
	their_delayed_payment_basepoint: Option<PublicKey>,
	their_htlc_basepoint: Option<PublicKey>,
	their_cur_commitment_point: Option<PublicKey>,

	their_prev_commitment_point: Option<PublicKey>,
	their_node_id: PublicKey,

	their_shutdown_scriptpubkey: Option<Script>,

	channel_monitor: ChannelMonitor,

	logger: Arc<Logger>,
}

pub const OUR_MAX_HTLCS: u16 = 50; //TODO
/// Confirmation count threshold at which we close a channel. Ideally we'd keep the channel around
/// on ice until the funding transaction gets more confirmations, but the LN protocol doesn't
/// really allow for this, so instead we're stuck closing it out at that point.
const UNCONF_THRESHOLD: u32 = 6;
/// Exposing these two constants for use in test in ChannelMonitor
pub const COMMITMENT_TX_BASE_WEIGHT: u64 = 724;
pub const COMMITMENT_TX_WEIGHT_PER_HTLC: u64 = 172;
const SPENDING_INPUT_FOR_A_OUTPUT_WEIGHT: u64 = 79; // prevout: 36, nSequence: 4, script len: 1, witness lengths: (3+1)/4, sig: 73/4, if-selector: 1, redeemScript: (6 ops + 2*33 pubkeys + 1*2 delay)/4
const B_OUTPUT_PLUS_SPENDING_INPUT_WEIGHT: u64 = 104; // prevout: 40, nSequence: 4, script len: 1, witness lengths: 3/4, sig: 73/4, pubkey: 33/4, output: 31 (TODO: Wrong? Useless?)
/// Maximmum `funding_satoshis` value, according to the BOLT #2 specification
/// it's 2^24.
pub const MAX_FUNDING_SATOSHIS: u64 = (1 << 24);

#[cfg(test)]
pub const ACCEPTED_HTLC_SCRIPT_WEIGHT: usize = 138; //Here we have a diff due to HTLC CLTV expiry being < 2^15 in test
#[cfg(not(test))]
pub const ACCEPTED_HTLC_SCRIPT_WEIGHT: usize = 139;
pub const OFFERED_HTLC_SCRIPT_WEIGHT: usize = 133;

/// Used to return a simple Error back to ChannelManager. Will get converted to a
/// msgs::ErrorAction::SendErrorMessage or msgs::ErrorAction::IgnoreError as appropriate with our
/// channel_id in ChannelManager.
pub(super) enum ChannelError {
	Ignore(&'static str),
	Close(&'static str),
	CloseDelayBroadcast {
		msg: &'static str,
		update: Option<ChannelMonitor>
	},
}

impl fmt::Debug for ChannelError {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self {
			&ChannelError::Ignore(e) => write!(f, "Ignore : {}", e),
			&ChannelError::Close(e) => write!(f, "Close : {}", e),
			&ChannelError::CloseDelayBroadcast { msg, .. } => write!(f, "CloseDelayBroadcast : {}", msg)
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

impl Channel {
	// Convert constants + channel value to limits:
	fn get_our_max_htlc_value_in_flight_msat(channel_value_satoshis: u64) -> u64 {
		channel_value_satoshis * 1000 / 10 //TODO
	}

	/// Returns a minimum channel reserve value **they** need to maintain
	///
	/// Guaranteed to return a value no larger than channel_value_satoshis
	pub(crate) fn get_our_channel_reserve_satoshis(channel_value_satoshis: u64) -> u64 {
		let (q, _) = channel_value_satoshis.overflowing_div(100);
		cmp::min(channel_value_satoshis, cmp::max(q, 1000)) //TODO
	}

	fn derive_our_dust_limit_satoshis(at_open_background_feerate: u64) -> u64 {
		cmp::max(at_open_background_feerate * B_OUTPUT_PLUS_SPENDING_INPUT_WEIGHT / 1000, 546) //TODO
	}

	fn derive_our_htlc_minimum_msat(_at_open_channel_feerate_per_kw: u64) -> u64 {
		1000 // TODO
	}

	// Constructors:
	pub fn new_outbound(fee_estimator: &FeeEstimator, keys_provider: &Arc<KeysInterface>, their_node_id: PublicKey, channel_value_satoshis: u64, push_msat: u64, user_id: u64, logger: Arc<Logger>, config: &UserConfig) -> Result<Channel, APIError> {
		let chan_keys = keys_provider.get_channel_keys(false);

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
		if Channel::get_our_channel_reserve_satoshis(channel_value_satoshis) < Channel::derive_our_dust_limit_satoshis(background_feerate) {
			return Err(APIError::FeeRateTooHigh{err: format!("Not enough reserve above dust limit can be found at current fee rate({})", background_feerate), feerate: background_feerate});
		}

		let feerate = fee_estimator.get_est_sat_per_1000_weight(ConfirmationTarget::Normal);

		let secp_ctx = Secp256k1::new();
		let channel_monitor = ChannelMonitor::new(&chan_keys.revocation_base_key, &chan_keys.delayed_payment_base_key,
		                                          &chan_keys.htlc_base_key, &chan_keys.payment_base_key, &keys_provider.get_shutdown_pubkey(), config.own_channel_config.our_to_self_delay,
		                                          keys_provider.get_destination_script(), logger.clone());

		Ok(Channel {
			user_id: user_id,
			config: config.channel_options.clone(),

			channel_id: keys_provider.get_channel_id(),
			channel_state: ChannelState::OurInitSent as u32,
			channel_outbound: true,
			secp_ctx: secp_ctx,
			channel_value_satoshis: channel_value_satoshis,

			local_keys: chan_keys,
			shutdown_pubkey: keys_provider.get_shutdown_pubkey(),
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
			channel_update_count: 1,

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

			last_local_commitment_txn: Vec::new(),

			last_sent_closing_fee: None,

			funding_tx_confirmed_in: None,
			short_channel_id: None,
			last_block_connected: Default::default(),
			funding_tx_confirmations: 0,

			feerate_per_kw: feerate,
			their_dust_limit_satoshis: 0,
			our_dust_limit_satoshis: Channel::derive_our_dust_limit_satoshis(background_feerate),
			their_max_htlc_value_in_flight_msat: 0,
			their_channel_reserve_satoshis: 0,
			their_htlc_minimum_msat: 0,
			our_htlc_minimum_msat: Channel::derive_our_htlc_minimum_msat(feerate),
			their_to_self_delay: 0,
			our_to_self_delay: config.own_channel_config.our_to_self_delay,
			their_max_accepted_htlcs: 0,
			minimum_depth: 0, // Filled in in accept_channel

			their_funding_pubkey: None,
			their_revocation_basepoint: None,
			their_payment_basepoint: None,
			their_delayed_payment_basepoint: None,
			their_htlc_basepoint: None,
			their_cur_commitment_point: None,

			their_prev_commitment_point: None,
			their_node_id: their_node_id,

			their_shutdown_scriptpubkey: None,

			channel_monitor: channel_monitor,

			logger,
		})
	}

	fn check_remote_fee(fee_estimator: &FeeEstimator, feerate_per_kw: u32) -> Result<(), ChannelError> {
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
	pub fn new_from_req(fee_estimator: &FeeEstimator, keys_provider: &Arc<KeysInterface>, their_node_id: PublicKey, their_local_features: LocalFeatures, msg: &msgs::OpenChannel, user_id: u64, logger: Arc<Logger>, config: &UserConfig) -> Result<Channel, ChannelError> {
		let chan_keys = keys_provider.get_channel_keys(true);
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
		Channel::check_remote_fee(fee_estimator, msg.feerate_per_kw)?;

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

		let our_dust_limit_satoshis = Channel::derive_our_dust_limit_satoshis(background_feerate);
		let our_channel_reserve_satoshis = Channel::get_our_channel_reserve_satoshis(msg.funding_satoshis);
		if our_channel_reserve_satoshis < our_dust_limit_satoshis {
			return Err(ChannelError::Close("Suitable channel reserve not found. aborting"));
		}
		if msg.channel_reserve_satoshis < our_dust_limit_satoshis {
			return Err(ChannelError::Close("channel_reserve_satoshis too small"));
		}
		if our_channel_reserve_satoshis < msg.dust_limit_satoshis {
			return Err(ChannelError::Close("Dust limit too high for our channel reserve"));
		}

		// check if the funder's amount for the initial commitment tx is sufficient
		// for full fee payment
		let funders_amount_msat = msg.funding_satoshis * 1000 - msg.push_msat;
		if funders_amount_msat < background_feerate * COMMITMENT_TX_BASE_WEIGHT {
			return Err(ChannelError::Close("Insufficient funding amount for initial commitment"));
		}

		let to_local_msat = msg.push_msat;
		let to_remote_msat = funders_amount_msat - background_feerate * COMMITMENT_TX_BASE_WEIGHT;
		if to_local_msat <= msg.channel_reserve_satoshis * 1000 && to_remote_msat <= our_channel_reserve_satoshis * 1000 {
			return Err(ChannelError::Close("Insufficient funding amount for initial commitment"));
		}

		let secp_ctx = Secp256k1::new();
		let mut channel_monitor = ChannelMonitor::new(&chan_keys.revocation_base_key, &chan_keys.delayed_payment_base_key,
		                                              &chan_keys.htlc_base_key, &chan_keys.payment_base_key, &keys_provider.get_shutdown_pubkey(), config.own_channel_config.our_to_self_delay,
		                                              keys_provider.get_destination_script(), logger.clone());
		channel_monitor.set_their_base_keys(&msg.htlc_basepoint, &msg.delayed_payment_basepoint);
		channel_monitor.set_their_to_self_delay(msg.to_self_delay);

		let their_shutdown_scriptpubkey = if their_local_features.supports_upfront_shutdown_script() {
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

		let mut chan = Channel {
			user_id: user_id,
			config: local_config,

			channel_id: msg.temporary_channel_id,
			channel_state: (ChannelState::OurInitSent as u32) | (ChannelState::TheirInitSent as u32),
			channel_outbound: false,
			secp_ctx: secp_ctx,

			local_keys: chan_keys,
			shutdown_pubkey: keys_provider.get_shutdown_pubkey(),
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
			channel_update_count: 1,

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

			last_local_commitment_txn: Vec::new(),

			last_sent_closing_fee: None,

			funding_tx_confirmed_in: None,
			short_channel_id: None,
			last_block_connected: Default::default(),
			funding_tx_confirmations: 0,

			feerate_per_kw: msg.feerate_per_kw as u64,
			channel_value_satoshis: msg.funding_satoshis,
			their_dust_limit_satoshis: msg.dust_limit_satoshis,
			our_dust_limit_satoshis: our_dust_limit_satoshis,
			their_max_htlc_value_in_flight_msat: cmp::min(msg.max_htlc_value_in_flight_msat, msg.funding_satoshis * 1000),
			their_channel_reserve_satoshis: msg.channel_reserve_satoshis,
			their_htlc_minimum_msat: msg.htlc_minimum_msat,
			our_htlc_minimum_msat: Channel::derive_our_htlc_minimum_msat(msg.feerate_per_kw as u64),
			their_to_self_delay: msg.to_self_delay,
			our_to_self_delay: config.own_channel_config.our_to_self_delay,
			their_max_accepted_htlcs: msg.max_accepted_htlcs,
			minimum_depth: config.own_channel_config.minimum_depth,

			their_funding_pubkey: Some(msg.funding_pubkey),
			their_revocation_basepoint: Some(msg.revocation_basepoint),
			their_payment_basepoint: Some(msg.payment_basepoint),
			their_delayed_payment_basepoint: Some(msg.delayed_payment_basepoint),
			their_htlc_basepoint: Some(msg.htlc_basepoint),
			their_cur_commitment_point: Some(msg.first_per_commitment_point),

			their_prev_commitment_point: None,
			their_node_id: their_node_id,

			their_shutdown_scriptpubkey,

			channel_monitor: channel_monitor,

			logger,
		};

		let obscure_factor = chan.get_commitment_transaction_number_obscure_factor();
		chan.channel_monitor.set_commitment_obscure_factor(obscure_factor);

		Ok(chan)
	}

	// Utilities to derive keys:

	fn build_local_commitment_secret(&self, idx: u64) -> SecretKey {
		let res = chan_utils::build_commitment_secret(self.local_keys.commitment_seed, idx);
		SecretKey::from_slice(&res).unwrap()
	}

	// Utilities to build transactions:

	fn get_commitment_transaction_number_obscure_factor(&self) -> u64 {
		let mut sha = Sha256::engine();
		let our_payment_basepoint = PublicKey::from_secret_key(&self.secp_ctx, &self.local_keys.payment_base_key);

		if self.channel_outbound {
			sha.input(&our_payment_basepoint.serialize());
			sha.input(&self.their_payment_basepoint.unwrap().serialize());
		} else {
			sha.input(&self.their_payment_basepoint.unwrap().serialize());
			sha.input(&our_payment_basepoint.serialize());
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
	fn build_commitment_transaction(&self, commitment_number: u64, keys: &TxCreationKeys, local: bool, generated_by_local: bool, feerate_per_kw: u64) -> (Transaction, usize, Vec<(HTLCOutputInCommitment, Option<&HTLCSource>)>) {
		let obscured_commitment_transaction_number = self.get_commitment_transaction_number_obscure_factor() ^ (INITIAL_COMMITMENT_NUMBER - commitment_number);

		let txins = {
			let mut ins: Vec<TxIn> = Vec::new();
			ins.push(TxIn {
				previous_output: self.channel_monitor.get_funding_txo().unwrap().into_bitcoin_outpoint(),
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

		log_trace!(self, "Building commitment transaction number {} for {}, generated by {} with fee {}...", commitment_number, if local { "us" } else { "remote" }, if generated_by_local { "us" } else { "remote" }, feerate_per_kw);

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
						log_trace!(self, "   ...including {} {} HTLC {} (hash {}) with value {}", if $outbound { "outbound" } else { "inbound" }, $state_name, $htlc.htlc_id, log_bytes!($htlc.payment_hash.0), $htlc.amount_msat);
						txouts.push((TxOut {
							script_pubkey: chan_utils::get_htlc_redeemscript(&htlc_in_tx, &keys).to_v0_p2wsh(),
							value: $htlc.amount_msat / 1000
						}, Some((htlc_in_tx, $source))));
					} else {
						log_trace!(self, "   ...including {} {} dust HTLC {} (hash {}) with value {} due to dust limit", if $outbound { "outbound" } else { "inbound" }, $state_name, $htlc.htlc_id, log_bytes!($htlc.payment_hash.0), $htlc.amount_msat);
						included_dust_htlcs.push((htlc_in_tx, $source));
					}
				} else {
					let htlc_in_tx = get_htlc_in_commitment!($htlc, false);
					if $htlc.amount_msat / 1000 >= dust_limit_satoshis + (feerate_per_kw * HTLC_SUCCESS_TX_WEIGHT / 1000) {
						log_trace!(self, "   ...including {} {} HTLC {} (hash {}) with value {}", if $outbound { "outbound" } else { "inbound" }, $state_name, $htlc.htlc_id, log_bytes!($htlc.payment_hash.0), $htlc.amount_msat);
						txouts.push((TxOut { // "received HTLC output"
							script_pubkey: chan_utils::get_htlc_redeemscript(&htlc_in_tx, &keys).to_v0_p2wsh(),
							value: $htlc.amount_msat / 1000
						}, Some((htlc_in_tx, $source))));
					} else {
						log_trace!(self, "   ...including {} {} dust HTLC {} (hash {}) with value {}", if $outbound { "outbound" } else { "inbound" }, $state_name, $htlc.htlc_id, log_bytes!($htlc.payment_hash.0), $htlc.amount_msat);
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
				log_trace!(self, "   ...not including inbound HTLC {} (hash {}) with value {} due to state ({})", htlc.htlc_id, log_bytes!(htlc.payment_hash.0), htlc.amount_msat, state_name);
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
				log_trace!(self, "   ...not including outbound HTLC {} (hash {}) with value {} due to state ({})", htlc.htlc_id, log_bytes!(htlc.payment_hash.0), htlc.amount_msat, state_name);
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
			debug_assert!(max_commitment_tx_output.0 <= value_to_self_msat as u64 || value_to_self_msat / 1000 >= self.their_channel_reserve_satoshis as i64);
			max_commitment_tx_output.0 = cmp::max(max_commitment_tx_output.0, value_to_self_msat as u64);
			debug_assert!(max_commitment_tx_output.1 <= value_to_remote_msat as u64 || value_to_remote_msat / 1000 >= Channel::get_our_channel_reserve_satoshis(self.channel_value_satoshis) as i64);
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
			log_trace!(self, "   ...including {} output with value {}", if local { "to_local" } else { "to_remote" }, value_to_a);
			txouts.push((TxOut {
				script_pubkey: chan_utils::get_revokeable_redeemscript(&keys.revocation_key,
				                                                       if local { self.their_to_self_delay } else { self.our_to_self_delay },
				                                                       &keys.a_delayed_payment_key).to_v0_p2wsh(),
				value: value_to_a as u64
			}, None));
		}

		if value_to_b >= (dust_limit_satoshis as i64) {
			log_trace!(self, "   ...including {} output with value {}", if local { "to_remote" } else { "to_local" }, value_to_b);
			txouts.push((TxOut {
				script_pubkey: Builder::new().push_opcode(opcodes::all::OP_PUSHBYTES_0)
				                             .push_slice(&Hash160::hash(&keys.b_payment_key.serialize())[..])
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
		let our_channel_close_key_hash = Hash160::hash(&self.shutdown_pubkey.serialize());
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
				previous_output: self.channel_monitor.get_funding_txo().unwrap().into_bitcoin_outpoint(),
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
		let delayed_payment_base = PublicKey::from_secret_key(&self.secp_ctx, &self.local_keys.delayed_payment_base_key);
		let htlc_basepoint = PublicKey::from_secret_key(&self.secp_ctx, &self.local_keys.htlc_base_key);

		Ok(secp_check!(TxCreationKeys::new(&self.secp_ctx, &per_commitment_point, &delayed_payment_base, &htlc_basepoint, &self.their_revocation_basepoint.unwrap(), &self.their_payment_basepoint.unwrap(), &self.their_htlc_basepoint.unwrap()), "Local tx keys generation got bogus keys"))
	}

	#[inline]
	/// Creates a set of keys for build_commitment_transaction to generate a transaction which we
	/// will sign and send to our counterparty.
	/// If an Err is returned, it is a ChannelError::Close (for get_outbound_funding_created)
	fn build_remote_transaction_keys(&self) -> Result<TxCreationKeys, ChannelError> {
		//TODO: Ensure that the payment_key derived here ends up in the library users' wallet as we
		//may see payments to it!
		let payment_basepoint = PublicKey::from_secret_key(&self.secp_ctx, &self.local_keys.payment_base_key);
		let revocation_basepoint = PublicKey::from_secret_key(&self.secp_ctx, &self.local_keys.revocation_base_key);
		let htlc_basepoint = PublicKey::from_secret_key(&self.secp_ctx, &self.local_keys.htlc_base_key);

		Ok(secp_check!(TxCreationKeys::new(&self.secp_ctx, &self.their_cur_commitment_point.unwrap(), &self.their_delayed_payment_basepoint.unwrap(), &self.their_htlc_basepoint.unwrap(), &revocation_basepoint, &payment_basepoint, &htlc_basepoint), "Remote tx keys generation got bogus keys"))
	}

	/// Gets the redeemscript for the funding transaction output (ie the funding transaction output
	/// pays to get_funding_redeemscript().to_v0_p2wsh()).
	/// Panics if called before accept_channel/new_from_req
	pub fn get_funding_redeemscript(&self) -> Script {
		let builder = Builder::new().push_opcode(opcodes::all::OP_PUSHNUM_2);
		let our_funding_key = PublicKey::from_secret_key(&self.secp_ctx, &self.local_keys.funding_key).serialize();
		let their_funding_key = self.their_funding_pubkey.expect("get_funding_redeemscript only allowed after accept_channel").serialize();
		if our_funding_key[..] < their_funding_key[..] {
			builder.push_slice(&our_funding_key)
				.push_slice(&their_funding_key)
		} else {
			builder.push_slice(&their_funding_key)
				.push_slice(&our_funding_key)
		}.push_opcode(opcodes::all::OP_PUSHNUM_2).push_opcode(opcodes::all::OP_CHECKMULTISIG).into_script()
	}

	fn sign_commitment_transaction(&self, tx: &mut Transaction, their_sig: &Signature) -> Signature {
		if tx.input.len() != 1 {
			panic!("Tried to sign commitment transaction that had input count != 1!");
		}
		if tx.input[0].witness.len() != 0 {
			panic!("Tried to re-sign commitment transaction");
		}

		let funding_redeemscript = self.get_funding_redeemscript();

		let sighash = hash_to_message!(&bip143::SighashComponents::new(&tx).sighash_all(&tx.input[0], &funding_redeemscript, self.channel_value_satoshis)[..]);
		let our_sig = self.secp_ctx.sign(&sighash, &self.local_keys.funding_key);

		tx.input[0].witness.push(Vec::new()); // First is the multisig dummy

		let our_funding_key = PublicKey::from_secret_key(&self.secp_ctx, &self.local_keys.funding_key).serialize();
		let their_funding_key = self.their_funding_pubkey.unwrap().serialize();
		if our_funding_key[..] < their_funding_key[..] {
			tx.input[0].witness.push(our_sig.serialize_der().to_vec());
			tx.input[0].witness.push(their_sig.serialize_der().to_vec());
		} else {
			tx.input[0].witness.push(their_sig.serialize_der().to_vec());
			tx.input[0].witness.push(our_sig.serialize_der().to_vec());
		}
		tx.input[0].witness[1].push(SigHashType::All as u8);
		tx.input[0].witness[2].push(SigHashType::All as u8);

		tx.input[0].witness.push(funding_redeemscript.into_bytes());

		our_sig
	}

	/// Builds the htlc-success or htlc-timeout transaction which spends a given HTLC output
	/// @local is used only to convert relevant internal structures which refer to remote vs local
	/// to decide value of outputs and direction of HTLCs.
	fn build_htlc_transaction(&self, prev_hash: &Sha256dHash, htlc: &HTLCOutputInCommitment, local: bool, keys: &TxCreationKeys, feerate_per_kw: u64) -> Transaction {
		chan_utils::build_htlc_transaction(prev_hash, feerate_per_kw, if local { self.their_to_self_delay } else { self.our_to_self_delay }, htlc, &keys.a_delayed_payment_key, &keys.revocation_key)
	}

	fn create_htlc_tx_signature(&self, tx: &Transaction, htlc: &HTLCOutputInCommitment, keys: &TxCreationKeys) -> Result<(Script, Signature, bool), ChannelError> {
		if tx.input.len() != 1 {
			panic!("Tried to sign HTLC transaction that had input count != 1!");
		}

		let htlc_redeemscript = chan_utils::get_htlc_redeemscript(&htlc, &keys);

		let our_htlc_key = secp_check!(chan_utils::derive_private_key(&self.secp_ctx, &keys.per_commitment_point, &self.local_keys.htlc_base_key), "Derived invalid key, peer is maliciously selecting parameters");
		let sighash = hash_to_message!(&bip143::SighashComponents::new(&tx).sighash_all(&tx.input[0], &htlc_redeemscript, htlc.amount_msat / 1000)[..]);
		let is_local_tx = PublicKey::from_secret_key(&self.secp_ctx, &our_htlc_key) == keys.a_htlc_key;
		Ok((htlc_redeemscript, self.secp_ctx.sign(&sighash, &our_htlc_key), is_local_tx))
	}

	/// Signs a transaction created by build_htlc_transaction. If the transaction is an
	/// HTLC-Success transaction (ie htlc.offered is false), preimage must be set!
	fn sign_htlc_transaction(&self, tx: &mut Transaction, their_sig: &Signature, preimage: &Option<PaymentPreimage>, htlc: &HTLCOutputInCommitment, keys: &TxCreationKeys) -> Result<Signature, ChannelError> {
		if tx.input.len() != 1 {
			panic!("Tried to sign HTLC transaction that had input count != 1!");
		}
		if tx.input[0].witness.len() != 0 {
			panic!("Tried to re-sign HTLC transaction");
		}

		let (htlc_redeemscript, our_sig, local_tx) = self.create_htlc_tx_signature(tx, htlc, keys)?;

		tx.input[0].witness.push(Vec::new()); // First is the multisig dummy

		if local_tx { // b, then a
			tx.input[0].witness.push(their_sig.serialize_der().to_vec());
			tx.input[0].witness.push(our_sig.serialize_der().to_vec());
		} else {
			tx.input[0].witness.push(our_sig.serialize_der().to_vec());
			tx.input[0].witness.push(their_sig.serialize_der().to_vec());
		}
		tx.input[0].witness[1].push(SigHashType::All as u8);
		tx.input[0].witness[2].push(SigHashType::All as u8);

		if htlc.offered {
			tx.input[0].witness.push(Vec::new());
		} else {
			tx.input[0].witness.push(preimage.unwrap().0.to_vec());
		}

		tx.input[0].witness.push(htlc_redeemscript.into_bytes());

		Ok(our_sig)
	}

	/// Per HTLC, only one get_update_fail_htlc or get_update_fulfill_htlc call may be made.
	/// In such cases we debug_assert!(false) and return an IgnoreError. Thus, will always return
	/// Ok(_) if debug assertions are turned on and preconditions are met.
	fn get_update_fulfill_htlc(&mut self, htlc_id_arg: u64, payment_preimage_arg: PaymentPreimage) -> Result<(Option<msgs::UpdateFulfillHTLC>, Option<ChannelMonitor>), ChannelError> {
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
							log_warn!(self, "Have preimage and want to fulfill HTLC with payment hash {} we already failed against channel {}", log_bytes!(htlc.payment_hash.0), log_bytes!(self.channel_id()));
						}
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
		self.channel_monitor.provide_payment_preimage(&payment_hash_calc, &payment_preimage_arg);

		if (self.channel_state & (ChannelState::AwaitingRemoteRevoke as u32 | ChannelState::PeerDisconnected as u32 | ChannelState::MonitorUpdateFailed as u32)) != 0 {
			for pending_update in self.holding_cell_htlc_updates.iter() {
				match pending_update {
					&HTLCUpdateAwaitingACK::ClaimHTLC { htlc_id, .. } => {
						if htlc_id_arg == htlc_id {
							return Ok((None, None));
						}
					},
					&HTLCUpdateAwaitingACK::FailHTLC { htlc_id, .. } => {
						if htlc_id_arg == htlc_id {
							log_warn!(self, "Have preimage and want to fulfill HTLC with pending failure against channel {}", log_bytes!(self.channel_id()));
							// TODO: We may actually be able to switch to a fulfill here, though its
							// rare enough it may not be worth the complexity burden.
							return Ok((None, Some(self.channel_monitor.clone())));
						}
					},
					_ => {}
				}
			}
			log_trace!(self, "Adding HTLC claim to holding_cell! Current state: {}", self.channel_state);
			self.holding_cell_htlc_updates.push(HTLCUpdateAwaitingACK::ClaimHTLC {
				payment_preimage: payment_preimage_arg, htlc_id: htlc_id_arg,
			});
			return Ok((None, Some(self.channel_monitor.clone())));
		}

		{
			let htlc = &mut self.pending_inbound_htlcs[pending_idx];
			if let InboundHTLCState::Committed = htlc.state {
			} else {
				debug_assert!(false, "Have an inbound HTLC we tried to claim before it was fully committed to");
				return Ok((None, Some(self.channel_monitor.clone())));
			}
			log_trace!(self, "Upgrading HTLC {} to LocalRemoved with a Fulfill!", log_bytes!(htlc.payment_hash.0));
			htlc.state = InboundHTLCState::LocalRemoved(InboundHTLCRemovalReason::Fulfill(payment_preimage_arg.clone()));
		}

		Ok((Some(msgs::UpdateFulfillHTLC {
			channel_id: self.channel_id(),
			htlc_id: htlc_id_arg,
			payment_preimage: payment_preimage_arg,
		}), Some(self.channel_monitor.clone())))
	}

	pub fn get_update_fulfill_htlc_and_commit(&mut self, htlc_id: u64, payment_preimage: PaymentPreimage) -> Result<(Option<(msgs::UpdateFulfillHTLC, msgs::CommitmentSigned)>, Option<ChannelMonitor>), ChannelError> {
		match self.get_update_fulfill_htlc(htlc_id, payment_preimage)? {
			(Some(update_fulfill_htlc), _) => {
				let (commitment, monitor_update) = self.send_commitment_no_status_check()?;
				Ok((Some((update_fulfill_htlc, commitment)), Some(monitor_update)))
			},
			(None, Some(channel_monitor)) => Ok((None, Some(channel_monitor))),
			(None, None) => Ok((None, None))
		}
	}

	/// Per HTLC, only one get_update_fail_htlc or get_update_fulfill_htlc call may be made.
	/// In such cases we debug_assert!(false) and return an IgnoreError. Thus, will always return
	/// Ok(_) if debug assertions are turned on and preconditions are met.
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
							return Err(ChannelError::Ignore("Unable to find a pending HTLC which matched the given HTLC ID"));
						}
					},
					&HTLCUpdateAwaitingACK::FailHTLC { htlc_id, .. } => {
						if htlc_id_arg == htlc_id {
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

	pub fn accept_channel(&mut self, msg: &msgs::AcceptChannel, config: &UserConfig, their_local_features: LocalFeatures) -> Result<(), ChannelError> {
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
		if msg.dust_limit_satoshis > Channel::get_our_channel_reserve_satoshis(self.channel_value_satoshis) {
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

		let their_shutdown_scriptpubkey = if their_local_features.supports_upfront_shutdown_script() {
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

		self.channel_monitor.set_their_base_keys(&msg.htlc_basepoint, &msg.delayed_payment_basepoint);

		self.their_dust_limit_satoshis = msg.dust_limit_satoshis;
		self.their_max_htlc_value_in_flight_msat = cmp::min(msg.max_htlc_value_in_flight_msat, self.channel_value_satoshis * 1000);
		self.their_channel_reserve_satoshis = msg.channel_reserve_satoshis;
		self.their_htlc_minimum_msat = msg.htlc_minimum_msat;
		self.their_to_self_delay = msg.to_self_delay;
		self.their_max_accepted_htlcs = msg.max_accepted_htlcs;
		self.minimum_depth = msg.minimum_depth;
		self.their_funding_pubkey = Some(msg.funding_pubkey);
		self.their_revocation_basepoint = Some(msg.revocation_basepoint);
		self.their_payment_basepoint = Some(msg.payment_basepoint);
		self.their_delayed_payment_basepoint = Some(msg.delayed_payment_basepoint);
		self.their_htlc_basepoint = Some(msg.htlc_basepoint);
		self.their_cur_commitment_point = Some(msg.first_per_commitment_point);
		self.their_shutdown_scriptpubkey = their_shutdown_scriptpubkey;

		let obscure_factor = self.get_commitment_transaction_number_obscure_factor();
		self.channel_monitor.set_commitment_obscure_factor(obscure_factor);
		self.channel_monitor.set_their_to_self_delay(msg.to_self_delay);

		self.channel_state = ChannelState::OurInitSent as u32 | ChannelState::TheirInitSent as u32;

		Ok(())
	}

	fn funding_created_signature(&mut self, sig: &Signature) -> Result<(Transaction, Transaction, Signature, TxCreationKeys), ChannelError> {
		let funding_script = self.get_funding_redeemscript();

		let local_keys = self.build_local_transaction_keys(self.cur_local_commitment_transaction_number)?;
		let mut local_initial_commitment_tx = self.build_commitment_transaction(self.cur_local_commitment_transaction_number, &local_keys, true, false, self.feerate_per_kw).0;
		let local_sighash = hash_to_message!(&bip143::SighashComponents::new(&local_initial_commitment_tx).sighash_all(&local_initial_commitment_tx.input[0], &funding_script, self.channel_value_satoshis)[..]);

		// They sign the "local" commitment transaction...
		secp_check!(self.secp_ctx.verify(&local_sighash, &sig, &self.their_funding_pubkey.unwrap()), "Invalid funding_created signature from peer");

		// ...and we sign it, allowing us to broadcast the tx if we wish
		self.sign_commitment_transaction(&mut local_initial_commitment_tx, sig);

		let remote_keys = self.build_remote_transaction_keys()?;
		let remote_initial_commitment_tx = self.build_commitment_transaction(self.cur_remote_commitment_transaction_number, &remote_keys, false, false, self.feerate_per_kw).0;
		let remote_sighash = hash_to_message!(&bip143::SighashComponents::new(&remote_initial_commitment_tx).sighash_all(&remote_initial_commitment_tx.input[0], &funding_script, self.channel_value_satoshis)[..]);

		// We sign the "remote" commitment transaction, allowing them to broadcast the tx if they wish.
		Ok((remote_initial_commitment_tx, local_initial_commitment_tx, self.secp_ctx.sign(&remote_sighash, &self.local_keys.funding_key), local_keys))
	}

	pub fn funding_created(&mut self, msg: &msgs::FundingCreated) -> Result<(msgs::FundingSigned, ChannelMonitor), ChannelError> {
		if self.channel_outbound {
			return Err(ChannelError::Close("Received funding_created for an outbound channel?"));
		}
		if self.channel_state != (ChannelState::OurInitSent as u32 | ChannelState::TheirInitSent as u32) {
			// BOLT 2 says that if we disconnect before we send funding_signed we SHOULD NOT
			// remember the channel, so it's safe to just send an error_message here and drop the
			// channel.
			return Err(ChannelError::Close("Received funding_created after we got the channel!"));
		}
		if self.channel_monitor.get_min_seen_secret() != (1 << 48) ||
				self.cur_remote_commitment_transaction_number != INITIAL_COMMITMENT_NUMBER ||
				self.cur_local_commitment_transaction_number != INITIAL_COMMITMENT_NUMBER {
			panic!("Should not have advanced channel commitment tx numbers prior to funding_created");
		}

		let funding_txo = OutPoint::new(msg.funding_txid, msg.funding_output_index);
		let funding_txo_script = self.get_funding_redeemscript().to_v0_p2wsh();
		self.channel_monitor.set_funding_info((funding_txo, funding_txo_script));

		let (remote_initial_commitment_tx, local_initial_commitment_tx, our_signature, local_keys) = match self.funding_created_signature(&msg.signature) {
			Ok(res) => res,
			Err(e) => {
				self.channel_monitor.unset_funding_info();
				return Err(e);
			}
		};

		// Now that we're past error-generating stuff, update our local state:

		self.channel_monitor.provide_latest_remote_commitment_tx_info(&remote_initial_commitment_tx, Vec::new(), self.cur_remote_commitment_transaction_number, self.their_cur_commitment_point.unwrap());
		self.last_local_commitment_txn = vec![local_initial_commitment_tx.clone()];
		self.channel_monitor.provide_latest_local_commitment_tx_info(local_initial_commitment_tx, local_keys, self.feerate_per_kw, Vec::new());
		self.channel_state = ChannelState::FundingSent as u32;
		self.channel_id = funding_txo.to_channel_id();
		self.cur_remote_commitment_transaction_number -= 1;
		self.cur_local_commitment_transaction_number -= 1;

		Ok((msgs::FundingSigned {
			channel_id: self.channel_id,
			signature: our_signature
		}, self.channel_monitor.clone()))
	}

	/// Handles a funding_signed message from the remote end.
	/// If this call is successful, broadcast the funding transaction (and not before!)
	pub fn funding_signed(&mut self, msg: &msgs::FundingSigned) -> Result<ChannelMonitor, ChannelError> {
		if !self.channel_outbound {
			return Err(ChannelError::Close("Received funding_signed for an inbound channel?"));
		}
		if self.channel_state & !(ChannelState::MonitorUpdateFailed as u32) != ChannelState::FundingCreated as u32 {
			return Err(ChannelError::Close("Received funding_signed in strange state!"));
		}
		if self.channel_monitor.get_min_seen_secret() != (1 << 48) ||
				self.cur_remote_commitment_transaction_number != INITIAL_COMMITMENT_NUMBER - 1 ||
				self.cur_local_commitment_transaction_number != INITIAL_COMMITMENT_NUMBER {
			panic!("Should not have advanced channel commitment tx numbers prior to funding_created");
		}

		let funding_script = self.get_funding_redeemscript();

		let local_keys = self.build_local_transaction_keys(self.cur_local_commitment_transaction_number)?;
		let mut local_initial_commitment_tx = self.build_commitment_transaction(self.cur_local_commitment_transaction_number, &local_keys, true, false, self.feerate_per_kw).0;
		let local_sighash = hash_to_message!(&bip143::SighashComponents::new(&local_initial_commitment_tx).sighash_all(&local_initial_commitment_tx.input[0], &funding_script, self.channel_value_satoshis)[..]);

		// They sign the "local" commitment transaction, allowing us to broadcast the tx if we wish.
		secp_check!(self.secp_ctx.verify(&local_sighash, &msg.signature, &self.their_funding_pubkey.unwrap()), "Invalid funding_signed signature from peer");

		self.sign_commitment_transaction(&mut local_initial_commitment_tx, &msg.signature);
		self.channel_monitor.provide_latest_local_commitment_tx_info(local_initial_commitment_tx.clone(), local_keys, self.feerate_per_kw, Vec::new());
		self.last_local_commitment_txn = vec![local_initial_commitment_tx];
		self.channel_state = ChannelState::FundingSent as u32 | (self.channel_state & (ChannelState::MonitorUpdateFailed as u32));
		self.cur_local_commitment_transaction_number -= 1;

		if self.channel_state & (ChannelState::MonitorUpdateFailed as u32) == 0 {
			Ok(self.channel_monitor.clone())
		} else {
			Err(ChannelError::Ignore("Previous monitor update failure prevented funding_signed from allowing funding broadcast"))
		}
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
			self.channel_update_count += 1;
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
		if msg.amount_msat < self.our_htlc_minimum_msat {
			return Err(ChannelError::Close("Remote side tried to send less than our minimum HTLC value"));
		}

		let (inbound_htlc_count, htlc_inbound_value_msat) = self.get_inbound_pending_htlc_stats();
		if inbound_htlc_count + 1 > OUR_MAX_HTLCS as u32 {
			return Err(ChannelError::Close("Remote tried to push more than our max accepted HTLCs"));
		}
		// Check our_max_htlc_value_in_flight_msat
		if htlc_inbound_value_msat + msg.amount_msat > Channel::get_our_max_htlc_value_in_flight_msat(self.channel_value_satoshis) {
			return Err(ChannelError::Close("Remote HTLC add would put them over our max HTLC value"));
		}
		// Check our_channel_reserve_satoshis (we're getting paid, so they have to at least meet
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
		if htlc_inbound_value_msat + msg.amount_msat + self.value_to_self_msat > (self.channel_value_satoshis - Channel::get_our_channel_reserve_satoshis(self.channel_value_satoshis)) * 1000 + removed_outbound_total_msat {
			return Err(ChannelError::Close("Remote HTLC add would put them over their reserve value"));
		}
		if self.next_remote_htlc_id != msg.htlc_id {
			return Err(ChannelError::Close("Remote skipped HTLC ID"));
		}
		if msg.cltv_expiry >= 500000000 {
			return Err(ChannelError::Close("Remote provided CLTV expiry in seconds instead of block height"));
		}

		//TODO: Check msg.cltv_expiry further? Do this in channel manager?

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

	pub fn update_fail_malformed_htlc<'a>(&mut self, msg: &msgs::UpdateFailMalformedHTLC, fail_reason: HTLCFailReason) -> Result<(), ChannelError> {
		if (self.channel_state & (ChannelState::ChannelFunded as u32)) != (ChannelState::ChannelFunded as u32) {
			return Err(ChannelError::Close("Got fail malformed HTLC message when channel was not in an operational state"));
		}
		if self.channel_state & (ChannelState::PeerDisconnected as u32) == ChannelState::PeerDisconnected as u32 {
			return Err(ChannelError::Close("Peer sent update_fail_malformed_htlc when we needed a channel_reestablish"));
		}

		self.mark_outbound_htlc_removed(msg.htlc_id, None, Some(fail_reason))?;
		Ok(())
	}

	pub fn commitment_signed(&mut self, msg: &msgs::CommitmentSigned, fee_estimator: &FeeEstimator) -> Result<(msgs::RevokeAndACK, Option<msgs::CommitmentSigned>, Option<msgs::ClosingSigned>, ChannelMonitor), ChannelError> {
		if (self.channel_state & (ChannelState::ChannelFunded as u32)) != (ChannelState::ChannelFunded as u32) {
			return Err(ChannelError::Close("Got commitment signed message when channel was not in an operational state"));
		}
		if self.channel_state & (ChannelState::PeerDisconnected as u32) == ChannelState::PeerDisconnected as u32 {
			return Err(ChannelError::Close("Peer sent commitment_signed when we needed a channel_reestablish"));
		}
		if self.channel_state & BOTH_SIDES_SHUTDOWN_MASK == BOTH_SIDES_SHUTDOWN_MASK && self.last_sent_closing_fee.is_some() {
			return Err(ChannelError::Close("Peer sent commitment_signed after we'd started exchanging closing_signeds"));
		}

		let funding_script = self.get_funding_redeemscript();

		let local_keys = self.build_local_transaction_keys(self.cur_local_commitment_transaction_number)?;

		let mut update_fee = false;
		let feerate_per_kw = if !self.channel_outbound && self.pending_update_fee.is_some() {
			update_fee = true;
			self.pending_update_fee.unwrap()
		} else {
			self.feerate_per_kw
		};

		let mut local_commitment_tx = {
			let mut commitment_tx = self.build_commitment_transaction(self.cur_local_commitment_transaction_number, &local_keys, true, false, feerate_per_kw);
			let htlcs_cloned: Vec<_> = commitment_tx.2.drain(..).map(|htlc| (htlc.0, htlc.1.map(|h| h.clone()))).collect();
			(commitment_tx.0, commitment_tx.1, htlcs_cloned)
		};
		let local_commitment_txid = local_commitment_tx.0.txid();
		let local_sighash = hash_to_message!(&bip143::SighashComponents::new(&local_commitment_tx.0).sighash_all(&local_commitment_tx.0.input[0], &funding_script, self.channel_value_satoshis)[..]);
		log_trace!(self, "Checking commitment tx signature {} by key {} against tx {} with redeemscript {}", log_bytes!(msg.signature.serialize_compact()[..]), log_bytes!(self.their_funding_pubkey.unwrap().serialize()), encode::serialize_hex(&local_commitment_tx.0), encode::serialize_hex(&funding_script));
		secp_check!(self.secp_ctx.verify(&local_sighash, &msg.signature, &self.their_funding_pubkey.unwrap()), "Invalid commitment tx signature from peer");

		//If channel fee was updated by funder confirm funder can afford the new fee rate when applied to the current local commitment transaction
		if update_fee {
			let num_htlcs = local_commitment_tx.1;
			let total_fee: u64 = feerate_per_kw as u64 * (COMMITMENT_TX_BASE_WEIGHT + (num_htlcs as u64) * COMMITMENT_TX_WEIGHT_PER_HTLC) / 1000;

			if self.channel_value_satoshis - self.value_to_self_msat / 1000 < total_fee + self.their_channel_reserve_satoshis {
				return Err(ChannelError::Close("Funding remote cannot afford proposed new fee"));
			}
		}

		if msg.htlc_signatures.len() != local_commitment_tx.1 {
			return Err(ChannelError::Close("Got wrong number of HTLC signatures from remote"));
		}

		let mut new_local_commitment_txn = Vec::with_capacity(local_commitment_tx.1 + 1);
		self.sign_commitment_transaction(&mut local_commitment_tx.0, &msg.signature);
		new_local_commitment_txn.push(local_commitment_tx.0.clone());

		let mut htlcs_and_sigs = Vec::with_capacity(local_commitment_tx.2.len());
		for (idx, (htlc, source)) in local_commitment_tx.2.drain(..).enumerate() {
			if let Some(_) = htlc.transaction_output_index {
				let mut htlc_tx = self.build_htlc_transaction(&local_commitment_txid, &htlc, true, &local_keys, feerate_per_kw);
				let htlc_redeemscript = chan_utils::get_htlc_redeemscript(&htlc, &local_keys);
				log_trace!(self, "Checking HTLC tx signature {} by key {} against tx {} with redeemscript {}", log_bytes!(msg.htlc_signatures[idx].serialize_compact()[..]), log_bytes!(local_keys.b_htlc_key.serialize()), encode::serialize_hex(&htlc_tx), encode::serialize_hex(&htlc_redeemscript));
				let htlc_sighash = hash_to_message!(&bip143::SighashComponents::new(&htlc_tx).sighash_all(&htlc_tx.input[0], &htlc_redeemscript, htlc.amount_msat / 1000)[..]);
				secp_check!(self.secp_ctx.verify(&htlc_sighash, &msg.htlc_signatures[idx], &local_keys.b_htlc_key), "Invalid HTLC tx signature from peer");
				let htlc_sig = if htlc.offered {
					let htlc_sig = self.sign_htlc_transaction(&mut htlc_tx, &msg.htlc_signatures[idx], &None, &htlc, &local_keys)?;
					new_local_commitment_txn.push(htlc_tx);
					htlc_sig
				} else {
					self.create_htlc_tx_signature(&htlc_tx, &htlc, &local_keys)?.1
				};
				htlcs_and_sigs.push((htlc, Some((msg.htlc_signatures[idx], htlc_sig)), source));
			} else {
				htlcs_and_sigs.push((htlc, None, source));
			}
		}

		let next_per_commitment_point = PublicKey::from_secret_key(&self.secp_ctx, &self.build_local_commitment_secret(self.cur_local_commitment_transaction_number - 1));
		let per_commitment_secret = chan_utils::build_commitment_secret(self.local_keys.commitment_seed, self.cur_local_commitment_transaction_number + 1);

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

		self.channel_monitor.provide_latest_local_commitment_tx_info(local_commitment_tx.0, local_keys, self.feerate_per_kw, htlcs_and_sigs);

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
		self.last_local_commitment_txn = new_local_commitment_txn;
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
				// Note that this generates a monitor update that we ignore! This is OK since we
				// won't actually send the commitment_signed that generated the update to the other
				// side until the latest monitor has been pulled from us and stored.
				self.monitor_pending_commitment_signed = true;
				self.send_commitment_no_status_check()?;
			}
			// TODO: Call maybe_propose_first_closing_signed on restoration (or call it here and
			// re-send the message on restoration)
			return Err(ChannelError::Ignore("Previous monitor update failure prevented generation of RAA"));
		}

		let (our_commitment_signed, monitor_update, closing_signed) = if need_our_commitment && (self.channel_state & (ChannelState::AwaitingRemoteRevoke as u32)) == 0 {
			// If we're AwaitingRemoteRevoke we can't send a new commitment here, but that's ok -
			// we'll send one right away when we get the revoke_and_ack when we
			// free_holding_cell_htlcs().
			let (msg, monitor) = self.send_commitment_no_status_check()?;
			(Some(msg), monitor, None)
		} else if !need_our_commitment {
			(None, self.channel_monitor.clone(), self.maybe_propose_first_closing_signed(fee_estimator))
		} else { (None, self.channel_monitor.clone(), None) };

		Ok((msgs::RevokeAndACK {
			channel_id: self.channel_id,
			per_commitment_secret: per_commitment_secret,
			next_per_commitment_point: next_per_commitment_point,
		}, our_commitment_signed, closing_signed, monitor_update))
	}

	/// Used to fulfill holding_cell_htlcs when we get a remote ack (or implicitly get it by them
	/// fulfilling or failing the last pending HTLC)
	fn free_holding_cell_htlcs(&mut self) -> Result<Option<(msgs::CommitmentUpdate, ChannelMonitor)>, ChannelError> {
		assert_eq!(self.channel_state & ChannelState::MonitorUpdateFailed as u32, 0);
		if self.holding_cell_htlc_updates.len() != 0 || self.holding_cell_update_fee.is_some() {
			log_trace!(self, "Freeing holding cell with {} HTLC updates{}", self.holding_cell_htlc_updates.len(), if self.holding_cell_update_fee.is_some() { " and a fee update" } else { "" });

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
											log_info!(self, "Failed to send HTLC with payment_hash {} due to {}", log_bytes!(payment_hash.0), msg);
										},
										_ => {
											log_info!(self, "Failed to send HTLC with payment_hash {} resulting in a channel closure during holding_cell freeing", log_bytes!(payment_hash.0));
										},
									}
									err = Some(e);
								}
							}
						},
						&HTLCUpdateAwaitingACK::ClaimHTLC { ref payment_preimage, htlc_id, .. } => {
							match self.get_update_fulfill_htlc(htlc_id, *payment_preimage) {
								Ok(update_fulfill_msg_option) => update_fulfill_htlcs.push(update_fulfill_msg_option.0.unwrap()),
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
					let (commitment_signed, monitor_update) = self.send_commitment_no_status_check()?;
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
	pub fn revoke_and_ack(&mut self, msg: &msgs::RevokeAndACK, fee_estimator: &FeeEstimator) -> Result<(Option<msgs::CommitmentUpdate>, Vec<(PendingForwardHTLCInfo, u64)>, Vec<(HTLCSource, PaymentHash, HTLCFailReason)>, Option<msgs::ClosingSigned>, ChannelMonitor), ChannelError> {
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
		self.channel_monitor.provide_secret(self.cur_remote_commitment_transaction_number + 1, msg.per_commitment_secret)
			.map_err(|e| ChannelError::Close(e.0))?;

		// Update state now that we've passed all the can-fail calls...
		// (note that we may still fail to generate the new commitment_signed message, but that's
		// OK, we step the channel here and *then* if the new generation fails we can fail the
		// channel based on that, but stepping stuff here should be safe either way.
		self.channel_state &= !(ChannelState::AwaitingRemoteRevoke as u32);
		self.their_prev_commitment_point = self.their_cur_commitment_point;
		self.their_cur_commitment_point = Some(msg.next_per_commitment_point);
		self.cur_remote_commitment_transaction_number -= 1;

		log_trace!(self, "Updating HTLCs on receipt of RAA...");
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
			let logger = LogHolder { logger: &self.logger };

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
				self.send_commitment_no_status_check()?;
			}
			self.monitor_pending_forwards.append(&mut to_forward_infos);
			self.monitor_pending_failures.append(&mut revoked_htlcs);
			return Ok((None, Vec::new(), Vec::new(), None, self.channel_monitor.clone()));
		}

		match self.free_holding_cell_htlcs()? {
			Some(mut commitment_update) => {
				commitment_update.0.update_fail_htlcs.reserve(update_fail_htlcs.len());
				for fail_msg in update_fail_htlcs.drain(..) {
					commitment_update.0.update_fail_htlcs.push(fail_msg);
				}
				commitment_update.0.update_fail_malformed_htlcs.reserve(update_fail_malformed_htlcs.len());
				for fail_msg in update_fail_malformed_htlcs.drain(..) {
					commitment_update.0.update_fail_malformed_htlcs.push(fail_msg);
				}
				Ok((Some(commitment_update.0), to_forward_infos, revoked_htlcs, None, commitment_update.1))
			},
			None => {
				if require_commitment {
					let (commitment_signed, monitor_update) = self.send_commitment_no_status_check()?;
					Ok((Some(msgs::CommitmentUpdate {
						update_add_htlcs: Vec::new(),
						update_fulfill_htlcs: Vec::new(),
						update_fail_htlcs,
						update_fail_malformed_htlcs,
						update_fee: None,
						commitment_signed
					}), to_forward_infos, revoked_htlcs, None, monitor_update))
				} else {
					Ok((None, to_forward_infos, revoked_htlcs, self.maybe_propose_first_closing_signed(fee_estimator), self.channel_monitor.clone()))
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

	pub fn send_update_fee_and_commit(&mut self, feerate_per_kw: u64) -> Result<Option<(msgs::UpdateFee, msgs::CommitmentSigned, ChannelMonitor)>, ChannelError> {
		match self.send_update_fee(feerate_per_kw) {
			Some(update_fee) => {
				let (commitment_signed, monitor_update) = self.send_commitment_no_status_check()?;
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
	pub fn remove_uncommitted_htlcs_and_mark_paused(&mut self) -> Vec<(HTLCSource, PaymentHash)> {
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
		log_debug!(self, "Peer disconnection resulted in {} remote-announced HTLC drops and {} waiting-to-locally-announced HTLC drops on channel {}", outbound_drops.len(), inbound_drop_count, log_bytes!(self.channel_id()));
		outbound_drops
	}

	/// Indicates that a ChannelMonitor update failed to be stored by the client and further
	/// updates are partially paused.
	/// This must be called immediately after the call which generated the ChannelMonitor update
	/// which failed. The messages which were generated from that call which generated the
	/// monitor update failure must *not* have been sent to the remote end, and must instead
	/// have been dropped. They will be regenerated when monitor_updating_restored is called.
	pub fn monitor_update_failed(&mut self, resend_raa: bool, resend_commitment: bool, mut pending_forwards: Vec<(PendingForwardHTLCInfo, u64)>, mut pending_fails: Vec<(HTLCSource, PaymentHash, HTLCFailReason)>) {
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
	pub fn monitor_updating_restored(&mut self) -> (Option<msgs::RevokeAndACK>, Option<msgs::CommitmentUpdate>, RAACommitmentOrder, Vec<(PendingForwardHTLCInfo, u64)>, Vec<(HTLCSource, PaymentHash, HTLCFailReason)>, bool, Option<msgs::FundingLocked>) {
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
			Some(self.get_last_commitment_update())
		} else { None };

		self.monitor_pending_revoke_and_ack = false;
		self.monitor_pending_commitment_signed = false;
		let order = self.resend_order.clone();
		log_trace!(self, "Restored monitor updating resulting in {}{} commitment update and {} RAA, with {} first",
			if needs_broadcast_safe { "a funding broadcast safe, " } else { "" },
			if commitment_update.is_some() { "a" } else { "no" },
			if raa.is_some() { "an" } else { "no" },
			match order { RAACommitmentOrder::CommitmentFirst => "commitment", RAACommitmentOrder::RevokeAndACKFirst => "RAA"});
		(raa, commitment_update, order, forwards, failures, needs_broadcast_safe, funding_locked)
	}

	pub fn update_fee(&mut self, fee_estimator: &FeeEstimator, msg: &msgs::UpdateFee) -> Result<(), ChannelError> {
		if self.channel_outbound {
			return Err(ChannelError::Close("Non-funding remote tried to update channel fee"));
		}
		if self.channel_state & (ChannelState::PeerDisconnected as u32) == ChannelState::PeerDisconnected as u32 {
			return Err(ChannelError::Close("Peer sent update_fee when we needed a channel_reestablish"));
		}
		Channel::check_remote_fee(fee_estimator, msg.feerate_per_kw)?;
		self.pending_update_fee = Some(msg.feerate_per_kw as u64);
		self.channel_update_count += 1;
		Ok(())
	}

	fn get_last_revoke_and_ack(&self) -> msgs::RevokeAndACK {
		let next_per_commitment_point = PublicKey::from_secret_key(&self.secp_ctx, &self.build_local_commitment_secret(self.cur_local_commitment_transaction_number));
		let per_commitment_secret = chan_utils::build_commitment_secret(self.local_keys.commitment_seed, self.cur_local_commitment_transaction_number + 2);
		msgs::RevokeAndACK {
			channel_id: self.channel_id,
			per_commitment_secret,
			next_per_commitment_point,
		}
	}

	fn get_last_commitment_update(&self) -> msgs::CommitmentUpdate {
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

		log_trace!(self, "Regenerated latest commitment update with {} update_adds, {} update_fulfills, {} update_fails, and {} update_fail_malformeds",
				update_add_htlcs.len(), update_fulfill_htlcs.len(), update_fail_htlcs.len(), update_fail_malformed_htlcs.len());
		msgs::CommitmentUpdate {
			update_add_htlcs, update_fulfill_htlcs, update_fail_htlcs, update_fail_malformed_htlcs,
			update_fee: None,
			commitment_signed: self.send_commitment_no_state_update().expect("It looks like we failed to re-generate a commitment_signed we had previously sent?").0,
		}
	}

	/// May panic if some calls other than message-handling calls (which will all Err immediately)
	/// have been called between remove_uncommitted_htlcs_and_mark_paused and this call.
	pub fn channel_reestablish(&mut self, msg: &msgs::ChannelReestablish) -> Result<(Option<msgs::FundingLocked>, Option<msgs::RevokeAndACK>, Option<msgs::CommitmentUpdate>, Option<ChannelMonitor>, RAACommitmentOrder, Option<msgs::Shutdown>), ChannelError> {
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
					if chan_utils::build_commitment_secret(self.local_keys.commitment_seed, INITIAL_COMMITMENT_NUMBER - msg.next_remote_commitment_number + 1) != data_loss.your_last_per_commitment_secret {
						return Err(ChannelError::Close("Peer sent a garbage channel_reestablish with secret key not matching the commitment height provided"));
					}
					if msg.next_remote_commitment_number > INITIAL_COMMITMENT_NUMBER - self.cur_local_commitment_transaction_number {
						self.channel_monitor.provide_rescue_remote_commitment_tx_info(data_loss.my_current_per_commitment_point);
						return Err(ChannelError::CloseDelayBroadcast { msg: "We have fallen behind - we have received proof that if we broadcast remote is going to claim our funds - we can't do any automated broadcasting", update: Some(self.channel_monitor.clone())
					});
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
				log_debug!(self, "Reconnected channel {} with only lost outbound RAA", log_bytes!(self.channel_id()));
			} else {
				log_debug!(self, "Reconnected channel {} with no loss", log_bytes!(self.channel_id()));
			}

			if (self.channel_state & (ChannelState::AwaitingRemoteRevoke as u32 | ChannelState::MonitorUpdateFailed as u32)) == 0 {
				// We're up-to-date and not waiting on a remote revoke (if we are our
				// channel_reestablish should result in them sending a revoke_and_ack), but we may
				// have received some updates while we were disconnected. Free the holding cell
				// now!
				match self.free_holding_cell_htlcs() {
					Err(ChannelError::Close(msg)) => return Err(ChannelError::Close(msg)),
					Err(ChannelError::Ignore(_)) | Err(ChannelError::CloseDelayBroadcast { .. }) => panic!("Got non-channel-failing result from free_holding_cell_htlcs"),
					Ok(Some((commitment_update, channel_monitor))) => return Ok((resend_funding_locked, required_revoke, Some(commitment_update), Some(channel_monitor), self.resend_order.clone(), shutdown_msg)),
					Ok(None) => return Ok((resend_funding_locked, required_revoke, None, None, self.resend_order.clone(), shutdown_msg)),
				}
			} else {
				return Ok((resend_funding_locked, required_revoke, None, None, self.resend_order.clone(), shutdown_msg));
			}
		} else if msg.next_local_commitment_number == our_next_remote_commitment_number - 1 {
			if required_revoke.is_some() {
				log_debug!(self, "Reconnected channel {} with lost outbound RAA and lost remote commitment tx", log_bytes!(self.channel_id()));
			} else {
				log_debug!(self, "Reconnected channel {} with only lost remote commitment tx", log_bytes!(self.channel_id()));
			}

			if self.channel_state & (ChannelState::MonitorUpdateFailed as u32) != 0 {
				self.monitor_pending_commitment_signed = true;
				return Ok((resend_funding_locked, None, None, None, self.resend_order.clone(), shutdown_msg));
			}

			return Ok((resend_funding_locked, required_revoke, Some(self.get_last_commitment_update()), None, self.resend_order.clone(), shutdown_msg));
		} else {
			return Err(ChannelError::Close("Peer attempted to reestablish channel with a very old remote commitment transaction"));
		}
	}

	fn maybe_propose_first_closing_signed(&mut self, fee_estimator: &FeeEstimator) -> Option<msgs::ClosingSigned> {
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
		let funding_redeemscript = self.get_funding_redeemscript();
		let sighash = hash_to_message!(&bip143::SighashComponents::new(&closing_tx).sighash_all(&closing_tx.input[0], &funding_redeemscript, self.channel_value_satoshis)[..]);

		self.last_sent_closing_fee = Some((proposed_feerate, total_fee_satoshis));
		Some(msgs::ClosingSigned {
			channel_id: self.channel_id,
			fee_satoshis: total_fee_satoshis,
			signature: self.secp_ctx.sign(&sighash, &self.local_keys.funding_key),
		})
	}

	pub fn shutdown(&mut self, fee_estimator: &FeeEstimator, msg: &msgs::Shutdown) -> Result<(Option<msgs::Shutdown>, Option<msgs::ClosingSigned>, Vec<(HTLCSource, PaymentHash)>), ChannelError> {
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
		self.channel_update_count += 1;

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
		self.channel_update_count += 1;
		Ok((our_shutdown, self.maybe_propose_first_closing_signed(fee_estimator), dropped_outbound_htlcs))
	}

	pub fn closing_signed(&mut self, fee_estimator: &FeeEstimator, msg: &msgs::ClosingSigned) -> Result<(Option<msgs::ClosingSigned>, Option<Transaction>), ChannelError> {
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

		match self.secp_ctx.verify(&sighash, &msg.signature, &self.their_funding_pubkey.unwrap()) {
			Ok(_) => {},
			Err(_e) => {
				// The remote end may have decided to revoke their output due to inconsistent dust
				// limits, so check for that case by re-checking the signature here.
				closing_tx = self.build_closing_transaction(msg.fee_satoshis, true).0;
				sighash = hash_to_message!(&bip143::SighashComponents::new(&closing_tx).sighash_all(&closing_tx.input[0], &funding_redeemscript, self.channel_value_satoshis)[..]);
				secp_check!(self.secp_ctx.verify(&sighash, &msg.signature, &self.their_funding_pubkey.unwrap()), "Invalid closing tx signature from peer");
			},
		};

		if let Some((_, last_fee)) = self.last_sent_closing_fee {
			if last_fee == msg.fee_satoshis {
				self.sign_commitment_transaction(&mut closing_tx, &msg.signature);
				self.channel_state = ChannelState::ShutdownComplete as u32;
				self.channel_update_count += 1;
				return Ok((None, Some(closing_tx)));
			}
		}

		macro_rules! propose_new_feerate {
			($new_feerate: expr) => {
				let closing_tx_max_weight = Self::get_closing_transaction_weight(&self.get_closing_scriptpubkey(), self.their_shutdown_scriptpubkey.as_ref().unwrap());
				let (closing_tx, used_total_fee) = self.build_closing_transaction($new_feerate * closing_tx_max_weight / 1000, false);
				sighash = hash_to_message!(&bip143::SighashComponents::new(&closing_tx).sighash_all(&closing_tx.input[0], &funding_redeemscript, self.channel_value_satoshis)[..]);
				let our_sig = self.secp_ctx.sign(&sighash, &self.local_keys.funding_key);
				self.last_sent_closing_fee = Some(($new_feerate, used_total_fee));
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
				if let Some((last_feerate, _)) = self.last_sent_closing_fee {
					if our_max_feerate <= last_feerate {
						return Err(ChannelError::Close("Unable to come to consensus about closing feerate, remote wanted something higher than our Normal feerate"));
					}
				}
				propose_new_feerate!(our_max_feerate);
			}
		} else {
			let our_min_feerate = fee_estimator.get_est_sat_per_1000_weight(ConfirmationTarget::Background);
			if proposed_sat_per_kw < our_min_feerate {
				if let Some((last_feerate, _)) = self.last_sent_closing_fee {
					if our_min_feerate >= last_feerate {
						return Err(ChannelError::Close("Unable to come to consensus about closing feerate, remote wanted something lower than our Background feerate"));
					}
				}
				propose_new_feerate!(our_min_feerate);
			}
		}

		let our_sig = self.sign_commitment_transaction(&mut closing_tx, &msg.signature);
		self.channel_state = ChannelState::ShutdownComplete as u32;
		self.channel_update_count += 1;

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
	pub fn channel_monitor(&self) -> ChannelMonitor {
		if self.channel_state < ChannelState::FundingCreated as u32 {
			panic!("Can't get a channel monitor until funding has been created");
		}
		self.channel_monitor.clone()
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
		self.channel_monitor.get_funding_txo()
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
	pub fn get_local_keys(&self) -> &ChannelKeys {
		&self.local_keys
	}

	#[cfg(test)]
	pub fn get_value_stat(&self) -> ChannelValueStat {
		ChannelValueStat {
			value_to_self_msat: self.value_to_self_msat,
			channel_value_msat: self.channel_value_satoshis * 1000,
			channel_reserve_msat: self.their_channel_reserve_satoshis * 1000,
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
	pub fn get_channel_update_count(&self) -> u32 {
		self.channel_update_count
	}

	pub fn should_announce(&self) -> bool {
		self.config.announced_channel
	}

	pub fn is_outbound(&self) -> bool {
		self.channel_outbound
	}

	/// Gets the fee we'd want to charge for adding an HTLC output to this Channel
	/// Allowed in any state (including after shutdown)
	pub fn get_our_fee_base_msat(&self, fee_estimator: &FeeEstimator) -> u32 {
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
		self.channel_state >= ChannelState::FundingCreated as u32
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

	/// Called by channelmanager based on chain blocks being connected.
	/// Note that we only need to use this to detect funding_signed, anything else is handled by
	/// the channel_monitor.
	/// In case of Err, the channel may have been closed, at which point the standard requirements
	/// apply - no calls may be made except those explicitly stated to be allowed post-shutdown.
	/// Only returns an ErrorAction of DisconnectPeer, if Err.
	pub fn block_connected(&mut self, header: &BlockHeader, height: u32, txn_matched: &[&Transaction], indexes_of_txn_matched: &[u32]) -> Result<Option<msgs::FundingLocked>, msgs::ErrorMessage> {
		let non_shutdown_state = self.channel_state & (!MULTI_STATE_FLAGS);
		if header.bitcoin_hash() != self.last_block_connected {
			self.last_block_connected = header.bitcoin_hash();
			self.channel_monitor.last_block_hash = self.last_block_connected;
			if self.funding_tx_confirmations > 0 {
				self.funding_tx_confirmations += 1;
				if self.funding_tx_confirmations == self.minimum_depth as u64 {
					let need_commitment_update = if non_shutdown_state == ChannelState::FundingSent as u32 {
						self.channel_state |= ChannelState::OurFundingLocked as u32;
						true
					} else if non_shutdown_state == (ChannelState::FundingSent as u32 | ChannelState::TheirFundingLocked as u32) {
						self.channel_state = ChannelState::ChannelFunded as u32 | (self.channel_state & MULTI_STATE_FLAGS);
						self.channel_update_count += 1;
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
							return Ok(Some(msgs::FundingLocked {
								channel_id: self.channel_id,
								next_per_commitment_point: next_per_commitment_point,
							}));
						} else {
							self.monitor_pending_funding_locked = true;
							return Ok(None);
						}
					}
				}
			}
		}
		if non_shutdown_state & !(ChannelState::TheirFundingLocked as u32) == ChannelState::FundingSent as u32 {
			for (ref tx, index_in_block) in txn_matched.iter().zip(indexes_of_txn_matched) {
				if tx.txid() == self.channel_monitor.get_funding_txo().unwrap().txid {
					let txo_idx = self.channel_monitor.get_funding_txo().unwrap().index as usize;
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
						self.channel_update_count += 1;
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
		Ok(None)
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
		self.channel_monitor.last_block_hash = self.last_block_connected;
		false
	}

	// Methods to get unprompted messages to send to the remote end (or where we already returned
	// something in the handler for the message that prompted this message):

	pub fn get_open_channel(&self, chain_hash: Sha256dHash, fee_estimator: &FeeEstimator) -> msgs::OpenChannel {
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
			max_htlc_value_in_flight_msat: Channel::get_our_max_htlc_value_in_flight_msat(self.channel_value_satoshis),
			channel_reserve_satoshis: Channel::get_our_channel_reserve_satoshis(self.channel_value_satoshis),
			htlc_minimum_msat: self.our_htlc_minimum_msat,
			feerate_per_kw: fee_estimator.get_est_sat_per_1000_weight(ConfirmationTarget::Background) as u32,
			to_self_delay: self.our_to_self_delay,
			max_accepted_htlcs: OUR_MAX_HTLCS,
			funding_pubkey: PublicKey::from_secret_key(&self.secp_ctx, &self.local_keys.funding_key),
			revocation_basepoint: PublicKey::from_secret_key(&self.secp_ctx, &self.local_keys.revocation_base_key),
			payment_basepoint: PublicKey::from_secret_key(&self.secp_ctx, &self.local_keys.payment_base_key),
			delayed_payment_basepoint: PublicKey::from_secret_key(&self.secp_ctx, &self.local_keys.delayed_payment_base_key),
			htlc_basepoint: PublicKey::from_secret_key(&self.secp_ctx, &self.local_keys.htlc_base_key),
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
			max_htlc_value_in_flight_msat: Channel::get_our_max_htlc_value_in_flight_msat(self.channel_value_satoshis),
			channel_reserve_satoshis: Channel::get_our_channel_reserve_satoshis(self.channel_value_satoshis),
			htlc_minimum_msat: self.our_htlc_minimum_msat,
			minimum_depth: self.minimum_depth,
			to_self_delay: self.our_to_self_delay,
			max_accepted_htlcs: OUR_MAX_HTLCS,
			funding_pubkey: PublicKey::from_secret_key(&self.secp_ctx, &self.local_keys.funding_key),
			revocation_basepoint: PublicKey::from_secret_key(&self.secp_ctx, &self.local_keys.revocation_base_key),
			payment_basepoint: PublicKey::from_secret_key(&self.secp_ctx, &self.local_keys.payment_base_key),
			delayed_payment_basepoint: PublicKey::from_secret_key(&self.secp_ctx, &self.local_keys.delayed_payment_base_key),
			htlc_basepoint: PublicKey::from_secret_key(&self.secp_ctx, &self.local_keys.htlc_base_key),
			first_per_commitment_point: PublicKey::from_secret_key(&self.secp_ctx, &local_commitment_secret),
			shutdown_scriptpubkey: OptionalField::Present(if self.config.commit_upfront_shutdown_pubkey { self.get_closing_scriptpubkey() } else { Builder::new().into_script() })
		}
	}

	/// If an Err is returned, it is a ChannelError::Close (for get_outbound_funding_created)
	fn get_outbound_funding_created_signature(&mut self) -> Result<(Signature, Transaction), ChannelError> {
		let funding_script = self.get_funding_redeemscript();

		let remote_keys = self.build_remote_transaction_keys()?;
		let remote_initial_commitment_tx = self.build_commitment_transaction(self.cur_remote_commitment_transaction_number, &remote_keys, false, false, self.feerate_per_kw).0;
		let remote_sighash = hash_to_message!(&bip143::SighashComponents::new(&remote_initial_commitment_tx).sighash_all(&remote_initial_commitment_tx.input[0], &funding_script, self.channel_value_satoshis)[..]);

		// We sign the "remote" commitment transaction, allowing them to broadcast the tx if they wish.
		Ok((self.secp_ctx.sign(&remote_sighash, &self.local_keys.funding_key), remote_initial_commitment_tx))
	}

	/// Updates channel state with knowledge of the funding transaction's txid/index, and generates
	/// a funding_created message for the remote peer.
	/// Panics if called at some time other than immediately after initial handshake, if called twice,
	/// or if called on an inbound channel.
	/// Note that channel_id changes during this call!
	/// Do NOT broadcast the funding transaction until after a successful funding_signed call!
	/// If an Err is returned, it is a ChannelError::Close.
	pub fn get_outbound_funding_created(&mut self, funding_txo: OutPoint) -> Result<(msgs::FundingCreated, ChannelMonitor), ChannelError> {
		if !self.channel_outbound {
			panic!("Tried to create outbound funding_created message on an inbound channel!");
		}
		if self.channel_state != (ChannelState::OurInitSent as u32 | ChannelState::TheirInitSent as u32) {
			panic!("Tried to get a funding_created messsage at a time other than immediately after initial handshake completion (or tried to get funding_created twice)");
		}
		if self.channel_monitor.get_min_seen_secret() != (1 << 48) ||
				self.cur_remote_commitment_transaction_number != INITIAL_COMMITMENT_NUMBER ||
				self.cur_local_commitment_transaction_number != INITIAL_COMMITMENT_NUMBER {
			panic!("Should not have advanced channel commitment tx numbers prior to funding_created");
		}

		let funding_txo_script = self.get_funding_redeemscript().to_v0_p2wsh();
		self.channel_monitor.set_funding_info((funding_txo, funding_txo_script));

		let (our_signature, commitment_tx) = match self.get_outbound_funding_created_signature() {
			Ok(res) => res,
			Err(e) => {
				log_error!(self, "Got bad signatures: {:?}!", e);
				self.channel_monitor.unset_funding_info();
				return Err(e);
			}
		};

		let temporary_channel_id = self.channel_id;

		// Now that we're past error-generating stuff, update our local state:
		self.channel_monitor.provide_latest_remote_commitment_tx_info(&commitment_tx, Vec::new(), self.cur_remote_commitment_transaction_number, self.their_cur_commitment_point.unwrap());
		self.channel_state = ChannelState::FundingCreated as u32;
		self.channel_id = funding_txo.to_channel_id();
		self.cur_remote_commitment_transaction_number -= 1;

		Ok((msgs::FundingCreated {
			temporary_channel_id: temporary_channel_id,
			funding_txid: funding_txo.txid,
			funding_output_index: funding_txo.index,
			signature: our_signature
		}, self.channel_monitor.clone()))
	}

	/// Gets an UnsignedChannelAnnouncement, as well as a signature covering it using our
	/// bitcoin_key, if available, for this channel. The channel must be publicly announceable and
	/// available for use (have exchanged FundingLocked messages in both directions). Should be used
	/// for both loose and in response to an AnnouncementSignatures message from the remote peer.
	/// Will only fail if we're not in a state where channel_announcement may be sent (including
	/// closing).
	/// Note that the "channel must be funded" requirement is stricter than BOLT 7 requires - see
	/// https://github.com/lightningnetwork/lightning-rfc/issues/468
	pub fn get_channel_announcement(&self, our_node_id: PublicKey, chain_hash: Sha256dHash) -> Result<(msgs::UnsignedChannelAnnouncement, Signature), ChannelError> {
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
		let our_bitcoin_key = PublicKey::from_secret_key(&self.secp_ctx, &self.local_keys.funding_key);

		let msg = msgs::UnsignedChannelAnnouncement {
			features: msgs::GlobalFeatures::new(),
			chain_hash: chain_hash,
			short_channel_id: self.get_short_channel_id().unwrap(),
			node_id_1: if were_node_one { our_node_id } else { self.get_their_node_id() },
			node_id_2: if were_node_one { self.get_their_node_id() } else { our_node_id },
			bitcoin_key_1: if were_node_one { our_bitcoin_key } else { self.their_funding_pubkey.unwrap() },
			bitcoin_key_2: if were_node_one { self.their_funding_pubkey.unwrap() } else { our_bitcoin_key },
			excess_data: Vec::new(),
		};

		let msghash = hash_to_message!(&Sha256dHash::hash(&msg.encode()[..])[..]);
		let sig = self.secp_ctx.sign(&msghash, &self.local_keys.funding_key);

		Ok((msg, sig))
	}

	/// May panic if called on a channel that wasn't immediately-previously
	/// self.remove_uncommitted_htlcs_and_mark_paused()'d
	pub fn get_channel_reestablish(&self) -> msgs::ChannelReestablish {
		assert_eq!(self.channel_state & ChannelState::PeerDisconnected as u32, ChannelState::PeerDisconnected as u32);
		assert_ne!(self.cur_remote_commitment_transaction_number, INITIAL_COMMITMENT_NUMBER);
		let data_loss_protect = if self.cur_remote_commitment_transaction_number + 1 < INITIAL_COMMITMENT_NUMBER {
			let remote_last_secret = self.channel_monitor.get_secret(self.cur_remote_commitment_transaction_number + 2).unwrap();
			log_trace!(self, "Enough info to generate a Data Loss Protect with per_commitment_secret {}", log_bytes!(remote_last_secret));
			OptionalField::Present(DataLossProtect {
				your_last_per_commitment_secret: remote_last_secret,
				my_current_per_commitment_point: PublicKey::from_secret_key(&self.secp_ctx, &self.build_local_commitment_secret(self.cur_local_commitment_transaction_number + 1))
			})
		} else {
			log_debug!(self, "We don't seen yet any revoked secret, if this channnel has already been updated it means we are fallen-behind, you should wait for other peer closing");
			OptionalField::Present(DataLossProtect {
				your_last_per_commitment_secret: [0;32],
				my_current_per_commitment_point: PublicKey::from_secret_key(&self.secp_ctx, &self.build_local_commitment_secret(self.cur_local_commitment_transaction_number))
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

		// Check self.their_channel_reserve_satoshis (the amount we must keep as
		// reserve for them to have something to claim if we misbehave)
		if self.value_to_self_msat < self.their_channel_reserve_satoshis * 1000 + amount_msat + htlc_outbound_value_msat {
			return Err(ChannelError::Ignore("Cannot send value that would put us over their reserve value"));
		}

		//TODO: Check cltv_expiry? Do this in channel manager?

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
	pub fn send_commitment(&mut self) -> Result<(msgs::CommitmentSigned, ChannelMonitor), ChannelError> {
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
		self.send_commitment_no_status_check()
	}
	/// Only fails in case of bad keys
	fn send_commitment_no_status_check(&mut self) -> Result<(msgs::CommitmentSigned, ChannelMonitor), ChannelError> {
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

		let (res, remote_commitment_tx, htlcs) = match self.send_commitment_no_state_update() {
			Ok((res, (remote_commitment_tx, mut htlcs))) => {
				// Update state now that we've passed all the can-fail calls...
				let htlcs_no_ref = htlcs.drain(..).map(|(htlc, htlc_source)| (htlc, htlc_source.map(|source_ref| Box::new(source_ref.clone())))).collect();
				(res, remote_commitment_tx, htlcs_no_ref)
			},
			Err(e) => return Err(e),
		};

		self.channel_monitor.provide_latest_remote_commitment_tx_info(&remote_commitment_tx, htlcs, self.cur_remote_commitment_transaction_number, self.their_cur_commitment_point.unwrap());
		self.channel_state |= ChannelState::AwaitingRemoteRevoke as u32;
		Ok((res, self.channel_monitor.clone()))
	}

	/// Only fails in case of bad keys. Used for channel_reestablish commitment_signed generation
	/// when we shouldn't change HTLC/channel state.
	fn send_commitment_no_state_update(&self) -> Result<(msgs::CommitmentSigned, (Transaction, Vec<(HTLCOutputInCommitment, Option<&HTLCSource>)>)), ChannelError> {
		let funding_script = self.get_funding_redeemscript();

		let mut feerate_per_kw = self.feerate_per_kw;
		if let Some(feerate) = self.pending_update_fee {
			if self.channel_outbound {
				feerate_per_kw = feerate;
			}
		}

		let remote_keys = self.build_remote_transaction_keys()?;
		let remote_commitment_tx = self.build_commitment_transaction(self.cur_remote_commitment_transaction_number, &remote_keys, false, true, feerate_per_kw);
		let remote_commitment_txid = remote_commitment_tx.0.txid();
		let remote_sighash = hash_to_message!(&bip143::SighashComponents::new(&remote_commitment_tx.0).sighash_all(&remote_commitment_tx.0.input[0], &funding_script, self.channel_value_satoshis)[..]);
		let our_sig = self.secp_ctx.sign(&remote_sighash, &self.local_keys.funding_key);
		log_trace!(self, "Signing remote commitment tx {} with redeemscript {} with pubkey {} -> {}", encode::serialize_hex(&remote_commitment_tx.0), encode::serialize_hex(&funding_script), log_bytes!(PublicKey::from_secret_key(&self.secp_ctx, &self.local_keys.funding_key).serialize()), log_bytes!(our_sig.serialize_compact()[..]));

		let mut htlc_sigs = Vec::with_capacity(remote_commitment_tx.1);
		for &(ref htlc, _) in remote_commitment_tx.2.iter() {
			if let Some(_) = htlc.transaction_output_index {
				let htlc_tx = self.build_htlc_transaction(&remote_commitment_txid, htlc, false, &remote_keys, feerate_per_kw);
				let htlc_redeemscript = chan_utils::get_htlc_redeemscript(&htlc, &remote_keys);
				let htlc_sighash = hash_to_message!(&bip143::SighashComponents::new(&htlc_tx).sighash_all(&htlc_tx.input[0], &htlc_redeemscript, htlc.amount_msat / 1000)[..]);
				let our_htlc_key = secp_check!(chan_utils::derive_private_key(&self.secp_ctx, &remote_keys.per_commitment_point, &self.local_keys.htlc_base_key), "Derived invalid key, peer is maliciously selecting parameters");
				htlc_sigs.push(self.secp_ctx.sign(&htlc_sighash, &our_htlc_key));
				log_trace!(self, "Signing remote HTLC tx {} with redeemscript {} with pubkey {} -> {}", encode::serialize_hex(&htlc_tx), encode::serialize_hex(&htlc_redeemscript), log_bytes!(PublicKey::from_secret_key(&self.secp_ctx, &our_htlc_key).serialize()), log_bytes!(htlc_sigs.last().unwrap().serialize_compact()[..]));
			}
		}

		Ok((msgs::CommitmentSigned {
			channel_id: self.channel_id,
			signature: our_sig,
			htlc_signatures: htlc_sigs,
		}, (remote_commitment_tx.0, remote_commitment_tx.2)))
	}

	/// Adds a pending outbound HTLC to this channel, and creates a signed commitment transaction
	/// to send to the remote peer in one go.
	/// Shorthand for calling send_htlc() followed by send_commitment(), see docs on those for
	/// more info.
	pub fn send_htlc_and_commit(&mut self, amount_msat: u64, payment_hash: PaymentHash, cltv_expiry: u32, source: HTLCSource, onion_routing_packet: msgs::OnionPacket) -> Result<Option<(msgs::UpdateAddHTLC, msgs::CommitmentSigned, ChannelMonitor)>, ChannelError> {
		match self.send_htlc(amount_msat, payment_hash, cltv_expiry, source, onion_routing_packet)? {
			Some(update_add_htlc) => {
				let (commitment_signed, monitor_update) = self.send_commitment_no_status_check()?;
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
		self.channel_update_count += 1;

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
	pub fn force_shutdown(&mut self) -> (Vec<Transaction>, Vec<(HTLCSource, PaymentHash)>) {
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
		self.channel_update_count += 1;
		let mut res = Vec::new();
		mem::swap(&mut res, &mut self.last_local_commitment_txn);
		(res, dropped_outbound_htlcs)
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

impl<R: ::std::io::Read> Readable<R> for InboundHTLCRemovalReason {
	fn read(reader: &mut R) -> Result<Self, DecodeError> {
		Ok(match <u8 as Readable<R>>::read(reader)? {
			0 => InboundHTLCRemovalReason::FailRelay(Readable::read(reader)?),
			1 => InboundHTLCRemovalReason::FailMalformed((Readable::read(reader)?, Readable::read(reader)?)),
			2 => InboundHTLCRemovalReason::Fulfill(Readable::read(reader)?),
			_ => return Err(DecodeError::InvalidValue),
		})
	}
}

impl Writeable for Channel {
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

		self.local_keys.write(writer)?;
		self.shutdown_pubkey.write(writer)?;

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
			htlc.htlc_id.write(writer)?;
			htlc.amount_msat.write(writer)?;
			htlc.cltv_expiry.write(writer)?;
			htlc.payment_hash.write(writer)?;
			match &htlc.state {
				&InboundHTLCState::RemoteAnnounced(_) => {}, // Drop
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

		macro_rules! write_option {
			($thing: expr) => {
				match &$thing {
					&None => 0u8.write(writer)?,
					&Some(ref v) => {
						1u8.write(writer)?;
						v.write(writer)?;
					},
				}
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
					write_option!(*fail_reason);
				},
				&OutboundHTLCState::AwaitingRemoteRevokeToRemove(ref fail_reason) => {
					3u8.write(writer)?;
					write_option!(*fail_reason);
				},
				&OutboundHTLCState::AwaitingRemovedRemoteRevoke(ref fail_reason) => {
					4u8.write(writer)?;
					write_option!(*fail_reason);
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

		write_option!(self.pending_update_fee);
		write_option!(self.holding_cell_update_fee);

		self.next_local_htlc_id.write(writer)?;
		(self.next_remote_htlc_id - dropped_inbound_htlcs).write(writer)?;
		self.channel_update_count.write(writer)?;
		self.feerate_per_kw.write(writer)?;

		(self.last_local_commitment_txn.len() as u64).write(writer)?;
		for tx in self.last_local_commitment_txn.iter() {
			if let Err(e) = tx.consensus_encode(&mut WriterWriteAdaptor(writer)) {
				match e {
					encode::Error::Io(e) => return Err(e),
					_ => panic!("last_local_commitment_txn must have been well-formed!"),
				}
			}
		}

		match self.last_sent_closing_fee {
			Some((feerate, fee)) => {
				1u8.write(writer)?;
				feerate.write(writer)?;
				fee.write(writer)?;
			},
			None => 0u8.write(writer)?,
		}

		write_option!(self.funding_tx_confirmed_in);
		write_option!(self.short_channel_id);

		self.last_block_connected.write(writer)?;
		self.funding_tx_confirmations.write(writer)?;

		self.their_dust_limit_satoshis.write(writer)?;
		self.our_dust_limit_satoshis.write(writer)?;
		self.their_max_htlc_value_in_flight_msat.write(writer)?;
		self.their_channel_reserve_satoshis.write(writer)?;
		self.their_htlc_minimum_msat.write(writer)?;
		self.our_htlc_minimum_msat.write(writer)?;
		self.their_to_self_delay.write(writer)?;
		self.our_to_self_delay.write(writer)?;
		self.their_max_accepted_htlcs.write(writer)?;
		self.minimum_depth.write(writer)?;

		write_option!(self.their_funding_pubkey);
		write_option!(self.their_revocation_basepoint);
		write_option!(self.their_payment_basepoint);
		write_option!(self.their_delayed_payment_basepoint);
		write_option!(self.their_htlc_basepoint);
		write_option!(self.their_cur_commitment_point);

		write_option!(self.their_prev_commitment_point);
		self.their_node_id.write(writer)?;

		write_option!(self.their_shutdown_scriptpubkey);

		self.channel_monitor.write_for_disk(writer)?;
		Ok(())
	}
}

impl<R : ::std::io::Read> ReadableArgs<R, Arc<Logger>> for Channel {
	fn read(reader: &mut R, logger: Arc<Logger>) -> Result<Self, DecodeError> {
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

		let local_keys = Readable::read(reader)?;
		let shutdown_pubkey = Readable::read(reader)?;

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
				state: match <u8 as Readable<R>>::read(reader)? {
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
				state: match <u8 as Readable<R>>::read(reader)? {
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
			holding_cell_htlc_updates.push(match <u8 as Readable<R>>::read(reader)? {
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

		let resend_order = match <u8 as Readable<R>>::read(reader)? {
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
		let channel_update_count = Readable::read(reader)?;
		let feerate_per_kw = Readable::read(reader)?;

		let last_local_commitment_txn_count: u64 = Readable::read(reader)?;
		let mut last_local_commitment_txn = Vec::with_capacity(cmp::min(last_local_commitment_txn_count as usize, OUR_MAX_HTLCS as usize*2 + 1));
		for _ in 0..last_local_commitment_txn_count {
			last_local_commitment_txn.push(match Transaction::consensus_decode(reader.by_ref()) {
				Ok(tx) => tx,
				Err(_) => return Err(DecodeError::InvalidValue),
			});
		}

		let last_sent_closing_fee = match <u8 as Readable<R>>::read(reader)? {
			0 => None,
			1 => Some((Readable::read(reader)?, Readable::read(reader)?)),
			_ => return Err(DecodeError::InvalidValue),
		};

		let funding_tx_confirmed_in = Readable::read(reader)?;
		let short_channel_id = Readable::read(reader)?;

		let last_block_connected = Readable::read(reader)?;
		let funding_tx_confirmations = Readable::read(reader)?;

		let their_dust_limit_satoshis = Readable::read(reader)?;
		let our_dust_limit_satoshis = Readable::read(reader)?;
		let their_max_htlc_value_in_flight_msat = Readable::read(reader)?;
		let their_channel_reserve_satoshis = Readable::read(reader)?;
		let their_htlc_minimum_msat = Readable::read(reader)?;
		let our_htlc_minimum_msat = Readable::read(reader)?;
		let their_to_self_delay = Readable::read(reader)?;
		let our_to_self_delay = Readable::read(reader)?;
		let their_max_accepted_htlcs = Readable::read(reader)?;
		let minimum_depth = Readable::read(reader)?;

		let their_funding_pubkey = Readable::read(reader)?;
		let their_revocation_basepoint = Readable::read(reader)?;
		let their_payment_basepoint = Readable::read(reader)?;
		let their_delayed_payment_basepoint = Readable::read(reader)?;
		let their_htlc_basepoint = Readable::read(reader)?;
		let their_cur_commitment_point = Readable::read(reader)?;

		let their_prev_commitment_point = Readable::read(reader)?;
		let their_node_id = Readable::read(reader)?;

		let their_shutdown_scriptpubkey = Readable::read(reader)?;
		let (monitor_last_block, channel_monitor) = ReadableArgs::read(reader, logger.clone())?;
		// We drop the ChannelMonitor's last block connected hash cause we don't actually bother
		// doing full block connection operations on the internal CHannelMonitor copies
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

			local_keys,
			shutdown_pubkey,

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
			channel_update_count,
			feerate_per_kw,

			#[cfg(debug_assertions)]
			max_commitment_tx_output_local: ::std::sync::Mutex::new((0, 0)),
			#[cfg(debug_assertions)]
			max_commitment_tx_output_remote: ::std::sync::Mutex::new((0, 0)),

			last_local_commitment_txn,

			last_sent_closing_fee,

			funding_tx_confirmed_in,
			short_channel_id,
			last_block_connected,
			funding_tx_confirmations,

			their_dust_limit_satoshis,
			our_dust_limit_satoshis,
			their_max_htlc_value_in_flight_msat,
			their_channel_reserve_satoshis,
			their_htlc_minimum_msat,
			our_htlc_minimum_msat,
			their_to_self_delay,
			our_to_self_delay,
			their_max_accepted_htlcs,
			minimum_depth,

			their_funding_pubkey,
			their_revocation_basepoint,
			their_payment_basepoint,
			their_delayed_payment_basepoint,
			their_htlc_basepoint,
			their_cur_commitment_point,

			their_prev_commitment_point,
			their_node_id,

			their_shutdown_scriptpubkey,

			channel_monitor,

			logger,
		})
	}
}

#[cfg(test)]
mod tests {
	use bitcoin::util::bip143;
	use bitcoin::consensus::encode::serialize;
	use bitcoin::blockdata::script::{Script, Builder};
	use bitcoin::blockdata::transaction::Transaction;
	use bitcoin::blockdata::opcodes;
	use bitcoin_hashes::hex::FromHex;
	use hex;
	use ln::channelmanager::{HTLCSource, PaymentPreimage, PaymentHash};
	use ln::channel::{Channel,ChannelKeys,InboundHTLCOutput,OutboundHTLCOutput,InboundHTLCState,OutboundHTLCState,HTLCOutputInCommitment,TxCreationKeys};
	use ln::channel::MAX_FUNDING_SATOSHIS;
	use ln::chan_utils;
	use chain::chaininterface::{FeeEstimator,ConfirmationTarget};
	use chain::keysinterface::KeysInterface;
	use chain::transaction::OutPoint;
	use util::config::UserConfig;
	use util::test_utils;
	use util::logger::Logger;
	use secp256k1::{Secp256k1,Message,Signature};
	use secp256k1::key::{SecretKey,PublicKey};
	use bitcoin_hashes::sha256::Hash as Sha256;
	use bitcoin_hashes::sha256d::Hash as Sha256dHash;
	use bitcoin_hashes::hash160::Hash as Hash160;
	use bitcoin_hashes::Hash;
	use std::sync::Arc;

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
		chan_keys: ChannelKeys,
	}
	impl KeysInterface for Keys {
		fn get_node_secret(&self) -> SecretKey { panic!(); }
		fn get_destination_script(&self) -> Script {
			let secp_ctx = Secp256k1::signing_only();
			let channel_monitor_claim_key = SecretKey::from_slice(&hex::decode("0fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").unwrap()[..]).unwrap();
			let our_channel_monitor_claim_key_hash = Hash160::hash(&PublicKey::from_secret_key(&secp_ctx, &channel_monitor_claim_key).serialize());
			Builder::new().push_opcode(opcodes::all::OP_PUSHBYTES_0).push_slice(&our_channel_monitor_claim_key_hash[..]).into_script()
		}

		fn get_shutdown_pubkey(&self) -> PublicKey {
			let secp_ctx = Secp256k1::signing_only();
			let channel_close_key = SecretKey::from_slice(&hex::decode("0fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").unwrap()[..]).unwrap();
			PublicKey::from_secret_key(&secp_ctx, &channel_close_key)
		}

		fn get_channel_keys(&self, _inbound: bool) -> ChannelKeys { self.chan_keys.clone() }
		fn get_session_key(&self) -> SecretKey { panic!(); }
		fn get_channel_id(&self) -> [u8; 32] { [0; 32] }
	}

	#[test]
	fn outbound_commitment_test() {
		// Test vectors from BOLT 3 Appendix C:
		let feeest = TestFeeEstimator{fee_est: 15000};
		let logger : Arc<Logger> = Arc::new(test_utils::TestLogger::new());
		let secp_ctx = Secp256k1::new();

		let chan_keys = ChannelKeys {
			funding_key: SecretKey::from_slice(&hex::decode("30ff4956bbdd3222d44cc5e8a1261dab1e07957bdac5ae88fe3261ef321f3749").unwrap()[..]).unwrap(),
			payment_base_key: SecretKey::from_slice(&hex::decode("1111111111111111111111111111111111111111111111111111111111111111").unwrap()[..]).unwrap(),
			delayed_payment_base_key: SecretKey::from_slice(&hex::decode("3333333333333333333333333333333333333333333333333333333333333333").unwrap()[..]).unwrap(),
			htlc_base_key: SecretKey::from_slice(&hex::decode("1111111111111111111111111111111111111111111111111111111111111111").unwrap()[..]).unwrap(),

			// These aren't set in the test vectors:
			revocation_base_key: SecretKey::from_slice(&hex::decode("0fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").unwrap()[..]).unwrap(),
			commitment_seed: [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
		};
		assert_eq!(PublicKey::from_secret_key(&secp_ctx, &chan_keys.funding_key).serialize()[..],
				hex::decode("023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb").unwrap()[..]);
		let keys_provider: Arc<KeysInterface> = Arc::new(Keys { chan_keys });

		let their_node_id = PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[42; 32]).unwrap());
		let mut config = UserConfig::new();
		config.channel_options.announced_channel = false;
		let mut chan = Channel::new_outbound(&feeest, &keys_provider, their_node_id, 10000000, 100000, 42, Arc::clone(&logger), &config).unwrap(); // Nothing uses their network key in this test
		chan.their_to_self_delay = 144;
		chan.our_dust_limit_satoshis = 546;

		let funding_info = OutPoint::new(Sha256dHash::from_hex("8984484a580b825b9972d7adb15050b3ab624ccd731946b3eeddb92f4e7ef6be").unwrap(), 0);
		chan.channel_monitor.set_funding_info((funding_info, Script::new()));

		chan.their_payment_basepoint = Some(PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&hex::decode("4444444444444444444444444444444444444444444444444444444444444444").unwrap()[..]).unwrap()));
		assert_eq!(chan.their_payment_basepoint.unwrap().serialize()[..],
				hex::decode("032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991").unwrap()[..]);

		chan.their_funding_pubkey = Some(PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&hex::decode("1552dfba4f6cf29a62a0af13c8d6981d36d0ef8d61ba10fb0fe90da7634d7e13").unwrap()[..]).unwrap()));
		assert_eq!(chan.their_funding_pubkey.unwrap().serialize()[..],
				hex::decode("030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c1").unwrap()[..]);

		chan.their_htlc_basepoint = Some(PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&hex::decode("4444444444444444444444444444444444444444444444444444444444444444").unwrap()[..]).unwrap()));
		assert_eq!(chan.their_htlc_basepoint.unwrap().serialize()[..],
				hex::decode("032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991").unwrap()[..]);

		chan.their_revocation_basepoint = Some(PublicKey::from_slice(&hex::decode("02466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27").unwrap()[..]).unwrap());

		// We can't just use build_local_transaction_keys here as the per_commitment_secret is not
		// derived from a commitment_seed, so instead we copy it here and call
		// build_commitment_transaction.
		let delayed_payment_base = PublicKey::from_secret_key(&secp_ctx, &chan.local_keys.delayed_payment_base_key);
		let per_commitment_secret = SecretKey::from_slice(&hex::decode("1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100").unwrap()[..]).unwrap();
		let per_commitment_point = PublicKey::from_secret_key(&secp_ctx, &per_commitment_secret);
		let htlc_basepoint = PublicKey::from_secret_key(&secp_ctx, &chan.local_keys.htlc_base_key);
		let keys = TxCreationKeys::new(&secp_ctx, &per_commitment_point, &delayed_payment_base, &htlc_basepoint, &chan.their_revocation_basepoint.unwrap(), &chan.their_payment_basepoint.unwrap(), &chan.their_htlc_basepoint.unwrap()).unwrap();

		let mut unsigned_tx: (Transaction, Vec<HTLCOutputInCommitment>);

		macro_rules! test_commitment {
			( $their_sig_hex: expr, $our_sig_hex: expr, $tx_hex: expr) => {
				unsigned_tx = {
					let mut res = chan.build_commitment_transaction(0xffffffffffff - 42, &keys, true, false, chan.feerate_per_kw);
					let htlcs = res.2.drain(..)
						.filter_map(|(htlc, _)| if htlc.transaction_output_index.is_some() { Some(htlc) } else { None })
						.collect();
					(res.0, htlcs)
				};
				let their_signature = Signature::from_der(&hex::decode($their_sig_hex).unwrap()[..]).unwrap();
				let sighash = Message::from_slice(&bip143::SighashComponents::new(&unsigned_tx.0).sighash_all(&unsigned_tx.0.input[0], &chan.get_funding_redeemscript(), chan.channel_value_satoshis)[..]).unwrap();
				secp_ctx.verify(&sighash, &their_signature, &chan.their_funding_pubkey.unwrap()).unwrap();

				chan.sign_commitment_transaction(&mut unsigned_tx.0, &their_signature);

				assert_eq!(serialize(&unsigned_tx.0)[..],
						hex::decode($tx_hex).unwrap()[..]);
			};
		}

		macro_rules! test_htlc_output {
			( $htlc_idx: expr, $their_sig_hex: expr, $our_sig_hex: expr, $tx_hex: expr ) => {
				let remote_signature = Signature::from_der(&hex::decode($their_sig_hex).unwrap()[..]).unwrap();

				let ref htlc = unsigned_tx.1[$htlc_idx];
				let mut htlc_tx = chan.build_htlc_transaction(&unsigned_tx.0.txid(), &htlc, true, &keys, chan.feerate_per_kw);
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

				chan.sign_htlc_transaction(&mut htlc_tx, &remote_signature, &preimage, &htlc, &keys).unwrap();
				assert_eq!(serialize(&htlc_tx)[..],
						hex::decode($tx_hex).unwrap()[..]);
			};
		}

		{
			// simple commitment tx with no HTLCs
			chan.value_to_self_msat = 7000000000;

			test_commitment!("3045022100f51d2e566a70ba740fc5d8c0f07b9b93d2ed741c3c0860c613173de7d39e7968022041376d520e9c0e1ad52248ddf4b22e12be8763007df977253ef45a4ca3bdb7c0",
			                 "3044022051b75c73198c6deee1a875871c3961832909acd297c6b908d59e3319e5185a46022055c419379c5051a78d00dbbce11b5b664a0c22815fbcc6fcef6b1937c3836939",
			                 "02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b8002c0c62d0000000000160014ccf1af2f2aabee14bb40fa3851ab2301de84311054a56a00000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0400473044022051b75c73198c6deee1a875871c3961832909acd297c6b908d59e3319e5185a46022055c419379c5051a78d00dbbce11b5b664a0c22815fbcc6fcef6b1937c383693901483045022100f51d2e566a70ba740fc5d8c0f07b9b93d2ed741c3c0860c613173de7d39e7968022041376d520e9c0e1ad52248ddf4b22e12be8763007df977253ef45a4ca3bdb7c001475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae3e195220");
		}

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

		{
			// commitment tx with all five HTLCs untrimmed (minimum feerate)
			chan.value_to_self_msat = 6993000000; // 7000000000 - 7000000
			chan.feerate_per_kw = 0;

			test_commitment!("304402204fd4928835db1ccdfc40f5c78ce9bd65249b16348df81f0c44328dcdefc97d630220194d3869c38bc732dd87d13d2958015e2fc16829e74cd4377f84d215c0b70606",
			                 "30440220275b0c325a5e9355650dc30c0eccfbc7efb23987c24b556b9dfdd40effca18d202206caceb2c067836c51f296740c7ae807ffcbfbf1dd3a0d56b6de9a5b247985f06",
			                 "02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b8007e80300000000000022002052bfef0479d7b293c27e0f1eb294bea154c63a3294ef092c19af51409bce0e2ad007000000000000220020403d394747cae42e98ff01734ad5c08f82ba123d3d9a620abda88989651e2ab5d007000000000000220020748eba944fedc8827f6b06bc44678f93c0f9e6078b35c6331ed31e75f8ce0c2db80b000000000000220020c20b5d1f8584fd90443e7b7b720136174fa4b9333c261d04dbbd012635c0f419a00f0000000000002200208c48d15160397c9731df9bc3b236656efb6665fbfe92b4a6878e88a499f741c4c0c62d0000000000160014ccf1af2f2aabee14bb40fa3851ab2301de843110e0a06a00000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e04004730440220275b0c325a5e9355650dc30c0eccfbc7efb23987c24b556b9dfdd40effca18d202206caceb2c067836c51f296740c7ae807ffcbfbf1dd3a0d56b6de9a5b247985f060147304402204fd4928835db1ccdfc40f5c78ce9bd65249b16348df81f0c44328dcdefc97d630220194d3869c38bc732dd87d13d2958015e2fc16829e74cd4377f84d215c0b7060601475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae3e195220");

			assert_eq!(unsigned_tx.1.len(), 5);

			test_htlc_output!(0,
			                  "304402206a6e59f18764a5bf8d4fa45eebc591566689441229c918b480fb2af8cc6a4aeb02205248f273be447684b33e3c8d1d85a8e0ca9fa0bae9ae33f0527ada9c162919a6",
			                  "304402207cb324fa0de88f452ffa9389678127ebcf4cabe1dd848b8e076c1a1962bf34720220116ed922b12311bd602d67e60d2529917f21c5b82f25ff6506c0f87886b4dfd5",
			                  "020000000001018154ecccf11a5fb56c39654c4deb4d2296f83c69268280b94d021370c94e219700000000000000000001e8030000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e050047304402206a6e59f18764a5bf8d4fa45eebc591566689441229c918b480fb2af8cc6a4aeb02205248f273be447684b33e3c8d1d85a8e0ca9fa0bae9ae33f0527ada9c162919a60147304402207cb324fa0de88f452ffa9389678127ebcf4cabe1dd848b8e076c1a1962bf34720220116ed922b12311bd602d67e60d2529917f21c5b82f25ff6506c0f87886b4dfd5012000000000000000000000000000000000000000000000000000000000000000008a76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a914b8bcb07f6344b42ab04250c86a6e8b75d3fdbbc688527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f401b175ac686800000000");

			test_htlc_output!(1,
			                  "3045022100d5275b3619953cb0c3b5aa577f04bc512380e60fa551762ce3d7a1bb7401cff9022037237ab0dac3fe100cde094e82e2bed9ba0ed1bb40154b48e56aa70f259e608b",
			                  "3045022100c89172099507ff50f4c925e6c5150e871fb6e83dd73ff9fbb72f6ce829a9633f02203a63821d9162e99f9be712a68f9e589483994feae2661e4546cd5b6cec007be5",
			                  "020000000001018154ecccf11a5fb56c39654c4deb4d2296f83c69268280b94d021370c94e219701000000000000000001d0070000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0500483045022100d5275b3619953cb0c3b5aa577f04bc512380e60fa551762ce3d7a1bb7401cff9022037237ab0dac3fe100cde094e82e2bed9ba0ed1bb40154b48e56aa70f259e608b01483045022100c89172099507ff50f4c925e6c5150e871fb6e83dd73ff9fbb72f6ce829a9633f02203a63821d9162e99f9be712a68f9e589483994feae2661e4546cd5b6cec007be501008576a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a914b43e1b38138a41b37f7cd9a1d274bc63e3a9b5d188ac6868f6010000");

			test_htlc_output!(2,
			                  "304402201b63ec807771baf4fdff523c644080de17f1da478989308ad13a58b51db91d360220568939d38c9ce295adba15665fa68f51d967e8ed14a007b751540a80b325f202",
			                  "3045022100def389deab09cee69eaa1ec14d9428770e45bcbe9feb46468ecf481371165c2f022015d2e3c46600b2ebba8dcc899768874cc6851fd1ecb3fffd15db1cc3de7e10da",
			                  "020000000001018154ecccf11a5fb56c39654c4deb4d2296f83c69268280b94d021370c94e219702000000000000000001d0070000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e050047304402201b63ec807771baf4fdff523c644080de17f1da478989308ad13a58b51db91d360220568939d38c9ce295adba15665fa68f51d967e8ed14a007b751540a80b325f20201483045022100def389deab09cee69eaa1ec14d9428770e45bcbe9feb46468ecf481371165c2f022015d2e3c46600b2ebba8dcc899768874cc6851fd1ecb3fffd15db1cc3de7e10da012001010101010101010101010101010101010101010101010101010101010101018a76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a9144b6b2e5444c2639cc0fb7bcea5afba3f3cdce23988527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f501b175ac686800000000");

			test_htlc_output!(3,
			                  "3045022100daee1808f9861b6c3ecd14f7b707eca02dd6bdfc714ba2f33bc8cdba507bb182022026654bf8863af77d74f51f4e0b62d461a019561bb12acb120d3f7195d148a554",
			                  "30440220643aacb19bbb72bd2b635bc3f7375481f5981bace78cdd8319b2988ffcc6704202203d27784ec8ad51ed3bd517a05525a5139bb0b755dd719e0054332d186ac08727",
			                  "020000000001018154ecccf11a5fb56c39654c4deb4d2296f83c69268280b94d021370c94e219703000000000000000001b80b0000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0500483045022100daee1808f9861b6c3ecd14f7b707eca02dd6bdfc714ba2f33bc8cdba507bb182022026654bf8863af77d74f51f4e0b62d461a019561bb12acb120d3f7195d148a554014730440220643aacb19bbb72bd2b635bc3f7375481f5981bace78cdd8319b2988ffcc6704202203d27784ec8ad51ed3bd517a05525a5139bb0b755dd719e0054332d186ac0872701008576a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a9148a486ff2e31d6158bf39e2608864d63fefd09d5b88ac6868f7010000");

			test_htlc_output!(4,
			                  "304402207e0410e45454b0978a623f36a10626ef17b27d9ad44e2760f98cfa3efb37924f0220220bd8acd43ecaa916a80bd4f919c495a2c58982ce7c8625153f8596692a801d",
			                  "30440220549e80b4496803cbc4a1d09d46df50109f546d43fbbf86cd90b174b1484acd5402205f12a4f995cb9bded597eabfee195a285986aa6d93ae5bb72507ebc6a4e2349e",
			                  "020000000001018154ecccf11a5fb56c39654c4deb4d2296f83c69268280b94d021370c94e219704000000000000000001a00f0000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e050047304402207e0410e45454b0978a623f36a10626ef17b27d9ad44e2760f98cfa3efb37924f0220220bd8acd43ecaa916a80bd4f919c495a2c58982ce7c8625153f8596692a801d014730440220549e80b4496803cbc4a1d09d46df50109f546d43fbbf86cd90b174b1484acd5402205f12a4f995cb9bded597eabfee195a285986aa6d93ae5bb72507ebc6a4e2349e012004040404040404040404040404040404040404040404040404040404040404048a76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a91418bc1a114ccf9c052d3d23e28d3b0a9d1227434288527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f801b175ac686800000000");
		}

		{
			// commitment tx with seven outputs untrimmed (maximum feerate)
			chan.value_to_self_msat = 6993000000; // 7000000000 - 7000000
			chan.feerate_per_kw = 647;

			test_commitment!("3045022100a5c01383d3ec646d97e40f44318d49def817fcd61a0ef18008a665b3e151785502203e648efddd5838981ef55ec954be69c4a652d021e6081a100d034de366815e9b",
			                 "304502210094bfd8f5572ac0157ec76a9551b6c5216a4538c07cd13a51af4a54cb26fa14320220768efce8ce6f4a5efac875142ff19237c011343670adf9c7ac69704a120d1163",
			                 "02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b8007e80300000000000022002052bfef0479d7b293c27e0f1eb294bea154c63a3294ef092c19af51409bce0e2ad007000000000000220020403d394747cae42e98ff01734ad5c08f82ba123d3d9a620abda88989651e2ab5d007000000000000220020748eba944fedc8827f6b06bc44678f93c0f9e6078b35c6331ed31e75f8ce0c2db80b000000000000220020c20b5d1f8584fd90443e7b7b720136174fa4b9333c261d04dbbd012635c0f419a00f0000000000002200208c48d15160397c9731df9bc3b236656efb6665fbfe92b4a6878e88a499f741c4c0c62d0000000000160014ccf1af2f2aabee14bb40fa3851ab2301de843110e09c6a00000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e040048304502210094bfd8f5572ac0157ec76a9551b6c5216a4538c07cd13a51af4a54cb26fa14320220768efce8ce6f4a5efac875142ff19237c011343670adf9c7ac69704a120d116301483045022100a5c01383d3ec646d97e40f44318d49def817fcd61a0ef18008a665b3e151785502203e648efddd5838981ef55ec954be69c4a652d021e6081a100d034de366815e9b01475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae3e195220");

			assert_eq!(unsigned_tx.1.len(), 5);

			test_htlc_output!(0,
			                  "30440220385a5afe75632f50128cbb029ee95c80156b5b4744beddc729ad339c9ca432c802202ba5f48550cad3379ac75b9b4fedb86a35baa6947f16ba5037fb8b11ab343740",
			                  "304402205999590b8a79fa346e003a68fd40366397119b2b0cdf37b149968d6bc6fbcc4702202b1e1fb5ab7864931caed4e732c359e0fe3d86a548b557be2246efb1708d579a",
			                  "020000000001018323148ce2419f21ca3d6780053747715832e18ac780931a514b187768882bb60000000000000000000122020000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e05004730440220385a5afe75632f50128cbb029ee95c80156b5b4744beddc729ad339c9ca432c802202ba5f48550cad3379ac75b9b4fedb86a35baa6947f16ba5037fb8b11ab3437400147304402205999590b8a79fa346e003a68fd40366397119b2b0cdf37b149968d6bc6fbcc4702202b1e1fb5ab7864931caed4e732c359e0fe3d86a548b557be2246efb1708d579a012000000000000000000000000000000000000000000000000000000000000000008a76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a914b8bcb07f6344b42ab04250c86a6e8b75d3fdbbc688527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f401b175ac686800000000");

			test_htlc_output!(1,
			                  "304402207ceb6678d4db33d2401fdc409959e57c16a6cb97a30261d9c61f29b8c58d34b90220084b4a17b4ca0e86f2d798b3698ca52de5621f2ce86f80bed79afa66874511b0",
			                  "304402207ff03eb0127fc7c6cae49cc29e2a586b98d1e8969cf4a17dfa50b9c2647720b902205e2ecfda2252956c0ca32f175080e75e4e390e433feb1f8ce9f2ba55648a1dac",
			                  "020000000001018323148ce2419f21ca3d6780053747715832e18ac780931a514b187768882bb60100000000000000000124060000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e050047304402207ceb6678d4db33d2401fdc409959e57c16a6cb97a30261d9c61f29b8c58d34b90220084b4a17b4ca0e86f2d798b3698ca52de5621f2ce86f80bed79afa66874511b00147304402207ff03eb0127fc7c6cae49cc29e2a586b98d1e8969cf4a17dfa50b9c2647720b902205e2ecfda2252956c0ca32f175080e75e4e390e433feb1f8ce9f2ba55648a1dac01008576a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a914b43e1b38138a41b37f7cd9a1d274bc63e3a9b5d188ac6868f6010000");

			test_htlc_output!(2,
			                  "304402206a401b29a0dff0d18ec903502c13d83e7ec019450113f4a7655a4ce40d1f65ba0220217723a084e727b6ca0cc8b6c69c014a7e4a01fcdcba3e3993f462a3c574d833",
			                  "3045022100d50d067ca625d54e62df533a8f9291736678d0b86c28a61bb2a80cf42e702d6e02202373dde7e00218eacdafb9415fe0e1071beec1857d1af3c6a201a44cbc47c877",
			                  "020000000001018323148ce2419f21ca3d6780053747715832e18ac780931a514b187768882bb6020000000000000000010a060000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e050047304402206a401b29a0dff0d18ec903502c13d83e7ec019450113f4a7655a4ce40d1f65ba0220217723a084e727b6ca0cc8b6c69c014a7e4a01fcdcba3e3993f462a3c574d83301483045022100d50d067ca625d54e62df533a8f9291736678d0b86c28a61bb2a80cf42e702d6e02202373dde7e00218eacdafb9415fe0e1071beec1857d1af3c6a201a44cbc47c877012001010101010101010101010101010101010101010101010101010101010101018a76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a9144b6b2e5444c2639cc0fb7bcea5afba3f3cdce23988527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f501b175ac686800000000");

			test_htlc_output!(3,
			                  "30450221009b1c987ba599ee3bde1dbca776b85481d70a78b681a8d84206723e2795c7cac002207aac84ad910f8598c4d1c0ea2e3399cf6627a4e3e90131315bc9f038451ce39d",
			                  "3045022100db9dc65291077a52728c622987e9895b7241d4394d6dcb916d7600a3e8728c22022036ee3ee717ba0bb5c45ee84bc7bbf85c0f90f26ae4e4a25a6b4241afa8a3f1cb",
			                  "020000000001018323148ce2419f21ca3d6780053747715832e18ac780931a514b187768882bb6030000000000000000010c0a0000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e05004830450221009b1c987ba599ee3bde1dbca776b85481d70a78b681a8d84206723e2795c7cac002207aac84ad910f8598c4d1c0ea2e3399cf6627a4e3e90131315bc9f038451ce39d01483045022100db9dc65291077a52728c622987e9895b7241d4394d6dcb916d7600a3e8728c22022036ee3ee717ba0bb5c45ee84bc7bbf85c0f90f26ae4e4a25a6b4241afa8a3f1cb01008576a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a9148a486ff2e31d6158bf39e2608864d63fefd09d5b88ac6868f7010000");

			test_htlc_output!(4,
			                  "3045022100cc28030b59f0914f45b84caa983b6f8effa900c952310708c2b5b00781117022022027ba2ccdf94d03c6d48b327f183f6e28c8a214d089b9227f94ac4f85315274f0",
			                  "304402202d1a3c0d31200265d2a2def2753ead4959ae20b4083e19553acfffa5dfab60bf022020ede134149504e15b88ab261a066de49848411e15e70f9e6a5462aec2949f8f",
			                  "020000000001018323148ce2419f21ca3d6780053747715832e18ac780931a514b187768882bb604000000000000000001da0d0000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0500483045022100cc28030b59f0914f45b84caa983b6f8effa900c952310708c2b5b00781117022022027ba2ccdf94d03c6d48b327f183f6e28c8a214d089b9227f94ac4f85315274f00147304402202d1a3c0d31200265d2a2def2753ead4959ae20b4083e19553acfffa5dfab60bf022020ede134149504e15b88ab261a066de49848411e15e70f9e6a5462aec2949f8f012004040404040404040404040404040404040404040404040404040404040404048a76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a91418bc1a114ccf9c052d3d23e28d3b0a9d1227434288527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f801b175ac686800000000");
		}

		{
			// commitment tx with six outputs untrimmed (minimum feerate)
			chan.value_to_self_msat = 6993000000; // 7000000000 - 7000000
			chan.feerate_per_kw = 648;

			test_commitment!("3044022072714e2fbb93cdd1c42eb0828b4f2eff143f717d8f26e79d6ada4f0dcb681bbe02200911be4e5161dd6ebe59ff1c58e1997c4aea804f81db6b698821db6093d7b057",
			                 "3045022100a2270d5950c89ae0841233f6efea9c951898b301b2e89e0adbd2c687b9f32efa02207943d90f95b9610458e7c65a576e149750ff3accaacad004cd85e70b235e27de",
			                 "02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b8006d007000000000000220020403d394747cae42e98ff01734ad5c08f82ba123d3d9a620abda88989651e2ab5d007000000000000220020748eba944fedc8827f6b06bc44678f93c0f9e6078b35c6331ed31e75f8ce0c2db80b000000000000220020c20b5d1f8584fd90443e7b7b720136174fa4b9333c261d04dbbd012635c0f419a00f0000000000002200208c48d15160397c9731df9bc3b236656efb6665fbfe92b4a6878e88a499f741c4c0c62d0000000000160014ccf1af2f2aabee14bb40fa3851ab2301de8431104e9d6a00000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0400483045022100a2270d5950c89ae0841233f6efea9c951898b301b2e89e0adbd2c687b9f32efa02207943d90f95b9610458e7c65a576e149750ff3accaacad004cd85e70b235e27de01473044022072714e2fbb93cdd1c42eb0828b4f2eff143f717d8f26e79d6ada4f0dcb681bbe02200911be4e5161dd6ebe59ff1c58e1997c4aea804f81db6b698821db6093d7b05701475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae3e195220");

			assert_eq!(unsigned_tx.1.len(), 4);

			test_htlc_output!(0,
			                  "3044022062ef2e77591409d60d7817d9bb1e71d3c4a2931d1a6c7c8307422c84f001a251022022dad9726b0ae3fe92bda745a06f2c00f92342a186d84518588cf65f4dfaada8",
			                  "3045022100a4c574f00411dd2f978ca5cdc1b848c311cd7849c087ad2f21a5bce5e8cc5ae90220090ae39a9bce2fb8bc879d7e9f9022df249f41e25e51f1a9bf6447a9eeffc098",
			                  "02000000000101579c183eca9e8236a5d7f5dcd79cfec32c497fdc0ec61533cde99ecd436cadd10000000000000000000123060000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0500473044022062ef2e77591409d60d7817d9bb1e71d3c4a2931d1a6c7c8307422c84f001a251022022dad9726b0ae3fe92bda745a06f2c00f92342a186d84518588cf65f4dfaada801483045022100a4c574f00411dd2f978ca5cdc1b848c311cd7849c087ad2f21a5bce5e8cc5ae90220090ae39a9bce2fb8bc879d7e9f9022df249f41e25e51f1a9bf6447a9eeffc09801008576a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a914b43e1b38138a41b37f7cd9a1d274bc63e3a9b5d188ac6868f6010000");

			test_htlc_output!(1,
			                  "3045022100e968cbbb5f402ed389fdc7f6cd2a80ed650bb42c79aeb2a5678444af94f6c78502204b47a1cb24ab5b0b6fe69fe9cfc7dba07b9dd0d8b95f372c1d9435146a88f8d4",
			                  "304402207679cf19790bea76a733d2fa0672bd43ab455687a068f815a3d237581f57139a0220683a1a799e102071c206b207735ca80f627ab83d6616b4bcd017c5d79ef3e7d0",
			                  "02000000000101579c183eca9e8236a5d7f5dcd79cfec32c497fdc0ec61533cde99ecd436cadd10100000000000000000109060000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0500483045022100e968cbbb5f402ed389fdc7f6cd2a80ed650bb42c79aeb2a5678444af94f6c78502204b47a1cb24ab5b0b6fe69fe9cfc7dba07b9dd0d8b95f372c1d9435146a88f8d40147304402207679cf19790bea76a733d2fa0672bd43ab455687a068f815a3d237581f57139a0220683a1a799e102071c206b207735ca80f627ab83d6616b4bcd017c5d79ef3e7d0012001010101010101010101010101010101010101010101010101010101010101018a76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a9144b6b2e5444c2639cc0fb7bcea5afba3f3cdce23988527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f501b175ac686800000000");

			test_htlc_output!(2,
			                  "3045022100aa91932e305292cf9969cc23502bbf6cef83a5df39c95ad04a707c4f4fed5c7702207099fc0f3a9bfe1e7683c0e9aa5e76c5432eb20693bf4cb182f04d383dc9c8c2",
			                  "304402200df76fea718745f3c529bac7fd37923e7309ce38b25c0781e4cf514dd9ef8dc802204172295739dbae9fe0474dcee3608e3433b4b2af3a2e6787108b02f894dcdda3",
			                  "02000000000101579c183eca9e8236a5d7f5dcd79cfec32c497fdc0ec61533cde99ecd436cadd1020000000000000000010b0a0000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0500483045022100aa91932e305292cf9969cc23502bbf6cef83a5df39c95ad04a707c4f4fed5c7702207099fc0f3a9bfe1e7683c0e9aa5e76c5432eb20693bf4cb182f04d383dc9c8c20147304402200df76fea718745f3c529bac7fd37923e7309ce38b25c0781e4cf514dd9ef8dc802204172295739dbae9fe0474dcee3608e3433b4b2af3a2e6787108b02f894dcdda301008576a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a9148a486ff2e31d6158bf39e2608864d63fefd09d5b88ac6868f7010000");

			test_htlc_output!(3,
			                  "3044022035cac88040a5bba420b1c4257235d5015309113460bc33f2853cd81ca36e632402202fc94fd3e81e9d34a9d01782a0284f3044370d03d60f3fc041e2da088d2de58f",
			                  "304402200daf2eb7afd355b4caf6fb08387b5f031940ea29d1a9f35071288a839c9039e4022067201b562456e7948616c13acb876b386b511599b58ac1d94d127f91c50463a6",
			                  "02000000000101579c183eca9e8236a5d7f5dcd79cfec32c497fdc0ec61533cde99ecd436cadd103000000000000000001d90d0000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0500473044022035cac88040a5bba420b1c4257235d5015309113460bc33f2853cd81ca36e632402202fc94fd3e81e9d34a9d01782a0284f3044370d03d60f3fc041e2da088d2de58f0147304402200daf2eb7afd355b4caf6fb08387b5f031940ea29d1a9f35071288a839c9039e4022067201b562456e7948616c13acb876b386b511599b58ac1d94d127f91c50463a6012004040404040404040404040404040404040404040404040404040404040404048a76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a91418bc1a114ccf9c052d3d23e28d3b0a9d1227434288527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f801b175ac686800000000");
		}

		{
			// commitment tx with six outputs untrimmed (maximum feerate)
			chan.value_to_self_msat = 6993000000; // 7000000000 - 7000000
			chan.feerate_per_kw = 2069;

			test_commitment!("3044022001d55e488b8b035b2dd29d50b65b530923a416d47f377284145bc8767b1b6a75022019bb53ddfe1cefaf156f924777eaaf8fdca1810695a7d0a247ad2afba8232eb4",
			                 "304402203ca8f31c6a47519f83255dc69f1894d9a6d7476a19f498d31eaf0cd3a85eeb63022026fd92dc752b33905c4c838c528b692a8ad4ced959990b5d5ee2ff940fa90eea",
			                 "02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b8006d007000000000000220020403d394747cae42e98ff01734ad5c08f82ba123d3d9a620abda88989651e2ab5d007000000000000220020748eba944fedc8827f6b06bc44678f93c0f9e6078b35c6331ed31e75f8ce0c2db80b000000000000220020c20b5d1f8584fd90443e7b7b720136174fa4b9333c261d04dbbd012635c0f419a00f0000000000002200208c48d15160397c9731df9bc3b236656efb6665fbfe92b4a6878e88a499f741c4c0c62d0000000000160014ccf1af2f2aabee14bb40fa3851ab2301de84311077956a00000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e040047304402203ca8f31c6a47519f83255dc69f1894d9a6d7476a19f498d31eaf0cd3a85eeb63022026fd92dc752b33905c4c838c528b692a8ad4ced959990b5d5ee2ff940fa90eea01473044022001d55e488b8b035b2dd29d50b65b530923a416d47f377284145bc8767b1b6a75022019bb53ddfe1cefaf156f924777eaaf8fdca1810695a7d0a247ad2afba8232eb401475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae3e195220");

			assert_eq!(unsigned_tx.1.len(), 4);

			test_htlc_output!(0,
			                  "3045022100d1cf354de41c1369336cf85b225ed033f1f8982a01be503668df756a7e668b66022001254144fb4d0eecc61908fccc3388891ba17c5d7a1a8c62bdd307e5a513f992",
			                  "3044022056eb1af429660e45a1b0b66568cb8c4a3aa7e4c9c292d5d6c47f86ebf2c8838f022065c3ac4ebe980ca7a41148569be4ad8751b0a724a41405697ec55035dae66402",
			                  "02000000000101ca94a9ad516ebc0c4bdd7b6254871babfa978d5accafb554214137d398bfcf6a0000000000000000000175020000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0500483045022100d1cf354de41c1369336cf85b225ed033f1f8982a01be503668df756a7e668b66022001254144fb4d0eecc61908fccc3388891ba17c5d7a1a8c62bdd307e5a513f99201473044022056eb1af429660e45a1b0b66568cb8c4a3aa7e4c9c292d5d6c47f86ebf2c8838f022065c3ac4ebe980ca7a41148569be4ad8751b0a724a41405697ec55035dae6640201008576a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a914b43e1b38138a41b37f7cd9a1d274bc63e3a9b5d188ac6868f6010000");

			test_htlc_output!(1,
			                  "3045022100d065569dcb94f090345402736385efeb8ea265131804beac06dd84d15dd2d6880220664feb0b4b2eb985fadb6ec7dc58c9334ea88ce599a9be760554a2d4b3b5d9f4",
			                  "3045022100914bb232cd4b2690ee3d6cb8c3713c4ac9c4fb925323068d8b07f67c8541f8d9022057152f5f1615b793d2d45aac7518989ae4fe970f28b9b5c77504799d25433f7f",
			                  "02000000000101ca94a9ad516ebc0c4bdd7b6254871babfa978d5accafb554214137d398bfcf6a0100000000000000000122020000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0500483045022100d065569dcb94f090345402736385efeb8ea265131804beac06dd84d15dd2d6880220664feb0b4b2eb985fadb6ec7dc58c9334ea88ce599a9be760554a2d4b3b5d9f401483045022100914bb232cd4b2690ee3d6cb8c3713c4ac9c4fb925323068d8b07f67c8541f8d9022057152f5f1615b793d2d45aac7518989ae4fe970f28b9b5c77504799d25433f7f012001010101010101010101010101010101010101010101010101010101010101018a76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a9144b6b2e5444c2639cc0fb7bcea5afba3f3cdce23988527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f501b175ac686800000000");

			test_htlc_output!(2,
			                  "3045022100d4e69d363de993684eae7b37853c40722a4c1b4a7b588ad7b5d8a9b5006137a102207a069c628170ee34be5612747051bdcc087466dbaa68d5756ea81c10155aef18",
			                  "304402200e362443f7af830b419771e8e1614fc391db3a4eb799989abfc5ab26d6fcd032022039ab0cad1c14dfbe9446bf847965e56fe016e0cbcf719fd18c1bfbf53ecbd9f9",
			                  "02000000000101ca94a9ad516ebc0c4bdd7b6254871babfa978d5accafb554214137d398bfcf6a020000000000000000015d060000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0500483045022100d4e69d363de993684eae7b37853c40722a4c1b4a7b588ad7b5d8a9b5006137a102207a069c628170ee34be5612747051bdcc087466dbaa68d5756ea81c10155aef180147304402200e362443f7af830b419771e8e1614fc391db3a4eb799989abfc5ab26d6fcd032022039ab0cad1c14dfbe9446bf847965e56fe016e0cbcf719fd18c1bfbf53ecbd9f901008576a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a9148a486ff2e31d6158bf39e2608864d63fefd09d5b88ac6868f7010000");

			test_htlc_output!(3,
			                  "30450221008ec888e36e4a4b3dc2ed6b823319855b2ae03006ca6ae0d9aa7e24bfc1d6f07102203b0f78885472a67ff4fe5916c0bb669487d659527509516fc3a08e87a2cc0a7c",
			                  "304402202c3e14282b84b02705dfd00a6da396c9fe8a8bcb1d3fdb4b20a4feba09440e8b02202b058b39aa9b0c865b22095edcd9ff1f71bbfe20aa4993755e54d042755ed0d5",
			                  "02000000000101ca94a9ad516ebc0c4bdd7b6254871babfa978d5accafb554214137d398bfcf6a03000000000000000001f2090000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e05004830450221008ec888e36e4a4b3dc2ed6b823319855b2ae03006ca6ae0d9aa7e24bfc1d6f07102203b0f78885472a67ff4fe5916c0bb669487d659527509516fc3a08e87a2cc0a7c0147304402202c3e14282b84b02705dfd00a6da396c9fe8a8bcb1d3fdb4b20a4feba09440e8b02202b058b39aa9b0c865b22095edcd9ff1f71bbfe20aa4993755e54d042755ed0d5012004040404040404040404040404040404040404040404040404040404040404048a76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a91418bc1a114ccf9c052d3d23e28d3b0a9d1227434288527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f801b175ac686800000000");
		}

		{
			// commitment tx with five outputs untrimmed (minimum feerate)
			chan.value_to_self_msat = 6993000000; // 7000000000 - 7000000
			chan.feerate_per_kw = 2070;

			test_commitment!("3045022100f2377f7a67b7fc7f4e2c0c9e3a7de935c32417f5668eda31ea1db401b7dc53030220415fdbc8e91d0f735e70c21952342742e25249b0d062d43efbfc564499f37526",
			                 "30440220443cb07f650aebbba14b8bc8d81e096712590f524c5991ac0ed3bbc8fd3bd0c7022028a635f548e3ca64b19b69b1ea00f05b22752f91daf0b6dab78e62ba52eb7fd0",
			                 "02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b8005d007000000000000220020403d394747cae42e98ff01734ad5c08f82ba123d3d9a620abda88989651e2ab5b80b000000000000220020c20b5d1f8584fd90443e7b7b720136174fa4b9333c261d04dbbd012635c0f419a00f0000000000002200208c48d15160397c9731df9bc3b236656efb6665fbfe92b4a6878e88a499f741c4c0c62d0000000000160014ccf1af2f2aabee14bb40fa3851ab2301de843110da966a00000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e04004730440220443cb07f650aebbba14b8bc8d81e096712590f524c5991ac0ed3bbc8fd3bd0c7022028a635f548e3ca64b19b69b1ea00f05b22752f91daf0b6dab78e62ba52eb7fd001483045022100f2377f7a67b7fc7f4e2c0c9e3a7de935c32417f5668eda31ea1db401b7dc53030220415fdbc8e91d0f735e70c21952342742e25249b0d062d43efbfc564499f3752601475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae3e195220");

			assert_eq!(unsigned_tx.1.len(), 3);

			test_htlc_output!(0,
			                  "3045022100eed143b1ee4bed5dc3cde40afa5db3e7354cbf9c44054b5f713f729356f08cf7022077161d171c2bbd9badf3c9934de65a4918de03bbac1450f715275f75b103f891",
			                  "3045022100a0d043ed533e7fb1911e0553d31a8e2f3e6de19dbc035257f29d747c5e02f1f5022030cd38d8e84282175d49c1ebe0470db3ebd59768cf40780a784e248a43904fb8",
			                  "0200000000010140a83ce364747ff277f4d7595d8d15f708418798922c40bc2b056aca5485a2180000000000000000000174020000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0500483045022100eed143b1ee4bed5dc3cde40afa5db3e7354cbf9c44054b5f713f729356f08cf7022077161d171c2bbd9badf3c9934de65a4918de03bbac1450f715275f75b103f89101483045022100a0d043ed533e7fb1911e0553d31a8e2f3e6de19dbc035257f29d747c5e02f1f5022030cd38d8e84282175d49c1ebe0470db3ebd59768cf40780a784e248a43904fb801008576a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a914b43e1b38138a41b37f7cd9a1d274bc63e3a9b5d188ac6868f6010000");

			test_htlc_output!(1,
			                  "3044022071e9357619fd8d29a411dc053b326a5224c5d11268070e88ecb981b174747c7a02202b763ae29a9d0732fa8836dd8597439460b50472183f420021b768981b4f7cf6",
			                  "3045022100adb1d679f65f96178b59f23ed37d3b70443118f345224a07ecb043eee2acc157022034d24524fe857144a3bcfff3065a9994d0a6ec5f11c681e49431d573e242612d",
			                  "0200000000010140a83ce364747ff277f4d7595d8d15f708418798922c40bc2b056aca5485a218010000000000000000015c060000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0500473044022071e9357619fd8d29a411dc053b326a5224c5d11268070e88ecb981b174747c7a02202b763ae29a9d0732fa8836dd8597439460b50472183f420021b768981b4f7cf601483045022100adb1d679f65f96178b59f23ed37d3b70443118f345224a07ecb043eee2acc157022034d24524fe857144a3bcfff3065a9994d0a6ec5f11c681e49431d573e242612d01008576a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a9148a486ff2e31d6158bf39e2608864d63fefd09d5b88ac6868f7010000");

			test_htlc_output!(2,
			                  "3045022100c9458a4d2cbb741705577deb0a890e5cb90ee141be0400d3162e533727c9cb2102206edcf765c5dc5e5f9b976ea8149bf8607b5a0efb30691138e1231302b640d2a4",
			                  "304402200831422aa4e1ee6d55e0b894201770a8f8817a189356f2d70be76633ffa6a6f602200dd1b84a4855dc6727dd46c98daae43dfc70889d1ba7ef0087529a57c06e5e04",
			                  "0200000000010140a83ce364747ff277f4d7595d8d15f708418798922c40bc2b056aca5485a21802000000000000000001f1090000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0500483045022100c9458a4d2cbb741705577deb0a890e5cb90ee141be0400d3162e533727c9cb2102206edcf765c5dc5e5f9b976ea8149bf8607b5a0efb30691138e1231302b640d2a40147304402200831422aa4e1ee6d55e0b894201770a8f8817a189356f2d70be76633ffa6a6f602200dd1b84a4855dc6727dd46c98daae43dfc70889d1ba7ef0087529a57c06e5e04012004040404040404040404040404040404040404040404040404040404040404048a76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a91418bc1a114ccf9c052d3d23e28d3b0a9d1227434288527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f801b175ac686800000000");
		}

		{
			// commitment tx with five outputs untrimmed (maximum feerate)
			chan.value_to_self_msat = 6993000000; // 7000000000 - 7000000
			chan.feerate_per_kw = 2194;

			test_commitment!("3045022100d33c4e541aa1d255d41ea9a3b443b3b822ad8f7f86862638aac1f69f8f760577022007e2a18e6931ce3d3a804b1c78eda1de17dbe1fb7a95488c9a4ec86203953348",
			                 "304402203b1b010c109c2ecbe7feb2d259b9c4126bd5dc99ee693c422ec0a5781fe161ba0220571fe4e2c649dea9c7aaf7e49b382962f6a3494963c97d80fef9a430ca3f7061",
			                 "02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b8005d007000000000000220020403d394747cae42e98ff01734ad5c08f82ba123d3d9a620abda88989651e2ab5b80b000000000000220020c20b5d1f8584fd90443e7b7b720136174fa4b9333c261d04dbbd012635c0f419a00f0000000000002200208c48d15160397c9731df9bc3b236656efb6665fbfe92b4a6878e88a499f741c4c0c62d0000000000160014ccf1af2f2aabee14bb40fa3851ab2301de84311040966a00000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e040047304402203b1b010c109c2ecbe7feb2d259b9c4126bd5dc99ee693c422ec0a5781fe161ba0220571fe4e2c649dea9c7aaf7e49b382962f6a3494963c97d80fef9a430ca3f706101483045022100d33c4e541aa1d255d41ea9a3b443b3b822ad8f7f86862638aac1f69f8f760577022007e2a18e6931ce3d3a804b1c78eda1de17dbe1fb7a95488c9a4ec8620395334801475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae3e195220");

			assert_eq!(unsigned_tx.1.len(), 3);

			test_htlc_output!(0,
			                  "30450221009ed2f0a67f99e29c3c8cf45c08207b765980697781bb727fe0b1416de0e7622902206052684229bc171419ed290f4b615c943f819c0262414e43c5b91dcf72ddcf44",
			                  "3044022004ad5f04ae69c71b3b141d4db9d0d4c38d84009fb3cfeeae6efdad414487a9a0022042d3fe1388c1ff517d1da7fb4025663d372c14728ed52dc88608363450ff6a2f",
			                  "02000000000101fb824d4e4dafc0f567789dee3a6bce8d411fe80f5563d8cdfdcc7d7e4447d43a0000000000000000000122020000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e05004830450221009ed2f0a67f99e29c3c8cf45c08207b765980697781bb727fe0b1416de0e7622902206052684229bc171419ed290f4b615c943f819c0262414e43c5b91dcf72ddcf4401473044022004ad5f04ae69c71b3b141d4db9d0d4c38d84009fb3cfeeae6efdad414487a9a0022042d3fe1388c1ff517d1da7fb4025663d372c14728ed52dc88608363450ff6a2f01008576a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a914b43e1b38138a41b37f7cd9a1d274bc63e3a9b5d188ac6868f6010000");

			test_htlc_output!(1,
			                  "30440220155d3b90c67c33a8321996a9be5b82431b0c126613be751d400669da9d5c696702204318448bcd48824439d2c6a70be6e5747446be47ff45977cf41672bdc9b6b12d",
			                  "304402201707050c870c1f77cc3ed58d6d71bf281de239e9eabd8ef0955bad0d7fe38dcc02204d36d80d0019b3a71e646a08fa4a5607761d341ae8be371946ebe437c289c915",
			                  "02000000000101fb824d4e4dafc0f567789dee3a6bce8d411fe80f5563d8cdfdcc7d7e4447d43a010000000000000000010a060000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e05004730440220155d3b90c67c33a8321996a9be5b82431b0c126613be751d400669da9d5c696702204318448bcd48824439d2c6a70be6e5747446be47ff45977cf41672bdc9b6b12d0147304402201707050c870c1f77cc3ed58d6d71bf281de239e9eabd8ef0955bad0d7fe38dcc02204d36d80d0019b3a71e646a08fa4a5607761d341ae8be371946ebe437c289c91501008576a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a9148a486ff2e31d6158bf39e2608864d63fefd09d5b88ac6868f7010000");

			test_htlc_output!(2,
			                  "3045022100a12a9a473ece548584aabdd051779025a5ed4077c4b7aa376ec7a0b1645e5a48022039490b333f53b5b3e2ddde1d809e492cba2b3e5fc3a436cd3ffb4cd3d500fa5a",
			                  "3045022100ff200bc934ab26ce9a559e998ceb0aee53bc40368e114ab9d3054d9960546e2802202496856ca163ac12c143110b6b3ac9d598df7254f2e17b3b94c3ab5301f4c3b0",
			                  "02000000000101fb824d4e4dafc0f567789dee3a6bce8d411fe80f5563d8cdfdcc7d7e4447d43a020000000000000000019a090000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0500483045022100a12a9a473ece548584aabdd051779025a5ed4077c4b7aa376ec7a0b1645e5a48022039490b333f53b5b3e2ddde1d809e492cba2b3e5fc3a436cd3ffb4cd3d500fa5a01483045022100ff200bc934ab26ce9a559e998ceb0aee53bc40368e114ab9d3054d9960546e2802202496856ca163ac12c143110b6b3ac9d598df7254f2e17b3b94c3ab5301f4c3b0012004040404040404040404040404040404040404040404040404040404040404048a76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a91418bc1a114ccf9c052d3d23e28d3b0a9d1227434288527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f801b175ac686800000000");
		}

		{
			// commitment tx with four outputs untrimmed (minimum feerate)
			chan.value_to_self_msat = 6993000000; // 7000000000 - 7000000
			chan.feerate_per_kw = 2195;

			test_commitment!("304402205e2f76d4657fb732c0dfc820a18a7301e368f5799e06b7828007633741bda6df0220458009ae59d0c6246065c419359e05eb2a4b4ef4a1b310cc912db44eb7924298",
			                 "304402203b12d44254244b8ff3bb4129b0920fd45120ab42f553d9976394b099d500c99e02205e95bb7a3164852ef0c48f9e0eaf145218f8e2c41251b231f03cbdc4f29a5429",
			                 "02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b8004b80b000000000000220020c20b5d1f8584fd90443e7b7b720136174fa4b9333c261d04dbbd012635c0f419a00f0000000000002200208c48d15160397c9731df9bc3b236656efb6665fbfe92b4a6878e88a499f741c4c0c62d0000000000160014ccf1af2f2aabee14bb40fa3851ab2301de843110b8976a00000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e040047304402203b12d44254244b8ff3bb4129b0920fd45120ab42f553d9976394b099d500c99e02205e95bb7a3164852ef0c48f9e0eaf145218f8e2c41251b231f03cbdc4f29a54290147304402205e2f76d4657fb732c0dfc820a18a7301e368f5799e06b7828007633741bda6df0220458009ae59d0c6246065c419359e05eb2a4b4ef4a1b310cc912db44eb792429801475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae3e195220");

			assert_eq!(unsigned_tx.1.len(), 2);

			test_htlc_output!(0,
			                  "3045022100a8a78fa1016a5c5c3704f2e8908715a3cef66723fb95f3132ec4d2d05cd84fb4022025ac49287b0861ec21932405f5600cbce94313dbde0e6c5d5af1b3366d8afbfc",
			                  "3045022100be6ae1977fd7b630a53623f3f25c542317ccfc2b971782802a4f1ef538eb22b402207edc4d0408f8f38fd3c7365d1cfc26511b7cd2d4fecd8b005fba3cd5bc704390",
			                  "020000000001014e16c488fa158431c1a82e8f661240ec0a71ba0ce92f2721a6538c510226ad5c0000000000000000000109060000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0500483045022100a8a78fa1016a5c5c3704f2e8908715a3cef66723fb95f3132ec4d2d05cd84fb4022025ac49287b0861ec21932405f5600cbce94313dbde0e6c5d5af1b3366d8afbfc01483045022100be6ae1977fd7b630a53623f3f25c542317ccfc2b971782802a4f1ef538eb22b402207edc4d0408f8f38fd3c7365d1cfc26511b7cd2d4fecd8b005fba3cd5bc70439001008576a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a9148a486ff2e31d6158bf39e2608864d63fefd09d5b88ac6868f7010000");

			test_htlc_output!(1,
			                  "3045022100e769cb156aa2f7515d126cef7a69968629620ce82afcaa9e210969de6850df4602200b16b3f3486a229a48aadde520dbee31ae340dbadaffae74fbb56681fef27b92",
			                  "30440220665b9cb4a978c09d1ca8977a534999bc8a49da624d0c5439451dd69cde1a003d022070eae0620f01f3c1bd029cc1488da13fb40fdab76f396ccd335479a11c5276d8",
			                  "020000000001014e16c488fa158431c1a82e8f661240ec0a71ba0ce92f2721a6538c510226ad5c0100000000000000000199090000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0500483045022100e769cb156aa2f7515d126cef7a69968629620ce82afcaa9e210969de6850df4602200b16b3f3486a229a48aadde520dbee31ae340dbadaffae74fbb56681fef27b92014730440220665b9cb4a978c09d1ca8977a534999bc8a49da624d0c5439451dd69cde1a003d022070eae0620f01f3c1bd029cc1488da13fb40fdab76f396ccd335479a11c5276d8012004040404040404040404040404040404040404040404040404040404040404048a76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a91418bc1a114ccf9c052d3d23e28d3b0a9d1227434288527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f801b175ac686800000000");
		}

		{
			// commitment tx with four outputs untrimmed (maximum feerate)
			chan.value_to_self_msat = 6993000000; // 7000000000 - 7000000
			chan.feerate_per_kw = 3702;

			test_commitment!("3045022100c1a3b0b60ca092ed5080121f26a74a20cec6bdee3f8e47bae973fcdceb3eda5502207d467a9873c939bf3aa758014ae67295fedbca52412633f7e5b2670fc7c381c1",
			                 "304402200e930a43c7951162dc15a2b7344f48091c74c70f7024e7116e900d8bcfba861c022066fa6cbda3929e21daa2e7e16a4b948db7e8919ef978402360d1095ffdaff7b0",
			                 "02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b8004b80b000000000000220020c20b5d1f8584fd90443e7b7b720136174fa4b9333c261d04dbbd012635c0f419a00f0000000000002200208c48d15160397c9731df9bc3b236656efb6665fbfe92b4a6878e88a499f741c4c0c62d0000000000160014ccf1af2f2aabee14bb40fa3851ab2301de8431106f916a00000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e040047304402200e930a43c7951162dc15a2b7344f48091c74c70f7024e7116e900d8bcfba861c022066fa6cbda3929e21daa2e7e16a4b948db7e8919ef978402360d1095ffdaff7b001483045022100c1a3b0b60ca092ed5080121f26a74a20cec6bdee3f8e47bae973fcdceb3eda5502207d467a9873c939bf3aa758014ae67295fedbca52412633f7e5b2670fc7c381c101475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae3e195220");

			assert_eq!(unsigned_tx.1.len(), 2);

			test_htlc_output!(0,
			                  "3045022100dfb73b4fe961b31a859b2bb1f4f15cabab9265016dd0272323dc6a9e85885c54022059a7b87c02861ee70662907f25ce11597d7b68d3399443a831ae40e777b76bdb",
			                  "304402202765b9c9ece4f127fa5407faf66da4c5ce2719cdbe47cd3175fc7d48b482e43d02205605125925e07bad1e41c618a4b434d72c88a164981c4b8af5eaf4ee9142ec3a",
			                  "02000000000101b8de11eb51c22498fe39722c7227b6e55ff1a94146cf638458cb9bc6a060d3a30000000000000000000122020000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0500483045022100dfb73b4fe961b31a859b2bb1f4f15cabab9265016dd0272323dc6a9e85885c54022059a7b87c02861ee70662907f25ce11597d7b68d3399443a831ae40e777b76bdb0147304402202765b9c9ece4f127fa5407faf66da4c5ce2719cdbe47cd3175fc7d48b482e43d02205605125925e07bad1e41c618a4b434d72c88a164981c4b8af5eaf4ee9142ec3a01008576a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a9148a486ff2e31d6158bf39e2608864d63fefd09d5b88ac6868f7010000");

			test_htlc_output!(1,
			                  "3045022100ea9dc2a7c3c3640334dab733bb4e036e32a3106dc707b24227874fa4f7da746802204d672f7ac0fe765931a8df10b81e53a3242dd32bd9dc9331eb4a596da87954e9",
			                  "30440220048a41c660c4841693de037d00a407810389f4574b3286afb7bc392a438fa3f802200401d71fa87c64fe621b49ac07e3bf85157ac680acb977124da28652cc7f1a5c",
			                  "02000000000101b8de11eb51c22498fe39722c7227b6e55ff1a94146cf638458cb9bc6a060d3a30100000000000000000176050000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0500483045022100ea9dc2a7c3c3640334dab733bb4e036e32a3106dc707b24227874fa4f7da746802204d672f7ac0fe765931a8df10b81e53a3242dd32bd9dc9331eb4a596da87954e9014730440220048a41c660c4841693de037d00a407810389f4574b3286afb7bc392a438fa3f802200401d71fa87c64fe621b49ac07e3bf85157ac680acb977124da28652cc7f1a5c012004040404040404040404040404040404040404040404040404040404040404048a76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a91418bc1a114ccf9c052d3d23e28d3b0a9d1227434288527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f801b175ac686800000000");
		}

		{
			// commitment tx with three outputs untrimmed (minimum feerate)
			chan.value_to_self_msat = 6993000000; // 7000000000 - 7000000
			chan.feerate_per_kw = 3703;

			test_commitment!("30450221008b7c191dd46893b67b628e618d2dc8e81169d38bade310181ab77d7c94c6675e02203b4dd131fd7c9deb299560983dcdc485545c98f989f7ae8180c28289f9e6bdb0",
			                 "3044022047305531dd44391dce03ae20f8735005c615eb077a974edb0059ea1a311857d602202e0ed6972fbdd1e8cb542b06e0929bc41b2ddf236e04cb75edd56151f4197506",
			                 "02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b8003a00f0000000000002200208c48d15160397c9731df9bc3b236656efb6665fbfe92b4a6878e88a499f741c4c0c62d0000000000160014ccf1af2f2aabee14bb40fa3851ab2301de843110eb936a00000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0400473044022047305531dd44391dce03ae20f8735005c615eb077a974edb0059ea1a311857d602202e0ed6972fbdd1e8cb542b06e0929bc41b2ddf236e04cb75edd56151f4197506014830450221008b7c191dd46893b67b628e618d2dc8e81169d38bade310181ab77d7c94c6675e02203b4dd131fd7c9deb299560983dcdc485545c98f989f7ae8180c28289f9e6bdb001475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae3e195220");

			assert_eq!(unsigned_tx.1.len(), 1);

			test_htlc_output!(0,
			                  "3044022044f65cf833afdcb9d18795ca93f7230005777662539815b8a601eeb3e57129a902206a4bf3e53392affbba52640627defa8dc8af61c958c9e827b2798ab45828abdd",
			                  "3045022100b94d931a811b32eeb885c28ddcf999ae1981893b21dd1329929543fe87ce793002206370107fdd151c5f2384f9ceb71b3107c69c74c8ed5a28a94a4ab2d27d3b0724",
			                  "020000000001011c076aa7fb3d7460d10df69432c904227ea84bbf3134d4ceee5fb0f135ef206d0000000000000000000175050000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0500473044022044f65cf833afdcb9d18795ca93f7230005777662539815b8a601eeb3e57129a902206a4bf3e53392affbba52640627defa8dc8af61c958c9e827b2798ab45828abdd01483045022100b94d931a811b32eeb885c28ddcf999ae1981893b21dd1329929543fe87ce793002206370107fdd151c5f2384f9ceb71b3107c69c74c8ed5a28a94a4ab2d27d3b0724012004040404040404040404040404040404040404040404040404040404040404048a76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a91418bc1a114ccf9c052d3d23e28d3b0a9d1227434288527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f801b175ac686800000000");
		}

		{
			// commitment tx with three outputs untrimmed (maximum feerate)
			chan.value_to_self_msat = 6993000000; // 7000000000 - 7000000
			chan.feerate_per_kw = 4914;

			test_commitment!("304402206d6cb93969d39177a09d5d45b583f34966195b77c7e585cf47ac5cce0c90cefb022031d71ae4e33a4e80df7f981d696fbdee517337806a3c7138b7491e2cbb077a0e",
			                 "304402206a2679efa3c7aaffd2a447fd0df7aba8792858b589750f6a1203f9259173198a022008d52a0e77a99ab533c36206cb15ad7aeb2aa72b93d4b571e728cb5ec2f6fe26",
			                 "02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b8003a00f0000000000002200208c48d15160397c9731df9bc3b236656efb6665fbfe92b4a6878e88a499f741c4c0c62d0000000000160014ccf1af2f2aabee14bb40fa3851ab2301de843110ae8f6a00000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e040047304402206a2679efa3c7aaffd2a447fd0df7aba8792858b589750f6a1203f9259173198a022008d52a0e77a99ab533c36206cb15ad7aeb2aa72b93d4b571e728cb5ec2f6fe260147304402206d6cb93969d39177a09d5d45b583f34966195b77c7e585cf47ac5cce0c90cefb022031d71ae4e33a4e80df7f981d696fbdee517337806a3c7138b7491e2cbb077a0e01475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae3e195220");

			assert_eq!(unsigned_tx.1.len(), 1);

			test_htlc_output!(0,
			                  "3045022100fcb38506bfa11c02874092a843d0cc0a8613c23b639832564a5f69020cb0f6ba02206508b9e91eaa001425c190c68ee5f887e1ad5b1b314002e74db9dbd9e42dbecf",
			                  "304502210086e76b460ddd3cea10525fba298405d3fe11383e56966a5091811368362f689a02200f72ee75657915e0ede89c28709acd113ede9e1b7be520e3bc5cda425ecd6e68",
			                  "0200000000010110a3fdcbcd5db477cd3ad465e7f501ffa8c437e8301f00a6061138590add757f0000000000000000000122020000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0500483045022100fcb38506bfa11c02874092a843d0cc0a8613c23b639832564a5f69020cb0f6ba02206508b9e91eaa001425c190c68ee5f887e1ad5b1b314002e74db9dbd9e42dbecf0148304502210086e76b460ddd3cea10525fba298405d3fe11383e56966a5091811368362f689a02200f72ee75657915e0ede89c28709acd113ede9e1b7be520e3bc5cda425ecd6e68012004040404040404040404040404040404040404040404040404040404040404048a76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a91418bc1a114ccf9c052d3d23e28d3b0a9d1227434288527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f801b175ac686800000000");
		}

		{
			// commitment tx with two outputs untrimmed (minimum feerate)
			chan.value_to_self_msat = 6993000000; // 7000000000 - 7000000
			chan.feerate_per_kw = 4915;

			test_commitment!("304402200769ba89c7330dfa4feba447b6e322305f12ac7dac70ec6ba997ed7c1b598d0802204fe8d337e7fee781f9b7b1a06e580b22f4f79d740059560191d7db53f8765552",
			                 "3045022100a012691ba6cea2f73fa8bac37750477e66363c6d28813b0bb6da77c8eb3fb0270220365e99c51304b0b1a6ab9ea1c8500db186693e39ec1ad5743ee231b0138384b9",
			                 "02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b8002c0c62d0000000000160014ccf1af2f2aabee14bb40fa3851ab2301de843110fa926a00000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0400483045022100a012691ba6cea2f73fa8bac37750477e66363c6d28813b0bb6da77c8eb3fb0270220365e99c51304b0b1a6ab9ea1c8500db186693e39ec1ad5743ee231b0138384b90147304402200769ba89c7330dfa4feba447b6e322305f12ac7dac70ec6ba997ed7c1b598d0802204fe8d337e7fee781f9b7b1a06e580b22f4f79d740059560191d7db53f876555201475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae3e195220");

			assert_eq!(unsigned_tx.1.len(), 0);
		}

		{
			// commitment tx with two outputs untrimmed (maximum feerate)
			chan.value_to_self_msat = 6993000000; // 7000000000 - 7000000
			chan.feerate_per_kw = 9651180;

			test_commitment!("3044022037f83ff00c8e5fb18ae1f918ffc24e54581775a20ff1ae719297ef066c71caa9022039c529cccd89ff6c5ed1db799614533844bd6d101da503761c45c713996e3bbd",
			                 "30440220514f977bf7edc442de8ce43ace9686e5ebdc0f893033f13e40fb46c8b8c6e1f90220188006227d175f5c35da0b092c57bea82537aed89f7778204dc5bacf4f29f2b9",
			                 "02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b800222020000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80ec0c62d0000000000160014ccf1af2f2aabee14bb40fa3851ab2301de84311004004730440220514f977bf7edc442de8ce43ace9686e5ebdc0f893033f13e40fb46c8b8c6e1f90220188006227d175f5c35da0b092c57bea82537aed89f7778204dc5bacf4f29f2b901473044022037f83ff00c8e5fb18ae1f918ffc24e54581775a20ff1ae719297ef066c71caa9022039c529cccd89ff6c5ed1db799614533844bd6d101da503761c45c713996e3bbd01475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae3e195220");

			assert_eq!(unsigned_tx.1.len(), 0);
		}

		{
			// commitment tx with one output untrimmed (minimum feerate)
			chan.value_to_self_msat = 6993000000; // 7000000000 - 7000000
			chan.feerate_per_kw = 9651181;

			test_commitment!("3044022064901950be922e62cbe3f2ab93de2b99f37cff9fc473e73e394b27f88ef0731d02206d1dfa227527b4df44a07599289e207d6fd9cca60c0365682dcd3deaf739567e",
			                 "3044022031a82b51bd014915fe68928d1abf4b9885353fb896cac10c3fdd88d7f9c7f2e00220716bda819641d2c63e65d3549b6120112e1aeaf1742eed94a471488e79e206b1",
			                 "02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b8001c0c62d0000000000160014ccf1af2f2aabee14bb40fa3851ab2301de8431100400473044022031a82b51bd014915fe68928d1abf4b9885353fb896cac10c3fdd88d7f9c7f2e00220716bda819641d2c63e65d3549b6120112e1aeaf1742eed94a471488e79e206b101473044022064901950be922e62cbe3f2ab93de2b99f37cff9fc473e73e394b27f88ef0731d02206d1dfa227527b4df44a07599289e207d6fd9cca60c0365682dcd3deaf739567e01475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae3e195220");

			assert_eq!(unsigned_tx.1.len(), 0);
		}

		{
			// commitment tx with fee greater than funder amount
			chan.value_to_self_msat = 6993000000; // 7000000000 - 7000000
			chan.feerate_per_kw = 9651936;

			test_commitment!("3044022064901950be922e62cbe3f2ab93de2b99f37cff9fc473e73e394b27f88ef0731d02206d1dfa227527b4df44a07599289e207d6fd9cca60c0365682dcd3deaf739567e",
			                 "3044022031a82b51bd014915fe68928d1abf4b9885353fb896cac10c3fdd88d7f9c7f2e00220716bda819641d2c63e65d3549b6120112e1aeaf1742eed94a471488e79e206b1",
			                 "02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b8001c0c62d0000000000160014ccf1af2f2aabee14bb40fa3851ab2301de8431100400473044022031a82b51bd014915fe68928d1abf4b9885353fb896cac10c3fdd88d7f9c7f2e00220716bda819641d2c63e65d3549b6120112e1aeaf1742eed94a471488e79e206b101473044022064901950be922e62cbe3f2ab93de2b99f37cff9fc473e73e394b27f88ef0731d02206d1dfa227527b4df44a07599289e207d6fd9cca60c0365682dcd3deaf739567e01475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae3e195220");

			assert_eq!(unsigned_tx.1.len(), 0);
		}
	}

	#[test]
	fn test_per_commitment_secret_gen() {
		// Test vectors from BOLT 3 Appendix D:

		let mut seed = [0; 32];
		seed[0..32].clone_from_slice(&hex::decode("0000000000000000000000000000000000000000000000000000000000000000").unwrap());
		assert_eq!(chan_utils::build_commitment_secret(seed, 281474976710655),
		           hex::decode("02a40c85b6f28da08dfdbe0926c53fab2de6d28c10301f8f7c4073d5e42e3148").unwrap()[..]);

		seed[0..32].clone_from_slice(&hex::decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF").unwrap());
		assert_eq!(chan_utils::build_commitment_secret(seed, 281474976710655),
		           hex::decode("7cc854b54e3e0dcdb010d7a3fee464a9687be6e8db3be6854c475621e007a5dc").unwrap()[..]);

		assert_eq!(chan_utils::build_commitment_secret(seed, 0xaaaaaaaaaaa),
		           hex::decode("56f4008fb007ca9acf0e15b054d5c9fd12ee06cea347914ddbaed70d1c13a528").unwrap()[..]);

		assert_eq!(chan_utils::build_commitment_secret(seed, 0x555555555555),
		           hex::decode("9015daaeb06dba4ccc05b91b2f73bd54405f2be9f217fbacd3c5ac2e62327d31").unwrap()[..]);

		seed[0..32].clone_from_slice(&hex::decode("0101010101010101010101010101010101010101010101010101010101010101").unwrap());
		assert_eq!(chan_utils::build_commitment_secret(seed, 1),
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
