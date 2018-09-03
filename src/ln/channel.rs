use bitcoin::blockdata::block::BlockHeader;
use bitcoin::blockdata::script::{Script,Builder};
use bitcoin::blockdata::transaction::{TxIn, TxOut, Transaction, SigHashType};
use bitcoin::blockdata::opcodes;
use bitcoin::util::hash::{Sha256dHash, Hash160};
use bitcoin::util::bip143;
use bitcoin::network::serialize::BitcoinHash;

use secp256k1::key::{PublicKey,SecretKey};
use secp256k1::{Secp256k1,Message,Signature};
use secp256k1;

use crypto::digest::Digest;
use crypto::hkdf::{hkdf_extract,hkdf_expand};

use ln::msgs;
use ln::msgs::{ErrorAction, HandleError, MsgEncodable};
use ln::channelmonitor::ChannelMonitor;
use ln::channelmanager::{PendingHTLCStatus, PendingForwardHTLCInfo, HTLCFailReason, HTLCFailureMsg};
use ln::chan_utils::{TxCreationKeys,HTLCOutputInCommitment,HTLC_SUCCESS_TX_WEIGHT,HTLC_TIMEOUT_TX_WEIGHT};
use ln::chan_utils;
use chain::chaininterface::{FeeEstimator,ConfirmationTarget};
use chain::transaction::OutPoint;
use util::{transaction_utils,rng};
use util::sha2::Sha256;
use util::logger::Logger;
use util::errors::APIError;

use std;
use std::default::Default;
use std::{cmp,mem};
use std::time::Instant;
use std::sync::{Arc};

pub struct ChannelKeys {
	pub funding_key: SecretKey,
	pub revocation_base_key: SecretKey,
	pub payment_base_key: SecretKey,
	pub delayed_payment_base_key: SecretKey,
	pub htlc_base_key: SecretKey,
	pub channel_close_key: SecretKey,
	pub channel_monitor_claim_key: SecretKey,
	pub commitment_seed: [u8; 32],
}

impl ChannelKeys {
	pub fn new_from_seed(seed: &[u8; 32]) -> Result<ChannelKeys, secp256k1::Error> {
		let mut prk = [0; 32];
		hkdf_extract(Sha256::new(), b"rust-lightning key gen salt", seed, &mut prk);
		let secp_ctx = Secp256k1::without_caps();

		let mut okm = [0; 32];
		hkdf_expand(Sha256::new(), &prk, b"rust-lightning funding key info", &mut okm);
		let funding_key = SecretKey::from_slice(&secp_ctx, &okm)?;

		hkdf_expand(Sha256::new(), &prk, b"rust-lightning revocation base key info", &mut okm);
		let revocation_base_key = SecretKey::from_slice(&secp_ctx, &okm)?;

		hkdf_expand(Sha256::new(), &prk, b"rust-lightning payment base key info", &mut okm);
		let payment_base_key = SecretKey::from_slice(&secp_ctx, &okm)?;

		hkdf_expand(Sha256::new(), &prk, b"rust-lightning delayed payment base key info", &mut okm);
		let delayed_payment_base_key = SecretKey::from_slice(&secp_ctx, &okm)?;

		hkdf_expand(Sha256::new(), &prk, b"rust-lightning htlc base key info", &mut okm);
		let htlc_base_key = SecretKey::from_slice(&secp_ctx, &okm)?;

		hkdf_expand(Sha256::new(), &prk, b"rust-lightning channel close key info", &mut okm);
		let channel_close_key = SecretKey::from_slice(&secp_ctx, &okm)?;

		hkdf_expand(Sha256::new(), &prk, b"rust-lightning channel monitor claim key info", &mut okm);
		let channel_monitor_claim_key = SecretKey::from_slice(&secp_ctx, &okm)?;

		hkdf_expand(Sha256::new(), &prk, b"rust-lightning local commitment seed info", &mut okm);

		Ok(ChannelKeys {
			funding_key: funding_key,
			revocation_base_key: revocation_base_key,
			payment_base_key: payment_base_key,
			delayed_payment_base_key: delayed_payment_base_key,
			htlc_base_key: htlc_base_key,
			channel_close_key: channel_close_key,
			channel_monitor_claim_key: channel_monitor_claim_key,
			commitment_seed: okm
		})
	}
}

#[derive(PartialEq)]
enum HTLCState {
	/// Added by remote, to be included in next local commitment tx.
	/// Implies HTLCOutput::outbound: false
	RemoteAnnounced,
	/// Included in a received commitment_signed message (implying we've revoke_and_ack'ed it), but
	/// the remote side hasn't yet revoked their previous state, which we need them to do before we
	/// accept this HTLC. Implies AwaitingRemoteRevoke.
	/// We also have not yet included this HTLC in a commitment_signed message, and are waiting on
	/// a remote revoke_and_ack on a previous state before we can do so.
	/// Implies HTLCOutput::outbound: false
	AwaitingRemoteRevokeToAnnounce,
	/// Included in a received commitment_signed message (implying we've revoke_and_ack'ed it), but
	/// the remote side hasn't yet revoked their previous state, which we need them to do before we
	/// accept this HTLC. Implies AwaitingRemoteRevoke.
	/// We have included this HTLC in our latest commitment_signed and are now just waiting on a
	/// revoke_and_ack.
	/// Implies HTLCOutput::outbound: true
	AwaitingAnnouncedRemoteRevoke,
	/// Added by us and included in a commitment_signed (if we were AwaitingRemoteRevoke when we
	/// created it we would have put it in the holding cell instead). When they next revoke_and_ack
	/// we will promote to Committed (note that they may not accept it until the next time we
	/// revoke, but we dont really care about that:
	///  * they've revoked, so worst case we can announce an old state and get our (option on)
	///    money back (though we wont), and,
	///  * we'll send them a revoke when they send a commitment_signed, and since only they're
	///    allowed to remove it, the "can only be removed once committed on both sides" requirement
	///    doesn't matter to us and its up to them to enforce it, worst-case they jump ahead but
	///    we'll never get out of sync).
	/// Implies HTLCOutput::outbound: true
	LocalAnnounced,
	Committed,
	/// Remote removed this (outbound) HTLC. We're waiting on their commitment_signed to finalize
	/// the change (though they'll need to revoke before we fail the payment).
	/// Implies HTLCOutput::outbound: true
	RemoteRemoved,
	/// Remote removed this and sent a commitment_signed (implying we've revoke_and_ack'ed it), but
	/// the remote side hasn't yet revoked their previous state, which we need them to do before we
	/// can do any backwards failing. Implies AwaitingRemoteRevoke.
	/// We also have not yet removed this HTLC in a commitment_signed message, and are waiting on a
	/// remote revoke_and_ack on a previous state before we can do so.
	/// Implies HTLCOutput::outbound: true
	AwaitingRemoteRevokeToRemove,
	/// Remote removed this and sent a commitment_signed (implying we've revoke_and_ack'ed it), but
	/// the remote side hasn't yet revoked their previous state, which we need them to do before we
	/// can do any backwards failing. Implies AwaitingRemoteRevoke.
	/// We have removed this HTLC in our latest commitment_signed and are now just waiting on a
	/// revoke_and_ack to drop completely.
	/// Implies HTLCOutput::outbound: true
	AwaitingRemovedRemoteRevoke,
	/// Removed by us and a new commitment_signed was sent (if we were AwaitingRemoteRevoke when we
	/// created it we would have put it in the holding cell instead). When they next revoke_and_ack
	/// we'll promote to LocalRemovedAwaitingCommitment if we fulfilled, otherwise we'll drop at
	/// that point.
	/// Note that we have to keep an eye on the HTLC until we've received a broadcastable
	/// commitment transaction without it as otherwise we'll have to force-close the channel to
	/// claim it before the timeout (obviously doesn't apply to revoked HTLCs that we can't claim
	/// anyway).
	/// Implies HTLCOutput::outbound: false
	LocalRemoved,
	/// Removed by us, sent a new commitment_signed and got a revoke_and_ack. Just waiting on an
	/// updated local commitment transaction. Implies local_removed_fulfilled.
	/// Implies HTLCOutput::outbound: false
	LocalRemovedAwaitingCommitment,
}

struct HTLCOutput { //TODO: Refactor into Outbound/InboundHTLCOutput (will save memory and fewer panics)
	outbound: bool, // ie to an HTLC-Timeout transaction
	htlc_id: u64,
	amount_msat: u64,
	cltv_expiry: u32,
	payment_hash: [u8; 32],
	state: HTLCState,
	/// If we're in a Remote* removed state, set if they failed, otherwise None
	fail_reason: Option<HTLCFailReason>,
	/// If we're in LocalRemoved*, set to true if we fulfilled the HTLC, and can claim money
	local_removed_fulfilled: bool,
	/// state pre-committed Remote* implies pending_forward_state, otherwise it must be None
	pending_forward_state: Option<PendingHTLCStatus>,
}

impl HTLCOutput {
	fn get_in_commitment(&self, offered: bool) -> HTLCOutputInCommitment {
		HTLCOutputInCommitment {
			offered: offered,
			amount_msat: self.amount_msat,
			cltv_expiry: self.cltv_expiry,
			payment_hash: self.payment_hash,
			transaction_output_index: 0
		}
	}
}

/// See AwaitingRemoteRevoke ChannelState for more info
enum HTLCUpdateAwaitingACK {
	AddHTLC {
		// always outbound
		amount_msat: u64,
		cltv_expiry: u32,
		payment_hash: [u8; 32],
		onion_routing_packet: msgs::OnionPacket,
		time_created: Instant, //TODO: Some kind of timeout thing-a-majig
	},
	ClaimHTLC {
		payment_preimage: [u8; 32],
		payment_hash: [u8; 32], // Only here for effecient duplicate detection
	},
	FailHTLC {
		payment_hash: [u8; 32],
		err_packet: msgs::OnionErrorPacket,
	},
}

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
	/// Flag which implies that we have sent a commitment_signed but are awaiting the responding
	/// revoke_and_ack message. During this time period, we can't generate new commitment_signed
	/// messages as then we will be unable to determine which HTLCs they included in their
	/// revoke_and_ack implicit ACK, so instead we have to hold them away temporarily to be sent
	/// later.
	/// Flag is set on ChannelFunded.
	AwaitingRemoteRevoke = (1 << 7),
	/// Flag which is set on ChannelFunded or FundingSent after receiving a shutdown message from
	/// the remote end. If set, they may not add any new HTLCs to the channel, and we are expected
	/// to respond with our own shutdown message when possible.
	RemoteShutdownSent = (1 << 8),
	/// Flag which is set on ChannelFunded or FundingSent after sending a shutdown message. At this
	/// point, we may not add any new HTLCs to the channel.
	/// TODO: Investigate some kind of timeout mechanism by which point the remote end must provide
	/// us their shutdown.
	LocalShutdownSent = (1 << 9),
	/// We've successfully negotiated a closing_signed dance. At this point ChannelManager is about
	/// to drop us, but we store this anyway.
	ShutdownComplete = (1 << 10),
}
const BOTH_SIDES_SHUTDOWN_MASK: u32 = (ChannelState::LocalShutdownSent as u32 | ChannelState::RemoteShutdownSent as u32);

// TODO: We should refactor this to be an Inbound/OutboundChannel until initial setup handshaking
// has been completed, and then turn into a Channel to get compiler-time enforcement of things like
// calling channel_id() before we're set up or things like get_outbound_funding_signed on an
// inbound channel.
pub struct Channel {
	user_id: u64,

	channel_id: [u8; 32],
	channel_state: u32,
	channel_outbound: bool,
	secp_ctx: Secp256k1<secp256k1::All>,
	announce_publicly: bool,
	channel_value_satoshis: u64,

	local_keys: ChannelKeys,

	// Our commitment numbers start at 2^48-1 and count down, whereas the ones used in transaction
	// generation start at 0 and count up...this simplifies some parts of implementation at the
	// cost of others, but should really just be changed.

	cur_local_commitment_transaction_number: u64,
	cur_remote_commitment_transaction_number: u64,
	value_to_self_msat: u64, // Excluding all pending_htlcs, excluding fees
	pending_htlcs: Vec<HTLCOutput>,
	holding_cell_htlc_updates: Vec<HTLCUpdateAwaitingACK>,
	next_local_htlc_id: u64,
	next_remote_htlc_id: u64,
	channel_update_count: u32,
	feerate_per_kw: u64,

	#[cfg(test)]
	// Used in ChannelManager's tests to send a revoked transaction
	pub last_local_commitment_txn: Vec<Transaction>,
	#[cfg(not(test))]
	last_local_commitment_txn: Vec<Transaction>,

	last_sent_closing_fee: Option<(u64, u64)>, // (feerate, fee)

	/// The hash of the block in which the funding transaction reached our CONF_TARGET. We use this
	/// to detect unconfirmation after a serialize-unserialize roudtrip where we may not see a full
	/// series of block_connected/block_disconnected calls. Obviously this is not a guarantee as we
	/// could miss the funding_tx_confirmed_in block as well, but it serves as a useful fallback.
	funding_tx_confirmed_in: Option<Sha256dHash>,
	short_channel_id: Option<u64>,
	/// Used to deduplicate block_connected callbacks
	last_block_connected: Sha256dHash,
	funding_tx_confirmations: u64,

	their_dust_limit_satoshis: u64,
	our_dust_limit_satoshis: u64,
	their_max_htlc_value_in_flight_msat: u64,
	//get_our_max_htlc_value_in_flight_msat(): u64,
	their_channel_reserve_satoshis: u64,
	//get_our_channel_reserve_satoshis(): u64,
	their_htlc_minimum_msat: u64,
	our_htlc_minimum_msat: u64,
	their_to_self_delay: u16,
	//implied by BREAKDOWN_TIMEOUT: our_to_self_delay: u16,
	their_max_accepted_htlcs: u16,
	//implied by OUR_MAX_HTLCS: our_max_accepted_htlcs: u16,

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

const OUR_MAX_HTLCS: u16 = 5; //TODO
/// Confirmation count threshold at which we close a channel. Ideally we'd keep the channel around
/// on ice until the funding transaction gets more confirmations, but the LN protocol doesn't
/// really allow for this, so instead we're stuck closing it out at that point.
const UNCONF_THRESHOLD: u32 = 6;
/// The amount of time we require our counterparty wait to claim their money (ie time between when
/// we, or our watchtower, must check for them having broadcast a theft transaction).
const BREAKDOWN_TIMEOUT: u16 = 6 * 24 * 7; //TODO?
/// The amount of time we're willing to wait to claim money back to us
const MAX_LOCAL_BREAKDOWN_TIMEOUT: u16 = 6 * 24 * 14;
const COMMITMENT_TX_BASE_WEIGHT: u64 = 724;
const COMMITMENT_TX_WEIGHT_PER_HTLC: u64 = 172;
const SPENDING_INPUT_FOR_A_OUTPUT_WEIGHT: u64 = 79; // prevout: 36, nSequence: 4, script len: 1, witness lengths: (3+1)/4, sig: 73/4, if-selector: 1, redeemScript: (6 ops + 2*33 pubkeys + 1*2 delay)/4
const B_OUTPUT_PLUS_SPENDING_INPUT_WEIGHT: u64 = 104; // prevout: 40, nSequence: 4, script len: 1, witness lengths: 3/4, sig: 73/4, pubkey: 33/4, output: 31 (TODO: Wrong? Useless?)
/// Maximmum `funding_satoshis` value, according to the BOLT #2 specification
/// it's 2^24.
pub const MAX_FUNDING_SATOSHIS: u64 = (1 << 24);

macro_rules! secp_call {
	( $res: expr, $err: expr ) => {
		match $res {
			Ok(key) => key,
			//TODO: make the error a parameter
			Err(_) => return Err(HandleError{err: $err, action: Some(msgs::ErrorAction::DisconnectPeer{ msg: None })})
		}
	};
}

macro_rules! secp_derived_key {
	( $res: expr ) => {
		secp_call!($res, "Derived invalid key, peer is maliciously selecting parameters")
	}
}
impl Channel {
	// Convert constants + channel value to limits:
	fn get_our_max_htlc_value_in_flight_msat(channel_value_satoshis: u64) -> u64 {
		channel_value_satoshis * 1000 / 10 //TODO
	}

	/// Guaranteed to return a value no larger than channel_value_satoshis
	fn get_our_channel_reserve_satoshis(channel_value_satoshis: u64) -> u64 {
		let (q, _) = channel_value_satoshis.overflowing_div(100);
		cmp::min(channel_value_satoshis, cmp::max(q, 1000)) //TODO
	}

	fn derive_our_dust_limit_satoshis(at_open_background_feerate: u64) -> u64 {
		at_open_background_feerate * B_OUTPUT_PLUS_SPENDING_INPUT_WEIGHT / 1000 //TODO
	}

	fn derive_our_htlc_minimum_msat(_at_open_channel_feerate_per_kw: u64) -> u64 {
		1000 // TODO
	}

	fn derive_minimum_depth(_channel_value_satoshis_msat: u64, _value_to_self_msat: u64) -> u32 {
		// Note that in order to comply with BOLT 7 announcement_signatures requirements this must
		// be at least 6.
		const CONF_TARGET: u32 = 12; //TODO: Should be much higher
		CONF_TARGET
	}

	fn derive_maximum_minimum_depth(_channel_value_satoshis_msat: u64, _value_to_self_msat: u64) -> u32 {
		const CONF_TARGET: u32 = 12; //TODO: Should be much higher
		CONF_TARGET * 2
	}

	// Constructors:
	pub fn new_outbound(fee_estimator: &FeeEstimator, chan_keys: ChannelKeys, their_node_id: PublicKey, channel_value_satoshis: u64, push_msat: u64, announce_publicly: bool, user_id: u64, logger: Arc<Logger>) -> Result<Channel, APIError> {
		if channel_value_satoshis >= MAX_FUNDING_SATOSHIS {
			return Err(APIError::APIMisuseError{err: "funding value > 2^24"});
		}

		if push_msat > channel_value_satoshis * 1000 {
			return Err(APIError::APIMisuseError{err: "push value > channel value"});
		}


		let background_feerate = fee_estimator.get_est_sat_per_1000_weight(ConfirmationTarget::Background);
		if Channel::get_our_channel_reserve_satoshis(channel_value_satoshis) < Channel::derive_our_dust_limit_satoshis(background_feerate) {
			return Err(APIError::FeeRateTooHigh{err: format!("Not enough reserve above dust limit can be found at current fee rate({})", background_feerate), feerate: background_feerate});
		}

		let feerate = fee_estimator.get_est_sat_per_1000_weight(ConfirmationTarget::Normal);

		let secp_ctx = Secp256k1::new();
		let our_channel_monitor_claim_key_hash = Hash160::from_data(&PublicKey::from_secret_key(&secp_ctx, &chan_keys.channel_monitor_claim_key).serialize());
		let our_channel_monitor_claim_script = Builder::new().push_opcode(opcodes::All::OP_PUSHBYTES_0).push_slice(&our_channel_monitor_claim_key_hash[..]).into_script();
		let channel_monitor = ChannelMonitor::new(&chan_keys.revocation_base_key,
		                                          &PublicKey::from_secret_key(&secp_ctx, &chan_keys.delayed_payment_base_key),
		                                          &chan_keys.htlc_base_key,
		                                          BREAKDOWN_TIMEOUT, our_channel_monitor_claim_script);

		Ok(Channel {
			user_id: user_id,

			channel_id: rng::rand_u832(),
			channel_state: ChannelState::OurInitSent as u32,
			channel_outbound: true,
			secp_ctx: secp_ctx,
			announce_publicly: announce_publicly,
			channel_value_satoshis: channel_value_satoshis,

			local_keys: chan_keys,
			cur_local_commitment_transaction_number: (1 << 48) - 1,
			cur_remote_commitment_transaction_number: (1 << 48) - 1,
			value_to_self_msat: channel_value_satoshis * 1000 - push_msat,
			pending_htlcs: Vec::new(),
			holding_cell_htlc_updates: Vec::new(),
			next_local_htlc_id: 0,
			next_remote_htlc_id: 0,
			channel_update_count: 1,

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
			their_max_accepted_htlcs: 0,

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

	fn check_remote_fee(fee_estimator: &FeeEstimator, feerate_per_kw: u32) -> Result<(), HandleError> {
		if (feerate_per_kw as u64) < fee_estimator.get_est_sat_per_1000_weight(ConfirmationTarget::Background) {
			return Err(HandleError{err: "Peer's feerate much too low", action: Some(msgs::ErrorAction::DisconnectPeer{ msg: None })});
		}
		if (feerate_per_kw as u64) > fee_estimator.get_est_sat_per_1000_weight(ConfirmationTarget::HighPriority) * 2 {
			return Err(HandleError{err: "Peer's feerate much too high", action: Some(msgs::ErrorAction::DisconnectPeer{ msg: None })});
		}
		Ok(())
	}

	/// Creates a new channel from a remote sides' request for one.
	/// Assumes chain_hash has already been checked and corresponds with what we expect!
	/// Generally prefers to take the DisconnectPeer action on failure, as a notice to the sender
	/// that we're rejecting the new channel.
	pub fn new_from_req(fee_estimator: &FeeEstimator, chan_keys: ChannelKeys, their_node_id: PublicKey, msg: &msgs::OpenChannel, user_id: u64, require_announce: bool, allow_announce: bool, logger: Arc<Logger>) -> Result<Channel, HandleError> {
		macro_rules! return_error_message {
			( $msg: expr ) => {
				return Err(HandleError{err: $msg, action: Some(msgs::ErrorAction::SendErrorMessage{ msg: msgs::ErrorMessage { channel_id: msg.temporary_channel_id, data: $msg.to_string() }})});
			}
		}

		// Check sanity of message fields:
		if msg.funding_satoshis >= MAX_FUNDING_SATOSHIS {
			return_error_message!("funding value > 2^24");
		}
		if msg.channel_reserve_satoshis > msg.funding_satoshis {
			return_error_message!("Bogus channel_reserve_satoshis");
		}
		if msg.push_msat > (msg.funding_satoshis - msg.channel_reserve_satoshis) * 1000 {
			return_error_message!("push_msat larger than funding value");
		}
		if msg.dust_limit_satoshis > msg.funding_satoshis {
			return_error_message!("Peer never wants payout outputs?");
		}
		if msg.dust_limit_satoshis > msg.channel_reserve_satoshis {
			return_error_message!("Bogus; channel reserve is less than dust limit");
		}
		if msg.htlc_minimum_msat >= (msg.funding_satoshis - msg.channel_reserve_satoshis) * 1000 {
			return_error_message!("Miminum htlc value is full channel value");
		}
		Channel::check_remote_fee(fee_estimator, msg.feerate_per_kw).map_err(|e|
			HandleError{err: e.err, action: Some(msgs::ErrorAction::SendErrorMessage{ msg: msgs::ErrorMessage { channel_id: msg.temporary_channel_id, data: e.err.to_string() }})}
		)?;

		if msg.to_self_delay > MAX_LOCAL_BREAKDOWN_TIMEOUT {
			return_error_message!("They wanted our payments to be delayed by a needlessly long period");
		}
		if msg.max_accepted_htlcs < 1 {
			return_error_message!("0 max_accpted_htlcs makes for a useless channel");
		}
		if msg.max_accepted_htlcs > 483 {
			return_error_message!("max_accpted_htlcs > 483");
		}

		// Convert things into internal flags and prep our state:

		let their_announce = if (msg.channel_flags & 1) == 1 { true } else { false };
		if require_announce && !their_announce {
			return Err(HandleError{err: "Peer tried to open unannounced channel, but we require public ones", action: Some(msgs::ErrorAction::IgnoreError) });
		}
		if !allow_announce && their_announce {
			return Err(HandleError{err: "Peer tried to open announced channel, but we require private ones", action: Some(msgs::ErrorAction::IgnoreError) });
		}

		let background_feerate = fee_estimator.get_est_sat_per_1000_weight(ConfirmationTarget::Background);

		let our_dust_limit_satoshis = Channel::derive_our_dust_limit_satoshis(background_feerate);
		let our_channel_reserve_satoshis = Channel::get_our_channel_reserve_satoshis(msg.funding_satoshis);
		if our_channel_reserve_satoshis < our_dust_limit_satoshis {
			return_error_message!("Suitalbe channel reserve not found. aborting");
		}
		if msg.channel_reserve_satoshis < our_dust_limit_satoshis {
			return_error_message!("channel_reserve_satoshis too small");
		}
		if our_channel_reserve_satoshis < msg.dust_limit_satoshis {
			return_error_message!("Dust limit too high for our channel reserve");
		}

		// check if the funder's amount for the initial commitment tx is sufficient
		// for full fee payment
		let funders_amount_msat = msg.funding_satoshis * 1000 - msg.push_msat;
		if funders_amount_msat < background_feerate * COMMITMENT_TX_BASE_WEIGHT {
			return_error_message!("Insufficient funding amount for initial commitment");
		}

		let to_local_msat = msg.push_msat;
		let to_remote_msat = funders_amount_msat - background_feerate * COMMITMENT_TX_BASE_WEIGHT;
		if to_local_msat <= msg.channel_reserve_satoshis * 1000 && to_remote_msat <= our_channel_reserve_satoshis * 1000 {
			return_error_message!("Insufficient funding amount for initial commitment");
		}

		let secp_ctx = Secp256k1::new();
		let our_channel_monitor_claim_key_hash = Hash160::from_data(&PublicKey::from_secret_key(&secp_ctx, &chan_keys.channel_monitor_claim_key).serialize());
		let our_channel_monitor_claim_script = Builder::new().push_opcode(opcodes::All::OP_PUSHBYTES_0).push_slice(&our_channel_monitor_claim_key_hash[..]).into_script();
		let mut channel_monitor = ChannelMonitor::new(&chan_keys.revocation_base_key,
		                                              &PublicKey::from_secret_key(&secp_ctx, &chan_keys.delayed_payment_base_key),
		                                              &chan_keys.htlc_base_key,
		                                              BREAKDOWN_TIMEOUT, our_channel_monitor_claim_script);
		channel_monitor.set_their_htlc_base_key(&msg.htlc_basepoint);
		channel_monitor.set_their_to_self_delay(msg.to_self_delay);

		let mut chan = Channel {
			user_id: user_id,

			channel_id: msg.temporary_channel_id,
			channel_state: (ChannelState::OurInitSent as u32) | (ChannelState::TheirInitSent as u32),
			channel_outbound: false,
			secp_ctx: secp_ctx,
			announce_publicly: their_announce,

			local_keys: chan_keys,
			cur_local_commitment_transaction_number: (1 << 48) - 1,
			cur_remote_commitment_transaction_number: (1 << 48) - 1,
			value_to_self_msat: msg.push_msat,
			pending_htlcs: Vec::new(),
			holding_cell_htlc_updates: Vec::new(),
			next_local_htlc_id: 0,
			next_remote_htlc_id: 0,
			channel_update_count: 1,

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
			their_max_accepted_htlcs: msg.max_accepted_htlcs,

			their_funding_pubkey: Some(msg.funding_pubkey),
			their_revocation_basepoint: Some(msg.revocation_basepoint),
			their_payment_basepoint: Some(msg.payment_basepoint),
			their_delayed_payment_basepoint: Some(msg.delayed_payment_basepoint),
			their_htlc_basepoint: Some(msg.htlc_basepoint),
			their_cur_commitment_point: Some(msg.first_per_commitment_point),

			their_prev_commitment_point: None,
			their_node_id: their_node_id,

			their_shutdown_scriptpubkey: None,

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
		SecretKey::from_slice(&self.secp_ctx, &res).unwrap()
	}

	// Utilities to build transactions:

	fn get_commitment_transaction_number_obscure_factor(&self) -> u64 {
		let mut sha = Sha256::new();
		let our_payment_basepoint = PublicKey::from_secret_key(&self.secp_ctx, &self.local_keys.payment_base_key);

		if self.channel_outbound {
			sha.input(&our_payment_basepoint.serialize());
			sha.input(&self.their_payment_basepoint.unwrap().serialize());
		} else {
			sha.input(&self.their_payment_basepoint.unwrap().serialize());
			sha.input(&our_payment_basepoint.serialize());
		}
		let mut res = [0; 32];
		sha.result(&mut res);

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
	#[inline]
	fn build_commitment_transaction(&self, commitment_number: u64, keys: &TxCreationKeys, local: bool, generated_by_local: bool) -> (Transaction, Vec<HTLCOutputInCommitment>) {
		let obscured_commitment_transaction_number = self.get_commitment_transaction_number_obscure_factor() ^ (0xffffffffffff - commitment_number);

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

		let mut txouts: Vec<(TxOut, Option<HTLCOutputInCommitment>)> = Vec::with_capacity(self.pending_htlcs.len() + 2);

		let dust_limit_satoshis = if local { self.our_dust_limit_satoshis } else { self.their_dust_limit_satoshis };
		let mut remote_htlc_total_msat = 0;
		let mut local_htlc_total_msat = 0;
		let mut value_to_self_msat_offset = 0;

		for ref htlc in self.pending_htlcs.iter() {
			let include = match htlc.state {
				HTLCState::RemoteAnnounced => !generated_by_local,
				HTLCState::AwaitingRemoteRevokeToAnnounce => !generated_by_local,
				HTLCState::AwaitingAnnouncedRemoteRevoke => true,
				HTLCState::LocalAnnounced => generated_by_local,
				HTLCState::Committed => true,
				HTLCState::RemoteRemoved => generated_by_local,
				HTLCState::AwaitingRemoteRevokeToRemove => generated_by_local,
				HTLCState::AwaitingRemovedRemoteRevoke => false,
				HTLCState::LocalRemoved => !generated_by_local,
				HTLCState::LocalRemovedAwaitingCommitment => false,
			};

			if include {
				if htlc.outbound == local { // "offered HTLC output"
					if htlc.amount_msat / 1000 >= dust_limit_satoshis + (self.feerate_per_kw * HTLC_TIMEOUT_TX_WEIGHT / 1000) {
						let htlc_in_tx = htlc.get_in_commitment(true);
						txouts.push((TxOut {
							script_pubkey: chan_utils::get_htlc_redeemscript(&htlc_in_tx, &keys).to_v0_p2wsh(),
							value: htlc.amount_msat / 1000
						}, Some(htlc_in_tx)));
					}
				} else {
					if htlc.amount_msat / 1000 >= dust_limit_satoshis + (self.feerate_per_kw * HTLC_SUCCESS_TX_WEIGHT / 1000) {
						let htlc_in_tx = htlc.get_in_commitment(false);
						txouts.push((TxOut { // "received HTLC output"
							script_pubkey: chan_utils::get_htlc_redeemscript(&htlc_in_tx, &keys).to_v0_p2wsh(),
							value: htlc.amount_msat / 1000
						}, Some(htlc_in_tx)));
					}
				};
				if htlc.outbound {
					local_htlc_total_msat += htlc.amount_msat;
				} else {
					remote_htlc_total_msat += htlc.amount_msat;
				}
			} else {
				match htlc.state {
					HTLCState::AwaitingRemoteRevokeToRemove|HTLCState::AwaitingRemovedRemoteRevoke => {
						if htlc.fail_reason.is_none() {
							value_to_self_msat_offset -= htlc.amount_msat as i64;
						}
					},
					HTLCState::RemoteRemoved => {
						if !generated_by_local && htlc.fail_reason.is_none() {
							value_to_self_msat_offset -= htlc.amount_msat as i64;
						}
					},
					HTLCState::LocalRemoved => {
						if generated_by_local && htlc.local_removed_fulfilled {
							value_to_self_msat_offset += htlc.amount_msat as i64;
						}
					},
					HTLCState::LocalRemovedAwaitingCommitment => {
						assert!(htlc.local_removed_fulfilled);
						value_to_self_msat_offset += htlc.amount_msat as i64;
					},
					_ => {},
				}
			}
		}

		let total_fee: u64 = self.feerate_per_kw * (COMMITMENT_TX_BASE_WEIGHT + (txouts.len() as u64) * COMMITMENT_TX_WEIGHT_PER_HTLC) / 1000;
		let value_to_self: i64 = ((self.value_to_self_msat - local_htlc_total_msat) as i64 + value_to_self_msat_offset) / 1000 - if self.channel_outbound { total_fee as i64 } else { 0 };
		let value_to_remote: i64 = (((self.channel_value_satoshis * 1000 - self.value_to_self_msat - remote_htlc_total_msat) as i64 - value_to_self_msat_offset) / 1000) - if self.channel_outbound { 0 } else { total_fee as i64 };

		let value_to_a = if local { value_to_self } else { value_to_remote };
		let value_to_b = if local { value_to_remote } else { value_to_self };

		if value_to_a >= (dust_limit_satoshis as i64) {
			txouts.push((TxOut {
				script_pubkey: chan_utils::get_revokeable_redeemscript(&keys.revocation_key,
				                                                       if local { self.their_to_self_delay } else { BREAKDOWN_TIMEOUT },
				                                                       &keys.a_delayed_payment_key).to_v0_p2wsh(),
				value: value_to_a as u64
			}, None));
		}

		if value_to_b >= (dust_limit_satoshis as i64) {
			txouts.push((TxOut {
				script_pubkey: Builder::new().push_opcode(opcodes::All::OP_PUSHBYTES_0)
				                             .push_slice(&Hash160::from_data(&keys.b_payment_key.serialize())[..])
				                             .into_script(),
				value: value_to_b as u64
			}, None));
		}

		transaction_utils::sort_outputs(&mut txouts);

		let mut outputs: Vec<TxOut> = Vec::with_capacity(txouts.len());
		let mut htlcs_used: Vec<HTLCOutputInCommitment> = Vec::with_capacity(txouts.len());
		for (idx, out) in txouts.drain(..).enumerate() {
			outputs.push(out.0);
			if let Some(out_htlc) = out.1 {
				htlcs_used.push(out_htlc);
				htlcs_used.last_mut().unwrap().transaction_output_index = idx as u32;
			}
		}

		(Transaction {
			version: 2,
			lock_time: ((0x20 as u32) << 8*3) | ((obscured_commitment_transaction_number & 0xffffffu64) as u32),
			input: txins,
			output: outputs,
		}, htlcs_used)
	}

	#[inline]
	fn get_closing_scriptpubkey(&self) -> Script {
		let our_channel_close_key_hash = Hash160::from_data(&PublicKey::from_secret_key(&self.secp_ctx, &self.local_keys.channel_close_key).serialize());
		Builder::new().push_opcode(opcodes::All::OP_PUSHBYTES_0).push_slice(&our_channel_close_key_hash[..]).into_script()
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

		assert!(self.pending_htlcs.is_empty());
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

		transaction_utils::sort_outputs(&mut txouts);

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
	fn build_local_transaction_keys(&self, commitment_number: u64) -> Result<TxCreationKeys, HandleError> {
		let per_commitment_point = PublicKey::from_secret_key(&self.secp_ctx, &self.build_local_commitment_secret(commitment_number));
		let delayed_payment_base = PublicKey::from_secret_key(&self.secp_ctx, &self.local_keys.delayed_payment_base_key);
		let htlc_basepoint = PublicKey::from_secret_key(&self.secp_ctx, &self.local_keys.htlc_base_key);

		Ok(secp_derived_key!(TxCreationKeys::new(&self.secp_ctx, &per_commitment_point, &delayed_payment_base, &htlc_basepoint, &self.their_revocation_basepoint.unwrap(), &self.their_payment_basepoint.unwrap(), &self.their_htlc_basepoint.unwrap())))
	}

	#[inline]
	/// Creates a set of keys for build_commitment_transaction to generate a transaction which we
	/// will sign and send to our counterparty.
	fn build_remote_transaction_keys(&self) -> Result<TxCreationKeys, HandleError> {
		//TODO: Ensure that the payment_key derived here ends up in the library users' wallet as we
		//may see payments to it!
		let payment_basepoint = PublicKey::from_secret_key(&self.secp_ctx, &self.local_keys.payment_base_key);
		let revocation_basepoint = PublicKey::from_secret_key(&self.secp_ctx, &self.local_keys.revocation_base_key);
		let htlc_basepoint = PublicKey::from_secret_key(&self.secp_ctx, &self.local_keys.htlc_base_key);

		Ok(secp_derived_key!(TxCreationKeys::new(&self.secp_ctx, &self.their_cur_commitment_point.unwrap(), &self.their_delayed_payment_basepoint.unwrap(), &self.their_htlc_basepoint.unwrap(), &revocation_basepoint, &payment_basepoint, &htlc_basepoint)))
	}

	/// Gets the redeemscript for the funding transaction output (ie the funding transaction output
	/// pays to get_funding_redeemscript().to_v0_p2wsh()).
	pub fn get_funding_redeemscript(&self) -> Script {
		let builder = Builder::new().push_opcode(opcodes::All::OP_PUSHNUM_2);
		let our_funding_key = PublicKey::from_secret_key(&self.secp_ctx, &self.local_keys.funding_key).serialize();
		let their_funding_key = self.their_funding_pubkey.unwrap().serialize();
		if our_funding_key[..] < their_funding_key[..] {
			builder.push_slice(&our_funding_key)
				.push_slice(&their_funding_key)
		} else {
			builder.push_slice(&their_funding_key)
				.push_slice(&our_funding_key)
		}.push_opcode(opcodes::All::OP_PUSHNUM_2).push_opcode(opcodes::All::OP_CHECKMULTISIG).into_script()
	}

	fn sign_commitment_transaction(&self, tx: &mut Transaction, their_sig: &Signature) -> Signature {
		if tx.input.len() != 1 {
			panic!("Tried to sign commitment transaction that had input count != 1!");
		}
		if tx.input[0].witness.len() != 0 {
			panic!("Tried to re-sign commitment transaction");
		}

		let funding_redeemscript = self.get_funding_redeemscript();

		let sighash = Message::from_slice(&bip143::SighashComponents::new(&tx).sighash_all(&tx.input[0], &funding_redeemscript, self.channel_value_satoshis)[..]).unwrap();
		let our_sig = self.secp_ctx.sign(&sighash, &self.local_keys.funding_key);

		tx.input[0].witness.push(Vec::new()); // First is the multisig dummy

		let our_funding_key = PublicKey::from_secret_key(&self.secp_ctx, &self.local_keys.funding_key).serialize();
		let their_funding_key = self.their_funding_pubkey.unwrap().serialize();
		if our_funding_key[..] < their_funding_key[..] {
			tx.input[0].witness.push(our_sig.serialize_der(&self.secp_ctx).to_vec());
			tx.input[0].witness.push(their_sig.serialize_der(&self.secp_ctx).to_vec());
		} else {
			tx.input[0].witness.push(their_sig.serialize_der(&self.secp_ctx).to_vec());
			tx.input[0].witness.push(our_sig.serialize_der(&self.secp_ctx).to_vec());
		}
		tx.input[0].witness[1].push(SigHashType::All as u8);
		tx.input[0].witness[2].push(SigHashType::All as u8);

		tx.input[0].witness.push(funding_redeemscript.into_bytes());

		our_sig
	}

	/// Builds the htlc-success or htlc-timeout transaction which spends a given HTLC output
	/// @local is used only to convert relevant internal structures which refer to remote vs local
	/// to decide value of outputs and direction of HTLCs.
	fn build_htlc_transaction(&self, prev_hash: &Sha256dHash, htlc: &HTLCOutputInCommitment, local: bool, keys: &TxCreationKeys) -> Transaction {
		chan_utils::build_htlc_transaction(prev_hash, self.feerate_per_kw, if local { self.their_to_self_delay } else { BREAKDOWN_TIMEOUT }, htlc, &keys.a_delayed_payment_key, &keys.revocation_key)
	}

	fn create_htlc_tx_signature(&self, tx: &Transaction, htlc: &HTLCOutputInCommitment, keys: &TxCreationKeys) -> Result<(Script, Signature, bool), HandleError> {
		if tx.input.len() != 1 {
			panic!("Tried to sign HTLC transaction that had input count != 1!");
		}

		let htlc_redeemscript = chan_utils::get_htlc_redeemscript(&htlc, &keys);

		let our_htlc_key = secp_derived_key!(chan_utils::derive_private_key(&self.secp_ctx, &keys.per_commitment_point, &self.local_keys.htlc_base_key));
		let sighash = Message::from_slice(&bip143::SighashComponents::new(&tx).sighash_all(&tx.input[0], &htlc_redeemscript, htlc.amount_msat / 1000)[..]).unwrap();
		let is_local_tx = PublicKey::from_secret_key(&self.secp_ctx, &our_htlc_key) == keys.a_htlc_key;
		Ok((htlc_redeemscript, self.secp_ctx.sign(&sighash, &our_htlc_key), is_local_tx))
	}

	/// Signs a transaction created by build_htlc_transaction. If the transaction is an
	/// HTLC-Success transaction (ie htlc.offered is false), preimate must be set!
	fn sign_htlc_transaction(&self, tx: &mut Transaction, their_sig: &Signature, preimage: &Option<[u8; 32]>, htlc: &HTLCOutputInCommitment, keys: &TxCreationKeys) -> Result<Signature, HandleError> {
		if tx.input.len() != 1 {
			panic!("Tried to sign HTLC transaction that had input count != 1!");
		}
		if tx.input[0].witness.len() != 0 {
			panic!("Tried to re-sign HTLC transaction");
		}

		let (htlc_redeemscript, our_sig, local_tx) = self.create_htlc_tx_signature(tx, htlc, keys)?;

		tx.input[0].witness.push(Vec::new()); // First is the multisig dummy

		if local_tx { // b, then a
			tx.input[0].witness.push(their_sig.serialize_der(&self.secp_ctx).to_vec());
			tx.input[0].witness.push(our_sig.serialize_der(&self.secp_ctx).to_vec());
		} else {
			tx.input[0].witness.push(our_sig.serialize_der(&self.secp_ctx).to_vec());
			tx.input[0].witness.push(their_sig.serialize_der(&self.secp_ctx).to_vec());
		}
		tx.input[0].witness[1].push(SigHashType::All as u8);
		tx.input[0].witness[2].push(SigHashType::All as u8);

		if htlc.offered {
			tx.input[0].witness.push(Vec::new());
		} else {
			tx.input[0].witness.push(preimage.unwrap().to_vec());
		}

		tx.input[0].witness.push(htlc_redeemscript.into_bytes());

		Ok(our_sig)
	}

	fn get_update_fulfill_htlc(&mut self, payment_preimage_arg: [u8; 32]) -> Result<(Option<msgs::UpdateFulfillHTLC>, Option<ChannelMonitor>), HandleError> {
		// Either ChannelFunded got set (which means it wont bet unset) or there is no way any
		// caller thought we could have something claimed (cause we wouldn't have accepted in an
		// incoming HTLC anyway). If we got to ShutdownComplete, callers aren't allowed to call us,
		// either.
		if (self.channel_state & (ChannelState::ChannelFunded as u32)) != (ChannelState::ChannelFunded as u32) {
			panic!("Was asked to fulfill an HTLC when channel was not in an operational state");
		}
		assert_eq!(self.channel_state & ChannelState::ShutdownComplete as u32, 0);

		let mut sha = Sha256::new();
		sha.input(&payment_preimage_arg);
		let mut payment_hash_calc = [0; 32];
		sha.result(&mut payment_hash_calc);

		let mut pending_idx = std::usize::MAX;
		for (idx, htlc) in self.pending_htlcs.iter().enumerate() {
			if !htlc.outbound && htlc.payment_hash == payment_hash_calc &&
					htlc.state != HTLCState::LocalRemoved && htlc.state != HTLCState::LocalRemovedAwaitingCommitment {
				if let Some(PendingHTLCStatus::Fail(_)) = htlc.pending_forward_state {
				} else {
					if pending_idx != std::usize::MAX {
						panic!("Duplicate HTLC payment_hash, ChannelManager should have prevented this!");
					}
					pending_idx = idx;
				}
			}
		}
		if pending_idx == std::usize::MAX {
			return Err(HandleError{err: "Unable to find a pending HTLC which matched the given payment preimage", action: None});
		}

		// Now update local state:
		//
		// We have to put the payment_preimage in the channel_monitor right away here to ensure we
		// can claim it even if the channel hits the chain before we see their next commitment.
		self.channel_monitor.provide_payment_preimage(&payment_hash_calc, &payment_preimage_arg);

		if (self.channel_state & (ChannelState::AwaitingRemoteRevoke as u32)) == (ChannelState::AwaitingRemoteRevoke as u32) {
			for pending_update in self.holding_cell_htlc_updates.iter() {
				match pending_update {
					&HTLCUpdateAwaitingACK::ClaimHTLC { ref payment_preimage, .. } => {
						if payment_preimage_arg == *payment_preimage {
							return Ok((None, None));
						}
					},
					&HTLCUpdateAwaitingACK::FailHTLC { ref payment_hash, .. } => {
						if payment_hash_calc == *payment_hash {
							return Err(HandleError{err: "Unable to find a pending HTLC which matched the given payment preimage", action: None});
						}
					},
					_ => {}
				}
			}
			self.holding_cell_htlc_updates.push(HTLCUpdateAwaitingACK::ClaimHTLC {
				payment_preimage: payment_preimage_arg, payment_hash: payment_hash_calc,
			});
			return Ok((None, Some(self.channel_monitor.clone())));
		}

		let htlc_id = {
			let htlc = &mut self.pending_htlcs[pending_idx];
			if htlc.state == HTLCState::Committed {
				htlc.state = HTLCState::LocalRemoved;
				htlc.local_removed_fulfilled = true;
			} else if htlc.state == HTLCState::RemoteAnnounced || htlc.state == HTLCState::AwaitingRemoteRevokeToAnnounce || htlc.state == HTLCState::AwaitingAnnouncedRemoteRevoke {
				// Theoretically we can hit this if we get the preimage on an HTLC prior to us
				// having forwarded it to anyone. This implies that the sender is busted as someone
				// else knows the preimage, but handling this case and implementing the logic to
				// take their money would be a lot of (never-tested) code to handle a case that
				// hopefully never happens. Instead, we make sure we get the preimage into the
				// channel_monitor and pretend we didn't just see the preimage.
				return Ok((None, Some(self.channel_monitor.clone())));
			} else {
				// LocalRemoved/LocalRemovedAwaitingCOmmitment handled in the search loop
				panic!("Have an inbound HTLC when not awaiting remote revoke that had a garbage state");
			}
			htlc.htlc_id
		};

		Ok((Some(msgs::UpdateFulfillHTLC {
			channel_id: self.channel_id(),
			htlc_id: htlc_id,
			payment_preimage: payment_preimage_arg,
		}), Some(self.channel_monitor.clone())))
	}

	pub fn get_update_fulfill_htlc_and_commit(&mut self, payment_preimage: [u8; 32]) -> Result<(Option<(msgs::UpdateFulfillHTLC, msgs::CommitmentSigned)>, Option<ChannelMonitor>), HandleError> {
		match self.get_update_fulfill_htlc(payment_preimage)? {
			(Some(update_fulfill_htlc), _) => {
				let (commitment, monitor_update) = self.send_commitment_no_status_check()?;
				Ok((Some((update_fulfill_htlc, commitment)), Some(monitor_update)))
			},
			(None, Some(channel_monitor)) => Ok((None, Some(channel_monitor))),
			(None, None) => Ok((None, None))
		}
	}

	pub fn get_update_fail_htlc(&mut self, payment_hash_arg: &[u8; 32], err_packet: msgs::OnionErrorPacket) -> Result<Option<msgs::UpdateFailHTLC>, HandleError> {
		if (self.channel_state & (ChannelState::ChannelFunded as u32)) != (ChannelState::ChannelFunded as u32) {
			return Err(HandleError{err: "Was asked to fail an HTLC when channel was not in an operational state", action: None});
		}
		assert_eq!(self.channel_state & ChannelState::ShutdownComplete as u32, 0);

		// Now update local state:
		if (self.channel_state & (ChannelState::AwaitingRemoteRevoke as u32)) == (ChannelState::AwaitingRemoteRevoke as u32) {
			for pending_update in self.holding_cell_htlc_updates.iter() {
				match pending_update {
					&HTLCUpdateAwaitingACK::ClaimHTLC { ref payment_hash, .. } => {
						if *payment_hash_arg == *payment_hash {
							return Err(HandleError{err: "Unable to find a pending HTLC which matched the given payment preimage", action: None});
						}
					},
					&HTLCUpdateAwaitingACK::FailHTLC { ref payment_hash, .. } => {
						if *payment_hash_arg == *payment_hash {
							return Ok(None);
						}
					},
					_ => {}
				}
			}
			self.holding_cell_htlc_updates.push(HTLCUpdateAwaitingACK::FailHTLC {
				payment_hash: payment_hash_arg.clone(),
				err_packet,
			});
			return Ok(None);
		}

		let mut htlc_id = 0;
		let mut htlc_amount_msat = 0;
		for htlc in self.pending_htlcs.iter_mut() {
			if !htlc.outbound && htlc.payment_hash == *payment_hash_arg {
				if htlc.state == HTLCState::Committed {
					htlc.state = HTLCState::LocalRemoved;
				} else if htlc.state == HTLCState::RemoteAnnounced {
					if let Some(PendingHTLCStatus::Forward(_)) = htlc.pending_forward_state {
						panic!("Somehow forwarded HTLC prior to remote revocation!");
					} else {
						// We have to pretend this isn't here - we're probably a duplicate with the
						// same payment_hash as some other HTLC, and the other is getting failed,
						// we'll fail this one as soon as remote commits to it.
						continue;
					}
				} else if htlc.state == HTLCState::LocalRemoved || htlc.state == HTLCState::LocalRemovedAwaitingCommitment {
					return Err(HandleError{err: "Unable to find a pending HTLC which matched the given payment preimage", action: None});
				} else {
					panic!("Have an inbound HTLC when not awaiting remote revoke that had a garbage state");
				}
				if htlc_id != 0 {
					panic!("Duplicate HTLC payment_hash, you probably re-used payment preimages, NEVER DO THIS!");
				}
				htlc_id = htlc.htlc_id;
				htlc_amount_msat += htlc.amount_msat;
			}
		}
		if htlc_amount_msat == 0 {
			return Err(HandleError{err: "Unable to find a pending HTLC which matched the given payment preimage", action: None});
		}

		Ok(Some(msgs::UpdateFailHTLC {
			channel_id: self.channel_id(),
			htlc_id,
			reason: err_packet
		}))
	}

	pub fn get_update_fail_htlc_and_commit(&mut self, payment_hash: &[u8; 32], err_packet: msgs::OnionErrorPacket) -> Result<Option<(msgs::UpdateFailHTLC, msgs::CommitmentSigned, ChannelMonitor)>, HandleError> {
		match self.get_update_fail_htlc(payment_hash, err_packet)? {
			Some(update_fail_htlc) => {
				let (commitment, monitor_update) = self.send_commitment_no_status_check()?;
				Ok(Some((update_fail_htlc, commitment, monitor_update)))
			},
			None => Ok(None)
		}
	}

	// Message handlers:

	pub fn accept_channel(&mut self, msg: &msgs::AcceptChannel) -> Result<(), HandleError> {
		macro_rules! return_error_message {
			( $msg: expr ) => {
				return Err(HandleError{err: $msg, action: Some(msgs::ErrorAction::SendErrorMessage{ msg: msgs::ErrorMessage { channel_id: msg.temporary_channel_id, data: $msg.to_string() }})});
			}
		}
		// Check sanity of message fields:
		if !self.channel_outbound {
			return_error_message!("Got an accept_channel message from an inbound peer");
		}
		if self.channel_state != ChannelState::OurInitSent as u32 {
			return_error_message!("Got an accept_channel message at a strange time");
		}
		if msg.dust_limit_satoshis > 21000000 * 100000000 {
			return_error_message!("Peer never wants payout outputs?");
		}
		if msg.channel_reserve_satoshis > self.channel_value_satoshis {
			return_error_message!("Bogus channel_reserve_satoshis");
		}
		if msg.dust_limit_satoshis > msg.channel_reserve_satoshis {
			return_error_message!("Bogus channel_reserve and dust_limit");
		}
		if msg.channel_reserve_satoshis < self.our_dust_limit_satoshis {
			return_error_message!("Peer never wants payout outputs?");
		}
		if msg.dust_limit_satoshis > Channel::get_our_channel_reserve_satoshis(self.channel_value_satoshis) {
			return_error_message!("Dust limit is bigger than our channel reverse");
		}
		if msg.htlc_minimum_msat >= (self.channel_value_satoshis - msg.channel_reserve_satoshis) * 1000 {
			return_error_message!("Minimum htlc value is full channel value");
		}
		if msg.minimum_depth > Channel::derive_maximum_minimum_depth(self.channel_value_satoshis*1000,  self.value_to_self_msat) {
			return_error_message!("minimum_depth too large");
		}
		if msg.to_self_delay > MAX_LOCAL_BREAKDOWN_TIMEOUT {
			return_error_message!("They wanted our payments to be delayed by a needlessly long period");
		}
		if msg.max_accepted_htlcs < 1 {
			return_error_message!("0 max_accpted_htlcs makes for a useless channel");
		}
		if msg.max_accepted_htlcs > 483 {
			return_error_message!("max_accpted_htlcs > 483");
		}

		// TODO: Optional additional constraints mentioned in the spec
		// MAY fail the channel if
		// funding_satoshi is too small
		// htlc_minimum_msat too large
		// max_htlc_value_in_flight_msat too small
		// channel_reserve_satoshis too large
		// max_accepted_htlcs too small
		// dust_limit_satoshis too small

		self.channel_monitor.set_their_htlc_base_key(&msg.htlc_basepoint);

		self.their_dust_limit_satoshis = msg.dust_limit_satoshis;
		self.their_max_htlc_value_in_flight_msat = cmp::min(msg.max_htlc_value_in_flight_msat, self.channel_value_satoshis * 1000);
		self.their_channel_reserve_satoshis = msg.channel_reserve_satoshis;
		self.their_htlc_minimum_msat = msg.htlc_minimum_msat;
		self.their_to_self_delay = msg.to_self_delay;
		self.their_max_accepted_htlcs = msg.max_accepted_htlcs;
		self.their_funding_pubkey = Some(msg.funding_pubkey);
		self.their_revocation_basepoint = Some(msg.revocation_basepoint);
		self.their_payment_basepoint = Some(msg.payment_basepoint);
		self.their_delayed_payment_basepoint = Some(msg.delayed_payment_basepoint);
		self.their_htlc_basepoint = Some(msg.htlc_basepoint);
		self.their_cur_commitment_point = Some(msg.first_per_commitment_point);

		let obscure_factor = self.get_commitment_transaction_number_obscure_factor();
		self.channel_monitor.set_commitment_obscure_factor(obscure_factor);
		self.channel_monitor.set_their_to_self_delay(msg.to_self_delay);

		self.channel_state = ChannelState::OurInitSent as u32 | ChannelState::TheirInitSent as u32;

		Ok(())
	}

	fn funding_created_signature(&mut self, sig: &Signature) -> Result<(Transaction, Signature), HandleError> {
		let funding_script = self.get_funding_redeemscript();

		let remote_keys = self.build_remote_transaction_keys()?;
		let remote_initial_commitment_tx = self.build_commitment_transaction(self.cur_remote_commitment_transaction_number, &remote_keys, false, false).0;
		let remote_sighash = Message::from_slice(&bip143::SighashComponents::new(&remote_initial_commitment_tx).sighash_all(&remote_initial_commitment_tx.input[0], &funding_script, self.channel_value_satoshis)[..]).unwrap();

		let local_keys = self.build_local_transaction_keys(self.cur_local_commitment_transaction_number)?;
		let local_initial_commitment_tx = self.build_commitment_transaction(self.cur_local_commitment_transaction_number, &local_keys, true, false).0;
		let local_sighash = Message::from_slice(&bip143::SighashComponents::new(&local_initial_commitment_tx).sighash_all(&local_initial_commitment_tx.input[0], &funding_script, self.channel_value_satoshis)[..]).unwrap();

		// They sign the "local" commitment transaction, allowing us to broadcast the tx if we wish.
		secp_call!(self.secp_ctx.verify(&local_sighash, &sig, &self.their_funding_pubkey.unwrap()), "Invalid funding_created signature from peer");

		// We sign the "remote" commitment transaction, allowing them to broadcast the tx if they wish.
		Ok((remote_initial_commitment_tx, self.secp_ctx.sign(&remote_sighash, &self.local_keys.funding_key)))
	}

	pub fn funding_created(&mut self, msg: &msgs::FundingCreated) -> Result<(msgs::FundingSigned, ChannelMonitor), HandleError> {
		if self.channel_outbound {
			return Err(HandleError{err: "Received funding_created for an outbound channel?", action: None});
		}
		if self.channel_state != (ChannelState::OurInitSent as u32 | ChannelState::TheirInitSent as u32) {
			return Err(HandleError{err: "Received funding_created after we got the channel!", action: None});
		}
		if self.channel_monitor.get_min_seen_secret() != (1 << 48) || self.cur_remote_commitment_transaction_number != (1 << 48) - 1 || self.cur_local_commitment_transaction_number != (1 << 48) - 1 {
			panic!("Should not have advanced channel commitment tx numbers prior to funding_created");
		}

		let funding_txo = OutPoint::new(msg.funding_txid, msg.funding_output_index);
		let funding_txo_script = self.get_funding_redeemscript().to_v0_p2wsh();
		self.channel_monitor.set_funding_info((funding_txo, funding_txo_script));

		let (remote_initial_commitment_tx, our_signature) = match self.funding_created_signature(&msg.signature) {
			Ok(res) => res,
			Err(e) => {
				self.channel_monitor.unset_funding_info();
				return Err(e);
			}
		};

		// Now that we're past error-generating stuff, update our local state:

		self.channel_monitor.provide_latest_remote_commitment_tx_info(&remote_initial_commitment_tx, Vec::new(), self.cur_remote_commitment_transaction_number);
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
	pub fn funding_signed(&mut self, msg: &msgs::FundingSigned) -> Result<ChannelMonitor, HandleError> {
		if !self.channel_outbound {
			return Err(HandleError{err: "Received funding_signed for an inbound channel?", action: None});
		}
		if self.channel_state != ChannelState::FundingCreated as u32 {
			return Err(HandleError{err: "Received funding_signed in strange state!", action: None});
		}
		if self.channel_monitor.get_min_seen_secret() != (1 << 48) || self.cur_remote_commitment_transaction_number != (1 << 48) - 2 || self.cur_local_commitment_transaction_number != (1 << 48) - 1 {
			panic!("Should not have advanced channel commitment tx numbers prior to funding_created");
		}

		let funding_script = self.get_funding_redeemscript();

		let local_keys = self.build_local_transaction_keys(self.cur_local_commitment_transaction_number)?;
		let mut local_initial_commitment_tx = self.build_commitment_transaction(self.cur_local_commitment_transaction_number, &local_keys, true, false).0;
		let local_sighash = Message::from_slice(&bip143::SighashComponents::new(&local_initial_commitment_tx).sighash_all(&local_initial_commitment_tx.input[0], &funding_script, self.channel_value_satoshis)[..]).unwrap();

		// They sign the "local" commitment transaction, allowing us to broadcast the tx if we wish.
		secp_call!(self.secp_ctx.verify(&local_sighash, &msg.signature, &self.their_funding_pubkey.unwrap()), "Invalid funding_signed signature from peer");

		self.sign_commitment_transaction(&mut local_initial_commitment_tx, &msg.signature);
		self.channel_monitor.provide_latest_local_commitment_tx_info(local_initial_commitment_tx.clone(), local_keys, self.feerate_per_kw, Vec::new());
		self.last_local_commitment_txn = vec![local_initial_commitment_tx];
		self.channel_state = ChannelState::FundingSent as u32;
		self.cur_local_commitment_transaction_number -= 1;

		Ok(self.channel_monitor.clone())
	}

	pub fn funding_locked(&mut self, msg: &msgs::FundingLocked) -> Result<(), HandleError> {
		let non_shutdown_state = self.channel_state & (!BOTH_SIDES_SHUTDOWN_MASK);
		if non_shutdown_state == ChannelState::FundingSent as u32 {
			self.channel_state |= ChannelState::TheirFundingLocked as u32;
		} else if non_shutdown_state == (ChannelState::FundingSent as u32 | ChannelState::OurFundingLocked as u32) {
			self.channel_state = ChannelState::ChannelFunded as u32 | (self.channel_state & BOTH_SIDES_SHUTDOWN_MASK);
			self.channel_update_count += 1;
		} else {
			return Err(HandleError{err: "Peer sent a funding_locked at a strange time", action: None});
		}

		self.their_prev_commitment_point = self.their_cur_commitment_point;
		self.their_cur_commitment_point = Some(msg.next_per_commitment_point);
		Ok(())
	}

	/// Returns (inbound_htlc_count, outbound_htlc_count, htlc_outbound_value_msat, htlc_inbound_value_msat)
	/// If its for a remote update check, we need to be more lax about checking against messages we
	/// sent but they may not have received/processed before they sent this message. Further, for
	/// our own sends, we're more conservative and even consider things they've removed against
	/// totals, though there is little reason to outside of further avoiding any race condition
	/// issues.
	fn get_pending_htlc_stats(&self, for_remote_update_check: bool) -> (u32, u32, u64, u64) {
		let mut inbound_htlc_count: u32 = 0;
		let mut outbound_htlc_count: u32 = 0;
		let mut htlc_outbound_value_msat = 0;
		let mut htlc_inbound_value_msat = 0;
		for ref htlc in self.pending_htlcs.iter() {
			match htlc.state {
				HTLCState::RemoteAnnounced => {},
				HTLCState::AwaitingRemoteRevokeToAnnounce => {},
				HTLCState::AwaitingAnnouncedRemoteRevoke => {},
				HTLCState::LocalAnnounced => { if for_remote_update_check { continue; } },
				HTLCState::Committed => {},
				HTLCState::RemoteRemoved => { if for_remote_update_check { continue; } },
				HTLCState::AwaitingRemoteRevokeToRemove => { if for_remote_update_check { continue; } },
				HTLCState::AwaitingRemovedRemoteRevoke => { if for_remote_update_check { continue; } },
				HTLCState::LocalRemoved => {},
				HTLCState::LocalRemovedAwaitingCommitment => { if for_remote_update_check { continue; } },
			}
			if !htlc.outbound {
				inbound_htlc_count += 1;
				htlc_inbound_value_msat += htlc.amount_msat;
			} else {
				outbound_htlc_count += 1;
				htlc_outbound_value_msat += htlc.amount_msat;
			}
		}
		(inbound_htlc_count, outbound_htlc_count, htlc_outbound_value_msat, htlc_inbound_value_msat)
	}

	pub fn update_add_htlc(&mut self, msg: &msgs::UpdateAddHTLC, pending_forward_state: PendingHTLCStatus) -> Result<(), HandleError> {
		if (self.channel_state & (ChannelState::ChannelFunded as u32 | ChannelState::RemoteShutdownSent as u32)) != (ChannelState::ChannelFunded as u32) {
			return Err(HandleError{err: "Got add HTLC message when channel was not in an operational state", action: None});
		}
		if msg.amount_msat > self.channel_value_satoshis * 1000 {
			return Err(HandleError{err: "Remote side tried to send more than the total value of the channel", action: None});
		}
		if msg.amount_msat < self.our_htlc_minimum_msat {
			return Err(HandleError{err: "Remote side tried to send less than our minimum HTLC value", action: None});
		}

		let (inbound_htlc_count, _, htlc_outbound_value_msat, htlc_inbound_value_msat) = self.get_pending_htlc_stats(true);
		if inbound_htlc_count + 1 > OUR_MAX_HTLCS as u32 {
			return Err(HandleError{err: "Remote tried to push more than our max accepted HTLCs", action: None});
		}
		//TODO: Spec is unclear if this is per-direction or in total (I assume per direction):
		// Check our_max_htlc_value_in_flight_msat
		if htlc_inbound_value_msat + msg.amount_msat > Channel::get_our_max_htlc_value_in_flight_msat(self.channel_value_satoshis) {
			return Err(HandleError{err: "Remote HTLC add would put them over their max HTLC value in flight", action: None});
		}
		// Check our_channel_reserve_satoshis (we're getting paid, so they have to at least meet
		// the reserve_satoshis we told them to always have as direct payment so that they lose
		// something if we punish them for broadcasting an old state).
		if htlc_inbound_value_msat + htlc_outbound_value_msat + msg.amount_msat + self.value_to_self_msat > (self.channel_value_satoshis - Channel::get_our_channel_reserve_satoshis(self.channel_value_satoshis)) * 1000 {
			return Err(HandleError{err: "Remote HTLC add would put them over their reserve value", action: None});
		}
		if self.next_remote_htlc_id != msg.htlc_id {
			return Err(HandleError{err: "Remote skipped HTLC ID", action: None});
		}
		if msg.cltv_expiry >= 500000000 {
			return Err(HandleError{err: "Remote provided CLTV expiry in seconds instead of block height", action: None});
		}

		//TODO: Check msg.cltv_expiry further? Do this in channel manager?

		// Now update local state:
		self.next_remote_htlc_id += 1;
		self.pending_htlcs.push(HTLCOutput {
			outbound: false,
			htlc_id: msg.htlc_id,
			amount_msat: msg.amount_msat,
			payment_hash: msg.payment_hash,
			cltv_expiry: msg.cltv_expiry,
			state: HTLCState::RemoteAnnounced,
			fail_reason: None,
			local_removed_fulfilled: false,
			pending_forward_state: Some(pending_forward_state),
		});

		Ok(())
	}

	/// Removes an outbound HTLC which has been commitment_signed by the remote end
	#[inline]
	fn mark_outbound_htlc_removed(&mut self, htlc_id: u64, check_preimage: Option<[u8; 32]>, fail_reason: Option<HTLCFailReason>) -> Result<[u8; 32], HandleError> {
		for htlc in self.pending_htlcs.iter_mut() {
			if htlc.outbound && htlc.htlc_id == htlc_id {
				match check_preimage {
					None => {},
					Some(payment_hash) =>
						if payment_hash != htlc.payment_hash {
							return Err(HandleError{err: "Remote tried to fulfill HTLC with an incorrect preimage", action: None});
						}
				};
				if htlc.state == HTLCState::LocalAnnounced {
					return Err(HandleError{err: "Remote tried to fulfill HTLC before it had been committed", action: None});
				} else if htlc.state == HTLCState::Committed {
					htlc.state = HTLCState::RemoteRemoved;
					htlc.fail_reason = fail_reason;
				} else if htlc.state == HTLCState::AwaitingRemoteRevokeToRemove || htlc.state == HTLCState::AwaitingRemovedRemoteRevoke || htlc.state == HTLCState::RemoteRemoved {
					return Err(HandleError{err: "Remote tried to fulfill HTLC that they'd already fulfilled", action: None});
				} else {
					panic!("Got a non-outbound state on an outbound HTLC");
				}
				return Ok(htlc.payment_hash.clone());
			}
		}
		Err(HandleError{err: "Remote tried to fulfill/fail an HTLC we couldn't find", action: None})
	}

	pub fn update_fulfill_htlc(&mut self, msg: &msgs::UpdateFulfillHTLC) -> Result<(), HandleError> {
		if (self.channel_state & (ChannelState::ChannelFunded as u32)) != (ChannelState::ChannelFunded as u32) {
			return Err(HandleError{err: "Got add HTLC message when channel was not in an operational state", action: None});
		}

		let mut sha = Sha256::new();
		sha.input(&msg.payment_preimage);
		let mut payment_hash = [0; 32];
		sha.result(&mut payment_hash);

		self.mark_outbound_htlc_removed(msg.htlc_id, Some(payment_hash), None)?;
		Ok(())
	}

	pub fn update_fail_htlc(&mut self, msg: &msgs::UpdateFailHTLC, fail_reason: HTLCFailReason) -> Result<[u8; 32], HandleError> {
		if (self.channel_state & (ChannelState::ChannelFunded as u32)) != (ChannelState::ChannelFunded as u32) {
			return Err(HandleError{err: "Got add HTLC message when channel was not in an operational state", action: None});
		}

		self.mark_outbound_htlc_removed(msg.htlc_id, None, Some(fail_reason))
	}

	pub fn update_fail_malformed_htlc(&mut self, msg: &msgs::UpdateFailMalformedHTLC, fail_reason: HTLCFailReason) -> Result<(), HandleError> {
		if (self.channel_state & (ChannelState::ChannelFunded as u32)) != (ChannelState::ChannelFunded as u32) {
			return Err(HandleError{err: "Got add HTLC message when channel was not in an operational state", action: None});
		}

		self.mark_outbound_htlc_removed(msg.htlc_id, None, Some(fail_reason))?;
		Ok(())
	}

	pub fn commitment_signed(&mut self, msg: &msgs::CommitmentSigned) -> Result<(msgs::RevokeAndACK, Option<msgs::CommitmentSigned>, ChannelMonitor), HandleError> {
		if (self.channel_state & (ChannelState::ChannelFunded as u32)) != (ChannelState::ChannelFunded as u32) {
			return Err(HandleError{err: "Got commitment signed message when channel was not in an operational state", action: None});
		}

		let funding_script = self.get_funding_redeemscript();

		let local_keys = self.build_local_transaction_keys(self.cur_local_commitment_transaction_number)?;
		let mut local_commitment_tx = self.build_commitment_transaction(self.cur_local_commitment_transaction_number, &local_keys, true, false);
		let local_commitment_txid = local_commitment_tx.0.txid();
		let local_sighash = Message::from_slice(&bip143::SighashComponents::new(&local_commitment_tx.0).sighash_all(&local_commitment_tx.0.input[0], &funding_script, self.channel_value_satoshis)[..]).unwrap();
		secp_call!(self.secp_ctx.verify(&local_sighash, &msg.signature, &self.their_funding_pubkey.unwrap()), "Invalid commitment tx signature from peer");

		if msg.htlc_signatures.len() != local_commitment_tx.1.len() {
			return Err(HandleError{err: "Got wrong number of HTLC signatures from remote", action: None});
		}

		let mut new_local_commitment_txn = Vec::with_capacity(local_commitment_tx.1.len() + 1);
		self.sign_commitment_transaction(&mut local_commitment_tx.0, &msg.signature);
		new_local_commitment_txn.push(local_commitment_tx.0.clone());

		let mut htlcs_and_sigs = Vec::with_capacity(local_commitment_tx.1.len());
		for (idx, ref htlc) in local_commitment_tx.1.iter().enumerate() {
			let mut htlc_tx = self.build_htlc_transaction(&local_commitment_txid, htlc, true, &local_keys);
			let htlc_redeemscript = chan_utils::get_htlc_redeemscript(&htlc, &local_keys);
			let htlc_sighash = Message::from_slice(&bip143::SighashComponents::new(&htlc_tx).sighash_all(&htlc_tx.input[0], &htlc_redeemscript, htlc.amount_msat / 1000)[..]).unwrap();
			secp_call!(self.secp_ctx.verify(&htlc_sighash, &msg.htlc_signatures[idx], &local_keys.b_htlc_key), "Invalid HTLC tx siganture from peer");
			let htlc_sig = if htlc.offered {
				let htlc_sig = self.sign_htlc_transaction(&mut htlc_tx, &msg.htlc_signatures[idx], &None, htlc, &local_keys)?;
				new_local_commitment_txn.push(htlc_tx);
				htlc_sig
			} else {
				self.create_htlc_tx_signature(&htlc_tx, htlc, &local_keys)?.1
			};
			htlcs_and_sigs.push(((*htlc).clone(), msg.htlc_signatures[idx], htlc_sig));
		}

		let next_per_commitment_point = PublicKey::from_secret_key(&self.secp_ctx, &self.build_local_commitment_secret(self.cur_local_commitment_transaction_number - 1));
		let per_commitment_secret = chan_utils::build_commitment_secret(self.local_keys.commitment_seed, self.cur_local_commitment_transaction_number + 1);

		// Update state now that we've passed all the can-fail calls...
		self.channel_monitor.provide_latest_local_commitment_tx_info(local_commitment_tx.0, local_keys, self.feerate_per_kw, htlcs_and_sigs);

		let mut need_our_commitment = false;
		for htlc in self.pending_htlcs.iter_mut() {
			if htlc.state == HTLCState::RemoteAnnounced {
				htlc.state = HTLCState::AwaitingRemoteRevokeToAnnounce;
				need_our_commitment = true;
			} else if htlc.state == HTLCState::RemoteRemoved {
				htlc.state = HTLCState::AwaitingRemoteRevokeToRemove;
				need_our_commitment = true;
			}
		}
		// Finally delete all the LocalRemovedAwaitingCommitment HTLCs
		// We really shouldnt have two passes here, but retain gives a non-mutable ref (Rust bug)
		let mut claimed_value_msat = 0;
		self.pending_htlcs.retain(|htlc| {
			if htlc.state == HTLCState::LocalRemovedAwaitingCommitment {
				claimed_value_msat += htlc.amount_msat;
				false
			} else { true }
		});
		self.value_to_self_msat += claimed_value_msat;

		self.cur_local_commitment_transaction_number -= 1;
		self.last_local_commitment_txn = new_local_commitment_txn;

		let (our_commitment_signed, monitor_update) = if need_our_commitment && (self.channel_state & (ChannelState::AwaitingRemoteRevoke as u32)) == 0 {
			// If we're AwaitingRemoteRevoke we can't send a new commitment here, but that's ok -
			// we'll send one right away when we get the revoke_and_ack when we
			// free_holding_cell_htlcs().
			let (msg, monitor) = self.send_commitment_no_status_check()?;
			(Some(msg), monitor)
		} else { (None, self.channel_monitor.clone()) };

		Ok((msgs::RevokeAndACK {
			channel_id: self.channel_id,
			per_commitment_secret: per_commitment_secret,
			next_per_commitment_point: next_per_commitment_point,
		}, our_commitment_signed, monitor_update))
	}

	/// Used to fulfill holding_cell_htlcs when we get a remote ack (or implicitly get it by them
	/// fulfilling or failing the last pending HTLC)
	fn free_holding_cell_htlcs(&mut self) -> Result<Option<(msgs::CommitmentUpdate, ChannelMonitor)>, HandleError> {
		if self.holding_cell_htlc_updates.len() != 0 {
			let mut htlc_updates = Vec::new();
			mem::swap(&mut htlc_updates, &mut self.holding_cell_htlc_updates);
			let mut update_add_htlcs = Vec::with_capacity(htlc_updates.len());
			let mut update_fulfill_htlcs = Vec::with_capacity(htlc_updates.len());
			let mut update_fail_htlcs = Vec::with_capacity(htlc_updates.len());
			let mut err = None;
			for htlc_update in htlc_updates.drain(..) {
				// Note that this *can* fail, though it should be due to rather-rare conditions on
				// fee races with adding too many outputs which push our total payments just over
				// the limit. In case its less rare than I anticipate, we may want to revisit
				// handling this case better and maybe fufilling some of the HTLCs while attempting
				// to rebalance channels.
				if err.is_some() { // We're back to AwaitingRemoteRevoke (or are about to fail the channel)
					self.holding_cell_htlc_updates.push(htlc_update);
				} else {
					match &htlc_update {
						&HTLCUpdateAwaitingACK::AddHTLC {amount_msat, cltv_expiry, payment_hash, ref onion_routing_packet, ..} => {
							match self.send_htlc(amount_msat, payment_hash, cltv_expiry, onion_routing_packet.clone()) {
								Ok(update_add_msg_option) => update_add_htlcs.push(update_add_msg_option.unwrap()),
								Err(e) => {
									err = Some(e);
								}
							}
						},
						&HTLCUpdateAwaitingACK::ClaimHTLC { payment_preimage, .. } => {
							match self.get_update_fulfill_htlc(payment_preimage) {
								Ok(update_fulfill_msg_option) => update_fulfill_htlcs.push(update_fulfill_msg_option.0.unwrap()),
								Err(e) => {
									err = Some(e);
								}
							}
						},
						&HTLCUpdateAwaitingACK::FailHTLC { payment_hash, ref err_packet } => {
							match self.get_update_fail_htlc(&payment_hash, err_packet.clone()) {
								Ok(update_fail_msg_option) => update_fail_htlcs.push(update_fail_msg_option.unwrap()),
								Err(e) => {
									err = Some(e);
								}
							}
						},
					}
					if err.is_some() {
						self.holding_cell_htlc_updates.push(htlc_update);
					}
				}
			}
			//TODO: Need to examine the type of err - if its a fee issue or similar we may want to
			//fail it back the route, if its a temporary issue we can ignore it...
			match err {
				None => {
					let (commitment_signed, monitor_update) = self.send_commitment_no_status_check()?;
					Ok(Some((msgs::CommitmentUpdate {
						update_add_htlcs,
						update_fulfill_htlcs,
						update_fail_htlcs,
						update_fail_malformed_htlcs: Vec::new(),
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
	pub fn revoke_and_ack(&mut self, msg: &msgs::RevokeAndACK) -> Result<(Option<msgs::CommitmentUpdate>, Vec<PendingForwardHTLCInfo>, Vec<([u8; 32], HTLCFailReason)>, ChannelMonitor), HandleError> {
		if (self.channel_state & (ChannelState::ChannelFunded as u32)) != (ChannelState::ChannelFunded as u32) {
			return Err(HandleError{err: "Got revoke/ACK message when channel was not in an operational state", action: None});
		}
		if let Some(their_prev_commitment_point) = self.their_prev_commitment_point {
			if PublicKey::from_secret_key(&self.secp_ctx, &secp_call!(SecretKey::from_slice(&self.secp_ctx, &msg.per_commitment_secret), "Peer provided an invalid per_commitment_secret")) != their_prev_commitment_point {
				return Err(HandleError{err: "Got a revoke commitment secret which didn't correspond to their current pubkey", action: None});
			}
		}
		self.channel_monitor.provide_secret(self.cur_remote_commitment_transaction_number + 1, msg.per_commitment_secret, Some((self.cur_remote_commitment_transaction_number - 1, msg.next_per_commitment_point)))?;

		// Update state now that we've passed all the can-fail calls...
		// (note that we may still fail to generate the new commitment_signed message, but that's
		// OK, we step the channel here and *then* if the new generation fails we can fail the
		// channel based on that, but stepping stuff here should be safe either way.
		self.channel_state &= !(ChannelState::AwaitingRemoteRevoke as u32);
		self.their_prev_commitment_point = self.their_cur_commitment_point;
		self.their_cur_commitment_point = Some(msg.next_per_commitment_point);
		self.cur_remote_commitment_transaction_number -= 1;

		let mut to_forward_infos = Vec::new();
		let mut revoked_htlcs = Vec::new();
		let mut update_fail_htlcs = Vec::new();
		let mut update_fail_malformed_htlcs = Vec::new();
		let mut require_commitment = false;
		let mut value_to_self_msat_diff: i64 = 0;
		// We really shouldnt have two passes here, but retain gives a non-mutable ref (Rust bug)
		self.pending_htlcs.retain(|htlc| {
			if htlc.state == HTLCState::LocalRemoved {
				if htlc.local_removed_fulfilled { true } else { false }
			} else if htlc.state == HTLCState::AwaitingRemovedRemoteRevoke {
				if let Some(reason) = htlc.fail_reason.clone() { // We really want take() here, but, again, non-mut ref :(
					revoked_htlcs.push((htlc.payment_hash, reason));
				} else {
					// They fulfilled, so we sent them money
					value_to_self_msat_diff -= htlc.amount_msat as i64;
				}
				false
			} else { true }
		});
		for htlc in self.pending_htlcs.iter_mut() {
			if htlc.state == HTLCState::LocalAnnounced {
				htlc.state = HTLCState::Committed;
			} else if htlc.state == HTLCState::AwaitingRemoteRevokeToAnnounce {
				htlc.state = HTLCState::AwaitingAnnouncedRemoteRevoke;
				require_commitment = true;
			} else if htlc.state == HTLCState::AwaitingAnnouncedRemoteRevoke {
				match htlc.pending_forward_state.take().unwrap() {
					PendingHTLCStatus::Fail(fail_msg) => {
						htlc.state = HTLCState::LocalRemoved;
						require_commitment = true;
						match fail_msg {
							HTLCFailureMsg::Relay(msg) => update_fail_htlcs.push(msg),
							HTLCFailureMsg::Malformed(msg) => update_fail_malformed_htlcs.push(msg),
						}
					},
					PendingHTLCStatus::Forward(forward_info) => {
						to_forward_infos.push(forward_info);
						htlc.state = HTLCState::Committed;
					}
				}
			} else if htlc.state == HTLCState::AwaitingRemoteRevokeToRemove {
				htlc.state = HTLCState::AwaitingRemovedRemoteRevoke;
				require_commitment = true;
			} else if htlc.state == HTLCState::LocalRemoved {
				assert!(htlc.local_removed_fulfilled);
				htlc.state = HTLCState::LocalRemovedAwaitingCommitment;
			}
		}
		self.value_to_self_msat = (self.value_to_self_msat as i64 + value_to_self_msat_diff) as u64;

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
				Ok((Some(commitment_update.0), to_forward_infos, revoked_htlcs, commitment_update.1))
			},
			None => {
				if require_commitment {
					let (commitment_signed, monitor_update) = self.send_commitment_no_status_check()?;
					Ok((Some(msgs::CommitmentUpdate {
						update_add_htlcs: Vec::new(),
						update_fulfill_htlcs: Vec::new(),
						update_fail_htlcs,
						update_fail_malformed_htlcs,
						commitment_signed
					}), to_forward_infos, revoked_htlcs, monitor_update))
				} else {
					Ok((None, to_forward_infos, revoked_htlcs, self.channel_monitor.clone()))
				}
			}
		}
	}

	pub fn update_fee(&mut self, fee_estimator: &FeeEstimator, msg: &msgs::UpdateFee) -> Result<(), HandleError> {
		if self.channel_outbound {
			return Err(HandleError{err: "Non-funding remote tried to update channel fee", action: None});
		}
		Channel::check_remote_fee(fee_estimator, msg.feerate_per_kw)?;
		self.channel_update_count += 1;
		self.feerate_per_kw = msg.feerate_per_kw as u64;
		Ok(())
	}

	pub fn shutdown(&mut self, fee_estimator: &FeeEstimator, msg: &msgs::Shutdown) -> Result<(Option<msgs::Shutdown>, Option<msgs::ClosingSigned>, Vec<[u8; 32]>), HandleError> {
		if self.channel_state < ChannelState::FundingSent as u32 {
			self.channel_state = ChannelState::ShutdownComplete as u32;
			self.channel_update_count += 1;
			return Ok((None, None, Vec::new()));
		}
		for htlc in self.pending_htlcs.iter() {
			if htlc.state == HTLCState::RemoteAnnounced {
				return Err(HandleError{err: "Got shutdown with remote pending HTLCs", action: None});
			}
		}
		if (self.channel_state & ChannelState::RemoteShutdownSent as u32) == ChannelState::RemoteShutdownSent as u32 {
			return Err(HandleError{err: "Remote peer sent duplicate shutdown message", action: None});
		}
		assert_eq!(self.channel_state & ChannelState::ShutdownComplete as u32, 0);

		// BOLT 2 says we must only send a scriptpubkey of certain standard forms, which are up to
		// 34 bytes in length, so dont let the remote peer feed us some super fee-heavy script.
		if self.channel_outbound && msg.scriptpubkey.len() > 34 {
			return Err(HandleError{err: "Got shutdown_scriptpubkey of absurd length from remote peer", action: None});
		}
		//TODO: Check shutdown_scriptpubkey form as BOLT says we must? WHYYY

		if self.their_shutdown_scriptpubkey.is_some() {
			if Some(&msg.scriptpubkey) != self.their_shutdown_scriptpubkey.as_ref() {
				return Err(HandleError{err: "Got shutdown request with a scriptpubkey which did not match their previous scriptpubkey", action: None});
			}
		} else {
			self.their_shutdown_scriptpubkey = Some(msg.scriptpubkey.clone());
		}

		let our_closing_script = self.get_closing_scriptpubkey();

		let (proposed_feerate, proposed_fee, our_sig) = if self.channel_outbound && self.pending_htlcs.is_empty() {
			let mut proposed_feerate = fee_estimator.get_est_sat_per_1000_weight(ConfirmationTarget::Background);
			if self.feerate_per_kw > proposed_feerate {
				proposed_feerate = self.feerate_per_kw;
			}
			let tx_weight = Self::get_closing_transaction_weight(&our_closing_script, &msg.scriptpubkey);
			let proposed_total_fee_satoshis = proposed_feerate * tx_weight / 1000;

			let (closing_tx, total_fee_satoshis) = self.build_closing_transaction(proposed_total_fee_satoshis, false);
			let funding_redeemscript = self.get_funding_redeemscript();
			let sighash = Message::from_slice(&bip143::SighashComponents::new(&closing_tx).sighash_all(&closing_tx.input[0], &funding_redeemscript, self.channel_value_satoshis)[..]).unwrap();

			(Some(proposed_feerate), Some(total_fee_satoshis), Some(self.secp_ctx.sign(&sighash, &self.local_keys.funding_key)))
		} else { (None, None, None) };

		// From here on out, we may not fail!

		self.channel_state |= ChannelState::RemoteShutdownSent as u32;
		self.channel_update_count += 1;

		// We can't send our shutdown until we've committed all of our pending HTLCs, but the
		// remote side is unlikely to accept any new HTLCs, so we go ahead and "free" any holding
		// cell HTLCs and return them to fail the payment.
		let mut dropped_outbound_htlcs = Vec::with_capacity(self.holding_cell_htlc_updates.len());
		self.holding_cell_htlc_updates.retain(|htlc_update| {
			match htlc_update {
				&HTLCUpdateAwaitingACK::AddHTLC { ref payment_hash, .. } => {
					dropped_outbound_htlcs.push(payment_hash.clone());
					false
				},
				_ => true
			}
		});
		for htlc in self.pending_htlcs.iter() {
			if htlc.state == HTLCState::LocalAnnounced {
				return Ok((None, None, dropped_outbound_htlcs));
			}
		}

		let our_shutdown = if (self.channel_state & ChannelState::LocalShutdownSent as u32) == ChannelState::LocalShutdownSent as u32 {
			None
		} else {
			Some(msgs::Shutdown {
				channel_id: self.channel_id,
				scriptpubkey: our_closing_script,
			})
		};

		self.channel_state |= ChannelState::LocalShutdownSent as u32;
		self.channel_update_count += 1;
		if self.pending_htlcs.is_empty() && self.channel_outbound {
			// There are no more HTLCs and we're the funder, this means we start the closing_signed
			// dance with an initial fee proposal!
			self.last_sent_closing_fee = Some((proposed_feerate.unwrap(), proposed_fee.unwrap()));
			Ok((our_shutdown, Some(msgs::ClosingSigned {
				channel_id: self.channel_id,
				fee_satoshis: proposed_fee.unwrap(),
				signature: our_sig.unwrap(),
			}), dropped_outbound_htlcs))
		} else {
			Ok((our_shutdown, None, dropped_outbound_htlcs))
		}
	}

	pub fn closing_signed(&mut self, fee_estimator: &FeeEstimator, msg: &msgs::ClosingSigned) -> Result<(Option<msgs::ClosingSigned>, Option<Transaction>), HandleError> {
		if self.channel_state & BOTH_SIDES_SHUTDOWN_MASK != BOTH_SIDES_SHUTDOWN_MASK {
			return Err(HandleError{err: "Remote end sent us a closing_signed before both sides provided a shutdown", action: None});
		}
		if !self.pending_htlcs.is_empty() {
			return Err(HandleError{err: "Remote end sent us a closing_signed while there were still pending HTLCs", action: None});
		}
		if msg.fee_satoshis > 21000000 * 10000000 {
			return Err(HandleError{err: "Remote tried to send us a closing tx with > 21 million BTC fee", action: None});
		}

		let funding_redeemscript = self.get_funding_redeemscript();
		let (mut closing_tx, used_total_fee) = self.build_closing_transaction(msg.fee_satoshis, false);
		if used_total_fee != msg.fee_satoshis {
			return Err(HandleError{err: "Remote sent us a closing_signed with a fee greater than the value they can claim", action: None});
		}
		let mut sighash = Message::from_slice(&bip143::SighashComponents::new(&closing_tx).sighash_all(&closing_tx.input[0], &funding_redeemscript, self.channel_value_satoshis)[..]).unwrap();

		match self.secp_ctx.verify(&sighash, &msg.signature, &self.their_funding_pubkey.unwrap()) {
			Ok(_) => {},
			Err(_e) => {
				// The remote end may have decided to revoke their output due to inconsistent dust
				// limits, so check for that case by re-checking the signature here.
				closing_tx = self.build_closing_transaction(msg.fee_satoshis, true).0;
				sighash = Message::from_slice(&bip143::SighashComponents::new(&closing_tx).sighash_all(&closing_tx.input[0], &funding_redeemscript, self.channel_value_satoshis)[..]).unwrap();
				secp_call!(self.secp_ctx.verify(&sighash, &msg.signature, &self.their_funding_pubkey.unwrap()), "Invalid closing tx signature from peer");
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
				sighash = Message::from_slice(&bip143::SighashComponents::new(&closing_tx).sighash_all(&closing_tx.input[0], &funding_redeemscript, self.channel_value_satoshis)[..]).unwrap();
				let our_sig = self.secp_ctx.sign(&sighash, &self.local_keys.funding_key);
				self.last_sent_closing_fee = Some(($new_feerate, used_total_fee));
				return Ok((Some(msgs::ClosingSigned {
					channel_id: self.channel_id,
					fee_satoshis: used_total_fee,
					signature: our_sig,
				}), None))
			}
		}

		let proposed_sat_per_kw = msg.fee_satoshis * 1000 / closing_tx.get_weight();
		if self.channel_outbound {
			let our_max_feerate = fee_estimator.get_est_sat_per_1000_weight(ConfirmationTarget::Normal);
			if proposed_sat_per_kw > our_max_feerate {
				if let Some((last_feerate, _)) = self.last_sent_closing_fee {
					if our_max_feerate <= last_feerate {
						return Err(HandleError{err: "Unable to come to consensus about closing feerate, remote wanted something higher than our Normal feerate", action: None});
					}
				}
				propose_new_feerate!(our_max_feerate);
			}
		} else {
			let our_min_feerate = fee_estimator.get_est_sat_per_1000_weight(ConfirmationTarget::Background);
			if proposed_sat_per_kw < our_min_feerate {
				if let Some((last_feerate, _)) = self.last_sent_closing_fee {
					if our_min_feerate >= last_feerate {
						return Err(HandleError{err: "Unable to come to consensus about closing feerate, remote wanted something lower than our Background feerate", action: None});
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

	pub fn get_value_satoshis(&self) -> u64 {
		self.channel_value_satoshis
	}

	//TODO: Testing purpose only, should be changed in another way after #81
	#[cfg(test)]
	pub fn get_local_keys(&self) -> &ChannelKeys {
		&self.local_keys
	}

	/// Allowed in any state (including after shutdown)
	pub fn get_channel_update_count(&self) -> u32 {
		self.channel_update_count
	}

	pub fn should_announce(&self) -> bool {
		self.announce_publicly
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
		self.is_usable()
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
	pub fn block_connected(&mut self, header: &BlockHeader, height: u32, txn_matched: &[&Transaction], indexes_of_txn_matched: &[u32]) -> Result<Option<msgs::FundingLocked>, HandleError> {
		let non_shutdown_state = self.channel_state & (!BOTH_SIDES_SHUTDOWN_MASK);
		if self.funding_tx_confirmations > 0 {
			if header.bitcoin_hash() != self.last_block_connected {
				self.last_block_connected = header.bitcoin_hash();
				self.funding_tx_confirmations += 1;
				if self.funding_tx_confirmations == Channel::derive_minimum_depth(self.channel_value_satoshis*1000, self.value_to_self_msat) as u64 {
					let need_commitment_update = if non_shutdown_state == ChannelState::FundingSent as u32 {
						self.channel_state |= ChannelState::OurFundingLocked as u32;
						true
					} else if non_shutdown_state == (ChannelState::FundingSent as u32 | ChannelState::TheirFundingLocked as u32) {
						self.channel_state = ChannelState::ChannelFunded as u32 | (self.channel_state & BOTH_SIDES_SHUTDOWN_MASK);
						self.channel_update_count += 1;
						true
					} else if self.channel_state == (ChannelState::FundingSent as u32 | ChannelState::OurFundingLocked as u32) {
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
						let next_per_commitment_secret = self.build_local_commitment_secret(self.cur_local_commitment_transaction_number);
						let next_per_commitment_point = PublicKey::from_secret_key(&self.secp_ctx, &next_per_commitment_secret);
						return Ok(Some(msgs::FundingLocked {
							channel_id: self.channel_id,
							next_per_commitment_point: next_per_commitment_point,
						}));
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
						return Err(HandleError{err: "funding tx had wrong script/value", action: Some(ErrorAction::DisconnectPeer{msg: None})});
					} else {
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
			self.funding_tx_confirmations = Channel::derive_minimum_depth(self.channel_value_satoshis*1000, self.value_to_self_msat) as u64 - 1;
		}
		false
	}

	// Methods to get unprompted messages to send to the remote end (or where we already returned
	// something in the handler for the message that prompted this message):

	pub fn get_open_channel(&self, chain_hash: Sha256dHash, fee_estimator: &FeeEstimator) -> Result<msgs::OpenChannel, APIError> {
		if !self.channel_outbound {
			panic!("Tried to open a channel for an inbound channel?");
		}
		if self.channel_state != ChannelState::OurInitSent as u32 {
			panic!("Cannot generate an open_channel after we've moved forward");
		}

		if self.cur_local_commitment_transaction_number != (1 << 48) - 1 {
			panic!("Tried to send an open_channel for a channel that has already advanced");
		}

		let local_commitment_secret = self.build_local_commitment_secret(self.cur_local_commitment_transaction_number);

		Ok(msgs::OpenChannel {
			chain_hash: chain_hash,
			temporary_channel_id: self.channel_id,
			funding_satoshis: self.channel_value_satoshis,
			push_msat: self.channel_value_satoshis * 1000 - self.value_to_self_msat,
			dust_limit_satoshis: self.our_dust_limit_satoshis,
			max_htlc_value_in_flight_msat: Channel::get_our_max_htlc_value_in_flight_msat(self.channel_value_satoshis),
			channel_reserve_satoshis: Channel::get_our_channel_reserve_satoshis(self.channel_value_satoshis),
			htlc_minimum_msat: self.our_htlc_minimum_msat,
			feerate_per_kw: fee_estimator.get_est_sat_per_1000_weight(ConfirmationTarget::Background) as u32,
			to_self_delay: BREAKDOWN_TIMEOUT,
			max_accepted_htlcs: OUR_MAX_HTLCS,
			funding_pubkey: PublicKey::from_secret_key(&self.secp_ctx, &self.local_keys.funding_key),
			revocation_basepoint: PublicKey::from_secret_key(&self.secp_ctx, &self.local_keys.revocation_base_key),
			payment_basepoint: PublicKey::from_secret_key(&self.secp_ctx, &self.local_keys.payment_base_key),
			delayed_payment_basepoint: PublicKey::from_secret_key(&self.secp_ctx, &self.local_keys.delayed_payment_base_key),
			htlc_basepoint: PublicKey::from_secret_key(&self.secp_ctx, &self.local_keys.htlc_base_key),
			first_per_commitment_point: PublicKey::from_secret_key(&self.secp_ctx, &local_commitment_secret),
			channel_flags: if self.announce_publicly {1} else {0},
			shutdown_scriptpubkey: None,
		})
	}

	pub fn get_accept_channel(&self) -> Result<msgs::AcceptChannel, HandleError> {
		if self.channel_outbound {
			panic!("Tried to send accept_channel for an outbound channel?");
		}
		if self.channel_state != (ChannelState::OurInitSent as u32) | (ChannelState::TheirInitSent as u32) {
			panic!("Tried to send accept_channel after channel had moved forward");
		}
		if self.cur_local_commitment_transaction_number != (1 << 48) - 1 {
			panic!("Tried to send an accept_channel for a channel that has already advanced");
		}

		let local_commitment_secret = self.build_local_commitment_secret(self.cur_local_commitment_transaction_number);

		Ok(msgs::AcceptChannel {
			temporary_channel_id: self.channel_id,
			dust_limit_satoshis: self.our_dust_limit_satoshis,
			max_htlc_value_in_flight_msat: Channel::get_our_max_htlc_value_in_flight_msat(self.channel_value_satoshis),
			channel_reserve_satoshis: Channel::get_our_channel_reserve_satoshis(self.channel_value_satoshis),
			htlc_minimum_msat: self.our_htlc_minimum_msat,
			minimum_depth: Channel::derive_minimum_depth(self.channel_value_satoshis*1000, self.value_to_self_msat),
			to_self_delay: BREAKDOWN_TIMEOUT,
			max_accepted_htlcs: OUR_MAX_HTLCS,
			funding_pubkey: PublicKey::from_secret_key(&self.secp_ctx, &self.local_keys.funding_key),
			revocation_basepoint: PublicKey::from_secret_key(&self.secp_ctx, &self.local_keys.revocation_base_key),
			payment_basepoint: PublicKey::from_secret_key(&self.secp_ctx, &self.local_keys.payment_base_key),
			delayed_payment_basepoint: PublicKey::from_secret_key(&self.secp_ctx, &self.local_keys.delayed_payment_base_key),
			htlc_basepoint: PublicKey::from_secret_key(&self.secp_ctx, &self.local_keys.htlc_base_key),
			first_per_commitment_point: PublicKey::from_secret_key(&self.secp_ctx, &local_commitment_secret),
			shutdown_scriptpubkey: None,
		})
	}

	fn get_outbound_funding_created_signature(&mut self) -> Result<(Signature, Transaction), HandleError> {
		let funding_script = self.get_funding_redeemscript();

		let remote_keys = self.build_remote_transaction_keys()?;
		let remote_initial_commitment_tx = self.build_commitment_transaction(self.cur_remote_commitment_transaction_number, &remote_keys, false, false).0;
		let remote_sighash = Message::from_slice(&bip143::SighashComponents::new(&remote_initial_commitment_tx).sighash_all(&remote_initial_commitment_tx.input[0], &funding_script, self.channel_value_satoshis)[..]).unwrap();

		// We sign the "remote" commitment transaction, allowing them to broadcast the tx if they wish.
		Ok((self.secp_ctx.sign(&remote_sighash, &self.local_keys.funding_key), remote_initial_commitment_tx))
	}

	/// Updates channel state with knowledge of the funding transaction's txid/index, and generates
	/// a funding_created message for the remote peer.
	/// Panics if called at some time other than immediately after initial handshake, if called twice,
	/// or if called on an inbound channel.
	/// Note that channel_id changes during this call!
	/// Do NOT broadcast the funding transaction until after a successful funding_signed call!
	pub fn get_outbound_funding_created(&mut self, funding_txo: OutPoint) -> Result<(msgs::FundingCreated, ChannelMonitor), HandleError> {
		if !self.channel_outbound {
			panic!("Tried to create outbound funding_created message on an inbound channel!");
		}
		if self.channel_state != (ChannelState::OurInitSent as u32 | ChannelState::TheirInitSent as u32) {
			panic!("Tried to get a funding_created messsage at a time other than immediately after initial handshake completion (or tried to get funding_created twice)");
		}
		if self.channel_monitor.get_min_seen_secret() != (1 << 48) || self.cur_remote_commitment_transaction_number != (1 << 48) - 1 || self.cur_local_commitment_transaction_number != (1 << 48) - 1 {
			panic!("Should not have advanced channel commitment tx numbers prior to funding_created");
		}

		let funding_txo_script = self.get_funding_redeemscript().to_v0_p2wsh();
		self.channel_monitor.set_funding_info((funding_txo, funding_txo_script));

		let (our_signature, commitment_tx) = match self.get_outbound_funding_created_signature() {
			Ok(res) => res,
			Err(e) => {
				log_error!(self, "Got bad signatures: {}!", e.err);
				self.channel_monitor.unset_funding_info();
				return Err(e);
			}
		};

		let temporary_channel_id = self.channel_id;

		// Now that we're past error-generating stuff, update our local state:
		self.channel_monitor.provide_latest_remote_commitment_tx_info(&commitment_tx, Vec::new(), self.cur_remote_commitment_transaction_number);
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
	pub fn get_channel_announcement(&self, our_node_id: PublicKey, chain_hash: Sha256dHash) -> Result<(msgs::UnsignedChannelAnnouncement, Signature), HandleError> {
		if !self.announce_publicly {
			return Err(HandleError{err: "Channel is not available for public announcements", action: None});
		}
		if self.channel_state & (ChannelState::ChannelFunded as u32) == 0 {
			return Err(HandleError{err: "Cannot get a ChannelAnnouncement until the channel funding has been locked", action: None});
		}
		if (self.channel_state & (ChannelState::LocalShutdownSent as u32 | ChannelState::ShutdownComplete as u32)) != 0 {
			return Err(HandleError{err: "Cannot get a ChannelAnnouncement once the channel is closing", action: None});
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

		let msghash = Message::from_slice(&Sha256dHash::from_data(&msg.encode()[..])[..]).unwrap();
		let sig = self.secp_ctx.sign(&msghash, &self.local_keys.funding_key);

		Ok((msg, sig))
	}


	// Send stuff to our remote peers:

	/// Adds a pending outbound HTLC to this channel, note that you probably want
	/// send_htlc_and_commit instead cause you'll want both messages at once.
	/// This returns an option instead of a pure UpdateAddHTLC as we may be in a state where we are
	/// waiting on the remote peer to send us a revoke_and_ack during which time we cannot add new
	/// HTLCs on the wire or we wouldn't be able to determine what they actually ACK'ed.
	pub fn send_htlc(&mut self, amount_msat: u64, payment_hash: [u8; 32], cltv_expiry: u32, onion_routing_packet: msgs::OnionPacket) -> Result<Option<msgs::UpdateAddHTLC>, HandleError> {
		if (self.channel_state & (ChannelState::ChannelFunded as u32 | BOTH_SIDES_SHUTDOWN_MASK)) != (ChannelState::ChannelFunded as u32) {
			return Err(HandleError{err: "Cannot send HTLC until channel is fully established and we haven't started shutting down", action: None});
		}

		if amount_msat > self.channel_value_satoshis * 1000 {
			return Err(HandleError{err: "Cannot send more than the total value of the channel", action: None});
		}
		if amount_msat < self.their_htlc_minimum_msat {
			return Err(HandleError{err: "Cannot send less than their minimum HTLC value", action: None});
		}

		let (_, outbound_htlc_count, htlc_outbound_value_msat, htlc_inbound_value_msat) = self.get_pending_htlc_stats(false);
		if outbound_htlc_count + 1 > self.their_max_accepted_htlcs as u32 {
			return Err(HandleError{err: "Cannot push more than their max accepted HTLCs", action: None});
		}
		//TODO: Spec is unclear if this is per-direction or in total (I assume per direction):
		// Check their_max_htlc_value_in_flight_msat
		if htlc_outbound_value_msat + amount_msat > self.their_max_htlc_value_in_flight_msat {
			return Err(HandleError{err: "Cannot send value that would put us over our max HTLC value in flight", action: None});
		}
		// Check their_channel_reserve_satoshis:
		if htlc_inbound_value_msat + htlc_outbound_value_msat + amount_msat + (self.channel_value_satoshis * 1000 - self.value_to_self_msat) > (self.channel_value_satoshis - self.their_channel_reserve_satoshis) * 1000 {
			return Err(HandleError{err: "Cannot send value that would put us over our reserve value", action: None});
		}

		//TODO: Check cltv_expiry? Do this in channel manager?

		// Now update local state:
		if (self.channel_state & (ChannelState::AwaitingRemoteRevoke as u32)) == (ChannelState::AwaitingRemoteRevoke as u32) {
			//TODO: Check the limits *including* other pending holding cell HTLCs!
			self.holding_cell_htlc_updates.push(HTLCUpdateAwaitingACK::AddHTLC {
				amount_msat: amount_msat,
				payment_hash: payment_hash,
				cltv_expiry: cltv_expiry,
				onion_routing_packet: onion_routing_packet,
				time_created: Instant::now(),
			});
			return Ok(None);
		}

		self.pending_htlcs.push(HTLCOutput {
			outbound: true,
			htlc_id: self.next_local_htlc_id,
			amount_msat: amount_msat,
			payment_hash: payment_hash.clone(),
			cltv_expiry: cltv_expiry,
			state: HTLCState::LocalAnnounced,
			fail_reason: None,
			local_removed_fulfilled: false,
			pending_forward_state: None
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
	pub fn send_commitment(&mut self) -> Result<(msgs::CommitmentSigned, ChannelMonitor), HandleError> {
		if (self.channel_state & (ChannelState::ChannelFunded as u32)) != (ChannelState::ChannelFunded as u32) {
			return Err(HandleError{err: "Cannot create commitment tx until channel is fully established", action: None});
		}
		if (self.channel_state & (ChannelState::AwaitingRemoteRevoke as u32)) == (ChannelState::AwaitingRemoteRevoke as u32) {
			return Err(HandleError{err: "Cannot create commitment tx until remote revokes their previous commitment", action: None});
		}
		let mut have_updates = false; // TODO initialize with "have we sent a fee update?"
		for htlc in self.pending_htlcs.iter() {
			if htlc.state == HTLCState::LocalAnnounced {
				have_updates = true;
			}
			if have_updates { break; }
		}
		if !have_updates {
			return Err(HandleError{err: "Cannot create commitment tx until we have some updates to send", action: None});
		}
		self.send_commitment_no_status_check()
	}
	/// Only fails in case of bad keys
	fn send_commitment_no_status_check(&mut self) -> Result<(msgs::CommitmentSigned, ChannelMonitor), HandleError> {
		let funding_script = self.get_funding_redeemscript();

		// We can upgrade the status of some HTLCs that are waiting on a commitment, even if we
		// fail to generate this, we still are at least at a position where upgrading their status
		// is acceptable.
		for htlc in self.pending_htlcs.iter_mut() {
			if htlc.state == HTLCState::AwaitingRemoteRevokeToAnnounce {
				htlc.state = HTLCState::AwaitingAnnouncedRemoteRevoke;
			} else if htlc.state == HTLCState::AwaitingRemoteRevokeToRemove {
				htlc.state = HTLCState::AwaitingRemovedRemoteRevoke;
			}
		}

		let remote_keys = self.build_remote_transaction_keys()?;
		let remote_commitment_tx = self.build_commitment_transaction(self.cur_remote_commitment_transaction_number, &remote_keys, false, true);
		let remote_commitment_txid = remote_commitment_tx.0.txid();
		let remote_sighash = Message::from_slice(&bip143::SighashComponents::new(&remote_commitment_tx.0).sighash_all(&remote_commitment_tx.0.input[0], &funding_script, self.channel_value_satoshis)[..]).unwrap();
		let our_sig = self.secp_ctx.sign(&remote_sighash, &self.local_keys.funding_key);

		let mut htlc_sigs = Vec::new();

		for ref htlc in remote_commitment_tx.1.iter() {
			let htlc_tx = self.build_htlc_transaction(&remote_commitment_txid, htlc, false, &remote_keys);
			let htlc_redeemscript = chan_utils::get_htlc_redeemscript(&htlc, &remote_keys);
			let htlc_sighash = Message::from_slice(&bip143::SighashComponents::new(&htlc_tx).sighash_all(&htlc_tx.input[0], &htlc_redeemscript, htlc.amount_msat / 1000)[..]).unwrap();
			let our_htlc_key = secp_derived_key!(chan_utils::derive_private_key(&self.secp_ctx, &remote_keys.per_commitment_point, &self.local_keys.htlc_base_key));
			htlc_sigs.push(self.secp_ctx.sign(&htlc_sighash, &our_htlc_key));
		}

		// Update state now that we've passed all the can-fail calls...
		self.channel_monitor.provide_latest_remote_commitment_tx_info(&remote_commitment_tx.0, remote_commitment_tx.1, self.cur_remote_commitment_transaction_number);
		self.channel_state |= ChannelState::AwaitingRemoteRevoke as u32;

		Ok((msgs::CommitmentSigned {
			channel_id: self.channel_id,
			signature: our_sig,
			htlc_signatures: htlc_sigs,
		}, self.channel_monitor.clone()))
	}

	/// Adds a pending outbound HTLC to this channel, and creates a signed commitment transaction
	/// to send to the remote peer in one go.
	/// Shorthand for calling send_htlc() followed by send_commitment(), see docs on those for
	/// more info.
	pub fn send_htlc_and_commit(&mut self, amount_msat: u64, payment_hash: [u8; 32], cltv_expiry: u32, onion_routing_packet: msgs::OnionPacket) -> Result<Option<(msgs::UpdateAddHTLC, msgs::CommitmentSigned, ChannelMonitor)>, HandleError> {
		match self.send_htlc(amount_msat, payment_hash, cltv_expiry, onion_routing_packet)? {
			Some(update_add_htlc) => {
				let (commitment_signed, monitor_update) = self.send_commitment_no_status_check()?;
				Ok(Some((update_add_htlc, commitment_signed, monitor_update)))
			},
			None => Ok(None)
		}
	}

	/// Begins the shutdown process, getting a message for the remote peer and returning all
	/// holding cell HTLCs for payment failure.
	pub fn get_shutdown(&mut self) -> Result<(msgs::Shutdown, Vec<[u8; 32]>), HandleError> {
		for htlc in self.pending_htlcs.iter() {
			if htlc.state == HTLCState::LocalAnnounced {
				return Err(HandleError{err: "Cannot begin shutdown with pending HTLCs, call send_commitment first", action: None});
			}
		}
		if self.channel_state & BOTH_SIDES_SHUTDOWN_MASK != 0 {
			return Err(HandleError{err: "Shutdown already in progress", action: None});
		}
		assert_eq!(self.channel_state & ChannelState::ShutdownComplete as u32, 0);

		let our_closing_script = self.get_closing_scriptpubkey();

		// From here on out, we may not fail!
		if self.channel_state < ChannelState::FundingSent as u32 {
			self.channel_state = ChannelState::ShutdownComplete as u32;
		} else {
			self.channel_state |= ChannelState::LocalShutdownSent as u32;
		}
		self.channel_update_count += 1;

		// We can't send our shutdown until we've committed all of our pending HTLCs, but the
		// remote side is unlikely to accept any new HTLCs, so we go ahead and "free" any holding
		// cell HTLCs and return them to fail the payment.
		let mut dropped_outbound_htlcs = Vec::with_capacity(self.holding_cell_htlc_updates.len());
		self.holding_cell_htlc_updates.retain(|htlc_update| {
			match htlc_update {
				&HTLCUpdateAwaitingACK::AddHTLC { ref payment_hash, .. } => {
					dropped_outbound_htlcs.push(payment_hash.clone());
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

	/// Gets the latest commitment transaction and any dependant transactions for relay (forcing
	/// shutdown of this channel - no more calls into this Channel may be made afterwards except
	/// those explicitly stated to be allowed after shutdown completes, eg some simple getters).
	/// Also returns the list of payment_hashes for channels which we can safely fail backwards
	/// immediately (others we will have to allow to time out).
	pub fn force_shutdown(&mut self) -> (Vec<Transaction>, Vec<[u8; 32]>) {
		assert!(self.channel_state != ChannelState::ShutdownComplete as u32);

		// We go ahead and "free" any holding cell HTLCs or HTLCs we haven't yet committed to and
		// return them to fail the payment.
		let mut dropped_outbound_htlcs = Vec::with_capacity(self.holding_cell_htlc_updates.len());
		for htlc_update in self.holding_cell_htlc_updates.drain(..) {
			match htlc_update {
				HTLCUpdateAwaitingACK::AddHTLC { payment_hash, .. } => {
					dropped_outbound_htlcs.push(payment_hash);
				},
				_ => {}
			}
		}

		for htlc in self.pending_htlcs.drain(..) {
			if htlc.state == HTLCState::LocalAnnounced {
				dropped_outbound_htlcs.push(htlc.payment_hash);
			}
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

#[cfg(test)]
mod tests {
	use bitcoin::util::hash::Sha256dHash;
	use bitcoin::util::bip143;
	use bitcoin::network::serialize::serialize;
	use bitcoin::blockdata::script::Script;
	use bitcoin::blockdata::transaction::Transaction;
	use hex;
	use ln::channel::{Channel,ChannelKeys,HTLCOutput,HTLCState,HTLCOutputInCommitment,TxCreationKeys};
	use ln::channel::MAX_FUNDING_SATOSHIS;
	use ln::chan_utils;
	use chain::chaininterface::{FeeEstimator,ConfirmationTarget};
	use chain::transaction::OutPoint;
	use util::test_utils;
	use util::logger::Logger;
	use secp256k1::{Secp256k1,Message,Signature};
	use secp256k1::key::{SecretKey,PublicKey};
	use crypto::sha2::Sha256;
	use crypto::digest::Digest;
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
		        "MAX_FUNDING_SATOSHIS is greater than all satoshis on existence");
	}

	#[test]
	fn outbound_commitment_test() {
		// Test vectors from BOLT 3 Appendix C:
		let feeest = TestFeeEstimator{fee_est: 15000};
		let logger : Arc<Logger> = Arc::new(test_utils::TestLogger::new());
		let secp_ctx = Secp256k1::new();

		let chan_keys = ChannelKeys {
			funding_key: SecretKey::from_slice(&secp_ctx, &hex::decode("30ff4956bbdd3222d44cc5e8a1261dab1e07957bdac5ae88fe3261ef321f3749").unwrap()[..]).unwrap(),
			payment_base_key: SecretKey::from_slice(&secp_ctx, &hex::decode("1111111111111111111111111111111111111111111111111111111111111111").unwrap()[..]).unwrap(),
			delayed_payment_base_key: SecretKey::from_slice(&secp_ctx, &hex::decode("3333333333333333333333333333333333333333333333333333333333333333").unwrap()[..]).unwrap(),
			htlc_base_key: SecretKey::from_slice(&secp_ctx, &hex::decode("1111111111111111111111111111111111111111111111111111111111111111").unwrap()[..]).unwrap(),

			// These aren't set in the test vectors:
			revocation_base_key: SecretKey::from_slice(&secp_ctx, &hex::decode("0fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").unwrap()[..]).unwrap(),
			channel_close_key: SecretKey::from_slice(&secp_ctx, &hex::decode("0fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").unwrap()[..]).unwrap(),
			channel_monitor_claim_key: SecretKey::from_slice(&secp_ctx, &hex::decode("0fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").unwrap()[..]).unwrap(),
			commitment_seed: [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
		};
		assert_eq!(PublicKey::from_secret_key(&secp_ctx, &chan_keys.funding_key).serialize()[..],
				hex::decode("023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb").unwrap()[..]);

		let their_node_id = PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&secp_ctx, &[42; 32]).unwrap());
		let mut chan = Channel::new_outbound(&feeest, chan_keys, their_node_id, 10000000, 100000, false, 42, Arc::clone(&logger)).unwrap(); // Nothing uses their network key in this test
		chan.their_to_self_delay = 144;
		chan.our_dust_limit_satoshis = 546;

		let funding_info = OutPoint::new(Sha256dHash::from_hex("8984484a580b825b9972d7adb15050b3ab624ccd731946b3eeddb92f4e7ef6be").unwrap(), 0);
		chan.channel_monitor.set_funding_info((funding_info, Script::new()));

		chan.their_payment_basepoint = Some(PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&secp_ctx, &hex::decode("4444444444444444444444444444444444444444444444444444444444444444").unwrap()[..]).unwrap()));
		assert_eq!(chan.their_payment_basepoint.unwrap().serialize()[..],
				hex::decode("032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991").unwrap()[..]);

		chan.their_funding_pubkey = Some(PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&secp_ctx, &hex::decode("1552dfba4f6cf29a62a0af13c8d6981d36d0ef8d61ba10fb0fe90da7634d7e13").unwrap()[..]).unwrap()));
		assert_eq!(chan.their_funding_pubkey.unwrap().serialize()[..],
				hex::decode("030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c1").unwrap()[..]);

		chan.their_htlc_basepoint = Some(PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&secp_ctx, &hex::decode("4444444444444444444444444444444444444444444444444444444444444444").unwrap()[..]).unwrap()));
		assert_eq!(chan.their_htlc_basepoint.unwrap().serialize()[..],
				hex::decode("032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991").unwrap()[..]);

		chan.their_revocation_basepoint = Some(PublicKey::from_slice(&secp_ctx, &hex::decode("02466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27").unwrap()[..]).unwrap());

		// We can't just use build_local_transaction_keys here as the per_commitment_secret is not
		// derived from a commitment_seed, so instead we copy it here and call
		// build_commitment_transaction.
		let delayed_payment_base = PublicKey::from_secret_key(&secp_ctx, &chan.local_keys.delayed_payment_base_key);
		let per_commitment_secret = SecretKey::from_slice(&secp_ctx, &hex::decode("1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100").unwrap()[..]).unwrap();
		let per_commitment_point = PublicKey::from_secret_key(&secp_ctx, &per_commitment_secret);
		let htlc_basepoint = PublicKey::from_secret_key(&secp_ctx, &chan.local_keys.htlc_base_key);
		let keys = TxCreationKeys::new(&secp_ctx, &per_commitment_point, &delayed_payment_base, &htlc_basepoint, &chan.their_revocation_basepoint.unwrap(), &chan.their_payment_basepoint.unwrap(), &chan.their_htlc_basepoint.unwrap()).unwrap();

		let mut unsigned_tx: (Transaction, Vec<HTLCOutputInCommitment>);

		macro_rules! test_commitment {
			( $their_sig_hex: expr, $our_sig_hex: expr, $tx_hex: expr) => {
				unsigned_tx = chan.build_commitment_transaction(0xffffffffffff - 42, &keys, true, false);
				let their_signature = Signature::from_der(&secp_ctx, &hex::decode($their_sig_hex).unwrap()[..]).unwrap();
				let sighash = Message::from_slice(&bip143::SighashComponents::new(&unsigned_tx.0).sighash_all(&unsigned_tx.0.input[0], &chan.get_funding_redeemscript(), chan.channel_value_satoshis)[..]).unwrap();
				secp_ctx.verify(&sighash, &their_signature, &chan.their_funding_pubkey.unwrap()).unwrap();

				chan.sign_commitment_transaction(&mut unsigned_tx.0, &their_signature);

				assert_eq!(serialize(&unsigned_tx.0).unwrap()[..],
						hex::decode($tx_hex).unwrap()[..]);
			};
		}

		macro_rules! test_htlc_output {
			( $htlc_idx: expr, $their_sig_hex: expr, $our_sig_hex: expr, $tx_hex: expr ) => {
				let remote_signature = Signature::from_der(&secp_ctx, &hex::decode($their_sig_hex).unwrap()[..]).unwrap();

				let ref htlc = unsigned_tx.1[$htlc_idx];
				let mut htlc_tx = chan.build_htlc_transaction(&unsigned_tx.0.txid(), &htlc, true, &keys);
				let htlc_redeemscript = chan_utils::get_htlc_redeemscript(&htlc, &keys);
				let htlc_sighash = Message::from_slice(&bip143::SighashComponents::new(&htlc_tx).sighash_all(&htlc_tx.input[0], &htlc_redeemscript, htlc.amount_msat / 1000)[..]).unwrap();
				secp_ctx.verify(&htlc_sighash, &remote_signature, &keys.b_htlc_key).unwrap();

				let mut preimage: Option<[u8; 32]> = None;
				if !htlc.offered {
					for i in 0..5 {
						let mut sha = Sha256::new();
						sha.input(&[i; 32]);

						let mut out = [0; 32];
						sha.result(&mut out);

						if out == htlc.payment_hash {
							preimage = Some([i; 32]);
						}
					}

					assert!(preimage.is_some());
				}

				chan.sign_htlc_transaction(&mut htlc_tx, &remote_signature, &preimage, &htlc, &keys).unwrap();
				assert_eq!(serialize(&htlc_tx).unwrap()[..],
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

		chan.pending_htlcs.push({
			let mut out = HTLCOutput{
				htlc_id: 0,
				outbound: false,
				amount_msat: 1000000,
				cltv_expiry: 500,
				payment_hash: [0; 32],
				state: HTLCState::Committed,
				fail_reason: None,
				local_removed_fulfilled: false,
				pending_forward_state: None,
			};
			let mut sha = Sha256::new();
			sha.input(&hex::decode("0000000000000000000000000000000000000000000000000000000000000000").unwrap());
			sha.result(&mut out.payment_hash);
			out
		});
		chan.pending_htlcs.push({
			let mut out = HTLCOutput{
				htlc_id: 1,
				outbound: false,
				amount_msat: 2000000,
				cltv_expiry: 501,
				payment_hash: [0; 32],
				state: HTLCState::Committed,
				fail_reason: None,
				local_removed_fulfilled: false,
				pending_forward_state: None,
			};
			let mut sha = Sha256::new();
			sha.input(&hex::decode("0101010101010101010101010101010101010101010101010101010101010101").unwrap());
			sha.result(&mut out.payment_hash);
			out
		});
		chan.pending_htlcs.push({
			let mut out = HTLCOutput{
				htlc_id: 2,
				outbound: true,
				amount_msat: 2000000,
				cltv_expiry: 502,
				payment_hash: [0; 32],
				state: HTLCState::Committed,
				fail_reason: None,
				local_removed_fulfilled: false,
				pending_forward_state: None,
			};
			let mut sha = Sha256::new();
			sha.input(&hex::decode("0202020202020202020202020202020202020202020202020202020202020202").unwrap());
			sha.result(&mut out.payment_hash);
			out
		});
		chan.pending_htlcs.push({
			let mut out = HTLCOutput{
				htlc_id: 3,
				outbound: true,
				amount_msat: 3000000,
				cltv_expiry: 503,
				payment_hash: [0; 32],
				state: HTLCState::Committed,
				fail_reason: None,
				local_removed_fulfilled: false,
				pending_forward_state: None,
			};
			let mut sha = Sha256::new();
			sha.input(&hex::decode("0303030303030303030303030303030303030303030303030303030303030303").unwrap());
			sha.result(&mut out.payment_hash);
			out
		});
		chan.pending_htlcs.push({
			let mut out = HTLCOutput{
				htlc_id: 4,
				outbound: false,
				amount_msat: 4000000,
				cltv_expiry: 504,
				payment_hash: [0; 32],
				state: HTLCState::Committed,
				fail_reason: None,
				local_removed_fulfilled: false,
				pending_forward_state: None,
			};
			let mut sha = Sha256::new();
			sha.input(&hex::decode("0404040404040404040404040404040404040404040404040404040404040404").unwrap());
			sha.result(&mut out.payment_hash);
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

		let base_secret = SecretKey::from_slice(&secp_ctx, &hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap()[..]).unwrap();
		let per_commitment_secret = SecretKey::from_slice(&secp_ctx, &hex::decode("1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100").unwrap()[..]).unwrap();

		let base_point = PublicKey::from_secret_key(&secp_ctx, &base_secret);
		assert_eq!(base_point.serialize()[..], hex::decode("036d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a95b216691468e2").unwrap()[..]);

		let per_commitment_point = PublicKey::from_secret_key(&secp_ctx, &per_commitment_secret);
		assert_eq!(per_commitment_point.serialize()[..], hex::decode("025f7117a78150fe2ef97db7cfc83bd57b2e2c0d0dd25eaf467a4a1c2a45ce1486").unwrap()[..]);

		assert_eq!(chan_utils::derive_public_key(&secp_ctx, &per_commitment_point, &base_point).unwrap().serialize()[..],
				hex::decode("0235f2dbfaa89b57ec7b055afe29849ef7ddfeb1cefdb9ebdc43f5494984db29e5").unwrap()[..]);

		assert_eq!(chan_utils::derive_private_key(&secp_ctx, &per_commitment_point, &base_secret).unwrap(),
				SecretKey::from_slice(&secp_ctx, &hex::decode("cbced912d3b21bf196a766651e436aff192362621ce317704ea2f75d87e7be0f").unwrap()[..]).unwrap());

		assert_eq!(chan_utils::derive_public_revocation_key(&secp_ctx, &per_commitment_point, &base_point).unwrap().serialize()[..],
				hex::decode("02916e326636d19c33f13e8c0c3a03dd157f332f3e99c317c141dd865eb01f8ff0").unwrap()[..]);

		assert_eq!(chan_utils::derive_private_revocation_key(&secp_ctx, &per_commitment_secret, &base_secret).unwrap(),
				SecretKey::from_slice(&secp_ctx, &hex::decode("d09ffff62ddb2297ab000cc85bcb4283fdeb6aa052affbc9dddcf33b61078110").unwrap()[..]).unwrap());
	}
}
