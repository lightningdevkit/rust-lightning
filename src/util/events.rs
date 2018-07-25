use ln::msgs;
use chain::transaction::OutPoint;

use bitcoin::blockdata::script::Script;

use secp256k1::key::PublicKey;

use std::time::Instant;

pub enum Event {
	// Events a user will probably have to handle
	/// Used to indicate that the client should generate a funding transaction with the given
	/// parameters and then call ChannelManager::funding_transaction_generated.
	/// Generated in ChannelManager message handling.
	FundingGenerationReady {
		temporary_channel_id: [u8; 32],
		channel_value_satoshis: u64,
		output_script: Script,
		/// The value passed in to ChannelManager::create_channel
		user_channel_id: u64,
	},
	/// Used to indicate that the client may now broadcast the funding transaction it created for a
	/// channel. Broadcasting such a transaction prior to this event may lead to our counterparty
	/// trivially stealing all funds in the funding transaction!
	FundingBroadcastSafe {
		funding_txo: OutPoint,
		/// The value passed in to ChannelManager::create_channel
		user_channel_id: u64,
	},
	/// Indicates we've received money! Just gotta dig out that payment preimage and feed it to
	/// ChannelManager::claim_funds to get it....
	/// Note that if the preimage is not known, you must call ChannelManager::fail_htlc_backwards
	/// to free up resources for this HTLC.
	PaymentReceived {
		payment_hash: [u8; 32],
		amt: u64,
	},
	/// Indicates an outbound payment we made succeeded (ie it made it all the way to its target
	/// and we got back the payment preimage for it). payment_preimage serves as a payment receipt,
	/// if you wish to have such a thing, you must store it somehow!
	PaymentSent {
		payment_preimage: [u8; 32],
	},
	/// Indicates an outbound payment we made failed. Probably some intermediary node dropped
	/// something. You may wish to retry with a different route.
	PaymentFailed {
		payment_hash: [u8; 32],
	},
	/// Used to indicate that ChannelManager::process_pending_htlc_forwards should be called at a
	/// time in the future.
	PendingHTLCsForwardable {
		time_forwardable: Instant,
	},

	// Events indicating the network loop should send a message to a peer:
	/// Used to indicate that we've initialted a channel open and should send the open_channel
	/// message provided to the given peer
	SendOpenChannel {
		node_id: PublicKey,
		msg: msgs::OpenChannel,
	},
	/// Used to indicate that a funding_created message should be sent to the peer with the given node_id.
	SendFundingCreated {
		node_id: PublicKey,
		msg: msgs::FundingCreated,
	},
	/// Used to indicate that a funding_locked message should be sent to the peer with the given node_id.
	SendFundingLocked {
		node_id: PublicKey,
		msg: msgs::FundingLocked,
		announcement_sigs: Option<msgs::AnnouncementSignatures>,
	},
	/// Used to indicate that a series of update_add_htlc messages, as well as a commitment_signed
	/// message should be sent to the peer with the given node_id.
	SendHTLCs {
		node_id: PublicKey,
		msgs: Vec<msgs::UpdateAddHTLC>,
		commitment_msg: msgs::CommitmentSigned,
	},
	/// Used to indicate that we're ready to fulfill an htlc from the peer with the given node_id.
	SendFulfillHTLC {
		node_id: PublicKey,
		msg: msgs::UpdateFulfillHTLC,
		commitment_msg: msgs::CommitmentSigned,
	},
	/// Used to indicate that we need to fail an htlc from the peer with the given node_id.
	SendFailHTLC {
		node_id: PublicKey,
		msg: msgs::UpdateFailHTLC,
		commitment_msg: msgs::CommitmentSigned,
	},
	/// Used to indicate that a shutdown message should be sent to the peer with the given node_id.
	SendShutdown {
		node_id: PublicKey,
		msg: msgs::Shutdown,
	},
	/// Used to indicate that a channel_announcement and channel_update should be broadcast to all
	/// peers (except the peer with node_id either msg.contents.node_id_1 or msg.contents.node_id_2).
	BroadcastChannelAnnouncement {
		msg: msgs::ChannelAnnouncement,
		update_msg: msgs::ChannelUpdate,
	},
	/// Used to indicate that a channel_update should be broadcast to all peers.
	BroadcastChannelUpdate {
		msg: msgs::ChannelUpdate,
	},

	// Events indicating the network loop should change the state of connection with peer:
	/// Disconnect the given peer, possibly making an attempt to send an ErrorMessage first.
	DisconnectPeer  {
		node_id: PublicKey,
		msg: Option<msgs::ErrorMessage>,
	}
}

pub trait EventsProvider {
	fn get_and_clear_pending_events(&self) -> Vec<Event>;
}
