//! Events are returned from various bits in the library which indicate some action must be taken
//! by the client.
//!
//! Because we don't have a built-in runtime, its up to the client to call events at a time in the
//! future, as well as generate and broadcast funding transactions handle payment preimages and a
//! few other things.
//!
//! Note that many events are handled for you by PeerHandler, so in the common design of having a
//! PeerManager which marshalls messages to ChannelManager and Router you only need to call
//! process_events on the PeerHandler and then get_and_clear_pending_events and handle the events
//! that bubble up to the surface. If, however, you do not have a PeerHandler managing a
//! ChannelManager you need to handle all of the events which may be generated.
//TODO: We need better separation of event types ^

use ln::msgs;
use chain::transaction::OutPoint;

use bitcoin::blockdata::script::Script;

use secp256k1::key::PublicKey;

use std::time::Instant;

/// An Event which you should probably take some action in response to.
pub enum Event {
	// Events a user will probably have to handle
	/// Used to indicate that the client should generate a funding transaction with the given
	/// parameters and then call ChannelManager::funding_transaction_generated.
	/// Generated in ChannelManager message handling.
	FundingGenerationReady {
		/// The random channel_id we picked which you'll need to pass into
		/// ChannelManager::funding_transaction_generated.
		temporary_channel_id: [u8; 32],
		/// The value, in satoshis, that the output should have.
		channel_value_satoshis: u64,
		/// The script which should be used in the transaction output.
		output_script: Script,
		/// The value passed in to ChannelManager::create_channel
		user_channel_id: u64,
	},
	/// Used to indicate that the client may now broadcast the funding transaction it created for a
	/// channel. Broadcasting such a transaction prior to this event may lead to our counterparty
	/// trivially stealing all funds in the funding transaction!
	FundingBroadcastSafe {
		/// The output, which was passed to ChannelManager::funding_transaction_generated, which is
		/// now safe to broadcast.
		funding_txo: OutPoint,
		/// The value passed in to ChannelManager::create_channel
		user_channel_id: u64,
	},
	/// Indicates we've received money! Just gotta dig out that payment preimage and feed it to
	/// ChannelManager::claim_funds to get it....
	/// Note that if the preimage is not known, you must call ChannelManager::fail_htlc_backwards
	/// to free up resources for this HTLC.
	PaymentReceived {
		/// The hash for which the preimage should be handed to the ChannelManager.
		payment_hash: [u8; 32],
		/// The value, in thousandths of a satoshi, that this payment is for.
		amt: u64,
	},
	/// Indicates an outbound payment we made succeeded (ie it made it all the way to its target
	/// and we got back the payment preimage for it).
	/// Note that duplicative PaymentSent Events may be generated - it is your responsibility to
	/// deduplicate them by payment_preimage (which MUST be unique)!
	PaymentSent {
		/// The preimage to the hash given to ChannelManager::send_payment.
		/// Note that this serves as a payment receipt, if you wish to have such a thing, you must
		/// store it somehow!
		payment_preimage: [u8; 32],
	},
	/// Indicates an outbound payment we made failed. Probably some intermediary node dropped
	/// something. You may wish to retry with a different route.
	/// Note that duplicative PaymentFailed Events may be generated - it is your responsibility to
	/// deduplicate them by payment_hash (which MUST be unique)!
	PaymentFailed {
		/// The hash which was given to ChannelManager::send_payment.
		payment_hash: [u8; 32],
		/// Indicates the payment was rejected for some reason by the recipient. This implies that
		/// the payment has failed, not just the route in question. If this is not set, you may
		/// retry the payment via a different route.
		rejected_by_dest: bool,
	},
	/// Used to indicate that ChannelManager::process_pending_htlc_forwards should be called at a
	/// time in the future.
	PendingHTLCsForwardable {
		/// The earliest time at which process_pending_htlc_forwards should be called.
		time_forwardable: Instant,
	},

	// Events indicating the network loop should send a message to a peer:
	// TODO: Move these into a separate struct and make a top-level enum
	/// Used to indicate that we've initialted a channel open and should send the open_channel
	/// message provided to the given peer.
	///
	/// This event is handled by PeerManager::process_events if you are using a PeerManager.
	SendOpenChannel {
		/// The node_id of the node which should receive this message
		node_id: PublicKey,
		/// The message which should be sent.
		msg: msgs::OpenChannel,
	},
	/// Used to indicate that a funding_created message should be sent to the peer with the given node_id.
	///
	/// This event is handled by PeerManager::process_events if you are using a PeerManager.
	SendFundingCreated {
		/// The node_id of the node which should receive this message
		node_id: PublicKey,
		/// The message which should be sent.
		msg: msgs::FundingCreated,
	},
	/// Used to indicate that a funding_locked message should be sent to the peer with the given node_id.
	///
	/// This event is handled by PeerManager::process_events if you are using a PeerManager.
	SendFundingLocked {
		/// The node_id of the node which should receive these message(s)
		node_id: PublicKey,
		/// The funding_locked message which should be sent.
		msg: msgs::FundingLocked,
		/// An optional additional announcement_signatures message which should be sent.
		announcement_sigs: Option<msgs::AnnouncementSignatures>,
	},
	/// Used to indicate that a series of HTLC update messages, as well as a commitment_signed
	/// message should be sent to the peer with the given node_id.
	///
	/// This event is handled by PeerManager::process_events if you are using a PeerManager.
	UpdateHTLCs {
		/// The node_id of the node which should receive these message(s)
		node_id: PublicKey,
		/// The update messages which should be sent. ALL messages in the struct should be sent!
		updates: msgs::CommitmentUpdate,
	},
	/// Used to indicate that a shutdown message should be sent to the peer with the given node_id.
	///
	/// This event is handled by PeerManager::process_events if you are using a PeerManager.
	SendShutdown {
		/// The node_id of the node which should receive this message
		node_id: PublicKey,
		/// The message which should be sent.
		msg: msgs::Shutdown,
	},
	/// Used to indicate that a channel_announcement and channel_update should be broadcast to all
	/// peers (except the peer with node_id either msg.contents.node_id_1 or msg.contents.node_id_2).
	///
	/// This event is handled by PeerManager::process_events if you are using a PeerManager.
	BroadcastChannelAnnouncement {
		/// The channel_announcement which should be sent.
		msg: msgs::ChannelAnnouncement,
		/// The followup channel_update which should be sent.
		update_msg: msgs::ChannelUpdate,
	},
	/// Used to indicate that a channel_update should be broadcast to all peers.
	///
	/// This event is handled by PeerManager::process_events if you are using a PeerManager.
	BroadcastChannelUpdate {
		/// The channel_update which should be sent.
		msg: msgs::ChannelUpdate,
	},

	//Error handling
	/// Broadcast an error downstream to be handled
	///
	/// This event is handled by PeerManager::process_events if you are using a PeerManager.
	HandleError {
		/// The node_id of the node which should receive this message
		node_id: PublicKey,
		/// The action which should be taken.
		action: Option<msgs::ErrorAction>
	},
	/// When a payment fails we may receive updates back from the hop where it failed. In such
	/// cases this event is generated so that we can inform the router of this information.
	///
	/// This event is handled by PeerManager::process_events if you are using a PeerManager.
	PaymentFailureNetworkUpdate {
		/// The channel/node update which should be sent to router
		update: msgs::HTLCFailChannelUpdate,
	}
}

/// A trait indicating an object may generate events
pub trait EventsProvider {
	/// Gets the list of pending events which were generated by previous actions, clearing the list
	/// in the process.
	fn get_and_clear_pending_events(&self) -> Vec<Event>;
}
