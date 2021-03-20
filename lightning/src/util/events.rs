// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Events are returned from various bits in the library which indicate some action must be taken
//! by the client.
//!
//! Because we don't have a built-in runtime, it's up to the client to call events at a time in the
//! future, as well as generate and broadcast funding transactions handle payment preimages and a
//! few other things.

use ln::msgs;
use ln::channelmanager::{PaymentPreimage, PaymentHash, PaymentSecret};
use chain::transaction::OutPoint;
use chain::keysinterface::SpendableOutputDescriptor;
use util::ser::{Writeable, Writer, MaybeReadable, Readable};

use bitcoin::blockdata::script::Script;

use bitcoin::secp256k1::key::PublicKey;

use std::time::Duration;

/// An Event which you should probably take some action in response to.
///
/// Note that while Writeable and Readable are implemented for Event, you probably shouldn't use
/// them directly as they don't round-trip exactly (for example FundingGenerationReady is never
/// written as it makes no sense to respond to it after reconnecting to peers).
#[derive(Clone, Debug)]
pub enum Event {
	/// Used to indicate that the client should generate a funding transaction with the given
	/// parameters and then call ChannelManager::funding_transaction_generated.
	/// Generated in ChannelManager message handling.
	/// Note that *all inputs* in the funding transaction must spend SegWit outputs or your
	/// counterparty can steal your funds!
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
	/// Note that if the preimage is not known or the amount paid is incorrect, you should call
	/// ChannelManager::fail_htlc_backwards to free up resources for this HTLC and avoid
	/// network congestion.
	/// The amount paid should be considered 'incorrect' when it is less than or more than twice
	/// the amount expected.
	/// If you fail to call either ChannelManager::claim_funds or
	/// ChannelManager::fail_htlc_backwards within the HTLC's timeout, the HTLC will be
	/// automatically failed.
	PaymentReceived {
		/// The hash for which the preimage should be handed to the ChannelManager.
		payment_hash: PaymentHash,
		/// The "payment secret". This authenticates the sender to the recipient, preventing a
		/// number of deanonymization attacks during the routing process.
		/// As nodes upgrade, the invoices you provide should likely migrate to setting the
		/// payment_secret feature to required, at which point you should fail_backwards any HTLCs
		/// which have a None here.
		/// Until then, however, values of None should be ignored, and only incorrect Some values
		/// should result in an HTLC fail_backwards.
		/// Note that, in any case, this value must be passed as-is to any fail or claim calls as
		/// the HTLC index includes this value.
		payment_secret: Option<PaymentSecret>,
		/// The value, in thousandths of a satoshi, that this payment is for. Note that you must
		/// compare this to the expected value before accepting the payment (as otherwise you are
		/// providing proof-of-payment for less than the value you expected!).
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
		payment_preimage: PaymentPreimage,
	},
	/// Indicates an outbound payment we made failed. Probably some intermediary node dropped
	/// something. You may wish to retry with a different route.
	/// Note that duplicative PaymentFailed Events may be generated - it is your responsibility to
	/// deduplicate them by payment_hash (which MUST be unique)!
	PaymentFailed {
		/// The hash which was given to ChannelManager::send_payment.
		payment_hash: PaymentHash,
		/// Indicates the payment was rejected for some reason by the recipient. This implies that
		/// the payment has failed, not just the route in question. If this is not set, you may
		/// retry the payment via a different route.
		rejected_by_dest: bool,
#[cfg(test)]
		error_code: Option<u16>,
#[cfg(test)]
		error_data: Option<Vec<u8>>,
	},
	/// Used to indicate that ChannelManager::process_pending_htlc_forwards should be called at a
	/// time in the future.
	PendingHTLCsForwardable {
		/// The minimum amount of time that should be waited prior to calling
		/// process_pending_htlc_forwards. To increase the effort required to correlate payments,
		/// you should wait a random amount of time in roughly the range (now + time_forwardable,
		/// now + 5*time_forwardable).
		time_forwardable: Duration,
	},
	/// Used to indicate that an output was generated on-chain which you should know how to spend.
	/// Such an output will *not* ever be spent by rust-lightning, and are not at risk of your
	/// counterparty spending them due to some kind of timeout. Thus, you need to store them
	/// somewhere and spend them when you create on-chain transactions.
	SpendableOutputs {
		/// The outputs which you should store as spendable by you.
		outputs: Vec<SpendableOutputDescriptor>,
	},
}

impl Writeable for Event {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
		match self {
			&Event::FundingGenerationReady { .. } => {
				0u8.write(writer)?;
				// We never write out FundingGenerationReady events as, upon disconnection, peers
				// drop any channels which have not yet exchanged funding_signed.
			},
			&Event::FundingBroadcastSafe { ref funding_txo, ref user_channel_id } => {
				1u8.write(writer)?;
				funding_txo.write(writer)?;
				user_channel_id.write(writer)?;
			},
			&Event::PaymentReceived { ref payment_hash, ref payment_secret, ref amt } => {
				2u8.write(writer)?;
				payment_hash.write(writer)?;
				payment_secret.write(writer)?;
				amt.write(writer)?;
			},
			&Event::PaymentSent { ref payment_preimage } => {
				3u8.write(writer)?;
				payment_preimage.write(writer)?;
			},
			&Event::PaymentFailed { ref payment_hash, ref rejected_by_dest,
				#[cfg(test)]
				ref error_code,
				#[cfg(test)]
				ref error_data,
			} => {
				4u8.write(writer)?;
				payment_hash.write(writer)?;
				rejected_by_dest.write(writer)?;
				#[cfg(test)]
				error_code.write(writer)?;
				#[cfg(test)]
				error_data.write(writer)?;
			},
			&Event::PendingHTLCsForwardable { time_forwardable: _ } => {
				5u8.write(writer)?;
				// We don't write the time_fordwardable out at all, as we presume when the user
				// deserializes us at least that much time has elapsed.
			},
			&Event::SpendableOutputs { ref outputs } => {
				6u8.write(writer)?;
				(outputs.len() as u64).write(writer)?;
				for output in outputs.iter() {
					output.write(writer)?;
				}
			},
		}
		Ok(())
	}
}
impl MaybeReadable for Event {
	fn read<R: ::std::io::Read>(reader: &mut R) -> Result<Option<Self>, msgs::DecodeError> {
		match Readable::read(reader)? {
			0u8 => Ok(None),
			1u8 => Ok(Some(Event::FundingBroadcastSafe {
					funding_txo: Readable::read(reader)?,
					user_channel_id: Readable::read(reader)?,
				})),
			2u8 => Ok(Some(Event::PaymentReceived {
					payment_hash: Readable::read(reader)?,
					payment_secret: Readable::read(reader)?,
					amt: Readable::read(reader)?,
				})),
			3u8 => Ok(Some(Event::PaymentSent {
					payment_preimage: Readable::read(reader)?,
				})),
			4u8 => Ok(Some(Event::PaymentFailed {
					payment_hash: Readable::read(reader)?,
					rejected_by_dest: Readable::read(reader)?,
					#[cfg(test)]
					error_code: Readable::read(reader)?,
					#[cfg(test)]
					error_data: Readable::read(reader)?,
				})),
			5u8 => Ok(Some(Event::PendingHTLCsForwardable {
					time_forwardable: Duration::from_secs(0)
				})),
			6u8 => {
				let outputs_len: u64 = Readable::read(reader)?;
				let mut outputs = Vec::new();
				for _ in 0..outputs_len {
					outputs.push(Readable::read(reader)?);
				}
				Ok(Some(Event::SpendableOutputs { outputs }))
			},
			_ => Err(msgs::DecodeError::InvalidValue)
		}
	}
}

/// An event generated by ChannelManager which indicates a message should be sent to a peer (or
/// broadcast to most peers).
/// These events are handled by PeerManager::process_events if you are using a PeerManager.
#[derive(Clone, Debug)]
pub enum MessageSendEvent {
	/// Used to indicate that we've accepted a channel open and should send the accept_channel
	/// message provided to the given peer.
	SendAcceptChannel {
		/// The node_id of the node which should receive this message
		node_id: PublicKey,
		/// The message which should be sent.
		msg: msgs::AcceptChannel,
	},
	/// Used to indicate that we've initiated a channel open and should send the open_channel
	/// message provided to the given peer.
	SendOpenChannel {
		/// The node_id of the node which should receive this message
		node_id: PublicKey,
		/// The message which should be sent.
		msg: msgs::OpenChannel,
	},
	/// Used to indicate that a funding_created message should be sent to the peer with the given node_id.
	SendFundingCreated {
		/// The node_id of the node which should receive this message
		node_id: PublicKey,
		/// The message which should be sent.
		msg: msgs::FundingCreated,
	},
	/// Used to indicate that a funding_signed message should be sent to the peer with the given node_id.
	SendFundingSigned {
		/// The node_id of the node which should receive this message
		node_id: PublicKey,
		/// The message which should be sent.
		msg: msgs::FundingSigned,
	},
	/// Used to indicate that a funding_locked message should be sent to the peer with the given node_id.
	SendFundingLocked {
		/// The node_id of the node which should receive these message(s)
		node_id: PublicKey,
		/// The funding_locked message which should be sent.
		msg: msgs::FundingLocked,
	},
	/// Used to indicate that an announcement_signatures message should be sent to the peer with the given node_id.
	SendAnnouncementSignatures {
		/// The node_id of the node which should receive these message(s)
		node_id: PublicKey,
		/// The announcement_signatures message which should be sent.
		msg: msgs::AnnouncementSignatures,
	},
	/// Used to indicate that a series of HTLC update messages, as well as a commitment_signed
	/// message should be sent to the peer with the given node_id.
	UpdateHTLCs {
		/// The node_id of the node which should receive these message(s)
		node_id: PublicKey,
		/// The update messages which should be sent. ALL messages in the struct should be sent!
		updates: msgs::CommitmentUpdate,
	},
	/// Used to indicate that a revoke_and_ack message should be sent to the peer with the given node_id.
	SendRevokeAndACK {
		/// The node_id of the node which should receive this message
		node_id: PublicKey,
		/// The message which should be sent.
		msg: msgs::RevokeAndACK,
	},
	/// Used to indicate that a closing_signed message should be sent to the peer with the given node_id.
	SendClosingSigned {
		/// The node_id of the node which should receive this message
		node_id: PublicKey,
		/// The message which should be sent.
		msg: msgs::ClosingSigned,
	},
	/// Used to indicate that a shutdown message should be sent to the peer with the given node_id.
	SendShutdown {
		/// The node_id of the node which should receive this message
		node_id: PublicKey,
		/// The message which should be sent.
		msg: msgs::Shutdown,
	},
	/// Used to indicate that a channel_reestablish message should be sent to the peer with the given node_id.
	SendChannelReestablish {
		/// The node_id of the node which should receive this message
		node_id: PublicKey,
		/// The message which should be sent.
		msg: msgs::ChannelReestablish,
	},
	/// Used to indicate that a channel_announcement and channel_update should be broadcast to all
	/// peers (except the peer with node_id either msg.contents.node_id_1 or msg.contents.node_id_2).
	///
	/// Note that after doing so, you very likely (unless you did so very recently) want to call
	/// ChannelManager::broadcast_node_announcement to trigger a BroadcastNodeAnnouncement event.
	/// This ensures that any nodes which see our channel_announcement also have a relevant
	/// node_announcement, including relevant feature flags which may be important for routing
	/// through or to us.
	BroadcastChannelAnnouncement {
		/// The channel_announcement which should be sent.
		msg: msgs::ChannelAnnouncement,
		/// The followup channel_update which should be sent.
		update_msg: msgs::ChannelUpdate,
	},
	/// Used to indicate that a node_announcement should be broadcast to all peers.
	BroadcastNodeAnnouncement {
		/// The node_announcement which should be sent.
		msg: msgs::NodeAnnouncement,
	},
	/// Used to indicate that a channel_update should be broadcast to all peers.
	BroadcastChannelUpdate {
		/// The channel_update which should be sent.
		msg: msgs::ChannelUpdate,
	},
	/// Broadcast an error downstream to be handled
	HandleError {
		/// The node_id of the node which should receive this message
		node_id: PublicKey,
		/// The action which should be taken.
		action: msgs::ErrorAction
	},
	/// When a payment fails we may receive updates back from the hop where it failed. In such
	/// cases this event is generated so that we can inform the network graph of this information.
	PaymentFailureNetworkUpdate {
		/// The channel/node update which should be sent to NetGraphMsgHandler
		update: msgs::HTLCFailChannelUpdate,
	},
	/// Query a peer for channels with funding transaction UTXOs in a block range.
	SendChannelRangeQuery {
		/// The node_id of this message recipient
		node_id: PublicKey,
		/// The query_channel_range which should be sent.
		msg: msgs::QueryChannelRange,
	},
	/// Request routing gossip messages from a peer for a list of channels identified by
	/// their short_channel_ids.
	SendShortIdsQuery {
		/// The node_id of this message recipient
		node_id: PublicKey,
		/// The query_short_channel_ids which should be sent.
		msg: msgs::QueryShortChannelIds,
	},
	/// Sends a reply to a channel range query. This may be one of several SendReplyChannelRange events
	/// emitted during processing of the query.
	SendReplyChannelRange {
		/// The node_id of this message recipient
		node_id: PublicKey,
		/// The reply_channel_range which should be sent.
		msg: msgs::ReplyChannelRange,
	}
}

/// A trait indicating an object may generate message send events
pub trait MessageSendEventsProvider {
	/// Gets the list of pending events which were generated by previous actions, clearing the list
	/// in the process.
	fn get_and_clear_pending_msg_events(&self) -> Vec<MessageSendEvent>;
}

/// A trait indicating an object may generate events
pub trait EventsProvider {
	/// Gets the list of pending events which were generated by previous actions, clearing the list
	/// in the process.
	fn get_and_clear_pending_events(&self) -> Vec<Event>;
}
