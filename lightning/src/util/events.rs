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

use chain::keysinterface::SpendableOutputDescriptor;
use ln::msgs;
use ln::{PaymentPreimage, PaymentHash, PaymentSecret};
use routing::network_graph::NetworkUpdate;
use util::ser::{Writeable, Writer, MaybeReadable, Readable, VecReadWrapper, VecWriteWrapper};

use bitcoin::blockdata::script::Script;

use bitcoin::secp256k1::key::PublicKey;

use io;
use prelude::*;
use core::time::Duration;
use core::ops::Deref;

/// Some information provided on receipt of payment depends on whether the payment received is a
/// spontaneous payment or a "conventional" lightning payment that's paying an invoice.
#[derive(Clone, Debug)]
pub enum PaymentPurpose {
	/// Information for receiving a payment that we generated an invoice for.
	InvoicePayment {
		/// The preimage to the payment_hash, if the payment hash (and secret) were fetched via
		/// [`ChannelManager::create_inbound_payment`]. If provided, this can be handed directly to
		/// [`ChannelManager::claim_funds`].
		///
		/// [`ChannelManager::create_inbound_payment`]: crate::ln::channelmanager::ChannelManager::create_inbound_payment
		/// [`ChannelManager::claim_funds`]: crate::ln::channelmanager::ChannelManager::claim_funds
		payment_preimage: Option<PaymentPreimage>,
		/// The "payment secret". This authenticates the sender to the recipient, preventing a
		/// number of deanonymization attacks during the routing process.
		/// It is provided here for your reference, however its accuracy is enforced directly by
		/// [`ChannelManager`] using the values you previously provided to
		/// [`ChannelManager::create_inbound_payment`] or
		/// [`ChannelManager::create_inbound_payment_for_hash`].
		///
		/// [`ChannelManager`]: crate::ln::channelmanager::ChannelManager
		/// [`ChannelManager::create_inbound_payment`]: crate::ln::channelmanager::ChannelManager::create_inbound_payment
		/// [`ChannelManager::create_inbound_payment_for_hash`]: crate::ln::channelmanager::ChannelManager::create_inbound_payment_for_hash
		payment_secret: PaymentSecret,
		/// This is the `user_payment_id` which was provided to
		/// [`ChannelManager::create_inbound_payment_for_hash`] or
		/// [`ChannelManager::create_inbound_payment`]. It has no meaning inside of LDK and is
		/// simply copied here. It may be used to correlate PaymentReceived events with invoice
		/// metadata stored elsewhere.
		///
		/// [`ChannelManager::create_inbound_payment`]: crate::ln::channelmanager::ChannelManager::create_inbound_payment
		/// [`ChannelManager::create_inbound_payment_for_hash`]: crate::ln::channelmanager::ChannelManager::create_inbound_payment_for_hash
		user_payment_id: u64,
	},
	/// Because this is a spontaneous payment, the payer generated their own preimage rather than us
	/// (the payee) providing a preimage.
	SpontaneousPayment(PaymentPreimage),
}

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
		/// The value, in thousandths of a satoshi, that this payment is for. Note that you must
		/// compare this to the expected value before accepting the payment (as otherwise you are
		/// providing proof-of-payment for less than the value you expected!).
		amt: u64,
		/// Information for claiming this received payment, based on whether the purpose of the
		/// payment is to pay an invoice or to send a spontaneous payment.
		purpose: PaymentPurpose,
	},
	/// Indicates an outbound payment we made succeeded (ie it made it all the way to its target
	/// and we got back the payment preimage for it).
	PaymentSent {
		/// The preimage to the hash given to ChannelManager::send_payment.
		/// Note that this serves as a payment receipt, if you wish to have such a thing, you must
		/// store it somehow!
		payment_preimage: PaymentPreimage,
	},
	/// Indicates an outbound payment we made failed. Probably some intermediary node dropped
	/// something. You may wish to retry with a different route.
	PaymentFailed {
		/// The hash which was given to ChannelManager::send_payment.
		payment_hash: PaymentHash,
		/// Indicates the payment was rejected for some reason by the recipient. This implies that
		/// the payment has failed, not just the route in question. If this is not set, you may
		/// retry the payment via a different route.
		rejected_by_dest: bool,
		/// Any failure information conveyed via the Onion return packet by a node along the failed
		/// payment route.
		///
		/// Should be applied to the [`NetworkGraph`] so that routing decisions can take into
		/// account the update. [`NetGraphMsgHandler`] is capable of doing this.
		///
		/// [`NetworkGraph`]: crate::routing::network_graph::NetworkGraph
		/// [`NetGraphMsgHandler`]: crate::routing::network_graph::NetGraphMsgHandler
		network_update: Option<NetworkUpdate>,
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
	/// Used to indicate that an output which you should know how to spend was confirmed on chain
	/// and is now spendable.
	/// Such an output will *not* ever be spent by rust-lightning, and are not at risk of your
	/// counterparty spending them due to some kind of timeout. Thus, you need to store them
	/// somewhere and spend them when you create on-chain transactions.
	SpendableOutputs {
		/// The outputs which you should store as spendable by you.
		outputs: Vec<SpendableOutputDescriptor>,
	},
	/// This event is generated when a payment has been successfully forwarded through us and a
	/// forwarding fee earned.
	PaymentForwarded {
		/// The fee, in milli-satoshis, which was earned as a result of the payment.
		///
		/// Note that if we force-closed the channel over which we forwarded an HTLC while the HTLC
		/// was pending, the amount the next hop claimed will have been rounded down to the nearest
		/// whole satoshi. Thus, the fee calculated here may be higher than expected as we still
		/// claimed the full value in millisatoshis from the source. In this case,
		/// `claim_from_onchain_tx` will be set.
		///
		/// If the channel which sent us the payment has been force-closed, we will claim the funds
		/// via an on-chain transaction. In that case we do not yet know the on-chain transaction
		/// fees which we will spend and will instead set this to `None`. It is possible duplicate
		/// `PaymentForwarded` events are generated for the same payment iff `fee_earned_msat` is
		/// `None`.
		fee_earned_msat: Option<u64>,
		/// If this is `true`, the forwarded HTLC was claimed by our counterparty via an on-chain
		/// transaction.
		claim_from_onchain_tx: bool,
	},
}

impl Writeable for Event {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		match self {
			&Event::FundingGenerationReady { .. } => {
				0u8.write(writer)?;
				// We never write out FundingGenerationReady events as, upon disconnection, peers
				// drop any channels which have not yet exchanged funding_signed.
			},
			&Event::PaymentReceived { ref payment_hash, ref amt, ref purpose } => {
				1u8.write(writer)?;
				let mut payment_secret = None;
				let mut user_payment_id = None;
				let payment_preimage;
				match &purpose {
					PaymentPurpose::InvoicePayment { payment_preimage: preimage, payment_secret: secret, user_payment_id: id } => {
						payment_secret = Some(secret);
						payment_preimage = *preimage;
						user_payment_id = Some(id);
					},
					PaymentPurpose::SpontaneousPayment(preimage) => {
						payment_preimage = Some(*preimage);
					}
				}
				write_tlv_fields!(writer, {
					(0, payment_hash, required),
					(2, payment_secret, option),
					(4, amt, required),
					(6, user_payment_id, option),
					(8, payment_preimage, option),
				});
			},
			&Event::PaymentSent { ref payment_preimage } => {
				2u8.write(writer)?;
				write_tlv_fields!(writer, {
					(0, payment_preimage, required),
				});
			},
			&Event::PaymentFailed { ref payment_hash, ref rejected_by_dest, ref network_update,
				#[cfg(test)]
				ref error_code,
				#[cfg(test)]
				ref error_data,
			} => {
				3u8.write(writer)?;
				#[cfg(test)]
				error_code.write(writer)?;
				#[cfg(test)]
				error_data.write(writer)?;
				write_tlv_fields!(writer, {
					(0, payment_hash, required),
					(1, network_update, option),
					(2, rejected_by_dest, required),
				});
			},
			&Event::PendingHTLCsForwardable { time_forwardable: _ } => {
				4u8.write(writer)?;
				// Note that we now ignore these on the read end as we'll re-generate them in
				// ChannelManager, we write them here only for backwards compatibility.
			},
			&Event::SpendableOutputs { ref outputs } => {
				5u8.write(writer)?;
				write_tlv_fields!(writer, {
					(0, VecWriteWrapper(outputs), required),
				});
			},
			&Event::PaymentForwarded { fee_earned_msat, claim_from_onchain_tx } => {
				7u8.write(writer)?;
				write_tlv_fields!(writer, {
					(0, fee_earned_msat, option),
					(2, claim_from_onchain_tx, required),
				});
			},
		}
		Ok(())
	}
}
impl MaybeReadable for Event {
	fn read<R: io::Read>(reader: &mut R) -> Result<Option<Self>, msgs::DecodeError> {
		match Readable::read(reader)? {
			0u8 => Ok(None),
			1u8 => {
				let f = || {
					let mut payment_hash = PaymentHash([0; 32]);
					let mut payment_preimage = None;
					let mut payment_secret = None;
					let mut amt = 0;
					let mut user_payment_id = None;
					read_tlv_fields!(reader, {
						(0, payment_hash, required),
						(2, payment_secret, option),
						(4, amt, required),
						(6, user_payment_id, option),
						(8, payment_preimage, option),
					});
					let purpose = match payment_secret {
						Some(secret) => PaymentPurpose::InvoicePayment {
							payment_preimage,
							payment_secret: secret,
							user_payment_id: if let Some(id) = user_payment_id {
								id
							} else { return Err(msgs::DecodeError::InvalidValue) }
						},
						None if payment_preimage.is_some() => PaymentPurpose::SpontaneousPayment(payment_preimage.unwrap()),
						None => return Err(msgs::DecodeError::InvalidValue),
					};
					Ok(Some(Event::PaymentReceived {
						payment_hash,
						amt,
						purpose,
					}))
				};
				f()
			},
			2u8 => {
				let f = || {
					let mut payment_preimage = PaymentPreimage([0; 32]);
					read_tlv_fields!(reader, {
						(0, payment_preimage, required),
					});
					Ok(Some(Event::PaymentSent {
						payment_preimage,
					}))
				};
				f()
			},
			3u8 => {
				let f = || {
					#[cfg(test)]
					let error_code = Readable::read(reader)?;
					#[cfg(test)]
					let error_data = Readable::read(reader)?;
					let mut payment_hash = PaymentHash([0; 32]);
					let mut rejected_by_dest = false;
					let mut network_update = None;
					read_tlv_fields!(reader, {
						(0, payment_hash, required),
						(1, network_update, ignorable),
						(2, rejected_by_dest, required),
					});
					Ok(Some(Event::PaymentFailed {
						payment_hash,
						rejected_by_dest,
						network_update,
						#[cfg(test)]
						error_code,
						#[cfg(test)]
						error_data,
					}))
				};
				f()
			},
			4u8 => Ok(None),
			5u8 => {
				let f = || {
					let mut outputs = VecReadWrapper(Vec::new());
					read_tlv_fields!(reader, {
						(0, outputs, required),
					});
					Ok(Some(Event::SpendableOutputs { outputs: outputs.0 }))
				};
				f()
			},
			7u8 => {
				let f = || {
					let mut fee_earned_msat = None;
					let mut claim_from_onchain_tx = false;
					read_tlv_fields!(reader, {
						(0, fee_earned_msat, option),
						(2, claim_from_onchain_tx, required),
					});
					Ok(Some(Event::PaymentForwarded { fee_earned_msat, claim_from_onchain_tx }))
				};
				f()
			},
			// Versions prior to 0.0.100 did not ignore odd types, instead returning InvalidValue.
			x if x % 2 == 1 => Ok(None),
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
	/// Used to indicate that a channel_update should be sent to a single peer.
	/// In contrast to [`Self::BroadcastChannelUpdate`], this is used when the channel is a
	/// private channel and we shouldn't be informing all of our peers of channel parameters.
	SendChannelUpdate {
		/// The node_id of the node which should receive this message
		node_id: PublicKey,
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

/// A trait indicating an object may generate events.
///
/// Events are processed by passing an [`EventHandler`] to [`process_pending_events`].
///
/// # Requirements
///
/// See [`process_pending_events`] for requirements around event processing.
///
/// When using this trait, [`process_pending_events`] will call [`handle_event`] for each pending
/// event since the last invocation. The handler must either act upon the event immediately
/// or preserve it for later handling.
///
/// Note, handlers may call back into the provider and thus deadlocking must be avoided. Be sure to
/// consult the provider's documentation on the implication of processing events and how a handler
/// may safely use the provider (e.g., see [`ChannelManager::process_pending_events`] and
/// [`ChainMonitor::process_pending_events`]).
///
/// (C-not implementable) As there is likely no reason for a user to implement this trait on their
/// own type(s).
///
/// [`process_pending_events`]: Self::process_pending_events
/// [`handle_event`]: EventHandler::handle_event
/// [`ChannelManager::process_pending_events`]: crate::ln::channelmanager::ChannelManager#method.process_pending_events
/// [`ChainMonitor::process_pending_events`]: crate::chain::chainmonitor::ChainMonitor#method.process_pending_events
pub trait EventsProvider {
	/// Processes any events generated since the last call using the given event handler.
	///
	/// Subsequent calls must only process new events. However, handlers must be capable of handling
	/// duplicate events across process restarts. This may occur if the provider was recovered from
	/// an old state (i.e., it hadn't been successfully persisted after processing pending events).
	fn process_pending_events<H: Deref>(&self, handler: H) where H::Target: EventHandler;
}

/// A trait implemented for objects handling events from [`EventsProvider`].
pub trait EventHandler {
	/// Handles the given [`Event`].
	///
	/// See [`EventsProvider`] for details that must be considered when implementing this method.
	fn handle_event(&self, event: &Event);
}

impl<F> EventHandler for F where F: Fn(&Event) {
	fn handle_event(&self, event: &Event) {
		self(event)
	}
}
