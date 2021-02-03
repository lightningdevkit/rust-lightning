//! Events are returned from various bits in the library which indicate some action must be taken
//! by the client.
//!
//! Because we don't have a built-in runtime, it's up to the client to call events at a time in the
//! future, as well as generate and broadcast funding transactions handle payment preimages and a
//! few other things.

use std::ffi::c_void;
use bitcoin::hashes::Hash;
use crate::c_types::*;

/// An Event which you should probably take some action in response to.
///
/// Note that while Writeable and Readable are implemented for Event, you probably shouldn't use
/// them directly as they don't round-trip exactly (for example FundingGenerationReady is never
/// written as it makes no sense to respond to it after reconnecting to peers).
#[must_use]
#[derive(Clone)]
#[repr(C)]
pub enum Event {
	/// Used to indicate that the client should generate a funding transaction with the given
	/// parameters and then call ChannelManager::funding_transaction_generated.
	/// Generated in ChannelManager message handling.
	/// Note that *all inputs* in the funding transaction must spend SegWit outputs or your
	/// counterparty can steal your funds!
	FundingGenerationReady {
		temporary_channel_id: crate::c_types::ThirtyTwoBytes,
		channel_value_satoshis: u64,
		output_script: crate::c_types::derived::CVec_u8Z,
		user_channel_id: u64,
	},
	/// Used to indicate that the client may now broadcast the funding transaction it created for a
	/// channel. Broadcasting such a transaction prior to this event may lead to our counterparty
	/// trivially stealing all funds in the funding transaction!
	FundingBroadcastSafe {
		funding_txo: crate::chain::transaction::OutPoint,
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
		payment_hash: crate::c_types::ThirtyTwoBytes,
		payment_secret: crate::c_types::ThirtyTwoBytes,
		amt: u64,
	},
	/// Indicates an outbound payment we made succeeded (ie it made it all the way to its target
	/// and we got back the payment preimage for it).
	/// Note that duplicative PaymentSent Events may be generated - it is your responsibility to
	/// deduplicate them by payment_preimage (which MUST be unique)!
	PaymentSent {
		payment_preimage: crate::c_types::ThirtyTwoBytes,
	},
	/// Indicates an outbound payment we made failed. Probably some intermediary node dropped
	/// something. You may wish to retry with a different route.
	/// Note that duplicative PaymentFailed Events may be generated - it is your responsibility to
	/// deduplicate them by payment_hash (which MUST be unique)!
	PaymentFailed {
		payment_hash: crate::c_types::ThirtyTwoBytes,
		rejected_by_dest: bool,
	},
	/// Used to indicate that ChannelManager::process_pending_htlc_forwards should be called at a
	/// time in the future.
	PendingHTLCsForwardable {
		time_forwardable: u64,
	},
	/// Used to indicate that an output was generated on-chain which you should know how to spend.
	/// Such an output will *not* ever be spent by rust-lightning, and are not at risk of your
	/// counterparty spending them due to some kind of timeout. Thus, you need to store them
	/// somewhere and spend them when you create on-chain transactions.
	SpendableOutputs {
		outputs: crate::c_types::derived::CVec_SpendableOutputDescriptorZ,
	},
}
use lightning::util::events::Event as nativeEvent;
impl Event {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeEvent {
		match self {
			Event::FundingGenerationReady {ref temporary_channel_id, ref channel_value_satoshis, ref output_script, ref user_channel_id, } => {
				let mut temporary_channel_id_nonref = (*temporary_channel_id).clone();
				let mut channel_value_satoshis_nonref = (*channel_value_satoshis).clone();
				let mut output_script_nonref = (*output_script).clone();
				let mut user_channel_id_nonref = (*user_channel_id).clone();
				nativeEvent::FundingGenerationReady {
					temporary_channel_id: temporary_channel_id_nonref.data,
					channel_value_satoshis: channel_value_satoshis_nonref,
					output_script: ::bitcoin::blockdata::script::Script::from(output_script_nonref.into_rust()),
					user_channel_id: user_channel_id_nonref,
				}
			},
			Event::FundingBroadcastSafe {ref funding_txo, ref user_channel_id, } => {
				let mut funding_txo_nonref = (*funding_txo).clone();
				let mut user_channel_id_nonref = (*user_channel_id).clone();
				nativeEvent::FundingBroadcastSafe {
					funding_txo: *unsafe { Box::from_raw(funding_txo_nonref.take_inner()) },
					user_channel_id: user_channel_id_nonref,
				}
			},
			Event::PaymentReceived {ref payment_hash, ref payment_secret, ref amt, } => {
				let mut payment_hash_nonref = (*payment_hash).clone();
				let mut payment_secret_nonref = (*payment_secret).clone();
				let mut local_payment_secret_nonref = if payment_secret_nonref.data == [0; 32] { None } else { Some( { ::lightning::ln::channelmanager::PaymentSecret(payment_secret_nonref.data) }) };
				let mut amt_nonref = (*amt).clone();
				nativeEvent::PaymentReceived {
					payment_hash: ::lightning::ln::channelmanager::PaymentHash(payment_hash_nonref.data),
					payment_secret: local_payment_secret_nonref,
					amt: amt_nonref,
				}
			},
			Event::PaymentSent {ref payment_preimage, } => {
				let mut payment_preimage_nonref = (*payment_preimage).clone();
				nativeEvent::PaymentSent {
					payment_preimage: ::lightning::ln::channelmanager::PaymentPreimage(payment_preimage_nonref.data),
				}
			},
			Event::PaymentFailed {ref payment_hash, ref rejected_by_dest, } => {
				let mut payment_hash_nonref = (*payment_hash).clone();
				let mut rejected_by_dest_nonref = (*rejected_by_dest).clone();
				nativeEvent::PaymentFailed {
					payment_hash: ::lightning::ln::channelmanager::PaymentHash(payment_hash_nonref.data),
					rejected_by_dest: rejected_by_dest_nonref,
				}
			},
			Event::PendingHTLCsForwardable {ref time_forwardable, } => {
				let mut time_forwardable_nonref = (*time_forwardable).clone();
				nativeEvent::PendingHTLCsForwardable {
					time_forwardable: std::time::Duration::from_secs(time_forwardable_nonref),
				}
			},
			Event::SpendableOutputs {ref outputs, } => {
				let mut outputs_nonref = (*outputs).clone();
				let mut local_outputs_nonref = Vec::new(); for mut item in outputs_nonref.into_rust().drain(..) { local_outputs_nonref.push( { item.into_native() }); };
				nativeEvent::SpendableOutputs {
					outputs: local_outputs_nonref,
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeEvent {
		match self {
			Event::FundingGenerationReady {mut temporary_channel_id, mut channel_value_satoshis, mut output_script, mut user_channel_id, } => {
				nativeEvent::FundingGenerationReady {
					temporary_channel_id: temporary_channel_id.data,
					channel_value_satoshis: channel_value_satoshis,
					output_script: ::bitcoin::blockdata::script::Script::from(output_script.into_rust()),
					user_channel_id: user_channel_id,
				}
			},
			Event::FundingBroadcastSafe {mut funding_txo, mut user_channel_id, } => {
				nativeEvent::FundingBroadcastSafe {
					funding_txo: *unsafe { Box::from_raw(funding_txo.take_inner()) },
					user_channel_id: user_channel_id,
				}
			},
			Event::PaymentReceived {mut payment_hash, mut payment_secret, mut amt, } => {
				let mut local_payment_secret = if payment_secret.data == [0; 32] { None } else { Some( { ::lightning::ln::channelmanager::PaymentSecret(payment_secret.data) }) };
				nativeEvent::PaymentReceived {
					payment_hash: ::lightning::ln::channelmanager::PaymentHash(payment_hash.data),
					payment_secret: local_payment_secret,
					amt: amt,
				}
			},
			Event::PaymentSent {mut payment_preimage, } => {
				nativeEvent::PaymentSent {
					payment_preimage: ::lightning::ln::channelmanager::PaymentPreimage(payment_preimage.data),
				}
			},
			Event::PaymentFailed {mut payment_hash, mut rejected_by_dest, } => {
				nativeEvent::PaymentFailed {
					payment_hash: ::lightning::ln::channelmanager::PaymentHash(payment_hash.data),
					rejected_by_dest: rejected_by_dest,
				}
			},
			Event::PendingHTLCsForwardable {mut time_forwardable, } => {
				nativeEvent::PendingHTLCsForwardable {
					time_forwardable: std::time::Duration::from_secs(time_forwardable),
				}
			},
			Event::SpendableOutputs {mut outputs, } => {
				let mut local_outputs = Vec::new(); for mut item in outputs.into_rust().drain(..) { local_outputs.push( { item.into_native() }); };
				nativeEvent::SpendableOutputs {
					outputs: local_outputs,
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &nativeEvent) -> Self {
		match native {
			nativeEvent::FundingGenerationReady {ref temporary_channel_id, ref channel_value_satoshis, ref output_script, ref user_channel_id, } => {
				let mut temporary_channel_id_nonref = (*temporary_channel_id).clone();
				let mut channel_value_satoshis_nonref = (*channel_value_satoshis).clone();
				let mut output_script_nonref = (*output_script).clone();
				let mut user_channel_id_nonref = (*user_channel_id).clone();
				Event::FundingGenerationReady {
					temporary_channel_id: crate::c_types::ThirtyTwoBytes { data: temporary_channel_id_nonref },
					channel_value_satoshis: channel_value_satoshis_nonref,
					output_script: output_script_nonref.into_bytes().into(),
					user_channel_id: user_channel_id_nonref,
				}
			},
			nativeEvent::FundingBroadcastSafe {ref funding_txo, ref user_channel_id, } => {
				let mut funding_txo_nonref = (*funding_txo).clone();
				let mut user_channel_id_nonref = (*user_channel_id).clone();
				Event::FundingBroadcastSafe {
					funding_txo: crate::chain::transaction::OutPoint { inner: Box::into_raw(Box::new(funding_txo_nonref)), is_owned: true },
					user_channel_id: user_channel_id_nonref,
				}
			},
			nativeEvent::PaymentReceived {ref payment_hash, ref payment_secret, ref amt, } => {
				let mut payment_hash_nonref = (*payment_hash).clone();
				let mut payment_secret_nonref = (*payment_secret).clone();
				let mut local_payment_secret_nonref = if payment_secret_nonref.is_none() { crate::c_types::ThirtyTwoBytes::null() } else {  { crate::c_types::ThirtyTwoBytes { data: (payment_secret_nonref.unwrap()).0 } } };
				let mut amt_nonref = (*amt).clone();
				Event::PaymentReceived {
					payment_hash: crate::c_types::ThirtyTwoBytes { data: payment_hash_nonref.0 },
					payment_secret: local_payment_secret_nonref,
					amt: amt_nonref,
				}
			},
			nativeEvent::PaymentSent {ref payment_preimage, } => {
				let mut payment_preimage_nonref = (*payment_preimage).clone();
				Event::PaymentSent {
					payment_preimage: crate::c_types::ThirtyTwoBytes { data: payment_preimage_nonref.0 },
				}
			},
			nativeEvent::PaymentFailed {ref payment_hash, ref rejected_by_dest, } => {
				let mut payment_hash_nonref = (*payment_hash).clone();
				let mut rejected_by_dest_nonref = (*rejected_by_dest).clone();
				Event::PaymentFailed {
					payment_hash: crate::c_types::ThirtyTwoBytes { data: payment_hash_nonref.0 },
					rejected_by_dest: rejected_by_dest_nonref,
				}
			},
			nativeEvent::PendingHTLCsForwardable {ref time_forwardable, } => {
				let mut time_forwardable_nonref = (*time_forwardable).clone();
				Event::PendingHTLCsForwardable {
					time_forwardable: time_forwardable_nonref.as_secs(),
				}
			},
			nativeEvent::SpendableOutputs {ref outputs, } => {
				let mut outputs_nonref = (*outputs).clone();
				let mut local_outputs_nonref = Vec::new(); for item in outputs_nonref.drain(..) { local_outputs_nonref.push( { crate::chain::keysinterface::SpendableOutputDescriptor::native_into(item) }); };
				Event::SpendableOutputs {
					outputs: local_outputs_nonref.into(),
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeEvent) -> Self {
		match native {
			nativeEvent::FundingGenerationReady {mut temporary_channel_id, mut channel_value_satoshis, mut output_script, mut user_channel_id, } => {
				Event::FundingGenerationReady {
					temporary_channel_id: crate::c_types::ThirtyTwoBytes { data: temporary_channel_id },
					channel_value_satoshis: channel_value_satoshis,
					output_script: output_script.into_bytes().into(),
					user_channel_id: user_channel_id,
				}
			},
			nativeEvent::FundingBroadcastSafe {mut funding_txo, mut user_channel_id, } => {
				Event::FundingBroadcastSafe {
					funding_txo: crate::chain::transaction::OutPoint { inner: Box::into_raw(Box::new(funding_txo)), is_owned: true },
					user_channel_id: user_channel_id,
				}
			},
			nativeEvent::PaymentReceived {mut payment_hash, mut payment_secret, mut amt, } => {
				let mut local_payment_secret = if payment_secret.is_none() { crate::c_types::ThirtyTwoBytes::null() } else {  { crate::c_types::ThirtyTwoBytes { data: (payment_secret.unwrap()).0 } } };
				Event::PaymentReceived {
					payment_hash: crate::c_types::ThirtyTwoBytes { data: payment_hash.0 },
					payment_secret: local_payment_secret,
					amt: amt,
				}
			},
			nativeEvent::PaymentSent {mut payment_preimage, } => {
				Event::PaymentSent {
					payment_preimage: crate::c_types::ThirtyTwoBytes { data: payment_preimage.0 },
				}
			},
			nativeEvent::PaymentFailed {mut payment_hash, mut rejected_by_dest, } => {
				Event::PaymentFailed {
					payment_hash: crate::c_types::ThirtyTwoBytes { data: payment_hash.0 },
					rejected_by_dest: rejected_by_dest,
				}
			},
			nativeEvent::PendingHTLCsForwardable {mut time_forwardable, } => {
				Event::PendingHTLCsForwardable {
					time_forwardable: time_forwardable.as_secs(),
				}
			},
			nativeEvent::SpendableOutputs {mut outputs, } => {
				let mut local_outputs = Vec::new(); for item in outputs.drain(..) { local_outputs.push( { crate::chain::keysinterface::SpendableOutputDescriptor::native_into(item) }); };
				Event::SpendableOutputs {
					outputs: local_outputs.into(),
				}
			},
		}
	}
}
#[no_mangle]
pub extern "C" fn Event_free(this_ptr: Event) { }
#[no_mangle]
pub extern "C" fn Event_clone(orig: &Event) -> Event {
	orig.clone()
}
/// An event generated by ChannelManager which indicates a message should be sent to a peer (or
/// broadcast to most peers).
/// These events are handled by PeerManager::process_events if you are using a PeerManager.
#[must_use]
#[derive(Clone)]
#[repr(C)]
pub enum MessageSendEvent {
	/// Used to indicate that we've accepted a channel open and should send the accept_channel
	/// message provided to the given peer.
	SendAcceptChannel {
		node_id: crate::c_types::PublicKey,
		msg: crate::ln::msgs::AcceptChannel,
	},
	/// Used to indicate that we've initiated a channel open and should send the open_channel
	/// message provided to the given peer.
	SendOpenChannel {
		node_id: crate::c_types::PublicKey,
		msg: crate::ln::msgs::OpenChannel,
	},
	/// Used to indicate that a funding_created message should be sent to the peer with the given node_id.
	SendFundingCreated {
		node_id: crate::c_types::PublicKey,
		msg: crate::ln::msgs::FundingCreated,
	},
	/// Used to indicate that a funding_signed message should be sent to the peer with the given node_id.
	SendFundingSigned {
		node_id: crate::c_types::PublicKey,
		msg: crate::ln::msgs::FundingSigned,
	},
	/// Used to indicate that a funding_locked message should be sent to the peer with the given node_id.
	SendFundingLocked {
		node_id: crate::c_types::PublicKey,
		msg: crate::ln::msgs::FundingLocked,
	},
	/// Used to indicate that an announcement_signatures message should be sent to the peer with the given node_id.
	SendAnnouncementSignatures {
		node_id: crate::c_types::PublicKey,
		msg: crate::ln::msgs::AnnouncementSignatures,
	},
	/// Used to indicate that a series of HTLC update messages, as well as a commitment_signed
	/// message should be sent to the peer with the given node_id.
	UpdateHTLCs {
		node_id: crate::c_types::PublicKey,
		updates: crate::ln::msgs::CommitmentUpdate,
	},
	/// Used to indicate that a revoke_and_ack message should be sent to the peer with the given node_id.
	SendRevokeAndACK {
		node_id: crate::c_types::PublicKey,
		msg: crate::ln::msgs::RevokeAndACK,
	},
	/// Used to indicate that a closing_signed message should be sent to the peer with the given node_id.
	SendClosingSigned {
		node_id: crate::c_types::PublicKey,
		msg: crate::ln::msgs::ClosingSigned,
	},
	/// Used to indicate that a shutdown message should be sent to the peer with the given node_id.
	SendShutdown {
		node_id: crate::c_types::PublicKey,
		msg: crate::ln::msgs::Shutdown,
	},
	/// Used to indicate that a channel_reestablish message should be sent to the peer with the given node_id.
	SendChannelReestablish {
		node_id: crate::c_types::PublicKey,
		msg: crate::ln::msgs::ChannelReestablish,
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
		msg: crate::ln::msgs::ChannelAnnouncement,
		update_msg: crate::ln::msgs::ChannelUpdate,
	},
	/// Used to indicate that a node_announcement should be broadcast to all peers.
	BroadcastNodeAnnouncement {
		msg: crate::ln::msgs::NodeAnnouncement,
	},
	/// Used to indicate that a channel_update should be broadcast to all peers.
	BroadcastChannelUpdate {
		msg: crate::ln::msgs::ChannelUpdate,
	},
	/// Broadcast an error downstream to be handled
	HandleError {
		node_id: crate::c_types::PublicKey,
		action: crate::ln::msgs::ErrorAction,
	},
	/// When a payment fails we may receive updates back from the hop where it failed. In such
	/// cases this event is generated so that we can inform the network graph of this information.
	PaymentFailureNetworkUpdate {
		update: crate::ln::msgs::HTLCFailChannelUpdate,
	},
	/// Query a peer for channels with funding transaction UTXOs in a block range.
	SendChannelRangeQuery {
		node_id: crate::c_types::PublicKey,
		msg: crate::ln::msgs::QueryChannelRange,
	},
	/// Request routing gossip messages from a peer for a list of channels identified by
	/// their short_channel_ids.
	SendShortIdsQuery {
		node_id: crate::c_types::PublicKey,
		msg: crate::ln::msgs::QueryShortChannelIds,
	},
}
use lightning::util::events::MessageSendEvent as nativeMessageSendEvent;
impl MessageSendEvent {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeMessageSendEvent {
		match self {
			MessageSendEvent::SendAcceptChannel {ref node_id, ref msg, } => {
				let mut node_id_nonref = (*node_id).clone();
				let mut msg_nonref = (*msg).clone();
				nativeMessageSendEvent::SendAcceptChannel {
					node_id: node_id_nonref.into_rust(),
					msg: *unsafe { Box::from_raw(msg_nonref.take_inner()) },
				}
			},
			MessageSendEvent::SendOpenChannel {ref node_id, ref msg, } => {
				let mut node_id_nonref = (*node_id).clone();
				let mut msg_nonref = (*msg).clone();
				nativeMessageSendEvent::SendOpenChannel {
					node_id: node_id_nonref.into_rust(),
					msg: *unsafe { Box::from_raw(msg_nonref.take_inner()) },
				}
			},
			MessageSendEvent::SendFundingCreated {ref node_id, ref msg, } => {
				let mut node_id_nonref = (*node_id).clone();
				let mut msg_nonref = (*msg).clone();
				nativeMessageSendEvent::SendFundingCreated {
					node_id: node_id_nonref.into_rust(),
					msg: *unsafe { Box::from_raw(msg_nonref.take_inner()) },
				}
			},
			MessageSendEvent::SendFundingSigned {ref node_id, ref msg, } => {
				let mut node_id_nonref = (*node_id).clone();
				let mut msg_nonref = (*msg).clone();
				nativeMessageSendEvent::SendFundingSigned {
					node_id: node_id_nonref.into_rust(),
					msg: *unsafe { Box::from_raw(msg_nonref.take_inner()) },
				}
			},
			MessageSendEvent::SendFundingLocked {ref node_id, ref msg, } => {
				let mut node_id_nonref = (*node_id).clone();
				let mut msg_nonref = (*msg).clone();
				nativeMessageSendEvent::SendFundingLocked {
					node_id: node_id_nonref.into_rust(),
					msg: *unsafe { Box::from_raw(msg_nonref.take_inner()) },
				}
			},
			MessageSendEvent::SendAnnouncementSignatures {ref node_id, ref msg, } => {
				let mut node_id_nonref = (*node_id).clone();
				let mut msg_nonref = (*msg).clone();
				nativeMessageSendEvent::SendAnnouncementSignatures {
					node_id: node_id_nonref.into_rust(),
					msg: *unsafe { Box::from_raw(msg_nonref.take_inner()) },
				}
			},
			MessageSendEvent::UpdateHTLCs {ref node_id, ref updates, } => {
				let mut node_id_nonref = (*node_id).clone();
				let mut updates_nonref = (*updates).clone();
				nativeMessageSendEvent::UpdateHTLCs {
					node_id: node_id_nonref.into_rust(),
					updates: *unsafe { Box::from_raw(updates_nonref.take_inner()) },
				}
			},
			MessageSendEvent::SendRevokeAndACK {ref node_id, ref msg, } => {
				let mut node_id_nonref = (*node_id).clone();
				let mut msg_nonref = (*msg).clone();
				nativeMessageSendEvent::SendRevokeAndACK {
					node_id: node_id_nonref.into_rust(),
					msg: *unsafe { Box::from_raw(msg_nonref.take_inner()) },
				}
			},
			MessageSendEvent::SendClosingSigned {ref node_id, ref msg, } => {
				let mut node_id_nonref = (*node_id).clone();
				let mut msg_nonref = (*msg).clone();
				nativeMessageSendEvent::SendClosingSigned {
					node_id: node_id_nonref.into_rust(),
					msg: *unsafe { Box::from_raw(msg_nonref.take_inner()) },
				}
			},
			MessageSendEvent::SendShutdown {ref node_id, ref msg, } => {
				let mut node_id_nonref = (*node_id).clone();
				let mut msg_nonref = (*msg).clone();
				nativeMessageSendEvent::SendShutdown {
					node_id: node_id_nonref.into_rust(),
					msg: *unsafe { Box::from_raw(msg_nonref.take_inner()) },
				}
			},
			MessageSendEvent::SendChannelReestablish {ref node_id, ref msg, } => {
				let mut node_id_nonref = (*node_id).clone();
				let mut msg_nonref = (*msg).clone();
				nativeMessageSendEvent::SendChannelReestablish {
					node_id: node_id_nonref.into_rust(),
					msg: *unsafe { Box::from_raw(msg_nonref.take_inner()) },
				}
			},
			MessageSendEvent::BroadcastChannelAnnouncement {ref msg, ref update_msg, } => {
				let mut msg_nonref = (*msg).clone();
				let mut update_msg_nonref = (*update_msg).clone();
				nativeMessageSendEvent::BroadcastChannelAnnouncement {
					msg: *unsafe { Box::from_raw(msg_nonref.take_inner()) },
					update_msg: *unsafe { Box::from_raw(update_msg_nonref.take_inner()) },
				}
			},
			MessageSendEvent::BroadcastNodeAnnouncement {ref msg, } => {
				let mut msg_nonref = (*msg).clone();
				nativeMessageSendEvent::BroadcastNodeAnnouncement {
					msg: *unsafe { Box::from_raw(msg_nonref.take_inner()) },
				}
			},
			MessageSendEvent::BroadcastChannelUpdate {ref msg, } => {
				let mut msg_nonref = (*msg).clone();
				nativeMessageSendEvent::BroadcastChannelUpdate {
					msg: *unsafe { Box::from_raw(msg_nonref.take_inner()) },
				}
			},
			MessageSendEvent::HandleError {ref node_id, ref action, } => {
				let mut node_id_nonref = (*node_id).clone();
				let mut action_nonref = (*action).clone();
				nativeMessageSendEvent::HandleError {
					node_id: node_id_nonref.into_rust(),
					action: action_nonref.into_native(),
				}
			},
			MessageSendEvent::PaymentFailureNetworkUpdate {ref update, } => {
				let mut update_nonref = (*update).clone();
				nativeMessageSendEvent::PaymentFailureNetworkUpdate {
					update: update_nonref.into_native(),
				}
			},
			MessageSendEvent::SendChannelRangeQuery {ref node_id, ref msg, } => {
				let mut node_id_nonref = (*node_id).clone();
				let mut msg_nonref = (*msg).clone();
				nativeMessageSendEvent::SendChannelRangeQuery {
					node_id: node_id_nonref.into_rust(),
					msg: *unsafe { Box::from_raw(msg_nonref.take_inner()) },
				}
			},
			MessageSendEvent::SendShortIdsQuery {ref node_id, ref msg, } => {
				let mut node_id_nonref = (*node_id).clone();
				let mut msg_nonref = (*msg).clone();
				nativeMessageSendEvent::SendShortIdsQuery {
					node_id: node_id_nonref.into_rust(),
					msg: *unsafe { Box::from_raw(msg_nonref.take_inner()) },
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeMessageSendEvent {
		match self {
			MessageSendEvent::SendAcceptChannel {mut node_id, mut msg, } => {
				nativeMessageSendEvent::SendAcceptChannel {
					node_id: node_id.into_rust(),
					msg: *unsafe { Box::from_raw(msg.take_inner()) },
				}
			},
			MessageSendEvent::SendOpenChannel {mut node_id, mut msg, } => {
				nativeMessageSendEvent::SendOpenChannel {
					node_id: node_id.into_rust(),
					msg: *unsafe { Box::from_raw(msg.take_inner()) },
				}
			},
			MessageSendEvent::SendFundingCreated {mut node_id, mut msg, } => {
				nativeMessageSendEvent::SendFundingCreated {
					node_id: node_id.into_rust(),
					msg: *unsafe { Box::from_raw(msg.take_inner()) },
				}
			},
			MessageSendEvent::SendFundingSigned {mut node_id, mut msg, } => {
				nativeMessageSendEvent::SendFundingSigned {
					node_id: node_id.into_rust(),
					msg: *unsafe { Box::from_raw(msg.take_inner()) },
				}
			},
			MessageSendEvent::SendFundingLocked {mut node_id, mut msg, } => {
				nativeMessageSendEvent::SendFundingLocked {
					node_id: node_id.into_rust(),
					msg: *unsafe { Box::from_raw(msg.take_inner()) },
				}
			},
			MessageSendEvent::SendAnnouncementSignatures {mut node_id, mut msg, } => {
				nativeMessageSendEvent::SendAnnouncementSignatures {
					node_id: node_id.into_rust(),
					msg: *unsafe { Box::from_raw(msg.take_inner()) },
				}
			},
			MessageSendEvent::UpdateHTLCs {mut node_id, mut updates, } => {
				nativeMessageSendEvent::UpdateHTLCs {
					node_id: node_id.into_rust(),
					updates: *unsafe { Box::from_raw(updates.take_inner()) },
				}
			},
			MessageSendEvent::SendRevokeAndACK {mut node_id, mut msg, } => {
				nativeMessageSendEvent::SendRevokeAndACK {
					node_id: node_id.into_rust(),
					msg: *unsafe { Box::from_raw(msg.take_inner()) },
				}
			},
			MessageSendEvent::SendClosingSigned {mut node_id, mut msg, } => {
				nativeMessageSendEvent::SendClosingSigned {
					node_id: node_id.into_rust(),
					msg: *unsafe { Box::from_raw(msg.take_inner()) },
				}
			},
			MessageSendEvent::SendShutdown {mut node_id, mut msg, } => {
				nativeMessageSendEvent::SendShutdown {
					node_id: node_id.into_rust(),
					msg: *unsafe { Box::from_raw(msg.take_inner()) },
				}
			},
			MessageSendEvent::SendChannelReestablish {mut node_id, mut msg, } => {
				nativeMessageSendEvent::SendChannelReestablish {
					node_id: node_id.into_rust(),
					msg: *unsafe { Box::from_raw(msg.take_inner()) },
				}
			},
			MessageSendEvent::BroadcastChannelAnnouncement {mut msg, mut update_msg, } => {
				nativeMessageSendEvent::BroadcastChannelAnnouncement {
					msg: *unsafe { Box::from_raw(msg.take_inner()) },
					update_msg: *unsafe { Box::from_raw(update_msg.take_inner()) },
				}
			},
			MessageSendEvent::BroadcastNodeAnnouncement {mut msg, } => {
				nativeMessageSendEvent::BroadcastNodeAnnouncement {
					msg: *unsafe { Box::from_raw(msg.take_inner()) },
				}
			},
			MessageSendEvent::BroadcastChannelUpdate {mut msg, } => {
				nativeMessageSendEvent::BroadcastChannelUpdate {
					msg: *unsafe { Box::from_raw(msg.take_inner()) },
				}
			},
			MessageSendEvent::HandleError {mut node_id, mut action, } => {
				nativeMessageSendEvent::HandleError {
					node_id: node_id.into_rust(),
					action: action.into_native(),
				}
			},
			MessageSendEvent::PaymentFailureNetworkUpdate {mut update, } => {
				nativeMessageSendEvent::PaymentFailureNetworkUpdate {
					update: update.into_native(),
				}
			},
			MessageSendEvent::SendChannelRangeQuery {mut node_id, mut msg, } => {
				nativeMessageSendEvent::SendChannelRangeQuery {
					node_id: node_id.into_rust(),
					msg: *unsafe { Box::from_raw(msg.take_inner()) },
				}
			},
			MessageSendEvent::SendShortIdsQuery {mut node_id, mut msg, } => {
				nativeMessageSendEvent::SendShortIdsQuery {
					node_id: node_id.into_rust(),
					msg: *unsafe { Box::from_raw(msg.take_inner()) },
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &nativeMessageSendEvent) -> Self {
		match native {
			nativeMessageSendEvent::SendAcceptChannel {ref node_id, ref msg, } => {
				let mut node_id_nonref = (*node_id).clone();
				let mut msg_nonref = (*msg).clone();
				MessageSendEvent::SendAcceptChannel {
					node_id: crate::c_types::PublicKey::from_rust(&node_id_nonref),
					msg: crate::ln::msgs::AcceptChannel { inner: Box::into_raw(Box::new(msg_nonref)), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendOpenChannel {ref node_id, ref msg, } => {
				let mut node_id_nonref = (*node_id).clone();
				let mut msg_nonref = (*msg).clone();
				MessageSendEvent::SendOpenChannel {
					node_id: crate::c_types::PublicKey::from_rust(&node_id_nonref),
					msg: crate::ln::msgs::OpenChannel { inner: Box::into_raw(Box::new(msg_nonref)), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendFundingCreated {ref node_id, ref msg, } => {
				let mut node_id_nonref = (*node_id).clone();
				let mut msg_nonref = (*msg).clone();
				MessageSendEvent::SendFundingCreated {
					node_id: crate::c_types::PublicKey::from_rust(&node_id_nonref),
					msg: crate::ln::msgs::FundingCreated { inner: Box::into_raw(Box::new(msg_nonref)), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendFundingSigned {ref node_id, ref msg, } => {
				let mut node_id_nonref = (*node_id).clone();
				let mut msg_nonref = (*msg).clone();
				MessageSendEvent::SendFundingSigned {
					node_id: crate::c_types::PublicKey::from_rust(&node_id_nonref),
					msg: crate::ln::msgs::FundingSigned { inner: Box::into_raw(Box::new(msg_nonref)), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendFundingLocked {ref node_id, ref msg, } => {
				let mut node_id_nonref = (*node_id).clone();
				let mut msg_nonref = (*msg).clone();
				MessageSendEvent::SendFundingLocked {
					node_id: crate::c_types::PublicKey::from_rust(&node_id_nonref),
					msg: crate::ln::msgs::FundingLocked { inner: Box::into_raw(Box::new(msg_nonref)), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendAnnouncementSignatures {ref node_id, ref msg, } => {
				let mut node_id_nonref = (*node_id).clone();
				let mut msg_nonref = (*msg).clone();
				MessageSendEvent::SendAnnouncementSignatures {
					node_id: crate::c_types::PublicKey::from_rust(&node_id_nonref),
					msg: crate::ln::msgs::AnnouncementSignatures { inner: Box::into_raw(Box::new(msg_nonref)), is_owned: true },
				}
			},
			nativeMessageSendEvent::UpdateHTLCs {ref node_id, ref updates, } => {
				let mut node_id_nonref = (*node_id).clone();
				let mut updates_nonref = (*updates).clone();
				MessageSendEvent::UpdateHTLCs {
					node_id: crate::c_types::PublicKey::from_rust(&node_id_nonref),
					updates: crate::ln::msgs::CommitmentUpdate { inner: Box::into_raw(Box::new(updates_nonref)), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendRevokeAndACK {ref node_id, ref msg, } => {
				let mut node_id_nonref = (*node_id).clone();
				let mut msg_nonref = (*msg).clone();
				MessageSendEvent::SendRevokeAndACK {
					node_id: crate::c_types::PublicKey::from_rust(&node_id_nonref),
					msg: crate::ln::msgs::RevokeAndACK { inner: Box::into_raw(Box::new(msg_nonref)), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendClosingSigned {ref node_id, ref msg, } => {
				let mut node_id_nonref = (*node_id).clone();
				let mut msg_nonref = (*msg).clone();
				MessageSendEvent::SendClosingSigned {
					node_id: crate::c_types::PublicKey::from_rust(&node_id_nonref),
					msg: crate::ln::msgs::ClosingSigned { inner: Box::into_raw(Box::new(msg_nonref)), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendShutdown {ref node_id, ref msg, } => {
				let mut node_id_nonref = (*node_id).clone();
				let mut msg_nonref = (*msg).clone();
				MessageSendEvent::SendShutdown {
					node_id: crate::c_types::PublicKey::from_rust(&node_id_nonref),
					msg: crate::ln::msgs::Shutdown { inner: Box::into_raw(Box::new(msg_nonref)), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendChannelReestablish {ref node_id, ref msg, } => {
				let mut node_id_nonref = (*node_id).clone();
				let mut msg_nonref = (*msg).clone();
				MessageSendEvent::SendChannelReestablish {
					node_id: crate::c_types::PublicKey::from_rust(&node_id_nonref),
					msg: crate::ln::msgs::ChannelReestablish { inner: Box::into_raw(Box::new(msg_nonref)), is_owned: true },
				}
			},
			nativeMessageSendEvent::BroadcastChannelAnnouncement {ref msg, ref update_msg, } => {
				let mut msg_nonref = (*msg).clone();
				let mut update_msg_nonref = (*update_msg).clone();
				MessageSendEvent::BroadcastChannelAnnouncement {
					msg: crate::ln::msgs::ChannelAnnouncement { inner: Box::into_raw(Box::new(msg_nonref)), is_owned: true },
					update_msg: crate::ln::msgs::ChannelUpdate { inner: Box::into_raw(Box::new(update_msg_nonref)), is_owned: true },
				}
			},
			nativeMessageSendEvent::BroadcastNodeAnnouncement {ref msg, } => {
				let mut msg_nonref = (*msg).clone();
				MessageSendEvent::BroadcastNodeAnnouncement {
					msg: crate::ln::msgs::NodeAnnouncement { inner: Box::into_raw(Box::new(msg_nonref)), is_owned: true },
				}
			},
			nativeMessageSendEvent::BroadcastChannelUpdate {ref msg, } => {
				let mut msg_nonref = (*msg).clone();
				MessageSendEvent::BroadcastChannelUpdate {
					msg: crate::ln::msgs::ChannelUpdate { inner: Box::into_raw(Box::new(msg_nonref)), is_owned: true },
				}
			},
			nativeMessageSendEvent::HandleError {ref node_id, ref action, } => {
				let mut node_id_nonref = (*node_id).clone();
				let mut action_nonref = (*action).clone();
				MessageSendEvent::HandleError {
					node_id: crate::c_types::PublicKey::from_rust(&node_id_nonref),
					action: crate::ln::msgs::ErrorAction::native_into(action_nonref),
				}
			},
			nativeMessageSendEvent::PaymentFailureNetworkUpdate {ref update, } => {
				let mut update_nonref = (*update).clone();
				MessageSendEvent::PaymentFailureNetworkUpdate {
					update: crate::ln::msgs::HTLCFailChannelUpdate::native_into(update_nonref),
				}
			},
			nativeMessageSendEvent::SendChannelRangeQuery {ref node_id, ref msg, } => {
				let mut node_id_nonref = (*node_id).clone();
				let mut msg_nonref = (*msg).clone();
				MessageSendEvent::SendChannelRangeQuery {
					node_id: crate::c_types::PublicKey::from_rust(&node_id_nonref),
					msg: crate::ln::msgs::QueryChannelRange { inner: Box::into_raw(Box::new(msg_nonref)), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendShortIdsQuery {ref node_id, ref msg, } => {
				let mut node_id_nonref = (*node_id).clone();
				let mut msg_nonref = (*msg).clone();
				MessageSendEvent::SendShortIdsQuery {
					node_id: crate::c_types::PublicKey::from_rust(&node_id_nonref),
					msg: crate::ln::msgs::QueryShortChannelIds { inner: Box::into_raw(Box::new(msg_nonref)), is_owned: true },
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeMessageSendEvent) -> Self {
		match native {
			nativeMessageSendEvent::SendAcceptChannel {mut node_id, mut msg, } => {
				MessageSendEvent::SendAcceptChannel {
					node_id: crate::c_types::PublicKey::from_rust(&node_id),
					msg: crate::ln::msgs::AcceptChannel { inner: Box::into_raw(Box::new(msg)), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendOpenChannel {mut node_id, mut msg, } => {
				MessageSendEvent::SendOpenChannel {
					node_id: crate::c_types::PublicKey::from_rust(&node_id),
					msg: crate::ln::msgs::OpenChannel { inner: Box::into_raw(Box::new(msg)), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendFundingCreated {mut node_id, mut msg, } => {
				MessageSendEvent::SendFundingCreated {
					node_id: crate::c_types::PublicKey::from_rust(&node_id),
					msg: crate::ln::msgs::FundingCreated { inner: Box::into_raw(Box::new(msg)), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendFundingSigned {mut node_id, mut msg, } => {
				MessageSendEvent::SendFundingSigned {
					node_id: crate::c_types::PublicKey::from_rust(&node_id),
					msg: crate::ln::msgs::FundingSigned { inner: Box::into_raw(Box::new(msg)), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendFundingLocked {mut node_id, mut msg, } => {
				MessageSendEvent::SendFundingLocked {
					node_id: crate::c_types::PublicKey::from_rust(&node_id),
					msg: crate::ln::msgs::FundingLocked { inner: Box::into_raw(Box::new(msg)), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendAnnouncementSignatures {mut node_id, mut msg, } => {
				MessageSendEvent::SendAnnouncementSignatures {
					node_id: crate::c_types::PublicKey::from_rust(&node_id),
					msg: crate::ln::msgs::AnnouncementSignatures { inner: Box::into_raw(Box::new(msg)), is_owned: true },
				}
			},
			nativeMessageSendEvent::UpdateHTLCs {mut node_id, mut updates, } => {
				MessageSendEvent::UpdateHTLCs {
					node_id: crate::c_types::PublicKey::from_rust(&node_id),
					updates: crate::ln::msgs::CommitmentUpdate { inner: Box::into_raw(Box::new(updates)), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendRevokeAndACK {mut node_id, mut msg, } => {
				MessageSendEvent::SendRevokeAndACK {
					node_id: crate::c_types::PublicKey::from_rust(&node_id),
					msg: crate::ln::msgs::RevokeAndACK { inner: Box::into_raw(Box::new(msg)), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendClosingSigned {mut node_id, mut msg, } => {
				MessageSendEvent::SendClosingSigned {
					node_id: crate::c_types::PublicKey::from_rust(&node_id),
					msg: crate::ln::msgs::ClosingSigned { inner: Box::into_raw(Box::new(msg)), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendShutdown {mut node_id, mut msg, } => {
				MessageSendEvent::SendShutdown {
					node_id: crate::c_types::PublicKey::from_rust(&node_id),
					msg: crate::ln::msgs::Shutdown { inner: Box::into_raw(Box::new(msg)), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendChannelReestablish {mut node_id, mut msg, } => {
				MessageSendEvent::SendChannelReestablish {
					node_id: crate::c_types::PublicKey::from_rust(&node_id),
					msg: crate::ln::msgs::ChannelReestablish { inner: Box::into_raw(Box::new(msg)), is_owned: true },
				}
			},
			nativeMessageSendEvent::BroadcastChannelAnnouncement {mut msg, mut update_msg, } => {
				MessageSendEvent::BroadcastChannelAnnouncement {
					msg: crate::ln::msgs::ChannelAnnouncement { inner: Box::into_raw(Box::new(msg)), is_owned: true },
					update_msg: crate::ln::msgs::ChannelUpdate { inner: Box::into_raw(Box::new(update_msg)), is_owned: true },
				}
			},
			nativeMessageSendEvent::BroadcastNodeAnnouncement {mut msg, } => {
				MessageSendEvent::BroadcastNodeAnnouncement {
					msg: crate::ln::msgs::NodeAnnouncement { inner: Box::into_raw(Box::new(msg)), is_owned: true },
				}
			},
			nativeMessageSendEvent::BroadcastChannelUpdate {mut msg, } => {
				MessageSendEvent::BroadcastChannelUpdate {
					msg: crate::ln::msgs::ChannelUpdate { inner: Box::into_raw(Box::new(msg)), is_owned: true },
				}
			},
			nativeMessageSendEvent::HandleError {mut node_id, mut action, } => {
				MessageSendEvent::HandleError {
					node_id: crate::c_types::PublicKey::from_rust(&node_id),
					action: crate::ln::msgs::ErrorAction::native_into(action),
				}
			},
			nativeMessageSendEvent::PaymentFailureNetworkUpdate {mut update, } => {
				MessageSendEvent::PaymentFailureNetworkUpdate {
					update: crate::ln::msgs::HTLCFailChannelUpdate::native_into(update),
				}
			},
			nativeMessageSendEvent::SendChannelRangeQuery {mut node_id, mut msg, } => {
				MessageSendEvent::SendChannelRangeQuery {
					node_id: crate::c_types::PublicKey::from_rust(&node_id),
					msg: crate::ln::msgs::QueryChannelRange { inner: Box::into_raw(Box::new(msg)), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendShortIdsQuery {mut node_id, mut msg, } => {
				MessageSendEvent::SendShortIdsQuery {
					node_id: crate::c_types::PublicKey::from_rust(&node_id),
					msg: crate::ln::msgs::QueryShortChannelIds { inner: Box::into_raw(Box::new(msg)), is_owned: true },
				}
			},
		}
	}
}
#[no_mangle]
pub extern "C" fn MessageSendEvent_free(this_ptr: MessageSendEvent) { }
#[no_mangle]
pub extern "C" fn MessageSendEvent_clone(orig: &MessageSendEvent) -> MessageSendEvent {
	orig.clone()
}
/// A trait indicating an object may generate message send events
#[repr(C)]
pub struct MessageSendEventsProvider {
	pub this_arg: *mut c_void,
	/// Gets the list of pending events which were generated by previous actions, clearing the list
	/// in the process.
	#[must_use]
	pub get_and_clear_pending_msg_events: extern "C" fn (this_arg: *const c_void) -> crate::c_types::derived::CVec_MessageSendEventZ,
	pub free: Option<extern "C" fn(this_arg: *mut c_void)>,
}

use lightning::util::events::MessageSendEventsProvider as rustMessageSendEventsProvider;
impl rustMessageSendEventsProvider for MessageSendEventsProvider {
	fn get_and_clear_pending_msg_events(&self) -> Vec<lightning::util::events::MessageSendEvent> {
		let mut ret = (self.get_and_clear_pending_msg_events)(self.this_arg);
		let mut local_ret = Vec::new(); for mut item in ret.into_rust().drain(..) { local_ret.push( { item.into_native() }); };
		local_ret
	}
}

// We're essentially a pointer already, or at least a set of pointers, so allow us to be used
// directly as a Deref trait in higher-level structs:
impl std::ops::Deref for MessageSendEventsProvider {
	type Target = Self;
	fn deref(&self) -> &Self {
		self
	}
}
/// Calls the free function if one is set
#[no_mangle]
pub extern "C" fn MessageSendEventsProvider_free(this_ptr: MessageSendEventsProvider) { }
impl Drop for MessageSendEventsProvider {
	fn drop(&mut self) {
		if let Some(f) = self.free {
			f(self.this_arg);
		}
	}
}
/// A trait indicating an object may generate events
#[repr(C)]
pub struct EventsProvider {
	pub this_arg: *mut c_void,
	/// Gets the list of pending events which were generated by previous actions, clearing the list
	/// in the process.
	#[must_use]
	pub get_and_clear_pending_events: extern "C" fn (this_arg: *const c_void) -> crate::c_types::derived::CVec_EventZ,
	pub free: Option<extern "C" fn(this_arg: *mut c_void)>,
}

use lightning::util::events::EventsProvider as rustEventsProvider;
impl rustEventsProvider for EventsProvider {
	fn get_and_clear_pending_events(&self) -> Vec<lightning::util::events::Event> {
		let mut ret = (self.get_and_clear_pending_events)(self.this_arg);
		let mut local_ret = Vec::new(); for mut item in ret.into_rust().drain(..) { local_ret.push( { item.into_native() }); };
		local_ret
	}
}

// We're essentially a pointer already, or at least a set of pointers, so allow us to be used
// directly as a Deref trait in higher-level structs:
impl std::ops::Deref for EventsProvider {
	type Target = Self;
	fn deref(&self) -> &Self {
		self
	}
}
/// Calls the free function if one is set
#[no_mangle]
pub extern "C" fn EventsProvider_free(this_ptr: EventsProvider) { }
impl Drop for EventsProvider {
	fn drop(&mut self) {
		if let Some(f) = self.free {
			f(self.this_arg);
		}
	}
}
