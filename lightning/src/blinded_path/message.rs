// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Data structures and methods for constructing [`BlindedMessagePath`]s to send a message over.

use bitcoin::secp256k1::{self, PublicKey, Secp256k1, SecretKey};

#[allow(unused_imports)]
use crate::prelude::*;

use crate::blinded_path::utils::{self, BlindedPathWithPadding};
use crate::blinded_path::{BlindedHop, BlindedPath, Direction, IntroductionNode, NodeIdLookUp};
use crate::crypto::streams::ChaChaPolyReadAdapter;
use crate::io;
use crate::io::Cursor;
use crate::ln::channelmanager::PaymentId;
use crate::ln::msgs::DecodeError;
use crate::ln::onion_utils;
use crate::offers::nonce::Nonce;
use crate::offers::offer::OfferId;
use crate::onion_message::packet::ControlTlvs;
use crate::routing::gossip::{NodeId, ReadOnlyNetworkGraph};
use crate::sign::{EntropySource, NodeSigner, ReceiveAuthKey, Recipient};
use crate::types::payment::PaymentHash;
use crate::util::scid_utils;
use crate::util::ser::{FixedLengthReader, LengthReadableArgs, Readable, Writeable, Writer};

use core::mem;
use core::ops::Deref;
use core::time::Duration;

/// A blinded path to be used for sending or receiving a message, hiding the identity of the
/// recipient.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct BlindedMessagePath(pub(super) BlindedPath);

impl Writeable for BlindedMessagePath {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		self.0.write(w)
	}
}

impl Readable for BlindedMessagePath {
	fn read<R: io::Read>(r: &mut R) -> Result<Self, DecodeError> {
		Ok(Self(BlindedPath::read(r)?))
	}
}

impl BlindedMessagePath {
	/// Create a one-hop blinded path for a message.
	pub fn one_hop<ES: Deref, T: secp256k1::Signing + secp256k1::Verification>(
		recipient_node_id: PublicKey, local_node_receive_key: ReceiveAuthKey,
		context: MessageContext, entropy_source: ES, secp_ctx: &Secp256k1<T>,
	) -> Result<Self, ()>
	where
		ES::Target: EntropySource,
	{
		Self::new(&[], recipient_node_id, local_node_receive_key, context, entropy_source, secp_ctx)
	}

	/// Create a path for an onion message, to be forwarded along `node_pks`. The last node
	/// pubkey in `node_pks` will be the destination node.
	///
	/// Errors if no hops are provided or if `node_pk`(s) are invalid.
	//  TODO: make all payloads the same size with padding + add dummy hops
	pub fn new<ES: Deref, T: secp256k1::Signing + secp256k1::Verification>(
		intermediate_nodes: &[MessageForwardNode], recipient_node_id: PublicKey,
		local_node_receive_key: ReceiveAuthKey, context: MessageContext, entropy_source: ES,
		secp_ctx: &Secp256k1<T>,
	) -> Result<Self, ()>
	where
		ES::Target: EntropySource,
	{
		let introduction_node = IntroductionNode::NodeId(
			intermediate_nodes.first().map_or(recipient_node_id, |n| n.node_id),
		);
		let blinding_secret_bytes = entropy_source.get_secure_random_bytes();
		let blinding_secret =
			SecretKey::from_slice(&blinding_secret_bytes[..]).expect("RNG is busted");

		Ok(Self(BlindedPath {
			introduction_node,
			blinding_point: PublicKey::from_secret_key(secp_ctx, &blinding_secret),
			blinded_hops: blinded_hops(
				secp_ctx,
				intermediate_nodes,
				recipient_node_id,
				context,
				&blinding_secret,
				local_node_receive_key,
			)
			.map_err(|_| ())?,
		}))
	}

	/// Attempts to a use a compact representation for the [`IntroductionNode`] by using a directed
	/// short channel id from a channel in `network_graph` leading to the introduction node.
	///
	/// While this may result in a smaller encoding, there is a trade off in that the path may
	/// become invalid if the channel is closed or hasn't been propagated via gossip. Therefore,
	/// calling this may not be suitable for long-lived blinded paths.
	pub fn use_compact_introduction_node(&mut self, network_graph: &ReadOnlyNetworkGraph) {
		if let IntroductionNode::NodeId(pubkey) = &self.0.introduction_node {
			let node_id = NodeId::from_pubkey(pubkey);
			if let Some(node_info) = network_graph.node(&node_id) {
				if let Some((scid, channel_info)) = node_info
					.channels
					.iter()
					.filter_map(|scid| network_graph.channel(*scid).map(|info| (*scid, info)))
					.min_by_key(|(scid, _)| scid_utils::block_from_scid(*scid))
				{
					let direction = if node_id == channel_info.node_one {
						Direction::NodeOne
					} else {
						debug_assert_eq!(node_id, channel_info.node_two);
						Direction::NodeTwo
					};
					self.0.introduction_node =
						IntroductionNode::DirectedShortChannelId(direction, scid);
				}
			}
		}
	}

	/// Returns the introduction [`NodeId`] of the blinded path, if it is publicly reachable (i.e.,
	/// it is found in the network graph).
	pub fn public_introduction_node_id<'a>(
		&self, network_graph: &'a ReadOnlyNetworkGraph,
	) -> Option<&'a NodeId> {
		self.0.public_introduction_node_id(network_graph)
	}

	/// The [`IntroductionNode`] of the blinded path.
	pub fn introduction_node(&self) -> &IntroductionNode {
		&self.0.introduction_node
	}

	/// Used by the [`IntroductionNode`] to decrypt its [`encrypted_payload`] to forward the message.
	///
	/// [`encrypted_payload`]: BlindedHop::encrypted_payload
	pub fn blinding_point(&self) -> PublicKey {
		self.0.blinding_point
	}

	/// The [`BlindedHop`]s within the blinded path.
	pub fn blinded_hops(&self) -> &[BlindedHop] {
		&self.0.blinded_hops
	}

	/// Advance the blinded onion message path by one hop, making the second hop into the new
	/// introduction node.
	///
	/// Will only modify `self` when returning `Ok`.
	pub fn advance_path_by_one<NS: Deref, NL: Deref, T>(
		&mut self, node_signer: &NS, node_id_lookup: &NL, secp_ctx: &Secp256k1<T>,
	) -> Result<(), ()>
	where
		NS::Target: NodeSigner,
		NL::Target: NodeIdLookUp,
		T: secp256k1::Signing + secp256k1::Verification,
	{
		let control_tlvs_ss = node_signer.ecdh(Recipient::Node, &self.0.blinding_point, None)?;
		let rho = onion_utils::gen_rho_from_shared_secret(&control_tlvs_ss.secret_bytes());
		let encrypted_control_tlvs = &self.0.blinded_hops.get(0).ok_or(())?.encrypted_payload;
		let mut s = Cursor::new(encrypted_control_tlvs);
		let mut reader = FixedLengthReader::new(&mut s, encrypted_control_tlvs.len() as u64);
		match ChaChaPolyReadAdapter::read(&mut reader, rho) {
			Ok(ChaChaPolyReadAdapter {
				readable: ControlTlvs::Forward(ForwardTlvs { next_hop, next_blinding_override }),
			}) => {
				let next_node_id = match next_hop {
					NextMessageHop::NodeId(pubkey) => pubkey,
					NextMessageHop::ShortChannelId(scid) => match node_id_lookup.next_node_id(scid)
					{
						Some(pubkey) => pubkey,
						None => return Err(()),
					},
				};
				let mut new_blinding_point = match next_blinding_override {
					Some(blinding_point) => blinding_point,
					None => onion_utils::next_hop_pubkey(
						secp_ctx,
						self.0.blinding_point,
						control_tlvs_ss.as_ref(),
					)
					.map_err(|_| ())?,
				};
				mem::swap(&mut self.0.blinding_point, &mut new_blinding_point);
				self.0.introduction_node = IntroductionNode::NodeId(next_node_id);
				self.0.blinded_hops.remove(0);
				Ok(())
			},
			_ => Err(()),
		}
	}

	pub(crate) fn introduction_node_mut(&mut self) -> &mut IntroductionNode {
		&mut self.0.introduction_node
	}

	/// Creates a new [`BlindedMessagePath`] from its constituent parts.
	///
	/// Useful when you need to reconstruct a blinded path from previously serialized components.
	///
	/// Parameters:
	/// * `introduction_node_id`: The public key of the introduction node in the path
	/// * `blinding_point`: The public key used for blinding the path
	/// * `blinded_hops`: The encrypted routing information for each hop in the path
	pub fn from_blinded_path(
		introduction_node_id: PublicKey, blinding_point: PublicKey, blinded_hops: Vec<BlindedHop>,
	) -> Self {
		Self(BlindedPath {
			introduction_node: IntroductionNode::NodeId(introduction_node_id),
			blinding_point,
			blinded_hops,
		})
	}

	#[cfg(test)]
	pub fn clear_blinded_hops(&mut self) {
		self.0.blinded_hops.clear()
	}
}

/// The next hop to forward an onion message along its path.
///
/// Note that payment blinded paths always specify their next hop using an explicit node id.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum NextMessageHop {
	/// The node id of the next hop.
	NodeId(PublicKey),
	/// The short channel id leading to the next hop.
	ShortChannelId(u64),
}

/// An intermediate node, and possibly a short channel id leading to the next node.
///
/// Note:
/// [`MessageForwardNode`] must represent a node that supports [`supports_onion_messages`]
/// in order to be included in valid blinded paths for onion messaging.
///
/// [`supports_onion_messages`]: crate::types::features::Features::supports_onion_messages
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct MessageForwardNode {
	/// This node's pubkey.
	pub node_id: PublicKey,
	/// The channel between `node_id` and the next hop. If set, the constructed [`BlindedHop`]'s
	/// `encrypted_payload` will use this instead of the next [`MessageForwardNode::node_id`] for a
	/// more compact representation.
	pub short_channel_id: Option<u64>,
}

/// TLVs to encode in an intermediate onion message packet's hop data. When provided in a blinded
/// route, they are encoded into [`BlindedHop::encrypted_payload`].
pub(crate) struct ForwardTlvs {
	/// The next hop in the onion message's path.
	pub(crate) next_hop: NextMessageHop,
	/// Senders to a blinded path use this value to concatenate the route they find to the
	/// introduction node with the blinded path.
	pub(crate) next_blinding_override: Option<PublicKey>,
}

/// Similar to [`ForwardTlvs`], but these TLVs are for the final node.
pub(crate) struct ReceiveTlvs {
	/// If `context` is `Some`, it is used to identify the blinded path that this onion message is
	/// sending to. This is useful for receivers to check that said blinded path is being used in
	/// the right context.
	pub context: Option<MessageContext>,
}

impl Writeable for ForwardTlvs {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		let (next_node_id, short_channel_id) = match self.next_hop {
			NextMessageHop::NodeId(pubkey) => (Some(pubkey), None),
			NextMessageHop::ShortChannelId(scid) => (None, Some(scid)),
		};
		encode_tlv_stream!(writer, {
			(2, short_channel_id, option),
			(4, next_node_id, option),
			(8, self.next_blinding_override, option)
		});
		Ok(())
	}
}

impl Writeable for ReceiveTlvs {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		encode_tlv_stream!(writer, {
			(65537, self.context, option),
		});
		Ok(())
	}
}

/// Additional data included by the recipient in a [`BlindedMessagePath`].
///
/// This data is encrypted by the recipient and will be given to the corresponding message handler
/// when handling a message sent over the [`BlindedMessagePath`]. The recipient can use this data to
/// authenticate the message or for further processing if needed.
#[derive(Clone, Debug)]
pub enum MessageContext {
	/// Context specific to an [`OffersMessage`].
	///
	/// [`OffersMessage`]: crate::onion_message::offers::OffersMessage
	Offers(OffersContext),
	/// Context specific to an [`AsyncPaymentsMessage`].
	///
	/// [`AsyncPaymentsMessage`]: crate::onion_message::async_payments::AsyncPaymentsMessage
	AsyncPayments(AsyncPaymentsContext),
	/// Represents a context for a blinded path used in a reply path when requesting a DNSSEC proof
	/// in a [`DNSResolverMessage`].
	///
	/// [`DNSResolverMessage`]: crate::onion_message::dns_resolution::DNSResolverMessage
	DNSResolver(DNSResolverContext),
	/// Context specific to a [`CustomOnionMessageHandler::CustomMessage`].
	///
	/// [`CustomOnionMessageHandler::CustomMessage`]: crate::onion_message::messenger::CustomOnionMessageHandler::CustomMessage
	Custom(Vec<u8>),
}

/// Contains data specific to an [`OffersMessage`].
///
/// [`OffersMessage`]: crate::onion_message::offers::OffersMessage
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OffersContext {
	/// Context used by a [`BlindedMessagePath`] within an [`Offer`].
	///
	/// This variant is intended to be received when handling an [`InvoiceRequest`].
	///
	/// [`Offer`]: crate::offers::offer::Offer
	/// [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
	InvoiceRequest {
		/// A nonce used for authenticating that an [`InvoiceRequest`] is for a valid [`Offer`] and
		/// for deriving the offer's signing keys.
		///
		/// [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
		/// [`Offer`]: crate::offers::offer::Offer
		nonce: Nonce,
	},
	/// Context used by a [`BlindedMessagePath`] within the [`Offer`] of an async recipient.
	///
	/// This variant is received by the static invoice server when handling an [`InvoiceRequest`] on
	/// behalf of said async recipient.
	///
	/// [`Offer`]: crate::offers::offer::Offer
	/// [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
	StaticInvoiceRequested {
		/// An identifier for the async recipient for whom we as a static invoice server are serving
		/// [`StaticInvoice`]s. Used paired with the
		/// [`OffersContext::StaticInvoiceRequested::invoice_slot`] when looking up a corresponding
		/// [`StaticInvoice`] to return to the payer if the recipient is offline. This id was previously
		/// provided via [`AsyncPaymentsContext::ServeStaticInvoice::recipient_id`].
		///
		/// Also useful for rate limiting the number of [`InvoiceRequest`]s we will respond to on
		/// recipient's behalf.
		///
		/// [`StaticInvoice`]: crate::offers::static_invoice::StaticInvoice
		/// [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
		recipient_id: Vec<u8>,

		/// The slot number for a specific [`StaticInvoice`] that the recipient previously
		/// requested be served on their behalf. Useful when paired with the
		/// [`OffersContext::StaticInvoiceRequested::recipient_id`] to pull that specific invoice from
		/// the database when payers send an [`InvoiceRequest`]. This id was previously
		/// provided via [`AsyncPaymentsContext::ServeStaticInvoice::invoice_slot`].
		///
		/// [`StaticInvoice`]: crate::offers::static_invoice::StaticInvoice
		/// [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
		invoice_slot: u16,

		/// The time as duration since the Unix epoch at which this path expires and messages sent over
		/// it should be ignored.
		///
		/// Useful to timeout async recipients that are no longer supported as clients.
		path_absolute_expiry: Duration,
	},
	/// Context used by a [`BlindedMessagePath`] within a [`Refund`] or as a reply path for an
	/// [`InvoiceRequest`].
	///
	/// This variant is intended to be received when handling a [`Bolt12Invoice`] or an
	/// [`InvoiceError`].
	///
	/// [`Refund`]: crate::offers::refund::Refund
	/// [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
	/// [`Bolt12Invoice`]: crate::offers::invoice::Bolt12Invoice
	/// [`InvoiceError`]: crate::offers::invoice_error::InvoiceError
	OutboundPayment {
		/// Payment ID used when creating a [`Refund`] or [`InvoiceRequest`].
		///
		/// [`Refund`]: crate::offers::refund::Refund
		/// [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
		payment_id: PaymentId,

		/// A nonce used for authenticating that a [`Bolt12Invoice`] is for a valid [`Refund`] or
		/// [`InvoiceRequest`] and for deriving their signing keys.
		///
		/// [`Bolt12Invoice`]: crate::offers::invoice::Bolt12Invoice
		/// [`Refund`]: crate::offers::refund::Refund
		/// [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
		nonce: Nonce,
	},
	/// Context used by a [`BlindedMessagePath`] as a reply path for a [`Bolt12Invoice`].
	///
	/// This variant is intended to be received when handling an [`InvoiceError`].
	///
	/// [`Bolt12Invoice`]: crate::offers::invoice::Bolt12Invoice
	/// [`InvoiceError`]: crate::offers::invoice_error::InvoiceError
	InboundPayment {
		/// The same payment hash as [`Bolt12Invoice::payment_hash`].
		///
		/// [`Bolt12Invoice::payment_hash`]: crate::offers::invoice::Bolt12Invoice::payment_hash
		payment_hash: PaymentHash,
	},
}

/// Contains data specific to an [`AsyncPaymentsMessage`].
///
/// [`AsyncPaymentsMessage`]: crate::onion_message::async_payments::AsyncPaymentsMessage
#[derive(Clone, Debug)]
pub enum AsyncPaymentsContext {
	/// Context used by a [`BlindedMessagePath`] provided out-of-band to an async recipient, where the
	/// context is provided back to the static invoice server in corresponding [`OfferPathsRequest`]s.
	///
	/// [`OfferPathsRequest`]: crate::onion_message::async_payments::OfferPathsRequest
	OfferPathsRequest {
		/// An identifier for the async recipient that is requesting blinded paths to include in their
		/// [`Offer::paths`]. This ID will be surfaced when the async recipient eventually sends a
		/// corresponding [`ServeStaticInvoice`] message, and can be used to rate limit the recipient.
		///
		/// [`Offer::paths`]: crate::offers::offer::Offer::paths
		/// [`ServeStaticInvoice`]: crate::onion_message::async_payments::ServeStaticInvoice
		recipient_id: Vec<u8>,
		/// An optional field indicating the time as duration since the Unix epoch at which this path
		/// expires and messages sent over it should be ignored.
		///
		/// Useful to timeout async recipients that are no longer supported as clients.
		path_absolute_expiry: Option<core::time::Duration>,
	},
	/// Context used by a reply path to an [`OfferPathsRequest`], provided back to us as an async
	/// recipient in corresponding [`OfferPaths`] messages from the static invoice server.
	///
	/// [`OfferPathsRequest`]: crate::onion_message::async_payments::OfferPathsRequest
	/// [`OfferPaths`]: crate::onion_message::async_payments::OfferPaths
	OfferPaths {
		/// The "slot" in the static invoice server's database that the invoice corresponding to these
		/// offer paths should go into, originally set by us in [`OfferPathsRequest::invoice_slot`]. This
		/// value allows us as the recipient to replace a specific invoice that is stored by the server,
		/// which is useful for limiting the number of invoices stored by the server while also keeping
		/// all the invoices persisted with the server fresh.
		///
		/// [`OfferPathsRequest::invoice_slot`]: crate::onion_message::async_payments::OfferPathsRequest::invoice_slot
		invoice_slot: u16,
		/// The time as duration since the Unix epoch at which this path expires and messages sent over
		/// it should be ignored.
		///
		/// This avoids the situation where the [`OfferPaths`] message is very delayed and thus
		/// outdated.
		///
		/// [`OfferPaths`]: crate::onion_message::async_payments::OfferPaths
		path_absolute_expiry: core::time::Duration,
	},
	/// Context used by a reply path to an [`OfferPaths`] message, provided back to us as the static
	/// invoice server in corresponding [`ServeStaticInvoice`] messages.
	///
	/// [`OfferPaths`]: crate::onion_message::async_payments::OfferPaths
	/// [`ServeStaticInvoice`]: crate::onion_message::async_payments::ServeStaticInvoice
	ServeStaticInvoice {
		/// An identifier for the async recipient that is requesting that a [`StaticInvoice`] be served
		/// on their behalf.
		///
		/// Useful when surfaced alongside the below `invoice_id` when payers send an
		/// [`InvoiceRequest`], to pull the specific static invoice from the database.
		///
		/// Also useful to rate limit the invoices being persisted on behalf of a particular recipient.
		///
		/// This id will be provided back to us as the static invoice server via
		/// [`OffersContext::StaticInvoiceRequested::recipient_id`].
		///
		/// [`StaticInvoice`]: crate::offers::static_invoice::StaticInvoice
		/// [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
		recipient_id: Vec<u8>,
		/// A random identifier for the specific [`StaticInvoice`] that the recipient is requesting be
		/// served on their behalf. Useful when surfaced alongside the above `recipient_id` when payers
		/// send an [`InvoiceRequest`], to pull the specific static invoice from the database.
		///
		/// [`StaticInvoice`]: crate::offers::static_invoice::StaticInvoice
		/// [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
		invoice_id: u128,
		/// The slot number for the specific [`StaticInvoice`] that the recipient is requesting be
		/// served on their behalf. Useful when surfaced alongside the above `recipient_id` when payers
		/// send an [`InvoiceRequest`], to pull the specific static invoice from the database. This id
		/// will be provided back to us as the static invoice server via
		/// [`OffersContext::StaticInvoiceRequested::invoice_slot`].
		///
		/// [`StaticInvoice`]: crate::offers::static_invoice::StaticInvoice
		/// [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
		invoice_slot: u16,
		/// The time as duration since the Unix epoch at which this path expires and messages sent over
		/// it should be ignored.
		///
		/// Useful to timeout async recipients that are no longer supported as clients.
		path_absolute_expiry: core::time::Duration,
	},
	/// Context used by a reply path to a [`ServeStaticInvoice`] message, provided back to us in
	/// corresponding [`StaticInvoicePersisted`] messages.
	///
	/// [`ServeStaticInvoice`]: crate::onion_message::async_payments::ServeStaticInvoice
	/// [`StaticInvoicePersisted`]: crate::onion_message::async_payments::StaticInvoicePersisted
	StaticInvoicePersisted {
		/// The id of the offer in the cache corresponding to the [`StaticInvoice`] that has been
		/// persisted. This invoice is now ready to be provided by the static invoice server in response
		/// to [`InvoiceRequest`]s, so the corresponding offer can be marked as ready to receive
		/// payments.
		///
		/// [`StaticInvoice`]: crate::offers::static_invoice::StaticInvoice
		/// [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
		offer_id: OfferId,
		/// The time as duration since the Unix epoch at which the invoice corresponding to this path
		/// was created. Useful to know when an invoice needs replacement.
		invoice_created_at: core::time::Duration,
	},
	/// Context contained within the reply [`BlindedMessagePath`] we put in outbound
	/// [`HeldHtlcAvailable`] messages, provided back to us in corresponding [`ReleaseHeldHtlc`]
	/// messages.
	///
	/// [`HeldHtlcAvailable`]: crate::onion_message::async_payments::HeldHtlcAvailable
	/// [`ReleaseHeldHtlc`]: crate::onion_message::async_payments::ReleaseHeldHtlc
	OutboundPayment {
		/// ID used when payment to the originating [`Offer`] was initiated. Useful for us to identify
		/// which of our pending outbound payments should be released to its often-offline payee.
		///
		/// [`Offer`]: crate::offers::offer::Offer
		payment_id: PaymentId,
	},
	/// Context contained within the [`BlindedMessagePath`]s we put in static invoices, provided back
	/// to us in corresponding [`HeldHtlcAvailable`] messages.
	///
	/// [`HeldHtlcAvailable`]: crate::onion_message::async_payments::HeldHtlcAvailable
	InboundPayment {
		/// The time as duration since the Unix epoch at which this path expires and messages sent over
		/// it should be ignored. Without this, anyone with the path corresponding to this context is
		/// able to trivially ask if we're online forever.
		path_absolute_expiry: core::time::Duration,
	},
}

impl_writeable_tlv_based_enum!(MessageContext,
	{0, Offers} => (),
	{1, Custom} => (),
	{2, AsyncPayments} => (),
	{3, DNSResolver} => (),
);

// Note: Several TLV fields (`nonce`, `hmac`, etc.) were removed in LDK v0.2 following the
// introduction of `ReceiveAuthKey`-based authentication for inbound `BlindedMessagePath`s. Because
// we do not support receiving to those contexts anymore (they will fail the `ReceiveAuthKey`-based
// authentication checks), we can reuse those fields here.
impl_writeable_tlv_based_enum!(OffersContext,
	(0, InvoiceRequest) => {
		(0, nonce, required),
	},
	(1, OutboundPayment) => {
		(0, payment_id, required),
		(1, nonce, required),
	},
	(2, InboundPayment) => {
		(0, payment_hash, required),
	},
	(3, StaticInvoiceRequested) => {
		(0, recipient_id, required),
		(2, invoice_slot, required),
		(4, path_absolute_expiry, required),
	},
);

impl_writeable_tlv_based_enum!(AsyncPaymentsContext,
	(0, OutboundPayment) => {
		(0, payment_id, required),
	},
	(1, InboundPayment) => {
		(4, path_absolute_expiry, required),
	},
	(2, OfferPaths) => {
		(0, path_absolute_expiry, required),
		(2, invoice_slot, required),
	},
	(3, StaticInvoicePersisted) => {
		(0, offer_id, required),
		(2, invoice_created_at, required),
	},
	(4, OfferPathsRequest) => {
		(0, recipient_id, required),
		(2, path_absolute_expiry, option),
	},
	(5, ServeStaticInvoice) => {
		(0, recipient_id, required),
		(2, invoice_id, required),
		(4, path_absolute_expiry, required),
		(6, invoice_slot, required),
	},
);

/// Contains a simple nonce for use in a blinded path's context.
///
/// Such a context is required when receiving a [`DNSSECProof`] message.
///
/// [`DNSSECProof`]: crate::onion_message::dns_resolution::DNSSECProof
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct DNSResolverContext {
	/// A nonce which uniquely describes a DNS resolution, useful for looking up metadata about the
	/// request.
	pub nonce: [u8; 16],
}

impl_writeable_tlv_based!(DNSResolverContext, {
	(0, nonce, required),
});

/// Represents the padding round off size (in bytes) that is used
/// to pad message blinded path's [`BlindedHop`]
pub(crate) const MESSAGE_PADDING_ROUND_OFF: usize = 100;

/// Construct blinded onion message hops for the given `intermediate_nodes` and `recipient_node_id`.
pub(super) fn blinded_hops<T: secp256k1::Signing + secp256k1::Verification>(
	secp_ctx: &Secp256k1<T>, intermediate_nodes: &[MessageForwardNode],
	recipient_node_id: PublicKey, context: MessageContext, session_priv: &SecretKey,
	local_node_receive_key: ReceiveAuthKey,
) -> Result<Vec<BlindedHop>, secp256k1::Error> {
	let pks = intermediate_nodes
		.iter()
		.map(|node| (node.node_id, None))
		.chain(core::iter::once((recipient_node_id, Some(local_node_receive_key))));
	let is_compact = intermediate_nodes.iter().any(|node| node.short_channel_id.is_some());

	let tlvs = pks
		.clone()
		.skip(1) // The first node's TLVs contains the next node's pubkey
		.zip(intermediate_nodes.iter().map(|node| node.short_channel_id))
		.map(|((pubkey, _), scid)| match scid {
			Some(scid) => NextMessageHop::ShortChannelId(scid),
			None => NextMessageHop::NodeId(pubkey),
		})
		.map(|next_hop| {
			ControlTlvs::Forward(ForwardTlvs { next_hop, next_blinding_override: None })
		})
		.chain(core::iter::once(ControlTlvs::Receive(ReceiveTlvs { context: Some(context) })));

	if is_compact {
		let path = pks.zip(tlvs);
		utils::construct_blinded_hops(secp_ctx, path, session_priv)
	} else {
		let path =
			pks.zip(tlvs.map(|tlv| BlindedPathWithPadding {
				tlvs: tlv,
				round_off: MESSAGE_PADDING_ROUND_OFF,
			}));
		utils::construct_blinded_hops(secp_ctx, path, session_priv)
	}
}
