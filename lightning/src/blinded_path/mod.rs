// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Creating blinded paths and related utilities live here.

pub mod message;
pub mod payment;
pub(crate) mod utils;

use bitcoin::secp256k1::PublicKey;
use core::ops::Deref;

use crate::ln::msgs::DecodeError;
use crate::routing::gossip::{NodeId, ReadOnlyNetworkGraph};
use crate::util::ser::{Readable, Writeable, Writer};

use crate::io;
use crate::prelude::*;

/// Onion messages and payments can be sent and received to blinded paths, which serve to hide the
/// identity of the recipient.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub(crate) struct BlindedPath {
	/// To send to a blinded path, the sender first finds a route to the unblinded
	/// `introduction_node`, which can unblind its [`encrypted_payload`] to find out the onion
	/// message or payment's next hop and forward it along.
	///
	/// [`encrypted_payload`]: BlindedHop::encrypted_payload
	pub introduction_node: IntroductionNode,
	/// Used by the introduction node to decrypt its [`encrypted_payload`] to forward the onion
	/// message or payment.
	///
	/// [`encrypted_payload`]: BlindedHop::encrypted_payload
	pub blinding_point: PublicKey,
	/// The hops composing the blinded path.
	pub blinded_hops: Vec<BlindedHop>,
}

/// The unblinded node in a blinded path.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum IntroductionNode {
	/// The node id of the introduction node.
	NodeId(PublicKey),
	/// The short channel id of the channel leading to the introduction node. The [`Direction`]
	/// identifies which side of the channel is the introduction node.
	DirectedShortChannelId(Direction, u64),
}

/// The side of a channel that is the [`IntroductionNode`] in a blinded path. [BOLT 7] defines which
/// nodes is which in the [`ChannelAnnouncement`] message.
///
/// [BOLT 7]: https://github.com/lightning/bolts/blob/master/07-routing-gossip.md#the-channel_announcement-message
/// [`ChannelAnnouncement`]: crate::ln::msgs::ChannelAnnouncement
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub enum Direction {
	/// The lesser node id when compared lexicographically in ascending order.
	NodeOne,
	/// The greater node id when compared lexicographically in ascending order.
	NodeTwo,
}

/// An interface for looking up the node id of a channel counterparty for the purpose of forwarding
/// an [`OnionMessage`].
///
/// [`OnionMessage`]: crate::ln::msgs::OnionMessage
pub trait NodeIdLookUp {
	/// Returns the node id of the forwarding node's channel counterparty with `short_channel_id`.
	///
	/// Here, the forwarding node is referring to the node of the [`OnionMessenger`] parameterized
	/// by the [`NodeIdLookUp`] and the counterparty to one of that node's peers.
	///
	/// [`OnionMessenger`]: crate::onion_message::messenger::OnionMessenger
	fn next_node_id(&self, short_channel_id: u64) -> Option<PublicKey>;
}

/// A [`NodeIdLookUp`] that always returns `None`.
pub struct EmptyNodeIdLookUp {}

impl NodeIdLookUp for EmptyNodeIdLookUp {
	fn next_node_id(&self, _short_channel_id: u64) -> Option<PublicKey> {
		None
	}
}

impl Deref for EmptyNodeIdLookUp {
	type Target = EmptyNodeIdLookUp;
	fn deref(&self) -> &Self {
		self
	}
}

/// An encrypted payload and node id corresponding to a hop in a payment or onion message path, to
/// be encoded in the sender's onion packet. These hops cannot be identified by outside observers
/// and thus can be used to hide the identity of the recipient.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct BlindedHop {
	/// The blinded node id of this hop in a blinded path.
	pub blinded_node_id: PublicKey,
	/// The encrypted payload intended for this hop in a blinded path.
	// The node sending to this blinded path will later encode this payload into the onion packet for
	// this hop.
	pub encrypted_payload: Vec<u8>,
}

impl BlindedPath {
	pub(super) fn public_introduction_node_id<'a>(
		&self, network_graph: &'a ReadOnlyNetworkGraph,
	) -> Option<&'a NodeId> {
		match &self.introduction_node {
			IntroductionNode::NodeId(pubkey) => {
				let node_id = NodeId::from_pubkey(pubkey);
				network_graph.nodes().get_key_value(&node_id).map(|(key, _)| key)
			},
			IntroductionNode::DirectedShortChannelId(direction, scid) => {
				network_graph.channel(*scid).map(|c| match direction {
					Direction::NodeOne => &c.node_one,
					Direction::NodeTwo => &c.node_two,
				})
			},
		}
	}
}

impl Writeable for BlindedPath {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		match &self.introduction_node {
			IntroductionNode::NodeId(pubkey) => pubkey.write(w)?,
			IntroductionNode::DirectedShortChannelId(direction, scid) => {
				match direction {
					Direction::NodeOne => 0u8.write(w)?,
					Direction::NodeTwo => 1u8.write(w)?,
				}
				scid.write(w)?;
			},
		}

		self.blinding_point.write(w)?;
		(self.blinded_hops.len() as u8).write(w)?;
		for hop in &self.blinded_hops {
			hop.write(w)?;
		}
		Ok(())
	}
}

impl Readable for BlindedPath {
	fn read<R: io::Read>(r: &mut R) -> Result<Self, DecodeError> {
		let first_byte: u8 = Readable::read(r)?;
		let introduction_node = match first_byte {
			0 => IntroductionNode::DirectedShortChannelId(Direction::NodeOne, Readable::read(r)?),
			1 => IntroductionNode::DirectedShortChannelId(Direction::NodeTwo, Readable::read(r)?),
			2 | 3 => {
				let mut bytes = [0; 33];
				bytes[0] = first_byte;
				r.read_exact(&mut bytes[1..])?;
				IntroductionNode::NodeId(Readable::read(&mut &bytes[..])?)
			},
			_ => return Err(DecodeError::InvalidValue),
		};
		let blinding_point = Readable::read(r)?;
		let num_hops: u8 = Readable::read(r)?;
		if num_hops == 0 {
			return Err(DecodeError::InvalidValue);
		}
		let mut blinded_hops: Vec<BlindedHop> = Vec::with_capacity(num_hops.into());
		for _ in 0..num_hops {
			blinded_hops.push(Readable::read(r)?);
		}
		Ok(BlindedPath { introduction_node, blinding_point, blinded_hops })
	}
}

impl_writeable!(BlindedHop, {
	blinded_node_id,
	encrypted_payload
});

impl Direction {
	/// Returns the [`NodeId`] from the inputs corresponding to the direction.
	pub fn select_node_id(&self, node_a: NodeId, node_b: NodeId) -> NodeId {
		match self {
			Direction::NodeOne => core::cmp::min(node_a, node_b),
			Direction::NodeTwo => core::cmp::max(node_a, node_b),
		}
	}

	/// Returns the [`PublicKey`] from the inputs corresponding to the direction.
	pub fn select_pubkey<'a>(&self, node_a: &'a PublicKey, node_b: &'a PublicKey) -> &'a PublicKey {
		let (node_one, node_two) = if NodeId::from_pubkey(node_a) < NodeId::from_pubkey(node_b) {
			(node_a, node_b)
		} else {
			(node_b, node_a)
		};
		match self {
			Direction::NodeOne => node_one,
			Direction::NodeTwo => node_two,
		}
	}
}
