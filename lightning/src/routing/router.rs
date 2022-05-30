// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! The top-level routing/network map tracking logic lives here.
//!
//! You probably want to create a NetGraphMsgHandler and use that as your RoutingMessageHandler and then
//! interrogate it to get routes for your own payments.

use bitcoin::secp256k1::PublicKey;

use ln::channelmanager::ChannelDetails;
use ln::features::{ChannelFeatures, InvoiceFeatures, NodeFeatures};
use ln::msgs::{DecodeError, ErrorAction, LightningError, MAX_VALUE_MSAT};
use routing::scoring::{ChannelUsage, Score};
use routing::network_graph::{DirectedChannelInfoWithUpdate, EffectiveCapacity, NetworkGraph, ReadOnlyNetworkGraph, NodeId, RoutingFees};
use util::ser::{Writeable, Readable, Writer};
use util::logger::{Level, Logger};
use util::chacha20::ChaCha20;

use io;
use prelude::*;
use alloc::collections::BinaryHeap;
use core::cmp;
use core::ops::Deref;

/// A hop in a route
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct RouteHop {
	/// The node_id of the node at this hop.
	pub pubkey: PublicKey,
	/// The node_announcement features of the node at this hop. For the last hop, these may be
	/// amended to match the features present in the invoice this node generated.
	pub node_features: NodeFeatures,
	/// The channel that should be used from the previous hop to reach this node.
	pub short_channel_id: u64,
	/// The channel_announcement features of the channel that should be used from the previous hop
	/// to reach this node.
	pub channel_features: ChannelFeatures,
	/// The fee taken on this hop (for paying for the use of the *next* channel in the path).
	/// For the last hop, this should be the full value of the payment (might be more than
	/// requested if we had to match htlc_minimum_msat).
	pub fee_msat: u64,
	/// The CLTV delta added for this hop. For the last hop, this should be the full CLTV value
	/// expected at the destination, in excess of the current block height.
	pub cltv_expiry_delta: u32,
}

impl_writeable_tlv_based!(RouteHop, {
	(0, pubkey, required),
	(2, node_features, required),
	(4, short_channel_id, required),
	(6, channel_features, required),
	(8, fee_msat, required),
	(10, cltv_expiry_delta, required),
});

/// A route directs a payment from the sender (us) to the recipient. If the recipient supports MPP,
/// it can take multiple paths. Each path is composed of one or more hops through the network.
#[derive(Clone, Hash, PartialEq, Eq)]
pub struct Route {
	/// The list of routes taken for a single (potentially-)multi-part payment. The pubkey of the
	/// last RouteHop in each path must be the same. Each entry represents a list of hops, NOT
	/// INCLUDING our own, where the last hop is the destination. Thus, this must always be at
	/// least length one. While the maximum length of any given path is variable, keeping the length
	/// of any path less or equal to 19 should currently ensure it is viable.
	pub paths: Vec<Vec<RouteHop>>,
	/// The `payment_params` parameter passed to [`find_route`].
	/// This is used by `ChannelManager` to track information which may be required for retries,
	/// provided back to you via [`Event::PaymentPathFailed`].
	///
	/// [`Event::PaymentPathFailed`]: crate::util::events::Event::PaymentPathFailed
	pub payment_params: Option<PaymentParameters>,
}

pub(crate) trait RoutePath {
	/// Gets the fees for a given path, excluding any excess paid to the recipient.
	fn get_path_fees(&self) -> u64;
}
impl RoutePath for Vec<RouteHop> {
	fn get_path_fees(&self) -> u64 {
		// Do not count last hop of each path since that's the full value of the payment
		self.split_last().map(|(_, path_prefix)| path_prefix).unwrap_or(&[])
			.iter().map(|hop| &hop.fee_msat)
			.sum()
	}
}

impl Route {
	/// Returns the total amount of fees paid on this [`Route`].
	///
	/// This doesn't include any extra payment made to the recipient, which can happen in excess of
	/// the amount passed to [`find_route`]'s `params.final_value_msat`.
	pub fn get_total_fees(&self) -> u64 {
		self.paths.iter().map(|path| path.get_path_fees()).sum()
	}

	/// Returns the total amount paid on this [`Route`], excluding the fees.
	pub fn get_total_amount(&self) -> u64 {
		return self.paths.iter()
			.map(|path| path.split_last().map(|(hop, _)| hop.fee_msat).unwrap_or(0))
			.sum();
	}
}

const SERIALIZATION_VERSION: u8 = 1;
const MIN_SERIALIZATION_VERSION: u8 = 1;

impl Writeable for Route {
	fn write<W: ::util::ser::Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		write_ver_prefix!(writer, SERIALIZATION_VERSION, MIN_SERIALIZATION_VERSION);
		(self.paths.len() as u64).write(writer)?;
		for hops in self.paths.iter() {
			(hops.len() as u8).write(writer)?;
			for hop in hops.iter() {
				hop.write(writer)?;
			}
		}
		write_tlv_fields!(writer, {
			(1, self.payment_params, option),
		});
		Ok(())
	}
}

impl Readable for Route {
	fn read<R: io::Read>(reader: &mut R) -> Result<Route, DecodeError> {
		let _ver = read_ver_prefix!(reader, SERIALIZATION_VERSION);
		let path_count: u64 = Readable::read(reader)?;
		let mut paths = Vec::with_capacity(cmp::min(path_count, 128) as usize);
		for _ in 0..path_count {
			let hop_count: u8 = Readable::read(reader)?;
			let mut hops = Vec::with_capacity(hop_count as usize);
			for _ in 0..hop_count {
				hops.push(Readable::read(reader)?);
			}
			paths.push(hops);
		}
		let mut payment_params = None;
		read_tlv_fields!(reader, {
			(1, payment_params, option),
		});
		Ok(Route { paths, payment_params })
	}
}

/// Parameters needed to find a [`Route`].
///
/// Passed to [`find_route`] and [`build_route_from_hops`], but also provided in
/// [`Event::PaymentPathFailed`] for retrying a failed payment path.
///
/// [`Event::PaymentPathFailed`]: crate::util::events::Event::PaymentPathFailed
#[derive(Clone, Debug)]
pub struct RouteParameters {
	/// The parameters of the failed payment path.
	pub payment_params: PaymentParameters,

	/// The amount in msats sent on the failed payment path.
	pub final_value_msat: u64,

	/// The CLTV on the final hop of the failed payment path.
	pub final_cltv_expiry_delta: u32,
}

impl_writeable_tlv_based!(RouteParameters, {
	(0, payment_params, required),
	(2, final_value_msat, required),
	(4, final_cltv_expiry_delta, required),
});

/// Maximum total CTLV difference we allow for a full payment path.
pub const DEFAULT_MAX_TOTAL_CLTV_EXPIRY_DELTA: u32 = 1008;

// The median hop CLTV expiry delta currently seen in the network.
const MEDIAN_HOP_CLTV_EXPIRY_DELTA: u32 = 40;

// During routing, we only consider paths shorter than our maximum length estimate.
// In the legacy onion format, the maximum number of hops used to be a fixed value of 20.
// However, in the TLV onion format, there is no fixed maximum length, but the `hop_payloads`
// field is always 1300 bytes. As the `tlv_payload` for each hop may vary in length, we have to
// estimate how many hops the route may have so that it actually fits the `hop_payloads` field.
//
// We estimate 3+32 (payload length and HMAC) + 2+8 (amt_to_forward) + 2+4 (outgoing_cltv_value) +
// 2+8 (short_channel_id) = 61 bytes for each intermediate hop and 3+32
// (payload length and HMAC) + 2+8 (amt_to_forward) + 2+4 (outgoing_cltv_value) + 2+32+8
// (payment_secret and total_msat) = 93 bytes for the final hop.
// Since the length of the potentially included `payment_metadata` is unknown to us, we round
// down from (1300-93) / 61 = 19.78... to arrive at a conservative estimate of 19.
const MAX_PATH_LENGTH_ESTIMATE: u8 = 19;

/// The recipient of a payment.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct PaymentParameters {
	/// The node id of the payee.
	pub payee_pubkey: PublicKey,

	/// Features supported by the payee.
	///
	/// May be set from the payee's invoice or via [`for_keysend`]. May be `None` if the invoice
	/// does not contain any features.
	///
	/// [`for_keysend`]: Self::for_keysend
	pub features: Option<InvoiceFeatures>,

	/// Hints for routing to the payee, containing channels connecting the payee to public nodes.
	pub route_hints: Vec<RouteHint>,

	/// Expiration of a payment to the payee, in seconds relative to the UNIX epoch.
	pub expiry_time: Option<u64>,

	/// The maximum total CLTV delta we accept for the route.
	pub max_total_cltv_expiry_delta: u32,
}

impl_writeable_tlv_based!(PaymentParameters, {
	(0, payee_pubkey, required),
	(1, max_total_cltv_expiry_delta, (default_value, DEFAULT_MAX_TOTAL_CLTV_EXPIRY_DELTA)),
	(2, features, option),
	(4, route_hints, vec_type),
	(6, expiry_time, option),
});

impl PaymentParameters {
	/// Creates a payee with the node id of the given `pubkey`.
	pub fn from_node_id(payee_pubkey: PublicKey) -> Self {
		Self {
			payee_pubkey,
			features: None,
			route_hints: vec![],
			expiry_time: None,
			max_total_cltv_expiry_delta: DEFAULT_MAX_TOTAL_CLTV_EXPIRY_DELTA,
		}
	}

	/// Creates a payee with the node id of the given `pubkey` to use for keysend payments.
	pub fn for_keysend(payee_pubkey: PublicKey) -> Self {
		Self::from_node_id(payee_pubkey).with_features(InvoiceFeatures::for_keysend())
	}

	/// Includes the payee's features.
	///
	/// (C-not exported) since bindings don't support move semantics
	pub fn with_features(self, features: InvoiceFeatures) -> Self {
		Self { features: Some(features), ..self }
	}

	/// Includes hints for routing to the payee.
	///
	/// (C-not exported) since bindings don't support move semantics
	pub fn with_route_hints(self, route_hints: Vec<RouteHint>) -> Self {
		Self { route_hints, ..self }
	}

	/// Includes a payment expiration in seconds relative to the UNIX epoch.
	///
	/// (C-not exported) since bindings don't support move semantics
	pub fn with_expiry_time(self, expiry_time: u64) -> Self {
		Self { expiry_time: Some(expiry_time), ..self }
	}

	/// Includes a limit for the total CLTV expiry delta which is considered during routing
	///
	/// (C-not exported) since bindings don't support move semantics
	pub fn with_max_total_cltv_expiry_delta(self, max_total_cltv_expiry_delta: u32) -> Self {
		Self { max_total_cltv_expiry_delta, ..self }
	}
}

/// A list of hops along a payment path terminating with a channel to the recipient.
#[derive(Clone, Debug, Hash, Eq, PartialEq)]
pub struct RouteHint(pub Vec<RouteHintHop>);

impl Writeable for RouteHint {
	fn write<W: ::util::ser::Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		(self.0.len() as u64).write(writer)?;
		for hop in self.0.iter() {
			hop.write(writer)?;
		}
		Ok(())
	}
}

impl Readable for RouteHint {
	fn read<R: io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
		let hop_count: u64 = Readable::read(reader)?;
		let mut hops = Vec::with_capacity(cmp::min(hop_count, 16) as usize);
		for _ in 0..hop_count {
			hops.push(Readable::read(reader)?);
		}
		Ok(Self(hops))
	}
}

/// A channel descriptor for a hop along a payment path.
#[derive(Clone, Debug, Hash, Eq, PartialEq)]
pub struct RouteHintHop {
	/// The node_id of the non-target end of the route
	pub src_node_id: PublicKey,
	/// The short_channel_id of this channel
	pub short_channel_id: u64,
	/// The fees which must be paid to use this channel
	pub fees: RoutingFees,
	/// The difference in CLTV values between this node and the next node.
	pub cltv_expiry_delta: u16,
	/// The minimum value, in msat, which must be relayed to the next hop.
	pub htlc_minimum_msat: Option<u64>,
	/// The maximum value in msat available for routing with a single HTLC.
	pub htlc_maximum_msat: Option<u64>,
}

impl_writeable_tlv_based!(RouteHintHop, {
	(0, src_node_id, required),
	(1, htlc_minimum_msat, option),
	(2, short_channel_id, required),
	(3, htlc_maximum_msat, option),
	(4, fees, required),
	(6, cltv_expiry_delta, required),
});

#[derive(Eq, PartialEq)]
struct RouteGraphNode {
	node_id: NodeId,
	lowest_fee_to_peer_through_node: u64,
	lowest_fee_to_node: u64,
	total_cltv_delta: u32,
	// The maximum value a yet-to-be-constructed payment path might flow through this node.
	// This value is upper-bounded by us by:
	// - how much is needed for a path being constructed
	// - how much value can channels following this node (up to the destination) can contribute,
	//   considering their capacity and fees
	value_contribution_msat: u64,
	/// The effective htlc_minimum_msat at this hop. If a later hop on the path had a higher HTLC
	/// minimum, we use it, plus the fees required at each earlier hop to meet it.
	path_htlc_minimum_msat: u64,
	/// All penalties incurred from this hop on the way to the destination, as calculated using
	/// channel scoring.
	path_penalty_msat: u64,
	/// The number of hops walked up to this node.
	path_length_to_node: u8,
}

impl cmp::Ord for RouteGraphNode {
	fn cmp(&self, other: &RouteGraphNode) -> cmp::Ordering {
		let other_score = cmp::max(other.lowest_fee_to_peer_through_node, other.path_htlc_minimum_msat)
			.saturating_add(other.path_penalty_msat);
		let self_score = cmp::max(self.lowest_fee_to_peer_through_node, self.path_htlc_minimum_msat)
			.saturating_add(self.path_penalty_msat);
		other_score.cmp(&self_score).then_with(|| other.node_id.cmp(&self.node_id))
	}
}

impl cmp::PartialOrd for RouteGraphNode {
	fn partial_cmp(&self, other: &RouteGraphNode) -> Option<cmp::Ordering> {
		Some(self.cmp(other))
	}
}

/// A wrapper around the various hop representations.
///
/// Used to construct a [`PathBuildingHop`] and to estimate [`EffectiveCapacity`].
#[derive(Clone, Debug)]
enum CandidateRouteHop<'a> {
	/// A hop from the payer, where the outbound liquidity is known.
	FirstHop {
		details: &'a ChannelDetails,
	},
	/// A hop found in the [`NetworkGraph`], where the channel capacity may or may not be known.
	PublicHop {
		info: DirectedChannelInfoWithUpdate<'a>,
		short_channel_id: u64,
	},
	/// A hop to the payee found in the payment invoice, though not necessarily a direct channel.
	PrivateHop {
		hint: &'a RouteHintHop,
	}
}

impl<'a> CandidateRouteHop<'a> {
	fn short_channel_id(&self) -> u64 {
		match self {
			CandidateRouteHop::FirstHop { details } => details.get_outbound_payment_scid().unwrap(),
			CandidateRouteHop::PublicHop { short_channel_id, .. } => *short_channel_id,
			CandidateRouteHop::PrivateHop { hint } => hint.short_channel_id,
		}
	}

	// NOTE: This may alloc memory so avoid calling it in a hot code path.
	fn features(&self) -> ChannelFeatures {
		match self {
			CandidateRouteHop::FirstHop { details } => details.counterparty.features.to_context(),
			CandidateRouteHop::PublicHop { info, .. } => info.channel().features.clone(),
			CandidateRouteHop::PrivateHop { .. } => ChannelFeatures::empty(),
		}
	}

	fn cltv_expiry_delta(&self) -> u32 {
		match self {
			CandidateRouteHop::FirstHop { .. } => 0,
			CandidateRouteHop::PublicHop { info, .. } => info.direction().cltv_expiry_delta as u32,
			CandidateRouteHop::PrivateHop { hint } => hint.cltv_expiry_delta as u32,
		}
	}

	fn htlc_minimum_msat(&self) -> u64 {
		match self {
			CandidateRouteHop::FirstHop { .. } => 0,
			CandidateRouteHop::PublicHop { info, .. } => info.direction().htlc_minimum_msat,
			CandidateRouteHop::PrivateHop { hint } => hint.htlc_minimum_msat.unwrap_or(0),
		}
	}

	fn htlc_maximum_msat(&self) -> u64 {
		match self {
			CandidateRouteHop::FirstHop { details } => details.next_outbound_htlc_limit_msat,
			CandidateRouteHop::PublicHop { info, .. } => info.htlc_maximum_msat(),
			CandidateRouteHop::PrivateHop { hint } => {
				hint.htlc_maximum_msat.unwrap_or(u64::max_value())
			},
		}
	}

	fn fees(&self) -> RoutingFees {
		match self {
			CandidateRouteHop::FirstHop { .. } => RoutingFees {
				base_msat: 0, proportional_millionths: 0,
			},
			CandidateRouteHop::PublicHop { info, .. } => info.direction().fees,
			CandidateRouteHop::PrivateHop { hint } => hint.fees,
		}
	}

	fn effective_capacity(&self) -> EffectiveCapacity {
		match self {
			CandidateRouteHop::FirstHop { details } => EffectiveCapacity::ExactLiquidity {
				liquidity_msat: details.next_outbound_htlc_limit_msat,
			},
			CandidateRouteHop::PublicHop { info, .. } => info.effective_capacity(),
			CandidateRouteHop::PrivateHop { .. } => EffectiveCapacity::Infinite,
		}
	}
}

/// It's useful to keep track of the hops associated with the fees required to use them,
/// so that we can choose cheaper paths (as per Dijkstra's algorithm).
/// Fee values should be updated only in the context of the whole path, see update_value_and_recompute_fees.
/// These fee values are useful to choose hops as we traverse the graph "payee-to-payer".
#[derive(Clone)]
struct PathBuildingHop<'a> {
	// Note that this should be dropped in favor of loading it from CandidateRouteHop, but doing so
	// is a larger refactor and will require careful performance analysis.
	node_id: NodeId,
	candidate: CandidateRouteHop<'a>,
	fee_msat: u64,

	/// Minimal fees required to route to the source node of the current hop via any of its inbound channels.
	src_lowest_inbound_fees: RoutingFees,
	/// All the fees paid *after* this channel on the way to the destination
	next_hops_fee_msat: u64,
	/// Fee paid for the use of the current channel (see candidate.fees()).
	/// The value will be actually deducted from the counterparty balance on the previous link.
	hop_use_fee_msat: u64,
	/// Used to compare channels when choosing the for routing.
	/// Includes paying for the use of a hop and the following hops, as well as
	/// an estimated cost of reaching this hop.
	/// Might get stale when fees are recomputed. Primarily for internal use.
	total_fee_msat: u64,
	/// A mirror of the same field in RouteGraphNode. Note that this is only used during the graph
	/// walk and may be invalid thereafter.
	path_htlc_minimum_msat: u64,
	/// All penalties incurred from this channel on the way to the destination, as calculated using
	/// channel scoring.
	path_penalty_msat: u64,
	/// If we've already processed a node as the best node, we shouldn't process it again. Normally
	/// we'd just ignore it if we did as all channels would have a higher new fee, but because we
	/// may decrease the amounts in use as we walk the graph, the actual calculated fee may
	/// decrease as well. Thus, we have to explicitly track which nodes have been processed and
	/// avoid processing them again.
	was_processed: bool,
	#[cfg(all(not(feature = "_bench_unstable"), any(test, fuzzing)))]
	// In tests, we apply further sanity checks on cases where we skip nodes we already processed
	// to ensure it is specifically in cases where the fee has gone down because of a decrease in
	// value_contribution_msat, which requires tracking it here. See comments below where it is
	// used for more info.
	value_contribution_msat: u64,
}

impl<'a> core::fmt::Debug for PathBuildingHop<'a> {
	fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
		let mut debug_struct = f.debug_struct("PathBuildingHop");
		debug_struct
			.field("node_id", &self.node_id)
			.field("short_channel_id", &self.candidate.short_channel_id())
			.field("total_fee_msat", &self.total_fee_msat)
			.field("next_hops_fee_msat", &self.next_hops_fee_msat)
			.field("hop_use_fee_msat", &self.hop_use_fee_msat)
			.field("total_fee_msat - (next_hops_fee_msat + hop_use_fee_msat)", &(&self.total_fee_msat - (&self.next_hops_fee_msat + &self.hop_use_fee_msat)))
			.field("path_penalty_msat", &self.path_penalty_msat)
			.field("path_htlc_minimum_msat", &self.path_htlc_minimum_msat)
			.field("cltv_expiry_delta", &self.candidate.cltv_expiry_delta());
		#[cfg(all(not(feature = "_bench_unstable"), any(test, fuzzing)))]
		let debug_struct = debug_struct
			.field("value_contribution_msat", &self.value_contribution_msat);
		debug_struct.finish()
	}
}

// Instantiated with a list of hops with correct data in them collected during path finding,
// an instance of this struct should be further modified only via given methods.
#[derive(Clone)]
struct PaymentPath<'a> {
	hops: Vec<(PathBuildingHop<'a>, NodeFeatures)>,
}

impl<'a> PaymentPath<'a> {
	// TODO: Add a value_msat field to PaymentPath and use it instead of this function.
	fn get_value_msat(&self) -> u64 {
		self.hops.last().unwrap().0.fee_msat
	}

	fn get_path_penalty_msat(&self) -> u64 {
		self.hops.first().map(|h| h.0.path_penalty_msat).unwrap_or(u64::max_value())
	}

	fn get_total_fee_paid_msat(&self) -> u64 {
		if self.hops.len() < 1 {
			return 0;
		}
		let mut result = 0;
		// Can't use next_hops_fee_msat because it gets outdated.
		for (i, (hop, _)) in self.hops.iter().enumerate() {
			if i != self.hops.len() - 1 {
				result += hop.fee_msat;
			}
		}
		return result;
	}

	fn get_cost_msat(&self) -> u64 {
		self.get_total_fee_paid_msat().saturating_add(self.get_path_penalty_msat())
	}

	// If the amount transferred by the path is updated, the fees should be adjusted. Any other way
	// to change fees may result in an inconsistency.
	//
	// Sometimes we call this function right after constructing a path which is inconsistent in
	// that it the value being transferred has decreased while we were doing path finding, leading
	// to the fees being paid not lining up with the actual limits.
	//
	// Note that this function is not aware of the available_liquidity limit, and thus does not
	// support increasing the value being transferred.
	fn update_value_and_recompute_fees(&mut self, value_msat: u64) {
		assert!(value_msat <= self.hops.last().unwrap().0.fee_msat);

		let mut total_fee_paid_msat = 0 as u64;
		for i in (0..self.hops.len()).rev() {
			let last_hop = i == self.hops.len() - 1;

			// For non-last-hop, this value will represent the fees paid on the current hop. It
			// will consist of the fees for the use of the next hop, and extra fees to match
			// htlc_minimum_msat of the current channel. Last hop is handled separately.
			let mut cur_hop_fees_msat = 0;
			if !last_hop {
				cur_hop_fees_msat = self.hops.get(i + 1).unwrap().0.hop_use_fee_msat;
			}

			let mut cur_hop = &mut self.hops.get_mut(i).unwrap().0;
			cur_hop.next_hops_fee_msat = total_fee_paid_msat;
			// Overpay in fees if we can't save these funds due to htlc_minimum_msat.
			// We try to account for htlc_minimum_msat in scoring (add_entry!), so that nodes don't
			// set it too high just to maliciously take more fees by exploiting this
			// match htlc_minimum_msat logic.
			let mut cur_hop_transferred_amount_msat = total_fee_paid_msat + value_msat;
			if let Some(extra_fees_msat) = cur_hop.candidate.htlc_minimum_msat().checked_sub(cur_hop_transferred_amount_msat) {
				// Note that there is a risk that *previous hops* (those closer to us, as we go
				// payee->our_node here) would exceed their htlc_maximum_msat or available balance.
				//
				// This might make us end up with a broken route, although this should be super-rare
				// in practice, both because of how healthy channels look like, and how we pick
				// channels in add_entry.
				// Also, this can't be exploited more heavily than *announce a free path and fail
				// all payments*.
				cur_hop_transferred_amount_msat += extra_fees_msat;
				total_fee_paid_msat += extra_fees_msat;
				cur_hop_fees_msat += extra_fees_msat;
			}

			if last_hop {
				// Final hop is a special case: it usually has just value_msat (by design), but also
				// it still could overpay for the htlc_minimum_msat.
				cur_hop.fee_msat = cur_hop_transferred_amount_msat;
			} else {
				// Propagate updated fees for the use of the channels to one hop back, where they
				// will be actually paid (fee_msat). The last hop is handled above separately.
				cur_hop.fee_msat = cur_hop_fees_msat;
			}

			// Fee for the use of the current hop which will be deducted on the previous hop.
			// Irrelevant for the first hop, as it doesn't have the previous hop, and the use of
			// this channel is free for us.
			if i != 0 {
				if let Some(new_fee) = compute_fees(cur_hop_transferred_amount_msat, cur_hop.candidate.fees()) {
					cur_hop.hop_use_fee_msat = new_fee;
					total_fee_paid_msat += new_fee;
				} else {
					// It should not be possible because this function is called only to reduce the
					// value. In that case, compute_fee was already called with the same fees for
					// larger amount and there was no overflow.
					unreachable!();
				}
			}
		}
	}
}

fn compute_fees(amount_msat: u64, channel_fees: RoutingFees) -> Option<u64> {
	let proportional_fee_millions =
		amount_msat.checked_mul(channel_fees.proportional_millionths as u64);
	if let Some(new_fee) = proportional_fee_millions.and_then(|part| {
			(channel_fees.base_msat as u64).checked_add(part / 1_000_000) }) {

		Some(new_fee)
	} else {
		// This function may be (indirectly) called without any verification,
		// with channel_fees provided by a caller. We should handle it gracefully.
		None
	}
}

/// The default `features` we assume for a node in a route, when no `features` are known about that
/// specific node.
///
/// Default features are:
/// * variable_length_onion_optional
fn default_node_features() -> NodeFeatures {
	let mut features = NodeFeatures::empty();
	features.set_variable_length_onion_optional();
	features
}

/// Finds a route from us (payer) to the given target node (payee).
///
/// If the payee provided features in their invoice, they should be provided via `params.payee`.
/// Without this, MPP will only be used if the payee's features are available in the network graph.
///
/// Private routing paths between a public node and the target may be included in `params.payee`.
///
/// If some channels aren't announced, it may be useful to fill in `first_hops` with the results
/// from [`ChannelManager::list_usable_channels`]. If it is filled in, the view of our local
/// channels from [`NetworkGraph`] will be ignored, and only those in `first_hops` will be used.
///
/// The fees on channels from us to the next hop are ignored as they are assumed to all be equal.
/// However, the enabled/disabled bit on such channels as well as the `htlc_minimum_msat` /
/// `htlc_maximum_msat` *are* checked as they may change based on the receiving node.
///
/// # Note
///
/// May be used to re-compute a [`Route`] when handling a [`Event::PaymentPathFailed`]. Any
/// adjustments to the [`NetworkGraph`] and channel scores should be made prior to calling this
/// function.
///
/// # Panics
///
/// Panics if first_hops contains channels without short_channel_ids;
/// [`ChannelManager::list_usable_channels`] will never include such channels.
///
/// [`ChannelManager::list_usable_channels`]: crate::ln::channelmanager::ChannelManager::list_usable_channels
/// [`Event::PaymentPathFailed`]: crate::util::events::Event::PaymentPathFailed
pub fn find_route<L: Deref, S: Score>(
	our_node_pubkey: &PublicKey, route_params: &RouteParameters, network: &NetworkGraph,
	first_hops: Option<&[&ChannelDetails]>, logger: L, scorer: &S, random_seed_bytes: &[u8; 32]
) -> Result<Route, LightningError>
where L::Target: Logger {
	let network_graph = network.read_only();
	let mut route = get_route(our_node_pubkey, &route_params.payment_params, &network_graph, first_hops,
		route_params.final_value_msat, route_params.final_cltv_expiry_delta, logger, scorer,
		random_seed_bytes)?;
	add_random_cltv_offset(&mut route, &route_params.payment_params, &network_graph, random_seed_bytes);
	Ok(route)
}

pub(crate) fn get_route<L: Deref, S: Score>(
	our_node_pubkey: &PublicKey, payment_params: &PaymentParameters, network_graph: &ReadOnlyNetworkGraph,
	first_hops: Option<&[&ChannelDetails]>, final_value_msat: u64, final_cltv_expiry_delta: u32,
	logger: L, scorer: &S, random_seed_bytes: &[u8; 32]
) -> Result<Route, LightningError>
where L::Target: Logger {
	let payee_node_id = NodeId::from_pubkey(&payment_params.payee_pubkey);
	let our_node_id = NodeId::from_pubkey(&our_node_pubkey);

	if payee_node_id == our_node_id {
		return Err(LightningError{err: "Cannot generate a route to ourselves".to_owned(), action: ErrorAction::IgnoreError});
	}

	if final_value_msat > MAX_VALUE_MSAT {
		return Err(LightningError{err: "Cannot generate a route of more value than all existing satoshis".to_owned(), action: ErrorAction::IgnoreError});
	}

	if final_value_msat == 0 {
		return Err(LightningError{err: "Cannot send a payment of 0 msat".to_owned(), action: ErrorAction::IgnoreError});
	}

	for route in payment_params.route_hints.iter() {
		for hop in &route.0 {
			if hop.src_node_id == payment_params.payee_pubkey {
				return Err(LightningError{err: "Route hint cannot have the payee as the source.".to_owned(), action: ErrorAction::IgnoreError});
			}
		}
	}
	if payment_params.max_total_cltv_expiry_delta <= final_cltv_expiry_delta {
		return Err(LightningError{err: "Can't find a route where the maximum total CLTV expiry delta is below the final CLTV expiry.".to_owned(), action: ErrorAction::IgnoreError});
	}

	// The general routing idea is the following:
	// 1. Fill first/last hops communicated by the caller.
	// 2. Attempt to construct a path from payer to payee for transferring
	//    any ~sufficient (described later) value.
	//    If succeed, remember which channels were used and how much liquidity they have available,
	//    so that future paths don't rely on the same liquidity.
	// 3. Proceed to the next step if:
	//    - we hit the recommended target value;
	//    - OR if we could not construct a new path. Any next attempt will fail too.
	//    Otherwise, repeat step 2.
	// 4. See if we managed to collect paths which aggregately are able to transfer target value
	//    (not recommended value).
	// 5. If yes, proceed. If not, fail routing.
	// 6. Randomly combine paths into routes having enough to fulfill the payment. (TODO: knapsack)
	// 7. Of all the found paths, select only those with the lowest total fee.
	// 8. The last path in every selected route is likely to be more than we need.
	//    Reduce its value-to-transfer and recompute fees.
	// 9. Choose the best route by the lowest total fee.

	// As for the actual search algorithm,
	// we do a payee-to-payer pseudo-Dijkstra's sorting by each node's distance from the payee
	// plus the minimum per-HTLC fee to get from it to another node (aka "shitty pseudo-A*").
	//
	// We are not a faithful Dijkstra's implementation because we can change values which impact
	// earlier nodes while processing later nodes. Specifically, if we reach a channel with a lower
	// liquidity limit (via htlc_maximum_msat, on-chain capacity or assumed liquidity limits) than
	// the value we are currently attempting to send over a path, we simply reduce the value being
	// sent along the path for any hops after that channel. This may imply that later fees (which
	// we've already tabulated) are lower because a smaller value is passing through the channels
	// (and the proportional fee is thus lower). There isn't a trivial way to recalculate the
	// channels which were selected earlier (and which may still be used for other paths without a
	// lower liquidity limit), so we simply accept that some liquidity-limited paths may be
	// de-preferenced.
	//
	// One potentially problematic case for this algorithm would be if there are many
	// liquidity-limited paths which are liquidity-limited near the destination (ie early in our
	// graph walking), we may never find a path which is not liquidity-limited and has lower
	// proportional fee (and only lower absolute fee when considering the ultimate value sent).
	// Because we only consider paths with at least 5% of the total value being sent, the damage
	// from such a case should be limited, however this could be further reduced in the future by
	// calculating fees on the amount we wish to route over a path, ie ignoring the liquidity
	// limits for the purposes of fee calculation.
	//
	// Alternatively, we could store more detailed path information in the heap (targets, below)
	// and index the best-path map (dist, below) by node *and* HTLC limits, however that would blow
	// up the runtime significantly both algorithmically (as we'd traverse nodes multiple times)
	// and practically (as we would need to store dynamically-allocated path information in heap
	// objects, increasing malloc traffic and indirect memory access significantly). Further, the
	// results of such an algorithm would likely be biased towards lower-value paths.
	//
	// Further, we could return to a faithful Dijkstra's algorithm by rejecting paths with limits
	// outside of our current search value, running a path search more times to gather candidate
	// paths at different values. While this may be acceptable, further path searches may increase
	// runtime for little gain. Specifically, the current algorithm rather efficiently explores the
	// graph for candidate paths, calculating the maximum value which can realistically be sent at
	// the same time, remaining generic across different payment values.
	//
	// TODO: There are a few tweaks we could do, including possibly pre-calculating more stuff
	// to use as the A* heuristic beyond just the cost to get one node further than the current
	// one.

	let network_channels = network_graph.channels();
	let network_nodes = network_graph.nodes();

	// Allow MPP only if we have a features set from somewhere that indicates the payee supports
	// it. If the payee supports it they're supposed to include it in the invoice, so that should
	// work reliably.
	let allow_mpp = if let Some(features) = &payment_params.features {
		features.supports_basic_mpp()
	} else if let Some(node) = network_nodes.get(&payee_node_id) {
		if let Some(node_info) = node.announcement_info.as_ref() {
			node_info.features.supports_basic_mpp()
		} else { false }
	} else { false };
	log_trace!(logger, "Searching for a route from payer {} to payee {} {} MPP and {} first hops {}overriding the network graph", our_node_pubkey,
		payment_params.payee_pubkey, if allow_mpp { "with" } else { "without" },
		first_hops.map(|hops| hops.len()).unwrap_or(0), if first_hops.is_some() { "" } else { "not " });

	// Step (1).
	// Prepare the data we'll use for payee-to-payer search by
	// inserting first hops suggested by the caller as targets.
	// Our search will then attempt to reach them while traversing from the payee node.
	let mut first_hop_targets: HashMap<_, Vec<&ChannelDetails>> =
		HashMap::with_capacity(if first_hops.is_some() { first_hops.as_ref().unwrap().len() } else { 0 });
	if let Some(hops) = first_hops {
		for chan in hops {
			if chan.get_outbound_payment_scid().is_none() {
				panic!("first_hops should be filled in with usable channels, not pending ones");
			}
			if chan.counterparty.node_id == *our_node_pubkey {
				return Err(LightningError{err: "First hop cannot have our_node_pubkey as a destination.".to_owned(), action: ErrorAction::IgnoreError});
			}
			first_hop_targets
				.entry(NodeId::from_pubkey(&chan.counterparty.node_id))
				.or_insert(Vec::new())
				.push(chan);
		}
		if first_hop_targets.is_empty() {
			return Err(LightningError{err: "Cannot route when there are no outbound routes away from us".to_owned(), action: ErrorAction::IgnoreError});
		}
	}

	// The main heap containing all candidate next-hops sorted by their score (max(A* fee,
	// htlc_minimum)). Ideally this would be a heap which allowed cheap score reduction instead of
	// adding duplicate entries when we find a better path to a given node.
	let mut targets: BinaryHeap<RouteGraphNode> = BinaryHeap::new();

	// Map from node_id to information about the best current path to that node, including feerate
	// information.
	let mut dist: HashMap<NodeId, PathBuildingHop> = HashMap::with_capacity(network_nodes.len());

	// During routing, if we ignore a path due to an htlc_minimum_msat limit, we set this,
	// indicating that we may wish to try again with a higher value, potentially paying to meet an
	// htlc_minimum with extra fees while still finding a cheaper path.
	let mut hit_minimum_limit;

	// When arranging a route, we select multiple paths so that we can make a multi-path payment.
	// We start with a path_value of the exact amount we want, and if that generates a route we may
	// return it immediately. Otherwise, we don't stop searching for paths until we have 3x the
	// amount we want in total across paths, selecting the best subset at the end.
	const ROUTE_CAPACITY_PROVISION_FACTOR: u64 = 3;
	let recommended_value_msat = final_value_msat * ROUTE_CAPACITY_PROVISION_FACTOR as u64;
	let mut path_value_msat = final_value_msat;

	// Keep track of how much liquidity has been used in selected channels. Used to determine
	// if the channel can be used by additional MPP paths or to inform path finding decisions. It is
	// aware of direction *only* to ensure that the correct htlc_maximum_msat value is used. Hence,
	// liquidity used in one direction will not offset any used in the opposite direction.
	let mut used_channel_liquidities: HashMap<(u64, bool), u64> =
		HashMap::with_capacity(network_nodes.len());

	// Keeping track of how much value we already collected across other paths. Helps to decide:
	// - how much a new path should be transferring (upper bound);
	// - whether a channel should be disregarded because
	//   it's available liquidity is too small comparing to how much more we need to collect;
	// - when we want to stop looking for new paths.
	let mut already_collected_value_msat = 0;

	for (_, channels) in first_hop_targets.iter_mut() {
		// Sort the first_hops channels to the same node(s) in priority order of which channel we'd
		// most like to use.
		//
		// First, if channels are below `recommended_value_msat`, sort them in descending order,
		// preferring larger channels to avoid splitting the payment into more MPP parts than is
		// required.
		//
		// Second, because simply always sorting in descending order would always use our largest
		// available outbound capacity, needlessly fragmenting our available channel capacities,
		// sort channels above `recommended_value_msat` in ascending order, preferring channels
		// which have enough, but not too much, capacity for the payment.
		channels.sort_unstable_by(|chan_a, chan_b| {
			if chan_b.next_outbound_htlc_limit_msat < recommended_value_msat || chan_a.next_outbound_htlc_limit_msat < recommended_value_msat {
				// Sort in descending order
				chan_b.next_outbound_htlc_limit_msat.cmp(&chan_a.next_outbound_htlc_limit_msat)
			} else {
				// Sort in ascending order
				chan_a.next_outbound_htlc_limit_msat.cmp(&chan_b.next_outbound_htlc_limit_msat)
			}
		});
	}

	log_trace!(logger, "Building path from {} (payee) to {} (us/payer) for value {} msat.", payment_params.payee_pubkey, our_node_pubkey, final_value_msat);

	macro_rules! add_entry {
		// Adds entry which goes from $src_node_id to $dest_node_id over the $candidate hop.
		// $next_hops_fee_msat represents the fees paid for using all the channels *after* this one,
		// since that value has to be transferred over this channel.
		// Returns whether this channel caused an update to `targets`.
		( $candidate: expr, $src_node_id: expr, $dest_node_id: expr, $next_hops_fee_msat: expr,
			$next_hops_value_contribution: expr, $next_hops_path_htlc_minimum_msat: expr,
			$next_hops_path_penalty_msat: expr, $next_hops_cltv_delta: expr, $next_hops_path_length: expr ) => { {
			// We "return" whether we updated the path at the end, via this:
			let mut did_add_update_path_to_src_node = false;
			// Channels to self should not be used. This is more of belt-and-suspenders, because in
			// practice these cases should be caught earlier:
			// - for regular channels at channel announcement (TODO)
			// - for first and last hops early in get_route
			if $src_node_id != $dest_node_id {
				let short_channel_id = $candidate.short_channel_id();
				let htlc_maximum_msat = $candidate.htlc_maximum_msat();

				// It is tricky to subtract $next_hops_fee_msat from available liquidity here.
				// It may be misleading because we might later choose to reduce the value transferred
				// over these channels, and the channel which was insufficient might become sufficient.
				// Worst case: we drop a good channel here because it can't cover the high following
				// fees caused by one expensive channel, but then this channel could have been used
				// if the amount being transferred over this path is lower.
				// We do this for now, but this is a subject for removal.
				if let Some(mut available_value_contribution_msat) = htlc_maximum_msat.checked_sub($next_hops_fee_msat) {
					let used_liquidity_msat = used_channel_liquidities
						.get(&(short_channel_id, $src_node_id < $dest_node_id))
						.map_or(0, |used_liquidity_msat| {
							available_value_contribution_msat = available_value_contribution_msat
								.saturating_sub(*used_liquidity_msat);
							*used_liquidity_msat
						});

					// Routing Fragmentation Mitigation heuristic:
					//
					// Routing fragmentation across many payment paths increases the overall routing
					// fees as you have irreducible routing fees per-link used (`fee_base_msat`).
					// Taking too many smaller paths also increases the chance of payment failure.
					// Thus to avoid this effect, we require from our collected links to provide
					// at least a minimal contribution to the recommended value yet-to-be-fulfilled.
					//
					// This requirement is currently 5% of the remaining-to-be-collected value.
					// This means as we successfully advance in our collection,
					// the absolute liquidity contribution is lowered,
					// thus increasing the number of potential channels to be selected.

					// Derive the minimal liquidity contribution with a ratio of 20 (5%, rounded up)
					// or 100% if we're not allowed to do multipath payments.
					let minimal_value_contribution_msat: u64 = if allow_mpp {
						(recommended_value_msat - already_collected_value_msat + 19) / 20
					} else {
						final_value_msat
					};
					// Verify the liquidity offered by this channel complies to the minimal contribution.
					let contributes_sufficient_value = available_value_contribution_msat >= minimal_value_contribution_msat;
					// Do not consider candidate hops that would exceed the maximum path length.
					let path_length_to_node = $next_hops_path_length + 1;
					let doesnt_exceed_max_path_length = path_length_to_node <= MAX_PATH_LENGTH_ESTIMATE;

					// Do not consider candidates that exceed the maximum total cltv expiry limit.
					// In order to already account for some of the privacy enhancing random CLTV
					// expiry delta offset we add on top later, we subtract a rough estimate
					// (2*MEDIAN_HOP_CLTV_EXPIRY_DELTA) here.
					let max_total_cltv_expiry_delta = (payment_params.max_total_cltv_expiry_delta - final_cltv_expiry_delta)
						.checked_sub(2*MEDIAN_HOP_CLTV_EXPIRY_DELTA)
						.unwrap_or(payment_params.max_total_cltv_expiry_delta - final_cltv_expiry_delta);
					let hop_total_cltv_delta = ($next_hops_cltv_delta as u32)
						.saturating_add($candidate.cltv_expiry_delta());
					let doesnt_exceed_cltv_delta_limit = hop_total_cltv_delta <= max_total_cltv_expiry_delta;

					let value_contribution_msat = cmp::min(available_value_contribution_msat, $next_hops_value_contribution);
					// Includes paying fees for the use of the following channels.
					let amount_to_transfer_over_msat: u64 = match value_contribution_msat.checked_add($next_hops_fee_msat) {
						Some(result) => result,
						// Can't overflow due to how the values were computed right above.
						None => unreachable!(),
					};
					#[allow(unused_comparisons)] // $next_hops_path_htlc_minimum_msat is 0 in some calls so rustc complains
					let over_path_minimum_msat = amount_to_transfer_over_msat >= $candidate.htlc_minimum_msat() &&
						amount_to_transfer_over_msat >= $next_hops_path_htlc_minimum_msat;

					#[allow(unused_comparisons)] // $next_hops_path_htlc_minimum_msat is 0 in some calls so rustc complains
					let may_overpay_to_meet_path_minimum_msat =
						((amount_to_transfer_over_msat < $candidate.htlc_minimum_msat() &&
						  recommended_value_msat > $candidate.htlc_minimum_msat()) ||
						 (amount_to_transfer_over_msat < $next_hops_path_htlc_minimum_msat &&
						  recommended_value_msat > $next_hops_path_htlc_minimum_msat));

					// If HTLC minimum is larger than the amount we're going to transfer, we shouldn't
					// bother considering this channel. If retrying with recommended_value_msat may
					// allow us to hit the HTLC minimum limit, set htlc_minimum_limit so that we go
					// around again with a higher amount.
					if contributes_sufficient_value && doesnt_exceed_max_path_length &&
						doesnt_exceed_cltv_delta_limit && may_overpay_to_meet_path_minimum_msat {
						hit_minimum_limit = true;
					} else if contributes_sufficient_value && doesnt_exceed_max_path_length &&
						doesnt_exceed_cltv_delta_limit && over_path_minimum_msat {
						// Note that low contribution here (limited by available_liquidity_msat)
						// might violate htlc_minimum_msat on the hops which are next along the
						// payment path (upstream to the payee). To avoid that, we recompute
						// path fees knowing the final path contribution after constructing it.
						let path_htlc_minimum_msat = compute_fees($next_hops_path_htlc_minimum_msat, $candidate.fees())
							.and_then(|fee_msat| fee_msat.checked_add($next_hops_path_htlc_minimum_msat))
							.map(|fee_msat| cmp::max(fee_msat, $candidate.htlc_minimum_msat()))
							.unwrap_or_else(|| u64::max_value());
						let hm_entry = dist.entry($src_node_id);
						let old_entry = hm_entry.or_insert_with(|| {
							// If there was previously no known way to access the source node
							// (recall it goes payee-to-payer) of short_channel_id, first add a
							// semi-dummy record just to compute the fees to reach the source node.
							// This will affect our decision on selecting short_channel_id
							// as a way to reach the $dest_node_id.
							let mut fee_base_msat = 0;
							let mut fee_proportional_millionths = 0;
							if let Some(Some(fees)) = network_nodes.get(&$src_node_id).map(|node| node.lowest_inbound_channel_fees) {
								fee_base_msat = fees.base_msat;
								fee_proportional_millionths = fees.proportional_millionths;
							}
							PathBuildingHop {
								node_id: $dest_node_id.clone(),
								candidate: $candidate.clone(),
								fee_msat: 0,
								src_lowest_inbound_fees: RoutingFees {
									base_msat: fee_base_msat,
									proportional_millionths: fee_proportional_millionths,
								},
								next_hops_fee_msat: u64::max_value(),
								hop_use_fee_msat: u64::max_value(),
								total_fee_msat: u64::max_value(),
								path_htlc_minimum_msat,
								path_penalty_msat: u64::max_value(),
								was_processed: false,
								#[cfg(all(not(feature = "_bench_unstable"), any(test, fuzzing)))]
								value_contribution_msat,
							}
						});

						#[allow(unused_mut)] // We only use the mut in cfg(test)
						let mut should_process = !old_entry.was_processed;
						#[cfg(all(not(feature = "_bench_unstable"), any(test, fuzzing)))]
						{
							// In test/fuzzing builds, we do extra checks to make sure the skipping
							// of already-seen nodes only happens in cases we expect (see below).
							if !should_process { should_process = true; }
						}

						if should_process {
							let mut hop_use_fee_msat = 0;
							let mut total_fee_msat = $next_hops_fee_msat;

							// Ignore hop_use_fee_msat for channel-from-us as we assume all channels-from-us
							// will have the same effective-fee
							if $src_node_id != our_node_id {
								match compute_fees(amount_to_transfer_over_msat, $candidate.fees()) {
									// max_value means we'll always fail
									// the old_entry.total_fee_msat > total_fee_msat check
									None => total_fee_msat = u64::max_value(),
									Some(fee_msat) => {
										hop_use_fee_msat = fee_msat;
										total_fee_msat += hop_use_fee_msat;
										// When calculating the lowest inbound fees to a node, we
										// calculate fees here not based on the actual value we think
										// will flow over this channel, but on the minimum value that
										// we'll accept flowing over it. The minimum accepted value
										// is a constant through each path collection run, ensuring
										// consistent basis. Otherwise we may later find a
										// different path to the source node that is more expensive,
										// but which we consider to be cheaper because we are capacity
										// constrained and the relative fee becomes lower.
										match compute_fees(minimal_value_contribution_msat, old_entry.src_lowest_inbound_fees)
												.map(|a| a.checked_add(total_fee_msat)) {
											Some(Some(v)) => {
												total_fee_msat = v;
											},
											_ => {
												total_fee_msat = u64::max_value();
											}
										};
									}
								}
							}

							let channel_usage = ChannelUsage {
								amount_msat: amount_to_transfer_over_msat,
								inflight_htlc_msat: used_liquidity_msat,
								effective_capacity: $candidate.effective_capacity(),
							};
							let channel_penalty_msat = scorer.channel_penalty_msat(
								short_channel_id, &$src_node_id, &$dest_node_id, channel_usage
							);
							let path_penalty_msat = $next_hops_path_penalty_msat
								.saturating_add(channel_penalty_msat);
							let new_graph_node = RouteGraphNode {
								node_id: $src_node_id,
								lowest_fee_to_peer_through_node: total_fee_msat,
								lowest_fee_to_node: $next_hops_fee_msat as u64 + hop_use_fee_msat,
								total_cltv_delta: hop_total_cltv_delta,
								value_contribution_msat: value_contribution_msat,
								path_htlc_minimum_msat,
								path_penalty_msat,
								path_length_to_node,
							};

							// Update the way of reaching $src_node_id with the given short_channel_id (from $dest_node_id),
							// if this way is cheaper than the already known
							// (considering the cost to "reach" this channel from the route destination,
							// the cost of using this channel,
							// and the cost of routing to the source node of this channel).
							// Also, consider that htlc_minimum_msat_difference, because we might end up
							// paying it. Consider the following exploit:
							// we use 2 paths to transfer 1.5 BTC. One of them is 0-fee normal 1 BTC path,
							// and for the other one we picked a 1sat-fee path with htlc_minimum_msat of
							// 1 BTC. Now, since the latter is more expensive, we gonna try to cut it
							// by 0.5 BTC, but then match htlc_minimum_msat by paying a fee of 0.5 BTC
							// to this channel.
							// Ideally the scoring could be smarter (e.g. 0.5*htlc_minimum_msat here),
							// but it may require additional tracking - we don't want to double-count
							// the fees included in $next_hops_path_htlc_minimum_msat, but also
							// can't use something that may decrease on future hops.
							let old_cost = cmp::max(old_entry.total_fee_msat, old_entry.path_htlc_minimum_msat)
								.saturating_add(old_entry.path_penalty_msat);
							let new_cost = cmp::max(total_fee_msat, path_htlc_minimum_msat)
								.saturating_add(path_penalty_msat);

							if !old_entry.was_processed && new_cost < old_cost {
								targets.push(new_graph_node);
								old_entry.next_hops_fee_msat = $next_hops_fee_msat;
								old_entry.hop_use_fee_msat = hop_use_fee_msat;
								old_entry.total_fee_msat = total_fee_msat;
								old_entry.node_id = $dest_node_id.clone();
								old_entry.candidate = $candidate.clone();
								old_entry.fee_msat = 0; // This value will be later filled with hop_use_fee_msat of the following channel
								old_entry.path_htlc_minimum_msat = path_htlc_minimum_msat;
								old_entry.path_penalty_msat = path_penalty_msat;
								#[cfg(all(not(feature = "_bench_unstable"), any(test, fuzzing)))]
								{
									old_entry.value_contribution_msat = value_contribution_msat;
								}
								did_add_update_path_to_src_node = true;
							} else if old_entry.was_processed && new_cost < old_cost {
								#[cfg(all(not(feature = "_bench_unstable"), any(test, fuzzing)))]
								{
									// If we're skipping processing a node which was previously
									// processed even though we found another path to it with a
									// cheaper fee, check that it was because the second path we
									// found (which we are processing now) has a lower value
									// contribution due to an HTLC minimum limit.
									//
									// e.g. take a graph with two paths from node 1 to node 2, one
									// through channel A, and one through channel B. Channel A and
									// B are both in the to-process heap, with their scores set by
									// a higher htlc_minimum than fee.
									// Channel A is processed first, and the channels onwards from
									// node 1 are added to the to-process heap. Thereafter, we pop
									// Channel B off of the heap, note that it has a much more
									// restrictive htlc_maximum_msat, and recalculate the fees for
									// all of node 1's channels using the new, reduced, amount.
									//
									// This would be bogus - we'd be selecting a higher-fee path
									// with a lower htlc_maximum_msat instead of the one we'd
									// already decided to use.
									debug_assert!(path_htlc_minimum_msat < old_entry.path_htlc_minimum_msat);
									debug_assert!(
										value_contribution_msat + path_penalty_msat <
										old_entry.value_contribution_msat + old_entry.path_penalty_msat
									);
								}
							}
						}
					}
				}
			}
			did_add_update_path_to_src_node
		} }
	}

	let default_node_features = default_node_features();

	// Find ways (channels with destination) to reach a given node and store them
	// in the corresponding data structures (routing graph etc).
	// $fee_to_target_msat represents how much it costs to reach to this node from the payee,
	// meaning how much will be paid in fees after this node (to the best of our knowledge).
	// This data can later be helpful to optimize routing (pay lower fees).
	macro_rules! add_entries_to_cheapest_to_target_node {
		( $node: expr, $node_id: expr, $fee_to_target_msat: expr, $next_hops_value_contribution: expr,
		  $next_hops_path_htlc_minimum_msat: expr, $next_hops_path_penalty_msat: expr,
		  $next_hops_cltv_delta: expr, $next_hops_path_length: expr ) => {
			let skip_node = if let Some(elem) = dist.get_mut(&$node_id) {
				let was_processed = elem.was_processed;
				elem.was_processed = true;
				was_processed
			} else {
				// Entries are added to dist in add_entry!() when there is a channel from a node.
				// Because there are no channels from payee, it will not have a dist entry at this point.
				// If we're processing any other node, it is always be the result of a channel from it.
				assert_eq!($node_id, payee_node_id);
				false
			};

			if !skip_node {
				if let Some(first_channels) = first_hop_targets.get(&$node_id) {
					for details in first_channels {
						let candidate = CandidateRouteHop::FirstHop { details };
						add_entry!(candidate, our_node_id, $node_id, $fee_to_target_msat,
							$next_hops_value_contribution,
							$next_hops_path_htlc_minimum_msat, $next_hops_path_penalty_msat,
							$next_hops_cltv_delta, $next_hops_path_length);
					}
				}

				let features = if let Some(node_info) = $node.announcement_info.as_ref() {
					&node_info.features
				} else {
					&default_node_features
				};

				if !features.requires_unknown_bits() {
					for chan_id in $node.channels.iter() {
						let chan = network_channels.get(chan_id).unwrap();
						if !chan.features.requires_unknown_bits() {
							let (directed_channel, source) =
								chan.as_directed_to(&$node_id).expect("inconsistent NetworkGraph");
							if first_hops.is_none() || *source != our_node_id {
								if let Some(direction) = directed_channel.direction() {
									if direction.enabled {
										let candidate = CandidateRouteHop::PublicHop {
											info: directed_channel.with_update().unwrap(),
											short_channel_id: *chan_id,
										};
										add_entry!(candidate, *source, $node_id,
											$fee_to_target_msat,
											$next_hops_value_contribution,
											$next_hops_path_htlc_minimum_msat,
											$next_hops_path_penalty_msat,
											$next_hops_cltv_delta, $next_hops_path_length);
									}
								}
							}
						}
					}
				}
			}
		};
	}

	let mut payment_paths = Vec::<PaymentPath>::new();

	// TODO: diversify by nodes (so that all paths aren't doomed if one node is offline).
	'paths_collection: loop {
		// For every new path, start from scratch, except for used_channel_liquidities, which
		// helps to avoid reusing previously selected paths in future iterations.
		targets.clear();
		dist.clear();
		hit_minimum_limit = false;

		// If first hop is a private channel and the only way to reach the payee, this is the only
		// place where it could be added.
		if let Some(first_channels) = first_hop_targets.get(&payee_node_id) {
			for details in first_channels {
				let candidate = CandidateRouteHop::FirstHop { details };
				let added = add_entry!(candidate, our_node_id, payee_node_id, 0, path_value_msat,
									0, 0u64, 0, 0);
				log_trace!(logger, "{} direct route to payee via SCID {}",
						if added { "Added" } else { "Skipped" }, candidate.short_channel_id());
			}
		}

		// Add the payee as a target, so that the payee-to-payer
		// search algorithm knows what to start with.
		match network_nodes.get(&payee_node_id) {
			// The payee is not in our network graph, so nothing to add here.
			// There is still a chance of reaching them via last_hops though,
			// so don't yet fail the payment here.
			// If not, targets.pop() will not even let us enter the loop in step 2.
			None => {},
			Some(node) => {
				add_entries_to_cheapest_to_target_node!(node, payee_node_id, 0, path_value_msat, 0, 0u64, 0, 0);
			},
		}

		// Step (2).
		// If a caller provided us with last hops, add them to routing targets. Since this happens
		// earlier than general path finding, they will be somewhat prioritized, although currently
		// it matters only if the fees are exactly the same.
		for route in payment_params.route_hints.iter().filter(|route| !route.0.is_empty()) {
			let first_hop_in_route = &(route.0)[0];
			let have_hop_src_in_graph =
				// Only add the hops in this route to our candidate set if either
				// we have a direct channel to the first hop or the first hop is
				// in the regular network graph.
				first_hop_targets.get(&NodeId::from_pubkey(&first_hop_in_route.src_node_id)).is_some() ||
				network_nodes.get(&NodeId::from_pubkey(&first_hop_in_route.src_node_id)).is_some();
			if have_hop_src_in_graph {
				// We start building the path from reverse, i.e., from payee
				// to the first RouteHintHop in the path.
				let hop_iter = route.0.iter().rev();
				let prev_hop_iter = core::iter::once(&payment_params.payee_pubkey).chain(
					route.0.iter().skip(1).rev().map(|hop| &hop.src_node_id));
				let mut hop_used = true;
				let mut aggregate_next_hops_fee_msat: u64 = 0;
				let mut aggregate_next_hops_path_htlc_minimum_msat: u64 = 0;
				let mut aggregate_next_hops_path_penalty_msat: u64 = 0;
				let mut aggregate_next_hops_cltv_delta: u32 = 0;
				let mut aggregate_next_hops_path_length: u8 = 0;

				for (idx, (hop, prev_hop_id)) in hop_iter.zip(prev_hop_iter).enumerate() {
					let source = NodeId::from_pubkey(&hop.src_node_id);
					let target = NodeId::from_pubkey(&prev_hop_id);
					let candidate = network_channels
						.get(&hop.short_channel_id)
						.and_then(|channel| channel.as_directed_to(&target))
						.and_then(|(channel, _)| channel.with_update())
						.map(|info| CandidateRouteHop::PublicHop {
							info,
							short_channel_id: hop.short_channel_id,
						})
						.unwrap_or_else(|| CandidateRouteHop::PrivateHop { hint: hop });

					if !add_entry!(candidate, source, target, aggregate_next_hops_fee_msat,
								path_value_msat, aggregate_next_hops_path_htlc_minimum_msat,
								aggregate_next_hops_path_penalty_msat,
								aggregate_next_hops_cltv_delta, aggregate_next_hops_path_length) {
						// If this hop was not used then there is no use checking the preceding
						// hops in the RouteHint. We can break by just searching for a direct
						// channel between last checked hop and first_hop_targets.
						hop_used = false;
					}

					let used_liquidity_msat = used_channel_liquidities
						.get(&(hop.short_channel_id, source < target)).copied().unwrap_or(0);
					let channel_usage = ChannelUsage {
						amount_msat: final_value_msat + aggregate_next_hops_fee_msat,
						inflight_htlc_msat: used_liquidity_msat,
						effective_capacity: candidate.effective_capacity(),
					};
					let channel_penalty_msat = scorer.channel_penalty_msat(
						hop.short_channel_id, &source, &target, channel_usage
					);
					aggregate_next_hops_path_penalty_msat = aggregate_next_hops_path_penalty_msat
						.saturating_add(channel_penalty_msat);

					aggregate_next_hops_cltv_delta = aggregate_next_hops_cltv_delta
						.saturating_add(hop.cltv_expiry_delta as u32);

					aggregate_next_hops_path_length = aggregate_next_hops_path_length
						.saturating_add(1);

					// Searching for a direct channel between last checked hop and first_hop_targets
					if let Some(first_channels) = first_hop_targets.get(&NodeId::from_pubkey(&prev_hop_id)) {
						for details in first_channels {
							let candidate = CandidateRouteHop::FirstHop { details };
							add_entry!(candidate, our_node_id, NodeId::from_pubkey(&prev_hop_id),
								aggregate_next_hops_fee_msat, path_value_msat,
								aggregate_next_hops_path_htlc_minimum_msat,
								aggregate_next_hops_path_penalty_msat, aggregate_next_hops_cltv_delta,
								aggregate_next_hops_path_length);
						}
					}

					if !hop_used {
						break;
					}

					// In the next values of the iterator, the aggregate fees already reflects
					// the sum of value sent from payer (final_value_msat) and routing fees
					// for the last node in the RouteHint. We need to just add the fees to
					// route through the current node so that the preceding node (next iteration)
					// can use it.
					let hops_fee = compute_fees(aggregate_next_hops_fee_msat + final_value_msat, hop.fees)
						.map_or(None, |inc| inc.checked_add(aggregate_next_hops_fee_msat));
					aggregate_next_hops_fee_msat = if let Some(val) = hops_fee { val } else { break; };

					let hop_htlc_minimum_msat = candidate.htlc_minimum_msat();
					let hop_htlc_minimum_msat_inc = if let Some(val) = compute_fees(aggregate_next_hops_path_htlc_minimum_msat, hop.fees) { val } else { break; };
					let hops_path_htlc_minimum = aggregate_next_hops_path_htlc_minimum_msat
						.checked_add(hop_htlc_minimum_msat_inc);
					aggregate_next_hops_path_htlc_minimum_msat = if let Some(val) = hops_path_htlc_minimum { cmp::max(hop_htlc_minimum_msat, val) } else { break; };

					if idx == route.0.len() - 1 {
						// The last hop in this iterator is the first hop in
						// overall RouteHint.
						// If this hop connects to a node with which we have a direct channel,
						// ignore the network graph and, if the last hop was added, add our
						// direct channel to the candidate set.
						//
						// Note that we *must* check if the last hop was added as `add_entry`
						// always assumes that the third argument is a node to which we have a
						// path.
						if let Some(first_channels) = first_hop_targets.get(&NodeId::from_pubkey(&hop.src_node_id)) {
							for details in first_channels {
								let candidate = CandidateRouteHop::FirstHop { details };
								add_entry!(candidate, our_node_id,
									NodeId::from_pubkey(&hop.src_node_id),
									aggregate_next_hops_fee_msat, path_value_msat,
									aggregate_next_hops_path_htlc_minimum_msat,
									aggregate_next_hops_path_penalty_msat,
									aggregate_next_hops_cltv_delta,
									aggregate_next_hops_path_length);
							}
						}
					}
				}
			}
		}

		log_trace!(logger, "Starting main path collection loop with {} nodes pre-filled from first/last hops.", targets.len());

		// At this point, targets are filled with the data from first and
		// last hops communicated by the caller, and the payment receiver.
		let mut found_new_path = false;

		// Step (3).
		// If this loop terminates due the exhaustion of targets, two situations are possible:
		// - not enough outgoing liquidity:
		//   0 < already_collected_value_msat < final_value_msat
		// - enough outgoing liquidity:
		//   final_value_msat <= already_collected_value_msat < recommended_value_msat
		// Both these cases (and other cases except reaching recommended_value_msat) mean that
		// paths_collection will be stopped because found_new_path==false.
		// This is not necessarily a routing failure.
		'path_construction: while let Some(RouteGraphNode { node_id, lowest_fee_to_node, total_cltv_delta, value_contribution_msat, path_htlc_minimum_msat, path_penalty_msat, path_length_to_node, .. }) = targets.pop() {

			// Since we're going payee-to-payer, hitting our node as a target means we should stop
			// traversing the graph and arrange the path out of what we found.
			if node_id == our_node_id {
				let mut new_entry = dist.remove(&our_node_id).unwrap();
				let mut ordered_hops: Vec<(PathBuildingHop, NodeFeatures)> = vec!((new_entry.clone(), default_node_features.clone()));

				'path_walk: loop {
					let mut features_set = false;
					if let Some(first_channels) = first_hop_targets.get(&ordered_hops.last().unwrap().0.node_id) {
						for details in first_channels {
							if details.get_outbound_payment_scid().unwrap() == ordered_hops.last().unwrap().0.candidate.short_channel_id() {
								ordered_hops.last_mut().unwrap().1 = details.counterparty.features.to_context();
								features_set = true;
								break;
							}
						}
					}
					if !features_set {
						if let Some(node) = network_nodes.get(&ordered_hops.last().unwrap().0.node_id) {
							if let Some(node_info) = node.announcement_info.as_ref() {
								ordered_hops.last_mut().unwrap().1 = node_info.features.clone();
							} else {
								ordered_hops.last_mut().unwrap().1 = default_node_features.clone();
							}
						} else {
							// We can fill in features for everything except hops which were
							// provided via the invoice we're paying. We could guess based on the
							// recipient's features but for now we simply avoid guessing at all.
						}
					}

					// Means we succesfully traversed from the payer to the payee, now
					// save this path for the payment route. Also, update the liquidity
					// remaining on the used hops, so that we take them into account
					// while looking for more paths.
					if ordered_hops.last().unwrap().0.node_id == payee_node_id {
						break 'path_walk;
					}

					new_entry = match dist.remove(&ordered_hops.last().unwrap().0.node_id) {
						Some(payment_hop) => payment_hop,
						// We can't arrive at None because, if we ever add an entry to targets,
						// we also fill in the entry in dist (see add_entry!).
						None => unreachable!(),
					};
					// We "propagate" the fees one hop backward (topologically) here,
					// so that fees paid for a HTLC forwarding on the current channel are
					// associated with the previous channel (where they will be subtracted).
					ordered_hops.last_mut().unwrap().0.fee_msat = new_entry.hop_use_fee_msat;
					ordered_hops.push((new_entry.clone(), default_node_features.clone()));
				}
				ordered_hops.last_mut().unwrap().0.fee_msat = value_contribution_msat;
				ordered_hops.last_mut().unwrap().0.hop_use_fee_msat = 0;

				log_trace!(logger, "Found a path back to us from the target with {} hops contributing up to {} msat: \n {:#?}",
					ordered_hops.len(), value_contribution_msat, ordered_hops.iter().map(|h| &(h.0)).collect::<Vec<&PathBuildingHop>>());

				let mut payment_path = PaymentPath {hops: ordered_hops};

				// We could have possibly constructed a slightly inconsistent path: since we reduce
				// value being transferred along the way, we could have violated htlc_minimum_msat
				// on some channels we already passed (assuming dest->source direction). Here, we
				// recompute the fees again, so that if that's the case, we match the currently
				// underpaid htlc_minimum_msat with fees.
				payment_path.update_value_and_recompute_fees(cmp::min(value_contribution_msat, final_value_msat));

				// Since a path allows to transfer as much value as
				// the smallest channel it has ("bottleneck"), we should recompute
				// the fees so sender HTLC don't overpay fees when traversing
				// larger channels than the bottleneck. This may happen because
				// when we were selecting those channels we were not aware how much value
				// this path will transfer, and the relative fee for them
				// might have been computed considering a larger value.
				// Remember that we used these channels so that we don't rely
				// on the same liquidity in future paths.
				let mut prevented_redundant_path_selection = false;
				let prev_hop_iter = core::iter::once(&our_node_id)
					.chain(payment_path.hops.iter().map(|(hop, _)| &hop.node_id));
				for (prev_hop, (hop, _)) in prev_hop_iter.zip(payment_path.hops.iter()) {
					let spent_on_hop_msat = value_contribution_msat + hop.next_hops_fee_msat;
					let used_liquidity_msat = used_channel_liquidities
						.entry((hop.candidate.short_channel_id(), *prev_hop < hop.node_id))
						.and_modify(|used_liquidity_msat| *used_liquidity_msat += spent_on_hop_msat)
						.or_insert(spent_on_hop_msat);
					if *used_liquidity_msat == hop.candidate.htlc_maximum_msat() {
						// If this path used all of this channel's available liquidity, we know
						// this path will not be selected again in the next loop iteration.
						prevented_redundant_path_selection = true;
					}
					debug_assert!(*used_liquidity_msat <= hop.candidate.htlc_maximum_msat());
				}
				if !prevented_redundant_path_selection {
					// If we weren't capped by hitting a liquidity limit on a channel in the path,
					// we'll probably end up picking the same path again on the next iteration.
					// Decrease the available liquidity of a hop in the middle of the path.
					let victim_scid = payment_path.hops[(payment_path.hops.len()) / 2].0.candidate.short_channel_id();
					let exhausted = u64::max_value();
					log_trace!(logger, "Disabling channel {} for future path building iterations to avoid duplicates.", victim_scid);
					*used_channel_liquidities.entry((victim_scid, false)).or_default() = exhausted;
					*used_channel_liquidities.entry((victim_scid, true)).or_default() = exhausted;
				}

				// Track the total amount all our collected paths allow to send so that we:
				// - know when to stop looking for more paths
				// - know which of the hops are useless considering how much more sats we need
				//   (contributes_sufficient_value)
				already_collected_value_msat += value_contribution_msat;

				payment_paths.push(payment_path);
				found_new_path = true;
				break 'path_construction;
			}

			// If we found a path back to the payee, we shouldn't try to process it again. This is
			// the equivalent of the `elem.was_processed` check in
			// add_entries_to_cheapest_to_target_node!() (see comment there for more info).
			if node_id == payee_node_id { continue 'path_construction; }

			// Otherwise, since the current target node is not us,
			// keep "unrolling" the payment graph from payee to payer by
			// finding a way to reach the current target from the payer side.
			match network_nodes.get(&node_id) {
				None => {},
				Some(node) => {
					add_entries_to_cheapest_to_target_node!(node, node_id, lowest_fee_to_node,
						value_contribution_msat, path_htlc_minimum_msat, path_penalty_msat,
						total_cltv_delta, path_length_to_node);
				},
			}
		}

		if !allow_mpp {
			// If we don't support MPP, no use trying to gather more value ever.
			break 'paths_collection;
		}

		// Step (4).
		// Stop either when the recommended value is reached or if no new path was found in this
		// iteration.
		// In the latter case, making another path finding attempt won't help,
		// because we deterministically terminated the search due to low liquidity.
		if already_collected_value_msat >= recommended_value_msat || !found_new_path {
			log_trace!(logger, "Have now collected {} msat (seeking {} msat) in paths. Last path loop {} a new path.",
				already_collected_value_msat, recommended_value_msat, if found_new_path { "found" } else { "did not find" });
			break 'paths_collection;
		} else if found_new_path && already_collected_value_msat == final_value_msat && payment_paths.len() == 1 {
			// Further, if this was our first walk of the graph, and we weren't limited by an
			// htlc_minimum_msat, return immediately because this path should suffice. If we were
			// limited by an htlc_minimum_msat value, find another path with a higher value,
			// potentially allowing us to pay fees to meet the htlc_minimum on the new path while
			// still keeping a lower total fee than this path.
			if !hit_minimum_limit {
				log_trace!(logger, "Collected exactly our payment amount on the first pass, without hitting an htlc_minimum_msat limit, exiting.");
				break 'paths_collection;
			}
			log_trace!(logger, "Collected our payment amount on the first pass, but running again to collect extra paths with a potentially higher limit.");
			path_value_msat = recommended_value_msat;
		}
	}

	// Step (5).
	if payment_paths.len() == 0 {
		return Err(LightningError{err: "Failed to find a path to the given destination".to_owned(), action: ErrorAction::IgnoreError});
	}

	if already_collected_value_msat < final_value_msat {
		return Err(LightningError{err: "Failed to find a sufficient route to the given destination".to_owned(), action: ErrorAction::IgnoreError});
	}

	// Sort by total fees and take the best paths.
	payment_paths.sort_unstable_by_key(|path| path.get_total_fee_paid_msat());
	if payment_paths.len() > 50 {
		payment_paths.truncate(50);
	}

	// Draw multiple sufficient routes by randomly combining the selected paths.
	let mut drawn_routes = Vec::new();
	let mut prng = ChaCha20::new(random_seed_bytes, &[0u8; 12]);
	let mut random_index_bytes = [0u8; ::core::mem::size_of::<usize>()];

	let num_permutations = payment_paths.len();
	for _ in 0..num_permutations {
		let mut cur_route = Vec::<PaymentPath>::new();
		let mut aggregate_route_value_msat = 0;

		// Step (6).
		// Do a Fisher-Yates shuffle to create a random permutation of the payment paths
		for cur_index in (1..payment_paths.len()).rev() {
			prng.process_in_place(&mut random_index_bytes);
			let random_index = usize::from_be_bytes(random_index_bytes).wrapping_rem(cur_index+1);
			payment_paths.swap(cur_index, random_index);
		}

		// Step (7).
		for payment_path in &payment_paths {
			cur_route.push(payment_path.clone());
			aggregate_route_value_msat += payment_path.get_value_msat();
			if aggregate_route_value_msat > final_value_msat {
				// Last path likely overpaid. Substract it from the most expensive
				// (in terms of proportional fee) path in this route and recompute fees.
				// This might be not the most economically efficient way, but fewer paths
				// also makes routing more reliable.
				let mut overpaid_value_msat = aggregate_route_value_msat - final_value_msat;

				// First, we drop some expensive low-value paths entirely if possible, since fewer
				// paths is better: the payment is less likely to fail. In order to do so, we sort
				// by value and fall back to total fees paid, i.e., in case of equal values we
				// prefer lower cost paths.
				cur_route.sort_unstable_by(|a, b| {
					a.get_value_msat().cmp(&b.get_value_msat())
						// Reverse ordering for cost, so we drop higher-cost paths first
						.then_with(|| b.get_cost_msat().cmp(&a.get_cost_msat()))
				});

				// We should make sure that at least 1 path left.
				let mut paths_left = cur_route.len();
				cur_route.retain(|path| {
					if paths_left == 1 {
						return true
					}
					let mut keep = true;
					let path_value_msat = path.get_value_msat();
					if path_value_msat <= overpaid_value_msat {
						keep = false;
						overpaid_value_msat -= path_value_msat;
						paths_left -= 1;
					}
					keep
				});

				if overpaid_value_msat == 0 {
					break;
				}

				assert!(cur_route.len() > 0);

				// Step (8).
				// Now, subtract the overpaid value from the most-expensive path.
				// TODO: this could also be optimized by also sorting by feerate_per_sat_routed,
				// so that the sender pays less fees overall. And also htlc_minimum_msat.
				cur_route.sort_unstable_by_key(|path| { path.hops.iter().map(|hop| hop.0.candidate.fees().proportional_millionths as u64).sum::<u64>() });
				let expensive_payment_path = cur_route.first_mut().unwrap();

				// We already dropped all the small value paths above, meaning all the
				// remaining paths are larger than remaining overpaid_value_msat.
				// Thus, this can't be negative.
				let expensive_path_new_value_msat = expensive_payment_path.get_value_msat() - overpaid_value_msat;
				expensive_payment_path.update_value_and_recompute_fees(expensive_path_new_value_msat);
				break;
			}
		}
		drawn_routes.push(cur_route);
	}

	// Step (9).
	// Select the best route by lowest total cost.
	drawn_routes.sort_unstable_by_key(|paths| paths.iter().map(|path| path.get_cost_msat()).sum::<u64>());
	let mut selected_paths = Vec::<Vec<Result<RouteHop, LightningError>>>::new();
	for payment_path in drawn_routes.first().unwrap() {
		let mut path = payment_path.hops.iter().map(|(payment_hop, node_features)| {
			Ok(RouteHop {
				pubkey: PublicKey::from_slice(payment_hop.node_id.as_slice()).map_err(|_| LightningError{err: format!("Public key {:?} is invalid", &payment_hop.node_id), action: ErrorAction::IgnoreAndLog(Level::Trace)})?,
				node_features: node_features.clone(),
				short_channel_id: payment_hop.candidate.short_channel_id(),
				channel_features: payment_hop.candidate.features(),
				fee_msat: payment_hop.fee_msat,
				cltv_expiry_delta: payment_hop.candidate.cltv_expiry_delta(),
			})
		}).collect::<Vec<_>>();
		// Propagate the cltv_expiry_delta one hop backwards since the delta from the current hop is
		// applicable for the previous hop.
		path.iter_mut().rev().fold(final_cltv_expiry_delta, |prev_cltv_expiry_delta, hop| {
			core::mem::replace(&mut hop.as_mut().unwrap().cltv_expiry_delta, prev_cltv_expiry_delta)
		});
		selected_paths.push(path);
	}

	if let Some(features) = &payment_params.features {
		for path in selected_paths.iter_mut() {
			if let Ok(route_hop) = path.last_mut().unwrap() {
				route_hop.node_features = features.to_context();
			}
		}
	}

	let route = Route {
		paths: selected_paths.into_iter().map(|path| path.into_iter().collect()).collect::<Result<Vec<_>, _>>()?,
		payment_params: Some(payment_params.clone()),
	};
	log_info!(logger, "Got route to {}: {}", payment_params.payee_pubkey, log_route!(route));
	Ok(route)
}

// When an adversarial intermediary node observes a payment, it may be able to infer its
// destination, if the remaining CLTV expiry delta exactly matches a feasible path in the network
// graph. In order to improve privacy, this method obfuscates the CLTV expiry deltas along the
// payment path by adding a randomized 'shadow route' offset to the final hop.
fn add_random_cltv_offset(route: &mut Route, payment_params: &PaymentParameters,
	network_graph: &ReadOnlyNetworkGraph, random_seed_bytes: &[u8; 32]
) {
	let network_channels = network_graph.channels();
	let network_nodes = network_graph.nodes();

	for path in route.paths.iter_mut() {
		let mut shadow_ctlv_expiry_delta_offset: u32 = 0;

		// Remember the last three nodes of the random walk and avoid looping back on them.
		// Init with the last three nodes from the actual path, if possible.
		let mut nodes_to_avoid: [NodeId; 3] = [NodeId::from_pubkey(&path.last().unwrap().pubkey),
			NodeId::from_pubkey(&path.get(path.len().saturating_sub(2)).unwrap().pubkey),
			NodeId::from_pubkey(&path.get(path.len().saturating_sub(3)).unwrap().pubkey)];

		// Choose the last publicly known node as the starting point for the random walk.
		let mut cur_hop: Option<NodeId> = None;
		let mut path_nonce = [0u8; 12];
		if let Some(starting_hop) = path.iter().rev()
			.find(|h| network_nodes.contains_key(&NodeId::from_pubkey(&h.pubkey))) {
				cur_hop = Some(NodeId::from_pubkey(&starting_hop.pubkey));
				path_nonce.copy_from_slice(&cur_hop.unwrap().as_slice()[..12]);
		}

		// Init PRNG with the path-dependant nonce, which is static for private paths.
		let mut prng = ChaCha20::new(random_seed_bytes, &path_nonce);
		let mut random_path_bytes = [0u8; ::core::mem::size_of::<usize>()];

		// Pick a random path length in [1 .. 3]
		prng.process_in_place(&mut random_path_bytes);
		let random_walk_length = usize::from_be_bytes(random_path_bytes).wrapping_rem(3).wrapping_add(1);

		for random_hop in 0..random_walk_length {
			// If we don't find a suitable offset in the public network graph, we default to
			// MEDIAN_HOP_CLTV_EXPIRY_DELTA.
			let mut random_hop_offset = MEDIAN_HOP_CLTV_EXPIRY_DELTA;

			if let Some(cur_node_id) = cur_hop {
				if let Some(cur_node) = network_nodes.get(&cur_node_id) {
					// Randomly choose the next unvisited hop.
					prng.process_in_place(&mut random_path_bytes);
					if let Some(random_channel) = usize::from_be_bytes(random_path_bytes)
						.checked_rem(cur_node.channels.len())
						.and_then(|index| cur_node.channels.get(index))
						.and_then(|id| network_channels.get(id)) {
							random_channel.as_directed_from(&cur_node_id).map(|(dir_info, next_id)| {
								if !nodes_to_avoid.iter().any(|x| x == next_id) {
									nodes_to_avoid[random_hop] = *next_id;
									dir_info.direction().map(|channel_update_info| {
										random_hop_offset = channel_update_info.cltv_expiry_delta.into();
										cur_hop = Some(*next_id);
									});
								}
							});
						}
				}
			}

			shadow_ctlv_expiry_delta_offset = shadow_ctlv_expiry_delta_offset
				.checked_add(random_hop_offset)
				.unwrap_or(shadow_ctlv_expiry_delta_offset);
		}

		// Limit the total offset to reduce the worst-case locked liquidity timevalue
		const MAX_SHADOW_CLTV_EXPIRY_DELTA_OFFSET: u32 = 3*144;
		shadow_ctlv_expiry_delta_offset = cmp::min(shadow_ctlv_expiry_delta_offset, MAX_SHADOW_CLTV_EXPIRY_DELTA_OFFSET);

		// Limit the offset so we never exceed the max_total_cltv_expiry_delta. To improve plausibility,
		// we choose the limit to be the largest possible multiple of MEDIAN_HOP_CLTV_EXPIRY_DELTA.
		let path_total_cltv_expiry_delta: u32 = path.iter().map(|h| h.cltv_expiry_delta).sum();
		let mut max_path_offset = payment_params.max_total_cltv_expiry_delta - path_total_cltv_expiry_delta;
		max_path_offset = cmp::max(
			max_path_offset - (max_path_offset % MEDIAN_HOP_CLTV_EXPIRY_DELTA),
			max_path_offset % MEDIAN_HOP_CLTV_EXPIRY_DELTA);
		shadow_ctlv_expiry_delta_offset = cmp::min(shadow_ctlv_expiry_delta_offset, max_path_offset);

		// Add 'shadow' CLTV offset to the final hop
		if let Some(last_hop) = path.last_mut() {
			last_hop.cltv_expiry_delta = last_hop.cltv_expiry_delta
				.checked_add(shadow_ctlv_expiry_delta_offset).unwrap_or(last_hop.cltv_expiry_delta);
		}
	}
}

/// Construct a route from us (payer) to the target node (payee) via the given hops (which should
/// exclude the payer, but include the payee). This may be useful, e.g., for probing the chosen path.
///
/// Re-uses logic from `find_route`, so the restrictions described there also apply here.
pub fn build_route_from_hops<L: Deref>(
	our_node_pubkey: &PublicKey, hops: &[PublicKey], route_params: &RouteParameters, network: &NetworkGraph,
	logger: L, random_seed_bytes: &[u8; 32]
) -> Result<Route, LightningError>
where L::Target: Logger {
	let network_graph = network.read_only();
	let mut route = build_route_from_hops_internal(
		our_node_pubkey, hops, &route_params.payment_params, &network_graph,
		route_params.final_value_msat, route_params.final_cltv_expiry_delta, logger, random_seed_bytes)?;
	add_random_cltv_offset(&mut route, &route_params.payment_params, &network_graph, random_seed_bytes);
	Ok(route)
}

fn build_route_from_hops_internal<L: Deref>(
	our_node_pubkey: &PublicKey, hops: &[PublicKey], payment_params: &PaymentParameters,
	network_graph: &ReadOnlyNetworkGraph, final_value_msat: u64, final_cltv_expiry_delta: u32,
	logger: L, random_seed_bytes: &[u8; 32]
) -> Result<Route, LightningError> where L::Target: Logger {

	struct HopScorer {
		our_node_id: NodeId,
		hop_ids: [Option<NodeId>; MAX_PATH_LENGTH_ESTIMATE as usize],
	}

	impl Score for HopScorer {
		fn channel_penalty_msat(&self, _short_channel_id: u64, source: &NodeId, target: &NodeId,
			_usage: ChannelUsage) -> u64
		{
			let mut cur_id = self.our_node_id;
			for i in 0..self.hop_ids.len() {
				if let Some(next_id) = self.hop_ids[i] {
					if cur_id == *source && next_id == *target {
						return 0;
					}
					cur_id = next_id;
				} else {
					break;
				}
			}
			u64::max_value()
		}

		fn payment_path_failed(&mut self, _path: &[&RouteHop], _short_channel_id: u64) {}

		fn payment_path_successful(&mut self, _path: &[&RouteHop]) {}
	}

	impl<'a> Writeable for HopScorer {
		#[inline]
		fn write<W: Writer>(&self, _w: &mut W) -> Result<(), io::Error> {
			unreachable!();
		}
	}

	if hops.len() > MAX_PATH_LENGTH_ESTIMATE.into() {
		return Err(LightningError{err: "Cannot build a route exceeding the maximum path length.".to_owned(), action: ErrorAction::IgnoreError});
	}

	let our_node_id = NodeId::from_pubkey(our_node_pubkey);
	let mut hop_ids = [None; MAX_PATH_LENGTH_ESTIMATE as usize];
	for i in 0..hops.len() {
		hop_ids[i] = Some(NodeId::from_pubkey(&hops[i]));
	}

	let scorer = HopScorer { our_node_id, hop_ids };

	get_route(our_node_pubkey, payment_params, network_graph, None, final_value_msat,
		final_cltv_expiry_delta, logger, &scorer, random_seed_bytes)
}

#[cfg(test)]
mod tests {
	use routing::network_graph::{NetworkGraph, NetGraphMsgHandler, NodeId};
	use routing::router::{get_route, build_route_from_hops_internal, add_random_cltv_offset, default_node_features,
		PaymentParameters, Route, RouteHint, RouteHintHop, RouteHop, RoutingFees,
		DEFAULT_MAX_TOTAL_CLTV_EXPIRY_DELTA, MAX_PATH_LENGTH_ESTIMATE};
	use routing::scoring::{ChannelUsage, Score};
	use chain::transaction::OutPoint;
	use chain::keysinterface::KeysInterface;
	use ln::features::{ChannelFeatures, InitFeatures, InvoiceFeatures, NodeFeatures};
	use ln::msgs::{ErrorAction, LightningError, OptionalField, UnsignedChannelAnnouncement, ChannelAnnouncement, RoutingMessageHandler,
		NodeAnnouncement, UnsignedNodeAnnouncement, ChannelUpdate, UnsignedChannelUpdate};
	use ln::channelmanager;
	use util::test_utils;
	use util::chacha20::ChaCha20;
	use util::ser::Writeable;
	#[cfg(c_bindings)]
	use util::ser::Writer;

	use bitcoin::hashes::sha256d::Hash as Sha256dHash;
	use bitcoin::hashes::Hash;
	use bitcoin::network::constants::Network;
	use bitcoin::blockdata::constants::genesis_block;
	use bitcoin::blockdata::script::Builder;
	use bitcoin::blockdata::opcodes;
	use bitcoin::blockdata::transaction::TxOut;

	use hex;

	use bitcoin::secp256k1::{PublicKey,SecretKey};
	use bitcoin::secp256k1::{Secp256k1, All};

	use prelude::*;
	use sync::{self, Arc};

	fn get_channel_details(short_channel_id: Option<u64>, node_id: PublicKey,
			features: InitFeatures, outbound_capacity_msat: u64) -> channelmanager::ChannelDetails {
		channelmanager::ChannelDetails {
			channel_id: [0; 32],
			counterparty: channelmanager::ChannelCounterparty {
				features,
				node_id,
				unspendable_punishment_reserve: 0,
				forwarding_info: None,
				outbound_htlc_minimum_msat: None,
				outbound_htlc_maximum_msat: None,
			},
			funding_txo: Some(OutPoint { txid: bitcoin::Txid::from_slice(&[0; 32]).unwrap(), index: 0 }),
			channel_type: None,
			short_channel_id,
			outbound_scid_alias: None,
			inbound_scid_alias: None,
			channel_value_satoshis: 0,
			user_channel_id: 0,
			balance_msat: 0,
			outbound_capacity_msat,
			next_outbound_htlc_limit_msat: outbound_capacity_msat,
			inbound_capacity_msat: 42,
			unspendable_punishment_reserve: None,
			confirmations_required: None,
			force_close_spend_delay: None,
			is_outbound: true, is_channel_ready: true,
			is_usable: true, is_public: true,
			inbound_htlc_minimum_msat: None,
			inbound_htlc_maximum_msat: None,
		}
	}

	// Using the same keys for LN and BTC ids
	fn add_channel(
		net_graph_msg_handler: &NetGraphMsgHandler<Arc<NetworkGraph>, Arc<test_utils::TestChainSource>, Arc<test_utils::TestLogger>>,
		secp_ctx: &Secp256k1<All>, node_1_privkey: &SecretKey, node_2_privkey: &SecretKey, features: ChannelFeatures, short_channel_id: u64
	) {
		let node_id_1 = PublicKey::from_secret_key(&secp_ctx, node_1_privkey);
		let node_id_2 = PublicKey::from_secret_key(&secp_ctx, node_2_privkey);

		let unsigned_announcement = UnsignedChannelAnnouncement {
			features,
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id,
			node_id_1,
			node_id_2,
			bitcoin_key_1: node_id_1,
			bitcoin_key_2: node_id_2,
			excess_data: Vec::new(),
		};

		let msghash = hash_to_message!(&Sha256dHash::hash(&unsigned_announcement.encode()[..])[..]);
		let valid_announcement = ChannelAnnouncement {
			node_signature_1: secp_ctx.sign_ecdsa(&msghash, node_1_privkey),
			node_signature_2: secp_ctx.sign_ecdsa(&msghash, node_2_privkey),
			bitcoin_signature_1: secp_ctx.sign_ecdsa(&msghash, node_1_privkey),
			bitcoin_signature_2: secp_ctx.sign_ecdsa(&msghash, node_2_privkey),
			contents: unsigned_announcement.clone(),
		};
		match net_graph_msg_handler.handle_channel_announcement(&valid_announcement) {
			Ok(res) => assert!(res),
			_ => panic!()
		};
	}

	fn update_channel(
		net_graph_msg_handler: &NetGraphMsgHandler<Arc<NetworkGraph>, Arc<test_utils::TestChainSource>, Arc<test_utils::TestLogger>>,
		secp_ctx: &Secp256k1<All>, node_privkey: &SecretKey, update: UnsignedChannelUpdate
	) {
		let msghash = hash_to_message!(&Sha256dHash::hash(&update.encode()[..])[..]);
		let valid_channel_update = ChannelUpdate {
			signature: secp_ctx.sign_ecdsa(&msghash, node_privkey),
			contents: update.clone()
		};

		match net_graph_msg_handler.handle_channel_update(&valid_channel_update) {
			Ok(res) => assert!(res),
			Err(_) => panic!()
		};
	}

	fn add_or_update_node(
		net_graph_msg_handler: &NetGraphMsgHandler<Arc<NetworkGraph>, Arc<test_utils::TestChainSource>, Arc<test_utils::TestLogger>>,
		secp_ctx: &Secp256k1<All>, node_privkey: &SecretKey, features: NodeFeatures, timestamp: u32
	) {
		let node_id = PublicKey::from_secret_key(&secp_ctx, node_privkey);
		let unsigned_announcement = UnsignedNodeAnnouncement {
			features,
			timestamp,
			node_id,
			rgb: [0; 3],
			alias: [0; 32],
			addresses: Vec::new(),
			excess_address_data: Vec::new(),
			excess_data: Vec::new(),
		};
		let msghash = hash_to_message!(&Sha256dHash::hash(&unsigned_announcement.encode()[..])[..]);
		let valid_announcement = NodeAnnouncement {
			signature: secp_ctx.sign_ecdsa(&msghash, node_privkey),
			contents: unsigned_announcement.clone()
		};

		match net_graph_msg_handler.handle_node_announcement(&valid_announcement) {
			Ok(_) => (),
			Err(_) => panic!()
		};
	}

	fn get_nodes(secp_ctx: &Secp256k1<All>) -> (SecretKey, PublicKey, Vec<SecretKey>, Vec<PublicKey>) {
		let privkeys: Vec<SecretKey> = (2..22).map(|i| {
			SecretKey::from_slice(&hex::decode(format!("{:02x}", i).repeat(32)).unwrap()[..]).unwrap()
		}).collect();

		let pubkeys = privkeys.iter().map(|secret| PublicKey::from_secret_key(&secp_ctx, secret)).collect();

		let our_privkey = SecretKey::from_slice(&hex::decode("01".repeat(32)).unwrap()[..]).unwrap();
		let our_id = PublicKey::from_secret_key(&secp_ctx, &our_privkey);

		(our_privkey, our_id, privkeys, pubkeys)
	}

	fn id_to_feature_flags(id: u8) -> Vec<u8> {
		// Set the feature flags to the id'th odd (ie non-required) feature bit so that we can
		// test for it later.
		let idx = (id - 1) * 2 + 1;
		if idx > 8*3 {
			vec![1 << (idx - 8*3), 0, 0, 0]
		} else if idx > 8*2 {
			vec![1 << (idx - 8*2), 0, 0]
		} else if idx > 8*1 {
			vec![1 << (idx - 8*1), 0]
		} else {
			vec![1 << idx]
		}
	}

	fn build_line_graph() -> (
		Secp256k1<All>, sync::Arc<NetworkGraph>, NetGraphMsgHandler<sync::Arc<NetworkGraph>,
		sync::Arc<test_utils::TestChainSource>, sync::Arc<crate::util::test_utils::TestLogger>>,
		sync::Arc<test_utils::TestChainSource>, sync::Arc<test_utils::TestLogger>,
	) {
		let secp_ctx = Secp256k1::new();
		let logger = Arc::new(test_utils::TestLogger::new());
		let chain_monitor = Arc::new(test_utils::TestChainSource::new(Network::Testnet));
		let network_graph = Arc::new(NetworkGraph::new(genesis_block(Network::Testnet).header.block_hash()));
		let net_graph_msg_handler = NetGraphMsgHandler::new(Arc::clone(&network_graph), None, Arc::clone(&logger));

		// Build network from our_id to node 19:
		// our_id -1(1)2- node0 -1(2)2- node1 - ... - node19
		let (our_privkey, _, privkeys, _) = get_nodes(&secp_ctx);

		for (idx, (cur_privkey, next_privkey)) in core::iter::once(&our_privkey)
			.chain(privkeys.iter()).zip(privkeys.iter()).enumerate() {
			let cur_short_channel_id = (idx as u64) + 1;
			add_channel(&net_graph_msg_handler, &secp_ctx, &cur_privkey, &next_privkey,
				ChannelFeatures::from_le_bytes(id_to_feature_flags(1)), cur_short_channel_id);
			update_channel(&net_graph_msg_handler, &secp_ctx, &cur_privkey, UnsignedChannelUpdate {
				chain_hash: genesis_block(Network::Testnet).header.block_hash(),
				short_channel_id: cur_short_channel_id,
				timestamp: idx as u32,
				flags: 0,
				cltv_expiry_delta: 0,
				htlc_minimum_msat: 0,
				htlc_maximum_msat: OptionalField::Absent,
				fee_base_msat: 0,
				fee_proportional_millionths: 0,
				excess_data: Vec::new()
			});
			update_channel(&net_graph_msg_handler, &secp_ctx, &next_privkey, UnsignedChannelUpdate {
				chain_hash: genesis_block(Network::Testnet).header.block_hash(),
				short_channel_id: cur_short_channel_id,
				timestamp: (idx as u32)+1,
				flags: 1,
				cltv_expiry_delta: 0,
				htlc_minimum_msat: 0,
				htlc_maximum_msat: OptionalField::Absent,
				fee_base_msat: 0,
				fee_proportional_millionths: 0,
				excess_data: Vec::new()
			});
			add_or_update_node(&net_graph_msg_handler, &secp_ctx, next_privkey,
				NodeFeatures::from_le_bytes(id_to_feature_flags(1)), 0);
		}

		(secp_ctx, network_graph, net_graph_msg_handler, chain_monitor, logger)
	}

	fn build_graph() -> (
		Secp256k1<All>,
		sync::Arc<NetworkGraph>,
		NetGraphMsgHandler<sync::Arc<NetworkGraph>, sync::Arc<test_utils::TestChainSource>, sync::Arc<crate::util::test_utils::TestLogger>>,
		sync::Arc<test_utils::TestChainSource>,
		sync::Arc<test_utils::TestLogger>,
	) {
		let secp_ctx = Secp256k1::new();
		let logger = Arc::new(test_utils::TestLogger::new());
		let chain_monitor = Arc::new(test_utils::TestChainSource::new(Network::Testnet));
		let network_graph = Arc::new(NetworkGraph::new(genesis_block(Network::Testnet).header.block_hash()));
		let net_graph_msg_handler = NetGraphMsgHandler::new(Arc::clone(&network_graph), None, Arc::clone(&logger));
		// Build network from our_id to node6:
		//
		//        -1(1)2-  node0  -1(3)2-
		//       /                       \
		// our_id -1(12)2- node7 -1(13)2--- node2
		//       \                       /
		//        -1(2)2-  node1  -1(4)2-
		//
		//
		// chan1  1-to-2: disabled
		// chan1  2-to-1: enabled, 0 fee
		//
		// chan2  1-to-2: enabled, ignored fee
		// chan2  2-to-1: enabled, 0 fee
		//
		// chan3  1-to-2: enabled, 0 fee
		// chan3  2-to-1: enabled, 100 msat fee
		//
		// chan4  1-to-2: enabled, 100% fee
		// chan4  2-to-1: enabled, 0 fee
		//
		// chan12 1-to-2: enabled, ignored fee
		// chan12 2-to-1: enabled, 0 fee
		//
		// chan13 1-to-2: enabled, 200% fee
		// chan13 2-to-1: enabled, 0 fee
		//
		//
		//       -1(5)2- node3 -1(8)2--
		//       |         2          |
		//       |       (11)         |
		//      /          1           \
		// node2--1(6)2- node4 -1(9)2--- node6 (not in global route map)
		//      \                      /
		//       -1(7)2- node5 -1(10)2-
		//
		// Channels 5, 8, 9 and 10 are private channels.
		//
		// chan5  1-to-2: enabled, 100 msat fee
		// chan5  2-to-1: enabled, 0 fee
		//
		// chan6  1-to-2: enabled, 0 fee
		// chan6  2-to-1: enabled, 0 fee
		//
		// chan7  1-to-2: enabled, 100% fee
		// chan7  2-to-1: enabled, 0 fee
		//
		// chan8  1-to-2: enabled, variable fee (0 then 1000 msat)
		// chan8  2-to-1: enabled, 0 fee
		//
		// chan9  1-to-2: enabled, 1001 msat fee
		// chan9  2-to-1: enabled, 0 fee
		//
		// chan10 1-to-2: enabled, 0 fee
		// chan10 2-to-1: enabled, 0 fee
		//
		// chan11 1-to-2: enabled, 0 fee
		// chan11 2-to-1: enabled, 0 fee

		let (our_privkey, _, privkeys, _) = get_nodes(&secp_ctx);

		add_channel(&net_graph_msg_handler, &secp_ctx, &our_privkey, &privkeys[0], ChannelFeatures::from_le_bytes(id_to_feature_flags(1)), 1);
		update_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[0], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 1,
			timestamp: 1,
			flags: 1,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Absent,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		add_or_update_node(&net_graph_msg_handler, &secp_ctx, &privkeys[0], NodeFeatures::from_le_bytes(id_to_feature_flags(1)), 0);

		add_channel(&net_graph_msg_handler, &secp_ctx, &our_privkey, &privkeys[1], ChannelFeatures::from_le_bytes(id_to_feature_flags(2)), 2);
		update_channel(&net_graph_msg_handler, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 2,
			timestamp: 1,
			flags: 0,
			cltv_expiry_delta: (5 << 4) | 3,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Absent,
			fee_base_msat: u32::max_value(),
			fee_proportional_millionths: u32::max_value(),
			excess_data: Vec::new()
		});
		update_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[1], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 2,
			timestamp: 1,
			flags: 1,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Absent,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		add_or_update_node(&net_graph_msg_handler, &secp_ctx, &privkeys[1], NodeFeatures::from_le_bytes(id_to_feature_flags(2)), 0);

		add_channel(&net_graph_msg_handler, &secp_ctx, &our_privkey, &privkeys[7], ChannelFeatures::from_le_bytes(id_to_feature_flags(12)), 12);
		update_channel(&net_graph_msg_handler, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 12,
			timestamp: 1,
			flags: 0,
			cltv_expiry_delta: (5 << 4) | 3,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Absent,
			fee_base_msat: u32::max_value(),
			fee_proportional_millionths: u32::max_value(),
			excess_data: Vec::new()
		});
		update_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[7], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 12,
			timestamp: 1,
			flags: 1,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Absent,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		add_or_update_node(&net_graph_msg_handler, &secp_ctx, &privkeys[7], NodeFeatures::from_le_bytes(id_to_feature_flags(8)), 0);

		add_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[0], &privkeys[2], ChannelFeatures::from_le_bytes(id_to_feature_flags(3)), 3);
		update_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[0], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 3,
			timestamp: 1,
			flags: 0,
			cltv_expiry_delta: (3 << 4) | 1,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Absent,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 3,
			timestamp: 1,
			flags: 1,
			cltv_expiry_delta: (3 << 4) | 2,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Absent,
			fee_base_msat: 100,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		add_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[1], &privkeys[2], ChannelFeatures::from_le_bytes(id_to_feature_flags(4)), 4);
		update_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[1], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 4,
			timestamp: 1,
			flags: 0,
			cltv_expiry_delta: (4 << 4) | 1,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Absent,
			fee_base_msat: 0,
			fee_proportional_millionths: 1000000,
			excess_data: Vec::new()
		});
		update_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 4,
			timestamp: 1,
			flags: 1,
			cltv_expiry_delta: (4 << 4) | 2,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Absent,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		add_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[7], &privkeys[2], ChannelFeatures::from_le_bytes(id_to_feature_flags(13)), 13);
		update_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[7], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 13,
			timestamp: 1,
			flags: 0,
			cltv_expiry_delta: (13 << 4) | 1,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Absent,
			fee_base_msat: 0,
			fee_proportional_millionths: 2000000,
			excess_data: Vec::new()
		});
		update_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 13,
			timestamp: 1,
			flags: 1,
			cltv_expiry_delta: (13 << 4) | 2,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Absent,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		add_or_update_node(&net_graph_msg_handler, &secp_ctx, &privkeys[2], NodeFeatures::from_le_bytes(id_to_feature_flags(3)), 0);

		add_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[2], &privkeys[4], ChannelFeatures::from_le_bytes(id_to_feature_flags(6)), 6);
		update_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 6,
			timestamp: 1,
			flags: 0,
			cltv_expiry_delta: (6 << 4) | 1,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Absent,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[4], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 6,
			timestamp: 1,
			flags: 1,
			cltv_expiry_delta: (6 << 4) | 2,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Absent,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new(),
		});

		add_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[4], &privkeys[3], ChannelFeatures::from_le_bytes(id_to_feature_flags(11)), 11);
		update_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[4], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 11,
			timestamp: 1,
			flags: 0,
			cltv_expiry_delta: (11 << 4) | 1,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Absent,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[3], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 11,
			timestamp: 1,
			flags: 1,
			cltv_expiry_delta: (11 << 4) | 2,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Absent,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		add_or_update_node(&net_graph_msg_handler, &secp_ctx, &privkeys[4], NodeFeatures::from_le_bytes(id_to_feature_flags(5)), 0);

		add_or_update_node(&net_graph_msg_handler, &secp_ctx, &privkeys[3], NodeFeatures::from_le_bytes(id_to_feature_flags(4)), 0);

		add_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[2], &privkeys[5], ChannelFeatures::from_le_bytes(id_to_feature_flags(7)), 7);
		update_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 7,
			timestamp: 1,
			flags: 0,
			cltv_expiry_delta: (7 << 4) | 1,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Absent,
			fee_base_msat: 0,
			fee_proportional_millionths: 1000000,
			excess_data: Vec::new()
		});
		update_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[5], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 7,
			timestamp: 1,
			flags: 1,
			cltv_expiry_delta: (7 << 4) | 2,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Absent,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		add_or_update_node(&net_graph_msg_handler, &secp_ctx, &privkeys[5], NodeFeatures::from_le_bytes(id_to_feature_flags(6)), 0);

		(secp_ctx, network_graph, net_graph_msg_handler, chain_monitor, logger)
	}

	#[test]
	fn simple_route_test() {
		let (secp_ctx, network_graph, _, _, logger) = build_graph();
		let (_, our_id, _, nodes) = get_nodes(&secp_ctx);
		let payment_params = PaymentParameters::from_node_id(nodes[2]);
		let scorer = test_utils::TestScorer::with_penalty(0);
		let keys_manager = test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();

		// Simple route to 2 via 1

		if let Err(LightningError{err, action: ErrorAction::IgnoreError}) = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 0, 42, Arc::clone(&logger), &scorer, &random_seed_bytes) {
			assert_eq!(err, "Cannot send a payment of 0 msat");
		} else { panic!(); }

		let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 100, 42, Arc::clone(&logger), &scorer, &random_seed_bytes).unwrap();
		assert_eq!(route.paths[0].len(), 2);

		assert_eq!(route.paths[0][0].pubkey, nodes[1]);
		assert_eq!(route.paths[0][0].short_channel_id, 2);
		assert_eq!(route.paths[0][0].fee_msat, 100);
		assert_eq!(route.paths[0][0].cltv_expiry_delta, (4 << 4) | 1);
		assert_eq!(route.paths[0][0].node_features.le_flags(), &id_to_feature_flags(2));
		assert_eq!(route.paths[0][0].channel_features.le_flags(), &id_to_feature_flags(2));

		assert_eq!(route.paths[0][1].pubkey, nodes[2]);
		assert_eq!(route.paths[0][1].short_channel_id, 4);
		assert_eq!(route.paths[0][1].fee_msat, 100);
		assert_eq!(route.paths[0][1].cltv_expiry_delta, 42);
		assert_eq!(route.paths[0][1].node_features.le_flags(), &id_to_feature_flags(3));
		assert_eq!(route.paths[0][1].channel_features.le_flags(), &id_to_feature_flags(4));
	}

	#[test]
	fn invalid_first_hop_test() {
		let (secp_ctx, network_graph, _, _, logger) = build_graph();
		let (_, our_id, _, nodes) = get_nodes(&secp_ctx);
		let payment_params = PaymentParameters::from_node_id(nodes[2]);
		let scorer = test_utils::TestScorer::with_penalty(0);
		let keys_manager = test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();

		// Simple route to 2 via 1

		let our_chans = vec![get_channel_details(Some(2), our_id, InitFeatures::from_le_bytes(vec![0b11]), 100000)];

		if let Err(LightningError{err, action: ErrorAction::IgnoreError}) =
			get_route(&our_id, &payment_params, &network_graph.read_only(), Some(&our_chans.iter().collect::<Vec<_>>()), 100, 42, Arc::clone(&logger), &scorer, &random_seed_bytes) {
			assert_eq!(err, "First hop cannot have our_node_pubkey as a destination.");
		} else { panic!(); }

		let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 100, 42, Arc::clone(&logger), &scorer, &random_seed_bytes).unwrap();
		assert_eq!(route.paths[0].len(), 2);
	}

	#[test]
	fn htlc_minimum_test() {
		let (secp_ctx, network_graph, net_graph_msg_handler, _, logger) = build_graph();
		let (our_privkey, our_id, privkeys, nodes) = get_nodes(&secp_ctx);
		let payment_params = PaymentParameters::from_node_id(nodes[2]);
		let scorer = test_utils::TestScorer::with_penalty(0);
		let keys_manager = test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();

		// Simple route to 2 via 1

		// Disable other paths
		update_channel(&net_graph_msg_handler, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 12,
			timestamp: 2,
			flags: 2, // to disable
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Absent,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[0], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 3,
			timestamp: 2,
			flags: 2, // to disable
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Absent,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[7], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 13,
			timestamp: 2,
			flags: 2, // to disable
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Absent,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 6,
			timestamp: 2,
			flags: 2, // to disable
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Absent,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 7,
			timestamp: 2,
			flags: 2, // to disable
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Absent,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		// Check against amount_to_transfer_over_msat.
		// Set minimal HTLC of 200_000_000 msat.
		update_channel(&net_graph_msg_handler, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 2,
			timestamp: 3,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 200_000_000,
			htlc_maximum_msat: OptionalField::Absent,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		// Second hop only allows to forward 199_999_999 at most, thus not allowing the first hop to
		// be used.
		update_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[1], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 4,
			timestamp: 3,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Present(199_999_999),
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		// Not possible to send 199_999_999, because the minimum on channel=2 is 200_000_000.
		if let Err(LightningError{err, action: ErrorAction::IgnoreError}) = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 199_999_999, 42, Arc::clone(&logger), &scorer, &random_seed_bytes) {
			assert_eq!(err, "Failed to find a path to the given destination");
		} else { panic!(); }

		// Lift the restriction on the first hop.
		update_channel(&net_graph_msg_handler, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 2,
			timestamp: 4,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Absent,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		// A payment above the minimum should pass
		let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 199_999_999, 42, Arc::clone(&logger), &scorer, &random_seed_bytes).unwrap();
		assert_eq!(route.paths[0].len(), 2);
	}

	#[test]
	fn htlc_minimum_overpay_test() {
		let (secp_ctx, network_graph, net_graph_msg_handler, _, logger) = build_graph();
		let (our_privkey, our_id, privkeys, nodes) = get_nodes(&secp_ctx);
		let payment_params = PaymentParameters::from_node_id(nodes[2]).with_features(InvoiceFeatures::known());
		let scorer = test_utils::TestScorer::with_penalty(0);
		let keys_manager = test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();

		// A route to node#2 via two paths.
		// One path allows transferring 35-40 sats, another one also allows 35-40 sats.
		// Thus, they can't send 60 without overpaying.
		update_channel(&net_graph_msg_handler, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 2,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 35_000,
			htlc_maximum_msat: OptionalField::Present(40_000),
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&net_graph_msg_handler, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 12,
			timestamp: 3,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 35_000,
			htlc_maximum_msat: OptionalField::Present(40_000),
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		// Make 0 fee.
		update_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[7], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 13,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Absent,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[1], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 4,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Absent,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		// Disable other paths
		update_channel(&net_graph_msg_handler, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 1,
			timestamp: 3,
			flags: 2, // to disable
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Absent,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 60_000, 42, Arc::clone(&logger), &scorer, &random_seed_bytes).unwrap();
		// Overpay fees to hit htlc_minimum_msat.
		let overpaid_fees = route.paths[0][0].fee_msat + route.paths[1][0].fee_msat;
		// TODO: this could be better balanced to overpay 10k and not 15k.
		assert_eq!(overpaid_fees, 15_000);

		// Now, test that if there are 2 paths, a "cheaper" by fee path wouldn't be prioritized
		// while taking even more fee to match htlc_minimum_msat.
		update_channel(&net_graph_msg_handler, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 12,
			timestamp: 4,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 65_000,
			htlc_maximum_msat: OptionalField::Present(80_000),
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&net_graph_msg_handler, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 2,
			timestamp: 3,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Absent,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[1], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 4,
			timestamp: 4,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Absent,
			fee_base_msat: 0,
			fee_proportional_millionths: 100_000,
			excess_data: Vec::new()
		});

		let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 60_000, 42, Arc::clone(&logger), &scorer, &random_seed_bytes).unwrap();
		// Fine to overpay for htlc_minimum_msat if it allows us to save fee.
		assert_eq!(route.paths.len(), 1);
		assert_eq!(route.paths[0][0].short_channel_id, 12);
		let fees = route.paths[0][0].fee_msat;
		assert_eq!(fees, 5_000);

		let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 50_000, 42, Arc::clone(&logger), &scorer, &random_seed_bytes).unwrap();
		// Not fine to overpay for htlc_minimum_msat if it requires paying more than fee on
		// the other channel.
		assert_eq!(route.paths.len(), 1);
		assert_eq!(route.paths[0][0].short_channel_id, 2);
		let fees = route.paths[0][0].fee_msat;
		assert_eq!(fees, 5_000);
	}

	#[test]
	fn disable_channels_test() {
		let (secp_ctx, network_graph, net_graph_msg_handler, _, logger) = build_graph();
		let (our_privkey, our_id, privkeys, nodes) = get_nodes(&secp_ctx);
		let payment_params = PaymentParameters::from_node_id(nodes[2]);
		let scorer = test_utils::TestScorer::with_penalty(0);
		let keys_manager = test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();

		// // Disable channels 4 and 12 by flags=2
		update_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[1], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 4,
			timestamp: 2,
			flags: 2, // to disable
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Absent,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&net_graph_msg_handler, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 12,
			timestamp: 2,
			flags: 2, // to disable
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Absent,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		// If all the channels require some features we don't understand, route should fail
		if let Err(LightningError{err, action: ErrorAction::IgnoreError}) = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 100, 42, Arc::clone(&logger), &scorer, &random_seed_bytes) {
			assert_eq!(err, "Failed to find a path to the given destination");
		} else { panic!(); }

		// If we specify a channel to node7, that overrides our local channel view and that gets used
		let our_chans = vec![get_channel_details(Some(42), nodes[7].clone(), InitFeatures::from_le_bytes(vec![0b11]), 250_000_000)];
		let route = get_route(&our_id, &payment_params, &network_graph.read_only(), Some(&our_chans.iter().collect::<Vec<_>>()), 100, 42, Arc::clone(&logger), &scorer, &random_seed_bytes).unwrap();
		assert_eq!(route.paths[0].len(), 2);

		assert_eq!(route.paths[0][0].pubkey, nodes[7]);
		assert_eq!(route.paths[0][0].short_channel_id, 42);
		assert_eq!(route.paths[0][0].fee_msat, 200);
		assert_eq!(route.paths[0][0].cltv_expiry_delta, (13 << 4) | 1);
		assert_eq!(route.paths[0][0].node_features.le_flags(), &vec![0b11]); // it should also override our view of their features
		assert_eq!(route.paths[0][0].channel_features.le_flags(), &Vec::<u8>::new()); // No feature flags will meet the relevant-to-channel conversion

		assert_eq!(route.paths[0][1].pubkey, nodes[2]);
		assert_eq!(route.paths[0][1].short_channel_id, 13);
		assert_eq!(route.paths[0][1].fee_msat, 100);
		assert_eq!(route.paths[0][1].cltv_expiry_delta, 42);
		assert_eq!(route.paths[0][1].node_features.le_flags(), &id_to_feature_flags(3));
		assert_eq!(route.paths[0][1].channel_features.le_flags(), &id_to_feature_flags(13));
	}

	#[test]
	fn disable_node_test() {
		let (secp_ctx, network_graph, net_graph_msg_handler, _, logger) = build_graph();
		let (_, our_id, privkeys, nodes) = get_nodes(&secp_ctx);
		let payment_params = PaymentParameters::from_node_id(nodes[2]);
		let scorer = test_utils::TestScorer::with_penalty(0);
		let keys_manager = test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();

		// Disable nodes 1, 2, and 8 by requiring unknown feature bits
		let mut unknown_features = NodeFeatures::known();
		unknown_features.set_unknown_feature_required();
		add_or_update_node(&net_graph_msg_handler, &secp_ctx, &privkeys[0], unknown_features.clone(), 1);
		add_or_update_node(&net_graph_msg_handler, &secp_ctx, &privkeys[1], unknown_features.clone(), 1);
		add_or_update_node(&net_graph_msg_handler, &secp_ctx, &privkeys[7], unknown_features.clone(), 1);

		// If all nodes require some features we don't understand, route should fail
		if let Err(LightningError{err, action: ErrorAction::IgnoreError}) = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 100, 42, Arc::clone(&logger), &scorer, &random_seed_bytes) {
			assert_eq!(err, "Failed to find a path to the given destination");
		} else { panic!(); }

		// If we specify a channel to node7, that overrides our local channel view and that gets used
		let our_chans = vec![get_channel_details(Some(42), nodes[7].clone(), InitFeatures::from_le_bytes(vec![0b11]), 250_000_000)];
		let route = get_route(&our_id, &payment_params, &network_graph.read_only(), Some(&our_chans.iter().collect::<Vec<_>>()), 100, 42, Arc::clone(&logger), &scorer, &random_seed_bytes).unwrap();
		assert_eq!(route.paths[0].len(), 2);

		assert_eq!(route.paths[0][0].pubkey, nodes[7]);
		assert_eq!(route.paths[0][0].short_channel_id, 42);
		assert_eq!(route.paths[0][0].fee_msat, 200);
		assert_eq!(route.paths[0][0].cltv_expiry_delta, (13 << 4) | 1);
		assert_eq!(route.paths[0][0].node_features.le_flags(), &vec![0b11]); // it should also override our view of their features
		assert_eq!(route.paths[0][0].channel_features.le_flags(), &Vec::<u8>::new()); // No feature flags will meet the relevant-to-channel conversion

		assert_eq!(route.paths[0][1].pubkey, nodes[2]);
		assert_eq!(route.paths[0][1].short_channel_id, 13);
		assert_eq!(route.paths[0][1].fee_msat, 100);
		assert_eq!(route.paths[0][1].cltv_expiry_delta, 42);
		assert_eq!(route.paths[0][1].node_features.le_flags(), &id_to_feature_flags(3));
		assert_eq!(route.paths[0][1].channel_features.le_flags(), &id_to_feature_flags(13));

		// Note that we don't test disabling node 3 and failing to route to it, as we (somewhat
		// naively) assume that the user checked the feature bits on the invoice, which override
		// the node_announcement.
	}

	#[test]
	fn our_chans_test() {
		let (secp_ctx, network_graph, _, _, logger) = build_graph();
		let (_, our_id, _, nodes) = get_nodes(&secp_ctx);
		let scorer = test_utils::TestScorer::with_penalty(0);
		let keys_manager = test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();

		// Route to 1 via 2 and 3 because our channel to 1 is disabled
		let payment_params = PaymentParameters::from_node_id(nodes[0]);
		let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 100, 42, Arc::clone(&logger), &scorer, &random_seed_bytes).unwrap();
		assert_eq!(route.paths[0].len(), 3);

		assert_eq!(route.paths[0][0].pubkey, nodes[1]);
		assert_eq!(route.paths[0][0].short_channel_id, 2);
		assert_eq!(route.paths[0][0].fee_msat, 200);
		assert_eq!(route.paths[0][0].cltv_expiry_delta, (4 << 4) | 1);
		assert_eq!(route.paths[0][0].node_features.le_flags(), &id_to_feature_flags(2));
		assert_eq!(route.paths[0][0].channel_features.le_flags(), &id_to_feature_flags(2));

		assert_eq!(route.paths[0][1].pubkey, nodes[2]);
		assert_eq!(route.paths[0][1].short_channel_id, 4);
		assert_eq!(route.paths[0][1].fee_msat, 100);
		assert_eq!(route.paths[0][1].cltv_expiry_delta, (3 << 4) | 2);
		assert_eq!(route.paths[0][1].node_features.le_flags(), &id_to_feature_flags(3));
		assert_eq!(route.paths[0][1].channel_features.le_flags(), &id_to_feature_flags(4));

		assert_eq!(route.paths[0][2].pubkey, nodes[0]);
		assert_eq!(route.paths[0][2].short_channel_id, 3);
		assert_eq!(route.paths[0][2].fee_msat, 100);
		assert_eq!(route.paths[0][2].cltv_expiry_delta, 42);
		assert_eq!(route.paths[0][2].node_features.le_flags(), &id_to_feature_flags(1));
		assert_eq!(route.paths[0][2].channel_features.le_flags(), &id_to_feature_flags(3));

		// If we specify a channel to node7, that overrides our local channel view and that gets used
		let payment_params = PaymentParameters::from_node_id(nodes[2]);
		let our_chans = vec![get_channel_details(Some(42), nodes[7].clone(), InitFeatures::from_le_bytes(vec![0b11]), 250_000_000)];
		let route = get_route(&our_id, &payment_params, &network_graph.read_only(), Some(&our_chans.iter().collect::<Vec<_>>()), 100, 42, Arc::clone(&logger), &scorer, &random_seed_bytes).unwrap();
		assert_eq!(route.paths[0].len(), 2);

		assert_eq!(route.paths[0][0].pubkey, nodes[7]);
		assert_eq!(route.paths[0][0].short_channel_id, 42);
		assert_eq!(route.paths[0][0].fee_msat, 200);
		assert_eq!(route.paths[0][0].cltv_expiry_delta, (13 << 4) | 1);
		assert_eq!(route.paths[0][0].node_features.le_flags(), &vec![0b11]);
		assert_eq!(route.paths[0][0].channel_features.le_flags(), &Vec::<u8>::new()); // No feature flags will meet the relevant-to-channel conversion

		assert_eq!(route.paths[0][1].pubkey, nodes[2]);
		assert_eq!(route.paths[0][1].short_channel_id, 13);
		assert_eq!(route.paths[0][1].fee_msat, 100);
		assert_eq!(route.paths[0][1].cltv_expiry_delta, 42);
		assert_eq!(route.paths[0][1].node_features.le_flags(), &id_to_feature_flags(3));
		assert_eq!(route.paths[0][1].channel_features.le_flags(), &id_to_feature_flags(13));
	}

	fn last_hops(nodes: &Vec<PublicKey>) -> Vec<RouteHint> {
		let zero_fees = RoutingFees {
			base_msat: 0,
			proportional_millionths: 0,
		};
		vec![RouteHint(vec![RouteHintHop {
			src_node_id: nodes[3],
			short_channel_id: 8,
			fees: zero_fees,
			cltv_expiry_delta: (8 << 4) | 1,
			htlc_minimum_msat: None,
			htlc_maximum_msat: None,
		}
		]), RouteHint(vec![RouteHintHop {
			src_node_id: nodes[4],
			short_channel_id: 9,
			fees: RoutingFees {
				base_msat: 1001,
				proportional_millionths: 0,
			},
			cltv_expiry_delta: (9 << 4) | 1,
			htlc_minimum_msat: None,
			htlc_maximum_msat: None,
		}]), RouteHint(vec![RouteHintHop {
			src_node_id: nodes[5],
			short_channel_id: 10,
			fees: zero_fees,
			cltv_expiry_delta: (10 << 4) | 1,
			htlc_minimum_msat: None,
			htlc_maximum_msat: None,
		}])]
	}

	fn last_hops_multi_private_channels(nodes: &Vec<PublicKey>) -> Vec<RouteHint> {
		let zero_fees = RoutingFees {
			base_msat: 0,
			proportional_millionths: 0,
		};
		vec![RouteHint(vec![RouteHintHop {
			src_node_id: nodes[2],
			short_channel_id: 5,
			fees: RoutingFees {
				base_msat: 100,
				proportional_millionths: 0,
			},
			cltv_expiry_delta: (5 << 4) | 1,
			htlc_minimum_msat: None,
			htlc_maximum_msat: None,
		}, RouteHintHop {
			src_node_id: nodes[3],
			short_channel_id: 8,
			fees: zero_fees,
			cltv_expiry_delta: (8 << 4) | 1,
			htlc_minimum_msat: None,
			htlc_maximum_msat: None,
		}
		]), RouteHint(vec![RouteHintHop {
			src_node_id: nodes[4],
			short_channel_id: 9,
			fees: RoutingFees {
				base_msat: 1001,
				proportional_millionths: 0,
			},
			cltv_expiry_delta: (9 << 4) | 1,
			htlc_minimum_msat: None,
			htlc_maximum_msat: None,
		}]), RouteHint(vec![RouteHintHop {
			src_node_id: nodes[5],
			short_channel_id: 10,
			fees: zero_fees,
			cltv_expiry_delta: (10 << 4) | 1,
			htlc_minimum_msat: None,
			htlc_maximum_msat: None,
		}])]
	}

	#[test]
	fn partial_route_hint_test() {
		let (secp_ctx, network_graph, _, _, logger) = build_graph();
		let (_, our_id, _, nodes) = get_nodes(&secp_ctx);
		let scorer = test_utils::TestScorer::with_penalty(0);
		let keys_manager = test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();

		// Simple test across 2, 3, 5, and 4 via a last_hop channel
		// Tests the behaviour when the RouteHint contains a suboptimal hop.
		// RouteHint may be partially used by the algo to build the best path.

		// First check that last hop can't have its source as the payee.
		let invalid_last_hop = RouteHint(vec![RouteHintHop {
			src_node_id: nodes[6],
			short_channel_id: 8,
			fees: RoutingFees {
				base_msat: 1000,
				proportional_millionths: 0,
			},
			cltv_expiry_delta: (8 << 4) | 1,
			htlc_minimum_msat: None,
			htlc_maximum_msat: None,
		}]);

		let mut invalid_last_hops = last_hops_multi_private_channels(&nodes);
		invalid_last_hops.push(invalid_last_hop);
		{
			let payment_params = PaymentParameters::from_node_id(nodes[6]).with_route_hints(invalid_last_hops);
			if let Err(LightningError{err, action: ErrorAction::IgnoreError}) = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 100, 42, Arc::clone(&logger), &scorer, &random_seed_bytes) {
				assert_eq!(err, "Route hint cannot have the payee as the source.");
			} else { panic!(); }
		}

		let payment_params = PaymentParameters::from_node_id(nodes[6]).with_route_hints(last_hops_multi_private_channels(&nodes));
		let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 100, 42, Arc::clone(&logger), &scorer, &random_seed_bytes).unwrap();
		assert_eq!(route.paths[0].len(), 5);

		assert_eq!(route.paths[0][0].pubkey, nodes[1]);
		assert_eq!(route.paths[0][0].short_channel_id, 2);
		assert_eq!(route.paths[0][0].fee_msat, 100);
		assert_eq!(route.paths[0][0].cltv_expiry_delta, (4 << 4) | 1);
		assert_eq!(route.paths[0][0].node_features.le_flags(), &id_to_feature_flags(2));
		assert_eq!(route.paths[0][0].channel_features.le_flags(), &id_to_feature_flags(2));

		assert_eq!(route.paths[0][1].pubkey, nodes[2]);
		assert_eq!(route.paths[0][1].short_channel_id, 4);
		assert_eq!(route.paths[0][1].fee_msat, 0);
		assert_eq!(route.paths[0][1].cltv_expiry_delta, (6 << 4) | 1);
		assert_eq!(route.paths[0][1].node_features.le_flags(), &id_to_feature_flags(3));
		assert_eq!(route.paths[0][1].channel_features.le_flags(), &id_to_feature_flags(4));

		assert_eq!(route.paths[0][2].pubkey, nodes[4]);
		assert_eq!(route.paths[0][2].short_channel_id, 6);
		assert_eq!(route.paths[0][2].fee_msat, 0);
		assert_eq!(route.paths[0][2].cltv_expiry_delta, (11 << 4) | 1);
		assert_eq!(route.paths[0][2].node_features.le_flags(), &id_to_feature_flags(5));
		assert_eq!(route.paths[0][2].channel_features.le_flags(), &id_to_feature_flags(6));

		assert_eq!(route.paths[0][3].pubkey, nodes[3]);
		assert_eq!(route.paths[0][3].short_channel_id, 11);
		assert_eq!(route.paths[0][3].fee_msat, 0);
		assert_eq!(route.paths[0][3].cltv_expiry_delta, (8 << 4) | 1);
		// If we have a peer in the node map, we'll use their features here since we don't have
		// a way of figuring out their features from the invoice:
		assert_eq!(route.paths[0][3].node_features.le_flags(), &id_to_feature_flags(4));
		assert_eq!(route.paths[0][3].channel_features.le_flags(), &id_to_feature_flags(11));

		assert_eq!(route.paths[0][4].pubkey, nodes[6]);
		assert_eq!(route.paths[0][4].short_channel_id, 8);
		assert_eq!(route.paths[0][4].fee_msat, 100);
		assert_eq!(route.paths[0][4].cltv_expiry_delta, 42);
		assert_eq!(route.paths[0][4].node_features.le_flags(), default_node_features().le_flags()); // We dont pass flags in from invoices yet
		assert_eq!(route.paths[0][4].channel_features.le_flags(), &Vec::<u8>::new()); // We can't learn any flags from invoices, sadly
	}

	fn empty_last_hop(nodes: &Vec<PublicKey>) -> Vec<RouteHint> {
		let zero_fees = RoutingFees {
			base_msat: 0,
			proportional_millionths: 0,
		};
		vec![RouteHint(vec![RouteHintHop {
			src_node_id: nodes[3],
			short_channel_id: 8,
			fees: zero_fees,
			cltv_expiry_delta: (8 << 4) | 1,
			htlc_minimum_msat: None,
			htlc_maximum_msat: None,
		}]), RouteHint(vec![

		]), RouteHint(vec![RouteHintHop {
			src_node_id: nodes[5],
			short_channel_id: 10,
			fees: zero_fees,
			cltv_expiry_delta: (10 << 4) | 1,
			htlc_minimum_msat: None,
			htlc_maximum_msat: None,
		}])]
	}

	#[test]
	fn ignores_empty_last_hops_test() {
		let (secp_ctx, network_graph, _, _, logger) = build_graph();
		let (_, our_id, _, nodes) = get_nodes(&secp_ctx);
		let payment_params = PaymentParameters::from_node_id(nodes[6]).with_route_hints(empty_last_hop(&nodes));
		let scorer = test_utils::TestScorer::with_penalty(0);
		let keys_manager = test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();

		// Test handling of an empty RouteHint passed in Invoice.

		let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 100, 42, Arc::clone(&logger), &scorer, &random_seed_bytes).unwrap();
		assert_eq!(route.paths[0].len(), 5);

		assert_eq!(route.paths[0][0].pubkey, nodes[1]);
		assert_eq!(route.paths[0][0].short_channel_id, 2);
		assert_eq!(route.paths[0][0].fee_msat, 100);
		assert_eq!(route.paths[0][0].cltv_expiry_delta, (4 << 4) | 1);
		assert_eq!(route.paths[0][0].node_features.le_flags(), &id_to_feature_flags(2));
		assert_eq!(route.paths[0][0].channel_features.le_flags(), &id_to_feature_flags(2));

		assert_eq!(route.paths[0][1].pubkey, nodes[2]);
		assert_eq!(route.paths[0][1].short_channel_id, 4);
		assert_eq!(route.paths[0][1].fee_msat, 0);
		assert_eq!(route.paths[0][1].cltv_expiry_delta, (6 << 4) | 1);
		assert_eq!(route.paths[0][1].node_features.le_flags(), &id_to_feature_flags(3));
		assert_eq!(route.paths[0][1].channel_features.le_flags(), &id_to_feature_flags(4));

		assert_eq!(route.paths[0][2].pubkey, nodes[4]);
		assert_eq!(route.paths[0][2].short_channel_id, 6);
		assert_eq!(route.paths[0][2].fee_msat, 0);
		assert_eq!(route.paths[0][2].cltv_expiry_delta, (11 << 4) | 1);
		assert_eq!(route.paths[0][2].node_features.le_flags(), &id_to_feature_flags(5));
		assert_eq!(route.paths[0][2].channel_features.le_flags(), &id_to_feature_flags(6));

		assert_eq!(route.paths[0][3].pubkey, nodes[3]);
		assert_eq!(route.paths[0][3].short_channel_id, 11);
		assert_eq!(route.paths[0][3].fee_msat, 0);
		assert_eq!(route.paths[0][3].cltv_expiry_delta, (8 << 4) | 1);
		// If we have a peer in the node map, we'll use their features here since we don't have
		// a way of figuring out their features from the invoice:
		assert_eq!(route.paths[0][3].node_features.le_flags(), &id_to_feature_flags(4));
		assert_eq!(route.paths[0][3].channel_features.le_flags(), &id_to_feature_flags(11));

		assert_eq!(route.paths[0][4].pubkey, nodes[6]);
		assert_eq!(route.paths[0][4].short_channel_id, 8);
		assert_eq!(route.paths[0][4].fee_msat, 100);
		assert_eq!(route.paths[0][4].cltv_expiry_delta, 42);
		assert_eq!(route.paths[0][4].node_features.le_flags(), default_node_features().le_flags()); // We dont pass flags in from invoices yet
		assert_eq!(route.paths[0][4].channel_features.le_flags(), &Vec::<u8>::new()); // We can't learn any flags from invoices, sadly
	}

	/// Builds a trivial last-hop hint that passes through the two nodes given, with channel 0xff00
	/// and 0xff01.
	fn multi_hop_last_hops_hint(hint_hops: [PublicKey; 2]) -> Vec<RouteHint> {
		let zero_fees = RoutingFees {
			base_msat: 0,
			proportional_millionths: 0,
		};
		vec![RouteHint(vec![RouteHintHop {
			src_node_id: hint_hops[0],
			short_channel_id: 0xff00,
			fees: RoutingFees {
				base_msat: 100,
				proportional_millionths: 0,
			},
			cltv_expiry_delta: (5 << 4) | 1,
			htlc_minimum_msat: None,
			htlc_maximum_msat: None,
		}, RouteHintHop {
			src_node_id: hint_hops[1],
			short_channel_id: 0xff01,
			fees: zero_fees,
			cltv_expiry_delta: (8 << 4) | 1,
			htlc_minimum_msat: None,
			htlc_maximum_msat: None,
		}])]
	}

	#[test]
	fn multi_hint_last_hops_test() {
		let (secp_ctx, network_graph, net_graph_msg_handler, _, logger) = build_graph();
		let (_, our_id, privkeys, nodes) = get_nodes(&secp_ctx);
		let last_hops = multi_hop_last_hops_hint([nodes[2], nodes[3]]);
		let payment_params = PaymentParameters::from_node_id(nodes[6]).with_route_hints(last_hops.clone());
		let scorer = test_utils::TestScorer::with_penalty(0);
		let keys_manager = test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();
		// Test through channels 2, 3, 0xff00, 0xff01.
		// Test shows that multiple hop hints are considered.

		// Disabling channels 6 & 7 by flags=2
		update_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 6,
			timestamp: 2,
			flags: 2, // to disable
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Absent,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 7,
			timestamp: 2,
			flags: 2, // to disable
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Absent,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 100, 42, Arc::clone(&logger), &scorer, &random_seed_bytes).unwrap();
		assert_eq!(route.paths[0].len(), 4);

		assert_eq!(route.paths[0][0].pubkey, nodes[1]);
		assert_eq!(route.paths[0][0].short_channel_id, 2);
		assert_eq!(route.paths[0][0].fee_msat, 200);
		assert_eq!(route.paths[0][0].cltv_expiry_delta, 65);
		assert_eq!(route.paths[0][0].node_features.le_flags(), &id_to_feature_flags(2));
		assert_eq!(route.paths[0][0].channel_features.le_flags(), &id_to_feature_flags(2));

		assert_eq!(route.paths[0][1].pubkey, nodes[2]);
		assert_eq!(route.paths[0][1].short_channel_id, 4);
		assert_eq!(route.paths[0][1].fee_msat, 100);
		assert_eq!(route.paths[0][1].cltv_expiry_delta, 81);
		assert_eq!(route.paths[0][1].node_features.le_flags(), &id_to_feature_flags(3));
		assert_eq!(route.paths[0][1].channel_features.le_flags(), &id_to_feature_flags(4));

		assert_eq!(route.paths[0][2].pubkey, nodes[3]);
		assert_eq!(route.paths[0][2].short_channel_id, last_hops[0].0[0].short_channel_id);
		assert_eq!(route.paths[0][2].fee_msat, 0);
		assert_eq!(route.paths[0][2].cltv_expiry_delta, 129);
		assert_eq!(route.paths[0][2].node_features.le_flags(), &id_to_feature_flags(4));
		assert_eq!(route.paths[0][2].channel_features.le_flags(), &Vec::<u8>::new()); // We can't learn any flags from invoices, sadly

		assert_eq!(route.paths[0][3].pubkey, nodes[6]);
		assert_eq!(route.paths[0][3].short_channel_id, last_hops[0].0[1].short_channel_id);
		assert_eq!(route.paths[0][3].fee_msat, 100);
		assert_eq!(route.paths[0][3].cltv_expiry_delta, 42);
		assert_eq!(route.paths[0][3].node_features.le_flags(), default_node_features().le_flags()); // We dont pass flags in from invoices yet
		assert_eq!(route.paths[0][3].channel_features.le_flags(), &Vec::<u8>::new()); // We can't learn any flags from invoices, sadly
	}

	#[test]
	fn private_multi_hint_last_hops_test() {
		let (secp_ctx, network_graph, net_graph_msg_handler, _, logger) = build_graph();
		let (_, our_id, privkeys, nodes) = get_nodes(&secp_ctx);

		let non_announced_privkey = SecretKey::from_slice(&hex::decode(format!("{:02x}", 0xf0).repeat(32)).unwrap()[..]).unwrap();
		let non_announced_pubkey = PublicKey::from_secret_key(&secp_ctx, &non_announced_privkey);

		let last_hops = multi_hop_last_hops_hint([nodes[2], non_announced_pubkey]);
		let payment_params = PaymentParameters::from_node_id(nodes[6]).with_route_hints(last_hops.clone());
		let scorer = test_utils::TestScorer::with_penalty(0);
		// Test through channels 2, 3, 0xff00, 0xff01.
		// Test shows that multiple hop hints are considered.

		// Disabling channels 6 & 7 by flags=2
		update_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 6,
			timestamp: 2,
			flags: 2, // to disable
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Absent,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 7,
			timestamp: 2,
			flags: 2, // to disable
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Absent,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 100, 42, Arc::clone(&logger), &scorer, &[42u8; 32]).unwrap();
		assert_eq!(route.paths[0].len(), 4);

		assert_eq!(route.paths[0][0].pubkey, nodes[1]);
		assert_eq!(route.paths[0][0].short_channel_id, 2);
		assert_eq!(route.paths[0][0].fee_msat, 200);
		assert_eq!(route.paths[0][0].cltv_expiry_delta, 65);
		assert_eq!(route.paths[0][0].node_features.le_flags(), &id_to_feature_flags(2));
		assert_eq!(route.paths[0][0].channel_features.le_flags(), &id_to_feature_flags(2));

		assert_eq!(route.paths[0][1].pubkey, nodes[2]);
		assert_eq!(route.paths[0][1].short_channel_id, 4);
		assert_eq!(route.paths[0][1].fee_msat, 100);
		assert_eq!(route.paths[0][1].cltv_expiry_delta, 81);
		assert_eq!(route.paths[0][1].node_features.le_flags(), &id_to_feature_flags(3));
		assert_eq!(route.paths[0][1].channel_features.le_flags(), &id_to_feature_flags(4));

		assert_eq!(route.paths[0][2].pubkey, non_announced_pubkey);
		assert_eq!(route.paths[0][2].short_channel_id, last_hops[0].0[0].short_channel_id);
		assert_eq!(route.paths[0][2].fee_msat, 0);
		assert_eq!(route.paths[0][2].cltv_expiry_delta, 129);
		assert_eq!(route.paths[0][2].node_features.le_flags(), default_node_features().le_flags()); // We dont pass flags in from invoices yet
		assert_eq!(route.paths[0][2].channel_features.le_flags(), &Vec::<u8>::new()); // We can't learn any flags from invoices, sadly

		assert_eq!(route.paths[0][3].pubkey, nodes[6]);
		assert_eq!(route.paths[0][3].short_channel_id, last_hops[0].0[1].short_channel_id);
		assert_eq!(route.paths[0][3].fee_msat, 100);
		assert_eq!(route.paths[0][3].cltv_expiry_delta, 42);
		assert_eq!(route.paths[0][3].node_features.le_flags(), default_node_features().le_flags()); // We dont pass flags in from invoices yet
		assert_eq!(route.paths[0][3].channel_features.le_flags(), &Vec::<u8>::new()); // We can't learn any flags from invoices, sadly
	}

	fn last_hops_with_public_channel(nodes: &Vec<PublicKey>) -> Vec<RouteHint> {
		let zero_fees = RoutingFees {
			base_msat: 0,
			proportional_millionths: 0,
		};
		vec![RouteHint(vec![RouteHintHop {
			src_node_id: nodes[4],
			short_channel_id: 11,
			fees: zero_fees,
			cltv_expiry_delta: (11 << 4) | 1,
			htlc_minimum_msat: None,
			htlc_maximum_msat: None,
		}, RouteHintHop {
			src_node_id: nodes[3],
			short_channel_id: 8,
			fees: zero_fees,
			cltv_expiry_delta: (8 << 4) | 1,
			htlc_minimum_msat: None,
			htlc_maximum_msat: None,
		}]), RouteHint(vec![RouteHintHop {
			src_node_id: nodes[4],
			short_channel_id: 9,
			fees: RoutingFees {
				base_msat: 1001,
				proportional_millionths: 0,
			},
			cltv_expiry_delta: (9 << 4) | 1,
			htlc_minimum_msat: None,
			htlc_maximum_msat: None,
		}]), RouteHint(vec![RouteHintHop {
			src_node_id: nodes[5],
			short_channel_id: 10,
			fees: zero_fees,
			cltv_expiry_delta: (10 << 4) | 1,
			htlc_minimum_msat: None,
			htlc_maximum_msat: None,
		}])]
	}

	#[test]
	fn last_hops_with_public_channel_test() {
		let (secp_ctx, network_graph, _, _, logger) = build_graph();
		let (_, our_id, _, nodes) = get_nodes(&secp_ctx);
		let payment_params = PaymentParameters::from_node_id(nodes[6]).with_route_hints(last_hops_with_public_channel(&nodes));
		let scorer = test_utils::TestScorer::with_penalty(0);
		let keys_manager = test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();
		// This test shows that public routes can be present in the invoice
		// which would be handled in the same manner.

		let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 100, 42, Arc::clone(&logger), &scorer, &random_seed_bytes).unwrap();
		assert_eq!(route.paths[0].len(), 5);

		assert_eq!(route.paths[0][0].pubkey, nodes[1]);
		assert_eq!(route.paths[0][0].short_channel_id, 2);
		assert_eq!(route.paths[0][0].fee_msat, 100);
		assert_eq!(route.paths[0][0].cltv_expiry_delta, (4 << 4) | 1);
		assert_eq!(route.paths[0][0].node_features.le_flags(), &id_to_feature_flags(2));
		assert_eq!(route.paths[0][0].channel_features.le_flags(), &id_to_feature_flags(2));

		assert_eq!(route.paths[0][1].pubkey, nodes[2]);
		assert_eq!(route.paths[0][1].short_channel_id, 4);
		assert_eq!(route.paths[0][1].fee_msat, 0);
		assert_eq!(route.paths[0][1].cltv_expiry_delta, (6 << 4) | 1);
		assert_eq!(route.paths[0][1].node_features.le_flags(), &id_to_feature_flags(3));
		assert_eq!(route.paths[0][1].channel_features.le_flags(), &id_to_feature_flags(4));

		assert_eq!(route.paths[0][2].pubkey, nodes[4]);
		assert_eq!(route.paths[0][2].short_channel_id, 6);
		assert_eq!(route.paths[0][2].fee_msat, 0);
		assert_eq!(route.paths[0][2].cltv_expiry_delta, (11 << 4) | 1);
		assert_eq!(route.paths[0][2].node_features.le_flags(), &id_to_feature_flags(5));
		assert_eq!(route.paths[0][2].channel_features.le_flags(), &id_to_feature_flags(6));

		assert_eq!(route.paths[0][3].pubkey, nodes[3]);
		assert_eq!(route.paths[0][3].short_channel_id, 11);
		assert_eq!(route.paths[0][3].fee_msat, 0);
		assert_eq!(route.paths[0][3].cltv_expiry_delta, (8 << 4) | 1);
		// If we have a peer in the node map, we'll use their features here since we don't have
		// a way of figuring out their features from the invoice:
		assert_eq!(route.paths[0][3].node_features.le_flags(), &id_to_feature_flags(4));
		assert_eq!(route.paths[0][3].channel_features.le_flags(), &id_to_feature_flags(11));

		assert_eq!(route.paths[0][4].pubkey, nodes[6]);
		assert_eq!(route.paths[0][4].short_channel_id, 8);
		assert_eq!(route.paths[0][4].fee_msat, 100);
		assert_eq!(route.paths[0][4].cltv_expiry_delta, 42);
		assert_eq!(route.paths[0][4].node_features.le_flags(), default_node_features().le_flags()); // We dont pass flags in from invoices yet
		assert_eq!(route.paths[0][4].channel_features.le_flags(), &Vec::<u8>::new()); // We can't learn any flags from invoices, sadly
	}

	#[test]
	fn our_chans_last_hop_connect_test() {
		let (secp_ctx, network_graph, _, _, logger) = build_graph();
		let (_, our_id, _, nodes) = get_nodes(&secp_ctx);
		let scorer = test_utils::TestScorer::with_penalty(0);
		let keys_manager = test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();

		// Simple test with outbound channel to 4 to test that last_hops and first_hops connect
		let our_chans = vec![get_channel_details(Some(42), nodes[3].clone(), InitFeatures::from_le_bytes(vec![0b11]), 250_000_000)];
		let mut last_hops = last_hops(&nodes);
		let payment_params = PaymentParameters::from_node_id(nodes[6]).with_route_hints(last_hops.clone());
		let route = get_route(&our_id, &payment_params, &network_graph.read_only(), Some(&our_chans.iter().collect::<Vec<_>>()), 100, 42, Arc::clone(&logger), &scorer, &random_seed_bytes).unwrap();
		assert_eq!(route.paths[0].len(), 2);

		assert_eq!(route.paths[0][0].pubkey, nodes[3]);
		assert_eq!(route.paths[0][0].short_channel_id, 42);
		assert_eq!(route.paths[0][0].fee_msat, 0);
		assert_eq!(route.paths[0][0].cltv_expiry_delta, (8 << 4) | 1);
		assert_eq!(route.paths[0][0].node_features.le_flags(), &vec![0b11]);
		assert_eq!(route.paths[0][0].channel_features.le_flags(), &Vec::<u8>::new()); // No feature flags will meet the relevant-to-channel conversion

		assert_eq!(route.paths[0][1].pubkey, nodes[6]);
		assert_eq!(route.paths[0][1].short_channel_id, 8);
		assert_eq!(route.paths[0][1].fee_msat, 100);
		assert_eq!(route.paths[0][1].cltv_expiry_delta, 42);
		assert_eq!(route.paths[0][1].node_features.le_flags(), default_node_features().le_flags()); // We dont pass flags in from invoices yet
		assert_eq!(route.paths[0][1].channel_features.le_flags(), &Vec::<u8>::new()); // We can't learn any flags from invoices, sadly

		last_hops[0].0[0].fees.base_msat = 1000;

		// Revert to via 6 as the fee on 8 goes up
		let payment_params = PaymentParameters::from_node_id(nodes[6]).with_route_hints(last_hops);
		let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 100, 42, Arc::clone(&logger), &scorer, &random_seed_bytes).unwrap();
		assert_eq!(route.paths[0].len(), 4);

		assert_eq!(route.paths[0][0].pubkey, nodes[1]);
		assert_eq!(route.paths[0][0].short_channel_id, 2);
		assert_eq!(route.paths[0][0].fee_msat, 200); // fee increased as its % of value transferred across node
		assert_eq!(route.paths[0][0].cltv_expiry_delta, (4 << 4) | 1);
		assert_eq!(route.paths[0][0].node_features.le_flags(), &id_to_feature_flags(2));
		assert_eq!(route.paths[0][0].channel_features.le_flags(), &id_to_feature_flags(2));

		assert_eq!(route.paths[0][1].pubkey, nodes[2]);
		assert_eq!(route.paths[0][1].short_channel_id, 4);
		assert_eq!(route.paths[0][1].fee_msat, 100);
		assert_eq!(route.paths[0][1].cltv_expiry_delta, (7 << 4) | 1);
		assert_eq!(route.paths[0][1].node_features.le_flags(), &id_to_feature_flags(3));
		assert_eq!(route.paths[0][1].channel_features.le_flags(), &id_to_feature_flags(4));

		assert_eq!(route.paths[0][2].pubkey, nodes[5]);
		assert_eq!(route.paths[0][2].short_channel_id, 7);
		assert_eq!(route.paths[0][2].fee_msat, 0);
		assert_eq!(route.paths[0][2].cltv_expiry_delta, (10 << 4) | 1);
		// If we have a peer in the node map, we'll use their features here since we don't have
		// a way of figuring out their features from the invoice:
		assert_eq!(route.paths[0][2].node_features.le_flags(), &id_to_feature_flags(6));
		assert_eq!(route.paths[0][2].channel_features.le_flags(), &id_to_feature_flags(7));

		assert_eq!(route.paths[0][3].pubkey, nodes[6]);
		assert_eq!(route.paths[0][3].short_channel_id, 10);
		assert_eq!(route.paths[0][3].fee_msat, 100);
		assert_eq!(route.paths[0][3].cltv_expiry_delta, 42);
		assert_eq!(route.paths[0][3].node_features.le_flags(), default_node_features().le_flags()); // We dont pass flags in from invoices yet
		assert_eq!(route.paths[0][3].channel_features.le_flags(), &Vec::<u8>::new()); // We can't learn any flags from invoices, sadly

		// ...but still use 8 for larger payments as 6 has a variable feerate
		let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 2000, 42, Arc::clone(&logger), &scorer, &random_seed_bytes).unwrap();
		assert_eq!(route.paths[0].len(), 5);

		assert_eq!(route.paths[0][0].pubkey, nodes[1]);
		assert_eq!(route.paths[0][0].short_channel_id, 2);
		assert_eq!(route.paths[0][0].fee_msat, 3000);
		assert_eq!(route.paths[0][0].cltv_expiry_delta, (4 << 4) | 1);
		assert_eq!(route.paths[0][0].node_features.le_flags(), &id_to_feature_flags(2));
		assert_eq!(route.paths[0][0].channel_features.le_flags(), &id_to_feature_flags(2));

		assert_eq!(route.paths[0][1].pubkey, nodes[2]);
		assert_eq!(route.paths[0][1].short_channel_id, 4);
		assert_eq!(route.paths[0][1].fee_msat, 0);
		assert_eq!(route.paths[0][1].cltv_expiry_delta, (6 << 4) | 1);
		assert_eq!(route.paths[0][1].node_features.le_flags(), &id_to_feature_flags(3));
		assert_eq!(route.paths[0][1].channel_features.le_flags(), &id_to_feature_flags(4));

		assert_eq!(route.paths[0][2].pubkey, nodes[4]);
		assert_eq!(route.paths[0][2].short_channel_id, 6);
		assert_eq!(route.paths[0][2].fee_msat, 0);
		assert_eq!(route.paths[0][2].cltv_expiry_delta, (11 << 4) | 1);
		assert_eq!(route.paths[0][2].node_features.le_flags(), &id_to_feature_flags(5));
		assert_eq!(route.paths[0][2].channel_features.le_flags(), &id_to_feature_flags(6));

		assert_eq!(route.paths[0][3].pubkey, nodes[3]);
		assert_eq!(route.paths[0][3].short_channel_id, 11);
		assert_eq!(route.paths[0][3].fee_msat, 1000);
		assert_eq!(route.paths[0][3].cltv_expiry_delta, (8 << 4) | 1);
		// If we have a peer in the node map, we'll use their features here since we don't have
		// a way of figuring out their features from the invoice:
		assert_eq!(route.paths[0][3].node_features.le_flags(), &id_to_feature_flags(4));
		assert_eq!(route.paths[0][3].channel_features.le_flags(), &id_to_feature_flags(11));

		assert_eq!(route.paths[0][4].pubkey, nodes[6]);
		assert_eq!(route.paths[0][4].short_channel_id, 8);
		assert_eq!(route.paths[0][4].fee_msat, 2000);
		assert_eq!(route.paths[0][4].cltv_expiry_delta, 42);
		assert_eq!(route.paths[0][4].node_features.le_flags(), default_node_features().le_flags()); // We dont pass flags in from invoices yet
		assert_eq!(route.paths[0][4].channel_features.le_flags(), &Vec::<u8>::new()); // We can't learn any flags from invoices, sadly
	}

	fn do_unannounced_path_test(last_hop_htlc_max: Option<u64>, last_hop_fee_prop: u32, outbound_capacity_msat: u64, route_val: u64) -> Result<Route, LightningError> {
		let source_node_id = PublicKey::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&hex::decode(format!("{:02}", 41).repeat(32)).unwrap()[..]).unwrap());
		let middle_node_id = PublicKey::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&hex::decode(format!("{:02}", 42).repeat(32)).unwrap()[..]).unwrap());
		let target_node_id = PublicKey::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&hex::decode(format!("{:02}", 43).repeat(32)).unwrap()[..]).unwrap());

		// If we specify a channel to a middle hop, that overrides our local channel view and that gets used
		let last_hops = RouteHint(vec![RouteHintHop {
			src_node_id: middle_node_id,
			short_channel_id: 8,
			fees: RoutingFees {
				base_msat: 1000,
				proportional_millionths: last_hop_fee_prop,
			},
			cltv_expiry_delta: (8 << 4) | 1,
			htlc_minimum_msat: None,
			htlc_maximum_msat: last_hop_htlc_max,
		}]);
		let payment_params = PaymentParameters::from_node_id(target_node_id).with_route_hints(vec![last_hops]);
		let our_chans = vec![get_channel_details(Some(42), middle_node_id, InitFeatures::from_le_bytes(vec![0b11]), outbound_capacity_msat)];
		let scorer = test_utils::TestScorer::with_penalty(0);
		let keys_manager = test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();
		get_route(&source_node_id, &payment_params, &NetworkGraph::new(genesis_block(Network::Testnet).header.block_hash()).read_only(),
				Some(&our_chans.iter().collect::<Vec<_>>()), route_val, 42, &test_utils::TestLogger::new(), &scorer, &random_seed_bytes)
	}

	#[test]
	fn unannounced_path_test() {
		// We should be able to send a payment to a destination without any help of a routing graph
		// if we have a channel with a common counterparty that appears in the first and last hop
		// hints.
		let route = do_unannounced_path_test(None, 1, 2000000, 1000000).unwrap();

		let middle_node_id = PublicKey::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&hex::decode(format!("{:02}", 42).repeat(32)).unwrap()[..]).unwrap());
		let target_node_id = PublicKey::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&hex::decode(format!("{:02}", 43).repeat(32)).unwrap()[..]).unwrap());
		assert_eq!(route.paths[0].len(), 2);

		assert_eq!(route.paths[0][0].pubkey, middle_node_id);
		assert_eq!(route.paths[0][0].short_channel_id, 42);
		assert_eq!(route.paths[0][0].fee_msat, 1001);
		assert_eq!(route.paths[0][0].cltv_expiry_delta, (8 << 4) | 1);
		assert_eq!(route.paths[0][0].node_features.le_flags(), &[0b11]);
		assert_eq!(route.paths[0][0].channel_features.le_flags(), &[0; 0]); // We can't learn any flags from invoices, sadly

		assert_eq!(route.paths[0][1].pubkey, target_node_id);
		assert_eq!(route.paths[0][1].short_channel_id, 8);
		assert_eq!(route.paths[0][1].fee_msat, 1000000);
		assert_eq!(route.paths[0][1].cltv_expiry_delta, 42);
		assert_eq!(route.paths[0][1].node_features.le_flags(), default_node_features().le_flags()); // We dont pass flags in from invoices yet
		assert_eq!(route.paths[0][1].channel_features.le_flags(), &[0; 0]); // We can't learn any flags from invoices, sadly
	}

	#[test]
	fn overflow_unannounced_path_test_liquidity_underflow() {
		// Previously, when we had a last-hop hint connected directly to a first-hop channel, where
		// the last-hop had a fee which overflowed a u64, we'd panic.
		// This was due to us adding the first-hop from us unconditionally, causing us to think
		// we'd built a path (as our node is in the "best candidate" set), when we had not.
		// In this test, we previously hit a subtraction underflow due to having less available
		// liquidity at the last hop than 0.
		assert!(do_unannounced_path_test(Some(21_000_000_0000_0000_000), 0, 21_000_000_0000_0000_000, 21_000_000_0000_0000_000).is_err());
	}

	#[test]
	fn overflow_unannounced_path_test_feerate_overflow() {
		// This tests for the same case as above, except instead of hitting a subtraction
		// underflow, we hit a case where the fee charged at a hop overflowed.
		assert!(do_unannounced_path_test(Some(21_000_000_0000_0000_000), 50000, 21_000_000_0000_0000_000, 21_000_000_0000_0000_000).is_err());
	}

	#[test]
	fn available_amount_while_routing_test() {
		// Tests whether we choose the correct available channel amount while routing.

		let (secp_ctx, network_graph, mut net_graph_msg_handler, chain_monitor, logger) = build_graph();
		let (our_privkey, our_id, privkeys, nodes) = get_nodes(&secp_ctx);
		let scorer = test_utils::TestScorer::with_penalty(0);
		let keys_manager = test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();
		let payment_params = PaymentParameters::from_node_id(nodes[2]).with_features(InvoiceFeatures::known());

		// We will use a simple single-path route from
		// our node to node2 via node0: channels {1, 3}.

		// First disable all other paths.
		update_channel(&net_graph_msg_handler, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 2,
			timestamp: 2,
			flags: 2,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Present(100_000),
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&net_graph_msg_handler, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 12,
			timestamp: 2,
			flags: 2,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Present(100_000),
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		// Make the first channel (#1) very permissive,
		// and we will be testing all limits on the second channel.
		update_channel(&net_graph_msg_handler, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 1,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Present(1_000_000_000),
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		// First, let's see if routing works if we have absolutely no idea about the available amount.
		// In this case, it should be set to 250_000 sats.
		update_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[0], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 3,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Absent,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		{
			// Attempt to route more than available results in a failure.
			if let Err(LightningError{err, action: ErrorAction::IgnoreError}) = get_route(
					&our_id, &payment_params, &network_graph.read_only(), None, 250_000_001, 42, Arc::clone(&logger), &scorer, &random_seed_bytes) {
				assert_eq!(err, "Failed to find a sufficient route to the given destination");
			} else { panic!(); }
		}

		{
			// Now, attempt to route an exact amount we have should be fine.
			let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 250_000_000, 42, Arc::clone(&logger), &scorer, &random_seed_bytes).unwrap();
			assert_eq!(route.paths.len(), 1);
			let path = route.paths.last().unwrap();
			assert_eq!(path.len(), 2);
			assert_eq!(path.last().unwrap().pubkey, nodes[2]);
			assert_eq!(path.last().unwrap().fee_msat, 250_000_000);
		}

		// Check that setting next_outbound_htlc_limit_msat in first_hops limits the channels.
		// Disable channel #1 and use another first hop.
		update_channel(&net_graph_msg_handler, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 1,
			timestamp: 3,
			flags: 2,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Present(1_000_000_000),
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		// Now, limit the first_hop by the next_outbound_htlc_limit_msat of 200_000 sats.
		let our_chans = vec![get_channel_details(Some(42), nodes[0].clone(), InitFeatures::from_le_bytes(vec![0b11]), 200_000_000)];

		{
			// Attempt to route more than available results in a failure.
			if let Err(LightningError{err, action: ErrorAction::IgnoreError}) = get_route(
					&our_id, &payment_params, &network_graph.read_only(), Some(&our_chans.iter().collect::<Vec<_>>()), 200_000_001, 42, Arc::clone(&logger), &scorer, &random_seed_bytes) {
				assert_eq!(err, "Failed to find a sufficient route to the given destination");
			} else { panic!(); }
		}

		{
			// Now, attempt to route an exact amount we have should be fine.
			let route = get_route(&our_id, &payment_params, &network_graph.read_only(), Some(&our_chans.iter().collect::<Vec<_>>()), 200_000_000, 42, Arc::clone(&logger), &scorer, &random_seed_bytes).unwrap();
			assert_eq!(route.paths.len(), 1);
			let path = route.paths.last().unwrap();
			assert_eq!(path.len(), 2);
			assert_eq!(path.last().unwrap().pubkey, nodes[2]);
			assert_eq!(path.last().unwrap().fee_msat, 200_000_000);
		}

		// Enable channel #1 back.
		update_channel(&net_graph_msg_handler, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 1,
			timestamp: 4,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Present(1_000_000_000),
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});


		// Now let's see if routing works if we know only htlc_maximum_msat.
		update_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[0], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 3,
			timestamp: 3,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Present(15_000),
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		{
			// Attempt to route more than available results in a failure.
			if let Err(LightningError{err, action: ErrorAction::IgnoreError}) = get_route(
					&our_id, &payment_params, &network_graph.read_only(), None, 15_001, 42, Arc::clone(&logger), &scorer, &random_seed_bytes) {
				assert_eq!(err, "Failed to find a sufficient route to the given destination");
			} else { panic!(); }
		}

		{
			// Now, attempt to route an exact amount we have should be fine.
			let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 15_000, 42, Arc::clone(&logger), &scorer, &random_seed_bytes).unwrap();
			assert_eq!(route.paths.len(), 1);
			let path = route.paths.last().unwrap();
			assert_eq!(path.len(), 2);
			assert_eq!(path.last().unwrap().pubkey, nodes[2]);
			assert_eq!(path.last().unwrap().fee_msat, 15_000);
		}

		// Now let's see if routing works if we know only capacity from the UTXO.

		// We can't change UTXO capacity on the fly, so we'll disable
		// the existing channel and add another one with the capacity we need.
		update_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[0], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 3,
			timestamp: 4,
			flags: 2,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Absent,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		let good_script = Builder::new().push_opcode(opcodes::all::OP_PUSHNUM_2)
		.push_slice(&PublicKey::from_secret_key(&secp_ctx, &privkeys[0]).serialize())
		.push_slice(&PublicKey::from_secret_key(&secp_ctx, &privkeys[2]).serialize())
		.push_opcode(opcodes::all::OP_PUSHNUM_2)
		.push_opcode(opcodes::all::OP_CHECKMULTISIG).into_script().to_v0_p2wsh();

		*chain_monitor.utxo_ret.lock().unwrap() = Ok(TxOut { value: 15, script_pubkey: good_script.clone() });
		net_graph_msg_handler.add_chain_access(Some(chain_monitor));

		add_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[0], &privkeys[2], ChannelFeatures::from_le_bytes(id_to_feature_flags(3)), 333);
		update_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[0], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 333,
			timestamp: 1,
			flags: 0,
			cltv_expiry_delta: (3 << 4) | 1,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Absent,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 333,
			timestamp: 1,
			flags: 1,
			cltv_expiry_delta: (3 << 4) | 2,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Absent,
			fee_base_msat: 100,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		{
			// Attempt to route more than available results in a failure.
			if let Err(LightningError{err, action: ErrorAction::IgnoreError}) = get_route(
					&our_id, &payment_params, &network_graph.read_only(), None, 15_001, 42, Arc::clone(&logger), &scorer, &random_seed_bytes) {
				assert_eq!(err, "Failed to find a sufficient route to the given destination");
			} else { panic!(); }
		}

		{
			// Now, attempt to route an exact amount we have should be fine.
			let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 15_000, 42, Arc::clone(&logger), &scorer, &random_seed_bytes).unwrap();
			assert_eq!(route.paths.len(), 1);
			let path = route.paths.last().unwrap();
			assert_eq!(path.len(), 2);
			assert_eq!(path.last().unwrap().pubkey, nodes[2]);
			assert_eq!(path.last().unwrap().fee_msat, 15_000);
		}

		// Now let's see if routing chooses htlc_maximum_msat over UTXO capacity.
		update_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[0], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 333,
			timestamp: 6,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Present(10_000),
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		{
			// Attempt to route more than available results in a failure.
			if let Err(LightningError{err, action: ErrorAction::IgnoreError}) = get_route(
					&our_id, &payment_params, &network_graph.read_only(), None, 10_001, 42, Arc::clone(&logger), &scorer, &random_seed_bytes) {
				assert_eq!(err, "Failed to find a sufficient route to the given destination");
			} else { panic!(); }
		}

		{
			// Now, attempt to route an exact amount we have should be fine.
			let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 10_000, 42, Arc::clone(&logger), &scorer, &random_seed_bytes).unwrap();
			assert_eq!(route.paths.len(), 1);
			let path = route.paths.last().unwrap();
			assert_eq!(path.len(), 2);
			assert_eq!(path.last().unwrap().pubkey, nodes[2]);
			assert_eq!(path.last().unwrap().fee_msat, 10_000);
		}
	}

	#[test]
	fn available_liquidity_last_hop_test() {
		// Check that available liquidity properly limits the path even when only
		// one of the latter hops is limited.
		let (secp_ctx, network_graph, net_graph_msg_handler, _, logger) = build_graph();
		let (our_privkey, our_id, privkeys, nodes) = get_nodes(&secp_ctx);
		let scorer = test_utils::TestScorer::with_penalty(0);
		let keys_manager = test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();
		let payment_params = PaymentParameters::from_node_id(nodes[3]).with_features(InvoiceFeatures::known());

		// Path via {node7, node2, node4} is channels {12, 13, 6, 11}.
		// {12, 13, 11} have the capacities of 100, {6} has a capacity of 50.
		// Total capacity: 50 sats.

		// Disable other potential paths.
		update_channel(&net_graph_msg_handler, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 2,
			timestamp: 2,
			flags: 2,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Present(100_000),
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 7,
			timestamp: 2,
			flags: 2,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Present(100_000),
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		// Limit capacities

		update_channel(&net_graph_msg_handler, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 12,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Present(100_000),
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[7], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 13,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Present(100_000),
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		update_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 6,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Present(50_000),
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[4], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 11,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Present(100_000),
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		{
			// Attempt to route more than available results in a failure.
			if let Err(LightningError{err, action: ErrorAction::IgnoreError}) = get_route(
					&our_id, &payment_params, &network_graph.read_only(), None, 60_000, 42, Arc::clone(&logger), &scorer, &random_seed_bytes) {
				assert_eq!(err, "Failed to find a sufficient route to the given destination");
			} else { panic!(); }
		}

		{
			// Now, attempt to route 49 sats (just a bit below the capacity).
			let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 49_000, 42, Arc::clone(&logger), &scorer, &random_seed_bytes).unwrap();
			assert_eq!(route.paths.len(), 1);
			let mut total_amount_paid_msat = 0;
			for path in &route.paths {
				assert_eq!(path.len(), 4);
				assert_eq!(path.last().unwrap().pubkey, nodes[3]);
				total_amount_paid_msat += path.last().unwrap().fee_msat;
			}
			assert_eq!(total_amount_paid_msat, 49_000);
		}

		{
			// Attempt to route an exact amount is also fine
			let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 50_000, 42, Arc::clone(&logger), &scorer, &random_seed_bytes).unwrap();
			assert_eq!(route.paths.len(), 1);
			let mut total_amount_paid_msat = 0;
			for path in &route.paths {
				assert_eq!(path.len(), 4);
				assert_eq!(path.last().unwrap().pubkey, nodes[3]);
				total_amount_paid_msat += path.last().unwrap().fee_msat;
			}
			assert_eq!(total_amount_paid_msat, 50_000);
		}
	}

	#[test]
	fn ignore_fee_first_hop_test() {
		let (secp_ctx, network_graph, net_graph_msg_handler, _, logger) = build_graph();
		let (our_privkey, our_id, privkeys, nodes) = get_nodes(&secp_ctx);
		let scorer = test_utils::TestScorer::with_penalty(0);
		let keys_manager = test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();
		let payment_params = PaymentParameters::from_node_id(nodes[2]);

		// Path via node0 is channels {1, 3}. Limit them to 100 and 50 sats (total limit 50).
		update_channel(&net_graph_msg_handler, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 1,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Present(100_000),
			fee_base_msat: 1_000_000,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[0], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 3,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Present(50_000),
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		{
			let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 50_000, 42, Arc::clone(&logger), &scorer, &random_seed_bytes).unwrap();
			assert_eq!(route.paths.len(), 1);
			let mut total_amount_paid_msat = 0;
			for path in &route.paths {
				assert_eq!(path.len(), 2);
				assert_eq!(path.last().unwrap().pubkey, nodes[2]);
				total_amount_paid_msat += path.last().unwrap().fee_msat;
			}
			assert_eq!(total_amount_paid_msat, 50_000);
		}
	}

	#[test]
	fn simple_mpp_route_test() {
		let (secp_ctx, network_graph, net_graph_msg_handler, _, logger) = build_graph();
		let (our_privkey, our_id, privkeys, nodes) = get_nodes(&secp_ctx);
		let scorer = test_utils::TestScorer::with_penalty(0);
		let keys_manager = test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();
		let payment_params = PaymentParameters::from_node_id(nodes[2]).with_features(InvoiceFeatures::known());

		// We need a route consisting of 3 paths:
		// From our node to node2 via node0, node7, node1 (three paths one hop each).
		// To achieve this, the amount being transferred should be around
		// the total capacity of these 3 paths.

		// First, we set limits on these (previously unlimited) channels.
		// Their aggregate capacity will be 50 + 60 + 180 = 290 sats.

		// Path via node0 is channels {1, 3}. Limit them to 100 and 50 sats (total limit 50).
		update_channel(&net_graph_msg_handler, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 1,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Present(100_000),
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[0], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 3,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Present(50_000),
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		// Path via node7 is channels {12, 13}. Limit them to 60 and 60 sats
		// (total limit 60).
		update_channel(&net_graph_msg_handler, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 12,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Present(60_000),
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[7], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 13,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Present(60_000),
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		// Path via node1 is channels {2, 4}. Limit them to 200 and 180 sats
		// (total capacity 180 sats).
		update_channel(&net_graph_msg_handler, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 2,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Present(200_000),
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[1], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 4,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Present(180_000),
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		{
			// Attempt to route more than available results in a failure.
			if let Err(LightningError{err, action: ErrorAction::IgnoreError}) = get_route(
					&our_id, &payment_params, &network_graph.read_only(), None, 300_000, 42, Arc::clone(&logger), &scorer, &random_seed_bytes) {
				assert_eq!(err, "Failed to find a sufficient route to the given destination");
			} else { panic!(); }
		}

		{
			// Now, attempt to route 250 sats (just a bit below the capacity).
			// Our algorithm should provide us with these 3 paths.
			let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 250_000, 42, Arc::clone(&logger), &scorer, &random_seed_bytes).unwrap();
			assert_eq!(route.paths.len(), 3);
			let mut total_amount_paid_msat = 0;
			for path in &route.paths {
				assert_eq!(path.len(), 2);
				assert_eq!(path.last().unwrap().pubkey, nodes[2]);
				total_amount_paid_msat += path.last().unwrap().fee_msat;
			}
			assert_eq!(total_amount_paid_msat, 250_000);
		}

		{
			// Attempt to route an exact amount is also fine
			let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 290_000, 42, Arc::clone(&logger), &scorer, &random_seed_bytes).unwrap();
			assert_eq!(route.paths.len(), 3);
			let mut total_amount_paid_msat = 0;
			for path in &route.paths {
				assert_eq!(path.len(), 2);
				assert_eq!(path.last().unwrap().pubkey, nodes[2]);
				total_amount_paid_msat += path.last().unwrap().fee_msat;
			}
			assert_eq!(total_amount_paid_msat, 290_000);
		}
	}

	#[test]
	fn long_mpp_route_test() {
		let (secp_ctx, network_graph, net_graph_msg_handler, _, logger) = build_graph();
		let (our_privkey, our_id, privkeys, nodes) = get_nodes(&secp_ctx);
		let scorer = test_utils::TestScorer::with_penalty(0);
		let keys_manager = test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();
		let payment_params = PaymentParameters::from_node_id(nodes[3]).with_features(InvoiceFeatures::known());

		// We need a route consisting of 3 paths:
		// From our node to node3 via {node0, node2}, {node7, node2, node4} and {node7, node2}.
		// Note that these paths overlap (channels 5, 12, 13).
		// We will route 300 sats.
		// Each path will have 100 sats capacity, those channels which
		// are used twice will have 200 sats capacity.

		// Disable other potential paths.
		update_channel(&net_graph_msg_handler, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 2,
			timestamp: 2,
			flags: 2,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Present(100_000),
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 7,
			timestamp: 2,
			flags: 2,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Present(100_000),
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		// Path via {node0, node2} is channels {1, 3, 5}.
		update_channel(&net_graph_msg_handler, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 1,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Present(100_000),
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[0], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 3,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Present(100_000),
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		// Capacity of 200 sats because this channel will be used by 3rd path as well.
		add_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[2], &privkeys[3], ChannelFeatures::from_le_bytes(id_to_feature_flags(5)), 5);
		update_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 5,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Present(200_000),
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		// Path via {node7, node2, node4} is channels {12, 13, 6, 11}.
		// Add 100 sats to the capacities of {12, 13}, because these channels
		// are also used for 3rd path. 100 sats for the rest. Total capacity: 100 sats.
		update_channel(&net_graph_msg_handler, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 12,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Present(200_000),
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[7], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 13,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Present(200_000),
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		update_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 6,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Present(100_000),
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[4], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 11,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Present(100_000),
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		// Path via {node7, node2} is channels {12, 13, 5}.
		// We already limited them to 200 sats (they are used twice for 100 sats).
		// Nothing to do here.

		{
			// Attempt to route more than available results in a failure.
			if let Err(LightningError{err, action: ErrorAction::IgnoreError}) = get_route(
					&our_id, &payment_params, &network_graph.read_only(), None, 350_000, 42, Arc::clone(&logger), &scorer, &random_seed_bytes) {
				assert_eq!(err, "Failed to find a sufficient route to the given destination");
			} else { panic!(); }
		}

		{
			// Now, attempt to route 300 sats (exact amount we can route).
			// Our algorithm should provide us with these 3 paths, 100 sats each.
			let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 300_000, 42, Arc::clone(&logger), &scorer, &random_seed_bytes).unwrap();
			assert_eq!(route.paths.len(), 3);

			let mut total_amount_paid_msat = 0;
			for path in &route.paths {
				assert_eq!(path.last().unwrap().pubkey, nodes[3]);
				total_amount_paid_msat += path.last().unwrap().fee_msat;
			}
			assert_eq!(total_amount_paid_msat, 300_000);
		}

	}

	#[test]
	fn mpp_cheaper_route_test() {
		let (secp_ctx, network_graph, net_graph_msg_handler, _, logger) = build_graph();
		let (our_privkey, our_id, privkeys, nodes) = get_nodes(&secp_ctx);
		let scorer = test_utils::TestScorer::with_penalty(0);
		let keys_manager = test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();
		let payment_params = PaymentParameters::from_node_id(nodes[3]).with_features(InvoiceFeatures::known());

		// This test checks that if we have two cheaper paths and one more expensive path,
		// so that liquidity-wise any 2 of 3 combination is sufficient,
		// two cheaper paths will be taken.
		// These paths have equal available liquidity.

		// We need a combination of 3 paths:
		// From our node to node3 via {node0, node2}, {node7, node2, node4} and {node7, node2}.
		// Note that these paths overlap (channels 5, 12, 13).
		// Each path will have 100 sats capacity, those channels which
		// are used twice will have 200 sats capacity.

		// Disable other potential paths.
		update_channel(&net_graph_msg_handler, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 2,
			timestamp: 2,
			flags: 2,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Present(100_000),
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 7,
			timestamp: 2,
			flags: 2,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Present(100_000),
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		// Path via {node0, node2} is channels {1, 3, 5}.
		update_channel(&net_graph_msg_handler, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 1,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Present(100_000),
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[0], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 3,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Present(100_000),
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		// Capacity of 200 sats because this channel will be used by 3rd path as well.
		add_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[2], &privkeys[3], ChannelFeatures::from_le_bytes(id_to_feature_flags(5)), 5);
		update_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 5,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Present(200_000),
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		// Path via {node7, node2, node4} is channels {12, 13, 6, 11}.
		// Add 100 sats to the capacities of {12, 13}, because these channels
		// are also used for 3rd path. 100 sats for the rest. Total capacity: 100 sats.
		update_channel(&net_graph_msg_handler, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 12,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Present(200_000),
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[7], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 13,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Present(200_000),
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		update_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 6,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Present(100_000),
			fee_base_msat: 1_000,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[4], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 11,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Present(100_000),
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		// Path via {node7, node2} is channels {12, 13, 5}.
		// We already limited them to 200 sats (they are used twice for 100 sats).
		// Nothing to do here.

		{
			// Now, attempt to route 180 sats.
			// Our algorithm should provide us with these 2 paths.
			let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 180_000, 42, Arc::clone(&logger), &scorer, &random_seed_bytes).unwrap();
			assert_eq!(route.paths.len(), 2);

			let mut total_value_transferred_msat = 0;
			let mut total_paid_msat = 0;
			for path in &route.paths {
				assert_eq!(path.last().unwrap().pubkey, nodes[3]);
				total_value_transferred_msat += path.last().unwrap().fee_msat;
				for hop in path {
					total_paid_msat += hop.fee_msat;
				}
			}
			// If we paid fee, this would be higher.
			assert_eq!(total_value_transferred_msat, 180_000);
			let total_fees_paid = total_paid_msat - total_value_transferred_msat;
			assert_eq!(total_fees_paid, 0);
		}
	}

	#[test]
	fn fees_on_mpp_route_test() {
		// This test makes sure that MPP algorithm properly takes into account
		// fees charged on the channels, by making the fees impactful:
		// if the fee is not properly accounted for, the behavior is different.
		let (secp_ctx, network_graph, net_graph_msg_handler, _, logger) = build_graph();
		let (our_privkey, our_id, privkeys, nodes) = get_nodes(&secp_ctx);
		let scorer = test_utils::TestScorer::with_penalty(0);
		let keys_manager = test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();
		let payment_params = PaymentParameters::from_node_id(nodes[3]).with_features(InvoiceFeatures::known());

		// We need a route consisting of 2 paths:
		// From our node to node3 via {node0, node2} and {node7, node2, node4}.
		// We will route 200 sats, Each path will have 100 sats capacity.

		// This test is not particularly stable: e.g.,
		// there's a way to route via {node0, node2, node4}.
		// It works while pathfinding is deterministic, but can be broken otherwise.
		// It's fine to ignore this concern for now.

		// Disable other potential paths.
		update_channel(&net_graph_msg_handler, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 2,
			timestamp: 2,
			flags: 2,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Present(100_000),
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		update_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 7,
			timestamp: 2,
			flags: 2,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Present(100_000),
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		// Path via {node0, node2} is channels {1, 3, 5}.
		update_channel(&net_graph_msg_handler, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 1,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Present(100_000),
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[0], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 3,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Present(100_000),
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		add_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[2], &privkeys[3], ChannelFeatures::from_le_bytes(id_to_feature_flags(5)), 5);
		update_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 5,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Present(100_000),
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		// Path via {node7, node2, node4} is channels {12, 13, 6, 11}.
		// All channels should be 100 sats capacity. But for the fee experiment,
		// we'll add absolute fee of 150 sats paid for the use channel 6 (paid to node2 on channel 13).
		// Since channel 12 allows to deliver only 250 sats to channel 13, channel 13 can transfer only
		// 100 sats (and pay 150 sats in fees for the use of channel 6),
		// so no matter how large are other channels,
		// the whole path will be limited by 100 sats with just these 2 conditions:
		// - channel 12 capacity is 250 sats
		// - fee for channel 6 is 150 sats
		// Let's test this by enforcing these 2 conditions and removing other limits.
		update_channel(&net_graph_msg_handler, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 12,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Present(250_000),
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[7], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 13,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Absent,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		update_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 6,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Absent,
			fee_base_msat: 150_000,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[4], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 11,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Absent,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		{
			// Attempt to route more than available results in a failure.
			if let Err(LightningError{err, action: ErrorAction::IgnoreError}) = get_route(
					&our_id, &payment_params, &network_graph.read_only(), None, 210_000, 42, Arc::clone(&logger), &scorer, &random_seed_bytes) {
				assert_eq!(err, "Failed to find a sufficient route to the given destination");
			} else { panic!(); }
		}

		{
			// Now, attempt to route 200 sats (exact amount we can route).
			let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 200_000, 42, Arc::clone(&logger), &scorer, &random_seed_bytes).unwrap();
			assert_eq!(route.paths.len(), 2);

			let mut total_amount_paid_msat = 0;
			for path in &route.paths {
				assert_eq!(path.last().unwrap().pubkey, nodes[3]);
				total_amount_paid_msat += path.last().unwrap().fee_msat;
			}
			assert_eq!(total_amount_paid_msat, 200_000);
			assert_eq!(route.get_total_fees(), 150_000);
		}
	}

	#[test]
	fn mpp_with_last_hops() {
		// Previously, if we tried to send an MPP payment to a destination which was only reachable
		// via a single last-hop route hint, we'd fail to route if we first collected routes
		// totaling close but not quite enough to fund the full payment.
		//
		// This was because we considered last-hop hints to have exactly the sought payment amount
		// instead of the amount we were trying to collect, needlessly limiting our path searching
		// at the very first hop.
		//
		// Specifically, this interacted with our "all paths must fund at least 5% of total target"
		// criterion to cause us to refuse all routes at the last hop hint which would be considered
		// to only have the remaining to-collect amount in available liquidity.
		//
		// This bug appeared in production in some specific channel configurations.
		let (secp_ctx, network_graph, net_graph_msg_handler, _, logger) = build_graph();
		let (our_privkey, our_id, privkeys, nodes) = get_nodes(&secp_ctx);
		let scorer = test_utils::TestScorer::with_penalty(0);
		let keys_manager = test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();
		let payment_params = PaymentParameters::from_node_id(PublicKey::from_slice(&[02; 33]).unwrap()).with_features(InvoiceFeatures::known())
			.with_route_hints(vec![RouteHint(vec![RouteHintHop {
				src_node_id: nodes[2],
				short_channel_id: 42,
				fees: RoutingFees { base_msat: 0, proportional_millionths: 0 },
				cltv_expiry_delta: 42,
				htlc_minimum_msat: None,
				htlc_maximum_msat: None,
			}])]);

		// Keep only two paths from us to nodes[2], both with a 99sat HTLC maximum, with one with
		// no fee and one with a 1msat fee. Previously, trying to route 100 sats to nodes[2] here
		// would first use the no-fee route and then fail to find a path along the second route as
		// we think we can only send up to 1 additional sat over the last-hop but refuse to as its
		// under 5% of our payment amount.
		update_channel(&net_graph_msg_handler, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 1,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: (5 << 4) | 5,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Present(99_000),
			fee_base_msat: u32::max_value(),
			fee_proportional_millionths: u32::max_value(),
			excess_data: Vec::new()
		});
		update_channel(&net_graph_msg_handler, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 2,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: (5 << 4) | 3,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Present(99_000),
			fee_base_msat: u32::max_value(),
			fee_proportional_millionths: u32::max_value(),
			excess_data: Vec::new()
		});
		update_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[1], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 4,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: (4 << 4) | 1,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Absent,
			fee_base_msat: 1,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[7], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 13,
			timestamp: 2,
			flags: 0|2, // Channel disabled
			cltv_expiry_delta: (13 << 4) | 1,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Absent,
			fee_base_msat: 0,
			fee_proportional_millionths: 2000000,
			excess_data: Vec::new()
		});

		// Get a route for 100 sats and check that we found the MPP route no problem and didn't
		// overpay at all.
		let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 100_000, 42, Arc::clone(&logger), &scorer, &random_seed_bytes).unwrap();
		assert_eq!(route.paths.len(), 2);
		// Paths are somewhat randomly ordered, but:
		// * the first is channel 2 (1 msat fee) -> channel 4 -> channel 42
		// * the second is channel 1 (0 fee, but 99 sat maximum) -> channel 3 -> channel 42
		assert_eq!(route.paths[0][0].short_channel_id, 2);
		assert_eq!(route.paths[0][0].fee_msat, 1);
		assert_eq!(route.paths[0][2].fee_msat, 1_000);
		assert_eq!(route.paths[1][0].short_channel_id, 1);
		assert_eq!(route.paths[1][0].fee_msat, 0);
		assert_eq!(route.paths[1][2].fee_msat, 99_000);
		assert_eq!(route.get_total_fees(), 1);
		assert_eq!(route.get_total_amount(), 100_000);
	}

	#[test]
	fn drop_lowest_channel_mpp_route_test() {
		// This test checks that low-capacity channel is dropped when after
		// path finding we realize that we found more capacity than we need.
		let (secp_ctx, network_graph, net_graph_msg_handler, _, logger) = build_graph();
		let (our_privkey, our_id, privkeys, nodes) = get_nodes(&secp_ctx);
		let scorer = test_utils::TestScorer::with_penalty(0);
		let keys_manager = test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();
		let payment_params = PaymentParameters::from_node_id(nodes[2]).with_features(InvoiceFeatures::known());

		// We need a route consisting of 3 paths:
		// From our node to node2 via node0, node7, node1 (three paths one hop each).

		// The first and the second paths should be sufficient, but the third should be
		// cheaper, so that we select it but drop later.

		// First, we set limits on these (previously unlimited) channels.
		// Their aggregate capacity will be 50 + 60 + 20 = 130 sats.

		// Path via node0 is channels {1, 3}. Limit them to 100 and 50 sats (total limit 50);
		update_channel(&net_graph_msg_handler, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 1,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Present(100_000),
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[0], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 3,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Present(50_000),
			fee_base_msat: 100,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		// Path via node7 is channels {12, 13}. Limit them to 60 and 60 sats (total limit 60);
		update_channel(&net_graph_msg_handler, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 12,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Present(60_000),
			fee_base_msat: 100,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[7], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 13,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Present(60_000),
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		// Path via node1 is channels {2, 4}. Limit them to 20 and 20 sats (total capacity 20 sats).
		update_channel(&net_graph_msg_handler, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 2,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Present(20_000),
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[1], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 4,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Present(20_000),
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		{
			// Attempt to route more than available results in a failure.
			if let Err(LightningError{err, action: ErrorAction::IgnoreError}) = get_route(
					&our_id, &payment_params, &network_graph.read_only(), None, 150_000, 42, Arc::clone(&logger), &scorer, &random_seed_bytes) {
				assert_eq!(err, "Failed to find a sufficient route to the given destination");
			} else { panic!(); }
		}

		{
			// Now, attempt to route 125 sats (just a bit below the capacity of 3 channels).
			// Our algorithm should provide us with these 3 paths.
			let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 125_000, 42, Arc::clone(&logger), &scorer, &random_seed_bytes).unwrap();
			assert_eq!(route.paths.len(), 3);
			let mut total_amount_paid_msat = 0;
			for path in &route.paths {
				assert_eq!(path.len(), 2);
				assert_eq!(path.last().unwrap().pubkey, nodes[2]);
				total_amount_paid_msat += path.last().unwrap().fee_msat;
			}
			assert_eq!(total_amount_paid_msat, 125_000);
		}

		{
			// Attempt to route without the last small cheap channel
			let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 90_000, 42, Arc::clone(&logger), &scorer, &random_seed_bytes).unwrap();
			assert_eq!(route.paths.len(), 2);
			let mut total_amount_paid_msat = 0;
			for path in &route.paths {
				assert_eq!(path.len(), 2);
				assert_eq!(path.last().unwrap().pubkey, nodes[2]);
				total_amount_paid_msat += path.last().unwrap().fee_msat;
			}
			assert_eq!(total_amount_paid_msat, 90_000);
		}
	}

	#[test]
	fn min_criteria_consistency() {
		// Test that we don't use an inconsistent metric between updating and walking nodes during
		// our Dijkstra's pass. In the initial version of MPP, the "best source" for a given node
		// was updated with a different criterion from the heap sorting, resulting in loops in
		// calculated paths. We test for that specific case here.

		// We construct a network that looks like this:
		//
		//            node2 -1(3)2- node3
		//              2          2
		//               (2)     (4)
		//                  1   1
		//    node1 -1(5)2- node4 -1(1)2- node6
		//    2
		//   (6)
		//	  1
		// our_node
		//
		// We create a loop on the side of our real path - our destination is node 6, with a
		// previous hop of node 4. From 4, the cheapest previous path is channel 2 from node 2,
		// followed by node 3 over channel 3. Thereafter, the cheapest next-hop is back to node 4
		// (this time over channel 4). Channel 4 has 0 htlc_minimum_msat whereas channel 1 (the
		// other channel with a previous-hop of node 4) has a high (but irrelevant to the overall
		// payment) htlc_minimum_msat. In the original algorithm, this resulted in node4's
		// "previous hop" being set to node 3, creating a loop in the path.
		let secp_ctx = Secp256k1::new();
		let logger = Arc::new(test_utils::TestLogger::new());
		let network = Arc::new(NetworkGraph::new(genesis_block(Network::Testnet).header.block_hash()));
		let net_graph_msg_handler = NetGraphMsgHandler::new(Arc::clone(&network), None, Arc::clone(&logger));
		let (our_privkey, our_id, privkeys, nodes) = get_nodes(&secp_ctx);
		let scorer = test_utils::TestScorer::with_penalty(0);
		let keys_manager = test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();
		let payment_params = PaymentParameters::from_node_id(nodes[6]);

		add_channel(&net_graph_msg_handler, &secp_ctx, &our_privkey, &privkeys[1], ChannelFeatures::from_le_bytes(id_to_feature_flags(6)), 6);
		update_channel(&net_graph_msg_handler, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 6,
			timestamp: 1,
			flags: 0,
			cltv_expiry_delta: (6 << 4) | 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Absent,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		add_or_update_node(&net_graph_msg_handler, &secp_ctx, &privkeys[1], NodeFeatures::from_le_bytes(id_to_feature_flags(1)), 0);

		add_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[1], &privkeys[4], ChannelFeatures::from_le_bytes(id_to_feature_flags(5)), 5);
		update_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[1], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 5,
			timestamp: 1,
			flags: 0,
			cltv_expiry_delta: (5 << 4) | 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Absent,
			fee_base_msat: 100,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		add_or_update_node(&net_graph_msg_handler, &secp_ctx, &privkeys[4], NodeFeatures::from_le_bytes(id_to_feature_flags(4)), 0);

		add_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[4], &privkeys[3], ChannelFeatures::from_le_bytes(id_to_feature_flags(4)), 4);
		update_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[4], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 4,
			timestamp: 1,
			flags: 0,
			cltv_expiry_delta: (4 << 4) | 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Absent,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		add_or_update_node(&net_graph_msg_handler, &secp_ctx, &privkeys[3], NodeFeatures::from_le_bytes(id_to_feature_flags(3)), 0);

		add_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[3], &privkeys[2], ChannelFeatures::from_le_bytes(id_to_feature_flags(3)), 3);
		update_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[3], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 3,
			timestamp: 1,
			flags: 0,
			cltv_expiry_delta: (3 << 4) | 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Absent,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		add_or_update_node(&net_graph_msg_handler, &secp_ctx, &privkeys[2], NodeFeatures::from_le_bytes(id_to_feature_flags(2)), 0);

		add_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[2], &privkeys[4], ChannelFeatures::from_le_bytes(id_to_feature_flags(2)), 2);
		update_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 2,
			timestamp: 1,
			flags: 0,
			cltv_expiry_delta: (2 << 4) | 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Absent,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		add_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[4], &privkeys[6], ChannelFeatures::from_le_bytes(id_to_feature_flags(1)), 1);
		update_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[4], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 1,
			timestamp: 1,
			flags: 0,
			cltv_expiry_delta: (1 << 4) | 0,
			htlc_minimum_msat: 100,
			htlc_maximum_msat: OptionalField::Absent,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		add_or_update_node(&net_graph_msg_handler, &secp_ctx, &privkeys[6], NodeFeatures::from_le_bytes(id_to_feature_flags(6)), 0);

		{
			// Now ensure the route flows simply over nodes 1 and 4 to 6.
			let route = get_route(&our_id, &payment_params, &network.read_only(), None, 10_000, 42, Arc::clone(&logger), &scorer, &random_seed_bytes).unwrap();
			assert_eq!(route.paths.len(), 1);
			assert_eq!(route.paths[0].len(), 3);

			assert_eq!(route.paths[0][0].pubkey, nodes[1]);
			assert_eq!(route.paths[0][0].short_channel_id, 6);
			assert_eq!(route.paths[0][0].fee_msat, 100);
			assert_eq!(route.paths[0][0].cltv_expiry_delta, (5 << 4) | 0);
			assert_eq!(route.paths[0][0].node_features.le_flags(), &id_to_feature_flags(1));
			assert_eq!(route.paths[0][0].channel_features.le_flags(), &id_to_feature_flags(6));

			assert_eq!(route.paths[0][1].pubkey, nodes[4]);
			assert_eq!(route.paths[0][1].short_channel_id, 5);
			assert_eq!(route.paths[0][1].fee_msat, 0);
			assert_eq!(route.paths[0][1].cltv_expiry_delta, (1 << 4) | 0);
			assert_eq!(route.paths[0][1].node_features.le_flags(), &id_to_feature_flags(4));
			assert_eq!(route.paths[0][1].channel_features.le_flags(), &id_to_feature_flags(5));

			assert_eq!(route.paths[0][2].pubkey, nodes[6]);
			assert_eq!(route.paths[0][2].short_channel_id, 1);
			assert_eq!(route.paths[0][2].fee_msat, 10_000);
			assert_eq!(route.paths[0][2].cltv_expiry_delta, 42);
			assert_eq!(route.paths[0][2].node_features.le_flags(), &id_to_feature_flags(6));
			assert_eq!(route.paths[0][2].channel_features.le_flags(), &id_to_feature_flags(1));
		}
	}


	#[test]
	fn exact_fee_liquidity_limit() {
		// Test that if, while walking the graph, we find a hop that has exactly enough liquidity
		// for us, including later hop fees, we take it. In the first version of our MPP algorithm
		// we calculated fees on a higher value, resulting in us ignoring such paths.
		let (secp_ctx, network_graph, net_graph_msg_handler, _, logger) = build_graph();
		let (our_privkey, our_id, _, nodes) = get_nodes(&secp_ctx);
		let scorer = test_utils::TestScorer::with_penalty(0);
		let keys_manager = test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();
		let payment_params = PaymentParameters::from_node_id(nodes[2]);

		// We modify the graph to set the htlc_maximum of channel 2 to below the value we wish to
		// send.
		update_channel(&net_graph_msg_handler, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 2,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Present(85_000),
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		update_channel(&net_graph_msg_handler, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 12,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: (4 << 4) | 1,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Present(270_000),
			fee_base_msat: 0,
			fee_proportional_millionths: 1000000,
			excess_data: Vec::new()
		});

		{
			// Now, attempt to route 90 sats, which is exactly 90 sats at the last hop, plus the
			// 200% fee charged channel 13 in the 1-to-2 direction.
			let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 90_000, 42, Arc::clone(&logger), &scorer, &random_seed_bytes).unwrap();
			assert_eq!(route.paths.len(), 1);
			assert_eq!(route.paths[0].len(), 2);

			assert_eq!(route.paths[0][0].pubkey, nodes[7]);
			assert_eq!(route.paths[0][0].short_channel_id, 12);
			assert_eq!(route.paths[0][0].fee_msat, 90_000*2);
			assert_eq!(route.paths[0][0].cltv_expiry_delta, (13 << 4) | 1);
			assert_eq!(route.paths[0][0].node_features.le_flags(), &id_to_feature_flags(8));
			assert_eq!(route.paths[0][0].channel_features.le_flags(), &id_to_feature_flags(12));

			assert_eq!(route.paths[0][1].pubkey, nodes[2]);
			assert_eq!(route.paths[0][1].short_channel_id, 13);
			assert_eq!(route.paths[0][1].fee_msat, 90_000);
			assert_eq!(route.paths[0][1].cltv_expiry_delta, 42);
			assert_eq!(route.paths[0][1].node_features.le_flags(), &id_to_feature_flags(3));
			assert_eq!(route.paths[0][1].channel_features.le_flags(), &id_to_feature_flags(13));
		}
	}

	#[test]
	fn htlc_max_reduction_below_min() {
		// Test that if, while walking the graph, we reduce the value being sent to meet an
		// htlc_maximum_msat, we don't end up undershooting a later htlc_minimum_msat. In the
		// initial version of MPP we'd accept such routes but reject them while recalculating fees,
		// resulting in us thinking there is no possible path, even if other paths exist.
		let (secp_ctx, network_graph, net_graph_msg_handler, _, logger) = build_graph();
		let (our_privkey, our_id, privkeys, nodes) = get_nodes(&secp_ctx);
		let scorer = test_utils::TestScorer::with_penalty(0);
		let keys_manager = test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();
		let payment_params = PaymentParameters::from_node_id(nodes[2]).with_features(InvoiceFeatures::known());

		// We modify the graph to set the htlc_minimum of channel 2 and 4 as needed - channel 2
		// gets an htlc_maximum_msat of 80_000 and channel 4 an htlc_minimum_msat of 90_000. We
		// then try to send 90_000.
		update_channel(&net_graph_msg_handler, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 2,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Present(80_000),
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[1], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 4,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: (4 << 4) | 1,
			htlc_minimum_msat: 90_000,
			htlc_maximum_msat: OptionalField::Absent,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		{
			// Now, attempt to route 90 sats, hitting the htlc_minimum on channel 4, but
			// overshooting the htlc_maximum on channel 2. Thus, we should pick the (absurdly
			// expensive) channels 12-13 path.
			let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 90_000, 42, Arc::clone(&logger), &scorer, &random_seed_bytes).unwrap();
			assert_eq!(route.paths.len(), 1);
			assert_eq!(route.paths[0].len(), 2);

			assert_eq!(route.paths[0][0].pubkey, nodes[7]);
			assert_eq!(route.paths[0][0].short_channel_id, 12);
			assert_eq!(route.paths[0][0].fee_msat, 90_000*2);
			assert_eq!(route.paths[0][0].cltv_expiry_delta, (13 << 4) | 1);
			assert_eq!(route.paths[0][0].node_features.le_flags(), &id_to_feature_flags(8));
			assert_eq!(route.paths[0][0].channel_features.le_flags(), &id_to_feature_flags(12));

			assert_eq!(route.paths[0][1].pubkey, nodes[2]);
			assert_eq!(route.paths[0][1].short_channel_id, 13);
			assert_eq!(route.paths[0][1].fee_msat, 90_000);
			assert_eq!(route.paths[0][1].cltv_expiry_delta, 42);
			assert_eq!(route.paths[0][1].node_features.le_flags(), InvoiceFeatures::known().le_flags());
			assert_eq!(route.paths[0][1].channel_features.le_flags(), &id_to_feature_flags(13));
		}
	}

	#[test]
	fn multiple_direct_first_hops() {
		// Previously we'd only ever considered one first hop path per counterparty.
		// However, as we don't restrict users to one channel per peer, we really need to support
		// looking at all first hop paths.
		// Here we test that we do not ignore all-but-the-last first hop paths per counterparty (as
		// we used to do by overwriting the `first_hop_targets` hashmap entry) and that we can MPP
		// route over multiple channels with the same first hop.
		let secp_ctx = Secp256k1::new();
		let (_, our_id, _, nodes) = get_nodes(&secp_ctx);
		let logger = Arc::new(test_utils::TestLogger::new());
		let network_graph = NetworkGraph::new(genesis_block(Network::Testnet).header.block_hash());
		let scorer = test_utils::TestScorer::with_penalty(0);
		let payment_params = PaymentParameters::from_node_id(nodes[0]).with_features(InvoiceFeatures::known());
		let keys_manager = test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();

		{
			let route = get_route(&our_id, &payment_params, &network_graph.read_only(), Some(&[
				&get_channel_details(Some(3), nodes[0], InitFeatures::known(), 200_000),
				&get_channel_details(Some(2), nodes[0], InitFeatures::known(), 10_000),
			]), 100_000, 42, Arc::clone(&logger), &scorer, &random_seed_bytes).unwrap();
			assert_eq!(route.paths.len(), 1);
			assert_eq!(route.paths[0].len(), 1);

			assert_eq!(route.paths[0][0].pubkey, nodes[0]);
			assert_eq!(route.paths[0][0].short_channel_id, 3);
			assert_eq!(route.paths[0][0].fee_msat, 100_000);
		}
		{
			let route = get_route(&our_id, &payment_params, &network_graph.read_only(), Some(&[
				&get_channel_details(Some(3), nodes[0], InitFeatures::known(), 50_000),
				&get_channel_details(Some(2), nodes[0], InitFeatures::known(), 50_000),
			]), 100_000, 42, Arc::clone(&logger), &scorer, &random_seed_bytes).unwrap();
			assert_eq!(route.paths.len(), 2);
			assert_eq!(route.paths[0].len(), 1);
			assert_eq!(route.paths[1].len(), 1);

			assert_eq!(route.paths[0][0].pubkey, nodes[0]);
			assert_eq!(route.paths[0][0].short_channel_id, 3);
			assert_eq!(route.paths[0][0].fee_msat, 50_000);

			assert_eq!(route.paths[1][0].pubkey, nodes[0]);
			assert_eq!(route.paths[1][0].short_channel_id, 2);
			assert_eq!(route.paths[1][0].fee_msat, 50_000);
		}

		{
			// If we have a bunch of outbound channels to the same node, where most are not
			// sufficient to pay the full payment, but one is, we should default to just using the
			// one single channel that has sufficient balance, avoiding MPP.
			//
			// If we have several options above the 3xpayment value threshold, we should pick the
			// smallest of them, avoiding further fragmenting our available outbound balance to
			// this node.
			let route = get_route(&our_id, &payment_params, &network_graph.read_only(), Some(&[
				&get_channel_details(Some(2), nodes[0], InitFeatures::known(), 50_000),
				&get_channel_details(Some(3), nodes[0], InitFeatures::known(), 50_000),
				&get_channel_details(Some(5), nodes[0], InitFeatures::known(), 50_000),
				&get_channel_details(Some(6), nodes[0], InitFeatures::known(), 300_000),
				&get_channel_details(Some(7), nodes[0], InitFeatures::known(), 50_000),
				&get_channel_details(Some(8), nodes[0], InitFeatures::known(), 50_000),
				&get_channel_details(Some(9), nodes[0], InitFeatures::known(), 50_000),
				&get_channel_details(Some(4), nodes[0], InitFeatures::known(), 1_000_000),
			]), 100_000, 42, Arc::clone(&logger), &scorer, &random_seed_bytes).unwrap();
			assert_eq!(route.paths.len(), 1);
			assert_eq!(route.paths[0].len(), 1);

			assert_eq!(route.paths[0][0].pubkey, nodes[0]);
			assert_eq!(route.paths[0][0].short_channel_id, 6);
			assert_eq!(route.paths[0][0].fee_msat, 100_000);
		}
	}

	#[test]
	fn prefers_shorter_route_with_higher_fees() {
		let (secp_ctx, network_graph, _, _, logger) = build_graph();
		let (_, our_id, _, nodes) = get_nodes(&secp_ctx);
		let payment_params = PaymentParameters::from_node_id(nodes[6]).with_route_hints(last_hops(&nodes));

		// Without penalizing each hop 100 msats, a longer path with lower fees is chosen.
		let scorer = test_utils::TestScorer::with_penalty(0);
		let keys_manager = test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();
		let route = get_route(
			&our_id, &payment_params, &network_graph.read_only(), None, 100, 42,
			Arc::clone(&logger), &scorer, &random_seed_bytes
		).unwrap();
		let path = route.paths[0].iter().map(|hop| hop.short_channel_id).collect::<Vec<_>>();

		assert_eq!(route.get_total_fees(), 100);
		assert_eq!(route.get_total_amount(), 100);
		assert_eq!(path, vec![2, 4, 6, 11, 8]);

		// Applying a 100 msat penalty to each hop results in taking channels 7 and 10 to nodes[6]
		// from nodes[2] rather than channel 6, 11, and 8, even though the longer path is cheaper.
		let scorer = test_utils::TestScorer::with_penalty(100);
		let route = get_route(
			&our_id, &payment_params, &network_graph.read_only(), None, 100, 42,
			Arc::clone(&logger), &scorer, &random_seed_bytes
		).unwrap();
		let path = route.paths[0].iter().map(|hop| hop.short_channel_id).collect::<Vec<_>>();

		assert_eq!(route.get_total_fees(), 300);
		assert_eq!(route.get_total_amount(), 100);
		assert_eq!(path, vec![2, 4, 7, 10]);
	}

	struct BadChannelScorer {
		short_channel_id: u64,
	}

	#[cfg(c_bindings)]
	impl Writeable for BadChannelScorer {
		fn write<W: Writer>(&self, _w: &mut W) -> Result<(), ::io::Error> { unimplemented!() }
	}
	impl Score for BadChannelScorer {
		fn channel_penalty_msat(&self, short_channel_id: u64, _: &NodeId, _: &NodeId, _: ChannelUsage) -> u64 {
			if short_channel_id == self.short_channel_id { u64::max_value() } else { 0 }
		}

		fn payment_path_failed(&mut self, _path: &[&RouteHop], _short_channel_id: u64) {}
		fn payment_path_successful(&mut self, _path: &[&RouteHop]) {}
	}

	struct BadNodeScorer {
		node_id: NodeId,
	}

	#[cfg(c_bindings)]
	impl Writeable for BadNodeScorer {
		fn write<W: Writer>(&self, _w: &mut W) -> Result<(), ::io::Error> { unimplemented!() }
	}

	impl Score for BadNodeScorer {
		fn channel_penalty_msat(&self, _: u64, _: &NodeId, target: &NodeId, _: ChannelUsage) -> u64 {
			if *target == self.node_id { u64::max_value() } else { 0 }
		}

		fn payment_path_failed(&mut self, _path: &[&RouteHop], _short_channel_id: u64) {}
		fn payment_path_successful(&mut self, _path: &[&RouteHop]) {}
	}

	#[test]
	fn avoids_routing_through_bad_channels_and_nodes() {
		let (secp_ctx, network, _, _, logger) = build_graph();
		let (_, our_id, _, nodes) = get_nodes(&secp_ctx);
		let payment_params = PaymentParameters::from_node_id(nodes[6]).with_route_hints(last_hops(&nodes));
		let network_graph = network.read_only();

		// A path to nodes[6] exists when no penalties are applied to any channel.
		let scorer = test_utils::TestScorer::with_penalty(0);
		let keys_manager = test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();
		let route = get_route(
			&our_id, &payment_params, &network_graph, None, 100, 42,
			Arc::clone(&logger), &scorer, &random_seed_bytes
		).unwrap();
		let path = route.paths[0].iter().map(|hop| hop.short_channel_id).collect::<Vec<_>>();

		assert_eq!(route.get_total_fees(), 100);
		assert_eq!(route.get_total_amount(), 100);
		assert_eq!(path, vec![2, 4, 6, 11, 8]);

		// A different path to nodes[6] exists if channel 6 cannot be routed over.
		let scorer = BadChannelScorer { short_channel_id: 6 };
		let route = get_route(
			&our_id, &payment_params, &network_graph, None, 100, 42,
			Arc::clone(&logger), &scorer, &random_seed_bytes
		).unwrap();
		let path = route.paths[0].iter().map(|hop| hop.short_channel_id).collect::<Vec<_>>();

		assert_eq!(route.get_total_fees(), 300);
		assert_eq!(route.get_total_amount(), 100);
		assert_eq!(path, vec![2, 4, 7, 10]);

		// A path to nodes[6] does not exist if nodes[2] cannot be routed through.
		let scorer = BadNodeScorer { node_id: NodeId::from_pubkey(&nodes[2]) };
		match get_route(
			&our_id, &payment_params, &network_graph, None, 100, 42,
			Arc::clone(&logger), &scorer, &random_seed_bytes
		) {
			Err(LightningError { err, .. } ) => {
				assert_eq!(err, "Failed to find a path to the given destination");
			},
			Ok(_) => panic!("Expected error"),
		}
	}

	#[test]
	fn total_fees_single_path() {
		let route = Route {
			paths: vec![vec![
				RouteHop {
					pubkey: PublicKey::from_slice(&hex::decode("02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619").unwrap()[..]).unwrap(),
					channel_features: ChannelFeatures::empty(), node_features: NodeFeatures::empty(),
					short_channel_id: 0, fee_msat: 100, cltv_expiry_delta: 0
				},
				RouteHop {
					pubkey: PublicKey::from_slice(&hex::decode("0324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c").unwrap()[..]).unwrap(),
					channel_features: ChannelFeatures::empty(), node_features: NodeFeatures::empty(),
					short_channel_id: 0, fee_msat: 150, cltv_expiry_delta: 0
				},
				RouteHop {
					pubkey: PublicKey::from_slice(&hex::decode("027f31ebc5462c1fdce1b737ecff52d37d75dea43ce11c74d25aa297165faa2007").unwrap()[..]).unwrap(),
					channel_features: ChannelFeatures::empty(), node_features: NodeFeatures::empty(),
					short_channel_id: 0, fee_msat: 225, cltv_expiry_delta: 0
				},
			]],
			payment_params: None,
		};

		assert_eq!(route.get_total_fees(), 250);
		assert_eq!(route.get_total_amount(), 225);
	}

	#[test]
	fn total_fees_multi_path() {
		let route = Route {
			paths: vec![vec![
				RouteHop {
					pubkey: PublicKey::from_slice(&hex::decode("02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619").unwrap()[..]).unwrap(),
					channel_features: ChannelFeatures::empty(), node_features: NodeFeatures::empty(),
					short_channel_id: 0, fee_msat: 100, cltv_expiry_delta: 0
				},
				RouteHop {
					pubkey: PublicKey::from_slice(&hex::decode("0324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c").unwrap()[..]).unwrap(),
					channel_features: ChannelFeatures::empty(), node_features: NodeFeatures::empty(),
					short_channel_id: 0, fee_msat: 150, cltv_expiry_delta: 0
				},
			],vec![
				RouteHop {
					pubkey: PublicKey::from_slice(&hex::decode("02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619").unwrap()[..]).unwrap(),
					channel_features: ChannelFeatures::empty(), node_features: NodeFeatures::empty(),
					short_channel_id: 0, fee_msat: 100, cltv_expiry_delta: 0
				},
				RouteHop {
					pubkey: PublicKey::from_slice(&hex::decode("0324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c").unwrap()[..]).unwrap(),
					channel_features: ChannelFeatures::empty(), node_features: NodeFeatures::empty(),
					short_channel_id: 0, fee_msat: 150, cltv_expiry_delta: 0
				},
			]],
			payment_params: None,
		};

		assert_eq!(route.get_total_fees(), 200);
		assert_eq!(route.get_total_amount(), 300);
	}

	#[test]
	fn total_empty_route_no_panic() {
		// In an earlier version of `Route::get_total_fees` and `Route::get_total_amount`, they
		// would both panic if the route was completely empty. We test to ensure they return 0
		// here, even though its somewhat nonsensical as a route.
		let route = Route { paths: Vec::new(), payment_params: None };

		assert_eq!(route.get_total_fees(), 0);
		assert_eq!(route.get_total_amount(), 0);
	}

	#[test]
	fn limits_total_cltv_delta() {
		let (secp_ctx, network, _, _, logger) = build_graph();
		let (_, our_id, _, nodes) = get_nodes(&secp_ctx);
		let network_graph = network.read_only();

		let scorer = test_utils::TestScorer::with_penalty(0);

		// Make sure that generally there is at least one route available
		let feasible_max_total_cltv_delta = 1008;
		let feasible_payment_params = PaymentParameters::from_node_id(nodes[6]).with_route_hints(last_hops(&nodes))
			.with_max_total_cltv_expiry_delta(feasible_max_total_cltv_delta);
		let keys_manager = test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();
		let route = get_route(&our_id, &feasible_payment_params, &network_graph, None, 100, 0, Arc::clone(&logger), &scorer, &random_seed_bytes).unwrap();
		let path = route.paths[0].iter().map(|hop| hop.short_channel_id).collect::<Vec<_>>();
		assert_ne!(path.len(), 0);

		// But not if we exclude all paths on the basis of their accumulated CLTV delta
		let fail_max_total_cltv_delta = 23;
		let fail_payment_params = PaymentParameters::from_node_id(nodes[6]).with_route_hints(last_hops(&nodes))
			.with_max_total_cltv_expiry_delta(fail_max_total_cltv_delta);
		match get_route(&our_id, &fail_payment_params, &network_graph, None, 100, 0, Arc::clone(&logger), &scorer, &random_seed_bytes)
		{
			Err(LightningError { err, .. } ) => {
				assert_eq!(err, "Failed to find a path to the given destination");
			},
			Ok(_) => panic!("Expected error"),
		}
	}

	#[test]
	fn limits_path_length() {
		let (secp_ctx, network, _, _, logger) = build_line_graph();
		let (_, our_id, _, nodes) = get_nodes(&secp_ctx);
		let network_graph = network.read_only();

		let scorer = test_utils::TestScorer::with_penalty(0);
		let keys_manager = test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();

		// First check we can actually create a long route on this graph.
		let feasible_payment_params = PaymentParameters::from_node_id(nodes[18]);
		let route = get_route(&our_id, &feasible_payment_params, &network_graph, None, 100, 0,
			Arc::clone(&logger), &scorer, &random_seed_bytes).unwrap();
		let path = route.paths[0].iter().map(|hop| hop.short_channel_id).collect::<Vec<_>>();
		assert!(path.len() == MAX_PATH_LENGTH_ESTIMATE.into());

		// But we can't create a path surpassing the MAX_PATH_LENGTH_ESTIMATE limit.
		let fail_payment_params = PaymentParameters::from_node_id(nodes[19]);
		match get_route(&our_id, &fail_payment_params, &network_graph, None, 100, 0,
			Arc::clone(&logger), &scorer, &random_seed_bytes)
		{
			Err(LightningError { err, .. } ) => {
				assert_eq!(err, "Failed to find a path to the given destination");
			},
			Ok(_) => panic!("Expected error"),
		}
	}

	#[test]
	fn adds_and_limits_cltv_offset() {
		let (secp_ctx, network_graph, _, _, logger) = build_graph();
		let (_, our_id, _, nodes) = get_nodes(&secp_ctx);

		let scorer = test_utils::TestScorer::with_penalty(0);

		let payment_params = PaymentParameters::from_node_id(nodes[6]).with_route_hints(last_hops(&nodes));
		let keys_manager = test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();
		let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 100, 42, Arc::clone(&logger), &scorer, &random_seed_bytes).unwrap();
		assert_eq!(route.paths.len(), 1);

		let cltv_expiry_deltas_before = route.paths[0].iter().map(|h| h.cltv_expiry_delta).collect::<Vec<u32>>();

		// Check whether the offset added to the last hop by default is in [1 .. DEFAULT_MAX_TOTAL_CLTV_EXPIRY_DELTA]
		let mut route_default = route.clone();
		add_random_cltv_offset(&mut route_default, &payment_params, &network_graph.read_only(), &random_seed_bytes);
		let cltv_expiry_deltas_default = route_default.paths[0].iter().map(|h| h.cltv_expiry_delta).collect::<Vec<u32>>();
		assert_eq!(cltv_expiry_deltas_before.split_last().unwrap().1, cltv_expiry_deltas_default.split_last().unwrap().1);
		assert!(cltv_expiry_deltas_default.last() > cltv_expiry_deltas_before.last());
		assert!(cltv_expiry_deltas_default.last().unwrap() <= &DEFAULT_MAX_TOTAL_CLTV_EXPIRY_DELTA);

		// Check that no offset is added when we restrict the max_total_cltv_expiry_delta
		let mut route_limited = route.clone();
		let limited_max_total_cltv_expiry_delta = cltv_expiry_deltas_before.iter().sum();
		let limited_payment_params = payment_params.with_max_total_cltv_expiry_delta(limited_max_total_cltv_expiry_delta);
		add_random_cltv_offset(&mut route_limited, &limited_payment_params, &network_graph.read_only(), &random_seed_bytes);
		let cltv_expiry_deltas_limited = route_limited.paths[0].iter().map(|h| h.cltv_expiry_delta).collect::<Vec<u32>>();
		assert_eq!(cltv_expiry_deltas_before, cltv_expiry_deltas_limited);
	}

	#[test]
	fn adds_plausible_cltv_offset() {
		let (secp_ctx, network, _, _, logger) = build_graph();
		let (_, our_id, _, nodes) = get_nodes(&secp_ctx);
		let network_graph = network.read_only();
		let network_nodes = network_graph.nodes();
		let network_channels = network_graph.channels();
		let scorer = test_utils::TestScorer::with_penalty(0);
		let payment_params = PaymentParameters::from_node_id(nodes[3]);
		let keys_manager = test_utils::TestKeysInterface::new(&[4u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();

		let mut route = get_route(&our_id, &payment_params, &network_graph, None, 100, 0,
								  Arc::clone(&logger), &scorer, &random_seed_bytes).unwrap();
		add_random_cltv_offset(&mut route, &payment_params, &network_graph, &random_seed_bytes);

		let mut path_plausibility = vec![];

		for p in route.paths {
			// 1. Select random observation point
			let mut prng = ChaCha20::new(&random_seed_bytes, &[0u8; 12]);
			let mut random_bytes = [0u8; ::core::mem::size_of::<usize>()];

			prng.process_in_place(&mut random_bytes);
			let random_path_index = usize::from_be_bytes(random_bytes).wrapping_rem(p.len());
			let observation_point = NodeId::from_pubkey(&p.get(random_path_index).unwrap().pubkey);

			// 2. Calculate what CLTV expiry delta we would observe there
			let observed_cltv_expiry_delta: u32 = p[random_path_index..].iter().map(|h| h.cltv_expiry_delta).sum();

			// 3. Starting from the observation point, find candidate paths
			let mut candidates: VecDeque<(NodeId, Vec<u32>)> = VecDeque::new();
			candidates.push_back((observation_point, vec![]));

			let mut found_plausible_candidate = false;

			'candidate_loop: while let Some((cur_node_id, cur_path_cltv_deltas)) = candidates.pop_front() {
				if let Some(remaining) = observed_cltv_expiry_delta.checked_sub(cur_path_cltv_deltas.iter().sum::<u32>()) {
					if remaining == 0 || remaining.wrapping_rem(40) == 0 || remaining.wrapping_rem(144) == 0 {
						found_plausible_candidate = true;
						break 'candidate_loop;
					}
				}

				if let Some(cur_node) = network_nodes.get(&cur_node_id) {
					for channel_id in &cur_node.channels {
						if let Some(channel_info) = network_channels.get(&channel_id) {
							if let Some((dir_info, next_id)) = channel_info.as_directed_from(&cur_node_id) {
								if let Some(channel_update_info) = dir_info.direction() {
									let next_cltv_expiry_delta = channel_update_info.cltv_expiry_delta as u32;
									if cur_path_cltv_deltas.iter().sum::<u32>()
										.saturating_add(next_cltv_expiry_delta) <= observed_cltv_expiry_delta {
										let mut new_path_cltv_deltas = cur_path_cltv_deltas.clone();
										new_path_cltv_deltas.push(next_cltv_expiry_delta);
										candidates.push_back((*next_id, new_path_cltv_deltas));
									}
								}
							}
						}
					}
				}
			}

			path_plausibility.push(found_plausible_candidate);
		}
		assert!(path_plausibility.iter().all(|x| *x));
	}

	#[test]
	fn builds_correct_path_from_hops() {
		let (secp_ctx, network, _, _, logger) = build_graph();
		let (_, our_id, _, nodes) = get_nodes(&secp_ctx);
		let network_graph = network.read_only();

		let keys_manager = test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();

		let payment_params = PaymentParameters::from_node_id(nodes[3]);
		let hops = [nodes[1], nodes[2], nodes[4], nodes[3]];
		let route = build_route_from_hops_internal(&our_id, &hops, &payment_params,
			 &network_graph, 100, 0, Arc::clone(&logger), &random_seed_bytes).unwrap();
		let route_hop_pubkeys = route.paths[0].iter().map(|hop| hop.pubkey).collect::<Vec<_>>();
		assert_eq!(hops.len(), route.paths[0].len());
		for (idx, hop_pubkey) in hops.iter().enumerate() {
			assert!(*hop_pubkey == route_hop_pubkeys[idx]);
		}
	}

	#[cfg(not(feature = "no-std"))]
	pub(super) fn random_init_seed() -> u64 {
		// Because the default HashMap in std pulls OS randomness, we can use it as a (bad) RNG.
		use core::hash::{BuildHasher, Hasher};
		let seed = std::collections::hash_map::RandomState::new().build_hasher().finish();
		println!("Using seed of {}", seed);
		seed
	}
	#[cfg(not(feature = "no-std"))]
	use util::ser::Readable;

	#[test]
	#[cfg(not(feature = "no-std"))]
	fn generate_routes() {
		use routing::scoring::{ProbabilisticScorer, ProbabilisticScoringParameters};

		let mut d = match super::test_utils::get_route_file() {
			Ok(f) => f,
			Err(e) => {
				eprintln!("{}", e);
				return;
			},
		};
		let graph = NetworkGraph::read(&mut d).unwrap();
		let keys_manager = test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();

		// First, get 100 (source, destination) pairs for which route-getting actually succeeds...
		let mut seed = random_init_seed() as usize;
		let nodes = graph.read_only().nodes().clone();
		'load_endpoints: for _ in 0..10 {
			loop {
				seed = seed.overflowing_mul(0xdeadbeef).0;
				let src = &PublicKey::from_slice(nodes.keys().skip(seed % nodes.len()).next().unwrap().as_slice()).unwrap();
				seed = seed.overflowing_mul(0xdeadbeef).0;
				let dst = PublicKey::from_slice(nodes.keys().skip(seed % nodes.len()).next().unwrap().as_slice()).unwrap();
				let payment_params = PaymentParameters::from_node_id(dst);
				let amt = seed as u64 % 200_000_000;
				let params = ProbabilisticScoringParameters::default();
				let logger = test_utils::TestLogger::new();
				let scorer = ProbabilisticScorer::new(params, &graph, &logger);
				if get_route(src, &payment_params, &graph.read_only(), None, amt, 42, &logger, &scorer, &random_seed_bytes).is_ok() {
					continue 'load_endpoints;
				}
			}
		}
	}

	#[test]
	#[cfg(not(feature = "no-std"))]
	fn generate_routes_mpp() {
		use routing::scoring::{ProbabilisticScorer, ProbabilisticScoringParameters};

		let mut d = match super::test_utils::get_route_file() {
			Ok(f) => f,
			Err(e) => {
				eprintln!("{}", e);
				return;
			},
		};
		let graph = NetworkGraph::read(&mut d).unwrap();
		let keys_manager = test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();

		// First, get 100 (source, destination) pairs for which route-getting actually succeeds...
		let mut seed = random_init_seed() as usize;
		let nodes = graph.read_only().nodes().clone();
		'load_endpoints: for _ in 0..10 {
			loop {
				seed = seed.overflowing_mul(0xdeadbeef).0;
				let src = &PublicKey::from_slice(nodes.keys().skip(seed % nodes.len()).next().unwrap().as_slice()).unwrap();
				seed = seed.overflowing_mul(0xdeadbeef).0;
				let dst = PublicKey::from_slice(nodes.keys().skip(seed % nodes.len()).next().unwrap().as_slice()).unwrap();
				let payment_params = PaymentParameters::from_node_id(dst).with_features(InvoiceFeatures::known());
				let amt = seed as u64 % 200_000_000;
				let params = ProbabilisticScoringParameters::default();
				let logger = test_utils::TestLogger::new();
				let scorer = ProbabilisticScorer::new(params, &graph, &logger);
				if get_route(src, &payment_params, &graph.read_only(), None, amt, 42, &logger, &scorer, &random_seed_bytes).is_ok() {
					continue 'load_endpoints;
				}
			}
		}
	}
}

#[cfg(all(test, not(feature = "no-std")))]
pub(crate) mod test_utils {
	use std::fs::File;
	/// Tries to open a network graph file, or panics with a URL to fetch it.
	pub(crate) fn get_route_file() -> Result<std::fs::File, &'static str> {
		let res = File::open("net_graph-2021-05-31.bin") // By default we're run in RL/lightning
			.or_else(|_| File::open("lightning/net_graph-2021-05-31.bin")) // We may be run manually in RL/
			.or_else(|_| { // Fall back to guessing based on the binary location
				// path is likely something like .../rust-lightning/target/debug/deps/lightning-...
				let mut path = std::env::current_exe().unwrap();
				path.pop(); // lightning-...
				path.pop(); // deps
				path.pop(); // debug
				path.pop(); // target
				path.push("lightning");
				path.push("net_graph-2021-05-31.bin");
				eprintln!("{}", path.to_str().unwrap());
				File::open(path)
			})
		.map_err(|_| "Please fetch https://bitcoin.ninja/ldk-net_graph-v0.0.15-2021-05-31.bin and place it at lightning/net_graph-2021-05-31.bin");
		#[cfg(require_route_graph_test)]
		return Ok(res.unwrap());
		#[cfg(not(require_route_graph_test))]
		return res;
	}
}

#[cfg(all(test, feature = "_bench_unstable", not(feature = "no-std")))]
mod benches {
	use super::*;
	use bitcoin::hashes::Hash;
	use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
	use chain::transaction::OutPoint;
	use chain::keysinterface::{KeysManager,KeysInterface};
	use ln::channelmanager::{ChannelCounterparty, ChannelDetails};
	use ln::features::{InitFeatures, InvoiceFeatures};
	use routing::scoring::{FixedPenaltyScorer, ProbabilisticScorer, ProbabilisticScoringParameters, Scorer};
	use util::logger::{Logger, Record};
	use util::test_utils::TestLogger;

	use test::Bencher;

	struct DummyLogger {}
	impl Logger for DummyLogger {
		fn log(&self, _record: &Record) {}
	}

	fn read_network_graph() -> NetworkGraph {
		let mut d = test_utils::get_route_file().unwrap();
		NetworkGraph::read(&mut d).unwrap()
	}

	fn payer_pubkey() -> PublicKey {
		let secp_ctx = Secp256k1::new();
		PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[42; 32]).unwrap())
	}

	#[inline]
	fn first_hop(node_id: PublicKey) -> ChannelDetails {
		ChannelDetails {
			channel_id: [0; 32],
			counterparty: ChannelCounterparty {
				features: InitFeatures::known(),
				node_id,
				unspendable_punishment_reserve: 0,
				forwarding_info: None,
				outbound_htlc_minimum_msat: None,
				outbound_htlc_maximum_msat: None,
			},
			funding_txo: Some(OutPoint {
				txid: bitcoin::Txid::from_slice(&[0; 32]).unwrap(), index: 0
			}),
			channel_type: None,
			short_channel_id: Some(1),
			inbound_scid_alias: None,
			outbound_scid_alias: None,
			channel_value_satoshis: 10_000_000,
			user_channel_id: 0,
			balance_msat: 10_000_000,
			outbound_capacity_msat: 10_000_000,
			next_outbound_htlc_limit_msat: 10_000_000,
			inbound_capacity_msat: 0,
			unspendable_punishment_reserve: None,
			confirmations_required: None,
			force_close_spend_delay: None,
			is_outbound: true,
			is_channel_ready: true,
			is_usable: true,
			is_public: true,
			inbound_htlc_minimum_msat: None,
			inbound_htlc_maximum_msat: None,
		}
	}

	#[bench]
	fn generate_routes_with_zero_penalty_scorer(bench: &mut Bencher) {
		let network_graph = read_network_graph();
		let scorer = FixedPenaltyScorer::with_penalty(0);
		generate_routes(bench, &network_graph, scorer, InvoiceFeatures::empty());
	}

	#[bench]
	fn generate_mpp_routes_with_zero_penalty_scorer(bench: &mut Bencher) {
		let network_graph = read_network_graph();
		let scorer = FixedPenaltyScorer::with_penalty(0);
		generate_routes(bench, &network_graph, scorer, InvoiceFeatures::known());
	}

	#[bench]
	fn generate_routes_with_default_scorer(bench: &mut Bencher) {
		let network_graph = read_network_graph();
		let scorer = Scorer::default();
		generate_routes(bench, &network_graph, scorer, InvoiceFeatures::empty());
	}

	#[bench]
	fn generate_mpp_routes_with_default_scorer(bench: &mut Bencher) {
		let network_graph = read_network_graph();
		let scorer = Scorer::default();
		generate_routes(bench, &network_graph, scorer, InvoiceFeatures::known());
	}

	#[bench]
	fn generate_routes_with_probabilistic_scorer(bench: &mut Bencher) {
		let logger = TestLogger::new();
		let network_graph = read_network_graph();
		let params = ProbabilisticScoringParameters::default();
		let scorer = ProbabilisticScorer::new(params, &network_graph, &logger);
		generate_routes(bench, &network_graph, scorer, InvoiceFeatures::empty());
	}

	#[bench]
	fn generate_mpp_routes_with_probabilistic_scorer(bench: &mut Bencher) {
		let logger = TestLogger::new();
		let network_graph = read_network_graph();
		let params = ProbabilisticScoringParameters::default();
		let scorer = ProbabilisticScorer::new(params, &network_graph, &logger);
		generate_routes(bench, &network_graph, scorer, InvoiceFeatures::known());
	}

	fn generate_routes<S: Score>(
		bench: &mut Bencher, graph: &NetworkGraph, mut scorer: S, features: InvoiceFeatures
	) {
		let nodes = graph.read_only().nodes().clone();
		let payer = payer_pubkey();
		let keys_manager = KeysManager::new(&[0u8; 32], 42, 42);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();

		// First, get 100 (source, destination) pairs for which route-getting actually succeeds...
		let mut routes = Vec::new();
		let mut route_endpoints = Vec::new();
		let mut seed: usize = 0xdeadbeef;
		'load_endpoints: for _ in 0..150 {
			loop {
				seed *= 0xdeadbeef;
				let src = PublicKey::from_slice(nodes.keys().skip(seed % nodes.len()).next().unwrap().as_slice()).unwrap();
				seed *= 0xdeadbeef;
				let dst = PublicKey::from_slice(nodes.keys().skip(seed % nodes.len()).next().unwrap().as_slice()).unwrap();
				let params = PaymentParameters::from_node_id(dst).with_features(features.clone());
				let first_hop = first_hop(src);
				let amt = seed as u64 % 1_000_000;
				if let Ok(route) = get_route(&payer, &params, &graph.read_only(), Some(&[&first_hop]), amt, 42, &DummyLogger{}, &scorer, &random_seed_bytes) {
					routes.push(route);
					route_endpoints.push((first_hop, params, amt));
					continue 'load_endpoints;
				}
			}
		}

		// ...and seed the scorer with success and failure data...
		for route in routes {
			let amount = route.get_total_amount();
			if amount < 250_000 {
				for path in route.paths {
					scorer.payment_path_successful(&path.iter().collect::<Vec<_>>());
				}
			} else if amount > 750_000 {
				for path in route.paths {
					let short_channel_id = path[path.len() / 2].short_channel_id;
					scorer.payment_path_failed(&path.iter().collect::<Vec<_>>(), short_channel_id);
				}
			}
		}

		// Because we've changed channel scores, its possible we'll take different routes to the
		// selected destinations, possibly causing us to fail because, eg, the newly-selected path
		// requires a too-high CLTV delta.
		route_endpoints.retain(|(first_hop, params, amt)| {
			get_route(&payer, params, &graph.read_only(), Some(&[first_hop]), *amt, 42, &DummyLogger{}, &scorer, &random_seed_bytes).is_ok()
		});
		route_endpoints.truncate(100);
		assert_eq!(route_endpoints.len(), 100);

		// ...then benchmark finding paths between the nodes we learned.
		let mut idx = 0;
		bench.iter(|| {
			let (first_hop, params, amt) = &route_endpoints[idx % route_endpoints.len()];
			assert!(get_route(&payer, params, &graph.read_only(), Some(&[first_hop]), *amt, 42, &DummyLogger{}, &scorer, &random_seed_bytes).is_ok());
			idx += 1;
		});
	}
}
