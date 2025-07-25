// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! The router finds paths within a [`NetworkGraph`] for a payment.

use bitcoin::secp256k1::{self, PublicKey, Secp256k1};
use lightning_invoice::Bolt11Invoice;

use crate::blinded_path::payment::{
	BlindedPaymentPath, ForwardTlvs, PaymentConstraints, PaymentForwardNode, PaymentRelay,
	ReceiveTlvs,
};
use crate::blinded_path::{BlindedHop, Direction, IntroductionNode};
use crate::crypto::chacha20::ChaCha20;
use crate::ln::channel_state::ChannelDetails;
use crate::ln::channelmanager::{PaymentId, RecipientOnionFields, MIN_FINAL_CLTV_EXPIRY_DELTA};
use crate::ln::msgs::{DecodeError, MAX_VALUE_MSAT};
use crate::ln::onion_utils;
use crate::offers::invoice::Bolt12Invoice;
#[cfg(async_payments)]
use crate::offers::static_invoice::StaticInvoice;
use crate::routing::gossip::{
	DirectedChannelInfo, EffectiveCapacity, NetworkGraph, NodeId, ReadOnlyNetworkGraph,
};
use crate::routing::scoring::{ChannelUsage, LockableScore, ScoreLookUp};
use crate::sign::EntropySource;
use crate::sync::Mutex;
use crate::types::features::{
	BlindedHopFeatures, Bolt11InvoiceFeatures, Bolt12InvoiceFeatures, ChannelFeatures, NodeFeatures,
};
use crate::types::payment::{PaymentHash, PaymentPreimage};
use crate::util::logger::Logger;
use crate::util::ser::{Readable, ReadableArgs, Writeable, Writer};

use crate::io;
use crate::prelude::*;
use alloc::collections::BinaryHeap;
use core::ops::Deref;
use core::{cmp, fmt};

use lightning_types::routing::RoutingFees;

pub use lightning_types::routing::{RouteHint, RouteHintHop};

/// A [`Router`] implemented using [`find_route`].
///
/// # Privacy
///
/// Creating [`BlindedPaymentPath`]s may affect privacy since, if a suitable path cannot be found,
/// it will create a one-hop path using the recipient as the introduction node if it is an announced
/// node. Otherwise, there is no way to find a path to the introduction node in order to send a
/// payment, and thus an `Err` is returned.
pub struct DefaultRouter<
	G: Deref<Target = NetworkGraph<L>>,
	L: Deref,
	ES: Deref,
	S: Deref,
	SP: Sized,
	Sc: ScoreLookUp<ScoreParams = SP>,
> where
	L::Target: Logger,
	S::Target: for<'a> LockableScore<'a, ScoreLookUp = Sc>,
	ES::Target: EntropySource,
{
	network_graph: G,
	logger: L,
	entropy_source: ES,
	scorer: S,
	score_params: SP,
}

impl<
		G: Deref<Target = NetworkGraph<L>>,
		L: Deref,
		ES: Deref,
		S: Deref,
		SP: Sized,
		Sc: ScoreLookUp<ScoreParams = SP>,
	> DefaultRouter<G, L, ES, S, SP, Sc>
where
	L::Target: Logger,
	S::Target: for<'a> LockableScore<'a, ScoreLookUp = Sc>,
	ES::Target: EntropySource,
{
	/// Creates a new router.
	pub fn new(
		network_graph: G, logger: L, entropy_source: ES, scorer: S, score_params: SP,
	) -> Self {
		Self { network_graph, logger, entropy_source, scorer, score_params }
	}
}

impl<
		G: Deref<Target = NetworkGraph<L>>,
		L: Deref,
		ES: Deref,
		S: Deref,
		SP: Sized,
		Sc: ScoreLookUp<ScoreParams = SP>,
	> Router for DefaultRouter<G, L, ES, S, SP, Sc>
where
	L::Target: Logger,
	S::Target: for<'a> LockableScore<'a, ScoreLookUp = Sc>,
	ES::Target: EntropySource,
{
	#[rustfmt::skip]
	fn find_route(
		&self,
		payer: &PublicKey,
		params: &RouteParameters,
		first_hops: Option<&[&ChannelDetails]>,
		inflight_htlcs: InFlightHtlcs
	) -> Result<Route, &'static str> {
		let random_seed_bytes = self.entropy_source.get_secure_random_bytes();
		find_route(
			payer, params, &self.network_graph, first_hops, &*self.logger,
			&ScorerAccountingForInFlightHtlcs::new(self.scorer.read_lock(), &inflight_htlcs),
			&self.score_params,
			&random_seed_bytes
		)
	}

	#[rustfmt::skip]
	fn create_blinded_payment_paths<
		T: secp256k1::Signing + secp256k1::Verification
	> (
		&self, recipient: PublicKey, first_hops: Vec<ChannelDetails>, tlvs: ReceiveTlvs,
		amount_msats: Option<u64>, secp_ctx: &Secp256k1<T>
	) -> Result<Vec<BlindedPaymentPath>, ()> {
		// Limit the number of blinded paths that are computed.
		const MAX_PAYMENT_PATHS: usize = 3;

		// Ensure peers have at least three channels so that it is more difficult to infer the
		// recipient's node_id.
		const MIN_PEER_CHANNELS: usize = 3;

		let has_one_peer = first_hops
			.first()
			.map(|details| details.counterparty.node_id)
			.map(|node_id| first_hops
				.iter()
				.skip(1)
				.all(|details| details.counterparty.node_id == node_id)
			)
			.unwrap_or(false);

		let network_graph = self.network_graph.deref().read_only();
		let is_recipient_announced =
			network_graph.nodes().contains_key(&NodeId::from_pubkey(&recipient));

		let paths = first_hops.into_iter()
			.filter(|details| details.counterparty.features.supports_route_blinding())
			.filter(|details| amount_msats.unwrap_or(0) <= details.inbound_capacity_msat)
			.filter(|details| amount_msats.unwrap_or(u64::MAX) >= details.inbound_htlc_minimum_msat.unwrap_or(0))
			.filter(|details| amount_msats.unwrap_or(0) <= details.inbound_htlc_maximum_msat.unwrap_or(u64::MAX))
			// Limit to peers with announced channels unless the recipient is unannounced.
			.filter(|details| network_graph
					.node(&NodeId::from_pubkey(&details.counterparty.node_id))
					.map(|node| !is_recipient_announced || node.channels.len() >= MIN_PEER_CHANNELS)
					// Allow payments directly with the only peer when unannounced.
					.unwrap_or(!is_recipient_announced && has_one_peer)
			)
			.filter_map(|details| {
				let short_channel_id = match details.get_inbound_payment_scid() {
					Some(short_channel_id) => short_channel_id,
					None => return None,
				};
				let payment_relay: PaymentRelay = match details.counterparty.forwarding_info {
					Some(forwarding_info) => match forwarding_info.try_into() {
						Ok(payment_relay) => payment_relay,
						Err(()) => return None,
					},
					None => return None,
				};

				let cltv_expiry_delta = payment_relay.cltv_expiry_delta as u32;
				let payment_constraints = PaymentConstraints {
					max_cltv_expiry: tlvs.tlvs().payment_constraints.max_cltv_expiry + cltv_expiry_delta,
					htlc_minimum_msat: details.inbound_htlc_minimum_msat.unwrap_or(0),
				};
				Some(PaymentForwardNode {
					tlvs: ForwardTlvs {
						short_channel_id,
						payment_relay,
						payment_constraints,
						next_blinding_override: None,
						features: BlindedHopFeatures::empty(),
					},
					node_id: details.counterparty.node_id,
					htlc_maximum_msat: details.inbound_htlc_maximum_msat.unwrap_or(u64::MAX),
				})
			})
			.map(|forward_node| {
				BlindedPaymentPath::new(
					&[forward_node], recipient, tlvs.clone(), u64::MAX, MIN_FINAL_CLTV_EXPIRY_DELTA,
					&*self.entropy_source, secp_ctx
				)
			})
			.take(MAX_PAYMENT_PATHS)
			.collect::<Result<Vec<_>, _>>();

		match paths {
			Ok(paths) if !paths.is_empty() => Ok(paths),
			_ => {
				if network_graph.nodes().contains_key(&NodeId::from_pubkey(&recipient)) {
					BlindedPaymentPath::new(
						&[], recipient, tlvs, u64::MAX, MIN_FINAL_CLTV_EXPIRY_DELTA, &*self.entropy_source,
						secp_ctx
					).map(|path| vec![path])
				} else {
					Err(())
				}
			},
		}
	}
}

/// A `Router` that returns a fixed route one time, erroring otherwise. Useful for
/// `ChannelManager::send_payment_with_route` to support sending to specific routes without
/// requiring a custom `Router` implementation.
pub(crate) struct FixedRouter {
	// Use an `Option` to avoid needing to clone the route when `find_route` is called.
	route: Mutex<Option<Route>>,
}

impl FixedRouter {
	pub(crate) fn new(route: Route) -> Self {
		Self { route: Mutex::new(Some(route)) }
	}
}

impl Router for FixedRouter {
	fn find_route(
		&self, _payer: &PublicKey, _route_params: &RouteParameters,
		_first_hops: Option<&[&ChannelDetails]>, _inflight_htlcs: InFlightHtlcs,
	) -> Result<Route, &'static str> {
		self.route.lock().unwrap().take().ok_or("Can't use this router to return multiple routes")
	}

	fn create_blinded_payment_paths<T: secp256k1::Signing + secp256k1::Verification>(
		&self, _recipient: PublicKey, _first_hops: Vec<ChannelDetails>, _tlvs: ReceiveTlvs,
		_amount_msats: Option<u64>, _secp_ctx: &Secp256k1<T>,
	) -> Result<Vec<BlindedPaymentPath>, ()> {
		// Should be unreachable as this router is only intended to provide a one-time payment route.
		debug_assert!(false);
		Err(())
	}
}

/// A trait defining behavior for routing a payment.
pub trait Router {
	/// Finds a [`Route`] for a payment between the given `payer` and a payee.
	///
	/// The `payee` and the payment's value are given in [`RouteParameters::payment_params`]
	/// and [`RouteParameters::final_value_msat`], respectively.
	#[rustfmt::skip]
	fn find_route(
		&self, payer: &PublicKey, route_params: &RouteParameters,
		first_hops: Option<&[&ChannelDetails]>, inflight_htlcs: InFlightHtlcs
	) -> Result<Route, &'static str>;

	/// Finds a [`Route`] for a payment between the given `payer` and a payee.
	///
	/// The `payee` and the payment's value are given in [`RouteParameters::payment_params`]
	/// and [`RouteParameters::final_value_msat`], respectively.
	///
	/// Includes a [`PaymentHash`] and a [`PaymentId`] to be able to correlate the request with a specific
	/// payment.
	fn find_route_with_id(
		&self, payer: &PublicKey, route_params: &RouteParameters,
		first_hops: Option<&[&ChannelDetails]>, inflight_htlcs: InFlightHtlcs,
		_payment_hash: PaymentHash, _payment_id: PaymentId,
	) -> Result<Route, &'static str> {
		self.find_route(payer, route_params, first_hops, inflight_htlcs)
	}

	/// Creates [`BlindedPaymentPath`]s for payment to the `recipient` node. The channels in `first_hops`
	/// are assumed to be with the `recipient`'s peers. The payment secret and any constraints are
	/// given in `tlvs`.
	fn create_blinded_payment_paths<T: secp256k1::Signing + secp256k1::Verification>(
		&self, recipient: PublicKey, first_hops: Vec<ChannelDetails>, tlvs: ReceiveTlvs,
		amount_msats: Option<u64>, secp_ctx: &Secp256k1<T>,
	) -> Result<Vec<BlindedPaymentPath>, ()>;
}

/// [`ScoreLookUp`] implementation that factors in in-flight HTLC liquidity.
///
/// Useful for custom [`Router`] implementations to wrap their [`ScoreLookUp`] on-the-fly when calling
/// [`find_route`].
///
/// [`ScoreLookUp`]: crate::routing::scoring::ScoreLookUp
pub struct ScorerAccountingForInFlightHtlcs<'a, S: Deref>
where
	S::Target: ScoreLookUp,
{
	scorer: S,
	// Maps a channel's short channel id and its direction to the liquidity used up.
	inflight_htlcs: &'a InFlightHtlcs,
}
impl<'a, S: Deref> ScorerAccountingForInFlightHtlcs<'a, S>
where
	S::Target: ScoreLookUp,
{
	/// Initialize a new `ScorerAccountingForInFlightHtlcs`.
	#[rustfmt::skip]
	pub fn new(scorer: S, inflight_htlcs: &'a InFlightHtlcs) -> Self {
		ScorerAccountingForInFlightHtlcs {
			scorer,
			inflight_htlcs
		}
	}
}

impl<'a, S: Deref> ScoreLookUp for ScorerAccountingForInFlightHtlcs<'a, S>
where
	S::Target: ScoreLookUp,
{
	type ScoreParams = <S::Target as ScoreLookUp>::ScoreParams;
	#[rustfmt::skip]
	fn channel_penalty_msat(&self, candidate: &CandidateRouteHop, usage: ChannelUsage, score_params: &Self::ScoreParams) -> u64 {
		let target = match candidate.target() {
			Some(target) => target,
			None => return self.scorer.channel_penalty_msat(candidate, usage, score_params),
		};
		let short_channel_id = match candidate.short_channel_id() {
			Some(short_channel_id) => short_channel_id,
			None => return self.scorer.channel_penalty_msat(candidate, usage, score_params),
		};
		let source = candidate.source();
		if let Some(used_liquidity) = self.inflight_htlcs.used_liquidity_msat(
			&source, &target, short_channel_id
		) {
			let usage = ChannelUsage {
				inflight_htlc_msat: usage.inflight_htlc_msat.saturating_add(used_liquidity),
				..usage
			};

			self.scorer.channel_penalty_msat(candidate, usage, score_params)
		} else {
			self.scorer.channel_penalty_msat(candidate, usage, score_params)
		}
	}
}

/// A data structure for tracking in-flight HTLCs. May be used during pathfinding to account for
/// in-use channel liquidity.
#[derive(Clone)]
pub struct InFlightHtlcs(
	// A map with liquidity value (in msat) keyed by a short channel id and the direction the HTLC
	// is traveling in. The direction boolean is determined by checking if the HTLC source's public
	// key is less than its destination. See `InFlightHtlcs::used_liquidity_msat` for more
	// details.
	HashMap<(u64, bool), u64>,
);

impl InFlightHtlcs {
	/// Constructs an empty `InFlightHtlcs`.
	#[rustfmt::skip]
	pub fn new() -> Self { InFlightHtlcs(new_hash_map()) }

	/// Takes in a path with payer's node id and adds the path's details to `InFlightHtlcs`.
	#[rustfmt::skip]
	pub fn process_path(&mut self, path: &Path, payer_node_id: PublicKey) {
		if path.hops.is_empty() { return };

		let mut cumulative_msat = 0;
		if let Some(tail) = &path.blinded_tail {
			cumulative_msat += tail.final_value_msat;
		}

		// total_inflight_map needs to be direction-sensitive when keeping track of the HTLC value
		// that is held up. However, the `hops` array, which is a path returned by `find_route` in
		// the router excludes the payer node. In the following lines, the payer's information is
		// hardcoded with an inflight value of 0 so that we can correctly represent the first hop
		// in our sliding window of two.
		let reversed_hops_with_payer = path.hops.iter().rev().skip(1)
			.map(|hop| hop.pubkey)
			.chain(core::iter::once(payer_node_id));

		// Taking the reversed vector from above, we zip it with just the reversed hops list to
		// work "backwards" of the given path, since the last hop's `fee_msat` actually represents
		// the total amount sent.
		for (next_hop, prev_hop) in path.hops.iter().rev().zip(reversed_hops_with_payer) {
			cumulative_msat += next_hop.fee_msat;
			self.0
				.entry((next_hop.short_channel_id, NodeId::from_pubkey(&prev_hop) < NodeId::from_pubkey(&next_hop.pubkey)))
				.and_modify(|used_liquidity_msat| *used_liquidity_msat += cumulative_msat)
				.or_insert(cumulative_msat);
		}
	}

	/// Adds a known HTLC given the public key of the HTLC source, target, and short channel
	/// id.
	pub fn add_inflight_htlc(
		&mut self, source: &NodeId, target: &NodeId, channel_scid: u64, used_msat: u64,
	) {
		self.0
			.entry((channel_scid, source < target))
			.and_modify(|used_liquidity_msat| *used_liquidity_msat += used_msat)
			.or_insert(used_msat);
	}

	/// Returns liquidity in msat given the public key of the HTLC source, target, and short channel
	/// id.
	pub fn used_liquidity_msat(
		&self, source: &NodeId, target: &NodeId, channel_scid: u64,
	) -> Option<u64> {
		self.0.get(&(channel_scid, source < target)).map(|v| *v)
	}
}

impl Writeable for InFlightHtlcs {
	#[rustfmt::skip]
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> { self.0.write(writer) }
}

impl Readable for InFlightHtlcs {
	fn read<R: io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
		let infight_map: HashMap<(u64, bool), u64> = Readable::read(reader)?;
		Ok(Self(infight_map))
	}
}

/// A hop in a route, and additional metadata about it. "Hop" is defined as a node and the channel
/// that leads to it.
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
	/// If this is the last hop in [`Path::hops`]:
	/// * if we're sending to a [`BlindedPaymentPath`], this is the fee paid for use of the entire
	///   blinded path (including any Trampoline hops)
	/// * otherwise, this is the full value of this [`Path`]'s part of the payment
	pub fee_msat: u64,
	/// The CLTV delta added for this hop.
	/// If this is the last hop in [`Path::hops`]:
	/// * if we're sending to a [`BlindedPaymentPath`], this is the CLTV delta for the entire blinded
	///   path (including any Trampoline hops)
	/// * otherwise, this is the CLTV delta expected at the destination
	pub cltv_expiry_delta: u32,
	/// Indicates whether this hop is possibly announced in the public network graph.
	///
	/// Will be `true` if there is a possibility that the channel is publicly known, i.e., if we
	/// either know for sure it's announced in the public graph, or if any public channels exist
	/// for which the given `short_channel_id` could be an alias for. Will be `false` if we believe
	/// the channel to be unannounced.
	///
	/// Will be `true` for objects serialized with LDK version 0.0.116 and before.
	pub maybe_announced_channel: bool,
}

impl_writeable_tlv_based!(RouteHop, {
	(0, pubkey, required),
	(1, maybe_announced_channel, (default_value, true)),
	(2, node_features, required),
	(4, short_channel_id, required),
	(6, channel_features, required),
	(8, fee_msat, required),
	(10, cltv_expiry_delta, required),
});

/// A Trampoline hop in a route, and additional metadata about it. "Hop" is defined as a node.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct TrampolineHop {
	/// The node_id of the node at this hop.
	pub pubkey: PublicKey,
	/// The node_announcement features of the node at this hop.
	pub node_features: NodeFeatures,
	/// The fee this hop should use to pay for routing towards the next Trampoline hop, or to the
	/// recipient if this is the last Trampoline hop.
	/// If this is the last Trampoline hop within [`BlindedTail`], this is the fee paid for the use of
	/// the entire blinded path.
	pub fee_msat: u64,
	/// The CLTV delta added for this hop.
	/// If this is the last Trampoline hop within [`BlindedTail`], this is the CLTV delta for the entire
	/// blinded path.
	pub cltv_expiry_delta: u32,
}

impl_writeable_tlv_based!(TrampolineHop, {
	(0, pubkey, required),
	(2, node_features, required),
	(4, fee_msat, required),
	(6, cltv_expiry_delta, required),
});

/// The blinded portion of a [`Path`], if we're routing to a recipient who provided blinded paths in
/// their [`Bolt12Invoice`].
///
/// [`Bolt12Invoice`]: crate::offers::invoice::Bolt12Invoice
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct BlindedTail {
	/// The list of unblinded Trampoline hops. When using Trampoline, must contain at least one hop.
	///
	/// Note that the first [`TrampolineHop`] node must also be present as the last [`RouteHop`] node,
	/// where the [`RouteHop`]'s fee_msat is the fee paid for use of the entire blinded path, including
	/// any Trampoline hops.
	pub trampoline_hops: Vec<TrampolineHop>,
	/// The hops of the [`BlindedPaymentPath`] provided by the recipient.
	pub hops: Vec<BlindedHop>,
	/// The blinding point of the [`BlindedPaymentPath`] provided by the recipient.
	pub blinding_point: PublicKey,
	/// Excess CLTV delta added to the recipient's CLTV expiry to deter intermediate nodes from
	/// inferring the destination. May be 0.
	pub excess_final_cltv_expiry_delta: u32,
	/// The total amount paid on this [`Path`], excluding the fees.
	pub final_value_msat: u64,
}

impl_writeable_tlv_based!(BlindedTail, {
	(0, hops, required_vec),
	(2, blinding_point, required),
	(4, excess_final_cltv_expiry_delta, required),
	(6, final_value_msat, required),
	(8, trampoline_hops, optional_vec),
});

/// A path in a [`Route`] to the payment recipient. Must always be at least length one.
/// If no [`Path::blinded_tail`] is present, then [`Path::hops`] length may be up to 19.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct Path {
	/// The list of unblinded hops in this [`Path`]. Must be at least length one.
	pub hops: Vec<RouteHop>,
	/// The blinded path at which this path terminates, if we're sending to one, and its metadata.
	pub blinded_tail: Option<BlindedTail>,
}

impl Path {
	/// Gets the fees for a given path, excluding any excess paid to the recipient.
	#[rustfmt::skip]
	pub fn fee_msat(&self) -> u64 {
		match &self.blinded_tail {
			Some(_) => self.hops.iter().map(|hop| hop.fee_msat).sum::<u64>(),
			None => {
				// Do not count last hop of each path since that's the full value of the payment
				self.hops.split_last().map_or(0,
					|(_, path_prefix)| path_prefix.iter().map(|hop| hop.fee_msat).sum())
			}
		}
	}

	/// Gets the total amount paid on this [`Path`], excluding the fees.
	#[rustfmt::skip]
	pub fn final_value_msat(&self) -> u64 {
		match &self.blinded_tail {
			Some(blinded_tail) => blinded_tail.final_value_msat,
			None => self.hops.last().map_or(0, |hop| hop.fee_msat)
		}
	}

	/// Gets the final hop's CLTV expiry delta.
	#[rustfmt::skip]
	pub fn final_cltv_expiry_delta(&self) -> Option<u32> {
		match &self.blinded_tail {
			Some(_) => None,
			None => self.hops.last().map(|hop| hop.cltv_expiry_delta)
		}
	}

	/// True if this [`Path`] has at least one Trampoline hop.
	pub fn has_trampoline_hops(&self) -> bool {
		self.blinded_tail.as_ref().map_or(false, |bt| !bt.trampoline_hops.is_empty())
	}
}

/// A route directs a payment from the sender (us) to the recipient. If the recipient supports MPP,
/// it can take multiple paths. Each path is composed of one or more hops through the network.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct Route {
	/// The list of [`Path`]s taken for a single (potentially-)multi-part payment. If no
	/// [`BlindedTail`]s are present, then the pubkey of the last [`RouteHop`] in each path must be
	/// the same.
	pub paths: Vec<Path>,
	/// The `route_params` parameter passed to [`find_route`].
	///
	/// This is used by `ChannelManager` to track information which may be required for retries.
	///
	/// Will be `None` for objects serialized with LDK versions prior to 0.0.117.
	pub route_params: Option<RouteParameters>,
}

impl Route {
	/// Returns the total amount of fees paid on this [`Route`].
	///
	/// For objects serialized with LDK 0.0.117 and after, this includes any extra payment made to
	/// the recipient, which can happen in excess of the amount passed to [`find_route`] via
	/// [`RouteParameters::final_value_msat`], if we had to reach the [`htlc_minimum_msat`] limits.
	///
	/// [`htlc_minimum_msat`]: https://github.com/lightning/bolts/blob/master/07-routing-gossip.md#the-channel_update-message
	#[rustfmt::skip]
	pub fn get_total_fees(&self) -> u64 {
		let overpaid_value_msat = self.route_params.as_ref()
			.map_or(0, |p| self.get_total_amount().saturating_sub(p.final_value_msat));
		overpaid_value_msat + self.paths.iter().map(|path| path.fee_msat()).sum::<u64>()
	}

	/// Returns the total amount paid on this [`Route`], excluding the fees.
	///
	/// Might be more than requested as part of the given [`RouteParameters::final_value_msat`] if
	/// we had to reach the [`htlc_minimum_msat`] limits.
	///
	/// [`htlc_minimum_msat`]: https://github.com/lightning/bolts/blob/master/07-routing-gossip.md#the-channel_update-message
	pub fn get_total_amount(&self) -> u64 {
		self.paths.iter().map(|path| path.final_value_msat()).sum()
	}
}

impl fmt::Display for Route {
	fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
		log_route!(self).fmt(f)
	}
}

const SERIALIZATION_VERSION: u8 = 1;
const MIN_SERIALIZATION_VERSION: u8 = 1;

impl Writeable for Route {
	#[rustfmt::skip]
	fn write<W: crate::util::ser::Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		write_ver_prefix!(writer, SERIALIZATION_VERSION, MIN_SERIALIZATION_VERSION);
		(self.paths.len() as u64).write(writer)?;
		let mut blinded_tails = Vec::new();
		for (idx, path) in self.paths.iter().enumerate() {
			(path.hops.len() as u8).write(writer)?;
			for hop in path.hops.iter() {
				hop.write(writer)?;
			}
			if let Some(blinded_tail) = &path.blinded_tail {
				if blinded_tails.is_empty() {
					blinded_tails = Vec::with_capacity(path.hops.len());
					for _ in 0..idx {
						blinded_tails.push(None);
					}
				}
				blinded_tails.push(Some(blinded_tail));
			} else if !blinded_tails.is_empty() { blinded_tails.push(None); }
		}
		write_tlv_fields!(writer, {
			// For compatibility with LDK versions prior to 0.0.117, we take the individual
			// RouteParameters' fields and reconstruct them on read.
			(1, self.route_params.as_ref().map(|p| &p.payment_params), option),
			(2, blinded_tails, optional_vec),
			(3, self.route_params.as_ref().map(|p| p.final_value_msat), option),
			(5, self.route_params.as_ref().and_then(|p| p.max_total_routing_fee_msat), option),
		});
		Ok(())
	}
}

impl Readable for Route {
	#[rustfmt::skip]
	fn read<R: io::Read>(reader: &mut R) -> Result<Route, DecodeError> {
		let _ver = read_ver_prefix!(reader, SERIALIZATION_VERSION);
		let path_count: u64 = Readable::read(reader)?;
		if path_count == 0 { return Err(DecodeError::InvalidValue); }
		let mut paths = Vec::with_capacity(cmp::min(path_count, 128) as usize);
		let mut min_final_cltv_expiry_delta = u32::max_value();
		for _ in 0..path_count {
			let hop_count: u8 = Readable::read(reader)?;
			let mut hops: Vec<RouteHop> = Vec::with_capacity(hop_count as usize);
			for _ in 0..hop_count {
				hops.push(Readable::read(reader)?);
			}
			if hops.is_empty() { return Err(DecodeError::InvalidValue); }
			min_final_cltv_expiry_delta =
				cmp::min(min_final_cltv_expiry_delta, hops.last().unwrap().cltv_expiry_delta);
			paths.push(Path { hops, blinded_tail: None });
		}
		_init_and_read_len_prefixed_tlv_fields!(reader, {
			(1, payment_params, (option: ReadableArgs, min_final_cltv_expiry_delta)),
			(2, blinded_tails, optional_vec),
			(3, final_value_msat, option),
			(5, max_total_routing_fee_msat, option)
		});
		let blinded_tails = blinded_tails.unwrap_or(Vec::new());
		if blinded_tails.len() != 0 {
			if blinded_tails.len() != paths.len() { return Err(DecodeError::InvalidValue) }
			for (path, blinded_tail_opt) in paths.iter_mut().zip(blinded_tails.into_iter()) {
				path.blinded_tail = blinded_tail_opt;
			}
		}

		// If we previously wrote the corresponding fields, reconstruct RouteParameters.
		let route_params = match (payment_params, final_value_msat) {
			(Some(payment_params), Some(final_value_msat)) => {
				Some(RouteParameters { payment_params, final_value_msat, max_total_routing_fee_msat })
			}
			_ => None,
		};

		Ok(Route { paths, route_params })
	}
}

/// Parameters needed to find a [`Route`].
///
/// Passed to [`find_route`] and [`build_route_from_hops`].
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct RouteParameters {
	/// The parameters of the failed payment path.
	pub payment_params: PaymentParameters,

	/// The amount in msats sent on the failed payment path.
	pub final_value_msat: u64,

	/// The maximum total fees, in millisatoshi, that may accrue during route finding.
	///
	/// This limit also applies to the total fees that may arise while retrying failed payment
	/// paths.
	///
	/// Note that values below a few sats may result in some paths being spuriously ignored.
	pub max_total_routing_fee_msat: Option<u64>,
}

impl RouteParameters {
	/// Constructs [`RouteParameters`] from the given [`PaymentParameters`] and a payment amount.
	///
	/// [`Self::max_total_routing_fee_msat`] defaults to 1% of the payment amount + 50 sats
	#[rustfmt::skip]
	pub fn from_payment_params_and_value(payment_params: PaymentParameters, final_value_msat: u64) -> Self {
		Self { payment_params, final_value_msat, max_total_routing_fee_msat: Some(final_value_msat / 100 + 50_000) }
	}

	/// Sets the maximum number of hops that can be included in a payment path, based on the provided
	/// [`RecipientOnionFields`] and blinded paths.
	#[rustfmt::skip]
	pub fn set_max_path_length(
		&mut self, recipient_onion: &RecipientOnionFields, is_keysend: bool, best_block_height: u32
	) -> Result<(), ()> {
		let keysend_preimage_opt = is_keysend.then(|| PaymentPreimage([42; 32]));
		// TODO: no way to account for the invoice request here yet
		onion_utils::set_max_path_length(
			self, recipient_onion, keysend_preimage_opt, None, best_block_height
		)
	}
}

impl Writeable for RouteParameters {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		write_tlv_fields!(writer, {
			(0, self.payment_params, required),
			(1, self.max_total_routing_fee_msat, option),
			(2, self.final_value_msat, required),
			// LDK versions prior to 0.0.114 had the `final_cltv_expiry_delta` parameter in
			// `RouteParameters` directly. For compatibility, we write it here.
			(4, self.payment_params.payee.final_cltv_expiry_delta(), option),
		});
		Ok(())
	}
}

impl Readable for RouteParameters {
	fn read<R: io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
		_init_and_read_len_prefixed_tlv_fields!(reader, {
			(0, payment_params, (required: ReadableArgs, 0)),
			(1, max_total_routing_fee_msat, option),
			(2, final_value_msat, required),
			(4, final_cltv_delta, option),
		});
		let mut payment_params: PaymentParameters = payment_params.0.unwrap();
		if let Payee::Clear { ref mut final_cltv_expiry_delta, .. } = payment_params.payee {
			if final_cltv_expiry_delta == &0 {
				*final_cltv_expiry_delta = final_cltv_delta.ok_or(DecodeError::InvalidValue)?;
			}
		}
		Ok(Self {
			payment_params,
			final_value_msat: final_value_msat.0.unwrap(),
			max_total_routing_fee_msat,
		})
	}
}

/// Maximum total CTLV difference we allow for a full payment path.
pub const DEFAULT_MAX_TOTAL_CLTV_EXPIRY_DELTA: u32 = 1008;

/// Maximum number of paths we allow an (MPP) payment to have.
// The default limit is currently set rather arbitrary - there aren't any real fundamental path-count
// limits, but for now more than 10 paths likely carries too much one-path failure.
pub const DEFAULT_MAX_PATH_COUNT: u8 = 10;

const DEFAULT_MAX_CHANNEL_SATURATION_POW_HALF: u8 = 2;

// The median hop CLTV expiry delta currently seen in the network.
const MEDIAN_HOP_CLTV_EXPIRY_DELTA: u32 = 40;

/// Estimated maximum number of hops that can be included in a payment path. May be inaccurate if
/// payment metadata, custom TLVs, or blinded paths are included in the payment.
// During routing, we only consider paths shorter than our maximum length estimate.
// In the TLV onion format, there is no fixed maximum length, but the `hop_payloads`
// field is always 1300 bytes. As the `tlv_payload` for each hop may vary in length, we have to
// estimate how many hops the route may have so that it actually fits the `hop_payloads` field.
//
// We estimate 3+32 (payload length and HMAC) + 2+8 (amt_to_forward) + 2+4 (outgoing_cltv_value) +
// 2+8 (short_channel_id) = 61 bytes for each intermediate hop and 3+32
// (payload length and HMAC) + 2+8 (amt_to_forward) + 2+4 (outgoing_cltv_value) + 2+32+8
// (payment_secret and total_msat) = 93 bytes for the final hop.
// Since the length of the potentially included `payment_metadata` is unknown to us, we round
// down from (1300-93) / 61 = 19.78... to arrive at a conservative estimate of 19.
pub const MAX_PATH_LENGTH_ESTIMATE: u8 = 19;

/// Information used to route a payment.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct PaymentParameters {
	/// Information about the payee, such as their features and route hints for their channels.
	pub payee: Payee,

	/// Expiration of a payment to the payee, in seconds relative to the UNIX epoch.
	pub expiry_time: Option<u64>,

	/// The maximum total CLTV delta we accept for the route.
	/// Defaults to [`DEFAULT_MAX_TOTAL_CLTV_EXPIRY_DELTA`].
	pub max_total_cltv_expiry_delta: u32,

	/// The maximum number of paths that may be used by (MPP) payments.
	/// Defaults to [`DEFAULT_MAX_PATH_COUNT`].
	pub max_path_count: u8,

	/// The maximum number of [`Path::hops`] in any returned path.
	/// Defaults to [`MAX_PATH_LENGTH_ESTIMATE`].
	pub max_path_length: u8,

	/// Selects the maximum share of a channel's total capacity which will be sent over a channel,
	/// as a power of 1/2. A higher value prefers to send the payment using more MPP parts whereas
	/// a lower value prefers to send larger MPP parts, potentially saturating channels and
	/// increasing failure probability for those paths.
	///
	/// Note that this restriction will be relaxed during pathfinding after paths which meet this
	/// restriction have been found. While paths which meet this criteria will be searched for, it
	/// is ultimately up to the scorer to select them over other paths.
	///
	/// A value of 0 will allow payments up to and including a channel's total announced usable
	/// capacity, a value of one will only use up to half its capacity, two 1/4, etc.
	///
	/// Default value: 2
	pub max_channel_saturation_power_of_half: u8,

	/// A list of SCIDs which this payment was previously attempted over and which caused the
	/// payment to fail. Future attempts for the same payment shouldn't be relayed through any of
	/// these SCIDs.
	pub previously_failed_channels: Vec<u64>,

	/// A list of indices corresponding to blinded paths in [`Payee::Blinded::route_hints`] which this
	/// payment was previously attempted over and which caused the payment to fail. Future attempts
	/// for the same payment shouldn't be relayed through any of these blinded paths.
	pub previously_failed_blinded_path_idxs: Vec<u64>,
}

impl Writeable for PaymentParameters {
	#[rustfmt::skip]
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		let mut clear_hints = &vec![];
		let mut blinded_hints = None;
		match &self.payee {
			Payee::Clear { route_hints, .. } => clear_hints = route_hints,
			Payee::Blinded { route_hints, .. } => {
				let hints_iter = route_hints.iter().map(|path| (&path.payinfo, path.inner_blinded_path()));
				blinded_hints = Some(crate::util::ser::IterableOwned(hints_iter));
			}
		}
		write_tlv_fields!(writer, {
			(0, self.payee.node_id(), option),
			(1, self.max_total_cltv_expiry_delta, required),
			(2, self.payee.features(), option),
			(3, self.max_path_count, required),
			(4, *clear_hints, required_vec),
			(5, self.max_channel_saturation_power_of_half, required),
			(6, self.expiry_time, option),
			(7, self.previously_failed_channels, required_vec),
			(8, blinded_hints, option),
			(9, self.payee.final_cltv_expiry_delta(), option),
			(11, self.previously_failed_blinded_path_idxs, required_vec),
			(13, self.max_path_length, required),
		});
		Ok(())
	}
}

impl ReadableArgs<u32> for PaymentParameters {
	#[rustfmt::skip]
	fn read<R: io::Read>(reader: &mut R, default_final_cltv_expiry_delta: u32) -> Result<Self, DecodeError> {
		_init_and_read_len_prefixed_tlv_fields!(reader, {
			(0, payee_pubkey, option),
			(1, max_total_cltv_expiry_delta, (default_value, DEFAULT_MAX_TOTAL_CLTV_EXPIRY_DELTA)),
			(2, features, (option: ReadableArgs, payee_pubkey.is_some())),
			(3, max_path_count, (default_value, DEFAULT_MAX_PATH_COUNT)),
			(4, clear_route_hints, required_vec),
			(5, max_channel_saturation_power_of_half, (default_value, DEFAULT_MAX_CHANNEL_SATURATION_POW_HALF)),
			(6, expiry_time, option),
			(7, previously_failed_channels, optional_vec),
			(8, blinded_route_hints, optional_vec),
			(9, final_cltv_expiry_delta, (default_value, default_final_cltv_expiry_delta)),
			(11, previously_failed_blinded_path_idxs, optional_vec),
			(13, max_path_length, (default_value, MAX_PATH_LENGTH_ESTIMATE)),
		});
		let blinded_route_hints = blinded_route_hints.unwrap_or(vec![]);
		let payee = if blinded_route_hints.len() != 0 {
			if clear_route_hints.len() != 0 || payee_pubkey.is_some() { return Err(DecodeError::InvalidValue) }
			Payee::Blinded {
				route_hints: blinded_route_hints
					.into_iter()
					.map(|(payinfo, path)| BlindedPaymentPath::from_parts(path, payinfo))
					.collect(),
				features: features.and_then(|f: Features| f.bolt12()),
			}
		} else {
			Payee::Clear {
				route_hints: clear_route_hints,
				node_id: payee_pubkey.ok_or(DecodeError::InvalidValue)?,
				features: features.and_then(|f| f.bolt11()),
				final_cltv_expiry_delta: final_cltv_expiry_delta.0.unwrap(),
			}
		};
		Ok(Self {
			max_total_cltv_expiry_delta: _init_tlv_based_struct_field!(max_total_cltv_expiry_delta, (default_value, unused)),
			max_path_count: _init_tlv_based_struct_field!(max_path_count, (default_value, unused)),
			payee,
			max_channel_saturation_power_of_half: _init_tlv_based_struct_field!(max_channel_saturation_power_of_half, (default_value, unused)),
			expiry_time,
			previously_failed_channels: previously_failed_channels.unwrap_or(Vec::new()),
			previously_failed_blinded_path_idxs: previously_failed_blinded_path_idxs.unwrap_or(Vec::new()),
			max_path_length: _init_tlv_based_struct_field!(max_path_length, (default_value, unused)),
		})
	}
}

impl PaymentParameters {
	/// Creates a payee with the node id of the given `pubkey`.
	///
	/// The `final_cltv_expiry_delta` should match the expected final CLTV delta the recipient has
	/// provided.
	#[rustfmt::skip]
	pub fn from_node_id(payee_pubkey: PublicKey, final_cltv_expiry_delta: u32) -> Self {
		Self {
			payee: Payee::Clear { node_id: payee_pubkey, route_hints: vec![], features: None, final_cltv_expiry_delta },
			expiry_time: None,
			max_total_cltv_expiry_delta: DEFAULT_MAX_TOTAL_CLTV_EXPIRY_DELTA,
			max_path_count: DEFAULT_MAX_PATH_COUNT,
			max_path_length: MAX_PATH_LENGTH_ESTIMATE,
			max_channel_saturation_power_of_half: DEFAULT_MAX_CHANNEL_SATURATION_POW_HALF,
			previously_failed_channels: Vec::new(),
			previously_failed_blinded_path_idxs: Vec::new(),
		}
	}

	/// Creates a payee with the node id of the given `pubkey` to use for keysend payments.
	///
	/// The `final_cltv_expiry_delta` should match the expected final CLTV delta the recipient has
	/// provided.
	///
	/// Note that MPP keysend is not widely supported yet. The `allow_mpp` lets you choose
	/// whether your router will be allowed to find a multi-part route for this payment. If you
	/// set `allow_mpp` to true, you should ensure a payment secret is set on send, likely via
	/// [`RecipientOnionFields::secret_only`].
	///
	/// [`RecipientOnionFields::secret_only`]: crate::ln::channelmanager::RecipientOnionFields::secret_only
	#[rustfmt::skip]
	pub fn for_keysend(payee_pubkey: PublicKey, final_cltv_expiry_delta: u32, allow_mpp: bool) -> Self {
		Self::from_node_id(payee_pubkey, final_cltv_expiry_delta)
			.with_bolt11_features(Bolt11InvoiceFeatures::for_keysend(allow_mpp))
			.expect("PaymentParameters::from_node_id should always initialize the payee as unblinded")
	}

	/// Creates parameters for paying to a blinded payee from the provided invoice. Sets
	/// [`Payee::Blinded::route_hints`], [`Payee::Blinded::features`], and
	/// [`PaymentParameters::expiry_time`].
	pub fn from_bolt11_invoice(invoice: &Bolt11Invoice) -> Self {
		let mut payment_params = Self::from_node_id(
			invoice.recover_payee_pub_key(),
			invoice.min_final_cltv_expiry_delta() as u32,
		)
		.with_route_hints(invoice.route_hints())
		.unwrap();

		if let Some(expiry) = invoice.expires_at() {
			payment_params = payment_params.with_expiry_time(expiry.as_secs());
		}
		if let Some(features) = invoice.features() {
			payment_params = payment_params.with_bolt11_features(features.clone()).unwrap();
		}

		payment_params
	}

	/// Creates parameters for paying to a blinded payee from the provided invoice. Sets
	/// [`Payee::Blinded::route_hints`], [`Payee::Blinded::features`], and
	/// [`PaymentParameters::expiry_time`].
	#[rustfmt::skip]
	pub fn from_bolt12_invoice(invoice: &Bolt12Invoice) -> Self {
		Self::blinded(invoice.payment_paths().to_vec())
			.with_bolt12_features(invoice.invoice_features().clone()).unwrap()
			.with_expiry_time(invoice.created_at().as_secs().saturating_add(invoice.relative_expiry().as_secs()))
	}

	/// Creates parameters for paying to a blinded payee from the provided invoice. Sets
	/// [`Payee::Blinded::route_hints`], [`Payee::Blinded::features`], and
	/// [`PaymentParameters::expiry_time`].
	#[cfg(async_payments)]
	#[rustfmt::skip]
	pub fn from_static_invoice(invoice: &StaticInvoice) -> Self {
		Self::blinded(invoice.payment_paths().to_vec())
			.with_bolt12_features(invoice.invoice_features().clone()).unwrap()
			.with_expiry_time(invoice.created_at().as_secs().saturating_add(invoice.relative_expiry().as_secs()))
	}

	/// Creates parameters for paying to a blinded payee from the provided blinded route hints.
	pub fn blinded(blinded_route_hints: Vec<BlindedPaymentPath>) -> Self {
		Self {
			payee: Payee::Blinded { route_hints: blinded_route_hints, features: None },
			expiry_time: None,
			max_total_cltv_expiry_delta: DEFAULT_MAX_TOTAL_CLTV_EXPIRY_DELTA,
			max_path_count: DEFAULT_MAX_PATH_COUNT,
			max_path_length: MAX_PATH_LENGTH_ESTIMATE,
			max_channel_saturation_power_of_half: DEFAULT_MAX_CHANNEL_SATURATION_POW_HALF,
			previously_failed_channels: Vec::new(),
			previously_failed_blinded_path_idxs: Vec::new(),
		}
	}

	/// Updates the parameters with the given route parameters configuration.
	///
	/// Note:
	/// We *do not* apply `max_total_routing_fee_msat` here, as it is unique to each route.
	/// Instead, we apply only the parameters that are common across multiple route-finding sessions
	/// for a payment across retries.
	#[rustfmt::skip]
	pub(crate) fn with_user_config_ignoring_fee_limit(self, params_config: RouteParametersConfig) -> Self {
		Self {
			max_total_cltv_expiry_delta: params_config.max_total_cltv_expiry_delta,
			max_path_count: params_config.max_path_count,
			max_channel_saturation_power_of_half: params_config.max_channel_saturation_power_of_half,
			..self
		}
	}

	/// Includes the payee's features. Errors if the parameters were not initialized with
	/// [`PaymentParameters::from_bolt12_invoice`].
	///
	/// This is not exported to bindings users since bindings don't support move semantics
	#[rustfmt::skip]
	pub fn with_bolt12_features(self, features: Bolt12InvoiceFeatures) -> Result<Self, ()> {
		match self.payee {
			Payee::Clear { .. } => Err(()),
			Payee::Blinded { route_hints, .. } =>
				Ok(Self { payee: Payee::Blinded { route_hints, features: Some(features) }, ..self })
		}
	}

	/// Includes the payee's features. Errors if the parameters were initialized with
	/// [`PaymentParameters::from_bolt12_invoice`].
	///
	/// This is not exported to bindings users since bindings don't support move semantics
	#[rustfmt::skip]
	pub fn with_bolt11_features(self, features: Bolt11InvoiceFeatures) -> Result<Self, ()> {
		match self.payee {
			Payee::Blinded { .. } => Err(()),
			Payee::Clear { route_hints, node_id, final_cltv_expiry_delta, .. } =>
				Ok(Self {
					payee: Payee::Clear {
						route_hints, node_id, features: Some(features), final_cltv_expiry_delta
					}, ..self
				})
		}
	}

	/// Includes hints for routing to the payee. Errors if the parameters were initialized with
	/// [`PaymentParameters::from_bolt12_invoice`].
	///
	/// This is not exported to bindings users since bindings don't support move semantics
	#[rustfmt::skip]
	pub fn with_route_hints(self, route_hints: Vec<RouteHint>) -> Result<Self, ()> {
		match self.payee {
			Payee::Blinded { .. } => Err(()),
			Payee::Clear { node_id, features, final_cltv_expiry_delta, .. } =>
				Ok(Self {
					payee: Payee::Clear {
						route_hints, node_id, features, final_cltv_expiry_delta,
					}, ..self
				})
		}
	}

	/// Includes a payment expiration in seconds relative to the UNIX epoch.
	///
	/// This is not exported to bindings users since bindings don't support move semantics
	pub fn with_expiry_time(self, expiry_time: u64) -> Self {
		Self { expiry_time: Some(expiry_time), ..self }
	}

	/// Includes a limit for the total CLTV expiry delta which is considered during routing
	///
	/// This is not exported to bindings users since bindings don't support move semantics
	pub fn with_max_total_cltv_expiry_delta(self, max_total_cltv_expiry_delta: u32) -> Self {
		Self { max_total_cltv_expiry_delta, ..self }
	}

	/// Includes a limit for the maximum number of payment paths that may be used.
	///
	/// This is not exported to bindings users since bindings don't support move semantics
	pub fn with_max_path_count(self, max_path_count: u8) -> Self {
		Self { max_path_count, ..self }
	}

	/// Includes a limit for the maximum share of a channel's total capacity that can be sent over, as
	/// a power of 1/2. See [`PaymentParameters::max_channel_saturation_power_of_half`].
	///
	/// This is not exported to bindings users since bindings don't support move semantics
	pub fn with_max_channel_saturation_power_of_half(
		self, max_channel_saturation_power_of_half: u8,
	) -> Self {
		Self { max_channel_saturation_power_of_half, ..self }
	}

	#[rustfmt::skip]
	pub(crate) fn insert_previously_failed_blinded_path(&mut self, failed_blinded_tail: &BlindedTail) {
		let mut found_blinded_tail = false;
		for (idx, path) in self.payee.blinded_route_hints().iter().enumerate() {
			if &failed_blinded_tail.hops == path.blinded_hops() &&
				failed_blinded_tail.blinding_point == path.blinding_point()
			{
				self.previously_failed_blinded_path_idxs.push(idx as u64);
				found_blinded_tail = true;
			}
		}
		debug_assert!(found_blinded_tail);
	}
}

/// A struct for configuring parameters for routing the payment.
#[derive(Clone, Copy, Debug)]
pub struct RouteParametersConfig {
	/// The maximum total fees, in millisatoshi, that may accrue during route finding.
	///
	/// This limit also applies to the total fees that may arise while retrying failed payment
	/// paths.
	///
	/// Note that values below a few sats may result in some paths being spuriously ignored.
	///
	/// Defaults to 1% of the payment amount + 50 sats
	pub max_total_routing_fee_msat: Option<u64>,

	/// The maximum total CLTV delta we accept for the route.
	/// Defaults to [`DEFAULT_MAX_TOTAL_CLTV_EXPIRY_DELTA`].
	pub max_total_cltv_expiry_delta: u32,

	/// The maximum number of paths that may be used by (MPP) payments.
	/// Defaults to [`DEFAULT_MAX_PATH_COUNT`].
	pub max_path_count: u8,

	/// Selects the maximum share of a channel's total capacity which will be sent over a channel,
	/// as a power of 1/2. A higher value prefers to send the payment using more MPP parts whereas
	/// a lower value prefers to send larger MPP parts, potentially saturating channels and
	/// increasing failure probability for those paths.
	///
	/// Note that this restriction will be relaxed during pathfinding after paths which meet this
	/// restriction have been found. While paths which meet this criteria will be searched for, it
	/// is ultimately up to the scorer to select them over other paths.
	///
	/// A value of 0 will allow payments up to and including a channel's total announced usable
	/// capacity, a value of one will only use up to half its capacity, two 1/4, etc.
	///
	/// Default value: 2
	pub max_channel_saturation_power_of_half: u8,
}

impl_writeable_tlv_based!(RouteParametersConfig, {
	(1, max_total_routing_fee_msat, option),
	(3, max_total_cltv_expiry_delta, required),
	(5, max_path_count, required),
	(7, max_channel_saturation_power_of_half, required),
});

impl RouteParametersConfig {
	/// Set the maximum total fees, in millisatoshi, that may accrue during route finding.
	///
	/// This is not exported to bindings users since bindings don't support move semantics
	pub fn with_max_total_routing_fee_msat(self, fee_msat: u64) -> Self {
		Self { max_total_routing_fee_msat: Some(fee_msat), ..self }
	}

	/// Includes a limit for the total CLTV expiry delta which is considered during routing
	///
	/// This is not exported to bindings users since bindings don't support move semantics
	pub fn with_max_total_cltv_expiry_delta(self, max_total_cltv_expiry_delta: u32) -> Self {
		Self { max_total_cltv_expiry_delta, ..self }
	}

	/// Includes a limit for the maximum number of payment paths that may be used.
	///
	/// This is not exported to bindings users since bindings don't support move semantics
	pub fn with_max_path_count(self, max_path_count: u8) -> Self {
		Self { max_path_count, ..self }
	}

	/// Includes a limit for the maximum share of a channel's total capacity that can be sent over, as
	/// a power of 1/2. See [`PaymentParameters::max_channel_saturation_power_of_half`].
	///
	/// This is not exported to bindings users since bindings don't support move semantics
	pub fn with_max_channel_saturation_power_of_half(
		self, max_channel_saturation_power_of_half: u8,
	) -> Self {
		Self { max_channel_saturation_power_of_half, ..self }
	}
}

impl Default for RouteParametersConfig {
	/// Initates an new set of route parameter configs with default parameters.
	fn default() -> Self {
		Self {
			max_total_routing_fee_msat: None,
			max_total_cltv_expiry_delta: DEFAULT_MAX_TOTAL_CLTV_EXPIRY_DELTA,
			max_path_count: DEFAULT_MAX_PATH_COUNT,
			max_channel_saturation_power_of_half: DEFAULT_MAX_CHANNEL_SATURATION_POW_HALF,
		}
	}
}

/// The recipient of a payment, differing based on whether they've hidden their identity with route
/// blinding.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum Payee {
	/// The recipient provided blinded paths and payinfo to reach them. The blinded paths themselves
	/// will be included in the final [`Route`].
	Blinded {
		/// Aggregated routing info and blinded paths, for routing to the payee without knowing their
		/// node id.
		route_hints: Vec<BlindedPaymentPath>,
		/// Features supported by the payee.
		///
		/// May be set from the payee's invoice. May be `None` if the invoice does not contain any
		/// features.
		features: Option<Bolt12InvoiceFeatures>,
	},
	/// The recipient included these route hints in their BOLT11 invoice.
	Clear {
		/// The node id of the payee.
		node_id: PublicKey,
		/// Hints for routing to the payee, containing channels connecting the payee to public nodes.
		route_hints: Vec<RouteHint>,
		/// Features supported by the payee.
		///
		/// May be set from the payee's invoice or via [`for_keysend`]. May be `None` if the invoice
		/// does not contain any features.
		///
		/// [`for_keysend`]: PaymentParameters::for_keysend
		features: Option<Bolt11InvoiceFeatures>,
		/// The minimum CLTV delta at the end of the route. This value must not be zero.
		final_cltv_expiry_delta: u32,
	},
}

impl Payee {
	fn node_id(&self) -> Option<PublicKey> {
		match self {
			Self::Clear { node_id, .. } => Some(*node_id),
			_ => None,
		}
	}
	fn node_features(&self) -> Option<NodeFeatures> {
		match self {
			Self::Clear { features, .. } => features.as_ref().map(|f| f.to_context()),
			Self::Blinded { features, .. } => features.as_ref().map(|f| f.to_context()),
		}
	}
	#[rustfmt::skip]
	fn supports_basic_mpp(&self) -> bool {
		match self {
			Self::Clear { features, .. } => features.as_ref().map_or(false, |f| f.supports_basic_mpp()),
			Self::Blinded { features, .. } => features.as_ref().map_or(false, |f| f.supports_basic_mpp()),
		}
	}
	fn features(&self) -> Option<FeaturesRef> {
		match self {
			Self::Clear { features, .. } => features.as_ref().map(|f| FeaturesRef::Bolt11(f)),
			Self::Blinded { features, .. } => features.as_ref().map(|f| FeaturesRef::Bolt12(f)),
		}
	}
	fn final_cltv_expiry_delta(&self) -> Option<u32> {
		match self {
			Self::Clear { final_cltv_expiry_delta, .. } => Some(*final_cltv_expiry_delta),
			_ => None,
		}
	}
	#[rustfmt::skip]
	pub(crate) fn blinded_route_hints(&self) -> &[BlindedPaymentPath] {
		match self {
			Self::Blinded { route_hints, .. } => &route_hints[..],
			Self::Clear { .. } => &[]
		}
	}

	#[rustfmt::skip]
	pub(crate) fn blinded_route_hints_mut(&mut self) -> &mut [BlindedPaymentPath] {
		match self {
			Self::Blinded { route_hints, .. } => &mut route_hints[..],
			Self::Clear { .. } => &mut []
		}
	}

	#[rustfmt::skip]
	fn unblinded_route_hints(&self) -> &[RouteHint] {
		match self {
			Self::Blinded { .. } => &[],
			Self::Clear { route_hints, .. } => &route_hints[..]
		}
	}
}

enum FeaturesRef<'a> {
	Bolt11(&'a Bolt11InvoiceFeatures),
	Bolt12(&'a Bolt12InvoiceFeatures),
}
enum Features {
	Bolt11(Bolt11InvoiceFeatures),
	Bolt12(Bolt12InvoiceFeatures),
}

impl Features {
	fn bolt12(self) -> Option<Bolt12InvoiceFeatures> {
		match self {
			Self::Bolt12(f) => Some(f),
			_ => None,
		}
	}
	fn bolt11(self) -> Option<Bolt11InvoiceFeatures> {
		match self {
			Self::Bolt11(f) => Some(f),
			_ => None,
		}
	}
}

impl<'a> Writeable for FeaturesRef<'a> {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		match self {
			Self::Bolt11(f) => Ok(f.write(w)?),
			Self::Bolt12(f) => Ok(f.write(w)?),
		}
	}
}

impl ReadableArgs<bool> for Features {
	#[rustfmt::skip]
	fn read<R: io::Read>(reader: &mut R, bolt11: bool) -> Result<Self, DecodeError> {
		if bolt11 { return Ok(Self::Bolt11(Readable::read(reader)?)) }
		Ok(Self::Bolt12(Readable::read(reader)?))
	}
}

impl Writeable for RouteHint {
	fn write<W: crate::util::ser::Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
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

impl_writeable_tlv_based!(RouteHintHop, {
	(0, src_node_id, required),
	(1, htlc_minimum_msat, option),
	(2, short_channel_id, required),
	(3, htlc_maximum_msat, option),
	(4, fees, required),
	(6, cltv_expiry_delta, required),
});

#[derive(Eq, PartialEq)]
#[repr(align(32))] // Force the size to 32 bytes
struct RouteGraphNode {
	node_counter: u32,
	score: u128,
	// The maximum value a yet-to-be-constructed payment path might flow through this node.
	// This value is upper-bounded by us by:
	// - how much is needed for a path being constructed
	// - how much value can channels following this node (up to the destination) can contribute,
	//   considering their capacity and fees
	value_contribution_msat: u64,
	total_cltv_delta: u16,
	/// The number of hops walked up to this node.
	path_length_to_node: u8,
}

impl cmp::Ord for RouteGraphNode {
	#[rustfmt::skip]
	fn cmp(&self, other: &RouteGraphNode) -> cmp::Ordering {
		other.score.cmp(&self.score)
			.then_with(|| self.value_contribution_msat.cmp(&other.value_contribution_msat))
			.then_with(|| other.path_length_to_node.cmp(&self.path_length_to_node))
			.then_with(|| other.node_counter.cmp(&self.node_counter))
	}
}

impl cmp::PartialOrd for RouteGraphNode {
	fn partial_cmp(&self, other: &RouteGraphNode) -> Option<cmp::Ordering> {
		Some(self.cmp(other))
	}
}

// While RouteGraphNode can be laid out with fewer bytes, performance appears to be improved
// substantially when it is laid out at exactly 32 bytes.
const _GRAPH_NODE_32: () = assert!(core::mem::size_of::<RouteGraphNode>() == 32);

/// A [`CandidateRouteHop::FirstHop`] entry.
#[derive(Clone, Debug)]
pub struct FirstHopCandidate<'a> {
	/// Channel details of the first hop
	///
	/// [`ChannelDetails::get_outbound_payment_scid`] MUST be `Some` (indicating the channel
	/// has been funded and is able to pay), and accessor methods may panic otherwise.
	///
	/// [`find_route`] validates this prior to constructing a [`CandidateRouteHop`].
	///
	/// This is not exported to bindings users as lifetimes are not expressible in most languages.
	pub details: &'a ChannelDetails,
	/// The node id of the payer, which is also the source side of this candidate route hop.
	///
	/// This is not exported to bindings users as lifetimes are not expressible in most languages.
	pub payer_node_id: &'a NodeId,
	/// A unique ID which describes the payer.
	///
	/// It will not conflict with any [`NodeInfo::node_counter`]s, but may be equal to one if the
	/// payer is a public node.
	///
	/// [`NodeInfo::node_counter`]: super::gossip::NodeInfo::node_counter
	pub(crate) payer_node_counter: u32,
	/// A unique ID which describes the first hop counterparty.
	///
	/// It will not conflict with any [`NodeInfo::node_counter`]s, but may be equal to one if the
	/// counterparty is a public node.
	///
	/// [`NodeInfo::node_counter`]: super::gossip::NodeInfo::node_counter
	pub(crate) target_node_counter: u32,
}

/// A [`CandidateRouteHop::PublicHop`] entry.
#[derive(Clone, Debug)]
pub struct PublicHopCandidate<'a> {
	/// Information about the channel, including potentially its capacity and
	/// direction-specific information.
	///
	/// This is not exported to bindings users as lifetimes are not expressible in most languages.
	pub info: DirectedChannelInfo<'a>,
	/// The short channel ID of the channel, i.e. the identifier by which we refer to this
	/// channel.
	pub short_channel_id: u64,
}

/// A [`CandidateRouteHop::PrivateHop`] entry.
#[derive(Clone, Debug)]
pub struct PrivateHopCandidate<'a> {
	/// Information about the private hop communicated via BOLT 11.
	///
	/// This is not exported to bindings users as lifetimes are not expressible in most languages.
	pub hint: &'a RouteHintHop,
	/// Node id of the next hop in BOLT 11 route hint.
	///
	/// This is not exported to bindings users as lifetimes are not expressible in most languages.
	pub target_node_id: &'a NodeId,
	/// A unique ID which describes the source node of the hop (further from the payment target).
	///
	/// It will not conflict with any [`NodeInfo::node_counter`]s, but may be equal to one if the
	/// node is a public node.
	///
	/// [`NodeInfo::node_counter`]: super::gossip::NodeInfo::node_counter
	pub(crate) source_node_counter: u32,
	/// A unique ID which describes the destination node of the hop (towards the payment target).
	///
	/// It will not conflict with any [`NodeInfo::node_counter`]s, but may be equal to one if the
	/// node is a public node.
	///
	/// [`NodeInfo::node_counter`]: super::gossip::NodeInfo::node_counter
	pub(crate) target_node_counter: u32,
}

/// A [`CandidateRouteHop::Blinded`] entry.
#[derive(Clone, Debug)]
pub struct BlindedPathCandidate<'a> {
	/// The node id of the introduction node, resolved from either the [`NetworkGraph`] or first
	/// hops.
	///
	/// This is not exported to bindings users as lifetimes are not expressible in most languages.
	pub source_node_id: &'a NodeId,
	/// Information about the blinded path including the fee, HTLC amount limits, and
	/// cryptographic material required to build an HTLC through the given path.
	///
	/// This is not exported to bindings users as lifetimes are not expressible in most languages.
	pub hint: &'a BlindedPaymentPath,
	/// Index of the hint in the original list of blinded hints.
	///
	/// This is used to cheaply uniquely identify this blinded path, even though we don't have
	/// a short channel ID for this hop.
	hint_idx: usize,
	/// A unique ID which describes the introduction point of the blinded path.
	///
	/// It will not conflict with any [`NodeInfo::node_counter`]s, but will generally be equal to
	/// one from the public network graph (assuming the introduction point is a public node).
	///
	/// [`NodeInfo::node_counter`]: super::gossip::NodeInfo::node_counter
	source_node_counter: u32,
}

/// A [`CandidateRouteHop::OneHopBlinded`] entry.
#[derive(Clone, Debug)]
pub struct OneHopBlindedPathCandidate<'a> {
	/// The node id of the introduction node, resolved from either the [`NetworkGraph`] or first
	/// hops.
	///
	/// This is not exported to bindings users as lifetimes are not expressible in most languages.
	pub source_node_id: &'a NodeId,
	/// Information about the blinded path including the fee, HTLC amount limits, and
	/// cryptographic material required to build an HTLC terminating with the given path.
	///
	/// Note that the [`BlindedPayInfo`] is ignored here.
	///
	/// This is not exported to bindings users as lifetimes are not expressible in most languages.
	///
	/// [`BlindedPayInfo`]: crate::blinded_path::payment::BlindedPayInfo
	pub hint: &'a BlindedPaymentPath,
	/// Index of the hint in the original list of blinded hints.
	///
	/// This is used to cheaply uniquely identify this blinded path, even though we don't have
	/// a short channel ID for this hop.
	hint_idx: usize,
	/// A unique ID which describes the introduction point of the blinded path.
	///
	/// It will not conflict with any [`NodeInfo::node_counter`]s, but will generally be equal to
	/// one from the public network graph (assuming the introduction point is a public node).
	///
	/// [`NodeInfo::node_counter`]: super::gossip::NodeInfo::node_counter
	source_node_counter: u32,
}

/// A wrapper around the various hop representations.
///
/// Can be used to examine the properties of a hop,
/// potentially to decide whether to include it in a route.
#[derive(Clone, Debug)]
pub enum CandidateRouteHop<'a> {
	/// A hop from the payer, where the outbound liquidity is known.
	FirstHop(FirstHopCandidate<'a>),
	/// A hop found in the [`ReadOnlyNetworkGraph`].
	PublicHop(PublicHopCandidate<'a>),
	/// A private hop communicated by the payee, generally via a BOLT 11 invoice.
	///
	/// Because BOLT 11 route hints can take multiple hops to get to the destination, this may not
	/// terminate at the payee.
	PrivateHop(PrivateHopCandidate<'a>),
	/// A blinded path which starts with an introduction point and ultimately terminates with the
	/// payee.
	///
	/// Because we don't know the payee's identity, [`CandidateRouteHop::target`] will return
	/// `None` in this state.
	///
	/// Because blinded paths are "all or nothing", and we cannot use just one part of a blinded
	/// path, the full path is treated as a single [`CandidateRouteHop`].
	Blinded(BlindedPathCandidate<'a>),
	/// Similar to [`Self::Blinded`], but the path here only has one hop.
	///
	/// While we treat this similarly to [`CandidateRouteHop::Blinded`] in many respects (e.g.
	/// returning `None` from [`CandidateRouteHop::target`]), in this case we do actually know the
	/// payee's identity - it's the introduction point!
	///
	/// [`BlindedPayInfo`] provided for 1-hop blinded paths is ignored because it is meant to apply
	/// to the hops *between* the introduction node and the destination.
	///
	/// This primarily exists to track that we need to included a blinded path at the end of our
	/// [`Route`], even though it doesn't actually add an additional hop in the payment.
	///
	/// [`BlindedPayInfo`]: crate::blinded_path::payment::BlindedPayInfo
	OneHopBlinded(OneHopBlindedPathCandidate<'a>),
}

impl<'a> CandidateRouteHop<'a> {
	/// Returns the short channel ID for this hop, if one is known.
	///
	/// This SCID could be an alias or a globally unique SCID, and thus is only expected to
	/// uniquely identify this channel in conjunction with the [`CandidateRouteHop::source`].
	///
	/// Returns `Some` as long as the candidate is a [`CandidateRouteHop::PublicHop`], a
	/// [`CandidateRouteHop::PrivateHop`] from a BOLT 11 route hint, or a
	/// [`CandidateRouteHop::FirstHop`] with a known [`ChannelDetails::get_outbound_payment_scid`]
	/// (which is always true for channels which are funded and ready for use).
	///
	/// In other words, this should always return `Some` as long as the candidate hop is not a
	/// [`CandidateRouteHop::Blinded`] or a [`CandidateRouteHop::OneHopBlinded`].
	///
	/// Note that this is deliberately not public as it is somewhat of a footgun because it doesn't
	/// define a global namespace.
	#[inline]
	fn short_channel_id(&self) -> Option<u64> {
		match self {
			CandidateRouteHop::FirstHop(hop) => hop.details.get_outbound_payment_scid(),
			CandidateRouteHop::PublicHop(hop) => Some(hop.short_channel_id),
			CandidateRouteHop::PrivateHop(hop) => Some(hop.hint.short_channel_id),
			CandidateRouteHop::Blinded(_) => None,
			CandidateRouteHop::OneHopBlinded(_) => None,
		}
	}

	/// Returns the globally unique short channel ID for this hop, if one is known.
	///
	/// This only returns `Some` if the channel is public (either our own, or one we've learned
	/// from the public network graph), and thus the short channel ID we have for this channel is
	/// globally unique and identifies this channel in a global namespace.
	#[inline]
	#[rustfmt::skip]
	pub fn globally_unique_short_channel_id(&self) -> Option<u64> {
		match self {
			CandidateRouteHop::FirstHop(hop) => if hop.details.is_announced { hop.details.short_channel_id } else { None },
			CandidateRouteHop::PublicHop(hop) => Some(hop.short_channel_id),
			CandidateRouteHop::PrivateHop(_) => None,
			CandidateRouteHop::Blinded(_) => None,
			CandidateRouteHop::OneHopBlinded(_) => None,
		}
	}

	// NOTE: This may alloc memory so avoid calling it in a hot code path.
	fn features(&self) -> ChannelFeatures {
		match self {
			CandidateRouteHop::FirstHop(hop) => hop.details.counterparty.features.to_context(),
			CandidateRouteHop::PublicHop(hop) => hop.info.channel().features.clone(),
			CandidateRouteHop::PrivateHop(_) => ChannelFeatures::empty(),
			CandidateRouteHop::Blinded(_) => ChannelFeatures::empty(),
			CandidateRouteHop::OneHopBlinded(_) => ChannelFeatures::empty(),
		}
	}

	/// Returns the required difference in HTLC CLTV expiry between the [`Self::source`] and the
	/// next-hop for an HTLC taking this hop.
	///
	/// This is the time that the node(s) in this hop have to claim the HTLC on-chain if the
	/// next-hop goes on chain with a payment preimage.
	#[inline]
	pub fn cltv_expiry_delta(&self) -> u32 {
		match self {
			CandidateRouteHop::FirstHop(_) => 0,
			CandidateRouteHop::PublicHop(hop) => hop.info.direction().cltv_expiry_delta as u32,
			CandidateRouteHop::PrivateHop(hop) => hop.hint.cltv_expiry_delta as u32,
			CandidateRouteHop::Blinded(hop) => hop.hint.payinfo.cltv_expiry_delta as u32,
			CandidateRouteHop::OneHopBlinded(_) => 0,
		}
	}

	/// Returns the minimum amount that can be sent over this hop, in millisatoshis.
	#[inline]
	pub fn htlc_minimum_msat(&self) -> u64 {
		match self {
			CandidateRouteHop::FirstHop(hop) => hop.details.next_outbound_htlc_minimum_msat,
			CandidateRouteHop::PublicHop(hop) => hop.info.direction().htlc_minimum_msat,
			CandidateRouteHop::PrivateHop(hop) => hop.hint.htlc_minimum_msat.unwrap_or(0),
			CandidateRouteHop::Blinded(hop) => hop.hint.payinfo.htlc_minimum_msat,
			CandidateRouteHop::OneHopBlinded { .. } => 0,
		}
	}

	#[inline(always)]
	fn src_node_counter(&self) -> u32 {
		match self {
			CandidateRouteHop::FirstHop(hop) => hop.payer_node_counter,
			CandidateRouteHop::PublicHop(hop) => hop.info.source_counter(),
			CandidateRouteHop::PrivateHop(hop) => hop.source_node_counter,
			CandidateRouteHop::Blinded(hop) => hop.source_node_counter,
			CandidateRouteHop::OneHopBlinded(hop) => hop.source_node_counter,
		}
	}

	#[inline]
	fn target_node_counter(&self) -> Option<u32> {
		match self {
			CandidateRouteHop::FirstHop(hop) => Some(hop.target_node_counter),
			CandidateRouteHop::PublicHop(hop) => Some(hop.info.target_counter()),
			CandidateRouteHop::PrivateHop(hop) => Some(hop.target_node_counter),
			CandidateRouteHop::Blinded(_) => None,
			CandidateRouteHop::OneHopBlinded(_) => None,
		}
	}

	/// Returns the fees that must be paid to route an HTLC over this channel.
	#[inline]
	#[rustfmt::skip]
	pub fn fees(&self) -> RoutingFees {
		match self {
			CandidateRouteHop::FirstHop(_) => RoutingFees {
				base_msat: 0, proportional_millionths: 0,
			},
			CandidateRouteHop::PublicHop(hop) => hop.info.direction().fees,
			CandidateRouteHop::PrivateHop(hop) => hop.hint.fees,
			CandidateRouteHop::Blinded(hop) => {
				RoutingFees {
					base_msat: hop.hint.payinfo.fee_base_msat,
					proportional_millionths: hop.hint.payinfo.fee_proportional_millionths
				}
			},
			CandidateRouteHop::OneHopBlinded(_) =>
				RoutingFees { base_msat: 0, proportional_millionths: 0 },
		}
	}

	/// Fetch the effective capacity of this hop.
	///
	/// Note that this may be somewhat expensive, so calls to this should be limited and results
	/// cached!
	#[rustfmt::skip]
	fn effective_capacity(&self) -> EffectiveCapacity {
		match self {
			CandidateRouteHop::FirstHop(hop) => EffectiveCapacity::ExactLiquidity {
				liquidity_msat: hop.details.next_outbound_htlc_limit_msat,
			},
			CandidateRouteHop::PublicHop(hop) => hop.info.effective_capacity(),
			CandidateRouteHop::PrivateHop(PrivateHopCandidate { hint: RouteHintHop { htlc_maximum_msat: Some(max), .. }, .. }) =>
				EffectiveCapacity::HintMaxHTLC { amount_msat: *max },
			CandidateRouteHop::PrivateHop(PrivateHopCandidate { hint: RouteHintHop { htlc_maximum_msat: None, .. }, .. }) =>
				EffectiveCapacity::Infinite,
			CandidateRouteHop::Blinded(hop) =>
				EffectiveCapacity::HintMaxHTLC { amount_msat: hop.hint.payinfo.htlc_maximum_msat },
			CandidateRouteHop::OneHopBlinded(_) => EffectiveCapacity::Infinite,
		}
	}

	/// Returns an ID describing the given hop.
	///
	/// See the docs on [`CandidateHopId`] for when this is, or is not, unique.
	#[inline]
	#[rustfmt::skip]
	fn id(&self) -> CandidateHopId {
		match self {
			CandidateRouteHop::Blinded(hop) => CandidateHopId::Blinded(hop.hint_idx),
			CandidateRouteHop::OneHopBlinded(hop) => CandidateHopId::Blinded(hop.hint_idx),
			_ => CandidateHopId::Clear((self.short_channel_id().unwrap(), self.source() < self.target().unwrap())),
		}
	}
	#[rustfmt::skip]
	fn blinded_path(&self) -> Option<&'a BlindedPaymentPath> {
		match self {
			CandidateRouteHop::Blinded(BlindedPathCandidate { hint, .. }) | CandidateRouteHop::OneHopBlinded(OneHopBlindedPathCandidate { hint, .. }) => {
				Some(&hint)
			},
			_ => None,
		}
	}
	#[rustfmt::skip]
	fn blinded_hint_idx(&self) -> Option<usize> {
		match self {
			Self::Blinded(BlindedPathCandidate { hint_idx, .. }) |
			Self::OneHopBlinded(OneHopBlindedPathCandidate { hint_idx, .. }) => {
				Some(*hint_idx)
			},
			_ => None,
		}
	}
	/// Returns the source node id of current hop.
	///
	/// Source node id refers to the node forwarding the HTLC through this hop.
	///
	/// For [`Self::FirstHop`] we return payer's node id.
	#[inline]
	pub fn source(&self) -> NodeId {
		match self {
			CandidateRouteHop::FirstHop(hop) => *hop.payer_node_id,
			CandidateRouteHop::PublicHop(hop) => *hop.info.source(),
			CandidateRouteHop::PrivateHop(hop) => hop.hint.src_node_id.into(),
			CandidateRouteHop::Blinded(hop) => *hop.source_node_id,
			CandidateRouteHop::OneHopBlinded(hop) => *hop.source_node_id,
		}
	}
	/// Returns the target node id of this hop, if known.
	///
	/// Target node id refers to the node receiving the HTLC after this hop.
	///
	/// For [`Self::Blinded`] we return `None` because the ultimate destination after the blinded
	/// path is unknown.
	///
	/// For [`Self::OneHopBlinded`] we return `None` because the target is the same as the source,
	/// and such a return value would be somewhat nonsensical.
	#[inline]
	pub fn target(&self) -> Option<NodeId> {
		match self {
			CandidateRouteHop::FirstHop(hop) => Some(hop.details.counterparty.node_id.into()),
			CandidateRouteHop::PublicHop(hop) => Some(*hop.info.target()),
			CandidateRouteHop::PrivateHop(hop) => Some(*hop.target_node_id),
			CandidateRouteHop::Blinded(_) => None,
			CandidateRouteHop::OneHopBlinded(_) => None,
		}
	}
}

/// A unique(ish) identifier for a specific [`CandidateRouteHop`].
///
/// For blinded paths, this ID is unique only within a given [`find_route`] call.
///
/// For other hops, because SCIDs between private channels and public channels can conflict, this
/// isn't guaranteed to be unique at all.
///
/// For our uses, this is generally fine, but it is not public as it is otherwise a rather
/// difficult-to-use API.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialOrd, PartialEq)]
enum CandidateHopId {
	/// Contains (scid, src_node_id < target_node_id)
	Clear((u64, bool)),
	/// Index of the blinded route hint in [`Payee::Blinded::route_hints`].
	Blinded(usize),
}

/// To avoid doing [`PublicKey`] -> [`PathBuildingHop`] hashtable lookups, we assign each
/// [`PublicKey`]/node a `usize` index and simply keep a `Vec` of values.
///
/// While this is easy for gossip-originating nodes (the [`DirectedChannelInfo`] exposes "counters"
/// for us for this purpose) we have to have our own indexes for nodes originating from invoice
/// hints, local channels, or blinded path fake nodes.
///
/// This wrapper handles all this for us, allowing look-up of counters from the various contexts.
///
/// It is first built by passing all [`NodeId`]s that we'll ever care about (which are not in our
/// [`NetworkGraph`], e.g. those from first- and last-hop hints and blinded path introduction
/// points) either though [`NodeCountersBuilder::select_node_counter_for_pubkey`] or
/// [`NodeCountersBuilder::select_node_counter_for_id`], then calling [`NodeCountersBuilder::build`]
/// and using the resulting [`NodeCounters`] to look up any counters.
///
/// [`NodeCounters::private_node_counter_from_pubkey`], specifically, will return `Some` iff
/// [`NodeCountersBuilder::select_node_counter_for_pubkey`] was called on the same key (not
/// [`NodeCountersBuilder::select_node_counter_for_id`]). It will also return a cached copy of the
/// [`PublicKey`] -> [`NodeId`] conversion.
struct NodeCounters<'a> {
	network_graph: &'a ReadOnlyNetworkGraph<'a>,
	private_node_id_to_node_counter: HashMap<NodeId, u32>,
	private_hop_key_cache: HashMap<PublicKey, (NodeId, u32)>,
}

struct NodeCountersBuilder<'a>(NodeCounters<'a>);

impl<'a> NodeCountersBuilder<'a> {
	fn new(network_graph: &'a ReadOnlyNetworkGraph) -> Self {
		Self(NodeCounters {
			network_graph,
			private_node_id_to_node_counter: new_hash_map(),
			private_hop_key_cache: new_hash_map(),
		})
	}

	fn select_node_counter_for_pubkey(&mut self, pubkey: PublicKey) -> u32 {
		let id = NodeId::from_pubkey(&pubkey);
		let counter = self.select_node_counter_for_id(id);
		self.0.private_hop_key_cache.insert(pubkey, (id, counter));
		counter
	}

	#[rustfmt::skip]
	fn select_node_counter_for_id(&mut self, node_id: NodeId) -> u32 {
		// For any node_id, we first have to check if its in the existing network graph, and then
		// ensure that we always look up in our internal map first.
		self.0.network_graph.nodes().get(&node_id)
			.map(|node| node.node_counter)
			.unwrap_or_else(|| {
				let next_node_counter = self.0.network_graph.max_node_counter() + 1 +
					self.0.private_node_id_to_node_counter.len() as u32;
				*self.0.private_node_id_to_node_counter.entry(node_id).or_insert(next_node_counter)
			})
	}

	#[rustfmt::skip]
	fn build(self) -> NodeCounters<'a> { self.0 }
}

impl<'a> NodeCounters<'a> {
	#[rustfmt::skip]
	fn max_counter(&self) -> u32 {
		self.network_graph.max_node_counter() +
			self.private_node_id_to_node_counter.len() as u32
	}

	fn private_node_counter_from_pubkey(&self, pubkey: &PublicKey) -> Option<&(NodeId, u32)> {
		self.private_hop_key_cache.get(pubkey)
	}

	#[rustfmt::skip]
	fn node_counter_from_id(&self, node_id: &NodeId) -> Option<(&NodeId, u32)> {
		self.private_node_id_to_node_counter.get_key_value(node_id).map(|(a, b)| (a, *b))
			.or_else(|| {
				self.network_graph.nodes().get_key_value(node_id)
					.map(|(node_id, node)| (node_id, node.node_counter))
			})
	}
}

/// Calculates the introduction point for each blinded path in the given [`PaymentParameters`], if
/// they can be found.
#[rustfmt::skip]
fn calculate_blinded_path_intro_points<'a, L: Deref>(
	payment_params: &PaymentParameters, node_counters: &'a NodeCounters,
	network_graph: &ReadOnlyNetworkGraph, logger: &L, our_node_id: NodeId,
	first_hop_targets: &HashMap<NodeId, (Vec<&ChannelDetails>, u32)>,
) -> Result<Vec<Option<(&'a NodeId, u32)>>, &'static str>
where L::Target: Logger {
	let introduction_node_id_cache = payment_params.payee.blinded_route_hints().iter()
		.map(|path| {
			match path.introduction_node() {
				IntroductionNode::NodeId(pubkey) => {
					// Note that this will only return `Some` if the `pubkey` is somehow known to
					// us (i.e. a channel counterparty or in the network graph).
					node_counters.node_counter_from_id(&NodeId::from_pubkey(&pubkey))
				},
				IntroductionNode::DirectedShortChannelId(direction, scid) => {
					path.public_introduction_node_id(network_graph)
						.map(|node_id_ref| *node_id_ref)
						.or_else(|| {
							first_hop_targets.iter().find(|(_, (channels, _))|
								channels
									.iter()
									.any(|details| Some(*scid) == details.get_outbound_payment_scid())
							).map(|(cp, _)| direction.select_node_id(our_node_id, *cp))
						})
						.and_then(|node_id| node_counters.node_counter_from_id(&node_id))
				},
			}
		})
		.collect::<Vec<_>>();
	match &payment_params.payee {
		Payee::Clear { route_hints, node_id, .. } => {
			for route in route_hints.iter() {
				for hop in &route.0 {
					if hop.src_node_id == *node_id {
						return Err("Route hint cannot have the payee as the source.");
					}
				}
			}
		},
		Payee::Blinded { route_hints, .. } => {
			if introduction_node_id_cache.iter().all(|info_opt| info_opt.map(|(a, _)| a) == Some(&our_node_id)) {
				return Err("Cannot generate a route to blinded paths if we are the introduction node to all of them");
			}
			for (blinded_path, info_opt) in route_hints.iter().zip(introduction_node_id_cache.iter()) {
				if blinded_path.blinded_hops().len() == 0 {
					return Err("0-hop blinded path provided");
				}
				let introduction_node_id = match info_opt {
					None => continue,
					Some(info) => info.0,
				};
				if *introduction_node_id == our_node_id {
					log_info!(logger, "Got blinded path with ourselves as the introduction node, ignoring");
				} else if blinded_path.blinded_hops().len() == 1 &&
					route_hints
						.iter().zip(introduction_node_id_cache.iter())
						.filter(|(p, _)| p.blinded_hops().len() == 1)
						.any(|(_, iter_info_opt)| iter_info_opt.is_some() && iter_info_opt != info_opt)
				{
					return Err("1-hop blinded paths must all have matching introduction node ids");
				}
			}
		}
	}

	Ok(introduction_node_id_cache)
}

#[inline]
#[rustfmt::skip]
fn max_htlc_from_capacity(capacity: EffectiveCapacity, max_channel_saturation_power_of_half: u8) -> u64 {
	let saturation_shift: u32 = max_channel_saturation_power_of_half as u32;
	match capacity {
		EffectiveCapacity::ExactLiquidity { liquidity_msat } => liquidity_msat,
		EffectiveCapacity::Infinite => u64::max_value(),
		EffectiveCapacity::Unknown => EffectiveCapacity::Unknown.as_msat(),
		EffectiveCapacity::AdvertisedMaxHTLC { amount_msat } =>
			amount_msat.checked_shr(saturation_shift).unwrap_or(0),
		// Treat htlc_maximum_msat from a route hint as an exact liquidity amount, since the invoice is
		// expected to have been generated from up-to-date capacity information.
		EffectiveCapacity::HintMaxHTLC { amount_msat } => amount_msat,
		EffectiveCapacity::Total { capacity_msat, htlc_maximum_msat } =>
			cmp::min(capacity_msat.checked_shr(saturation_shift).unwrap_or(0), htlc_maximum_msat),
	}
}

#[rustfmt::skip]
fn iter_equal<I1: Iterator, I2: Iterator>(mut iter_a: I1, mut iter_b: I2)
-> bool where I1::Item: PartialEq<I2::Item> {
	loop {
		let a = iter_a.next();
		let b = iter_b.next();
		if a.is_none() && b.is_none() { return true; }
		if a.is_none() || b.is_none() { return false; }
		if a.unwrap().ne(&b.unwrap()) { return false; }
	}
}

/// It's useful to keep track of the hops associated with the fees required to use them,
/// so that we can choose cheaper paths (as per Dijkstra's algorithm).
/// Fee values should be updated only in the context of the whole path, see update_value_and_recompute_fees.
/// These fee values are useful to choose hops as we traverse the graph "payee-to-payer".
#[derive(Clone)]
#[repr(align(128))]
struct PathBuildingHop<'a> {
	candidate: CandidateRouteHop<'a>,
	/// If we've already processed a node as the best node, we shouldn't process it again. Normally
	/// we'd just ignore it if we did as all channels would have a higher new fee, but because we
	/// may decrease the amounts in use as we walk the graph, the actual calculated fee may
	/// decrease as well. Thus, we have to explicitly track which nodes have been processed and
	/// avoid processing them again.
	was_processed: bool,
	/// If we've already processed a channel backwards from a target node, we shouldn't update our
	/// selected best path from that node to the destination. This should never happen, but with
	/// multiple codepaths processing channels we've had issues here in the past, so in debug-mode
	/// we track it and assert on it when processing a node.
	#[cfg(all(not(ldk_bench), any(test, fuzzing)))]
	best_path_from_hop_selected: bool,
	/// When processing a node as the next best-score candidate, we want to quickly check if it is
	/// a direct counterparty of ours, using our local channel information immediately if we can.
	///
	/// In order to do so efficiently, we cache whether a node is a direct counterparty here at the
	/// start of a route-finding pass. Unlike all other fields in this struct, this field is never
	/// updated after being initialized - it is set at the start of a route-finding pass and only
	/// read thereafter.
	is_first_hop_target: bool,
	/// Identical to the above, but for handling unblinded last-hops rather than first-hops.
	is_last_hop_target: bool,
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

	fee_msat: u64,

	/// All the fees paid *after* this channel on the way to the destination
	next_hops_fee_msat: u64,
	/// Fee paid for the use of the current channel (see candidate.fees()).
	/// The value will be actually deducted from the counterparty balance on the previous link.
	hop_use_fee_msat: u64,

	/// The quantity of funds we're willing to route over this channel
	value_contribution_msat: u64,
}

const _NODE_MAP_SIZE_TWO_CACHE_LINES: usize = 128 - core::mem::size_of::<Option<PathBuildingHop>>();
const _NODE_MAP_SIZE_EXACTLY_TWO_CACHE_LINES: usize =
	core::mem::size_of::<Option<PathBuildingHop>>() - 128;

impl<'a> core::fmt::Debug for PathBuildingHop<'a> {
	#[rustfmt::skip]
	fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
		let mut debug_struct = f.debug_struct("PathBuildingHop");
		debug_struct
			.field("source_node_id", &self.candidate.source())
			.field("target_node_id", &self.candidate.target())
			.field("short_channel_id", &self.candidate.short_channel_id())
			.field("is_first_hop_target", &self.is_first_hop_target)
			.field("is_last_hop_target", &self.is_last_hop_target)
			.field("total_fee_msat", &self.total_fee_msat)
			.field("next_hops_fee_msat", &self.next_hops_fee_msat)
			.field("hop_use_fee_msat", &self.hop_use_fee_msat)
			.field("total_fee_msat - (next_hops_fee_msat + hop_use_fee_msat)", &(&self.total_fee_msat.saturating_sub(self.next_hops_fee_msat).saturating_sub(self.hop_use_fee_msat)))
			.field("path_penalty_msat", &self.path_penalty_msat)
			.field("path_htlc_minimum_msat", &self.path_htlc_minimum_msat)
			.field("cltv_expiry_delta", &self.candidate.cltv_expiry_delta())
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

	/// Gets the cost (fees plus scorer penalty in msats) of the path divided by the value we
	/// can/will send over the path. This is also the heap score during our Dijkstra's walk.
	fn get_cost_per_msat(&self) -> u128 {
		let fee_cost = self.get_cost_msat();
		let value_msat = self.get_value_msat();
		debug_assert!(value_msat > 0, "Paths should always send more than 0 msat");
		if fee_cost == u64::MAX || value_msat == 0 {
			u64::MAX.into()
		} else {
			// In order to avoid integer division precision loss, we simply shift the costs up to
			// the top half of a u128 and divide by the value (which is, at max, just under a u64).
			((fee_cost as u128) << 64) / value_msat as u128
		}
	}

	/// Gets the fees plus scorer penalty in msats of the path.
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
	// This function may also be used to increase the value being transferred in the case that
	// overestimating later hops' fees caused us to underutilize earlier hops' capacity.
	//
	// Note that this function is not aware of the available_liquidity limit of any hops.
	//
	// Returns the amount that this path contributes to the total payment value, which may be greater
	// than `value_msat` if we had to overpay to meet the final node's `htlc_minimum_msat`.
	#[rustfmt::skip]
	fn update_value_and_recompute_fees(&mut self, value_msat: u64) -> u64 {
		let mut extra_contribution_msat = 0;
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

			let cur_hop = &mut self.hops.get_mut(i).unwrap().0;
			cur_hop.next_hops_fee_msat = total_fee_paid_msat;
			cur_hop.path_penalty_msat += extra_contribution_msat;
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

				// We remember and return the extra fees on the final hop to allow accounting for
				// them in the path's value contribution.
				if last_hop {
					extra_contribution_msat = extra_fees_msat;
				} else {
					total_fee_paid_msat += extra_fees_msat;
					cur_hop_fees_msat += extra_fees_msat;
				}
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
					// It should not be possible because this function is only called either to reduce the
					// value or with a larger amount that was already checked for overflow in
					// `compute_max_final_value_contribution`. In the former case, compute_fee was already
					// called with the same fees for larger amount and there was no overflow.
					unreachable!();
				}
			}
		}
		value_msat + extra_contribution_msat
	}

	/// Returns the hop which most limited our maximum contribution as well as the maximum
	/// contribution this path can make to the final value of the payment.
	/// May be slightly lower than the actual max due to rounding errors when aggregating fees
	/// along the path.
	#[rustfmt::skip]
	fn max_final_value_msat(
		&self, used_liquidities: &HashMap<CandidateHopId, u64>, channel_saturation_pow_half: u8
	) -> (usize, u64) {
		let mut max_path_contribution = (0, u64::MAX);
		for (idx, (hop, _)) in self.hops.iter().enumerate() {
			let hop_effective_capacity_msat = hop.candidate.effective_capacity();
			let hop_max_msat = max_htlc_from_capacity(
				hop_effective_capacity_msat, channel_saturation_pow_half
			).saturating_sub(*used_liquidities.get(&hop.candidate.id()).unwrap_or(&0_u64));

			let next_hops_feerates_iter = self.hops
				.iter()
				.skip(idx + 1)
				.map(|(hop, _)| hop.candidate.fees());

			// Aggregate the fees of the hops that come after this one, and use those fees to compute the
			// maximum amount that this hop can contribute to the final value received by the payee.
			let (next_hops_aggregated_base, next_hops_aggregated_prop) =
				crate::blinded_path::payment::compute_aggregated_base_prop_fee(next_hops_feerates_iter).unwrap();

			// floor(((hop_max_msat - agg_base) * 1_000_000) / (1_000_000 + agg_prop))
			let hop_max_final_value_contribution = (hop_max_msat as u128)
				.checked_sub(next_hops_aggregated_base as u128)
				.and_then(|f| f.checked_mul(1_000_000))
				.and_then(|f| f.checked_add(next_hops_aggregated_prop as u128))
				.map(|f| f / ((next_hops_aggregated_prop as u128).saturating_add(1_000_000)));

			if let Some(hop_contribution) = hop_max_final_value_contribution {
				let hop_contribution: u64 = hop_contribution.try_into().unwrap_or(u64::MAX);
				if hop_contribution <= max_path_contribution.1 {
					max_path_contribution = (idx, hop_contribution);
				}
			} else { debug_assert!(false); }
		}

		max_path_contribution
	}
}

#[inline(always)]
/// Calculate the fees required to route the given amount over a channel with the given fees.
#[rustfmt::skip]
fn compute_fees(amount_msat: u64, channel_fees: RoutingFees) -> Option<u64> {
	amount_msat.checked_mul(channel_fees.proportional_millionths as u64)
		.and_then(|part| (channel_fees.base_msat as u64).checked_add(part / 1_000_000))
}

#[inline(always)]
/// Calculate the fees required to route the given amount over a channel with the given fees,
/// saturating to [`u64::max_value`].
#[rustfmt::skip]
fn compute_fees_saturating(amount_msat: u64, channel_fees: RoutingFees) -> u64 {
	amount_msat.checked_mul(channel_fees.proportional_millionths as u64)
		.map(|prop| prop / 1_000_000).unwrap_or(u64::max_value())
		.saturating_add(channel_fees.base_msat as u64)
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

struct LoggedPayeePubkey(Option<PublicKey>);
impl fmt::Display for LoggedPayeePubkey {
	#[rustfmt::skip]
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self.0 {
			Some(pk) => {
				"payee node id ".fmt(f)?;
				pk.fmt(f)
			},
			None => {
				"blinded payee".fmt(f)
			},
		}
	}
}

struct LoggedCandidateHop<'a>(&'a CandidateRouteHop<'a>);
impl<'a> fmt::Display for LoggedCandidateHop<'a> {
	#[rustfmt::skip]
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self.0 {
			CandidateRouteHop::Blinded(BlindedPathCandidate { hint, .. }) | CandidateRouteHop::OneHopBlinded(OneHopBlindedPathCandidate { hint, .. }) => {
				"blinded route hint with introduction node ".fmt(f)?;
				match hint.introduction_node() {
					IntroductionNode::NodeId(pubkey) => write!(f, "id {}", pubkey)?,
					IntroductionNode::DirectedShortChannelId(direction, scid) => {
						match direction {
							Direction::NodeOne => {
								write!(f, "one on channel with SCID {}", scid)?;
							},
							Direction::NodeTwo => {
								write!(f, "two on channel with SCID {}", scid)?;
							},
						}
					}
				}
				" and blinding point ".fmt(f)?;
				hint.blinding_point().fmt(f)
			},
			CandidateRouteHop::FirstHop(_) => {
				"first hop with SCID ".fmt(f)?;
				self.0.short_channel_id().unwrap().fmt(f)
			},
			CandidateRouteHop::PrivateHop(_) => {
				"route hint with SCID ".fmt(f)?;
				self.0.short_channel_id().unwrap().fmt(f)
			},
			_ => {
				"SCID ".fmt(f)?;
				self.0.short_channel_id().unwrap().fmt(f)
			},
		}
	}
}

#[inline]
#[rustfmt::skip]
fn sort_first_hop_channels(
	channels: &mut Vec<&ChannelDetails>, used_liquidities: &HashMap<CandidateHopId, u64>,
	recommended_value_msat: u64, our_node_pubkey: &PublicKey
) {
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
	//
	// Available outbound balances factor in liquidity already reserved for previously found paths.
	channels.sort_unstable_by(|chan_a, chan_b| {
		let chan_a_outbound_limit_msat = chan_a.next_outbound_htlc_limit_msat
			.saturating_sub(*used_liquidities.get(&CandidateHopId::Clear((chan_a.get_outbound_payment_scid().unwrap(),
			our_node_pubkey < &chan_a.counterparty.node_id))).unwrap_or(&0));
		let chan_b_outbound_limit_msat = chan_b.next_outbound_htlc_limit_msat
			.saturating_sub(*used_liquidities.get(&CandidateHopId::Clear((chan_b.get_outbound_payment_scid().unwrap(),
			our_node_pubkey < &chan_b.counterparty.node_id))).unwrap_or(&0));
		if chan_b_outbound_limit_msat < recommended_value_msat || chan_a_outbound_limit_msat < recommended_value_msat {
			// Sort in descending order
			chan_b_outbound_limit_msat.cmp(&chan_a_outbound_limit_msat)
		} else {
			// Sort in ascending order
			chan_a_outbound_limit_msat.cmp(&chan_b_outbound_limit_msat)
		}
	});
}

/// Finds a route from us (payer) to the given target node (payee).
///
/// If the payee provided features in their invoice, they should be provided via the `payee` field
/// in the given [`RouteParameters::payment_params`].
/// Without this, MPP will only be used if the payee's features are available in the network graph.
///
/// Private routing paths between a public node and the target may be included in the `payee` field
/// of [`RouteParameters::payment_params`].
///
/// If some channels aren't announced, it may be useful to fill in `first_hops` with the results
/// from [`ChannelManager::list_usable_channels`]. If it is filled in, the view of these channels
/// from `network_graph` will be ignored, and only those in `first_hops` will be used.
///
/// The fees on channels from us to the next hop are ignored as they are assumed to all be equal.
/// However, the enabled/disabled bit on such channels as well as the `htlc_minimum_msat` /
/// `htlc_maximum_msat` *are* checked as they may change based on the receiving node.
///
/// # Panics
///
/// Panics if first_hops contains channels without `short_channel_id`s;
/// [`ChannelManager::list_usable_channels`] will never include such channels.
///
/// [`ChannelManager::list_usable_channels`]: crate::ln::channelmanager::ChannelManager::list_usable_channels
/// [`Event::PaymentPathFailed`]: crate::events::Event::PaymentPathFailed
/// [`NetworkGraph`]: crate::routing::gossip::NetworkGraph
#[rustfmt::skip]
pub fn find_route<L: Deref, GL: Deref, S: ScoreLookUp>(
	our_node_pubkey: &PublicKey, route_params: &RouteParameters,
	network_graph: &NetworkGraph<GL>, first_hops: Option<&[&ChannelDetails]>, logger: L,
	scorer: &S, score_params: &S::ScoreParams, random_seed_bytes: &[u8; 32]
) -> Result<Route, &'static str>
where L::Target: Logger, GL::Target: Logger {
	let graph_lock = network_graph.read_only();
	let mut route = get_route(our_node_pubkey, &route_params, &graph_lock, first_hops, logger,
		scorer, score_params, random_seed_bytes)?;
	add_random_cltv_offset(&mut route, &route_params.payment_params, &graph_lock, random_seed_bytes);
	Ok(route)
}

#[rustfmt::skip]
pub(crate) fn get_route<L: Deref, S: ScoreLookUp>(
	our_node_pubkey: &PublicKey, route_params: &RouteParameters, network_graph: &ReadOnlyNetworkGraph,
	first_hops: Option<&[&ChannelDetails]>, logger: L, scorer: &S, score_params: &S::ScoreParams,
	_random_seed_bytes: &[u8; 32]
) -> Result<Route, &'static str>
where L::Target: Logger {

	let payment_params = &route_params.payment_params;
	let max_path_length = core::cmp::min(payment_params.max_path_length, MAX_PATH_LENGTH_ESTIMATE);
	let final_value_msat = route_params.final_value_msat;
	// If we're routing to a blinded recipient, we won't have their node id. Therefore, keep the
	// unblinded payee id as an option. We also need a non-optional "payee id" for path construction,
	// so use a dummy id for this in the blinded case.
	let payee_node_id_opt = payment_params.payee.node_id().map(|pk| NodeId::from_pubkey(&pk));
	const DUMMY_BLINDED_PAYEE_ID: [u8; 33] = [2; 33];
	let maybe_dummy_payee_pk = payment_params.payee.node_id().unwrap_or_else(|| PublicKey::from_slice(&DUMMY_BLINDED_PAYEE_ID).unwrap());
	let maybe_dummy_payee_node_id = NodeId::from_pubkey(&maybe_dummy_payee_pk);
	let our_node_id = NodeId::from_pubkey(&our_node_pubkey);

	if payee_node_id_opt.map_or(false, |payee| payee == our_node_id) {
		return Err("Cannot generate a route to ourselves");
	}
	if our_node_id == maybe_dummy_payee_node_id {
		return Err("Invalid origin node id provided, use a different one");
	}

	if final_value_msat > MAX_VALUE_MSAT {
		return Err("Cannot generate a route of more value than all existing satoshis");
	}

	if final_value_msat == 0 {
		return Err("Cannot send a payment of 0 msat");
	}

	let final_cltv_expiry_delta = payment_params.payee.final_cltv_expiry_delta().unwrap_or(0);
	if payment_params.max_total_cltv_expiry_delta <= final_cltv_expiry_delta {
		return Err("Can't find a route where the maximum total CLTV expiry delta is below the final CLTV expiry.");
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
	// 6. Select the paths which have the lowest cost (fee plus scorer penalty) per amount
	//    transferred up to the transfer target value.
	// 7. Reduce the value of the last path until we are sending only the target value.
	// 8. If our maximum channel saturation limit caused us to pick two identical paths, combine
	//    them so that we're not sending two HTLCs along the same path.

	// As for the actual search algorithm, we do a payee-to-payer Dijkstra's sorting by each node's
	// distance from the payee
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

	let network_channels = network_graph.channels();
	let network_nodes = network_graph.nodes();

	if payment_params.max_path_count == 0 {
		return Err("Can't find a route with no paths allowed.");
	}

	// Allow MPP only if we have a features set from somewhere that indicates the payee supports
	// it. If the payee supports it they're supposed to include it in the invoice, so that should
	// work reliably.
	let allow_mpp = if payment_params.max_path_count == 1 {
		false
	} else if payment_params.payee.supports_basic_mpp() {
		true
	} else if let Some(payee) = payee_node_id_opt {
		network_nodes.get(&payee).map_or(false, |node| node.announcement_info.as_ref().map_or(false,
			|info| info.features().supports_basic_mpp()))
	} else { false };

	let max_total_routing_fee_msat = route_params.max_total_routing_fee_msat.unwrap_or(u64::max_value());

	let first_hop_count = first_hops.map(|hops| hops.len()).unwrap_or(0);
	log_trace!(logger, "Searching for a route from payer {} to {} {} MPP and {} first hops {}overriding the network graph of {} nodes and {} channels with a fee limit of {} msat",
		our_node_pubkey, LoggedPayeePubkey(payment_params.payee.node_id()),
		if allow_mpp { "with" } else { "without" },
		first_hop_count, if first_hops.is_some() { "" } else { "not " },
		network_graph.nodes().len(), network_graph.channels().len(),
		max_total_routing_fee_msat);

	if first_hop_count < 10 {
		if let Some(hops) = first_hops {
			for hop in hops {
				log_trace!(
					logger,
					" First hop through {}/{} can send between {}msat and {}msat (inclusive).",
					hop.counterparty.node_id,
					hop.get_outbound_payment_scid().unwrap_or(0),
					hop.next_outbound_htlc_minimum_msat,
					hop.next_outbound_htlc_limit_msat
				);
			}
		}
	}

	let mut node_counter_builder = NodeCountersBuilder::new(&network_graph);

	let payer_node_counter = node_counter_builder.select_node_counter_for_pubkey(*our_node_pubkey);
	let payee_node_counter = node_counter_builder.select_node_counter_for_pubkey(maybe_dummy_payee_pk);

	for route in payment_params.payee.unblinded_route_hints().iter() {
		for hop in route.0.iter() {
			node_counter_builder.select_node_counter_for_pubkey(hop.src_node_id);
		}
	}

	// Step (1). Prepare first and last hop targets.
	//
	// For unblinded first- and last-hop channels, cache them in maps so that we can detect them as
	// we walk the graph and incorporate them into our candidate set.
	// For blinded last-hop paths, look up their introduction point and cache the node counters
	// identifying them.
	let mut first_hop_targets: HashMap<_, (Vec<&ChannelDetails>, u32)> =
		hash_map_with_capacity(if first_hops.is_some() { first_hops.as_ref().unwrap().len() } else { 0 });
	if let Some(hops) = first_hops {
		for chan in hops {
			if chan.get_outbound_payment_scid().is_none() {
				panic!("first_hops should be filled in with usable channels, not pending ones");
			}
			if chan.counterparty.node_id == *our_node_pubkey {
				return Err("First hop cannot have our_node_pubkey as a destination.");
			}
			let counterparty_id = NodeId::from_pubkey(&chan.counterparty.node_id);
			first_hop_targets
				.entry(counterparty_id)
				.or_insert_with(|| {
					// Make sure there's a counter assigned for the counterparty
					let node_counter = node_counter_builder.select_node_counter_for_id(counterparty_id);
					(Vec::new(), node_counter)
				})
				.0.push(chan);
		}
		if first_hop_targets.is_empty() {
			return Err("Cannot route when there are no outbound routes away from us");
		}
	}

	let node_counters = node_counter_builder.build();

	let introduction_node_id_cache = calculate_blinded_path_intro_points(
		&payment_params, &node_counters, network_graph, &logger, our_node_id, &first_hop_targets,
	)?;

	let mut last_hop_candidates =
		hash_map_with_capacity(payment_params.payee.unblinded_route_hints().len());
	for route in payment_params.payee.unblinded_route_hints().iter()
		.filter(|route| !route.0.is_empty())
	{
		let hop_iter = route.0.iter().rev();
		let prev_hop_iter = core::iter::once(&maybe_dummy_payee_pk).chain(
			route.0.iter().skip(1).rev().map(|hop| &hop.src_node_id));

		for (hop, prev_hop_id) in hop_iter.zip(prev_hop_iter) {
			let (target, private_target_node_counter) =
				node_counters.private_node_counter_from_pubkey(&prev_hop_id)
					.ok_or_else(|| {
						debug_assert!(false);
						"We should always have private target node counters available"
					})?;
			let (_src_id, private_source_node_counter) =
				node_counters.private_node_counter_from_pubkey(&hop.src_node_id)
					.ok_or_else(|| {
						debug_assert!(false);
						"We should always have private source node counters available"
					})?;

			if let Some((first_channels, _)) = first_hop_targets.get(target) {
				let matches_an_scid = |d: &&ChannelDetails|
					d.outbound_scid_alias == Some(hop.short_channel_id) || d.short_channel_id == Some(hop.short_channel_id);
				if first_channels.iter().any(matches_an_scid) {
					log_trace!(logger, "Ignoring route hint with SCID {} (and any previous) due to it being a direct channel of ours.",
						hop.short_channel_id);
					break;
				}
			}

			let candidate = network_channels
				.get(&hop.short_channel_id)
				.and_then(|channel| channel.as_directed_to(target))
				.map(|(info, _)| CandidateRouteHop::PublicHop(PublicHopCandidate {
					info,
					short_channel_id: hop.short_channel_id,
				}))
				.unwrap_or_else(|| CandidateRouteHop::PrivateHop(PrivateHopCandidate {
					hint: hop, target_node_id: target,
					source_node_counter: *private_source_node_counter,
					target_node_counter: *private_target_node_counter,
				}));

			last_hop_candidates.entry(private_target_node_counter).or_insert_with(Vec::new).push(candidate);
		}
	}

	// The main heap containing all candidate next-hops sorted by their score (max(fee,
	// htlc_minimum)). Ideally this would be a heap which allowed cheap score reduction instead of
	// adding duplicate entries when we find a better path to a given node.
	let mut targets: BinaryHeap<RouteGraphNode> = BinaryHeap::new();

	// Map from node_id to information about the best current path to that node, including feerate
	// information.
	let dist_len = node_counters.max_counter() + 1;
	let mut dist: Vec<Option<PathBuildingHop>> = vec![None; dist_len as usize];

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

	// Routing Fragmentation Mitigation heuristic:
	//
	// Routing fragmentation across many payment paths increases the overall routing
	// fees as you have irreducible routing fees per-link used (`fee_base_msat`).
	// Taking too many smaller paths also increases the chance of payment failure.
	// Thus to avoid this effect, we require from our collected links to provide
	// at least a minimal contribution to the recommended value yet-to-be-fulfilled.
	// This requirement is currently set to be 1/max_path_count of the payment
	// value to ensure we only ever return routes that do not violate this limit.
	let minimal_value_contribution_msat: u64 = if allow_mpp {
		(final_value_msat + (payment_params.max_path_count as u64 - 1)) / payment_params.max_path_count as u64
	} else {
		final_value_msat
	};

	// When we start collecting routes we enforce the max_channel_saturation_power_of_half
	// requirement strictly. After we've collected enough (or if we fail to find new routes) we
	// drop the requirement by setting this to 0.
	let mut channel_saturation_pow_half = payment_params.max_channel_saturation_power_of_half;

	// In order to already account for some of the privacy enhancing random CLTV
	// expiry delta offset we add on top later, we subtract a rough estimate
	// (2*MEDIAN_HOP_CLTV_EXPIRY_DELTA) here.
	let max_total_cltv_expiry_delta: u16 =
		(payment_params.max_total_cltv_expiry_delta - final_cltv_expiry_delta)
		.checked_sub(2*MEDIAN_HOP_CLTV_EXPIRY_DELTA)
		.unwrap_or(payment_params.max_total_cltv_expiry_delta - final_cltv_expiry_delta)
		.try_into()
		.unwrap_or(u16::MAX);

	// Keep track of how much liquidity has been used in selected channels or blinded paths. Used to
	// determine if the channel can be used by additional MPP paths or to inform path finding
	// decisions. It is aware of direction *only* to ensure that the correct htlc_maximum_msat value
	// is used. Hence, liquidity used in one direction will not offset any used in the opposite
	// direction.
	let mut used_liquidities: HashMap<CandidateHopId, u64> =
		hash_map_with_capacity(network_nodes.len());

	// Keeping track of how much value we already collected across other paths. Helps to decide
	// when we want to stop looking for new paths.
	let mut already_collected_value_msat = 0;

	for (_, (channels, _)) in first_hop_targets.iter_mut() {
		sort_first_hop_channels(channels, &used_liquidities, recommended_value_msat,
			our_node_pubkey);
	}

	log_trace!(logger, "Building path from {} to payer {} for value {} msat.",
		LoggedPayeePubkey(payment_params.payee.node_id()), our_node_pubkey, final_value_msat);

	// Remember how many candidates we ignored to allow for some logging afterwards.
	let mut num_ignored_value_contribution: u32 = 0;
	let mut num_ignored_path_length_limit: u32 = 0;
	let mut num_ignored_cltv_delta_limit: u32 = 0;
	let mut num_ignored_previously_failed: u32 = 0;
	let mut num_ignored_total_fee_limit: u32 = 0;
	let mut num_ignored_avoid_overpayment: u32 = 0;
	let mut num_ignored_htlc_minimum_msat_limit: u32 = 0;

	macro_rules! add_entry {
		// Adds entry which goes from $candidate.source() to $candidate.target() over the $candidate hop.
		// $next_hops_fee_msat represents the fees paid for using all the channels *after* this one,
		// since that value has to be transferred over this channel.
		// Returns the contribution amount of $candidate if the channel caused an update to `targets`.
		( $candidate: expr, $next_hops_fee_msat: expr,
			$next_hops_value_contribution: expr, $next_hops_path_htlc_minimum_msat: expr,
			$next_hops_path_penalty_msat: expr, $next_hops_cltv_delta: expr, $next_hops_path_length: expr ) => { {
			// We "return" whether we updated the path at the end, and how much we can route via
			// this channel, via this:
			let mut hop_contribution_amt_msat = None;

			#[cfg(all(not(ldk_bench), any(test, fuzzing)))]
			if let Some(counter) = $candidate.target_node_counter() {
				// Once we are adding paths backwards from a given target, we've selected the best
				// path from that target to the destination and it should no longer change. We thus
				// set the best-path selected flag and check that it doesn't change below.
				if let Some(node) = &mut dist[counter as usize] {
					node.best_path_from_hop_selected = true;
				} else if counter != payee_node_counter {
					panic!("No dist entry for target node counter {}", counter);
				}
			}

			// Channels to self should not be used. This is more of belt-and-suspenders, because in
			// practice these cases should be caught earlier:
			// - for regular channels at channel announcement (TODO)
			// - for first and last hops early in get_route
			let src_node_id = $candidate.source();
			if Some(src_node_id) != $candidate.target() {
				let scid_opt = $candidate.short_channel_id();
				let effective_capacity = $candidate.effective_capacity();
				let htlc_maximum_msat = max_htlc_from_capacity(effective_capacity, channel_saturation_pow_half);

				// It is tricky to subtract $next_hops_fee_msat from available liquidity here.
				// It may be misleading because we might later choose to reduce the value transferred
				// over these channels, and the channel which was insufficient might become sufficient.
				// Worst case: we drop a good channel here because it can't cover the high following
				// fees caused by one expensive channel, but then this channel could have been used
				// if the amount being transferred over this path is lower.
				// We do this for now, but this is a subject for removal.
				if let Some(mut available_value_contribution_msat) = htlc_maximum_msat.checked_sub($next_hops_fee_msat) {
					let cltv_expiry_delta = $candidate.cltv_expiry_delta();
					let htlc_minimum_msat = $candidate.htlc_minimum_msat();
					let used_liquidity_msat = used_liquidities
						.get(&$candidate.id())
						.map_or(0, |used_liquidity_msat| {
							available_value_contribution_msat = available_value_contribution_msat
								.saturating_sub(*used_liquidity_msat);
							*used_liquidity_msat
						});

					// Do not consider candidate hops that would exceed the maximum path length.
					let path_length_to_node = $next_hops_path_length
						+ if $candidate.blinded_hint_idx().is_some() { 0 } else { 1 };
					let exceeds_max_path_length = path_length_to_node > max_path_length;

					// Do not consider candidates that exceed the maximum total cltv expiry limit.
					let hop_total_cltv_delta = ($next_hops_cltv_delta as u32)
						.saturating_add(cltv_expiry_delta);
					let exceeds_cltv_delta_limit = hop_total_cltv_delta > max_total_cltv_expiry_delta as u32;

					let value_contribution_msat = cmp::min(available_value_contribution_msat, $next_hops_value_contribution);
					// Verify the liquidity offered by this channel complies to the minimal contribution.
					let contributes_sufficient_value = value_contribution_msat >= minimal_value_contribution_msat;
					// Includes paying fees for the use of the following channels.
					let amount_to_transfer_over_msat: u64 = match value_contribution_msat.checked_add($next_hops_fee_msat) {
						Some(result) => result,
						// Can't overflow due to how the values were computed right above.
						None => unreachable!(),
					};
					#[allow(unused_comparisons)] // $next_hops_path_htlc_minimum_msat is 0 in some calls so rustc complains
					let over_path_minimum_msat = amount_to_transfer_over_msat >= htlc_minimum_msat &&
						amount_to_transfer_over_msat >= $next_hops_path_htlc_minimum_msat;

					#[allow(unused_comparisons)] // $next_hops_path_htlc_minimum_msat is 0 in some calls so rustc complains
					let may_overpay_to_meet_path_minimum_msat =
						(amount_to_transfer_over_msat < htlc_minimum_msat &&
						  recommended_value_msat >= htlc_minimum_msat) ||
						(amount_to_transfer_over_msat < $next_hops_path_htlc_minimum_msat &&
						 recommended_value_msat >= $next_hops_path_htlc_minimum_msat);

					let payment_failed_on_this_channel = match scid_opt {
						Some(scid) => payment_params.previously_failed_channels.contains(&scid),
						None => match $candidate.blinded_hint_idx() {
							Some(idx) => {
								payment_params.previously_failed_blinded_path_idxs.contains(&(idx as u64))
							},
							None => false,
						},
					};

					let (should_log_candidate, first_hop_details) = match $candidate {
						CandidateRouteHop::FirstHop(hop) => (true, Some(hop.details)),
						CandidateRouteHop::PrivateHop(_) => (true, None),
						CandidateRouteHop::Blinded(_) => (true, None),
						CandidateRouteHop::OneHopBlinded(_) => (true, None),
						_ => (false, None),
					};

					// If HTLC minimum is larger than the amount we're going to transfer, we shouldn't
					// bother considering this channel. If retrying with recommended_value_msat may
					// allow us to hit the HTLC minimum limit, set htlc_minimum_limit so that we go
					// around again with a higher amount.
					if !contributes_sufficient_value {
						if should_log_candidate {
							log_trace!(logger, "Ignoring {} due to insufficient value contribution (channel max {:?}).",
								LoggedCandidateHop(&$candidate),
								effective_capacity);
						}
						num_ignored_value_contribution += 1;
					} else if exceeds_max_path_length {
						if should_log_candidate {
							log_trace!(logger, "Ignoring {} due to exceeding maximum path length limit.", LoggedCandidateHop(&$candidate));
						}
						num_ignored_path_length_limit += 1;
					} else if exceeds_cltv_delta_limit {
						if should_log_candidate {
							log_trace!(logger, "Ignoring {} due to exceeding CLTV delta limit.", LoggedCandidateHop(&$candidate));

							if let Some(_) = first_hop_details {
								log_trace!(logger,
									"First hop candidate cltv_expiry_delta: {}. Limit: {}",
									hop_total_cltv_delta,
									max_total_cltv_expiry_delta,
								);
							}
						}
						num_ignored_cltv_delta_limit += 1;
					} else if payment_failed_on_this_channel {
						if should_log_candidate {
							log_trace!(logger, "Ignoring {} due to a failed previous payment attempt.", LoggedCandidateHop(&$candidate));
						}
						num_ignored_previously_failed += 1;
					} else if may_overpay_to_meet_path_minimum_msat {
						if should_log_candidate {
							log_trace!(logger,
								"Ignoring {} to avoid overpaying to meet htlc_minimum_msat limit ({}).",
								LoggedCandidateHop(&$candidate), $candidate.htlc_minimum_msat());
						}
						num_ignored_avoid_overpayment += 1;
						hit_minimum_limit = true;
					} else if over_path_minimum_msat {
						// Note that low contribution here (limited by available_liquidity_msat)
						// might violate htlc_minimum_msat on the hops which are next along the
						// payment path (upstream to the payee). To avoid that, we recompute
						// path fees knowing the final path contribution after constructing it.
						let curr_min = cmp::max(
							$next_hops_path_htlc_minimum_msat, htlc_minimum_msat
						);
						let src_node_counter = $candidate.src_node_counter();
						let mut candidate_fees = $candidate.fees();
						if src_node_counter == payer_node_counter {
							// We do not charge ourselves a fee to use our own channels.
							candidate_fees = RoutingFees {
								proportional_millionths: 0,
								base_msat: 0,
							};
						}
						let path_htlc_minimum_msat = compute_fees_saturating(curr_min, candidate_fees)
							.saturating_add(curr_min);

						let dist_entry = &mut dist[src_node_counter as usize];
						let old_entry = if let Some(hop) = dist_entry {
							hop
						} else {
							// If there was previously no known way to access the source node
							// (recall it goes payee-to-payer) of short_channel_id, first add a
							// semi-dummy record just to compute the fees to reach the source node.
							// This will affect our decision on selecting short_channel_id
							// as a way to reach the $candidate.target() node.
							*dist_entry = Some(PathBuildingHop {
								candidate: $candidate.clone(),
								fee_msat: 0,
								next_hops_fee_msat: u64::max_value(),
								hop_use_fee_msat: u64::max_value(),
								total_fee_msat: u64::max_value(),
								path_htlc_minimum_msat,
								path_penalty_msat: u64::max_value(),
								was_processed: false,
								is_first_hop_target: false,
								is_last_hop_target: false,
								#[cfg(all(not(ldk_bench), any(test, fuzzing)))]
								best_path_from_hop_selected: false,
								value_contribution_msat,
							});
							dist_entry.as_mut().unwrap()
						};

						#[allow(unused_mut)] // We only use the mut in cfg(test)
						let mut should_process = !old_entry.was_processed;
						#[cfg(all(not(ldk_bench), any(test, fuzzing)))]
						{
							// In test/fuzzing builds, we do extra checks to make sure the skipping
							// of already-seen nodes only happens in cases we expect (see below).
							if !should_process { should_process = true; }
						}

						if should_process {
							let mut hop_use_fee_msat = 0;
							let mut total_fee_msat: u64 = $next_hops_fee_msat;

							// Ignore hop_use_fee_msat for channel-from-us as we assume all channels-from-us
							// will have the same effective-fee
							if src_node_id != our_node_id {
								// Note that `u64::max_value` means we'll always fail the
								// `old_entry.total_fee_msat > total_fee_msat` check below
								hop_use_fee_msat = compute_fees_saturating(amount_to_transfer_over_msat, candidate_fees);
								total_fee_msat = total_fee_msat.saturating_add(hop_use_fee_msat);
							}

							// Ignore hops if augmenting the current path to them would put us over `max_total_routing_fee_msat`
							if total_fee_msat > max_total_routing_fee_msat {
								if should_log_candidate {
									log_trace!(logger, "Ignoring {} with fee {total_fee_msat} due to exceeding max total routing fee limit {max_total_routing_fee_msat}.", LoggedCandidateHop(&$candidate));

									if let Some(_) = first_hop_details {
										log_trace!(logger,
											"First hop candidate routing fee: {}. Limit: {}",
											total_fee_msat,
											max_total_routing_fee_msat,
										);
									}
								}
								num_ignored_total_fee_limit += 1;
							} else {
								let channel_usage = ChannelUsage {
									amount_msat: amount_to_transfer_over_msat,
									inflight_htlc_msat: used_liquidity_msat,
									effective_capacity,
								};
								let channel_penalty_msat =
									scorer.channel_penalty_msat($candidate,
										channel_usage,
										score_params);
								let path_penalty_msat = $next_hops_path_penalty_msat
									.saturating_add(channel_penalty_msat);

								// Update the way of reaching $candidate.source()
								// with the given short_channel_id (from $candidate.target()),
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
								let old_fee_cost = cmp::max(old_entry.total_fee_msat, old_entry.path_htlc_minimum_msat)
									.saturating_add(old_entry.path_penalty_msat);
								let new_fee_cost = cmp::max(total_fee_msat, path_htlc_minimum_msat)
									.saturating_add(path_penalty_msat);
								// The actual score we use for our heap is the cost divided by how
								// much we are thinking of sending over this channel. This avoids
								// prioritizing channels that have a very low fee because we aren't
								// sending very much over them.
								// In order to avoid integer division precision loss, we simply
								// shift the costs up to the top half of a u128 and divide by the
								// value (which is, at max, just under a u64).
								let old_cost = if old_fee_cost != u64::MAX && old_entry.value_contribution_msat != 0 {
									((old_fee_cost as u128) << 64) / old_entry.value_contribution_msat as u128
								} else {
									u128::MAX
								};
								let new_cost = if new_fee_cost != u64::MAX {
									// value_contribution_msat is always >= 1, checked above via
									// `contributes_sufficient_value`.
									((new_fee_cost as u128) << 64) / value_contribution_msat as u128
								} else {
									u128::MAX
								};

								if !old_entry.was_processed && new_cost < old_cost {
									#[cfg(all(not(ldk_bench), any(test, fuzzing)))]
									{
										assert!(!old_entry.best_path_from_hop_selected);
										assert!(hop_total_cltv_delta <= u16::MAX as u32);
									}

									let new_graph_node = RouteGraphNode {
										node_counter: src_node_counter,
										score: new_cost,
										total_cltv_delta: hop_total_cltv_delta as u16,
										value_contribution_msat,
										path_length_to_node,
									};
									targets.push(new_graph_node);
									old_entry.next_hops_fee_msat = $next_hops_fee_msat;
									old_entry.hop_use_fee_msat = hop_use_fee_msat;
									old_entry.total_fee_msat = total_fee_msat;
									old_entry.candidate = $candidate.clone();
									old_entry.fee_msat = 0; // This value will be later filled with hop_use_fee_msat of the following channel
									old_entry.path_htlc_minimum_msat = path_htlc_minimum_msat;
									old_entry.path_penalty_msat = path_penalty_msat;
									old_entry.value_contribution_msat = value_contribution_msat;
									hop_contribution_amt_msat = Some(value_contribution_msat);
								} else if old_entry.was_processed && new_cost < old_cost {
									#[cfg(all(not(ldk_bench), any(test, fuzzing)))]
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
					} else {
						if should_log_candidate {
							log_trace!(logger,
								"Ignoring {} due to its htlc_minimum_msat limit.",
								LoggedCandidateHop(&$candidate));

							if let Some(details) = first_hop_details {
								log_trace!(logger,
									"First hop candidate next_outbound_htlc_minimum_msat: {}",
									details.next_outbound_htlc_minimum_msat,
								);
							}
						}
						num_ignored_htlc_minimum_msat_limit += 1;
					}
				}
			}
			hop_contribution_amt_msat
		} }
	}

	let default_node_features = default_node_features();

	// Find ways (channels with destination) to reach a given node and store them
	// in the corresponding data structures (routing graph etc).
	// $fee_to_target_msat represents how much it costs to reach to this node from the payee,
	// meaning how much will be paid in fees after this node (to the best of our knowledge).
	// This data can later be helpful to optimize routing (pay lower fees).
	#[rustfmt::skip]
	macro_rules! add_entries_to_cheapest_to_target_node {
		( $node_counter: expr, $node_id: expr, $next_hops_value_contribution: expr,
		  $next_hops_cltv_delta: expr, $next_hops_path_length: expr ) => {
			let fee_to_target_msat;
			let next_hops_path_htlc_minimum_msat;
			let next_hops_path_penalty_msat;
			let (is_first_hop_target, is_last_hop_target);
			let skip_node = if let Some(elem) = &mut dist[$node_counter as usize] {
				let was_processed = elem.was_processed;
				elem.was_processed = true;
				fee_to_target_msat = elem.total_fee_msat;
				next_hops_path_htlc_minimum_msat = elem.path_htlc_minimum_msat;
				next_hops_path_penalty_msat = elem.path_penalty_msat;
				is_first_hop_target = elem.is_first_hop_target;
				is_last_hop_target = elem.is_last_hop_target;
				was_processed
			} else {
				// Entries are added to dist in add_entry!() when there is a channel from a node.
				// Because there are no channels from payee, it will not have a dist entry at this point.
				// If we're processing any other node, it is always be the result of a channel from it.
				debug_assert_eq!($node_id, maybe_dummy_payee_node_id);

				fee_to_target_msat = 0;
				next_hops_path_htlc_minimum_msat = 0;
				next_hops_path_penalty_msat = 0;
				is_first_hop_target = false;
				is_last_hop_target = false;
				false
			};

			if !skip_node {
				if is_last_hop_target {
					if let Some(candidates) = last_hop_candidates.get(&$node_counter) {
						for candidate in candidates {
							add_entry!(candidate, fee_to_target_msat,
								$next_hops_value_contribution,
								next_hops_path_htlc_minimum_msat, next_hops_path_penalty_msat,
								$next_hops_cltv_delta, $next_hops_path_length);
						}
					}
				}
				if is_first_hop_target {
					if let Some((first_channels, peer_node_counter)) = first_hop_targets.get(&$node_id) {
						for details in first_channels {
							debug_assert_eq!(*peer_node_counter, $node_counter);
							let candidate = CandidateRouteHop::FirstHop(FirstHopCandidate {
								details, payer_node_id: &our_node_id, payer_node_counter,
								target_node_counter: $node_counter,
							});
							add_entry!(&candidate, fee_to_target_msat,
								$next_hops_value_contribution,
								next_hops_path_htlc_minimum_msat, next_hops_path_penalty_msat,
								$next_hops_cltv_delta, $next_hops_path_length);
						}
					}
				}

				if let Some(node) = network_nodes.get(&$node_id) {
					let features = if let Some(node_info) = node.announcement_info.as_ref() {
						&node_info.features()
					} else {
						&default_node_features
					};

					if !features.requires_unknown_bits() {
						for chan_id in node.channels.iter() {
							let chan = network_channels.get(chan_id).unwrap();
							if !chan.features.requires_unknown_bits() {
								if let Some((directed_channel, source)) = chan.as_directed_to(&$node_id) {
									if first_hops.is_none() || *source != our_node_id {
										if directed_channel.direction().enabled {
											let candidate = CandidateRouteHop::PublicHop(PublicHopCandidate {
												info: directed_channel,
												short_channel_id: *chan_id,
											});
											add_entry!(&candidate,
												fee_to_target_msat,
												$next_hops_value_contribution,
												next_hops_path_htlc_minimum_msat,
												next_hops_path_penalty_msat,
												$next_hops_cltv_delta, $next_hops_path_length);
										}
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
		// For every new path, start from scratch, except for used_liquidities, which
		// helps to avoid reusing previously selected paths in future iterations.
		targets.clear();
		for e in dist.iter_mut() {
			*e = None;
		}

		// Step (2).
		// Add entries for first-hop and last-hop channel hints to `dist` and add the payee node as
		// the best entry via `add_entry`.
		// For first- and last-hop hints we need only add dummy entries in `dist` with the relevant
		// flags set. As we walk the graph in `add_entries_to_cheapest_to_target_node` we'll check
		// those flags and add the channels described by the hints.
		// We then either add the payee using `add_entries_to_cheapest_to_target_node` or add the
		// blinded paths to the payee using `add_entry`, filling `targets` and setting us up for
		// our graph walk.
		for (_, (chans, peer_node_counter)) in first_hop_targets.iter() {
			// In order to avoid looking up whether each node is a first-hop target, we store a
			// dummy entry in dist for each first-hop target, allowing us to do this lookup for
			// free since we're already looking at the `was_processed` flag.
			//
			// Note that all the fields (except `is_{first,last}_hop_target`) will be overwritten
			// whenever we find a path to the target, so are left as dummies here.
			dist[*peer_node_counter as usize] = Some(PathBuildingHop {
				candidate: CandidateRouteHop::FirstHop(FirstHopCandidate {
					details: &chans[0],
					payer_node_id: &our_node_id,
					target_node_counter: u32::max_value(),
					payer_node_counter: u32::max_value(),
				}),
				fee_msat: 0,
				next_hops_fee_msat: u64::max_value(),
				hop_use_fee_msat: u64::max_value(),
				total_fee_msat: u64::max_value(),
				path_htlc_minimum_msat: u64::max_value(),
				path_penalty_msat: u64::max_value(),
				was_processed: false,
				is_first_hop_target: true,
				is_last_hop_target: false,
				value_contribution_msat: 0,
				#[cfg(all(not(ldk_bench), any(test, fuzzing)))]
				best_path_from_hop_selected: false,
			});
		}
		for (target_node_counter, candidates) in last_hop_candidates.iter() {
			// In order to avoid looking up whether each node is a last-hop target, we store a
			// dummy entry in dist for each last-hop target, allowing us to do this lookup for
			// free since we're already looking at the `was_processed` flag.
			//
			// Note that all the fields (except `is_{first,last}_hop_target`) will be overwritten
			// whenever we find a path to the target, so are left as dummies here.
			debug_assert!(!candidates.is_empty());
			if candidates.is_empty() { continue }
			let entry = &mut dist[**target_node_counter as usize];
			if let Some(hop) = entry {
				hop.is_last_hop_target = true;
			} else {
				*entry = Some(PathBuildingHop {
					candidate: candidates[0].clone(),
					fee_msat: 0,
					next_hops_fee_msat: u64::max_value(),
					hop_use_fee_msat: u64::max_value(),
					total_fee_msat: u64::max_value(),
					path_htlc_minimum_msat: u64::max_value(),
					path_penalty_msat: u64::max_value(),
					was_processed: false,
					is_first_hop_target: false,
					is_last_hop_target: true,
					value_contribution_msat: 0,
					#[cfg(all(not(ldk_bench), any(test, fuzzing)))]
					best_path_from_hop_selected: false,
				});
			}
		}
		hit_minimum_limit = false;

		if let Some(payee) = payee_node_id_opt {
			if let Some(entry) = &mut dist[payee_node_counter as usize] {
				// If we built a dummy entry above we need to reset the values to represent 0 fee
				// from the target "to the target".
				entry.next_hops_fee_msat = 0;
				entry.hop_use_fee_msat = 0;
				entry.total_fee_msat = 0;
				entry.path_htlc_minimum_msat = 0;
				entry.path_penalty_msat = 0;
				entry.value_contribution_msat = path_value_msat;
			}
			add_entries_to_cheapest_to_target_node!(
				payee_node_counter, payee, path_value_msat, 0, 0
			);
		}

		debug_assert_eq!(
			payment_params.payee.blinded_route_hints().len(),
			introduction_node_id_cache.len(),
			"introduction_node_id_cache was built by iterating the blinded_route_hints, so they should be the same len"
		);
		let mut blind_intros_added = hash_map_with_capacity(payment_params.payee.blinded_route_hints().len());
		for (hint_idx, hint) in payment_params.payee.blinded_route_hints().iter().enumerate() {
			// Only add the hops in this route to our candidate set if either
			// we have a direct channel to the first hop or the first hop is
			// in the regular network graph.
			let source_node_opt = introduction_node_id_cache[hint_idx];
			let (source_node_id, source_node_counter) = if let Some(v) = source_node_opt { v } else { continue };
			if our_node_id == *source_node_id { continue }
			let candidate = if hint.blinded_hops().len() == 1 {
				CandidateRouteHop::OneHopBlinded(
					OneHopBlindedPathCandidate { source_node_counter, source_node_id, hint, hint_idx }
				)
			} else {
				CandidateRouteHop::Blinded(BlindedPathCandidate { source_node_counter, source_node_id, hint, hint_idx })
			};
			if let Some(hop_used_msat) = add_entry!(&candidate,
				0, path_value_msat, 0, 0_u64, 0, 0)
			{
				blind_intros_added.insert(source_node_id, (hop_used_msat, candidate));
			} else { continue }
		}
		// If we added a blinded path from an introduction node to the destination, where the
		// introduction node is one of our direct peers, we need to scan our `first_channels`
		// to detect this. However, doing so immediately after calling `add_entry`, above, could
		// result in incorrect behavior if we, in a later loop iteration, update the fee from the
		// same introduction point to the destination (due to a different blinded path with the
		// same introduction point having a lower score).
		// Thus, we track the nodes that we added paths from in `blind_intros_added` and scan for
		// introduction points we have a channel with after processing all blinded paths.
		for (source_node_id, (path_contribution_msat, candidate)) in blind_intros_added {
			if let Some((first_channels, peer_node_counter)) = first_hop_targets.get_mut(source_node_id) {
				sort_first_hop_channels(
					first_channels, &used_liquidities, recommended_value_msat, our_node_pubkey
				);
				for details in first_channels {
					let first_hop_candidate = CandidateRouteHop::FirstHop(FirstHopCandidate {
						details, payer_node_id: &our_node_id, payer_node_counter,
						target_node_counter: *peer_node_counter,
					});
					let blinded_path_fee = match compute_fees(path_contribution_msat, candidate.fees()) {
						Some(fee) => fee,
						None => continue
					};
					let path_min = candidate.htlc_minimum_msat().saturating_add(
						compute_fees_saturating(candidate.htlc_minimum_msat(), candidate.fees()));
					add_entry!(&first_hop_candidate, blinded_path_fee, path_contribution_msat, path_min,
						0_u64, candidate.cltv_expiry_delta(), 0);
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
		'path_construction: while let Some(RouteGraphNode { node_counter, total_cltv_delta, mut value_contribution_msat, path_length_to_node, .. }) = targets.pop() {

			// Since we're going payee-to-payer, hitting our node as a target means we should stop
			// traversing the graph and arrange the path out of what we found.
			if node_counter == payer_node_counter {
				let mut new_entry = dist[payer_node_counter as usize].take().unwrap();
				let mut ordered_hops: Vec<(PathBuildingHop, NodeFeatures)> = vec!((new_entry.clone(), default_node_features.clone()));

				'path_walk: loop {
					let mut features_set = false;
					let candidate = &ordered_hops.last().unwrap().0.candidate;
					let target = candidate.target().unwrap_or(maybe_dummy_payee_node_id);
					let target_node_counter = candidate.target_node_counter();
					if let Some((first_channels, _)) = first_hop_targets.get(&target) {
						for details in first_channels {
							if let CandidateRouteHop::FirstHop(FirstHopCandidate { details: last_hop_details, .. })
								= candidate
							{
								if details.get_outbound_payment_scid() == last_hop_details.get_outbound_payment_scid() {
									ordered_hops.last_mut().unwrap().1 = details.counterparty.features.to_context();
									features_set = true;
									break;
								}
							}
						}
					}
					if !features_set {
						if let Some(node) = network_nodes.get(&target) {
							if let Some(node_info) = node.announcement_info.as_ref() {
								ordered_hops.last_mut().unwrap().1 = node_info.features().clone();
							} else {
								ordered_hops.last_mut().unwrap().1 = default_node_features.clone();
							}
						} else {
							// We can fill in features for everything except hops which were
							// provided via the invoice we're paying. We could guess based on the
							// recipient's features but for now we simply avoid guessing at all.
						}
					}

					// Means we successfully traversed from the payer to the payee, now
					// save this path for the payment route. Also, update the liquidity
					// remaining on the used hops, so that we take them into account
					// while looking for more paths.
					if target_node_counter.is_none() {
						break 'path_walk;
					}
					if target_node_counter == Some(payee_node_counter) { break 'path_walk; }

					new_entry = match dist[target_node_counter.unwrap() as usize].take() {
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
				debug_assert_eq!(payment_path.get_value_msat(), value_contribution_msat);
				let (lowest_value_contrib_hop, max_path_contribution_msat) =
					payment_path.max_final_value_msat(&used_liquidities, channel_saturation_pow_half);
				let desired_value_contribution = cmp::min(max_path_contribution_msat, final_value_msat);
				value_contribution_msat = payment_path.update_value_and_recompute_fees(desired_value_contribution);

				// Since a path allows to transfer as much value as
				// the smallest channel it has ("bottleneck"), we should recompute
				// the fees so sender HTLC don't overpay fees when traversing
				// larger channels than the bottleneck. This may happen because
				// when we were selecting those channels we were not aware how much value
				// this path will transfer, and the relative fee for them
				// might have been computed considering a larger value.
				// Remember that we used these channels so that we don't rely
				// on the same liquidity in future paths.
				for (hop, _) in payment_path.hops.iter() {
					let spent_on_hop_msat = value_contribution_msat + hop.next_hops_fee_msat;
					let used_liquidity_msat = used_liquidities
						.entry(hop.candidate.id())
						.and_modify(|used_liquidity_msat| *used_liquidity_msat += spent_on_hop_msat)
						.or_insert(spent_on_hop_msat);
					let hop_capacity = hop.candidate.effective_capacity();
					let hop_max_msat = max_htlc_from_capacity(hop_capacity, channel_saturation_pow_half);
					debug_assert!(*used_liquidity_msat <= hop_max_msat);
				}
				if max_path_contribution_msat > value_contribution_msat {
					// If we weren't capped by hitting a liquidity limit on a channel in the path,
					// we'll probably end up picking the same path again on the next iteration.
					// Decrease the available liquidity of a hop in the middle of the path.
					let victim_candidate = &payment_path.hops[(payment_path.hops.len()) / 2].0.candidate;
					let exhausted = u64::max_value();
					log_trace!(logger,
						"Disabling route candidate {} for future path building iterations to avoid duplicates.",
						LoggedCandidateHop(victim_candidate));
					if let Some(scid) = victim_candidate.short_channel_id() {
						*used_liquidities.entry(CandidateHopId::Clear((scid, false))).or_default() = exhausted;
						*used_liquidities.entry(CandidateHopId::Clear((scid, true))).or_default() = exhausted;
					}
				} else {
					log_trace!(logger, "Path was limited to {}msat by hop {}", max_path_contribution_msat, lowest_value_contrib_hop);
				}

				// Track the total amount all our collected paths allow to send so that we know
				// when to stop looking for more paths
				already_collected_value_msat += value_contribution_msat;

				payment_paths.push(payment_path);
				found_new_path = true;
				break 'path_construction;
			}

			// If we found a path back to the payee, we shouldn't try to process it again. This is
			// the equivalent of the `elem.was_processed` check in
			// add_entries_to_cheapest_to_target_node!() (see comment there for more info).
			if node_counter == payee_node_counter { continue 'path_construction; }

			let node_id = if let Some(entry) = &dist[node_counter as usize] {
				entry.candidate.source()
			} else {
				debug_assert!(false, "Best nodes in the heap should have entries in dist");
				continue 'path_construction;
			};

			// Otherwise, since the current target node is not us,
			// keep "unrolling" the payment graph from payee to payer by
			// finding a way to reach the current target from the payer side.
			add_entries_to_cheapest_to_target_node!(
				node_counter, node_id,
				value_contribution_msat,
				total_cltv_delta, path_length_to_node
			);
		}

		if !allow_mpp {
			if !found_new_path && channel_saturation_pow_half != 0 {
				channel_saturation_pow_half = 0;
				continue 'paths_collection;
			}
			// If we don't support MPP, no use trying to gather more value ever.
			break 'paths_collection;
		}

		// Step (4).
		// Stop either when the recommended value is reached or if no new path was found in this
		// iteration.
		// In the latter case, making another path finding attempt won't help,
		// because we deterministically terminated the search due to low liquidity.
		if !found_new_path && channel_saturation_pow_half != 0 {
			channel_saturation_pow_half = 0;
		} else if !found_new_path && hit_minimum_limit && already_collected_value_msat < final_value_msat && path_value_msat != recommended_value_msat {
			log_trace!(logger, "Failed to collect enough value, but running again to collect extra paths with a potentially higher limit.");
			path_value_msat = recommended_value_msat;
		} else if already_collected_value_msat >= recommended_value_msat || !found_new_path {
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
			log_trace!(logger, "Collected our payment amount on the first pass, but running again to collect extra paths with a potentially higher value to meet htlc_minimum_msat limit.");
			path_value_msat = recommended_value_msat;
		}
	}

	let num_ignored_total = num_ignored_value_contribution + num_ignored_path_length_limit +
		num_ignored_cltv_delta_limit + num_ignored_previously_failed +
		num_ignored_avoid_overpayment + num_ignored_htlc_minimum_msat_limit +
		num_ignored_total_fee_limit;
	if num_ignored_total > 0 {
		log_trace!(logger,
			"Ignored {} candidate hops due to insufficient value contribution, {} due to path length limit, {} due to CLTV delta limit, {} due to previous payment failure, {} due to htlc_minimum_msat limit, {} to avoid overpaying, {} due to maximum total fee limit. Total: {} ignored candidates.",
			num_ignored_value_contribution, num_ignored_path_length_limit,
			num_ignored_cltv_delta_limit, num_ignored_previously_failed,
			num_ignored_htlc_minimum_msat_limit, num_ignored_avoid_overpayment,
			num_ignored_total_fee_limit, num_ignored_total);
	}

	// Step (5).
	if payment_paths.len() == 0 {
		return Err("Failed to find a path to the given destination");
	}

	if already_collected_value_msat < final_value_msat {
		return Err("Failed to find a sufficient route to the given destination");
	}

	// Step (6).
	let mut selected_route = payment_paths;

	debug_assert_eq!(selected_route.iter().map(|p| p.get_value_msat()).sum::<u64>(), already_collected_value_msat);
	let mut overpaid_value_msat = already_collected_value_msat - final_value_msat;

	// First, sort by the cost-per-value of the path, dropping the paths that cost the most for
	// the value they contribute towards the payment amount.
	// We sort in descending order as we will remove from the front in `retain`, next.
	selected_route.sort_unstable_by(|a, b| b.get_cost_per_msat().cmp(&a.get_cost_per_msat()));

	// We should make sure that at least 1 path left.
	let mut paths_left = selected_route.len();
	selected_route.retain(|path| {
		if paths_left == 1 {
			return true
		}
		let path_value_msat = path.get_value_msat();
		if path_value_msat <= overpaid_value_msat {
			overpaid_value_msat -= path_value_msat;
			paths_left -= 1;
			return false;
		}
		true
	});
	debug_assert!(selected_route.len() > 0);

	if overpaid_value_msat != 0 {
		// Step (7).
		// Now, subtract the remaining overpaid value from the most-expensive path.
		// TODO: this could also be optimized by also sorting by feerate_per_sat_routed,
		// so that the sender pays less fees overall. And also htlc_minimum_msat.
		selected_route.sort_unstable_by(|a, b| {
			let a_f = a.hops.iter().map(|hop| hop.0.candidate.fees().proportional_millionths as u64).sum::<u64>();
			let b_f = b.hops.iter().map(|hop| hop.0.candidate.fees().proportional_millionths as u64).sum::<u64>();
			a_f.cmp(&b_f).then_with(|| b.get_cost_msat().cmp(&a.get_cost_msat()))
		});
		let expensive_payment_path = selected_route.first_mut().unwrap();

		// We already dropped all the paths with value below `overpaid_value_msat` above, thus this
		// can't go negative.
		let expensive_path_new_value_msat = expensive_payment_path.get_value_msat() - overpaid_value_msat;
		expensive_payment_path.update_value_and_recompute_fees(expensive_path_new_value_msat);
	}

	// Step (8).
	// Sort by the path itself and combine redundant paths.
	// Note that we sort by SCIDs alone as its simpler but when combining we have to ensure we
	// compare both SCIDs and NodeIds as individual nodes may use random aliases causing collisions
	// across nodes.
	selected_route.sort_unstable_by_key(|path| {
		let mut key = [CandidateHopId::Clear((42, true)) ; MAX_PATH_LENGTH_ESTIMATE as usize];
		debug_assert!(path.hops.len() <= key.len());
		for (scid, key) in path.hops.iter() .map(|h| h.0.candidate.id()).zip(key.iter_mut()) {
			*key = scid;
		}
		key
	});
	for idx in 0..(selected_route.len() - 1) {
		if idx + 1 >= selected_route.len() { break; }
		if iter_equal(selected_route[idx    ].hops.iter().map(|h| (h.0.candidate.id(), h.0.candidate.target())),
		              selected_route[idx + 1].hops.iter().map(|h| (h.0.candidate.id(), h.0.candidate.target()))) {
			let new_value = selected_route[idx].get_value_msat() + selected_route[idx + 1].get_value_msat();
			selected_route[idx].update_value_and_recompute_fees(new_value);
			selected_route.remove(idx + 1);
		}
	}

	let mut paths = Vec::new();
	for payment_path in selected_route {
		let mut hops = Vec::with_capacity(payment_path.hops.len());
		for (hop, node_features) in payment_path.hops.iter()
			.filter(|(h, _)| h.candidate.short_channel_id().is_some())
		{
			let target = hop.candidate.target().expect("target is defined when short_channel_id is defined");
			let maybe_announced_channel = if let CandidateRouteHop::PublicHop(_) = hop.candidate {
				// If we sourced the hop from the graph we're sure the target node is announced.
				true
			} else if let CandidateRouteHop::FirstHop(first_hop) = &hop.candidate {
				// If this is a first hop we also know if it's announced.
				first_hop.details.is_announced
			} else {
				// If we sourced it any other way, we double-check the network graph to see if
				// there are announced channels between the endpoints. If so, the hop might be
				// referring to any of the announced channels, as its `short_channel_id` might be
				// an alias, in which case we don't take any chances here.
				network_graph.node(&target).map_or(false, |hop_node|
					hop_node.channels.iter().any(|scid| network_graph.channel(*scid)
							.map_or(false, |c| c.as_directed_from(&hop.candidate.source()).is_some()))
				)
			};

			hops.push(RouteHop {
				pubkey: PublicKey::from_slice(target.as_slice()).map_err(|_| "A PublicKey in NetworkGraph is invalid!")?,
				node_features: node_features.clone(),
				short_channel_id: hop.candidate.short_channel_id().unwrap(),
				channel_features: hop.candidate.features(),
				fee_msat: hop.fee_msat,
				cltv_expiry_delta: hop.candidate.cltv_expiry_delta(),
				maybe_announced_channel,
			});
		}
		let mut final_cltv_delta = final_cltv_expiry_delta;
		let blinded_tail = payment_path.hops.last().and_then(|(h, _)| {
			if let Some(blinded_path) = h.candidate.blinded_path() {
				final_cltv_delta = h.candidate.cltv_expiry_delta();
				Some(BlindedTail {
					// TODO: fill correctly
					trampoline_hops: vec![],
					hops: blinded_path.blinded_hops().to_vec(),
					blinding_point: blinded_path.blinding_point(),
					excess_final_cltv_expiry_delta: 0,
					final_value_msat: h.fee_msat,
				})
			} else { None }
		});
		// Propagate the cltv_expiry_delta one hop backwards since the delta from the current hop is
		// applicable for the previous hop.
		hops.iter_mut().rev().fold(final_cltv_delta, |prev_cltv_expiry_delta, hop| {
			core::mem::replace(&mut hop.cltv_expiry_delta, prev_cltv_expiry_delta)
		});

		paths.push(Path { hops, blinded_tail });
	}
	// Make sure we would never create a route with more paths than we allow.
	debug_assert!(paths.len() <= payment_params.max_path_count.into());

	if let Some(node_features) = payment_params.payee.node_features() {
		for path in paths.iter_mut() {
			path.hops.last_mut().unwrap().node_features = node_features.clone();
		}
	}

	let route = Route { paths, route_params: Some(route_params.clone()) };

	// Make sure we would never create a route whose total fees exceed max_total_routing_fee_msat.
	if let Some(max_total_routing_fee_msat) = route_params.max_total_routing_fee_msat {
		if route.get_total_fees() > max_total_routing_fee_msat {
			return Err("Failed to find route that adheres to the maximum total fee limit");
		}
	}

	log_info!(logger, "Got route: {}", log_route!(route));
	Ok(route)
}

// When an adversarial intermediary node observes a payment, it may be able to infer its
// destination, if the remaining CLTV expiry delta exactly matches a feasible path in the network
// graph. In order to improve privacy, this method obfuscates the CLTV expiry deltas along the
// payment path by adding a randomized 'shadow route' offset to the final hop.
#[rustfmt::skip]
fn add_random_cltv_offset(route: &mut Route, payment_params: &PaymentParameters,
	network_graph: &ReadOnlyNetworkGraph, random_seed_bytes: &[u8; 32]
) {
	let network_channels = network_graph.channels();
	let network_nodes = network_graph.nodes();

	for path in route.paths.iter_mut() {
		let mut shadow_ctlv_expiry_delta_offset: u32 = 0;

		// Remember the last three nodes of the random walk and avoid looping back on them.
		// Init with the last three nodes from the actual path, if possible.
		let mut nodes_to_avoid: [NodeId; 3] = [NodeId::from_pubkey(&path.hops.last().unwrap().pubkey),
			NodeId::from_pubkey(&path.hops.get(path.hops.len().saturating_sub(2)).unwrap().pubkey),
			NodeId::from_pubkey(&path.hops.get(path.hops.len().saturating_sub(3)).unwrap().pubkey)];

		// Choose the last publicly known node as the starting point for the random walk.
		let mut cur_hop: Option<NodeId> = None;
		let mut path_nonce = [0u8; 12];
		if let Some(starting_hop) = path.hops.iter().rev()
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
									random_hop_offset = dir_info.direction().cltv_expiry_delta.into();
									cur_hop = Some(*next_id);
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
		let path_total_cltv_expiry_delta: u32 = path.hops.iter().map(|h| h.cltv_expiry_delta).sum();
		let mut max_path_offset = payment_params.max_total_cltv_expiry_delta - path_total_cltv_expiry_delta;
		max_path_offset = cmp::max(
			max_path_offset - (max_path_offset % MEDIAN_HOP_CLTV_EXPIRY_DELTA),
			max_path_offset % MEDIAN_HOP_CLTV_EXPIRY_DELTA);
		shadow_ctlv_expiry_delta_offset = cmp::min(shadow_ctlv_expiry_delta_offset, max_path_offset);

		// Add 'shadow' CLTV offset to the final hop
		if let Some(tail) = path.blinded_tail.as_mut() {
			tail.excess_final_cltv_expiry_delta = tail.excess_final_cltv_expiry_delta
				.checked_add(shadow_ctlv_expiry_delta_offset).unwrap_or(tail.excess_final_cltv_expiry_delta);
		}
		if let Some(last_hop) = path.hops.last_mut() {
			last_hop.cltv_expiry_delta = last_hop.cltv_expiry_delta
				.checked_add(shadow_ctlv_expiry_delta_offset).unwrap_or(last_hop.cltv_expiry_delta);
		}
	}
}

/// Construct a route from us (payer) to the target node (payee) via the given hops (which should
/// exclude the payer, but include the payee). This may be useful, e.g., for probing the chosen path.
///
/// Re-uses logic from `find_route`, so the restrictions described there also apply here.
#[rustfmt::skip]
pub fn build_route_from_hops<L: Deref, GL: Deref>(
	our_node_pubkey: &PublicKey, hops: &[PublicKey], route_params: &RouteParameters,
	network_graph: &NetworkGraph<GL>, logger: L, random_seed_bytes: &[u8; 32]
) -> Result<Route, &'static str>
where L::Target: Logger, GL::Target: Logger {
	let graph_lock = network_graph.read_only();
	let mut route = build_route_from_hops_internal(our_node_pubkey, hops, &route_params,
		&graph_lock, logger, random_seed_bytes)?;
	add_random_cltv_offset(&mut route, &route_params.payment_params, &graph_lock, random_seed_bytes);
	Ok(route)
}

#[rustfmt::skip]
fn build_route_from_hops_internal<L: Deref>(
	our_node_pubkey: &PublicKey, hops: &[PublicKey], route_params: &RouteParameters,
	network_graph: &ReadOnlyNetworkGraph, logger: L, random_seed_bytes: &[u8; 32],
) -> Result<Route, &'static str> where L::Target: Logger {

	struct HopScorer {
		our_node_id: NodeId,
		hop_ids: [Option<NodeId>; MAX_PATH_LENGTH_ESTIMATE as usize],
	}

	impl ScoreLookUp for HopScorer {
		type ScoreParams = ();
		fn channel_penalty_msat(&self, candidate: &CandidateRouteHop,
			_usage: ChannelUsage, _score_params: &Self::ScoreParams) -> u64
		{
			let mut cur_id = self.our_node_id;
			for i in 0..self.hop_ids.len() {
				if let Some(next_id) = self.hop_ids[i] {
					if cur_id == candidate.source() && Some(next_id) == candidate.target() {
						return 0;
					}
					cur_id = next_id;
				} else {
					break;
				}
			}
			u64::max_value()
		}
	}

	impl<'a> Writeable for HopScorer {
		#[inline]
		#[rustfmt::skip]
		fn write<W: Writer>(&self, _w: &mut W) -> Result<(), io::Error> {
			unreachable!();
		}
	}

	if hops.len() > MAX_PATH_LENGTH_ESTIMATE.into() {
		return Err("Cannot build a route exceeding the maximum path length.");
	}

	let our_node_id = NodeId::from_pubkey(our_node_pubkey);
	let mut hop_ids = [None; MAX_PATH_LENGTH_ESTIMATE as usize];
	for i in 0..hops.len() {
		hop_ids[i] = Some(NodeId::from_pubkey(&hops[i]));
	}

	let scorer = HopScorer { our_node_id, hop_ids };

	get_route(our_node_pubkey, route_params, network_graph, None, logger, &scorer, &Default::default(), random_seed_bytes)
}

#[cfg(test)]
mod tests {
	use crate::blinded_path::payment::{BlindedPayInfo, BlindedPaymentPath};
	use crate::blinded_path::BlindedHop;
	use crate::chain::transaction::OutPoint;
	use crate::crypto::chacha20::ChaCha20;
	use crate::ln::channel_state::{ChannelCounterparty, ChannelDetails, ChannelShutdownState};
	use crate::ln::channelmanager;
	use crate::ln::msgs::{UnsignedChannelUpdate, MAX_VALUE_MSAT};
	use crate::ln::types::ChannelId;
	use crate::routing::gossip::{EffectiveCapacity, NetworkGraph, NodeId, P2PGossipSync};
	use crate::routing::router::{
		add_random_cltv_offset, build_route_from_hops_internal, default_node_features, get_route,
		BlindedTail, CandidateRouteHop, InFlightHtlcs, Path, PaymentParameters, PublicHopCandidate,
		Route, RouteHint, RouteHintHop, RouteHop, RouteParameters, RoutingFees,
		DEFAULT_MAX_TOTAL_CLTV_EXPIRY_DELTA, MAX_PATH_LENGTH_ESTIMATE,
	};
	use crate::routing::scoring::{
		ChannelUsage, FixedPenaltyScorer, ProbabilisticScorer, ProbabilisticScoringDecayParameters,
		ProbabilisticScoringFeeParameters, ScoreLookUp,
	};
	use crate::routing::test_utils::{
		add_channel, add_or_update_node, build_graph, build_line_graph, get_nodes,
		id_to_feature_flags, update_channel,
	};
	use crate::routing::utxo::UtxoResult;
	use crate::types::features::{BlindedHopFeatures, ChannelFeatures, InitFeatures, NodeFeatures};
	use crate::util::config::UserConfig;
	#[cfg(c_bindings)]
	use crate::util::ser::Writer;
	use crate::util::ser::{FixedLengthReader, Readable, ReadableArgs, Writeable};
	use crate::util::test_utils as ln_test_utils;

	use bitcoin::amount::Amount;
	use bitcoin::constants::ChainHash;
	use bitcoin::hashes::Hash;
	use bitcoin::hex::FromHex;
	use bitcoin::network::Network;
	use bitcoin::opcodes;
	use bitcoin::script::Builder;
	use bitcoin::secp256k1::Secp256k1;
	use bitcoin::secp256k1::{PublicKey, SecretKey};
	use bitcoin::transaction::TxOut;

	use crate::io::Cursor;
	use crate::prelude::*;
	use crate::sync::Arc;

	#[rustfmt::skip]
	fn get_channel_details(short_channel_id: Option<u64>, node_id: PublicKey,
			features: InitFeatures, outbound_capacity_msat: u64) -> ChannelDetails {
		#[allow(deprecated)] // TODO: Remove once balance_msat is removed.
		ChannelDetails {
			channel_id: ChannelId::new_zero(),
			counterparty: ChannelCounterparty {
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
			outbound_capacity_msat,
			next_outbound_htlc_limit_msat: outbound_capacity_msat,
			next_outbound_htlc_minimum_msat: 0,
			inbound_capacity_msat: 42,
			unspendable_punishment_reserve: None,
			confirmations_required: None,
			confirmations: None,
			force_close_spend_delay: None,
			is_outbound: true, is_channel_ready: true,
			is_usable: true, is_announced: true,
			inbound_htlc_minimum_msat: None,
			inbound_htlc_maximum_msat: None,
			config: None,
			feerate_sat_per_1000_weight: None,
			channel_shutdown_state: Some(ChannelShutdownState::NotShuttingDown),
			pending_inbound_htlcs: Vec::new(),
			pending_outbound_htlcs: Vec::new(),
		}
	}

	#[rustfmt::skip]
	fn dummy_blinded_path(intro_node: PublicKey, payinfo: BlindedPayInfo) -> BlindedPaymentPath {
		BlindedPaymentPath::from_blinded_path_and_payinfo(
			intro_node, ln_test_utils::pubkey(42),
			vec![
				BlindedHop { blinded_node_id: ln_test_utils::pubkey(42 as u8), encrypted_payload: Vec::new() },
				BlindedHop { blinded_node_id: ln_test_utils::pubkey(42 as u8), encrypted_payload: Vec::new() }
			],
			payinfo
		)
	}

	#[rustfmt::skip]
	fn dummy_one_hop_blinded_path(intro_node: PublicKey, payinfo: BlindedPayInfo) -> BlindedPaymentPath {
		BlindedPaymentPath::from_blinded_path_and_payinfo(
			intro_node, ln_test_utils::pubkey(42),
			vec![
				BlindedHop { blinded_node_id: ln_test_utils::pubkey(42 as u8), encrypted_payload: Vec::new() },
			],
			payinfo
		)
	}

	#[test]
	#[rustfmt::skip]
	fn simple_route_test() {
		let (secp_ctx, network_graph, _, _, logger) = build_graph();
		let (_, our_id, _, nodes) = get_nodes(&secp_ctx);
		let mut payment_params = PaymentParameters::from_node_id(nodes[2], 42);
		let scorer = ln_test_utils::TestScorer::new();
		let random_seed_bytes = [42; 32];

		// Simple route to 2 via 1

		let route_params = RouteParameters::from_payment_params_and_value(
			payment_params.clone(), 0);
		if let Err(err) = get_route(&our_id,
			&route_params, &network_graph.read_only(), None, Arc::clone(&logger), &scorer,
			&Default::default(), &random_seed_bytes) {
				assert_eq!(err, "Cannot send a payment of 0 msat");
		} else { panic!(); }

		payment_params.max_path_length = 2;
		let mut route_params = RouteParameters::from_payment_params_and_value(payment_params, 100);
		let route = get_route(&our_id, &route_params, &network_graph.read_only(), None,
			Arc::clone(&logger), &scorer, &Default::default(), &random_seed_bytes).unwrap();
		assert_eq!(route.paths[0].hops.len(), 2);

		assert_eq!(route.paths[0].hops[0].pubkey, nodes[1]);
		assert_eq!(route.paths[0].hops[0].short_channel_id, 2);
		assert_eq!(route.paths[0].hops[0].fee_msat, 100);
		assert_eq!(route.paths[0].hops[0].cltv_expiry_delta, (4 << 4) | 1);
		assert_eq!(route.paths[0].hops[0].node_features.le_flags(), &id_to_feature_flags(2));
		assert_eq!(route.paths[0].hops[0].channel_features.le_flags(), &id_to_feature_flags(2));

		assert_eq!(route.paths[0].hops[1].pubkey, nodes[2]);
		assert_eq!(route.paths[0].hops[1].short_channel_id, 4);
		assert_eq!(route.paths[0].hops[1].fee_msat, 100);
		assert_eq!(route.paths[0].hops[1].cltv_expiry_delta, 42);
		assert_eq!(route.paths[0].hops[1].node_features.le_flags(), &id_to_feature_flags(3));
		assert_eq!(route.paths[0].hops[1].channel_features.le_flags(), &id_to_feature_flags(4));

		route_params.payment_params.max_path_length = 1;
		get_route(&our_id, &route_params, &network_graph.read_only(), None,
			Arc::clone(&logger), &scorer, &Default::default(), &random_seed_bytes).unwrap_err();
	}

	#[test]
	#[rustfmt::skip]
	fn invalid_first_hop_test() {
		let (secp_ctx, network_graph, _, _, logger) = build_graph();
		let (_, our_id, _, nodes) = get_nodes(&secp_ctx);
		let payment_params = PaymentParameters::from_node_id(nodes[2], 42);
		let scorer = ln_test_utils::TestScorer::new();
		let random_seed_bytes = [42; 32];

		// Simple route to 2 via 1

		let our_chans = vec![get_channel_details(Some(2), our_id, InitFeatures::from_le_bytes(vec![0b11]), 100000)];

		let route_params = RouteParameters::from_payment_params_and_value(payment_params, 100);
		if let Err(err) = get_route(&our_id,
			&route_params, &network_graph.read_only(), Some(&our_chans.iter().collect::<Vec<_>>()),
			Arc::clone(&logger), &scorer, &Default::default(), &random_seed_bytes) {
				assert_eq!(err, "First hop cannot have our_node_pubkey as a destination.");
		} else { panic!(); }

		let route = get_route(&our_id, &route_params, &network_graph.read_only(), None,
			Arc::clone(&logger), &scorer, &Default::default(), &random_seed_bytes).unwrap();
		assert_eq!(route.paths[0].hops.len(), 2);
	}

	#[test]
	#[rustfmt::skip]
	fn htlc_minimum_test() {
		let (secp_ctx, network_graph, gossip_sync, _, logger) = build_graph();
		let (our_privkey, our_id, privkeys, nodes) = get_nodes(&secp_ctx);
		let payment_params = PaymentParameters::from_node_id(nodes[2], 42);
		let scorer = ln_test_utils::TestScorer::new();
		let random_seed_bytes = [42; 32];

		// Simple route to 2 via 1

		// Disable other paths
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 12,
			timestamp: 2,
			message_flags: 1, // Only must_be_one
			channel_flags: 2, // to disable
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[0], UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 3,
			timestamp: 2,
			message_flags: 1, // Only must_be_one
			channel_flags: 2, // to disable
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[7], UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 13,
			timestamp: 2,
			message_flags: 1, // Only must_be_one
			channel_flags: 2, // to disable
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 6,
			timestamp: 2,
			message_flags: 1, // Only must_be_one
			channel_flags: 2, // to disable
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 7,
			timestamp: 2,
			message_flags: 1, // Only must_be_one
			channel_flags: 2, // to disable
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		// Check against amount_to_transfer_over_msat.
		// Set minimal HTLC of 200_000_000 msat.
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 2,
			timestamp: 3,
			message_flags: 1, // Only must_be_one
			channel_flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 200_000_000,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		// Second hop only allows to forward 199_999_999 at most, thus not allowing the first hop to
		// be used.
		update_channel(&gossip_sync, &secp_ctx, &privkeys[1], UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 4,
			timestamp: 3,
			message_flags: 1, // Only must_be_one
			channel_flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 199_999_999,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		// Not possible to send 199_999_999, because the minimum on channel=2 is 200_000_000.
		let route_params = RouteParameters::from_payment_params_and_value(
			payment_params, 199_999_999);
		if let Err(err) = get_route(&our_id,
			&route_params, &network_graph.read_only(), None, Arc::clone(&logger), &scorer,
			&Default::default(), &random_seed_bytes) {
				assert_eq!(err, "Failed to find a path to the given destination");
		} else { panic!(); }

		// Lift the restriction on the first hop.
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 2,
			timestamp: 4,
			message_flags: 1, // Only must_be_one
			channel_flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		// A payment above the minimum should pass
		let route = get_route(&our_id, &route_params, &network_graph.read_only(), None,
			Arc::clone(&logger), &scorer, &Default::default(), &random_seed_bytes).unwrap();
		assert_eq!(route.paths[0].hops.len(), 2);
	}

	#[test]
	#[rustfmt::skip]
	fn htlc_minimum_overpay_test() {
		let (secp_ctx, network_graph, gossip_sync, _, logger) = build_graph();
		let (our_privkey, our_id, privkeys, nodes) = get_nodes(&secp_ctx);
		let config = UserConfig::default();
		let payment_params = PaymentParameters::from_node_id(nodes[2], 42)
			.with_bolt11_features(channelmanager::provided_bolt11_invoice_features(&config))
			.unwrap();
		let scorer = ln_test_utils::TestScorer::new();
		let random_seed_bytes = [42; 32];

		// A route to node#2 via two paths.
		// One path allows transferring 35-40 sats, another one also allows 35-40 sats.
		// Thus, they can't send 60 without overpaying.
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 2,
			timestamp: 2,
			message_flags: 1, // Only must_be_one
			channel_flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 35_000,
			htlc_maximum_msat: 40_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 12,
			timestamp: 3,
			message_flags: 1, // Only must_be_one
			channel_flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 35_000,
			htlc_maximum_msat: 40_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		// Make 0 fee.
		update_channel(&gossip_sync, &secp_ctx, &privkeys[7], UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 13,
			timestamp: 2,
			message_flags: 1, // Only must_be_one
			channel_flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[1], UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 4,
			timestamp: 2,
			message_flags: 1, // Only must_be_one
			channel_flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		// Disable other paths
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 1,
			timestamp: 3,
			message_flags: 1, // Only must_be_one
			channel_flags: 2, // to disable
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		let mut route_params = RouteParameters::from_payment_params_and_value(
			payment_params.clone(), 60_000);
		route_params.max_total_routing_fee_msat = Some(15_000);
		let route = get_route(&our_id, &route_params, &network_graph.read_only(), None,
			Arc::clone(&logger), &scorer, &Default::default(), &random_seed_bytes).unwrap();
		// Overpay fees to hit htlc_minimum_msat.
		let overpaid_fees = route.paths[0].hops[0].fee_msat + route.paths[1].hops[0].fee_msat;
		// TODO: this could be better balanced to overpay 10k and not 15k.
		assert_eq!(overpaid_fees, 15_000);

		// Now, test that if there are 2 paths, a "cheaper" by fee path wouldn't be prioritized
		// while taking even more fee to match htlc_minimum_msat.
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 12,
			timestamp: 4,
			message_flags: 1, // Only must_be_one
			channel_flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 65_000,
			htlc_maximum_msat: 80_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 2,
			timestamp: 3,
			message_flags: 1, // Only must_be_one
			channel_flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[1], UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 4,
			timestamp: 4,
			message_flags: 1, // Only must_be_one
			channel_flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,
			fee_proportional_millionths: 100_000,
			excess_data: Vec::new()
		});

		let route = get_route(&our_id, &route_params, &network_graph.read_only(), None,
			Arc::clone(&logger), &scorer, &Default::default(), &random_seed_bytes).unwrap();
		// Fine to overpay for htlc_minimum_msat if it allows us to save fee.
		assert_eq!(route.paths.len(), 1);
		assert_eq!(route.paths[0].hops[0].short_channel_id, 12);
		let fees = route.paths[0].hops[0].fee_msat;
		assert_eq!(fees, 5_000);

		let route_params = RouteParameters::from_payment_params_and_value(payment_params, 50_000);
		let route = get_route(&our_id, &route_params, &network_graph.read_only(), None,
			Arc::clone(&logger), &scorer, &Default::default(), &random_seed_bytes).unwrap();
		// Not fine to overpay for htlc_minimum_msat if it requires paying more than fee on
		// the other channel.
		assert_eq!(route.paths.len(), 1);
		assert_eq!(route.paths[0].hops[0].short_channel_id, 2);
		let fees = route.paths[0].hops[0].fee_msat;
		assert_eq!(fees, 5_000);
	}

	#[test]
	#[rustfmt::skip]
	fn htlc_minimum_recipient_overpay_test() {
		let (secp_ctx, network_graph, gossip_sync, _, logger) = build_graph();
		let (_, our_id, privkeys, nodes) = get_nodes(&secp_ctx);
		let config = UserConfig::default();
		let payment_params = PaymentParameters::from_node_id(nodes[2], 42).with_bolt11_features(channelmanager::provided_bolt11_invoice_features(&config)).unwrap();
		let scorer = ln_test_utils::TestScorer::new();
		let random_seed_bytes = [42; 32];

		// Route to node2 over a single path which requires overpaying the recipient themselves.

		// First disable all paths except the us -> node1 -> node2 path
		update_channel(&gossip_sync, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 13,
			timestamp: 2,
			message_flags: 1, // Only must_be_one
			channel_flags: 3,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 0,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		// Set channel 4 to free but with a high htlc_minimum_msat
		update_channel(&gossip_sync, &secp_ctx, &privkeys[1], UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 4,
			timestamp: 2,
			message_flags: 1, // Only must_be_one
			channel_flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 15_000,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		// Now check that we'll fail to find a path if we fail to find a path if the htlc_minimum
		// is overrun. Note that the fees are actually calculated on 3*payment amount as that's
		// what we try to find a route for, so this test only just happens to work out to exactly
		// the fee limit.
		let mut route_params = RouteParameters::from_payment_params_and_value(
			payment_params.clone(), 5_000);
		route_params.max_total_routing_fee_msat = Some(9_999);
		if let Err(err) = get_route(&our_id,
			&route_params, &network_graph.read_only(), None, Arc::clone(&logger), &scorer,
			&Default::default(), &random_seed_bytes) {
				assert_eq!(err, "Failed to find route that adheres to the maximum total fee limit");
		} else { panic!(); }

		let mut route_params = RouteParameters::from_payment_params_and_value(
			payment_params.clone(), 5_000);
		route_params.max_total_routing_fee_msat = Some(10_000);
		let route = get_route(&our_id, &route_params, &network_graph.read_only(), None,
			Arc::clone(&logger), &scorer, &Default::default(), &random_seed_bytes).unwrap();
		assert_eq!(route.get_total_fees(), 10_000);
	}

	#[test]
	#[rustfmt::skip]
	fn disable_channels_test() {
		let (secp_ctx, network_graph, gossip_sync, _, logger) = build_graph();
		let (our_privkey, our_id, privkeys, nodes) = get_nodes(&secp_ctx);
		let payment_params = PaymentParameters::from_node_id(nodes[2], 42);
		let scorer = ln_test_utils::TestScorer::new();
		let random_seed_bytes = [42; 32];

		// // Disable channels 4 and 12 by flags=2
		update_channel(&gossip_sync, &secp_ctx, &privkeys[1], UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 4,
			timestamp: 2,
			message_flags: 1, // Only must_be_one
			channel_flags: 2, // to disable
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 12,
			timestamp: 2,
			message_flags: 1, // Only must_be_one
			channel_flags: 2, // to disable
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		// If all the channels require some features we don't understand, route should fail
		let mut route_params = RouteParameters::from_payment_params_and_value(payment_params, 100);
		if let Err(err) = get_route(&our_id,
			&route_params, &network_graph.read_only(), None, Arc::clone(&logger), &scorer,
			&Default::default(), &random_seed_bytes) {
				assert_eq!(err, "Failed to find a path to the given destination");
		} else { panic!(); }

		// If we specify a channel to node7, that overrides our local channel view and that gets used
		let our_chans = vec![get_channel_details(Some(42), nodes[7].clone(),
			InitFeatures::from_le_bytes(vec![0b11]), 250_000_000)];
		route_params.payment_params.max_path_length = 2;
		let route = get_route(&our_id, &route_params, &network_graph.read_only(),
			Some(&our_chans.iter().collect::<Vec<_>>()), Arc::clone(&logger), &scorer,
			&Default::default(), &random_seed_bytes).unwrap();
		assert_eq!(route.paths[0].hops.len(), 2);

		assert_eq!(route.paths[0].hops[0].pubkey, nodes[7]);
		assert_eq!(route.paths[0].hops[0].short_channel_id, 42);
		assert_eq!(route.paths[0].hops[0].fee_msat, 200);
		assert_eq!(route.paths[0].hops[0].cltv_expiry_delta, (13 << 4) | 1);
		assert_eq!(route.paths[0].hops[0].node_features.le_flags(), &vec![0b11]); // it should also override our view of their features
		assert_eq!(route.paths[0].hops[0].channel_features.le_flags(), &Vec::<u8>::new()); // No feature flags will meet the relevant-to-channel conversion

		assert_eq!(route.paths[0].hops[1].pubkey, nodes[2]);
		assert_eq!(route.paths[0].hops[1].short_channel_id, 13);
		assert_eq!(route.paths[0].hops[1].fee_msat, 100);
		assert_eq!(route.paths[0].hops[1].cltv_expiry_delta, 42);
		assert_eq!(route.paths[0].hops[1].node_features.le_flags(), &id_to_feature_flags(3));
		assert_eq!(route.paths[0].hops[1].channel_features.le_flags(), &id_to_feature_flags(13));
	}

	#[test]
	#[rustfmt::skip]
	fn disable_node_test() {
		let (secp_ctx, network_graph, gossip_sync, _, logger) = build_graph();
		let (_, our_id, privkeys, nodes) = get_nodes(&secp_ctx);
		let payment_params = PaymentParameters::from_node_id(nodes[2], 42);
		let scorer = ln_test_utils::TestScorer::new();
		let random_seed_bytes = [42; 32];

		// Disable nodes 1, 2, and 8 by requiring unknown feature bits
		let mut unknown_features = NodeFeatures::empty();
		unknown_features.set_unknown_feature_required();
		add_or_update_node(&gossip_sync, &secp_ctx, &privkeys[0], unknown_features.clone(), 1);
		add_or_update_node(&gossip_sync, &secp_ctx, &privkeys[1], unknown_features.clone(), 1);
		add_or_update_node(&gossip_sync, &secp_ctx, &privkeys[7], unknown_features.clone(), 1);

		// If all nodes require some features we don't understand, route should fail
		let route_params = RouteParameters::from_payment_params_and_value(payment_params, 100);
		if let Err(err) = get_route(&our_id,
			&route_params, &network_graph.read_only(), None, Arc::clone(&logger), &scorer,
			&Default::default(), &random_seed_bytes) {
				assert_eq!(err, "Failed to find a path to the given destination");
		} else { panic!(); }

		// If we specify a channel to node7, that overrides our local channel view and that gets used
		let our_chans = vec![get_channel_details(Some(42), nodes[7].clone(),
			InitFeatures::from_le_bytes(vec![0b11]), 250_000_000)];
		let route = get_route(&our_id, &route_params, &network_graph.read_only(),
			Some(&our_chans.iter().collect::<Vec<_>>()), Arc::clone(&logger), &scorer,
			&Default::default(), &random_seed_bytes).unwrap();
		assert_eq!(route.paths[0].hops.len(), 2);

		assert_eq!(route.paths[0].hops[0].pubkey, nodes[7]);
		assert_eq!(route.paths[0].hops[0].short_channel_id, 42);
		assert_eq!(route.paths[0].hops[0].fee_msat, 200);
		assert_eq!(route.paths[0].hops[0].cltv_expiry_delta, (13 << 4) | 1);
		assert_eq!(route.paths[0].hops[0].node_features.le_flags(), &vec![0b11]); // it should also override our view of their features
		assert_eq!(route.paths[0].hops[0].channel_features.le_flags(), &Vec::<u8>::new()); // No feature flags will meet the relevant-to-channel conversion

		assert_eq!(route.paths[0].hops[1].pubkey, nodes[2]);
		assert_eq!(route.paths[0].hops[1].short_channel_id, 13);
		assert_eq!(route.paths[0].hops[1].fee_msat, 100);
		assert_eq!(route.paths[0].hops[1].cltv_expiry_delta, 42);
		assert_eq!(route.paths[0].hops[1].node_features.le_flags(), &id_to_feature_flags(3));
		assert_eq!(route.paths[0].hops[1].channel_features.le_flags(), &id_to_feature_flags(13));

		// Note that we don't test disabling node 3 and failing to route to it, as we (somewhat
		// naively) assume that the user checked the feature bits on the invoice, which override
		// the node_announcement.
	}

	#[test]
	#[rustfmt::skip]
	fn our_chans_test() {
		let (secp_ctx, network_graph, _, _, logger) = build_graph();
		let (_, our_id, _, nodes) = get_nodes(&secp_ctx);
		let scorer = ln_test_utils::TestScorer::new();
		let random_seed_bytes = [42; 32];

		// Route to 1 via 2 and 3 because our channel to 1 is disabled
		let payment_params = PaymentParameters::from_node_id(nodes[0], 42);
		let route_params = RouteParameters::from_payment_params_and_value(payment_params, 100);
		let route = get_route(&our_id, &route_params, &network_graph.read_only(), None,
			Arc::clone(&logger), &scorer, &Default::default(), &random_seed_bytes).unwrap();
		assert_eq!(route.paths[0].hops.len(), 3);

		assert_eq!(route.paths[0].hops[0].pubkey, nodes[1]);
		assert_eq!(route.paths[0].hops[0].short_channel_id, 2);
		assert_eq!(route.paths[0].hops[0].fee_msat, 200);
		assert_eq!(route.paths[0].hops[0].cltv_expiry_delta, (4 << 4) | 1);
		assert_eq!(route.paths[0].hops[0].node_features.le_flags(), &id_to_feature_flags(2));
		assert_eq!(route.paths[0].hops[0].channel_features.le_flags(), &id_to_feature_flags(2));

		assert_eq!(route.paths[0].hops[1].pubkey, nodes[2]);
		assert_eq!(route.paths[0].hops[1].short_channel_id, 4);
		assert_eq!(route.paths[0].hops[1].fee_msat, 100);
		assert_eq!(route.paths[0].hops[1].cltv_expiry_delta, (3 << 4) | 2);
		assert_eq!(route.paths[0].hops[1].node_features.le_flags(), &id_to_feature_flags(3));
		assert_eq!(route.paths[0].hops[1].channel_features.le_flags(), &id_to_feature_flags(4));

		assert_eq!(route.paths[0].hops[2].pubkey, nodes[0]);
		assert_eq!(route.paths[0].hops[2].short_channel_id, 3);
		assert_eq!(route.paths[0].hops[2].fee_msat, 100);
		assert_eq!(route.paths[0].hops[2].cltv_expiry_delta, 42);
		assert_eq!(route.paths[0].hops[2].node_features.le_flags(), &id_to_feature_flags(1));
		assert_eq!(route.paths[0].hops[2].channel_features.le_flags(), &id_to_feature_flags(3));

		// If we specify a channel to node7, that overrides our local channel view and that gets used
		let payment_params = PaymentParameters::from_node_id(nodes[2], 42);
		let route_params = RouteParameters::from_payment_params_and_value(payment_params, 100);
		let our_chans = vec![get_channel_details(Some(42), nodes[7].clone(),
			InitFeatures::from_le_bytes(vec![0b11]), 250_000_000)];
		let route = get_route(&our_id, &route_params, &network_graph.read_only(),
			Some(&our_chans.iter().collect::<Vec<_>>()), Arc::clone(&logger), &scorer,
			&Default::default(), &random_seed_bytes).unwrap();
		assert_eq!(route.paths[0].hops.len(), 2);

		assert_eq!(route.paths[0].hops[0].pubkey, nodes[7]);
		assert_eq!(route.paths[0].hops[0].short_channel_id, 42);
		assert_eq!(route.paths[0].hops[0].fee_msat, 200);
		assert_eq!(route.paths[0].hops[0].cltv_expiry_delta, (13 << 4) | 1);
		assert_eq!(route.paths[0].hops[0].node_features.le_flags(), &vec![0b11]);
		assert_eq!(route.paths[0].hops[0].channel_features.le_flags(), &Vec::<u8>::new()); // No feature flags will meet the relevant-to-channel conversion

		assert_eq!(route.paths[0].hops[1].pubkey, nodes[2]);
		assert_eq!(route.paths[0].hops[1].short_channel_id, 13);
		assert_eq!(route.paths[0].hops[1].fee_msat, 100);
		assert_eq!(route.paths[0].hops[1].cltv_expiry_delta, 42);
		assert_eq!(route.paths[0].hops[1].node_features.le_flags(), &id_to_feature_flags(3));
		assert_eq!(route.paths[0].hops[1].channel_features.le_flags(), &id_to_feature_flags(13));
	}

	#[rustfmt::skip]
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

	#[rustfmt::skip]
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
	#[rustfmt::skip]
	fn partial_route_hint_test() {
		let (secp_ctx, network_graph, _, _, logger) = build_graph();
		let (_, our_id, _, nodes) = get_nodes(&secp_ctx);
		let scorer = ln_test_utils::TestScorer::new();
		let random_seed_bytes = [42; 32];

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
			let payment_params = PaymentParameters::from_node_id(nodes[6], 42)
				.with_route_hints(invalid_last_hops).unwrap();
			let route_params = RouteParameters::from_payment_params_and_value(payment_params, 100);
			if let Err(err) = get_route(&our_id,
				&route_params, &network_graph.read_only(), None, Arc::clone(&logger), &scorer,
				&Default::default(), &random_seed_bytes) {
					assert_eq!(err, "Route hint cannot have the payee as the source.");
			} else { panic!(); }
		}

		let mut payment_params = PaymentParameters::from_node_id(nodes[6], 42)
			.with_route_hints(last_hops_multi_private_channels(&nodes)).unwrap();
		payment_params.max_path_length = 5;
		let route_params = RouteParameters::from_payment_params_and_value(payment_params, 100);
		let route = get_route(&our_id, &route_params, &network_graph.read_only(), None,
			Arc::clone(&logger), &scorer, &Default::default(), &random_seed_bytes).unwrap();
		assert_eq!(route.paths[0].hops.len(), 5);

		assert_eq!(route.paths[0].hops[0].pubkey, nodes[1]);
		assert_eq!(route.paths[0].hops[0].short_channel_id, 2);
		assert_eq!(route.paths[0].hops[0].fee_msat, 100);
		assert_eq!(route.paths[0].hops[0].cltv_expiry_delta, (4 << 4) | 1);
		assert_eq!(route.paths[0].hops[0].node_features.le_flags(), &id_to_feature_flags(2));
		assert_eq!(route.paths[0].hops[0].channel_features.le_flags(), &id_to_feature_flags(2));

		assert_eq!(route.paths[0].hops[1].pubkey, nodes[2]);
		assert_eq!(route.paths[0].hops[1].short_channel_id, 4);
		assert_eq!(route.paths[0].hops[1].fee_msat, 0);
		assert_eq!(route.paths[0].hops[1].cltv_expiry_delta, (6 << 4) | 1);
		assert_eq!(route.paths[0].hops[1].node_features.le_flags(), &id_to_feature_flags(3));
		assert_eq!(route.paths[0].hops[1].channel_features.le_flags(), &id_to_feature_flags(4));

		assert_eq!(route.paths[0].hops[2].pubkey, nodes[4]);
		assert_eq!(route.paths[0].hops[2].short_channel_id, 6);
		assert_eq!(route.paths[0].hops[2].fee_msat, 0);
		assert_eq!(route.paths[0].hops[2].cltv_expiry_delta, (11 << 4) | 1);
		assert_eq!(route.paths[0].hops[2].node_features.le_flags(), &id_to_feature_flags(5));
		assert_eq!(route.paths[0].hops[2].channel_features.le_flags(), &id_to_feature_flags(6));

		assert_eq!(route.paths[0].hops[3].pubkey, nodes[3]);
		assert_eq!(route.paths[0].hops[3].short_channel_id, 11);
		assert_eq!(route.paths[0].hops[3].fee_msat, 0);
		assert_eq!(route.paths[0].hops[3].cltv_expiry_delta, (8 << 4) | 1);
		// If we have a peer in the node map, we'll use their features here since we don't have
		// a way of figuring out their features from the invoice:
		assert_eq!(route.paths[0].hops[3].node_features.le_flags(), &id_to_feature_flags(4));
		assert_eq!(route.paths[0].hops[3].channel_features.le_flags(), &id_to_feature_flags(11));

		assert_eq!(route.paths[0].hops[4].pubkey, nodes[6]);
		assert_eq!(route.paths[0].hops[4].short_channel_id, 8);
		assert_eq!(route.paths[0].hops[4].fee_msat, 100);
		assert_eq!(route.paths[0].hops[4].cltv_expiry_delta, 42);
		assert_eq!(route.paths[0].hops[4].node_features.le_flags(), default_node_features().le_flags()); // We dont pass flags in from invoices yet
		assert_eq!(route.paths[0].hops[4].channel_features.le_flags(), &Vec::<u8>::new()); // We can't learn any flags from invoices, sadly
	}

	#[rustfmt::skip]
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
	#[rustfmt::skip]
	fn ignores_empty_last_hops_test() {
		let (secp_ctx, network_graph, _, _, logger) = build_graph();
		let (_, our_id, _, nodes) = get_nodes(&secp_ctx);
		let payment_params = PaymentParameters::from_node_id(nodes[6], 42).with_route_hints(empty_last_hop(&nodes)).unwrap();
		let scorer = ln_test_utils::TestScorer::new();
		let random_seed_bytes = [42; 32];

		// Test handling of an empty RouteHint passed in Invoice.
		let route_params = RouteParameters::from_payment_params_and_value(payment_params, 100);
		let route = get_route(&our_id, &route_params, &network_graph.read_only(), None,
			Arc::clone(&logger), &scorer, &Default::default(), &random_seed_bytes).unwrap();
		assert_eq!(route.paths[0].hops.len(), 5);

		assert_eq!(route.paths[0].hops[0].pubkey, nodes[1]);
		assert_eq!(route.paths[0].hops[0].short_channel_id, 2);
		assert_eq!(route.paths[0].hops[0].fee_msat, 100);
		assert_eq!(route.paths[0].hops[0].cltv_expiry_delta, (4 << 4) | 1);
		assert_eq!(route.paths[0].hops[0].node_features.le_flags(), &id_to_feature_flags(2));
		assert_eq!(route.paths[0].hops[0].channel_features.le_flags(), &id_to_feature_flags(2));

		assert_eq!(route.paths[0].hops[1].pubkey, nodes[2]);
		assert_eq!(route.paths[0].hops[1].short_channel_id, 4);
		assert_eq!(route.paths[0].hops[1].fee_msat, 0);
		assert_eq!(route.paths[0].hops[1].cltv_expiry_delta, (6 << 4) | 1);
		assert_eq!(route.paths[0].hops[1].node_features.le_flags(), &id_to_feature_flags(3));
		assert_eq!(route.paths[0].hops[1].channel_features.le_flags(), &id_to_feature_flags(4));

		assert_eq!(route.paths[0].hops[2].pubkey, nodes[4]);
		assert_eq!(route.paths[0].hops[2].short_channel_id, 6);
		assert_eq!(route.paths[0].hops[2].fee_msat, 0);
		assert_eq!(route.paths[0].hops[2].cltv_expiry_delta, (11 << 4) | 1);
		assert_eq!(route.paths[0].hops[2].node_features.le_flags(), &id_to_feature_flags(5));
		assert_eq!(route.paths[0].hops[2].channel_features.le_flags(), &id_to_feature_flags(6));

		assert_eq!(route.paths[0].hops[3].pubkey, nodes[3]);
		assert_eq!(route.paths[0].hops[3].short_channel_id, 11);
		assert_eq!(route.paths[0].hops[3].fee_msat, 0);
		assert_eq!(route.paths[0].hops[3].cltv_expiry_delta, (8 << 4) | 1);
		// If we have a peer in the node map, we'll use their features here since we don't have
		// a way of figuring out their features from the invoice:
		assert_eq!(route.paths[0].hops[3].node_features.le_flags(), &id_to_feature_flags(4));
		assert_eq!(route.paths[0].hops[3].channel_features.le_flags(), &id_to_feature_flags(11));

		assert_eq!(route.paths[0].hops[4].pubkey, nodes[6]);
		assert_eq!(route.paths[0].hops[4].short_channel_id, 8);
		assert_eq!(route.paths[0].hops[4].fee_msat, 100);
		assert_eq!(route.paths[0].hops[4].cltv_expiry_delta, 42);
		assert_eq!(route.paths[0].hops[4].node_features.le_flags(), default_node_features().le_flags()); // We dont pass flags in from invoices yet
		assert_eq!(route.paths[0].hops[4].channel_features.le_flags(), &Vec::<u8>::new()); // We can't learn any flags from invoices, sadly
	}

	/// Builds a trivial last-hop hint that passes through the two nodes given, with channel 0xff00
	/// and 0xff01.
	#[rustfmt::skip]
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
	#[rustfmt::skip]
	fn multi_hint_last_hops_test() {
		let (secp_ctx, network_graph, gossip_sync, _, logger) = build_graph();
		let (_, our_id, privkeys, nodes) = get_nodes(&secp_ctx);
		let last_hops = multi_hop_last_hops_hint([nodes[2], nodes[3]]);
		let payment_params = PaymentParameters::from_node_id(nodes[6], 42).with_route_hints(last_hops.clone()).unwrap();
		let scorer = ln_test_utils::TestScorer::new();
		let random_seed_bytes = [42; 32];

		// Test through channels 2, 3, 0xff00, 0xff01.
		// Test shows that multi-hop route hints are considered and factored correctly into the
		// max path length.

		// Disabling channels 6 & 7 by flags=2
		update_channel(&gossip_sync, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 6,
			timestamp: 2,
			message_flags: 1, // Only must_be_one
			channel_flags: 2, // to disable
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 7,
			timestamp: 2,
			message_flags: 1, // Only must_be_one
			channel_flags: 2, // to disable
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		let mut route_params = RouteParameters::from_payment_params_and_value(payment_params, 100);
		route_params.payment_params.max_path_length = 4;
		let route = get_route(&our_id, &route_params, &network_graph.read_only(), None,
			Arc::clone(&logger), &scorer, &Default::default(), &random_seed_bytes).unwrap();
		assert_eq!(route.paths[0].hops.len(), 4);

		assert_eq!(route.paths[0].hops[0].pubkey, nodes[1]);
		assert_eq!(route.paths[0].hops[0].short_channel_id, 2);
		assert_eq!(route.paths[0].hops[0].fee_msat, 200);
		assert_eq!(route.paths[0].hops[0].cltv_expiry_delta, 65);
		assert_eq!(route.paths[0].hops[0].node_features.le_flags(), &id_to_feature_flags(2));
		assert_eq!(route.paths[0].hops[0].channel_features.le_flags(), &id_to_feature_flags(2));

		assert_eq!(route.paths[0].hops[1].pubkey, nodes[2]);
		assert_eq!(route.paths[0].hops[1].short_channel_id, 4);
		assert_eq!(route.paths[0].hops[1].fee_msat, 100);
		assert_eq!(route.paths[0].hops[1].cltv_expiry_delta, 81);
		assert_eq!(route.paths[0].hops[1].node_features.le_flags(), &id_to_feature_flags(3));
		assert_eq!(route.paths[0].hops[1].channel_features.le_flags(), &id_to_feature_flags(4));

		assert_eq!(route.paths[0].hops[2].pubkey, nodes[3]);
		assert_eq!(route.paths[0].hops[2].short_channel_id, last_hops[0].0[0].short_channel_id);
		assert_eq!(route.paths[0].hops[2].fee_msat, 0);
		assert_eq!(route.paths[0].hops[2].cltv_expiry_delta, 129);
		assert_eq!(route.paths[0].hops[2].node_features.le_flags(), &id_to_feature_flags(4));
		assert_eq!(route.paths[0].hops[2].channel_features.le_flags(), &Vec::<u8>::new()); // We can't learn any flags from invoices, sadly

		assert_eq!(route.paths[0].hops[3].pubkey, nodes[6]);
		assert_eq!(route.paths[0].hops[3].short_channel_id, last_hops[0].0[1].short_channel_id);
		assert_eq!(route.paths[0].hops[3].fee_msat, 100);
		assert_eq!(route.paths[0].hops[3].cltv_expiry_delta, 42);
		assert_eq!(route.paths[0].hops[3].node_features.le_flags(), default_node_features().le_flags()); // We dont pass flags in from invoices yet
		assert_eq!(route.paths[0].hops[3].channel_features.le_flags(), &Vec::<u8>::new()); // We can't learn any flags from invoices, sadly
		route_params.payment_params.max_path_length = 3;
		get_route(&our_id, &route_params, &network_graph.read_only(), None,
			Arc::clone(&logger), &scorer, &Default::default(), &random_seed_bytes).unwrap_err();
	}

	#[test]
	#[rustfmt::skip]
	fn private_multi_hint_last_hops_test() {
		let (secp_ctx, network_graph, gossip_sync, _, logger) = build_graph();
		let (_, our_id, privkeys, nodes) = get_nodes(&secp_ctx);

		let non_announced_privkey = SecretKey::from_slice(&<Vec<u8>>::from_hex(&format!("{:02x}", 0xf0).repeat(32)).unwrap()[..]).unwrap();
		let non_announced_pubkey = PublicKey::from_secret_key(&secp_ctx, &non_announced_privkey);

		let last_hops = multi_hop_last_hops_hint([nodes[2], non_announced_pubkey]);
		let payment_params = PaymentParameters::from_node_id(nodes[6], 42).with_route_hints(last_hops.clone()).unwrap();
		let scorer = ln_test_utils::TestScorer::new();
		// Test through channels 2, 3, 0xff00, 0xff01.
		// Test shows that multiple hop hints are considered.

		// Disabling channels 6 & 7 by flags=2
		update_channel(&gossip_sync, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 6,
			timestamp: 2,
			message_flags: 1, // Only must_be_one
			channel_flags: 2, // to disable
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 7,
			timestamp: 2,
			message_flags: 1, // Only must_be_one
			channel_flags: 2, // to disable
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		let route_params = RouteParameters::from_payment_params_and_value(payment_params, 100);
		let route = get_route(&our_id, &route_params, &network_graph.read_only(), None,
			Arc::clone(&logger), &scorer, &Default::default(), &[42u8; 32]).unwrap();
		assert_eq!(route.paths[0].hops.len(), 4);

		assert_eq!(route.paths[0].hops[0].pubkey, nodes[1]);
		assert_eq!(route.paths[0].hops[0].short_channel_id, 2);
		assert_eq!(route.paths[0].hops[0].fee_msat, 200);
		assert_eq!(route.paths[0].hops[0].cltv_expiry_delta, 65);
		assert_eq!(route.paths[0].hops[0].node_features.le_flags(), &id_to_feature_flags(2));
		assert_eq!(route.paths[0].hops[0].channel_features.le_flags(), &id_to_feature_flags(2));

		assert_eq!(route.paths[0].hops[1].pubkey, nodes[2]);
		assert_eq!(route.paths[0].hops[1].short_channel_id, 4);
		assert_eq!(route.paths[0].hops[1].fee_msat, 100);
		assert_eq!(route.paths[0].hops[1].cltv_expiry_delta, 81);
		assert_eq!(route.paths[0].hops[1].node_features.le_flags(), &id_to_feature_flags(3));
		assert_eq!(route.paths[0].hops[1].channel_features.le_flags(), &id_to_feature_flags(4));

		assert_eq!(route.paths[0].hops[2].pubkey, non_announced_pubkey);
		assert_eq!(route.paths[0].hops[2].short_channel_id, last_hops[0].0[0].short_channel_id);
		assert_eq!(route.paths[0].hops[2].fee_msat, 0);
		assert_eq!(route.paths[0].hops[2].cltv_expiry_delta, 129);
		assert_eq!(route.paths[0].hops[2].node_features.le_flags(), default_node_features().le_flags()); // We dont pass flags in from invoices yet
		assert_eq!(route.paths[0].hops[2].channel_features.le_flags(), &Vec::<u8>::new()); // We can't learn any flags from invoices, sadly

		assert_eq!(route.paths[0].hops[3].pubkey, nodes[6]);
		assert_eq!(route.paths[0].hops[3].short_channel_id, last_hops[0].0[1].short_channel_id);
		assert_eq!(route.paths[0].hops[3].fee_msat, 100);
		assert_eq!(route.paths[0].hops[3].cltv_expiry_delta, 42);
		assert_eq!(route.paths[0].hops[3].node_features.le_flags(), default_node_features().le_flags()); // We dont pass flags in from invoices yet
		assert_eq!(route.paths[0].hops[3].channel_features.le_flags(), &Vec::<u8>::new()); // We can't learn any flags from invoices, sadly
	}

	#[rustfmt::skip]
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
	#[rustfmt::skip]
	fn last_hops_with_public_channel_test() {
		let (secp_ctx, network_graph, _, _, logger) = build_graph();
		let (_, our_id, _, nodes) = get_nodes(&secp_ctx);
		let payment_params = PaymentParameters::from_node_id(nodes[6], 42).with_route_hints(last_hops_with_public_channel(&nodes)).unwrap();
		let scorer = ln_test_utils::TestScorer::new();
		let random_seed_bytes = [42; 32];

		// This test shows that public routes can be present in the invoice
		// which would be handled in the same manner.

		let route_params = RouteParameters::from_payment_params_and_value(payment_params, 100);
		let route = get_route(&our_id, &route_params, &network_graph.read_only(), None,
			Arc::clone(&logger), &scorer, &Default::default(), &random_seed_bytes).unwrap();
		assert_eq!(route.paths[0].hops.len(), 5);

		assert_eq!(route.paths[0].hops[0].pubkey, nodes[1]);
		assert_eq!(route.paths[0].hops[0].short_channel_id, 2);
		assert_eq!(route.paths[0].hops[0].fee_msat, 100);
		assert_eq!(route.paths[0].hops[0].cltv_expiry_delta, (4 << 4) | 1);
		assert_eq!(route.paths[0].hops[0].node_features.le_flags(), &id_to_feature_flags(2));
		assert_eq!(route.paths[0].hops[0].channel_features.le_flags(), &id_to_feature_flags(2));

		assert_eq!(route.paths[0].hops[1].pubkey, nodes[2]);
		assert_eq!(route.paths[0].hops[1].short_channel_id, 4);
		assert_eq!(route.paths[0].hops[1].fee_msat, 0);
		assert_eq!(route.paths[0].hops[1].cltv_expiry_delta, (6 << 4) | 1);
		assert_eq!(route.paths[0].hops[1].node_features.le_flags(), &id_to_feature_flags(3));
		assert_eq!(route.paths[0].hops[1].channel_features.le_flags(), &id_to_feature_flags(4));

		assert_eq!(route.paths[0].hops[2].pubkey, nodes[4]);
		assert_eq!(route.paths[0].hops[2].short_channel_id, 6);
		assert_eq!(route.paths[0].hops[2].fee_msat, 0);
		assert_eq!(route.paths[0].hops[2].cltv_expiry_delta, (11 << 4) | 1);
		assert_eq!(route.paths[0].hops[2].node_features.le_flags(), &id_to_feature_flags(5));
		assert_eq!(route.paths[0].hops[2].channel_features.le_flags(), &id_to_feature_flags(6));

		assert_eq!(route.paths[0].hops[3].pubkey, nodes[3]);
		assert_eq!(route.paths[0].hops[3].short_channel_id, 11);
		assert_eq!(route.paths[0].hops[3].fee_msat, 0);
		assert_eq!(route.paths[0].hops[3].cltv_expiry_delta, (8 << 4) | 1);
		// If we have a peer in the node map, we'll use their features here since we don't have
		// a way of figuring out their features from the invoice:
		assert_eq!(route.paths[0].hops[3].node_features.le_flags(), &id_to_feature_flags(4));
		assert_eq!(route.paths[0].hops[3].channel_features.le_flags(), &id_to_feature_flags(11));

		assert_eq!(route.paths[0].hops[4].pubkey, nodes[6]);
		assert_eq!(route.paths[0].hops[4].short_channel_id, 8);
		assert_eq!(route.paths[0].hops[4].fee_msat, 100);
		assert_eq!(route.paths[0].hops[4].cltv_expiry_delta, 42);
		assert_eq!(route.paths[0].hops[4].node_features.le_flags(), default_node_features().le_flags()); // We dont pass flags in from invoices yet
		assert_eq!(route.paths[0].hops[4].channel_features.le_flags(), &Vec::<u8>::new()); // We can't learn any flags from invoices, sadly
	}

	#[test]
	#[rustfmt::skip]
	fn our_chans_last_hop_connect_test() {
		let (secp_ctx, network_graph, _, _, logger) = build_graph();
		let (_, our_id, _, nodes) = get_nodes(&secp_ctx);
		let scorer = ln_test_utils::TestScorer::new();
		let random_seed_bytes = [42; 32];

		// Simple test with outbound channel to 4 to test that last_hops and first_hops connect
		let our_chans = vec![get_channel_details(Some(42), nodes[3].clone(), InitFeatures::from_le_bytes(vec![0b11]), 250_000_000)];
		let mut last_hops = last_hops(&nodes);
		let payment_params = PaymentParameters::from_node_id(nodes[6], 42)
			.with_route_hints(last_hops.clone()).unwrap();
		let route_params = RouteParameters::from_payment_params_and_value(payment_params, 100);
		let route = get_route(&our_id, &route_params, &network_graph.read_only(),
			Some(&our_chans.iter().collect::<Vec<_>>()), Arc::clone(&logger), &scorer,
			&Default::default(), &random_seed_bytes).unwrap();
		assert_eq!(route.paths[0].hops.len(), 2);

		assert_eq!(route.paths[0].hops[0].pubkey, nodes[3]);
		assert_eq!(route.paths[0].hops[0].short_channel_id, 42);
		assert_eq!(route.paths[0].hops[0].fee_msat, 0);
		assert_eq!(route.paths[0].hops[0].cltv_expiry_delta, (8 << 4) | 1);
		assert_eq!(route.paths[0].hops[0].node_features.le_flags(), &vec![0b11]);
		assert_eq!(route.paths[0].hops[0].channel_features.le_flags(), &Vec::<u8>::new()); // No feature flags will meet the relevant-to-channel conversion

		assert_eq!(route.paths[0].hops[1].pubkey, nodes[6]);
		assert_eq!(route.paths[0].hops[1].short_channel_id, 8);
		assert_eq!(route.paths[0].hops[1].fee_msat, 100);
		assert_eq!(route.paths[0].hops[1].cltv_expiry_delta, 42);
		assert_eq!(route.paths[0].hops[1].node_features.le_flags(), default_node_features().le_flags()); // We dont pass flags in from invoices yet
		assert_eq!(route.paths[0].hops[1].channel_features.le_flags(), &Vec::<u8>::new()); // We can't learn any flags from invoices, sadly

		last_hops[0].0[0].fees.base_msat = 1000;

		// Revert to via 6 as the fee on 8 goes up
		let payment_params = PaymentParameters::from_node_id(nodes[6], 42)
			.with_route_hints(last_hops).unwrap();
		let route_params = RouteParameters::from_payment_params_and_value(
			payment_params.clone(), 100);
		let route = get_route(&our_id, &route_params, &network_graph.read_only(), None,
			Arc::clone(&logger), &scorer, &Default::default(), &random_seed_bytes).unwrap();
		assert_eq!(route.paths[0].hops.len(), 4);

		assert_eq!(route.paths[0].hops[0].pubkey, nodes[1]);
		assert_eq!(route.paths[0].hops[0].short_channel_id, 2);
		assert_eq!(route.paths[0].hops[0].fee_msat, 200); // fee increased as its % of value transferred across node
		assert_eq!(route.paths[0].hops[0].cltv_expiry_delta, (4 << 4) | 1);
		assert_eq!(route.paths[0].hops[0].node_features.le_flags(), &id_to_feature_flags(2));
		assert_eq!(route.paths[0].hops[0].channel_features.le_flags(), &id_to_feature_flags(2));

		assert_eq!(route.paths[0].hops[1].pubkey, nodes[2]);
		assert_eq!(route.paths[0].hops[1].short_channel_id, 4);
		assert_eq!(route.paths[0].hops[1].fee_msat, 100);
		assert_eq!(route.paths[0].hops[1].cltv_expiry_delta, (7 << 4) | 1);
		assert_eq!(route.paths[0].hops[1].node_features.le_flags(), &id_to_feature_flags(3));
		assert_eq!(route.paths[0].hops[1].channel_features.le_flags(), &id_to_feature_flags(4));

		assert_eq!(route.paths[0].hops[2].pubkey, nodes[5]);
		assert_eq!(route.paths[0].hops[2].short_channel_id, 7);
		assert_eq!(route.paths[0].hops[2].fee_msat, 0);
		assert_eq!(route.paths[0].hops[2].cltv_expiry_delta, (10 << 4) | 1);
		// If we have a peer in the node map, we'll use their features here since we don't have
		// a way of figuring out their features from the invoice:
		assert_eq!(route.paths[0].hops[2].node_features.le_flags(), &id_to_feature_flags(6));
		assert_eq!(route.paths[0].hops[2].channel_features.le_flags(), &id_to_feature_flags(7));

		assert_eq!(route.paths[0].hops[3].pubkey, nodes[6]);
		assert_eq!(route.paths[0].hops[3].short_channel_id, 10);
		assert_eq!(route.paths[0].hops[3].fee_msat, 100);
		assert_eq!(route.paths[0].hops[3].cltv_expiry_delta, 42);
		assert_eq!(route.paths[0].hops[3].node_features.le_flags(), default_node_features().le_flags()); // We dont pass flags in from invoices yet
		assert_eq!(route.paths[0].hops[3].channel_features.le_flags(), &Vec::<u8>::new()); // We can't learn any flags from invoices, sadly

		// ...but still use 8 for larger payments as 6 has a variable feerate
		let route_params = RouteParameters::from_payment_params_and_value(payment_params, 2000);
		let route = get_route(&our_id, &route_params, &network_graph.read_only(), None,
			Arc::clone(&logger), &scorer, &Default::default(), &random_seed_bytes).unwrap();
		assert_eq!(route.paths[0].hops.len(), 5);

		assert_eq!(route.paths[0].hops[0].pubkey, nodes[1]);
		assert_eq!(route.paths[0].hops[0].short_channel_id, 2);
		assert_eq!(route.paths[0].hops[0].fee_msat, 3000);
		assert_eq!(route.paths[0].hops[0].cltv_expiry_delta, (4 << 4) | 1);
		assert_eq!(route.paths[0].hops[0].node_features.le_flags(), &id_to_feature_flags(2));
		assert_eq!(route.paths[0].hops[0].channel_features.le_flags(), &id_to_feature_flags(2));

		assert_eq!(route.paths[0].hops[1].pubkey, nodes[2]);
		assert_eq!(route.paths[0].hops[1].short_channel_id, 4);
		assert_eq!(route.paths[0].hops[1].fee_msat, 0);
		assert_eq!(route.paths[0].hops[1].cltv_expiry_delta, (6 << 4) | 1);
		assert_eq!(route.paths[0].hops[1].node_features.le_flags(), &id_to_feature_flags(3));
		assert_eq!(route.paths[0].hops[1].channel_features.le_flags(), &id_to_feature_flags(4));

		assert_eq!(route.paths[0].hops[2].pubkey, nodes[4]);
		assert_eq!(route.paths[0].hops[2].short_channel_id, 6);
		assert_eq!(route.paths[0].hops[2].fee_msat, 0);
		assert_eq!(route.paths[0].hops[2].cltv_expiry_delta, (11 << 4) | 1);
		assert_eq!(route.paths[0].hops[2].node_features.le_flags(), &id_to_feature_flags(5));
		assert_eq!(route.paths[0].hops[2].channel_features.le_flags(), &id_to_feature_flags(6));

		assert_eq!(route.paths[0].hops[3].pubkey, nodes[3]);
		assert_eq!(route.paths[0].hops[3].short_channel_id, 11);
		assert_eq!(route.paths[0].hops[3].fee_msat, 1000);
		assert_eq!(route.paths[0].hops[3].cltv_expiry_delta, (8 << 4) | 1);
		// If we have a peer in the node map, we'll use their features here since we don't have
		// a way of figuring out their features from the invoice:
		assert_eq!(route.paths[0].hops[3].node_features.le_flags(), &id_to_feature_flags(4));
		assert_eq!(route.paths[0].hops[3].channel_features.le_flags(), &id_to_feature_flags(11));

		assert_eq!(route.paths[0].hops[4].pubkey, nodes[6]);
		assert_eq!(route.paths[0].hops[4].short_channel_id, 8);
		assert_eq!(route.paths[0].hops[4].fee_msat, 2000);
		assert_eq!(route.paths[0].hops[4].cltv_expiry_delta, 42);
		assert_eq!(route.paths[0].hops[4].node_features.le_flags(), default_node_features().le_flags()); // We dont pass flags in from invoices yet
		assert_eq!(route.paths[0].hops[4].channel_features.le_flags(), &Vec::<u8>::new()); // We can't learn any flags from invoices, sadly
	}

	#[rustfmt::skip]
	fn do_unannounced_path_test(last_hop_htlc_max: Option<u64>, last_hop_fee_prop: u32, outbound_capacity_msat: u64, route_val: u64) -> Result<Route, &'static str> {
		let source_node_id = PublicKey::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&<Vec<u8>>::from_hex(&format!("{:02}", 41).repeat(32)).unwrap()[..]).unwrap());
		let middle_node_id = PublicKey::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&<Vec<u8>>::from_hex(&format!("{:02}", 42).repeat(32)).unwrap()[..]).unwrap());
		let target_node_id = PublicKey::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&<Vec<u8>>::from_hex(&format!("{:02}", 43).repeat(32)).unwrap()[..]).unwrap());

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
		let payment_params = PaymentParameters::from_node_id(target_node_id, 42).with_route_hints(vec![last_hops]).unwrap();
		let our_chans = vec![get_channel_details(Some(42), middle_node_id, InitFeatures::from_le_bytes(vec![0b11]), outbound_capacity_msat)];
		let scorer = ln_test_utils::TestScorer::new();
		let random_seed_bytes = [42; 32];
		let logger = ln_test_utils::TestLogger::new();
		let network_graph = NetworkGraph::new(Network::Testnet, &logger);
		let route_params = RouteParameters::from_payment_params_and_value(payment_params, route_val);
		let route = get_route(&source_node_id, &route_params, &network_graph.read_only(),
				Some(&our_chans.iter().collect::<Vec<_>>()), &logger, &scorer, &Default::default(),
				&random_seed_bytes);
		route
	}

	#[test]
	#[rustfmt::skip]
	fn unannounced_path_test() {
		// We should be able to send a payment to a destination without any help of a routing graph
		// if we have a channel with a common counterparty that appears in the first and last hop
		// hints.
		let route = do_unannounced_path_test(None, 1, 2000000, 1000000).unwrap();

		let middle_node_id = PublicKey::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&<Vec<u8>>::from_hex(&format!("{:02}", 42).repeat(32)).unwrap()[..]).unwrap());
		let target_node_id = PublicKey::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&<Vec<u8>>::from_hex(&format!("{:02}", 43).repeat(32)).unwrap()[..]).unwrap());
		assert_eq!(route.paths[0].hops.len(), 2);

		assert_eq!(route.paths[0].hops[0].pubkey, middle_node_id);
		assert_eq!(route.paths[0].hops[0].short_channel_id, 42);
		assert_eq!(route.paths[0].hops[0].fee_msat, 1001);
		assert_eq!(route.paths[0].hops[0].cltv_expiry_delta, (8 << 4) | 1);
		assert_eq!(route.paths[0].hops[0].node_features.le_flags(), &[0b11]);
		assert_eq!(route.paths[0].hops[0].channel_features.le_flags(), &[0; 0]); // We can't learn any flags from invoices, sadly

		assert_eq!(route.paths[0].hops[1].pubkey, target_node_id);
		assert_eq!(route.paths[0].hops[1].short_channel_id, 8);
		assert_eq!(route.paths[0].hops[1].fee_msat, 1000000);
		assert_eq!(route.paths[0].hops[1].cltv_expiry_delta, 42);
		assert_eq!(route.paths[0].hops[1].node_features.le_flags(), default_node_features().le_flags()); // We dont pass flags in from invoices yet
		assert_eq!(route.paths[0].hops[1].channel_features.le_flags(), &[0; 0]); // We can't learn any flags from invoices, sadly
	}

	#[test]
	#[rustfmt::skip]
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
	#[rustfmt::skip]
	fn overflow_unannounced_path_test_feerate_overflow() {
		// This tests for the same case as above, except instead of hitting a subtraction
		// underflow, we hit a case where the fee charged at a hop overflowed.
		assert!(do_unannounced_path_test(Some(21_000_000_0000_0000_000), 50000, 21_000_000_0000_0000_000, 21_000_000_0000_0000_000).is_err());
	}

	#[test]
	#[rustfmt::skip]
	fn available_amount_while_routing_test() {
		// Tests whether we choose the correct available channel amount while routing.

		let (secp_ctx, network_graph, gossip_sync, chain_monitor, logger) = build_graph();
		let (our_privkey, our_id, privkeys, nodes) = get_nodes(&secp_ctx);
		let scorer = ln_test_utils::TestScorer::new();
		let random_seed_bytes = [42; 32];
		let config = UserConfig::default();
		let payment_params = PaymentParameters::from_node_id(nodes[2], 42)
			.with_bolt11_features(channelmanager::provided_bolt11_invoice_features(&config))
			.unwrap();

		// We will use a simple single-path route from
		// our node to node2 via node0: channels {1, 3}.

		// First disable all other paths.
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 2,
			timestamp: 2,
			message_flags: 1, // Only must_be_one
			channel_flags: 2,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 100_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 12,
			timestamp: 2,
			message_flags: 1, // Only must_be_one
			channel_flags: 2,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 100_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		// Make the first channel (#1) very permissive,
		// and we will be testing all limits on the second channel.
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 1,
			timestamp: 2,
			message_flags: 1, // Only must_be_one
			channel_flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 1_000_000_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		// First, let's see if routing works if we have absolutely no idea about the available amount.
		// In this case, it should be set to 250_000 sats.
		update_channel(&gossip_sync, &secp_ctx, &privkeys[0], UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 3,
			timestamp: 2,
			message_flags: 1, // Only must_be_one
			channel_flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 250_000_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		{
			// Attempt to route more than available results in a failure.
			let route_params = RouteParameters::from_payment_params_and_value(
				payment_params.clone(), 250_000_001);
			if let Err(err) = get_route(
					&our_id, &route_params, &network_graph.read_only(), None,
					Arc::clone(&logger), &scorer, &Default::default(), &random_seed_bytes) {
						assert_eq!(err, "Failed to find a sufficient route to the given destination");
			} else { panic!(); }
		}

		{
			// Now, attempt to route an exact amount we have should be fine.
			let route_params = RouteParameters::from_payment_params_and_value(
				payment_params.clone(), 250_000_000);
			let route = get_route(&our_id, &route_params, &network_graph.read_only(), None,
				Arc::clone(&logger), &scorer, &Default::default(), &random_seed_bytes).unwrap();
			assert_eq!(route.paths.len(), 1);
			let path = route.paths.last().unwrap();
			assert_eq!(path.hops.len(), 2);
			assert_eq!(path.hops.last().unwrap().pubkey, nodes[2]);
			assert_eq!(path.final_value_msat(), 250_000_000);
		}

		// Check that setting next_outbound_htlc_limit_msat in first_hops limits the channels.
		// Disable channel #1 and use another first hop.
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 1,
			timestamp: 3,
			message_flags: 1, // Only must_be_one
			channel_flags: 2,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 1_000_000_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		// Now, limit the first_hop by the next_outbound_htlc_limit_msat of 200_000 sats.
		let our_chans = vec![get_channel_details(Some(42), nodes[0].clone(), InitFeatures::from_le_bytes(vec![0b11]), 200_000_000)];

		{
			// Attempt to route more than available results in a failure.
			let route_params = RouteParameters::from_payment_params_and_value(
				payment_params.clone(), 200_000_001);
			if let Err(err) = get_route(
					&our_id, &route_params, &network_graph.read_only(),
					Some(&our_chans.iter().collect::<Vec<_>>()), Arc::clone(&logger), &scorer,
					&Default::default(), &random_seed_bytes) {
						assert_eq!(err, "Failed to find a sufficient route to the given destination");
			} else { panic!(); }
		}

		{
			// Now, attempt to route an exact amount we have should be fine.
			let route_params = RouteParameters::from_payment_params_and_value(
				payment_params.clone(), 200_000_000);
			let route = get_route(&our_id, &route_params, &network_graph.read_only(),
				Some(&our_chans.iter().collect::<Vec<_>>()), Arc::clone(&logger), &scorer,
				&Default::default(), &random_seed_bytes).unwrap();
			assert_eq!(route.paths.len(), 1);
			let path = route.paths.last().unwrap();
			assert_eq!(path.hops.len(), 2);
			assert_eq!(path.hops.last().unwrap().pubkey, nodes[2]);
			assert_eq!(path.final_value_msat(), 200_000_000);
		}

		// Enable channel #1 back.
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 1,
			timestamp: 4,
			message_flags: 1, // Only must_be_one
			channel_flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 1_000_000_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});


		// Now let's see if routing works if we know only htlc_maximum_msat.
		update_channel(&gossip_sync, &secp_ctx, &privkeys[0], UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 3,
			timestamp: 3,
			message_flags: 1, // Only must_be_one
			channel_flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 15_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		{
			// Attempt to route more than available results in a failure.
			let route_params = RouteParameters::from_payment_params_and_value(
				payment_params.clone(), 15_001);
			if let Err(err) = get_route(
					&our_id, &route_params, &network_graph.read_only(), None, Arc::clone(&logger),
					&scorer, &Default::default(), &random_seed_bytes) {
						assert_eq!(err, "Failed to find a sufficient route to the given destination");
			} else { panic!(); }
		}

		{
			// Now, attempt to route an exact amount we have should be fine.
			let route_params = RouteParameters::from_payment_params_and_value(
				payment_params.clone(), 15_000);
			let route = get_route(&our_id, &route_params, &network_graph.read_only(), None,
				Arc::clone(&logger), &scorer, &Default::default(), &random_seed_bytes).unwrap();
			assert_eq!(route.paths.len(), 1);
			let path = route.paths.last().unwrap();
			assert_eq!(path.hops.len(), 2);
			assert_eq!(path.hops.last().unwrap().pubkey, nodes[2]);
			assert_eq!(path.final_value_msat(), 15_000);
		}

		// Now let's see if routing works if we know only capacity from the UTXO.

		// We can't change UTXO capacity on the fly, so we'll disable
		// the existing channel and add another one with the capacity we need.
		update_channel(&gossip_sync, &secp_ctx, &privkeys[0], UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 3,
			timestamp: 4,
			message_flags: 1, // Only must_be_one
			channel_flags: 2,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		let good_script = Builder::new().push_opcode(opcodes::all::OP_PUSHNUM_2)
		.push_slice(&PublicKey::from_secret_key(&secp_ctx, &privkeys[0]).serialize())
		.push_slice(&PublicKey::from_secret_key(&secp_ctx, &privkeys[2]).serialize())
		.push_opcode(opcodes::all::OP_PUSHNUM_2)
		.push_opcode(opcodes::all::OP_CHECKMULTISIG).into_script().to_p2wsh();

		*chain_monitor.utxo_ret.lock().unwrap() =
			UtxoResult::Sync(Ok(TxOut { value: Amount::from_sat(15), script_pubkey: good_script.clone() }));
		gossip_sync.add_utxo_lookup(Some(chain_monitor));

		add_channel(&gossip_sync, &secp_ctx, &privkeys[0], &privkeys[2], ChannelFeatures::from_le_bytes(id_to_feature_flags(3)), 333);
		update_channel(&gossip_sync, &secp_ctx, &privkeys[0], UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 333,
			timestamp: 1,
			message_flags: 1, // Only must_be_one
			channel_flags: 0,
			cltv_expiry_delta: (3 << 4) | 1,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 15_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 333,
			timestamp: 1,
			message_flags: 1, // Only must_be_one
			channel_flags: 1,
			cltv_expiry_delta: (3 << 4) | 2,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 15_000,
			fee_base_msat: 100,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		{
			// Attempt to route more than available results in a failure.
			let route_params = RouteParameters::from_payment_params_and_value(
				payment_params.clone(), 15_001);
			if let Err(err) = get_route(
					&our_id, &route_params, &network_graph.read_only(), None, Arc::clone(&logger),
					&scorer, &Default::default(), &random_seed_bytes) {
						assert_eq!(err, "Failed to find a sufficient route to the given destination");
			} else { panic!(); }
		}

		{
			// Now, attempt to route an exact amount we have should be fine.
			let route_params = RouteParameters::from_payment_params_and_value(
				payment_params.clone(), 15_000);
			let route = get_route(&our_id, &route_params, &network_graph.read_only(), None,
				Arc::clone(&logger), &scorer, &Default::default(), &random_seed_bytes).unwrap();
			assert_eq!(route.paths.len(), 1);
			let path = route.paths.last().unwrap();
			assert_eq!(path.hops.len(), 2);
			assert_eq!(path.hops.last().unwrap().pubkey, nodes[2]);
			assert_eq!(path.final_value_msat(), 15_000);
		}

		// Now let's see if routing chooses htlc_maximum_msat over UTXO capacity.
		update_channel(&gossip_sync, &secp_ctx, &privkeys[0], UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 333,
			timestamp: 6,
			message_flags: 1, // Only must_be_one
			channel_flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 10_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		{
			// Attempt to route more than available results in a failure.
			let route_params = RouteParameters::from_payment_params_and_value(
				payment_params.clone(), 10_001);
			if let Err(err) = get_route(
					&our_id, &route_params, &network_graph.read_only(), None, Arc::clone(&logger),
					&scorer, &Default::default(), &random_seed_bytes) {
						assert_eq!(err, "Failed to find a sufficient route to the given destination");
			} else { panic!(); }
		}

		{
			// Now, attempt to route an exact amount we have should be fine.
			let route_params = RouteParameters::from_payment_params_and_value(
				payment_params.clone(), 10_000);
			let route = get_route(&our_id, &route_params, &network_graph.read_only(), None,
				Arc::clone(&logger), &scorer, &Default::default(), &random_seed_bytes).unwrap();
			assert_eq!(route.paths.len(), 1);
			let path = route.paths.last().unwrap();
			assert_eq!(path.hops.len(), 2);
			assert_eq!(path.hops.last().unwrap().pubkey, nodes[2]);
			assert_eq!(path.final_value_msat(), 10_000);
		}
	}

	#[test]
	#[rustfmt::skip]
	fn available_liquidity_last_hop_test() {
		// Check that available liquidity properly limits the path even when only
		// one of the latter hops is limited.
		let (secp_ctx, network_graph, gossip_sync, _, logger) = build_graph();
		let (our_privkey, our_id, privkeys, nodes) = get_nodes(&secp_ctx);
		let scorer = ln_test_utils::TestScorer::new();
		let random_seed_bytes = [42; 32];
		let config = UserConfig::default();
		let payment_params = PaymentParameters::from_node_id(nodes[3], 42)
			.with_bolt11_features(channelmanager::provided_bolt11_invoice_features(&config))
			.unwrap();

		// Path via {node7, node2, node4} is channels {12, 13, 6, 11}.
		// {12, 13, 11} have the capacities of 100, {6} has a capacity of 50.
		// Total capacity: 50 sats.

		// Disable other potential paths.
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 2,
			timestamp: 2,
			message_flags: 1, // Only must_be_one
			channel_flags: 2,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 100_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 7,
			timestamp: 2,
			message_flags: 1, // Only must_be_one
			channel_flags: 2,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 100_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		// Limit capacities

		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 12,
			timestamp: 2,
			message_flags: 1, // Only must_be_one
			channel_flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 100_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[7], UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 13,
			timestamp: 2,
			message_flags: 1, // Only must_be_one
			channel_flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 100_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		update_channel(&gossip_sync, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 6,
			timestamp: 2,
			message_flags: 1, // Only must_be_one
			channel_flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 50_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[4], UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 11,
			timestamp: 2,
			message_flags: 1, // Only must_be_one
			channel_flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 100_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		{
			// Attempt to route more than available results in a failure.
			let route_params = RouteParameters::from_payment_params_and_value(
				payment_params.clone(), 60_000);
			if let Err(err) = get_route(
					&our_id, &route_params, &network_graph.read_only(), None, Arc::clone(&logger),
					&scorer, &Default::default(), &random_seed_bytes) {
						assert_eq!(err, "Failed to find a sufficient route to the given destination");
			} else { panic!(); }
		}

		{
			// Now, attempt to route 49 sats (just a bit below the capacity).
			let route_params = RouteParameters::from_payment_params_and_value(
				payment_params.clone(), 49_000);
			let route = get_route(&our_id, &route_params, &network_graph.read_only(), None,
				Arc::clone(&logger), &scorer, &Default::default(), &random_seed_bytes).unwrap();
			assert_eq!(route.paths.len(), 1);
			let mut total_amount_paid_msat = 0;
			for path in &route.paths {
				assert_eq!(path.hops.len(), 4);
				assert_eq!(path.hops.last().unwrap().pubkey, nodes[3]);
				total_amount_paid_msat += path.final_value_msat();
			}
			assert_eq!(total_amount_paid_msat, 49_000);
		}

		{
			// Attempt to route an exact amount is also fine
			let route_params = RouteParameters::from_payment_params_and_value(
				payment_params, 50_000);
			let route = get_route(&our_id, &route_params, &network_graph.read_only(), None,
				Arc::clone(&logger), &scorer, &Default::default(), &random_seed_bytes).unwrap();
			assert_eq!(route.paths.len(), 1);
			let mut total_amount_paid_msat = 0;
			for path in &route.paths {
				assert_eq!(path.hops.len(), 4);
				assert_eq!(path.hops.last().unwrap().pubkey, nodes[3]);
				total_amount_paid_msat += path.final_value_msat();
			}
			assert_eq!(total_amount_paid_msat, 50_000);
		}
	}

	#[test]
	#[rustfmt::skip]
	fn ignore_fee_first_hop_test() {
		let (secp_ctx, network_graph, gossip_sync, _, logger) = build_graph();
		let (our_privkey, our_id, privkeys, nodes) = get_nodes(&secp_ctx);
		let scorer = ln_test_utils::TestScorer::new();
		let random_seed_bytes = [42; 32];
		let payment_params = PaymentParameters::from_node_id(nodes[2], 42);

		// Path via node0 is channels {1, 3}. Limit them to 100 and 50 sats (total limit 50).
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 1,
			timestamp: 2,
			message_flags: 1, // Only must_be_one
			channel_flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 100_000,
			fee_base_msat: 1_000_000,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[0], UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 3,
			timestamp: 2,
			message_flags: 1, // Only must_be_one
			channel_flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 50_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		{
			let route_params = RouteParameters::from_payment_params_and_value(
				payment_params, 50_000);
			let route = get_route(&our_id, &route_params, &network_graph.read_only(), None,
				Arc::clone(&logger), &scorer, &Default::default(), &random_seed_bytes).unwrap();
			assert_eq!(route.paths.len(), 1);
			let mut total_amount_paid_msat = 0;
			for path in &route.paths {
				assert_eq!(path.hops.len(), 2);
				assert_eq!(path.hops.last().unwrap().pubkey, nodes[2]);
				total_amount_paid_msat += path.final_value_msat();
			}
			assert_eq!(total_amount_paid_msat, 50_000);
		}
	}

	#[test]
	#[rustfmt::skip]
	fn simple_mpp_route_test() {
		let (secp_ctx, _, _, _, _) = build_graph();
		let (_, _, _, nodes) = get_nodes(&secp_ctx);
		let config = UserConfig::default();
		let clear_payment_params = PaymentParameters::from_node_id(nodes[2], 42)
			.with_bolt11_features(channelmanager::provided_bolt11_invoice_features(&config))
			.unwrap();
		do_simple_mpp_route_test(clear_payment_params);

		// MPP to a 1-hop blinded path for nodes[2]
		let bolt12_features = channelmanager::provided_bolt12_invoice_features(&config);
		let blinded_payinfo = BlindedPayInfo { // These fields are ignored for 1-hop blinded paths
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 0,
			cltv_expiry_delta: 0,
			features: BlindedHopFeatures::empty(),
		};
		let blinded_path = dummy_one_hop_blinded_path(nodes[2], blinded_payinfo.clone());
		let one_hop_blinded_payment_params = PaymentParameters::blinded(vec![blinded_path.clone()])
			.with_bolt12_features(bolt12_features.clone()).unwrap();
		do_simple_mpp_route_test(one_hop_blinded_payment_params.clone());

		// MPP to 3 2-hop blinded paths
		let mut node_0_payinfo = blinded_payinfo.clone();
		node_0_payinfo.htlc_maximum_msat = 50_000;
		let blinded_path_node_0 = dummy_blinded_path(nodes[0], node_0_payinfo);

		let mut node_7_payinfo = blinded_payinfo.clone();
		node_7_payinfo.htlc_maximum_msat = 60_000;
		let blinded_path_node_7 = dummy_blinded_path(nodes[7], node_7_payinfo);

		let mut node_1_payinfo = blinded_payinfo;
		node_1_payinfo.htlc_maximum_msat = 180_000;
		let blinded_path_node_1 = dummy_blinded_path(nodes[1], node_1_payinfo);

		let two_hop_blinded_payment_params = PaymentParameters::blinded(
			vec![blinded_path_node_0, blinded_path_node_7, blinded_path_node_1])
			.with_bolt12_features(bolt12_features).unwrap();
		do_simple_mpp_route_test(two_hop_blinded_payment_params);
	}

	#[rustfmt::skip]
	fn do_simple_mpp_route_test(payment_params: PaymentParameters) {
		let (secp_ctx, network_graph, gossip_sync, _, logger) = build_graph();
		let (our_privkey, our_id, privkeys, nodes) = get_nodes(&secp_ctx);
		let scorer = ln_test_utils::TestScorer::new();
		let random_seed_bytes = [42; 32];

		// We need a route consisting of 3 paths:
		// From our node to node2 via node0, node7, node1 (three paths one hop each).
		// To achieve this, the amount being transferred should be around
		// the total capacity of these 3 paths.

		// First, we set limits on these (previously unlimited) channels.
		// Their aggregate capacity will be 50 + 60 + 180 = 290 sats.

		// Path via node0 is channels {1, 3}. Limit them to 100 and 50 sats (total limit 50).
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 1,
			timestamp: 2,
			message_flags: 1, // Only must_be_one
			channel_flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 100_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[0], UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 3,
			timestamp: 2,
			message_flags: 1, // Only must_be_one
			channel_flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 50_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		// Path via node7 is channels {12, 13}. Limit them to 60 and 60 sats
		// (total limit 60).
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 12,
			timestamp: 2,
			message_flags: 1, // Only must_be_one
			channel_flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 60_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[7], UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 13,
			timestamp: 2,
			message_flags: 1, // Only must_be_one
			channel_flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 60_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		// Path via node1 is channels {2, 4}. Limit them to 200 and 180 sats
		// (total capacity 180 sats).
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 2,
			timestamp: 2,
			message_flags: 1, // Only must_be_one
			channel_flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 200_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[1], UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 4,
			timestamp: 2,
			message_flags: 1, // Only must_be_one
			channel_flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 180_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		{
			// Attempt to route more than available results in a failure.
			let route_params = RouteParameters::from_payment_params_and_value(
				payment_params.clone(), 300_000);
			if let Err(err) = get_route(
				&our_id, &route_params, &network_graph.read_only(), None,
				Arc::clone(&logger), &scorer, &Default::default(), &random_seed_bytes) {
					assert_eq!(err, "Failed to find a sufficient route to the given destination");
			} else { panic!(); }
		}

		{
			// Attempt to route while setting max_path_count to 0 results in a failure.
			let zero_payment_params = payment_params.clone().with_max_path_count(0);
			let route_params = RouteParameters::from_payment_params_and_value(
				zero_payment_params, 100);
			if let Err(err) = get_route(
				&our_id, &route_params, &network_graph.read_only(), None,
				Arc::clone(&logger), &scorer, &Default::default(), &random_seed_bytes) {
					assert_eq!(err, "Can't find a route with no paths allowed.");
			} else { panic!(); }
		}

		{
			// Attempt to route while setting max_path_count to 3 results in a failure.
			// This is the case because the minimal_value_contribution_msat would require each path
			// to account for 1/3 of the total value, which is violated by 2 out of 3 paths.
			let fail_payment_params = payment_params.clone().with_max_path_count(3);
			let route_params = RouteParameters::from_payment_params_and_value(
				fail_payment_params, 250_000);
			if let Err(err) = get_route(
				&our_id, &route_params, &network_graph.read_only(), None,
				Arc::clone(&logger), &scorer, &Default::default(), &random_seed_bytes) {
					assert_eq!(err, "Failed to find a sufficient route to the given destination");
			} else { panic!(); }
		}

		{
			// Now, attempt to route 250 sats (just a bit below the capacity).
			// Our algorithm should provide us with these 3 paths.
			let route_params = RouteParameters::from_payment_params_and_value(
				payment_params.clone(), 250_000);
			let route = get_route(&our_id, &route_params, &network_graph.read_only(), None,
				Arc::clone(&logger), &scorer, &Default::default(), &random_seed_bytes).unwrap();
			assert_eq!(route.paths.len(), 3);
			let mut total_amount_paid_msat = 0;
			for path in &route.paths {
				if let Some(bt) = &path.blinded_tail {
					assert_eq!(path.hops.len() + if bt.hops.len() == 1 { 0 } else { 1 }, 2);
				} else {
					assert_eq!(path.hops.len(), 2);
					assert_eq!(path.hops.last().unwrap().pubkey, nodes[2]);
				}
				total_amount_paid_msat += path.final_value_msat();
			}
			assert_eq!(total_amount_paid_msat, 250_000);
		}

		{
			// Attempt to route an exact amount is also fine
			let route_params = RouteParameters::from_payment_params_and_value(
				payment_params.clone(), 290_000);
			let route = get_route(&our_id, &route_params, &network_graph.read_only(), None,
				Arc::clone(&logger), &scorer, &Default::default(), &random_seed_bytes).unwrap();
			assert_eq!(route.paths.len(), 3);
			let mut total_amount_paid_msat = 0;
			for path in &route.paths {
				if payment_params.payee.blinded_route_hints().len() != 0 {
					assert!(path.blinded_tail.is_some()) } else { assert!(path.blinded_tail.is_none()) }
				if let Some(bt) = &path.blinded_tail {
					assert_eq!(path.hops.len() + if bt.hops.len() == 1 { 0 } else { 1 }, 2);
					if bt.hops.len() > 1 {
						let network_graph = network_graph.read_only();
						assert_eq!(
							NodeId::from_pubkey(&path.hops.last().unwrap().pubkey),
							payment_params.payee.blinded_route_hints().iter()
								.find(|p| p.payinfo.htlc_maximum_msat == path.final_value_msat())
								.and_then(|p| p.public_introduction_node_id(&network_graph))
								.copied()
								.unwrap()
						);
					} else {
						assert_eq!(path.hops.last().unwrap().pubkey, nodes[2]);
					}
				} else {
					assert_eq!(path.hops.len(), 2);
					assert_eq!(path.hops.last().unwrap().pubkey, nodes[2]);
				}
				total_amount_paid_msat += path.final_value_msat();
			}
			assert_eq!(total_amount_paid_msat, 290_000);
		}
	}

	#[test]
	fn mpp_tests() {
		let secp_ctx = Secp256k1::new();
		let (_, _, _, nodes) = get_nodes(&secp_ctx);
		{
			// Check that if we have two cheaper paths and a more expensive (fewer hops) path, we
			// choose the two cheaper paths:
			let route = do_mpp_route_tests(180_000).unwrap();
			assert_eq!(route.paths.len(), 2);

			let mut total_value_transferred_msat = 0;
			let mut total_paid_msat = 0;
			for path in &route.paths {
				assert_eq!(path.hops.last().unwrap().pubkey, nodes[3]);
				total_value_transferred_msat += path.final_value_msat();
				for hop in &path.hops {
					total_paid_msat += hop.fee_msat;
				}
			}
			// If we paid fee, this would be higher.
			assert_eq!(total_value_transferred_msat, 180_000);
			let total_fees_paid = total_paid_msat - total_value_transferred_msat;
			assert_eq!(total_fees_paid, 0);
		}
		{
			// Check that if we use the same channels but need to send more than we could fit in
			// the cheaper paths we select all three paths:
			let route = do_mpp_route_tests(300_000).unwrap();
			assert_eq!(route.paths.len(), 3);

			let mut total_amount_paid_msat = 0;
			for path in &route.paths {
				assert_eq!(path.hops.last().unwrap().pubkey, nodes[3]);
				total_amount_paid_msat += path.final_value_msat();
			}
			assert_eq!(total_amount_paid_msat, 300_000);
		}
		// Check that trying to pay more than our available liquidity fails.
		assert!(do_mpp_route_tests(300_001).is_err());
	}

	#[rustfmt::skip]
	fn do_mpp_route_tests(amt: u64) -> Result<Route, &'static str> {
		let (secp_ctx, network_graph, gossip_sync, _, logger) = build_graph();
		let (our_privkey, our_id, privkeys, nodes) = get_nodes(&secp_ctx);
		let scorer = ln_test_utils::TestScorer::new();
		let random_seed_bytes = [42; 32];
		let config = UserConfig::default();
		let payment_params = PaymentParameters::from_node_id(nodes[3], 42)
			.with_bolt11_features(channelmanager::provided_bolt11_invoice_features(&config))
			.unwrap();

		// Build a setup where we have three potential paths from us to node3:
		//  {node0, node2, node4} (channels 1, 3, 6, 11), fee 0 msat,
		//  {node7, node2, node4} (channels 12, 13, 6, 11), fee 0 msat, and
		//  {node1} (channel 2, then a new channel 16), fee 1000 msat.
		// Note that these paths overlap on channels 6 and 11.
		// Each channel will have 100 sats capacity except for 6 and 11, which have 200.

		// Disable other potential paths.
		update_channel(&gossip_sync, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 7,
			timestamp: 2,
			message_flags: 1, // Only must_be_one
			channel_flags: 2,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 100_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[1], UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 4,
			timestamp: 2,
			message_flags: 1, // Only must_be_one
			channel_flags: 2,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 100_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		// Path via {node0, node2} is channels {1, 3, 5}.
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 1,
			timestamp: 2,
			message_flags: 1, // Only must_be_one
			channel_flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 100_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[0], UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 3,
			timestamp: 2,
			message_flags: 1, // Only must_be_one
			channel_flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 100_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		add_channel(&gossip_sync, &secp_ctx, &privkeys[1], &privkeys[3], ChannelFeatures::from_le_bytes(id_to_feature_flags(16)), 16);
		update_channel(&gossip_sync, &secp_ctx, &privkeys[1], UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 16,
			timestamp: 2,
			message_flags: 1, // Only must_be_one
			channel_flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 100_000,
			fee_base_msat: 1_000,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[3], UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 16,
			timestamp: 2,
			message_flags: 1, // Only must_be_one
			channel_flags: 3, // disable direction 1
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 100_000,
			fee_base_msat: 1_000,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		// Path via {node7, node2, node4} is channels {12, 13, 6, 11}.
		// Add 100 sats to the capacities of {12, 13}, because these channels
		// are also used for 3rd path. 100 sats for the rest. Total capacity: 100 sats.
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 12,
			timestamp: 2,
			message_flags: 1, // Only must_be_one
			channel_flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 100_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[7], UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 13,
			timestamp: 2,
			message_flags: 1, // Only must_be_one
			channel_flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 100_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		update_channel(&gossip_sync, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 6,
			timestamp: 2,
			message_flags: 1, // Only must_be_one
			channel_flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 200_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[4], UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 11,
			timestamp: 2,
			message_flags: 1, // Only must_be_one
			channel_flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 200_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		// Path via {node7, node2} is channels {12, 13, 5}.
		// We already limited them to 200 sats (they are used twice for 100 sats).
		// Nothing to do here.

		let route_params = RouteParameters::from_payment_params_and_value(
			payment_params, amt);
		let res = get_route(&our_id, &route_params, &network_graph.read_only(), None,
			Arc::clone(&logger), &scorer, &Default::default(), &random_seed_bytes);
		res
	}

	#[test]
	#[rustfmt::skip]
	fn fees_on_mpp_route_test() {
		// This test makes sure that MPP algorithm properly takes into account
		// fees charged on the channels, by making the fees impactful:
		// if the fee is not properly accounted for, the behavior is different.
		let (secp_ctx, network_graph, gossip_sync, _, logger) = build_graph();
		let (our_privkey, our_id, privkeys, nodes) = get_nodes(&secp_ctx);
		let scorer = ln_test_utils::TestScorer::new();
		let random_seed_bytes = [42; 32];
		let config = UserConfig::default();
		let payment_params = PaymentParameters::from_node_id(nodes[3], 42)
			.with_bolt11_features(channelmanager::provided_bolt11_invoice_features(&config))
			.unwrap();

		// We need a route consisting of 2 paths:
		// From our node to node3 via {node0, node2} and {node7, node2, node4}.
		// We will route 200 sats, Each path will have 100 sats capacity.

		// This test is not particularly stable: e.g.,
		// there's a way to route via {node0, node2, node4}.
		// It works while pathfinding is deterministic, but can be broken otherwise.
		// It's fine to ignore this concern for now.

		// Disable other potential paths.
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 2,
			timestamp: 2,
			message_flags: 1, // Only must_be_one
			channel_flags: 2,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 100_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		update_channel(&gossip_sync, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 7,
			timestamp: 2,
			message_flags: 1, // Only must_be_one
			channel_flags: 2,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 100_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		// Path via {node0, node2} is channels {1, 3, 5}.
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 1,
			timestamp: 2,
			message_flags: 1, // Only must_be_one
			channel_flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 100_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[0], UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 3,
			timestamp: 2,
			message_flags: 1, // Only must_be_one
			channel_flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 100_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		add_channel(&gossip_sync, &secp_ctx, &privkeys[2], &privkeys[3], ChannelFeatures::from_le_bytes(id_to_feature_flags(5)), 5);
		update_channel(&gossip_sync, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 5,
			timestamp: 2,
			message_flags: 1, // Only must_be_one
			channel_flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 100_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[3], UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 5,
			timestamp: 2,
			message_flags: 1, // Only must_be_one
			channel_flags: 3, // Disable direction 1
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 100_000,
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
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 12,
			timestamp: 2,
			message_flags: 1, // Only must_be_one
			channel_flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 250_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[7], UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 13,
			timestamp: 2,
			message_flags: 1, // Only must_be_one
			channel_flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		update_channel(&gossip_sync, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 6,
			timestamp: 2,
			message_flags: 1, // Only must_be_one
			channel_flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 150_000,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[4], UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 11,
			timestamp: 2,
			message_flags: 1, // Only must_be_one
			channel_flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		{
			// Attempt to route more than available results in a failure.
			let route_params = RouteParameters::from_payment_params_and_value(
				payment_params.clone(), 210_000);
			if let Err(err) = get_route(
					&our_id, &route_params, &network_graph.read_only(), None, Arc::clone(&logger),
					&scorer, &Default::default(), &random_seed_bytes) {
						assert_eq!(err, "Failed to find a sufficient route to the given destination");
			} else { panic!(); }
		}

		{
			// Attempt to route while setting max_total_routing_fee_msat to 149_999 results in a failure.
			let route_params = RouteParameters { payment_params: payment_params.clone(), final_value_msat: 200_000,
				max_total_routing_fee_msat: Some(149_999) };
			if let Err(err) = get_route(
				&our_id, &route_params, &network_graph.read_only(), None, Arc::clone(&logger),
				&scorer, &Default::default(), &random_seed_bytes) {
					assert_eq!(err, "Failed to find a sufficient route to the given destination");
			} else { panic!(); }
		}

		{
			// Now, attempt to route 200 sats (exact amount we can route).
			let route_params = RouteParameters { payment_params: payment_params.clone(), final_value_msat: 200_000,
				max_total_routing_fee_msat: Some(150_000) };
			let route = get_route(&our_id, &route_params, &network_graph.read_only(), None,
				Arc::clone(&logger), &scorer, &Default::default(), &random_seed_bytes).unwrap();
			assert_eq!(route.paths.len(), 2);

			let mut total_amount_paid_msat = 0;
			for path in &route.paths {
				assert_eq!(path.hops.last().unwrap().pubkey, nodes[3]);
				total_amount_paid_msat += path.final_value_msat();
			}
			assert_eq!(total_amount_paid_msat, 200_000);
			assert_eq!(route.get_total_fees(), 150_000);
		}
	}

	#[test]
	#[rustfmt::skip]
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
		let (secp_ctx, network_graph, gossip_sync, _, logger) = build_graph();
		let (our_privkey, our_id, privkeys, nodes) = get_nodes(&secp_ctx);
		let scorer = ln_test_utils::TestScorer::new();
		let random_seed_bytes = [42; 32];
		let config = UserConfig::default();
		let payment_params = PaymentParameters::from_node_id(PublicKey::from_slice(&[2; 33]).unwrap(), 42)
			.with_bolt11_features(channelmanager::provided_bolt11_invoice_features(&config)).unwrap()
			.with_route_hints(vec![RouteHint(vec![RouteHintHop {
				src_node_id: nodes[2],
				short_channel_id: 42,
				fees: RoutingFees { base_msat: 0, proportional_millionths: 0 },
				cltv_expiry_delta: 42,
				htlc_minimum_msat: None,
				htlc_maximum_msat: None,
			}])]).unwrap().with_max_channel_saturation_power_of_half(0);

		// Keep only two paths from us to nodes[2], both with a 99sat HTLC maximum, with one with
		// no fee and one with a 1msat fee. Previously, trying to route 100 sats to nodes[2] here
		// would first use the no-fee route and then fail to find a path along the second route as
		// we think we can only send up to 1 additional sat over the last-hop but refuse to as its
		// under 5% of our payment amount.
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 1,
			timestamp: 2,
			message_flags: 1, // Only must_be_one
			channel_flags: 0,
			cltv_expiry_delta: (5 << 4) | 5,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 99_000,
			fee_base_msat: u32::max_value(),
			fee_proportional_millionths: u32::max_value(),
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 2,
			timestamp: 2,
			message_flags: 1, // Only must_be_one
			channel_flags: 0,
			cltv_expiry_delta: (5 << 4) | 3,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 99_000,
			fee_base_msat: u32::max_value(),
			fee_proportional_millionths: u32::max_value(),
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[1], UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 4,
			timestamp: 2,
			message_flags: 1, // Only must_be_one
			channel_flags: 0,
			cltv_expiry_delta: (4 << 4) | 1,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 1,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[7], UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 13,
			timestamp: 2,
			message_flags: 1, // Only must_be_one
			channel_flags: 0|2, // Channel disabled
			cltv_expiry_delta: (13 << 4) | 1,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,
			fee_proportional_millionths: 2000000,
			excess_data: Vec::new()
		});

		// Get a route for 100 sats and check that we found the MPP route no problem and didn't
		// overpay at all.
		let route_params = RouteParameters::from_payment_params_and_value(
			payment_params, 100_000);
		let mut route = get_route(&our_id, &route_params, &network_graph.read_only(), None,
			Arc::clone(&logger), &scorer, &Default::default(), &random_seed_bytes).unwrap();
		assert_eq!(route.paths.len(), 2);
		route.paths.sort_by_key(|path| path.hops[0].short_channel_id);
		// Paths are manually ordered ordered by SCID, so:
		// * the first is channel 1 (0 fee, but 99 sat maximum) -> channel 3 -> channel 42
		// * the second is channel 2 (1 msat fee) -> channel 4 -> channel 42
		assert_eq!(route.paths[0].hops[0].short_channel_id, 1);
		assert_eq!(route.paths[0].hops[0].fee_msat, 0);
		assert_eq!(route.paths[0].hops[2].fee_msat, 99_000);
		assert_eq!(route.paths[1].hops[0].short_channel_id, 2);
		assert_eq!(route.paths[1].hops[0].fee_msat, 1);
		assert_eq!(route.paths[1].hops[2].fee_msat, 1_000);
		assert_eq!(route.get_total_fees(), 1);
		assert_eq!(route.get_total_amount(), 100_000);
	}

	#[test]
	#[rustfmt::skip]
	fn drop_lowest_channel_mpp_route_test() {
		// This test checks that low-capacity channel is dropped when after
		// path finding we realize that we found more capacity than we need.
		let (secp_ctx, network_graph, gossip_sync, _, logger) = build_graph();
		let (our_privkey, our_id, privkeys, nodes) = get_nodes(&secp_ctx);
		let scorer = ln_test_utils::TestScorer::new();
		let random_seed_bytes = [42; 32];
		let config = UserConfig::default();
		let payment_params = PaymentParameters::from_node_id(nodes[2], 42)
			.with_bolt11_features(channelmanager::provided_bolt11_invoice_features(&config))
			.unwrap()
			.with_max_channel_saturation_power_of_half(0);

		// We need a route consisting of 3 paths:
		// From our node to node2 via node0, node7, node1 (three paths one hop each).

		// The first and the second paths should be sufficient, but the third should be
		// cheaper, so that we select it but drop later.

		// First, we set limits on these (previously unlimited) channels.
		// Their aggregate capacity will be 50 + 60 + 20 = 130 sats.

		// Path via node0 is channels {1, 3}. Limit them to 100 and 50 sats (total limit 50);
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 1,
			timestamp: 2,
			message_flags: 1, // Only must_be_one
			channel_flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 100_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[0], UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 3,
			timestamp: 2,
			message_flags: 1, // Only must_be_one
			channel_flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 50_000,
			fee_base_msat: 100,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		// Path via node7 is channels {12, 13}. Limit them to 60 and 60 sats (total limit 60);
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 12,
			timestamp: 2,
			message_flags: 1, // Only must_be_one
			channel_flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 60_000,
			fee_base_msat: 100,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[7], UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 13,
			timestamp: 2,
			message_flags: 1, // Only must_be_one
			channel_flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 60_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		// Path via node1 is channels {2, 4}. Limit them to 20 and 20 sats (total capacity 20 sats).
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 2,
			timestamp: 2,
			message_flags: 1, // Only must_be_one
			channel_flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 20_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[1], UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 4,
			timestamp: 2,
			message_flags: 1, // Only must_be_one
			channel_flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 20_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		{
			// Attempt to route more than available results in a failure.
			let route_params = RouteParameters::from_payment_params_and_value(
				payment_params.clone(), 150_000);
			if let Err(err) = get_route(
					&our_id, &route_params, &network_graph.read_only(), None, Arc::clone(&logger),
					&scorer, &Default::default(), &random_seed_bytes) {
						assert_eq!(err, "Failed to find a sufficient route to the given destination");
			} else { panic!(); }
		}

		{
			// Now, attempt to route 125 sats (just a bit below the capacity of 3 channels).
			// Our algorithm should provide us with these 3 paths.
			let route_params = RouteParameters::from_payment_params_and_value(
				payment_params.clone(), 125_000);
			let route = get_route(&our_id, &route_params, &network_graph.read_only(), None,
				Arc::clone(&logger), &scorer, &Default::default(), &random_seed_bytes).unwrap();
			assert_eq!(route.paths.len(), 3);
			let mut total_amount_paid_msat = 0;
			for path in &route.paths {
				assert_eq!(path.hops.len(), 2);
				assert_eq!(path.hops.last().unwrap().pubkey, nodes[2]);
				total_amount_paid_msat += path.final_value_msat();
			}
			assert_eq!(total_amount_paid_msat, 125_000);
		}

		{
			// Attempt to route without the last small cheap channel
			let route_params = RouteParameters::from_payment_params_and_value(
				payment_params, 90_000);
			let route = get_route(&our_id, &route_params, &network_graph.read_only(), None,
				Arc::clone(&logger), &scorer, &Default::default(), &random_seed_bytes).unwrap();
			assert_eq!(route.paths.len(), 2);
			let mut total_amount_paid_msat = 0;
			for path in &route.paths {
				assert_eq!(path.hops.len(), 2);
				assert_eq!(path.hops.last().unwrap().pubkey, nodes[2]);
				total_amount_paid_msat += path.final_value_msat();
			}
			assert_eq!(total_amount_paid_msat, 90_000);
		}
	}

	#[test]
	#[rustfmt::skip]
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
		let logger = Arc::new(ln_test_utils::TestLogger::new());
		let network = Arc::new(NetworkGraph::new(Network::Testnet, Arc::clone(&logger)));
		let gossip_sync = P2PGossipSync::new(Arc::clone(&network), None, Arc::clone(&logger));
		let (our_privkey, our_id, privkeys, nodes) = get_nodes(&secp_ctx);
		let scorer = ln_test_utils::TestScorer::new();
		let random_seed_bytes = [42; 32];
		let payment_params = PaymentParameters::from_node_id(nodes[6], 42);

		add_channel(&gossip_sync, &secp_ctx, &our_privkey, &privkeys[1], ChannelFeatures::from_le_bytes(id_to_feature_flags(6)), 6);
		for (key, channel_flags) in [(&our_privkey, 0), (&privkeys[1], 3)] {
			update_channel(&gossip_sync, &secp_ctx, key, UnsignedChannelUpdate {
				chain_hash: ChainHash::using_genesis_block(Network::Testnet),
				short_channel_id: 6,
				timestamp: 1,
				message_flags: 1, // Only must_be_one
				channel_flags,
				cltv_expiry_delta: (6 << 4) | 0,
				htlc_minimum_msat: 0,
				htlc_maximum_msat: MAX_VALUE_MSAT,
				fee_base_msat: 0,
				fee_proportional_millionths: 0,
				excess_data: Vec::new()
			});
		}
		add_or_update_node(&gossip_sync, &secp_ctx, &privkeys[1], NodeFeatures::from_le_bytes(id_to_feature_flags(1)), 0);

		add_channel(&gossip_sync, &secp_ctx, &privkeys[1], &privkeys[4], ChannelFeatures::from_le_bytes(id_to_feature_flags(5)), 5);
		for (key, channel_flags) in [(&privkeys[1], 0), (&privkeys[4], 3)] {
			update_channel(&gossip_sync, &secp_ctx, key, UnsignedChannelUpdate {
				chain_hash: ChainHash::using_genesis_block(Network::Testnet),
				short_channel_id: 5,
				timestamp: 1,
				message_flags: 1, // Only must_be_one
				channel_flags,
				cltv_expiry_delta: (5 << 4) | 0,
				htlc_minimum_msat: 0,
				htlc_maximum_msat: MAX_VALUE_MSAT,
				fee_base_msat: 100,
				fee_proportional_millionths: 0,
				excess_data: Vec::new()
			});
		}
		add_or_update_node(&gossip_sync, &secp_ctx, &privkeys[4], NodeFeatures::from_le_bytes(id_to_feature_flags(4)), 0);

		add_channel(&gossip_sync, &secp_ctx, &privkeys[4], &privkeys[3], ChannelFeatures::from_le_bytes(id_to_feature_flags(4)), 4);
		for (key, channel_flags) in [(&privkeys[4], 0), (&privkeys[3], 3)] {
			update_channel(&gossip_sync, &secp_ctx, key, UnsignedChannelUpdate {
				chain_hash: ChainHash::using_genesis_block(Network::Testnet),
				short_channel_id: 4,
				timestamp: 1,
				message_flags: 1, // Only must_be_one
				channel_flags,
				cltv_expiry_delta: (4 << 4) | 0,
				htlc_minimum_msat: 0,
				htlc_maximum_msat: MAX_VALUE_MSAT,
				fee_base_msat: 0,
				fee_proportional_millionths: 0,
				excess_data: Vec::new()
			});
		}
		add_or_update_node(&gossip_sync, &secp_ctx, &privkeys[3], NodeFeatures::from_le_bytes(id_to_feature_flags(3)), 0);

		add_channel(&gossip_sync, &secp_ctx, &privkeys[3], &privkeys[2], ChannelFeatures::from_le_bytes(id_to_feature_flags(3)), 3);
		for (key, channel_flags) in [(&privkeys[3], 0), (&privkeys[2], 3)] {
			update_channel(&gossip_sync, &secp_ctx, key, UnsignedChannelUpdate {
				chain_hash: ChainHash::using_genesis_block(Network::Testnet),
				short_channel_id: 3,
				timestamp: 1,
				message_flags: 1, // Only must_be_one
				channel_flags,
				cltv_expiry_delta: (3 << 4) | 0,
				htlc_minimum_msat: 0,
				htlc_maximum_msat: MAX_VALUE_MSAT,
				fee_base_msat: 0,
				fee_proportional_millionths: 0,
				excess_data: Vec::new()
			});
		}
		add_or_update_node(&gossip_sync, &secp_ctx, &privkeys[2], NodeFeatures::from_le_bytes(id_to_feature_flags(2)), 0);

		add_channel(&gossip_sync, &secp_ctx, &privkeys[2], &privkeys[4], ChannelFeatures::from_le_bytes(id_to_feature_flags(2)), 2);
		for (key, channel_flags) in [(&privkeys[2], 0), (&privkeys[4], 3)] {
			update_channel(&gossip_sync, &secp_ctx, key, UnsignedChannelUpdate {
				chain_hash: ChainHash::using_genesis_block(Network::Testnet),
				short_channel_id: 2,
				timestamp: 1,
				message_flags: 1, // Only must_be_one
				channel_flags,
				cltv_expiry_delta: (2 << 4) | 0,
				htlc_minimum_msat: 0,
				htlc_maximum_msat: MAX_VALUE_MSAT,
				fee_base_msat: 0,
				fee_proportional_millionths: 0,
				excess_data: Vec::new()
			});
		}

		add_channel(&gossip_sync, &secp_ctx, &privkeys[4], &privkeys[6], ChannelFeatures::from_le_bytes(id_to_feature_flags(1)), 1);
		for (key, channel_flags) in [(&privkeys[4], 0), (&privkeys[6], 3)] {
			update_channel(&gossip_sync, &secp_ctx, key, UnsignedChannelUpdate {
				chain_hash: ChainHash::using_genesis_block(Network::Testnet),
				short_channel_id: 1,
				timestamp: 1,
				message_flags: 1, // Only must_be_one
				channel_flags,
				cltv_expiry_delta: (1 << 4) | 0,
				htlc_minimum_msat: 100,
				htlc_maximum_msat: MAX_VALUE_MSAT,
				fee_base_msat: 0,
				fee_proportional_millionths: 0,
				excess_data: Vec::new()
			});
		}
		add_or_update_node(&gossip_sync, &secp_ctx, &privkeys[6], NodeFeatures::from_le_bytes(id_to_feature_flags(6)), 0);

		{
			// Now ensure the route flows simply over nodes 1 and 4 to 6.
			let route_params = RouteParameters::from_payment_params_and_value(
				payment_params, 10_000);
			let route = get_route(&our_id, &route_params, &network.read_only(), None,
				Arc::clone(&logger), &scorer, &Default::default(), &random_seed_bytes).unwrap();
			assert_eq!(route.paths.len(), 1);
			assert_eq!(route.paths[0].hops.len(), 3);

			assert_eq!(route.paths[0].hops[0].pubkey, nodes[1]);
			assert_eq!(route.paths[0].hops[0].short_channel_id, 6);
			assert_eq!(route.paths[0].hops[0].fee_msat, 100);
			assert_eq!(route.paths[0].hops[0].cltv_expiry_delta, (5 << 4) | 0);
			assert_eq!(route.paths[0].hops[0].node_features.le_flags(), &id_to_feature_flags(1));
			assert_eq!(route.paths[0].hops[0].channel_features.le_flags(), &id_to_feature_flags(6));

			assert_eq!(route.paths[0].hops[1].pubkey, nodes[4]);
			assert_eq!(route.paths[0].hops[1].short_channel_id, 5);
			assert_eq!(route.paths[0].hops[1].fee_msat, 0);
			assert_eq!(route.paths[0].hops[1].cltv_expiry_delta, (1 << 4) | 0);
			assert_eq!(route.paths[0].hops[1].node_features.le_flags(), &id_to_feature_flags(4));
			assert_eq!(route.paths[0].hops[1].channel_features.le_flags(), &id_to_feature_flags(5));

			assert_eq!(route.paths[0].hops[2].pubkey, nodes[6]);
			assert_eq!(route.paths[0].hops[2].short_channel_id, 1);
			assert_eq!(route.paths[0].hops[2].fee_msat, 10_000);
			assert_eq!(route.paths[0].hops[2].cltv_expiry_delta, 42);
			assert_eq!(route.paths[0].hops[2].node_features.le_flags(), &id_to_feature_flags(6));
			assert_eq!(route.paths[0].hops[2].channel_features.le_flags(), &id_to_feature_flags(1));
		}
	}

	#[test]
	#[rustfmt::skip]
	fn exact_fee_liquidity_limit() {
		// Test that if, while walking the graph, we find a hop that has exactly enough liquidity
		// for us, including later hop fees, we take it. In the first version of our MPP algorithm
		// we calculated fees on a higher value, resulting in us ignoring such paths.
		let (secp_ctx, network_graph, gossip_sync, _, logger) = build_graph();
		let (our_privkey, our_id, _, nodes) = get_nodes(&secp_ctx);
		let scorer = ln_test_utils::TestScorer::new();
		let random_seed_bytes = [42; 32];
		let payment_params = PaymentParameters::from_node_id(nodes[2], 42);

		// We modify the graph to set the htlc_maximum of channel 2 to below the value we wish to
		// send.
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 2,
			timestamp: 2,
			message_flags: 1, // Only must_be_one
			channel_flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 85_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 12,
			timestamp: 2,
			message_flags: 1, // Only must_be_one
			channel_flags: 0,
			cltv_expiry_delta: (4 << 4) | 1,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 270_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 1000000,
			excess_data: Vec::new()
		});

		{
			// Now, attempt to route 90 sats, which is exactly 90 sats at the last hop, plus the
			// 200% fee charged channel 13 in the 1-to-2 direction.
			let mut route_params = RouteParameters::from_payment_params_and_value(
				payment_params, 90_000);
			route_params.max_total_routing_fee_msat = Some(90_000*2);
			let route = get_route(&our_id, &route_params, &network_graph.read_only(), None,
				Arc::clone(&logger), &scorer, &Default::default(), &random_seed_bytes).unwrap();
			assert_eq!(route.paths.len(), 1);
			assert_eq!(route.paths[0].hops.len(), 2);

			assert_eq!(route.paths[0].hops[0].pubkey, nodes[7]);
			assert_eq!(route.paths[0].hops[0].short_channel_id, 12);
			assert_eq!(route.paths[0].hops[0].fee_msat, 90_000*2);
			assert_eq!(route.paths[0].hops[0].cltv_expiry_delta, (13 << 4) | 1);
			assert_eq!(route.paths[0].hops[0].node_features.le_flags(), &id_to_feature_flags(8));
			assert_eq!(route.paths[0].hops[0].channel_features.le_flags(), &id_to_feature_flags(12));

			assert_eq!(route.paths[0].hops[1].pubkey, nodes[2]);
			assert_eq!(route.paths[0].hops[1].short_channel_id, 13);
			assert_eq!(route.paths[0].hops[1].fee_msat, 90_000);
			assert_eq!(route.paths[0].hops[1].cltv_expiry_delta, 42);
			assert_eq!(route.paths[0].hops[1].node_features.le_flags(), &id_to_feature_flags(3));
			assert_eq!(route.paths[0].hops[1].channel_features.le_flags(), &id_to_feature_flags(13));
		}
	}

	#[test]
	#[rustfmt::skip]
	fn htlc_max_reduction_below_min() {
		// Test that if, while walking the graph, we reduce the value being sent to meet an
		// htlc_maximum_msat, we don't end up undershooting a later htlc_minimum_msat. In the
		// initial version of MPP we'd accept such routes but reject them while recalculating fees,
		// resulting in us thinking there is no possible path, even if other paths exist.
		let (secp_ctx, network_graph, gossip_sync, _, logger) = build_graph();
		let (our_privkey, our_id, privkeys, nodes) = get_nodes(&secp_ctx);
		let scorer = ln_test_utils::TestScorer::new();
		let random_seed_bytes = [42; 32];
		let config = UserConfig::default();
		let payment_params = PaymentParameters::from_node_id(nodes[2], 42)
			.with_bolt11_features(channelmanager::provided_bolt11_invoice_features(&config))
			.unwrap();

		// We modify the graph to set the htlc_minimum of channel 2 and 4 as needed - channel 2
		// gets an htlc_maximum_msat of 80_000 and channel 4 an htlc_minimum_msat of 90_000. We
		// then try to send 90_000.
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 2,
			timestamp: 2,
			message_flags: 1, // Only must_be_one
			channel_flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 80_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[1], UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 4,
			timestamp: 2,
			message_flags: 1, // Only must_be_one
			channel_flags: 0,
			cltv_expiry_delta: (4 << 4) | 1,
			htlc_minimum_msat: 90_000,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		{
			// Now, attempt to route 90 sats, hitting the htlc_minimum on channel 4, but
			// overshooting the htlc_maximum on channel 2. Thus, we should pick the (absurdly
			// expensive) channels 12-13 path.
			let mut route_params = RouteParameters::from_payment_params_and_value(
				payment_params, 90_000);
			route_params.max_total_routing_fee_msat = Some(90_000*2);
			let route = get_route(&our_id, &route_params, &network_graph.read_only(), None,
				Arc::clone(&logger), &scorer, &Default::default(), &random_seed_bytes).unwrap();
			assert_eq!(route.paths.len(), 1);
			assert_eq!(route.paths[0].hops.len(), 2);

			assert_eq!(route.paths[0].hops[0].pubkey, nodes[7]);
			assert_eq!(route.paths[0].hops[0].short_channel_id, 12);
			assert_eq!(route.paths[0].hops[0].fee_msat, 90_000*2);
			assert_eq!(route.paths[0].hops[0].cltv_expiry_delta, (13 << 4) | 1);
			assert_eq!(route.paths[0].hops[0].node_features.le_flags(), &id_to_feature_flags(8));
			assert_eq!(route.paths[0].hops[0].channel_features.le_flags(), &id_to_feature_flags(12));

			assert_eq!(route.paths[0].hops[1].pubkey, nodes[2]);
			assert_eq!(route.paths[0].hops[1].short_channel_id, 13);
			assert_eq!(route.paths[0].hops[1].fee_msat, 90_000);
			assert_eq!(route.paths[0].hops[1].cltv_expiry_delta, 42);
			assert_eq!(route.paths[0].hops[1].node_features.le_flags(), channelmanager::provided_bolt11_invoice_features(&config).le_flags());
			assert_eq!(route.paths[0].hops[1].channel_features.le_flags(), &id_to_feature_flags(13));
		}
	}

	#[test]
	#[rustfmt::skip]
	fn multiple_direct_first_hops() {
		// Previously we'd only ever considered one first hop path per counterparty.
		// However, as we don't restrict users to one channel per peer, we really need to support
		// looking at all first hop paths.
		// Here we test that we do not ignore all-but-the-last first hop paths per counterparty (as
		// we used to do by overwriting the `first_hop_targets` hashmap entry) and that we can MPP
		// route over multiple channels with the same first hop.
		let secp_ctx = Secp256k1::new();
		let (_, our_id, _, nodes) = get_nodes(&secp_ctx);
		let logger = Arc::new(ln_test_utils::TestLogger::new());
		let network_graph = NetworkGraph::new(Network::Testnet, Arc::clone(&logger));
		let scorer = ln_test_utils::TestScorer::new();
		let config = UserConfig::default();
		let payment_params = PaymentParameters::from_node_id(nodes[0], 42)
			.with_bolt11_features(channelmanager::provided_bolt11_invoice_features(&config))
			.unwrap();
		let random_seed_bytes = [42; 32];

		{
			let route_params = RouteParameters::from_payment_params_and_value(
				payment_params.clone(), 100_000);
			let route = get_route(&our_id, &route_params, &network_graph.read_only(), Some(&[
				&get_channel_details(Some(3), nodes[0], channelmanager::provided_init_features(&config), 200_000),
				&get_channel_details(Some(2), nodes[0], channelmanager::provided_init_features(&config), 10_000),
			]), Arc::clone(&logger), &scorer, &Default::default(), &random_seed_bytes).unwrap();
			assert_eq!(route.paths.len(), 1);
			assert_eq!(route.paths[0].hops.len(), 1);

			assert_eq!(route.paths[0].hops[0].pubkey, nodes[0]);
			assert_eq!(route.paths[0].hops[0].short_channel_id, 3);
			assert_eq!(route.paths[0].hops[0].fee_msat, 100_000);
		}
		{
			let route_params = RouteParameters::from_payment_params_and_value(
				payment_params.clone(), 100_000);
			let route = get_route(&our_id, &route_params, &network_graph.read_only(), Some(&[
				&get_channel_details(Some(3), nodes[0], channelmanager::provided_init_features(&config), 50_000),
				&get_channel_details(Some(2), nodes[0], channelmanager::provided_init_features(&config), 50_000),
			]), Arc::clone(&logger), &scorer, &Default::default(), &random_seed_bytes).unwrap();
			assert_eq!(route.paths.len(), 2);
			assert_eq!(route.paths[0].hops.len(), 1);
			assert_eq!(route.paths[1].hops.len(), 1);

			assert!((route.paths[0].hops[0].short_channel_id == 3 && route.paths[1].hops[0].short_channel_id == 2) ||
				(route.paths[0].hops[0].short_channel_id == 2 && route.paths[1].hops[0].short_channel_id == 3));

			assert_eq!(route.paths[0].hops[0].pubkey, nodes[0]);
			assert_eq!(route.paths[0].hops[0].fee_msat, 50_000);

			assert_eq!(route.paths[1].hops[0].pubkey, nodes[0]);
			assert_eq!(route.paths[1].hops[0].fee_msat, 50_000);
		}

		{
			// If we have a bunch of outbound channels to the same node, where most are not
			// sufficient to pay the full payment, but one is, we should default to just using the
			// one single channel that has sufficient balance, avoiding MPP.
			//
			// If we have several options above the 3xpayment value threshold, we should pick the
			// smallest of them, avoiding further fragmenting our available outbound balance to
			// this node.
			let route_params = RouteParameters::from_payment_params_and_value(
				payment_params, 100_000);
			let route = get_route(&our_id, &route_params, &network_graph.read_only(), Some(&[
				&get_channel_details(Some(2), nodes[0], channelmanager::provided_init_features(&config), 50_000),
				&get_channel_details(Some(3), nodes[0], channelmanager::provided_init_features(&config), 50_000),
				&get_channel_details(Some(5), nodes[0], channelmanager::provided_init_features(&config), 50_000),
				&get_channel_details(Some(6), nodes[0], channelmanager::provided_init_features(&config), 300_000),
				&get_channel_details(Some(7), nodes[0], channelmanager::provided_init_features(&config), 50_000),
				&get_channel_details(Some(8), nodes[0], channelmanager::provided_init_features(&config), 50_000),
				&get_channel_details(Some(9), nodes[0], channelmanager::provided_init_features(&config), 50_000),
				&get_channel_details(Some(4), nodes[0], channelmanager::provided_init_features(&config), 1_000_000),
			]), Arc::clone(&logger), &scorer, &Default::default(), &random_seed_bytes).unwrap();
			assert_eq!(route.paths.len(), 1);
			assert_eq!(route.paths[0].hops.len(), 1);

			assert_eq!(route.paths[0].hops[0].pubkey, nodes[0]);
			assert_eq!(route.paths[0].hops[0].short_channel_id, 6);
			assert_eq!(route.paths[0].hops[0].fee_msat, 100_000);
		}
	}

	#[test]
	#[rustfmt::skip]
	fn prefers_shorter_route_with_higher_fees() {
		let (secp_ctx, network_graph, _, _, logger) = build_graph();
		let (_, our_id, _, nodes) = get_nodes(&secp_ctx);
		let payment_params = PaymentParameters::from_node_id(nodes[6], 42).with_route_hints(last_hops(&nodes)).unwrap();

		// Without penalizing each hop 100 msats, a longer path with lower fees is chosen.
		let scorer = ln_test_utils::TestScorer::new();
		let random_seed_bytes = [42; 32];
		let route_params = RouteParameters::from_payment_params_and_value(
			payment_params.clone(), 100);
		let route = get_route( &our_id, &route_params, &network_graph.read_only(), None,
			Arc::clone(&logger), &scorer, &Default::default(), &random_seed_bytes).unwrap();
		let path = route.paths[0].hops.iter().map(|hop| hop.short_channel_id).collect::<Vec<_>>();

		assert_eq!(route.get_total_fees(), 100);
		assert_eq!(route.get_total_amount(), 100);
		assert_eq!(path, vec![2, 4, 6, 11, 8]);

		// Applying a 100 msat penalty to each hop results in taking channels 7 and 10 to nodes[6]
		// from nodes[2] rather than channel 6, 11, and 8, even though the longer path is cheaper.
		let scorer = FixedPenaltyScorer::with_penalty(100);
		let route_params = RouteParameters::from_payment_params_and_value(
			payment_params, 100);
		let route = get_route( &our_id, &route_params, &network_graph.read_only(), None,
			Arc::clone(&logger), &scorer, &Default::default(), &random_seed_bytes).unwrap();
		let path = route.paths[0].hops.iter().map(|hop| hop.short_channel_id).collect::<Vec<_>>();

		assert_eq!(route.get_total_fees(), 300);
		assert_eq!(route.get_total_amount(), 100);
		assert_eq!(path, vec![2, 4, 7, 10]);
	}

	struct BadChannelScorer {
		short_channel_id: u64,
	}

	#[cfg(c_bindings)]
	impl Writeable for BadChannelScorer {
		#[rustfmt::skip]
		fn write<W: Writer>(&self, _w: &mut W) -> Result<(), crate::io::Error> { unimplemented!() }
	}
	impl ScoreLookUp for BadChannelScorer {
		type ScoreParams = ();
		#[rustfmt::skip]
		fn channel_penalty_msat(&self, candidate: &CandidateRouteHop, _: ChannelUsage, _score_params:&Self::ScoreParams) -> u64 {
			if candidate.short_channel_id() == Some(self.short_channel_id) { u64::max_value()  } else { 0  }
		}
	}

	struct BadNodeScorer {
		node_id: NodeId,
	}

	#[cfg(c_bindings)]
	impl Writeable for BadNodeScorer {
		#[rustfmt::skip]
		fn write<W: Writer>(&self, _w: &mut W) -> Result<(), crate::io::Error> { unimplemented!() }
	}

	impl ScoreLookUp for BadNodeScorer {
		type ScoreParams = ();
		#[rustfmt::skip]
		fn channel_penalty_msat(&self, candidate: &CandidateRouteHop, _: ChannelUsage, _score_params:&Self::ScoreParams) -> u64 {
			if candidate.target() == Some(self.node_id) { u64::max_value() } else { 0 }
		}
	}

	#[test]
	#[rustfmt::skip]
	fn avoids_routing_through_bad_channels_and_nodes() {
		let (secp_ctx, network, _, _, logger) = build_graph();
		let (_, our_id, _, nodes) = get_nodes(&secp_ctx);
		let payment_params = PaymentParameters::from_node_id(nodes[6], 42).with_route_hints(last_hops(&nodes)).unwrap();
		let network_graph = network.read_only();

		// A path to nodes[6] exists when no penalties are applied to any channel.
		let scorer = ln_test_utils::TestScorer::new();
		let random_seed_bytes = [42; 32];
		let route_params = RouteParameters::from_payment_params_and_value(
			payment_params, 100);
		let route = get_route( &our_id, &route_params, &network_graph, None, Arc::clone(&logger),
			&scorer, &Default::default(), &random_seed_bytes).unwrap();
		let path = route.paths[0].hops.iter().map(|hop| hop.short_channel_id).collect::<Vec<_>>();

		assert_eq!(route.get_total_fees(), 100);
		assert_eq!(route.get_total_amount(), 100);
		assert_eq!(path, vec![2, 4, 6, 11, 8]);

		// A different path to nodes[6] exists if channel 6 cannot be routed over.
		let scorer = BadChannelScorer { short_channel_id: 6 };
		let route = get_route( &our_id, &route_params, &network_graph, None, Arc::clone(&logger),
			&scorer, &Default::default(), &random_seed_bytes).unwrap();
		let path = route.paths[0].hops.iter().map(|hop| hop.short_channel_id).collect::<Vec<_>>();

		assert_eq!(route.get_total_fees(), 300);
		assert_eq!(route.get_total_amount(), 100);
		assert_eq!(path, vec![2, 4, 7, 10]);

		// A path to nodes[6] does not exist if nodes[2] cannot be routed through.
		let scorer = BadNodeScorer { node_id: NodeId::from_pubkey(&nodes[2]) };
		match get_route( &our_id, &route_params, &network_graph, None, Arc::clone(&logger),
			&scorer, &Default::default(), &random_seed_bytes) {
				Err(err) => {
					assert_eq!(err, "Failed to find a path to the given destination");
				},
				Ok(_) => panic!("Expected error"),
		}
	}

	#[test]
	fn total_fees_single_path() {
		let route = Route {
			paths: vec![Path { hops: vec![
				RouteHop {
					pubkey: PublicKey::from_slice(&<Vec<u8>>::from_hex("02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619").unwrap()[..]).unwrap(),
					channel_features: ChannelFeatures::empty(), node_features: NodeFeatures::empty(),
					short_channel_id: 0, fee_msat: 100, cltv_expiry_delta: 0, maybe_announced_channel: true,
				},
				RouteHop {
					pubkey: PublicKey::from_slice(&<Vec<u8>>::from_hex("0324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c").unwrap()[..]).unwrap(),
					channel_features: ChannelFeatures::empty(), node_features: NodeFeatures::empty(),
					short_channel_id: 0, fee_msat: 150, cltv_expiry_delta: 0, maybe_announced_channel: true,
				},
				RouteHop {
					pubkey: PublicKey::from_slice(&<Vec<u8>>::from_hex("027f31ebc5462c1fdce1b737ecff52d37d75dea43ce11c74d25aa297165faa2007").unwrap()[..]).unwrap(),
					channel_features: ChannelFeatures::empty(), node_features: NodeFeatures::empty(),
					short_channel_id: 0, fee_msat: 225, cltv_expiry_delta: 0, maybe_announced_channel: true,
				},
			], blinded_tail: None }],
			route_params: None,
		};

		assert_eq!(route.get_total_fees(), 250);
		assert_eq!(route.get_total_amount(), 225);
	}

	#[test]
	fn total_fees_multi_path() {
		let route = Route {
			paths: vec![Path { hops: vec![
				RouteHop {
					pubkey: PublicKey::from_slice(&<Vec<u8>>::from_hex("02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619").unwrap()[..]).unwrap(),
					channel_features: ChannelFeatures::empty(), node_features: NodeFeatures::empty(),
					short_channel_id: 0, fee_msat: 100, cltv_expiry_delta: 0, maybe_announced_channel: true,
				},
				RouteHop {
					pubkey: PublicKey::from_slice(&<Vec<u8>>::from_hex("0324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c").unwrap()[..]).unwrap(),
					channel_features: ChannelFeatures::empty(), node_features: NodeFeatures::empty(),
					short_channel_id: 0, fee_msat: 150, cltv_expiry_delta: 0, maybe_announced_channel: true,
				},
			], blinded_tail: None }, Path { hops: vec![
				RouteHop {
					pubkey: PublicKey::from_slice(&<Vec<u8>>::from_hex("02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619").unwrap()[..]).unwrap(),
					channel_features: ChannelFeatures::empty(), node_features: NodeFeatures::empty(),
					short_channel_id: 0, fee_msat: 100, cltv_expiry_delta: 0, maybe_announced_channel: true,
				},
				RouteHop {
					pubkey: PublicKey::from_slice(&<Vec<u8>>::from_hex("0324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c").unwrap()[..]).unwrap(),
					channel_features: ChannelFeatures::empty(), node_features: NodeFeatures::empty(),
					short_channel_id: 0, fee_msat: 150, cltv_expiry_delta: 0, maybe_announced_channel: true,
				},
			], blinded_tail: None }],
			route_params: None,
		};

		assert_eq!(route.get_total_fees(), 200);
		assert_eq!(route.get_total_amount(), 300);
	}

	#[test]
	fn total_empty_route_no_panic() {
		// In an earlier version of `Route::get_total_fees` and `Route::get_total_amount`, they
		// would both panic if the route was completely empty. We test to ensure they return 0
		// here, even though its somewhat nonsensical as a route.
		let route = Route { paths: Vec::new(), route_params: None };

		assert_eq!(route.get_total_fees(), 0);
		assert_eq!(route.get_total_amount(), 0);
	}

	#[test]
	#[rustfmt::skip]
	fn limits_total_cltv_delta() {
		let (secp_ctx, network, _, _, logger) = build_graph();
		let (_, our_id, _, nodes) = get_nodes(&secp_ctx);
		let network_graph = network.read_only();

		let scorer = ln_test_utils::TestScorer::new();

		// Make sure that generally there is at least one route available
		let feasible_max_total_cltv_delta = 1008;
		let feasible_payment_params = PaymentParameters::from_node_id(nodes[6], 0).with_route_hints(last_hops(&nodes)).unwrap()
			.with_max_total_cltv_expiry_delta(feasible_max_total_cltv_delta);
		let random_seed_bytes = [42; 32];
		let route_params = RouteParameters::from_payment_params_and_value(
			feasible_payment_params, 100);
		let route = get_route(&our_id, &route_params, &network_graph, None, Arc::clone(&logger),
			&scorer, &Default::default(), &random_seed_bytes).unwrap();
		let path = route.paths[0].hops.iter().map(|hop| hop.short_channel_id).collect::<Vec<_>>();
		assert_ne!(path.len(), 0);

		// But not if we exclude all paths on the basis of their accumulated CLTV delta
		let fail_max_total_cltv_delta = 23;
		let fail_payment_params = PaymentParameters::from_node_id(nodes[6], 0).with_route_hints(last_hops(&nodes)).unwrap()
			.with_max_total_cltv_expiry_delta(fail_max_total_cltv_delta);
		let route_params = RouteParameters::from_payment_params_and_value(
			fail_payment_params, 100);
		match get_route(&our_id, &route_params, &network_graph, None, Arc::clone(&logger), &scorer,
			&Default::default(), &random_seed_bytes)
		{
			Err(err) => {
				assert_eq!(err, "Failed to find a path to the given destination");
			},
			Ok(_) => panic!("Expected error"),
		}
	}

	#[test]
	#[rustfmt::skip]
	fn avoids_recently_failed_paths() {
		// Ensure that the router always avoids all of the `previously_failed_channels` channels by
		// randomly inserting channels into it until we can't find a route anymore.
		let (secp_ctx, network, _, _, logger) = build_graph();
		let (_, our_id, _, nodes) = get_nodes(&secp_ctx);
		let network_graph = network.read_only();

		let scorer = ln_test_utils::TestScorer::new();
		let mut payment_params = PaymentParameters::from_node_id(nodes[6], 0).with_route_hints(last_hops(&nodes)).unwrap()
			.with_max_path_count(1);
		let random_seed_bytes = [42; 32];

		// We should be able to find a route initially, and then after we fail a few random
		// channels eventually we won't be able to any longer.
		let route_params = RouteParameters::from_payment_params_and_value(
			payment_params.clone(), 100);
		assert!(get_route(&our_id, &route_params, &network_graph, None, Arc::clone(&logger),
			&scorer, &Default::default(), &random_seed_bytes).is_ok());
		loop {
			let route_params = RouteParameters::from_payment_params_and_value(
				payment_params.clone(), 100);
			if let Ok(route) = get_route(&our_id, &route_params, &network_graph, None,
				Arc::clone(&logger), &scorer, &Default::default(), &random_seed_bytes)
			{
				for chan in route.paths[0].hops.iter() {
					assert!(!payment_params.previously_failed_channels.contains(&chan.short_channel_id));
				}
				let victim = (u64::from_ne_bytes(random_seed_bytes[0..8].try_into().unwrap()) as usize)
					% route.paths[0].hops.len();
				payment_params.previously_failed_channels.push(route.paths[0].hops[victim].short_channel_id);
			} else { break; }
		}
	}

	#[test]
	#[rustfmt::skip]
	fn limits_path_length() {
		let (secp_ctx, network, _, _, logger) = build_line_graph();
		let (_, our_id, _, nodes) = get_nodes(&secp_ctx);
		let network_graph = network.read_only();

		let scorer = ln_test_utils::TestScorer::new();
		let random_seed_bytes = [42; 32];

		// First check we can actually create a long route on this graph.
		let feasible_payment_params = PaymentParameters::from_node_id(nodes[18], 0);
		let route_params = RouteParameters::from_payment_params_and_value(
			feasible_payment_params, 100);
		let route = get_route(&our_id, &route_params, &network_graph, None, Arc::clone(&logger),
			&scorer, &Default::default(), &random_seed_bytes).unwrap();
		let path = route.paths[0].hops.iter().map(|hop| hop.short_channel_id).collect::<Vec<_>>();
		assert!(path.len() == MAX_PATH_LENGTH_ESTIMATE.into());

		// But we can't create a path surpassing the MAX_PATH_LENGTH_ESTIMATE limit.
		let fail_payment_params = PaymentParameters::from_node_id(nodes[19], 0);
		let route_params = RouteParameters::from_payment_params_and_value(
			fail_payment_params, 100);
		match get_route(&our_id, &route_params, &network_graph, None, Arc::clone(&logger), &scorer,
			&Default::default(), &random_seed_bytes)
		{
			Err(err) => {
				assert_eq!(err, "Failed to find a path to the given destination");
			},
			Ok(_) => panic!("Expected error"),
		}
	}

	#[test]
	#[rustfmt::skip]
	fn adds_and_limits_cltv_offset() {
		let (secp_ctx, network_graph, _, _, logger) = build_graph();
		let (_, our_id, _, nodes) = get_nodes(&secp_ctx);

		let scorer = ln_test_utils::TestScorer::new();

		let payment_params = PaymentParameters::from_node_id(nodes[6], 42).with_route_hints(last_hops(&nodes)).unwrap();
		let random_seed_bytes = [42; 32];
		let route_params = RouteParameters::from_payment_params_and_value(
			payment_params.clone(), 100);
		let route = get_route(&our_id, &route_params, &network_graph.read_only(), None,
			Arc::clone(&logger), &scorer, &Default::default(), &random_seed_bytes).unwrap();
		assert_eq!(route.paths.len(), 1);

		let cltv_expiry_deltas_before = route.paths[0].hops.iter().map(|h| h.cltv_expiry_delta).collect::<Vec<u32>>();

		// Check whether the offset added to the last hop by default is in [1 .. DEFAULT_MAX_TOTAL_CLTV_EXPIRY_DELTA]
		let mut route_default = route.clone();
		add_random_cltv_offset(&mut route_default, &payment_params, &network_graph.read_only(), &random_seed_bytes);
		let cltv_expiry_deltas_default = route_default.paths[0].hops.iter().map(|h| h.cltv_expiry_delta).collect::<Vec<u32>>();
		assert_eq!(cltv_expiry_deltas_before.split_last().unwrap().1, cltv_expiry_deltas_default.split_last().unwrap().1);
		assert!(cltv_expiry_deltas_default.last() > cltv_expiry_deltas_before.last());
		assert!(cltv_expiry_deltas_default.last().unwrap() <= &DEFAULT_MAX_TOTAL_CLTV_EXPIRY_DELTA);

		// Check that no offset is added when we restrict the max_total_cltv_expiry_delta
		let mut route_limited = route.clone();
		let limited_max_total_cltv_expiry_delta = cltv_expiry_deltas_before.iter().sum();
		let limited_payment_params = payment_params.with_max_total_cltv_expiry_delta(limited_max_total_cltv_expiry_delta);
		add_random_cltv_offset(&mut route_limited, &limited_payment_params, &network_graph.read_only(), &random_seed_bytes);
		let cltv_expiry_deltas_limited = route_limited.paths[0].hops.iter().map(|h| h.cltv_expiry_delta).collect::<Vec<u32>>();
		assert_eq!(cltv_expiry_deltas_before, cltv_expiry_deltas_limited);
	}

	#[test]
	#[rustfmt::skip]
	fn adds_plausible_cltv_offset() {
		let (secp_ctx, network, _, _, logger) = build_graph();
		let (_, our_id, _, nodes) = get_nodes(&secp_ctx);
		let network_graph = network.read_only();
		let network_nodes = network_graph.nodes();
		let network_channels = network_graph.channels();
		let scorer = ln_test_utils::TestScorer::new();
		let payment_params = PaymentParameters::from_node_id(nodes[3], 0);
		let random_seed_bytes = [42; 32];

		let route_params = RouteParameters::from_payment_params_and_value(
			payment_params.clone(), 100);
		let mut route = get_route(&our_id, &route_params, &network_graph, None,
			Arc::clone(&logger), &scorer, &Default::default(), &random_seed_bytes).unwrap();
		add_random_cltv_offset(&mut route, &payment_params, &network_graph, &random_seed_bytes);

		let mut path_plausibility = vec![];

		for p in route.paths {
			// 1. Select random observation point
			let mut prng = ChaCha20::new(&random_seed_bytes, &[0u8; 12]);
			let mut random_bytes = [0u8; ::core::mem::size_of::<usize>()];

			prng.process_in_place(&mut random_bytes);
			let random_path_index = usize::from_be_bytes(random_bytes).wrapping_rem(p.hops.len());
			let observation_point = NodeId::from_pubkey(&p.hops.get(random_path_index).unwrap().pubkey);

			// 2. Calculate what CLTV expiry delta we would observe there
			let observed_cltv_expiry_delta: u32 = p.hops[random_path_index..].iter().map(|h| h.cltv_expiry_delta).sum();

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
								let next_cltv_expiry_delta = dir_info.direction().cltv_expiry_delta as u32;
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

			path_plausibility.push(found_plausible_candidate);
		}
		assert!(path_plausibility.iter().all(|x| *x));
	}

	#[test]
	#[rustfmt::skip]
	fn builds_correct_path_from_hops() {
		let (secp_ctx, network, _, _, logger) = build_graph();
		let (_, our_id, _, nodes) = get_nodes(&secp_ctx);
		let network_graph = network.read_only();

		let random_seed_bytes = [42; 32];
		let payment_params = PaymentParameters::from_node_id(nodes[3], 0);
		let hops = [nodes[1], nodes[2], nodes[4], nodes[3]];
		let route_params = RouteParameters::from_payment_params_and_value(payment_params, 100);
		let route = build_route_from_hops_internal(&our_id, &hops, &route_params, &network_graph,
			Arc::clone(&logger), &random_seed_bytes).unwrap();
		let route_hop_pubkeys = route.paths[0].hops.iter().map(|hop| hop.pubkey).collect::<Vec<_>>();
		assert_eq!(hops.len(), route.paths[0].hops.len());
		for (idx, hop_pubkey) in hops.iter().enumerate() {
			assert!(*hop_pubkey == route_hop_pubkeys[idx]);
		}
	}

	#[test]
	#[rustfmt::skip]
	fn avoids_saturating_channels() {
		let (secp_ctx, network_graph, gossip_sync, _, logger) = build_graph();
		let (_, our_id, privkeys, nodes) = get_nodes(&secp_ctx);
		let decay_params = ProbabilisticScoringDecayParameters::default();
		let scorer = ProbabilisticScorer::new(decay_params, &*network_graph, Arc::clone(&logger));

		// Set the fee on channel 13 to 0% to match channel 4 giving us two equivalent paths (us
		// -> node 7 -> node2 and us -> node 1 -> node 2) which we should balance over.
		update_channel(&gossip_sync, &secp_ctx, &privkeys[1], UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 4,
			timestamp: 2,
			message_flags: 1, // Only must_be_one
			channel_flags: 0,
			cltv_expiry_delta: (4 << 4) | 1,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 250_000_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[7], UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 13,
			timestamp: 2,
			message_flags: 1, // Only must_be_one
			channel_flags: 0,
			cltv_expiry_delta: (13 << 4) | 1,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 250_000_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		let config = UserConfig::default();
		let payment_params = PaymentParameters::from_node_id(nodes[2], 42)
			.with_bolt11_features(channelmanager::provided_bolt11_invoice_features(&config))
			.unwrap();
		let random_seed_bytes = [42; 32];

		// 75,000 sats is less than the available liquidity on each channel, set above, when
		// applying max_channel_saturation_power_of_half. This value also ensures the cost of paths
		// considered when applying max_channel_saturation_power_of_half is less than the cost of
		// those when it is not applied.
		let route_params = RouteParameters::from_payment_params_and_value(
			payment_params, 75_000_000);
		let route = get_route(&our_id, &route_params, &network_graph.read_only(), None,
			Arc::clone(&logger), &scorer, &ProbabilisticScoringFeeParameters::default(), &random_seed_bytes).unwrap();
		assert_eq!(route.paths.len(), 2);
		assert!((route.paths[0].hops[1].short_channel_id == 4 && route.paths[1].hops[1].short_channel_id == 13) ||
			(route.paths[1].hops[1].short_channel_id == 4 && route.paths[0].hops[1].short_channel_id == 13));
	}

	pub(super) fn random_init_seed() -> u64 {
		// Because the default HashMap in std pulls OS randomness, we can use it as a (bad) RNG.
		use core::hash::{BuildHasher, Hasher};
		let seed = std::collections::hash_map::RandomState::new().build_hasher().finish();
		println!("Using seed of {}", seed);
		seed
	}

	#[test]
	#[rustfmt::skip]
	fn generate_routes() {
		use crate::routing::scoring::ProbabilisticScoringFeeParameters;

		let logger = ln_test_utils::TestLogger::new();
		let (graph, mut scorer) = match super::bench_utils::read_graph_scorer(&logger) {
			Ok(res) => res,
			Err(e) => {
				eprintln!("{}", e);
				return;
			},
		};

		let params = ProbabilisticScoringFeeParameters::default();
		let features = super::Bolt11InvoiceFeatures::empty();

		super::bench_utils::generate_test_routes(&graph, &mut scorer, &params, features, random_init_seed(), 0, 2);
	}

	#[test]
	#[rustfmt::skip]
	fn generate_routes_mpp() {
		use crate::routing::scoring::ProbabilisticScoringFeeParameters;

		let logger = ln_test_utils::TestLogger::new();
		let (graph, mut scorer) = match super::bench_utils::read_graph_scorer(&logger) {
			Ok(res) => res,
			Err(e) => {
				eprintln!("{}", e);
				return;
			},
		};

		let params = ProbabilisticScoringFeeParameters::default();
		let features = channelmanager::provided_bolt11_invoice_features(&UserConfig::default());

		super::bench_utils::generate_test_routes(&graph, &mut scorer, &params, features, random_init_seed(), 0, 2);
	}

	#[test]
	#[rustfmt::skip]
	fn generate_large_mpp_routes() {
		use crate::routing::scoring::ProbabilisticScoringFeeParameters;

		let logger = ln_test_utils::TestLogger::new();
		let (graph, mut scorer) = match super::bench_utils::read_graph_scorer(&logger) {
			Ok(res) => res,
			Err(e) => {
				eprintln!("{}", e);
				return;
			},
		};

		let params = ProbabilisticScoringFeeParameters::default();
		let features = channelmanager::provided_bolt11_invoice_features(&UserConfig::default());

		super::bench_utils::generate_test_routes(&graph, &mut scorer, &params, features, random_init_seed(), 1_000_000, 2);
	}

	#[test]
	#[rustfmt::skip]
	fn honors_manual_penalties() {
		let (secp_ctx, network_graph, _, _, logger) = build_line_graph();
		let (_, our_id, _, nodes) = get_nodes(&secp_ctx);

		let random_seed_bytes = [42; 32];
		let mut scorer_params = ProbabilisticScoringFeeParameters::default();
		let scorer = ProbabilisticScorer::new(ProbabilisticScoringDecayParameters::default(), Arc::clone(&network_graph), Arc::clone(&logger));

		// First check set manual penalties are returned by the scorer.
		let usage = ChannelUsage {
			amount_msat: 0,
			inflight_htlc_msat: 0,
			effective_capacity: EffectiveCapacity::Total { capacity_msat: 1_024_000, htlc_maximum_msat: 1_000 },
		};
		scorer_params.set_manual_penalty(&NodeId::from_pubkey(&nodes[3]), 123);
		scorer_params.set_manual_penalty(&NodeId::from_pubkey(&nodes[4]), 456);
		let network_graph = network_graph.read_only();
		let channels = network_graph.channels();
		let channel = channels.get(&5).unwrap();
		let info = channel.as_directed_from(&NodeId::from_pubkey(&nodes[3])).unwrap();
		let candidate: CandidateRouteHop = CandidateRouteHop::PublicHop(PublicHopCandidate {
			info: info.0,
			short_channel_id: 5,
		});
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &scorer_params), 456);

		// Then check we can get a normal route
		let payment_params = PaymentParameters::from_node_id(nodes[10], 42);
		let route_params = RouteParameters::from_payment_params_and_value(
			payment_params, 100);
		let route = get_route(&our_id, &route_params, &network_graph, None,
			Arc::clone(&logger), &scorer, &scorer_params, &random_seed_bytes);
		assert!(route.is_ok());

		// Then check that we can't get a route if we ban an intermediate node.
		scorer_params.add_banned(&NodeId::from_pubkey(&nodes[3]));
		let route = get_route(&our_id, &route_params, &network_graph, None, Arc::clone(&logger), &scorer, &scorer_params,&random_seed_bytes);
		assert!(route.is_err());

		// Finally make sure we can route again, when we remove the ban.
		scorer_params.remove_banned(&NodeId::from_pubkey(&nodes[3]));
		let route = get_route(&our_id, &route_params, &network_graph, None, Arc::clone(&logger), &scorer, &scorer_params,&random_seed_bytes);
		assert!(route.is_ok());
	}

	#[test]
	#[rustfmt::skip]
	fn abide_by_route_hint_max_htlc() {
		// Check that we abide by any htlc_maximum_msat provided in the route hints of the payment
		// params in the final route.
		let (secp_ctx, network_graph, _, _, logger) = build_graph();
		let netgraph = network_graph.read_only();
		let (_, our_id, _, nodes) = get_nodes(&secp_ctx);
		let scorer = ln_test_utils::TestScorer::new();
		let random_seed_bytes = [42; 32];
		let config = UserConfig::default();

		let max_htlc_msat = 50_000;
		let route_hint_1 = RouteHint(vec![RouteHintHop {
			src_node_id: nodes[2],
			short_channel_id: 42,
			fees: RoutingFees {
				base_msat: 100,
				proportional_millionths: 0,
			},
			cltv_expiry_delta: 10,
			htlc_minimum_msat: None,
			htlc_maximum_msat: Some(max_htlc_msat),
		}]);
		let dest_node_id = ln_test_utils::pubkey(42);
		let payment_params = PaymentParameters::from_node_id(dest_node_id, 42)
			.with_route_hints(vec![route_hint_1.clone()]).unwrap()
			.with_bolt11_features(channelmanager::provided_bolt11_invoice_features(&config))
			.unwrap();

		// Make sure we'll error if our route hints don't have enough liquidity according to their
		// htlc_maximum_msat.
		let mut route_params = RouteParameters::from_payment_params_and_value(
			payment_params, max_htlc_msat + 1);
		route_params.max_total_routing_fee_msat = None;
		if let Err(err) = get_route(&our_id,
			&route_params, &netgraph, None, Arc::clone(&logger), &scorer, &Default::default(),
			&random_seed_bytes)
		{
			assert_eq!(err, "Failed to find a sufficient route to the given destination");
		} else { panic!(); }

		// Make sure we'll split an MPP payment across route hints if their htlc_maximum_msat warrants.
		let mut route_hint_2 = route_hint_1.clone();
		route_hint_2.0[0].short_channel_id = 43;
		let payment_params = PaymentParameters::from_node_id(dest_node_id, 42)
			.with_route_hints(vec![route_hint_1, route_hint_2]).unwrap()
			.with_bolt11_features(channelmanager::provided_bolt11_invoice_features(&config))
			.unwrap();
		let mut route_params = RouteParameters::from_payment_params_and_value(
			payment_params, max_htlc_msat + 1);
		route_params.max_total_routing_fee_msat = Some(max_htlc_msat * 2);
		let route = get_route(&our_id, &route_params, &netgraph, None, Arc::clone(&logger),
			&scorer, &Default::default(), &random_seed_bytes).unwrap();
		assert_eq!(route.paths.len(), 2);
		assert!(route.paths[0].hops.last().unwrap().fee_msat <= max_htlc_msat);
		assert!(route.paths[1].hops.last().unwrap().fee_msat <= max_htlc_msat);
	}

	#[test]
	#[rustfmt::skip]
	fn direct_channel_to_hints_with_max_htlc() {
		// Check that if we have a first hop channel peer that's connected to multiple provided route
		// hints, that we properly split the payment between the route hints if needed.
		let logger = Arc::new(ln_test_utils::TestLogger::new());
		let network_graph = Arc::new(NetworkGraph::new(Network::Testnet, Arc::clone(&logger)));
		let scorer = ln_test_utils::TestScorer::new();
		let random_seed_bytes = [42; 32];
		let config = UserConfig::default();

		let our_node_id = ln_test_utils::pubkey(42);
		let intermed_node_id = ln_test_utils::pubkey(43);
		let first_hop = vec![get_channel_details(Some(42), intermed_node_id, InitFeatures::from_le_bytes(vec![0b11]), 10_000_000)];

		let amt_msat = 900_000;
		let max_htlc_msat = 500_000;
		let route_hint_1 = RouteHint(vec![RouteHintHop {
			src_node_id: intermed_node_id,
			short_channel_id: 44,
			fees: RoutingFees {
				base_msat: 100,
				proportional_millionths: 0,
			},
			cltv_expiry_delta: 10,
			htlc_minimum_msat: None,
			htlc_maximum_msat: Some(max_htlc_msat),
		}, RouteHintHop {
			src_node_id: intermed_node_id,
			short_channel_id: 45,
			fees: RoutingFees {
				base_msat: 100,
				proportional_millionths: 0,
			},
			cltv_expiry_delta: 10,
			htlc_minimum_msat: None,
			// Check that later route hint max htlcs don't override earlier ones
			htlc_maximum_msat: Some(max_htlc_msat - 50),
		}]);
		let mut route_hint_2 = route_hint_1.clone();
		route_hint_2.0[0].short_channel_id = 46;
		route_hint_2.0[1].short_channel_id = 47;
		let dest_node_id = ln_test_utils::pubkey(44);
		let payment_params = PaymentParameters::from_node_id(dest_node_id, 42)
			.with_route_hints(vec![route_hint_1, route_hint_2]).unwrap()
			.with_bolt11_features(channelmanager::provided_bolt11_invoice_features(&config))
			.unwrap();

		let route_params = RouteParameters::from_payment_params_and_value(
			payment_params, amt_msat);
		let route = get_route(&our_node_id, &route_params, &network_graph.read_only(),
			Some(&first_hop.iter().collect::<Vec<_>>()), Arc::clone(&logger), &scorer,
			&Default::default(), &random_seed_bytes).unwrap();
		assert_eq!(route.paths.len(), 2);
		assert!(route.paths[0].hops.last().unwrap().fee_msat <= max_htlc_msat);
		assert!(route.paths[1].hops.last().unwrap().fee_msat <= max_htlc_msat);
		assert_eq!(route.get_total_amount(), amt_msat);

		// Re-run but with two first hop channels connected to the same route hint peers that must be
		// split between.
		let first_hops = vec![
			get_channel_details(Some(42), intermed_node_id, InitFeatures::from_le_bytes(vec![0b11]), amt_msat - 10),
			get_channel_details(Some(43), intermed_node_id, InitFeatures::from_le_bytes(vec![0b11]), amt_msat - 10),
		];
		let route = get_route(&our_node_id, &route_params, &network_graph.read_only(),
			Some(&first_hops.iter().collect::<Vec<_>>()), Arc::clone(&logger), &scorer,
			&Default::default(), &random_seed_bytes).unwrap();
		assert_eq!(route.paths.len(), 2);
		assert!(route.paths[0].hops.last().unwrap().fee_msat <= max_htlc_msat);
		assert!(route.paths[1].hops.last().unwrap().fee_msat <= max_htlc_msat);
		assert_eq!(route.get_total_amount(), amt_msat);

		// Make sure this works for blinded route hints.
		let blinded_payinfo = BlindedPayInfo {
			fee_base_msat: 100,
			fee_proportional_millionths: 0,
			htlc_minimum_msat: 1,
			htlc_maximum_msat: max_htlc_msat,
			cltv_expiry_delta: 10,
			features: BlindedHopFeatures::empty(),
		};
		let blinded_path = dummy_blinded_path(intermed_node_id, blinded_payinfo);
		let bolt12_features = channelmanager::provided_bolt12_invoice_features(&config);
		let payment_params = PaymentParameters::blinded(vec![
			blinded_path.clone(), blinded_path.clone()
		]).with_bolt12_features(bolt12_features).unwrap();
		let route_params = RouteParameters::from_payment_params_and_value(
			payment_params, amt_msat);
		let route = get_route(&our_node_id, &route_params, &network_graph.read_only(),
			Some(&first_hops.iter().collect::<Vec<_>>()), Arc::clone(&logger), &scorer,
			&Default::default(), &random_seed_bytes).unwrap();
		assert_eq!(route.paths.len(), 2);
		assert!(route.paths[0].hops.last().unwrap().fee_msat <= max_htlc_msat);
		assert!(route.paths[1].hops.last().unwrap().fee_msat <= max_htlc_msat);
		assert_eq!(route.get_total_amount(), amt_msat);
	}

	#[test]
	#[rustfmt::skip]
	fn blinded_route_ser() {
		// (De)serialize a Route with 1 blinded path out of two total paths.
		let mut route = Route { paths: vec![Path {
			hops: vec![RouteHop {
				pubkey: ln_test_utils::pubkey(50),
				node_features: NodeFeatures::empty(),
				short_channel_id: 42,
				channel_features: ChannelFeatures::empty(),
				fee_msat: 100,
				cltv_expiry_delta: 0,
				maybe_announced_channel: true,
			}],
			blinded_tail: Some(BlindedTail {
				trampoline_hops: vec![],
				hops: vec![
					BlindedHop { blinded_node_id: ln_test_utils::pubkey(44), encrypted_payload: Vec::new() },
					BlindedHop { blinded_node_id: ln_test_utils::pubkey(45), encrypted_payload: Vec::new() }
				],
				blinding_point: ln_test_utils::pubkey(43),
				excess_final_cltv_expiry_delta: 40,
				final_value_msat: 100,
			})}, Path {
			hops: vec![RouteHop {
				pubkey: ln_test_utils::pubkey(51),
				node_features: NodeFeatures::empty(),
				short_channel_id: 43,
				channel_features: ChannelFeatures::empty(),
				fee_msat: 100,
				cltv_expiry_delta: 0,
				maybe_announced_channel: true,
			}], blinded_tail: None }],
			route_params: None,
		};
		let encoded_route = route.encode();
		let decoded_route: Route = Readable::read(&mut Cursor::new(&encoded_route[..])).unwrap();
		assert_eq!(decoded_route.paths[0].blinded_tail, route.paths[0].blinded_tail);
		assert_eq!(decoded_route.paths[1].blinded_tail, route.paths[1].blinded_tail);

		// (De)serialize a Route with two paths, each containing a blinded tail.
		route.paths[1].blinded_tail = Some(BlindedTail {
			trampoline_hops: vec![],
			hops: vec![
				BlindedHop { blinded_node_id: ln_test_utils::pubkey(48), encrypted_payload: Vec::new() },
				BlindedHop { blinded_node_id: ln_test_utils::pubkey(49), encrypted_payload: Vec::new() }
			],
			blinding_point: ln_test_utils::pubkey(47),
			excess_final_cltv_expiry_delta: 41,
			final_value_msat: 101,
		});
		let encoded_route = route.encode();
		let decoded_route: Route = Readable::read(&mut Cursor::new(&encoded_route[..])).unwrap();
		assert_eq!(decoded_route.paths[0].blinded_tail, route.paths[0].blinded_tail);
		assert_eq!(decoded_route.paths[1].blinded_tail, route.paths[1].blinded_tail);
	}

	#[test]
	#[rustfmt::skip]
	fn blinded_path_inflight_processing() {
		// Ensure we'll score the channel that's inbound to a blinded path's introduction node, and
		// account for the blinded tail's final amount_msat.
		let mut inflight_htlcs = InFlightHtlcs::new();
		let path = Path {
			hops: vec![RouteHop {
				pubkey: ln_test_utils::pubkey(42),
				node_features: NodeFeatures::empty(),
				short_channel_id: 42,
				channel_features: ChannelFeatures::empty(),
				fee_msat: 100,
				cltv_expiry_delta: 0,
				maybe_announced_channel: false,
			},
			RouteHop {
				pubkey: ln_test_utils::pubkey(43),
				node_features: NodeFeatures::empty(),
				short_channel_id: 43,
				channel_features: ChannelFeatures::empty(),
				fee_msat: 1,
				cltv_expiry_delta: 0,
				maybe_announced_channel: false,
			}],
			blinded_tail: Some(BlindedTail {
				trampoline_hops: vec![],
				hops: vec![BlindedHop { blinded_node_id: ln_test_utils::pubkey(49), encrypted_payload: Vec::new() }],
				blinding_point: ln_test_utils::pubkey(48),
				excess_final_cltv_expiry_delta: 0,
				final_value_msat: 200,
			}),
		};
		inflight_htlcs.process_path(&path, ln_test_utils::pubkey(44));
		assert_eq!(*inflight_htlcs.0.get(&(42, true)).unwrap(), 301);
		assert_eq!(*inflight_htlcs.0.get(&(43, false)).unwrap(), 201);
	}

	#[test]
	#[rustfmt::skip]
	fn blinded_path_cltv_shadow_offset() {
		// Make sure we add a shadow offset when sending to blinded paths.
		let mut route = Route { paths: vec![Path {
			hops: vec![RouteHop {
				pubkey: ln_test_utils::pubkey(42),
				node_features: NodeFeatures::empty(),
				short_channel_id: 42,
				channel_features: ChannelFeatures::empty(),
				fee_msat: 100,
				cltv_expiry_delta: 0,
				maybe_announced_channel: false,
			},
			RouteHop {
				pubkey: ln_test_utils::pubkey(43),
				node_features: NodeFeatures::empty(),
				short_channel_id: 43,
				channel_features: ChannelFeatures::empty(),
				fee_msat: 1,
				cltv_expiry_delta: 0,
				maybe_announced_channel: false,
			}
			],
			blinded_tail: Some(BlindedTail {
				trampoline_hops: vec![],
				hops: vec![
					BlindedHop { blinded_node_id: ln_test_utils::pubkey(45), encrypted_payload: Vec::new() },
					BlindedHop { blinded_node_id: ln_test_utils::pubkey(46), encrypted_payload: Vec::new() }
				],
				blinding_point: ln_test_utils::pubkey(44),
				excess_final_cltv_expiry_delta: 0,
				final_value_msat: 200,
			}),
		}], route_params: None};

		let payment_params = PaymentParameters::from_node_id(ln_test_utils::pubkey(47), 18);
		let (_, network_graph, _, _, _) = build_line_graph();
		add_random_cltv_offset(&mut route, &payment_params, &network_graph.read_only(), &[0; 32]);
		assert_eq!(route.paths[0].blinded_tail.as_ref().unwrap().excess_final_cltv_expiry_delta, 40);
		assert_eq!(route.paths[0].hops.last().unwrap().cltv_expiry_delta, 40);
	}

	#[test]
	fn simple_blinded_route_hints() {
		do_simple_blinded_route_hints(1);
		do_simple_blinded_route_hints(2);
		do_simple_blinded_route_hints(3);
	}

	#[rustfmt::skip]
	fn do_simple_blinded_route_hints(num_blinded_hops: usize) {
		// Check that we can generate a route to a blinded path with the expected hops.
		let (secp_ctx, network, _, _, logger) = build_graph();
		let (_, our_id, _, nodes) = get_nodes(&secp_ctx);
		let network_graph = network.read_only();

		let scorer = ln_test_utils::TestScorer::new();
		let random_seed_bytes = [42; 32];

		let mut blinded_hops = Vec::new();
		for i in 0..num_blinded_hops {
			blinded_hops.push(
				BlindedHop { blinded_node_id: ln_test_utils::pubkey(42 + i as u8), encrypted_payload: Vec::new() },
			);
		}
		let blinded_payinfo = BlindedPayInfo {
			fee_base_msat: 100,
			fee_proportional_millionths: 500,
			htlc_minimum_msat: 1000,
			htlc_maximum_msat: 100_000_000,
			cltv_expiry_delta: 15,
			features: BlindedHopFeatures::empty(),
		};
		let blinded_path = BlindedPaymentPath::from_blinded_path_and_payinfo(
			nodes[2], ln_test_utils::pubkey(42), blinded_hops, blinded_payinfo.clone()
		);
		let payment_params = PaymentParameters::blinded(vec![blinded_path.clone(), blinded_path.clone()]);

		// Make sure we can round-trip read and write blinded payment params.
		let encoded_params = payment_params.encode();
		let mut s = Cursor::new(&encoded_params);
		let mut reader = FixedLengthReader::new(&mut s, encoded_params.len() as u64);
		let decoded_params: PaymentParameters = ReadableArgs::read(&mut reader, 42).unwrap();
		assert_eq!(payment_params, decoded_params);

		let route_params = RouteParameters::from_payment_params_and_value(
			payment_params, 1001);
		let route = get_route(&our_id, &route_params, &network_graph, None, Arc::clone(&logger),
			&scorer, &Default::default(), &random_seed_bytes).unwrap();
		assert_eq!(route.paths.len(), 1);
		assert_eq!(route.paths[0].hops.len(), 2);

		let tail = route.paths[0].blinded_tail.as_ref().unwrap();
		assert_eq!(&tail.hops, blinded_path.blinded_hops());
		assert_eq!(tail.excess_final_cltv_expiry_delta, 0);
		assert_eq!(tail.final_value_msat, 1001);

		let final_hop = route.paths[0].hops.last().unwrap();
		assert_eq!(
			NodeId::from_pubkey(&final_hop.pubkey),
			*blinded_path.public_introduction_node_id(&network_graph).unwrap()
		);
		if tail.hops.len() > 1 {
			assert_eq!(final_hop.fee_msat,
				blinded_payinfo.fee_base_msat as u64 + blinded_payinfo.fee_proportional_millionths as u64 * tail.final_value_msat / 1000000);
			assert_eq!(final_hop.cltv_expiry_delta, blinded_payinfo.cltv_expiry_delta as u32);
		} else {
			assert_eq!(final_hop.fee_msat, 0);
			assert_eq!(final_hop.cltv_expiry_delta, 0);
		}
	}

	#[test]
	#[rustfmt::skip]
	fn blinded_path_routing_errors() {
		// Check that we can generate a route to a blinded path with the expected hops.
		let (secp_ctx, network, _, _, logger) = build_graph();
		let (_, our_id, _, nodes) = get_nodes(&secp_ctx);
		let network_graph = network.read_only();

		let scorer = ln_test_utils::TestScorer::new();
		let random_seed_bytes = [42; 32];

		let blinded_payinfo = BlindedPayInfo {
			fee_base_msat: 100,
			fee_proportional_millionths: 500,
			htlc_minimum_msat: 1000,
			htlc_maximum_msat: 100_000_000,
			cltv_expiry_delta: 15,
			features: BlindedHopFeatures::empty(),
		};

		let invalid_blinded_path_2 = dummy_one_hop_blinded_path(nodes[2], blinded_payinfo.clone());
		let invalid_blinded_path_3 = dummy_one_hop_blinded_path(nodes[3], blinded_payinfo.clone());
		let payment_params = PaymentParameters::blinded(vec![
			invalid_blinded_path_2, invalid_blinded_path_3]);
		let route_params = RouteParameters::from_payment_params_and_value(payment_params, 1001);
		match get_route(&our_id, &route_params, &network_graph, None, Arc::clone(&logger),
			&scorer, &Default::default(), &random_seed_bytes)
		{
			Err(err) => {
				assert_eq!(err, "1-hop blinded paths must all have matching introduction node ids");
			},
			_ => panic!("Expected error")
		}

		let invalid_blinded_path = dummy_blinded_path(our_id, blinded_payinfo.clone());
		let payment_params = PaymentParameters::blinded(vec![invalid_blinded_path]);
		let route_params = RouteParameters::from_payment_params_and_value(payment_params, 1001);
		match get_route(&our_id, &route_params, &network_graph, None, Arc::clone(&logger), &scorer,
			&Default::default(), &random_seed_bytes)
		{
			Err(err) => {
				assert_eq!(err, "Cannot generate a route to blinded paths if we are the introduction node to all of them");
			},
			_ => panic!("Expected error")
		}

		let mut invalid_blinded_path = dummy_one_hop_blinded_path(ln_test_utils::pubkey(46), blinded_payinfo);
		invalid_blinded_path.clear_blinded_hops();
		let payment_params = PaymentParameters::blinded(vec![invalid_blinded_path]);
		let route_params = RouteParameters::from_payment_params_and_value(payment_params, 1001);
		match get_route(&our_id, &route_params, &network_graph, None, Arc::clone(&logger), &scorer,
			&Default::default(), &random_seed_bytes)
		{
			Err(err) => {
				assert_eq!(err, "0-hop blinded path provided");
			},
			_ => panic!("Expected error")
		}
	}

	#[test]
	#[rustfmt::skip]
	fn matching_intro_node_paths_provided() {
		// Check that if multiple blinded paths with the same intro node are provided in payment
		// parameters, we'll return the correct paths in the resulting MPP route.
		let (secp_ctx, network, _, _, logger) = build_graph();
		let (_, our_id, _, nodes) = get_nodes(&secp_ctx);
		let network_graph = network.read_only();

		let scorer = ln_test_utils::TestScorer::new();
		let random_seed_bytes = [42; 32];
		let config = UserConfig::default();

		let bolt12_features = channelmanager::provided_bolt12_invoice_features(&config);
		let blinded_payinfo_1 = BlindedPayInfo {
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 30_000,
			cltv_expiry_delta: 0,
			features: BlindedHopFeatures::empty(),
		};
		let blinded_path_1 = dummy_blinded_path(nodes[2], blinded_payinfo_1.clone());

		let mut blinded_payinfo_2 = blinded_payinfo_1;
		blinded_payinfo_2.htlc_maximum_msat = 70_000;
		let blinded_path_2 = BlindedPaymentPath::from_blinded_path_and_payinfo(
			nodes[2],
			ln_test_utils::pubkey(43),
			vec![
				BlindedHop { blinded_node_id: ln_test_utils::pubkey(42 as u8), encrypted_payload: Vec::new() },
				BlindedHop { blinded_node_id: ln_test_utils::pubkey(42 as u8), encrypted_payload: Vec::new() }
			],
			blinded_payinfo_2
		);

		let blinded_hints = vec![blinded_path_1.clone(), blinded_path_2.clone()];
		let payment_params = PaymentParameters::blinded(blinded_hints.clone())
			.with_bolt12_features(bolt12_features).unwrap();

		let mut route_params = RouteParameters::from_payment_params_and_value(payment_params, 100_000);
		route_params.max_total_routing_fee_msat = Some(100_000);
		let route = get_route(&our_id, &route_params, &network_graph, None, Arc::clone(&logger),
			&scorer, &Default::default(), &random_seed_bytes).unwrap();
		assert_eq!(route.paths.len(), 2);
		let mut total_amount_paid_msat = 0;
		for path in route.paths.into_iter() {
			assert_eq!(path.hops.last().unwrap().pubkey, nodes[2]);
			if let Some(bt) = &path.blinded_tail {
				assert_eq!(bt.blinding_point,
					blinded_hints.iter().find(|p| p.payinfo.htlc_maximum_msat == path.final_value_msat())
						.map(|bp| bp.blinding_point()).unwrap());
			} else { panic!(); }
			total_amount_paid_msat += path.final_value_msat();
		}
		assert_eq!(total_amount_paid_msat, 100_000);
	}

	#[test]
	#[rustfmt::skip]
	fn direct_to_intro_node() {
		// This previously caused a debug panic in the router when asserting
		// `used_liquidity_msat <= hop_max_msat`, because when adding first_hop<>blinded_route_hint
		// direct channels we failed to account for the fee charged for use of the blinded path.

		// Build a graph:
		// node0 -1(1)2 - node1
		// such that there isn't enough liquidity to reach node1, but the router thinks there is if it
		// doesn't account for the blinded path fee.

		let secp_ctx = Secp256k1::new();
		let logger = Arc::new(ln_test_utils::TestLogger::new());
		let network_graph = Arc::new(NetworkGraph::new(Network::Testnet, Arc::clone(&logger)));
		let gossip_sync = P2PGossipSync::new(Arc::clone(&network_graph), None, Arc::clone(&logger));
		let scorer = ln_test_utils::TestScorer::new();
		let random_seed_bytes = [42; 32];

		let amt_msat = 10_000_000;
		let (_, _, privkeys, nodes) = get_nodes(&secp_ctx);
		add_channel(&gossip_sync, &secp_ctx, &privkeys[0], &privkeys[1],
			ChannelFeatures::from_le_bytes(id_to_feature_flags(1)), 1);
		update_channel(&gossip_sync, &secp_ctx, &privkeys[0], UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 1,
			timestamp: 1,
			message_flags: 1, // Only must_be_one
			channel_flags: 0,
			cltv_expiry_delta: 42,
			htlc_minimum_msat: 1_000,
			htlc_maximum_msat: 10_000_000,
			fee_base_msat: 800,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[1], UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 1,
			timestamp: 1,
			message_flags: 1, // Only must_be_one
			channel_flags: 1,
			cltv_expiry_delta: 42,
			htlc_minimum_msat: 1_000,
			htlc_maximum_msat: 10_000_000,
			fee_base_msat: 800,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		let first_hops = vec![
			get_channel_details(Some(1), nodes[1], InitFeatures::from_le_bytes(vec![0b11]), 10_000_000)];

		let blinded_payinfo = BlindedPayInfo {
			fee_base_msat: 1000,
			fee_proportional_millionths: 0,
			htlc_minimum_msat: 1000,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			cltv_expiry_delta: 0,
			features: BlindedHopFeatures::empty(),
		};
		let blinded_path = dummy_blinded_path(nodes[1], blinded_payinfo.clone());
		let blinded_hints = vec![blinded_path];

		let payment_params = PaymentParameters::blinded(blinded_hints.clone());

		let netgraph = network_graph.read_only();
		let route_params = RouteParameters::from_payment_params_and_value(
			payment_params.clone(), amt_msat);
		if let Err(err) = get_route(&nodes[0], &route_params, &netgraph,
			Some(&first_hops.iter().collect::<Vec<_>>()), Arc::clone(&logger), &scorer,
			&Default::default(), &random_seed_bytes) {
				assert_eq!(err, "Failed to find a path to the given destination");
		} else { panic!("Expected error") }

		// Sending an exact amount accounting for the blinded path fee works.
		let amt_minus_blinded_path_fee = amt_msat - blinded_payinfo.fee_base_msat as u64;
		let route_params = RouteParameters::from_payment_params_and_value(
			payment_params, amt_minus_blinded_path_fee);
		let route = get_route(&nodes[0], &route_params, &netgraph,
			Some(&first_hops.iter().collect::<Vec<_>>()), Arc::clone(&logger), &scorer,
			&Default::default(), &random_seed_bytes).unwrap();
		assert_eq!(route.get_total_fees(), blinded_payinfo.fee_base_msat as u64);
		assert_eq!(route.get_total_amount(), amt_minus_blinded_path_fee);
	}

	#[test]
	#[rustfmt::skip]
	fn direct_to_matching_intro_nodes() {
		// This previously caused us to enter `unreachable` code in the following situation:
		// 1. We add a route candidate for intro_node contributing a high amount
		// 2. We add a first_hop<>intro_node route candidate for the same high amount
		// 3. We see a cheaper blinded route hint for the same intro node but a much lower contribution
		//    amount, and update our route candidate for intro_node for the lower amount
		// 4. We then attempt to update the aforementioned first_hop<>intro_node route candidate for the
		//    lower contribution amount, but fail (this was previously caused by failure to account for
		//    blinded path fees when adding first_hop<>intro_node candidates)
		// 5. We go to construct the path from these route candidates and our first_hop<>intro_node
		//    candidate still thinks its path is contributing the original higher amount. This caused us
		//    to hit an `unreachable` overflow when calculating the cheaper intro_node fees over the
		//    larger amount
		let secp_ctx = Secp256k1::new();
		let logger = Arc::new(ln_test_utils::TestLogger::new());
		let network_graph = Arc::new(NetworkGraph::new(Network::Testnet, Arc::clone(&logger)));
		let scorer = ln_test_utils::TestScorer::new();
		let random_seed_bytes = [42; 32];
		let config = UserConfig::default();

		// Values are taken from the fuzz input that uncovered this panic.
		let amt_msat = 21_7020_5185_1403_2640;
		let (_, _, _, nodes) = get_nodes(&secp_ctx);
		let first_hops = vec![
			get_channel_details(Some(1), nodes[1], channelmanager::provided_init_features(&config),
				18446744073709551615)];

		let blinded_payinfo = BlindedPayInfo {
			fee_base_msat: 5046_2720,
			fee_proportional_millionths: 0,
			htlc_minimum_msat: 4503_5996_2737_0496,
			htlc_maximum_msat: 45_0359_9627_3704_9600,
			cltv_expiry_delta: 0,
			features: BlindedHopFeatures::empty(),
		};
		let blinded_path = dummy_blinded_path(nodes[1], blinded_payinfo.clone());
		let mut blinded_hints = vec![blinded_path.clone(), blinded_path.clone()];
		blinded_hints[1].payinfo.fee_base_msat = 419_4304;
		blinded_hints[1].payinfo.fee_proportional_millionths = 257;
		blinded_hints[1].payinfo.htlc_minimum_msat = 280_8908_6115_8400;
		blinded_hints[1].payinfo.htlc_maximum_msat = 2_8089_0861_1584_0000;
		blinded_hints[1].payinfo.cltv_expiry_delta = 0;

		let bolt12_features = channelmanager::provided_bolt12_invoice_features(&config);
		let payment_params = PaymentParameters::blinded(blinded_hints.clone())
			.with_bolt12_features(bolt12_features).unwrap();

		let netgraph = network_graph.read_only();
		let route_params = RouteParameters::from_payment_params_and_value(
			payment_params, amt_msat);
		let route = get_route(&nodes[0], &route_params, &netgraph,
			Some(&first_hops.iter().collect::<Vec<_>>()), Arc::clone(&logger), &scorer,
			&Default::default(), &random_seed_bytes).unwrap();
		assert_eq!(route.get_total_fees(), blinded_payinfo.fee_base_msat as u64);
		assert_eq!(route.get_total_amount(), amt_msat);
	}

	#[test]
	#[rustfmt::skip]
	fn we_are_intro_node_candidate_hops() {
		// This previously led to a panic in the router because we'd generate a Path with only a
		// BlindedTail and 0 unblinded hops, due to the only candidate hops being blinded route hints
		// where the origin node is the intro node. We now fully disallow considering candidate hops
		// where the origin node is the intro node.
		let (secp_ctx, network_graph, _, _, logger) = build_graph();
		let (_, our_id, _, nodes) = get_nodes(&secp_ctx);
		let scorer = ln_test_utils::TestScorer::new();
		let random_seed_bytes = [42; 32];
		let config = UserConfig::default();

		// Values are taken from the fuzz input that uncovered this panic.
		let amt_msat = 21_7020_5185_1423_0019;

		let blinded_payinfo = BlindedPayInfo {
			fee_base_msat: 5052_9027,
			fee_proportional_millionths: 0,
			htlc_minimum_msat: 21_7020_5185_1423_0019,
			htlc_maximum_msat: 1844_6744_0737_0955_1615,
			cltv_expiry_delta: 0,
			features: BlindedHopFeatures::empty(),
		};
		let blinded_path = dummy_blinded_path(our_id, blinded_payinfo.clone());
		let mut blinded_hints = vec![blinded_path.clone(), blinded_path.clone()];
		blinded_hints[1] = dummy_blinded_path(nodes[6], blinded_payinfo);

		let bolt12_features = channelmanager::provided_bolt12_invoice_features(&config);
		let payment_params = PaymentParameters::blinded(blinded_hints.clone())
			.with_bolt12_features(bolt12_features.clone()).unwrap();

		let netgraph = network_graph.read_only();
		let route_params = RouteParameters::from_payment_params_and_value(
			payment_params, amt_msat);
		if let Err(err) = get_route(
			&our_id, &route_params, &netgraph, None, Arc::clone(&logger), &scorer, &Default::default(), &random_seed_bytes
		) {
			assert_eq!(err, "Failed to find a path to the given destination");
		} else { panic!() }
	}

	#[test]
	#[rustfmt::skip]
	fn we_are_intro_node_bp_in_final_path_fee_calc() {
		// This previously led to a debug panic in the router because we'd find an invalid Path with
		// 0 unblinded hops and a blinded tail, leading to the generation of a final
		// PaymentPathHop::fee_msat that included both the blinded path fees and the final value of
		// the payment, when it was intended to only include the final value of the payment.
		let (secp_ctx, network_graph, _, _, logger) = build_graph();
		let (_, our_id, _, nodes) = get_nodes(&secp_ctx);
		let scorer = ln_test_utils::TestScorer::new();
		let random_seed_bytes = [42; 32];
		let config = UserConfig::default();

		// Values are taken from the fuzz input that uncovered this panic.
		let amt_msat = 21_7020_5185_1423_0019;

		let blinded_payinfo = BlindedPayInfo {
			fee_base_msat: 10_4425_1395,
			fee_proportional_millionths: 0,
			htlc_minimum_msat: 21_7301_9934_9094_0931,
			htlc_maximum_msat: 1844_6744_0737_0955_1615,
			cltv_expiry_delta: 0,
			features: BlindedHopFeatures::empty(),
		};
		let blinded_path = dummy_blinded_path(our_id, blinded_payinfo.clone());
		let mut blinded_hints = vec![
			blinded_path.clone(), blinded_path.clone(), blinded_path.clone(),
		];
		blinded_hints[1].payinfo.fee_base_msat = 5052_9027;
		blinded_hints[1].payinfo.htlc_minimum_msat = 21_7020_5185_1423_0019;
		blinded_hints[1].payinfo.htlc_maximum_msat = 1844_6744_0737_0955_1615;

		blinded_hints[2] = dummy_blinded_path(nodes[6], blinded_payinfo);

		let bolt12_features = channelmanager::provided_bolt12_invoice_features(&config);
		let payment_params = PaymentParameters::blinded(blinded_hints.clone())
			.with_bolt12_features(bolt12_features.clone()).unwrap();

		let netgraph = network_graph.read_only();
		let route_params = RouteParameters::from_payment_params_and_value(
			payment_params, amt_msat);
		if let Err(err) = get_route(
			&our_id, &route_params, &netgraph, None, Arc::clone(&logger), &scorer, &Default::default(), &random_seed_bytes
		) {
			assert_eq!(err, "Failed to find a path to the given destination");
		} else { panic!() }
	}

	#[test]
	fn min_htlc_overpay_violates_max_htlc() {
		do_min_htlc_overpay_violates_max_htlc(true);
		do_min_htlc_overpay_violates_max_htlc(false);
	}
	#[rustfmt::skip]
	fn do_min_htlc_overpay_violates_max_htlc(blinded_payee: bool) {
		// Test that if overpaying to meet a later hop's min_htlc and causes us to violate an earlier
		// hop's max_htlc, we don't consider that candidate hop valid. Previously we would add this hop
		// to `targets` and build an invalid path with it, and subsequently hit a debug panic asserting
		// that the used liquidity for a hop was less than its available liquidity limit.
		let secp_ctx = Secp256k1::new();
		let logger = Arc::new(ln_test_utils::TestLogger::new());
		let network_graph = Arc::new(NetworkGraph::new(Network::Testnet, Arc::clone(&logger)));
		let scorer = ln_test_utils::TestScorer::new();
		let random_seed_bytes = [42; 32];
		let config = UserConfig::default();

		// Values are taken from the fuzz input that uncovered this panic.
		let amt_msat = 7_4009_8048;
		let (_, our_id, _, nodes) = get_nodes(&secp_ctx);
		let first_hop_outbound_capacity = 2_7345_2000;
		let first_hops = vec![get_channel_details(
			Some(200), nodes[0], channelmanager::provided_init_features(&config),
			first_hop_outbound_capacity
		)];

		let base_fee = 1_6778_3453;
		let htlc_min = 2_5165_8240;
		let payment_params = if blinded_payee {
			let blinded_payinfo = BlindedPayInfo {
				fee_base_msat: base_fee,
				fee_proportional_millionths: 0,
				htlc_minimum_msat: htlc_min,
				htlc_maximum_msat: htlc_min * 1000,
				cltv_expiry_delta: 0,
				features: BlindedHopFeatures::empty(),
			};
			let blinded_path = dummy_blinded_path(nodes[0], blinded_payinfo);
			let bolt12_features = channelmanager::provided_bolt12_invoice_features(&config);
			PaymentParameters::blinded(vec![blinded_path])
				.with_bolt12_features(bolt12_features.clone()).unwrap()
		} else {
			let route_hint = RouteHint(vec![RouteHintHop {
				src_node_id: nodes[0],
				short_channel_id: 42,
				fees: RoutingFees {
					base_msat: base_fee,
					proportional_millionths: 0,
				},
				cltv_expiry_delta: 10,
				htlc_minimum_msat: Some(htlc_min),
				htlc_maximum_msat: None,
			}]);

			PaymentParameters::from_node_id(nodes[1], 42)
				.with_route_hints(vec![route_hint]).unwrap()
				.with_bolt11_features(channelmanager::provided_bolt11_invoice_features(&config)).unwrap()
		};

		let netgraph = network_graph.read_only();
		let route_params = RouteParameters::from_payment_params_and_value(
			payment_params, amt_msat);
		if let Err(err) = get_route(
			&our_id, &route_params, &netgraph, Some(&first_hops.iter().collect::<Vec<_>>()),
			Arc::clone(&logger), &scorer, &Default::default(), &random_seed_bytes
		) {
			assert_eq!(err, "Failed to find a path to the given destination");
		} else { panic!() }
	}

	#[test]
	#[rustfmt::skip]
	fn previously_used_liquidity_violates_max_htlc() {
		do_previously_used_liquidity_violates_max_htlc(true);
		do_previously_used_liquidity_violates_max_htlc(false);

	}
	#[rustfmt::skip]
	fn do_previously_used_liquidity_violates_max_htlc(blinded_payee: bool) {
		// Test that if a candidate first_hop<>route_hint_src_node channel does not have enough
		// contribution amount to cover the next hop's min_htlc plus fees, we will not consider that
		// candidate. In this case, the candidate does not have enough due to a previous path taking up
		// some of its liquidity. Previously we would construct an invalid path and hit a debug panic
		// asserting that the used liquidity for a hop was less than its available liquidity limit.
		let secp_ctx = Secp256k1::new();
		let logger = Arc::new(ln_test_utils::TestLogger::new());
		let network_graph = Arc::new(NetworkGraph::new(Network::Testnet, Arc::clone(&logger)));
		let scorer = ln_test_utils::TestScorer::new();
		let random_seed_bytes = [42; 32];
		let config = UserConfig::default();

		// Values are taken from the fuzz input that uncovered this panic.
		let amt_msat = 52_4288;
		let (_, our_id, _, nodes) = get_nodes(&secp_ctx);
		let first_hops = vec![get_channel_details(
			Some(161), nodes[0], channelmanager::provided_init_features(&config), 486_4000
		), get_channel_details(
			Some(122), nodes[0], channelmanager::provided_init_features(&config), 179_5000
		)];

		let base_fees = [0, 425_9840, 0, 0];
		let htlc_mins = [1_4392, 19_7401, 1027, 6_5535];
		let payment_params = if blinded_payee {
			let mut blinded_hints = Vec::new();
			for (base_fee, htlc_min) in base_fees.iter().zip(htlc_mins.iter()) {
				let blinded_payinfo = BlindedPayInfo {
					fee_base_msat: *base_fee,
					fee_proportional_millionths: 0,
					htlc_minimum_msat: *htlc_min,
					htlc_maximum_msat: htlc_min * 100,
					cltv_expiry_delta: 10,
					features: BlindedHopFeatures::empty(),
				};
				blinded_hints.push(dummy_blinded_path(nodes[0], blinded_payinfo));
			}
			let bolt12_features = channelmanager::provided_bolt12_invoice_features(&config);
			PaymentParameters::blinded(blinded_hints.clone())
				.with_bolt12_features(bolt12_features.clone()).unwrap()
		} else {
			let mut route_hints = Vec::new();
			for (idx, (base_fee, htlc_min)) in base_fees.iter().zip(htlc_mins.iter()).enumerate() {
				route_hints.push(RouteHint(vec![RouteHintHop {
					src_node_id: nodes[0],
					short_channel_id: 42 + idx as u64,
					fees: RoutingFees {
						base_msat: *base_fee,
						proportional_millionths: 0,
					},
					cltv_expiry_delta: 10,
					htlc_minimum_msat: Some(*htlc_min),
					htlc_maximum_msat: Some(htlc_min * 100),
				}]));
			}
			PaymentParameters::from_node_id(nodes[1], 42)
				.with_route_hints(route_hints).unwrap()
				.with_bolt11_features(channelmanager::provided_bolt11_invoice_features(&config)).unwrap()
		};

		let netgraph = network_graph.read_only();
		let route_params = RouteParameters::from_payment_params_and_value(
			payment_params, amt_msat);

		let route = get_route(
			&our_id, &route_params, &netgraph, Some(&first_hops.iter().collect::<Vec<_>>()),
			Arc::clone(&logger), &scorer, &Default::default(), &random_seed_bytes
		).unwrap();
		assert_eq!(route.paths.len(), 1);
		assert_eq!(route.get_total_amount(), amt_msat);
	}

	#[test]
	#[rustfmt::skip]
	fn candidate_path_min() {
		// Test that if a candidate first_hop<>network_node channel does not have enough contribution
		// amount to cover the next channel's min htlc plus fees, we will not consider that candidate.
		// Previously, we were storing RouteGraphNodes with a path_min that did not include fees, and
		// would add a connecting first_hop node that did not have enough contribution amount, leading
		// to a debug panic upon invalid path construction.
		let secp_ctx = Secp256k1::new();
		let logger = Arc::new(ln_test_utils::TestLogger::new());
		let network_graph = Arc::new(NetworkGraph::new(Network::Testnet, Arc::clone(&logger)));
		let gossip_sync = P2PGossipSync::new(Arc::clone(&network_graph), None, Arc::clone(&logger));
		let scorer = ProbabilisticScorer::new(ProbabilisticScoringDecayParameters::default(), Arc::clone(&network_graph), Arc::clone(&logger));
		let random_seed_bytes = [42; 32];
		let config = UserConfig::default();

		// Values are taken from the fuzz input that uncovered this panic.
		let amt_msat = 7_4009_8048;
		let (_, our_id, privkeys, nodes) = get_nodes(&secp_ctx);
		let first_hops = vec![get_channel_details(
			Some(200), nodes[0], channelmanager::provided_init_features(&config), 2_7345_2000
		)];

		add_channel(&gossip_sync, &secp_ctx, &privkeys[0], &privkeys[6], ChannelFeatures::from_le_bytes(id_to_feature_flags(6)), 6);
		update_channel(&gossip_sync, &secp_ctx, &privkeys[0], UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 6,
			timestamp: 1,
			message_flags: 1, // Only must_be_one
			channel_flags: 0,
			cltv_expiry_delta: (6 << 4) | 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		add_or_update_node(&gossip_sync, &secp_ctx, &privkeys[0], NodeFeatures::from_le_bytes(id_to_feature_flags(1)), 0);

		let htlc_min = 2_5165_8240;
		let blinded_hints = vec![
			dummy_blinded_path(nodes[0], BlindedPayInfo {
				fee_base_msat: 1_6778_3453,
				fee_proportional_millionths: 0,
				htlc_minimum_msat: htlc_min,
				htlc_maximum_msat: htlc_min * 100,
				cltv_expiry_delta: 10,
				features: BlindedHopFeatures::empty(),
			})
		];
		let bolt12_features = channelmanager::provided_bolt12_invoice_features(&config);
		let payment_params = PaymentParameters::blinded(blinded_hints.clone())
			.with_bolt12_features(bolt12_features.clone()).unwrap();
		let route_params = RouteParameters::from_payment_params_and_value(
			payment_params, amt_msat);
		let netgraph = network_graph.read_only();

		if let Err(err) = get_route(
			&our_id, &route_params, &netgraph, Some(&first_hops.iter().collect::<Vec<_>>()),
			Arc::clone(&logger), &scorer, &ProbabilisticScoringFeeParameters::default(),
			&random_seed_bytes
		) {
			assert_eq!(err, "Failed to find a path to the given destination");
		} else { panic!() }
	}

	#[test]
	#[rustfmt::skip]
	fn path_contribution_includes_min_htlc_overpay() {
		// Previously, the fuzzer hit a debug panic because we wouldn't include the amount overpaid to
		// meet a last hop's min_htlc in the total collected paths value. We now include this value and
		// also penalize hops along the overpaying path to ensure that it gets deprioritized in path
		// selection, both tested here.
		let secp_ctx = Secp256k1::new();
		let logger = Arc::new(ln_test_utils::TestLogger::new());
		let network_graph = Arc::new(NetworkGraph::new(Network::Testnet, Arc::clone(&logger)));
		let scorer = ProbabilisticScorer::new(ProbabilisticScoringDecayParameters::default(), Arc::clone(&network_graph), Arc::clone(&logger));
		let random_seed_bytes = [42; 32];
		let config = UserConfig::default();

		// Values are taken from the fuzz input that uncovered this panic.
		let amt_msat = 562_0000;
		let (_, our_id, _, nodes) = get_nodes(&secp_ctx);
		let first_hops = vec![
			get_channel_details(
				Some(83), nodes[0], channelmanager::provided_init_features(&config), 2199_0000,
			),
		];

		let htlc_mins = [49_0000, 1125_0000];
		let payment_params = {
			let mut blinded_hints = Vec::new();
			for htlc_min in htlc_mins.iter() {
				let payinfo = BlindedPayInfo {
					fee_base_msat: 0,
					fee_proportional_millionths: 0,
					htlc_minimum_msat: *htlc_min,
					htlc_maximum_msat: *htlc_min * 100,
					cltv_expiry_delta: 10,
					features: BlindedHopFeatures::empty(),
				};
				blinded_hints.push(dummy_blinded_path(nodes[0], payinfo));
			}
			let bolt12_features = channelmanager::provided_bolt12_invoice_features(&config);
			PaymentParameters::blinded(blinded_hints.clone())
				.with_bolt12_features(bolt12_features.clone()).unwrap()
		};

		let netgraph = network_graph.read_only();
		let route_params = RouteParameters::from_payment_params_and_value(
			payment_params, amt_msat);
		let route = get_route(
			&our_id, &route_params, &netgraph, Some(&first_hops.iter().collect::<Vec<_>>()),
			Arc::clone(&logger), &scorer, &ProbabilisticScoringFeeParameters::default(),
			&random_seed_bytes
		).unwrap();
		assert_eq!(route.paths.len(), 1);
		assert_eq!(route.get_total_amount(), amt_msat);
	}

	#[test]
	#[rustfmt::skip]
	fn first_hop_preferred_over_hint() {
		// Check that if we have a first hop to a peer we'd always prefer that over a route hint
		// they gave us, but we'd still consider all subsequent hints if they are more attractive.
		let secp_ctx = Secp256k1::new();
		let logger = Arc::new(ln_test_utils::TestLogger::new());
		let network_graph = Arc::new(NetworkGraph::new(Network::Testnet, Arc::clone(&logger)));
		let gossip_sync = P2PGossipSync::new(Arc::clone(&network_graph), None, Arc::clone(&logger));
		let scorer = ln_test_utils::TestScorer::new();
		let random_seed_bytes = [42; 32];
		let config = UserConfig::default();

		let amt_msat = 1_000_000;
		let (our_privkey, our_node_id, privkeys, nodes) = get_nodes(&secp_ctx);

		add_channel(&gossip_sync, &secp_ctx, &our_privkey, &privkeys[0],
			ChannelFeatures::from_le_bytes(id_to_feature_flags(1)), 1);
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 1,
			timestamp: 1,
			message_flags: 1, // Only must_be_one
			channel_flags: 0,
			cltv_expiry_delta: 42,
			htlc_minimum_msat: 1_000,
			htlc_maximum_msat: 10_000_000,
			fee_base_msat: 800,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[0], UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 1,
			timestamp: 1,
			message_flags: 1, // Only must_be_one
			channel_flags: 1,
			cltv_expiry_delta: 42,
			htlc_minimum_msat: 1_000,
			htlc_maximum_msat: 10_000_000,
			fee_base_msat: 800,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		add_channel(&gossip_sync, &secp_ctx, &privkeys[0], &privkeys[1],
			ChannelFeatures::from_le_bytes(id_to_feature_flags(1)), 2);
		update_channel(&gossip_sync, &secp_ctx, &privkeys[0], UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 2,
			timestamp: 2,
			message_flags: 1, // Only must_be_one
			channel_flags: 0,
			cltv_expiry_delta: 42,
			htlc_minimum_msat: 1_000,
			htlc_maximum_msat: 10_000_000,
			fee_base_msat: 800,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[1], UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 2,
			timestamp: 2,
			message_flags: 1, // Only must_be_one
			channel_flags: 1,
			cltv_expiry_delta: 42,
			htlc_minimum_msat: 1_000,
			htlc_maximum_msat: 10_000_000,
			fee_base_msat: 800,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		let dest_node_id = nodes[2];

		let route_hint = RouteHint(vec![RouteHintHop {
			src_node_id: our_node_id,
			short_channel_id: 44,
			fees: RoutingFees {
				base_msat: 234,
				proportional_millionths: 0,
			},
			cltv_expiry_delta: 10,
			htlc_minimum_msat: None,
			htlc_maximum_msat: Some(5_000_000),
		},
		RouteHintHop {
			src_node_id: nodes[0],
			short_channel_id: 45,
			fees: RoutingFees {
				base_msat: 123,
				proportional_millionths: 0,
			},
			cltv_expiry_delta: 10,
			htlc_minimum_msat: None,
			htlc_maximum_msat: None,
		}]);

		let payment_params = PaymentParameters::from_node_id(dest_node_id, 42)
			.with_route_hints(vec![route_hint]).unwrap()
			.with_bolt11_features(channelmanager::provided_bolt11_invoice_features(&config)).unwrap();
		let route_params = RouteParameters::from_payment_params_and_value(
			payment_params, amt_msat);

		// First create an insufficient first hop for channel with SCID 1 and check we'd use the
		// route hint.
		let first_hop = get_channel_details(Some(1), nodes[0],
			channelmanager::provided_init_features(&config), 999_999);
		let first_hops = vec![first_hop];

		let route = get_route(&our_node_id, &route_params.clone(), &network_graph.read_only(),
			Some(&first_hops.iter().collect::<Vec<_>>()), Arc::clone(&logger), &scorer,
			&Default::default(), &random_seed_bytes).unwrap();
		assert_eq!(route.paths.len(), 1);
		assert_eq!(route.get_total_amount(), amt_msat);
		assert_eq!(route.paths[0].hops.len(), 2);
		assert_eq!(route.paths[0].hops[0].short_channel_id, 44);
		assert_eq!(route.paths[0].hops[1].short_channel_id, 45);
		assert_eq!(route.get_total_fees(), 123);

		// Now check we would trust our first hop info, i.e., fail if we detect the route hint is
		// for a first hop channel.
		let mut first_hop = get_channel_details(Some(1), nodes[0], channelmanager::provided_init_features(&config), 999_999);
		first_hop.outbound_scid_alias = Some(44);
		let first_hops = vec![first_hop];

		let route_res = get_route(&our_node_id, &route_params.clone(), &network_graph.read_only(),
			Some(&first_hops.iter().collect::<Vec<_>>()), Arc::clone(&logger), &scorer,
			&Default::default(), &random_seed_bytes);
		assert!(route_res.is_err());

		// Finally check we'd use the first hop if has sufficient outbound capacity. But we'd stil
		// use the cheaper second hop of the route hint.
		let mut first_hop = get_channel_details(Some(1), nodes[0],
			channelmanager::provided_init_features(&config), 10_000_000);
		first_hop.outbound_scid_alias = Some(44);
		let first_hops = vec![first_hop];

		let route = get_route(&our_node_id, &route_params.clone(), &network_graph.read_only(),
			Some(&first_hops.iter().collect::<Vec<_>>()), Arc::clone(&logger), &scorer,
			&Default::default(), &random_seed_bytes).unwrap();
		assert_eq!(route.paths.len(), 1);
		assert_eq!(route.get_total_amount(), amt_msat);
		assert_eq!(route.paths[0].hops.len(), 2);
		assert_eq!(route.paths[0].hops[0].short_channel_id, 1);
		assert_eq!(route.paths[0].hops[1].short_channel_id, 45);
		assert_eq!(route.get_total_fees(), 123);
	}

	#[test]
	#[rustfmt::skip]
	fn test_max_final_contribution() {
		// When `compute_max_final_value_contribution` was added, it had a bug where it would
		// over-estimate the maximum value contribution of a hop by using `ceil` rather than
		// `floor`. This tests that case by attempting to send 1 million sats over a channel where
		// the remaining hops have a base fee of zero and a proportional fee of 1 millionth.

		let (secp_ctx, network_graph, gossip_sync, _, logger) = build_graph();
		let (our_privkey, our_id, privkeys, nodes) = get_nodes(&secp_ctx);
		let scorer = ln_test_utils::TestScorer::new();
		let random_seed_bytes = [42; 32];

		// Enable channel 1, setting max HTLC to 1M sats
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 1,
			timestamp: 2,
			message_flags: 1, // Only must_be_one
			channel_flags: 0,
			cltv_expiry_delta: (1 << 4) | 1,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 1_000_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		// Set the fee on channel 3 to zero
		update_channel(&gossip_sync, &secp_ctx, &privkeys[0], UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 3,
			timestamp: 2,
			message_flags: 1, // Only must_be_one
			channel_flags: 0,
			cltv_expiry_delta: (3 << 4) | 1,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 1_000_000_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		// Set the fee on channel 6 to 1 millionth
		update_channel(&gossip_sync, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 6,
			timestamp: 2,
			message_flags: 1, // Only must_be_one
			channel_flags: 0,
			cltv_expiry_delta: (6 << 4) | 1,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 1_000_000_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 1,
			excess_data: Vec::new()
		});

		// Now attempt to pay over the channel 1 -> channel 3 -> channel 6 path
		// This should fail as we need to send 1M + 1 sats to cover the fee but channel 1 only
		// allows for 1M sats to flow over it.
		let config = UserConfig::default();
		let payment_params = PaymentParameters::from_node_id(nodes[4], 42)
			.with_bolt11_features(channelmanager::provided_bolt11_invoice_features(&config))
			.unwrap();
		let route_params = RouteParameters::from_payment_params_and_value(payment_params, 1_000_000);
		get_route(&our_id, &route_params, &network_graph.read_only(), None,
			Arc::clone(&logger), &scorer, &Default::default(), &random_seed_bytes).unwrap_err();

		// Now set channel 1 max HTLC to 1M + 1 sats
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 1,
			timestamp: 3,
			message_flags: 1, // Only must_be_one
			channel_flags: 0,
			cltv_expiry_delta: (1 << 4) | 1,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 1_000_001,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		// And attempt the same payment again, but this time it should work.
		let route = get_route(&our_id, &route_params, &network_graph.read_only(), None,
			Arc::clone(&logger), &scorer, &Default::default(), &random_seed_bytes).unwrap();
		assert_eq!(route.paths.len(), 1);
		assert_eq!(route.paths[0].hops.len(), 3);
		assert_eq!(route.paths[0].hops[0].short_channel_id, 1);
		assert_eq!(route.paths[0].hops[1].short_channel_id, 3);
		assert_eq!(route.paths[0].hops[2].short_channel_id, 6);
	}

	#[test]
	#[rustfmt::skip]
	fn allow_us_being_first_hint() {
		// Check that we consider a route hint even if we are the src of the first hop.
		let secp_ctx = Secp256k1::new();
		let logger = Arc::new(ln_test_utils::TestLogger::new());
		let network_graph = Arc::new(NetworkGraph::new(Network::Testnet, Arc::clone(&logger)));
		let scorer = ln_test_utils::TestScorer::new();
		let random_seed_bytes = [42; 32];
		let config = UserConfig::default();

		let (_, our_node_id, _, nodes) = get_nodes(&secp_ctx);

		let amt_msat = 1_000_000;
		let dest_node_id = nodes[1];

		let first_hop = get_channel_details(Some(1), nodes[0], channelmanager::provided_init_features(&config), 10_000_000);
		let first_hops = vec![first_hop];

		let route_hint = RouteHint(vec![RouteHintHop {
			src_node_id: our_node_id,
			short_channel_id: 44,
			fees: RoutingFees {
				base_msat: 123,
				proportional_millionths: 0,
			},
			cltv_expiry_delta: 10,
			htlc_minimum_msat: None,
			htlc_maximum_msat: None,
		}]);

		let payment_params = PaymentParameters::from_node_id(dest_node_id, 42)
			.with_route_hints(vec![route_hint]).unwrap()
			.with_bolt11_features(channelmanager::provided_bolt11_invoice_features(&config)).unwrap();

		let route_params = RouteParameters::from_payment_params_and_value(
			payment_params, amt_msat);


		let route = get_route(&our_node_id, &route_params, &network_graph.read_only(),
			Some(&first_hops.iter().collect::<Vec<_>>()), Arc::clone(&logger), &scorer,
			&Default::default(), &random_seed_bytes).unwrap();

		assert_eq!(route.paths.len(), 1);
		assert_eq!(route.get_total_amount(), amt_msat);
		assert_eq!(route.get_total_fees(), 0);
		assert_eq!(route.paths[0].hops.len(), 1);

		assert_eq!(route.paths[0].hops[0].short_channel_id, 44);
	}

	#[test]
	fn prefers_paths_by_cost_amt_ratio() {
		// Previously, we preferred paths during MPP selection based on their absolute cost, rather
		// than the cost-per-amount-transferred. This could result in selecting many MPP paths with
		// relatively low value contribution, rather than one large path which is ultimately
		// cheaper. While this is a tradeoff (and not universally better), in practice the old
		// behavior was problematic, so we shifted to a proportional cost.
		//
		// Here we check that the proportional cost is being used in a somewhat absurd setup where
		// we have one good path and several cheaper, but smaller paths.
		let (secp_ctx, network_graph, gossip_sync, _, logger) = build_graph();
		let (our_privkey, our_id, privkeys, nodes) = get_nodes(&secp_ctx);
		let scorer = ln_test_utils::TestScorer::new();
		let random_seed_bytes = [42; 32];

		// Enable channel 1
		let update_1 = UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 1,
			timestamp: 2,
			message_flags: 1, // Only must_be_one
			channel_flags: 0,
			cltv_expiry_delta: (1 << 4) | 1,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 10_000_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new(),
		};
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, update_1);

		// Set the fee on channel 3 to 1 sat, max HTLC to 1M msat
		let update_3 = UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 3,
			timestamp: 2,
			message_flags: 1, // Only must_be_one
			channel_flags: 0,
			cltv_expiry_delta: (3 << 4) | 1,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 1_000_000,
			fee_base_msat: 1_000,
			fee_proportional_millionths: 0,
			excess_data: Vec::new(),
		};
		update_channel(&gossip_sync, &secp_ctx, &privkeys[0], update_3);

		// Set the fee on channel 13 to 1 sat, max HTLC to 1M msat
		let update_13 = UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 13,
			timestamp: 2,
			message_flags: 1, // Only must_be_one
			channel_flags: 0,
			cltv_expiry_delta: (13 << 4) | 1,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 1_000_000,
			fee_base_msat: 1_000,
			fee_proportional_millionths: 0,
			excess_data: Vec::new(),
		};
		update_channel(&gossip_sync, &secp_ctx, &privkeys[7], update_13);

		// Set the fee on channel 4 to 1 sat, max HTLC to 1M msat
		let update_4 = UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 4,
			timestamp: 2,
			message_flags: 1, // Only must_be_one
			channel_flags: 0,
			cltv_expiry_delta: (4 << 4) | 1,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 1_000_000,
			fee_base_msat: 1_000,
			fee_proportional_millionths: 0,
			excess_data: Vec::new(),
		};
		update_channel(&gossip_sync, &secp_ctx, &privkeys[1], update_4);

		// The router will attempt to gather 3x the requested amount, and if it finds the new path
		// through channel 16, added below, it'll always prefer that, even prior to the changes
		// which introduced this test.
		// Instead, we add 6 additional channels so that the pathfinder always just gathers useless
		// paths first.
		for i in 0..6 {
			// Finally, create a single channel with fee of 2 sat from node 1 to node 2 which allows
			// for a larger payment.
			let chan_features = ChannelFeatures::from_le_bytes(vec![]);
			add_channel(&gossip_sync, &secp_ctx, &privkeys[7], &privkeys[2], chan_features, i + 42);

			// Set the fee on channel 16 to 2 sats, max HTLC to 3M msat
			let update_a = UnsignedChannelUpdate {
				chain_hash: ChainHash::using_genesis_block(Network::Testnet),
				short_channel_id: i + 42,
				timestamp: 2,
				message_flags: 1, // Only must_be_one
				channel_flags: 0,
				cltv_expiry_delta: (42 << 4) | 1,
				htlc_minimum_msat: 0,
				htlc_maximum_msat: 1_000_000,
				fee_base_msat: 1_000,
				fee_proportional_millionths: 0,
				excess_data: Vec::new(),
			};
			update_channel(&gossip_sync, &secp_ctx, &privkeys[7], update_a);

			// Enable channel 16 by providing an update in both directions
			let update_b = UnsignedChannelUpdate {
				chain_hash: ChainHash::using_genesis_block(Network::Testnet),
				short_channel_id: i + 42,
				timestamp: 2,
				message_flags: 1, // Only must_be_one
				channel_flags: 1,
				cltv_expiry_delta: (42 << 4) | 1,
				htlc_minimum_msat: 0,
				htlc_maximum_msat: 10_000_000,
				fee_base_msat: u32::MAX,
				fee_proportional_millionths: 0,
				excess_data: Vec::new(),
			};
			update_channel(&gossip_sync, &secp_ctx, &privkeys[2], update_b);
		}

		// Ensure that we can build a route for 3M msat across the three paths to node 2.
		let config = UserConfig::default();
		let mut payment_params = PaymentParameters::from_node_id(nodes[2], 42)
			.with_bolt11_features(channelmanager::provided_bolt11_invoice_features(&config))
			.unwrap();
		payment_params.max_channel_saturation_power_of_half = 0;
		let route_params =
			RouteParameters::from_payment_params_and_value(payment_params, 3_000_000);
		let route = get_route(
			&our_id,
			&route_params,
			&network_graph.read_only(),
			None,
			Arc::clone(&logger),
			&scorer,
			&Default::default(),
			&random_seed_bytes,
		)
		.unwrap();
		assert_eq!(route.paths.len(), 3);
		for path in route.paths {
			assert_eq!(path.hops.len(), 2);
		}

		// Finally, create a single channel with fee of 2 sat from node 1 to node 2 which allows
		// for a larger payment.
		let features_16 = ChannelFeatures::from_le_bytes(id_to_feature_flags(16));
		add_channel(&gossip_sync, &secp_ctx, &privkeys[1], &privkeys[2], features_16, 16);

		// Set the fee on channel 16 to 2 sats, max HTLC to 3M msat
		let update_16_a = UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 16,
			timestamp: 2,
			message_flags: 1, // Only must_be_one
			channel_flags: 0,
			cltv_expiry_delta: (16 << 4) | 1,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 3_000_000,
			fee_base_msat: 2_000,
			fee_proportional_millionths: 0,
			excess_data: Vec::new(),
		};
		update_channel(&gossip_sync, &secp_ctx, &privkeys[1], update_16_a);

		// Enable channel 16 by providing an update in both directions
		let update_16_b = UnsignedChannelUpdate {
			chain_hash: ChainHash::using_genesis_block(Network::Testnet),
			short_channel_id: 16,
			timestamp: 2,
			message_flags: 1, // Only must_be_one
			channel_flags: 1,
			cltv_expiry_delta: (16 << 4) | 1,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 10_000_000,
			fee_base_msat: u32::MAX,
			fee_proportional_millionths: 0,
			excess_data: Vec::new(),
		};
		update_channel(&gossip_sync, &secp_ctx, &privkeys[2], update_16_b);

		// Ensure that we now build a route for 3M msat across just the new path
		let route = get_route(
			&our_id,
			&route_params,
			&network_graph.read_only(),
			None,
			Arc::clone(&logger),
			&scorer,
			&Default::default(),
			&random_seed_bytes,
		)
		.unwrap();
		assert_eq!(route.paths.len(), 1);
		assert_eq!(route.paths[0].hops.len(), 2);
		assert_eq!(route.paths[0].hops[1].short_channel_id, 16);
	}
}

#[cfg(any(test, ldk_bench))]
pub(crate) mod bench_utils {
	use super::*;
	use bitcoin::hashes::Hash;
	use bitcoin::secp256k1::SecretKey;
	use std::fs::File;
	use std::io::Read;

	use crate::chain::transaction::OutPoint;
	use crate::ln::channel_state::{ChannelCounterparty, ChannelShutdownState};
	use crate::ln::channelmanager;
	use crate::ln::types::ChannelId;
	use crate::routing::scoring::{ProbabilisticScorer, ScoreUpdate};
	use crate::sync::Arc;
	use crate::util::config::UserConfig;
	use crate::util::test_utils::TestLogger;

	/// Tries to open a network graph file, or panics with a URL to fetch it.
	#[rustfmt::skip]
	pub(crate) fn get_graph_scorer_file() -> Result<(std::fs::File, std::fs::File), &'static str> {
		let load_file = |fname, err_str| {
			File::open(fname) // By default we're run in RL/lightning
				.or_else(|_| File::open(&format!("lightning/{}", fname))) // We may be run manually in RL/
				.or_else(|_| { // Fall back to guessing based on the binary location
					// path is likely something like .../rust-lightning/target/debug/deps/lightning-...
					let mut path = std::env::current_exe().unwrap();
					path.pop(); // lightning-...
					path.pop(); // deps
					path.pop(); // debug
					path.pop(); // target
					path.push("lightning");
					path.push(fname);
					File::open(path)
				})
				.or_else(|_| { // Fall back to guessing based on the binary location for a subcrate
					// path is likely something like .../rust-lightning/bench/target/debug/deps/bench..
					let mut path = std::env::current_exe().unwrap();
					path.pop(); // bench...
					path.pop(); // deps
					path.pop(); // debug
					path.pop(); // target
					path.pop(); // bench
					path.push("lightning");
					path.push(fname);
					File::open(path)
				})
			.map_err(|_| err_str)
		};
		let graph_res = load_file(
			"net_graph-2023-12-10.bin",
			"Please fetch https://bitcoin.ninja/ldk-net_graph-v0.0.118-2023-12-10.bin and place it at lightning/net_graph-2023-12-10.bin"
		);
		let scorer_res = load_file(
			"scorer-2023-12-10.bin",
			"Please fetch https://bitcoin.ninja/ldk-scorer-v0.0.118-2023-12-10.bin and place it at lightning/scorer-2023-12-10.bin"
		);
		#[cfg(require_route_graph_test)]
		return Ok((graph_res.unwrap(), scorer_res.unwrap()));
		#[cfg(not(require_route_graph_test))]
		return Ok((graph_res?, scorer_res?));
	}

	pub(crate) fn read_graph_scorer(
		logger: &TestLogger,
	) -> Result<
		(
			Arc<NetworkGraph<&TestLogger>>,
			ProbabilisticScorer<Arc<NetworkGraph<&TestLogger>>, &TestLogger>,
		),
		&'static str,
	> {
		let (mut graph_file, mut scorer_file) = get_graph_scorer_file()?;
		let mut graph_buffer = Vec::new();
		let mut scorer_buffer = Vec::new();
		graph_file.read_to_end(&mut graph_buffer).unwrap();
		scorer_file.read_to_end(&mut scorer_buffer).unwrap();
		let graph = Arc::new(NetworkGraph::read(&mut &graph_buffer[..], logger).unwrap());
		let scorer_args = (Default::default(), Arc::clone(&graph), logger);
		let scorer = ProbabilisticScorer::read(&mut &scorer_buffer[..], scorer_args).unwrap();
		Ok((graph, scorer))
	}

	pub(crate) fn payer_pubkey() -> PublicKey {
		let secp_ctx = Secp256k1::new();
		PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[42; 32]).unwrap())
	}

	#[inline]
	#[rustfmt::skip]
	pub(crate) fn first_hop(node_id: PublicKey) -> ChannelDetails {
		#[allow(deprecated)] // TODO: Remove once balance_msat is removed.
		ChannelDetails {
			channel_id: ChannelId::new_zero(),
			counterparty: ChannelCounterparty {
				features: channelmanager::provided_init_features(&UserConfig::default()),
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
			channel_value_satoshis: 10_000_000_000,
			user_channel_id: 0,
			outbound_capacity_msat: 10_000_000_000,
			next_outbound_htlc_minimum_msat: 0,
			next_outbound_htlc_limit_msat: 10_000_000_000,
			inbound_capacity_msat: 0,
			unspendable_punishment_reserve: None,
			confirmations_required: None,
			confirmations: None,
			force_close_spend_delay: None,
			is_outbound: true,
			is_channel_ready: true,
			is_usable: true,
			is_announced: true,
			inbound_htlc_minimum_msat: None,
			inbound_htlc_maximum_msat: None,
			config: None,
			feerate_sat_per_1000_weight: None,
			channel_shutdown_state: Some(ChannelShutdownState::NotShuttingDown),
			pending_inbound_htlcs: Vec::new(),
			pending_outbound_htlcs: Vec::new(),
		}
	}

	#[rustfmt::skip]
	pub(crate) fn generate_test_routes<S: ScoreLookUp + ScoreUpdate>(graph: &NetworkGraph<&TestLogger>, scorer: &mut S,
		score_params: &S::ScoreParams, features: Bolt11InvoiceFeatures, mut seed: u64,
		starting_amount: u64, route_count: usize,
	) -> Vec<(ChannelDetails, PaymentParameters, u64)> {
		let payer = payer_pubkey();
		let random_seed_bytes = [42; 32];

		let mut nodes = graph.read_only().nodes().clone();
		let mut route_endpoints = Vec::new();
		for _ in 0..route_count {
			loop {
				seed = seed.overflowing_mul(6364136223846793005).0.overflowing_add(1).0;
				let src_idx = (seed as usize) % nodes.len();
				let src_key = nodes.range(..).skip(src_idx).next().unwrap().0;
				let src = PublicKey::from_slice(src_key.as_slice()).unwrap();

				seed = seed.overflowing_mul(6364136223846793005).0.overflowing_add(1).0;
				let dst_idx = (seed as usize) % nodes.len();
				let dst_key = nodes.range(..).skip(dst_idx).next().unwrap().0;
				let dst = PublicKey::from_slice(dst_key.as_slice()).unwrap();

				let params = PaymentParameters::from_node_id(dst, 42)
					.with_bolt11_features(features.clone()).unwrap();
				let first_hop = first_hop(src);
				let amt_msat = starting_amount + seed % 1_000_000;
				let route_params = RouteParameters::from_payment_params_and_value(
					params.clone(), amt_msat);
				let path_exists =
					get_route(&payer, &route_params, &graph.read_only(), Some(&[&first_hop]),
						&TestLogger::new(), scorer, score_params, &random_seed_bytes).is_ok();
				if path_exists {
					route_endpoints.push((first_hop, params, amt_msat));
					break;
				}
			}
		}

		route_endpoints
	}
}

#[cfg(ldk_bench)]
pub mod benches {
	use super::*;
	use crate::ln::channelmanager;
	use crate::routing::gossip::NetworkGraph;
	use crate::routing::scoring::{FixedPenaltyScorer, ProbabilisticScoringFeeParameters};
	use crate::routing::scoring::{ScoreLookUp, ScoreUpdate};
	use crate::types::features::Bolt11InvoiceFeatures;
	use crate::util::config::UserConfig;
	use crate::util::logger::{Logger, Record};
	use crate::util::test_utils::TestLogger;

	use criterion::Criterion;

	struct DummyLogger {}
	impl Logger for DummyLogger {
		fn log(&self, _record: Record) {}
	}

	#[rustfmt::skip]
	pub fn generate_routes_with_zero_penalty_scorer(bench: &mut Criterion) {
		let logger = TestLogger::new();
		let (network_graph, _) = bench_utils::read_graph_scorer(&logger).unwrap();
		let scorer = FixedPenaltyScorer::with_penalty(0);
		generate_routes(bench, &network_graph, scorer, &Default::default(),
			Bolt11InvoiceFeatures::empty(), 0, "generate_routes_with_zero_penalty_scorer");
	}

	#[rustfmt::skip]
	pub fn generate_mpp_routes_with_zero_penalty_scorer(bench: &mut Criterion) {
		let logger = TestLogger::new();
		let (network_graph, _) = bench_utils::read_graph_scorer(&logger).unwrap();
		let scorer = FixedPenaltyScorer::with_penalty(0);
		generate_routes(bench, &network_graph, scorer, &Default::default(),
			channelmanager::provided_bolt11_invoice_features(&UserConfig::default()), 0,
			"generate_mpp_routes_with_zero_penalty_scorer");
	}

	#[rustfmt::skip]
	pub fn generate_routes_with_probabilistic_scorer(bench: &mut Criterion) {
		let logger = TestLogger::new();
		let (network_graph, scorer) = bench_utils::read_graph_scorer(&logger).unwrap();
		let params = ProbabilisticScoringFeeParameters::default();
		generate_routes(bench, &network_graph, scorer, &params, Bolt11InvoiceFeatures::empty(), 0,
			"generate_routes_with_probabilistic_scorer");
	}

	#[rustfmt::skip]
	pub fn generate_mpp_routes_with_probabilistic_scorer(bench: &mut Criterion) {
		let logger = TestLogger::new();
		let (network_graph, scorer) = bench_utils::read_graph_scorer(&logger).unwrap();
		let params = ProbabilisticScoringFeeParameters::default();
		generate_routes(bench, &network_graph, scorer, &params,
			channelmanager::provided_bolt11_invoice_features(&UserConfig::default()), 0,
			"generate_mpp_routes_with_probabilistic_scorer");
	}

	#[rustfmt::skip]
	pub fn generate_large_mpp_routes_with_probabilistic_scorer(bench: &mut Criterion) {
		let logger = TestLogger::new();
		let (network_graph, scorer) = bench_utils::read_graph_scorer(&logger).unwrap();
		let params = ProbabilisticScoringFeeParameters::default();
		generate_routes(bench, &network_graph, scorer, &params,
			channelmanager::provided_bolt11_invoice_features(&UserConfig::default()), 100_000_000,
			"generate_large_mpp_routes_with_probabilistic_scorer");
	}

	#[rustfmt::skip]
	pub fn generate_routes_with_nonlinear_probabilistic_scorer(bench: &mut Criterion) {
		let logger = TestLogger::new();
		let (network_graph, scorer) = bench_utils::read_graph_scorer(&logger).unwrap();
		let mut params = ProbabilisticScoringFeeParameters::default();
		params.linear_success_probability = false;
		generate_routes(bench, &network_graph, scorer, &params,
			channelmanager::provided_bolt11_invoice_features(&UserConfig::default()), 0,
			"generate_routes_with_nonlinear_probabilistic_scorer");
	}

	#[rustfmt::skip]
	pub fn generate_mpp_routes_with_nonlinear_probabilistic_scorer(bench: &mut Criterion) {
		let logger = TestLogger::new();
		let (network_graph, scorer) = bench_utils::read_graph_scorer(&logger).unwrap();
		let mut params = ProbabilisticScoringFeeParameters::default();
		params.linear_success_probability = false;
		generate_routes(bench, &network_graph, scorer, &params,
			channelmanager::provided_bolt11_invoice_features(&UserConfig::default()), 0,
			"generate_mpp_routes_with_nonlinear_probabilistic_scorer");
	}

	#[rustfmt::skip]
	pub fn generate_large_mpp_routes_with_nonlinear_probabilistic_scorer(bench: &mut Criterion) {
		let logger = TestLogger::new();
		let (network_graph, scorer) = bench_utils::read_graph_scorer(&logger).unwrap();
		let mut params = ProbabilisticScoringFeeParameters::default();
		params.linear_success_probability = false;
		generate_routes(bench, &network_graph, scorer, &params,
			channelmanager::provided_bolt11_invoice_features(&UserConfig::default()), 100_000_000,
			"generate_large_mpp_routes_with_nonlinear_probabilistic_scorer");
	}

	#[rustfmt::skip]
	fn generate_routes<S: ScoreLookUp + ScoreUpdate>(
		bench: &mut Criterion, graph: &NetworkGraph<&TestLogger>, mut scorer: S,
		score_params: &S::ScoreParams, features: Bolt11InvoiceFeatures, starting_amount: u64,
		bench_name: &'static str,
	) {
		// First, get 100 (source, destination) pairs for which route-getting actually succeeds...
		let route_endpoints = bench_utils::generate_test_routes(graph, &mut scorer, score_params, features, 0xdeadbeef, starting_amount, 50);

		// ...then benchmark finding paths between the nodes we learned.
		do_route_bench(bench, graph, scorer, score_params, bench_name, route_endpoints);
	}

	#[inline(never)]
	#[rustfmt::skip]
	fn do_route_bench<S: ScoreLookUp + ScoreUpdate>(
		bench: &mut Criterion, graph: &NetworkGraph<&TestLogger>, scorer: S,
		score_params: &S::ScoreParams, bench_name: &'static str,
		route_endpoints: Vec<(ChannelDetails, PaymentParameters, u64)>,
	) {
		let payer = bench_utils::payer_pubkey();
		let random_seed_bytes = [42; 32];

		let mut idx = 0;
		bench.bench_function(bench_name, |b| b.iter(|| {
			let (first_hop, params, amt) = &route_endpoints[idx % route_endpoints.len()];
			let route_params = RouteParameters::from_payment_params_and_value(params.clone(), *amt);
			assert!(get_route(&payer, &route_params, &graph.read_only(), Some(&[first_hop]),
				&DummyLogger{}, &scorer, score_params, &random_seed_bytes).is_ok());
			idx += 1;
		}));
	}
}
