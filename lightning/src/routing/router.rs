// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! The router finds paths within a [`NetworkGraph`] for a payment.

use bitcoin::secp256k1::PublicKey;
use bitcoin::hashes::Hash;
use bitcoin::hashes::sha256::Hash as Sha256;

use crate::blinded_path::{BlindedHop, BlindedPath};
use crate::ln::PaymentHash;
use crate::ln::channelmanager::{ChannelDetails, PaymentId};
use crate::ln::features::{Bolt11InvoiceFeatures, Bolt12InvoiceFeatures, ChannelFeatures, NodeFeatures};
use crate::ln::msgs::{DecodeError, ErrorAction, LightningError, MAX_VALUE_MSAT};
use crate::offers::invoice::{BlindedPayInfo, Bolt12Invoice};
use crate::routing::gossip::{DirectedChannelInfo, EffectiveCapacity, ReadOnlyNetworkGraph, NetworkGraph, NodeId, RoutingFees};
use crate::routing::scoring::{ChannelUsage, LockableScore, Score};
use crate::util::ser::{Writeable, Readable, ReadableArgs, Writer};
use crate::util::logger::{Level, Logger};
use crate::util::chacha20::ChaCha20;

use crate::io;
use crate::prelude::*;
use crate::sync::{Mutex};
use alloc::collections::BinaryHeap;
use core::{cmp, fmt};
use core::ops::{Deref, DerefMut};

/// A [`Router`] implemented using [`find_route`].
pub struct DefaultRouter<G: Deref<Target = NetworkGraph<L>>, L: Deref, S: Deref, SP: Sized, Sc: Score<ScoreParams = SP>> where
	L::Target: Logger,
	S::Target: for <'a> LockableScore<'a, Score = Sc>,
{
	network_graph: G,
	logger: L,
	random_seed_bytes: Mutex<[u8; 32]>,
	scorer: S,
	score_params: SP
}

impl<G: Deref<Target = NetworkGraph<L>>, L: Deref, S: Deref, SP: Sized, Sc: Score<ScoreParams = SP>> DefaultRouter<G, L, S, SP, Sc> where
	L::Target: Logger,
	S::Target: for <'a> LockableScore<'a, Score = Sc>,
{
	/// Creates a new router.
	pub fn new(network_graph: G, logger: L, random_seed_bytes: [u8; 32], scorer: S, score_params: SP) -> Self {
		let random_seed_bytes = Mutex::new(random_seed_bytes);
		Self { network_graph, logger, random_seed_bytes, scorer, score_params }
	}
}

impl< G: Deref<Target = NetworkGraph<L>>, L: Deref, S: Deref, SP: Sized, Sc: Score<ScoreParams = SP>> Router for DefaultRouter<G, L, S, SP, Sc> where
	L::Target: Logger,
	S::Target: for <'a> LockableScore<'a, Score = Sc>,
{
	fn find_route(
		&self,
		payer: &PublicKey,
		params: &RouteParameters,
		first_hops: Option<&[&ChannelDetails]>,
		inflight_htlcs: InFlightHtlcs
	) -> Result<Route, LightningError> {
		let random_seed_bytes = {
			let mut locked_random_seed_bytes = self.random_seed_bytes.lock().unwrap();
			*locked_random_seed_bytes = Sha256::hash(&*locked_random_seed_bytes).into_inner();
			*locked_random_seed_bytes
		};
		find_route(
			payer, params, &self.network_graph, first_hops, &*self.logger,
			&ScorerAccountingForInFlightHtlcs::new(self.scorer.lock().deref_mut(), &inflight_htlcs),
			&self.score_params,
			&random_seed_bytes
		)
	}
}

/// A trait defining behavior for routing a payment.
pub trait Router {
	/// Finds a [`Route`] for a payment between the given `payer` and a payee.
	///
	/// The `payee` and the payment's value are given in [`RouteParameters::payment_params`]
	/// and [`RouteParameters::final_value_msat`], respectively.
	fn find_route(
		&self, payer: &PublicKey, route_params: &RouteParameters,
		first_hops: Option<&[&ChannelDetails]>, inflight_htlcs: InFlightHtlcs
	) -> Result<Route, LightningError>;
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
		_payment_hash: PaymentHash, _payment_id: PaymentId
	) -> Result<Route, LightningError> {
		self.find_route(payer, route_params, first_hops, inflight_htlcs)
	}
}

/// [`Score`] implementation that factors in in-flight HTLC liquidity.
///
/// Useful for custom [`Router`] implementations to wrap their [`Score`] on-the-fly when calling
/// [`find_route`].
///
/// [`Score`]: crate::routing::scoring::Score
pub struct ScorerAccountingForInFlightHtlcs<'a, S: Score<ScoreParams = SP>, SP: Sized> {
	scorer: &'a mut S,
	// Maps a channel's short channel id and its direction to the liquidity used up.
	inflight_htlcs: &'a InFlightHtlcs,
}

impl<'a, S: Score<ScoreParams = SP>, SP: Sized> ScorerAccountingForInFlightHtlcs<'a, S, SP> {
	/// Initialize a new `ScorerAccountingForInFlightHtlcs`.
	pub fn new(scorer: &'a mut S, inflight_htlcs: &'a InFlightHtlcs) -> Self {
		ScorerAccountingForInFlightHtlcs {
			scorer,
			inflight_htlcs
		}
	}
}

#[cfg(c_bindings)]
impl<'a, S: Score<ScoreParams = SP>, SP: Sized> Writeable for ScorerAccountingForInFlightHtlcs<'a, S, SP> {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> { self.scorer.write(writer) }
}

impl<'a, S: Score<ScoreParams = SP>, SP: Sized> Score for ScorerAccountingForInFlightHtlcs<'a, S, SP>  {
	type ScoreParams = S::ScoreParams;
	fn channel_penalty_msat(&self, short_channel_id: u64, source: &NodeId, target: &NodeId, usage: ChannelUsage, score_params: &Self::ScoreParams) -> u64 {
		if let Some(used_liquidity) = self.inflight_htlcs.used_liquidity_msat(
			source, target, short_channel_id
		) {
			let usage = ChannelUsage {
				inflight_htlc_msat: usage.inflight_htlc_msat + used_liquidity,
				..usage
			};

			self.scorer.channel_penalty_msat(short_channel_id, source, target, usage, score_params)
		} else {
			self.scorer.channel_penalty_msat(short_channel_id, source, target, usage, score_params)
		}
	}

	fn payment_path_failed(&mut self, path: &Path, short_channel_id: u64) {
		self.scorer.payment_path_failed(path, short_channel_id)
	}

	fn payment_path_successful(&mut self, path: &Path) {
		self.scorer.payment_path_successful(path)
	}

	fn probe_failed(&mut self, path: &Path, short_channel_id: u64) {
		self.scorer.probe_failed(path, short_channel_id)
	}

	fn probe_successful(&mut self, path: &Path) {
		self.scorer.probe_successful(path)
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
	HashMap<(u64, bool), u64>
);

impl InFlightHtlcs {
	/// Constructs an empty `InFlightHtlcs`.
	pub fn new() -> Self { InFlightHtlcs(HashMap::new()) }

	/// Takes in a path with payer's node id and adds the path's details to `InFlightHtlcs`.
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
	pub fn add_inflight_htlc(&mut self, source: &NodeId, target: &NodeId, channel_scid: u64, used_msat: u64){
		self.0
			.entry((channel_scid, source < target))
			.and_modify(|used_liquidity_msat| *used_liquidity_msat += used_msat)
			.or_insert(used_msat);
	}

	/// Returns liquidity in msat given the public key of the HTLC source, target, and short channel
	/// id.
	pub fn used_liquidity_msat(&self, source: &NodeId, target: &NodeId, channel_scid: u64) -> Option<u64> {
		self.0.get(&(channel_scid, source < target)).map(|v| *v)
	}
}

impl Writeable for InFlightHtlcs {
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
	/// * if we're sending to a [`BlindedPath`], this is the fee paid for use of the entire blinded path
	/// * otherwise, this is the full value of this [`Path`]'s part of the payment
	///
	/// [`BlindedPath`]: crate::blinded_path::BlindedPath
	pub fee_msat: u64,
	/// The CLTV delta added for this hop.
	/// If this is the last hop in [`Path::hops`]:
	/// * if we're sending to a [`BlindedPath`], this is the CLTV delta for the entire blinded path
	/// * otherwise, this is the CLTV delta expected at the destination
	///
	/// [`BlindedPath`]: crate::blinded_path::BlindedPath
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

/// The blinded portion of a [`Path`], if we're routing to a recipient who provided blinded paths in
/// their [`Bolt12Invoice`].
///
/// [`Bolt12Invoice`]: crate::offers::invoice::Bolt12Invoice
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct BlindedTail {
	/// The hops of the [`BlindedPath`] provided by the recipient.
	///
	/// [`BlindedPath`]: crate::blinded_path::BlindedPath
	pub hops: Vec<BlindedHop>,
	/// The blinding point of the [`BlindedPath`] provided by the recipient.
	///
	/// [`BlindedPath`]: crate::blinded_path::BlindedPath
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
	pub fn final_value_msat(&self) -> u64 {
		match &self.blinded_tail {
			Some(blinded_tail) => blinded_tail.final_value_msat,
			None => self.hops.last().map_or(0, |hop| hop.fee_msat)
		}
	}

	/// Gets the final hop's CLTV expiry delta.
	pub fn final_cltv_expiry_delta(&self) -> Option<u32> {
		match &self.blinded_tail {
			Some(_) => None,
			None => self.hops.last().map(|hop| hop.cltv_expiry_delta)
		}
	}
}

/// A route directs a payment from the sender (us) to the recipient. If the recipient supports MPP,
/// it can take multiple paths. Each path is composed of one or more hops through the network.
#[derive(Clone, Hash, PartialEq, Eq)]
pub struct Route {
	/// The list of [`Path`]s taken for a single (potentially-)multi-part payment. If no
	/// [`BlindedTail`]s are present, then the pubkey of the last [`RouteHop`] in each path must be
	/// the same.
	pub paths: Vec<Path>,
	/// The `payment_params` parameter passed via [`RouteParameters`] to [`find_route`].
	///
	/// This is used by `ChannelManager` to track information which may be required for retries.
	pub payment_params: Option<PaymentParameters>,
}

impl Route {
	/// Returns the total amount of fees paid on this [`Route`].
	///
	/// This doesn't include any extra payment made to the recipient, which can happen in excess of
	/// the amount passed to [`find_route`]'s `route_params.final_value_msat`.
	pub fn get_total_fees(&self) -> u64 {
		self.paths.iter().map(|path| path.fee_msat()).sum()
	}

	/// Returns the total amount paid on this [`Route`], excluding the fees. Might be more than
	/// requested if we had to reach htlc_minimum_msat.
	pub fn get_total_amount(&self) -> u64 {
		self.paths.iter().map(|path| path.final_value_msat()).sum()
	}
}

const SERIALIZATION_VERSION: u8 = 1;
const MIN_SERIALIZATION_VERSION: u8 = 1;

impl Writeable for Route {
	fn write<W: crate::util::ser::Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		write_ver_prefix!(writer, SERIALIZATION_VERSION, MIN_SERIALIZATION_VERSION);
		(self.paths.len() as u64).write(writer)?;
		let mut blinded_tails = Vec::new();
		for path in self.paths.iter() {
			(path.hops.len() as u8).write(writer)?;
			for (idx, hop) in path.hops.iter().enumerate() {
				hop.write(writer)?;
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
		}
		write_tlv_fields!(writer, {
			(1, self.payment_params, option),
			(2, blinded_tails, optional_vec),
		});
		Ok(())
	}
}

impl Readable for Route {
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
		});
		let blinded_tails = blinded_tails.unwrap_or(Vec::new());
		if blinded_tails.len() != 0 {
			if blinded_tails.len() != paths.len() { return Err(DecodeError::InvalidValue) }
			for (path, blinded_tail_opt) in paths.iter_mut().zip(blinded_tails.into_iter()) {
				path.blinded_tail = blinded_tail_opt;
			}
		}
		Ok(Route { paths, payment_params })
	}
}

/// Parameters needed to find a [`Route`].
///
/// Passed to [`find_route`] and [`build_route_from_hops`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteParameters {
	/// The parameters of the failed payment path.
	pub payment_params: PaymentParameters,

	/// The amount in msats sent on the failed payment path.
	pub final_value_msat: u64,
}

impl Writeable for RouteParameters {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		write_tlv_fields!(writer, {
			(0, self.payment_params, required),
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
const MAX_PATH_LENGTH_ESTIMATE: u8 = 19;

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
}

impl Writeable for PaymentParameters {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		let mut clear_hints = &vec![];
		let mut blinded_hints = &vec![];
		match &self.payee {
			Payee::Clear { route_hints, .. } => clear_hints = route_hints,
			Payee::Blinded { route_hints, .. } => blinded_hints = route_hints,
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
			(8, *blinded_hints, optional_vec),
			(9, self.payee.final_cltv_expiry_delta(), option),
		});
		Ok(())
	}
}

impl ReadableArgs<u32> for PaymentParameters {
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
		});
		let blinded_route_hints = blinded_route_hints.unwrap_or(vec![]);
		let payee = if blinded_route_hints.len() != 0 {
			if clear_route_hints.len() != 0 || payee_pubkey.is_some() { return Err(DecodeError::InvalidValue) }
			Payee::Blinded {
				route_hints: blinded_route_hints,
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
		})
	}
}


impl PaymentParameters {
	/// Creates a payee with the node id of the given `pubkey`.
	///
	/// The `final_cltv_expiry_delta` should match the expected final CLTV delta the recipient has
	/// provided.
	pub fn from_node_id(payee_pubkey: PublicKey, final_cltv_expiry_delta: u32) -> Self {
		Self {
			payee: Payee::Clear { node_id: payee_pubkey, route_hints: vec![], features: None, final_cltv_expiry_delta },
			expiry_time: None,
			max_total_cltv_expiry_delta: DEFAULT_MAX_TOTAL_CLTV_EXPIRY_DELTA,
			max_path_count: DEFAULT_MAX_PATH_COUNT,
			max_channel_saturation_power_of_half: DEFAULT_MAX_CHANNEL_SATURATION_POW_HALF,
			previously_failed_channels: Vec::new(),
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
	pub fn for_keysend(payee_pubkey: PublicKey, final_cltv_expiry_delta: u32, allow_mpp: bool) -> Self {
		Self::from_node_id(payee_pubkey, final_cltv_expiry_delta)
			.with_bolt11_features(Bolt11InvoiceFeatures::for_keysend(allow_mpp))
			.expect("PaymentParameters::from_node_id should always initialize the payee as unblinded")
	}

	/// Creates parameters for paying to a blinded payee from the provided invoice. Sets
	/// [`Payee::Blinded::route_hints`], [`Payee::Blinded::features`], and
	/// [`PaymentParameters::expiry_time`].
	pub fn from_bolt12_invoice(invoice: &Bolt12Invoice) -> Self {
		Self::blinded(invoice.payment_paths().to_vec())
			.with_bolt12_features(invoice.invoice_features().clone()).unwrap()
			.with_expiry_time(invoice.created_at().as_secs().saturating_add(invoice.relative_expiry().as_secs()))
	}

	/// Creates parameters for paying to a blinded payee from the provided blinded route hints.
	pub fn blinded(blinded_route_hints: Vec<(BlindedPayInfo, BlindedPath)>) -> Self {
		Self {
			payee: Payee::Blinded { route_hints: blinded_route_hints, features: None },
			expiry_time: None,
			max_total_cltv_expiry_delta: DEFAULT_MAX_TOTAL_CLTV_EXPIRY_DELTA,
			max_path_count: DEFAULT_MAX_PATH_COUNT,
			max_channel_saturation_power_of_half: DEFAULT_MAX_CHANNEL_SATURATION_POW_HALF,
			previously_failed_channels: Vec::new(),
		}
	}

	/// Includes the payee's features. Errors if the parameters were not initialized with
	/// [`PaymentParameters::from_bolt12_invoice`].
	///
	/// This is not exported to bindings users since bindings don't support move semantics
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
	pub fn with_max_channel_saturation_power_of_half(self, max_channel_saturation_power_of_half: u8) -> Self {
		Self { max_channel_saturation_power_of_half, ..self }
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
		route_hints: Vec<(BlindedPayInfo, BlindedPath)>,
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
	fn blinded_route_hints(&self) -> &[(BlindedPayInfo, BlindedPath)] {
		match self {
			Self::Blinded { route_hints, .. } => &route_hints[..],
			Self::Clear { .. } => &[]
		}
	}

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
	fn read<R: io::Read>(reader: &mut R, bolt11: bool) -> Result<Self, DecodeError> {
		if bolt11 { return Ok(Self::Bolt11(Readable::read(reader)?)) }
		Ok(Self::Bolt12(Readable::read(reader)?))
	}
}

/// A list of hops along a payment path terminating with a channel to the recipient.
#[derive(Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct RouteHint(pub Vec<RouteHintHop>);

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

/// A channel descriptor for a hop along a payment path.
#[derive(Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd)]
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
		let other_score = cmp::max(other.lowest_fee_to_node, other.path_htlc_minimum_msat)
			.saturating_add(other.path_penalty_msat);
		let self_score = cmp::max(self.lowest_fee_to_node, self.path_htlc_minimum_msat)
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
	/// A hop found in the [`ReadOnlyNetworkGraph`], where the channel capacity may be unknown.
	PublicHop {
		info: DirectedChannelInfo<'a>,
		short_channel_id: u64,
	},
	/// A hop to the payee found in the BOLT 11 payment invoice, though not necessarily a direct
	/// channel.
	PrivateHop {
		hint: &'a RouteHintHop,
	},
	/// The payee's identity is concealed behind blinded paths provided in a BOLT 12 invoice.
	Blinded {
		hint: &'a (BlindedPayInfo, BlindedPath),
		hint_idx: usize,
	},
	/// Similar to [`Self::Blinded`], but the path here has 1 blinded hop. `BlindedPayInfo` provided
	/// for 1-hop blinded paths is ignored because it is meant to apply to the hops *between* the
	/// introduction node and the destination. Useful for tracking that we need to include a blinded
	/// path at the end of our [`Route`].
	OneHopBlinded {
		hint: &'a (BlindedPayInfo, BlindedPath),
		hint_idx: usize,
	},
}

impl<'a> CandidateRouteHop<'a> {
	fn short_channel_id(&self) -> Option<u64> {
		match self {
			CandidateRouteHop::FirstHop { details } => Some(details.get_outbound_payment_scid().unwrap()),
			CandidateRouteHop::PublicHop { short_channel_id, .. } => Some(*short_channel_id),
			CandidateRouteHop::PrivateHop { hint } => Some(hint.short_channel_id),
			CandidateRouteHop::Blinded { .. } => None,
			CandidateRouteHop::OneHopBlinded { .. } => None,
		}
	}

	// NOTE: This may alloc memory so avoid calling it in a hot code path.
	fn features(&self) -> ChannelFeatures {
		match self {
			CandidateRouteHop::FirstHop { details } => details.counterparty.features.to_context(),
			CandidateRouteHop::PublicHop { info, .. } => info.channel().features.clone(),
			CandidateRouteHop::PrivateHop { .. } => ChannelFeatures::empty(),
			CandidateRouteHop::Blinded { .. } => ChannelFeatures::empty(),
			CandidateRouteHop::OneHopBlinded { .. } => ChannelFeatures::empty(),
		}
	}

	fn cltv_expiry_delta(&self) -> u32 {
		match self {
			CandidateRouteHop::FirstHop { .. } => 0,
			CandidateRouteHop::PublicHop { info, .. } => info.direction().cltv_expiry_delta as u32,
			CandidateRouteHop::PrivateHop { hint } => hint.cltv_expiry_delta as u32,
			CandidateRouteHop::Blinded { hint, .. } => hint.0.cltv_expiry_delta as u32,
			CandidateRouteHop::OneHopBlinded { .. } => 0,
		}
	}

	fn htlc_minimum_msat(&self) -> u64 {
		match self {
			CandidateRouteHop::FirstHop { details } => details.next_outbound_htlc_minimum_msat,
			CandidateRouteHop::PublicHop { info, .. } => info.direction().htlc_minimum_msat,
			CandidateRouteHop::PrivateHop { hint } => hint.htlc_minimum_msat.unwrap_or(0),
			CandidateRouteHop::Blinded { hint, .. } => hint.0.htlc_minimum_msat,
			CandidateRouteHop::OneHopBlinded { .. } => 0,
		}
	}

	fn fees(&self) -> RoutingFees {
		match self {
			CandidateRouteHop::FirstHop { .. } => RoutingFees {
				base_msat: 0, proportional_millionths: 0,
			},
			CandidateRouteHop::PublicHop { info, .. } => info.direction().fees,
			CandidateRouteHop::PrivateHop { hint } => hint.fees,
			CandidateRouteHop::Blinded { hint, .. } => {
				RoutingFees {
					base_msat: hint.0.fee_base_msat,
					proportional_millionths: hint.0.fee_proportional_millionths
				}
			},
			CandidateRouteHop::OneHopBlinded { .. } =>
				RoutingFees { base_msat: 0, proportional_millionths: 0 },
		}
	}

	fn effective_capacity(&self) -> EffectiveCapacity {
		match self {
			CandidateRouteHop::FirstHop { details } => EffectiveCapacity::ExactLiquidity {
				liquidity_msat: details.next_outbound_htlc_limit_msat,
			},
			CandidateRouteHop::PublicHop { info, .. } => info.effective_capacity(),
			CandidateRouteHop::PrivateHop { hint: RouteHintHop { htlc_maximum_msat: Some(max), .. }} =>
				EffectiveCapacity::HintMaxHTLC { amount_msat: *max },
			CandidateRouteHop::PrivateHop { hint: RouteHintHop { htlc_maximum_msat: None, .. }} =>
				EffectiveCapacity::Infinite,
			CandidateRouteHop::Blinded { hint, .. } =>
				EffectiveCapacity::HintMaxHTLC { amount_msat: hint.0.htlc_maximum_msat },
			CandidateRouteHop::OneHopBlinded { .. } => EffectiveCapacity::Infinite,
		}
	}

	fn id(&self, channel_direction: bool /* src_node_id < target_node_id */) -> CandidateHopId {
		match self {
			CandidateRouteHop::Blinded { hint_idx, .. } => CandidateHopId::Blinded(*hint_idx),
			CandidateRouteHop::OneHopBlinded { hint_idx, .. } => CandidateHopId::Blinded(*hint_idx),
			_ => CandidateHopId::Clear((self.short_channel_id().unwrap(), channel_direction)),
		}
	}
	fn blinded_path(&self) -> Option<&'a BlindedPath> {
		match self {
			CandidateRouteHop::Blinded { hint, .. } | CandidateRouteHop::OneHopBlinded { hint, .. } => {
				Some(&hint.1)
			},
			_ => None,
		}
	}
}

#[derive(Clone, Copy, Eq, Hash, Ord, PartialOrd, PartialEq)]
enum CandidateHopId {
	/// Contains (scid, src_node_id < target_node_id)
	Clear((u64, bool)),
	/// Index of the blinded route hint in [`Payee::Blinded::route_hints`].
	Blinded(usize),
}

#[inline]
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
struct PathBuildingHop<'a> {
	// Note that this should be dropped in favor of loading it from CandidateRouteHop, but doing so
	// is a larger refactor and will require careful performance analysis.
	node_id: NodeId,
	candidate: CandidateRouteHop<'a>,
	fee_msat: u64,

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
	#[cfg(all(not(ldk_bench), any(test, fuzzing)))]
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
		#[cfg(all(not(ldk_bench), any(test, fuzzing)))]
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
	// support increasing the value being transferred beyond what was selected during the initial
	// routing passes.
	fn update_value_and_recompute_fees(&mut self, value_msat: u64) {
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

#[inline(always)]
/// Calculate the fees required to route the given amount over a channel with the given fees.
fn compute_fees(amount_msat: u64, channel_fees: RoutingFees) -> Option<u64> {
	amount_msat.checked_mul(channel_fees.proportional_millionths as u64)
		.and_then(|part| (channel_fees.base_msat as u64).checked_add(part / 1_000_000))
}

#[inline(always)]
/// Calculate the fees required to route the given amount over a channel with the given fees,
/// saturating to [`u64::max_value`].
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
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self.0 {
			CandidateRouteHop::Blinded { hint, .. } | CandidateRouteHop::OneHopBlinded { hint, .. } => {
				"blinded route hint with introduction node id ".fmt(f)?;
				hint.1.introduction_node_id.fmt(f)?;
				" and blinding point ".fmt(f)?;
				hint.1.blinding_point.fmt(f)
			},
			CandidateRouteHop::FirstHop { .. } => {
				"first hop with SCID ".fmt(f)?;
				self.0.short_channel_id().unwrap().fmt(f)
			},
			CandidateRouteHop::PrivateHop { .. } => {
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
pub fn find_route<L: Deref, GL: Deref, S: Score>(
	our_node_pubkey: &PublicKey, route_params: &RouteParameters,
	network_graph: &NetworkGraph<GL>, first_hops: Option<&[&ChannelDetails]>, logger: L,
	scorer: &S, score_params: &S::ScoreParams, random_seed_bytes: &[u8; 32]
) -> Result<Route, LightningError>
where L::Target: Logger, GL::Target: Logger {
	let graph_lock = network_graph.read_only();
	let mut route = get_route(our_node_pubkey, &route_params.payment_params, &graph_lock, first_hops,
		route_params.final_value_msat, logger, scorer, score_params,
		random_seed_bytes)?;
	add_random_cltv_offset(&mut route, &route_params.payment_params, &graph_lock, random_seed_bytes);
	Ok(route)
}

pub(crate) fn get_route<L: Deref, S: Score>(
	our_node_pubkey: &PublicKey, payment_params: &PaymentParameters, network_graph: &ReadOnlyNetworkGraph,
	first_hops: Option<&[&ChannelDetails]>, final_value_msat: u64, logger: L, scorer: &S, score_params: &S::ScoreParams,
	_random_seed_bytes: &[u8; 32]
) -> Result<Route, LightningError>
where L::Target: Logger {
	// If we're routing to a blinded recipient, we won't have their node id. Therefore, keep the
	// unblinded payee id as an option. We also need a non-optional "payee id" for path construction,
	// so use a dummy id for this in the blinded case.
	let payee_node_id_opt = payment_params.payee.node_id().map(|pk| NodeId::from_pubkey(&pk));
	const DUMMY_BLINDED_PAYEE_ID: [u8; 33] = [2; 33];
	let maybe_dummy_payee_pk = payment_params.payee.node_id().unwrap_or_else(|| PublicKey::from_slice(&DUMMY_BLINDED_PAYEE_ID).unwrap());
	let maybe_dummy_payee_node_id = NodeId::from_pubkey(&maybe_dummy_payee_pk);
	let our_node_id = NodeId::from_pubkey(&our_node_pubkey);

	if payee_node_id_opt.map_or(false, |payee| payee == our_node_id) {
		return Err(LightningError{err: "Cannot generate a route to ourselves".to_owned(), action: ErrorAction::IgnoreError});
	}

	if final_value_msat > MAX_VALUE_MSAT {
		return Err(LightningError{err: "Cannot generate a route of more value than all existing satoshis".to_owned(), action: ErrorAction::IgnoreError});
	}

	if final_value_msat == 0 {
		return Err(LightningError{err: "Cannot send a payment of 0 msat".to_owned(), action: ErrorAction::IgnoreError});
	}

	match &payment_params.payee {
		Payee::Clear { route_hints, node_id, .. } => {
			for route in route_hints.iter() {
				for hop in &route.0 {
					if hop.src_node_id == *node_id {
						return Err(LightningError{err: "Route hint cannot have the payee as the source.".to_owned(), action: ErrorAction::IgnoreError});
					}
				}
			}
		},
		Payee::Blinded { route_hints, .. } => {
			if route_hints.iter().all(|(_, path)| &path.introduction_node_id == our_node_pubkey) {
				return Err(LightningError{err: "Cannot generate a route to blinded paths if we are the introduction node to all of them".to_owned(), action: ErrorAction::IgnoreError});
			}
			for (_, blinded_path) in route_hints.iter() {
				if blinded_path.blinded_hops.len() == 0 {
					return Err(LightningError{err: "0-hop blinded path provided".to_owned(), action: ErrorAction::IgnoreError});
				} else if &blinded_path.introduction_node_id == our_node_pubkey {
					log_info!(logger, "Got blinded path with ourselves as the introduction node, ignoring");
				} else if blinded_path.blinded_hops.len() == 1 &&
					route_hints.iter().any( |(_, p)| p.blinded_hops.len() == 1
						&& p.introduction_node_id != blinded_path.introduction_node_id)
				{
					return Err(LightningError{err: format!("1-hop blinded paths must all have matching introduction node ids"), action: ErrorAction::IgnoreError});
				}
			}
		}
	}
	let final_cltv_expiry_delta = payment_params.payee.final_cltv_expiry_delta().unwrap_or(0);
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
		return Err(LightningError{err: "Can't find a route with no paths allowed.".to_owned(), action: ErrorAction::IgnoreError});
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
			|info| info.features.supports_basic_mpp()))
	} else { false };

	log_trace!(logger, "Searching for a route from payer {} to {} {} MPP and {} first hops {}overriding the network graph", our_node_pubkey,
		LoggedPayeePubkey(payment_params.payee.node_id()), if allow_mpp { "with" } else { "without" },
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

	// The main heap containing all candidate next-hops sorted by their score (max(fee,
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

	// Keep track of how much liquidity has been used in selected channels or blinded paths. Used to
	// determine if the channel can be used by additional MPP paths or to inform path finding
	// decisions. It is aware of direction *only* to ensure that the correct htlc_maximum_msat value
	// is used. Hence, liquidity used in one direction will not offset any used in the opposite
	// direction.
	let mut used_liquidities: HashMap<CandidateHopId, u64> =
		HashMap::with_capacity(network_nodes.len());

	// Keeping track of how much value we already collected across other paths. Helps to decide
	// when we want to stop looking for new paths.
	let mut already_collected_value_msat = 0;

	for (_, channels) in first_hop_targets.iter_mut() {
		sort_first_hop_channels(channels, &used_liquidities, recommended_value_msat,
			our_node_pubkey);
	}

	log_trace!(logger, "Building path from {} to payer {} for value {} msat.",
		LoggedPayeePubkey(payment_params.payee.node_id()), our_node_pubkey, final_value_msat);

	// Remember how many candidates we ignored to allow for some logging afterwards.
	let mut num_ignored_value_contribution = 0;
	let mut num_ignored_path_length_limit = 0;
	let mut num_ignored_cltv_delta_limit = 0;
	let mut num_ignored_previously_failed = 0;

	macro_rules! add_entry {
		// Adds entry which goes from $src_node_id to $dest_node_id over the $candidate hop.
		// $next_hops_fee_msat represents the fees paid for using all the channels *after* this one,
		// since that value has to be transferred over this channel.
		// Returns whether this channel caused an update to `targets`.
		( $candidate: expr, $src_node_id: expr, $dest_node_id: expr, $next_hops_fee_msat: expr,
			$next_hops_value_contribution: expr, $next_hops_path_htlc_minimum_msat: expr,
			$next_hops_path_penalty_msat: expr, $next_hops_cltv_delta: expr, $next_hops_path_length: expr ) => { {
			// We "return" whether we updated the path at the end, and how much we can route via
			// this channel, via this:
			let mut did_add_update_path_to_src_node = None;
			// Channels to self should not be used. This is more of belt-and-suspenders, because in
			// practice these cases should be caught earlier:
			// - for regular channels at channel announcement (TODO)
			// - for first and last hops early in get_route
			if $src_node_id != $dest_node_id {
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
					let used_liquidity_msat = used_liquidities
						.get(&$candidate.id($src_node_id < $dest_node_id))
						.map_or(0, |used_liquidity_msat| {
							available_value_contribution_msat = available_value_contribution_msat
								.saturating_sub(*used_liquidity_msat);
							*used_liquidity_msat
						});

					// Verify the liquidity offered by this channel complies to the minimal contribution.
					let contributes_sufficient_value = available_value_contribution_msat >= minimal_value_contribution_msat;
					// Do not consider candidate hops that would exceed the maximum path length.
					let path_length_to_node = $next_hops_path_length + 1;
					let exceeds_max_path_length = path_length_to_node > MAX_PATH_LENGTH_ESTIMATE;

					// Do not consider candidates that exceed the maximum total cltv expiry limit.
					// In order to already account for some of the privacy enhancing random CLTV
					// expiry delta offset we add on top later, we subtract a rough estimate
					// (2*MEDIAN_HOP_CLTV_EXPIRY_DELTA) here.
					let max_total_cltv_expiry_delta = (payment_params.max_total_cltv_expiry_delta - final_cltv_expiry_delta)
						.checked_sub(2*MEDIAN_HOP_CLTV_EXPIRY_DELTA)
						.unwrap_or(payment_params.max_total_cltv_expiry_delta - final_cltv_expiry_delta);
					let hop_total_cltv_delta = ($next_hops_cltv_delta as u32)
						.saturating_add($candidate.cltv_expiry_delta());
					let exceeds_cltv_delta_limit = hop_total_cltv_delta > max_total_cltv_expiry_delta;

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

					let payment_failed_on_this_channel = scid_opt.map_or(false,
						|scid| payment_params.previously_failed_channels.contains(&scid));

					let should_log_candidate = match $candidate {
						CandidateRouteHop::FirstHop { .. } => true,
						CandidateRouteHop::PrivateHop { .. } => true,
						CandidateRouteHop::Blinded { .. } => true,
						_ => false,
					};

					// If HTLC minimum is larger than the amount we're going to transfer, we shouldn't
					// bother considering this channel. If retrying with recommended_value_msat may
					// allow us to hit the HTLC minimum limit, set htlc_minimum_limit so that we go
					// around again with a higher amount.
					if !contributes_sufficient_value {
						if should_log_candidate {
							log_trace!(logger, "Ignoring {} due to insufficient value contribution.", LoggedCandidateHop(&$candidate));
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
						}
						num_ignored_cltv_delta_limit += 1;
					} else if payment_failed_on_this_channel {
						if should_log_candidate {
							log_trace!(logger, "Ignoring {} due to a failed previous payment attempt.", LoggedCandidateHop(&$candidate));
						}
						num_ignored_previously_failed += 1;
					} else if may_overpay_to_meet_path_minimum_msat {
						hit_minimum_limit = true;
					} else if over_path_minimum_msat {
						// Note that low contribution here (limited by available_liquidity_msat)
						// might violate htlc_minimum_msat on the hops which are next along the
						// payment path (upstream to the payee). To avoid that, we recompute
						// path fees knowing the final path contribution after constructing it.
						let path_htlc_minimum_msat = cmp::max(
							compute_fees_saturating($next_hops_path_htlc_minimum_msat, $candidate.fees())
								.saturating_add($next_hops_path_htlc_minimum_msat),
							$candidate.htlc_minimum_msat());
						let hm_entry = dist.entry($src_node_id);
						let old_entry = hm_entry.or_insert_with(|| {
							// If there was previously no known way to access the source node
							// (recall it goes payee-to-payer) of short_channel_id, first add a
							// semi-dummy record just to compute the fees to reach the source node.
							// This will affect our decision on selecting short_channel_id
							// as a way to reach the $dest_node_id.
							PathBuildingHop {
								node_id: $dest_node_id.clone(),
								candidate: $candidate.clone(),
								fee_msat: 0,
								next_hops_fee_msat: u64::max_value(),
								hop_use_fee_msat: u64::max_value(),
								total_fee_msat: u64::max_value(),
								path_htlc_minimum_msat,
								path_penalty_msat: u64::max_value(),
								was_processed: false,
								#[cfg(all(not(ldk_bench), any(test, fuzzing)))]
								value_contribution_msat,
							}
						});

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
							if $src_node_id != our_node_id {
								// Note that `u64::max_value` means we'll always fail the
								// `old_entry.total_fee_msat > total_fee_msat` check below
								hop_use_fee_msat = compute_fees_saturating(amount_to_transfer_over_msat, $candidate.fees());
								total_fee_msat = total_fee_msat.saturating_add(hop_use_fee_msat);
							}

							let channel_usage = ChannelUsage {
								amount_msat: amount_to_transfer_over_msat,
								inflight_htlc_msat: used_liquidity_msat,
								effective_capacity,
							};
							let channel_penalty_msat = scid_opt.map_or(0,
								|scid| scorer.channel_penalty_msat(scid, &$src_node_id, &$dest_node_id,
									channel_usage, score_params));
							let path_penalty_msat = $next_hops_path_penalty_msat
								.saturating_add(channel_penalty_msat);
							let new_graph_node = RouteGraphNode {
								node_id: $src_node_id,
								lowest_fee_to_node: total_fee_msat,
								total_cltv_delta: hop_total_cltv_delta,
								value_contribution_msat,
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
								#[cfg(all(not(ldk_bench), any(test, fuzzing)))]
								{
									old_entry.value_contribution_msat = value_contribution_msat;
								}
								did_add_update_path_to_src_node = Some(value_contribution_msat);
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
				debug_assert_eq!($node_id, maybe_dummy_payee_node_id);
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
							if let Some((directed_channel, source)) = chan.as_directed_to(&$node_id) {
								if first_hops.is_none() || *source != our_node_id {
									if directed_channel.direction().enabled {
										let candidate = CandidateRouteHop::PublicHop {
											info: directed_channel,
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
		// For every new path, start from scratch, except for used_liquidities, which
		// helps to avoid reusing previously selected paths in future iterations.
		targets.clear();
		dist.clear();
		hit_minimum_limit = false;

		// If first hop is a private channel and the only way to reach the payee, this is the only
		// place where it could be added.
		payee_node_id_opt.map(|payee| first_hop_targets.get(&payee).map(|first_channels| {
			for details in first_channels {
				let candidate = CandidateRouteHop::FirstHop { details };
				let added = add_entry!(candidate, our_node_id, payee, 0, path_value_msat,
									0, 0u64, 0, 0).is_some();
				log_trace!(logger, "{} direct route to payee via {}",
						if added { "Added" } else { "Skipped" }, LoggedCandidateHop(&candidate));
			}
		}));

		// Add the payee as a target, so that the payee-to-payer
		// search algorithm knows what to start with.
		payee_node_id_opt.map(|payee| match network_nodes.get(&payee) {
			// The payee is not in our network graph, so nothing to add here.
			// There is still a chance of reaching them via last_hops though,
			// so don't yet fail the payment here.
			// If not, targets.pop() will not even let us enter the loop in step 2.
			None => {},
			Some(node) => {
				add_entries_to_cheapest_to_target_node!(node, payee, 0, path_value_msat, 0, 0u64, 0, 0);
			},
		});

		// Step (2).
		// If a caller provided us with last hops, add them to routing targets. Since this happens
		// earlier than general path finding, they will be somewhat prioritized, although currently
		// it matters only if the fees are exactly the same.
		for (hint_idx, hint) in payment_params.payee.blinded_route_hints().iter().enumerate() {
			let intro_node_id = NodeId::from_pubkey(&hint.1.introduction_node_id);
			let have_intro_node_in_graph =
				// Only add the hops in this route to our candidate set if either
				// we have a direct channel to the first hop or the first hop is
				// in the regular network graph.
				first_hop_targets.get(&intro_node_id).is_some() ||
				network_nodes.get(&intro_node_id).is_some();
			if !have_intro_node_in_graph { continue }
			let candidate = if hint.1.blinded_hops.len() == 1 {
				CandidateRouteHop::OneHopBlinded { hint, hint_idx }
			} else { CandidateRouteHop::Blinded { hint, hint_idx } };
			let mut path_contribution_msat = path_value_msat;
			if let Some(hop_used_msat) = add_entry!(candidate, intro_node_id, maybe_dummy_payee_node_id,
				0, path_contribution_msat, 0, 0_u64, 0, 0)
			{
				path_contribution_msat = hop_used_msat;
			} else { continue }
			if let Some(first_channels) = first_hop_targets.get_mut(&NodeId::from_pubkey(&hint.1.introduction_node_id)) {
				sort_first_hop_channels(first_channels, &used_liquidities, recommended_value_msat,
					our_node_pubkey);
				for details in first_channels {
					let first_hop_candidate = CandidateRouteHop::FirstHop { details };
					let blinded_path_fee = match compute_fees(path_contribution_msat, candidate.fees()) {
						Some(fee) => fee,
						None => continue
					};
					add_entry!(first_hop_candidate, our_node_id, intro_node_id, blinded_path_fee,
						path_contribution_msat, candidate.htlc_minimum_msat(), 0_u64,
						candidate.cltv_expiry_delta(),
						candidate.blinded_path().map_or(1, |bp| bp.blinded_hops.len() as u8));
				}
			}
		}
		for route in payment_params.payee.unblinded_route_hints().iter()
			.filter(|route| !route.0.is_empty())
		{
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
				let prev_hop_iter = core::iter::once(&maybe_dummy_payee_pk).chain(
					route.0.iter().skip(1).rev().map(|hop| &hop.src_node_id));
				let mut hop_used = true;
				let mut aggregate_next_hops_fee_msat: u64 = 0;
				let mut aggregate_next_hops_path_htlc_minimum_msat: u64 = 0;
				let mut aggregate_next_hops_path_penalty_msat: u64 = 0;
				let mut aggregate_next_hops_cltv_delta: u32 = 0;
				let mut aggregate_next_hops_path_length: u8 = 0;
				let mut aggregate_path_contribution_msat = path_value_msat;

				for (idx, (hop, prev_hop_id)) in hop_iter.zip(prev_hop_iter).enumerate() {
					let source = NodeId::from_pubkey(&hop.src_node_id);
					let target = NodeId::from_pubkey(&prev_hop_id);
					let candidate = network_channels
						.get(&hop.short_channel_id)
						.and_then(|channel| channel.as_directed_to(&target))
						.map(|(info, _)| CandidateRouteHop::PublicHop {
							info,
							short_channel_id: hop.short_channel_id,
						})
						.unwrap_or_else(|| CandidateRouteHop::PrivateHop { hint: hop });

					if let Some(hop_used_msat) = add_entry!(candidate, source, target,
						aggregate_next_hops_fee_msat, aggregate_path_contribution_msat,
						aggregate_next_hops_path_htlc_minimum_msat, aggregate_next_hops_path_penalty_msat,
						aggregate_next_hops_cltv_delta, aggregate_next_hops_path_length)
					{
						aggregate_path_contribution_msat = hop_used_msat;
					} else {
						// If this hop was not used then there is no use checking the preceding
						// hops in the RouteHint. We can break by just searching for a direct
						// channel between last checked hop and first_hop_targets.
						hop_used = false;
					}

					let used_liquidity_msat = used_liquidities
						.get(&candidate.id(source < target)).copied()
						.unwrap_or(0);
					let channel_usage = ChannelUsage {
						amount_msat: final_value_msat + aggregate_next_hops_fee_msat,
						inflight_htlc_msat: used_liquidity_msat,
						effective_capacity: candidate.effective_capacity(),
					};
					let channel_penalty_msat = scorer.channel_penalty_msat(
						hop.short_channel_id, &source, &target, channel_usage, score_params
					);
					aggregate_next_hops_path_penalty_msat = aggregate_next_hops_path_penalty_msat
						.saturating_add(channel_penalty_msat);

					aggregate_next_hops_cltv_delta = aggregate_next_hops_cltv_delta
						.saturating_add(hop.cltv_expiry_delta as u32);

					aggregate_next_hops_path_length = aggregate_next_hops_path_length
						.saturating_add(1);

					// Searching for a direct channel between last checked hop and first_hop_targets
					if let Some(first_channels) = first_hop_targets.get_mut(&NodeId::from_pubkey(&prev_hop_id)) {
						sort_first_hop_channels(first_channels, &used_liquidities,
							recommended_value_msat, our_node_pubkey);
						for details in first_channels {
							let first_hop_candidate = CandidateRouteHop::FirstHop { details };
							add_entry!(first_hop_candidate, our_node_id, NodeId::from_pubkey(&prev_hop_id),
								aggregate_next_hops_fee_msat, aggregate_path_contribution_msat,
								aggregate_next_hops_path_htlc_minimum_msat, aggregate_next_hops_path_penalty_msat,
								aggregate_next_hops_cltv_delta, aggregate_next_hops_path_length);
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
						if let Some(first_channels) = first_hop_targets.get_mut(&NodeId::from_pubkey(&hop.src_node_id)) {
							sort_first_hop_channels(first_channels, &used_liquidities,
								recommended_value_msat, our_node_pubkey);
							for details in first_channels {
								let first_hop_candidate = CandidateRouteHop::FirstHop { details };
								add_entry!(first_hop_candidate, our_node_id,
									NodeId::from_pubkey(&hop.src_node_id),
									aggregate_next_hops_fee_msat,
									aggregate_path_contribution_msat,
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
		'path_construction: while let Some(RouteGraphNode { node_id, lowest_fee_to_node, total_cltv_delta, mut value_contribution_msat, path_htlc_minimum_msat, path_penalty_msat, path_length_to_node, .. }) = targets.pop() {

			// Since we're going payee-to-payer, hitting our node as a target means we should stop
			// traversing the graph and arrange the path out of what we found.
			if node_id == our_node_id {
				let mut new_entry = dist.remove(&our_node_id).unwrap();
				let mut ordered_hops: Vec<(PathBuildingHop, NodeFeatures)> = vec!((new_entry.clone(), default_node_features.clone()));

				'path_walk: loop {
					let mut features_set = false;
					if let Some(first_channels) = first_hop_targets.get(&ordered_hops.last().unwrap().0.node_id) {
						for details in first_channels {
							if let Some(scid) = ordered_hops.last().unwrap().0.candidate.short_channel_id() {
								if details.get_outbound_payment_scid().unwrap() == scid {
									ordered_hops.last_mut().unwrap().1 = details.counterparty.features.to_context();
									features_set = true;
									break;
								}
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
					if ordered_hops.last().unwrap().0.node_id == maybe_dummy_payee_node_id {
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
				debug_assert_eq!(payment_path.get_value_msat(), value_contribution_msat);
				value_contribution_msat = cmp::min(value_contribution_msat, final_value_msat);
				payment_path.update_value_and_recompute_fees(value_contribution_msat);

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
					let used_liquidity_msat = used_liquidities
						.entry(hop.candidate.id(*prev_hop < hop.node_id))
						.and_modify(|used_liquidity_msat| *used_liquidity_msat += spent_on_hop_msat)
						.or_insert(spent_on_hop_msat);
					let hop_capacity = hop.candidate.effective_capacity();
					let hop_max_msat = max_htlc_from_capacity(hop_capacity, channel_saturation_pow_half);
					if *used_liquidity_msat == hop_max_msat {
						// If this path used all of this channel's available liquidity, we know
						// this path will not be selected again in the next loop iteration.
						prevented_redundant_path_selection = true;
					}
					debug_assert!(*used_liquidity_msat <= hop_max_msat);
				}
				if !prevented_redundant_path_selection {
					// If we weren't capped by hitting a liquidity limit on a channel in the path,
					// we'll probably end up picking the same path again on the next iteration.
					// Decrease the available liquidity of a hop in the middle of the path.
					let victim_candidate = &payment_path.hops[(payment_path.hops.len()) / 2].0.candidate;
					let exhausted = u64::max_value();
					log_trace!(logger, "Disabling route candidate {} for future path building iterations to
						avoid duplicates.", LoggedCandidateHop(victim_candidate));
					*used_liquidities.entry(victim_candidate.id(false)).or_default() = exhausted;
					*used_liquidities.entry(victim_candidate.id(true)).or_default() = exhausted;
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
			if node_id == maybe_dummy_payee_node_id { continue 'path_construction; }

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
			log_trace!(logger, "Collected our payment amount on the first pass, but running again to collect extra paths with a potentially higher limit.");
			path_value_msat = recommended_value_msat;
		}
	}

	let num_ignored_total = num_ignored_value_contribution + num_ignored_path_length_limit +
		num_ignored_cltv_delta_limit + num_ignored_previously_failed;
	if num_ignored_total > 0 {
		log_trace!(logger, "Ignored {} candidate hops due to insufficient value contribution, {} due to path length limit, {} due to CLTV delta limit, {} due to previous payment failure. Total: {} ignored candidates.", num_ignored_value_contribution, num_ignored_path_length_limit, num_ignored_cltv_delta_limit, num_ignored_previously_failed, num_ignored_total);
	}

	// Step (5).
	if payment_paths.len() == 0 {
		return Err(LightningError{err: "Failed to find a path to the given destination".to_owned(), action: ErrorAction::IgnoreError});
	}

	if already_collected_value_msat < final_value_msat {
		return Err(LightningError{err: "Failed to find a sufficient route to the given destination".to_owned(), action: ErrorAction::IgnoreError});
	}

	// Step (6).
	let mut selected_route = payment_paths;

	debug_assert_eq!(selected_route.iter().map(|p| p.get_value_msat()).sum::<u64>(), already_collected_value_msat);
	let mut overpaid_value_msat = already_collected_value_msat - final_value_msat;

	// First, sort by the cost-per-value of the path, dropping the paths that cost the most for
	// the value they contribute towards the payment amount.
	// We sort in descending order as we will remove from the front in `retain`, next.
	selected_route.sort_unstable_by(|a, b|
		(((b.get_cost_msat() as u128) << 64) / (b.get_value_msat() as u128))
			.cmp(&(((a.get_cost_msat() as u128) << 64) / (a.get_value_msat() as u128)))
	);

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
		for (scid, key) in path.hops.iter() .map(|h| h.0.candidate.id(true)).zip(key.iter_mut()) {
			*key = scid;
		}
		key
	});
	for idx in 0..(selected_route.len() - 1) {
		if idx + 1 >= selected_route.len() { break; }
		if iter_equal(selected_route[idx    ].hops.iter().map(|h| (h.0.candidate.id(true), h.0.node_id)),
		              selected_route[idx + 1].hops.iter().map(|h| (h.0.candidate.id(true), h.0.node_id))) {
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
			hops.push(RouteHop {
				pubkey: PublicKey::from_slice(hop.node_id.as_slice()).map_err(|_| LightningError{err: format!("Public key {:?} is invalid", &hop.node_id), action: ErrorAction::IgnoreAndLog(Level::Trace)})?,
				node_features: node_features.clone(),
				short_channel_id: hop.candidate.short_channel_id().unwrap(),
				channel_features: hop.candidate.features(),
				fee_msat: hop.fee_msat,
				cltv_expiry_delta: hop.candidate.cltv_expiry_delta(),
			});
		}
		let mut final_cltv_delta = final_cltv_expiry_delta;
		let blinded_tail = payment_path.hops.last().and_then(|(h, _)| {
			if let Some(blinded_path) = h.candidate.blinded_path() {
				final_cltv_delta = h.candidate.cltv_expiry_delta();
				Some(BlindedTail {
					hops: blinded_path.blinded_hops.clone(),
					blinding_point: blinded_path.blinding_point,
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

	let route = Route { paths, payment_params: Some(payment_params.clone()) };
	log_info!(logger, "Got route: {}", log_route!(route));
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
pub fn build_route_from_hops<L: Deref, GL: Deref>(
	our_node_pubkey: &PublicKey, hops: &[PublicKey], route_params: &RouteParameters,
	network_graph: &NetworkGraph<GL>, logger: L, random_seed_bytes: &[u8; 32]
) -> Result<Route, LightningError>
where L::Target: Logger, GL::Target: Logger {
	let graph_lock = network_graph.read_only();
	let mut route = build_route_from_hops_internal(
		our_node_pubkey, hops, &route_params.payment_params, &graph_lock,
		route_params.final_value_msat, logger, random_seed_bytes)?;
	add_random_cltv_offset(&mut route, &route_params.payment_params, &graph_lock, random_seed_bytes);
	Ok(route)
}

fn build_route_from_hops_internal<L: Deref>(
	our_node_pubkey: &PublicKey, hops: &[PublicKey], payment_params: &PaymentParameters,
	network_graph: &ReadOnlyNetworkGraph, final_value_msat: u64, logger: L,
	random_seed_bytes: &[u8; 32]
) -> Result<Route, LightningError> where L::Target: Logger {

	struct HopScorer {
		our_node_id: NodeId,
		hop_ids: [Option<NodeId>; MAX_PATH_LENGTH_ESTIMATE as usize],
	}

	impl Score for HopScorer {
		type ScoreParams = ();
		fn channel_penalty_msat(&self, _short_channel_id: u64, source: &NodeId, target: &NodeId,
			_usage: ChannelUsage, _score_params: &Self::ScoreParams) -> u64
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

		fn payment_path_failed(&mut self, _path: &Path, _short_channel_id: u64) {}

		fn payment_path_successful(&mut self, _path: &Path) {}

		fn probe_failed(&mut self, _path: &Path, _short_channel_id: u64) {}

		fn probe_successful(&mut self, _path: &Path) {}
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
		logger, &scorer, &(), random_seed_bytes)
}

#[cfg(test)]
mod tests {
	use crate::blinded_path::{BlindedHop, BlindedPath};
	use crate::routing::gossip::{NetworkGraph, P2PGossipSync, NodeId, EffectiveCapacity};
	use crate::routing::utxo::UtxoResult;
	use crate::routing::router::{get_route, build_route_from_hops_internal, add_random_cltv_offset, default_node_features,
		BlindedTail, InFlightHtlcs, Path, PaymentParameters, Route, RouteHint, RouteHintHop, RouteHop, RoutingFees,
		DEFAULT_MAX_TOTAL_CLTV_EXPIRY_DELTA, MAX_PATH_LENGTH_ESTIMATE};
	use crate::routing::scoring::{ChannelUsage, FixedPenaltyScorer, Score, ProbabilisticScorer, ProbabilisticScoringFeeParameters, ProbabilisticScoringDecayParameters};
	use crate::routing::test_utils::{add_channel, add_or_update_node, build_graph, build_line_graph, id_to_feature_flags, get_nodes, update_channel};
	use crate::chain::transaction::OutPoint;
	use crate::sign::EntropySource;
	use crate::ln::ChannelId;
	use crate::ln::features::{BlindedHopFeatures, Bolt12InvoiceFeatures, ChannelFeatures, InitFeatures, NodeFeatures};
	use crate::ln::msgs::{ErrorAction, LightningError, UnsignedChannelUpdate, MAX_VALUE_MSAT};
	use crate::ln::channelmanager;
	use crate::offers::invoice::BlindedPayInfo;
	use crate::util::config::UserConfig;
	use crate::util::test_utils as ln_test_utils;
	use crate::util::chacha20::ChaCha20;
	use crate::util::ser::{Readable, Writeable};
	#[cfg(c_bindings)]
	use crate::util::ser::Writer;

	use bitcoin::hashes::Hash;
	use bitcoin::network::constants::Network;
	use bitcoin::blockdata::constants::genesis_block;
	use bitcoin::blockdata::script::Builder;
	use bitcoin::blockdata::opcodes;
	use bitcoin::blockdata::transaction::TxOut;

	use hex;

	use bitcoin::secp256k1::{PublicKey,SecretKey};
	use bitcoin::secp256k1::Secp256k1;

	use crate::io::Cursor;
	use crate::prelude::*;
	use crate::sync::Arc;

	use core::convert::TryInto;

	fn get_channel_details(short_channel_id: Option<u64>, node_id: PublicKey,
			features: InitFeatures, outbound_capacity_msat: u64) -> channelmanager::ChannelDetails {
		channelmanager::ChannelDetails {
			channel_id: ChannelId::new_zero(),
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
			outbound_capacity_msat,
			next_outbound_htlc_limit_msat: outbound_capacity_msat,
			next_outbound_htlc_minimum_msat: 0,
			inbound_capacity_msat: 42,
			unspendable_punishment_reserve: None,
			confirmations_required: None,
			confirmations: None,
			force_close_spend_delay: None,
			is_outbound: true, is_channel_ready: true,
			is_usable: true, is_public: true,
			inbound_htlc_minimum_msat: None,
			inbound_htlc_maximum_msat: None,
			config: None,
			feerate_sat_per_1000_weight: None,
			channel_shutdown_state: Some(channelmanager::ChannelShutdownState::NotShuttingDown),
		}
	}

	#[test]
	fn simple_route_test() {
		let (secp_ctx, network_graph, _, _, logger) = build_graph();
		let (_, our_id, _, nodes) = get_nodes(&secp_ctx);
		let payment_params = PaymentParameters::from_node_id(nodes[2], 42);
		let scorer = ln_test_utils::TestScorer::new();
		let keys_manager = ln_test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();

		// Simple route to 2 via 1

		if let Err(LightningError{err, action: ErrorAction::IgnoreError}) = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 0, Arc::clone(&logger), &scorer, &(), &random_seed_bytes) {
			assert_eq!(err, "Cannot send a payment of 0 msat");
		} else { panic!(); }

		let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 100, Arc::clone(&logger), &scorer, &(), &random_seed_bytes).unwrap();
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
	}

	#[test]
	fn invalid_first_hop_test() {
		let (secp_ctx, network_graph, _, _, logger) = build_graph();
		let (_, our_id, _, nodes) = get_nodes(&secp_ctx);
		let payment_params = PaymentParameters::from_node_id(nodes[2], 42);
		let scorer = ln_test_utils::TestScorer::new();
		let keys_manager = ln_test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();

		// Simple route to 2 via 1

		let our_chans = vec![get_channel_details(Some(2), our_id, InitFeatures::from_le_bytes(vec![0b11]), 100000)];

		if let Err(LightningError{err, action: ErrorAction::IgnoreError}) =
			get_route(&our_id, &payment_params, &network_graph.read_only(), Some(&our_chans.iter().collect::<Vec<_>>()), 100, Arc::clone(&logger), &scorer, &(), &random_seed_bytes) {
			assert_eq!(err, "First hop cannot have our_node_pubkey as a destination.");
		} else { panic!(); }

		let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 100, Arc::clone(&logger), &scorer, &(), &random_seed_bytes).unwrap();
		assert_eq!(route.paths[0].hops.len(), 2);
	}

	#[test]
	fn htlc_minimum_test() {
		let (secp_ctx, network_graph, gossip_sync, _, logger) = build_graph();
		let (our_privkey, our_id, privkeys, nodes) = get_nodes(&secp_ctx);
		let payment_params = PaymentParameters::from_node_id(nodes[2], 42);
		let scorer = ln_test_utils::TestScorer::new();
		let keys_manager = ln_test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();

		// Simple route to 2 via 1

		// Disable other paths
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 12,
			timestamp: 2,
			flags: 2, // to disable
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[0], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 3,
			timestamp: 2,
			flags: 2, // to disable
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[7], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 13,
			timestamp: 2,
			flags: 2, // to disable
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 6,
			timestamp: 2,
			flags: 2, // to disable
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 7,
			timestamp: 2,
			flags: 2, // to disable
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
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 2,
			timestamp: 3,
			flags: 0,
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
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 4,
			timestamp: 3,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 199_999_999,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		// Not possible to send 199_999_999, because the minimum on channel=2 is 200_000_000.
		if let Err(LightningError{err, action: ErrorAction::IgnoreError}) = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 199_999_999, Arc::clone(&logger), &scorer, &(), &random_seed_bytes) {
			assert_eq!(err, "Failed to find a path to the given destination");
		} else { panic!(); }

		// Lift the restriction on the first hop.
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 2,
			timestamp: 4,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		// A payment above the minimum should pass
		let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 199_999_999, Arc::clone(&logger), &scorer, &(), &random_seed_bytes).unwrap();
		assert_eq!(route.paths[0].hops.len(), 2);
	}

	#[test]
	fn htlc_minimum_overpay_test() {
		let (secp_ctx, network_graph, gossip_sync, _, logger) = build_graph();
		let (our_privkey, our_id, privkeys, nodes) = get_nodes(&secp_ctx);
		let config = UserConfig::default();
		let payment_params = PaymentParameters::from_node_id(nodes[2], 42).with_bolt11_features(channelmanager::provided_invoice_features(&config)).unwrap();
		let scorer = ln_test_utils::TestScorer::new();
		let keys_manager = ln_test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();

		// A route to node#2 via two paths.
		// One path allows transferring 35-40 sats, another one also allows 35-40 sats.
		// Thus, they can't send 60 without overpaying.
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 2,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 35_000,
			htlc_maximum_msat: 40_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 12,
			timestamp: 3,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 35_000,
			htlc_maximum_msat: 40_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		// Make 0 fee.
		update_channel(&gossip_sync, &secp_ctx, &privkeys[7], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 13,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[1], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 4,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		// Disable other paths
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 1,
			timestamp: 3,
			flags: 2, // to disable
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 60_000, Arc::clone(&logger), &scorer, &(), &random_seed_bytes).unwrap();
		// Overpay fees to hit htlc_minimum_msat.
		let overpaid_fees = route.paths[0].hops[0].fee_msat + route.paths[1].hops[0].fee_msat;
		// TODO: this could be better balanced to overpay 10k and not 15k.
		assert_eq!(overpaid_fees, 15_000);

		// Now, test that if there are 2 paths, a "cheaper" by fee path wouldn't be prioritized
		// while taking even more fee to match htlc_minimum_msat.
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 12,
			timestamp: 4,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 65_000,
			htlc_maximum_msat: 80_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 2,
			timestamp: 3,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[1], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 4,
			timestamp: 4,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,
			fee_proportional_millionths: 100_000,
			excess_data: Vec::new()
		});

		let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 60_000, Arc::clone(&logger), &scorer, &(), &random_seed_bytes).unwrap();
		// Fine to overpay for htlc_minimum_msat if it allows us to save fee.
		assert_eq!(route.paths.len(), 1);
		assert_eq!(route.paths[0].hops[0].short_channel_id, 12);
		let fees = route.paths[0].hops[0].fee_msat;
		assert_eq!(fees, 5_000);

		let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 50_000, Arc::clone(&logger), &scorer, &(), &random_seed_bytes).unwrap();
		// Not fine to overpay for htlc_minimum_msat if it requires paying more than fee on
		// the other channel.
		assert_eq!(route.paths.len(), 1);
		assert_eq!(route.paths[0].hops[0].short_channel_id, 2);
		let fees = route.paths[0].hops[0].fee_msat;
		assert_eq!(fees, 5_000);
	}

	#[test]
	fn disable_channels_test() {
		let (secp_ctx, network_graph, gossip_sync, _, logger) = build_graph();
		let (our_privkey, our_id, privkeys, nodes) = get_nodes(&secp_ctx);
		let payment_params = PaymentParameters::from_node_id(nodes[2], 42);
		let scorer = ln_test_utils::TestScorer::new();
		let keys_manager = ln_test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();

		// // Disable channels 4 and 12 by flags=2
		update_channel(&gossip_sync, &secp_ctx, &privkeys[1], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 4,
			timestamp: 2,
			flags: 2, // to disable
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 12,
			timestamp: 2,
			flags: 2, // to disable
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		// If all the channels require some features we don't understand, route should fail
		if let Err(LightningError{err, action: ErrorAction::IgnoreError}) = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 100, Arc::clone(&logger), &scorer, &(), &random_seed_bytes) {
			assert_eq!(err, "Failed to find a path to the given destination");
		} else { panic!(); }

		// If we specify a channel to node7, that overrides our local channel view and that gets used
		let our_chans = vec![get_channel_details(Some(42), nodes[7].clone(), InitFeatures::from_le_bytes(vec![0b11]), 250_000_000)];
		let route = get_route(&our_id, &payment_params, &network_graph.read_only(), Some(&our_chans.iter().collect::<Vec<_>>()), 100, Arc::clone(&logger), &scorer, &(), &random_seed_bytes).unwrap();
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
	fn disable_node_test() {
		let (secp_ctx, network_graph, gossip_sync, _, logger) = build_graph();
		let (_, our_id, privkeys, nodes) = get_nodes(&secp_ctx);
		let payment_params = PaymentParameters::from_node_id(nodes[2], 42);
		let scorer = ln_test_utils::TestScorer::new();
		let keys_manager = ln_test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();

		// Disable nodes 1, 2, and 8 by requiring unknown feature bits
		let mut unknown_features = NodeFeatures::empty();
		unknown_features.set_unknown_feature_required();
		add_or_update_node(&gossip_sync, &secp_ctx, &privkeys[0], unknown_features.clone(), 1);
		add_or_update_node(&gossip_sync, &secp_ctx, &privkeys[1], unknown_features.clone(), 1);
		add_or_update_node(&gossip_sync, &secp_ctx, &privkeys[7], unknown_features.clone(), 1);

		// If all nodes require some features we don't understand, route should fail
		if let Err(LightningError{err, action: ErrorAction::IgnoreError}) = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 100, Arc::clone(&logger), &scorer, &(), &random_seed_bytes) {
			assert_eq!(err, "Failed to find a path to the given destination");
		} else { panic!(); }

		// If we specify a channel to node7, that overrides our local channel view and that gets used
		let our_chans = vec![get_channel_details(Some(42), nodes[7].clone(), InitFeatures::from_le_bytes(vec![0b11]), 250_000_000)];
		let route = get_route(&our_id, &payment_params, &network_graph.read_only(), Some(&our_chans.iter().collect::<Vec<_>>()), 100, Arc::clone(&logger), &scorer, &(), &random_seed_bytes).unwrap();
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
	fn our_chans_test() {
		let (secp_ctx, network_graph, _, _, logger) = build_graph();
		let (_, our_id, _, nodes) = get_nodes(&secp_ctx);
		let scorer = ln_test_utils::TestScorer::new();
		let keys_manager = ln_test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();

		// Route to 1 via 2 and 3 because our channel to 1 is disabled
		let payment_params = PaymentParameters::from_node_id(nodes[0], 42);
		let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 100, Arc::clone(&logger), &scorer, &(), &random_seed_bytes).unwrap();
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
		let our_chans = vec![get_channel_details(Some(42), nodes[7].clone(), InitFeatures::from_le_bytes(vec![0b11]), 250_000_000)];
		let route = get_route(&our_id, &payment_params, &network_graph.read_only(), Some(&our_chans.iter().collect::<Vec<_>>()), 100, Arc::clone(&logger), &scorer, &(), &random_seed_bytes).unwrap();
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
		let scorer = ln_test_utils::TestScorer::new();
		let keys_manager = ln_test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
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
			let payment_params = PaymentParameters::from_node_id(nodes[6], 42).with_route_hints(invalid_last_hops).unwrap();
			if let Err(LightningError{err, action: ErrorAction::IgnoreError}) = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 100, Arc::clone(&logger), &scorer, &(), &random_seed_bytes) {
				assert_eq!(err, "Route hint cannot have the payee as the source.");
			} else { panic!(); }
		}

		let payment_params = PaymentParameters::from_node_id(nodes[6], 42).with_route_hints(last_hops_multi_private_channels(&nodes)).unwrap();
		let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 100, Arc::clone(&logger), &scorer, &(), &random_seed_bytes).unwrap();
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
		let payment_params = PaymentParameters::from_node_id(nodes[6], 42).with_route_hints(empty_last_hop(&nodes)).unwrap();
		let scorer = ln_test_utils::TestScorer::new();
		let keys_manager = ln_test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();

		// Test handling of an empty RouteHint passed in Invoice.

		let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 100, Arc::clone(&logger), &scorer, &(), &random_seed_bytes).unwrap();
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
		let (secp_ctx, network_graph, gossip_sync, _, logger) = build_graph();
		let (_, our_id, privkeys, nodes) = get_nodes(&secp_ctx);
		let last_hops = multi_hop_last_hops_hint([nodes[2], nodes[3]]);
		let payment_params = PaymentParameters::from_node_id(nodes[6], 42).with_route_hints(last_hops.clone()).unwrap();
		let scorer = ln_test_utils::TestScorer::new();
		let keys_manager = ln_test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();
		// Test through channels 2, 3, 0xff00, 0xff01.
		// Test shows that multiple hop hints are considered.

		// Disabling channels 6 & 7 by flags=2
		update_channel(&gossip_sync, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 6,
			timestamp: 2,
			flags: 2, // to disable
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 7,
			timestamp: 2,
			flags: 2, // to disable
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 100, Arc::clone(&logger), &scorer, &(), &random_seed_bytes).unwrap();
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
	}

	#[test]
	fn private_multi_hint_last_hops_test() {
		let (secp_ctx, network_graph, gossip_sync, _, logger) = build_graph();
		let (_, our_id, privkeys, nodes) = get_nodes(&secp_ctx);

		let non_announced_privkey = SecretKey::from_slice(&hex::decode(format!("{:02x}", 0xf0).repeat(32)).unwrap()[..]).unwrap();
		let non_announced_pubkey = PublicKey::from_secret_key(&secp_ctx, &non_announced_privkey);

		let last_hops = multi_hop_last_hops_hint([nodes[2], non_announced_pubkey]);
		let payment_params = PaymentParameters::from_node_id(nodes[6], 42).with_route_hints(last_hops.clone()).unwrap();
		let scorer = ln_test_utils::TestScorer::new();
		// Test through channels 2, 3, 0xff00, 0xff01.
		// Test shows that multiple hop hints are considered.

		// Disabling channels 6 & 7 by flags=2
		update_channel(&gossip_sync, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 6,
			timestamp: 2,
			flags: 2, // to disable
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 7,
			timestamp: 2,
			flags: 2, // to disable
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 100, Arc::clone(&logger), &scorer, &(), &[42u8; 32]).unwrap();
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
		let payment_params = PaymentParameters::from_node_id(nodes[6], 42).with_route_hints(last_hops_with_public_channel(&nodes)).unwrap();
		let scorer = ln_test_utils::TestScorer::new();
		let keys_manager = ln_test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();
		// This test shows that public routes can be present in the invoice
		// which would be handled in the same manner.

		let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 100, Arc::clone(&logger), &scorer, &(), &random_seed_bytes).unwrap();
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
	fn our_chans_last_hop_connect_test() {
		let (secp_ctx, network_graph, _, _, logger) = build_graph();
		let (_, our_id, _, nodes) = get_nodes(&secp_ctx);
		let scorer = ln_test_utils::TestScorer::new();
		let keys_manager = ln_test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();

		// Simple test with outbound channel to 4 to test that last_hops and first_hops connect
		let our_chans = vec![get_channel_details(Some(42), nodes[3].clone(), InitFeatures::from_le_bytes(vec![0b11]), 250_000_000)];
		let mut last_hops = last_hops(&nodes);
		let payment_params = PaymentParameters::from_node_id(nodes[6], 42).with_route_hints(last_hops.clone()).unwrap();
		let route = get_route(&our_id, &payment_params, &network_graph.read_only(), Some(&our_chans.iter().collect::<Vec<_>>()), 100, Arc::clone(&logger), &scorer, &(), &random_seed_bytes).unwrap();
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
		let payment_params = PaymentParameters::from_node_id(nodes[6], 42).with_route_hints(last_hops).unwrap();
		let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 100, Arc::clone(&logger), &scorer, &(), &random_seed_bytes).unwrap();
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
		let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 2000, Arc::clone(&logger), &scorer, &(), &random_seed_bytes).unwrap();
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
		let payment_params = PaymentParameters::from_node_id(target_node_id, 42).with_route_hints(vec![last_hops]).unwrap();
		let our_chans = vec![get_channel_details(Some(42), middle_node_id, InitFeatures::from_le_bytes(vec![0b11]), outbound_capacity_msat)];
		let scorer = ln_test_utils::TestScorer::new();
		let keys_manager = ln_test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();
		let logger = ln_test_utils::TestLogger::new();
		let network_graph = NetworkGraph::new(Network::Testnet, &logger);
		let route = get_route(&source_node_id, &payment_params, &network_graph.read_only(),
				Some(&our_chans.iter().collect::<Vec<_>>()), route_val, &logger, &scorer, &(), &random_seed_bytes);
		route
	}

	#[test]
	fn unannounced_path_test() {
		// We should be able to send a payment to a destination without any help of a routing graph
		// if we have a channel with a common counterparty that appears in the first and last hop
		// hints.
		let route = do_unannounced_path_test(None, 1, 2000000, 1000000).unwrap();

		let middle_node_id = PublicKey::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&hex::decode(format!("{:02}", 42).repeat(32)).unwrap()[..]).unwrap());
		let target_node_id = PublicKey::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&hex::decode(format!("{:02}", 43).repeat(32)).unwrap()[..]).unwrap());
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

		let (secp_ctx, network_graph, gossip_sync, chain_monitor, logger) = build_graph();
		let (our_privkey, our_id, privkeys, nodes) = get_nodes(&secp_ctx);
		let scorer = ln_test_utils::TestScorer::new();
		let keys_manager = ln_test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();
		let config = UserConfig::default();
		let payment_params = PaymentParameters::from_node_id(nodes[2], 42).with_bolt11_features(channelmanager::provided_invoice_features(&config)).unwrap();

		// We will use a simple single-path route from
		// our node to node2 via node0: channels {1, 3}.

		// First disable all other paths.
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 2,
			timestamp: 2,
			flags: 2,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 100_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 12,
			timestamp: 2,
			flags: 2,
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
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 1,
			timestamp: 2,
			flags: 0,
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
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 3,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 250_000_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		{
			// Attempt to route more than available results in a failure.
			if let Err(LightningError{err, action: ErrorAction::IgnoreError}) = get_route(
					&our_id, &payment_params, &network_graph.read_only(), None, 250_000_001, Arc::clone(&logger), &scorer, &(), &random_seed_bytes) {
				assert_eq!(err, "Failed to find a sufficient route to the given destination");
			} else { panic!(); }
		}

		{
			// Now, attempt to route an exact amount we have should be fine.
			let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 250_000_000, Arc::clone(&logger), &scorer, &(),&random_seed_bytes).unwrap();
			assert_eq!(route.paths.len(), 1);
			let path = route.paths.last().unwrap();
			assert_eq!(path.hops.len(), 2);
			assert_eq!(path.hops.last().unwrap().pubkey, nodes[2]);
			assert_eq!(path.final_value_msat(), 250_000_000);
		}

		// Check that setting next_outbound_htlc_limit_msat in first_hops limits the channels.
		// Disable channel #1 and use another first hop.
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 1,
			timestamp: 3,
			flags: 2,
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
			if let Err(LightningError{err, action: ErrorAction::IgnoreError}) = get_route(
					&our_id, &payment_params, &network_graph.read_only(), Some(&our_chans.iter().collect::<Vec<_>>()), 200_000_001, Arc::clone(&logger), &scorer, &(), &random_seed_bytes) {
				assert_eq!(err, "Failed to find a sufficient route to the given destination");
			} else { panic!(); }
		}

		{
			// Now, attempt to route an exact amount we have should be fine.
			let route = get_route(&our_id, &payment_params, &network_graph.read_only(), Some(&our_chans.iter().collect::<Vec<_>>()), 200_000_000, Arc::clone(&logger), &scorer, &(), &random_seed_bytes).unwrap();
			assert_eq!(route.paths.len(), 1);
			let path = route.paths.last().unwrap();
			assert_eq!(path.hops.len(), 2);
			assert_eq!(path.hops.last().unwrap().pubkey, nodes[2]);
			assert_eq!(path.final_value_msat(), 200_000_000);
		}

		// Enable channel #1 back.
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 1,
			timestamp: 4,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 1_000_000_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});


		// Now let's see if routing works if we know only htlc_maximum_msat.
		update_channel(&gossip_sync, &secp_ctx, &privkeys[0], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 3,
			timestamp: 3,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 15_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		{
			// Attempt to route more than available results in a failure.
			if let Err(LightningError{err, action: ErrorAction::IgnoreError}) = get_route(
					&our_id, &payment_params, &network_graph.read_only(), None, 15_001, Arc::clone(&logger), &scorer, &(), &random_seed_bytes) {
				assert_eq!(err, "Failed to find a sufficient route to the given destination");
			} else { panic!(); }
		}

		{
			// Now, attempt to route an exact amount we have should be fine.
			let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 15_000, Arc::clone(&logger), &scorer, &(), &random_seed_bytes).unwrap();
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
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 3,
			timestamp: 4,
			flags: 2,
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
		.push_opcode(opcodes::all::OP_CHECKMULTISIG).into_script().to_v0_p2wsh();

		*chain_monitor.utxo_ret.lock().unwrap() =
			UtxoResult::Sync(Ok(TxOut { value: 15, script_pubkey: good_script.clone() }));
		gossip_sync.add_utxo_lookup(Some(chain_monitor));

		add_channel(&gossip_sync, &secp_ctx, &privkeys[0], &privkeys[2], ChannelFeatures::from_le_bytes(id_to_feature_flags(3)), 333);
		update_channel(&gossip_sync, &secp_ctx, &privkeys[0], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 333,
			timestamp: 1,
			flags: 0,
			cltv_expiry_delta: (3 << 4) | 1,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 15_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 333,
			timestamp: 1,
			flags: 1,
			cltv_expiry_delta: (3 << 4) | 2,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 15_000,
			fee_base_msat: 100,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		{
			// Attempt to route more than available results in a failure.
			if let Err(LightningError{err, action: ErrorAction::IgnoreError}) = get_route(
					&our_id, &payment_params, &network_graph.read_only(), None, 15_001, Arc::clone(&logger), &scorer, &(), &random_seed_bytes) {
				assert_eq!(err, "Failed to find a sufficient route to the given destination");
			} else { panic!(); }
		}

		{
			// Now, attempt to route an exact amount we have should be fine.
			let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 15_000, Arc::clone(&logger), &scorer, &(), &random_seed_bytes).unwrap();
			assert_eq!(route.paths.len(), 1);
			let path = route.paths.last().unwrap();
			assert_eq!(path.hops.len(), 2);
			assert_eq!(path.hops.last().unwrap().pubkey, nodes[2]);
			assert_eq!(path.final_value_msat(), 15_000);
		}

		// Now let's see if routing chooses htlc_maximum_msat over UTXO capacity.
		update_channel(&gossip_sync, &secp_ctx, &privkeys[0], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 333,
			timestamp: 6,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 10_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		{
			// Attempt to route more than available results in a failure.
			if let Err(LightningError{err, action: ErrorAction::IgnoreError}) = get_route(
					&our_id, &payment_params, &network_graph.read_only(), None, 10_001, Arc::clone(&logger), &scorer, &(), &random_seed_bytes) {
				assert_eq!(err, "Failed to find a sufficient route to the given destination");
			} else { panic!(); }
		}

		{
			// Now, attempt to route an exact amount we have should be fine.
			let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 10_000, Arc::clone(&logger), &scorer, &(), &random_seed_bytes).unwrap();
			assert_eq!(route.paths.len(), 1);
			let path = route.paths.last().unwrap();
			assert_eq!(path.hops.len(), 2);
			assert_eq!(path.hops.last().unwrap().pubkey, nodes[2]);
			assert_eq!(path.final_value_msat(), 10_000);
		}
	}

	#[test]
	fn available_liquidity_last_hop_test() {
		// Check that available liquidity properly limits the path even when only
		// one of the latter hops is limited.
		let (secp_ctx, network_graph, gossip_sync, _, logger) = build_graph();
		let (our_privkey, our_id, privkeys, nodes) = get_nodes(&secp_ctx);
		let scorer = ln_test_utils::TestScorer::new();
		let keys_manager = ln_test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();
		let config = UserConfig::default();
		let payment_params = PaymentParameters::from_node_id(nodes[3], 42).with_bolt11_features(channelmanager::provided_invoice_features(&config)).unwrap();

		// Path via {node7, node2, node4} is channels {12, 13, 6, 11}.
		// {12, 13, 11} have the capacities of 100, {6} has a capacity of 50.
		// Total capacity: 50 sats.

		// Disable other potential paths.
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 2,
			timestamp: 2,
			flags: 2,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 100_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 7,
			timestamp: 2,
			flags: 2,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 100_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		// Limit capacities

		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 12,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 100_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[7], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 13,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 100_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		update_channel(&gossip_sync, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 6,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 50_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[4], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 11,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 100_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		{
			// Attempt to route more than available results in a failure.
			if let Err(LightningError{err, action: ErrorAction::IgnoreError}) = get_route(
					&our_id, &payment_params, &network_graph.read_only(), None, 60_000, Arc::clone(&logger), &scorer, &(), &random_seed_bytes) {
				assert_eq!(err, "Failed to find a sufficient route to the given destination");
			} else { panic!(); }
		}

		{
			// Now, attempt to route 49 sats (just a bit below the capacity).
			let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 49_000, Arc::clone(&logger), &scorer, &(), &random_seed_bytes).unwrap();
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
			let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 50_000, Arc::clone(&logger), &scorer, &(), &random_seed_bytes).unwrap();
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
	fn ignore_fee_first_hop_test() {
		let (secp_ctx, network_graph, gossip_sync, _, logger) = build_graph();
		let (our_privkey, our_id, privkeys, nodes) = get_nodes(&secp_ctx);
		let scorer = ln_test_utils::TestScorer::new();
		let keys_manager = ln_test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();
		let payment_params = PaymentParameters::from_node_id(nodes[2], 42);

		// Path via node0 is channels {1, 3}. Limit them to 100 and 50 sats (total limit 50).
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 1,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 100_000,
			fee_base_msat: 1_000_000,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[0], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 3,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 50_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		{
			let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 50_000, Arc::clone(&logger), &scorer, &(), &random_seed_bytes).unwrap();
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
	fn simple_mpp_route_test() {
		let (secp_ctx, _, _, _, _) = build_graph();
		let (_, _, _, nodes) = get_nodes(&secp_ctx);
		let config = UserConfig::default();
		let clear_payment_params = PaymentParameters::from_node_id(nodes[2], 42)
			.with_bolt11_features(channelmanager::provided_invoice_features(&config)).unwrap();
		do_simple_mpp_route_test(clear_payment_params);

		// MPP to a 1-hop blinded path for nodes[2]
		let bolt12_features: Bolt12InvoiceFeatures = channelmanager::provided_invoice_features(&config).to_context();
		let blinded_path = BlindedPath {
			introduction_node_id: nodes[2],
			blinding_point: ln_test_utils::pubkey(42),
			blinded_hops: vec![BlindedHop { blinded_node_id: ln_test_utils::pubkey(42 as u8), encrypted_payload: Vec::new() }],
		};
		let blinded_payinfo = BlindedPayInfo { // These fields are ignored for 1-hop blinded paths
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 0,
			cltv_expiry_delta: 0,
			features: BlindedHopFeatures::empty(),
		};
		let one_hop_blinded_payment_params = PaymentParameters::blinded(vec![(blinded_payinfo.clone(), blinded_path.clone())])
			.with_bolt12_features(bolt12_features.clone()).unwrap();
		do_simple_mpp_route_test(one_hop_blinded_payment_params.clone());

		// MPP to 3 2-hop blinded paths
		let mut blinded_path_node_0 = blinded_path.clone();
		blinded_path_node_0.introduction_node_id = nodes[0];
		blinded_path_node_0.blinded_hops.push(blinded_path.blinded_hops[0].clone());
		let mut node_0_payinfo = blinded_payinfo.clone();
		node_0_payinfo.htlc_maximum_msat = 50_000;

		let mut blinded_path_node_7 = blinded_path_node_0.clone();
		blinded_path_node_7.introduction_node_id = nodes[7];
		let mut node_7_payinfo = blinded_payinfo.clone();
		node_7_payinfo.htlc_maximum_msat = 60_000;

		let mut blinded_path_node_1 = blinded_path_node_0.clone();
		blinded_path_node_1.introduction_node_id = nodes[1];
		let mut node_1_payinfo = blinded_payinfo.clone();
		node_1_payinfo.htlc_maximum_msat = 180_000;

		let two_hop_blinded_payment_params = PaymentParameters::blinded(
			vec![
				(node_0_payinfo, blinded_path_node_0),
				(node_7_payinfo, blinded_path_node_7),
				(node_1_payinfo, blinded_path_node_1)
			])
			.with_bolt12_features(bolt12_features).unwrap();
		do_simple_mpp_route_test(two_hop_blinded_payment_params);
	}


	fn do_simple_mpp_route_test(payment_params: PaymentParameters) {
		let (secp_ctx, network_graph, gossip_sync, _, logger) = build_graph();
		let (our_privkey, our_id, privkeys, nodes) = get_nodes(&secp_ctx);
		let scorer = ln_test_utils::TestScorer::new();
		let keys_manager = ln_test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();

		// We need a route consisting of 3 paths:
		// From our node to node2 via node0, node7, node1 (three paths one hop each).
		// To achieve this, the amount being transferred should be around
		// the total capacity of these 3 paths.

		// First, we set limits on these (previously unlimited) channels.
		// Their aggregate capacity will be 50 + 60 + 180 = 290 sats.

		// Path via node0 is channels {1, 3}. Limit them to 100 and 50 sats (total limit 50).
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 1,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 100_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[0], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 3,
			timestamp: 2,
			flags: 0,
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
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 12,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 60_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[7], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 13,
			timestamp: 2,
			flags: 0,
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
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 2,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 200_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[1], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 4,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 180_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		{
			// Attempt to route more than available results in a failure.
			if let Err(LightningError{err, action: ErrorAction::IgnoreError}) = get_route(
				&our_id, &payment_params, &network_graph.read_only(), None, 300_000,
				Arc::clone(&logger), &scorer, &(), &random_seed_bytes) {
					assert_eq!(err, "Failed to find a sufficient route to the given destination");
			} else { panic!(); }
		}

		{
			// Attempt to route while setting max_path_count to 0 results in a failure.
			let zero_payment_params = payment_params.clone().with_max_path_count(0);
			if let Err(LightningError{err, action: ErrorAction::IgnoreError}) = get_route(
				&our_id, &zero_payment_params, &network_graph.read_only(), None, 100,
				Arc::clone(&logger), &scorer, &(), &random_seed_bytes) {
					assert_eq!(err, "Can't find a route with no paths allowed.");
			} else { panic!(); }
		}

		{
			// Attempt to route while setting max_path_count to 3 results in a failure.
			// This is the case because the minimal_value_contribution_msat would require each path
			// to account for 1/3 of the total value, which is violated by 2 out of 3 paths.
			let fail_payment_params = payment_params.clone().with_max_path_count(3);
			if let Err(LightningError{err, action: ErrorAction::IgnoreError}) = get_route(
				&our_id, &fail_payment_params, &network_graph.read_only(), None, 250_000,
				Arc::clone(&logger), &scorer, &(), &random_seed_bytes) {
					assert_eq!(err, "Failed to find a sufficient route to the given destination");
			} else { panic!(); }
		}

		{
			// Now, attempt to route 250 sats (just a bit below the capacity).
			// Our algorithm should provide us with these 3 paths.
			let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None,
				250_000, Arc::clone(&logger), &scorer, &(), &random_seed_bytes).unwrap();
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
			let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None,
				290_000, Arc::clone(&logger), &scorer, &(), &random_seed_bytes).unwrap();
			assert_eq!(route.paths.len(), 3);
			let mut total_amount_paid_msat = 0;
			for path in &route.paths {
				if payment_params.payee.blinded_route_hints().len() != 0 {
					assert!(path.blinded_tail.is_some()) } else { assert!(path.blinded_tail.is_none()) }
				if let Some(bt) = &path.blinded_tail {
					assert_eq!(path.hops.len() + if bt.hops.len() == 1 { 0 } else { 1 }, 2);
					if bt.hops.len() > 1 {
						assert_eq!(path.hops.last().unwrap().pubkey,
							payment_params.payee.blinded_route_hints().iter()
								.find(|(p, _)| p.htlc_maximum_msat == path.final_value_msat())
								.map(|(_, p)| p.introduction_node_id).unwrap());
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
	fn long_mpp_route_test() {
		let (secp_ctx, network_graph, gossip_sync, _, logger) = build_graph();
		let (our_privkey, our_id, privkeys, nodes) = get_nodes(&secp_ctx);
		let scorer = ln_test_utils::TestScorer::new();
		let keys_manager = ln_test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();
		let config = UserConfig::default();
		let payment_params = PaymentParameters::from_node_id(nodes[3], 42).with_bolt11_features(channelmanager::provided_invoice_features(&config)).unwrap();

		// We need a route consisting of 3 paths:
		// From our node to node3 via {node0, node2}, {node7, node2, node4} and {node7, node2}.
		// Note that these paths overlap (channels 5, 12, 13).
		// We will route 300 sats.
		// Each path will have 100 sats capacity, those channels which
		// are used twice will have 200 sats capacity.

		// Disable other potential paths.
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 2,
			timestamp: 2,
			flags: 2,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 100_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 7,
			timestamp: 2,
			flags: 2,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 100_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		// Path via {node0, node2} is channels {1, 3, 5}.
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 1,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 100_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[0], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 3,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 100_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		// Capacity of 200 sats because this channel will be used by 3rd path as well.
		add_channel(&gossip_sync, &secp_ctx, &privkeys[2], &privkeys[3], ChannelFeatures::from_le_bytes(id_to_feature_flags(5)), 5);
		update_channel(&gossip_sync, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 5,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 200_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		// Path via {node7, node2, node4} is channels {12, 13, 6, 11}.
		// Add 100 sats to the capacities of {12, 13}, because these channels
		// are also used for 3rd path. 100 sats for the rest. Total capacity: 100 sats.
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 12,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 200_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[7], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 13,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 200_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		update_channel(&gossip_sync, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 6,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 100_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[4], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 11,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 100_000,
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
					&our_id, &payment_params, &network_graph.read_only(), None, 350_000, Arc::clone(&logger), &scorer, &(), &random_seed_bytes) {
				assert_eq!(err, "Failed to find a sufficient route to the given destination");
			} else { panic!(); }
		}

		{
			// Now, attempt to route 300 sats (exact amount we can route).
			// Our algorithm should provide us with these 3 paths, 100 sats each.
			let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 300_000, Arc::clone(&logger), &scorer, &(), &random_seed_bytes).unwrap();
			assert_eq!(route.paths.len(), 3);

			let mut total_amount_paid_msat = 0;
			for path in &route.paths {
				assert_eq!(path.hops.last().unwrap().pubkey, nodes[3]);
				total_amount_paid_msat += path.final_value_msat();
			}
			assert_eq!(total_amount_paid_msat, 300_000);
		}

	}

	#[test]
	fn mpp_cheaper_route_test() {
		let (secp_ctx, network_graph, gossip_sync, _, logger) = build_graph();
		let (our_privkey, our_id, privkeys, nodes) = get_nodes(&secp_ctx);
		let scorer = ln_test_utils::TestScorer::new();
		let keys_manager = ln_test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();
		let config = UserConfig::default();
		let payment_params = PaymentParameters::from_node_id(nodes[3], 42).with_bolt11_features(channelmanager::provided_invoice_features(&config)).unwrap();

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
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 2,
			timestamp: 2,
			flags: 2,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 100_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 7,
			timestamp: 2,
			flags: 2,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 100_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		// Path via {node0, node2} is channels {1, 3, 5}.
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 1,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 100_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[0], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 3,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 100_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		// Capacity of 200 sats because this channel will be used by 3rd path as well.
		add_channel(&gossip_sync, &secp_ctx, &privkeys[2], &privkeys[3], ChannelFeatures::from_le_bytes(id_to_feature_flags(5)), 5);
		update_channel(&gossip_sync, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 5,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 200_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		// Path via {node7, node2, node4} is channels {12, 13, 6, 11}.
		// Add 100 sats to the capacities of {12, 13}, because these channels
		// are also used for 3rd path. 100 sats for the rest. Total capacity: 100 sats.
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 12,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 200_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[7], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 13,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 200_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		update_channel(&gossip_sync, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 6,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 100_000,
			fee_base_msat: 1_000,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[4], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 11,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 100_000,
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
			let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 180_000, Arc::clone(&logger), &scorer, &(), &random_seed_bytes).unwrap();
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
	}

	#[test]
	fn fees_on_mpp_route_test() {
		// This test makes sure that MPP algorithm properly takes into account
		// fees charged on the channels, by making the fees impactful:
		// if the fee is not properly accounted for, the behavior is different.
		let (secp_ctx, network_graph, gossip_sync, _, logger) = build_graph();
		let (our_privkey, our_id, privkeys, nodes) = get_nodes(&secp_ctx);
		let scorer = ln_test_utils::TestScorer::new();
		let keys_manager = ln_test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();
		let config = UserConfig::default();
		let payment_params = PaymentParameters::from_node_id(nodes[3], 42).with_bolt11_features(channelmanager::provided_invoice_features(&config)).unwrap();

		// We need a route consisting of 2 paths:
		// From our node to node3 via {node0, node2} and {node7, node2, node4}.
		// We will route 200 sats, Each path will have 100 sats capacity.

		// This test is not particularly stable: e.g.,
		// there's a way to route via {node0, node2, node4}.
		// It works while pathfinding is deterministic, but can be broken otherwise.
		// It's fine to ignore this concern for now.

		// Disable other potential paths.
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 2,
			timestamp: 2,
			flags: 2,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 100_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		update_channel(&gossip_sync, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 7,
			timestamp: 2,
			flags: 2,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 100_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		// Path via {node0, node2} is channels {1, 3, 5}.
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 1,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 100_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[0], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 3,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 100_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		add_channel(&gossip_sync, &secp_ctx, &privkeys[2], &privkeys[3], ChannelFeatures::from_le_bytes(id_to_feature_flags(5)), 5);
		update_channel(&gossip_sync, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 5,
			timestamp: 2,
			flags: 0,
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
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 12,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 250_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[7], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 13,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		update_channel(&gossip_sync, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 6,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 150_000,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[4], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 11,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		{
			// Attempt to route more than available results in a failure.
			if let Err(LightningError{err, action: ErrorAction::IgnoreError}) = get_route(
					&our_id, &payment_params, &network_graph.read_only(), None, 210_000, Arc::clone(&logger), &scorer, &(), &random_seed_bytes) {
				assert_eq!(err, "Failed to find a sufficient route to the given destination");
			} else { panic!(); }
		}

		{
			// Now, attempt to route 200 sats (exact amount we can route).
			let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 200_000, Arc::clone(&logger), &scorer, &(), &random_seed_bytes).unwrap();
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
		let keys_manager = ln_test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();
		let config = UserConfig::default();
		let payment_params = PaymentParameters::from_node_id(PublicKey::from_slice(&[02; 33]).unwrap(), 42).with_bolt11_features(channelmanager::provided_invoice_features(&config)).unwrap()
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
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 1,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: (5 << 4) | 5,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 99_000,
			fee_base_msat: u32::max_value(),
			fee_proportional_millionths: u32::max_value(),
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 2,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: (5 << 4) | 3,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 99_000,
			fee_base_msat: u32::max_value(),
			fee_proportional_millionths: u32::max_value(),
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[1], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 4,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: (4 << 4) | 1,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 1,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[7], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 13,
			timestamp: 2,
			flags: 0|2, // Channel disabled
			cltv_expiry_delta: (13 << 4) | 1,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,
			fee_proportional_millionths: 2000000,
			excess_data: Vec::new()
		});

		// Get a route for 100 sats and check that we found the MPP route no problem and didn't
		// overpay at all.
		let mut route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 100_000, Arc::clone(&logger), &scorer, &(), &random_seed_bytes).unwrap();
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
	fn drop_lowest_channel_mpp_route_test() {
		// This test checks that low-capacity channel is dropped when after
		// path finding we realize that we found more capacity than we need.
		let (secp_ctx, network_graph, gossip_sync, _, logger) = build_graph();
		let (our_privkey, our_id, privkeys, nodes) = get_nodes(&secp_ctx);
		let scorer = ln_test_utils::TestScorer::new();
		let keys_manager = ln_test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();
		let config = UserConfig::default();
		let payment_params = PaymentParameters::from_node_id(nodes[2], 42).with_bolt11_features(channelmanager::provided_invoice_features(&config)).unwrap()
			.with_max_channel_saturation_power_of_half(0);

		// We need a route consisting of 3 paths:
		// From our node to node2 via node0, node7, node1 (three paths one hop each).

		// The first and the second paths should be sufficient, but the third should be
		// cheaper, so that we select it but drop later.

		// First, we set limits on these (previously unlimited) channels.
		// Their aggregate capacity will be 50 + 60 + 20 = 130 sats.

		// Path via node0 is channels {1, 3}. Limit them to 100 and 50 sats (total limit 50);
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 1,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 100_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[0], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 3,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 50_000,
			fee_base_msat: 100,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		// Path via node7 is channels {12, 13}. Limit them to 60 and 60 sats (total limit 60);
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 12,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 60_000,
			fee_base_msat: 100,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[7], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 13,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 60_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		// Path via node1 is channels {2, 4}. Limit them to 20 and 20 sats (total capacity 20 sats).
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 2,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 20_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[1], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 4,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 20_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		{
			// Attempt to route more than available results in a failure.
			if let Err(LightningError{err, action: ErrorAction::IgnoreError}) = get_route(
					&our_id, &payment_params, &network_graph.read_only(), None, 150_000, Arc::clone(&logger), &scorer, &(), &random_seed_bytes) {
				assert_eq!(err, "Failed to find a sufficient route to the given destination");
			} else { panic!(); }
		}

		{
			// Now, attempt to route 125 sats (just a bit below the capacity of 3 channels).
			// Our algorithm should provide us with these 3 paths.
			let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 125_000, Arc::clone(&logger), &scorer, &(), &random_seed_bytes).unwrap();
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
			let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 90_000, Arc::clone(&logger), &scorer, &(), &random_seed_bytes).unwrap();
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
		let keys_manager = ln_test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();
		let payment_params = PaymentParameters::from_node_id(nodes[6], 42);

		add_channel(&gossip_sync, &secp_ctx, &our_privkey, &privkeys[1], ChannelFeatures::from_le_bytes(id_to_feature_flags(6)), 6);
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 6,
			timestamp: 1,
			flags: 0,
			cltv_expiry_delta: (6 << 4) | 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		add_or_update_node(&gossip_sync, &secp_ctx, &privkeys[1], NodeFeatures::from_le_bytes(id_to_feature_flags(1)), 0);

		add_channel(&gossip_sync, &secp_ctx, &privkeys[1], &privkeys[4], ChannelFeatures::from_le_bytes(id_to_feature_flags(5)), 5);
		update_channel(&gossip_sync, &secp_ctx, &privkeys[1], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 5,
			timestamp: 1,
			flags: 0,
			cltv_expiry_delta: (5 << 4) | 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 100,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		add_or_update_node(&gossip_sync, &secp_ctx, &privkeys[4], NodeFeatures::from_le_bytes(id_to_feature_flags(4)), 0);

		add_channel(&gossip_sync, &secp_ctx, &privkeys[4], &privkeys[3], ChannelFeatures::from_le_bytes(id_to_feature_flags(4)), 4);
		update_channel(&gossip_sync, &secp_ctx, &privkeys[4], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 4,
			timestamp: 1,
			flags: 0,
			cltv_expiry_delta: (4 << 4) | 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		add_or_update_node(&gossip_sync, &secp_ctx, &privkeys[3], NodeFeatures::from_le_bytes(id_to_feature_flags(3)), 0);

		add_channel(&gossip_sync, &secp_ctx, &privkeys[3], &privkeys[2], ChannelFeatures::from_le_bytes(id_to_feature_flags(3)), 3);
		update_channel(&gossip_sync, &secp_ctx, &privkeys[3], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 3,
			timestamp: 1,
			flags: 0,
			cltv_expiry_delta: (3 << 4) | 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		add_or_update_node(&gossip_sync, &secp_ctx, &privkeys[2], NodeFeatures::from_le_bytes(id_to_feature_flags(2)), 0);

		add_channel(&gossip_sync, &secp_ctx, &privkeys[2], &privkeys[4], ChannelFeatures::from_le_bytes(id_to_feature_flags(2)), 2);
		update_channel(&gossip_sync, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 2,
			timestamp: 1,
			flags: 0,
			cltv_expiry_delta: (2 << 4) | 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		add_channel(&gossip_sync, &secp_ctx, &privkeys[4], &privkeys[6], ChannelFeatures::from_le_bytes(id_to_feature_flags(1)), 1);
		update_channel(&gossip_sync, &secp_ctx, &privkeys[4], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 1,
			timestamp: 1,
			flags: 0,
			cltv_expiry_delta: (1 << 4) | 0,
			htlc_minimum_msat: 100,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		add_or_update_node(&gossip_sync, &secp_ctx, &privkeys[6], NodeFeatures::from_le_bytes(id_to_feature_flags(6)), 0);

		{
			// Now ensure the route flows simply over nodes 1 and 4 to 6.
			let route = get_route(&our_id, &payment_params, &network.read_only(), None, 10_000, Arc::clone(&logger), &scorer, &(), &random_seed_bytes).unwrap();
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
	fn exact_fee_liquidity_limit() {
		// Test that if, while walking the graph, we find a hop that has exactly enough liquidity
		// for us, including later hop fees, we take it. In the first version of our MPP algorithm
		// we calculated fees on a higher value, resulting in us ignoring such paths.
		let (secp_ctx, network_graph, gossip_sync, _, logger) = build_graph();
		let (our_privkey, our_id, _, nodes) = get_nodes(&secp_ctx);
		let scorer = ln_test_utils::TestScorer::new();
		let keys_manager = ln_test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();
		let payment_params = PaymentParameters::from_node_id(nodes[2], 42);

		// We modify the graph to set the htlc_maximum of channel 2 to below the value we wish to
		// send.
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 2,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 85_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 12,
			timestamp: 2,
			flags: 0,
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
			let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 90_000, Arc::clone(&logger), &scorer, &(), &random_seed_bytes).unwrap();
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
	fn htlc_max_reduction_below_min() {
		// Test that if, while walking the graph, we reduce the value being sent to meet an
		// htlc_maximum_msat, we don't end up undershooting a later htlc_minimum_msat. In the
		// initial version of MPP we'd accept such routes but reject them while recalculating fees,
		// resulting in us thinking there is no possible path, even if other paths exist.
		let (secp_ctx, network_graph, gossip_sync, _, logger) = build_graph();
		let (our_privkey, our_id, privkeys, nodes) = get_nodes(&secp_ctx);
		let scorer = ln_test_utils::TestScorer::new();
		let keys_manager = ln_test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();
		let config = UserConfig::default();
		let payment_params = PaymentParameters::from_node_id(nodes[2], 42).with_bolt11_features(channelmanager::provided_invoice_features(&config)).unwrap();

		// We modify the graph to set the htlc_minimum of channel 2 and 4 as needed - channel 2
		// gets an htlc_maximum_msat of 80_000 and channel 4 an htlc_minimum_msat of 90_000. We
		// then try to send 90_000.
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 2,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 80_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[1], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 4,
			timestamp: 2,
			flags: 0,
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
			let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 90_000, Arc::clone(&logger), &scorer, &(), &random_seed_bytes).unwrap();
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
			assert_eq!(route.paths[0].hops[1].node_features.le_flags(), channelmanager::provided_invoice_features(&config).le_flags());
			assert_eq!(route.paths[0].hops[1].channel_features.le_flags(), &id_to_feature_flags(13));
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
		let logger = Arc::new(ln_test_utils::TestLogger::new());
		let network_graph = NetworkGraph::new(Network::Testnet, Arc::clone(&logger));
		let scorer = ln_test_utils::TestScorer::new();
		let config = UserConfig::default();
		let payment_params = PaymentParameters::from_node_id(nodes[0], 42).with_bolt11_features(channelmanager::provided_invoice_features(&config)).unwrap();
		let keys_manager = ln_test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();

		{
			let route = get_route(&our_id, &payment_params, &network_graph.read_only(), Some(&[
				&get_channel_details(Some(3), nodes[0], channelmanager::provided_init_features(&config), 200_000),
				&get_channel_details(Some(2), nodes[0], channelmanager::provided_init_features(&config), 10_000),
			]), 100_000, Arc::clone(&logger), &scorer, &(), &random_seed_bytes).unwrap();
			assert_eq!(route.paths.len(), 1);
			assert_eq!(route.paths[0].hops.len(), 1);

			assert_eq!(route.paths[0].hops[0].pubkey, nodes[0]);
			assert_eq!(route.paths[0].hops[0].short_channel_id, 3);
			assert_eq!(route.paths[0].hops[0].fee_msat, 100_000);
		}
		{
			let route = get_route(&our_id, &payment_params, &network_graph.read_only(), Some(&[
				&get_channel_details(Some(3), nodes[0], channelmanager::provided_init_features(&config), 50_000),
				&get_channel_details(Some(2), nodes[0], channelmanager::provided_init_features(&config), 50_000),
			]), 100_000, Arc::clone(&logger), &scorer, &(), &random_seed_bytes).unwrap();
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
			let route = get_route(&our_id, &payment_params, &network_graph.read_only(), Some(&[
				&get_channel_details(Some(2), nodes[0], channelmanager::provided_init_features(&config), 50_000),
				&get_channel_details(Some(3), nodes[0], channelmanager::provided_init_features(&config), 50_000),
				&get_channel_details(Some(5), nodes[0], channelmanager::provided_init_features(&config), 50_000),
				&get_channel_details(Some(6), nodes[0], channelmanager::provided_init_features(&config), 300_000),
				&get_channel_details(Some(7), nodes[0], channelmanager::provided_init_features(&config), 50_000),
				&get_channel_details(Some(8), nodes[0], channelmanager::provided_init_features(&config), 50_000),
				&get_channel_details(Some(9), nodes[0], channelmanager::provided_init_features(&config), 50_000),
				&get_channel_details(Some(4), nodes[0], channelmanager::provided_init_features(&config), 1_000_000),
			]), 100_000, Arc::clone(&logger), &scorer, &(), &random_seed_bytes).unwrap();
			assert_eq!(route.paths.len(), 1);
			assert_eq!(route.paths[0].hops.len(), 1);

			assert_eq!(route.paths[0].hops[0].pubkey, nodes[0]);
			assert_eq!(route.paths[0].hops[0].short_channel_id, 6);
			assert_eq!(route.paths[0].hops[0].fee_msat, 100_000);
		}
	}

	#[test]
	fn prefers_shorter_route_with_higher_fees() {
		let (secp_ctx, network_graph, _, _, logger) = build_graph();
		let (_, our_id, _, nodes) = get_nodes(&secp_ctx);
		let payment_params = PaymentParameters::from_node_id(nodes[6], 42).with_route_hints(last_hops(&nodes)).unwrap();

		// Without penalizing each hop 100 msats, a longer path with lower fees is chosen.
		let scorer = ln_test_utils::TestScorer::new();
		let keys_manager = ln_test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();
		let route = get_route(
			&our_id, &payment_params, &network_graph.read_only(), None, 100,
			Arc::clone(&logger), &scorer, &(), &random_seed_bytes
		).unwrap();
		let path = route.paths[0].hops.iter().map(|hop| hop.short_channel_id).collect::<Vec<_>>();

		assert_eq!(route.get_total_fees(), 100);
		assert_eq!(route.get_total_amount(), 100);
		assert_eq!(path, vec![2, 4, 6, 11, 8]);

		// Applying a 100 msat penalty to each hop results in taking channels 7 and 10 to nodes[6]
		// from nodes[2] rather than channel 6, 11, and 8, even though the longer path is cheaper.
		let scorer = FixedPenaltyScorer::with_penalty(100);
		let route = get_route(
			&our_id, &payment_params, &network_graph.read_only(), None, 100,
			Arc::clone(&logger), &scorer, &(), &random_seed_bytes
		).unwrap();
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
		fn write<W: Writer>(&self, _w: &mut W) -> Result<(), crate::io::Error> { unimplemented!() }
	}
	impl Score for BadChannelScorer {
		type ScoreParams = ();
		fn channel_penalty_msat(&self, short_channel_id: u64, _: &NodeId, _: &NodeId, _: ChannelUsage, _score_params:&Self::ScoreParams) -> u64 {
			if short_channel_id == self.short_channel_id { u64::max_value() } else { 0 }
		}

		fn payment_path_failed(&mut self, _path: &Path, _short_channel_id: u64) {}
		fn payment_path_successful(&mut self, _path: &Path) {}
		fn probe_failed(&mut self, _path: &Path, _short_channel_id: u64) {}
		fn probe_successful(&mut self, _path: &Path) {}
	}

	struct BadNodeScorer {
		node_id: NodeId,
	}

	#[cfg(c_bindings)]
	impl Writeable for BadNodeScorer {
		fn write<W: Writer>(&self, _w: &mut W) -> Result<(), crate::io::Error> { unimplemented!() }
	}

	impl Score for BadNodeScorer {
		type ScoreParams = ();
		fn channel_penalty_msat(&self, _: u64, _: &NodeId, target: &NodeId, _: ChannelUsage, _score_params:&Self::ScoreParams) -> u64 {
			if *target == self.node_id { u64::max_value() } else { 0 }
		}

		fn payment_path_failed(&mut self, _path: &Path, _short_channel_id: u64) {}
		fn payment_path_successful(&mut self, _path: &Path) {}
		fn probe_failed(&mut self, _path: &Path, _short_channel_id: u64) {}
		fn probe_successful(&mut self, _path: &Path) {}
	}

	#[test]
	fn avoids_routing_through_bad_channels_and_nodes() {
		let (secp_ctx, network, _, _, logger) = build_graph();
		let (_, our_id, _, nodes) = get_nodes(&secp_ctx);
		let payment_params = PaymentParameters::from_node_id(nodes[6], 42).with_route_hints(last_hops(&nodes)).unwrap();
		let network_graph = network.read_only();

		// A path to nodes[6] exists when no penalties are applied to any channel.
		let scorer = ln_test_utils::TestScorer::new();
		let keys_manager = ln_test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();
		let route = get_route(
			&our_id, &payment_params, &network_graph, None, 100,
			Arc::clone(&logger), &scorer, &(), &random_seed_bytes
		).unwrap();
		let path = route.paths[0].hops.iter().map(|hop| hop.short_channel_id).collect::<Vec<_>>();

		assert_eq!(route.get_total_fees(), 100);
		assert_eq!(route.get_total_amount(), 100);
		assert_eq!(path, vec![2, 4, 6, 11, 8]);

		// A different path to nodes[6] exists if channel 6 cannot be routed over.
		let scorer = BadChannelScorer { short_channel_id: 6 };
		let route = get_route(
			&our_id, &payment_params, &network_graph, None, 100,
			Arc::clone(&logger), &scorer, &(), &random_seed_bytes
		).unwrap();
		let path = route.paths[0].hops.iter().map(|hop| hop.short_channel_id).collect::<Vec<_>>();

		assert_eq!(route.get_total_fees(), 300);
		assert_eq!(route.get_total_amount(), 100);
		assert_eq!(path, vec![2, 4, 7, 10]);

		// A path to nodes[6] does not exist if nodes[2] cannot be routed through.
		let scorer = BadNodeScorer { node_id: NodeId::from_pubkey(&nodes[2]) };
		match get_route(
			&our_id, &payment_params, &network_graph, None, 100,
			Arc::clone(&logger), &scorer, &(), &random_seed_bytes
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
			paths: vec![Path { hops: vec![
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
			], blinded_tail: None }],
			payment_params: None,
		};

		assert_eq!(route.get_total_fees(), 250);
		assert_eq!(route.get_total_amount(), 225);
	}

	#[test]
	fn total_fees_multi_path() {
		let route = Route {
			paths: vec![Path { hops: vec![
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
			], blinded_tail: None }, Path { hops: vec![
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
			], blinded_tail: None }],
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

		let scorer = ln_test_utils::TestScorer::new();

		// Make sure that generally there is at least one route available
		let feasible_max_total_cltv_delta = 1008;
		let feasible_payment_params = PaymentParameters::from_node_id(nodes[6], 0).with_route_hints(last_hops(&nodes)).unwrap()
			.with_max_total_cltv_expiry_delta(feasible_max_total_cltv_delta);
		let keys_manager = ln_test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();
		let route = get_route(&our_id, &feasible_payment_params, &network_graph, None, 100, Arc::clone(&logger), &scorer, &(), &random_seed_bytes).unwrap();
		let path = route.paths[0].hops.iter().map(|hop| hop.short_channel_id).collect::<Vec<_>>();
		assert_ne!(path.len(), 0);

		// But not if we exclude all paths on the basis of their accumulated CLTV delta
		let fail_max_total_cltv_delta = 23;
		let fail_payment_params = PaymentParameters::from_node_id(nodes[6], 0).with_route_hints(last_hops(&nodes)).unwrap()
			.with_max_total_cltv_expiry_delta(fail_max_total_cltv_delta);
		match get_route(&our_id, &fail_payment_params, &network_graph, None, 100, Arc::clone(&logger), &scorer, &(), &random_seed_bytes)
		{
			Err(LightningError { err, .. } ) => {
				assert_eq!(err, "Failed to find a path to the given destination");
			},
			Ok(_) => panic!("Expected error"),
		}
	}

	#[test]
	fn avoids_recently_failed_paths() {
		// Ensure that the router always avoids all of the `previously_failed_channels` channels by
		// randomly inserting channels into it until we can't find a route anymore.
		let (secp_ctx, network, _, _, logger) = build_graph();
		let (_, our_id, _, nodes) = get_nodes(&secp_ctx);
		let network_graph = network.read_only();

		let scorer = ln_test_utils::TestScorer::new();
		let mut payment_params = PaymentParameters::from_node_id(nodes[6], 0).with_route_hints(last_hops(&nodes)).unwrap()
			.with_max_path_count(1);
		let keys_manager = ln_test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();

		// We should be able to find a route initially, and then after we fail a few random
		// channels eventually we won't be able to any longer.
		assert!(get_route(&our_id, &payment_params, &network_graph, None, 100, Arc::clone(&logger), &scorer, &(), &random_seed_bytes).is_ok());
		loop {
			if let Ok(route) = get_route(&our_id, &payment_params, &network_graph, None, 100, Arc::clone(&logger), &scorer, &(), &random_seed_bytes) {
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
	fn limits_path_length() {
		let (secp_ctx, network, _, _, logger) = build_line_graph();
		let (_, our_id, _, nodes) = get_nodes(&secp_ctx);
		let network_graph = network.read_only();

		let scorer = ln_test_utils::TestScorer::new();
		let keys_manager = ln_test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();

		// First check we can actually create a long route on this graph.
		let feasible_payment_params = PaymentParameters::from_node_id(nodes[18], 0);
		let route = get_route(&our_id, &feasible_payment_params, &network_graph, None, 100,
			Arc::clone(&logger), &scorer, &(), &random_seed_bytes).unwrap();
		let path = route.paths[0].hops.iter().map(|hop| hop.short_channel_id).collect::<Vec<_>>();
		assert!(path.len() == MAX_PATH_LENGTH_ESTIMATE.into());

		// But we can't create a path surpassing the MAX_PATH_LENGTH_ESTIMATE limit.
		let fail_payment_params = PaymentParameters::from_node_id(nodes[19], 0);
		match get_route(&our_id, &fail_payment_params, &network_graph, None, 100,
			Arc::clone(&logger), &scorer, &(), &random_seed_bytes)
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

		let scorer = ln_test_utils::TestScorer::new();

		let payment_params = PaymentParameters::from_node_id(nodes[6], 42).with_route_hints(last_hops(&nodes)).unwrap();
		let keys_manager = ln_test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();
		let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 100, Arc::clone(&logger), &scorer, &(), &random_seed_bytes).unwrap();
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
	fn adds_plausible_cltv_offset() {
		let (secp_ctx, network, _, _, logger) = build_graph();
		let (_, our_id, _, nodes) = get_nodes(&secp_ctx);
		let network_graph = network.read_only();
		let network_nodes = network_graph.nodes();
		let network_channels = network_graph.channels();
		let scorer = ln_test_utils::TestScorer::new();
		let payment_params = PaymentParameters::from_node_id(nodes[3], 0);
		let keys_manager = ln_test_utils::TestKeysInterface::new(&[4u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();

		let mut route = get_route(&our_id, &payment_params, &network_graph, None, 100,
								  Arc::clone(&logger), &scorer, &(), &random_seed_bytes).unwrap();
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
	fn builds_correct_path_from_hops() {
		let (secp_ctx, network, _, _, logger) = build_graph();
		let (_, our_id, _, nodes) = get_nodes(&secp_ctx);
		let network_graph = network.read_only();

		let keys_manager = ln_test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();

		let payment_params = PaymentParameters::from_node_id(nodes[3], 0);
		let hops = [nodes[1], nodes[2], nodes[4], nodes[3]];
		let route = build_route_from_hops_internal(&our_id, &hops, &payment_params,
			 &network_graph, 100, Arc::clone(&logger), &random_seed_bytes).unwrap();
		let route_hop_pubkeys = route.paths[0].hops.iter().map(|hop| hop.pubkey).collect::<Vec<_>>();
		assert_eq!(hops.len(), route.paths[0].hops.len());
		for (idx, hop_pubkey) in hops.iter().enumerate() {
			assert!(*hop_pubkey == route_hop_pubkeys[idx]);
		}
	}

	#[test]
	fn avoids_saturating_channels() {
		let (secp_ctx, network_graph, gossip_sync, _, logger) = build_graph();
		let (_, our_id, privkeys, nodes) = get_nodes(&secp_ctx);
		let decay_params = ProbabilisticScoringDecayParameters::default();
		let scorer = ProbabilisticScorer::new(decay_params, &*network_graph, Arc::clone(&logger));

		// Set the fee on channel 13 to 100% to match channel 4 giving us two equivalent paths (us
		// -> node 7 -> node2 and us -> node 1 -> node 2) which we should balance over.
		update_channel(&gossip_sync, &secp_ctx, &privkeys[1], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 4,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: (4 << 4) | 1,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 250_000_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[7], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 13,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: (13 << 4) | 1,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 250_000_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		let config = UserConfig::default();
		let payment_params = PaymentParameters::from_node_id(nodes[2], 42).with_bolt11_features(channelmanager::provided_invoice_features(&config)).unwrap();
		let keys_manager = ln_test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();
		// 100,000 sats is less than the available liquidity on each channel, set above.
		let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 100_000_000, Arc::clone(&logger), &scorer, &ProbabilisticScoringFeeParameters::default(), &random_seed_bytes).unwrap();
		assert_eq!(route.paths.len(), 2);
		assert!((route.paths[0].hops[1].short_channel_id == 4 && route.paths[1].hops[1].short_channel_id == 13) ||
			(route.paths[1].hops[1].short_channel_id == 4 && route.paths[0].hops[1].short_channel_id == 13));
	}

	#[cfg(not(feature = "no-std"))]
	pub(super) fn random_init_seed() -> u64 {
		// Because the default HashMap in std pulls OS randomness, we can use it as a (bad) RNG.
		use core::hash::{BuildHasher, Hasher};
		let seed = std::collections::hash_map::RandomState::new().build_hasher().finish();
		println!("Using seed of {}", seed);
		seed
	}

	#[test]
	#[cfg(not(feature = "no-std"))]
	fn generate_routes() {
		use crate::routing::scoring::{ProbabilisticScorer, ProbabilisticScoringFeeParameters};

		let logger = ln_test_utils::TestLogger::new();
		let graph = match super::bench_utils::read_network_graph(&logger) {
			Ok(f) => f,
			Err(e) => {
				eprintln!("{}", e);
				return;
			},
		};

		let params = ProbabilisticScoringFeeParameters::default();
		let mut scorer = ProbabilisticScorer::new(ProbabilisticScoringDecayParameters::default(), &graph, &logger);
		let features = super::Bolt11InvoiceFeatures::empty();

		super::bench_utils::generate_test_routes(&graph, &mut scorer, &params, features, random_init_seed(), 0, 2);
	}

	#[test]
	#[cfg(not(feature = "no-std"))]
	fn generate_routes_mpp() {
		use crate::routing::scoring::{ProbabilisticScorer, ProbabilisticScoringFeeParameters};

		let logger = ln_test_utils::TestLogger::new();
		let graph = match super::bench_utils::read_network_graph(&logger) {
			Ok(f) => f,
			Err(e) => {
				eprintln!("{}", e);
				return;
			},
		};

		let params = ProbabilisticScoringFeeParameters::default();
		let mut scorer = ProbabilisticScorer::new(ProbabilisticScoringDecayParameters::default(), &graph, &logger);
		let features = channelmanager::provided_invoice_features(&UserConfig::default());

		super::bench_utils::generate_test_routes(&graph, &mut scorer, &params, features, random_init_seed(), 0, 2);
	}

	#[test]
	#[cfg(not(feature = "no-std"))]
	fn generate_large_mpp_routes() {
		use crate::routing::scoring::{ProbabilisticScorer, ProbabilisticScoringFeeParameters};

		let logger = ln_test_utils::TestLogger::new();
		let graph = match super::bench_utils::read_network_graph(&logger) {
			Ok(f) => f,
			Err(e) => {
				eprintln!("{}", e);
				return;
			},
		};

		let params = ProbabilisticScoringFeeParameters::default();
		let mut scorer = ProbabilisticScorer::new(ProbabilisticScoringDecayParameters::default(), &graph, &logger);
		let features = channelmanager::provided_invoice_features(&UserConfig::default());

		super::bench_utils::generate_test_routes(&graph, &mut scorer, &params, features, random_init_seed(), 1_000_000, 2);
	}

	#[test]
	fn honors_manual_penalties() {
		let (secp_ctx, network_graph, _, _, logger) = build_line_graph();
		let (_, our_id, _, nodes) = get_nodes(&secp_ctx);

		let keys_manager = ln_test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();

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
		assert_eq!(scorer.channel_penalty_msat(42, &NodeId::from_pubkey(&nodes[3]), &NodeId::from_pubkey(&nodes[4]), usage, &scorer_params), 456);

		// Then check we can get a normal route
		let payment_params = PaymentParameters::from_node_id(nodes[10], 42);
		let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 100, Arc::clone(&logger), &scorer, &scorer_params,&random_seed_bytes);
		assert!(route.is_ok());

		// Then check that we can't get a route if we ban an intermediate node.
		scorer_params.add_banned(&NodeId::from_pubkey(&nodes[3]));
		let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 100, Arc::clone(&logger), &scorer, &scorer_params,&random_seed_bytes);
		assert!(route.is_err());

		// Finally make sure we can route again, when we remove the ban.
		scorer_params.remove_banned(&NodeId::from_pubkey(&nodes[3]));
		let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 100, Arc::clone(&logger), &scorer, &scorer_params,&random_seed_bytes);
		assert!(route.is_ok());
	}

	#[test]
	fn abide_by_route_hint_max_htlc() {
		// Check that we abide by any htlc_maximum_msat provided in the route hints of the payment
		// params in the final route.
		let (secp_ctx, network_graph, _, _, logger) = build_graph();
		let netgraph = network_graph.read_only();
		let (_, our_id, _, nodes) = get_nodes(&secp_ctx);
		let scorer = ln_test_utils::TestScorer::new();
		let keys_manager = ln_test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();
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
			.with_bolt11_features(channelmanager::provided_invoice_features(&config)).unwrap();

		// Make sure we'll error if our route hints don't have enough liquidity according to their
		// htlc_maximum_msat.
		if let Err(LightningError{err, action: ErrorAction::IgnoreError}) = get_route(&our_id,
			&payment_params, &netgraph, None, max_htlc_msat + 1, Arc::clone(&logger), &scorer, &(),
			&random_seed_bytes)
		{
			assert_eq!(err, "Failed to find a sufficient route to the given destination");
		} else { panic!(); }

		// Make sure we'll split an MPP payment across route hints if their htlc_maximum_msat warrants.
		let mut route_hint_2 = route_hint_1.clone();
		route_hint_2.0[0].short_channel_id = 43;
		let payment_params = PaymentParameters::from_node_id(dest_node_id, 42)
			.with_route_hints(vec![route_hint_1, route_hint_2]).unwrap()
			.with_bolt11_features(channelmanager::provided_invoice_features(&config)).unwrap();
		let route = get_route(&our_id, &payment_params, &netgraph, None, max_htlc_msat + 1,
			Arc::clone(&logger), &scorer, &(), &random_seed_bytes).unwrap();
		assert_eq!(route.paths.len(), 2);
		assert!(route.paths[0].hops.last().unwrap().fee_msat <= max_htlc_msat);
		assert!(route.paths[1].hops.last().unwrap().fee_msat <= max_htlc_msat);
	}

	#[test]
	fn direct_channel_to_hints_with_max_htlc() {
		// Check that if we have a first hop channel peer that's connected to multiple provided route
		// hints, that we properly split the payment between the route hints if needed.
		let logger = Arc::new(ln_test_utils::TestLogger::new());
		let network_graph = Arc::new(NetworkGraph::new(Network::Testnet, Arc::clone(&logger)));
		let scorer = ln_test_utils::TestScorer::new();
		let keys_manager = ln_test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();
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
			.with_bolt11_features(channelmanager::provided_invoice_features(&config)).unwrap();

		let route = get_route(&our_node_id, &payment_params, &network_graph.read_only(),
			Some(&first_hop.iter().collect::<Vec<_>>()), amt_msat, Arc::clone(&logger), &scorer, &(),
			&random_seed_bytes).unwrap();
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
		let route = get_route(&our_node_id, &payment_params, &network_graph.read_only(),
			Some(&first_hops.iter().collect::<Vec<_>>()), amt_msat, Arc::clone(&logger), &scorer, &(),
			&random_seed_bytes).unwrap();
		assert_eq!(route.paths.len(), 2);
		assert!(route.paths[0].hops.last().unwrap().fee_msat <= max_htlc_msat);
		assert!(route.paths[1].hops.last().unwrap().fee_msat <= max_htlc_msat);
		assert_eq!(route.get_total_amount(), amt_msat);

		// Make sure this works for blinded route hints.
		let blinded_path = BlindedPath {
			introduction_node_id: intermed_node_id,
			blinding_point: ln_test_utils::pubkey(42),
			blinded_hops: vec![
				BlindedHop { blinded_node_id: ln_test_utils::pubkey(42), encrypted_payload: vec![] },
				BlindedHop { blinded_node_id: ln_test_utils::pubkey(43), encrypted_payload: vec![] },
			],
		};
		let blinded_payinfo = BlindedPayInfo {
			fee_base_msat: 100,
			fee_proportional_millionths: 0,
			htlc_minimum_msat: 1,
			htlc_maximum_msat: max_htlc_msat,
			cltv_expiry_delta: 10,
			features: BlindedHopFeatures::empty(),
		};
		let bolt12_features: Bolt12InvoiceFeatures = channelmanager::provided_invoice_features(&config).to_context();
		let payment_params = PaymentParameters::blinded(vec![
			(blinded_payinfo.clone(), blinded_path.clone()),
			(blinded_payinfo.clone(), blinded_path.clone())])
			.with_bolt12_features(bolt12_features).unwrap();
		let route = get_route(&our_node_id, &payment_params, &network_graph.read_only(),
			Some(&first_hops.iter().collect::<Vec<_>>()), amt_msat, Arc::clone(&logger), &scorer, &(),
			&random_seed_bytes).unwrap();
		assert_eq!(route.paths.len(), 2);
		assert!(route.paths[0].hops.last().unwrap().fee_msat <= max_htlc_msat);
		assert!(route.paths[1].hops.last().unwrap().fee_msat <= max_htlc_msat);
		assert_eq!(route.get_total_amount(), amt_msat);
	}

	#[test]
	fn blinded_route_ser() {
		let blinded_path_1 = BlindedPath {
			introduction_node_id: ln_test_utils::pubkey(42),
			blinding_point: ln_test_utils::pubkey(43),
			blinded_hops: vec![
				BlindedHop { blinded_node_id: ln_test_utils::pubkey(44), encrypted_payload: Vec::new() },
				BlindedHop { blinded_node_id: ln_test_utils::pubkey(45), encrypted_payload: Vec::new() }
			],
		};
		let blinded_path_2 = BlindedPath {
			introduction_node_id: ln_test_utils::pubkey(46),
			blinding_point: ln_test_utils::pubkey(47),
			blinded_hops: vec![
				BlindedHop { blinded_node_id: ln_test_utils::pubkey(48), encrypted_payload: Vec::new() },
				BlindedHop { blinded_node_id: ln_test_utils::pubkey(49), encrypted_payload: Vec::new() }
			],
		};
		// (De)serialize a Route with 1 blinded path out of two total paths.
		let mut route = Route { paths: vec![Path {
			hops: vec![RouteHop {
				pubkey: ln_test_utils::pubkey(50),
				node_features: NodeFeatures::empty(),
				short_channel_id: 42,
				channel_features: ChannelFeatures::empty(),
				fee_msat: 100,
				cltv_expiry_delta: 0,
			}],
			blinded_tail: Some(BlindedTail {
				hops: blinded_path_1.blinded_hops,
				blinding_point: blinded_path_1.blinding_point,
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
			}], blinded_tail: None }],
			payment_params: None,
		};
		let encoded_route = route.encode();
		let decoded_route: Route = Readable::read(&mut Cursor::new(&encoded_route[..])).unwrap();
		assert_eq!(decoded_route.paths[0].blinded_tail, route.paths[0].blinded_tail);
		assert_eq!(decoded_route.paths[1].blinded_tail, route.paths[1].blinded_tail);

		// (De)serialize a Route with two paths, each containing a blinded tail.
		route.paths[1].blinded_tail = Some(BlindedTail {
			hops: blinded_path_2.blinded_hops,
			blinding_point: blinded_path_2.blinding_point,
			excess_final_cltv_expiry_delta: 41,
			final_value_msat: 101,
		});
		let encoded_route = route.encode();
		let decoded_route: Route = Readable::read(&mut Cursor::new(&encoded_route[..])).unwrap();
		assert_eq!(decoded_route.paths[0].blinded_tail, route.paths[0].blinded_tail);
		assert_eq!(decoded_route.paths[1].blinded_tail, route.paths[1].blinded_tail);
	}

	#[test]
	fn blinded_path_inflight_processing() {
		// Ensure we'll score the channel that's inbound to a blinded path's introduction node, and
		// account for the blinded tail's final amount_msat.
		let mut inflight_htlcs = InFlightHtlcs::new();
		let blinded_path = BlindedPath {
			introduction_node_id: ln_test_utils::pubkey(43),
			blinding_point: ln_test_utils::pubkey(48),
			blinded_hops: vec![BlindedHop { blinded_node_id: ln_test_utils::pubkey(49), encrypted_payload: Vec::new() }],
		};
		let path = Path {
			hops: vec![RouteHop {
				pubkey: ln_test_utils::pubkey(42),
				node_features: NodeFeatures::empty(),
				short_channel_id: 42,
				channel_features: ChannelFeatures::empty(),
				fee_msat: 100,
				cltv_expiry_delta: 0,
			},
			RouteHop {
				pubkey: blinded_path.introduction_node_id,
				node_features: NodeFeatures::empty(),
				short_channel_id: 43,
				channel_features: ChannelFeatures::empty(),
				fee_msat: 1,
				cltv_expiry_delta: 0,
			}],
			blinded_tail: Some(BlindedTail {
				hops: blinded_path.blinded_hops,
				blinding_point: blinded_path.blinding_point,
				excess_final_cltv_expiry_delta: 0,
				final_value_msat: 200,
			}),
		};
		inflight_htlcs.process_path(&path, ln_test_utils::pubkey(44));
		assert_eq!(*inflight_htlcs.0.get(&(42, true)).unwrap(), 301);
		assert_eq!(*inflight_htlcs.0.get(&(43, false)).unwrap(), 201);
	}

	#[test]
	fn blinded_path_cltv_shadow_offset() {
		// Make sure we add a shadow offset when sending to blinded paths.
		let blinded_path = BlindedPath {
			introduction_node_id: ln_test_utils::pubkey(43),
			blinding_point: ln_test_utils::pubkey(44),
			blinded_hops: vec![
				BlindedHop { blinded_node_id: ln_test_utils::pubkey(45), encrypted_payload: Vec::new() },
				BlindedHop { blinded_node_id: ln_test_utils::pubkey(46), encrypted_payload: Vec::new() }
			],
		};
		let mut route = Route { paths: vec![Path {
			hops: vec![RouteHop {
				pubkey: ln_test_utils::pubkey(42),
				node_features: NodeFeatures::empty(),
				short_channel_id: 42,
				channel_features: ChannelFeatures::empty(),
				fee_msat: 100,
				cltv_expiry_delta: 0,
			},
			RouteHop {
				pubkey: blinded_path.introduction_node_id,
				node_features: NodeFeatures::empty(),
				short_channel_id: 43,
				channel_features: ChannelFeatures::empty(),
				fee_msat: 1,
				cltv_expiry_delta: 0,
			}
			],
			blinded_tail: Some(BlindedTail {
				hops: blinded_path.blinded_hops,
				blinding_point: blinded_path.blinding_point,
				excess_final_cltv_expiry_delta: 0,
				final_value_msat: 200,
			}),
		}], payment_params: None};

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

	fn do_simple_blinded_route_hints(num_blinded_hops: usize) {
		// Check that we can generate a route to a blinded path with the expected hops.
		let (secp_ctx, network, _, _, logger) = build_graph();
		let (_, our_id, _, nodes) = get_nodes(&secp_ctx);
		let network_graph = network.read_only();

		let scorer = ln_test_utils::TestScorer::new();
		let keys_manager = ln_test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();

		let mut blinded_path = BlindedPath {
			introduction_node_id: nodes[2],
			blinding_point: ln_test_utils::pubkey(42),
			blinded_hops: Vec::with_capacity(num_blinded_hops),
		};
		for i in 0..num_blinded_hops {
			blinded_path.blinded_hops.push(
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

		let final_amt_msat = 1001;
		let payment_params = PaymentParameters::blinded(vec![(blinded_payinfo.clone(), blinded_path.clone())]);
		let route = get_route(&our_id, &payment_params, &network_graph, None, final_amt_msat , Arc::clone(&logger),
			&scorer, &(), &random_seed_bytes).unwrap();
		assert_eq!(route.paths.len(), 1);
		assert_eq!(route.paths[0].hops.len(), 2);

		let tail = route.paths[0].blinded_tail.as_ref().unwrap();
		assert_eq!(tail.hops, blinded_path.blinded_hops);
		assert_eq!(tail.excess_final_cltv_expiry_delta, 0);
		assert_eq!(tail.final_value_msat, 1001);

		let final_hop = route.paths[0].hops.last().unwrap();
		assert_eq!(final_hop.pubkey, blinded_path.introduction_node_id);
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
	fn blinded_path_routing_errors() {
		// Check that we can generate a route to a blinded path with the expected hops.
		let (secp_ctx, network, _, _, logger) = build_graph();
		let (_, our_id, _, nodes) = get_nodes(&secp_ctx);
		let network_graph = network.read_only();

		let scorer = ln_test_utils::TestScorer::new();
		let keys_manager = ln_test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();

		let mut invalid_blinded_path = BlindedPath {
			introduction_node_id: nodes[2],
			blinding_point: ln_test_utils::pubkey(42),
			blinded_hops: vec![
				BlindedHop { blinded_node_id: ln_test_utils::pubkey(43), encrypted_payload: vec![0; 43] },
			],
		};
		let blinded_payinfo = BlindedPayInfo {
			fee_base_msat: 100,
			fee_proportional_millionths: 500,
			htlc_minimum_msat: 1000,
			htlc_maximum_msat: 100_000_000,
			cltv_expiry_delta: 15,
			features: BlindedHopFeatures::empty(),
		};

		let mut invalid_blinded_path_2 = invalid_blinded_path.clone();
		invalid_blinded_path_2.introduction_node_id = ln_test_utils::pubkey(45);
		let payment_params = PaymentParameters::blinded(vec![
			(blinded_payinfo.clone(), invalid_blinded_path.clone()),
			(blinded_payinfo.clone(), invalid_blinded_path_2)]);
		match get_route(&our_id, &payment_params, &network_graph, None, 1001, Arc::clone(&logger),
			&scorer, &(), &random_seed_bytes)
		{
			Err(LightningError { err, .. }) => {
				assert_eq!(err, "1-hop blinded paths must all have matching introduction node ids");
			},
			_ => panic!("Expected error")
		}

		invalid_blinded_path.introduction_node_id = our_id;
		let payment_params = PaymentParameters::blinded(vec![(blinded_payinfo.clone(), invalid_blinded_path.clone())]);
		match get_route(&our_id, &payment_params, &network_graph, None, 1001, Arc::clone(&logger),
			&scorer, &(), &random_seed_bytes)
		{
			Err(LightningError { err, .. }) => {
				assert_eq!(err, "Cannot generate a route to blinded paths if we are the introduction node to all of them");
			},
			_ => panic!("Expected error")
		}

		invalid_blinded_path.introduction_node_id = ln_test_utils::pubkey(46);
		invalid_blinded_path.blinded_hops.clear();
		let payment_params = PaymentParameters::blinded(vec![(blinded_payinfo, invalid_blinded_path)]);
		match get_route(&our_id, &payment_params, &network_graph, None, 1001, Arc::clone(&logger),
			&scorer, &(), &random_seed_bytes)
		{
			Err(LightningError { err, .. }) => {
				assert_eq!(err, "0-hop blinded path provided");
			},
			_ => panic!("Expected error")
		}
	}

	#[test]
	fn matching_intro_node_paths_provided() {
		// Check that if multiple blinded paths with the same intro node are provided in payment
		// parameters, we'll return the correct paths in the resulting MPP route.
		let (secp_ctx, network, _, _, logger) = build_graph();
		let (_, our_id, _, nodes) = get_nodes(&secp_ctx);
		let network_graph = network.read_only();

		let scorer = ln_test_utils::TestScorer::new();
		let keys_manager = ln_test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();
		let config = UserConfig::default();

		let bolt12_features: Bolt12InvoiceFeatures = channelmanager::provided_invoice_features(&config).to_context();
		let blinded_path_1 = BlindedPath {
			introduction_node_id: nodes[2],
			blinding_point: ln_test_utils::pubkey(42),
			blinded_hops: vec![
				BlindedHop { blinded_node_id: ln_test_utils::pubkey(42 as u8), encrypted_payload: Vec::new() },
				BlindedHop { blinded_node_id: ln_test_utils::pubkey(42 as u8), encrypted_payload: Vec::new() }
			],
		};
		let blinded_payinfo_1 = BlindedPayInfo {
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 30_000,
			cltv_expiry_delta: 0,
			features: BlindedHopFeatures::empty(),
		};

		let mut blinded_path_2 = blinded_path_1.clone();
		blinded_path_2.blinding_point = ln_test_utils::pubkey(43);
		let mut blinded_payinfo_2 = blinded_payinfo_1.clone();
		blinded_payinfo_2.htlc_maximum_msat = 70_000;

		let blinded_hints = vec![
			(blinded_payinfo_1.clone(), blinded_path_1.clone()),
			(blinded_payinfo_2.clone(), blinded_path_2.clone()),
		];
		let payment_params = PaymentParameters::blinded(blinded_hints.clone())
			.with_bolt12_features(bolt12_features.clone()).unwrap();

		let route = get_route(&our_id, &payment_params, &network_graph, None,
			100_000, Arc::clone(&logger), &scorer, &(), &random_seed_bytes).unwrap();
		assert_eq!(route.paths.len(), 2);
		let mut total_amount_paid_msat = 0;
		for path in route.paths.into_iter() {
			assert_eq!(path.hops.last().unwrap().pubkey, nodes[2]);
			if let Some(bt) = &path.blinded_tail {
				assert_eq!(bt.blinding_point,
					blinded_hints.iter().find(|(p, _)| p.htlc_maximum_msat == path.final_value_msat())
						.map(|(_, bp)| bp.blinding_point).unwrap());
			} else { panic!(); }
			total_amount_paid_msat += path.final_value_msat();
		}
		assert_eq!(total_amount_paid_msat, 100_000);
	}

	#[test]
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
		let keys_manager = ln_test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();

		let amt_msat = 10_000_000;
		let (_, _, privkeys, nodes) = get_nodes(&secp_ctx);
		add_channel(&gossip_sync, &secp_ctx, &privkeys[0], &privkeys[1],
			ChannelFeatures::from_le_bytes(id_to_feature_flags(1)), 1);
		update_channel(&gossip_sync, &secp_ctx, &privkeys[0], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 1,
			timestamp: 1,
			flags: 0,
			cltv_expiry_delta: 42,
			htlc_minimum_msat: 1_000,
			htlc_maximum_msat: 10_000_000,
			fee_base_msat: 800,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[1], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 1,
			timestamp: 1,
			flags: 1,
			cltv_expiry_delta: 42,
			htlc_minimum_msat: 1_000,
			htlc_maximum_msat: 10_000_000,
			fee_base_msat: 800,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		let first_hops = vec![
			get_channel_details(Some(1), nodes[1], InitFeatures::from_le_bytes(vec![0b11]), 10_000_000)];

		let blinded_path = BlindedPath {
			introduction_node_id: nodes[1],
			blinding_point: ln_test_utils::pubkey(42),
			blinded_hops: vec![
				BlindedHop { blinded_node_id: ln_test_utils::pubkey(42 as u8), encrypted_payload: Vec::new() },
				BlindedHop { blinded_node_id: ln_test_utils::pubkey(42 as u8), encrypted_payload: Vec::new() }
			],
		};
		let blinded_payinfo = BlindedPayInfo {
			fee_base_msat: 1000,
			fee_proportional_millionths: 0,
			htlc_minimum_msat: 1000,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			cltv_expiry_delta: 0,
			features: BlindedHopFeatures::empty(),
		};
		let blinded_hints = vec![(blinded_payinfo.clone(), blinded_path)];

		let payment_params = PaymentParameters::blinded(blinded_hints.clone());

		let netgraph = network_graph.read_only();
		if let Err(LightningError { err, .. }) = get_route(&nodes[0], &payment_params, &netgraph,
			Some(&first_hops.iter().collect::<Vec<_>>()), amt_msat, Arc::clone(&logger), &scorer, &(),
			&random_seed_bytes) {
			assert_eq!(err, "Failed to find a path to the given destination");
		} else { panic!("Expected error") }

		// Sending an exact amount accounting for the blinded path fee works.
		let amt_minus_blinded_path_fee = amt_msat - blinded_payinfo.fee_base_msat as u64;
		let route = get_route(&nodes[0], &payment_params, &netgraph,
			Some(&first_hops.iter().collect::<Vec<_>>()), amt_minus_blinded_path_fee,
			Arc::clone(&logger), &scorer, &(), &random_seed_bytes).unwrap();
		assert_eq!(route.get_total_fees(), blinded_payinfo.fee_base_msat as u64);
		assert_eq!(route.get_total_amount(), amt_minus_blinded_path_fee);
	}

	#[test]
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
		let keys_manager = ln_test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();
		let config = UserConfig::default();

		// Values are taken from the fuzz input that uncovered this panic.
		let amt_msat = 21_7020_5185_1403_2640;
		let (_, _, _, nodes) = get_nodes(&secp_ctx);
		let first_hops = vec![
			get_channel_details(Some(1), nodes[1], channelmanager::provided_init_features(&config),
				18446744073709551615)];

		let blinded_path = BlindedPath {
			introduction_node_id: nodes[1],
			blinding_point: ln_test_utils::pubkey(42),
			blinded_hops: vec![
				BlindedHop { blinded_node_id: ln_test_utils::pubkey(42 as u8), encrypted_payload: Vec::new() },
				BlindedHop { blinded_node_id: ln_test_utils::pubkey(42 as u8), encrypted_payload: Vec::new() }
			],
		};
		let blinded_payinfo = BlindedPayInfo {
			fee_base_msat: 5046_2720,
			fee_proportional_millionths: 0,
			htlc_minimum_msat: 4503_5996_2737_0496,
			htlc_maximum_msat: 45_0359_9627_3704_9600,
			cltv_expiry_delta: 0,
			features: BlindedHopFeatures::empty(),
		};
		let mut blinded_hints = vec![
			(blinded_payinfo.clone(), blinded_path.clone()),
			(blinded_payinfo.clone(), blinded_path.clone()),
		];
		blinded_hints[1].0.fee_base_msat = 419_4304;
		blinded_hints[1].0.fee_proportional_millionths = 257;
		blinded_hints[1].0.htlc_minimum_msat = 280_8908_6115_8400;
		blinded_hints[1].0.htlc_maximum_msat = 2_8089_0861_1584_0000;
		blinded_hints[1].0.cltv_expiry_delta = 0;

		let bolt12_features: Bolt12InvoiceFeatures = channelmanager::provided_invoice_features(&config).to_context();
		let payment_params = PaymentParameters::blinded(blinded_hints.clone())
			.with_bolt12_features(bolt12_features.clone()).unwrap();

		let netgraph = network_graph.read_only();
		let route = get_route(&nodes[0], &payment_params, &netgraph,
			Some(&first_hops.iter().collect::<Vec<_>>()), amt_msat,
			Arc::clone(&logger), &scorer, &(), &random_seed_bytes).unwrap();
		assert_eq!(route.get_total_fees(), blinded_payinfo.fee_base_msat as u64);
		assert_eq!(route.get_total_amount(), amt_msat);
	}
}

#[cfg(all(any(test, ldk_bench), not(feature = "no-std")))]
pub(crate) mod bench_utils {
	use super::*;
	use std::fs::File;

	use bitcoin::hashes::Hash;
	use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};

	use crate::chain::transaction::OutPoint;
	use crate::sign::{EntropySource, KeysManager};
	use crate::ln::ChannelId;
	use crate::ln::channelmanager::{self, ChannelCounterparty, ChannelDetails};
	use crate::ln::features::Bolt11InvoiceFeatures;
	use crate::routing::gossip::NetworkGraph;
	use crate::util::config::UserConfig;
	use crate::util::ser::ReadableArgs;
	use crate::util::test_utils::TestLogger;

	/// Tries to open a network graph file, or panics with a URL to fetch it.
	pub(crate) fn get_route_file() -> Result<std::fs::File, &'static str> {
		let res = File::open("net_graph-2023-01-18.bin") // By default we're run in RL/lightning
			.or_else(|_| File::open("lightning/net_graph-2023-01-18.bin")) // We may be run manually in RL/
			.or_else(|_| { // Fall back to guessing based on the binary location
				// path is likely something like .../rust-lightning/target/debug/deps/lightning-...
				let mut path = std::env::current_exe().unwrap();
				path.pop(); // lightning-...
				path.pop(); // deps
				path.pop(); // debug
				path.pop(); // target
				path.push("lightning");
				path.push("net_graph-2023-01-18.bin");
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
				path.push("net_graph-2023-01-18.bin");
				File::open(path)
			})
		.map_err(|_| "Please fetch https://bitcoin.ninja/ldk-net_graph-v0.0.113-2023-01-18.bin and place it at lightning/net_graph-2023-01-18.bin");
		#[cfg(require_route_graph_test)]
		return Ok(res.unwrap());
		#[cfg(not(require_route_graph_test))]
		return res;
	}

	pub(crate) fn read_network_graph(logger: &TestLogger) -> Result<NetworkGraph<&TestLogger>, &'static str> {
		get_route_file().map(|mut f| NetworkGraph::read(&mut f, logger).unwrap())
	}

	pub(crate) fn payer_pubkey() -> PublicKey {
		let secp_ctx = Secp256k1::new();
		PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[42; 32]).unwrap())
	}

	#[inline]
	pub(crate) fn first_hop(node_id: PublicKey) -> ChannelDetails {
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
			is_public: true,
			inbound_htlc_minimum_msat: None,
			inbound_htlc_maximum_msat: None,
			config: None,
			feerate_sat_per_1000_weight: None,
			channel_shutdown_state: Some(channelmanager::ChannelShutdownState::NotShuttingDown),
		}
	}

	pub(crate) fn generate_test_routes<S: Score>(graph: &NetworkGraph<&TestLogger>, scorer: &mut S,
		score_params: &S::ScoreParams, features: Bolt11InvoiceFeatures, mut seed: u64,
		starting_amount: u64, route_count: usize,
	) -> Vec<(ChannelDetails, PaymentParameters, u64)> {
		let payer = payer_pubkey();
		let keys_manager = KeysManager::new(&[0u8; 32], 42, 42);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();

		let nodes = graph.read_only().nodes().clone();
		let mut route_endpoints = Vec::new();
		// Fetch 1.5x more routes than we need as after we do some scorer updates we may end up
		// with some routes we picked being un-routable.
		for _ in 0..route_count * 3 / 2 {
			loop {
				seed = seed.overflowing_mul(6364136223846793005).0.overflowing_add(1).0;
				let src = PublicKey::from_slice(nodes.unordered_keys()
					.skip((seed as usize) % nodes.len()).next().unwrap().as_slice()).unwrap();
				seed = seed.overflowing_mul(6364136223846793005).0.overflowing_add(1).0;
				let dst = PublicKey::from_slice(nodes.unordered_keys()
					.skip((seed as usize) % nodes.len()).next().unwrap().as_slice()).unwrap();
				let params = PaymentParameters::from_node_id(dst, 42)
					.with_bolt11_features(features.clone()).unwrap();
				let first_hop = first_hop(src);
				let amt = starting_amount + seed % 1_000_000;
				let path_exists =
					get_route(&payer, &params, &graph.read_only(), Some(&[&first_hop]),
						amt, &TestLogger::new(), &scorer, score_params, &random_seed_bytes).is_ok();
				if path_exists {
					// ...and seed the scorer with success and failure data...
					seed = seed.overflowing_mul(6364136223846793005).0.overflowing_add(1).0;
					let mut score_amt = seed % 1_000_000_000;
					loop {
						// Generate fail/success paths for a wider range of potential amounts with
						// MPP enabled to give us a chance to apply penalties for more potential
						// routes.
						let mpp_features = channelmanager::provided_invoice_features(&UserConfig::default());
						let params = PaymentParameters::from_node_id(dst, 42)
							.with_bolt11_features(mpp_features).unwrap();

						let route_res = get_route(&payer, &params, &graph.read_only(),
							Some(&[&first_hop]), score_amt, &TestLogger::new(), &scorer,
							score_params, &random_seed_bytes);
						if let Ok(route) = route_res {
							for path in route.paths {
								if seed & 0x80 == 0 {
									scorer.payment_path_successful(&path);
								} else {
									let short_channel_id = path.hops[path.hops.len() / 2].short_channel_id;
									scorer.payment_path_failed(&path, short_channel_id);
								}
								seed = seed.overflowing_mul(6364136223846793005).0.overflowing_add(1).0;
							}
							break;
						}
						// If we couldn't find a path with a higer amount, reduce and try again.
						score_amt /= 100;
					}

					route_endpoints.push((first_hop, params, amt));
					break;
				}
			}
		}

		// Because we've changed channel scores, it's possible we'll take different routes to the
		// selected destinations, possibly causing us to fail because, eg, the newly-selected path
		// requires a too-high CLTV delta.
		route_endpoints.retain(|(first_hop, params, amt)| {
			get_route(&payer, params, &graph.read_only(), Some(&[first_hop]), *amt,
				&TestLogger::new(), &scorer, score_params, &random_seed_bytes).is_ok()
		});
		route_endpoints.truncate(route_count);
		assert_eq!(route_endpoints.len(), route_count);
		route_endpoints
	}
}

#[cfg(ldk_bench)]
pub mod benches {
	use super::*;
	use crate::sign::{EntropySource, KeysManager};
	use crate::ln::channelmanager;
	use crate::ln::features::Bolt11InvoiceFeatures;
	use crate::routing::gossip::NetworkGraph;
	use crate::routing::scoring::{FixedPenaltyScorer, ProbabilisticScorer, ProbabilisticScoringFeeParameters, ProbabilisticScoringDecayParameters};
	use crate::util::config::UserConfig;
	use crate::util::logger::{Logger, Record};
	use crate::util::test_utils::TestLogger;

	use criterion::Criterion;

	struct DummyLogger {}
	impl Logger for DummyLogger {
		fn log(&self, _record: &Record) {}
	}

	pub fn generate_routes_with_zero_penalty_scorer(bench: &mut Criterion) {
		let logger = TestLogger::new();
		let network_graph = bench_utils::read_network_graph(&logger).unwrap();
		let scorer = FixedPenaltyScorer::with_penalty(0);
		generate_routes(bench, &network_graph, scorer, &(), Bolt11InvoiceFeatures::empty(), 0,
			"generate_routes_with_zero_penalty_scorer");
	}

	pub fn generate_mpp_routes_with_zero_penalty_scorer(bench: &mut Criterion) {
		let logger = TestLogger::new();
		let network_graph = bench_utils::read_network_graph(&logger).unwrap();
		let scorer = FixedPenaltyScorer::with_penalty(0);
		generate_routes(bench, &network_graph, scorer, &(),
			channelmanager::provided_invoice_features(&UserConfig::default()), 0,
			"generate_mpp_routes_with_zero_penalty_scorer");
	}

	pub fn generate_routes_with_probabilistic_scorer(bench: &mut Criterion) {
		let logger = TestLogger::new();
		let network_graph = bench_utils::read_network_graph(&logger).unwrap();
		let params = ProbabilisticScoringFeeParameters::default();
		let scorer = ProbabilisticScorer::new(ProbabilisticScoringDecayParameters::default(), &network_graph, &logger);
		generate_routes(bench, &network_graph, scorer, &params, Bolt11InvoiceFeatures::empty(), 0,
			"generate_routes_with_probabilistic_scorer");
	}

	pub fn generate_mpp_routes_with_probabilistic_scorer(bench: &mut Criterion) {
		let logger = TestLogger::new();
		let network_graph = bench_utils::read_network_graph(&logger).unwrap();
		let params = ProbabilisticScoringFeeParameters::default();
		let scorer = ProbabilisticScorer::new(ProbabilisticScoringDecayParameters::default(), &network_graph, &logger);
		generate_routes(bench, &network_graph, scorer, &params,
			channelmanager::provided_invoice_features(&UserConfig::default()), 0,
			"generate_mpp_routes_with_probabilistic_scorer");
	}

	pub fn generate_large_mpp_routes_with_probabilistic_scorer(bench: &mut Criterion) {
		let logger = TestLogger::new();
		let network_graph = bench_utils::read_network_graph(&logger).unwrap();
		let params = ProbabilisticScoringFeeParameters::default();
		let scorer = ProbabilisticScorer::new(ProbabilisticScoringDecayParameters::default(), &network_graph, &logger);
		generate_routes(bench, &network_graph, scorer, &params,
			channelmanager::provided_invoice_features(&UserConfig::default()), 100_000_000,
			"generate_large_mpp_routes_with_probabilistic_scorer");
	}

	fn generate_routes<S: Score>(
		bench: &mut Criterion, graph: &NetworkGraph<&TestLogger>, mut scorer: S,
		score_params: &S::ScoreParams, features: Bolt11InvoiceFeatures, starting_amount: u64,
		bench_name: &'static str,
	) {
		let payer = bench_utils::payer_pubkey();
		let keys_manager = KeysManager::new(&[0u8; 32], 42, 42);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();

		// First, get 100 (source, destination) pairs for which route-getting actually succeeds...
		let route_endpoints = bench_utils::generate_test_routes(graph, &mut scorer, score_params, features, 0xdeadbeef, starting_amount, 50);

		// ...then benchmark finding paths between the nodes we learned.
		let mut idx = 0;
		bench.bench_function(bench_name, |b| b.iter(|| {
			let (first_hop, params, amt) = &route_endpoints[idx % route_endpoints.len()];
			assert!(get_route(&payer, params, &graph.read_only(), Some(&[first_hop]), *amt,
				&DummyLogger{}, &scorer, score_params, &random_seed_bytes).is_ok());
			idx += 1;
		}));
	}
}
