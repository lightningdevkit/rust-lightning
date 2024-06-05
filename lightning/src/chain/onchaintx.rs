// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! The logic to build claims and bump in-flight transactions until confirmations.
//!
//! OnchainTxHandler objects are fully-part of ChannelMonitor and encapsulates all
//! building, tracking, bumping and notifications functions.

use bitcoin::blockdata::locktime::absolute::LockTime;
use bitcoin::blockdata::transaction::Transaction;
use bitcoin::blockdata::transaction::OutPoint as BitcoinOutPoint;
use bitcoin::blockdata::script::{Script, ScriptBuf};
use bitcoin::hashes::{Hash, HashEngine};
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hash_types::{Txid, BlockHash};
use bitcoin::secp256k1::PublicKey;
use bitcoin::secp256k1::{Secp256k1, ecdsa::Signature};
use bitcoin::secp256k1;

use crate::chain::chaininterface::compute_feerate_sat_per_1000_weight;
use crate::sign::{ChannelDerivationParameters, HTLCDescriptor, ChannelSigner, EntropySource, SignerProvider, ecdsa::EcdsaChannelSigner};
use crate::ln::msgs::DecodeError;
use crate::ln::types::PaymentPreimage;
use crate::ln::chan_utils::{self, ChannelTransactionParameters, HTLCOutputInCommitment, HolderCommitmentTransaction};
use crate::chain::ClaimId;
use crate::chain::chaininterface::{ConfirmationTarget, FeeEstimator, BroadcasterInterface, LowerBoundedFeeEstimator};
use crate::chain::channelmonitor::{ANTI_REORG_DELAY, CLTV_SHARED_CLAIM_BUFFER};
use crate::chain::package::{PackageSolvingData, PackageTemplate};
use crate::chain::transaction::MaybeSignedTransaction;
use crate::util::logger::Logger;
use crate::util::ser::{Readable, ReadableArgs, MaybeReadable, UpgradableRequired, Writer, Writeable};

use crate::io;
use crate::prelude::*;
use alloc::collections::BTreeMap;
use core::cmp;
use core::ops::Deref;
use core::mem::replace;
use core::mem::swap;
use crate::ln::features::ChannelTypeFeatures;

const MAX_ALLOC_SIZE: usize = 64*1024;

/// An entry for an [`OnchainEvent`], stating the block height when the event was observed and the
/// transaction causing it.
///
/// Used to determine when the on-chain event can be considered safe from a chain reorganization.
#[derive(Clone, PartialEq, Eq)]
struct OnchainEventEntry {
	txid: Txid,
	height: u32,
	block_hash: Option<BlockHash>, // Added as optional, will be filled in for any entry generated on 0.0.113 or after
	event: OnchainEvent,
}

impl OnchainEventEntry {
	fn confirmation_threshold(&self) -> u32 {
		self.height + ANTI_REORG_DELAY - 1
	}

	fn has_reached_confirmation_threshold(&self, height: u32) -> bool {
		height >= self.confirmation_threshold()
	}
}

/// Events for claims the [`OnchainTxHandler`] has generated. Once the events are considered safe
/// from a chain reorg, the [`OnchainTxHandler`] will act accordingly.
#[derive(Clone, PartialEq, Eq)]
enum OnchainEvent {
	/// A pending request has been claimed by a transaction spending the exact same set of outpoints
	/// as the request. This claim can either be ours or from the counterparty. Once the claiming
	/// transaction has met [`ANTI_REORG_DELAY`] confirmations, we consider it final and remove the
	/// pending request.
	Claim {
		claim_id: ClaimId,
	},
	/// The counterparty has claimed an outpoint from one of our pending requests through a
	/// different transaction than ours. If our transaction was attempting to claim multiple
	/// outputs, we need to drop the outpoint claimed by the counterparty and regenerate a new claim
	/// transaction for ourselves. We keep tracking, separately, the outpoint claimed by the
	/// counterparty up to [`ANTI_REORG_DELAY`] confirmations to ensure we attempt to re-claim it
	/// if the counterparty's claim is reorged from the chain.
	ContentiousOutpoint {
		package: PackageTemplate,
	}
}

impl Writeable for OnchainEventEntry {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		write_tlv_fields!(writer, {
			(0, self.txid, required),
			(1, self.block_hash, option),
			(2, self.height, required),
			(4, self.event, required),
		});
		Ok(())
	}
}

impl MaybeReadable for OnchainEventEntry {
	fn read<R: io::Read>(reader: &mut R) -> Result<Option<Self>, DecodeError> {
		let mut txid = Txid::all_zeros();
		let mut height = 0;
		let mut block_hash = None;
		let mut event = UpgradableRequired(None);
		read_tlv_fields!(reader, {
			(0, txid, required),
			(1, block_hash, option),
			(2, height, required),
			(4, event, upgradable_required),
		});
		Ok(Some(Self { txid, height, block_hash, event: _init_tlv_based_struct_field!(event, upgradable_required) }))
	}
}

impl_writeable_tlv_based_enum_upgradable!(OnchainEvent,
	(0, Claim) => {
		(0, claim_id, required),
	},
	(1, ContentiousOutpoint) => {
		(0, package, required),
	},
);

impl Readable for Option<Vec<Option<(usize, Signature)>>> {
	fn read<R: io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
		match Readable::read(reader)? {
			0u8 => Ok(None),
			1u8 => {
				let vlen: u64 = Readable::read(reader)?;
				let mut ret = Vec::with_capacity(cmp::min(vlen as usize, MAX_ALLOC_SIZE / ::core::mem::size_of::<Option<(usize, Signature)>>()));
				for _ in 0..vlen {
					ret.push(match Readable::read(reader)? {
						0u8 => None,
						1u8 => Some((<u64 as Readable>::read(reader)? as usize, Readable::read(reader)?)),
						_ => return Err(DecodeError::InvalidValue)
					});
				}
				Ok(Some(ret))
			},
			_ => Err(DecodeError::InvalidValue),
		}
	}
}

impl Writeable for Option<Vec<Option<(usize, Signature)>>> {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		match self {
			&Some(ref vec) => {
				1u8.write(writer)?;
				(vec.len() as u64).write(writer)?;
				for opt in vec.iter() {
					match opt {
						&Some((ref idx, ref sig)) => {
							1u8.write(writer)?;
							(*idx as u64).write(writer)?;
							sig.write(writer)?;
						},
						&None => 0u8.write(writer)?,
					}
				}
			},
			&None => 0u8.write(writer)?,
		}
		Ok(())
	}
}

/// The claim commonly referred to as the pre-signed second-stage HTLC transaction.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ExternalHTLCClaim {
	pub(crate) commitment_txid: Txid,
	pub(crate) per_commitment_number: u64,
	pub(crate) htlc: HTLCOutputInCommitment,
	pub(crate) preimage: Option<PaymentPreimage>,
	pub(crate) counterparty_sig: Signature,
	pub(crate) per_commitment_point: PublicKey,
}

// Represents the different types of claims for which events are yielded externally to satisfy said
// claims.
#[derive(Clone, PartialEq, Eq)]
pub(crate) enum ClaimEvent {
	/// Event yielded to signal that the commitment transaction fee must be bumped to claim any
	/// encumbered funds and proceed to HTLC resolution, if any HTLCs exist.
	BumpCommitment {
		package_target_feerate_sat_per_1000_weight: u32,
		commitment_tx: Transaction,
		anchor_output_idx: u32,
	},
	/// Event yielded to signal that the commitment transaction has confirmed and its HTLCs must be
	/// resolved by broadcasting a transaction with sufficient fee to claim them.
	BumpHTLC {
		target_feerate_sat_per_1000_weight: u32,
		htlcs: Vec<ExternalHTLCClaim>,
		tx_lock_time: LockTime,
	},
}

/// Represents the different ways an output can be claimed (i.e., spent to an address under our
/// control) onchain.
pub(crate) enum OnchainClaim {
	/// A finalized transaction pending confirmation spending the output to claim.
	Tx(MaybeSignedTransaction),
	/// An event yielded externally to signal additional inputs must be added to a transaction
	/// pending confirmation spending the output to claim.
	Event(ClaimEvent),
}

/// Represents the different feerate strategies a pending request can use when generating a claim.
pub(crate) enum FeerateStrategy {
	/// We must reuse the most recently used feerate, if any.
	RetryPrevious,
	/// We must pick the highest between the most recently used and the current feerate estimate.
	HighestOfPreviousOrNew,
	/// We must force a bump of the most recently used feerate, either by using the current feerate
	/// estimate if it's higher, or manually bumping.
	ForceBump,
}

/// OnchainTxHandler receives claiming requests, aggregates them if it's sound, broadcast and
/// do RBF bumping if possible.
#[derive(Clone)]
pub struct OnchainTxHandler<ChannelSigner: EcdsaChannelSigner> {
	channel_value_satoshis: u64,
	channel_keys_id: [u8; 32],
	destination_script: ScriptBuf,
	holder_commitment: HolderCommitmentTransaction,
	prev_holder_commitment: Option<HolderCommitmentTransaction>,

	pub(super) signer: ChannelSigner,
	pub(crate) channel_transaction_parameters: ChannelTransactionParameters,

	// Used to track claiming requests. If claim tx doesn't confirm before height timer expiration we need to bump
	// it (RBF or CPFP). If an input has been part of an aggregate tx at first claim try, we need to keep it within
	// another bumped aggregate tx to comply with RBF rules. We may have multiple claiming txn in the flight for the
	// same set of outpoints. One of the outpoints may be spent by a transaction not issued by us. That's why at
	// block connection we scan all inputs and if any of them is among a set of a claiming request we test for set
	// equality between spending transaction and claim request. If true, it means transaction was one our claiming one
	// after a security delay of 6 blocks we remove pending claim request. If false, it means transaction wasn't and
	// we need to regenerate new claim request with reduced set of still-claimable outpoints.
	// Key is identifier of the pending claim request, i.e the txid of the initial claiming transaction generated by
	// us and is immutable until all outpoint of the claimable set are post-anti-reorg-delay solved.
	// Entry is cache of elements need to generate a bumped claiming transaction (see ClaimTxBumpMaterial)
	#[cfg(test)] // Used in functional_test to verify sanitization
	pub(crate) pending_claim_requests: HashMap<ClaimId, PackageTemplate>,
	#[cfg(not(test))]
	pending_claim_requests: HashMap<ClaimId, PackageTemplate>,

	// Used to track external events that need to be forwarded to the `ChainMonitor`. This `Vec`
	// essentially acts as an insertion-ordered `HashMap` – there should only ever be one occurrence
	// of a `ClaimId`, which tracks its latest `ClaimEvent`, i.e., if a pending claim exists, and
	// a new block has been connected, resulting in a new claim, the previous will be replaced with
	// the new.
	//
	// These external events may be generated in the following cases:
	//	- A channel has been force closed by broadcasting the holder's latest commitment transaction
	//	- A block being connected/disconnected
	//	- Learning the preimage for an HTLC we can claim onchain
	pending_claim_events: Vec<(ClaimId, ClaimEvent)>,

	// Used to link outpoints claimed in a connected block to a pending claim request. The keys
	// represent the outpoints that our `ChannelMonitor` has detected we have keys/scripts to
	// claim. The values track the pending claim request identifier and the initial confirmation
	// block height, and are immutable until the outpoint has enough confirmations to meet our
	// [`ANTI_REORG_DELAY`]. The initial confirmation block height is used to remove the entry if
	// the block gets disconnected.
	#[cfg(test)] // Used in functional_test to verify sanitization
	pub claimable_outpoints: HashMap<BitcoinOutPoint, (ClaimId, u32)>,
	#[cfg(not(test))]
	claimable_outpoints: HashMap<BitcoinOutPoint, (ClaimId, u32)>,

	locktimed_packages: BTreeMap<u32, Vec<PackageTemplate>>,

	onchain_events_awaiting_threshold_conf: Vec<OnchainEventEntry>,

	pub(super) secp_ctx: Secp256k1<secp256k1::All>,
}

impl<ChannelSigner: EcdsaChannelSigner> PartialEq for OnchainTxHandler<ChannelSigner> {
	fn eq(&self, other: &Self) -> bool {
		// `signer`, `secp_ctx`, and `pending_claim_events` are excluded on purpose.
		self.channel_value_satoshis == other.channel_value_satoshis &&
			self.channel_keys_id == other.channel_keys_id &&
			self.destination_script == other.destination_script &&
			self.holder_commitment == other.holder_commitment &&
			self.prev_holder_commitment == other.prev_holder_commitment &&
			self.channel_transaction_parameters == other.channel_transaction_parameters &&
			self.pending_claim_requests == other.pending_claim_requests &&
			self.claimable_outpoints == other.claimable_outpoints &&
			self.locktimed_packages == other.locktimed_packages &&
			self.onchain_events_awaiting_threshold_conf == other.onchain_events_awaiting_threshold_conf
	}
}

const SERIALIZATION_VERSION: u8 = 1;
const MIN_SERIALIZATION_VERSION: u8 = 1;

impl<ChannelSigner: EcdsaChannelSigner> OnchainTxHandler<ChannelSigner> {
	pub(crate) fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		write_ver_prefix!(writer, SERIALIZATION_VERSION, MIN_SERIALIZATION_VERSION);

		self.destination_script.write(writer)?;
		self.holder_commitment.write(writer)?;
		None::<Option<Vec<Option<(usize, Signature)>>>>.write(writer)?; // holder_htlc_sigs
		self.prev_holder_commitment.write(writer)?;
		None::<Option<Vec<Option<(usize, Signature)>>>>.write(writer)?; // prev_holder_htlc_sigs

		self.channel_transaction_parameters.write(writer)?;

		// Write a zero-length signer. The data is no longer deserialized as of version 0.0.113 and
		// downgrades before version 0.0.113 are no longer supported as of version 0.0.119.
		0u32.write(writer)?;

		writer.write_all(&(self.pending_claim_requests.len() as u64).to_be_bytes())?;
		for (ref ancestor_claim_txid, request) in self.pending_claim_requests.iter() {
			ancestor_claim_txid.write(writer)?;
			request.write(writer)?;
		}

		writer.write_all(&(self.claimable_outpoints.len() as u64).to_be_bytes())?;
		for (ref outp, ref claim_and_height) in self.claimable_outpoints.iter() {
			outp.write(writer)?;
			claim_and_height.0.write(writer)?;
			claim_and_height.1.write(writer)?;
		}

		writer.write_all(&(self.locktimed_packages.len() as u64).to_be_bytes())?;
		for (ref locktime, ref packages) in self.locktimed_packages.iter() {
			locktime.write(writer)?;
			writer.write_all(&(packages.len() as u64).to_be_bytes())?;
			for ref package in packages.iter() {
				package.write(writer)?;
			}
		}

		writer.write_all(&(self.onchain_events_awaiting_threshold_conf.len() as u64).to_be_bytes())?;
		for ref entry in self.onchain_events_awaiting_threshold_conf.iter() {
			entry.write(writer)?;
		}

		write_tlv_fields!(writer, {});
		Ok(())
	}
}

impl<'a, 'b, ES: EntropySource, SP: SignerProvider> ReadableArgs<(&'a ES, &'b SP, u64, [u8; 32])> for OnchainTxHandler<SP::EcdsaSigner> {
	fn read<R: io::Read>(reader: &mut R, args: (&'a ES, &'b SP, u64, [u8; 32])) -> Result<Self, DecodeError> {
		let entropy_source = args.0;
		let signer_provider = args.1;
		let channel_value_satoshis = args.2;
		let channel_keys_id = args.3;

		let _ver = read_ver_prefix!(reader, SERIALIZATION_VERSION);

		let destination_script = Readable::read(reader)?;

		let holder_commitment = Readable::read(reader)?;
		let _holder_htlc_sigs: Option<Vec<Option<(usize, Signature)>>> = Readable::read(reader)?;
		let prev_holder_commitment = Readable::read(reader)?;
		let _prev_holder_htlc_sigs: Option<Vec<Option<(usize, Signature)>>> = Readable::read(reader)?;

		let channel_parameters = Readable::read(reader)?;

		// Read the serialized signer bytes, but don't deserialize them, as we'll obtain our signer
		// by re-deriving the private key material.
		let keys_len: u32 = Readable::read(reader)?;
		let mut bytes_read = 0;
		while bytes_read != keys_len as usize {
			// Read 1KB at a time to avoid accidentally allocating 4GB on corrupted channel keys
			let mut data = [0; 1024];
			let bytes_to_read = cmp::min(1024, keys_len as usize - bytes_read);
			let read_slice = &mut data[0..bytes_to_read];
			reader.read_exact(read_slice)?;
			bytes_read += bytes_to_read;
		}

		let mut signer = signer_provider.derive_channel_signer(channel_value_satoshis, channel_keys_id);
		signer.provide_channel_parameters(&channel_parameters);

		let pending_claim_requests_len: u64 = Readable::read(reader)?;
		let mut pending_claim_requests = hash_map_with_capacity(cmp::min(pending_claim_requests_len as usize, MAX_ALLOC_SIZE / 128));
		for _ in 0..pending_claim_requests_len {
			pending_claim_requests.insert(Readable::read(reader)?, Readable::read(reader)?);
		}

		let claimable_outpoints_len: u64 = Readable::read(reader)?;
		let mut claimable_outpoints = hash_map_with_capacity(cmp::min(pending_claim_requests_len as usize, MAX_ALLOC_SIZE / 128));
		for _ in 0..claimable_outpoints_len {
			let outpoint = Readable::read(reader)?;
			let ancestor_claim_txid = Readable::read(reader)?;
			let height = Readable::read(reader)?;
			claimable_outpoints.insert(outpoint, (ancestor_claim_txid, height));
		}

		let locktimed_packages_len: u64 = Readable::read(reader)?;
		let mut locktimed_packages = BTreeMap::new();
		for _ in 0..locktimed_packages_len {
			let locktime = Readable::read(reader)?;
			let packages_len: u64 = Readable::read(reader)?;
			let mut packages = Vec::with_capacity(cmp::min(packages_len as usize, MAX_ALLOC_SIZE / core::mem::size_of::<PackageTemplate>()));
			for _ in 0..packages_len {
				packages.push(Readable::read(reader)?);
			}
			locktimed_packages.insert(locktime, packages);
		}

		let waiting_threshold_conf_len: u64 = Readable::read(reader)?;
		let mut onchain_events_awaiting_threshold_conf = Vec::with_capacity(cmp::min(waiting_threshold_conf_len as usize, MAX_ALLOC_SIZE / 128));
		for _ in 0..waiting_threshold_conf_len {
			if let Some(val) = MaybeReadable::read(reader)? {
				onchain_events_awaiting_threshold_conf.push(val);
			}
		}

		read_tlv_fields!(reader, {});

		let mut secp_ctx = Secp256k1::new();
		secp_ctx.seeded_randomize(&entropy_source.get_secure_random_bytes());

		Ok(OnchainTxHandler {
			channel_value_satoshis,
			channel_keys_id,
			destination_script,
			holder_commitment,
			prev_holder_commitment,
			signer,
			channel_transaction_parameters: channel_parameters,
			claimable_outpoints,
			locktimed_packages,
			pending_claim_requests,
			onchain_events_awaiting_threshold_conf,
			pending_claim_events: Vec::new(),
			secp_ctx,
		})
	}
}

impl<ChannelSigner: EcdsaChannelSigner> OnchainTxHandler<ChannelSigner> {
	pub(crate) fn new(
		channel_value_satoshis: u64, channel_keys_id: [u8; 32], destination_script: ScriptBuf,
		signer: ChannelSigner, channel_parameters: ChannelTransactionParameters,
		holder_commitment: HolderCommitmentTransaction, secp_ctx: Secp256k1<secp256k1::All>
	) -> Self {
		OnchainTxHandler {
			channel_value_satoshis,
			channel_keys_id,
			destination_script,
			holder_commitment,
			prev_holder_commitment: None,
			signer,
			channel_transaction_parameters: channel_parameters,
			pending_claim_requests: new_hash_map(),
			claimable_outpoints: new_hash_map(),
			locktimed_packages: BTreeMap::new(),
			onchain_events_awaiting_threshold_conf: Vec::new(),
			pending_claim_events: Vec::new(),
			secp_ctx,
		}
	}

	pub(crate) fn get_prev_holder_commitment_to_self_value(&self) -> Option<u64> {
		self.prev_holder_commitment.as_ref().map(|commitment| commitment.to_broadcaster_value_sat())
	}

	pub(crate) fn get_cur_holder_commitment_to_self_value(&self) -> u64 {
		self.holder_commitment.to_broadcaster_value_sat()
	}

	pub(crate) fn get_and_clear_pending_claim_events(&mut self) -> Vec<(ClaimId, ClaimEvent)> {
		let mut events = Vec::new();
		swap(&mut events, &mut self.pending_claim_events);
		events
	}

	/// Triggers rebroadcasts/fee-bumps of pending claims from a force-closed channel. This is
	/// crucial in preventing certain classes of pinning attacks, detecting substantial mempool
	/// feerate changes between blocks, and ensuring reliability if broadcasting fails. We recommend
	/// invoking this every 30 seconds, or lower if running in an environment with spotty
	/// connections, like on mobile.
	pub(super) fn rebroadcast_pending_claims<B: Deref, F: Deref, L: Logger>(
		&mut self, current_height: u32, feerate_strategy: FeerateStrategy, broadcaster: &B,
		fee_estimator: &LowerBoundedFeeEstimator<F>, logger: &L,
	)
	where
		B::Target: BroadcasterInterface,
		F::Target: FeeEstimator,
	{
		let mut bump_requests = Vec::with_capacity(self.pending_claim_requests.len());
		for (claim_id, request) in self.pending_claim_requests.iter() {
			let inputs = request.outpoints();
			log_info!(logger, "Triggering rebroadcast/fee-bump for request with inputs {:?}", inputs);
			bump_requests.push((*claim_id, request.clone()));
		}
		for (claim_id, request) in bump_requests {
			self.generate_claim(current_height, &request, &feerate_strategy, fee_estimator, logger)
				.map(|(_, new_feerate, claim)| {
					let mut bumped_feerate = false;
					if let Some(mut_request) = self.pending_claim_requests.get_mut(&claim_id) {
						bumped_feerate = request.previous_feerate() > new_feerate;
						mut_request.set_feerate(new_feerate);
					}
					match claim {
						OnchainClaim::Tx(tx) => {
							if tx.is_fully_signed() {
								let log_start = if bumped_feerate { "Broadcasting RBF-bumped" } else { "Rebroadcasting" };
								log_info!(logger, "{} onchain {}", log_start, log_tx!(tx.0));
								broadcaster.broadcast_transactions(&[&tx.0]);
							} else {
								log_info!(logger, "Waiting for signature of unsigned onchain transaction {}", tx.0.txid());
							}
						},
						OnchainClaim::Event(event) => {
							let log_start = if bumped_feerate { "Yielding fee-bumped" } else { "Replaying" };
							log_info!(logger, "{} onchain event to spend inputs {:?}", log_start,
								request.outpoints());
							#[cfg(debug_assertions)] {
								debug_assert!(request.requires_external_funding());
								let num_existing = self.pending_claim_events.iter()
									.filter(|entry| entry.0 == claim_id).count();
								assert!(num_existing == 0 || num_existing == 1);
							}
							self.pending_claim_events.retain(|event| event.0 != claim_id);
							self.pending_claim_events.push((claim_id, event));
						}
					}
				});
		}
	}

	/// Lightning security model (i.e being able to redeem/timeout HTLC or penalize counterparty
	/// onchain) lays on the assumption of claim transactions getting confirmed before timelock
	/// expiration (CSV or CLTV following cases). In case of high-fee spikes, claim tx may get stuck
	/// in the mempool, so you need to bump its feerate quickly using Replace-By-Fee or
	/// Child-Pay-For-Parent.
	///
	/// Panics if there are signing errors, because signing operations in reaction to on-chain
	/// events are not expected to fail, and if they do, we may lose funds.
	fn generate_claim<F: Deref, L: Logger>(
		&mut self, cur_height: u32, cached_request: &PackageTemplate, feerate_strategy: &FeerateStrategy,
		fee_estimator: &LowerBoundedFeeEstimator<F>, logger: &L,
	) -> Option<(u32, u64, OnchainClaim)>
	where F::Target: FeeEstimator,
	{
		let request_outpoints = cached_request.outpoints();
		if request_outpoints.is_empty() {
			// Don't prune pending claiming request yet, we may have to resurrect HTLCs. Untractable
			// packages cannot be aggregated and will never be split, so we cannot end up with an
			// empty claim.
			debug_assert!(cached_request.is_malleable());
			return None;
		}
		// If we've seen transaction inclusion in the chain for all outpoints in our request, we
		// don't need to continue generating more claims. We'll keep tracking the request to fully
		// remove it once it reaches the confirmation threshold, or to generate a new claim if the
		// transaction is reorged out.
		let mut all_inputs_have_confirmed_spend = true;
		for outpoint in request_outpoints.iter() {
			if let Some((request_claim_id, _)) = self.claimable_outpoints.get(*outpoint) {
				// We check for outpoint spends within claims individually rather than as a set
				// since requests can have outpoints split off.
				if !self.onchain_events_awaiting_threshold_conf.iter()
					.any(|event_entry| if let OnchainEvent::Claim { claim_id } = event_entry.event {
						*request_claim_id == claim_id
					} else {
						// The onchain event is not a claim, keep seeking until we find one.
						false
					})
				{
					// Either we had no `OnchainEvent::Claim`, or we did but none matched the
					// outpoint's registered spend.
					all_inputs_have_confirmed_spend = false;
				}
			} else {
				// The request's outpoint spend does not exist yet.
				all_inputs_have_confirmed_spend = false;
			}
		}
		if all_inputs_have_confirmed_spend {
			return None;
		}

		// Compute new height timer to decide when we need to regenerate a new bumped version of the claim tx (if we
		// didn't receive confirmation of it before, or not enough reorg-safe depth on top of it).
		let new_timer = cached_request.get_height_timer(cur_height);
		if cached_request.is_malleable() {
			if cached_request.requires_external_funding() {
				let target_feerate_sat_per_1000_weight = cached_request.compute_package_feerate(
					fee_estimator, ConfirmationTarget::OnChainSweep, feerate_strategy,
				);
				if let Some(htlcs) = cached_request.construct_malleable_package_with_external_funding(self) {
					return Some((
						new_timer,
						target_feerate_sat_per_1000_weight as u64,
						OnchainClaim::Event(ClaimEvent::BumpHTLC {
							target_feerate_sat_per_1000_weight,
							htlcs,
							tx_lock_time: LockTime::from_consensus(cached_request.package_locktime(cur_height)),
						}),
					));
				} else {
					return None;
				}
			}

			let predicted_weight = cached_request.package_weight(&self.destination_script);
			if let Some((output_value, new_feerate)) = cached_request.compute_package_output(
				predicted_weight, self.destination_script.dust_value().to_sat(),
				feerate_strategy, fee_estimator, logger,
			) {
				assert!(new_feerate != 0);

				let transaction = cached_request.maybe_finalize_malleable_package(
					cur_height, self, output_value, self.destination_script.clone(), logger
				).unwrap();
				assert!(predicted_weight >= transaction.0.weight().to_wu());
				return Some((new_timer, new_feerate, OnchainClaim::Tx(transaction)));
			}
		} else {
			// Untractable packages cannot have their fees bumped through Replace-By-Fee. Some
			// packages may support fee bumping through Child-Pays-For-Parent, indicated by those
			// which require external funding.
			let mut inputs = cached_request.inputs();
			debug_assert_eq!(inputs.len(), 1);
			let tx = match cached_request.maybe_finalize_untractable_package(self, logger) {
				Some(tx) => tx,
				None => return None,
			};
			if !cached_request.requires_external_funding() {
				return Some((new_timer, 0, OnchainClaim::Tx(tx)));
			}
			return inputs.find_map(|input| match input {
				// Commitment inputs with anchors support are the only untractable inputs supported
				// thus far that require external funding.
				PackageSolvingData::HolderFundingOutput(output) => {
					debug_assert_eq!(tx.0.txid(), self.holder_commitment.trust().txid(),
						"Holder commitment transaction mismatch");

					let conf_target = ConfirmationTarget::OnChainSweep;
					let package_target_feerate_sat_per_1000_weight = cached_request
						.compute_package_feerate(fee_estimator, conf_target, feerate_strategy);
					if let Some(input_amount_sat) = output.funding_amount {
						let fee_sat = input_amount_sat - tx.0.output.iter().map(|output| output.value).sum::<u64>();
						let commitment_tx_feerate_sat_per_1000_weight =
							compute_feerate_sat_per_1000_weight(fee_sat, tx.0.weight().to_wu());
						if commitment_tx_feerate_sat_per_1000_weight >= package_target_feerate_sat_per_1000_weight {
							log_debug!(logger, "Pre-signed commitment {} already has feerate {} sat/kW above required {} sat/kW",
								tx.0.txid(), commitment_tx_feerate_sat_per_1000_weight,
								package_target_feerate_sat_per_1000_weight);
							return Some((new_timer, 0, OnchainClaim::Tx(tx.clone())));
						}
					}

					// We'll locate an anchor output we can spend within the commitment transaction.
					let funding_pubkey = &self.channel_transaction_parameters.holder_pubkeys.funding_pubkey;
					match chan_utils::get_anchor_output(&tx.0, funding_pubkey) {
						// An anchor output was found, so we should yield a funding event externally.
						Some((idx, _)) => {
							// TODO: Use a lower confirmation target when both our and the
							// counterparty's latest commitment don't have any HTLCs present.
							Some((
								new_timer,
								package_target_feerate_sat_per_1000_weight as u64,
								OnchainClaim::Event(ClaimEvent::BumpCommitment {
									package_target_feerate_sat_per_1000_weight,
									commitment_tx: tx.0.clone(),
									anchor_output_idx: idx,
								}),
							))
						},
						// An anchor output was not found. There's nothing we can do other than
						// attempt to broadcast the transaction with its current fee rate and hope
						// it confirms. This is essentially the same behavior as a commitment
						// transaction without anchor outputs.
						None => Some((new_timer, 0, OnchainClaim::Tx(tx.clone()))),
					}
				},
				_ => {
					debug_assert!(false, "Only HolderFundingOutput inputs should be untractable and require external funding");
					None
				},
			})
		}
		None
	}

	pub fn abandon_claim(&mut self, outpoint: &BitcoinOutPoint) {
		let claim_id = self.claimable_outpoints.get(outpoint).map(|(claim_id, _)| *claim_id)
			.or_else(|| {
				self.pending_claim_requests.iter()
					.find(|(_, claim)| claim.outpoints().iter().any(|claim_outpoint| *claim_outpoint == outpoint))
					.map(|(claim_id, _)| *claim_id)
			});
		if let Some(claim_id) = claim_id {
			if let Some(claim) = self.pending_claim_requests.remove(&claim_id) {
				for outpoint in claim.outpoints() {
					self.claimable_outpoints.remove(outpoint);
				}
			}
		} else {
			self.locktimed_packages.values_mut().for_each(|claims|
				claims.retain(|claim| !claim.outpoints().iter().any(|claim_outpoint| *claim_outpoint == outpoint)));
		}
	}

	/// Upon channelmonitor.block_connected(..) or upon provision of a preimage on the forward link
	/// for this channel, provide new relevant on-chain transactions and/or new claim requests.
	/// Together with `update_claims_view_from_matched_txn` this used to be named
	/// `block_connected`, but it is now also used for claiming an HTLC output if we receive a
	/// preimage after force-close.
	///
	/// `conf_height` represents the height at which the request was generated. This
	/// does not need to equal the current blockchain tip height, which should be provided via
	/// `cur_height`, however it must never be higher than `cur_height`.
	pub(super) fn update_claims_view_from_requests<B: Deref, F: Deref, L: Logger>(
		&mut self, requests: Vec<PackageTemplate>, conf_height: u32, cur_height: u32,
		broadcaster: &B, fee_estimator: &LowerBoundedFeeEstimator<F>, logger: &L
	) where
		B::Target: BroadcasterInterface,
		F::Target: FeeEstimator,
	{
		if !requests.is_empty() {
			log_debug!(logger, "Updating claims view at height {} with {} claim requests", cur_height, requests.len());
		}

		let mut preprocessed_requests = Vec::with_capacity(requests.len());
		let mut aggregated_request = None;

		// Try to aggregate outputs if their timelock expiration isn't imminent (package timelock
		// <= CLTV_SHARED_CLAIM_BUFFER) and they don't require an immediate nLockTime (aggregable).
		for req in requests {
			// Don't claim a outpoint twice that would be bad for privacy and may uselessly lock a CPFP input for a while
			if let Some(_) = self.claimable_outpoints.get(req.outpoints()[0]) {
				log_info!(logger, "Ignoring second claim for outpoint {}:{}, already registered its claiming request", req.outpoints()[0].txid, req.outpoints()[0].vout);
			} else {
				let timelocked_equivalent_package = self.locktimed_packages.iter().map(|v| v.1.iter()).flatten()
					.find(|locked_package| locked_package.outpoints() == req.outpoints());
				if let Some(package) = timelocked_equivalent_package {
					log_info!(logger, "Ignoring second claim for outpoint {}:{}, we already have one which we're waiting on a timelock at {} for.",
						req.outpoints()[0].txid, req.outpoints()[0].vout, package.package_locktime(cur_height));
					continue;
				}

				let package_locktime = req.package_locktime(cur_height);
				if package_locktime > cur_height + 1 {
					log_info!(logger, "Delaying claim of package until its timelock at {} (current height {}), the following outpoints are spent:", package_locktime, cur_height);
					for outpoint in req.outpoints() {
						log_info!(logger, "  Outpoint {}", outpoint);
					}
					self.locktimed_packages.entry(package_locktime).or_insert(Vec::new()).push(req);
					continue;
				}

				log_trace!(logger, "Test if outpoint can be aggregated with expiration {} against {}", req.timelock(), cur_height + CLTV_SHARED_CLAIM_BUFFER);
				if req.timelock() <= cur_height + CLTV_SHARED_CLAIM_BUFFER || !req.aggregable() {
					// Don't aggregate if outpoint package timelock is soon or marked as non-aggregable
					preprocessed_requests.push(req);
				} else if aggregated_request.is_none() {
					aggregated_request = Some(req);
				} else {
					aggregated_request.as_mut().unwrap().merge_package(req);
				}
			}
		}
		if let Some(req) = aggregated_request {
			preprocessed_requests.push(req);
		}

		// Claim everything up to and including `cur_height`
		let remaining_locked_packages = self.locktimed_packages.split_off(&(cur_height + 1));
		if !self.locktimed_packages.is_empty() {
			log_debug!(logger,
				"Updating claims view at height {} with {} locked packages available for claim",
				cur_height,
				self.locktimed_packages.len());
		}
		for (pop_height, mut entry) in self.locktimed_packages.iter_mut() {
			log_trace!(logger, "Restoring delayed claim of package(s) at their timelock at {}.", pop_height);
			preprocessed_requests.append(&mut entry);
		}
		self.locktimed_packages = remaining_locked_packages;

		// Generate claim transactions and track them to bump if necessary at
		// height timer expiration (i.e in how many blocks we're going to take action).
		for mut req in preprocessed_requests {
			if let Some((new_timer, new_feerate, claim)) = self.generate_claim(
				cur_height, &req, &FeerateStrategy::ForceBump, &*fee_estimator, &*logger,
			) {
				req.set_timer(new_timer);
				req.set_feerate(new_feerate);
				// Once a pending claim has an id assigned, it remains fixed until the claim is
				// satisfied, regardless of whether the claim switches between different variants of
				// `OnchainClaim`.
				let claim_id = match claim {
					OnchainClaim::Tx(tx) => {
						if tx.is_fully_signed() {
							log_info!(logger, "Broadcasting onchain {}", log_tx!(tx.0));
							broadcaster.broadcast_transactions(&[&tx.0]);
						} else {
							log_info!(logger, "Waiting for signature of unsigned onchain transaction {}", tx.0.txid());
						}
						ClaimId(tx.0.txid().to_byte_array())
					},
					OnchainClaim::Event(claim_event) => {
						log_info!(logger, "Yielding onchain event to spend inputs {:?}", req.outpoints());
						let claim_id = match claim_event {
							ClaimEvent::BumpCommitment { ref commitment_tx, .. } =>
								// For commitment claims, we can just use their txid as it should
								// already be unique.
								ClaimId(commitment_tx.txid().to_byte_array()),
							ClaimEvent::BumpHTLC { ref htlcs, .. } => {
								// For HTLC claims, commit to the entire set of HTLC outputs to
								// claim, which will always be unique per request. Once a claim ID
								// is generated, it is assigned and remains unchanged, even if the
								// underlying set of HTLCs changes.
								let mut engine = Sha256::engine();
								for htlc in htlcs {
									engine.input(&htlc.commitment_txid.to_byte_array());
									engine.input(&htlc.htlc.transaction_output_index.unwrap().to_be_bytes());
								}
								ClaimId(Sha256::from_engine(engine).to_byte_array())
							},
						};
						debug_assert!(self.pending_claim_requests.get(&claim_id).is_none());
						debug_assert_eq!(self.pending_claim_events.iter().filter(|entry| entry.0 == claim_id).count(), 0);
						self.pending_claim_events.push((claim_id, claim_event));
						claim_id
					},
				};
				// Because fuzzing can cause hash collisions, we can end up with conflicting claim
				// ids here, so we only assert when not fuzzing.
				debug_assert!(cfg!(fuzzing) || self.pending_claim_requests.get(&claim_id).is_none());
				for k in req.outpoints() {
					log_info!(logger, "Registering claiming request for {}:{}", k.txid, k.vout);
					self.claimable_outpoints.insert(k.clone(), (claim_id, conf_height));
				}
				self.pending_claim_requests.insert(claim_id, req);
			}
		}
	}

	/// Upon channelmonitor.block_connected(..) or upon provision of a preimage on the forward link
	/// for this channel, provide new relevant on-chain transactions and/or new claim requests.
	/// Together with `update_claims_view_from_requests` this used to be named `block_connected`,
	/// but it is now also used for claiming an HTLC output if we receive a preimage after force-close.
	///
	/// `conf_height` represents the height at which the transactions in `txn_matched` were
	/// confirmed. This does not need to equal the current blockchain tip height, which should be
	/// provided via `cur_height`, however it must never be higher than `cur_height`.
	pub(super) fn update_claims_view_from_matched_txn<B: Deref, F: Deref, L: Logger>(
		&mut self, txn_matched: &[&Transaction], conf_height: u32, conf_hash: BlockHash,
		cur_height: u32, broadcaster: &B, fee_estimator: &LowerBoundedFeeEstimator<F>, logger: &L
	) where
		B::Target: BroadcasterInterface,
		F::Target: FeeEstimator,
	{
		let mut have_logged_intro = false;
		let mut maybe_log_intro = || {
			if !have_logged_intro {
				log_debug!(logger, "Updating claims view at height {} with {} matched transactions in block {}", cur_height, txn_matched.len(), conf_height);
				have_logged_intro = true;
			}
		};
		let mut bump_candidates = new_hash_map();
		if !txn_matched.is_empty() { maybe_log_intro(); }
		for tx in txn_matched {
			// Scan all input to verify is one of the outpoint spent is of interest for us
			let mut claimed_outputs_material = Vec::new();
			for inp in &tx.input {
				if let Some((claim_id, _)) = self.claimable_outpoints.get(&inp.previous_output) {
					// If outpoint has claim request pending on it...
					if let Some(request) = self.pending_claim_requests.get_mut(claim_id) {
						//... we need to verify equality between transaction outpoints and claim request
						// outpoints to know if transaction is the original claim or a bumped one issued
						// by us.
						let mut are_sets_equal = true;
						let mut tx_inputs = tx.input.iter().map(|input| &input.previous_output).collect::<Vec<_>>();
						tx_inputs.sort_unstable();
						for request_input in request.outpoints() {
							if tx_inputs.binary_search(&request_input).is_err() {
								are_sets_equal = false;
								break;
							}
						}

						macro_rules! clean_claim_request_after_safety_delay {
							() => {
								let entry = OnchainEventEntry {
									txid: tx.txid(),
									height: conf_height,
									block_hash: Some(conf_hash),
									event: OnchainEvent::Claim { claim_id: *claim_id }
								};
								if !self.onchain_events_awaiting_threshold_conf.contains(&entry) {
									self.onchain_events_awaiting_threshold_conf.push(entry);
								}
							}
						}

						// If this is our transaction (or our counterparty spent all the outputs
						// before we could anyway with same inputs order than us), wait for
						// ANTI_REORG_DELAY and clean the RBF tracking map.
						if are_sets_equal {
							clean_claim_request_after_safety_delay!();
						} else { // If false, generate new claim request with update outpoint set
							let mut at_least_one_drop = false;
							for input in tx.input.iter() {
								if let Some(package) = request.split_package(&input.previous_output) {
									claimed_outputs_material.push(package);
									at_least_one_drop = true;
								}
								// If there are no outpoints left to claim in this request, drop it entirely after ANTI_REORG_DELAY.
								if request.outpoints().is_empty() {
									clean_claim_request_after_safety_delay!();
								}
							}
							//TODO: recompute soonest_timelock to avoid wasting a bit on fees
							if at_least_one_drop {
								bump_candidates.insert(*claim_id, request.clone());
								// If we have any pending claim events for the request being updated
								// that have yet to be consumed, we'll remove them since they will
								// end up producing an invalid transaction by double spending
								// input(s) that already have a confirmed spend. If such spend is
								// reorged out of the chain, then we'll attempt to re-spend the
								// inputs once we see it.
								#[cfg(debug_assertions)] {
									let existing = self.pending_claim_events.iter()
										.filter(|entry| entry.0 == *claim_id).count();
									assert!(existing == 0 || existing == 1);
								}
								self.pending_claim_events.retain(|entry| entry.0 != *claim_id);
							}
						}
						break; //No need to iterate further, either tx is our or their
					} else {
						panic!("Inconsistencies between pending_claim_requests map and claimable_outpoints map");
					}
				}
			}
			for package in claimed_outputs_material.drain(..) {
				let entry = OnchainEventEntry {
					txid: tx.txid(),
					height: conf_height,
					block_hash: Some(conf_hash),
					event: OnchainEvent::ContentiousOutpoint { package },
				};
				if !self.onchain_events_awaiting_threshold_conf.contains(&entry) {
					self.onchain_events_awaiting_threshold_conf.push(entry);
				}
			}
		}

		// After security delay, either our claim tx got enough confs or outpoint is definetely out of reach
		let onchain_events_awaiting_threshold_conf =
			self.onchain_events_awaiting_threshold_conf.drain(..).collect::<Vec<_>>();
		for entry in onchain_events_awaiting_threshold_conf {
			if entry.has_reached_confirmation_threshold(cur_height) {
				maybe_log_intro();
				match entry.event {
					OnchainEvent::Claim { claim_id } => {
						// We may remove a whole set of claim outpoints here, as these one may have
						// been aggregated in a single tx and claimed so atomically
						if let Some(request) = self.pending_claim_requests.remove(&claim_id) {
							for outpoint in request.outpoints() {
								log_debug!(logger, "Removing claim tracking for {} due to maturation of claim package {}.",
									outpoint, log_bytes!(claim_id.0));
								self.claimable_outpoints.remove(outpoint);
							}
							#[cfg(debug_assertions)] {
								let num_existing = self.pending_claim_events.iter()
									.filter(|entry| entry.0 == claim_id).count();
								assert!(num_existing == 0 || num_existing == 1);
							}
							self.pending_claim_events.retain(|(id, _)| *id != claim_id);
						}
					},
					OnchainEvent::ContentiousOutpoint { package } => {
						log_debug!(logger, "Removing claim tracking due to maturation of claim tx for outpoints:");
						log_debug!(logger, " {:?}", package.outpoints());
						self.claimable_outpoints.remove(package.outpoints()[0]);
					}
				}
			} else {
				self.onchain_events_awaiting_threshold_conf.push(entry);
			}
		}

		// Check if any pending claim request must be rescheduled
		for (claim_id, request) in self.pending_claim_requests.iter() {
			if cur_height >= request.timer() {
				bump_candidates.insert(*claim_id, request.clone());
			}
		}

		// Build, bump and rebroadcast tx accordingly
		if !bump_candidates.is_empty() {
			maybe_log_intro();
			log_trace!(logger, "Bumping {} candidates", bump_candidates.len());
		}

		for (claim_id, request) in bump_candidates.iter() {
			if let Some((new_timer, new_feerate, bump_claim)) = self.generate_claim(
				cur_height, &request, &FeerateStrategy::ForceBump, &*fee_estimator, &*logger,
			) {
				match bump_claim {
					OnchainClaim::Tx(bump_tx) => {
						if bump_tx.is_fully_signed() {
							log_info!(logger, "Broadcasting RBF-bumped onchain {}", log_tx!(bump_tx.0));
							broadcaster.broadcast_transactions(&[&bump_tx.0]);
						} else {
							log_info!(logger, "Waiting for signature of RBF-bumped unsigned onchain transaction {}",
								bump_tx.0.txid());
						}
					},
					OnchainClaim::Event(claim_event) => {
						log_info!(logger, "Yielding RBF-bumped onchain event to spend inputs {:?}", request.outpoints());
						#[cfg(debug_assertions)] {
							let num_existing = self.pending_claim_events.iter().
								filter(|entry| entry.0 == *claim_id).count();
							assert!(num_existing == 0 || num_existing == 1);
						}
						self.pending_claim_events.retain(|event| event.0 != *claim_id);
						self.pending_claim_events.push((*claim_id, claim_event));
					},
				}
				if let Some(request) = self.pending_claim_requests.get_mut(claim_id) {
					request.set_timer(new_timer);
					request.set_feerate(new_feerate);
				}
			}
		}
	}

	pub(super) fn transaction_unconfirmed<B: Deref, F: Deref, L: Logger>(
		&mut self,
		txid: &Txid,
		broadcaster: B,
		fee_estimator: &LowerBoundedFeeEstimator<F>,
		logger: &L,
	) where
		B::Target: BroadcasterInterface,
		F::Target: FeeEstimator,
	{
		let mut height = None;
		for entry in self.onchain_events_awaiting_threshold_conf.iter() {
			if entry.txid == *txid {
				height = Some(entry.height);
				break;
			}
		}

		if let Some(height) = height {
			self.block_disconnected(height, broadcaster, fee_estimator, logger);
		}
	}

	pub(super) fn block_disconnected<B: Deref, F: Deref, L: Logger>(&mut self, height: u32, broadcaster: B, fee_estimator: &LowerBoundedFeeEstimator<F>, logger: &L)
		where B::Target: BroadcasterInterface,
			F::Target: FeeEstimator,
	{
		let mut bump_candidates = new_hash_map();
		let onchain_events_awaiting_threshold_conf =
			self.onchain_events_awaiting_threshold_conf.drain(..).collect::<Vec<_>>();
		for entry in onchain_events_awaiting_threshold_conf {
			if entry.height >= height {
				//- our claim tx on a commitment tx output
				//- resurect outpoint back in its claimable set and regenerate tx
				match entry.event {
					OnchainEvent::ContentiousOutpoint { package } => {
						if let Some(pending_claim) = self.claimable_outpoints.get(package.outpoints()[0]) {
							if let Some(request) = self.pending_claim_requests.get_mut(&pending_claim.0) {
								request.merge_package(package);
								// Using a HashMap guarantee us than if we have multiple outpoints getting
								// resurrected only one bump claim tx is going to be broadcast
								bump_candidates.insert(pending_claim.clone(), request.clone());
							}
						}
					},
					_ => {},
				}
			} else {
				self.onchain_events_awaiting_threshold_conf.push(entry);
			}
		}
		for ((_claim_id, _), ref mut request) in bump_candidates.iter_mut() {
			// `height` is the height being disconnected, so our `current_height` is 1 lower.
			let current_height = height - 1;
			if let Some((new_timer, new_feerate, bump_claim)) = self.generate_claim(
				current_height, &request, &FeerateStrategy::ForceBump, fee_estimator, logger
			) {
				request.set_timer(new_timer);
				request.set_feerate(new_feerate);
				match bump_claim {
					OnchainClaim::Tx(bump_tx) => {
						if bump_tx.is_fully_signed() {
							log_info!(logger, "Broadcasting onchain {}", log_tx!(bump_tx.0));
							broadcaster.broadcast_transactions(&[&bump_tx.0]);
						} else {
							log_info!(logger, "Waiting for signature of unsigned onchain transaction {}", bump_tx.0.txid());
						}
					},
					OnchainClaim::Event(claim_event) => {
						log_info!(logger, "Yielding onchain event after reorg to spend inputs {:?}", request.outpoints());
						#[cfg(debug_assertions)] {
							let num_existing = self.pending_claim_events.iter()
								.filter(|entry| entry.0 == *_claim_id).count();
							assert!(num_existing == 0 || num_existing == 1);
						}
						self.pending_claim_events.retain(|event| event.0 != *_claim_id);
						self.pending_claim_events.push((*_claim_id, claim_event));
					},
				}
			}
		}
		for (ancestor_claim_txid, request) in bump_candidates.drain() {
			self.pending_claim_requests.insert(ancestor_claim_txid.0, request);
		}
		//TODO: if we implement cross-block aggregated claim transaction we need to refresh set of outpoints and regenerate tx but
		// right now if one of the outpoint get disconnected, just erase whole pending claim request.
		let mut remove_request = Vec::new();
		self.claimable_outpoints.retain(|_, ref v|
			if v.1 >= height {
			remove_request.push(v.0.clone());
			false
			} else { true });
		for req in remove_request {
			self.pending_claim_requests.remove(&req);
		}
	}

	pub(crate) fn is_output_spend_pending(&self, outpoint: &BitcoinOutPoint) -> bool {
		self.claimable_outpoints.get(outpoint).is_some()
	}

	pub(crate) fn get_relevant_txids(&self) -> Vec<(Txid, u32, Option<BlockHash>)> {
		let mut txids: Vec<(Txid, u32, Option<BlockHash>)> = self.onchain_events_awaiting_threshold_conf
			.iter()
			.map(|entry| (entry.txid, entry.height, entry.block_hash))
			.collect();
		txids.sort_unstable_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)));
		txids.dedup_by_key(|(txid, _, _)| *txid);
		txids
	}

	pub(crate) fn provide_latest_holder_tx(&mut self, tx: HolderCommitmentTransaction) {
		self.prev_holder_commitment = Some(replace(&mut self.holder_commitment, tx));
	}

	pub(crate) fn get_unsigned_holder_commitment_tx(&self) -> &Transaction {
		&self.holder_commitment.trust().built_transaction().transaction
	}

	pub(crate) fn get_maybe_signed_holder_tx(&mut self, funding_redeemscript: &Script) -> MaybeSignedTransaction {
		let tx = self.signer.sign_holder_commitment(&self.holder_commitment, &self.secp_ctx)
			.map(|sig| self.holder_commitment.add_holder_sig(funding_redeemscript, sig))
			.unwrap_or_else(|_| self.get_unsigned_holder_commitment_tx().clone());
		MaybeSignedTransaction(tx)
	}

	#[cfg(any(test, feature="unsafe_revoked_tx_signing"))]
	pub(crate) fn get_fully_signed_copy_holder_tx(&mut self, funding_redeemscript: &Script) -> Transaction {
		let sig = self.signer.unsafe_sign_holder_commitment(&self.holder_commitment, &self.secp_ctx).expect("sign holder commitment");
		self.holder_commitment.add_holder_sig(funding_redeemscript, sig)
	}

	pub(crate) fn get_maybe_signed_htlc_tx(&mut self, outp: &::bitcoin::OutPoint, preimage: &Option<PaymentPreimage>) -> Option<MaybeSignedTransaction> {
		let get_signed_htlc_tx = |holder_commitment: &HolderCommitmentTransaction| {
			let trusted_tx = holder_commitment.trust();
			if trusted_tx.txid() != outp.txid {
				return None;
			}
			let (htlc_idx, htlc) = trusted_tx.htlcs().iter().enumerate()
				.find(|(_, htlc)| htlc.transaction_output_index.unwrap() == outp.vout)
				.unwrap();
			let counterparty_htlc_sig = holder_commitment.counterparty_htlc_sigs[htlc_idx];
			let mut htlc_tx = trusted_tx.build_unsigned_htlc_tx(
				&self.channel_transaction_parameters.as_holder_broadcastable(), htlc_idx, preimage,
			);

			let htlc_descriptor = HTLCDescriptor {
				channel_derivation_parameters: ChannelDerivationParameters {
					value_satoshis: self.channel_value_satoshis,
					keys_id: self.channel_keys_id,
					transaction_parameters: self.channel_transaction_parameters.clone(),
				},
				commitment_txid: trusted_tx.txid(),
				per_commitment_number: trusted_tx.commitment_number(),
				per_commitment_point: trusted_tx.per_commitment_point(),
				feerate_per_kw: trusted_tx.feerate_per_kw(),
				htlc: htlc.clone(),
				preimage: preimage.clone(),
				counterparty_sig: counterparty_htlc_sig.clone(),
			};
			if let Ok(htlc_sig) = self.signer.sign_holder_htlc_transaction(&htlc_tx, 0, &htlc_descriptor, &self.secp_ctx) {
				htlc_tx.input[0].witness = trusted_tx.build_htlc_input_witness(
					htlc_idx, &counterparty_htlc_sig, &htlc_sig, preimage,
				);
			}
			Some(MaybeSignedTransaction(htlc_tx))
		};

		// Check if the HTLC spends from the current holder commitment first, or the previous.
		get_signed_htlc_tx(&self.holder_commitment)
			.or_else(|| self.prev_holder_commitment.as_ref().and_then(|prev_holder_commitment| get_signed_htlc_tx(prev_holder_commitment)))
	}

	pub(crate) fn generate_external_htlc_claim(
		&self, outp: &::bitcoin::OutPoint, preimage: &Option<PaymentPreimage>
	) -> Option<ExternalHTLCClaim> {
		let find_htlc = |holder_commitment: &HolderCommitmentTransaction| -> Option<ExternalHTLCClaim> {
			let trusted_tx = holder_commitment.trust();
			if outp.txid != trusted_tx.txid() {
				return None;
			}
			trusted_tx.htlcs().iter().enumerate()
				.find(|(_, htlc)| if let Some(output_index) = htlc.transaction_output_index {
					output_index == outp.vout
				} else {
					false
				})
				.map(|(htlc_idx, htlc)| {
					let counterparty_htlc_sig = holder_commitment.counterparty_htlc_sigs[htlc_idx];
					ExternalHTLCClaim {
						commitment_txid: trusted_tx.txid(),
						per_commitment_number: trusted_tx.commitment_number(),
						htlc: htlc.clone(),
						preimage: *preimage,
						counterparty_sig: counterparty_htlc_sig,
						per_commitment_point: trusted_tx.per_commitment_point(),
					}
				})
		};
		// Check if the HTLC spends from the current holder commitment or the previous one otherwise.
		find_htlc(&self.holder_commitment)
			.or_else(|| self.prev_holder_commitment.as_ref().map(|c| find_htlc(c)).flatten())
	}

	pub(crate) fn channel_type_features(&self) -> &ChannelTypeFeatures {
		&self.channel_transaction_parameters.channel_type_features
	}
}
