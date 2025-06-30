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

use bitcoin::amount::Amount;
use bitcoin::hash_types::{BlockHash, Txid};
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::{Hash, HashEngine};
use bitcoin::locktime::absolute::LockTime;
use bitcoin::script::{Script, ScriptBuf};
use bitcoin::secp256k1;
use bitcoin::secp256k1::{ecdsa::Signature, Secp256k1};
use bitcoin::transaction::OutPoint as BitcoinOutPoint;
use bitcoin::transaction::Transaction;

use crate::chain::chaininterface::{compute_feerate_sat_per_1000_weight, ConfirmationTarget};
use crate::chain::chaininterface::{BroadcasterInterface, FeeEstimator, LowerBoundedFeeEstimator};
use crate::chain::channelmonitor::ANTI_REORG_DELAY;
use crate::chain::package::{PackageSolvingData, PackageTemplate};
use crate::chain::transaction::MaybeSignedTransaction;
use crate::chain::ClaimId;
use crate::ln::chan_utils::{
	self, ChannelTransactionParameters, HTLCOutputInCommitment, HolderCommitmentTransaction,
};
use crate::ln::msgs::DecodeError;
use crate::sign::{ecdsa::EcdsaChannelSigner, EntropySource, HTLCDescriptor, SignerProvider};
use crate::util::logger::Logger;
use crate::util::ser::{
	MaybeReadable, Readable, ReadableArgs, UpgradableRequired, Writeable, Writer,
};

use crate::io;
use crate::prelude::*;
use alloc::collections::BTreeMap;
use core::cmp;
use core::mem::replace;
use core::mem::swap;
use core::ops::Deref;

const MAX_ALLOC_SIZE: usize = 64 * 1024;

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
	Claim { claim_id: ClaimId },
	/// The counterparty has claimed an outpoint from one of our pending requests through a
	/// different transaction than ours. If our transaction was attempting to claim multiple
	/// outputs, we need to drop the outpoint claimed by the counterparty and regenerate a new claim
	/// transaction for ourselves. We keep tracking, separately, the outpoint claimed by the
	/// counterparty up to [`ANTI_REORG_DELAY`] confirmations to ensure we attempt to re-claim it
	/// if the counterparty's claim is reorged from the chain.
	ContentiousOutpoint { package: PackageTemplate },
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
	#[rustfmt::skip]
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
	#[rustfmt::skip]
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

// Represents the different types of claims for which events are yielded externally to satisfy said
// claims.
#[derive(Clone, PartialEq, Eq)]
pub(crate) enum ClaimEvent {
	/// Event yielded to signal that the commitment transaction fee must be bumped to claim any
	/// encumbered funds and proceed to HTLC resolution, if any HTLCs exist.
	BumpCommitment {
		package_target_feerate_sat_per_1000_weight: u32,
		commitment_tx: Transaction,
		commitment_tx_fee_satoshis: u64,
		pending_nondust_htlcs: Vec<HTLCOutputInCommitment>,
		anchor_output_idx: u32,
		channel_parameters: ChannelTransactionParameters,
	},
	/// Event yielded to signal that the commitment transaction has confirmed and its HTLCs must be
	/// resolved by broadcasting a transaction with sufficient fee to claim them.
	BumpHTLC {
		target_feerate_sat_per_1000_weight: u32,
		htlcs: Vec<HTLCDescriptor>,
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
#[derive(Debug)]
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
	channel_value_satoshis: u64,   // Deprecated as of 0.2.
	channel_keys_id: [u8; 32],     // Deprecated as of 0.2.
	destination_script: ScriptBuf, // Deprecated as of 0.2.
	holder_commitment: HolderCommitmentTransaction,
	prev_holder_commitment: Option<HolderCommitmentTransaction>,

	pub(super) signer: ChannelSigner,
	channel_transaction_parameters: ChannelTransactionParameters, // Deprecated as of 0.2.

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
	#[cfg(any(test, feature = "_test_utils"))]
	pub(crate) pending_claim_requests: HashMap<ClaimId, PackageTemplate>,
	#[cfg(not(any(test, feature = "_test_utils")))]
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
	#[cfg(any(test, feature = "_test_utils"))]
	pub(crate) claimable_outpoints: HashMap<BitcoinOutPoint, (ClaimId, u32)>,
	#[cfg(not(any(test, feature = "_test_utils")))]
	claimable_outpoints: HashMap<BitcoinOutPoint, (ClaimId, u32)>,

	locktimed_packages: BTreeMap<u32, Vec<PackageTemplate>>,

	onchain_events_awaiting_threshold_conf: Vec<OnchainEventEntry>,

	pub(super) secp_ctx: Secp256k1<secp256k1::All>,
}

impl<ChannelSigner: EcdsaChannelSigner> PartialEq for OnchainTxHandler<ChannelSigner> {
	#[rustfmt::skip]
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
	#[rustfmt::skip]
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

impl<'a, 'b, ES: EntropySource, SP: SignerProvider> ReadableArgs<(&'a ES, &'b SP, u64, [u8; 32])>
	for OnchainTxHandler<SP::EcdsaSigner>
{
	#[rustfmt::skip]
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

		let channel_parameters = ReadableArgs::<Option<u64>>::read(reader, Some(channel_value_satoshis))?;

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

		let signer = signer_provider.derive_channel_signer(channel_keys_id);

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
		holder_commitment: HolderCommitmentTransaction, secp_ctx: Secp256k1<secp256k1::All>,
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

	pub(crate) fn prev_holder_commitment_tx(&self) -> Option<&HolderCommitmentTransaction> {
		self.prev_holder_commitment.as_ref()
	}

	pub(crate) fn current_holder_commitment_tx(&self) -> &HolderCommitmentTransaction {
		&self.holder_commitment
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
	#[rustfmt::skip]
	pub(super) fn rebroadcast_pending_claims<B: Deref, F: Deref, L: Logger>(
		&mut self, current_height: u32, feerate_strategy: FeerateStrategy, broadcaster: &B,
		conf_target: ConfirmationTarget, destination_script: &Script,
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
			self.generate_claim(
				current_height, &request, &feerate_strategy, conf_target, destination_script,
				fee_estimator, logger,
			)
				.map(|(_, new_feerate, claim)| {
					let mut feerate_was_bumped = false;
					if let Some(mut_request) = self.pending_claim_requests.get_mut(&claim_id) {
						feerate_was_bumped = new_feerate > request.previous_feerate();
						mut_request.set_feerate(new_feerate);
					}
					match claim {
						OnchainClaim::Tx(tx) => {
							if tx.is_fully_signed() {
								let log_start = if feerate_was_bumped { "Broadcasting RBF-bumped" } else { "Rebroadcasting" };
								log_info!(logger, "{} onchain {}", log_start, log_tx!(tx.0));
								broadcaster.broadcast_transactions(&[&tx.0]);
							} else {
								log_info!(logger, "Waiting for signature of unsigned onchain transaction {}", tx.0.compute_txid());
							}
						},
						OnchainClaim::Event(event) => {
							let log_start = if feerate_was_bumped { "Yielding fee-bumped" } else { "Replaying" };
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

	/// Returns true if we are currently tracking any pending claim requests that are not fully
	/// confirmed yet.
	pub(super) fn has_pending_claims(&self) -> bool {
		self.pending_claim_requests.len() != 0
	}

	/// Lightning security model (i.e being able to redeem/timeout HTLC or penalize counterparty
	/// onchain) lays on the assumption of claim transactions getting confirmed before timelock
	/// expiration (CSV or CLTV following cases). In case of high-fee spikes, claim tx may get stuck
	/// in the mempool, so you need to bump its feerate quickly using Replace-By-Fee or
	/// Child-Pay-For-Parent.
	///
	/// Panics if there are signing errors, because signing operations in reaction to on-chain
	/// events are not expected to fail, and if they do, we may lose funds.
	#[rustfmt::skip]
	fn generate_claim<F: Deref, L: Logger>(
		&mut self, cur_height: u32, cached_request: &PackageTemplate,
		feerate_strategy: &FeerateStrategy, conf_target: ConfirmationTarget,
		destination_script: &Script, fee_estimator: &LowerBoundedFeeEstimator<F>, logger: &L,
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
					fee_estimator, conf_target, feerate_strategy,
				);
				let htlcs = cached_request.construct_malleable_package_with_external_funding(self)?;
				return Some((
					new_timer,
					target_feerate_sat_per_1000_weight as u64,
					OnchainClaim::Event(ClaimEvent::BumpHTLC {
						target_feerate_sat_per_1000_weight,
						htlcs,
						tx_lock_time: LockTime::from_consensus(cached_request.package_locktime(cur_height)),
					}),
				));
			}

			let predicted_weight = cached_request.package_weight(destination_script);
			if let Some((output_value, new_feerate)) = cached_request.compute_package_output(
				predicted_weight, destination_script.minimal_non_dust().to_sat(),
				feerate_strategy, conf_target, fee_estimator, logger,
			) {
				assert!(new_feerate != 0);

				let transaction = cached_request.maybe_finalize_malleable_package(
					cur_height, self, Amount::from_sat(output_value), destination_script.into(), logger
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

			if !cached_request.requires_external_funding() {
				return cached_request.maybe_finalize_untractable_package(self, logger)
					.map(|tx| (new_timer, 0, OnchainClaim::Tx(tx)))
			}

			return inputs.find_map(|input| match input {
				// Commitment inputs with anchors support are the only untractable inputs supported
				// thus far that require external funding.
				PackageSolvingData::HolderFundingOutput(output) => {
					let maybe_signed_commitment_tx = output.get_maybe_signed_commitment_tx(self);
					let tx = if maybe_signed_commitment_tx.is_fully_signed() {
						maybe_signed_commitment_tx.0
					} else {
						// We couldn't sign the commitment as the signer was unavailable, but we
						// should still retry it later. We return the unsigned transaction anyway to
						// register the claim.
						return Some((new_timer, 0, OnchainClaim::Tx(maybe_signed_commitment_tx)));
					};

					let holder_commitment = output.commitment_tx.as_ref()
						.unwrap_or(self.current_holder_commitment_tx());

					let input_amount_sats = if let Some(funding_amount_sats) = output.funding_amount_sats {
						funding_amount_sats
					} else {
						debug_assert!(false, "Funding amount should always exist for anchor-based claims");
						self.channel_value_satoshis
					};

					let fee_sat = input_amount_sats - tx.output.iter()
						.map(|output| output.value.to_sat()).sum::<u64>();
					let commitment_tx_feerate_sat_per_1000_weight =
						compute_feerate_sat_per_1000_weight(fee_sat, tx.weight().to_wu());
					let package_target_feerate_sat_per_1000_weight = cached_request
						.compute_package_feerate(fee_estimator, conf_target, feerate_strategy);
					if commitment_tx_feerate_sat_per_1000_weight >= package_target_feerate_sat_per_1000_weight {
						log_debug!(logger, "Pre-signed commitment {} already has feerate {} sat/kW above required {} sat/kW",
							tx.compute_txid(), commitment_tx_feerate_sat_per_1000_weight,
							package_target_feerate_sat_per_1000_weight);
						// The commitment transaction already meets the required feerate and doesn't
						// need a CPFP. We still want to return something other than the event to
						// register the claim.
						return Some((new_timer, 0, OnchainClaim::Tx(MaybeSignedTransaction(tx))));
					}

					// We'll locate an anchor output we can spend within the commitment transaction.
					let channel_parameters = output.channel_parameters.as_ref()
						.unwrap_or(self.channel_parameters());
					let funding_pubkey = &channel_parameters.holder_pubkeys.funding_pubkey;
					match chan_utils::get_keyed_anchor_output(&tx, funding_pubkey) {
						// An anchor output was found, so we should yield a funding event externally.
						Some((idx, _)) => {
							// TODO: Use a lower confirmation target when both our and the
							// counterparty's latest commitment don't have any HTLCs present.
							Some((
								new_timer,
								package_target_feerate_sat_per_1000_weight as u64,
								OnchainClaim::Event(ClaimEvent::BumpCommitment {
									package_target_feerate_sat_per_1000_weight,
									commitment_tx: tx,
									pending_nondust_htlcs: holder_commitment.nondust_htlcs().to_vec(),
									commitment_tx_fee_satoshis: fee_sat,
									anchor_output_idx: idx,
									channel_parameters: channel_parameters.clone(),
								}),
							))
						},
						// An anchor output was not found. There's nothing we can do other than
						// attempt to broadcast the transaction with its current fee rate and hope
						// it confirms. This is essentially the same behavior as a commitment
						// transaction without anchor outputs.
						None => Some((new_timer, 0, OnchainClaim::Tx(MaybeSignedTransaction(tx)))),
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

	#[rustfmt::skip]
	pub fn abandon_claim(&mut self, outpoint: &BitcoinOutPoint) {
		let claim_id = self.claimable_outpoints.get(outpoint).map(|(claim_id, _)| *claim_id)
			.or_else(|| {
				self.pending_claim_requests.iter()
					.find(|(_, claim)| claim.outpoints().contains(&outpoint))
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
				claims.retain(|claim| !claim.outpoints().contains(&outpoint)));
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
	#[rustfmt::skip]
	pub(super) fn update_claims_view_from_requests<B: Deref, F: Deref, L: Logger>(
		&mut self, mut requests: Vec<PackageTemplate>, conf_height: u32, cur_height: u32,
		broadcaster: &B, conf_target: ConfirmationTarget, destination_script: &Script,
		fee_estimator: &LowerBoundedFeeEstimator<F>, logger: &L
	) where
		B::Target: BroadcasterInterface,
		F::Target: FeeEstimator,
	{
		if !requests.is_empty() {
			log_debug!(logger, "Updating claims view at height {} with {} claim requests", cur_height, requests.len());
		}

		// First drop any duplicate claims.
		requests.retain(|req| {
			debug_assert_eq!(
				req.outpoints().len(),
				1,
				"Claims passed to `update_claims_view_from_requests` should not be aggregated"
			);
			let mut all_outpoints_claiming = true;
			for outpoint in req.outpoints() {
				if self.claimable_outpoints.get(outpoint).is_none() {
					all_outpoints_claiming = false;
				}
			}
			if all_outpoints_claiming {
				log_info!(logger, "Ignoring second claim for outpoint {}:{}, already registered its claiming request",
					req.outpoints()[0].txid, req.outpoints()[0].vout);
				false
			} else {
				let timelocked_equivalent_package = self.locktimed_packages.iter().map(|v| v.1.iter()).flatten()
					.find(|locked_package| locked_package.outpoints() == req.outpoints());
				if let Some(package) = timelocked_equivalent_package {
					log_info!(logger, "Ignoring second claim for outpoint {}:{}, we already have one which we're waiting on a timelock at {} for.",
						req.outpoints()[0].txid, req.outpoints()[0].vout, package.package_locktime(cur_height));
					false
				} else {
					true
				}
			}
		});

		// Then try to maximally aggregate `requests`.
		for i in (1..requests.len()).rev() {
			for j in 0..i {
				if requests[i].can_merge_with(&requests[j], cur_height) {
					let merge = requests.remove(i);
					if let Err(rejected) = requests[j].merge_package(merge, cur_height) {
						debug_assert!(false, "Merging package should not be rejected after verifying can_merge_with.");
						requests.insert(i, rejected);
					} else {
						break;
					}
				}
			}
		}

		// Finally, split requests into timelocked ones and immediately-spendable ones.
		let mut preprocessed_requests = Vec::with_capacity(requests.len());
		for req in requests {
			let package_locktime = req.package_locktime(cur_height);
			if package_locktime > cur_height {
				log_info!(logger, "Delaying claim of package until its timelock at {} (current height {}), the following outpoints are spent:", package_locktime, cur_height);
				for outpoint in req.outpoints() {
					log_info!(logger, "  Outpoint {}", outpoint);
				}
				self.locktimed_packages.entry(package_locktime).or_default().push(req);
			} else {
				preprocessed_requests.push(req);
			}
		}

		// Claim everything up to and including `cur_height`.
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
				cur_height, &req, &FeerateStrategy::ForceBump, conf_target, destination_script,
				&*fee_estimator, &*logger,
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
							log_info!(logger, "Waiting for signature of unsigned onchain transaction {}", tx.0.compute_txid());
						}
						ClaimId(tx.0.compute_txid().to_byte_array())
					},
					OnchainClaim::Event(claim_event) => {
						log_info!(logger, "Yielding onchain event to spend inputs {:?}", req.outpoints());
						let claim_id = match claim_event {
							ClaimEvent::BumpCommitment { ref commitment_tx, .. } =>
								// For commitment claims, we can just use their txid as it should
								// already be unique.
								ClaimId(commitment_tx.compute_txid().to_byte_array()),
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
	#[rustfmt::skip]
	pub(super) fn update_claims_view_from_matched_txn<B: Deref, F: Deref, L: Logger>(
		&mut self, txn_matched: &[&Transaction], conf_height: u32, conf_hash: BlockHash,
		cur_height: u32, broadcaster: &B, conf_target: ConfirmationTarget,
		destination_script: &Script, fee_estimator: &LowerBoundedFeeEstimator<F>, logger: &L
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
						//... we need to check if the pending claim was for a subset of the outputs
						// spent by the confirmed transaction. If so, we can drop the pending claim
						// after ANTI_REORG_DELAY blocks, otherwise we need to split it and retry
						// claiming the remaining outputs.
						let mut is_claim_subset_of_tx = true;
						let mut tx_inputs = tx.input.iter().map(|input| &input.previous_output).collect::<Vec<_>>();
						tx_inputs.sort_unstable();
						for request_input in request.outpoints() {
							if tx_inputs.binary_search(&request_input).is_err() {
								is_claim_subset_of_tx = false;
								break;
							}
						}

						macro_rules! clean_claim_request_after_safety_delay {
							() => {
								let entry = OnchainEventEntry {
									txid: tx.compute_txid(),
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
						if is_claim_subset_of_tx {
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
					} else {
						panic!("Inconsistencies between pending_claim_requests map and claimable_outpoints map");
					}
				}

				// Also remove/split any locktimed packages whose inputs have been spent by this transaction.
				self.locktimed_packages.retain(|_locktime, packages|{
					packages.retain_mut(|package| {
						if let Some(p) = package.split_package(&inp.previous_output) {
							claimed_outputs_material.push(p);
						}
						!package.outpoints().is_empty()
					});
					!packages.is_empty()
				});
			}
			for package in claimed_outputs_material.drain(..) {
				let entry = OnchainEventEntry {
					txid: tx.compute_txid(),
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
				cur_height, &request, &FeerateStrategy::ForceBump, conf_target, destination_script,
				&*fee_estimator, &*logger,
			) {
				match bump_claim {
					OnchainClaim::Tx(bump_tx) => {
						if bump_tx.is_fully_signed() {
							log_info!(logger, "Broadcasting RBF-bumped onchain {}", log_tx!(bump_tx.0));
							broadcaster.broadcast_transactions(&[&bump_tx.0]);
						} else {
							log_info!(logger, "Waiting for signature of RBF-bumped unsigned onchain transaction {}",
								bump_tx.0.compute_txid());
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

	#[rustfmt::skip]
	pub(super) fn transaction_unconfirmed<B: Deref, F: Deref, L: Logger>(
		&mut self,
		txid: &Txid,
		broadcaster: B,
		conf_target: ConfirmationTarget,
		destination_script: &Script,
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
			self.block_disconnected(
				height, broadcaster, conf_target, destination_script, fee_estimator, logger,
			);
		}
	}

	#[rustfmt::skip]
	pub(super) fn block_disconnected<B: Deref, F: Deref, L: Logger>(
		&mut self, height: u32, broadcaster: B, conf_target: ConfirmationTarget,
		destination_script: &Script, fee_estimator: &LowerBoundedFeeEstimator<F>, logger: &L,
	)
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
						let package_locktime = package.package_locktime(height);
						if package_locktime > height {
							self.locktimed_packages.entry(package_locktime).or_default().push(package);
							continue;
						}

						if let Some(pending_claim) = self.claimable_outpoints.get(package.outpoints()[0]) {
							if let Some(request) = self.pending_claim_requests.get_mut(&pending_claim.0) {
								assert!(request.merge_package(package, height).is_ok());
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
				current_height, &request, &FeerateStrategy::ForceBump, conf_target,
				destination_script, fee_estimator, logger
			) {
				request.set_timer(new_timer);
				request.set_feerate(new_feerate);
				match bump_claim {
					OnchainClaim::Tx(bump_tx) => {
						if bump_tx.is_fully_signed() {
							log_info!(logger, "Broadcasting onchain {}", log_tx!(bump_tx.0));
							broadcaster.broadcast_transactions(&[&bump_tx.0]);
						} else {
							log_info!(logger, "Waiting for signature of unsigned onchain transaction {}", bump_tx.0.compute_txid());
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

	#[rustfmt::skip]
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

	// Deprecated as of 0.2, only use in cases where it was not previously available.
	pub(crate) fn channel_parameters(&self) -> &ChannelTransactionParameters {
		&self.channel_transaction_parameters
	}

	// Deprecated as of 0.2, only use in cases where it was not previously available.
	pub(crate) fn channel_keys_id(&self) -> [u8; 32] {
		self.channel_keys_id
	}
}

#[cfg(test)]
mod tests {
	use bitcoin::hash_types::Txid;
	use bitcoin::hashes::sha256::Hash as Sha256;
	use bitcoin::hashes::Hash;
	use bitcoin::Network;
	use bitcoin::{key::Secp256k1, secp256k1::PublicKey, secp256k1::SecretKey, ScriptBuf};
	use types::features::ChannelTypeFeatures;

	use crate::chain::chaininterface::{ConfirmationTarget, LowerBoundedFeeEstimator};
	use crate::chain::package::{HolderHTLCOutput, PackageSolvingData, PackageTemplate};
	use crate::chain::transaction::OutPoint;
	use crate::ln::chan_utils::{
		ChannelPublicKeys, ChannelTransactionParameters, CounterpartyChannelTransactionParameters,
		HTLCOutputInCommitment, HolderCommitmentTransaction,
	};
	use crate::ln::channel_keys::{DelayedPaymentBasepoint, HtlcBasepoint, RevocationBasepoint};
	use crate::ln::functional_test_utils::create_dummy_block;
	use crate::sign::{ChannelDerivationParameters, HTLCDescriptor, InMemorySigner};
	use crate::types::payment::{PaymentHash, PaymentPreimage};
	use crate::util::test_utils::{TestBroadcaster, TestFeeEstimator, TestLogger};

	use super::OnchainTxHandler;

	// Test that all claims with locktime equal to or less than the current height are broadcast
	// immediately while claims with locktime greater than the current height are only broadcast
	// once the locktime is reached.
	#[test]
	#[rustfmt::skip]
	fn test_broadcast_height() {
		let secp_ctx = Secp256k1::new();
		let signer = InMemorySigner::new(
			&secp_ctx,
			SecretKey::from_slice(&[41; 32]).unwrap(),
			SecretKey::from_slice(&[41; 32]).unwrap(),
			SecretKey::from_slice(&[41; 32]).unwrap(),
			SecretKey::from_slice(&[41; 32]).unwrap(),
			SecretKey::from_slice(&[41; 32]).unwrap(),
			[41; 32],
			[0; 32],
			[0; 32],
		);
		let counterparty_pubkeys = ChannelPublicKeys {
			funding_pubkey: PublicKey::from_secret_key(
				&secp_ctx,
				&SecretKey::from_slice(&[44; 32]).unwrap(),
			),
			revocation_basepoint: RevocationBasepoint::from(PublicKey::from_secret_key(
				&secp_ctx,
				&SecretKey::from_slice(&[45; 32]).unwrap(),
			)),
			payment_point: PublicKey::from_secret_key(
				&secp_ctx,
				&SecretKey::from_slice(&[46; 32]).unwrap(),
			),
			delayed_payment_basepoint: DelayedPaymentBasepoint::from(PublicKey::from_secret_key(
				&secp_ctx,
				&SecretKey::from_slice(&[47; 32]).unwrap(),
			)),
			htlc_basepoint: HtlcBasepoint::from(PublicKey::from_secret_key(
				&secp_ctx,
				&SecretKey::from_slice(&[48; 32]).unwrap(),
			)),
		};
		let funding_outpoint = OutPoint { txid: Txid::all_zeros(), index: u16::MAX };

		// Use non-anchor channels so that HTLC-Timeouts are broadcast immediately instead of sent
		// to the user for external funding.
		let chan_params = ChannelTransactionParameters {
			holder_pubkeys: signer.holder_channel_pubkeys.clone(),
			holder_selected_contest_delay: 66,
			is_outbound_from_holder: true,
			counterparty_parameters: Some(CounterpartyChannelTransactionParameters {
				pubkeys: counterparty_pubkeys,
				selected_contest_delay: 67,
			}),
			funding_outpoint: Some(funding_outpoint),
			splice_parent_funding_txid: None,
			channel_type_features: ChannelTypeFeatures::only_static_remote_key(),
			channel_value_satoshis: 0,
		};

		// Create an OnchainTxHandler for a commitment containing HTLCs with CLTV expiries of 0, 1,
		// and 2 blocks.
		let mut nondust_htlcs = Vec::new();
		for i in 0..3 {
			let preimage = PaymentPreimage([i; 32]);
			let hash = PaymentHash(Sha256::hash(&preimage.0[..]).to_byte_array());
			nondust_htlcs.push(
				HTLCOutputInCommitment {
					offered: true,
					amount_msat: 10000,
					cltv_expiry: i as u32,
					payment_hash: hash,
					transaction_output_index: Some(i as u32),
				}
			);
		}
		let holder_commit = HolderCommitmentTransaction::dummy(1000000, nondust_htlcs);
		let destination_script = ScriptBuf::new();
		let mut tx_handler = OnchainTxHandler::new(
			1000000,
			[0; 32],
			destination_script.clone(),
			signer,
			chan_params,
			holder_commit,
			secp_ctx,
		);

		// Create a broadcaster with current block height 1.
		let broadcaster = TestBroadcaster::new(Network::Testnet);
		{
			let mut blocks = broadcaster.blocks.lock().unwrap();
			let genesis_hash = blocks[0].0.block_hash();
			blocks.push((create_dummy_block(genesis_hash, 0, Vec::new()), 1));
		}

		let fee_estimator = TestFeeEstimator::new(253);
		let fee_estimator = LowerBoundedFeeEstimator::new(&fee_estimator);
		let logger = TestLogger::new();

		// Request claiming of each HTLC on the holder's commitment, with current block height 1.
		let holder_commit = tx_handler.current_holder_commitment_tx();
		let holder_commit_txid = holder_commit.trust().txid();
		let mut requests = Vec::new();
		for (htlc, counterparty_sig) in holder_commit.nondust_htlcs().iter().zip(holder_commit.counterparty_htlc_sigs.iter()) {
			requests.push(PackageTemplate::build_package(
				holder_commit_txid,
				htlc.transaction_output_index.unwrap(),
				PackageSolvingData::HolderHTLCOutput(HolderHTLCOutput::build(HTLCDescriptor {
					channel_derivation_parameters: ChannelDerivationParameters {
						value_satoshis: tx_handler.channel_value_satoshis,
						keys_id: tx_handler.channel_keys_id,
						transaction_parameters: tx_handler.channel_transaction_parameters.clone(),
					},
					commitment_txid: holder_commit_txid,
					per_commitment_number: holder_commit.commitment_number(),
					per_commitment_point: holder_commit.per_commitment_point(),
					feerate_per_kw: holder_commit.feerate_per_kw(),
					htlc: htlc.clone(),
					preimage: None,
					counterparty_sig: *counterparty_sig,
				})),
				0,
			));
		}
		tx_handler.update_claims_view_from_requests(
			requests,
			1,
			1,
			&&broadcaster,
			ConfirmationTarget::UrgentOnChainSweep,
			&destination_script,
			&fee_estimator,
			&logger,
		);

		// HTLC-Timeouts should be broadcast for the HTLCs with expiries at heights 0 and 1. The
		// HTLC with expiry at height 2 should not be claimed yet.
		let txs_broadcasted = broadcaster.txn_broadcast();
		assert_eq!(txs_broadcasted.len(), 2);
		assert!(txs_broadcasted[0].lock_time.to_consensus_u32() <= 1);
		assert!(txs_broadcasted[1].lock_time.to_consensus_u32() <= 1);

		// Advance to block height 2, and reprocess pending claims.
		{
			let mut blocks = broadcaster.blocks.lock().unwrap();
			let block1_hash = blocks[1].0.block_hash();
			blocks.push((create_dummy_block(block1_hash, 0, Vec::new()), 2));
		}
		tx_handler.update_claims_view_from_requests(
			Vec::new(),
			2,
			2,
			&&broadcaster,
			ConfirmationTarget::UrgentOnChainSweep,
			&destination_script,
			&fee_estimator,
			&logger,
		);

		// The final HTLC-Timeout should now be broadcast.
		let txs_broadcasted = broadcaster.txn_broadcast();
		assert_eq!(txs_broadcasted.len(), 1);
		assert_eq!(txs_broadcasted[0].lock_time.to_consensus_u32(), 2);
	}
}
