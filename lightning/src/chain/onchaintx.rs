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

use bitcoin::blockdata::transaction::Transaction;
use bitcoin::blockdata::transaction::OutPoint as BitcoinOutPoint;
use bitcoin::blockdata::script::Script;

use bitcoin::hash_types::Txid;

use bitcoin::secp256k1::{Secp256k1, Signature};
use bitcoin::secp256k1;

use ln::msgs::DecodeError;
use ln::PaymentPreimage;
use ln::chan_utils::{ChannelTransactionParameters, HolderCommitmentTransaction};
use chain::chaininterface::{FeeEstimator, BroadcasterInterface};
use chain::channelmonitor::{ANTI_REORG_DELAY, CLTV_SHARED_CLAIM_BUFFER};
use chain::keysinterface::{Sign, KeysInterface};
use chain::package::PackageTemplate;
use util::logger::Logger;
use util::ser::{Readable, ReadableArgs, Writer, Writeable, VecWriter};
use util::byte_utils;

use io;
use prelude::*;
use alloc::collections::BTreeMap;
use core::cmp;
use core::ops::Deref;
use core::mem::replace;

const MAX_ALLOC_SIZE: usize = 64*1024;

/// An entry for an [`OnchainEvent`], stating the block height when the event was observed and the
/// transaction causing it.
///
/// Used to determine when the on-chain event can be considered safe from a chain reorganization.
#[derive(PartialEq)]
struct OnchainEventEntry {
	txid: Txid,
	height: u32,
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

/// Upon discovering of some classes of onchain tx by ChannelMonitor, we may have to take actions on it
/// once they mature to enough confirmations (ANTI_REORG_DELAY)
#[derive(PartialEq)]
enum OnchainEvent {
	/// Outpoint under claim process by our own tx, once this one get enough confirmations, we remove it from
	/// bump-txn candidate buffer.
	Claim {
		claim_request: Txid,
	},
	/// Claim tx aggregate multiple claimable outpoints. One of the outpoint may be claimed by a counterparty party tx.
	/// In this case, we need to drop the outpoint and regenerate a new claim tx. By safety, we keep tracking
	/// the outpoint to be sure to resurect it back to the claim tx if reorgs happen.
	ContentiousOutpoint {
		package: PackageTemplate,
	}
}

impl_writeable_tlv_based!(OnchainEventEntry, {
	(0, txid, required),
	(2, height, required),
	(4, event, required),
});

impl_writeable_tlv_based_enum!(OnchainEvent,
	(0, Claim) => {
		(0, claim_request, required),
	},
	(1, ContentiousOutpoint) => {
		(0, package, required),
	},
;);

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


/// OnchainTxHandler receives claiming requests, aggregates them if it's sound, broadcast and
/// do RBF bumping if possible.
pub struct OnchainTxHandler<ChannelSigner: Sign> {
	destination_script: Script,
	holder_commitment: HolderCommitmentTransaction,
	// holder_htlc_sigs and prev_holder_htlc_sigs are in the order as they appear in the commitment
	// transaction outputs (hence the Option<>s inside the Vec). The first usize is the index in
	// the set of HTLCs in the HolderCommitmentTransaction.
	holder_htlc_sigs: Option<Vec<Option<(usize, Signature)>>>,
	prev_holder_commitment: Option<HolderCommitmentTransaction>,
	prev_holder_htlc_sigs: Option<Vec<Option<(usize, Signature)>>>,

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
	pub(crate) pending_claim_requests: HashMap<Txid, PackageTemplate>,
	#[cfg(not(test))]
	pending_claim_requests: HashMap<Txid, PackageTemplate>,

	// Used to link outpoints claimed in a connected block to a pending claim request.
	// Key is outpoint than monitor parsing has detected we have keys/scripts to claim
	// Value is (pending claim request identifier, confirmation_block), identifier
	// is txid of the initial claiming transaction and is immutable until outpoint is
	// post-anti-reorg-delay solved, confirmaiton_block is used to erase entry if
	// block with output gets disconnected.
	#[cfg(test)] // Used in functional_test to verify sanitization
	pub claimable_outpoints: HashMap<BitcoinOutPoint, (Txid, u32)>,
	#[cfg(not(test))]
	claimable_outpoints: HashMap<BitcoinOutPoint, (Txid, u32)>,

	locktimed_packages: BTreeMap<u32, Vec<PackageTemplate>>,

	onchain_events_awaiting_threshold_conf: Vec<OnchainEventEntry>,

	pub(super) secp_ctx: Secp256k1<secp256k1::All>,
}

const SERIALIZATION_VERSION: u8 = 1;
const MIN_SERIALIZATION_VERSION: u8 = 1;

impl<ChannelSigner: Sign> OnchainTxHandler<ChannelSigner> {
	pub(crate) fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		write_ver_prefix!(writer, SERIALIZATION_VERSION, MIN_SERIALIZATION_VERSION);

		self.destination_script.write(writer)?;
		self.holder_commitment.write(writer)?;
		self.holder_htlc_sigs.write(writer)?;
		self.prev_holder_commitment.write(writer)?;
		self.prev_holder_htlc_sigs.write(writer)?;

		self.channel_transaction_parameters.write(writer)?;

		let mut key_data = VecWriter(Vec::new());
		self.signer.write(&mut key_data)?;
		assert!(key_data.0.len() < core::usize::MAX);
		assert!(key_data.0.len() < core::u32::MAX as usize);
		(key_data.0.len() as u32).write(writer)?;
		writer.write_all(&key_data.0[..])?;

		writer.write_all(&byte_utils::be64_to_array(self.pending_claim_requests.len() as u64))?;
		for (ref ancestor_claim_txid, request) in self.pending_claim_requests.iter() {
			ancestor_claim_txid.write(writer)?;
			request.write(writer)?;
		}

		writer.write_all(&byte_utils::be64_to_array(self.claimable_outpoints.len() as u64))?;
		for (ref outp, ref claim_and_height) in self.claimable_outpoints.iter() {
			outp.write(writer)?;
			claim_and_height.0.write(writer)?;
			claim_and_height.1.write(writer)?;
		}

		writer.write_all(&byte_utils::be64_to_array(self.locktimed_packages.len() as u64))?;
		for (ref locktime, ref packages) in self.locktimed_packages.iter() {
			locktime.write(writer)?;
			writer.write_all(&byte_utils::be64_to_array(packages.len() as u64))?;
			for ref package in packages.iter() {
				package.write(writer)?;
			}
		}

		writer.write_all(&byte_utils::be64_to_array(self.onchain_events_awaiting_threshold_conf.len() as u64))?;
		for ref entry in self.onchain_events_awaiting_threshold_conf.iter() {
			entry.write(writer)?;
		}

		write_tlv_fields!(writer, {});
		Ok(())
	}
}

impl<'a, K: KeysInterface> ReadableArgs<&'a K> for OnchainTxHandler<K::Signer> {
	fn read<R: io::Read>(reader: &mut R, keys_manager: &'a K) -> Result<Self, DecodeError> {
		let _ver = read_ver_prefix!(reader, SERIALIZATION_VERSION);

		let destination_script = Readable::read(reader)?;

		let holder_commitment = Readable::read(reader)?;
		let holder_htlc_sigs = Readable::read(reader)?;
		let prev_holder_commitment = Readable::read(reader)?;
		let prev_holder_htlc_sigs = Readable::read(reader)?;

		let channel_parameters = Readable::read(reader)?;

		let keys_len: u32 = Readable::read(reader)?;
		let mut keys_data = Vec::with_capacity(cmp::min(keys_len as usize, MAX_ALLOC_SIZE));
		while keys_data.len() != keys_len as usize {
			// Read 1KB at a time to avoid accidentally allocating 4GB on corrupted channel keys
			let mut data = [0; 1024];
			let read_slice = &mut data[0..cmp::min(1024, keys_len as usize - keys_data.len())];
			reader.read_exact(read_slice)?;
			keys_data.extend_from_slice(read_slice);
		}
		let signer = keys_manager.read_chan_signer(&keys_data)?;

		let pending_claim_requests_len: u64 = Readable::read(reader)?;
		let mut pending_claim_requests = HashMap::with_capacity(cmp::min(pending_claim_requests_len as usize, MAX_ALLOC_SIZE / 128));
		for _ in 0..pending_claim_requests_len {
			pending_claim_requests.insert(Readable::read(reader)?, Readable::read(reader)?);
		}

		let claimable_outpoints_len: u64 = Readable::read(reader)?;
		let mut claimable_outpoints = HashMap::with_capacity(cmp::min(pending_claim_requests_len as usize, MAX_ALLOC_SIZE / 128));
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
			onchain_events_awaiting_threshold_conf.push(Readable::read(reader)?);
		}

		read_tlv_fields!(reader, {});

		let mut secp_ctx = Secp256k1::new();
		secp_ctx.seeded_randomize(&keys_manager.get_secure_random_bytes());

		Ok(OnchainTxHandler {
			destination_script,
			holder_commitment,
			holder_htlc_sigs,
			prev_holder_commitment,
			prev_holder_htlc_sigs,
			signer,
			channel_transaction_parameters: channel_parameters,
			claimable_outpoints,
			locktimed_packages,
			pending_claim_requests,
			onchain_events_awaiting_threshold_conf,
			secp_ctx,
		})
	}
}

impl<ChannelSigner: Sign> OnchainTxHandler<ChannelSigner> {
	pub(crate) fn new(destination_script: Script, signer: ChannelSigner, channel_parameters: ChannelTransactionParameters, holder_commitment: HolderCommitmentTransaction, secp_ctx: Secp256k1<secp256k1::All>) -> Self {
		OnchainTxHandler {
			destination_script,
			holder_commitment,
			holder_htlc_sigs: None,
			prev_holder_commitment: None,
			prev_holder_htlc_sigs: None,
			signer,
			channel_transaction_parameters: channel_parameters,
			pending_claim_requests: HashMap::new(),
			claimable_outpoints: HashMap::new(),
			locktimed_packages: BTreeMap::new(),
			onchain_events_awaiting_threshold_conf: Vec::new(),

			secp_ctx,
		}
	}

	/// Lightning security model (i.e being able to redeem/timeout HTLC or penalize coutnerparty onchain) lays on the assumption of claim transactions getting confirmed before timelock expiration
	/// (CSV or CLTV following cases). In case of high-fee spikes, claim tx may stuck in the mempool, so you need to bump its feerate quickly using Replace-By-Fee or Child-Pay-For-Parent.
	/// Panics if there are signing errors, because signing operations in reaction to on-chain events
	/// are not expected to fail, and if they do, we may lose funds.
	fn generate_claim_tx<F: Deref, L: Deref>(&mut self, cur_height: u32, cached_request: &PackageTemplate, fee_estimator: &F, logger: &L) -> Option<(Option<u32>, u64, Transaction)>
		where F::Target: FeeEstimator,
					L::Target: Logger,
	{
		if cached_request.outpoints().len() == 0 { return None } // But don't prune pending claiming request yet, we may have to resurrect HTLCs

		// Compute new height timer to decide when we need to regenerate a new bumped version of the claim tx (if we
		// didn't receive confirmation of it before, or not enough reorg-safe depth on top of it).
		let new_timer = Some(cached_request.get_height_timer(cur_height));
		if cached_request.is_malleable() {
			let predicted_weight = cached_request.package_weight(&self.destination_script);
			if let Some((output_value, new_feerate)) = cached_request.compute_package_output(predicted_weight, fee_estimator, logger) {
				assert!(new_feerate != 0);

				let transaction = cached_request.finalize_package(self, output_value, self.destination_script.clone(), logger).unwrap();
				log_trace!(logger, "...with timer {} and feerate {}", new_timer.unwrap(), new_feerate);
				assert!(predicted_weight >= transaction.get_weight());
				return Some((new_timer, new_feerate, transaction))
			}
		} else {
			// Note: Currently, amounts of holder outputs spending witnesses aren't used
			// as we can't malleate spending package to increase their feerate. This
			// should change with the remaining anchor output patchset.
			if let Some(transaction) = cached_request.finalize_package(self, 0, self.destination_script.clone(), logger) {
				return Some((None, 0, transaction));
			}
		}
		None
	}

	/// Upon channelmonitor.block_connected(..) or upon provision of a preimage on the forward link
	/// for this channel, provide new relevant on-chain transactions and/or new claim requests.
	/// Formerly this was named `block_connected`, but it is now also used for claiming an HTLC output
	/// if we receive a preimage after force-close.
	/// `conf_height` represents the height at which the transactions in `txn_matched` were
	/// confirmed. This does not need to equal the current blockchain tip height, which should be
	/// provided via `cur_height`, however it must never be higher than `cur_height`.
	pub(crate) fn update_claims_view<B: Deref, F: Deref, L: Deref>(&mut self, txn_matched: &[&Transaction], requests: Vec<PackageTemplate>, conf_height: u32, cur_height: u32, broadcaster: &B, fee_estimator: &F, logger: &L)
		where B::Target: BroadcasterInterface,
		      F::Target: FeeEstimator,
					L::Target: Logger,
	{
		log_debug!(logger, "Updating claims view at height {} with {} matched transactions in block {} and {} claim requests", cur_height, txn_matched.len(), conf_height, requests.len());
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
						req.outpoints()[0].txid, req.outpoints()[0].vout, package.package_timelock());
					continue;
				}

				if req.package_timelock() > cur_height + 1 {
					log_info!(logger, "Delaying claim of package until its timelock at {} (current height {}), the following outpoints are spent:", req.package_timelock(), cur_height);
					for outpoint in req.outpoints() {
						log_info!(logger, "  Outpoint {}", outpoint);
					}
					self.locktimed_packages.entry(req.package_timelock()).or_insert(Vec::new()).push(req);
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

		// Claim everything up to and including cur_height + 1
		let remaining_locked_packages = self.locktimed_packages.split_off(&(cur_height + 2));
		for (pop_height, mut entry) in self.locktimed_packages.iter_mut() {
			log_trace!(logger, "Restoring delayed claim of package(s) at their timelock at {}.", pop_height);
			preprocessed_requests.append(&mut entry);
		}
		self.locktimed_packages = remaining_locked_packages;

		// Generate claim transactions and track them to bump if necessary at
		// height timer expiration (i.e in how many blocks we're going to take action).
		for mut req in preprocessed_requests {
			if let Some((new_timer, new_feerate, tx)) = self.generate_claim_tx(cur_height, &req, &*fee_estimator, &*logger) {
				req.set_timer(new_timer);
				req.set_feerate(new_feerate);
				let txid = tx.txid();
				for k in req.outpoints() {
					log_info!(logger, "Registering claiming request for {}:{}", k.txid, k.vout);
					self.claimable_outpoints.insert(k.clone(), (txid, conf_height));
				}
				self.pending_claim_requests.insert(txid, req);
				log_info!(logger, "Broadcasting onchain {}", log_tx!(tx));
				broadcaster.broadcast_transaction(&tx);
			}
		}

		let mut bump_candidates = HashMap::new();
		for tx in txn_matched {
			// Scan all input to verify is one of the outpoint spent is of interest for us
			let mut claimed_outputs_material = Vec::new();
			for inp in &tx.input {
				if let Some(first_claim_txid_height) = self.claimable_outpoints.get(&inp.previous_output) {
					// If outpoint has claim request pending on it...
					if let Some(request) = self.pending_claim_requests.get_mut(&first_claim_txid_height.0) {
						//... we need to verify equality between transaction outpoints and claim request
						// outpoints to know if transaction is the original claim or a bumped one issued
						// by us.
						let mut set_equality = true;
						if request.outpoints().len() != tx.input.len() {
							set_equality = false;
						} else {
							for (claim_inp, tx_inp) in request.outpoints().iter().zip(tx.input.iter()) {
								if **claim_inp != tx_inp.previous_output {
									set_equality = false;
								}
							}
						}

						macro_rules! clean_claim_request_after_safety_delay {
							() => {
								let entry = OnchainEventEntry {
									txid: tx.txid(),
									height: conf_height,
									event: OnchainEvent::Claim { claim_request: first_claim_txid_height.0.clone() }
								};
								if !self.onchain_events_awaiting_threshold_conf.contains(&entry) {
									self.onchain_events_awaiting_threshold_conf.push(entry);
								}
							}
						}

						// If this is our transaction (or our counterparty spent all the outputs
						// before we could anyway with same inputs order than us), wait for
						// ANTI_REORG_DELAY and clean the RBF tracking map.
						if set_equality {
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
								bump_candidates.insert(first_claim_txid_height.0.clone(), request.clone());
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
				match entry.event {
					OnchainEvent::Claim { claim_request } => {
						// We may remove a whole set of claim outpoints here, as these one may have
						// been aggregated in a single tx and claimed so atomically
						if let Some(request) = self.pending_claim_requests.remove(&claim_request) {
							for outpoint in request.outpoints() {
								log_debug!(logger, "Removing claim tracking for {} due to maturation of claim tx {}.", outpoint, claim_request);
								self.claimable_outpoints.remove(&outpoint);
							}
						}
					},
					OnchainEvent::ContentiousOutpoint { package } => {
						log_debug!(logger, "Removing claim tracking due to maturation of claim tx for outpoints:");
						log_debug!(logger, " {:?}", package.outpoints());
						self.claimable_outpoints.remove(&package.outpoints()[0]);
					}
				}
			} else {
				self.onchain_events_awaiting_threshold_conf.push(entry);
			}
		}

		// Check if any pending claim request must be rescheduled
		for (first_claim_txid, ref request) in self.pending_claim_requests.iter() {
			if let Some(h) = request.timer() {
				if cur_height >= h {
					bump_candidates.insert(*first_claim_txid, (*request).clone());
				}
			}
		}

		// Build, bump and rebroadcast tx accordingly
		log_trace!(logger, "Bumping {} candidates", bump_candidates.len());
		for (first_claim_txid, request) in bump_candidates.iter() {
			if let Some((new_timer, new_feerate, bump_tx)) = self.generate_claim_tx(cur_height, &request, &*fee_estimator, &*logger) {
				log_info!(logger, "Broadcasting RBF-bumped onchain {}", log_tx!(bump_tx));
				broadcaster.broadcast_transaction(&bump_tx);
				if let Some(request) = self.pending_claim_requests.get_mut(first_claim_txid) {
					request.set_timer(new_timer);
					request.set_feerate(new_feerate);
				}
			}
		}
	}

	pub(crate) fn transaction_unconfirmed<B: Deref, F: Deref, L: Deref>(
		&mut self,
		txid: &Txid,
		broadcaster: B,
		fee_estimator: F,
		logger: L,
	) where
		B::Target: BroadcasterInterface,
		F::Target: FeeEstimator,
		L::Target: Logger,
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

	pub(crate) fn block_disconnected<B: Deref, F: Deref, L: Deref>(&mut self, height: u32, broadcaster: B, fee_estimator: F, logger: L)
		where B::Target: BroadcasterInterface,
		      F::Target: FeeEstimator,
					L::Target: Logger,
	{
		let mut bump_candidates = HashMap::new();
		let onchain_events_awaiting_threshold_conf =
			self.onchain_events_awaiting_threshold_conf.drain(..).collect::<Vec<_>>();
		for entry in onchain_events_awaiting_threshold_conf {
			if entry.height >= height {
				//- our claim tx on a commitment tx output
				//- resurect outpoint back in its claimable set and regenerate tx
				match entry.event {
					OnchainEvent::ContentiousOutpoint { package } => {
						if let Some(ancestor_claimable_txid) = self.claimable_outpoints.get(&package.outpoints()[0]) {
							if let Some(request) = self.pending_claim_requests.get_mut(&ancestor_claimable_txid.0) {
								request.merge_package(package);
								// Using a HashMap guarantee us than if we have multiple outpoints getting
								// resurrected only one bump claim tx is going to be broadcast
								bump_candidates.insert(ancestor_claimable_txid.clone(), request.clone());
							}
						}
					},
					_ => {},
				}
			} else {
				self.onchain_events_awaiting_threshold_conf.push(entry);
			}
		}
		for (_, request) in bump_candidates.iter_mut() {
			if let Some((new_timer, new_feerate, bump_tx)) = self.generate_claim_tx(height, &request, &&*fee_estimator, &&*logger) {
				request.set_timer(new_timer);
				request.set_feerate(new_feerate);
				log_info!(logger, "Broadcasting onchain {}", log_tx!(bump_tx));
				broadcaster.broadcast_transaction(&bump_tx);
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

	pub(crate) fn get_relevant_txids(&self) -> Vec<Txid> {
		let mut txids: Vec<Txid> = self.onchain_events_awaiting_threshold_conf
			.iter()
			.map(|entry| entry.txid)
			.collect();
		txids.sort_unstable();
		txids.dedup();
		txids
	}

	pub(crate) fn provide_latest_holder_tx(&mut self, tx: HolderCommitmentTransaction) {
		self.prev_holder_commitment = Some(replace(&mut self.holder_commitment, tx));
		self.holder_htlc_sigs = None;
	}

	// Normally holder HTLCs are signed at the same time as the holder commitment tx.  However,
	// in some configurations, the holder commitment tx has been signed and broadcast by a
	// ChannelMonitor replica, so we handle that case here.
	fn sign_latest_holder_htlcs(&mut self) {
		if self.holder_htlc_sigs.is_none() {
			let (_sig, sigs) = self.signer.sign_holder_commitment_and_htlcs(&self.holder_commitment, &self.secp_ctx).expect("sign holder commitment");
			self.holder_htlc_sigs = Some(Self::extract_holder_sigs(&self.holder_commitment, sigs));
		}
	}

	// Normally only the latest commitment tx and HTLCs need to be signed.  However, in some
	// configurations we may have updated our holder commitment but a replica of the ChannelMonitor
	// broadcast the previous one before we sync with it.  We handle that case here.
	fn sign_prev_holder_htlcs(&mut self) {
		if self.prev_holder_htlc_sigs.is_none() {
			if let Some(ref holder_commitment) = self.prev_holder_commitment {
				let (_sig, sigs) = self.signer.sign_holder_commitment_and_htlcs(holder_commitment, &self.secp_ctx).expect("sign previous holder commitment");
				self.prev_holder_htlc_sigs = Some(Self::extract_holder_sigs(holder_commitment, sigs));
			}
		}
	}

	fn extract_holder_sigs(holder_commitment: &HolderCommitmentTransaction, sigs: Vec<Signature>) -> Vec<Option<(usize, Signature)>> {
		let mut ret = Vec::new();
		for (htlc_idx, (holder_sig, htlc)) in sigs.iter().zip(holder_commitment.htlcs().iter()).enumerate() {
			let tx_idx = htlc.transaction_output_index.unwrap();
			if ret.len() <= tx_idx as usize { ret.resize(tx_idx as usize + 1, None); }
			ret[tx_idx as usize] = Some((htlc_idx, holder_sig.clone()));
		}
		ret
	}

	//TODO: getting lastest holder transactions should be infallible and result in us "force-closing the channel", but we may
	// have empty holder commitment transaction if a ChannelMonitor is asked to force-close just after Channel::get_outbound_funding_created,
	// before providing a initial commitment transaction. For outbound channel, init ChannelMonitor at Channel::funding_signed, there is nothing
	// to monitor before.
	pub(crate) fn get_fully_signed_holder_tx(&mut self, funding_redeemscript: &Script) -> Transaction {
		let (sig, htlc_sigs) = self.signer.sign_holder_commitment_and_htlcs(&self.holder_commitment, &self.secp_ctx).expect("signing holder commitment");
		self.holder_htlc_sigs = Some(Self::extract_holder_sigs(&self.holder_commitment, htlc_sigs));
		self.holder_commitment.add_holder_sig(funding_redeemscript, sig)
	}

	#[cfg(any(test, feature="unsafe_revoked_tx_signing"))]
	pub(crate) fn get_fully_signed_copy_holder_tx(&mut self, funding_redeemscript: &Script) -> Transaction {
		let (sig, htlc_sigs) = self.signer.unsafe_sign_holder_commitment_and_htlcs(&self.holder_commitment, &self.secp_ctx).expect("sign holder commitment");
		self.holder_htlc_sigs = Some(Self::extract_holder_sigs(&self.holder_commitment, htlc_sigs));
		self.holder_commitment.add_holder_sig(funding_redeemscript, sig)
	}

	pub(crate) fn get_fully_signed_htlc_tx(&mut self, outp: &::bitcoin::OutPoint, preimage: &Option<PaymentPreimage>) -> Option<Transaction> {
		let mut htlc_tx = None;
		let commitment_txid = self.holder_commitment.trust().txid();
		// Check if the HTLC spends from the current holder commitment
		if commitment_txid == outp.txid {
			self.sign_latest_holder_htlcs();
			if let &Some(ref htlc_sigs) = &self.holder_htlc_sigs {
				let &(ref htlc_idx, ref htlc_sig) = htlc_sigs[outp.vout as usize].as_ref().unwrap();
				let trusted_tx = self.holder_commitment.trust();
				let counterparty_htlc_sig = self.holder_commitment.counterparty_htlc_sigs[*htlc_idx];
				htlc_tx = Some(trusted_tx
					.get_signed_htlc_tx(&self.channel_transaction_parameters.as_holder_broadcastable(), *htlc_idx, &counterparty_htlc_sig, htlc_sig, preimage));
			}
		}
		// If the HTLC doesn't spend the current holder commitment, check if it spends the previous one
		if htlc_tx.is_none() && self.prev_holder_commitment.is_some() {
			let commitment_txid = self.prev_holder_commitment.as_ref().unwrap().trust().txid();
			if commitment_txid == outp.txid {
				self.sign_prev_holder_htlcs();
				if let &Some(ref htlc_sigs) = &self.prev_holder_htlc_sigs {
					let &(ref htlc_idx, ref htlc_sig) = htlc_sigs[outp.vout as usize].as_ref().unwrap();
					let holder_commitment = self.prev_holder_commitment.as_ref().unwrap();
					let trusted_tx = holder_commitment.trust();
					let counterparty_htlc_sig = holder_commitment.counterparty_htlc_sigs[*htlc_idx];
					htlc_tx = Some(trusted_tx
						.get_signed_htlc_tx(&self.channel_transaction_parameters.as_holder_broadcastable(), *htlc_idx, &counterparty_htlc_sig, htlc_sig, preimage));
				}
			}
		}
		htlc_tx
	}

	#[cfg(any(test,feature = "unsafe_revoked_tx_signing"))]
	pub(crate) fn unsafe_get_fully_signed_htlc_tx(&mut self, outp: &::bitcoin::OutPoint, preimage: &Option<PaymentPreimage>) -> Option<Transaction> {
		let latest_had_sigs = self.holder_htlc_sigs.is_some();
		let prev_had_sigs = self.prev_holder_htlc_sigs.is_some();
		let ret = self.get_fully_signed_htlc_tx(outp, preimage);
		if !latest_had_sigs {
			self.holder_htlc_sigs = None;
		}
		if !prev_had_sigs {
			self.prev_holder_htlc_sigs = None;
		}
		ret
	}
}
