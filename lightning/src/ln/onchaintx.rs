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
//! OnchainTxHandler objetcs are fully-part of ChannelMonitor and encapsulates all
//! building, tracking, bumping and notifications functions.

use bitcoin::blockdata::transaction::Transaction;
use bitcoin::blockdata::transaction::OutPoint as BitcoinOutPoint;
use bitcoin::blockdata::script::Script;

use bitcoin::hash_types::Txid;

use bitcoin::secp256k1::{Secp256k1, Signature};
use bitcoin::secp256k1;

use ln::msgs::DecodeError;
use ln::channelmonitor::{ANTI_REORG_DELAY, CLTV_SHARED_CLAIM_BUFFER};
use ln::channelmanager::PaymentPreimage;
use ln::chan_utils::HolderCommitmentTransaction;
use ln::onchain_utils::{OnchainRequest, PackageTemplate, BumpStrategy};
use ln::onchain_utils;
use chain::chaininterface::{FeeEstimator, BroadcasterInterface, ConfirmationTarget};
use chain::keysinterface::ChannelKeys;
use chain::utxointerface::UtxoPool;
use util::logger::Logger;
use util::ser::{Readable, Writer, Writeable};
use util::byte_utils;

use std::collections::{HashMap, hash_map};
use std::cmp;
use std::ops::Deref;

const MAX_ALLOC_SIZE: usize = 64*1024;

/// Upon discovering of some classes of onchain tx by ChannelMonitor, we may have to take actions on it
/// once they mature to enough confirmations (ANTI_REORG_DELAY)
#[derive(Clone, PartialEq)]
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

impl Readable for Option<Vec<Option<(usize, Signature)>>> {
	fn read<R: ::std::io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
		match Readable::read(reader)? {
			0u8 => Ok(None),
			1u8 => {
				let vlen: u64 = Readable::read(reader)?;
				let mut ret = Vec::with_capacity(cmp::min(vlen as usize, MAX_ALLOC_SIZE / ::std::mem::size_of::<Option<(usize, Signature)>>()));
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
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
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
pub struct OnchainTxHandler<ChanSigner: ChannelKeys> {
	destination_script: Script,
	pub(super) holder_commitment: Option<HolderCommitmentTransaction>,
	// holder_htlc_sigs and prev_holder_htlc_sigs are in the order as they appear in the commitment
	// transaction outputs (hence the Option<>s inside the Vec). The first usize is the index in
	// the set of HTLCs in the HolderCommitmentTransaction (including those which do not appear in
	// the commitment transaction).
	holder_htlc_sigs: Option<Vec<Option<(usize, Signature)>>>,
	prev_holder_commitment: Option<HolderCommitmentTransaction>,
	prev_holder_htlc_sigs: Option<Vec<Option<(usize, Signature)>>>,
	on_holder_tx_csv: u16,

	pub(super) key_storage: ChanSigner,

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
	pub pending_claim_requests: HashMap<Txid, OnchainRequest>,
	#[cfg(not(test))]
	pending_claim_requests: HashMap<Txid, OnchainRequest>,

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

	onchain_events_waiting_threshold_conf: HashMap<u32, Vec<OnchainEvent>>,

	pub(super) secp_ctx: Secp256k1<secp256k1::All>,
}

impl<ChanSigner: ChannelKeys + Writeable> OnchainTxHandler<ChanSigner> {
	pub(crate) fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
		self.destination_script.write(writer)?;
		self.holder_commitment.write(writer)?;
		self.holder_htlc_sigs.write(writer)?;
		self.prev_holder_commitment.write(writer)?;
		self.prev_holder_htlc_sigs.write(writer)?;

		self.on_holder_tx_csv.write(writer)?;

		self.key_storage.write(writer)?;

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

		writer.write_all(&byte_utils::be64_to_array(self.onchain_events_waiting_threshold_conf.len() as u64))?;
		for (ref target, ref events) in self.onchain_events_waiting_threshold_conf.iter() {
			writer.write_all(&byte_utils::be32_to_array(**target))?;
			writer.write_all(&byte_utils::be64_to_array(events.len() as u64))?;
			for ev in events.iter() {
				match *ev {
					OnchainEvent::Claim { ref claim_request } => {
						writer.write_all(&[0; 1])?;
						claim_request.write(writer)?;
					},
					OnchainEvent::ContentiousOutpoint { ref package } => {
						writer.write_all(&[1; 1])?;
						package.write(writer)?;
					}
				}
			}
		}
		Ok(())
	}
}

impl<ChanSigner: ChannelKeys + Readable> Readable for OnchainTxHandler<ChanSigner> {
	fn read<R: ::std::io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
		let destination_script = Readable::read(reader)?;

		let holder_commitment = Readable::read(reader)?;
		let holder_htlc_sigs = Readable::read(reader)?;
		let prev_holder_commitment = Readable::read(reader)?;
		let prev_holder_htlc_sigs = Readable::read(reader)?;

		let on_holder_tx_csv = Readable::read(reader)?;

		let key_storage = Readable::read(reader)?;

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
		let waiting_threshold_conf_len: u64 = Readable::read(reader)?;
		let mut onchain_events_waiting_threshold_conf = HashMap::with_capacity(cmp::min(waiting_threshold_conf_len as usize, MAX_ALLOC_SIZE / 128));
		for _ in 0..waiting_threshold_conf_len {
			let height_target = Readable::read(reader)?;
			let events_len: u64 = Readable::read(reader)?;
			let mut events = Vec::with_capacity(cmp::min(events_len as usize, MAX_ALLOC_SIZE / 128));
			for _ in 0..events_len {
				let ev = match <u8 as Readable>::read(reader)? {
					0 => {
						let claim_request = Readable::read(reader)?;
						OnchainEvent::Claim {
							claim_request
						}
					},
					1 => {
						let package = Readable::read(reader)?;
						OnchainEvent::ContentiousOutpoint {
							package
						}
					}
					_ => return Err(DecodeError::InvalidValue),
				};
				events.push(ev);
			}
			onchain_events_waiting_threshold_conf.insert(height_target, events);
		}

		Ok(OnchainTxHandler {
			destination_script,
			holder_commitment,
			holder_htlc_sigs,
			prev_holder_commitment,
			prev_holder_htlc_sigs,
			on_holder_tx_csv,
			key_storage,
			claimable_outpoints,
			pending_claim_requests,
			onchain_events_waiting_threshold_conf,
			secp_ctx: Secp256k1::new(),
		})
	}
}

impl<ChanSigner: ChannelKeys> OnchainTxHandler<ChanSigner> {
	pub(super) fn new(destination_script: Script, keys: ChanSigner, on_holder_tx_csv: u16) -> Self {

		let key_storage = keys;

		OnchainTxHandler {
			destination_script,
			holder_commitment: None,
			holder_htlc_sigs: None,
			prev_holder_commitment: None,
			prev_holder_htlc_sigs: None,
			on_holder_tx_csv,
			key_storage,
			pending_claim_requests: HashMap::new(),
			claimable_outpoints: HashMap::new(),
			onchain_events_waiting_threshold_conf: HashMap::new(),

			secp_ctx: Secp256k1::new(),
		}
	}

	/// In LN, output claimed are time-sensitive, which means we have to spend them before reaching some timelock expiration. At in-channel
	/// output detection, we generate a first version of a claim tx and associate to it a height timer. A height timer is an absolute block
	/// height than once reached we should generate a new bumped "version" of the claim tx to be sure than we safely claim outputs before
	/// than our counterparty can do it too. If timelock expires soon, height timer is going to be scale down in consequence to increase
	/// frequency of the bump and so increase our bets of success.
	fn get_height_timer(current_height: u32, timelock_expiration: u32) -> u32 {
		if timelock_expiration <= current_height + 3 {
			return current_height + 1
		} else if timelock_expiration - current_height <= 15 {
			return current_height + 3
		}
		current_height + 15
	}

	/// Lightning security model (i.e being able to redeem/timeout HTLC or penalize coutnerparty onchain) lays on the assumption of claim transactions getting confirmed before timelock expiration
	/// (CSV or CLTV following cases). In case of high-fee spikes, claim tx may stuck in the mempool, so you need to bump its feerate quickly using Replace-By-Fee or Child-Pay-For-Parent.
	fn generate_claim_tx<F: Deref, L: Deref, U: Deref>(&mut self, height: u32, cached_request: &mut OnchainRequest, fee_estimator: F, logger: L, utxo_pool: U) -> Option<(Option<u32>, u64, Vec<Transaction>)>
		where F::Target: FeeEstimator,
					L::Target: Logger,
		      U::Target: UtxoPool,
	{
		if cached_request.content.outpoints().len() == 0 { return None } // But don't prune pending claiming request yet, we may have to resurrect HTLCs

		if cached_request.bump_strategy == BumpStrategy::CPFP {
			if cached_request.feerate_previous < fee_estimator.get_est_sat_per_1000_weight(ConfirmationTarget::HighPriority) as u64 {
				// Bumping UTXO is allocated the first time we detect the pre-signed feerate
				// is our fee estimator confirmation target
				cached_request.content.package_cpfp(&utxo_pool);
			}
		}

		// Compute new height timer to decide when we need to regenerate a new bumped version of the claim tx (if we
		// didn't receive confirmation of it before, or not enough reorg-safe depth on top of it).
		let mut new_timer = Some(Self::get_height_timer(height, cached_request.absolute_timelock));
		let mut amt = cached_request.content.package_amounts();
		let holder_commitment = self.holder_commitment.as_ref().unwrap();
		let predicted_weight = cached_request.content.package_weight(&self.destination_script, &holder_commitment.unsigned_tx);
		if let Some((output_value, new_feerate)) = onchain_utils::compute_output_value(predicted_weight, amt, cached_request.feerate_previous, &fee_estimator, &logger) {
			assert!(new_feerate != 0);

			let txn = cached_request.content.package_finalize(self, output_value, self.destination_script.clone(), &logger, &utxo_pool).unwrap();
			log_trace!(logger, "...with timer {} weight {} feerate {} CPFP: {}", new_timer.unwrap(), predicted_weight, new_feerate, txn.len() > 1);
			assert!(predicted_weight >= txn[0].get_weight() + if txn.len() == 2 { txn[1].get_weight() } else { 0 });
			//TODO: for now disable timer for CPFP-package (2nd-stage HTLC only).
			// Enabling them is pending on refactoring first holder HTLCs construction 
			// and signing.
			if predicted_weight == 706 || predicted_weight == 666 {
				new_timer = None;
			}
			return Some((new_timer, new_feerate, txn))
		}
		None
	}

	pub(super) fn block_connected<B: Deref, F: Deref, L: Deref, U: Deref>(&mut self, txn_matched: &[&Transaction], requests: Vec<OnchainRequest>, height: u32, broadcaster: B, fee_estimator: F, logger: L, utxo_pool: U)
		where B::Target: BroadcasterInterface,
		      F::Target: FeeEstimator,
					L::Target: Logger,
		      U::Target: UtxoPool
	{
		log_trace!(logger, "Block at height {} connected with {} claim requests", height, requests.len());
		let mut preprocessed_requests = Vec::with_capacity(requests.len());
		let mut aggregated_request = OnchainRequest::default();

		// Try to aggregate outputs if their timelock expiration isn't imminent (absolute_timelock
		// <= CLTV_SHARED_CLAIM_BUFFER) and they don't require an immediate nLockTime (aggregable).
		for req in requests {
			// Don't claim a outpoint twice that would be bad for privacy and may uselessly lock a CPFP input for a while
			if let Some(_) = self.claimable_outpoints.get(req.content.outpoints()[0]) { log_trace!(logger, "Bouncing off outpoint {}:{}, already registered its claiming request", req.content.outpoints()[0].txid, req.content.outpoints()[0].vout); } else {
				log_trace!(logger, "Test if outpoint can be aggregated with expiration {} against {}", req.absolute_timelock, height + CLTV_SHARED_CLAIM_BUFFER);
				if req.absolute_timelock <= height + CLTV_SHARED_CLAIM_BUFFER || !req.aggregation {
					// Don't aggregate if outpoint absolute timelock is soon or marked as non-aggregable
					preprocessed_requests.push(req);
				} else {
					aggregated_request.request_merge(req);
				}
			}
		}
		preprocessed_requests.push(aggregated_request);

		// Generate claim transactions and track them to bump if necessary at
		// height timer expiration (i.e in how many blocks we're going to take action).
		for mut req in preprocessed_requests {
			if let Some((new_timer, new_feerate, txn)) = self.generate_claim_tx(height, &mut req, &*fee_estimator, &*logger, &*utxo_pool) {
				req.height_timer = new_timer;
				req.feerate_previous = new_feerate;
				let txid = txn[0].txid();
				for k in req.content.outpoints() {
					log_trace!(logger, "Registering claiming request for {}:{}", k.txid, k.vout);
					self.claimable_outpoints.insert(k.clone(), (txid, height));
				}
				self.pending_claim_requests.insert(txid, req);
				for tx in txn {
					log_trace!(logger, "Broadcast onchain {}", log_tx!(tx));
					broadcaster.broadcast_transaction(&tx);
				}
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
						if request.content.outpoints().len() != tx.input.len() {
							set_equality = false;
						} else {
							for (claim_inp, tx_inp) in request.content.outpoints().iter().zip(tx.input.iter()) {
								if **claim_inp != tx_inp.previous_output {
									set_equality = false;
								}
							}
						}

						macro_rules! clean_claim_request_after_safety_delay {
							() => {
								let new_event = OnchainEvent::Claim { claim_request: first_claim_txid_height.0.clone() };
								match self.onchain_events_waiting_threshold_conf.entry(height + ANTI_REORG_DELAY - 1) {
									hash_map::Entry::Occupied(mut entry) => {
										if !entry.get().contains(&new_event) {
											entry.get_mut().push(new_event);
										}
									},
									hash_map::Entry::Vacant(entry) => {
										entry.insert(vec![new_event]);
									}
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
								if let Some(package) = request.content.package_split(&input.previous_output) {
									claimed_outputs_material.push(package);
									at_least_one_drop = true;
								}
								// If there are no outpoints left to claim in this request, drop it entirely after ANTI_REORG_DELAY.
								if request.content.outpoints().is_empty() {
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
				let new_event = OnchainEvent::ContentiousOutpoint { package };
				match self.onchain_events_waiting_threshold_conf.entry(height + ANTI_REORG_DELAY - 1) {
					hash_map::Entry::Occupied(mut entry) => {
						if !entry.get().contains(&new_event) {
							entry.get_mut().push(new_event);
						}
					},
					hash_map::Entry::Vacant(entry) => {
						entry.insert(vec![new_event]);
					}
				}
			}
		}

		// After security delay, either our claim tx got enough confs or outpoint is definetely out of reach
		if let Some(events) = self.onchain_events_waiting_threshold_conf.remove(&height) {
			for ev in events {
				match ev {
					OnchainEvent::Claim { claim_request } => {
						// We may remove a whole set of claim outpoints here, as these one may have
						// been aggregated in a single tx and claimed so atomically
						if let Some(request) = self.pending_claim_requests.remove(&claim_request) {
							for outpoint in request.content.outpoints() {
								self.claimable_outpoints.remove(&outpoint);
							}
						}
					},
					OnchainEvent::ContentiousOutpoint { package } => {
						self.claimable_outpoints.remove(&package.outpoints()[0]);
					}
				}
			}
		}

		// Check if any pending claim request must be rescheduled
		for (first_claim_txid, ref request) in self.pending_claim_requests.iter() {
			if let Some(h) = request.height_timer {
				if h == height {
					bump_candidates.insert(*first_claim_txid, (*request).clone());
				}
			}
		}

		// Build, bump and rebroadcast tx accordingly
		log_trace!(logger, "Bumping {} candidates", bump_candidates.len());
		for (first_claim_txid, ref mut request) in bump_candidates.iter_mut() {
			if let Some((new_timer, new_feerate, txn)) = self.generate_claim_tx(height, request, &*fee_estimator, &*logger, &*utxo_pool) {
				for tx in txn {
					log_trace!(logger, "Broadcast onchain {}", log_tx!(tx));
					broadcaster.broadcast_transaction(&tx);
				}
				if let Some(request) = self.pending_claim_requests.get_mut(first_claim_txid) {
					request.height_timer = new_timer;
					request.feerate_previous = new_feerate;
				}
			}
		}
	}

	pub(super) fn block_disconnected<B: Deref, F: Deref, L: Deref, U: Deref>(&mut self, height: u32, broadcaster: B, fee_estimator: F, logger: L, utxo_pool: U)
		where B::Target: BroadcasterInterface,
		      F::Target: FeeEstimator,
					L::Target: Logger,
		      U::Target: UtxoPool
	{
		let mut bump_candidates = HashMap::new();
		if let Some(events) = self.onchain_events_waiting_threshold_conf.remove(&(height + ANTI_REORG_DELAY - 1)) {
			//- our claim tx on a commitment tx output
			//- resurect outpoint back in its claimable set and regenerate tx
			for ev in events {
				match ev {
					OnchainEvent::ContentiousOutpoint { package } => {
						if let Some(ancestor_claimable_txid) = self.claimable_outpoints.get(&package.outpoints()[0]) {
							if let Some(request) = self.pending_claim_requests.get_mut(&ancestor_claimable_txid.0) {
								request.content.package_merge(package);
								// Using a HashMap guarantee us than if we have multiple outpoints getting
								// resurrected only one bump claim tx is going to be broadcast
								bump_candidates.insert(ancestor_claimable_txid.clone(), request.clone());
							}
						}
					},
					_ => {},
				}
			}
		}
		for (_, ref mut request) in bump_candidates.iter_mut() {
			if let Some((new_timer, new_feerate, txn)) = self.generate_claim_tx(height, request, &*fee_estimator, &*logger, &*utxo_pool) {
				request.height_timer = new_timer;
				request.feerate_previous = new_feerate;
				for tx in txn {
					broadcaster.broadcast_transaction(&tx);
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
			if v.1 == height {
			remove_request.push(v.0.clone());
			false
			} else { true });
		for req in remove_request {
			self.pending_claim_requests.remove(&req);
		}
	}

	pub(super) fn provide_latest_holder_tx(&mut self, tx: HolderCommitmentTransaction) {
		self.prev_holder_commitment = self.holder_commitment.take();
		self.holder_commitment = Some(tx);
	}

	fn sign_latest_holder_htlcs(&mut self) {
		if let Some(ref holder_commitment) = self.holder_commitment {
			if let Ok(sigs) = self.key_storage.sign_holder_commitment_htlc_transactions(holder_commitment, &self.secp_ctx) {
				self.holder_htlc_sigs = Some(Vec::new());
				let ret = self.holder_htlc_sigs.as_mut().unwrap();
				for (htlc_idx, (holder_sig, &(ref htlc, _))) in sigs.iter().zip(holder_commitment.per_htlc.iter()).enumerate() {
					if let Some(tx_idx) = htlc.transaction_output_index {
						if ret.len() <= tx_idx as usize { ret.resize(tx_idx as usize + 1, None); }
						ret[tx_idx as usize] = Some((htlc_idx, holder_sig.expect("Did not receive a signature for a non-dust HTLC")));
					} else {
						assert!(holder_sig.is_none(), "Received a signature for a dust HTLC");
					}
				}
			}
		}
	}
	fn sign_prev_holder_htlcs(&mut self) {
		if let Some(ref holder_commitment) = self.prev_holder_commitment {
			if let Ok(sigs) = self.key_storage.sign_holder_commitment_htlc_transactions(holder_commitment, &self.secp_ctx) {
				self.prev_holder_htlc_sigs = Some(Vec::new());
				let ret = self.prev_holder_htlc_sigs.as_mut().unwrap();
				for (htlc_idx, (holder_sig, &(ref htlc, _))) in sigs.iter().zip(holder_commitment.per_htlc.iter()).enumerate() {
					if let Some(tx_idx) = htlc.transaction_output_index {
						if ret.len() <= tx_idx as usize { ret.resize(tx_idx as usize + 1, None); }
						ret[tx_idx as usize] = Some((htlc_idx, holder_sig.expect("Did not receive a signature for a non-dust HTLC")));
					} else {
						assert!(holder_sig.is_none(), "Received a signature for a dust HTLC");
					}
				}
			}
		}
	}

	//TODO: getting lastest holder transactions should be infaillible and result in us "force-closing the channel", but we may
	// have empty holder commitment transaction if a ChannelMonitor is asked to force-close just after Channel::get_outbound_funding_created,
	// before providing a initial commitment transaction. For outbound channel, init ChannelMonitor at Channel::funding_signed, there is nothing
	// to monitor before.
	pub(super) fn get_fully_signed_holder_tx(&mut self, funding_redeemscript: &Script) -> Option<Transaction> {
		if let Some(ref mut holder_commitment) = self.holder_commitment {
			match self.key_storage.sign_holder_commitment(holder_commitment, &self.secp_ctx) {
				Ok(sig) => Some(holder_commitment.add_holder_sig(funding_redeemscript, sig)),
				Err(_) => return None,
			}
		} else {
			None
		}
	}

	#[cfg(any(test, feature="unsafe_revoked_tx_signing"))]
	pub(super) fn get_fully_signed_copy_holder_tx(&mut self, funding_redeemscript: &Script) -> Option<Transaction> {
		if let Some(ref mut holder_commitment) = self.holder_commitment {
			let holder_commitment = holder_commitment.clone();
			match self.key_storage.sign_holder_commitment(&holder_commitment, &self.secp_ctx) {
				Ok(sig) => Some(holder_commitment.add_holder_sig(funding_redeemscript, sig)),
				Err(_) => return None,
			}
		} else {
			None
		}
	}

	pub(super) fn get_fully_signed_htlc_tx(&mut self, outp: &::bitcoin::OutPoint, preimage: &Option<PaymentPreimage>) -> Option<Transaction> {
		let mut htlc_tx = None;
		if self.holder_commitment.is_some() {
			let commitment_txid = self.holder_commitment.as_ref().unwrap().txid();
			if commitment_txid == outp.txid {
				self.sign_latest_holder_htlcs();
				if let &Some(ref htlc_sigs) = &self.holder_htlc_sigs {
					let &(ref htlc_idx, ref htlc_sig) = htlc_sigs[outp.vout as usize].as_ref().unwrap();
					htlc_tx = Some(self.holder_commitment.as_ref().unwrap()
						.get_signed_htlc_tx(*htlc_idx, htlc_sig, preimage, self.on_holder_tx_csv));
				}
			}
		}
		if self.prev_holder_commitment.is_some() {
			let commitment_txid = self.prev_holder_commitment.as_ref().unwrap().txid();
			if commitment_txid == outp.txid {
				self.sign_prev_holder_htlcs();
				if let &Some(ref htlc_sigs) = &self.prev_holder_htlc_sigs {
					let &(ref htlc_idx, ref htlc_sig) = htlc_sigs[outp.vout as usize].as_ref().unwrap();
					htlc_tx = Some(self.prev_holder_commitment.as_ref().unwrap()
						.get_signed_htlc_tx(*htlc_idx, htlc_sig, preimage, self.on_holder_tx_csv));
				}
			}
		}
		htlc_tx
	}

	#[cfg(any(test,feature = "unsafe_revoked_tx_signing"))]
	pub(super) fn unsafe_get_fully_signed_htlc_tx(&mut self, outp: &::bitcoin::OutPoint, preimage: &Option<PaymentPreimage>) -> Option<Transaction> {
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
