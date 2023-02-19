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

use bitcoin::hash_types::{Txid, BlockHash};

use bitcoin::secp256k1::{Secp256k1, ecdsa::Signature};
use bitcoin::secp256k1;

use crate::chain::keysinterface::{ChannelSigner, EntropySource, SignerProvider};
use crate::ln::msgs::DecodeError;
use crate::ln::PaymentPreimage;
#[cfg(anchors)]
use crate::ln::chan_utils::{self, HTLCOutputInCommitment};
use crate::ln::chan_utils::{ChannelTransactionParameters, HolderCommitmentTransaction};
#[cfg(anchors)]
use crate::chain::chaininterface::ConfirmationTarget;
use crate::chain::chaininterface::{FeeEstimator, BroadcasterInterface, LowerBoundedFeeEstimator};
use crate::chain::channelmonitor::{ANTI_REORG_DELAY, CLTV_SHARED_CLAIM_BUFFER};
use crate::chain::keysinterface::WriteableEcdsaChannelSigner;
#[cfg(anchors)]
use crate::chain::package::PackageSolvingData;
use crate::chain::package::PackageTemplate;
use crate::util::logger::Logger;
use crate::util::ser::{Readable, ReadableArgs, MaybeReadable, UpgradableRequired, Writer, Writeable, VecWriter};

use crate::io;
use crate::prelude::*;
use alloc::collections::BTreeMap;
use core::cmp;
use core::ops::Deref;
use core::mem::replace;
#[cfg(anchors)]
use core::mem::swap;
use bitcoin::hashes::Hash;

const MAX_ALLOC_SIZE: usize = 64*1024;

/// An entry for an [`OnchainEvent`], stating the block height when the event was observed and the
/// transaction causing it.
///
/// Used to determine when the on-chain event can be considered safe from a chain reorganization.
#[derive(PartialEq, Eq)]
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

/// Upon discovering of some classes of onchain tx by ChannelMonitor, we may have to take actions on it
/// once they mature to enough confirmations (ANTI_REORG_DELAY)
#[derive(PartialEq, Eq)]
enum OnchainEvent {
	/// Outpoint under claim process by our own tx, once this one get enough confirmations, we remove it from
	/// bump-txn candidate buffer.
	Claim {
		package_id: PackageID,
	},
	/// Claim tx aggregate multiple claimable outpoints. One of the outpoint may be claimed by a counterparty party tx.
	/// In this case, we need to drop the outpoint and regenerate a new claim tx. By safety, we keep tracking
	/// the outpoint to be sure to resurect it back to the claim tx if reorgs happen.
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
		(0, package_id, required),
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

#[cfg(anchors)]
/// The claim commonly referred to as the pre-signed second-stage HTLC transaction.
pub(crate) struct ExternalHTLCClaim {
	pub(crate) commitment_txid: Txid,
	pub(crate) per_commitment_number: u64,
	pub(crate) htlc: HTLCOutputInCommitment,
	pub(crate) preimage: Option<PaymentPreimage>,
	pub(crate) counterparty_sig: Signature,
}

// Represents the different types of claims for which events are yielded externally to satisfy said
// claims.
#[cfg(anchors)]
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
	},
}

/// Represents the different ways an output can be claimed (i.e., spent to an address under our
/// control) onchain.
pub(crate) enum OnchainClaim {
	/// A finalized transaction pending confirmation spending the output to claim.
	Tx(Transaction),
	#[cfg(anchors)]
	/// An event yielded externally to signal additional inputs must be added to a transaction
	/// pending confirmation spending the output to claim.
	Event(ClaimEvent),
}

/// An internal identifier to track pending package claims within the `OnchainTxHandler`.
type PackageID = [u8; 32];

/// OnchainTxHandler receives claiming requests, aggregates them if it's sound, broadcast and
/// do RBF bumping if possible.
#[derive(PartialEq)]
pub struct OnchainTxHandler<ChannelSigner: WriteableEcdsaChannelSigner> {
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
	pub(crate) pending_claim_requests: HashMap<PackageID, PackageTemplate>,
	#[cfg(not(test))]
	pending_claim_requests: HashMap<PackageID, PackageTemplate>,
	#[cfg(anchors)]
	pending_claim_events: HashMap<PackageID, ClaimEvent>,

	// Used to link outpoints claimed in a connected block to a pending claim request.
	// Key is outpoint than monitor parsing has detected we have keys/scripts to claim
	// Value is (pending claim request identifier, confirmation_block), identifier
	// is txid of the initial claiming transaction and is immutable until outpoint is
	// post-anti-reorg-delay solved, confirmaiton_block is used to erase entry if
	// block with output gets disconnected.
	#[cfg(test)] // Used in functional_test to verify sanitization
	pub claimable_outpoints: HashMap<BitcoinOutPoint, (PackageID, u32)>,
	#[cfg(not(test))]
	claimable_outpoints: HashMap<BitcoinOutPoint, (PackageID, u32)>,

	locktimed_packages: BTreeMap<u32, Vec<PackageTemplate>>,

	onchain_events_awaiting_threshold_conf: Vec<OnchainEventEntry>,

	pub(super) secp_ctx: Secp256k1<secp256k1::All>,
}

const SERIALIZATION_VERSION: u8 = 1;
const MIN_SERIALIZATION_VERSION: u8 = 1;

impl<ChannelSigner: WriteableEcdsaChannelSigner> OnchainTxHandler<ChannelSigner> {
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

impl<'a, 'b, ES: EntropySource, SP: SignerProvider> ReadableArgs<(&'a ES, &'b SP, u64, [u8; 32])> for OnchainTxHandler<SP::Signer> {
	fn read<R: io::Read>(reader: &mut R, args: (&'a ES, &'b SP, u64, [u8; 32])) -> Result<Self, DecodeError> {
		let entropy_source = args.0;
		let signer_provider = args.1;
		let channel_value_satoshis = args.2;
		let channel_keys_id = args.3;

		let _ver = read_ver_prefix!(reader, SERIALIZATION_VERSION);

		let destination_script = Readable::read(reader)?;

		let holder_commitment = Readable::read(reader)?;
		let holder_htlc_sigs = Readable::read(reader)?;
		let prev_holder_commitment = Readable::read(reader)?;
		let prev_holder_htlc_sigs = Readable::read(reader)?;

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
			if let Some(val) = MaybeReadable::read(reader)? {
				onchain_events_awaiting_threshold_conf.push(val);
			}
		}

		read_tlv_fields!(reader, {});

		let mut secp_ctx = Secp256k1::new();
		secp_ctx.seeded_randomize(&entropy_source.get_secure_random_bytes());

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
			#[cfg(anchors)]
			pending_claim_events: HashMap::new(),
			secp_ctx,
		})
	}
}

impl<ChannelSigner: WriteableEcdsaChannelSigner> OnchainTxHandler<ChannelSigner> {
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
			#[cfg(anchors)]
			pending_claim_events: HashMap::new(),

			secp_ctx,
		}
	}

	pub(crate) fn get_prev_holder_commitment_to_self_value(&self) -> Option<u64> {
		self.prev_holder_commitment.as_ref().map(|commitment| commitment.to_broadcaster_value_sat())
	}

	pub(crate) fn get_cur_holder_commitment_to_self_value(&self) -> u64 {
		self.holder_commitment.to_broadcaster_value_sat()
	}

	#[cfg(anchors)]
	pub(crate) fn get_and_clear_pending_claim_events(&mut self) -> Vec<ClaimEvent> {
		let mut ret = HashMap::new();
		swap(&mut ret, &mut self.pending_claim_events);
		ret.into_iter().map(|(_, event)| event).collect::<Vec<_>>()
	}

	/// Lightning security model (i.e being able to redeem/timeout HTLC or penalize counterparty
	/// onchain) lays on the assumption of claim transactions getting confirmed before timelock
	/// expiration (CSV or CLTV following cases). In case of high-fee spikes, claim tx may get stuck
	/// in the mempool, so you need to bump its feerate quickly using Replace-By-Fee or
	/// Child-Pay-For-Parent.
	///
	/// Panics if there are signing errors, because signing operations in reaction to on-chain
	/// events are not expected to fail, and if they do, we may lose funds.
	fn generate_claim<F: Deref, L: Deref>(&mut self, cur_height: u32, cached_request: &PackageTemplate, fee_estimator: &LowerBoundedFeeEstimator<F>, logger: &L) -> Option<(Option<u32>, u64, OnchainClaim)>
		where F::Target: FeeEstimator,
					L::Target: Logger,
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
			if let Some(first_claim_txid_height) = self.claimable_outpoints.get(*outpoint) {
				// We check for outpoint spends within claims individually rather than as a set
				// since requests can have outpoints split off.
				if !self.onchain_events_awaiting_threshold_conf.iter()
					.any(|event_entry| if let OnchainEvent::Claim { package_id } = event_entry.event {
						first_claim_txid_height.0 == package_id
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
		let new_timer = Some(cached_request.get_height_timer(cur_height));
		if cached_request.is_malleable() {
			#[cfg(anchors)]
			{ // Attributes are not allowed on if expressions on our current MSRV of 1.41.
				if cached_request.requires_external_funding() {
					let target_feerate_sat_per_1000_weight = cached_request
						.compute_package_feerate(fee_estimator, ConfirmationTarget::HighPriority);
					if let Some(htlcs) = cached_request.construct_malleable_package_with_external_funding(self) {
						return Some((
							new_timer,
							target_feerate_sat_per_1000_weight as u64,
							OnchainClaim::Event(ClaimEvent::BumpHTLC {
								target_feerate_sat_per_1000_weight,
								htlcs,
							}),
						));
					} else {
						return None;
					}
				}
			}

			let predicted_weight = cached_request.package_weight(&self.destination_script);
			if let Some((output_value, new_feerate)) = cached_request.compute_package_output(
				predicted_weight, self.destination_script.dust_value().to_sat(), fee_estimator, logger,
			) {
				assert!(new_feerate != 0);

				let transaction = cached_request.finalize_malleable_package(self, output_value, self.destination_script.clone(), logger).unwrap();
				log_trace!(logger, "...with timer {} and feerate {}", new_timer.unwrap(), new_feerate);
				assert!(predicted_weight >= transaction.weight());
				return Some((new_timer, new_feerate, OnchainClaim::Tx(transaction)));
			}
		} else {
			// Untractable packages cannot have their fees bumped through Replace-By-Fee. Some
			// packages may support fee bumping through Child-Pays-For-Parent, indicated by those
			// which require external funding.
			#[cfg(not(anchors))]
			let inputs = cached_request.inputs();
			#[cfg(anchors)]
			let mut inputs = cached_request.inputs();
			debug_assert_eq!(inputs.len(), 1);
			let tx = match cached_request.finalize_untractable_package(self, logger) {
				Some(tx) => tx,
				None => return None,
			};
			if !cached_request.requires_external_funding() {
				return Some((None, 0, OnchainClaim::Tx(tx)));
			}
			#[cfg(anchors)]
			return inputs.find_map(|input| match input {
				// Commitment inputs with anchors support are the only untractable inputs supported
				// thus far that require external funding.
				PackageSolvingData::HolderFundingOutput(..) => {
					debug_assert_eq!(tx.txid(), self.holder_commitment.trust().txid(),
						"Holder commitment transaction mismatch");
					// We'll locate an anchor output we can spend within the commitment transaction.
					let funding_pubkey = &self.channel_transaction_parameters.holder_pubkeys.funding_pubkey;
					match chan_utils::get_anchor_output(&tx, funding_pubkey) {
						// An anchor output was found, so we should yield a funding event externally.
						Some((idx, _)) => {
							// TODO: Use a lower confirmation target when both our and the
							// counterparty's latest commitment don't have any HTLCs present.
							let conf_target = ConfirmationTarget::HighPriority;
							let package_target_feerate_sat_per_1000_weight = cached_request
								.compute_package_feerate(fee_estimator, conf_target);
							Some((
								new_timer,
								package_target_feerate_sat_per_1000_weight as u64,
								OnchainClaim::Event(ClaimEvent::BumpCommitment {
									package_target_feerate_sat_per_1000_weight,
									commitment_tx: tx.clone(),
									anchor_output_idx: idx,
								}),
							))
						},
						// An anchor output was not found. There's nothing we can do other than
						// attempt to broadcast the transaction with its current fee rate and hope
						// it confirms. This is essentially the same behavior as a commitment
						// transaction without anchor outputs.
						None => Some((None, 0, OnchainClaim::Tx(tx.clone()))),
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

	/// Upon channelmonitor.block_connected(..) or upon provision of a preimage on the forward link
	/// for this channel, provide new relevant on-chain transactions and/or new claim requests.
	/// Together with `update_claims_view_from_matched_txn` this used to be named
	/// `block_connected`, but it is now also used for claiming an HTLC output if we receive a
	/// preimage after force-close.
	///
	/// `conf_height` represents the height at which the request was generated. This
	/// does not need to equal the current blockchain tip height, which should be provided via
	/// `cur_height`, however it must never be higher than `cur_height`.
	pub(crate) fn update_claims_view_from_requests<B: Deref, F: Deref, L: Deref>(
		&mut self, requests: Vec<PackageTemplate>, conf_height: u32, cur_height: u32,
		broadcaster: &B, fee_estimator: &LowerBoundedFeeEstimator<F>, logger: &L
	) where
		B::Target: BroadcasterInterface,
		F::Target: FeeEstimator,
		L::Target: Logger,
	{
		log_debug!(logger, "Updating claims view at height {} with {} claim requests", cur_height, requests.len());
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
			if let Some((new_timer, new_feerate, claim)) = self.generate_claim(cur_height, &req, &*fee_estimator, &*logger) {
				req.set_timer(new_timer);
				req.set_feerate(new_feerate);
				let package_id = match claim {
					OnchainClaim::Tx(tx) => {
						log_info!(logger, "Broadcasting onchain {}", log_tx!(tx));
						broadcaster.broadcast_transaction(&tx);
						tx.txid().into_inner()
					},
					#[cfg(anchors)]
					OnchainClaim::Event(claim_event) => {
						log_info!(logger, "Yielding onchain event to spend inputs {:?}", req.outpoints());
						let package_id = match claim_event {
							ClaimEvent::BumpCommitment { ref commitment_tx, .. } => commitment_tx.txid().into_inner(),
							ClaimEvent::BumpHTLC { ref htlcs, .. } => {
								// Use the same construction as a lightning channel id to generate
								// the package id for this request based on the first HTLC. It
								// doesn't matter what we use as long as it's unique per request.
								let mut package_id = [0; 32];
								package_id[..].copy_from_slice(&htlcs[0].commitment_txid[..]);
								let htlc_output_index = htlcs[0].htlc.transaction_output_index.unwrap();
								package_id[30] ^= ((htlc_output_index >> 8) & 0xff) as u8;
								package_id[31] ^= ((htlc_output_index >> 0) & 0xff) as u8;
								package_id
							},
						};
						self.pending_claim_events.insert(package_id, claim_event);
						package_id
					},
				};
				for k in req.outpoints() {
					log_info!(logger, "Registering claiming request for {}:{}", k.txid, k.vout);
					self.claimable_outpoints.insert(k.clone(), (package_id, conf_height));
				}
				self.pending_claim_requests.insert(package_id, req);
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
	pub(crate) fn update_claims_view_from_matched_txn<B: Deref, F: Deref, L: Deref>(
		&mut self, txn_matched: &[&Transaction], conf_height: u32, conf_hash: BlockHash,
		cur_height: u32, broadcaster: &B, fee_estimator: &LowerBoundedFeeEstimator<F>, logger: &L
	) where
		B::Target: BroadcasterInterface,
		F::Target: FeeEstimator,
		L::Target: Logger,
	{
		log_debug!(logger, "Updating claims view at height {} with {} matched transactions in block {}", cur_height, txn_matched.len(), conf_height);
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
									event: OnchainEvent::Claim { package_id: first_claim_txid_height.0 }
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
				match entry.event {
					OnchainEvent::Claim { package_id } => {
						// We may remove a whole set of claim outpoints here, as these one may have
						// been aggregated in a single tx and claimed so atomically
						if let Some(request) = self.pending_claim_requests.remove(&package_id) {
							for outpoint in request.outpoints() {
								log_debug!(logger, "Removing claim tracking for {} due to maturation of claim package {}.",
									outpoint, log_bytes!(package_id));
								self.claimable_outpoints.remove(outpoint);
								#[cfg(anchors)]
								self.pending_claim_events.remove(&package_id);
							}
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
			if let Some((new_timer, new_feerate, bump_claim)) = self.generate_claim(cur_height, &request, &*fee_estimator, &*logger) {
				match bump_claim {
					OnchainClaim::Tx(bump_tx) => {
						log_info!(logger, "Broadcasting RBF-bumped onchain {}", log_tx!(bump_tx));
						broadcaster.broadcast_transaction(&bump_tx);
					},
					#[cfg(anchors)]
					OnchainClaim::Event(claim_event) => {
						log_info!(logger, "Yielding RBF-bumped onchain event to spend inputs {:?}", request.outpoints());
						self.pending_claim_events.insert(*first_claim_txid, claim_event);
					},
				}
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
		fee_estimator: &LowerBoundedFeeEstimator<F>,
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

	pub(crate) fn block_disconnected<B: Deref, F: Deref, L: Deref>(&mut self, height: u32, broadcaster: B, fee_estimator: &LowerBoundedFeeEstimator<F>, logger: L)
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
						if let Some(ancestor_claimable_txid) = self.claimable_outpoints.get(package.outpoints()[0]) {
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
		for (_first_claim_txid_height, request) in bump_candidates.iter_mut() {
			if let Some((new_timer, new_feerate, bump_claim)) = self.generate_claim(height, &request, fee_estimator, &&*logger) {
				request.set_timer(new_timer);
				request.set_feerate(new_feerate);
				match bump_claim {
					OnchainClaim::Tx(bump_tx) => {
						log_info!(logger, "Broadcasting onchain {}", log_tx!(bump_tx));
						broadcaster.broadcast_transaction(&bump_tx);
					},
					#[cfg(anchors)]
					OnchainClaim::Event(claim_event) => {
						log_info!(logger, "Yielding onchain event after reorg to spend inputs {:?}", request.outpoints());
						self.pending_claim_events.insert(_first_claim_txid_height.0, claim_event);
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

	pub(crate) fn get_relevant_txids(&self) -> Vec<(Txid, Option<BlockHash>)> {
		let mut txids: Vec<(Txid, Option<BlockHash>)> = self.onchain_events_awaiting_threshold_conf
			.iter()
			.map(|entry| (entry.txid, entry.block_hash))
			.collect();
		txids.sort_unstable_by_key(|(txid, _)| *txid);
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

	#[cfg(anchors)]
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
					}
				})
		};
		// Check if the HTLC spends from the current holder commitment or the previous one otherwise.
		find_htlc(&self.holder_commitment)
			.or_else(|| self.prev_holder_commitment.as_ref().map(|c| find_htlc(c)).flatten())
	}

	pub(crate) fn opt_anchors(&self) -> bool {
		self.channel_transaction_parameters.opt_anchors.is_some()
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
