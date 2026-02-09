// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Test that monitor update failures don't get our channel state out of sync.
//! One of the biggest concern with the monitor update failure handling code is that messages
//! resent after monitor updating is restored are delivered out-of-order, resulting in
//! commitment_signed messages having "invalid signatures".
//! To test this we stand up a network of three nodes and read bytes from the fuzz input to denote
//! actions such as sending payments, handling events, or changing monitor update return values on
//! a per-node basis. This should allow it to find any cases where the ordering of actions results
//! in us getting out of sync with ourselves, and, assuming at least one of our recieve- or
//! send-side handling is correct, other peers. We consider it a failure if any action results in a
//! channel being force-closed.

use bitcoin::amount::Amount;
use bitcoin::constants::genesis_block;
use bitcoin::locktime::absolute::LockTime;
use bitcoin::network::Network;
use bitcoin::opcodes;
use bitcoin::script::{Builder, ScriptBuf};
use bitcoin::transaction::Version;
use bitcoin::transaction::{Transaction, TxOut};
use bitcoin::FeeRate;

use bitcoin::block::Header;
use bitcoin::hash_types::{BlockHash, Txid};
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::sha256d::Hash as Sha256dHash;
use bitcoin::hashes::Hash as TraitImport;
use bitcoin::WPubkeyHash;

use lightning::blinded_path::message::{BlindedMessagePath, MessageContext, MessageForwardNode};
use lightning::blinded_path::payment::{BlindedPaymentPath, ReceiveTlvs};
use lightning::chain;
use lightning::chain::chaininterface::{
	BroadcasterInterface, ConfirmationTarget, FeeEstimator, TransactionType,
};
use lightning::chain::channelmonitor::{ChannelMonitor, MonitorEvent};
use lightning::chain::transaction::OutPoint;
use lightning::chain::{
	chainmonitor, channelmonitor, BestBlock, ChannelMonitorUpdateStatus, Confirm, Watch,
};
use lightning::events;
use lightning::ln::channel::{
	FEE_SPIKE_BUFFER_FEE_INCREASE_MULTIPLE, MAX_STD_OUTPUT_DUST_LIMIT_SATOSHIS,
};
use lightning::ln::channel_state::ChannelDetails;
use lightning::ln::channelmanager::{
	ChainParameters, ChannelManager, ChannelManagerReadArgs, PaymentId, RecentPaymentDetails,
};
use lightning::ln::functional_test_utils::*;
use lightning::ln::funding::{FundingContribution, FundingTemplate};
use lightning::ln::inbound_payment::ExpandedKey;
use lightning::ln::msgs::{
	self, BaseMessageHandler, ChannelMessageHandler, CommitmentUpdate, Init, MessageSendEvent,
	UpdateAddHTLC,
};
use lightning::ln::outbound_payment::RecipientOnionFields;
use lightning::ln::script::ShutdownScript;
use lightning::ln::types::ChannelId;
use lightning::offers::invoice::UnsignedBolt12Invoice;
use lightning::onion_message::messenger::{Destination, MessageRouter, OnionMessagePath};
use lightning::routing::router::{
	InFlightHtlcs, Path, PaymentParameters, Route, RouteHop, RouteParameters, Router,
};
use lightning::sign::{
	EntropySource, InMemorySigner, NodeSigner, PeerStorageKey, ReceiveAuthKey, Recipient,
	SignerProvider,
};
use lightning::types::payment::{PaymentHash, PaymentPreimage, PaymentSecret};
use lightning::util::async_poll::{MaybeSend, MaybeSync};
use lightning::util::config::UserConfig;
use lightning::util::errors::APIError;
use lightning::util::hash_tables::*;
use lightning::util::logger::Logger;
use lightning::util::ser::{LengthReadable, ReadableArgs, Writeable, Writer};
use lightning::util::test_channel_signer::{EnforcementState, SignerOp, TestChannelSigner};
use lightning::util::test_utils::TestWalletSource;
use lightning::util::wallet_utils::{WalletSourceSync, WalletSync};

use lightning_invoice::RawBolt11Invoice;

use crate::utils::test_logger::{self, Output};
use crate::utils::test_persister::TestPersister;

use bitcoin::secp256k1::ecdh::SharedSecret;
use bitcoin::secp256k1::ecdsa::{RecoverableSignature, Signature};
use bitcoin::secp256k1::schnorr;
use bitcoin::secp256k1::{self, Message, PublicKey, Scalar, Secp256k1, SecretKey};

use lightning::util::dyn_signer::DynSigner;

use std::cell::RefCell;
use std::cmp;
use std::collections::HashSet;
use std::mem;
use std::sync::atomic;
use std::sync::{Arc, Mutex};

const MAX_FEE: u32 = 10_000;
struct FuzzEstimator {
	ret_val: atomic::AtomicU32,
}

impl FeeEstimator for FuzzEstimator {
	fn get_est_sat_per_1000_weight(&self, conf_target: ConfirmationTarget) -> u32 {
		// We force-close channels if our counterparty sends us a feerate which is a small multiple
		// of our HighPriority fee estimate or smaller than our Background fee estimate. Thus, we
		// always return a HighPriority feerate here which is >= the maximum Normal feerate and a
		// Background feerate which is <= the minimum Normal feerate.
		match conf_target {
			ConfirmationTarget::MaximumFeeEstimate | ConfirmationTarget::UrgentOnChainSweep => {
				MAX_FEE
			},
			ConfirmationTarget::ChannelCloseMinimum
			| ConfirmationTarget::AnchorChannelFee
			| ConfirmationTarget::MinAllowedAnchorChannelRemoteFee
			| ConfirmationTarget::MinAllowedNonAnchorChannelRemoteFee
			| ConfirmationTarget::OutputSpendingFee => 253,
			ConfirmationTarget::NonAnchorChannelFee => {
				cmp::min(self.ret_val.load(atomic::Ordering::Acquire), MAX_FEE)
			},
		}
	}
}

impl FuzzEstimator {
	fn feerate_sat_per_kw(&self) -> FeeRate {
		let feerate = self.ret_val.load(atomic::Ordering::Acquire);
		FeeRate::from_sat_per_kwu(feerate as u64)
	}
}

struct FuzzRouter {}

impl Router for FuzzRouter {
	fn find_route(
		&self, _payer: &PublicKey, _params: &RouteParameters,
		_first_hops: Option<&[&ChannelDetails]>, _inflight_htlcs: InFlightHtlcs,
	) -> Result<Route, &'static str> {
		unreachable!()
	}

	fn create_blinded_payment_paths<T: secp256k1::Signing + secp256k1::Verification>(
		&self, _recipient: PublicKey, _local_node_receive_key: ReceiveAuthKey,
		_first_hops: Vec<ChannelDetails>, _tlvs: ReceiveTlvs, _amount_msats: Option<u64>,
		_secp_ctx: &Secp256k1<T>,
	) -> Result<Vec<BlindedPaymentPath>, ()> {
		unreachable!()
	}
}

impl MessageRouter for FuzzRouter {
	fn find_path(
		&self, _sender: PublicKey, _peers: Vec<PublicKey>, _destination: Destination,
	) -> Result<OnionMessagePath, ()> {
		unreachable!()
	}

	fn create_blinded_paths<T: secp256k1::Signing + secp256k1::Verification>(
		&self, _recipient: PublicKey, _local_node_receive_key: ReceiveAuthKey,
		_context: MessageContext, _peers: Vec<MessageForwardNode>, _secp_ctx: &Secp256k1<T>,
	) -> Result<Vec<BlindedMessagePath>, ()> {
		unreachable!()
	}
}

pub struct TestBroadcaster {
	txn_broadcasted: RefCell<Vec<Transaction>>,
}
impl BroadcasterInterface for TestBroadcaster {
	fn broadcast_transactions(&self, txs: &[(&Transaction, TransactionType)]) {
		for (tx, _broadcast_type) in txs {
			self.txn_broadcasted.borrow_mut().push((*tx).clone());
		}
	}
}

struct ChainState {
	blocks: Vec<(Header, Vec<Transaction>)>,
	confirmed_txids: HashSet<Txid>,
}

impl ChainState {
	fn new() -> Self {
		let genesis_hash = genesis_block(Network::Bitcoin).block_hash();
		let genesis_header = create_dummy_header(genesis_hash, 42);
		Self { blocks: vec![(genesis_header, Vec::new())], confirmed_txids: HashSet::new() }
	}

	fn tip_height(&self) -> u32 {
		(self.blocks.len() - 1) as u32
	}

	fn confirm_tx(&mut self, tx: Transaction) -> bool {
		let txid = tx.compute_txid();
		if self.confirmed_txids.contains(&txid) {
			return false;
		}
		self.confirmed_txids.insert(txid);

		let prev_hash = self.blocks.last().unwrap().0.block_hash();
		let header = create_dummy_header(prev_hash, 42);
		self.blocks.push((header, vec![tx]));

		for _ in 0..5 {
			let prev_hash = self.blocks.last().unwrap().0.block_hash();
			let header = create_dummy_header(prev_hash, 42);
			self.blocks.push((header, Vec::new()));
		}
		true
	}

	fn block_at(&self, height: u32) -> &(Header, Vec<Transaction>) {
		&self.blocks[height as usize]
	}
}

pub struct VecWriter(pub Vec<u8>);
impl Writer for VecWriter {
	fn write_all(&mut self, buf: &[u8]) -> Result<(), ::lightning::io::Error> {
		self.0.extend_from_slice(buf);
		Ok(())
	}
}

/// The LDK API requires that any time we tell it we're done persisting a `ChannelMonitor[Update]`
/// we never pass it in as the "latest" `ChannelMonitor` on startup. However, we can pass
/// out-of-date monitors as long as we never told LDK we finished persisting them, which we do by
/// storing both old `ChannelMonitor`s and ones that are "being persisted" here.
///
/// Note that such "being persisted" `ChannelMonitor`s are stored in `ChannelManager` and will
/// simply be replayed on startup.
struct LatestMonitorState {
	/// The latest monitor id which we told LDK we've persisted.
	///
	/// Note that there may still be earlier pending monitor updates in [`Self::pending_monitors`]
	/// which we haven't yet completed. We're allowed to reload with those as well, at least until
	/// they're completed.
	persisted_monitor_id: u64,
	/// The latest serialized `ChannelMonitor` that we told LDK we persisted.
	persisted_monitor: Vec<u8>,
	/// A set of (monitor id, serialized `ChannelMonitor`)s which we're currently "persisting",
	/// from LDK's perspective.
	pending_monitors: Vec<(u64, Vec<u8>)>,
}

struct TestChainMonitor {
	pub logger: Arc<dyn Logger>,
	pub keys: Arc<KeyProvider>,
	pub persister: Arc<TestPersister>,
	pub chain_monitor: Arc<
		chainmonitor::ChainMonitor<
			TestChannelSigner,
			Arc<dyn chain::Filter>,
			Arc<TestBroadcaster>,
			Arc<FuzzEstimator>,
			Arc<dyn Logger>,
			Arc<TestPersister>,
			Arc<KeyProvider>,
		>,
	>,
	pub latest_monitors: Mutex<HashMap<ChannelId, LatestMonitorState>>,
}
impl TestChainMonitor {
	pub fn new(
		broadcaster: Arc<TestBroadcaster>, logger: Arc<dyn Logger>, feeest: Arc<FuzzEstimator>,
		persister: Arc<TestPersister>, keys: Arc<KeyProvider>,
	) -> Self {
		Self {
			chain_monitor: Arc::new(chainmonitor::ChainMonitor::new(
				None,
				broadcaster,
				logger.clone(),
				feeest,
				Arc::clone(&persister),
				Arc::clone(&keys),
				keys.get_peer_storage_key(),
				false,
			)),
			logger,
			keys,
			persister,
			latest_monitors: Mutex::new(new_hash_map()),
		}
	}
}
impl chain::Watch<TestChannelSigner> for TestChainMonitor {
	fn watch_channel(
		&self, channel_id: ChannelId, monitor: channelmonitor::ChannelMonitor<TestChannelSigner>,
	) -> Result<chain::ChannelMonitorUpdateStatus, ()> {
		let mut ser = VecWriter(Vec::new());
		monitor.write(&mut ser).unwrap();
		let monitor_id = monitor.get_latest_update_id();
		let res = self.chain_monitor.watch_channel(channel_id, monitor);
		let state = match res {
			Ok(chain::ChannelMonitorUpdateStatus::Completed) => LatestMonitorState {
				persisted_monitor_id: monitor_id,
				persisted_monitor: ser.0,
				pending_monitors: Vec::new(),
			},
			Ok(chain::ChannelMonitorUpdateStatus::InProgress) => LatestMonitorState {
				persisted_monitor_id: monitor_id,
				persisted_monitor: Vec::new(),
				pending_monitors: vec![(monitor_id, ser.0)],
			},
			Ok(chain::ChannelMonitorUpdateStatus::UnrecoverableError) => panic!(),
			Err(()) => panic!(),
		};
		if self.latest_monitors.lock().unwrap().insert(channel_id, state).is_some() {
			panic!("Already had monitor pre-watch_channel");
		}
		res
	}

	fn update_channel(
		&self, channel_id: ChannelId, update: &channelmonitor::ChannelMonitorUpdate,
	) -> chain::ChannelMonitorUpdateStatus {
		let mut map_lock = self.latest_monitors.lock().unwrap();
		let map_entry = map_lock.get_mut(&channel_id).expect("Didn't have monitor on update call");
		let latest_monitor_data = map_entry
			.pending_monitors
			.last()
			.as_ref()
			.map(|(_, data)| data)
			.unwrap_or(&map_entry.persisted_monitor);
		let deserialized_monitor =
			<(BlockHash, channelmonitor::ChannelMonitor<TestChannelSigner>)>::read(
				&mut &latest_monitor_data[..],
				(&*self.keys, &*self.keys),
			)
			.unwrap()
			.1;
		deserialized_monitor
			.update_monitor(
				update,
				&&TestBroadcaster { txn_broadcasted: RefCell::new(Vec::new()) },
				&&FuzzEstimator { ret_val: atomic::AtomicU32::new(253) },
				&self.logger,
			)
			.unwrap();
		let mut ser = VecWriter(Vec::new());
		deserialized_monitor.write(&mut ser).unwrap();
		let res = self.chain_monitor.update_channel(channel_id, update);
		match res {
			chain::ChannelMonitorUpdateStatus::Completed => {
				map_entry.persisted_monitor_id = update.update_id;
				map_entry.persisted_monitor = ser.0;
			},
			chain::ChannelMonitorUpdateStatus::InProgress => {
				map_entry.pending_monitors.push((update.update_id, ser.0));
			},
			chain::ChannelMonitorUpdateStatus::UnrecoverableError => panic!(),
		}
		res
	}

	fn release_pending_monitor_events(
		&self,
	) -> Vec<(OutPoint, ChannelId, Vec<MonitorEvent>, PublicKey)> {
		return self.chain_monitor.release_pending_monitor_events();
	}
}

struct KeyProvider {
	node_secret: SecretKey,
	rand_bytes_id: atomic::AtomicU32,
	enforcement_states: Mutex<HashMap<[u8; 32], Arc<Mutex<EnforcementState>>>>,
}

impl EntropySource for KeyProvider {
	fn get_secure_random_bytes(&self) -> [u8; 32] {
		let id = self.rand_bytes_id.fetch_add(1, atomic::Ordering::Relaxed);
		#[rustfmt::skip]
		let mut res = [self.node_secret[31], 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 11, self.node_secret[31]];
		res[2..6].copy_from_slice(&id.to_le_bytes());
		res[30 - 4..30].copy_from_slice(&id.to_le_bytes());
		res
	}
}

impl NodeSigner for KeyProvider {
	fn get_node_id(&self, recipient: Recipient) -> Result<PublicKey, ()> {
		let node_secret = match recipient {
			Recipient::Node => Ok(&self.node_secret),
			Recipient::PhantomNode => Err(()),
		}?;
		Ok(PublicKey::from_secret_key(&Secp256k1::signing_only(), node_secret))
	}

	fn ecdh(
		&self, recipient: Recipient, other_key: &PublicKey, tweak: Option<&Scalar>,
	) -> Result<SharedSecret, ()> {
		let mut node_secret = match recipient {
			Recipient::Node => Ok(self.node_secret.clone()),
			Recipient::PhantomNode => Err(()),
		}?;
		if let Some(tweak) = tweak {
			node_secret = node_secret.mul_tweak(tweak).map_err(|_| ())?;
		}
		Ok(SharedSecret::new(other_key, &node_secret))
	}

	fn get_expanded_key(&self) -> ExpandedKey {
		#[rustfmt::skip]
		let random_bytes = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, self.node_secret[31]];
		ExpandedKey::new(random_bytes)
	}

	fn sign_invoice(
		&self, _invoice: &RawBolt11Invoice, _recipient: Recipient,
	) -> Result<RecoverableSignature, ()> {
		unreachable!()
	}

	fn get_peer_storage_key(&self) -> PeerStorageKey {
		PeerStorageKey { inner: [42; 32] }
	}

	fn get_receive_auth_key(&self) -> ReceiveAuthKey {
		ReceiveAuthKey([41; 32])
	}

	fn sign_bolt12_invoice(
		&self, _invoice: &UnsignedBolt12Invoice,
	) -> Result<schnorr::Signature, ()> {
		unreachable!()
	}

	fn sign_gossip_message(
		&self, msg: lightning::ln::msgs::UnsignedGossipMessage,
	) -> Result<Signature, ()> {
		let msg_hash = Message::from_digest(Sha256dHash::hash(&msg.encode()[..]).to_byte_array());
		let secp_ctx = Secp256k1::signing_only();
		Ok(secp_ctx.sign_ecdsa(&msg_hash, &self.node_secret))
	}

	fn sign_message(&self, msg: &[u8]) -> Result<String, ()> {
		Ok(lightning::util::message_signing::sign(msg, &self.node_secret))
	}
}

impl SignerProvider for KeyProvider {
	type EcdsaSigner = TestChannelSigner;
	#[cfg(taproot)]
	type TaprootSigner = TestChannelSigner;

	fn generate_channel_keys_id(&self, _inbound: bool, _user_channel_id: u128) -> [u8; 32] {
		let id = self.rand_bytes_id.fetch_add(1, atomic::Ordering::Relaxed) as u8;
		[id; 32]
	}

	fn derive_channel_signer(&self, channel_keys_id: [u8; 32]) -> Self::EcdsaSigner {
		let id = channel_keys_id[0];
		#[rustfmt::skip]
		let keys = InMemorySigner::new(
			SecretKey::from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, self.node_secret[31]]).unwrap(),
			SecretKey::from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, self.node_secret[31]]).unwrap(),
			// We leave both the v1 and v2 derivation to_remote keys the same as there's not any
			// real reason to fuzz differences here.
			SecretKey::from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6, self.node_secret[31]]).unwrap(),
			SecretKey::from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6, self.node_secret[31]]).unwrap(),
			true,
			SecretKey::from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, self.node_secret[31]]).unwrap(),
			SecretKey::from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, self.node_secret[31]]).unwrap(),
			[id, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9, self.node_secret[31]],
			channel_keys_id,
			channel_keys_id,
		);
		let revoked_commitment = self.make_enforcement_state_cell(keys.commitment_seed);
		let keys = DynSigner::new(keys);
		TestChannelSigner::new_with_revoked(keys, revoked_commitment, false, false)
	}

	fn get_destination_script(&self, _channel_keys_id: [u8; 32]) -> Result<ScriptBuf, ()> {
		let secp_ctx = Secp256k1::signing_only();
		#[rustfmt::skip]
		let channel_monitor_claim_key = SecretKey::from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, self.node_secret[31]]).unwrap();
		let our_channel_monitor_claim_key_hash = WPubkeyHash::hash(
			&PublicKey::from_secret_key(&secp_ctx, &channel_monitor_claim_key).serialize(),
		);
		Ok(Builder::new()
			.push_opcode(opcodes::all::OP_PUSHBYTES_0)
			.push_slice(our_channel_monitor_claim_key_hash)
			.into_script())
	}

	fn get_shutdown_scriptpubkey(&self) -> Result<ShutdownScript, ()> {
		let secp_ctx = Secp256k1::signing_only();
		#[rustfmt::skip]
		let secret_key = SecretKey::from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, self.node_secret[31]]).unwrap();
		let pubkey_hash =
			WPubkeyHash::hash(&PublicKey::from_secret_key(&secp_ctx, &secret_key).serialize());
		Ok(ShutdownScript::new_p2wpkh(&pubkey_hash))
	}
}

// Since this fuzzer is only concerned with live-channel operations, we don't need to worry about
// any signer operations that come after a force close.
const SUPPORTED_SIGNER_OPS: [SignerOp; 3] = [
	SignerOp::SignCounterpartyCommitment,
	SignerOp::GetPerCommitmentPoint,
	SignerOp::ReleaseCommitmentSecret,
];

impl KeyProvider {
	fn make_enforcement_state_cell(
		&self, commitment_seed: [u8; 32],
	) -> Arc<Mutex<EnforcementState>> {
		let mut revoked_commitments = self.enforcement_states.lock().unwrap();
		if !revoked_commitments.contains_key(&commitment_seed) {
			revoked_commitments
				.insert(commitment_seed, Arc::new(Mutex::new(EnforcementState::new())));
		}
		let cell = revoked_commitments.get(&commitment_seed).unwrap();
		Arc::clone(cell)
	}

	fn disable_supported_ops_for_all_signers(&self) {
		let enforcement_states = self.enforcement_states.lock().unwrap();
		for (_, state) in enforcement_states.iter() {
			for signer_op in SUPPORTED_SIGNER_OPS {
				state.lock().unwrap().disabled_signer_ops.insert(signer_op);
			}
		}
	}

	fn enable_op_for_all_signers(&self, signer_op: SignerOp) {
		let enforcement_states = self.enforcement_states.lock().unwrap();
		for (_, state) in enforcement_states.iter() {
			state.lock().unwrap().disabled_signer_ops.remove(&signer_op);
		}
	}
}

// Returns a bool indicating whether the payment failed.
#[inline]
fn check_payment_send_events(source: &ChanMan, sent_payment_id: PaymentId) -> bool {
	for payment in source.list_recent_payments() {
		match payment {
			RecentPaymentDetails::Pending { payment_id, .. } if payment_id == sent_payment_id => {
				return true;
			},
			RecentPaymentDetails::Abandoned { payment_id, .. } if payment_id == sent_payment_id => {
				return false;
			},
			_ => {},
		}
	}
	return false;
}

type ChanMan<'a> = ChannelManager<
	Arc<TestChainMonitor>,
	Arc<TestBroadcaster>,
	Arc<KeyProvider>,
	Arc<KeyProvider>,
	Arc<KeyProvider>,
	Arc<FuzzEstimator>,
	&'a FuzzRouter,
	&'a FuzzRouter,
	Arc<dyn Logger + MaybeSend + MaybeSync>,
>;

#[inline]
fn get_payment_secret_hash(dest: &ChanMan, payment_ctr: &mut u64) -> (PaymentSecret, PaymentHash) {
	*payment_ctr += 1;
	let payment_hash = PaymentHash(Sha256::hash(&[*payment_ctr as u8]).to_byte_array());
	let payment_secret = dest
		.create_inbound_payment_for_hash(payment_hash, None, 3600, None)
		.expect("create_inbound_payment_for_hash failed");
	(payment_secret, payment_hash)
}

#[inline]
fn send_payment(
	source: &ChanMan, dest: &ChanMan, dest_chan_id: ChannelId, amt: u64,
	payment_secret: PaymentSecret, payment_hash: PaymentHash, payment_id: PaymentId,
) -> bool {
	let (min_value_sendable, max_value_sendable, dest_scid) = source
		.list_usable_channels()
		.iter()
		.find(|chan| chan.channel_id == dest_chan_id)
		.map(|chan| {
			(
				chan.next_outbound_htlc_minimum_msat,
				chan.next_outbound_htlc_limit_msat,
				chan.short_channel_id.unwrap_or(0),
			)
		})
		.unwrap_or((0, 0, 0));
	let route_params = RouteParameters::from_payment_params_and_value(
		PaymentParameters::from_node_id(source.get_our_node_id(), TEST_FINAL_CLTV),
		amt,
	);
	let route = Route {
		paths: vec![Path {
			hops: vec![RouteHop {
				pubkey: dest.get_our_node_id(),
				node_features: dest.node_features(),
				short_channel_id: dest_scid,
				channel_features: dest.channel_features(),
				fee_msat: amt,
				cltv_expiry_delta: 200,
				maybe_announced_channel: true,
			}],
			blinded_tail: None,
		}],
		route_params: Some(route_params.clone()),
	};
	let onion = RecipientOnionFields::secret_only(payment_secret);
	let res = source.send_payment_with_route(route, payment_hash, onion, payment_id);
	match res {
		Err(err) => {
			panic!("Errored with {:?} on initial payment send", err);
		},
		Ok(()) => {
			let expect_failure = amt < min_value_sendable || amt > max_value_sendable;
			let succeeded = check_payment_send_events(source, payment_id);
			assert_eq!(succeeded, !expect_failure);
			succeeded
		},
	}
}

#[inline]
fn send_hop_payment(
	source: &ChanMan, middle: &ChanMan, middle_chan_id: ChannelId, dest: &ChanMan,
	dest_chan_id: ChannelId, amt: u64, payment_secret: PaymentSecret, payment_hash: PaymentHash,
	payment_id: PaymentId,
) -> bool {
	let (min_value_sendable, max_value_sendable, middle_scid) = source
		.list_usable_channels()
		.iter()
		.find(|chan| chan.channel_id == middle_chan_id)
		.map(|chan| {
			(
				chan.next_outbound_htlc_minimum_msat,
				chan.next_outbound_htlc_limit_msat,
				chan.short_channel_id.unwrap_or(0),
			)
		})
		.unwrap_or((0, 0, 0));
	let dest_scid = dest
		.list_channels()
		.iter()
		.find(|chan| chan.channel_id == dest_chan_id)
		.and_then(|chan| chan.short_channel_id)
		.unwrap_or(0);
	let first_hop_fee = 50_000;
	let route_params = RouteParameters::from_payment_params_and_value(
		PaymentParameters::from_node_id(source.get_our_node_id(), TEST_FINAL_CLTV),
		amt,
	);
	let route = Route {
		paths: vec![Path {
			hops: vec![
				RouteHop {
					pubkey: middle.get_our_node_id(),
					node_features: middle.node_features(),
					short_channel_id: middle_scid,
					channel_features: middle.channel_features(),
					fee_msat: first_hop_fee,
					cltv_expiry_delta: 100,
					maybe_announced_channel: true,
				},
				RouteHop {
					pubkey: dest.get_our_node_id(),
					node_features: dest.node_features(),
					short_channel_id: dest_scid,
					channel_features: dest.channel_features(),
					fee_msat: amt,
					cltv_expiry_delta: 200,
					maybe_announced_channel: true,
				},
			],
			blinded_tail: None,
		}],
		route_params: Some(route_params.clone()),
	};
	let onion = RecipientOnionFields::secret_only(payment_secret);
	let res = source.send_payment_with_route(route, payment_hash, onion, payment_id);
	match res {
		Err(err) => {
			panic!("Errored with {:?} on initial payment send", err);
		},
		Ok(()) => {
			let sent_amt = amt + first_hop_fee;
			let expect_failure = sent_amt < min_value_sendable || sent_amt > max_value_sendable;
			let succeeded = check_payment_send_events(source, payment_id);
			assert_eq!(succeeded, !expect_failure);
			succeeded
		},
	}
}

/// Send an MPP payment directly from source to dest using multiple channels.
#[inline]
fn send_mpp_payment(
	source: &ChanMan, dest: &ChanMan, dest_chan_ids: &[ChannelId], amt: u64,
	payment_secret: PaymentSecret, payment_hash: PaymentHash, payment_id: PaymentId,
) -> bool {
	let num_paths = dest_chan_ids.len();
	if num_paths == 0 {
		return false;
	}

	let amt_per_path = amt / num_paths as u64;
	let mut paths = Vec::with_capacity(num_paths);

	let dest_chans = dest.list_channels();
	let dest_scids = dest_chan_ids.iter().map(|chan_id| {
		dest_chans
			.iter()
			.find(|chan| chan.channel_id == *chan_id)
			.and_then(|chan| chan.short_channel_id)
			.unwrap()
	});

	for (i, dest_scid) in dest_scids.enumerate() {
		let path_amt = if i == num_paths - 1 {
			amt - amt_per_path * (num_paths as u64 - 1)
		} else {
			amt_per_path
		};

		paths.push(Path {
			hops: vec![RouteHop {
				pubkey: dest.get_our_node_id(),
				node_features: dest.node_features(),
				short_channel_id: dest_scid,
				channel_features: dest.channel_features(),
				fee_msat: path_amt,
				cltv_expiry_delta: 200,
				maybe_announced_channel: true,
			}],
			blinded_tail: None,
		});
	}

	let route_params = RouteParameters::from_payment_params_and_value(
		PaymentParameters::from_node_id(dest.get_our_node_id(), TEST_FINAL_CLTV),
		amt,
	);
	let route = Route { paths, route_params: Some(route_params) };
	let onion = RecipientOnionFields::secret_only(payment_secret);
	let res = source.send_payment_with_route(route, payment_hash, onion, payment_id);
	match res {
		Err(_) => false,
		Ok(()) => check_payment_send_events(source, payment_id),
	}
}

/// Send an MPP payment from source to dest via middle node.
/// Supports multiple channels on either or both hops.
#[inline]
fn send_mpp_hop_payment(
	source: &ChanMan, middle: &ChanMan, middle_chan_ids: &[ChannelId], dest: &ChanMan,
	dest_chan_ids: &[ChannelId], amt: u64, payment_secret: PaymentSecret,
	payment_hash: PaymentHash, payment_id: PaymentId,
) -> bool {
	// Create paths by pairing middle_scids with dest_scids
	let num_paths = middle_chan_ids.len().max(dest_chan_ids.len());
	if num_paths == 0 {
		return false;
	}

	let first_hop_fee = 50_000;
	let amt_per_path = amt / num_paths as u64;
	let fee_per_path = first_hop_fee / num_paths as u64;
	let mut paths = Vec::with_capacity(num_paths);

	let middle_chans = middle.list_channels();
	let middle_scids: Vec<_> = middle_chan_ids
		.iter()
		.map(|chan_id| {
			middle_chans
				.iter()
				.find(|chan| chan.channel_id == *chan_id)
				.and_then(|chan| chan.short_channel_id)
				.unwrap()
		})
		.collect();

	let dest_chans = dest.list_channels();
	let dest_scids: Vec<_> = dest_chan_ids
		.iter()
		.map(|chan_id| {
			dest_chans
				.iter()
				.find(|chan| chan.channel_id == *chan_id)
				.and_then(|chan| chan.short_channel_id)
				.unwrap()
		})
		.collect();

	for i in 0..num_paths {
		let middle_scid = middle_scids[i % middle_scids.len()];
		let dest_scid = dest_scids[i % dest_scids.len()];

		let path_amt = if i == num_paths - 1 {
			amt - amt_per_path * (num_paths as u64 - 1)
		} else {
			amt_per_path
		};
		let path_fee = if i == num_paths - 1 {
			first_hop_fee - fee_per_path * (num_paths as u64 - 1)
		} else {
			fee_per_path
		};

		paths.push(Path {
			hops: vec![
				RouteHop {
					pubkey: middle.get_our_node_id(),
					node_features: middle.node_features(),
					short_channel_id: middle_scid,
					channel_features: middle.channel_features(),
					fee_msat: path_fee,
					cltv_expiry_delta: 100,
					maybe_announced_channel: true,
				},
				RouteHop {
					pubkey: dest.get_our_node_id(),
					node_features: dest.node_features(),
					short_channel_id: dest_scid,
					channel_features: dest.channel_features(),
					fee_msat: path_amt,
					cltv_expiry_delta: 200,
					maybe_announced_channel: true,
				},
			],
			blinded_tail: None,
		});
	}

	let route_params = RouteParameters::from_payment_params_and_value(
		PaymentParameters::from_node_id(dest.get_our_node_id(), TEST_FINAL_CLTV),
		amt,
	);
	let route = Route { paths, route_params: Some(route_params) };
	let onion = RecipientOnionFields::secret_only(payment_secret);
	let res = source.send_payment_with_route(route, payment_hash, onion, payment_id);
	match res {
		Err(_) => false,
		Ok(()) => check_payment_send_events(source, payment_id),
	}
}

#[inline]
fn assert_action_timeout_awaiting_response(action: &msgs::ErrorAction) {
	// Since sending/receiving messages may be delayed, `timer_tick_occurred` may cause a node to
	// disconnect their counterparty if they're expecting a timely response.
	assert!(matches!(
		action,
		msgs::ErrorAction::DisconnectPeerWithWarning { msg }
		if msg.data.contains("Disconnecting due to timeout awaiting response")
	));
}

#[inline]
pub fn do_test<Out: Output + MaybeSend + MaybeSync>(
	data: &[u8], underlying_out: Out, anchors: bool,
) {
	let out = SearchingOutput::new(underlying_out);
	let broadcast_a = Arc::new(TestBroadcaster { txn_broadcasted: RefCell::new(Vec::new()) });
	let broadcast_b = Arc::new(TestBroadcaster { txn_broadcasted: RefCell::new(Vec::new()) });
	let broadcast_c = Arc::new(TestBroadcaster { txn_broadcasted: RefCell::new(Vec::new()) });
	let router = FuzzRouter {};

	// Read initial monitor styles from fuzz input (1 byte: 2 bits per node)
	let initial_mon_styles = if !data.is_empty() { data[0] } else { 0 };
	let mon_style = [
		RefCell::new(if initial_mon_styles & 0b01 != 0 {
			ChannelMonitorUpdateStatus::InProgress
		} else {
			ChannelMonitorUpdateStatus::Completed
		}),
		RefCell::new(if initial_mon_styles & 0b10 != 0 {
			ChannelMonitorUpdateStatus::InProgress
		} else {
			ChannelMonitorUpdateStatus::Completed
		}),
		RefCell::new(if initial_mon_styles & 0b100 != 0 {
			ChannelMonitorUpdateStatus::InProgress
		} else {
			ChannelMonitorUpdateStatus::Completed
		}),
	];

	let mut chain_state = ChainState::new();
	let mut node_height_a: u32 = 0;
	let mut node_height_b: u32 = 0;
	let mut node_height_c: u32 = 0;

	macro_rules! make_node {
		($node_id: expr, $fee_estimator: expr, $broadcaster: expr) => {{
			let logger: Arc<dyn Logger + MaybeSend + MaybeSync> =
				Arc::new(test_logger::TestLogger::new($node_id.to_string(), out.clone()));
			let node_secret = SecretKey::from_slice(&[
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 1, $node_id,
			])
			.unwrap();
			let keys_manager = Arc::new(KeyProvider {
				node_secret,
				rand_bytes_id: atomic::AtomicU32::new(0),
				enforcement_states: Mutex::new(new_hash_map()),
			});
			let monitor = Arc::new(TestChainMonitor::new(
				$broadcaster.clone(),
				logger.clone(),
				$fee_estimator.clone(),
				Arc::new(TestPersister {
					update_ret: Mutex::new(mon_style[$node_id as usize].borrow().clone()),
				}),
				Arc::clone(&keys_manager),
			));

			let mut config = UserConfig::default();
			config.channel_config.forwarding_fee_proportional_millionths = 0;
			config.channel_handshake_config.announce_for_forwarding = true;
			config.reject_inbound_splices = false;
			if !anchors {
				config.channel_handshake_config.negotiate_anchors_zero_fee_htlc_tx = false;
			}
			let network = Network::Bitcoin;
			let best_block_timestamp = genesis_block(network).header.time;
			let params = ChainParameters { network, best_block: BestBlock::from_network(network) };
			(
				ChannelManager::new(
					$fee_estimator.clone(),
					monitor.clone(),
					$broadcaster.clone(),
					&router,
					&router,
					Arc::clone(&logger),
					keys_manager.clone(),
					keys_manager.clone(),
					keys_manager.clone(),
					config,
					params,
					best_block_timestamp,
				),
				monitor,
				keys_manager,
				logger,
			)
		}};
	}

	let reload_node = |ser: &Vec<u8>,
	                   node_id: u8,
	                   old_monitors: &TestChainMonitor,
	                   mut use_old_mons,
	                   keys,
	                   fee_estimator,
	                   broadcaster: Arc<TestBroadcaster>| {
		let keys_manager = Arc::clone(keys);
		let logger: Arc<dyn Logger + MaybeSend + MaybeSync> =
			Arc::new(test_logger::TestLogger::new(node_id.to_string(), out.clone()));
		let chain_monitor = Arc::new(TestChainMonitor::new(
			broadcaster.clone(),
			logger.clone(),
			Arc::clone(fee_estimator),
			Arc::new(TestPersister {
				update_ret: Mutex::new(ChannelMonitorUpdateStatus::Completed),
			}),
			Arc::clone(keys),
		));

		let mut config = UserConfig::default();
		config.channel_config.forwarding_fee_proportional_millionths = 0;
		config.channel_handshake_config.announce_for_forwarding = true;
		config.reject_inbound_splices = false;
		if !anchors {
			config.channel_handshake_config.negotiate_anchors_zero_fee_htlc_tx = false;
		}

		let mut monitors = new_hash_map();
		let mut old_monitors = old_monitors.latest_monitors.lock().unwrap();
		for (channel_id, mut prev_state) in old_monitors.drain() {
			let (mon_id, serialized_mon) = if use_old_mons % 3 == 0 {
				// Reload with the oldest `ChannelMonitor` (the one that we already told
				// `ChannelManager` we finished persisting).
				(prev_state.persisted_monitor_id, prev_state.persisted_monitor)
			} else if use_old_mons % 3 == 1 {
				// Reload with the second-oldest `ChannelMonitor`
				let old_mon = (prev_state.persisted_monitor_id, prev_state.persisted_monitor);
				prev_state.pending_monitors.drain(..).next().unwrap_or(old_mon)
			} else {
				// Reload with the newest `ChannelMonitor`
				let old_mon = (prev_state.persisted_monitor_id, prev_state.persisted_monitor);
				prev_state.pending_monitors.pop().unwrap_or(old_mon)
			};
			// Use a different value of `use_old_mons` if we have another monitor (only for node B)
			// by shifting `use_old_mons` one in base-3.
			use_old_mons /= 3;
			let mon = <(BlockHash, ChannelMonitor<TestChannelSigner>)>::read(
				&mut &serialized_mon[..],
				(&**keys, &**keys),
			)
			.expect("Failed to read monitor");
			monitors.insert(channel_id, mon.1);
			// Update the latest `ChannelMonitor` state to match what we just told LDK.
			prev_state.persisted_monitor = serialized_mon;
			prev_state.persisted_monitor_id = mon_id;
			// Wipe any `ChannelMonitor`s which we never told LDK we finished persisting,
			// considering them discarded. LDK should replay these for us as they're stored in
			// the `ChannelManager`.
			prev_state.pending_monitors.clear();
			chain_monitor.latest_monitors.lock().unwrap().insert(channel_id, prev_state);
		}
		let mut monitor_refs = new_hash_map();
		for (channel_id, monitor) in monitors.iter() {
			monitor_refs.insert(*channel_id, monitor);
		}

		let read_args = ChannelManagerReadArgs {
			entropy_source: Arc::clone(&keys_manager),
			node_signer: Arc::clone(&keys_manager),
			signer_provider: keys_manager,
			fee_estimator: Arc::clone(fee_estimator),
			chain_monitor: chain_monitor.clone(),
			tx_broadcaster: broadcaster,
			router: &router,
			message_router: &router,
			logger,
			config,
			channel_monitors: monitor_refs,
		};

		let manager =
			<(BlockHash, ChanMan)>::read(&mut &ser[..], read_args).expect("Failed to read manager");
		let res = (manager.1, chain_monitor.clone());
		for (channel_id, mon) in monitors.drain() {
			assert_eq!(
				chain_monitor.chain_monitor.watch_channel(channel_id, mon),
				Ok(ChannelMonitorUpdateStatus::Completed)
			);
		}
		*chain_monitor.persister.update_ret.lock().unwrap() = *mon_style[node_id as usize].borrow();
		res
	};

	macro_rules! complete_all_pending_monitor_updates {
		($monitor: expr) => {{
			for (channel_id, state) in $monitor.latest_monitors.lock().unwrap().iter_mut() {
				for (id, data) in state.pending_monitors.drain(..) {
					$monitor.chain_monitor.channel_monitor_updated(*channel_id, id).unwrap();
					if id >= state.persisted_monitor_id {
						state.persisted_monitor_id = id;
						state.persisted_monitor = data;
					}
				}
			}
		}};
	}
	macro_rules! connect_peers {
		($source: expr, $dest: expr) => {{
			let init_dest = Init {
				features: $dest.init_features(),
				networks: None,
				remote_network_address: None,
			};
			$source.peer_connected($dest.get_our_node_id(), &init_dest, true).unwrap();
			let init_src = Init {
				features: $source.init_features(),
				networks: None,
				remote_network_address: None,
			};
			$dest.peer_connected($source.get_our_node_id(), &init_src, false).unwrap();
		}};
	}
	macro_rules! make_channel {
		($source: expr, $dest: expr, $source_monitor: expr, $dest_monitor: expr, $dest_keys_manager: expr, $chan_id: expr) => {{
			$source.create_channel($dest.get_our_node_id(), 100_000, 42, 0, None, None).unwrap();
			let open_channel = {
				let events = $source.get_and_clear_pending_msg_events();
				assert_eq!(events.len(), 1);
				if let MessageSendEvent::SendOpenChannel { ref msg, .. } = events[0] {
					msg.clone()
				} else {
					panic!("Wrong event type");
				}
			};

			$dest.handle_open_channel($source.get_our_node_id(), &open_channel);
			let accept_channel = {
				let events = $dest.get_and_clear_pending_events();
				assert_eq!(events.len(), 1);
				if let events::Event::OpenChannelRequest {
					ref temporary_channel_id,
					ref counterparty_node_id,
					..
				} = events[0]
				{
					let mut random_bytes = [0u8; 16];
					random_bytes
						.copy_from_slice(&$dest_keys_manager.get_secure_random_bytes()[..16]);
					let user_channel_id = u128::from_be_bytes(random_bytes);
					$dest
						.accept_inbound_channel(
							temporary_channel_id,
							counterparty_node_id,
							user_channel_id,
							None,
						)
						.unwrap();
				} else {
					panic!("Wrong event type");
				}
				let events = $dest.get_and_clear_pending_msg_events();
				assert_eq!(events.len(), 1);
				if let MessageSendEvent::SendAcceptChannel { ref msg, .. } = events[0] {
					msg.clone()
				} else {
					panic!("Wrong event type");
				}
			};

			$source.handle_accept_channel($dest.get_our_node_id(), &accept_channel);
			{
				let mut events = $source.get_and_clear_pending_events();
				assert_eq!(events.len(), 1);
				if let events::Event::FundingGenerationReady {
					temporary_channel_id,
					channel_value_satoshis,
					output_script,
					..
				} = events.pop().unwrap()
				{
					let tx = Transaction {
						version: Version($chan_id),
						lock_time: LockTime::ZERO,
						input: Vec::new(),
						output: vec![TxOut {
							value: Amount::from_sat(channel_value_satoshis),
							script_pubkey: output_script,
						}],
					};
					$source
						.funding_transaction_generated(
							temporary_channel_id,
							$dest.get_our_node_id(),
							tx.clone(),
						)
						.unwrap();
					chain_state.confirm_tx(tx);
				} else {
					panic!("Wrong event type");
				}
			}

			let funding_created = {
				let events = $source.get_and_clear_pending_msg_events();
				assert_eq!(events.len(), 1);
				if let MessageSendEvent::SendFundingCreated { ref msg, .. } = events[0] {
					msg.clone()
				} else {
					panic!("Wrong event type");
				}
			};
			$dest.handle_funding_created($source.get_our_node_id(), &funding_created);
			// Complete any pending monitor updates for dest after watch_channel
			complete_all_pending_monitor_updates!($dest_monitor);

			let (funding_signed, channel_id) = {
				let events = $dest.get_and_clear_pending_msg_events();
				assert_eq!(events.len(), 1);
				if let MessageSendEvent::SendFundingSigned { ref msg, .. } = events[0] {
					(msg.clone(), msg.channel_id.clone())
				} else {
					panic!("Wrong event type");
				}
			};
			let events = $dest.get_and_clear_pending_events();
			assert_eq!(events.len(), 1);
			if let events::Event::ChannelPending { ref counterparty_node_id, .. } = events[0] {
				assert_eq!(counterparty_node_id, &$source.get_our_node_id());
			} else {
				panic!("Wrong event type");
			}

			$source.handle_funding_signed($dest.get_our_node_id(), &funding_signed);
			// Complete any pending monitor updates for source after watch_channel
			complete_all_pending_monitor_updates!($source_monitor);

			let events = $source.get_and_clear_pending_events();
			assert_eq!(events.len(), 1);
			if let events::Event::ChannelPending {
				ref counterparty_node_id,
				channel_id: ref event_channel_id,
				..
			} = events[0]
			{
				assert_eq!(counterparty_node_id, &$dest.get_our_node_id());
				assert_eq!(*event_channel_id, channel_id);
			} else {
				panic!("Wrong event type");
			}
		}};
	}

	macro_rules! lock_fundings {
		($nodes: expr) => {{
			let mut node_events = Vec::new();
			for node in $nodes.iter() {
				node_events.push(node.get_and_clear_pending_msg_events());
			}
			for (idx, node_event) in node_events.iter().enumerate() {
				for event in node_event {
					if let MessageSendEvent::SendChannelReady { ref node_id, ref msg } = event {
						for node in $nodes.iter() {
							if node.get_our_node_id() == *node_id {
								node.handle_channel_ready($nodes[idx].get_our_node_id(), msg);
							}
						}
					} else {
						panic!("Wrong event type");
					}
				}
			}

			for node in $nodes.iter() {
				let events = node.get_and_clear_pending_msg_events();
				for event in events {
					if let MessageSendEvent::SendAnnouncementSignatures { .. } = event {
					} else {
						panic!("Wrong event type");
					}
				}
			}
		}};
	}

	let wallet_a = TestWalletSource::new(SecretKey::from_slice(&[1; 32]).unwrap());
	let wallet_b = TestWalletSource::new(SecretKey::from_slice(&[2; 32]).unwrap());
	let wallet_c = TestWalletSource::new(SecretKey::from_slice(&[3; 32]).unwrap());

	let wallets = vec![wallet_a, wallet_b, wallet_c];
	let coinbase_tx = bitcoin::Transaction {
		version: bitcoin::transaction::Version::TWO,
		lock_time: bitcoin::absolute::LockTime::ZERO,
		input: vec![bitcoin::TxIn { ..Default::default() }],
		output: wallets
			.iter()
			.map(|w| TxOut {
				value: Amount::from_sat(100_000),
				script_pubkey: w.get_change_script().unwrap(),
			})
			.collect(),
	};
	wallets.iter().enumerate().for_each(|(i, w)| {
		w.add_utxo(coinbase_tx.clone(), i as u32);
	});

	let fee_est_a = Arc::new(FuzzEstimator { ret_val: atomic::AtomicU32::new(253) });
	let mut last_htlc_clear_fee_a = 253;
	let fee_est_b = Arc::new(FuzzEstimator { ret_val: atomic::AtomicU32::new(253) });
	let mut last_htlc_clear_fee_b = 253;
	let fee_est_c = Arc::new(FuzzEstimator { ret_val: atomic::AtomicU32::new(253) });
	let mut last_htlc_clear_fee_c = 253;

	// 3 nodes is enough to hit all the possible cases, notably unknown-source-unknown-dest
	// forwarding.
	let (node_a, mut monitor_a, keys_manager_a, logger_a) = make_node!(0, fee_est_a, broadcast_a);
	let (node_b, mut monitor_b, keys_manager_b, logger_b) = make_node!(1, fee_est_b, broadcast_b);
	let (node_c, mut monitor_c, keys_manager_c, logger_c) = make_node!(2, fee_est_c, broadcast_c);

	let mut nodes = [node_a, node_b, node_c];
	let loggers = [logger_a, logger_b, logger_c];
	let fee_estimators = [Arc::clone(&fee_est_a), Arc::clone(&fee_est_b), Arc::clone(&fee_est_c)];

	// Connect peers first, then create channels
	connect_peers!(nodes[0], nodes[1]);
	connect_peers!(nodes[1], nodes[2]);

	// Create 3 channels between A-B and 3 channels between B-C (6 total).
	//
	// Use version numbers 1-6 to avoid txid collisions under fuzz hashing.
	// Fuzz mode uses XOR-based hashing (all bytes XOR to one byte), and
	// versions 0-5 cause collisions between A-B and B-C channel pairs
	// (e.g., A-B with Version(1) collides with B-C with Version(3)).
	make_channel!(nodes[0], nodes[1], monitor_a, monitor_b, keys_manager_b, 1);
	make_channel!(nodes[0], nodes[1], monitor_a, monitor_b, keys_manager_b, 2);
	make_channel!(nodes[0], nodes[1], monitor_a, monitor_b, keys_manager_b, 3);
	make_channel!(nodes[1], nodes[2], monitor_b, monitor_c, keys_manager_c, 4);
	make_channel!(nodes[1], nodes[2], monitor_b, monitor_c, keys_manager_c, 5);
	make_channel!(nodes[1], nodes[2], monitor_b, monitor_c, keys_manager_c, 6);

	// Wipe the transactions-broadcasted set to make sure we don't broadcast any transactions
	// during normal operation in `test_return`.
	broadcast_a.txn_broadcasted.borrow_mut().clear();
	broadcast_b.txn_broadcasted.borrow_mut().clear();
	broadcast_c.txn_broadcasted.borrow_mut().clear();

	let sync_with_chain_state = |chain_state: &ChainState,
	                             node: &ChannelManager<_, _, _, _, _, _, _, _, _>,
	                             node_height: &mut u32,
	                             num_blocks: Option<u32>| {
		let target_height = if let Some(num_blocks) = num_blocks {
			std::cmp::min(*node_height + num_blocks, chain_state.tip_height())
		} else {
			chain_state.tip_height()
		};

		while *node_height < target_height {
			*node_height += 1;
			let (header, txn) = chain_state.block_at(*node_height);
			let txdata: Vec<_> = txn.iter().enumerate().map(|(i, tx)| (i + 1, tx)).collect();
			if !txdata.is_empty() {
				node.transactions_confirmed(header, &txdata, *node_height);
			}
			node.best_block_updated(header, *node_height);
		}
	};

	// Sync all nodes to tip to lock the funding.
	sync_with_chain_state(&mut chain_state, &nodes[0], &mut node_height_a, None);
	sync_with_chain_state(&mut chain_state, &nodes[1], &mut node_height_b, None);
	sync_with_chain_state(&mut chain_state, &nodes[2], &mut node_height_c, None);

	lock_fundings!(nodes);

	// Get channel IDs for all A-B channels (from node A's perspective)
	let chan_ab_ids = {
		let node_a_chans = nodes[0].list_usable_channels();
		[node_a_chans[0].channel_id, node_a_chans[1].channel_id, node_a_chans[2].channel_id]
	};
	// Get channel IDs for all B-C channels (from node C's perspective)
	let chan_bc_ids = {
		let node_c_chans = nodes[2].list_usable_channels();
		[node_c_chans[0].channel_id, node_c_chans[1].channel_id, node_c_chans[2].channel_id]
	};
	// Keep old names for backward compatibility in existing code
	let chan_a_id = chan_ab_ids[0];
	let chan_b_id = chan_bc_ids[0];

	let mut p_ctr: u64 = 0;

	let mut peers_ab_disconnected = false;
	let mut peers_bc_disconnected = false;
	let mut ab_events = Vec::new();
	let mut ba_events = Vec::new();
	let mut bc_events = Vec::new();
	let mut cb_events = Vec::new();

	let mut node_a_ser = nodes[0].encode();
	let mut node_b_ser = nodes[1].encode();
	let mut node_c_ser = nodes[2].encode();

	let pending_payments = RefCell::new([Vec::new(), Vec::new(), Vec::new()]);
	let resolved_payments = RefCell::new([Vec::new(), Vec::new(), Vec::new()]);

	macro_rules! test_return {
		() => {{
			assert_eq!(nodes[0].list_channels().len(), 3);
			assert_eq!(nodes[1].list_channels().len(), 6);
			assert_eq!(nodes[2].list_channels().len(), 3);

			// All broadcasters should be empty (all broadcast transactions should be handled
			// explicitly).
			assert!(broadcast_a.txn_broadcasted.borrow().is_empty());
			assert!(broadcast_b.txn_broadcasted.borrow().is_empty());
			assert!(broadcast_c.txn_broadcasted.borrow().is_empty());

			return;
		}};
	}

	let mut read_pos = 1; // First byte was consumed for initial mon_style
	macro_rules! get_slice {
		($len: expr) => {{
			let slice_len = $len as usize;
			if data.len() < read_pos + slice_len {
				test_return!();
			}
			read_pos += slice_len;
			&data[read_pos - slice_len..read_pos]
		}};
	}

	let splice_channel = |node: &ChanMan,
	                      counterparty_node_id: &PublicKey,
	                      channel_id: &ChannelId,
	                      f: &dyn Fn(FundingTemplate) -> Result<FundingContribution, ()>,
	                      funding_feerate_sat_per_kw: FeeRate| {
		match node.splice_channel(channel_id, counterparty_node_id, funding_feerate_sat_per_kw) {
			Ok(funding_template) => {
				if let Ok(contribution) = f(funding_template) {
					let _ = node.funding_contributed(
						channel_id,
						counterparty_node_id,
						contribution,
						None,
					);
				}
			},
			Err(e) => {
				assert!(
					matches!(e, APIError::APIMisuseError { ref err } if err.contains("splice")),
					"{:?}",
					e
				);
			},
		}
	};

	let splice_in =
		|node: &ChanMan,
		 counterparty_node_id: &PublicKey,
		 channel_id: &ChannelId,
		 wallet: &WalletSync<&TestWalletSource, Arc<dyn Logger + MaybeSend + MaybeSync>>,
		 funding_feerate_sat_per_kw: FeeRate| {
			splice_channel(
				node,
				counterparty_node_id,
				channel_id,
				&move |funding_template: FundingTemplate| {
					funding_template.splice_in_sync(Amount::from_sat(10_000), wallet)
				},
				funding_feerate_sat_per_kw,
			);
		};

	let splice_out = |node: &ChanMan,
	                  counterparty_node_id: &PublicKey,
	                  channel_id: &ChannelId,
	                  wallet: &TestWalletSource,
	                  logger: Arc<dyn Logger + MaybeSend + MaybeSync>,
	                  funding_feerate_sat_per_kw: FeeRate| {
		// We conditionally splice out `MAX_STD_OUTPUT_DUST_LIMIT_SATOSHIS` only when the node
		// has double the balance required to send a payment upon a `0xff` byte. We do this to
		// ensure there's always liquidity available for a payment to succeed then.
		let outbound_capacity_msat = node
			.list_channels()
			.iter()
			.find(|chan| chan.channel_id == *channel_id)
			.map(|chan| chan.outbound_capacity_msat)
			.unwrap();
		if outbound_capacity_msat < 20_000_000 {
			return;
		}
		splice_channel(
			node,
			counterparty_node_id,
			channel_id,
			&move |funding_template| {
				let outputs = vec![TxOut {
					value: Amount::from_sat(MAX_STD_OUTPUT_DUST_LIMIT_SATOSHIS),
					script_pubkey: wallet.get_change_script().unwrap(),
				}];
				funding_template.splice_out_sync(outputs, &WalletSync::new(wallet, logger.clone()))
			},
			funding_feerate_sat_per_kw,
		);
	};

	loop {
		// Push any events from Node B onto ba_events and bc_events
		macro_rules! push_excess_b_events {
			($excess_events: expr, $expect_drop_node: expr) => { {
				let a_id = nodes[0].get_our_node_id();
				let expect_drop_node: Option<usize> = $expect_drop_node;
				let expect_drop_id = if let Some(id) = expect_drop_node { Some(nodes[id].get_our_node_id()) } else { None };
				for event in $excess_events {
					let push_a = match event {
						MessageSendEvent::UpdateHTLCs { ref node_id, .. } => {
							if Some(*node_id) == expect_drop_id { panic!("peer_disconnected should drop msgs bound for the disconnected peer"); }
							*node_id == a_id
						},
						MessageSendEvent::SendRevokeAndACK { ref node_id, .. } => {
							if Some(*node_id) == expect_drop_id { panic!("peer_disconnected should drop msgs bound for the disconnected peer"); }
							*node_id == a_id
						},
						MessageSendEvent::SendChannelReestablish { ref node_id, .. } => {
							if Some(*node_id) == expect_drop_id { panic!("peer_disconnected should drop msgs bound for the disconnected peer"); }
							*node_id == a_id
						},
						MessageSendEvent::SendStfu { ref node_id, .. } => {
							if Some(*node_id) == expect_drop_id { panic!("peer_disconnected should drop msgs bound for the disconnected peer"); }
							*node_id == a_id
						},
						MessageSendEvent::SendSpliceInit { ref node_id, .. } => {
							if Some(*node_id) == expect_drop_id { panic!("peer_disconnected should drop msgs bound for the disconnected peer"); }
							*node_id == a_id
						},
						MessageSendEvent::SendSpliceAck { ref node_id, .. } => {
							if Some(*node_id) == expect_drop_id { panic!("peer_disconnected should drop msgs bound for the disconnected peer"); }
							*node_id == a_id
						},
						MessageSendEvent::SendSpliceLocked { ref node_id, .. } => {
							if Some(*node_id) == expect_drop_id { panic!("peer_disconnected should drop msgs bound for the disconnected peer"); }
							*node_id == a_id
						},
						MessageSendEvent::SendTxAddInput { ref node_id, .. } => {
							if Some(*node_id) == expect_drop_id { panic!("peer_disconnected should drop msgs bound for the disconnected peer"); }
							*node_id == a_id
						},
						MessageSendEvent::SendTxAddOutput { ref node_id, .. } => {
							if Some(*node_id) == expect_drop_id { panic!("peer_disconnected should drop msgs bound for the disconnected peer"); }
							*node_id == a_id
						},
						MessageSendEvent::SendTxComplete { ref node_id, .. } => {
							if Some(*node_id) == expect_drop_id { panic!("peer_disconnected should drop msgs bound for the disconnected peer"); }
							*node_id == a_id
						},
						MessageSendEvent::SendTxAbort { ref node_id, .. } => {
							if Some(*node_id) == expect_drop_id { panic!("peer_disconnected should drop msgs bound for the disconnected peer"); }
							*node_id == a_id
						},
						MessageSendEvent::SendTxSignatures { ref node_id, .. } => {
							if Some(*node_id) == expect_drop_id { panic!("peer_disconnected should drop msgs bound for the disconnected peer"); }
							*node_id == a_id
						},
						MessageSendEvent::SendChannelReady { .. } => continue,
						MessageSendEvent::SendAnnouncementSignatures { .. } => continue,
						MessageSendEvent::SendChannelUpdate { ref node_id, .. } => {
							if Some(*node_id) == expect_drop_id { panic!("peer_disconnected should drop msgs bound for the disconnected peer"); }
							*node_id == a_id
						},
						MessageSendEvent::HandleError { ref action, ref node_id } => {
							assert_action_timeout_awaiting_response(action);
							if Some(*node_id) == expect_drop_id { panic!("peer_disconnected should drop msgs bound for the disconnected peer"); }
							*node_id == a_id
						},
						_ => panic!("Unhandled message event {:?}", event),
					};
					if push_a { ba_events.push(event); } else { bc_events.push(event); }
				}
			} }
		}

		// While delivering messages, we select across three possible message selection processes
		// to ensure we get as much coverage as possible. See the individual enum variants for more
		// details.
		#[derive(PartialEq)]
		enum ProcessMessages {
			/// Deliver all available messages, including fetching any new messages from
			/// `get_and_clear_pending_msg_events()` (which may have side effects).
			AllMessages,
			/// Call `get_and_clear_pending_msg_events()` first, and then deliver up to one
			/// message (which may already be queued).
			OneMessage,
			/// Deliver up to one already-queued message. This avoids any potential side-effects
			/// of `get_and_clear_pending_msg_events()` (eg freeing the HTLC holding cell), which
			/// provides potentially more coverage.
			OnePendingMessage,
		}

		macro_rules! process_msg_events {
			($node: expr, $corrupt_forward: expr, $limit_events: expr) => { {
				let mut events = if $node == 1 {
					let mut new_events = Vec::new();
					mem::swap(&mut new_events, &mut ba_events);
					new_events.extend_from_slice(&bc_events[..]);
					bc_events.clear();
					new_events
				} else if $node == 0 {
					let mut new_events = Vec::new();
					mem::swap(&mut new_events, &mut ab_events);
					new_events
				} else {
					let mut new_events = Vec::new();
					mem::swap(&mut new_events, &mut cb_events);
					new_events
				};
				let mut new_events = Vec::new();
				if $limit_events != ProcessMessages::OnePendingMessage {
					new_events = nodes[$node].get_and_clear_pending_msg_events();
				}
				let mut had_events = false;
				let mut events_iter = events.drain(..).chain(new_events.drain(..));
				let mut extra_ev = None;
				for event in &mut events_iter {
					had_events = true;
					match event {
						MessageSendEvent::UpdateHTLCs { node_id, channel_id, updates: CommitmentUpdate { update_add_htlcs, update_fail_htlcs, update_fulfill_htlcs, update_fail_malformed_htlcs, update_fee, commitment_signed } } => {
							for (idx, dest) in nodes.iter().enumerate() {
								if dest.get_our_node_id() == node_id {
									for update_add in update_add_htlcs.iter() {
										out.locked_write(format!("Delivering update_add_htlc from node {} to node {}.\n", $node, idx).as_bytes());
										if !$corrupt_forward {
											dest.handle_update_add_htlc(nodes[$node].get_our_node_id(), update_add);
										} else {
											// Corrupt the update_add_htlc message so that its HMAC
											// check will fail and we generate a
											// update_fail_malformed_htlc instead of an
											// update_fail_htlc as we do when we reject a payment.
											let mut msg_ser = update_add.encode();
											msg_ser[1000] ^= 0xff;
											let new_msg = UpdateAddHTLC::read_from_fixed_length_buffer(&mut &msg_ser[..]).unwrap();
											dest.handle_update_add_htlc(nodes[$node].get_our_node_id(), &new_msg);
										}
									}
									let processed_change = !update_add_htlcs.is_empty() || !update_fulfill_htlcs.is_empty() ||
										!update_fail_htlcs.is_empty() || !update_fail_malformed_htlcs.is_empty();
									for update_fulfill in update_fulfill_htlcs {
										out.locked_write(format!("Delivering update_fulfill_htlc from node {} to node {}.\n", $node, idx).as_bytes());
										dest.handle_update_fulfill_htlc(nodes[$node].get_our_node_id(), update_fulfill);
									}
									for update_fail in update_fail_htlcs.iter() {
										out.locked_write(format!("Delivering update_fail_htlc from node {} to node {}.\n", $node, idx).as_bytes());
										dest.handle_update_fail_htlc(nodes[$node].get_our_node_id(), update_fail);
									}
									for update_fail_malformed in update_fail_malformed_htlcs.iter() {
										out.locked_write(format!("Delivering update_fail_malformed_htlc from node {} to node {}.\n", $node, idx).as_bytes());
										dest.handle_update_fail_malformed_htlc(nodes[$node].get_our_node_id(), update_fail_malformed);
									}
									if let Some(msg) = update_fee {
										out.locked_write(format!("Delivering update_fee from node {} to node {}.\n", $node, idx).as_bytes());
										dest.handle_update_fee(nodes[$node].get_our_node_id(), &msg);
									}
									if $limit_events != ProcessMessages::AllMessages && processed_change {
										// If we only want to process some messages, don't deliver the CS until later.
										extra_ev = Some(MessageSendEvent::UpdateHTLCs { node_id, channel_id, updates: CommitmentUpdate {
											update_add_htlcs: Vec::new(),
											update_fail_htlcs: Vec::new(),
											update_fulfill_htlcs: Vec::new(),
											update_fail_malformed_htlcs: Vec::new(),
											update_fee: None,
											commitment_signed
										} });
										break;
									}
									out.locked_write(format!("Delivering commitment_signed from node {} to node {}.\n", $node, idx).as_bytes());
									dest.handle_commitment_signed_batch_test(nodes[$node].get_our_node_id(), &commitment_signed);
									break;
								}
							}
						},
						MessageSendEvent::SendRevokeAndACK { ref node_id, ref msg } => {
							for (idx, dest) in nodes.iter().enumerate() {
								if dest.get_our_node_id() == *node_id {
									out.locked_write(format!("Delivering revoke_and_ack from node {} to node {}.\n", $node, idx).as_bytes());
									dest.handle_revoke_and_ack(nodes[$node].get_our_node_id(), msg);
								}
							}
						},
						MessageSendEvent::SendChannelReestablish { ref node_id, ref msg } => {
							for (idx, dest) in nodes.iter().enumerate() {
								if dest.get_our_node_id() == *node_id {
									out.locked_write(format!("Delivering channel_reestablish from node {} to node {}.\n", $node, idx).as_bytes());
									dest.handle_channel_reestablish(nodes[$node].get_our_node_id(), msg);
								}
							}
						},
						MessageSendEvent::SendStfu { ref node_id, ref msg } => {
							for (idx, dest) in nodes.iter().enumerate() {
								if dest.get_our_node_id() == *node_id {
									out.locked_write(format!("Delivering stfu from node {} to node {}.\n", $node, idx).as_bytes());
									dest.handle_stfu(nodes[$node].get_our_node_id(), msg);
								}
							}
						},
						MessageSendEvent::SendTxAddInput { ref node_id, ref msg } => {
							for (idx, dest) in nodes.iter().enumerate() {
								if dest.get_our_node_id() == *node_id {
									out.locked_write(format!("Delivering tx_add_input from node {} to node {}.\n", $node, idx).as_bytes());
									dest.handle_tx_add_input(nodes[$node].get_our_node_id(), msg);
								}
							}
						},
						MessageSendEvent::SendTxAddOutput { ref node_id, ref msg } => {
							for (idx, dest) in nodes.iter().enumerate() {
								if dest.get_our_node_id() == *node_id {
									out.locked_write(format!("Delivering tx_add_output from node {} to node {}.\n", $node, idx).as_bytes());
									dest.handle_tx_add_output(nodes[$node].get_our_node_id(), msg);
								}
							}
						},
						MessageSendEvent::SendTxRemoveInput { ref node_id, ref msg } => {
							for (idx, dest) in nodes.iter().enumerate() {
								if dest.get_our_node_id() == *node_id {
									out.locked_write(format!("Delivering tx_remove_input from node {} to node {}.\n", $node, idx).as_bytes());
									dest.handle_tx_remove_input(nodes[$node].get_our_node_id(), msg);
								}
							}
						},
						MessageSendEvent::SendTxRemoveOutput { ref node_id, ref msg } => {
							for (idx, dest) in nodes.iter().enumerate() {
								if dest.get_our_node_id() == *node_id {
									out.locked_write(format!("Delivering tx_remove_output from node {} to node {}.\n", $node, idx).as_bytes());
									dest.handle_tx_remove_output(nodes[$node].get_our_node_id(), msg);
								}
							}
						},
						MessageSendEvent::SendTxComplete { ref node_id, ref msg } => {
							for (idx, dest) in nodes.iter().enumerate() {
								if dest.get_our_node_id() == *node_id {
									out.locked_write(format!("Delivering tx_complete from node {} to node {}.\n", $node, idx).as_bytes());
									dest.handle_tx_complete(nodes[$node].get_our_node_id(), msg);
								}
							}
						},
						MessageSendEvent::SendTxAbort { ref node_id, ref msg } => {
							for (idx, dest) in nodes.iter().enumerate() {
								if dest.get_our_node_id() == *node_id {
									out.locked_write(format!("Delivering tx_abort from node {} to node {}.\n", $node, idx).as_bytes());
									dest.handle_tx_abort(nodes[$node].get_our_node_id(), msg);
								}
							}
						},
						MessageSendEvent::SendTxSignatures { ref node_id, ref msg } => {
							for (idx, dest) in nodes.iter().enumerate() {
								if dest.get_our_node_id() == *node_id {
									out.locked_write(format!("Delivering tx_signatures from node {} to node {}.\n", $node, idx).as_bytes());
									dest.handle_tx_signatures(nodes[$node].get_our_node_id(), msg);
								}
							}
						},
						MessageSendEvent::SendSpliceInit { ref node_id, ref msg } => {
							for (idx, dest) in nodes.iter().enumerate() {
								if dest.get_our_node_id() == *node_id {
									out.locked_write(format!("Delivering splice_init from node {} to node {}.\n", $node, idx).as_bytes());
									dest.handle_splice_init(nodes[$node].get_our_node_id(), msg);
								}
							}
						},
						MessageSendEvent::SendSpliceAck { ref node_id, ref msg } => {
							for (idx, dest) in nodes.iter().enumerate() {
								if dest.get_our_node_id() == *node_id {
									out.locked_write(format!("Delivering splice_ack from node {} to node {}.\n", $node, idx).as_bytes());
									dest.handle_splice_ack(nodes[$node].get_our_node_id(), msg);
								}
							}
						},
						MessageSendEvent::SendSpliceLocked { ref node_id, ref msg } => {
							for (idx, dest) in nodes.iter().enumerate() {
								if dest.get_our_node_id() == *node_id {
									out.locked_write(format!("Delivering splice_locked from node {} to node {}.\n", $node, idx).as_bytes());
									dest.handle_splice_locked(nodes[$node].get_our_node_id(), msg);
								}
							}
						},
						MessageSendEvent::HandleError { ref action, .. } => {
							assert_action_timeout_awaiting_response(action);
						},
						MessageSendEvent::SendChannelReady { .. } => {
							// Can be generated as a reestablish response
						},
						MessageSendEvent::SendAnnouncementSignatures { .. } => {
							// Can be generated as a reestablish response
						},
						MessageSendEvent::SendChannelUpdate { .. } => {
							// Can be generated as a reestablish response
						},
						MessageSendEvent::BroadcastChannelUpdate { .. } => {
							// Can be generated as a result of calling `timer_tick_occurred` enough
							// times while peers are disconnected
						},
						_ => if out.may_fail.load(atomic::Ordering::Acquire) {
							return;
						} else {
							panic!("Unhandled message event {:?}", event)
						},
					}
					if $limit_events != ProcessMessages::AllMessages {
						break;
					}
				}
				if $node == 1 {
					push_excess_b_events!(extra_ev.into_iter().chain(events_iter), None);
				} else if $node == 0 {
					if let Some(ev) = extra_ev { ab_events.push(ev); }
					for event in events_iter { ab_events.push(event); }
				} else {
					if let Some(ev) = extra_ev { cb_events.push(ev); }
					for event in events_iter { cb_events.push(event); }
				}
				had_events
			} }
		}

		macro_rules! process_msg_noret {
			($node: expr, $corrupt_forward: expr, $limit_events: expr) => {{
				process_msg_events!($node, $corrupt_forward, $limit_events);
			}};
		}

		macro_rules! drain_msg_events_on_disconnect {
			($counterparty_id: expr) => {{
				if $counterparty_id == 0 {
					for event in nodes[0].get_and_clear_pending_msg_events() {
						match event {
							MessageSendEvent::UpdateHTLCs { .. } => {},
							MessageSendEvent::SendRevokeAndACK { .. } => {},
							MessageSendEvent::SendChannelReestablish { .. } => {},
							MessageSendEvent::SendStfu { .. } => {},
							MessageSendEvent::SendChannelReady { .. } => {},
							MessageSendEvent::SendAnnouncementSignatures { .. } => {},
							MessageSendEvent::SendChannelUpdate { .. } => {},
							MessageSendEvent::HandleError { ref action, .. } => {
								assert_action_timeout_awaiting_response(action);
							},
							_ => {
								if out.may_fail.load(atomic::Ordering::Acquire) {
									return;
								} else {
									panic!("Unhandled message event")
								}
							},
						}
					}
					push_excess_b_events!(
						nodes[1].get_and_clear_pending_msg_events().drain(..),
						Some(0)
					);
					ab_events.clear();
					ba_events.clear();
				} else {
					for event in nodes[2].get_and_clear_pending_msg_events() {
						match event {
							MessageSendEvent::UpdateHTLCs { .. } => {},
							MessageSendEvent::SendRevokeAndACK { .. } => {},
							MessageSendEvent::SendChannelReestablish { .. } => {},
							MessageSendEvent::SendStfu { .. } => {},
							MessageSendEvent::SendChannelReady { .. } => {},
							MessageSendEvent::SendAnnouncementSignatures { .. } => {},
							MessageSendEvent::SendChannelUpdate { .. } => {},
							MessageSendEvent::HandleError { ref action, .. } => {
								assert_action_timeout_awaiting_response(action);
							},
							_ => {
								if out.may_fail.load(atomic::Ordering::Acquire) {
									return;
								} else {
									panic!("Unhandled message event")
								}
							},
						}
					}
					push_excess_b_events!(
						nodes[1].get_and_clear_pending_msg_events().drain(..),
						Some(2)
					);
					bc_events.clear();
					cb_events.clear();
				}
			}};
		}

		macro_rules! process_events {
			($node: expr, $fail: expr) => {{
				// In case we get 256 payments we may have a hash collision, resulting in the
				// second claim/fail call not finding the duplicate-hash HTLC, so we have to
				// deduplicate the calls here.
				let mut claim_set = new_hash_map();
				let mut events = nodes[$node].get_and_clear_pending_events();
				let had_events = !events.is_empty();
				let mut pending_payments = pending_payments.borrow_mut();
				let mut resolved_payments = resolved_payments.borrow_mut();
				for event in events.drain(..) {
					match event {
						events::Event::PaymentClaimable { payment_hash, .. } => {
							if claim_set.insert(payment_hash.0, ()).is_none() {
								if $fail {
									nodes[$node].fail_htlc_backwards(&payment_hash);
								} else {
									nodes[$node].claim_funds(PaymentPreimage(payment_hash.0));
								}
							}
						},
						events::Event::PaymentSent { payment_id, .. } => {
							let sent_id = payment_id.unwrap();
							let idx_opt =
								pending_payments[$node].iter().position(|id| *id == sent_id);
							if let Some(idx) = idx_opt {
								pending_payments[$node].remove(idx);
								resolved_payments[$node].push(sent_id);
							} else {
								assert!(resolved_payments[$node].contains(&sent_id));
							}
						},
						// Even though we don't explicitly send probes, because probes are
						// detected based on hashing the payment hash+preimage, its rather
						// trivial for the fuzzer to build payments that accidentally end up
						// looking like probes.
						events::Event::ProbeSuccessful { payment_id, .. } => {
							let idx_opt =
								pending_payments[$node].iter().position(|id| *id == payment_id);
							if let Some(idx) = idx_opt {
								pending_payments[$node].remove(idx);
								resolved_payments[$node].push(payment_id);
							} else {
								assert!(resolved_payments[$node].contains(&payment_id));
							}
						},
						events::Event::PaymentFailed { payment_id, .. }
						| events::Event::ProbeFailed { payment_id, .. } => {
							let idx_opt =
								pending_payments[$node].iter().position(|id| *id == payment_id);
							if let Some(idx) = idx_opt {
								pending_payments[$node].remove(idx);
								resolved_payments[$node].push(payment_id);
							} else if !resolved_payments[$node].contains(&payment_id) {
								// Payment failed immediately on send, so it was never added to
								// pending_payments. Add it to resolved_payments to track it.
								resolved_payments[$node].push(payment_id);
							}
						},
						events::Event::PaymentClaimed { .. } => {},
						events::Event::PaymentPathSuccessful { .. } => {},
						events::Event::PaymentPathFailed { .. } => {},
						events::Event::PaymentForwarded { .. } if $node == 1 => {},
						events::Event::ChannelReady { .. } => {},
						events::Event::HTLCHandlingFailed { .. } => {},

						events::Event::FundingTransactionReadyForSigning {
							channel_id,
							counterparty_node_id,
							unsigned_transaction,
							..
						} => {
							let signed_tx = wallets[$node].sign_tx(unsigned_transaction).unwrap();
							nodes[$node]
								.funding_transaction_signed(
									&channel_id,
									&counterparty_node_id,
									signed_tx,
								)
								.unwrap();
						},
						events::Event::SplicePending { new_funding_txo, .. } => {
							let broadcaster = match $node {
								0 => &broadcast_a,
								1 => &broadcast_b,
								_ => &broadcast_c,
							};
							let mut txs = broadcaster.txn_broadcasted.borrow_mut();
							assert!(txs.len() >= 1);
							let splice_tx = txs.remove(0);
							assert_eq!(new_funding_txo.txid, splice_tx.compute_txid());
							chain_state.confirm_tx(splice_tx);
						},
						events::Event::SpliceFailed { .. } => {},

						_ => {
							if out.may_fail.load(atomic::Ordering::Acquire) {
								return;
							} else {
								panic!("Unhandled event")
							}
						},
					}
				}
				while nodes[$node].needs_pending_htlc_processing() {
					nodes[$node].process_pending_htlc_forwards();
				}
				had_events
			}};
		}

		macro_rules! process_ev_noret {
			($node: expr, $fail: expr) => {{
				process_events!($node, $fail);
			}};
		}

		let complete_first = |v: &mut Vec<_>| if !v.is_empty() { Some(v.remove(0)) } else { None };
		let complete_second = |v: &mut Vec<_>| if v.len() > 1 { Some(v.remove(1)) } else { None };
		let complete_monitor_update =
			|monitor: &Arc<TestChainMonitor>,
			 chan_funding,
			 compl_selector: &dyn Fn(&mut Vec<(u64, Vec<u8>)>) -> Option<(u64, Vec<u8>)>| {
				if let Some(state) = monitor.latest_monitors.lock().unwrap().get_mut(chan_funding) {
					assert!(
						state.pending_monitors.windows(2).all(|pair| pair[0].0 < pair[1].0),
						"updates should be sorted by id"
					);
					if let Some((id, data)) = compl_selector(&mut state.pending_monitors) {
						monitor.chain_monitor.channel_monitor_updated(*chan_funding, id).unwrap();
						if id > state.persisted_monitor_id {
							state.persisted_monitor_id = id;
							state.persisted_monitor = data;
						}
					}
				}
			};

		let complete_all_monitor_updates = |monitor: &Arc<TestChainMonitor>, chan_id| {
			if let Some(state) = monitor.latest_monitors.lock().unwrap().get_mut(chan_id) {
				assert!(
					state.pending_monitors.windows(2).all(|pair| pair[0].0 < pair[1].0),
					"updates should be sorted by id"
				);
				for (id, data) in state.pending_monitors.drain(..) {
					monitor.chain_monitor.channel_monitor_updated(*chan_id, id).unwrap();
					if id > state.persisted_monitor_id {
						state.persisted_monitor_id = id;
						state.persisted_monitor = data;
					}
				}
			}
		};

		let send =
			|source_idx: usize, dest_idx: usize, dest_chan_id, amt, payment_ctr: &mut u64| {
				let source = &nodes[source_idx];
				let dest = &nodes[dest_idx];
				let (secret, hash) = get_payment_secret_hash(dest, payment_ctr);
				let mut id = PaymentId([0; 32]);
				id.0[0..8].copy_from_slice(&payment_ctr.to_ne_bytes());
				let succeeded = send_payment(source, dest, dest_chan_id, amt, secret, hash, id);
				if succeeded {
					pending_payments.borrow_mut()[source_idx].push(id);
				}
				succeeded
			};
		let send_noret = |source_idx, dest_idx, dest_chan_id, amt, payment_ctr: &mut u64| {
			send(source_idx, dest_idx, dest_chan_id, amt, payment_ctr);
		};

		let send_hop_noret = |source_idx: usize,
		                      middle_idx: usize,
		                      middle_chan_id: ChannelId,
		                      dest_idx: usize,
		                      dest_chan_id: ChannelId,
		                      amt: u64,
		                      payment_ctr: &mut u64| {
			let source = &nodes[source_idx];
			let middle = &nodes[middle_idx];
			let dest = &nodes[dest_idx];
			let (secret, hash) = get_payment_secret_hash(dest, payment_ctr);
			let mut id = PaymentId([0; 32]);
			id.0[0..8].copy_from_slice(&payment_ctr.to_ne_bytes());
			let succeeded = send_hop_payment(
				source,
				middle,
				middle_chan_id,
				dest,
				dest_chan_id,
				amt,
				secret,
				hash,
				id,
			);
			if succeeded {
				pending_payments.borrow_mut()[source_idx].push(id);
			}
		};

		// Direct MPP payment (no hop)
		let send_mpp_direct = |source_idx: usize,
		                       dest_idx: usize,
		                       dest_chan_ids: &[ChannelId],
		                       amt: u64,
		                       payment_ctr: &mut u64| {
			let source = &nodes[source_idx];
			let dest = &nodes[dest_idx];
			let (secret, hash) = get_payment_secret_hash(dest, payment_ctr);
			let mut id = PaymentId([0; 32]);
			id.0[0..8].copy_from_slice(&payment_ctr.to_ne_bytes());
			let succeeded = send_mpp_payment(source, dest, dest_chan_ids, amt, secret, hash, id);
			if succeeded {
				pending_payments.borrow_mut()[source_idx].push(id);
			}
		};

		// MPP payment via hop - splits payment across multiple channels on either or both hops
		let send_mpp_hop = |source_idx: usize,
		                    middle_idx: usize,
		                    middle_chan_ids: &[ChannelId],
		                    dest_idx: usize,
		                    dest_chan_ids: &[ChannelId],
		                    amt: u64,
		                    payment_ctr: &mut u64| {
			let source = &nodes[source_idx];
			let middle = &nodes[middle_idx];
			let dest = &nodes[dest_idx];
			let (secret, hash) = get_payment_secret_hash(dest, payment_ctr);
			let mut id = PaymentId([0; 32]);
			id.0[0..8].copy_from_slice(&payment_ctr.to_ne_bytes());
			let succeeded = send_mpp_hop_payment(
				source,
				middle,
				middle_chan_ids,
				dest,
				dest_chan_ids,
				amt,
				secret,
				hash,
				id,
			);
			if succeeded {
				pending_payments.borrow_mut()[source_idx].push(id);
			}
		};

		let v = get_slice!(1)[0];
		out.locked_write(format!("READ A BYTE! HANDLING INPUT {:x}...........\n", v).as_bytes());
		match v {
			// In general, we keep related message groups close together in binary form, allowing
			// bit-twiddling mutations to have similar effects. This is probably overkill, but no
			// harm in doing so.
			0x00 => {
				*mon_style[0].borrow_mut() = ChannelMonitorUpdateStatus::InProgress;
			},
			0x01 => {
				*mon_style[1].borrow_mut() = ChannelMonitorUpdateStatus::InProgress;
			},
			0x02 => {
				*mon_style[2].borrow_mut() = ChannelMonitorUpdateStatus::InProgress;
			},
			0x04 => {
				*mon_style[0].borrow_mut() = ChannelMonitorUpdateStatus::Completed;
			},
			0x05 => {
				*mon_style[1].borrow_mut() = ChannelMonitorUpdateStatus::Completed;
			},
			0x06 => {
				*mon_style[2].borrow_mut() = ChannelMonitorUpdateStatus::Completed;
			},

			0x08 => {
				for id in &chan_ab_ids {
					complete_all_monitor_updates(&monitor_a, id);
				}
			},
			0x09 => {
				for id in &chan_ab_ids {
					complete_all_monitor_updates(&monitor_b, id);
				}
			},
			0x0a => {
				for id in &chan_bc_ids {
					complete_all_monitor_updates(&monitor_b, id);
				}
			},
			0x0b => {
				for id in &chan_bc_ids {
					complete_all_monitor_updates(&monitor_c, id);
				}
			},

			0x0c => {
				if !peers_ab_disconnected {
					nodes[0].peer_disconnected(nodes[1].get_our_node_id());
					nodes[1].peer_disconnected(nodes[0].get_our_node_id());
					peers_ab_disconnected = true;
					drain_msg_events_on_disconnect!(0);
				}
			},
			0x0d => {
				if !peers_bc_disconnected {
					nodes[1].peer_disconnected(nodes[2].get_our_node_id());
					nodes[2].peer_disconnected(nodes[1].get_our_node_id());
					peers_bc_disconnected = true;
					drain_msg_events_on_disconnect!(2);
				}
			},
			0x0e => {
				if peers_ab_disconnected {
					let init_1 = Init {
						features: nodes[1].init_features(),
						networks: None,
						remote_network_address: None,
					};
					nodes[0].peer_connected(nodes[1].get_our_node_id(), &init_1, true).unwrap();
					let init_0 = Init {
						features: nodes[0].init_features(),
						networks: None,
						remote_network_address: None,
					};
					nodes[1].peer_connected(nodes[0].get_our_node_id(), &init_0, false).unwrap();
					peers_ab_disconnected = false;
				}
			},
			0x0f => {
				if peers_bc_disconnected {
					let init_2 = Init {
						features: nodes[2].init_features(),
						networks: None,
						remote_network_address: None,
					};
					nodes[1].peer_connected(nodes[2].get_our_node_id(), &init_2, true).unwrap();
					let init_1 = Init {
						features: nodes[1].init_features(),
						networks: None,
						remote_network_address: None,
					};
					nodes[2].peer_connected(nodes[1].get_our_node_id(), &init_1, false).unwrap();
					peers_bc_disconnected = false;
				}
			},

			0x10 => process_msg_noret!(0, true, ProcessMessages::AllMessages),
			0x11 => process_msg_noret!(0, false, ProcessMessages::AllMessages),
			0x12 => process_msg_noret!(0, true, ProcessMessages::OneMessage),
			0x13 => process_msg_noret!(0, false, ProcessMessages::OneMessage),
			0x14 => process_msg_noret!(0, true, ProcessMessages::OnePendingMessage),
			0x15 => process_msg_noret!(0, false, ProcessMessages::OnePendingMessage),

			0x16 => process_ev_noret!(0, true),
			0x17 => process_ev_noret!(0, false),

			0x18 => process_msg_noret!(1, true, ProcessMessages::AllMessages),
			0x19 => process_msg_noret!(1, false, ProcessMessages::AllMessages),
			0x1a => process_msg_noret!(1, true, ProcessMessages::OneMessage),
			0x1b => process_msg_noret!(1, false, ProcessMessages::OneMessage),
			0x1c => process_msg_noret!(1, true, ProcessMessages::OnePendingMessage),
			0x1d => process_msg_noret!(1, false, ProcessMessages::OnePendingMessage),

			0x1e => process_ev_noret!(1, true),
			0x1f => process_ev_noret!(1, false),

			0x20 => process_msg_noret!(2, true, ProcessMessages::AllMessages),
			0x21 => process_msg_noret!(2, false, ProcessMessages::AllMessages),
			0x22 => process_msg_noret!(2, true, ProcessMessages::OneMessage),
			0x23 => process_msg_noret!(2, false, ProcessMessages::OneMessage),
			0x24 => process_msg_noret!(2, true, ProcessMessages::OnePendingMessage),
			0x25 => process_msg_noret!(2, false, ProcessMessages::OnePendingMessage),

			0x26 => process_ev_noret!(2, true),
			0x27 => process_ev_noret!(2, false),

			// 1/10th the channel size:
			0x30 => send_noret(0, 1, chan_a_id, 10_000_000, &mut p_ctr),
			0x31 => send_noret(1, 0, chan_a_id, 10_000_000, &mut p_ctr),
			0x32 => send_noret(1, 2, chan_b_id, 10_000_000, &mut p_ctr),
			0x33 => send_noret(2, 1, chan_b_id, 10_000_000, &mut p_ctr),
			0x34 => send_hop_noret(0, 1, chan_a_id, 2, chan_b_id, 10_000_000, &mut p_ctr),
			0x35 => send_hop_noret(2, 1, chan_b_id, 0, chan_a_id, 10_000_000, &mut p_ctr),

			0x38 => send_noret(0, 1, chan_a_id, 1_000_000, &mut p_ctr),
			0x39 => send_noret(1, 0, chan_a_id, 1_000_000, &mut p_ctr),
			0x3a => send_noret(1, 2, chan_b_id, 1_000_000, &mut p_ctr),
			0x3b => send_noret(2, 1, chan_b_id, 1_000_000, &mut p_ctr),
			0x3c => send_hop_noret(0, 1, chan_a_id, 2, chan_b_id, 1_000_000, &mut p_ctr),
			0x3d => send_hop_noret(2, 1, chan_b_id, 0, chan_a_id, 1_000_000, &mut p_ctr),

			0x40 => send_noret(0, 1, chan_a_id, 100_000, &mut p_ctr),
			0x41 => send_noret(1, 0, chan_a_id, 100_000, &mut p_ctr),
			0x42 => send_noret(1, 2, chan_b_id, 100_000, &mut p_ctr),
			0x43 => send_noret(2, 1, chan_b_id, 100_000, &mut p_ctr),
			0x44 => send_hop_noret(0, 1, chan_a_id, 2, chan_b_id, 100_000, &mut p_ctr),
			0x45 => send_hop_noret(2, 1, chan_b_id, 0, chan_a_id, 100_000, &mut p_ctr),

			0x48 => send_noret(0, 1, chan_a_id, 10_000, &mut p_ctr),
			0x49 => send_noret(1, 0, chan_a_id, 10_000, &mut p_ctr),
			0x4a => send_noret(1, 2, chan_b_id, 10_000, &mut p_ctr),
			0x4b => send_noret(2, 1, chan_b_id, 10_000, &mut p_ctr),
			0x4c => send_hop_noret(0, 1, chan_a_id, 2, chan_b_id, 10_000, &mut p_ctr),
			0x4d => send_hop_noret(2, 1, chan_b_id, 0, chan_a_id, 10_000, &mut p_ctr),

			0x50 => send_noret(0, 1, chan_a_id, 1_000, &mut p_ctr),
			0x51 => send_noret(1, 0, chan_a_id, 1_000, &mut p_ctr),
			0x52 => send_noret(1, 2, chan_b_id, 1_000, &mut p_ctr),
			0x53 => send_noret(2, 1, chan_b_id, 1_000, &mut p_ctr),
			0x54 => send_hop_noret(0, 1, chan_a_id, 2, chan_b_id, 1_000, &mut p_ctr),
			0x55 => send_hop_noret(2, 1, chan_b_id, 0, chan_a_id, 1_000, &mut p_ctr),

			0x58 => send_noret(0, 1, chan_a_id, 100, &mut p_ctr),
			0x59 => send_noret(1, 0, chan_a_id, 100, &mut p_ctr),
			0x5a => send_noret(1, 2, chan_b_id, 100, &mut p_ctr),
			0x5b => send_noret(2, 1, chan_b_id, 100, &mut p_ctr),
			0x5c => send_hop_noret(0, 1, chan_a_id, 2, chan_b_id, 100, &mut p_ctr),
			0x5d => send_hop_noret(2, 1, chan_b_id, 0, chan_a_id, 100, &mut p_ctr),

			0x60 => send_noret(0, 1, chan_a_id, 10, &mut p_ctr),
			0x61 => send_noret(1, 0, chan_a_id, 10, &mut p_ctr),
			0x62 => send_noret(1, 2, chan_b_id, 10, &mut p_ctr),
			0x63 => send_noret(2, 1, chan_b_id, 10, &mut p_ctr),
			0x64 => send_hop_noret(0, 1, chan_a_id, 2, chan_b_id, 10, &mut p_ctr),
			0x65 => send_hop_noret(2, 1, chan_b_id, 0, chan_a_id, 10, &mut p_ctr),

			0x68 => send_noret(0, 1, chan_a_id, 1, &mut p_ctr),
			0x69 => send_noret(1, 0, chan_a_id, 1, &mut p_ctr),
			0x6a => send_noret(1, 2, chan_b_id, 1, &mut p_ctr),
			0x6b => send_noret(2, 1, chan_b_id, 1, &mut p_ctr),
			0x6c => send_hop_noret(0, 1, chan_a_id, 2, chan_b_id, 1, &mut p_ctr),
			0x6d => send_hop_noret(2, 1, chan_b_id, 0, chan_a_id, 1, &mut p_ctr),

			// MPP payments
			// 0x70: direct MPP from 0 to 1 (multi A-B channels)
			0x70 => send_mpp_direct(0, 1, &chan_ab_ids, 1_000_000, &mut p_ctr),
			// 0x71: MPP 0->1->2, multi channels on first hop (A-B)
			0x71 => send_mpp_hop(0, 1, &chan_ab_ids, 2, &[chan_b_id], 1_000_000, &mut p_ctr),
			// 0x72: MPP 0->1->2, multi channels on both hops (A-B and B-C)
			0x72 => send_mpp_hop(0, 1, &chan_ab_ids, 2, &chan_bc_ids, 1_000_000, &mut p_ctr),
			// 0x73: MPP 0->1->2, multi channels on second hop (B-C)
			0x73 => send_mpp_hop(0, 1, &[chan_a_id], 2, &chan_bc_ids, 1_000_000, &mut p_ctr),
			// 0x74: direct MPP from 0 to 1, multi parts over single channel
			0x74 => {
				send_mpp_direct(0, 1, &[chan_a_id, chan_a_id, chan_a_id], 1_000_000, &mut p_ctr)
			},

			0x80 => {
				let mut max_feerate = last_htlc_clear_fee_a;
				if !anchors {
					max_feerate *= FEE_SPIKE_BUFFER_FEE_INCREASE_MULTIPLE as u32;
				}
				if fee_est_a.ret_val.fetch_add(250, atomic::Ordering::AcqRel) + 250 > max_feerate {
					fee_est_a.ret_val.store(max_feerate, atomic::Ordering::Release);
				}
				nodes[0].timer_tick_occurred();
			},
			0x81 => {
				fee_est_a.ret_val.store(253, atomic::Ordering::Release);
				nodes[0].timer_tick_occurred();
			},

			0x84 => {
				let mut max_feerate = last_htlc_clear_fee_b;
				if !anchors {
					max_feerate *= FEE_SPIKE_BUFFER_FEE_INCREASE_MULTIPLE as u32;
				}
				if fee_est_b.ret_val.fetch_add(250, atomic::Ordering::AcqRel) + 250 > max_feerate {
					fee_est_b.ret_val.store(max_feerate, atomic::Ordering::Release);
				}
				nodes[1].timer_tick_occurred();
			},
			0x85 => {
				fee_est_b.ret_val.store(253, atomic::Ordering::Release);
				nodes[1].timer_tick_occurred();
			},

			0x88 => {
				let mut max_feerate = last_htlc_clear_fee_c;
				if !anchors {
					max_feerate *= FEE_SPIKE_BUFFER_FEE_INCREASE_MULTIPLE as u32;
				}
				if fee_est_c.ret_val.fetch_add(250, atomic::Ordering::AcqRel) + 250 > max_feerate {
					fee_est_c.ret_val.store(max_feerate, atomic::Ordering::Release);
				}
				nodes[2].timer_tick_occurred();
			},
			0x89 => {
				fee_est_c.ret_val.store(253, atomic::Ordering::Release);
				nodes[2].timer_tick_occurred();
			},

			0xa0 => {
				let cp_node_id = nodes[1].get_our_node_id();
				let wallet = WalletSync::new(&wallets[0], Arc::clone(&loggers[0]));
				let feerate_sat_per_kw = fee_estimators[0].feerate_sat_per_kw();
				splice_in(&nodes[0], &cp_node_id, &chan_a_id, &wallet, feerate_sat_per_kw);
			},
			0xa1 => {
				let cp_node_id = nodes[0].get_our_node_id();
				let wallet = WalletSync::new(&wallets[1], Arc::clone(&loggers[1]));
				let feerate_sat_per_kw = fee_estimators[1].feerate_sat_per_kw();
				splice_in(&nodes[1], &cp_node_id, &chan_a_id, &wallet, feerate_sat_per_kw);
			},
			0xa2 => {
				let cp_node_id = nodes[2].get_our_node_id();
				let wallet = WalletSync::new(&wallets[1], Arc::clone(&loggers[1]));
				let feerate_sat_per_kw = fee_estimators[1].feerate_sat_per_kw();
				splice_in(&nodes[1], &cp_node_id, &chan_b_id, &wallet, feerate_sat_per_kw);
			},
			0xa3 => {
				let cp_node_id = nodes[1].get_our_node_id();
				let wallet = WalletSync::new(&wallets[2], Arc::clone(&loggers[2]));
				let feerate_sat_per_kw = fee_estimators[2].feerate_sat_per_kw();
				splice_in(&nodes[2], &cp_node_id, &chan_b_id, &wallet, feerate_sat_per_kw);
			},

			0xa4 => {
				let cp_node_id = nodes[1].get_our_node_id();
				let wallet = &wallets[0];
				let logger = Arc::clone(&loggers[0]);
				let feerate_sat_per_kw = fee_estimators[0].feerate_sat_per_kw();
				splice_out(&nodes[0], &cp_node_id, &chan_a_id, wallet, logger, feerate_sat_per_kw);
			},
			0xa5 => {
				let cp_node_id = nodes[0].get_our_node_id();
				let wallet = &wallets[1];
				let logger = Arc::clone(&loggers[1]);
				let feerate_sat_per_kw = fee_estimators[1].feerate_sat_per_kw();
				splice_out(&nodes[1], &cp_node_id, &chan_a_id, wallet, logger, feerate_sat_per_kw);
			},
			0xa6 => {
				let cp_node_id = nodes[2].get_our_node_id();
				let wallet = &wallets[1];
				let logger = Arc::clone(&loggers[1]);
				let feerate_sat_per_kw = fee_estimators[1].feerate_sat_per_kw();
				splice_out(&nodes[1], &cp_node_id, &chan_b_id, wallet, logger, feerate_sat_per_kw);
			},
			0xa7 => {
				let cp_node_id = nodes[1].get_our_node_id();
				let wallet = &wallets[2];
				let logger = Arc::clone(&loggers[2]);
				let feerate_sat_per_kw = fee_estimators[2].feerate_sat_per_kw();
				splice_out(&nodes[2], &cp_node_id, &chan_b_id, wallet, logger, feerate_sat_per_kw);
			},

			// Sync node by 1 block to cover confirmation of a transaction.
			0xa8 => sync_with_chain_state(&mut chain_state, &nodes[0], &mut node_height_a, Some(1)),
			0xa9 => sync_with_chain_state(&mut chain_state, &nodes[1], &mut node_height_b, Some(1)),
			0xaa => sync_with_chain_state(&mut chain_state, &nodes[2], &mut node_height_c, Some(1)),
			// Sync node to chain tip to cover confirmation of a transaction post-reorg-risk.
			0xab => sync_with_chain_state(&mut chain_state, &nodes[0], &mut node_height_a, None),
			0xac => sync_with_chain_state(&mut chain_state, &nodes[1], &mut node_height_b, None),
			0xad => sync_with_chain_state(&mut chain_state, &nodes[2], &mut node_height_c, None),

			0xb0 | 0xb1 | 0xb2 => {
				// Restart node A, picking among the in-flight `ChannelMonitor`s to use based on
				// the value of `v` we're matching.
				if !peers_ab_disconnected {
					nodes[1].peer_disconnected(nodes[0].get_our_node_id());
					peers_ab_disconnected = true;
					push_excess_b_events!(
						nodes[1].get_and_clear_pending_msg_events().drain(..),
						Some(0)
					);
					ab_events.clear();
					ba_events.clear();
				}
				let (new_node_a, new_monitor_a) = reload_node(
					&node_a_ser,
					0,
					&monitor_a,
					v,
					&keys_manager_a,
					&fee_est_a,
					broadcast_a.clone(),
				);
				nodes[0] = new_node_a;
				monitor_a = new_monitor_a;
			},
			0xb3..=0xbb => {
				// Restart node B, picking among the in-flight `ChannelMonitor`s to use based on
				// the value of `v` we're matching.
				if !peers_ab_disconnected {
					nodes[0].peer_disconnected(nodes[1].get_our_node_id());
					peers_ab_disconnected = true;
					nodes[0].get_and_clear_pending_msg_events();
					ab_events.clear();
					ba_events.clear();
				}
				if !peers_bc_disconnected {
					nodes[2].peer_disconnected(nodes[1].get_our_node_id());
					peers_bc_disconnected = true;
					nodes[2].get_and_clear_pending_msg_events();
					bc_events.clear();
					cb_events.clear();
				}
				let (new_node_b, new_monitor_b) = reload_node(
					&node_b_ser,
					1,
					&monitor_b,
					v,
					&keys_manager_b,
					&fee_est_b,
					broadcast_b.clone(),
				);
				nodes[1] = new_node_b;
				monitor_b = new_monitor_b;
			},
			0xbc | 0xbd | 0xbe => {
				// Restart node C, picking among the in-flight `ChannelMonitor`s to use based on
				// the value of `v` we're matching.
				if !peers_bc_disconnected {
					nodes[1].peer_disconnected(nodes[2].get_our_node_id());
					peers_bc_disconnected = true;
					push_excess_b_events!(
						nodes[1].get_and_clear_pending_msg_events().drain(..),
						Some(2)
					);
					bc_events.clear();
					cb_events.clear();
				}
				let (new_node_c, new_monitor_c) = reload_node(
					&node_c_ser,
					2,
					&monitor_c,
					v,
					&keys_manager_c,
					&fee_est_c,
					broadcast_c.clone(),
				);
				nodes[2] = new_node_c;
				monitor_c = new_monitor_c;
			},

			0xc0 => keys_manager_a.disable_supported_ops_for_all_signers(),
			0xc1 => keys_manager_b.disable_supported_ops_for_all_signers(),
			0xc2 => keys_manager_c.disable_supported_ops_for_all_signers(),
			0xc3 => {
				keys_manager_a.enable_op_for_all_signers(SignerOp::SignCounterpartyCommitment);
				nodes[0].signer_unblocked(None);
			},
			0xc4 => {
				keys_manager_b.enable_op_for_all_signers(SignerOp::SignCounterpartyCommitment);
				nodes[1].signer_unblocked(None);
			},
			0xc5 => {
				keys_manager_c.enable_op_for_all_signers(SignerOp::SignCounterpartyCommitment);
				nodes[2].signer_unblocked(None);
			},
			0xc6 => {
				keys_manager_a.enable_op_for_all_signers(SignerOp::GetPerCommitmentPoint);
				nodes[0].signer_unblocked(None);
			},
			0xc7 => {
				keys_manager_b.enable_op_for_all_signers(SignerOp::GetPerCommitmentPoint);
				nodes[1].signer_unblocked(None);
			},
			0xc8 => {
				keys_manager_c.enable_op_for_all_signers(SignerOp::GetPerCommitmentPoint);
				nodes[2].signer_unblocked(None);
			},
			0xc9 => {
				keys_manager_a.enable_op_for_all_signers(SignerOp::ReleaseCommitmentSecret);
				nodes[0].signer_unblocked(None);
			},
			0xca => {
				keys_manager_b.enable_op_for_all_signers(SignerOp::ReleaseCommitmentSecret);
				nodes[1].signer_unblocked(None);
			},
			0xcb => {
				keys_manager_c.enable_op_for_all_signers(SignerOp::ReleaseCommitmentSecret);
				nodes[2].signer_unblocked(None);
			},

			0xf0 => {
				for id in &chan_ab_ids {
					complete_monitor_update(&monitor_a, id, &complete_first);
				}
			},
			0xf1 => {
				for id in &chan_ab_ids {
					complete_monitor_update(&monitor_a, id, &complete_second);
				}
			},
			0xf2 => {
				for id in &chan_ab_ids {
					complete_monitor_update(&monitor_a, id, &Vec::pop);
				}
			},

			0xf4 => {
				for id in &chan_ab_ids {
					complete_monitor_update(&monitor_b, id, &complete_first);
				}
			},
			0xf5 => {
				for id in &chan_ab_ids {
					complete_monitor_update(&monitor_b, id, &complete_second);
				}
			},
			0xf6 => {
				for id in &chan_ab_ids {
					complete_monitor_update(&monitor_b, id, &Vec::pop);
				}
			},

			0xf8 => {
				for id in &chan_bc_ids {
					complete_monitor_update(&monitor_b, id, &complete_first);
				}
			},
			0xf9 => {
				for id in &chan_bc_ids {
					complete_monitor_update(&monitor_b, id, &complete_second);
				}
			},
			0xfa => {
				for id in &chan_bc_ids {
					complete_monitor_update(&monitor_b, id, &Vec::pop);
				}
			},

			0xfc => {
				for id in &chan_bc_ids {
					complete_monitor_update(&monitor_c, id, &complete_first);
				}
			},
			0xfd => {
				for id in &chan_bc_ids {
					complete_monitor_update(&monitor_c, id, &complete_second);
				}
			},
			0xfe => {
				for id in &chan_bc_ids {
					complete_monitor_update(&monitor_c, id, &Vec::pop);
				}
			},

			0xff => {
				// Test that no channel is in a stuck state where neither party can send funds even
				// after we resolve all pending events.

				// First, make sure peers are all connected to each other
				if peers_ab_disconnected {
					let init_1 = Init {
						features: nodes[1].init_features(),
						networks: None,
						remote_network_address: None,
					};
					nodes[0].peer_connected(nodes[1].get_our_node_id(), &init_1, true).unwrap();
					let init_0 = Init {
						features: nodes[0].init_features(),
						networks: None,
						remote_network_address: None,
					};
					nodes[1].peer_connected(nodes[0].get_our_node_id(), &init_0, false).unwrap();
					peers_ab_disconnected = false;
				}
				if peers_bc_disconnected {
					let init_2 = Init {
						features: nodes[2].init_features(),
						networks: None,
						remote_network_address: None,
					};
					nodes[1].peer_connected(nodes[2].get_our_node_id(), &init_2, true).unwrap();
					let init_1 = Init {
						features: nodes[1].init_features(),
						networks: None,
						remote_network_address: None,
					};
					nodes[2].peer_connected(nodes[1].get_our_node_id(), &init_1, false).unwrap();
					peers_bc_disconnected = false;
				}

				for op in SUPPORTED_SIGNER_OPS {
					keys_manager_a.enable_op_for_all_signers(op);
					keys_manager_b.enable_op_for_all_signers(op);
					keys_manager_c.enable_op_for_all_signers(op);
				}
				nodes[0].signer_unblocked(None);
				nodes[1].signer_unblocked(None);
				nodes[2].signer_unblocked(None);

				macro_rules! process_all_events {
					() => { {
						let mut last_pass_no_updates = false;
						for i in 0..std::usize::MAX {
							if i == 100 {
								panic!("It may take may iterations to settle the state, but it should not take forever");
							}
							// Next, make sure no monitor updates are pending
							for id in &chan_ab_ids {
								complete_all_monitor_updates(&monitor_a, id);
								complete_all_monitor_updates(&monitor_b, id);
							}
							for id in &chan_bc_ids {
								complete_all_monitor_updates(&monitor_b, id);
								complete_all_monitor_updates(&monitor_c, id);
							}
							// Then, make sure any current forwards make their way to their destination
							if process_msg_events!(0, false, ProcessMessages::AllMessages) {
								last_pass_no_updates = false;
								continue;
							}
							if process_msg_events!(1, false, ProcessMessages::AllMessages) {
								last_pass_no_updates = false;
								continue;
							}
							if process_msg_events!(2, false, ProcessMessages::AllMessages) {
								last_pass_no_updates = false;
								continue;
							}
							// ...making sure any payments are claimed.
							if process_events!(0, false) {
								last_pass_no_updates = false;
								continue;
							}
							if process_events!(1, false) {
								last_pass_no_updates = false;
								continue;
							}
							if process_events!(2, false) {
								last_pass_no_updates = false;
								continue;
							}
							if last_pass_no_updates {
								// In some cases, we may generate a message to send in
								// `process_msg_events`, but block sending until
								// `complete_all_monitor_updates` gets called on the next
								// iteration.
								//
								// Thus, we only exit if we manage two iterations with no messages
								// or events to process.
								break;
							}
							last_pass_no_updates = true;
						}
					} };
				}

				process_all_events!();

				// Since MPP payments are supported, we wait until we fully settle the state of all
				// channels to see if we have any committed HTLC parts of an MPP payment that need
				// to be failed back.
				for node in &nodes {
					node.timer_tick_occurred();
				}
				process_all_events!();

				// Verify no payments are stuck - all should have resolved
				for (idx, pending) in pending_payments.borrow().iter().enumerate() {
					assert!(
						pending.is_empty(),
						"Node {} has {} stuck pending payments after settling all state",
						idx,
						pending.len()
					);
				}

				// Finally, make sure that at least one end of each channel can make a substantial payment
				for &chan_id in &chan_ab_ids {
					assert!(
						send(0, 1, chan_id, 10_000_000, &mut p_ctr)
							|| send(1, 0, chan_id, 10_000_000, &mut p_ctr)
					);
				}
				for &chan_id in &chan_bc_ids {
					assert!(
						send(1, 2, chan_id, 10_000_000, &mut p_ctr)
							|| send(2, 1, chan_id, 10_000_000, &mut p_ctr)
					);
				}

				last_htlc_clear_fee_a = fee_est_a.ret_val.load(atomic::Ordering::Acquire);
				last_htlc_clear_fee_b = fee_est_b.ret_val.load(atomic::Ordering::Acquire);
				last_htlc_clear_fee_c = fee_est_c.ret_val.load(atomic::Ordering::Acquire);
			},
			_ => test_return!(),
		}

		if nodes[0].get_and_clear_needs_persistence() == true {
			node_a_ser = nodes[0].encode();
		}
		if nodes[1].get_and_clear_needs_persistence() == true {
			node_b_ser = nodes[1].encode();
		}
		if nodes[2].get_and_clear_needs_persistence() == true {
			node_c_ser = nodes[2].encode();
		}
	}
}

/// We actually have different behavior based on if a certain log string has been seen, so we have
/// to do a bit more tracking.
#[derive(Clone)]
struct SearchingOutput<O: Output> {
	output: O,
	may_fail: Arc<atomic::AtomicBool>,
}
impl<O: Output> Output for SearchingOutput<O> {
	fn locked_write(&self, data: &[u8]) {
		// We hit a design limitation of LN state machine (see CONCURRENT_INBOUND_HTLC_FEE_BUFFER)
		if std::str::from_utf8(data).unwrap().contains("Outbound update_fee HTLC buffer overflow - counterparty should force-close this channel") {
			self.may_fail.store(true, atomic::Ordering::Release);
		}
		self.output.locked_write(data)
	}
}
impl<O: Output> SearchingOutput<O> {
	pub fn new(output: O) -> Self {
		Self { output, may_fail: Arc::new(atomic::AtomicBool::new(false)) }
	}
}

pub fn chanmon_consistency_test<Out: Output + MaybeSend + MaybeSync>(data: &[u8], out: Out) {
	do_test(data, out.clone(), false);
	do_test(data, out, true);
}

#[no_mangle]
pub extern "C" fn chanmon_consistency_run(data: *const u8, datalen: usize) {
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) }, test_logger::DevNull {}, false);
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) }, test_logger::DevNull {}, true);
}
