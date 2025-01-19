use bitcoin::constants::ChainHash;

use crate::chain::{self};
use crate::events::{MessageSendEvent, MessageSendEventsProvider};
use crate::ln::channelmanager::{
	provided_init_features, provided_node_features, ChainParameters, PeerState,
};
use crate::ln::features::{InitFeatures, NodeFeatures};
use crate::ln::msgs;
use crate::ln::msgs::{ChannelMessageHandler, DecodeError};
use crate::ln::script::ShutdownScript;
use crate::ln::types::ChannelId;
use bitcoin::block::Header;
use bitcoin::hash_types::{BlockHash, Txid};
use bitcoin::{secp256k1, ScriptBuf};
use bitcoin::secp256k1::{Secp256k1, PublicKey};

use crate::chain::chaininterface::{BroadcasterInterface, FeeEstimator};
use crate::chain::chainmonitor::{
	process_chain_data_util, LockedChannelMonitor, MonitorHolder, Persist,
};
use crate::chain::channelmonitor::{
	ChannelMonitor, TransactionOutputs, STUB_CHANNEL_UPDATE_IDENTIFIER,
	read_util, ReadUtilOpt, get_stub_channel_info_from_ser_channel
};
use crate::chain::transaction::{OutPoint, TransactionData};
use crate::chain::{BestBlock, ChannelMonitorUpdateStatus};
use crate::crypto::chacha20poly1305rfc::ChaCha20Poly1305RFC;

use crate::events::{self, EventHandler, ReplayEvent};

use crate::ln::our_peer_storage::OurPeerStorage;
use crate::sign::ecdsa::EcdsaChannelSigner;
use crate::sign::{EntropySource, NodeSigner, SignerProvider};
use crate::sync::RwLock;
use crate::util::config::UserConfig;
use crate::util::logger::{Logger, WithContext};
use crate::util::ser::Readable;
use crate::util::wakers::Notifier;
use core::sync::atomic::AtomicUsize;

use crate::prelude::*;
use crate::sync::{Arc, FairRwLock, Mutex};
use core::cell::RefCell;
use core::ops::Deref;

pub use crate::ln::outbound_payment::{
	Bolt12PaymentError, PaymentSendFailure, ProbeSendFailure, RecipientOnionFields, Retry,
	RetryableSendFailure,
};

/// Represents events related to recovering channel funds.
///
/// This enum defines the types of recovery actions required to restore channel
/// functionality or recover funds. It is primarily used during offline operation
/// or when reinitializing channel monitors.
///
/// # Variants
///
/// - `RescanBlock`:
///   Triggers a blockchain rescan starting from a specific block to identify
///   relevant transactions for channel recovery.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecoveryEvent {
	/// `rescan_from`: The [`BestBlock`] indicating the starting point for the rescan.
	RescanBlock {
		rescan_from: BestBlock
	},
}

/// A trait for handling recovery-related events during [`ChannelMonitor`] restoration.
///
/// Implementations of this trait define how to process specific [`RecoveryEvent`]s,
/// which typically arise during reinitialization of [`ChannelMonitor`] through peer storage.
///
/// Required Method
///
/// `handle_recovery_event`: Handles a given [`RecoveryEvent`] and determines the appropriate
///  actions, such as rescanning blocks or processing replay events.
pub trait RecoveryHandler {
	fn handle_recovery_event(&self, event: RecoveryEvent) -> Result<(), ReplayEvent>;
}

impl<F> RecoveryHandler for F where F: Fn(RecoveryEvent) -> Result<(), ReplayEvent> {
	fn handle_recovery_event(&self, event: RecoveryEvent) -> Result<(), ReplayEvent> {
		self(event)
	}
}

impl<T: RecoveryHandler> RecoveryHandler for Arc<T> {
	fn handle_recovery_event(&self, event: RecoveryEvent) -> Result<(), ReplayEvent> {
		self.deref().handle_recovery_event(event)
	}
}

/// A utility for recovering funds from channels in scenarios where a node operates in offline mode.
///
/// This works as a mock [`ChannelMessageHandler`] it is used mainly when a user wants to run their node in
/// offline mode i.e. This node won't communicate with any peer except sending a BogusChannelReestablish
/// for all the [`StubChannelMonitors`] being tracked by the [`ChainMonitor`].
///
/// [`FundRecoverer`] is parameterized by a number of components to achieve this.
/// - [`chain::Watch`] (typically [`ChainMonitor`]) for on-chain monitoring and enforcement of each
///   channel
/// - [`SignerProvider`] for providing signers whose operations are scoped to individual channels
/// - [`Logger`] for logging operational information of varying degrees
///
/// Additionally, it implements the following traits:
/// - [`ChannelMessageHandler`] to handle off-chain channel activity from peers
/// - [`MessageSendEventsProvider`] to similarly send such messages to peers
///
pub struct FundRecoverer<
	ChannelSigner: EcdsaChannelSigner,
	C: Deref,
	SP: Deref,
	L: Deref,
	NS: Deref,
	ES: Deref,
	P: Deref,
	T: Deref,
	F: Deref,
> where
	SP::Target: SignerProvider,
	NS::Target: NodeSigner,
	L::Target: Logger,
	ES::Target: EntropySource,
	C::Target: chain::Filter,
	P::Target: Persist<ChannelSigner>,
	T::Target: BroadcasterInterface,
	F::Target: FeeEstimator,
{
	default_configuration: UserConfig,
	secp_ctx: Secp256k1<secp256k1::All>,
	entropy_source: ES,
	chain_source: Option<C>,
	persister: P,
	broadcaster: T,
	fee_estimator: F,

	monitors: RwLock<HashMap<OutPoint, MonitorHolder<ChannelSigner>>>,

	highest_chain_height: AtomicUsize,
	signer_provider: SP,
	node_signer: NS,
	chain_hash: ChainHash,
	/// The key used to encrypt our peer storage that would be sent to our peers.
	our_peerstorage_encryption_key: [u8; 32],
	per_peer_state: FairRwLock<HashMap<PublicKey, Mutex<PeerState<SP>>>>,

	#[cfg(test)]
	pub(super) best_block: RwLock<BestBlock>,
	#[cfg(not(test))]
	best_block: RwLock<BestBlock>,

	pending_events: Mutex<Vec<RecoveryEvent>>,
	/// A [`Notifier`] used to wake up the background processor in case we have any [`Event`]s for
	/// it to give to users (or [`MonitorEvent`]s for `ChannelManager` to process).
	event_notifier: Notifier,

	logger: L,
}

impl<
		ChannelSigner: EcdsaChannelSigner,
		C: Deref,
		SP: Deref,
		L: Deref,
		NS: Deref,
		ES: Deref,
		P: Deref,
		T: Deref,
		F: Deref,
	> events::EventsProvider for FundRecoverer<ChannelSigner, C, SP, L, NS, ES, P, T, F>
where
	SP::Target: SignerProvider,
	NS::Target: NodeSigner,
	L::Target: Logger,
	ES::Target: EntropySource,
	C::Target: chain::Filter,
	P::Target: Persist<ChannelSigner>,
	T::Target: BroadcasterInterface,
	F::Target: FeeEstimator,
{
	/// Processes [`SpendableOutputs`] events produced from each [`ChannelMonitor`] upon maturity.
	///
	/// For channels featuring anchor outputs, this method will also process [`BumpTransaction`]
	/// events produced from each [`ChannelMonitor`] while there is a balance to claim onchain
	/// within each channel. As the confirmation of a commitment transaction may be critical to the
	/// safety of funds, we recommend invoking this every 30 seconds, or lower if running in an
	/// environment with spotty connections, like on mobile.
	///
	/// An [`EventHandler`] may safely call back to the provider, though this shouldn't be needed in
	/// order to handle these events.
	///
	/// [`SpendableOutputs`]: events::Event::SpendableOutputs
	/// [`BumpTransaction`]: events::Event::BumpTransaction
	fn process_pending_events<H: Deref>(&self, handler: H)
	where
		H::Target: EventHandler,
	{
		for monitor_state in self.monitors.read().unwrap().values() {
			match monitor_state.monitor.process_pending_events(&handler) {
				Ok(()) => {},
				Err(ReplayEvent()) => {
					self.event_notifier.notify();
				},
			}
		}
	}
}

impl<
		ChannelSigner: EcdsaChannelSigner,
		C: Deref,
		SP: Deref,
		L: Deref,
		NS: Deref,
		ES: Deref,
		P: Deref,
		T: Deref,
		F: Deref,
	> FundRecoverer<ChannelSigner, C, SP, L, NS, ES, P, T, F>
where
	SP::Target: SignerProvider,
	NS::Target: NodeSigner,
	L::Target: Logger,
	ES::Target: EntropySource,
	C::Target: chain::Filter,
	P::Target: Persist<ChannelSigner>,
	T::Target: BroadcasterInterface,
	F::Target: FeeEstimator,
{
	fn process_pending_recovery_events<RH: Deref>(&self, handler: RH)
	where
		RH::Target: RecoveryHandler,
	{
		let mut events = self.pending_events.lock().unwrap();
		for event in events.drain(..) {
			match handler.handle_recovery_event(event) {
				Ok(()) => {},
				Err(ReplayEvent()) => {
					self.event_notifier.notify();
				},
			}
		}
	}
}

impl<
		ChannelSigner: EcdsaChannelSigner,
		C: Deref,
		SP: Deref,
		L: Deref,
		NS: Deref,
		ES: Deref,
		P: Deref,
		T: Deref,
		F: Deref,
	> MessageSendEventsProvider for FundRecoverer<ChannelSigner, C, SP, L, NS, ES, P, T, F>
where
	SP::Target: SignerProvider,
	NS::Target: NodeSigner,
	L::Target: Logger,
	ES::Target: EntropySource,
	C::Target: chain::Filter,
	P::Target: Persist<ChannelSigner>,
	T::Target: BroadcasterInterface,
	F::Target: FeeEstimator,
{
	fn get_and_clear_pending_msg_events(&self) -> Vec<MessageSendEvent> {
		let mut pending_events = Vec::new();
		let events = RefCell::new(Vec::new());
		let per_peer_state = self.per_peer_state.read().unwrap();
		for (_cp_id, peer_state_mutex) in per_peer_state.iter() {
			let mut peer_state_lock = peer_state_mutex.lock().unwrap();
			let peer_state = &mut *peer_state_lock;
			if peer_state.pending_msg_events.len() > 0 {
				pending_events.append(&mut peer_state.pending_msg_events);
			}
		}
		if !pending_events.is_empty() {
			events.replace(pending_events);
		}
		events.into_inner()
	}
}

impl<
		ChannelSigner: EcdsaChannelSigner,
		C: Deref,
		SP: Deref,
		L: Deref,
		NS: Deref,
		ES: Deref,
		P: Deref,
		T: Deref,
		F: Deref,
	> FundRecoverer<ChannelSigner, C, SP, L, NS, ES, P, T, F>
where
	SP::Target: SignerProvider,
	NS::Target: NodeSigner,
	L::Target: Logger,
	ES::Target: EntropySource,
	C::Target: chain::Filter,
	P::Target: Persist<ChannelSigner>,
	T::Target: BroadcasterInterface,
	F::Target: FeeEstimator,
{
	/// Creates a new instance of `FundRecoverer`.
	/// This function initializes a `FundRecoverer` with the provided `chain_monitor`,
	/// `logger`, configuration, and chain parameters. The `FundRecoverer` is set up with
	/// the default configuration and a chain hash derived from the genesis block of the
	/// specified network.
	pub fn new(
		node_signer: NS, logger: L, config: UserConfig, params: ChainParameters,
		signer_provider: SP, entropy_source: ES, chain_source: Option<C>, persister: P,
		fee_estimator: F, broadcaster: T, monitors: Vec<ChannelMonitor<ChannelSigner>>,
	) -> Self {
		let our_peerstorage_encryption_key = node_signer.get_peer_storage_key();
		let mut secp_ctx = Secp256k1::new();
		let mut monitor_map = new_hash_map();
		for monitor in monitors {
			let entry = match monitor_map.entry(monitor.get_funding_txo().0) {
				hash_map::Entry::Occupied(_) => {
					continue;
				},
				hash_map::Entry::Vacant(e) => e,
			};

			if let Some(ref chain_source) = chain_source {
				monitor.load_outputs_to_watch(chain_source, &logger);
			}

			entry
				.insert(MonitorHolder { monitor, pending_monitor_updates: Mutex::new(Vec::new()) });
		}
		secp_ctx.seeded_randomize(&entropy_source.get_secure_random_bytes());
		return Self {
			default_configuration: config.clone(),
			monitors: RwLock::new(monitor_map),
			persister,
			fee_estimator,
			broadcaster,
			chain_source,
			signer_provider,
			entropy_source,
			secp_ctx,
			highest_chain_height: AtomicUsize::new(0),
			best_block: RwLock::new(params.best_block),
			node_signer,
			our_peerstorage_encryption_key,
			pending_events: Mutex::new(Vec::new()),
			event_notifier: Notifier::new(),
			chain_hash: ChainHash::using_genesis_block(params.network),
			per_peer_state: FairRwLock::new(new_hash_map()),
			logger,
		};
	}

	#[cfg(any(test, feature = "_test_utils"))]
	pub fn get_and_clear_pending_events(&self) -> Vec<events::Event> {
		use crate::events::EventsProvider;
		let events = core::cell::RefCell::new(Vec::new());
		let event_handler = |event: events::Event| Ok(events.borrow_mut().push(event));
		self.process_pending_events(&event_handler);
		events.into_inner()
	}

	#[cfg(any(test, feature = "_test_utils"))]
	pub fn get_and_clear_recovery_pending_events(&self) -> Vec<RecoveryEvent> {
		let events = core::cell::RefCell::new(Vec::new());
		let event_handler = |event: RecoveryEvent| Ok(events.borrow_mut().push(event));
		self.process_pending_recovery_events(&event_handler);
		events.into_inner()
	}

	/// Decrypt `OurPeerStorage` using the `key`, result is stored inside the `res`.
	/// Returns an error if the the `cyphertext` is not correct.
	fn decrypt_our_peer_storage(&self, res: &mut [u8], cyphertext: &[u8]) -> Result<(), ()> {
		let key = self.our_peerstorage_encryption_key;
		let n = 0u64;

		let mut nonce = [0; 12];
		nonce[4..].copy_from_slice(&n.to_le_bytes()[..]);

		let mut chacha = ChaCha20Poly1305RFC::new(&key, &nonce, b"");
		if chacha
			.variable_time_decrypt(
				&cyphertext[0..cyphertext.len() - 16],
				res,
				&cyphertext[cyphertext.len() - 16..],
			)
			.is_err()
		{
			return Err(());
		}
		Ok(())
	}

	/// Returns a tuple indicating if the ChannelMonitor is stale or missing.
	/// - `is_stale`: `(true, false)` if the ChannelMonitor is stale.
	/// - `is_missing`: `(false, true)` if the ChannelMonitor is missing.
	/// - Both `false` indicates the ChannelMonitor is healthy.
	fn stale_or_missing_channel_monitor(&self, funding_outpoint: OutPoint, min_seen_secret: u64) -> (bool, bool) {
		let monitor_state = self.monitors.read().unwrap();
		let monitor_holder = monitor_state.get(&funding_outpoint);

		// If monitor doesn't exists.
		if !monitor_holder.is_some() {
			return (false, true);
		}
		let monitor = &monitor_holder.unwrap().monitor;

		// If we get an updated peer storage for an existing channel or if the monitor is stale.
		if monitor.get_min_seen_secret() > min_seen_secret {
			return (true, false);
		}
		return (false, false);
	}

	fn watch_dummy(&self, stub_channel_monitor: ChannelMonitor<ChannelSigner>) {
		if let Some(ref chain_source) = self.chain_source {
			stub_channel_monitor.load_outputs_to_watch(chain_source, &self.logger);
		}

		let mut monitors = self.monitors.write().unwrap();
		let entry = match monitors.entry(stub_channel_monitor.get_funding_txo().0) {
			hash_map::Entry::Occupied(mut m) => {
				log_error!(self.logger, "Failed to add new channel data: channel monitor for given outpoint is already present");
				// If this one isn't stale we need to update the monitor.
				let holder = m.get_mut();
				if holder.monitor.get_min_seen_secret()
					> stub_channel_monitor.get_min_seen_secret()
				{
					holder.monitor.merge_commitment_secret(stub_channel_monitor);
				}
				return;
			},
			hash_map::Entry::Vacant(e) => e,
		};
		self.pending_events.lock().unwrap().push(RecoveryEvent::RescanBlock {
			rescan_from: stub_channel_monitor.current_best_block(),
		});

		let persist_res = self
			.persister
			.persist_new_channel(stub_channel_monitor.get_funding_txo().0, &stub_channel_monitor);

		match persist_res {
			ChannelMonitorUpdateStatus::InProgress => {
				log_info!(
					self.logger,
					"Persistence of new ChannelMonitor for channel {} in progress",
					log_funding_info!(stub_channel_monitor)
				);
			},
			ChannelMonitorUpdateStatus::Completed => {
				log_info!(
					self.logger,
					"Persistence of new ChannelMonitor for channel {} completed",
					log_funding_info!(stub_channel_monitor)
				);
			},
			ChannelMonitorUpdateStatus::UnrecoverableError => {
				let err_str = "ChannelMonitor[Update] persistence failed unrecoverably. This indicates we cannot continue normal operation and must shut down.";
				log_error!(self.logger, "{}", err_str);
				panic!("{}", err_str);
			},
		}
		entry.insert(MonitorHolder {
			monitor: stub_channel_monitor,
			pending_monitor_updates: Mutex::new(Vec::new()),
		});
	}

	fn process_chain_data<FN>(
		&self, header: &Header, best_height: Option<u32>, txdata: &TransactionData, process: FN,
	) where
		FN: Fn(&ChannelMonitor<ChannelSigner>, &TransactionData) -> Vec<TransactionOutputs>,
	{
		process_chain_data_util(
			&self.persister,
			&self.chain_source,
			&self.logger,
			&self.monitors,
			&self.highest_chain_height,
			header,
			best_height,
			txdata,
			process,
		);
	}

	/// Lists the funding outpoint and channel ID of each [`ChannelMonitor`] being monitored.
	///
	/// Note that [`ChannelMonitor`]s are not removed when a channel is closed as they are always
	/// monitoring for on-chain state resolutions.
	pub fn list_monitors(&self) -> Vec<(OutPoint, ChannelId)> {
		self.monitors
			.read()
			.unwrap()
			.iter()
			.map(|(outpoint, monitor_holder)| {
				let channel_id = monitor_holder.monitor.channel_id();
				(*outpoint, channel_id)
			})
			.collect()
	}

	/// Gets the [`LockedChannelMonitor`] for a given funding outpoint, returning an `Err` if no
	/// such [`ChannelMonitor`] is currently being monitored for.
	///
	/// Note that the result holds a mutex over our monitor set, and should not be held
	/// indefinitely.
	pub fn get_monitor(
		&self, funding_txo: OutPoint,
	) -> Result<LockedChannelMonitor<'_, ChannelSigner>, ()> {
		let lock = self.monitors.read().unwrap();
		if lock.get(&funding_txo).is_some() {
			Ok(LockedChannelMonitor { lock, funding_txo })
		} else {
			Err(())
		}
	}
}

struct DummySignerProvider <ChannelSigner: EcdsaChannelSigner> {
    _marker: std::marker::PhantomData<ChannelSigner>,
}

struct DummyEntropySource;
impl<ChannelSigner: EcdsaChannelSigner> SignerProvider for DummySignerProvider<ChannelSigner> {
	type EcdsaSigner = ChannelSigner;

	fn generate_channel_keys_id(
		&self, _inbound: bool, _channel_value_satoshis: u64, _user_channel_id: u128,
	) -> [u8; 32] {
		unreachable!()
	}

	fn derive_channel_signer(
		&self, _channel_value_satoshis: u64, _channel_keys_id: [u8; 32],
	) -> Self::EcdsaSigner {
		unreachable!();
	}

	fn read_chan_signer(&self, _reader: &[u8]) -> Result<Self::EcdsaSigner, DecodeError> {
		unreachable!();
	}

	fn get_destination_script(&self, _channel_keys_id: [u8; 32]) -> Result<ScriptBuf, ()> {
		unreachable!();
	}

	fn get_shutdown_scriptpubkey(&self) -> Result<ShutdownScript, ()> {
		unreachable!();
	}

}

impl EntropySource for DummyEntropySource {
	fn get_secure_random_bytes(&self) -> [u8; 32] {
		unreachable!();
	}
}

impl<
		ChannelSigner: EcdsaChannelSigner,
		C: Deref,
		SP: Deref,
		L: Deref,
		NS: Deref,
		ES: Deref,
		P: Deref,
		T: Deref,
		F: Deref,
	> ChannelMessageHandler for FundRecoverer<ChannelSigner, C, SP, L, NS, ES, P, T, F>
where
	SP::Target: SignerProvider<EcdsaSigner = ChannelSigner>,
	NS::Target: NodeSigner,
	L::Target: Logger,
	ES::Target: EntropySource,
	C::Target: chain::Filter,
	P::Target: Persist<ChannelSigner>,
	T::Target: BroadcasterInterface,
	F::Target: FeeEstimator,
{
	fn handle_open_channel(&self, _their_node_id: PublicKey, _msg: &msgs::OpenChannel) {}
	fn handle_accept_channel(&self, _their_node_id: PublicKey, _msg: &msgs::AcceptChannel) {}
	fn handle_funding_created(&self, _their_node_id: PublicKey, _msg: &msgs::FundingCreated) {}
	fn handle_funding_signed(&self, _their_node_id: PublicKey, _msg: &msgs::FundingSigned) {}
	fn handle_channel_ready(&self, _their_node_id: PublicKey, _msg: &msgs::ChannelReady) {}
	fn handle_shutdown(&self, _their_node_id: PublicKey, _msg: &msgs::Shutdown) {}
	fn handle_closing_signed(&self, _their_node_id: PublicKey, _msg: &msgs::ClosingSigned) {}
	fn handle_update_add_htlc(&self, _their_node_id: PublicKey, _msg: &msgs::UpdateAddHTLC) {}
	fn handle_update_fulfill_htlc(
		&self, _their_node_id: PublicKey, _msg: &msgs::UpdateFulfillHTLC,
	) {
	}
	fn handle_update_fail_htlc(&self, _their_node_id: PublicKey, _msg: &msgs::UpdateFailHTLC) {}
	fn handle_update_fail_malformed_htlc(
		&self, _their_node_id: PublicKey, _msg: &msgs::UpdateFailMalformedHTLC,
	) {
	}
	fn handle_commitment_signed(&self, _their_node_id: PublicKey, _msg: &msgs::CommitmentSigned) {}
	fn handle_revoke_and_ack(&self, _their_node_id: PublicKey, _msg: &msgs::RevokeAndACK) {}
	fn handle_update_fee(&self, _their_node_id: PublicKey, _msg: &msgs::UpdateFee) {}
	fn handle_announcement_signatures(
		&self, _their_node_id: PublicKey, _msg: &msgs::AnnouncementSignatures,
	) {
	}
	fn handle_channel_update(&self, _their_node_id: PublicKey, _msg: &msgs::ChannelUpdate) {}
	fn handle_open_channel_v2(&self, _their_node_id: PublicKey, _msg: &msgs::OpenChannelV2) {}
	fn handle_accept_channel_v2(&self, _their_node_id: PublicKey, _msg: &msgs::AcceptChannelV2) {}
	fn handle_stfu(&self, _their_node_id: PublicKey, _msg: &msgs::Stfu) {}
	#[cfg(splicing)]
	fn handle_splice_init(&self, _their_node_id: PublicKey, _msg: &msgs::SpliceInit) {}
	#[cfg(splicing)]
	fn handle_splice_ack(&self, _their_node_id: PublicKey, _msg: &msgs::SpliceAck) {}
	#[cfg(splicing)]
	fn handle_splice_locked(&self, _their_node_id: PublicKey, _msg: &msgs::SpliceLocked) {}
	fn handle_tx_add_input(&self, _their_node_id: PublicKey, _msg: &msgs::TxAddInput) {}
	fn handle_tx_add_output(&self, _their_node_id: PublicKey, _msg: &msgs::TxAddOutput) {}
	fn handle_tx_remove_input(&self, _their_node_id: PublicKey, _msg: &msgs::TxRemoveInput) {}
	fn handle_tx_remove_output(&self, _their_node_id: PublicKey, _msg: &msgs::TxRemoveOutput) {}
	fn handle_tx_complete(&self, _their_node_id: PublicKey, _msg: &msgs::TxComplete) {}
	fn handle_tx_signatures(&self, _their_node_id: PublicKey, _msg: &msgs::TxSignatures) {}
	fn handle_tx_init_rbf(&self, _their_node_id: PublicKey, _msg: &msgs::TxInitRbf) {}
	fn handle_tx_ack_rbf(&self, _their_node_id: PublicKey, _msg: &msgs::TxAckRbf) {}
	fn handle_tx_abort(&self, _their_node_id: PublicKey, _msg: &msgs::TxAbort) {}
	fn handle_peer_storage(&self, _their_node_id: PublicKey, _msg: &msgs::PeerStorageMessage) {}

	fn handle_your_peer_storage(
		&self, counterparty_node_id: PublicKey, msg: &msgs::YourPeerStorageMessage,
	) {
		let logger = WithContext::from(&self.logger, Some(counterparty_node_id), None, None);
		if msg.data.len() < 16 {
			log_debug!(
				logger,
				"Invalid YourPeerStorage received from {}",
				log_pubkey!(counterparty_node_id)
			);
			return;
		}

		let mut res = vec![0; msg.data.len() - 16];
		{
			match self.decrypt_our_peer_storage(&mut res, msg.data.as_slice()) {
				Ok(()) => {
					// Decryption successful, the plaintext is now stored in `res`
					log_debug!(
						logger,
						"Received a peer storage from peer {}",
						log_pubkey!(counterparty_node_id)
					);
				},
				Err(_) => {
					log_debug!(
						logger,
						"Invalid YourPeerStorage received from {}",
						log_pubkey!(counterparty_node_id)
					);
					return;
				},
			}
		}

		let our_peer_storage =
			<OurPeerStorage as Readable>::read(&mut ::bitcoin::io::Cursor::new(res)).unwrap();

		for ((_, _), _) in our_peer_storage.get_cid_and_min_seen_secret().unwrap() {
			let chan_reader = &mut ::bitcoin::io::Cursor::new(our_peer_storage.get_ser_channels());
			let num_chan: u64 = Readable::read(chan_reader).unwrap_or_else(|op| panic!("Failed to read num_chan: {:?}", op));
			for _ in 0..num_chan {
				let len: u64 = Readable::read(chan_reader).unwrap_or_else(|op| panic!("Failed to read len: {:?}", op));
				let mut chan_bytes: Vec<u8> = Vec::with_capacity(len as usize);
				for _ in 0..len {
					chan_bytes.push(Readable::read(chan_reader).unwrap_or_else(|op| panic!("Failed to read chan_bytes: {:?}", op)));
				}
				let mut chan_reader = ::bitcoin::io::Cursor::new(chan_bytes);

				match get_stub_channel_info_from_ser_channel(&mut chan_reader) {
					Ok(ps_channel) => {
						let (stale, missing) = self.stale_or_missing_channel_monitor(ps_channel.funding_outpoint, ps_channel.min_seen_secret);
						if stale || missing {
							let keys = self.signer_provider.derive_channel_signer(
								ps_channel.channel_value_satoshi,
								ps_channel.channel_keys_id,
							);

							let (_, monitor) = read_util::<_, ChannelSigner, DummySignerProvider<ChannelSigner>, DummyEntropySource>(&mut chan_reader,
																																							ReadUtilOpt::IsStub{keys, secp_ctx: self.secp_ctx.clone()}).unwrap();
							let cid = monitor.channel_id();
							let channel_partner_node_id = monitor.get_counterparty_node_id().unwrap();
							self.watch_dummy(monitor);
							log_debug!(
								logger,
								"Generating BogusChannelReestablish to force close the channel."
							);

							let per_peer_state = self.per_peer_state.read().unwrap();
							if let Some(peer_state_mutex) = per_peer_state.get(&channel_partner_node_id) {
								let mut peer_state_lock = peer_state_mutex.lock().unwrap();
								let peer_state = &mut *peer_state_lock;
								let pending_msg_events = &mut peer_state.pending_msg_events;
								pending_msg_events.push(MessageSendEvent::SendChannelReestablish {
									node_id: channel_partner_node_id,
									msg: msgs::ChannelReestablish {
										channel_id: cid,
										next_local_commitment_number: 0,
										next_remote_commitment_number: 0,
										your_last_per_commitment_secret: [1u8; 32],
										my_current_per_commitment_point: PublicKey::from_slice(&[2u8; 33])
											.unwrap(),
										next_funding_txid: None,
									},
								})
							}
						}
					}
					Err(_) => {
						panic!("Could not get peer storage");
					}
				}
			}
		}
	}

	fn peer_disconnected(&self, _their_node_id: PublicKey) {}

	fn peer_connected(
		&self, counterparty_node_id: PublicKey, init_msg: &msgs::Init, _inbound: bool,
	) -> Result<(), ()> {
		let logger = WithContext::from(&self.logger, Some(counterparty_node_id), None, None);

		{
			let mut peer_state_lock = self.per_peer_state.write().unwrap();
			match peer_state_lock.entry(counterparty_node_id.clone()) {
				hash_map::Entry::Vacant(e) => {
					e.insert(Mutex::new(PeerState::new(&init_msg.features)));
				},
				hash_map::Entry::Occupied(e) => {
					let mut peer_state = e.get().lock().unwrap();

					debug_assert!(!peer_state.is_connected, "A peer shouldn't be connected twice");
					peer_state.is_connected = true;
				},
			}
		}

		log_debug!(logger, "Connected to node {}", log_pubkey!(counterparty_node_id));
		Ok(())
	}

	fn handle_channel_reestablish(
		&self, their_node_id: PublicKey, msg: &msgs::ChannelReestablish,
	) {
		let per_peer_state = self.per_peer_state.read().unwrap();
		if let Some(peer_state_mutex) = per_peer_state.get(&their_node_id) {
			let mut peer_state_lock = peer_state_mutex.lock().unwrap();
			let peer_state = &mut *peer_state_lock;
			let pending_msg_events = &mut peer_state.pending_msg_events;
			for monitor_state in self.monitors.read().unwrap().values() {
				if monitor_state.monitor.channel_id() == msg.channel_id && monitor_state.monitor.get_latest_update_id() == STUB_CHANNEL_UPDATE_IDENTIFIER {
					pending_msg_events.push(MessageSendEvent::SendChannelReestablish {
						node_id: their_node_id,
						msg: msgs::ChannelReestablish {
							channel_id: msg.channel_id,
							next_local_commitment_number: 0,
							next_remote_commitment_number: 0,
							your_last_per_commitment_secret: [1u8; 32],
							my_current_per_commitment_point: PublicKey::from_slice(&[2u8; 33])
								.unwrap(),
							next_funding_txid: None,
						},
					})
				}
			}
		}
	}
	fn handle_error(&self, _their_node_id: PublicKey, _msg: &msgs::ErrorMessage) {}
	fn provided_node_features(&self) -> NodeFeatures {
		provided_node_features(&self.default_configuration)
	}
	fn provided_init_features(&self, _their_node_id: PublicKey) -> InitFeatures {
		provided_init_features(&self.default_configuration)
	}
	fn get_chain_hashes(&self) -> Option<Vec<ChainHash>> {
		Some(vec![self.chain_hash])
	}

	fn message_received(&self) {}
}


impl<
		ChannelSigner: EcdsaChannelSigner,
		C: Deref,
		SP: Deref,
		L: Deref,
		NS: Deref,
		ES: Deref,
		P: Deref,
		T: Deref,
		F: Deref,
	> chain::Confirm for FundRecoverer<ChannelSigner, C, SP, L, NS, ES, P, T, F>
where
	SP::Target: SignerProvider<EcdsaSigner = ChannelSigner>,
	NS::Target: NodeSigner,
	L::Target: Logger,
	ES::Target: EntropySource,
	C::Target: chain::Filter,
	P::Target: Persist<ChannelSigner>,
	T::Target: BroadcasterInterface,
	F::Target: FeeEstimator,
{
	fn transactions_confirmed(&self, header: &Header, txdata: &TransactionData, height: u32) {
		log_debug!(
			self.logger,
			"{} provided transactions confirmed at height {} in block {}",
			txdata.len(),
			height,
			header.block_hash()
		);

		self.process_chain_data(header, None, txdata, |monitor, txdata| {
			monitor.transactions_confirmed(
				header,
				txdata,
				height,
				&*self.broadcaster,
				&*self.fee_estimator,
				&self.logger,
			)
		});
		// Assume we may have some new events and wake the event processor
		self.event_notifier.notify();
	}

	fn transaction_unconfirmed(&self, txid: &Txid) {
		log_debug!(self.logger, "Transaction {} reorganized out of chain", txid);
		let monitor_states = self.monitors.read().unwrap();
		for monitor_state in monitor_states.values() {
			monitor_state.monitor.transaction_unconfirmed(
				txid,
				&*self.broadcaster,
				&*self.fee_estimator,
				&self.logger,
			);
		}
	}

	fn best_block_updated(&self, header: &Header, height: u32) {
		log_debug!(
			self.logger,
			"New best block {} at height {} provided via best_block_updated",
			header.block_hash(),
			height
		);
		self.process_chain_data(header, Some(height), &[], |monitor, txdata| {
			// While in practice there shouldn't be any recursive calls when given empty txdata,
			// it's still possible if a chain::Filter implementation returns a transaction.
			debug_assert!(txdata.is_empty());
			monitor.best_block_updated(
				header,
				height,
				&*self.broadcaster,
				&*self.fee_estimator,
				&self.logger,
			)
		});
		// Assume we may have some new events and wake the event processor
		self.event_notifier.notify();
	}

	fn get_relevant_txids(&self) -> Vec<(Txid, u32, Option<BlockHash>)> {
		let mut txids = Vec::new();
		let monitor_states = self.monitors.read().unwrap();
		for monitor_state in monitor_states.values() {
			txids.append(&mut monitor_state.monitor.get_relevant_txids());
		}

		txids.sort_unstable_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)));
		txids.dedup_by_key(|(txid, _, _)| *txid);
		txids
	}
}
