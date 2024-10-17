use bitcoin::constants::ChainHash;

use crate::chain;
use crate::events::{MessageSendEvent, MessageSendEventsProvider, RecoveryHandler};
use crate::ln::channelmanager::{
	provided_init_features, provided_node_features, ChainParameters, PeerState,
};
use crate::ln::features::{ChannelTypeFeatures, InitFeatures, NodeFeatures};
use crate::ln::msgs;
use crate::ln::msgs::ChannelMessageHandler;

use crate::ln::types::ChannelId;
use bitcoin::block::Header;
use bitcoin::hash_types::{BlockHash, Txid};
use bitcoin::hashes::Hash;
use bitcoin::secp256k1;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::secp256k1::{PublicKey, SecretKey};

use crate::chain::chaininterface::{BroadcasterInterface, FeeEstimator};
use crate::chain::chainmonitor::{
	process_chain_data_util, LockedChannelMonitor, MonitorHolder, Persist,
};
use crate::chain::channelmonitor::{
	ChannelMonitor, ChannelMonitorUpdate, ChannelMonitorUpdateStep, TransactionOutputs,
	WithChannelMonitor, STUB_CHANNEL_UPDATE_IDENTIFIER,
};
use crate::chain::transaction::{OutPoint, TransactionData};
use crate::chain::{BestBlock, ChannelMonitorUpdateStatus, Confirm, Filter, Watch, WatchedOutput};
use crate::crypto::chacha20poly1305rfc::ChaCha20Poly1305RFC;

use crate::events::{self, Event, EventHandler, RecoveryEvent, ReplayEvent};
use crate::ln::chan_utils::{
	make_funding_redeemscript, ChannelPublicKeys, ChannelTransactionParameters,
	CounterpartyChannelTransactionParameters,
};
use crate::ln::channel_keys::RevocationBasepoint;
use crate::ln::our_peer_storage::{OurPeerStorage, StubChannelMonitor};
use crate::sign::ecdsa::EcdsaChannelSigner;
use crate::sign::{EntropySource, NodeSigner, SignerProvider};
use crate::sync::RwLock;
use crate::util::config::UserConfig;
use crate::util::logger::{Logger, WithContext};
use crate::util::ser::Readable;
use crate::util::wakers::Notifier;
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::prelude::*;
use crate::sync::{FairRwLock, Mutex};
use core::cell::RefCell;
use core::ops::Deref;

// Re-export this for use in the public API.
pub use crate::ln::outbound_payment::{
	Bolt12PaymentError, PaymentSendFailure, ProbeSendFailure, RecipientOnionFields, Retry,
	RetryableSendFailure,
};

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
	> events::RecoverEventsProvider for FundRecoverer<ChannelSigner, C, SP, L, NS, ES, P, T, F>
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
		RH::Target: events::RecoveryHandler,
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
	pub fn get_and_clear_recovery_pending_events(&self) -> Vec<events::RecoveryEvent> {
		use crate::events::RecoverEventsProvider;
		let events = core::cell::RefCell::new(Vec::new());
		let event_handler = |event: events::RecoveryEvent| Ok(events.borrow_mut().push(event));
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

	fn stale_or_missing_channel_monitor(&self, stub_chan: &StubChannelMonitor) -> bool {
		let monitor_state = self.monitors.read().unwrap();
		let monitor_holder = monitor_state.get(&stub_chan.funding_outpoint);

		// If monitor doesn't exists.
		if !monitor_holder.is_some() {
			return true;
		}
		let monitor = &monitor_holder.unwrap().monitor;

		// If we get an updated peer storage for an existing channel.
		if monitor.get_latest_update_id() == STUB_CHANNEL_UPDATE_IDENTIFIER
			&& monitor.get_min_seen_secret() > stub_chan.get_min_seen_secret()
		{
			monitor.update_latest_state_from_new_stubmonitor(stub_chan);
			return false;
		} else {
			// if the existing monitor is stale.
			monitor.get_min_seen_secret() > stub_chan.get_min_seen_secret()
		}
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
				if holder.monitor.get_latest_update_id() != STUB_CHANNEL_UPDATE_IDENTIFIER {
					if holder.monitor.get_min_seen_secret()
						> stub_channel_monitor.get_min_seen_secret()
					{
						holder.monitor.merge_commitment_secret(stub_channel_monitor);
					}
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

		for ps_channel in our_peer_storage.get_channels() {
			if self.stale_or_missing_channel_monitor(ps_channel) {
				let mut keys = self.signer_provider.derive_channel_signer(
					ps_channel.channel_value_stoshis,
					ps_channel.channel_keys_id,
				);
				let channel_parameters = ChannelTransactionParameters {
					holder_pubkeys: keys.pubkeys().clone(),
					is_outbound_from_holder: true,
					holder_selected_contest_delay: 66,
					counterparty_parameters: Some(CounterpartyChannelTransactionParameters {
						pubkeys: ChannelPublicKeys {
							funding_pubkey: PublicKey::from_secret_key(
								&self.secp_ctx,
								&SecretKey::from_slice(&[44; 32]).unwrap(),
							),
							revocation_basepoint: RevocationBasepoint::from(
								PublicKey::from_secret_key(
									&self.secp_ctx,
									&SecretKey::from_slice(&[45; 32]).unwrap(),
								),
							),
							payment_point: PublicKey::from_secret_key(
								&self.secp_ctx,
								&SecretKey::from_slice(&[46; 32]).unwrap(),
							),
							delayed_payment_basepoint: ps_channel
								.counterparty_delayed_payment_base_key,
							htlc_basepoint: ps_channel.counterparty_htlc_base_key,
						},
						selected_contest_delay: ps_channel.on_counterparty_tx_csv,
					}),
					funding_outpoint: Some(ps_channel.funding_outpoint),
					channel_type_features: ChannelTypeFeatures::only_static_remote_key(),
				};
				keys.provide_channel_parameters(&channel_parameters);
				let pubkeys = keys.pubkeys().clone();
				let funding_redeemscript =
					make_funding_redeemscript(&pubkeys.funding_pubkey, &counterparty_node_id);
				let funding_txo_script = funding_redeemscript.to_p2wsh();
				let destination_script = self
					.signer_provider
					.get_destination_script(ps_channel.channel_keys_id)
					.unwrap();
				let monitor = ChannelMonitor::new_stub(
					self.secp_ctx.clone(),
					ps_channel,
					keys,
					channel_parameters,
					funding_txo_script,
					destination_script,
				);

				self.watch_dummy(monitor);
				log_debug!(
					logger,
					"Generating BogusChannelReestablish to force close the channel."
				);

				let per_peer_state = self.per_peer_state.read().unwrap();
				if let Some(peer_state_mutex) = per_peer_state.get(&counterparty_node_id) {
					let mut peer_state_lock = peer_state_mutex.lock().unwrap();
					let peer_state = &mut *peer_state_lock;
					let pending_msg_events = &mut peer_state.pending_msg_events;
					pending_msg_events.push(MessageSendEvent::SendChannelReestablish {
						node_id: counterparty_node_id,
						msg: msgs::ChannelReestablish {
							channel_id: ps_channel.channel_id,
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
		&self, _their_node_id: PublicKey, _msg: &msgs::ChannelReestablish,
	) {
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
