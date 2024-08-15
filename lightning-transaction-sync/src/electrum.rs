use crate::common::{ConfirmedTx, FilterQueue, SyncState};
use crate::error::{InternalError, TxSyncError};

use electrum_client::utils::validate_merkle_proof;
use electrum_client::Client as ElectrumClient;
use electrum_client::ElectrumApi;

use lightning::chain::WatchedOutput;
use lightning::chain::{Confirm, Filter};
use lightning::util::logger::Logger;
use lightning::{log_debug, log_error, log_trace};

use bitcoin::block::Header;
use bitcoin::{BlockHash, Script, Transaction, Txid};

use std::collections::HashSet;
use std::ops::Deref;
use std::sync::Mutex;
use std::time::Instant;

/// Synchronizes LDK with a given Electrum server.
///
/// Needs to be registered with a [`ChainMonitor`] via the [`Filter`] interface to be informed of
/// transactions and outputs to monitor for on-chain confirmation, unconfirmation, and
/// reconfirmation.
///
/// Note that registration via [`Filter`] needs to happen before any calls to
/// [`Watch::watch_channel`] to ensure we get notified of the items to monitor.
///
/// [`ChainMonitor`]: lightning::chain::chainmonitor::ChainMonitor
/// [`Watch::watch_channel`]: lightning::chain::Watch::watch_channel
/// [`Filter`]: lightning::chain::Filter
pub struct ElectrumSyncClient<L: Deref>
where
	L::Target: Logger,
{
	sync_state: Mutex<SyncState>,
	queue: Mutex<FilterQueue>,
	client: ElectrumClient,
	logger: L,
}

impl<L: Deref> ElectrumSyncClient<L>
where
	L::Target: Logger,
{
	/// Returns a new [`ElectrumSyncClient`] object.
	pub fn new(server_url: String, logger: L) -> Result<Self, TxSyncError> {
		let client = ElectrumClient::new(&server_url).map_err(|e| {
			log_error!(logger, "Failed to connect to electrum server '{}': {}", server_url, e);
			e
		})?;

		Self::from_client(client, logger)
	}

	/// Returns a new [`ElectrumSyncClient`] object using the given Electrum client.
	///
	/// This is not exported to bindings users as the underlying client from BDK is not exported.
	pub fn from_client(client: ElectrumClient, logger: L) -> Result<Self, TxSyncError> {
		let sync_state = Mutex::new(SyncState::new());
		let queue = Mutex::new(FilterQueue::new());

		Ok(Self { sync_state, queue, client, logger })
	}

	/// Synchronizes the given `confirmables` via their [`Confirm`] interface implementations. This
	/// method should be called regularly to keep LDK up-to-date with current chain data.
	///
	/// For example, instances of [`ChannelManager`] and [`ChainMonitor`] can be informed about the
	/// newest on-chain activity related to the items previously registered via the [`Filter`]
	/// interface.
	///
	/// [`Confirm`]: lightning::chain::Confirm
	/// [`ChainMonitor`]: lightning::chain::chainmonitor::ChainMonitor
	/// [`ChannelManager`]: lightning::ln::channelmanager::ChannelManager
	/// [`Filter`]: lightning::chain::Filter
	pub fn sync<C: Deref>(&self, confirmables: Vec<C>) -> Result<(), TxSyncError>
	where
		C::Target: Confirm,
	{
		// This lock makes sure we're syncing once at a time.
		let mut sync_state = self.sync_state.lock().unwrap();

		log_trace!(self.logger, "Starting transaction sync.");
		#[cfg(feature = "time")]
		let start_time = Instant::now();
		let mut num_confirmed = 0;
		let mut num_unconfirmed = 0;

		// Clear any header notifications we might have gotten to keep the queue count low.
		while let Some(_) = self.client.block_headers_pop()? {}

		let tip_notification = self.client.block_headers_subscribe()?;
		let mut tip_header = tip_notification.header;
		let mut tip_height = tip_notification.height as u32;

		loop {
			let pending_registrations = self.queue.lock().unwrap().process_queues(&mut sync_state);
			let tip_is_new = Some(tip_header.block_hash()) != sync_state.last_sync_hash;

			// We loop until any registered transactions have been processed at least once, or the
			// tip hasn't been updated during the last iteration.
			if !sync_state.pending_sync && !pending_registrations && !tip_is_new {
				// Nothing to do.
				break;
			} else {
				// Update the known tip to the newest one.
				if tip_is_new {
					// First check for any unconfirmed transactions and act on it immediately.
					match self.get_unconfirmed_transactions(&confirmables) {
						Ok(unconfirmed_txs) => {
							// Double-check the tip hash. If it changed, a reorg happened since
							// we started syncing and we need to restart last-minute.
							match self.check_update_tip(&mut tip_header, &mut tip_height) {
								Ok(false) => {
									num_unconfirmed += unconfirmed_txs.len();
									sync_state.sync_unconfirmed_transactions(
										&confirmables,
										unconfirmed_txs,
									);
								},
								Ok(true) => {
									log_debug!(self.logger,
										"Encountered inconsistency during transaction sync, restarting.");
									sync_state.pending_sync = true;
									continue;
								},
								Err(err) => {
									// (Semi-)permanent failure, retry later.
									log_error!(self.logger,
										"Failed during transaction sync, aborting. Synced so far: {} confirmed, {} unconfirmed.",
										num_confirmed,
										num_unconfirmed
									);
									sync_state.pending_sync = true;
									return Err(TxSyncError::from(err));
								},
							}
						},
						Err(err) => {
							// (Semi-)permanent failure, retry later.
							log_error!(self.logger,
								"Failed during transaction sync, aborting. Synced so far: {} confirmed, {} unconfirmed.",
								num_confirmed,
								num_unconfirmed
							);
							sync_state.pending_sync = true;
							return Err(TxSyncError::from(err));
						},
					}

					// Update the best block.
					for c in &confirmables {
						c.best_block_updated(&tip_header, tip_height);
					}

					// Prune any sufficiently confirmed output spends
					sync_state.prune_output_spends(tip_height);
				}

				match self.get_confirmed_transactions(&sync_state) {
					Ok(confirmed_txs) => {
						// Double-check the tip hash. If it changed, a reorg happened since
						// we started syncing and we need to restart last-minute.
						match self.check_update_tip(&mut tip_header, &mut tip_height) {
							Ok(false) => {
								num_confirmed += confirmed_txs.len();
								sync_state
									.sync_confirmed_transactions(&confirmables, confirmed_txs);
							},
							Ok(true) => {
								log_debug!(self.logger,
									"Encountered inconsistency during transaction sync, restarting.");
								sync_state.pending_sync = true;
								continue;
							},
							Err(err) => {
								// (Semi-)permanent failure, retry later.
								log_error!(self.logger,
									"Failed during transaction sync, aborting. Synced so far: {} confirmed, {} unconfirmed.",
									num_confirmed,
									num_unconfirmed
								);
								sync_state.pending_sync = true;
								return Err(TxSyncError::from(err));
							},
						}
					},
					Err(InternalError::Inconsistency) => {
						// Immediately restart syncing when we encounter any inconsistencies.
						log_debug!(
							self.logger,
							"Encountered inconsistency during transaction sync, restarting."
						);
						sync_state.pending_sync = true;
						continue;
					},
					Err(err) => {
						// (Semi-)permanent failure, retry later.
						log_error!(self.logger,
							"Failed during transaction sync, aborting. Synced so far: {} confirmed, {} unconfirmed.",
							num_confirmed,
							num_unconfirmed
						);
						sync_state.pending_sync = true;
						return Err(TxSyncError::from(err));
					},
				}
				sync_state.last_sync_hash = Some(tip_header.block_hash());
				sync_state.pending_sync = false;
			}
		}
		#[cfg(feature = "time")]
		log_debug!(
			self.logger,
			"Finished transaction sync at tip {} in {}ms: {} confirmed, {} unconfirmed.",
			tip_header.block_hash(),
			start_time.elapsed().as_millis(),
			num_confirmed,
			num_unconfirmed
		);
		#[cfg(not(feature = "time"))]
		log_debug!(
			self.logger,
			"Finished transaction sync at tip {}: {} confirmed, {} unconfirmed.",
			tip_header.block_hash(),
			num_confirmed,
			num_unconfirmed
		);
		Ok(())
	}

	fn check_update_tip(
		&self, cur_tip_header: &mut Header, cur_tip_height: &mut u32,
	) -> Result<bool, InternalError> {
		let check_notification = self.client.block_headers_subscribe()?;
		let check_tip_hash = check_notification.header.block_hash();

		// Restart if either the tip changed or we got some divergent tip
		// change notification since we started. In the latter case we
		// make sure we clear the queue before continuing.
		let mut restart_sync = check_tip_hash != cur_tip_header.block_hash();
		while let Some(queued_notif) = self.client.block_headers_pop()? {
			if queued_notif.header.block_hash() != check_tip_hash {
				restart_sync = true
			}
		}

		if restart_sync {
			*cur_tip_header = check_notification.header;
			*cur_tip_height = check_notification.height as u32;
			Ok(true)
		} else {
			Ok(false)
		}
	}

	fn get_confirmed_transactions(
		&self, sync_state: &SyncState,
	) -> Result<Vec<ConfirmedTx>, InternalError> {
		// First, check the confirmation status of registered transactions as well as the
		// status of dependent transactions of registered outputs.
		let mut confirmed_txs: Vec<ConfirmedTx> = Vec::new();
		let mut watched_script_pubkeys = Vec::with_capacity(
			sync_state.watched_transactions.len() + sync_state.watched_outputs.len(),
		);
		let mut watched_txs = Vec::with_capacity(sync_state.watched_transactions.len());

		for txid in &sync_state.watched_transactions {
			match self.client.transaction_get(&txid) {
				Ok(tx) => {
					// Bitcoin Core's Merkle tree implementation has no way to discern between
					// internal and leaf node entries. As a consequence it is susceptible to an
					// attacker injecting additional transactions by crafting 64-byte
					// transactions matching an inner Merkle node's hash (see
					// https://web.archive.org/web/20240329003521/https://bitslog.com/2018/06/09/leaf-node-weakness-in-bitcoin-merkle-tree-design/).
					// To protect against this (highly unlikely) attack vector, we check that the
					// transaction is at least 65 bytes in length.
					if tx.total_size() == 64 {
						log_error!(self.logger, "Skipping transaction {} due to retrieving potentially invalid tx data.", txid);
						continue;
					}

					watched_txs.push((txid, tx.clone()));
					if let Some(tx_out) = tx.output.first() {
						// We watch an arbitrary output of the transaction of interest in order to
						// retrieve the associated script history, before narrowing down our search
						// through `filter`ing by `txid` below.
						watched_script_pubkeys.push(tx_out.script_pubkey.clone());
					} else {
						debug_assert!(false, "Failed due to retrieving invalid tx data.");
						log_error!(self.logger, "Failed due to retrieving invalid tx data.");
						return Err(InternalError::Failed);
					}
				},
				Err(electrum_client::Error::Protocol(_)) => {
					// We couldn't find the tx, do nothing.
				},
				Err(e) => {
					log_error!(self.logger, "Failed to look up transaction {}: {}.", txid, e);
					return Err(InternalError::Failed);
				},
			}
		}

		let num_tx_lookups = watched_script_pubkeys.len();
		debug_assert_eq!(num_tx_lookups, watched_txs.len());

		for output in sync_state.watched_outputs.values() {
			watched_script_pubkeys.push(output.script_pubkey.clone());
		}

		let num_output_spend_lookups = watched_script_pubkeys.len() - num_tx_lookups;
		debug_assert_eq!(num_output_spend_lookups, sync_state.watched_outputs.len());

		match self.client.batch_script_get_history(watched_script_pubkeys.iter().map(|s| s.deref()))
		{
			Ok(results) => {
				let (tx_results, output_results) = results.split_at(num_tx_lookups);
				debug_assert_eq!(num_output_spend_lookups, output_results.len());

				for (i, script_history) in tx_results.iter().enumerate() {
					let (txid, tx) = &watched_txs[i];
					if confirmed_txs.iter().any(|ctx| ctx.txid == **txid) {
						continue;
					}
					let mut filtered_history =
						script_history.iter().filter(|h| h.tx_hash == **txid);
					if let Some(history) = filtered_history.next() {
						let prob_conf_height = history.height as u32;
						let confirmed_tx = self.get_confirmed_tx(tx, prob_conf_height)?;
						confirmed_txs.push(confirmed_tx);
					}
					debug_assert!(filtered_history.next().is_none());
				}

				for (watched_output, script_history) in
					sync_state.watched_outputs.values().zip(output_results)
				{
					for possible_output_spend in script_history {
						if possible_output_spend.height <= 0 {
							continue;
						}

						let txid = possible_output_spend.tx_hash;
						if confirmed_txs.iter().any(|ctx| ctx.txid == txid) {
							continue;
						}

						match self.client.transaction_get(&txid) {
							Ok(tx) => {
								let mut is_spend = false;
								for txin in &tx.input {
									let watched_outpoint =
										watched_output.outpoint.into_bitcoin_outpoint();
									if txin.previous_output == watched_outpoint {
										is_spend = true;
										break;
									}
								}

								if !is_spend {
									continue;
								}

								let prob_conf_height = possible_output_spend.height as u32;
								let confirmed_tx = self.get_confirmed_tx(&tx, prob_conf_height)?;
								confirmed_txs.push(confirmed_tx);
							},
							Err(e) => {
								log_trace!(
									self.logger,
									"Inconsistency: Tx {} was unconfirmed during syncing: {}",
									txid,
									e
								);
								return Err(InternalError::Inconsistency);
							},
						}
					}
				}
			},
			Err(e) => {
				log_error!(self.logger, "Failed to look up script histories: {}.", e);
				return Err(InternalError::Failed);
			},
		}

		// Sort all confirmed transactions first by block height, then by in-block
		// position, and finally feed them to the interface in order.
		confirmed_txs.sort_unstable_by(|tx1, tx2| {
			tx1.block_height.cmp(&tx2.block_height).then_with(|| tx1.pos.cmp(&tx2.pos))
		});

		Ok(confirmed_txs)
	}

	fn get_unconfirmed_transactions<C: Deref>(
		&self, confirmables: &Vec<C>,
	) -> Result<Vec<Txid>, InternalError>
	where
		C::Target: Confirm,
	{
		// Query the interface for relevant txids and check whether the relevant blocks are still
		// in the best chain, mark them unconfirmed otherwise
		let relevant_txids = confirmables
			.iter()
			.flat_map(|c| c.get_relevant_txids())
			.collect::<HashSet<(Txid, u32, Option<BlockHash>)>>();

		let mut unconfirmed_txs = Vec::new();

		for (txid, conf_height, block_hash_opt) in relevant_txids {
			if let Some(block_hash) = block_hash_opt {
				let block_header = self.client.block_header(conf_height as usize)?;
				if block_header.block_hash() == block_hash {
					// Skip if the tx is still confirmed in the block in question.
					continue;
				}

				unconfirmed_txs.push(txid);
			} else {
				log_error!(self.logger,
					"Untracked confirmation of funding transaction. Please ensure none of your channels had been created with LDK prior to version 0.0.113!");
				panic!("Untracked confirmation of funding transaction. Please ensure none of your channels had been created with LDK prior to version 0.0.113!");
			}
		}
		Ok(unconfirmed_txs)
	}

	fn get_confirmed_tx(
		&self, tx: &Transaction, prob_conf_height: u32,
	) -> Result<ConfirmedTx, InternalError> {
		let txid = tx.compute_txid();
		match self.client.transaction_get_merkle(&txid, prob_conf_height as usize) {
			Ok(merkle_res) => {
				debug_assert_eq!(prob_conf_height, merkle_res.block_height as u32);
				match self.client.block_header(prob_conf_height as usize) {
					Ok(block_header) => {
						let pos = merkle_res.pos;
						if !validate_merkle_proof(&txid, &block_header.merkle_root, &merkle_res) {
							log_trace!(
								self.logger,
								"Inconsistency: Block {} was unconfirmed during syncing.",
								block_header.block_hash()
							);
							return Err(InternalError::Inconsistency);
						}
						let confirmed_tx = ConfirmedTx {
							tx: tx.clone(),
							txid,
							block_header,
							block_height: prob_conf_height,
							pos,
						};
						Ok(confirmed_tx)
					},
					Err(e) => {
						log_error!(
							self.logger,
							"Failed to retrieve block header for height {}: {}.",
							prob_conf_height,
							e
						);
						Err(InternalError::Failed)
					},
				}
			},
			Err(e) => {
				log_trace!(
					self.logger,
					"Inconsistency: Tx {} was unconfirmed during syncing: {}",
					txid,
					e
				);
				Err(InternalError::Inconsistency)
			},
		}
	}

	/// Returns a reference to the underlying Electrum client.
	///
	/// This is not exported to bindings users as the underlying client from BDK is not exported.
	pub fn client(&self) -> &ElectrumClient {
		&self.client
	}
}

impl<L: Deref> Filter for ElectrumSyncClient<L>
where
	L::Target: Logger,
{
	fn register_tx(&self, txid: &Txid, _script_pubkey: &Script) {
		let mut locked_queue = self.queue.lock().unwrap();
		locked_queue.transactions.insert(*txid);
	}

	fn register_output(&self, output: WatchedOutput) {
		let mut locked_queue = self.queue.lock().unwrap();
		locked_queue.outputs.insert(output.outpoint.into_bitcoin_outpoint(), output);
	}
}
