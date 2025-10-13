// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Provides utilities for syncing LDK via the transaction-based [`Confirm`] interface.
//!
//! The provided synchronization clients need to be registered with a [`ChainMonitor`] via the
//! [`Filter`] interface. Then, the respective `fn sync` needs to be called with the [`Confirm`]
//! implementations to be synchronized, i.e., usually instances of [`ChannelManager`] and
//! [`ChainMonitor`].
//!
//! ## Features and Backend Support
//!
//!- `esplora-blocking` enables syncing against an Esplora backend based on a blocking client.
//!- `esplora-async` enables syncing against an Esplora backend based on an async client.
//!- `esplora-async-https` enables the async Esplora client with support for HTTPS.
//!
//! ## Version Compatibility
//!
//! Currently this crate is compatible with LDK version 0.0.114 and above using channels which were
//! created on LDK version 0.0.113 and above.
//!
//! ## Usage Example:
//!
//! ```ignore
//! let tx_sync = Arc::new(EsploraSyncClient::new(
//! 	esplora_server_url,
//! 	Arc::clone(&some_logger),
//! ));
//!
//! let chain_monitor = Arc::new(ChainMonitor::new(
//! 	Some(Arc::clone(&tx_sync)),
//! 	Arc::clone(&some_broadcaster),
//! 	Arc::clone(&some_logger),
//! 	Arc::clone(&some_fee_estimator),
//! 	Arc::clone(&some_persister),
//! ));
//!
//! let channel_manager = Arc::new(ChannelManager::new(
//! 	Arc::clone(&some_fee_estimator),
//! 	Arc::clone(&chain_monitor),
//! 	Arc::clone(&some_broadcaster),
//! 	Arc::clone(&some_router),
//! 	Arc::clone(&some_logger),
//! 	Arc::clone(&some_entropy_source),
//! 	Arc::clone(&some_node_signer),
//! 	Arc::clone(&some_signer_provider),
//! 	user_config,
//! 	chain_params,
//! ));
//!
//! let confirmables = vec![
//! 	&*channel_manager as &(dyn Confirm + Sync + Send),
//! 	&*chain_monitor as &(dyn Confirm + Sync + Send),
//! ];
//!
//! tx_sync.sync(confirmables).unwrap();
//! ```
//!
//! [`Confirm`]: lightning::chain::Confirm
//! [`Filter`]: lightning::chain::Filter
//! [`ChainMonitor`]: lightning::chain::chainmonitor::ChainMonitor
//! [`ChannelManager`]: lightning::ln::channelmanager::ChannelManager

#![deny(rustdoc::broken_intra_doc_links)]
#![deny(rustdoc::private_intra_doc_links)]
#![deny(missing_docs)]
#![deny(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]

#[cfg(any(feature = "esplora-blocking", feature = "esplora-async"))]
mod esplora;

#[cfg(any(feature = "_electrum"))]
mod electrum;

#[cfg(any(feature = "esplora-blocking", feature = "esplora-async", feature = "_electrum"))]
mod common;
#[cfg(any(feature = "esplora-blocking", feature = "esplora-async", feature = "_electrum"))]
mod error;
#[cfg(any(feature = "esplora-blocking", feature = "esplora-async", feature = "_electrum"))]
pub use error::TxSyncError;

#[cfg(feature = "_electrum")]
pub use electrum::ElectrumSyncClient;
#[cfg(any(feature = "esplora-blocking", feature = "esplora-async"))]
pub use esplora::EsploraSyncClient;
