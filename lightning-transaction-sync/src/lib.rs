//! Provides utilities for syncing LDK via the transaction-based [`Confirm`] interface.
//!
//! The provided synchronization clients need to be registered with a [`ChainMonitor`] via the
//! [`Filter`] interface. Then, the respective `fn sync` needs to be called with the [`Confirm`]
//! implementations to be synchronized, i.e., usually instances of [`ChannelManager`] and
//! [`ChainMonitor`].
//!
//! ## Features and Backend Support
//!
//!- `esplora_blocking` enables syncing against an Esplora backend based on a blocking client.
//!- `esplora_async` enables syncing against an Esplora backend based on an async client.
//!
//! ## Version Compatibility
//!
//! Currently this crate is compatible with nodes that were created with LDK version 0.0.113 and above.
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

// Prefix these with `rustdoc::` when we update our MSRV to be >= 1.52 to remove warnings.
#![deny(broken_intra_doc_links)]
#![deny(private_intra_doc_links)]

#![deny(missing_docs)]
#![deny(unsafe_code)]

#![cfg_attr(docsrs, feature(doc_auto_cfg))]

#[cfg(any(feature = "esplora-blocking", feature = "esplora-async"))]
#[macro_use]
extern crate bdk_macros;

#[cfg(any(feature = "esplora-blocking", feature = "esplora-async"))]
mod esplora;

#[cfg(any(feature = "esplora-blocking", feature = "esplora-async"))]
mod common;

mod error;
pub use error::TxSyncError;

#[cfg(any(feature = "esplora-blocking", feature = "esplora-async"))]
pub use esplora::EsploraSyncClient;
