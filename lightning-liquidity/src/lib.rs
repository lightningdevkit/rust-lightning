// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.
#![crate_name = "lightning_liquidity"]

//! The goal of this crate is to provide types and primitives to integrate a spec-compliant LSP with an LDK-based node. To this end, this crate provides client-side as well as service-side logic to implement the [LSP specifications].
//!
//! Currently the following specifications are supported:
//! - [LSPS0] defines the transport protocol with the LSP over which the other protocols communicate.
//! - [LSPS1] allows to order Lightning channels from an LSP. This is useful when the client needs
//! inbound Lightning liquidity for which they are willing and able to pay in bitcoin.
//! - [LSPS2] allows to generate a special invoice for which, when paid, an LSP will open a "just-in-time".
//! This is useful for the initial on-boarding of clients as the channel opening fees are deducted
//! from the incoming payment, i.e., no funds are required client-side to initiate this flow.
//!
//! To get started, you'll want to setup a [`LiquidityManager`] and configure it to be the
//! [`CustomMessageHandler`] of your LDK node. You can then for example call
//! [`LiquidityManager::lsps1_client_handler`] / [`LiquidityManager::lsps2_client_handler`], or
//! [`LiquidityManager::lsps2_service_handler`], to access the respective client-side or
//! service-side handlers.
//!
//! [`LiquidityManager`] uses an eventing system to notify the user about important updates to the
//! protocol flow. To this end, you will need to handle events emitted via one of the event
//! handling methods provided by [`LiquidityManager`], e.g., [`LiquidityManager::next_event`].
//!
//! [LSP specifications]: https://github.com/BitcoinAndLightningLayerSpecs/lsp
//! [LSPS0]: https://github.com/BitcoinAndLightningLayerSpecs/lsp/tree/main/LSPS0
//! [LSPS1]: https://github.com/BitcoinAndLightningLayerSpecs/lsp/tree/main/LSPS1
//! [LSPS2]: https://github.com/BitcoinAndLightningLayerSpecs/lsp/tree/main/LSPS2
//! [`CustomMessageHandler`]: lightning::ln::peer_handler::CustomMessageHandler
//! [`LiquidityManager::next_event`]: crate::LiquidityManager::next_event
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(rustdoc::private_intra_doc_links)]
#![allow(bare_trait_objects)]
#![allow(ellipsis_inclusive_range_patterns)]
#![allow(clippy::drop_non_drop)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]

#[macro_use]
extern crate alloc;

mod prelude {
	#![allow(unused_imports)]
	pub use alloc::{boxed::Box, collections::VecDeque, string::String, vec, vec::Vec};

	pub use alloc::borrow::ToOwned;
	pub use alloc::string::ToString;

	pub(crate) use lightning::util::hash_tables::*;
}

pub mod events;
pub mod lsps0;
pub mod lsps1;
pub mod lsps2;
mod manager;
pub mod message_queue;
mod sync;
#[cfg(test)]
mod tests;
mod utils;

pub use manager::{LiquidityClientConfig, LiquidityManager, LiquidityServiceConfig};
