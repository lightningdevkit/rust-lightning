// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.
#![crate_name = "lightning_liquidity"]

//! # `lightning-liquidity`
//! Types and primitives to integrate a spec-compliant LSP with an LDK-based node.
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(rustdoc::private_intra_doc_links)]
#![allow(bare_trait_objects)]
#![allow(ellipsis_inclusive_range_patterns)]
#![allow(clippy::drop_non_drop)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]
#[cfg(not(any(feature = "std", feature = "no-std")))]
compile_error!("at least one of the `std` or `no-std` features must be enabled");

#[macro_use]
extern crate alloc;

mod prelude {
	#![allow(unused_imports)]
	#[cfg(feature = "hashbrown")]
	extern crate hashbrown;

	#[cfg(feature = "hashbrown")]
	pub use self::hashbrown::{hash_map, HashMap, HashSet};
	pub use alloc::{boxed::Box, collections::VecDeque, string::String, vec, vec::Vec};
	#[cfg(not(feature = "hashbrown"))]
	pub use std::collections::{hash_map, HashMap, HashSet};

	pub use alloc::borrow::ToOwned;
	pub use alloc::string::ToString;
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
