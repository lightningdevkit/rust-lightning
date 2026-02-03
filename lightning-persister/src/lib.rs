//! Provides utilities for LDK data persistence and retrieval.

#![deny(rustdoc::broken_intra_doc_links)]
#![deny(rustdoc::private_intra_doc_links)]
#![deny(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]

#[cfg(ldk_bench)]
extern crate criterion;

pub mod fs_store;

mod fs_store_common;
mod utils;

#[cfg(test)]
mod test_utils;
