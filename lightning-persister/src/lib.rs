//! Provides utilities for LDK data persistence and retrieval.
//
// TODO: Prefix these with `rustdoc::` when we update our MSRV to be >= 1.52 to remove warnings.
#![deny(broken_intra_doc_links)]
#![deny(private_intra_doc_links)]

#![deny(missing_docs)]

#![cfg_attr(docsrs, feature(doc_auto_cfg))]

#[cfg(ldk_bench)] extern crate criterion;

pub mod fs_store;

mod utils;

#[cfg(test)]
mod test_utils;
