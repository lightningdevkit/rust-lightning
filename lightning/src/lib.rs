// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

#![crate_name = "lightning"]

//! Rust-Lightning, not Rusty's Lightning!
//!
//! A full-featured but also flexible lightning implementation, in library form. This allows the
//! user (you) to decide how they wish to use it instead of being a fully self-contained daemon.
//! This means there is no built-in threading/execution environment and it's up to the user to
//! figure out how best to make networking happen/timers fire/things get written to disk/keys get
//! generated/etc. This makes it a good candidate for tight integration into an existing wallet
//! instead of having a rather-separate lightning appendage to a wallet.

#![cfg_attr(not(any(feature = "fuzztarget", feature = "_test_utils")), deny(missing_docs))]
#![cfg_attr(not(any(test, feature = "fuzztarget", feature = "_test_utils")), forbid(unsafe_code))]
#![deny(broken_intra_doc_links)]

// In general, rust is absolutely horrid at supporting users doing things like,
// for example, compiling Rust code for real environments. Disable useless lints
// that don't do anything but annoy us and cant actually ever be resolved.
#![allow(bare_trait_objects)]
#![allow(ellipsis_inclusive_range_patterns)]

#![cfg_attr(all(any(test, feature = "_test_utils"), feature = "unstable"), feature(test))]
#[cfg(all(any(test, feature = "_test_utils"), feature = "unstable"))] extern crate test;

extern crate bitcoin;
#[cfg(any(test, feature = "_test_utils"))] extern crate hex;
#[cfg(any(test, feature = "fuzztarget", feature = "_test_utils"))] extern crate regex;

#[macro_use]
pub mod util;
pub mod chain;
pub mod ln;
pub mod routing;
