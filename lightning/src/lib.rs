#![crate_name = "lightning"]

//! Rust-Lightning, not Rusty's Lightning!
//!
//! A full-featured but also flexible lightning implementation, in library form. This allows the
//! user (you) to decide how they wish to use it instead of being a fully self-contained daemon.
//! This means there is no built-in threading/execution environment and it's up to the user to
//! figure out how best to make networking happen/timers fire/things get written to disk/keys get
//! generated/etc. This makes it a good candidate for tight integration into an existing wallet
//! instead of having a rather-separate lightning appendage to a wallet.

#![cfg_attr(not(feature = "fuzztarget"), deny(missing_docs))]
#![forbid(unsafe_code)]

// In general, rust is absolutely horrid at supporting users doing things like,
// for example, compiling Rust code for real environments. Disable useless lints
// that don't do anything but annoy us and cant actually ever be resolved.
#![allow(bare_trait_objects)]
#![allow(ellipsis_inclusive_range_patterns)]

extern crate bitcoin;
extern crate bitcoin_hashes;
extern crate secp256k1;
#[cfg(test)] extern crate rand;
#[cfg(test)] extern crate hex;
#[cfg(all(test, feature = "mutation_testing"))] extern crate mutagen;

#[macro_use]
pub mod util;
pub mod chain;
pub mod ln;

#[cfg(all(
		any(feature = "mutation_testing", feature = "fuzztarget"),
		not(any(test, debug_assertions))
		))]
const ERR: () = "You should never be building with feature = mutation_testing or feature = fuzztarget! They are used to compile with broken code for testing only!";
