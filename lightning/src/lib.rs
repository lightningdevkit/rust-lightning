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
//!
//! `default` features are:
//!
//! * `std` - enables functionalities which require `std`, including `std::io` trait implementations and things which utilize time
//! * `grind_signatures` - enables generation of [low-r bitcoin signatures](https://bitcoin.stackexchange.com/questions/111660/what-is-signature-grinding),
//! which saves 1 byte per signature in 50% of the cases (see [bitcoin PR #13666](https://github.com/bitcoin/bitcoin/pull/13666))
//!
//! Available features are:
//!
//! * `std`
//! * `grind_signatures`
//! * `no-std ` - exposes write trait implementations from the `core2` crate (at least one of `no-std` or `std` are required)
//! * Skip logging of messages at levels below the given log level:
//!     * `max_level_off`
//!     * `max_level_error`
//!     * `max_level_warn`
//!     * `max_level_info`
//!     * `max_level_debug`
//!     * `max_level_trace`

#![cfg_attr(not(any(test, fuzzing, feature = "_test_utils")), deny(missing_docs))]
#![cfg_attr(not(any(test, fuzzing, feature = "_test_utils")), forbid(unsafe_code))]

// Prefix these with `rustdoc::` when we update our MSRV to be >= 1.52 to remove warnings.
#![deny(broken_intra_doc_links)]
#![deny(private_intra_doc_links)]

// In general, rust is absolutely horrid at supporting users doing things like,
// for example, compiling Rust code for real environments. Disable useless lints
// that don't do anything but annoy us and cant actually ever be resolved.
#![allow(bare_trait_objects)]
#![allow(ellipsis_inclusive_range_patterns)]

#![cfg_attr(docsrs, feature(doc_auto_cfg))]

#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]

#![cfg_attr(all(any(test, feature = "_test_utils"), feature = "_bench_unstable"), feature(test))]
#[cfg(all(any(test, feature = "_test_utils"), feature = "_bench_unstable"))] extern crate test;

#[cfg(not(any(feature = "std", feature = "no-std")))]
compile_error!("at least one of the `std` or `no-std` features must be enabled");

#[cfg(all(fuzzing, test))]
compile_error!("Tests will always fail with cfg=fuzzing");

#[macro_use]
extern crate alloc;
extern crate bitcoin;
#[cfg(any(test, feature = "std"))]
extern crate core;

#[cfg(any(test, feature = "_test_utils"))] extern crate hex;
#[cfg(any(test, fuzzing, feature = "_test_utils"))] extern crate regex;

#[cfg(not(feature = "std"))] extern crate core2;

#[macro_use]
pub mod util;
pub mod chain;
pub mod ln;
pub mod offers;
pub mod routing;
pub mod onion_message;

#[cfg(feature = "std")]
/// Re-export of either `core2::io` or `std::io`, depending on the `std` feature flag.
pub use std::io;
#[cfg(not(feature = "std"))]
/// Re-export of either `core2::io` or `std::io`, depending on the `std` feature flag.
pub use core2::io;

#[cfg(not(feature = "std"))]
mod io_extras {
	use core2::io::{self, Read, Write};

	/// A writer which will move data into the void.
	pub struct Sink {
		_priv: (),
	}

	/// Creates an instance of a writer which will successfully consume all data.
	pub const fn sink() -> Sink {
		Sink { _priv: () }
	}

	impl core2::io::Write for Sink {
		#[inline]
		fn write(&mut self, buf: &[u8]) -> core2::io::Result<usize> {
			Ok(buf.len())
		}

		#[inline]
		fn flush(&mut self) -> core2::io::Result<()> {
			Ok(())
		}
	}

	pub fn copy<R: ?Sized, W: ?Sized>(reader: &mut R, writer: &mut W) -> Result<u64, io::Error>
		where
		R: Read,
		W: Write,
	{
		let mut count = 0;
		let mut buf = [0u8; 64];

		loop {
			match reader.read(&mut buf) {
				Ok(0) => break,
				Ok(n) => { writer.write_all(&buf[0..n])?; count += n as u64; },
				Err(ref e) if e.kind() == io::ErrorKind::Interrupted => {},
				Err(e) => return Err(e.into()),
			};
		}
		Ok(count)
	}

	pub fn read_to_end<D: io::Read>(mut d: D) -> Result<alloc::vec::Vec<u8>, io::Error> {
		let mut result = vec![];
		let mut buf = [0u8; 64];
		loop {
			match d.read(&mut buf) {
				Ok(0) => break,
				Ok(n) => result.extend_from_slice(&buf[0..n]),
				Err(ref e) if e.kind() == io::ErrorKind::Interrupted => {},
				Err(e) => return Err(e.into()),
			};
		}
		Ok(result)
	}
}

#[cfg(feature = "std")]
mod io_extras {
	pub fn read_to_end<D: ::std::io::Read>(mut d: D) -> Result<Vec<u8>, ::std::io::Error> {
		let mut buf = Vec::new();
		d.read_to_end(&mut buf)?;
		Ok(buf)
	}

	pub use std::io::{copy, sink};
}

mod prelude {
	#[cfg(feature = "hashbrown")]
	extern crate hashbrown;

	pub use alloc::{vec, vec::Vec, string::String, collections::VecDeque, boxed::Box};
	#[cfg(not(feature = "hashbrown"))]
	pub use std::collections::{HashMap, HashSet, hash_map};
	#[cfg(feature = "hashbrown")]
	pub use self::hashbrown::{HashMap, HashSet, hash_map};

	pub use alloc::borrow::ToOwned;
	pub use alloc::string::ToString;
}

#[cfg(all(not(feature = "_bench_unstable"), feature = "backtrace", feature = "std", test))]
extern crate backtrace;

mod sync;
