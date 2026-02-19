// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Some utility modules live here. See individual sub-modules for more info.

#[macro_use]
pub(crate) mod fuzz_wrappers;

#[macro_use]
pub mod ser_macros;

#[cfg(any(test, feature = "_test_utils"))]
pub mod mut_global;

pub mod anchor_channel_reserves;

pub mod async_poll;
#[cfg(fuzzing)]
pub mod base32;
#[cfg(not(fuzzing))]
pub(crate) mod base32;
pub mod errors;
pub mod message_signing;
pub mod native_async;
pub mod persist;
pub mod scid_utils;
pub mod ser;
pub mod sweep;
pub mod wakers;

pub(crate) mod atomic_counter;
pub(crate) mod byte_utils;
pub mod hash_tables;
pub(crate) mod transaction_utils;

#[cfg(feature = "std")]
pub(crate) mod time;

pub mod indexed_map;

/// Logging macro utilities.
#[macro_use]
pub(crate) mod macro_logger;

// These have to come after macro_logger to build
pub mod config;
pub mod logger;
pub mod wallet_utils;

#[cfg(any(test, feature = "_test_utils"))]
pub mod test_utils;

/// impls of traits that add exra enforcement on the way they're called. Useful for detecting state
/// machine errors and used in fuzz targets and tests.
#[cfg(any(test, feature = "_test_utils"))]
pub mod test_channel_signer;

/// A macro to delegate trait implementations to a field of a struct.
///
/// For example:
/// ```ignore
/// use lightning::delegate;
/// delegate!(A, T, inner,
///     fn b(, c: u64) -> u64,
///     fn m(mut, d: u64) -> (),
///     fn o(, ) -> u64,
///     #[cfg(debug_assertions)]
///     fn t(,) -> (),
///     ;
///     type O = u64,
///     #[cfg(debug_assertions)]
///     type T = (),
/// );
/// ```
///
/// where T is the trait to be implemented, A is the struct
/// to implement the trait for, and inner is the field of A
/// to delegate the trait implementation to.
#[cfg(any(test, feature = "_test_utils"))]
macro_rules! delegate {
    ($N: ident, $T: ident, $ref: ident,
        $($(#[$fpat: meta])? fn $f: ident($($mu: ident)?, $($n: ident: $t: ty),*) -> $r: ty),* $(,)?
        $(;$($(#[$tpat: meta])? type $TN: ident = $TT: ty),*)? $(,)?
    ) => {
        impl $T for $N {
            $(
                $(#[$fpat])?
                fn $f(&$($mu)? self, $($n: $t),*) ->  $r {
                   $T::$f(&$($mu)? *self.$ref, $($n),*)
               }
            )*
            $($(
                $(#[$tpat])?
                type $TN = $TT;
            )*)?
        }
    };
}

#[cfg(any(test, feature = "_test_utils"))]
pub mod dyn_signer;
