#[cfg(not(feature = "std"))]
/// Re-export of either `core2::io` or `std::io`, depending on the `std` feature flag.
pub use core2::io::*;
#[cfg(feature = "std")]
/// Re-export of either `core2::io` or `std::io`, depending on the `std` feature flag.
pub use std::io::*;
