// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Onion Messages: sending, receiving, forwarding, and ancillary utilities live here

mod blinded_route;
mod messenger;
mod packet;
mod utils;

// Re-export structs so they can be imported with just the `onion_message::` module prefix.
pub use self::blinded_route::{BlindedRoute, BlindedHop};
pub use self::messenger::{OnionMessenger, SimpleArcOnionMessenger, SimpleRefOnionMessenger};
pub(crate) use self::packet::Packet;
