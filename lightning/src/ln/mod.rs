//! High level lightning structs and impls live here.
//!
//! You probably want to create a channelmanager::ChannelManager, and a router::Router first.
//! Then, you probably want to pass them both on to a peer_handler::PeerManager and use that to
//! create/manage connections and call get_and_clear_pending_events after each action, handling
//! them appropriately.
//!
//! When you want to open/close a channel or send a payment, call into your ChannelManager and when
//! you want to learn things about the network topology (eg get a route for sending a payment),
//! call into your Router.

pub mod channelmanager;
pub mod channelmonitor;
pub mod msgs;
pub mod router;
pub mod peer_handler;

#[cfg(feature = "fuzztarget")]
pub mod peer_channel_encryptor;
#[cfg(not(feature = "fuzztarget"))]
pub(crate) mod peer_channel_encryptor;

mod channel;
mod chan_utils;
mod onion_utils;

#[cfg(test)]
#[macro_use] mod functional_test_utils;
#[cfg(test)]
mod functional_tests;
#[cfg(test)]
mod chanmon_update_fail_tests;
