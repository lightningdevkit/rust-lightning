//! High level lightning structs and impls live here.
//!
//! You probably want to create a channelmanager::ChannelManager, and a routing::NetGraphMsgHandler first.
//! Then, you probably want to pass them both on to a peer_handler::PeerManager and use that to
//! create/manage connections and call get_and_clear_pending_events after each action, handling
//! them appropriately.
//!
//! When you want to open/close a channel or send a payment, call into your ChannelManager and when
//! you want to learn things about the network topology (eg get a route for sending a payment),
//! call into your NetGraphMsgHandler.

pub mod channelmanager;
pub mod channelmonitor;
pub mod msgs;
pub mod peer_handler;
pub mod chan_utils;
pub mod features;
pub(crate) mod onchaintx;

#[cfg(feature = "fuzztarget")]
pub mod peer_channel_encryptor;
#[cfg(not(feature = "fuzztarget"))]
pub(crate) mod peer_channel_encryptor;

mod channel;
mod onion_utils;
mod wire;

#[cfg(test)]
#[macro_use]
pub(crate) mod functional_test_utils;
#[cfg(test)]
mod functional_tests;
#[cfg(test)]
mod chanmon_update_fail_tests;
#[cfg(test)]
mod reorg_tests;

pub use self::peer_channel_encryptor::LN_MAX_MSG_LEN;
