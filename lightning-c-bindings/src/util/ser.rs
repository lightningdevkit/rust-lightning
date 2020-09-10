//! A very simple serialization framework which is used to serialize/deserialize messages as well
//! as ChannelsManagers and ChannelMonitors.

use std::ffi::c_void;
use bitcoin::hashes::Hash;
use crate::c_types::*;

