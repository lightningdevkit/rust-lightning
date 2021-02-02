//! A very simple serialization framework which is used to serialize/deserialize messages as well
//! as ChannelsManagers and ChannelMonitors.

use std::ffi::c_void;
use bitcoin::hashes::Hash;
use crate::c_types::*;


#[no_mangle]
pub static MAX_BUF_SIZE: usize = lightning::util::ser::MAX_BUF_SIZE;
