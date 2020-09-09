//! Structs and impls for receiving messages about the network and storing the topology live here.

use std::ffi::c_void;
use bitcoin::hashes::Hash;
use crate::c_types::*;

pub mod router;
pub mod network_graph;
