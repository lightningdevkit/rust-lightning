// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Contains LSPS0 event types

use crate::prelude::Vec;
use bitcoin::secp256k1::PublicKey;

/// An event which an LSPS0 client may want to take some action in response to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LSPS0ClientEvent {
	/// Information from the LSP about the protocols they support.
	ListProtocolsResponse {
		/// The node id of the LSP.
		counterparty_node_id: PublicKey,
		/// A list of supported protocols.
		protocols: Vec<u16>,
	},
}
