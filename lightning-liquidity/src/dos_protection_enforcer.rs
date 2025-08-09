//! DoS Protection Enforcement for LSP operations.
//!
//! This module provides mechanisms to prevent denial-of-service attacks
//! when using the Lightning Service Provider (LSP) protocols.

#[cfg(lsps1_service)]
use crate::lsps1::service::LSPS1ServiceHandler;
use crate::lsps2::service::LSPS2ServiceHandler;
use crate::lsps5::service::LSPS5ServiceHandler;
use crate::utils::time::TimeProvider;
use bitcoin::secp256k1::PublicKey;
use core::ops::Deref;
#[cfg(lsps1_service)]
use lightning::chain::Filter;
use lightning::ln::channelmanager::AChannelManager;
#[cfg(lsps1_service)]
use lightning::sign::EntropySource;
use lightning::sign::NodeSigner;

/// A trait for implementing Denial-of-Service (DoS) protection mechanisms for LSP services.
pub trait DosProtectionEnforcer {
	/// Checks if the specified peer is currently engaged in an ongoing operation.
	///
	/// Different LSP protocols have different definitions of "engagement":
	/// - **LSPS1**: Checks for active channel order requests
	/// - **LSPS2**: Checks for pending channel open requests  
	/// - **LSPS5**: Checks for existing open channels with the client
	fn is_engaged(&self, counterparty_node_id: &PublicKey) -> bool;
}

#[cfg(lsps1_service)]
impl<ES: Deref, CM: Deref + Clone, C: Deref> DosProtectionEnforcer
	for LSPS1ServiceHandler<ES, CM, C>
where
	ES::Target: EntropySource,
	CM::Target: AChannelManager,
	C::Target: Filter,
{
	fn is_engaged(&self, counterparty_node_id: &PublicKey) -> bool {
		self.has_active_requests(counterparty_node_id)
	}
}

impl<CM: Deref> DosProtectionEnforcer for LSPS2ServiceHandler<CM>
where
	CM::Target: AChannelManager,
{
	fn is_engaged(&self, counterparty_node_id: &PublicKey) -> bool {
		self.has_pending_channel_open_request(counterparty_node_id)
	}
}

impl<CM: Deref, NS: Deref, TP: Deref> DosProtectionEnforcer for LSPS5ServiceHandler<CM, NS, TP>
where
	CM::Target: AChannelManager,
	TP::Target: TimeProvider,
	NS::Target: NodeSigner,
{
	fn is_engaged(&self, counterparty_node_id: &PublicKey) -> bool {
		self.client_has_open_channel(counterparty_node_id)
	}
}
