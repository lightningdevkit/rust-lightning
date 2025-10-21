//! A dynamically dispatched signer

use crate::prelude::*;

use core::any::Any;

use crate::ln::chan_utils::{
	ChannelPublicKeys, ChannelTransactionParameters, ClosingTransaction, CommitmentTransaction,
	HTLCOutputInCommitment, HolderCommitmentTransaction,
};
use crate::ln::inbound_payment::ExpandedKey;
use crate::ln::msgs::{UnsignedChannelAnnouncement, UnsignedGossipMessage};
use crate::ln::script::ShutdownScript;
use crate::sign::ecdsa::EcdsaChannelSigner;
#[cfg(taproot)]
use crate::sign::taproot::TaprootChannelSigner;
use crate::sign::InMemorySigner;
use crate::sign::{ChannelSigner, ReceiveAuthKey};
use crate::sign::{EntropySource, HTLCDescriptor, OutputSpender, PhantomKeysManager};
use crate::sign::{
	NodeSigner, PeerStorageKey, Recipient, SignerProvider, SpendableOutputDescriptor,
};
use bitcoin;
use bitcoin::absolute::LockTime;
use bitcoin::secp256k1::All;
use bitcoin::{secp256k1, ScriptBuf, Transaction, TxOut, Txid};
use lightning_invoice::RawBolt11Invoice;
#[cfg(taproot)]
use musig2::types::{PartialSignature, PublicNonce};
use secp256k1::ecdsa::RecoverableSignature;
use secp256k1::{ecdh::SharedSecret, ecdsa::Signature, PublicKey, Scalar, Secp256k1, SecretKey};
use types::payment::PaymentPreimage;

#[cfg(not(taproot))]
/// A super-trait for all the traits that a dyn signer backing implements
pub trait DynSignerTrait: EcdsaChannelSigner + Send + Sync {}

#[cfg(taproot)]
/// A super-trait for all the traits that a dyn signer backing implements
pub trait DynSignerTrait: EcdsaChannelSigner + TaprootChannelSigner + Send + Sync {}

/// Helper to allow DynSigner to clone itself
pub trait InnerSign: DynSignerTrait {
	/// Clone into a Box
	fn box_clone(&self) -> Box<dyn InnerSign>;
	/// Cast to Any for runtime type checking
	fn as_any(&self) -> &dyn Any;
}

/// A ChannelSigner derived struct allowing run-time selection of a signer
pub struct DynSigner {
	/// The inner signer
	pub inner: Box<dyn InnerSign>,
}

impl DynSigner {
	/// Create a new DynSigner
	pub fn new<S: InnerSign + 'static>(inner: S) -> Self {
		DynSigner { inner: Box::new(inner) }
	}
}

#[cfg(taproot)]
#[allow(unused_variables)]
impl TaprootChannelSigner for DynSigner {
	fn generate_local_nonce_pair(
		&self, commitment_number: u64, secp_ctx: &Secp256k1<All>,
	) -> PublicNonce {
		todo!()
	}

	fn partially_sign_counterparty_commitment(
		&self, counterparty_nonce: PublicNonce, commitment_tx: &CommitmentTransaction,
		inbound_htlc_preimages: Vec<PaymentPreimage>,
		outbound_htlc_preimages: Vec<PaymentPreimage>, secp_ctx: &Secp256k1<All>,
	) -> Result<(crate::ln::msgs::PartialSignatureWithNonce, Vec<secp256k1::schnorr::Signature>), ()>
	{
		todo!();
	}

	fn finalize_holder_commitment(
		&self, commitment_tx: &HolderCommitmentTransaction,
		counterparty_partial_signature: crate::ln::msgs::PartialSignatureWithNonce,
		secp_ctx: &Secp256k1<All>,
	) -> Result<PartialSignature, ()> {
		todo!();
	}

	fn sign_justice_revoked_output(
		&self, justice_tx: &Transaction, input: usize, amount: u64, per_commitment_key: &SecretKey,
		secp_ctx: &Secp256k1<All>,
	) -> Result<secp256k1::schnorr::Signature, ()> {
		todo!();
	}

	fn sign_justice_revoked_htlc(
		&self, justice_tx: &Transaction, input: usize, amount: u64, per_commitment_key: &SecretKey,
		htlc: &HTLCOutputInCommitment, secp_ctx: &Secp256k1<All>,
	) -> Result<secp256k1::schnorr::Signature, ()> {
		todo!();
	}

	fn sign_holder_htlc_transaction(
		&self, htlc_tx: &Transaction, input: usize, htlc_descriptor: &HTLCDescriptor,
		secp_ctx: &Secp256k1<All>,
	) -> Result<secp256k1::schnorr::Signature, ()> {
		todo!();
	}

	fn sign_counterparty_htlc_transaction(
		&self, htlc_tx: &Transaction, input: usize, amount: u64, per_commitment_point: &PublicKey,
		htlc: &HTLCOutputInCommitment, secp_ctx: &Secp256k1<All>,
	) -> Result<secp256k1::schnorr::Signature, ()> {
		todo!();
	}

	fn partially_sign_closing_transaction(
		&self, closing_tx: &ClosingTransaction, secp_ctx: &Secp256k1<All>,
	) -> Result<PartialSignature, ()> {
		todo!();
	}
}

impl Clone for DynSigner {
	fn clone(&self) -> Self {
		DynSigner { inner: self.inner.box_clone() }
	}
}

delegate!(DynSigner, EcdsaChannelSigner, inner,
	fn sign_holder_commitment(, channel_parameters: &ChannelTransactionParameters,
		commitment_tx: &HolderCommitmentTransaction,
		secp_ctx: &Secp256k1<secp256k1::All>) -> Result<Signature, ()>,
	#[cfg(any(test, feature = "_test_utils", feature = "unsafe_revoked_tx_signing"))]
	fn unsafe_sign_holder_commitment(, channel_parameters: &ChannelTransactionParameters,
		commitment_tx: &HolderCommitmentTransaction,
		secp_ctx: &Secp256k1<secp256k1::All>) -> Result<Signature, ()>,
	fn sign_counterparty_commitment(, channel_parameters: &ChannelTransactionParameters,
		commitment_tx: &CommitmentTransaction, inbound_htlc_preimages: Vec<PaymentPreimage>,
		outbound_htlc_preimages: Vec<PaymentPreimage>,
		secp_ctx: &Secp256k1<secp256k1::All>) -> Result<(Signature, Vec<Signature>), ()>,
	fn sign_justice_revoked_output(, channel_parameters: &ChannelTransactionParameters,
		justice_tx: &Transaction, input: usize, amount: u64, per_commitment_key: &SecretKey,
		secp_ctx: &Secp256k1<secp256k1::All>) -> Result<Signature, ()>,
	fn sign_justice_revoked_htlc(, channel_parameters: &ChannelTransactionParameters,
		justice_tx: &Transaction, input: usize, amount: u64, per_commitment_key: &SecretKey,
		htlc: &HTLCOutputInCommitment, secp_ctx: &Secp256k1<secp256k1::All>) -> Result<Signature, ()>,
	fn sign_counterparty_htlc_transaction(, channel_parameters: &ChannelTransactionParameters,
		htlc_tx: &Transaction, input: usize, amount: u64, per_commitment_point: &PublicKey,
		htlc: &HTLCOutputInCommitment, secp_ctx: &Secp256k1<secp256k1::All>) -> Result<Signature, ()>,
	fn sign_closing_transaction(, channel_parameters: &ChannelTransactionParameters,
		closing_tx: &ClosingTransaction, secp_ctx: &Secp256k1<secp256k1::All>) -> Result<Signature, ()>,
	fn sign_channel_announcement_with_funding_key(,
		channel_parameters: &ChannelTransactionParameters, msg: &UnsignedChannelAnnouncement,
		secp_ctx: &Secp256k1<secp256k1::All>
	) -> Result<Signature, ()>,
	fn sign_holder_keyed_anchor_input(, channel_parameters: &ChannelTransactionParameters,
		anchor_tx: &Transaction, input: usize,
		secp_ctx: &Secp256k1<secp256k1::All>) -> Result<Signature, ()>,
	fn sign_holder_htlc_transaction(, htlc_tx: &Transaction, input: usize,
		htlc_descriptor: &HTLCDescriptor, secp_ctx: &Secp256k1<All>) -> Result<Signature, ()>,
	fn sign_splice_shared_input(, channel_parameters: &ChannelTransactionParameters,
		tx: &Transaction, input_index: usize, secp_ctx: &Secp256k1<All>) -> Signature
);

delegate!(DynSigner, ChannelSigner,
	inner,
	fn get_per_commitment_point(,
		idx: u64,
		secp_ctx: &Secp256k1<secp256k1::All>
	) -> Result<PublicKey, ()>,
	fn release_commitment_secret(, idx: u64) -> Result<[u8; 32], ()>,
	fn validate_holder_commitment(,
		holder_tx: &HolderCommitmentTransaction,
		preimages: Vec<PaymentPreimage>
	) -> Result<(), ()>,
	fn pubkeys(,
		secp_ctx: &Secp256k1<secp256k1::All>
	) -> ChannelPublicKeys,
	fn new_funding_pubkey(,
		splice_parent_funding_txid: Txid, secp_ctx: &Secp256k1<secp256k1::All>
	) -> PublicKey,
	fn channel_keys_id(,) -> [u8; 32],
	fn validate_counterparty_revocation(, idx: u64, secret: &SecretKey) -> Result<(), ()>
);

impl DynSignerTrait for InMemorySigner {}

impl InnerSign for InMemorySigner {
	fn box_clone(&self) -> Box<dyn InnerSign> {
		Box::new(self.clone())
	}

	fn as_any(&self) -> &dyn Any {
		self
	}
}

/// A convenience wrapper for DynKeysInterfaceTrait
pub struct DynKeysInterface {
	/// The inner dyn keys interface
	pub inner: Box<dyn DynKeysInterfaceTrait>,
}

impl DynKeysInterface {
	/// Create a new DynKeysInterface
	pub fn new(inner: Box<dyn DynKeysInterfaceTrait>) -> Self {
		DynKeysInterface { inner }
	}
}

delegate!(DynKeysInterface, NodeSigner,
inner,
	fn get_node_id(, recipient: Recipient) -> Result<PublicKey, ()>,
	fn sign_gossip_message(, msg: UnsignedGossipMessage) -> Result<Signature, ()>,
	fn sign_message(, msg: &[u8]) -> Result<String, ()>,
	fn ecdh(, recipient: Recipient, other_key: &PublicKey, tweak: Option<&Scalar>) -> Result<SharedSecret, ()>,
	fn sign_invoice(, invoice: &RawBolt11Invoice, recipient: Recipient) -> Result<RecoverableSignature, ()>,
	fn sign_bolt12_invoice(,
		invoice: &crate::offers::invoice::UnsignedBolt12Invoice
	) -> Result<secp256k1::schnorr::Signature, ()>,
	fn get_expanded_key(,) -> ExpandedKey,
	fn get_peer_storage_key(,) -> PeerStorageKey,
	fn get_receive_auth_key(,) -> ReceiveAuthKey
);

delegate!(DynKeysInterface, SignerProvider,
	inner,
	fn get_destination_script(, channel_keys_id: [u8; 32]) -> Result<ScriptBuf, ()>,
	fn get_shutdown_scriptpubkey(,) -> Result<ShutdownScript, ()>,
	fn generate_channel_keys_id(, _inbound: bool, _user_channel_id: u128) -> [u8; 32],
	fn derive_channel_signer(, _channel_keys_id: [u8; 32]) -> Self::EcdsaSigner;
	type EcdsaSigner = DynSigner,
	#[cfg(taproot)]
	type TaprootSigner = DynSigner
);

delegate!(DynKeysInterface, EntropySource, inner,
	fn get_secure_random_bytes(,) -> [u8; 32]
);

delegate!(DynKeysInterface, OutputSpender, inner,
	fn spend_spendable_outputs(,
		descriptors: &[&SpendableOutputDescriptor], outputs: Vec<TxOut>,
		change_destination_script: ScriptBuf, feerate_sat_per_1000_weight: u32,
		locktime: Option<LockTime>, secp_ctx: &Secp256k1<All>
	) -> Result<Transaction, ()>
);
#[cfg(not(taproot))]
/// A supertrait for all the traits that a keys interface implements
pub trait DynKeysInterfaceTrait:
	NodeSigner + OutputSpender + SignerProvider<EcdsaSigner = DynSigner> + EntropySource + Send + Sync
{
}

#[cfg(taproot)]
/// A supertrait for all the traits that a keys interface implements
pub trait DynKeysInterfaceTrait:
	NodeSigner
	+ OutputSpender
	+ SignerProvider<EcdsaSigner = DynSigner, TaprootSigner = DynSigner>
	+ EntropySource
	+ Send
	+ Sync
{
}

/// A dyn wrapper for PhantomKeysManager
pub struct DynPhantomKeysInterface {
	inner: Box<PhantomKeysManager>,
}

impl DynPhantomKeysInterface {
	/// Create a new DynPhantomKeysInterface
	pub fn new(inner: PhantomKeysManager) -> Self {
		DynPhantomKeysInterface { inner: Box::new(inner) }
	}
}

delegate!(DynPhantomKeysInterface, NodeSigner,
	inner,
	fn get_node_id(, recipient: Recipient) -> Result<PublicKey, ()>,
	fn sign_gossip_message(, msg: UnsignedGossipMessage) -> Result<Signature, ()>,
	fn sign_message(, msg: &[u8]) -> Result<String, ()>,
	fn ecdh(, recipient: Recipient, other_key: &PublicKey, tweak: Option<&Scalar>) -> Result<SharedSecret, ()>,
	fn sign_invoice(, invoice: &RawBolt11Invoice, recipient: Recipient) -> Result<RecoverableSignature, ()>,
	fn sign_bolt12_invoice(, invoice: &crate::offers::invoice::UnsignedBolt12Invoice
	) -> Result<secp256k1::schnorr::Signature, ()>,
	fn get_expanded_key(,) -> ExpandedKey,
	fn get_peer_storage_key(,) -> PeerStorageKey,
	fn get_receive_auth_key(,) -> ReceiveAuthKey
);

impl SignerProvider for DynPhantomKeysInterface {
	type EcdsaSigner = DynSigner;
	#[cfg(taproot)]
	type TaprootSigner = DynSigner;

	fn get_destination_script(&self, channel_keys_id: [u8; 32]) -> Result<ScriptBuf, ()> {
		self.inner.get_destination_script(channel_keys_id)
	}

	fn get_shutdown_scriptpubkey(&self) -> Result<ShutdownScript, ()> {
		self.inner.get_shutdown_scriptpubkey()
	}

	fn generate_channel_keys_id(&self, _inbound: bool, _user_channel_id: u128) -> [u8; 32] {
		self.inner.generate_channel_keys_id(_inbound, _user_channel_id)
	}

	fn derive_channel_signer(&self, channel_keys_id: [u8; 32]) -> Self::EcdsaSigner {
		let inner = self.inner.derive_channel_signer(channel_keys_id);
		DynSigner::new(inner)
	}
}

delegate!(DynPhantomKeysInterface, EntropySource, inner,
	fn get_secure_random_bytes(,) -> [u8; 32]
);

delegate!(DynPhantomKeysInterface, OutputSpender, inner,
	fn spend_spendable_outputs(,
		descriptors: &[&SpendableOutputDescriptor], outputs: Vec<TxOut>,
		change_destination_script: ScriptBuf, feerate_sat_per_1000_weight: u32,
		locktime: Option<LockTime>, secp_ctx: &Secp256k1<All>
	) -> Result<Transaction, ()>
);

impl DynKeysInterfaceTrait for DynPhantomKeysInterface {}
