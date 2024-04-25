//! A dynamically dispatched signer

use crate::prelude::*;

use core::any::Any;
use delegate::delegate;

use crate::chain::transaction::OutPoint;
use crate::io::{Error, Read};
use crate::ln::chan_utils::{
	ChannelPublicKeys, ChannelTransactionParameters, ClosingTransaction, CommitmentTransaction,
	HTLCOutputInCommitment, HolderCommitmentTransaction,
};
use crate::ln::features::ChannelTypeFeatures;
use crate::ln::msgs::{DecodeError, UnsignedChannelAnnouncement, UnsignedGossipMessage};
use crate::ln::script::ShutdownScript;
use crate::ln::PaymentPreimage;
use crate::sign::ecdsa::EcdsaChannelSigner;
#[cfg(taproot)]
use crate::sign::taproot::TaprootChannelSigner;
use crate::sign::ChannelSigner;
use crate::sign::InMemorySigner;
use crate::sign::{
	ecdsa::WriteableEcdsaChannelSigner, KeyMaterial, NodeSigner, Recipient, SignerProvider,
	SpendableOutputDescriptor,
};
use crate::sign::{EntropySource, HTLCDescriptor, OutputSpender, PhantomKeysManager};
use crate::util::ser::{Readable, ReadableArgs};
use crate::util::ser::{Writeable, Writer};
#[cfg(any(test, feature = "_test_utils"))]
use crate::util::test_utils::OnlyReadsKeysInterface;
use bitcoin;
use bitcoin::absolute::LockTime;
use bitcoin::bech32::u5;
use bitcoin::secp256k1::All;
use bitcoin::{secp256k1, ScriptBuf, Transaction, TxOut};
#[cfg(taproot)]
use musig2::types::{PartialSignature, PublicNonce};
use secp256k1::ecdsa::RecoverableSignature;
use secp256k1::{ecdh::SharedSecret, ecdsa::Signature, PublicKey, Scalar, Secp256k1, SecretKey};

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
	/// Serialize the signer.
	/// We can't have a write method with a generic (i.e. `Writeable`) because that would make signers
	/// dyn object incompatible.
	fn vwrite(&self, writer: &mut Vec<u8>) -> Result<(), Error>;
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

impl WriteableEcdsaChannelSigner for DynSigner {}

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

	fn sign_holder_anchor_input(
		&self, anchor_tx: &Transaction, input: usize, secp_ctx: &Secp256k1<All>,
	) -> Result<secp256k1::schnorr::Signature, ()> {
		todo!();
	}
}

impl Clone for DynSigner {
	fn clone(&self) -> Self {
		DynSigner { inner: self.inner.box_clone() }
	}
}

// This is taken care of by KeysInterface
impl Readable for DynSigner {
	fn read<R: Read>(_reader: &mut R) -> Result<Self, DecodeError> {
		unimplemented!()
	}
}

impl EcdsaChannelSigner for DynSigner {
	fn sign_holder_commitment(
		&self, commitment_tx: &HolderCommitmentTransaction, secp_ctx: &Secp256k1<secp256k1::All>,
	) -> Result<Signature, ()> {
		self.inner.sign_holder_commitment(commitment_tx, secp_ctx)
	}

	#[cfg(any(test, feature = "unsafe_revoked_tx_signing"))]
	fn unsafe_sign_holder_commitment(
		&self, commitment_tx: &HolderCommitmentTransaction, secp_ctx: &Secp256k1<secp256k1::All>,
	) -> Result<Signature, ()> {
		self.inner.unsafe_sign_holder_commitment(commitment_tx, secp_ctx)
	}

	fn sign_counterparty_commitment(
		&self, commitment_tx: &CommitmentTransaction, inbound_htlc_preimages: Vec<PaymentPreimage>,
		outbound_htlc_preimages: Vec<PaymentPreimage>, secp_ctx: &Secp256k1<secp256k1::All>,
	) -> Result<(Signature, Vec<Signature>), ()> {
		self.inner.sign_counterparty_commitment(
			commitment_tx,
			inbound_htlc_preimages,
			outbound_htlc_preimages,
			secp_ctx,
		)
	}

	fn sign_justice_revoked_output(
		&self, justice_tx: &Transaction, input: usize, amount: u64, per_commitment_key: &SecretKey,
		secp_ctx: &Secp256k1<secp256k1::All>,
	) -> Result<Signature, ()> {
		EcdsaChannelSigner::sign_justice_revoked_output(
			&*self.inner,
			justice_tx,
			input,
			amount,
			per_commitment_key,
			secp_ctx,
		)
	}

	fn sign_justice_revoked_htlc(
		&self, justice_tx: &Transaction, input: usize, amount: u64, per_commitment_key: &SecretKey,
		htlc: &HTLCOutputInCommitment, secp_ctx: &Secp256k1<secp256k1::All>,
	) -> Result<Signature, ()> {
		EcdsaChannelSigner::sign_justice_revoked_htlc(
			&*self.inner,
			justice_tx,
			input,
			amount,
			per_commitment_key,
			htlc,
			secp_ctx,
		)
	}

	fn sign_counterparty_htlc_transaction(
		&self, htlc_tx: &Transaction, input: usize, amount: u64, per_commitment_point: &PublicKey,
		htlc: &HTLCOutputInCommitment, secp_ctx: &Secp256k1<secp256k1::All>,
	) -> Result<Signature, ()> {
		EcdsaChannelSigner::sign_counterparty_htlc_transaction(
			&*self.inner,
			htlc_tx,
			input,
			amount,
			per_commitment_point,
			htlc,
			secp_ctx,
		)
	}

	fn sign_closing_transaction(
		&self, closing_tx: &ClosingTransaction, secp_ctx: &Secp256k1<secp256k1::All>,
	) -> Result<Signature, ()> {
		self.inner.sign_closing_transaction(closing_tx, secp_ctx)
	}

	fn sign_channel_announcement_with_funding_key(
		&self, msg: &UnsignedChannelAnnouncement, secp_ctx: &Secp256k1<secp256k1::All>,
	) -> Result<Signature, ()> {
		self.inner.sign_channel_announcement_with_funding_key(msg, secp_ctx)
	}

	fn sign_holder_anchor_input(
		&self, anchor_tx: &Transaction, input: usize, secp_ctx: &Secp256k1<secp256k1::All>,
	) -> Result<Signature, ()> {
		EcdsaChannelSigner::sign_holder_anchor_input(&*self.inner, anchor_tx, input, secp_ctx)
	}

	fn sign_holder_htlc_transaction(
		&self, htlc_tx: &Transaction, input: usize, htlc_descriptor: &HTLCDescriptor,
		secp_ctx: &Secp256k1<All>,
	) -> Result<Signature, ()> {
		EcdsaChannelSigner::sign_holder_htlc_transaction(
			&*self.inner,
			htlc_tx,
			input,
			htlc_descriptor,
			secp_ctx,
		)
	}
}

impl ChannelSigner for DynSigner {
	delegate! {
		to self.inner {
			fn commitment_seed(&self) -> [u8; 32];
			fn channel_type_features(&self) -> Option<&ChannelTypeFeatures>;
			fn get_per_commitment_point(
				&self,
				idx: u64,
				secp_ctx: &Secp256k1<secp256k1::All>,
			) -> PublicKey;
			fn counterparty_pubkeys(&self) -> Option<&ChannelPublicKeys>;
			fn funding_outpoint(&self) -> Option<&OutPoint>;
			fn get_channel_parameters(&self) -> Option<&ChannelTransactionParameters>;
			fn release_commitment_secret(&self, idx: u64) -> [u8; 32];

			fn validate_holder_commitment(
				&self,
				holder_tx: &HolderCommitmentTransaction,
				preimages: Vec<PaymentPreimage>,
			) -> Result<(), ()>;

			fn pubkeys(&self) -> &ChannelPublicKeys;

			fn channel_keys_id(&self) -> [u8; 32];

			fn provide_channel_parameters(&mut self, channel_parameters: &ChannelTransactionParameters);

			fn validate_counterparty_revocation(&self, idx: u64, secret: &SecretKey) -> Result<(), ()>;
		}
	}
}

impl Writeable for DynSigner {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), Error> {
		let inner = self.inner.as_ref();
		let mut buf = Vec::new();
		inner.vwrite(&mut buf)?;
		writer.write_all(&buf)
	}
}

impl DynSignerTrait for InMemorySigner {}

impl InnerSign for InMemorySigner {
	fn box_clone(&self) -> Box<dyn InnerSign> {
		Box::new(self.clone())
	}

	fn as_any(&self) -> &dyn Any {
		self
	}

	fn vwrite(&self, writer: &mut Vec<u8>) -> Result<(), Error> {
		self.write(writer)
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

impl NodeSigner for DynKeysInterface {
	delegate! {
		to self.inner {
			fn get_node_id(&self, recipient: Recipient) -> Result<PublicKey, ()>;
			fn sign_gossip_message(&self, msg: UnsignedGossipMessage) -> Result<Signature, ()>;
			fn ecdh(&self, recipient: Recipient, other_key: &PublicKey, tweak: Option<&Scalar>) -> Result<SharedSecret, ()>;

			fn sign_invoice(
				&self,
				hrp_bytes: &[u8],
				invoice_data: &[u5],
				recipient: Recipient,
			) -> Result<RecoverableSignature, ()>;

			fn sign_bolt12_invoice(
				&self, invoice: &crate::offers::invoice::UnsignedBolt12Invoice
			) -> Result<bitcoin::secp256k1::schnorr::Signature, ()>;

			fn sign_bolt12_invoice_request(
				&self, invoice_request: &crate::offers::invoice_request::UnsignedInvoiceRequest
			) -> Result<bitcoin::secp256k1::schnorr::Signature, ()>;

			fn get_inbound_payment_key_material(&self) -> KeyMaterial;
		}
	}
}

impl SignerProvider for DynKeysInterface {
	type EcdsaSigner = DynSigner;
	#[cfg(taproot)]
	type TaprootSigner = DynSigner;

	delegate! {
		to self.inner {
			fn get_destination_script(&self, channel_keys_id: [u8; 32]) -> Result<ScriptBuf, ()>;

			fn get_shutdown_scriptpubkey(&self) -> Result<ShutdownScript, ()>;

			fn generate_channel_keys_id(&self, _inbound: bool, _channel_value_satoshis: u64, _user_channel_id: u128) -> [u8; 32];

			fn derive_channel_signer(&self, _channel_value_satoshis: u64, _channel_keys_id: [u8; 32]) -> Self::EcdsaSigner;

			fn read_chan_signer(&self, reader: &[u8]) -> Result<Self::EcdsaSigner, DecodeError>;
		}
	}
}

impl EntropySource for DynKeysInterface {
	delegate! {
		to self.inner {
			fn get_secure_random_bytes(&self) -> [u8; 32];
		}
	}
}

impl OutputSpender for DynKeysInterface {
	delegate! {
		to self.inner {
			fn spend_spendable_outputs(
				&self, descriptors: &[&SpendableOutputDescriptor], outputs: Vec<TxOut>,
				change_destination_script: ScriptBuf, feerate_sat_per_1000_weight: u32,
				locktime: Option<LockTime>, secp_ctx: &Secp256k1<All>,
			) -> Result<Transaction, ()>;
		}
	}
}

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
	inner: PhantomKeysManager,
}

impl DynPhantomKeysInterface {
	/// Create a new DynPhantomKeysInterface
	pub fn new(inner: PhantomKeysManager) -> Self {
		DynPhantomKeysInterface { inner }
	}
}

impl NodeSigner for DynPhantomKeysInterface {
	delegate! {
		to self.inner {
			fn get_node_id(&self, recipient: Recipient) -> Result<PublicKey, ()>;
			fn sign_gossip_message(&self, msg: UnsignedGossipMessage) -> Result<Signature, ()>;
			fn ecdh(&self, recipient: Recipient, other_key: &PublicKey, tweak: Option<&Scalar>) -> Result<SharedSecret, ()>;

			fn sign_invoice(
				&self,
				hrp_bytes: &[u8],
				invoice_data: &[u5],
				recipient: Recipient,
			) -> Result<RecoverableSignature, ()>;

			fn sign_bolt12_invoice(
				&self, invoice: &crate::offers::invoice::UnsignedBolt12Invoice
			) -> Result<bitcoin::secp256k1::schnorr::Signature, ()>;

			fn sign_bolt12_invoice_request(
				&self, invoice_request: &crate::offers::invoice_request::UnsignedInvoiceRequest
			) -> Result<bitcoin::secp256k1::schnorr::Signature, ()>;

			fn get_inbound_payment_key_material(&self) -> KeyMaterial;
		}
	}
}

impl SignerProvider for DynPhantomKeysInterface {
	type EcdsaSigner = DynSigner;
	#[cfg(taproot)]
	type TaprootSigner = DynSigner;

	delegate! {
		to self.inner {
			fn get_destination_script(&self, channel_keys_id: [u8; 32]) -> Result<ScriptBuf, ()>;

			fn get_shutdown_scriptpubkey(&self) -> Result<ShutdownScript, ()>;

			fn generate_channel_keys_id(&self, _inbound: bool, _channel_value_satoshis: u64, _user_channel_id: u128) -> [u8; 32];
		}
	}

	fn derive_channel_signer(
		&self, channel_value_satoshis: u64, channel_keys_id: [u8; 32],
	) -> Self::EcdsaSigner {
		let inner = self.inner.derive_channel_signer(channel_value_satoshis, channel_keys_id);
		DynSigner::new(inner)
	}

	fn read_chan_signer(&self, _reader: &[u8]) -> Result<Self::EcdsaSigner, DecodeError> {
		todo!()
	}
}

impl EntropySource for DynPhantomKeysInterface {
	delegate! {
		to self.inner {
			fn get_secure_random_bytes(&self) -> [u8; 32];
		}
	}
}

impl OutputSpender for DynPhantomKeysInterface {
	delegate! {
		to self.inner {
			fn spend_spendable_outputs(
				&self, descriptors: &[&SpendableOutputDescriptor], outputs: Vec<TxOut>,
				change_destination_script: ScriptBuf, feerate_sat_per_1000_weight: u32,
				locktime: Option<LockTime>, secp_ctx: &Secp256k1<All>,
			) -> Result<Transaction, ()>;
		}
	}
}

impl DynKeysInterfaceTrait for DynPhantomKeysInterface {}

impl ReadableArgs<&DynKeysInterface> for DynSigner {
	fn read<R: Read>(_reader: &mut R, _params: &DynKeysInterface) -> Result<Self, DecodeError> {
		todo!()
	}
}

#[cfg(any(test, feature = "_test_utils"))]
impl ReadableArgs<&OnlyReadsKeysInterface> for DynSigner {
	fn read<R: Read>(
		_reader: &mut R, _params: &OnlyReadsKeysInterface,
	) -> Result<Self, DecodeError> {
		todo!()
	}
}
