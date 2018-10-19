//! WalletInterface is *not* a wallet, only an interface to bridge between
//! user wallet and ChannelMonitor. If this last one discover on-chain outputs they will
//! be send with associate data as events::Event::SpendableOutputs to be at the disposal of wallet.
//!
//! KeysInterface is no more a wallet, just an entity to get secret from user wallet and derive
//! appropriate keyring materials to others lightning components, as such node_id, destination_script.
//!

use bitcoin::blockdata::transaction::OutPoint;
use bitcoin::blockdata::script::Script;

use secp256k1::key::SecretKey;

use util::events;

/// A trait to describe a wallet which sould receive data to be able to spend onchain outputs
/// fron a lightning channel
pub trait WalletInterface: Send + Sync {
	/// Handle an incoming SpendableOutputs event from SimpleManyChannelMonitor containing a 
	/// CustomOutputScriptDesctitpor. Follow doc of the latter to know how to spend the output.
	fn handle_spendable_output(&self, event: events::Event);
}

/// Hacky custom output script descriptors to ease spending of onchain outputs by user wallet
/// Maybe should be changed by real ones when merged into rust-bitcoin.
/// StaticOutputs commit to a static pubkey, i.e one derived once for node operation lifetime.
/// DynamicOutputs commit to a dynamic local_delayedpubkey, i.e one which change for each per_commitment_point
pub enum CustomOutputScriptDescriptor {
	/// Outpoint commits to a P2PWKH, should be spend by the following witness :
	/// <signature> <pubkey>
	/// With pubkey being bip32 /1' from HMAC-Sha512 of user-provided seed as master private key
	StaticOutput {
		/// Outpoint spendable by user wallet
		outpoint: OutPoint,
	},
	/// Outpoint commits to a P2WSH, should be spend by the following witness :
	/// <local_delayedsig> 0 <witnessScript>
	/// With input nSequence set to_self_delay.
	DynamicOutput {
		/// Outpoint spendable by user wallet
		outpoint: OutPoint,
		/// local_delayedkey = delayed_payment_basepoint_secret + SHA256(per_commitment_point || delayed_payment_basepoint
		local_delayedkey: SecretKey,
		/// witness redeemScript encumbering output
		witness_script: Script,
		/// nSequence input must commit to self_delay to satisfy script's OP_CSV
		to_self_delay: u16,
	}
}

impl CustomOutputScriptDescriptor {
	/// Build a StaticOuput descriptor
	pub fn static_key(outpoint: OutPoint) -> Self {
		CustomOutputScriptDescriptor::StaticOutput {
			outpoint,
		}
	}

	/// Build a DynamicOuput descriptor
	pub fn dynamic_key(outpoint: OutPoint, local_delayedkey: SecretKey, witness_script: Script, to_self_delay: u16) -> Self {
		CustomOutputScriptDescriptor::DynamicOutput {
			outpoint,
			local_delayedkey,
			witness_script,
			to_self_delay,
		}
	}
}
