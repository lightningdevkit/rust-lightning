//! keysinterface provides keys into rust-lightning and defines some useful enums which describe
//! spendable on-chain outputs which the user owns and is responsible for using just as any other
//! on-chain output which is theirs.

use bitcoin::blockdata::transaction::{OutPoint, TxOut};
use bitcoin::blockdata::script::Script;

use secp256k1::key::SecretKey;

/// When on-chain outputs are created by rust-lightning an event is generated which informs the
/// user thereof. This enum describes the format of the output and provides the OutPoint.
pub enum SpendableOutputDescriptor {
	/// Outpoint with an output to a script which was provided via KeysInterface, thus you should
	/// have stored somewhere how to spend script_pubkey!
	/// Outputs from a justice tx, claim tx or preimage tx
	StaticOutput {
		/// The outpoint spendable by user wallet
		outpoint: OutPoint,
		/// The output which is referenced by the given outpoint
		output: TxOut,
	},
	/// Outpoint commits to a P2WSH, should be spend by the following witness :
	/// <local_delayedsig> 0 <witnessScript>
	/// With input nSequence set to_self_delay.
	/// Outputs from a HTLC-Success/Timeout tx
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
