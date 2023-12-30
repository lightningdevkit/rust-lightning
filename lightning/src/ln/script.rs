//! Abstractions for scripts used in the Lightning Network.

use bitcoin::blockdata::opcodes::all::OP_PUSHBYTES_0 as SEGWIT_V0;
use bitcoin::blockdata::script::{Script, ScriptBuf};
use bitcoin::hashes::Hash;
use bitcoin::hash_types::{WPubkeyHash, WScriptHash};
use bitcoin::secp256k1::PublicKey;
use bitcoin::address::WitnessProgram;

use crate::ln::channelmanager;
use crate::ln::features::InitFeatures;
use crate::ln::msgs::DecodeError;
use crate::util::ser::{Readable, Writeable, Writer};

use core::convert::TryFrom;
use crate::io;

/// A script pubkey for shutting down a channel as defined by [BOLT #2].
///
/// [BOLT #2]: https://github.com/lightning/bolts/blob/master/02-peer-protocol.md
#[derive(Clone, PartialEq, Eq)]
pub struct ShutdownScript(ShutdownScriptImpl);

/// An error occurring when converting from [`ScriptBuf`] to [`ShutdownScript`].
#[derive(Clone, Debug)]
pub struct InvalidShutdownScript {
	/// The script that did not meet the requirements from [BOLT #2].
	///
	/// [BOLT #2]: https://github.com/lightning/bolts/blob/master/02-peer-protocol.md
	pub script: ScriptBuf
}

#[derive(Clone, PartialEq, Eq)]
enum ShutdownScriptImpl {
	/// [`PublicKey`] used to form a P2WPKH script pubkey. Used to support backward-compatible
	/// serialization.
	Legacy(PublicKey),

	/// [`ScriptBuf`] adhering to a script pubkey format specified in BOLT #2.
	Bolt2(ScriptBuf),
}

impl Writeable for ShutdownScript {
	fn write(&self, w: &mut impl Writer) -> Result<(), io::Error> {
		self.0.write(w)
	}
}

impl Readable for ShutdownScript {
	fn read<R: io::Read>(r: &mut R) -> Result<Self, DecodeError> {
		Ok(ShutdownScript(ShutdownScriptImpl::read(r)?))
	}
}

impl_writeable_tlv_based_enum!(ShutdownScriptImpl, ;
	(0, Legacy),
	(1, Bolt2),
);

impl ShutdownScript {
	/// Generates a P2WPKH script pubkey from the given [`PublicKey`].
	pub(crate) fn new_p2wpkh_from_pubkey(pubkey: PublicKey) -> Self {
		Self(ShutdownScriptImpl::Legacy(pubkey))
	}

	/// Generates a P2WPKH script pubkey from the given [`WPubkeyHash`].
	pub fn new_p2wpkh(pubkey_hash: &WPubkeyHash) -> Self {
		Self(ShutdownScriptImpl::Bolt2(ScriptBuf::new_v0_p2wpkh(pubkey_hash)))
	}

	/// Generates a P2WSH script pubkey from the given [`WScriptHash`].
	pub fn new_p2wsh(script_hash: &WScriptHash) -> Self {
		Self(ShutdownScriptImpl::Bolt2(ScriptBuf::new_v0_p2wsh(script_hash)))
	}

	/// Generates a witness script pubkey from the given segwit version and program.
	///
	/// Note for version-zero witness scripts you must use [`ShutdownScript::new_p2wpkh`] or
	/// [`ShutdownScript::new_p2wsh`] instead.
	///
	/// # Errors
	///
	/// This function may return an error if `program` is invalid for the segwit `version`.
	pub fn new_witness_program(witness_program: &WitnessProgram) -> Result<Self, InvalidShutdownScript> {
		Self::try_from(ScriptBuf::new_witness_program(witness_program))
	}

	/// Converts the shutdown script into the underlying [`ScriptBuf`].
	pub fn into_inner(self) -> ScriptBuf {
		self.into()
	}

	/// Returns the [`PublicKey`] used for a P2WPKH shutdown script if constructed directly from it.
	pub fn as_legacy_pubkey(&self) -> Option<&PublicKey> {
		match &self.0 {
			ShutdownScriptImpl::Legacy(pubkey) => Some(pubkey),
			ShutdownScriptImpl::Bolt2(_) => None,
		}
	}

	/// Returns whether the shutdown script is compatible with the features as defined by BOLT #2.
	///
	/// Specifically, checks for compliance with feature `option_shutdown_anysegwit`.
	pub fn is_compatible(&self, features: &InitFeatures) -> bool {
		match &self.0 {
			ShutdownScriptImpl::Legacy(_) => true,
			ShutdownScriptImpl::Bolt2(script) => is_bolt2_compliant(script, features),
		}
	}
}

/// Check if a given script is compliant with BOLT 2's shutdown script requirements for the given
/// counterparty features.
pub(crate) fn is_bolt2_compliant(script: &Script, features: &InitFeatures) -> bool {
	if script.is_p2pkh() || script.is_p2sh() || script.is_v0_p2wpkh() || script.is_v0_p2wsh() {
		true
	} else if features.supports_shutdown_anysegwit() {
		script.is_witness_program() && script.as_bytes()[0] != SEGWIT_V0.to_u8()
	} else {
		false
	}
}

// Note that this is only for our own shutdown scripts. Counterparties are still allowed to send us
// non-witness shutdown scripts which this rejects.
impl TryFrom<ScriptBuf> for ShutdownScript {
	type Error = InvalidShutdownScript;

	fn try_from(script: ScriptBuf) -> Result<Self, Self::Error> {
		Self::try_from((script, &channelmanager::provided_init_features(&crate::util::config::UserConfig::default())))
	}
}

// Note that this is only for our own shutdown scripts. Counterparties are still allowed to send us
// non-witness shutdown scripts which this rejects.
impl TryFrom<(ScriptBuf, &InitFeatures)> for ShutdownScript {
	type Error = InvalidShutdownScript;

	fn try_from((script, features): (ScriptBuf, &InitFeatures)) -> Result<Self, Self::Error> {
		if is_bolt2_compliant(&script, features) && script.is_witness_program() {
			Ok(Self(ShutdownScriptImpl::Bolt2(script)))
		} else {
			Err(InvalidShutdownScript { script })
		}
	}
}

impl Into<ScriptBuf> for ShutdownScript {
	fn into(self) -> ScriptBuf {
		match self.0 {
			ShutdownScriptImpl::Legacy(pubkey) =>
				ScriptBuf::new_v0_p2wpkh(&WPubkeyHash::hash(&pubkey.serialize())),
			ShutdownScriptImpl::Bolt2(script_pubkey) => script_pubkey,
		}
	}
}

impl core::fmt::Display for ShutdownScript{
	fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
		match &self.0 {
			ShutdownScriptImpl::Legacy(_) => self.clone().into_inner().fmt(f),
			ShutdownScriptImpl::Bolt2(script) => script.fmt(f),
		}
	}
}

#[cfg(test)]
mod shutdown_script_tests {
	use super::ShutdownScript;
	use bitcoin::blockdata::opcodes;
	use bitcoin::blockdata::script::{Builder, ScriptBuf};
	use bitcoin::secp256k1::Secp256k1;
	use bitcoin::secp256k1::{PublicKey, SecretKey};
	use crate::ln::features::InitFeatures;
	use core::convert::TryFrom;
	use bitcoin::address::{WitnessProgram, WitnessVersion};

	fn pubkey() -> bitcoin::key::PublicKey {
		let secp_ctx = Secp256k1::signing_only();
		let secret_key = SecretKey::from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]).unwrap();
		bitcoin::key::PublicKey::new(PublicKey::from_secret_key(&secp_ctx, &secret_key))
	}

	fn redeem_script() -> ScriptBuf {
		let pubkey = pubkey();
		Builder::new()
			.push_opcode(opcodes::all::OP_PUSHNUM_2)
			.push_key(&pubkey)
			.push_key(&pubkey)
			.push_opcode(opcodes::all::OP_PUSHNUM_2)
			.push_opcode(opcodes::all::OP_CHECKMULTISIG)
			.into_script()
	}

	fn any_segwit_features() -> InitFeatures {
		let mut features = InitFeatures::empty();
		features.set_shutdown_any_segwit_optional();
		features
	}

	#[test]
	fn generates_p2wpkh_from_pubkey() {
		let pubkey = pubkey();
		let pubkey_hash = pubkey.wpubkey_hash().unwrap();
		let p2wpkh_script = ScriptBuf::new_v0_p2wpkh(&pubkey_hash);

		let shutdown_script = ShutdownScript::new_p2wpkh_from_pubkey(pubkey.inner);
		assert!(shutdown_script.is_compatible(&any_segwit_features()));
		assert!(shutdown_script.is_compatible(&InitFeatures::empty()));
		assert_eq!(shutdown_script.into_inner(), p2wpkh_script);
	}

	#[test]
	fn generates_p2wpkh_from_pubkey_hash() {
		let pubkey_hash = pubkey().wpubkey_hash().unwrap();
		let p2wpkh_script = ScriptBuf::new_v0_p2wpkh(&pubkey_hash);

		let shutdown_script = ShutdownScript::new_p2wpkh(&pubkey_hash);
		assert!(shutdown_script.is_compatible(&any_segwit_features()));
		assert!(shutdown_script.is_compatible(&InitFeatures::empty()));
		assert_eq!(shutdown_script.into_inner(), p2wpkh_script);
		assert!(ShutdownScript::try_from(p2wpkh_script).is_ok());
	}

	#[test]
	fn generates_p2wsh_from_script_hash() {
		let script_hash = redeem_script().wscript_hash();
		let p2wsh_script = ScriptBuf::new_v0_p2wsh(&script_hash);

		let shutdown_script = ShutdownScript::new_p2wsh(&script_hash);
		assert!(shutdown_script.is_compatible(&any_segwit_features()));
		assert!(shutdown_script.is_compatible(&InitFeatures::empty()));
		assert_eq!(shutdown_script.into_inner(), p2wsh_script);
		assert!(ShutdownScript::try_from(p2wsh_script).is_ok());
	}

	#[test]
	fn generates_segwit_from_non_v0_witness_program() {
		let witness_program = WitnessProgram::new(WitnessVersion::V16, &[0; 40]).unwrap();
		let script = ScriptBuf::new_witness_program(&witness_program);
		let shutdown_script = ShutdownScript::new_witness_program(&witness_program).unwrap();
		assert!(shutdown_script.is_compatible(&any_segwit_features()));
		assert!(!shutdown_script.is_compatible(&InitFeatures::empty()));
		assert_eq!(shutdown_script.into_inner(), script);
	}

	#[test]
	fn fails_from_unsupported_script() {
		let op_return = ScriptBuf::new_op_return(&[0; 42]);
		assert!(ShutdownScript::try_from(op_return).is_err());
	}
}
