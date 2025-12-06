//! Abstractions for scripts used in the Lightning Network.

use bitcoin::blockdata::script::Instruction;
use bitcoin::hashes::Hash;
use bitcoin::opcodes::all::{OP_PUSHBYTES_0 as SEGWIT_V0, OP_RETURN};
use bitcoin::script::{PushBytes, Script, ScriptBuf};
use bitcoin::secp256k1::PublicKey;
use bitcoin::{WPubkeyHash, WScriptHash, WitnessProgram};

use crate::ln::channelmanager;
use crate::ln::msgs::DecodeError;
use crate::types::features::InitFeatures;
use crate::util::config::UserConfig;
use crate::util::ser::{Readable, Writeable, Writer};

use crate::io;

#[allow(unused_imports)]
use crate::prelude::*;

/// A script pubkey for shutting down a channel as defined by [BOLT #2].
///
/// [BOLT #2]: https://github.com/lightning/bolts/blob/master/02-peer-protocol.md
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ShutdownScript(ShutdownScriptImpl);

/// An error occurring when converting from [`ScriptBuf`] to [`ShutdownScript`].
#[derive(Clone, Debug)]
pub struct InvalidShutdownScript {
	/// The script that did not meet the requirements from [BOLT #2].
	///
	/// [BOLT #2]: https://github.com/lightning/bolts/blob/master/02-peer-protocol.md
	pub script: ScriptBuf,
}

#[derive(Clone, PartialEq, Eq, Debug)]
enum ShutdownScriptImpl {
	/// [`PublicKey`] used to form a P2WPKH script pubkey. Used to support backward-compatible
	/// serialization.
	Legacy(PublicKey),

	/// [`ScriptBuf`] adhering to a script pubkey format specified in BOLT #2.
	Bolt2(ScriptBuf),
}

impl Writeable for ShutdownScript {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		self.0.write(w)
	}
}

impl Readable for ShutdownScript {
	fn read<R: io::Read>(r: &mut R) -> Result<Self, DecodeError> {
		Ok(ShutdownScript(ShutdownScriptImpl::read(r)?))
	}
}

impl_writeable_tlv_based_enum_legacy!(ShutdownScriptImpl, ;
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
		Self(ShutdownScriptImpl::Bolt2(ScriptBuf::new_p2wpkh(pubkey_hash)))
	}

	/// Generates a P2WSH script pubkey from the given [`WScriptHash`].
	pub fn new_p2wsh(script_hash: &WScriptHash) -> Self {
		Self(ShutdownScriptImpl::Bolt2(ScriptBuf::new_p2wsh(script_hash)))
	}

	/// Generates an `OP_RETURN` script pubkey from the given `data` bytes.
	///
	/// This is only needed and valid for channels supporting `option_simple_close`. Please refer
	/// to [BOLT-2] for more information.
	///
	/// # Errors
	///
	/// This function may return an error if `data` is not [BOLT-2] compliant.
	///
	/// [BOLT-2]: https://github.com/lightning/bolts/blob/master/02-peer-protocol.md#closing-negotiation-closing_complete-and-closing_sig
	pub fn new_op_return<T: AsRef<PushBytes>>(data: T) -> Result<Self, InvalidShutdownScript> {
		Self::try_from(ScriptBuf::new_op_return(data))
	}

	/// Generates a witness script pubkey from the given segwit version and program.
	///
	/// Note for version-zero witness scripts you must use [`ShutdownScript::new_p2wpkh`] or
	/// [`ShutdownScript::new_p2wsh`] instead.
	///
	/// # Errors
	///
	/// This function may return an error if `program` is invalid for the segwit `version`.
	pub fn new_witness_program(
		witness_program: &WitnessProgram,
	) -> Result<Self, InvalidShutdownScript> {
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
	/// Specifically, checks for compliance with feature `option_shutdown_anysegwit` and/or
	/// `option_simple_close`.
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
	// BOLT2:
	// 1. `OP_0` `20` 20-bytes (version 0 pay to witness pubkey hash), OR
	// 2. `OP_0` `32` 32-bytes (version 0 pay to witness script hash), OR
	if script.is_p2pkh() || script.is_p2sh() || script.is_p2wpkh() || script.is_p2wsh() {
		true
	} else if features.supports_shutdown_anysegwit() && script.is_witness_program() {
		// 3. if (and only if) `option_shutdown_anysegwit` is negotiated:
		//    * `OP_1` through `OP_16` inclusive, followed by a single push of 2 to 40 bytes
		//     (witness program versions 1 through 16)
		script.as_bytes()[0] != SEGWIT_V0.to_u8()
	} else if features.supports_simple_close() && script.is_op_return() {
		// 4. if (and only if) `option_simple_close` is negotiated:
		let mut instruction_iter = script.instructions();
		if let Some(Ok(Instruction::Op(opcode))) = instruction_iter.next() {
			// * `OP_RETURN` followed by one of:
			if opcode != OP_RETURN {
				return false;
			}

			match instruction_iter.next() {
				Some(Ok(Instruction::PushBytes(bytes))) => {
					// * `6` to `75` inclusive followed by exactly that many bytes
					if (6..=75).contains(&bytes.len()) {
						return instruction_iter.next().is_none();
					}

					// `rust-bitcoin` interprets `OP_PUSHDATA1` as `Instruction::PushBytes`, having
					// us land here in this case, too.
					//
					// * `76` followed by `76` to `80` followed by exactly that many bytes
					if (76..=80).contains(&bytes.len()) {
						return instruction_iter.next().is_none();
					}

					false
				},
				_ => false,
			}
		} else {
			false
		}
	} else {
		false
	}
}

// Note that this is only for our own shutdown scripts. Counterparties are still allowed to send us
// non-witness shutdown scripts which this rejects.
impl TryFrom<ScriptBuf> for ShutdownScript {
	type Error = InvalidShutdownScript;

	fn try_from(script: ScriptBuf) -> Result<Self, Self::Error> {
		let features = channelmanager::provided_init_features(&UserConfig::default());
		Self::try_from((script, &features))
	}
}

// Note that this is only for our own shutdown scripts. Counterparties are still allowed to send us
// non-witness shutdown scripts which this rejects.
impl TryFrom<(ScriptBuf, &InitFeatures)> for ShutdownScript {
	type Error = InvalidShutdownScript;

	fn try_from((script, features): (ScriptBuf, &InitFeatures)) -> Result<Self, Self::Error> {
		if is_bolt2_compliant(&script, features) {
			Ok(Self(ShutdownScriptImpl::Bolt2(script)))
		} else {
			Err(InvalidShutdownScript { script })
		}
	}
}

impl From<ShutdownScript> for ScriptBuf {
	fn from(value: ShutdownScript) -> Self {
		match value.0 {
			ShutdownScriptImpl::Legacy(pubkey) => {
				ScriptBuf::new_p2wpkh(&WPubkeyHash::hash(&pubkey.serialize()))
			},
			ShutdownScriptImpl::Bolt2(script_pubkey) => script_pubkey,
		}
	}
}

impl core::fmt::Display for ShutdownScript {
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

	use bitcoin::opcodes;
	use bitcoin::script::{Builder, PushBytes, ScriptBuf};
	use bitcoin::secp256k1::Secp256k1;
	use bitcoin::secp256k1::{PublicKey, SecretKey};
	use bitcoin::{WitnessProgram, WitnessVersion};

	use crate::prelude::*;
	use crate::types::features::InitFeatures;

	fn pubkey() -> bitcoin::key::PublicKey {
		let secp_ctx = Secp256k1::signing_only();
		let secret_key = SecretKey::from_slice(&[
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 1,
		])
		.unwrap();
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

	#[cfg(simple_close)]
	fn simple_close_features() -> InitFeatures {
		let mut features = InitFeatures::empty();
		features.set_simple_close_optional();
		features
	}

	#[test]
	fn generates_p2wpkh_from_pubkey() {
		let pubkey = pubkey();
		let pubkey_hash = pubkey.wpubkey_hash().unwrap();
		let p2wpkh_script = ScriptBuf::new_p2wpkh(&pubkey_hash);

		let shutdown_script = ShutdownScript::new_p2wpkh_from_pubkey(pubkey.inner);
		assert!(shutdown_script.is_compatible(&any_segwit_features()));
		assert!(shutdown_script.is_compatible(&InitFeatures::empty()));
		assert_eq!(shutdown_script.into_inner(), p2wpkh_script);
	}

	#[test]
	fn generates_p2wpkh_from_pubkey_hash() {
		let pubkey_hash = pubkey().wpubkey_hash().unwrap();
		let p2wpkh_script = ScriptBuf::new_p2wpkh(&pubkey_hash);

		let shutdown_script = ShutdownScript::new_p2wpkh(&pubkey_hash);
		assert!(shutdown_script.is_compatible(&any_segwit_features()));
		assert!(shutdown_script.is_compatible(&InitFeatures::empty()));
		assert_eq!(shutdown_script.into_inner(), p2wpkh_script);
		assert!(ShutdownScript::try_from(p2wpkh_script).is_ok());
	}

	#[test]
	fn generates_p2wsh_from_script_hash() {
		let script_hash = redeem_script().wscript_hash();
		let p2wsh_script = ScriptBuf::new_p2wsh(&script_hash);

		let shutdown_script = ShutdownScript::new_p2wsh(&script_hash);
		assert!(shutdown_script.is_compatible(&any_segwit_features()));
		assert!(shutdown_script.is_compatible(&InitFeatures::empty()));
		assert_eq!(shutdown_script.into_inner(), p2wsh_script);
		assert!(ShutdownScript::try_from(p2wsh_script).is_ok());
	}

	#[cfg(simple_close)]
	#[test]
	fn generates_op_return_from_data() {
		let data = [6; 6];
		let op_return_script = ScriptBuf::new_op_return(&data);
		let shutdown_script = ShutdownScript::new_op_return(&data).unwrap();
		assert!(shutdown_script.is_compatible(&simple_close_features()));
		assert!(!shutdown_script.is_compatible(&InitFeatures::empty()));
		assert_eq!(shutdown_script.into_inner(), op_return_script);
		assert!(ShutdownScript::try_from(op_return_script).is_ok());

		let assert_pushdata_script_compat = |len| {
			let mut pushdata_vec = Builder::new()
				.push_opcode(opcodes::all::OP_RETURN)
				.push_opcode(opcodes::all::OP_PUSHDATA1)
				.into_bytes();
			pushdata_vec.push(len as u8);
			pushdata_vec.extend_from_slice(&vec![1u8; len]);
			let pushdata_script = ScriptBuf::from_bytes(pushdata_vec);
			let pushdata_shutdown_script = ShutdownScript::try_from(pushdata_script).unwrap();
			assert!(pushdata_shutdown_script.is_compatible(&simple_close_features()));
			assert!(!pushdata_shutdown_script.is_compatible(&InitFeatures::empty()));
		};

		// For `option_simple_close` we assert compatibility with `OP_PUSHDATA1` scripts for the
		// intended length range of 76 to 80 bytes.
		assert_pushdata_script_compat(76);
		assert_pushdata_script_compat(80);

		// While the `option_simple_close` spec prescribes the use of `OP_PUSHBYTES_0` up to 75
		// bytes, we follow Postel's law and accept if our counterparty would create an
		// `OP_PUSHDATA1` script for less than 76 bytes of payload.
		assert_pushdata_script_compat(75);
		assert_pushdata_script_compat(6);
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
		// For `option_simple_close` we assert we fail when:
		//
		// - The first byte of the OP_RETURN data (interpreted as u8 int) is not equal to the
		// remaining number of bytes (i.e., `[5; 6]` would succeed here).
		let op_return = ScriptBuf::new_op_return(&[5; 5]);
		assert!(ShutdownScript::try_from(op_return).is_err());

		// - The OP_RETURN data will fail if it's longer than 80 bytes.
		let mut pushdata_vec = Builder::new()
			.push_opcode(opcodes::all::OP_RETURN)
			.push_opcode(opcodes::all::OP_PUSHDATA1)
			.into_bytes();
		pushdata_vec.push(81);
		pushdata_vec.extend_from_slice(&[1u8; 81]);
		let pushdata_script = ScriptBuf::from_bytes(pushdata_vec);
		assert!(ShutdownScript::try_from(pushdata_script).is_err());

		// - In `ShutdownScript::new_op_return` the OP_RETURN data is longer than 80 bytes.
		let big_buffer = &[1u8; 81][..];
		let push_bytes: &PushBytes = big_buffer.try_into().unwrap();
		assert!(ShutdownScript::new_op_return(&push_bytes).is_err());
	}
}
