// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Shared code between BOLT 12 static and single-use invoices.

macro_rules! invoice_builder_methods_common { (
	$self: ident, $self_type: ty, $invoice_fields: expr, $return_type: ty, $return_value: expr,
	$type_param: ty $(, $self_mut: tt)?
) => {
	/// Sets the [`Bolt12Invoice::relative_expiry`] as seconds since [`Bolt12Invoice::created_at`].
	/// Any expiry that has already passed is valid and can be checked for using
	/// [`Bolt12Invoice::is_expired`].
	///
	/// Successive calls to this method will override the previous setting.
	pub fn relative_expiry($($self_mut)* $self: $self_type, relative_expiry_secs: u32) -> $return_type {
		let relative_expiry = Duration::from_secs(relative_expiry_secs as u64);
		$invoice_fields.relative_expiry = Some(relative_expiry);
		$return_value
	}

	/// Adds a P2WSH address to [`Bolt12Invoice::fallbacks`].
	///
	/// Successive calls to this method will add another address. Caller is responsible for not
	/// adding duplicate addresses and only calling if capable of receiving to P2WSH addresses.
	pub fn fallback_v0_p2wsh(
		$($self_mut)* $self: $self_type, script_hash: &bitcoin::WScriptHash
	) -> $return_type {
		use bitcoin::hashes::Hash;

		let address = FallbackAddress {
			version: bitcoin::WitnessVersion::V0.to_num(),
			program: Vec::from(script_hash.to_byte_array()),
		};
		$invoice_fields.fallbacks.get_or_insert_with(Vec::new).push(address);
		$return_value
	}

	/// Adds a P2WPKH address to [`Bolt12Invoice::fallbacks`].
	///
	/// Successive calls to this method will add another address. Caller is responsible for not
	/// adding duplicate addresses and only calling if capable of receiving to P2WPKH addresses.
	pub fn fallback_v0_p2wpkh(
		$($self_mut)* $self: $self_type, pubkey_hash: &bitcoin::WPubkeyHash
	) -> $return_type {
		use bitcoin::hashes::Hash;

		let address = FallbackAddress {
			version: bitcoin::WitnessVersion::V0.to_num(),
			program: Vec::from(pubkey_hash.to_byte_array()),
		};
		$invoice_fields.fallbacks.get_or_insert_with(Vec::new).push(address);
		$return_value
	}

	/// Adds a P2TR address to [`Bolt12Invoice::fallbacks`].
	///
	/// Successive calls to this method will add another address. Caller is responsible for not
	/// adding duplicate addresses and only calling if capable of receiving to P2TR addresses.
	pub fn fallback_v1_p2tr_tweaked(
		$($self_mut)* $self: $self_type, output_key: &bitcoin::key::TweakedPublicKey
	) -> $return_type {
		let address = FallbackAddress {
			version: bitcoin::WitnessVersion::V1.to_num(),
			program: Vec::from(&output_key.serialize()[..]),
		};
		$invoice_fields.fallbacks.get_or_insert_with(Vec::new).push(address);
		$return_value
	}

	/// Sets [`Bolt12Invoice::invoice_features`] to indicate MPP may be used. Otherwise, MPP is
	/// disallowed.
	pub fn allow_mpp($($self_mut)* $self: $self_type) -> $return_type {
		$invoice_fields.features.set_basic_mpp_optional();
		$return_value
	}
} }

macro_rules! invoice_accessors_common { ($self: ident, $contents: expr) => {
	/// Paths to the recipient originating from publicly reachable nodes, including information
	/// needed for routing payments across them.
	///
	/// Blinded paths provide recipient privacy by obfuscating its node id. Note, however, that this
	/// privacy is lost if a public node id is used for [`Bolt12Invoice::signing_pubkey`].
	///
	/// This is not exported to bindings users as slices with non-reference types cannot be ABI
	/// matched in another language.
	pub fn payment_paths(&$self) -> &[(BlindedPayInfo, BlindedPath)] {
		$contents.payment_paths()
	}

	/// Duration since the Unix epoch when the invoice was created.
	pub fn created_at(&$self) -> Duration {
		$contents.created_at()
	}

	/// Duration since [`Bolt12Invoice::created_at`] when the invoice has expired and therefore
	/// should no longer be paid.
	pub fn relative_expiry(&$self) -> Duration {
		$contents.relative_expiry()
	}

	/// Whether the invoice has expired.
	#[cfg(feature = "std")]
	pub fn is_expired(&$self) -> bool {
		$contents.is_expired()
	}

	/// Fallback addresses for paying the invoice on-chain, in order of most-preferred to
	/// least-preferred.
	pub fn fallbacks(&$self) -> Vec<Address> {
		$contents.fallbacks()
	}

	/// Features pertaining to paying an invoice.
	pub fn invoice_features(&$self) -> &Bolt12InvoiceFeatures {
		$contents.features()
	}

	/// The public key corresponding to the key used to sign the invoice.
	pub fn signing_pubkey(&$self) -> PublicKey {
		$contents.signing_pubkey()
	}
} }

pub(super) use invoice_accessors_common;
pub(super) use invoice_builder_methods_common;
