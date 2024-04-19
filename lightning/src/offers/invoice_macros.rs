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
	$self: ident, $self_type: ty, $invoice_fields: expr, $return_type: ty, $return_value: expr, $type_param: ty $(, $self_mut: tt)?
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

pub(super) use invoice_builder_methods_common;
