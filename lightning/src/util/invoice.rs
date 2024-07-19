//! Low level invoice utilities.

use crate::ln::types::InvoiceData;
use bech32::{Fe32, Fe32IterExt};

#[allow(unused)]
use crate::prelude::*;

/// Construct the invoice's HRP and signatureless data into a preimage to be hashed.
/// TODO(bech32): This should be moved to lightning-invoice crate, and use FromBase32 from there
pub fn construct_invoice_preimage(hrp_bytes: &[u8], data_without_signature: &InvoiceData) -> Vec<u8> {
	let mut preimage = Vec::<u8>::from(hrp_bytes);

	let mut data_part = data_without_signature.0.clone();
	let overhang = (data_part.len() * 5) % 8;
	if overhang > 0 {
		// add padding if data does not end at a byte boundary
		data_part.push(Fe32::try_from(0).unwrap());

		// if overhang is in (1..3) we need to add u5(0) padding two times
		if overhang < 3 {
			data_part.push(Fe32::try_from(0).unwrap());
		}
	}

	// TODO(bech32): Should use FromBase32 from lightning-invoice crate
	preimage.extend(&data_part.iter().copied().fes_to_bytes().collect::<Vec<u8>>());
	preimage
}

