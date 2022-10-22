//! Low level invoice utilities.

use bitcoin::bech32::{u5, FromBase32};
use crate::prelude::*;

/// Construct the invoice's HRP and signatureless data into a preimage to be hashed.
pub fn construct_invoice_preimage(hrp_bytes: &[u8], data_without_signature: &[u5]) -> Vec<u8> {
	let mut preimage = Vec::<u8>::from(hrp_bytes);

	let mut data_part = Vec::from(data_without_signature);
	let overhang = (data_part.len() * 5) % 8;
	if overhang > 0 {
		// add padding if data does not end at a byte boundary
		data_part.push(u5::try_from_u8(0).unwrap());

		// if overhang is in (1..3) we need to add u5(0) padding two times
		if overhang < 3 {
			data_part.push(u5::try_from_u8(0).unwrap());
		}
	}

	preimage.extend_from_slice(&Vec::<u8>::from_base32(&data_part)
		.expect("No padding error may occur due to appended zero above."));
	preimage
}

