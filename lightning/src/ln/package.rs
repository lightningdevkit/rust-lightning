//! Utilities for computing witnesses weight and feerate computation for onchain operation

use ln::msgs::DecodeError;
use util::ser::{Readable, Writer, Writeable};

#[derive(PartialEq, Clone, Copy)]
pub(crate) enum InputDescriptors {
	RevokedOfferedHTLC,
	RevokedReceivedHTLC,
	OfferedHTLC,
	ReceivedHTLC,
	RevokedOutput, // either a revoked to_holder output on commitment tx, a revoked HTLC-Timeout output or a revoked HTLC-Success output
}

impl Writeable for InputDescriptors {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
		match self {
			&InputDescriptors::RevokedOfferedHTLC => {
				writer.write_all(&[0; 1])?;
			},
			&InputDescriptors::RevokedReceivedHTLC => {
				writer.write_all(&[1; 1])?;
			},
			&InputDescriptors::OfferedHTLC => {
				writer.write_all(&[2; 1])?;
			},
			&InputDescriptors::ReceivedHTLC => {
				writer.write_all(&[3; 1])?;
			}
			&InputDescriptors::RevokedOutput => {
				writer.write_all(&[4; 1])?;
			}
		}
		Ok(())
	}
}

impl Readable for InputDescriptors {
	fn read<R: ::std::io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
		let input_descriptor = match <u8 as Readable>::read(reader)? {
			0 => {
				InputDescriptors::RevokedOfferedHTLC
			},
			1 => {
				InputDescriptors::RevokedReceivedHTLC
			},
			2 => {
				InputDescriptors::OfferedHTLC
			},
			3 => {
				InputDescriptors::ReceivedHTLC
			},
			4 => {
				InputDescriptors::RevokedOutput
			}
			_ => return Err(DecodeError::InvalidValue),
		};
		Ok(input_descriptor)
	}
}

pub(crate) fn get_witnesses_weight(inputs: &[InputDescriptors]) -> usize {
	let mut tx_weight = 2; // count segwit flags
	for inp in inputs {
		// We use expected weight (and not actual) as signatures and time lock delays may vary
		tx_weight +=  match inp {
			// number_of_witness_elements + sig_length + revocation_sig + pubkey_length + revocationpubkey + witness_script_length + witness_script
			&InputDescriptors::RevokedOfferedHTLC => {
				1 + 1 + 73 + 1 + 33 + 1 + 133
			},
			// number_of_witness_elements + sig_length + revocation_sig + pubkey_length + revocationpubkey + witness_script_length + witness_script
			&InputDescriptors::RevokedReceivedHTLC => {
				1 + 1 + 73 + 1 + 33 + 1 + 139
			},
			// number_of_witness_elements + sig_length + counterpartyhtlc_sig  + preimage_length + preimage + witness_script_length + witness_script
			&InputDescriptors::OfferedHTLC => {
				1 + 1 + 73 + 1 + 32 + 1 + 133
			},
			// number_of_witness_elements + sig_length + revocation_sig + pubkey_length + revocationpubkey + witness_script_length + witness_script
			&InputDescriptors::ReceivedHTLC => {
				1 + 1 + 73 + 1 + 1 + 1 + 139
			},
			// number_of_witness_elements + sig_length + revocation_sig + true_length + op_true + witness_script_length + witness_script
			&InputDescriptors::RevokedOutput => {
				1 + 1 + 73 + 1 + 1 + 1 + 77
			},
		};
	}
	tx_weight
}
