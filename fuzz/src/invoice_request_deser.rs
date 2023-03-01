// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

use bitcoin::secp256k1::{KeyPair, Parity, PublicKey, Secp256k1, SecretKey, self};
use crate::utils::test_logger;
use core::convert::{Infallible, TryFrom};
use lightning::chain::keysinterface::EntropySource;
use lightning::ln::PaymentHash;
use lightning::ln::features::BlindedHopFeatures;
use lightning::offers::invoice::{BlindedPayInfo, UnsignedInvoice};
use lightning::offers::invoice_request::InvoiceRequest;
use lightning::offers::parse::SemanticError;
use lightning::onion_message::BlindedPath;
use lightning::util::ser::Writeable;

#[inline]
pub fn do_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	if let Ok(invoice_request) = InvoiceRequest::try_from(data.to_vec()) {
		let mut bytes = Vec::with_capacity(data.len());
		invoice_request.write(&mut bytes).unwrap();
		assert_eq!(data, bytes);

		let secp_ctx = Secp256k1::new();
		let keys = KeyPair::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[42; 32]).unwrap());
		let mut buffer = Vec::new();

		if let Ok(unsigned_invoice) = build_response(&invoice_request, &secp_ctx) {
			let signing_pubkey = unsigned_invoice.signing_pubkey();
			let (x_only_pubkey, _) = keys.x_only_public_key();
			let odd_pubkey = x_only_pubkey.public_key(Parity::Odd);
			let even_pubkey = x_only_pubkey.public_key(Parity::Even);
			if signing_pubkey == odd_pubkey || signing_pubkey == even_pubkey {
				unsigned_invoice
					.sign::<_, Infallible>(
						|digest| Ok(secp_ctx.sign_schnorr_no_aux_rand(digest, &keys))
					)
					.unwrap()
					.write(&mut buffer)
					.unwrap();
			} else {
				unsigned_invoice
					.sign::<_, Infallible>(
						|digest| Ok(secp_ctx.sign_schnorr_no_aux_rand(digest, &keys))
					)
					.unwrap_err();
			}
		}
	}
}

struct Randomness;

impl EntropySource for Randomness {
	fn get_secure_random_bytes(&self) -> [u8; 32] { [42; 32] }
}

fn pubkey(byte: u8) -> PublicKey {
	let secp_ctx = Secp256k1::new();
	PublicKey::from_secret_key(&secp_ctx, &privkey(byte))
}

fn privkey(byte: u8) -> SecretKey {
	SecretKey::from_slice(&[byte; 32]).unwrap()
}

fn build_response<'a, T: secp256k1::Signing + secp256k1::Verification>(
	invoice_request: &'a InvoiceRequest, secp_ctx: &Secp256k1<T>
) -> Result<UnsignedInvoice<'a>, SemanticError> {
	let entropy_source = Randomness {};
	let paths = vec![
		BlindedPath::new(&[pubkey(43), pubkey(44), pubkey(42)], &entropy_source, secp_ctx).unwrap(),
		BlindedPath::new(&[pubkey(45), pubkey(46), pubkey(42)], &entropy_source, secp_ctx).unwrap(),
	];

	let payinfo = vec![
		BlindedPayInfo {
			fee_base_msat: 1,
			fee_proportional_millionths: 1_000,
			cltv_expiry_delta: 42,
			htlc_minimum_msat: 100,
			htlc_maximum_msat: 1_000_000_000_000,
			features: BlindedHopFeatures::empty(),
		},
		BlindedPayInfo {
			fee_base_msat: 1,
			fee_proportional_millionths: 1_000,
			cltv_expiry_delta: 42,
			htlc_minimum_msat: 100,
			htlc_maximum_msat: 1_000_000_000_000,
			features: BlindedHopFeatures::empty(),
		},
	];

	let payment_paths = paths.into_iter().zip(payinfo.into_iter()).collect();
	let payment_hash = PaymentHash([42; 32]);
	invoice_request.respond_with(payment_paths, payment_hash)?.build()
}

pub fn invoice_request_deser_test<Out: test_logger::Output>(data: &[u8], out: Out) {
	do_test(data, out);
}

#[no_mangle]
pub extern "C" fn invoice_request_deser_run(data: *const u8, datalen: usize) {
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) }, test_logger::DevNull {});
}
