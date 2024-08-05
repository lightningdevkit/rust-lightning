// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

use crate::utils::test_logger;
use bitcoin::secp256k1::{self, Keypair, Parity, PublicKey, Secp256k1, SecretKey};
use core::convert::TryFrom;
use lightning::blinded_path::payment::{
	Bolt12OfferContext, ForwardNode, ForwardTlvs, PaymentConstraints, PaymentContext, PaymentRelay,
	ReceiveTlvs,
};
use lightning::blinded_path::BlindedPath;
use lightning::ln::channelmanager::MIN_FINAL_CLTV_EXPIRY_DELTA;
use lightning::ln::features::BlindedHopFeatures;
use lightning::ln::types::PaymentSecret;
use lightning::ln::PaymentHash;
use lightning::offers::invoice::UnsignedBolt12Invoice;
use lightning::offers::invoice_request::{InvoiceRequest, InvoiceRequestFields};
use lightning::offers::offer::OfferId;
use lightning::offers::parse::Bolt12SemanticError;
use lightning::sign::EntropySource;
use lightning::util::ser::Writeable;
use lightning::util::string::UntrustedString;

#[inline]
pub fn do_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	if let Ok(invoice_request) = InvoiceRequest::try_from(data.to_vec()) {
		let mut bytes = Vec::with_capacity(data.len());
		invoice_request.write(&mut bytes).unwrap();
		assert_eq!(data, bytes);

		let secp_ctx = Secp256k1::new();
		let keys = Keypair::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[42; 32]).unwrap());
		let mut buffer = Vec::new();

		if let Ok(unsigned_invoice) = build_response(&invoice_request, &secp_ctx) {
			let signing_pubkey = unsigned_invoice.signing_pubkey();
			let (x_only_pubkey, _) = keys.x_only_public_key();
			let odd_pubkey = x_only_pubkey.public_key(Parity::Odd);
			let even_pubkey = x_only_pubkey.public_key(Parity::Even);
			if signing_pubkey == odd_pubkey || signing_pubkey == even_pubkey {
				unsigned_invoice
					.sign(|message: &UnsignedBolt12Invoice| {
						Ok(secp_ctx.sign_schnorr_no_aux_rand(message.as_ref().as_digest(), &keys))
					})
					.unwrap()
					.write(&mut buffer)
					.unwrap();
			} else {
				unsigned_invoice
					.sign(|message: &UnsignedBolt12Invoice| {
						Ok(secp_ctx.sign_schnorr_no_aux_rand(message.as_ref().as_digest(), &keys))
					})
					.unwrap_err();
			}
		}
	}
}

struct Randomness;

impl EntropySource for Randomness {
	fn get_secure_random_bytes(&self) -> [u8; 32] {
		[42; 32]
	}
}

fn pubkey(byte: u8) -> PublicKey {
	let secp_ctx = Secp256k1::new();
	PublicKey::from_secret_key(&secp_ctx, &privkey(byte))
}

fn privkey(byte: u8) -> SecretKey {
	SecretKey::from_slice(&[byte; 32]).unwrap()
}

fn build_response<T: secp256k1::Signing + secp256k1::Verification>(
	invoice_request: &InvoiceRequest, secp_ctx: &Secp256k1<T>,
) -> Result<UnsignedBolt12Invoice, Bolt12SemanticError> {
	let entropy_source = Randomness {};
	let payment_context = PaymentContext::Bolt12Offer(Bolt12OfferContext {
		offer_id: OfferId([42; 32]),
		invoice_request: InvoiceRequestFields {
			payer_id: invoice_request.payer_id(),
			quantity: invoice_request.quantity(),
			payer_note_truncated: invoice_request
				.payer_note()
				.map(|s| UntrustedString(s.to_string())),
		},
	});
	let payee_tlvs = ReceiveTlvs {
		payment_secret: PaymentSecret([42; 32]),
		payment_constraints: PaymentConstraints {
			max_cltv_expiry: 1_000_000,
			htlc_minimum_msat: 1,
		},
		payment_context,
	};
	let intermediate_nodes = [ForwardNode {
		tlvs: ForwardTlvs {
			short_channel_id: 43,
			payment_relay: PaymentRelay {
				cltv_expiry_delta: 40,
				fee_proportional_millionths: 1_000,
				fee_base_msat: 1,
			},
			payment_constraints: PaymentConstraints {
				max_cltv_expiry: payee_tlvs.payment_constraints.max_cltv_expiry + 40,
				htlc_minimum_msat: 100,
			},
			features: BlindedHopFeatures::empty(),
		},
		node_id: pubkey(43),
		htlc_maximum_msat: 1_000_000_000_000,
	}];
	let payment_path = BlindedPath::new_for_payment(
		&intermediate_nodes,
		pubkey(42),
		payee_tlvs,
		u64::MAX,
		MIN_FINAL_CLTV_EXPIRY_DELTA,
		&entropy_source,
		secp_ctx,
	)
	.unwrap();

	let payment_hash = PaymentHash([42; 32]);
	invoice_request.respond_with(vec![payment_path], payment_hash)?.build()
}

pub fn invoice_request_deser_test<Out: test_logger::Output>(data: &[u8], out: Out) {
	do_test(data, out);
}

#[no_mangle]
pub extern "C" fn invoice_request_deser_run(data: *const u8, datalen: usize) {
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) }, test_logger::DevNull {});
}
