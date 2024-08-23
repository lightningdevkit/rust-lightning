use crate::{
	sha256, Base32Len, FromBase32, PayeePubKey, PaymentSecret, PositiveTimestamp, RawDataPart,
	Sha256, ToBase32,
};

use core::fmt::Debug;
use std::str::FromStr;

/// Test base32 encode and decode
fn ser_de_test<T>(o: T, expected_str: &str)
where
	T: ToBase32 + FromBase32 + Eq + Debug,
	T::Err: Debug,
{
	let serialized_32 = o.to_base32();
	let serialized_str = serialized_32.iter().map(|f| f.to_char()).collect::<String>();
	assert_eq!(serialized_str, expected_str);

	// deserialize back
	let o2 = T::from_base32(&serialized_32).unwrap();
	assert_eq!(o, o2);
}

/// Test base32 encode and decode, and also length hint
fn ser_de_test_len<T>(o: T, expected_str: &str)
where
	T: ToBase32 + FromBase32 + Base32Len + Eq + Debug,
	T::Err: Debug,
{
	assert_eq!(o.base32_len(), expected_str.len());

	ser_de_test(o, expected_str)
}

#[test]
fn vec_u8() {
	ser_de_test_len(vec![0], "qq");
	ser_de_test_len(vec![255], "lu");
	ser_de_test_len(vec![0, 1], "qqqs");
	ser_de_test_len(vec![0, 1, 2], "qqqsy");
	ser_de_test_len(vec![0, 1, 2, 3], "qqqsyqc");
	ser_de_test_len(vec![0, 1, 2, 3, 4], "qqqsyqcy");
	ser_de_test_len(vec![0, 1, 2, 3, 4, 5], "qqqsyqcyq5");
	ser_de_test_len(vec![0, 1, 2, 3, 4, 5, 6], "qqqsyqcyq5rq");
	ser_de_test_len(vec![0, 1, 2, 3, 4, 5, 6, 7], "qqqsyqcyq5rqw");
	ser_de_test_len(vec![0, 1, 2, 3, 4, 5, 6, 7, 8], "qqqsyqcyq5rqwzq");
	ser_de_test_len(vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9], "qqqsyqcyq5rqwzqf");
	ser_de_test_len(vec![9, 8, 7, 6, 5, 4, 3, 2, 1, 0], "pyyqwps9qspsyqgq");
	ser_de_test_len(vec![255, 254, 253, 252, 251, 250, 249, 248, 247, 246], "lll0ml8mltul3alk");
}

#[test]
fn payment_secret() {
	let payment_secret = PaymentSecret([7; 32]);
	ser_de_test_len(payment_secret, "qurswpc8qurswpc8qurswpc8qurswpc8qurswpc8qurswpc8qurs");
}

#[test]
fn positive_timestamp() {
	use crate::PositiveTimestamp;

	let timestamp = PositiveTimestamp::from_unix_timestamp(10000).unwrap();
	ser_de_test(timestamp, "qqqqfcs");
}

#[test]
fn bolt11_invoice_features() {
	use crate::Bolt11InvoiceFeatures;

	let features = Bolt11InvoiceFeatures::from_le_bytes(vec![1, 2, 3, 4, 5, 42, 100, 101]);
	ser_de_test_len(features, "x2ep2q5zqxqsp");
}

#[test]
fn raw_tagged_field() {
	use crate::TaggedField::PaymentHash;

	let field = PaymentHash(Sha256(
		sha256::Hash::from_str("0001020304050607080900010203040506070809000102030405060708090102")
			.unwrap(),
	));
	ser_de_test(field, "pp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypq");
}

#[test]
fn sha256() {
	let hash = Sha256(
		sha256::Hash::from_str("0001020304050607080900010203040506070809000102030405060708090102")
			.unwrap(),
	);
	ser_de_test_len(hash, "qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypq");
}

#[test]
fn description() {
	use crate::Description;

	let description =
		Description::new("This is a looooong        description".to_string()).unwrap();
	ser_de_test_len(description, "235xjueqd9ejqcfqd3hk7mm0dahxwgpqyqszqgpqypjx2umrwf5hqarfdahq");
}

#[test]
fn raw_data_part() {
	use crate::TaggedField::PaymentHash;

	let raw_data_part = RawDataPart {
		timestamp: PositiveTimestamp::from_unix_timestamp(10000).unwrap(),
		tagged_fields: vec![PaymentHash(Sha256(
			sha256::Hash::from_str(
				"0001020304050607080900010203040506070809000102030405060708090102",
			)
			.unwrap(),
		))
		.into()],
	};
	ser_de_test(raw_data_part, "qqqqfcspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypq");
}

#[test]
fn payeepubkey() {
	use bitcoin::key::Secp256k1;
	use bitcoin::secp256k1::{PublicKey, SecretKey};

	let secp = Secp256k1::new();
	let dummy_secret_key = SecretKey::from_slice(&[1; 32]).unwrap();
	let payee_pub_key = PayeePubKey(PublicKey::from_secret_key(&secp, &dummy_secret_key));
	ser_de_test_len(payee_pub_key, "qvdcf32k0vfxgsyet5ldt246q4jaw8scx3sysx0lnstlt6w4m5rc7");
}

#[test]
fn expiry_time() {
	use crate::ExpiryTime;

	let expiry = ExpiryTime::from_seconds(10000);
	ser_de_test_len(expiry, "fcs");
}

#[test]
fn min_final_cltv_expiry_delta() {
	use crate::MinFinalCltvExpiryDelta;

	let cltv_delta = MinFinalCltvExpiryDelta(124);
	ser_de_test_len(cltv_delta, "ru");
}

#[test]
fn fallback() {
	use crate::{Fallback, PubkeyHash, ScriptHash, WitnessVersion};
	use bitcoin::hashes::Hash;

	{
		let fallback = Fallback::PubKeyHash(PubkeyHash::from_slice(&[3; 20]).unwrap());
		ser_de_test_len(fallback, "3qvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcr");
	}
	{
		let fallback = Fallback::ScriptHash(ScriptHash::from_slice(&[3; 20]).unwrap());
		ser_de_test_len(fallback, "jqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcr");
	}
	{
		let fallback =
			Fallback::SegWitProgram { version: WitnessVersion::V0, program: vec![3; 20] };
		ser_de_test_len(fallback, "qqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcr");
	}
}

#[test]
fn private_route() {
	use crate::{PrivateRoute, PublicKey, RouteHint, RouteHintHop, RoutingFees};

	let private_route = PrivateRoute(RouteHint(vec![RouteHintHop {
		src_node_id: PublicKey::from_slice(&vec![2; 33]).unwrap(),
		short_channel_id: 0x0102030405060708,
		fees: RoutingFees { base_msat: 1, proportional_millionths: 20 },
		cltv_expiry_delta: 3,
		htlc_minimum_msat: None,
		htlc_maximum_msat: None,
	}]));
	ser_de_test_len(
		private_route,
		"qgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqgzqvzq2ps8pqqqqqqpqqqqq9qqqv",
	);
}
