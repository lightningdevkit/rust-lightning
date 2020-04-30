#![cfg(test)]

use hex;
use bitcoin::secp256k1;

use bitcoin::secp256k1::key::{PublicKey, SecretKey};

use ln::peers::handshake::PeerHandshake;

#[test]
fn test_exchange() {
	let curve = secp256k1::Secp256k1::new();

	let local_private_key = SecretKey::from_slice(&[0x_11_u8; 32]).unwrap();
	let remote_private_key = SecretKey::from_slice(&[0x_21_u8; 32]).unwrap();

	let local_ephemeral_private_key = SecretKey::from_slice(&[0x_12_u8; 32]).unwrap();
	let remote_ephemeral_private_key = SecretKey::from_slice(&[0x_22_u8; 32]).unwrap();

	let remote_public_key = PublicKey::from_secret_key(&curve, &remote_private_key);

	let mut local_handshake = PeerHandshake::new_outbound(&local_private_key, &remote_public_key, &local_ephemeral_private_key);
	let mut remote_handshake = PeerHandshake::new_inbound(&remote_private_key, &remote_ephemeral_private_key);

	let act_1 = local_handshake.initiate(&remote_public_key).unwrap();
	let act_1_hex = hex::encode(&act_1.0.to_vec());
	assert_eq!(act_1_hex, "00036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f70df6086551151f58b8afe6c195782c6a");

	let act_2 = remote_handshake.process_act_one(act_1).unwrap();
	let act_2_hex = hex::encode(&act_2.0.to_vec());
	assert_eq!(act_2_hex, "0002466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f276e2470b93aac583c9ef6eafca3f730ae");

	let act_2_result = local_handshake.process_act_two(act_2).unwrap();
	let act_3 = act_2_result.0;
	let act_3_hex = hex::encode(&act_3.0.to_vec());
	assert_eq!(act_3_hex, "00b9e3a702e93e3a9948c2ed6e5fd7590a6e1c3a0344cfc9d5b57357049aa22355361aa02e55a8fc28fef5bd6d71ad0c38228dc68b1c466263b47fdf31e560e139ba");

	remote_handshake.process_act_three(act_3).unwrap();
}
