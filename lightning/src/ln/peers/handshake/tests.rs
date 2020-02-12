#![cfg(test)]

use secp256k1::key::{PublicKey, SecretKey};

use ln::peers::handshake::PeerHandshake;

#[test]
fn test_exchange() {
	let curve = secp256k1::Secp256k1::new();

	let local_private_key = SecretKey::from_slice(&[0x_11_u8; 32]).unwrap();
	let remote_private_key = SecretKey::from_slice(&[0x_21_u8; 32]).unwrap();

	let local_ephemeral_private_key = SecretKey::from_slice(&[0x_12_u8; 32]).unwrap();
	let remote_ephemeral_private_key = SecretKey::from_slice(&[0x_22_u8; 32]).unwrap();

	let mut local_handshake = PeerHandshake::new(&local_private_key, &local_ephemeral_private_key);
	let mut remote_handshake = PeerHandshake::new(&remote_private_key, &remote_ephemeral_private_key);

	let remote_public_key = PublicKey::from_secret_key(&curve, &remote_private_key);

	let act_1_message = local_handshake.initiate(&remote_public_key);
	let act_2_message = remote_handshake.process_act_one(act_1_message.unwrap());
	let act_3_message = local_handshake.process_act_two(act_2_message.unwrap());
	remote_handshake.process_act_three(act_3_message.unwrap().0).unwrap();
}