// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

use lightning::ln::peer_channel_encryptor::PeerChannelEncryptor;
use lightning::util::test_utils::TestNodeSigner;

use bitcoin::secp256k1::{Secp256k1, PublicKey, SecretKey};

use crate::utils::test_logger;

#[inline]
fn slice_to_be16(v: &[u8]) -> u16 {
	((v[0] as u16) << 8*1) |
	((v[1] as u16) << 8*0)
}

#[inline]
pub fn do_test(data: &[u8]) {
	let mut read_pos = 0;
	macro_rules! get_slice {
		($len: expr) => {
			{
				let slice_len = $len as usize;
				if data.len() < read_pos + slice_len {
					return;
				}
				read_pos += slice_len;
				&data[read_pos - slice_len..read_pos]
			}
		}
	}

	let secp_ctx = Secp256k1::signing_only();

	let our_network_key = match SecretKey::from_slice(get_slice!(32)) {
		Ok(key) => key,
		Err(_) => return,
	};
	let node_signer = TestNodeSigner::new(our_network_key);
	let ephemeral_key = match SecretKey::from_slice(get_slice!(32)) {
		Ok(key) => key,
		Err(_) => return,
	};

	let mut crypter = if get_slice!(1)[0] != 0 {
		let their_pubkey = match PublicKey::from_slice(get_slice!(33)) {
			Ok(key) => key,
			Err(_) => return,
		};
		let mut crypter = PeerChannelEncryptor::new_outbound(their_pubkey, ephemeral_key);
		crypter.get_act_one(&secp_ctx);
		match crypter.process_act_two(get_slice!(50), &&node_signer) {
			Ok(_) => {},
			Err(_) => return,
		}
		assert!(crypter.is_ready_for_encryption());
		crypter
	} else {
		let mut crypter = PeerChannelEncryptor::new_inbound(&&node_signer);
		match crypter.process_act_one_with_keys(get_slice!(50), &&node_signer, ephemeral_key, &secp_ctx) {
			Ok(_) => {},
			Err(_) => return,
		}
		match crypter.process_act_three(get_slice!(66)) {
			Ok(_) => {},
			Err(_) => return,
		}
		assert!(crypter.is_ready_for_encryption());
		crypter
	};
	loop {
		if get_slice!(1)[0] == 0 {
			crypter.encrypt_buffer(get_slice!(slice_to_be16(get_slice!(2))));
		} else {
			let len = match crypter.decrypt_length_header(get_slice!(16+2)) {
				Ok(len) => len,
				Err(_) => return,
			};
			match crypter.decrypt_message(get_slice!(len as usize + 16)) {
				Ok(_) => {},
				Err(_) => return,
			}
		}
	}
}

pub fn peer_crypt_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}

#[no_mangle]
pub extern "C" fn peer_crypt_run(data: *const u8, datalen: usize) {
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) });
}
