extern crate lightning;
extern crate secp256k1;

use lightning::ln::peer_channel_encryptor::PeerChannelEncryptor;

use secp256k1::key::{PublicKey,SecretKey};

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

	let our_network_key = match SecretKey::from_slice(get_slice!(32)) {
		Ok(key) => key,
		Err(_) => return,
	};
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
		crypter.get_act_one();
		match crypter.process_act_two(get_slice!(50), &our_network_key) {
			Ok(_) => {},
			Err(_) => return,
		}
		assert!(crypter.is_ready_for_encryption());
		crypter
	} else {
		let mut crypter = PeerChannelEncryptor::new_inbound(&our_network_key);
		match crypter.process_act_one_with_keys(get_slice!(50), &our_network_key, ephemeral_key) {
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
			crypter.encrypt_message(get_slice!(slice_to_be16(get_slice!(2))));
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

#[cfg(feature = "afl")]
#[macro_use] extern crate afl;
#[cfg(feature = "afl")]
fn main() {
	fuzz!(|data| {
		do_test(data);
	});
}

#[cfg(feature = "honggfuzz")]
#[macro_use] extern crate honggfuzz;
#[cfg(feature = "honggfuzz")]
fn main() {
	loop {
		fuzz!(|data| {
			do_test(data);
		});
	}
}

extern crate hex;
#[cfg(test)]
mod tests {

	#[test]
	fn duplicate_crash() {
		super::do_test(&::hex::decode("01").unwrap());
	}
}
