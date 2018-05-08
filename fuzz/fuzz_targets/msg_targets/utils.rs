#![macro_use]

#[allow(dead_code)]
#[inline]
pub fn slice_to_be16(v: &[u8]) -> u16 {
	  ((v[0] as u16) << 8*1) |
			  ((v[1] as u16) << 8*0)
}

#[macro_export]
macro_rules! test_msg {
	($MsgType: path, $data: ident, $read_pos: ident) => {
		{
			let len = slice_to_be16(get_slice!($data, $read_pos, 2));
			let raw = get_slice!($data, $read_pos, len);
			let cb = decode_msg!($MsgType, raw).encode();
			assert_eq!(&raw[..cb.len()], &cb[..]);
		}
	}
}

#[macro_export]
macro_rules! decode_msg {
	($MsgType: path, $data: expr) => {
		match <($MsgType)>::decode($data) {
			Ok(msg) => msg,
			Err(e) => match e {
				msgs::DecodeError::UnknownRealmByte => return,
				msgs::DecodeError::BadPublicKey => return,
				msgs::DecodeError::BadSignature => return,
				msgs::DecodeError::ExtraAddressesPerType => return,
				msgs::DecodeError::WrongLength => return,
			}
		}
	}
}

#[macro_export]
macro_rules! get_slice {
	($data: ident, $read_pos: ident, $len: expr) => {
		{
			let slice_len = $len as usize;
			if $data.len() < $read_pos + slice_len {
				return;
			}
			$read_pos += slice_len;
			&$data[$read_pos - slice_len..$read_pos]
		}
	}
}

#[allow(dead_code)]
#[cfg(test)]
pub fn extend_vec_from_hex(hex: &str, out: &mut Vec<u8>) {
	let mut b = 0;
	for (idx, c) in hex.as_bytes().iter().enumerate() {
		b <<= 4;
		match *c {
			b'A'...b'F' => b |= c - b'A' + 10,
			b'a'...b'f' => b |= c - b'a' + 10,
			b'0'...b'9' => b |= c - b'0',
			_ => panic!("Bad hex"),
		}
		if (idx & 1) == 1 {
			out.push(b);
			b = 0;
		}
	}
}
