#![macro_use]

#[macro_export]
macro_rules! test_msg {
	($MsgType: path, $data: ident) => {
		{
			if let Ok(msg) = <$MsgType as MsgDecodable>::decode($data){
				let enc = msg.encode();
				assert_eq!(&$data[..enc.len()], &enc[..]);
			}
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
