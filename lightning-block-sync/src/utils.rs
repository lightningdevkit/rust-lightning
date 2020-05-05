use bitcoin::util::uint::Uint256;

pub fn hex_to_uint256(hex: &str) -> Option<Uint256> {
	if hex.len() != 64 { return None; }
	let mut out = [0u64; 4];

	let mut b: u64 = 0;
	for (idx, c) in hex.as_bytes().iter().enumerate() {
		b <<= 4;
		match *c {
			b'A'..=b'F' => b |= (c - b'A' + 10) as u64,
			b'a'..=b'f' => b |= (c - b'a' + 10) as u64,
			b'0'..=b'9' => b |= (c - b'0') as u64,
			_ => return None,
		}
		if idx % 16 == 15 {
			out[3 - (idx / 16)] = b;
			b = 0;
		}
	}
	Some(Uint256::from(&out[..]))
}

#[cfg(feature = "rpc-client")]
pub fn hex_to_vec(hex: &str) -> Option<Vec<u8>> {
	let mut out = Vec::with_capacity(hex.len() / 2);

	let mut b = 0;
	for (idx, c) in hex.as_bytes().iter().enumerate() {
		b <<= 4;
		match *c {
			b'A'..=b'F' => b |= c - b'A' + 10,
			b'a'..=b'f' => b |= c - b'a' + 10,
			b'0'..=b'9' => b |= c - b'0',
			_ => return None,
		}
		if (idx & 1) == 1 {
			out.push(b);
			b = 0;
		}
	}

	Some(out)
}
