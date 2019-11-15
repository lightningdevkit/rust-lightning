#[inline]
pub fn slice_to_be16(v: &[u8]) -> u16 {
	((v[0] as u16) << 8*1) |
	((v[1] as u16) << 8*0)
}
#[inline]
pub fn slice_to_be32(v: &[u8]) -> u32 {
	((v[0] as u32) << 8*3) |
	((v[1] as u32) << 8*2) |
	((v[2] as u32) << 8*1) |
	((v[3] as u32) << 8*0)
}
#[cfg(not(feature = "fuzztarget"))] // Used only by poly1305
#[inline]
pub fn slice_to_le32(v: &[u8]) -> u32 {
	((v[0] as u32) << 8*0) |
	((v[1] as u32) << 8*1) |
	((v[2] as u32) << 8*2) |
	((v[3] as u32) << 8*3)
}
#[inline]
pub fn slice_to_be48(v: &[u8]) -> u64 {
	((v[0] as u64) << 8*5) |
	((v[1] as u64) << 8*4) |
	((v[2] as u64) << 8*3) |
	((v[3] as u64) << 8*2) |
	((v[4] as u64) << 8*1) |
	((v[5] as u64) << 8*0)
}
#[inline]
pub fn slice_to_be64(v: &[u8]) -> u64 {
	((v[0] as u64) << 8*7) |
	((v[1] as u64) << 8*6) |
	((v[2] as u64) << 8*5) |
	((v[3] as u64) << 8*4) |
	((v[4] as u64) << 8*3) |
	((v[5] as u64) << 8*2) |
	((v[6] as u64) << 8*1) |
	((v[7] as u64) << 8*0)
}

#[inline]
pub fn be16_to_array(u: u16) -> [u8; 2] {
	let mut v = [0; 2];
	v[0] = ((u >> 8*1) & 0xff) as u8;
	v[1] = ((u >> 8*0) & 0xff) as u8;
	v
}
#[inline]
pub fn be32_to_array(u: u32) -> [u8; 4] {
	let mut v = [0; 4];
	v[0] = ((u >> 8*3) & 0xff) as u8;
	v[1] = ((u >> 8*2) & 0xff) as u8;
	v[2] = ((u >> 8*1) & 0xff) as u8;
	v[3] = ((u >> 8*0) & 0xff) as u8;
	v
}
#[cfg(not(feature = "fuzztarget"))] // Used only by poly1305
#[inline]
pub fn le32_to_array(u: u32) -> [u8; 4] {
	let mut v = [0; 4];
	v[0] = ((u >> 8*0) & 0xff) as u8;
	v[1] = ((u >> 8*1) & 0xff) as u8;
	v[2] = ((u >> 8*2) & 0xff) as u8;
	v[3] = ((u >> 8*3) & 0xff) as u8;
	v
}
#[inline]
pub fn be48_to_array(u: u64) -> [u8; 6] {
	assert!(u & 0xffff_0000_0000_0000 == 0);
	let mut v = [0; 6];
	v[0] = ((u >> 8*5) & 0xff) as u8;
	v[1] = ((u >> 8*4) & 0xff) as u8;
	v[2] = ((u >> 8*3) & 0xff) as u8;
	v[3] = ((u >> 8*2) & 0xff) as u8;
	v[4] = ((u >> 8*1) & 0xff) as u8;
	v[5] = ((u >> 8*0) & 0xff) as u8;
	v
}
#[inline]
pub fn be64_to_array(u: u64) -> [u8; 8] {
	let mut v = [0; 8];
	v[0] = ((u >> 8*7) & 0xff) as u8;
	v[1] = ((u >> 8*6) & 0xff) as u8;
	v[2] = ((u >> 8*5) & 0xff) as u8;
	v[3] = ((u >> 8*4) & 0xff) as u8;
	v[4] = ((u >> 8*3) & 0xff) as u8;
	v[5] = ((u >> 8*2) & 0xff) as u8;
	v[6] = ((u >> 8*1) & 0xff) as u8;
	v[7] = ((u >> 8*0) & 0xff) as u8;
	v
}

#[inline]
pub fn le64_to_array(u: u64) -> [u8; 8] {
	let mut v = [0; 8];
	v[0] = ((u >> 8*0) & 0xff) as u8;
	v[1] = ((u >> 8*1) & 0xff) as u8;
	v[2] = ((u >> 8*2) & 0xff) as u8;
	v[3] = ((u >> 8*3) & 0xff) as u8;
	v[4] = ((u >> 8*4) & 0xff) as u8;
	v[5] = ((u >> 8*5) & 0xff) as u8;
	v[6] = ((u >> 8*6) & 0xff) as u8;
	v[7] = ((u >> 8*7) & 0xff) as u8;
	v
}
