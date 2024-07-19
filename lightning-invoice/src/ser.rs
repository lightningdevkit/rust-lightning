use core::fmt;
use core::fmt::{Display, Formatter};
use bech32::{Bech32, ByteIterExt, Fe32, Fe32IterExt, Hrp};
use crate::prelude::*;

use super::{Bolt11Invoice, Bolt11InvoiceFeatures, Sha256, TaggedField, ExpiryTime, MinFinalCltvExpiryDelta, Fallback, PayeePubKey, Bolt11InvoiceSignature, PaymentSecret, PositiveTimestamp,
	PrivateRoute, Description, RawTaggedField, Currency, RawHrp, SiPrefix, constants, SignedRawBolt11Invoice, RawDataPart, WriteBase32, ToBase32, Base32Len};

impl WriteBase32 for Vec<Fe32> {
	type Err = ();

	fn write(&mut self, data: &Vec<Fe32>) -> Result<(), Self::Err> {
		self.extend_from_slice(data);
		Ok(())
	}

	fn write_fe32(&mut self, data: Fe32) -> Result<(), Self::Err> {
		self.push(data);
		Ok(())
	}
}

impl ToBase32 for Vec<u8> {
	/// Encode as base32 and write it to the supplied writer
	fn write_base32<W: WriteBase32>(&self, writer: &mut W) -> Result<(), <W as WriteBase32>::Err> {
		writer.write(&self.iter().copied().bytes_to_fes().collect::<Vec<Fe32>>())
	}
}

impl Base32Len for Vec<u8> {
	/// Calculate the base32 serialized length
	fn base32_len(&self) -> usize {
		(self.len() * 8 + 7) / 5
	}
}

impl ToBase32 for PaymentSecret {
	fn write_base32<W: WriteBase32>(&self, writer: &mut W) -> Result<(), <W as WriteBase32>::Err> {
		(&self.0[..]).to_vec().write_base32(writer)
	}
}

impl Base32Len for PaymentSecret {
	fn base32_len(&self) -> usize {
		52
	}
}

impl ToBase32 for Bolt11InvoiceFeatures {
	fn write_base32<W: WriteBase32>(&self, writer: &mut W) -> Result<(), <W as WriteBase32>::Err> {
		// Explanation for the "4": the normal way to round up when dividing is to add the divisor
		// minus one before dividing
		let length_u5s = (self.flags().len() * 8 + 4) / 5 as usize;
		let mut res_u5s: Vec<Fe32> = vec![Fe32::Q; length_u5s];
		for (byte_idx, byte) in self.flags().iter().enumerate() {
			let bit_pos_from_left_0_indexed = byte_idx * 8;
			let new_u5_idx = length_u5s - (bit_pos_from_left_0_indexed / 5) as usize - 1;
			let new_bit_pos = bit_pos_from_left_0_indexed % 5;
			let shifted_chunk_u16 = (*byte as u16) << new_bit_pos;
			let curr_u5_as_u8 = res_u5s[new_u5_idx].to_u8();
			res_u5s[new_u5_idx] = Fe32::try_from(curr_u5_as_u8 | ((shifted_chunk_u16 & 0x001f) as u8)).unwrap();
			if new_u5_idx > 0 {
				let curr_u5_as_u8 = res_u5s[new_u5_idx - 1].to_u8();
				res_u5s[new_u5_idx - 1] = Fe32::try_from(curr_u5_as_u8 | (((shifted_chunk_u16 >> 5) & 0x001f) as u8)).unwrap();
			}
			if new_u5_idx > 1 {
				let curr_u5_as_u8 = res_u5s[new_u5_idx - 2].to_u8();
				res_u5s[new_u5_idx - 2] = Fe32::try_from(curr_u5_as_u8 | (((shifted_chunk_u16 >> 10) & 0x001f) as u8)).unwrap();
			}
		}
		// Trim the highest feature bits.
		while !res_u5s.is_empty() && res_u5s[0] == Fe32::Q {
			res_u5s.remove(0);
		}
		writer.write(&res_u5s)
	}
}

impl Base32Len for Bolt11InvoiceFeatures {
	fn base32_len(&self) -> usize {
		self.to_base32().len()
	}
}

/// Converts a stream of bytes written to it to base32. On finalization the according padding will
/// be applied. That means the results of writing two data blocks with one or two `BytesToBase32`
/// converters will differ.
struct BytesToBase32<'a, W: WriteBase32 + 'a> {
	/// Target for writing the resulting `Fe32`s resulting from the written bytes
	writer: &'a mut W,
	/// Holds all unwritten bits left over from last round. The bits are stored beginning from
	/// the most significant bit. E.g. if buffer_bits=3, then the byte with bits a, b and c will
	/// look as follows: [a, b, c, 0, 0, 0, 0, 0]
	buffer: u8,
	/// Amount of bits left over from last round, stored in buffer.
	buffer_bits: u8,
}

impl<'a, W: WriteBase32> BytesToBase32<'a, W> {
	/// Create a new bytes-to-base32 converter with `writer` as  a sink for the resulting base32
	/// data.
	pub fn new(writer: &'a mut W) -> BytesToBase32<'a, W> {
		BytesToBase32 {
			writer,
			buffer: 0,
			buffer_bits: 0,
		}
	}

	/// Add more bytes to the current conversion unit
	pub fn append(&mut self, bytes: &[u8]) -> Result<(), W::Err> {
		for b in bytes {
			self.append_u8(*b)?;
		}
		Ok(())
	}

	pub fn append_u8(&mut self, byte: u8) -> Result<(), W::Err> {
		// Write first Fe32 if we have to write two Fe32s this round. That only happens if the
		// buffer holds too many bits, so we don't have to combine buffer bits with new bits
		// from this rounds byte.
		if self.buffer_bits >= 5 {
			self.writer.write_fe32(
				Fe32::try_from((self.buffer & 0b11111000) >> 3 ).expect("<32")
			)?;
			self.buffer <<= 5;
			self.buffer_bits -= 5;
		}

		// Combine all bits from buffer with enough bits from this rounds byte so that they fill
		// a Fe32. Save remaining bits from byte to buffer.
		let from_buffer = self.buffer >> 3;
		let from_byte = byte >> (3 + self.buffer_bits); // buffer_bits <= 4

		self.writer.write_fe32(Fe32::try_from(from_buffer | from_byte).expect("<32"))?;
		self.buffer = byte << (5 - self.buffer_bits);
		self.buffer_bits += 3;

		Ok(())
	}

	pub fn finalize(mut self) ->  Result<(), W::Err> {
		self.inner_finalize()?;
		core::mem::forget(self);
		Ok(())
	}

	fn inner_finalize(&mut self) -> Result<(), W::Err>{
		// There can be at most two Fe32a left in the buffer after processing all bytes, write them.
		if self.buffer_bits >= 5 {
			self.writer.write_fe32(
				Fe32::try_from((self.buffer & 0b11111000) >> 3).expect("<32")
			)?;
			self.buffer <<= 5;
			self.buffer_bits -= 5;
		}

		if self.buffer_bits != 0 {
			self.writer.write_fe32(Fe32::try_from(self.buffer >> 3).expect("<32"))?;
		}

		Ok(())
	}
}

impl<'a, W: WriteBase32> Drop for BytesToBase32<'a, W> {
	fn drop(&mut self) {
		self.inner_finalize()
			.expect("Unhandled error when finalizing conversion on drop. User finalize to handle.")
	}
}

/// Calculates the base32 encoded size of a byte slice
fn bytes_size_to_base32_size(byte_size: usize) -> usize {
	let bits = byte_size * 8;
	if bits % 5 == 0 {
		// without padding bits
		bits / 5
	} else {
		// with padding bits
		bits / 5 + 1
	}
}

impl Display for Bolt11Invoice {
	fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
		self.signed_invoice.fmt(f)
	}
}

impl Display for SignedRawBolt11Invoice {
	fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
		let hrp = self.raw_invoice.hrp.to_string();
		let mut data  = self.raw_invoice.data.to_base32();
		data.extend_from_slice(&self.signature.to_base32());

		let bech32 = data.iter().copied().with_checksum::<Bech32>(&Hrp::parse(&hrp).expect("not a valid hrp string")).chars().collect::<String>();
		f.write_str(&bech32)?;

		Ok(())
	}
}

/// This is not exported to bindings users
impl Display for RawHrp {
	fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
		let amount = match self.raw_amount {
			Some(ref amt) => amt.to_string(),
			None => String::new(),
		};

		let si_prefix = match self.si_prefix {
			Some(ref si) => si.to_string(),
			None => String::new(),
		};

		write!(
			f,
			"ln{}{}{}",
			self.currency,
			amount,
			si_prefix
		)
	}
}

impl Display for Currency {
	fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
		let currency_code = match *self {
			Currency::Bitcoin => "bc",
			Currency::BitcoinTestnet => "tb",
			Currency::Regtest => "bcrt",
			Currency::Simnet => "sb",
			Currency::Signet => "tbs",
		};
		write!(f, "{}", currency_code)
	}
}

impl Display for SiPrefix {
	fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
		write!(f, "{}",
			match *self {
				SiPrefix::Milli => "m",
				SiPrefix::Micro => "u",
				SiPrefix::Nano => "n",
				SiPrefix::Pico => "p",
			}
		)
	}
}

fn encode_int_be_base32(int: u64) -> Vec<Fe32> {
	let base = 32u64;

	let mut out_vec = Vec::<Fe32>::new();

	let mut rem_int = int;
	while rem_int != 0 {
		out_vec.push(Fe32::try_from((rem_int % base) as u8).expect("always <32"));
		rem_int /= base;
	}

	out_vec.reverse();
	out_vec
}

fn encoded_int_be_base32_size(int: u64) -> usize {
	for pos in (0..13).rev() {
		if int & (0x1f << (5 * pos)) != 0 {
			return (pos + 1) as usize;
		}
	}
	0usize
}

fn encode_int_be_base256<T: Into<u64>>(int: T) -> Vec<u8> {
	let base = 256u64;

	let mut out_vec = Vec::<u8>::new();

	let mut rem_int: u64 = int.into();
	while rem_int != 0 {
		out_vec.push((rem_int % base) as u8);
		rem_int /= base;
	}

	out_vec.reverse();
	out_vec
}

/// Appends the default value of `T` to the front of the `in_vec` till it reaches the length
/// `target_length`. If `in_vec` already is too lang `None` is returned.
// TODO(bech32): Default value parameter is added because `bech32::Fe32` does not have `Default`.
// If it get's added, the `default_value` parameter can be dropped (https://github.com/rust-bitcoin/rust-bech32/pull/184)
fn try_stretch<T>(mut in_vec: Vec<T>, target_len: usize, default_value: T) -> Option<Vec<T>>
	where T: Copy
{
	if in_vec.len() > target_len {
		None
	} else if in_vec.len() == target_len {
		Some(in_vec)
	} else {
		let mut out_vec = Vec::<T>::with_capacity(target_len);
		out_vec.append(&mut vec![default_value; target_len - in_vec.len()]);
		out_vec.append(&mut in_vec);
		Some(out_vec)
	}
}

impl ToBase32 for RawDataPart {
	fn write_base32<W: WriteBase32>(&self, writer: &mut W) -> Result<(), <W as WriteBase32>::Err> {
		// encode timestamp
		self.timestamp.write_base32(writer)?;

		// encode tagged fields
		for tagged_field in self.tagged_fields.iter() {
			tagged_field.write_base32(writer)?;
		}

		Ok(())
	}
}

impl ToBase32 for PositiveTimestamp {
	fn write_base32<W: WriteBase32>(&self, writer: &mut W) -> Result<(), <W as WriteBase32>::Err> {
		// FIXME: use writer for int encoding
		writer.write(
			&try_stretch(encode_int_be_base32(self.as_unix_timestamp()), 7, Fe32::Q)
				.expect("Can't be longer due than 7 Fe32s due to timestamp bounds")
		)
	}
}

impl ToBase32 for RawTaggedField {
	fn write_base32<W: WriteBase32>(&self, writer: &mut W) -> Result<(), <W as WriteBase32>::Err> {
		match *self {
			RawTaggedField::UnknownSemantics(ref content) => {
				writer.write(&content.iter().map(|v| v.0).collect())
			},
			RawTaggedField::KnownSemantics(ref tagged_field) => {
				tagged_field.write_base32(writer)
			}
		}
	}
}

impl ToBase32 for Sha256 {
	fn write_base32<W: WriteBase32>(&self, writer: &mut W) -> Result<(), <W as WriteBase32>::Err> {
		(self.0[..].to_vec()).write_base32(writer)
	}
}
impl Base32Len for Sha256 {
	fn base32_len(&self) -> usize {
		(&self.0[..].to_vec()).base32_len()
	}
}

impl ToBase32 for Description {
	fn write_base32<W: WriteBase32>(&self, writer: &mut W) -> Result<(), <W as WriteBase32>::Err> {
		self.0.0.as_bytes().to_vec().write_base32(writer)
	}
}

impl Base32Len for Description {
	fn base32_len(&self) -> usize {
		self.0.0.as_bytes().to_vec().base32_len()
	}
}

impl ToBase32 for PayeePubKey {
	fn write_base32<W: WriteBase32>(&self, writer: &mut W) -> Result<(), <W as WriteBase32>::Err> {
		(&self.serialize()[..]).to_vec().write_base32(writer)
	}
}

impl Base32Len for PayeePubKey {
	fn base32_len(&self) -> usize {
		bytes_size_to_base32_size(secp256k1::constants::PUBLIC_KEY_SIZE)
	}
}

impl ToBase32 for ExpiryTime {
	fn write_base32<W: WriteBase32>(&self, writer: &mut W) -> Result<(), <W as WriteBase32>::Err> {
		writer.write(&encode_int_be_base32(self.as_seconds()))
	}
}

impl Base32Len for ExpiryTime {
	fn base32_len(&self) -> usize {
		encoded_int_be_base32_size(self.0.as_secs())
	}
}

impl ToBase32 for MinFinalCltvExpiryDelta {
	fn write_base32<W: WriteBase32>(&self, writer: &mut W) -> Result<(), <W as WriteBase32>::Err> {
		writer.write(&encode_int_be_base32(self.0))
	}
}

impl Base32Len for MinFinalCltvExpiryDelta {
	fn base32_len(&self) -> usize {
		encoded_int_be_base32_size(self.0)
	}
}

impl ToBase32 for Fallback {
	fn write_base32<W: WriteBase32>(&self, writer: &mut W) -> Result<(), <W as WriteBase32>::Err> {
		match *self {
			Fallback::SegWitProgram {version: v, program: ref p} => {
				writer.write_fe32(Fe32::try_from(v.to_num()).expect("witness version <= 16"))?;
				p.write_base32(writer)
			},
			Fallback::PubKeyHash(ref hash) => {
				writer.write_fe32(Fe32::try_from(17).expect("17 < 32"))?;
				(&hash[..]).to_vec().write_base32(writer)
			},
			Fallback::ScriptHash(ref hash) => {
				writer.write_fe32(Fe32::try_from(18).expect("18 < 32"))?;
				(&hash[..]).to_vec().write_base32(writer)
			}
		}
	}
}

impl Base32Len for Fallback {
	fn base32_len(&self) -> usize {
		match *self {
			Fallback::SegWitProgram {program: ref p, ..} => {
				bytes_size_to_base32_size(p.len()) + 1
			},
			Fallback::PubKeyHash(_) | Fallback::ScriptHash(_) => {
				33
			},
		}
	}
}

impl ToBase32 for PrivateRoute {
	fn write_base32<W: WriteBase32>(&self, writer: &mut W) -> Result<(), <W as WriteBase32>::Err> {
		let mut converter = BytesToBase32::new(writer);

		for hop in (self.0).0.iter() {
			converter.append(&hop.src_node_id.serialize()[..])?;
			let short_channel_id = try_stretch(
				encode_int_be_base256(hop.short_channel_id),
				8, u8::default()
			).expect("sizeof(u64) == 8");
			converter.append(&short_channel_id)?;

			let fee_base_msat = try_stretch(
				encode_int_be_base256(hop.fees.base_msat),
				4, u8::default()
			).expect("sizeof(u32) == 4");
			converter.append(&fee_base_msat)?;

			let fee_proportional_millionths = try_stretch(
				encode_int_be_base256(hop.fees.proportional_millionths),
				4, u8::default()
			).expect("sizeof(u32) == 4");
			converter.append(&fee_proportional_millionths)?;

			let cltv_expiry_delta = try_stretch(
				encode_int_be_base256(hop.cltv_expiry_delta),
				2, u8::default()
			).expect("sizeof(u16) == 2");
			converter.append(&cltv_expiry_delta)?;
		}

		converter.finalize()?;
		Ok(())
	}
}

impl Base32Len for PrivateRoute {
	fn base32_len(&self) -> usize {
		bytes_size_to_base32_size((self.0).0.len() * 51)
	}
}

impl ToBase32 for TaggedField {
	fn write_base32<W: WriteBase32>(&self, writer: &mut W) -> Result<(), <W as WriteBase32>::Err> {
		/// Writes a tagged field: tag, length and data. `tag` should be in `0..32` otherwise the
		/// function will panic.
		fn write_tagged_field<W, P>(writer: &mut W, tag: u8, payload: &P) -> Result<(), W::Err>
			where W: WriteBase32,
				  P: ToBase32 + Base32Len,
		{
			let len = payload.base32_len();
			assert!(len < 1024, "Every tagged field data can be at most 1023 bytes long.");

			writer.write_fe32(Fe32::try_from(tag).expect("invalid tag, not in 0..32"))?;
			writer.write(&try_stretch(
				encode_int_be_base32(len as u64),
				2, Fe32::Q
			).expect("Can't be longer than 2, see assert above."))?;
			payload.write_base32(writer)
		}

		match *self {
			TaggedField::PaymentHash(ref hash) => {
				write_tagged_field(writer, constants::TAG_PAYMENT_HASH, hash)
			},
			TaggedField::Description(ref description) => {
				write_tagged_field(writer, constants::TAG_DESCRIPTION, description)
			},
			TaggedField::PayeePubKey(ref pub_key) => {
				write_tagged_field(writer, constants::TAG_PAYEE_PUB_KEY, pub_key)
			},
			TaggedField::DescriptionHash(ref hash) => {
				write_tagged_field(writer, constants::TAG_DESCRIPTION_HASH, hash)
			},
			TaggedField::ExpiryTime(ref duration) => {
				write_tagged_field(writer, constants::TAG_EXPIRY_TIME, duration)
			},
			TaggedField::MinFinalCltvExpiryDelta(ref expiry) => {
				write_tagged_field(writer, constants::TAG_MIN_FINAL_CLTV_EXPIRY_DELTA, expiry)
			},
			TaggedField::Fallback(ref fallback_address) => {
				write_tagged_field(writer, constants::TAG_FALLBACK, fallback_address)
			},
			TaggedField::PrivateRoute(ref route_hops) => {
				write_tagged_field(writer, constants::TAG_PRIVATE_ROUTE, route_hops)
			},
			TaggedField::PaymentSecret(ref payment_secret) => {
				  write_tagged_field(writer, constants::TAG_PAYMENT_SECRET, payment_secret)
			},
			TaggedField::PaymentMetadata(ref payment_metadata) => {
				  write_tagged_field(writer, constants::TAG_PAYMENT_METADATA, payment_metadata)
			},
			TaggedField::Features(ref features) => {
				write_tagged_field(writer, constants::TAG_FEATURES, features)
			},
		}
	}
}

impl ToBase32 for Bolt11InvoiceSignature {
	fn write_base32<W: WriteBase32>(&self, writer: &mut W) -> Result<(), <W as WriteBase32>::Err> {
		let mut converter = BytesToBase32::new(writer);
		let (recovery_id, signature) = self.0.serialize_compact();
		converter.append(&signature[..])?;
		converter.append_u8(recovery_id.to_i32() as u8)?;
		converter.finalize()
	}
}

#[cfg(test)]
mod test {
	#[test]
	fn test_currency_code() {
		use crate::Currency;

		assert_eq!("bc", Currency::Bitcoin.to_string());
		assert_eq!("tb", Currency::BitcoinTestnet.to_string());
		assert_eq!("bcrt", Currency::Regtest.to_string());
		assert_eq!("sb", Currency::Simnet.to_string());
		assert_eq!("tbs", Currency::Signet.to_string());
	}

	#[test]
	fn test_raw_hrp() {
		use crate::{Currency, RawHrp, SiPrefix};

		let hrp = RawHrp {
			currency: Currency::Bitcoin,
			raw_amount: Some(100),
			si_prefix: Some(SiPrefix::Micro),
		};

		assert_eq!(hrp.to_string(), "lnbc100u");
	}

	#[test]
	fn test_encode_int_be_base32() {
		use crate::ser::encode_int_be_base32;
		use bech32::Fe32;

		let input: u64 = 33764;
		let expected_out = &[1, 0, 31, 4].iter().copied().map(|v| Fe32::try_from(v).expect("should be <= 31")).collect::<Vec<Fe32>>();

		assert_eq!(expected_out.iter().copied().map(|v| v.to_char()).collect::<String>(), encode_int_be_base32(input).iter().copied().map(|v| v.to_char()).collect::<String>());
	}

	#[test]
	fn test_encode_int_be_base256() {
		use crate::ser::encode_int_be_base256;

		let input: u64 = 16842530;
		let expected_out = vec![1, 0, 255, 34];

		assert_eq!(expected_out, encode_int_be_base256(input));
	}
}
