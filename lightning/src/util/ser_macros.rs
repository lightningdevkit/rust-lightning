// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

macro_rules! encode_tlv {
	($stream: expr, {$(($type: expr, $field: expr)),*}, {$(($optional_type: expr, $optional_field: expr)),*}) => { {
		#[allow(unused_imports)]
		use util::ser::BigSize;
		// Fields must be serialized in order, so we have to potentially switch between optional
		// fields and normal fields while serializing. Thus, we end up having to loop over the type
		// counts.
		// Sadly, while LLVM does appear smart enough to make `max_field` a constant, it appears to
		// refuse to unroll the loop. If we have enough entries that this is slow we can revisit
		// this design in the future.
		#[allow(unused_mut)]
		let mut max_field: u64 = 0;
		$(
			if $type >= max_field { max_field = $type + 1; }
		)*
		$(
			if $optional_type >= max_field { max_field = $optional_type + 1; }
		)*
		#[allow(unused_variables)]
		for i in 0..max_field {
			$(
				if i == $type {
					BigSize($type).write($stream)?;
					BigSize($field.serialized_length() as u64).write($stream)?;
					$field.write($stream)?;
				}
			)*
			$(
				if i == $optional_type {
					if let Some(ref field) = $optional_field {
						BigSize($optional_type).write($stream)?;
						BigSize(field.serialized_length() as u64).write($stream)?;
						field.write($stream)?;
					}
				}
			)*
		}
	} }
}

macro_rules! encode_varint_length_prefixed_tlv {
	($stream: expr, {$(($type: expr, $field: expr)),*}, {$(($optional_type: expr, $optional_field: expr)),*}) => { {
		use util::ser::{BigSize, LengthCalculatingWriter};
		#[allow(unused_mut)]
		let mut len = LengthCalculatingWriter(0);
		{
			$(
				BigSize($type).write(&mut len)?;
				let field_len = $field.serialized_length();
				BigSize(field_len as u64).write(&mut len)?;
				len.0 += field_len;
			)*
			$(
				if let Some(ref field) = $optional_field {
					BigSize($optional_type).write(&mut len)?;
					let field_len = field.serialized_length();
					BigSize(field_len as u64).write(&mut len)?;
					len.0 += field_len;
				}
			)*
		}

		BigSize(len.0 as u64).write($stream)?;
		encode_tlv!($stream, { $(($type, $field)),* }, { $(($optional_type, $optional_field)),* });
	} }
}

macro_rules! decode_tlv {
	($stream: expr, {$(($reqtype: expr, $reqfield: ident)),*}, {$(($type: expr, $field: ident)),*}) => { {
		use ln::msgs::DecodeError;
		let mut last_seen_type: Option<u64> = None;
		'tlv_read: loop {
			use util::ser;

			// First decode the type of this TLV:
			let typ: ser::BigSize = {
				// We track whether any bytes were read during the consensus_decode call to
				// determine whether we should break or return ShortRead if we get an
				// UnexpectedEof. This should in every case be largely cosmetic, but its nice to
				// pass the TLV test vectors exactly, which requre this distinction.
				let mut tracking_reader = ser::ReadTrackingReader::new($stream);
				match ser::Readable::read(&mut tracking_reader) {
					Err(DecodeError::ShortRead) => {
						if !tracking_reader.have_read {
							break 'tlv_read
						} else {
							Err(DecodeError::ShortRead)?
						}
					},
					Err(e) => Err(e)?,
					Ok(t) => t,
				}
			};

			// Types must be unique and monotonically increasing:
			match last_seen_type {
				Some(t) if typ.0 <= t => {
					Err(DecodeError::InvalidValue)?
				},
				_ => {},
			}
			// As we read types, make sure we hit every required type:
			$({
				#[allow(unused_comparisons)] // Note that $reqtype may be 0 making the second comparison always true
				let invalid_order = (last_seen_type.is_none() || last_seen_type.unwrap() < $reqtype) && typ.0 > $reqtype;
				if invalid_order {
					Err(DecodeError::InvalidValue)?
				}
			})*
			last_seen_type = Some(typ.0);

			// Finally, read the length and value itself:
			let length: ser::BigSize = Readable::read($stream)?;
			let mut s = ser::FixedLengthReader::new($stream, length.0);
			match typ.0 {
				$($reqtype => {
					$reqfield = ser::Readable::read(&mut s)?;
					if s.bytes_remain() {
						s.eat_remaining()?; // Return ShortRead if there's actually not enough bytes
						Err(DecodeError::InvalidValue)?
					}
				},)*
				$($type => {
					$field = Some(ser::Readable::read(&mut s)?);
					if s.bytes_remain() {
						s.eat_remaining()?; // Return ShortRead if there's actually not enough bytes
						Err(DecodeError::InvalidValue)?
					}
				},)*
				x if x % 2 == 0 => {
					Err(DecodeError::UnknownRequiredFeature)?
				},
				_ => {},
			}
			s.eat_remaining()?;
		}
		// Make sure we got to each required type after we've read every TLV:
		$({
			#[allow(unused_comparisons)] // Note that $reqtype may be 0 making the second comparison always true
			let missing_req_type = last_seen_type.is_none() || last_seen_type.unwrap() < $reqtype;
			if missing_req_type {
				Err(DecodeError::InvalidValue)?
			}
		})*
	} }
}

macro_rules! impl_writeable {
	($st:ident, $len: expr, {$($field:ident),*}) => {
		impl ::util::ser::Writeable for $st {
			fn write<W: ::util::ser::Writer>(&self, w: &mut W) -> Result<(), ::std::io::Error> {
				if $len != 0 {
					w.size_hint($len);
				}
				#[cfg(any(test, feature = "fuzztarget"))]
				{
					// In tests, assert that the hard-coded length matches the actual one
					if $len != 0 {
						use util::ser::LengthCalculatingWriter;
						let mut len_calc = LengthCalculatingWriter(0);
						$( self.$field.write(&mut len_calc)?; )*
						assert_eq!(len_calc.0, $len);
					}
				}
				$( self.$field.write(w)?; )*
				Ok(())
			}
		}

		impl ::util::ser::Readable for $st {
			fn read<R: ::std::io::Read>(r: &mut R) -> Result<Self, ::ln::msgs::DecodeError> {
				Ok(Self {
					$($field: ::util::ser::Readable::read(r)?),*
				})
			}
		}
	}
}
macro_rules! impl_writeable_len_match {
	($struct: ident, $cmp: tt, {$({$match: pat, $length: expr}),*}, {$($field:ident),*}) => {
		impl Writeable for $struct {
			fn write<W: Writer>(&self, w: &mut W) -> Result<(), ::std::io::Error> {
				let len = match *self {
					$($match => $length,)*
				};
				w.size_hint(len);
				#[cfg(any(test, feature = "fuzztarget"))]
				{
					// In tests, assert that the hard-coded length matches the actual one
					use util::ser::LengthCalculatingWriter;
					let mut len_calc = LengthCalculatingWriter(0);
					$( self.$field.write(&mut len_calc)?; )*
					assert!(len_calc.0 $cmp len);
				}
				$( self.$field.write(w)?; )*
				Ok(())
			}
		}

		impl ::util::ser::Readable for $struct {
			fn read<R: ::std::io::Read>(r: &mut R) -> Result<Self, DecodeError> {
				Ok(Self {
					$($field: Readable::read(r)?),*
				})
			}
		}
	};
	($struct: ident, {$({$match: pat, $length: expr}),*}, {$($field:ident),*}) => {
		impl_writeable_len_match!($struct, ==, { $({ $match, $length }),* }, { $($field),* });
	}
}

/// Write out two bytes to indicate the version of an object.
/// $this_version represents a unique version of a type. Incremented whenever the type's
///               serialization format has changed or has a new interpretation. Used by a type's
///               reader to determine how to interpret fields or if it can understand a serialized
///               object.
/// $min_version_that_can_read_this is the minimum reader version which can understand this
///                                 serialized object. Previous versions will simply err with a
///                                 DecodeError::UnknownVersion.
///
/// Updates to either $this_version or $min_version_that_can_read_this should be included in
/// release notes.
///
/// Both version fields can be specific to this type of object.
macro_rules! write_ver_prefix {
	($stream: expr, $this_version: expr, $min_version_that_can_read_this: expr) => {
		$stream.write_all(&[$this_version; 1])?;
		$stream.write_all(&[$min_version_that_can_read_this; 1])?;
	}
}

/// Writes out a suffix to an object which contains potentially backwards-compatible, optional
/// fields which old nodes can happily ignore.
///
/// It is written out in TLV format and, as with all TLV fields, unknown even fields cause a
/// DecodeError::UnknownRequiredFeature error, with unknown odd fields ignored.
///
/// This is the preferred method of adding new fields that old nodes can ignore and still function
/// correctly.
macro_rules! write_tlv_fields {
	($stream: expr, {$(($type: expr, $field: expr)),* $(,)*}, {$(($optional_type: expr, $optional_field: expr)),* $(,)*}) => {
		encode_varint_length_prefixed_tlv!($stream, {$(($type, $field)),*} , {$(($optional_type, $optional_field)),*});
	}
}

/// Reads a prefix added by write_ver_prefix!(), above. Takes the current version of the
/// serialization logic for this object. This is compared against the
/// $min_version_that_can_read_this added by write_ver_prefix!().
macro_rules! read_ver_prefix {
	($stream: expr, $this_version: expr) => { {
		let ver: u8 = Readable::read($stream)?;
		let min_ver: u8 = Readable::read($stream)?;
		if min_ver > $this_version {
			return Err(DecodeError::UnknownVersion);
		}
		ver
	} }
}

/// Reads a suffix added by write_tlv_fields.
macro_rules! read_tlv_fields {
	($stream: expr, {$(($reqtype: expr, $reqfield: ident)),* $(,)*}, {$(($type: expr, $field: ident)),* $(,)*}) => { {
		let tlv_len = ::util::ser::BigSize::read($stream)?;
		let mut rd = ::util::ser::FixedLengthReader::new($stream, tlv_len.0);
		decode_tlv!(&mut rd, {$(($reqtype, $reqfield)),*}, {$(($type, $field)),*});
		rd.eat_remaining().map_err(|_| DecodeError::ShortRead)?;
	} }
}

// If we naively create a struct in impl_writeable_tlv_based below, we may end up returning
// `Self { ,,vecfield: vecfield }` which is obviously incorrect. Instead, we have to match here to
// detect at least one empty field set and skip the potentially-extra comma.
macro_rules! _init_tlv_based_struct {
	({}, {$($field: ident),*}, {$($vecfield: ident),*}) => {
		Ok(Self {
			$($field),*,
			$($vecfield: $vecfield.unwrap().0),*
		})
	};
	({$($reqfield: ident),*}, {}, {$($vecfield: ident),*}) => {
		Ok(Self {
			$($reqfield: $reqfield.0.unwrap()),*,
			$($vecfield: $vecfield.unwrap().0),*
		})
	};
	({$($reqfield: ident),*}, {$($field: ident),*}, {}) => {
		Ok(Self {
			$($reqfield: $reqfield.0.unwrap()),*,
			$($field),*
		})
	};
	({$($reqfield: ident),*}, {$($field: ident),*}, {$($vecfield: ident),*}) => {
		Ok(Self {
			$($reqfield: $reqfield.0.unwrap()),*,
			$($field),*,
			$($vecfield: $vecfield.unwrap().0),*
		})
	}
}

// If we don't have any optional types below, but do have some vec types, we end up calling
// `write_tlv_field!($stream, {..}, {, (vec_ty, vec_val)})`, which is obviously broken.
// Instead, for write and read we match the missing values and skip the extra comma.
macro_rules! _write_tlv_fields {
	($stream: expr, {$(($type: expr, $field: expr)),* $(,)*}, {}, {$(($optional_type: expr, $optional_field: expr)),* $(,)*}) => {
		write_tlv_fields!($stream, {$(($type, $field)),*} , {$(($optional_type, $optional_field)),*});
	};
	($stream: expr, {$(($type: expr, $field: expr)),* $(,)*}, {$(($optional_type: expr, $optional_field: expr)),* $(,)*}, {$(($optional_type_2: expr, $optional_field_2: expr)),* $(,)*}) => {
		write_tlv_fields!($stream, {$(($type, $field)),*} , {$(($optional_type, $optional_field)),*, $(($optional_type_2, $optional_field_2)),*});
	}
}
macro_rules! _read_tlv_fields {
	($stream: expr, {$(($reqtype: expr, $reqfield: ident)),* $(,)*}, {}, {$(($type: expr, $field: ident)),* $(,)*}) => {
		read_tlv_fields!($stream, {$(($reqtype, $reqfield)),*}, {$(($type, $field)),*});
	};
	($stream: expr, {$(($reqtype: expr, $reqfield: ident)),* $(,)*}, {$(($type: expr, $field: ident)),* $(,)*}, {$(($type_2: expr, $field_2: ident)),* $(,)*}) => {
		read_tlv_fields!($stream, {$(($reqtype, $reqfield)),*}, {$(($type, $field)),*, $(($type_2, $field_2)),*});
	}
}

/// Implements Readable/Writeable for a struct storing it as a set of TLVs
/// First block includes all the required fields including a dummy value which is used during
/// deserialization but which will never be exposed to other code.
/// The second block includes optional fields.
/// The third block includes any Vecs which need to have their individual elements serialized.
macro_rules! impl_writeable_tlv_based {
	($st: ident, {$(($reqtype: expr, $reqfield: ident)),* $(,)*}, {$(($type: expr, $field: ident)),* $(,)*}, {$(($vectype: expr, $vecfield: ident)),* $(,)*}) => {
		impl ::util::ser::Writeable for $st {
			fn write<W: ::util::ser::Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
				_write_tlv_fields!(writer, {
					$(($reqtype, self.$reqfield)),*
				}, {
					$(($type, self.$field)),*
				}, {
					$(($vectype, Some(::util::ser::VecWriteWrapper(&self.$vecfield)))),*
				});
				Ok(())
			}
		}

		impl ::util::ser::Readable for $st {
			fn read<R: ::std::io::Read>(reader: &mut R) -> Result<Self, ::ln::msgs::DecodeError> {
				$(
					let mut $reqfield = ::util::ser::OptionDeserWrapper(None);
				)*
				$(
					let mut $field = None;
				)*
				$(
					let mut $vecfield = Some(::util::ser::VecReadWrapper(Vec::new()));
				)*
				_read_tlv_fields!(reader, {
					$(($reqtype, $reqfield)),*
				}, {
					$(($type, $field)),*
				}, {
					$(($vectype, $vecfield)),*
				});
				_init_tlv_based_struct!({$($reqfield),*}, {$($field),*}, {$($vecfield),*})
			}
		}
	}
}

#[cfg(test)]
mod tests {
	use prelude::*;
	use std::io::{Cursor, Read};
	use ln::msgs::DecodeError;
	use util::ser::{Readable, Writeable, HighZeroBytesDroppedVarInt, VecWriter};
	use bitcoin::secp256k1::PublicKey;

	// The BOLT TLV test cases don't include any tests which use our "required-value" logic since
	// the encoding layer in the BOLTs has no such concept, though it makes our macros easier to
	// work with so they're baked into the decoder. Thus, we have a few additional tests below
	fn tlv_reader(s: &[u8]) -> Result<(u64, u32, Option<u32>), DecodeError> {
		let mut s = Cursor::new(s);
		let mut a: u64 = 0;
		let mut b: u32 = 0;
		let mut c: Option<u32> = None;
		decode_tlv!(&mut s, {(2, a), (3, b)}, {(4, c)});
		Ok((a, b, c))
	}

	#[test]
	fn tlv_v_short_read() {
		// We only expect a u32 for type 3 (which we are given), but the L says its 8 bytes.
		if let Err(DecodeError::ShortRead) = tlv_reader(&::hex::decode(
				concat!("0100", "0208deadbeef1badbeef", "0308deadbeef")
				).unwrap()[..]) {
		} else { panic!(); }
	}

	#[test]
	fn tlv_types_out_of_order() {
		if let Err(DecodeError::InvalidValue) = tlv_reader(&::hex::decode(
				concat!("0100", "0304deadbeef", "0208deadbeef1badbeef")
				).unwrap()[..]) {
		} else { panic!(); }
		// ...even if its some field we don't understand
		if let Err(DecodeError::InvalidValue) = tlv_reader(&::hex::decode(
				concat!("0208deadbeef1badbeef", "0100", "0304deadbeef")
				).unwrap()[..]) {
		} else { panic!(); }
	}

	#[test]
	fn tlv_req_type_missing_or_extra() {
		// It's also bad if they included even fields we don't understand
		if let Err(DecodeError::UnknownRequiredFeature) = tlv_reader(&::hex::decode(
				concat!("0100", "0208deadbeef1badbeef", "0304deadbeef", "0600")
				).unwrap()[..]) {
		} else { panic!(); }
		// ... or if they're missing fields we need
		if let Err(DecodeError::InvalidValue) = tlv_reader(&::hex::decode(
				concat!("0100", "0208deadbeef1badbeef")
				).unwrap()[..]) {
		} else { panic!(); }
		// ... even if that field is even
		if let Err(DecodeError::InvalidValue) = tlv_reader(&::hex::decode(
				concat!("0304deadbeef", "0500")
				).unwrap()[..]) {
		} else { panic!(); }
	}

	#[test]
	fn tlv_simple_good_cases() {
		assert_eq!(tlv_reader(&::hex::decode(
				concat!("0208deadbeef1badbeef", "03041bad1dea")
				).unwrap()[..]).unwrap(),
			(0xdeadbeef1badbeef, 0x1bad1dea, None));
		assert_eq!(tlv_reader(&::hex::decode(
				concat!("0208deadbeef1badbeef", "03041bad1dea", "040401020304")
				).unwrap()[..]).unwrap(),
			(0xdeadbeef1badbeef, 0x1bad1dea, Some(0x01020304)));
	}

	impl Readable for (PublicKey, u64, u64) {
		#[inline]
		fn read<R: Read>(reader: &mut R) -> Result<(PublicKey, u64, u64), DecodeError> {
			Ok((Readable::read(reader)?, Readable::read(reader)?, Readable::read(reader)?))
		}
	}

	// BOLT TLV test cases
	fn tlv_reader_n1(s: &[u8]) -> Result<(Option<HighZeroBytesDroppedVarInt<u64>>, Option<u64>, Option<(PublicKey, u64, u64)>, Option<u16>), DecodeError> {
		let mut s = Cursor::new(s);
		let mut tlv1: Option<HighZeroBytesDroppedVarInt<u64>> = None;
		let mut tlv2: Option<u64> = None;
		let mut tlv3: Option<(PublicKey, u64, u64)> = None;
		let mut tlv4: Option<u16> = None;
		decode_tlv!(&mut s, {}, {(1, tlv1), (2, tlv2), (3, tlv3), (254, tlv4)});
		Ok((tlv1, tlv2, tlv3, tlv4))
	}

	#[test]
	fn bolt_tlv_bogus_stream() {
		macro_rules! do_test {
			($stream: expr, $reason: ident) => {
				if let Err(DecodeError::$reason) = tlv_reader_n1(&::hex::decode($stream).unwrap()[..]) {
				} else { panic!(); }
			}
		}

		// TLVs from the BOLT test cases which should not decode as either n1 or n2
		do_test!(concat!("fd01"), ShortRead);
		do_test!(concat!("fd0001", "00"), InvalidValue);
		do_test!(concat!("fd0101"), ShortRead);
		do_test!(concat!("0f", "fd"), ShortRead);
		do_test!(concat!("0f", "fd26"), ShortRead);
		do_test!(concat!("0f", "fd2602"), ShortRead);
		do_test!(concat!("0f", "fd0001", "00"), InvalidValue);
		do_test!(concat!("0f", "fd0201", "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"), ShortRead);

		do_test!(concat!("12", "00"), UnknownRequiredFeature);
		do_test!(concat!("fd0102", "00"), UnknownRequiredFeature);
		do_test!(concat!("fe01000002", "00"), UnknownRequiredFeature);
		do_test!(concat!("ff0100000000000002", "00"), UnknownRequiredFeature);
	}

	#[test]
	fn bolt_tlv_bogus_n1_stream() {
		macro_rules! do_test {
			($stream: expr, $reason: ident) => {
				if let Err(DecodeError::$reason) = tlv_reader_n1(&::hex::decode($stream).unwrap()[..]) {
				} else { panic!(); }
			}
		}

		// TLVs from the BOLT test cases which should not decode as n1
		do_test!(concat!("01", "09", "ffffffffffffffffff"), InvalidValue);
		do_test!(concat!("01", "01", "00"), InvalidValue);
		do_test!(concat!("01", "02", "0001"), InvalidValue);
		do_test!(concat!("01", "03", "000100"), InvalidValue);
		do_test!(concat!("01", "04", "00010000"), InvalidValue);
		do_test!(concat!("01", "05", "0001000000"), InvalidValue);
		do_test!(concat!("01", "06", "000100000000"), InvalidValue);
		do_test!(concat!("01", "07", "00010000000000"), InvalidValue);
		do_test!(concat!("01", "08", "0001000000000000"), InvalidValue);
		do_test!(concat!("02", "07", "01010101010101"), ShortRead);
		do_test!(concat!("02", "09", "010101010101010101"), InvalidValue);
		do_test!(concat!("03", "21", "023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb"), ShortRead);
		do_test!(concat!("03", "29", "023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb0000000000000001"), ShortRead);
		do_test!(concat!("03", "30", "023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb000000000000000100000000000001"), ShortRead);
		do_test!(concat!("03", "31", "043da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb00000000000000010000000000000002"), InvalidValue);
		do_test!(concat!("03", "32", "023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb0000000000000001000000000000000001"), InvalidValue);
		do_test!(concat!("fd00fe", "00"), ShortRead);
		do_test!(concat!("fd00fe", "01", "01"), ShortRead);
		do_test!(concat!("fd00fe", "03", "010101"), InvalidValue);
		do_test!(concat!("00", "00"), UnknownRequiredFeature);

		do_test!(concat!("02", "08", "0000000000000226", "01", "01", "2a"), InvalidValue);
		do_test!(concat!("02", "08", "0000000000000231", "02", "08", "0000000000000451"), InvalidValue);
		do_test!(concat!("1f", "00", "0f", "01", "2a"), InvalidValue);
		do_test!(concat!("1f", "00", "1f", "01", "2a"), InvalidValue);

		// The last BOLT test modified to not require creating a new decoder for one trivial test.
		do_test!(concat!("ffffffffffffffffff", "00", "01", "00"), InvalidValue);
	}

	#[test]
	fn bolt_tlv_valid_n1_stream() {
		macro_rules! do_test {
			($stream: expr, $tlv1: expr, $tlv2: expr, $tlv3: expr, $tlv4: expr) => {
				if let Ok((tlv1, tlv2, tlv3, tlv4)) = tlv_reader_n1(&::hex::decode($stream).unwrap()[..]) {
					assert_eq!(tlv1.map(|v| v.0), $tlv1);
					assert_eq!(tlv2, $tlv2);
					assert_eq!(tlv3, $tlv3);
					assert_eq!(tlv4, $tlv4);
				} else { panic!(); }
			}
		}

		do_test!(concat!(""), None, None, None, None);
		do_test!(concat!("21", "00"), None, None, None, None);
		do_test!(concat!("fd0201", "00"), None, None, None, None);
		do_test!(concat!("fd00fd", "00"), None, None, None, None);
		do_test!(concat!("fd00ff", "00"), None, None, None, None);
		do_test!(concat!("fe02000001", "00"), None, None, None, None);
		do_test!(concat!("ff0200000000000001", "00"), None, None, None, None);

		do_test!(concat!("01", "00"), Some(0), None, None, None);
		do_test!(concat!("01", "01", "01"), Some(1), None, None, None);
		do_test!(concat!("01", "02", "0100"), Some(256), None, None, None);
		do_test!(concat!("01", "03", "010000"), Some(65536), None, None, None);
		do_test!(concat!("01", "04", "01000000"), Some(16777216), None, None, None);
		do_test!(concat!("01", "05", "0100000000"), Some(4294967296), None, None, None);
		do_test!(concat!("01", "06", "010000000000"), Some(1099511627776), None, None, None);
		do_test!(concat!("01", "07", "01000000000000"), Some(281474976710656), None, None, None);
		do_test!(concat!("01", "08", "0100000000000000"), Some(72057594037927936), None, None, None);
		do_test!(concat!("02", "08", "0000000000000226"), None, Some((0 << 30) | (0 << 5) | (550 << 0)), None, None);
		do_test!(concat!("03", "31", "023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb00000000000000010000000000000002"),
			None, None, Some((
				PublicKey::from_slice(&::hex::decode("023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb").unwrap()[..]).unwrap(), 1, 2)),
			None);
		do_test!(concat!("fd00fe", "02", "0226"), None, None, None, Some(550));
	}

	fn do_simple_test_tlv_write() -> Result<(), ::std::io::Error> {
		let mut stream = VecWriter(Vec::new());

		stream.0.clear();
		encode_varint_length_prefixed_tlv!(&mut stream, { (1, 1u8) }, { (42, None::<u64>) });
		assert_eq!(stream.0, ::hex::decode("03010101").unwrap());

		stream.0.clear();
		encode_varint_length_prefixed_tlv!(&mut stream, { }, { (1, Some(1u8)) });
		assert_eq!(stream.0, ::hex::decode("03010101").unwrap());

		stream.0.clear();
		encode_varint_length_prefixed_tlv!(&mut stream, { (4, 0xabcdu16) }, { (42, None::<u64>) });
		assert_eq!(stream.0, ::hex::decode("040402abcd").unwrap());

		stream.0.clear();
		encode_varint_length_prefixed_tlv!(&mut stream, { (0xff, 0xabcdu16) }, { (42, None::<u64>) });
		assert_eq!(stream.0, ::hex::decode("06fd00ff02abcd").unwrap());

		stream.0.clear();
		encode_varint_length_prefixed_tlv!(&mut stream, { (0, 1u64), (0xff, HighZeroBytesDroppedVarInt(0u64)) }, { (42, None::<u64>) });
		assert_eq!(stream.0, ::hex::decode("0e00080000000000000001fd00ff00").unwrap());

		stream.0.clear();
		encode_varint_length_prefixed_tlv!(&mut stream, { (0xff, HighZeroBytesDroppedVarInt(0u64)) }, { (0, Some(1u64)) });
		assert_eq!(stream.0, ::hex::decode("0e00080000000000000001fd00ff00").unwrap());

		Ok(())
	}

	#[test]
	fn simple_test_tlv_write() {
		do_simple_test_tlv_write().unwrap();
	}
}
