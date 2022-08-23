// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

macro_rules! encode_tlv {
	($stream: expr, $type: expr, $field: expr, (default_value, $default: expr)) => {
		encode_tlv!($stream, $type, $field, required)
	};
	($stream: expr, $type: expr, $field: expr, required) => {
		BigSize($type).write($stream)?;
		BigSize($field.serialized_length() as u64).write($stream)?;
		$field.write($stream)?;
	};
	($stream: expr, $type: expr, $field: expr, vec_type) => {
		encode_tlv!($stream, $type, $crate::util::ser::WithoutLength(&$field), required);
	};
	($stream: expr, $optional_type: expr, $optional_field: expr, option) => {
		if let Some(ref field) = $optional_field {
			BigSize($optional_type).write($stream)?;
			BigSize(field.serialized_length() as u64).write($stream)?;
			field.write($stream)?;
		}
	};
	($stream: expr, $type: expr, $field: expr, (option, encoding: ($fieldty: ty, $encoding: ident))) => {
		encode_tlv!($stream, $type, $field.map(|f| $encoding(f)), option);
	};
	($stream: expr, $type: expr, $field: expr, (option, encoding: $fieldty: ty)) => {
		encode_tlv!($stream, $type, $field, option);
	};
}

macro_rules! encode_tlv_stream {
	($stream: expr, {$(($type: expr, $field: expr, $fieldty: tt)),* $(,)*}) => { {
		#[allow(unused_imports)]
		use $crate::{
			ln::msgs::DecodeError,
			util::ser,
			util::ser::BigSize,
		};

		$(
			encode_tlv!($stream, $type, $field, $fieldty);
		)*

		#[allow(unused_mut, unused_variables, unused_assignments)]
		#[cfg(debug_assertions)]
		{
			let mut last_seen: Option<u64> = None;
			$(
				if let Some(t) = last_seen {
					debug_assert!(t <= $type);
				}
				last_seen = Some($type);
			)*
		}
	} }
}

macro_rules! get_varint_length_prefixed_tlv_length {
	($len: expr, $type: expr, $field: expr, (default_value, $default: expr)) => {
		get_varint_length_prefixed_tlv_length!($len, $type, $field, required)
	};
	($len: expr, $type: expr, $field: expr, required) => {
		BigSize($type).write(&mut $len).expect("No in-memory data may fail to serialize");
		let field_len = $field.serialized_length();
		BigSize(field_len as u64).write(&mut $len).expect("No in-memory data may fail to serialize");
		$len.0 += field_len;
	};
	($len: expr, $type: expr, $field: expr, vec_type) => {
		get_varint_length_prefixed_tlv_length!($len, $type, $crate::util::ser::WithoutLength(&$field), required);
	};
	($len: expr, $optional_type: expr, $optional_field: expr, option) => {
		if let Some(ref field) = $optional_field {
			BigSize($optional_type).write(&mut $len).expect("No in-memory data may fail to serialize");
			let field_len = field.serialized_length();
			BigSize(field_len as u64).write(&mut $len).expect("No in-memory data may fail to serialize");
			$len.0 += field_len;
		}
	};
}

macro_rules! encode_varint_length_prefixed_tlv {
	($stream: expr, {$(($type: expr, $field: expr, $fieldty: tt)),*}) => { {
		use $crate::util::ser::BigSize;
		let len = {
			#[allow(unused_mut)]
			let mut len = $crate::util::ser::LengthCalculatingWriter(0);
			$(
				get_varint_length_prefixed_tlv_length!(len, $type, $field, $fieldty);
			)*
			len.0
		};
		BigSize(len as u64).write($stream)?;
		encode_tlv_stream!($stream, { $(($type, $field, $fieldty)),* });
	} }
}

macro_rules! check_tlv_order {
	($last_seen_type: expr, $typ: expr, $type: expr, $field: ident, (default_value, $default: expr)) => {{
		#[allow(unused_comparisons)] // Note that $type may be 0 making the second comparison always true
		let invalid_order = ($last_seen_type.is_none() || $last_seen_type.unwrap() < $type) && $typ.0 > $type;
		if invalid_order {
			$field = $default.into();
		}
	}};
	($last_seen_type: expr, $typ: expr, $type: expr, $field: ident, required) => {{
		#[allow(unused_comparisons)] // Note that $type may be 0 making the second comparison always true
		let invalid_order = ($last_seen_type.is_none() || $last_seen_type.unwrap() < $type) && $typ.0 > $type;
		if invalid_order {
			return Err(DecodeError::InvalidValue);
		}
	}};
	($last_seen_type: expr, $typ: expr, $type: expr, $field: ident, option) => {{
		// no-op
	}};
	($last_seen_type: expr, $typ: expr, $type: expr, $field: ident, vec_type) => {{
		// no-op
	}};
	($last_seen_type: expr, $typ: expr, $type: expr, $field: ident, ignorable) => {{
		// no-op
	}};
	($last_seen_type: expr, $typ: expr, $type: expr, $field: ident, (option: $trait: ident $(, $read_arg: expr)?)) => {{
		// no-op
	}};
	($last_seen_type: expr, $typ: expr, $type: expr, $field: ident, (option, encoding: $encoding: tt)) => {{
		// no-op
	}};
}

macro_rules! check_missing_tlv {
	($last_seen_type: expr, $type: expr, $field: ident, (default_value, $default: expr)) => {{
		#[allow(unused_comparisons)] // Note that $type may be 0 making the second comparison always true
		let missing_req_type = $last_seen_type.is_none() || $last_seen_type.unwrap() < $type;
		if missing_req_type {
			$field = $default.into();
		}
	}};
	($last_seen_type: expr, $type: expr, $field: ident, required) => {{
		#[allow(unused_comparisons)] // Note that $type may be 0 making the second comparison always true
		let missing_req_type = $last_seen_type.is_none() || $last_seen_type.unwrap() < $type;
		if missing_req_type {
			return Err(DecodeError::InvalidValue);
		}
	}};
	($last_seen_type: expr, $type: expr, $field: ident, vec_type) => {{
		// no-op
	}};
	($last_seen_type: expr, $type: expr, $field: ident, option) => {{
		// no-op
	}};
	($last_seen_type: expr, $type: expr, $field: ident, ignorable) => {{
		// no-op
	}};
	($last_seen_type: expr, $type: expr, $field: ident, (option: $trait: ident $(, $read_arg: expr)?)) => {{
		// no-op
	}};
	($last_seen_type: expr, $type: expr, $field: ident, (option, encoding: $encoding: tt)) => {{
		// no-op
	}};
}

macro_rules! decode_tlv {
	($reader: expr, $field: ident, (default_value, $default: expr)) => {{
		decode_tlv!($reader, $field, required)
	}};
	($reader: expr, $field: ident, required) => {{
		$field = $crate::util::ser::Readable::read(&mut $reader)?;
	}};
	($reader: expr, $field: ident, vec_type) => {{
		let f: $crate::util::ser::WithoutLength<Vec<_>> = $crate::util::ser::Readable::read(&mut $reader)?;
		$field = Some(f.0);
	}};
	($reader: expr, $field: ident, option) => {{
		$field = Some($crate::util::ser::Readable::read(&mut $reader)?);
	}};
	($reader: expr, $field: ident, ignorable) => {{
		$field = $crate::util::ser::MaybeReadable::read(&mut $reader)?;
	}};
	($reader: expr, $field: ident, (option: $trait: ident $(, $read_arg: expr)?)) => {{
		$field = Some($trait::read(&mut $reader $(, $read_arg)*)?);
	}};
	($reader: expr, $field: ident, (option, encoding: ($fieldty: ty, $encoding: ident))) => {{
		$field = {
			let field: $encoding<$fieldty> = ser::Readable::read(&mut $reader)?;
			Some(field.0)
		};
	}};
	($reader: expr, $field: ident, (option, encoding: $fieldty: ty)) => {{
		decode_tlv!($reader, $field, option);
	}};
}

// `$decode_custom_tlv` is a closure that may be optionally provided to handle custom message types.
// If it is provided, it will be called with the custom type and the `FixedLengthReader` containing
// the message contents. It should return `Ok(true)` if the custom message is successfully parsed,
// `Ok(false)` if the message type is unknown, and `Err(DecodeError)` if parsing fails.
macro_rules! decode_tlv_stream {
	($stream: expr, {$(($type: expr, $field: ident, $fieldty: tt)),* $(,)*}
	 $(, $decode_custom_tlv: expr)?) => { {
		let rewind = |_, _| { unreachable!() };
		use core::ops::RangeBounds;
		decode_tlv_stream_range!(
			$stream, .., rewind, {$(($type, $field, $fieldty)),*} $(, $decode_custom_tlv)?
		);
	} }
}

macro_rules! decode_tlv_stream_range {
	($stream: expr, $range: expr, $rewind: ident, {$(($type: expr, $field: ident, $fieldty: tt)),* $(,)*}
	 $(, $decode_custom_tlv: expr)?) => { {
		use $crate::ln::msgs::DecodeError;
		let mut last_seen_type: Option<u64> = None;
		let mut stream_ref = $stream;
		'tlv_read: loop {
			use $crate::util::ser;

			// First decode the type of this TLV:
			let typ: ser::BigSize = {
				// We track whether any bytes were read during the consensus_decode call to
				// determine whether we should break or return ShortRead if we get an
				// UnexpectedEof. This should in every case be largely cosmetic, but its nice to
				// pass the TLV test vectors exactly, which requre this distinction.
				let mut tracking_reader = ser::ReadTrackingReader::new(&mut stream_ref);
				match <$crate::util::ser::BigSize as $crate::util::ser::Readable>::read(&mut tracking_reader) {
					Err(DecodeError::ShortRead) => {
						if !tracking_reader.have_read {
							break 'tlv_read;
						} else {
							return Err(DecodeError::ShortRead);
						}
					},
					Err(e) => return Err(e),
					Ok(t) => if $range.contains(&t.0) { t } else {
						drop(tracking_reader);

						// Assumes the type id is minimally encoded, which is enforced on read.
						use $crate::util::ser::Writeable;
						let bytes_read = t.serialized_length();
						$rewind(stream_ref, bytes_read);
						break 'tlv_read;
					},
				}
			};

			// Types must be unique and monotonically increasing:
			match last_seen_type {
				Some(t) if typ.0 <= t => {
					return Err(DecodeError::InvalidValue);
				},
				_ => {},
			}
			// As we read types, make sure we hit every required type:
			$({
				check_tlv_order!(last_seen_type, typ, $type, $field, $fieldty);
			})*
			last_seen_type = Some(typ.0);

			// Finally, read the length and value itself:
			let length: ser::BigSize = $crate::util::ser::Readable::read(&mut stream_ref)?;
			let mut s = ser::FixedLengthReader::new(&mut stream_ref, length.0);
			match typ.0 {
				$($type => {
					decode_tlv!(s, $field, $fieldty);
					if s.bytes_remain() {
						s.eat_remaining()?; // Return ShortRead if there's actually not enough bytes
						return Err(DecodeError::InvalidValue);
					}
				},)*
				t => {
					$(
						if $decode_custom_tlv(t, &mut s)? {
							// If a custom TLV was successfully read (i.e. decode_custom_tlv returns true),
							// continue to the next TLV read.
							s.eat_remaining()?;
							continue 'tlv_read;
						}
					)?
					if t % 2 == 0 {
						return Err(DecodeError::UnknownRequiredFeature);
					}
				}
			}
			s.eat_remaining()?;
		}
		// Make sure we got to each required type after we've read every TLV:
		$({
			check_missing_tlv!(last_seen_type, $type, $field, $fieldty);
		})*
	} }
}

macro_rules! impl_writeable_msg {
	($st:ident, {$($field:ident),* $(,)*}, {$(($type: expr, $tlvfield: ident, $fieldty: tt)),* $(,)*}) => {
		impl $crate::util::ser::Writeable for $st {
			fn write<W: $crate::util::ser::Writer>(&self, w: &mut W) -> Result<(), $crate::io::Error> {
				$( self.$field.write(w)?; )*
				encode_tlv_stream!(w, {$(($type, self.$tlvfield, $fieldty)),*});
				Ok(())
			}
		}
		impl $crate::util::ser::Readable for $st {
			fn read<R: $crate::io::Read>(r: &mut R) -> Result<Self, $crate::ln::msgs::DecodeError> {
				$(let $field = $crate::util::ser::Readable::read(r)?;)*
				$(init_tlv_field_var!($tlvfield, $fieldty);)*
				decode_tlv_stream!(r, {$(($type, $tlvfield, $fieldty)),*});
				Ok(Self {
					$($field),*,
					$($tlvfield),*
				})
			}
		}
	}
}

macro_rules! impl_writeable {
	($st:ident, {$($field:ident),*}) => {
		impl $crate::util::ser::Writeable for $st {
			fn write<W: $crate::util::ser::Writer>(&self, w: &mut W) -> Result<(), $crate::io::Error> {
				$( self.$field.write(w)?; )*
				Ok(())
			}

			#[inline]
			fn serialized_length(&self) -> usize {
				let mut len_calc = 0;
				$( len_calc += self.$field.serialized_length(); )*
				return len_calc;
			}
		}

		impl $crate::util::ser::Readable for $st {
			fn read<R: $crate::io::Read>(r: &mut R) -> Result<Self, $crate::ln::msgs::DecodeError> {
				Ok(Self {
					$($field: $crate::util::ser::Readable::read(r)?),*
				})
			}
		}
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
	($stream: expr, {$(($type: expr, $field: expr, $fieldty: tt)),* $(,)*}) => {
		encode_varint_length_prefixed_tlv!($stream, {$(($type, $field, $fieldty)),*})
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
	($stream: expr, {$(($type: expr, $field: ident, $fieldty: tt)),* $(,)*}) => { {
		let tlv_len: $crate::util::ser::BigSize = $crate::util::ser::Readable::read($stream)?;
		let mut rd = $crate::util::ser::FixedLengthReader::new($stream, tlv_len.0);
		decode_tlv_stream!(&mut rd, {$(($type, $field, $fieldty)),*});
		rd.eat_remaining().map_err(|_| $crate::ln::msgs::DecodeError::ShortRead)?;
	} }
}

macro_rules! init_tlv_based_struct_field {
	($field: ident, (default_value, $default: expr)) => {
		$field.0.unwrap()
	};
	($field: ident, option) => {
		$field
	};
	($field: ident, required) => {
		$field.0.unwrap()
	};
	($field: ident, vec_type) => {
		$field.unwrap()
	};
}

macro_rules! init_tlv_field_var {
	($field: ident, (default_value, $default: expr)) => {
		let mut $field = $crate::util::ser::OptionDeserWrapper(None);
	};
	($field: ident, required) => {
		let mut $field = $crate::util::ser::OptionDeserWrapper(None);
	};
	($field: ident, vec_type) => {
		let mut $field = Some(Vec::new());
	};
	($field: ident, option) => {
		let mut $field = None;
	};
}

macro_rules! init_and_read_tlv_fields {
	($reader: ident, {$(($type: expr, $field: ident, $fieldty: tt)),* $(,)*}) => {
		$(
			init_tlv_field_var!($field, $fieldty);
		)*

		read_tlv_fields!($reader, {
			$(($type, $field, $fieldty)),*
		});
	}
}

/// Implements Readable/Writeable for a struct storing it as a set of TLVs
/// If $fieldty is `required`, then $field is a required field that is not an Option nor a Vec.
/// If $fieldty is `option`, then $field is optional field.
/// if $fieldty is `vec_type`, then $field is a Vec, which needs to have its individual elements
/// serialized.
macro_rules! impl_writeable_tlv_based {
	($st: ident, {$(($type: expr, $field: ident, $fieldty: tt)),* $(,)*}) => {
		impl $crate::util::ser::Writeable for $st {
			fn write<W: $crate::util::ser::Writer>(&self, writer: &mut W) -> Result<(), $crate::io::Error> {
				write_tlv_fields!(writer, {
					$(($type, self.$field, $fieldty)),*
				});
				Ok(())
			}

			#[inline]
			fn serialized_length(&self) -> usize {
				use $crate::util::ser::BigSize;
				let len = {
					#[allow(unused_mut)]
					let mut len = $crate::util::ser::LengthCalculatingWriter(0);
					$(
						get_varint_length_prefixed_tlv_length!(len, $type, self.$field, $fieldty);
					)*
					len.0
				};
				let mut len_calc = $crate::util::ser::LengthCalculatingWriter(0);
				BigSize(len as u64).write(&mut len_calc).expect("No in-memory data may fail to serialize");
				len + len_calc.0
			}
		}

		impl $crate::util::ser::Readable for $st {
			fn read<R: $crate::io::Read>(reader: &mut R) -> Result<Self, $crate::ln::msgs::DecodeError> {
				init_and_read_tlv_fields!(reader, {
					$(($type, $field, $fieldty)),*
				});
				Ok(Self {
					$(
						$field: init_tlv_based_struct_field!($field, $fieldty)
					),*
				})
			}
		}
	}
}

/// Defines a struct for a TLV stream and a similar struct using references for non-primitive types,
/// implementing [`Readable`] for the former and [`Writeable`] for the latter. Useful as an
/// intermediary format when reading or writing a type encoded as a TLV stream. Note that each field
/// representing a TLV record has its type wrapped with an [`Option`]. A tuple consisting of a type
/// and a serialization wrapper may be given in place of a type when custom serialization is
/// required.
///
/// [`Readable`]: crate::util::ser::Readable
/// [`Writeable`]: crate::util::ser::Writeable
macro_rules! tlv_stream {
	($name:ident, $nameref:ident, $range:expr, {
		$(($type:expr, $field:ident : $fieldty:tt)),* $(,)*
	}) => {
		#[derive(Debug)]
		pub(super) struct $name {
			$(
				pub(super) $field: Option<tlv_record_type!($fieldty)>,
			)*
		}

		pub(super) struct $nameref<'a> {
			$(
				pub(super) $field: Option<tlv_record_ref_type!($fieldty)>,
			)*
		}

		impl<'a> $crate::util::ser::Writeable for $nameref<'a> {
			fn write<W: $crate::util::ser::Writer>(&self, writer: &mut W) -> Result<(), $crate::io::Error> {
				encode_tlv_stream!(writer, {
					$(($type, self.$field, (option, encoding: $fieldty))),*
				});
				Ok(())
			}
		}

		impl $crate::util::ser::SeekReadable for $name {
			fn read<R: $crate::io::Read + $crate::io::Seek>(reader: &mut R) -> Result<Self, $crate::ln::msgs::DecodeError> {
				$(
					init_tlv_field_var!($field, option);
				)*
				let rewind = |cursor: &mut R, offset: usize| {
					cursor.seek($crate::io::SeekFrom::Current(-(offset as i64))).expect("");
				};
				decode_tlv_stream_range!(reader, $range, rewind, {
					$(($type, $field, (option, encoding: $fieldty))),*
				});

				Ok(Self {
					$(
						$field: $field
					),*
				})
			}
		}
	}
}

macro_rules! tlv_record_type {
	(($type:ty, $wrapper:ident)) => { $type };
	($type:ty) => { $type };
}

macro_rules! tlv_record_ref_type {
	(char) => { char };
	(u8) => { u8 };
	((u16, $wrapper: ident)) => { u16 };
	((u32, $wrapper: ident)) => { u32 };
	((u64, $wrapper: ident)) => { u64 };
	(($type:ty, $wrapper:ident)) => { &'a $type };
	($type:ty) => { &'a $type };
}

macro_rules! _impl_writeable_tlv_based_enum_common {
	($st: ident, $(($variant_id: expr, $variant_name: ident) =>
		{$(($type: expr, $field: ident, $fieldty: tt)),* $(,)*}
	),* $(,)*;
	$(($tuple_variant_id: expr, $tuple_variant_name: ident)),*  $(,)*) => {
		impl $crate::util::ser::Writeable for $st {
			fn write<W: $crate::util::ser::Writer>(&self, writer: &mut W) -> Result<(), $crate::io::Error> {
				match self {
					$($st::$variant_name { $(ref $field),* } => {
						let id: u8 = $variant_id;
						id.write(writer)?;
						write_tlv_fields!(writer, {
							$(($type, *$field, $fieldty)),*
						});
					}),*
					$($st::$tuple_variant_name (ref field) => {
						let id: u8 = $tuple_variant_id;
						id.write(writer)?;
						field.write(writer)?;
					}),*
				}
				Ok(())
			}
		}
	}
}

/// Implement MaybeReadable and Writeable for an enum, with struct variants stored as TLVs and
/// tuple variants stored directly.
///
/// This is largely identical to `impl_writeable_tlv_based_enum`, except that odd variants will
/// return `Ok(None)` instead of `Err(UnknownRequiredFeature)`. It should generally be preferred
/// when `MaybeReadable` is practical instead of just `Readable` as it provides an upgrade path for
/// new variants to be added which are simply ignored by existing clients.
macro_rules! impl_writeable_tlv_based_enum_upgradable {
	($st: ident, $(($variant_id: expr, $variant_name: ident) =>
		{$(($type: expr, $field: ident, $fieldty: tt)),* $(,)*}
	),* $(,)*
	$(;
	$(($tuple_variant_id: expr, $tuple_variant_name: ident)),*  $(,)*)*) => {
		_impl_writeable_tlv_based_enum_common!($st,
			$(($variant_id, $variant_name) => {$(($type, $field, $fieldty)),*}),*;
			$($(($tuple_variant_id, $tuple_variant_name)),*)*);

		impl $crate::util::ser::MaybeReadable for $st {
			fn read<R: $crate::io::Read>(reader: &mut R) -> Result<Option<Self>, $crate::ln::msgs::DecodeError> {
				let id: u8 = $crate::util::ser::Readable::read(reader)?;
				match id {
					$($variant_id => {
						// Because read_tlv_fields creates a labeled loop, we cannot call it twice
						// in the same function body. Instead, we define a closure and call it.
						let f = || {
							init_and_read_tlv_fields!(reader, {
								$(($type, $field, $fieldty)),*
							});
							Ok(Some($st::$variant_name {
								$(
									$field: init_tlv_based_struct_field!($field, $fieldty)
								),*
							}))
						};
						f()
					}),*
					$($($tuple_variant_id => {
						Ok(Some($st::$tuple_variant_name(Readable::read(reader)?)))
					}),*)*
					_ if id % 2 == 1 => Ok(None),
					_ => Err(DecodeError::UnknownRequiredFeature),
				}
			}
		}

	}
}

/// Implement Readable and Writeable for an enum, with struct variants stored as TLVs and tuple
/// variants stored directly.
/// The format is, for example
/// impl_writeable_tlv_based_enum!(EnumName,
///   (0, StructVariantA) => {(0, required_variant_field, required), (1, optional_variant_field, option)},
///   (1, StructVariantB) => {(0, variant_field_a, required), (1, variant_field_b, required), (2, variant_vec_field, vec_type)};
///   (2, TupleVariantA), (3, TupleVariantB),
/// );
/// The type is written as a single byte, followed by any variant data.
/// Attempts to read an unknown type byte result in DecodeError::UnknownRequiredFeature.
macro_rules! impl_writeable_tlv_based_enum {
	($st: ident, $(($variant_id: expr, $variant_name: ident) =>
		{$(($type: expr, $field: ident, $fieldty: tt)),* $(,)*}
	),* $(,)*;
	$(($tuple_variant_id: expr, $tuple_variant_name: ident)),*  $(,)*) => {
		_impl_writeable_tlv_based_enum_common!($st,
			$(($variant_id, $variant_name) => {$(($type, $field, $fieldty)),*}),*;
			$(($tuple_variant_id, $tuple_variant_name)),*);

		impl $crate::util::ser::Readable for $st {
			fn read<R: $crate::io::Read>(reader: &mut R) -> Result<Self, $crate::ln::msgs::DecodeError> {
				let id: u8 = $crate::util::ser::Readable::read(reader)?;
				match id {
					$($variant_id => {
						// Because read_tlv_fields creates a labeled loop, we cannot call it twice
						// in the same function body. Instead, we define a closure and call it.
						let f = || {
							init_and_read_tlv_fields!(reader, {
								$(($type, $field, $fieldty)),*
							});
							Ok($st::$variant_name {
								$(
									$field: init_tlv_based_struct_field!($field, $fieldty)
								),*
							})
						};
						f()
					}),*
					$($tuple_variant_id => {
						Ok($st::$tuple_variant_name(Readable::read(reader)?))
					}),*
					_ => {
						Err(DecodeError::UnknownRequiredFeature)
					},
				}
			}
		}
	}
}

#[cfg(test)]
mod tests {
	use crate::io::{self, Cursor};
	use crate::prelude::*;
	use crate::ln::msgs::DecodeError;
	use crate::util::ser::{Writeable, HighZeroBytesDroppedBigSize, VecWriter};
	use bitcoin::secp256k1::PublicKey;

	// The BOLT TLV test cases don't include any tests which use our "required-value" logic since
	// the encoding layer in the BOLTs has no such concept, though it makes our macros easier to
	// work with so they're baked into the decoder. Thus, we have a few additional tests below
	fn tlv_reader(s: &[u8]) -> Result<(u64, u32, Option<u32>), DecodeError> {
		let mut s = Cursor::new(s);
		let mut a: u64 = 0;
		let mut b: u32 = 0;
		let mut c: Option<u32> = None;
		decode_tlv_stream!(&mut s, {(2, a, required), (3, b, required), (4, c, option)});
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

	// BOLT TLV test cases
	fn tlv_reader_n1(s: &[u8]) -> Result<(Option<HighZeroBytesDroppedBigSize<u64>>, Option<u64>, Option<(PublicKey, u64, u64)>, Option<u16>), DecodeError> {
		let mut s = Cursor::new(s);
		let mut tlv1: Option<HighZeroBytesDroppedBigSize<u64>> = None;
		let mut tlv2: Option<u64> = None;
		let mut tlv3: Option<(PublicKey, u64, u64)> = None;
		let mut tlv4: Option<u16> = None;
		decode_tlv_stream!(&mut s, {(1, tlv1, option), (2, tlv2, option), (3, tlv3, option), (254, tlv4, option)});
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

	fn do_simple_test_tlv_write() -> Result<(), io::Error> {
		let mut stream = VecWriter(Vec::new());

		stream.0.clear();
		encode_varint_length_prefixed_tlv!(&mut stream, {(1, 1u8, required), (42, None::<u64>, option)});
		assert_eq!(stream.0, ::hex::decode("03010101").unwrap());

		stream.0.clear();
		encode_varint_length_prefixed_tlv!(&mut stream, {(1, Some(1u8), option)});
		assert_eq!(stream.0, ::hex::decode("03010101").unwrap());

		stream.0.clear();
		encode_varint_length_prefixed_tlv!(&mut stream, {(4, 0xabcdu16, required), (42, None::<u64>, option)});
		assert_eq!(stream.0, ::hex::decode("040402abcd").unwrap());

		stream.0.clear();
		encode_varint_length_prefixed_tlv!(&mut stream, {(42, None::<u64>, option), (0xff, 0xabcdu16, required)});
		assert_eq!(stream.0, ::hex::decode("06fd00ff02abcd").unwrap());

		stream.0.clear();
		encode_varint_length_prefixed_tlv!(&mut stream, {(0, 1u64, required), (42, None::<u64>, option), (0xff, HighZeroBytesDroppedBigSize(0u64), required)});
		assert_eq!(stream.0, ::hex::decode("0e00080000000000000001fd00ff00").unwrap());

		stream.0.clear();
		encode_varint_length_prefixed_tlv!(&mut stream, {(0, Some(1u64), option), (0xff, HighZeroBytesDroppedBigSize(0u64), required)});
		assert_eq!(stream.0, ::hex::decode("0e00080000000000000001fd00ff00").unwrap());

		Ok(())
	}

	#[test]
	fn simple_test_tlv_write() {
		do_simple_test_tlv_write().unwrap();
	}
}
