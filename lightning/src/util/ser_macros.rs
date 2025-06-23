// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Some macros that implement [`Readable`]/[`Writeable`] traits for lightning messages.
//! They also handle serialization and deserialization of TLVs.
//!
//! [`Readable`]: crate::util::ser::Readable
//! [`Writeable`]: crate::util::ser::Writeable

/// Implements serialization for a single TLV record.
/// This is exported for use by other exported macros, do not use directly.
#[doc(hidden)]
#[macro_export]
macro_rules! _encode_tlv {
	($stream: expr, $type: expr, $field: expr, (default_value, $default: expr) $(, $self: ident)?) => {
		$crate::_encode_tlv!($stream, $type, $field, required)
	};
	($stream: expr, $type: expr, $field: expr, (static_value, $value: expr) $(, $self: ident)?) => {
		let _ = &$field; // Ensure we "use" the $field
	};
	($stream: expr, $type: expr, $field: expr, required $(, $self: ident)?) => {
		BigSize($type).write($stream)?;
		BigSize($field.serialized_length() as u64).write($stream)?;
		$field.write($stream)?;
	};
	($stream: expr, $type: expr, $field: expr, (required: $trait: ident $(, $read_arg: expr)?) $(, $self: ident)?) => {
		$crate::_encode_tlv!($stream, $type, $field, required);
	};
	($stream: expr, $type: expr, $field: expr, required_vec $(, $self: ident)?) => {
		$crate::_encode_tlv!($stream, $type, $crate::util::ser::WithoutLength($field), required);
	};
	($stream: expr, $type: expr, $field: expr, (required_vec, encoding: ($fieldty: ty, $encoding: ident)) $(, $self: ident)?) => {
		$crate::_encode_tlv!($stream, $type, $encoding($field), required);
	};
	($stream: expr, $optional_type: expr, $optional_field: expr, option $(, $self: ident)?) => {
		if let Some(ref field) = $optional_field {
			BigSize($optional_type).write($stream)?;
			BigSize(field.serialized_length() as u64).write($stream)?;
			field.write($stream)?;
		}
	};
	($stream: expr, $optional_type: expr, $optional_field: expr, (no_write_default, $default: expr) $(, $self: ident)?) => {
		if $optional_field != &$default {
			BigSize($optional_type).write($stream)?;
			BigSize($optional_field.serialized_length() as u64).write($stream)?;
			$optional_field.write($stream)?;
		}
	};
	($stream: expr, $optional_type: expr, $optional_field: expr, (legacy, $fieldty: ty, $write: expr) $(, $self: ident)?) => { {
		let value: Option<_> = $write($($self)?);
		#[cfg(debug_assertions)]
		{
			// The value we write may be either an Option<$fieldty> or an Option<&$fieldty>.
			// Either way, it should decode just fine as a $fieldty, so we check that here.
			// This is useful in that it checks that we aren't accidentally writing, for example,
			// Option<Option<$fieldty>>.
			if let Some(v) = &value {
				let encoded_value = v.encode();
				let mut read_slice = &encoded_value[..];
				let _: $fieldty = $crate::util::ser::Readable::read(&mut read_slice)
					.expect("Failed to read written TLV, check types");
				assert!(read_slice.is_empty(), "Reading written TLV was short, check types");
			}
		}
		$crate::_encode_tlv!($stream, $optional_type, value, option);
	} };
	($stream: expr, $type: expr, $field: expr, optional_vec $(, $self: ident)?) => {
		if !$field.is_empty() {
			$crate::_encode_tlv!($stream, $type, $field, required_vec);
		}
	};
	($stream: expr, $type: expr, $field: expr, upgradable_required $(, $self: ident)?) => {
		$crate::_encode_tlv!($stream, $type, $field, required);
	};
	($stream: expr, $type: expr, $field: expr, upgradable_option $(, $self: ident)?) => {
		$crate::_encode_tlv!($stream, $type, $field, option);
	};
	($stream: expr, $type: expr, $field: expr, (option, encoding: ($fieldty: ty, $encoding: ident) $(, $self: ident)?)) => {
		$crate::_encode_tlv!($stream, $type, $field.map(|f| $encoding(f)), option);
	};
	($stream: expr, $type: expr, $field: expr, (option, encoding: $fieldty: ty) $(, $self: ident)?) => {
		$crate::_encode_tlv!($stream, $type, $field, option);
	};
	($stream: expr, $type: expr, $field: expr, (option: $trait: ident $(, $read_arg: expr)?) $(, $self: ident)?) => {
		// Just a read-mapped type
		$crate::_encode_tlv!($stream, $type, $field, option);
	};
}

/// Panics if the last seen TLV type is not numerically less than the TLV type currently being checked.
/// This is exported for use by other exported macros, do not use directly.
#[doc(hidden)]
#[macro_export]
macro_rules! _check_encoded_tlv_order {
	($last_type: expr, $type: expr, (static_value, $value: expr)) => {};
	($last_type: expr, $type: expr, $fieldty: tt) => {
		if let Some(t) = $last_type {
			// Note that $type may be 0 making the following comparison always false
			#[allow(unused_comparisons)]
			(debug_assert!(t < $type))
		}
		$last_type = Some($type);
	};
}

/// Implements the TLVs serialization part in a [`Writeable`] implementation of a struct.
///
/// This should be called inside a method which returns `Result<_, `[`io::Error`]`>`, such as
/// [`Writeable::write`]. It will only return an `Err` if the stream `Err`s or [`Writeable::write`]
/// on one of the fields `Err`s.
///
/// `$stream` must be a `&mut `[`Writer`] which will receive the bytes for each TLV in the stream.
///
/// Fields MUST be sorted in `$type`-order.
///
/// Note that the lightning TLV requirements require that a single type not appear more than once,
/// that TLVs are sorted in type-ascending order, and that any even types be understood by the
/// decoder.
///
/// Any `option` fields which have a value of `None` will not be serialized at all.
///
/// For example,
/// ```
/// # use lightning::encode_tlv_stream;
/// # fn write<W: lightning::util::ser::Writer> (stream: &mut W) -> Result<(), lightning::io::Error> {
/// let mut required_value = 0u64;
/// let mut optional_value: Option<u64> = None;
/// encode_tlv_stream!(stream, {
///     (0, required_value, required),
///     (1, Some(42u64), option),
///     (2, optional_value, option),
/// });
/// // At this point `required_value` has been written as a TLV of type 0, `42u64` has been written
/// // as a TLV of type 1 (indicating the reader may ignore it if it is not understood), and *no*
/// // TLV is written with type 2.
/// # Ok(())
/// # }
/// ```
///
/// [`Writeable`]: crate::util::ser::Writeable
/// [`io::Error`]: crate::io::Error
/// [`Writeable::write`]: crate::util::ser::Writeable::write
/// [`Writer`]: crate::util::ser::Writer
#[macro_export]
macro_rules! encode_tlv_stream {
	($stream: expr, {$(($type: expr, $field: expr, $fieldty: tt)),* $(,)*}) => {
		$crate::_encode_tlv_stream!($stream, {$(($type, $field, $fieldty)),*})
	}
}

/// Implementation of [`encode_tlv_stream`].
/// This is exported for use by other exported macros, do not use directly.
#[doc(hidden)]
#[macro_export]
macro_rules! _encode_tlv_stream {
	($stream: expr, {$(($type: expr, $field: expr, $fieldty: tt $(, $self: ident)?)),* $(,)*}) => { {
		$crate::_encode_tlv_stream!($stream, { $(($type, $field, $fieldty $(, $self)?)),* }, &[])
	} };
	($stream: expr, {$(($type: expr, $field: expr, $fieldty: tt $(, $self: ident)?)),* $(,)*}, $extra_tlvs: expr) => { {
		#[allow(unused_imports)]
		use $crate::{
			ln::msgs::DecodeError,
			util::ser,
			util::ser::BigSize,
			util::ser::Writeable,
		};

		$(
			$crate::_encode_tlv!($stream, $type, $field, $fieldty $(, $self)?);
		)*
		for tlv in $extra_tlvs {
			let (typ, value): &(u64, Vec<u8>) = tlv;
			$crate::_encode_tlv!($stream, *typ, value, required_vec);
		}

		#[allow(unused_mut, unused_variables, unused_assignments)]
		#[cfg(debug_assertions)]
		{
			let mut last_seen: Option<u64> = None;
			$(
				$crate::_check_encoded_tlv_order!(last_seen, $type, $fieldty);
			)*
			for tlv in $extra_tlvs {
				let (typ, _): &(u64, Vec<u8>) = tlv;
				$crate::_check_encoded_tlv_order!(last_seen, *typ, required_vec);
			}
		}
	} };
}

/// Adds the length of the serialized field to a [`LengthCalculatingWriter`].
/// This is exported for use by other exported macros, do not use directly.
///
/// [`LengthCalculatingWriter`]: crate::util::ser::LengthCalculatingWriter
#[doc(hidden)]
#[macro_export]
macro_rules! _get_varint_length_prefixed_tlv_length {
	($len: expr, $type: expr, $field: expr, (default_value, $default: expr) $(, $self: ident)?) => {
		$crate::_get_varint_length_prefixed_tlv_length!($len, $type, $field, required)
	};
	($len: expr, $type: expr, $field: expr, (static_value, $value: expr) $(, $self: ident)?) => {};
	($len: expr, $type: expr, $field: expr, required $(, $self: ident)?) => {
		BigSize($type).write(&mut $len).expect("No in-memory data may fail to serialize");
		let field_len = $field.serialized_length();
		BigSize(field_len as u64)
			.write(&mut $len)
			.expect("No in-memory data may fail to serialize");
		$len.0 += field_len;
	};
	($len: expr, $type: expr, $field: expr, (required: $trait: ident $(, $read_arg: expr)?) $(, $self: ident)?) => {
		$crate::_get_varint_length_prefixed_tlv_length!($len, $type, $field, required);
	};
	($len: expr, $type: expr, $field: expr, required_vec $(, $self: ident)?) => {
		let field = $crate::util::ser::WithoutLength($field);
		$crate::_get_varint_length_prefixed_tlv_length!($len, $type, field, required);
	};
	($len: expr, $type: expr, $field: expr, (required_vec, encoding: ($fieldty: ty, $encoding: ident)) $(, $self: ident)?) => {
		let field = $encoding($field);
		$crate::_get_varint_length_prefixed_tlv_length!($len, $type, field, required);
	};
	($len: expr, $optional_type: expr, $optional_field: expr, option $(, $self: ident)?) => {
		if let Some(ref field) = $optional_field.as_ref() {
			BigSize($optional_type)
				.write(&mut $len)
				.expect("No in-memory data may fail to serialize");
			let field_len = field.serialized_length();
			BigSize(field_len as u64)
				.write(&mut $len)
				.expect("No in-memory data may fail to serialize");
			$len.0 += field_len;
		}
	};
	($len: expr, $optional_type: expr, $optional_field: expr, (no_write_default, $default: expr) $(, $self: ident)?) => {
		if $optional_field != &$default {
			BigSize($optional_type)
				.write(&mut $len)
				.expect("No in-memory data may fail to serialize");
			let field_len = $optional_field.serialized_length();
			BigSize(field_len as u64)
				.write(&mut $len)
				.expect("No in-memory data may fail to serialize");
			$len.0 += field_len;
		}
	};
	($len: expr, $optional_type: expr, $optional_field: expr, (legacy, $fieldty: ty, $write: expr) $(, $self: ident)?) => {
		$crate::_get_varint_length_prefixed_tlv_length!($len, $optional_type, $write($($self)?), option);
	};
	($len: expr, $type: expr, $field: expr, optional_vec $(, $self: ident)?) => {
		if !$field.is_empty() {
			$crate::_get_varint_length_prefixed_tlv_length!($len, $type, $field, required_vec);
		}
	};
	($len: expr, $type: expr, $field: expr, (option: $trait: ident $(, $read_arg: expr)?) $(, $self: ident)?) => {
		$crate::_get_varint_length_prefixed_tlv_length!($len, $type, $field, option);
	};
	($len: expr, $type: expr, $field: expr, (option, encoding: ($fieldty: ty, $encoding: ident)) $(, $self: ident)?) => {
		let field = $field.map(|f| $encoding(f));
		$crate::_get_varint_length_prefixed_tlv_length!($len, $type, field, option);
	};
	($len: expr, $type: expr, $field: expr, upgradable_required $(, $self: ident)?) => {
		$crate::_get_varint_length_prefixed_tlv_length!($len, $type, $field, required);
	};
	($len: expr, $type: expr, $field: expr, upgradable_option $(, $self: ident)?) => {
		$crate::_get_varint_length_prefixed_tlv_length!($len, $type, $field, option);
	};
}

/// See the documentation of [`write_tlv_fields`].
/// This is exported for use by other exported macros, do not use directly.
#[doc(hidden)]
#[macro_export]
macro_rules! _encode_varint_length_prefixed_tlv {
	($stream: expr, {$(($type: expr, $field: expr, $fieldty: tt $(, $self: ident)?)),*}) => { {
		$crate::_encode_varint_length_prefixed_tlv!($stream, {$(($type, $field, $fieldty $(, $self)?)),*}, &[])
	} };
	($stream: expr, {$(($type: expr, $field: expr, $fieldty: tt $(, $self: ident)?)),*}, $extra_tlvs: expr) => { {
		extern crate alloc;
		use $crate::util::ser::BigSize;
		use alloc::vec::Vec;
		let len = {
			#[allow(unused_mut)]
			let mut len = $crate::util::ser::LengthCalculatingWriter(0);
			$(
				$crate::_get_varint_length_prefixed_tlv_length!(len, $type, $field, $fieldty $(, $self)?);
			)*
			for tlv in $extra_tlvs {
				let (typ, value): &(u64, Vec<u8>) = tlv;
				$crate::_get_varint_length_prefixed_tlv_length!(len, *typ, value, required_vec);
			}
			len.0
		};
		BigSize(len as u64).write($stream)?;
		$crate::_encode_tlv_stream!($stream, { $(($type, $field, $fieldty $(, $self)?)),* }, $extra_tlvs);
	} };
}

/// Errors if there are missing required TLV types between the last seen type and the type currently being processed.
/// This is exported for use by other exported macros, do not use directly.
#[doc(hidden)]
#[macro_export]
macro_rules! _check_decoded_tlv_order {
	($last_seen_type: expr, $typ: expr, $type: expr, $field: ident, (default_value, $default: expr)) => {{
		// Note that $type may be 0 making the second comparison always false
		#[allow(unused_comparisons)]
		let invalid_order =
			($last_seen_type.is_none() || $last_seen_type.unwrap() < $type) && $typ.0 > $type;
		if invalid_order {
			$field = $default.into();
		}
	}};
	($last_seen_type: expr, $typ: expr, $type: expr, $field: ident, (static_value, $value: expr)) => {};
	($last_seen_type: expr, $typ: expr, $type: expr, $field: ident, required) => {{
		// Note that $type may be 0 making the second comparison always false
		#[allow(unused_comparisons)]
		let invalid_order =
			($last_seen_type.is_none() || $last_seen_type.unwrap() < $type) && $typ.0 > $type;
		if invalid_order {
			return Err(DecodeError::InvalidValue);
		}
	}};
	($last_seen_type: expr, $typ: expr, $type: expr, $field: ident, (required: $trait: ident $(, $read_arg: expr)?)) => {{
		$crate::_check_decoded_tlv_order!($last_seen_type, $typ, $type, $field, required);
	}};
	($last_seen_type: expr, $typ: expr, $type: expr, $field: ident, option) => {{
		// no-op
	}};
	($last_seen_type: expr, $typ: expr, $type: expr, $field: ident, (option, explicit_type: $fieldty: ty)) => {{
		// no-op
	}};
	($last_seen_type: expr, $typ: expr, $type: expr, $field: ident, (legacy, $fieldty: ty, $write: expr)) => {{
		// no-op
	}};
	($last_seen_type: expr, $typ: expr, $type: expr, $field: ident, (required, explicit_type: $fieldty: ty)) => {{
		_check_decoded_tlv_order!($last_seen_type, $typ, $type, $field, required);
	}};
	($last_seen_type: expr, $typ: expr, $type: expr, $field: ident, required_vec) => {{
		$crate::_check_decoded_tlv_order!($last_seen_type, $typ, $type, $field, required);
	}};
	($last_seen_type: expr, $typ: expr, $type: expr, $field: ident, (required_vec, encoding: $encoding: tt)) => {{
		$crate::_check_decoded_tlv_order!($last_seen_type, $typ, $type, $field, required);
	}};
	($last_seen_type: expr, $typ: expr, $type: expr, $field: ident, optional_vec) => {{
		// no-op
	}};
	($last_seen_type: expr, $typ: expr, $type: expr, $field: ident, upgradable_required) => {{
		_check_decoded_tlv_order!($last_seen_type, $typ, $type, $field, required)
	}};
	($last_seen_type: expr, $typ: expr, $type: expr, $field: ident, upgradable_option) => {{
		// no-op
	}};
	($last_seen_type: expr, $typ: expr, $type: expr, $field: ident, (option: $trait: ident $(, $read_arg: expr)?)) => {{
		// no-op
	}};
	($last_seen_type: expr, $typ: expr, $type: expr, $field: ident, (option, encoding: $encoding: tt)) => {{
		// no-op
	}};
}

/// Errors if there are missing required TLV types after the last seen type.
/// This is exported for use by other exported macros, do not use directly.
#[doc(hidden)]
#[macro_export]
macro_rules! _check_missing_tlv {
	($last_seen_type: expr, $type: expr, $field: ident, (default_value, $default: expr)) => {{
		// Note that $type may be 0 making the second comparison always false
		#[allow(unused_comparisons)]
		let missing_req_type = $last_seen_type.is_none() || $last_seen_type.unwrap() < $type;
		if missing_req_type {
			$field = $default.into();
		}
	}};
	($last_seen_type: expr, $type: expr, $field: expr, (static_value, $value: expr)) => {
		$field = $value;
	};
	($last_seen_type: expr, $type: expr, $field: ident, required) => {{
		// Note that $type may be 0 making the second comparison always false
		#[allow(unused_comparisons)]
		let missing_req_type = $last_seen_type.is_none() || $last_seen_type.unwrap() < $type;
		if missing_req_type {
			return Err(DecodeError::InvalidValue);
		}
	}};
	($last_seen_type: expr, $type: expr, $field: ident, (required: $trait: ident $(, $read_arg: expr)?)) => {{
		$crate::_check_missing_tlv!($last_seen_type, $type, $field, required);
	}};
	($last_seen_type: expr, $type: expr, $field: ident, required_vec) => {{
		$crate::_check_missing_tlv!($last_seen_type, $type, $field, required);
	}};
	($last_seen_type: expr, $type: expr, $field: ident, (required_vec, encoding: $encoding: tt)) => {{
		$crate::_check_missing_tlv!($last_seen_type, $type, $field, required);
	}};
	($last_seen_type: expr, $type: expr, $field: ident, option) => {{
		// no-op
	}};
	($last_seen_type: expr, $type: expr, $field: ident, (option, explicit_type: $fieldty: ty)) => {{
		// no-op
	}};
	($last_seen_type: expr, $type: expr, $field: ident, (legacy, $fieldty: ty, $write: expr)) => {{
		// no-op
	}};
	($last_seen_type: expr, $type: expr, $field: ident, (required, explicit_type: $fieldty: ty)) => {{
		_check_missing_tlv!($last_seen_type, $type, $field, required);
	}};
	($last_seen_type: expr, $type: expr, $field: ident, optional_vec) => {{
		// no-op
	}};
	($last_seen_type: expr, $type: expr, $field: ident, upgradable_required) => {{
		_check_missing_tlv!($last_seen_type, $type, $field, required)
	}};
	($last_seen_type: expr, $type: expr, $field: ident, upgradable_option) => {{
		// no-op
	}};
	($last_seen_type: expr, $type: expr, $field: ident, (option: $trait: ident $(, $read_arg: expr)?)) => {{
		// no-op
	}};
	($last_seen_type: expr, $type: expr, $field: ident, (option, encoding: $encoding: tt)) => {{
		// no-op
	}};
}

/// Implements deserialization for a single TLV record.
/// This is exported for use by other exported macros, do not use directly.
#[doc(hidden)]
#[macro_export]
macro_rules! _decode_tlv {
	($outer_reader: expr, $reader: expr, $field: ident, (default_value, $default: expr)) => {{
		$crate::_decode_tlv!($outer_reader, $reader, $field, required)
	}};
	($outer_reader: expr, $reader: expr, $field: ident, (static_value, $value: expr)) => {{
	}};
	($outer_reader: expr, $reader: expr, $field: ident, required) => {{
		$field = $crate::util::ser::LengthReadable::read_from_fixed_length_buffer(&mut $reader)?;
	}};
	($outer_reader: expr, $reader: expr, $field: ident, (required: $trait: ident $(, $read_arg: expr)?)) => {{
		$field = $trait::read(&mut $reader $(, $read_arg)*)?;
	}};
	($outer_reader: expr, $reader: expr, $field: ident, required_vec) => {{
		let f: $crate::util::ser::WithoutLength<Vec<_>> = $crate::util::ser::LengthReadable::read_from_fixed_length_buffer(&mut $reader)?;
		$field = f.0;
	}};
	($outer_reader: expr, $reader: expr, $field: ident, (required_vec, encoding: ($fieldty: ty, $encoding: ident))) => {{
		$field = {
			let field: $encoding<$fieldty> = ser::LengthReadable::read_from_fixed_length_buffer(&mut $reader)?;
			$crate::util::ser::RequiredWrapper(Some(field.0))
		};
	}};
	($outer_reader: expr, $reader: expr, $field: ident, option) => {{
		$field = Some($crate::util::ser::LengthReadable::read_from_fixed_length_buffer(&mut $reader)?);
	}};
	($outer_reader: expr, $reader: expr, $field: ident, (option, explicit_type: $fieldty: ty)) => {{
		let _field: &Option<$fieldty> = &$field;
		$crate::_decode_tlv!($outer_reader, $reader, $field, option);
	}};
	($outer_reader: expr, $reader: expr, $field: ident, (legacy, $fieldty: ty, $write: expr)) => {{
		$crate::_decode_tlv!($outer_reader, $reader, $field, (option, explicit_type: $fieldty));
	}};
	($outer_reader: expr, $reader: expr, $field: ident, (required, explicit_type: $fieldty: ty)) => {{
		let _field: &$fieldty = &$field;
		_decode_tlv!($outer_reader, $reader, $field, required);
	}};
	($outer_reader: expr, $reader: expr, $field: ident, optional_vec) => {{
		let f: $crate::util::ser::WithoutLength<Vec<_>> = $crate::util::ser::LengthReadable::read_from_fixed_length_buffer(&mut $reader)?;
		$field = Some(f.0);
	}};
	// `upgradable_required` indicates we're reading a required TLV that may have been upgraded
	// without backwards compat. We'll error if the field is missing, and return `Ok(None)` if the
	// field is present but we can no longer understand it.
	// Note that this variant can only be used within a `MaybeReadable` read.
	($outer_reader: expr, $reader: expr, $field: ident, upgradable_required) => {{
		$field = match $crate::util::ser::MaybeReadable::read(&mut $reader)? {
			Some(res) => res,
			None => {
				// If we successfully read a value but we don't know how to parse it, we give up
				// and immediately return `None`. However, we need to make sure we read the correct
				// number of bytes for this TLV stream, which is implicitly the end of the stream.
				// Thus, we consume everything left in the `$outer_reader` here, ensuring that if
				// we're being read as a part of another TLV stream we don't spuriously fail to
				// deserialize the outer object due to a TLV length mismatch.
				$crate::io_extras::copy($outer_reader, &mut $crate::io_extras::sink()).unwrap();
				return Ok(None)
			},
		};
	}};
	// `upgradable_option` indicates we're reading an Option-al TLV that may have been upgraded
	// without backwards compat. $field will be None if the TLV is missing or if the field is present
	// but we can no longer understand it.
	($outer_reader: expr, $reader: expr, $field: ident, upgradable_option) => {{
		$field = $crate::util::ser::MaybeReadable::read(&mut $reader)?;
		if $field.is_none() {
			#[cfg(not(debug_assertions))] {
				// In general, MaybeReadable implementations are required to consume all the bytes
				// of the object even if they don't understand it, but due to a bug in the
				// serialization format for `impl_writeable_tlv_based_enum_upgradable` we sometimes
				// don't know how many bytes that is. In such cases, we'd like to spuriously allow
				// TLV length mismatches, which we do here by calling `eat_remaining` so that the
				// `s.bytes_remain()` check in `_decode_tlv_stream_range` doesn't fail.
				$reader.eat_remaining()?;
			}
		}
	}};
	($outer_reader: expr, $reader: expr, $field: ident, (option: $trait: ident $(, $read_arg: expr)?)) => {{
		$field = Some($trait::read(&mut $reader $(, $read_arg)*)?);
	}};
	($outer_reader: expr, $reader: expr, $field: ident, (option, encoding: ($fieldty: ty, $encoding: ident, $encoder:ty))) => {{
		$crate::_decode_tlv!($outer_reader, $reader, $field, (option, encoding: ($fieldty, $encoding)));
	}};
	($outer_reader: expr, $reader: expr, $field: ident, (option, encoding: ($fieldty: ty, $encoding: ident))) => {{
		$field = {
			let field: $encoding<$fieldty> = ser::LengthReadable::read_from_fixed_length_buffer(&mut $reader)?;
			Some(field.0)
		};
	}};
	($outer_reader: expr, $reader: expr, $field: ident, (option, encoding: $fieldty: ty)) => {{
		$crate::_decode_tlv!($outer_reader, $reader, $field, option);
	}};
}

/// Checks if `$val` matches `$type`.
/// This is exported for use by other exported macros, do not use directly.
#[doc(hidden)]
#[macro_export]
macro_rules! _decode_tlv_stream_match_check {
	($val: ident, $type: expr, (static_value, $value: expr)) => {
		false
	};
	($val: ident, $type: expr, $fieldty: tt) => {
		$val == $type
	};
}

/// Implements the TLVs deserialization part in a [`Readable`] implementation of a struct.
///
/// This should be called inside a method which returns `Result<_, `[`DecodeError`]`>`, such as
/// [`Readable::read`]. It will either return an `Err` or ensure all `required` fields have been
/// read and optionally read `optional` fields.
///
/// `$stream` must be a [`Read`] and will be fully consumed, reading until no more bytes remain
/// (i.e. it returns [`DecodeError::ShortRead`]).
///
/// Fields MUST be sorted in `$type`-order.
///
/// Note that the lightning TLV requirements require that a single type not appear more than once,
/// that TLVs are sorted in type-ascending order, and that any even types be understood by the
/// decoder.
///
/// For example,
/// ```
/// # use lightning::decode_tlv_stream;
/// # fn read<R: lightning::io::Read> (stream: &mut R) -> Result<(), lightning::ln::msgs::DecodeError> {
/// let mut required_value = 0u64;
/// let mut optional_value: Option<u64> = None;
/// decode_tlv_stream!(stream, {
///     (0, required_value, required),
///     (2, optional_value, option),
/// });
/// // At this point, `required_value` has been overwritten with the TLV with type 0.
/// // `optional_value` may have been overwritten, setting it to `Some` if a TLV with type 2 was
/// // present.
/// # Ok(())
/// # }
/// ```
///
/// [`Readable`]: crate::util::ser::Readable
/// [`DecodeError`]: crate::ln::msgs::DecodeError
/// [`Readable::read`]: crate::util::ser::Readable::read
/// [`Read`]: crate::io::Read
/// [`DecodeError::ShortRead`]: crate::ln::msgs::DecodeError::ShortRead
#[macro_export]
macro_rules! decode_tlv_stream {
	($stream: expr, {$(($type: expr, $field: ident, $fieldty: tt)),* $(,)*}) => {
		let rewind = |_, _| { unreachable!() };
		$crate::_decode_tlv_stream_range!($stream, .., rewind, {$(($type, $field, $fieldty)),*});
	}
}

/// Similar to [`decode_tlv_stream`] with a custom TLV decoding capabilities.
///
/// `$decode_custom_tlv` is a closure that may be optionally provided to handle custom message types.
/// If it is provided, it will be called with the custom type and the [`FixedLengthReader`] containing
/// the message contents. It should return `Ok(true)` if the custom message is successfully parsed,
/// `Ok(false)` if the message type is unknown, and `Err(`[`DecodeError`]`)` if parsing fails.
///
/// [`FixedLengthReader`]: crate::util::ser::FixedLengthReader
/// [`DecodeError`]: crate::ln::msgs::DecodeError
macro_rules! decode_tlv_stream_with_custom_tlv_decode {
	($stream: expr, {$(($type: expr, $field: ident, $fieldty: tt)),* $(,)*}
	 $(, $decode_custom_tlv: expr)?) => { {
		let rewind = |_, _| { unreachable!() };
		_decode_tlv_stream_range!(
			$stream, .., rewind, {$(($type, $field, $fieldty)),*} $(, $decode_custom_tlv)?
		);
	} }
}

#[doc(hidden)]
#[macro_export]
macro_rules! _decode_tlv_stream_range {
	($stream: expr, $range: expr, $rewind: ident, {$(($type: expr, $field: ident, $fieldty: tt)),* $(,)*}
	 $(, $decode_custom_tlv: expr)?) => { {
		use $crate::ln::msgs::DecodeError;
		let mut last_seen_type: Option<u64> = None;
		let stream_ref = $stream;
		'tlv_read: loop {
			use $crate::util::ser;

			// First decode the type of this TLV:
			let typ: ser::BigSize = {
				// We track whether any bytes were read during the consensus_decode call to
				// determine whether we should break or return ShortRead if we get an
				// UnexpectedEof. This should in every case be largely cosmetic, but its nice to
				// pass the TLV test vectors exactly, which require this distinction.
				let mut tracking_reader = ser::ReadTrackingReader::new(stream_ref);
				match <$crate::util::ser::BigSize as $crate::util::ser::Readable>::read(&mut tracking_reader) {
					Err(DecodeError::ShortRead) => {
						if !tracking_reader.have_read {
							break 'tlv_read;
						} else {
							return Err(DecodeError::ShortRead);
						}
					},
					Err(e) => return Err(e),
					Ok(t) => if core::ops::RangeBounds::contains(&$range, &t.0) { t } else {
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
			// As we read types, make sure we hit every required type between `last_seen_type` and `typ`:
			$({
				$crate::_check_decoded_tlv_order!(last_seen_type, typ, $type, $field, $fieldty);
			})*
			last_seen_type = Some(typ.0);

			// Finally, read the length and value itself:
			let length: ser::BigSize = $crate::util::ser::Readable::read(stream_ref)?;
			let mut s = ser::FixedLengthReader::new(stream_ref, length.0);
			match typ.0 {
				$(_t if $crate::_decode_tlv_stream_match_check!(_t, $type, $fieldty) => {
					$crate::_decode_tlv!($stream, s, $field, $fieldty);
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
			$crate::_check_missing_tlv!(last_seen_type, $type, $field, $fieldty);
		})*
	} }
}

/// Implements [`LengthReadable`]/[`Writeable`] for a message struct that may include non-TLV and
/// TLV-encoded parts.
///
/// This is useful to implement a [`CustomMessageReader`].
///
/// Currently `$fieldty` may only be `option`, i.e., `$tlvfield` is optional field.
///
/// For example,
/// ```
/// # use lightning::impl_writeable_msg;
/// struct MyCustomMessage {
/// 	pub field_1: u32,
/// 	pub field_2: bool,
/// 	pub field_3: String,
/// 	pub tlv_optional_integer: Option<u32>,
/// }
///
/// impl_writeable_msg!(MyCustomMessage, {
/// 	field_1,
/// 	field_2,
/// 	field_3
/// }, {
/// 	(1, tlv_optional_integer, option),
/// });
/// ```
///
/// [`LengthReadable`]: crate::util::ser::LengthReadable
/// [`Writeable`]: crate::util::ser::Writeable
/// [`CustomMessageReader`]: crate::ln::wire::CustomMessageReader
#[macro_export]
macro_rules! impl_writeable_msg {
	($st:ident, {$($field:ident),* $(,)*}, {$(($type: expr, $tlvfield: ident, $fieldty: tt)),* $(,)*}) => {
		impl $crate::util::ser::Writeable for $st {
			fn write<W: $crate::util::ser::Writer>(&self, w: &mut W) -> Result<(), $crate::io::Error> {
				$( self.$field.write(w)?; )*
				$crate::encode_tlv_stream!(w, {$(($type, self.$tlvfield.as_ref(), $fieldty)),*});
				Ok(())
			}
		}
		impl $crate::util::ser::LengthReadable for $st {
			fn read_from_fixed_length_buffer<R: $crate::util::ser::LengthLimitedRead>(
				r: &mut R
			) -> Result<Self, $crate::ln::msgs::DecodeError> {
				$(let $field = $crate::util::ser::Readable::read(r)?;)*
				$($crate::_init_tlv_field_var!($tlvfield, $fieldty);)*
				$crate::decode_tlv_stream!(r, {$(($type, $tlvfield, $fieldty)),*});
				Ok(Self {
					$($field,)*
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
///
/// $this_version represents a unique version of a type. Incremented whenever the type's
/// serialization format has changed or has a new interpretation. Used by a type's reader to
/// determine how to interpret fields or if it can understand a serialized object.
///
/// $min_version_that_can_read_this is the minimum reader version which can understand this
/// serialized object. Previous versions will simply err with a [`DecodeError::UnknownVersion`].
///
/// Updates to either `$this_version` or `$min_version_that_can_read_this` should be included in
/// release notes.
///
/// Both version fields can be specific to this type of object.
///
/// [`DecodeError::UnknownVersion`]: crate::ln::msgs::DecodeError::UnknownVersion
macro_rules! write_ver_prefix {
	($stream: expr, $this_version: expr, $min_version_that_can_read_this: expr) => {
		$stream.write_all(&[$this_version; 1])?;
		$stream.write_all(&[$min_version_that_can_read_this; 1])?;
	};
}

/// Writes out a suffix to an object as a length-prefixed TLV stream which contains potentially
/// backwards-compatible, optional fields which old nodes can happily ignore.
///
/// It is written out in TLV format and, as with all TLV fields, unknown even fields cause a
/// [`DecodeError::UnknownRequiredFeature`] error, with unknown odd fields ignored.
///
/// This is the preferred method of adding new fields that old nodes can ignore and still function
/// correctly.
///
/// [`DecodeError::UnknownRequiredFeature`]: crate::ln::msgs::DecodeError::UnknownRequiredFeature
#[macro_export]
macro_rules! write_tlv_fields {
	($stream: expr, {$(($type: expr, $field: expr, $fieldty: tt)),* $(,)*}) => {
		$crate::_encode_varint_length_prefixed_tlv!($stream, {$(($type, &$field, $fieldty)),*})
	}
}

/// Reads a prefix added by [`write_ver_prefix`], above. Takes the current version of the
/// serialization logic for this object. This is compared against the
/// `$min_version_that_can_read_this` added by [`write_ver_prefix`].
macro_rules! read_ver_prefix {
	($stream: expr, $this_version: expr) => {{
		let ver: u8 = Readable::read($stream)?;
		let min_ver: u8 = Readable::read($stream)?;
		if min_ver > $this_version {
			return Err(DecodeError::UnknownVersion);
		}
		ver
	}};
}

/// Reads a suffix added by [`write_tlv_fields`].
///
/// [`write_tlv_fields`]: crate::write_tlv_fields
#[macro_export]
macro_rules! read_tlv_fields {
	($stream: expr, {$(($type: expr, $field: ident, $fieldty: tt)),* $(,)*}) => { {
		let tlv_len: $crate::util::ser::BigSize = $crate::util::ser::Readable::read($stream)?;
		let mut rd = $crate::util::ser::FixedLengthReader::new($stream, tlv_len.0);
		$crate::decode_tlv_stream!(&mut rd, {$(($type, $field, $fieldty)),*});
		rd.eat_remaining().map_err(|_| $crate::ln::msgs::DecodeError::ShortRead)?;
	} }
}

/// Initializes the struct fields.
///
/// This is exported for use by other exported macros, do not use directly.
#[doc(hidden)]
#[macro_export]
macro_rules! _init_tlv_based_struct_field {
	($field: ident, (default_value, $default: expr)) => {
		$field.0.unwrap()
	};
	($field: ident, (static_value, $value: expr)) => {
		$field
	};
	($field: ident, option) => {
		$field
	};
	($field: ident, (legacy, $fieldty: ty, $write: expr)) => {
		$crate::_init_tlv_based_struct_field!($field, option)
	};
	($field: ident, (option: $trait: ident $(, $read_arg: expr)?)) => {
		$crate::_init_tlv_based_struct_field!($field, option)
	};
	// Note that legacy TLVs are eaten by `drop_legacy_field_definition`
	($field: ident, upgradable_required) => {
		$field.0.unwrap()
	};
	($field: ident, upgradable_option) => {
		$field
	};
	($field: ident, required) => {
		$field.0.unwrap()
	};
	($field: ident, (required: $trait: ident $(, $read_arg: expr)?)) => {
		$crate::_init_tlv_based_struct_field!($field, required)
	};
	($field: ident, required_vec) => {
		$field
	};
	($field: ident, (required_vec, encoding: ($fieldty: ty, $encoding: ident))) => {
		$crate::_init_tlv_based_struct_field!($field, required)
	};
	($field: ident, optional_vec) => {
		$field.unwrap()
	};
}

/// Initializes the variable we are going to read the TLV into.
///
/// This is exported for use by other exported macros, do not use directly.
#[doc(hidden)]
#[macro_export]
macro_rules! _init_tlv_field_var {
	($field: ident, (default_value, $default: expr)) => {
		let mut $field = $crate::util::ser::RequiredWrapper(None);
	};
	($field: ident, (static_value, $value: expr)) => {
		let $field;
	};
	($field: ident, required) => {
		let mut $field = $crate::util::ser::RequiredWrapper(None);
	};
	($field: ident, (required: $trait: ident $(, $read_arg: expr)?)) => {
		$crate::_init_tlv_field_var!($field, required);
	};
	($field: ident, required_vec) => {
		let mut $field = Vec::new();
	};
	($field: ident, (required_vec, encoding: ($fieldty: ty, $encoding: ident))) => {
		$crate::_init_tlv_field_var!($field, required);
	};
	($field: ident, option) => {
		let mut $field = None;
	};
	($field: ident, optional_vec) => {
		let mut $field = Some(Vec::new());
	};
	($field: ident, (option, explicit_type: $fieldty: ty)) => {
		let mut $field: Option<$fieldty> = None;
	};
	($field: ident, (legacy, $fieldty: ty, $write: expr)) => {
		$crate::_init_tlv_field_var!($field, (option, explicit_type: $fieldty));
	};
	($field: ident, (required, explicit_type: $fieldty: ty)) => {
		let mut $field = $crate::util::ser::RequiredWrapper::<$fieldty>(None);
	};
	($field: ident, (option, encoding: ($fieldty: ty, $encoding: ident))) => {
		$crate::_init_tlv_field_var!($field, option);
	};
	($field: ident, (option: $trait: ident $(, $read_arg: expr)?)) => {
		$crate::_init_tlv_field_var!($field, option);
	};
	($field: ident, upgradable_required) => {
		let mut $field = $crate::util::ser::UpgradableRequired(None);
	};
	($field: ident, upgradable_option) => {
		let mut $field = None;
	};
}

/// Equivalent to running [`_init_tlv_field_var`] then [`read_tlv_fields`].
///
/// If any unused values are read, their type MUST be specified or else `rustc` will read them as an
/// `i64`.
///
/// This is exported for use by other exported macros, do not use directly.
#[doc(hidden)]
#[macro_export]
macro_rules! _init_and_read_len_prefixed_tlv_fields {
	($reader: ident, {$(($type: expr, $field: ident, $fieldty: tt)),* $(,)*}) => {
		$(
			$crate::_init_tlv_field_var!($field, $fieldty);
		)*

		$crate::read_tlv_fields!($reader, {
			$(($type, $field, $fieldty)),*
		});
	}
}

/// Equivalent to running [`_init_tlv_field_var`] then [`decode_tlv_stream`].
///
/// If any unused values are read, their type MUST be specified or else `rustc` will read them as an
/// `i64`.
macro_rules! _init_and_read_tlv_stream {
	($reader: ident, {$(($type: expr, $field: ident, $fieldty: tt)),* $(,)*}) => {
		$(
			$crate::_init_tlv_field_var!($field, $fieldty);
		)*
		$crate::decode_tlv_stream!($reader, {
			$(($type, $field, $fieldty)),*
		});
	}
}

/// Reads a TLV stream with the given fields to build a struct/enum variant of type `$thing`
#[doc(hidden)]
#[macro_export]
macro_rules! _decode_and_build {
	($stream: ident, $thing: path, {$(($type: expr, $field: ident, $fieldty: tt)),* $(,)*}) => { {
		$crate::_init_and_read_len_prefixed_tlv_fields!($stream, {
			$(($type, $field, $fieldty)),*
		});
		::lightning_macros::drop_legacy_field_definition!($thing {
			$($field: $crate::_init_tlv_based_struct_field!($field, $fieldty)),*
		})
	} }
}

/// Implements [`Readable`]/[`Writeable`] for a struct storing it as a set of TLVs. Each TLV is
/// read/written in the order they appear and contains a type number, a field name, and a
/// de/serialization method, from the following:
///
/// If `$fieldty` is `required`, then `$field` is a required field that is not an [`Option`] nor a [`Vec`].
/// If `$fieldty` is `(default_value, $default)`, then `$field` will be set to `$default` if not present.
/// If `$fieldty` is `(static_value, $static)`, then `$field` will be set to `$static`.
/// If `$fieldty` is `option`, then `$field` is optional field.
/// If `$fieldty` is `upgradable_option`, then `$field` is optional and read via [`MaybeReadable`].
/// If `$fieldty` is `upgradable_required`, then `$field` is stored as an [`Option`] and read via
///    [`MaybeReadable`], requiring the TLV to be present.
/// If `$fieldty` is `optional_vec`, then `$field` is a [`Vec`], which needs to have its individual elements serialized.
///    Note that for `optional_vec` no bytes are written if the vec is empty
/// If `$fieldty` is `(legacy, $ty, $write)` then, when writing, the function $write will be
///    called with the object being serialized and a returned `Option` and is written as a TLV if
///    `Some`. When reading, an optional field of type `$ty` is read (which can be used in later
///    `default_value` or `static_value` fields by referring to the value by name).
///
/// For example,
/// ```
/// # use lightning::impl_writeable_tlv_based;
/// struct LightningMessage {
/// 	tlv_integer: u32,
/// 	tlv_default_integer: u32,
/// 	tlv_optional_integer: Option<u32>,
/// 	tlv_vec_type_integer: Vec<u32>,
///		tlv_upgraded_integer: u32,
/// }
///
/// impl_writeable_tlv_based!(LightningMessage, {
/// 	(0, tlv_integer, required),
/// 	(1, tlv_default_integer, (default_value, 7)),
/// 	(2, tlv_optional_integer, option),
/// 	(3, tlv_vec_type_integer, optional_vec),
/// 	(4, unwritten_type, (legacy, u32, |us: &LightningMessage| Some(us.tlv_integer))),
/// 	(_unused, tlv_upgraded_integer, (static_value, unwritten_type.unwrap_or(0) * 2))
/// });
/// ```
///
/// [`Readable`]: crate::util::ser::Readable
/// [`MaybeReadable`]: crate::util::ser::MaybeReadable
/// [`Writeable`]: crate::util::ser::Writeable
/// [`Vec`]: crate::prelude::Vec
#[macro_export]
macro_rules! impl_writeable_tlv_based {
	($st: ident, {$(($type: expr, $field: ident, $fieldty: tt)),* $(,)*}) => {
		impl $crate::util::ser::Writeable for $st {
			fn write<W: $crate::util::ser::Writer>(&self, writer: &mut W) -> Result<(), $crate::io::Error> {
				$crate::_encode_varint_length_prefixed_tlv!(writer, {
					$(($type, &self.$field, $fieldty, self)),*
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
						$crate::_get_varint_length_prefixed_tlv_length!(len, $type, &self.$field, $fieldty, self);
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
				Ok($crate::_decode_and_build!(reader, Self, {$(($type, $field, $fieldty)),*}))
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
	($name:ident, $nameref:ident $(<$lifetime:lifetime>)?, $range:expr, {
		$(($type:expr, $field:ident : $fieldty:tt)),* $(,)*
	}) => {
		#[derive(Debug)]
		pub(super) struct $name {
			$(
				pub(super) $field: Option<tlv_record_type!($fieldty)>,
			)*
		}

		#[cfg_attr(test, derive(PartialEq))]
		#[derive(Debug)]
		pub(crate) struct $nameref<$($lifetime)*> {
			$(
				pub(super) $field: Option<tlv_record_ref_type!($fieldty)>,
			)*
		}

		impl<$($lifetime)*> $crate::util::ser::Writeable for $nameref<$($lifetime)*> {
			fn write<W: $crate::util::ser::Writer>(&self, writer: &mut W) -> Result<(), $crate::io::Error> {
				encode_tlv_stream!(writer, {
					$(($type, self.$field, (option, encoding: $fieldty))),*
				});
				Ok(())
			}
		}

		impl $crate::util::ser::CursorReadable for $name {
			fn read<R: AsRef<[u8]>>(reader: &mut crate::io::Cursor<R>) -> Result<Self, $crate::ln::msgs::DecodeError> {
				$(
					_init_tlv_field_var!($field, option);
				)*
				let rewind = |cursor: &mut crate::io::Cursor<R>, offset: usize| {
					cursor.set_position(cursor.position().checked_sub(offset as u64).expect("Cannot rewind past 0."));
				};
				_decode_tlv_stream_range!(reader, $range, rewind, {
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
	(($type:ty, $wrapper:ident)) => {
		$type
	};
	(($type:ty, $wrapper:ident, $encoder:ty)) => {
		$type
	};
	($type:ty) => {
		$type
	};
}

macro_rules! tlv_record_ref_type {
	(char) => { char };
	(u8) => { u8 };
	((u16, $wrapper: ident)) => { u16 };
	((u32, $wrapper: ident)) => { u32 };
	((u64, $wrapper: ident)) => { u64 };
	(($type:ty, $wrapper:ident)) => { &'a $type };
	(($type:ty, $wrapper:ident, $encoder:ty)) => { $encoder };
	($type:ty) => { &'a $type };
}

#[doc(hidden)]
#[macro_export]
macro_rules! _impl_writeable_tlv_based_enum_common {
	($st: ident, $(($variant_id: expr, $variant_name: ident) =>
		{$(($type: expr, $field: ident, $fieldty: tt)),* $(,)*}
	),* $(,)?;
	// $tuple_variant_* are only passed from `impl_writeable_tlv_based_enum_*_legacy`
	$(($tuple_variant_id: expr, $tuple_variant_name: ident)),* $(,)?;
	// $length_prefixed_* are only passed from `impl_writeable_tlv_based_enum_*` non-`legacy`
	$(($length_prefixed_tuple_variant_id: expr, $length_prefixed_tuple_variant_name: ident)),* $(,)?) => {
		impl $crate::util::ser::Writeable for $st {
			fn write<W: $crate::util::ser::Writer>(&self, writer: &mut W) -> Result<(), $crate::io::Error> {
				lightning_macros::skip_legacy_fields!(match self {
					$($st::$variant_name { $(ref $field: $fieldty, )* .. } => {
						let id: u8 = $variant_id;
						id.write(writer)?;
						$crate::_encode_varint_length_prefixed_tlv!(writer, {
							$(($type, $field, $fieldty, self)),*
						});
					}),*
					$($st::$tuple_variant_name (ref field) => {
						let id: u8 = $tuple_variant_id;
						id.write(writer)?;
						field.write(writer)?;
					}),*
					$($st::$length_prefixed_tuple_variant_name (ref field) => {
						let id: u8 = $length_prefixed_tuple_variant_id;
						id.write(writer)?;
						$crate::util::ser::BigSize(field.serialized_length() as u64).write(writer)?;
						field.write(writer)?;
					}),*
				});
				Ok(())
			}
		}
	}
}

/// Implement [`Readable`] and [`Writeable`] for an enum, with struct variants stored as TLVs and tuple
/// variants stored directly.
///
/// The format is, for example,
/// ```
/// enum EnumName {
///   StructVariantA {
///     required_variant_field: u64,
///     optional_variant_field: Option<u8>,
///   },
///   StructVariantB {
///     variant_field_a: bool,
///     variant_field_b: u32,
///     variant_vec_field: Vec<u32>,
///   },
///   TupleVariantA(),
///   TupleVariantB(Vec<u8>),
/// }
/// # use lightning::impl_writeable_tlv_based_enum;
/// impl_writeable_tlv_based_enum!(EnumName,
///   (0, StructVariantA) => {(0, required_variant_field, required), (1, optional_variant_field, option)},
///   (1, StructVariantB) => {(0, variant_field_a, required), (1, variant_field_b, required), (2, variant_vec_field, optional_vec)},
///   (2, TupleVariantA) => {}, // Note that empty tuple variants have to use the struct syntax due to rust limitations
///   {3, TupleVariantB} => (),
/// );
/// ```
///
/// The type is written as a single byte, followed by length-prefixed variant data.
///
/// Attempts to read an unknown type byte result in [`DecodeError::UnknownRequiredFeature`].
///
/// Note that the serialization for tuple variants (as well as the call format) was changed in LDK
/// 0.0.124.
///
/// [`Readable`]: crate::util::ser::Readable
/// [`Writeable`]: crate::util::ser::Writeable
/// [`DecodeError::UnknownRequiredFeature`]: crate::ln::msgs::DecodeError::UnknownRequiredFeature
#[macro_export]
macro_rules! impl_writeable_tlv_based_enum {
	($st: ident,
		$(($variant_id: expr, $variant_name: ident) =>
			{$(($type: expr, $field: ident, $fieldty: tt)),* $(,)*}
		),*
		$($(,)? {$tuple_variant_id: expr, $tuple_variant_name: ident} => ()),*
		$(,)?
	) => {
		$crate::_impl_writeable_tlv_based_enum_common!($st,
			$(($variant_id, $variant_name) => {$(($type, $field, $fieldty)),*}),*
			;;
			$(($tuple_variant_id, $tuple_variant_name)),*);

		impl $crate::util::ser::Readable for $st {
			#[allow(unused_mut)]
			fn read<R: $crate::io::Read>(mut reader: &mut R) -> Result<Self, $crate::ln::msgs::DecodeError> {
				let id: u8 = $crate::util::ser::Readable::read(reader)?;
				match id {
					$($variant_id => {
						// Because read_tlv_fields creates a labeled loop, we cannot call it twice
						// in the same function body. Instead, we define a closure and call it.
						let mut f = || {
							Ok($crate::_decode_and_build!(reader, $st::$variant_name, {$(($type, $field, $fieldty)),*}))
						};
						f()
					}),*
					$($tuple_variant_id => {
						let length: $crate::util::ser::BigSize = $crate::util::ser::Readable::read(reader)?;
						let mut s = $crate::util::ser::FixedLengthReader::new(reader, length.0);
						let res = $crate::util::ser::LengthReadable::read_from_fixed_length_buffer(&mut s)?;
						if s.bytes_remain() {
							s.eat_remaining()?; // Return ShortRead if there's actually not enough bytes
							return Err($crate::ln::msgs::DecodeError::InvalidValue);
						}
						Ok($st::$tuple_variant_name(res))
					}),*
					_ => {
						Err($crate::ln::msgs::DecodeError::UnknownRequiredFeature)
					},
				}
			}
		}
	}
}

/// See [`impl_writeable_tlv_based_enum`] and use that unless backwards-compatibility with tuple
/// variants is required.
macro_rules! impl_writeable_tlv_based_enum_legacy {
	($st: ident, $(($variant_id: expr, $variant_name: ident) =>
		{$(($type: expr, $field: ident, $fieldty: tt)),* $(,)*}
	),* $(,)*;
	$(($tuple_variant_id: expr, $tuple_variant_name: ident)),+  $(,)?) => {
		$crate::_impl_writeable_tlv_based_enum_common!($st,
			$(($variant_id, $variant_name) => {$(($type, $field, $fieldty)),*}),*;
			$(($tuple_variant_id, $tuple_variant_name)),+;);

		impl $crate::util::ser::Readable for $st {
			fn read<R: $crate::io::Read>(reader: &mut R) -> Result<Self, $crate::ln::msgs::DecodeError> {
				let id: u8 = $crate::util::ser::Readable::read(reader)?;
				match id {
					$($variant_id => {
						// Because read_tlv_fields creates a labeled loop, we cannot call it twice
						// in the same function body. Instead, we define a closure and call it.
						let mut f = || {
							Ok($crate::_decode_and_build!(reader, $st::$variant_name, {$(($type, $field, $fieldty)),*}))
						};
						f()
					}),*
					$($tuple_variant_id => {
						Ok($st::$tuple_variant_name($crate::util::ser::Readable::read(reader)?))
					}),+
					_ => {
						Err($crate::ln::msgs::DecodeError::UnknownRequiredFeature)
					},
				}
			}
		}
	}
}

/// Implement [`MaybeReadable`] and [`Writeable`] for an enum, with struct variants stored as TLVs and
/// tuple variants stored directly.
///
/// This is largely identical to [`impl_writeable_tlv_based_enum`], except that odd variants will
/// return `Ok(None)` instead of `Err(`[`DecodeError::UnknownRequiredFeature`]`)`. It should generally be preferred
/// when [`MaybeReadable`] is practical instead of just [`Readable`] as it provides an upgrade path for
/// new variants to be added which are simply ignored by existing clients.
///
/// Note that the serialization for tuple variants (as well as the call format) was changed in LDK
/// 0.0.124.
///
/// [`MaybeReadable`]: crate::util::ser::MaybeReadable
/// [`Writeable`]: crate::util::ser::Writeable
/// [`DecodeError::UnknownRequiredFeature`]: crate::ln::msgs::DecodeError::UnknownRequiredFeature
/// [`Readable`]: crate::util::ser::Readable
#[macro_export]
macro_rules! impl_writeable_tlv_based_enum_upgradable {
	($st: ident,
		$(($variant_id: expr, $variant_name: ident) =>
			{$(($type: expr, $field: ident, $fieldty: tt)),* $(,)*}
		),*
		$(, {$tuple_variant_id: expr, $tuple_variant_name: ident} => ())*
		$(, unread_variants: $($unread_variant: ident),*)?
		$(,)?
	) => {
		$crate::_impl_writeable_tlv_based_enum_common!($st,
			$(($variant_id, $variant_name) => {$(($type, $field, $fieldty)),*}),*
			$(, $((255, $unread_variant) => {}),*)?
			;;
			$(($tuple_variant_id, $tuple_variant_name)),*);

		impl $crate::util::ser::MaybeReadable for $st {
			#[allow(unused_mut)]
			fn read<R: $crate::io::Read>(mut reader: &mut R) -> Result<Option<Self>, $crate::ln::msgs::DecodeError> {
				let id: u8 = $crate::util::ser::Readable::read(reader)?;
				match id {
					$($variant_id => {
						// Because read_tlv_fields creates a labeled loop, we cannot call it twice
						// in the same function body. Instead, we define a closure and call it.
						let mut f = || {
							Ok(Some($crate::_decode_and_build!(reader, $st::$variant_name, {$(($type, $field, $fieldty)),*})))
						};
						f()
					}),*
					$($tuple_variant_id => {
						let length: $crate::util::ser::BigSize = $crate::util::ser::Readable::read(reader)?;
						let mut s = $crate::util::ser::FixedLengthReader::new(reader, length.0);
						let res = $crate::util::ser::Readable::read(&mut s)?;
						if s.bytes_remain() {
							s.eat_remaining()?; // Return ShortRead if there's actually not enough bytes
							return Err($crate::ln::msgs::DecodeError::InvalidValue);
						}
						Ok(Some($st::$tuple_variant_name(res)))
					}),*
					// Note that we explicitly match 255 here to reserve it for use in
					// `unread_variants`.
					255|_ if id % 2 == 1 => {
						let tlv_len: $crate::util::ser::BigSize = $crate::util::ser::Readable::read(reader)?;
						let mut rd = $crate::util::ser::FixedLengthReader::new(reader, tlv_len.0);
						rd.eat_remaining().map_err(|_| $crate::ln::msgs::DecodeError::ShortRead)?;
						Ok(None)
					},
					_ => Err($crate::ln::msgs::DecodeError::UnknownRequiredFeature),
				}
			}
		}
	}
}

/// See [`impl_writeable_tlv_based_enum_upgradable`] and use that unless backwards-compatibility
/// with tuple variants is required.
macro_rules! impl_writeable_tlv_based_enum_upgradable_legacy {
	($st: ident, $(($variant_id: expr, $variant_name: ident) =>
		{$(($type: expr, $field: ident, $fieldty: tt)),* $(,)*}
	),* $(,)?
	;
	$(($tuple_variant_id: expr, $tuple_variant_name: ident)),+  $(,)?) => {
		$crate::_impl_writeable_tlv_based_enum_common!($st,
			$(($variant_id, $variant_name) => {$(($type, $field, $fieldty)),*}),*;
			$(($tuple_variant_id, $tuple_variant_name)),+;);

		impl $crate::util::ser::MaybeReadable for $st {
			fn read<R: $crate::io::Read>(reader: &mut R) -> Result<Option<Self>, $crate::ln::msgs::DecodeError> {
				let id: u8 = $crate::util::ser::Readable::read(reader)?;
				match id {
					$($variant_id => {
						// Because read_tlv_fields creates a labeled loop, we cannot call it twice
						// in the same function body. Instead, we define a closure and call it.
						let mut f = || {
							Ok(Some($crate::_decode_and_build!(reader, $st::$variant_name, {$(($type, $field, $fieldty)),*})))
						};
						f()
					}),*
					$($tuple_variant_id => {
						Ok(Some($st::$tuple_variant_name(Readable::read(reader)?)))
					}),+
					_ if id % 2 == 1 => {
						// Assume that a $variant_id was written, not a $tuple_variant_id, and read
						// the length prefix and discard the correct number of bytes.
						let tlv_len: $crate::util::ser::BigSize = $crate::util::ser::Readable::read(reader)?;
						let mut rd = $crate::util::ser::FixedLengthReader::new(reader, tlv_len.0);
						rd.eat_remaining().map_err(|_| $crate::ln::msgs::DecodeError::ShortRead)?;
						Ok(None)
					},
					_ => Err($crate::ln::msgs::DecodeError::UnknownRequiredFeature),
				}
			}
		}
	}
}

#[cfg(test)]
mod tests {
	#[allow(unused_imports)]
	use crate::prelude::*;

	use crate::io::{self, Cursor};
	use crate::ln::msgs::DecodeError;
	use crate::util::ser::{
		HighZeroBytesDroppedBigSize, LengthReadable, MaybeReadable, Readable, VecWriter,
		WithoutLength, Writeable,
	};
	use bitcoin::hex::FromHex;
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
		let buf =
			<Vec<u8>>::from_hex(concat!("0100", "0208deadbeef1badbeef", "0308deadbeef")).unwrap();
		if let Err(DecodeError::ShortRead) = tlv_reader(&buf[..]) {
		} else {
			panic!();
		}
	}

	#[test]
	fn tlv_types_out_of_order() {
		let buf =
			<Vec<u8>>::from_hex(concat!("0100", "0304deadbeef", "0208deadbeef1badbeef")).unwrap();
		if let Err(DecodeError::InvalidValue) = tlv_reader(&buf[..]) {
		} else {
			panic!();
		}
		// ...even if its some field we don't understand
		let buf =
			<Vec<u8>>::from_hex(concat!("0208deadbeef1badbeef", "0100", "0304deadbeef")).unwrap();
		if let Err(DecodeError::InvalidValue) = tlv_reader(&buf[..]) {
		} else {
			panic!();
		}
	}

	#[test]
	fn tlv_req_type_missing_or_extra() {
		// It's also bad if they included even fields we don't understand
		let buf =
			<Vec<u8>>::from_hex(concat!("0100", "0208deadbeef1badbeef", "0304deadbeef", "0600"))
				.unwrap();
		if let Err(DecodeError::UnknownRequiredFeature) = tlv_reader(&buf[..]) {
		} else {
			panic!();
		}
		// ... or if they're missing fields we need
		let buf = <Vec<u8>>::from_hex(concat!("0100", "0208deadbeef1badbeef")).unwrap();
		if let Err(DecodeError::InvalidValue) = tlv_reader(&buf[..]) {
		} else {
			panic!();
		}
		// ... even if that field is even
		let buf = <Vec<u8>>::from_hex(concat!("0304deadbeef", "0500")).unwrap();
		if let Err(DecodeError::InvalidValue) = tlv_reader(&buf[..]) {
		} else {
			panic!();
		}
	}

	#[test]
	fn tlv_simple_good_cases() {
		let buf = <Vec<u8>>::from_hex(concat!("0208deadbeef1badbeef", "03041bad1dea")).unwrap();
		assert_eq!(tlv_reader(&buf[..]).unwrap(), (0xdeadbeef1badbeef, 0x1bad1dea, None));
		let buf =
			<Vec<u8>>::from_hex(concat!("0208deadbeef1badbeef", "03041bad1dea", "040401020304"))
				.unwrap();
		assert_eq!(
			tlv_reader(&buf[..]).unwrap(),
			(0xdeadbeef1badbeef, 0x1bad1dea, Some(0x01020304))
		);
	}

	#[derive(Debug, PartialEq)]
	struct TestUpgradable {
		a: u32,
		b: u32,
		c: Option<u32>,
	}

	fn upgradable_tlv_reader(s: &[u8]) -> Result<Option<TestUpgradable>, DecodeError> {
		let mut s = Cursor::new(s);
		let mut a = 0;
		let mut b = 0;
		let mut c: Option<u32> = None;
		decode_tlv_stream!(&mut s, {(2, a, upgradable_required), (3, b, upgradable_required), (4, c, upgradable_option)});
		Ok(Some(TestUpgradable { a, b, c }))
	}

	#[test]
	fn upgradable_tlv_simple_good_cases() {
		let buf =
			<Vec<u8>>::from_hex(concat!("0204deadbeef", "03041bad1dea", "0404deadbeef")).unwrap();
		assert_eq!(
			upgradable_tlv_reader(&buf[..]).unwrap(),
			Some(TestUpgradable { a: 0xdeadbeef, b: 0x1bad1dea, c: Some(0xdeadbeef) })
		);

		let buf = <Vec<u8>>::from_hex(concat!("0204deadbeef", "03041bad1dea")).unwrap();
		assert_eq!(
			upgradable_tlv_reader(&buf[..]).unwrap(),
			Some(TestUpgradable { a: 0xdeadbeef, b: 0x1bad1dea, c: None })
		);
	}

	#[test]
	fn missing_required_upgradable() {
		let buf = <Vec<u8>>::from_hex(concat!("0100", "0204deadbeef")).unwrap();
		if let Err(DecodeError::InvalidValue) = upgradable_tlv_reader(&buf[..]) {
		} else {
			panic!();
		}
		let buf = <Vec<u8>>::from_hex(concat!("0100", "03041bad1dea")).unwrap();
		if let Err(DecodeError::InvalidValue) = upgradable_tlv_reader(&buf[..]) {
		} else {
			panic!();
		}
	}

	/// A "V1" enum with only one variant
	enum InnerEnumV1 {
		StructVariantA { field: u32 },
	}

	impl_writeable_tlv_based_enum_upgradable!(InnerEnumV1,
		(0, StructVariantA) => {
			(0, field, required),
		},
	);

	struct OuterStructOptionalEnumV1 {
		inner_enum: Option<InnerEnumV1>,
		other_field: u32,
	}

	impl_writeable_tlv_based!(OuterStructOptionalEnumV1, {
		(0, inner_enum, upgradable_option),
		(2, other_field, required),
	});

	/// An upgraded version of [`InnerEnumV1`] that added a second variant
	enum InnerEnumV2 {
		StructVariantA { field: u32 },
		StructVariantB { field2: u64 },
	}

	impl_writeable_tlv_based_enum_upgradable!(InnerEnumV2,
		(0, StructVariantA) => {
			(0, field, required),
		},
		(1, StructVariantB) => {
			(0, field2, required),
		},
	);

	struct OuterStructOptionalEnumV2 {
		inner_enum: Option<InnerEnumV2>,
		other_field: u32,
	}

	impl_writeable_tlv_based!(OuterStructOptionalEnumV2, {
		(0, inner_enum, upgradable_option),
		(2, other_field, required),
	});

	#[test]
	fn upgradable_enum_option() {
		// Test downgrading from `OuterStructOptionalEnumV2` to `OuterStructOptionalEnumV1` and
		// ensure we still read the `other_field` just fine.
		let serialized_bytes = OuterStructOptionalEnumV2 {
			inner_enum: Some(InnerEnumV2::StructVariantB { field2: 64 }),
			other_field: 0x1bad1dea,
		}
		.encode();
		let mut s = Cursor::new(serialized_bytes);

		let outer_struct: OuterStructOptionalEnumV1 = Readable::read(&mut s).unwrap();
		assert!(outer_struct.inner_enum.is_none());
		assert_eq!(outer_struct.other_field, 0x1bad1dea);
	}

	/// A struct that is read with an [`InnerEnumV1`] but is written with an [`InnerEnumV2`].
	struct OuterStructRequiredEnum {
		#[allow(unused)]
		inner_enum: InnerEnumV1,
	}

	impl MaybeReadable for OuterStructRequiredEnum {
		fn read<R: io::Read>(reader: &mut R) -> Result<Option<Self>, DecodeError> {
			let mut inner_enum = crate::util::ser::UpgradableRequired(None);
			read_tlv_fields!(reader, {
				(0, inner_enum, upgradable_required),
			});
			Ok(Some(Self { inner_enum: inner_enum.0.unwrap() }))
		}
	}

	impl Writeable for OuterStructRequiredEnum {
		fn write<W: crate::util::ser::Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
			write_tlv_fields!(writer, {
				(0, InnerEnumV2::StructVariantB { field2: 0xdeadbeef }, required),
			});
			Ok(())
		}
	}

	struct OuterOuterStruct {
		outer_struct: Option<OuterStructRequiredEnum>,
		other_field: u32,
	}

	impl_writeable_tlv_based!(OuterOuterStruct, {
		(0, outer_struct, upgradable_option),
		(2, other_field, required),
	});

	#[test]
	fn upgradable_enum_required() {
		// Test downgrading from an `OuterOuterStruct` (i.e. test downgrading an
		// `upgradable_required` `InnerEnumV2` to an `InnerEnumV1`).
		//
		// Note that `OuterStructRequiredEnum` has a split write/read implementation that writes an
		// `InnerEnumV2::StructVariantB` irrespective of the value of `inner_enum`.

		let dummy_inner_enum = InnerEnumV1::StructVariantA { field: 42 };
		let serialized_bytes = OuterOuterStruct {
			outer_struct: Some(OuterStructRequiredEnum { inner_enum: dummy_inner_enum }),
			other_field: 0x1bad1dea,
		}
		.encode();
		let mut s = Cursor::new(serialized_bytes);

		let outer_outer_struct: OuterOuterStruct = Readable::read(&mut s).unwrap();
		assert!(outer_outer_struct.outer_struct.is_none());
		assert_eq!(outer_outer_struct.other_field, 0x1bad1dea);
	}

	// BOLT TLV test cases
	fn tlv_reader_n1(
		s: &[u8],
	) -> Result<
		(
			Option<HighZeroBytesDroppedBigSize<u64>>,
			Option<u64>,
			Option<(PublicKey, u64, u64)>,
			Option<u16>,
		),
		DecodeError,
	> {
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
				if let Err(DecodeError::$reason) =
					tlv_reader_n1(&<Vec<u8>>::from_hex($stream).unwrap()[..])
				{
				} else {
					panic!();
				}
			};
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
				if let Err(DecodeError::$reason) =
					tlv_reader_n1(&<Vec<u8>>::from_hex($stream).unwrap()[..])
				{
				} else {
					panic!();
				}
			};
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
		do_test!(
			concat!(
				"03",
				"21",
				"023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb"
			),
			ShortRead
		);
		do_test!(concat!("03", "29", "023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb0000000000000001"), ShortRead);
		do_test!(concat!("03", "30", "023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb000000000000000100000000000001"), ShortRead);
		do_test!(concat!("03", "31", "043da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb00000000000000010000000000000002"), InvalidValue);
		do_test!(concat!("03", "32", "023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb0000000000000001000000000000000001"), InvalidValue);
		do_test!(concat!("fd00fe", "00"), ShortRead);
		do_test!(concat!("fd00fe", "01", "01"), ShortRead);
		do_test!(concat!("fd00fe", "03", "010101"), InvalidValue);
		do_test!(concat!("00", "00"), UnknownRequiredFeature);

		do_test!(concat!("02", "08", "0000000000000226", "01", "01", "2a"), InvalidValue);
		do_test!(
			concat!("02", "08", "0000000000000231", "02", "08", "0000000000000451"),
			InvalidValue
		);
		do_test!(concat!("1f", "00", "0f", "01", "2a"), InvalidValue);
		do_test!(concat!("1f", "00", "1f", "01", "2a"), InvalidValue);

		// The last BOLT test modified to not require creating a new decoder for one trivial test.
		do_test!(concat!("ffffffffffffffffff", "00", "01", "00"), InvalidValue);
	}

	#[test]
	fn bolt_tlv_valid_n1_stream() {
		macro_rules! do_test {
			($stream: expr, $tlv1: expr, $tlv2: expr, $tlv3: expr, $tlv4: expr) => {
				if let Ok((tlv1, tlv2, tlv3, tlv4)) =
					tlv_reader_n1(&<Vec<u8>>::from_hex($stream).unwrap()[..])
				{
					assert_eq!(tlv1.map(|v| v.0), $tlv1);
					assert_eq!(tlv2, $tlv2);
					assert_eq!(tlv3, $tlv3);
					assert_eq!(tlv4, $tlv4);
				} else {
					panic!();
				}
			};
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
		do_test!(
			concat!("01", "08", "0100000000000000"),
			Some(72057594037927936),
			None,
			None,
			None
		);
		do_test!(
			concat!("02", "08", "0000000000000226"),
			None,
			Some((0 << 30) | (0 << 5) | (550 << 0)),
			None,
			None
		);
		do_test!(concat!("03", "31", "023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb00000000000000010000000000000002"),
			None, None, Some((
				PublicKey::from_slice(&<Vec<u8>>::from_hex("023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb").unwrap()[..]).unwrap(), 1, 2)),
			None);
		do_test!(concat!("fd00fe", "02", "0226"), None, None, None, Some(550));
	}

	fn do_simple_test_tlv_write() -> Result<(), io::Error> {
		let mut stream = VecWriter(Vec::new());

		stream.0.clear();
		_encode_varint_length_prefixed_tlv!(&mut stream, {(1, 1u8, required), (42, None::<u64>, option)});
		assert_eq!(stream.0, <Vec<u8>>::from_hex("03010101").unwrap());

		stream.0.clear();
		_encode_varint_length_prefixed_tlv!(&mut stream, { (1, Some(1u8), option) });
		assert_eq!(stream.0, <Vec<u8>>::from_hex("03010101").unwrap());

		stream.0.clear();
		_encode_varint_length_prefixed_tlv!(&mut stream, {(4, 0xabcdu16, required), (42, None::<u64>, option)});
		assert_eq!(stream.0, <Vec<u8>>::from_hex("040402abcd").unwrap());

		stream.0.clear();
		_encode_varint_length_prefixed_tlv!(&mut stream, {(42, None::<u64>, option), (0xff, 0xabcdu16, required)});
		assert_eq!(stream.0, <Vec<u8>>::from_hex("06fd00ff02abcd").unwrap());

		stream.0.clear();
		_encode_varint_length_prefixed_tlv!(&mut stream, {(0, 1u64, required), (42, None::<u64>, option), (0xff, HighZeroBytesDroppedBigSize(0u64), required)});
		assert_eq!(stream.0, <Vec<u8>>::from_hex("0e00080000000000000001fd00ff00").unwrap());

		stream.0.clear();
		_encode_varint_length_prefixed_tlv!(&mut stream, {(0, Some(1u64), option), (0xff, HighZeroBytesDroppedBigSize(0u64), required)});
		assert_eq!(stream.0, <Vec<u8>>::from_hex("0e00080000000000000001fd00ff00").unwrap());

		Ok(())
	}

	#[test]
	fn simple_test_tlv_write() {
		do_simple_test_tlv_write().unwrap();
	}

	#[derive(Debug, Eq, PartialEq)]
	struct EmptyMsg {}
	impl_writeable_msg!(EmptyMsg, {}, {});

	#[test]
	fn impl_writeable_msg_empty() {
		let msg = EmptyMsg {};
		let encoded_msg = msg.encode();
		assert!(encoded_msg.is_empty());
		let decoded_msg: EmptyMsg =
			LengthReadable::read_from_fixed_length_buffer(&mut &encoded_msg[..]).unwrap();
		assert_eq!(msg, decoded_msg);
	}

	#[derive(Debug, PartialEq, Eq)]
	enum TuplesOnly {
		A(),
		B(u64),
	}
	impl_writeable_tlv_based_enum_upgradable!(TuplesOnly, (2, A) => {}, {3, B} => ());

	#[test]
	fn test_impl_writeable_enum() {
		let a = TuplesOnly::A().encode();
		assert_eq!(TuplesOnly::read(&mut Cursor::new(&a)).unwrap(), Some(TuplesOnly::A()));
		let b42 = TuplesOnly::B(42).encode();
		assert_eq!(TuplesOnly::read(&mut Cursor::new(&b42)).unwrap(), Some(TuplesOnly::B(42)));

		// Test unknown variants with 0-length data
		let unknown_variant = vec![41, 0];
		let mut none_read = Cursor::new(&unknown_variant);
		assert_eq!(TuplesOnly::read(&mut none_read).unwrap(), None);
		assert_eq!(none_read.position(), unknown_variant.len() as u64);

		TuplesOnly::read(&mut Cursor::new(&vec![42, 0])).unwrap_err();

		// Test unknown variants with data
		let unknown_data_variant = vec![41, 3, 42, 52, 62];
		let mut none_data_read = Cursor::new(&unknown_data_variant);
		assert_eq!(TuplesOnly::read(&mut none_data_read).unwrap(), None);
		assert_eq!(none_data_read.position(), unknown_data_variant.len() as u64);
	}

	#[derive(Debug, PartialEq, Eq)]
	struct ExpandedField {
		// Old versions of LDK are presumed to have had something like:
		// old_field: u8,
		new_field: (u8, u8),
	}
	impl_writeable_tlv_based!(ExpandedField, {
		(0, old_field, (legacy, u8, |us: &ExpandedField| Some(us.new_field.0))),
		(1, new_field, (default_value, (old_field.ok_or(DecodeError::InvalidValue)?, 0))),
	});

	#[test]
	fn test_legacy_conversion() {
		let mut encoded = ExpandedField { new_field: (43, 42) }.encode();
		assert_eq!(encoded, <Vec<u8>>::from_hex("0700012b01022b2a").unwrap());

		// On read, we'll read a `new_field` which means we won't bother looking at `old_field`.
		encoded[3] = 10;
		let read = <ExpandedField as Readable>::read(&mut &encoded[..]).unwrap();
		assert_eq!(read, ExpandedField { new_field: (43, 42) });

		// On read, if we read an old `ExpandedField` that just has a type-0 `old_field` entry,
		// we'll copy that into the first position of `new_field`.
		let encoded = <Vec<u8>>::from_hex("0300012a").unwrap();
		let read = <ExpandedField as Readable>::read(&mut &encoded[..]).unwrap();
		assert_eq!(read, ExpandedField { new_field: (42, 0) });
	}

	#[test]
	fn required_vec_with_encoding() {
		// Ensure that serializing a required vec with a specified encoding will survive a ser round
		// trip.
		#[derive(PartialEq, Eq, Debug)]
		struct MyCustomStruct {
			tlv_field: Vec<u8>,
		}
		impl_writeable_tlv_based!(MyCustomStruct, {
			(0, tlv_field, (required_vec, encoding: (Vec<u8>, WithoutLength))),
		});

		let instance = MyCustomStruct { tlv_field: vec![42; 32] };
		let encoded = instance.encode();
		let decoded: MyCustomStruct =
			LengthReadable::read_from_fixed_length_buffer(&mut &encoded[..]).unwrap();
		assert_eq!(decoded, instance);
	}
}
