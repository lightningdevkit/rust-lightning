macro_rules! encode_tlv {
	($stream: expr, {$(($type: expr, $field: expr)),*}) => { {
		use bitcoin::consensus::Encodable;
		use bitcoin::consensus::encode::{Error, VarInt};
		use util::ser::{WriterWriteAdaptor, LengthCalculatingWriter};
		$(
			VarInt($type).consensus_encode(WriterWriteAdaptor($stream))
				.map_err(|e| if let Error::Io(ioe) = e { ioe } else { unreachable!() })?;
			let mut len_calc = LengthCalculatingWriter(0);
			$field.write(&mut len_calc)?;
			VarInt(len_calc.0 as u64).consensus_encode(WriterWriteAdaptor($stream))
				.map_err(|e| if let Error::Io(ioe) = e { ioe } else { unreachable!() })?;
			$field.write($stream)?;
		)*
	} }
}

macro_rules! encode_varint_length_prefixed_tlv {
	($stream: expr, {$(($type: expr, $field: expr)),*}) => { {
		use bitcoin::consensus::Encodable;
		use bitcoin::consensus::encode::{Error, VarInt};
		use util::ser::{WriterWriteAdaptor, LengthCalculatingWriter};
		let mut len = LengthCalculatingWriter(0);
		encode_tlv!(&mut len, {
			$(($type, $field)),*
		});
		VarInt(len.0 as u64).consensus_encode(WriterWriteAdaptor($stream))
			.map_err(|e| if let Error::Io(ioe) = e { ioe } else { unreachable!() })?;
		encode_tlv!($stream, {
			$(($type, $field)),*
		});
	} }
}

macro_rules! decode_tlv {
	($stream: expr, {$(($reqtype: expr, $reqfield: ident)),*}, {$(($type: expr, $field: ident)),*}) => { {
		use ln::msgs::DecodeError;
		let mut max_type: u64 = 0;
		'tlv_read: loop {
			use bitcoin::consensus::encode;
			use util::ser;
			use std;

			let typ: encode::VarInt = match encode::Decodable::consensus_decode($stream) {
				Err(encode::Error::Io(ref ioe)) if ioe.kind() == std::io::ErrorKind::UnexpectedEof
					=> break 'tlv_read,
				Err(encode::Error::Io(ioe)) => Err(DecodeError::from(ioe))?,
				Err(_) => Err(DecodeError::InvalidValue)?,
				Ok(t) => t,
			};
			if typ.0 == std::u64::MAX || typ.0 + 1 <= max_type {
				Err(DecodeError::InvalidValue)?
			}
			$(if max_type < $reqtype + 1 && typ.0 > $reqtype {
				Err(DecodeError::InvalidValue)?
			})*
			max_type = typ.0 + 1;

			let length: encode::VarInt = encode::Decodable::consensus_decode($stream)
				.map_err(|e| match e {
					encode::Error::Io(ioe) => DecodeError::from(ioe),
					_ => DecodeError::InvalidValue
				})?;
			let mut s = ser::FixedLengthReader {
				read: $stream,
				read_len: 0,
				max_len: length.0,
			};
			match typ.0 {
				$($reqtype => {
					$reqfield = ser::Readable::read(&mut s)?;
				},)*
				$($type => {
					$field = Some(ser::Readable::read(&mut s)?);
				},)*
				x if x % 2 == 0 => {
					Err(DecodeError::UnknownRequiredFeature)?
				},
				_ => {},
			}
			s.eat_remaining().map_err(|_| DecodeError::ShortRead)?;
		}
		$(if max_type < $reqtype + 1 {
			Err(DecodeError::InvalidValue)?
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
				$( self.$field.write(w)?; )*
				Ok(())
			}
		}

		impl<R: ::std::io::Read> ::util::ser::Readable<R> for $st {
			fn read(r: &mut R) -> Result<Self, ::ln::msgs::DecodeError> {
				Ok(Self {
					$($field: ::util::ser::Readable::read(r)?),*
				})
			}
		}
	}
}
macro_rules! impl_writeable_len_match {
	($st:ident, {$({$m: pat, $l: expr}),*}, {$($field:ident),*}) => {
		impl Writeable for $st {
			fn write<W: Writer>(&self, w: &mut W) -> Result<(), ::std::io::Error> {
				w.size_hint(match *self {
					$($m => $l,)*
				});
				$( self.$field.write(w)?; )*
				Ok(())
			}
		}

		impl<R: ::std::io::Read> Readable<R> for $st {
			fn read(r: &mut R) -> Result<Self, DecodeError> {
				Ok(Self {
					$($field: Readable::read(r)?),*
				})
			}
		}
	}
}

#[cfg(test)]
mod tests {
	use std::io::Cursor;
	use ln::msgs::DecodeError;

	fn tlv_reader(s: &[u8]) -> Result<(u64, u32, Option<u32>), DecodeError> {
		let mut s = Cursor::new(s);
		let mut a: u64 = 0;
		let mut b: u32 = 0;
		let mut c: Option<u32> = None;
		decode_tlv!(&mut s, {(2, a), (3, b)}, {(4, c)});
		Ok((a, b, c))
	}
	#[test]
	fn test_tlv() {
		// Value for 3 is longer than we expect, but that's ok...
		assert_eq!(tlv_reader(&::hex::decode(
				concat!("0100", "0208deadbeef1badbeef", "0308deadbeef1badf00d")
				).unwrap()[..]).unwrap(),
			(0xdeadbeef1badbeef, 0xdeadbeef, None));
		// ...even if there's something afterwards
		assert_eq!(tlv_reader(&::hex::decode(
				concat!("0100", "0208deadbeef1badbeef", "0308deadbeef1badf00d", "0404ffffffff")
				).unwrap()[..]).unwrap(),
			(0xdeadbeef1badbeef, 0xdeadbeef, Some(0xffffffff)));
		// ...but not if that extra length is missing
		if let Err(DecodeError::ShortRead) = tlv_reader(&::hex::decode(
				concat!("0100", "0208deadbeef1badbeef", "0308deadbeef")
				).unwrap()[..]) {
		} else { panic!(); }

		// If they're out of order that's also bad
		if let Err(DecodeError::InvalidValue) = tlv_reader(&::hex::decode(
				concat!("0100", "0304deadbeef", "0208deadbeef1badbeef")
				).unwrap()[..]) {
		} else { panic!(); }
		// ...even if its some field we don't understand
		if let Err(DecodeError::InvalidValue) = tlv_reader(&::hex::decode(
				concat!("0208deadbeef1badbeef", "0100", "0304deadbeef")
				).unwrap()[..]) {
		} else { panic!(); }

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

		// But usually things are pretty much what we expect:
		assert_eq!(tlv_reader(&::hex::decode(
				concat!("0208deadbeef1badbeef", "03041bad1dea")
				).unwrap()[..]).unwrap(),
			(0xdeadbeef1badbeef, 0x1bad1dea, None));
		assert_eq!(tlv_reader(&::hex::decode(
				concat!("0208deadbeef1badbeef", "03041bad1dea", "040401020304")
				).unwrap()[..]).unwrap(),
			(0xdeadbeef1badbeef, 0x1bad1dea, Some(0x01020304)));
	}
}
