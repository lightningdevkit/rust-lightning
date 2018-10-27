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
