macro_rules! impl_writeable {
	($st:ident, $len: expr, {$($field:ident),*}) => {
		impl<W: Writer> Writeable<W> for $st {
			fn write(&self, w: &mut W) -> Result<(), DecodeError> {
				w.size_hint($len);
				$( self.$field.write(w)?; )*
				Ok(())
			}
		}

		impl<R: Read> Readable<R> for $st {
			fn read(r: &mut R) -> Result<Self, DecodeError> {
				Ok(Self {
					$($field: Readable::read(r)?),*
				})
			}
		}
	}
}
macro_rules! impl_writeable_len_match {
	($st:ident, {$({$m: pat, $l: expr}),*}, {$($field:ident),*}) => {
		impl<W: Writer> Writeable<W> for $st {
			fn write(&self, w: &mut W) -> Result<(), DecodeError> {
				w.size_hint(match *self {
					$($m => $l,)*
				});
				$( self.$field.write(w)?; )*
				Ok(())
			}
		}

		impl<R: Read> Readable<R> for $st {
			fn read(r: &mut R) -> Result<Self, DecodeError> {
				Ok(Self {
					$($field: Readable::read(r)?),*
				})
			}
		}
	}
}
