macro_rules! impl_writeable {
	($st:ident, {$($field:ident),*}) => {
		impl<W: Writer> Writeable<W> for $st {
			fn write(&self, w: &mut W) -> Result<(), DecodeError> {
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
