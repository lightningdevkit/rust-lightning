macro_rules! impl_writeable {
	($st:ident, {$($field:ident),*}) => {
		impl<W: ::std::io::Write> Writeable<W> for $st {
			fn write(&self, w: &mut Writer<W>) -> Result<(), DecodeError> {
				$( self.$field.write(w)?; )*
				Ok(())
			}
		}

		impl<R: ::std::io::Read> Readable<R> for $st {
			fn read(r: &mut Reader<R>) -> Result<Self, DecodeError> {
				Ok(Self {
					$($field: Readable::read(r)?),*
				})
			}
		}
	}
}
