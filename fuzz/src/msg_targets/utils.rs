#![macro_use]

use lightning::util::ser::Writer;
pub struct VecWriter(pub Vec<u8>);
impl Writer for VecWriter {
	fn write_all(&mut self, buf: &[u8]) -> Result<(), ::std::io::Error> {
		assert!(self.0.capacity() >= self.0.len() + buf.len());
		self.0.extend_from_slice(buf);
		Ok(())
	}
	fn size_hint(&mut self, size: usize) {
		self.0.reserve_exact(size);
	}
}

// We attempt to test the strictest behavior we can for a given message, however, some messages
// have different expected behavior. You can see which messages have which behavior in
// gen_target.sh, but, in general, the *_announcement messages have to round-trip exactly (as
// otherwise we'd invalidate the signatures), most messages just need to round-trip up to the
// amount of data we know how to interpret, and some messages we may throw out invalid stuff (eg
// if an error message isn't valid UTF-8 we cant String-ize it), so they wont roundtrip correctly.

// Tests a message that must survive roundtrip exactly, though may not empty the read buffer
// entirely
#[macro_export]
macro_rules! test_msg {
	($MsgType: path, $data: ident) => {
		{
			use lightning::util::ser::{Writeable, Readable};
			let mut r = ::std::io::Cursor::new($data);
			if let Ok(msg) = <$MsgType as Readable<::std::io::Cursor<&[u8]>>>::read(&mut r) {
				let p = r.position() as usize;
				let mut w = VecWriter(Vec::new());
				msg.write(&mut w).unwrap();

				assert_eq!(w.0.len(), p);
				assert_eq!(&r.into_inner()[..p], &w.0[..p]);
			}
		}
	}
}

// Tests a message that may lose data on roundtrip, but shoulnd't lose data compared to our
// re-serialization.
#[macro_export]
macro_rules! test_msg_simple {
	($MsgType: path, $data: ident) => {
		{
			use lightning::util::ser::{Writeable, Readable};
			let mut r = ::std::io::Cursor::new($data);
			if let Ok(msg) = <$MsgType as Readable<::std::io::Cursor<&[u8]>>>::read(&mut r) {
				let mut w = VecWriter(Vec::new());
				msg.write(&mut w).unwrap();

				let msg = <$MsgType as Readable<::std::io::Cursor<&[u8]>>>::read(&mut ::std::io::Cursor::new(&w.0)).unwrap();
				let mut w_two = VecWriter(Vec::new());
				msg.write(&mut w_two).unwrap();
				assert_eq!(&w.0[..], &w_two.0[..]);
			}
		}
	}
}

// Tests a message that must survive roundtrip exactly, and must exactly empty the read buffer and
// split it back out on re-serialization.
#[macro_export]
macro_rules! test_msg_exact {
	($MsgType: path, $data: ident) => {
		{
			use lightning::util::ser::{Writeable, Readable};
			let mut r = ::std::io::Cursor::new($data);
			if let Ok(msg) = <$MsgType as Readable<::std::io::Cursor<&[u8]>>>::read(&mut r) {
				let mut w = VecWriter(Vec::new());
				msg.write(&mut w).unwrap();
				assert_eq!(&r.into_inner()[..], &w.0[..]);
			}
		}
	}
}

// Tests a message that must survive roundtrip exactly, modulo one "hole" which may be set to 0s on
// re-serialization.
#[macro_export]
macro_rules! test_msg_hole {
	($MsgType: path, $data: ident, $hole: expr, $hole_len: expr) => {
		{
			use lightning::util::ser::{Writeable, Readable};
			let mut r = ::std::io::Cursor::new($data);
			if let Ok(msg) = <$MsgType as Readable<::std::io::Cursor<&[u8]>>>::read(&mut r) {
				let mut w = VecWriter(Vec::new());
				msg.write(&mut w).unwrap();
				let p = w.0.len() as usize;

				assert_eq!(w.0.len(), p);
				assert_eq!(&r.get_ref()[..$hole], &w.0[..$hole]);
				assert_eq!(&r.get_ref()[$hole+$hole_len..p], &w.0[$hole+$hole_len..]);
			}
		}
	}
}
