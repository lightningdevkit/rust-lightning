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

#[macro_export]
macro_rules! test_msg_simple {
	($MsgType: path, $data: ident) => {
		{
			use lightning::util::ser::{Writeable, Readable};
			let mut r = ::std::io::Cursor::new($data);
			if let Ok(msg) = <$MsgType as Readable<::std::io::Cursor<&[u8]>>>::read(&mut r) {
				let mut w = VecWriter(Vec::new());
				msg.write(&mut w).unwrap();
			}
		}
	}
}

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
