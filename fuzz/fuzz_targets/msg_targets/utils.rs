#![macro_use]

#[macro_export]
macro_rules! test_msg {
	($MsgType: path, $data: ident) => {
		{
			use lightning::util::ser::{Writeable, Readable};
			let mut r = ::std::io::Cursor::new($data);
			if let Ok(msg) = <$MsgType as Readable<::std::io::Cursor<&[u8]>>>::read(&mut r) {
				let p = r.position() as usize;
				let mut w = ::std::io::Cursor::new(vec![]);
				msg.write(&mut w).unwrap();

				let buf = w.into_inner();
				assert_eq!(buf.len(), p);
				assert_eq!(&r.into_inner()[..p], &buf[..p]);
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
				msg.write(&mut ::std::io::Cursor::new(vec![])).unwrap();
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
				let mut w = ::std::io::Cursor::new(vec![]);
				msg.write(&mut w).unwrap();

				let buf = w.into_inner();
				assert_eq!(&r.into_inner()[..], &buf[..]);
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
				let mut w = ::std::io::Cursor::new(vec![]);
				msg.write(&mut w).unwrap();
				let p = w.position() as usize;

				let buf = w.into_inner();
				assert_eq!(buf.len(),p);
				assert_eq!(&r.get_ref()[..$hole], &buf[..$hole]);
				assert_eq!(&r.get_ref()[$hole+$hole_len..p], &buf[$hole+$hole_len..]);
			}
		}
	}
}
