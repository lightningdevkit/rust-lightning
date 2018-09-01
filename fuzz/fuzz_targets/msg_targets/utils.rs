#![macro_use]

#[macro_export]
macro_rules! test_msg {
	($MsgType: path, $data: ident) => {
		{
			use lightning::ln::msgs::{MsgEncodable, MsgDecodable};
			if let Ok(msg) = <$MsgType as MsgDecodable>::decode($data){
				let enc = msg.encode();
				assert_eq!(&$data[..enc.len()], &enc[..]);
			}
		}
	}
}

#[macro_export]
macro_rules! test_msg_simple {
	($MsgType: path, $data: ident) => {
		{
			use lightning::ln::msgs::{MsgEncodable, MsgDecodable};
			if let Ok(msg) = <$MsgType as MsgDecodable>::decode($data){
				let _ = msg.encode();
			}
		}
	}
}

#[macro_export]
macro_rules! test_msg_exact {
	($MsgType: path, $data: ident) => {
		{
			use lightning::ln::msgs::{MsgEncodable, MsgDecodable};
			if let Ok(msg) = <$MsgType as MsgDecodable>::decode($data){
				let enc = msg.encode();
				assert_eq!(&$data[..], &enc[..]);
			}
		}
	}
}

#[macro_export]
macro_rules! test_msg_hole {
	($MsgType: path, $data: ident, $hole: expr, $hole_len: expr) => {
		{
			use lightning::ln::msgs::{MsgEncodable, MsgDecodable};
			if let Ok(msg) = <$MsgType as MsgDecodable>::decode($data){
				let enc = msg.encode();
				assert_eq!(&$data[..$hole], &enc[..$hole]);
				assert_eq!(&$data[$hole + $hole_len..enc.len()], &enc[$hole + $hole_len..]);
			}
		}
	}
}

#[macro_export]
macro_rules! test_msg_writeable {
	($MsgType: path, $data: ident) => {
		{
			use lightning::ln::msgs::{MsgEncodable, MsgDecodable};
			use lightning::util::ser::{Writer, Reader, Writeable, Readable};
			let mut r = Reader::new(::std::io::Cursor::new($data));
			if let Ok(msg) = <$MsgType as Readable<::std::io::Cursor<&[u8]>>>::read(&mut r) {
				let p = r.get_ref().position() as usize;
				let mut w = Writer::new(::std::io::Cursor::new(vec![]));
				msg.write(&mut w).unwrap();

				let buf = w.into_inner().into_inner();
				assert_eq!(&r.into_inner().into_inner()[..p], &buf[..p]);

				let encoded = <$MsgType as MsgDecodable>::decode(&buf[..]).unwrap().encode();
				assert_eq!(&$data[..p], &encoded[..]);
			}
		}
	}
}

#[macro_export]
macro_rules! test_msg_writeable_simple {
	($MsgType: path, $data: ident) => {
		{
			use lightning::util::ser::{Writer, Reader, Writeable, Readable};
			let mut r = Reader::new(::std::io::Cursor::new($data));
			if let Ok(msg) = <$MsgType as Readable<::std::io::Cursor<&[u8]>>>::read(&mut r) {
				msg.write(&mut Writer::new(::std::io::Cursor::new(vec![]))).unwrap();
			}
		}
	}
}

#[macro_export]
macro_rules! test_msg_writeable_exact {
	($MsgType: path, $data: ident) => {
		{
			use lightning::ln::msgs::{MsgEncodable, MsgDecodable};
			use lightning::util::ser::{Writer, Reader, Writeable, Readable};
			let mut r = Reader::new(::std::io::Cursor::new($data));
			if let Ok(msg) = <$MsgType as Readable<::std::io::Cursor<&[u8]>>>::read(&mut r) {
				let mut w = Writer::new(::std::io::Cursor::new(vec![]));
				msg.write(&mut w).unwrap();

				let buf = w.into_inner().into_inner();
				assert_eq!(&r.into_inner().into_inner()[..], &buf[..]);

				let encoded = <$MsgType as MsgDecodable>::decode(&buf[..]).unwrap().encode();
				assert_eq!(&$data[..], &encoded[..]);
			}
		}
	}
}

#[macro_export]
macro_rules! test_msg_writeable_hole {
	($MsgType: path, $data: ident, $hole: expr, $hole_len: expr) => {
		{
			use lightning::ln::msgs::{MsgEncodable, MsgDecodable};
			use lightning::util::ser::{Writer, Reader, Writeable, Readable};
			let mut r = Reader::new(::std::io::Cursor::new($data));
			if let Ok(msg) = <$MsgType as Readable<::std::io::Cursor<&[u8]>>>::read(&mut r) {
				let mut w = Writer::new(::std::io::Cursor::new(vec![]));
				msg.write(&mut w).unwrap();
				let p = w.get_ref().position() as usize;

				let buf = w.into_inner().into_inner();
				eprintln!("buf({})", buf.len());
				assert_eq!(&r.get_ref().get_ref()[..$hole], &buf[..$hole]);
				assert_eq!(&r.get_ref().get_ref()[$hole+$hole_len..p], &buf[$hole+$hole_len..]);

				let encoded = <$MsgType as MsgDecodable>::decode(&buf[..]).unwrap().encode();
				assert_eq!(&$data[..$hole], &encoded[..$hole]);
				assert_eq!(&$data[$hole+$hole_len..p], &encoded[$hole+$hole_len..]);
			}
		}
	}
}
