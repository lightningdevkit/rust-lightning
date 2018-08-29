#![macro_use]

#[macro_export]
macro_rules! test_msg {
	($MsgType: path, $data: ident) => {
		{
			if let Ok(msg) = <$MsgType as MsgDecodable>::decode($data){
				let enc = msg.encode();
				assert_eq!(&$data[..enc.len()], &enc[..]);
			}
		}
	}
}

#[macro_export]
macro_rules! test_msg_exact {
	($MsgType: path, $data: ident) => {
		{
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
			if let Ok(msg) = <$MsgType as MsgDecodable>::decode($data){
				let enc = msg.encode();
				assert_eq!(&$data[..$hole], &enc[..$hole]);
				assert_eq!(&$data[$hole + $hole_len..enc.len()], &enc[$hole + $hole_len..]);
			}
		}
	}
}
