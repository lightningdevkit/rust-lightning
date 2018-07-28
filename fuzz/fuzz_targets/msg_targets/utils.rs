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
