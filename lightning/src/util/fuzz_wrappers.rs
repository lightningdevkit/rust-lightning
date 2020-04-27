macro_rules! hash_to_message {
	($slice: expr) => {
		{
			#[cfg(not(feature = "fuzztarget"))]
			{
				::bitcoin::secp256k1::Message::from_slice($slice).unwrap()
			}
			#[cfg(feature = "fuzztarget")]
			{
				match ::bitcoin::secp256k1::Message::from_slice($slice) {
					Ok(msg) => msg,
					Err(_) => ::bitcoin::secp256k1::Message::from_slice(&[1; 32]).unwrap()
				}
			}
		}
	}
}
