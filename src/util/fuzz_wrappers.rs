macro_rules! hash_to_message {
	($slice: expr) => {
		{
			#[cfg(not(feature = "fuzztarget"))]
			{
				::secp256k1::Message::from_slice($slice).unwrap()
			}
			#[cfg(feature = "fuzztarget")]
			{
				match ::secp256k1::Message::from_slice($slice) {
					Ok(msg) => msg,
					Err(_) => ::secp256k1::Message::from_slice(&[1; 32]).unwrap()
				}
			}
		}
	}
}
