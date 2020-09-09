use bitcoin::network::constants::Network as BitcoinNetwork;

#[repr(C)]
pub enum Network {
	Bitcoin,
	Testnet,
	Regtest,
}

impl Network {
	pub(crate) fn into_bitcoin(&self) -> BitcoinNetwork {
		match self {
			Network::Bitcoin => BitcoinNetwork::Bitcoin,
			Network::Testnet => BitcoinNetwork::Testnet,
			Network::Regtest => BitcoinNetwork::Regtest,
		}
	}
}
