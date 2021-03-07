use bitcoin::network::constants::Network as BitcoinNetwork;

#[repr(C)]
pub enum Network {
	Bitcoin,
	Testnet,
	Regtest,
	Signet,
}

impl Network {
	pub(crate) fn into_bitcoin(&self) -> BitcoinNetwork {
		match self {
			Network::Bitcoin => BitcoinNetwork::Bitcoin,
			Network::Testnet => BitcoinNetwork::Testnet,
			Network::Regtest => BitcoinNetwork::Regtest,
			Network::Signet => BitcoinNetwork::Signet,
		}
	}
	pub(crate) fn from_bitcoin(net: BitcoinNetwork) -> Self {
		match net {
			BitcoinNetwork::Bitcoin => Network::Bitcoin,
			BitcoinNetwork::Testnet => Network::Testnet,
			BitcoinNetwork::Regtest => Network::Regtest,
			BitcoinNetwork::Signet => Network::Signet,
		}
	}
}
