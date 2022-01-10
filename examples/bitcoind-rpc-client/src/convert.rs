use std::convert::TryInto;

use bitcoin::{BlockHash, hashes::hex::FromHex};
use lightning_block_sync::http::JsonResponse;

// TryInto implementation specifies the conversion logic from json response to BlockchainInfo object.
pub struct BlockchainInfoResponse {
    pub latest_height: usize,
    pub latest_blockhash: BlockHash,
    pub chain: String,
}

impl TryInto<BlockchainInfoResponse> for JsonResponse {
    type Error = std::io::Error;
    fn try_into(self) -> std::io::Result<BlockchainInfoResponse> {
        Ok(BlockchainInfoResponse { 
            latest_height: self.0["blocks"].as_u64().unwrap() as usize,
			latest_blockhash: BlockHash::from_hex(self.0["bestblockhash"].as_str().unwrap())
				.unwrap(),
			chain: self.0["chain"].as_str().unwrap().to_string(),
        })
    }
}

pub struct CreateWalletResponse {
    pub name: String,
    pub warning: String,
}

impl TryInto<CreateWalletResponse> for JsonResponse {
    type Error = std::io::Error;
    fn try_into(self) -> std::io::Result<CreateWalletResponse> {
        Ok(CreateWalletResponse {
            name: self.0["name"].as_str().unwrap().to_string(),
            warning: self.0["warning"].as_str().unwrap().to_string(),
        })
    }
}
pub struct GetBalanceResponse(pub usize);

impl TryInto<GetBalanceResponse> for JsonResponse {
    type Error = std::io::Error;
    fn try_into(self) -> std::io::Result<GetBalanceResponse> {
        Ok(GetBalanceResponse(self.0.as_f64().unwrap() as usize))
    }
}

pub struct GenerateToAddressResponse(pub Vec<BlockHash>);

impl TryInto<GenerateToAddressResponse> for JsonResponse {
    type Error = std::io::Error;
    fn try_into(self) -> std::io::Result<GenerateToAddressResponse> {
        let mut x: Vec<BlockHash> = Vec::new();

        for item in self.0.as_array().unwrap() {
            x.push(BlockHash::from_hex(item.as_str().unwrap())
            .unwrap());
        }

        Ok(GenerateToAddressResponse(x))
    }
}


pub struct NewAddressResponse(pub String); 

impl TryInto<NewAddressResponse> for JsonResponse {
    type Error = std::io::Error;
    fn try_into(self) -> std::io::Result<NewAddressResponse> {
        Ok(NewAddressResponse(self.0.as_str().unwrap().to_string()))
    }
}









