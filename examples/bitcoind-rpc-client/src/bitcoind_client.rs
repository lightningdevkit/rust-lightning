use std::{sync::{Arc}};

use bitcoin::{BlockHash, Block};
use lightning_block_sync::{rpc::RpcClient, http::{HttpEndpoint}, BlockSource, AsyncBlockSourceResult, BlockHeaderData};
use tokio::sync::Mutex;

use crate::convert::{CreateWalletResponse, BlockchainInfoResponse, NewAddressResponse, GetBalanceResponse, GenerateToAddressResponse};


pub struct BitcoindClient {
    bitcoind_rpc_client: Arc<Mutex<RpcClient>>,
    host: String,
    port: u16,
    rpc_user: String,
    rpc_password: String,
}

impl BlockSource for &BitcoindClient {
	fn get_header<'a>(
		&'a mut self, header_hash: &'a BlockHash, height_hint: Option<u32>,
	) -> AsyncBlockSourceResult<'a, BlockHeaderData> {
		Box::pin(async move {
			let mut rpc = self.bitcoind_rpc_client.lock().await;
			rpc.get_header(header_hash, height_hint).await
		})
	}

	fn get_block<'a>(
		&'a mut self, header_hash: &'a BlockHash,
	) -> AsyncBlockSourceResult<'a, Block> {
		Box::pin(async move {
			let mut rpc = self.bitcoind_rpc_client.lock().await;
			rpc.get_block(header_hash).await
		})
	}

	fn get_best_block<'a>(&'a mut self) -> AsyncBlockSourceResult<(BlockHash, Option<u32>)> {
		Box::pin(async move {
			let mut rpc = self.bitcoind_rpc_client.lock().await;
			rpc.get_best_block().await
		})
	}
}

impl BitcoindClient {
    pub async fn new(host: String, port: u16, rpc_user: String, rpc_password: String) -> std::io::Result<Self> {
        let http_endpoint = HttpEndpoint::for_host(host.clone()).with_port(port);
        let rpc_creditials = 
            base64::encode(format!("{}:{}", rpc_user.clone(), rpc_password.clone()));
        let mut bitcoind_rpc_client = RpcClient::new(&rpc_creditials, http_endpoint)?;
        let _dummy = bitcoind_rpc_client
			.call_method::<BlockchainInfoResponse>("getblockchaininfo", &vec![])
			.await
			.map_err(|_| {
				std::io::Error::new(std::io::ErrorKind::PermissionDenied,
				"Failed to make initial call to bitcoind - please check your RPC user/password and access settings")
			})?;

        let client = Self {
            bitcoind_rpc_client: Arc::new(Mutex::new(bitcoind_rpc_client)),
            host,
            port,
            rpc_user,
            rpc_password,
        };
       
        Ok(client)
    }

    pub fn get_new_rpc_client(&self) -> std::io::Result<RpcClient> {
		let http_endpoint = HttpEndpoint::for_host(self.host.clone()).with_port(self.port);
		let rpc_credentials =
			base64::encode(format!("{}:{}", self.rpc_user.clone(), self.rpc_password.clone()));
		RpcClient::new(&rpc_credentials, http_endpoint)
	}

    pub async fn get_blockchain_info(&self) -> BlockchainInfoResponse {
		let mut rpc = self.bitcoind_rpc_client.lock().await;
		rpc.call_method::<BlockchainInfoResponse>("getblockchaininfo", &vec![]).await.unwrap()
	}

    pub async fn create_wallet(&self) -> CreateWalletResponse {
        let mut rpc = self.bitcoind_rpc_client.lock().await;
        let create_wallet_args = vec![serde_json::json!("test-wallet")];

        rpc.call_method::<CreateWalletResponse>("createwallet", &create_wallet_args).await.unwrap()
    }

    pub async fn get_new_address(&self) -> String {
		let mut rpc = self.bitcoind_rpc_client.lock().await;

		let addr_args = vec![serde_json::json!("LDK output address")];
		let addr = rpc.call_method::<NewAddressResponse>("getnewaddress", &addr_args).await.unwrap();
		addr.0.to_string()
	}

    pub async fn get_balance(&self) -> GetBalanceResponse {
        let mut rpc = self.bitcoind_rpc_client.lock().await;
        
        rpc.call_method::<GetBalanceResponse>("getbalance", &vec![]).await.unwrap()
    }

    pub async fn generate_to_address(&self, block_num: u64, address: &str) -> GenerateToAddressResponse {
		let mut rpc = self.bitcoind_rpc_client.lock().await;

		let generate_to_address_args = vec![serde_json::json!(block_num), serde_json::json!(address)];


		rpc.call_method::<GenerateToAddressResponse>("generatetoaddress", &generate_to_address_args).await.unwrap()
	}
}







