use std::{sync::{Arc}, io};

use lightning_block_sync::{rpc::RpcClient, http::{HttpEndpoint}};
use serde_json::json;
use tokio::sync::Mutex;

use crate::convert::{CreateWalletResponse, BlockchainInfoResponse, NewAddressResponse, GetBalanceResponse, GenerateToAddressResponse};


pub struct BitcoindClient {
    bitcoind_rpc_client: Arc<Mutex<RpcClient>>,
    host: String,
    port: u16,
    rpc_user: String,
    rpc_password: String,
}

impl BitcoindClient {
    pub async fn new(host: String, port: u16, rpc_user: String, rpc_password: String) -> io::Result<Self> {
        let http_endpoint = HttpEndpoint::for_host(host.clone()).with_port(port);
        let rpc_creditials = 
            base64::encode(format!("{}:{}", rpc_user.clone(), rpc_password.clone()));
        let mut bitcoind_rpc_client = RpcClient::new(&rpc_creditials, http_endpoint)?;
        bitcoind_rpc_client
			.call_method::<BlockchainInfoResponse>("getblockchaininfo", &vec![])
			.await
			.map_err(|_| {
				io::Error::new(io::ErrorKind::PermissionDenied,
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

    pub fn get_new_rpc_client(&self) -> io::Result<RpcClient> {
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
        let create_wallet_args = vec![json!("test-wallet")];

        rpc.call_method::<CreateWalletResponse>("createwallet", &create_wallet_args).await.unwrap()
    }

    pub async fn get_new_address(&self) -> String {
		let mut rpc = self.bitcoind_rpc_client.lock().await;

		let addr_args = vec![json!("LDK output address")];
		let addr = rpc.call_method::<NewAddressResponse>("getnewaddress", &addr_args).await.unwrap();
		addr.0.to_string()
	}

    pub async fn get_balance(&self) -> GetBalanceResponse {
        let mut rpc = self.bitcoind_rpc_client.lock().await;
        
        rpc.call_method::<GetBalanceResponse>("getbalance", &vec![]).await.unwrap()
    }

    pub async fn generate_to_address(&self, block_num: u64, address: &str) -> GenerateToAddressResponse {
		let mut rpc = self.bitcoind_rpc_client.lock().await;

		let generate_to_address_args = vec![json!(block_num), json!(address)];


		rpc.call_method::<GenerateToAddressResponse>("generatetoaddress", &generate_to_address_args).await.unwrap()
	}
}