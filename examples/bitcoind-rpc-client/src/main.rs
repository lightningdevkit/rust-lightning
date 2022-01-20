pub mod bitcoind_client;

use std::{sync::Arc};

use crate::bitcoind_client::BitcoindClient;

mod convert;

#[tokio::main]
pub async fn main() {
    start_ldk().await;
}

async fn start_ldk() {
    // Initialize our bitcoind client
    let bitcoind_client = match BitcoindClient::new(
        String::from("127.0.0.1"),
        18443,
        String::from("admin"),
        String::from("password")
    )
    .await 
    {
        Ok(client) => {
            println!("Successfully connected to bitcoind client");
            Arc::new(client)
        },
        Err(e) => {
            println!("Failed to connect to bitcoind client: {}", e);
			return;
        }
    };

    // Check we connected to the expected network
    let bitcoind_blockchain_info = bitcoind_client.get_blockchain_info().await;
    println!("Chain network: {}", bitcoind_blockchain_info.chain);
    println!("Latest block height: {}", bitcoind_blockchain_info.latest_height);

    // Create a named bitcoin core wallet
    let bitcoind_wallet = bitcoind_client.create_wallet().await;
    println!("Successfully created wallet with name: {}", bitcoind_wallet.name);

    // Generate a new address 
    let bitcoind_new_address = bitcoind_client.get_new_address().await;
    println!("Address: {}", bitcoind_new_address);

    // Generate 101 blocks and use the above address as coinbase
    bitcoind_client.generate_to_address(101, &bitcoind_new_address).await;

    // Show balance
    let balance = bitcoind_client.get_balance().await;
    println!("Balance: {}", balance.0);
}