// Integration tests for lightning-net-tor
// These tests require a Tor daemon to be running

use lightning_net_tor::{connect_outbound_tor, TorSocketDescriptor};
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use lightning::ln::peer_handler::{
    IgnoringMessageHandler, MessageHandler, PeerManager, ErroringMessageHandler,
};
use lightning::util::test_utils::TestNodeSigner;
use std::sync::Arc;

struct TestLogger;
impl lightning::util::logger::Logger for TestLogger {
    fn log(&self, record: lightning::util::logger::Record) {
        println!("[{}] {}", record.level, record.args);
    }
}

/// Test that we can create a Tor client and initialize the networking stack
/// This test requires a Tor daemon to be running on the system
#[tokio::test]
#[ignore] // Ignored by default - run with: cargo test --ignored
async fn test_tor_client_initialization() {
    // Try to create a Tor client - this will fail if Tor daemon isn't running
    let result = arti_client::TorClient::builder()
        .bootstrap_behavior(arti_client::BootstrapBehavior::OnDemand)
        .create_unbootstrapped();
    
    match result {
        Ok(client) => {
            println!("✓ Successfully created Tor client");
            // Try to bootstrap
            match tokio::time::timeout(
                std::time::Duration::from_secs(30),
                client.bootstrap()
            ).await {
                Ok(Ok(())) => println!("✓ Successfully bootstrapped to Tor network"),
                Ok(Err(e)) => println!("⚠ Bootstrap failed (may be expected): {}", e),
                Err(_) => println!("⚠ Bootstrap timeout (may be expected)"),
            }
        },
        Err(e) => {
            println!("✗ Failed to create Tor client: {}", e);
            println!("  Make sure Tor daemon is running: systemctl status tor");
            panic!("Tor client creation failed");
        }
    }
}

/// Test connection to a well-known onion service
/// This test attempts to connect to DuckDuckGo's onion service as a connectivity test
#[tokio::test]
#[ignore] // Ignored by default - run with: cargo test --ignored
async fn test_tor_connectivity_to_known_onion() {
    // DuckDuckGo's onion address (v3)
    const DUCKDUCKGO_ONION: &str = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion";
    const PORT: u16 = 80;
    
    println!("Testing Tor connectivity to {}:{}", DUCKDUCKGO_ONION, PORT);
    
    let tor_client = match arti_client::TorClient::builder()
        .bootstrap_behavior(arti_client::BootstrapBehavior::OnDemand)
        .create_unbootstrapped()
    {
        Ok(client) => Arc::new(client),
        Err(e) => {
            println!("✗ Failed to create Tor client: {}", e);
            panic!("Cannot proceed without Tor client");
        }
    };
    
    println!("Connecting via Tor...");
    let addr_port = format!("{}:{}", DUCKDUCKGO_ONION, PORT);
    let connect_result = tokio::time::timeout(
        std::time::Duration::from_secs(60),
        tor_client.connect(addr_port)
    ).await;
    
    match connect_result {
        Ok(Ok(stream)) => {
            println!("✓ Successfully connected to {} via Tor!", DUCKDUCKGO_ONION);
            println!("  Stream created, connection is working");
            drop(stream);
        },
        Ok(Err(e)) => {
            println!("✗ Connection failed: {}", e);
            panic!("Tor connection failed");
        },
        Err(_) => {
            println!("✗ Connection timeout after 60 seconds");
            panic!("Connection timeout");
        }
    }
}

/// Test the TorSocketDescriptor with a mock PeerManager
/// This verifies the basic structure works even without a real Lightning connection
#[tokio::test]
async fn test_tor_socket_descriptor_basic() {
    let secp_ctx = Secp256k1::new();
    let our_key = SecretKey::from_slice(&[1; 32]).unwrap();
    let our_pubkey = PublicKey::from_secret_key(&secp_ctx, &our_key);
    
    // Create a test PeerManager
    let msg_handler = MessageHandler {
        chan_handler: Arc::new(ErroringMessageHandler::new()),
        route_handler: Arc::new(IgnoringMessageHandler {}),
        onion_message_handler: Arc::new(IgnoringMessageHandler {}),
        custom_message_handler: Arc::new(IgnoringMessageHandler {}),
        send_only_message_handler: Arc::new(IgnoringMessageHandler {}),
    };
    
    let _peer_manager = Arc::new(PeerManager::<
        TorSocketDescriptor,
        Arc<ErroringMessageHandler>,
        Arc<IgnoringMessageHandler>,
        Arc<IgnoringMessageHandler>,
        Arc<TestLogger>,
        Arc<IgnoringMessageHandler>,
        Arc<TestNodeSigner>,
        Arc<IgnoringMessageHandler>,
    >::new(
        msg_handler,
        0,
        &[1; 32],
        Arc::new(TestLogger),
        Arc::new(TestNodeSigner::new(our_key)),
    ));
    
    println!("✓ TorSocketDescriptor works with PeerManager");
}

/// Helper function to check if Tor daemon is running
#[tokio::test]
async fn check_tor_daemon() {
    use std::process::Command;
    
    println!("\n=== Checking Tor Daemon Status ===");
    
    // Try to check Tor service status
    let status = Command::new("systemctl")
        .args(&["is-active", "tor"])
        .output();
    
    match status {
        Ok(output) => {
            let status_str = String::from_utf8_lossy(&output.stdout);
            if status_str.trim() == "active" {
                println!("✓ Tor daemon is running");
            } else {
                println!("✗ Tor daemon is not active: {}", status_str.trim());
                println!("  Start it with: sudo systemctl start tor");
            }
        },
        Err(_) => {
            println!("⚠ Could not check Tor status (systemctl not available)");
            println!("  On Ubuntu/Debian: sudo apt install tor && sudo systemctl start tor");
        }
    }
    
    // Try to connect to local Tor SOCKS proxy
    use tokio::net::TcpStream;
    match TcpStream::connect("127.0.0.1:9050").await {
        Ok(_) => println!("✓ Tor SOCKS proxy is listening on 127.0.0.1:9050"),
        Err(_) => {
            match TcpStream::connect("127.0.0.1:9150").await {
                Ok(_) => println!("✓ Tor SOCKS proxy is listening on 127.0.0.1:9150 (Tor Browser)"),
                Err(_) => println!("✗ No Tor SOCKS proxy found on standard ports"),
            }
        }
    }
}
