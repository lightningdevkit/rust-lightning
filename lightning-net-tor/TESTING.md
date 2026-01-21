# Testing Guide for lightning-net-tor

This guide provides step-by-step instructions for testing the Tor networking functionality.

## Prerequisites

### 1. Install Tor Daemon

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install tor
sudo systemctl start tor
sudo systemctl enable tor
```

**macOS:**
```bash
brew install tor
brew services start tor
```

**Arch Linux:**
```bash
sudo pacman -S tor
sudo systemctl start tor
sudo systemctl enable tor
```

### 2. Verify Tor is Running

```bash
# Check Tor service status
sudo systemctl status tor

# Check if Tor SOCKS proxy is listening
netstat -tlnp | grep 9050
# Or
ss -tlnp | grep 9050

# Test with curl
curl --socks5-hostname localhost:9050 https://check.torproject.org
```

Expected output should indicate you're using Tor.

## Running the Tests

### Quick Test Suite

```bash
cd lightning-net-tor

# Run basic tests (no Tor required)
cargo test

# Check Tor daemon status
cargo test check_tor_daemon -- --nocapture

# Run all tests including Tor integration tests
cargo test --ignored -- --nocapture
```

### Individual Test Scenarios

#### Test 1: Tor Client Initialization
Tests that we can create and initialize a Tor client.

```bash
cargo test test_tor_client_initialization --ignored -- --nocapture
```

**Expected Output:**
```
✓ Successfully created Tor client
✓ Successfully bootstrapped to Tor network
```

**Troubleshooting:**
- If fails: Ensure Tor daemon is running (`sudo systemctl start tor`)
- Check logs: `sudo journalctl -u tor -f`

#### Test 2: Tor Connectivity Test
Tests actual connection to a known onion service (DuckDuckGo).

```bash
cargo test test_tor_connectivity_to_known_onion --ignored -- --nocapture
```

**Expected Output:**
```
Testing Tor connectivity to duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion:80
Connecting via Tor...
✓ Successfully connected to duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion via Tor!
  Stream created, connection is working
```

**Note:** First connection may take 30-60 seconds as Tor builds circuits.

#### Test 3: TorSocketDescriptor Integration
Tests that TorSocketDescriptor works with Lightning's PeerManager.

```bash
cargo test test_tor_socket_descriptor_basic -- --nocapture
```

**Expected Output:**
```
✓ TorSocketDescriptor works with PeerManager
```

## Manual End-to-End Testing

### Test with a Real Lightning Node

#### Step 1: Set Up Test Environment

Create a test file `examples/connect_to_node.rs`:

```rust
use lightning_net_tor::{connect_outbound_tor, TorSocketDescriptor};
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use lightning::ln::peer_handler::{
    IgnoringMessageHandler, MessageHandler, PeerManager, ErroringMessageHandler,
};
use lightning::util::test_utils::TestNodeSigner;
use std::sync::Arc;
use std::str::FromStr;

struct TestLogger;
impl lightning::util::logger::Logger for TestLogger {
    fn log(&self, record: lightning::util::logger::Record) {
        println!("[{}] {}", record.level, record.args);
    }
}

#[tokio::main]
async fn main() {
    // Your node's key
    let our_key = SecretKey::from_slice(&[1; 32]).unwrap();
    
    // Create PeerManager
    let msg_handler = MessageHandler {
        chan_handler: Arc::new(ErroringMessageHandler::new()),
        route_handler: Arc::new(IgnoringMessageHandler {}),
        onion_message_handler: Arc::new(IgnoringMessageHandler {}),
        custom_message_handler: Arc::new(IgnoringMessageHandler {}),
        send_only_message_handler: Arc::new(IgnoringMessageHandler {}),
    };
    
    let peer_manager = Arc::new(PeerManager::<
        _, TorSocketDescriptor, _, _
    >::new(
        msg_handler,
        0,
        &[1; 32],
        Arc::new(TestLogger),
        Arc::new(TestNodeSigner::new(our_key)),
    ));
    
    // Target node's public key and onion address
    // Replace with a real Lightning node's info
    let target_pubkey_hex = "02..."; // Replace with real pubkey
    let target_onion = "abcdef1234567890.onion"; // Replace with real onion
    let target_port = 9735;
    
    let target_pubkey = PublicKey::from_str(target_pubkey_hex)
        .expect("Invalid pubkey");
    
    println!("Connecting to {}:{} via Tor...", target_onion, target_port);
    
    match connect_outbound_tor(
        peer_manager.clone(),
        target_pubkey,
        target_onion,
        target_port,
    ).await {
        Some(connection_future) => {
            println!("✓ Connection established!");
            println!("Spawning connection handler...");
            
            let handle = tokio::spawn(connection_future);
            
            // Keep connection alive for testing
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            
            println!("Test complete");
        },
        None => {
            println!("✗ Failed to establish connection");
        }
    }
}
```

#### Step 2: Run the Example

```bash
cd lightning-net-tor
cargo run --example connect_to_node
```

### Finding Test Lightning Nodes

To find Lightning nodes with Tor onion addresses for testing:

1. **1ML.com**: https://1ml.com
   - Filter for nodes with Tor addresses
   - Look for "Tor" badge

2. **Amboss.space**: https://amboss.space
   - Search for nodes
   - Check node details for onion addresses

3. **Use a Known Public Node**:
   - ACINQ: Has public Tor address
   - ln.nicehash.com: Often accessible via Tor

## Verification Checklist

### Basic Functionality
- [ ] Code compiles: `cargo build`
- [ ] Unit tests pass: `cargo test`
- [ ] Tor daemon is running: `systemctl status tor`
- [ ] Tor SOCKS proxy is accessible: `netstat -tlnp | grep 9050`

### Tor Integration
- [ ] Tor client initializes: `cargo test test_tor_client_initialization --ignored`
- [ ] Can connect to .onion address: `cargo test test_tor_connectivity_to_known_onion --ignored`
- [ ] TorSocketDescriptor compiles with PeerManager

### Lightning Integration
- [ ] Can create PeerManager with TorSocketDescriptor
- [ ] Can call connect_outbound_tor()
- [ ] Connection future is returned and can be spawned

### End-to-End (Optional)
- [ ] Successfully connect to a real Lightning node over Tor
- [ ] Can send/receive Lightning messages
- [ ] Connection stays stable

## Troubleshooting

### Tor Connection Fails

**Problem:** `Failed to create Tor client`

**Solutions:**
1. Check Tor is running: `sudo systemctl status tor`
2. Check Tor logs: `sudo journalctl -u tor -n 50`
3. Restart Tor: `sudo systemctl restart tor`
4. Check firewall isn't blocking Tor

### Bootstrap Timeout

**Problem:** `Bootstrap timeout`

**Solutions:**
1. Tor may be blocked by firewall
2. Try with Tor Browser Bundle (uses port 9150)
3. Check internet connectivity
4. May need to configure bridges if Tor is blocked in your region

### Connection Timeout to .onion

**Problem:** Connection to .onion address times out

**Solutions:**
1. .onion address may be offline
2. Try a known-good onion like DuckDuckGo
3. Increase timeout duration
4. Check Tor circuit is established: `tor-ctrl -p 9051`

### Compilation Errors

**Problem:** `cannot find -lsqlite3`

**Solution:**
```bash
# Ubuntu/Debian
sudo apt install libsqlite3-dev

# macOS
brew install sqlite3

# Arch
sudo pacman -S sqlite
```

## Performance Notes

- **First connection**: 30-60 seconds (Tor circuit building)
- **Subsequent connections**: 5-10 seconds
- **Keep-alive**: Circuits are reused for ~10 minutes
- **Latency**: Expect 2-5x higher latency than direct TCP

## Security Considerations

- Always verify .onion addresses from trusted sources
- Be aware of timing attacks
- Don't mix Tor and clearnet connections for the same node
- Use proper operational security practices

## CI/CD Integration

For automated testing in CI:

```yaml
# Example GitHub Actions workflow
- name: Install Tor
  run: |
    sudo apt-get update
    sudo apt-get install -y tor
    sudo systemctl start tor
    sleep 5  # Wait for Tor to start

- name: Run Tor Integration Tests
  run: |
    cd lightning-net-tor
    cargo test --ignored -- --test-threads=1
  timeout-minutes: 10
```

## Getting Help

If tests fail and you can't resolve the issue:

1. Check this guide's troubleshooting section
2. Verify Tor daemon logs: `sudo journalctl -u tor -f`
3. Test Tor independently: `curl --socks5-hostname localhost:9050 https://check.torproject.org`
4. File an issue with:
   - Test output
   - Tor version: `tor --version`
   - OS and version
   - Tor daemon logs
