# lightning-net-tor

Tor networking support for rust-lightning.

This crate provides the ability to connect to Lightning Network nodes over Tor, enabling enhanced privacy and the ability to reach nodes only accessible via .onion addresses.

## Features

- Connect to Lightning nodes over Tor
- Support for .onion addresses (v2 and v3)
- Compatible with rust-lightning's PeerManager
- Based on the arti-client Tor implementation

## Usage

```rust
use lightning_net_tor::{connect_outbound_tor, TorSocketDescriptor};
use lightning::ln::peer_handler::PeerManager;

// Create your PeerManager with TorSocketDescriptor
let peer_manager: Arc<PeerManager<..., TorSocketDescriptor, ...>> = ...;

// Connect to a node over Tor
let their_node_id = ...; // PublicKey of the node you want to connect to
let onion_address = "abcdef1234567890.onion";
let port = 9735;

if let Some(connection_future) = connect_outbound_tor(
    peer_manager,
    their_node_id,
    onion_address,
    port,
).await {
    // Connection established, spawn the future to handle it
    tokio::spawn(connection_future);
}
```

## Comparison with lightning-net-tokio

`lightning-net-tor` provides similar functionality to `lightning-net-tokio` but with Tor support:

| Feature | lightning-net-tokio | lightning-net-tor |
|---------|-------------------|------------------|
| Direct TCP connections | ✓ | ✗ |
| Tor connections | ✗ | ✓ |
| .onion address support | ✗ | ✓ |
| Enhanced privacy | ✗ | ✓ |
| Connection overhead | Low | Higher (Tor circuits) |

## Security Considerations

- Tor connections have higher latency than direct TCP connections
- Circuit building can take several seconds
- Requires proper Tor configuration for production use
- The arti-client dependency tree is substantial

## Dependencies

This crate depends on:
- `arti-client`: Rust implementation of Tor
- `tor-rtcompat`: Runtime compatibility for Tor
- `tokio`: Async runtime
- `lightning`: Core Lightning functionality

## License

Licensed under either of:
- Apache License, Version 2.0 ([LICENSE-APACHE](../LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](../LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
