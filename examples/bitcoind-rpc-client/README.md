# Creates a basic bitcoind client

This is example shows how you could create a client that directly communicates with bitcoind from LDK. The API is flexible and allows for different ways to implement the interface.

It implements some basic RPC methods that allow you to create a core wallet and print it's balance to stdout.

To run with this example you need to have a bitcoin core node running in regtest mode. Get the bitcoin core binary either from the [bitcoin core repo](https://bitcoincore.org/bin/bitcoin-core-0.22.0/) or [build from source](https://github.com/bitcoin/bitcoin/blob/v0.21.1/doc/build-unix.md).

Then configure the node with the following `bitcoin.conf`

```
regtest=1
fallbackfee=0.0001
server=1
txindex=1
rpcuser=admin
rpcpassword=password
```

## How to use 

```
Cargo run
```

## Notes

`RpcClient` is a simple RPC client for calling methods using HTTP POST. It is implemented in [rust-lightning/lightning-block-sync/rpc.rs](https://github.com/lightningdevkit/rust-lightning/blob/61341df39e90de9d650851a624c0644f5c9dd055/lightning-block-sync/src/rpc.rs)

The purpose of `RpcClient` is to create a new RPC client connected to the given endpoint with the provided credentials. The credentials should be a base64 encoding of a user name and password joined by a colon, as is required for HTTP basic access authentication.

It implements [BlockSource](https://github.com/rust-bitcoin/rust-lightning/blob/61341df39e90de9d650851a624c0644f5c9dd055/lightning-block-sync/src/lib.rs#L55) against a Bitcoin Core RPC. It is an asynchronous interface for retrieving block headers and data.

Check out our [LDK sample node](https://github.com/lightningdevkit/ldk-sample) for an integrated example.



