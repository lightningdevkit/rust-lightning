#!/bin/bash
set -eox pipefail

RUSTC_MINOR_VERSION=$(rustc --version | awk '{ split($2,a,"."); print a[2] }')
HOST_PLATFORM="$(rustc --version --verbose | grep "host:" | awk '{ print $2 }')"

# Tokio MSRV on versions 1.17 through 1.26 is rustc 1.49. Above 1.26 MSRV is 1.56.
[ "$RUSTC_MINOR_VERSION" -lt 49 ] && cargo update -p tokio --precise "1.14.0" --verbose
[[ "$RUSTC_MINOR_VERSION" -gt 48  &&  "$RUSTC_MINOR_VERSION" -lt 56 ]] && cargo update -p tokio --precise "1.26.0" --verbose
[ "$LDK_COVERAGE_BUILD" != "" ] && export RUSTFLAGS="-C link-dead-code"

export RUST_BACKTRACE=1

echo -e "\n\nBuilding and testing all workspace crates..."
cargo build --verbose --color always
cargo test --verbose --color always

echo -e "\n\nBuilding with all Log-Limiting features"
pushd lightning
grep '^max_level_' Cargo.toml | awk '{ print $1 }'| while read -r FEATURE; do
	cargo build --verbose --color always --features "$FEATURE"
done
popd

if [ "$RUSTC_MINOR_VERSION" -gt 51 ]; then # Current `object` MSRV, subject to change
	echo -e "\n\nTest backtrace-debug builds"
	pushd lightning
	cargo test --verbose --color always --features backtrace
	popd
fi

echo -e "\n\nTesting no-std flags in various combinations"
for DIR in lightning lightning-invoice lightning-rapid-gossip-sync; do
	pushd $DIR
	cargo test --verbose --color always --no-default-features --features no-std
	# check if there is a conflict between no-std and the default std feature
	cargo test --verbose --color always --features no-std
	# check that things still pass without grind_signatures
	# note that outbound_commitment_test only runs in this mode, because of hardcoded signature values
	cargo test --verbose --color always --no-default-features --features std
	# check if there is a conflict between no-std and the c_bindings cfg
	RUSTFLAGS="--cfg=c_bindings" cargo test --verbose --color always --no-default-features --features=no-std
	popd
done

echo -e "\n\nTesting no-std build on a downstream no-std crate"
# check no-std compatibility across dependencies
pushd no-std-check
cargo check --verbose --color always --features lightning-transaction-sync
popd

if [ -f "$(which arm-none-eabi-gcc)" ]; then
	pushd no-std-check
	cargo build --target=thumbv7m-none-eabi
	popd
fi

echo -e "\n\nBuilding and testing Block Sync Clients with features"
pushd lightning-block-sync
cargo build --verbose --color always --features rest-client
cargo test --verbose --color always --features rest-client
cargo build --verbose --color always --features rpc-client
cargo test --verbose --color always --features rpc-client
cargo build --verbose --color always --features rpc-client,rest-client
cargo test --verbose --color always --features rpc-client,rest-client
cargo build --verbose --color always --features rpc-client,rest-client,tokio
cargo test --verbose --color always --features rpc-client,rest-client,tokio
popd

if [[ $RUSTC_MINOR_VERSION -gt 67 && "$HOST_PLATFORM" != *windows* ]]; then
	echo -e "\n\nBuilding and testing Transaction Sync Clients with features"
	pushd lightning-transaction-sync
	cargo build --verbose --color always --features esplora-blocking
	cargo test --verbose --color always --features esplora-blocking
	cargo build --verbose --color always --features esplora-async
	cargo test --verbose --color always --features esplora-async
	cargo build --verbose --color always --features esplora-async-https
	cargo test --verbose --color always --features esplora-async-https
	popd
fi

echo -e "\n\nTest futures builds"
pushd lightning-background-processor
cargo test --verbose --color always --no-default-features --features futures
popd

if [ "$RUSTC_MINOR_VERSION" -gt 55 ]; then
	echo -e "\n\nTest Custom Message Macros"
	pushd lightning-custom-message
	cargo test --verbose --color always
	popd
fi

echo -e "\n\nTest anchors builds"
pushd lightning
RUSTFLAGS="$RUSTFLAGS --cfg=anchors" cargo test --verbose --color always -p lightning
echo -e "\n\nTest Taproot builds"
RUSTFLAGS="$RUSTFLAGS --cfg=anchors --cfg=taproot" cargo test --verbose --color always -p lightning
popd
