#!/bin/bash
set -eox pipefail

RUSTC_MINOR_VERSION=$(rustc --version | awk '{ split($2,a,"."); print a[2] }')
HOST_PLATFORM="$(rustc --version --verbose | grep "host:" | awk '{ print $2 }')"

# Some crates require pinning to meet our MSRV even for our downstream users,
# which we do here.
# Further crates which appear only as dev-dependencies are pinned further down.
function PIN_RELEASE_DEPS {
	return 0 # Don't fail the script if our rustc is higher than the last check
}

PIN_RELEASE_DEPS # pin the release dependencies in our main workspace

# Starting with version 1.10.0, the `regex` crate has an MSRV of rustc 1.65.0.
[ "$RUSTC_MINOR_VERSION" -lt 65 ] && cargo update -p regex --precise "1.9.6" --verbose

# The addr2line v0.21 crate (a dependency of `backtrace` starting with 0.3.69) relies on rustc 1.65
[ "$RUSTC_MINOR_VERSION" -lt 65 ] && cargo update -p backtrace --precise "0.3.68" --verbose

export RUST_BACKTRACE=1

echo -e "\n\nBuilding and testing all workspace crates..."
cargo test --verbose --color always
cargo check --verbose --color always

echo -e "\n\nBuilding and testing Block Sync Clients with features"
pushd lightning-block-sync
cargo test --verbose --color always --features rest-client
cargo check --verbose --color always --features rest-client
cargo test --verbose --color always --features rpc-client
cargo check --verbose --color always --features rpc-client
cargo test --verbose --color always --features rpc-client,rest-client
cargo check --verbose --color always --features rpc-client,rest-client
cargo test --verbose --color always --features rpc-client,rest-client,tokio
cargo check --verbose --color always --features rpc-client,rest-client,tokio
popd

if [[ "$HOST_PLATFORM" != *windows* ]]; then
	echo -e "\n\nBuilding and testing Transaction Sync Clients with features"
	pushd lightning-transaction-sync

	# zstd-sys 2.0.9+zstd.1.5.5 requires rustc 1.64.0
	[ "$RUSTC_MINOR_VERSION" -lt 64 ] && cargo update -p zstd-sys --precise "2.0.8+zstd.1.5.5" --verbose
	# reqwest 0.11.21 had a regression that broke its 1.63.0 MSRV
	[ "$RUSTC_MINOR_VERSION" -lt 65 ] && cargo update -p reqwest --precise "0.11.20" --verbose
	# jobserver 0.1.27 requires rustc 1.66.0
	[ "$RUSTC_MINOR_VERSION" -lt 66 ] && cargo update -p jobserver --precise "0.1.26" --verbose
	# Starting with version 1.10.0, the `regex` crate has an MSRV of rustc 1.65.0.
	[ "$RUSTC_MINOR_VERSION" -lt 65 ] && cargo update -p regex --precise "1.9.6" --verbose

	cargo test --verbose --color always --features esplora-blocking
	cargo check --verbose --color always --features esplora-blocking
	cargo test --verbose --color always --features esplora-async
	cargo check --verbose --color always --features esplora-async
	cargo test --verbose --color always --features esplora-async-https
	cargo check --verbose --color always --features esplora-async-https
	cargo test --verbose --color always --features electrum
	cargo check --verbose --color always --features electrum

	popd
fi

echo -e "\n\nTest futures builds"
pushd lightning-background-processor
cargo test --verbose --color always --features futures
popd

echo -e "\n\nTest Custom Message Macros"
pushd lightning-custom-message
cargo test --verbose --color always
[ "$CI_MINIMIZE_DISK_USAGE" != "" ] && cargo clean
popd

echo -e "\n\nTest backtrace-debug builds"
pushd lightning
cargo test --verbose --color always --features backtrace
popd

echo -e "\n\nBuilding with all Log-Limiting features"
pushd lightning
grep '^max_level_' Cargo.toml | awk '{ print $1 }'| while read -r FEATURE; do
	cargo check --verbose --color always --features "$FEATURE"
done
popd

echo -e "\n\nTesting no-std flags in various combinations"
for DIR in lightning lightning-invoice lightning-rapid-gossip-sync; do
	cargo test -p $DIR --verbose --color always --no-default-features --features no-std
	# check if there is a conflict between no-std and the default std feature
	cargo test -p $DIR --verbose --color always --features no-std
done

for DIR in lightning lightning-invoice lightning-rapid-gossip-sync; do
	# check if there is a conflict between no-std and the c_bindings cfg
	RUSTFLAGS="--cfg=c_bindings" cargo test -p $DIR --verbose --color always --no-default-features --features=no-std
done
RUSTFLAGS="--cfg=c_bindings" cargo test --verbose --color always

# Note that outbound_commitment_test only runs in this mode because of hardcoded signature values
pushd lightning
cargo test --verbose --color always --no-default-features --features=std,_test_vectors
popd
# This one only works for lightning-invoice
pushd lightning-invoice
# check that compile with no-std and serde works in lightning-invoice
cargo test --verbose --color always --no-default-features --features no-std --features serde
popd

echo -e "\n\nTesting no-std build on a downstream no-std crate"
# check no-std compatibility across dependencies
pushd no-std-check
cargo check --verbose --color always --features lightning-transaction-sync
[ "$CI_MINIMIZE_DISK_USAGE" != "" ] && cargo clean
popd

# Test that we can build downstream code with only the "release pins".
pushd msrv-no-dev-deps-check
PIN_RELEASE_DEPS
cargo check
[ "$CI_MINIMIZE_DISK_USAGE" != "" ] && cargo clean
popd

if [ -f "$(which arm-none-eabi-gcc)" ]; then
	pushd no-std-check
	cargo build --target=thumbv7m-none-eabi
	[ "$CI_MINIMIZE_DISK_USAGE" != "" ] && cargo clean
	popd
fi

echo -e "\n\nTest Taproot builds"
pushd lightning
RUSTFLAGS="$RUSTFLAGS --cfg=taproot" cargo test --verbose --color always -p lightning
popd
