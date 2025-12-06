#!/bin/bash
#shellcheck disable=SC2002,SC2207
set -eox pipefail

# Currently unused as we don't have to pin anything for MSRV:
RUSTC_MINOR_VERSION=$(rustc --version | awk '{ split($2,a,"."); print a[2] }')

# Some crates require pinning to meet our MSRV even for our downstream users,
# which we do here.
# Further crates which appear only as dev-dependencies are pinned further down.
function PIN_RELEASE_DEPS {
	return 0 # Don't fail the script if our rustc is higher than the last check
}

PIN_RELEASE_DEPS # pin the release dependencies in our main workspace

# The backtrace v0.3.75 crate relies on rustc 1.82
[ "$RUSTC_MINOR_VERSION" -lt 82 ] && cargo update -p backtrace --precise "0.3.74" --verbose

# proptest 1.9.0 requires rustc 1.82.0
[ "$RUSTC_MINOR_VERSION" -lt 82 ] && cargo update -p proptest --precise "1.8.0" --verbose

export RUST_BACKTRACE=1

echo -e "\n\nChecking the workspace, except lightning-transaction-sync."
cargo check --verbose --color always

WORKSPACE_MEMBERS=( $(cat Cargo.toml | tr '\n' '\r' | sed 's/\r    //g' | tr '\r' '\n' | grep '^members =' | sed 's/members.*=.*\[//' | tr -d '"' | tr ',' ' ') )

echo -e "\n\nTesting the workspace, except lightning-transaction-sync."
cargo test --verbose --color always

echo -e "\n\nTesting upgrade from prior versions of LDK"
pushd lightning-tests
cargo test
popd

echo -e "\n\nChecking and building docs for all workspace members individually..."
for DIR in "${WORKSPACE_MEMBERS[@]}"; do
	cargo check -p "$DIR" --verbose --color always
	cargo doc -p "$DIR" --document-private-items
done

echo -e "\n\nChecking and testing lightning with features"
cargo test -p lightning --verbose --color always --features dnssec
cargo check -p lightning --verbose --color always --features dnssec
cargo doc -p lightning --document-private-items --features dnssec

echo -e "\n\nChecking and testing lightning with safe_channels"
cargo test -p lightning --verbose --color always --features safe_channels
cargo check -p lightning --verbose --color always --features safe_channels
cargo doc -p lightning --document-private-items --features safe_channels

echo -e "\n\nChecking and testing Block Sync Clients with features"

cargo test -p lightning-block-sync --verbose --color always --features rest-client
cargo check -p lightning-block-sync --verbose --color always --features rest-client
cargo test -p lightning-block-sync --verbose --color always --features rpc-client
cargo check -p lightning-block-sync --verbose --color always --features rpc-client
cargo test -p lightning-block-sync --verbose --color always --features rpc-client,rest-client
cargo check -p lightning-block-sync --verbose --color always --features rpc-client,rest-client
cargo test -p lightning-block-sync --verbose --color always --features rpc-client,rest-client,tokio
cargo check -p lightning-block-sync --verbose --color always --features rpc-client,rest-client,tokio

echo -e "\n\nChecking and testing lightning-persister with features"
cargo test -p lightning-persister --verbose --color always --features tokio
cargo check -p lightning-persister --verbose --color always --features tokio
cargo doc -p lightning-persister --document-private-items --features tokio

echo -e "\n\nTest Custom Message Macros"
cargo test -p lightning-custom-message --verbose --color always
[ "$CI_MINIMIZE_DISK_USAGE" != "" ] && cargo clean

echo -e "\n\nTest backtrace-debug builds"
cargo test -p lightning --verbose --color always --features backtrace

echo -e "\n\nTesting no_std builds"
for DIR in lightning-invoice lightning-rapid-gossip-sync lightning-liquidity; do
	cargo test -p $DIR --verbose --color always --no-default-features
done

cargo test -p lightning --verbose --color always --no-default-features
cargo test -p lightning-background-processor --verbose --color always --no-default-features

echo -e "\n\nTesting c_bindings builds"
# Note that because `$RUSTFLAGS` is not passed through to doctest builds we cannot selectively
# disable doctests in `c_bindings` so we skip doctests entirely here.
RUSTFLAGS="$RUSTFLAGS --cfg=c_bindings" cargo test --verbose --color always --lib --bins --tests

for DIR in lightning-invoice lightning-rapid-gossip-sync; do
	# check if there is a conflict between no_std and the c_bindings cfg
	RUSTFLAGS="$RUSTFLAGS --cfg=c_bindings" cargo test -p $DIR --verbose --color always --no-default-features
done

# Note that because `$RUSTFLAGS` is not passed through to doctest builds we cannot selectively
# disable doctests in `c_bindings` so we skip doctests entirely here.
RUSTFLAGS="$RUSTFLAGS --cfg=c_bindings" cargo test -p lightning-background-processor --verbose --color always --no-default-features --lib --bins --tests
RUSTFLAGS="$RUSTFLAGS --cfg=c_bindings" cargo test -p lightning --verbose --color always --no-default-features --lib --bins --tests

echo -e "\n\nTesting other crate-specific builds"
# Note that outbound_commitment_test only runs in this mode because of hardcoded signature values
RUSTFLAGS="$RUSTFLAGS --cfg=ldk_test_vectors" cargo test -p lightning --verbose --color always --no-default-features --features=std
# This one only works for lightning-invoice
# check that compile with no_std and serde works in lightning-invoice
cargo test -p lightning-invoice --verbose --color always --no-default-features --features serde

echo -e "\n\nTesting no_std build on a downstream no-std crate"
# check no-std compatibility across dependencies
pushd no-std-check
cargo check --verbose --color always
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

echo -e "\n\nTest cfg-flag builds"
RUSTFLAGS="--cfg=taproot" cargo test --verbose --color always -p lightning
[ "$CI_MINIMIZE_DISK_USAGE" != "" ] && cargo clean
RUSTFLAGS="--cfg=simple_close" cargo test --verbose --color always -p lightning
[ "$CI_MINIMIZE_DISK_USAGE" != "" ] && cargo clean
RUSTFLAGS="--cfg=lsps1_service" cargo test --verbose --color always -p lightning-liquidity
[ "$CI_MINIMIZE_DISK_USAGE" != "" ] && cargo clean
RUSTFLAGS="--cfg=peer_storage" cargo test --verbose --color always -p lightning
