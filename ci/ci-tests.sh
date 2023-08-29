#!/bin/bash
set -eox pipefail

RUSTC_MINOR_VERSION=$(rustc --version | awk '{ split($2,a,"."); print a[2] }')
HOST_PLATFORM="$(rustc --version --verbose | grep "host:" | awk '{ print $2 }')"

# Some crates require pinning to meet our MSRV even for our downstream users,
# which we do here.
# Further crates which appear only as dev-dependencies are pinned further down.
function PIN_RELEASE_DEPS {
	# Tokio MSRV on versions 1.17 through 1.26 is rustc 1.49. Above 1.26 MSRV is 1.56.
	[ "$RUSTC_MINOR_VERSION" -lt 49 ] && cargo update -p tokio --precise "1.14.1" --verbose
	[[ "$RUSTC_MINOR_VERSION" -gt 48  &&  "$RUSTC_MINOR_VERSION" -lt 56 ]] && cargo update -p tokio --precise "1.25.1" --verbose

	# Sadly the log crate is always a dependency of tokio until 1.20, and has no reasonable MSRV guarantees
	[ "$RUSTC_MINOR_VERSION" -lt 49 ] && cargo update -p log --precise "0.4.18" --verbose

	# The serde_json crate switched to Rust edition 2021 starting with v1.0.101, i.e., has MSRV of 1.56
	[ "$RUSTC_MINOR_VERSION" -lt 56 ] && cargo update -p serde_json --precise "1.0.100" --verbose

	return 0 # Don't fail the script if our rustc is higher than the last check
}

PIN_RELEASE_DEPS # pin the release dependencies in our main workspace

# The addr2line v0.20 crate (a dependency of `backtrace` starting with 0.3.68) relies on 1.55+
[ "$RUSTC_MINOR_VERSION" -lt 55 ] && cargo update -p backtrace --precise "0.3.67" --verbose

# The quote crate switched to Rust edition 2021 starting with v1.0.31, i.e., has MSRV of 1.56
[ "$RUSTC_MINOR_VERSION" -lt 56 ] && cargo update -p quote --precise "1.0.30" --verbose

# The proc-macro2 crate switched to Rust edition 2021 starting with v1.0.66, i.e., has MSRV of 1.56
[ "$RUSTC_MINOR_VERSION" -lt 56 ] && cargo update -p proc-macro2 --precise "1.0.65" --verbose

# The memchr crate switched to an MSRV of 1.60 starting with v2.6.0
[ "$RUSTC_MINOR_VERSION" -lt 60 ] && cargo update -p memchr --precise "2.5.0" --verbose

[ "$LDK_COVERAGE_BUILD" != "" ] && export RUSTFLAGS="-C link-dead-code"

export RUST_BACKTRACE=1

echo -e "\n\nBuilding and testing all workspace crates..."
cargo test --verbose --color always
cargo build --verbose --color always

echo -e "\n\nBuilding and testing Block Sync Clients with features"
pushd lightning-block-sync
cargo test --verbose --color always --features rest-client
cargo build --verbose --color always --features rest-client
cargo test --verbose --color always --features rpc-client
cargo build --verbose --color always --features rpc-client
cargo test --verbose --color always --features rpc-client,rest-client
cargo build --verbose --color always --features rpc-client,rest-client
cargo test --verbose --color always --features rpc-client,rest-client,tokio
cargo build --verbose --color always --features rpc-client,rest-client,tokio
popd

if [[ $RUSTC_MINOR_VERSION -gt 67 && "$HOST_PLATFORM" != *windows* ]]; then
	echo -e "\n\nBuilding and testing Transaction Sync Clients with features"
	pushd lightning-transaction-sync
	cargo test --verbose --color always --features esplora-blocking
	cargo build --verbose --color always --features esplora-blocking
	cargo test --verbose --color always --features esplora-async
	cargo build --verbose --color always --features esplora-async
	cargo test --verbose --color always --features esplora-async-https
	cargo build --verbose --color always --features esplora-async-https
	popd
fi

echo -e "\n\nTest futures builds"
pushd lightning-background-processor
cargo test --verbose --color always --features futures
popd

if [ "$RUSTC_MINOR_VERSION" -gt 55 ]; then
	echo -e "\n\nTest Custom Message Macros"
	pushd lightning-custom-message
	cargo test --verbose --color always
	popd
fi

if [ "$RUSTC_MINOR_VERSION" -gt 51 ]; then # Current `object` MSRV, subject to change
	echo -e "\n\nTest backtrace-debug builds"
	pushd lightning
	cargo test --verbose --color always --features backtrace
	popd
fi

echo -e "\n\nBuilding with all Log-Limiting features"
pushd lightning
grep '^max_level_' Cargo.toml | awk '{ print $1 }'| while read -r FEATURE; do
	cargo build --verbose --color always --features "$FEATURE"
done
popd

echo -e "\n\nTesting no-std flags in various combinations"
for DIR in lightning lightning-invoice lightning-rapid-gossip-sync; do
	pushd $DIR
	cargo test --verbose --color always --no-default-features --features no-std
	# check if there is a conflict between no-std and the default std feature
	cargo test --verbose --color always --features no-std
	# check if there is a conflict between no-std and the c_bindings cfg
	RUSTFLAGS="--cfg=c_bindings" cargo test --verbose --color always --no-default-features --features=no-std
	popd
done
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
if [[ $RUSTC_MINOR_VERSION -gt 67 ]]; then
	# lightning-transaction-sync's MSRV is 1.67
	cargo check --verbose --color always --features lightning-transaction-sync
else
	cargo check --verbose --color always
fi
popd

# Test that we can build downstream code with only the "release pins".
pushd msrv-no-dev-deps-check
PIN_RELEASE_DEPS
cargo check
popd

if [ -f "$(which arm-none-eabi-gcc)" ]; then
	pushd no-std-check
	cargo build --target=thumbv7m-none-eabi
	popd
fi

echo -e "\n\nTest Taproot builds"
pushd lightning
RUSTFLAGS="$RUSTFLAGS --cfg=taproot" cargo test --verbose --color always -p lightning
popd
