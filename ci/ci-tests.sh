#!/bin/bash
set -eox pipefail

RUSTC_MINOR_VERSION=$(rustc --version | awk '{ split($2,a,"."); print a[2] }')
HOST_PLATFORM="$(rustc --version --verbose | grep "host:" | awk '{ print $2 }')"

# Some crates require pinning to meet our MSRV even for our downstream users,
# which we do here.
# Further crates which appear only as dev-dependencies are pinned further down.
function PIN_RELEASE_DEPS {
	# Starting with version 1.39.0, the `tokio` crate has an MSRV of rustc 1.70.0
	[ "$RUSTC_MINOR_VERSION" -lt 70 ] && cargo update -p tokio --precise "1.38.1" --verbose

	return 0 # Don't fail the script if our rustc is higher than the last check
}

# The tests of `lightning-transaction-sync` require `electrs` and `bitcoind`
# binaries. Here, we download the binaries, validate them, and export their
# location via `ELECTRS_EXE`/`BITCOIND_EXE` which will be used by the
# `electrsd`/`bitcoind` crates in our tests.
function DOWNLOAD_ELECTRS_AND_BITCOIND {
	ELECTRS_DL_ENDPOINT="https://github.com/RCasatta/electrsd/releases/download/electrs_releases"
	ELECTRS_VERSION="esplora_a33e97e1a1fc63fa9c20a116bb92579bbf43b254"
	BITCOIND_DL_ENDPOINT="https://bitcoincore.org/bin/"
	BITCOIND_VERSION="25.1"
	if [[ "$HOST_PLATFORM" == *linux* ]]; then
		ELECTRS_DL_FILE_NAME=electrs_linux_"$ELECTRS_VERSION".zip
		ELECTRS_DL_HASH="865e26a96e8df77df01d96f2f569dcf9622fc87a8d99a9b8fe30861a4db9ddf1"
		BITCOIND_DL_FILE_NAME=bitcoin-"$BITCOIND_VERSION"-x86_64-linux-gnu.tar.gz
		BITCOIND_DL_HASH="a978c407b497a727f0444156e397b50491ce862d1f906fef9b521415b3611c8b"
	elif [[ "$HOST_PLATFORM" == *darwin* ]]; then
		ELECTRS_DL_FILE_NAME=electrs_macos_"$ELECTRS_VERSION".zip
		ELECTRS_DL_HASH="2d5ff149e8a2482d3658e9b386830dfc40c8fbd7c175ca7cbac58240a9505bcd"
		BITCOIND_DL_FILE_NAME=bitcoin-"$BITCOIND_VERSION"-x86_64-apple-darwin.tar.gz
		BITCOIND_DL_HASH="1acfde0ec3128381b83e3e5f54d1c7907871d324549129592144dd12a821eff1"
	else
		echo -e "\n\nUnsupported platform. Exiting.."
		exit 1
	fi

	DL_TMP_DIR=$(mktemp -d)
	trap 'rm -rf -- "$DL_TMP_DIR"' EXIT

	pushd "$DL_TMP_DIR"
	ELECTRS_DL_URL="$ELECTRS_DL_ENDPOINT"/"$ELECTRS_DL_FILE_NAME"
	curl -L -o "$ELECTRS_DL_FILE_NAME" "$ELECTRS_DL_URL"
	echo "$ELECTRS_DL_HASH  $ELECTRS_DL_FILE_NAME"|shasum -a 256 -c
	unzip "$ELECTRS_DL_FILE_NAME"
	export ELECTRS_EXE="$DL_TMP_DIR"/electrs
	chmod +x "$ELECTRS_EXE"

	BITCOIND_DL_URL="$BITCOIND_DL_ENDPOINT"/bitcoin-core-"$BITCOIND_VERSION"/"$BITCOIND_DL_FILE_NAME"
	curl -L -o "$BITCOIND_DL_FILE_NAME" "$BITCOIND_DL_URL"
	echo "$BITCOIND_DL_HASH  $BITCOIND_DL_FILE_NAME"|shasum -a 256 -c
	tar xzf "$BITCOIND_DL_FILE_NAME"
	export BITCOIND_EXE="$DL_TMP_DIR"/bitcoin-"$BITCOIND_VERSION"/bin/bitcoind
	chmod +x "$BITCOIND_EXE"
	popd
}

PIN_RELEASE_DEPS # pin the release dependencies in our main workspace

# Starting with version 1.10.0, the `regex` crate has an MSRV of rustc 1.65.0.
[ "$RUSTC_MINOR_VERSION" -lt 65 ] && cargo update -p regex --precise "1.9.6" --verbose

# The addr2line v0.21 crate (a dependency of `backtrace` starting with 0.3.69) relies on rustc 1.65
[ "$RUSTC_MINOR_VERSION" -lt 65 ] && cargo update -p backtrace --precise "0.3.68" --verbose

# Starting with version 0.5.9 (there is no .6-.8), the `home` crate has an MSRV of rustc 1.70.0.
[ "$RUSTC_MINOR_VERSION" -lt 70 ] && cargo update -p home --precise "0.5.5" --verbose

export RUST_BACKTRACE=1

# Build `lightning-transaction-sync` in no_download mode.
export RUSTFLAGS="$RUSTFLAGS --cfg no_download"

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

	DOWNLOAD_ELECTRS_AND_BITCOIND

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
	RUSTFLAGS="$RUSTFLAGS -A unused_variables -A unused_macros -A unused_imports -A dead_code" cargo check --verbose --color always --features "$FEATURE"
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
	RUSTFLAGS="$RUSTFLAGS --cfg=c_bindings" cargo test -p $DIR --verbose --color always --no-default-features --features=no-std
done
RUSTFLAGS="$RUSTFLAGS --cfg=c_bindings" cargo test --verbose --color always

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

echo -e "\n\nTest cfg-flag builds"
RUSTFLAGS="--cfg=taproot" cargo test --verbose --color always -p lightning
[ "$CI_MINIMIZE_DISK_USAGE" != "" ] && cargo clean
RUSTFLAGS="--cfg=async_signing" cargo test --verbose --color always -p lightning
[ "$CI_MINIMIZE_DISK_USAGE" != "" ] && cargo clean
RUSTFLAGS="--cfg=dual_funding" cargo test --verbose --color always -p lightning
[ "$CI_MINIMIZE_DISK_USAGE" != "" ] && cargo clean
RUSTFLAGS="--cfg=splicing" cargo test --verbose --color always -p lightning
[ "$CI_MINIMIZE_DISK_USAGE" != "" ] && cargo clean
RUSTFLAGS="--cfg=async_payments" cargo test --verbose --color always -p lightning
