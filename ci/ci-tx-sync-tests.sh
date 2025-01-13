#!/bin/bash
set -eox pipefail

RUSTC_MINOR_VERSION=$(rustc --version | awk '{ split($2,a,"."); print a[2] }')

pushd lightning-transaction-sync

# Some crates require pinning to meet our MSRV even for our downstream users,
# which we do here.
# Further crates which appear only as dev-dependencies are pinned further down.
function PIN_RELEASE_DEPS {
	return 0 # Don't fail the script if our rustc is higher than the last check
}

PIN_RELEASE_DEPS # pin the release dependencies

# Starting with version 0.5.11, the `home` crate has an MSRV of rustc 1.81.0.
[ "$RUSTC_MINOR_VERSION" -lt 81 ] && cargo update -p home --precise "0.5.9" --verbose

export RUST_BACKTRACE=1

echo -e "\n\nChecking Transaction Sync Clients with features."
cargo check --verbose --color always --features esplora-blocking
cargo check --verbose --color always --features esplora-async
cargo check --verbose --color always --features esplora-async-https
cargo check --verbose --color always --features electrum

if [ -z "$CI_ENV" ] && [[ -z "$BITCOIND_EXE" || -z "$ELECTRS_EXE" ]]; then
	echo -e "\n\nSkipping testing Transaction Sync Clients due to BITCOIND_EXE or ELECTRS_EXE being unset."
	cargo check --tests
else
	echo -e "\n\nTesting Transaction Sync Clients with features."
	cargo test --verbose --color always --features esplora-blocking
	cargo test --verbose --color always --features esplora-async
	cargo test --verbose --color always --features esplora-async-https
	cargo test --verbose --color always --features electrum
fi

popd
