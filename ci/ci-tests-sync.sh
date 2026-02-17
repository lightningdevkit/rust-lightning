#!/bin/bash
set -eox pipefail

# shellcheck source=ci/ci-tests-common.sh
source "$(dirname "$0")/ci-tests-common.sh"

echo -e "\n\nChecking and testing Block Sync Clients with features"

cargo test -p lightning-block-sync --quiet --color always --features rest-client
cargo check -p lightning-block-sync --quiet --color always --features rest-client
cargo test -p lightning-block-sync --quiet --color always --features rpc-client
cargo check -p lightning-block-sync --quiet --color always --features rpc-client
cargo test -p lightning-block-sync --quiet --color always --features rpc-client,rest-client
cargo check -p lightning-block-sync --quiet --color always --features rpc-client,rest-client
cargo test -p lightning-block-sync --quiet --color always --features rpc-client,rest-client,tokio
cargo check -p lightning-block-sync --quiet --color always --features rpc-client,rest-client,tokio

echo -e "\n\nChecking Transaction Sync Clients with features."
cargo check -p lightning-transaction-sync --quiet --color always --features esplora-blocking
cargo check -p lightning-transaction-sync --quiet --color always --features esplora-async
cargo check -p lightning-transaction-sync --quiet --color always --features esplora-async-https
cargo check -p lightning-transaction-sync --quiet --color always --features electrum

if [ -z "$CI_ENV" ] && [[ -z "$BITCOIND_EXE" || -z "$ELECTRS_EXE" ]]; then
	echo -e "\n\nSkipping testing Transaction Sync Clients due to BITCOIND_EXE or ELECTRS_EXE being unset."
	cargo check -p lightning-transaction-sync --tests
else
	echo -e "\n\nTesting Transaction Sync Clients with features."
	cargo test -p lightning-transaction-sync --quiet --color always --features esplora-blocking
	cargo test -p lightning-transaction-sync --quiet --color always --features esplora-async
	cargo test -p lightning-transaction-sync --quiet --color always --features esplora-async-https
	cargo test -p lightning-transaction-sync --quiet --color always --features electrum
fi
