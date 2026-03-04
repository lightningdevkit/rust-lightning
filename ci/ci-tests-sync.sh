#!/bin/bash
set -eox pipefail

# shellcheck source=ci/ci-tests-common.sh
source "$(dirname "$0")/ci-tests-common.sh"

echo -e "\n\nTesting Block Sync Clients with features"

cargo test -p lightning-block-sync --quiet --color always --features rest-client
cargo test -p lightning-block-sync --quiet --color always --features rpc-client
cargo test -p lightning-block-sync --quiet --color always --features rpc-client,rest-client
cargo test -p lightning-block-sync --quiet --color always --features rpc-client,rest-client,tokio

if [ -z "$CI_ENV" ] && [[ -z "$BITCOIND_EXE" || -z "$ELECTRS_EXE" ]]; then
	echo -e "\n\nSkipping testing Transaction Sync Clients due to BITCOIND_EXE or ELECTRS_EXE being unset."
	cargo check -p lightning-transaction-sync --tests --quiet --color always
	cargo check -p lightning-transaction-sync --tests --quiet --color always --features esplora-blocking
	cargo check -p lightning-transaction-sync --tests --quiet --color always --features esplora-async
	cargo check -p lightning-transaction-sync --tests --quiet --color always --features esplora-async-https
	cargo check -p lightning-transaction-sync --tests --quiet --color always --features electrum
else
	echo -e "\n\nTesting Transaction Sync Clients with features."
	cargo test -p lightning-transaction-sync --quiet --color always
	cargo test -p lightning-transaction-sync --quiet --color always --features esplora-blocking
	cargo test -p lightning-transaction-sync --quiet --color always --features esplora-async
	cargo test -p lightning-transaction-sync --quiet --color always --features esplora-async-https
	cargo test -p lightning-transaction-sync --quiet --color always --features electrum
fi
