#!/bin/bash
set -eox pipefail

# shellcheck source=ci/ci-tests-common.sh
source "$(dirname "$0")/ci-tests-common.sh"

echo -e "\n\nChecking and testing lightning with features"
cargo test -p lightning --quiet --color always --features dnssec
cargo check -p lightning --quiet --color always --features dnssec
cargo doc -p lightning --quiet --document-private-items --features dnssec

echo -e "\n\nChecking and testing lightning-persister with features"
cargo test -p lightning-persister --quiet --color always --features tokio
cargo check -p lightning-persister --quiet --color always --features tokio
cargo doc -p lightning-persister --quiet --document-private-items --features tokio

echo -e "\n\nTest backtrace-debug builds"
cargo test -p lightning --quiet --color always --features backtrace

echo -e "\n\nTesting other crate-specific builds"
# Note that outbound_commitment_test only runs in this mode because of hardcoded signature values
RUSTFLAGS="$RUSTFLAGS --cfg=ldk_test_vectors" cargo test -p lightning --quiet --color always --no-default-features --features=std
# This one only works for lightning-invoice
# check that compile with no_std and serde works in lightning-invoice
cargo test -p lightning-invoice --quiet --color always --no-default-features --features serde
