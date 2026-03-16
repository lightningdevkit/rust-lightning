#!/bin/bash
set -eox pipefail

# shellcheck source=ci/ci-tests-common.sh
source "$(dirname "$0")/ci-tests-common.sh"

echo -e "\n\nChecking the workspace."
cargo check --quiet --color always

echo -e "\n\nTesting the workspace."
cargo test --quiet --color always

echo -e "\n\nTesting upgrade from prior versions of LDK"
pushd lightning-tests
cargo test --quiet
popd

echo -e "\n\nBuilding docs for all workspace members."
cargo doc --workspace --quiet --document-private-items

[ "$CI_MINIMIZE_DISK_USAGE" != "" ] && cargo clean

# Test that we can build downstream code with only the "release pins".
pushd msrv-no-dev-deps-check
PIN_RELEASE_DEPS
cargo check --quiet
[ "$CI_MINIMIZE_DISK_USAGE" != "" ] && cargo clean
popd
