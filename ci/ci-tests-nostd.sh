#!/bin/bash
set -eox pipefail

# shellcheck source=ci/ci-tests-common.sh
source "$(dirname "$0")/ci-tests-common.sh"

echo -e "\n\nTesting no_std builds"
for DIR in lightning-invoice lightning-rapid-gossip-sync lightning-liquidity; do
	cargo test -p $DIR --quiet --color always --no-default-features
done

cargo test -p lightning --quiet --color always --no-default-features
cargo test -p lightning-background-processor --quiet --color always --no-default-features

echo -e "\n\nTesting no_std build on a downstream no-std crate"
# check no-std compatibility across dependencies
pushd no-std-check
cargo check --quiet --color always
[ "$CI_MINIMIZE_DISK_USAGE" != "" ] && cargo clean
popd

if [ -f "$(which arm-none-eabi-gcc)" ]; then
	pushd no-std-check
	cargo build --quiet --target=thumbv7m-none-eabi
	[ "$CI_MINIMIZE_DISK_USAGE" != "" ] && cargo clean
	popd
fi
