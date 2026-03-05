#!/bin/bash
set -eox pipefail

# shellcheck source=ci/ci-tests-common.sh
source "$(dirname "$0")/ci-tests-common.sh"

echo -e "\n\nTesting c_bindings builds"
# Note that because `$RUSTFLAGS` is not passed through to doctest builds we cannot selectively
# disable doctests in `c_bindings` so we skip doctests entirely here.
RUSTFLAGS="$RUSTFLAGS --cfg=c_bindings" cargo test --quiet --color always --lib --bins --tests

for DIR in lightning-invoice lightning-rapid-gossip-sync; do
	# check if there is a conflict between no_std and the c_bindings cfg
	RUSTFLAGS="$RUSTFLAGS --cfg=c_bindings" cargo test -p $DIR --quiet --color always --no-default-features
done

# Note that because `$RUSTFLAGS` is not passed through to doctest builds we cannot selectively
# disable doctests in `c_bindings` so we skip doctests entirely here.
RUSTFLAGS="$RUSTFLAGS --cfg=c_bindings" cargo test -p lightning-background-processor --quiet --color always --no-default-features --lib --bins --tests
RUSTFLAGS="$RUSTFLAGS --cfg=c_bindings" cargo test -p lightning --quiet --color always --no-default-features --lib --bins --tests
