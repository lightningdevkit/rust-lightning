#!/bin/bash
# ci/ci-tests-common.sh - Shared helpers for CI test scripts.
# Source this file; do not execute it directly.
# shellcheck disable=SC2002,SC2207

# Some crates require pinning to meet our MSRV even for our downstream users,
# which we do here.
# Further crates which appear only as dev-dependencies are pinned further down.
function PIN_RELEASE_DEPS {
	return 0 # Don't fail the script if our rustc is higher than the last check
}

PIN_RELEASE_DEPS # pin the release dependencies in our main workspace

export RUST_BACKTRACE=1
