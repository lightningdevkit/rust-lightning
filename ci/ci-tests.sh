#!/bin/bash
#shellcheck disable=SC2002,SC2207
set -eox pipefail

RUSTC_MINOR_VERSION=$(rustc --version | awk '{ split($2,a,"."); print a[2] }')

# Some crates require pinning to meet our MSRV even for our downstream users,
# which we do here.
# Further crates which appear only as dev-dependencies are pinned further down.
function PIN_RELEASE_DEPS {
	return 0 # Don't fail the script if our rustc is higher than the last check
}

PIN_RELEASE_DEPS # pin the release dependencies in our main workspace

# The backtrace v0.3.75 crate relies on rustc 1.82
[ "$RUSTC_MINOR_VERSION" -lt 82 ] && cargo update -p backtrace --precise "0.3.74" --quiet

# proptest 1.9.0 requires rustc 1.82.0
[ "$RUSTC_MINOR_VERSION" -lt 82 ] && cargo update -p proptest --precise "1.8.0" --quiet

# Starting with version 1.2.0, the `idna_adapter` crate has an MSRV of rustc 1.81.0.
[ "$RUSTC_MINOR_VERSION" -lt 81 ] && cargo update -p idna_adapter --precise "1.1.0" --quiet

export RUST_BACKTRACE=1

# All steps in order, matching the original script flow
ALL_STEPS="
check-workspace
test-workspace
test-ldk-upgrade
check-workspace-members
test-lightning-dnssec
test-lightning-block-sync
check-lightning-transaction-sync
test-lightning-transaction-sync
test-lightning-persister
test-lightning-custom-message
test-lightning-backtrace
test-no-std
test-c-bindings
test-crate-specific
check-no-std
check-msrv-no-dev-deps
build-no-std-arm
test-cfg-flags
"

# If a step name is passed, run just that step. Otherwise run all.
if [ -n "$1" ]; then
	STEPS_TO_RUN="$1"
else
	STEPS_TO_RUN="$ALL_STEPS"
fi

WORKSPACE_MEMBERS=( $(cat Cargo.toml | tr '\n' '\r' | sed 's/\r    //g' | tr '\r' '\n' | grep '^members =' | sed 's/members.*=.*\[//' | tr -d '"' | tr ',' ' ') )

# Verify that all steps were executed (called at the end of CI)
if [ "$1" = "--verify-complete" ]; then
	MISSING_STEPS=""
	for STEP in $ALL_STEPS; do
		if [[ ! " $CI_COMPLETED_STEPS " == *" $STEP "* ]]; then
			MISSING_STEPS="$MISSING_STEPS $STEP"
		fi
	done
	if [ -n "$MISSING_STEPS" ]; then
		echo "ERROR: The following CI steps were not executed:$MISSING_STEPS"
		exit 1
	fi
	echo "All CI steps were executed successfully."
	exit 0
fi

for STEP in $STEPS_TO_RUN; do
case "$STEP" in

check-workspace)
echo -e "\n\nChecking the workspace, except lightning-transaction-sync."
cargo check --quiet --color always
;;

test-workspace)
echo -e "\n\nTesting the workspace, except lightning-transaction-sync."
cargo test --quiet --color always
;;

test-ldk-upgrade)
echo -e "\n\nTesting upgrade from prior versions of LDK"
pushd lightning-tests
cargo test --quiet
popd
;;

check-workspace-members)
echo -e "\n\nChecking and building docs for all workspace members individually..."
for DIR in "${WORKSPACE_MEMBERS[@]}"; do
	cargo check -p "$DIR" --quiet --color always
	cargo doc -p "$DIR" --quiet --document-private-items
done
;;

test-lightning-dnssec)
echo -e "\n\nChecking and testing lightning with features"
cargo test -p lightning --quiet --color always --features dnssec
cargo check -p lightning --quiet --color always --features dnssec
cargo doc -p lightning --quiet --document-private-items --features dnssec
;;

test-lightning-block-sync)
echo -e "\n\nChecking and testing Block Sync Clients with features"

cargo test -p lightning-block-sync --quiet --color always --features rest-client
cargo check -p lightning-block-sync --quiet --color always --features rest-client
cargo test -p lightning-block-sync --quiet --color always --features rpc-client
cargo check -p lightning-block-sync --quiet --color always --features rpc-client
cargo test -p lightning-block-sync --quiet --color always --features rpc-client,rest-client
cargo check -p lightning-block-sync --quiet --color always --features rpc-client,rest-client
cargo test -p lightning-block-sync --quiet --color always --features rpc-client,rest-client,tokio
cargo check -p lightning-block-sync --quiet --color always --features rpc-client,rest-client,tokio
;;

check-lightning-transaction-sync)
echo -e "\n\nChecking Transaction Sync Clients with features."
cargo check -p lightning-transaction-sync --quiet --color always --features esplora-blocking
cargo check -p lightning-transaction-sync --quiet --color always --features esplora-async
cargo check -p lightning-transaction-sync --quiet --color always --features esplora-async-https
cargo check -p lightning-transaction-sync --quiet --color always --features electrum
;;

test-lightning-transaction-sync)
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
;;

test-lightning-persister)
echo -e "\n\nChecking and testing lightning-persister with features"
cargo test -p lightning-persister --quiet --color always --features tokio
cargo check -p lightning-persister --quiet --color always --features tokio
cargo doc -p lightning-persister --quiet --document-private-items --features tokio
;;

test-lightning-custom-message)
echo -e "\n\nTest Custom Message Macros"
cargo test -p lightning-custom-message --quiet --color always
[ "$CI_MINIMIZE_DISK_USAGE" != "" ] && cargo clean
;;

test-lightning-backtrace)
echo -e "\n\nTest backtrace-debug builds"
cargo test -p lightning --quiet --color always --features backtrace
;;

test-no-std)
echo -e "\n\nTesting no_std builds"
for DIR in lightning-invoice lightning-rapid-gossip-sync lightning-liquidity; do
	cargo test -p $DIR --quiet --color always --no-default-features
done

cargo test -p lightning --quiet --color always --no-default-features
cargo test -p lightning-background-processor --quiet --color always --no-default-features
;;

test-c-bindings)
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
;;

test-crate-specific)
echo -e "\n\nTesting other crate-specific builds"
# Note that outbound_commitment_test only runs in this mode because of hardcoded signature values
RUSTFLAGS="$RUSTFLAGS --cfg=ldk_test_vectors" cargo test -p lightning --quiet --color always --no-default-features --features=std
# This one only works for lightning-invoice
# check that compile with no_std and serde works in lightning-invoice
cargo test -p lightning-invoice --quiet --color always --no-default-features --features serde
;;

check-no-std)
echo -e "\n\nTesting no_std build on a downstream no-std crate"
# check no-std compatibility across dependencies
pushd no-std-check
cargo check --quiet --color always
[ "$CI_MINIMIZE_DISK_USAGE" != "" ] && cargo clean
popd
;;

check-msrv-no-dev-deps)
# Test that we can build downstream code with only the "release pins".
pushd msrv-no-dev-deps-check
PIN_RELEASE_DEPS
cargo check --quiet
[ "$CI_MINIMIZE_DISK_USAGE" != "" ] && cargo clean
popd
;;

build-no-std-arm)
if [ -f "$(which arm-none-eabi-gcc)" ]; then
	pushd no-std-check
	cargo build --quiet --target=thumbv7m-none-eabi
	[ "$CI_MINIMIZE_DISK_USAGE" != "" ] && cargo clean
	popd
fi
;;

test-cfg-flags)
echo -e "\n\nTest cfg-flag builds"
RUSTFLAGS="--cfg=taproot" cargo test --quiet --color always -p lightning
[ "$CI_MINIMIZE_DISK_USAGE" != "" ] && cargo clean
RUSTFLAGS="--cfg=simple_close" cargo test --quiet --color always -p lightning
[ "$CI_MINIMIZE_DISK_USAGE" != "" ] && cargo clean
RUSTFLAGS="--cfg=lsps1_service" cargo test --quiet --color always -p lightning-liquidity
[ "$CI_MINIMIZE_DISK_USAGE" != "" ] && cargo clean
RUSTFLAGS="--cfg=peer_storage" cargo test --quiet --color always -p lightning
;;

*)
echo "Unknown step: $STEP"
exit 1
;;

esac

# Log the completed step to GITHUB_ENV for the verification step
if [ -n "$GITHUB_ENV" ]; then
	echo "CI_COMPLETED_STEPS=${CI_COMPLETED_STEPS:-} $STEP" >> "$GITHUB_ENV"
fi
done
