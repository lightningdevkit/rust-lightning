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

# Initialize GitHub Actions Job Summary
if [ -n "$GITHUB_STEP_SUMMARY" ]; then
	{
		echo "## CI Test Results"
		echo ""
		echo "| Test | Status | Duration |"
		echo "|------|--------|----------|"
	} >> "$GITHUB_STEP_SUMMARY"
fi

# Run a test command and report results to GitHub Job Summary
# Usage: run_test "Test Name" command arg1 arg2 ...
function run_test {
	local name="$1"
	shift
	local start end duration

	echo -e "\n\n$name"
	start=$(date +%s)
	if "$@"; then
		end=$(date +%s)
		duration=$((end - start))
		[ -n "$GITHUB_STEP_SUMMARY" ] && echo "| $name | ✅ | ${duration}s |" >> "$GITHUB_STEP_SUMMARY"
		return 0
	else
		end=$(date +%s)
		duration=$((end - start))
		[ -n "$GITHUB_STEP_SUMMARY" ] && echo "| $name | ❌ | ${duration}s |" >> "$GITHUB_STEP_SUMMARY"
		return 1
	fi
}

# Run a test command with custom RUSTFLAGS
# Usage: run_test_with_flags "Test Name" "extra flags" command arg1 arg2 ...
function run_test_with_flags {
	local name="$1"
	local extra_flags="$2"
	shift 2
	RUSTFLAGS="$RUSTFLAGS $extra_flags" run_test "$name" "$@"
}

PIN_RELEASE_DEPS # pin the release dependencies in our main workspace

# The backtrace v0.3.75 crate relies on rustc 1.82
[ "$RUSTC_MINOR_VERSION" -lt 82 ] && cargo update -p backtrace --precise "0.3.74" --verbose

# proptest 1.9.0 requires rustc 1.82.0
[ "$RUSTC_MINOR_VERSION" -lt 82 ] && cargo update -p proptest --precise "1.8.0" --verbose

# Starting with version 1.2.0, the `idna_adapter` crate has an MSRV of rustc 1.81.0.
[ "$RUSTC_MINOR_VERSION" -lt 81 ] && cargo update -p idna_adapter --precise "1.1.0" --verbose

export RUST_BACKTRACE=1

run_test "Workspace check" cargo check --verbose --color always

WORKSPACE_MEMBERS=( $(cat Cargo.toml | tr '\n' '\r' | sed 's/\r    //g' | tr '\r' '\n' | grep '^members =' | sed 's/members.*=.*\[//' | tr -d '"' | tr ',' ' ') )

run_test "Workspace tests" cargo test --verbose --color always

run_test "LDK upgrade tests" bash -c 'pushd lightning-tests && cargo test && popd'

for DIR in "${WORKSPACE_MEMBERS[@]}"; do
	run_test "Check $DIR" cargo check -p "$DIR" --verbose --color always
	run_test "Docs $DIR" cargo doc -p "$DIR" --document-private-items
done

run_test "lightning tests (dnssec)" cargo test -p lightning --verbose --color always --features dnssec
run_test "lightning check (dnssec)" cargo check -p lightning --verbose --color always --features dnssec
run_test "lightning docs (dnssec)" cargo doc -p lightning --document-private-items --features dnssec

run_test "block-sync test (rest-client)" cargo test -p lightning-block-sync --verbose --color always --features rest-client
run_test "block-sync check (rest-client)" cargo check -p lightning-block-sync --verbose --color always --features rest-client
run_test "block-sync test (rpc-client)" cargo test -p lightning-block-sync --verbose --color always --features rpc-client
run_test "block-sync check (rpc-client)" cargo check -p lightning-block-sync --verbose --color always --features rpc-client
run_test "block-sync test (rpc+rest)" cargo test -p lightning-block-sync --verbose --color always --features rpc-client,rest-client
run_test "block-sync check (rpc+rest)" cargo check -p lightning-block-sync --verbose --color always --features rpc-client,rest-client
run_test "block-sync test (rpc+rest+tokio)" cargo test -p lightning-block-sync --verbose --color always --features rpc-client,rest-client,tokio
run_test "block-sync check (rpc+rest+tokio)" cargo check -p lightning-block-sync --verbose --color always --features rpc-client,rest-client,tokio

run_test "tx-sync check (esplora-blocking)" cargo check -p lightning-transaction-sync --verbose --color always --features esplora-blocking
run_test "tx-sync check (esplora-async)" cargo check -p lightning-transaction-sync --verbose --color always --features esplora-async
run_test "tx-sync check (esplora-async-https)" cargo check -p lightning-transaction-sync --verbose --color always --features esplora-async-https
run_test "tx-sync check (electrum)" cargo check -p lightning-transaction-sync --verbose --color always --features electrum

if [ -z "$CI_ENV" ] && [[ -z "$BITCOIND_EXE" || -z "$ELECTRS_EXE" ]]; then
	echo -e "\n\nSkipping testing Transaction Sync Clients due to BITCOIND_EXE or ELECTRS_EXE being unset."
	run_test "tx-sync check (tests only)" cargo check -p lightning-transaction-sync --tests
else
	run_test "tx-sync test (esplora-blocking)" cargo test -p lightning-transaction-sync --verbose --color always --features esplora-blocking
	run_test "tx-sync test (esplora-async)" cargo test -p lightning-transaction-sync --verbose --color always --features esplora-async
	run_test "tx-sync test (esplora-async-https)" cargo test -p lightning-transaction-sync --verbose --color always --features esplora-async-https
	run_test "tx-sync test (electrum)" cargo test -p lightning-transaction-sync --verbose --color always --features electrum
fi

run_test "persister test (tokio)" cargo test -p lightning-persister --verbose --color always --features tokio
run_test "persister check (tokio)" cargo check -p lightning-persister --verbose --color always --features tokio
run_test "persister docs (tokio)" cargo doc -p lightning-persister --document-private-items --features tokio

run_test "custom-message test" cargo test -p lightning-custom-message --verbose --color always
[ "$CI_MINIMIZE_DISK_USAGE" != "" ] && cargo clean

run_test "lightning test (backtrace)" cargo test -p lightning --verbose --color always --features backtrace

for DIR in lightning-invoice lightning-rapid-gossip-sync lightning-liquidity; do
	run_test "$DIR test (no-std)" cargo test -p $DIR --verbose --color always --no-default-features
done

run_test "lightning test (no-std)" cargo test -p lightning --verbose --color always --no-default-features
run_test "background-processor test (no-std)" cargo test -p lightning-background-processor --verbose --color always --no-default-features

# Note that because `$RUSTFLAGS` is not passed through to doctest builds we cannot selectively
# disable doctests in `c_bindings` so we skip doctests entirely here.
run_test_with_flags "c_bindings test (workspace)" "--cfg=c_bindings" cargo test --verbose --color always --lib --bins --tests

for DIR in lightning-invoice lightning-rapid-gossip-sync; do
	# check if there is a conflict between no_std and the c_bindings cfg
	run_test_with_flags "$DIR test (c_bindings+no-std)" "--cfg=c_bindings" cargo test -p $DIR --verbose --color always --no-default-features
done

# Note that because `$RUSTFLAGS` is not passed through to doctest builds we cannot selectively
# disable doctests in `c_bindings` so we skip doctests entirely here.
run_test_with_flags "background-processor test (c_bindings+no-std)" "--cfg=c_bindings" cargo test -p lightning-background-processor --verbose --color always --no-default-features --lib --bins --tests
run_test_with_flags "lightning test (c_bindings+no-std)" "--cfg=c_bindings" cargo test -p lightning --verbose --color always --no-default-features --lib --bins --tests

# Note that outbound_commitment_test only runs in this mode because of hardcoded signature values
run_test_with_flags "lightning test (test_vectors)" "--cfg=ldk_test_vectors" cargo test -p lightning --verbose --color always --no-default-features --features=std
# check that compile with no_std and serde works in lightning-invoice
run_test "lightning-invoice test (no-std+serde)" cargo test -p lightning-invoice --verbose --color always --no-default-features --features serde

run_test "no-std-check" bash -c 'pushd no-std-check && cargo check --verbose --color always && popd'
[ "$CI_MINIMIZE_DISK_USAGE" != "" ] && (cd no-std-check && cargo clean)

# Test that we can build downstream code with only the "release pins".
run_test "msrv-no-dev-deps-check" bash -c 'pushd msrv-no-dev-deps-check && cargo check && popd'
[ "$CI_MINIMIZE_DISK_USAGE" != "" ] && (cd msrv-no-dev-deps-check && cargo clean)

if [ -f "$(which arm-none-eabi-gcc)" ]; then
	run_test "no-std-check (ARM)" bash -c 'pushd no-std-check && cargo build --target=thumbv7m-none-eabi && popd'
	[ "$CI_MINIMIZE_DISK_USAGE" != "" ] && (cd no-std-check && cargo clean)
fi

run_test_with_flags "lightning test (taproot)" "--cfg=taproot" cargo test --verbose --color always -p lightning
[ "$CI_MINIMIZE_DISK_USAGE" != "" ] && cargo clean
run_test_with_flags "lightning test (simple_close)" "--cfg=simple_close" cargo test --verbose --color always -p lightning
[ "$CI_MINIMIZE_DISK_USAGE" != "" ] && cargo clean
run_test_with_flags "lightning-liquidity test (lsps1_service)" "--cfg=lsps1_service" cargo test --verbose --color always -p lightning-liquidity
[ "$CI_MINIMIZE_DISK_USAGE" != "" ] && cargo clean
run_test_with_flags "lightning test (peer_storage)" "--cfg=peer_storage" cargo test --verbose --color always -p lightning
