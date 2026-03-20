#!/bin/bash
set -e
set -x

pushd src/msg_targets
rm msg_*.rs
./gen_target.sh
[ "$(git diff)" != "" ] && exit 1
popd
pushd src/bin
rm *_target.rs
./gen_target.sh
[ "$(git diff)" != "" ] && exit 1
popd

export RUSTFLAGS="--cfg=secp256k1_fuzz --cfg=hashes_fuzz"

mkdir -p hfuzz_workspace/full_stack_target/input
pushd write-seeds
RUSTFLAGS="$RUSTFLAGS --cfg=fuzzing" cargo run ../hfuzz_workspace/full_stack_target/input
cargo clean
popd

cargo install --color always --force honggfuzz --no-default-features

# Because we're fuzzing relatively few iterations, the maximum possible
# compiler optimizations aren't necessary, so we turn off LTO
sed -i 's/lto = true//' Cargo.toml

export HFUZZ_BUILD_ARGS="--features honggfuzz_fuzz"

cargo --color always hfuzz build -j8

SUMMARY=""

for TARGET in src/bin/*.rs; do
	FILENAME=$(basename $TARGET)
	FILE="${FILENAME%.*}"
	CORPUS_DIR="hfuzz_workspace/$FILE/input"
	CORPUS_COUNT=$(find "$CORPUS_DIR" -type f 2>/dev/null | wc -l)
	# Run 8x the corpus size plus a baseline, ensuring full corpus replay
	# with room for new mutations. The 10-minute hard cap (--run_time 600)
	# prevents slow-per-iteration targets from running too long.
	ITERATIONS=$((CORPUS_COUNT * 8 + 1000))
	HFUZZ_RUN_ARGS="--exit_upon_crash -q -n8 -t 3 -N $ITERATIONS --run_time 600"
	if [ "$FILE" = "chanmon_consistency_target" -o "$FILE" = "fs_store_target" ]; then
		HFUZZ_RUN_ARGS="$HFUZZ_RUN_ARGS -F 64"
	fi
	export HFUZZ_RUN_ARGS
	FUZZ_START=$(date +%s)
	cargo --color always hfuzz run $FILE
	FUZZ_END=$(date +%s)
	FUZZ_TIME=$((FUZZ_END - FUZZ_START))
	FUZZ_CORPUS_COUNT=$(find "$CORPUS_DIR" -type f 2>/dev/null | wc -l)
	if [ -f hfuzz_workspace/$FILE/HONGGFUZZ.REPORT.TXT ]; then
		cat hfuzz_workspace/$FILE/HONGGFUZZ.REPORT.TXT
		for CASE in hfuzz_workspace/$FILE/SIG*; do
			cat $CASE | xxd -p
		done
		exit 1
	fi
	if [ "$GITHUB_REF" = "refs/heads/main" ] || [ "$FUZZ_MINIMIZE" = "true" ]; then
		HFUZZ_RUN_ARGS="-M -q -n8 -t 3"
		export HFUZZ_RUN_ARGS
		MIN_START=$(date +%s)
		cargo --color always hfuzz run $FILE
		MIN_END=$(date +%s)
		MIN_TIME=$((MIN_END - MIN_START))
		MIN_CORPUS_COUNT=$(find "$CORPUS_DIR" -type f 2>/dev/null | wc -l)
		SUMMARY="${SUMMARY}${FILE}|${ITERATIONS}|${CORPUS_COUNT}|${FUZZ_CORPUS_COUNT}|${FUZZ_TIME}|${MIN_CORPUS_COUNT}|${MIN_TIME}\n"
	else
		SUMMARY="${SUMMARY}${FILE}|${ITERATIONS}|${CORPUS_COUNT}|${FUZZ_CORPUS_COUNT}|${FUZZ_TIME}|-|-\n"
	fi
done

fmt_time() {
	local secs=$1
	local m=$((secs / 60))
	local s=$((secs % 60))
	if [ "$m" -gt 0 ]; then
		printf "%dm %ds" "$m" "$s"
	else
		printf "%ds" "$s"
	fi
}

# Print summary table
set +x
echo ""
echo "==== Fuzz Summary ===="
HDR="%-40s %7s %7s  %-15s %9s  %-15s %9s\n"
FMT="%-40s %7s %7s %6s %-9s %9s %6s %-9s %9s\n"
printf "$HDR" "Target" "Iters" "Corpus" "   Fuzzed" "Fuzz time" "  Minimized" "Min. time"
printf "$HDR" "------" "-----" "------" "---------------" "---------" "---------------" "---------"
echo -e "$SUMMARY" | while IFS='|' read -r name iters orig fuzzed ftime minimized mtime; do
	[ -z "$name" ] && continue
	fuzz_delta=$((fuzzed - orig))
	if [ "$minimized" = "-" ]; then
		printf "$FMT" "$name" "$iters" "$orig" "$fuzzed" "(+$fuzz_delta)" "$(fmt_time "$ftime")" "-" "" "-"
	else
		min_delta=$((minimized - fuzzed))
		printf "$FMT" "$name" "$iters" "$orig" "$fuzzed" "(+$fuzz_delta)" "$(fmt_time "$ftime")" "$minimized" "($min_delta)" "$(fmt_time "$mtime")"
	fi
done
echo "======================"
