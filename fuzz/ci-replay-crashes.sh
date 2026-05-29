#!/bin/bash
set -euo pipefail

HFUZZ_WORKSPACE="${HFUZZ_WORKSPACE:-hfuzz_workspace}"

cleanup_files=()
cleanup_dirs=()
cleanup() {
	for file in "${cleanup_files[@]}"; do
		rm -f "$file"
	done
	for dir in "${cleanup_dirs[@]}"; do
		rmdir "$dir" 2>/dev/null || true
	done
}
trap cleanup EXIT

if [ ! -d "$HFUZZ_WORKSPACE" ]; then
	echo "No honggfuzz workspace found at $HFUZZ_WORKSPACE; skipping replay."
	exit 0
fi

found_crash=0
replay_status=0

for target_dir in "$HFUZZ_WORKSPACE"/*_target; do
	[ -d "$target_dir" ] || continue

	file="$(basename "$target_dir")"
	crash_files=()
	for crash_file in "$target_dir"/SIG*; do
		[ -f "$crash_file" ] || continue
		crash_files+=("$crash_file")
	done
	[ "${#crash_files[@]}" -gt 0 ] || continue

	if [ -f "fuzz-fake-hashes/src/bin/$file.rs" ]; then
		manifest="fuzz-fake-hashes/Cargo.toml"
		target_rustflags="--cfg=fuzzing --cfg=secp256k1_fuzz --cfg=hashes_fuzz"
	elif [ -f "fuzz-real-hashes/src/bin/$file.rs" ]; then
		manifest="fuzz-real-hashes/Cargo.toml"
		target_rustflags="--cfg=fuzzing --cfg=secp256k1_fuzz"
	else
		echo "Could not find generated target source for $file; skipping replay."
		continue
	fi

	found_crash=1
	target_name="${file%_target}"
	testcase_dir="test_cases/$target_name"
	if [ ! -d "$testcase_dir" ]; then
		mkdir -p "$testcase_dir"
		cleanup_dirs+=("$testcase_dir")
	fi

	idx=0
	for crash_file in "${crash_files[@]}"; do
		idx=$((idx + 1))
		replay_file="$testcase_dir/ci_hfuzz_replay_$idx"
		cp "$crash_file" "$replay_file"
		cleanup_files+=("$replay_file")
		echo "Replaying honggfuzz crash input $crash_file with $file"
		printf "HEX="
		xxd -p "$crash_file" | tr -d '\n'
		echo
	done

	if ! RUST_BACKTRACE=1 RUSTFLAGS="$target_rustflags" \
		cargo --color always test --manifest-path "$manifest" --bin "$file" -- --nocapture
	then
		replay_status=1
	fi
done

if [ "$found_crash" -eq 0 ]; then
	echo "No honggfuzz crash inputs found; skipping replay."
fi

exit "$replay_status"
