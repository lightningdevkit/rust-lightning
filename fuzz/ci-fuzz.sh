#!/bin/bash
set -e

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

cargo install --force honggfuzz
sed -i 's/lto = true//' Cargo.toml
HFUZZ_BUILD_ARGS="--features honggfuzz_fuzz" cargo hfuzz build
for TARGET in src/bin/*.rs; do
	FILENAME=$(basename $TARGET)
	FILE="${FILENAME%.*}"
	HFUZZ_RUN_ARGS="--exit_upon_crash -v -n2"
	if [ "$FILE" = "chanmon_consistency_target" ]; then
		HFUZZ_RUN_ARGS="$HFUZZ_RUN_ARGS -F 64 -N100000"
	else
		HFUZZ_RUN_ARGS="$HFUZZ_RUN_ARGS -N1000000"
	fi
	export HFUZZ_RUN_ARGS
	HFUZZ_BUILD_ARGS="--features honggfuzz_fuzz" cargo hfuzz run $FILE
	if [ -f hfuzz_workspace/$FILE/HONGGFUZZ.REPORT.TXT ]; then
		cat hfuzz_workspace/$FILE/HONGGFUZZ.REPORT.TXT
		for CASE in hfuzz_workspace/$FILE/SIG*; do
			cat $CASE | xxd -p
		done
		exit 1
	fi
done
