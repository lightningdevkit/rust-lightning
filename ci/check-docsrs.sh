#!/bin/bash
#shellcheck disable=SC2002,SC2086,SC2207

set -ex

# Attempt to simulate the docsrs builds. Sadly its not entirely trivial as
# docs.rs reads metadata out of Cargo.toml which we don't want to have a whole
# parser for.

WORKSPACE_MEMBERS=( $(cat Cargo.toml | tr '\n' '\r' | sed 's/\r    //g' | tr '\r' '\n' | grep '^members =' | sed 's/members.*=.*\[//' | tr -d '"' | tr ',' '\n') )
echo "${WORKSPACE_MEMBERS[@]}"
for CRATE in "${WORKSPACE_MEMBERS[@]}"; do
	pushd "$CRATE"
	CARGO_ARGS=""
	RUSTDOC_ARGS=""
	cat Cargo.toml | grep -A 100 '\[package.metadata.docs.rs\]' | tail -n +2 > /tmp/ldk-docsrs-rustdoc-config.txt
	while read -r LINE; do
		case "$LINE" in
			"["*) break;;
			"features"*)
				OG_IFS="$IFS"
				IFS=','
				for FEATURE in $(echo "$LINE" | sed 's/features.*=.*\[//g' | tr -d '"] '); do
					export CARGO_ARGS="$CARGO_ARGS --features $FEATURE"
				done
				IFS="$OG_IFS"
				;;
			"all-features = true")
				export CARGO_ARGS="$CARGO_ARGS --all-features"
				;;
			"rustdoc-args"*)
				RUSTDOC_ARGS="$(echo "$LINE" | sed 's/rustdoc-args.*=.*\[//g' | tr -d '"],')"
				;;
		esac
	done < /tmp/ldk-docsrs-rustdoc-config.txt
	rm /tmp/ldk-docsrs-rustdoc-config.txt
	echo "Building $CRATE with args $CARGO_ARGS and flags $RUSTDOC_ARGS"
	# We rely on nightly features but want to use a stable release in CI to avoid
	# spurous breakage, thus we set RUSTC_BOOTSTRAP=1 here.
	RUSTC_BOOTSTRAP=1 cargo rustdoc $CARGO_ARGS -- $RUSTDOC_ARGS
	popd
done
