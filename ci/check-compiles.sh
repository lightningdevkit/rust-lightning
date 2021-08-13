#!/bin/sh
set -e
set -x
echo Testing $(git log -1 --oneline)
cargo check
cargo doc
cargo doc --document-private-items
cd fuzz && RUSTFLAGS="--cfg=fuzzing" cargo check --features=stdin_fuzz
cd ../lightning && cargo check --no-default-features --features=no-std
