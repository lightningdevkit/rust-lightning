#!/bin/sh
set -e
set -x
echo Testing $(git log -1 --oneline)
cargo check
cargo doc
cargo doc --document-private-items
cd fuzz && cargo check --features=stdin_fuzz
