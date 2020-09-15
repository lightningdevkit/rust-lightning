#!/bin/sh
set -e
set -x
echo Testing $(git log -1 --oneline)
cargo check
cd fuzz && cargo check --features=stdin_fuzz
