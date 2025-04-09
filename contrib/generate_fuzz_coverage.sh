#!/bin/bash
set -e
set -x

cd fuzz
export RUSTFLAGS="--cfg=fuzzing --cfg=secp256k1_fuzz --cfg=hashes_fuzz"
# ignore anything in fuzz directory since we done want coverage of targets 
cargo llvm-cov --html --ignore-filename-regex "fuzz/"


