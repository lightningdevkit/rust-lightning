#!/bin/bash
set -e
set -x

# Check if we're in the root directory, if so change to fuzz
if [ -d "fuzz" ]; then
    cd fuzz
elif [ ! -f "Cargo.toml" ] || ! grep -q "fuzz" Cargo.toml 2>/dev/null; then
    echo "Error: Please run this script from the rust-lightning root directory or fuzz directory"
    exit 1
fi

# Check if test_cases directory exists and has content
show_corpus_message=false
if [ ! -d "test_cases" ]; then
    show_corpus_message=true
elif [ -z "$(find test_cases -name '*' -type f 2>/dev/null | head -1)" ]; then
    show_corpus_message=true
fi

if [ "$show_corpus_message" = true ]; then
    echo "Warning: No corpus found in test_cases directory."
    echo "Generating coverage report without fuzzing corpus."
    echo ""
    echo "To include fuzzing corpus coverage, create test_cases directories with your corpus:"
    echo "  mkdir -p test_cases/{target_name}"
    echo "  cp your_corpus_directory/* test_cases/{target_name}/"
    echo ""
    echo "Example:"
    echo "  mkdir -p test_cases/base32"
    echo "  cp /path/to/your/base32_corpus/* test_cases/base32/"
    echo ""
fi

export RUSTFLAGS="--cfg=fuzzing --cfg=secp256k1_fuzz --cfg=hashes_fuzz"
# ignore anything in fuzz directory since we don't want coverage of targets 
cargo llvm-cov --html --ignore-filename-regex "fuzz/"

echo ""
echo "Coverage report generated in target/llvm-cov/html/index.html"


