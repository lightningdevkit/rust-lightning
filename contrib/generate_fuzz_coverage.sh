#!/bin/bash
set -ex

# Parse command line arguments
OUTPUT_DIR="coverage-report"
OUTPUT_CODECOV_JSON=0
while [[ $# -gt 0 ]]; do
    case $1 in
        --output-dir)
            OUTPUT_DIR="$2"
            shift 2
            ;;
		--output-codecov-json)
			OUTPUT_CODECOV_JSON=1
			shift 1
			;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--output-dir OUTPUT_DIRECTORY]"
            exit 1
            ;;
    esac
done

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

# Create output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

export RUSTFLAGS="--cfg=fuzzing --cfg=secp256k1_fuzz --cfg=hashes_fuzz"

# dont run this command when running in CI
if [ "$OUTPUT_CODECOV_JSON" = "0" ]; then
    cargo llvm-cov --html --ignore-filename-regex "fuzz/" --output-dir "$OUTPUT_DIR"
    echo "Coverage report generated in $OUTPUT_DIR/html/index.html"
else
    cargo llvm-cov -j8 --codecov --ignore-filename-regex "fuzz/" --output-path "$OUTPUT_DIR/fuzz-codecov.json"
    echo "Fuzz codecov report available at $OUTPUT_DIR/fuzz-codecov.json"
fi



