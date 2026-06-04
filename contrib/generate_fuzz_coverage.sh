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

generate_coverage_report() {
    local manifest_path="$1"
    local output_path="$2"
    local rustflags="$3"

    cargo llvm-cov clean --workspace
    RUSTFLAGS="$rustflags" cargo llvm-cov -j8 --manifest-path "$manifest_path" --codecov \
        --dep-coverage lightning,lightning-invoice,lightning-liquidity,lightning-rapid-gossip-sync,lightning-persister \
        --no-default-ignore-filename-regex \
        --ignore-filename-regex "(\.cargo/registry|\.rustup/toolchains|/fuzz/)" \
        --output-path "$output_path" --tests
}

# dont run this command when running in CI
if [ "$OUTPUT_CODECOV_JSON" = "0" ]; then
    cargo llvm-cov clean --workspace
    RUSTFLAGS="--cfg=fuzzing --cfg=secp256k1_fuzz --cfg=hashes_fuzz" \
        cargo llvm-cov --manifest-path fuzz-fake-hashes/Cargo.toml --html \
        --dep-coverage lightning,lightning-invoice,lightning-liquidity,lightning-rapid-gossip-sync,lightning-persister \
        --no-default-ignore-filename-regex \
        --ignore-filename-regex "(\.cargo/registry|\.rustup/toolchains|/fuzz/)" \
        --output-dir "$OUTPUT_DIR/fake-hashes" --tests
    cargo llvm-cov clean --workspace
    RUSTFLAGS="--cfg=fuzzing --cfg=secp256k1_fuzz" \
        cargo llvm-cov --manifest-path fuzz-real-hashes/Cargo.toml --html \
        --dep-coverage lightning,lightning-invoice,lightning-liquidity,lightning-rapid-gossip-sync,lightning-persister \
        --no-default-ignore-filename-regex \
        --ignore-filename-regex "(\.cargo/registry|\.rustup/toolchains|/fuzz/)" \
        --output-dir "$OUTPUT_DIR/real-hashes" --tests
    echo "Coverage reports generated in $OUTPUT_DIR/fake-hashes and $OUTPUT_DIR/real-hashes"
else
    # Import honggfuzz corpus if the artifact was downloaded.
    if [ -d "hfuzz_workspace" ]; then
        echo "Importing corpus from hfuzz_workspace..."
        for target_dir in hfuzz_workspace/*; do
            [ -d "$target_dir" ] || continue
            src_name="$(basename "$target_dir")"
            dest="${src_name%_target}"
            mkdir -p "test_cases/$dest"
            # Copy corpus files into the test_cases directory
            find "$target_dir" -maxdepth 2 -type f -path "$target_dir/input/*" \
              -print0 | xargs -0 -I{} cp -n {} "test_cases/$dest/"
        done
    fi

    echo "Replaying imported corpus (if found) via tests to generate coverage..."
    generate_coverage_report \
        "fuzz-fake-hashes/Cargo.toml" \
        "$OUTPUT_DIR/fuzz-fake-hashes-codecov.json" \
        "--cfg=fuzzing --cfg=secp256k1_fuzz --cfg=hashes_fuzz"
    generate_coverage_report \
        "fuzz-real-hashes/Cargo.toml" \
        "$OUTPUT_DIR/fuzz-real-hashes-codecov.json" \
        "--cfg=fuzzing --cfg=secp256k1_fuzz"

    echo "Fuzz codecov reports available at $OUTPUT_DIR/fuzz-fake-hashes-codecov.json and $OUTPUT_DIR/fuzz-real-hashes-codecov.json"
fi
