#!/bin/bash
set -eox pipefail

echo -e "\n\nGenerating fuzz coverage report"
# In CI, store coverage in target directory for consistency with other artifacts
COVERAGE_DIR="target/coverage-report"
echo "Installing cargo-llvm-cov..."
# Install cargo-llvm-cov if not already installed
cargo install cargo-llvm-cov --locked

echo "Cleaning up to save disk space..."
rm -rf target/*
echo "Disk cleanup completed"


echo "Running fuzz coverage generation..."
./contrib/generate_fuzz_coverage.sh --output-dir "$COVERAGE_DIR"
echo "Coverage generation completed. Checking results..."

# Upload fuzz coverage to codecov if the file exists (CI only)
if [ -f "target/fuzz-codecov.json" ]; then
    echo "Uploading fuzz coverage to codecov..."
    bash <(curl -s https://codecov.io/bash) -f "target/fuzz-codecov.json" -F fuzz -t "f421b687-4dc2-4387-ac3d-dc3b2528af57"
fi
