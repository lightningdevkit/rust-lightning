#!/bin/bash
set -eox pipefail

echo -e "\n\nGenerating fuzz coverage report"
# In CI, store coverage in a specific directory for artifact collection
COVERAGE_DIR="coverage-report"
echo "Installing cargo-llvm-cov..."
# Install cargo-llvm-cov if not already installed
cargo install cargo-llvm-cov --locked
echo "Running fuzz coverage generation..."
./contrib/generate_fuzz_coverage.sh --output-dir "$COVERAGE_DIR"
echo "Coverage generation completed. Checking results..."
if [ -f "fuzz/$COVERAGE_DIR/html/index.html" ]; then
    echo "✓ Coverage report successfully generated at fuzz/$COVERAGE_DIR/html/index.html"
    ls -la "fuzz/$COVERAGE_DIR/html/"
else
    echo "✗ Coverage report not found at expected location"
fi
