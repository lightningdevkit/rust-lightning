#!/bin/bash
set -eox pipefail

# Run all CI test groups sequentially for local testing.
# In GitHub Actions, these run as separate parallel jobs.

DIR="$(dirname "$0")"
"$DIR/ci-tests-workspace.sh"
"$DIR/ci-tests-features.sh"
"$DIR/ci-tests-bindings.sh"
"$DIR/ci-tests-nostd.sh"
"$DIR/ci-tests-cfg-flags.sh"
"$DIR/ci-tests-sync.sh"
