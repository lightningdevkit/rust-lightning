#!/bin/bash
set -eox pipefail

# Generate initial exclusion list
#find . -name '*.rs' -type f |sort >rustfmt_excluded_files

# Run fmt
TMP_FILE=$(mktemp)
find . -name '*.rs' -type f |sort >$TMP_FILE
for file in $(comm -23 $TMP_FILE rustfmt_excluded_files); do
	echo "Checking formatting of $file"
	rustfmt +1.63.0 --check $file
done
