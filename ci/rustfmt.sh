#!/bin/bash
set -eox pipefail

export LC_ALL=C

# Generate initial exclusion list
#find . -name '*.rs' -type f |sort >rustfmt_excluded_files

# The +rustversion syntax only works with rustup-installed rust toolchains,
# not with any distro-provided ones. Thus, we check for a rustup install and
# only pass +1.63.0 if we find one.
VERS=""
[ "$(which rustup)" != "" ] && VERS="+1.63.0"

# Run fmt
TMP_FILE=$(mktemp)
find . -name '*.rs' -type f |sort >$TMP_FILE
for file in $(comm -23 $TMP_FILE rustfmt_excluded_files); do
	echo "Checking formatting of $file"
	rustfmt $VERS --edition 2021 --check $file
done
