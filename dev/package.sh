#!/usr/bin/env bash
# Build the installable Splunk app archive in dist/.
#
# The archive holds one top-level directory, `adversarial`, as Splunk
# requires. Cache files and editor files stay out of the archive.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
app="adversarial"
out="${root}/dist/${app}.tar.gz"

mkdir -p "${root}/dist"
rm -f "${out}"

find "${root}/${app}" -name '__pycache__' -type d -prune -exec rm -rf {} +
find "${root}/${app}" -name '*.pyc' -delete

# COPYFILE_DISABLE stops the macOS tar from adding a `._<name>` file for a file
# with extended attributes. Splunk reads `._alert_actions.conf` as a .conf file.
# Splunk recommends the ustar format for an app archive. See
# https://dev.splunk.com/enterprise/docs/releaseapps/packageapps/
COPYFILE_DISABLE=1 tar --format ustar --exclude='__pycache__' --exclude='*.pyc' \
    --exclude='.DS_Store' --exclude='._*' -C "${root}" -czf "${out}" "${app}"

echo "wrote ${out}"
tar -tzf "${out}" | sort
