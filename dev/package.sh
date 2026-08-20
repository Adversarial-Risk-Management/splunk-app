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

tar --exclude='__pycache__' --exclude='*.pyc' --exclude='.DS_Store' \
    -C "${root}" -czf "${out}" "${app}"

echo "wrote ${out}"
tar -tzf "${out}" | sort
