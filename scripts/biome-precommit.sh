#!/usr/bin/env bash
# pre-commit hook: run the frontend's own Biome (frontend/node_modules) on staged frontend files.
# pre-commit passes repo-relative paths (frontend/src/...); Biome must run inside frontend/ to pick up
# frontend/biome.json, so the prefix is stripped here.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/../frontend"
biome="node_modules/.bin/biome"
if [ ! -x "$biome" ]; then
    echo "biome not installed: run 'npm ci' in frontend/ first" >&2
    exit 1
fi

files=()
for f in "$@"; do
    files+=("${f#frontend/}")
done
[ "${#files[@]}" -gt 0 ] || exit 0

exec "$biome" check --write --no-errors-on-unmatched --files-ignore-unknown=true "${files[@]}"
