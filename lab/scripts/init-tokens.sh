#!/bin/sh
# Lab bootstrap (tokiwa-init service): create the DB tables and one ingest token per component.
# Idempotent: existing token files are kept, so restarts do not invalidate running sensors.
# Tokens are written to the data volume (mode 600, owned by the image's non-root user) and never printed.
set -eu

dir="${TOKIWA_LAB_TOKEN_DIR:-/data/lab-tokens}"
umask 077
mkdir -p "$dir"

make_token() {
    name="$1"; shift
    file="$dir/$name.token"
    if [ -s "$file" ]; then
        echo "init: token for $name already exists"
        return
    fi
    tokiwa token create "lab-$name" "$@" > "$file.tmp"
    mv "$file.tmp" "$file"
    echo "init: created token for $name"
}

make_token gate --scope ingest --scope gate
make_token agent --scope ingest
make_token sim --scope ingest
echo "init: done"
