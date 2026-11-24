#!/bin/sh
# Lab bootstrap (tokiwa-init service): create the DB tables and one ingest token per component.
# Idempotent: existing token files are kept, so restarts do not invalidate running sensors.
# Tokens are written to the data volume (mode 600, owned by the image's non-root user) and never printed.
# Each token gets its own directory (<dir>/<name>/token) because each sensor mounts only its directory
# (volume subpath, lab/compose.yaml): the gate must not be able to read the agent's token, secret.key or the DB.
set -eu

dir="${TOKIWA_LAB_TOKEN_DIR:-/data/lab-tokens}"
umask 077
mkdir -p "$dir"

make_token() {
    name="$1"; shift
    mkdir -p "$dir/$name"
    file="$dir/$name/token"
    if [ ! -s "$file" ] && [ -s "$dir/$name.token" ]; then
        mv "$dir/$name.token" "$file"   # layout before per-component directories: keep the existing token
    fi
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
