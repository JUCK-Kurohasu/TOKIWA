#!/bin/sh
# Entrypoint of the TOKIWA image. One image serves every role:
#
#   (no arguments)                        -> tokiwa serve
#   serve | gate run ... | agent run ...  -> tokiwa <arguments>   (tokiwa sub-commands and options)
#   tokiwa ... | sh | python ...          -> executed as given
#
# `exec` keeps the process as PID 1's direct child so SIGTERM from `docker stop` reaches it
# (compose sets `init: true`, so tini/docker-init reaps zombies).
set -eu

if [ "$#" -eq 0 ]; then
    set -- serve
fi

case "$1" in
    -* | serve | version | user | token | agent | gate | intel | eval | sim)
        set -- tokiwa "$@"
        ;;
    *)
        # Not an executable on PATH -> most likely a tokiwa sub-command added after this script was written.
        if ! command -v "$1" >/dev/null 2>&1; then
            set -- tokiwa "$@"
        fi
        ;;
esac

data_dir="${TOKIWA_SERVER__DATA_DIR:-/data}"
if [ "$1" = "tokiwa" ] && [ -d "$data_dir" ] && [ ! -w "$data_dir" ]; then
    echo "docker-entrypoint: WARNING: $data_dir is not writable by uid $(id -u)." >&2
    echo "  For a bind mount run: sudo chown -R $(id -u):$(id -g) <host dir>  (see docs/deploy.md)" >&2
fi

exec "$@"
