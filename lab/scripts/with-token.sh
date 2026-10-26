#!/bin/sh
# Read an ingest token from the shared volume into an environment variable, then exec the command.
#   TOKIWA_TOKEN_FILE  path of the token file written by init-tokens.sh
#   TOKIWA_TOKEN_ENV   variable to export (e.g. TOKIWA_GATE__INGEST_TOKEN)
# Keeps tokens out of compose files, `docker inspect` and process arguments.
set -eu

: "${TOKIWA_TOKEN_FILE:?TOKIWA_TOKEN_FILE is required}"
: "${TOKIWA_TOKEN_ENV:?TOKIWA_TOKEN_ENV is required}"

i=0
while [ ! -s "$TOKIWA_TOKEN_FILE" ]; do
    i=$((i + 1))
    if [ "$i" -gt 60 ]; then
        echo "with-token: $TOKIWA_TOKEN_FILE not found after 60s (did tokiwa-init run?)" >&2
        exit 1
    fi
    sleep 1
done

token="$(tr -d '\r\n' < "$TOKIWA_TOKEN_FILE")"
export "$TOKIWA_TOKEN_ENV=$token"
unset token
exec "$@"
