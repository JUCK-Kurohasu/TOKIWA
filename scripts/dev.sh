#!/usr/bin/env bash
# Start the TOKIWA dev stack: backend (uvicorn --reload, :8788) + frontend (vite, :5173). Ctrl-C stops both.
#
#   scripts/dev.sh                     # or: make dev
#   TOKIWA_BACKEND_PORT=8790 TOKIWA_FRONTEND_PORT=5180 scripts/dev.sh
#
# Installs dependencies on first run (uv sync / npm ci). Works with bash 3.2+ (macOS) and Linux.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKEND_PORT="${TOKIWA_BACKEND_PORT:-8788}"
FRONTEND_PORT="${TOKIWA_FRONTEND_PORT:-5173}"

die() {
    echo "dev.sh: $*" >&2
    exit 1
}
command -v uv >/dev/null 2>&1 || die "uv not found (https://docs.astral.sh/uv/)"
command -v npm >/dev/null 2>&1 || die "npm not found (Node.js 22)"

(cd "$ROOT/backend" && uv sync --quiet)
if [ ! -d "$ROOT/frontend/node_modules" ]; then
    (cd "$ROOT/frontend" && npm ci --no-audit --no-fund)
fi

# Each job gets its own process group (job control) so cleanup can stop uvicorn's reloader and vite's
# children too. stdin is detached: background jobs reading the TTY would be stopped by SIGTTIN.
set -m

cleanup() {
    trap - INT TERM EXIT
    local pgid
    for pgid in $(jobs -p); do
        kill -TERM -- "-$pgid" 2>/dev/null || true
    done
    wait 2>/dev/null || true
}
trap cleanup INT TERM EXIT

# Line-by-line prefixer (awk implementations such as mawk block-buffer their input, delaying output).
prefix() {
    local line
    while IFS= read -r line || [ -n "$line" ]; do
        printf '%s %s\n' "$1" "$line"
    done
}

(cd "$ROOT/backend" && exec uv run tokiwa serve --reload --port "$BACKEND_PORT") </dev/null 2>&1 | prefix "[api]" &
(cd "$ROOT/frontend" && TOKIWA_BACKEND="http://localhost:${BACKEND_PORT}" \
    exec npm run dev -- --port "$FRONTEND_PORT" --strictPort) </dev/null 2>&1 | prefix "[web]" &

echo "dev.sh: API http://localhost:${BACKEND_PORT}/api/docs  UI http://localhost:${FRONTEND_PORT}  (Ctrl-C to stop)"

# Exit (and stop the other one) as soon as either process ends.
while [ "$(jobs -rp | wc -l | tr -d ' ')" -ge 2 ]; do
    sleep 1
done
echo "dev.sh: a process exited, stopping the dev stack" >&2
