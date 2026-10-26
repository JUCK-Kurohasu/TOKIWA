#!/usr/bin/env bash
# Smoke-test a built TOKIWA image (used by CI and `make docker-smoke`).
#
#   scripts/docker-smoke.sh [image]        # default: $TOKIWA_IMAGE or tokiwa:local
#
# Checks: entrypoint routing, non-root user, server readiness + Docker health status, UI and SPA fallback,
# token creation via `docker exec`, ingest round-trip, state persisted in /data across a restart.
# Only talks to the container on 127.0.0.1.
set -euo pipefail

IMAGE="${1:-${TOKIWA_IMAGE:-tokiwa:local}}"
PORT="${SMOKE_PORT:-28788}"
NAME="tokiwa-smoke-$$"
VOLUME="tokiwa-smoke-$$"
BASE="http://127.0.0.1:${PORT}"

cleanup() {
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    docker volume rm "$VOLUME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

step() { printf '\n--- %s\n' "$*"; }
fail() {
    echo "FAIL: $*" >&2
    docker logs --tail 60 "$NAME" >&2 2>&1 || true
    exit 1
}

wait_ready() {
    local _
    for _ in $(seq 1 60); do
        if curl -fsS "${BASE}/api/v1/health" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    fail "server did not answer /api/v1/health within 60s"
}

wait_healthy() {
    local _ status=""
    for _ in $(seq 1 45); do
        status="$(docker inspect --format '{{.State.Health.Status}}' "$NAME")"
        if [ "$status" = "healthy" ]; then
            echo "docker health: $status"
            return 0
        fi
        sleep 2
    done
    fail "container never became healthy (last status: ${status:-unknown})"
}

step "entrypoint routing ($IMAGE)"
docker run --rm "$IMAGE" version
docker run --rm "$IMAGE" tokiwa version
docker run --rm "$IMAGE" --help >/dev/null
[ "$(docker run --rm "$IMAGE" id -u)" = "10001" ] || fail "image does not run as uid 10001"
docker run --rm -e TOKIWA_HEALTHCHECK_URL=none "$IMAGE" tokiwa-healthcheck || fail "healthcheck opt-out failed"
if docker run --rm "$IMAGE" tokiwa-healthcheck 2>/dev/null; then
    fail "healthcheck reported healthy without a running server"
fi
echo "ok"

step "start server"
docker run -d --name "$NAME" -p "127.0.0.1:${PORT}:8788" -v "${VOLUME}:/data" "$IMAGE" >/dev/null
wait_ready
curl -fsS "${BASE}/api/v1/health"
echo
wait_healthy

step "web UI"
curl -fsS "${BASE}/" | grep -q '<div id="root">' || fail "index.html not served at /"
curl -fsS "${BASE}/alerts" | grep -q '<div id="root">' || fail "SPA fallback not served"
asset="$(curl -fsS "${BASE}/" | grep -o '/assets/[^"]*\.js' | head -n 1)"
[ -n "$asset" ] || fail "no JS asset referenced by index.html"
curl -fsS -o /dev/null "${BASE}${asset}" || fail "asset ${asset} not served"
echo "ok (${asset})"

step "admin setup + ingest round-trip"
curl -fsS -X POST "${BASE}/api/v1/auth/setup" -H 'content-type: application/json' \
    -d '{"username":"admin","password":"smoke-test-password"}' >/dev/null || fail "auth setup failed"
token="$(docker exec "$NAME" tokiwa token create smoke --scope ingest)"
case "$token" in tkw_*) ;; *) fail "unexpected token format" ;; esac
event='{"events":[{"kind":"http","dataset":"smoke.http","source":{"ip":"203.0.113.9"},"http":{"method":"GET","path":"/","status":200}}]}'
curl -fsS -X POST "${BASE}/api/v1/ingest/events" -H "X-Tokiwa-Token: ${token}" \
    -H 'content-type: application/json' -d "$event" | grep -q '"accepted":1' || fail "ingest did not accept the event"
docker exec "$NAME" test -s /data/tokiwa.db || fail "sqlite database not under /data"
docker exec "$NAME" test -s /data/secret.key || fail "JWT secret not persisted under /data"
echo "ok"

step "restart keeps state"
docker restart "$NAME" >/dev/null
wait_ready
curl -fsS -X POST "${BASE}/api/v1/auth/login" -H 'content-type: application/json' \
    -d '{"username":"admin","password":"smoke-test-password"}' >/dev/null || fail "login after restart failed"
curl -fsS -X POST "${BASE}/api/v1/ingest/events" -H "X-Tokiwa-Token: ${token}" \
    -H 'content-type: application/json' -d "$event" | grep -q '"accepted":1' || fail "token lost after restart"
echo "ok"

printf '\nSMOKE TEST PASSED: %s\n' "$IMAGE"
