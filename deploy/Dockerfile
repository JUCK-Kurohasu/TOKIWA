# TOKIWA all-in-one image: API server + built web UI, and the same CLI for gate / agent / sim.
#
#   docker build -f deploy/Dockerfile -t tokiwa:local .        # build context = repository root
#   docker run -p 8788:8788 -v tokiwa-data:/data tokiwa:local    # -> tokiwa serve
#   docker run tokiwa:local gate run --upstream http://app:3000  # -> tokiwa gate run ...
#
# Requires BuildKit (Docker Engine 25+; default builder). Base images are pinned; override them with
# --build-arg (e.g. a registry mirror) without editing this file. See docs/deploy.md.

ARG NODE_IMAGE=node:22.23.4-trixie-slim
ARG PYTHON_IMAGE=python:3.12.15-slim-trixie
ARG UV_IMAGE=ghcr.io/astral-sh/uv:0.11.32

# uv binary only (COPY --from cannot expand build args, so it gets its own stage).
FROM ${UV_IMAGE} AS uv

# ---------------------------------------------------------------------------------------------------------
# 1) Frontend: vite build -> /src/frontend/dist
# ---------------------------------------------------------------------------------------------------------
FROM ${NODE_IMAGE} AS frontend
WORKDIR /src/frontend
ENV NPM_CONFIG_UPDATE_NOTIFIER=false \
    NPM_CONFIG_FUND=false \
    NPM_CONFIG_AUDIT=false
COPY frontend/package.json frontend/package-lock.json ./
RUN --mount=type=cache,target=/root/.npm,sharing=locked \
    npm ci
COPY frontend/ ./
RUN npm run build

# ---------------------------------------------------------------------------------------------------------
# 2) Backend: locked, non-editable virtualenv in /app/.venv (no dev dependencies, no source tree needed)
# ---------------------------------------------------------------------------------------------------------
FROM ${PYTHON_IMAGE} AS backend
COPY --from=uv /uv /uvx /usr/local/bin/
# Optional extras from backend/pyproject.toml, space separated. "postgres" adds asyncpg so the same image
# works with SQLite (default) and PostgreSQL. Build with --build-arg TOKIWA_EXTRAS="" for SQLite only.
ARG TOKIWA_EXTRAS="postgres"
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=0 \
    UV_PROJECT_ENVIRONMENT=/app/.venv
WORKDIR /src/backend
# Dependencies first (cached until uv.lock / pyproject.toml change), then the project itself.
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=backend/uv.lock,target=uv.lock \
    --mount=type=bind,source=backend/pyproject.toml,target=pyproject.toml \
    set --; for e in ${TOKIWA_EXTRAS}; do set -- "$@" --extra "$e"; done; \
    uv sync --frozen --no-dev --no-install-project "$@"
COPY backend/ ./
RUN --mount=type=cache,target=/root/.cache/uv \
    set --; for e in ${TOKIWA_EXTRAS}; do set -- "$@" --extra "$e"; done; \
    uv sync --frozen --no-dev --no-editable "$@"

# ---------------------------------------------------------------------------------------------------------
# 3) Sigma rules (rules/, owned by the sigma module): copied when present, empty rules/sigma otherwise.
#    A bind mount is used because COPY fails on a missing source.
# ---------------------------------------------------------------------------------------------------------
FROM ${PYTHON_IMAGE} AS rules
RUN --mount=type=bind,target=/ctx \
    mkdir -p /out/sigma \
    && if [ -d /ctx/rules ]; then cp -a /ctx/rules/. /out/; fi

# ---------------------------------------------------------------------------------------------------------
# 4) Runtime: python slim + venv + static UI, non-root, state in /data
# ---------------------------------------------------------------------------------------------------------
FROM ${PYTHON_IMAGE} AS runtime

ARG TOKIWA_UID=10001
ARG TOKIWA_GID=10001
ARG TOKIWA_VERSION=0.1.0

LABEL org.opencontainers.image.title="TOKIWA" \
      org.opencontainers.image.description="LLM-driven SIEM/XDR against generative-AI-driven cyber attacks" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${TOKIWA_VERSION}"

RUN groupadd --system --gid "${TOKIWA_GID}" tokiwa \
    && useradd --system --uid "${TOKIWA_UID}" --gid tokiwa --home-dir /data --no-create-home \
       --shell /usr/sbin/nologin tokiwa \
    && mkdir -p /data /etc/tokiwa \
    && chown tokiwa:tokiwa /data \
    && chmod 0750 /data

COPY --from=backend /app/.venv /app/.venv
COPY --from=rules /out /app/rules
COPY --from=frontend /src/frontend/dist /app/frontend/dist
COPY --chmod=0755 deploy/docker-entrypoint.sh /usr/local/bin/docker-entrypoint
COPY --chmod=0755 deploy/healthcheck.py /usr/local/bin/tokiwa-healthcheck

# Settings use the TOKIWA_* env convention (see backend/src/tokiwa/config.py). Everything stateful
# (SQLite DB, generated JWT secret, uploads/exports) lives under /data.
ENV PATH="/app/.venv/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TOKIWA_ENV=prod \
    TOKIWA_CONFIG=/etc/tokiwa/tokiwa.yaml \
    TOKIWA_SERVER__HOST=0.0.0.0 \
    TOKIWA_SERVER__PORT=8788 \
    TOKIWA_SERVER__STATIC_DIR=/app/frontend/dist \
    TOKIWA_SERVER__DATA_DIR=/data \
    TOKIWA_DATABASE__URL=sqlite+aiosqlite:////data/tokiwa.db \
    TOKIWA_DETECTION__SIGMA_RULE_DIRS='["/app/rules/sigma"]'

# Numeric so orchestrators (e.g. Kubernetes runAsNonRoot) can verify the user without /etc/passwd.
USER ${TOKIWA_UID}:${TOKIWA_GID}
WORKDIR /data
VOLUME ["/data"]

# 8788 = server (API + UI). 8080 = gate listener when the image runs `gate run`.
EXPOSE 8788 8080

# Probes /api/v1/health by default; TOKIWA_HEALTHCHECK_URL retargets it (gate) or disables it ("none").
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --start-interval=2s --retries=3 \
    CMD ["tokiwa-healthcheck"]

ENTRYPOINT ["docker-entrypoint"]
CMD ["serve"]
