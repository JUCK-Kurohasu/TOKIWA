# TOKIWA developer shortcuts. `make help` lists targets.
# Python runs in backend/ via uv, the UI in frontend/ via npm (see AGENTS.md).

SHELL := /bin/bash
.DEFAULT_GOAL := help

UV       ?= uv
NPM      ?= npm
DOCKER   ?= docker
COMPOSE  ?= $(DOCKER) compose
IMAGE    ?= tokiwa:local
SEED_URL ?= http://127.0.0.1:8788
# Pass the root .env to compose only when it exists.
COMPOSE_FILE_ARGS := -f deploy/compose.yaml $(if $(wildcard .env),--env-file .env,)

.PHONY: help install dev test test-backend test-frontend lint lint-backend lint-frontend format typecheck \
        build seed ci docker docker-smoke up down logs lab lab-down clean

help: ## Show this help
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z_-]+:.*## / {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

install: ## Install backend (uv) and frontend (npm) dependencies
	cd backend && $(UV) sync
	cd frontend && $(NPM) ci --no-audit --no-fund

dev: ## Run API (:8788, reload) + UI (:5173) together
	./scripts/dev.sh

test: test-backend test-frontend ## Run all tests

test-backend: ## pytest
	cd backend && $(UV) run pytest

test-frontend: ## vitest (passes when there are no tests yet)
	cd frontend && $(NPM) test -- --passWithNoTests

lint: lint-backend lint-frontend ## ruff + biome + TypeScript typecheck

lint-backend: ## ruff check + format check (backend, scripts, deploy)
	cd backend && $(UV) run ruff check src tests ../scripts ../deploy
	cd backend && $(UV) run ruff format --check src tests ../scripts ../deploy

lint-frontend: ## tsc --noEmit + biome
	cd frontend && $(NPM) run typecheck
	cd frontend && $(NPM) run lint

format: ## Auto-fix formatting (ruff, biome)
	cd backend && $(UV) run ruff check --fix src tests ../scripts ../deploy
	cd backend && $(UV) run ruff format src tests ../scripts ../deploy
	cd frontend && $(NPM) run lint:fix

typecheck: ## mypy (informational) + tsc
	-cd backend && $(UV) run mypy src
	cd frontend && $(NPM) run typecheck

build: ## Production build of the UI (frontend/dist, served by `tokiwa serve`)
	cd frontend && $(NPM) run build

seed: ## Send synthetic demo events to a local server (SEED_URL, default :8788)
	@token="$${TOKIWA_INGEST_TOKEN:-}"; \
	if [ -z "$$token" ]; then token="$$(cd backend && $(UV) run --quiet tokiwa token create seed-demo --scope ingest)"; fi; \
	TOKIWA_INGEST_TOKEN="$$token" python3 scripts/seed_demo.py --url "$(SEED_URL)"

ci: lint test build ## What CI runs (minus docker)
	cd backend && $(UV) run python ../scripts/seed_demo.py --validate

docker: ## Build the all-in-one image (IMAGE=tokiwa:local)
	$(DOCKER) build -f deploy/Dockerfile -t $(IMAGE) .

docker-smoke: ## Smoke-test the image (health, UI, ingest, restart)
	./scripts/docker-smoke.sh $(IMAGE)

up: ## Start deploy/compose.yaml (uses .env when present)
	$(COMPOSE) $(COMPOSE_FILE_ARGS) up -d --build --wait

down: ## Stop deploy/compose.yaml (volumes are kept)
	$(COMPOSE) $(COMPOSE_FILE_ARGS) down

logs: ## Follow server logs
	$(COMPOSE) $(COMPOSE_FILE_ARGS) logs -f tokiwa

lab: ## Start the lab (lab/compose.yaml: victim + gate + simulator)
	$(COMPOSE) -f lab/compose.yaml up --build

lab-down: ## Stop the lab
	$(COMPOSE) -f lab/compose.yaml down

clean: ## Remove build artefacts and caches (keeps data/ and .venv)
	rm -rf frontend/dist frontend/node_modules/.tmp
	find backend scripts deploy -type d \( -name __pycache__ -o -name .pytest_cache -o -name .ruff_cache -o -name .mypy_cache \) -prune -exec rm -rf {} +
