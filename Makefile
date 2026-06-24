# Sigil SIEM — developer & container tasks. Run `make` (or `make help`).

CARGO         ?= cargo
IMAGE         ?= sigil:latest
SIDECAR_IMAGE ?= sigil-sidecar:latest
CONFIG        ?= configs/sigil.yaml
COMPOSE       ?= docker compose -f deploy/docker-compose.yml

.DEFAULT_GOAL := help
.PHONY: help build release test fmt fmt-check lint check rl run eval sidecar \
        docker docker-sidecar docker-run up down logs clean

help: ## Show this help
	@grep -E '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) \
	  | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

## --- Rust ---------------------------------------------------------------

build: ## Build the workspace (debug)
	$(CARGO) build

release: ## Build the optimized `sigil` binary
	$(CARGO) build --release -p sigil-cli

test: ## Run all workspace tests
	$(CARGO) test --workspace

fmt: ## Format the code
	$(CARGO) fmt --all

fmt-check: ## Check formatting (no changes)
	$(CARGO) fmt --all --check

lint: ## Run clippy, denying warnings
	$(CARGO) clippy --workspace --all-targets -- -D warnings

check: fmt-check lint test ## CI gate: fmt + clippy + tests

rl: ## Build the optional RL module (excluded from the default build)
	$(CARGO) build -p sigil-correlate-rl

## --- Run ----------------------------------------------------------------

run: ## Run a node from CONFIG (override with CONFIG=path)
	$(CARGO) run -p sigil-cli -- run --config $(CONFIG)

eval: ## Run the evaluation harness (reproducible report)
	$(CARGO) run -p sigil-cli -- eval

sidecar: ## Run the Python ML sidecar (needs `pip install -e ml-sidecar`)
	cd ml-sidecar && python -m sidecar.server

## --- Frontend -----------------------------------------------------------

web-dev: ## Run the web console dev server (proxies /api → SIGIL_API)
	cd frontend && npm install && npm run dev

web-build: ## Type-check + build the web console to frontend/dist
	cd frontend && npm install && npm run check && npm run build

## --- Docker -------------------------------------------------------------

docker: ## Build the sigil image
	docker build -t $(IMAGE) .

docker-sidecar: ## Build the ML sidecar image
	docker build -f ml-sidecar/Dockerfile -t $(SIDECAR_IMAGE) .

docker-run: docker ## Build + run the sigil image (API/UI on :8080)
	docker run --rm -p 8080:8080 -p 5514:5514/udp $(IMAGE)

up: ## Start the full dev stack (sigil + sidecar + minio + redpanda)
	$(COMPOSE) up --build -d

down: ## Stop the dev stack
	$(COMPOSE) down -v

logs: ## Tail dev-stack logs
	$(COMPOSE) logs -f

## --- Housekeeping -------------------------------------------------------

clean: ## Remove build artifacts and local data
	$(CARGO) clean
	rm -rf data
