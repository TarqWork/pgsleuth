# pgsleuth top-level Makefile
# Unified dev/test/lint across the Rust agent and Python brain.
#
# Discipline rule (see docs/design/000-architecture.md): the two stacks
# must always be testable from one command. If you ever find yourself
# saying "but it works in just the Rust side" — that's a smell, fix it here.

.PHONY: help dev test lint fmt build clean check ci \
        fixture-up fixture-down fixture-logs fixture-status fixture-psql fixture-reset

# Compose file for the dev Postgres fixture (primary + 2 replicas with
# pg_stat_statements + auto_explain). See infra/docker/pg-fixture/README.md.
FIXTURE_COMPOSE := infra/docker/pg-fixture.compose.yml

help:
	@echo "pgsleuth — top-level targets:"
	@echo "  make dev             — install dev deps + bring up the Postgres fixture"
	@echo "  make test            — run all tests (Rust + Python)"
	@echo "  make lint            — run all linters (clippy + ruff + mypy)"
	@echo "  make fmt             — format both stacks (rustfmt + ruff format)"
	@echo "  make build           — build the agent in release mode"
	@echo "  make check           — fast type/syntax check, no tests"
	@echo "  make ci              — what CI runs: lint + test"
	@echo "  make clean           — remove build artifacts"
	@echo ""
	@echo "  Postgres dev fixture (primary :5432, replicas :5433/:5434):"
	@echo "  make fixture-up      — bring it up (detached)"
	@echo "  make fixture-down    — stop it (keeps named volumes)"
	@echo "  make fixture-reset   — stop it + drop volumes (full re-bootstrap next time)"
	@echo "  make fixture-status  — docker compose ps"
	@echo "  make fixture-logs    — tail compose logs"
	@echo "  make fixture-psql    — open psql on the primary as postgres"

dev:
	@echo "==> Rust toolchain"
	@command -v cargo >/dev/null 2>&1 || { echo "Install Rust first: https://rustup.rs"; exit 1; }
	@cargo --version
	@echo "==> Python toolchain"
	@command -v python3 >/dev/null 2>&1 || { echo "Install Python 3.11+ first"; exit 1; }
	@python3 --version
	@echo "==> Installing brain dev deps"
	cd brain && python3 -m pip install -e ".[dev]"
	@echo "==> Bringing up the Postgres dev fixture"
	@command -v docker >/dev/null 2>&1 || { echo "Install Docker first: https://docs.docker.com/get-docker/"; exit 1; }
	$(MAKE) fixture-up
	@echo "==> Done. Run 'make test' to verify."

# --- dev fixture --------------------------------------------------------------
fixture-up:
	docker compose -f $(FIXTURE_COMPOSE) up -d
	@echo "==> primary: postgres://postgres@localhost:5432/postgres"
	@echo "    replica-1: postgres://postgres@localhost:5433/postgres"
	@echo "    replica-2: postgres://postgres@localhost:5434/postgres"
	@echo "    agent:    postgres://pgsleuth_agent:pgsleuth@localhost:5432/postgres"

fixture-down:
	docker compose -f $(FIXTURE_COMPOSE) down

fixture-reset:
	docker compose -f $(FIXTURE_COMPOSE) down -v

fixture-status:
	docker compose -f $(FIXTURE_COMPOSE) ps

fixture-logs:
	docker compose -f $(FIXTURE_COMPOSE) logs -f

fixture-psql:
	docker compose -f $(FIXTURE_COMPOSE) exec pg-primary psql -U postgres -d postgres

test: test-rust test-python

test-rust:
	cargo test --workspace

test-python:
	cd brain && python3 -m pytest -q

lint: lint-rust lint-python

lint-rust:
	cargo clippy --workspace --all-targets -- -D warnings
	cargo fmt --all -- --check

lint-python:
	cd brain && python3 -m ruff check .
	cd brain && python3 -m ruff format --check .
	cd brain && python3 -m mypy pgsleuth_brain

fmt:
	cargo fmt --all
	cd brain && python3 -m ruff format .

build:
	cargo build --release --workspace

check:
	cargo check --workspace --all-targets
	cd brain && python3 -m mypy pgsleuth_brain

ci: lint test

clean:
	cargo clean
	rm -rf brain/.pytest_cache brain/.mypy_cache brain/.ruff_cache
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
