# SPUC — developer workflow shortcuts.
# Mirrors the GitHub Actions pipeline (make ci = local quality gates).

CARGO      := cargo
GUI_TARGET := -p spuc-gui

.DEFAULT_GOAL := help
.PHONY: help fmt fmt-check clippy check doc test-unit test-cli test-integration test test-gui build build-release cli web clean ci

help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

fmt: ## Format code
	$(CARGO) fmt

fmt-check: ## Verify formatting (no writes)
	$(CARGO) fmt --check

clippy: ## Lint with clippy (deny warnings)
	$(CARGO) clippy --all-targets -- -D warnings

check: ## Type-check without producing binaries
	$(CARGO) check

doc: ## Build rustdoc (no dependencies)
	$(CARGO) doc --no-deps

test-unit: ## Unit tests: core library + CLI bin (fast)
	$(CARGO) test -p spuc-core --lib
	$(CARGO) test -p spuc-cli

test-integration: ## Core integration tests (jsonrpc, cli examples, sigma; slow)
	$(CARGO) test -p spuc-core --tests

test: ## Full test suite of default members (core + cli; slow)
	$(CARGO) test

test-gui: ## GUI desktop tests (needs webkit2gtk system deps)
	$(CARGO) test -q $(GUI_TARGET)

build: ## Debug build of default members (core + cli)
	$(CARGO) build -q

build-release: ## Release build (core + cli)
	$(CARGO) build --release -q

cli: ## Build the spuc CLI binary only
	$(CARGO) build -q -p spuc-cli --bin spuc

web: ## Run the local web server (spuc web)
	$(CARGO) run -q -p spuc-cli --bin spuc -- web --no-open

clean: ## Remove cargo build artifacts
	$(CARGO) clean

ci: ## Run the CI quality pipeline locally (fmt + clippy + tests + docs)
	$(MAKE) fmt-check
	$(MAKE) clippy
	$(MAKE) test
	$(MAKE) doc
