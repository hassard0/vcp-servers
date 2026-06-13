# VCP reference implementations — one entry point for every language.
# Usage: `make` (help), `make test`, `make example`, `make demo`, `make conformance`.
# Each target is just the documented per-language command; nothing magic.

.DEFAULT_GOAL := help
.PHONY: help setup test test-ts test-py test-rs test-go \
        example example-ts example-py example-rs example-go \
        demo demo-obo conformance fmt lint clean

help: ## Show this help
	@echo "VCP reference implementations"
	@echo
	@echo "Targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'
	@echo
	@echo "Per language, you can also just cd into typescript/ python/ rust/ go/ and run the native tool."

setup: ## Install dependencies that need installing (TS)
	cd typescript && npm install

# ---- tests -----------------------------------------------------------------
test: test-ts test-py test-rs test-go ## Run every language's test suite

test-ts: ## TypeScript tests (Node 18+)
	cd typescript && npm install && npm test

test-py: ## Python tests (3.10+)
	cd python && python -m unittest discover -s . -p "test_*.py" -t .

test-rs: ## Rust tests (1.74+)
	cd rust && cargo test

test-go: ## Go tests (1.22+)
	cd go && go test ./...

# ---- the 30-line "hello VCP" example ---------------------------------------
example: example-ts example-py example-rs example-go ## Run the minimal hello example in every language

example-ts: ## TypeScript hello example
	cd typescript && npm run example

example-py: ## Python hello example
	cd python && python examples/hello.py

example-rs: ## Rust hello example
	cd rust && cargo run -p vcp-gateway --example hello

example-go: ## Go hello example
	cd go && go run ./examples/hello

# ---- the bigger end-to-end demos -------------------------------------------
demo: ## The §16 calendar demo (TypeScript)
	cd typescript && npm run demo

demo-obo: ## The §26 multi-provider on-behalf-of demo (TypeScript)
	cd typescript && npm run demo:obo

# ---- conformance -----------------------------------------------------------
conformance: ## Regenerate the shared vectors and run every suite against them
	python conformance/generate.py
	@git diff --quiet conformance/vectors || (echo "vectors drifted — commit the regenerated vectors" && exit 1)
	$(MAKE) test

# ---- housekeeping ----------------------------------------------------------
fmt: ## Format each language with its standard formatter
	-cd python && python -m ruff format . 2>/dev/null || true
	-cd rust && cargo fmt
	-cd go && gofmt -w .

lint: ## Lint where a linter is configured
	-cd rust && cargo clippy --all-targets
	-cd python && python -m ruff check . 2>/dev/null || true
	-cd go && go vet ./...

clean: ## Remove build artifacts
	-rm -rf typescript/node_modules typescript/**/dist typescript/**/*.tsbuildinfo
	-rm -rf rust/target
	-find python -name __pycache__ -type d -prune -exec rm -rf {} + 2>/dev/null || true
