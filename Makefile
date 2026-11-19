ORACLE_REPO ?= $(HOME)/Code/samuel-stidham/safetybox
# src/reference.rs names the Go release and its commit. A move to a new
# release changes that file alone.
REFERENCE   := src/reference.rs
ORACLE_REF  ?= $(shell sed -n 's/^pub const COMMIT: &str = "\([0-9a-f]\{40\}\)";$$/\1/p' $(REFERENCE))
ORACLE_TAG  ?= $(shell sed -n 's/^ *"\(v[0-9][0-9.]*\)"$$/\1/p' $(REFERENCE))

ifeq ($(strip $(ORACLE_REF)),)
$(error $(REFERENCE) names no commit)
endif
ifeq ($(strip $(ORACLE_TAG)),)
$(error $(REFERENCE) names no tag)
endif

ORACLE_DIR   := target/oracle
ORACLE_SRC   := $(ORACLE_DIR)/src
ORACLE_BIN   := $(ORACLE_DIR)/safetybox
ORACLE_STAMP := $(ORACLE_DIR)/.built-$(ORACLE_REF)

.DEFAULT_GOAL := help

.PHONY: help
help: ## Display all available targets.
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-14s\033[0m %s\n", $$1, $$2}'

$(ORACLE_STAMP):
	rm -rf $(ORACLE_DIR)
	mkdir -p $(ORACLE_SRC)
	git -C $(ORACLE_REPO) archive $(ORACLE_REF) | tar -x -C $(ORACLE_SRC)
	cd $(ORACLE_SRC) && CGO_ENABLED=0 go build -ldflags "-X main.version=$(ORACLE_TAG)" -o ../safetybox .
	touch $@

.PHONY: oracle-ref
oracle-ref: ## Print the commit of the Go reference.
	@echo $(ORACLE_REF)

.PHONY: oracle
oracle: $(ORACLE_STAMP) ## Build the Go reference binary into target/oracle/.

.PHONY: test
test: ## Run the conformance suite against the Rust port.
	cargo test

.PHONY: test-oracle
test-oracle: oracle ## Run the conformance suite against the Go reference.
	SAFETYBOX_BIN=$(abspath $(ORACLE_BIN)) cargo test --test conformance

.PHONY: golden
golden: oracle ## Re-capture the help snapshots from the Go reference.
	UPDATE_GOLDEN=1 SAFETYBOX_BIN=$(abspath $(ORACLE_BIN)) cargo test --test conformance cli::

.PHONY: parity
parity: oracle ## Check every Go test is ported or listed in tests/PARITY.md.
	./tests/check-parity.sh $(ORACLE_SRC)

.PHONY: lint
lint: ## Run rustfmt and clippy over the crate and its tests.
	cargo fmt --all -- --check
	cargo clippy --all-targets -- -D warnings

.PHONY: clean
clean: ## Remove build output, the Go reference included.
	cargo clean
