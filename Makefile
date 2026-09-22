PYTHON ?= python3

.DEFAULT_GOAL := help

.PHONY: help run test browser-test compile check package install-user uninstall-user

help: ## Show available targets
	@awk 'BEGIN {FS = ":.*## "; print "Luma OS developer targets:\n"} /^[a-zA-Z0-9_-]+:.*## / {printf "  %-16s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

run: ## Run the local developer MVP from source
	@./scripts/run.sh

test: ## Run dependency-free unit tests
	@$(PYTHON) -m unittest discover -s tests -p 'test_*.py' -v

browser-test: ## Run the optional real UI journey (requires Node 22+ and Chrome)
	@node tests/browser_test.cjs

compile: ## Compile Python sources without writing inside src
	@$(PYTHON) scripts/check.py --compile-only

check: ## Validate source, tests, docs, and release metadata
	@$(PYTHON) scripts/check.py

package: ## Build deterministic source archives under dist/
	@$(PYTHON) scripts/build_release.py

install-user: ## Install to the current user account (no sudo)
	@./scripts/install-user.sh

uninstall-user: ## Print the explicit safe uninstall command
	@echo "Run ./scripts/uninstall-user.sh --yes to remove a marked user install."
