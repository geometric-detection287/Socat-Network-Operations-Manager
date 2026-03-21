#======================================================================
# Makefile - Socat Network Operations Manager
#======================================================================
#
# Synopsis   : Build, test, install, and package socat_manager.sh.
#
# Targets    :
#   help             - Show all targets with descriptions
#   check-deps       - Verify all prerequisites
#   lint             - Run ShellCheck static analysis
#   test             - Run full test suite (lint + BATS)
#   test-unit        - Run unit tests only (fast)
#   test-integration - Run integration tests only
#   install          - Install system-wide command
#   uninstall        - Remove system-wide installation
#   venv             - Create isolated virtual environment
#   dist             - Build release tarballs + checksums
#   clean            - Remove build artifacts
#
# Usage      :
#   make install                      # Default paths (requires sudo)
#   make install PREFIX=/usr/local    # Custom prefix
#   make test                         # Full lint + test suite
#   make venv VENV_DIR=./my-env       # Custom venv location
#
# Version    : 1.0.0
#======================================================================

# =====================================================================
# CONFIGURATION
# =====================================================================

VERSION     := $(shell grep -m1 'SCRIPT_VERSION=' socat_manager.sh 2>/dev/null | cut -d'"' -f2)
SCRIPT      := socat_manager.sh

# Installation paths
PREFIX      ?= /opt/tools/socat-manager
BINDIR      ?= /usr/local/bin
DESTDIR     ?=
INSTALL_DIR  = $(DESTDIR)$(PREFIX)
BIN_TARGET   = $(DESTDIR)$(BINDIR)/socat-manager

# Virtual environment
VENV_DIR    ?= ./socat-manager-venv

# Distribution
DIST_DIR    := dist
DIST_NAME   := socat-manager-v$(VERSION)

# Docs included in distribution and installation
DOCS        := README.md USAGE_GUIDE.md CHANGELOG.md SECURITY.md \
               CODE_OF_CONDUCT.md CONTRIBUTING.md LICENSE

# Tool paths (override for non-standard installs)
BATS        := bats
SHELLCHECK  := shellcheck

# =====================================================================
# PHONY DECLARATIONS
# =====================================================================

.PHONY: help check-deps lint test test-unit test-integration \
        install uninstall verify venv dist clean _check-socat

.DEFAULT_GOAL := help

# =====================================================================
# HELP
# =====================================================================

help: ## Show this help message
	@echo ""
	@echo "  Socat Network Operations Manager v$(VERSION)"
	@echo "  ──────────────────────────────────────────────"
	@echo ""
	@echo "  Usage: make <target> [VARIABLE=value ...]"
	@echo ""
	@echo "  Targets:"
	@grep -E '^[a-zA-Z_-]+:.*##' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*##"}; {printf "    \033[36m%-20s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "  Variables:"
	@echo "    PREFIX       = $(PREFIX)"
	@echo "    BINDIR       = $(BINDIR)"
	@echo "    VENV_DIR     = $(VENV_DIR)"
	@echo "    DESTDIR      = $(DESTDIR)"
	@echo ""
	@echo "  Examples:"
	@echo "    make install                                              # System-wide (sudo)"
	@echo "    make install PREFIX=~/.local/socat-manager BINDIR=~/.local/bin  # User-local"
	@echo "    make test                                                 # Full test suite"
	@echo "    make venv VENV_DIR=/opt/engagements/alpha/env             # Custom venv"
	@echo "    make dist                                                 # Release tarballs"
	@echo ""

# =====================================================================
# DEPENDENCY CHECKS
# =====================================================================

check-deps: ## Verify all required and optional dependencies
	@echo ""
	@echo "  Checking dependencies..."
	@echo "  ───────────────────────"
	@echo ""
	@echo "  Required:"
	@printf "    %-14s" "bash (4.4+):"
	@bash_ver=$$(bash --version 2>/dev/null | head -1 | grep -oP '\d+\.\d+' | head -1) && \
		major=$$(echo "$$bash_ver" | cut -d. -f1) && \
		minor=$$(echo "$$bash_ver" | cut -d. -f2) && \
		if [ "$$major" -gt 4 ] || { [ "$$major" -eq 4 ] && [ "$$minor" -ge 4 ]; }; then \
			echo "✓ $$bash_ver"; \
		else \
			echo "✗ $$bash_ver (need 4.4+)"; \
		fi
	@printf "    %-14s" "socat:"
	@if command -v socat >/dev/null 2>&1; then \
		echo "✓ found"; \
	else \
		echo "✗ not found  →  sudo apt-get install -y socat"; \
	fi
	@printf "    %-14s" "setsid:"
	@if command -v setsid >/dev/null 2>&1; then \
		echo "✓ found"; \
	else \
		echo "✗ not found  →  sudo apt-get install -y util-linux"; \
	fi
	@echo ""
	@echo "  Testing:"
	@printf "    %-14s" "bats:"
	@if command -v $(BATS) >/dev/null 2>&1; then \
		echo "✓ $$($(BATS) --version 2>/dev/null)"; \
	else \
		echo "✗ not found  →  https://github.com/bats-core/bats-core"; \
	fi
	@printf "    %-14s" "shellcheck:"
	@if command -v $(SHELLCHECK) >/dev/null 2>&1; then \
		echo "✓ $$($(SHELLCHECK) --version 2>/dev/null | grep '^version:' | awk '{print $$2}')"; \
	else \
		echo "✗ not found  →  sudo apt-get install -y shellcheck"; \
	fi
	@echo ""
	@echo "  Optional:"
	@printf "    %-14s" "openssl:"
	@if command -v openssl >/dev/null 2>&1; then echo "✓ found"; else echo "- not found (tunnel mode auto-cert)"; fi
	@printf "    %-14s" "ss:"
	@if command -v ss >/dev/null 2>&1; then echo "✓ found"; else echo "- not found (iproute2)"; fi
	@printf "    %-14s" "lsof:"
	@if command -v lsof >/dev/null 2>&1; then echo "✓ found"; else echo "- not found"; fi
	@printf "    %-14s" "pstree:"
	@if command -v pstree >/dev/null 2>&1; then echo "✓ found"; else echo "- not found (psmisc)"; fi
	@echo ""

# =====================================================================
# LINTING
# =====================================================================

lint: ## Run ShellCheck static analysis on the main script
	@echo ""
	@if ! command -v $(SHELLCHECK) >/dev/null 2>&1; then \
		echo "  ⚠ ShellCheck not found — skipping lint"; \
		echo "  Install: sudo apt-get install -y shellcheck"; \
		echo ""; \
		exit 0; \
	fi
	@echo "  Running ShellCheck..."
	@$(SHELLCHECK) --shell=bash --severity=warning $(SCRIPT) \
		&& echo "  ✓ ShellCheck passed" \
		|| { echo "  ✗ ShellCheck found issues"; exit 1; }
	@if [ -f bin/socat-manager ]; then \
		$(SHELLCHECK) --shell=bash --severity=warning bin/socat-manager \
			&& echo "  ✓ ShellCheck passed (bin/socat-manager)" \
			|| { echo "  ✗ ShellCheck found issues in bin/socat-manager"; exit 1; }; \
	fi
	@echo ""

# =====================================================================
# TESTING
# =====================================================================

test: lint test-unit test-integration ## Run full test suite (lint + all BATS tests)
	@echo ""
	@echo "  ════════════════════════════════════════"
	@echo "  ✓ All tests passed"
	@echo "  ════════════════════════════════════════"
	@echo ""

test-unit: ## Run unit tests only (validation + session functions)
	@echo ""
	@echo "  Running unit tests..."
	@$(BATS) tests/unit/
	@echo ""

test-integration: ## Run integration tests only (lifecycle, dual-stack, capture)
	@echo ""
	@echo "  Running integration tests..."
	@$(BATS) tests/integration/
	@echo ""

# =====================================================================
# PRE-INSTALL VALIDATION
# =====================================================================

_check-socat:
	@printf "  Checking socat... "
	@if command -v socat >/dev/null 2>&1; then \
		echo "✓ found"; \
	else \
		echo "✗ not found"; \
		echo ""; \
		echo "  ERROR: socat is required but not installed."; \
		echo "  Install: sudo apt-get install -y socat"; \
		echo ""; \
		exit 1; \
	fi
	@printf "  Checking bash 4.4+... "
	@bash_ver=$$(bash --version 2>/dev/null | head -1 | grep -oP '\d+\.\d+' | head -1) && \
		major=$$(echo "$$bash_ver" | cut -d. -f1) && \
		minor=$$(echo "$$bash_ver" | cut -d. -f2) && \
		if [ "$$major" -gt 4 ] || { [ "$$major" -eq 4 ] && [ "$$minor" -ge 4 ]; }; then \
			echo "✓ $$bash_ver"; \
		else \
			echo "✗ $$bash_ver (need 4.4+)"; \
			exit 1; \
		fi

# =====================================================================
# INSTALL
# =====================================================================

install: _check-socat ## Install system-wide command (requires sudo for default paths)
	@echo ""
	@echo "  Installing socat-manager v$(VERSION)..."
	@echo "  ────────────────────────────────────────"
	@echo "  Script:  $(INSTALL_DIR)/$(SCRIPT)"
	@echo "  Command: $(BIN_TARGET)"
	@echo ""
	@# Create installation directory and runtime subdirectories
	@mkdir -p "$(INSTALL_DIR)"
	@mkdir -p "$(INSTALL_DIR)/sessions" && chmod 700 "$(INSTALL_DIR)/sessions"
	@mkdir -p "$(INSTALL_DIR)/logs"
	@mkdir -p "$(INSTALL_DIR)/certs"
	@mkdir -p "$(INSTALL_DIR)/conf"
	@# Copy main script
	@cp $(SCRIPT) "$(INSTALL_DIR)/$(SCRIPT)"
	@chmod 755 "$(INSTALL_DIR)/$(SCRIPT)"
	@# Copy documentation
	@for doc in $(DOCS); do \
		if [ -f "$$doc" ]; then cp "$$doc" "$(INSTALL_DIR)/$$doc"; fi; \
	done
	@# Copy .shellcheckrc
	@test -f .shellcheckrc && cp .shellcheckrc "$(INSTALL_DIR)/" || true
	@# Copy tests if present
	@if [ -d tests ]; then \
		cp -r tests "$(INSTALL_DIR)/tests"; \
		chmod +x "$(INSTALL_DIR)/tests/stubs/"* 2>/dev/null || true; \
	fi
	@# Install wrapper to BINDIR (patches PREFIX into the wrapper)
	@mkdir -p "$(DESTDIR)$(BINDIR)"
	@sed 's|SOCAT_MANAGER_HOME="$${SOCAT_MANAGER_HOME:-/opt/tools/socat-manager}"|SOCAT_MANAGER_HOME="$${SOCAT_MANAGER_HOME:-$(PREFIX)}"|' \
		bin/socat-manager > "$(BIN_TARGET)"
	@chmod 755 "$(BIN_TARGET)"
	@echo ""
	@echo "  ✓ Installed successfully"
	@echo ""
	@echo "  Verify:  socat-manager --version"
	@echo "  Help:    socat-manager --help"
	@echo ""

# =====================================================================
# UNINSTALL
# =====================================================================

uninstall: ## Remove system-wide installation
	@echo ""
	@echo "  Uninstalling socat-manager..."
	@echo "  ─────────────────────────────"
	@if [ -f "$(BIN_TARGET)" ]; then \
		rm -f "$(BIN_TARGET)"; \
		echo "  Removed: $(BIN_TARGET)"; \
	else \
		echo "  Not found: $(BIN_TARGET) (skipped)"; \
	fi
	@if [ -d "$(INSTALL_DIR)" ]; then \
		echo ""; \
		echo "  WARNING: This removes the installation directory and all runtime data"; \
		echo "  (sessions, logs, certificates): $(INSTALL_DIR)"; \
		echo ""; \
		printf "  Continue? [y/N] "; \
		read -r confirm; \
		if [ "$$confirm" = "y" ] || [ "$$confirm" = "Y" ]; then \
			rm -rf "$(INSTALL_DIR)"; \
			echo "  Removed: $(INSTALL_DIR)"; \
		else \
			echo "  Skipped. Remove manually: rm -rf $(INSTALL_DIR)"; \
		fi; \
	else \
		echo "  Not found: $(INSTALL_DIR) (skipped)"; \
	fi
	@echo ""
	@echo "  ✓ Uninstall complete"
	@echo ""

# =====================================================================
# POST-INSTALL VERIFICATION
# =====================================================================

verify: ## Verify installation is working correctly
	@echo ""
	@echo "  Verifying socat-manager installation..."
	@echo "  ────────────────────────────────────────"
	@# Check wrapper is on PATH
	@printf "  Command on PATH:  "
	@if command -v socat-manager >/dev/null 2>&1; then \
		echo "✓ $$(command -v socat-manager)"; \
	else \
		echo "✗ socat-manager not found on PATH"; \
		echo "    Ensure $(BINDIR) is on your PATH"; \
		exit 1; \
	fi
	@# Check version output
	@printf "  Version output:   "
	@ver_output=$$(socat-manager --version 2>&1) && \
		echo "✓ $$ver_output" || \
		{ echo "✗ socat-manager --version failed"; exit 1; }
	@# Check install directory
	@printf "  Install directory: "
	@if [ -d "$(INSTALL_DIR)" ]; then \
		echo "✓ $(INSTALL_DIR)"; \
	else \
		echo "✗ $(INSTALL_DIR) not found"; \
		exit 1; \
	fi
	@# Check runtime directories
	@printf "  Runtime dirs:     "
	@if [ -d "$(INSTALL_DIR)/sessions" ] && [ -d "$(INSTALL_DIR)/logs" ]; then \
		echo "✓ sessions/ logs/ certs/ conf/"; \
	else \
		echo "✗ missing runtime directories"; \
		exit 1; \
	fi
	@# Check socat dependency
	@printf "  socat available:  "
	@if command -v socat >/dev/null 2>&1; then \
		echo "✓ found"; \
	else \
		echo "⚠ not found (install before use)"; \
	fi
	@echo ""
	@echo "  ✓ Installation verified"
	@echo ""

# =====================================================================
# VIRTUAL ENVIRONMENT
# =====================================================================

venv: ## Create an isolated virtual environment
	@echo ""
	@echo "  Creating virtual environment at: $(VENV_DIR)"
	@echo "  ──────────────────────────────────────────────"
	@mkdir -p "$(VENV_DIR)/sessions"
	@mkdir -p "$(VENV_DIR)/logs"
	@mkdir -p "$(VENV_DIR)/certs"
	@mkdir -p "$(VENV_DIR)/conf"
	@chmod 700 "$(VENV_DIR)/sessions"
	@cp $(SCRIPT) "$(VENV_DIR)/$(SCRIPT)"
	@chmod +x "$(VENV_DIR)/$(SCRIPT)"
	@for doc in $(DOCS); do \
		if [ -f "$$doc" ]; then cp "$$doc" "$(VENV_DIR)/$$doc"; fi; \
	done
	@cp templates/activate.sh "$(VENV_DIR)/activate.sh"
	@chmod +x "$(VENV_DIR)/activate.sh"
	@echo ""
	@echo "  ✓ Virtual environment created"
	@echo ""
	@echo "  Activate:    source $(VENV_DIR)/activate.sh"
	@echo "  Use:         socat-manager listen --port 8080"
	@echo "  Deactivate:  deactivate_socat"
	@echo ""

# =====================================================================
# DISTRIBUTION
# =====================================================================

dist: ## Build release tarballs and SHA256 checksums
	@echo ""
	@echo "  Building distribution v$(VERSION)..."
	@echo "  ─────────────────────────────────────"
	@mkdir -p $(DIST_DIR)
	@# --- Source tarball ---
	@rm -rf /tmp/$(DIST_NAME)
	@mkdir -p /tmp/$(DIST_NAME)/bin
	@mkdir -p /tmp/$(DIST_NAME)/templates
	@cp $(SCRIPT) Makefile /tmp/$(DIST_NAME)/
	@cp bin/socat-manager /tmp/$(DIST_NAME)/bin/
	@cp templates/activate.sh /tmp/$(DIST_NAME)/templates/
	@test -f .shellcheckrc && cp .shellcheckrc /tmp/$(DIST_NAME)/ || true
	@test -f .gitignore && cp .gitignore /tmp/$(DIST_NAME)/ || true
	@for doc in $(DOCS); do test -f "$$doc" && cp "$$doc" /tmp/$(DIST_NAME)/ || true; done
	@if [ -d tests ]; then \
		cp -r tests /tmp/$(DIST_NAME)/tests; \
		chmod +x /tmp/$(DIST_NAME)/tests/stubs/* 2>/dev/null || true; \
	fi
	@tar czf $(DIST_DIR)/$(DIST_NAME).tar.gz -C /tmp $(DIST_NAME)
	@echo "  Created: $(DIST_DIR)/$(DIST_NAME).tar.gz"
	@# --- Venv example tarball ---
	@rm -rf /tmp/$(DIST_NAME)-venv
	@mkdir -p /tmp/$(DIST_NAME)-venv/sessions
	@mkdir -p /tmp/$(DIST_NAME)-venv/logs
	@mkdir -p /tmp/$(DIST_NAME)-venv/certs
	@mkdir -p /tmp/$(DIST_NAME)-venv/conf
	@cp $(SCRIPT) /tmp/$(DIST_NAME)-venv/
	@chmod +x /tmp/$(DIST_NAME)-venv/$(SCRIPT)
	@cp templates/activate.sh /tmp/$(DIST_NAME)-venv/
	@chmod +x /tmp/$(DIST_NAME)-venv/activate.sh
	@chmod 700 /tmp/$(DIST_NAME)-venv/sessions
	@for doc in $(DOCS); do test -f "$$doc" && cp "$$doc" /tmp/$(DIST_NAME)-venv/ || true; done
	@tar czf $(DIST_DIR)/$(DIST_NAME)-venv-example.tar.gz -C /tmp $(DIST_NAME)-venv
	@echo "  Created: $(DIST_DIR)/$(DIST_NAME)-venv-example.tar.gz"
	@# --- Checksums ---
	@cd $(DIST_DIR) && sha256sum *.tar.gz > SHA256SUMS.txt
	@echo "  Created: $(DIST_DIR)/SHA256SUMS.txt"
	@echo ""
	@cat $(DIST_DIR)/SHA256SUMS.txt | sed 's/^/    /'
	@echo ""
	@rm -rf /tmp/$(DIST_NAME) /tmp/$(DIST_NAME)-venv
	@echo "  ✓ Distribution ready in $(DIST_DIR)/"
	@echo ""

# =====================================================================
# CLEAN
# =====================================================================

clean: ## Remove build artifacts and distribution packages
	@echo ""
	@echo "  Cleaning..."
	@rm -rf $(DIST_DIR)
	@rm -rf /tmp/socat-manager-v*
	@echo "  ✓ Clean"
	@echo ""
