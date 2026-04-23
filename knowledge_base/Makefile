# RedAmon Knowledge Base — Makefile
# Configuration defaults are sourced from kb_config.yaml (this directory).

# =============================================================================
# Configuration
# =============================================================================
# Helper macro: extract a dotted key from kb_config.yaml. Returns the second
# argument as fallback if the file/key/python is missing. Uses python (always
# present where this Makefile runs) instead of yq (less ubiquitous).
_KB_YAML := kb_config.yaml
define _kb_yaml_get
$(shell python -c "import yaml; d=yaml.safe_load(open('$(_KB_YAML)')); \
[d := d[k] for k in '$(1)'.split('.')]; print(d)" 2>/dev/null || echo "$(2)")
endef

# Execution mode: "docker" or "local". Default sourced from kb_config.yaml.
MODE ?= $(call _kb_yaml_get,runtime.mode,local)

# Container name (must match docker-compose service)
AGENT_CONTAINER ?= redamon-agent

# Default Neo4j connection (override with env vars)
# In docker mode: connects to neo4j service via internal network
# In local mode: connects to localhost
NEO4J_URI ?= bolt://localhost:7687
NEO4J_USER ?= neo4j
NEO4J_PASSWORD ?= changeme123

# Embedding model. Default sourced from kb_config.yaml (`embedder.model`).
MODEL ?= $(call _kb_yaml_get,embedder.model,intfloat/e5-large-v2)

# NVD lookback window in days. Default sourced from kb_config.yaml
# (`ingestion.nvd_lookback_days`). Only applies to standard profile.
NVD_DAYS ?= $(call _kb_yaml_get,ingestion.nvd_lookback_days,90)

# =============================================================================
# Python Environment Detection (MODE=local only)
# =============================================================================
# Priority order for which Python to use:
#   1. $(VIRTUAL_ENV) if set — any venv the user has activated (venv, uv,
#      poetry, conda, pyenv-virtualenv, etc — all export VIRTUAL_ENV).
#      Trusted as-is; user is responsible for having deps installed.
#   2. .redamon-venv/ if it exists — auto-bootstrapped from a previous run.
#   3. Otherwise → bootstrap .redamon-venv on first kb-* invocation.
#
# In docker mode, everything runs via `docker exec` so none of this applies.

MAKEFILE_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
VENV_DIR := $(MAKEFILE_DIR).redamon-venv
VENV_PYTHON := $(VENV_DIR)/bin/python
VENV_PIP := $(VENV_DIR)/bin/pip
VENV_MARKER := $(VENV_DIR)/.installed

ifeq ($(MODE),docker)
  PYTHON ?= python
  _NEEDS_BOOTSTRAP := no
else
  ifneq ($(VIRTUAL_ENV),)
    # User has a venv activated (any name, any path) — use it as-is
    PYTHON := $(VIRTUAL_ENV)/bin/python
    _NEEDS_BOOTSTRAP := no
    _ACTIVE_VENV_INFO := active: $(VIRTUAL_ENV)
  else ifneq ($(shell test -x "$(VENV_PYTHON)" && echo yes),)
    # Previously bootstrapped .redamon-venv exists on disk — use it
    PYTHON := $(VENV_PYTHON)
    _NEEDS_BOOTSTRAP := no
    _ACTIVE_VENV_INFO := using: $(VENV_DIR)
  else
    # Nothing available — bootstrap .redamon-venv on first kb-* invocation
    PYTHON := $(VENV_PYTHON)
    _NEEDS_BOOTSTRAP := yes
    _ACTIVE_VENV_INFO := will bootstrap: $(VENV_DIR)
  endif
endif

# Build the data_ingestion command — switches between docker exec and local python
ifeq ($(MODE),docker)
  KB_CMD = docker exec $(AGENT_CONTAINER) python -m knowledge_base.curation.data_ingestion \
    --neo4j-uri bolt://neo4j:7687 \
    --neo4j-user $(NEO4J_USER) \
    --neo4j-password $(NEO4J_PASSWORD) \
    --model $(MODEL) \
    --nvd-days $(NVD_DAYS)
  PY_RUN = docker exec $(AGENT_CONTAINER) python
else
  KB_CMD = "$(PYTHON)" -m knowledge_base.curation.data_ingestion \
    --neo4j-uri $(NEO4J_URI) \
    --neo4j-user $(NEO4J_USER) \
    --neo4j-password $(NEO4J_PASSWORD) \
    --model $(MODEL) \
    --nvd-days $(NVD_DAYS)
  PY_RUN = "$(PYTHON)"
endif

# =============================================================================
# Python VENV Bootstrap (internal prerequisite target)
# =============================================================================
# Runs once on first `make kb-*` invocation when no venv is available.
# Idempotent via $(VENV_MARKER) — subsequent runs see the marker and skip.
# Prints a visible banner so the user knows what's happening and why.

.PHONY: _kb_ensure_deps

_kb_ensure_deps:
ifeq ($(_NEEDS_BOOTSTRAP),yes)
	@if [ ! -f "$(VENV_MARKER)" ]; then \
		echo ""; \
		echo "=========================================================="; \
		echo "  First-run KB dependency bootstrap"; \
		echo "=========================================================="; \
		echo "  No activated venv detected (\$$VIRTUAL_ENV unset) and"; \
		echo "  $(VENV_DIR) doesn't exist yet."; \
		echo ""; \
		echo "  Creating $(VENV_DIR) and installing from"; \
		echo "  ../agentic/requirements.txt (takes 3-10 min on first run"; \
		echo "  due to torch + sentence-transformers downloads)."; \
		echo ""; \
		echo "  To use your own Python environment instead:"; \
		echo "    1. Ctrl-C now"; \
		echo "    2. Activate your venv (source .../bin/activate)"; \
		echo "    3. pip install -r ../agentic/requirements.txt"; \
		echo "    4. Re-run this make command"; \
		echo "=========================================================="; \
		echo ""; \
		if [ ! -d "$(VENV_DIR)" ]; then \
			python3 -m venv "$(VENV_DIR)" || { \
				echo "ERROR: Failed to create venv at $(VENV_DIR)"; \
				echo "Make sure python3 + python3-venv are installed."; \
				exit 1; \
			}; \
		fi; \
		"$(VENV_PIP)" install --quiet --upgrade pip; \
		"$(VENV_PIP)" install -r ../agentic/requirements.txt; \
		touch "$(VENV_MARKER)"; \
		echo ""; \
		echo "✓ Bootstrap complete. Using $(VENV_PYTHON)"; \
		echo ""; \
	fi
endif

# =============================================================================
# Management
# =============================================================================

.PHONY: kb-stats kb-setup

kb-stats: _kb_ensure_deps ## Print KB index stats (FAISS + Neo4j chunks per source)
	$(KB_CMD) --stats

kb-setup: _kb_ensure_deps ## Bootstrap Python venv + install KB dependencies (no-op if already set up)
	@echo "KB Python environment ready:"
	@echo "  PYTHON: $(PYTHON)"
	@echo "  MODE:   $(MODE)"
	@echo "  $(_ACTIVE_VENV_INFO)"


# =============================================================================
# Initial KB Build (lite|standard|full)
# =============================================================================

.PHONY: kb-build-cpu-lite kb-build-lite kb-build-standard kb-build-full

# CPU-lite: tool_docs + gtfobins + lolbas only (~5 min on CPU).
# Skips owasp (~35 min) and exploitdb (~3 hours) to keep first-run
# fast on machines without GPU or embedding API.
kb-build-cpu-lite: _kb_ensure_deps
kb-build-cpu-lite: ## Build CPU-lite KB (tool_docs + gtfobins + lolbas, ~5 min)
	$(KB_CMD) --profile cpu-lite

# Lite: committed source caches only — tool_docs, gtfobins, lolbas,
# owasp, exploitdb. No NVD, no nuclei.
kb-build-lite: _kb_ensure_deps
kb-build-lite: ## Build lite KB (all offline sources, ~4 hours on CPU)
	$(KB_CMD) --profile lite

# Standard: lite + 2 years of NVD history.
# Target-specific NVD_DAYS override: 730.
kb-build-standard: NVD_DAYS := 730
kb-build-standard: _kb_ensure_deps
kb-build-standard: ## Build standard KB (lite + 2 years of NVD history, ~6-8 min on host)
	$(KB_CMD) --profile standard

# Full: standard + Nuclei templates. Ingestion runs entirely on the host —
# no kali-sandbox dependency. The NucleiClient downloads the
# projectdiscovery/nuclei-templates tarball directly and parses template
# YAML files in-process (same pattern as GTFOBinsClient / LOLBASClient).
# The kali container still bundles its own /root/nuclei-templates for
# scan-time use by the nuclei binary; that path is unrelated to KB ingestion.
kb-build-full: NVD_DAYS := 730
kb-build-full: _kb_ensure_deps
kb-build-full: ## Build full KB (standard + Nuclei templates, host-only, no kali required)
	$(KB_CMD) --profile full

# =============================================================================
# Per-Source Incremental KB Updates (ongoing refresh)
# =============================================================================

.PHONY: kb-update-nvd kb-update-nvd-key kb-update-exploitdb kb-update-nuclei kb-update-gtfobins kb-update-lolbas kb-update-owasp kb-update-tools

kb-update-nvd: _kb_ensure_deps ## Daily: incremental NVD update (new CVEs since last ingest)
	$(KB_CMD) --source nvd

kb-update-nvd-key: _kb_ensure_deps ## NVD update with API key (50 req/30s vs 5 req/30s) — needs NVD_API_KEY env
	$(KB_CMD) --source nvd --nvd-key $(NVD_API_KEY)

kb-update-exploitdb: _kb_ensure_deps ## Weekly: update ExploitDB descriptions
	$(KB_CMD) --source exploitdb

kb-update-nuclei: _kb_ensure_deps ## Weekly: update Nuclei template metadata
	$(KB_CMD) --source nuclei

kb-update-gtfobins: _kb_ensure_deps ## Monthly: update GTFOBins (Linux priv-esc)
	$(KB_CMD) --source gtfobins

kb-update-lolbas: _kb_ensure_deps ## Monthly: update LOLBAS (Windows LOLBin abuse)
	$(KB_CMD) --source lolbas

kb-update-owasp: _kb_ensure_deps ## On-demand: update OWASP WSTG methodology
	$(KB_CMD) --source owasp

kb-update-tools: _kb_ensure_deps ## On-demand: update tool docs from agentic/skills/
	$(KB_CMD) --source tool_docs

# =============================================================================
# KB Rebuild
# =============================================================================

.PHONY: kb-rebuild-cpu-lite kb-rebuild-lite kb-rebuild-standard kb-rebuild-full

# Target-specific NVD_DAYS defaults mirror the kb-build-* targets so the
# rebuild flavors don't accidentally fall through to the global NVD_DAYS
# default (which would shadow the intent of --profile lite/standard/full).
# Command-line `make kb-rebuild-* NVD_DAYS=N` still wins — GNU Make's
# precedence puts command-line above target-specific.
# NVD_DAYS intentionally omitted — the lite profile doesn't include NVD,
# so the lookback window is a no-op here. Command-line `NVD_DAYS=N` is
# still accepted (for consistency with the other targets) but ignored.
kb-rebuild-cpu-lite: _kb_ensure_deps ## Full rebuild (cpu-lite profile) — drops + re-creates all data
	$(KB_CMD) --profile cpu-lite --rebuild

kb-rebuild-lite: _kb_ensure_deps ## Full rebuild (lite profile) — drops + re-creates all data
	$(KB_CMD) --profile lite --rebuild

kb-rebuild-standard: NVD_DAYS := 730
kb-rebuild-standard: _kb_ensure_deps ## Full rebuild (standard profile) — drops + re-creates all data (Optional: NVD_DAYS=90, MODE=local/docker)
	$(KB_CMD) --profile standard --rebuild

kb-rebuild-full: NVD_DAYS := 730
kb-rebuild-full: _kb_ensure_deps ## Full rebuild (full profile, includes Nuclei) — WARNING: slow
	$(KB_CMD) --profile full --rebuild

# =============================================================================
# Cleanup
# =============================================================================

.PHONY: kb-clean kb-venv-clean kb-clean-full

kb-clean: ## Remove Python caches (__pycache__ + .pytest_cache). Leaves $(VENV_DIR) intact.
	@find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	@find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
	@echo "Cleaned Python caches (__pycache__ and .pytest_cache)"

kb-venv-clean: ## Remove the auto-bootstrapped $(VENV_DIR) only
	@if [ -n "$$VIRTUAL_ENV" ] && [ "$$VIRTUAL_ENV" = "$(VENV_DIR)" ]; then \
		echo "WARNING: $(VENV_DIR) is currently activated in your shell."; \
		echo "Run 'deactivate' manually after this command completes."; \
	fi
	@rm -rf "$(VENV_DIR)"
	@echo "Removed $(VENV_DIR)"

kb-clean-full: kb-clean kb-venv-clean ## Remove Python caches AND $(VENV_DIR) (everything kb-clean + kb-venv-clean do)
	@echo "Full KB cleanup complete"

# =============================================================================
# Testing
# =============================================================================

.PHONY: kb-test-unit kb-test-integration

kb-test-unit: _kb_ensure_deps ## Run unit tests (mocked Neo4j, no infra needed)
	$(PY_RUN) -m pytest knowledge_base/tests/ -v -m "not neo4j"

kb-test-integration: _kb_ensure_deps ## Run all tests including live Neo4j integration
	$(PY_RUN) -m pytest knowledge_base/tests/ -v

# =============================================================================
# Help
# =============================================================================

.PHONY: kb-help help

help: kb-help

kb-help: ## Show this help
	@echo ""
	@echo "RedAmon Knowledge Base — Makefile targets"
	@echo ""
	@echo "Initial setup (first run):"
	@echo "  make kb-build-lite                Build minimal KB (~3 min)"
	@echo "  make kb-build-standard            + recent NVD CVEs (~10 min)"
	@echo "  make kb-build-full                + full ExploitDB (~30 min)"
	@echo ""
	@echo "Ongoing refresh (cron-friendly):"
	@echo "  make kb-update-nvd                Daily NVD delta"
	@echo "  make kb-update-exploitdb          Weekly"
	@echo "  make kb-update-gtfobins           Monthly"
	@echo "  make kb-update-lolbas             Monthly"
	@echo ""
	@echo "Management:"
	@echo "  make kb-stats                     Show index stats"
	@echo "  make kb-rebuild                   Full rebuild (standard profile)"
	@echo ""
	@echo "All targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-24s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "Modes:"
	@echo "  MODE=docker                       Run inside redamon-agent container"
	@echo "  MODE=local (default)              Run on host (requires local Python deps)"
	@echo ""
	@echo "Environment variables:"
	@echo "  MODEL                             Embedding model (default: intfloat/e5-large-v2)"
	@echo "  NVD_DAYS                          NVD lookback window in days (default: 730 = 2 years)"
	@echo "  NVD_API_KEY                       NVD API key (for kb-update-nvd-key)"
	@echo "  NEO4J_URI                         Neo4j URI (default: bolt://localhost:7687)"
	@echo "  NEO4J_USER, NEO4J_PASSWORD        Neo4j credentials"
	@echo "  AGENT_CONTAINER                   Container name (default: redamon-agent)"
	@echo ""
	@echo "Examples:"
	@echo "  make kb-build-standard NVD_DAYS=90       Fast test (3 months of CVEs)"
	@echo "  make kb-build-standard NVD_DAYS=730      Production (2 years)"
	@echo "  make kb-rebuild NVD_DAYS=365             Rebuild with last 1 year of CVEs"
	@echo ""
