# =============================================================================
# RedAmon AI Attack Surface Scanner — Python Container
# =============================================================================
# One image, PER-TOOL VIRTUALENVS. The attack tools' dependencies conflict and
# cannot share one environment (garak needs datasets<4.0; pyrit needs >=4.8.0;
# promptfoo is Node.js). So the shared spine (neo4j driver + main/target_loader/
# safety/normalizer) runs in the BASE interpreter, and each tool gets its own
# venv. Each adapter invokes its tool via that venv's interpreter as a subprocess.
# =============================================================================

FROM python:3.12-slim

LABEL maintainer="RedAmon Project"
LABEL description="AI Attack Surface deterministic offensive scanner for RedAmon"

WORKDIR /app

# Build tools some tool wheels need at install time. (Kept in the image; a future
# optimization could strip build-essential after the venvs are built to slim it.)
RUN apt-get update && apt-get install -y --no-install-recommends git build-essential curl \
    && rm -rf /var/lib/apt/lists/*

# --- Base (shared spine): just the Neo4j driver ---
COPY scanners/ai_attack_surface_scan/requirements.txt /tmp/base-requirements.txt
RUN pip install --no-cache-dir -r /tmp/base-requirements.txt

# --- Per-tool venvs (isolated, conflicting deps) ---
# All three tool venvs transitively pull PyTorch (garak & pyrit directly;
# giskard via bert-score in the [llm] extra), and each independently resolves to
# the CUDA wheel by default -> ~2.5 GB of unused nvidia-* runtime PER venv. They
# are pinned to the CPU-only wheel: local torch does ~no heavy compute here
# (garak's default probes use heuristic detectors; pyrit/giskard score via the
# local Ollama judge over HTTP). This scanner is CPU-only by design and is NOT
# parametrized for GPU (unlike the agent's KB).
COPY scanners/ai_attack_surface_scan/adapters/garak/requirements.txt /tmp/garak-requirements.txt
RUN python -m venv /opt/venv-garak \
    && /opt/venv-garak/bin/pip install --no-cache-dir -U pip \
    && /opt/venv-garak/bin/pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu \
    && /opt/venv-garak/bin/pip install --no-cache-dir -r /tmp/garak-requirements.txt

COPY scanners/ai_attack_surface_scan/adapters/pyrit/requirements.txt /tmp/pyrit-requirements.txt
# pyrit pulls base2048, which ships no arm64/aarch64 wheel and compiles a small
# Rust extension from source. Provide a Rust toolchain ONLY for this build and
# remove it in the same layer so the image stays slim (on amd64 a prebuilt wheel
# exists and the toolchain simply goes unused).
RUN python -m venv /opt/venv-pyrit \
    && /opt/venv-pyrit/bin/pip install --no-cache-dir -U pip \
    && /opt/venv-pyrit/bin/pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu \
    && curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable \
    && . "$HOME/.cargo/env" \
    && /opt/venv-pyrit/bin/pip install --no-cache-dir -r /tmp/pyrit-requirements.txt \
    && rustup self uninstall -y

COPY scanners/ai_attack_surface_scan/adapters/giskard/requirements.txt /tmp/giskard-requirements.txt
RUN python -m venv /opt/venv-giskard \
    && /opt/venv-giskard/bin/pip install --no-cache-dir -U pip \
    && /opt/venv-giskard/bin/pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu \
    && /opt/venv-giskard/bin/pip install --no-cache-dir -r /tmp/giskard-requirements.txt

# Guard: fail the BUILD if any venv ended up with a CUDA torch. Pinning torch
# first only holds while the tools' own pins stay compatible -- a future garak/
# pyrit/giskard bump could make pip resolve a different torch from PyPI (the
# default index = CUDA) and silently restore ~2.5 GB per venv. This assertion
# turns that silent size regression into a loud failure. `+cpu` is the CPU
# wheel's build tag; the CUDA wheels carry `+cuXXX` or no local tag.
RUN for v in garak pyrit giskard; do \
        /opt/venv-$v/bin/python -c "import torch,sys; \
v=torch.__version__; \
sys.exit(0) if v.endswith('+cpu') else (print(f'FATAL: venv-$v has non-CPU torch {v}'), sys.exit(1))" \
        || exit 1; \
    done \
    && echo "torch CPU-variant guard: all venvs OK"

# --- promptfoo (Node CLI; NOT a venv) ---
# First non-Python tool. Install Node 22 + the pinned promptfoo. The dataset-based
# red-team plugins (our defaults) pull their payloads from HuggingFace
# (datasets-server) at scan time -- promptfoo does NOT persist that dataset to a
# disk cache, so there is nothing to pre-warm into the image; the scan container
# live-fetches at runtime (it is spawned on the host network and has the egress).
# Grading is forced to the local Ollama, so there is zero egress to OpenAI or
# promptfoo-cloud (see adapters/promptfoo/TOOL_API.md §8).
ENV PROMPTFOO_VERSION=0.121.17
ENV PROMPTFOO_BIN=promptfoo
ENV PROMPTFOO_DISABLE_TELEMETRY=true \
    PROMPTFOO_DISABLE_UPDATE=true \
    PROMPTFOO_DISABLE_REDTEAM_REMOTE_GENERATION=true
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates gnupg \
    && curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && npm install -g "promptfoo@${PROMPTFOO_VERSION}" \
    && rm -rf /var/lib/apt/lists/* /root/.npm

# Base-interpreter extra: PyYAML lets the promptfoo adapter parse promptfoo's
# generated redteam test file (always YAML) so it can apply the local encoding
# strategies offline (adapters/promptfoo/local_strategies.py). Kept as its own
# late layer so it reuses the heavy venv/npm cache above instead of busting it.
RUN pip install --no-cache-dir "PyYAML>=6.0"

# Copy the scanner (spine + adapters). The runner scripts are invoked by their
# tool's venv; the spine runs in the base interpreter.
COPY scanners/ai_attack_surface_scan/ ./ai_attack_surface_scan/
# The shared hostname rule and guardrail copy (IP-mode target admission,
# target_loader.py): the spawn mounts no recon_settings into this container.
COPY recon_settings/ ./recon_settings/

RUN mkdir -p ai_attack_surface_scan/output

# Per-tool interpreter paths (adapters default to these; overridable for dev).
ENV GARAK_PYTHON=/opt/venv-garak/bin/python
ENV PYRIT_PYTHON=/opt/venv-pyrit/bin/python
ENV GISKARD_PYTHON=/opt/venv-giskard/bin/python
ENV PYTHONPATH=/app/ai_attack_surface_scan:/app
ENV PYTHONUNBUFFERED=1

CMD ["python", "ai_attack_surface_scan/main.py"]
