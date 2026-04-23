# RedAmon Agent Dockerfile
# Python-based LangGraph agent with MCP and Neo4j integration

FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    ripgrep \
    jq \
    make \
    gcc \
    g++ \
    openssh-client \
    unzip \
    wget \
    file \
    ca-certificates \
    gnupg \
    && rm -rf /var/lib/apt/lists/*

# Retry helper for transient network failures
RUN printf '#!/bin/sh\nmax=5; n=0; until "$@"; do n=$((n+1)); [ $n -ge $max ] && exit 1; echo "Retry $n/$max ..."; sleep $((n*5)); done\n' \
    > /usr/local/bin/retry && chmod +x /usr/local/bin/retry

# Install Node.js 20 LTS + npm (for JS/TS projects)
RUN retry curl -fsSL --retry 5 --retry-delay 5 --retry-all-errors \
        -o /tmp/nodesource.sh https://deb.nodesource.com/setup_20.x \
    && bash /tmp/nodesource.sh \
    && rm /tmp/nodesource.sh \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/* \
    && npm install -g yarn pnpm

# Install Go 1.22 (for Go projects)
# Download to file first (not piped to tar) so `retry` can cleanly re-run on
# a truncated HTTP/2 stream. curl's own --retry adds a second layer for
# transient errors; sha256 check catches any silently-short download.
RUN retry curl -fsSL --retry 5 --retry-delay 5 --retry-all-errors \
        -o /tmp/go.tgz https://go.dev/dl/go1.22.10.linux-amd64.tar.gz \
    && echo "736ce492a19d756a92719a6121226087ccd91b652ed5caec40ad6dbfb2252092  /tmp/go.tgz" | sha256sum -c - \
    && tar -C /usr/local -xzf /tmp/go.tgz \
    && rm /tmp/go.tgz
ENV PATH="/usr/local/go/bin:/root/go/bin:${PATH}"

# Install Ruby + Bundler (for Ruby/Rails projects)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ruby ruby-dev \
    && rm -rf /var/lib/apt/lists/* \
    && gem install bundler --no-document

# Install Java 17 JDK + Maven (for Java projects)
RUN apt-get update && apt-get install -y --no-install-recommends \
    default-jdk-headless \
    maven \
    && rm -rf /var/lib/apt/lists/*

# Install PHP + Composer (for PHP projects)
RUN apt-get update && apt-get install -y --no-install-recommends \
    php-cli php-xml php-mbstring php-curl php-zip \
    && rm -rf /var/lib/apt/lists/* \
    && retry curl -sS --retry 5 --retry-delay 5 --retry-all-errors \
        -o /tmp/composer-setup.php https://getcomposer.org/installer \
    && php /tmp/composer-setup.php --install-dir=/usr/local/bin --filename=composer \
    && rm /tmp/composer-setup.php

# Install .NET 8 SDK (for C# projects)
RUN apt-get update && apt-get install -y --no-install-recommends libicu-dev && rm -rf /var/lib/apt/lists/* \
    && retry curl -fsSL --retry 5 --retry-delay 5 --retry-all-errors \
        -o /tmp/dotnet-install.sh https://dot.net/v1/dotnet-install.sh \
    && bash /tmp/dotnet-install.sh --channel 8.0 --install-dir /usr/share/dotnet \
    && rm /tmp/dotnet-install.sh \
    && ln -s /usr/share/dotnet/dotnet /usr/local/bin/dotnet
ENV DOTNET_ROOT="/usr/share/dotnet"

# Copy requirements first for better caching.
# NOTE: build context is the project root (./), not ./agentic — see docker-compose.yml
COPY agentic/requirements.txt .
COPY agentic/requirements-kb.txt .

# Core Python dependencies (always installed)
RUN pip install --no-cache-dir -r requirements.txt

# Build arg: set to "true" to skip heavy KB dependencies (~4.4 GB saved)
# Use ./redamon.sh install --skipkbase to activate
# Declared AFTER core pip install so changing SKIP_KB doesn't bust that cache layer.
ARG SKIP_KB=false

# KB heavy dependencies: torch, sentence-transformers, faiss-cpu
# Skipped when SKIP_KB=true (--skipkbase flag)
RUN if [ "$SKIP_KB" != "true" ]; then \
        pip install --no-cache-dir -r requirements-kb.txt; \
    fi

# Pre-download the embedding model (~1.3 GB) unless KB is skipped.
# Cached at /root/.cache/huggingface/.
# Override at build time with --build-arg KB_EMBEDDING_MODEL=<other-model>.
ARG KB_EMBEDDING_MODEL=intfloat/e5-large-v2
ENV KB_EMBEDDING_MODEL=${KB_EMBEDDING_MODEL}
RUN if [ "$SKIP_KB" != "true" ]; then \
        python -c "from sentence_transformers import SentenceTransformer; SentenceTransformer('${KB_EMBEDDING_MODEL}')"; \
    fi

# Pre-download the cross-encoder reranker model (~568 MB) unless KB is skipped.
# Override at build time with --build-arg KB_RERANKER_MODEL=<other>.
# Disable the reranker at runtime via KB_RERANK_ENABLED=false.
ARG KB_RERANKER_MODEL=BAAI/bge-reranker-base
ENV KB_RERANKER_MODEL=${KB_RERANKER_MODEL}
RUN if [ "$SKIP_KB" != "true" ]; then \
        python -c "from sentence_transformers import CrossEncoder; CrossEncoder('${KB_RERANKER_MODEL}')"; \
    fi

# Copy application code
# - graph_db/ : shared Neo4j schema (used by both agent and KB)
# - knowledge_base/ : KB package (sibling to agentic/, imported as `knowledge_base`)
# - agentic/ : the agent itself (orchestrator, tools, prompts, skills, ...)
COPY graph_db/ ./graph_db/    
COPY knowledge_base/ ./knowledge_base/
COPY agentic/ ./

# Make knowledge_base and graph_db importable as top-level packages
ENV PYTHONPATH="/app:${PYTHONPATH}"

# Ensure KB data + cache directories exist (mounted as a volume at runtime).
# Created BEFORE the chmod -R a-w below so the volume mountpoint exists when
# nothing is mounted (the agent gracefully degrades to no-op KB in that case).
RUN mkdir -p /app/knowledge_base/data/sources /app/knowledge_base/data/cache

# Note: the container currently runs as root (no USER directive), so
# CAP_DAC_OVERRIDE lets the process bypass these permissions at runtime.
# The chmod still provides defense-in-depth against accidental writes
# (typos, buggy code) and surfaces EACCES errors early instead of silent
# corruption. For stronger enforcement, add a non-root USER directive
# and drop CAP_DAC_OVERRIDE via docker-compose.
#
# The `|| true` fallback is scoped to ONLY the __pycache__ chmod via
# parentheses — a failure of the two chmods above is a real build failure,
# not silently swallowed. Previously the ungrouped `|| true` applied to
# the whole `&&` chain and could ship an image with writable source code
# if any chmod in the chain failed. The __pycache__ restore itself is a
# no-op under PYTHONDONTWRITEBYTECODE=1 (set at the top of this file),
# but preserved as a defensive fallback for anyone who unsets that env
# var at runtime.
RUN chmod -R a-w /app/knowledge_base \
    && chmod -R u+w /app/knowledge_base/data \
    && ( chmod -R u+w /app/knowledge_base/__pycache__ 2>/dev/null || true )

# Expose API port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Run the API server
CMD ["uvicorn", "api:app", "--host", "0.0.0.0", "--port", "8080"]
