# =============================================================================
# RedAmon Vulnerability Scanner - Python Container
# =============================================================================
# This container runs the GVM Python scanner script, connecting to gvmd
# via Unix socket to create and execute vulnerability scans.
# =============================================================================

FROM python:3.12-slim

LABEL maintainer="RedAmon Project"
LABEL description="Python-based GVM vulnerability scanner for RedAmon"

# Set working directory
WORKDIR /app

# pip's default 15s socket timeout expires mid-download when several images build
# concurrently and share the host's bandwidth. This step pulls the two largest
# wheels in the repo (lxml ~5MB, cryptography ~4.7MB), so it is the first to lose
# that race. When the fetch that fails is a transitive dependency's metadata, pip
# reports it as a version conflict in the parent instead of a network error
# ("paramiko depends on bcrypt" - issue #171), so a generous timeout plus retries
# is also what keeps the failure legible.
ENV PIP_DEFAULT_TIMEOUT=60 \
    PIP_RETRIES=10 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Retry helper for transient network failures during build
RUN printf '#!/bin/sh\nmax=5; n=0; until "$@"; do n=$((n+1)); [ $n -ge $max ] && exit 1; echo "Retry $n/$max ..."; sleep $((n*3)); done\n' \
    > /usr/local/bin/retry && chmod +x /usr/local/bin/retry

# Install dependencies (python-gvm for scanner, neo4j for graph updates).
# One pip invocation: neo4j resolves together with the scanner deps rather than
# paying a second full index round-trip.
COPY scanners/gvm_scan/requirements.txt /tmp/gvm_requirements.txt
RUN retry pip install -r /tmp/gvm_requirements.txt neo4j

# Copy project files (context is parent directory, so paths are relative to project root)
COPY scanners/gvm_scan/ ./gvm_scan/
COPY graph_db/ ./graph_db/
COPY recon_settings/ ./recon_settings/

# Create output directories
RUN mkdir -p gvm_scan/output recon/output

# Set Python path and ensure unbuffered output for log streaming
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

# Default command
CMD ["python", "gvm_scan/main.py"]
