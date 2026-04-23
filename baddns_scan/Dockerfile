# RedAmon BadDNS sidecar
# ======================================================================
# AGPL-3.0 ISOLATION
# ----------------------------------------------------------------------
# BadDNS (https://github.com/blacklanternsecurity/baddns, AGPL-3.0) runs
# ONLY inside this container. It is invoked as an unmodified upstream
# Python package via `pip install baddns`. RedAmon code never imports
# from this package -- the recon container spawns this image via
# Docker-in-Docker (`docker run --rm redamon-baddns:latest ...`) and
# receives results as NDJSON written to a shared volume.
#
# This process + filesystem boundary is the license-safe integration
# pattern for AGPL tooling. See THIRD-PARTY-LICENSES.md for details.
# ======================================================================

FROM python:3.12-slim

LABEL maintainer="RedAmon Team"
LABEL description="Isolated BadDNS sidecar (AGPL-3.0). Invoked by the recon container via Docker-in-Docker. Never linked against RedAmon code."
LABEL upstream="https://github.com/blacklanternsecurity/baddns"
LABEL license="AGPL-3.0"

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Pin baddns version. Upstream is actively developed and bumps Finding
# schema / CLI flags occasionally. Bump this deliberately after verifying
# the normalizer in recon/helpers/takeover_helpers.py still matches.
ARG BADDNS_VERSION=2.1.0

# Retry helper for transient network failures during build
RUN printf '#!/bin/sh\nmax=5; n=0; until "$@"; do n=$((n+1)); [ $n -ge $max ] && exit 1; echo "Retry $n/$max ..."; sleep $((n*3)); done\n' \
    > /usr/local/bin/retry && chmod +x /usr/local/bin/retry

# Minimal runtime deps: ca-certificates for TLS, bash + coreutils for the
# batch loop (coreutils provides `timeout` used to bound per-target runs).
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates bash coreutils \
    && rm -rf /var/lib/apt/lists/* && apt-get clean

# Install baddns from PyPI (unmodified upstream, pinned version)
RUN retry pip install "baddns==${BADDNS_VERSION}"

# Non-root user for safety
RUN groupadd -r baddns && useradd -r -g baddns -d /work baddns \
    && mkdir -p /work && chown -R baddns:baddns /work

WORKDIR /work

# Batch entrypoint -- reads newline-separated targets from $1, runs baddns
# once per target (baddns does not support batch mode), emits NDJSON to
# stdout. The calling container redirects stdout to a file on a shared
# volume.
COPY baddns_scan/entrypoint.sh /usr/local/bin/baddns-batch
RUN chmod +x /usr/local/bin/baddns-batch

USER baddns

ENTRYPOINT ["/usr/local/bin/baddns-batch"]
