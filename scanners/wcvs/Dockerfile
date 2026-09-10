# =============================================================================
# RedAmon - Web Cache Vulnerability Scanner (WCVS) image
# =============================================================================
# Builds Hackmanit's WCVS (https://github.com/Hackmanit/Web-Cache-Vulnerability-Scanner)
# from source. There is no official prebuilt image on a registry, so RedAmon
# builds a local image tagged `redamon-wcvs:latest` and runs it docker-in-docker
# from the recon container (see recon/cache_scan/wcvs_runner.py).
#
# Build:  docker compose --profile tools build wcvs
# Run:    docker run --rm --net=host redamon-wcvs /wcvs -u https://example.com -gr
#
# Pin WCVS_REF to a release tag/commit for reproducible builds.
# -----------------------------------------------------------------------------
FROM golang:1.23-bookworm AS builder

# Retry helper for transient network failures. Module fetches from the Go proxy
# stall and get reset mid-transfer on some networks (observed on the larger
# klauspost/compress zip), so every network step is wrapped; the module cache
# persists across attempts, so a retry resumes instead of restarting.
RUN printf '#!/bin/sh\nmax=6; n=0; until "$@"; do n=$((n+1)); [ $n -ge $max ] && exit 1; echo "Retry $n/$max ..."; sleep $((n*5)); done\n' \
    > /usr/local/bin/retry && chmod +x /usr/local/bin/retry

ARG WCVS_REF=master
# HTTP/1.1: bookworm's git 2.39 + GitHub's edge answer the HTTP/2
# git-upload-pack POST with 401, which git reports as a credential prompt.
RUN git -c http.version=HTTP/1.1 clone https://github.com/Hackmanit/Web-Cache-Vulnerability-Scanner.git /src \
    && cd /src \
    && git checkout "${WCVS_REF}"

WORKDIR /src

# proxy.golang.org fronts its module zips on a Google CDN edge that
# intermittently resets the transfer of the larger ones on some networks.
# goproxy.io is a separate, independently-hosted mirror serving the same
# checksum-verified modules (go.sum + the sumdb still validate every download,
# so an alternate mirror cannot substitute code), tried first to sidestep the
# flaky edge; the default proxy and a direct VCS fetch remain as fallbacks.
ENV GOPROXY=https://goproxy.io,https://proxy.golang.org,direct

RUN retry go mod download \
    && CGO_ENABLED=0 retry go build -o /wcvs .

# -----------------------------------------------------------------------------
FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Binary at /wcvs (matches upstream), wordlists relative to WORKDIR so WCVS
# finds its default header/parameter lists without -hw/-pw flags.
COPY --from=builder /wcvs /wcvs
COPY --from=builder /src/wordlists /app/wordlists

ENTRYPOINT ["/wcvs"]
