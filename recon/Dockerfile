# RedAmon Reconnaissance Module - Dockerfile
# ============================================
# Fully containerized OSINT reconnaissance framework
# Supports Docker-in-Docker for ProjectDiscovery tools
# Includes Tor/Proxychains for anonymous scanning

# Stage 1a: Build jsluice binary (Go-based JS analyzer, requires CGO for tree-sitter)
# Static linking required: Alpine uses musl but the final image uses Debian/glibc
# Source: https://github.com/BishopFox/jsluice (MIT)
FROM golang:1.22-alpine AS jsluice-builder
RUN printf '#!/bin/sh\nmax=5; n=0; until "$@"; do n=$((n+1)); [ $n -ge $max ] && exit 1; echo "Retry $n/$max ..."; sleep $((n*5)); done\n' \
    > /usr/local/bin/retry && chmod +x /usr/local/bin/retry
RUN retry apk add --no-cache gcc musl-dev && \
    CGO_ENABLED=1 retry go install -ldflags='-linkmode external -extldflags "-static"' \
        github.com/BishopFox/jsluice/cmd/jsluice@latest

# Stage 1b: Build ffuf binary (pure Go, no CGO needed)
FROM golang:1.22-alpine AS ffuf-builder
RUN printf '#!/bin/sh\nmax=5; n=0; until "$@"; do n=$((n+1)); [ $n -ge $max ] && exit 1; echo "Retry $n/$max ..."; sleep $((n*5)); done\n' \
    > /usr/local/bin/retry && chmod +x /usr/local/bin/retry
RUN CGO_ENABLED=0 retry go install github.com/ffuf/ffuf/v2@latest

# Stage 1d: Build subjack binary (pure Go, DNS takeover scanner)
# Source: https://github.com/haccer/subjack (Apache-2.0)
# Recent subjack tip requires Go >= 1.25, so we use a matching builder.
# Fingerprints are compiled into the binary — no runtime data file required.
FROM golang:1.25-alpine AS subjack-builder
RUN printf '#!/bin/sh\nmax=5; n=0; until "$@"; do n=$((n+1)); [ $n -ge $max ] && exit 1; echo "Retry $n/$max ..."; sleep $((n*5)); done\n' \
    > /usr/local/bin/retry && chmod +x /usr/local/bin/retry
RUN CGO_ENABLED=0 retry go install github.com/haccer/subjack@latest

# Stage 1c: Build masscan from source (C project, requires libpcap)
FROM debian:bookworm-slim AS masscan-builder
RUN apt-get update && apt-get install -y --no-install-recommends \
    git gcc make libpcap-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && git clone --depth 1 https://github.com/robertdavidgraham/masscan.git /masscan \
    && cd /masscan && make -j$(nproc)

# Stage 2: Main recon image
FROM python:3.11-slim-bookworm

LABEL maintainer="RedAmon Team"
LABEL description="RedAmon Reconnaissance Module - Automated OSINT Framework"
LABEL version="1.0"

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Set Python environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

# Set working directory
WORKDIR /app

# Add Docker official APT repository (for up-to-date CLI)
# Retry helper for transient network failures
RUN printf '#!/bin/sh\nmax=5; n=0; until "$@"; do n=$((n+1)); [ $n -ge $max ] && exit 1; echo "Retry $n/$max ..."; sleep $((n*5)); done\n' \
    > /usr/local/bin/retry && chmod +x /usr/local/bin/retry

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
    && install -m 0755 -d /etc/apt/keyrings \
    && retry curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc \
    && chmod a+r /etc/apt/keyrings/docker.asc \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian \
    $(. /etc/os-release && echo "$VERSION_CODENAME") stable" > /etc/apt/sources.list.d/docker.list \
    && rm -rf /var/lib/apt/lists/*

# Install system dependencies
# - Docker CLI for orchestrating ProjectDiscovery containers
# - Tor and proxychains for anonymous scanning
# - DNS utilities for domain resolution
# - Git for installing knock-subdomains
# - Build tools for Python packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Docker CLI (to communicate with host Docker daemon)
    docker-ce-cli \
    # Tor and proxychains for anonymous scanning
    tor \
    proxychains4 \
    # DNS utilities
    dnsutils \
    bind9-host \
    # Network tools
    curl \
    wget \
    netcat-openbsd \
    iputils-ping \
    # Git for knock-subdomains installation
    git \
    # Build dependencies for Python packages
    build-essential \
    libffi-dev \
    libssl-dev \
    # Runtime dependency for masscan
    libpcap0.8 \
    # Nmap for service version detection (-sV) and NSE vuln scripts (--script vuln)
    nmap \
    # Clean up apt cache
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Copy masscan binary from builder stage
COPY --from=masscan-builder /masscan/bin/masscan /usr/local/bin/masscan

# Configure proxychains for Tor
# Use dynamic_chain for better reliability
RUN sed -i 's/^strict_chain/#strict_chain/' /etc/proxychains4.conf && \
    sed -i 's/^#dynamic_chain/dynamic_chain/' /etc/proxychains4.conf && \
    echo "socks5 127.0.0.1 9050" >> /etc/proxychains4.conf

# Create Tor configuration for running as service
RUN mkdir -p /var/run/tor && \
    chown -R debian-tor:debian-tor /var/run/tor && \
    echo "SocksPort 0.0.0.0:9050" > /etc/tor/torrc && \
    echo "ControlPort 9051" >> /etc/tor/torrc && \
    echo "CookieAuthentication 0" >> /etc/tor/torrc && \
    echo "Log notice stdout" >> /etc/tor/torrc

# Create non-root user for security (but allow Docker access)
RUN groupadd -f docker && \
    groupadd -r redamon && \
    useradd -r -g redamon -G docker redamon && \
    mkdir -p /home/redamon && \
    chown -R redamon:redamon /home/redamon

# Create necessary directories
RUN mkdir -p /app/recon/output \
             /app/recon/data/mitre_db \
             /app/utils \
             /data/output \
             /data/.env \
    && chown -R redamon:redamon /app /data

# Copy requirements first (for better Docker layer caching)
COPY recon/requirements.txt /app/recon/requirements.txt

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r /app/recon/requirements.txt

# Copy Go binaries from build stages
COPY --from=jsluice-builder /go/bin/jsluice /usr/local/bin/jsluice
COPY --from=ffuf-builder /go/bin/ffuf /usr/local/bin/ffuf
COPY --from=subjack-builder /go/bin/subjack /usr/local/bin/subjack

# Install SecLists wordlists for FFuf directory fuzzing
RUN mkdir -p /usr/share/seclists/Discovery/Web-Content && \
    retry curl -sL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt \
        -o /usr/share/seclists/Discovery/Web-Content/common.txt && \
    retry curl -sL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-directories.txt \
        -o /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt && \
    retry curl -sL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/big.txt \
        -o /usr/share/seclists/Discovery/Web-Content/big.txt

# Download jhaddix all.txt wordlist for Amass brute-force subdomain enumeration
RUN mkdir -p /app/recon/wordlists && \
    retry curl -sL "https://gist.githubusercontent.com/jhaddix/86a06c5dc309d08580a018c66354a056/raw/all.txt" \
        -o /app/recon/wordlists/jhaddix-all.txt

# Copy the application code
# Copy recon module (includes recon/params.py and helpers/anonymity.py)
COPY recon/ /app/recon/

# Copy graph_db module (for Neo4j integration)
COPY graph_db/ /app/graph_db/

# Note: .env file is mounted via docker-compose volume, not copied here

# Copy entrypoint script
COPY recon/entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Create volume mount points (NOT /app/recon/output - that's bind-mounted by the orchestrator)
VOLUME ["/var/run/docker.sock", "/data"]

# Expose Tor SOCKS port (if using container's Tor)
EXPOSE 9050

# Set default environment variables (can be overridden)
ENV TARGET_DOMAIN=""
ENV SUBDOMAIN_LIST=""
ENV SCAN_MODULES="domain_discovery,port_scan,http_probe,resource_enum,vuln_scan"
ENV USE_TOR_FOR_RECON="false"
ENV USE_BRUTEFORCE_FOR_SUBDOMAINS="false"
ENV UPDATE_GRAPH_DB="false"
ENV USER_ID="default_user"
ENV PROJECT_ID="default_project"

# Use non-root user by default
# Note: May need root for some operations (Naabu SYN scan)
# USER redamon

# Health check - verify Docker socket and Python are working
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import sys; sys.exit(0)" && \
        (test -S /var/run/docker.sock && docker info > /dev/null 2>&1 || true)

# Default command - run the recon pipeline
ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["python", "/app/recon/main.py"]
