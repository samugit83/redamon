#!/bin/bash
# RedAmon Reconnaissance Module - Docker Entrypoint
# ==================================================
# Handles initialization and executes the recon pipeline

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

printf '%s\n' "
                       ▄▄▄▄▄▄▄▄
                 ▄▄███████████████▄▄▄
             ▄▄█████▀▀▀        ▀▀▀█████▄▄
          ▄█████▀▀   ▄▄▄▄████▄▄▄   ▄██████▄▄
 ▄▄▄▄▄▄██████▀    ▄██████████████████▀ ▀███▀
 ████████▀▀    ▄████▀▀   ████████▀▀██▄   ▀
 ▀▀▀▀       ▄▄█████       ▀████▀    ███▄
  ▄▄▄▄▄▄▄▄████▀▀██████▄▄▄▄▄▄▄▄▄▄█████▀▀
  ████████▀▀        ▀▀▀▀▀▀███████▀
  ▀▀▀▀▀   ▄█████▄        ▄██▀▀████
          ███▀████    ▄▄██▀   ███▀
          ██▄  ▀▀  ▄▄███▀     ███
          ▀███▄▄▄████▀        ████
            ▀▀▀▀▀▀▀

  R E D A M O N — Recon Pipeline
"

# =============================================================================
# Check Docker Socket Access
# =============================================================================
echo -e "${YELLOW}[*] Checking Docker socket access...${NC}"

# If DOCKER_HOST is set to a unix socket, check that path instead
SOCKET_PATH=${DOCKER_HOST#unix://}
SOCKET_PATH=${SOCKET_PATH:-/var/run/docker.sock}

# The socket may be the filtering broker socket shared via a named volume
# (post-5.1.0 hardening), which can briefly race the volume mount at the first
# instant of boot. Retry the functional check before declaring failure, and
# always report the path actually in use ($SOCKET_PATH), not a hardcoded one.
DOCKER_READY=false
for _attempt in {1..8}; do
    if [ -S "$SOCKET_PATH" ] && docker info > /dev/null 2>&1; then
        DOCKER_READY=true
        break
    fi
    sleep 1
done

if [ "$DOCKER_READY" = true ]; then
    echo -e "${GREEN}[+] Docker socket accessible at ${SOCKET_PATH}${NC}"
elif [ -S "$SOCKET_PATH" ]; then
    echo -e "${RED}[!] Docker socket at ${SOCKET_PATH} exists but is not responding${NC}"
    echo -e "${RED}    Make sure the container can reach the Docker/broker daemon${NC}"
    echo -e "${YELLOW}    Continuing anyway - some tools may not work${NC}"
else
    echo -e "${RED}[!] Docker socket not found at ${SOCKET_PATH}${NC}"
    echo -e "${RED}    Expected the host socket or the broker socket mounted at this path${NC}"
    echo -e "${YELLOW}    Continuing anyway - some tools may not work${NC}"
fi

# =============================================================================
# Create necessary directories
# =============================================================================
echo -e "${YELLOW}[*] Ensuring output directories exist...${NC}"
mkdir -p /app/recon/output
mkdir -p /app/recon/wordlists
mkdir -p /app/recon/data/mitre_db
mkdir -p /app/recon/data/wappalyzer
echo -e "${GREEN}[+] Directories ready${NC}"

# =============================================================================
# Download DNS resolvers for puredns (refresh every 7 days)
# =============================================================================
RESOLVER_FILE="/app/recon/data/resolvers.txt"
if [ ! -f "$RESOLVER_FILE" ] || [ $(find "$RESOLVER_FILE" -mtime +7 2>/dev/null | wc -l) -gt 0 ]; then
    echo -e "${YELLOW}[*][Puredns] Downloading fresh DNS resolvers...${NC}"
    curl -sL https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt \
        -o "$RESOLVER_FILE" 2>/dev/null && \
        echo -e "${GREEN}[+][Puredns] Resolvers downloaded ($(wc -l < "$RESOLVER_FILE") entries)${NC}" || \
        echo -e "${RED}[!][Puredns] Failed to download resolvers${NC}"
else
    echo -e "${GREEN}[✓][Puredns] DNS resolvers up to date${NC}"
fi

# =============================================================================
# Pull required Docker images (ProjectDiscovery tools)
# =============================================================================
echo -e "${YELLOW}[*] Checking ProjectDiscovery Docker images...${NC}"

# List of images used by recon modules
IMAGES=(
    "projectdiscovery/naabu:latest"
    "projectdiscovery/httpx:latest"
    "projectdiscovery/katana:latest"
    "projectdiscovery/nuclei:latest"
    "projectdiscovery/subfinder:latest"
    "projectdiscovery/tlsx:latest"
    "sxcurity/gau:latest"
    "caffix/amass:latest"
    "frost19k/puredns:latest"
    "jauderho/hakrawler:latest"
    "projectdiscovery/uncover:latest"
    "dolevf/graphql-cop:1.14"
    "ghcr.io/zaproxy/zaproxy:stable"
    "redamon-wcvs:latest"
)

for IMAGE in "${IMAGES[@]}"; do
    if docker images -q "$IMAGE" 2>/dev/null | grep -q .; then
        echo -e "${GREEN}[+] $IMAGE already pulled${NC}"
    elif [[ "$IMAGE" == redamon-* ]]; then
        # Locally-built image (e.g. WCVS) — never pull from a registry.
        echo -e "${YELLOW}[!] $IMAGE not found locally — build with: docker compose --profile tools build wcvs${NC}"
    else
        echo -e "${YELLOW}[*] Pulling $IMAGE...${NC}"
        if [[ "$IMAGE" == "sxcurity/gau:latest" ]] && [[ "$(uname -m)" =~ ^(arm64|aarch64)$ ]]; then
            docker pull --platform linux/amd64 "$IMAGE" 2>/dev/null || echo -e "${RED}[!] Failed to pull $IMAGE${NC}"
        else
            docker pull "$IMAGE" 2>/dev/null || echo -e "${RED}[!] Failed to pull $IMAGE${NC}"
        fi
    fi
done

# =============================================================================
# Execute the command
# =============================================================================
echo -e "${GREEN}[*] Starting reconnaissance pipeline...${NC}"
echo ""

# Execute the main command (default: python /app/recon/main.py)
exec "$@"
