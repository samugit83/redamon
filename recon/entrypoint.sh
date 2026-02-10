#!/bin/bash
# RedAmon Reconnaissance Module - Docker Entrypoint
# ==================================================
# Handles initialization, Tor setup, and executes the recon pipeline

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║           RedAmon Reconnaissance Module                    ║${NC}"
echo -e "${BLUE}║              Containerized OSINT Framework                 ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

# =============================================================================
# Check Docker Socket Access
# =============================================================================
echo -e "${YELLOW}[*] Checking Docker socket access...${NC}"

if [ -S /var/run/docker.sock ]; then
    if docker info > /dev/null 2>&1; then
        echo -e "${GREEN}[+] Docker socket accessible${NC}"
    else
        echo -e "${RED}[!] Docker socket exists but not accessible${NC}"
        echo -e "${RED}    Make sure the container has permissions to access Docker${NC}"
        echo -e "${RED}    Try: docker-compose up with the docker group or root${NC}"
    fi
else
    echo -e "${RED}[!] Docker socket not found at /var/run/docker.sock${NC}"
    echo -e "${RED}    Mount it with: -v /var/run/docker.sock:/var/run/docker.sock${NC}"
    echo -e "${YELLOW}    Continuing anyway - some tools may not work${NC}"
fi

# =============================================================================
# Initialize Tor if requested
# =============================================================================
if [ "${USE_TOR_FOR_RECON}" = "true" ] || [ "${USE_TOR_FOR_RECON}" = "1" ]; then
    echo -e "${YELLOW}[*] Tor anonymity requested - checking Tor availability...${NC}"

    # Check if Tor is already running (external Tor service)
    if nc -z 127.0.0.1 9050 2>/dev/null; then
        echo -e "${GREEN}[+] External Tor SOCKS proxy detected on port 9050${NC}"
    else
        # Try to start Tor service inside the container
        echo -e "${YELLOW}[*] Starting Tor service inside container...${NC}"

        # Start Tor in background
        if command -v tor &> /dev/null; then
            tor &
            TOR_PID=$!

            # Wait for Tor to start (max 30 seconds)
            echo -e "${YELLOW}[*] Waiting for Tor to establish circuit...${NC}"
            for i in {1..30}; do
                if nc -z 127.0.0.1 9050 2>/dev/null; then
                    echo -e "${GREEN}[+] Tor SOCKS proxy ready on port 9050${NC}"
                    break
                fi
                sleep 1
                echo -n "."
            done
            echo ""

            if ! nc -z 127.0.0.1 9050 2>/dev/null; then
                echo -e "${RED}[!] Tor failed to start within 30 seconds${NC}"
                echo -e "${YELLOW}    Continuing without Tor anonymity${NC}"
            fi
        else
            echo -e "${RED}[!] Tor not installed in container${NC}"
            echo -e "${YELLOW}    Continuing without Tor anonymity${NC}"
        fi
    fi

    # Check proxychains availability
    if command -v proxychains4 &> /dev/null; then
        echo -e "${GREEN}[+] Proxychains4 available${NC}"
    else
        echo -e "${YELLOW}[!] Proxychains4 not found - some tools may not use Tor${NC}"
    fi
else
    echo -e "${YELLOW}[*] Tor anonymity disabled (USE_TOR_FOR_RECON=${USE_TOR_FOR_RECON:-false})${NC}"
fi

# =============================================================================
# Create necessary directories
# =============================================================================
echo -e "${YELLOW}[*] Ensuring output directories exist...${NC}"
mkdir -p /app/recon/output
mkdir -p /app/recon/data/mitre_db
mkdir -p /app/recon/data/wappalyzer
echo -e "${GREEN}[+] Directories ready${NC}"

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
    "sxcurity/gau:latest"
)

for IMAGE in "${IMAGES[@]}"; do
    if docker images -q "$IMAGE" 2>/dev/null | grep -q .; then
        echo -e "${GREEN}[+] $IMAGE already pulled${NC}"
    else
        echo -e "${YELLOW}[*] Pulling $IMAGE...${NC}"
        docker pull "$IMAGE" 2>/dev/null || echo -e "${RED}[!] Failed to pull $IMAGE${NC}"
    fi
done

# =============================================================================
# Execute the command
# =============================================================================
echo -e "${GREEN}[*] Starting reconnaissance pipeline...${NC}"
echo ""

# Execute the main command (default: python /app/recon/main.py)
exec "$@"
