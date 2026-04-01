FROM kalilinux/kali-rolling:latest

LABEL maintainer="RedAmon Project"
LABEL description="Kali Linux sandbox with MCP servers for agentic penetration testing"

# Avoid prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Bootstrap CA certificates using the direct CDN mirror over HTTP first,
# then upgrade to HTTPS once ca-certificates is installed.
# This avoids the unreliable http.kali.org redirector that causes 403/timeout errors.
RUN echo "deb http://kali.download/kali kali-rolling main contrib non-free non-free-firmware" > /etc/apt/sources.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && update-ca-certificates \
    && echo "deb https://kali.download/kali kali-rolling main contrib non-free non-free-firmware" > /etc/apt/sources.list \
    && apt-get update

# Allow HTTPS→HTTP redirects (Kali CDN sometimes redirects to http mirrors)
RUN echo 'Acquire::https::Redirect::Allowed "true";' > /etc/apt/apt.conf.d/99allow-redirect

# Update and install penetration testing tools
RUN apt-get install -y --fix-missing \
    # Core tools
    curl \
    wget \
    git \
    # Python
    python3 \
    python3-pip \
    python3-venv \
    # Nmap (used by naabu via -nmap-cli for service detection)
    nmap \
    # Metasploit framework
    metasploit-framework \
    # Network utilities
    net-tools \
    iputils-ping \
    dnsutils \
    netcat-traditional \
    socat \
    rlwrap \
    # Exploitation & post-exploitation
    exploitdb \
    john \
    hydra \
    sshpass \
    smbclient \
    sqlmap \
    jq \
    # DoS / stress-testing
    hping3 \
    slowhttptest \
    # Compilers (for execute_code C/C++ support)
    gcc \
    g++ \
    make \
    # Scripting (for execute_code perl support)
    perl \
    # Build dependencies for naabu (requires libpcap)
    libpcap-dev \
    # Masscan port scanner (for AI agent network reconnaissance)
    masscan \
    # WPScan WordPress vulnerability scanner
    wpscan \
    # Clean up
    && rm -rf /var/lib/apt/lists/*

# Install Go (required for naabu and nuclei)
# Handle ARM64 (Apple Silicon) vs AMD64 automatically
RUN ARCH=$(dpkg --print-architecture) && \
    if [ "$ARCH" = "arm64" ]; then GO_ARCH="arm64"; else GO_ARCH="amd64"; fi && \
    wget -q https://go.dev/dl/go1.25.7.linux-${GO_ARCH}.tar.gz && \
    tar -C /usr/local -xzf go1.25.7.linux-${GO_ARCH}.tar.gz && \
    rm go1.25.7.linux-${GO_ARCH}.tar.gz

ENV PATH="${PATH}:/usr/local/go/bin:/root/go/bin"
ENV GOPATH="/root/go"

# Install ProjectDiscovery tools (naabu, nuclei, interactsh)
# Source: https://github.com/projectdiscovery/naabu (AGPL-3.0)
# Source: https://github.com/projectdiscovery/nuclei (AGPL-3.0)
# Source: https://github.com/projectdiscovery/interactsh (MIT)
RUN go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest \
    && go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
    && go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest

# Install API security testing tools (Go-based)
# Source: https://github.com/ffuf/ffuf (MIT) - Fast web fuzzer
# Source: https://github.com/projectdiscovery/httpx (MIT) - HTTP toolkit
# Source: https://github.com/hahwul/dalfox (MIT) - XSS vulnerability scanner
RUN go install -v github.com/ffuf/ffuf/v2@latest \
    && go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest \
    && go install -v github.com/hahwul/dalfox/v2@latest

# Update nuclei templates
RUN nuclei -update-templates || true

# Create virtual environment for Python dependencies
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install Python MCP dependencies
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# Install API security testing tools (Python-based)
# jwt_tool - JWT exploitation toolkit (alg:none, key confusion, cracking)
# Source: https://github.com/ticarpi/jwt_tool (GPL-3.0)
RUN pip install --no-cache-dir pycryptodomex termcolor ratelimit \
    && git clone --depth 1 https://github.com/ticarpi/jwt_tool.git /opt/jwt_tool \
    && chmod +x /opt/jwt_tool/jwt_tool.py \
    && ln -s /opt/jwt_tool/jwt_tool.py /usr/local/bin/jwt_tool

# graphql-cop - GraphQL security auditor
# Source: https://github.com/dolevf/graphql-cop (BSD-3-Clause)
RUN git clone --depth 1 https://github.com/dolevf/graphql-cop.git /opt/graphql-cop \
    && pip install --no-cache-dir -r /opt/graphql-cop/requirements.txt \
    && chmod +x /opt/graphql-cop/graphql-cop.py \
    && ln -s /opt/graphql-cop/graphql-cop.py /usr/local/bin/graphql-cop

# GraphQLmap - GraphQL exploitation engine
# Source: https://github.com/swisskyrepo/GraphQLmap (MIT)
# Note: Install via setup.py to get the 'graphqlmap' command. Skip readline
# from requirements.txt as it fails on Python 3.13 (Linux Python has readline built-in)
RUN git clone --depth 1 https://github.com/swisskyrepo/GraphQLmap.git /opt/graphqlmap \
    && cd /opt/graphqlmap \
    && pip install --no-cache-dir requests \
    && pip install --no-cache-dir -e .

# Playwright browser automation (for web application recon & interaction)
RUN pip install --no-cache-dir playwright \
    && playwright install chromium \
    && playwright install-deps chromium \
    && rm -rf /var/lib/apt/lists/*

# Ensure ProjectDiscovery Go httpx wins over Python httpx CLI wrapper in PATH
RUN ln -sf /root/go/bin/httpx /opt/venv/bin/httpx

# Create directories
RUN mkdir -p /opt/mcp_servers /opt/output

# Copy MCP servers
COPY servers/ /opt/mcp_servers/

# Copy and set entrypoint script
COPY kali-sandbox/entrypoint.sh /opt/entrypoint.sh
RUN chmod +x /opt/entrypoint.sh

WORKDIR /opt/mcp_servers

# Install ngrok (for optional single-port TCP tunneling of reverse shells)
RUN ARCH=$(dpkg --print-architecture) && \
    curl -sSLf "https://bin.equinox.io/c/bNyj1mQVY4c/ngrok-v3-stable-linux-${ARCH}.tgz" \
    | tar -xz -C /usr/local/bin \
    || echo "WARNING: ngrok download failed (CDN may be down), skipping"

# Install chisel (for optional multi-port TCP tunneling — reverse shells + web delivery)
RUN CHISEL_VERSION="1.11.4" && \
    ARCH=$(dpkg --print-architecture) && \
    curl -sSL "https://github.com/jpillora/chisel/releases/download/v${CHISEL_VERSION}/chisel_${CHISEL_VERSION}_linux_${ARCH}.gz" \
    | gunzip > /usr/local/bin/chisel && \
    chmod +x /usr/local/bin/chisel

# Expose ports for MCP servers (SSE/HTTP transport) + tunnel manager + ngrok API + terminal WS
EXPOSE 8000 8002 8003 8004 8005 8014 8015 8016 4040

# Initialize Metasploit database (speeds up first run)
RUN msfdb init || true

# Entrypoint handles updates + launches MCP servers
ENTRYPOINT ["/opt/entrypoint.sh"]
