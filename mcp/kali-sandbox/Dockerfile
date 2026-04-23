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
    john-data \
    hashcat \
    hydra \
    sshpass \
    smbclient \
    sqlmap \
    jq \
    # DoS / stress-testing
    hping3 \
    slowhttptest \
    # Web server & technology scanning
    nikto \
    whatweb \
    # SMB/Windows/AD enumeration
    enum4linux-ng \
    samba-common-bin \
    # Multi-protocol network exploitation (CrackMapExec successor)
    netexec \
    # SSL/TLS configuration auditing
    testssl.sh \
    # Command injection exploitation
    commix \
    # DNS enumeration (zone transfers, SRV, DNSSEC walk)
    dnsrecon \
    # Custom wordlist generation from target websites
    cewl \
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
    # NOTE: WPScan is licensed under the WPScan Public Source License (NOT MIT).
    # Free for pentesting assessments and personal use. Commercial use may require
    # a separate license from https://wpscan.com. See: github.com/wpscanteam/wpscan/blob/master/LICENSE
    wpscan \
    # Clean up
    && rm -rf /var/lib/apt/lists/*

# Retry helper for transient network failures (git clone, curl, go install, etc.)
RUN printf '#!/bin/sh\nmax=5; n=0; until "$@"; do n=$((n+1)); [ $n -ge $max ] && exit 1; echo "Retry $n/$max ..."; sleep $((n*5)); done\n' \
    > /usr/local/bin/retry && chmod +x /usr/local/bin/retry

# Install Go (required for naabu and nuclei)
# Handle ARM64 (Apple Silicon) vs AMD64 automatically
RUN ARCH=$(dpkg --print-architecture) && \
    if [ "$ARCH" = "arm64" ]; then GO_ARCH="arm64"; else GO_ARCH="amd64"; fi && \
    retry wget -q https://go.dev/dl/go1.25.7.linux-${GO_ARCH}.tar.gz && \
    tar -C /usr/local -xzf go1.25.7.linux-${GO_ARCH}.tar.gz && \
    rm go1.25.7.linux-${GO_ARCH}.tar.gz

ENV PATH="${PATH}:/usr/local/go/bin:/root/go/bin"
ENV GOPATH="/root/go"

# Install ProjectDiscovery tools (naabu, nuclei, interactsh, subfinder, katana)
# Source: https://github.com/projectdiscovery/naabu (AGPL-3.0)
# Source: https://github.com/projectdiscovery/nuclei (AGPL-3.0)
# Source: https://github.com/projectdiscovery/interactsh (MIT)
# Source: https://github.com/projectdiscovery/subfinder (MIT)
# Source: https://github.com/projectdiscovery/katana (MIT)
RUN retry go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest \
    && retry go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
    && retry go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest \
    && retry go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
    && retry go install -v github.com/projectdiscovery/katana/cmd/katana@latest

# Install API security testing tools (Go-based)
# Source: https://github.com/ffuf/ffuf (MIT) - Fast web fuzzer
# Source: https://github.com/projectdiscovery/httpx (MIT) - HTTP toolkit
# Source: https://github.com/hahwul/dalfox (MIT) - XSS vulnerability scanner
# Source: https://github.com/projectdiscovery/dnsx (MIT) - Fast DNS toolkit
# Source: https://github.com/Emoe/kxss (MIT) - Per-character XSS reflection probe
RUN retry go install -v github.com/ffuf/ffuf/v2@latest \
    && retry go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest \
    && retry go install -v github.com/hahwul/dalfox/v2@latest \
    && retry go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest \
    && retry go install -v github.com/Emoe/kxss@latest

# Install jsluice -- JavaScript static analyzer for hidden endpoints and secrets
# Source: https://github.com/BishopFox/jsluice (MIT)
# Requires CGO for tree-sitter bindings; gcc already installed above
RUN CGO_ENABLED=1 retry go install -v github.com/BishopFox/jsluice/cmd/jsluice@latest

# Install gitleaks -- git repository secret scanner (API keys, passwords, tokens)
# Source: https://github.com/gitleaks/gitleaks (MIT)
# Note: Go module path uses old org (zricethezav), not new org (gitleaks) -- known issue #1839
RUN retry go install -v github.com/zricethezav/gitleaks/v8@latest

# Install OWASP Amass (subdomain enumeration & network mapping)
# Source: https://github.com/owasp-amass/amass (Apache-2.0)
RUN retry go install -v github.com/owasp-amass/amass/v4/...@master

# Install GAU (GetAllUrls) -- passive URL discovery from web archives
# Source: https://github.com/lc/gau (MIT)
RUN retry go install -v github.com/lc/gau/v2/cmd/gau@latest

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
    && retry git clone --depth 1 https://github.com/ticarpi/jwt_tool.git /opt/jwt_tool \
    && chmod +x /opt/jwt_tool/jwt_tool.py \
    && ln -s /opt/jwt_tool/jwt_tool.py /usr/local/bin/jwt_tool

# graphql-cop - GraphQL security auditor
# Source: https://github.com/dolevf/graphql-cop (BSD-3-Clause)
RUN retry git clone --depth 1 https://github.com/dolevf/graphql-cop.git /opt/graphql-cop \
    && pip install --no-cache-dir -r /opt/graphql-cop/requirements.txt \
    && chmod +x /opt/graphql-cop/graphql-cop.py \
    && ln -s /opt/graphql-cop/graphql-cop.py /usr/local/bin/graphql-cop

# GraphQLmap - GraphQL exploitation engine
# Source: https://github.com/swisskyrepo/GraphQLmap (MIT)
# Note: Install via setup.py to get the 'graphqlmap' command. Skip readline
# from requirements.txt as it fails on Python 3.13 (Linux Python has readline built-in)
RUN retry git clone --depth 1 https://github.com/swisskyrepo/GraphQLmap.git /opt/graphqlmap \
    && cd /opt/graphqlmap \
    && pip install --no-cache-dir requests \
    && pip install --no-cache-dir -e .

# Playwright browser automation (for web application recon & interaction)
RUN pip install --no-cache-dir playwright \
    && playwright install chromium \
    && playwright install-deps chromium \
    && rm -rf /var/lib/apt/lists/*

# Install SecLists wordlists for ffuf/gobuster directory fuzzing
RUN mkdir -p /usr/share/seclists/Discovery/Web-Content && \
    retry curl -sL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt \
        -o /usr/share/seclists/Discovery/Web-Content/common.txt && \
    retry curl -sL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-directories.txt \
        -o /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt && \
    retry curl -sL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/big.txt \
        -o /usr/share/seclists/Discovery/Web-Content/big.txt

# ParamSpider — passive URL parameter discovery from Wayback Machine
# Source: https://github.com/devanshbatham/ParamSpider (MIT)
RUN retry pip install --no-cache-dir git+https://github.com/devanshbatham/ParamSpider.git

# AD/post-exploitation Python tools
# hashID: hash type identification (MD5, NTLM, bcrypt, etc) — unmaintained since 2015 but functional
# bloodhound: Active Directory relationship collector (attack path analysis)
# certipy-ad: AD Certificate Services exploitation (ESC1-ESC13) — pins impacket~=0.13.0
# ldapdomaindump: LDAP enumeration (users, groups, password policies)
# bloodyAD: live AD abuse primitives (password reset, group add, SPN set) driven by BloodHound edges
# networkx + orjson: power the /opt/adkc/bhgraph helper (BloodHound JSON → in-memory graph, no Neo4j)
RUN pip install --no-cache-dir hashID bloodhound certipy-ad ldapdomaindump \
    bloodyAD networkx orjson

# gMSADumper: read gMSA passwords when BloodHound flags ReadGMSAPassword edge.
# Not on PyPI — install from git. Source: https://github.com/micahvandeusen/gMSADumper (MIT)
RUN retry git clone --depth 1 https://github.com/micahvandeusen/gMSADumper.git /opt/gMSADumper \
    && pip install --no-cache-dir ldap3 pyasn1 \
    && chmod +x /opt/gMSADumper/gMSADumper.py \
    && ln -sf /opt/gMSADumper/gMSADumper.py /usr/local/bin/gMSADumper.py \
    && ln -sf /opt/gMSADumper/gMSADumper.py /usr/local/bin/gMSADumper

# kerbrute — fast Kerberos pre-auth based user enumeration + password spray
# Source: https://github.com/ropnop/kerbrute (Apache-2.0)
RUN retry go install -v github.com/ropnop/kerbrute@latest

# AD kill-chain helper: BloodHound JSON → NetworkX path-finder (Option A, no Neo4j)
COPY kali-sandbox/adkc/bhgraph.py /opt/adkc/bhgraph.py
RUN chmod +x /opt/adkc/bhgraph.py \
    && ln -s /opt/adkc/bhgraph.py /usr/local/bin/bhgraph

# gpp-decrypt: one-shot decrypt of GPP cpassword blobs (public AES key, MS14-025 legacy)
COPY kali-sandbox/adkc/gpp-decrypt.py /opt/adkc/gpp-decrypt.py
RUN chmod +x /opt/adkc/gpp-decrypt.py \
    && ln -s /opt/adkc/gpp-decrypt.py /usr/local/bin/gpp-decrypt

# Create impacket-* shell aliases. pip-installed impacket only ships
# `<Tool>.py` names in /opt/venv/bin; the `impacket-<Tool>` aliases are
# what the tool_registry and skills assume. Symlink every .py to both names.
RUN set -e; for f in /opt/venv/bin/*.py; do \
      base=$(basename "$f" .py); \
      case "$base" in \
        GetADUsers|GetNPUsers|GetUserSPNs|psexec|wmiexec|smbexec|secretsdump|\
        ticketer|getST|getTGT|dacledit|owneredit|rbcd|addcomputer|changepasswd|\
        ntlmrelayx|samrdump|services|reg|atexec|mqtt_check|mssqlclient|\
        rpcdump|rpcmap|lookupsid|goldenPac|kintercept|karmaSMB|keylistattack|\
        machine_role|mimikatz|nmapAnswerMachine|ntfs-read|ping|ping6|raiseChild|\
        sambaPipe|sniff|sniffer|split|ticketConverter|tstool) \
          ln -sf "$f" "/usr/local/bin/impacket-$base" ;; \
      esac; \
    done

# Wordlists needed by the AD kill-chain skill (and other crackers).
# - rockyou: /usr/share/wordlists/rockyou.txt (Kali's wordlists package)
# - xato-net usernames: raw SecLists download (~70MB)
# - common passwords (10k): small fallback for quick spray tiers
RUN apt-get update \
    && apt-get install -y --no-install-recommends wordlists \
    && rm -rf /var/lib/apt/lists/* \
    && if [ -f /usr/share/wordlists/rockyou.txt.gz ]; then \
         gunzip -k /usr/share/wordlists/rockyou.txt.gz; \
       fi \
    && mkdir -p /usr/share/seclists/Passwords/Leaked-Databases \
                /usr/share/seclists/Passwords/Common-Credentials \
                /usr/share/seclists/Usernames \
    && if [ -f /usr/share/wordlists/rockyou.txt ]; then \
         ln -sf /usr/share/wordlists/rockyou.txt \
                /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt; \
       fi \
    && retry curl -sL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt \
        -o /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt \
    && retry curl -sL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/xato-net-10-million-usernames.txt \
        -o /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt

# SSTImap — Server-Side Template Injection detection & exploitation
# Source: https://github.com/vladko312/SSTImap (MIT)
RUN retry git clone --depth 1 https://github.com/vladko312/SSTImap.git /opt/sstimap \
    && pip install --no-cache-dir -r /opt/sstimap/requirements.txt \
    && chmod +x /opt/sstimap/sstimap.py \
    && ln -s /opt/sstimap/sstimap.py /usr/local/bin/sstimap

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
    retry curl -sSLf "https://bin.equinox.io/c/bNyj1mQVY4c/ngrok-v3-stable-linux-${ARCH}.tgz" \
    | tar -xz -C /usr/local/bin \
    || echo "WARNING: ngrok download failed (CDN may be down), skipping"

# Install chisel (for optional multi-port TCP tunneling — reverse shells + web delivery)
RUN CHISEL_VERSION="1.11.4" && \
    ARCH=$(dpkg --print-architecture) && \
    retry curl -sSL "https://github.com/jpillora/chisel/releases/download/v${CHISEL_VERSION}/chisel_${CHISEL_VERSION}_linux_${ARCH}.gz" \
    | gunzip > /usr/local/bin/chisel && \
    chmod +x /usr/local/bin/chisel

# Expose ports for MCP servers (SSE/HTTP transport) + tunnel manager + ngrok API + terminal WS
EXPOSE 8000 8002 8003 8004 8005 8014 8015 8016 4040

# Initialize Metasploit database (speeds up first run)
RUN msfdb init || true

# Entrypoint handles updates + launches MCP servers
ENTRYPOINT ["/opt/entrypoint.sh"]
