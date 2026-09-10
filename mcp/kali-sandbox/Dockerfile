# Supply-chain L3 (plan Phase 1): build the osv-scanner binary in a Go stage.
# Kali's bundled Go (1.25.x) is older than osv-scanner v2.4.0 requires (>=1.26.4),
# so we build it here on golang:1-bookworm (glibc, ABI-compatible with Kali) and
# COPY the static binary into the sandbox below.
FROM golang:1-bookworm AS osv-builder
RUN GOBIN=/out go install github.com/google/osv-scanner/v2/cmd/osv-scanner@v2.4.0

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

# Update and install penetration testing tools.
# `apt-get update` is repeated here (same layer as install) because Kali rolling
# rotates package versions frequently; a stale list cached from an earlier layer
# leads to 404s on .deb fetches even minutes later.
RUN apt-get update && apt-get install -y --fix-missing \
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
    # Network utilities. iproute2 supplies `ip` (net-tools only ships the
    # deprecated ifconfig/route); the agent reaches for `ip addr` to read its
    # own interfaces during exploitation, so its absence surfaced as a hard
    # "ip: command not found" (issue #180).
    net-tools \
    iproute2 \
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
    # Java runtime for the ysoserial JAR (installed below from upstream releases;
    # the Kali `ysoserial` apt package is no longer reliably published)
    default-jre-headless \
    # DNS enumeration (zone transfers, SRV, DNSSEC walk)
    dnsrecon \
    # Custom wordlist generation from target websites
    cewl \
    # Compilers (for execute_code C/C++ support)
    gcc \
    g++ \
    make \
    # Toolchain for source-built Python wheels. The Kali base ships an
    # ever-newer python3 (FROM ...:latest), so any pinned dependency can lose
    # its pre-built wheel on the next base bump and fall back to compiling from
    # source. Keeping the full build toolchain here makes that fallback succeed
    # regardless of Python version, instead of failing on a missing tool:
    #   - cmake / ninja-build: unicorn (via pwntools)
    #   - libgit2-dev / pkg-config: pygit2 (via guarddog)
    #   - python3-dev: C-extension headers (Python.h)
    cmake \
    ninja-build \
    build-essential \
    libgit2-dev \
    pkg-config \
    python3-dev \
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

# ysoserial: Java deserialization gadget chains (used by the RCE built-in skill)
# Source: https://github.com/frohoff/ysoserial (MIT). Downloaded directly from
# the upstream release because the Kali apt package is no longer reliably published.
RUN mkdir -p /usr/share/ysoserial \
    && retry curl -fsSL -o /usr/share/ysoserial/ysoserial.jar \
       https://github.com/frohoff/ysoserial/releases/download/v0.0.6/ysoserial-all.jar \
    && printf '#!/bin/sh\nexec java -jar /usr/share/ysoserial/ysoserial.jar "$@"\n' \
       > /usr/local/bin/ysoserial \
    && chmod +x /usr/local/bin/ysoserial

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
# Source: https://github.com/Emoe/kxss (Apache-2.0) - Per-character XSS reflection probe
RUN retry go install -v github.com/ffuf/ffuf/v2@latest \
    && retry go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest \
    && retry go install -v github.com/hahwul/dalfox/v2@latest \
    && retry go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest \
    && retry go install -v github.com/Emoe/kxss@latest

# Install jsluice -- JavaScript static analyzer for hidden endpoints and secrets
# Source: https://github.com/BishopFox/jsluice (MIT)
# Requires CGO for tree-sitter bindings; gcc already installed above
RUN CGO_ENABLED=1 retry go install -v github.com/BishopFox/jsluice/cmd/jsluice@latest

# Install betterleaks -- git repository secret scanner (API keys, passwords, tokens).
# Gitleaks successor from the same author (Zach Rice); drop-in CLI, reads .gitleaks.toml,
# gitleaks-compatible JSON, and parallelises the git-log walk via --git-workers.
# Source: https://github.com/betterleaks/betterleaks (MIT)
RUN retry go install -v github.com/betterleaks/betterleaks@latest

# Install OWASP Amass (subdomain enumeration & network mapping)
# Source: https://github.com/owasp-amass/amass (Apache-2.0)
RUN retry go install -v github.com/owasp-amass/amass/v4/...@master

# Install GAU (GetAllUrls) -- passive URL discovery from web archives
# Source: https://github.com/lc/gau (MIT)
RUN retry go install -v github.com/lc/gau/v2/cmd/gau@latest

# Install vulnx -- ProjectDiscovery CVE intelligence CLI (successor to cvemap).
# Aggregates NVD, CISA KEV, EPSS, HackerOne, GitHub PoCs, and Nuclei template
# availability into a single queryable dataset. Source:
# https://github.com/projectdiscovery/vulnx (MIT). Used by the cve_intel tool.
# Optional PDCP key (configured per-user from /settings, never via env vars or
# build args) is injected at call time via the cve_intel MCP wrapper.
RUN retry go install -v github.com/projectdiscovery/vulnx/v2/cmd/vulnx@latest

# Install subzy: subdomain takeover fingerprint scanner.
# Maintained fingerprint corpus (90+ providers) sharper than httpx -td banks for
# unclaimed-resource detection. Source: https://github.com/PentestPad/subzy (GPL-2.0;
# invoked as separate-process CLI, mere aggregation).
# Used by the Subdomain Takeover community skill.
RUN retry go install -v github.com/PentestPad/subzy@latest

# Update nuclei templates
RUN nuclei -update-templates || true

# Create virtual environment for Python dependencies
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Global pip constraints bind every `pip install` below (issue #181): a later
# isolated install (e.g. semgrep) can otherwise silently downgrade a pinned dep
# in this shared venv and the build still exits 0. With PIP_CONSTRAINT set, such
# a version skew becomes a hard build failure instead of a runtime crash-loop.
COPY kali-sandbox/pip-constraints.txt /etc/pip-constraints.txt
ENV PIP_CONSTRAINT=/etc/pip-constraints.txt

# Install Python MCP dependencies
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# Neo4j driver for the redagraph CLI (tenant-scoped graph queries from the shell)
RUN pip install --no-cache-dir neo4j

# Supply-chain L3 tools (plan Phase 1):
#  - osv-scanner: offline verdict engine (binary from the builder stage above).
#    Reads the redamon-osv-db volume (mounted read-only in docker-compose); the
#    execute_osv_scanner MCP tool sets OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY.
#  - guarddog: behavioural analysis. execute_guarddog dispatches the actual
#    tarball unpack to the hardened analyzer image, but guarddog is installed
#    here too for local metadata checks / fallback. no-install-ok: our tool.
COPY --from=osv-builder /out/osv-scanner /usr/local/bin/osv-scanner
RUN pip install --no-cache-dir guarddog==3.0.1   # no-install-ok

# Install API security testing tools (Python-based)
# jwt_tool - JWT exploitation toolkit (alg:none, key confusion, cracking)
# Source: https://github.com/ticarpi/jwt_tool (GPL-3.0)
RUN pip install --no-cache-dir pycryptodomex termcolor ratelimit \
    && retry git clone https://github.com/ticarpi/jwt_tool.git /opt/jwt_tool \
    && git -C /opt/jwt_tool -c advice.detachedHead=false checkout 3bc7407cf2222d6a821dcc19c776e5a1b1cb9a9b \
    && chmod +x /opt/jwt_tool/jwt_tool.py \
    && ln -s /opt/jwt_tool/jwt_tool.py /usr/local/bin/jwt_tool

# graphql-cop - GraphQL security auditor
# Source: https://github.com/dolevf/graphql-cop (BSD-3-Clause)
RUN retry git clone https://github.com/dolevf/graphql-cop.git /opt/graphql-cop \
    && git -C /opt/graphql-cop -c advice.detachedHead=false checkout 2b7e086efae672f28b419c7fcdfe6b48d846c9dc \
    && pip install --no-cache-dir -r /opt/graphql-cop/requirements.txt \
    && chmod +x /opt/graphql-cop/graphql-cop.py \
    && ln -s /opt/graphql-cop/graphql-cop.py /usr/local/bin/graphql-cop

# GraphQLmap - GraphQL exploitation engine
# Source: https://github.com/swisskyrepo/GraphQLmap (MIT)
# Note: Install via setup.py to get the 'graphqlmap' command. Skip readline
# from requirements.txt as it fails on Python 3.13 (Linux Python has readline built-in)
RUN retry git clone https://github.com/swisskyrepo/GraphQLmap.git /opt/graphqlmap \
    && git -C /opt/graphqlmap -c advice.detachedHead=false checkout 59305d7570c8fbbb04a324e869ec9a196c150936 \
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
    retry curl -sL https://raw.githubusercontent.com/danielmiessler/SecLists/47c02ddb16744a80c79fe19880096868c4c90cee/Discovery/Web-Content/common.txt \
        -o /usr/share/seclists/Discovery/Web-Content/common.txt && \
    retry curl -sL https://raw.githubusercontent.com/danielmiessler/SecLists/47c02ddb16744a80c79fe19880096868c4c90cee/Discovery/Web-Content/raft-medium-directories.txt \
        -o /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt && \
    retry curl -sL https://raw.githubusercontent.com/danielmiessler/SecLists/47c02ddb16744a80c79fe19880096868c4c90cee/Discovery/Web-Content/big.txt \
        -o /usr/share/seclists/Discovery/Web-Content/big.txt

# ParamSpider — passive URL parameter discovery from Wayback Machine
# Source: https://github.com/devanshbatham/ParamSpider (MIT)
RUN retry pip install --no-cache-dir git+https://github.com/devanshbatham/ParamSpider.git

# semgrep — source-aware static analysis (rule packs from semgrep registry).
# Used by the source-aware-sast Chat Skill when the operator provides a repo
# (git clone target) for a black-box-bridged code review. Pinned via pip in the
# shared venv; no apt package because the upstream Kali build lags semgrep releases.
# Source: https://github.com/semgrep/semgrep (LGPL-2.1)
RUN retry pip install --no-cache-dir semgrep

# Node.js + npm (for the prototype-pollution Chat Skill: gadget testing via execute_code Node workers).
# Apt list was wiped by the earlier core-tools layer, so update first.
RUN apt-get update \
    && apt-get install -y --no-install-recommends nodejs npm \
    && rm -rf /var/lib/apt/lists/*

# Python libs powering the SOAP, SAML, and WebSocket Chat Skills via execute_code.
# - websockets: ws/wss client for CSWSH and per-message-auth probes.
# - zeep: SOAP client for WS-Security / XSW probing.
# - python3-saml: SAML XSW / Comment Injection / Golden SAML construction.
RUN pip install --no-cache-dir websockets zeep python3-saml

# Cloud SDKs powering the AWS / Azure / GCP Chat Skills via execute_code.
# Heavy CLIs (awscli, az, gcloud) are skipped in favor of the Python SDKs which
# are both lighter and more script-friendly inside the agent's execute_code path.
# - boto3 + botocore: AWS API access, IAM enumeration, IMDS interaction.
# - msal + azure-identity + azure-mgmt-resource: Entra ID / Azure resource probes.
# - google-auth + google-api-python-client + google-cloud-storage: GCP service
#   accounts, IAM, Storage probes.
RUN pip install --no-cache-dir \
    boto3 \
    msal azure-identity azure-mgmt-resource \
    google-auth google-api-python-client google-cloud-storage

# Post-exploitation enumerators (Linux side, served via /opt/tools/linux/).
# Used by the Linux Privilege Escalation Chat Skill and the Docker Escape skill
# (deepce). Pre-staged in the image so the agent can serve them to a foothold
# host or run them inside the sandbox during local-priv-esc reconnaissance.
# - linpeas.sh: PEASS-ng Linux privesc auditor (carlospolop)
# - LinEnum.sh:  rebootuser/LinEnum Linux enumeration helper
# - pspy64:      DominicBreuker/pspy real-time process snooper (no root needed)
# - deepce.sh:   stealthcopter/deepce Docker container escape primitive scanner
RUN mkdir -p /opt/tools/linux \
    && retry curl -fsSL -o /opt/tools/linux/linpeas.sh \
       https://github.com/peass-ng/PEASS-ng/releases/download/20260708-abaa95f3/linpeas.sh \
    && retry curl -fsSL -o /opt/tools/linux/LinEnum.sh \
       https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh \
    && retry curl -fsSL -o /opt/tools/linux/pspy64 \
       https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64 \
    && retry curl -fsSL -o /opt/tools/linux/deepce.sh \
       https://raw.githubusercontent.com/stealthcopter/deepce/main/deepce.sh \
    && chmod +x /opt/tools/linux/*

# Post-exploitation enumerators (Windows side, served via /opt/tools/windows/).
# Used by the Windows Privilege Escalation Chat Skill. The agent stages these
# from the sandbox to a compromised Windows host (HTTP, SMB, or upload primitive).
# - winPEASx64.exe: PEASS-ng Windows privesc auditor (carlospolop)
# - PowerUp.ps1:    PowerSploit / Empire PowerUp (now under PowerShellMafia mirror)
# - PrivescCheck.ps1: itm4n/PrivescCheck audit script
RUN mkdir -p /opt/tools/windows \
    && retry curl -fsSL -o /opt/tools/windows/winPEASx64.exe \
       https://github.com/peass-ng/PEASS-ng/releases/download/20260708-abaa95f3/winPEASx64.exe \
    && retry curl -fsSL -o /opt/tools/windows/PowerUp.ps1 \
       https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1 \
    && retry curl -fsSL -o /opt/tools/windows/PrivescCheck.ps1 \
       https://github.com/itm4n/PrivescCheck/releases/download/2026.07.02-1/PrivescCheck.ps1

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
# Not on PyPI — install from git. Source: https://github.com/micahvandeusen/gMSADumper
# (GPL-3.0; invoked as separate-process CLI, mere aggregation)
RUN retry git clone https://github.com/micahvandeusen/gMSADumper.git /opt/gMSADumper \
    && git -C /opt/gMSADumper -c advice.detachedHead=false checkout e03187ca5c2b38b8742a20b919ebe38633c0b084 \
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
    && retry curl -sL https://raw.githubusercontent.com/danielmiessler/SecLists/47c02ddb16744a80c79fe19880096868c4c90cee/Passwords/Common-Credentials/10k-most-common.txt \
        -o /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt \
    && retry curl -sL https://raw.githubusercontent.com/danielmiessler/SecLists/47c02ddb16744a80c79fe19880096868c4c90cee/Usernames/xato-net-10-million-usernames.txt \
        -o /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt

# SSTImap — Server-Side Template Injection detection & exploitation
# Source: https://github.com/vladko312/SSTImap (GPL-3.0; invoked as separate-process CLI, mere aggregation)
RUN retry git clone https://github.com/vladko312/SSTImap.git /opt/sstimap \
    && git -C /opt/sstimap -c advice.detachedHead=false checkout d4f09055b15967b0e2265f20eb348a7ec2f25a2c \
    && pip install --no-cache-dir -r /opt/sstimap/requirements.txt \
    && chmod +x /opt/sstimap/sstimap.py \
    && ln -s /opt/sstimap/sstimap.py /usr/local/bin/sstimap

# tplmap: SSTI scanner that complements SSTImap by covering Smarty and Velocity
# engines that the SSTImap plugin set does not currently fingerprint.
# Source: https://github.com/epinna/tplmap (GPL-3.0). Lightly maintained but the
# core engine runs on Python 3. Pinned deps are old, so install into an isolated
# venv to avoid clashes with /opt/venv. Failures during the pinned-requirements
# install are non-fatal: the wrapper still launches the tool with relaxed deps,
# and the SSTI community skill documents an SSTImap-only fallback.
RUN retry git clone https://github.com/epinna/tplmap.git /opt/tplmap \
    && git -C /opt/tplmap -c advice.detachedHead=false checkout 616b0e527f62dd0930e6346ede6bef79e9bcf717 \
    && python3 -m venv /opt/tplmap/venv \
    && /opt/tplmap/venv/bin/pip install --no-cache-dir requests pysocks \
       || echo "WARNING: tplmap base deps install hit issues; tplmap may be degraded" \
    && (/opt/tplmap/venv/bin/pip install --no-cache-dir -r /opt/tplmap/requirements.txt \
        || echo "WARNING: tplmap pinned requirements failed; falling back to base deps") \
    && chmod +x /opt/tplmap/tplmap.py \
    && printf '#!/bin/sh\nexec /opt/tplmap/venv/bin/python /opt/tplmap/tplmap.py "$@"\n' \
       > /usr/local/bin/tplmap \
    && chmod +x /usr/local/bin/tplmap

# phpggc: PHP gadget-chain generator for unserialize/PHAR exploitation
# Source: https://github.com/ambionics/phpggc (Apache-2.0). Used by the
# Insecure Deserialization community skill (PHP track). Requires php-cli.
RUN apt-get update \
    && apt-get install -y --no-install-recommends php-cli \
    && rm -rf /var/lib/apt/lists/* \
    && retry git clone https://github.com/ambionics/phpggc.git /opt/phpggc \
    && git -C /opt/phpggc -c advice.detachedHead=false checkout f8aebde3a1abb88b02042fd12a71b4c61d6cfe2c \
    && chmod +x /opt/phpggc/phpggc \
    && ln -s /opt/phpggc/phpggc /usr/local/bin/phpggc

# Ensure ProjectDiscovery Go httpx wins over Python httpx CLI wrapper in PATH
RUN ln -sf /root/go/bin/httpx /opt/venv/bin/httpx

# Create directories
RUN mkdir -p /opt/mcp_servers /opt/output

# Copy MCP servers
COPY servers/ /opt/mcp_servers/

# Expose redagraph CLI on PATH (script lives in the volume-mounted servers dir,
# so iteration does not require a rebuild — only the symlink does).
RUN chmod +x /opt/mcp_servers/redagraph.py \
    && ln -sf /opt/mcp_servers/redagraph.py /usr/local/bin/redagraph

# RedAmon MOTD hint shown after the Kali login banner.
COPY kali-sandbox/redamon-motd.sh /etc/profile.d/zz-redamon-motd.sh
RUN chmod 0644 /etc/profile.d/zz-redamon-motd.sh

# Copy and set entrypoint script
COPY kali-sandbox/entrypoint.sh /opt/entrypoint.sh
RUN chmod +x /opt/entrypoint.sh

WORKDIR /opt/mcp_servers

# Build-time smoke test (issue #181): fail the build if the MCP server libraries
# are skewed instead of shipping an image whose servers crash-loop at startup.
# Runs after every pip install, so it sees the mcp/fastmcp that actually survived
# (semgrep's later install included). `from fastmcp import FastMCP` is what
# triggered the original ImportError; importing each server module is stricter.
RUN python3 -c "from fastmcp import FastMCP" \
    && for s in network_recon_server nuclei_server metasploit_server nmap_server playwright_server; do \
         echo "[smoke] importing $s" ; \
         python3 -c "import importlib; importlib.import_module('$s')" || exit 1 ; \
       done \
    && echo "[smoke] all MCP server modules import cleanly"

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
