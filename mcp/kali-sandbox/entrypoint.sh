#!/bin/bash
set -e

echo "[*] Starting RedAmon MCP container..."

# V7: run from a WRITABLE working directory, not the now read-only
# /opt/mcp_servers source mount. MCP processes (and the tools/agent terminal they
# spawn) inherit this cwd, so relative-path output lands in /tmp instead of
# failing on the read-only mount. Imports are unaffected (PYTHONPATH is absolute).
cd /tmp

# Tunnel manager API first (instant, runs in background).
# Allows the agent to push this person's tunnel config at any time during boot.
python3 /opt/mcp_servers/tunnel_manager.py &

# Wait for tunnel manager to bind to port 8015
for i in $(seq 1 10); do
    curl -sf http://localhost:8015/health > /dev/null 2>&1 && break
    [ "$i" -eq 10 ] && echo "[!] Tunnel manager failed to start on port 8015"
    sleep 1
done
echo "[*] Tunnel manager ready on port 8015"

# Initialize Metasploit database synchronously: it's fast (~10-30s) and
# required before any msf tool call works, so we don't want a race window.
echo "[*] Initializing Metasploit database..."
msfdb init 2>/dev/null || true

# Slow updates run in the background so the MCP servers can bind their ports
# immediately and the docker healthcheck passes. A sandbox never fetches a tunnel
# config: the agent pushes each person's own to the tunnel manager on 8015.
deferred_init() {
    if [ "${MSF_AUTO_UPDATE:-true}" = "true" ]; then
        echo "[*] [deferred] Updating Metasploit modules..."
        MSF_OUT=$(msfconsole -q -x "msfupdate; exit" 2>&1 || true)
        if echo "$MSF_OUT" | grep -q "no longer supported"; then
            echo "[*] [deferred] msfupdate deprecated on this base image; skipping (refresh manually via 'apt install metasploit-framework' on the host image)"
        elif echo "$MSF_OUT" | grep -qiE "error|failed"; then
            echo "[!] [deferred] msfupdate reported issues; trying apt fallback..."
            (apt-get update -qq && apt-get install -y -qq metasploit-framework) >/dev/null 2>&1 \
                && echo "[*] [deferred] Metasploit update complete (via apt)" \
                || echo "[!] [deferred] apt fallback failed, continuing with existing modules"
        else
            echo "[*] [deferred] Metasploit update complete"
        fi
    else
        echo "[*] [deferred] Skipping Metasploit update (MSF_AUTO_UPDATE=false)"
    fi

    if [ "${NUCLEI_AUTO_UPDATE:-true}" = "true" ]; then
        echo "[*] [deferred] Updating nuclei templates..."
        nuclei -update-templates 2>/dev/null || echo "[!] Nuclei template update failed"
    fi

    echo "[*] [deferred] Initialization complete"
}

deferred_init &

echo "[*] Starting terminal WebSocket server..."
python3 /opt/mcp_servers/terminal_server.py &

echo "[*] Starting MCP servers..."
exec python3 /opt/mcp_servers/run_servers.py "$@"
