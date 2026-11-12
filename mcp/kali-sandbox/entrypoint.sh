#!/bin/bash
set -e

echo "[*] Starting RedAmon MCP container..."

# V7: run from a WRITABLE working directory, not the now read-only
# /opt/mcp_servers source mount. MCP processes (and the tools/agent terminal they
# spawn) inherit this cwd, so relative-path output lands in /tmp instead of
# failing on the read-only mount. Imports are unaffected (PYTHONPATH is absolute).
cd /tmp

# Tunnel manager API first (instant, runs in background).
# Allows the webapp to push tunnel config at any time during boot.
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

# Slow updates and tunnel config fetch run in the background so the MCP
# servers can bind their ports immediately and the docker healthcheck passes.
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

    WEBAPP_URL="${WEBAPP_API_URL:-http://webapp:3000}"
    # The worker holds no secrets. Instead of PULLING credentials (which would
    # require the internal key to live in this least-trusted container), we ask
    # the webapp to PUSH the saved tunnel config to our tunnel-manager on port
    # 8015. Best-effort: if the webapp is not up yet, tunnels can still be
    # (re)applied at any time from Global Settings > Tunneling.
    # The webapp takes the call only with the inbound tunnel token this sandbox already
    # holds (F-23). printf is a shell builtin and curl reads the header from stdin
    # (-H @-), so the token is on no command line another process here can read.
    if [ -z "${TUNNEL_AUTH_TOKEN:-}" ]; then
        echo "[*] [deferred] TUNNEL_AUTH_TOKEN not set: no tunnel sync (the tunnel manager refuses every push, so no tunnel can be up)"
    else
        echo "[*] [deferred] Requesting tunnel config sync from webapp..."
        for i in $(seq 1 30); do
            if printf 'Authorization: Bearer %s\n' "$TUNNEL_AUTH_TOKEN" | curl -sf -X POST -H @- "${WEBAPP_URL}/api/global/tunnel-config/sync" > /dev/null 2>&1; then
                echo "[*] [deferred] Tunnel config sync requested"
                break
            fi
            [ "$i" -eq 30 ] && echo "[*] [deferred] Webapp not reachable for tunnel sync; configure tunnels in Global Settings > Tunneling"
            sleep 2
        done
    fi

    echo "[*] [deferred] Initialization complete"
}

deferred_init &

echo "[*] Starting terminal WebSocket server..."
python3 /opt/mcp_servers/terminal_server.py &

echo "[*] Starting MCP servers..."
exec python3 /opt/mcp_servers/run_servers.py "$@"
