#!/bin/bash
set -e

echo "[*] Starting RedAmon MCP container..."

# Start tunnel manager API first (instant, runs in background)
# This allows the webapp to push tunnel config at any time during boot.
python3 /opt/mcp_servers/tunnel_manager.py &

# Wait for tunnel manager to bind to port 8015
for i in $(seq 1 10); do
    curl -sf http://localhost:8015/health > /dev/null 2>&1 && break
    [ "$i" -eq 10 ] && echo "[!] Tunnel manager failed to start on port 8015"
    sleep 1
done
echo "[*] Tunnel manager ready on port 8015"

# Ensure Metasploit database is running
echo "[*] Initializing Metasploit database..."
msfdb init 2>/dev/null || true

# Update Metasploit modules if enabled (default: true)
if [ "${MSF_AUTO_UPDATE:-true}" = "true" ]; then
    echo "[*] Updating Metasploit modules (this may take a minute)..."
    msfconsole -q -x "msfupdate; exit" 2>/dev/null || \
        apt-get update -qq && apt-get install -y -qq metasploit-framework 2>/dev/null || \
        echo "[!] Metasploit update failed, continuing with existing modules"
    echo "[*] Metasploit update complete"
else
    echo "[*] Skipping Metasploit update (MSF_AUTO_UPDATE=false)"
fi

# Update nuclei templates if enabled
if [ "${NUCLEI_AUTO_UPDATE:-true}" = "true" ]; then
    echo "[*] Updating nuclei templates..."
    nuclei -update-templates 2>/dev/null || echo "[!] Nuclei template update failed"
fi

# Fetch initial tunnel config from webapp DB and apply
# By this point MSF/nuclei updates are done (1-5 min), so webapp is almost certainly healthy.
WEBAPP_URL="${WEBAPP_API_URL:-http://webapp:3000}"
echo "[*] Fetching tunnel config from webapp..."
TUNNEL_CONFIG=""
for i in $(seq 1 30); do
    TUNNEL_CONFIG=$(curl -sf "${WEBAPP_URL}/api/global/tunnel-config" 2>/dev/null) && break
    echo "[*] Waiting for webapp... (attempt $i/30)"
    sleep 2
done

if [ -n "$TUNNEL_CONFIG" ] && [ "$TUNNEL_CONFIG" != '{}' ] && [ "$TUNNEL_CONFIG" != '{"ngrokAuthtoken":"","chiselServerUrl":"","chiselAuth":""}' ]; then
    echo "[*] Applying tunnel config from database..."
    PUSH_OK=false
    for j in $(seq 1 3); do
        if curl -sf -X POST http://localhost:8015/tunnel/configure \
            -H 'Content-Type: application/json' \
            -d "$TUNNEL_CONFIG" > /dev/null 2>&1; then
            PUSH_OK=true
            break
        fi
        echo "[!] Tunnel config push failed (attempt $j/3), retrying..."
        sleep 2
    done
    if [ "$PUSH_OK" = "false" ]; then
        echo "[!] Failed to apply tunnel config after 3 attempts — tunnels will not start automatically"
        echo "[!] Configure tunnels in Global Settings → Tunneling (changes push immediately)"
    fi
else
    echo "[*] No tunnel credentials configured (set them in Global Settings → Tunneling)"
fi

echo "[*] Starting terminal WebSocket server..."
python3 /opt/mcp_servers/terminal_server.py &

echo "[*] Starting MCP servers..."
exec python3 run_servers.py "$@"
