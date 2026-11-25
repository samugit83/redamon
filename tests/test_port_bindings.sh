#!/usr/bin/env bash
# =============================================================================
# Verifies the host-port publish policy after the STRIDE S10/S13 hardening.
#
# Debug-only DB ports (5432/7474/7687) MUST be published on 127.0.0.1 only.
# Genuinely external ports (webapp 3000, agent 8090) MUST stay routable. No Kali
# sandbox port is published by compose at all: the sandboxes are per person,
# started by the recon orchestrator on their own networks, and only the agent and
# the capture proxy reach their ports (MCP 8000-8005, progress 8013/8014, tunnel
# 8015, the terminal 8016, which hands out a root shell (GHSA-3cjg-8cp8-j269), and
# ngrok 4040). The reverse-shell listener 4444 is not published either: a sandbox
# publishes only its optional pool port (KALI_SANDBOX_PORT_POOL), at runtime.
# The build-only `kali-sandbox` service (profile `tools`) is checked too.
#
# Runs against `docker compose config` (the fully-resolved model) so it needs no
# running stack and works in CI. Run:  bash tests/test_port_bindings.sh
# =============================================================================
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

PASS=0; FAIL=0
pass() { PASS=$((PASS+1)); printf '  \033[0;32mPASS\033[0m %s\n' "$1"; }
fail() { FAIL=$((FAIL+1)); printf '  \033[0;31mFAIL\033[0m %s\n' "$1"; }

if ! docker compose version >/dev/null 2>&1; then
    echo "docker compose unavailable — skipping (not failing) port-binding checks."
    exit 0
fi

CONFIG="$(docker compose config 2>/dev/null)"
if [[ -z "$CONFIG" ]]; then
    echo "docker compose config produced no output — skipping."
    exit 0
fi
# The build-only services as well, so `--profile tools up` could publish nothing either.
TOOLS_CONFIG="$(docker compose --profile tools config 2>/dev/null)"

# published_host_ip <container_port> -> prints the host IP the port is published
# on (empty = all interfaces / 0.0.0.0). Parses the normalized long-form ports,
# where host_ip PRECEDES target within each block:
#   - mode: ingress
#     host_ip: 127.0.0.1
#     target: 8000
#     published: "8000"
published_host_ip() {
    local target="$1"
    echo "$CONFIG" | awk -v tgt="$target" '
        /- mode:/    { hip="" }
        /host_ip:/   { hip=$2 }
        /target:/    { if ($2 == tgt) { print hip; exit } }
    '
}

# Some compose versions emit short form "127.0.0.1:8000:8000". Fallback grep.
is_loopback_only() {
    local port="$1"
    local ip; ip="$(published_host_ip "$port")"
    if [[ -n "$ip" ]]; then
        [[ "$ip" == "127.0.0.1" ]] && return 0 || return 1
    fi
    # Fallback: look for any published mapping of this container port.
    if echo "$CONFIG" | grep -qE "127\.0\.0\.1:[0-9]+:${port}(\"|$|/)"; then return 0; fi
    if echo "$CONFIG" | grep -qE "(^|[^.0-9])[0-9]+:${port}(\"|$|/)"; then return 1; fi
    return 2   # not published at all
}

check_loopback() {
    local label="$1" port="$2"
    case "$(is_loopback_only "$port"; echo $?)" in
        *0) pass "$label ($port) loopback-only" ;;
        *1) fail "$label ($port) is NOT loopback-only (LAN-exposed!)" ;;
        *)  fail "$label ($port) not found in resolved config" ;;
    esac
}

# is_published <config> <container_port>: whether any service publishes that container port, on
# any host IP. The long form names it as a ports entry's `target:` (published_host_ip cannot
# tell an all-interfaces publish, which has no host_ip, from none); the short form is a list item.
is_published() {
    echo "$1" | awk -v tgt="$2" '$1 == "target:" && $2 == tgt { found = 1 } END { exit !found }' && return 0
    echo "$1" | grep -qE "^[[:space:]]*- \"?([0-9.]+:)?[0-9]+:${2}(/[a-z]+)?\"?[[:space:]]*$"
}

check_unpublished() {
    local label="$1" port="$2"
    if is_published "$CONFIG" "$port"; then
        fail "$label ($port) is published on the host"
    elif [[ -n "$TOOLS_CONFIG" ]] && is_published "$TOOLS_CONFIG" "$port"; then
        fail "$label ($port) is published by a service of the tools profile"
    else
        pass "$label ($port) not published on the host"
    fi
}

check_routable() {
    local label="$1" port="$2"
    local ip; ip="$(published_host_ip "$port")"
    if [[ -z "$ip" || "$ip" == "0.0.0.0" || "$ip" == "::" ]]; then
        pass "$label ($port) stays routable"
    else
        fail "$label ($port) got restricted to $ip (would break the feature)"
    fi
}

echo "== Debug-only ports must be loopback-only =="
for p in 5432 7474 7687; do
    check_loopback "db" "$p"
done

echo "== Ports that must not be published at all =="
if [[ -z "$TOOLS_CONFIG" ]]; then
    fail "docker compose --profile tools config produced no output (the Kali sandbox image's service is unchecked)"
fi
for p in 8000 8002 8003 8004 8005 8013 8014 8015 4040; do
    check_unpublished "kali sandbox" "$p"
done
check_unpublished "kali terminal, a root shell" 8016
check_unpublished "reverse-shell listener" 4444

echo "== Genuinely external ports must stay routable =="
check_routable "webapp" 3000
check_routable "agent"  8090

echo
echo "-----------------------------------------"
printf 'Port-binding suite: \033[0;32m%d passed\033[0m, ' "$PASS"
if [[ $FAIL -gt 0 ]]; then printf '\033[0;31m%d failed\033[0m\n' "$FAIL"; exit 1; else printf '%d failed\n' "$FAIL"; fi
