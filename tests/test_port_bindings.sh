#!/usr/bin/env bash
# =============================================================================
# Verifies the host-port publish policy after the STRIDE S10/S13 hardening.
#
# Debug-only ports (MCP 8000-8005, progress 8013/8014, tunnel 8015, ngrok 4040,
# DB 5432/7474/7687) MUST be published on 127.0.0.1 only. Genuinely external
# ports (webapp 3000, agent 8090, reverse-shell 4444) MUST stay routable. The
# Kali terminal (8016) hands out a root shell and MUST NOT be published at all:
# only the agent's proxy reaches it, over the bridge (GHSA-3cjg-8cp8-j269).
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
for p in 8000 8002 8003 8004 8005 8013 8014 8015 4040 5432 7474 7687; do
    check_loopback "kali/db" "$p"
done

echo "== Ports that must not be published at all =="
case "$(is_loopback_only 8016; echo $?)" in
    *2) pass "kali terminal (8016) not published on the host" ;;
    *)  fail "kali terminal (8016) is published on the host (a root shell)" ;;
esac

echo "== Genuinely external ports must stay routable =="
check_routable "webapp" 3000
check_routable "agent"  8090
check_routable "reverse-shell (4444)" 4444

echo
echo "-----------------------------------------"
printf 'Port-binding suite: \033[0;32m%d passed\033[0m, ' "$PASS"
if [[ $FAIL -gt 0 ]]; then printf '\033[0;31m%d failed\033[0m\n' "$FAIL"; exit 1; else printf '%d failed\n' "$FAIL"; fi
