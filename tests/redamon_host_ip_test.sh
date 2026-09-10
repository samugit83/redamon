#!/usr/bin/env bash
# =============================================================================
# Test suite for the host-LAN-IP detection/export in redamon.sh
# (detect_host_lan_ip / export_host_lan_ip), added for issue #180 so the agent
# can suggest the reverse-shell LHOST instead of guessing the sandbox's 172.x.
#
# Pure unit test: `ip` and `hostname` are stubbed as bash functions, so it runs
# anywhere with no network and no Docker.  Run:  bash tests/redamon_host_ip_test.sh
# =============================================================================
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# shellcheck disable=SC1090
source "$REPO_ROOT/redamon.sh"   # BASH_SOURCE guard blocks command dispatch
set +e

PASS=0; FAIL=0
pass() { PASS=$((PASS+1)); printf '  \033[0;32mPASS\033[0m %s\n' "$1"; }
fail() { FAIL=$((FAIL+1)); printf '  \033[0;31mFAIL\033[0m %s\n' "$1"; }
assert_eq() { if [[ "$2" == "$3" ]]; then pass "$1 ($2)"; else fail "$1 (got='$2' expected='$3')"; fi; }
section() { printf '\n\033[1m== %s ==\033[0m\n' "$1"; }

# Silence redamon's info/warn (the empty-detection warn would pollute output).
info() { :; }
warn() { :; }

# --- stubs: `ip` and `hostname` shadow the real binaries (command -v finds fns) ---
IP_OUT=""; HOSTNAME_OUT=""
ip() { printf '%s\n' "$IP_OUT"; }
hostname() { printf '%s\n' "$HOSTNAME_OUT"; }

# Isolate the .env the export helper reads: point SCRIPT_DIR at a temp dir.
TMPDIR_T="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_T"' EXIT
_REAL_SCRIPT_DIR="$SCRIPT_DIR"
SCRIPT_DIR="$TMPDIR_T"

reset_case() { unset HOST_LAN_IP; rm -f "$TMPDIR_T/.env"; IP_OUT=""; HOSTNAME_OUT=""; }

# ---------------------------------------------------------------------------
section "detect_host_lan_ip parsing"

reset_case
IP_OUT="1.1.1.1 via 10.0.0.1 dev eth0 src 10.0.0.7 uid 1000"
assert_eq "default-route src IPv4 is parsed" "$(detect_host_lan_ip)" "10.0.0.7"

reset_case
IP_OUT=""                                   # ip yields nothing -> hostname fallback
HOSTNAME_OUT="fe80::1 192.168.5.5"
assert_eq "falls back to first IPv4 of hostname -I" "$(detect_host_lan_ip)" "192.168.5.5"

reset_case
IP_OUT=""
HOSTNAME_OUT="fe80::1 dead:beef::2"          # v6 only -> no IPv4 anywhere
assert_eq "v6-only result yields empty (webapp validates IPv4)" "$(detect_host_lan_ip)" ""

reset_case
# The ip-branch grep 'src [0-9.]+' is loose: a malformed/partial dotted string
# must be rejected by the final quad check, not returned as a bad LHOST.
IP_OUT="1.1.1.1 dev eth0 src 10.0.0 uid 0"
assert_eq "malformed partial src (3 octets) is rejected" "$(detect_host_lan_ip)" ""

# ---------------------------------------------------------------------------
section "export_host_lan_ip pin precedence"

reset_case
IP_OUT="1.1.1.1 dev eth0 src 172.20.0.9 uid 0"
export_host_lan_ip
assert_eq "detection exports when nothing is pinned" "${HOST_LAN_IP:-}" "172.20.0.9"

reset_case
HOST_LAN_IP="203.0.113.4"                     # shell/env pin
IP_OUT="1.1.1.1 dev eth0 src 172.20.0.9 uid 0"
export_host_lan_ip
assert_eq "shell pin wins over detection" "${HOST_LAN_IP:-}" "203.0.113.4"

reset_case
printf 'HOST_LAN_IP=\n' > "$TMPDIR_T/.env"    # bare placeholder (from .env.example)
IP_OUT="1.1.1.1 dev eth0 src 172.20.0.9 uid 0"
export_host_lan_ip
assert_eq "bare .env HOST_LAN_IP= is NOT a pin; detection still runs" "${HOST_LAN_IP:-}" "172.20.0.9"

reset_case
printf 'HOST_LAN_IP=198.51.100.7\n' > "$TMPDIR_T/.env"   # real .env pin
IP_OUT="1.1.1.1 dev eth0 src 172.20.0.9 uid 0"
export_host_lan_ip
# A .env pin means compose reads .env directly; the helper must NOT also export
# (that would let the shell env shadow the operator's .env value).
assert_eq ".env pin suppresses export (compose reads .env)" "${HOST_LAN_IP:-}" ""

reset_case
IP_OUT=""; HOSTNAME_OUT=""                     # detection fails entirely
export_host_lan_ip
assert_eq "failed detection leaves HOST_LAN_IP unset (agent will ask)" "${HOST_LAN_IP:-}" ""

# ---------------------------------------------------------------------------
SCRIPT_DIR="$_REAL_SCRIPT_DIR"
printf '\n\033[1m%d passed, %d failed\033[0m\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
