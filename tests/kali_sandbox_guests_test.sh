#!/usr/bin/env bash
# =============================================================================
# The two guests of every per-user Kali sandbox network forward nothing, and the
# capture proxy refuses the sandbox pool (group 1: S7, E4; TD-23, TD-24).
# Run:  bash tests/kali_sandbox_guests_test.sh
#
# The agent and the capture proxy join each person's sandbox network. A sandbox
# holds NET_ADMIN, so a guest that forwards packets is a route from one sandbox
# into redamon-network or into another person's sandbox, and the proxy, on every
# sandbox network, must never carry a request to the sandbox pool. The
# orchestrator refuses to attach a guest that lacks either (sandbox_manager.py,
# _guests_sync); this suite pins the compose side of both, which is what a
# `docker compose up` (the agent, `--profile capture` for the proxy) starts:
#   - `agent` and `capture-proxy` carry `sysctls: net.ipv4.ip_forward: "0"`, are
#     not privileged (a privileged container may write /proc/sys) and do not share
#     the host's network namespace;
#   - the proxy's CAPTURE_BLOCKED_IPS starts with the contract's SUBNET_POOL;
#   - no overlay (the root ones, the single-host deploy's) touches either.
# The orchestrator's own start of the proxy (start_capture_proxy) is covered by
# recon_orchestrator/tests/test_sandbox_api.py.
#
# Each rule is also run against a copy with a planted violation. Exits 77 (the
# gate's "cannot run") when a file it reads is missing. awk only.
# =============================================================================
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE="$REPO_ROOT/docker-compose.yml"
CONTRACT="$REPO_ROOT/recon_orchestrator/sandbox_contract.py"

for f in "$COMPOSE" "$CONTRACT"; do
    [[ -f "$f" ]] || { echo "CANNOT RUN: $f is missing"; exit 77; }
done
command -v awk >/dev/null 2>&1 || { echo "CANNOT RUN: awk is not installed"; exit 77; }

PASS=0; FAIL=0
pass() { PASS=$((PASS+1)); printf '  \033[0;32mPASS\033[0m %s\n' "$1"; }
fail() { FAIL=$((FAIL+1)); printf '  \033[0;31mFAIL\033[0m %s\n' "$1"; }
section() { printf '\n\033[1m== %s ==\033[0m\n' "$1"; }
report() {  # <label> <violations>
    if [[ -z "$2" ]]; then pass "$1"; else fail "$1"; printf '%s\n' "$2" | sed 's/^/        /' | head -20; fi
}
expect_caught() {  # <label> <violations>
    if [[ -n "$2" ]]; then pass "$1"; else fail "$1 (a planted violation was not found)"; fi
}

POOL="$(sed -nE 's/^SUBNET_POOL = "([^"]+)"$/\1/p' "$CONTRACT")"
[[ -n "$POOL" ]] || { echo "CANNOT RUN: SUBNET_POOL not found in $CONTRACT"; exit 77; }

# "<block>|<line>" for every line of one service that is not a comment (keys at
# four spaces open a block).
service_lines() {  # <file> <service>
    awk -v svc="  $2:" '
        $0 == svc { inside = 1; next }
        inside && /^  [A-Za-z0-9_.-]+:/ { exit }
        inside && /^[^ #]/ { exit }
        !inside || /^[[:space:]]*#/ || /^[[:space:]]*$/ { next }
        /^    [A-Za-z0-9_.-]+:/ { blk = $1; sub(/:.*/, "", blk) }
        { print blk "|" $0 }
    ' "$1"
}

# Violations of the guest rules for one service of the base file.
guest_violations() {  # <file> <service>
    local lines; lines="$(service_lines "$1" "$2")"
    [[ -n "$lines" ]] || { echo "service $2 not found"; return; }
    grep -qxF 'sysctls|      net.ipv4.ip_forward: "0"' <<< "$lines" \
        || echo "$2: no sysctls net.ipv4.ip_forward: \"0\""
    grep -E '^[^|]*\|    (privileged|network_mode|pid|userns_mode):' <<< "$lines" \
        | sed "s/^[^|]*|/$2: /"
}

# The proxy's always-on denylist starts with the pool.
proxy_pool_violations() {  # <file>
    local value
    value="$(service_lines "$1" capture-proxy \
        | sed -nE 's/^environment\|      CAPTURE_BLOCKED_IPS:[[:space:]]*"?([^"]*)"?[[:space:]]*$/\1/p')"
    [[ -n "$value" ]] || { echo "capture-proxy: no CAPTURE_BLOCKED_IPS in its environment"; return; }
    [[ "$value" == "$POOL,"* || "$value" == "$POOL" ]] \
        || echo "capture-proxy: CAPTURE_BLOCKED_IPS does not start with $POOL: $value"
}

# The proxy's egress guard runs on HTTP requests only; with raw TCP on, a stream
# after a CONNECT that is not HTTP is relayed to any address, the pool included.
proxy_rawtcp_violations() {  # <file>
    local cmd
    cmd="$(service_lines "$1" capture-proxy | sed -n 's/^[^|]*|    command:[[:space:]]*//p')"
    [[ -n "$cmd" ]] || { echo "capture-proxy: no command"; return; }
    [[ "$cmd" == *'"--set","rawtcp=false"'* ]] || echo "capture-proxy: command lacks --set rawtcp=false: $cmd"
    [[ "$cmd" != *'rawtcp=true'* && "$cmd" != *'"--rawtcp"'* ]] || echo "capture-proxy: command turns raw TCP on: $cmd"
}

# An overlay touches neither guest's forwarding, namespace, privileges or denylist.
overlay_violations() {  # <file>
    local svc
    for svc in agent capture-proxy; do
        service_lines "$1" "$svc" \
            | grep -E '(^[^|]*\|    (sysctls|privileged|network_mode|pid|userns_mode):)|CAPTURE_BLOCKED_IPS|net\.ipv4\.ip_forward' \
            | sed "s#^[^|]*|#$(basename "$1") $svc: #"
    done
    service_lines "$1" capture-proxy | grep -E '^[^|]*\|    (command|entrypoint):' \
        | sed "s#^[^|]*|#$(basename "$1") capture-proxy: #"
}

OVERLAYS=()
for f in "$REPO_ROOT"/docker-compose*.yml "$REPO_ROOT"/tooling/deploy/single-host/compose/*.yml; do
    [[ -f "$f" && "$f" != "$COMPOSE" ]] && OVERLAYS+=("$f")
done

section "the contract's pool"
if [[ "$POOL" == "10.214.0.0/16" ]]; then pass "SUBNET_POOL is $POOL"; else fail "SUBNET_POOL is $POOL"; fi

section "both guests forward nothing"
report "agent" "$(guest_violations "$COMPOSE" agent)"
report "capture-proxy" "$(guest_violations "$COMPOSE" capture-proxy)"

section "the capture proxy refuses the sandbox pool"
report "capture-proxy CAPTURE_BLOCKED_IPS" "$(proxy_pool_violations "$COMPOSE")"
report "capture-proxy relays no raw TCP" "$(proxy_rawtcp_violations "$COMPOSE")"

section "no overlay drops either"
for f in "${OVERLAYS[@]}"; do
    report "${f#"$REPO_ROOT"/}" "$(overlay_violations "$f")"
done

section "planted violations are caught"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
# Drop the sysctl from the agent only (the first one after `  agent:`).
awk '/^  agent:$/ { a = 1 } a && /^      net\.ipv4\.ip_forward: "0"$/ { a = 0; next } { print }' \
    "$COMPOSE" > "$TMP/agent.yml"
expect_caught "an agent that forwards" "$(guest_violations "$TMP/agent.yml" agent)"
awk '/^  capture-proxy:$/ { a = 1 } a && /^      net\.ipv4\.ip_forward: "0"$/ { print "      net.ipv4.ip_forward: \"1\""; a = 0; next } { print }' \
    "$COMPOSE" > "$TMP/proxy.yml"
expect_caught "a proxy that forwards" "$(guest_violations "$TMP/proxy.yml" capture-proxy)"
awk '{ print } /^  agent:$/ { print "    privileged: true" }' "$COMPOSE" > "$TMP/privileged.yml"
expect_caught "a privileged agent" "$(guest_violations "$TMP/privileged.yml" agent)"
sed -E 's|^(      CAPTURE_BLOCKED_IPS: ")[^"]*"$|\1${CAPTURE_BLOCKED_IPS:-}"|' "$COMPOSE" > "$TMP/nopool.yml"
expect_caught "a proxy denylist without the pool" "$(proxy_pool_violations "$TMP/nopool.yml")"
sed 's|"--set","rawtcp=false",||' "$COMPOSE" > "$TMP/rawtcp.yml"
expect_caught "a proxy that relays raw TCP" "$(proxy_rawtcp_violations "$TMP/rawtcp.yml")"
printf 'services:\n  agent:\n    sysctls: !reset {}\n  capture-proxy:\n    environment:\n      CAPTURE_BLOCKED_IPS: ""\n' \
    > "$TMP/overlay.yml"
expect_caught "an overlay that resets them" "$(overlay_violations "$TMP/overlay.yml")"
printf 'services:\n  capture-proxy:\n    command: ["mitmdump","--listen-port","8888"]\n' > "$TMP/overlay_cmd.yml"
expect_caught "an overlay that replaces the proxy command" "$(overlay_violations "$TMP/overlay_cmd.yml")"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
