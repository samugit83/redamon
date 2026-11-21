#!/usr/bin/env bash
# =============================================================================
# The AI attack-surface judge (Ollama) is published on the host's loopback only,
# and the single-host deploy's verify step fails when it is not (T9, D29).
# Run:  bash tests/deploy_ollama_loopback_test.sh
#
# WHY THIS MATTERS: Ollama's API has no authentication. Published on every host
# interface, anyone on the LAN, or on the internet where the cloud firewall leaves
# 11434 open, could replace the judge model every tenant's AI scans are graded by
# (T9), or pull models until the host disk holding the databases is full (D29).
# The orchestrator publishes the port through the Docker SDK, so the deploy's prod
# overlay cannot re-bind it and ufw does not filter it: the binding in
# local_llm_manager.py is the control, and verify is the deploy's check of it.
#
# Static checks, then the verify step's own loop, cut out of deploy.sh, run
# against listening-socket tables for each binding Docker can produce.
# =============================================================================
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEPLOY_SH="$REPO_ROOT/tooling/deploy/single-host/deploy.sh"
MANAGER="$REPO_ROOT/recon_orchestrator/local_llm_manager.py"
PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf '  ok   %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  FAIL %s (got: %s want: %s)\n' "$1" "$2" "$3"; }
eq()  { if [[ "$2" == "$3" ]]; then ok "$1"; else bad "$1" "$2" "$3"; fi; }

echo "== the orchestrator publishes the judge on loopback =="
eq "LLM_PUBLISH_HOST is 127.0.0.1" \
    "$(grep -cE '^LLM_PUBLISH_HOST = "127\.0\.0\.1"$' "$MANAGER")" "1"
eq "the publish names the host address" \
    "$(grep -cF 'ports={f"{LLM_PORT}/tcp": (LLM_PUBLISH_HOST, LLM_PORT)},' "$MANAGER")" "1"
eq "no bare-port publish is left" \
    "$(grep -cF 'ports={f"{LLM_PORT}/tcp": LLM_PORT}' "$MANAGER")" "0"
eq "the publish host is not an env knob" \
    "$(grep -cE 'LLM_PUBLISH_HOST *= *os\.environ' "$MANAGER")" "0"

echo "== deploy.sh verify checks 11434 with the other internal ports =="
loop_line="$(grep -nE '^for p in 5432 7474 7687 8010 4444' "$DEPLOY_SH")"
case "$loop_line" in
    *" 11434; do") ok "the off-loopback loop lists 11434" ;;
    *) bad "the off-loopback loop lists 11434" "$loop_line" "... 4444 11434; do" ;;
esac

# The loop as the remote shell runs it: the heredoc's \$ become $.
start="${loop_line%%:*}"
LOOP="$(sed -n "${start},$((start + 3))p" "$DEPLOY_SH" | sed 's/\\\$/$/g')"
case "$LOOP" in
    *done*) ok "cut the verify loop out of deploy.sh" ;;
    *) bad "cut the verify loop out of deploy.sh" "$LOOP" "a for ... done loop" ;;
esac

# verdict <ss Local Address column>: what the verify loop decides for that table.
verdict() {
    local LB="$1" rc=0 db_bad=0
    err() { printf '%s\n' "$*" >&2; }
    eval "$LOOP" 2>/dev/null
    [[ "$rc" -eq 0 ]] && echo pass || echo fail
}

eq "judge not running (no 11434 socket)" "$(verdict $'127.0.0.1:5432\n127.0.0.1:8010')" pass
eq "judge on loopback (the fix)"         "$(verdict $'127.0.0.1:5432\n127.0.0.1:11434')" pass
eq "judge on IPv6 loopback"              "$(verdict $'[::1]:11434')" pass
eq "judge on every IPv4 interface"       "$(verdict $'127.0.0.1:5432\n0.0.0.0:11434')" fail
eq "judge on every IPv6 interface"       "$(verdict $'[::]:11434')" fail
eq "judge on the bare public address"    "$(verdict $'203.0.113.7:11434')" fail
eq "a port that only ends like 11434"    "$(verdict $'0.0.0.0:111434')" pass

echo
echo "deploy_ollama_loopback: $PASS passed, $FAIL failed"
[[ "$FAIL" -eq 0 ]]
