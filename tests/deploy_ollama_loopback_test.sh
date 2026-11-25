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
#
# verify's other port checks too, cut out of the remote script verify() renders
# against a stubbed SSH: the reverse-shell pool is the SERVER's (its sandboxes
# publish that one, not the laptop's), read one key at a time so no secret is
# printed; the 4444 hint tells a Docker publish (an app older than the deploy
# assets) from the old socat forwarder; and the Kali image is the per-user one.
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
echo "== verify checks the server's port pool, and prints none of its .env =="
DSH_DIR="$REPO_ROOT/tooling/deploy/single-host"
FIXTURE=".env.verifypool$$"
W="$(mktemp -d)"
trap 'rm -rf "$W"; rm -f "$DSH_DIR/$FIXTURE"' EXIT
mkdir -p "$W/srv/redamon"
printf 'AUTH_SECRET=SENTINEL-auth\nKALI_SANDBOX_PORT_POOL="127.0.0.1:4600-4602"\nPOSTGRES_PASSWORD=SENTINEL-pg\n' \
    > "$W/srv/redamon/.env"
# This laptop's .env names another pool: the server's is the one its sandboxes publish.
printf 'ACCESS_MODE=https-ip\nTLS_MODE=self-signed\nKALI_SANDBOX_PORT_POOL=4500-4509\n' > "$DSH_DIR/$FIXTURE"
# verify() for real, with SSH run locally against $W/srv as the remote $HOME, the
# remote script captured instead of sent, and the public probes answering nothing.
VOUT="$( cd "$DSH_DIR" && W="$W" bash -c '
    set -uo pipefail
    source ./deploy.sh status 203.0.113.5 /dev/null ubuntu --env "'"${FIXTURE#.env.}"'" >/dev/null 2>&1 || exit 3
    ssh_stub() { printf "%s\n" "$*" >> "$W/ssh.log"; HOME="$W/srv" bash -c "$*"; }
    SSH=ssh_stub
    remote() { cat > "$W/verify.sh"; }
    curl() { echo 000; }
    verify' 2>&1 )"
rm -f "$DSH_DIR/$FIXTURE"
if [[ -s "$W/verify.sh" ]]; then ok "verify rendered its remote script"
else bad "verify rendered its remote script" "${VOUT:0:200}" "a captured script"; fi
eq "the pool loop names the server's ports" \
    "$(grep -cxE 'for p in 4600 4601 4602 ?; do' "$W/verify.sh")" "1"
eq "and not the laptop's" "$(grep -c '^for p in 4500' "$W/verify.sh")" "0"
eq "the server is asked for that one key only" \
    "$(grep -vc "^grep -m1 '^KALI_SANDBOX_PORT_POOL=' " "$W/ssh.log" 2>/dev/null)" "0"
case "$VOUT$(cat "$W/verify.sh")" in
    *SENTINEL*) bad "no value of the server's .env is printed or sent" "a SENTINEL value" "none" ;;
    *) ok "no value of the server's .env is printed or sent" ;;
esac

# The pool loop as rendered, after the internal-ports loop.
POOL_LOOP="$(awk '/^for p in 5432 /{seen=1; next} seen && /^for p in /{on=1} on {print} on && /^done$/{exit}' "$W/verify.sh")"
pool_verdict() {  # pool_verdict <ss Local Address column>
    local LB="$1" rc=0 db_bad=0
    err() { :; }
    eval "$POOL_LOOP" 2>/dev/null
    [[ "$rc" -eq 0 ]] && echo pass || echo fail
}
eq "a server pool port on loopback passes"     "$(pool_verdict $'127.0.0.1:4601')" pass
eq "a server pool port off loopback fails"     "$(pool_verdict $'0.0.0.0:4601')" fail
eq "a port of the laptop's pool is not judged" "$(pool_verdict $'0.0.0.0:4505')" pass

echo
echo "== verify's 4444 hint names the likely cause =="
HINT="$(awk '/^if printf .*4444/{on=1} on {print} on && /^fi$/{exit}' "$W/verify.sh")"
hint() {  # hint <ss Local Address column> <containers publishing 4444>
    local LB="$1" PUB="$2" REPO_BRANCH=master
    info() { printf '%s\n' "$*"; }
    sg() { [[ "$3" == *"publish=4444"* ]] && printf '%s\n' "$PUB"; return 0; }
    eval "$HINT"
}
out="$(hint $'0.0.0.0:4444' redamon-kali)"
for want in "published by redamon-kali" "older than these deploy assets" "REPO_BRANCH=master" \
            "revshell-close cannot remove a Docker publish"; do
    case "$out" in *"$want"*) ok "a Docker publish of 4444: '$want'" ;;
                   *) bad "a Docker publish of 4444: '$want'" "${out:-<nothing>}" "$want" ;; esac
done
out="$(hint $'203.0.113.7:4444' '')"
case "$out" in *"'./deploy.sh revshell-close' removes it"*) ok "a host listener on 4444 is the old forwarder" ;;
               *) bad "a host listener on 4444 is the old forwarder" "${out:-<nothing>}" "revshell-close removes it" ;; esac
eq "4444 on loopback only: no hint" "$(hint $'127.0.0.1:4444' redamon-kali)" ""

echo
echo "== verify warns when the Kali image is not the per-user one =="
LABEL="$(awk '/^labels=/{on=1} on {print} on && /^fi$/{exit}' "$W/verify.sh")"
label() {  # label <the image's labels as JSON, or nothing for no image>: the verdict line
    local L="$1"
    warn() { printf 'WARN %s\n' "$*"; }
    success() { printf 'OK %s\n' "$*"; }
    sg() { [[ -n "$L" ]] && printf '%s\n' "$L"; }
    eval "$LABEL"
}
eq "the per-user image (empty stamp) passes" \
    "$(label '{"maintainer":"RedAmon Project","redamon.msf_refresh":""}' | cut -c1-3)" "OK "
eq "a refreshed one too" "$(label '{"redamon.msf_refresh":"20261101"}' | cut -c1-3)" "OK "
case "$(label '{"maintainer":"RedAmon Project"}')" in
    "WARN "*"was not rebuilt"*) ok "the old shared image (no label) warns that it was not rebuilt" ;;
    *) bad "the old shared image warns" "$(label '{"maintainer":"RedAmon Project"}')" "WARN ... not rebuilt" ;;
esac
case "$(label '')" in
    "WARN "*) ok "no image warns" ;;
    *) bad "no image warns" "$(label '')" "WARN" ;;
esac

echo
echo "deploy_ollama_loopback: $PASS passed, $FAIL failed"
[[ "$FAIL" -eq 0 ]]
