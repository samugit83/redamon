#!/usr/bin/env bash
# =============================================================================
# redamon.sh must stay runnable on bash 3.2 -- the /bin/bash Apple still ships
# (frozen at 3.2.57 for GPLv3 licensing reasons), and what a stock macOS host
# runs `./redamon.sh install` with. Two comments in redamon.sh already treat 3.2
# as supported; nothing enforced it until this suite.
#
# The regression it exists to catch: bash 3.2 does not remove double quotes
# inside an arithmetic expression before evaluating it, so
#
#     blast_mb=$(( total * "$(_pct_env BLAST_PCT 55 20 90)" / 100 ))
#
# died with `syntax error: operand expected`. Under the `set -euo pipefail` at
# the top of redamon.sh that aborted install/update before anything ran -- on
# every stock macOS host, while every Linux CI box stayed green.
#
# Layer 1 (always runs, hermetic): scan redamon.sh for that arithmetic form and
#   for bash-4-only syntax, so the break is caught without a 3.2 interpreter.
# Layer 2 (only when a bash:3.2 image is already local): actually run the
#   memory-governor suite under 3.2. Never pulls, so the gate stays offline.
#
# Run:  bash tests/redamon_bash32_compat_test.sh
# =============================================================================
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[0;33m'; NC='\033[0m'
PASS=0; FAIL=0
pass() { PASS=$((PASS+1)); printf "  ${GREEN}PASS${NC} %s\n" "$1"; }
fail() { FAIL=$((FAIL+1)); printf "  ${RED}FAIL${NC} %s\n" "$1"; }
skip() { printf "  ${YELLOW}SKIP${NC} %s\n" "$1"; }

# The file must contain no line matching the pattern; offenders are printed so
# the failure names the line rather than only the rule.
no_match() {
    local label="$1" re="$2" file="$3" hits
    hits="$(grep -nE "$re" "$file" || true)"
    if [[ -z "$hits" ]]; then
        pass "$label"
    else
        fail "$label"
        printf '        %s\n' "$hits"
    fi
}

echo "== no quoted command substitution inside \$(( )) =="
# Any double quote between `$((` and the first `)` is the 3.2 hazard: assign to
# a local first, the way every other _pct_env call site in redamon.sh does.
no_match "redamon.sh keeps quotes out of arithmetic expansions" \
         '\$\(\([^)]*"' redamon.sh

echo "== no bash-4-only syntax =="
no_match "no associative arrays (declare/local -A)" \
         '(declare|local|typeset)[[:space:]]+-[A-Za-z]*A([[:space:]]|$)' redamon.sh
no_match "no mapfile/readarray" \
         '(^|[^[:alnum:]_])(mapfile|readarray)([^[:alnum:]_]|$)' redamon.sh
no_match "no \${var,,} / \${var^^} case modification" \
         '\$\{[A-Za-z_][A-Za-z0-9_]*(\[[^]]*\])?(,,?|\^\^?)\}' redamon.sh
no_match "no &>> / ;;& / |& operators" \
         '&>>|;;&|\|&' redamon.sh

echo "== the reverse-shell catcher keeps one number on both sides =="
# Not a bash matter, but the same class of silent break: msfconsole binds the
# agent's LPORT inside the container and the payload advertises that same
# number, so a host side that differs produces a shell that never lands and never
# errors. The catcher is each person's sandbox's MSF_REVERSE_PORT: its pool port,
# which the orchestrator publishes as the same number on both sides, or an
# unpublished 4444. No compose file publishes 4444 any more.
for f in docker-compose.yml docker-compose.dev.yml docker-compose.gpu.yml docker-compose.plugins.yml \
         tooling/deploy/single-host/compose/docker-compose.prod.yml; do
    [[ -f "$f" ]] && no_match "$f publishes no 4444" '[:"]4444(/tcp|/udp)?"?[[:space:]]*(#.*)?$' "$f"
done
if grep -qF 'return {f"{port}/tcp": (bind_ip, port)}' recon_orchestrator/sandbox_contract.py; then
    pass "a sandbox's pool port is published as the same number"
else
    fail "recon_orchestrator/sandbox_contract.py no longer publishes the pool port as port -> (bind_ip, port)"
fi

echo "== the memory governor really runs under bash 3.2 =="
if ! command -v docker >/dev/null 2>&1; then
    skip "docker unavailable — layer 1 still ran"
elif ! docker image inspect bash:3.2 >/dev/null 2>&1; then
    skip "bash:3.2 image not present (docker pull bash:3.2 to enable this check)"
else
    # Mounted read-only and copied in: the suite writes a scratch .env, and a
    # container running as root must not leave anything in the working copy.
    if docker run --rm -v "$REPO_ROOT:/src:ro" bash:3.2 sh -c '
            mkdir -p /w/tests \
            && cp /src/redamon.sh /w/redamon.sh \
            && cp /src/tests/redamon_governor_test.sh /w/tests/ \
            && cd /w && bash tests/redamon_governor_test.sh' >/dev/null 2>&1; then
        pass "tests/redamon_governor_test.sh is green under bash 3.2"
    else
        fail "tests/redamon_governor_test.sh FAILS under bash 3.2"
        printf '        re-run to see it:\n'
        printf '        docker run --rm -v "%s:/src:ro" bash:3.2 sh -c '"'"'mkdir -p /w/tests && cp /src/redamon.sh /w/ && cp /src/tests/redamon_governor_test.sh /w/tests/ && cd /w && bash tests/redamon_governor_test.sh'"'"'\n' "$REPO_ROOT"
    fi
fi

echo
echo "-----------------------------------------"
printf "bash 3.2 compat suite: ${GREEN}%d passed${NC}, " "$PASS"
if [[ $FAIL -gt 0 ]]; then
    printf "${RED}%d failed${NC}\n" "$FAIL"
    exit 1
fi
printf "%d failed\n" "$FAIL"
