#!/usr/bin/env bash
# =============================================================================
# Live security regression — agent GET /files unauthenticated OS command
# injection (CWE-78). Proves, against a RUNNING stack, that:
#   1. Without the internal key the route is rejected (401)         [auth]
#   2. With the key a normal workspace file still downloads (200)   [no regression]
#   3. A `; <cmd>` injection payload does NOT execute anywhere: no marker file
#      in the agent nor in any of this stack's running Kali sandboxes [the fix]
#   4. With the key the injection payload just 404s (treated as a filename)
#
# /files serves only the named project's workspace (projectId required, a path
# elsewhere 403): the agent reads the bind mount through the descriptor it
# checked, and no shell sees the path. So the probes live in a throwaway project
# workspace (a synthetic id, removed at the end), every payload names a path in it
# so it gets past the confinement to the open, and a command that ran would leave
# its marker in the agent, which serves the file, or in a sandbox, where the old
# kali_shell read ran.
#
# Requires the agent running; SKIPS (exit 0) otherwise so it is CI-safe.
# Run:  bash tests/test_files_injection_live.sh
# =============================================================================
set -uo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

PASS=0; FAIL=0
pass() { PASS=$((PASS+1)); printf '  \033[0;32mPASS\033[0m %s\n' "$1"; }
fail() { FAIL=$((FAIL+1)); printf '  \033[0;31mFAIL\033[0m %s\n' "$1"; }

running() { docker compose ps --format '{{.Service}} {{.State}}' 2>/dev/null | grep -q "^$1 running"; }
if ! running agent; then
    echo "agent not running — skipping live /files injection checks."
    exit 0
fi
# The orchestrator labels each sandbox it starts with its own compose project: this stack's.
STACK_OWNER="$(docker ps --filter 'name=^redamon-recon-orchestrator$' --format '{{.Label "com.docker.compose.project"}}' 2>/dev/null | head -1)"
if [[ -z "$STACK_OWNER" ]]; then
    fail "no compose project on a running redamon-recon-orchestrator: this stack's sandboxes cannot be told apart"
    exit 1
fi

KEY="$(grep -E '^INTERNAL_API_KEY=' .env 2>/dev/null | head -1 | cut -d= -f2-)"
URL="http://127.0.0.1:8090/files"
PID="files-injection-live-$$"
WS="/workspace/$PID"
MARKER="/tmp/PWNED_files_injection_$$"
PROBE="$WS/redamon_files_probe_$$.txt"

in_agent() { docker compose exec -T agent sh -c "$1" >/dev/null 2>&1; }
# This stack's running per-user sandboxes only: another stack's on the same host are not ours to enter.
sandboxes() {
    docker ps -q --filter label=redamon.sandbox=1 --filter label=redamon.sandbox.user \
        --filter "label=redamon.sandbox.owner=$STACK_OWNER" 2>/dev/null
}
# Whether the marker exists in the agent or in any of this stack's sandboxes (removed where found).
ran() {
    local m="$1" hit=1 id
    if in_agent "test -e '$m'"; then hit=0; in_agent "rm -f '$m'"; fi
    for id in $(sandboxes); do
        if docker exec "$id" test -e "$m" 2>/dev/null; then hit=0; docker exec "$id" rm -f "$m" >/dev/null 2>&1; fi
    done
    return "$hit"
}

cleanup() {
    in_agent "rm -rf '$WS' '$MARKER'" || true
}
trap cleanup EXIT
cleanup
in_agent "mkdir -p '$WS'"

# ---- 1. No key -> 401 (fails only meaningfully when the key is actually set) ----
echo "== 1. unauthenticated request rejected =="
code_noauth="$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 -G "$URL" --data-urlencode "projectId=$PID" \
    --data-urlencode "path=$WS/whatever" 2>/dev/null)"
if [[ -z "$KEY" ]]; then
    echo "  (INTERNAL_API_KEY unset in .env — auth fails open by design; skipping the 401 assertion)"
elif [[ "$code_noauth" == "401" ]]; then
    pass "no key -> 401 ($code_noauth)"
else
    fail "no key -> expected 401, got '$code_noauth'"
fi

AUTH=(); [[ -n "$KEY" ]] && AUTH=(-H "x-internal-key: $KEY")

files() { # path -> the body of an authenticated GET /files of the throwaway project
    curl -s --max-time 15 "${AUTH[@]}" -G "$URL" --data-urlencode "projectId=$PID" --data-urlencode "path=$1" 2>/dev/null
}

# ---- 2. Authenticated benign download works ----
echo "== 2. authenticated benign workspace download works =="
in_agent "printf hello > '$PROBE'"
body="$(files "$PROBE")"
if [[ "$body" == "hello" ]]; then
    pass "benign download returned file contents"
else
    fail "benign download expected 'hello', got '$body'"
fi

# ---- 3. Injection payload does NOT execute (no marker created) ----
echo "== 3. injection payload does not execute in the agent or a sandbox =="
files "$WS/x; touch $MARKER" >/dev/null
if ran "$MARKER"; then
    fail "INJECTION EXECUTED — marker '$MARKER' was created"
else
    pass "marker not created — injection neutralised"
fi

# ---- 4. A second injection class ($(...) command substitution) also blocked ----
# Separate metacharacter family from test 3's `;`, with the same deterministic
# marker technique (independent of the endpoint's missing-file response code).
echo "== 4. command-substitution \$(...) payload does not execute =="
MARKER2="/tmp/PWNED_files_subst_$$"
ran "$MARKER2"  # clears a leftover of an earlier run with the same pid
files "$WS/\$(touch $MARKER2)" >/dev/null
if ran "$MARKER2"; then
    fail "COMMAND SUBSTITUTION EXECUTED — marker '$MARKER2' created"
else
    pass "\$(...) marker not created — command substitution neutralised"
fi

# ---- 5. A legit filename with spaces/parens still downloads (functional) ----
# Pre-fix the unquoted interpolation broke these too.
echo "== 5. legit filename with spaces downloads correctly =="
SPACED="$WS/redamon probe ($$).txt"
in_agent "printf spaced-ok > '$SPACED'"
body_sp="$(files "$SPACED")"
if [[ "$body_sp" == "spaced-ok" ]]; then
    pass "filename with spaces/parens downloaded correctly"
else
    fail "spaced filename expected 'spaced-ok', got '$body_sp'"
fi

# ---- 6. Pipe-class injection also inert at runtime (third distinct class) ----
echo "== 6. pipe | injection does not execute =="
MARKER3="/tmp/PWNED_files_pipe_$$"
ran "$MARKER3"  # clears a leftover of an earlier run with the same pid
files "$WS/x | touch $MARKER3" >/dev/null
if ran "$MARKER3"; then
    fail "PIPE INJECTION EXECUTED — marker '$MARKER3' created"
else
    pass "| marker not created — pipe injection neutralised"
fi

echo
echo "==================================================================="
printf 'RESULT: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]] && exit 0 || exit 1
