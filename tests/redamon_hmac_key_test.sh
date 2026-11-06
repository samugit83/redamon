#!/usr/bin/env bash
# =============================================================================
# REDAMON_SECRET_HMAC_KEY: created on install and on update when missing, never
# overwritten, and passed to the orchestrator with NO default.
#
# The recon container HMACs a secret seen in a URL with it (urlscan's
# Secret.value_hmac). A new key turns every such Secret into a new node, and a
# fixed compose default would make the HMAC a public, reversible hash.
#
# Hermetic: sources redamon.sh against a temporary .env.
# Run:  bash tests/redamon_hmac_key_test.sh
# =============================================================================
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$REPO_ROOT/redamon.sh"
PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf '  ok   %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  FAIL %s\n' "$1"; }

W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT

run_ensure() {   # run_ensure <dir>: ensure_auth_secrets with SCRIPT_DIR=<dir>
    ( cd "$REPO_ROOT"
      # shellcheck disable=SC1090
      source "$SCRIPT"; set +e
      SCRIPT_DIR="$1"; info() { :; }
      ensure_auth_secrets ) >/dev/null 2>&1
}

key_of() { grep -E '^REDAMON_SECRET_HMAC_KEY=' "$1/.env" | cut -d= -f2-; }

echo "== a missing key is created: 32 random bytes, hex =="
mkdir -p "$W/a"; : > "$W/a/.env"
run_ensure "$W/a"
k1="$(key_of "$W/a")"
[[ "$k1" =~ ^[0-9a-f]{64}$ ]] && ok "64 hex characters" || bad "created key has the wrong shape: '$k1'"

echo "== a second run (an update) keeps it =="
run_ensure "$W/a"
[[ "$(key_of "$W/a")" == "$k1" ]] && ok "unchanged" || bad "the key was rotated"
[[ "$(grep -c '^REDAMON_SECRET_HMAC_KEY=' "$W/a/.env")" == 1 ]] && ok "written once" || bad "duplicated"

echo "== an operator's own key is never overwritten =="
mkdir -p "$W/b"; printf 'REDAMON_SECRET_HMAC_KEY=operator-chosen\n' > "$W/b/.env"
run_ensure "$W/b"
[[ "$(key_of "$W/b")" == "operator-chosen" ]] && ok "kept" || bad "replaced"

echo "== install and update both run the generator =="
for fn in cmd_install cmd_update; do
    body="$(awk "/^${fn}\\(\\)/{p=1} p{print} /^}/{if(p) exit}" "$SCRIPT")"
    grep -q 'ensure_auth_secrets' <<<"$body" && ok "$fn calls ensure_auth_secrets" || bad "$fn never creates the key"
done

echo "== compose passes it to the orchestrator with no default =="
grep -qE '^      REDAMON_SECRET_HMAC_KEY: \$\{REDAMON_SECRET_HMAC_KEY:-\}$' "$REPO_ROOT/docker-compose.yml" \
    && ok "\${REDAMON_SECRET_HMAC_KEY:-}" || bad "missing, or carries a default"

echo
echo "passed: $PASS  failed: $FAIL"
[[ $FAIL -eq 0 ]]
