#!/usr/bin/env bash
# =============================================================================
# Test suite for _status_core_service_report in redamon.sh (issue #184).
#
# Why this exists: `docker compose ps` without -a omits a container that has
# EXITED, so a crashed core service simply vanished from `redamon.sh status`
# and the stack looked clean. Meanwhile the webapp, which reaches those
# services by container name, failed with "getaddrinfo ENOTFOUND agent" and the
# operator read that as a fault in the LLM endpoint they had just configured.
#
# Pure unit test: `docker` is stubbed as a bash function, so it runs anywhere
# with no Docker daemon.  Run:  bash tests/redamon_status_core_test.sh
# =============================================================================
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# shellcheck disable=SC1090
source "$REPO_ROOT/redamon.sh"   # BASH_SOURCE guard blocks command dispatch
set +e

PASS=0; FAIL=0
pass() { PASS=$((PASS+1)); printf '  \033[0;32mPASS\033[0m %s\n' "$1"; }
fail() { FAIL=$((FAIL+1)); printf '  \033[0;31mFAIL\033[0m %s\n' "$1"; }
section() { printf '\n\033[1m== %s ==\033[0m\n' "$1"; }
assert_contains() {
  if [[ "$2" == *"$3"* ]]; then pass "$1"; else fail "$1 (missing '$3' in: $2)"; fi
}
assert_not_contains() {
  if [[ "$2" != *"$3"* ]]; then pass "$1"; else fail "$1 (unexpected '$3' in: $2)"; fi
}

# --- stub: `docker` shadows the real binary (a function wins over $PATH) ------
# STATES maps a compose service name to what `compose ps -a --format {{.State}}`
# would print. An unset key prints nothing, which is how Compose reports a
# service that has no container at all.
TMP_SETE="$(mktemp)"
trap 'rm -f "$TMP_SETE"' EXIT

declare -A STATES=()
docker() {
  # We only ever call: docker compose ps -a --format '{{.State}}' <service>
  local svc="${*: -1}"
  [[ -n "${STATES[$svc]+x}" ]] && printf '%s\n' "${STATES[$svc]}"
  return 0
}

all_running() {
  STATES=()
  local s
  for s in $CORE_SERVICES; do STATES["$s"]="running"; done
}

# ---------------------------------------------------------------------------
section "healthy stack stays quiet"

all_running
OUT="$(_status_core_service_report 2>&1)"
if [[ -z "${OUT//[[:space:]]/}" ]]; then
  pass "no output when every core service is running"
else
  fail "expected silence on a healthy stack (got: $OUT)"
fi

# ---------------------------------------------------------------------------
section "a stopped agent is named"

all_running
STATES["agent"]="exited"
OUT="$(_status_core_service_report 2>&1)"
assert_contains "reports the section header"        "$OUT" "Core services NOT running"
assert_contains "names the dead service"            "$OUT" "agent"
assert_contains "reports its actual state"          "$OUT" "exited"
assert_contains "explains the ENOTFOUND symptom"    "$OUT" "ENOTFOUND"
assert_contains "gives the logs command"            "$OUT" "docker compose logs"
assert_contains "gives the recovery command"        "$OUT" "./redamon.sh up"
assert_not_contains "does not name healthy services" "$OUT" "postgres"

# ---------------------------------------------------------------------------
section "a service that was never created"

all_running
unset 'STATES[agent]'
OUT="$(_status_core_service_report 2>&1)"
assert_contains "distinguishes 'not created' from 'exited'" "$OUT" "not created"

# ---------------------------------------------------------------------------
section "a restart loop is not mistaken for healthy"

all_running
STATES["agent"]="restarting"
OUT="$(_status_core_service_report 2>&1)"
assert_contains "restarting counts as down" "$OUT" "restarting"

# ---------------------------------------------------------------------------
section "multiple services down"

all_running
STATES["agent"]="exited"
STATES["neo4j"]="exited"
OUT="$(_status_core_service_report 2>&1)"
assert_contains "lists the agent"  "$OUT" "agent"
assert_contains "lists neo4j"      "$OUT" "neo4j"

# ---------------------------------------------------------------------------
section "the agent is actually in CORE_SERVICES"
# The report is only useful if the service behind issue #184 is covered.
assert_contains "CORE_SERVICES includes agent"  " $CORE_SERVICES " " agent "
assert_contains "CORE_SERVICES includes webapp" " $CORE_SERVICES " " webapp "

# ---------------------------------------------------------------------------
section "regression: a never-installed clone is told to install, not to 'up'"
# Before install NOTHING has a container, so every service reads "not created".
# Telling that user to run `./redamon.sh up` is wrong advice - there are no
# images to start. This is a fresh clone, not an outage.

STATES=()
OUT="$(_status_core_service_report 2>&1)"
assert_contains "points a fresh clone at install" "$OUT" "install"
assert_not_contains "does not call a fresh clone an outage" "$OUT" "Core services NOT running"
assert_not_contains "does not tell a fresh clone to run up" "$OUT" "./redamon.sh up"

# One container existing is enough to prove the stack WAS installed, so a
# missing service there is a real outage again.
STATES=()
STATES["postgres"]="running"
OUT="$(_status_core_service_report 2>&1)"
assert_contains "an installed stack with a missing service is still an outage" \
  "$OUT" "Core services NOT running"
assert_contains "and it names the missing agent" "$OUT" "agent"

# ---------------------------------------------------------------------------
section "regression: the report must survive set -e"
# redamon.sh runs under `set -euo pipefail`. A helper whose last evaluated
# command is a false test returns non-zero, and a bare call to it would abort
# `status` before the memory report ever prints.
(
  set -euo pipefail
  all_running
  _status_core_service_report >/dev/null
  echo "survived-healthy"
) > "$TMP_SETE" 2>&1
if grep -q survived-healthy "$TMP_SETE"; then
  pass "healthy path returns 0 under set -e"
else
  fail "healthy path aborted under set -e"
fi

(
  set -euo pipefail
  all_running
  STATES["agent"]="exited"
  _status_core_service_report >/dev/null
  echo "survived-degraded"
) > "$TMP_SETE" 2>&1
if grep -q survived-degraded "$TMP_SETE"; then
  pass "degraded path returns 0 under set -e"
else
  fail "degraded path aborted under set -e"
fi

# ---------------------------------------------------------------------------
printf '\n\033[1mResults:\033[0m \033[0;32m%d passed\033[0m, \033[0;31m%d failed\033[0m\n' "$PASS" "$FAIL"
[[ $FAIL -eq 0 ]]
