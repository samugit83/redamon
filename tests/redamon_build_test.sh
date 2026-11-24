#!/usr/bin/env bash
# =============================================================================
# Test suite for the adaptive memory-safe Docker build logic in redamon.sh
# (compose_build / detect_build_resources / pick_parallelism / maybe_warn_low_memory).
#
# Suites: unit, integration (stubbed docker), smoke (real docker/compose),
#         regression. Run:  bash tests/redamon_build_test.sh
# Smoke tests that need a running Docker daemon are skipped (not failed) when
# Docker is unavailable, so the suite is CI-friendly.
# =============================================================================
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Source the script (BASH_SOURCE guard prevents command dispatch). This defines
# compose_build, detect_build_resources, pick_parallelism, maybe_warn_low_memory,
# info/warn/error, etc. It also turns on `set -euo pipefail`; we relax -e in the
# harness so a failing assertion does not abort the whole run.
# shellcheck disable=SC1090
source "$REPO_ROOT/redamon.sh"
set +e

PASS=0; FAIL=0
pass() { PASS=$((PASS+1)); printf '  \033[0;32mPASS\033[0m %s\n' "$1"; }
fail() { FAIL=$((FAIL+1)); printf '  \033[0;31mFAIL\033[0m %s\n' "$1"; }
# assert_eq <label> <got> <expected>
assert_eq() { if [[ "$2" == "$3" ]]; then pass "$1 ($2)"; else fail "$1 (got='$2' expected='$3')"; fi; }
# assert_contains <label> <haystack> <needle>
assert_contains() { if [[ "$2" == *"$3"* ]]; then pass "$1"; else fail "$1 (missing '$3' in: $2)"; fi; }
# assert_not_contains <label> <haystack> <needle>
assert_not_contains() { if [[ "$2" != *"$3"* ]]; then pass "$1"; else fail "$1 (unexpected '$3' in: $2)"; fi; }
section() { printf '\n\033[1m== %s ==\033[0m\n' "$1"; }

# Silence info/warn during tests unless a test opts in (they write to stdout and
# would pollute captured output). Re-defined AFTER source, overriding redamon's.
info() { :; }
warn() { :; }

# --- docker stub: records every invocation + the parallel-limit env in effect ---
# `builder prune` is special-cased so the Layer-3 cache prune can be driven
# independently of the build: PRUNE_RC fails the prune while the build succeeds,
# and PRUNE_OUT injects a realistic "Total:\t<size>" trailer to exercise the
# reclaimed-space reporting path.
# FAIL_MATCH narrows DOCKER_RC to the calls whose arguments contain it, so a
# single batch can fail while its siblings succeed (a plain DOCKER_RC would fail
# the Layer-1 webapp build first and never reach Layer 2).
CALLS=""
DOCKER_RC=0
FAIL_MATCH=""
PRUNE_RC=0
PRUNE_OUT=""
docker() {
    printf 'LIMIT=%s|%s\n' "${COMPOSE_PARALLEL_LIMIT:-unset}" "$*" >> "$CALLS"
    if [[ "${1:-} ${2:-}" == "builder prune" ]]; then
        [[ -n "$PRUNE_OUT" ]] && printf '%s\n' "$PRUNE_OUT"
        return "$PRUNE_RC"
    fi
    if [[ -n "$FAIL_MATCH" ]]; then
        if [[ "$*" == *"$FAIL_MATCH"* ]]; then return "$DOCKER_RC"; fi
        return 0
    fi
    return "$DOCKER_RC"
}
reset_calls() {
    CALLS="$(mktemp)"; DOCKER_RC=0; FAIL_MATCH=""; PRUNE_RC=0; PRUNE_OUT=""
    unset COMPOSE_PARALLEL_LIMIT REDAMON_NO_AUTO_PRUNE
}

# Fix detected resources deterministically for integration tests.
stub_resources() { detect_build_resources() { BUILD_MEM_MB="${1:-8192}"; BUILD_NCPU="${2:-8}"; BUILD_RES_SOURCE="stub"; }; }

# Fix the "build everything" target set so batch membership is deterministic.
# The real resolver shells out to `docker compose build --print`; S5 covers it
# against the real compose file. 7 targets at parallelism 2 -> 4 batches.
STUB_TARGETS="agent baddns-scanner capture-proxy recon vuln-scanner webapp wcvs"
stub_targets() { _compose_build_targets() { printf '%s\n' $STUB_TARGETS; }; }
# Count the service names in a recorded call line (everything after `build `).
svc_count_of() { local rest="${1##*build }"; printf '%s\n' $rest | wc -l | tr -d ' '; }

# =============================================================================
section "UNIT: pick_parallelism tiers"
# formula: usable=mem-2560; bound=usable/2048 (1 if usable<2048); min(bound,cpu) clamp[1,6]
unset REDAMON_BUILD_PARALLEL
u_pp() { BUILD_MEM_MB="$1"; BUILD_NCPU="$2"; pick_parallelism; }
assert_eq "mem=0 undetected -> serial"      "$(u_pp 0 8)"      "1"
assert_eq "mem=2GB -> 1"                     "$(u_pp 2048 8)"   "1"
assert_eq "mem=4GB -> 1"                     "$(u_pp 4096 8)"   "1"
assert_eq "mem=8GB/8cpu -> 2"                "$(u_pp 8192 8)"   "2"
assert_eq "mem=8GB/1cpu -> cpu-bound 1"      "$(u_pp 8192 1)"   "1"
assert_eq "mem=12GB/8cpu -> 4"               "$(u_pp 12288 8)"  "4"
assert_eq "mem=16GB/8cpu -> 6 (clamp)"       "$(u_pp 16384 8)"  "6"
assert_eq "mem=32GB/16cpu -> 6 (clamp)"      "$(u_pp 32768 16)" "6"
assert_eq "mem=32GB/3cpu -> cpu-bound 3"     "$(u_pp 32768 3)"  "3"

section "UNIT: pick_parallelism override"
BUILD_MEM_MB=8192; BUILD_NCPU=8
# Set the env var IN the same subshell that runs pick_parallelism (a `VAR=x cmd`
# prefix would not reach the command substitution).
_ov() { ( export REDAMON_BUILD_PARALLEL="$1"; pick_parallelism ); }
assert_eq "override 0 -> unbounded"    "$(_ov 0)"  "0"
assert_eq "override 1"                 "$(_ov 1)"  "1"
assert_eq "override 5 beats detection" "$(_ov 5)"  "5"
assert_eq "override non-numeric -> 1"  "$(_ov xx)" "1"
unset REDAMON_BUILD_PARALLEL
assert_eq "no override -> detection (8GB->2)" "$(pick_parallelism)" "2"

section "UNIT: detect_build_resources sources"
# Primary: docker info
_docker_info_field() { case "$1" in MemTotal) echo 16777216000;; NCPU) echo 10;; esac; }
detect_build_resources
assert_eq "primary mem (16000MB)"  "$BUILD_MEM_MB"     "16000"
assert_eq "primary cpu"            "$BUILD_NCPU"       "10"
assert_eq "primary source"         "$BUILD_RES_SOURCE" "docker info"
# Fallback Linux: /proc/meminfo (real host)
_docker_info_field() { echo ""; }
uname() { echo "Linux"; }
detect_build_resources
if [[ "$BUILD_MEM_MB" -gt 0 ]]; then pass "linux fallback mem>0 ($BUILD_MEM_MB)"; else fail "linux fallback mem=0"; fi
assert_eq "linux fallback source" "$BUILD_RES_SOURCE" "/proc/meminfo (host)"
if [[ "$BUILD_NCPU" -ge 1 ]]; then pass "linux fallback cpu>=1 ($BUILD_NCPU)"; else fail "cpu<1"; fi
# Fallback macOS: sysctl
_docker_info_field() { echo ""; }
uname() { echo "Darwin"; }
sysctl() { case "$2" in hw.memsize) echo 34359738368;; hw.logicalcpu) echo 12;; esac; }
detect_build_resources
assert_eq "darwin fallback mem (32768MB)" "$BUILD_MEM_MB"     "32768"
assert_eq "darwin fallback source"        "$BUILD_RES_SOURCE" "sysctl (host)"
unset -f _docker_info_field uname sysctl

section "UNIT: maybe_warn_low_memory"
_warn() { warn() { echo "$*"; }; }   # temporarily capture warn
uname() { echo "Darwin"; }
BUILD_MEM_MB=3072; BUILD_RES_SOURCE="docker info"
out="$(warn() { echo "$*"; }; maybe_warn_low_memory 2>&1)"
assert_contains "mac/win hint -> Docker Desktop" "$out" "Docker Desktop"
uname() { echo "Linux"; }
grep() { return 1; }  # not WSL
out="$(warn() { echo "$*"; }; maybe_warn_low_memory 2>&1)"
assert_contains "linux hint -> swap" "$out" "swapfile"
grep() { return 0; }  # WSL
out="$(warn() { echo "$*"; }; maybe_warn_low_memory 2>&1)"
assert_contains "wsl hint -> .wslconfig" "$out" "wslconfig"
unset -f grep uname
BUILD_MEM_MB=16000
out="$(warn() { echo "$*"; }; maybe_warn_low_memory 2>&1)"
assert_eq "adequate mem -> no warning" "$out" ""

# =============================================================================
section "INTEGRATION: compose_build orchestration (stubbed docker)"
stub_resources 8192 8   # -> parallelism 2
stub_targets

# I1: install full build. Layer 1 (webapp alone) + one call per batch of the
# resolved target set + Layer 3's build-cache prune. See the "build-cache
# auto-prune" and "Layer 2 batching" sections below.
reset_calls; compose_build --profile tools build
c1="$(sed -n 1p "$CALLS")"; c2="$(sed -n 2p "$CALLS")"; n="$(wc -l < "$CALLS")"
assert_eq       "I1 full build: 6 docker calls (webapp + 4 batches + prune)" "$n" "6"
assert_contains "I1 webapp isolated first (unset limit)" "$c1" "LIMIT=unset|compose build webapp"
assert_contains "I1 first batch capped, profile kept"    "$c2" "LIMIT=2|compose --profile tools build agent baddns-scanner"
assert_contains "I1 last batch is the remainder" "$(sed -n 5p "$CALLS")" "LIMIT=2|compose --profile tools build wcvs"

# I2: update core INCLUDING webapp (the OOM case) + ordering + passthrough. An
# explicit list longer than the budget is paced too, in the caller's order.
# The list is cmd_update's rebuild_core after a compose change (no Kali service:
# its image is a tool image now).
reset_calls; compose_build build recon-orchestrator agent webapp docker-broker
c1="$(sed -n 1p "$CALLS")"; c2="$(sed -n 2p "$CALLS")"
assert_contains "I2 webapp built FIRST"      "$c1" "LIMIT=unset|compose build webapp"
assert_contains "I2 batch 1 in caller order" "$c2" "LIMIT=2|compose build recon-orchestrator agent"
assert_contains "I2 batch 2 in caller order" "$(sed -n 3p "$CALLS")" "LIMIT=2|compose build webapp docker-broker"
assert_not_contains "I2 no third batch"      "$(sed -n 4p "$CALLS")" "compose build"
reset_calls; compose_build build recon-orchestrator agent webapp docker-broker plugin-runner
assert_contains "I2b an odd list's last batch is the remainder" "$(sed -n 4p "$CALLS")" "LIMIT=2|compose build plugin-runner"

# I3: update core WITHOUT webapp -> no isolation, single capped build (+ prune)
reset_calls; compose_build build agent
n="$(wc -l < "$CALLS")"; c1="$(sed -n 1p "$CALLS")"
assert_eq       "I3 agent-only: 2 docker calls (1 build + 1 prune)" "$n" "2"
assert_not_contains "I3 no webapp isolation"    "$(cat "$CALLS")" "build webapp"
assert_contains "I3 capped single build"        "$c1" "LIMIT=2|compose build agent"

# I4: tools-only update -> no webapp isolation
reset_calls; compose_build --profile tools build recon vuln-scanner
assert_not_contains "I4 tools-only: no webapp build" "$(cat "$CALLS")" "compose build webapp"
assert_contains     "I4 tools built capped"          "$(cat "$CALLS")" "LIMIT=2|compose --profile tools build recon vuln-scanner"

# I5: override=0 still isolates webapp; the rest goes out unbatched and unbounded
reset_calls; REDAMON_BUILD_PARALLEL=0 compose_build build agent webapp
c1="$(sed -n 1p "$CALLS")"; c2="$(sed -n 2p "$CALLS")"
assert_contains "I5 override0 still isolates webapp" "$c1" "LIMIT=unset|compose build webapp"
assert_contains "I5 override0 second call unbounded" "$c2" "LIMIT=unset|compose build agent webapp"
assert_eq       "I5 override0 does not batch" "$(wc -l < "$CALLS")" "3"

# I6: override=3 -> limit 3
reset_calls; REDAMON_BUILD_PARALLEL=3 compose_build build agent
assert_contains "I6 override3 applied" "$(cat "$CALLS")" "LIMIT=3|compose build agent"

# I7: build flags must be repeated on EVERY batch, not just the first
reset_calls; compose_build --profile tools build --no-cache
assert_contains "I7 flag passthrough + isolation" "$(sed -n 2p "$CALLS")" "LIMIT=2|compose --profile tools build --no-cache agent baddns-scanner"
assert_eq       "I7 flag present in all 4 batches" "$(grep -c -- '--no-cache' "$CALLS")" "4"
assert_contains "I7 webapp still isolated"         "$(sed -n 1p "$CALLS")" "compose build webapp"

# I8: failure propagation under set -e (faithful to real script)
reset_calls; DOCKER_RC=7
if ( set -e; DOCKER_RC=7; compose_build build agent ); then rc=0; else rc=$?; fi
assert_eq "I8 non-zero docker propagates" "$rc" "7"
DOCKER_RC=0

# I9: isolation command shape is exactly `build webapp` (no --profile leakage)
reset_calls; compose_build --profile tools build
assert_eq "I9 isolation call exact" "$(sed -n 1p "$CALLS" | cut -d'|' -f2)" "compose build webapp"

# =============================================================================
section "INTEGRATION: Layer 2 batching (bake ignores COMPOSE_PARALLEL_LIMIT)"
# COMPOSE_PARALLEL_LIMIT is only a hint, and Compose v5 / Docker 29 drop it: they
# delegate to bake, which starts every target at once. Issue #171 is that failure
# -- a host that logged "parallelism=3" and then built 16 images together until
# pip ran out of bandwidth. Layer 2 therefore pages the list through `build` N
# names at a time, so the cap is a property of the command line, not a request.
# These tests pin that property; the limit env var is still asserted above because
# older Compose honours it.

# B1: no single call may exceed the budget. This is THE invariant #171 broke.
reset_calls; compose_build --profile tools build
over=""
while IFS= read -r line; do
    case "$line" in *"builder prune"*|*"compose build webapp") continue ;; esac
    if [[ "$(svc_count_of "$line")" -gt 2 ]]; then over="$over[$line]"; fi
done < "$CALLS"
assert_eq "B1 no batch exceeds parallelism 2" "$over" ""

# B2: the batches must cover the resolved set exactly once. A slicing bug that
# drops a target is otherwise invisible -- the build still succeeds, just without
# one image, and the miss only surfaces at `up` time.
built="$(tail -n +2 "$CALLS" | grep -v 'builder prune' | sed 's/.*build //' | tr ' ' '\n' | sort | tr '\n' ' ')"
assert_eq "B2 batches cover the target set once each" "$built" "$(printf '%s\n' $STUB_TARGETS | sort | tr '\n' ' ')"

# B3: a failing batch stops the run (building on wastes minutes on a broken tree)
# and propagates its code. FAIL_MATCH fails only batch 2.
reset_calls; DOCKER_RC=7; FAIL_MATCH="build capture-proxy"
( set -e; compose_build --profile tools build ) >/dev/null 2>&1; rc=$?
assert_eq           "B3 failing batch propagates its code" "$rc" "7"
assert_not_contains "B3 later batches never run"           "$(cat "$CALLS")" "vuln-scanner"
assert_not_contains "B3 failed run does not prune"         "$(cat "$CALLS")" "builder prune"
reset_calls

# B4: a build flag that consumes the next token must not have its VALUE batched as
# if it were a service name (`--build-arg FOO=bar` -> `docker compose build bar`).
reset_calls; compose_build --profile tools build --build-arg FOO=bar recon vuln-scanner baddns-scanner
assert_contains "B4 flag value stays a flag value" "$(sed -n 1p "$CALLS")" "build --build-arg FOO=bar recon vuln-scanner"
assert_contains "B4 remainder batch keeps the flag" "$(sed -n 2p "$CALLS")" "build --build-arg FOO=bar baddns-scanner"

# B5: parallelism 1 (a low-memory host) means strictly one image per call.
reset_calls; REDAMON_BUILD_PARALLEL=1 compose_build build agent recon webapp
assert_eq       "B5 serial: 5 calls (webapp + 3 batches + prune)" "$(wc -l < "$CALLS")" "5"
assert_contains "B5 one service per call" "$(sed -n 2p "$CALLS")" "LIMIT=1|compose build agent"
assert_contains "B5 one service per call" "$(sed -n 4p "$CALLS")" "LIMIT=1|compose build webapp"

# B6: an unresolvable target set (older Compose has no `build --print`) must fall
# back to one unbatched build rather than building nothing. That path is also the
# one where COMPOSE_PARALLEL_LIMIT is still honoured, so nothing is lost.
reset_calls
_compose_build_targets() { :; }
compose_build --profile tools build
assert_eq "B6 no targets -> single unbatched build" "$(sed -n 2p "$CALLS")" "LIMIT=2|compose --profile tools build"
assert_eq "B6 still 3 calls total"                  "$(wc -l < "$CALLS")" "3"
stub_targets

# =============================================================================
section "INTEGRATION: build-cache auto-prune (compose_build Layer 3)"
# A rebuild leaves the previous version's layers in the BuildKit cache with
# nothing referencing them, and Docker never collects them. Layer 3 reclaims that
# after every successful build; these tests pin the safety properties.

# P1: a successful build prunes, and does so AFTER the build, never before.
reset_calls; compose_build build agent
assert_contains "P1 prunes after a successful build" "$(cat "$CALLS")" "builder prune -f"
assert_eq       "P1 prune is the LAST call" "$(tail -1 "$CALLS" | cut -d'|' -f2)" "builder prune -f"

# P2: `-af` must NEVER be used. The plain form keeps the cache backing the images
# just built, so the next update stays incremental. `-af` would additionally wipe
# that warm cache and free no extra disk (those bytes are SHARED with the images
# and stay on disk regardless), making every future rebuild cold for nothing.
assert_not_contains "P2 never prunes with -a" "$(cat "$CALLS")" "builder prune -af"

# P3: a FAILED build must NOT prune. The cache that looks orphaned after a
# failure is the partial work the retry wants to resume from.
reset_calls; DOCKER_RC=7
( set -e; compose_build build agent ) >/dev/null 2>&1
assert_not_contains "P3 no prune after a failed build" "$(cat "$CALLS")" "builder prune"
DOCKER_RC=0

# P4: the prune must not alter the build's exit status in either direction. A
# wedged builder or an old daemon cannot be allowed to fail a good build.
reset_calls; PRUNE_RC=1
( set -e; compose_build build agent ) >/dev/null 2>&1; rc=$?
assert_eq "P4 prune failure keeps build rc 0" "$rc" "0"
PRUNE_RC=0

# P5: REDAMON_NO_AUTO_PRUNE=1 opts out. The builder cache is per-DAEMON, not
# per-project, so on a shared workstation this evicts other projects' cache too.
reset_calls; REDAMON_NO_AUTO_PRUNE=1 compose_build build agent
assert_not_contains "P5 opt-out skips the prune" "$(cat "$CALLS")" "builder prune"

# P6: reclaimed space is reported only when non-zero (the no-op case must stay
# silent rather than print "Reclaimed 0B" after every single build).
reset_calls; PRUNE_OUT=$'abc123\nTotal:\t4.2GB'
out="$( info() { echo "$*"; }; compose_build build agent 2>&1 )"
assert_contains "P6 reports reclaimed space" "$out" "Reclaimed 4.2GB"
reset_calls; PRUNE_OUT=$'Total:\t0B'
out="$( info() { echo "$*"; }; compose_build build agent 2>&1 )"
assert_not_contains "P6 silent when nothing reclaimed" "$out" "Reclaimed"
reset_calls

# =============================================================================
section "SMOKE: real script + docker/compose"
# S1: syntax
if bash -n "$REPO_ROOT/redamon.sh"; then pass "S1 bash -n clean"; else fail "S1 syntax"; fi
# S2: help dispatch runs when executed directly
if bash "$REPO_ROOT/redamon.sh" help >/dev/null 2>&1; then pass "S2 direct 'help' dispatch ok"; else fail "S2 help dispatch"; fi
# S3/S4 need a docker daemon. Probe with `command docker` so the integration
# `docker()` stub (which always returns 0) cannot make an absent daemon look up.
if command -v docker >/dev/null 2>&1 && command docker info >/dev/null 2>&1; then
    # S3: webapp is a real, buildable compose service (Layer-1 target valid)
    svcs="$(command docker compose -f "$REPO_ROOT/docker-compose.yml" config --services 2>/dev/null)"
    assert_contains "S3 webapp is a compose service" "$svcs" "webapp"
    assert_contains "S3 agent is a compose service"  "$svcs" "agent"
    # S4: real detection returns sane values via docker info
    unset -f detect_build_resources 2>/dev/null || true
    source "$REPO_ROOT/redamon.sh"; set +e   # restore real detect_build_resources
    info() { :; }; warn() { :; }
    detect_build_resources
    if [[ "$BUILD_MEM_MB" -gt 0 ]]; then pass "S4 real mem>0 ($BUILD_MEM_MB MB, $BUILD_RES_SOURCE)"; else fail "S4 real mem=0"; fi
    if [[ "$BUILD_NCPU" -ge 1 ]]; then pass "S4 real cpu>=1 ($BUILD_NCPU)"; else fail "S4 cpu"; fi
    # S5: the real target resolver against the real compose file. Everything it
    # returns is handed to `docker compose build`, so an image-only service
    # (neo4j, postgres) leaking into the list would fail the batch it lands in.
    # `unset -f docker` drops the integration stub for this one call.
    targets="$( unset -f docker; _compose_build_targets --profile tools build 2>/dev/null | tr '\n' ' ' )"
    if [[ -n "$targets" ]]; then
        assert_contains     "S5 resolver finds webapp"        "$targets" "webapp"
        assert_contains     "S5 resolver finds vuln-scanner"   "$targets" "vuln-scanner"
        assert_not_contains "S5 resolver excludes neo4j"      "$targets" "neo4j"
        assert_not_contains "S5 resolver excludes postgres"   "$targets" "postgres"
    else
        printf '  \033[0;33mSKIP\033[0m S5 (compose has no `build --print`; batching falls back)\n'
    fi
else
    printf '  \033[0;33mSKIP\033[0m S3/S4 (docker daemon unavailable)\n'
fi

# =============================================================================
section "REGRESSION: call-site wiring"
rd="$REPO_ROOT/redamon.sh"
# R1: no raw `docker compose ... build` invocations remain outside compose_build's own body.
#     compose_build contains exactly one intentional `docker compose build webapp` (Layer 1)
#     and one `docker compose "$@"` (Layer 2). Everything else must go through compose_build.
raw="$(grep -nE '^[[:space:]]*docker compose( --profile tools)? build( |$)' "$rd" | grep -v 'docker compose build webapp' || true)"
assert_eq "R1 no raw parallel builds outside wrapper" "$raw" ""
# R2: all four call sites use compose_build
n_calls="$(grep -cE '(^|[^_])compose_build (--profile tools )?build' "$rd")"
if [[ "$n_calls" -ge 4 ]]; then pass "R2 >=4 compose_build call sites ($n_calls)"; else fail "R2 only $n_calls call sites"; fi
# R3: tools-failure warn message preserved
if grep -q "One or more tool images failed to build" "$rd"; then pass "R3 tools-failure warn intact"; else fail "R3 warn removed"; fi
# R4: source guard present so tests can load functions
if grep -qF '"${BASH_SOURCE[0]}" == "${0}"' "$rd"; then pass "R4 source guard present"; else fail "R4 source guard missing"; fi
# R5: no service silently dropped from a paced build -- pinned by B2 (coverage of
# the resolved set) and I2 (caller-supplied list, in order).
pass "R5 service-set coverage verified in B2/I2"
# R6: the two pieces that make the cap real rather than advisory. If a refactor
# removes either, Layer 2 is back to handing bake the whole list at once (#171).
if grep -q '_compose_build_targets' "$rd"; then pass "R6 target resolver present"; else fail "R6 target resolver missing"; fi
if grep -qF 'batch_svcs[@]:i:parallel' "$rd"; then pass "R6 batching slice present"; else fail "R6 batching slice missing"; fi

# =============================================================================
printf '\n\033[1m==================== RESULTS ====================\033[0m\n'
printf 'PASS: %d   FAIL: %d\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]] && { printf '\033[0;32mALL GREEN\033[0m\n'; exit 0; } || { printf '\033[0;31mFAILURES\033[0m\n'; exit 1; }
