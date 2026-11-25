#!/usr/bin/env bash
#
# Reverse-shell ports of per-user Kali sandboxes, end to end on the LIVE stack (follow-up FU:
# E1-E9, E11, E12 through the real agent, MCP and the orchestrator; E10's screens are group E of
# testing/e2e/scripts/per-user-sandbox-e2e.sh). The scenarios, the phases and what each asserts
# are described in tests/kali_reverse_ports_live.py.
#
#   bash tests/kali_reverse_ports_live.sh                 every scenario (about 60-80 minutes)
#   bash tests/kali_reverse_ports_live.sh --only E1,E7    those scenarios and their prerequisites
#   bash tests/kali_reverse_ports_live.sh --plan          what would run; touches nothing
#   bash tests/kali_reverse_ports_live.sh --self-test     the offline parsers; touches nothing
#
# It recreates the stack's recon-orchestrator per phase (the port pool and its hold time set in
# this process only, every other input replayed) and puts it back at the end, so it runs under
# the shared heavy lock: it takes REDAMON_HEAVY_LOCK (default the stack checkout's
# .git/redamon-heavy.lock) unless a parent holds it (`flock -o LOCK bash tests/...`), waiting at
# most FU_P7_LOCK_WAIT_S seconds (default 10800). Needs the stack up, the g1 seed's accounts
# (it seeds them again itself, idempotent), Agent in the Loop and the MCP server on, the images
# apache_2449-vulnerable-apache:latest, busybox:latest and redamon-kali-sandbox:latest.
# Exit 0 all PASS, 1 any FAIL, 2 not ready (never a skip: it is milestone evidence).
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="$ROOT/tests/kali_reverse_ports_live.py"

command -v python3 >/dev/null 2>&1 || { echo "FAIL: python3 is not installed"; exit 2; }
for arg in "$@"; do
    case "$arg" in
        --plan|--self-test|-h|--help) exec python3 -I "$PY" "$@" ;;
    esac
done
command -v docker >/dev/null 2>&1 || { echo "FAIL: docker is not installed"; exit 2; }

ORCH="${FU_P7_ORCHESTRATOR:-redamon-recon-orchestrator}"
if [[ -n "${REDAMON_HEAVY_LOCK:-}" ]]; then
    LOCK="$REDAMON_HEAVY_LOCK"
else
    workdir="$(docker inspect -f '{{index .Config.Labels "com.docker.compose.project.working_dir"}}' "$ORCH" 2>/dev/null || true)"
    [[ -n "$workdir" ]] || { echo "FAIL: $ORCH does not exist, so the stack's lock is unknown (set REDAMON_HEAVY_LOCK)"; exit 2; }
    LOCK="$(git -C "$workdir" rev-parse --path-format=absolute --git-common-dir)/redamon-heavy.lock"
fi

# Whether an ancestor holds the lock without passing a descriptor down (`flock -o LOCK ...`):
# /proc/locks names the holder's pid right before the MAJ:MIN:INODE field.
ancestor_holds_lock() {
    local inode pids p
    inode="$(stat -c %i "$LOCK" 2>/dev/null)" || return 1
    pids="$(awk -v ino="$inode" '{ for (i = 2; i <= NF; i++) if ($i ~ ("^[0-9a-f]+:[0-9a-f]+:" ino "$")) print $(i - 1) }' /proc/locks)"
    [[ -n "$pids" ]] || return 1
    p=$PPID
    while [[ -n "$p" && "$p" -gt 1 ]]; do
        grep -qx "$p" <<< "$pids" && return 0
        p="$(awk '/^PPid:/ {print $2}' "/proc/$p/status" 2>/dev/null)"
    done
    return 1
}

if ancestor_holds_lock; then
    echo "lock: held by a parent process"
else
    exec 9>>"$LOCK"
    if ! flock -n 9; then
        echo "waiting for the heavy lock $LOCK (at most ${FU_P7_LOCK_WAIT_S:-10800} s) ..."
        flock -w "${FU_P7_LOCK_WAIT_S:-10800}" 9 || { echo "FAIL: the heavy lock was not free in time"; exit 2; }
    fi
    echo "lock: taken"
fi
# python3 keeps descriptor 9 (the lock) and its subprocesses do not inherit it (close_fds).
exec python3 -I "$PY" "$@"
