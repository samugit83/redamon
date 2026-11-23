#!/usr/bin/env bash
# The UI end-to-end test of per-user Kali sandboxes (group 1, S23): runs
# testing/e2e/tests/perUserSandbox.spec.ts one group at a time, each against the
# orchestrator setting it needs.
#
#   bash testing/e2e/scripts/per-user-sandbox-e2e.sh              # groups A, B, C, D
#   bash testing/e2e/scripts/per-user-sandbox-e2e.sh --groups A,D
#   bash testing/e2e/scripts/per-user-sandbox-e2e.sh --list       # list the tests; touches nothing
#   bash testing/e2e/scripts/per-user-sandbox-e2e.sh --dry-run    # say, per group, what would be recreated
#   bash testing/e2e/scripts/per-user-sandbox-e2e.sh --check-lock # take the lock as a run would, then exit
#   bash testing/e2e/scripts/per-user-sandbox-e2e.sh -- --reporter=line   # extra Playwright arguments
#
# For each group it recreates the running stack's recon-orchestrator with that
# group's variables set in this shell only (never in .env), and only when the
# running one differs. Every other input the orchestrator was created with is
# replayed from the running container (its variables, CPU, memory and process
# limits, port), so shell-only values survive. Before the first recreate the
# originals go to a 0600 file beside the lock (secret values as SHA-256 only);
# the exit trap puts them back and compares, and a run killed before that
# puts them back at the start of the next one. It stops and removes no sandbox and
# no templates volume: the sandboxes a run starts are its test persons' own and
# stop when idle, as anyone's.
#
# It fails (exit 1) when Docker, npx, curl, the orchestrator, the agent or the
# webapp is missing, before doing anything; G1_E2E_ALLOW_SKIP=1 turns that into
# SKIP (exit 0). It takes the shared heavy lock (REDAMON_HEAVY_LOCK, default the
# stack checkout's .git/redamon-heavy.lock) unless it inherits a descriptor that
# holds it or runs under the process that holds it (`flock LOCK bash ...`);
# G1_E2E_LOCK_HELD=1 asks for that and fails when it is not so. It waits at most
# G1_E2E_LOCK_WAIT_S seconds (default 10800).
#
# The spec reads the seed state of tests/kali_sandbox_seed_live.py (G1_STATE, or
# ${TMPDIR:-/tmp}/g1-live-state.json) and seeds it again itself (idempotent).
#
# Each run keeps every group's Playwright results (failure messages, attached
# screenshots) in its own folder, G1_E2E_RESULTS_DIR/<UTC time>-<pid>/group-<G>
# (default testing/e2e/test-results-g1e2e, ignored by git): Playwright empties its
# output folder at every start, so one folder per group would lose the earlier ones.
# Playwright runs under `setpriv --pdeathsig TERM` where setpriv offers it, so it
# ends with a wrapper killed by SIGKILL; the next run stops what is left of it first.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
E2E="$(cd "$HERE/.." && pwd)"
ORCH="${G1_E2E_ORCHESTRATOR:-redamon-recon-orchestrator}"
AGENT="${G1_E2E_AGENT:-redamon-agent}"
BASE_URL="${REDAMON_BASE_URL:-http://localhost:3000}"
LOCK_WAIT="${G1_E2E_LOCK_WAIT_S:-10800}"
# Every variable a group may set. A group leaves the others at the values the
# orchestrator had when the run started.
MANAGED=(KALI_SANDBOX_IDLE_MINUTES OS_HEADROOM_MEM SERVICE_BASELINE_MEM)
# Names whose values never reach the originals file (compared by hash instead).
SECRET_NAME='(_KEY|_TOKEN|_SECRET|_PASSWORD|_PASS|DATABASE_URL)$'

usage() { sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'; }

GROUPS_ARG="A,B,C,D"
LIST=0
DRY=0
CHECK_LOCK=0
EXTRA=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --groups) GROUPS_ARG="${2:?--groups needs a list such as A,C}"; shift ;;
        --groups=*) GROUPS_ARG="${1#--groups=}" ;;
        --list) LIST=1 ;;
        --dry-run) DRY=1 ;;
        --check-lock) CHECK_LOCK=1 ;;
        -h|--help) usage; exit 0 ;;
        --) shift; EXTRA=("$@"); break ;;
        *) echo "unknown argument: $1 (see --help)" >&2; exit 2 ;;
    esac
    shift
done

not_ready() {
    if [[ "${G1_E2E_ALLOW_SKIP:-0}" == 1 ]]; then echo "SKIP: $1"; exit 0; fi
    echo "FAIL: $1 (G1_E2E_ALLOW_SKIP=1 turns this into a skip)" >&2
    exit 1
}

command -v npx >/dev/null || not_ready "npx is not installed"
if [[ $LIST -eq 1 ]]; then
    cd "$E2E"
    exec npx playwright test --list perUserSandbox
fi

IFS=',' read -r -a GROUP_LIST <<< "${GROUPS_ARG^^}"
for g in "${GROUP_LIST[@]}"; do
    [[ "$g" =~ ^[ABCD]$ ]] || { echo "unknown group: $g (A, B, C or D)" >&2; exit 2; }
done

command -v docker >/dev/null || not_ready "docker is not installed"
command -v curl >/dev/null || not_ready "curl is not installed"

is_running() { [[ "$(docker inspect -f '{{.State.Running}}' "$1" 2>/dev/null)" == true ]]; }

label() { docker inspect -f "{{index .Config.Labels \"$1\"}}" "$ORCH" 2>/dev/null || true; }
if [[ -n "${REDAMON_HEAVY_LOCK:-}" ]]; then
    LOCK="$REDAMON_HEAVY_LOCK"
elif [[ -n "$(label com.docker.compose.project.working_dir)" ]]; then
    LOCK="$(git -C "$(label com.docker.compose.project.working_dir)" rev-parse --path-format=absolute --git-common-dir)/redamon-heavy.lock"
else
    not_ready "$ORCH does not exist, so the stack's lock file is unknown (set REDAMON_HEAVY_LOCK)"
fi
ORIG_FILE="${G1_E2E_ORIGINALS:-$(dirname "$LOCK")/redamon-g1-e2e-orchestrator.env}"
# A run's Playwright process group and its leader's start time: Playwright holds no lock descriptor, so
# after a killed wrapper it would run on unlocked beside the next run, which stops it first.
PW_FILE="${ORIG_FILE%.env}.playwright"

# --- the lock ------------------------------------------------------------------
LOCK_STATE=""

lock_id() { stat -L -c '%d:%i' "$1" 2>/dev/null; }

# A descriptor of this shell open on the lock file through which the lock is held:
# inherited from a caller that did `exec 9>LOCK; flock 9` or ran `flock LOCK bash ...`.
held_descriptor() {
    local entry fd want
    want="$(lock_id "$LOCK")" || return 1
    for entry in "/proc/$$/fd/"*; do
        fd="${entry##*/}"
        [[ "$fd" =~ ^[0-9]+$ && "$fd" -gt 2 ]] || continue
        [[ "$(lock_id "$entry")" == "$want" ]] || continue
        # The kernel lists a flock in the fdinfo of every descriptor of the open file that holds it.
        # Trying `flock -n` instead would take the lock through a descriptor the caller merely
        # opened, and it would stay held by the caller after this script.
        if grep -q '^lock:.*FLOCK' "/proc/$$/fdinfo/$fd" 2>/dev/null; then echo "$fd"; return 0; fi
    done
    return 1
}

# Whether an ancestor holds the lock without passing a descriptor down (`flock -o LOCK ...`).
ancestor_holds_lock() {
    local inode pids p
    inode="$(stat -c %i "$LOCK" 2>/dev/null)" || return 1
    # A /proc/locks line names the holder's pid right before the MAJ:MIN:INODE field.
    pids="$(awk -v ino="$inode" '{ for (i = 2; i <= NF; i++) if ($i ~ ("^[0-9a-f]+:[0-9a-f]+:" ino "$")) print $(i - 1) }' /proc/locks)"
    [[ -n "$pids" ]] || return 1
    p=$PPID
    while [[ -n "$p" && "$p" -gt 1 ]]; do
        grep -qx "$p" <<< "$pids" && return 0
        p="$(awk '/^PPid:/ {print $2}' "/proc/$p/status" 2>/dev/null)"
    done
    return 1
}

take_lock() {
    local fd
    if fd="$(held_descriptor)"; then LOCK_STATE="held by the caller (inherited descriptor $fd)"; return 0; fi
    if ancestor_holds_lock; then LOCK_STATE="held by a parent process"; return 0; fi
    if [[ "${G1_E2E_LOCK_HELD:-0}" == 1 ]]; then
        echo "FAIL: G1_E2E_LOCK_HELD=1, but no descriptor of this process and no parent holds $LOCK" >&2
        exit 1
    fi
    exec 9>>"$LOCK"
    if ! flock -n 9; then
        echo "waiting for the heavy lock $LOCK (at most ${LOCK_WAIT} s) ..."
        if ! flock -w "$LOCK_WAIT" 9; then
            echo "FAIL: the heavy lock $LOCK was not free within ${LOCK_WAIT} s" >&2
            exit 1
        fi
    fi
    LOCK_STATE="taken"
}

if [[ $CHECK_LOCK -eq 1 ]]; then
    take_lock
    echo "lock: $LOCK_STATE"
    exit 0
fi

# --- readiness: nothing is done before these hold -------------------------------------
is_running "$ORCH" || not_ready "$ORCH is not running (the suite does not start the stack)"
STACK_DIR="$(label com.docker.compose.project.working_dir)"
STACK_PROJECT="$(label com.docker.compose.project)"
STACK_FILES="$(label com.docker.compose.project.config_files)"
if [[ -z "$STACK_DIR" || -z "$STACK_PROJECT" || -z "$STACK_FILES" ]]; then
    echo "FAIL: $ORCH carries no compose labels: it was not started by docker compose" >&2
    exit 1
fi

readiness_problem() {
    local code
    is_running "$AGENT" || { echo "the $AGENT container is not running"; return; }
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "$BASE_URL/api/health" || true)"
    [[ "$code" == 200 ]] || echo "the webapp at $BASE_URL does not answer /api/health (HTTP ${code:-none})"
}

# --- the orchestrator's inputs ---------------------------------------------------------
# Lines "KEY NAME" for the orchestrator service: KEY an environment entry whose value is
# ${NAME...}, or @mem / @pids / @cpus / @port for the limits and the published port.
service_inputs() {
    local f files
    IFS=',' read -r -a files <<< "$STACK_FILES"
    for f in "${files[@]}"; do
        [[ -f "$f" ]] || continue
        awk '
            /^  recon-orchestrator:[[:space:]]*$/ { inside = 1; next }
            inside && /^  [A-Za-z0-9_.-]+:[[:space:]]*$/ { inside = 0 }
            inside && /^[^[:space:]#]/ { inside = 0 }
            inside {
                line = $0; sub(/[[:space:]]#.*$/, "", line)
                if (!match(line, /\$\{[A-Za-z_][A-Za-z0-9_]*/)) next
                name = substr(line, RSTART + 2, RLENGTH - 2)
                if (line ~ /^[[:space:]]*mem_limit:/) print "@mem " name
                else if (line ~ /^[[:space:]]*pids_limit:/) print "@pids " name
                else if (line ~ /^[[:space:]]*cpus:/) print "@cpus " name
                else if (line ~ /^[[:space:]]*-[[:space:]]*"?[0-9.]*:?\$\{/) print "@port " name
                # Only an entry whose whole value is ${NAME...}: a value built around one
                # (http://localhost:${AGENT_PORT}) cannot be replayed into NAME.
                else if (line ~ /^[[:space:]]*-?[[:space:]]*[A-Za-z_][A-Za-z0-9_]*[[:space:]]*[:=][[:space:]]*"?\$\{[A-Za-z_][A-Za-z0-9_]*(:?[-?][^}]*)?\}"?[[:space:]]*$/) {
                    match(line, /^[[:space:]]*-?[[:space:]]*[A-Za-z_][A-Za-z0-9_]*/)
                    key = substr(line, RSTART, RLENGTH); gsub(/[-[:space:]]/, "", key); print key " " name
                }
            }' "$f"
    done
}

sha() { printf '%s' "$1" | sha256sum | cut -d' ' -f1; }

declare -A ORIG_ENV=() ORIG_HASH=() ORIG_LIM=()
declare -A TARGET=() TARGET_HASH=()
declare -A SNAP_ENV=() SNAP_LIM=()

# The running container's environment and limits, into SNAP_ENV and SNAP_LIM.
snapshot() {
    local line ports nano mem pids
    SNAP_ENV=(); SNAP_LIM=()
    while IFS= read -r line; do
        [[ "$line" == *=* ]] && SNAP_ENV["${line%%=*}"]="${line#*=}"
    done < <(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$ORCH")
    read -r nano mem pids < <(
        docker inspect -f '{{.HostConfig.NanoCpus}} {{.HostConfig.Memory}} {{if .HostConfig.PidsLimit}}{{.HostConfig.PidsLimit}}{{else}}0{{end}}' "$ORCH")
    ports="$(docker inspect -f '{{json .HostConfig.PortBindings}}' "$ORCH")"
    SNAP_LIM["NanoCpus"]="$nano"
    SNAP_LIM["Memory"]="$mem"
    SNAP_LIM["PidsLimit"]="$pids"
    SNAP_LIM["Port"]="$(sed -n 's/.*"8010\/tcp":\[{"HostIp":"[^"]*","HostPort":"\([0-9]*\)".*/\1/p' <<< "$ports")"
}

# The originals are the running container's inputs now.
snapshot_originals() {
    local key
    snapshot
    ORIG_ENV=(); ORIG_HASH=(); ORIG_LIM=()
    for key in "${!SNAP_ENV[@]}"; do ORIG_ENV[$key]="${SNAP_ENV[$key]}"; done
    for key in "${!SNAP_LIM[@]}"; do ORIG_LIM[$key]="${SNAP_LIM[$key]}"; done
}

# Writes the originals before the first recreate (secret values as SHA-256 only).
persist_originals() {
    local key tmp
    tmp="$ORIG_FILE.tmp.$$"
    ( umask 077
      { echo "# redamon g1 e2e (S23): $ORCH as it was before a wrapper run recreated it"
        for key in "${!ORIG_ENV[@]}"; do
            if [[ "$key" =~ $SECRET_NAME ]]; then echo "S $key=$(sha "${ORIG_ENV[$key]}")"
            else echo "E $key=${ORIG_ENV[$key]}"; fi
        done
        for key in "${!ORIG_LIM[@]}"; do echo "L $key=${ORIG_LIM[$key]}"; done
      } > "$tmp" )
    chmod 600 "$tmp"
    mv -f "$tmp" "$ORIG_FILE"
}

load_originals() {
    local kind rest
    ORIG_ENV=(); ORIG_HASH=(); ORIG_LIM=()
    # A file an older wrapper wrote may also hold T and P lines (its sandbox records): ignored.
    while IFS=' ' read -r kind rest; do
        case "$kind" in
            E) ORIG_ENV["${rest%%=*}"]="${rest#*=}" ;;
            S) ORIG_HASH["${rest%%=*}"]="${rest#*=}" ;;
            L) ORIG_LIM["${rest%%=*}"]="${rest#*=}" ;;
        esac
    done < "$ORIG_FILE"
}

# TARGET = the originals with the managed NAME=value pairs given as arguments.
set_target() {
    local key pair
    TARGET=(); TARGET_HASH=()
    for key in "${!ORIG_ENV[@]}"; do TARGET[$key]="${ORIG_ENV[$key]}"; done
    for key in "${!ORIG_HASH[@]}"; do TARGET_HASH[$key]="${ORIG_HASH[$key]}"; done
    for pair in "$@"; do TARGET["${pair%%=*}"]="${pair#*=}"; done
}

wait_healthy() {
    local _ status
    for _ in $(seq 1 90); do
        # "running" is printed only for a container without a healthcheck.
        status="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$ORCH" 2>/dev/null || true)"
        [[ "$status" == healthy || "$status" == running ]] && return 0
        sleep 2
    done
    echo "FAIL: $ORCH did not become healthy" >&2
    return 1
}

# Recreates the orchestrator with TARGET and the original limits. Values are exported in a
# subshell, never put on a command line (some are secrets); a secret known only by its hash
# is left to .env and checked by compare_running.
recreate() {
    local summary="" v
    for v in "${MANAGED[@]}"; do summary+=" $v=${TARGET[$v]-}"; done
    echo "recreating $ORCH with${summary} (every other input replayed from the original)"
    (
        while read -r key name; do
            case "$key" in
                @mem) [[ "${ORIG_LIM[Memory]:-0}" -gt 0 ]] && export "$name=${ORIG_LIM[Memory]}" ;;
                @pids) [[ "${ORIG_LIM[PidsLimit]:-0}" -gt 0 ]] && export "$name=${ORIG_LIM[PidsLimit]}" ;;
                @cpus) [[ "${ORIG_LIM[NanoCpus]:-0}" -gt 0 ]] && export "$name=$(awk -v n="${ORIG_LIM[NanoCpus]}" 'BEGIN { printf "%g", n / 1e9 }')" ;;
                @port) [[ -n "${ORIG_LIM[Port]:-}" ]] && export "$name=${ORIG_LIM[Port]}" ;;
                *) if [[ -v TARGET[$key] ]]; then export "$name=${TARGET[$key]}"; fi ;;
            esac
        done < <(service_inputs)
        export COMPOSE_FILE="${STACK_FILES//,/:}"
        cd "$STACK_DIR"
        exec docker compose -p "$STACK_PROJECT" up -d --no-deps recon-orchestrator
    )
    wait_healthy
}

# Whether the running orchestrator matches TARGET and the original limits; names what differs (never a value).
compare_running() {
    local key bad=0
    snapshot
    for key in "${!TARGET[@]}"; do
        [[ "${SNAP_ENV[$key]-}" == "${TARGET[$key]}" ]] || { echo "  $key differs" >&2; bad=1; }
    done
    for key in "${!TARGET_HASH[@]}"; do
        [[ "$(sha "${SNAP_ENV[$key]-}")" == "${TARGET_HASH[$key]}" ]] || { echo "  $key differs" >&2; bad=1; }
    done
    for key in NanoCpus Memory PidsLimit Port; do
        [[ "${SNAP_LIM[$key]-}" == "${ORIG_LIM[$key]-}" ]] || { echo "  $key differs (${ORIG_LIM[$key]-} -> ${SNAP_LIM[$key]-})" >&2; bad=1; }
    done
    return "$bad"
}

# The pool of group C: two sandbox envelopes (2 GiB) plus half of a partial recon's
# (768 MiB in resource_profile.default.json). Alice's sandbox and the scan are each the
# first of their class (never refused); Bob's sandbox then finds 0.625 GiB left, under its
# 1 GiB envelope, and 1.375 GiB once the scan has stopped.
group_c_pool() {
    local total headroom pool baseline
    total=$(awk '/^MemTotal:/ {print $2 * 1024}' /proc/meminfo)
    headroom="${G1_E2E_OS_HEADROOM_MEM:-1073741824}"
    pool="${G1_E2E_POOL_BYTES:-2550136832}"
    baseline=$(( total - headroom - pool ))
    if (( baseline <= 0 )); then
        echo "FAIL: this host's memory ($total bytes) is too small to lower the pool to $pool bytes" >&2
        return 1
    fi
    echo "OS_HEADROOM_MEM=$headroom SERVICE_BASELINE_MEM=$baseline"
}

# The managed NAME=value pairs of a group (the original value where the group sets none).
group_env() {
    local -A want=()
    local v pair
    for v in "${MANAGED[@]}"; do want[$v]="${ORIG_ENV[$v]-}"; done
    case "$1" in
        B) want[KALI_SANDBOX_IDLE_MINUTES]=1 ;;
        C) for pair in $C_POOL; do want[${pair%%=*}]="${pair#*=}"; done ;;
    esac
    for v in "${MANAGED[@]}"; do echo "$v=${want[$v]}"; done
}

# Whether the running orchestrator already has the group's managed values.
running_matches() {
    local pair
    snapshot
    for pair in "$@"; do
        [[ "${pair#*=}" == "${SNAP_ENV[${pair%%=*}]-}" ]] || return 1
    done
    return 0
}

C_POOL=""
if [[ ",${GROUP_LIST[*]}," == *C* ]]; then
    C_POOL="$(group_c_pool)" || exit 1
fi

declare -A TITLE=([A]="Group A" [B]="Group B" [C]="Group C" [D]="Group D")

if [[ $DRY -eq 1 ]]; then
    problem="$(readiness_problem)"
    echo "readiness: ${problem:-ok}"
    [[ -f "$ORIG_FILE" ]] && echo "an earlier run left $ORIG_FILE: a run puts the orchestrator back from it first"
    [[ -f "$PW_FILE" ]] && echo "an earlier run left $PW_FILE: a run first stops that Playwright if it still runs"
    snapshot_originals
    echo "replayed inputs: $(service_inputs | wc -l) (limits: cpus $(awk -v n="${ORIG_LIM[NanoCpus]}" 'BEGIN { printf "%g", n / 1e9 }'), memory ${ORIG_LIM[Memory]}, pids ${ORIG_LIM[PidsLimit]}, port ${ORIG_LIM[Port]:-none})"
    for g in "${GROUP_LIST[@]}"; do
        mapfile -t wanted < <(group_env "$g")
        if running_matches "${wanted[@]}"; then
            echo "${TITLE[$g]}: the running $ORCH already has its variables; nothing is recreated"
        else
            echo "${TITLE[$g]}: $ORCH would be recreated with ${wanted[*]}"
        fi
    done
    exit 0
fi

problem="$(readiness_problem)"
[[ -z "$problem" ]] || not_ready "$problem"

take_lock
echo "lock: $LOCK_STATE"

# The labs, chisel edges and their networks of a test that timed out or was killed (its finally never
# ran); the spec labels every one g1e2e=1.
sweep_test_leftovers() {
    local id
    for id in $(docker ps -aq --filter label=g1e2e=1); do
        docker rm -f "$id" >/dev/null 2>&1 && echo "removed a test container left behind ($id)"
    done
    for id in $(docker network ls -q --filter label=g1e2e=1); do
        docker network rm "$id" >/dev/null 2>&1 && echo "removed a test network left behind ($id)"
    done
    return 0
}

# The start time of process $1 (field 22 of /proc/<pid>/stat), nothing when it is gone.
proc_start() {
    local stat f
    stat="$(cat "/proc/$1/stat" 2>/dev/null)" || return 0
    read -r -a f <<< "${stat##*) }"
    echo "${f[19]-}"
}

# Stops the process group $1 (Playwright, its browsers and stub servers) and waits until it is gone.
# INT first: Playwright then runs the spec's afterAll hooks, which put the settings back.
stop_group() {
    local _
    kill -INT -- "-$1" 2>/dev/null || true
    for _ in $(seq 1 60); do kill -0 -- "-$1" 2>/dev/null || return 0; sleep 0.5; done
    kill -TERM -- "-$1" 2>/dev/null || true
    for _ in $(seq 1 20); do kill -0 -- "-$1" 2>/dev/null || return 0; sleep 0.5; done
    kill -KILL -- "-$1" 2>/dev/null || true
    for _ in $(seq 1 20); do kill -0 -- "-$1" 2>/dev/null || return 0; sleep 0.5; done
    return 1
}

# The Playwright group a killed run recorded, while it still runs: its leader with the recorded start
# time, or what is left of the group once the leader is gone (a group id is not reused while a member
# lives). A leader with another start time is a reused pid, never signalled.
orphan_group() {
    local pgid start now
    [[ -f "$PW_FILE" ]] || return 1
    read -r pgid start < "$PW_FILE" || return 1
    [[ "$pgid" =~ ^[0-9]+$ ]] || return 1
    now="$(proc_start "$pgid")"
    [[ -z "$now" || "$now" == "$start" ]] || return 1
    kill -0 -- "-$pgid" 2>/dev/null || return 1
    echo "$pgid"
}

# Playwright holds no lock descriptor, so a killed run's runs on unlocked: stop it before anything else.
if PW_ORPHAN="$(orphan_group)"; then
    echo "a killed run's Playwright (process group $PW_ORPHAN) still runs: stopping it first"
    if ! stop_group "$PW_ORPHAN"; then
        echo "FAIL: it did not stop; nothing else was done" >&2
        exit 1
    fi
fi
rm -f "$PW_FILE"

# Under the lock no spec runs, so a g1e2e container now is a killed run's.
sweep_test_leftovers

# A run killed after a recreate left its originals: put them back first, with what that run left.
if [[ -f "$ORIG_FILE" ]]; then
    echo "an earlier run left $ORIG_FILE: putting $ORCH back first"
    load_originals
    set_target
    if ! recreate || ! compare_running; then
        echo "FAIL: $ORCH could not be put back from $ORIG_FILE (kept); fix it by hand before the next run" >&2
        exit 1
    fi
    rm -f "$ORIG_FILE"
fi

# Read under the lock: these are the values the trap puts back.
snapshot_originals
CHANGED=0
PW_PID=""

stop_playwright() {
    [[ -n "$PW_PID" ]] || return 0
    if stop_group "$PW_PID"; then
        rm -f "$PW_FILE"
    else
        echo "FAIL: Playwright (process group $PW_PID) did not stop; the next run stops it first" >&2
    fi
    PW_PID=""
}

restore() {
    local rc=$?
    # A second Ctrl-C must not leave the orchestrator half put back.
    trap '' INT TERM HUP
    trap - EXIT
    stop_playwright
    sweep_test_leftovers
    if [[ $CHANGED -eq 1 ]]; then
        set_target
        if recreate && compare_running; then
            rm -f "$ORIG_FILE"
        else
            echo "FAIL: $ORCH differs from what it was before this run (the originals stay in $ORIG_FILE; the next run puts them back)" >&2
            rc=1
        fi
    fi
    exit "$rc"
}
trap restore EXIT
trap 'exit 130' INT TERM HUP

RESULTS="${G1_E2E_RESULTS_DIR:-$E2E/test-results-g1e2e}/$(date -u +%Y%m%dT%H%M%SZ)-$$"
mkdir -p "$RESULTS"
echo "results of this run: $RESULTS"

# Descriptors 3 and up are closed for Playwright: one holding the heavy lock (ours, or the caller's)
# would keep it held by any browser or helper outliving this script.
close_inherited_fds() {
    local entry fd
    for entry in "/proc/$BASHPID/fd/"*; do
        fd="${entry##*/}"
        [[ "$fd" =~ ^[0-9]+$ && "$fd" -gt 2 ]] && eval "exec $fd>&-"
    done
    return 0
}

# Playwright gets SIGTERM when this shell dies, where setpriv offers it (pdeathsig survives the
# execs below; setsid does not fork here, this subshell leading no process group).
PDEATH=()
if command -v setpriv >/dev/null && [[ "$(setpriv --help 2>/dev/null || true)" == *--pdeathsig* ]]; then
    PDEATH=(setpriv --pdeathsig TERM)
fi

# Playwright runs in its own process group in the background, so a signal reaches the trap at once
# and the trap can stop the whole group (browsers and stub servers included). A shell started in the
# background starts its children with SIGINT ignored; env --default-signal gives Playwright it back,
# so the trap's INT lets it run the spec's afterAll hooks.
run_group() {
    local rc=0
    ( close_inherited_fds && cd "$E2E" && export G1_E2E_REQUIRE_LIVE=1 \
        && exec "${PDEATH[@]}" setsid env --default-signal=INT,QUIT npx playwright test perUserSandbox --grep "${TITLE[$1]} \\(" \
            --output "$RESULTS/group-$1" "${EXTRA[@]}" ) &
    PW_PID=$!
    echo "$PW_PID $(proc_start "$PW_PID")" > "$PW_FILE"
    wait "$PW_PID" || rc=$?
    PW_PID=""
    rm -f "$PW_FILE"
    return "$rc"
}

FAILED=()
for g in "${GROUP_LIST[@]}"; do
    mapfile -t wanted < <(group_env "$g")
    if ! running_matches "${wanted[@]}"; then
        [[ $CHANGED -eq 1 ]] || persist_originals
        CHANGED=1
        set_target "${wanted[@]}"
        if ! recreate || ! compare_running; then
            echo "FAIL: $ORCH did not come up with ${TITLE[$g]}'s variables and its original inputs" >&2
            exit 1
        fi
    fi
    echo "== ${TITLE[$g]} =="
    if run_group "$g"; then
        echo "== ${TITLE[$g]}: PASS =="
    else
        echo "== ${TITLE[$g]}: FAIL =="
        FAILED+=("$g")
    fi
done

if [[ ${#FAILED[@]} -gt 0 ]]; then
    echo "per-user sandbox e2e: FAILED groups ${FAILED[*]}"
    exit 1
fi
echo "per-user sandbox e2e: every group passed"
