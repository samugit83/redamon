#!/usr/bin/env bash
# RedAmon BadDNS batch runner.
# =========================================================================
# Usage:
#   docker run --rm -v /host/work:/work redamon-baddns:latest \
#       /work/targets.txt [modules] [nameservers]
#
# Arguments (positional):
#   $1  targets_file   Path to newline-separated hostnames (required)
#   $2  modules        Comma-separated module list (optional)
#                      Default: cname,ns,mx,txt,spf
#   $3  nameservers    Comma-separated resolvers (optional, empty = system)
#
# Env vars:
#   BADDNS_PER_TARGET_TIMEOUT  Seconds per target (default 90). Bounds any
#                              single baddns invocation so one hanging
#                              target cannot stall the whole batch.
#
# Output:
#   NDJSON on stdout: one JSON finding per line (baddns -s emits
#   Finding.to_json() via print()). Non-vulnerable targets emit nothing.
#
# Exit behaviour:
#   - `set -e` is NOT used: per-target failures must not abort the batch.
#   - SIGTERM / SIGINT from the parent (recon container) is forwarded to
#     the currently-running baddns child so we exit cleanly instead of
#     leaving a zombie.
# =========================================================================

set -u

targets_file="${1:-}"
modules="${2:-cname,ns,mx,txt,spf}"
nameservers="${3:-}"
per_target_timeout="${BADDNS_PER_TARGET_TIMEOUT:-90}"

if [ -z "$targets_file" ] || [ ! -r "$targets_file" ]; then
    echo "usage: baddns-batch <targets_file> [modules] [nameservers]" >&2
    exit 2
fi

# Signal forwarding: propagate SIGTERM/SIGINT to the current child baddns
# process so `docker kill` on the parent exits promptly without zombies.
child_pid=""
forward_signal() {
    if [ -n "$child_pid" ]; then
        kill -TERM "$child_pid" 2>/dev/null || true
    fi
    exit 130
}
trap 'forward_signal' INT TERM

resolver_args=()
if [ -n "$nameservers" ]; then
    resolver_args=(-n "$nameservers")
fi

targets_seen=0
targets_skipped=0
findings_emitted=0
target=""   # explicit init for `set -u`

while IFS= read -r target || [ -n "$target" ]; do
    # Trim whitespace + skip blank lines and comments
    target="${target#"${target%%[![:space:]]*}"}"
    target="${target%"${target##*[![:space:]]}"}"
    if [ -z "$target" ] || [[ "$target" == \#* ]]; then
        continue
    fi

    # Basic sanity filter: hostnames must contain a dot and no whitespace.
    # baddns itself validates more strictly; this reduces wasted spawns.
    if [[ "$target" != *.* ]] || [[ "$target" == *" "* ]]; then
        targets_skipped=$((targets_skipped + 1))
        continue
    fi

    targets_seen=$((targets_seen + 1))

    # Run baddns under a hard per-target timeout. `timeout --foreground`
    # keeps stdin/TTY semantics sane so signal forwarding still works.
    # Output buffered to a per-process temp file to keep counts accurate
    # and avoid interleaving partial lines from concurrent writes.
    tmp_out="/tmp/baddns-out.$$.${targets_seen}"
    timeout --foreground --kill-after=10s "${per_target_timeout}s" \
        baddns -s -m "$modules" "${resolver_args[@]}" -- "$target" \
        > "$tmp_out" 2>/dev/null &
    child_pid=$!
    set +e
    wait "$child_pid"
    rc=$?
    set -u

    # Relay + count findings for this target
    if [ -s "$tmp_out" ]; then
        emitted_here=$(grep -c '^{' "$tmp_out" 2>/dev/null || echo 0)
        findings_emitted=$((findings_emitted + emitted_here))
        cat "$tmp_out"
    fi
    rm -f "$tmp_out"
    child_pid=""

    # rc == 124: per-target timeout fired. Logged on stderr, batch continues.
    if [ "$rc" = "124" ]; then
        echo "[baddns-batch] timeout after ${per_target_timeout}s on ${target}" >&2
    fi
done < "$targets_file"

# Summary on stderr for orchestrator logs
echo "[baddns-batch] summary: scanned=${targets_seen} skipped=${targets_skipped} findings=${findings_emitted}" >&2
