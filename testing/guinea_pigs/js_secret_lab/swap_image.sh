#!/usr/bin/env bash
# Swap redamon-trufflehog:latest for the lifecycle scenarios, and always put it back.
#
#   swap_image.sh park    -- <command...>   E8: latest is retagged :parked and removed (image missing)
#   swap_image.sh slow    -- <command...>   E7: latest = slow_trufflehog/ (sleeps SLOW_S, default 300, then scans)
#   swap_image.sh restore                   :parked back to latest (also what the trap runs)
#
# A swap lasts exactly as long as its command: the EXIT/INT/TERM trap restores
# the image whatever the command does, and the swap itself runs after the trap
# is armed, so a failed build restores too. While swapped, the ledger's
# `Flags:` line carries IMAGE_PARKED (plan §0.1: a resumed session restores
# first). --hold leaves a swap in place with no command (manual use only;
# run `swap_image.sh restore` after).
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
LEDGER="${JSLAB_LEDGER:-$REPO/_local/internal/temp_fix/js_recon_truffle_progress.md}"
IMG=redamon-trufflehog
LATEST=$IMG:latest
PARKED=$IMG:parked
WRAPPER_LABEL=org.redamon.jslab.slow-wrapper
SLOW_S="${SLOW_S:-300}"

log() { echo "[*][swap_image] $*" >&2; }
die() { echo "[!][swap_image] $*" >&2; exit 1; }

image_id() { docker image inspect -f '{{.Id}}' "$1" 2>/dev/null || true; }
is_wrapper() { [ "$(docker image inspect -f "{{index .Config.Labels \"$WRAPPER_LABEL\"}}" "$1" 2>/dev/null || true)" = 1 ]; }

flag() {  # flag set|clear: edit IMAGE_PARKED on the ledger's Flags: line, atomically
  [ -f "$LEDGER" ] || { log "no ledger at $LEDGER: flag not ${1}"; return 0; }
  python3 -I - "$LEDGER" "$1" <<'PY'
import os, re, sys
path, action = sys.argv[1], sys.argv[2]
lines = open(path, encoding="utf-8").read().split("\n")
for i, line in enumerate(lines):
    m = re.match(r"^Flags:\s*(.*)$", line)
    if not m:
        continue
    flags = [f.strip() for f in m.group(1).split(",") if f.strip() and f.strip() != "(none set)"]
    flags = [f for f in flags if f != "IMAGE_PARKED"] + (["IMAGE_PARKED"] if action == "set" else [])
    lines[i] = "Flags: " + (", ".join(flags) if flags else "(none set)")
    break
else:
    lines[1:1] = ["", "Flags: IMAGE_PARKED"] if action == "set" else []
tmp = path + ".swap.tmp"
open(tmp, "w", encoding="utf-8").write("\n".join(lines))
os.replace(tmp, path)
PY
  log "ledger: IMAGE_PARKED ${1}"
}

park_real() {  # make sure :parked holds the REAL image
  if [ -n "$(image_id "$PARKED")" ]; then
    return 0
  fi
  [ -n "$(image_id "$LATEST")" ] || die "$LATEST is missing and nothing is parked: rebuild it (./redamon.sh update)"
  is_wrapper "$LATEST" && die "$LATEST is the slow wrapper and nothing is parked: refusing to park it"
  docker tag "$LATEST" "$PARKED"
  log "tagged $LATEST as $PARKED"
}

restore() {
  local parked latest
  parked=$(image_id "$PARKED")
  latest=$(image_id "$LATEST")
  if [ -z "$parked" ]; then
    if [ -n "$latest" ] && ! is_wrapper "$LATEST"; then
      log "nothing parked; $LATEST is the real image"
      flag clear
      return 0
    fi
    die "no $PARKED and no real $LATEST: rebuild it (./redamon.sh update); IMAGE_PARKED left set"
  fi
  if [ -n "$latest" ] && [ "$latest" != "$parked" ]; then
    docker rmi "$LATEST" >/dev/null   # the slow wrapper: only tag on its image
    log "removed the swapped-in $LATEST"
  fi
  docker tag "$PARKED" "$LATEST"
  # Untag :parked so a later ./redamon.sh update cannot leave a stale one behind.
  [ "$(image_id "$LATEST")" = "$parked" ] && docker rmi "$PARKED" >/dev/null
  log "restored $LATEST"
  flag clear
}

park() {
  park_real
  flag set
  if [ -n "$(image_id "$LATEST")" ]; then
    docker rmi "$LATEST" >/dev/null   # untags only: :parked keeps the image
  fi
  log "$LATEST is now missing (parked as $PARKED)"
}

slow() {
  park_real
  flag set
  docker build -q --build-arg "SLOW_S=$SLOW_S" -t "$LATEST" "$HERE/slow_trufflehog" >/dev/null
  log "$LATEST is now the slow wrapper (SLOW_S=$SLOW_S)"
}

mode="${1:-}"
[ $# -gt 0 ] && shift
hold=0
if [ "${1:-}" = "--hold" ]; then hold=1; shift; fi
if [ "${1:-}" = "--" ]; then shift; fi

case "$mode" in
  restore)
    restore
    exit 0
    ;;
  park|slow)
    if [ $# -eq 0 ] && [ $hold -eq 0 ]; then
      die "give the scenario to run: swap_image.sh $mode -- <command...> (or --hold for manual use)"
    fi
    if [ $hold -eq 0 ]; then
      trap 'rc=$?; trap - EXIT INT TERM; restore || rc=1; exit $rc' EXIT INT TERM
    fi
    "$mode"
    if [ $hold -eq 1 ]; then
      log "held: run '$0 restore' when done"
      exit 0
    fi
    set +e
    "$@"
    rc=$?
    set -e
    exit $rc
    ;;
  *)
    sed -n '2,14p' "$0" >&2
    exit 2
    ;;
esac
