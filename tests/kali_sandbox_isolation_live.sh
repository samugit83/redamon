#!/usr/bin/env bash
#
# Live isolation harness for per-user Kali sandboxes (group 1: T5, T7, I9, I10, D16,
# D22, E3, D24, S5, S7, I11, E4), run against the LIVE stack. One check per threat
# (LV-T5a, LV-T5b, LV-I9, LV-I10, LV-I11, LV-S5, LV-T7, LV-E3, LV-D24, LV-D22, LV-D16,
# LV-S7, LV-E4): two seeded persons run commands through MCP `kali_exec`, the real
# entry point, and each check asserts that nothing one plants is visible to, reachable
# from or writable by the other. Ground truth comes from `docker inspect` / `docker exec`.
# It FAILS on today's shared `redamon-kali` and passes with per-user sandboxes; the
# checks and their controls are described in tests/kali_sandbox_isolation_live.py.
#
# Seed first (idempotent; synthetic g1-* accounts and projects, targets under .invalid):
#   python3 tests/kali_sandbox_seed_live.py
# Then:
#   bash tests/kali_sandbox_isolation_live.sh                 one PASS|FAIL line per check; exit 1 on any FAIL
#   bash tests/kali_sandbox_isolation_live.sh --expect-fail   exit 0 only when every check FAILs with its own
#                                                             breach (M-a's "fails before" evidence, shared mode)
#   G1_ALLOW_FORK_TEST=1 bash tests/kali_sandbox_isolation_live.sh   also LV-D22, a fork load in A's sandbox
#                                                             (shared mode: wedges, then restarts, redamon-kali)
#   bash tests/kali_sandbox_isolation_live.sh --connect-lab <container> --as alice|bob
#   bash tests/kali_sandbox_isolation_live.sh --disconnect-lab <container> --as alice|bob
#                                                             put an operator's lab on that person's sandbox
#                                                             network for a milestone (OQ-G1-3), and take it off
#
# The seed's state (ids, generated passwords, MCP tokens) is $G1_STATE, default
# ${TMPDIR:-/tmp}/g1-live-state.json, mode 0600: seed and harness must see the same one.
# No token or password is ever printed. For LV-E3 the harness turns the capture proxy's
# block_private on and off through the .env admin's Global Settings and puts the original
# value back right after; a run killed meanwhile leaves it recorded in the state file, and
# the next run (or the seed) puts it back, as it undoes the rest a killed run left.
#
# Prints SKIP and exits 0 when the webapp, Docker or python3 is missing; with --expect-fail
# or G1_REQUIRE_LIVE=1 (what the milestones set) a skip exits 2, since it is no evidence.
# Once the webapp answers, a missing seed state and a check that cannot run are FAILs. As a
# *_live.sh it is never in the gate. Takes 3-6 minutes (the proxy toggle and a Metasploit
# console start).
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if ! command -v python3 >/dev/null 2>&1; then
  required="${G1_REQUIRE_LIVE:-}"
  for arg in "$@"; do
    case "$arg" in --expect-fail | --connect-lab | --disconnect-lab) required=1 ;; esac
  done
  echo "SKIP: python3 is not installed"
  if [ "$required" = 1 ]; then
    echo "FAIL: this run cannot skip (--expect-fail, a lab change, or G1_REQUIRE_LIVE=1)"
    exit 2
  fi
  exit 0
fi
exec python3 -I "$ROOT/tests/kali_sandbox_isolation_live.py" "$@"
