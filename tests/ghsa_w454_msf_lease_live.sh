#!/usr/bin/env bash
#
# Live check of GHSA-w454-6hwp-fm58 against a REAL msfconsole: one project cannot list,
# drive, kill or re-link another project's Metasploit session through the sandbox's
# shared console, and the console passes to the next project only empty and restarted.
#
# tests/ghsa_w454_msf_lease_live.py is fed on stdin to the running kali-sandbox, where
# it starts a second Metasploit server from the mounted mcp/servers on loopback ports
# 18003/18013 with its own msfconsole and a 20 s idle window, plays two projects
# against it with a loopback reverse shell as the only "target", and kills it. The
# stack's own console, sessions and ports are never touched, so it needs no restart:
# it tests the mounted source, which is what a restart would load.
#
# Needs the kali-sandbox container running; prints SKIP and exits 0 when it is not.
# As a *_live.sh it is never in the gate. Takes 3-6 minutes (two msfconsole starts).
#
# Run:  bash tests/ghsa_w454_msf_lease_live.sh
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if ! (cd "$ROOT" && docker compose ps --status running -q kali-sandbox 2>/dev/null | grep -q .); then
  echo "SKIP: no running kali-sandbox container (docker compose ps kali-sandbox)"
  exit 0
fi

(cd "$ROOT" && docker compose exec -T kali-sandbox python3 -) < "$ROOT/tests/ghsa_w454_msf_lease_live.py"
