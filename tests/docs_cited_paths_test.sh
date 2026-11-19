#!/usr/bin/env bash
# =============================================================================
# Every repo path the prose docs cite exists at the path shown (drift-map
# section 6 guard #10).
#
# Runs skills/skill-sync/assets/drift-audit.sh --docs over docs/readmes/**,
# README.md, CONTRIBUTING.md, the SKILL.md and AGENTS.md files and the wiki
# checkout, and compares its dead citations with the allowlist in
#   tests/fixtures/docs_paths_drift_{wiki,readmes,root}.json
# (split by where the citing doc lives, so each docs lane edits its own file).
# It fails on a dead citation in none of them, and on an entry that no longer
# fails, so fixing a doc means deleting its entry in the same commit.
#
# Wiki page links, anchors, images and counts belong to tests/test_docs_not_stale.py.
#
# An empty wiki checkout fails unless REDAMON_TEST_ALLOW_MISSING names `wiki`
# or `all`; then the wiki pages and their entries are left out.
#
# Run: bash tests/docs_cited_paths_test.sh
# =============================================================================
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AUDIT="$REPO_ROOT/skills/skill-sync/assets/drift-audit.sh"
FIXTURES="$REPO_ROOT/tests/fixtures"

PASS=0; FAIL=0
pass() { PASS=$((PASS+1)); printf '  \033[0;32mPASS\033[0m %s\n' "$1"; }
fail() { FAIL=$((FAIL+1)); printf '  \033[0;31mFAIL\033[0m %s\n' "$1"; }
finish() {
  echo
  echo "-----------------------------------------"
  printf 'docs cited paths: \033[0;32m%d passed\033[0m, ' "$PASS"
  if [[ $FAIL -gt 0 ]]; then printf '\033[0;31m%d failed\033[0m\n' "$FAIL"; exit 1; fi
  printf '%d failed\n' "$FAIL"; exit 0
}

if ! command -v git >/dev/null 2>&1 || ! git -C "$REPO_ROOT" rev-parse --git-dir >/dev/null 2>&1; then
  # 77: the gate's "cannot run" code (redamon.sh _TEST_SHELL_CANNOT_RUN).
  echo "  CANNOT RUN  needs git and this repository's .git (the audit lists files with git ls-files)"
  exit 77
fi
if ! command -v python3 >/dev/null 2>&1; then
  fail "python3 is unavailable, so the allowlist cannot be read"
  finish
fi

allow_missing_wiki() {
  local IFS=, n
  for n in ${REDAMON_TEST_ALLOW_MISSING:-}; do
    n="${n// /}"
    [[ "$n" == "wiki" || "$n" == "all" ]] && return 0
  done
  return 1
}

echo "== the wiki checkout is present =="
WIKI=1
if [[ -f "$REPO_ROOT/redamon.wiki/Home.md" ]]; then
  pass "redamon.wiki/Home.md exists"
elif allow_missing_wiki; then
  WIKI=0
  echo "  SKIPPED wiki pages: no wiki checkout, allowed by REDAMON_TEST_ALLOW_MISSING"
else
  fail "no wiki checkout at redamon.wiki/: run \`git submodule update --init redamon.wiki\`, or set REDAMON_TEST_ALLOW_MISSING=wiki"
  finish
fi

echo "== drift-audit --docs ran over the docs =="
OUT="$(bash "$AUDIT" --docs 2>&1)"; RC=$?
if [[ $RC -gt 1 ]]; then
  fail "drift-audit.sh --docs exited $RC: $OUT"
  finish
fi
summary="$(printf '%s\n' "$OUT" | grep -m1 '^drift-audit --docs:')"
nfiles="$(printf '%s\n' "$summary" | sed -n 's/^drift-audit --docs: \([0-9]*\) file.*/\1/p')"
nchecked="$(printf '%s\n' "$summary" | sed -n 's/.*, \([0-9]*\) citation.*/\1/p')"
# Floors well below today's counts (139 files, 1727 citations with the wiki): a
# broken file list or extractor must fail here, not pass by finding nothing.
min_files=$(( WIKI ? 100 : 60 )); min_checked=$(( WIKI ? 1200 : 700 ))
if [[ -n "$nfiles" && -n "$nchecked" && $nfiles -ge $min_files && $nchecked -ge $min_checked ]]; then
  pass "audited $nfiles files, $nchecked citations"
else
  fail "the audit saw too little (want >= $min_files files, >= $min_checked citations): ${summary:-no summary line}"
fi

echo "== every dead citation is allowlisted, every entry still fails =="
REPORT="$(printf '%s\n' "$OUT" | WIKI="$WIKI" FIXTURES="$FIXTURES" python3 -c '
import json, os, re, sys

fixtures = os.environ["FIXTURES"]
with_wiki = os.environ["WIKI"] == "1"

def group(path):
    if path.startswith("redamon.wiki/"):
        return "wiki"
    if path.startswith("docs/readmes/"):
        return "readmes"
    return "root"

ITEM = re.compile(r"^(drift-map #\d+|drift-map \d+\.\d+: .+|drift-map: found in wave 2|not a path: .+)$")
problems, allowed = [], {}
for g in ("wiki", "readmes", "root"):
    name = f"docs_paths_drift_{g}.json"
    try:
        with open(os.path.join(fixtures, name), encoding="utf-8") as fh:
            entries = json.load(fh)["entries"]
    except (OSError, ValueError, KeyError) as exc:
        problems.append(f"tests/fixtures/{name} unreadable: {exc}")
        continue
    for e in entries:
        f, p, item = e.get("file", ""), e.get("path", ""), e.get("item", "")
        if not (f and p and ITEM.match(item)):
            problems.append(f"{name}: malformed entry {e} (item must name a drift-map item or say \"not a path: why\")")
            continue
        if group(f) != g:
            problems.append(f"{name}: {f} belongs in docs_paths_drift_{group(f)}.json")
        if (f, p) in allowed:
            problems.append(f"{name}: duplicate entry {f} -> {p}")
        allowed[(f, p)] = name

found = set()
for line in sys.stdin:
    m = re.match(r"^  (\S.*?) -> (.*)$", line.rstrip("\n"))
    if m:
        found.add((m.group(1), m.group(2)))

for f, p in sorted(found - set(allowed)):
    problems.append(f"dead citation {f} -> {p}: fix the doc, or add it to tests/fixtures/docs_paths_drift_{group(f)}.json with its drift-map item")
for (f, p), name in sorted(allowed.items()):
    if (f, p) in found or (not with_wiki and group(f) == "wiki"):
        continue
    problems.append(f"{name}: {f} -> {p} no longer fails; delete the entry")

print(f"COUNTS {len(found)} {len(allowed)}")
for msg in problems:
    print(msg)
')"
counts="$(printf '%s\n' "$REPORT" | sed -n 's/^COUNTS //p')"
issues="$(printf '%s\n' "$REPORT" | grep -v '^COUNTS ' | grep -v '^$')"
if [[ -z "$counts" ]]; then
  fail "the allowlist comparison did not run: $REPORT"
elif [[ -z "$issues" ]]; then
  pass "dead citations and allowlist agree (dead/allowlisted: ${counts/ //})"
else
  while IFS= read -r msg; do fail "$msg"; done <<< "$issues"
fi

finish
