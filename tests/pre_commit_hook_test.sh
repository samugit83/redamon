#!/usr/bin/env bash
# =============================================================================
# tooling/hooks/pre-commit blocks a commit that leaves a generated artifact
# stale, and lets every other commit through (drift-map section 6 guard #15).
#
# Builds a throwaway repository from HEAD's copy of the three generators and
# what they read and write, drops in the working tree's hook, and runs it:
#   - a commit staging a generator's area on a clean tree passes;
#   - a stale output of each generator fails it and names the fixing command;
#   - a commit that stages nothing a generator owns passes on a stale tree;
#   - without python3, or without PyYAML, it says so and lets the commit through.
# The real checkout is never touched.
#
# Run: bash tests/pre_commit_hook_test.sh
# =============================================================================
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOOK="$REPO_ROOT/tooling/hooks/pre-commit"

PASS=0; FAIL=0
pass() { PASS=$((PASS+1)); printf '  \033[0;32mPASS\033[0m %s\n' "$1"; }
fail() { FAIL=$((FAIL+1)); printf '  \033[0;31mFAIL\033[0m %s\n' "$1"; }

# 77: the gate's "cannot run" code (redamon.sh _TEST_SHELL_CANNOT_RUN), which
# fails it unless REDAMON_TEST_ALLOW_MISSING names this suite.
if ! command -v git >/dev/null 2>&1 || ! git -C "$REPO_ROOT" rev-parse --verify -q HEAD >/dev/null; then
  echo "  CANNOT RUN  needs git and a HEAD commit to copy the generators from"; exit 77
fi
if ! command -v python3 >/dev/null 2>&1 || ! python3 -c 'import yaml' >/dev/null 2>&1; then
  echo "  CANNOT RUN  needs python3 with PyYAML to run the generator checks"; exit 77
fi

FX="$(mktemp -d)"
trap 'rm -rf "$FX"' EXIT
git -C "$REPO_ROOT" archive HEAD -- \
    recon_settings graph_db tooling/scripts skills/skill-sync/assets \
    webapp/prisma/schema.prisma webapp/src/lib/reconSettings webapp/src/lib/nodeFilters \
    webapp/src/components/projects/ProjectForm/ProjectForm.tsx \
    webapp/src/components/projects/ProjectForm/nodeMapping.ts recon/helpers/finding_sources.py \
  | tar -x -C "$FX"
mkdir -p "$FX/tooling/hooks"
cp "$HOOK" "$FX/tooling/hooks/pre-commit"
git -C "$FX" init -q
git -C "$FX" -c user.name=t -c user.email=t@t add -A
git -C "$FX" -c user.name=t -c user.email=t@t commit -qm base

# hook [env...]: run the copied hook the way git does (cwd = repo root); sets OUT, RC.
hook() { OUT="$(cd "$FX" && env "$@" bash tooling/hooks/pre-commit 2>&1)"; RC=$?; }
reset_fx() { git -C "$FX" reset -q --hard; git -C "$FX" clean -qfd; }

echo "== the scratch copy is clean before the hook is judged =="
pre=0
for s in recon_settings/build.py graph_db/node_filters/build.py tooling/scripts/seed_schema_catalog.py; do
  (cd "$FX" && python3 "$s" --check >/dev/null 2>&1) || { pre=1; fail "HEAD's own $s --check fails; fix HEAD first"; }
done
[[ $pre -eq 0 ]] && pass "all three --check pass on HEAD's copy"

echo "== a clean commit in a generator's area passes =="
printf 'note\n' > "$FX/graph_db/NOTE.txt"; git -C "$FX" add graph_db/NOTE.txt
hook
[[ $RC -eq 0 && "$OUT" != *STALE* ]] && pass "exit 0, nothing stale" || fail "exit $RC: $OUT"
reset_fx

echo "== a stale artifact of each generator blocks the commit =="
for case in "graph_db/schema_catalog.py|tooling/scripts/seed_schema_catalog.py" \
            "webapp/src/lib/nodeFilters/catalog.json|graph_db/node_filters/build.py" \
            "webapp/src/lib/reconSettings/registryDigest.generated.ts|recon_settings/build.py"; do
  out_file="${case%|*}"; script="${case#*|}"
  printf '\n// hand edit\n' >> "$FX/$out_file"; git -C "$FX" add "$out_file"
  hook
  if [[ $RC -ne 0 && "$OUT" == *"STALE: python3 $script --check failed"* && "$OUT" == *"fix: python3 $script "* ]]; then
    pass "stale $out_file blocks and names: python3 $script"
  else
    fail "stale $out_file: exit $RC: $OUT"
  fi
  reset_fx
done

echo "== an unrelated commit is not blocked by a stale tree =="
printf '\n// hand edit\n' >> "$FX/graph_db/schema_catalog.py"     # left unstaged
printf 'x\n' > "$FX/README.txt"; git -C "$FX" add README.txt
hook
[[ $RC -eq 0 && "$OUT" != *STALE* ]] && pass "exit 0 when nothing staged is a generator's" || fail "exit $RC: $OUT"
reset_fx

echo "== no python3 or no PyYAML: say so, let the commit through =="
printf '\n// hand edit\n' >> "$FX/graph_db/schema_catalog.py"; git -C "$FX" add graph_db/schema_catalog.py
BIN="$FX/.nopython"; mkdir -p "$BIN"
for t in bash git sed grep cat basename dirname env; do
  p="$(command -v "$t")" && ln -sf "$p" "$BIN/$t"
done
hook PATH="$BIN"
[[ $RC -eq 0 && "$OUT" == *"python3 not found"* ]] && pass "no python3: exit 0 with a notice" || fail "exit $RC: $OUT"
NOYAML="$FX/.noyaml"; mkdir -p "$NOYAML"
printf 'raise ImportError("PyYAML hidden by the test")\n' > "$NOYAML/yaml.py"
hook PYTHONPATH="$NOYAML"
[[ "$OUT" == *"PyYAML not installed"*"recon_settings/build.py --check skipped"* \
   && "$OUT" == *"graph_db/node_filters/build.py --check skipped"* ]] \
    && pass "no PyYAML: both YAML generators skipped with a notice" || fail "no PyYAML notice: $OUT"
[[ $RC -ne 0 && "$OUT" == *"STALE: python3 tooling/scripts/seed_schema_catalog.py"* ]] \
    && pass "no PyYAML: the schema catalog check (no YAML) still blocks" || fail "exit $RC: $OUT"

echo
echo "-----------------------------------------"
printf 'pre-commit hook suite: \033[0;32m%d passed\033[0m, ' "$PASS"
if [[ $FAIL -gt 0 ]]; then printf '\033[0;31m%d failed\033[0m\n' "$FAIL"; exit 1; else printf '%d failed\n' "$FAIL"; fi
