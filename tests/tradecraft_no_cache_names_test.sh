#!/usr/bin/env bash
# =============================================================================
# The Tradecraft 1.x page cache is gone from the code (§7 item 12, §10 "No cache is left", T9.4):
#   - TradecraftCache, tradecraft_cache and TRADECRAFT_DEFAULT_TTL_SEC appear in no code file;
#     the one exception is the volume name the once-only removal in redamon.sh deletes
#     (OLD_PAGE_CACHE_VOLUME), and this test itself;
#   - cacheTtlSec appears only in webapp/prisma/schema.prisma (the column stays, R-200, R-218)
#     and in the frozen upgrade fixtures;
#   - NOISE_PATH_PATTERNS is defined once at most (R-199: 1.x kept two copies).
# Run:  bash tests/tradecraft_no_cache_names_test.sh
# =============================================================================
set -uo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT" || exit 1

PASS=0; FAIL=0
pass() { PASS=$((PASS+1)); printf '  \033[0;32mPASS\033[0m %s\n' "$1"; }
fail() { FAIL=$((FAIL+1)); printf '  \033[0;31mFAIL\033[0m %s\n' "$1"; }

SELF="tests/tradecraft_no_cache_names_test.sh"
CODE_DIRS=(agentic mcp graph_db services webapp/src webapp/scripts)
CODE_FILES=(redamon.sh)
for f in docker-compose*.yml; do [[ -f "$f" ]] && CODE_FILES+=("$f"); done
# Dependencies, caches and build output are no code of this repository.
EXCLUDES=(--exclude-dir=node_modules --exclude-dir=.next --exclude-dir=__pycache__ --exclude-dir=.pytest_cache
          --exclude-dir=.redamon-venv --exclude-dir=logs --exclude-dir=agent-workspace)

hits() {  # <extended regex> -> "path:line:text" lines
    { grep -rnE "${EXCLUDES[@]}" "$1" "${CODE_DIRS[@]}" 2>/dev/null; grep -nHE "$1" "${CODE_FILES[@]}" 2>/dev/null; } |
        grep -v "^$SELF:" | sort
}

printf '\n\033[1m== no Tradecraft cache name in code ==\033[0m\n'
found="$(hits 'TradecraftCache|tradecraft_cache|TRADECRAFT_DEFAULT_TTL_SEC' |
    grep -vE '^redamon\.sh:[0-9]+:OLD_PAGE_CACHE_VOLUME="redamon_tradecraft_cache"$')"
if [[ -z "$found" ]]; then pass "no cache name"; else fail "cache names left:"; printf '%s\n' "$found"; fi
volume_lines="$(grep -cE '^OLD_PAGE_CACHE_VOLUME="redamon_tradecraft_cache"$' redamon.sh)"
if [[ "$volume_lines" == "1" ]]; then pass "redamon.sh names the old volume once, for its removal"; else fail "redamon.sh names the old volume $volume_lines times"; fi

printf '\n\033[1m== cacheTtlSec only in the schema and the frozen upgrade fixtures ==\033[0m\n'
found="$(hits 'cacheTtlSec' | grep -vE '^webapp/src/lib/authz/__fixtures__/')"
if [[ -z "$found" ]]; then pass "no cacheTtlSec in code"; else fail "cacheTtlSec read or written:"; printf '%s\n' "$found"; fi
if grep -qE '^\s+cacheTtlSec\s+Int' webapp/prisma/schema.prisma; then pass "the column stays in the schema (R-200, R-218)"; else fail "the cacheTtlSec column left the schema"; fi

printf '\n\033[1m== one exclude list (R-199) ==\033[0m\n'
defs="$(hits '^[[:space:]]*NOISE_PATH_PATTERNS[[:space:]]*=' | wc -l | tr -d ' ')"
if [[ "$defs" -le 1 ]]; then pass "NOISE_PATH_PATTERNS defined $defs time(s)"; else fail "NOISE_PATH_PATTERNS defined $defs times"; fi

# The search itself: a name planted in a scanned file is found.
planted="$(CODE_DIRS=() CODE_FILES=("$SELF") ; grep -nHE 'TradecraftCache' "$SELF" | head -1)"
if [[ -n "$planted" ]]; then pass "the search reads a file"; else fail "the search reads nothing"; fi

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
