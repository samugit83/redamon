#!/usr/bin/env bash
# =============================================================================
# The dev webapp runs the same startup scripts as the production image.
#
# webapp/Dockerfile writes the production entrypoint inline (one printf); the
# dev override in docker-compose.dev.yml replaces it with its own command, so a
# script added to one and not the other silently never runs in that mode
# (drift-map #18: dev ran 2 of the 7). This extracts the ordered step list from
# both, `db push` included, since migrate-trufflehog-profiles must precede it,
# and marks each step fatal (`|| exit 1`) or not, then compares.
#
# Run: bash tests/webapp_dev_startup_parity_test.sh
# =============================================================================
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DOCKERFILE="$REPO_ROOT/webapp/Dockerfile"
DEV_COMPOSE="$REPO_ROOT/docker-compose.dev.yml"

PASS=0; FAIL=0
pass() { PASS=$((PASS+1)); printf '  \033[0;32mPASS\033[0m %s\n' "$1"; }
fail() { FAIL=$((FAIL+1)); printf '  \033[0;31mFAIL\033[0m %s\n' "$1"; }

# Shell text on stdin -> one step per line: a script basename or "db-push",
# suffixed with "!" when the step stops the startup on failure (`|| exit 1`, or
# chained with `&&` to what follows). Splitting on `;` and `&&` as well as
# newlines keeps a one-line `sh -c "a && b; c"` from hiding steps.
steps_of() {
    sed 's/&&/ <and>\n/g' | tr ';' '\n' | while IFS= read -r seg; do
        local name=""
        if [[ "$seg" =~ scripts/([A-Za-z0-9_-]+)\.mjs ]]; then
            name="${BASH_REMATCH[1]}"
        elif [[ "$seg" == *"db push"* ]]; then
            name="db-push"
        fi
        [[ -z "$name" ]] && continue
        [[ "$seg" == *"|| exit 1"* || "$seg" == *"<and>"* ]] && name="$name!"
        printf '%s\n' "$name"
    done
}

# The printf that writes /app/entrypoint.sh, with its literal \n made real.
dockerfile_steps() {
    grep -m1 '> /app/entrypoint.sh' "$1" | sed 's/\\n/\n/g' | steps_of
}

# The webapp service's `command:` block: from that key to the next key at the
# same indent.
dev_steps() {
    awk '
        /^  webapp:/            { in_svc = 1; next }
        in_svc && /^  [^ ]/     { in_svc = 0 }
        in_svc && /^    command:/ { in_cmd = 1; sub(/^    command:/, ""); print; next }
        in_cmd && /^    [^ -]/  { in_cmd = 0 }
        in_cmd                  { print }
    ' "$1" | steps_of
}

echo "== parsers =="
PROD="$(dockerfile_steps "$DOCKERFILE")"
DEV="$(dev_steps "$DEV_COMPOSE")"
prod_n=$(printf '%s\n' "$PROD" | grep -c .)
# A broken parser must fail here, not compare two empty lists as equal.
[[ $prod_n -ge 5 ]] && pass "Dockerfile entrypoint: $prod_n steps" \
    || fail "Dockerfile entrypoint parsed to $prod_n steps (expected the printf at '> /app/entrypoint.sh')"
# The push runs through scripts/db-push-locked.mjs (an advisory lock, so copies booting
# together push one at a time), which the parser names db-push-locked.
printf '%s\n' "$PROD" | grep -qx 'db-push-locked!' && pass "Dockerfile entrypoint has a fatal db push (db-push-locked)" \
    || fail "no fatal db push in the Dockerfile entrypoint (expected db-push-locked!)"

# The comparison itself must catch an omission and a reorder.
FIXTURE_DOCKERFILE="RUN printf '#!/bin/sh\nnode scripts/a.mjs 2>&1 || exit 1\nnpx prisma db push 2>&1 || exit 1\nnode scripts/b.mjs\nexec node server.js\n' > /app/entrypoint.sh"
FIXTURE_DEV='  webapp:
    command: sh -c "npx prisma db push --accept-data-loss && (node scripts/b.mjs) && npm run dev"
    volumes:
      - ./x:/x'
fp="$(dockerfile_steps <(printf '%s\n' "$FIXTURE_DOCKERFILE"))"
fd="$(dev_steps <(printf '%s\n' "$FIXTURE_DEV"))"
[[ "$fp" == $'a!\ndb-push!\nb' ]] && pass "fixture Dockerfile parses to a!, db-push!, b" \
    || fail "fixture Dockerfile parsed to: $(echo $fp)"
[[ "$fp" != "$fd" ]] && pass "a dev command missing a script is caught" \
    || fail "the comparison did not catch a missing script"

echo "== dev compose vs Dockerfile =="
if [[ "$DEV" == "$PROD" ]]; then
    pass "docker-compose.dev.yml runs the Dockerfile's steps, same order, same fatal split"
else
    fail "docker-compose.dev.yml webapp command differs from webapp/Dockerfile's entrypoint"
    diff <(printf '%s\n' "$PROD") <(printf '%s\n' "$DEV") | sed 's/^/      /'
    echo "      (< Dockerfile, > dev compose; ! = fatal)"
fi

echo
echo "-----------------------------------------"
printf 'webapp dev startup parity: \033[0;32m%d passed\033[0m, ' "$PASS"
if [[ $FAIL -gt 0 ]]; then printf '\033[0;31m%d failed\033[0m\n' "$FAIL"; exit 1; else printf '%d failed\n' "$FAIL"; fi
