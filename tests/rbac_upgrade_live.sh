#!/usr/bin/env bash
#
# RBAC upgrade harness: boots a webapp image's own startup list against synthetic
# 7.7.x-shaped databases and checks what the upgrade did to them.
#
# Each scenario is a full dump (schema and data) in tests/fixtures/rbac_upgrade/<name>.sql,
# made with the pinned redamon-webapp:rbac-7.7.2 image (git archive 442debbf:webapp), so
# it keeps the 7.7.x shape while redamon-webapp:latest moves on. The startup list is the
# image's /app/entrypoint.sh minus its last line (exec node server.js), which
# webapp/Dockerfile writes: the harness runs exactly what the image runs at boot.
#
# After every run it asserts:
#   - nothing changed but what the upgrade adds by design: the row count of every table
#     and every users column (definition and values) that existed before the run are
#     identical after it, audit_log counted without the rows of UPGRADE_AUDIT_ACTIONS; a
#     table or users column the run added is printed as a NOTE;
#   - the scenario's checks: tests/fixtures/rbac_upgrade/checks.sql, then checks_after.sql
#     (what the upgrade adds: legacy grants, Nuclei template owners, the instance settings
#     row, the Root the boot chose, their marker rows, the empty permission tables, the
#     legacy-grant conversion), through psql, diffed against expected/<scenario>.after.out,
#     or expected/<scenario>.after.permissions.out when RBAC_PERMISSIONS_ENABLED reads on
#     (it needs RBAC_IDENTITY_ENABLED on, as src/lib/authz/flags.ts reads them). The fixture
#     itself is checked with checks.sql against expected/<scenario>.out before the run.
#
# Modes (several may be chained; each runs every scenario):
#   all       the startup list once
#   twice     the startup list twice in a row (the second run must change nothing)
#   parallel  two containers start the startup list at once (several webapp copies)
#   failure   the list once; then the marker row of the backfill under test is deleted
#             (with the data it wrote, when its skip reads the data: the Root choice),
#             a psql session holds LOCK TABLE <its table> IN ACCESS EXCLUSIVE MODE, and
#             only that backfill's line of the list runs again with lock_timeout=2000
#             appended to its own DATABASE_URL: it must log a failure, exit 0 and leave
#             no marker; the lock is released and a third run of the list completes it.
#             The lock covers only the backfill, never the fatal `db push`.
#   serve <scenario>   the list, then the image's server on 127.0.0.1:3901 with fake
#             secrets, until Ctrl-C: the disposable instance for destructive identity
#             checks (Root transfer, set-root, upgrade, downgrade). Webapp only: no
#             agent, recon or graph. Never part of a chain.
#   regen     rebuild every fixture from seed/<name>.sql with the pinned 7.7.2 image
#             and rewrite expected/<name>.out (review the diff before committing).
#
# Everything runs in containers named rbac-upg-<pid>-* on a private network of their
# own (internal, except for serve), fed on stdin (snap Docker cannot read /tmp), and is
# removed on exit, Ctrl-C included. The running stack is never touched. Fixture users
# share one synthetic password (README.md).
#
# Environment:
#   RBAC_UPGRADE_IMAGE      image under test (default redamon-webapp:latest)
#   RBAC_UPGRADE_OLD_IMAGE  pinned 7.7.2 image (default redamon-webapp:rbac-7.7.2)
#   RBAC_UPGRADE_SCENARIOS  scenario name regex (default: all)
#   RBAC_UPGRADE_FAIL_BACKFILL  the backfill the failure mode breaks: user-skill-toggles
#                           (default), rbac-legacy-grants, rbac-instance-settings, rbac-root or
#                           rbac-legacy-overrides (runs only with the permissions switch on)
#   RBAC_UPGRADE_FAIL_SCRIPT / _FAIL_MARKER / _FAIL_TABLE / _FAIL_LOG
#                           override that choice: its script, its AuditLog marker action,
#                           the table it reads inside the marker's transaction, and the
#                           regex of its failure log line
#   REDAMON_SHARED_TOOLS_COMPAT, RBAC_*_ENABLED   passed to every run and to serve when set
#
# Needs Docker and the images; prints SKIP and exits 0 without them. Live suites
# (*_live.sh) are not part of the gate.
#
# Run:  bash tests/rbac_upgrade_live.sh all twice parallel failure
#       RBAC_UPGRADE_FAIL_BACKFILL=rbac-legacy-grants bash tests/rbac_upgrade_live.sh failure
#       RBAC_UPGRADE_FAIL_BACKFILL=rbac-instance-settings bash tests/rbac_upgrade_live.sh failure
#       RBAC_UPGRADE_FAIL_BACKFILL=rbac-root bash tests/rbac_upgrade_live.sh failure
#       RBAC_IDENTITY_ENABLED=true RBAC_PERMISSIONS_ENABLED=true bash tests/rbac_upgrade_live.sh all twice parallel failure
#       RBAC_IDENTITY_ENABLED=true RBAC_PERMISSIONS_ENABLED=true \
#         RBAC_UPGRADE_FAIL_BACKFILL=rbac-legacy-overrides bash tests/rbac_upgrade_live.sh failure
#       RBAC_UPGRADE_SCENARIOS='^one_admin$' bash tests/rbac_upgrade_live.sh twice
#       bash tests/rbac_upgrade_live.sh serve several_admins
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FIX="$ROOT/tests/fixtures/rbac_upgrade"
IMAGE="${RBAC_UPGRADE_IMAGE:-redamon-webapp:latest}"
OLD_IMAGE="${RBAC_UPGRADE_OLD_IMAGE:-redamon-webapp:rbac-7.7.2}"
PG_IMAGE=postgres:16-alpine
SCENARIO_FILTER="${RBAC_UPGRADE_SCENARIOS:-}"
SERVE_PORT=3901

# Each backfill reads its table right after it finds no marker, inside the transaction
# that writes the marker: user_attack_skills for the user-skill toggles, users for the
# legacy grants, instance_settings for the instance settings and the Root. The Root choice
# skips on its data, not on its marker, and writes one only when a scenario has an admin
# with a password: d_rows is how many marker rows the first run left, d_undo removes the
# Root it chose so the failed run and the third one choose again.
d_rows='SELECT 1'; d_undo=''
case "${RBAC_UPGRADE_FAIL_BACKFILL:-user-skill-toggles}" in
  user-skill-toggles)
    d_script=backfill-user-skill-toggles.mjs; d_marker=system.user_skill_toggles_backfill
    d_table=user_attack_skills; d_log='\[skills\] could not backfill user-skill toggles' ;;
  rbac-legacy-grants)
    d_script=backfill-rbac-legacy-grants.mjs; d_marker=system.rbac_legacy_grants_backfill
    d_table=users; d_log='\[rbac\] could not backfill legacy grants' ;;
  rbac-instance-settings)
    d_script=backfill-rbac-instance-settings.mjs; d_marker=system.rbac_instance_settings_backfill
    d_table=instance_settings; d_log='\[rbac\] could not fill the instance settings' ;;
  rbac-root)
    d_script=backfill-rbac-root.mjs; d_marker=system.rbac_root_assigned
    d_table=instance_settings; d_log='\[rbac\] could not recognise the Root'
    d_rows="SELECT least(count(*), 1) FROM users WHERE role = 'admin' AND password <> ''"
    d_undo="UPDATE instance_settings SET root_user_id = NULL, root_confirmed_at = NULL, root_assigned_by = NULL" ;;
  rbac-legacy-overrides)
    # Writes its marker only with the permissions switch on; the fixtures hold no Keep, so it
    # writes no override to undo.
    d_script=backfill-rbac-legacy-overrides.mjs; d_marker=system.rbac_legacy_overrides_backfill
    d_table=users; d_log='\[rbac\] could not convert the legacy grants' ;;
  *) echo "RBAC_UPGRADE_FAIL_BACKFILL: user-skill-toggles, rbac-legacy-grants, rbac-instance-settings, rbac-root or rbac-legacy-overrides" >&2; exit 2 ;;
esac
FAIL_SCRIPT="${RBAC_UPGRADE_FAIL_SCRIPT:-$d_script}"
FAIL_MARKER="${RBAC_UPGRADE_FAIL_MARKER:-$d_marker}"
FAIL_TABLE="${RBAC_UPGRADE_FAIL_TABLE:-$d_table}"
FAIL_LOG="${RBAC_UPGRADE_FAIL_LOG:-$d_log}"

# Audit rows the upgrade writes by design: left out of the row-count comparison and pinned
# instead, by count, in checks.sql's markers and by checks_after.sql.
UPGRADE_AUDIT_ACTIONS=(system.rbac_legacy_grants_cutoff system.rbac_legacy_grants_backfill
                       system.nuclei_template_owners_backfill system.rbac_instance_settings_backfill
                       system.rbac_root_assigned system.rbac_legacy_overrides_backfill)
UPGRADE_AUDIT_SQL="$(printf "'%s'," "${UPGRADE_AUDIT_ACTIONS[@]}")"
UPGRADE_AUDIT_SQL="${UPGRADE_AUDIT_SQL%,}"

# Obvious fakes: the containers live only for this run, on a private network.
PG_PASSWORD=rbac-upgrade-fake-pg
FIXTURE_PASSWORD=rbac-upgrade-pass-0001
FAKE_AUTH_SECRET=rbac-upgrade-fake-auth-secret-0001
FAKE_INTERNAL_API_KEY=rbac-upgrade-fake-internal-key-0001
FAKE_SCANNER_API_KEY=rbac-upgrade-fake-scanner-key-0001
SWITCHES=(REDAMON_SHARED_TOOLS_COMPAT RBAC_IDENTITY_ENABLED RBAC_PERMISSIONS_ENABLED
          RBAC_SHARING_ENABLED RBAC_SHARING_WRITE_ENABLED RBAC_GOVERNANCE_ENABLED)

PFX="rbac-upg-$$"
NET="$PFX-net"
PG="$PFX-pg"
LABEL="redamon.rbac-upgrade=$PFX"
DB_URL="postgresql://postgres:${PG_PASSWORD}@${PG}:5432/redamon"

usage() {
  echo "usage: bash tests/rbac_upgrade_live.sh <all|twice|parallel|failure>... | serve <scenario> | regen" >&2
  echo "  scenarios: $(cd "$FIX/seed" 2>/dev/null && ls -- *.sql 2>/dev/null | sed 's/\.sql$//' | tr '\n' ' ')" >&2
  exit 2
}

[ $# -ge 1 ] || usage
MODES=()
SERVE_SCENARIO=""
case "$1" in
  serve)
    [ $# -eq 2 ] || usage
    SERVE_SCENARIO="$2"
    [ -f "$FIX/$SERVE_SCENARIO.sql" ] || { echo "unknown scenario: $SERVE_SCENARIO" >&2; usage; }
    MODES=(serve) ;;
  regen)
    [ $# -eq 1 ] || usage
    MODES=(regen) ;;
  *)
    for m in "$@"; do
      case "$m" in all|twice|parallel|failure) MODES+=("$m") ;; *) usage ;; esac
    done ;;
esac

SCENARIOS=()
while IFS= read -r f; do
  name="$(basename "$f" .sql)"
  if [ -n "$SCENARIO_FILTER" ] && ! [[ "$name" =~ $SCENARIO_FILTER ]]; then continue; fi
  SCENARIOS+=("$name")
done < <(find "$FIX/seed" -maxdepth 1 -name '*.sql' | LC_ALL=C sort)
[ "${MODES[0]}" = serve ] && SCENARIOS=("$SERVE_SCENARIO")
[ "${#SCENARIOS[@]}" -gt 0 ] || { echo "no scenario selected" >&2; exit 2; }

# ---- self-skip without Docker or the images ------------------------------------
if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
  echo "SKIP: Docker is not available"
  exit 0
fi
for img in "$IMAGE" "$OLD_IMAGE" "$PG_IMAGE"; do
  if ! docker image inspect "$img" >/dev/null 2>&1; then
    echo "SKIP: image $img is absent (see tests/fixtures/rbac_upgrade/README.md)"
    exit 0
  fi
done
if [ "${MODES[0]}" = serve ] && \
   curl -s -m 2 -o /dev/null "http://127.0.0.1:$SERVE_PORT/" 2>/dev/null; then
  echo "port $SERVE_PORT is already answering: stop that server first" >&2
  exit 2
fi

TMP="$(mktemp -d)"
CLEANED_UP=0
cleanup() {
  [ "$CLEANED_UP" -eq 1 ] && return
  CLEANED_UP=1
  [ -n "${SLEEP_PID:-}" ] && kill "$SLEEP_PID" 2>/dev/null
  local ids
  ids="$(docker ps -aq --filter "label=$LABEL" 2>/dev/null)"
  [ -n "$ids" ] && docker rm -f $ids >/dev/null 2>&1
  docker network rm "$NET" >/dev/null 2>&1
  rm -rf "$TMP"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

PASS=0
FAIL=0
pass() { PASS=$((PASS + 1)); echo "  PASS $1"; }
fail() { FAIL=$((FAIL + 1)); echo "  FAIL $1"; }

switch_args() {
  local s
  for s in "${SWITCHES[@]}"; do
    [ -n "${!s+x}" ] && printf '%s\n' -e "$s=${!s}"
  done
}
mapfile -t SWITCH_ARGS < <(switch_args)

# A switch as src/lib/authz/flags.ts reads it: true, 1 or yes, any case, spaces trimmed.
switch_on() {
  local v="${!1:-}"
  v="$(printf '%s' "$v" | tr '[:upper:]' '[:lower:]' | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
  [[ "$v" == true || "$v" == 1 || "$v" == yes ]]
}
# With the permissions switch on the boot also records the identity switch on and converts the
# legacy grants: those scenarios' expected state is its own file.
AFTER_SUFFIX=after
if switch_on RBAC_IDENTITY_ENABLED && switch_on RBAC_PERMISSIONS_ENABLED; then AFTER_SUFFIX=after.permissions; fi

start_infra() { # internal | public
  local net_flag=--internal
  [ "$1" = public ] && net_flag=
  docker network create $net_flag --label "$LABEL" "$NET" >/dev/null || { echo "network create failed"; exit 1; }
  docker run -d --name "$PG" --label "$LABEL" --network "$NET" \
    -e POSTGRES_PASSWORD="$PG_PASSWORD" -e POSTGRES_DB=redamon "$PG_IMAGE" >/dev/null \
    || { echo "postgres start failed"; exit 1; }
  local i
  for i in $(seq 1 60); do
    # pg_isready answers during the init server too; a real query on the final server
    # is the readiness signal.
    docker exec "$PG" psql -X -U postgres -d redamon -qAt -c 'SELECT 1' >/dev/null 2>&1 \
      && docker exec "$PG" pg_isready -h 127.0.0.1 -U postgres >/dev/null 2>&1 && return 0
    sleep 1
  done
  echo "postgres did not become ready"; exit 1
}

psql_db() { docker exec -i "$PG" psql -X -U postgres -d redamon -v ON_ERROR_STOP=1 -qAt -F '|' "$@"; }

reset_db() {
  docker exec "$PG" psql -X -U postgres -d postgres -v ON_ERROR_STOP=1 -q \
    -c 'DROP DATABASE IF EXISTS redamon WITH (FORCE)' -c 'CREATE DATABASE redamon' >/dev/null
}

# The startup list as the image writes it, minus `exec node server.js`. The guard stops
# the harness from silently skipping a step a later Dockerfile appends after the server.
LIST_CMD='tail -n 1 /app/entrypoint.sh | grep -qx "exec node server.js" || { echo "[harness] /app/entrypoint.sh does not end with exec node server.js"; exit 97; }; sed "\$d" /app/entrypoint.sh | sh'

run_list() { # image log_file [url_suffix] -> exit code of the list
  docker run --rm --label "$LABEL" --network "$NET" \
    -e DATABASE_URL="$DB_URL${3:-}" -e CHECKPOINT_DISABLE=1 "${SWITCH_ARGS[@]}" \
    --entrypoint sh "$1" -c "$LIST_CMD" > "$2" 2>&1
}

show_log() { sed -n '1,60p' "$1" | sed 's/^/    | /'; }

# ---- snapshots ---------------------------------------------------------------------
capture_shape() { # records the tables and users columns that exist before a run
  TABLES="$(psql_db -c "SELECT table_name FROM information_schema.tables
    WHERE table_schema = 'public' AND table_type = 'BASE TABLE' ORDER BY 1")"
  USER_COLS="$(psql_db -c "SELECT column_name FROM information_schema.columns
    WHERE table_schema = 'public' AND table_name = 'users' ORDER BY column_name")"
}

snapshot() { # out_file: row counts of the recorded tables, users column definitions and rows
  local t c count_sql="" col_list="" col_select=""
  for t in $TABLES; do
    local only=""
    [ "$t" = audit_log ] && only=" WHERE action NOT IN ($UPGRADE_AUDIT_SQL)"
    count_sql+="${count_sql:+ UNION ALL }SELECT '$t', count(*) FROM \"$t\"$only"
  done
  for c in $USER_COLS; do
    col_list+="${col_list:+, }'$c'"
    col_select+="${col_select:+, }\"$c\""
  done
  {
    echo "== row counts"
    psql_db -c "$count_sql ORDER BY 1" 2>&1
    echo "== users columns"
    psql_db -c "SELECT column_name, data_type, is_nullable, coalesce(column_default, '')
      FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'users'
      AND column_name IN ($col_list) ORDER BY column_name" 2>&1
    echo "== users rows"
    psql_db -c "SELECT $col_select FROM users ORDER BY id" 2>&1
  } > "$1"
}

note_additions() {
  local now_tables now_cols x
  now_tables="$(psql_db -c "SELECT table_name FROM information_schema.tables
    WHERE table_schema = 'public' AND table_type = 'BASE TABLE' ORDER BY 1")"
  now_cols="$(psql_db -c "SELECT column_name FROM information_schema.columns
    WHERE table_schema = 'public' AND table_name = 'users' ORDER BY column_name")"
  for x in $(comm -13 <(printf '%s\n' "$TABLES") <(printf '%s\n' "$now_tables")); do
    echo "  NOTE table added: $x"
  done
  for x in $(comm -13 <(printf '%s\n' "$USER_COLS") <(printf '%s\n' "$now_cols")); do
    echo "  NOTE users column added: $x"
  done
}

assert_same() { # label expected_file actual_file
  if diff -u "$2" "$3" > "$TMP/diff"; then
    pass "$1"
  else
    fail "$1"
    sed -n '1,40p' "$TMP/diff" | sed 's/^/    /'
  fi
}

run_checks() { psql_db < "$FIX/checks.sql" > "$1" 2>&1; }
run_checks_after() { { psql_db < "$FIX/checks.sql"; psql_db < "$FIX/checks_after.sql"; } > "$1" 2>&1; }

prepare() { # scenario: a fresh database holding the fixture, its shape and snapshot
  reset_db || { fail "$1: database reset"; return 1; }
  if ! psql_db < "$FIX/$1.sql" > "$TMP/load.log" 2>&1; then
    fail "$1: fixture loads"; show_log "$TMP/load.log"; return 1
  fi
  capture_shape
  snapshot "$TMP/before.txt"
  run_checks "$TMP/checks.txt"
  assert_same "$1: fixture holds what expected/$1.out records" "$FIX/expected/$1.out" "$TMP/checks.txt"
}

verify() { # scenario label: nothing else changed, scenario checks
  snapshot "$TMP/after.txt"
  assert_same "$1 $2: row counts and users columns unchanged" "$TMP/before.txt" "$TMP/after.txt"
  note_additions
  run_checks_after "$TMP/checks.txt"
  assert_same "$1 $2: checks.sql + checks_after.sql match expected/$1.$AFTER_SUFFIX.out" "$FIX/expected/$1.$AFTER_SUFFIX.out" "$TMP/checks.txt"
}

list_ok() { # scenario label log rc
  if [ "$4" -eq 0 ]; then pass "$1 $2: startup list exits 0"; return 0; fi
  fail "$1 $2: startup list exits 0 (got $4)"; show_log "$3"; return 1
}

# ---- modes ---------------------------------------------------------------------------
mode_all() {
  prepare "$1" || return
  run_list "$IMAGE" "$TMP/run1.log"; list_ok "$1" "run 1" "$TMP/run1.log" $? || return
  verify "$1" "run 1"
}

mode_twice() {
  prepare "$1" || return
  local i
  for i in 1 2; do
    run_list "$IMAGE" "$TMP/run$i.log"; list_ok "$1" "run $i" "$TMP/run$i.log" $? || return
    verify "$1" "run $i"
  done
}

mode_parallel() {
  prepare "$1" || return
  local a="$PFX-par-a" b="$PFX-par-b" ra rb c
  for c in "$a" "$b"; do
    docker run -d --name "$c" --label "$LABEL" --network "$NET" \
      -e DATABASE_URL="$DB_URL" -e CHECKPOINT_DISABLE=1 "${SWITCH_ARGS[@]}" \
      --entrypoint sh "$IMAGE" -c "$LIST_CMD" >/dev/null || { fail "$1 parallel: start $c"; return; }
  done
  ra="$(docker wait "$a")"; rb="$(docker wait "$b")"
  docker logs "$a" > "$TMP/par-a.log" 2>&1; docker logs "$b" > "$TMP/par-b.log" 2>&1
  docker rm -f "$a" "$b" >/dev/null 2>&1
  list_ok "$1" "parallel copy A" "$TMP/par-a.log" "$ra"
  list_ok "$1" "parallel copy B" "$TMP/par-b.log" "$rb"
  verify "$1" "parallel"
}

lock_held() { # 1 when the lock session holds its ACCESS EXCLUSIVE lock
  psql_db -c "SELECT count(*) FROM pg_locks l JOIN pg_class c ON c.oid = l.relation
    WHERE c.relname = '$FAIL_TABLE' AND l.mode = 'AccessExclusiveLock' AND l.granted"
}

mode_failure() {
  prepare "$1" || return
  run_list "$IMAGE" "$TMP/run1.log"; list_ok "$1" "failure run 1" "$TMP/run1.log" $? || return
  verify "$1" "failure run 1"

  local deleted want
  want="$(psql_db -c "$d_rows")"
  deleted="$(psql_db -c "WITH d AS (DELETE FROM audit_log WHERE action = '$FAIL_MARKER' RETURNING 1)
    SELECT count(*) FROM d")"
  if [ -n "$want" ] && [ "$deleted" = "$want" ]; then pass "$1 failure: marker $FAIL_MARKER deleted ($deleted row(s))"
  else fail "$1 failure: marker $FAIL_MARKER deleted (rows: ${deleted:-none}, expected ${want:-?})"; return; fi
  if [ -n "$d_undo" ]; then
    if psql_db -c "$d_undo" >/dev/null; then pass "$1 failure: the data it wrote undone too"
    else fail "$1 failure: the data it wrote undone too"; return; fi
  fi

  docker exec -d -e PGAPPNAME="$PFX-lock" "$PG" psql -X -U postgres -d redamon -qAt \
    -c "BEGIN; LOCK TABLE \"$FAIL_TABLE\" IN ACCESS EXCLUSIVE MODE; SELECT pg_sleep(600); COMMIT;"
  local i
  for i in $(seq 1 40); do [ "$(lock_held)" = 1 ] && break; sleep 0.25; done
  if [ "$(lock_held)" = 1 ]; then pass "$1 failure: $FAIL_TABLE locked by a second session"
  else fail "$1 failure: $FAIL_TABLE locked by a second session"; return; fi

  local start rc elapsed
  start=$(date +%s)
  docker run --rm --label "$LABEL" --network "$NET" \
    -e DATABASE_URL="$DB_URL?options=-c%20lock_timeout%3D2000" -e CHECKPOINT_DISABLE=1 "${SWITCH_ARGS[@]}" \
    --entrypoint sh "$IMAGE" -c "grep -F 'scripts/$FAIL_SCRIPT' /app/entrypoint.sh | sh" \
    > "$TMP/fail.log" 2>&1
  rc=$?
  elapsed=$(( $(date +%s) - start ))
  if [ "$rc" -eq 0 ]; then pass "$1 failure: $FAIL_SCRIPT exits 0 under the lock (${elapsed}s)"
  else fail "$1 failure: $FAIL_SCRIPT exits 0 under the lock (got $rc)"; show_log "$TMP/fail.log"; fi
  if grep -Eq -- "$FAIL_LOG" "$TMP/fail.log" && grep -q 'lock timeout' "$TMP/fail.log"; then
    pass "$1 failure: the failure is logged (lock timeout)"
  else
    fail "$1 failure: the failure is logged (lock timeout)"; show_log "$TMP/fail.log"
  fi
  if [ "$(psql_db -c "SELECT count(*) FROM audit_log WHERE action = '$FAIL_MARKER'")" = 0 ]; then
    pass "$1 failure: no marker written by the failed run"
  else
    fail "$1 failure: no marker written by the failed run"
  fi

  psql_db -c "SELECT pg_cancel_backend(pid) FROM pg_stat_activity WHERE application_name = '$PFX-lock'" >/dev/null
  for i in $(seq 1 40); do [ "$(lock_held)" = 0 ] && break; sleep 0.25; done
  if [ "$(lock_held)" = 0 ]; then pass "$1 failure: lock released"
  else fail "$1 failure: lock released"; return; fi

  run_list "$IMAGE" "$TMP/run3.log"; list_ok "$1" "failure run 3" "$TMP/run3.log" $? || return
  verify "$1" "failure run 3 (backfill completed)"
}

mode_serve() {
  local scn="$1" web="$PFX-web" i code
  prepare "$scn" || exit 1
  run_list "$IMAGE" "$TMP/run1.log"; list_ok "$scn" "serve list" "$TMP/run1.log" $? || exit 1
  verify "$scn" "serve list"
  docker run -d --name "$web" --label "$LABEL" --network "$NET" -p "127.0.0.1:$SERVE_PORT:3000" \
    -e DATABASE_URL="$DB_URL" -e CHECKPOINT_DISABLE=1 \
    -e AUTH_SECRET="$FAKE_AUTH_SECRET" -e INTERNAL_API_KEY="$FAKE_INTERNAL_API_KEY" \
    -e SCANNER_API_KEY="$FAKE_SCANNER_API_KEY" "${SWITCH_ARGS[@]}" \
    --entrypoint sh "$IMAGE" -c 'eval "$(tail -n 1 /app/entrypoint.sh)"' >/dev/null \
    || { echo "server start failed"; exit 1; }
  for i in $(seq 1 120); do
    code="$(curl -s -m 2 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$SERVE_PORT/api/health" 2>/dev/null || true)"
    [ "$code" = 200 ] && break
    sleep 1
  done
  if [ "$code" != 200 ]; then
    echo "server not healthy on 127.0.0.1:$SERVE_PORT (got ${code:-nothing})"
    docker logs "$web" 2>&1 | tail -n 40 | sed 's/^/    | /'
    exit 1
  fi
  echo
  echo "== Serving scenario $scn at http://127.0.0.1:$SERVE_PORT (Ctrl-C stops and removes it)"
  echo "   password of every account with one: $FIXTURE_PASSWORD"
  echo "   fake AUTH_SECRET=$FAKE_AUTH_SECRET INTERNAL_API_KEY=$FAKE_INTERNAL_API_KEY SCANNER_API_KEY=$FAKE_SCANNER_API_KEY"
  echo "   accounts (email | role | password state):"
  psql_db -c "SELECT email, role, CASE WHEN password = '' THEN 'passwordless' ELSE 'password' END
    FROM users ORDER BY created_at" | sed 's/^/     /'
  while :; do sleep 3600 & SLEEP_PID=$!; wait "$SLEEP_PID"; done
}

mode_regen() {
  local scn out
  for scn in "${SCENARIOS[@]}"; do
    echo "== regen $scn"
    reset_db || { echo "database reset failed"; exit 1; }
    run_list "$OLD_IMAGE" "$TMP/regen.log" || { echo "7.7.2 startup list failed"; show_log "$TMP/regen.log"; exit 1; }
    psql_db < "$FIX/seed/$scn.sql" > "$TMP/seed.log" 2>&1 || { echo "seed failed"; show_log "$TMP/seed.log"; exit 1; }
    out="$FIX/$scn.sql"
    {
      echo "-- SYNTHETIC test fixture of tests/rbac_upgrade_live.sh, scenario $scn: no real user, host or secret."
      echo "-- Full dump (schema and data, pg_dump --no-owner) of the database the pinned"
      echo "-- redamon-webapp:rbac-7.7.2 startup list creates, plus seed/$scn.sql. Regenerate with"
      echo "-- 'bash tests/rbac_upgrade_live.sh regen'; never edit by hand (README.md)."
      docker exec "$PG" pg_dump --no-owner -U postgres redamon
    } > "$out.tmp" || { echo "pg_dump failed"; rm -f "$out.tmp"; exit 1; }
    mv "$out.tmp" "$out"
    reset_db
    psql_db < "$out" > "$TMP/load.log" 2>&1 || { echo "the new dump does not load"; show_log "$TMP/load.log"; exit 1; }
    run_checks "$FIX/expected/$scn.out"
    echo "  wrote $(basename "$out") ($(wc -c < "$out") bytes) and expected/$scn.out"
  done
}

# ---- run -------------------------------------------------------------------------------
case "${MODES[0]}" in
  serve) start_infra public; mode_serve "$SERVE_SCENARIO" ;;
  regen) start_infra internal; mode_regen; echo "== regen done: review git diff tests/fixtures/rbac_upgrade"; exit 0 ;;
esac

start_infra internal
started=$(date +%s)
for mode in "${MODES[@]}"; do
  for scn in "${SCENARIOS[@]}"; do
    echo "== $mode: $scn"
    "mode_$mode" "$scn"
  done
done
echo "== RESULT: $PASS passed, $FAIL failed ($(( $(date +%s) - started ))s) =="
[ "$FAIL" -eq 0 ]
