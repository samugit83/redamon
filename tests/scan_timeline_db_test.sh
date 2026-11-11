#!/usr/bin/env bash
# =============================================================================
# Scan Timeline — Postgres integration test (schema + referential actions)
# =============================================================================
# Verifies at the DATABASE level what the Prisma models promise, because the
# Scan Timeline's data-loss guarantees rest on them:
#   - the three tables exist with the expected shape
#   - (project_id, seq) is unique  -> version numbering can't fork
#   - project delete cascades      -> no orphan versions/jobs/schedules, and a
#                                     deleted project's snapshot bytes go away
#   - version delete cascades jobs -> Section 5 delete semantics
#   - schedule delete NULLs jobs   -> run history survives losing its schedule
#
# Requires the stack's postgres container to be up:
#   docker compose up -d postgres
# Usage: tests/scan_timeline_db_test.sh
# =============================================================================
set -uo pipefail

cd "$(dirname "$0")/.."

PSQL=(docker compose exec -T postgres psql -U redamon -d redamon -qtAX)

pass=0
fail=0

ok()   { echo "  PASS  $1"; pass=$((pass + 1)); }
bad()  { echo "  FAIL  $1"; echo "        $2"; fail=$((fail + 1)); }

q() { "${PSQL[@]}" -c "$1" 2>&1; }

expect_eq() { # desc expected actual
  if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "expected '$2' got '$3'"; fi
}

echo "== Scan Timeline DB integration =="

if ! q "select 1" >/dev/null 2>&1; then
  echo "  SKIP  postgres container not reachable (docker compose up -d postgres)"
  exit 0
fi

# ---------------------------------------------------------------- fixtures ---
SUF="st_$(date +%s)_$$"
U="user_$SUF"
P="proj_$SUF"

q "insert into users (id, name, email, password, role, created_at, updated_at)
   values ('$U', 'timeline test', '$U@example.invalid', '', 'standard', now(), now())" >/dev/null
# ownership_token is NOT NULL and only Prisma fills it, so a raw insert brings its own.
q "insert into projects (id, user_id, name, ownership_token, created_at, updated_at)
   values ('$P', '$U', 'timeline test', gen_random_uuid()::text, now(), now())" >/dev/null

cleanup() {
  q "delete from projects where id = '$P'" >/dev/null 2>&1
  q "delete from users where id = '$U'" >/dev/null 2>&1
}
trap cleanup EXIT

# ------------------------------------------------------------------ tables ---
for t in scan_versions scan_jobs scan_schedules; do
  got=$(q "select count(*) from information_schema.tables where table_name = '$t'")
  expect_eq "table $t exists" "1" "$got"
done

got=$(q "select data_type from information_schema.columns
         where table_name='scan_versions' and column_name='snapshot'")
expect_eq "scan_versions.snapshot is bytea" "bytea" "$got"

got=$(q "select count(*) from information_schema.columns
         where table_name='projects' and column_name='activation_state'")
expect_eq "projects.activation_state exists (activation lock)" "1" "$got"

# --------------------------------------------------------- unique(pid, seq) ---
q "insert into scan_versions (id, project_id, seq, label, is_current, pinned, created_at, updated_at)
   values ('v1_$SUF', '$P', 1, 'Scan 1', false, false, now(), now())" >/dev/null
dup=$(q "insert into scan_versions (id, project_id, seq, label, is_current, pinned, created_at, updated_at)
         values ('vdup_$SUF', '$P', 1, 'dupe', false, false, now(), now())")
if echo "$dup" | grep -qi "duplicate key\|unique constraint"; then
  ok "unique(project_id, seq) rejects a duplicate seq"
else
  bad "unique(project_id, seq) rejects a duplicate seq" "insert unexpectedly succeeded: $dup"
fi

# ------------------------------------------------- version delete cascades ---
q "insert into scan_versions (id, project_id, seq, label, is_current, pinned, created_at, updated_at)
   values ('v2_$SUF', '$P', 2, 'Scan 2', true, false, now(), now())" >/dev/null
q "insert into scan_schedules (id, project_id, user_id, label, mode, scan_mode, enabled, created_at, updated_at)
   values ('s1_$SUF', '$P', '$U', '', 'once', 'new', true, now(), now())" >/dev/null
q "insert into scan_jobs (id, project_id, version_id, schedule_id, trigger, status, created_at, updated_at)
   values ('j1_$SUF', '$P', 'v1_$SUF', 's1_$SUF', 'manual', 'completed', now(), now())" >/dev/null

q "delete from scan_versions where id = 'v1_$SUF'" >/dev/null
got=$(q "select count(*) from scan_jobs where id = 'j1_$SUF'")
expect_eq "deleting a version cascade-deletes its jobs" "0" "$got"

# ------------------------------------------------ schedule delete NULLs job ---
q "insert into scan_jobs (id, project_id, version_id, schedule_id, trigger, status, created_at, updated_at)
   values ('j2_$SUF', '$P', 'v2_$SUF', 's1_$SUF', 'scheduled', 'completed', now(), now())" >/dev/null
q "delete from scan_schedules where id = 's1_$SUF'" >/dev/null
got=$(q "select count(*) from scan_jobs where id = 'j2_$SUF' and schedule_id is null")
expect_eq "deleting a schedule keeps its run history (schedule_id -> NULL)" "1" "$got"

# --------------------------------------------- snapshot bytes round-trip ------
q "update scan_versions set snapshot = decode('1f8b0800', 'hex') where id = 'v2_$SUF'" >/dev/null
got=$(q "select length(snapshot) from scan_versions where id = 'v2_$SUF'")
expect_eq "snapshot bytes persist" "4" "$got"

# ------------------------------------------------------ FK + NOT NULL ---------
bad=$(q "insert into scan_jobs (id, project_id, version_id, trigger, status, created_at, updated_at)
         values ('jbad_$SUF', '$P', 'no_such_version', 'manual', 'completed', now(), now())")
if echo "$bad" | grep -qi "foreign key"; then
  ok "a job cannot reference a version that does not exist (FK)"
else
  bad "a job cannot reference a version that does not exist (FK)" "insert unexpectedly succeeded: $bad"
fi

bad=$(q "insert into scan_versions (id, project_id, seq, label, is_current, pinned, created_at, updated_at)
         values ('vnull_$SUF', '$P', null, 'no seq', false, false, now(), now())")
if echo "$bad" | grep -qi "not-null\|null value"; then
  ok "seq is NOT NULL (a version always has an identity)"
else
  bad "seq is NOT NULL (a version always has an identity)" "insert unexpectedly succeeded: $bad"
fi

bad=$(q "insert into scan_schedules (id, project_id, user_id, label, mode, scan_mode, enabled, created_at, updated_at)
         values ('sbad_$SUF', 'no_such_project', '$U', '', 'once', 'new', true, now(), now())")
if echo "$bad" | grep -qi "foreign key"; then
  ok "a schedule cannot reference a project that does not exist (FK)"
else
  bad "a schedule cannot reference a project that does not exist (FK)" "insert unexpectedly succeeded: $bad"
fi

# ------------------------------------------- activation lock atomicity --------
# The lock is a conditional UPDATE; two concurrent acquires must not both win, or
# two activations would clear and rebuild the same graph at the same time.
q "update projects set activation_state='idle', activation_started_at=null where id='$P'" >/dev/null
a=$(q "update projects set activation_state='activating', activation_started_at=now()
       where id='$P' and (activation_state='idle' or activation_started_at is null) returning id" &)
b=$(q "update projects set activation_state='activating', activation_started_at=now()
       where id='$P' and (activation_state='idle' or activation_started_at is null) returning id")
wait
winners=0
[ -n "$a" ] && winners=$((winners + 1))
[ -n "$b" ] && winners=$((winners + 1))
if [ "$winners" -eq 1 ]; then
  ok "two concurrent activation-lock acquires: exactly one wins"
else
  bad "two concurrent activation-lock acquires: exactly one wins" "winners=$winners"
fi
q "update projects set activation_state='idle', activation_started_at=null where id='$P'" >/dev/null

# ------------------------------------------------- schema push idempotency ----
# The project deploys schema with `prisma db push` (never migrate), so the check
# that matters is: re-pushing against POPULATED tables is a no-op with no data loss.
before=$(q "select count(*) from scan_versions where project_id='$P'")
push=$(docker compose exec -T webapp npx prisma db push --skip-generate 2>&1)
after=$(q "select count(*) from scan_versions where project_id='$P'")
if echo "$push" | grep -qi "already in sync"; then
  ok "re-pushing the schema is a no-op (already in sync)"
else
  bad "re-pushing the schema is a no-op (already in sync)" "$(echo "$push" | tail -3)"
fi
expect_eq "populated version rows survive a schema push (no data loss)" "$before" "$after"

# -------------------------------------------------- project delete cascades ---
q "insert into scan_schedules (id, project_id, user_id, label, mode, scan_mode, enabled, created_at, updated_at)
   values ('s2_$SUF', '$P', '$U', '', 'interval', 'new', true, now(), now())" >/dev/null
q "delete from projects where id = '$P'" >/dev/null
for t in scan_versions scan_jobs scan_schedules; do
  got=$(q "select count(*) from $t where project_id = '$P'")
  expect_eq "project delete cascades $t (snapshot bytes go with it)" "0" "$got"
done

# ------------------------------------ P0-2: rollback of a refused start -------
# A start the orchestrator REFUSES must cost the user nothing. Before P0-2 the
# freeze ran first and carried retention with it, so retrying a 403 in a loop
# minted a version, stored a duplicate snapshot and evicted the oldest saved
# one. rollbackPreparedVersions undoes the freeze in ONE transaction; these
# assert the database-level result of that transaction, and the referential
# hazard it runs into.
SUF2="rb_$(date +%s)_$$"
U2="user_$SUF2"
P2="proj_$SUF2"
q "insert into users (id, name, email, password, role, created_at, updated_at)
   values ('$U2', 'rb test', '$U2@test.local', 'x', 'standard', now(), now())" >/dev/null
q "insert into projects (id, user_id, name, target_domain, ownership_token, created_at, updated_at)
   values ('$P2', '$U2', 'rb', 'rb.test', gen_random_uuid()::text, now(), now())" >/dev/null

# The pre-start state: v1 current, carrying a snapshot and a run history row.
q "insert into scan_versions (id, project_id, seq, label, is_current, pinned, node_count, link_count, snapshot, created_at, updated_at)
   values ('v1_$SUF2', '$P2', 1, 'Scan 1', true, false, 100, 200, '\\x1f8b'::bytea, now(), now())" >/dev/null
q "insert into scan_jobs (id, project_id, version_id, kind, run_id, trigger, mode, status, created_at, updated_at)
   values ('j1_$SUF2', '$P2', 'v1_$SUF2', 'full_recon', '', 'manual', 'new', 'completed', now(), now())" >/dev/null

# prepareVersionsForFullScan: freeze v1 (demote + store snapshot), mint v2.
q "update scan_versions set is_current = false where id = 'v1_$SUF2'" >/dev/null
q "insert into scan_versions (id, project_id, seq, label, is_current, pinned, created_at, updated_at)
   values ('v2_$SUF2', '$P2', 2, 'Scan 2', true, false, now(), now())" >/dev/null
expect_eq "after the freeze there are 2 versions" "2" \
  "$(q "select count(*) from scan_versions where project_id='$P2'")"

# The orchestrator refuses -> rollbackPreparedVersions, in ONE transaction.
q "begin;
   delete from scan_versions where id = 'v2_$SUF2';
   update scan_versions set is_current = true, snapshot = null where id = 'v1_$SUF2';
   commit;" >/dev/null

expect_eq "a refused start leaves the version COUNT unchanged" "1" \
  "$(q "select count(*) from scan_versions where project_id='$P2'")"
expect_eq "the frozen version is current again" "t" \
  "$(q "select is_current from scan_versions where id='v1_$SUF2'")"
expect_eq "exactly ONE version is current" "1" \
  "$(q "select count(*) from scan_versions where project_id='$P2' and is_current")"
expect_eq "the duplicate snapshot is cleared" "t" \
  "$(q "select snapshot is null from scan_versions where id='v1_$SUF2'")"
expect_eq "the minted version is gone" "0" \
  "$(q "select count(*) from scan_versions where id='v2_$SUF2'")"
# The run history must survive the rollback: it hangs off v1, not v2.
expect_eq "prior run history survives the rollback" "1" \
  "$(q "select count(*) from scan_jobs where id='j1_$SUF2'")"

# REFERENTIAL HAZARD: scan_jobs.version_id is ON DELETE CASCADE, so deleting
# the minted version takes any job row pointing at it. Today the minted version
# is brand new and has none - the per-project mutex keeps a second start out
# until the first finishes - but if that ever stops holding, the rollback would
# silently delete run history. Pinned so the cascade is a known property.
q "insert into scan_versions (id, project_id, seq, label, is_current, pinned, created_at, updated_at)
   values ('v3_$SUF2', '$P2', 3, 'Scan 3', false, false, now(), now())" >/dev/null
q "insert into scan_jobs (id, project_id, version_id, kind, run_id, trigger, mode, status, created_at, updated_at)
   values ('j3_$SUF2', '$P2', 'v3_$SUF2', 'full_recon', '', 'manual', 'new', 'running', now(), now())" >/dev/null
q "delete from scan_versions where id = 'v3_$SUF2'" >/dev/null
expect_eq "deleting a version CASCADES its scan_jobs (known hazard for rollback)" "0" \
  "$(q "select count(*) from scan_jobs where id='j3_$SUF2'")"

q "delete from users where id = '$U2'" >/dev/null

echo
echo "  $pass passed, $fail failed"
[ "$fail" -eq 0 ] || exit 1
