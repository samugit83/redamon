#!/usr/bin/env bash
#
# Live check of RBAC step 1.12 (HD-08, DV-33, F-07) against the LIVE stack: Nuclei
# templates have owners. The E2E-P0-08 flow over HTTP: member A uploads x.yaml; member B
# cannot overwrite, see, delete or select it (nor reach it through a free-form -t path);
# a scan's settings read drops it from B's project even when written behind the PUT's
# back; an admin overwrites it with the flag and promotes it; then B can select it and
# still cannot replace it. Then the user deletion hands a member's templates to the
# deleting admin (DV-33), and the upgrade backfill made the shipped templates instance
# templates, so an existing selection of them still reaches the scan.
#
# Fixtures are synthetic: webapp/scripts/e2e-rbac-seed.mjs (rbac-*@e2e.local, rbac-PA /
# rbac-PB), the throwaway rbac-tpl-owner@e2e.local, and templates under the rbac-e2e/
# folder of the shared templates directory. The trap removes the templates (files and
# rows), then runs e2e-rbac-cleanup.mjs, even on a failure or Ctrl-C. Response bodies,
# passwords and the internal key (read from .env into curl's config on stdin) are never
# printed.
#
# Needs the stack up (webapp on :3000 with step 1.12's image, postgres); prints SKIP and
# exits 0 when it is not. As a *_live.sh it is never in the gate.
#
# Run:  bash tests/rbac_nuclei_templates_live.sh       (BASE_URL overrides :3000)
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASE="${BASE_URL:-http://localhost:3000}"
FOLDER='rbac-e2e'
X="$FOLDER/x.yaml"
OWNER_EMAIL='rbac-tpl-owner@e2e.local'
OWNER_PASSWORD='rbac-tpl-owner-passphrase'
SHIPPED='aem-json-exposure.yaml'

health="$(curl -s -m 5 -o /dev/null -w '%{http_code}' "$BASE/api/health" 2>/dev/null || true)"
if [ "$health" != 200 ]; then
  echo "SKIP: RedAmon webapp not answering at $BASE/api/health (got ${health:-nothing})"
  exit 0
fi
for svc in webapp postgres; do
  if ! (cd "$ROOT" && docker compose ps --status running -q "$svc" 2>/dev/null | grep -q .); then
    echo "SKIP: no running $svc container (docker compose ps $svc)"
    exit 0
  fi
done

TMP="$(mktemp -d)"
CLEANED_UP=0
OWNER_ID=''
STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
safe_id() { [[ "$1" =~ ^[A-Za-z0-9_-]+$ ]]; }
webapp_node() { # script: run a fixture script inside the webapp container, read from stdin
  (cd "$ROOT" && docker compose exec -T -w /app webapp node --input-type=module -) < "$ROOT/webapp/scripts/$1"
}
db_sql() { # SQL on stdin -> psql in the postgres container; prints only the returned values
  (cd "$ROOT" && docker compose exec -T postgres \
    sh -c 'psql -X -q -t -A -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB"') 2>/dev/null
}
env_key() { # NAME -> value from the repo .env (never printed)
  grep -m1 "^$1=" "$ROOT/.env" 2>/dev/null | cut -d= -f2- | sed -e 's/^["'\'']//' -e 's/["'\'']$//'
}
cleanup() {
  [ "$CLEANED_UP" -eq 1 ] && return
  CLEANED_UP=1
  echo "== Cleaning up fixtures =="
  # The folder holds only this script's uploads; the rows go with them.
  (cd "$ROOT" && docker compose exec -T webapp sh -c 'rm -rf "${NUCLEI_TEMPLATES_PATH:-/data/nuclei-templates}/rbac-e2e"') 2>/dev/null \
    || echo "  could not remove the rbac-e2e template folder"
  printf "delete from nuclei_templates where path like '%s/%%';\ndelete from audit_log where target_type = 'nuclei_template' and target_id like '%s/%%';\n" "$FOLDER" "$FOLDER" \
    | db_sql > /dev/null || echo "  could not remove the rbac-e2e template rows"
  # The throwaway account is gone by then, so e2e-rbac-cleanup.mjs no longer matches its rows.
  if [ -n "$OWNER_ID" ] && safe_id "$OWNER_ID"; then
    printf "delete from audit_log where actor_id = '%s' or target_id = '%s';\n" "$OWNER_ID" "$OWNER_ID" | db_sql > /dev/null || true
  fi
  webapp_node e2e-rbac-cleanup.mjs | sed 's/^/  /' || echo "  cleanup failed: rerun it by hand (see e2e-rbac-cleanup.mjs)"
  rm -rf "$TMP"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

echo "== Seeding fixtures =="
declare -A SEED=()
seed_out="$(webapp_node e2e-rbac-seed.mjs)" || { echo "seed failed"; exit 1; }
while IFS= read -r kv; do
  [[ "$kv" =~ ^([A-Z][A-Z0-9_]*)=([A-Za-z0-9@._:-]*)$ ]] && SEED[${BASH_REMATCH[1]}]="${BASH_REMATCH[2]}"
done <<< "$seed_out"
for k in ADMIN_A_EMAIL ADMIN_A_ID MEMBER_A_EMAIL MEMBER_A_ID MEMBER_B_EMAIL PA_ID PB_ID RBAC_PASSWORD; do
  [ -n "${SEED[$k]:-}" ] || { echo "seed output lacks $k"; exit 1; }
done
KEY="$(env_key INTERNAL_API_KEY)"
[ -n "$KEY" ] || { echo "INTERNAL_API_KEY is not set in .env"; exit 1; }

PASS=0; FAIL=0
check() { # name ok-flag [why]
  if [ "$2" = 1 ]; then echo "PASS  $1"; PASS=$((PASS + 1)); else echo "FAIL  $1  ${3:-}"; FAIL=$((FAIL + 1)); fi
}
sign_in() { # email password jar -> http code
  printf '{"email":"%s","password":"%s"}' "$1" "$2" > "$TMP/login.json"
  curl -s -m 30 -o /dev/null -w '%{http_code}' -c "$3" -X POST "$BASE/api/auth/login" \
    -H 'Content-Type: application/json' --data-binary @"$TMP/login.json"
}
call() { # jar method path [json-body] -> http code; the body lands in $TMP/body, never printed
  local jar="$1" method="$2" path="$3"
  local args=(-s -m 60 -o "$TMP/body" -w '%{http_code}' -X "$method" -b "$jar" -H "Origin: $BASE")
  if [ $# -ge 4 ]; then
    printf '%s' "$4" > "$TMP/req"
    args+=(-H 'Content-Type: application/json' --data-binary @"$TMP/req")
  fi
  curl "${args[@]}" "$BASE$path"
}
upload() { # jar file-name template-id [overwrite] -> http code; uploads into rbac-e2e/
  printf 'id: %s\ninfo:\n  name: RBAC %s\n  severity: info\n' "$3" "$3" > "$TMP/$2"
  local args=(-s -m 60 -o "$TMP/body" -w '%{http_code}' -X POST -b "$1" -H "Origin: $BASE"
    -F "file=@$TMP/$2;filename=$2" -F "subdir=$FOLDER")
  [ "${4:-}" = overwrite ] && args+=(-F overwrite=true)
  curl "${args[@]}" "$BASE/api/nuclei-templates"
}
internal_get() { # path -> http code, with the internal key (from .env, on curl's stdin)
  printf 'header = "X-Internal-Key: %s"\n' "$KEY" | curl -K - -s -m 60 -o "$TMP/body" -w '%{http_code}' "$BASE$1"
}
body_has() { grep -qF -- "$1" "$TMP/body"; }
json_field() { # python expression over `b` (the parsed body) -> printed value
  python3 -c 'import json,sys; b=json.load(open(sys.argv[1])); print(eval(sys.argv[2]))' "$TMP/body" "$1" 2>/dev/null
}
owner_of() { printf "select coalesce(owner_user_id, '<instance>') from nuclei_templates where path = '%s';\n" "$1" | db_sql | tail -n 1; }

A_JAR="$TMP/jar.a"; B_JAR="$TMP/jar.b"; ADMIN_JAR="$TMP/jar.admin"
ok=0
[ "$(sign_in "${SEED[MEMBER_A_EMAIL]}" "${SEED[RBAC_PASSWORD]}" "$A_JAR")" = 200 ] \
  && [ "$(sign_in "${SEED[MEMBER_B_EMAIL]}" "${SEED[RBAC_PASSWORD]}" "$B_JAR")" = 200 ] \
  && [ "$(sign_in "${SEED[ADMIN_A_EMAIL]}" "${SEED[RBAC_PASSWORD]}" "$ADMIN_JAR")" = 200 ] && ok=1
check "sign in as member A, member B and admin A" "$ok"
[ "$ok" = 1 ] || exit 1

# ---- E2E-P0-08 -------------------------------------------------------------------------
echo "== Member A's template =="
code="$(upload "$A_JAR" x.yaml rbac-x)"
ok=0; [ "$code" = 200 ] && [ "$(owner_of "$X")" = "${SEED[MEMBER_A_ID]}" ] && ok=1
check "member A uploads $X: 200, the row names A" "$ok" "got $code"

code="$(upload "$B_JAR" x.yaml rbac-x-by-b)"
ok=0; [ "$code" = 409 ] && body_has '"code":"template_owned_by_other"' && ok=1
check "member B uploads the same path: 409 template_owned_by_other" "$ok" "got $code"

code="$(call "$B_JAR" GET /api/nuclei-templates)"
ok=0; [ "$code" = 200 ] && ! body_has "\"$X\"" && body_has '"ownership":"instance"' && ok=1
check "member B's list leaves A's template out and shows the instance ones" "$ok" "got $code"
code="$(call "$A_JAR" GET /api/nuclei-templates)"
ok=0; [ "$code" = 200 ] && [ "$(json_field "[t['ownership'] for t in b['templates'] if t['path']=='$X']")" = "['own']" ] && ok=1
check "member A sees it as theirs" "$ok" "got $code"

code="$(call "$B_JAR" DELETE "/api/nuclei-templates?path=$X")"
ok=0; [ "$code" = 403 ] && body_has '"permission":"platform:nuclei_templates"' && [ "$(owner_of "$X")" = "${SEED[MEMBER_A_ID]}" ] && ok=1
check "member B deletes A's template: 403, the template stays" "$ok" "got $code"

code="$(call "$B_JAR" PUT "/api/projects/${SEED[PB_ID]}" "{\"nucleiSelectedCustomTemplates\":[\"$X\"]}")"
ok=0; [ "$code" = 400 ] && body_has '"code":"template_not_selectable"' && ok=1
check "member B selects A's template in PB: 400 template_not_selectable" "$ok" "got $code"
code="$(call "$B_JAR" PUT "/api/projects/${SEED[PB_ID]}" "{\"nucleiTemplates\":[\"../../custom-templates/$X\"]}")"
ok=0; [ "$code" = 400 ] && body_has '"field":"nucleiTemplates"' && ok=1
check "member B reaches it through a free-form -t path: 400" "$ok" "got $code"

code="$(call "$A_JAR" PUT "/api/projects/${SEED[PA_ID]}" "{\"nucleiSelectedCustomTemplates\":[\"$X\",\"$SHIPPED\"]}")"
ok=0; [ "$code" = 200 ] && ok=1
check "member A selects their own and a shipped template in PA: 200" "$ok" "got $code"

echo "== What a scan reads =="
code="$(internal_get "/api/projects/${SEED[PA_ID]}")"
ok=0; [ "$code" = 200 ] && [ "$(json_field "b['nucleiSelectedCustomTemplates']")" = "['$X', '$SHIPPED']" ] && ok=1
check "the scan of PA gets A's own and the shipped template" "$ok" "got $code"
# A selection written behind the PUT's back (as an import, a preset or an MCP tool would).
printf "update projects set nuclei_selected_custom_templates = array['%s', '%s'], nuclei_templates = array['/custom-templates/%s'] where id = '%s' returning id;\n" \
  "$X" "$SHIPPED" "$X" "${SEED[PB_ID]}" | db_sql > /dev/null
code="$(internal_get "/api/projects/${SEED[PB_ID]}")"
ok=0
[ "$code" = 200 ] && [ "$(json_field "b['nucleiSelectedCustomTemplates']")" = "['$SHIPPED']" ] \
  && [ "$(json_field "b['nucleiTemplates']")" = "[]" ] && ok=1
check "the scan of PB never gets A's file, even written behind the PUT's back" "$ok" "got $code"
n="$( (cd "$ROOT" && docker compose logs --no-color --since "$STARTED_AT" webapp 2>/dev/null) \
  | grep -cF "[rbac] nuclei template dropped project=${SEED[PB_ID]}")"
ok=0; [ "${n:-0}" -ge 2 ] && ok=1
check "the webapp logs each drop: [rbac] nuclei template dropped project=<PB>" "$ok" "lines: ${n:-0}"

# Back to an empty selection, so the selection after the promotion is judged afresh.
printf "update projects set nuclei_selected_custom_templates = '{}', nuclei_templates = '{}' where id = '%s' returning id;\n" \
  "${SEED[PB_ID]}" | db_sql > /dev/null

echo "== The admin =="
code="$(upload "$ADMIN_JAR" x.yaml rbac-x-fixed)"
ok=0; [ "$code" = 409 ] && ok=1
check "an admin without the overwrite flag: 409" "$ok" "got $code"
code="$(upload "$ADMIN_JAR" x.yaml rbac-x-fixed overwrite)"
ok=0; [ "$code" = 200 ] && [ "$(owner_of "$X")" = "${SEED[MEMBER_A_ID]}" ] && ok=1
check "an admin overwrites with the flag: 200, the owner stays A" "$ok" "got $code"
code="$(call "$A_JAR" PATCH /api/nuclei-templates "{\"path\":\"$X\",\"promote\":true}")"
ok=0; [ "$code" = 403 ] && ok=1
check "member A cannot promote their own template: 403" "$ok" "got $code"
code="$(call "$ADMIN_JAR" PATCH /api/nuclei-templates "{\"path\":\"$X\",\"promote\":true}")"
promoted_by="$(printf "select coalesce(promoted_by_id, '') from nuclei_templates where path = '%s';\n" "$X" | db_sql | tail -n 1)"
ok=0; [ "$code" = 200 ] && [ "$(owner_of "$X")" = '<instance>' ] && [ "$promoted_by" = "${SEED[ADMIN_A_ID]}" ] && ok=1
check "the admin promotes it: 200, an instance template promoted by the admin" "$ok" "got $code"

code="$(call "$B_JAR" PUT "/api/projects/${SEED[PB_ID]}" "{\"nucleiSelectedCustomTemplates\":[\"$X\"]}")"
ok=0; [ "$code" = 200 ] && ok=1
check "after the promotion member B selects it in PB: 200" "$ok" "got $code"
code="$(upload "$B_JAR" x.yaml rbac-x-by-b)"
ok=0; [ "$code" = 409 ] && body_has '"ownership":"instance"' && ok=1
check "member B still cannot replace it: 409, an instance template" "$ok" "got $code"
code="$(call "$B_JAR" DELETE "/api/nuclei-templates?path=$X")"
ok=0; [ "$code" = 403 ] && ok=1
check "nor delete it: 403" "$ok" "got $code"

n="$(printf "select string_agg(action, ',' order by created_at, id) from audit_log where target_type = 'nuclei_template' and target_id = '%s';\n" "$X" | db_sql | tail -n 1)"
ok=0; [ "$n" = 'nuclei_template.upload,nuclei_template.upload,nuclei_template.promote' ] && ok=1
check "audited: A's upload, the admin's overwrite, the promotion (refusals write nothing)" "$ok" "got: ${n:-none}"

# ---- DV-33: deleting a user hands their templates to the deleting admin -----------------
echo "== Deleting a member with a template =="
code="$(call "$ADMIN_JAR" POST /api/users \
  "{\"name\":\"RBAC Template Owner\",\"email\":\"$OWNER_EMAIL\",\"password\":\"$OWNER_PASSWORD\",\"role\":\"standard\"}")"
OWNER_ID="$(json_field "b.get('id','')")"
ok=0; [ "$code" = 201 ] && safe_id "$OWNER_ID" && ok=1
check "create the throwaway account -> $code" "$ok"
if [ "$ok" = 1 ]; then
  O_JAR="$TMP/jar.owner"
  code="$(sign_in "$OWNER_EMAIL" "$OWNER_PASSWORD" "$O_JAR")"
  [ "$code" = 200 ] && code="$(upload "$O_JAR" owned.yaml rbac-owned)"
  ok=0; [ "$code" = 200 ] && [ "$(owner_of "$FOLDER/owned.yaml")" = "$OWNER_ID" ] && ok=1
  check "it uploads $FOLDER/owned.yaml" "$ok" "got $code"
  code="$(call "$ADMIN_JAR" DELETE "/api/users/$OWNER_ID")"
  ok=0; [ "$code" = 200 ] && [ "$(owner_of "$FOLDER/owned.yaml")" = "${SEED[ADMIN_A_ID]}" ] && ok=1
  check "the admin deletes the account: 200, the template now belongs to that admin, not the instance" "$ok" "got $code"
  n="$(printf "select after::text from audit_log where action = 'user.delete' and target_id = '%s';\n" "$OWNER_ID" | db_sql | tail -n 1)"
  ok=0; [[ "$n" == *'"templatesReassigned": 1'* ]] && ok=1
  check "user.delete records templatesReassigned 1" "$ok"
fi

# ---- UP-03 / done-when: the shipped templates are instance templates ---------------------
echo "== The upgrade backfill =="
n="$(printf "select count(*) from audit_log where action = 'system.nuclei_template_owners_backfill';\n" | db_sql | tail -n 1)"
ok=0; [ "${n:-0}" -ge 1 ] && [ "$(owner_of "$SHIPPED")" = '<instance>' ] && ok=1
check "the backfill ran (marker row) and the shipped $SHIPPED is an instance template" "$ok" "markers: ${n:-0}"

echo
echo "== RESULT: $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
