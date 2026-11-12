#!/usr/bin/env bash
#
# Live check of impersonation under RBAC (step 3.14: IM-03, IM-04, IM-05, IM-08, IM-09, IM-10,
# IM-11, AU-03), run against the LIVE stack, in whichever state the webapp's switches are (read
# from its container). The API side of E2E rows P3-07 and P3-08; the dialog and the banner are
# the rows' Chrome DevTools part.
#
# Permissions switch on (needs identity on): rbac-admin-a (Full admin) acts as rbac-member-c only
# with its own password and within the instance's reason rule; the cookie lives the chosen 15
# minutes; /api/auth/me names whom it acts as, why and until when; the start row carries reason and
# duration and the member gets an acted_as notice (unless Root turned it off); changing the
# member's password, email or deleting it, and adding an MCP server or an LLM provider to the
# passwordless managed account, answer 403 not_while_acting_as with an act_as.refused row each; acting as rbac-admin-b is Root's (403 root_only); the User manager profile may not act
# as anyone (403 users:impersonate); Stop, disabling the member and signing out each end it once
# with their endedBy (stopped, target_disabled, logout); a saved copy of the cookie replayed after
# a sign-out, a newer act-as or a Stop acts as nobody and writes nothing; the member's next sign-in
# shows the notice.
#
# Switch off: act-as answers as Phase 2 (no reason, no password for a member), /api/auth/me has
# no `actingAs`, and nothing above is refused.
#
# Fixtures are synthetic: webapp/scripts/e2e-rbac-seed.mjs (rbac-*@e2e.local), removed with their
# audit and act-as rows by e2e-rbac-cleanup.mjs, even on Ctrl-C. The member is enabled again after
# its disable. act_as_audit, audit_log and users are read through psql in the postgres container.
# Response bodies and the fixture password are never printed.
#
# Needs the stack up (webapp on :3000); prints SKIP and exits 0 when it is not. As a *_live.sh it
# is never in the gate.
#
# Run:  bash tests/rbac_act_as_live.sh            (BASE_URL overrides :3000)
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASE="${BASE_URL:-http://localhost:3000}"

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
webapp_node() { # script: run a fixture script inside the webapp container, read from stdin
  (cd "$ROOT" && docker compose exec -T -w /app webapp node --input-type=module -) < "$ROOT/webapp/scripts/$1"
}
db_sql() { # SQL on stdin -> psql in the postgres container; prints only the returned values
  (cd "$ROOT" && docker compose exec -T postgres \
    sh -c 'psql -X -q -t -A -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB"') 2>/dev/null
}
cleanup() {
  [ "$CLEANED_UP" -eq 1 ] && return
  CLEANED_UP=1
  echo "== Cleaning up fixtures =="
  webapp_node e2e-rbac-cleanup.mjs | sed 's/^/  /' || echo "  cleanup failed: rerun it by hand (see e2e-rbac-cleanup.mjs)"
  rm -rf "$TMP"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

on() { case "$(printf '%s' "$1" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')" in true|1|yes) echo on ;; *) echo off ;; esac; }
env_line="$(cd "$ROOT" && docker compose exec -T webapp sh -c 'printf "%s|%s" "${RBAC_IDENTITY_ENABLED:-}" "${RBAC_PERMISSIONS_ENABLED:-}"' 2>/dev/null)"
IDENTITY="$(on "${env_line%%|*}")"
PERMISSIONS="$(on "${env_line##*|}")"
# The permissions switch reads off while the identity switch is off (lib/authz/flags.ts).
[ "$IDENTITY" = off ] && PERMISSIONS=off
echo "== Switches: identity $IDENTITY, permissions $PERMISSIONS =="

echo "== Seeding fixtures =="
declare -A SEED=()
seed_out="$(webapp_node e2e-rbac-seed.mjs)" || { echo "seed failed"; exit 1; }
while IFS= read -r kv; do
  [[ "$kv" =~ ^([A-Z][A-Z0-9_]*)=([A-Za-z0-9@._:-]*)$ ]] && SEED[${BASH_REMATCH[1]}]="${BASH_REMATCH[2]}"
done <<< "$seed_out"
for k in ADMIN_A_EMAIL ADMIN_A_ID ADMIN_B_ID MEMBER_C_EMAIL MEMBER_C_ID MANAGED_ID USERMGR_EMAIL RBAC_PASSWORD; do
  [ -n "${SEED[$k]:-}" ] || { echo "seed output lacks $k"; exit 1; }
done
safe_id() { [[ "$1" =~ ^[A-Za-z0-9_-]+$ ]]; }
for k in ADMIN_A_ID ADMIN_B_ID MEMBER_C_ID MANAGED_ID; do safe_id "${SEED[$k]}" || { echo "unexpected fixture id"; exit 1; }; done
A="${SEED[ADMIN_A_ID]}"; C="${SEED[MEMBER_C_ID]}"

PASS=0; FAIL=0
check() { # name ok-flag [why]
  if [ "$2" = 1 ]; then echo "PASS  $1"; PASS=$((PASS + 1)); else echo "FAIL  $1  ${3:-}"; FAIL=$((FAIL + 1)); fi
}
login() { # email jar -> http code; the body lands in $TMP/body
  printf '{"email":"%s","password":"%s"}' "$1" "${SEED[RBAC_PASSWORD]}" > "$TMP/login.json"
  curl -s -m 30 -o "$TMP/body" -w '%{http_code}' -c "$2" -X POST "$BASE/api/auth/login" \
    -H 'Content-Type: application/json' --data-binary @"$TMP/login.json"
}
call() { # jar method path [json-body] -> http code; body in $TMP/body, headers in $TMP/headers
  local jar="$1" method="$2" path="$3"
  local args=(-s -m 70 -o "$TMP/body" -D "$TMP/headers" -w '%{http_code}' -X "$method" -b "$jar" -c "$jar" -H "Origin: $BASE")
  if [ $# -ge 4 ]; then
    printf '%s' "$4" > "$TMP/req"
    args+=(-H 'Content-Type: application/json' --data-binary @"$TMP/req")
  fi
  curl "${args[@]}" "$BASE$path"
}
field() { # python expression on the JSON body `b` -> printed value (never the whole body)
  python3 -c 'import json,sys; b=json.load(open(sys.argv[1])); print(eval(sys.argv[2]))' "$TMP/body" "$1" 2>/dev/null || true
}
# The act-as body; with `pw` it carries the fixture password, read from the environment so it is
# never on a command line.
act_as_body() { # target reason minutes [pw]
  RBAC_PW="${SEED[RBAC_PASSWORD]}" python3 -c 'import json,os,sys; print(json.dumps({"targetUserId": sys.argv[1], "reason": sys.argv[2], "durationMinutes": int(sys.argv[3]), **({"stepUpPassword": os.environ["RBAC_PW"]} if len(sys.argv) > 4 else {})}))' "$@"
}
ends() { # endedBy -> end rows of rbac-admin-a acting as the member with that cause
  printf "select count(*) from act_as_audit where admin_id = '%s' and target_user_id = '%s' and event = 'end' and ended_by = '%s';\n" "$A" "$C" "$1" | db_sql
}
refused() { # action -> act_as.refused rows by rbac-admin-a on behalf of the member for that action
  printf "select count(*) from audit_log where action = 'act_as.refused' and actor_id = '%s' and on_behalf_of_user_id = '%s' and after->>'action' = '%s';\n" "$A" "$C" "$1" | db_sql
}

ADMIN="$TMP/jar.admin"
code="$(login "${SEED[ADMIN_A_EMAIL]}" "$ADMIN")"
[ "$code" = 200 ] || { echo "FAIL  sign-in as rbac-admin-a answered $code"; exit 1; }

if [ "$PERMISSIONS" = off ]; then
  echo "== Switch off: Phase 2's act-as =="
  code="$(call "$ADMIN" POST /api/auth/act-as "{\"targetUserId\":\"$C\"}")"; ok=0; [ "$code" = 200 ] && ok=1
  check "act as a member with no reason and no password -> $code" "$ok"
  code="$(call "$ADMIN" GET /api/auth/me)"; ok=0; [ "$code" = 200 ] && [ "$(field "'actingAs' in b")" = False ] && ok=1
  check "/api/auth/me has no actingAs -> $code" "$ok"
  code="$(call "$ADMIN" PUT "/api/users/$C" '{"name":"RBAC Member C"}')"; ok=0; [ "$code" = 200 ] && ok=1
  check "the admin's own administration of the account is not refused -> $code" "$ok"
  code="$(call "$ADMIN" DELETE /api/auth/act-as)"; ok=0; [ "$code" = 200 ] && ok=1
  check "stop -> $code" "$ok"
else
  POLICY="$(printf "select impersonation_reason_required || '|' || impersonation_notify_target || '|' || impersonation_max_minutes from instance_settings where id = 'instance';\n" | db_sql)"
  REASON_REQUIRED="${POLICY%%|*}"; rest="${POLICY#*|}"; NOTIFY="${rest%%|*}"; MAX="${rest##*|}"
  [[ "$MAX" =~ ^[0-9]+$ ]] || { echo "FAIL  could not read the instance's impersonation settings"; exit 1; }
  echo "== Policy: reason required $REASON_REQUIRED, notify $NOTIFY, at most $MAX min =="
  MINUTES=15; [ "$MAX" -lt 15 ] && MINUTES="$MAX"

  echo "== Starting: who, why, for how long, with the admin's own password (IM-03, IM-04) =="
  code="$(call "$ADMIN" POST /api/auth/act-as "$(act_as_body "$C" 'rbac live 3.14' "$MINUTES")")"
  ok=0; [ "$code" = 403 ] && [ "$(field "b.get('code')")" = step_up_required ] && ok=1
  check "no password -> $code step_up_required" "$ok"
  if [ "$REASON_REQUIRED" = t ]; then
    code="$(call "$ADMIN" POST /api/auth/act-as "$(act_as_body "$C" '' "$MINUTES" pw)")"
    ok=0; [ "$code" = 400 ] && [ "$(field "b.get('code')")" = reason_required ] && ok=1
    check "no reason while Root requires one -> $code reason_required" "$ok"
  fi
  code="$(call "$ADMIN" POST /api/auth/act-as "$(act_as_body "${SEED[ADMIN_B_ID]}" 'rbac live 3.14' "$MINUTES" pw)")"
  ok=0; [ "$code" = 403 ] && [ "$(field "b.get('code')")" = root_only ] && ok=1
  check "acting as another admin is Root's -> $code root_only" "$ok"
  UM="$TMP/jar.um"
  code="$(login "${SEED[USERMGR_EMAIL]}" "$UM")"
  code="$(call "$UM" POST /api/auth/act-as "$(act_as_body "$C" 'rbac live 3.14' "$MINUTES" pw)")"
  ok=0; [ "$code" = 403 ] && [ "$(field "b.get('permission')")" = users:impersonate ] && ok=1
  check "the User manager profile may not act as anyone -> $code users:impersonate" "$ok"

  code="$(call "$ADMIN" POST /api/auth/act-as "$(act_as_body "$C" 'rbac live 3.14' "$MINUTES" pw)")"
  ok=0; [ "$code" = 200 ] && [ "$(field "b.get('durationMinutes')")" = "$MINUTES" ] && ok=1
  check "rbac-admin-a acts as rbac-member-c for $MINUTES min -> $code" "$ok"
  ok=0; grep -qiE "^set-cookie: redamon-act-as=[^;]+;.*max-age=$((MINUTES * 60))" "$TMP/headers" && ok=1
  check "the cookie lives the chosen duration (Max-Age=$((MINUTES * 60)))" "$ok"
  n="$(printf "select count(*) from act_as_audit where admin_id = '%s' and target_user_id = '%s' and event = 'start' and reason = 'rbac live 3.14' and duration_minutes = %s;\n" "$A" "$C" "$MINUTES" | db_sql)"
  ok=0; [ "$n" = 1 ] && ok=1; check "one start row with the reason and the duration (AU-03)" "$ok"
  code="$(call "$ADMIN" GET /api/auth/me)"
  ok=0; [ "$code" = 200 ] && [ "$(field "b['actingAs']['id'] == '$C' and b['actingAs']['reason'] == 'rbac live 3.14' and b['actingAs']['accountType'] == 'member' and bool(b['actingAs']['endsAt'])")" = True ] && ok=1
  check "/api/auth/me names whom, why and until when (the banner's content, IM-05)" "$ok"
  if [ "$NOTIFY" = t ]; then
    n="$(printf "select count(*) from users, jsonb_array_elements(pending_notices) n where users.id = '%s' and n->>'type' = 'acted_as' and n->>'reason' = 'rbac live 3.14';\n" "$C" | db_sql)"
    ok=0; [ "$n" = 1 ] && ok=1; check "the member has an acted_as notice waiting (IM-10)" "$ok"
  fi

  echo "== Never while acting (IM-08, E2E P3-08) =="
  code="$(call "$ADMIN" PUT "/api/users/$C/password" "{\"newPassword\":\"rbac-live-new-pass-0002\",\"reason\":\"x\"}")"
  ok=0; [ "$code" = 403 ] && [ "$(field "b.get('code')")" = not_while_acting_as ] && [ "$(refused change_password)" = 1 ] && ok=1
  check "changing the member's password -> $code not_while_acting_as, audited" "$ok"
  code="$(call "$ADMIN" PUT "/api/users/$C" '{"email":"rbac-member-c2@e2e.local"}')"
  ok=0; [ "$code" = 403 ] && [ "$(field "b.get('code')")" = not_while_acting_as ] && [ "$(refused change_email)" = 1 ] && ok=1
  check "changing the member's email -> $code not_while_acting_as, audited" "$ok"
  code="$(call "$ADMIN" DELETE "/api/users/$C")"
  ok=0; [ "$code" = 403 ] && [ "$(field "b.get('code')")" = not_while_acting_as ] && [ "$(refused delete_account)" = 1 ] && ok=1
  check "deleting the member -> $code not_while_acting_as, audited" "$ok"

  echo "== Ends, each once with how (IM-11) =="
  code="$(call "$ADMIN" DELETE /api/auth/act-as)"; call "$ADMIN" DELETE /api/auth/act-as >/dev/null
  ok=0; [ "$code" = 200 ] && [ "$(ends stopped)" = 1 ] && ok=1; check "Stop, twice -> one end row, stopped" "$ok"

  # rbac-managed has no password: act-as is how it is run, so 1.6 lets its catalogs be written; the
  # never-list still keeps where its keys and data go with it.
  M="${SEED[MANAGED_ID]}"
  code="$(call "$ADMIN" POST /api/auth/act-as "$(act_as_body "$M" 'rbac live 3.14 managed' "$MINUTES" pw)")"
  ok=0; [ "$code" = 200 ] && ok=1; check "rbac-admin-a acts as the managed account -> $code" "$ok"
  code="$(call "$ADMIN" POST "/api/users/$M/mcp" '{"name":"rbac-live","transport":"http","url":"https://mcp.e2e.test/mcp"}')"
  ok=0; [ "$code" = 403 ] && [ "$(field "b.get('code')")" = not_while_acting_as ] && ok=1
  check "adding an MCP server to it -> $code not_while_acting_as" "$ok"
  code="$(call "$ADMIN" POST "/api/users/$M/llm-providers" '{"providerType":"openai_compatible","name":"rbac-live","baseUrl":"https://llm.e2e.test/v1","apiKey":"sk-rbac-live-fake"}')"
  ok=0; [ "$code" = 403 ] && [ "$(field "b.get('code')")" = not_while_acting_as ] && ok=1
  check "adding an LLM provider to it -> $code not_while_acting_as" "$ok"
  n="$(printf "select count(*) from audit_log where action = 'act_as.refused' and actor_id = '%s' and on_behalf_of_user_id = '%s' and after->>'action' in ('add_mcp_server', 'change_llm_endpoint');\n" "$A" "$M" | db_sql)"
  ok=0; [ "$n" = 2 ] && ok=1; check "both refusals audited" "$ok"
  call "$ADMIN" DELETE /api/auth/act-as >/dev/null

  call "$ADMIN" POST /api/auth/act-as "$(act_as_body "$C" 'rbac live 3.14 b' "$MINUTES" pw)" >/dev/null
  code="$(call "$ADMIN" POST "/api/users/$C/disable" '{}')"; ok=0; [ "$code" = 200 ] && ok=1
  check "the member is disabled while acted as -> $code" "$ok"
  code="$(call "$ADMIN" GET /api/auth/me)"
  ok=0; [ "$code" = 200 ] && [ "$(field "b.get('actingAs')")" = None ] && [ "$(ends target_disabled)" = 1 ] && ok=1
  check "the next request runs as the admin; one end row, target_disabled" "$ok"
  code="$(call "$ADMIN" POST "/api/users/$C/enable" '{}')"; ok=0; [ "$code" = 200 ] && ok=1
  check "the member is enabled again -> $code" "$ok"

  call "$ADMIN" POST /api/auth/act-as "$(act_as_body "$C" 'rbac live 3.14 c' "$MINUTES" pw)" >/dev/null
  cp "$ADMIN" "$TMP/jar.before-logout"
  code="$(call "$ADMIN" POST /api/auth/logout '{}')"
  ok=0; [ "$code" = 200 ] && [ "$(ends logout)" = 1 ] && ok=1; check "signing out -> one end row, logout" "$ok"

  # A copy of the act-as cookie saved before its impersonation ended (step 3.14 review, finding 1):
  # the token names its start row, so it acts as nobody once the log shows the end.
  echo "== A saved act-as cookie replayed after the end acts as nobody =="
  acting_as() { # jar -> the id /api/auth/me says the admin acts as, or None
    call "$1" GET /api/auth/me >/dev/null; field "(b.get('actingAs') or {}).get('id')"
  }
  code="$(login "${SEED[ADMIN_A_EMAIL]}" "$ADMIN")"
  grep 'redamon-act-as' "$TMP/jar.before-logout" >> "$ADMIN" || true
  ok=0; [ "$code" = 200 ] && [ "$(acting_as "$ADMIN")" = None ] && [ "$(ends logout)" = 1 ] && ok=1
  check "after signing out and in again (the version did not move): the old cookie acts as nobody" "$ok"
  end_rows() { printf "select count(*) from act_as_audit where admin_id = '%s' and target_user_id = '%s' and event = 'end';\n" "$A" "$C" | db_sql; }
  call "$ADMIN" POST /api/auth/act-as "$(act_as_body "$C" 'rbac live 3.14 d' "$MINUTES" pw)" >/dev/null
  cp "$ADMIN" "$TMP/jar.first"
  call "$ADMIN" POST /api/auth/act-as "$(act_as_body "$C" 'rbac live 3.14 e' "$MINUTES" pw)" >/dev/null
  before="$(end_rows)"
  ok=0; [ "$(acting_as "$TMP/jar.first")" = None ] && [ "$(acting_as "$ADMIN")" = "$C" ] && ok=1
  check "after a new act-as of the same member: only the newest cookie acts" "$ok"
  ok=0; [ -n "$before" ] && [ "$(end_rows)" = "$before" ] && ok=1; check "that replay wrote no end row" "$ok"
  cp "$ADMIN" "$TMP/jar.second"
  code="$(call "$ADMIN" DELETE /api/auth/act-as)"
  before="$(end_rows)"
  ok=0; [ "$code" = 200 ] && [ "$(acting_as "$TMP/jar.second")" = None ] && ok=1
  check "after Stop: the saved cookie acts as nobody" "$ok"
  ok=0; [ -n "$before" ] && [ "$(end_rows)" = "$before" ] && ok=1; check "that replay wrote no end row" "$ok"

  if [ "$NOTIFY" = t ]; then
    code="$(login "${SEED[MEMBER_C_EMAIL]}" "$TMP/jar.c")"
    ok=0; [ "$code" = 200 ] && [ "$(field "any(n.get('type') == 'acted_as' and n.get('reason') == 'rbac live 3.14' for n in b.get('notices', []))")" = True ] && ok=1
    check "the member's next sign-in shows who acted as it and why -> $code" "$ok"
  fi
fi

echo
echo "== RESULT: $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
