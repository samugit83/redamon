#!/usr/bin/env bash
#
# Live RBAC route matrix: who may call which route, run against the LIVE stack.
#
# It is the behaviour oracle of the RBAC evolution: baseline.tsv records what every
# seeded account gets today, so a later change that moves an owner's answer shows
# up as a FAIL. Each later phase adds its own file (p1.tsv, ...).
#
# Row format (tests/fixtures/rbac_matrix/*.tsv, one row per line, '#' comments):
#   id <TAB> since <TAB> actor <TAB> method <TAB> path <TAB> body <TAB> expect <TAB> tags
#   since   the step that recorded the row (0.5 = the untouched baseline)
#   actor   anon | internal | scanner | admin_a | admin_b | member_a | member_b |
#           member_c (owner_a / owner_b are aliases of member_a / member_b) |
#           operator | analyst | noaccess (members on the built-in sets Recon operator,
#           Read-only analyst and No access, each owning a project) | usermgr (an admin on the
#           User manager profile); the sets count only with RBAC_PERMISSIONS_ENABLED on |
#           viewer | viewer_raw | viewer_tmp (members holding a Read share of member_c's PSHARED,
#           viewer_raw with Raw data & files; viewer_tmp's is the one p4.tsv revokes, grants and
#           leaves; the shares count only with sharing in force) |
#           <actor>_as_<user> (signed in as <actor>, then POST /api/auth/act-as <user>,
#           e.g. admin_a_as_member_a; <user> may also be "managed") |
#           <admin>_demoted, <admin>_as_<user>_demoted (admin_a or admin_b signed in, and
#           acting as <user>, while an admin; the account is demoted to standard by SQL
#           just before the row's request and restored right after it, the cookies kept) |
#           deleted (the seed's throwaway account, signed in, then deleted by SQL; its
#           still-valid cookie is kept) |
#           <user>_revoked (admin_a, admin_b, member_a, member_b or member_c signed in;
#           the account's session version is raised by SQL just before the row's
#           request and put back right after it, the cookie kept: a cookie of an
#           older version)
#   body    '-' for none, else sent as application/json
#   expect  status codes joined by '|', then optional ';has=<text>' / ';lacks=<text>'
#           checks on the response body (literal text) and ';hdr=<text>' /
#           ';nohdr=<text>' on its headers (literal text, any case)
#   tags    space-separated: hole:<finding> (today's behaviour a later phase closes),
#           req:<id>, probe:<how>, superseded-by:<file> (kept, never run again),
#           identity:on | identity:off (run only while the webapp's RBAC_IDENTITY_ENABLED
#           is so, read from the container; SKIP otherwise), permissions:on | permissions:off
#           (the same for RBAC_PERMISSIONS_ENABLED, which reads off while the identity
#           switch is off, as in the webapp), sharing:on | sharing:off (whether sharing
#           is in force: RBAC_SHARING_ENABLED on, which reads off while the permissions
#           switch is off, AND Root's policy instance_settings.sharing_policy enabled, as
#           sharingPolicy.ts reads it; the policy is read by psql once, only when the
#           switch is on and a selected row is so tagged, and a policy that cannot be read
#           fails those rows),
#           origin:<url> (the Origin header
#           the row sends instead of the webapp's own, e.g. a page of another site)
#   path, body and expect take ${KEY} from the seed output (KEY=VALUE lines).
#
# Rows never start a scan or an agent run. A row that must prove "allowed" without
# a side effect sends what the route refuses AFTER its authorization check (400,
# 422), so a refused caller still gets 401, 403 or 404.
#
# Fixtures are synthetic (webapp/scripts/e2e-rbac-seed.mjs: rbac-*@e2e.local,
# rbac-* projects, rbac.test) and always removed (e2e-rbac-cleanup.mjs), even on
# Ctrl-C. Both scripts are fed to the webapp container on stdin, so they work
# against an image built before they existed. Response bodies are never printed:
# some rows read secrets on purpose. INTERNAL_API_KEY and SCANNER_API_KEY are read
# from .env for the internal and scanner rows only, straight into curl's header
# config on stdin, never echoed and never on a command line. The demoted, deleted and
# revoked actors change the users table through psql in the postgres container (SQL on
# stdin); an interrupted run leaves nothing behind, because the cleanup deletes every
# fixture account and the next seed resets each one's role. With RBAC_IDENTITY_ENABLED
# on, a webapp process keeps an account it read for RBAC_AUTHZ_CACHE_MS, so after each
# such change the runner waits that long (read from the webapp container) before the
# next request: a change made by SQL is a change made by another copy.
#
# Needs the stack up (webapp on :3000); prints SKIP and exits 0 when it is not, so
# it never fails a gate. Live suites (*_live.sh) are not part of the gate.
#
# Run:  bash tests/rbac_matrix_live.sh baseline           (one or more files, or all)
#       RBAC_MATRIX_ROWS='^bl-users-' bash tests/rbac_matrix_live.sh baseline   (id regex)
#       BASE_URL=https://redamon.example bash tests/rbac_matrix_live.sh all
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FIXTURES="$ROOT/tests/fixtures/rbac_matrix"
BASE="${BASE_URL:-http://localhost:3000}"
SEED_FILE="$ROOT/testing/e2e/.rbac-seed.env"
ROW_FILTER="${RBAC_MATRIX_ROWS:-}"
REQUEST_TIMEOUT=70

usage() {
  echo "usage: bash tests/rbac_matrix_live.sh <file>... | all" >&2
  echo "  files: $(cd "$FIXTURES" 2>/dev/null && ls -- *.tsv 2>/dev/null | sed 's/\.tsv$//' | tr '\n' ' ')" >&2
  exit 2
}

[ $# -ge 1 ] || usage
FILES=()
for arg in "$@"; do
  if [ "$arg" = all ]; then
    [ -f "$FIXTURES/baseline.tsv" ] && FILES+=("$FIXTURES/baseline.tsv")
    while IFS= read -r f; do
      [ "$(basename "$f")" = baseline.tsv ] || FILES+=("$f")
    done < <(find "$FIXTURES" -maxdepth 1 -name '*.tsv' | LC_ALL=C sort)
  else
    [ -f "$FIXTURES/$arg.tsv" ] || { echo "unknown matrix file: $arg" >&2; usage; }
    FILES+=("$FIXTURES/$arg.tsv")
  fi
done

# ---- load and lint the rows before touching the stack ------------------------
ROWS=()
declare -A SEEN_ID=()
lint_errors=0
for f in "${FILES[@]}"; do
  n=0
  while IFS= read -r line || [ -n "$line" ]; do
    n=$((n + 1))
    [[ -z "${line//[[:space:]]/}" || "$line" == \#* ]] && continue
    IFS=$'\t' read -r -a cols <<< "$line"
    if [ "${#cols[@]}" -ne 8 ]; then
      echo "LINT $(basename "$f"):$n has ${#cols[@]} columns, expected 8" >&2
      lint_errors=$((lint_errors + 1)); continue
    fi
    id="${cols[0]}"
    if [ -n "${SEEN_ID[$id]:-}" ]; then
      echo "LINT $(basename "$f"):$n duplicate id $id (first at ${SEEN_ID[$id]})" >&2
      lint_errors=$((lint_errors + 1)); continue
    fi
    SEEN_ID[$id]="$(basename "$f"):$n"
    if [ -n "$ROW_FILTER" ] && ! [[ "$id" =~ $ROW_FILTER ]]; then continue; fi
    ROWS+=("$line")
  done < "$f"
done
[ "$lint_errors" -eq 0 ] || { echo "== $lint_errors malformed row(s); nothing was run ==" >&2; exit 2; }
[ "${#ROWS[@]}" -gt 0 ] || { echo "no rows selected" >&2; exit 2; }

# ---- self-skip when the stack is down ----------------------------------------
health="$(curl -s -m 5 -o /dev/null -w '%{http_code}' "$BASE/api/health" 2>/dev/null || true)"
if [ "$health" != 200 ]; then
  echo "SKIP: RedAmon webapp not answering at $BASE/api/health (got ${health:-nothing})"
  exit 0
fi
if ! (cd "$ROOT" && docker compose ps --status running -q webapp 2>/dev/null | grep -q .); then
  echo "SKIP: no running webapp container to seed fixtures into (docker compose ps webapp)"
  exit 0
fi

TMP="$(mktemp -d)"
CLEANED_UP=0
webapp_node() { # script: run a fixture script inside the webapp container, read from stdin
  (cd "$ROOT" && docker compose exec -T -w /app webapp node --input-type=module -) < "$ROOT/webapp/scripts/$1"
}
cleanup() {
  [ "$CLEANED_UP" -eq 1 ] && return
  CLEANED_UP=1
  echo "== Cleaning up fixtures =="
  webapp_node e2e-rbac-cleanup.mjs | sed 's/^/  /' || echo "  cleanup failed: rerun it by hand (see e2e-rbac-cleanup.mjs)"
  rm -f "$SEED_FILE"
  rm -rf "$TMP"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# ---- seed ---------------------------------------------------------------------
echo "== Seeding fixtures =="
declare -A SEED=()
seed_out="$(webapp_node e2e-rbac-seed.mjs)" || { echo "seed failed"; exit 1; }
while IFS= read -r kv; do
  [ -z "$kv" ] && continue
  if [[ "$kv" =~ ^([A-Z][A-Z0-9_]*)=([A-Za-z0-9@._:-]*)$ ]]; then
    SEED[${BASH_REMATCH[1]}]="${BASH_REMATCH[2]}"
  else
    echo "unexpected seed output line (not KEY=VALUE)"; exit 1
  fi
done <<< "$seed_out"
for k in PA_ID PB_ID MEMBER_A_ID MEMBER_B_ID ADMIN_A_ID RBAC_PASSWORD; do
  [ -n "${SEED[$k]:-}" ] || { echo "seed output lacks $k"; exit 1; }
done
( umask 077; printf '%s\n' "$seed_out" > "$SEED_FILE" )
echo "  ${#SEED[@]} values (written to ${SEED_FILE#"$ROOT"/})"

# ${KEY} -> seed value; an unknown key is left in place and fails the row.
subst() {
  local s="$1" k
  for k in "${!SEED[@]}"; do s="${s//\$\{$k\}/${SEED[$k]}}"; done
  printf '%s' "$s"
}

# ---- actors -------------------------------------------------------------------
declare -A JAR=()
declare -A ACTOR_ERR=()
user_key() { # actor name -> seed key prefix (MEMBER_A, ...)
  case "$1" in
    owner_a) echo MEMBER_A ;; owner_b) echo MEMBER_B ;;
    admin_a|admin_b|member_a|member_b|member_c|managed|deleted|operator|analyst|noaccess|usermgr|viewer|viewer_raw|viewer_tmp) echo "${1^^}" ;;
    *) return 1 ;;
  esac
}
login_into() { # user-key jar -> http code
  local email="${SEED[${1}_EMAIL]:-}"
  printf '{"email":"%s","password":"%s"}' "$email" "${SEED[RBAC_PASSWORD]}" > "$TMP/login.json"
  curl -s -m 30 -o /dev/null -w '%{http_code}' -c "$2" -X POST "$BASE/api/auth/login" \
    -H 'Content-Type: application/json' --data-binary @"$TMP/login.json"
}
sign_in() { # actor jar -> fills the jar; prints why and returns 1 when it cannot
  local actor="$1" jar="$2" who target key tkey code
  if [[ "$actor" == *_as_* ]]; then
    who="${actor%%_as_*}"; target="${actor#*_as_}"
    key="$(user_key "$who")" && tkey="$(user_key "$target")" || { echo "unknown actor"; return 1; }
    code="$(login_into "$key" "$jar")"
    [ "$code" = 200 ] || { echo "login as $who answered $code"; return 1; }
    # The reason, duration and own password RBAC_PERMISSIONS_ENABLED asks (step 3.14); ignored with it
    # off. In a file, so the password is never on a command line.
    printf '{"targetUserId":"%s","reason":"rbac matrix row","durationMinutes":15,"stepUpPassword":"%s"}' \
      "${SEED[${tkey}_ID]}" "${SEED[RBAC_PASSWORD]}" > "$TMP/actas.json"
    code="$(curl -s -m 30 -o /dev/null -w '%{http_code}' -b "$jar" -c "$jar" -X POST "$BASE/api/auth/act-as" \
      -H 'Content-Type: application/json' -H "Origin: $BASE" \
      --data-binary @"$TMP/actas.json")"
    [ "$code" = 200 ] || { echo "act-as $target answered $code"; return 1; }
  else
    key="$(user_key "$actor")" || { echo "unknown actor"; return 1; }
    code="$(login_into "$key" "$jar")"
    [ "$code" = 200 ] || { echo "login answered $code"; return 1; }
  fi
}
demoted_user_id() { # <admin>[_as_<user>]_demoted -> the seeded id of <admin>
  local who="${1%_demoted}"; who="${who%%_as_*}"
  case "$who" in admin_a|admin_b) printf '%s' "${SEED[$(user_key "$who")_ID]:-}" ;; *) return 1 ;; esac
}
db_sql() { # SQL on stdin -> psql in the postgres container; prints only the returned values
  (cd "$ROOT" && docker compose exec -T postgres \
    sh -c 'psql -X -q -t -A -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB"') 2>/dev/null
}
safe_id() { [[ "$1" =~ ^[A-Za-z0-9_-]+$ ]]; }
set_role() { # user-id role -> 0 when exactly that account now has the role
  safe_id "$1" || return 1
  [ "$(printf "update users set role = '%s' where id = '%s' returning id;\n" "$2" "$1" | db_sql)" = "$1" ] && cache_settle
}
delete_account() { # user-id -> 0 when exactly that account was deleted
  safe_id "$1" || return 1
  [ "$(printf "delete from users where id = '%s' returning id;\n" "$1" | db_sql)" = "$1" ] && cache_settle
}
revoked_user_id() { # <user>_revoked -> the seeded id of <user>
  local who="${1%_revoked}"
  case "$who" in admin_a|admin_b|member_a|member_b|member_c) printf '%s' "${SEED[$(user_key "$who")_ID]:-}" ;; *) return 1 ;; esac
}
shift_session_version() { # user-id +1|-1 -> 0 when exactly that account's version moved
  safe_id "$1" || return 1
  [ "$(printf "update users set session_version = session_version %s 1 where id = '%s' and session_version %s returning id;\n" \
    "${2:0:1}" "$1" "$([ "$2" = -1 ] && echo '> 0' || echo '>= 0')" | db_sql)" = "$1" ] && cache_settle
}
IDENTITY=""; PERMISSIONS=""; SHARING=""; CACHE_MS=""
switch_value() { # raw env value -> on|off, parsed as webapp/src/lib/authz/flags.ts does
  case "$(printf '%s' "$1" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')" in true|1|yes) echo on ;; *) echo off ;; esac
}
read_switches() { # the webapp's switches (IDENTITY, PERMISSIONS, SHARING = on|off) and cache bound, read once
  [ -n "$IDENTITY" ] && return
  local env rest
  env="$(cd "$ROOT" && docker compose exec -T webapp sh -c \
    'printf "%s|%s|%s|%s" "${RBAC_IDENTITY_ENABLED:-}" "${RBAC_PERMISSIONS_ENABLED:-}" "${RBAC_SHARING_ENABLED:-}" "${RBAC_AUTHZ_CACHE_MS:-}"' 2>/dev/null)"
  IDENTITY="$(switch_value "${env%%|*}")"; rest="${env#*|}"
  PERMISSIONS="$(switch_value "${rest%%|*}")"; rest="${rest#*|}"
  SHARING="$(switch_value "${rest%%|*}")"
  # flags.ts: each switch requires the one before it and reads off without it.
  [ "$IDENTITY" = on ] || PERMISSIONS=off
  [ "$PERMISSIONS" = on ] || SHARING=off
  CACHE_MS="${rest#*|}"; CACHE_MS="${CACHE_MS//[[:space:]]/}"
}
# parseSharingPolicy (webapp/src/lib/authz/sharingPolicy.ts) in SQL: `enabled` true and every
# known setting valid, or the whole policy reads as the defaults (off); no row reads as the
# defaults too. Always one row, so an empty answer means the read failed.
SHARING_POLICY_SQL="select coalesce((select case when jsonb_typeof(p) = 'object'
    and p->'enabled' = 'true'::jsonb
    and (not p ? 'maxLevel' or p->'maxLevel' in ('\"read\"'::jsonb, '\"write\"'::jsonb))
    and (not p ? 'membersMayGrantExploit' or jsonb_typeof(p->'membersMayGrantExploit') = 'boolean')
    and (not p ? 'adminsSeeAllShares' or jsonb_typeof(p->'adminsSeeAllShares') = 'boolean')
    and (not p ? 'defaultExpiryDays' or jsonb_typeof(p->'defaultExpiryDays') = 'null'
         or coalesce(case when jsonb_typeof(p->'defaultExpiryDays') = 'number'
              then (p->>'defaultExpiryDays')::numeric between 1 and 3650
                   and (p->>'defaultExpiryDays')::numeric % 1 = 0 end, false))
  then 'on' else 'off' end
  from (select sharing_policy::jsonb as p from instance_settings where id = 'instance') s), 'off');"
SHARING_POLICY=""
read_sharing_policy() { # Root's sharing policy -> SHARING_POLICY = on | off | unknown, read once
  [ -n "$SHARING_POLICY" ] && return
  case "$(printf '%s\n' "$SHARING_POLICY_SQL" | db_sql)" in
    on) SHARING_POLICY=on ;;
    off) SHARING_POLICY=off ;;
    *) SHARING_POLICY=unknown ;;
  esac
}
CACHE_SETTLE=""
cache_settle() { # waits out the webapp's account cache when the identity switch is on
  if [ -z "$CACHE_SETTLE" ]; then
    local ms
    read_switches
    ms="$CACHE_MS"
    if [ "$IDENTITY" = on ]; then
      [[ "$ms" =~ ^[0-9]+$ ]] || ms=5000
      [ "$ms" -gt 60000 ] && ms=60000
      CACHE_SETTLE=$(( (ms + 999) / 1000 + 1 ))
      echo "== identity switch on: each account change by SQL waits ${CACHE_SETTLE}s for the webapp's account cache =="
    else
      CACHE_SETTLE=0
    fi
  fi
  [ "$CACHE_SETTLE" -eq 0 ] || sleep "$CACHE_SETTLE"
}
actor_jar() { # actor -> sets JAR[actor] or ACTOR_ERR[actor]
  local actor="$1" base="$1" jar err
  [ -n "${JAR[$actor]:-}" ] || [ -n "${ACTOR_ERR[$actor]:-}" ] && return
  jar="$TMP/jar.$actor"
  if [[ "$actor" == *_demoted ]]; then
    demoted_user_id "$actor" >/dev/null || { ACTOR_ERR[$actor]="only admin_a or admin_b can be demoted"; return; }
    base="${actor%_demoted}"
  elif [[ "$actor" == *_revoked ]]; then
    revoked_user_id "$actor" >/dev/null || { ACTOR_ERR[$actor]="only a plain seeded account can be revoked"; return; }
    base="${actor%_revoked}"
  fi
  err="$(sign_in "$base" "$jar")" || { ACTOR_ERR[$actor]="$err"; return; }
  if [ "$actor" = deleted ] && ! delete_account "${SEED[DELETED_ID]:-}"; then
    ACTOR_ERR[$actor]="could not delete the throwaway account by SQL"; return
  fi
  JAR[$actor]="$jar"
}
env_key() { # NAME -> value from the repo .env (never printed)
  grep -m1 "^$1=" "$ROOT/.env" 2>/dev/null | cut -d= -f2- | sed -e 's/^["'\'']//' -e 's/["'\'']$//'
}

# ---- rows ---------------------------------------------------------------------
PASS=0; FAIL=0; SKIPPED=0
echo "== Running ${#ROWS[@]} row(s) against $BASE =="
for line in "${ROWS[@]}"; do
  IFS=$'\t' read -r id since actor method path body expect tags <<< "$line"
  label="$id  $actor $method $path"
  if [[ " $tags " == *" superseded-by:"* ]]; then
    echo "SKIP  $label  [$tags]"; SKIPPED=$((SKIPPED + 1)); continue
  fi
  off_switch=""; policy_unread=""
  for sw in identity permissions sharing; do
    [[ " $tags " =~ \ $sw:(on|off)\  ]] || continue
    want="${BASH_REMATCH[1]}"
    read_switches
    why="$sw switch"
    case "$sw" in
      identity) state="$IDENTITY" ;;
      permissions) state="$PERMISSIONS" ;;
      *) state="$SHARING"
         # The switch alone is not sharing in force: with Root's policy still `{}` the
         # webapp answers owner-only, so the sharing:off rows must run.
         if [ "$state" = on ]; then
           read_sharing_policy
           [ "$SHARING_POLICY" = unknown ] && { policy_unread=1; break; }
           [ "$SHARING_POLICY" = off ] && { state=off; why="sharing switch on, Root's policy"; }
         fi ;;
    esac
    if [ "$want" != "$state" ]; then off_switch="$why $state"; break; fi
  done
  if [ -n "$policy_unread" ]; then
    echo "FAIL  $label  could not read Root's sharing policy (psql in the postgres container)  [$tags]"
    FAIL=$((FAIL + 1)); continue
  fi
  if [ -n "$off_switch" ]; then
    echo "SKIP  $label  ($off_switch)  [$tags]"; SKIPPED=$((SKIPPED + 1)); continue
  fi
  url_path="$(subst "$path")"
  expect_s="$(subst "$expect")"
  if [[ "$url_path$expect_s" == *'${'* ]] || { [ "$body" != - ] && [[ "$(subst "$body")" == *'${'* ]]; }; then
    echo "FAIL  $label  unresolved \${...} in the row  [$tags]"; FAIL=$((FAIL + 1)); continue
  fi

  args=(-s -m "$REQUEST_TIMEOUT" -o "$TMP/body" -D "$TMP/headers" -w '%{http_code}' -X "$method")
  # A browser sends Origin on every non-GET request; the same-origin guards expect it.
  origin="$BASE"
  [[ " $tags " =~ \ origin:([^ ]+)\  ]] && origin="${BASH_REMATCH[1]}"
  [ "$method" = GET ] || [ "$method" = HEAD ] || args+=(-H "Origin: $origin")
  if [ "$body" != - ]; then
    subst "$body" > "$TMP/req"
    args+=(-H 'Content-Type: application/json' --data-binary @"$TMP/req")
  fi
  : > "$TMP/body"; : > "$TMP/headers"
  case "$actor" in
    anon)
      code="$(curl "${args[@]}" "$BASE$url_path")" ;;
    internal|scanner)
      name=INTERNAL_API_KEY; [ "$actor" = scanner ] && name=SCANNER_API_KEY
      key="$(env_key "$name")"
      if [ -z "$key" ]; then
        echo "FAIL  $label  $name is not set in .env  [$tags]"; FAIL=$((FAIL + 1)); continue
      fi
      code="$(printf 'header = "X-Internal-Key: %s"\n' "$key" | curl -K - "${args[@]}" "$BASE$url_path")"
      key="" ;;
    *)
      actor_jar "$actor"
      if [ -n "${ACTOR_ERR[$actor]:-}" ]; then
        echo "FAIL  $label  actor not ready: ${ACTOR_ERR[$actor]}  [$tags]"; FAIL=$((FAIL + 1)); continue
      fi
      demoted=""; revoked=""
      if [[ "$actor" == *_demoted ]]; then
        demoted="$(demoted_user_id "$actor")"
        if ! set_role "$demoted" standard; then
          echo "FAIL  $label  could not demote the account by SQL  [$tags]"; FAIL=$((FAIL + 1)); continue
        fi
      elif [[ "$actor" == *_revoked ]]; then
        revoked="$(revoked_user_id "$actor")"
        if ! shift_session_version "$revoked" +1; then
          echo "FAIL  $label  could not raise the session version by SQL  [$tags]"; FAIL=$((FAIL + 1)); continue
        fi
      fi
      # Read-only jar: a row's Set-Cookie never changes the actor for the next row.
      code="$(curl "${args[@]}" -b "${JAR[$actor]}" "$BASE$url_path")"
      if [ -n "$demoted" ] && ! set_role "$demoted" admin; then
        echo "FAIL  $label  could not restore the demoted account to admin: later rows are unreliable  [$tags]"
        FAIL=$((FAIL + 1)); continue
      fi
      if [ -n "$revoked" ] && ! shift_session_version "$revoked" -1; then
        echo "FAIL  $label  could not put the session version back: later rows are unreliable  [$tags]"
        FAIL=$((FAIL + 1)); continue
      fi ;;
  esac

  codes="${expect_s%%;*}"
  why=""
  if [[ "|$codes|" != *"|$code|"* ]]; then
    why="expected $codes, got $code"
  else
    checks="${expect#"${expect%%;*}"}"
    while [ -n "$checks" ]; do
      checks="${checks#;}"
      check="${checks%%;*}"; checks="${checks#"$check"}"
      text="$(subst "${check#*=}")"
      case "$check" in
        has=*) grep -qF -- "$text" "$TMP/body" || why="body lacks ${check#*=}" ;;
        hdr=*) grep -qiF -- "$text" "$TMP/headers" || why="headers lack ${check#*=}" ;;
        nohdr=*) grep -qiF -- "$text" "$TMP/headers" && why="headers contain ${check#*=}" ;;
        lacks=*) grep -qF -- "$text" "$TMP/body" && why="body contains ${check#*=}" ;;
        *) why="unknown check '$check'" ;;
      esac
      [ -n "$why" ] && break
    done
  fi
  if [ -z "$why" ]; then
    echo "PASS  $label -> $code  [$tags]"; PASS=$((PASS + 1))
  else
    echo "FAIL  $label  $why  [$tags]"; FAIL=$((FAIL + 1))
  fi
done

echo
echo "== RESULT: $PASS passed, $FAIL failed, $SKIPPED skipped =="
[ "$FAIL" -eq 0 ]
