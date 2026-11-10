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
#           <actor>_as_<user> (signed in as <actor>, then POST /api/auth/act-as <user>,
#           e.g. admin_a_as_member_a; <user> may also be "managed")
#   body    '-' for none, else sent as application/json
#   expect  status codes joined by '|', then optional ';has=<text>' / ';lacks=<text>'
#           checks on the response body (literal text)
#   tags    space-separated: hole:<finding> (today's behaviour a later phase closes),
#           req:<id>, probe:<how>, superseded-by:<file> (kept, never run again)
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
# config on stdin, never echoed and never on a command line.
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
    admin_a|admin_b|member_a|member_b|member_c|managed) echo "${1^^}" ;;
    *) return 1 ;;
  esac
}
login_into() { # user-key jar -> http code
  local email="${SEED[${1}_EMAIL]:-}"
  printf '{"email":"%s","password":"%s"}' "$email" "${SEED[RBAC_PASSWORD]}" > "$TMP/login.json"
  curl -s -m 30 -o /dev/null -w '%{http_code}' -c "$2" -X POST "$BASE/api/auth/login" \
    -H 'Content-Type: application/json' --data-binary @"$TMP/login.json"
}
actor_jar() { # actor -> sets JAR[actor] or ACTOR_ERR[actor]
  local actor="$1" who target key tkey code jar
  [ -n "${JAR[$actor]:-}" ] || [ -n "${ACTOR_ERR[$actor]:-}" ] && return
  jar="$TMP/jar.$actor"
  if [[ "$actor" == *_as_* ]]; then
    who="${actor%%_as_*}"; target="${actor#*_as_}"
    key="$(user_key "$who")" && tkey="$(user_key "$target")" \
      || { ACTOR_ERR[$actor]="unknown actor"; return; }
    code="$(login_into "$key" "$jar")"
    [ "$code" = 200 ] || { ACTOR_ERR[$actor]="login as $who answered $code"; return; }
    code="$(curl -s -m 30 -o /dev/null -w '%{http_code}' -b "$jar" -c "$jar" -X POST "$BASE/api/auth/act-as" \
      -H 'Content-Type: application/json' -H "Origin: $BASE" \
      --data-binary "{\"targetUserId\":\"${SEED[${tkey}_ID]}\"}")"
    [ "$code" = 200 ] || { ACTOR_ERR[$actor]="act-as $target answered $code"; return; }
  else
    key="$(user_key "$actor")" || { ACTOR_ERR[$actor]="unknown actor"; return; }
    code="$(login_into "$key" "$jar")"
    [ "$code" = 200 ] || { ACTOR_ERR[$actor]="login answered $code"; return; }
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
  url_path="$(subst "$path")"
  expect_s="$(subst "$expect")"
  if [[ "$url_path$expect_s" == *'${'* ]] || { [ "$body" != - ] && [[ "$(subst "$body")" == *'${'* ]]; }; then
    echo "FAIL  $label  unresolved \${...} in the row  [$tags]"; FAIL=$((FAIL + 1)); continue
  fi

  args=(-s -m "$REQUEST_TIMEOUT" -o "$TMP/body" -w '%{http_code}' -X "$method")
  # A browser sends Origin on every non-GET request; the same-origin guards expect it.
  [ "$method" = GET ] || [ "$method" = HEAD ] || args+=(-H "Origin: $BASE")
  if [ "$body" != - ]; then
    subst "$body" > "$TMP/req"
    args+=(-H 'Content-Type: application/json' --data-binary @"$TMP/req")
  fi
  : > "$TMP/body"
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
      # Read-only jar: a row's Set-Cookie never changes the actor for the next row.
      code="$(curl "${args[@]}" -b "${JAR[$actor]}" "$BASE$url_path")" ;;
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
