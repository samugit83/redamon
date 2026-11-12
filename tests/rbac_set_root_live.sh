#!/usr/bin/env bash
#
# Live check of the host Root commands (RBAC step 2.7, ID-08 / ID-09) on a DISPOSABLE
# instance: the upgrade harness's `serve several_admins` (tests/rbac_upgrade_live.sh: its own
# Postgres and the image's webapp on 127.0.0.1:3901, fake secrets). Since step 2.5 the boot
# chooses a Root on every instance with an admin, so on the running stack Root is a real
# account and moving it would sign that account out: the running stack is never touched.
#
# The host commands are redamon.sh's own functions (cmd_set_root, _confirm_root), sourced,
# with `docker compose exec webapp` routed to the disposable webapp container by a `docker`
# shim that refuses every other compose call. On top of the scenario (upg-admin-c chosen
# Root at boot, automatic) it seeds two admins and checks that `set-root` moves Root to the
# first and on to the second (each move signing out the new Root and the one it replaced,
# and revoking the new Root's MCP tokens), check-root.mjs reports it, a second set-root of
# the same account changes nothing, and update's _confirm_root (identity switch on in a
# scratch .env) keeps an unconfirmed Root without ADMIN_EMAIL and confirms it, signing
# nobody out, when ADMIN_EMAIL names it.
#
# The instance runs with RBAC_IDENTITY_ENABLED from the caller's environment (default off:
# set-root works either way). Fixtures are synthetic (rbac-step27-a/b@e2e.local, fake
# passphrases) and go with the instance.
#
# Needs Docker and the images the harness needs (redamon-webapp:latest built from a commit
# that has step 2.7, postgres:16-alpine, redamon-webapp:rbac-7.7.2); SKIPs (exit 0) without
# them or when port 3901 is taken. As a *_live.sh it is never in the gate.
#
# Run:  bash tests/rbac_set_root_live.sh
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 1
PORT=3901
BASE="http://127.0.0.1:$PORT"
IMAGE="${RBAC_UPGRADE_IMAGE:-redamon-webapp:latest}"
SWITCH="${RBAC_IDENTITY_ENABLED:-false}"
A_EMAIL='rbac-step27-a@e2e.local'
B_EMAIL='rbac-step27-b@e2e.local'

pass=0; fail=0
ok()  { echo "  PASS  $1"; pass=$((pass + 1)); }
bad() { echo "  FAIL  $1"; echo "        $2"; fail=$((fail + 1)); }
expect_eq()  { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "expected '$2' got '$3'"; fi; }
expect_has() { case "$3" in *"$2"*) ok "$1" ;; *) bad "$1" "output lacks '$2'" ;; esac; }

skip() { echo "SKIP: $1"; exit 0; }
command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1 || skip "docker unavailable"
docker image inspect "$IMAGE" >/dev/null 2>&1 || skip "image $IMAGE missing"
docker run --rm --entrypoint sh "$IMAGE" -c 'test -f scripts/set-root.mjs && test -f scripts/check-root.mjs' \
  >/dev/null 2>&1 || skip "image $IMAGE predates step 2.7 (no scripts/set-root.mjs)"
code="$(curl -s -m 2 -o /dev/null -w '%{http_code}' "$BASE/api/health" 2>/dev/null || true)"
[ "$code" = 000 ] || skip "port $PORT already answers ($code): stop that server first"

WORK="$(mktemp -d)"
HPID=""
stop_serve() {
  [ -n "$HPID" ] || return 0
  pkill -TERM -P "$HPID" sleep 2>/dev/null
  kill -TERM "$HPID" 2>/dev/null
  wait "$HPID" 2>/dev/null
  HPID=""
}
trap 'stop_serve; rm -rf "$WORK"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

LOG="$WORK/serve.log"
RBAC_IDENTITY_ENABLED=$SWITCH bash "$ROOT/tests/rbac_upgrade_live.sh" serve several_admins > "$LOG" 2>&1 &
HPID=$!
echo "== booting the disposable instance (scenario several_admins, identity switch $SWITCH)"
for _ in $(seq 1 600); do
  grep -q '^== Serving scenario' "$LOG" && break
  kill -0 "$HPID" 2>/dev/null || { echo "the harness stopped:"; tail -n 30 "$LOG"; exit 1; }
  grep -q '^SKIP' "$LOG" && { cat "$LOG"; exit 0; }
  sleep 1
done
grep -q '^== Serving scenario' "$LOG" || { echo "the instance did not come up"; tail -n 30 "$LOG"; exit 1; }
PG="rbac-upg-$HPID-pg"; WEB="rbac-upg-$HPID-web"
q() { docker exec -i "$PG" psql -X -q -t -A -v ON_ERROR_STOP=1 -U postgres -d redamon <<<"$1" 2>&1; }

# The redamon.sh functions run sourced, with SCRIPT_DIR on a scratch folder whose .env has
# the identity switch on and no ADMIN_EMAIL (so _confirm_root reads no real setting), and
# with this shim in front of docker: the instance's webapp stands in for the compose service.
SCRATCH="$WORK/scratch"
mkdir -p "$SCRATCH"
printf 'RBAC_IDENTITY_ENABLED=true\n' >"$SCRATCH/.env"
cat >"$SCRATCH/shim.sh" <<'SHIM'
docker() {
  [ "${1:-}" = compose ] || { command docker "$@"; return; }
  case "${2:-}" in
    version) command docker compose version; return ;;
    exec) shift 2 ;;
    *) echo "[shim] refused: docker compose $*" >&2; return 99 ;;
  esac
  local args=()
  while [ $# -gt 0 ]; do
    case "$1" in
      -T) shift ;;
      -e|-w) args+=("$1" "$2"); shift 2 ;;
      webapp) shift; command docker exec -i "${args[@]}" "$WEB" "$@"; return ;;
      *) echo "[shim] refused: docker compose exec ... $1" >&2; return 99 ;;
    esac
  done
  echo "[shim] refused: no service" >&2; return 99
}
SHIM
host() { # [ADMIN_EMAIL=<email>] <function> [args]: a redamon.sh host function, non-interactive
  local admin_email=""
  case "$1" in ADMIN_EMAIL=*) admin_email="${1#ADMIN_EMAIL=}"; shift ;; esac
  env -u ADMIN_EMAIL ${admin_email:+ADMIN_EMAIL="$admin_email"} WEB="$WEB" SCRATCH="$SCRATCH" ROOT_DIR="$ROOT" \
    bash -c 'call=("$@"); set --; cd "$ROOT_DIR"; source ./redamon.sh; set +e; source "$SCRATCH/shim.sh"
      SCRIPT_DIR="$SCRATCH"; "${call[@]}"' host "$@" </dev/null 2>&1
}

HASH="$(docker exec -e P='rbac-step27-fake-passphrase' "$WEB" node -e \
  "process.stdout.write(require('bcryptjs').hashSync(process.env.P, 4))")"
q "insert into users (id, name, email, password, role, updated_at, created_at) values
     ('rbac-step27-a', 'rbac step27 a', '$A_EMAIL', '$HASH', 'admin', now(), now() + interval '1 second'),
     ('rbac-step27-b', 'rbac step27 b', '$B_EMAIL', '$HASH', 'admin', now(), now() + interval '2 seconds');
   insert into mcp_access_tokens (id, user_id, name, token_prefix, token_hash) values
     ('rbac-step27-tok-a', 'rbac-step27-a', 'rbac-step27', 'rdmn_mcp_rbac27a', 'rbac-step27-fake-hash-a'),
     ('rbac-step27-tok-b', 'rbac-step27-b', 'rbac-step27', 'rdmn_mcp_rbac27b', 'rbac-step27-fake-hash-b');" >/dev/null \
  || { echo "seeding the fixtures failed"; exit 1; }
sv()   { q "select session_version from users where id = '$1'"; }
live() { q "select count(*) from mcp_access_tokens where user_id = '$1' and revoked_at is null"; }
root() { q "select root_user_id || '|' || (root_confirmed_at is not null) || '|' || root_assigned_by
            from instance_settings where id = 'instance'"; }
echo "   Root at boot: $(q "select (select email from users where id = root_user_id) || ' ' || root_assigned_by from instance_settings")"

echo "== ./redamon.sh set-root moves Root to a seeded admin =="
OUT="$(host cmd_set_root "$A_EMAIL")"; RC=$?
expect_eq "set-root exits 0" "0" "$RC"
expect_eq "Root is A, confirmed, set by the host" "rbac-step27-a|true|host" "$(root)"
expect_eq "A is signed out and its MCP token revoked" "1|0" "$(sv rbac-step27-a)|$(live rbac-step27-a)"
expect_eq "B is untouched" "0|1" "$(sv rbac-step27-b)|$(live rbac-step27-b)"
expect_eq "the move is audited by the system" "root.set_by_host/system" \
  "$(q "select string_agg(action || '/' || source, ' ') from audit_log where target_id = 'rbac-step27-a'")"
OUT="$(docker exec "$WEB" node scripts/check-root.mjs </dev/null 2>&1)"
expect_has "check-root names A as the confirmed Root" "\"root\":{\"email\":\"$A_EMAIL\",\"confirmed\":true,\"rule\":\"host\"}" "$OUT"
expect_has "...and B among the candidates" "\"$B_EMAIL\"" "$OUT"

echo "== and on to the second one =="
OUT="$(host cmd_set_root "$B_EMAIL")"; RC=$?
expect_eq "set-root exits 0" "0" "$RC"
expect_eq "Root is B" "rbac-step27-b|true|host" "$(root)"
expect_eq "B and the Root it replaced are signed out, B's token revoked" "1|2|0" \
  "$(sv rbac-step27-b)|$(sv rbac-step27-a)|$(live rbac-step27-b)"
OUT="$(host cmd_set_root "$B_EMAIL")"; RC=$?
expect_eq "set-root of the confirmed Root exits 0" "0" "$RC"
expect_has "...and changes nothing" "nothing changed" "$OUT"
expect_eq "nobody is signed out" "1|2" "$(sv rbac-step27-b)|$(sv rbac-step27-a)"

echo "== update's _confirm_root with the switch on (scratch .env) =="
q "update instance_settings set root_user_id = 'rbac-step27-a', root_confirmed_at = null, root_assigned_by = 'automatic'
   where id = 'instance'" >/dev/null
OUT="$(host _confirm_root)"
expect_eq "without ADMIN_EMAIL the automatic Root is kept unconfirmed" "rbac-step27-a|false|automatic" "$(root)"
expect_has "...and the way to change it is printed" "./redamon.sh set-root <email>" "$OUT"
OUT="$(host ADMIN_EMAIL="$A_EMAIL" _confirm_root)"
expect_eq "ADMIN_EMAIL naming it confirms it" "rbac-step27-a|true|automatic" "$(root)"
expect_eq "...signing nobody out" "2|1" "$(sv rbac-step27-a)|$(sv rbac-step27-b)"
expect_has "...and says so" "Root confirmed" "$OUT"

echo
echo "== RESULT: $pass passed, $fail failed =="
[ "$fail" -eq 0 ]
