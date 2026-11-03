#!/usr/bin/env bash
# =============================================================================
# The MCP env chain, END TO END, without an SSH host.
# Run:  bash tests/deploy_mcp_env_chain_test.sh
#
# WHY: `MCP_SERVER_ENABLED=true` in the deploy .env has to survive FOUR hops to
# reach the running container, and it silently died at three of them:
#
#   1. deploy.sh default        (set -u would otherwise kill the run)
#   2. build_deploy_env         (writes .deploy.env.staged, scp'd to the host)
#   3. the seed step            (writes $APP_PATH/.env on the host)
#   4. compose `environment:`   (the webapp has NO env_file)
#
# Each hop is a different file, and a break in any one of them produces the
# SAME symptom: the endpoint 404s and nothing says why. Worse for this flag
# specifically, redamon.sh's ensure_auth_secrets APPENDS
# `MCP_SERVER_ENABLED=false` when the key is absent, so an unseeded host does
# not merely default off, it is actively pinned off.
#
# This simulates hops 1-3 for real (sourcing deploy.sh's own functions, running
# its own seed shell code) and asserts hop 4 against docker-compose.yml, so the
# whole chain is proven without touching a server.
# =============================================================================
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEPLOY="$REPO_ROOT/tooling/deploy/single-host/deploy.sh"
COMPOSE="$REPO_ROOT/docker-compose.yml"

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf '  ok   %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  FAIL %s (got: %s want: %s)\n' "$1" "$2" "$3"; }
eq()  { if [[ "$2" == "$3" ]]; then ok "$1"; else bad "$1" "$2" "$3"; fi; }

# ---------------------------------------------------------------- hop 1 + 2 --
# Run deploy.sh's OWN build_deploy_env with a realistic operator config and read
# back the staged file it would scp. Sourcing the real script means a key
# removed from its list fails here, not in production.
echo "== hops 1+2: the operator's value reaches .deploy.env.staged =="
# deploy.sh only runs main() when EXECUTED, so sourcing it with a valid verb
# gives us its real functions and its real derivations, no SSH host needed.
#
# It reads `.env.<name>` with `--env <name>`, so the probe writes a CONTROLLED
# fixture rather than inheriting whatever the operator has in .env (which would
# make these assertions depend on a gitignored file).
DSH_DIR="$REPO_ROOT/tooling/deploy/single-host"
FIXTURE=".env.mcpchaintest$$"
cleanup_fixture() { rm -f "$DSH_DIR/$FIXTURE"; }
trap cleanup_fixture EXIT

_probe() {  # _probe <ACCESS_MODE> <DOMAIN> [HTTPS_PORT] [HTTP_PORT] -> staged env
  cat > "$DSH_DIR/$FIXTURE" <<FIX
ACCESS_MODE=$1
DOMAIN=$2
HTTPS_PORT=${3:-443}
HTTP_PORT=${4:-80}
ALLOW_INSECURE=1
OPERATOR_ALLOW_CIDRS=1.2.3.4/32
MCP_SERVER_ENABLED=true
MCP_EDGE_ALLOW_BEARER=true
MCP_CLIENT_CIDRS=198.51.100.0/24
MCP_LLM_DAILY_BUDGET=50
AGENT_IN_THE_LOOP_ENABLED=true
FIX
  ( cd "$DSH_DIR" && bash -c '
      set -uo pipefail
      source ./deploy.sh status 203.0.113.5 /dev/null ubuntu --env "'"${FIXTURE#.env.}"'" >/dev/null 2>&1
      f="$(build_deploy_env)" || exit 1
      cat "$f"; rm -f "$f"
    ' 2>/dev/null )
}

STAGED="$(_probe https-domain redamon.example)"

if [[ -z "$STAGED" ]]; then
  echo "  SKIP  deploy.sh could not be sourced headlessly (its main() ran or died)"
  echo "        falling back to a static check of the key list"
  for k in MCP_SERVER_ENABLED MCP_EDGE_ALLOW_BEARER MCP_CLIENT_CIDRS MCP_PUBLIC_ORIGIN AGENT_IN_THE_LOOP_ENABLED; do
    awk -v k="$k" '/^build_deploy_env\(\)/,/^}/ { if ($0 ~ k) f=1 } END { exit !f }' "$DEPLOY" \
      && ok "$k is in build_deploy_env's key list" \
      || bad "$k is in build_deploy_env's key list" "absent" "present"
  done
else
  for kv in "MCP_SERVER_ENABLED=true" "MCP_EDGE_ALLOW_BEARER=true" "AGENT_IN_THE_LOOP_ENABLED=true"; do
    k="${kv%%=*}"
    got="$(grep -E "^${k}=" <<<"$STAGED" | head -1 | cut -d= -f2- | tr -d "'\"")"
    eq "$k crosses the SSH boundary with the operator's value" "$got" "${kv#*=}"
  done
  got="$(grep -E '^MCP_CLIENT_CIDRS=' <<<"$STAGED" | head -1 | cut -d= -f2- | tr -d "'\"")"
  eq "MCP_CLIENT_CIDRS crosses intact" "$got" "198.51.100.0/24"
  # The origin is DERIVED (scheme + host + non-default port), never typed.
  got="$(grep -E '^MCP_PUBLIC_ORIGIN=' <<<"$STAGED" | head -1 | cut -d= -f2- | tr -d "'\"")"
  eq "MCP_PUBLIC_ORIGIN is derived from ACCESS_MODE" "$got" "https://redamon.example"

  # THE case this variable exists for: nginx forwards `Host $host`, which drops
  # the port, so on a non-default port the webapp cannot rebuild its own origin
  # and would 403 a same-origin client against itself.
  PORTED="$(_probe https-domain redamon.example 8443)"
  got="$(grep -E '^MCP_PUBLIC_ORIGIN=' <<<"$PORTED" | head -1 | cut -d= -f2- | tr -d "'\"")"
  eq "a non-default HTTPS_PORT is carried in the origin" "$got" "https://redamon.example:8443"

  # And the default port must NOT be appended: https://host:443 is not the
  # origin a browser sends, so appending it would break the common case.
  eq "the DEFAULT port is not appended" \
     "$(grep -E '^MCP_PUBLIC_ORIGIN=' <<<"$STAGED" | grep -c ':443')" "0"
fi

# ------------------------------------------------------------------- hop 3 ---
# The seed shell code, run for real against a throwaway .env. This is the exact
# `seed()` the host executes, so an ordering or quoting bug shows up here.
echo
echo "== hop 3: the seed writes it into the app .env, idempotently =="
T="$(mktemp -d)"
seed() { local k="$1" v="$2"; [ -z "$v" ] && return 0; grep -q "^$k=" "$T/.env" && sed -i "s|^$k=.*|$k=$v|" "$T/.env" || echo "$k=$v" >> "$T/.env"; }
touch "$T/.env"

MCP_SERVER_ENABLED=true; seed MCP_SERVER_ENABLED "$MCP_SERVER_ENABLED"
eq "a fresh .env gets the operator's value" \
   "$(grep '^MCP_SERVER_ENABLED=' "$T/.env" | cut -d= -f2)" "true"

# redamon.sh runs AFTER the seed and appends the key only when ABSENT. Simulate
# it to prove the ordering: a seeded 'true' must survive.
grep -q '^MCP_SERVER_ENABLED=' "$T/.env" || echo "MCP_SERVER_ENABLED=false" >> "$T/.env"
eq "redamon.sh does NOT clobber a seeded true" \
   "$(grep '^MCP_SERVER_ENABLED=' "$T/.env" | cut -d= -f2)" "true"
eq "and writes exactly one entry" "$(grep -c '^MCP_SERVER_ENABLED=' "$T/.env")" "1"

# An operator flipping it back must also take effect (seed overwrites).
MCP_SERVER_ENABLED=false; seed MCP_SERVER_ENABLED "$MCP_SERVER_ENABLED"
eq "re-seeding false overwrites a previous true" \
   "$(grep '^MCP_SERVER_ENABLED=' "$T/.env" | cut -d= -f2)" "false"
eq "still exactly one entry" "$(grep -c '^MCP_SERVER_ENABLED=' "$T/.env")" "1"

AGENT_IN_THE_LOOP_ENABLED=true; seed AGENT_IN_THE_LOOP_ENABLED "$AGENT_IN_THE_LOOP_ENABLED"
grep -q '^AGENT_IN_THE_LOOP_ENABLED=' "$T/.env" || echo "AGENT_IN_THE_LOOP_ENABLED=false" >> "$T/.env"
eq "redamon.sh does NOT clobber a seeded loop switch" \
   "$(grep '^AGENT_IN_THE_LOOP_ENABLED=' "$T/.env" | cut -d= -f2)" "true"

# A blank knob must not write an empty line that shadows the compose default.
seed MCP_RATE_QUERY_PER_MIN ""
grep -q '^MCP_RATE_QUERY_PER_MIN=' "$T/.env" \
  && bad "a blank knob is NOT seeded" "written as empty" "absent" \
  || ok "a blank knob is NOT seeded (compose default stands)"
rm -rf "$T"

# ------------------------------------------------------------------- hop 4 ---
echo
echo "== hop 4: compose passes it to the webapp (which has NO env_file) =="
for k in MCP_SERVER_ENABLED MCP_TOKEN_RETENTION_DAYS MCP_LLM_DAILY_BUDGET \
         MCP_RATE_READ_PER_MIN MCP_RATE_QUERY_PER_MIN MCP_RATE_WRITE_PER_MIN MCP_RATE_MUTE_PER_MIN \
         MCP_RATE_START_PER_WINDOW MCP_RATE_START_WINDOW_MS MCP_ALLOWED_ORIGIN; do
  grep -qE "^ +${k}: \\\$\{${k}" "$COMPOSE" && ok "$k reaches the webapp" \
    || bad "$k reaches the webapp" "absent from the environment block" "present"
done

echo
echo "== hop 4: the Agent in the Loop switch reaches BOTH the agent and the webapp =="
LOOP_SVCS="$(python3 -c '
import sys, yaml
d = yaml.safe_load(open(sys.argv[1]))
for svc in ("agent", "webapp"):
    env = d["services"].get(svc, {}).get("environment") or {}
    print(svc, env.get("AGENT_IN_THE_LOOP_ENABLED", "<absent>"))
' "$COMPOSE" 2>/dev/null)"
if [[ -z "$LOOP_SVCS" ]]; then
  echo "  skip  compose not parseable here (no python3 / pyyaml)"
else
  for svc in agent webapp; do
    eq "$svc gets AGENT_IN_THE_LOOP_ENABLED" \
       "$(awk -v s="$svc" '$1==s{print $2}' <<<"$LOOP_SVCS")" '${AGENT_IN_THE_LOOP_ENABLED:-true}'
  done
fi
for site in cmd_init cmd_update; do
  _end=$([[ $site == cmd_init ]] && echo cmd_update || echo cmd_status)
  awk "/^${site}\\(\\)/,/^${_end}\\(\\)/" "$DEPLOY" | grep -q '^seed AGENT_IN_THE_LOOP_ENABLED ' \
    && ok "$site seeds AGENT_IN_THE_LOOP_ENABLED" \
    || bad "$site seeds AGENT_IN_THE_LOOP_ENABLED" "absent" "a seed line"
done
grep -qE ': "\$\{AGENT_IN_THE_LOOP_ENABLED:=true\}"' "$DEPLOY" \
  && ok "deploy.sh defaults the loop switch to true" \
  || bad "deploy.sh defaults the loop switch" "no default" ': "${AGENT_IN_THE_LOOP_ENABLED:=true}"'
grep -q 'AGENT_IN_THE_LOOP_ENABLED=true but MCP_SERVER_ENABLED is off' "$DEPLOY" \
  && ok "deploy.sh notes when the loop is on without the MCP server" \
  || bad "deploy.sh notes when the loop is on without the MCP server" "no note" "a log line"
# The loop switch is on by default and the MCP server off by default here, so this
# is the default state: a note, never a warning or a refusal.
awk '/AGENT_IN_THE_LOOP_ENABLED=true but MCP_SERVER_ENABLED is off/{print}' "$DEPLOY" | grep -q '^ *log ' \
  && ok "that is a log(), not a warn() or a die()" \
  || bad "that is a log()" "warn, die or absent" "log"
for site in cmd_init cmd_update; do
  _end=$([[ $site == cmd_init ]] && echo cmd_update || echo cmd_status)
  awk "/^${site}\\(\\)/,/^${_end}\\(\\)/" "$DEPLOY" | grep -q '^seed REDAMON_SINGLE_HOST_DEPLOY true' \
    && ok "$site marks the .env as a deployed server" \
    || bad "$site marks the .env as a deployed server" "absent" "seed REDAMON_SINGLE_HOST_DEPLOY true"
done
grep -q 'the flag did not reach the \\$svc container' "$DEPLOY" \
  && ok "verify checks both containers received the loop switch" \
  || bad "verify checks the loop switch" "absent" "a printenv check"

# ------------------------------------------------------------ the overlay ----
echo
echo "== the prod overlay supplies what only a fronted deploy can know =="
OVERLAY="$REPO_ROOT/tooling/deploy/single-host/compose/docker-compose.prod.yml"
grep -qE 'TRUST_PROXY: *"true"' "$OVERLAY" \
  && ok "TRUST_PROXY=true (nginx pins XFF to the real peer)" \
  || bad "TRUST_PROXY=true" "absent" 'TRUST_PROXY: "true"'
grep -q 'MCP_ALLOWED_ORIGIN' "$OVERLAY" \
  && ok "MCP_ALLOWED_ORIGIN is passed (Host \$host drops the port)" \
  || bad "MCP_ALLOWED_ORIGIN is passed" "absent" "present"

# ------------------------------------------------------- the http-* refusal --
echo
echo "== MCP is REFUSED in http-* modes (a bearer token in plaintext) =="
grep -qE 'MCP_SERVER_ENABLED=true is refused in' "$DEPLOY" \
  && ok "deploy.sh refuses MCP over plaintext" \
  || bad "deploy.sh refuses MCP over plaintext" "no refusal" "a die() on http-*"
# It must be a hard die, not something ALLOW_INSECURE can wave through.
awk '/MCP_SERVER_ENABLED=true is refused in/{print}' "$DEPLOY" | grep -q 'die ' \
  && ok "the refusal is a die(), not a warn" \
  || bad "the refusal is a die()" "warn" "die"


# ------------------------------------------------- the structural invariant --
# Everything above pins the keys that exist TODAY. This pins the SHAPE, so the
# next inbound-MCP key someone adds cannot repeat the original bug: a key wired
# into compose and reachable from nowhere. Three rules, each broken at some
# point in this feature's life:
#
#   a) a key compose reads must be seeded into the app .env, or compose
#      interpolates it to empty and the operator's value is silently discarded
#   b) cmd_init and cmd_update must seed the SAME set, or the flag works on a
#      fresh install and vanishes on the next upgrade
#   c) every key deploy.sh DEREFERENCES must have a default, or `set -u` aborts
#      the run on an .env that simply omits it, with an unbound-variable trace
#      instead of a usable message
#
# Scope: the INBOUND server's keys, which compose hands to `webapp` and
# `recon-orchestrator`. The MCP_* keys on `agent` and `kali-sandbox` belong to
# the internal Kali MCP servers -- a different feature, whose values are
# container-to-container URLs rather than operator knobs, and which the deploy
# .env has no business carrying.
#
# Also out of scope for (a): MCP_CLIENT_CIDRS and MCP_EDGE_ALLOW_BEARER, which
# nginx.sh and firewall.sh consume on the host and the app never sees. Seeding
# them into the app .env would imply the container honours them.
echo
echo "== the chain's SHAPE, so a future key cannot break it silently =="

# (a) every inbound MCP key compose reads is seeded.
INBOUND_KEYS="$(python3 -c '
import sys, yaml
d = yaml.safe_load(open(sys.argv[1]))
out = set()
for svc in ("webapp", "recon-orchestrator"):
    env = d["services"].get(svc, {}).get("environment") or {}
    if isinstance(env, list):
        env = dict(e.split("=", 1) for e in env if "=" in e)
    out |= {k for k in env if k.startswith("MCP_")}
print("\n".join(sorted(out)))
' "$COMPOSE" 2>/dev/null)"

if [[ -z "$INBOUND_KEYS" ]]; then
  echo "  skip  compose not parseable here (no python3 / pyyaml)"
else
  while read -r k; do
    [[ -z "$k" ]] && continue
    # MCP_ALLOWED_ORIGIN is seeded from the DERIVED MCP_PUBLIC_ORIGIN, so its
    # seed line carries a different right-hand side; the target name is what
    # has to be present.
    if grep -qE "^seed ${k} " "$DEPLOY"; then
      ok "$k is seeded into the app .env"
    else
      bad "$k is seeded into the app .env" "compose reads it, deploy never writes it" "a seed line"
    fi
  done <<< "$INBOUND_KEYS"
fi

# (b) the two seed sites agree. A key added to one only is the upgrade-path bug:
# it works on a fresh install and silently reverts on the next `update`.
_init_seeds="$(awk '/^cmd_init\(\)/,/^cmd_update\(\)/' "$DEPLOY" | grep -oE '^seed MCP_[A-Z_]+' | sort -u)"
_upd_seeds="$(awk  '/^cmd_update\(\)/,/^cmd_status\(\)/' "$DEPLOY" | grep -oE '^seed MCP_[A-Z_]+' | sort -u)"
if [[ -n "$_init_seeds" && "$_init_seeds" == "$_upd_seeds" ]]; then
  ok "cmd_init and cmd_update seed the same MCP keys ($(wc -l <<<"$_init_seeds"))"
else
  bad "cmd_init and cmd_update seed the same MCP keys" \
      "differ: $(comm -3 <(echo "$_init_seeds") <(echo "$_upd_seeds") | tr -d '\t' | tr '\n' ' ')" \
      "identical sets"
fi

# (c) every MCP key deploy.sh reads BARE has a default.
#
# "Bare" means an unescaped `${KEY}` with no `:-` fallback of its own, which is
# the only form that aborts under `set -u`. Three exclusions, each of which
# would otherwise make this rule fire on something safe or, worse, make it
# vacuous:
#
#   - the default declarations themselves (`: "${KEY:=}"`). These ARE unescaped
#     dereferences, so counting them would make every key trivially satisfy its
#     own assertion and the rule could never fail.
#   - `\${KEY}` inside a heredoc. Not expanded here at all: it is written
#     verbatim into the remote script and expands on the host.
#   - keys the script ASSIGNS (MCP_PUBLIC_ORIGIN is derived from ACCESS_MODE),
#     which are never read before they are set.
#
# build_deploy_env is also safe by construction -- it reads `"${!k:-}"` -- so
# what remains is the validation and plan output, which read these bare.
_derefs="$(grep -vE '^\s*: "\$\{' "$DEPLOY" \
           | grep -oE '(^|[^\\])\$\{MCP_[A-Z_]+\}' | grep -oE 'MCP_[A-Z_]+' | sort -u)"
_assigned="$(grep -oE '^\s*MCP_[A-Z_]+=' "$DEPLOY" | tr -d ' =' | sort -u)"
while read -r k; do
  [[ -z "$k" ]] && continue
  grep -qx "$k" <<<"$_assigned" && continue
  if grep -qE ": \"\\\$\{${k}:=" "$DEPLOY"; then
    ok "$k has a default (set -u safe)"
  else
    bad "$k has a default" "none" ": \"\${${k}:=...}\""
  fi
done <<< "$_derefs"

# ------------------------------------------------ the post-deploy verdict --
# `deploy.sh verify` is the only thing that tells an operator WHICH of the four
# silent failure modes they are in, and it can only do that because the route
# answers with distinguishable codes. The codes are asserted on the app side in
# webapp/src/app/api/mcp-server/route.test.ts; what is pinned here is that
# verify still discriminates on them.
#
# The 200 case matters most and is the easiest to lose: it is the alarm for an
# endpoint answering with NO credential at all. Trimmed to a default branch, a
# wide-open MCP surface would be reported as merely "unexpected".
echo
echo "== deploy.sh verify can still name the failure mode =="
VERIFY_MCP="$(awk '/Inbound MCP surface/,/MCP GET/' "$DEPLOY")"
for code in 401 403 404 200; do
  grep -qE "^\s+${code}\)" <<<"$VERIFY_MCP" \
    && ok "verify discriminates $code" \
    || bad "verify discriminates $code" "no case arm" "a $code) arm"
done
# Match the SEVERITY CALL, not the message: the wording mentions
# "unauthenticated" either way, so a looser pattern passes on a downgraded arm.
grep -qE '^\s*200\)\s*err ' <<<"$VERIFY_MCP" \
  && ok "the 200 arm calls err(), not warn()" \
  || bad "the 200 arm calls err()" "downgraded to a warning" "err on an uncredentialed 200"

echo
printf 'passed %d, failed %d\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
