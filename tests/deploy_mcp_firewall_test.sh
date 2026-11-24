#!/usr/bin/env bash
# =============================================================================
# The ufw rules the MCP client CIDRs actually produce.
# Run:  bash tests/deploy_mcp_firewall_test.sh
#
# WHY: this is the gate operators hit first and understand last. The firewall
# filters by PORT and cannot see a URL path, so when OPERATOR_ALLOW_CIDRS is
# set, an agent connecting from anywhere else is dropped before nginx is ever
# consulted. The symptom is a TIMEOUT, not a 403, so it looks like the server is
# down rather than like a policy decision -- and turning MCP_EDGE_ALLOW_BEARER
# on, which is the documented fix for the 403, changes nothing at all here.
#
# The module's real functions are sourced with `ufw` stubbed, so what is
# asserted is the rule set that would be installed, not the presence of a line
# of code that looks like it would install one.
#
# The reverse-shell verbs the same way: revshell-open and revshell-close render
# their remote scripts from deploy.sh itself (SSH answered locally), and those run
# with `run_sudo` recording: the tagged pool rules and forwarders open installs,
# what close's sweep deletes from a sample `ufw status numbered`, and open's
# refusal when the server's pool is not this .env's.
#
# Only documentation-range addresses appear here (RFC 5737).
# =============================================================================
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEPLOY="$REPO_ROOT/tooling/deploy/single-host"
FW="$DEPLOY/modules/firewall.sh"

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf '  ok   %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  FAIL %s (got: %s want: %s)\n' "$1" "$2" "$3"; }
eq()  { if [[ "$2" == "$3" ]]; then ok "$1"; else bad "$1" "$2" "$3"; fi; }

# A tracked file: absent means a broken checkout or a move this suite must follow.
# 77 is the gate's "cannot run" code (redamon.sh _TEST_SHELL_CANNOT_RUN).
[[ -f "$FW" ]] || { echo "CANNOT RUN  $FW not found"; exit 77; }

# rules <MCP_SERVER_ENABLED> <MCP_CLIENT_CIDRS> [PORT] -> the ufw command lines
rules() {
  MCP_SERVER_ENABLED="$1" MCP_CLIENT_CIDRS="$2" _PORT="${3:-443}" _FW="$FW" \
  bash -c '
    set -uo pipefail
    is_true()  { [[ "$(printf "%s" "${1:-}" | tr "[:upper:]" "[:lower:]")" == "true" || "${1:-}" == "1" ]]; }
    info()     { :; }
    warn()     { :; }
    # The stub: record what would have been installed instead of installing it.
    run_sudo() { printf "%s\n" "$*"; }
    source "$_FW"
    _allow_mcp_clients "$_PORT"
  ' 2>/dev/null
}

echo "== the CIDRs become real ufw rules on the app port =="
OUT="$(rules true "198.51.100.0/24" 443)"
if grep -qF 'ufw allow from 198.51.100.0/24 to any port 443 proto tcp' <<<"$OUT"; then
  ok "an agent CIDR is admitted to the HTTPS port"
else
  bad "an agent CIDR is admitted to the HTTPS port" "${OUT:-<nothing>}" "a ufw allow-from rule"
fi

# A comma list is the documented form, and a split that kept the commas would
# hand ufw one invalid argument rather than two rules.
OUT="$(rules true "198.51.100.0/24, 203.0.113.0/24" 443)"
N="$(grep -c 'ufw allow from' <<<"$OUT")"
[[ "$N" == "2" ]] && ok "a comma list becomes one rule per CIDR" \
  || bad "a comma list becomes one rule per CIDR" "$N rules" "2 rules"
grep -qF 'from 203.0.113.0/24 ' <<<"$OUT" \
  && ok "surrounding whitespace is trimmed" \
  || bad "surrounding whitespace is trimmed" "$OUT" "a clean CIDR"

# The port is a parameter: an operator on a non-default HTTPS_PORT must get the
# rule on the port nginx is actually listening on.
OUT="$(rules true "198.51.100.0/24" 8443)"
grep -qF 'to any port 8443 ' <<<"$OUT" \
  && ok "the rule lands on the configured port, not a hardcoded 443" \
  || bad "the rule lands on the configured port" "$OUT" "port 8443"

echo
echo "== and NOTHING when the feature is off =="
# The whole point of the guards: a deploy that never enables MCP must not grow
# a firewall hole because a CIDR was left in a copied .env.
OUT="$(rules false "198.51.100.0/24" 443)"
[[ -z "$OUT" ]] && ok "MCP_SERVER_ENABLED=false opens nothing" \
  || bad "MCP_SERVER_ENABLED=false opens nothing" "$OUT" "no rules"

OUT="$(rules true "" 443)"
[[ -z "$OUT" ]] && ok "no MCP_CLIENT_CIDRS opens nothing" \
  || bad "no MCP_CLIENT_CIDRS opens nothing" "$OUT" "no rules"

# An empty list must not degrade into _ufw_allow_sources' world-open branch:
# that function treats "" as "allow the port from anywhere", which is correct
# for the operator path and catastrophic here.
OUT="$(rules true "  " 443)"
if grep -q 'ufw allow 443/tcp' <<<"$OUT"; then
  bad "a blank CIDR list does NOT fall through to world-open" \
      "ufw allow 443/tcp" "no rules"
else
  ok "a blank CIDR list does NOT fall through to world-open"
fi

echo
echo "== it is wired into BOTH access modes =="
# http-* is refused by deploy.sh's preflight, but the branch must still be
# correct: the refusal is one `die` away from being relaxed, and a firewall
# that silently skipped the http path would then be a lasting hole.
for mode in http https; do
  if awk "/${mode}_port\}\" tcp/{found=1} found&&/_allow_mcp_clients/{print; exit}" "$FW" | grep -q .; then
    ok "the ${mode} branch calls _allow_mcp_clients"
  else
    bad "the ${mode} branch calls _allow_mcp_clients" "absent" "a call"
  fi
done

# It must sit alongside the operator allow, not replace it: an operator locked
# out of their own UI by enabling MCP would be a bad trade.
grep -A2 '_ufw_allow_sources "${OPERATOR_ALLOW_CIDRS}"' "$FW" | grep -q '_allow_mcp_clients' \
  && ok "it ADDS to the operator CIDRs rather than replacing them" \
  || bad "it adds to the operator CIDRs" "not adjacent to the operator allow" "both rules installed"

echo
echo "== revshell-open: refused unless the server runs this .env's pool =="
FIXTURE=".env.revshelltest$$"
W="$(mktemp -d)"
trap 'rm -rf "$W"; rm -f "$DEPLOY/$FIXTURE"' EXIT
CIDRS="198.51.100.0/24, 203.0.113.0/24"
# drive <cmd_revshell_open|cmd_revshell_close> <server pool, or - for none>: the verb as
# deploy.sh runs it, SSH answered from $W/srv as the remote $HOME, the remote script
# captured in $W/<cmd>.sh instead of sent. Prints the verb's own output.
drive() {
  rm -rf "$W/srv"; mkdir -p "$W/srv/redamon"; : > "$W/$1.sh"
  [[ "$2" == - ]] || printf 'AUTH_SECRET=x\nKALI_SANDBOX_PORT_POOL=%s\n' "$2" > "$W/srv/redamon/.env"
  printf 'ACCESS_MODE=https-ip\nTLS_MODE=self-signed\nKALI_SANDBOX_PORT_POOL=4500-4509\nREVSHELL_TARGET_CIDRS="%s"\n' \
    "$CIDRS" > "$DEPLOY/$FIXTURE"
  ( cd "$DEPLOY" && W="$W" CMD="$1" bash -c '
      set -uo pipefail
      source ./deploy.sh status 203.0.113.5 /dev/null ubuntu --env "'"${FIXTURE#.env.}"'" >/dev/null 2>&1 || exit 3
      ssh_stub() { HOME="$W/srv" bash -c "$*"; }
      SSH=ssh_stub
      ship_assets() { :; }
      remote() { cat > "$W/$CMD.sh"; }
      PREAMBLE="set -euo pipefail"
      "$CMD"' 2>&1 )
  rm -f "$DEPLOY/$FIXTURE"
}
# run_remote <script> [ufw status numbered output]: every run_sudo call the script makes.
run_remote() {
  : > "$W/calls"
  ( CALLS="$W/calls" SAMPLE="${2:-}" REVSHELL_TARGET_CIDRS="$CIDRS" ENABLE_UFW=true bash -c '
      is_true() { [[ "$(printf "%s" "${1:-}" | tr "[:upper:]" "[:lower:]")" == "true" || "${1:-}" == "1" ]]; }
      step() { :; }; info() { :; }; warn() { :; }; success() { :; }; err() { :; }
      install_if_missing() { :; }; sleep() { :; }
      ip() { echo "1.1.1.1 via 10.0.0.1 dev eth0 src 10.0.0.5 uid 1000"; }
      run_sudo() { printf "%s\n" "$*" >> "$CALLS"; [[ "$*" != "ufw status numbered" ]] || printf "%s\n" "$SAMPLE"; }
      source "$1"' _ "$1" ) >/dev/null 2>&1
  cat "$W/calls"
}
for case in "-|not set on the server" "4600-4609|the server's KALI_SANDBOX_PORT_POOL is '4600-4609'" \
            "0.0.0.0:4500-4509|the server's KALI_SANDBOX_PORT_POOL is '0.0.0.0:4500-4509'"; do
  srv="${case%%|*}"; want="${case#*|}"
  OUT="$(drive cmd_revshell_open "$srv")"
  label="server pool '${srv/#-/unset}'"
  [[ "$OUT" == *"$want"* && "$OUT" == *"'./deploy.sh update' first"* ]] \
    && ok "$label: refused, and told to run update first" \
    || bad "$label: refused, and told to run update first" "${OUT:-<nothing>}" "$want ... './deploy.sh update' first"
  [[ ! -s "$W/cmd_revshell_open.sh" ]] && ok "$label: nothing is sent to the server" \
    || bad "$label: nothing is sent to the server" "a remote script" "none"
done

echo
echo "== revshell-open: the rules and forwarders it installs =="
OUT="$(drive cmd_revshell_open 127.0.0.1:4500-4509)"
if [[ -s "$W/cmd_revshell_open.sh" ]]; then
  ok "the same pool, written with its loopback address, proceeds"
  CALLS_OPEN="$(run_remote "$W/cmd_revshell_open.sh")"
  for c in 198.51.100.0/24 203.0.113.0/24; do
    grep -qxF "ufw allow from $c to any port 4500:4509 proto tcp comment redamon-revshell" <<<"$CALLS_OPEN" \
      && ok "$c: one ufw rule for the whole pool, tagged redamon-revshell" \
      || bad "$c: one tagged ufw rule for the pool" "$(grep 'ufw allow' <<<"$CALLS_OPEN" | tr '\n' ' ')" "allow ... 4500:4509 ... comment redamon-revshell"
  done
  eq "no other ufw rule" "$(grep -c '^ufw allow' <<<"$CALLS_OPEN")" "2"
  eq "one forwarder per pool port" "$(grep -c '^systemd-run --unit=redamon-revshell-45[0-9][0-9] ' <<<"$CALLS_OPEN")" "10"
  grep -qxF 'systemd-run --unit=redamon-revshell-4503 --collect --description=RedAmon reverse-shell forwarder (pool port 4503) /usr/bin/socat TCP-LISTEN:4503,bind=10.0.0.5,fork,reuseaddr TCP:127.0.0.1:4503' <<<"$CALLS_OPEN" \
    && ok "each forwards the primary address to the same port on loopback" \
    || bad "each forwards to loopback" "$(grep 4503 <<<"$CALLS_OPEN" | head -1)" "socat TCP-LISTEN:4503,bind=10.0.0.5 -> TCP:127.0.0.1:4503"
else
  bad "the same pool, written with its loopback address, proceeds" "${OUT:-<nothing>}" "a remote script"
fi

echo
echo "== revshell-close: the sweep deletes every tagged rule and every old 4444 rule =="
# Old 4444 rules carry no tag (the release before per-user sandboxes added none), and
# 192.0.2.0/24 is a CIDR no longer in REVSHELL_TARGET_CIDRS.
SAMPLE='Status: active

     To                         Action      From
     --                         ------      ----
[ 1] 22/tcp                     ALLOW IN    203.0.113.0/24
[ 2] 443/tcp                    ALLOW IN    203.0.113.0/24
[ 3] 4444/tcp                   ALLOW IN    192.0.2.0/24
[ 4] 4500:4509/tcp              ALLOW IN    198.51.100.0/24            # redamon-revshell
[ 5] 4500:4509/tcp              ALLOW IN    203.0.113.0/24             # redamon-revshell
[ 6] 4444/tcp                   ALLOW IN    Anywhere
[ 7] 4600/tcp                   ALLOW IN    192.0.2.0/24               # redamon-revshell
[ 8] 14444/tcp                  ALLOW IN    192.0.2.0/24
[ 9] 22/tcp (v6)                ALLOW IN    Anywhere (v6)
[10] 4444/tcp (v6)              ALLOW IN    Anywhere (v6)
[11] 8443/tcp                   ALLOW IN    198.51.100.0/24            # operator'
drive cmd_revshell_close - >/dev/null
if [[ -s "$W/cmd_revshell_close.sh" ]]; then
  DELETED="$(run_remote "$W/cmd_revshell_close.sh" "$SAMPLE" | sed -n 's/^ufw --force delete \([0-9][0-9]*\)$/\1/p' | tr '\n' ' ')"
  eq "deleted by number, highest first: the pool rules and the old 4444 rules" "$DELETED" "10 7 6 5 4 3 "
else
  bad "revshell-close renders its remote script" "nothing" "a script"
fi

echo
printf 'passed %d, failed %d\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
