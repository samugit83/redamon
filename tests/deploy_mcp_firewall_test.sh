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
# Only documentation-range addresses appear here (RFC 5737).
# =============================================================================
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEPLOY="$REPO_ROOT/tooling/deploy/single-host"
FW="$DEPLOY/modules/firewall.sh"

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf '  ok   %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  FAIL %s (got: %s want: %s)\n' "$1" "$2" "$3"; }

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
printf 'passed %d, failed %d\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
