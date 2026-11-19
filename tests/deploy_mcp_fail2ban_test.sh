#!/usr/bin/env bash
# =============================================================================
# The [redamon-mcp-auth] fail2ban filter, matched against real nginx log lines.
# Run:  bash tests/deploy_mcp_fail2ban_test.sh
#
# WHY: a fail2ban failregex fails in two directions and neither is visible on a
# running host. Too narrow and the jail never fires, so a token brute force is
# unpoliced while the jail sits there looking configured. Too broad and it bans
# a healthy MCP client for being rate-limited, or bans on a 401 from an
# unrelated endpoint. Nothing logs "your filter matched nothing", so the only
# way to know is to run the regex over lines nginx actually writes.
#
# The regex is read OUT of modules/fail2ban.sh rather than restated here, so
# editing the module without revisiting the corpus fails this test.
#
# The corpus carries each line twice: once as nginx writes it, and once with
# the timestamp blanked to `[]`, because fail2ban cuts the matched datetime out
# of the line before applying failregex (this is why the stock nginx-botsearch
# filter is written against `\[\]`). A regex that anchors on the date passes one
# form and silently fails the other.
#
# Only documentation-range addresses appear here (RFC 5737 / RFC 3849).
# =============================================================================
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODULE="$REPO_ROOT/tooling/deploy/single-host/modules/fail2ban.sh"

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf '  ok   %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  FAIL %s (got: %s want: %s)\n' "$1" "$2" "$3"; }
eq()  { if [[ "$2" == "$3" ]]; then ok "$1"; else bad "$1" "$2" "$3"; fi; }

# A tracked file: absent means a broken checkout or a move this suite must follow.
# 77 is the gate's "cannot run" code (redamon.sh _TEST_SHELL_CANNOT_RUN).
[[ -f "$MODULE" ]] || { echo "CANNOT RUN  $MODULE not found"; exit 77; }

# ------------------------------------------------------------ the regex -----
# Pull the live failregex out of the module's quoted heredoc.
FAILREGEX="$(awk -F'= ' '/^failregex = /{print $2; exit}' "$MODULE")"

echo "== the filter is defined at all =="
if [[ -z "$FAILREGEX" ]]; then
  bad "modules/fail2ban.sh defines a failregex" "none" "one"
  printf 'passed %d, failed %d\n' "$PASS" "$FAIL"; exit 1
fi
ok "failregex read from the module: $FAILREGEX"

if ! command -v grep >/dev/null || ! echo x | grep -qP x 2>/dev/null; then
  echo "  SKIP  grep -P unavailable; cannot evaluate the regex"
  exit 0
fi

# fail2ban expands <HOST> to an address-or-hostname group. This is the
# substitution fail2ban itself performs, narrowed to what nginx can emit in the
# first field: an IPv4 or IPv6 literal.
HOST_RE='(?:[0-9a-fA-F:.]+)'
PCRE="${FAILREGEX//<HOST>/$HOST_RE}"

matches() { printf '%s\n' "$1" | grep -qP -- "$PCRE"; }

# --------------------------------------------------------- the corpus -------
# Lines the jail MUST ban on: every transport, verb and address family the
# endpoint really answers on, all returning 401.
SHOULD_MATCH=(
  '198.51.100.7 - - [13/Sep/2026:10:00:01 +0000] "POST /api/mcp-server HTTP/1.1" 401 52 "-" "claude-code/1.0"'
  '198.51.100.7 - - [13/Sep/2026:10:00:02 +0000] "POST /api/mcp-server HTTP/2.0" 401 52 "-" "node"'
  '203.0.113.9 - - [13/Sep/2026:10:00:03 +0000] "GET /api/mcp-server HTTP/1.1" 401 52 "-" "curl/8.5.0"'
  '198.51.100.7 - - [13/Sep/2026:10:00:04 +0000] "POST /api/mcp-server?x=1 HTTP/1.1" 401 52 "-" "node"'
  '2001:db8::42 - - [13/Sep/2026:10:00:05 +0000] "POST /api/mcp-server HTTP/1.1" 401 52 "-" "node"'
)

# Lines the jail must NEVER ban on. 429 and 403 are the dangerous ones: a
# legitimate agent bursting past the rate limit, or one arriving from outside
# MCP_CLIENT_CIDRS, would otherwise be banned at the firewall for a
# configuration problem rather than a credential attack.
SHOULD_NOT_MATCH=(
  '198.51.100.7 - - [13/Sep/2026:10:00:06 +0000] "POST /api/mcp-server HTTP/1.1" 200 1200 "-" "node"'
  '198.51.100.7 - - [13/Sep/2026:10:00:07 +0000] "POST /api/mcp-server HTTP/1.1" 429 52 "-" "node"'
  '198.51.100.7 - - [13/Sep/2026:10:00:08 +0000] "POST /api/mcp-server HTTP/1.1" 404 52 "-" "node"'
  '198.51.100.7 - - [13/Sep/2026:10:00:09 +0000] "POST /api/mcp-server HTTP/1.1" 403 52 "-" "node"'
  '198.51.100.7 - - [13/Sep/2026:10:00:10 +0000] "GET /api/auth/session HTTP/1.1" 401 52 "-" "Mozilla/5.0"'
  '198.51.100.7 - - [13/Sep/2026:10:00:11 +0000] "POST /api/mcp/manifest HTTP/1.1" 401 52 "-" "node"'
  '198.51.100.7 - - [13/Sep/2026:10:00:12 +0000] "POST /api/mcp-server-admin HTTP/1.1" 401 52 "-" "node"'
  # The 401 belongs to the referrer field, not to this request's status.
  '198.51.100.7 - - [13/Sep/2026:10:00:13 +0000] "GET /dashboard HTTP/1.1" 200 12 "/api/mcp-server 401" "node"'
)

# Both timestamp forms: as written, and as fail2ban presents it after cutting
# the date out.
blank_date() { printf '%s\n' "${1/\[13\/Sep\/2026:*+0000\]/[]}"; }

echo
echo "== a credential failure is banned, in both timestamp forms =="
for line in "${SHOULD_MATCH[@]}"; do
  desc="$(printf '%s' "$line" | grep -oP '"\S+ \S+ [^"]+" \d+' | head -1)"
  matches "$line" && ok "bans: $desc" || bad "bans: $desc" "no match" "match"
  stripped="$(blank_date "$line")"
  matches "$stripped" && ok "bans (date cut): $desc" \
    || bad "bans (date cut): $desc" "no match" "match"
done

echo
echo "== nothing else is banned =="
for line in "${SHOULD_NOT_MATCH[@]}"; do
  desc="$(printf '%s' "$line" | grep -oP '"\S+ \S+ [^"]+" \d+' | head -1)"
  matches "$line" && bad "ignores: $desc" "match" "no match" || ok "ignores: $desc"
  stripped="$(blank_date "$line")"
  matches "$stripped" && bad "ignores (date cut): $desc" "match" "no match" \
    || ok "ignores (date cut): $desc"
done

# ------------------------------------------------------ the jail wiring -----
# A correct filter that no jail references bans nothing.
echo
echo "== the jail that uses it is wired correctly =="
JAIL="$(awk '/^\[redamon-mcp-auth\]/,/^$/' "$MODULE")"
[[ -n "$JAIL" ]] && ok "a [redamon-mcp-auth] jail exists" \
  || bad "a [redamon-mcp-auth] jail exists" "absent" "present"

grep -q 'filter *= *redamon-mcp-auth' <<<"$JAIL" \
  && ok "the jail points at this filter by name" \
  || bad "the jail points at this filter" "wrong name" "redamon-mcp-auth"

# access.log, not error.log: the 401 is an application response, and nginx does
# not write those to the error log at all.
grep -q 'logpath *= */var/log/nginx/access.log' <<<"$JAIL" \
  && ok "it reads the access log (where a 401 is recorded)" \
  || bad "it reads the access log" "not access.log" "/var/log/nginx/access.log"

# Off unless the feature is on, so a deploy without MCP grows no new jail.
grep -q 'enabled *= *\${_MCP_JAIL_ENABLED}' <<<"$JAIL" \
  && ok "enablement is bound to MCP_SERVER_ENABLED" \
  || bad "enablement is bound to MCP_SERVER_ENABLED" "hardcoded" "\${_MCP_JAIL_ENABLED}"
grep -qE '_MCP_JAIL_ENABLED=false' "$MODULE" \
  && ok "and it defaults to false" \
  || bad "it defaults to false" "not defaulted false" "_MCP_JAIL_ENABLED=false"

# The filter file has to be written, or fail2ban refuses to start the jail and
# takes the sshd jail down with it.
grep -q '/etc/fail2ban/filter.d/redamon-mcp-auth.conf' "$MODULE" \
  && ok "the filter file is installed where the jail looks for it" \
  || bad "the filter file is installed" "absent" "/etc/fail2ban/filter.d/redamon-mcp-auth.conf"

echo
printf 'passed %d, failed %d\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
