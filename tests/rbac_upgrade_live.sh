#!/usr/bin/env bash
#
# RBAC upgrade harness: boots a webapp image's own startup list against synthetic
# 7.7.x-shaped databases and checks what the upgrade did to them.
#
# Each scenario is a full dump (schema and data) in tests/fixtures/rbac_upgrade/<name>.sql,
# made with the pinned redamon-webapp:rbac-7.7.2 image (git archive 442debbf:webapp), so
# it keeps the 7.7.x shape while redamon-webapp:latest moves on. The startup list is the
# image's /app/entrypoint.sh minus its last line (exec node server.js), which
# webapp/Dockerfile writes: the harness runs exactly what the image runs at boot.
#
# After every run it asserts:
#   - nothing changed but what the upgrade adds by design: the row count of every table
#     and every users column (definition and values) that existed before the run are
#     identical after it, audit_log counted without the rows of UPGRADE_AUDIT_ACTIONS; a
#     table or users column the run added is printed as a NOTE;
#   - the scenario's checks: tests/fixtures/rbac_upgrade/checks.sql, then checks_after.sql
#     (what the upgrade adds: legacy grants, Nuclei template owners, the instance settings
#     row, the Root the boot chose, their marker rows, the empty permission tables, the
#     legacy-grant conversion, the empty sharing tables and the MCP token sharing defaults),
#     through psql, diffed against expected/<scenario>.after.out,
#     expected/<scenario>.after.identity.out when RBAC_IDENTITY_ENABLED reads on alone, or
#     expected/<scenario>.after.permissions.out when RBAC_PERMISSIONS_ENABLED reads on too
#     (it needs RBAC_IDENTITY_ENABLED on, as src/lib/authz/flags.ts reads them). The fixture
#     itself is checked with checks.sql against expected/<scenario>.out before the run.
#
# Modes (several may be chained; each runs every scenario):
#   all       the startup list once
#   twice     the startup list twice in a row (the second run must change nothing)
#   parallel  two containers start the startup list at once (several webapp copies)
#   failure   the list once; then the marker row of the backfill under test is deleted
#             (with the data it wrote, when its skip reads the data: the Root choice),
#             a psql session holds LOCK TABLE <its table> IN ACCESS EXCLUSIVE MODE, and
#             only that backfill's line of the list runs again with lock_timeout=2000
#             appended to its own DATABASE_URL: it must log a failure, exit 0 and leave
#             no marker; the lock is released and a third run of the list completes it.
#             The lock covers only the backfill, never the fatal `db push`.
#   preview   the image's upgrade preview (scripts/rbac-upgrade-preview.mjs, as
#             ./redamon.sh update runs it) on the fixture before the list: it must write
#             nothing, exit 10 exactly when it has something to review (else 0), and name
#             what the run then wrote: its root, legacy_grants, tunnel_rows,
#             instance_settings, stdio_mcp, mcp_token_env_var and scanner_key sections,
#             reduced to one line per fact, diffed against preview_after.sql's lines.
#   serve-check  the list, then the image's server as `serve` boots it; every fixture
#             account signs in (or is refused, passwordless) and /api/auth/me's
#             capabilities must equal expected/<scenario>.capabilities[.identity|
#             .permissions].out, picked as the .after files are; a 7.7.x cookie ({sub,
#             role}, no sv, no sid, signed with the fake AUTH_SECRET) must answer the
#             same, one signed with another secret 401; /api/projects must list each
#             account's own projects only. The server is removed after each scenario.
#   downgrade the new image's list with every RBAC switch on, then RBAC state in every
#             table and column the release adds (downgrade_state.sql, dg-*@e2e.local) and a
#             device session revoked after a real sign-in; the new image's
#             `rbac-upgrade-preview.mjs --downgrade` must exit 10 and name it, its
#             `--downgrade-sql` must leave no `instance/` model id; then the pinned 7.7.2
#             image's list on the same database (its `db push --accept-data-loss`) must drop
#             every table and column the report listed and keep the 7.7.2 rows, and its
#             server must refuse the disabled and invited accounts, give a No-access member
#             a member's rights (fail open), hide the shared project from the collaborator
#             (fail closed) and accept the revoked session until AUTH_SECRET changes. Last,
#             the new image's list again: the tables come back, Root is chosen again
#             (unconfirmed), the instance settings and legacy grants are derived again, the
#             disabled account is active without a password and signs in after
#             scripts/reset-password.mjs. Publishes 127.0.0.1:3901, as serve-check does.
#   serve <scenario>   the list, then the image's server on 127.0.0.1:3901 with fake
#             secrets, until Ctrl-C: the disposable instance for destructive identity
#             checks (Root transfer, set-root, upgrade, downgrade). Webapp only: no
#             agent, recon or graph. Never part of a chain.
#   regen     rebuild every fixture from seed/<name>.sql with the pinned 7.7.2 image
#             and rewrite expected/<name>.out (review the diff before committing).
#   selftest  offline, no Docker: the capabilities oracles name every fixture account
#             and only known permissions and sets, and the preview reader and the 7.7.x
#             cookie minter give what they should on canned input.
#
# Everything runs in containers named rbac-upg-<pid>-* on a private network of their
# own (internal, except for serve), fed on stdin (snap Docker cannot read /tmp), and is
# removed on exit, Ctrl-C included, with the database's volume rbac-upg-<pid>-pgdata.
# The running stack is never touched. Fixture users share one synthetic password
# (README.md).
#
# Environment:
#   RBAC_UPGRADE_IMAGE      image under test (default redamon-webapp:latest)
#   RBAC_UPGRADE_OLD_IMAGE  pinned 7.7.2 image (default redamon-webapp:rbac-7.7.2)
#   RBAC_UPGRADE_SCENARIOS  scenario name regex (default: all)
#   RBAC_UPGRADE_FAIL_BACKFILL  the backfill the failure mode breaks: user-skill-toggles
#                           (default), rbac-legacy-grants, nuclei-template-owners,
#                           rbac-instance-settings, rbac-root or rbac-legacy-overrides (runs
#                           only with the permissions switch on)
#   RBAC_UPGRADE_PREVIEW_SCRIPT  a preview file fed on stdin to the image's node instead of
#                           the image's own copy (a working-tree preview before a rebuild)
#   RBAC_UPGRADE_FAIL_SCRIPT / _FAIL_MARKER / _FAIL_TABLE / _FAIL_LOG
#                           override that choice: its script, its AuditLog marker action,
#                           the table it reads inside the marker's transaction, and the
#                           regex of its failure log line
#   REDAMON_SHARED_TOOLS_COMPAT, RBAC_*_ENABLED   passed to every run and to serve when set
#
# Needs Docker and the images (preview, serve-check and selftest also python3); prints SKIP
# and exits 0 without them. Live suites (*_live.sh) are not part of the gate.
#
# Run:  bash tests/rbac_upgrade_live.sh all twice parallel failure preview serve-check
#       bash tests/rbac_upgrade_live.sh selftest
#       bash tests/rbac_upgrade_live.sh downgrade
#       RBAC_UPGRADE_FAIL_BACKFILL=rbac-legacy-grants bash tests/rbac_upgrade_live.sh failure
#       RBAC_UPGRADE_FAIL_BACKFILL=nuclei-template-owners bash tests/rbac_upgrade_live.sh failure
#       RBAC_UPGRADE_FAIL_BACKFILL=rbac-instance-settings bash tests/rbac_upgrade_live.sh failure
#       RBAC_UPGRADE_FAIL_BACKFILL=rbac-root bash tests/rbac_upgrade_live.sh failure
#       RBAC_IDENTITY_ENABLED=true bash tests/rbac_upgrade_live.sh all twice parallel failure preview serve-check
#       RBAC_IDENTITY_ENABLED=true RBAC_PERMISSIONS_ENABLED=true bash tests/rbac_upgrade_live.sh all twice parallel failure preview serve-check
#       RBAC_IDENTITY_ENABLED=true RBAC_PERMISSIONS_ENABLED=true \
#         RBAC_UPGRADE_FAIL_BACKFILL=rbac-legacy-overrides bash tests/rbac_upgrade_live.sh failure
#       RBAC_UPGRADE_SCENARIOS='^one_admin$' bash tests/rbac_upgrade_live.sh twice
#       bash tests/rbac_upgrade_live.sh serve several_admins
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FIX="$ROOT/tests/fixtures/rbac_upgrade"
IMAGE="${RBAC_UPGRADE_IMAGE:-redamon-webapp:latest}"
OLD_IMAGE="${RBAC_UPGRADE_OLD_IMAGE:-redamon-webapp:rbac-7.7.2}"
PG_IMAGE=postgres:16-alpine
SCENARIO_FILTER="${RBAC_UPGRADE_SCENARIOS:-}"
SERVE_PORT=3901

# Each backfill reads its table right after it finds no marker, inside the transaction
# that writes the marker: user_attack_skills for the user-skill toggles, users for the
# legacy grants, instance_settings for the instance settings and the Root. The Root choice
# skips on its data, not on its marker, and writes one only when a scenario has an admin
# with a password: d_rows is how many marker rows the first run left, d_undo removes the
# Root it chose so the failed run and the third one choose again.
d_rows='SELECT 1'; d_undo=''
case "${RBAC_UPGRADE_FAIL_BACKFILL:-user-skill-toggles}" in
  user-skill-toggles)
    d_script=backfill-user-skill-toggles.mjs; d_marker=system.user_skill_toggles_backfill
    d_table=user_attack_skills; d_log='\[skills\] could not backfill user-skill toggles' ;;
  rbac-legacy-grants)
    d_script=backfill-rbac-legacy-grants.mjs; d_marker=system.rbac_legacy_grants_backfill
    d_table=users; d_log='\[rbac\] could not backfill legacy grants' ;;
  nuclei-template-owners)
    # It reads nuclei_templates only after a marker that found files, and no fixture holds a
    # template file: what it reads with no marker is audit_log, looking for one.
    d_script=backfill-nuclei-template-owners.mjs; d_marker=system.nuclei_template_owners_backfill
    d_table=audit_log; d_log='\[rbac\] could not record the nuclei template owners' ;;
  rbac-instance-settings)
    d_script=backfill-rbac-instance-settings.mjs; d_marker=system.rbac_instance_settings_backfill
    d_table=instance_settings; d_log='\[rbac\] could not fill the instance settings' ;;
  rbac-root)
    d_script=backfill-rbac-root.mjs; d_marker=system.rbac_root_assigned
    d_table=instance_settings; d_log='\[rbac\] could not recognise the Root'
    d_rows="SELECT least(count(*), 1) FROM users WHERE role = 'admin' AND password <> ''"
    d_undo="UPDATE instance_settings SET root_user_id = NULL, root_confirmed_at = NULL, root_assigned_by = NULL" ;;
  rbac-legacy-overrides)
    # Writes its marker only with the permissions switch on; the fixtures hold no Keep, so it
    # writes no override to undo.
    d_script=backfill-rbac-legacy-overrides.mjs; d_marker=system.rbac_legacy_overrides_backfill
    d_table=users; d_log='\[rbac\] could not convert the legacy grants' ;;
  *) echo "RBAC_UPGRADE_FAIL_BACKFILL: user-skill-toggles, rbac-legacy-grants, nuclei-template-owners, rbac-instance-settings, rbac-root or rbac-legacy-overrides" >&2; exit 2 ;;
esac
FAIL_SCRIPT="${RBAC_UPGRADE_FAIL_SCRIPT:-$d_script}"
FAIL_MARKER="${RBAC_UPGRADE_FAIL_MARKER:-$d_marker}"
FAIL_TABLE="${RBAC_UPGRADE_FAIL_TABLE:-$d_table}"
FAIL_LOG="${RBAC_UPGRADE_FAIL_LOG:-$d_log}"

# Audit rows the upgrade writes by design: left out of the row-count comparison and pinned
# instead, by count, in checks.sql's markers and by checks_after.sql.
UPGRADE_AUDIT_ACTIONS=(system.rbac_legacy_grants_cutoff system.rbac_legacy_grants_backfill
                       system.nuclei_template_owners_backfill system.rbac_instance_settings_backfill
                       system.rbac_root_assigned system.rbac_legacy_overrides_backfill)
UPGRADE_AUDIT_SQL="$(printf "'%s'," "${UPGRADE_AUDIT_ACTIONS[@]}")"
UPGRADE_AUDIT_SQL="${UPGRADE_AUDIT_SQL%,}"

# Obvious fakes: the containers live only for this run, on a private network.
PG_PASSWORD=rbac-upgrade-fake-pg
FIXTURE_PASSWORD=rbac-upgrade-pass-0001
FAKE_AUTH_SECRET=rbac-upgrade-fake-auth-secret-0001
FAKE_INTERNAL_API_KEY=rbac-upgrade-fake-internal-key-0001
FAKE_SCANNER_API_KEY=rbac-upgrade-fake-scanner-key-0001
SWITCHES=(REDAMON_SHARED_TOOLS_COMPAT RBAC_IDENTITY_ENABLED RBAC_PERMISSIONS_ENABLED
          RBAC_SHARING_ENABLED RBAC_SHARING_WRITE_ENABLED RBAC_GOVERNANCE_ENABLED)
# serve-check's control: a login cookie this secret signs must be refused.
WRONG_AUTH_SECRET=rbac-upgrade-wrong-auth-secret-0001
AUTH_COOKIE=redamon-auth
PREVIEW_SCRIPT="${RBAC_UPGRADE_PREVIEW_SCRIPT:-}"
if [ -n "$PREVIEW_SCRIPT" ]; then
  [[ "$PREVIEW_SCRIPT" = /* ]] || PREVIEW_SCRIPT="$ROOT/$PREVIEW_SCRIPT"
  [ -f "$PREVIEW_SCRIPT" ] || { echo "RBAC_UPGRADE_PREVIEW_SCRIPT: no file $PREVIEW_SCRIPT" >&2; exit 2; }
fi

# The JSON and text work of preview, serve-check and selftest:
#   mint <secret> <sub> <role>      a 7.7.x login token: {sub, role}, iat, a 7-day exp, HS256
#   expand <catalog> <oracle>       the lines serve-check must collect for a capabilities oracle
#   caps <me.json> <email> <way>    those lines from one /api/auth/me answer
#   projects <list.json> <email>    "<email>|<project id>" per project /api/projects lists
#   preview <file>                  the preview's sections reduced to preview_after.sql's lines
#   selftest <fixtures> <catalog>   the offline checks of the selftest mode
IFS= read -r -d '' PY_HELPER <<'PY'
import base64, hashlib, hmac, json, os, re, sys, time

def b64(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b'=').decode()

def mint(secret, sub, role, now=None):
    now = int(time.time()) if now is None else now
    seg = lambda o: b64(json.dumps(o, separators=(',', ':')).encode())
    signed = seg({'alg': 'HS256'}) + '.' + seg({'sub': sub, 'role': role, 'iat': now, 'exp': now + 7 * 86400})
    return signed + '.' + b64(hmac.new(secret.encode(), signed.encode(), hashlib.sha256).digest())

def oracle(path):
    rows = []
    for n, line in enumerate(open(path), 1):
        line = line.strip()
        if line:
            email, _, expr = line.partition('|')
            rows.append((n, email, expr.split()))
    return rows

# An oracle line is `<email>|<tokens>`, applied left to right: a built-in set id or `root` /
# `root_unconfirmed` (every permission / all but the Root-only ones) adds its permissions,
# `+<permission>` adds one, `-<permission>` removes one; `login_refused` alone: no sign-in.
def expand(catalog, path):
    perms = catalog['permissions']
    sets = {s['id']: s['permissions'] for s in catalog['sets']}
    out = []
    for n, email, tokens in oracle(path):
        if tokens == ['login_refused']:
            out.append(f'{email}|login 401')
            continue
        held = set()
        for t in tokens:
            if t == 'root':
                held |= set(perms)
            elif t == 'root_unconfirmed':
                held |= {p for p, meta in perms.items() if not meta['rootOnly']}
            elif t in sets:
                held |= set(sets[t])
            elif t[:1] in ('+', '-') and t[1:] in perms:
                (held.add if t[0] == '+' else held.discard)(t[1:])
            else:
                raise SystemExit(f'{path}:{n}: unknown token {t!r}')
        for way in ('fresh', 'old'):
            out.append(f'{email}|{way}|account {email}')
            out.extend(f'{email}|{way}|{p}' for p in held)
    return out

def caps(path, email, way):
    try:
        body = json.load(open(path))
    except ValueError:
        body = None
    if not isinstance(body, dict):
        return [f'{email}|{way}|unreadable answer']
    held = body.get('capabilities')
    lines = [f"{email}|{way}|account {body.get('email')}"]
    if not isinstance(held, list):
        return lines + [f'{email}|{way}|capabilities {held!r}']
    return lines + [f'{email}|{way}|{p}' for p in held]

def projects(path, email):
    try:
        body = json.load(open(path))
    except ValueError:
        return [f'{email}|unreadable answer']
    if not isinstance(body, list):
        return [f'{email}|not a list']
    return [f"{email}|{p.get('id')}" for p in body]

GRANT_LABELS = {'Kali terminal': 'kali_terminal', 'all shell sessions': 'shell_sessions', 'tunnel settings': 'tunnels'}
HEADS = [('root', 'Root: '), ('legacy_grants', 'Shared tools existing members keep'),
         ('tunnel_rows', 'Tunnel settings saved in accounts'), ('instance_settings', 'Instance settings'),
         ('stdio_mcp', 'stdio MCP servers that stop loading'), ('mcp_token_env_var', 'MCP servers that lose the bearer'),
         ('scanner_key', 'SCANNER_API_KEY is ')]
ACCOUNT_ROW = re.compile(r'^    (\S+@\S+)(?: \((admin|member)\))?\s{2,}(.+)$')

def preview(lines):
    """A section starts at a two-space line; its rows are the four-space lines under it."""
    out, section = [], None
    for line in (l.rstrip('\n') for l in lines):
        if line.startswith('  ') and not line.startswith('   '):
            head = line[2:]
            section = next((s for s, start in HEADS if head.startswith(start)), None)
            if section == 'root':
                only = re.match(r'Root: (\S+), the only admin with a password', head)
                oldest = re.match(r'Root: (\S+), the oldest of (\d+) admins with a password', head)
                if only: out.append(f'root|{only.group(1)}|only_admin|1')
                elif oldest: out.append(f'root|{oldest.group(1)}|oldest_admin|{oldest.group(2)}')
                elif head.startswith('Root: none yet'): out.append('root|none')
                else: out.append(f'root|unrecognised|{head}')
            elif section == 'scanner_key':
                out.append('scanner_key|' + ('missing' if 'is not set' in head else 'set'))
            continue
        if not line.startswith('    '):
            continue
        if section == 'instance_settings':
            m = re.match(r'^    (tunnel|TrafficMind, egress, SCA)\s{2,}(.+)$', line)
            if m:
                key, value = ('tunnel' if m.group(1) == 'tunnel' else 'capture'), m.group(2)
                if value.startswith('none saved'):
                    out.append(f'instance_settings|{key}|none')
                else:
                    count = re.search(r'; (\d+) accounts hold one' if key == 'tunnel' else r'the latest of (\d+) admin rows', value)
                    out.append(f"instance_settings|{key}|{value.split()[0].rstrip(',')}|{count.group(1) if count else 1}")
            continue
        m = ACCOUNT_ROW.match(line)
        if not m:
            continue
        email, role, rest = m.groups()
        if section == 'legacy_grants':
            grants = sorted(GRANT_LABELS.get(g.strip(), '?' + g.strip()) for g in rest.split(','))
            out.append(f"legacy_grants|{email}|{','.join(grants)}")
        elif section == 'tunnel_rows':
            kinds, state = (re.split(r'\s{2,}', rest) + ['', ''])[:2]
            out.append(f'tunnel_rows|{email}|{role}|{kinds}|{state}')
            if rest.endswith("<- the agent's tunnel"):
                out.append(f'tunnel_pick|{email}')
        elif section == 'stdio_mcp':
            out.extend(f'stdio_mcp|{email}|{name}' for name in rest.split(', '))
        elif section == 'mcp_token_env_var':
            for entry in rest.split(', '):
                e = re.match(r'^(.*) \(([^()]*)\)$', entry)
                out.append(f'mcp_token_env_var|{email}|{e.group(1)}|{e.group(2)}' if e else f'mcp_token_env_var|{email}|?{entry}')
    return out

SAMPLE_FULL = """RBAC upgrade preview (read-only: nothing has been changed)

  Accounts: 2 admins, 2 members who can sign in, 0 without a password.

  Root: upg-admin-a@e2e.local, the oldest of 2 admins with a password, chosen automatically at the next start.
    upg-admin-a@e2e.local  <- proposed
    upg-admin-b@e2e.local
    Nothing changes while RBAC_IDENTITY_ENABLED is off. With it on, ./redamon.sh update confirms Root;
    ./redamon.sh set-root <email> picks another admin.

  Shared tools existing members keep (legacy grants; admins review them on the Users page):
    upg-member-a@e2e.local  Kali terminal, all shell sessions, tunnel settings
    upg-member-b@e2e.local  Kali terminal, all shell sessions
    Accounts created after the upgrade get none.

  Tunnel settings saved in accounts:
    upg-member-b@e2e.local (member)  chisel  enabled  saved 2026-03-02  <- the agent's tunnel
    upg-member-a@e2e.local (member)  ngrok  disabled  saved 2026-03-10
    After the upgrade only admins and members keeping the tunnel grant change it.

  Instance settings, copied at the next start from the accounts' settings (which stay):
    tunnel                    upg-member-b@e2e.local (member), saved 2026-03-02; 2 accounts hold one
    TrafficMind, egress, SCA  upg-admin-b@e2e.local, saved 2026-04-01, the latest of 2 admin rows
    While RBAC_IDENTITY_ENABLED is off the accounts' settings stay in force; each start copies them again.

  stdio MCP servers that stop loading (they run inside the agent; only admins may add them):
    upg-member-a@e2e.local  upg stdio, upg other (disabled)
    They stay saved in those accounts.

  MCP servers that lose the bearer they read from the agent's environment:
    upg-member-b@e2e.local  upg http (UPG_TOKEN)

  SCANNER_API_KEY is set: scan containers use it, never the master key.

  What changes for members:
    - Emergency stop stops only their own agent runs; admins still stop everyone's.
"""
SAMPLE_FULL_LINES = [
    'root|upg-admin-a@e2e.local|oldest_admin|2',
    'legacy_grants|upg-member-a@e2e.local|kali_terminal,shell_sessions,tunnels',
    'legacy_grants|upg-member-b@e2e.local|kali_terminal,shell_sessions',
    'tunnel_rows|upg-member-b@e2e.local|member|chisel|enabled', 'tunnel_pick|upg-member-b@e2e.local',
    'tunnel_rows|upg-member-a@e2e.local|member|ngrok|disabled',
    'instance_settings|tunnel|upg-member-b@e2e.local|2', 'instance_settings|capture|upg-admin-b@e2e.local|2',
    'stdio_mcp|upg-member-a@e2e.local|upg stdio', 'stdio_mcp|upg-member-a@e2e.local|upg other (disabled)',
    'mcp_token_env_var|upg-member-b@e2e.local|upg http|UPG_TOKEN', 'scanner_key|set',
]
SAMPLE_SHORT = """RBAC upgrade preview (read-only: nothing has been changed)
  Nothing changes for existing accounts (every account that can sign in is an admin).

  Root: upg-admin-a@e2e.local, the only admin with a password, chosen automatically at the next start.
    After the restart this update confirms it.

  Instance settings, copied at the next start from the accounts' settings (which stay):
    tunnel                    none saved (off)
    TrafficMind, egress, SCA  upg-admin-a@e2e.local, saved 2026-01-05
    With RBAC_IDENTITY_ENABLED on this copy is the one in force; admins change it in Global Settings.

  SCANNER_API_KEY is not set in .env: scans will refuse to start without it.
"""
SAMPLE_SHORT_LINES = ['root|upg-admin-a@e2e.local|only_admin|1', 'instance_settings|tunnel|none',
                      'instance_settings|capture|upg-admin-a@e2e.local|1', 'scanner_key|missing']
SAMPLE_NONE = "  Root: none yet (no admin has a password); ./redamon.sh create-admin makes one, and it becomes Root.\n"

def fixture_accounts(path):
    """The emails of expected/<scenario>.out's users section: the fixture's own oracle."""
    emails, inside = [], False
    for line in open(path):
        if line.startswith('== '):
            inside = line.startswith('== users ')
        elif inside and line.strip():
            emails.append(line.split('|', 1)[0])
    return emails

def selftest(fixtures, catalog_path, added_sample):
    results = []
    check = lambda label, ok: results.append((label, bool(ok)))
    check('the NOTE lines name only the tables a run added, whatever the host collation',
          added_sample == 'conversation_shares user_sessions')
    catalog = json.load(open(catalog_path))
    scenarios = sorted(f[:-4] for f in os.listdir(os.path.join(fixtures, 'seed')) if f.endswith('.sql'))
    for scn in scenarios:
        accounts = sorted(fixture_accounts(os.path.join(fixtures, 'expected', f'{scn}.out')))
        for suffix in ('', '.identity', '.permissions'):
            name = f'expected/{scn}.capabilities{suffix}.out'
            path = os.path.join(fixtures, name)
            if not os.path.isfile(path):
                check(f'{name} exists', False)
                continue
            check(f'{name} names every fixture account once, and only those',
                  sorted(email for _, email, _ in oracle(path)) == accounts)
            try:
                expand(catalog, path)
                check(f'{name} names only known sets and permissions', True)
            except SystemExit as err:
                check(f'{name} names only known sets and permissions ({err})', False)
    check('the preview reader reduces a full report', preview(SAMPLE_FULL.splitlines()) == SAMPLE_FULL_LINES)
    check('the preview reader reduces a short report', preview(SAMPLE_SHORT.splitlines()) == SAMPLE_SHORT_LINES)
    check('the preview reader reads "no Root yet"', preview(SAMPLE_NONE.splitlines()) == ['root|none'])
    token = mint('selftest-secret', 'upg-member-a', 'standard', now=1_700_000_000)
    head, body, sig = token.split('.')
    claims = json.loads(base64.urlsafe_b64decode(body + '=' * (-len(body) % 4)))
    check('the minted cookie is HS256-signed with the secret', hmac.compare_digest(
        sig, b64(hmac.new(b'selftest-secret', f'{head}.{body}'.encode(), hashlib.sha256).digest())))
    check('the minted cookie carries {sub, role, iat, exp} and no sv or sid',
          claims == {'sub': 'upg-member-a', 'role': 'standard', 'iat': 1_700_000_000, 'exp': 1_700_604_800})
    for label, ok in results:
        print(f"  {'PASS' if ok else 'FAIL'} {label}")
    failed = sum(1 for _, ok in results if not ok)
    print(f'== RESULT: {len(results) - failed} passed, {failed} failed ==')
    return 1 if failed else 0

def emit(lines):
    for line in lines:
        print(line)

cmd, args = sys.argv[1], sys.argv[2:]
if cmd == 'mint':
    print(mint(*args))
elif cmd == 'expand':
    emit(expand(json.load(open(args[0])), args[1]))
elif cmd == 'caps':
    emit(caps(*args))
elif cmd == 'projects':
    emit(projects(*args))
elif cmd == 'preview':
    emit(preview(open(args[0])))
elif cmd == 'selftest':
    sys.exit(selftest(*args))
PY
py() { python3 -c "$PY_HELPER" "$@"; }
# comm needs both inputs in its own collation; Postgres lists in byte order, which an en_US host
# disagrees with ('_' sorts after letters there), and comm then reports tables that were already there.
added_lines() { # before now -> the lines of now that before lacks
  LC_ALL=C comm -13 <(printf '%s\n' "$1" | LC_ALL=C sort) <(printf '%s\n' "$2" | LC_ALL=C sort)
}

PFX="rbac-upg-$$"
NET="$PFX-net"
PG="$PFX-pg"
LABEL="redamon.rbac-upgrade=$PFX"
DB_URL="postgresql://postgres:${PG_PASSWORD}@${PG}:5432/redamon"

usage() {
  echo "usage: bash tests/rbac_upgrade_live.sh <all|twice|parallel|failure|preview|serve-check|downgrade>... | serve <scenario> | regen | selftest" >&2
  echo "  scenarios: $(cd "$FIX/seed" 2>/dev/null && ls -- *.sql 2>/dev/null | sed 's/\.sql$//' | tr '\n' ' ')" >&2
  exit 2
}

[ $# -ge 1 ] || usage
MODES=()
SERVE_SCENARIO=""
case "$1" in
  serve)
    [ $# -eq 2 ] || usage
    SERVE_SCENARIO="$2"
    [ -f "$FIX/$SERVE_SCENARIO.sql" ] || { echo "unknown scenario: $SERVE_SCENARIO" >&2; usage; }
    MODES=(serve) ;;
  regen|selftest)
    [ $# -eq 1 ] || usage
    MODES=("$1") ;;
  *)
    for m in "$@"; do
      case "$m" in all|twice|parallel|failure|preview|serve-check|downgrade) MODES+=("$m") ;; *) usage ;; esac
    done ;;
esac
HAS_SERVE_CHECK=0
NEEDS_PYTHON=0
for m in "${MODES[@]}"; do
  case "$m" in
    serve-check) HAS_SERVE_CHECK=1; NEEDS_PYTHON=1 ;;
    downgrade) HAS_SERVE_CHECK=1 ;; # publishes the server's port too
    preview|selftest) NEEDS_PYTHON=1 ;;
  esac
done
if [ "$NEEDS_PYTHON" -eq 1 ] && ! command -v python3 >/dev/null 2>&1; then
  echo "SKIP: python3 is not available (preview, serve-check and selftest read JSON and text with it)"
  exit 0
fi

SCENARIOS=()
while IFS= read -r f; do
  name="$(basename "$f" .sql)"
  if [ -n "$SCENARIO_FILTER" ] && ! [[ "$name" =~ $SCENARIO_FILTER ]]; then continue; fi
  SCENARIOS+=("$name")
done < <(find "$FIX/seed" -maxdepth 1 -name '*.sql' | LC_ALL=C sort)
[ "${MODES[0]}" = serve ] && SCENARIOS=("$SERVE_SCENARIO")
[ "${#SCENARIOS[@]}" -gt 0 ] || { echo "no scenario selected" >&2; exit 2; }

if [ "${MODES[0]}" = selftest ]; then
  echo "== selftest (offline)"
  # Postgres lists names in byte order, where conversation_shares precedes conversations; an
  # en_US host sorts them the other way round.
  added_sample="$(LC_ALL=en_US.UTF-8 added_lines $'conversations\nprojects\nusers' \
    $'conversation_shares\nconversations\nprojects\nuser_sessions\nusers' 2>/dev/null | tr '\n' ' ' | sed 's/ $//')"
  py selftest "$FIX" "$ROOT/webapp/src/lib/authz/permissionCatalog.json" "$added_sample"
  exit $?
fi

# ---- self-skip without Docker or the images ------------------------------------
if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
  echo "SKIP: Docker is not available"
  exit 0
fi
for img in "$IMAGE" "$OLD_IMAGE" "$PG_IMAGE"; do
  if ! docker image inspect "$img" >/dev/null 2>&1; then
    echo "SKIP: image $img is absent (see tests/fixtures/rbac_upgrade/README.md)"
    exit 0
  fi
done
if { [ "${MODES[0]}" = serve ] || [ "$HAS_SERVE_CHECK" -eq 1 ]; } && \
   curl -s -m 2 -o /dev/null "http://127.0.0.1:$SERVE_PORT/" 2>/dev/null; then
  echo "port $SERVE_PORT is already answering: stop that server first" >&2
  exit 2
fi

TMP="$(mktemp -d)"
CLEANED_UP=0
cleanup() {
  [ "$CLEANED_UP" -eq 1 ] && return
  CLEANED_UP=1
  [ -n "${SLEEP_PID:-}" ] && kill "$SLEEP_PID" 2>/dev/null
  local ids
  ids="$(docker ps -aq --filter "label=$LABEL" 2>/dev/null)"
  [ -n "$ids" ] && docker rm -f -v $ids >/dev/null 2>&1
  # Named volumes outlive `rm -v`: the database's is removed by its label once its container is gone.
  ids="$(docker volume ls -q --filter "label=$LABEL" 2>/dev/null)"
  [ -n "$ids" ] && docker volume rm $ids >/dev/null 2>&1
  docker network rm "$NET" >/dev/null 2>&1
  rm -rf "$TMP"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

PASS=0
FAIL=0
pass() { PASS=$((PASS + 1)); echo "  PASS $1"; }
fail() { FAIL=$((FAIL + 1)); echo "  FAIL $1"; }

switch_args() {
  local s
  for s in "${SWITCHES[@]}"; do
    [ -n "${!s+x}" ] && printf '%s\n' -e "$s=${!s}"
  done
}
mapfile -t SWITCH_ARGS < <(switch_args)

# A switch as src/lib/authz/flags.ts reads it: true, 1 or yes, any case, spaces trimmed.
switch_on() {
  local v="${!1:-}"
  v="$(printf '%s' "$v" | tr '[:upper:]' '[:lower:]' | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
  [[ "$v" == true || "$v" == 1 || "$v" == yes ]]
}
# The boot records the identity switch in the instance settings marker, and with the permissions
# switch on too it converts the legacy grants: each combination's expected state is its own file.
AFTER_SUFFIX=after
if switch_on RBAC_IDENTITY_ENABLED; then
  AFTER_SUFFIX=after.identity
  switch_on RBAC_PERMISSIONS_ENABLED && AFTER_SUFFIX=after.permissions
fi

start_infra() { # internal | public
  local net_flag=--internal
  [ "$1" = public ] && net_flag=
  docker network create $net_flag --label "$LABEL" "$NET" >/dev/null || { echo "network create failed"; exit 1; }
  # A named, labelled volume instead of the image's anonymous one: cleanup removes it by label, and a
  # run killed before its trap leaves a volume that names its run (rbac-upg-<pid>-pgdata).
  docker volume create --label "$LABEL" "$PFX-pgdata" >/dev/null || { echo "volume create failed"; exit 1; }
  docker run -d --name "$PG" --label "$LABEL" --network "$NET" -v "$PFX-pgdata:/var/lib/postgresql/data" \
    -e POSTGRES_PASSWORD="$PG_PASSWORD" -e POSTGRES_DB=redamon "$PG_IMAGE" >/dev/null \
    || { echo "postgres start failed"; exit 1; }
  local i
  for i in $(seq 1 60); do
    # pg_isready answers during the init server too; a real query on the final server
    # is the readiness signal.
    docker exec "$PG" psql -X -U postgres -d redamon -qAt -c 'SELECT 1' >/dev/null 2>&1 \
      && docker exec "$PG" pg_isready -h 127.0.0.1 -U postgres >/dev/null 2>&1 && return 0
    sleep 1
  done
  echo "postgres did not become ready"; exit 1
}

psql_db() { docker exec -i "$PG" psql -X -U postgres -d redamon -v ON_ERROR_STOP=1 -qAt -F '|' "$@"; }

reset_db() {
  docker exec "$PG" psql -X -U postgres -d postgres -v ON_ERROR_STOP=1 -q \
    -c 'DROP DATABASE IF EXISTS redamon WITH (FORCE)' -c 'CREATE DATABASE redamon' >/dev/null
}

# The startup list as the image writes it, minus `exec node server.js`. The guard stops
# the harness from silently skipping a step a later Dockerfile appends after the server.
LIST_CMD='tail -n 1 /app/entrypoint.sh | grep -qx "exec node server.js" || { echo "[harness] /app/entrypoint.sh does not end with exec node server.js"; exit 97; }; sed "\$d" /app/entrypoint.sh | sh'

run_list() { # image log_file [url_suffix] -> exit code of the list
  docker run --rm --label "$LABEL" --network "$NET" \
    -e DATABASE_URL="$DB_URL${3:-}" -e CHECKPOINT_DISABLE=1 "${SWITCH_ARGS[@]}" \
    --entrypoint sh "$1" -c "$LIST_CMD" > "$2" 2>&1
}

show_log() { sed -n '1,60p' "$1" | sed 's/^/    | /'; }

# ---- snapshots ---------------------------------------------------------------------
capture_shape() { # records the tables and users columns that exist before a run
  TABLES="$(psql_db -c "SELECT table_name FROM information_schema.tables
    WHERE table_schema = 'public' AND table_type = 'BASE TABLE' ORDER BY 1")"
  USER_COLS="$(psql_db -c "SELECT column_name FROM information_schema.columns
    WHERE table_schema = 'public' AND table_name = 'users' ORDER BY column_name")"
}

snapshot() { # out_file: row counts of the recorded tables, users column definitions and rows
  local t c count_sql="" col_list="" col_select=""
  for t in $TABLES; do
    local only=""
    [ "$t" = audit_log ] && only=" WHERE action NOT IN ($UPGRADE_AUDIT_SQL)"
    count_sql+="${count_sql:+ UNION ALL }SELECT '$t', count(*) FROM \"$t\"$only"
  done
  for c in $USER_COLS; do
    col_list+="${col_list:+, }'$c'"
    col_select+="${col_select:+, }\"$c\""
  done
  {
    echo "== row counts"
    psql_db -c "$count_sql ORDER BY 1" 2>&1
    echo "== users columns"
    psql_db -c "SELECT column_name, data_type, is_nullable, coalesce(column_default, '')
      FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'users'
      AND column_name IN ($col_list) ORDER BY column_name" 2>&1
    echo "== users rows"
    psql_db -c "SELECT $col_select FROM users ORDER BY id" 2>&1
  } > "$1"
}

note_additions() {
  local now_tables now_cols x
  now_tables="$(psql_db -c "SELECT table_name FROM information_schema.tables
    WHERE table_schema = 'public' AND table_type = 'BASE TABLE' ORDER BY 1")"
  now_cols="$(psql_db -c "SELECT column_name FROM information_schema.columns
    WHERE table_schema = 'public' AND table_name = 'users' ORDER BY column_name")"
  for x in $(added_lines "$TABLES" "$now_tables"); do
    echo "  NOTE table added: $x"
  done
  for x in $(added_lines "$USER_COLS" "$now_cols"); do
    echo "  NOTE users column added: $x"
  done
}

assert_same() { # label expected_file actual_file
  if diff -u "$2" "$3" > "$TMP/diff"; then
    pass "$1"
  else
    fail "$1"
    sed -n '1,40p' "$TMP/diff" | sed 's/^/    /'
  fi
}

run_checks() { psql_db < "$FIX/checks.sql" > "$1" 2>&1; }
run_checks_after() { { psql_db < "$FIX/checks.sql"; psql_db < "$FIX/checks_after.sql"; } > "$1" 2>&1; }

prepare() { # scenario: a fresh database holding the fixture, its shape and snapshot
  reset_db || { fail "$1: database reset"; return 1; }
  if ! psql_db < "$FIX/$1.sql" > "$TMP/load.log" 2>&1; then
    fail "$1: fixture loads"; show_log "$TMP/load.log"; return 1
  fi
  capture_shape
  snapshot "$TMP/before.txt"
  run_checks "$TMP/checks.txt"
  assert_same "$1: fixture holds what expected/$1.out records" "$FIX/expected/$1.out" "$TMP/checks.txt"
}

verify() { # scenario label: nothing else changed, scenario checks
  snapshot "$TMP/after.txt"
  assert_same "$1 $2: row counts and users columns unchanged" "$TMP/before.txt" "$TMP/after.txt"
  note_additions
  run_checks_after "$TMP/checks.txt"
  assert_same "$1 $2: checks.sql + checks_after.sql match expected/$1.$AFTER_SUFFIX.out" "$FIX/expected/$1.$AFTER_SUFFIX.out" "$TMP/checks.txt"
}

list_ok() { # scenario label log rc
  if [ "$4" -eq 0 ]; then pass "$1 $2: startup list exits 0"; return 0; fi
  fail "$1 $2: startup list exits 0 (got $4)"; show_log "$3"; return 1
}

# ---- modes ---------------------------------------------------------------------------
mode_all() {
  prepare "$1" || return
  run_list "$IMAGE" "$TMP/run1.log"; list_ok "$1" "run 1" "$TMP/run1.log" $? || return
  verify "$1" "run 1"
}

mode_twice() {
  prepare "$1" || return
  local i
  for i in 1 2; do
    run_list "$IMAGE" "$TMP/run$i.log"; list_ok "$1" "run $i" "$TMP/run$i.log" $? || return
    verify "$1" "run $i"
  done
}

mode_parallel() {
  prepare "$1" || return
  local a="$PFX-par-a" b="$PFX-par-b" ra rb c
  for c in "$a" "$b"; do
    docker run -d --name "$c" --label "$LABEL" --network "$NET" \
      -e DATABASE_URL="$DB_URL" -e CHECKPOINT_DISABLE=1 "${SWITCH_ARGS[@]}" \
      --entrypoint sh "$IMAGE" -c "$LIST_CMD" >/dev/null || { fail "$1 parallel: start $c"; return; }
  done
  ra="$(docker wait "$a")"; rb="$(docker wait "$b")"
  docker logs "$a" > "$TMP/par-a.log" 2>&1; docker logs "$b" > "$TMP/par-b.log" 2>&1
  docker rm -f -v "$a" "$b" >/dev/null 2>&1
  list_ok "$1" "parallel copy A" "$TMP/par-a.log" "$ra"
  list_ok "$1" "parallel copy B" "$TMP/par-b.log" "$rb"
  verify "$1" "parallel"
}

lock_held() { # 1 when the lock session holds its ACCESS EXCLUSIVE lock
  psql_db -c "SELECT count(*) FROM pg_locks l JOIN pg_class c ON c.oid = l.relation
    WHERE c.relname = '$FAIL_TABLE' AND l.mode = 'AccessExclusiveLock' AND l.granted"
}

mode_failure() {
  prepare "$1" || return
  run_list "$IMAGE" "$TMP/run1.log"; list_ok "$1" "failure run 1" "$TMP/run1.log" $? || return
  verify "$1" "failure run 1"

  local deleted want
  want="$(psql_db -c "$d_rows")"
  deleted="$(psql_db -c "WITH d AS (DELETE FROM audit_log WHERE action = '$FAIL_MARKER' RETURNING 1)
    SELECT count(*) FROM d")"
  if [ -n "$want" ] && [ "$deleted" = "$want" ]; then pass "$1 failure: marker $FAIL_MARKER deleted ($deleted row(s))"
  else fail "$1 failure: marker $FAIL_MARKER deleted (rows: ${deleted:-none}, expected ${want:-?})"; return; fi
  if [ -n "$d_undo" ]; then
    if psql_db -c "$d_undo" >/dev/null; then pass "$1 failure: the data it wrote undone too"
    else fail "$1 failure: the data it wrote undone too"; return; fi
  fi

  docker exec -d -e PGAPPNAME="$PFX-lock" "$PG" psql -X -U postgres -d redamon -qAt \
    -c "BEGIN; LOCK TABLE \"$FAIL_TABLE\" IN ACCESS EXCLUSIVE MODE; SELECT pg_sleep(600); COMMIT;"
  local i
  for i in $(seq 1 40); do [ "$(lock_held)" = 1 ] && break; sleep 0.25; done
  if [ "$(lock_held)" = 1 ]; then pass "$1 failure: $FAIL_TABLE locked by a second session"
  else fail "$1 failure: $FAIL_TABLE locked by a second session"; return; fi

  local start rc elapsed
  start=$(date +%s)
  docker run --rm --label "$LABEL" --network "$NET" \
    -e DATABASE_URL="$DB_URL?options=-c%20lock_timeout%3D2000" -e CHECKPOINT_DISABLE=1 "${SWITCH_ARGS[@]}" \
    --entrypoint sh "$IMAGE" -c "grep -F 'scripts/$FAIL_SCRIPT' /app/entrypoint.sh | sh" \
    > "$TMP/fail.log" 2>&1
  rc=$?
  elapsed=$(( $(date +%s) - start ))
  if [ "$rc" -eq 0 ]; then pass "$1 failure: $FAIL_SCRIPT exits 0 under the lock (${elapsed}s)"
  else fail "$1 failure: $FAIL_SCRIPT exits 0 under the lock (got $rc)"; show_log "$TMP/fail.log"; fi
  if grep -Eq -- "$FAIL_LOG" "$TMP/fail.log" && grep -q 'lock timeout' "$TMP/fail.log"; then
    pass "$1 failure: the failure is logged (lock timeout)"
  else
    fail "$1 failure: the failure is logged (lock timeout)"; show_log "$TMP/fail.log"
  fi

  psql_db -c "SELECT pg_cancel_backend(pid) FROM pg_stat_activity WHERE application_name = '$PFX-lock'" >/dev/null
  for i in $(seq 1 40); do [ "$(lock_held)" = 0 ] && break; sleep 0.25; done
  if [ "$(lock_held)" = 0 ]; then pass "$1 failure: lock released"
  else fail "$1 failure: lock released"; return; fi
  # Read after the release: the nuclei-template-owners preset locks audit_log itself.
  if [ "$(psql_db -c "SELECT count(*) FROM audit_log WHERE action = '$FAIL_MARKER'")" = 0 ]; then
    pass "$1 failure: no marker written by the failed run"
  else
    fail "$1 failure: no marker written by the failed run"
  fi

  run_list "$IMAGE" "$TMP/run3.log"; list_ok "$1" "failure run 3" "$TMP/run3.log" $? || return
  verify "$1" "failure run 3 (backfill completed)"
}

# The list, then the image's server on 127.0.0.1:$SERVE_PORT with the fake secrets, until it
# answers /api/health. Non-zero (with a FAIL) when any of it does not.
serve_boot() {
  local scn="$1" web="$PFX-web" i code
  prepare "$scn" || return 1
  run_list "$IMAGE" "$TMP/run1.log"; list_ok "$scn" "serve list" "$TMP/run1.log" $? || return 1
  verify "$scn" "serve list"
  if ! docker run -d --name "$web" --label "$LABEL" --network "$NET" -p "127.0.0.1:$SERVE_PORT:3000" \
    -e DATABASE_URL="$DB_URL" -e CHECKPOINT_DISABLE=1 \
    -e AUTH_SECRET="$FAKE_AUTH_SECRET" -e INTERNAL_API_KEY="$FAKE_INTERNAL_API_KEY" \
    -e SCANNER_API_KEY="$FAKE_SCANNER_API_KEY" "${SWITCH_ARGS[@]}" \
    --entrypoint sh "$IMAGE" -c 'eval "$(tail -n 1 /app/entrypoint.sh)"' >/dev/null; then
    fail "$scn: server starts"; return 1
  fi
  for i in $(seq 1 120); do
    code="$(curl -s -m 2 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$SERVE_PORT/api/health" 2>/dev/null || true)"
    [ "$code" = 200 ] && return 0
    sleep 1
  done
  fail "$scn: server healthy on 127.0.0.1:$SERVE_PORT (got ${code:-nothing})"
  docker logs "$web" 2>&1 | tail -n 40 | sed 's/^/    | /'
  return 1
}

mode_serve() {
  local scn="$1"
  serve_boot "$scn" || exit 1
  echo
  echo "== Serving scenario $scn at http://127.0.0.1:$SERVE_PORT (Ctrl-C stops and removes it)"
  echo "   password of every account with one: $FIXTURE_PASSWORD"
  echo "   fake AUTH_SECRET=$FAKE_AUTH_SECRET INTERNAL_API_KEY=$FAKE_INTERNAL_API_KEY SCANNER_API_KEY=$FAKE_SCANNER_API_KEY"
  echo "   accounts (email | role | password state):"
  psql_db -c "SELECT email, role, CASE WHEN password = '' THEN 'passwordless' ELSE 'password' END
    FROM users ORDER BY created_at" | sed 's/^/     /'
  while :; do sleep 3600 & SLEEP_PID=$!; wait "$SLEEP_PID"; done
}

# ---- preview -----------------------------------------------------------------------------
# The upgrade preview as ./redamon.sh update runs it (`node scripts/rbac-upgrade-preview.mjs` in the
# new image, before its startup list), or RBAC_UPGRADE_PREVIEW_SCRIPT fed on stdin.
run_preview() { # out_file err_file -> the preview's exit code
  local args=(--rm --label "$LABEL" --network "$NET" -e DATABASE_URL="$DB_URL" -e CHECKPOINT_DISABLE=1
              -e SCANNER_API_KEY="$FAKE_SCANNER_API_KEY" "${SWITCH_ARGS[@]}" -w /app --entrypoint node)
  if [ -n "$PREVIEW_SCRIPT" ]; then
    docker run -i "${args[@]}" "$IMAGE" --input-type=module - < "$PREVIEW_SCRIPT" > "$1" 2> "$2"
  else
    docker run "${args[@]}" "$IMAGE" scripts/rbac-upgrade-preview.mjs < /dev/null > "$1" 2> "$2"
  fi
}

mode_preview() {
  prepare "$1" || return
  local rc want_rc=0
  run_preview "$TMP/preview.txt" "$TMP/preview.err"; rc=$?
  snapshot "$TMP/after-preview.txt"
  assert_same "$1 preview: the preview writes nothing" "$TMP/before.txt" "$TMP/after-preview.txt"
  run_list "$IMAGE" "$TMP/run1.log"; list_ok "$1" "preview run" "$TMP/run1.log" $? || return
  verify "$1" "preview run"

  if ! psql_db < "$FIX/preview_after.sql" > "$TMP/preview.wrote" 2>&1; then
    fail "$1 preview: preview_after.sql runs"; show_log "$TMP/preview.wrote"; return
  fi
  grep -qx 'review|yes' "$TMP/preview.wrote" && want_rc=10
  # Nothing to review: the preview prints only its two `always` sections.
  if [ "$want_rc" -eq 10 ]; then
    { grep -v '^review|' "$TMP/preview.wrote"; echo 'scanner_key|set'; }
  else
    grep -E '^(root|instance_settings)\|' "$TMP/preview.wrote"
  fi | LC_ALL=C sort > "$TMP/preview.want"

  if [ "$rc" -eq "$want_rc" ]; then pass "$1 preview: exits $want_rc"
  else fail "$1 preview: exits $want_rc (got $rc)"; show_log "$TMP/preview.err"; fi
  py preview "$TMP/preview.txt" | LC_ALL=C sort > "$TMP/preview.said"
  local before=$FAIL
  assert_same "$1 preview: the preview names what the run wrote (preview_after.sql)" "$TMP/preview.want" "$TMP/preview.said"
  [ "$FAIL" -gt "$before" ] && { echo "    the preview printed:"; show_log "$TMP/preview.txt"; }
}

# ---- serve-check -------------------------------------------------------------------------
SERVE_BASE="http://127.0.0.1:$SERVE_PORT"
login() { # email jar -> HTTP code
  curl -s -m 30 -o "$TMP/body" -w '%{http_code}' -c "$2" -X POST "$SERVE_BASE/api/auth/login" \
    -H 'Content-Type: application/json' --data-binary "{\"email\":\"$1\",\"password\":\"$FIXTURE_PASSWORD\"}"
}
http_get() { # path curl-args... -> HTTP code; the answer in $TMP/body
  local path="$1"; shift
  curl -s -m 30 -o "$TMP/body" -w '%{http_code}' "$@" "$SERVE_BASE$path"
}

mode_serve_check() {
  local scn="$1" oracle="$FIX/expected/$1.capabilities${AFTER_SUFFIX#after}.out"
  local email expr code id role token first=""
  if [ ! -s "$TMP/catalog.json" ] && ! docker run --rm --entrypoint cat "$IMAGE" \
      /app/src/lib/authz/permissionCatalog.json > "$TMP/catalog.json" 2>/dev/null; then
    rm -f "$TMP/catalog.json"; fail "$scn serve-check: $IMAGE carries src/lib/authz/permissionCatalog.json"; return
  fi
  [ -f "$oracle" ] || { fail "$scn serve-check: ${oracle#"$FIX"/} exists"; return; }
  serve_boot "$scn" || { docker rm -f -v "$PFX-web" >/dev/null 2>&1; return; }

  psql_db -c "SELECT email FROM users" | LC_ALL=C sort > "$TMP/accounts.db"
  cut -d'|' -f1 "$oracle" | sed '/^$/d' | LC_ALL=C sort > "$TMP/accounts.oracle"
  assert_same "$scn serve-check: ${oracle#"$FIX"/} names every fixture account" "$TMP/accounts.db" "$TMP/accounts.oracle"
  if ! py expand "$TMP/catalog.json" "$oracle" > "$TMP/caps.want.raw" 2> "$TMP/caps.err"; then
    fail "$scn serve-check: ${oracle#"$FIX"/} expands"; show_log "$TMP/caps.err"; docker rm -f -v "$PFX-web" >/dev/null 2>&1; return
  fi
  LC_ALL=C sort "$TMP/caps.want.raw" > "$TMP/caps.want"
  psql_db -c "SELECT u.email || '|' || p.id FROM projects p JOIN users u ON u.id = p.user_id
    WHERE u.password <> ''" | LC_ALL=C sort > "$TMP/projects.want"

  : > "$TMP/caps.got.raw"; : > "$TMP/projects.got.raw"
  while IFS='|' read -r email expr <&3; do
    [ -n "$email" ] || continue
    rm -f "$TMP/jar"
    code="$(login "$email" "$TMP/jar")"
    if [ "$expr" = login_refused ]; then echo "$email|login $code" >> "$TMP/caps.got.raw"; continue; fi
    if [ "$code" = 200 ]; then
      code="$(http_get /api/auth/me -b "$TMP/jar")"
      if [ "$code" = 200 ]; then py caps "$TMP/body" "$email" fresh; else echo "$email|fresh|status $code"; fi >> "$TMP/caps.got.raw"
      code="$(http_get /api/projects -b "$TMP/jar")"
      if [ "$code" = 200 ]; then py projects "$TMP/body" "$email"; else echo "$email|status $code"; fi >> "$TMP/projects.got.raw"
    else
      echo "$email|fresh|login $code" >> "$TMP/caps.got.raw"
    fi
    IFS='|' read -r id role < <(psql_db -c "SELECT id, role FROM users WHERE email = '$email'" < /dev/null)
    [ -n "$first" ] || first="$id|$role"
    token="$(py mint "$FAKE_AUTH_SECRET" "$id" "$role")"
    code="$(http_get /api/auth/me -H "Cookie: $AUTH_COOKIE=$token")"
    if [ "$code" = 200 ]; then py caps "$TMP/body" "$email" old; else echo "$email|old|status $code"; fi >> "$TMP/caps.got.raw"
  done 3< "$oracle"
  LC_ALL=C sort "$TMP/caps.got.raw" > "$TMP/caps.got"
  LC_ALL=C sort "$TMP/projects.got.raw" > "$TMP/projects.got"
  assert_same "$scn serve-check: capabilities at sign-in and with a 7.7.x cookie match ${oracle#"$FIX"/}" "$TMP/caps.want" "$TMP/caps.got"
  assert_same "$scn serve-check: every account lists its own projects only" "$TMP/projects.want" "$TMP/projects.got"
  if [ -n "$first" ]; then
    token="$(py mint "$WRONG_AUTH_SECRET" "${first%%|*}" "${first#*|}")"
    code="$(http_get /api/auth/me -H "Cookie: $AUTH_COOKIE=$token")"
    if [ "$code" = 401 ]; then pass "$scn serve-check: a cookie signed with another secret is refused (401)"
    else fail "$scn serve-check: a cookie signed with another secret is refused (got $code)"; fi
  fi
  docker rm -f -v "$PFX-web" >/dev/null 2>&1
}

# ---- downgrade ---------------------------------------------------------------------------
# The new image runs with every RBAC switch on whatever the environment says (the downgrade
# leaves the most state behind then); 7.7.2 reads none of them. No authorization cache, so a
# revoke shows at the next request.
DG_SWITCH_ARGS=(-e RBAC_IDENTITY_ENABLED=true -e RBAC_PERMISSIONS_ENABLED=true -e RBAC_SHARING_ENABLED=true
                -e RBAC_SHARING_WRITE_ENABLED=true -e RBAC_GOVERNANCE_ENABLED=true -e RBAC_AUTHZ_CACHE_MS=0)
ROTATED_AUTH_SECRET=rbac-upgrade-rotated-auth-secret-0001

run_list_as() { # image log docker-args... -> exit code of the list
  local image="$1" log="$2"; shift 2
  docker run --rm --label "$LABEL" --network "$NET" -e DATABASE_URL="$DB_URL" -e CHECKPOINT_DISABLE=1 "$@" \
    --entrypoint sh "$image" -c "$LIST_CMD" > "$log" 2>&1
}

start_web() { # image auth_secret docker-args... -> 0 once /api/health answers 200 on $SERVE_PORT
  local image="$1" secret="$2" web="$PFX-web" i code; shift 2
  docker rm -f -v "$web" >/dev/null 2>&1
  docker run -d --name "$web" --label "$LABEL" --network "$NET" -p "127.0.0.1:$SERVE_PORT:3000" \
    -e DATABASE_URL="$DB_URL" -e CHECKPOINT_DISABLE=1 -e AUTH_SECRET="$secret" \
    -e INTERNAL_API_KEY="$FAKE_INTERNAL_API_KEY" -e SCANNER_API_KEY="$FAKE_SCANNER_API_KEY" "$@" \
    --entrypoint sh "$image" -c 'eval "$(tail -n 1 /app/entrypoint.sh)"' >/dev/null || return 1
  for i in $(seq 1 120); do
    code="$(curl -s -m 2 -o /dev/null -w '%{http_code}' "$SERVE_BASE/api/health" 2>/dev/null || true)"
    [ "$code" = 200 ] && return 0
    sleep 1
  done
  docker logs "$web" 2>&1 | tail -n 40 | sed 's/^/    | /'
  return 1
}
stop_web() { docker rm -f -v "$PFX-web" >/dev/null 2>&1; }

run_report() { # out err args... -> exit code: the new image's preview (or RBAC_UPGRADE_PREVIEW_SCRIPT) with args
  local out="$1" err="$2"; shift 2
  local args=(--rm --label "$LABEL" --network "$NET" -e DATABASE_URL="$DB_URL" -e CHECKPOINT_DISABLE=1
              "${DG_SWITCH_ARGS[@]}" -w /app --entrypoint node)
  if [ -n "$PREVIEW_SCRIPT" ]; then
    docker run -i "${args[@]}" "$IMAGE" --input-type=module - "$@" < "$PREVIEW_SCRIPT" > "$out" 2> "$err"
  else
    docker run "${args[@]}" "$IMAGE" scripts/rbac-upgrade-preview.mjs "$@" < /dev/null > "$out" 2> "$err"
  fi
}

listed_drops() { # report "Tables dropped" | "Columns dropped" -> the names it lists as present
  awk -v head="  $2" 'index($0, head) == 1 { on = 1; next }
    on && $0 == "" { exit }
    on && /^    [^ ]/ && $0 !~ /not in this database/ { print $1 }' "$1"
}

cookie_of() { awk -F'\t' -v name="$AUTH_COOKIE" '$6 == name { print $7 }' "$1"; }

expect_code() { # label want(regex) got
  if [[ "$3" =~ ^($2)$ ]]; then pass "$1 ($3)"; else fail "$1 (want $2, got $3)"; fi
}

expect_eq() { # label want got
  if [ "$2" = "$3" ]; then pass "$1"; else fail "$1"; echo "    want: $2"; echo "    got:  $3"; fi
}

instance_ids_left() {
  psql_db -c "SELECT (SELECT count(*) FROM projects WHERE agent_openai_model LIKE 'instance/%'
                        OR ai_pipeline_model LIKE 'instance/%' OR cypherfix_llm_model LIKE 'instance/%')
                   + (SELECT count(*) FROM users WHERE default_agent_model LIKE 'instance/%'
                        OR default_ai_pipeline_model LIKE 'instance/%')
                   + (SELECT count(*) FROM user_tradecraft_resources WHERE llm_model LIKE 'instance/%')
                   + (SELECT count(*) FROM user_project_presets WHERE settings::text LIKE '%\"instance/%')"
}

mode_downgrade() {
  local scn="$1" hash code rc cookie t c gone kept want
  local up="$scn downgrade"
  prepare "$scn" || return
  run_list_as "$IMAGE" "$TMP/dg-up1.log" "${DG_SWITCH_ARGS[@]}"
  list_ok "$scn" "downgrade: new image, every switch on" "$TMP/dg-up1.log" $? || return
  psql_db -c "SELECT email || '|' || array_to_string(legacy_grants, ',') FROM users ORDER BY email" > "$TMP/dg-grants.before"
  psql_db -c "SELECT coalesce(tunnel_source_user_id, '-') || '|' || coalesce(capture_source_user_id, '-') FROM instance_settings" > "$TMP/dg-sources.before"

  hash="$(docker run --rm --entrypoint node "$IMAGE" -e 'process.stdout.write(require("bcryptjs").hashSync(process.argv[1], 10))' "$FIXTURE_PASSWORD")"
  if [[ "$hash" == '$2'* ]] && psql_db -v pw="$hash" < "$FIX/downgrade_state.sql" > "$TMP/dg-state.log" 2>&1; then
    pass "$up: RBAC state written in every table and column the release adds"
  else
    fail "$up: RBAC state written in every table and column the release adds"; show_log "$TMP/dg-state.log"; return
  fi

  # A real device session, then its revoke, on the new release.
  start_web "$IMAGE" "$FAKE_AUTH_SECRET" "${DG_SWITCH_ARGS[@]}" || { fail "$up: new server starts"; stop_web; return; }
  rm -f "$TMP/jar"
  expect_code "$up: dg-member signs in on the new release" 200 "$(login dg-member@e2e.local "$TMP/jar")"
  cookie="$(cookie_of "$TMP/jar")"
  rm -f "$TMP/jar2"
  expect_code "$up: dg-collab signs in on the new release" 200 "$(login dg-collab@e2e.local "$TMP/jar2")"
  code="$(http_get /api/projects -b "$TMP/jar2")"
  if [ "$code" = 200 ] && grep -q '"dg-p1"' "$TMP/body"; then pass "$up: the collaborator lists the shared project on the new release"
  else fail "$up: the collaborator lists the shared project on the new release (status $code)"; fi
  expect_eq "$up: the device session revoked (one row)" 1 \
    "$(psql_db -c "WITH r AS (UPDATE user_sessions SET revoked_at = now(), revoked_by_id = 'dg-admin', ended_by = 'admin'
                     WHERE user_id = 'dg-member' AND revoked_at IS NULL RETURNING 1) SELECT count(*) FROM r")"
  expect_code "$up: the revoked session is refused on the new release" 401 "$(http_get /api/auth/me -H "Cookie: $AUTH_COOKIE=$cookie")"
  stop_web

  # The procedure: read the report, reset the instance model ids.
  run_report "$TMP/dg-report.txt" "$TMP/dg-report.err" --downgrade; rc=$?
  expect_code "$up: the downgrade report exits 10 (something would be lost)" 10 "$rc"
  local said=1
  for want in '^RBAC downgrade preview: going back to 7\.7\.2' 'dg-noaccess@e2e\.local +permission set No access' \
              'dg-custom@e2e\.local +permission set dg scanners only \(custom\)' 'dg-usermgr@e2e\.local +admin profile User manager' \
              'dg-disabled@e2e\.local +disabled' 'dg-invited@e2e\.local +invited' '1 device session revoked' \
              'dg shared project \(dg-owner@e2e\.local\) +agent model' 'pg_dump'; do
    grep -Eq -- "$want" "$TMP/dg-report.txt" || { said=0; echo "    missing: $want"; }
  done
  if [ "$said" -eq 1 ]; then pass "$up: the report names the accounts, the revoked session, the instance model and the backup"
  else fail "$up: the report names the accounts, the revoked session, the instance model and the backup"; show_log "$TMP/dg-report.txt"; fi
  listed_drops "$TMP/dg-report.txt" 'Tables dropped' > "$TMP/dg-tables"
  listed_drops "$TMP/dg-report.txt" 'Columns dropped' > "$TMP/dg-columns"
  if [ -s "$TMP/dg-tables" ] && [ -s "$TMP/dg-columns" ]; then
    pass "$up: the report lists $(wc -l < "$TMP/dg-tables") tables and $(wc -l < "$TMP/dg-columns") columns present here"
  else fail "$up: the report lists the tables and columns to drop"; show_log "$TMP/dg-report.txt"; return; fi
  if awk '/^  Tables dropped/ { on = 1; next } on && $0 == "" { exit } on && / 0 rows /' "$TMP/dg-report.txt" | grep -q .; then
    fail "$up: every dropped table holds a row of the state"
    awk '/^  Tables dropped/ { on = 1; next } on && $0 == "" { exit } on && / 0 rows /' "$TMP/dg-report.txt" | sed 's/^/    /'
  else pass "$up: every dropped table holds a row of the state"; fi
  run_report "$TMP/dg-reset.sql" "$TMP/dg-reset.err" --downgrade-sql; rc=$?
  if [ "$rc" -eq 0 ] && psql_db < "$TMP/dg-reset.sql" > "$TMP/dg-reset.log" 2>&1; then pass "$up: --downgrade-sql runs"
  else fail "$up: --downgrade-sql runs (exit $rc)"; show_log "$TMP/dg-reset.err"; show_log "$TMP/dg-reset.log"; fi
  expect_eq "$up: no instance/ model id left" 0 "$(instance_ids_left)"

  # 7.7.2's own list on the same database.
  local users_before projects_before
  users_before="$(psql_db -c 'SELECT count(*) FROM users')"
  projects_before="$(psql_db -c 'SELECT count(*) FROM projects')"
  run_list_as "$OLD_IMAGE" "$TMP/dg-old.log"
  list_ok "$scn" "downgrade: 7.7.2 list on the upgraded database" "$TMP/dg-old.log" $? || return
  gone=""
  while read -r t; do
    [ "$(psql_db -c "SELECT to_regclass('public.$t') IS NULL")" = t ] || gone+=" $t"
  done < "$TMP/dg-tables"
  while IFS=. read -r t c; do
    [ "$(psql_db -c "SELECT count(*) FROM information_schema.columns WHERE table_schema = 'public'
                       AND table_name = '$t' AND column_name = '$c'")" = 0 ] || gone+=" $t.$c"
  done < "$TMP/dg-columns"
  if [ -z "$gone" ]; then pass "$up: 7.7.2's db push dropped every table and column the report listed"
  else fail "$up: 7.7.2's db push dropped every table and column the report listed (still there:$gone)"; fi
  expect_eq "$up: 7.7.2 keeps every account and project" "$users_before|$projects_before" \
    "$(psql_db -c 'SELECT count(*) FROM users')|$(psql_db -c 'SELECT count(*) FROM projects')"
  expect_eq "$up: the disabled account still has no password" "" "$(psql_db -c "SELECT password FROM users WHERE id = 'dg-disabled'")"

  # 7.7.2's server, same AUTH_SECRET, then a new one.
  start_web "$OLD_IMAGE" "$FAKE_AUTH_SECRET" || { fail "$up: 7.7.2 server starts"; stop_web; return; }
  expect_code "$up: the revoked session is valid again on 7.7.2" 200 "$(http_get /api/auth/me -H "Cookie: $AUTH_COOKIE=$cookie")"
  rm -f "$TMP/jar"
  expect_code "$up: the disabled account cannot sign in on 7.7.2" '4[0-9][0-9]' "$(login dg-disabled@e2e.local "$TMP/jar")"
  expect_code "$up: the invited account cannot sign in on 7.7.2" '4[0-9][0-9]' "$(login dg-invited@e2e.local "$TMP/jar")"
  rm -f "$TMP/jar"
  expect_code "$up: the No-access member signs in on 7.7.2" 200 "$(login dg-noaccess@e2e.local "$TMP/jar")"
  code="$(http_get /api/auth/me -b "$TMP/jar")"
  if [ "$code" = 200 ] && grep -q '"role":"standard"' "$TMP/body"; then pass "$up: the No-access member is a plain member on 7.7.2 (fail open)"
  else fail "$up: the No-access member is a plain member on 7.7.2 (status $code)"; fi
  expect_code "$up: the No-access member lists projects on 7.7.2" 200 "$(http_get /api/projects -b "$TMP/jar")"
  rm -f "$TMP/jar"
  expect_code "$up: the collaborator signs in on 7.7.2" 200 "$(login dg-collab@e2e.local "$TMP/jar")"
  code="$(http_get /api/projects -b "$TMP/jar")"
  if [ "$code" = 200 ] && ! grep -q '"dg-p1"' "$TMP/body"; then pass "$up: the shared project is gone from the collaborator's list (fail closed)"
  else fail "$up: the shared project is gone from the collaborator's list (status $code)"; fi
  expect_code "$up: the collaborator cannot open the shared project on 7.7.2" '403|404' "$(http_get /api/projects/dg-p1 -b "$TMP/jar")"
  stop_web
  start_web "$OLD_IMAGE" "$ROTATED_AUTH_SECRET" || { fail "$up: 7.7.2 server starts with a new AUTH_SECRET"; stop_web; return; }
  expect_code "$up: a new AUTH_SECRET ends the revoked session" 401 "$(http_get /api/auth/me -H "Cookie: $AUTH_COOKIE=$cookie")"
  stop_web

  # Upgrading again.
  run_list_as "$IMAGE" "$TMP/dg-up2.log" "${DG_SWITCH_ARGS[@]}"
  list_ok "$scn" "downgrade: the new image again (re-upgrade)" "$TMP/dg-up2.log" $? || return
  kept=""
  while read -r t; do
    [ "$(psql_db -c "SELECT to_regclass('public.$t') IS NOT NULL")" = t ] || kept+=" $t"
  done < "$TMP/dg-tables"
  if [ -z "$kept" ]; then pass "$up: re-upgrade: every dropped table exists again"
  else fail "$up: re-upgrade: every dropped table exists again (missing:$kept)"; fi
  expect_eq "$up: re-upgrade: Root chosen again, unconfirmed" 'dg-admin|unconfirmed|automatic' \
    "$(psql_db -c "SELECT root_user_id || '|' || coalesce(root_confirmed_at::text, 'unconfirmed') || '|' || coalesce(root_assigned_by, '')
                     FROM instance_settings")"
  expect_eq "$up: re-upgrade: the instance settings copied again from the same accounts" "$(cat "$TMP/dg-sources.before")" \
    "$(psql_db -c "SELECT coalesce(tunnel_source_user_id, '-') || '|' || coalesce(capture_source_user_id, '-') FROM instance_settings")"
  psql_db -c "SELECT email || '|' || array_to_string(legacy_grants, ',') FROM users WHERE email NOT LIKE 'dg-%' ORDER BY email" > "$TMP/dg-grants.after"
  assert_same "$up: re-upgrade: the legacy grants derived again as at the first upgrade" "$TMP/dg-grants.before" "$TMP/dg-grants.after"
  expect_eq "$up: re-upgrade: the disabled account is active again, without a password" 'active|' \
    "$(psql_db -c "SELECT status || '|' || password FROM users WHERE id = 'dg-disabled'")"
  if docker run --rm --label "$LABEL" --network "$NET" -e DATABASE_URL="$DB_URL" -e CHECKPOINT_DISABLE=1 "${DG_SWITCH_ARGS[@]}" \
       -e RESET_EMAIL=dg-disabled@e2e.local -e RESET_PASSWORD="$FIXTURE_PASSWORD" -w /app --entrypoint node "$IMAGE" \
       scripts/reset-password.mjs > "$TMP/dg-resetpw.log" 2>&1; then
    pass "$up: re-upgrade: scripts/reset-password.mjs sets the disabled account's password"
  else fail "$up: re-upgrade: scripts/reset-password.mjs sets the disabled account's password"; show_log "$TMP/dg-resetpw.log"; fi
  start_web "$IMAGE" "$FAKE_AUTH_SECRET" "${DG_SWITCH_ARGS[@]}" || { fail "$up: re-upgraded server starts"; stop_web; return; }
  rm -f "$TMP/jar"
  expect_code "$up: re-upgrade: the account signs in after the reset" 200 "$(login dg-disabled@e2e.local "$TMP/jar")"
  stop_web
}

mode_regen() {
  local scn out
  for scn in "${SCENARIOS[@]}"; do
    echo "== regen $scn"
    reset_db || { echo "database reset failed"; exit 1; }
    run_list "$OLD_IMAGE" "$TMP/regen.log" || { echo "7.7.2 startup list failed"; show_log "$TMP/regen.log"; exit 1; }
    psql_db < "$FIX/seed/$scn.sql" > "$TMP/seed.log" 2>&1 || { echo "seed failed"; show_log "$TMP/seed.log"; exit 1; }
    out="$FIX/$scn.sql"
    {
      echo "-- SYNTHETIC test fixture of tests/rbac_upgrade_live.sh, scenario $scn: no real user, host or secret."
      echo "-- Full dump (schema and data, pg_dump --no-owner) of the database the pinned"
      echo "-- redamon-webapp:rbac-7.7.2 startup list creates, plus seed/$scn.sql. Regenerate with"
      echo "-- 'bash tests/rbac_upgrade_live.sh regen'; never edit by hand (README.md)."
      docker exec "$PG" pg_dump --no-owner -U postgres redamon
    } > "$out.tmp" || { echo "pg_dump failed"; rm -f "$out.tmp"; exit 1; }
    mv "$out.tmp" "$out"
    reset_db
    psql_db < "$out" > "$TMP/load.log" 2>&1 || { echo "the new dump does not load"; show_log "$TMP/load.log"; exit 1; }
    run_checks "$FIX/expected/$scn.out"
    echo "  wrote $(basename "$out") ($(wc -c < "$out") bytes) and expected/$scn.out"
  done
}

# ---- run -------------------------------------------------------------------------------
case "${MODES[0]}" in
  serve) start_infra public; mode_serve "$SERVE_SCENARIO" ;;
  regen) start_infra internal; mode_regen; echo "== regen done: review git diff tests/fixtures/rbac_upgrade"; exit 0 ;;
esac

# serve-check publishes the server's port, which an internal network cannot.
if [ "$HAS_SERVE_CHECK" -eq 1 ]; then start_infra public; else start_infra internal; fi
started=$(date +%s)
for mode in "${MODES[@]}"; do
  for scn in "${SCENARIOS[@]}"; do
    echo "== $mode: $scn"
    "mode_${mode//-/_}" "$scn"
  done
done
echo "== RESULT: $PASS passed, $FAIL failed ($(( $(date +%s) - started ))s) =="
[ "$FAIL" -eq 0 ]
