/**
 * Upgrade preview of the RBAC hardening: what the new release changes for the accounts of
 * this install, before anything changes.
 *
 * `./redamon.sh update` runs it from the webapp image it has just built, against the live
 * database, between the build and the restart (`docker compose run --no-deps`, so the
 * running webapp is untouched); `./redamon.sh update --preview` runs it and stops there.
 * In dev, or by hand: `docker exec -w /app redamon-webapp node scripts/rbac-upgrade-preview.mjs`
 * (or the same script fed on stdin with `node --input-type=module -`).
 *
 * It never writes: one READ ONLY transaction of plain SELECTs, no lock, no schema change.
 * It runs before the new image's `db push`, so it reads the old (7.7.x) schema: a column a
 * new release adds (NEW_COLUMNS) is checked before any query names it. It reads whether a
 * password, a tunnel credential or an MCP bearer is set, never the value. It prints the
 * emails of the affected accounts to the operator's terminal and nowhere else.
 *
 * The legacy grants are computed with the backfill's own planLegacyGrants, on the same
 * rows, so the list is what scripts/backfill-rbac-legacy-grants.mjs writes at the next boot.
 * Root and the instance settings sources follow the rules of backfill-rbac-root.mjs and
 * backfill-rbac-instance-settings.mjs the same way (their candidate orders, imported).
 *
 * Each SECTIONS and MEMBER_CHANGES entry names the step whose behaviour it reports: a step
 * that changes that behaviour updates its entry.
 *
 * Exit status: REVIEW_EXIT when something changes for an account or an operator setting
 * (redamon.sh then asks "Continue?" in a terminal); NOTHING_CHANGES_EXIT when nothing does
 * (no question); 1 when the report could not be made (the update goes on).
 *
 * `--downgrade` (UP-05, step 7.2) is the opposite report, read on the running install BEFORE
 * going back to DOWNGRADE_TARGET, so it reads the new schema: that release's boot runs
 * `prisma db push --accept-data-loss` against its own schema, which drops every table and
 * column added since (DOWNGRADE_TABLES, DOWNGRADE_COLUMNS; a step that adds one to
 * schema.prisma adds it there, the test pins both lists to the schema). It prints them with
 * their rows, the accounts whose rights go back to their account type's, the accounts that
 * cannot sign in, the revoked sessions, the projects on an `instance/` model and the backup
 * command. Same transaction rules, same exit statuses (REVIEW_EXIT: something would be lost).
 * `--downgrade-sql` prints the statements that reset the `instance/` model ids, and reads
 * nothing. Any other argument: USAGE_EXIT.
 */
import { PrismaClient } from '@prisma/client'
import { readdir } from 'node:fs/promises'
import path from 'node:path'
import { pathToFileURL } from 'node:url'

// Fed on stdin the module has no file of its own: its relative imports would resolve from
// the working directory (/app), not from scripts/.
const FROM_STDIN = process.argv[1] === '-'
const sibling = (name) => (FROM_STDIN ? pathToFileURL(path.join(process.cwd(), 'scripts', name)).href : `./${name}`)
const {
  CUTOFF_ACTION, LEGACY_GRANTS, MARKER_ACTION, REMOVE_ACTION,
  existedAtCutoff, planLegacyGrants, recordedGrants, removedGrantKeys,
} = await import(sibling('backfill-rbac-legacy-grants.mjs'))
const { CANDIDATE_ORDER, SINGLETON_ID, chooseRoot } = await import(sibling('backfill-rbac-root.mjs'))
const {
  CAPTURE_ROW_ORDER, MARKER_ACTION: INSTANCE_MARKER_ACTION, TUNNEL_ROW_ORDER, identitySwitchOn,
} = await import(sibling('backfill-rbac-instance-settings.mjs'))
const { permissionsSwitchOn } = await import(sibling('backfill-rbac-legacy-overrides.mjs'))

export const READ_ONLY_SQL = 'SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY'
export const NOTHING_CHANGES_EXIT = 0
export const REVIEW_EXIT = 10
export const USAGE_EXIT = 2

/** Columns a release adds that the preview reads; absent on the schema it upgrades from. */
export const NEW_COLUMNS = [
  { table: 'users', column: 'legacy_grants', step: '1.8' },
  { table: 'instance_settings', column: 'root_user_id', step: '2.1' },
  { table: 'instance_settings', column: 'root_confirmed_at', step: '2.1' },
  { table: 'instance_settings', column: 'updated_by_id', step: '2.1' },
]
const INSTANCE_COLUMNS = NEW_COLUMNS.filter((c) => c.table === 'instance_settings').map((c) => `${c.table}.${c.column}`)

const GRANT_LABELS = { kali_terminal: 'Kali terminal', shell_sessions: 'all shell sessions', tunnels: 'tunnel settings' }

/**
 * Reads everything the report needs in one transaction. Its first statement makes it
 * read-only (and one snapshot), so a statement that would write fails instead.
 */
export async function readUpgradeState(prisma) {
  return prisma.$transaction(async (tx) => {
    await tx.$executeRawUnsafe(READ_ONLY_SQL)
    const [{ now }] = await tx.$queryRawUnsafe('SELECT now() AS now')
    const wanted = NEW_COLUMNS.map((c) => `${c.table}.${c.column}`)
    const present = new Set((await tx.$queryRawUnsafe(
      `SELECT table_name, column_name FROM information_schema.columns
        WHERE table_schema = current_schema()
          AND (table_name || '.' || column_name) IN (${wanted.map((_, i) => `$${i + 1}`).join(', ')})`,
      ...wanted,
    )).map((r) => `${r.table_name}.${r.column_name}`))
    const hasLegacyGrants = present.has('users.legacy_grants')
    const hasInstanceSettings = INSTANCE_COLUMNS.every((c) => present.has(c))

    const users = (await tx.$queryRawUnsafe(
      `SELECT id, email, role, password <> '' AS has_password, created_at${hasLegacyGrants ? ', legacy_grants' : ''}
         FROM users ORDER BY id`,
    )).map((u) => ({
      id: u.id, email: u.email, role: u.role, hasPassword: u.has_password === true, createdAt: u.created_at,
      legacyGrants: hasLegacyGrants && Array.isArray(u.legacy_grants) ? u.legacy_grants : null,
    }))

    const settings = (await tx.$queryRawUnsafe(
      `SELECT id, user_id, tunnels_enabled, ngrok_authtoken <> '' AS has_ngrok,
              chisel_server_url <> '' AS has_chisel_url, updated_at
         FROM user_settings ORDER BY id`,
    )).map((s) => ({
      id: s.id, userId: s.user_id, tunnelsEnabled: s.tunnels_enabled === true, hasNgrok: s.has_ngrok === true,
      hasChiselUrl: s.has_chisel_url === true, updatedAt: s.updated_at,
    }))

    // Server by server, without the bearer, the headers or a stdio server's env values.
    const mcpServers = (await tx.$queryRawUnsafe(
      `SELECT s.user_id, srv->>'id' AS server_id, srv->>'name' AS name, srv->>'transport' AS transport,
              COALESCE(srv->>'enabled', 'true') <> 'false' AS enabled,
              COALESCE(srv->'auth'->>'token_env_var', '') AS token_env_var,
              COALESCE(srv->'auth'->>'token', '') <> '' AS has_token
         FROM user_settings s
        CROSS JOIN LATERAL jsonb_array_elements(
              CASE WHEN jsonb_typeof(s.mcp_servers) = 'array' THEN s.mcp_servers ELSE '[]'::jsonb END) AS srv
        WHERE jsonb_typeof(srv) = 'object'
        ORDER BY s.user_id`,
    )).map((m) => ({
      userId: m.user_id, serverId: m.server_id ?? '', name: m.name ?? '', transport: m.transport ?? '',
      enabled: m.enabled !== false, tokenEnvVar: m.token_env_var ?? '', hasToken: m.has_token === true,
    }))

    const audit = (await tx.$queryRawUnsafe(
      `SELECT action, target_id, after, created_at FROM audit_log
        WHERE action IN ($1, $2, $3, $4) ORDER BY created_at, id`,
      CUTOFF_ACTION, MARKER_ACTION, REMOVE_ACTION, INSTANCE_MARKER_ACTION,
    )).map((a) => ({ action: a.action, targetId: a.target_id, after: a.after, createdAt: a.created_at }))

    // The Root and whether an admin saved the row; never the tunnel or capture values.
    const [row] = hasInstanceSettings
      ? await tx.$queryRawUnsafe(
        `SELECT root_user_id, root_confirmed_at, updated_by_id IS NOT NULL AS admin_saved
           FROM instance_settings WHERE id = $1`,
        SINGLETON_ID,
      )
      : []
    const instance = row
      ? { rootUserId: row.root_user_id ?? null, rootConfirmedAt: row.root_confirmed_at ?? null, adminSaved: row.admin_saved === true }
      : null

    return { now, columns: [...present].sort(), users, settings, mcpServers, audit, instance }
  }, { timeout: 60_000, maxWait: 10_000 })
}

/** Stored names are user input: no control character may reach the operator's terminal. */
const clean = (s, max = 80) => {
  // eslint-disable-next-line no-control-regex
  const v = String(s ?? '').replace(/[\u0000-\u001f\u007f-\u009f]/g, '?')
  return v.length > max ? `${v.slice(0, max - 1)}…` : v
}
const day = (d) => (d instanceof Date ? d : new Date(d)).toISOString().slice(0, 10)
const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`
const isAdmin = (u) => u.role === 'admin'
const canSignIn = (u) => u.hasPassword
const pad = (rows) => {
  const width = Math.max(...rows.map((r) => r[0].length))
  return rows.map(([a, b]) => `    ${a.padEnd(width)}  ${b}`.trimEnd())
}
const isPlainObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v)

/** Rows in the order of a Prisma `orderBy` list (the backfills' own), over non-null fields. */
function orderedBy(rows, order) {
  const keys = order.flatMap((o) => Object.entries(o))
  const value = (v) => (v instanceof Date ? v.getTime() : typeof v === 'boolean' ? Number(v) : v)
  return [...rows].sort((a, b) => {
    for (const [k, dir] of keys) {
      const x = value(a[k])
      const y = value(b[k])
      const c = x < y ? -1 : x > y ? 1 : 0
      if (c !== 0) return dir === 'desc' ? -c : c
    }
    return 0
  })
}

// redamon.sh's _confirm_root runs only with the identity switch on.
const ROOT_WAITS = [
  '    Nothing changes while RBAC_IDENTITY_ENABLED is off. With it on, ./redamon.sh update confirms Root;',
  '    ./redamon.sh set-root <email> picks another admin.',
]

/** What the backfill does on these rows: nothing (`done`), or each account's grants after it. */
function legacyGrantsPlan(state) {
  const cutoff = state.audit.find((a) => a.action === CUTOFF_ACTION)?.createdAt ?? state.now
  const marker = state.audit.filter((a) => a.action === MARKER_ACTION).at(-1)
  const someoneHolds = state.users.some((u) => (u.legacyGrants ?? []).some((g) => LEGACY_GRANTS.includes(g)))
  if (marker && (recordedGrants(marker.after) === 0 || someoneHolds)) return { done: true, cutoff, accounts: [] }

  const members = state.users
    .filter((u) => !isAdmin(u) && canSignIn(u))
    .filter(existedAtCutoff(cutoff))
    .map((u) => ({ id: u.id, legacyGrants: u.legacyGrants ?? [] }))
  const tunnelHolders = new Set(state.settings.filter((s) => s.hasNgrok || s.hasChiselUrl).map((s) => s.userId))
  const removed = removedGrantKeys(state.audit.filter((a) => a.action === REMOVE_ACTION))
  const { accounts } = planLegacyGrants(members, tunnelHolders, removed)
  return { done: false, cutoff, accounts: accounts.map((a) => ({ id: a.member.id, grants: a.next })) }
}

/**
 * The report's sections, in print order. `render(ctx)` returns null when the section has
 * nothing to say, else `{affects, lines}`: `affects` is true when what it reports changes
 * something for an account or needs the operator, which makes the update ask. An `always`
 * section is printed even when nothing changes for the accounts (§14.12 "who will be Root,
 * and why"; "which instance settings values will be copied, and from where").
 */
export const SECTIONS = [
  {
    id: 'accounts', step: '1.19',
    render: ({ state: { users } }) => {
      const admins = users.filter(isAdmin).length
      const members = users.filter((u) => !isAdmin(u) && canSignIn(u)).length
      const passwordless = users.filter((u) => !isAdmin(u) && !canSignIn(u)).length
      return {
        affects: false,
        lines: [`  Accounts: ${plural(admins, 'admin', 'admins')}, ${plural(members, 'member who can sign in', 'members who can sign in')}, ${passwordless} without a password.`],
      }
    },
  },
  {
    // Root acts only with the identity switch on, and the update confirms it after the
    // restart, so it never makes the update ask here.
    id: 'root', step: '2.5', always: true,
    render: ({ state, env, email }) => {
      const switchOn = identitySwitchOn(env)
      const recorded = state.instance?.rootUserId ?? null
      const current = recorded ? state.users.find((u) => u.id === recorded) : null
      if (current && isAdmin(current)) {
        if (state.instance.rootConfirmedAt) return { affects: false, lines: [`  Root: ${email(current.id)} (confirmed).`] }
        return {
          affects: false,
          lines: [
            `  Root: ${email(current.id)}, chosen automatically, not confirmed yet.`,
            ...(switchOn ? ['    After the restart this update confirms it, or asks which admin to confirm.'] : ROOT_WAITS),
          ],
        }
      }
      const candidates = orderedBy(state.users.filter((u) => isAdmin(u) && canSignIn(u)), CANDIDATE_ORDER)
      const choice = chooseRoot(candidates)
      const stale = recorded ? [`  The Root recorded (account ${clean(recorded)}) is no longer an admin: Root is chosen again.`] : []
      if (!choice) {
        return {
          affects: false,
          lines: [...stale, '  Root: none yet (no admin has a password); ./redamon.sh create-admin makes one, and it becomes Root.'],
        }
      }
      const why = choice.rule === 'only_admin' ? 'the only admin with a password' : `the oldest of ${choice.candidateCount} admins with a password`
      const next = choice.rule === 'only_admin'
        ? ['    After the restart this update confirms it.']
        : ['    After the restart this update asks which admin to confirm (a non-interactive one: the admin ADMIN_EMAIL names).']
      return {
        affects: false,
        lines: [
          ...stale,
          `  Root: ${email(choice.userId)}, ${why}, chosen automatically at the next start.`,
          ...(choice.rule === 'only_admin' ? [] : pad(candidates.map((u) => [email(u.id), u.id === choice.userId ? '<- proposed' : '']))),
          ...(switchOn ? next : ROOT_WAITS),
        ],
      }
    },
  },
  {
    id: 'legacy_grants', step: '1.8',
    render: ({ grants, email }) => {
      const listed = grants.filter((a) => a.grants.some((g) => LEGACY_GRANTS.includes(g)))
      if (listed.length === 0) return null
      return {
        affects: true,
        lines: [
          '  Shared tools existing members keep (legacy grants; admins review them on the Users page):',
          ...pad(listed
            .map((a) => [email(a.id), a.grants.filter((g) => LEGACY_GRANTS.includes(g)).map((g) => GRANT_LABELS[g]).join(', ')])
            .sort((x, y) => x[0].localeCompare(y[0]))),
          '    Accounts created after the upgrade get none.',
        ],
      }
    },
  },
  {
    // The pick of step 1.10: an enabled row first, then the most recently saved, then the lowest id.
    id: 'tunnel_rows', step: '1.10',
    render: ({ state, email, role }) => {
      const rows = state.settings
        .filter((s) => s.hasNgrok || s.hasChiselUrl)
        .sort((a, b) => (Number(b.tunnelsEnabled) - Number(a.tunnelsEnabled))
          || (new Date(b.updatedAt) - new Date(a.updatedAt))
          || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0))
      if (rows.length === 0) return null
      const memberRow = rows.some((s) => role(s.userId) !== 'admin')
      return {
        affects: memberRow || rows.length > 1,
        lines: [
          '  Tunnel settings saved in accounts:',
          ...pad(rows.map((s, i) => [
            `${email(s.userId)} (${role(s.userId)})`,
            `${[s.hasNgrok && 'ngrok', s.hasChiselUrl && 'chisel'].filter(Boolean).join('+')}  `
              + `${s.tunnelsEnabled ? 'enabled' : 'disabled'}  saved ${day(s.updatedAt)}${i === 0 ? "  <- the agent's tunnel" : ''}`,
          ])),
          '    After the upgrade only admins and members keeping the tunnel grant change it.',
        ],
      }
    },
  },
  {
    // Step 2.4's backfill copies the tunnel and the TrafficMind capture, egress and SCA
    // settings from these rows; their values are never read here.
    id: 'instance_settings', step: '2.4', always: true,
    render: ({ state, env, email, role }) => {
      const switchOn = identitySwitchOn(env)
      const marker = state.audit.filter((a) => a.action === INSTANCE_MARKER_ACTION).at(-1)
      const filledWithSwitchOn = isPlainObject(marker?.after) && marker.after.identity === true
      if (switchOn && state.instance && (filledWithSwitchOn || state.instance.adminSaved)) {
        return {
          affects: false,
          lines: [
            '  Instance settings (tunnel, TrafficMind capture and egress, SCA ignore list): in force; admins change them in Global Settings.',
            "    The accounts' settings are not copied again.",
          ],
        }
      }
      const tunnels = orderedBy(state.settings.filter((s) => s.hasNgrok || s.hasChiselUrl), TUNNEL_ROW_ORDER)
      const captures = orderedBy(state.settings.filter((s) => role(s.userId) === 'admin'), CAPTURE_ROW_ORDER)
      const [tunnel] = tunnels
      const [capture] = captures
      return {
        affects: false,
        lines: [
          "  Instance settings, copied at the next start from the accounts' settings (which stay):",
          ...pad([
            ['tunnel', tunnel
              ? `${email(tunnel.userId)} (${role(tunnel.userId)}), saved ${day(tunnel.updatedAt)}${tunnels.length > 1 ? `; ${tunnels.length} accounts hold one` : ''}`
              : 'none saved (off)'],
            ['TrafficMind, egress, SCA', capture
              ? `${email(capture.userId)}, saved ${day(capture.updatedAt)}${captures.length > 1 ? `, the latest of ${captures.length} admin rows` : ''}`
              : 'none saved (the defaults)'],
          ]),
          switchOn
            ? '    With RBAC_IDENTITY_ENABLED on this copy is the one in force; admins change it in Global Settings.'
            : "    While RBAC_IDENTITY_ENABLED is off the accounts' settings stay in force; each start copies them again.",
        ],
      }
    },
  },
  {
    id: 'stdio_mcp', step: '1.9',
    render: ({ state, email, role }) => {
      const byOwner = groupBy(state.mcpServers.filter((m) => m.transport === 'stdio' && role(m.userId) !== 'admin'))
      if (byOwner.length === 0) return null
      return {
        affects: true,
        lines: [
          '  stdio MCP servers that stop loading (they run inside the agent; only admins may add them):',
          ...pad(byOwner.map(([userId, servers]) => [
            email(userId),
            servers.map((m) => `${clean(m.name || m.serverId, 40)}${m.enabled ? '' : ' (disabled)'}`).join(', '),
          ])),
          '    They stay saved in those accounts.',
        ],
      }
    },
  },
  {
    // OQ-R1 (a): a user-supplied server's `auth.token_env_var` is no longer resolved.
    id: 'mcp_token_env_var', step: '1.9',
    render: ({ state, email }) => {
      const byOwner = groupBy(state.mcpServers.filter((m) => m.tokenEnvVar !== '' && !m.hasToken))
      if (byOwner.length === 0) return null
      return {
        affects: true,
        lines: [
          "  MCP servers that lose the bearer they read from the agent's environment:",
          ...pad(byOwner.map(([userId, servers]) => [
            email(userId),
            servers.map((m) => `${clean(m.name || m.serverId, 40)} (${clean(m.tokenEnvVar, 40)})`).join(', '),
          ])),
        ],
      }
    },
  },
  {
    // Step 1.16: scan containers no longer fall back to INTERNAL_API_KEY.
    id: 'scanner_key', step: '1.16',
    render: ({ env, full }) => {
      const key = env.SCANNER_API_KEY ?? ''
      if (key === '' || key === 'changeme') {
        return {
          affects: true,
          lines: [
            '  SCANNER_API_KEY is not set in .env: scans will refuse to start without it.',
            '    ./redamon.sh update generates it; check that .env holds a SCANNER_API_KEY line.',
          ],
        }
      }
      return full ? { affects: false, lines: ['  SCANNER_API_KEY is set: scan containers use it, never the master key.'] } : null
    },
  },
  {
    id: 'member_changes', step: '1.9-1.14',
    render: (ctx) => {
      if (!ctx.state.users.some((u) => !isAdmin(u) && canSignIn(u))) return null
      return {
        affects: true,
        lines: [
          '  What changes for members:',
          ...MEMBER_CHANGES.map((c) => `    - ${c.text(ctx)}`),
          '  If something a member relied on breaks, REDAMON_SHARED_TOOLS_COMPAT=true in .env restores',
          '  the shared tools for accounts that existed before the upgrade, for this release only.',
        ],
      }
    },
  },
]

/** The short list of §14.7: what a member sees change, each from the step that changes it. */
export const MEMBER_CHANGES = [
  { step: '1.11', text: () => "Emergency stop stops only their own agent runs; admins still stop everyone's." },
  {
    step: '1.12',
    text: ({ templateFiles }) => 'Nuclei templates: they upload and delete only their own'
      + (templateFiles > 0 ? `; the ${templateFiles} template file(s) already in the folder become instance templates that admins manage.` : '.'),
  },
  { step: '1.10', text: () => 'Tunnel: only admins and members keeping the tunnel grant change it; the others see its status.' },
  { step: '1.13', text: () => "Shell sessions: they see their own projects' sessions; the all-sessions console needs the sessions grant." },
  { step: '1.14', text: () => "Kali terminal: needs the terminal grant, and warns that other projects' files are visible there." },
  { step: '1.9', text: () => 'MCP servers: only admins add, test or load stdio servers.' },
]

function groupBy(servers) {
  const map = new Map()
  for (const m of servers) map.set(m.userId, [...(map.get(m.userId) ?? []), m])
  return [...map.entries()]
}

/**
 * The report for a state read by readUpgradeState. Pure. `review` says whether anything
 * changes for an account or needs the operator; `grants` is each granted account's grants
 * after the backfill.
 *
 * @param {any} state
 * @param {{ env?: Record<string, string | undefined>, templateFiles?: number }} [opts]
 */
export function buildReport(state, { env = {}, templateFiles = 0 } = {}) {
  const usersById = new Map(state.users.map((u) => [u.id, u]))
  const email = (id) => clean(usersById.get(id)?.email ?? `(account ${id})`)
  const role = (id) => (isAdmin(usersById.get(id) ?? {}) ? 'admin' : 'member')
  const plan = legacyGrantsPlan(state)
  const grants = plan.accounts.filter((a) => a.grants.length > 0)
  const header = 'RBAC upgrade preview (read-only: nothing has been changed)'
  const ctx = { state, env, templateFiles, grants, email, role, full: true }
  const asSection = ({ s, out }) => ({ id: s.id, step: s.step, lines: out.lines })
  const always = SECTIONS.filter((s) => s.always).map((s) => ({ s, out: s.render(ctx) })).filter((x) => x.out)
  const alwaysLines = always.flatMap(({ out }) => ['', ...out.lines])
  const alwaysAffects = always.some((x) => x.out.affects)

  if (plan.done) {
    const scanner = SECTIONS.find((s) => s.id === 'scanner_key').render({ env, full: false })
    const lines = [header, `  The RBAC hardening is already in place (since ${day(plan.cutoff)}): nothing changes for existing accounts.`, ...alwaysLines]
    if (scanner) lines.push('', ...scanner.lines)
    return {
      applied: true, review: Boolean(scanner?.affects) || alwaysAffects, grants: [],
      sections: [...always.map(asSection), ...(scanner ? [{ id: 'scanner_key', step: '1.16', lines: scanner.lines }] : [])],
      text: `${lines.join('\n')}\n`,
    }
  }

  const rendered = SECTIONS.map((s) => ({ s, out: s.render(ctx) })).filter((x) => x.out)
  const review = rendered.some((x) => x.out.affects)
  if (!review) {
    const reason = state.users.some(canSignIn) ? ' (every account that can sign in is an admin)' : ''
    return {
      applied: false, review: false, grants, sections: always.map(asSection),
      text: `${[header, `  Nothing changes for existing accounts${reason}.`, ...alwaysLines].join('\n')}\n`,
    }
  }
  const sections = rendered.map(asSection)
  return {
    applied: false, review: true, grants, sections,
    text: `${[header, ...sections.flatMap((s) => ['', ...s.lines])].join('\n')}\n`,
  }
}

/** How many template files (.yaml/.yml, any depth) the custom templates folder holds. */
export async function countTemplateFiles(dir) {
  let n = 0
  async function walk(d) {
    for (const e of await readdir(d, { withFileTypes: true })) {
      if (e.isDirectory()) await walk(path.join(d, e.name))
      else if (e.isFile() && /\.ya?ml$/i.test(e.name)) n++
    }
  }
  try {
    await walk(dir)
  } catch {
    // No folder, or one this account cannot read: the line then names no count.
  }
  return n
}

/**
 * @param {any} prisma a PrismaClient, or anything with its interactive `$transaction`
 * @param {{ env?: Record<string, string | undefined>, templateFiles?: number, templatesPath?: string }} [opts]
 */
export async function previewRbacUpgrade(prisma, { env = process.env, templateFiles, templatesPath } = {}) {
  const state = await readUpgradeState(prisma)
  const files = templateFiles ?? await countTemplateFiles(templatesPath ?? env.NUCLEI_TEMPLATES_PATH ?? '/data/nuclei-templates')
  return buildReport(state, { env, templateFiles: files })
}

// ---------------------------------------------------------------------------------------
// --downgrade
// ---------------------------------------------------------------------------------------

/** The release a downgrade goes back to: the last one before the RBAC work (E11's image). */
export const DOWNGRADE_TARGET = Object.freeze({ version: '7.7.2', commit: '442debbf' })

/**
 * The tables the target release does not have: its boot's `db push --accept-data-loss` drops
 * each, with every row. `step` names the RBAC step that added it; `lost` is what goes.
 */
export const DOWNGRADE_TABLES = [
  { table: 'nuclei_templates', step: '1.12', lost: 'who owns each custom Nuclei template (the template files stay)' },
  {
    table: 'instance_settings', step: '2.1',
    lost: "Root, the security policy, the public address, the sharing policy, quotas, audit retention and the instance copy of the tunnel and TrafficMind settings (the accounts' own copies stay)",
  },
  { table: 'user_invites', step: '2.1', lost: 'invite and reset links: one not used yet stops working' },
  { table: 'permission_sets', step: '3.3', lost: 'custom permission sets and admin profiles' },
  { table: 'user_permission_sets', step: '3.3', lost: 'which account holds which permission set' },
  { table: 'user_permission_overrides', step: '3.3', lost: 'per-account grants and denies, including the legacy grants kept as overrides' },
  { table: 'project_collaborators', step: '4.2', lost: 'project shares: every shared project is private to its owner again' },
  { table: 'project_break_glass', step: '4.2', lost: 'break-glass accesses to projects' },
  { table: 'project_access_policies', step: '5.6', lost: "owners' consent to collaborators running with their credentials, and managers seeing every conversation" },
  { table: 'conversation_shares', step: '5.8', lost: 'conversations shared with a project: each is private to its author again' },
  { table: 'project_transfers', step: '5.12', lost: 'ownership transfer offers and their history (a completed transfer stays done)' },
  { table: 'plugin_access_rules', step: '6.9', lost: 'the per-plugin allowlists' },
  { table: 'user_sessions', step: '6.10', lost: 'device sessions and their revocations' },
  { table: 'instance_llm_providers', step: '6.11', lost: 'the instance LLM providers, with their keys' },
  { table: 'permission_set_providers', step: '6.11', lost: 'which permission set may use which instance LLM provider' },
  { table: 'quota_usage', step: '6.11', lost: "today's use counted against the quotas and the daily LLM budget" },
]

/**
 * The columns the target release's tables do not have, dropped with their values. `unset` is
 * the SQL value a new row gets (the schema default, NULL without one): a row holds data the
 * downgrade loses when its value IS DISTINCT FROM it. `step: null` names a non-RBAC feature.
 */
export const DOWNGRADE_COLUMNS = [
  { table: 'users', column: 'legacy_grants', step: '1.8', unset: "'{}'", lost: 'the shared tools each member kept as a legacy grant' },
  { table: 'users', column: 'status', step: '2.1', unset: "'active'", lost: 'account status: a disabled or invited account comes back active after a re-upgrade, still without a password' },
  { table: 'users', column: 'session_version', step: '2.1', unset: '0', lost: 'sign-outs everywhere: the tokens issued before one are valid again on 7.7.2' },
  { table: 'users', column: 'must_change_password', step: '2.1', unset: 'false', lost: 'forced password changes: 7.7.2 never asks for one' },
  { table: 'users', column: 'last_login_at', step: '2.1', unset: 'NULL', lost: 'the last sign-in of each account' },
  { table: 'users', column: 'admin_profile_id', step: '2.1', unset: 'NULL', lost: 'admin profiles: every admin is a full admin again' },
  { table: 'users', column: 'password_on_hold', step: '2.1', unset: "''", lost: 'the password a disabled account gets back when enabled: after a re-upgrade it needs a password reset' },
  { table: 'users', column: 'pending_notices', step: '2.1', unset: "'[]'", lost: 'notices waiting for the next sign-in' },
  { table: 'mcp_access_tokens', column: 'include_shared_projects', step: '4.2', unset: 'false', lost: "MCP tokens' reach into the projects shared with their owner" },
  { table: 'mcp_access_tokens', column: 'project_allowlist', step: '4.2', unset: "'{}'", lost: "MCP tokens' project allowlists: such a token reaches all its owner's projects again" },
  { table: 'scan_schedules', column: 'paused_reason', step: '5.5', unset: 'NULL', lost: 'why a schedule paused itself (it stays paused)' },
  { table: 'conversations', column: 'former_author_id', step: '5.8', unset: 'NULL', lost: "the former author of a conversation passed to the project owner when the author's account was deleted" },
  { table: 'conversations', column: 'former_author_label', step: '5.8', unset: 'NULL', lost: "that former author's name or email" },
  { table: 'audit_log', column: 'on_behalf_of_user_id', step: '2.1', unset: 'NULL', lost: 'the account an admin acted as, on each audit row (the rows stay)' },
  { table: 'audit_log', column: 'project_id', step: '2.1', unset: 'NULL', lost: 'the project of each audit row' },
  { table: 'audit_log', column: 'permission', step: '2.1', unset: 'NULL', lost: 'the permission each audited action used' },
  { table: 'audit_log', column: 'actor_email', step: '2.1', unset: 'NULL', lost: 'the email that keeps naming the actor of an audit row once the account is deleted' },
  { table: 'act_as_audit', column: 'reason', step: '2.1', unset: 'NULL', lost: 'the reason given for each act-as session' },
  { table: 'act_as_audit', column: 'duration_minutes', step: '2.1', unset: 'NULL', lost: 'the length asked for each act-as session' },
  { table: 'act_as_audit', column: 'ended_by', step: '2.1', unset: 'NULL', lost: 'who or what ended each act-as session' },
  ...[
    ['ip_hostname_mode', "'ip_only'", "each IP-mode project's hostname policy"],
    ['ip_hostname_include', "'{}'", 'the hostnames an IP-mode project scans'],
    ['ip_hostname_exclude', "'{}'", 'the hostnames an IP-mode project skips'],
    ['ip_hostname_passive_expand', 'true', 'whether an IP-mode project expands its hostnames passively'],
    ['ip_hostname_scan_all_confirmed', 'false', 'the confirmation to scan every hostname of an IP-mode project'],
    ['ip_hostname_max_scanned', '100', 'how many hostnames an IP-mode project scans at most'],
    ['ip_hostname_passive_max_names', '500', 'how many names the passive expansion keeps at most'],
  ].map(([column, unset, lost]) => ({ table: 'projects', column, step: null, feature: 'IP hostname modes', unset, lost })),
  { table: 'projects', column: 'naabu_run_timeout', step: null, feature: 'Naabu run timeout (recon audit R-9)', unset: '1800', lost: "each project's Naabu run timeout" },
]

/**
 * Where the target release reads a model id. Its `parse_model_provider` has no `instance/`
 * route and sends an unknown prefix to OpenAI with the owner's key, so these are reset
 * before the downgrade (`= DEFAULT`: what a new row holds) and the presets lose the key.
 */
export const INSTANCE_MODEL_COLUMNS = [
  { table: 'projects', column: 'agent_openai_model', label: 'agent model' },
  { table: 'projects', column: 'ai_pipeline_model', label: 'AI pipeline model' },
  { table: 'projects', column: 'cypherfix_llm_model', label: 'CypherFix model' },
  { table: 'users', column: 'default_agent_model', label: 'remembered agent model', noun: ['account', 'accounts'] },
  { table: 'users', column: 'default_ai_pipeline_model', label: 'remembered AI pipeline model', noun: ['account', 'accounts'] },
  { table: 'user_tradecraft_resources', column: 'llm_model', label: 'model', noun: ['tradecraft resource', 'tradecraft resources'] },
]
export const INSTANCE_MODEL_PRESET_KEYS = ['agentOpenaiModel', 'aiPipelineModel', 'cypherfixLlmModel']
const INSTANCE_LIKE = 'instance/%'

/** The statements that leave no `instance/` model id where the target release reads one. */
export function instanceModelResetSql() {
  return [
    ...INSTANCE_MODEL_COLUMNS.map((c) => `UPDATE ${c.table} SET ${c.column} = DEFAULT WHERE ${c.column} LIKE '${INSTANCE_LIKE}';`),
    ...INSTANCE_MODEL_PRESET_KEYS.map((k) =>
      `UPDATE user_project_presets SET settings = settings - '${k}' WHERE settings->>'${k}' LIKE '${INSTANCE_LIKE}';`),
  ]
}

/** src/lib/authz/builtinSets.ts, by id; the test pins it to permissionCatalog.json (no src/ in the image). */
export const BUILTIN_SET_NAMES = Object.freeze({
  'builtin:default-member': 'Default member',
  'builtin:read-only-analyst': 'Read-only analyst',
  'builtin:recon-operator': 'Recon operator',
  'builtin:red-team-operator': 'Red-team operator',
  'builtin:automation': 'Automation',
  'builtin:no-access': 'No access',
  'builtin:full-admin': 'Full admin',
  'builtin:user-manager': 'User manager',
  'builtin:platform-operator': 'Platform operator',
  'builtin:security-auditor': 'Security auditor',
})
/** The member sets holding all of Default member, i.e. what every 7.7.2 member can do. */
export const SETS_EQUAL_TO_DEFAULT_MEMBER = Object.freeze(['builtin:default-member', 'builtin:red-team-operator'])
export const FULL_ADMIN_PROFILE = 'builtin:full-admin'

const ident = (name) => `"${name}"`

/** Reads everything the downgrade report needs, in one read-only transaction. */
export async function readDowngradeState(prisma) {
  return prisma.$transaction(async (tx) => {
    await tx.$executeRawUnsafe(READ_ONLY_SQL)
    const [{ now }] = await tx.$queryRawUnsafe('SELECT now() AS now')
    const tables = [...new Set([...DOWNGRADE_TABLES.map((d) => d.table), ...DOWNGRADE_COLUMNS.map((d) => d.table)])]
    const present = new Map()
    for (const r of await tx.$queryRawUnsafe(
      `SELECT table_name, column_name FROM information_schema.columns
        WHERE table_schema = current_schema() AND table_name IN (${tables.map((_, i) => `$${i + 1}`).join(', ')})`,
      ...tables,
    )) present.set(r.table_name, (present.get(r.table_name) ?? new Set()).add(r.column_name))
    const has = (table, column) => (column === undefined ? present.has(table) : present.get(table)?.has(column) === true)

    const tableRows = {}
    const counted = DOWNGRADE_TABLES.filter((d) => has(d.table))
    if (counted.length > 0) {
      for (const r of await tx.$queryRawUnsafe(
        counted.map((d, i) => `SELECT $${i + 1}::text AS t, count(*)::int AS n FROM ${ident(d.table)}`).join(' UNION ALL '),
        ...counted.map((d) => d.table),
      )) tableRows[r.t] = Number(r.n)
    }

    const columnRows = {}
    for (const table of [...new Set(DOWNGRADE_COLUMNS.map((d) => d.table))]) {
      const columns = DOWNGRADE_COLUMNS.filter((d) => d.table === table && has(table, d.column))
      if (columns.length === 0) continue
      const [row] = await tx.$queryRawUnsafe(
        `SELECT ${columns.map((d) => `count(*) FILTER (WHERE ${ident(d.column)} IS DISTINCT FROM ${d.unset})::int AS ${ident(d.column)}`).join(', ')} FROM ${ident(table)}`,
      )
      for (const d of columns) columnRows[`${table}.${d.column}`] = Number(row[d.column])
    }

    // Whether a disabled account's hash is held, never the hash.
    const userColumn = (column, missing) => (has('users', column) ? column : `${missing} AS ${column}`)
    const users = (await tx.$queryRawUnsafe(
      `SELECT id, email, role, ${userColumn('status', "'active'")}, ${userColumn('must_change_password', 'false')},
              ${userColumn('session_version', '0')}, ${userColumn('admin_profile_id', 'NULL')},
              ${has('users', 'password_on_hold') ? "password_on_hold <> '' AS has_held_password" : 'false AS has_held_password'}
         FROM users ORDER BY id`,
    )).map((u) => ({
      id: u.id, email: u.email, role: u.role, status: u.status ?? 'active', mustChangePassword: u.must_change_password === true,
      sessionVersion: Number(u.session_version ?? 0), adminProfileId: u.admin_profile_id ?? null, heldPassword: u.has_held_password === true,
    }))

    const assignments = has('user_permission_sets')
      ? (await tx.$queryRawUnsafe('SELECT user_id, set_id FROM user_permission_sets ORDER BY user_id, set_id'))
        .map((r) => ({ userId: r.user_id, setId: r.set_id }))
      : []
    const sets = has('permission_sets')
      ? (await tx.$queryRawUnsafe('SELECT id, kind, name FROM permission_sets ORDER BY id')).map((r) => ({ id: r.id, kind: r.kind, name: r.name }))
      : []
    const denies = has('user_permission_overrides')
      ? (await tx.$queryRawUnsafe(
        `SELECT user_id, count(*)::int AS n FROM user_permission_overrides
          WHERE effect = 'deny' AND (expires_at IS NULL OR expires_at > now()) GROUP BY user_id ORDER BY user_id`,
      )).map((r) => ({ userId: r.user_id, count: Number(r.n) }))
      : []
    const [instance] = has('instance_settings', 'default_member_set_id')
      ? await tx.$queryRawUnsafe('SELECT default_member_set_id FROM instance_settings WHERE id = $1', SINGLETON_ID)
      : []
    const [sessions] = has('user_sessions', 'revoked_at')
      ? await tx.$queryRawUnsafe('SELECT count(*)::int AS revoked FROM user_sessions WHERE revoked_at IS NOT NULL AND expires_at > now()')
      : []

    // The target release's own tables and columns: present on any install.
    const projectColumns = INSTANCE_MODEL_COLUMNS.filter((c) => c.table === 'projects')
    const instanceProjects = (await tx.$queryRawUnsafe(
      `SELECT id, name, user_id, ${projectColumns.map((c) => c.column).join(', ')} FROM projects
        WHERE ${projectColumns.map((c) => `${c.column} LIKE $1`).join(' OR ')} ORDER BY name, id`,
      INSTANCE_LIKE,
    )).map((p) => ({
      id: p.id, name: p.name, userId: p.user_id,
      fields: projectColumns.filter((c) => String(p[c.column] ?? '').startsWith('instance/')).map((c) => c.label),
    }))
    const instanceRows = []
    for (const table of [...new Set(INSTANCE_MODEL_COLUMNS.filter((c) => c.table !== 'projects').map((c) => c.table))]) {
      const columns = INSTANCE_MODEL_COLUMNS.filter((c) => c.table === table)
      const [row] = await tx.$queryRawUnsafe(
        `SELECT ${columns.map((c) => `count(*) FILTER (WHERE ${ident(c.column)} LIKE $1)::int AS ${ident(c.column)}`).join(', ')} FROM ${ident(table)}`,
        INSTANCE_LIKE,
      )
      for (const c of columns) instanceRows.push({ label: c.label, noun: c.noun, count: Number(row[c.column]) })
    }
    const instancePresets = (await tx.$queryRawUnsafe(
      `SELECT user_id, name FROM user_project_presets
        WHERE ${INSTANCE_MODEL_PRESET_KEYS.map((k) => `settings->>'${k}' LIKE $1`).join(' OR ')} ORDER BY user_id, name`,
      INSTANCE_LIKE,
    )).map((p) => ({ userId: p.user_id, name: p.name }))

    return {
      now, tableRows, columnRows, users, assignments, sets, denies,
      defaultMemberSetId: instance?.default_member_set_id ?? null,
      revokedSessions: Number(sessions?.revoked ?? 0),
      instanceProjects, instanceRows, instancePresets,
    }
  }, { timeout: 60_000, maxWait: 10_000 })
}

const rows = (n) => plural(n, 'row', 'rows')
const ABSENT = 'not in this database'
const BACKUP_COMMAND = `docker compose exec -T postgres sh -c 'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc' > redamon-before-downgrade.dump`
const RESTORE_COMMAND = `docker compose exec -T postgres sh -c 'pg_restore -U "$POSTGRES_USER" -d "$POSTGRES_DB" --clean --if-exists' < redamon-before-downgrade.dump`
/** Three columns: name, count, what it holds. */
const pad3 = (list) => {
  const w0 = Math.max(...list.map((r) => r[0].length))
  const w1 = Math.max(...list.map((r) => r[1].length))
  return list.map(([a, b, c]) => `    ${a.padEnd(w0)}  ${b.padEnd(w1)}  ${c}`.trimEnd())
}

/** Each active account the stored RBAC data narrows today, with what narrows it. */
function narrowedAccounts(state, email) {
  const named = new Map(state.sets.map((s) => [s.id, s.name]))
  const setName = (id) => BUILTIN_SET_NAMES[id] ?? (named.has(id) ? `${clean(named.get(id), 40)} (custom)` : `${clean(id, 40)} (deleted)`)
  const denied = new Map(state.denies.map((d) => [d.userId, d.count]))
  const out = []
  for (const u of state.users) {
    if (u.status !== 'active') continue
    const why = []
    if (isAdmin(u) && u.adminProfileId && u.adminProfileId !== FULL_ADMIN_PROFILE) why.push(`admin profile ${setName(u.adminProfileId)}`)
    const assigned = state.assignments.filter((a) => a.userId === u.id).map((a) => a.setId)
    if (assigned.length > 0) {
      if (!assigned.some((id) => SETS_EQUAL_TO_DEFAULT_MEMBER.includes(id))) {
        why.push(`permission set${assigned.length > 1 ? 's' : ''} ${assigned.map(setName).join(', ')}`)
      }
    } else if (!isAdmin(u) && state.defaultMemberSetId && !SETS_EQUAL_TO_DEFAULT_MEMBER.includes(state.defaultMemberSetId)) {
      why.push(`the instance default set ${setName(state.defaultMemberSetId)}`)
    }
    if (denied.get(u.id)) why.push(plural(denied.get(u.id), 'denied permission', 'denied permissions'))
    if (why.length > 0) out.push([email(u.id), why.join('; ')])
  }
  return out
}

/** The downgrade report's sections, in print order; `render` as in SECTIONS. */
export const DOWNGRADE_SECTIONS = [
  {
    id: 'backup', always: true,
    render: () => ({
      affects: false,
      lines: [
        `  ${DOWNGRADE_TARGET.version}'s first start runs \`prisma db push --accept-data-loss\` against its own schema: it drops`,
        '  every table and column added since, with their data. Back up the database first:',
        `    ${BACKUP_COMMAND}`,
      ],
    }),
  },
  {
    id: 'tables', always: true,
    render: ({ state }) => ({
      affects: Object.values(state.tableRows).some((n) => n > 0),
      lines: [
        '  Tables dropped (rows now):',
        ...pad3(DOWNGRADE_TABLES.map((d) => [d.table, d.table in state.tableRows ? rows(state.tableRows[d.table]) : ABSENT, d.lost])),
      ],
    }),
  },
  {
    id: 'columns', always: true,
    render: ({ state }) => ({
      affects: Object.values(state.columnRows).some((n) => n > 0),
      lines: [
        '  Columns dropped (rows holding a value):',
        ...pad3(DOWNGRADE_COLUMNS.map((d) => {
          const key = `${d.table}.${d.column}`
          return [key, key in state.columnRows ? rows(state.columnRows[key]) : ABSENT, d.lost]
        })),
      ],
    }),
  },
  {
    id: 'rights',
    render: ({ state, env, email }) => {
      const narrowed = narrowedAccounts(state, email)
      const active = state.users.filter((u) => u.status === 'active')
      const members = active.some((u) => !isAdmin(u))
      const admins = active.filter(isAdmin).length
      const rootPowers = identitySwitchOn(env) && admins > 1
      if (narrowed.length === 0 && !members && !rootPowers) return null
      return {
        affects: true,
        lines: [
          `  Rights after the downgrade: ${DOWNGRADE_TARGET.version} has two account types, admins (everything) and members.`,
          ...(narrowed.length > 0
            ? [
              '  Accounts narrowed today that get their account type\'s full rights back (fail open):',
              ...pad(narrowed),
              permissionsSwitchOn(env)
                ? '    Review them before the downgrade: nothing narrows them on 7.7.2.'
                : '    RBAC_PERMISSIONS_ENABLED is off: none of these is in force now, so their rights do not change; only the stored assignments go.',
            ]
            : []),
          ...(members
            ? ["    Every member can again use the five shared tools: the Kali terminal, every user's shell sessions, the tunnel settings, the instance-wide emergency stop and every Nuclei template."]
            : []),
          ...(rootPowers ? ['    Every admin can again manage the other admins (7.7.2 has no Root).'] : []),
        ],
      }
    },
  },
  {
    id: 'sign_in',
    render: ({ state, email }) => {
      const list = state.users.flatMap((u) => {
        if (u.status === 'disabled') return [[email(u.id), `disabled${u.heldPassword ? ' (its password, held for re-enabling, is dropped)' : ''}`]]
        if (u.status === 'invited') return [[email(u.id), 'invited, never signed in (the invite link stops working)']]
        if (u.status !== 'active') return [[email(u.id), clean(u.status, 20)]]
        if (u.mustChangePassword) return [[email(u.id), 'must change their password (7.7.2 never asks)']]
        return []
      })
      if (list.length === 0) return null
      return {
        affects: true,
        lines: [
          '  Accounts that cannot sign in, or must change their password:',
          ...pad(list),
          '    Disabled and invited accounts have no password, so 7.7.2 refuses them too. After a re-upgrade they come back',
          '    active and still without a password: set one with ./redamon.sh reset-password, or disable them again.',
        ],
      }
    },
  },
  {
    id: 'sessions',
    render: ({ state }) => {
      const signedOut = state.users.filter((u) => u.sessionVersion > 0).length
      if (state.revokedSessions === 0 && signedOut === 0) return null
      return {
        affects: true,
        lines: [
          `  Sessions: ${plural(state.revokedSessions, 'device session revoked', 'device sessions revoked')} and not expired,`
            + ` ${plural(signedOut, 'account signed out everywhere', 'accounts signed out everywhere')} at least once.`,
          '    7.7.2 checks neither, so those sign-ins are valid again until they expire: give AUTH_SECRET a new value',
          '    in .env before the downgrade (everyone signs in again).',
        ],
      }
    },
  },
  {
    id: 'instance_models',
    render: ({ state, email }) => {
      const others = state.instanceRows.filter((r) => r.count > 0)
      if (state.instanceProjects.length === 0 && others.length === 0 && state.instancePresets.length === 0) return null
      return {
        affects: true,
        lines: [
          "  Models of an instance LLM provider (instance/...): 7.7.2 would send them to OpenAI with the owner's key.",
          '  Reset them before the downgrade; their owners pick a model again afterwards.',
          ...(state.instanceProjects.length > 0
            ? pad(state.instanceProjects.map((p) => [`${clean(p.name, 60)} (${email(p.userId)})`, p.fields.join(', ')]))
            : []),
          ...others.map((r) => `    ${plural(r.count, ...r.noun)} (${r.label})`),
          ...(state.instancePresets.length > 0
            ? [`    ${plural(state.instancePresets.length, 'saved preset', 'saved presets')}: ${state.instancePresets.map((p) => `${clean(p.name, 40)} (${email(p.userId)})`).join(', ')}`]
            : []),
          '  The reset (also printed by --downgrade-sql, to pipe into psql):',
          ...instanceModelResetSql().map((s) => `    ${s}`),
        ],
      }
    },
  },
  {
    id: 'reupgrade', always: true,
    render: () => ({
      affects: false,
      lines: [
        '  Upgrading again later: the first start creates these tables and columns empty, and the RBAC backfills run again',
        '  (their audit markers survive, their data does not): Root is chosen again (unconfirmed), the instance settings are',
        '  copied again from the accounts, and members who existed at the first upgrade get their legacy grants again,',
        '  minus those an admin removed. Shares, sets, overrides and instance providers start empty. To get them back',
        '  instead, restore the backup before upgrading (it loses what changed on 7.7.2):',
        `    ${RESTORE_COMMAND}`,
      ],
    }),
  },
]

/**
 * The downgrade report for a state read by readDowngradeState. Pure. `review` says whether
 * anything would be lost or needs the operator before the downgrade.
 *
 * @param {any} state
 * @param {{ env?: Record<string, string | undefined> }} [opts]
 */
export function buildDowngradeReport(state, { env = {} } = {}) {
  const usersById = new Map(state.users.map((u) => [u.id, u]))
  const email = (id) => clean(usersById.get(id)?.email ?? `(account ${id})`)
  const ctx = { state, env, email }
  const rendered = DOWNGRADE_SECTIONS.map((s) => ({ s, out: s.render(ctx) })).filter((x) => x.out)
  const review = rendered.some((x) => x.out.affects)
  const sections = rendered.map(({ s, out }) => ({ id: s.id, lines: out.lines }))
  const header = `RBAC downgrade preview: going back to ${DOWNGRADE_TARGET.version} (read-only: nothing has been changed)`
  const verdict = review ? [] : ['', '  Nothing is lost: no RBAC row and no value in a column the downgrade drops.']
  return { review, sections, text: `${[header, ...verdict, ...sections.flatMap((s) => ['', ...s.lines])].join('\n')}\n` }
}

/**
 * @param {any} prisma a PrismaClient, or anything with its interactive `$transaction`
 * @param {{ env?: Record<string, string | undefined> }} [opts]
 */
export async function previewRbacDowngrade(prisma, { env = process.env } = {}) {
  return buildDowngradeReport(await readDowngradeState(prisma), { env })
}

/** The report the arguments ask for, or null for anything else. */
export function parseMode(argv) {
  if (argv.length === 0) return 'upgrade'
  if (argv.length === 1 && (argv[0] === '--downgrade' || argv[0] === '--downgrade-sql')) return argv[0].slice(2)
  return null
}

async function main() {
  const mode = parseMode(process.argv.slice(2))
  if (mode === null) {
    console.error('[rbac] usage: node scripts/rbac-upgrade-preview.mjs [--downgrade | --downgrade-sql]')
    process.exitCode = USAGE_EXIT
    return
  }
  if (mode === 'downgrade-sql') {
    process.stdout.write(`${instanceModelResetSql().join('\n')}\n`)
    return
  }
  const prisma = new PrismaClient()
  let code = 1
  try {
    const report = mode === 'downgrade' ? await previewRbacDowngrade(prisma) : await previewRbacUpgrade(prisma)
    process.stdout.write(report.text)
    code = report.review ? REVIEW_EXIT : NOTHING_CHANGES_EXIT
  } catch (err) {
    console.error(`[rbac] ${mode} preview failed:`, err?.message || err)
  } finally {
    await prisma.$disconnect().catch(() => {})
  }
  process.exitCode = code
}

if (FROM_STDIN || (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href)) {
  main()
}
