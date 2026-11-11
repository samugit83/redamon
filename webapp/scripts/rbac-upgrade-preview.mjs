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
 *
 * Each SECTIONS and MEMBER_CHANGES entry names the step whose behaviour it reports: a step
 * that changes that behaviour updates its entry.
 *
 * Exit status: REVIEW_EXIT when something changes for an account or an operator setting
 * (redamon.sh then asks "Continue?" in a terminal); NOTHING_CHANGES_EXIT when nothing does
 * (no question); 1 when the report could not be made (the update goes on).
 */
import { PrismaClient } from '@prisma/client'
import { readdir } from 'node:fs/promises'
import path from 'node:path'
import { pathToFileURL } from 'node:url'

// Fed on stdin the module has no file of its own: its relative imports would resolve from
// the working directory (/app), not from scripts/.
const FROM_STDIN = process.argv[1] === '-'
const {
  CUTOFF_ACTION, LEGACY_GRANTS, MARKER_ACTION, REMOVE_ACTION,
  existedAtCutoff, planLegacyGrants, recordedGrants, removedGrantKeys,
} = await import(FROM_STDIN
  ? pathToFileURL(path.join(process.cwd(), 'scripts', 'backfill-rbac-legacy-grants.mjs')).href
  : './backfill-rbac-legacy-grants.mjs')

export const READ_ONLY_SQL = 'SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY'
export const NOTHING_CHANGES_EXIT = 0
export const REVIEW_EXIT = 10

/** Columns a release adds that the preview reads; absent on the schema it upgrades from. */
export const NEW_COLUMNS = [
  { table: 'users', column: 'legacy_grants', step: '1.8' },
]

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
        WHERE action IN ($1, $2, $3) ORDER BY created_at, id`,
      CUTOFF_ACTION, MARKER_ACTION, REMOVE_ACTION,
    )).map((a) => ({ action: a.action, targetId: a.target_id, after: a.after, createdAt: a.created_at }))

    return { now, columns: [...present].sort(), users, settings, mcpServers, audit }
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
 * something for an account or needs the operator, which makes the update ask.
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

  if (plan.done) {
    const scanner = SECTIONS.find((s) => s.id === 'scanner_key').render({ env, full: false })
    const lines = [header, `  The RBAC hardening is already in place (since ${day(plan.cutoff)}): nothing changes for existing accounts.`]
    if (scanner) lines.push('', ...scanner.lines)
    return {
      applied: true, review: Boolean(scanner?.affects), grants: [],
      sections: scanner ? [{ id: 'scanner_key', step: '1.16', lines: scanner.lines }] : [],
      text: `${lines.join('\n')}\n`,
    }
  }

  const ctx = { state, env, templateFiles, grants, email, role, full: true }
  const rendered = SECTIONS.map((s) => ({ s, out: s.render(ctx) })).filter((x) => x.out)
  const review = rendered.some((x) => x.out.affects)
  if (!review) {
    const reason = state.users.some(canSignIn) ? ' (every account that can sign in is an admin)' : ''
    return {
      applied: false, review: false, grants, sections: [],
      text: `${header}\n  Nothing changes for existing accounts${reason}.\n`,
    }
  }
  const sections = rendered.map(({ s, out }) => ({ id: s.id, step: s.step, lines: out.lines }))
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

async function main() {
  const prisma = new PrismaClient()
  let code = 1
  try {
    const report = await previewRbacUpgrade(prisma)
    process.stdout.write(report.text)
    code = report.review ? REVIEW_EXIT : NOTHING_CHANGES_EXIT
  } catch (err) {
    console.error('[rbac] upgrade preview failed:', err?.message || err)
  } finally {
    await prisma.$disconnect().catch(() => {})
  }
  process.exitCode = code
}

if (FROM_STDIN || (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href)) {
  main()
}
