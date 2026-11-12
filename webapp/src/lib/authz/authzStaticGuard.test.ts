/**
 * Owner checks, admin checks and "my projects" filters go through the policy (lib/authz):
 * `projectAccess()` / `visibleProjectsWhere()` for a project, `can()` for a permission
 * (adminPermission.ts for the signed-in person's administration permissions), `ownsRow()` for a
 * per-user row. An inline `project.userId === user` or `role === 'admin'` elsewhere is a second
 * policy that the next change to the first one (shares, permission sets) silently misses.
 *
 * Scans every non-test source under src/app/api and src/lib, except lib/authz itself, line by
 * line, for the shapes such a check takes. Each remaining match is listed below, per file and rule,
 * with how many lines match and why it is not an ownership or permission decision (a per-user row,
 * a lookup keyed by the account, an account type, the account the path names). A new match fails
 * the test until it goes through lib/authz or joins the list with its reason; a listed entry that
 * no longer matches fails too, so the list never outgrows the code.
 *
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import { readFileSync, readdirSync } from 'node:fs'
import { join, relative, sep } from 'node:path'

const WEBAPP = join(__dirname, '..', '..', '..')
const ROOTS = ['src/app/api', 'src/lib']
const SKIP_DIRS = new Set(['__testing__', '__fixtures__', 'node_modules'])

/**
 * The shapes of an inline check. `owner_compare` skips `typeof x.userId === 'string'` (a type
 * check of a body field); `is_admin` is the identifier, not `isAdminAccount` (an account type).
 */
const RULES: Record<string, RegExp> = {
  owner_compare: /(?<!typeof\s+[\w.]+)\.userId\s*[!=]==?/,
  owner_compare_rows: /userId\s*[!=]==?\s*\w+\.userId/,
  role_admin: /role\s*[!=]==?\s*['"]admin['"]/,
  find_by_id_and_owner: /findFirst\(\{\s*where:\s*\{[^}]*\bid\b[^}]*\buserId\b/,
  list_on_caller: /(where|project):\s*\{\s*userId:\s*(eff|session|ctx)/,
  row_owner_helper: /\b(ownerScope|assertOwner|assertOwnerStrict)\(/,
  identity_header: /headers\.get\(['"]x-user-/,
  is_admin: /\bisAdmin\b/,
}

const ACCOUNT_TYPE = 'an account type (admin or member; Root is an admin), not a permission'
const OWN_ACCOUNT = 'the account the path names is the signed-in one: an account check, not ownership'
const SHARED_TOOL = 'a shared-tool short-circuit before sharedToolAccess (sharedTools.ts); the platform permission replaces both with the platform routes'

interface Allowed {
  count: number
  reason: string
  /** Converted by the change set that adds this test; gone when it is done. */
  pending?: true
}

const ALLOWED: Record<string, Allowed> = {
  'src/app/api/admin/instance-settings/route.ts::role_admin': { count: 1, reason: SHARED_TOOL },
  'src/app/api/auth/act-as/route.ts::role_admin': { count: 1, reason: `the target's ${ACCOUNT_TYPE}: acting as another admin is Root's (rootPowers.ts)` },
  'src/app/api/auth/me/route.ts::role_admin': { count: 2, reason: `the caller's ${ACCOUNT_TYPE}: /api/auth/me reports it, and the Root block is shown to admins only` },
  'src/app/api/mcp/manifest/route.ts::list_on_caller': { count: 1, reason: "the caller's own MCP servers: a per-user row" },
  'src/app/api/models/route.ts::list_on_caller': { count: 1, reason: "the caller's own LLM providers: a per-user row" },
  'src/app/api/mute-rule-presets/[id]/route.ts::owner_compare': { count: 1, reason: '', pending: true },
  'src/app/api/mute-rule-presets/route.ts::row_owner_helper': { count: 1, reason: "the caller's own mute-rule presets: a per-user row (rowOwner.ts)" },
  'src/app/api/nuclei-templates/route.ts::role_admin': { count: 1, reason: SHARED_TOOL },
  'src/app/api/plugins/[pluginId]/route.ts::is_admin': { count: 2, reason: '', pending: true },
  'src/app/api/plugins/route.ts::is_admin': { count: 2, reason: '', pending: true },
  'src/app/api/presets/[id]/route.ts::row_owner_helper': { count: 2, reason: "a preset is its author's: a per-user row (rowOwner.ts)" },
  'src/app/api/presets/route.ts::row_owner_helper': { count: 1, reason: "the caller's own presets: a per-user row (rowOwner.ts)" },
  'src/app/api/projects/[id]/supply-chain-batch/route.ts::list_on_caller': { count: 1, reason: "the effective user's own GitHub token: a per-user row" },
  'src/app/api/projects/route.ts::row_owner_helper': { count: 1, reason: '', pending: true },
  'src/app/api/reports/route.ts::list_on_caller': { count: 1, reason: '', pending: true },
  'src/app/api/system/jobs/route.ts::list_on_caller': { count: 4, reason: '', pending: true },
  'src/app/api/traffic/[projectId]/[id]/route.ts::row_owner_helper': { count: 1, reason: 'the capture rows of a project carry its owner as tenant (ingest writes it), filtered after the project guard' },
  'src/app/api/traffic/[projectId]/facets/route.ts::row_owner_helper': { count: 1, reason: 'the capture rows of a project carry its owner as tenant (ingest writes it), filtered after the project guard' },
  'src/app/api/traffic/[projectId]/route.ts::row_owner_helper': { count: 1, reason: 'the capture rows of a project carry its owner as tenant (ingest writes it), filtered after the project guard' },
  'src/app/api/users/[id]/attack-skills/[skillId]/release/route.ts::owner_compare': { count: 1, reason: OWN_ACCOUNT },
  'src/app/api/users/[id]/llm-providers/route.ts::owner_compare': { count: 1, reason: `${OWN_ACCOUNT}; another account needs users:read` },
  'src/app/api/users/[id]/mcp-tokens/[tokenId]/route.ts::owner_compare': { count: 2, reason: '', pending: true },
  'src/app/api/users/[id]/mcp-tokens/route.ts::owner_compare': { count: 1, reason: OWN_ACCOUNT },
  'src/app/api/users/[id]/password/route.ts::owner_compare': { count: 1, reason: OWN_ACCOUNT },
  'src/app/api/users/[id]/password/route.ts::role_admin': { count: 1, reason: `the target's ${ACCOUNT_TYPE}: resetting another admin is Root's (rootPowers.ts)` },
  'src/app/api/users/[id]/route.ts::owner_compare': { count: 5, reason: `the Root re-check under the Root lock names Root's account (rootProtection.ts), and ${OWN_ACCOUNT} (another account needs users:read or users:edit; nobody deletes their own)` },
  'src/app/api/users/[id]/route.ts::owner_compare_rows': { count: 1, reason: "the Root re-check under the Root lock: whether the actor is the confirmed Root (step 2.6's power)" },
  'src/app/api/users/[id]/route.ts::role_admin': { count: 5, reason: `the target's or the requested ${ACCOUNT_TYPE}: another admin and a promotion are Root's or admins:manage's (hierarchy.ts)` },
  'src/app/api/users/[id]/settings/api-usage/route.ts::owner_compare': { count: 1, reason: OWN_ACCOUNT },
  'src/app/api/users/[id]/settings/route.ts::owner_compare': { count: 1, reason: OWN_ACCOUNT },
  'src/app/api/users/[id]/settings/route.ts::role_admin': { count: 1, reason: SHARED_TOOL },
  'src/app/api/users/route.ts::role_admin': { count: 2, reason: `the requested ${ACCOUNT_TYPE}: creating an admin is Root's (rootPowers.ts)` },
  'src/lib/access.ts::row_owner_helper': { count: 3, reason: 'the definitions of the per-user row helpers, which delegate to rowOwner.ts' },
  'src/lib/mcp/engagementTools.ts::owner_compare': { count: 1, reason: '', pending: true },
  'src/lib/mcp/presetTools.ts::list_on_caller': { count: 1, reason: "the token user's own presets, counted for the per-user cap: a per-user row" },
  'src/lib/mcp/tools.ts::list_on_caller': { count: 1, reason: 'MCP lists the projects its token user owns: every MCP project tool needs the owner level (mcpAuth.ts assertMcpProjectAccess)' },
  'src/lib/mcp/userServerAccess.ts::role_admin': { count: 1, reason: "whether a stdio server's owner runs it: the owner's admin account type until the platform routes check platform:agent_mcp" },
  'src/lib/plugins/lifecycleRoutes.ts::role_admin': { count: 1, reason: '', pending: true },
  'src/lib/plugins/pageModel.ts::is_admin': { count: 19, reason: '', pending: true },
  'src/lib/plugins/pageModel.ts::role_admin': { count: 1, reason: '', pending: true },
  'src/lib/plugins/userSkillOverrideOps.ts::find_by_id_and_owner': { count: 1, reason: "the token user's own skill, re-read in the write's transaction: a per-user row" },
  'src/lib/reconPresets/server.ts::find_by_id_and_owner': { count: 1, reason: "the caller's own recon preset: a per-user row" },
  'src/lib/session.ts::owner_compare': { count: 2, reason: OWN_ACCOUNT },
  'src/lib/session.ts::role_admin': { count: 3, reason: `${ACCOUNT_TYPE}: the act-as rule (only an admin acts as anyone, nobody as Root) and requireAdmin, the administrator-account gate each caller follows with its permission` },
  'src/lib/triageRun.ts::owner_compare': { count: 1, reason: '', pending: true },
  'src/lib/userAudit.ts::role_admin': { count: 1, reason: 'the act-as rule (only an admin acts as anyone), as session.ts mayActAs reads it, for the audit row' },
  'src/lib/userSkillWrites.ts::find_by_id_and_owner': { count: 4, reason: '', pending: true },
}

function sources(dir: string, out: string[] = []): string[] {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name)
    if (entry.isDirectory()) {
      if (!SKIP_DIRS.has(entry.name)) sources(full, out)
    } else if (/\.tsx?$/.test(entry.name) && !/\.test\.tsx?$/.test(entry.name)) {
      out.push(full)
    }
  }
  return out
}

/** `file::rule` -> the matching lines, for every file outside lib/authz. */
function scan(): Map<string, string[]> {
  const found = new Map<string, string[]>()
  for (const root of ROOTS) {
    for (const full of sources(join(WEBAPP, root))) {
      const file = relative(WEBAPP, full).split(sep).join('/')
      if (file.startsWith('src/lib/authz/')) continue
      readFileSync(full, 'utf8').split('\n').forEach((line, i) => {
        for (const [rule, re] of Object.entries(RULES)) {
          if (!re.test(line)) continue
          const key = `${file}::${rule}`
          const lines = found.get(key) ?? []
          lines.push(`${i + 1}: ${line.trim()}`)
          found.set(key, lines)
        }
      })
    }
  }
  return found
}

describe('no inline owner or admin check outside lib/authz', () => {
  const found = scan()

  test('the scan reads the tree (a moved folder must not make it pass empty)', () => {
    expect(found.size).toBeGreaterThan(0)
    expect([...found.keys()].some((k) => k.startsWith('src/app/api/'))).toBe(true)
    expect([...found.keys()].some((k) => k.startsWith('src/lib/'))).toBe(true)
  })

  test('every match is listed with its count and a reason', () => {
    const unlisted: string[] = []
    for (const [key, lines] of found) {
      const allowed = ALLOWED[key]
      if (!allowed || allowed.count !== lines.length) {
        unlisted.push(`${key}: ${lines.length} line(s), listed ${allowed?.count ?? 0}\n    ${lines.join('\n    ')}`)
      }
    }
    expect(unlisted, 'go through lib/authz (projectAccess, visibleProjectsWhere, can / adminPermission.ts, ownsRow) or list the line with its reason').toEqual([])
  })

  test('no listed entry outlives its lines', () => {
    expect(Object.keys(ALLOWED).filter((key) => !found.has(key))).toEqual([])
  })

  test('every entry gives its reason', () => {
    expect(Object.entries(ALLOWED).filter(([, a]) => !a.pending && a.reason.trim().length < 20).map(([k]) => k)).toEqual([])
  })

  test('the rules catch the shapes they name, and not their look-alikes', () => {
    const hits = (rule: string, line: string) => RULES[rule].test(line)
    expect(hits('owner_compare', 'if (project.userId !== eff.userId) return')).toBe(true)
    expect(hits('owner_compare', "const id = typeof body.userId === 'string' ? body.userId : null")).toBe(false)
    expect(hits('role_admin', "if (session.role !== 'admin')")).toBe(true)
    expect(hits('list_on_caller', 'where: { project: { userId: eff.userId } },')).toBe(true)
    expect(hits('find_by_id_and_owner', 'tx.project.findFirst({ where: { id: projectId, userId } })')).toBe(true)
    expect(hits('row_owner_helper', 'where: ownerScope(eff),')).toBe(true)
    expect(hits('identity_header', "request.headers.get('x-user-id')")).toBe(true)
    expect(hits('is_admin', 'const isAdmin = true')).toBe(true)
    expect(hits('is_admin', 'await isAdminAccount(id)')).toBe(false)
  })
})
