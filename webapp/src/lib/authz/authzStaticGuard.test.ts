/**
 * Owner checks, admin checks and "my projects" filters go through the policy (lib/authz):
 * `projectAccess()` / `visibleProjectsWhere()` for a project, `can()` for a permission
 * (adminPermission.ts for the signed-in person's administration permissions), `ownsRow()` for a
 * per-user row. An inline `project.userId === user` or `role === 'admin'` elsewhere is a second
 * policy that the next change to the first one (shares, permission sets) silently misses.
 *
 * Scans every non-test source under src/app/api and src/lib, except lib/authz itself, for the
 * shapes such a check takes. Each file is matched whole, so a check written over several lines
 * (`findFirst({` with `where: { id, userId }` on the next) is caught like a one-line one. Each
 * remaining match is listed below by its statement (the lines it spans, trimmed and joined), per
 * file and rule, with why it is not an ownership or permission decision (a per-user row, a
 * lookup keyed by the account, an account type, the account the path names). A new match fails
 * the test until it goes through lib/authz or joins the list with its reason, and so does a listed
 * statement that changed: replacing a listed line with another check in the same file is a new
 * match, not the old one. A listed statement that no longer matches fails too, so the list never
 * outgrows the code.
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
 * `\s` and `[^}]` cross line ends, because a file is matched whole.
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
const PATH_ROW = "a per-user row of the account requireUserAccess / requireOwnBrowserRequest let in, not a project's owner"
const SKILL_OWNER_PROJECT = "the project whose toggles name the skill owner's own skills (the agent loads the project owner's user skills, so only the owner's project can switch them on), not any project the person sees"
const CAPTURE_TENANT = 'the capture rows of a project carry its owner as tenant (ingest writes it), filtered after the project guard'
const PLUGINS_VIEWER = `the viewer manages plugins (pageModel.ts viewerIsAdmin, which asks platform:plugins): the isAdmin field of /api/plugins that PluginsPageClient.tsx and PluginCard.tsx read`
const SHARED_TOOL = 'a shared-tool short-circuit before sharedToolAccess (sharedTools.ts); the platform permission replaces both with the platform routes'

interface Allowed {
  reason: string
  /** The listed statements, one per match (a statement that matches twice is listed twice). */
  lines: readonly string[]
}

const ALLOWED: Record<string, Allowed> = {
  'src/app/api/admin/instance-settings/route.ts::role_admin': {
    reason: SHARED_TOOL,
    lines: [
      "if (session.role === 'admin') {",
    ],
  },
  'src/app/api/auth/act-as/route.ts::role_admin': {
    reason: `the target's ${ACCOUNT_TYPE}: acting as another admin is Root's (rootPowers.ts)`,
    lines: [
      "if (target.role === 'admin') {",
    ],
  },
  'src/app/api/mcp/manifest/route.ts::list_on_caller': {
    reason: "the caller's own MCP servers: a per-user row",
    lines: [
      'where: { userId: eff.userId },',
    ],
  },
  'src/app/api/models/route.ts::list_on_caller': {
    reason: "the caller's own LLM providers: a per-user row",
    lines: [
      'const rows = await prisma.userLlmProvider.findMany({ where: { userId: eff.userId } })',
    ],
  },
  'src/app/api/mute-rule-presets/route.ts::row_owner_helper': {
    reason: "the caller's own mute-rule presets: a per-user row (rowOwner.ts)",
    lines: [
      'where: ownerScope(eff),',
    ],
  },
  'src/app/api/nuclei-templates/route.ts::role_admin': {
    reason: SHARED_TOOL,
    lines: [
      "if (session.role === 'admin') return { allowed: true, via: 'admin' }",
    ],
  },
  'src/app/api/plugins/[pluginId]/route.ts::is_admin': {
    reason: PLUGINS_VIEWER,
    lines: [
      'const isAdmin = !!session && (await viewerIsAdmin(session.userId))',
      'const out = await buildPluginDetail(pluginId, isAdmin)',
    ],
  },
  'src/app/api/plugins/route.ts::is_admin': {
    reason: PLUGINS_VIEWER,
    lines: [
      'const isAdmin = !!session && (await viewerIsAdmin(session.userId))',
      "return NextResponse.json(await buildPluginsPage(isAdmin), { headers: { 'Cache-Control': 'no-store' } })",
    ],
  },
  'src/app/api/presets/[id]/route.ts::row_owner_helper': {
    reason: "a preset is its author's: a per-user row (rowOwner.ts)",
    lines: [
      'const denied = assertOwner(eff, preset.userId)',
      'const denied = assertOwner(eff, preset.userId)',
    ],
  },
  'src/app/api/presets/route.ts::row_owner_helper': {
    reason: "the caller's own presets: a per-user row (rowOwner.ts)",
    lines: [
      'where: ownerScope(eff),',
    ],
  },
  'src/app/api/projects/[id]/supply-chain-batch/route.ts::list_on_caller': {
    reason: "the effective user's own GitHub token: a per-user row",
    lines: [
      'where: { userId: eff.userId },',
    ],
  },
  'src/app/api/system/jobs/route.ts::list_on_caller': {
    reason: "the caller's own queue rows (JobQueue.userId is the actor who queued them): a per-user row; the running scans go by the projects the caller sees (visibleProjects.ts)",
    lines: [
      "where: { userId: eff.userId, status: { in: ['running', 'dispatching', 'queued', 'needs_review'] } },",
      "where: { userId: eff.userId, status: { in: ['done', 'failed', 'canceled'] } },",
    ],
  },
  'src/app/api/traffic/[projectId]/[id]/route.ts::row_owner_helper': {
    reason: CAPTURE_TENANT,
    lines: [
      'where: { id, projectId, ...ownerScope(eff) },',
    ],
  },
  'src/app/api/traffic/[projectId]/facets/route.ts::row_owner_helper': {
    reason: CAPTURE_TENANT,
    lines: [
      'const where = { projectId, ...ownerScope(eff) }',
    ],
  },
  'src/app/api/traffic/[projectId]/route.ts::row_owner_helper': {
    reason: CAPTURE_TENANT,
    lines: [
      'const where: Prisma.CapturedHttpTransactionWhereInput = { projectId, ...ownerScope(eff) }',
    ],
  },
  'src/app/api/users/[id]/attack-skills/[skillId]/release/route.ts::owner_compare': {
    reason: OWN_ACCOUNT,
    lines: [
      'if (session.userId !== id) {',
    ],
  },
  'src/app/api/users/[id]/attack-skills/[skillId]/route.ts::find_by_id_and_owner': {
    reason: `the path's account's own attack skill, looked up by id and that account: ${PATH_ROW}`,
    lines: [
      'const skill = await prisma.userAttackSkill.findFirst({ where: { id: skillId, userId: id },',
    ],
  },
  'src/app/api/users/[id]/attack-skills/name-check/route.ts::find_by_id_and_owner': {
    reason: `the path's account's own attack skill (the source of a new version), looked up by id and that account: ${PATH_ROW}`,
    lines: [
      '? await prisma.userAttackSkill.findFirst({ where: { id: sourceId, userId: id }, select: { id: true, name: true, lineageRootId: true },',
    ],
  },
  'src/app/api/users/[id]/chat-skills/[skillId]/route.ts::find_by_id_and_owner': {
    reason: `the path's account's own chat skill, looked up by id and that account: ${PATH_ROW}`,
    lines: [
      'const skill = await prisma.userChatSkill.findFirst({ where: { id: skillId, userId: id },',
      'const existing = await prisma.userChatSkill.findFirst({ where: { id: skillId, userId: id },',
      'const existing = await prisma.userChatSkill.findFirst({ where: { id: skillId, userId: id },',
    ],
  },
  'src/app/api/users/[id]/llm-providers/[providerId]/route.ts::find_by_id_and_owner': {
    reason: `the path's account's own LLM provider, looked up by id and that account: ${PATH_ROW}`,
    lines: [
      'const provider = await prisma.userLlmProvider.findFirst({ where: { id: providerId, userId: id },',
      'const existing = await prisma.userLlmProvider.findFirst({ where: { id: providerId, userId: id },',
      'const existing = await prisma.userLlmProvider.findFirst({ where: { id: providerId, userId: id },',
    ],
  },
  'src/app/api/users/[id]/llm-providers/[providerId]/test/route.ts::find_by_id_and_owner': {
    reason: `the path's account's own LLM provider, looked up by id and that account: ${PATH_ROW}`,
    lines: [
      'const provider = await prisma.userLlmProvider.findFirst({ where: { id: providerId, userId: id },',
    ],
  },
  'src/app/api/users/[id]/llm-providers/route.ts::owner_compare': {
    reason: `${OWN_ACCOUNT}; another account needs users:read`,
    lines: [
      "if (session.userId !== id && !(await sessionHolds(session, 'users:read'))) {",
    ],
  },
  'src/app/api/users/[id]/mcp-tokens/[tokenId]/route.ts::owner_compare': {
    reason: OWN_ACCOUNT,
    lines: [
      'if (!session || session.userId !== id) {',
    ],
  },
  'src/app/api/users/[id]/mcp-tokens/route.ts::owner_compare': {
    reason: OWN_ACCOUNT,
    lines: [
      'if (session.userId !== id) {',
    ],
  },
  'src/app/api/users/[id]/password/route.ts::owner_compare': {
    reason: OWN_ACCOUNT,
    lines: [
      'const isSelf = session.userId === id',
    ],
  },
  'src/app/api/users/[id]/password/route.ts::role_admin': {
    reason: `the target's ${ACCOUNT_TYPE}: resetting another admin is Root's (rootPowers.ts)`,
    lines: [
      "adminTarget = target?.role === 'admin'",
    ],
  },
  'src/app/api/users/[id]/route.ts::owner_compare': {
    reason: `the Root re-check under the Root lock names Root's account (rootProtection.ts), and ${OWN_ACCOUNT} (another account needs users:read or users:edit; nobody deletes their own)`,
    lines: [
      "if (root && root.userId === id && id !== session.userId) return { refused: 'root_protected' }",
      "if (needsRoot && !(root && root.userId === session.userId && root.confirmed)) return { refused: 'root_only' }",
      "if (session.userId !== id && !(await sessionHolds(session, 'users:read'))) {",
      "if ((session.userId !== id || role) && !(await sessionHolds(session, 'users:edit', { fresh: true }))) {",
      'if (session.userId === id) {',
    ],
  },
  'src/app/api/users/[id]/route.ts::owner_compare_rows': {
    reason: "the Root re-check under the Root lock: whether the actor is the confirmed Root (step 2.6's power)",
    lines: [
      "if (needsRoot && !(root && root.userId === session.userId && root.confirmed)) return { refused: 'root_only' }",
    ],
  },
  'src/app/api/users/[id]/route.ts::role_admin': {
    reason: `the target's or the requested ${ACCOUNT_TYPE}: another admin and a promotion are Root's or admins:manage's (hierarchy.ts)`,
    lines: [
      "const otherAdmin = !self && target.role === 'admin'",
      "const promotes = roleChange && data.role === 'admin'",
      "return target?.role === 'admin'",
      "if (role === 'admin' || role === 'standard') data.role = role",
      "const targetIsAdmin = target?.role === 'admin'",
    ],
  },
  'src/app/api/users/[id]/settings/api-usage/route.ts::owner_compare': {
    reason: OWN_ACCOUNT,
    lines: [
      "if (eff.userId !== id) return json({ error: 'Forbidden' }, 403)",
    ],
  },
  'src/app/api/users/[id]/settings/route.ts::owner_compare': {
    reason: OWN_ACCOUNT,
    lines: [
      'if (eff.userId !== id) return refused',
    ],
  },
  'src/app/api/users/[id]/settings/route.ts::role_admin': {
    reason: SHARED_TOOL,
    lines: [
      "if (session.role === 'admin') return { access: { allowed: true, via: 'admin' }, actor }",
    ],
  },
  'src/app/api/users/[id]/tradecraft-resources/[resourceId]/refresh/route.ts::find_by_id_and_owner': {
    reason: `the path's account's own tradecraft resource, looked up by id and that account: ${PATH_ROW}`,
    lines: [
      'const existing = await prisma.userTradecraftResource.findFirst({ where: { id: resourceId, userId: id },',
    ],
  },
  'src/app/api/users/[id]/tradecraft-resources/[resourceId]/route.ts::find_by_id_and_owner': {
    reason: `the path's account's own tradecraft resource, looked up by id and that account: ${PATH_ROW}`,
    lines: [
      'const resource = await prisma.userTradecraftResource.findFirst({ where: { id: resourceId, userId: id },',
      'const existing = await prisma.userTradecraftResource.findFirst({ where: { id: resourceId, userId: id },',
      'const existing = await prisma.userTradecraftResource.findFirst({ where: { id: resourceId, userId: id },',
    ],
  },
  'src/app/api/users/[id]/tradecraft-resources/[resourceId]/verify/route.ts::find_by_id_and_owner': {
    reason: `the path's account's own tradecraft resource, looked up by id and that account: ${PATH_ROW}`,
    lines: [
      'const existing = await prisma.userTradecraftResource.findFirst({ where: { id: resourceId, userId: id },',
    ],
  },
  'src/app/api/users/route.ts::role_admin': {
    reason: `the requested ${ACCOUNT_TYPE}: creating an admin is Root's (rootPowers.ts)`,
    lines: [
      "const makesAdmin = role === 'admin' && rbacFlags().identity",
      "...((role === 'admin' || role === 'standard') ? { role } : {}),",
    ],
  },
  'src/lib/access.ts::row_owner_helper': {
    reason: "the definitions of the per-user row helpers, which delegate to rowOwner.ts",
    lines: [
      'export function assertOwnerStrict(eff: EffectiveUser, ownerId: string): NextResponse | null {',
      'export function assertOwner(eff: EffectiveUser, ownerId: string): NextResponse | null {',
      'export function ownerScope(eff: EffectiveUser): RowOwnerFilter {',
    ],
  },
  'src/lib/mcp/engagementTools.ts::find_by_id_and_owner': {
    reason: "the project owner's Jev provider (resolveAiHooks): the owner's own LLM provider row, a lookup keyed by the account",
    lines: [
      'const provider = await prisma.userLlmProvider.findFirst({ where: { id: selected, userId: ownerUserId, providerType: { in: [...JEV_PROVIDER_TYPES] } },',
    ],
  },
  'src/lib/mcp/presetTools.ts::find_by_id_and_owner': {
    reason: "the token user's own preset, read and re-read around its write: a per-user row",
    lines: [
      'const row = await prisma.userProjectPreset.findFirst({ where: { id, userId: ctx.token.userId },',
      'const row = await prisma.userProjectPreset.findFirst({ where: { id: args.presetId, userId: ctx.token.userId },',
      'const row = await prisma.userProjectPreset.findFirst({ where: { id: args.presetId, userId: ctx.token.userId },',
      'const still = await prisma.userProjectPreset.findFirst({ where: { id: row.id, userId: ctx.token.userId }, select: { id: true },',
    ],
  },
  'src/lib/mcp/presetTools.ts::list_on_caller': {
    reason: "the token user's own presets, counted for the per-user cap: a per-user row",
    lines: [
      'const count = await prisma.userProjectPreset.count({ where: { userId: ctx.token.userId } })',
    ],
  },
  'src/lib/mcp/tools.ts::list_on_caller': {
    reason: "MCP lists the projects its token user owns: every MCP project tool needs the owner level (mcpAuth.ts assertMcpProjectAccess)",
    lines: [
      'where: { userId: ctx.token.userId },',
    ],
  },
  'src/lib/mcp/userServerAccess.ts::role_admin': {
    reason: "whether a stdio server's owner runs it: the owner's admin account type until the platform routes check platform:agent_mcp",
    lines: [
      "return owner?.role === 'admin'",
    ],
  },
  'src/lib/plugins/pageModel.ts::is_admin': {
    reason: PLUGINS_VIEWER,
    lines: [
      'isAdmin: boolean',
      'function catalogView(loaded: LoadedCatalog | null, error: CatalogError | null, isAdmin: boolean): CatalogView {',
      '...(isAdmin && error ? { detail: capped(error.message, CATALOG_DETAIL_MAX) } : {}),',
      '...(isAdmin && details?.length ? { details } : {}),',
      'function installedView(row: PluginInstall, isAdmin: boolean): InstalledView {',
      'if (isAdmin) v.lastError = row.lastError',
      'isAdmin: boolean,',
      'installed: row && installedState ? installedView(row, isAdmin) : null,',
      'if (isAdmin && row && !installedState) entry.lastAttemptError = row.lastError',
      'export async function buildPluginsPage(isAdmin: boolean): Promise<PluginsPage> {',
      'plugins.push(entryOf(p.id, p, p.releases, byId.get(p.id) ?? null, loaded, isAdmin))',
      "if (row.status === 'available' && (!isAdmin || !(await hasKeptAnything(row.pluginId)))) continue",
      'plugins.push(entryOf(row.pluginId, null, null, row, loaded, isAdmin))',
      'if (isAdmin) {',
      'return { platformVersion: PLUGIN_PLATFORM_VERSION, isAdmin, catalog: catalogView(loaded, error, isAdmin), plugins }',
      'export async function buildPluginDetail(pluginId: string, isAdmin: boolean): Promise<PluginDetail | null> {',
      'const page = await buildPluginsPage(isAdmin)',
      'const entry = plugin ?? entryOf(pluginId, null, null, row, null, isAdmin)',
      'if (!isAdmin) return { plugin: entry }',
    ],
  },
  'src/lib/plugins/userSkillAdoption.ts::find_by_id_and_owner': {
    reason: `the skill owner's source skill (a per-user row) and ${SKILL_OWNER_PROJECT}, inside the save's transaction`,
    lines: [
      'const source = await tx.userAttackSkill.findFirst({ where: { id: sourceId, userId: input.ownerId },',
      'const row = await tx.project.findFirst({ where: { id: input.projectId, userId: input.ownerId },',
    ],
  },
  'src/lib/plugins/userSkillOverrideOps.ts::find_by_id_and_owner': {
    reason: "the token user's own skill, read and re-read in the write's transaction: a per-user row",
    lines: [
      'skill = await prisma.userAttackSkill.findFirst({ where: { id: group, userId: ctx.userId },',
      'const now = await tx.userAttackSkill.findFirst({ where: { id: skill.id, userId: ctx.userId }, select: { content: true } })',
    ],
  },
  'src/lib/plugins/userSkillReviewModel.ts::find_by_id_and_owner': {
    reason: `the skill owner's source skill (a per-user row) and ${SKILL_OWNER_PROJECT}, for the review card`,
    lines: [
      'prisma.userAttackSkill.findFirst({ where: { id: set.targetGroup, userId: ownerId },',
      'const row = await prisma.project.findFirst({ where: { id: opts.projectId, userId: ownerId },',
    ],
  },
  'src/lib/plugins/userSkillVersionsModel.ts::find_by_id_and_owner': {
    reason: "the skill owner's own skill, whose versions the page lists: a per-user row",
    lines: [
      'const skill = await prisma.userAttackSkill.findFirst({ where: { id: skillId, userId: ownerId },',
    ],
  },
  'src/lib/reconPresets/server.ts::find_by_id_and_owner': {
    reason: "the caller's own recon preset: a per-user row",
    lines: [
      'const row = await prisma.userProjectPreset.findFirst({ where: { id: presetId, userId }, select: PRESET_ROW_SELECT })',
    ],
  },
  'src/lib/reconSettings/jevEngine.ts::find_by_id_and_owner': {
    reason: "the project owner's Jev provider: the owner's own LLM provider row, a lookup keyed by the account",
    lines: [
      'const provider = await prisma.userLlmProvider.findFirst({ where: { id: selection, userId: ownerUserId, providerType: { in: [...JEV_PROVIDER_TYPES] } },',
    ],
  },
  'src/lib/session.ts::owner_compare': {
    reason: OWN_ACCOUNT,
    lines: [
      'if (session.userId === targetUserId) return null',
      "if (session.userId !== targetUserId && !(await sessionHolds(session, 'users:read'))) {",
    ],
  },
  'src/lib/session.ts::role_admin': {
    reason: `${ACCOUNT_TYPE}: the act-as rule (only an admin acts as anyone, nobody as Root) and requireAdmin, the administrator-account gate each caller follows with its permission`,
    lines: [
      "return account.role === 'admin'",
      "return target.role !== 'admin' || !(await isRootAccount(target.id, opts))",
      "if (result.role !== 'admin') {",
    ],
  },
  'src/lib/userAudit.ts::role_admin': {
    reason: "the act-as rule (only an admin acts as anyone), as session.ts mayActAs reads it, for the audit row",
    lines: [
      "if (actor.role !== 'admin') return null",
    ],
  },
  'src/lib/userSkillWrites.ts::find_by_id_and_owner': {
    reason: `the skill owner's rows inside the per-user lock's transaction: its user skills, and ${SKILL_OWNER_PROJECT}`,
    lines: [
      'const row = await tx.project.findFirst({ where: { id: projectId, userId }, select: { id: true, attackSkillConfig: true } })',
      'const existing = await tx.userAttackSkill.findFirst({ where: { id: input.skillId, userId: input.userId } })',
      'const existing = await tx.userAttackSkill.findFirst({ where: { id: input.skillId, userId: input.userId } })',
      'const existing = await tx.userAttackSkill.findFirst({ where: { id: input.skillId, userId: input.userId } })',
    ],
  },
}

/** One match: its rule, the line it starts on, and its statement (the lines it spans, trimmed, joined by a space). */
interface Match {
  rule: string
  line: number
  statement: string
}

/** Every match in one file's text, at most one per rule and starting line. */
function scanText(text: string): Match[] {
  const starts = [0]
  for (let i = 0; i < text.length; i++) if (text[i] === '\n') starts.push(i + 1)
  const lineOf = (pos: number) => {
    let lo = 0
    let hi = starts.length - 1
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1
      if (starts[mid] <= pos) lo = mid
      else hi = mid - 1
    }
    return lo
  }
  const lines = text.split('\n')
  const out: Match[] = []
  for (const [rule, re] of Object.entries(RULES)) {
    const seen = new Set<number>()
    for (const m of text.matchAll(new RegExp(re.source, `${re.flags}g`))) {
      const at = m.index ?? 0
      const first = lineOf(at)
      if (seen.has(first)) continue
      seen.add(first)
      const last = lineOf(at + Math.max(m[0].length - 1, 0))
      out.push({ rule, line: first + 1, statement: lines.slice(first, last + 1).map((l) => l.trim()).join(' ') })
    }
  }
  return out
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

/** `file::rule` -> its matches, for every file outside lib/authz. */
function scan(): Map<string, Match[]> {
  const found = new Map<string, Match[]>()
  for (const root of ROOTS) {
    for (const full of sources(join(WEBAPP, root))) {
      const file = relative(WEBAPP, full).split(sep).join('/')
      if (file.startsWith('src/lib/authz/')) continue
      for (const match of scanText(readFileSync(full, 'utf8'))) {
        const key = `${file}::${match.rule}`
        found.set(key, [...(found.get(key) ?? []), match])
      }
    }
  }
  return found
}

/**
 * The matches no listed statement accounts for, and the listed statements no match accounts for,
 * per `file::rule`; each statement counts as often as it is listed.
 */
function compare(found: Map<string, Match[]>, allowed: Record<string, Allowed>): { unlisted: string[]; stale: string[] } {
  const unlisted: string[] = []
  const stale: string[] = []
  for (const key of new Set([...found.keys(), ...Object.keys(allowed)])) {
    const left = [...(allowed[key]?.lines ?? [])]
    for (const m of found.get(key) ?? []) {
      const i = left.indexOf(m.statement)
      if (i >= 0) left.splice(i, 1)
      else unlisted.push(`${key} line ${m.line}: ${m.statement}`)
    }
    stale.push(...left.map((s) => `${key}: ${s}`))
  }
  return { unlisted, stale }
}

describe('no inline owner or admin check outside lib/authz', () => {
  const found = scan()
  const { unlisted, stale } = compare(found, ALLOWED)

  test('the scan reads the tree (a moved folder must not make it pass empty)', () => {
    expect(found.size).toBeGreaterThan(0)
    expect([...found.keys()].some((k) => k.startsWith('src/app/api/'))).toBe(true)
    expect([...found.keys()].some((k) => k.startsWith('src/lib/'))).toBe(true)
  })

  test('every match is listed by its statement, with a reason', () => {
    expect(unlisted, 'go through lib/authz (projectAccess, visibleProjectsWhere, can / adminPermission.ts, ownsRow) or list the statement with its reason').toEqual([])
  })

  test('no listed statement outlives its match', () => {
    expect(stale).toEqual([])
  })

  test('every entry gives its reason and lists a statement', () => {
    expect(Object.entries(ALLOWED).filter(([, a]) => a.reason.trim().length < 20 || a.lines.length === 0).map(([k]) => k)).toEqual([])
  })

  test('the rules catch the shapes they name, and not their look-alikes', () => {
    const hits = (rule: string, text: string) => scanText(text).some((m) => m.rule === rule)
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

  test('a check written over several lines is caught, on the line it starts, with its whole statement', () => {
    const text = [
      'export async function load(projectId: string, ownerId: string) {',
      '  const row = await tx.project.findFirst({',
      '    where: { id: projectId, userId: ownerId },',
      '    select: { id: true },',
      '  })',
      '  if (row.userId',
      '      !== eff.userId) return null',
      '  return prisma.project.findMany({ where: {',
      '    userId: session.userId } })',
      '}',
    ].join('\n')
    expect(scanText(text)).toEqual(expect.arrayContaining([
      { rule: 'find_by_id_and_owner', line: 2, statement: 'const row = await tx.project.findFirst({ where: { id: projectId, userId: ownerId },' },
      { rule: 'owner_compare', line: 6, statement: 'if (row.userId !== eff.userId) return null' },
      { rule: 'list_on_caller', line: 8, statement: 'return prisma.project.findMany({ where: { userId: session.userId } })' },
    ]))
  })

  test('a listed statement replaced by another check in the same file fails, though the count holds', () => {
    const allowed = { 'f.ts::role_admin': { reason: 'a fixture: the target account type', lines: ["if (target.role === 'admin') {"] } }
    const replaced = new Map([['f.ts::role_admin', scanText("if (session.role === 'admin') return everything()")]])
    expect(compare(replaced, allowed)).toEqual({
      unlisted: ["f.ts::role_admin line 1: if (session.role === 'admin') return everything()"],
      stale: ["f.ts::role_admin: if (target.role === 'admin') {"],
    })
    const kept = new Map([['f.ts::role_admin', scanText("if (target.role === 'admin') {")]])
    expect(compare(kept, allowed)).toEqual({ unlisted: [], stale: [] })
    const twice = new Map([['f.ts::role_admin', scanText("if (target.role === 'admin') {\nif (target.role === 'admin') {")]])
    expect(compare(twice, allowed).unlisted).toEqual(["f.ts::role_admin line 2: if (target.role === 'admin') {"])
  })
})
