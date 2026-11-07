/**
 * The three tools that open, authorize and verify an engagement.
 *
 * Together they close the gap between "an agent can configure every parameter of
 * the pipeline" and "an agent can stand up a project that provably cannot
 * violate its scope". Configuring was already possible; the rest was not, and a
 * pipeline whose compliance nobody can check is a pipeline nobody should point
 * at a third party.
 *
 *   create_project                     opens an engagement and fixes its scope
 *   attach_engagement_authorization    records what permitted it
 *   preflight_scope_check              proves the configuration fits
 *
 * There is no fourth. `tighten_engagement_roe` existed because the engagement's
 * limits were a block with its own direction rules; they are ordinary settings
 * now, written through `update_recon_settings` like every other field and
 * enforced at scan start whatever a write said. `preflight_scope_check` is what
 * replaced the reassurance the direction rules only appeared to give: it reports
 * the RESOLVED configuration rather than the written one.
 *
 * Every one of them joins the guards the existing write tools already use, and
 * a tool that skipped one would be a hole in a control that holds everywhere
 * else on this surface: the project-access assertion, a rate-limit bucket, the
 * busy check where a running scan would not see the change, optimistic
 * concurrency, and an audit row.
 *
 * `create_project` is the exception to two of them, and both exceptions are
 * structural rather than convenient: there is no project yet to be busy on and
 * no prior `updatedAt` to compare. What it has instead is an idempotency key,
 * which matters more here than usual because an unattended loop's normal
 * failure path is a retry, and a retry that creates a second project with the
 * same scope is two engagements where the operator authorized one.
 */
import prisma from '@/lib/prisma'
import { writeAudit } from '@/lib/audit'
import { describeInvalid, validateDomainBatch, MAX_BATCH_HOSTS } from '@/lib/domainBatch'
import {
  guardrailNames, resolveScopeGroups, scopeGuardrailNames, softGuardrailNames,
} from '@/lib/scopeGroups'
import { internalKeyHeaders } from '@/lib/agentAuth'
import {
  currentAuthorization,
  describeEngagement,
  digestScopeDocument,
  effectiveCeiling,
  isDocumentKind,
  isEngagementKind,
  deriveRoeEnabled,
  isSha256,
  loadEngagement,
  DOCUMENT_KINDS,
  ENGAGEMENT_KINDS,
  type EngagementProjectRow,
} from '@/lib/engagement'
import { describeScanWriters } from '@/lib/graphWriters'
import { firstHardBlocked } from '@/lib/hard-guardrail'
import { assertMcpProjectAccess, requireScope } from '@/lib/mcpAuth'
import { McpToolError } from '@/lib/mcp/errors'
import { enforceRate, type McpContext } from '@/lib/mcp/tools'
import { settingsFingerprint } from '@/lib/jobQueue'
import { filterReconSettings, reconSettingsSelect } from '@/lib/reconSettings/filter'
import { fieldsWhere, field } from '@/lib/reconSettings/registry'
import { checkHeader, isInsideProjectFileRoot } from '@/lib/reconSettings/validators'
import { validateJevEngineChange } from '@/lib/reconSettings/jevEngine'
import { JEV_PROVIDER_TYPES } from '@/lib/llmProviderKinds'
import { normalizeUserSkillToggles, UserSkillError } from '@/lib/userSkills'

// --- create_project -----------------------------------------------------------------

export interface CreateProjectArgs {
  name: string
  description?: string
  engagementKind: string
  /** Exactly one targeting mode. */
  targetDomain?: string
  targetIps?: string[]
  domainBatchHosts?: string[]
  subdomainList?: string[]
  /**
   * Ordinary tuning AND the engagement's limits, applied at creation so the
   * first scan runs configured. There is no separate `roe` argument: the limits
   * are ordinary settings, writable here and through update_recon_settings
   * afterwards.
   */
  settings?: Record<string, unknown>
  engagementIdentityHeader?: string
  /** Required when engagementKind is third_party. */
  authorization?: AuthorizationArgs
  /**
   * Derived from the authorization digest plus the program handle by the caller.
   * A second call with the same key returns the FIRST project rather than
   * creating another.
   */
  idempotencyKey?: string
}

export interface AuthorizationArgs {
  documentSha256?: string
  /** The scope document itself, when the caller has the text rather than a digest. */
  documentText?: string
  documentKind: string
  sourceUrl?: string
  programHandle?: string
  issuedAt: string
  summary?: string
}

function requireTargetingMode(args: CreateProjectArgs) {
  const modes = [
    args.targetDomain?.trim() ? 'targetDomain' : null,
    args.targetIps?.length ? 'targetIps' : null,
    args.domainBatchHosts?.length ? 'domainBatchHosts' : null,
  ].filter(Boolean) as string[]

  if (modes.length === 0) {
    throw new McpToolError(
      'A project needs exactly one targeting mode: targetDomain, targetIps, or ' +
      'domainBatchHosts. None was given.',
      'bad_args'
    )
  }
  if (modes.length > 1) {
    throw new McpToolError(
      `A project has exactly one targeting mode, and ${modes.join(' and ')} were both given. ` +
      'They are mutually exclusive: the pipeline derives its hosts from one of them.',
      'bad_args'
    )
  }
  return modes[0]
}

export function normaliseAuthorization(auth: AuthorizationArgs) {
  if (!isDocumentKind(auth.documentKind)) {
    throw new McpToolError(
      `documentKind must be one of ${DOCUMENT_KINDS.join(', ')}.`,
      'bad_args'
    )
  }
  let digest = auth.documentSha256
  if (!digest && typeof auth.documentText === 'string' && auth.documentText.trim()) {
    digest = digestScopeDocument(auth.documentText)
  }
  if (!isSha256(digest)) {
    throw new McpToolError(
      'documentSha256 must be 64 lower-case hex characters, or pass documentText and it ' +
      'will be digested here. The document itself is never stored.',
      'bad_args'
    )
  }
  const issuedAt = new Date(auth.issuedAt)
  if (Number.isNaN(issuedAt.getTime())) {
    throw new McpToolError('issuedAt must be an ISO 8601 timestamp.', 'bad_args')
  }
  if (issuedAt.getTime() > Date.now() + 60_000) {
    throw new McpToolError('issuedAt is in the future.', 'bad_args')
  }
  return {
    documentSha256: digest,
    documentKind: auth.documentKind,
    sourceUrl: (auth.sourceUrl ?? '').trim(),
    programHandle: auth.programHandle?.trim() || null,
    issuedAt,
    summary: (auth.summary ?? '').trim().slice(0, 500),
  }
}

/**
 * Keys `settings` may not carry, because this tool derives them from its own
 * arguments.
 *
 * `settings` is filtered in CREATE mode, which by design accepts the create-only
 * fields too. That is right for a creation and wrong for this one object: it is
 * applied last, so a key here would silently overwrite a value the engagement
 * guard above had just checked. The mode selectors are derived from the
 * targeting arguments and `engagementKind` decides which guard runs at all.
 *
 * The engagement's LIMITS are deliberately absent from this list. They are
 * ordinary settings and belong in `settings`, and the third_party ceiling check
 * below reads what lands there.
 */
const RESERVED_AT_CREATE = new Set([
  'targetDomain', 'targetIps', 'ipMode',
  'domainBatchMode', 'domainBatchHosts', 'domainBatchGroups', 'subdomainList',
  'engagementKind', 'engagementIdentityHeader',
])

function filterSettingsAtCreate(settings: Record<string, unknown>): Record<string, unknown> {
  const reserved = Object.keys(settings).filter(k => RESERVED_AT_CREATE.has(k))
  if (reserved.length > 0) {
    throw new McpToolError(
      `${reserved.join(', ')} may not be set through \`settings\`: this tool derives the ` +
      'targeting mode and the engagement kind from its own arguments, and a value here ' +
      'would override the scope that was just checked. Pass them as arguments.',
      'bad_args'
    )
  }
  const filtered = filterReconSettings(settings, { mode: 'create' })
  if (!filtered.ok) throw new McpToolError(filtered.error, 'setting_rejected')
  return filtered.data
}

/**
 * The project an earlier call with this key already created, or null.
 *
 * Used twice: once before writing anything, and again when the write loses the
 * race. The pre-check alone is check-then-act, and the column is `@unique`, so
 * two concurrent retries of the same loop tick would otherwise give the second
 * one a raw P2002 instead of the first project. An unattended caller's answer
 * to an opaque error is another retry, this time with a fresh key, which is the
 * second project the key exists to prevent.
 */
async function findByIdempotencyKey(ctx: McpContext, key: string) {
  const existing = await prisma.engagementAuthorization.findUnique({
    where: { idempotencyKey: key },
    select: { projectId: true, project: { select: { userId: true, name: true } } },
  })
  if (!existing) return null
  if (existing.project.userId !== ctx.token.userId) {
    throw new McpToolError(
      'That idempotency key belongs to another account\'s project.',
      'access_denied'
    )
  }
  return {
    projectId: existing.projectId,
    name: existing.project.name,
    created: false,
    note: 'An earlier call with this idempotency key already created this project.',
  }
}

/**
 * The non-disableable check the project form runs at creation. Scan start runs
 * it again, but a project that can never be scanned should not be created
 * either: it would carry an authorization record for a target nobody may touch.
 */
export function refuseHardBlocked(domains: string[]): void {
  const hit = firstHardBlocked(domains)
  if (hit) {
    throw new McpToolError(`Target permanently blocked: ${hit.name}: ${hit.reason}`, 'target_blocked')
  }
}

const AGENT_API_URL = process.env.AGENT_API_URL || 'http://localhost:8080'
// The soft guardrail fails open by design (the hard guardrail is the control
// that may not be bypassed), so a hung agent must not stall a write either.
const SOFT_GUARDRAIL_TIMEOUT_MS = 10_000

/**
 * The soft (LLM) guardrail, as the HTTP project routes call it: the reason when
 * the agent refuses the target, null when it allows it or cannot be asked.
 */
export async function softGuardrailRefusal(target: {
  targetDomain?: string
  targetDomains?: string[]
  targetIps?: string[]
  userId: string
}): Promise<string | null> {
  try {
    const res = await fetch(`${AGENT_API_URL}/guardrail/check-target`, {
      method: 'POST',
      headers: internalKeyHeaders({ 'Content-Type': 'application/json' }),
      signal: AbortSignal.timeout(SOFT_GUARDRAIL_TIMEOUT_MS),
      body: JSON.stringify({
        target_domain: target.targetDomain ?? '',
        target_domains: target.targetDomains ?? [],
        target_ips: target.targetIps ?? [],
        user_id: target.userId,
      }),
    })
    if (!res.ok) return null
    const verdict = await res.json()
    return verdict?.allowed === false ? String(verdict.reason || 'refused by the guardrail') : null
  } catch (err) {
    console.warn('[mcp] soft guardrail unreachable, allowing:', err)
    return null
  }
}

function isUniqueViolation(error: unknown): boolean {
  return (
    typeof error === 'object' && error !== null && (error as { code?: string }).code === 'P2002'
  )
}

export async function createProject(ctx: McpContext, args: CreateProjectArgs) {
  requireScope(ctx.token, 'project:create')
  enforceRate(ctx, 'write')

  const name = (args.name ?? '').trim()
  if (!name) throw new McpToolError('A project needs a name.', 'bad_args')
  if (!isEngagementKind(args.engagementKind)) {
    throw new McpToolError(
      `engagementKind must be one of ${ENGAGEMENT_KINDS.join(', ')}. 'third_party' means ` +
      'somebody else\'s estate and requires a rate ceiling and an authorization record.',
      'bad_args'
    )
  }
  const mode = requireTargetingMode(args)

  // A retried loop tick, a duplicated run or two operators acting at once would
  // otherwise produce two projects with the same scope and two authorization
  // records. Checked BEFORE anything is written.
  if (args.idempotencyKey) {
    const seen = await findByIdempotencyKey(ctx, args.idempotencyKey)
    if (seen) return seen
  }

  const data: Record<string, unknown> = {
    name,
    description: (args.description ?? '').trim(),
    userId: ctx.token.userId,
    createdById: ctx.token.userId,
    engagementKind: args.engagementKind,
  }

  if (args.subdomainList?.length && mode !== 'targetDomain') {
    throw new McpToolError(
      'subdomainList is the host list of a single-domain project (targetDomain): each entry is a ' +
      'prefix such as "www" or "eu.api", scanned exactly. It does not apply to targetIps or ' +
      'domainBatchHosts.',
      'bad_args'
    )
  }

  if (mode === 'targetDomain') {
    // The rules the form and the HTTP routes apply, judged here rather than in
    // the schema so an idempotent replay still returns its first project. An
    // agent that emits bug-bounty scope notation (`*.example.com`) gets the
    // domain, normalised and lower-cased; a public suffix or an address is
    // refused with its reason.
    refuseHardBlocked(scopeGuardrailNames({ targetDomain: args.targetDomain, subdomainList: args.subdomainList }))
    const resolved = resolveScopeGroups({ targetDomain: args.targetDomain, subdomainList: args.subdomainList ?? [] })
    if (resolved.invalid.length > 0 || resolved.groups.length === 0) {
      throw new McpToolError(describeInvalid(resolved.invalid), 'bad_args')
    }
    data.targetDomain = resolved.groups[0].scanRoot
  } else if (mode === 'targetIps') {
    data.ipMode = true
    data.targetIps = args.targetIps!.map(s => s.trim()).filter(Boolean)
  } else {
    const hosts = args.domainBatchHosts!.map(s => s.trim()).filter(Boolean)
    const validation = validateDomainBatch(hosts)
    if (validation.errors.length > 0) {
      throw new McpToolError(validation.errors.join(' '), 'bad_args')
    }
    // Every host and root, so the refusal names the host that was listed.
    refuseHardBlocked(scopeGuardrailNames({ domainBatchMode: true, domainBatchHosts: hosts }))
    data.domainBatchMode = true
    data.domainBatchHosts = validation.entries
    // The server re-derives the grouping from the raw host list and discards
    // any client-supplied one. That is a control, not a convenience: the
    // grouping decides the run order and therefore what gets scanned together.
    data.domainBatchGroups = validation.legacy
  }

  if (args.subdomainList?.length) {
    // The stored form the project form writes: "." for the target itself,
    // every other prefix with one trailing dot.
    data.subdomainList = args.subdomainList
      .map(s => s.trim().toLowerCase()).filter(Boolean)
      .map(s => (s === '.' ? '.' : `${s.replace(/\.+$/, '')}.`))
  }

  if (args.engagementIdentityHeader) {
    const problem = checkHeader(args.engagementIdentityHeader)
    if (problem) {
      throw new McpToolError(`engagementIdentityHeader ${problem}.`, 'setting_rejected')
    }
    data.engagementIdentityHeader = args.engagementIdentityHeader
  }

  if (args.settings) Object.assign(data, filterSettingsAtCreate(args.settings))

  // The user-skill toggles may name only the creator's own skills, at most 20 of them on.
  if ('attackSkillConfig' in data) {
    try {
      data.attackSkillConfig = await normalizeUserSkillToggles(prisma, ctx.token.userId, data.attackSkillConfig)
    } catch (e) {
      if (e instanceof UserSkillError) throw new McpToolError(e.message, 'setting_rejected', { rejectedKey: 'attackSkillConfig' })
      throw e
    }
  }

  // A new project starts with every engine on the LLM, so a Jev flag in the
  // settings is a switch-on and needs a Jev provider of the creating account selected.
  const jevError = await validateJevEngineChange(null, data, ctx.token.userId)
  if (jevError) throw new McpToolError(jevError, 'setting_rejected')

  // The rule third_party projects live under, checked BEFORE the row exists so
  // a refused creation leaves nothing behind.
  let authorization: ReturnType<typeof normaliseAuthorization> | null = null
  if (args.authorization) authorization = normaliseAuthorization(args.authorization)

  if (data.engagementKind === 'third_party') {
    const ceiling = effectiveCeiling({
      id: '', engagementKind: 'third_party',
      roeGlobalMaxRps: Number(data.roeGlobalMaxRps ?? 0),
    })
    if (ceiling === null) {
      throw new McpToolError(
        'A third_party engagement must declare a request-rate ceiling: set ' +
        'settings.roeGlobalMaxRps to a non-zero value. Note that 0 means NO ceiling ' +
        'rather than a slow one.',
        'bad_args'
      )
    }
    if (!authorization) {
      throw new McpToolError(
        'A third_party engagement must record what authorized it: pass `authorization` with ' +
        'the scope document\'s digest, its kind and when it was issued.',
        'bad_args'
      )
    }
  }

  // The soft (LLM) guardrail, as the HTTP create route runs it: on unless the
  // settings switch it off, and failing open.
  if (data.targetGuardrailEnabled !== false) {
    const scope = resolveScopeGroups({
      ipMode: data.ipMode === true, domainBatchMode: data.domainBatchMode === true,
      domainBatchHosts: data.domainBatchHosts as string[] | undefined,
      targetDomain: data.targetDomain as string | undefined,
      subdomainList: data.subdomainList as string[] | undefined,
    })
    const refusal = await softGuardrailRefusal({
      targetDomain: mode === 'targetDomain' ? data.targetDomain as string : '',
      targetDomains: mode === 'domainBatchHosts' ? softGuardrailNames(scope.groups) : [],
      targetIps: mode === 'targetIps' ? data.targetIps as string[] : [],
      userId: ctx.token.userId,
    })
    if (refusal) throw new McpToolError(`Target blocked by the guardrail: ${refusal}`, 'target_blocked')
  }

  let created: { id: string; name: string }
  try {
    created = await prisma.$transaction(async tx => {
      const project = await tx.project.create({
        data: data as never,
        select: { id: true, name: true },
      })
      if (authorization) {
        await tx.engagementAuthorization.create({
          data: {
            projectId: project.id,
            ...authorization,
            recordedVia: 'mcp',
            recordedByTokenId: ctx.token.tokenId,
            recordedByUserId: ctx.token.userId,
            idempotencyKey: args.idempotencyKey ?? null,
          },
        })
      }
      return project
    })
  } catch (error) {
    // Lost the race against a concurrent call with the same key. The
    // transaction rolled back, so the winner's project is the only one, and
    // returning it is the same answer the pre-check would have given.
    if (args.idempotencyKey && isUniqueViolation(error)) {
      const winner = await findByIdempotencyKey(ctx, args.idempotencyKey)
      if (winner) return winner
    }
    throw error
  }

  void writeAudit({
    actorId: ctx.token.userId,
    action: 'mcp.create_project',
    targetType: 'project',
    targetId: created.id,
    after: {
      tokenId: ctx.token.tokenId, tokenPrefix: ctx.token.tokenPrefix,
      engagementKind: data.engagementKind,
      targetingMode: mode,
      scope: {
        targetDomain: data.targetDomain ?? null,
        targetIps: data.targetIps ?? null,
        domainBatchHosts: data.domainBatchHosts ?? null,
      },
      engagementLimits: Object.fromEntries(
        Object.keys(data)
          .filter(k => field(k)?.group === 'engagement_limits')
          .map(k => [k, data[k]])
      ),
      authorizationDigest: authorization?.documentSha256 ?? null,
    },
    source: 'mcp',
  })

  const engagement = await loadEngagement(created.id)
  return {
    projectId: created.id,
    name: created.name,
    created: true,
    engagement,
    note:
      'Scope is fixed now. update_recon_settings refuses every targeting field on an ' +
      'existing project, so a different target means a different project. Call ' +
      'preflight_scope_check before start_recon.',
  }
}

// --- attach_engagement_authorization -------------------------------------------------------

export async function attachEngagementAuthorization(
  ctx: McpContext,
  projectId: string,
  auth: AuthorizationArgs
) {
  requireScope(ctx.token, 'engagement:authorize')
  await assertMcpProjectAccess(ctx.token.userId, projectId)
  enforceRate(ctx, 'write')

  const record = normaliseAuthorization(auth)
  const previous = await currentAuthorization(projectId)

  const created = await prisma.engagementAuthorization.create({
    data: {
      projectId,
      ...record,
      recordedVia: 'mcp',
      recordedByTokenId: ctx.token.tokenId,
      recordedByUserId: ctx.token.userId,
    },
    select: { id: true, recordedAt: true },
  })

  void writeAudit({
    actorId: ctx.token.userId,
    action: 'mcp.attach_authorization',
    targetType: 'project',
    targetId: projectId,
    after: {
      tokenId: ctx.token.tokenId, tokenPrefix: ctx.token.tokenPrefix,
      authorizationId: created.id,
      documentSha256: record.documentSha256,
      documentKind: record.documentKind,
      programHandle: record.programHandle,
      supersedesId: previous?.id ?? null,
    },
    source: 'mcp',
  })

  return {
    projectId,
    authorizationId: created.id,
    recordedAt: created.recordedAt,
    supersedes: previous?.id ?? null,
    note:
      previous && previous.programHandle && previous.programHandle !== record.programHandle
        ? `This records a DIFFERENT program (${previous.programHandle} -> ` +
          `${record.programHandle}) on an existing project. The earlier record is kept; ` +
          'nothing here re-points the project, and its scope is still the one it was ' +
          'created with.'
        : 'Append-only: the earlier records are kept and nothing was overwritten.',
  }
}

// --- preflight_scope_check -------------------------------------------------------------

interface ResolvedRate {
  field: string
  runtimeKey: string | null
  written: number
  /** After the engagement ceiling is applied at scan start. */
  resolved: number
  capped: boolean
  /** True when the written value was 0 and 0 means unlimited for this field. */
  wasUnlimited: boolean
}

/**
 * Apply the ceiling the way `recon/project_settings.py` does.
 *
 * Deliberately a re-implementation of the same rule rather than a call into it,
 * because this runs in the webapp and that runs in a scan container. The two are
 * kept honest by the golden master on the Python side and by this tool's own
 * tests, and the rule is three lines: a value above the ceiling comes down to
 * it, and a 0 that means unlimited comes down to it too.
 */
function resolveRates(row: Record<string, unknown>, ceiling: number | null): ResolvedRate[] {
  const out: ResolvedRate[] = []
  for (const f of fieldsWhere(s => s.roe_capped)) {
    const written = row[f.key]
    if (typeof written !== 'number') continue
    let resolved = written
    let capped = false
    let wasUnlimited = false
    if (ceiling !== null) {
      if (written === 0 && f.zero_means === 'unlimited') {
        resolved = ceiling
        capped = true
        wasUnlimited = true
      } else if (written > ceiling) {
        resolved = ceiling
        capped = true
      }
    } else if (written === 0 && f.zero_means === 'unlimited') {
      wasUnlimited = true
    }
    out.push({
      field: f.key,
      runtimeKey: f.runtime_key,
      written,
      resolved,
      capped,
      wasUnlimited,
    })
  }
  return out
}

/**
 * The recon hooks that can run on Jev. An `engine` hook is an LLM hook with an
 * LLM | Jev switch: false means the LLM. An `enable` hook is Jev-only: false
 * means the hook is off and the step runs without AI. `requires` names a scan
 * that is off by default and without which the hook never runs.
 */
const AI_HOOKS = [
  { hook: 'ffuf_extensions', engineField: 'ffufAiUseJev', kind: 'engine' },
  { hook: 'nuclei_tags', engineField: 'nucleiTagsAiUseJev', kind: 'engine' },
  { hook: 'waf_classification', engineField: 'wafAiUseJev', kind: 'engine' },
  { hook: 'takeover_disambiguation', engineField: 'takeoverAiUseJev', kind: 'engine' },
  { hook: 'ffuf_base_paths', engineField: 'ffufJevBasePaths', kind: 'enable' },
  { hook: 'page_type', engineField: 'httpxJevPageType', kind: 'enable' },
  { hook: 'tool_health', engineField: 'resourceEnumJevToolHealth', kind: 'enable' },
  { hook: 'crawl_seed_order', engineField: 'hakrawlerJevSeedOrder', kind: 'enable' },
  { hook: 'serialized_assess', engineField: 'serializedScanJevRank', kind: 'enable',
    requires: 'serializedScanEnabled' },
  { hook: 'route_privacy_rank', engineField: 'routeExposureJevRank', kind: 'enable',
    requires: 'routeExposureEnabled' },
  { hook: 'route_exposure_wall', engineField: 'routeExposureJevWallCheck', kind: 'enable',
    requires: 'routeExposureEnabled' },
  { hook: 'route_exposure_assess', engineField: 'routeExposureJevAssess', kind: 'enable',
    requires: 'routeExposureEnabled' },
] as const

/**
 * Which engine each AI hook will actually use at the next scan.
 *
 * `aiInPipeline` forces every per-hook AI flag to its own value at scan start
 * and never touches the Jev fields, so with it off every hook is off, and with
 * it on the Jev field alone decides: an engine hook is on the LLM or on Jev, an
 * enable hook is off or on Jev. A hook on Jev runs only if the project selects a
 * Jev provider (`jevProviderId`, TypeSafe or OpenRouter) that is still on the
 * owner's account, exactly the row the agent resolves; otherwise it uses its
 * static fallback, which is what this reports. Over MCP the token's user IS the
 * owner (a mismatch is a hard deny), so the selection is looked up among that
 * user's rows. Only the row's existence is read: the key has no business here.
 */
async function resolveAiHooks(row: Record<string, unknown>, ownerUserId: string) {
  const aiOn = row.aiInPipeline === true
  const wantsJev = AI_HOOKS.some(h => row[h.engineField] === true)
  const selected = typeof row.jevProviderId === 'string' && row.jevProviderId ? row.jevProviderId : null

  // null: the lookup failed, so nothing is claimed either way.
  let jev: 'ready' | 'unselected' | 'unavailable' | null = 'unselected'
  if (aiOn && wantsJev && selected) {
    try {
      const provider = await prisma.userLlmProvider.findFirst({
        where: { id: selected, userId: ownerUserId, providerType: { in: [...JEV_PROVIDER_TYPES] } },
        select: { id: true },
      })
      jev = provider ? 'ready' : 'unavailable'
    } catch {
      jev = null
    }
  }

  return AI_HOOKS.map((h) => {
    const { hook, engineField, kind } = h
    const onJev = row[engineField] === true
    const engine = onJev ? 'jev' : kind === 'engine' ? 'llm' : 'off'
    const requires = 'requires' in h ? h.requires : null
    let effective: string
    if (!aiOn) effective = 'off'
    else if (!onJev) effective = engine
    else if (requires && row[requires] !== true) effective = `off (${requires} is false)`
    else if (jev === 'ready') effective = 'jev'
    else if (jev === 'unselected') effective = 'jev → static fallback (no Jev provider selected for the project)'
    else if (jev === 'unavailable') {
      effective = 'jev → static fallback (the selected Jev provider is not on the owner\'s account)'
    } else effective = 'jev (could not check the project\'s Jev provider)'
    return { hook, kind, engine, effective }
  })
}

/**
 * Why an enabled tool will not run, or null when it will.
 *
 * The registry files JS recon's settings under a 'js_recon' phase, but that is
 * no scanModules phase: the pipeline runs JS recon on jsReconEnabled alone,
 * after resource_enum, on the JS URLs resource_enum and http_probe found (or
 * on uploaded files), and its options do nothing while it is off. jsluice,
 * filed there too, runs inside resource_enum.
 */
function noOpReason(
  t: { field: string; tool: string; phase: string },
  row: Record<string, unknown>,
  scanModules: string[],
): string | null {
  if (t.phase === 'standalone') return null
  if (t.phase !== 'js_recon') {
    return scanModules.includes(t.phase) ? null : `enabled, but '${t.phase}' is not in scanModules, so it will not run`
  }
  if (t.tool === 'jsluice') {
    return scanModules.includes('resource_enum')
      ? null : "enabled, but jsluice runs inside resource_enum, which is not in scanModules"
  }
  if (t.field !== 'jsReconEnabled' && row.jsReconEnabled !== true) {
    return 'enabled, but jsReconEnabled is off, so JS recon does not run'
  }
  const uploads = Array.isArray(row.jsReconUploadedFiles) && row.jsReconUploadedFiles.length > 0
  if (row.jsReconEnabled === true && !uploads
      && !scanModules.includes('resource_enum') && !scanModules.includes('http_probe')) {
    return 'enabled, but neither resource_enum nor http_probe is in scanModules, so JS recon has no JS file to analyze'
  }
  return null
}

/**
 * Read-only proof that the configured pipeline fits the engagement.
 *
 * Without it "the pipeline respects the scope" is an assertion. With it, it is a
 * diff a person checks in ten seconds, and an agent is expected to call it and
 * report it before `start_recon`.
 *
 * The distinction that earns its place: it reports RESOLVED values, not written
 * ones. `get_recon_settings` echoes what a caller wrote, and for the fields the
 * runtime corrects - a rate above the ceiling, a wordlist path outside the
 * project directory - those are two different answers. An agent that only read the first would believe a rejected
 * value was accepted.
 */
export async function preflightScopeCheck(ctx: McpContext, projectId: string) {
  requireScope(ctx.token, 'recon:read')
  await assertMcpProjectAccess(ctx.token.userId, projectId)
  // The 'query' bucket rather than 'read': this resolves the whole settings
  // tree, the cap list and the authorization record, which is not the cost of
  // an ordinary read.
  enforceRate(ctx, 'query')

  const project = await prisma.project.findUnique({
    where: { id: projectId },
    // roeParsedJson for its version only: a project whose RoE went through the
    // replace route carries limits no migration derived. Never returned.
    select: { ...reconSettingsSelect(), id: true, updatedAt: true, roeParsedJson: true },
  })
  if (!project) throw new McpToolError('Project not found', 'not_found')

  const row = project as Record<string, unknown>
  const roeParse = row.roeParsedJson
  delete row.roeParsedJson
  const roeAppliedByDocument = Boolean(
    roeParse && typeof roeParse === 'object' && (roeParse as { version?: unknown }).version === 2
  )
  const engagement = await loadEngagement(projectId)
  const authorization = await currentAuthorization(projectId)
  const ceiling = engagement.ceilingRps
  const rates = resolveRates(row, ceiling)

  const rewritten: { field: string; written: unknown; willRun: unknown; why: string }[] = []

  for (const f of fieldsWhere(s => s.validator === 'project_file')) {
    const value = row[f.key]
    const entries = Array.isArray(value) ? value : [value]
    for (const entry of entries) {
      if (typeof entry !== 'string' || entry === '') continue
      // The same predicate the write path uses, rather than a third copy of
      // the rule: preflight exists to report what the scan will actually run
      // with, and a rule restated here would drift from the one enforced.
      if (isInsideProjectFileRoot(entry, projectId)) continue
      rewritten.push({
        field: f.key,
        written: entry,
        willRun: f.default ?? null,
        why: 'outside this project\'s wordlist and template directories; dropped at scan start',
      })
    }
  }

  // The provenance of the LAST run, so the chain from a graph node back to the
  // document that permitted looking at it can be walked from one call. Without
  // it the chain breaks in the middle: JobQueue.settingsHash is the only other
  // settings fingerprint and it is deleted with the queue row at dispatch.
  const lastJob = await prisma.scanJob
    .findFirst({
      where: { projectId },
      orderBy: { createdAt: 'desc' },
      select: {
        id: true, kind: true, status: true, startedAt: true,
        settingsHash: true, authorizationId: true, versionId: true, roeTextSha256: true,
      },
    })
    .catch(() => null)

  const scanModules = Array.isArray(row.scanModules) ? (row.scanModules as string[]) : []
  const enabledTools = fieldsWhere((f, key) => /Enabled$/.test(key) && row[key] === true)
    .map(f => ({ field: f.key, tool: f.tool, phase: f.phase, traffic: f.traffic }))

  // A module whose phase is not in scanModules will not run whatever its own
  // flag says. That two-level model is the mistake this surface's docs lead
  // with, and reporting it here turns it into something a caller can see.
  const silentNoOps = enabledTools.flatMap(t => {
    const why = noOpReason(t, row, scanModules)
    return why === null ? [] : [{ field: t.field, phase: t.phase, why }]
  })

  const exceeds = rates.filter(r => ceiling !== null && r.resolved > ceiling)

  const aiHooks = await resolveAiHooks(row, ctx.token.userId)

  // The scope the next scan runs, derived from the stored target fields exactly
  // as the scan derives it, and the entries the current rules refuse.
  const resolvedScope = resolveScopeGroups({
    ipMode: row.ipMode === true, domainBatchMode: row.domainBatchMode === true,
    domainBatchHosts: Array.isArray(row.domainBatchHosts) ? row.domainBatchHosts as string[] : [],
    targetDomain: typeof row.targetDomain === 'string' ? row.targetDomain : '',
    subdomainList: Array.isArray(row.subdomainList) ? row.subdomainList as string[] : [],
  })
  const scopeUnusable = resolvedScope.invalid.length > 0
    || (row.ipMode !== true && resolvedScope.groups.length === 0)

  return {
    projectId,
    engagement,
    authorization,
    scope: {
      targetDomain: row.targetDomain ?? '',
      targetIps: row.targetIps ?? [],
      domainBatchMode: row.domainBatchMode ?? false,
      domainBatchHosts: row.domainBatchHosts ?? [],
      // The DERIVED shape of each batch group, so a caller can verify what the
      // list actually means instead of re-implementing the rule. rootDomain,
      // wildcard and includesRoot keep their meaning for older callers
      // (rootDomain is the scan root); scanRoot, orgDomain, mode and
      // includeRoot are the same answer in the current vocabulary.
      domainBatchGroupShape: row.domainBatchMode === true
        ? resolvedScope.groups.map(g => ({
            rootDomain: g.scanRoot,
            wildcard: g.mode === 'enumerate',
            includesRoot: g.includeRoot,
            hostCount: g.exactHosts.length,
            scanRoot: g.scanRoot,
            orgDomain: g.orgDomain,
            mode: g.mode,
            includeRoot: g.includeRoot,
          }))
        : [],
      // Every mode, single domain included (one group).
      scopeGroups: resolvedScope.groups,
      // Entries the current rules refuse (a public suffix, a wildcard on one, an
      // address in a domain field...). While any is listed the scan is refused.
      invalidEntries: resolvedScope.invalid,
      // What the non-disableable guardrail checks: every entry, exact host,
      // scan root and org.
      guardrailNames: guardrailNames(resolvedScope.groups),
      ipMode: row.ipMode ?? false,
      targetGuardrailEnabled: row.targetGuardrailEnabled ?? false,
      excludedHosts: row.roeExcludedHosts ?? [],
      maxBatchHosts: MAX_BATCH_HOSTS,
    },
    ceilingRps: ceiling,
    // Per hook: the engine the row asks for and the one that will run. A hook on
    // Jev with no token on the owner's account runs its static fallback.
    aiHooks,
    // The DERIVED answer to "are this project's limits live", and which of the
    // three makes them so. It is not a column, so a caller cannot read it from
    // get_recon_settings; this is the only place it is reported.
    engagementLimits: {
      active: deriveRoeEnabled(row as never),
      because: [
        Number(row.roeGlobalMaxRps ?? 0) > 0 ? 'a request-rate ceiling' : null,
        Array.isArray(row.roeExcludedHosts) && row.roeExcludedHosts.length > 0
          ? 'an excluded-host list' : null,
        row.roeTimeWindowEnabled ? 'a scanning time window' : null,
      ].filter(Boolean),
      // True when the stored column disagrees with the derivation: the project
      // predates the change and acquires (or loses) limits without anyone
      // having touched it. The migration records an audit row for each.
      limitsNewlyDerived: !roeAppliedByDocument && Boolean(row.roeEnabled) !== deriveRoeEnabled(row as never),
    },
    resolvedRates: rates,
    ratesExceedingCeiling: exceeds,
    rewrittenAtScanStart: rewritten,
    phases: scanModules,
    enabledTools,
    silentNoOps,
    forbidden: {
      tools: row.roeForbiddenTools ?? [],
      categories: row.roeForbiddenCategories ?? [],
      allowDos: row.roeAllowDos ?? false,
      allowDataExfiltration: row.roeAllowDataExfiltration ?? false,
      maxSeverityPhase: row.roeMaxSeverityPhase ?? null,
    },
    identityHeader: row.engagementIdentityHeader ?? '',
    lastRun: lastJob
      ? {
          scanJobId: lastJob.id,
          kind: lastJob.kind,
          status: lastJob.status,
          startedAt: lastJob.startedAt,
          scanVersionId: lastJob.versionId,
          // The settings it ACTUALLY started with, and what permitted it. A
          // null hash means the run predates provenance, not that it had none.
          settingsHash: lastJob.settingsHash,
          authorizationId: lastJob.authorizationId,
          settingsChangedSince:
            lastJob.settingsHash === null
              ? null
              : lastJob.settingsHash !== settingsFingerprint(lastJob.kind, row),
          // The RoE document it ran under, and whether that document has since
          // been replaced or removed. Null when the run predates the record.
          roeTextSha256: lastJob.roeTextSha256,
          roeChangedSince:
            lastJob.roeTextSha256 === null || lastJob.roeTextSha256 === undefined
              ? null
              : lastJob.roeTextSha256 !== engagement.documentTextSha256,
        }
      : null,
    startable: engagement.blockers.length === 0 && exceeds.length === 0 && !scopeUnusable,
    notes: [
      'Values here are RESOLVED, not written. get_recon_settings echoes what you wrote; this ' +
        'reports what the scan will actually run with, which differs wherever a validator or ' +
        'the engagement ceiling rewrites a value.',
      'rewrittenAtScanStart is not an error. A wordlist path outside the project directory is ' +
        'corrected rather than refused, and logged with a [guardrail] line during the scan.',
      'silentNoOps is the two-level model biting: a tool can be enabled inside a phase that ' +
        'is not running. The scan succeeds, nothing is scanned by that tool, and no result ' +
        'field says why.',
      'engagementLimits.active is DERIVED: limits apply when there is a limit to apply - a ' +
        'non-zero roeGlobalMaxRps, a non-empty roeExcludedHosts, or a time window. There is ' +
        'no switch that turns them off while leaving them configured. limitsNewlyDerived true ' +
        'means this project predates that and its limits changed without anyone touching it; a ' +
        'project whose limits came from a Rules of Engagement document is never reported so.',
      'lastRun.settingsChangedSince true means the graph you are looking at was produced by a ' +
        'DIFFERENT configuration than the one above. That is the chain an incident review ' +
        'walks: a graph node, the scan job that wrote it, the settings hash it ran with, and ' +
        'the authorization that permitted looking.',
    ],
  }
}

/** Every authorization ever recorded for a project, newest first. */
export async function listEngagementAuthorizations(ctx: McpContext, projectId: string) {
  requireScope(ctx.token, 'recon:read')
  await assertMcpProjectAccess(ctx.token.userId, projectId)
  enforceRate(ctx, 'read')

  const rows = await prisma.engagementAuthorization.findMany({
    where: { projectId },
    orderBy: { recordedAt: 'desc' },
    select: {
      id: true, documentSha256: true, documentKind: true, sourceUrl: true,
      programHandle: true, issuedAt: true, recordedAt: true, recordedVia: true,
      recordedByTokenId: true, summary: true,
    },
  })
  return {
    projectId,
    authorizations: rows,
    note:
      'Append-only. A later record does not replace an earlier one: it says the engagement ' +
      'continued under a new authority from that moment.',
  }
}

export { describeEngagement, type EngagementProjectRow }
