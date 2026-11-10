/**
 * The inbound MCP tool surface.
 *
 * Each tool takes an explicit `projectId` and calls `assertMcpProjectAccess`
 * FIRST. A personal access token resolves to exactly one user; there is no
 * admin act-as here, and no tool trusts an identity from its arguments.
 *
 * Two rules run through all of it:
 *
 *  - NEVER report a dependency failure as an empty result. An empty result
 *    means "nothing found". Conflating the two produces a false negative in a
 *    security tool: an agent told "no malicious dependencies" cannot tell
 *    whether the scan ran and found nothing or never ran at all.
 *  - Every outbound call carries an explicit timeout, never an inherited
 *    unbounded default.
 *
 * The tool DESCRIPTIONS are LLM-facing content, not code comments: they are
 * sized for the model that reads them at runtime.
 */
import prisma from '@/lib/prisma'
import { orchestratorFetch } from '@/lib/orchestrator'
import { readProjectActivity, type ProjectActivity } from '@/lib/mcp/activity'
import { describeLiveGraphWriters } from '@/lib/graphWriters'
import {
  assertMcpProjectAccess,
  checkLlmBudget,
  checkRateLimit,
  requireScope,
  type ResolvedMcpToken,
} from '@/lib/mcpAuth'
import { projectReconSettings, reconSettingsSelect } from '@/lib/reconSettings/filter'
import { assertReadableSelect } from '@/lib/mcpReadableFields'
import { resolveScopeGroups, scopeSummary } from '@/lib/scopeGroups'
import { McpToolError } from '@/lib/mcp/errors'
import { assertTenantScoped, TenantViolation } from '@/lib/mcp/graphGuard'
import { agentBaseUrl } from '@/lib/agentFetch'
import { internalKeyHeaders } from '@/lib/agentAuth'
import { execCypher, graphSchemaDoc, nlQuery, type GraphRecords } from '@/lib/mcp/graphClient'
import { staleFindingsCypher } from '@/lib/mcp/findingLabels'
import { coverageCountsBlock } from '@/lib/coverageStamps'
import { kaliToolboxDoc } from '@/lib/mcp/kaliClient'
import { reconcileScanJobStatus } from '@/lib/scanTimeline'

const RECON_ORCHESTRATOR_URL = process.env.RECON_ORCHESTRATOR_URL || 'http://localhost:8010'

export interface McpContext {
  token: ResolvedMcpToken
}

/**
 * Enforce a bucket, reporting when to retry rather than failing generically.
 *
 * `perProject` drops the token from the key. Buckets that exist to protect the
 * CALLER (read/query/write budgets) are per token; the one that exists to
 * protect a RESOURCE - the start bucket, which guards the version retention
 * window - has to be per project, or a user holding N tokens gets N times the
 * documented rate against the same project.
 */
export function enforceRate(
  ctx: McpContext,
  bucket: Parameters<typeof checkRateLimit>[0],
  scopeKey = '',
  opts: { perProject?: boolean } = {}
): void {
  const d = checkRateLimit(bucket, opts.perProject ? '*' : ctx.token.tokenId, scopeKey)
  if (!d.allowed) {
    throw new McpToolError(
      `Rate limit reached for this token. Try again in ${d.retryAfterSeconds}s.`,
      'rate_limited'
    )
  }
}

/**
 * Post-validate a graph result, then hand it back.
 *
 * A tenant violation drops the WHOLE response and audits at error level: a
 * partial answer is indistinguishable from a complete one and would be acted
 * on as if it were.
 */
export function guardGraphResult(
  result: GraphRecords,
  ctx: McpContext,
  projectId: string,
  tool: string
): GraphRecords {
  try {
    assertTenantScoped(result.records, ctx.token.userId, projectId)
  } catch (err) {
    if (err instanceof TenantViolation) {
      console.error(
        `[mcp][SECURITY] tenant post-validation failed tool=${tool} ` +
        `token=${ctx.token.tokenPrefix} project=${projectId}`,
        JSON.stringify(err.detail)
      )
      throw new McpToolError('The query result failed a safety check and was discarded.', 'tenant_violation')
    }
    throw err
  }
  return result
}

// --- reads --------------------------------------------------------------------

export async function listProjects(ctx: McpContext) {
  requireScope(ctx.token, 'recon:read')
  enforceRate(ctx, 'read')

  // Checked against the READ classification, which is a different set from the
  // write allowlist: `targetDomain` is readable so a caller knows which
  // engagement it is looking at, and writable by nobody here.
  const select = {
    id: true, name: true, targetDomain: true, targetIps: true,
    ipMode: true, domainBatchMode: true, updatedAt: true,
    // The host and prefix lists derive the scope groups: whether any of them
    // enumerates is the difference between a five-host scan and a multi-hour
    // one, so a caller choosing a project needs it. Reduced to counts and a
    // one-line summary below; never returned raw.
    domainBatchHosts: true, subdomainList: true,
  }
  assertReadableSelect(select, 'list_projects')

  // `where: { userId }` is the enumeration boundary: an external agent can
  // never see another user's project ids, so it can never name one.
  const projects = await prisma.project.findMany({
    where: { userId: ctx.token.userId },
    select,
    orderBy: { updatedAt: 'desc' },
  })
  return {
    projects: projects.map(({ domainBatchHosts, subdomainList, ...p }) => {
      const { groups } = resolveScopeGroups({ ...p, domainBatchHosts, subdomainList })
      const enumerated = groups.filter(g => g.mode === 'enumerate').length
      return {
        ...p,
        // Enumerated Domain-batch groups, as before; 0 for a single domain.
        wildcardDomainCount: p.domainBatchMode ? enumerated : 0,
        // Enumerated scope groups in every mode, a single domain included.
        enumerateGroupCount: enumerated,
        scopeSummary: scopeSummary(groups),
      }
    }),
  }
}

export async function getReconStatus(ctx: McpContext, projectId: string) {
  requireScope(ctx.token, 'recon:read')
  enforceRate(ctx, 'read')
  await assertMcpProjectAccess(ctx.token.userId, projectId)

  let resp: Response
  try {
    resp = await orchestratorFetch(`${RECON_ORCHESTRATOR_URL}/recon/${projectId}/status`)
  } catch (err) {
    console.error('[mcp] orchestrator status unreachable:', err)
    // NOT "idle". The webapp's own /api/recon/[id]/status answers a synthetic
    // idle here, and reporting "not running" for "cannot tell" is exactly the
    // false negative this surface must not produce.
    throw new McpToolError('Scan status is unknown: the orchestrator is unreachable.', 'status_unknown')
  }
  if (!resp.ok) {
    console.error(`[mcp] orchestrator status returned ${resp.status}`)
    throw new McpToolError('Scan status is unknown.', 'status_unknown')
  }
  const raw = await resp.json()
  const live = projectReconState(raw)

  // The same bookkeeping as the UI's status route: a terminal status closes the
  // open full-recon ScanJob. Without it a run an agent stopped or watched end
  // stayed `running` until a browser opened the project, and `lastRun` below
  // contradicted the `idle` above. Never throws.
  await reconcileScanJobStatus(projectId, (raw as { status?: string } | null)?.status)

  // The orchestrator only knows the RUNNING container. Once it exits, its
  // status is a flat `idle` with null timestamps - identical whether the scan
  // completed, failed, was canceled a minute in, or never ran at all. An agent
  // diffing last night's rescan, gating a build on a fresh scan, or producing
  // proof of coverage was reading that `idle` as success. ScanJob is the
  // durable record; nothing else on this surface exposes it.
  try {
    const last = await prisma.scanJob.findFirst({
      where: { projectId, kind: 'full_recon' },
      orderBy: { createdAt: 'desc' },
      select: {
        status: true, startedAt: true, finishedAt: true,
        trigger: true, mode: true, nodeCount: true,
      },
    })
    live.lastRun = last
      ? {
        status: last.status,
        // The whole point of the field: an agent must not have to know which
        // of six status strings count as success.
        completed: last.status === 'completed',
        startedAt: last.startedAt?.toISOString() ?? null,
        finishedAt: last.finishedAt?.toISOString() ?? null,
        trigger: last.trigger,
        mode: last.mode,
        nodeCount: last.nodeCount,
      }
      : null
  } catch (err) {
    // History is an addition to this answer, never a precondition for it.
    // Omitted rather than nulled: `lastRun: null` is a claim ("never scanned")
    // and this code does not know that.
    console.error('[mcp] scan history unreadable:', err)
  }
  return live
}

/**
 * Project the orchestrator's ReconState onto the fields an external caller
 * needs, dropping the rest.
 *
 * The raw state carries `container_id` and an `error` populated with raw
 * exception text - a Docker SDK failure embeds the deployment's absolute host
 * paths and image names. Returning it verbatim would hand an untrusted agent
 * reconnaissance about the host and then place it in a model's context, which
 * is exactly what errors.ts forbids everywhere else.
 */
function projectReconState(raw: unknown): Record<string, unknown> {
  const s = (raw ?? {}) as Record<string, unknown>
  return {
    status: s.status ?? 'unknown',
    currentPhase: s.current_phase ?? s.currentPhase ?? null,
    phaseNumber: s.phase_number ?? s.phaseNumber ?? null,
    // The denominator. Without it a poller has a numerator and no way to turn
    // it into progress.
    totalPhases: s.total_phases ?? s.totalPhases ?? null,
    // Domain-batch progress. Phases RESTART per group, so on a multi-domain
    // scan the phase number barely moves for an hour and the group is the only
    // thing that says "still on the first of six".
    currentGroup: s.current_group ?? s.currentGroup ?? null,
    groupNumber: s.group_number ?? s.groupNumber ?? null,
    totalGroups: s.total_groups ?? s.totalGroups ?? null,
    startedAt: s.started_at ?? s.startedAt ?? null,
    completedAt: s.completed_at ?? s.completedAt ?? null,
    // A boolean, never the text: "it failed" is actionable, the exception is not.
    failed: s.status === 'error' || Boolean(s.error),
  }
}

/**
 * What is running on this project, so an agent can ask BEFORE acting.
 *
 * Today the only way to learn a GVM scan is running is to attempt `start_recon`
 * and read the rejection, which costs the per-project start window.
 *
 * The two halves come from different sources ON PURPOSE. The scan LIST is the
 * cheap in-memory read. `canStartFullScan` is the same call `start_recon`
 * itself makes, because that check is strictly wider - it also covers a live
 * triage run and an in-app agent session, neither of which appears in the
 * orchestrator's scan list. Deriving the predicate from the cheap read would
 * sometimes answer "yes, you can start" and then have `start_recon` refuse,
 * which for an unattended agent is a retry loop: a worse failure than not
 * offering the field at all.
 */
export async function getProjectActivity(ctx: McpContext, projectId: string) {
  requireScope(ctx.token, 'recon:read')
  // The `query` bucket, not `read`, because this is not a cheap read. One call
  // costs one in-memory orchestrator read plus, for canStartFullScan, up to
  // SEVEN more sequential orchestrator round trips. At the read bucket's 120 a
  // minute a single looping token could issue nearly a thousand orchestrator
  // requests a minute while staying inside its documented limit, and the
  // orchestrator is shared by every project on the host. Telling the model not
  // to poll is advice to an untrusted caller, not a control.
  enforceRate(ctx, 'query')
  await assertMcpProjectAccess(ctx.token.userId, projectId)

  const activity = await readProjectActivity(projectId)
  const blocker = await describeLiveGraphWriters(projectId)

  return {
    projectId,
    // Already filtered to this project. The endpoint behind it is cross-project
    // and another tenant's work is never echoed, nor counted.
    scans: activity.scans,
    agentSession: activity.agentSession,
    ...(activity.waitingForExternalAgent
      ? { agentSessionNote: 'The chat run is waiting for the external agent (Agent in the Loop) to answer a step.' }
      : {}),
    triageRun: activity.triageRun,
    muteRulesApply: activity.muteRulesApply,
    activating: activity.activating,
    liveGraphState: liveGraphStateOf(activity),
    canStartFullScan: blocker === null,
    ...(blocker ? { startBlockedBecause: blocker } : {}),
    ...(activity.unknown
      ? { unknown: true, unknownReason: activity.unknownReason }
      : {}),
  }
}

// --- remediations -------------------------------------------------------------

const REMEDIATION_SORTS = ['priority', 'severity', 'createdAt', 'updatedAt'] as const
type RemediationSort = (typeof REMEDIATION_SORTS)[number]

/**
 * The fix-side corpus, projected.
 *
 * Read from Prisma directly, never through `GET /api/remediations`: that route
 * SKIPS all ownership checks for an internal-key caller, and the codebase's own
 * server-to-server idiom is an internal-key fetch. Composing those two facts
 * would leave `assertMcpProjectAccess` as the only thing between a caller and
 * every tenant's remediations, and it would work correctly in testing right up
 * until a refactor forwarded the raw argument instead of the validated one.
 *
 * Excluded by name and permanently: `agentNotes`, `fileChanges`, `evidence` and
 * `attackChainPath` (large, internal, and target-derived text sized for a UI),
 * and `prUrl`, which can be
 * `https://x-access-token:ghs_...@github.com/...` - a credential.
 */
export async function listRemediations(
  ctx: McpContext,
  projectId: string,
  args: {
    status?: string
    severity?: string
    limit?: number
    offset?: number
    sort?: string
    detail?: boolean
  } = {}
) {
  requireScope(ctx.token, 'triage:read')
  enforceRate(ctx, 'read')
  await assertMcpProjectAccess(ctx.token.userId, projectId)

  const limit = Math.max(1, Math.min(Math.trunc(args.limit ?? 25), 100))
  const offset = Math.max(0, Math.trunc(args.offset ?? 0))

  const sort = (args.sort ?? 'priority') as RemediationSort
  if (!REMEDIATION_SORTS.includes(sort)) {
    throw new McpToolError(
      `Unknown sort '${args.sort}'. One of: ${REMEDIATION_SORTS.join(', ')}.`,
      'bad_args'
    )
  }

  const where = {
    projectId,
    ...(args.status ? { status: args.status } : {}),
    ...(args.severity ? { severity: args.severity } : {}),
  }

  const [rows, total] = await Promise.all([
    prisma.remediation.findMany({
      where,
      select: {
        id: true, title: true, severity: true, priority: true, priorityScore: true,
        category: true, status: true, cvssScore: true, cveIds: true, cweIds: true,
        capecIds: true, exploitAvailable: true, cisaKev: true, fixComplexity: true,
        estimatedFiles: true, groupKey: true, findingIds: true, stillDetected: true,
        prStatus: true, createdAt: true, updatedAt: true,
        // @db.Text, so only on request.
        ...(args.detail === true ? { solution: true, description: true } : {}),
      },
      orderBy: sort === 'severity'
        ? [{ priorityScore: 'desc' as const }, { priority: 'desc' as const }]
        : sort === 'priority'
          ? [{ priority: 'desc' as const }, { priorityScore: 'desc' as const }]
          : { [sort]: 'desc' as const },
      take: limit,
      skip: offset,
    }),
    prisma.remediation.count({ where }),
  ])

  return {
    projectId,
    remediations: rows,
    returned: rows.length,
    offset,
    total,
    ...(offset + rows.length < total ? { truncated: true } : {}),
  }
}

export async function getReconSettings(ctx: McpContext, projectId: string) {
  requireScope(ctx.token, 'recon:read')
  enforceRate(ctx, 'read')
  await assertMcpProjectAccess(ctx.token.userId, projectId)

  // Selected BY the allowlist, so no credential-bearing column is ever loaded,
  // let alone returned - and re-checked against the READ classification, so a
  // future widening of the write allowlist cannot quietly widen this too.
  const select = { ...reconSettingsSelect(), updatedAt: true }
  assertReadableSelect(select, 'get_recon_settings')
  const row = await prisma.project.findUnique({
    where: { id: projectId },
    select,
  })
  if (!row) throw new McpToolError('Project not found', 'not_found')
  return {
    projectId,
    // Returned as METADATA, not as a setting: update_recon_settings tells the
    // caller to pass it back as `expectedUpdatedAt`, and without it here that
    // anti-clobber control was unreachable through its own documented flow.
    updatedAt: (row as { updatedAt?: Date }).updatedAt?.toISOString() ?? null,
    settings: projectReconSettings(row as Record<string, unknown>),
  }
}

/**
 * What does this project actually contain?
 *
 * Exists because "no results" has two very different causes: the scan ran and
 * the project is clean, or that surface was never scanned. An agent that cannot
 * tell them apart reports the second as the first.
 */
export async function graphSummary(ctx: McpContext, projectId: string) {
  requireScope(ctx.token, 'recon:read')
  enforceRate(ctx, 'read')
  await assertMcpProjectAccess(ctx.token.userId, projectId)

  const current = await prisma.scanVersion.findFirst({
    where: { projectId, isCurrent: true },
    select: { id: true, seq: true, label: true, createdAt: true, nodeCount: true },
  })
  // nodeCount is the graph-loss check's reference, not part of the answer:
  // it is null on a version scanned into, and only a saved one carries it.
  const { nodeCount: currentNodeCount, ...version } = current ?? { nodeCount: null }

  // Counts FIRST, then the state. Sampling the state first meant a scan that
  // started in between was reported as `stable` alongside mid-wipe near-zero
  // counts - the exact false negative this field exists to prevent. This way
  // the same race over-warns instead: the counts predate the wipe and the
  // state still says the graph is moving.
  const summary = await summaryCounts(ctx, projectId)
  const stale = await staleFindingCount(ctx, projectId)
  const liveGraphState = await resolveLiveGraphState(projectId)
  // Computed by the agent inside the same summary op, so the block costs this
  // most-called tool no round trip of its own.
  const coverage = coverageCountsBlock(summary.coverage)
  // Only a settled graph can be called lost: a running state already explains
  // near-zero counts, and says so in its own warning.
  const missing = liveGraphState === 'stable'
    ? await graphDataMissing(projectId, summary.nodes, currentNodeCount, current?.seq ?? null)
    : null

  return {
    projectId,
    // Prepended deliberately: counts taken during a wipe or a version swap are
    // near-zero, which a reader would otherwise take for "never scanned".
    liveGraphState,
    ...(liveGraphState === 'stable' ? {} : { warning: STATE_WARNING[liveGraphState] }),
    ...(missing ? { warning: 'graph_data_missing', graphDataMissing: missing } : {}),
    scanVersion: current ? version : null,
    nodes: summary.nodes,
    relationships: summary.relationships,
    // Omitted entirely when it could not be read. Reporting 0 for "could not
    // count" would be the same false negative the rest of this tool exists to
    // prevent, one field down.
    ...(stale === null ? {} : { hiddenFromCounts: { stale } }),
    // Per module, the web hosts (BaseURL) it analyzed in each state and the
    // live ones it never looked at. Same rule as above: absent, never zeros.
    ...(coverage === null ? {} : { coverage }),
  }
}

/** Below this share of the version it should hold, a settled graph reads as lost. */
const LOST_GRAPH_RATIO = 0.1

export interface GraphDataMissing {
  liveNodes: number
  expectedNodes: number | null
  basis: 'scan_version' | 'completed_scan'
  versionSeq?: number
  detail: string
}

const UNKNOWN_CONTENTS =
  'Treat the live graph\'s contents as UNKNOWN: an absent node type or finding proves nothing until ' +
  'the data is restored or rescanned. list_scan_versions and get_recon_status show the history.'

/**
 * Whether the settled live graph is missing data the project's own history
 * says it had. A reset Neo4j volume or a failed restore otherwise makes a
 * project scanned yesterday read as "never scanned".
 *
 * The reference is the current version's node count when it has one (a
 * restored version does), else the newest saved version's: the one scanned
 * into carries none until it is saved. A census below a tenth of it, or an
 * empty census after a completed full scan, is graph_data_missing. `null` when
 * the history cannot be read: an invented warning is no better than none.
 */
async function graphDataMissing(
  projectId: string,
  nodes: { count: number }[],
  currentNodeCount: number | null,
  currentSeq: number | null,
): Promise<GraphDataMissing | null> {
  const liveNodes = nodes.reduce((sum, n) => sum + (Number(n.count) || 0), 0)
  try {
    const reference = currentNodeCount && currentNodeCount > 0
      ? { seq: currentSeq, nodeCount: currentNodeCount }
      : await prisma.scanVersion.findFirst({
        where: { projectId, nodeCount: { gt: 0 } },
        orderBy: { seq: 'desc' },
        select: { seq: true, nodeCount: true },
      })
    if (reference?.nodeCount && liveNodes < reference.nodeCount * LOST_GRAPH_RATIO) {
      return {
        liveNodes,
        expectedNodes: reference.nodeCount,
        basis: 'scan_version',
        ...(reference.seq != null ? { versionSeq: reference.seq } : {}),
        detail:
          `The live graph holds ${liveNodes} node(s), but version ${reference.seq} of this project held ` +
          `${reference.nodeCount}. Its data was most likely lost (a reset database volume or a failed ` +
          `restore), unless the scope shrank sharply since. ${UNKNOWN_CONTENTS}`,
      }
    }
    if (liveNodes === 0) {
      const scanned = await prisma.scanJob.findFirst({
        where: { projectId, kind: 'full_recon', status: 'completed' },
        orderBy: { finishedAt: 'desc' },
        select: { finishedAt: true },
      })
      if (scanned) {
        return {
          liveNodes,
          expectedNodes: null,
          basis: 'completed_scan',
          detail:
            `The live graph is empty, but a full scan of this project completed` +
            `${scanned.finishedAt ? ` on ${scanned.finishedAt.toISOString()}` : ''}. Its data was most ` +
            `likely lost (a reset database volume or a failed restore). ${UNKNOWN_CONTENTS}`,
        }
      }
    }
  } catch (err) {
    console.error('[mcp] graph-loss check could not read the scan history:', err)
  }
  return null
}

export type LiveGraphState = 'stable' | 'scan_running' | 'agent_writing' | 'activating' | 'unknown'

const STATE_WARNING: Record<Exclude<LiveGraphState, 'stable'>, string> = {
  activating:
    'A saved version is being swapped in, so these counts are mid-restore and can be near zero. ' +
    'Re-check once the state is "stable".',
  scan_running:
    'A scan is writing the live graph right now, so these counts are not settled. ' +
    'Re-check once the state is "stable".',
  agent_writing:
    'A triage run, an in-app agent session or a Mute Rules apply is writing the live graph, so ' +
    'these counts are not settled. Re-check once the state is "stable".',
  unknown:
    'Whether anything is rewriting the graph could NOT be determined, so these counts cannot be ' +
    'trusted. This is not a report that the graph is settled - treat it as "do not know".',
}

/**
 * Which of the five states the graph is in, worst-case first.
 *
 * `unknown` outranks the running states because it is the honest answer when a
 * source could not be read, and because the one thing it must never be mistaken
 * for is `stable`, which the wiki documents as "the counts are trustworthy".
 */
export function liveGraphStateOf(activity: ProjectActivity): LiveGraphState {
  if (activity.activating) return 'activating'
  if (activity.unknown) return 'unknown'
  if (activity.scans.length > 0) return 'scan_running'
  // A Mute Rules apply runs in the agent service, so it is the agent writing.
  if (activity.agentSession || activity.triageRun || activity.muteRulesApply) return 'agent_writing'
  return 'stable'
}

export async function resolveLiveGraphState(projectId: string): Promise<LiveGraphState> {
  return liveGraphStateOf(await readProjectActivity(projectId))
}

async function summaryCounts(ctx: McpContext, projectId: string) {
  let resp: Response
  try {
    resp = await fetch(`${agentBaseUrl()}/graph/exec`, {
      method: 'POST',
      headers: internalKeyHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify({
        op: 'summary',
        user_id: ctx.token.userId,
        project_id: projectId,
        source: 'mcp',
      }),
      signal: AbortSignal.timeout(60_000),
    })
  } catch (err) {
    console.error('[mcp] graph summary transport error:', err)
    // Plain failure, never an empty summary: an empty summary reads as
    // "nothing has ever been scanned".
    throw new McpToolError('The graph service is unavailable.', 'agent_unreachable')
  }
  if (!resp.ok) {
    console.error(`[mcp] graph summary failed (${resp.status})`)
    throw new McpToolError('The graph summary could not be read.', 'agent_failed')
  }
  return (await resp.json()) as {
    nodes: { label: string; count: number }[]
    relationships: { type: string; count: number }[]
    coverage?: unknown
  }
}

/**
 * How many findings the census is hiding because a later scan stopped
 * reporting them.
 *
 * `null`, never 0, when it cannot be read: the caller is deciding whether to
 * trust a count, and a fabricated zero is worse than an absent field. This is
 * the one place in `graph_summary` where a dependency failure is NOT fatal -
 * the counts themselves are still true, so the tool degrades by omitting an
 * explanatory field rather than by refusing to answer.
 *
 * No muted count, deliberately. The agent does have one (`count_muted`, the
 * exact total behind the muted list and `search_muted_findings`), but it is a
 * separate round trip under the MCP graph ceiling on the most-called tool on
 * the surface, and Cypher cannot reach muted findings at all.
 * `list_muted_findings` and `search_muted_findings` are where that number lives.
 */
async function staleFindingCount(ctx: McpContext, projectId: string): Promise<number | null> {
  try {
    const result = await execCypher(ctx.token.userId, projectId, staleFindingsCypher())
    const row = (result.records?.[0] ?? {}) as Record<string, unknown>
    const n = row.stale
    return typeof n === 'number' && Number.isFinite(n) ? n : null
  } catch (err) {
    console.error('[mcp] stale finding count could not be read:', err)
    return null
  }
}

export async function graphSchema(ctx: McpContext) {
  requireScope(ctx.token, 'recon:read')
  enforceRate(ctx, 'read')
  // No projectId, no database, no tenant data: it is derived from code, so it
  // still answers when Neo4j and Postgres are down.
  return { schema: await graphSchemaDoc() }
}

/**
 * What the Kali sandbox carries, so a caller can plan around what exists.
 *
 * Reading the catalogue is NOT permission to run any of it: nothing on this
 * surface executes a command. That is stated in the tool description too,
 * because an agent that reads a list of exploitation tools will otherwise spend
 * calls looking for the tool that runs them.
 */
export async function kaliToolbox(ctx: McpContext) {
  requireScope(ctx.token, 'recon:read')
  enforceRate(ctx, 'read')
  // Like graph_schema: no projectId, no database, no tenant data, no call into
  // the container. It is a constant in the agent image.
  return { toolbox: await kaliToolboxDoc() }
}

export async function queryGraph(
  ctx: McpContext,
  projectId: string,
  args: { question?: string; cypher?: string }
) {
  requireScope(ctx.token, 'recon:read')
  const question = typeof args.question === 'string' ? args.question.trim() : ''
  const cypher = typeof args.cypher === 'string' ? args.cypher.trim() : ''

  if (!!question === !!cypher) {
    throw new McpToolError('Provide exactly one of "question" or "cypher".', 'bad_args')
  }
  if (cypher) requireScope(ctx.token, 'graph:cypher')

  await assertMcpProjectAccess(ctx.token.userId, projectId)

  let result: GraphRecords
  if (question) {
    // The NL path spends the project owner's provider key, so it is budgeted
    // per token on top of the agent's own per-user daily cap.
    enforceRate(ctx, 'query')
    const budget = checkLlmBudget(ctx.token.tokenId)
    if (!budget.allowed) {
      throw new McpToolError(
        `This token's daily query budget (${budget.limit}) is spent. It resets at ${budget.resetsAt}.`,
        'budget_exhausted'
      )
    }
    result = await nlQuery(ctx.token.userId, projectId, question)
  } else {
    enforceRate(ctx, 'read')
    result = await execCypher(ctx.token.userId, projectId, cypher)
  }

  const guarded = guardGraphResult(result, ctx, projectId, 'query_graph')
  return {
    projectId,
    records: guarded.records,
    // Transparency: the caller should see what its question became.
    ...(guarded.cypher ? { cypher: guarded.cypher } : {}),
    ...(guarded.truncated ? { truncated: true } : {}),
  }
}
