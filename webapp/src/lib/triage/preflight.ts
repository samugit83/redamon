/**
 * What a triage run would do to a project right now, and whether it may start.
 *
 * Shared by the confirm dialog (`GET /api/triage/preflight`) and MCP
 * `get_triage_status` / `start_triage_run`, so a person and an agent are told
 * the same numbers and refused for the same reasons.
 *
 * The REAL blockers, and nothing else:
 *   - a live graph writer, other than a full or partial recon scan (the publish
 *     guard skips any node a scan changed, so the two run side by side);
 *   - a version activation;
 *   - a live triage run.
 * Ownership is the caller's job. "No model" is not a blocker for a budget of 0:
 * the run ranks rules-only. A budget above 0 with no model is `modelRequired`,
 * which each door presents its own way.
 */
import prisma from '@/lib/prisma'
import { findLiveTriageRun, mcpRunBudget, MCP_RUNS_PER_DAY } from '@/lib/triageRun'
import { isActivationInProgress } from '@/lib/activationLock'
import { describeLiveGraphWriters } from '@/lib/graphWriters'
import { readFeatureModel } from '@/lib/featureModels'
import { agentTriage, TriageActionError, type TriageChannel, type TriageTenant } from '@/lib/triage/actions'
import { MAX_REVIEW_BUDGET } from '@/lib/triage/limits'
import { isChatProvider } from '@/lib/llmProviderKinds'
import { entitledInstanceProviders, ownProvidersWithheld } from '@/lib/instanceProviders/entitlement'
import { splitInstanceModel } from '@/lib/instanceProviders/rows'

export { MAX_REVIEW_BUDGET }

/** Findings per review call, as the agent batches them. */
const REVIEW_BATCH_SIZE = 12

export interface TriagePreflight {
  projectName: string
  model: string
  modelRequired: boolean
  hasModelKey: boolean
  inScope: number
  newSinceLastRun: number
  openFindings: number
  reviewable: number
  reviewBudget: number
  reviewsKept: number
  externalReviews: number
  estimatedAiCalls: number
  estimatedReviewed: number
  pendingRemediations: number
  inProgressRemediations: number
  lastTriagedAt: string | null
  lastRun: { id: string; finishedAt: Date | null; model: string; summary: unknown } | null
  liveRun: {
    id: string; status: string; startedAt: Date; trigger: string; phase: string;
    progress: number; tokenPrefix: string | null
  } | null
  blockedReason: string | null
  /**
   * Why the graph counts could not be read (`agent_unreachable`,
   * `agent_failed`), or null. The counts are then zeros that mean "unknown",
   * which the dialog must not present as "nothing to do".
   */
  countsUnavailable: string | null
  /** What a live run holds up while it works. */
  blocking: string[]
  defaultRepo: string
  mcpRunsToday: number | null
  mcpRunsPerDay: number
  nextMcpStartAllowedAt: Date | null
  mcpStartRefusal: 'cooldown' | 'daily_cap' | null
}

/** What a live run blocks, for a caller deciding whether to start one. */
export const RUN_BLOCKS = [
  'version activation',
  'Recon Delta against the current graph',
  'Mute Rules apply',
  'start_recon',
  'compare against the current graph',
]

export async function computePreflight(
  caller: TriageTenant, channel: TriageChannel = 'app',
): Promise<TriagePreflight | null> {
  const project = await prisma.project.findUnique({
    where: { id: caller.projectId },
    select: { name: true, userId: true, cypherfixDefaultRepo: true, triageReviewBudget: true },
  })
  if (!project) return null

  // How many findings the AI review may look at; 0 means no review, and the
  // board is still fully ranked without any model. Clamped as the run clamps
  // it, so the dialog never promises more than will happen.
  const reviewBudget = Math.min(MAX_REVIEW_BUDGET, Math.max(0, project.triageReviewBudget ?? 0))
  const model = await readFeatureModel(caller.userId, 'triage')

  const [lastRun, liveRun, remediations, providers] = await Promise.all([
    prisma.triageRun.findFirst({
      where: { projectId: caller.projectId, status: { in: ['completed', 'completed_partial'] } },
      orderBy: { finishedAt: 'desc' },
      select: { id: true, finishedAt: true, model: true, summary: true },
    }),
    findLiveTriageRun(caller.projectId),
    prisma.remediation.groupBy({
      by: ['status'],
      where: { projectId: caller.projectId },
      _count: { _all: true },
    }).catch(() => []),
    prisma.userLlmProvider.findMany({
      where: { userId: caller.userId },
      select: { providerType: true, apiKey: true },
    }).catch(() => []),
  ])

  // Counts from the graph. A failure here degrades the dialog rather than
  // blocking the run: the numbers are guidance, not a guard.
  let counts = { in_scope: 0, never_triaged: 0, open_findings: 0, reviewable: 0,
                 last_triaged_at: null as string | null, reviews_kept: 0, external_reviews: 0 }
  let countsUnavailable: string | null = null
  try {
    const body = await agentTriage('preflight', caller, {}, { channel })
    counts = { ...counts, ...(body as Partial<typeof counts>) }
  } catch (err) {
    countsUnavailable = err instanceof TriageActionError ? err.code : 'agent_failed'
    console.error('[triage] preflight counts unavailable:', err)
  }

  const byStatus = new Map(
    (remediations as Array<{ status: string; _count: { _all: number } }>)
      .map((row) => [row.status, row._count._all])
  )

  // "Does the configured model have a key" is a yes/no; the key itself never
  // leaves the server, and its absence is not an error. An instance provider's
  // model (step 6.11) has one only while the owner may use that provider: the
  // agent builds it from that provider alone, never from the owner's own keys. Own keys Root's
  // byoLlmForbidden withholds from the agent are no key either.
  const instanceRef = splitInstanceModel(model)
  const hasKey = Boolean(model) && (instanceRef
    ? (await entitledInstanceProviders(caller.userId).catch((err) => {
        console.error('[triage] instance providers unreadable:', err)
        return []
      })).some((p) => p.id === instanceRef.providerId)
    : !(await ownProvidersWithheld(caller.userId).catch((err) => {
        console.error('[triage] bring-your-own policy unreadable:', err)
        return false
      })) && providers.filter(isChatProvider).some((p) => Boolean(p.apiKey)))

  let blockedReason: string | null = null
  if (liveRun) {
    blockedReason = 'A triage run is already in progress for this project.'
  } else if (await isActivationInProgress(caller.projectId)) {
    blockedReason = 'A version activation is in progress for this project.'
  } else {
    const busy = await describeLiveGraphWriters(caller.projectId)
    if (busy && !busy.startsWith('a full recon scan') &&
        !busy.startsWith('a partial recon run')) {
      blockedReason = `The live graph is busy: ${busy}.`
    }
  }

  let tokenPrefix: string | null = null
  if (liveRun?.tokenId) {
    const token = await prisma.mcpAccessToken.findUnique({
      where: { id: liveRun.tokenId }, select: { tokenPrefix: true },
    }).catch(() => null)
    tokenPrefix = token?.tokenPrefix ?? null
  }

  let mcp: Awaited<ReturnType<typeof mcpRunBudget>> | null = null
  try {
    mcp = await mcpRunBudget(caller.projectId)
  } catch (err) {
    console.error('[triage] MCP run budget unreadable:', err)
  }

  // What this run would review: findings with no still-valid review, up to the
  // budget. Reviews still valid are kept rather than paid for again.
  const toReview = model ? Math.min(counts.reviewable, reviewBudget) : 0

  return {
    projectName: project.name,
    model,
    modelRequired: !model && reviewBudget > 0,
    hasModelKey: hasKey,
    inScope: counts.in_scope,
    newSinceLastRun: counts.never_triaged,
    openFindings: counts.open_findings,
    reviewable: counts.reviewable,
    reviewBudget,
    reviewsKept: counts.reviews_kept,
    externalReviews: counts.external_reviews,
    estimatedAiCalls: hasKey ? Math.ceil(toReview / REVIEW_BATCH_SIZE) : 0,
    estimatedReviewed: hasKey ? toReview : 0,
    pendingRemediations: byStatus.get('pending') ?? 0,
    inProgressRemediations:
      (byStatus.get('in_progress') ?? 0) + (byStatus.get('pr_created') ?? 0),
    lastTriagedAt: counts.last_triaged_at,
    lastRun: lastRun
      ? { id: lastRun.id, finishedAt: lastRun.finishedAt, model: lastRun.model,
          summary: lastRun.summary }
      : null,
    liveRun: liveRun
      ? { id: liveRun.id, status: liveRun.status, startedAt: liveRun.startedAt,
          trigger: liveRun.trigger ?? 'app', phase: liveRun.phase ?? '',
          progress: liveRun.progress ?? 0, tokenPrefix }
      : null,
    blockedReason,
    countsUnavailable,
    blocking: liveRun ? RUN_BLOCKS : [],
    defaultRepo: project.cypherfixDefaultRepo || '',
    mcpRunsToday: mcp ? mcp.runsToday : null,
    mcpRunsPerDay: MCP_RUNS_PER_DAY,
    nextMcpStartAllowedAt: mcp ? mcp.nextAllowedAt : null,
    mcpStartRefusal: mcp ? mcp.reason : null,
  }
}
