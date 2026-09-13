/**
 * GET /api/triage/preflight?projectId= — what the confirm dialog needs to say.
 *
 * The dialog exists because a triage run is not free and not invisible: it
 * spends LLM budget, replaces the board's order, rewrites the fix list, and
 * blocks version activation while it works. An operator should be told all of
 * that with THIS project's numbers in it, not with a generic warning.
 *
 * So this answers four questions in one call:
 *   how much is in scope, and how much of it is new since the last run;
 *   when the last run was, and with which model;
 *   whether the configured model actually has a key (the run still works
 *     without one, math-only, and the dialog says so rather than failing later);
 *   whether anything is BLOCKING a run right now.
 *
 * Guarded by `requireProjectOwner`, which ignores the log-only ACCESS_ENFORCE=0
 * mode, for the same reason the mute routes do.
 */
import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { requireProjectOwner, callGraphTriage } from '@/lib/triageClient'
import { findLiveTriageRun } from '@/lib/triageRun'
import { isActivationInProgress } from '@/lib/activationLock'
import { describeLiveGraphWriters } from '@/lib/graphWriters'

//: Findings the LLM review will actually be asked about, capped by the budget.
const DEFAULT_REVIEW_BUDGET = 150

export async function GET(request: NextRequest) {
  const projectId = request.nextUrl.searchParams.get('projectId')
  const caller = await requireProjectOwner(projectId)
  if (caller instanceof NextResponse) return caller

  const project = await prisma.project.findUnique({
    where: { id: caller.projectId },
    select: {
      name: true, userId: true, cypherfixLlmModel: true, agentOpenaiModel: true,
      cypherfixDefaultRepo: true,
    },
  })
  if (!project) return NextResponse.json({ error: 'Not found' }, { status: 404 })

  const model = project.cypherfixLlmModel || project.agentOpenaiModel || ''

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
                 last_triaged_at: null as string | null }
  try {
    const res = await callGraphTriage('preflight', caller)
    if (res.ok) counts = { ...counts, ...(await res.json()) }
  } catch {
    // leave the zeros
  }

  const byStatus = new Map(
    (remediations as Array<{ status: string; _count: { _all: number } }>)
      .map((row) => [row.status, row._count._all])
  )

  // "Does the configured model have a key" is a yes/no; the key itself never
  // leaves the server, and its absence is not an error.
  const hasKey = providers.some((p) => Boolean(p.apiKey))

  let blockedReason: string | null = null
  if (liveRun) {
    blockedReason = 'A triage run is already in progress for this project.'
  } else if (await isActivationInProgress(caller.projectId)) {
    blockedReason = 'A version activation is in progress for this project.'
  } else {
    // Scans deliberately do NOT block: the publish guard skips any node a scan
    // changed, so the two can run side by side.
    const busy = await describeLiveGraphWriters(caller.projectId)
    if (busy && !busy.startsWith('a full recon scan') &&
        !busy.startsWith('a partial recon run')) {
      blockedReason = `The live graph is busy: ${busy}.`
    }
  }

  const reviewBudget = DEFAULT_REVIEW_BUDGET
  const toReview = Math.min(counts.reviewable, reviewBudget)

  return NextResponse.json({
    projectName: project.name,
    model,
    hasModelKey: hasKey,
    inScope: counts.in_scope,
    newSinceLastRun: counts.never_triaged,
    openFindings: counts.open_findings,
    reviewBudget,
    estimatedAiCalls: hasKey ? Math.ceil(toReview / 12) : 0,
    estimatedReviewed: hasKey ? toReview : 0,
    pendingRemediations: byStatus.get('pending') ?? 0,
    inProgressRemediations:
      (byStatus.get('in_progress') ?? 0) + (byStatus.get('pr_created') ?? 0),
    lastRun: lastRun
      ? { id: lastRun.id, finishedAt: lastRun.finishedAt, model: lastRun.model,
          summary: lastRun.summary }
      : null,
    liveRun: liveRun ? { id: liveRun.id, startedAt: liveRun.startedAt } : null,
    blockedReason,
    defaultRepo: project.cypherfixDefaultRepo || '',
  })
}
