/**
 * POST /api/internal/triage-runs/[runId]/remediations — publish the fix list.
 *
 * The old path deleted every pending remediation and then created the new ones,
 * outside a transaction. Two things went wrong with that:
 *
 * - a failure between the delete and the creates left the project with NO fix
 *   list at all;
 * - a row the CodeFix agent was working on could be deleted underneath it,
 *   taking its branch, its PR link and its session with it.
 *
 * So this upserts by `(projectId, groupKey)` in ONE transaction, and the rule
 * it applies is about ownership rather than freshness: anything a person or the
 * CodeFix agent has touched belongs to them, and a triage run may only refresh
 * the facts around it.
 *
 * | existing row                                   | what happens                    |
 * |------------------------------------------------|---------------------------------|
 * | none                                            | create                          |
 * | pending, unprotected, unchanged since we read   | update in place, same id        |
 * | protected (session / branch / PR / not pending) | only the counts and rank refresh|
 * | pending but edited while we were working        | skipped, and counted            |
 * | dismissed or no_fix                             | left alone, never recreated     |
 * | resolved but its findings are still open        | left resolved, flagged          |
 * | no live members, pending and unprotected        | deleted                         |
 * | legacy row with no group key                    | deleted if pending, else kept   |
 */
import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { isInternalRequest } from '@/lib/session'

interface RouteParams {
  params: Promise<{ runId: string }>
}

/** A row nobody has started work on, so a run may rewrite its content. */
function isProtected(row: {
  status: string; agentSessionId: string; fixBranch: string; prUrl: string
}): boolean {
  return (
    row.status !== 'pending' ||
    Boolean(row.agentSessionId) ||
    Boolean(row.fixBranch) ||
    Boolean(row.prUrl)
  )
}

const SEVERITIES = new Set(['critical', 'high', 'medium', 'low', 'info'])

function str(value: unknown, max: number, fallback = ''): string {
  return typeof value === 'string' ? value.slice(0, max) : fallback
}

function strArray(value: unknown, max = 200, itemMax = 300): string[] {
  if (!Array.isArray(value)) return []
  return value
    .filter((v): v is string => typeof v === 'string')
    .slice(0, max)
    .map((v) => v.slice(0, itemMax))
}

function int(value: unknown, min: number, max: number, fallback: number): number {
  if (typeof value !== 'number' || !Number.isFinite(value)) return fallback
  return Math.min(max, Math.max(min, Math.round(value)))
}

/** The fields a run owns: content plus the facts around it. */
function contentOf(rem: Record<string, unknown>) {
  return {
    title: str(rem.title, 200),
    description: str(rem.description, 5000),
    solution: str(rem.solution, 5000),
    severity: SEVERITIES.has(String(rem.severity)) ? String(rem.severity) : 'medium',
    category: str(rem.category, 60, 'vulnerability') || 'vulnerability',
    remediationType: str(rem.remediationType, 60, 'code_fix') || 'code_fix',
    fixComplexity: str(rem.fixComplexity, 40, 'medium') || 'medium',
    estimatedFiles: int(rem.estimatedFiles, 0, 1000, 0),
    affectedAssets: strArray(rem.affectedAssets),
    cveIds: strArray(rem.cveIds, 50, 120),
    cweIds: strArray(rem.cweIds, 50, 120),
    evidence: str(rem.evidence, 5000),
    exploitAvailable: rem.exploitAvailable === true,
    cisaKev: rem.cisaKev === true,
    cvssScore:
      typeof rem.cvssScore === 'number' && Number.isFinite(rem.cvssScore)
        ? Math.min(10, Math.max(0, rem.cvssScore))
        : undefined,
    // Never model output: this is where the CodeFix agent clones and pushes.
    targetRepo: str(rem.targetRepo, 200),
    targetBranch: str(rem.targetBranch, 200, 'main') || 'main',
  }
}

/** The rank and the link back to the findings: refreshed even on a protected row. */
function factsOf(rem: Record<string, unknown>, runId: string) {
  return {
    priority: int(rem.priority, 0, 100000, 0),
    priorityScore: typeof rem.priorityScore === 'number' && Number.isFinite(rem.priorityScore)
      ? rem.priorityScore
      : 0,
    findingIds: strArray(rem.findingIds, 500, 200),
    liveMemberCount: int(rem.liveMemberCount, 0, 100000, 0),
    triageRunId: runId,
  }
}

export async function POST(request: NextRequest, { params }: RouteParams) {
  if (!isInternalRequest(request)) {
    return NextResponse.json({ error: 'Not found' }, { status: 404 })
  }

  const { runId } = await params
  let body: Record<string, unknown>
  try {
    body = await request.json()
  } catch {
    return NextResponse.json({ error: 'Invalid JSON' }, { status: 400 })
  }

  const projectId = typeof body.projectId === 'string' ? body.projectId : ''
  const incoming = Array.isArray(body.remediations) ? body.remediations : []
  if (!projectId) {
    return NextResponse.json({ error: 'projectId is required' }, { status: 400 })
  }

  const run = await prisma.triageRun.findUnique({
    where: { id: runId },
    select: { id: true, projectId: true, status: true },
  })
  if (!run) return NextResponse.json({ error: 'Unknown run' }, { status: 404 })

  // Only a run that has CLAIMED the publish may write, and only to its own
  // project. The internal key is global, so this pair is the tenant boundary.
  if (run.status !== 'publishing') {
    return NextResponse.json(
      { error: `The run is ${run.status}, not publishing.` },
      { status: 409 }
    )
  }
  if (run.projectId !== projectId) {
    return NextResponse.json({ error: 'Not found' }, { status: 404 })
  }

  const rows = incoming
    .filter((r): r is Record<string, unknown> =>
      Boolean(r) && typeof r === 'object' && !Array.isArray(r))
    .filter((r) => typeof r.groupKey === 'string' && r.groupKey)

  const stats = { created: 0, updated: 0, deleted: 0, skipped: 0, flagged: 0 }

  await prisma.$transaction(async (tx) => {
    const existing = await tx.remediation.findMany({
      where: { projectId },
      select: {
        id: true, groupKey: true, status: true, agentSessionId: true,
        fixBranch: true, prUrl: true, updatedAt: true,
      },
    })
    const byKey = new Map(
      existing.filter((r) => r.groupKey).map((r) => [r.groupKey as string, r])
    )
    const incomingKeys = new Set(rows.map((r) => r.groupKey as string))

    for (const rem of rows) {
      const key = rem.groupKey as string
      const current = byKey.get(key)
      const facts = factsOf(rem, runId)

      if (!current) {
        await tx.remediation.create({
          data: { projectId, groupKey: key, ...contentOf(rem), ...facts },
        })
        stats.created += 1
        continue
      }

      if (isProtected(current)) {
        // Somebody owns this row. Its words stay exactly as they are; only the
        // rank and the link back to the findings are refreshed, so the board
        // and the fix list still agree on the order.
        const stillDetected =
          current.status === 'resolved' && facts.liveMemberCount > 0
        await tx.remediation.update({
          where: { id: current.id },
          data: { ...facts, stillDetected },
        })
        if (stillDetected) stats.flagged += 1
        stats.updated += 1
        continue
      }

      if (facts.liveMemberCount === 0) {
        // Nothing is reporting this any more and nobody has started on it.
        await tx.remediation.delete({ where: { id: current.id } })
        stats.deleted += 1
        continue
      }

      await tx.remediation.update({
        where: { id: current.id },
        data: { ...contentOf(rem), ...facts, stillDetected: false },
      })
      stats.updated += 1
    }

    // Rows this run produced no group for: the findings behind them are gone.
    for (const row of existing) {
      if (row.groupKey && incomingKeys.has(row.groupKey)) continue
      if (isProtected(row)) {
        // Dismissed, resolved, in progress, or owned by a CodeFix session:
        // never recreated and never deleted. Its live count is now zero.
        await tx.remediation.update({
          where: { id: row.id },
          data: { liveMemberCount: 0, stillDetected: false },
        })
        stats.skipped += 1
        continue
      }
      await tx.remediation.delete({ where: { id: row.id } })
      stats.deleted += 1
    }
  })

  return NextResponse.json(stats)
}
