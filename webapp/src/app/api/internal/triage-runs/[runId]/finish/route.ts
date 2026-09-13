/**
 * POST /api/internal/triage-runs/[runId]/finish — record how the run ended.
 *
 * Always called, from a `finally`, including after an exception. A run left in
 * `running` would block activation until its heartbeat went stale ten minutes
 * later, so the failure path matters more here than the success one.
 *
 * `summary` is counts only and `errorClass` is a code: raw provider text
 * routinely carries the API key it was called with, and this row is readable
 * wherever the run is.
 */
import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { isInternalRequest } from '@/lib/session'
import { writeAudit } from '@/lib/audit'
import { TRIAGE_STATUSES, type TriageStatus } from '@/lib/triageRun'

interface RouteParams {
  params: Promise<{ runId: string }>
}

const TERMINAL: TriageStatus[] = [
  'completed', 'completed_partial', 'failed', 'stopped',
]

/** Counts only. An unexpected key is dropped rather than stored. */
const SUMMARY_KEYS = new Set([
  'scored', 'reviewed', 'cache_hits', 'not_reviewed', 'skipped_changed',
  'false_positives', 'groups', 'llm_calls', 'duration_ms',
  'remediations_created', 'remediations_updated', 'remediations_deleted',
  'remediations_skipped', 'nodes_written',
])

function cleanSummary(value: unknown): Record<string, number> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return {}
  const out: Record<string, number> = {}
  for (const [key, raw] of Object.entries(value as Record<string, unknown>)) {
    if (!SUMMARY_KEYS.has(key)) continue
    const num = Number(raw)
    if (Number.isFinite(num)) out[key] = Math.round(num)
  }
  return out
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
    body = {}
  }

  const requested = String(body.status || '')
  const status = (TERMINAL as string[]).includes(requested)
    ? (requested as TriageStatus)
    : 'failed'

  const run = await prisma.triageRun.findUnique({
    where: { id: runId },
    select: { id: true, projectId: true, actorUserId: true, realActorUserId: true },
  })
  if (!run) {
    return NextResponse.json({ error: 'Unknown run' }, { status: 404 })
  }

  const summary = cleanSummary(body.summary)
  await prisma.triageRun.update({
    where: { id: runId },
    data: {
      status,
      summary,
      errorClass: typeof body.errorClass === 'string' ? body.errorClass.slice(0, 60) : '',
      finishedAt: new Date(),
      ...(typeof body.intelDate === 'string' && body.intelDate
        ? { intelDate: new Date(body.intelDate) }
        : {}),
    },
  })

  await writeAudit({
    actorId: run.realActorUserId ?? run.actorUserId,
    action: 'triage.finish',
    targetType: 'project',
    targetId: run.projectId,
    after: { runId, status, summary },
    source: 'system',
  })

  return NextResponse.json({ status })
}
