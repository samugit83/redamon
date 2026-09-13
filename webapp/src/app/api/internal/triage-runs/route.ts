/**
 * POST /api/internal/triage-runs — the agent asks permission to start a run.
 *
 * This is where a triage run becomes visible to the rest of the product. The
 * agent calls it BEFORE it reads anything, and refuses to start if the call
 * fails for any reason (network, 4xx, 5xx): fail closed.
 *
 * Ownership is re-checked here, strictly. The WebSocket ticket is minted by
 * `requireProjectAccess`, which honours the log-only `ACCESS_ENFORCE=0` mode;
 * that mode exists so an ownership fix can be rolled out in observe-mode, but a
 * run must never start on somebody else's project because of it (S9).
 */
import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { isInternalRequest } from '@/lib/session'
import { writeAudit } from '@/lib/audit'
import { refuseTriageStart } from '@/lib/triageRun'

export async function POST(request: NextRequest) {
  // The middleware allowlist is fail-open by design, so this is the real guard.
  if (!isInternalRequest(request)) {
    return NextResponse.json({ error: 'Not found' }, { status: 404 })
  }

  let body: Record<string, unknown>
  try {
    body = await request.json()
  } catch {
    return NextResponse.json({ error: 'Invalid JSON' }, { status: 400 })
  }

  const projectId = typeof body.projectId === 'string' ? body.projectId : ''
  const actorUserId = typeof body.actorUserId === 'string' ? body.actorUserId : ''
  const realActorUserId =
    typeof body.realActorUserId === 'string' && body.realActorUserId
      ? body.realActorUserId
      : null
  const model = typeof body.model === 'string' ? body.model.slice(0, 200) : ''
  const scoreModelVersion =
    typeof body.scoreModelVersion === 'string' ? body.scoreModelVersion.slice(0, 40) : ''

  if (!projectId || !actorUserId) {
    return NextResponse.json(
      { error: 'projectId and actorUserId are required' },
      { status: 400 }
    )
  }

  const refusal = await refuseTriageStart(projectId, actorUserId)
  if (refusal) {
    // 404 for "not yours", 409 for "not now": the first must not distinguish
    // itself from a missing project, the second is a retryable state.
    const status = refusal.reason === 'Not found' ? 404 : 409
    return NextResponse.json(
      { error: refusal.reason, runId: refusal.runId },
      { status }
    )
  }

  const run = await prisma.triageRun.create({
    data: {
      projectId,
      actorUserId,
      realActorUserId,
      model,
      scoreModelVersion,
      status: 'running',
    },
    select: { id: true, startedAt: true },
  })

  await writeAudit({
    actorId: realActorUserId ?? actorUserId,
    action: 'triage.start',
    targetType: 'project',
    targetId: projectId,
    after: { runId: run.id, model, scoreModelVersion, effectiveUser: actorUserId },
    source: 'system',
  })

  return NextResponse.json(
    { runId: run.id, startedAt: run.startedAt },
    { status: 201 }
  )
}
