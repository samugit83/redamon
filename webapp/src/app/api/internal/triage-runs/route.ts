/**
 * POST /api/internal/triage-runs — the agent asks permission to start a run.
 *
 * This is where a triage run becomes visible to the rest of the product. The
 * agent calls it BEFORE it reads anything, and refuses to start if the call
 * fails for any reason (network, 4xx, 5xx): fail closed.
 *
 * Ownership is re-checked here, strictly: the WebSocket ticket was minted
 * against the project earlier, and a run must never start on somebody else's
 * project (S9).
 */
import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { isInternalRequest } from '@/lib/session'
import { writeAudit } from '@/lib/audit'
import { refuseTriageStart } from '@/lib/triageRun'
import { auditActorOf } from '@/lib/auditActor'
import { recordOwnerCredentialSpend } from '@/lib/authz/ownerSpend'
import { safeErrorCode } from '@/lib/routeErrors'

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
  // Who started it. Anything but an MCP start is the app, whatever was sent.
  const trigger = body.trigger === 'mcp' ? 'mcp' : 'app'
  const tokenId =
    trigger === 'mcp' && typeof body.tokenId === 'string' && /^[A-Za-z0-9_-]{1,64}$/.test(body.tokenId)
      ? body.tokenId
      : null
  const reviewBudget =
    typeof body.reviewBudget === 'number' && Number.isFinite(body.reviewBudget)
      ? Math.max(0, Math.round(body.reviewBudget))
      : null

  if (!projectId || !actorUserId) {
    return NextResponse.json(
      { error: 'projectId and actorUserId are required' },
      { status: 400 }
    )
  }

  const actingAs = realActorUserId !== null && realActorUserId !== actorUserId
  const refusal = await refuseTriageStart(projectId, actorUserId, { actingAs })
  if (refusal) {
    // 404 for "not yours", 409 for "not now": the first must not distinguish
    // itself from a missing project, the second is a retryable state.
    const status = refusal.reason === 'Not found' ? 404 : 409
    return NextResponse.json(
      { error: refusal.reason, runId: refusal.runId },
      { status }
    )
  }

  // A collaborator's run spends the owner's model and keys (step 5.6, C1): recorded as theirs before
  // it starts, and no record, no run.
  try {
    const project = await prisma.project.findUnique({ where: { id: projectId }, select: { userId: true } })
    if (!project) return NextResponse.json({ error: 'Not found' }, { status: 404 })
    await recordOwnerCredentialSpend({
      projectId,
      ownerId: project.userId,
      userId: actorUserId,
      actor: auditActorOf({ id: realActorUserId ?? actorUserId }, actorUserId),
      feature: 'triage_run',
      permission: 'triage:run',
      source: 'system',
    })
  } catch (err) {
    console.error(`[rbac] credits.used not recorded project=${projectId} user=${actorUserId} feature=triage_run: ${safeErrorCode(err)}`)
    return NextResponse.json({ error: 'The run could not be recorded; it did not start.', code: 'spend_not_recorded' }, { status: 503 })
  }

  const run = await prisma.triageRun.create({
    data: {
      projectId,
      actorUserId,
      realActorUserId,
      model,
      scoreModelVersion,
      status: 'running',
      trigger,
      tokenId,
    },
    select: { id: true, startedAt: true },
  })

  await writeAudit({
    actorId: realActorUserId ?? actorUserId,
    action: 'triage.start',
    targetType: 'project',
    targetId: projectId,
    after: {
      runId: run.id, model, scoreModelVersion, effectiveUser: actorUserId,
      trigger, tokenId, reviewBudget,
    },
    source: 'system',
  })

  return NextResponse.json(
    { runId: run.id, startedAt: run.startedAt },
    { status: 201 }
  )
}
