/**
 * POST /api/projects/[id]/schedules/[scheduleId]/confirm (step 5.5, D-13): a person takes a
 * schedule over as its actor and turns it on. A schedule runs its scans as its actor; when that
 * person loses access to the project the schedule is paused when it fires and never re-attributed
 * silently (internal/scan-schedules/[scheduleId]/run). This is the explicit act that moves it.
 *
 * `recon:schedule` at the Manage level (the owner; a co-owner once Phase 5's Manage level exists),
 * plus every permission the schedule's scans need (`recon:scan`, `recon:overwrite` in overwrite
 * mode), since they now run as the confirmer. Same-origin JSON (`{}`). A saved scope the rules now
 * refuse answers 422 (fix it first, as the PATCH that enables a schedule does); a one-off whose time
 * has passed answers 409 `schedule_spent`. Audited `scan_schedule.confirmed` with the actor before
 * and after.
 */
import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { requireAlso, requireLevel, requirePermission } from '@/lib/authz/guards'
import { queuedJobPermissions } from '@/lib/authz/queuedJobPermissions'
import { auditActorOf } from '@/lib/auditActor'
import { writeAudit } from '@/lib/audit'
import { readJsonBody } from '@/lib/jsonBody'
import { crossOriginResponse, sameOrigin } from '@/lib/plugins/sameOrigin'
import { withRouteErrors } from '@/lib/routeErrors'
import { computeNextRun } from '@/lib/scanSchedule'
import { IP_HOSTNAME_SELECT, scopeStartProblem } from '@/lib/scopeGroups'

interface RouteParams {
  params: Promise<{ id: string; scheduleId: string }>
}

export const POST = withRouteErrors('Could not confirm the schedule', async (request: NextRequest, { params }: RouteParams) => {
  const { id, scheduleId } = await params
  const auth = await requirePermission(request, 'recon:schedule', { projectId: id, fresh: true })
  if (auth instanceof NextResponse) return auth
  const level = requireLevel(auth, 'M')
  if (level) return level
  if (!sameOrigin(request)) return crossOriginResponse(request)
  const parsed = await readJsonBody(request)
  if (parsed instanceof NextResponse) return parsed

  const schedule = scheduleId ? await prisma.scanSchedule.findUnique({ where: { id: scheduleId } }) : null
  if (!schedule || schedule.projectId !== id) return NextResponse.json({ error: 'Not found' }, { status: 404 })

  for (const permission of queuedJobPermissions('full_recon', { mode: schedule.scanMode })) {
    const refused = requireAlso(auth, permission)
    if (refused) return refused
  }

  const project = await prisma.project.findUnique({
    where: { id },
    select: {
      ipMode: true, domainBatchMode: true, domainBatchHosts: true, targetDomain: true, subdomainList: true,
      engagementKind: true, ...IP_HOSTNAME_SELECT,
    },
  })
  const problem = project ? scopeStartProblem(project) : null
  if (problem) {
    return NextResponse.json(
      {
        error: `${problem.message} Edit the target list, then confirm this schedule.`,
        code: 'scope_invalid',
        invalidEntries: problem.invalid,
      },
      { status: 422 },
    )
  }

  const now = new Date()
  let nextRunAt: Date | null
  if (schedule.mode === 'once') {
    if (!schedule.runAt || schedule.runAt.getTime() <= now.getTime()) {
      return NextResponse.json(
        { error: 'This one-off schedule\'s time has passed. Schedule a new scan instead.', code: 'schedule_spent' },
        { status: 409 },
      )
    }
    nextRunAt = schedule.runAt
  } else {
    // Counted from now: the occurrences missed while it was paused are not caught up.
    nextRunAt = computeNextRun(schedule, now)
  }

  const actorUserId = auth.effective.userId
  const updated = await prisma.scanSchedule.update({
    where: { id: scheduleId },
    data: { userId: actorUserId, enabled: true, nextRunAt },
  })
  await writeAudit({
    ...auditActorOf(auth.principal, actorUserId),
    projectId: id,
    permission: 'recon:schedule',
    action: 'scan_schedule.confirmed',
    targetType: 'scanSchedule',
    targetId: scheduleId,
    before: { userId: schedule.userId, enabled: schedule.enabled },
    after: { userId: actorUserId, enabled: true, nextRunAt },
  })
  return NextResponse.json({
    schedule: {
      ...updated,
      estimatedEnvelopeBytes: updated.estimatedEnvelopeBytes === null ? null : Number(updated.estimatedEnvelopeBytes),
    },
  })
})
