/**
 * Scan Timeline - one schedule (Section 7.2).
 *
 * PATCH  enable/disable, retime, change scan mode or label
 * DELETE remove the schedule (its ScanJob history survives, schedule_id -> NULL)
 */
import { NextRequest, NextResponse } from 'next/server'
import { requireAlso, requirePermission } from '@/lib/authz/guards'
import prisma from '@/lib/prisma'
import { writeAudit } from '@/lib/audit'
import {
  validateSchedule,
  checkScheduleFeasibility,
  sanitizeScheduleLabel,
  ScheduleValidationError,
} from '@/lib/scanSchedule'
import { fetchScanEnvelope } from '@/lib/scanEnvelope'
import { IP_HOSTNAME_SELECT, scopeStartProblem } from '@/lib/scopeGroups'
import { internalError, withRouteErrors } from '@/lib/routeErrors'

interface RouteParams {
  params: Promise<{ id: string; scheduleId: string }>
}

/** Anti-IDOR: a schedule id is client-supplied and must belong to this project. */
async function loadOwnedSchedule(projectId: string, scheduleId: string) {
  if (!scheduleId) return null
  const row = await prisma.scanSchedule.findUnique({ where: { id: scheduleId } })
  if (!row || row.projectId !== projectId) return null
  return row
}

const NOT_FOUND = () => NextResponse.json({ error: 'Not found' }, { status: 404 })

export const PATCH = withRouteErrors('Failed to update the schedule', async (request: NextRequest, { params }: RouteParams) => {
  const { id, scheduleId } = await params
  const auth = await requirePermission(request, 'recon:schedule', { projectId: id })
  if (auth instanceof NextResponse) return auth
  const eff = auth.effective

  const existing = await loadOwnedSchedule(id, scheduleId)
  if (!existing) return NOT_FOUND()

  const body = (await request.json().catch(() => ({}))) as Record<string, unknown>
  // Turning a schedule on lets it start full recons as its author; overwrite mode replaces the graph.
  const refused = (body.enabled === true ? requireAlso(auth, 'recon:scan') : null)
    ?? (body.scanMode === 'overwrite' ? requireAlso(auth, 'recon:overwrite') : null)
  if (refused) return refused

  // A schedule paused because its saved scope is no longer valid would fail
  // again on its next tick: the scope is fixed first, then the schedule.
  if (body.enabled === true) {
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
          error: `${problem.message} Edit the target list, then enable this schedule.`,
          code: 'scope_invalid',
          invalidEntries: problem.invalid,
        },
        { status: 422 },
      )
    }
  }

  // Only a change that touches the TIMING re-validates it. A spent one-off has a
  // runAt in the past, so re-validating on every edit would make renaming or
  // re-enabling it impossible ("runAt must be in the future") even though the
  // caller never touched the schedule's timing.
  const touchesTiming = ['mode', 'runAt', 'intervalMinutes', 'cronExpr'].some(k => k in body)
  if (!touchesTiming) {
    const data: { enabled?: boolean; label?: string; scanMode?: string } = {}
    if ('enabled' in body) {
      if (typeof body.enabled !== 'boolean') {
        return NextResponse.json({ error: 'enabled must be a boolean' }, { status: 400 })
      }
      data.enabled = body.enabled
    }
    if ('label' in body) {
      const label = sanitizeScheduleLabel(body.label)
      if (label instanceof Error) {
        return NextResponse.json({ error: label.message }, { status: 400 })
      }
      if (label !== null) data.label = label
    }
    if ('scanMode' in body) {
      if (body.scanMode !== 'new' && body.scanMode !== 'overwrite') {
        return NextResponse.json({ error: "scanMode must be 'new' or 'overwrite'" }, { status: 400 })
      }
      data.scanMode = body.scanMode
    }
    if (Object.keys(data).length === 0) {
      return NextResponse.json(
        { error: 'Nothing to update (expected enabled, label, scanMode or a timing change)' },
        { status: 400 }
      )
    }

    const updated = await prisma.scanSchedule.update({ where: { id: scheduleId }, data })
    await writeAudit({
      actorId: eff.userId,
      action: 'scan-schedule.update',
      targetType: 'scanSchedule',
      targetId: scheduleId,
      before: { enabled: existing.enabled, label: existing.label, scanMode: existing.scanMode },
      after: { enabled: updated.enabled, label: updated.label, scanMode: updated.scanMode },
    })
    return NextResponse.json({ schedule: serialize(updated) })
  }

  let validated
  try {
    validated = validateSchedule({
      mode: (body.mode as string) ?? existing.mode,
      runAt: (body.runAt as string) ?? existing.runAt,
      intervalMinutes: (body.intervalMinutes as number) ?? existing.intervalMinutes,
      cronExpr: (body.cronExpr as string) ?? existing.cronExpr,
      scanMode: (body.scanMode as 'new' | 'overwrite') ?? existing.scanMode,
      label: (body.label as string) ?? existing.label,
      enabled: body.enabled === undefined ? existing.enabled : Boolean(body.enabled),
    })
  } catch (err) {
    if (err instanceof ScheduleValidationError) {
      return NextResponse.json({ error: err.message }, { status: 400 })
    }
    throw err
  }

  try {
    const env = await fetchScanEnvelope()
    if (env && validated.enabled) {
      const others = await prisma.scanSchedule.findMany({
        where: { enabled: true, nextRunAt: { not: null }, id: { not: scheduleId } },
        select: { id: true, nextRunAt: true, estimatedEnvelopeBytes: true },
      })
      const feasibility = checkScheduleFeasibility(validated.nextRunAt, env, others)
      if (!feasibility.feasible) {
        return NextResponse.json(
          {
            error: feasibility.detail,
            limit: {
              limitType: feasibility.limitType,
              resource: 'scan',
              detail: feasibility.detail,
              reason: feasibility.reason,
              conflictingScheduleIds: feasibility.conflictingScheduleIds,
            },
          },
          { status: 409 }
        )
      }
    }

    const updated = await prisma.scanSchedule.update({
      where: { id: scheduleId },
      data: {
        label: validated.label,
        mode: validated.mode,
        runAt: validated.runAt,
        intervalMinutes: validated.intervalMinutes,
        cronExpr: validated.cronExpr,
        scanMode: validated.scanMode,
        enabled: validated.enabled,
        nextRunAt: validated.nextRunAt,
        ...(env ? { estimatedEnvelopeBytes: BigInt(env.envelopeBytes) } : {}),
      },
    })

    await writeAudit({
      actorId: eff.userId,
      action: 'scan-schedule.update',
      targetType: 'scanSchedule',
      targetId: scheduleId,
      before: { mode: existing.mode, nextRunAt: existing.nextRunAt, enabled: existing.enabled },
      after: { mode: updated.mode, nextRunAt: updated.nextRunAt, enabled: updated.enabled },
    })

    return NextResponse.json({ schedule: serialize(updated) })
  } catch (error) {
    return internalError(error, 'Failed to update the schedule', { log: '[scanTimeline] schedule update failed' })
  }
})

export const DELETE = withRouteErrors('Failed to delete the schedule', async (request: NextRequest, { params }: RouteParams) => {
  const { id, scheduleId } = await params
  const auth = await requirePermission(request, 'recon:schedule', { projectId: id })
  if (auth instanceof NextResponse) return auth
  const eff = auth.effective

  const existing = await loadOwnedSchedule(id, scheduleId)
  if (!existing) return NOT_FOUND()

  try {
    await prisma.scanSchedule.delete({ where: { id: scheduleId } })
    await writeAudit({
      actorId: eff.userId,
      action: 'scan-schedule.delete',
      targetType: 'scanSchedule',
      targetId: scheduleId,
      before: {
        projectId: id, mode: existing.mode, scanMode: existing.scanMode,
        cronExpr: existing.cronExpr, intervalMinutes: existing.intervalMinutes,
      },
    })
    return NextResponse.json({ ok: true, deletedScheduleId: scheduleId })
  } catch (error) {
    return internalError(error, 'Failed to delete the schedule', { log: '[scanTimeline] schedule delete failed' })
  }
})

function serialize(s: { estimatedEnvelopeBytes: bigint | null }) {
  return {
    ...s,
    estimatedEnvelopeBytes: s.estimatedEnvelopeBytes === null ? null : Number(s.estimatedEnvelopeBytes),
  }
}
