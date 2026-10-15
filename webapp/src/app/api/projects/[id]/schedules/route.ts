/**
 * Scan Timeline - Scan Scheduler CRUD (Section 7.2).
 *
 * GET  /api/projects/[id]/schedules   upcoming schedules + recent run history
 * POST /api/projects/[id]/schedules   create a schedule (validated + RAM-checked)
 */
import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { requireEffectiveUser, requireProjectAccess } from '@/lib/access'
import { writeAudit } from '@/lib/audit'
import {
  validateSchedule,
  checkScheduleFeasibility,
  ScheduleValidationError,
} from '@/lib/scanSchedule'
import { fetchScanEnvelope } from '@/lib/scanEnvelope'

interface RouteParams {
  params: Promise<{ id: string }>
}

// The UI caps each table at 1000 rows (paginated 30/page). Match it here so the
// client has the full, bounded history to page through. Each source (ScanJobs,
// finished queue jobs) is capped, then merged and re-capped newest-first.
const JOB_HISTORY_LIMIT = 1000

export async function GET(_request: NextRequest, { params }: RouteParams) {
  const { id } = await params
  const eff = await requireEffectiveUser()
  if (eff instanceof NextResponse) return eff
  const access = await requireProjectAccess(eff, id)
  if (access instanceof NextResponse) return access

  try {
    const [schedules, jobs, queueHistory] = await Promise.all([
      prisma.scanSchedule.findMany({
        where: { projectId: id },
        // Newest created on top.
        orderBy: { createdAt: 'desc' },
        take: 1000,
      }),
      prisma.scanJob.findMany({
        where: { projectId: id },
        orderBy: { createdAt: 'desc' },
        take: JOB_HISTORY_LIMIT,
        include: {
          version: { select: { seq: true, label: true } },
          change: {
            select: {
              newSubdomains: true,
              removedSubdomains: true,
              newCves: true,
              newVulnCount: true,
              newPorts: true,
              removedPorts: true,
            },
          },
        },
      }),
      // Directly-started scans of every kind now write a ScanJob, so the history
      // above is already multi-kind. This adds the runs the QUEUE owns: a job that
      // was canceled or failed before it ever started has no ScanJob at all, and
      // a queue-dispatched non-full-recon scan is recorded only here.
      prisma.jobQueue.findMany({
        where: {
          projectId: id,
          status: { in: ['done', 'failed', 'canceled'] },
          kind: { not: 'full_recon' },
        },
        orderBy: { finishedAt: 'desc' },
        take: JOB_HISTORY_LIMIT,
        select: {
          id: true, kind: true, status: true, error: true, blockedReason: true,
          enqueuedAt: true, startedAt: true, finishedAt: true, scheduleId: true,
        },
      }),
    ])

    // ScanJob status vocabulary, so one column reads consistently.
    const QUEUE_STATUS: Record<string, string> = {
      done: 'completed', failed: 'failed', canceled: 'canceled',
    }
    const queueRuns = queueHistory.map(q => ({
      id: q.id,
      kind: q.kind,
      trigger: q.scheduleId ? 'scheduled' : 'manual',
      mode: null,
      status: QUEUE_STATUS[q.status] ?? q.status,
      startedAt: q.startedAt,
      finishedAt: q.finishedAt,
      createdAt: q.enqueuedAt,
      nodeCount: null,
      ramReason: q.error || q.blockedReason || null,
      degradedSources: null,
      scheduleId: q.scheduleId,
      version: null,
    }))

    return NextResponse.json(
      {
        schedules: schedules.map(s => ({
          ...s,
          // BigInt is not JSON-serializable.
          estimatedEnvelopeBytes: s.estimatedEnvelopeBytes === null
            ? null
            : Number(s.estimatedEnvelopeBytes),
        })),
        jobs: [
          ...jobs.map(j => ({
            id: j.id,
            kind: j.kind,
            trigger: j.trigger,
            mode: j.mode,
            status: j.status,
            startedAt: j.startedAt,
            finishedAt: j.finishedAt,
            createdAt: j.createdAt,
            nodeCount: j.nodeCount,
            ramReason: j.ramReason,
            degradedSources: j.degradedSources,
            scheduleId: j.scheduleId,
            version: j.version ? { seq: j.version.seq, label: j.version.label } : null,
            change: j.change
              ? {
                  newSubdomains: j.change.newSubdomains.length,
                  removedSubdomains: j.change.removedSubdomains.length,
                  newCves: j.change.newCves,
                  newVulnCount: j.change.newVulnCount,
                  newPorts: Array.isArray(j.change.newPorts) ? j.change.newPorts.length : 0,
                }
              : null,
          })),
          ...queueRuns,
        ]
          .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())
          .slice(0, JOB_HISTORY_LIMIT),
      },
      { headers: { 'Cache-Control': 'private, no-cache' } }
    )
  } catch (error) {
    console.error('[scanTimeline] schedule list failed:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Failed to list schedules' },
      { status: 500 }
    )
  }
}

export async function POST(request: NextRequest, { params }: RouteParams) {
  const { id } = await params
  const eff = await requireEffectiveUser()
  if (eff instanceof NextResponse) return eff
  const access = await requireProjectAccess(eff, id)
  if (access instanceof NextResponse) return access

  const body = await request.json().catch(() => null)

  let validated
  try {
    validated = validateSchedule(body)
  } catch (err) {
    if (err instanceof ScheduleValidationError) {
      return NextResponse.json({ error: err.message }, { status: 400 })
    }
    throw err
  }

  try {
    // Static RAM feasibility (Section 7.3). Overlap is global: the memory pool is
    // shared across ALL projects, so we look at every enabled schedule.
    const env = await fetchScanEnvelope()
    if (env) {
      const others = await prisma.scanSchedule.findMany({
        where: { enabled: true, nextRunAt: { not: null } },
        select: { id: true, nextRunAt: true, estimatedEnvelopeBytes: true },
      })
      const feasibility = checkScheduleFeasibility(validated.nextRunAt, env, others)
      if (!feasibility.feasible) {
        return NextResponse.json(
          {
            error: feasibility.detail,
            // Mirrors the manual-scan limit payload so the UI can reuse its modal.
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

    const created = await prisma.scanSchedule.create({
      data: {
        projectId: id,
        userId: eff.userId,
        label: validated.label,
        mode: validated.mode,
        runAt: validated.runAt,
        intervalMinutes: validated.intervalMinutes,
        cronExpr: validated.cronExpr,
        scanMode: validated.scanMode,
        enabled: validated.enabled,
        nextRunAt: validated.nextRunAt,
        estimatedEnvelopeBytes: env ? BigInt(env.envelopeBytes) : null,
      },
    })

    await writeAudit({
      actorId: eff.userId,
      action: 'scan-schedule.create',
      targetType: 'scanSchedule',
      targetId: created.id,
      after: {
        projectId: id,
        mode: created.mode,
        scanMode: created.scanMode,
        nextRunAt: created.nextRunAt,
        cronExpr: created.cronExpr,
        intervalMinutes: created.intervalMinutes,
      },
    })

    return NextResponse.json({
      schedule: {
        ...created,
        estimatedEnvelopeBytes: created.estimatedEnvelopeBytes === null
          ? null
          : Number(created.estimatedEnvelopeBytes),
      },
    })
  } catch (error) {
    console.error('[scanTimeline] schedule create failed:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Failed to create the schedule' },
      { status: 500 }
    )
  }
}
