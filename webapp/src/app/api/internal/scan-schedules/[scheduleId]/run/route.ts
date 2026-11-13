/**
 * Scan Timeline - execute a due schedule (Section 7.2). Internal-key only.
 *
 * Runs the scan through the SAME path a manual scan uses (lib/startFullScan.ts),
 * so a scheduled run inherits, unchanged:
 *   - the project activation lock (F3),
 *   - the freeze-before-start of the outgoing graph (Section 3.2 option 1),
 *   - the orchestrator's RoE time-window / excluded-host / hard-guardrail checks
 *     and the admission ledger (Section 7.3 "ROE at execution"),
 *   - the ScanJob history row, tagged trigger='scheduled'.
 *
 * `nextRunAt` is advanced whatever the outcome, so a scan that cannot start does
 * not pin the schedule to a due state and hot-loop the worker.
 *
 * A live agent session holds the run, as it holds a queued full recon at
 * dispatch: the scan would clear the graph the agent is working on. The check
 * runs BEFORE startFullScan (which would freeze a version first) and fails
 * closed on an unverified session; the occurrence becomes a queue row, never
 * a second one while a full recon is already queued or running.
 *
 * The schedule starts its scans as the person who created it (or last confirmed it), so
 * that person must still be allowed to start a full recon here when it fires (step 5.5,
 * DV-38, D-13): a collaborator whose share was revoked, expired or narrowed since. A
 * schedule whose actor lost access is paused (`enabled: false`, `pausedReason:
 * 'actor_no_access'`), audited `scan_schedule.paused`, with a notice to the owner, never
 * re-attributed: the owner or a co-owner confirms it
 * (`POST /api/projects/[id]/schedules/[scheduleId]/confirm`) and becomes its actor.
 */

/** A full recon of this project already waiting or running in the queue. */
async function openFullReconJob(projectId: string) {
  return prisma.jobQueue.findFirst({
    where: { projectId, kind: 'full_recon', status: { in: ['queued', 'dispatching', 'running', 'needs_review'] } },
    select: { id: true, status: true },
  })
}

/** Queue the occurrence unless a full recon is already queued or running. */
async function enqueueOccurrence(schedule: { id: string; projectId: string; userId: string }, mode: string) {
  const open = await openFullReconJob(schedule.projectId)
  if (open) return { ok: true, id: open.id as string | undefined, alreadyQueued: true }
  const enq = await enqueueJob({
    projectId: schedule.projectId,
    userId: schedule.userId,
    kind: 'full_recon',
    payload: { mode },
    priority: 0, // scheduled
    scheduleId: schedule.id,
  }).catch(err => {
    console.error('[scanScheduler] could not enqueue deferred scheduled run:', err)
    return { ok: false, status: 500, error: String(err), id: undefined as string | undefined }
  })
  return { ok: enq.ok, id: enq.id, alreadyQueued: false }
}
import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { isInternalRequest } from '@/lib/session'
import { startFullScan } from '@/lib/startFullScan'
import { computeNextRun } from '@/lib/scanSchedule'
import { parseScanMode, createScanJob } from '@/lib/scanTimeline'
import { classifyStartFailure } from '@/lib/scanStartOutcome'
import { enqueueJob } from '@/lib/enqueueJob'
import { writeAudit } from '@/lib/audit'
import { checkAgentSessions, describeAgentSessionState } from '@/lib/agentSessions'
import {
  actorScanRefusal, actorScanRefusalReason, inactiveScanAccount, inactiveScanReason, noticeSchedulePaused,
} from '@/lib/authz/scanActor'
import { queuedJobPermissions } from '@/lib/authz/queuedJobPermissions'

export const runtime = 'nodejs'

interface RouteParams {
  params: Promise<{ scheduleId: string }>
}

export async function POST(request: NextRequest, { params }: RouteParams) {
  if (!isInternalRequest(request)) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  }

  const { scheduleId } = await params

  try {
    const schedule = await prisma.scanSchedule.findUnique({ where: { id: scheduleId } })
    if (!schedule) return NextResponse.json({ error: 'Not found' }, { status: 404 })
    if (!schedule.enabled) {
      return NextResponse.json({ ok: false, skipped: 'disabled' }, { status: 409 })
    }

    const mode = parseScanMode(schedule.scanMode) ?? 'new'
    const now = new Date()
    // A one-off schedule is spent after it fires; recurring ones roll forward.
    // `enabled` is never written back for a recurring one: the value read above
    // predates the start, and a pause made meanwhile (a rescope that widened the
    // batch, or a person) must survive it.
    const nextRunAt = computeNextRun(schedule, now)
    const advance = () => prisma.scanSchedule.update({
      where: { id: scheduleId },
      data: {
        lastRunAt: now,
        nextRunAt,
        ...(schedule.mode === 'once' ? { enabled: false } : {}),
      },
    })

    // A disabled person's schedule must not keep starting scans on their keys (DV-39). The
    // occurrence is spent, unlike the `disabled` skip above: once the account is enabled the
    // next occurrence fires, and the missed ones are not caught up.
    const inactive = await inactiveScanAccount({ actorUserId: schedule.userId, projectId: schedule.projectId })
    if (inactive) {
      await advance()
      const reason = inactiveScanReason(inactive, 'scheduled')
      console.warn(`[rbac] schedule ${scheduleId} skipped: ${inactive.as} ${inactive.userId} is ${inactive.status}`)
      await writeAudit({
        actorId: null,
        action: 'scan_schedule.skipped',
        targetType: 'scanSchedule',
        targetId: schedule.id,
        after: {
          reason: 'actor_inactive', projectId: schedule.projectId,
          userId: inactive.userId, account: inactive.as, status: inactive.status,
        },
        source: 'system',
      })
      return NextResponse.json(
        { ok: false, skipped: 'actor_inactive', error: `skipped: ${reason}`, nextRunAt },
        { status: 200 },
      )
    }

    const refusal = await actorScanRefusal(
      schedule.userId, schedule.projectId, queuedJobPermissions('full_recon', { mode: schedule.scanMode }),
    )
    if (refusal) {
      // Only while the schedule still names this actor: a confirmation that landed since the read
      // above made someone else its actor, and pausing would undo it (two at once).
      const paused = await prisma.scanSchedule.updateMany({
        where: { id: scheduleId, userId: schedule.userId },
        data: { lastRunAt: now, nextRunAt, enabled: false, pausedReason: 'actor_no_access' },
      })
      if (paused.count === 0) {
        console.info(`[scanScheduler] schedule ${scheduleId} changed actor while firing; left to its next run`)
        return NextResponse.json({ ok: false, skipped: 'actor_changed' }, { status: 409 })
      }
      const reason = actorScanRefusalReason(refusal, 'scheduled')
      console.warn(
        `[rbac] schedule ${scheduleId} paused: actor ${refusal.userId} lost ${refusal.permission} ` +
        `on project ${schedule.projectId} (${refusal.reason})`,
      )
      await writeAudit({
        actorId: null,
        projectId: schedule.projectId,
        action: 'scan_schedule.paused',
        targetType: 'scanSchedule',
        targetId: schedule.id,
        after: {
          reason: 'actor_no_access', projectId: schedule.projectId,
          userId: refusal.userId, permission: refusal.permission, refusal: refusal.reason,
        },
        source: 'system',
      })
      await noticeSchedulePaused({
        projectId: schedule.projectId, scheduleId: schedule.id, label: schedule.label, actorUserId: refusal.userId,
      })
      return NextResponse.json(
        { ok: false, paused: true, code: 'actor_no_access', error: `paused: ${reason}`, nextRunAt },
        { status: 200 },
      )
    }

    const agent = describeAgentSessionState(await checkAgentSessions(schedule.projectId))
    if (agent) {
      await advance()
      const enq = await enqueueOccurrence(schedule, mode)
      console.info(
        `[scanScheduler] schedule ${scheduleId} held: ${agent}; ` +
        `${enq.alreadyQueued ? 'a full recon is already queued' : 'enqueued'} as ${enq.id ?? 'none'}`
      )
      return NextResponse.json(
        {
          ok: false, queued: enq.ok, jobId: enq.id ?? null, blockedCode: 'agent_running',
          error: `${agent} for this project; a full recon would wipe its graph`,
          ...(enq.alreadyQueued ? { alreadyQueued: true } : {}),
          nextRunAt,
        },
        { status: 200 },
      )
    }

    const result = await startFullScan({
      projectId: schedule.projectId,
      mode,
      trigger: 'scheduled',
      actorUserId: schedule.userId,
      scheduleId: schedule.id,
      // A transient refusal becomes a queue row below, so no failed run for it.
      quietTransient: true,
    })

    await advance()

    if (!result.ok) {
      const cls = classifyStartFailure(result.status, {
        error: result.error,
        limit: result.limit as { limitType?: string } | undefined,
        activationInProgress: result.activationInProgress,
        busy: result.busy,
        snapshotFailed: result.snapshotFailed,
        startOutcome: result.startOutcome,
        code: result.code,
      }, { orchestratorAnswered: result.startOutcome !== 'unknown' })

      // The orchestrator did not answer: a scan may be running. Queueing the
      // occurrence could start a second one, so it is not enqueued; the failed
      // ScanJob startFullScan wrote ("start outcome unknown") is the record.
      if (cls.kind === 'unknown') {
        console.warn(`[scanScheduler] schedule ${scheduleId}: ${result.error}`)
        return NextResponse.json(
          { ok: false, startOutcome: 'unknown', error: result.error, scanJobId: result.scanJobId ?? null, nextRunAt },
          { status: 200 },
        )
      }

      // Phase 4: a TEMPORARY refusal (RAM/hard limit, activation, the graph is
      // busy, or a transient error the orchestrator answered) must NOT burn the
      // occurrence. Advancing nextRunAt above is correct
      // precisely because the occurrence becomes a durable queue row here, which
      // the dispatcher runs when resources free up. This replaces the old
      // defer-and-retry-every-tick path.
      if (cls.temporary) {
        const enq = await enqueueOccurrence(schedule, mode)
        console.info(
          `[scanScheduler] schedule ${scheduleId} refused (${cls.blockedCode || 'temporary'}); ` +
          `${enq.alreadyQueued ? 'a full recon is already queued' : 'enqueued'} as ${enq.id ?? 'none'}`
        )
        return NextResponse.json(
          {
            ok: false, queued: enq.ok, jobId: enq.id ?? null, blockedCode: cls.blockedCode, error: result.error,
            ...(enq.alreadyQueued ? { alreadyQueued: true } : {}),
            nextRunAt,
          },
          { status: 200 },
        )
      }

      // PERMANENT: nothing to queue. Record a failed ScanJob so the run history
      // shows why (an admission-limit rejection already recorded its own).
      console.warn(`[scanScheduler] schedule ${scheduleId} could not start: ${result.error}`)
      let scanJobId = result.scanJobId ?? null
      if (!scanJobId) {
        const job = await createScanJob({
          projectId: schedule.projectId,
          trigger: 'scheduled',
          mode: parseScanMode(schedule.scanMode),
          status: 'failed',
          initiatedByUserId: schedule.userId,
          scheduleId: schedule.id,
          ramReason: result.error,
        }).catch(err => {
          console.error('[scanScheduler] could not record skipped scheduled run:', err)
          return null
        })
        scanJobId = job?.id ?? null
      }
      // A schedule fires headless, so a scope the rules now refuse would fail on
      // every tick. Pause it until a person fixes the list and re-enables it.
      let paused = false
      if (result.code === 'scope_invalid') {
        await prisma.scanSchedule.update({ where: { id: scheduleId }, data: { enabled: false } })
        paused = true
        void writeAudit({
          actorId: schedule.userId,
          action: 'schedule.paused',
          targetType: 'scanSchedule',
          targetId: schedule.id,
          after: {
            reason: 'scope_invalid',
            projectId: schedule.projectId,
            invalidEntries: result.invalidEntries ?? [],
          },
          source: 'system',
        })
      }
      return NextResponse.json(
        {
          ok: false,
          error: result.error,
          ...(paused ? { paused: true, code: 'scope_invalid' } : {}),
          ...(result.snapshotFailed ? { snapshotFailed: true } : {}),
          scanJobId,
          nextRunAt,
        },
        { status: 200 },
      )
    }

    console.info(
      `[scanScheduler] started scheduled scan for project ${schedule.projectId} ` +
      `(schedule ${scheduleId}, mode ${mode}, version ${result.versionSeq})`
    )
    return NextResponse.json({
      ok: true,
      projectId: schedule.projectId,
      scanJobId: result.scanJobId,
      versionId: result.versionId,
      frozenVersionId: result.frozenVersionId,
      nextRunAt,
    })
  } catch (error) {
    console.error('[scanScheduler] run failed:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Failed to run the schedule' },
      { status: 500 }
    )
  }
}
