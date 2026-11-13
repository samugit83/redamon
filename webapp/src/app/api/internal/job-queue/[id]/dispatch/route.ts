/**
 * Scan Queue - dispatch one queued job (plan Phase 2). Internal-key only.
 *
 * The dispatcher (orchestrator) decides WHICH job fits the ledger; this route runs
 * it, re-running every safety check at dispatch time because minutes-to-hours have
 * passed since enqueue. Order of checks, ALL fail-closed:
 *   1. claim the row (queued -> dispatching) with a conditional update, so two
 *      dispatch calls can never both run the same job (C-12 per-project serialize
 *      is enforced by step 3 + this claim).
 *   2. project still exists (C-7): gone -> status=failed, never proceed.
 *   2b. with the identity switch on, the job's account and the project's owner are
 *      active (DV-39): otherwise status=canceled, blockedCode=actor_inactive.
 *   2c. the job's account still holds the permission that starts its kind on this project,
 *      at the scan's level (step 5.5, DV-38): a collaborator whose share was revoked,
 *      expired or narrowed since queueing is refused: status=canceled,
 *      blockedCode=actor_no_access. The owner always passes.
 *   3. no OTHER non-terminal job for this project (C-12): one job per project.
 *   4. settings fingerprint matches (C-4): changed -> status=needs_review, no run.
 *   5. no agent running when kind=full_recon (C-5): defer, blockedCode=agent_running.
 *   6. then the same start path the button uses (lib/startScan.ts, R2).
 *
 * A capacity wait (RAM/hard/activation/409) returns the row to 'queued' on a short
 * recheck without spending an attempt. A transient refusal (an answered 5xx, a
 * freeze failure) is retried with backoff, spending one; a permanent one fails it.
 * A start whose outcome is unknown (the orchestrator did not answer) is never
 * retried blindly: a full recon adopts the scan the orchestrator reports as just
 * started, or requeues when nothing started; any other kind waits for a person
 * (needs_review). A throw spends an attempt too, so it cannot retry every tick.
 */
import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { isInternalRequest } from '@/lib/session'
import { nextBackoff, CAPACITY_RECHECK_MS } from '@/lib/jobQueue'
import { currentFingerprintFor } from '@/lib/jobFingerprint'
import { classifyStartFailure, isCapacityWait } from '@/lib/scanStartOutcome'
import { dispatchStart, stopScan } from '@/lib/startScan'
import { checkAgentSessions, describeAgentSessionState } from '@/lib/agentSessions'
import { orchestratorFetch } from '@/lib/orchestrator'
import { actorScanRefusal, actorScanRefusalReason, inactiveScanAccount, inactiveScanReason } from '@/lib/authz/scanActor'
import { queuedJobPermissions } from '@/lib/authz/queuedJobPermissions'
import { writeAudit } from '@/lib/audit'

export const runtime = 'nodejs'

const RECON_ORCHESTRATOR_URL = process.env.RECON_ORCHESTRATOR_URL || 'http://localhost:8010'
const UNKNOWN_START_REASON = 'the orchestrator did not answer; check whether the scan started'
const LIVE_RECON_STATUSES = new Set(['starting', 'running', 'paused'])

type QueueRow = NonNullable<Awaited<ReturnType<typeof prisma.jobQueue.findUnique>>>

/** The orchestrator's full-recon state for the project, or null when unreadable. */
async function readReconStatus(projectId: string): Promise<{ status?: string; started_at?: string | null } | null> {
  try {
    const res = await orchestratorFetch(`${RECON_ORCHESTRATOR_URL}/recon/${projectId}/status`)
    if (!res.ok) return null
    return await res.json()
  } catch {
    return null
  }
}

/** Back to 'queued' after a backoff, spending an attempt; 'failed' once they run out. */
async function retryOrFail(row: QueueRow, blockedCode: string, reason: string) {
  const attempts = row.attempts + 1
  if (attempts < row.maxAttempts) {
    await prisma.jobQueue.updateMany({
      where: { id: row.id, status: 'dispatching' },
      data: {
        status: 'queued',
        attempts,
        blockedCode,
        blockedReason: reason,
        notBefore: new Date(Date.now() + nextBackoff(attempts)),
      },
    })
    return NextResponse.json({ ok: false, blocked: blockedCode, temporary: true })
  }
  await prisma.jobQueue.updateMany({
    where: { id: row.id, status: 'dispatching' },
    data: {
      status: 'failed',
      attempts,
      error: `gave up after ${attempts} attempts: ${reason}`,
      blockedCode,
      blockedReason: reason,
      finishedAt: new Date(),
    },
  })
  return NextResponse.json({ ok: false, failed: true, error: reason }, { status: 200 })
}

async function needsReviewUnknown(row: QueueRow, scanJobId: string | null) {
  await prisma.jobQueue.updateMany({
    where: { id: row.id, status: 'dispatching' },
    data: {
      status: 'needs_review',
      blockedCode: 'start_unknown',
      blockedReason: UNKNOWN_START_REASON,
      scanJobId,
    },
  })
  return NextResponse.json({ ok: false, needsReview: true, blocked: 'start_unknown' })
}

/**
 * The orchestrator did not answer the start, so a scan may be running. A blind
 * retry of a full recon would wait as busy and then start a SECOND one (another
 * freeze, another graph wipe). A full recon runs one container per project, so
 * its status settles it: a scan that started after this claim is this job's, and
 * is adopted; nothing live means nothing started. Other kinds can run in
 * parallel, so only a person can tell.
 */
async function resolveUnknownStart(row: QueueRow, scanJobId: string | null, claimedAt: Date) {
  if (row.kind !== 'full_recon') return needsReviewUnknown(row, scanJobId)
  const live = await readReconStatus(row.projectId)
  if (!live) return needsReviewUnknown(row, scanJobId)

  if (LIVE_RECON_STATUSES.has(String(live.status))) {
    const started = live.started_at ? new Date(live.started_at) : null
    if (!started || Number.isNaN(started.getTime())) return needsReviewUnknown(row, scanJobId)
    if (started.getTime() < claimedAt.getTime()) {
      return retryOrFail(row, 'transient', 'another full recon was already running when this job started')
    }
    const now = new Date()
    await prisma.jobQueue.updateMany({
      where: { id: row.id, status: 'dispatching' },
      data: {
        status: 'running', blockedCode: '', blockedReason: '', error: '',
        scanJobId, dispatchedAt: now, startedAt: now,
      },
    })
    // startFullScan recorded the attempt as failed ("start outcome unknown");
    // the scan did start, and the reconcile closes this row like any other.
    if (scanJobId) {
      await prisma.scanJob.updateMany({
        where: { id: scanJobId, status: 'failed' },
        data: { status: 'running', finishedAt: null, ramReason: null },
      })
    }
    return NextResponse.json({ ok: true, adopted: true, scanJobId })
  }
  return retryOrFail(row, 'transient', 'the orchestrator did not answer and no scan started')
}

interface RouteParams {
  params: Promise<{ id: string }>
}

export async function POST(request: NextRequest, { params }: RouteParams) {
  if (!isInternalRequest(request)) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  }

  const { id } = await params
  let row: QueueRow | null = null

  try {
    row = await prisma.jobQueue.findUnique({ where: { id } })
    if (!row) return NextResponse.json({ error: 'Not found' }, { status: 404 })
    if (row.status !== 'queued') {
      return NextResponse.json({ ok: false, skipped: row.status }, { status: 409 })
    }

    // 1. Claim: only one dispatch can flip queued -> dispatching.
    const claim = await prisma.jobQueue.updateMany({
      where: { id, status: 'queued' },
      data: { status: 'dispatching' },
    })
    if (claim.count === 0) {
      return NextResponse.json({ ok: false, skipped: 'already-claimed' }, { status: 409 })
    }
    const claimedAt = new Date()

    // 3. One job per project (C-12): any OTHER row dispatching/running for this
    // project means we must wait. Revert our claim and defer with a reason.
    const otherActive = await prisma.jobQueue.findFirst({
      where: {
        projectId: row.projectId,
        status: { in: ['dispatching', 'running'] },
        id: { not: id },
      },
      select: { id: true },
    })
    if (otherActive) {
      // Guarded on status='dispatching' so a cancel that raced our claim is not
      // overwritten (Finding 1). If it was canceled, this is a no-op and the
      // canceled state stands.
      await prisma.jobQueue.updateMany({
        where: { id, status: 'dispatching' },
        data: {
          status: 'queued',
          blockedCode: 'busy',
          blockedReason: 'another job for this project is already dispatching or running',
          // Capacity wait: short fixed recheck, no attempt spent (see CAPACITY_RECHECK_MS).
          notBefore: new Date(Date.now() + CAPACITY_RECHECK_MS),
        },
      })
      return NextResponse.json({ ok: false, blocked: 'busy' })
    }

    // 2. Project still exists (C-7). Fail closed: never dispatch against a deleted
    // project (the scanners fall back to DEFAULT_*_SETTINGS on a 404 otherwise).
    const project = await prisma.project.findUnique({ where: { id: row.projectId } })
    if (!project) {
      await prisma.jobQueue.updateMany({
        where: { id, status: 'dispatching' },
        data: {
          status: 'failed',
          error: 'project no longer exists',
          blockedCode: '',
          finishedAt: new Date(),
        },
      })
      return NextResponse.json({ ok: false, error: 'project no longer exists' }, { status: 200 })
    }

    // 2b. The account that queued it and the project's owner are still active (DV-39): a
    // disabled person's queued work never starts on their keys. Cancelled, not deferred:
    // enabling the account later re-attributes nothing.
    const inactive = await inactiveScanAccount({ actorUserId: row.userId, ownerUserId: project.userId })
    if (inactive) {
      const reason = inactiveScanReason(inactive, 'queued')
      await prisma.jobQueue.updateMany({
        where: { id, status: 'dispatching' },
        data: { status: 'canceled', blockedCode: 'actor_inactive', blockedReason: reason, finishedAt: new Date() },
      })
      console.warn(`[rbac] job ${id} cancelled: ${inactive.as} ${inactive.userId} is ${inactive.status}`)
      await writeAudit({
        actorId: null,
        action: 'job_queue.cancelled',
        targetType: 'jobQueue',
        targetId: id,
        after: {
          reason: 'actor_inactive', projectId: row.projectId, kind: row.kind,
          userId: inactive.userId, account: inactive.as, status: inactive.status,
        },
        source: 'system',
      })
      return NextResponse.json({ ok: false, canceled: true, blocked: 'actor_inactive', error: reason })
    }

    // 2c. The job starts as the person who queued it, so they must still be allowed to start it
    // here (late: a share revoked or expired while it waited). Cancelled with the reason, never
    // re-attributed to the owner: the owner can queue it again as themselves.
    const refusal = await actorScanRefusal(row.userId, row.projectId, queuedJobPermissions(row.kind, row.payload))
    if (refusal) {
      const reason = actorScanRefusalReason(refusal, 'queued')
      await prisma.jobQueue.updateMany({
        where: { id, status: 'dispatching' },
        data: { status: 'canceled', blockedCode: 'actor_no_access', blockedReason: reason, finishedAt: new Date() },
      })
      console.warn(`[rbac] job ${id} cancelled: actor ${refusal.userId} lost ${refusal.permission} on project ${row.projectId} (${refusal.reason})`)
      await writeAudit({
        actorId: null,
        projectId: row.projectId,
        action: 'job_queue.cancelled',
        targetType: 'jobQueue',
        targetId: id,
        after: {
          reason: 'actor_no_access', projectId: row.projectId, kind: row.kind,
          userId: refusal.userId, permission: refusal.permission, refusal: refusal.reason,
        },
        source: 'system',
      })
      return NextResponse.json({ ok: false, canceled: true, blocked: 'actor_no_access', error: reason })
    }

    // 4. Settings fingerprint (C-4). A change between enqueue and dispatch means the
    // operator changed where/what this job scans; never silently run the new config.
    const currentHash = await currentFingerprintFor(row, project as unknown as Record<string, unknown>)
    if (currentHash !== row.settingsHash) {
      await prisma.jobQueue.updateMany({
        where: { id, status: 'dispatching' },
        data: {
          status: 'needs_review',
          blockedCode: 'settings_changed',
          blockedReason: 'scan settings changed since this job was queued; re-confirm to run with the new configuration',
        },
      })
      return NextResponse.json({ ok: false, needsReview: true })
    }

    // 5. Agent running + full_recon (C-5). Stricter than the manual path on purpose:
    // an unattended dispatcher must not wipe the graph under a live agent session.
    if (row.kind === 'full_recon') {
      const agent = describeAgentSessionState(await checkAgentSessions(row.projectId))
      if (agent) {
        await prisma.jobQueue.updateMany({
          where: { id, status: 'dispatching' },
          data: {
            status: 'queued',
            blockedCode: 'agent_running',
            blockedReason: `${agent} for this project; a full recon would wipe its graph`,
            // Capacity/contention wait: short fixed recheck, no attempt spent.
            notBefore: new Date(Date.now() + CAPACITY_RECHECK_MS),
          },
        })
        return NextResponse.json({ ok: false, blocked: 'agent_running' })
      }
    }

    // 6. Run it through the same start path the button uses.
    const payload = (row.payload && typeof row.payload === 'object' ? row.payload : {}) as Record<string, unknown>
    const result = await dispatchStart(row.kind, row.projectId, { actorUserId: row.userId, payload })

    if (result.ok) {
      // CONDITIONAL on still being 'dispatching' (Finding 1): a cancel that landed
      // during the (multi-second, for full_recon) start window set the row to
      // 'canceled'. Do NOT resurrect it to 'running'; instead, since the scan has
      // already started, best-effort stop it so it does not run orphaned.
      const won = await prisma.jobQueue.updateMany({
        where: { id, status: 'dispatching' },
        data: {
          status: 'running',
          blockedCode: '',
          blockedReason: '',
          error: '',
          runId: result.runId ?? '',
          scanJobId: result.scanJobId ?? null,
          dispatchedAt: new Date(),
          startedAt: new Date(),
        },
      })
      if (won.count === 0) {
        console.warn(`[jobQueue] job ${id} was canceled during dispatch; stopping the scan that started`)
        await stopScan(row.kind, row.projectId, result.runId ?? '')
        return NextResponse.json({ ok: false, canceledDuringDispatch: true })
      }
      return NextResponse.json({ ok: true, runId: result.runId ?? '', scanJobId: result.scanJobId ?? null })
    }

    // Failed to start. Unknown -> resolve; capacity -> recheck; transient ->
    // backoff; permanent -> fail.
    const cls = classifyStartFailure(result.status, {
      error: result.error,
      limit: result.limit as { limitType?: string } | undefined,
      activationInProgress: result.activationInProgress,
      busy: result.busy,
      snapshotFailed: result.snapshotFailed,
      startOutcome: result.startOutcome,
      code: result.code,
    }, { orchestratorAnswered: result.startOutcome !== 'unknown' })

    if (cls.kind === 'unknown') {
      return await resolveUnknownStart(row, result.scanJobId ?? null, claimedAt)
    }

    // A capacity wait (no memory / concurrency slot / project busy / activation in
    // flight) is not a defect: the job is simply waiting its turn. Requeue on a
    // short FIXED recheck and DO NOT consume an attempt, so a freed slot is picked
    // up within a tick and a validly-waiting job is never failed. This matches the
    // per-project 'busy' and 'agent_running' branches above. Guarded on
    // 'dispatching' (Finding 1): if a cancel raced, leave it canceled.
    if (cls.temporary && isCapacityWait(cls.blockedCode)) {
      await prisma.jobQueue.updateMany({
        where: { id, status: 'dispatching' },
        data: {
          status: 'queued',
          blockedCode: cls.blockedCode,
          blockedReason: cls.reason,
          notBefore: new Date(Date.now() + CAPACITY_RECHECK_MS),
        },
      })
      return NextResponse.json({ ok: false, blocked: cls.blockedCode, temporary: true })
    }

    // A transient refusal (an answered 5xx, a freeze failure) DOES spend the
    // attempt budget and eventually fails, so a job that keeps erroring for a real
    // reason cannot retry forever.
    if (cls.temporary) return await retryOrFail(row, cls.blockedCode, cls.reason)

    await prisma.jobQueue.updateMany({
      where: { id, status: 'dispatching' },
      data: {
        status: 'failed',
        attempts: row.attempts + 1,
        error: cls.reason,
        blockedCode: cls.blockedCode,
        blockedReason: cls.reason,
        finishedAt: new Date(),
      },
    })
    return NextResponse.json({ ok: false, failed: true, error: cls.reason }, { status: 200 })
  } catch (error) {
    console.error('[jobQueue] dispatch failed:', error)
    // Never leave a row stuck in 'dispatching', and never retry it on the next
    // tick for free: a throw that repeats (a version freeze erroring every time)
    // would otherwise run for ever. It spends an attempt and backs off.
    const message = error instanceof Error ? error.message : 'Internal server error'
    if (row) {
      await retryOrFail(row, 'transient', message).catch(() => {})
    } else {
      await prisma.jobQueue
        .updateMany({ where: { id, status: 'dispatching' }, data: { status: 'queued' } })
        .catch(() => {})
    }
    return NextResponse.json({ error: message }, { status: 500 })
  }
}
