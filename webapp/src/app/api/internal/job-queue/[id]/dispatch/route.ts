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
 *   3. no OTHER non-terminal job for this project (C-12): one job per project.
 *   4. settings fingerprint matches (C-4): changed -> status=needs_review, no run.
 *   5. no agent running when kind=full_recon (C-5): defer, blockedCode=agent_running.
 *   6. then the same start path the button uses (lib/startScan.ts, R2).
 *
 * A temporary start failure (RAM/hard/activation/409) returns the row to 'queued'
 * with a backoff; a permanent one fails it.
 */
import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { isInternalRequest } from '@/lib/session'
import { settingsFingerprint, nextBackoff, CAPACITY_RECHECK_MS } from '@/lib/jobQueue'
import { resolveTrufflehogFingerprintExtra } from '@/lib/trufflehogStart'
import { authProfileFingerprintExtra } from '@/lib/authProfileFingerprint'
import { classifyStartFailure, isCapacityWait } from '@/lib/scanStartOutcome'
import { dispatchStart, stopScan } from '@/lib/startScan'

export const runtime = 'nodejs'

interface RouteParams {
  params: Promise<{ id: string }>
}

export async function POST(request: NextRequest, { params }: RouteParams) {
  if (!isInternalRequest(request)) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  }

  const { id } = await params

  try {
    const row = await prisma.jobQueue.findUnique({ where: { id } })
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

    // 4. Settings fingerprint (C-4). A change between enqueue and dispatch means the
    // operator changed where/what this job scans; never silently run the new config.
    const currentHash = settingsFingerprint(
      row.kind, project as unknown as Record<string, unknown>,
      {
        ...(await resolveTrufflehogFingerprintExtra(
          row.kind, row.projectId, (row.payload ?? {}) as Record<string, unknown>,
        )),
        ...(await authProfileFingerprintExtra(row.kind, row.projectId)),
      },
    )
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
      const agent = await prisma.conversation.findFirst({
        where: { projectId: row.projectId, agentRunning: true },
        select: { id: true },
      })
      if (agent) {
        await prisma.jobQueue.updateMany({
          where: { id, status: 'dispatching' },
          data: {
            status: 'queued',
            blockedCode: 'agent_running',
            blockedReason: 'an agent session is running for this project; a full recon would wipe its graph',
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

    // Failed to start. Temporary -> requeue; permanent -> fail.
    const cls = classifyStartFailure(result.status, {
      error: result.error,
      limit: result.limit as { limitType?: string } | undefined,
      activationInProgress: result.activationInProgress,
      busy: result.busy,
    })

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

    // A non-capacity temporary (an unexpected transient error) DOES spend the
    // attempt budget and eventually fails, so a job that keeps erroring for a real
    // reason cannot retry forever.
    const attempts = row.attempts + 1
    if (cls.temporary && attempts < row.maxAttempts) {
      await prisma.jobQueue.updateMany({
        where: { id, status: 'dispatching' },
        data: {
          status: 'queued',
          attempts,
          blockedCode: cls.blockedCode,
          blockedReason: cls.reason,
          notBefore: new Date(Date.now() + nextBackoff(attempts)),
        },
      })
      return NextResponse.json({ ok: false, blocked: cls.blockedCode, temporary: true })
    }

    await prisma.jobQueue.updateMany({
      where: { id, status: 'dispatching' },
      data: {
        status: 'failed',
        attempts,
        error: cls.temporary ? `gave up after ${attempts} attempts: ${cls.reason}` : cls.reason,
        blockedCode: cls.blockedCode,
        blockedReason: cls.reason,
        finishedAt: new Date(),
      },
    })
    return NextResponse.json({ ok: false, failed: true, error: cls.reason }, { status: 200 })
  } catch (error) {
    console.error('[jobQueue] dispatch failed:', error)
    // Best-effort: never leave a row stuck in 'dispatching' on an unexpected throw.
    await prisma.jobQueue
      .updateMany({ where: { id, status: 'dispatching' }, data: { status: 'queued' } })
      .catch(() => {})
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Internal server error' },
      { status: 500 },
    )
  }
}
