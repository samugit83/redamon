/**
 * Scan Timeline - the project activation lock (Section 4A.3).
 *
 * Activating a version DELETES the live recon graph and rebuilds it from stored
 * bytes. Anything else that reads or writes that graph while the swap is in
 * flight sees a half-built world, so activation must be mutually exclusive with:
 *   - a full scan (start is rejected while activating; activation is rejected
 *     while a scan runs)
 *   - a partial recon run
 *   - an agent session (swapping the graph mid-reasoning changes the agent's
 *     world; we block rather than corrupt the session)
 *   - the scheduler worker (F3 - it defers instead of spawning into a swap)
 *
 * The lock is a single project-scoped row flag (`Project.activationState`), taken
 * with a conditional UPDATE so two concurrent activations cannot both win. It is
 * released in a `finally`, and a stale lock (process died mid-activation) expires
 * after ACTIVATION_LOCK_TTL_MS so a project can never be wedged forever.
 *
 * An ownership transfer (step 5.12) holds the same flag as `transferring` while it
 * moves the graph and the project to the new owner: every writer that asks this lock
 * waits for it too, and the 409 built here names `project_transfer_in_progress`.
 */
import { NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import {
  ACTIVATION_STATE_ACTIVATING,
  ACTIVATION_STATE_IDLE,
  ACTIVATION_STATE_TRANSFERRING,
  ACTIVATION_STATE_TRANSFER_SPLIT,
  activationLockTtlMs,
  holdOf,
  transferInProgressResponse,
  type GraphHold,
} from './graphHold'

export {
  ACTIVATION_STATE_ACTIVATING,
  ACTIVATION_STATE_IDLE,
  ACTIVATION_STATE_TRANSFERRING,
  ACTIVATION_STATE_TRANSFER_SPLIT,
  activationLockTtlMs,
  holdOf,
  transferInProgressResponse,
  type GraphHold,
} from './graphHold'

/** What holds the project's graph now (a non-stale activation or ownership transfer), or null. */
export async function graphHold(projectId: string): Promise<GraphHold | null> {
  return holdOf(await prisma.project.findUnique({
    where: { id: projectId },
    select: { activationState: true, activationStartedAt: true },
  }))
}

/** True when a (non-stale) activation or ownership transfer currently holds the project's graph. */
export async function isActivationInProgress(projectId: string): Promise<boolean> {
  return (await graphHold(projectId)) !== null
}

/**
 * Batched form for callers that hold a LIST of projects (the scheduler's due
 * feed). One query for N projects: asking per project turned a 25-schedule tick
 * into 25 sequential round-trips.
 */
export async function activationStates(projectIds: string[]): Promise<Map<string, boolean>> {
  const states = new Map<string, boolean>(projectIds.map(id => [id, false]))
  if (projectIds.length === 0) return states
  const rows = await prisma.project.findMany({
    where: { id: { in: projectIds } },
    select: { id: true, activationState: true, activationStartedAt: true },
  })
  for (const row of rows) states.set(row.id, holdOf(row) !== null)
  return states
}

/**
 * Guard for every path that touches the live graph while an activation may be
 * running (scan start, partial-recon start, agent-session start, scheduler).
 * Returns a 409 response to return, or null when the graph is free.
 *
 * Best-effort by design: if the check itself fails (DB hiccup) we allow the
 * operation rather than hard-blocking normal work on a lock read.
 */
export async function assertGraphNotActivating(projectId: string): Promise<NextResponse | null> {
  let hold: GraphHold | null
  try {
    hold = await graphHold(projectId)
  } catch (err) {
    console.error('[activationLock] state check failed (allowing):', err)
    return null
  }
  if (!hold) return null
  if (hold === ACTIVATION_STATE_TRANSFERRING) return transferInProgressResponse()
  return NextResponse.json(
    {
      error: 'A version activation is in progress for this project - the graph is being swapped. Try again once it finishes.',
      activationInProgress: true,
    },
    { status: 409 }
  )
}

/**
 * The FAIL-CLOSED form, for writes that an activation would silently lose.
 *
 * `assertGraphNotActivating` allows the operation when the lock cannot be read,
 * which is right for starting work. A mute or unmute is different: activation
 * freezes, clears and restores the graph, so one landing in between returns
 * success and is then gone. When the lock cannot be read, that is "busy".
 */
export async function activationBusy(projectId: string): Promise<boolean> {
  try {
    return await isActivationInProgress(projectId)
  } catch (err) {
    console.error('[activationLock] state check failed (treating as busy):', err)
    return true
  }
}

/** The 409 a mute or unmute route returns while an activation holds the graph. */
export function activationBusyResponse(): NextResponse {
  return NextResponse.json(
    {
      error: 'A version activation is in progress for this project (or its state could not be ' +
        'read), and a mute or unmute written now could be lost. Try again once it finishes.',
      activationInProgress: true,
    },
    { status: 409 }
  )
}

export interface LockHandle {
  acquired: boolean
  /** Set when the lock could not be taken. */
  reason?: string
}

/**
 * Take the lock, or report why not. Atomic: the conditional `updateMany` only
 * matches a project that is idle (or whose lock has expired), so exactly one
 * concurrent caller can win.
 */
export async function acquireActivationLock(
  projectId: string,
  versionId: string
): Promise<LockHandle> {
  const now = new Date()
  const staleBefore = new Date(now.getTime() - activationLockTtlMs())

  const res = await prisma.project.updateMany({
    where: {
      id: projectId,
      // A transfer that may have split the graph keeps the project until it completes or is run back.
      activationState: { not: ACTIVATION_STATE_TRANSFER_SPLIT },
      OR: [
        { activationState: ACTIVATION_STATE_IDLE },
        { activationStartedAt: null },
        { activationStartedAt: { lt: staleBefore } },
      ],
    },
    data: {
      activationState: ACTIVATION_STATE_ACTIVATING,
      activationStartedAt: now,
      activationVersionId: versionId,
    },
  })

  if (res.count === 0) {
    return { acquired: false, reason: 'Another activation is already in progress for this project.' }
  }
  return { acquired: true }
}

/** Always call from a `finally` - a leaked lock blocks scans and the agent. */
export async function releaseActivationLock(projectId: string): Promise<void> {
  try {
    await prisma.project.update({
      where: { id: projectId },
      data: {
        activationState: ACTIVATION_STATE_IDLE,
        activationStartedAt: null,
        activationVersionId: null,
      },
    })
  } catch (err) {
    // The TTL is the backstop: a lock we failed to release expires on its own.
    console.error('[activationLock] release failed (will expire via TTL):', err)
  }
}

/**
 * The ownership transfer's take of the lock (step 5.12): only while the project is still owned by
 * `ownerId` (the offer's giver). A retry of a transfer that may have split the graph resumes its own
 * split hold and keeps it split (`split: true`); otherwise only an idle or stale project that no split
 * transfer holds, so two accepts, an activation and a transfer whose project changed owner cannot both win.
 */
export async function acquireTransferLock(projectId: string, transferId: string, ownerId: string): Promise<{ acquired: boolean; split: boolean }> {
  const now = new Date()
  const own = `transfer:${transferId}`
  const staleBefore = new Date(now.getTime() - activationLockTtlMs())
  // Its own split hold, when no attempt is live on it: parked at the end of an attempt (null), or left
  // by a copy that died mid-move (no heartbeat for a TTL).
  const resumed = await prisma.project.updateMany({
    where: {
      id: projectId, userId: ownerId, activationState: ACTIVATION_STATE_TRANSFER_SPLIT, activationVersionId: own,
      OR: [{ activationStartedAt: null }, { activationStartedAt: { lt: staleBefore } }],
    },
    data: { activationStartedAt: now },
  })
  if (resumed.count === 1) return { acquired: true, split: true }
  const res = await prisma.project.updateMany({
    where: {
      id: projectId,
      userId: ownerId,
      activationState: { not: ACTIVATION_STATE_TRANSFER_SPLIT },
      OR: [
        { activationState: ACTIVATION_STATE_IDLE },
        { activationStartedAt: null },
        { activationStartedAt: { lt: staleBefore } },
      ],
    },
    data: {
      activationState: ACTIVATION_STATE_TRANSFERRING,
      activationStartedAt: now,
      activationVersionId: own,
    },
  })
  return { acquired: res.count === 1, split: false }
}

/** The graph move is about to start: from here the hold never goes stale until cleared. */
export async function markTransferSplit(projectId: string, transferId: string): Promise<void> {
  await prisma.project.updateMany({
    where: { id: projectId, activationState: ACTIVATION_STATE_TRANSFERRING, activationVersionId: `transfer:${transferId}` },
    data: { activationState: ACTIVATION_STATE_TRANSFER_SPLIT },
  })
}

/**
 * The graph is verified whole again under the project's owner (the move was refused before writing, run
 * back by the agent, or run back by this transfer): the split hold of `transferId` ends. A completed
 * transfer ends it inside the Postgres move instead.
 */
export async function clearTransferSplit(projectId: string, transferId: string): Promise<void> {
  await prisma.project.updateMany({
    where: { id: projectId, activationState: ACTIVATION_STATE_TRANSFER_SPLIT, activationVersionId: `transfer:${transferId}` },
    data: { activationState: ACTIVATION_STATE_IDLE, activationStartedAt: null, activationVersionId: null },
  })
}

/**
 * The live attempt's heartbeat on its own hold, split or not. Raw SQL so the project's updatedAt does not
 * move: the Postgres move compares it, and a heartbeat is no change to the project.
 */
export async function refreshTransferLock(projectId: string, transferId: string): Promise<void> {
  await prisma.$executeRaw`
    UPDATE projects SET activation_started_at = ${new Date()}
    WHERE id = ${projectId} AND activation_version_id = ${`transfer:${transferId}`}
      AND activation_state IN (${ACTIVATION_STATE_TRANSFERRING}, ${ACTIVATION_STATE_TRANSFER_SPLIT})`
}

/**
 * An attempt ended with the graph possibly split: the split hold stays (every writer keeps refusing) but no
 * attempt is live on it any more, so the next accept or withdrawal of the same transfer resumes it at once.
 * Never throws: an unparked hold is resumed once its heartbeat is a TTL old.
 */
export async function parkTransferSplit(projectId: string, transferId: string): Promise<void> {
  try {
    await prisma.$executeRaw`
      UPDATE projects SET activation_started_at = NULL
      WHERE id = ${projectId} AND activation_state = ${ACTIVATION_STATE_TRANSFER_SPLIT}
        AND activation_version_id = ${`transfer:${transferId}`}`
  } catch (err) {
    console.error('[rbac] transfer split park failed (resumable once its heartbeat is a TTL old):', err)
  }
}

/**
 * Releases a transfer's lock and nothing else (an activation that took a stale one keeps it, and a split
 * hold stays until clearTransferSplit or the completed move). Never throws.
 */
export async function releaseTransferLock(projectId: string): Promise<void> {
  try {
    await prisma.project.updateMany({
      where: { id: projectId, activationState: ACTIVATION_STATE_TRANSFERRING },
      data: { activationState: ACTIVATION_STATE_IDLE, activationStartedAt: null, activationVersionId: null },
    })
  } catch (err) {
    console.error('[rbac] transfer lock release failed (will expire via TTL):', err)
  }
}
