/**
 * The project lock's states and the reading of one row (step 5.12), apart from activationLock.ts so a
 * writer that already reads the project row (the settings save) judges the hold without a second read,
 * and without importing the lock's database helpers.
 */
import { NextResponse } from 'next/server'

export const ACTIVATION_STATE_IDLE = 'idle'
export const ACTIVATION_STATE_ACTIVATING = 'activating'
export const ACTIVATION_STATE_TRANSFERRING = 'transferring'

/** What can hold a project's graph through `Project.activationState`. */
export type GraphHold = typeof ACTIVATION_STATE_ACTIVATING | typeof ACTIVATION_STATE_TRANSFERRING

export const HOLDS: ReadonlySet<string> = new Set([ACTIVATION_STATE_ACTIVATING, ACTIVATION_STATE_TRANSFERRING])

export function activationLockTtlMs(): number {
  const raw = parseInt(process.env.ACTIVATION_LOCK_TTL_MS || '', 10)
  return Number.isFinite(raw) && raw > 0 ? raw : 15 * 60 * 1000
}

export function isStale(startedAt: Date | null | undefined, now: number): boolean {
  if (!startedAt) return true
  return now - new Date(startedAt).getTime() > activationLockTtlMs()
}

/**
 * What a project row read with `activationState` and `activationStartedAt` says holds its graph,
 * or null: for a writer that already reads the row (the settings save, step 5.12).
 */
export function holdOf(row: { activationState?: string | null; activationStartedAt?: Date | null } | null | undefined): GraphHold | null {
  if (!row?.activationState || !HOLDS.has(row.activationState)) return null
  return isStale(row.activationStartedAt, Date.now()) ? null : row.activationState as GraphHold
}

/** The 409 of a write refused while the project moves to its new owner (step 5.12). */
export function transferInProgressResponse(): NextResponse {
  return NextResponse.json(
    {
      error: "This project's ownership is being transferred. Try again in a moment, once it finishes.",
      code: 'project_transfer_in_progress',
      transferInProgress: true,
    },
    { status: 409 },
  )
}
