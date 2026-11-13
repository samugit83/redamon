/**
 * Audit retention (step 6.6; AU-04, OQ-31, OQ-40): how long `audit_log` rows are kept, and the sweep
 * part that deletes the older ones. Root sets the number of days (`InstanceSettings.auditRetentionDays`,
 * null = keep every row, today's behaviour); nothing deletes a row on request.
 *
 * - A change waits AUDIT_RETENTION_DELAY_DAYS: Root's request is stored as pending
 *   (`auditRetentionPending`, audited `instance.audit_retention_requested`) and is the retention in force
 *   from its `effectiveAt` on, read lazily, so nothing waits for the sweep (T19); the sweep then moves it
 *   into `auditRetentionDays` (`instance.audit_retention_activated`, once with several copies). Sending
 *   the value in force while a change waits cancels it (`instance.audit_retention_cancelled`). The delay
 *   gives whoever reads the audit log a week to see a shortening before it deletes anything.
 *
 * - Only with RBAC_GOVERNANCE_ENABLED on: the sweep (lib/authz/expirySweep.ts) runs this part only
 *   then, so with the switch off no row is deleted whatever was set while it was on (DV-30).
 * - Never below AUDIT_RETENTION_MIN_DAYS: a stored value under the floor (written around the API)
 *   deletes as the floor does and is logged.
 * - The act-as and Fireteam tables keep every row (assumption recorded by the Phase 6 kickoff).
 *
 * Kept whatever their age: the rows the code reads back, because deleting one changes what the code
 * does, not only what a screen shows (KEPT_AUDIT_RULES; auditRetention.test.ts reads every audit_log
 * reader in src/ and scripts/ and fails on one that reads an action no rule keeps, unless it is a
 * display reader listed there):
 * - every `system.*` row: the boot backfills' markers and cut-offs (a marker gone re-runs its
 *   backfill; the legacy-grants cut-off decides who counts as a pre-upgrade account; the conversion
 *   marker, without which capabilities.ts counts the raw `legacy_grants` column again, so old grants
 *   would come back) and `system.rbac_root_assigned` (/api/auth/me's unconfirmed-Root notice);
 * - the legacy-grant review decisions (`rbac.legacy_grant.keep` / `.remove`) and the What's new
 *   dismissal, which every boot and the review card read;
 * - `user.permissions_changed` about an account that holds legacy grants: the conversion skips a
 *   Keep that a person's later change superseded, on every boot.
 * Their personal data (the actor's email on a decision) is the residual SECURITY_POSTURE §16 names.
 *
 * Several webapp copies may sweep at once: audit rows never change, each batch is read and then
 * deleted by id, and a second delete of a row already gone matches nothing.
 */
import { Prisma } from '@prisma/client'
import prisma from '@/lib/prisma'
import { writeAuditTx } from '@/lib/audit'
import { auditedTransaction } from '@/lib/auditForward'
import { actorFields, type AuditActor } from '@/lib/auditActor'
import { INSTANCE_SETTINGS_ID } from '@/lib/sharedInstanceSettings'
import { rbacFlags } from './flags'

/** PLACEHOLDER(OQ-40): the shortest retention Root may set. */
export const AUDIT_RETENTION_MIN_DAYS = 90
/** A sanity bound, not a policy: about a hundred years. */
export const AUDIT_RETENTION_MAX_DAYS = 36_500
/** PLACEHOLDER(OQ-40): how long a change waits before it applies. */
export const AUDIT_RETENTION_DELAY_DAYS = 7
// Every reader and writer of the retention takes it, so a request, a cancel and an activation by two
// webapp copies never cross.
const RETENTION_LOCK = 'rbac.audit_retention'
/** Rows deleted per batch, and batches per sweep; a backlog goes on at the next sweep. */
export const RETENTION_BATCH = 1_000
export const RETENTION_MAX_BATCHES = 10

const DAY_MS = 86_400_000

export interface KeptAuditRule {
  /** An exact action, or a prefix ending in `.`. */
  action: string
  /** When set, only the rows about these accounts are kept. */
  scope?: 'legacy_grant_holders'
  why: string
}

export const KEPT_AUDIT_RULES: readonly KeptAuditRule[] = Object.freeze([
  { action: 'system.', why: 'boot backfill markers and cut-offs, and the automatic Root choice' },
  { action: 'rbac.legacy_grant.keep', why: 'the review decision every boot converts into an override' },
  { action: 'rbac.legacy_grant.remove', why: 'the review decision that keeps a removed grant removed' },
  { action: 'rbac.whats_new_dismissed', why: "an admin's dismissal of the update notes" },
  {
    action: 'user.permissions_changed',
    scope: 'legacy_grant_holders',
    why: "a person's change that supersedes a Keep, read by the legacy-overrides conversion",
  },
])

/** The rule that keeps an action's rows, or null: the scoped rule keeps only part of them. */
export function keptRuleFor(action: string): KeptAuditRule | null {
  return KEPT_AUDIT_RULES.find((r) => (r.action.endsWith('.') ? action.startsWith(r.action) : action === r.action)) ?? null
}

/** The rows older than `cutoff` that no rule keeps. */
export function retentionDeleteWhere(cutoff: Date, legacyHolders: readonly string[]): Prisma.AuditLogWhereInput {
  const kept: Prisma.AuditLogWhereInput[] = []
  for (const r of KEPT_AUDIT_RULES) {
    const action = r.action.endsWith('.') ? { startsWith: r.action } : { equals: r.action }
    if (!r.scope) kept.push({ action })
    else if (legacyHolders.length) kept.push({ action, targetId: { in: [...legacyHolders] } })
  }
  return { createdAt: { lt: cutoff }, NOT: kept }
}

/** The retention in force: null keeps every row; a stored value under the floor counts as the floor. */
export function effectiveRetentionDays(stored: number | null): number | null {
  if (stored === null) return null
  if (!Number.isInteger(stored) || stored < AUDIT_RETENTION_MIN_DAYS) {
    console.error(`[rbac] audit retention ${stored} is below the floor: ${AUDIT_RETENTION_MIN_DAYS} days apply`)
    return AUDIT_RETENTION_MIN_DAYS
  }
  return stored
}

export interface PendingRetention {
  /** The retention it sets; null keeps every row. */
  days: number | null
  requestedAt: string
  effectiveAt: string
  requestedById: string | null
}

export interface RetentionState {
  /** The retention in force now: the stored value, or a pending change whose time has come. */
  days: number | null
  /** A change still waiting (its effectiveAt is ahead). */
  pending: PendingRetention | null
  /** A change whose time has come that the sweep has not moved into auditRetentionDays yet. */
  due: PendingRetention | null
}

const validDays = (v: unknown): v is number | null =>
  v === null || (Number.isInteger(v) && (v as number) >= AUDIT_RETENTION_MIN_DAYS && (v as number) <= AUDIT_RETENTION_MAX_DAYS)
const validTime = (v: unknown): v is string => typeof v === 'string' && !Number.isNaN(new Date(v).getTime())

/** The stored pending change, or null; one that cannot be read is ignored and logged (it never deletes). */
export function parsePendingRetention(value: unknown): PendingRetention | null {
  if (value === null || value === undefined) return null
  const v = value as Record<string, unknown>
  if (typeof value !== 'object' || Array.isArray(value) || !validDays(v.days) || !validTime(v.requestedAt) || !validTime(v.effectiveAt)) {
    console.error('[rbac] audit retention pending change unreadable: ignored')
    return null
  }
  return {
    days: v.days as number | null,
    requestedAt: v.requestedAt as string,
    effectiveAt: v.effectiveAt as string,
    requestedById: typeof v.requestedById === 'string' ? v.requestedById : null,
  }
}

export function retentionState(row: { auditRetentionDays: number | null; auditRetentionPending?: unknown } | null, at: Date): RetentionState {
  const stored = row?.auditRetentionDays ?? null
  const pending = parsePendingRetention(row?.auditRetentionPending ?? null)
  if (pending && new Date(pending.effectiveAt).getTime() <= at.getTime()) return { days: pending.days, pending: null, due: pending }
  return { days: stored, pending, due: null }
}

/** What the instance settings answer shows of it (the floor and delay say what a change may be). */
export function retentionView(row: { auditRetentionDays: number | null; auditRetentionPending?: unknown }, at: Date) {
  const { days, pending } = retentionState(row, at)
  return {
    days,
    pending: pending ? { days: pending.days, requestedAt: pending.requestedAt, effectiveAt: pending.effectiveAt } : null,
    minDays: AUDIT_RETENTION_MIN_DAYS,
    delayDays: AUDIT_RETENTION_DELAY_DAYS,
  }
}

/** `auditRetentionDays` of a request body: null (keep every row) or whole days from the floor up. */
export function parseRetentionDays(value: unknown): { days: number | null } | { error: string } {
  if (validDays(value)) return { days: value }
  return {
    error: `auditRetentionDays must be null (keep every row) or a whole number of days from ${AUDIT_RETENTION_MIN_DAYS} to ${AUDIT_RETENTION_MAX_DAYS}`,
  }
}

export type RetentionChange = 'request' | 'cancel'

/** What asking for `days` changes: nothing (already in force with nothing waiting, or already waiting), a cancel, or a request. */
export function retentionChangeOf(state: RetentionState, days: number | null): RetentionChange | null {
  if (state.pending) {
    if (days === state.pending.days) return null
    return days === state.days ? 'cancel' : 'request'
  }
  return days === state.days ? null : 'request'
}

const SELECT_RETENTION = { auditRetentionDays: true, auditRetentionPending: true } as const

async function lockedRow(tx: Prisma.TransactionClient) {
  await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtext(${RETENTION_LOCK}))`
  return tx.instanceSettings.findUnique({ where: { id: INSTANCE_SETTINGS_ID }, select: SELECT_RETENTION })
}

const pendingJson = (p: PendingRetention): Prisma.InputJsonValue => ({ ...p })

async function writeActivation(tx: Prisma.TransactionClient, from: number | null, due: PendingRetention): Promise<void> {
  await writeAuditTx(tx, {
    actorId: null,
    action: 'instance.audit_retention_activated',
    targetType: 'instance',
    targetId: INSTANCE_SETTINGS_ID,
    before: { days: from },
    after: { days: due.days, requestedAt: due.requestedAt, effectiveAt: due.effectiveAt, requestedById: due.requestedById },
    source: 'system',
  })
}

export interface RetentionChangeResult {
  change: RetentionChange | null
  state: RetentionState
}

/**
 * Root's request for `days`, judged again under the lock on the row as it is: a request stores the
 * pending change (a due one is moved into force first, audited as its activation), a cancel clears
 * it; each with its audit row in the same transaction (a failed audit write changes nothing).
 */
export async function changeRetention(days: number | null, actor: AuditActor, at: Date): Promise<RetentionChangeResult> {
  return auditedTransaction(prisma, async (tx) => {
    const row = await lockedRow(tx)
    if (!row) throw new Error('the instance settings row is missing')
    const state = retentionState(row, at)
    const change = retentionChangeOf(state, days)
    if (!change) return { change, state }
    if (state.due) await writeActivation(tx, row.auditRetentionDays, state.due)
    if (change === 'cancel') {
      await tx.instanceSettings.update({
        where: { id: INSTANCE_SETTINGS_ID },
        data: { auditRetentionPending: Prisma.DbNull, ...(state.due ? { auditRetentionDays: state.due.days } : {}) },
      })
      await writeAuditTx(tx, {
        ...actorFields(actor),
        action: 'instance.audit_retention_cancelled',
        targetType: 'instance',
        targetId: INSTANCE_SETTINGS_ID,
        before: { days: state.pending!.days, effectiveAt: state.pending!.effectiveAt },
        after: { days: state.days },
        source: 'api',
      })
      return { change, state: { days: state.days, pending: null, due: null } }
    }
    const pending: PendingRetention = {
      days,
      requestedAt: at.toISOString(),
      effectiveAt: new Date(at.getTime() + AUDIT_RETENTION_DELAY_DAYS * DAY_MS).toISOString(),
      requestedById: actor.actorId,
    }
    await tx.instanceSettings.update({
      where: { id: INSTANCE_SETTINGS_ID },
      data: { auditRetentionPending: pendingJson(pending), ...(state.due ? { auditRetentionDays: state.due.days } : {}) },
    })
    await writeAuditTx(tx, {
      ...actorFields(actor),
      action: 'instance.audit_retention_requested',
      targetType: 'instance',
      targetId: INSTANCE_SETTINGS_ID,
      before: { days: state.days, ...(state.pending ? { replaced: { days: state.pending.days, effectiveAt: state.pending.effectiveAt } } : {}) },
      after: { days, effectiveAt: pending.effectiveAt },
      source: 'api',
    })
    return { change, state: { days: state.days, pending, due: null } }
  })
}

/**
 * Moves a pending change whose time has come into `auditRetentionDays`, audited once whatever the
 * number of copies sweeping (the second finds it moved). The retention in force is already that value.
 */
export async function activateDueRetention(at: Date): Promise<boolean> {
  return auditedTransaction(prisma, async (tx) => {
    const row = await lockedRow(tx)
    const state = retentionState(row, at)
    if (!row || !state.due) return false
    await tx.instanceSettings.update({
      where: { id: INSTANCE_SETTINGS_ID },
      data: { auditRetentionDays: state.due.days, auditRetentionPending: Prisma.DbNull },
    })
    await writeActivation(tx, row.auditRetentionDays, state.due)
    return true
  })
}

export interface RetentionSweep {
  /** The retention applied; null when every row is kept. */
  days: number | null
  deleted: number
  /** A pending change whose time had come was moved into force by this sweep. */
  activated?: true
}

/**
 * The sweep part: moves a due change into force, then deletes, in batches, the audit_log rows older
 * than the retention in force that no rule keeps. With RBAC_GOVERNANCE_ENABLED off it reads and deletes
 * nothing, whoever calls it. Throws when a read or a write fails (the sweep records the part as failed
 * and retries).
 */
export async function sweepAuditRetention(at: Date): Promise<RetentionSweep> {
  if (!rbacFlags().governance) return { days: null, deleted: 0 }
  const row = await prisma.instanceSettings.findUnique({ where: { id: INSTANCE_SETTINGS_ID }, select: SELECT_RETENTION })
  const state = retentionState(row, at)
  const activated = state.due ? await activateDueRetention(at) : false
  const days = effectiveRetentionDays(state.days)
  if (days === null) return { days: null, deleted: 0, ...(activated ? { activated: true as const } : {}) }
  const holders = (await prisma.user.findMany({ where: { legacyGrants: { isEmpty: false } }, select: { id: true } })).map((u) => u.id)
  const where = retentionDeleteWhere(new Date(at.getTime() - days * DAY_MS), holders)
  let deleted = 0
  for (let batch = 0; batch < RETENTION_MAX_BATCHES; batch++) {
    const ids = (await prisma.auditLog.findMany({ where, select: { id: true }, take: RETENTION_BATCH })).map((r) => r.id)
    if (!ids.length) break
    deleted += (await prisma.auditLog.deleteMany({ where: { id: { in: ids } } })).count
    if (ids.length < RETENTION_BATCH) break
  }
  return { days, deleted, ...(activated ? { activated: true as const } : {}) }
}
