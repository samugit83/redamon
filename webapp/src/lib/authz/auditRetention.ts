/**
 * Audit retention (step 6.6; AU-04, OQ-31, OQ-40): how long `audit_log` rows are kept, and the sweep
 * part that deletes the older ones. Root sets the number of days (`InstanceSettings.auditRetentionDays`,
 * null = keep every row, today's behaviour); nothing deletes a row on request.
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
import type { Prisma } from '@prisma/client'
import prisma from '@/lib/prisma'
import { INSTANCE_SETTINGS_ID } from '@/lib/sharedInstanceSettings'
import { rbacFlags } from './flags'

/** PLACEHOLDER(OQ-40): the shortest retention Root may set. */
export const AUDIT_RETENTION_MIN_DAYS = 90
/** A sanity bound, not a policy: about a hundred years. */
export const AUDIT_RETENTION_MAX_DAYS = 36_500
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

export interface RetentionSweep {
  /** The retention applied; null when every row is kept. */
  days: number | null
  deleted: number
}

/**
 * The sweep part: deletes, in batches, the audit_log rows older than the retention in force that no
 * rule keeps. With RBAC_GOVERNANCE_ENABLED off it reads and deletes nothing, whoever calls it. Throws
 * when a read or a delete fails (the sweep records the part as failed and retries).
 */
export async function sweepAuditRetention(at: Date): Promise<RetentionSweep> {
  if (!rbacFlags().governance) return { days: null, deleted: 0 }
  const row = await prisma.instanceSettings.findUnique({
    where: { id: INSTANCE_SETTINGS_ID },
    select: { auditRetentionDays: true },
  })
  const days = effectiveRetentionDays(row?.auditRetentionDays ?? null)
  if (days === null) return { days: null, deleted: 0 }
  const holders = (await prisma.user.findMany({ where: { legacyGrants: { isEmpty: false } }, select: { id: true } })).map((u) => u.id)
  const where = retentionDeleteWhere(new Date(at.getTime() - days * DAY_MS), holders)
  let deleted = 0
  for (let batch = 0; batch < RETENTION_MAX_BATCHES; batch++) {
    const ids = (await prisma.auditLog.findMany({ where, select: { id: true }, take: RETENTION_BATCH })).map((r) => r.id)
    if (!ids.length) break
    deleted += (await prisma.auditLog.deleteMany({ where: { id: { in: ids } } })).count
    if (ids.length < RETENTION_BATCH) break
  }
  return { days, deleted }
}
